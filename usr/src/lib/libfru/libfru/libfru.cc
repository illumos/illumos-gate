/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * libfru is divided into the following modules:
 * 1) This file.  Support for the API and ties together all the sub-modules.
 * 2) The parser which parses the field_paths supplied by the user.
 * 3) The data_source sub-libraries which provide payloads(tags) and the tree
 *    structure of frus and locations.
 * 4) The PayloadReader which given a payload and a path definition can extract
 *    the exact field the user is looking for.
 * 5) The Registry which provides the definitions for all the Data Elements
 *    supported.
 *
 * The basic algorithim for reading/updating fields is this:
 * 1) Parse the field_path given by the user.
 * 2) Using the registry determine which payloads this data MAY appear in.
 * 3) Figure out which tags of this type are in the container.
 * 4) Find the specific tag which contains the instance of this data the user
 *    requested.
 * 5) Get this tag from the data source and read it with the PayloadReader to
 *    read/write data.
 * 6) For UPDATES write this tag back to the data source.
 *
 * This algorithim is altered only when dealing with "UNKNOWN" payloads where
 * it simplifies slightly.
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <pthread.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <alloca.h>
#include <limits.h>

#include "libfru.h"
#include "libfrup.h"
#include "libfruds.h"
#include "Ancestor.h"
#include "libfrureg.h"
#include "Parser.h"
#include "PayloadReader.h"

#define	DATA_SOURCE_OBJ_NAME "data_source"

#define	ENCRYPTION_LIB_NAME "libfrucrypt.so.1"
#define	FRU_ENCRYPT_FUNC_NAME "fru_encrypt_func"

#define	UNKNOWN_PATH "UNKNOWN"
#define	IS_UNKNOWN_PATH(path) \
((strcmp(path, "/UNKNOWN") == 0) || (strcmp(path, "UNKNOWN") == 0))

#define	NODEHDL_TO_TREEHDL(nodehdl) (fru_treehdl_t)nodehdl
#define	TREEHDL_TO_NODEHDL(treehdl) (fru_nodehdl_t)treehdl

/* ========================================================================= */
/*
 * Define a hash of rwlocks for each container.
 */
struct cont_lock
{
	fru_nodehdl_t handle;
	pthread_rwlock_t lock;
	struct cont_lock *next;
};
typedef struct cont_lock cont_lock_t;

fru_encrypt_func_t encrypt_func;

#define	CONT_LOCK_HASH_NUM 128
cont_lock_t *cont_lock_hash[CONT_LOCK_HASH_NUM];
pthread_mutex_t cont_lock_hash_lock;

typedef enum { WRITE_LOCK, READ_LOCK } lock_mode_t;

/*
 * These control the Data sources available.
 */
static pthread_mutex_t ds_lock;
static fru_datasource_t *data_source = NULL;
static void *ds_lib = NULL;
static int ds_lib_ref_cnt = 0;
static char *ds_lib_name = NULL;

#define	FRU_NORESPONSE_RETRY 500

#define RETRY(expr) 						\
	{ for (int loop = 0; loop < FRU_NORESPONSE_RETRY &&	\
		(expr) == FRU_NORESPONSE; loop++) ;		\
	}	

/* ========================================================================= */
static const char *fru_errmsg[] =
{
	"Success",
	"Node not found",
	"IO error",
	"No registry definition for this element",
	"Not container",
	"Invalid handle",
	"Invalid Segment",
	"Invalid Path",
	"Invalid Element",
	"Invalid Data size (does not match registry definition)",
	"Duplicate Segment",
	"Not Field",
	"No space available",
	"Data could not be found",
	"Iteration full",
	"Invalid Permisions",
	"Feature not Supported",
	"Element is not Tagged",
	"Failed to read container device",
	"Segment Corrupt",
	"Data Corrupt",
	"General LIBFRU FAILURE",
	"Walk terminated",
	"FRU No response",
	"Unknown error"
};

fru_errno_t
fru_encryption_supported(void)
{
	if (encrypt_func == NULL)
		return (FRU_NOTSUP);
	else
		return (FRU_SUCCESS);
}

extern "C" {
void
init_libfru(void)
{
	// attempt to find the encryption library.
	void *crypt_lib = NULL;
	encrypt_func = NULL;
	crypt_lib = dlopen(ENCRYPTION_LIB_NAME, RTLD_LAZY);
	if (crypt_lib != NULL) {
		encrypt_func = (fru_encrypt_func_t)dlsym(crypt_lib,
						FRU_ENCRYPT_FUNC_NAME);
	}
}
#pragma init(init_libfru)
}

/* ========================================================================= */
static void
add_cont_lock(cont_lock_t *lock)
{
	cont_lock_t *prev = NULL;
	int hash_bucket = lock->handle % CONT_LOCK_HASH_NUM;

	/* insert at tail */
	if (cont_lock_hash[hash_bucket] == NULL) {
		cont_lock_hash[hash_bucket] = lock;
	} else {
		cont_lock_t *prev = cont_lock_hash[hash_bucket];
		while (prev->next != NULL) {
			prev = prev->next;
		}
		prev->next = lock;
	}
}

/* ========================================================================= */
static cont_lock_t *
find_cont_lock(fru_nodehdl_t handle)
{
	int hash_bucket = handle % CONT_LOCK_HASH_NUM;
	cont_lock_t *which = cont_lock_hash[hash_bucket];

	while (which != NULL) {
		if (which->handle == handle) {
			break;
		}
		which = which->next;
	}
	return (which);
}

/* ========================================================================= */
static cont_lock_t *
alloc_cont_lock(fru_nodehdl_t handle)
{
	cont_lock_t *lock = (cont_lock_t *)malloc(sizeof (cont_lock_t));
	if (lock == NULL) {
		return (NULL);
	}
	lock->handle = handle;
	if (pthread_rwlock_init(&(lock->lock), NULL) != 0) {
		free(lock);
		return (NULL);
	}
	lock->next = NULL;
	return (lock);
}

/* ========================================================================= */
static fru_errno_t
lock_container(lock_mode_t mode, fru_nodehdl_t handle)
{
	cont_lock_t *which = NULL;
	int hash_bucket = 0;
	int lock_rc;

	pthread_mutex_lock(&cont_lock_hash_lock);

	which = find_cont_lock(handle);

	/* if not found add to hash */
	if (which == NULL) {
		if ((which = alloc_cont_lock(handle)) == NULL) {
			pthread_mutex_unlock(&cont_lock_hash_lock);
			return (FRU_FAILURE);
		}
		add_cont_lock(which);
	}

	/* execute lock */
	lock_rc = 0;
	switch (mode) {
		case READ_LOCK:
			lock_rc = pthread_rwlock_rdlock(&(which->lock));
			break;
		case WRITE_LOCK:
			lock_rc = pthread_rwlock_wrlock(&(which->lock));
			break;
	}

	pthread_mutex_unlock(&cont_lock_hash_lock);
	if (lock_rc != 0) {
		return (FRU_FAILURE);
	}
	return (FRU_SUCCESS);
}

/* ========================================================================= */
/*
 * Macro to make checking unlock_conatiner error code easier
 */
#define	CHK_UNLOCK_CONTAINER(handle) \
	if (unlock_container(handle) != FRU_SUCCESS) { \
		return (FRU_FAILURE); \
	}
static fru_errno_t
unlock_container(fru_nodehdl_t handle)
{
	cont_lock_t *which = NULL;
	pthread_mutex_lock(&cont_lock_hash_lock);

	which = find_cont_lock(handle);
	if (which == NULL) {
		pthread_mutex_unlock(&cont_lock_hash_lock);
		return (FRU_NODENOTFOUND);
	}

	if (pthread_rwlock_unlock(&(which->lock)) != 0) {
		pthread_mutex_unlock(&cont_lock_hash_lock);
		return (FRU_FAILURE);
	}

	pthread_mutex_unlock(&cont_lock_hash_lock);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
clear_cont_locks(void)
{
	pthread_mutex_lock(&cont_lock_hash_lock);

	// for each bucket
	for (int i = 0; i < CONT_LOCK_HASH_NUM; i++) {
		// free all the locks
		cont_lock_t *cur = cont_lock_hash[i];
		while (cur != NULL) {
			cont_lock_t *tmp = cur;
			cur = cur->next;
			pthread_rwlock_destroy(&(tmp->lock));
			free(tmp);
		}
		cont_lock_hash[i] = NULL;
	}

	pthread_mutex_unlock(&cont_lock_hash_lock);
	return (FRU_SUCCESS);
}


/* ========================================================================= */
/* VARARGS */
fru_errno_t
fru_open_data_source(const char *name, ...)
{
	fru_errno_t err = FRU_SUCCESS;

	va_list args;
	int num_args = 0;
	char **init_args = NULL;
	char *tmp;
	int i = 0;

	char ds_name[PATH_MAX];
	fru_datasource_t *ds = NULL;
	void *tmp_lib = NULL;

	pthread_mutex_lock(&ds_lock);

	if ((ds_lib_name != NULL) && (data_source != NULL)) {
		// we already have a DS assigned.
		if ((strcmp(ds_lib_name, name) == 0)) {
			// user wants to open the same one... ok.
			ds_lib_ref_cnt++;
			pthread_mutex_unlock(&ds_lock);
			return (FRU_SUCCESS);
		} else {
			pthread_mutex_unlock(&ds_lock);
			return (FRU_FAILURE);
		}
	}

	snprintf(ds_name, sizeof (ds_name), "libfru%s.so.%d",
				name, LIBFRU_DS_VER);
	tmp_lib = dlopen(ds_name, RTLD_LAZY);
	if (tmp_lib == NULL) {
		pthread_mutex_unlock(&ds_lock);
		return (FRU_NOTSUP);
	}
	ds = (fru_datasource_t *)dlsym(tmp_lib,
				DATA_SOURCE_OBJ_NAME);
	if (ds == NULL) {
		pthread_mutex_unlock(&ds_lock);
		return (FRU_FAILURE);
	}

	va_start(args, name);
	tmp = va_arg(args, char *);
	while (tmp != NULL) {
		num_args++;
		tmp = va_arg(args, char *);
	}
	va_end(args);

	init_args = (char **)malloc(sizeof (char *) * num_args);
	if (init_args == NULL) {
		pthread_mutex_unlock(&ds_lock);
		return (FRU_FAILURE);
	}

	va_start(args, name);
	for (tmp = va_arg(args, char *), i = 0;
		(tmp != NULL) && (i < num_args);
			tmp = va_arg(args, char *), i++) {
		init_args[i] = tmp;
	}
	va_end(args);

	if ((err = ds->initialize(num_args, init_args)) == FRU_SUCCESS) {
		// don't switch unless the source connects ok.
		ds_lib = tmp_lib;
		data_source = ds;
		ds_lib_name = strdup(name);
		ds_lib_ref_cnt++;
	}

	free(init_args);
	pthread_mutex_unlock(&ds_lock);
	return (err);
}


/* ========================================================================= */
fru_errno_t
fru_close_data_source(void)
{
	fru_errno_t err = FRU_SUCCESS;

	if (ds_lib_ref_cnt == 0) {
		return (FRU_FAILURE);
	}

	pthread_mutex_lock(&ds_lock);
	if ((--ds_lib_ref_cnt) == 0) {
		/* don't check err code here */
		err = data_source->shutdown();
		/* continue to clean up libfru and return the err at the end */
		clear_cont_locks();
		dlclose(ds_lib);
		ds_lib = NULL;
		free(ds_lib_name);
		ds_lib_name = NULL;
		data_source = NULL;
	}

	pthread_mutex_unlock(&ds_lock);
	return (err);
}

/* ========================================================================= */
int
segment_is_encrypted(fru_nodehdl_t container, const char *seg_name)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_segdef_t segdef;

	if (data_source == NULL) {
		return (0);
	}

	RETRY(err = data_source->get_seg_def(NODEHDL_TO_TREEHDL(container),
							seg_name, &segdef))

	if (err != FRU_SUCCESS) {
		return (0);
	}

	return (segdef.desc.field.encrypted == 1);
}

/* ========================================================================= */
static fru_errno_t
get_seg_list_from_ds(fru_nodehdl_t node, fru_strlist_t *list)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_strlist_t raw_list;
	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	/* get a list of all segments */
	RETRY(err = data_source->get_seg_list(NODEHDL_TO_TREEHDL(node),
								&raw_list))

	if (err != FRU_SUCCESS) {
		return (err);
	}

	/* leave out the encrypted segments if necessary */
	list->num = 0;
	list->strs = (char **)malloc(sizeof (*(list->strs)) * raw_list.num);
	if (list->strs == NULL) {
		fru_destroy_strlist(&raw_list);
		return (err);
	}
	for (int i = 0; i < raw_list.num; i++) {
		if (segment_is_encrypted(node, raw_list.strs[i])) {
			if (fru_encryption_supported() == FRU_SUCCESS) {
				list->strs[list->num]
					= strdup(raw_list.strs[i]);
				list->num++;
			} // else leave it out.
		} else {
			list->strs[list->num] = strdup(raw_list.strs[i]);
			list->num++;
		}
	}

	fru_destroy_strlist(&raw_list);
	return (FRU_SUCCESS);
}


/* ========================================================================= */
const char *
fru_strerror(fru_errno_t errnum)
{
	if ((errnum < (sizeof (fru_errmsg)/sizeof (*fru_errmsg))) &&
			(errnum >= 0)) {
		return (gettext(fru_errmsg[errnum]));
	}
	return (gettext
		(fru_errmsg[(sizeof (fru_errmsg)/sizeof (*fru_errmsg))]));
}

/* ========================================================================= */
fru_errno_t
fru_get_root(fru_nodehdl_t *handle)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_treehdl_t tr_root;
	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	RETRY(err = data_source->get_root(&tr_root))
	if (err == FRU_SUCCESS) {
		*handle = TREEHDL_TO_NODEHDL(tr_root);
	}
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_get_child(fru_nodehdl_t handle, fru_nodehdl_t *child)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_treehdl_t tr_child;
	fru_node_t type;
	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	RETRY(err = data_source->get_child(NODEHDL_TO_TREEHDL(handle),
								&tr_child))
	if (err != FRU_SUCCESS) {
		return (err);
	}

	RETRY(err = data_source->get_node_type(tr_child, &type))

	if (err != FRU_SUCCESS) {
		return (err);
	}
	if ((type == FRU_NODE_LOCATION) ||
		(type == FRU_NODE_FRU) ||
		(type == FRU_NODE_CONTAINER)) {
		*child = TREEHDL_TO_NODEHDL(tr_child);
		return (FRU_SUCCESS);
	}

/*
 * if the child is not valid try and find a peer of the child which is
 * valid
 */
	do {
		RETRY(err = data_source->get_peer(tr_child, &tr_child))
		if (err != FRU_SUCCESS) {
			return (err);
		}
		
		RETRY(err = data_source->get_node_type(tr_child, &type))
		if (err != FRU_SUCCESS) {
			return (err);
		}
		if ((type == FRU_NODE_LOCATION) ||
			(type == FRU_NODE_FRU) ||
			(type == FRU_NODE_CONTAINER)) {
			*child = TREEHDL_TO_NODEHDL(tr_child);
			return (FRU_SUCCESS);
		}
	} while (1);
}

/* ========================================================================= */
fru_errno_t
fru_get_peer(fru_nodehdl_t handle, fru_nodehdl_t *peer)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_treehdl_t tr_peer = NODEHDL_TO_TREEHDL(handle);
	fru_node_t type;

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	do {
		RETRY(err = data_source->get_peer(tr_peer, &tr_peer))

		if (err != FRU_SUCCESS) {
			return (err);
		}

		RETRY(err = data_source->get_node_type(tr_peer, &type))
		if (err != FRU_SUCCESS) {
			return (err);
		}
		if ((type == FRU_NODE_LOCATION) ||
			(type == FRU_NODE_FRU) ||
			(type == FRU_NODE_CONTAINER)) {
			*peer = TREEHDL_TO_NODEHDL(tr_peer);
			return (FRU_SUCCESS);
		}
	} while (1);
}
/* ========================================================================= */
fru_errno_t
fru_get_parent(fru_nodehdl_t handle, fru_nodehdl_t *parent)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_treehdl_t tr_parent;
	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	RETRY(err = data_source->get_parent(NODEHDL_TO_TREEHDL(handle),
								&tr_parent))
	if (err == FRU_SUCCESS) {
		*parent = TREEHDL_TO_NODEHDL(tr_parent);
	}
	return (err);
}


/* ========================================================================= */
fru_errno_t
fru_get_name_from_hdl(fru_nodehdl_t handle, char **name)
{
	fru_errno_t	err = FRU_SUCCESS;

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	RETRY(err = data_source->get_name_from_hdl(NODEHDL_TO_TREEHDL(handle),
									name))
	return (err);
}

/* ========================================================================= */
/*
 * Project-private interface
 *
 * Apply process_node() to each node in the tree rooted at "node".
 *
 * process_node() has available the handle, path (in the subtree from the root
 * "node" passed to fru_walk_tree()), and name of the node to which it is
 * applied, as well as any arguments provided via the generic pointer "args".
 * process_node() also takes a pointer to an end_node() function pointer
 * argument and a pointer to a generic pointer "end_args" argument.  If
 * non-null, end_node() is called after the node and its children have been
 * processed, but before the node's siblings are visited.
 */
extern "C" fru_errno_t
fru_walk_tree(fru_nodehdl_t node, const char *prior_path,
		fru_errno_t (*process_node)(fru_nodehdl_t node,
						const char *path,
						const char *name, void *args,
						end_node_fp_t *end_node,
						void **end_args),
		void *args)
{
	void		*end_args = NULL;

	char		*name = NULL, *path;

	int		prior_length;

	fru_errno_t	status;

	fru_nodehdl_t	next;

	end_node_fp_t	end_node = NULL;


	/* Build node's path */
	if ((status = fru_get_name_from_hdl(node, &name)) != FRU_SUCCESS)
		return (status);
	else if (name == NULL)
		return (FRU_FAILURE);

	prior_length = strlen(prior_path);
	path = (char *)alloca(prior_length + sizeof ("/") + strlen(name));
	(void) sprintf(path, "%s/%s", prior_path, name);
	free(name);
	name = path + prior_length + 1;


	/* Process node */
	assert(process_node != NULL);
	if ((status = process_node(node, path, name, args,
					&end_node, &end_args))
	    != FRU_SUCCESS) {
		if (end_node) end_node(node, path, name, end_args);
		return (status);
	}


	/* Process children */
	if ((status = fru_get_child(node, &next)) == FRU_SUCCESS)
		status = fru_walk_tree(next, path, process_node, args);
	else if (status == FRU_NODENOTFOUND)
		status = FRU_SUCCESS;

	/* "Close" node */
	if (end_node) end_node(node, path, name, end_args);
	if (status != FRU_SUCCESS)
		return (status);

	/* Process siblings */
	if ((status = fru_get_peer(node, &next)) == FRU_SUCCESS)
		status = fru_walk_tree(next, prior_path, process_node, args);
	else if (status == FRU_NODENOTFOUND)
		status = FRU_SUCCESS;

	return (status);
}

/* ========================================================================= */
/*
 * Project-private interface
 *
 * Return true if "searchpath" equals "path" or is a tail of "path" and
 * begins at a component name within "path"
 */
int
fru_pathmatch(const char *path, const char *searchpath)
{
	const char	*match;

	if (((match = strstr(path, searchpath)) != NULL) &&
	    ((match + strlen(searchpath)) == (path + strlen(path))) &&
	    ((match == path) || (*(match - 1) == '/')))
		return (1);

	return (0);
}

/* ========================================================================= */
fru_errno_t
fru_get_node_type(fru_nodehdl_t handle, fru_node_t *type)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_node_t tmp;
	if (data_source == NULL) {
		return (FRU_FAILURE);
	}
	
	RETRY(err = data_source->get_node_type(NODEHDL_TO_TREEHDL(handle),
								&tmp))
	if (err == FRU_SUCCESS) {
		*type = tmp;
	}
	return (err);
}

/* ========================================================================= */
static fru_errno_t
is_container(fru_nodehdl_t handle)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_node_t type;
	if ((err = fru_get_node_type(handle, &type)) != FRU_SUCCESS) {
		return (err);
	}
	if (type == FRU_NODE_CONTAINER) {
		return (FRU_SUCCESS);
	}
	return (FRU_NOTCONTAINER);
}

/* ========================================================================= */
fru_errno_t
fru_destroy_enum(fru_enum_t *e)
{
	if (e == NULL) {
		return (FRU_SUCCESS);
	}
	if (e->text != NULL)
		free(e->text);

	return (FRU_SUCCESS);
}

/* ========================================================================= */
/*
 * NOTE: does not free list.  This is allocated by the user and should be
 * deallocated by the user.
 */
fru_errno_t
fru_destroy_strlist(fru_strlist_t *list)
{
	if (list == NULL) {
		return (FRU_SUCCESS);
	}
	if (list->strs != NULL) {
		for (int i = 0; i < list->num; i++) {
			if (list->strs[i] != NULL)
				free(list->strs[i]);
		}
		free(list->strs);
	}

	list->num = 0;

	return (FRU_SUCCESS);
}

/* ========================================================================= */
fru_errno_t
fru_destroy_elemdef(fru_elemdef_t *def)
{
	if (def == NULL) {
		return (FRU_SUCCESS);
	}
	if (def->enum_table != NULL) {
		for (int i = 0; i < def->enum_count; i++)
			fru_destroy_enum(&(def->enum_table[i]));
		free(def->enum_table);
	}
	def->enum_count = 0;

	if (def->example_string != NULL)
		free(def->example_string);

	return (FRU_SUCCESS);
}

/* ========================================================================= */
fru_errno_t
fru_list_segments(fru_nodehdl_t container, fru_strlist_t *list)
{
	fru_errno_t err = FRU_SUCCESS;

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	err = get_seg_list_from_ds(container, list);

	CHK_UNLOCK_CONTAINER(container);
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_create_segment(fru_nodehdl_t container, fru_segdef_t *def)
{
	fru_errno_t err = FRU_SUCCESS;
	int i = 0;

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((def->desc.field.encrypted == 1) &&
	       (fru_encryption_supported() == FRU_NOTSUP)) {
		return (FRU_NOTSUP);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(WRITE_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	fru_strlist_t seg_list;

	/* get a list of all segments */
	/* here we do not want to leave out the encrypted segments. */
	RETRY(err = data_source->get_seg_list(NODEHDL_TO_TREEHDL(container),
								&seg_list))
	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		return (err);
	}

	for (i = 0; i < seg_list.num; i++) {
		if (strncmp(seg_list.strs[i], def->name, FRU_SEGNAMELEN)
			== 0) {
			fru_destroy_strlist(&seg_list);
			CHK_UNLOCK_CONTAINER(container);
			return (FRU_DUPSEG);
		}
	}
	fru_destroy_strlist(&seg_list);

	RETRY(err = data_source->add_seg(NODEHDL_TO_TREEHDL(container), def))

	CHK_UNLOCK_CONTAINER(container);
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_remove_segment(fru_nodehdl_t container, const char *seg_name)
{
	fru_errno_t err = FRU_SUCCESS;
	if ((seg_name == NULL) || (strlen(seg_name) > FRU_SEGNAMELEN)) {
		return (FRU_INVALSEG);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(WRITE_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	/* do not allow encrypted segments to be removed */
	/* unless encryption is supported */
	if ((segment_is_encrypted(container, seg_name)) &&
		(fru_encryption_supported() == FRU_NOTSUP)) {
		err = FRU_INVALSEG;
	} else {
		RETRY(err =
			data_source->delete_seg(NODEHDL_TO_TREEHDL(container),
								seg_name))
	}

	CHK_UNLOCK_CONTAINER(container);
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_get_segment_def(fru_nodehdl_t container, const char *seg_name,
			fru_segdef_t *definition)
{
	fru_errno_t err = FRU_SUCCESS;
	if ((seg_name == NULL) || (strlen(seg_name) > 2)) {
		return (FRU_INVALSEG);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	// NOTE: not passing "definition" to this function such that I may
	// check for encryption before allowing the user to get the data.
	fru_segdef_t segdef;

	RETRY(err = data_source->get_seg_def(NODEHDL_TO_TREEHDL(container),
							seg_name, &segdef))

	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		return (err);
	}

	if ((segdef.desc.field.encrypted == 1) &&
		(fru_encryption_supported() == FRU_NOTSUP)) {
		CHK_UNLOCK_CONTAINER(container);
		return (FRU_INVALSEG);
	}

	// After encryption check, copy from my def to users.
	definition->version = segdef.version;
	strlcpy(definition->name, segdef.name, FRU_SEGNAMELEN+1);
	definition->desc = segdef.desc;
	definition->size = segdef.size;
	definition->address = segdef.address;
	definition->hw_desc = segdef.hw_desc;

	CHK_UNLOCK_CONTAINER(container);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
fru_errno_t
fru_list_elems_in(fru_nodehdl_t container, const char *seg_name,
		fru_strlist_t *list)
{
	fru_errno_t err = FRU_SUCCESS;
	fru_tag_t *tags = NULL;
	int i = 0;
	int num_tags = 0;
	fru_strlist_t rc_list;

	if ((seg_name == NULL) || (strlen(seg_name) > 2)) {
		return (FRU_INVALSEG);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	if ((segment_is_encrypted(container, seg_name)) &&
		(fru_encryption_supported() == FRU_NOTSUP)) {
		CHK_UNLOCK_CONTAINER(container);
		return (FRU_INVALSEG);
	}

	RETRY(err = data_source->get_tag_list(NODEHDL_TO_TREEHDL(container),
						seg_name, &tags, &num_tags))
	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		return (err);
	}
	if (num_tags == 0) {
		CHK_UNLOCK_CONTAINER(container);
		list->num = 0;
		list->strs = NULL;
		return (FRU_SUCCESS);
	}

	// allocate the memory for the names.
	rc_list.num = 0;
	rc_list.strs = (char **)malloc(num_tags * sizeof (char *));
	if (rc_list.strs == NULL) {
		CHK_UNLOCK_CONTAINER(container);
		free(tags);
		return (FRU_FAILURE);
	}

	// for each tag fill in it's name.
	for (i = 0; i < num_tags; i++) {
		const fru_regdef_t *def = fru_reg_lookup_def_by_tag(tags[i]);
		if (def != NULL) {
			rc_list.strs[i] = strdup(def->name);
			if (rc_list.strs[i] == NULL) {
				CHK_UNLOCK_CONTAINER(container);
				fru_destroy_strlist(&rc_list);
				free(tags);
				return (FRU_FAILURE);
			}
		} else {
			// instead of failing return "UNKNOWN"
			rc_list.strs[i] = strdup(UNKNOWN_PATH);
			if (rc_list.strs[i] == NULL) {
				CHK_UNLOCK_CONTAINER(container);
				fru_destroy_strlist(&rc_list);
				free(tags);
				return (FRU_FAILURE);
			}
		}
		rc_list.num++;
	}

	CHK_UNLOCK_CONTAINER(container);
	list->num = rc_list.num;
	list->strs = rc_list.strs;
	free(tags);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
/* Project-private interface */
extern "C" fru_errno_t
fru_for_each_segment(fru_nodehdl_t container,
			int (*function)(fru_seghdl_t segment, void *args),
			void *args)
{
	fru_errno_t	status;


	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	RETRY(status =
		data_source->for_each_segment(NODEHDL_TO_TREEHDL(container),
							function, args))
	CHK_UNLOCK_CONTAINER(container);
	return (status);
}

/* ========================================================================= */
/*
 * Project-private interface
 *
 * This routine is only safe when called from within fru_for_each_segment()
 * (which is currently the only way to get a segment handle) so that the
 * segment's container will be locked
 */
fru_errno_t
fru_get_segment_name(fru_seghdl_t segment, char **name)
{
	fru_errno_t	err = FRU_SUCCESS;

	assert(data_source != NULL);

	RETRY(err = data_source->get_segment_name(NODEHDL_TO_TREEHDL(segment),
									name))
	return (err);
}

/* ========================================================================= */
/*
 * Project-private interface
 *
 * This routine is only safe when called from within fru_for_each_segment()
 * (which is currently the only way to get a segment handle) so that the
 * segment's container will be locked
 */
extern "C" fru_errno_t
fru_for_each_packet(fru_seghdl_t segment,
			int (*function)(fru_tag_t *tag, uint8_t *payload,
					size_t length, void *args),
			void *args)
{
	fru_errno_t	err = FRU_SUCCESS;

	assert(data_source != NULL);

	RETRY(err = data_source->for_each_packet(NODEHDL_TO_TREEHDL(segment),
							function, args))
	return (err);
}


/* ========================================================================= */
// To keep track of the number of instances for each type of tag which
// might occur.
struct TagInstPair
{
	int inst;
	fru_tag_t tag;
};

struct tag_inst_hist_t
{
	TagInstPair *pairs;
	unsigned size;
	unsigned numStored;
};

static fru_errno_t
update_tag_inst_hist(tag_inst_hist_t *hist, fru_tag_t tag)
{
	// find if this tag has occured before.
	int found = 0;
	for (int s = 0; s < (hist->numStored); s++) {
		if (tags_equal((hist->pairs)[s].tag, tag)) {
		// if so just add to the instance.
			hist->pairs[s].inst++;
			found = 1;
			break;
		}
	}
	// if not add to the end of the array of instance 0.
	if (!found) {
		if (hist->numStored > hist->size) {
			return (FRU_FAILURE);
		}
		(hist->pairs)[(hist->numStored)].tag.raw_data = tag.raw_data;
		(hist->pairs)[(hist->numStored)].inst = 0;
		(hist->numStored)++;
	}
	return (FRU_SUCCESS);
}

static fru_errno_t
get_tag_inst_from_hist(tag_inst_hist_t *hist, fru_tag_t tag, int *instance)
{
	int j = 0;
	for (j = 0; j < hist->numStored; j++) {
		if (tags_equal((hist->pairs)[j].tag, tag)) {
			*instance = (hist->pairs)[j].inst;
			return (FRU_SUCCESS);
		}
	}
	return (FRU_FAILURE);
}

/* ========================================================================= */
// Input:
// a list of tags and number of them
// and an instance of the unknown payload you are looking for.
// Returns:
// on FRU_SUCCESS
// instance == the instance of the tag "tag" to read from the list
// else
// instance == the number of instances remaining.
//
static fru_errno_t
find_unknown_element(fru_tag_t *tags, int num_tags,
			int *instance, fru_tag_t *tag)
{
	fru_errno_t err = FRU_SUCCESS;

	tag_inst_hist_t hist;
	hist.pairs = (TagInstPair *)alloca(sizeof (TagInstPair) * num_tags);
	if (hist.pairs == NULL) {
		return (FRU_FAILURE);
	}
	hist.numStored = 0;
	hist.size = num_tags;

	// search all the tags untill they are exhausted or we find
	// the instance we want.
	int found = 0;
	int instFound = 0;
	// NOTE: instancesFound is a running total of the instances in the tags
	// WE SKIPED!
	// (ie instances left over == instance - instancesFound)

	int i = 0;
	for (i = 0; i < num_tags; i++) {

		const fru_regdef_t *def = fru_reg_lookup_def_by_tag(tags[i]);
		// unknown tag encountered.
		if (def == NULL) {
			if (update_tag_inst_hist(&hist, tags[i])
					!= FRU_SUCCESS) {
				return (FRU_FAILURE);
			}
			// do this check because everything is 0 based.
			// if we do the add before the check we will go
			// to far.
			if ((instFound + 1) > (*instance)) {
				found = 1;
				break;
			} else {
				instFound++;
			}
		}
	}

	*instance -= instFound;
	if (!found) {
		return (FRU_DATANOTFOUND);
	}

	(*tag).raw_data = tags[i].raw_data;
	if (get_tag_inst_from_hist(&hist, tags[i], instance) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	return (FRU_SUCCESS);
}

// Input:
// a list of tags and number of them
// a list of Ancestors
// the instance we are looking for
// Returns:
// on FRU_SUCCESS
// instance == the instance of the field within the payload to read.
// correct == pointer into ants which is correct.
// tagInstance == instance of the tag
// else
// instance == the number of instances remaining.
// correct == NULL
// tagInstance == UNDEFINED
//
static fru_errno_t
find_known_element(fru_tag_t *tags, int num_tags, Ancestor *ants,
			int *instance, Ancestor **correct,
			int *tagInstance)
{
	int j = 0;
	Ancestor *cur = ants;
	int num_posible = 0;
	while (cur != NULL) {
		num_posible++;
		cur = cur->next;
	}

	tag_inst_hist_t hist;
	hist.pairs = (TagInstPair *)alloca(sizeof (TagInstPair) * num_posible);
	hist.size = num_posible;
	if (hist.pairs == NULL) {
		return (FRU_FAILURE);
	}
	hist.numStored = 0;

	*correct = NULL;
	int i = 0;
	int found = 0;
	int instancesFound = 0;
	// NOTE: instancesFound is a running total of the instances in the tags
	//	WE SKIPED!
	//	(ie instances left over == instance - instancesFound)
	for (i = 0; i < num_tags; i++) {
		cur = ants;
		while (cur != NULL) {
			if (tags_equal(cur->getTag(), tags[i])) {
				if (update_tag_inst_hist(&hist, tags[i])
						!= FRU_SUCCESS) {
					return (FRU_FAILURE);
				}

				// do this check because everything is 0 based.
				// if we do the add before the check we will go
				// to far.
				if ((instancesFound + cur->getNumInstances())
						> (*instance)) {
					*correct = cur;
					found = 1;
					break; /* while loop */
				}
				instancesFound += cur->getNumInstances();
			}
			cur = cur->next;
		}
		/* when found break out of both "for" and "while" loops */
		if (found == 1) {
			break; /* for loop */
		}
	}

	*instance -= instancesFound;
	if (!found) {
		return (FRU_DATANOTFOUND);
	}

	if (get_tag_inst_from_hist(&hist, tags[i], tagInstance)
			!= FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	return (FRU_SUCCESS);
}

/*
 * Same as find_known_element but ONLY searches for absolute paths
 * (ie PathDef->head == tag)
 */
static fru_errno_t
find_known_element_abs(fru_tag_t *tags, int num_tags, int *instance,
		PathDef *head, Ancestor *ants, Ancestor **correct,
		int *tagInstance)
{
	*correct = NULL;
	// find the exact ancestor we want.
	Ancestor *cur = ants;
	while (cur != NULL) {
		if (strcmp(cur->getDef()->name, head->def->name) == 0) {
			*correct = cur;
			break;
		}
		cur = cur->next;
	}
	if (cur == NULL) {
		// serious parser bug might cause this, double check.
		return (FRU_FAILURE);
	}

	int found = 0;
	(*tagInstance) = 0;
	for (int i = 0; i < num_tags; i++) {
		if (tags_equal(cur->getTag(), tags[i])) {
			// do this check because everything is 0 based.
			// if we do the add before the check we will go
			// to far.
			if (((*tagInstance) +1) > (*instance)) {
				*correct = cur;
				found = 1;
				break;
			}
			(*tagInstance)++;
		}
	}

	*instance -= (*tagInstance);
	if (!found) {
		return (FRU_DATANOTFOUND);
	}

	return (FRU_SUCCESS);
}


/* ========================================================================= */
// From the container, seg_name, instance, and field_path get me...
// pathDef:	A linked list of Path Def objects which represent the
//		field_path
// ancestors:	A linked list of Tagged Ancestors which represent the
//		possible payloads this data MAY reside in.
// correct:	A pointer into the above list which indicates the Ancestor
//		in which this instance actually resides.
// tagInstance:	The instance of this ancestor in the segment.  (ie Tag
//		instance)
// instWICur:	The instance of this element within the tag itself.
//		Or in other words "the instances left"
// payload:	The payload data
//
// For an "UNKNOWN" payload this will return NULL for the pathDef, ancestors,
// cur pointers.  This will indicate to read that this payload should be
// returned with a special definition for it (UNKNOWN)...  What a HACK I
// know...
#define	READ_MODE 0
#define	UPDATE_MODE 1
static fru_errno_t get_payload(fru_nodehdl_t container,
			const char *seg_name,
			int instance,
			const char *field_path,
			// returns the following...
			PathDef **pathDef,
			Ancestor **ancestors,
			Ancestor **correct,
			int *tagInstance, // instance of the tag within the seg
			int *instLeft,    // within this payload
			uint8_t **payload,
			size_t *payloadLen,
			int mode)
{
	int abs_path_flg = 0;
	fru_errno_t err = FRU_SUCCESS;
	int num_tags = 0;
	fru_tag_t *tags = NULL;

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}
	RETRY(err = data_source->get_tag_list(NODEHDL_TO_TREEHDL(container),
						seg_name, &tags, &num_tags))
	if (err != FRU_SUCCESS) {
		return (err);
	}

	if (num_tags == 0) {
		*instLeft = instance;
		return (FRU_DATANOTFOUND);
	}

	if (IS_UNKNOWN_PATH(field_path)) {
		fru_tag_t tagToRead;

		*pathDef = NULL;
		*correct = *ancestors = NULL;
		*tagInstance = 0;

		int unknown_inst = instance;
		if ((err = find_unknown_element(tags, num_tags, &unknown_inst,
			&tagToRead)) != FRU_SUCCESS) {
			*instLeft = unknown_inst;
			free(tags);
			return (err);
		}
		RETRY(err =
			data_source->get_tag_data(NODEHDL_TO_TREEHDL(container),
				seg_name, tagToRead, unknown_inst, payload,
								payloadLen))
		free(tags);
		return (err);
	}

	err = fru_field_parser(field_path, ancestors,
					&abs_path_flg, pathDef);

	if (err != FRU_SUCCESS) {
		free(tags);
		return (err);
	} else if (ancestors == NULL) {
		/* without valid ancestors we can't find payloads for this */
		free(tags);
		delete pathDef;
		return (FRU_INVALELEMENT);
	}

	if ((mode == UPDATE_MODE) && (abs_path_flg != 1)) {
		free(tags);
		delete *ancestors; // linked list
		delete *pathDef;
		return (FRU_INVALPATH);
	}

	if (abs_path_flg == 1) {
		if ((err = find_known_element_abs(tags, num_tags, &instance,
				*pathDef, *ancestors, correct, tagInstance))
				!= FRU_SUCCESS) {
			// set up to search next segment for instances left
			// over
			*instLeft = instance;
			free(tags);
			delete *ancestors; // linked list
			delete *pathDef;
			return (err);
		}
	} else {
		if ((err = find_known_element(tags, num_tags, *ancestors,
				&instance, correct, tagInstance))
				!= FRU_SUCCESS) {
			// set up to search next segment for instances left
			// over
			*instLeft = instance;
			free(tags);
			delete *ancestors; // linked list
			delete *pathDef;
			return (err);
		}
	}

	// if we get here this means the instance number within the payload.
	*instLeft = instance;
	RETRY(err = data_source->get_tag_data(NODEHDL_TO_TREEHDL(container),
		seg_name, (*correct)->getTag(), (*tagInstance), payload,
								payloadLen))
	free(tags);
	if (err != FRU_SUCCESS) {
		delete *ancestors; // linked list
		delete *pathDef;
	}
	return (err);
}

/* ========================================================================= */
/*
 * Handle decryption if necessary
 */
static fru_errno_t
do_decryption(fru_nodehdl_t container, const char *seg_name,
		uint8_t *payload, size_t payloadLen)
{
	fru_errno_t err = FRU_SUCCESS;
	if (segment_is_encrypted(container, seg_name)) {
		if (fru_encryption_supported() == FRU_SUCCESS) {
			if ((err = encrypt_func(FRU_DECRYPT,
				payload, payloadLen)) != FRU_SUCCESS) {
				return (err);
			}
		} else {
			return (FRU_FAILURE);
		}
	}
	return (FRU_SUCCESS);
}

/* ========================================================================= */
// Same as get_payload except if seg_name is NULL and it will find the one
// used and return it.
//
static fru_errno_t
get_seg_and_payload(fru_nodehdl_t container,
			char **seg_name,
			int instance,
			const char *field_path,
			// returns the following...
			PathDef **pathDef,
			Ancestor **ancestors,
			Ancestor **correct,
			int *tagInstance, // within the segment.
			int *instLeft,   // within this payload
			uint8_t **payload,
			size_t *payloadLen)
{
	fru_errno_t err = FRU_SUCCESS;
	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (field_path == NULL)
		return (FRU_INVALPATH);

	if ((*seg_name) != NULL) {

		// always check for valid segment names.
		if (strlen((const char *)(*seg_name)) > FRU_SEGNAMELEN) {
			return (FRU_INVALSEG);
		}

		if ((err = get_payload(container, (const char *)(*seg_name),
			instance, field_path, pathDef, ancestors, correct,
			tagInstance, instLeft, payload, payloadLen, READ_MODE))
				!= FRU_SUCCESS) {
			return (err);
		}
		return (do_decryption(container, (const char *)(*seg_name),
				*payload, *payloadLen));

	} else {
		fru_strlist_t seg_list;

		if ((err = get_seg_list_from_ds(container, &seg_list))
			!= FRU_SUCCESS) {
			return (err);
		}

		int found = 0;
		for (int i = 0; i < seg_list.num; i++) {
			err = get_payload(container,
					seg_list.strs[i],
					instance, field_path,
					pathDef, ancestors, correct,
					tagInstance, instLeft,
					payload, payloadLen, READ_MODE);
			if (err == FRU_SUCCESS) {
				(*seg_name) = strdup(seg_list.strs[i]);
				fru_destroy_strlist(&seg_list);
				return (do_decryption(container,
						(const char *)(*seg_name),
						*payload, *payloadLen));
			} else if (err == FRU_DATANOTFOUND) {
				// we may have found some instances or none at
				// all but not enough all together.  search
				// again with the # of instances left.
				instance = *instLeft;
			} else {
				fru_destroy_strlist(&seg_list);
				return (err);
			}
		}
		fru_destroy_strlist(&seg_list);
		return (FRU_DATANOTFOUND);
	}
}

/* ========================================================================= */
fru_errno_t
fru_read_field(fru_nodehdl_t container,
		char **seg_name, unsigned int instance,
		const char *field_path,
		void **data, size_t *data_len,
		char **found_path)
{
	fru_errno_t err = FRU_SUCCESS;
	// just init this value for the user
	*data = NULL;
	*data_len = 0;

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	PathDef *pathDef;
	Ancestor *ancestors;
	Ancestor *correctAnt;
	int tagInstance = 0;
	int instWIPayload = 0;
	uint8_t *payload;
	size_t payloadLen = 0;
	err = get_seg_and_payload(container, seg_name, instance, field_path,
			&pathDef, &ancestors, &correctAnt, &tagInstance,
			&instWIPayload, &payload, &payloadLen);

	CHK_UNLOCK_CONTAINER(container);

	if (err != FRU_SUCCESS) {
		return (err);
	}

	if (pathDef == NULL) { // SPECIAL CASE of UNKNOW payload.
		delete ancestors;
		delete pathDef;
		free(payload);

		*data = (void *)malloc(payloadLen);
		if ((*data) == NULL) {
			return (FRU_FAILURE);
		}
		memcpy(*data, payload, payloadLen);
		*data_len = payloadLen;
		if (found_path != NULL) {
			*found_path = strdup(UNKNOWN_PATH);
		}
		return (FRU_SUCCESS);
	}

	// get the specific data
	err = PayloadReader::readData(pathDef, correctAnt,
					instWIPayload,
					payload, payloadLen,
					data, data_len);
	delete pathDef;
	free(payload);

	if (err == FRU_SUCCESS) {
		if (found_path != NULL) {
			*found_path = (char *)malloc(
				strlen(correctAnt->getPath(instWIPayload))
				+ strlen(field_path) + 2);
			if ((*found_path) == NULL) {
				delete ancestors;
				return (FRU_FAILURE);
			}
			sprintf(*found_path, "%s%s",
				correctAnt->getPath(instWIPayload),
					field_path);
		}
	}

	delete ancestors;
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_update_field(fru_nodehdl_t container,
		char *seg_name, unsigned int instance,
		const char *field_path,
		void *data, size_t length)
{
	fru_errno_t err = FRU_SUCCESS;

	if ((field_path == NULL) || IS_UNKNOWN_PATH(field_path)) {
		return (FRU_INVALPATH);
	} else if (seg_name == NULL) {
		return (FRU_INVALSEG);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if (lock_container(WRITE_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	PathDef *pathDef;
	Ancestor *ancestors;
	Ancestor *correctAnt;
	int tagInstance = 0;
	int instWIPayload = 0;
	uint8_t *payload;
	size_t payloadLen = 0;
	err = get_payload(container, seg_name, instance, field_path,
			&pathDef, &ancestors, &correctAnt, &tagInstance,
			&instWIPayload, &payload, &payloadLen, UPDATE_MODE);

	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		return (err);
	}

	if ((err = do_decryption(container, (const char *)seg_name,
				payload, payloadLen)) != FRU_SUCCESS) {
		free(payload);
		return (err);
	}

	// fill in the new data in the payload
	err = PayloadReader::updateData(pathDef, correctAnt, instWIPayload,
					payload, payloadLen,
					data, length);

	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		delete ancestors; // linked list.
		delete pathDef;
		free(payload);
		return (err);
	}

	if ((segment_is_encrypted(container, seg_name)) &&
		(fru_encryption_supported() == FRU_SUCCESS)) {
		if ((err = encrypt_func(FRU_ENCRYPT, payload, payloadLen))
			!= FRU_SUCCESS) {
			CHK_UNLOCK_CONTAINER(container);
			delete ancestors; // linked list.
			delete pathDef;
			free(payload);
			return (err);
		}
	}

	RETRY(err = data_source->set_tag_data(NODEHDL_TO_TREEHDL(container),
					seg_name, correctAnt->getTag(),
					tagInstance, payload, payloadLen))
	CHK_UNLOCK_CONTAINER(container);
	delete ancestors; // linked list.
	free(payload);
	delete pathDef;
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_get_num_iterations(fru_nodehdl_t container,
			char **seg_name,
			unsigned int instance,
			const char *iter_path,
			int *num_there,
			char **found_path)
{
	// this ensures a more descriptive error message.
	fru_errno_t err = FRU_SUCCESS;

	if (lock_container(READ_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	PathDef *pathDef;
	Ancestor *ancestors;
	Ancestor *correctAnt;
	int tagInstance = 0;
	int instWIPayload = 0;
	uint8_t *payload;
	size_t payloadLen = 0;
	err = get_seg_and_payload(container, seg_name, instance, iter_path,
			&pathDef, &ancestors, &correctAnt, &tagInstance,
			&instWIPayload, &payload, &payloadLen);

	CHK_UNLOCK_CONTAINER(container);

	if (err != FRU_SUCCESS) {
		return (err);
	}

	if (pathDef == NULL) { // SPECIAL CASE of UNKNOW payload.
		// clean up memory from called functions.
		err = FRU_INVALPATH;
	} else {
		// get the specific data
		err = PayloadReader::findIterThere(pathDef, correctAnt,
						instWIPayload,
						payload, payloadLen,
						num_there);
	}

	delete pathDef;
	free(payload);

	if (err == FRU_SUCCESS) {
		if (found_path != NULL) {
			*found_path = (char *)malloc(
				strlen(correctAnt->getPath(instWIPayload))
				+ strlen(iter_path) + 2);
			if ((*found_path) == NULL) {
				delete ancestors;
				return (FRU_FAILURE);
			}
			sprintf(*found_path, "%s%s",
					correctAnt->getPath(instWIPayload),
					iter_path);
		}
	}

	delete ancestors;
	return (err);
}

/* ========================================================================= */
// When adding a new payload with 0 data the iteration control bytes must be
// filled in with the number possible.
fru_errno_t
fill_in_iteration_control_bytes(uint8_t *data,
				const fru_regdef_t *def,
				int inIteration)
{
	fru_errno_t rc = FRU_SUCCESS;

	if ((def->iterationType == FRU_NOT_ITERATED) ||
		(inIteration)) {

		if (def->dataType == FDTYPE_Record) {

			int offset = 0;
			for (int i = 0; i < def->enumCount; i++) {
				const fru_regdef_t *newDef
	= fru_reg_lookup_def_by_name((char *)def->enumTable[i].text);
				fru_errno_t rc2
	= fill_in_iteration_control_bytes(&(data[offset]), newDef, 0);
				if (rc2 != FRU_SUCCESS)
					return (rc2);
				offset += newDef->payloadLen;
			}

		} // else field, no sub elements; do nothing...  ;-)

	} else {
		data[3] = (char)def->iterationCount;

		int offset = 3;
		for (int i = 0; i < def->iterationCount; i++) {
			fru_errno_t rc3
	= fill_in_iteration_control_bytes(&(data[offset]), def, 1);
			if (rc3 != FRU_SUCCESS)
				return (rc3);
			offset += ((def->payloadLen - 4)/(def->iterationCount));
		}
	}

	return (rc);
}

/* ========================================================================= */
fru_errno_t
fru_add_element(fru_nodehdl_t container,
	const char *seg_name,
	const char *element)
{
	fru_errno_t err = FRU_SUCCESS;

	if ((seg_name == NULL) || (strlen(seg_name) > FRU_SEGNAMELEN)) {
		return (FRU_INVALSEG);
	}

	const fru_regdef_t *def
		= fru_reg_lookup_def_by_name((char *)element);
	if (def == NULL) {
		return (FRU_NOREGDEF);
	}
	if (def->tagType == FRU_X) {
		return (FRU_ELEMNOTTAGGED);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(WRITE_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}

	fru_tag_t tag;
	mk_tag(def->tagType, def->tagDense, def->payloadLen, &tag);
	uint8_t *data = new uint8_t[def->payloadLen];
	memset(data, 0x00, def->payloadLen);

	err = fill_in_iteration_control_bytes(data, def, 0);
	if (err != FRU_SUCCESS) {
		CHK_UNLOCK_CONTAINER(container);
		delete[] data;
		return (err);
	}

	if (segment_is_encrypted(container, seg_name)) {
		if (fru_encryption_supported() == FRU_NOTSUP) {
			CHK_UNLOCK_CONTAINER(container);
			delete[] data;
			return (FRU_INVALSEG);
		}
		if ((err = encrypt_func(FRU_ENCRYPT, data,
				def->payloadLen)) != FRU_SUCCESS) {
			CHK_UNLOCK_CONTAINER(container);
			delete[] data;
			return (err);
		}
	}
	
	RETRY(err = data_source->add_tag_to_seg(NODEHDL_TO_TREEHDL(container),
					seg_name, tag, data, def->payloadLen))
	CHK_UNLOCK_CONTAINER(container);
	delete[] data;
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_delete_element(fru_nodehdl_t container,
		const char *seg_name,
		unsigned int   instance,
		const char *element)
{
	fru_errno_t err = FRU_SUCCESS;

	if ((seg_name == NULL) || (strlen(seg_name) > FRU_SEGNAMELEN)) {
		return (FRU_INVALSEG);
	}

	if (data_source == NULL) {
		return (FRU_FAILURE);
	}

	if ((err = is_container(container)) != FRU_SUCCESS) {
		return (err);
	}

	if (lock_container(WRITE_LOCK, container) != FRU_SUCCESS) {
		return (FRU_FAILURE);
	}
	if ((segment_is_encrypted(container, seg_name)) &&
		(fru_encryption_supported() == FRU_NOTSUP)) {
		CHK_UNLOCK_CONTAINER(container);
		return (FRU_INVALSEG);
	}

	fru_tag_t tag;
	int localInst = instance;
	// again the special case of UNKNOWN.  This allows us to delete these
	// elements if they are somehow not wanted.
	// NOTE: "/UNKNOWN" is not supported just as "/ManR" would not be valid
	// either.  Both of these will result in returning FRU_NOREGDEF
	if (strcmp(element, "UNKNOWN") == 0) {
		fru_tag_t *tags = NULL;
		int num_tags = 0;

		RETRY(err =
			data_source->get_tag_list(NODEHDL_TO_TREEHDL(container),
						seg_name, &tags, &num_tags))
							
		if (err != FRU_SUCCESS) {
			CHK_UNLOCK_CONTAINER(container);
			return (err);
		}
		if ((err = find_unknown_element(tags, num_tags,
			&localInst, &tag)) != FRU_SUCCESS) {
			free(tags);
			CHK_UNLOCK_CONTAINER(container);
			return (err);
		}
		free(tags);
	} else {
		const fru_regdef_t *def
			= fru_reg_lookup_def_by_name((char *)element);
		if (def == NULL) {
			CHK_UNLOCK_CONTAINER(container);
			return (FRU_NOREGDEF);
		}
		if (def->tagType == FRU_X) {
			CHK_UNLOCK_CONTAINER(container);
			return (FRU_ELEMNOTTAGGED);
		}
		mk_tag(def->tagType, def->tagDense, def->payloadLen, &tag);
	}
	
	RETRY(err = data_source->delete_tag(NODEHDL_TO_TREEHDL(container),
						seg_name, tag, instance))
	CHK_UNLOCK_CONTAINER(container);
	return (err);
}

/* General library support */
/* ========================================================================= */
static fru_errno_t
make_definition(const fru_regdef_t *def, fru_elemdef_t *definition)
{
	definition->version = FRU_ELEMDEF_REV;
	definition->data_type = def->dataType;
	if (def->tagType != FRU_X)
		definition->tagged = FRU_Yes;
	else
		definition->tagged = FRU_No;

	// zzz
	// This should be the following statement.
	// (*definition)->data_length = def->dataLength;
	// instead of.
	if (def->iterationType != FRU_NOT_ITERATED) {
		int elemLen = ((def->dataLength-4)/def->iterationCount);
		definition->data_length = elemLen;
	} else {
		definition->data_length = def->dataLength;
	}
	// END zzz

	definition->disp_type = def->dispType;
	definition->purgeable = def->purgeable;
	definition->relocatable = def->relocatable;

	definition->enum_count = 0;
	definition->enum_table = NULL;

	unsigned int count = def->enumCount;
	if (count != 0) {
		definition->enum_table = (fru_enum_t *)malloc(
					(sizeof (fru_enum_t)) * count);
		if ((definition->enum_table) == NULL) {
			return (FRU_FAILURE);
		}
		memset(definition->enum_table, 0x00,
					((sizeof (fru_enum_t)) * count));
	}

	for (int i = 0; i < count; i++) {
		definition->enum_table[i].value = def->enumTable[i].value;
		definition->enum_table[i].text = strdup(def->enumTable[i].text);
		if ((definition->enum_table[i].text) == NULL) {
			fru_destroy_elemdef(definition);
			return (FRU_FAILURE);
		}
		(definition->enum_count)++;
	}

	definition->iteration_count = def->iterationCount;
	definition->iteration_type = def->iterationType;

	definition->example_string = strdup(def->exampleString);
	if ((definition->example_string) == NULL) {
		fru_destroy_elemdef(definition);
		return (FRU_FAILURE);
	}

	return (FRU_SUCCESS);
}

/* ========================================================================= */
fru_errno_t
fru_get_definition(const char *element_name,
			fru_elemdef_t *definition)
{
	// find the last one in the string...
	int abs_path_flg = 0;
	Ancestor *ancestors = NULL;
	PathDef *pathDef = NULL;
	fru_errno_t err = FRU_SUCCESS;

	err = fru_field_parser(element_name, &ancestors,
					&abs_path_flg, &pathDef);
	if (err != FRU_SUCCESS) {
		return (err);
	}

	PathDef *last = pathDef;
	while (last->next != NULL)
		last = last->next;

	err = make_definition(last->def, definition);

	delete ancestors;
	delete pathDef;
	return (err);
}

/* ========================================================================= */
fru_errno_t
fru_get_registry(fru_strlist_t *list)
{
	fru_errno_t err = FRU_SUCCESS;
	unsigned int number = 0;
	char **entries = fru_reg_list_entries(&number);
	if (entries == NULL) {
		return (FRU_FAILURE);
	}
	list->strs = entries;
	list->num = number;
	return (FRU_SUCCESS);
}

/* ========================================================================= */
fru_errno_t
fru_get_tagged_parents(const char *element, fru_strlist_t *parents)
{
	Ancestor *ancestors
		= Ancestor::listTaggedAncestors((char *)element);

	Ancestor *cur = ancestors;
	/* count them */
	int number = 0;
	while (cur != NULL) {
		number++;
		cur = cur->next;
	}

	parents->num = 0;
	parents->strs = NULL;
	if (number == 0) {
		return (FRU_SUCCESS);
	}
	parents->strs = (char **)malloc(number * sizeof (char *));
	if (parents->strs == NULL) {
		return (FRU_FAILURE);
	}
	memset(parents->strs, 0x00, (number * sizeof (char *)));

	cur = ancestors;
	for (int i = 0; i < number; i++) {
		if (cur == NULL) {
			fru_destroy_strlist(parents);
			return (FRU_FAILURE);
		}
		parents->strs[i] = strdup(cur->getDef()->name);
		if (parents->strs[i] == NULL) {
			fru_destroy_strlist(parents);
			return (FRU_FAILURE);
		}
		parents->num++;
		cur = cur->next;
	}

	return (FRU_SUCCESS);
}

/*
 * Enum string converters.
 */
/* ========================================================================= */
const char *
get_displaytype_str(fru_displaytype_t e)
{
	switch (e) {
		case FDISP_Binary:
			return (gettext("Binary"));
		case FDISP_Hex:
			return (gettext("Hex"));
		case FDISP_Decimal:
			return (gettext("Decimal"));
		case FDISP_Octal:
			return (gettext("Octal"));
		case FDISP_String:
			return (gettext("String"));
		case FDISP_Time:
			return (gettext("Time"));
		case FDISP_UNDEFINED:
			return (gettext("UNDEFINED"));
	}
	return (gettext("UNDEFINED"));
}

/* ========================================================================= */
const char *
get_datatype_str(fru_datatype_t e)
{
	switch (e) {
		case FDTYPE_Binary:
			return (gettext("Binary"));
		case FDTYPE_ByteArray:
			return (gettext("Byte Array"));
		case FDTYPE_ASCII:
			return (gettext("ASCII"));
		case FDTYPE_Unicode:
			return (gettext("Unicode"));
		case FDTYPE_Record:
			return (gettext("Record"));
		case FDTYPE_Enumeration:
			return (gettext("Enumeration"));
		case FDTYPE_UNDEFINED:
			return (gettext("UNDEFINED"));
	}
	return (gettext("UNDEFINED"));
}
/* ========================================================================= */
const char *
get_which_str(fru_which_t e)
{
	switch (e) {
		case FRU_No:
			return (gettext("No"));
		case FRU_Yes:
			return (gettext("Yes"));
		case FRU_WHICH_UNDEFINED:
			return (gettext("WHICH UNDEFINED"));
	}
	return (gettext("WHICH UNDEFINED"));
}
/* ========================================================================= */
const char *
get_itertype_str(fru_itertype_t e)
{
	switch (e) {
		case FRU_FIFO:
			return (gettext("FIFO"));
		case FRU_Circular:
			return (gettext("Circular"));
		case FRU_Linear:
			return (gettext("Linear"));
		case FRU_LIFO:
			return (gettext("LIFO"));
		case FRU_NOT_ITERATED:
			return (gettext("NOT ITERATED"));
	}
	return (gettext("NOT ITERATED"));
}
