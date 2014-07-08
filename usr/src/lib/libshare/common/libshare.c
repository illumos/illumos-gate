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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Share control API
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <libscf.h>
#include "scfutil.h"
#include <ctype.h>
#include <libintl.h>
#include <thread.h>
#include <synch.h>

#define	DFS_LOCK_FILE	"/etc/dfs/fstypes"
#define	SA_STRSIZE	256	/* max string size for names */

/*
 * internal object type values returned by sa_get_object_type()
 */
#define	SA_TYPE_UNKNOWN		0
#define	SA_TYPE_GROUP		1
#define	SA_TYPE_SHARE		2
#define	SA_TYPE_RESOURCE	3
#define	SA_TYPE_OPTIONSET	4
#define	SA_TYPE_ALTSPACE	5

/*
 * internal data structures
 */

extern struct sa_proto_plugin *sap_proto_list;

/* current SMF/SVC repository handle */
extern void getlegacyconfig(sa_handle_t, char *, xmlNodePtr *);
extern int gettransients(sa_handle_impl_t, xmlNodePtr *);
extern char *sa_fstype(char *);
extern int sa_is_share(void *);
extern int sa_is_resource(void *);
extern ssize_t scf_max_name_len; /* defined in scfutil during initialization */
extern int sa_group_is_zfs(sa_group_t);
extern int sa_path_is_zfs(char *);
extern int sa_zfs_set_sharenfs(sa_group_t, char *, int);
extern int sa_zfs_set_sharesmb(sa_group_t, char *, int);
extern void update_legacy_config(sa_handle_t);
extern int issubdir(char *, char *);
extern int sa_zfs_init(sa_handle_impl_t);
extern void sa_zfs_fini(sa_handle_impl_t);
extern void sablocksigs(sigset_t *);
extern void saunblocksigs(sigset_t *);
static sa_group_t sa_get_optionset_parent(sa_optionset_t);
static char *get_node_attr(void *, char *);
extern void sa_update_sharetab_ts(sa_handle_t);

/*
 * Data structures for finding/managing the document root to access
 * handle mapping. The list isn't expected to grow very large so a
 * simple list is acceptable. The purpose is to provide a way to start
 * with a group or share and find the library handle needed for
 * various operations.
 */
mutex_t sa_global_lock;
struct doc2handle {
	struct doc2handle	*next;
	xmlNodePtr		root;
	sa_handle_impl_t	handle;
};

mutex_t sa_dfstab_lock;

/* definitions used in a couple of property functions */
#define	SA_PROP_OP_REMOVE	1
#define	SA_PROP_OP_ADD		2
#define	SA_PROP_OP_UPDATE	3

static struct doc2handle *sa_global_handles = NULL;

/* helper functions */

/*
 * sa_errorstr(err)
 *
 * convert an error value to an error string
 */

char *
sa_errorstr(int err)
{
	static char errstr[32];
	char *ret = NULL;

	switch (err) {
	case SA_OK:
		ret = dgettext(TEXT_DOMAIN, "ok");
		break;
	case SA_NO_SUCH_PATH:
		ret = dgettext(TEXT_DOMAIN, "path doesn't exist");
		break;
	case SA_NO_MEMORY:
		ret = dgettext(TEXT_DOMAIN, "no memory");
		break;
	case SA_DUPLICATE_NAME:
		ret = dgettext(TEXT_DOMAIN, "name in use");
		break;
	case SA_BAD_PATH:
		ret = dgettext(TEXT_DOMAIN, "bad path");
		break;
	case SA_NO_SUCH_GROUP:
		ret = dgettext(TEXT_DOMAIN, "no such group");
		break;
	case SA_CONFIG_ERR:
		ret = dgettext(TEXT_DOMAIN, "configuration error");
		break;
	case SA_SYSTEM_ERR:
		ret = dgettext(TEXT_DOMAIN, "system error");
		break;
	case SA_SYNTAX_ERR:
		ret = dgettext(TEXT_DOMAIN, "syntax error");
		break;
	case SA_NO_PERMISSION:
		ret = dgettext(TEXT_DOMAIN, "no permission");
		break;
	case SA_BUSY:
		ret = dgettext(TEXT_DOMAIN, "busy");
		break;
	case SA_NO_SUCH_PROP:
		ret = dgettext(TEXT_DOMAIN, "no such property");
		break;
	case SA_INVALID_NAME:
		ret = dgettext(TEXT_DOMAIN, "invalid name");
		break;
	case SA_INVALID_PROTOCOL:
		ret = dgettext(TEXT_DOMAIN, "invalid protocol");
		break;
	case SA_NOT_ALLOWED:
		ret = dgettext(TEXT_DOMAIN, "operation not allowed");
		break;
	case SA_BAD_VALUE:
		ret = dgettext(TEXT_DOMAIN, "bad property value");
		break;
	case SA_INVALID_SECURITY:
		ret = dgettext(TEXT_DOMAIN, "invalid security type");
		break;
	case SA_NO_SUCH_SECURITY:
		ret = dgettext(TEXT_DOMAIN, "security type not found");
		break;
	case SA_VALUE_CONFLICT:
		ret = dgettext(TEXT_DOMAIN, "property value conflict");
		break;
	case SA_NOT_IMPLEMENTED:
		ret = dgettext(TEXT_DOMAIN, "not implemented");
		break;
	case SA_INVALID_PATH:
		ret = dgettext(TEXT_DOMAIN, "invalid path");
		break;
	case SA_NOT_SUPPORTED:
		ret = dgettext(TEXT_DOMAIN, "operation not supported");
		break;
	case SA_PROP_SHARE_ONLY:
		ret = dgettext(TEXT_DOMAIN, "property not valid for group");
		break;
	case SA_NOT_SHARED:
		ret = dgettext(TEXT_DOMAIN, "not shared");
		break;
	case SA_NO_SUCH_RESOURCE:
		ret = dgettext(TEXT_DOMAIN, "no such resource");
		break;
	case SA_RESOURCE_REQUIRED:
		ret = dgettext(TEXT_DOMAIN, "resource name required");
		break;
	case SA_MULTIPLE_ERROR:
		ret = dgettext(TEXT_DOMAIN, "errors from multiple protocols");
		break;
	case SA_PATH_IS_SUBDIR:
		ret = dgettext(TEXT_DOMAIN, "path is a subpath of share");
		break;
	case SA_PATH_IS_PARENTDIR:
		ret = dgettext(TEXT_DOMAIN, "path is parent of a share");
		break;
	case SA_NO_SECTION:
		ret = dgettext(TEXT_DOMAIN, "protocol requires a section");
		break;
	case SA_NO_PROPERTIES:
		ret = dgettext(TEXT_DOMAIN, "properties not found");
		break;
	case SA_NO_SUCH_SECTION:
		ret = dgettext(TEXT_DOMAIN, "section not found");
		break;
	case SA_PASSWORD_ENC:
		ret = dgettext(TEXT_DOMAIN, "passwords must be encrypted");
		break;
	case SA_SHARE_EXISTS:
		ret = dgettext(TEXT_DOMAIN, "path or file is already shared");
		break;
	default:
		(void) snprintf(errstr, sizeof (errstr),
		    dgettext(TEXT_DOMAIN, "unknown %d"), err);
		ret = errstr;
	}
	return (ret);
}

/*
 * Document root to active handle mapping functions.  These are only
 * used internally. A mutex is used to prevent access while the list
 * is changing. In general, the list will be relatively short - one
 * item per thread that has called sa_init().
 */

sa_handle_impl_t
get_handle_for_root(xmlNodePtr root)
{
	struct doc2handle *item;

	(void) mutex_lock(&sa_global_lock);
	for (item = sa_global_handles; item != NULL; item = item->next) {
		if (item->root == root)
			break;
	}
	(void) mutex_unlock(&sa_global_lock);
	if (item != NULL)
		return (item->handle);
	return (NULL);
}

static int
add_handle_for_root(xmlNodePtr root, sa_handle_impl_t handle)
{
	struct doc2handle *item;
	int ret = SA_NO_MEMORY;

	item = (struct doc2handle *)calloc(sizeof (struct doc2handle), 1);
	if (item != NULL) {
		item->root = root;
		item->handle = handle;
		(void) mutex_lock(&sa_global_lock);
		item->next = sa_global_handles;
		sa_global_handles = item;
		(void) mutex_unlock(&sa_global_lock);
		ret = SA_OK;
	}
	return (ret);
}

/*
 * remove_handle_for_root(root)
 *
 * Walks the list of handles and removes the one for this "root" from
 * the list. It is up to the caller to free the data.
 */

static void
remove_handle_for_root(xmlNodePtr root)
{
	struct doc2handle *item, *prev;

	(void) mutex_lock(&sa_global_lock);
	for (prev = NULL, item = sa_global_handles; item != NULL;
	    item = item->next) {
		if (item->root == root) {
			/* first in the list */
			if (prev == NULL)
				sa_global_handles = sa_global_handles->next;
			else
				prev->next = item->next;
			/* Item is out of the list so free the list structure */
			free(item);
			break;
		}
		prev = item;
	}
	(void) mutex_unlock(&sa_global_lock);
}

/*
 * sa_find_group_handle(sa_group_t group)
 *
 * Find the sa_handle_t for the configuration associated with this
 * group.
 */
sa_handle_t
sa_find_group_handle(sa_group_t group)
{
	xmlNodePtr node = (xmlNodePtr)group;
	sa_handle_t handle;

	while (node != NULL) {
		if (strcmp((char *)(node->name), "sharecfg") == 0) {
			/* have the root so get the handle */
			handle = (sa_handle_t)get_handle_for_root(node);
			return (handle);
		}
		node = node->parent;
	}
	return (NULL);
}

/*
 * set_legacy_timestamp(root, path, timevalue)
 *
 * add the current timestamp value to the configuration for use in
 * determining when to update the legacy files.  For SMF, this
 * property is kept in default/operation/legacy_timestamp
 */

static void
set_legacy_timestamp(xmlNodePtr root, char *path, uint64_t tval)
{
	xmlNodePtr node;
	xmlChar *lpath = NULL;
	sa_handle_impl_t handle;

	/* Have to have a handle or else we weren't initialized. */
	handle = get_handle_for_root(root);
	if (handle == NULL)
		return;

	for (node = root->xmlChildrenNode; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"legacy") == 0) {
			/* a possible legacy node for this path */
			lpath = xmlGetProp(node, (xmlChar *)"path");
			if (lpath != NULL &&
			    xmlStrcmp(lpath, (xmlChar *)path) == 0) {
				xmlFree(lpath);
				break;
			}
			if (lpath != NULL)
				xmlFree(lpath);
		}
	}
	if (node == NULL) {
		/* need to create the first legacy timestamp node */
		node = xmlNewChild(root, NULL, (xmlChar *)"legacy", NULL);
	}
	if (node != NULL) {
		char tstring[32];
		int ret;

		(void) snprintf(tstring, sizeof (tstring), "%lld", tval);
		(void) xmlSetProp(node, (xmlChar *)"timestamp",
		    (xmlChar *)tstring);
		(void) xmlSetProp(node, (xmlChar *)"path", (xmlChar *)path);
		/* now commit to SMF */
		ret = sa_get_instance(handle->scfhandle, "default");
		if (ret == SA_OK) {
			ret = sa_start_transaction(handle->scfhandle,
			    "operation");
			if (ret == SA_OK) {
				ret = sa_set_property(handle->scfhandle,
				    "legacy-timestamp", tstring);
				if (ret == SA_OK) {
					(void) sa_end_transaction(
					    handle->scfhandle, handle);
				} else {
					sa_abort_transaction(handle->scfhandle);
				}
			}
		}
	}
}

/*
 * is_shared(share)
 *
 * determine if the specified share is currently shared or not.
 */
static int
is_shared(sa_share_t share)
{
	char *shared;
	int result = 0; /* assume not */

	shared = sa_get_share_attr(share, "shared");
	if (shared != NULL) {
		if (strcmp(shared, "true") == 0)
			result = 1;
		sa_free_attr_string(shared);
	}
	return (result);
}

/*
 * excluded_protocol(share, proto)
 *
 * Returns B_TRUE if the specified protocol appears in the "exclude"
 * property. This is used to prevent sharing special case shares
 * (e.g. subdirs when SMB wants a subdir and NFS doesn't. B_FALSE is
 * returned if the protocol isn't in the list.
 */
static boolean_t
excluded_protocol(sa_share_t share, char *proto)
{
	char *protolist;
	char *str;
	char *token;

	protolist = sa_get_share_attr(share, "exclude");
	if (protolist != NULL) {
		str = protolist;
		while ((token = strtok(str, ",")) != NULL) {
			if (strcmp(token, proto) == 0) {
				sa_free_attr_string(protolist);
				return (B_TRUE);
			}
			str = NULL;
		}
		sa_free_attr_string(protolist);
	}
	return (B_FALSE);
}

/*
 * checksubdirgroup(group, newpath, strictness)
 *
 * check all the specified newpath against all the paths in the
 * group. This is a helper function for checksubdir to make it easier
 * to also check ZFS subgroups.
 * The strictness values mean:
 * SA_CHECK_NORMAL == only check newpath against shares that are active
 * SA_CHECK_STRICT == check newpath against both active shares and those
 *		      stored in the repository
 */
static int
checksubdirgroup(sa_group_t group, char *newpath, int strictness)
{
	sa_share_t share;
	char *path;
	int issub = SA_OK;
	int subdir;
	int parent;

	if (newpath == NULL)
		return (SA_INVALID_PATH);

	for (share = sa_get_share(group, NULL); share != NULL;
	    share = sa_get_next_share(share)) {
		/*
		 * The original behavior of share never checked
		 * against the permanent configuration
		 * (/etc/dfs/dfstab).  PIT has a number of cases where
		 * it depends on this older behavior even though it
		 * could be considered incorrect.  We may tighten this
		 * up in the future.
		 */
		if (strictness == SA_CHECK_NORMAL && !is_shared(share))
			continue;

		path = sa_get_share_attr(share, "path");
		/*
		 * If path is NULL, then a share is in the process of
		 * construction or someone has modified the property
		 * group inappropriately. It should be
		 * ignored. issubdir() comes from the original share
		 * implementation and does the difficult part of
		 * checking subdirectories.
		 */
		if (path == NULL)
			continue;

		if (strcmp(path, newpath) == 0) {
			issub = SA_INVALID_PATH;
		} else {
			subdir = issubdir(newpath, path);
			parent = issubdir(path, newpath);
			if (subdir || parent) {
				sa_free_attr_string(path);
				path = NULL;
				return (subdir ?
				    SA_PATH_IS_SUBDIR : SA_PATH_IS_PARENTDIR);
			}
		}
		sa_free_attr_string(path);
		path = NULL;
	}
	return (issub);
}

/*
 * checksubdir(newpath, strictness)
 *
 * checksubdir determines if the specified path (newpath) is a
 * subdirectory of another share. It calls checksubdirgroup() to do
 * the complicated work. The strictness parameter determines how
 * strict a check to make against the path. The strictness values
 * mean: SA_CHECK_NORMAL == only check newpath against shares that are
 * active SA_CHECK_STRICT == check newpath against both active shares
 * and those * stored in the repository
 */
static int
checksubdir(sa_handle_t handle, char *newpath, int strictness)
{
	sa_group_t group;
	int issub = SA_OK;
	char *path = NULL;

	for (group = sa_get_group(handle, NULL);
	    group != NULL && issub == SA_OK;
	    group = sa_get_next_group(group)) {
		if (sa_group_is_zfs(group)) {
			sa_group_t subgroup;
			for (subgroup = sa_get_sub_group(group);
			    subgroup != NULL && issub == SA_OK;
			    subgroup = sa_get_next_group(subgroup))
				issub = checksubdirgroup(subgroup, newpath,
				    strictness);
		} else {
			issub = checksubdirgroup(group, newpath, strictness);
		}
	}
	if (path != NULL)
		sa_free_attr_string(path);
	return (issub);
}

/*
 * validpath(path, strictness)
 * determine if the provided path is valid for a share. It shouldn't
 * be a sub-dir of an already shared path or the parent directory of a
 * share path.
 */
static int
validpath(sa_handle_t handle, char *path, int strictness)
{
	int error = SA_OK;
	struct stat st;
	sa_share_t share;
	char *fstype;

	if (*path != '/')
		return (SA_BAD_PATH);

	if (stat(path, &st) < 0) {
		error = SA_NO_SUCH_PATH;
	} else {
		share = sa_find_share(handle, path);
		if (share != NULL)
			error = SA_DUPLICATE_NAME;

		if (error == SA_OK) {
			/*
			 * check for special case with file system
			 * that might have restrictions.  For now, ZFS
			 * is the only case since it has its own idea
			 * of how to configure shares. We do this
			 * before subdir checking since things like
			 * ZFS will do that for us. This should also
			 * be done via plugin interface.
			 */
			fstype = sa_fstype(path);
			if (fstype != NULL && strcmp(fstype, "zfs") == 0) {
				if (sa_zfs_is_shared(handle, path))
					error = SA_INVALID_NAME;
			}
			if (fstype != NULL)
				sa_free_fstype(fstype);
		}
		if (error == SA_OK)
			error = checksubdir(handle, path, strictness);
	}
	return (error);
}

/*
 * check to see if group/share is persistent.
 *
 * "group" can be either an sa_group_t or an sa_share_t. (void *)
 * works since both these types are also void *.
 * If the share is a ZFS share, mark it as persistent.
 */
int
sa_is_persistent(void *group)
{
	char *type;
	int persist = 1;
	sa_group_t grp;

	type = sa_get_group_attr((sa_group_t)group, "type");
	if (type != NULL) {
		if (strcmp(type, "transient") == 0)
			persist = 0;
		sa_free_attr_string(type);
	}

	grp = (sa_is_share(group)) ? sa_get_parent_group(group) : group;
	if (sa_group_is_zfs(grp))
		persist = 1;

	return (persist);
}

/*
 * sa_valid_group_name(name)
 *
 * check that the "name" contains only valid characters and otherwise
 * fits the required naming conventions. Valid names must start with
 * an alphabetic and the remainder may consist of only alphanumeric
 * plus the '-' and '_' characters. This name limitation comes from
 * inherent limitations in SMF.
 */

int
sa_valid_group_name(char *name)
{
	int ret = 1;
	ssize_t len;

	if (name != NULL && isalpha(*name)) {
		char c;
		len = strlen(name);
		if (len < (scf_max_name_len - sizeof ("group:"))) {
			for (c = *name++; c != '\0' && ret != 0; c = *name++) {
				if (!isalnum(c) && c != '-' && c != '_')
					ret = 0;
			}
		} else {
			ret = 0;
		}
	} else {
		ret = 0;
	}
	return (ret);
}


/*
 * is_zfs_group(group)
 *	Determine if the specified group is a ZFS sharenfs group
 */
static int
is_zfs_group(sa_group_t group)
{
	int ret = 0;
	xmlNodePtr parent;
	xmlChar *zfs;

	if (strcmp((char *)((xmlNodePtr)group)->name, "share") == 0)
		parent = (xmlNodePtr)sa_get_parent_group(group);
	else
		parent = (xmlNodePtr)group;
	zfs = xmlGetProp(parent, (xmlChar *)"zfs");
	if (zfs != NULL) {
		xmlFree(zfs);
		ret = 1;
	}
	return (ret);
}

/*
 * sa_get_object_type(object)
 *
 * This function returns a numeric value representing the object
 * type. This allows using simpler checks when doing type specific
 * operations.
 */

static int
sa_get_object_type(void *object)
{
	xmlNodePtr node = (xmlNodePtr)object;
	int type;

	if (xmlStrcmp(node->name, (xmlChar *)"group") == 0)
		type = SA_TYPE_GROUP;
	else if (xmlStrcmp(node->name, (xmlChar *)"share") == 0)
		type = SA_TYPE_SHARE;
	else if (xmlStrcmp(node->name, (xmlChar *)"resource") == 0)
		type = SA_TYPE_RESOURCE;
	else if (xmlStrcmp(node->name, (xmlChar *)"optionset") == 0)
		type = SA_TYPE_OPTIONSET;
	else if (xmlStrcmp(node->name, (xmlChar *)"security") == 0)
		type = SA_TYPE_ALTSPACE;
	else
		assert(0);
	return (type);
}

/*
 * sa_optionset_name(optionset, oname, len, id)
 *	return the SMF name for the optionset. If id is not NULL, it
 *	will have the GUID value for a share and should be used
 *	instead of the keyword "optionset" which is used for
 *	groups. If the optionset doesn't have a protocol type
 *	associated with it, "default" is used. This shouldn't happen
 *	at this point but may be desirable in the future if there are
 *	protocol independent properties added. The name is returned in
 *	oname.
 */

static int
sa_optionset_name(sa_optionset_t optionset, char *oname, size_t len, char *id)
{
	char *proto;
	void *parent;
	int ptype;

	if (id == NULL)
		id = "optionset";

	parent = sa_get_optionset_parent(optionset);
	if (parent != NULL) {
		ptype = sa_get_object_type(parent);
		proto = sa_get_optionset_attr(optionset, "type");
		if (ptype != SA_TYPE_RESOURCE) {
			len = snprintf(oname, len, "%s_%s", id,
			    proto ? proto : "default");
		} else {
			char *index;
			index = get_node_attr((void *)parent, "id");
			if (index != NULL) {
				len = snprintf(oname, len, "%s_%s_%s", id,
				    proto ? proto : "default", index);
				sa_free_attr_string(index);
			} else {
				len = 0;
			}
		}

		if (proto != NULL)
			sa_free_attr_string(proto);
	} else {
		len = 0;
	}
	return (len);
}

/*
 * sa_security_name(optionset, oname, len, id)
 *
 * return the SMF name for the security. If id is not NULL, it will
 * have the GUID value for a share and should be used instead of the
 * keyword "optionset" which is used for groups. If the optionset
 * doesn't have a protocol type associated with it, "default" is
 * used. This shouldn't happen at this point but may be desirable in
 * the future if there are protocol independent properties added. The
 * name is returned in oname. The security type is also encoded into
 * the name. In the future, this wil *be handled a bit differently.
 */

static int
sa_security_name(sa_security_t security, char *oname, size_t len, char *id)
{
	char *proto;
	char *sectype;

	if (id == NULL)
		id = "optionset";

	proto = sa_get_security_attr(security, "type");
	sectype = sa_get_security_attr(security, "sectype");
	len = snprintf(oname, len, "%s_%s_%s", id, proto ? proto : "default",
	    sectype ? sectype : "default");
	if (proto != NULL)
		sa_free_attr_string(proto);
	if (sectype != NULL)
		sa_free_attr_string(sectype);
	return (len);
}

/*
 * verifydefgroupopts(handle)
 *
 * Make sure a "default" group exists and has default protocols enabled.
 */
static void
verifydefgroupopts(sa_handle_t handle)
{
	sa_group_t defgrp;
	sa_optionset_t opt;

	defgrp = sa_get_group(handle, "default");
	if (defgrp != NULL) {
		opt = sa_get_optionset(defgrp, NULL);
		/*
		 * NFS is the default for default group
		 */
		if (opt == NULL)
			opt = sa_create_optionset(defgrp, "nfs");
	}
}

/*
 * sa_init(init_service)
 *	Initialize the API
 *	find all the shared objects
 *	init the tables with all objects
 *	read in the current configuration
 */

#define	GETPROP(prop)	scf_simple_prop_next_astring(prop)
#define	CHECKTSTAMP(st, tval)	stat(SA_LEGACY_DFSTAB, &st) >= 0 && \
	tval != TSTAMP(st.st_ctim)

sa_handle_t
sa_init(int init_service)
{
	struct stat st;
	int legacy = 0;
	uint64_t tval = 0;
	int lockfd;
	sigset_t old;
	int updatelegacy = B_FALSE;
	scf_simple_prop_t *prop;
	sa_handle_impl_t handle;
	int err;

	handle = calloc(sizeof (struct sa_handle_impl), 1);

	if (handle != NULL) {
		/*
		 * Get protocol specific structures, but only if this
		 * is the only handle.
		 */
		(void) mutex_lock(&sa_global_lock);
		if (sa_global_handles == NULL)
			(void) proto_plugin_init();
		(void) mutex_unlock(&sa_global_lock);
		if (init_service & SA_INIT_SHARE_API) {
			/*
			 * initialize access into libzfs. We use this
			 * when collecting info about ZFS datasets and
			 * shares.
			 */
			if (sa_zfs_init(handle) == B_FALSE) {
				free(handle);
				(void) mutex_lock(&sa_global_lock);
				(void) proto_plugin_fini();
				(void) mutex_unlock(&sa_global_lock);
				return (NULL);
			}
			/*
			 * since we want to use SMF, initialize an svc handle
			 * and find out what is there.
			 */
			handle->scfhandle = sa_scf_init(handle);
			if (handle->scfhandle != NULL) {
				/*
				 * Need to lock the extraction of the
				 * configuration if the dfstab file has
				 * changed. Lock everything now and release if
				 * not needed.  Use a file that isn't being
				 * manipulated by other parts of the system in
				 * order to not interfere with locking. Using
				 * dfstab doesn't work.
				 */
				sablocksigs(&old);
				lockfd = open(DFS_LOCK_FILE, O_RDWR);
				if (lockfd >= 0) {
					extern int errno;
					errno = 0;
					(void) lockf(lockfd, F_LOCK, 0);
					(void) mutex_lock(&sa_dfstab_lock);
					/*
					 * Check whether we are going to need
					 * to merge any dfstab changes. This
					 * is done by comparing the value of
					 * legacy-timestamp with the current
					 * st_ctim of the file. If they are
					 * different, an update is needed and
					 * the file must remain locked until
					 * the merge is done in order to
					 * prevent multiple startups from
					 * changing the SMF repository at the
					 * same time.  The first to get the
					 * lock will make any changes before
					 * the others can read the repository.
					 */
					prop = scf_simple_prop_get
					    (handle->scfhandle->handle,
					    (const char *)SA_SVC_FMRI_BASE
					    ":default", "operation",
					    "legacy-timestamp");
					if (prop != NULL) {
						char *i64;
						i64 = GETPROP(prop);
						if (i64 != NULL)
							tval = strtoull(i64,
							    NULL, 0);
						if (CHECKTSTAMP(st, tval))
							updatelegacy = B_TRUE;
						scf_simple_prop_free(prop);
					} else {
						/*
						 * We haven't set the
						 * timestamp before so do it.
						 */
						updatelegacy = B_TRUE;
					}
					if (updatelegacy == B_FALSE) {
						(void) mutex_unlock(
						    &sa_dfstab_lock);
						(void) lockf(lockfd, F_ULOCK,
						    0);
						(void) close(lockfd);
					}

				}
				/*
				 * It is essential that the document tree and
				 * the internal list of roots to handles be
				 * setup before anything that might try to
				 * create a new object is called. The document
				 * tree is the combination of handle->doc and
				 * handle->tree. This allows searches,
				 * etc. when all you have is an object in the
				 * tree.
				 */
				handle->doc = xmlNewDoc((xmlChar *)"1.0");
				handle->tree = xmlNewNode(NULL,
				    (xmlChar *)"sharecfg");
				if (handle->doc != NULL &&
				    handle->tree != NULL) {
					(void) xmlDocSetRootElement(handle->doc,
					    handle->tree);
					err = add_handle_for_root(handle->tree,
					    handle);
					if (err == SA_OK)
						err = sa_get_config(
						    handle->scfhandle,
						    handle->tree, handle);
				} else {
					if (handle->doc != NULL)
						xmlFreeDoc(handle->doc);
					if (handle->tree != NULL)
						xmlFreeNode(handle->tree);
					err = SA_NO_MEMORY;
				}

				saunblocksigs(&old);

				if (err != SA_OK) {
					/*
					 * If we couldn't add the tree handle
					 * to the list, then things are going
					 * to fail badly. Might as well undo
					 * everything now and fail the
					 * sa_init().
					 */
					sa_fini(handle);
					if (updatelegacy == B_TRUE) {
						(void) mutex_unlock(
						    &sa_dfstab_lock);
						(void) lockf(lockfd,
						    F_ULOCK, 0);
						(void) close(lockfd);
					}
					return (NULL);
				}

				if (tval == 0) {
					/*
					 * first time so make sure
					 * default is setup
					 */
					verifydefgroupopts(handle);
				}

				if (updatelegacy == B_TRUE) {
					sablocksigs(&old);
					getlegacyconfig((sa_handle_t)handle,
					    SA_LEGACY_DFSTAB, &handle->tree);
					if (stat(SA_LEGACY_DFSTAB, &st) >= 0)
						set_legacy_timestamp(
						    handle->tree,
						    SA_LEGACY_DFSTAB,
						    TSTAMP(st.st_ctim));
					saunblocksigs(&old);
					/*
					 * Safe to unlock now to allow
					 * others to run
					 */
					(void) mutex_unlock(&sa_dfstab_lock);
					(void) lockf(lockfd, F_ULOCK, 0);
					(void) close(lockfd);
				}
				/* Get sharetab timestamp */
				sa_update_sharetab_ts((sa_handle_t)handle);

				/* Get lastupdate (transaction) timestamp */
				prop = scf_simple_prop_get(
				    handle->scfhandle->handle,
				    (const char *)SA_SVC_FMRI_BASE ":default",
				    "state", "lastupdate");
				if (prop != NULL) {
					char *str;
					str =
					    scf_simple_prop_next_astring(prop);
					if (str != NULL)
						handle->tstrans =
						    strtoull(str, NULL, 0);
					else
						handle->tstrans = 0;
					scf_simple_prop_free(prop);
				}
				legacy |= sa_get_zfs_shares(handle, "zfs");
				legacy |= gettransients(handle, &handle->tree);
			}
		}
	}
	return ((sa_handle_t)handle);
}

/*
 * sa_fini(handle)
 *	Uninitialize the API structures including the configuration
 *	data structures and ZFS related data.
 */

void
sa_fini(sa_handle_t handle)
{
	sa_handle_impl_t impl_handle = (sa_handle_impl_t)handle;

	if (impl_handle != NULL) {
		/*
		 * Free the config trees and any other data structures
		 * used in the handle.
		 */
		if (impl_handle->doc != NULL)
			xmlFreeDoc(impl_handle->doc);

		/* Remove and free the entry in the global list. */
		remove_handle_for_root(impl_handle->tree);

		/*
		 * If this was the last handle to release, unload the
		 * plugins that were loaded. Use a mutex in case
		 * another thread is reinitializing.
		 */
		(void) mutex_lock(&sa_global_lock);
		if (sa_global_handles == NULL)
			(void) proto_plugin_fini();
		(void) mutex_unlock(&sa_global_lock);

		sa_scf_fini(impl_handle->scfhandle);
		sa_zfs_fini(impl_handle);

		/* Make sure we free the handle */
		free(impl_handle);

	}
}

/*
 * sa_get_protocols(char **protocol)
 *	Get array of protocols that are supported
 *	Returns pointer to an allocated and NULL terminated
 *	array of strings.  Caller must free.
 *	This really should be determined dynamically.
 *	If there aren't any defined, return -1.
 *	Use free() to return memory.
 */

int
sa_get_protocols(char ***protocols)
{
	int numproto = -1;

	if (protocols != NULL) {
		struct sa_proto_plugin *plug;
		for (numproto = 0, plug = sap_proto_list; plug != NULL;
		    plug = plug->plugin_next) {
			numproto++;
		}

		*protocols = calloc(numproto + 1,  sizeof (char *));
		if (*protocols != NULL) {
			int ret = 0;
			for (plug = sap_proto_list; plug != NULL;
			    plug = plug->plugin_next) {
				/* faking for now */
				(*protocols)[ret++] =
				    plug->plugin_ops->sa_protocol;
			}
		} else {
			numproto = -1;
		}
	}
	return (numproto);
}

/*
 * find_group_by_name(node, group)
 *
 * search the XML document subtree specified by node to find the group
 * specified by group. Searching subtree allows subgroups to be
 * searched for.
 */

static xmlNodePtr
find_group_by_name(xmlNodePtr node, xmlChar *group)
{
	xmlChar *name = NULL;

	for (node = node->xmlChildrenNode; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"group") == 0) {
			/* if no groupname, return the first found */
			if (group == NULL)
				break;
			name = xmlGetProp(node, (xmlChar *)"name");
			if (name != NULL && xmlStrcmp(name, group) == 0)
				break;
			if (name != NULL) {
				xmlFree(name);
				name = NULL;
			}
		}
	}
	if (name != NULL)
		xmlFree(name);
	return (node);
}

/*
 * sa_get_group(groupname)
 *	Return the "group" specified.  If groupname is NULL,
 *	return the first group of the list of groups.
 */
sa_group_t
sa_get_group(sa_handle_t handle, char *groupname)
{
	xmlNodePtr node = NULL;
	char *subgroup = NULL;
	char *group = NULL;
	sa_handle_impl_t impl_handle = (sa_handle_impl_t)handle;

	if (impl_handle != NULL && impl_handle->tree != NULL) {
		if (groupname != NULL) {
			group = strdup(groupname);
			if (group != NULL) {
				subgroup = strchr(group, '/');
				if (subgroup != NULL)
					*subgroup++ = '\0';
			}
		}
		/*
		 * We want to find the, possibly, named group. If
		 * group is not NULL, then lookup the name. If it is
		 * NULL, we only do the find if groupname is also
		 * NULL. This allows lookup of the "first" group in
		 * the internal list.
		 */
		if (group != NULL || groupname == NULL)
			node = find_group_by_name(impl_handle->tree,
			    (xmlChar *)group);

		/* if a subgroup, find it before returning */
		if (subgroup != NULL && node != NULL)
			node = find_group_by_name(node, (xmlChar *)subgroup);
	}
	if (node != NULL && (char *)group != NULL)
		(void) sa_get_instance(impl_handle->scfhandle, (char *)group);
	if (group != NULL)
		free(group);
	return ((sa_group_t)(node));
}

/*
 * sa_get_next_group(group)
 *	Return the "next" group after the specified group from
 *	the internal group list.  NULL if there are no more.
 */
sa_group_t
sa_get_next_group(sa_group_t group)
{
	xmlNodePtr ngroup = NULL;
	if (group != NULL) {
		for (ngroup = ((xmlNodePtr)group)->next; ngroup != NULL;
		    ngroup = ngroup->next) {
			if (xmlStrcmp(ngroup->name, (xmlChar *)"group") == 0)
				break;
		}
	}
	return ((sa_group_t)ngroup);
}

/*
 * sa_get_share(group, sharepath)
 *	Return the share object for the share specified. The share
 *	must be in the specified group.  Return NULL if not found.
 */
sa_share_t
sa_get_share(sa_group_t group, char *sharepath)
{
	xmlNodePtr node = NULL;
	xmlChar *path;

	/*
	 * For future scalability, this should end up building a cache
	 * since it will get called regularly by the mountd and info
	 * services.
	 */
	if (group != NULL) {
		for (node = ((xmlNodePtr)group)->children; node != NULL;
		    node = node->next) {
			if (xmlStrcmp(node->name, (xmlChar *)"share") == 0) {
				if (sharepath == NULL) {
					break;
				} else {
					/* is it the correct share? */
					path = xmlGetProp(node,
					    (xmlChar *)"path");
					if (path != NULL &&
					    xmlStrcmp(path,
					    (xmlChar *)sharepath) == 0) {
						xmlFree(path);
						break;
					}
					xmlFree(path);
				}
			}
		}
	}
	return ((sa_share_t)node);
}

/*
 * sa_get_next_share(share)
 *	Return the next share following the specified share
 *	from the internal list of shares. Returns NULL if there
 *	are no more shares.  The list is relative to the same
 *	group.
 */
sa_share_t
sa_get_next_share(sa_share_t share)
{
	xmlNodePtr node = NULL;

	if (share != NULL) {
		for (node = ((xmlNodePtr)share)->next; node != NULL;
		    node = node->next) {
			if (xmlStrcmp(node->name, (xmlChar *)"share") == 0) {
				break;
			}
		}
	}
	return ((sa_share_t)node);
}

/*
 * _sa_get_child_node(node, type)
 *
 * find the child node of the specified node that has "type". This is
 * used to implement several internal functions.
 */

static xmlNodePtr
_sa_get_child_node(xmlNodePtr node, xmlChar *type)
{
	xmlNodePtr child;
	for (child = node->xmlChildrenNode; child != NULL;
	    child = child->next)
		if (xmlStrcmp(child->name, type) == 0)
			return (child);
	return ((xmlNodePtr)NULL);
}

/*
 *  find_share(group, path)
 *
 * Search all the shares in the specified group for one that has the
 * specified path.
 */

static sa_share_t
find_share(sa_group_t group, char *sharepath)
{
	sa_share_t share;
	char *path;

	for (share = sa_get_share(group, NULL); share != NULL;
	    share = sa_get_next_share(share)) {
		path = sa_get_share_attr(share, "path");
		if (path != NULL && strcmp(path, sharepath) == 0) {
			sa_free_attr_string(path);
			break;
		}
		if (path != NULL)
			sa_free_attr_string(path);
	}
	return (share);
}

/*
 * sa_get_sub_group(group)
 *
 * Get the first sub-group of group. The sa_get_next_group() function
 * can be used to get the rest. This is currently only used for ZFS
 * sub-groups but could be used to implement a more general mechanism.
 */

sa_group_t
sa_get_sub_group(sa_group_t group)
{
	return ((sa_group_t)_sa_get_child_node((xmlNodePtr)group,
	    (xmlChar *)"group"));
}

/*
 * sa_find_share(sharepath)
 *	Finds a share regardless of group.  In the future, this
 *	function should utilize a cache and hash table of some kind.
 *	The current assumption is that a path will only be shared
 *	once.  In the future, this may change as implementation of
 *	resource names comes into being.
 */
sa_share_t
sa_find_share(sa_handle_t handle, char *sharepath)
{
	sa_group_t group;
	sa_group_t zgroup;
	sa_share_t share = NULL;
	int done = 0;

	for (group = sa_get_group(handle, NULL); group != NULL && !done;
	    group = sa_get_next_group(group)) {
		if (is_zfs_group(group)) {
			for (zgroup =
			    (sa_group_t)_sa_get_child_node((xmlNodePtr)group,
			    (xmlChar *)"group");
			    zgroup != NULL;
			    zgroup = sa_get_next_group(zgroup)) {
				share = find_share(zgroup, sharepath);
				if (share != NULL)
					break;
			}
		} else {
			share = find_share(group, sharepath);
		}
		if (share != NULL)
			break;
	}
	return (share);
}

/*
 *  sa_check_path(group, path, strictness)
 *
 * Check that path is a valid path relative to the group.  Currently,
 * we are ignoring the group and checking only the NFS rules. Later,
 * we may want to use the group to then check against the protocols
 * enabled on the group. The strictness values mean:
 * SA_CHECK_NORMAL == only check newpath against shares that are active
 * SA_CHECK_STRICT == check newpath against both active shares and those
 *		      stored in the repository
 */

int
sa_check_path(sa_group_t group, char *path, int strictness)
{
	sa_handle_t handle;

	handle = sa_find_group_handle(group);
	if (handle == NULL)
		return (SA_BAD_PATH);

	return (validpath(handle, path, strictness));
}

/*
 * mark_excluded_protos(group, share, flags)
 *
 * Walk through all the protocols enabled for the group and check to
 * see if the share has any of them should be in the exclude list
 * based on the featureset of the protocol. If there are any, add the
 * "exclude" property to the share.
 */
static void
mark_excluded_protos(sa_group_t group, xmlNodePtr share, uint64_t flags)
{
	sa_optionset_t optionset;
	char exclude_list[SA_STRSIZE];
	char *sep = "";

	exclude_list[0] = '\0';
	for (optionset = sa_get_optionset(group, NULL);
	    optionset != NULL;
	    optionset = sa_get_next_optionset(optionset)) {
		char *value;
		uint64_t features;
		value = sa_get_optionset_attr(optionset, "type");
		if (value == NULL)
			continue;
		features = sa_proto_get_featureset(value);
		if (!(features & flags)) {
			(void) strlcat(exclude_list, sep,
			    sizeof (exclude_list));
			(void) strlcat(exclude_list, value,
			    sizeof (exclude_list));
			sep = ",";
		}
		sa_free_attr_string(value);
	}
	if (exclude_list[0] != '\0')
		(void) xmlSetProp(share, (xmlChar *)"exclude",
		    (xmlChar *)exclude_list);
}

/*
 * get_all_features(group)
 *
 * Walk through all the protocols on the group and collect all
 * possible enabled features. This is the OR of all the featuresets.
 */
static uint64_t
get_all_features(sa_group_t group)
{
	sa_optionset_t optionset;
	uint64_t features = 0;

	for (optionset = sa_get_optionset(group, NULL);
	    optionset != NULL;
	    optionset = sa_get_next_optionset(optionset)) {
		char *value;
		value = sa_get_optionset_attr(optionset, "type");
		if (value == NULL)
			continue;
		features |= sa_proto_get_featureset(value);
		sa_free_attr_string(value);
	}
	return (features);
}


/*
 * _sa_add_share(group, sharepath, persist, *error, flags)
 *
 * Common code for all types of add_share. sa_add_share() is the
 * public API, we also need to be able to do this when parsing legacy
 * files and construction of the internal configuration while
 * extracting config info from SMF. "flags" indicates if some
 * protocols need relaxed rules while other don't. These values are
 * the featureset values defined in libshare.h.
 */

sa_share_t
_sa_add_share(sa_group_t group, char *sharepath, int persist, int *error,
    uint64_t flags)
{
	xmlNodePtr node = NULL;
	int err;

	err  = SA_OK; /* assume success */

	node = xmlNewChild((xmlNodePtr)group, NULL, (xmlChar *)"share", NULL);
	if (node == NULL) {
		if (error != NULL)
			*error = SA_NO_MEMORY;
		return (node);
	}

	(void) xmlSetProp(node, (xmlChar *)"path", (xmlChar *)sharepath);
	(void) xmlSetProp(node, (xmlChar *)"type",
	    persist ? (xmlChar *)"persist" : (xmlChar *)"transient");
	if (flags != 0)
		mark_excluded_protos(group, node, flags);
	if (persist != SA_SHARE_TRANSIENT) {
		/*
		 * persistent shares come in two flavors: SMF and
		 * ZFS. Sort this one out based on target group and
		 * path type. Both NFS and SMB are supported. First,
		 * check to see if the protocol is enabled on the
		 * subgroup and then setup the share appropriately.
		 */
		if (sa_group_is_zfs(group) &&
		    sa_path_is_zfs(sharepath)) {
			if (sa_get_optionset(group, "nfs") != NULL)
				err = sa_zfs_set_sharenfs(group, sharepath, 1);
			else if (sa_get_optionset(group, "smb") != NULL)
				err = sa_zfs_set_sharesmb(group, sharepath, 1);
		} else {
			sa_handle_impl_t impl_handle;
			impl_handle =
			    (sa_handle_impl_t)sa_find_group_handle(group);
			if (impl_handle != NULL) {
				err = sa_commit_share(impl_handle->scfhandle,
				    group, (sa_share_t)node);
			} else {
				err = SA_SYSTEM_ERR;
			}
		}
	}
	if (err == SA_NO_PERMISSION && persist & SA_SHARE_PARSER)
		/* called by the dfstab parser so could be a show */
		err = SA_OK;

	if (err != SA_OK) {
		/*
		 * we couldn't commit to the repository so undo
		 * our internal state to reflect reality.
		 */
		xmlUnlinkNode(node);
		xmlFreeNode(node);
		node = NULL;
	}

	if (error != NULL)
		*error = err;

	return (node);
}

/*
 * sa_add_share(group, sharepath, persist, *error)
 *
 *	Add a new share object to the specified group.  The share will
 *	have the specified sharepath and will only be constructed if
 *	it is a valid path to be shared.  NULL is returned on error
 *	and a detailed error value will be returned via the error
 *	pointer.
 */
sa_share_t
sa_add_share(sa_group_t group, char *sharepath, int persist, int *error)
{
	xmlNodePtr node = NULL;
	int strictness = SA_CHECK_NORMAL;
	sa_handle_t handle;
	uint64_t special = 0;
	uint64_t features;

	/*
	 * If the share is to be permanent, use strict checking so a
	 * bad config doesn't get created. Transient shares only need
	 * to check against the currently active
	 * shares. SA_SHARE_PARSER is a modifier used internally to
	 * indicate that we are being called by the dfstab parser and
	 * that we need strict checking in all cases. Normally persist
	 * is in integer value but SA_SHARE_PARSER may be or'd into
	 * it as an override.
	 */
	if (persist & SA_SHARE_PARSER || persist == SA_SHARE_PERMANENT)
		strictness = SA_CHECK_STRICT;

	handle = sa_find_group_handle(group);

	/*
	 * need to determine if the share is valid. The rules are:
	 *	- The path must not already exist
	 *	- The path must not be a subdir or parent dir of an
	 *	  existing path unless at least one protocol allows it.
	 * The sub/parent check is done in sa_check_path().
	 */

	if (sa_find_share(handle, sharepath) == NULL) {
		*error = sa_check_path(group, sharepath, strictness);
		features = get_all_features(group);
		switch (*error) {
		case SA_PATH_IS_SUBDIR:
			if (features & SA_FEATURE_ALLOWSUBDIRS)
				special |= SA_FEATURE_ALLOWSUBDIRS;
			break;
		case SA_PATH_IS_PARENTDIR:
			if (features & SA_FEATURE_ALLOWPARDIRS)
				special |= SA_FEATURE_ALLOWPARDIRS;
			break;
		}
		if (*error == SA_OK || special != SA_FEATURE_NONE)
			node = _sa_add_share(group, sharepath, persist,
			    error, special);
	} else {
		*error = SA_DUPLICATE_NAME;
	}

	return ((sa_share_t)node);
}

/*
 * sa_enable_share(share, protocol)
 *	Enable the specified share to the specified protocol.
 *	If protocol is NULL, then all protocols.
 */
int
sa_enable_share(sa_share_t share, char *protocol)
{
	char *sharepath;
	struct stat st;
	int err = SA_OK;
	int ret;

	sharepath = sa_get_share_attr(share, "path");
	if (sharepath == NULL)
		return (SA_NO_MEMORY);
	if (stat(sharepath, &st) < 0) {
		err = SA_NO_SUCH_PATH;
	} else {
		/* tell the server about the share */
		if (protocol != NULL) {
			if (excluded_protocol(share, protocol))
				goto done;

			/* lookup protocol specific handler */
			err = sa_proto_share(protocol, share);
			if (err == SA_OK)
				(void) sa_set_share_attr(share,
				    "shared", "true");
		} else {
			/* Tell all protocols about the share */
			sa_group_t group;
			sa_optionset_t optionset;

			group = sa_get_parent_group(share);

			for (optionset = sa_get_optionset(group, NULL);
			    optionset != NULL;
			    optionset = sa_get_next_optionset(optionset)) {
				char *proto;
				proto = sa_get_optionset_attr(optionset,
				    "type");
				if (proto != NULL) {
					if (!excluded_protocol(share, proto)) {
						ret = sa_proto_share(proto,
						    share);
						if (ret != SA_OK)
							err = ret;
					}
					sa_free_attr_string(proto);
				}
			}
			(void) sa_set_share_attr(share, "shared", "true");
		}
	}
done:
	if (sharepath != NULL)
		sa_free_attr_string(sharepath);
	return (err);
}

/*
 * sa_disable_share(share, protocol)
 *	Disable the specified share to the specified protocol.  If
 *	protocol is NULL, then all protocols that are enabled for the
 *	share should be disabled.
 */
int
sa_disable_share(sa_share_t share, char *protocol)
{
	char *path;
	int err = SA_OK;
	int ret = SA_OK;

	path = sa_get_share_attr(share, "path");

	if (protocol != NULL) {
		ret = sa_proto_unshare(share, protocol, path);
	} else {
		/* need to do all protocols */
		sa_group_t group;
		sa_optionset_t optionset;

		group = sa_get_parent_group(share);

		/* Tell all protocols about the share */
		for (optionset = sa_get_optionset(group, NULL);
		    optionset != NULL;
		    optionset = sa_get_next_optionset(optionset)) {
			char *proto;

			proto = sa_get_optionset_attr(optionset, "type");
			if (proto != NULL) {
				err = sa_proto_unshare(share, proto, path);
				if (err != SA_OK)
					ret = err;
				sa_free_attr_string(proto);
			}
		}
	}
	if (ret == SA_OK)
		(void) sa_set_share_attr(share, "shared", NULL);
	if (path != NULL)
		sa_free_attr_string(path);
	return (ret);
}

/*
 * sa_remove_share(share)
 *
 * remove the specified share from its containing group.
 * Remove from the SMF or ZFS configuration space.
 */

int
sa_remove_share(sa_share_t share)
{
	sa_group_t group;
	int ret = SA_OK;
	char *type;
	int transient = 0;
	char *groupname;
	char *zfs;

	type = sa_get_share_attr(share, "type");
	group = sa_get_parent_group(share);
	zfs = sa_get_group_attr(group, "zfs");
	groupname = sa_get_group_attr(group, "name");
	if (type != NULL && strcmp(type, "persist") != 0)
		transient = 1;
	if (type != NULL)
		sa_free_attr_string(type);

	/* remove the node from its group then free the memory */

	/*
	 * need to test if "busy"
	 */
	/* only do SMF action if permanent */
	if (!transient || zfs != NULL) {
		/* remove from legacy dfstab as well as possible SMF */
		ret = sa_delete_legacy(share, NULL);
		if (ret == SA_OK) {
			if (!sa_group_is_zfs(group)) {
				sa_handle_impl_t impl_handle;
				impl_handle = (sa_handle_impl_t)
				    sa_find_group_handle(group);
				if (impl_handle != NULL) {
					ret = sa_delete_share(
					    impl_handle->scfhandle, group,
					    share);
				} else {
					ret = SA_SYSTEM_ERR;
				}
			} else {
				char *sharepath = sa_get_share_attr(share,
				    "path");
				if (sharepath != NULL) {
					ret = sa_zfs_set_sharenfs(group,
					    sharepath, 0);
					sa_free_attr_string(sharepath);
				}
			}
		}
	}
	if (groupname != NULL)
		sa_free_attr_string(groupname);
	if (zfs != NULL)
		sa_free_attr_string(zfs);

	xmlUnlinkNode((xmlNodePtr)share);
	xmlFreeNode((xmlNodePtr)share);
	return (ret);
}

/*
 * sa_move_share(group, share)
 *
 * move the specified share to the specified group.  Update SMF
 * appropriately.
 */

int
sa_move_share(sa_group_t group, sa_share_t share)
{
	sa_group_t oldgroup;
	int ret = SA_OK;

	/* remove the node from its group then free the memory */

	oldgroup = sa_get_parent_group(share);
	if (oldgroup != group) {
		sa_handle_impl_t impl_handle;
		xmlUnlinkNode((xmlNodePtr)share);
		/*
		 * now that the share isn't in its old group, add to
		 * the new one
		 */
		(void) xmlAddChild((xmlNodePtr)group, (xmlNodePtr)share);
		/* need to deal with SMF */
		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (impl_handle != NULL) {
			/*
			 * need to remove from old group first and then add to
			 * new group. Ideally, we would do the other order but
			 * need to avoid having the share in two groups at the
			 * same time.
			 */
			ret = sa_delete_share(impl_handle->scfhandle, oldgroup,
			    share);
			if (ret == SA_OK)
				ret = sa_commit_share(impl_handle->scfhandle,
				    group, share);
		} else {
			ret = SA_SYSTEM_ERR;
		}
	}
	return (ret);
}

/*
 * sa_get_parent_group(share)
 *
 * Return the containing group for the share. If a group was actually
 * passed in, we don't want a parent so return NULL.
 */

sa_group_t
sa_get_parent_group(sa_share_t share)
{
	xmlNodePtr node = NULL;
	if (share != NULL) {
		node = ((xmlNodePtr)share)->parent;
		/*
		 * make sure parent is a group and not sharecfg since
		 * we may be cheating and passing in a group.
		 * Eventually, groups of groups might come into being.
		 */
		if (node == NULL ||
		    xmlStrcmp(node->name, (xmlChar *)"sharecfg") == 0)
			node = NULL;
	}
	return ((sa_group_t)node);
}

/*
 * _sa_create_group(impl_handle, groupname)
 *
 * Create a group in the document. The caller will need to deal with
 * configuration store and activation.
 */

sa_group_t
_sa_create_group(sa_handle_impl_t impl_handle, char *groupname)
{
	xmlNodePtr node = NULL;

	if (sa_valid_group_name(groupname)) {
		node = xmlNewChild(impl_handle->tree, NULL, (xmlChar *)"group",
		    NULL);
		if (node != NULL) {
			(void) xmlSetProp(node, (xmlChar *)"name",
			    (xmlChar *)groupname);
			(void) xmlSetProp(node, (xmlChar *)"state",
			    (xmlChar *)"enabled");
		}
	}
	return ((sa_group_t)node);
}

/*
 * _sa_create_zfs_group(group, groupname)
 *
 * Create a ZFS subgroup under the specified group. This may
 * eventually form the basis of general sub-groups, but is currently
 * restricted to ZFS.
 */
sa_group_t
_sa_create_zfs_group(sa_group_t group, char *groupname)
{
	xmlNodePtr node = NULL;

	node = xmlNewChild((xmlNodePtr)group, NULL, (xmlChar *)"group", NULL);
	if (node != NULL) {
		(void) xmlSetProp(node, (xmlChar *)"name",
		    (xmlChar *)groupname);
		(void) xmlSetProp(node, (xmlChar *)"state",
		    (xmlChar *)"enabled");
	}

	return ((sa_group_t)node);
}

/*
 * sa_create_group(groupname, *error)
 *
 * Create a new group with groupname.  Need to validate that it is a
 * legal name for SMF and the construct the SMF service instance of
 * svc:/network/shares/group to implement the group. All necessary
 * operational properties must be added to the group at this point
 * (via the SMF transaction model).
 */
sa_group_t
sa_create_group(sa_handle_t handle, char *groupname, int *error)
{
	xmlNodePtr node = NULL;
	sa_group_t group;
	int ret;
	char rbacstr[SA_STRSIZE];
	sa_handle_impl_t impl_handle = (sa_handle_impl_t)handle;

	ret = SA_OK;

	if (impl_handle == NULL || impl_handle->scfhandle == NULL) {
		ret = SA_SYSTEM_ERR;
		goto err;
	}

	group = sa_get_group(handle, groupname);
	if (group != NULL) {
		ret = SA_DUPLICATE_NAME;
	} else {
		if (sa_valid_group_name(groupname)) {
			node = xmlNewChild(impl_handle->tree, NULL,
			    (xmlChar *)"group", NULL);
			if (node != NULL) {
				(void) xmlSetProp(node, (xmlChar *)"name",
				    (xmlChar *)groupname);
				/* default to the group being enabled */
				(void) xmlSetProp(node, (xmlChar *)"state",
				    (xmlChar *)"enabled");
				ret = sa_create_instance(impl_handle->scfhandle,
				    groupname);
				if (ret == SA_OK) {
					ret = sa_start_transaction(
					    impl_handle->scfhandle,
					    "operation");
				}
				if (ret == SA_OK) {
					ret = sa_set_property(
					    impl_handle->scfhandle,
					    "state", "enabled");
					if (ret == SA_OK) {
						ret = sa_end_transaction(
						    impl_handle->scfhandle,
						    impl_handle);
					} else {
						sa_abort_transaction(
						    impl_handle->scfhandle);
					}
				}
				if (ret == SA_OK) {
					/* initialize the RBAC strings */
					ret = sa_start_transaction(
					    impl_handle->scfhandle,
					    "general");
					if (ret == SA_OK) {
						(void) snprintf(rbacstr,
						    sizeof (rbacstr), "%s.%s",
						    SA_RBAC_MANAGE, groupname);
						ret = sa_set_property(
						    impl_handle->scfhandle,
						    "action_authorization",
						    rbacstr);
					}
					if (ret == SA_OK) {
						(void) snprintf(rbacstr,
						    sizeof (rbacstr), "%s.%s",
						    SA_RBAC_VALUE, groupname);
						ret = sa_set_property(
						    impl_handle->scfhandle,
						    "value_authorization",
						    rbacstr);
					}
					if (ret == SA_OK) {
						ret = sa_end_transaction(
						    impl_handle->scfhandle,
						    impl_handle);
					} else {
						sa_abort_transaction(
						    impl_handle->scfhandle);
					}
				}
				if (ret != SA_OK) {
					/*
					 * Couldn't commit the group
					 * so we need to undo
					 * internally.
					 */
					xmlUnlinkNode(node);
					xmlFreeNode(node);
					node = NULL;
				}
			} else {
				ret = SA_NO_MEMORY;
			}
		} else {
			ret = SA_INVALID_NAME;
		}
	}
err:
	if (error != NULL)
		*error = ret;
	return ((sa_group_t)node);
}

/*
 * sa_remove_group(group)
 *
 * Remove the specified group. This deletes from the SMF repository.
 * All property groups and properties are removed.
 */

int
sa_remove_group(sa_group_t group)
{
	char *name;
	int ret = SA_OK;
	sa_handle_impl_t impl_handle;

	impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
	if (impl_handle != NULL) {
		name = sa_get_group_attr(group, "name");
		if (name != NULL) {
			ret = sa_delete_instance(impl_handle->scfhandle, name);
			sa_free_attr_string(name);
		}
		xmlUnlinkNode((xmlNodePtr)group); /* make sure unlinked */
		xmlFreeNode((xmlNodePtr)group);   /* now it is gone */
	} else {
		ret = SA_SYSTEM_ERR;
	}
	return (ret);
}

/*
 * sa_update_config()
 *
 * Used to update legacy files that need to be updated in bulk
 * Currently, this is a placeholder and will go away in a future
 * release.
 */

int
sa_update_config(sa_handle_t handle)
{
	/*
	 * do legacy files first so we can tell when they change.
	 * This will go away when we start updating individual records
	 * rather than the whole file.
	 */
	update_legacy_config(handle);
	return (SA_OK);
}

/*
 * get_node_attr(node, tag)
 *
 * Get the specified tag(attribute) if it exists on the node.  This is
 * used internally by a number of attribute oriented functions.
 */

static char *
get_node_attr(void *nodehdl, char *tag)
{
	xmlNodePtr node = (xmlNodePtr)nodehdl;
	xmlChar *name = NULL;

	if (node != NULL)
		name = xmlGetProp(node, (xmlChar *)tag);
	return ((char *)name);
}

/*
 * set_node_attr(node, tag)
 *
 * Set the specified tag(attribute) to the specified value This is
 * used internally by a number of attribute oriented functions. It
 * doesn't update the repository, only the internal document state.
 */

void
set_node_attr(void *nodehdl, char *tag, char *value)
{
	xmlNodePtr node = (xmlNodePtr)nodehdl;
	if (node != NULL && tag != NULL) {
		if (value != NULL)
			(void) xmlSetProp(node, (xmlChar *)tag,
			    (xmlChar *)value);
		else
			(void) xmlUnsetProp(node, (xmlChar *)tag);
	}
}

/*
 * sa_get_group_attr(group, tag)
 *
 * Get the specied attribute, if defined, for the group.
 */

char *
sa_get_group_attr(sa_group_t group, char *tag)
{
	return (get_node_attr((void *)group, tag));
}

/*
 * sa_set_group_attr(group, tag, value)
 *
 * set the specified tag/attribute on the group using value as its
 * value.
 *
 * This will result in setting the property in the SMF repository as
 * well as in the internal document.
 */

int
sa_set_group_attr(sa_group_t group, char *tag, char *value)
{
	int ret;
	char *groupname;
	sa_handle_impl_t impl_handle;

	/*
	 * ZFS group/subgroup doesn't need the handle so shortcut.
	 */
	if (sa_group_is_zfs(group)) {
		set_node_attr((void *)group, tag, value);
		return (SA_OK);
	}

	impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
	if (impl_handle != NULL) {
		groupname = sa_get_group_attr(group, "name");
		ret = sa_get_instance(impl_handle->scfhandle, groupname);
		if (ret == SA_OK) {
			set_node_attr((void *)group, tag, value);
			ret = sa_start_transaction(impl_handle->scfhandle,
			    "operation");
			if (ret == SA_OK) {
				ret = sa_set_property(impl_handle->scfhandle,
				    tag, value);
				if (ret == SA_OK)
					ret = sa_end_transaction(
					    impl_handle->scfhandle,
					    impl_handle);
				else
					sa_abort_transaction(
					    impl_handle->scfhandle);
			}
			if (ret == SA_SYSTEM_ERR)
				ret = SA_NO_PERMISSION;
		}
		if (groupname != NULL)
			sa_free_attr_string(groupname);
	} else {
		ret = SA_SYSTEM_ERR;
	}
	return (ret);
}

/*
 * sa_get_share_attr(share, tag)
 *
 * Return the value of the tag/attribute set on the specified
 * share. Returns NULL if the tag doesn't exist.
 */

char *
sa_get_share_attr(sa_share_t share, char *tag)
{
	return (get_node_attr((void *)share, tag));
}

/*
 * _sa_set_share_description(share, description)
 *
 * Add a description tag with text contents to the specified share.  A
 * separate XML tag is used rather than a property. This can also be
 * used with resources.
 */

xmlNodePtr
_sa_set_share_description(void *share, char *content)
{
	xmlNodePtr node;
	node = xmlNewChild((xmlNodePtr)share, NULL, (xmlChar *)"description",
	    NULL);
	xmlNodeSetContent(node, (xmlChar *)content);
	return (node);
}

/*
 * sa_set_share_attr(share, tag, value)
 *
 * Set the share attribute specified by tag to the specified value. In
 * the case of "resource", enforce a no duplicates in a group rule. If
 * the share is not transient, commit the changes to the repository
 * else just update the share internally.
 */

int
sa_set_share_attr(sa_share_t share, char *tag, char *value)
{
	sa_group_t group;
	sa_share_t resource;
	int ret = SA_OK;

	group = sa_get_parent_group(share);

	/*
	 * There are some attributes that may have specific
	 * restrictions on them. Initially, only "resource" has
	 * special meaning that needs to be checked. Only one instance
	 * of a resource name may exist within a group.
	 */

	if (strcmp(tag, "resource") == 0) {
		resource = sa_get_resource(group, value);
		if (resource != share && resource != NULL)
			ret = SA_DUPLICATE_NAME;
	}
	if (ret == SA_OK) {
		set_node_attr((void *)share, tag, value);
		if (group != NULL) {
			char *type;
			/* we can probably optimize this some */
			type = sa_get_share_attr(share, "type");
			if (type == NULL || strcmp(type, "transient") != 0) {
				sa_handle_impl_t impl_handle;
				impl_handle =
				    (sa_handle_impl_t)sa_find_group_handle(
				    group);
				if (impl_handle != NULL) {
					ret = sa_commit_share(
					    impl_handle->scfhandle, group,
					    share);
				} else {
					ret = SA_SYSTEM_ERR;
				}
			}
			if (type != NULL)
				sa_free_attr_string(type);
		}
	}
	return (ret);
}

/*
 * sa_get_property_attr(prop, tag)
 *
 * Get the value of the specified property attribute. Standard
 * attributes are "type" and "value".
 */

char *
sa_get_property_attr(sa_property_t prop, char *tag)
{
	return (get_node_attr((void *)prop, tag));
}

/*
 * sa_get_optionset_attr(prop, tag)
 *
 * Get the value of the specified property attribute. Standard
 * attribute is "type".
 */

char *
sa_get_optionset_attr(sa_property_t optionset, char *tag)
{
	return (get_node_attr((void *)optionset, tag));

}

/*
 * sa_set_optionset_attr(optionset, tag, value)
 *
 * Set the specified attribute(tag) to the specified value on the
 * optionset.
 */

void
sa_set_optionset_attr(sa_group_t optionset, char *tag, char *value)
{
	set_node_attr((void *)optionset, tag, value);
}

/*
 * sa_free_attr_string(string)
 *
 * Free the string that was returned in one of the sa_get_*_attr()
 * functions.
 */

void
sa_free_attr_string(char *string)
{
	xmlFree((xmlChar *)string);
}

/*
 * sa_get_optionset(group, proto)
 *
 * Return the optionset, if it exists, that is associated with the
 * specified protocol.
 */

sa_optionset_t
sa_get_optionset(void *group, char *proto)
{
	xmlNodePtr node;
	xmlChar *value = NULL;

	for (node = ((xmlNodePtr)group)->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"optionset") == 0) {
			value = xmlGetProp(node, (xmlChar *)"type");
			if (proto != NULL) {
				if (value != NULL &&
				    xmlStrcmp(value, (xmlChar *)proto) == 0) {
					break;
				}
				if (value != NULL) {
					xmlFree(value);
					value = NULL;
				}
			} else {
				break;
			}
		}
	}
	if (value != NULL)
		xmlFree(value);
	return ((sa_optionset_t)node);
}

/*
 * sa_get_next_optionset(optionset)
 *
 * Return the next optionset in the group. NULL if this was the last.
 */

sa_optionset_t
sa_get_next_optionset(sa_optionset_t optionset)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)optionset)->next; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"optionset") == 0) {
			break;
		}
	}
	return ((sa_optionset_t)node);
}

/*
 * sa_get_security(group, sectype, proto)
 *
 * Return the security optionset. The internal name is a hold over
 * from the implementation and will be changed before the API is
 * finalized. This is really a named optionset that can be negotiated
 * as a group of properties (like NFS security options).
 */

sa_security_t
sa_get_security(sa_group_t group, char *sectype, char *proto)
{
	xmlNodePtr node;
	xmlChar *value = NULL;

	for (node = ((xmlNodePtr)group)->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"security") == 0) {
			if (proto != NULL) {
				value = xmlGetProp(node, (xmlChar *)"type");
				if (value == NULL ||
				    (value != NULL &&
				    xmlStrcmp(value, (xmlChar *)proto) != 0)) {
					/* it doesn't match so continue */
					xmlFree(value);
					value = NULL;
					continue;
				}
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}
			/* potential match */
			if (sectype != NULL) {
				value = xmlGetProp(node, (xmlChar *)"sectype");
				if (value != NULL &&
				    xmlStrcmp(value, (xmlChar *)sectype) == 0) {
					break;
				}
			} else {
				break;
			}
		}
		if (value != NULL) {
			xmlFree(value);
			value = NULL;
		}
	}
	if (value != NULL)
		xmlFree(value);
	return ((sa_security_t)node);
}

/*
 * sa_get_next_security(security)
 *
 * Get the next security optionset if one exists.
 */

sa_security_t
sa_get_next_security(sa_security_t security)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)security)->next; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"security") == 0) {
			break;
		}
	}
	return ((sa_security_t)node);
}

/*
 * sa_get_property(optionset, prop)
 *
 * Get the property object with the name specified in prop from the
 * optionset.
 */

sa_property_t
sa_get_property(sa_optionset_t optionset, char *prop)
{
	xmlNodePtr node = (xmlNodePtr)optionset;
	xmlChar *value = NULL;

	if (optionset == NULL)
		return (NULL);

	for (node = node->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			if (prop == NULL)
				break;
			value = xmlGetProp(node, (xmlChar *)"type");
			if (value != NULL &&
			    xmlStrcmp(value, (xmlChar *)prop) == 0) {
				break;
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}
		}
	}
	if (value != NULL)
		xmlFree(value);
	if (node != NULL && xmlStrcmp(node->name, (xmlChar *)"option") != 0) {
		/*
		 * avoid a non option node -- it is possible to be a
		 * text node
		 */
		node = NULL;
	}
	return ((sa_property_t)node);
}

/*
 * sa_get_next_property(property)
 *
 * Get the next property following the specified property. NULL if
 * this was the last.
 */

sa_property_t
sa_get_next_property(sa_property_t property)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)property)->next; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			break;
		}
	}
	return ((sa_property_t)node);
}

/*
 * sa_set_share_description(share, content)
 *
 * Set the description of share to content.
 */

int
sa_set_share_description(sa_share_t share, char *content)
{
	xmlNodePtr node;
	sa_group_t group;
	int ret = SA_OK;

	for (node = ((xmlNodePtr)share)->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"description") == 0) {
			break;
		}
	}
	/* no existing description but want to add */
	if (node == NULL && content != NULL) {
		/* add a description */
		node = _sa_set_share_description(share, content);
	} else if (node != NULL && content != NULL) {
		/* update a description */
		xmlNodeSetContent(node, (xmlChar *)content);
	} else if (node != NULL && content == NULL) {
		/* remove an existing description */
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}
	group = sa_get_parent_group(share);
	if (group != NULL &&
	    sa_is_persistent(share) && (!sa_group_is_zfs(group))) {
		sa_handle_impl_t impl_handle;
		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (impl_handle != NULL) {
			ret = sa_commit_share(impl_handle->scfhandle, group,
			    share);
		} else {
			ret = SA_SYSTEM_ERR;
		}
	}
	return (ret);
}

/*
 * fixproblemchars(string)
 *
 * don't want any newline or tab characters in the text since these
 * could break display of data and legacy file formats.
 */
static void
fixproblemchars(char *str)
{
	int c;
	for (c = *str; c != '\0'; c = *++str) {
		if (c == '\t' || c == '\n')
			*str = ' ';
		else if (c == '"')
			*str = '\'';
	}
}

/*
 * sa_get_share_description(share)
 *
 * Return the description text for the specified share if it
 * exists. NULL if no description exists.
 */

char *
sa_get_share_description(sa_share_t share)
{
	xmlChar *description = NULL;
	xmlNodePtr node;

	for (node = ((xmlNodePtr)share)->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"description") == 0) {
			break;
		}
	}
	if (node != NULL) {
		description = xmlNodeGetContent(node);
		fixproblemchars((char *)description);
	}
	return ((char *)description);
}

/*
 * sa_free(share_description(description)
 *
 * Free the description string.
 */

void
sa_free_share_description(char *description)
{
	xmlFree((xmlChar *)description);
}

/*
 * sa_create_optionset(group, proto)
 *
 * Create an optionset for the specified protocol in the specied
 * group. This is manifested as a property group within SMF.
 */

sa_optionset_t
sa_create_optionset(sa_group_t group, char *proto)
{
	sa_optionset_t optionset;
	sa_group_t parent = group;
	sa_share_t share = NULL;
	int err = SA_OK;
	char *id = NULL;

	optionset = sa_get_optionset(group, proto);
	if (optionset != NULL) {
		/* can't have a duplicate protocol */
		optionset = NULL;
	} else {
		/*
		 * Account for resource names being slightly
		 * different.
		 */
		if (sa_is_share(group)) {
			/*
			 * Transient shares do not have an "id" so not an
			 * error to not find one.
			 */
			id = sa_get_share_attr((sa_share_t)group, "id");
		} else if (sa_is_resource(group)) {
			share = sa_get_resource_parent(
			    (sa_resource_t)group);
			id = sa_get_resource_attr(share, "id");

			/* id can be NULL if the group is transient (ZFS) */
			if (id == NULL && sa_is_persistent(group))
				err = SA_NO_MEMORY;
		}
		if (err == SA_NO_MEMORY) {
			/*
			 * Couldn't get the id for the share or
			 * resource. While this could be a
			 * configuration issue, it is most likely an
			 * out of memory. In any case, fail the create.
			 */
			return (NULL);
		}

		optionset = (sa_optionset_t)xmlNewChild((xmlNodePtr)group,
		    NULL, (xmlChar *)"optionset", NULL);
		/*
		 * only put to repository if on a group and we were
		 * able to create an optionset.
		 */
		if (optionset != NULL) {
			char oname[SA_STRSIZE];
			char *groupname;

			/*
			 * Need to get parent group in all cases, but also get
			 * the share if this is a resource.
			 */
			if (sa_is_share(group)) {
				parent = sa_get_parent_group((sa_share_t)group);
			} else if (sa_is_resource(group)) {
				share = sa_get_resource_parent(
				    (sa_resource_t)group);
				parent = sa_get_parent_group(share);
			}

			sa_set_optionset_attr(optionset, "type", proto);

			(void) sa_optionset_name(optionset, oname,
			    sizeof (oname), id);
			groupname = sa_get_group_attr(parent, "name");
			if (groupname != NULL && sa_is_persistent(group)) {
				sa_handle_impl_t impl_handle;
				impl_handle =
				    (sa_handle_impl_t)sa_find_group_handle(
				    group);
				assert(impl_handle != NULL);
				if (impl_handle != NULL) {
					(void) sa_get_instance(
					    impl_handle->scfhandle, groupname);
					(void) sa_create_pgroup(
					    impl_handle->scfhandle, oname);
				}
			}
			if (groupname != NULL)
				sa_free_attr_string(groupname);
		}
	}

	if (id != NULL)
		sa_free_attr_string(id);
	return (optionset);
}

/*
 * sa_get_property_parent(property)
 *
 * Given a property, return the object it is a property of. This will
 * be an optionset of some type.
 */

static sa_optionset_t
sa_get_property_parent(sa_property_t property)
{
	xmlNodePtr node = NULL;

	if (property != NULL)
		node = ((xmlNodePtr)property)->parent;
	return ((sa_optionset_t)node);
}

/*
 * sa_get_optionset_parent(optionset)
 *
 * Return the parent of the specified optionset. This could be a group
 * or a share.
 */

static sa_group_t
sa_get_optionset_parent(sa_optionset_t optionset)
{
	xmlNodePtr node = NULL;

	if (optionset != NULL)
		node = ((xmlNodePtr)optionset)->parent;
	return ((sa_group_t)node);
}

/*
 * zfs_needs_update(share)
 *
 * In order to avoid making multiple updates to a ZFS share when
 * setting properties, the share attribute "changed" will be set to
 * true when a property is added or modified.  When done adding
 * properties, we can then detect that an update is needed.  We then
 * clear the state here to detect additional changes.
 */

static int
zfs_needs_update(sa_share_t share)
{
	char *attr;
	int result = 0;

	attr = sa_get_share_attr(share, "changed");
	if (attr != NULL) {
		sa_free_attr_string(attr);
		result = 1;
	}
	set_node_attr((void *)share, "changed", NULL);
	return (result);
}

/*
 * zfs_set_update(share)
 *
 * Set the changed attribute of the share to true.
 */

static void
zfs_set_update(sa_share_t share)
{
	set_node_attr((void *)share, "changed", "true");
}

/*
 * sa_commit_properties(optionset, clear)
 *
 * Check if SMF or ZFS config and either update or abort the pending
 * changes.
 */

int
sa_commit_properties(sa_optionset_t optionset, int clear)
{
	sa_group_t group;
	sa_group_t parent;
	int zfs = 0;
	int needsupdate = 0;
	int ret = SA_OK;
	sa_handle_impl_t impl_handle;

	group = sa_get_optionset_parent(optionset);
	if (group != NULL && (sa_is_share(group) || is_zfs_group(group))) {
		/* only update ZFS if on a share */
		parent = sa_get_parent_group(group);
		zfs++;
		if (parent != NULL && is_zfs_group(parent))
			needsupdate = zfs_needs_update(group);
		else
			zfs = 0;
	}
	if (zfs) {
		if (!clear && needsupdate)
			ret = sa_zfs_update((sa_share_t)group);
	} else {
		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (impl_handle != NULL) {
			if (clear) {
				(void) sa_abort_transaction(
				    impl_handle->scfhandle);
			} else {
				ret = sa_end_transaction(
				    impl_handle->scfhandle, impl_handle);
			}
		} else {
			ret = SA_SYSTEM_ERR;
		}
	}
	return (ret);
}

/*
 * sa_destroy_optionset(optionset)
 *
 * Remove the optionset from its group. Update the repository to
 * reflect this change.
 */

int
sa_destroy_optionset(sa_optionset_t optionset)
{
	char name[SA_STRSIZE];
	int len;
	int ret;
	char *id = NULL;
	sa_group_t group;
	int ispersist = 1;

	/* now delete the prop group */
	group = sa_get_optionset_parent(optionset);
	if (group != NULL) {
		if (sa_is_resource(group)) {
			sa_resource_t resource = group;
			sa_share_t share = sa_get_resource_parent(resource);
			group = sa_get_parent_group(share);
			id = sa_get_share_attr(share, "id");
		} else if (sa_is_share(group)) {
			id = sa_get_share_attr((sa_share_t)group, "id");
		}
		ispersist = sa_is_persistent(group);
	}
	if (ispersist) {
		sa_handle_impl_t impl_handle;
		len = sa_optionset_name(optionset, name, sizeof (name), id);
		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (impl_handle != NULL) {
			if (len > 0) {
				ret = sa_delete_pgroup(impl_handle->scfhandle,
				    name);
			}
		} else {
			ret = SA_SYSTEM_ERR;
		}
	}
	xmlUnlinkNode((xmlNodePtr)optionset);
	xmlFreeNode((xmlNodePtr)optionset);
	if (id != NULL)
		sa_free_attr_string(id);
	return (ret);
}

/* private to the implementation */
int
_sa_remove_optionset(sa_optionset_t optionset)
{
	int ret = SA_OK;

	xmlUnlinkNode((xmlNodePtr)optionset);
	xmlFreeNode((xmlNodePtr)optionset);
	return (ret);
}

/*
 * sa_create_security(group, sectype, proto)
 *
 * Create a security optionset (one that has a type name and a
 * proto). Security is left over from a pure NFS implementation. The
 * naming will change in the future when the API is released.
 */
sa_security_t
sa_create_security(sa_group_t group, char *sectype, char *proto)
{
	sa_security_t security;
	char *id = NULL;
	sa_group_t parent;
	char *groupname = NULL;

	if (group != NULL && sa_is_share(group)) {
		id = sa_get_share_attr((sa_share_t)group, "id");
		parent = sa_get_parent_group(group);
		if (parent != NULL)
			groupname = sa_get_group_attr(parent, "name");
	} else if (group != NULL) {
		groupname = sa_get_group_attr(group, "name");
	}

	security = sa_get_security(group, sectype, proto);
	if (security != NULL) {
		/* can't have a duplicate security option */
		security = NULL;
	} else {
		security = (sa_security_t)xmlNewChild((xmlNodePtr)group,
		    NULL, (xmlChar *)"security", NULL);
		if (security != NULL) {
			char oname[SA_STRSIZE];
			sa_set_security_attr(security, "type", proto);

			sa_set_security_attr(security, "sectype", sectype);
			(void) sa_security_name(security, oname,
			    sizeof (oname), id);
			if (groupname != NULL && sa_is_persistent(group)) {
				sa_handle_impl_t impl_handle;
				impl_handle =
				    (sa_handle_impl_t)sa_find_group_handle(
				    group);
				if (impl_handle != NULL) {
					(void) sa_get_instance(
					    impl_handle->scfhandle, groupname);
					(void) sa_create_pgroup(
					    impl_handle->scfhandle, oname);
				}
			}
		}
	}
	if (id != NULL)
		sa_free_attr_string(id);
	if (groupname != NULL)
		sa_free_attr_string(groupname);
	return (security);
}

/*
 * sa_destroy_security(security)
 *
 * Remove the specified optionset from the document and the
 * configuration.
 */

int
sa_destroy_security(sa_security_t security)
{
	char name[SA_STRSIZE];
	int len;
	int ret = SA_OK;
	char *id = NULL;
	sa_group_t group;
	int iszfs = 0;
	int ispersist = 1;

	group = sa_get_optionset_parent(security);

	if (group != NULL)
		iszfs = sa_group_is_zfs(group);

	if (group != NULL && !iszfs) {
		if (sa_is_share(group))
			ispersist = sa_is_persistent(group);
		id = sa_get_share_attr((sa_share_t)group, "id");
	}
	if (ispersist) {
		len = sa_security_name(security, name, sizeof (name), id);
		if (!iszfs && len > 0) {
			sa_handle_impl_t impl_handle;
			impl_handle =
			    (sa_handle_impl_t)sa_find_group_handle(group);
			if (impl_handle != NULL) {
				ret = sa_delete_pgroup(impl_handle->scfhandle,
				    name);
			} else {
				ret = SA_SYSTEM_ERR;
			}
		}
	}
	xmlUnlinkNode((xmlNodePtr)security);
	xmlFreeNode((xmlNodePtr)security);
	if (iszfs)
		ret = sa_zfs_update(group);
	if (id != NULL)
		sa_free_attr_string(id);
	return (ret);
}

/*
 * sa_get_security_attr(optionset, tag)
 *
 * Return the specified attribute value from the optionset.
 */

char *
sa_get_security_attr(sa_property_t optionset, char *tag)
{
	return (get_node_attr((void *)optionset, tag));

}

/*
 * sa_set_security_attr(optionset, tag, value)
 *
 * Set the optioset attribute specied by tag to the specified value.
 */

void
sa_set_security_attr(sa_group_t optionset, char *tag, char *value)
{
	set_node_attr((void *)optionset, tag, value);
}

/*
 * is_nodetype(node, type)
 *
 * Check to see if node is of the type specified.
 */

static int
is_nodetype(void *node, char *type)
{
	return (strcmp((char *)((xmlNodePtr)node)->name, type) == 0);
}

/*
 * add_or_update()
 *
 * Add or update a property. Pulled out of sa_set_prop_by_prop for
 * readability.
 */
static int
add_or_update(scfutilhandle_t *scf_handle, int type, scf_value_t *value,
    scf_transaction_entry_t *entry, char *name, char *valstr)
{
	int ret = SA_SYSTEM_ERR;

	if (value != NULL) {
		if (type == SA_PROP_OP_ADD)
			ret = scf_transaction_property_new(scf_handle->trans,
			    entry, name, SCF_TYPE_ASTRING);
		else
			ret = scf_transaction_property_change(scf_handle->trans,
			    entry, name, SCF_TYPE_ASTRING);
		if (ret == 0) {
			ret = scf_value_set_astring(value, valstr);
			if (ret == 0)
				ret = scf_entry_add_value(entry, value);
			if (ret == 0)
				return (ret);
			scf_value_destroy(value);
		} else {
			scf_entry_destroy(entry);
		}
	}
	return (SA_SYSTEM_ERR);
}

/*
 * sa_set_prop_by_prop(optionset, group, prop, type)
 *
 * Add/remove/update the specified property prop into the optionset or
 * share. If a share, sort out which property group based on GUID. In
 * all cases, the appropriate transaction is set (or ZFS share is
 * marked as needing an update)
 */

static int
sa_set_prop_by_prop(sa_optionset_t optionset, sa_group_t group,
			sa_property_t prop, int type)
{
	char *name;
	char *valstr;
	int ret = SA_OK;
	scf_transaction_entry_t *entry;
	scf_value_t *value;
	int opttype; /* 1 == optionset, 0 == security */
	char *id = NULL;
	int iszfs = 0;
	sa_group_t parent = NULL;
	sa_share_t share = NULL;
	sa_handle_impl_t impl_handle;
	scfutilhandle_t  *scf_handle;

	if (!sa_is_persistent(group)) {
		/*
		 * if the group/share is not persistent we don't need
		 * to do anything here
		 */
		return (SA_OK);
	}
	impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
	if (impl_handle == NULL || impl_handle->scfhandle == NULL)
		return (SA_SYSTEM_ERR);
	scf_handle = impl_handle->scfhandle;
	name = sa_get_property_attr(prop, "type");
	valstr = sa_get_property_attr(prop, "value");
	entry = scf_entry_create(scf_handle->handle);
	opttype = is_nodetype((void *)optionset, "optionset");

	/*
	 * Check for share vs. resource since they need slightly
	 * different treatment given the hierarchy.
	 */
	if (valstr != NULL && entry != NULL) {
		if (sa_is_share(group)) {
			parent = sa_get_parent_group(group);
			share = (sa_share_t)group;
			if (parent != NULL)
				iszfs = is_zfs_group(parent);
		} else if (sa_is_resource(group)) {
			share = sa_get_parent_group(group);
			if (share != NULL)
				parent = sa_get_parent_group(share);
		} else {
			iszfs = is_zfs_group(group);
		}
		if (!iszfs) {
			if (scf_handle->trans == NULL) {
				char oname[SA_STRSIZE];
				char *groupname = NULL;
				if (share != NULL) {
					if (parent != NULL)
						groupname =
						    sa_get_group_attr(parent,
						    "name");
					id = sa_get_share_attr(
					    (sa_share_t)share, "id");
				} else {
					groupname = sa_get_group_attr(group,
					    "name");
				}
				if (groupname != NULL) {
					ret = sa_get_instance(scf_handle,
					    groupname);
					sa_free_attr_string(groupname);
				}
				if (opttype)
					(void) sa_optionset_name(optionset,
					    oname, sizeof (oname), id);
				else
					(void) sa_security_name(optionset,
					    oname, sizeof (oname), id);
				ret = sa_start_transaction(scf_handle, oname);
				if (id != NULL)
					sa_free_attr_string(id);
			}
			if (ret == SA_OK) {
				switch (type) {
				case SA_PROP_OP_REMOVE:
					ret = scf_transaction_property_delete(
					    scf_handle->trans, entry, name);
					break;
				case SA_PROP_OP_ADD:
				case SA_PROP_OP_UPDATE:
					value = scf_value_create(
					    scf_handle->handle);
					ret = add_or_update(scf_handle, type,
					    value, entry, name, valstr);
					break;
				}
			}
		} else {
			/*
			 * ZFS update. The calling function would have updated
			 * the internal XML structure. Just need to flag it as
			 * changed for ZFS.
			 */
			zfs_set_update((sa_share_t)group);
		}
	}

	if (name != NULL)
		sa_free_attr_string(name);
	if (valstr != NULL)
		sa_free_attr_string(valstr);
	else if (entry != NULL)
		scf_entry_destroy(entry);

	if (ret == -1)
		ret = SA_SYSTEM_ERR;

	return (ret);
}

/*
 * sa_create_section(name, value)
 *
 * Create a new section with the specified name and extra data.
 */

sa_property_t
sa_create_section(char *name, char *extra)
{
	xmlNodePtr node;

	node = xmlNewNode(NULL, (xmlChar *)"section");
	if (node != NULL) {
		if (name != NULL)
			(void) xmlSetProp(node, (xmlChar *)"name",
			    (xmlChar *)name);
		if (extra != NULL)
			(void) xmlSetProp(node, (xmlChar *)"extra",
			    (xmlChar *)extra);
	}
	return ((sa_property_t)node);
}

void
sa_set_section_attr(sa_property_t sect, char *name, char *value)
{
	(void) xmlSetProp(sect, (xmlChar *)name, (xmlChar *)value);
}

/*
 * sa_create_property(section, name, value)
 *
 * Create a new property with the specified name and value.
 */

sa_property_t
sa_create_property(char *name, char *value)
{
	xmlNodePtr node;

	node = xmlNewNode(NULL, (xmlChar *)"option");
	if (node != NULL) {
		(void) xmlSetProp(node, (xmlChar *)"type", (xmlChar *)name);
		(void) xmlSetProp(node, (xmlChar *)"value", (xmlChar *)value);
	}
	return ((sa_property_t)node);
}

/*
 * sa_add_property(object, property)
 *
 * Add the specified property to the object. Issue the appropriate
 * transaction or mark a ZFS object as needing an update.
 */

int
sa_add_property(void *object, sa_property_t property)
{
	int ret = SA_OK;
	sa_group_t parent;
	sa_group_t group;
	char *proto;

	if (property != NULL) {
		sa_handle_t handle;
		handle = sa_find_group_handle((sa_group_t)object);
		/* It is legitimate to not find a handle */
		proto = sa_get_optionset_attr(object, "type");
		if ((ret = sa_valid_property(handle, object, proto,
		    property)) == SA_OK) {
			property = (sa_property_t)xmlAddChild(
			    (xmlNodePtr)object, (xmlNodePtr)property);
		} else {
			if (proto != NULL)
				sa_free_attr_string(proto);
			return (ret);
		}
		if (proto != NULL)
			sa_free_attr_string(proto);
	}


	parent = sa_get_parent_group(object);
	if (!sa_is_persistent(parent))
		return (ret);

	if (sa_is_resource(parent)) {
		/*
		 * Resources are children of share.  Need to go up two
		 * levels to find the group but the parent needs to be
		 * the share at this point in order to get the "id".
		 */
		parent = sa_get_parent_group(parent);
		group = sa_get_parent_group(parent);
	} else if (sa_is_share(parent)) {
		group = sa_get_parent_group(parent);
	} else {
		group = parent;
	}

	if (property == NULL) {
		ret = SA_NO_MEMORY;
	} else {
		char oname[SA_STRSIZE];

		if (!is_zfs_group(group)) {
			char *id = NULL;
			sa_handle_impl_t impl_handle;
			scfutilhandle_t  *scf_handle;

			impl_handle = (sa_handle_impl_t)sa_find_group_handle(
			    group);
			if (impl_handle == NULL ||
			    impl_handle->scfhandle == NULL)
				ret = SA_SYSTEM_ERR;
			if (ret == SA_OK) {
				scf_handle = impl_handle->scfhandle;
				if (sa_is_share((sa_group_t)parent)) {
					id = sa_get_share_attr(
					    (sa_share_t)parent, "id");
				}
				if (scf_handle->trans == NULL) {
					if (is_nodetype(object, "optionset")) {
						(void) sa_optionset_name(
						    (sa_optionset_t)object,
						    oname, sizeof (oname), id);
					} else {
						(void) sa_security_name(
						    (sa_optionset_t)object,
						    oname, sizeof (oname), id);
					}
					ret = sa_start_transaction(scf_handle,
					    oname);
				}
				if (ret == SA_OK) {
					char *name;
					char *value;
					name = sa_get_property_attr(property,
					    "type");
					value = sa_get_property_attr(property,
					    "value");
					if (name != NULL && value != NULL) {
						if (scf_handle->scf_state ==
						    SCH_STATE_INIT) {
							ret = sa_set_property(
							    scf_handle, name,
							    value);
						}
					} else {
						ret = SA_CONFIG_ERR;
					}
					if (name != NULL)
						sa_free_attr_string(
						    name);
					if (value != NULL)
						sa_free_attr_string(value);
				}
				if (id != NULL)
					sa_free_attr_string(id);
			}
		} else {
			/*
			 * ZFS is a special case. We do want
			 * to allow editing property/security
			 * lists since we can have a better
			 * syntax and we also want to keep
			 * things consistent when possible.
			 *
			 * Right now, we defer until the
			 * sa_commit_properties so we can get
			 * them all at once. We do need to
			 * mark the share as "changed"
			 */
			zfs_set_update((sa_share_t)parent);
		}
	}
	return (ret);
}

/*
 * sa_remove_property(property)
 *
 * Remove the specied property from its containing object. Update the
 * repository as appropriate.
 */

int
sa_remove_property(sa_property_t property)
{
	int ret = SA_OK;

	if (property != NULL) {
		sa_optionset_t optionset;
		sa_group_t group;
		optionset = sa_get_property_parent(property);
		if (optionset != NULL) {
			group = sa_get_optionset_parent(optionset);
			if (group != NULL) {
				ret = sa_set_prop_by_prop(optionset, group,
				    property, SA_PROP_OP_REMOVE);
			}
		}
		xmlUnlinkNode((xmlNodePtr)property);
		xmlFreeNode((xmlNodePtr)property);
	} else {
		ret = SA_NO_SUCH_PROP;
	}
	return (ret);
}

/*
 * sa_update_property(property, value)
 *
 * Update the specified property to the new value.  If value is NULL,
 * we currently treat this as a remove.
 */

int
sa_update_property(sa_property_t property, char *value)
{
	int ret = SA_OK;
	if (value == NULL) {
		return (sa_remove_property(property));
	} else {
		sa_optionset_t optionset;
		sa_group_t group;
		set_node_attr((void *)property, "value", value);
		optionset = sa_get_property_parent(property);
		if (optionset != NULL) {
			group = sa_get_optionset_parent(optionset);
			if (group != NULL) {
				ret = sa_set_prop_by_prop(optionset, group,
				    property, SA_PROP_OP_UPDATE);
			}
		} else {
			ret = SA_NO_SUCH_PROP;
		}
	}
	return (ret);
}

/*
 * sa_get_protocol_section(propset, prop)
 *
 * Get the specified protocol specific section. These are global to
 * the protocol and not specific to a group or share.
 */

sa_protocol_properties_t
sa_get_protocol_section(sa_protocol_properties_t propset, char *section)
{
	xmlNodePtr node = (xmlNodePtr)propset;
	xmlChar *value = NULL;
	char *proto;

	proto = sa_get_optionset_attr(propset, "type");
	if ((sa_proto_get_featureset(proto) & SA_FEATURE_HAS_SECTIONS) == 0) {
		if (proto != NULL)
			sa_free_attr_string(proto);
		return (propset);
	}

	for (node = node->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"section") == 0) {
			if (section == NULL)
				break;
			value = xmlGetProp(node, (xmlChar *)"name");
			if (value != NULL &&
			    xmlStrcasecmp(value, (xmlChar *)section) == 0) {
				break;
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}
		}
	}
	if (value != NULL)
		xmlFree(value);
	if (proto != NULL)
		sa_free_attr_string(proto);
	if (node != NULL && xmlStrcmp(node->name, (xmlChar *)"section") != 0) {
		/*
		 * avoid a non option node -- it is possible to be a
		 * text node
		 */
		node = NULL;
	}
	return ((sa_protocol_properties_t)node);
}

/*
 * sa_get_next_protocol_section(prop, find)
 *
 * Get the next protocol specific section in the list.
 */

sa_property_t
sa_get_next_protocol_section(sa_property_t prop, char *find)
{
	xmlNodePtr node;
	xmlChar *value = NULL;
	char *proto;

	proto = sa_get_optionset_attr(prop, "type");
	if ((sa_proto_get_featureset(proto) & SA_FEATURE_HAS_SECTIONS) == 0) {
		if (proto != NULL)
			sa_free_attr_string(proto);
		return ((sa_property_t)NULL);
	}

	for (node = ((xmlNodePtr)prop)->next; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"section") == 0) {
			if (find == NULL)
				break;
			value = xmlGetProp(node, (xmlChar *)"name");
			if (value != NULL &&
			    xmlStrcasecmp(value, (xmlChar *)find) == 0) {
				break;
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}

		}
	}
	if (value != NULL)
		xmlFree(value);
	if (proto != NULL)
		sa_free_attr_string(proto);
	return ((sa_property_t)node);
}

/*
 * sa_get_protocol_property(propset, prop)
 *
 * Get the specified protocol specific property. These are global to
 * the protocol and not specific to a group or share.
 */

sa_property_t
sa_get_protocol_property(sa_protocol_properties_t propset, char *prop)
{
	xmlNodePtr node = (xmlNodePtr)propset;
	xmlChar *value = NULL;

	if (propset == NULL)
		return (NULL);

	for (node = node->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			if (prop == NULL)
				break;
			value = xmlGetProp(node, (xmlChar *)"type");
			if (value != NULL &&
			    xmlStrcasecmp(value, (xmlChar *)prop) == 0) {
				break;
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}
		}
	}
	if (value != NULL)
		xmlFree(value);
	if (node != NULL && xmlStrcmp(node->name, (xmlChar *)"option") != 0) {
		/*
		 * avoid a non option node -- it is possible to be a
		 * text node
		 */
		node = NULL;
	}
	return ((sa_property_t)node);
}

/*
 * sa_get_next_protocol_property(prop)
 *
 * Get the next protocol specific property in the list.
 */

sa_property_t
sa_get_next_protocol_property(sa_property_t prop, char *find)
{
	xmlNodePtr node;
	xmlChar *value = NULL;

	for (node = ((xmlNodePtr)prop)->next; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			if (find == NULL)
				break;
			value = xmlGetProp(node, (xmlChar *)"type");
			if (value != NULL &&
			    xmlStrcasecmp(value, (xmlChar *)find) == 0) {
				break;
			}
			if (value != NULL) {
				xmlFree(value);
				value = NULL;
			}

		}
	}
	if (value != NULL)
		xmlFree(value);
	return ((sa_property_t)node);
}

/*
 * sa_set_protocol_property(prop, value)
 *
 * Set the specified property to have the new value.  The protocol
 * specific plugin will then be called to update the property.
 */

int
sa_set_protocol_property(sa_property_t prop, char *section, char *value)
{
	sa_protocol_properties_t propset;
	char *proto;
	int ret = SA_INVALID_PROTOCOL;

	propset = ((xmlNodePtr)prop)->parent;
	if (propset != NULL) {
		proto = sa_get_optionset_attr(propset, "type");
		if (proto != NULL) {
			if (section != NULL)
				set_node_attr((xmlNodePtr)prop, "section",
				    section);
			set_node_attr((xmlNodePtr)prop, "value", value);
			ret = sa_proto_set_property(proto, prop);
			sa_free_attr_string(proto);
		}
	}
	return (ret);
}

/*
 * sa_add_protocol_property(propset, prop)
 *
 * Add a new property to the protocol specific property set.
 */

int
sa_add_protocol_property(sa_protocol_properties_t propset, sa_property_t prop)
{
	xmlNodePtr node;

	/* should check for legitimacy */
	node = xmlAddChild((xmlNodePtr)propset, (xmlNodePtr)prop);
	if (node != NULL)
		return (SA_OK);
	return (SA_NO_MEMORY);
}

/*
 * sa_create_protocol_properties(proto)
 *
 * Create a protocol specific property set.
 */

sa_protocol_properties_t
sa_create_protocol_properties(char *proto)
{
	xmlNodePtr node;

	node = xmlNewNode(NULL, (xmlChar *)"propertyset");
	if (node != NULL)
		(void) xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	return (node);
}

/*
 * sa_get_share_resource(share, resource)
 *
 * Get the named resource from the share, if it exists. If resource is
 * NULL, get the first resource.
 */

sa_resource_t
sa_get_share_resource(sa_share_t share, char *resource)
{
	xmlNodePtr node = NULL;
	xmlChar *name;

	if (share != NULL) {
		for (node = ((xmlNodePtr)share)->children; node != NULL;
		    node = node->next) {
			if (xmlStrcmp(node->name, (xmlChar *)"resource") == 0) {
				if (resource == NULL) {
					/*
					 * We are looking for the first
					 * resource node and not a names
					 * resource.
					 */
					break;
				} else {
					/* is it the correct share? */
					name = xmlGetProp(node,
					    (xmlChar *)"name");
					if (name != NULL &&
					    xmlStrcasecmp(name,
					    (xmlChar *)resource) == 0) {
						xmlFree(name);
						break;
					}
					xmlFree(name);
				}
			}
		}
	}
	return ((sa_resource_t)node);
}

/*
 * sa_get_next_resource(resource)
 *	Return the next share following the specified share
 *	from the internal list of shares. Returns NULL if there
 *	are no more shares.  The list is relative to the same
 *	group.
 */
sa_share_t
sa_get_next_resource(sa_resource_t resource)
{
	xmlNodePtr node = NULL;

	if (resource != NULL) {
		for (node = ((xmlNodePtr)resource)->next; node != NULL;
		    node = node->next) {
			if (xmlStrcmp(node->name, (xmlChar *)"resource") == 0)
				break;
		}
	}
	return ((sa_share_t)node);
}

/*
 * _sa_get_next_resource_index(share)
 *
 * get the next resource index number (one greater then current largest)
 */

static int
_sa_get_next_resource_index(sa_share_t share)
{
	sa_resource_t resource;
	int index = 0;
	char *id;

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource)) {
		id = get_node_attr((void *)resource, "id");
		if (id != NULL) {
			int val;
			val = atoi(id);
			if (val > index)
				index = val;
			sa_free_attr_string(id);
		}
	}
	return (index + 1);
}


/*
 * sa_add_resource(share, resource, persist, &err)
 *
 * Adds a new resource name associated with share. The resource name
 * must be unique in the system and will be case insensitive (eventually).
 */

sa_resource_t
sa_add_resource(sa_share_t share, char *resource, int persist, int *error)
{
	xmlNodePtr node;
	int err = SA_OK;
	sa_resource_t res;
	sa_group_t group;
	sa_handle_t handle;
	char istring[8]; /* just big enough for an integer value */
	int index;

	group = sa_get_parent_group(share);
	handle = sa_find_group_handle(group);
	res = sa_find_resource(handle, resource);
	if (res != NULL) {
		err = SA_DUPLICATE_NAME;
		res = NULL;
	} else {
		node = xmlNewChild((xmlNodePtr)share, NULL,
		    (xmlChar *)"resource", NULL);
		if (node != NULL) {
			(void) xmlSetProp(node, (xmlChar *)"name",
			    (xmlChar *)resource);
			(void) xmlSetProp(node, (xmlChar *)"type", persist ?
			    (xmlChar *)"persist" : (xmlChar *)"transient");
			if (persist != SA_SHARE_TRANSIENT) {
				index = _sa_get_next_resource_index(share);
				(void) snprintf(istring, sizeof (istring), "%d",
				    index);
				(void) xmlSetProp(node, (xmlChar *)"id",
				    (xmlChar *)istring);

				if (!sa_is_persistent((sa_group_t)share))
					goto done;

				if (!sa_group_is_zfs(group)) {
					/* ZFS doesn't use resource names */
					sa_handle_impl_t ihandle;

					ihandle = (sa_handle_impl_t)
					    sa_find_group_handle(
					    group);
					if (ihandle != NULL)
						err = sa_commit_share(
						    ihandle->scfhandle, group,
						    share);
					else
						err = SA_SYSTEM_ERR;
				} else {
					err = sa_zfs_update((sa_share_t)group);
				}
			}
		}
	}
done:
	if (error != NULL)
		*error = err;
	return ((sa_resource_t)node);
}

/*
 * sa_remove_resource(resource)
 *
 * Remove the resource name from the share (and the system)
 */

int
sa_remove_resource(sa_resource_t resource)
{
	sa_share_t share;
	sa_group_t group;
	char *type;
	int ret = SA_OK;
	boolean_t transient = B_FALSE;
	sa_optionset_t opt;

	share = sa_get_resource_parent(resource);
	type = sa_get_share_attr(share, "type");
	group = sa_get_parent_group(share);


	if (type != NULL) {
		if (strcmp(type, "persist") != 0)
			transient = B_TRUE;
		sa_free_attr_string(type);
	}

	/* Disable the resource for all protocols. */
	(void) sa_disable_resource(resource, NULL);

	/* Remove any optionsets from the resource. */
	for (opt = sa_get_optionset(resource, NULL);
	    opt != NULL;
	    opt = sa_get_next_optionset(opt))
		(void) sa_destroy_optionset(opt);

	/* Remove from the share */
	xmlUnlinkNode((xmlNode *)resource);
	xmlFreeNode((xmlNode *)resource);

	/* only do SMF action if permanent and not ZFS */
	if (transient)
		return (ret);

	if (!sa_group_is_zfs(group)) {
		sa_handle_impl_t ihandle;
		ihandle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (ihandle != NULL)
			ret = sa_commit_share(ihandle->scfhandle, group, share);
		else
			ret = SA_SYSTEM_ERR;
	} else {
		ret = sa_zfs_update((sa_share_t)group);
	}

	return (ret);
}

/*
 * proto_rename_resource(handle, group, resource, newname)
 *
 * Helper function for sa_rename_resource that notifies the protocol
 * of a resource name change prior to a config repository update.
 */
static int
proto_rename_resource(sa_handle_t handle, sa_group_t group,
    sa_resource_t resource, char *newname)
{
	sa_optionset_t optionset;
	int ret = SA_OK;
	int err;

	for (optionset = sa_get_optionset(group, NULL);
	    optionset != NULL;
	    optionset = sa_get_next_optionset(optionset)) {
		char *type;
		type = sa_get_optionset_attr(optionset, "type");
		if (type != NULL) {
			err = sa_proto_rename_resource(handle, type, resource,
			    newname);
			if (err != SA_OK)
				ret = err;
			sa_free_attr_string(type);
		}
	}
	return (ret);
}

/*
 * sa_rename_resource(resource, newname)
 *
 * Rename the resource to the new name, if it is unique.
 */

int
sa_rename_resource(sa_resource_t resource, char *newname)
{
	sa_share_t share;
	sa_group_t group = NULL;
	sa_resource_t target;
	int ret = SA_CONFIG_ERR;
	sa_handle_t handle = NULL;

	share = sa_get_resource_parent(resource);
	if (share == NULL)
		return (ret);

	group = sa_get_parent_group(share);
	if (group == NULL)
		return (ret);

	handle = (sa_handle_impl_t)sa_find_group_handle(group);
	if (handle == NULL)
		return (ret);

	target = sa_find_resource(handle, newname);
	if (target != NULL) {
		ret = SA_DUPLICATE_NAME;
	} else {
		/*
		 * Everything appears to be valid at this
		 * point. Change the name of the active share and then
		 * update the share in the appropriate repository.
		 */
		ret = proto_rename_resource(handle, group, resource, newname);
		set_node_attr(resource, "name", newname);

		if (!sa_is_persistent((sa_group_t)share))
			return (ret);

		if (!sa_group_is_zfs(group)) {
			sa_handle_impl_t ihandle = (sa_handle_impl_t)handle;
			ret = sa_commit_share(ihandle->scfhandle, group,
			    share);
		} else {
			ret = sa_zfs_update((sa_share_t)group);
		}
	}
	return (ret);
}

/*
 * sa_get_resource_attr(resource, tag)
 *
 * Get the named attribute of the resource. "name" and "id" are
 * currently defined.  NULL if tag not defined.
 */

char *
sa_get_resource_attr(sa_resource_t resource, char *tag)
{
	return (get_node_attr((void *)resource, tag));
}

/*
 * sa_set_resource_attr(resource, tag, value)
 *
 * Get the named attribute of the resource. "name" and "id" are
 * currently defined.  NULL if tag not defined. Currently we don't do
 * much, but additional checking may be needed in the future.
 */

int
sa_set_resource_attr(sa_resource_t resource, char *tag, char *value)
{
	set_node_attr((void *)resource, tag, value);
	return (SA_OK);
}

/*
 * sa_get_resource_parent(resource_t)
 *
 * Returns the share associated with the resource.
 */

sa_share_t
sa_get_resource_parent(sa_resource_t resource)
{
	sa_share_t share = NULL;

	if (resource != NULL)
		share = (sa_share_t)((xmlNodePtr)resource)->parent;
	return (share);
}

/*
 * find_resource(group, name)
 *
 * Find the resource within the group.
 */

static sa_resource_t
find_resource(sa_group_t group, char *resname)
{
	sa_share_t share;
	sa_resource_t resource = NULL;
	char *name;

	/* Iterate over all the shares and resources in the group. */
	for (share = sa_get_share(group, NULL);
	    share != NULL && resource == NULL;
	    share = sa_get_next_share(share)) {
		for (resource = sa_get_share_resource(share, NULL);
		    resource != NULL;
		    resource = sa_get_next_resource(resource)) {
			name = sa_get_resource_attr(resource, "name");
			if (name != NULL && xmlStrcasecmp((xmlChar*)name,
			    (xmlChar*)resname) == 0) {
				sa_free_attr_string(name);
				break;
			}
			if (name != NULL) {
				sa_free_attr_string(name);
			}
		}
	}
	return (resource);
}

/*
 * sa_find_resource(name)
 *
 * Find the named resource in the system.
 */

sa_resource_t
sa_find_resource(sa_handle_t handle, char *name)
{
	sa_group_t group;
	sa_group_t zgroup;
	sa_resource_t resource = NULL;

	/*
	 * Iterate over all groups and zfs subgroups and check for
	 * resource name in them.
	 */
	for (group = sa_get_group(handle, NULL); group != NULL;
	    group = sa_get_next_group(group)) {

		if (is_zfs_group(group)) {
			for (zgroup =
			    (sa_group_t)_sa_get_child_node((xmlNodePtr)group,
			    (xmlChar *)"group");
			    zgroup != NULL && resource == NULL;
			    zgroup = sa_get_next_group(zgroup)) {
				resource = find_resource(zgroup, name);
			}
		} else {
			resource = find_resource(group, name);
		}
		if (resource != NULL)
			break;
	}
	return (resource);
}

/*
 * sa_get_resource(group, resource)
 *
 * Search all the shares in the specified group for a share with a
 * resource name matching the one specified.
 *
 * In the future, it may be advantageous to allow group to be NULL and
 * search all groups but that isn't needed at present.
 */

sa_resource_t
sa_get_resource(sa_group_t group, char *resource)
{
	sa_share_t share = NULL;
	sa_resource_t res = NULL;

	if (resource != NULL) {
		for (share = sa_get_share(group, NULL);
		    share != NULL && res == NULL;
		    share = sa_get_next_share(share)) {
			res = sa_get_share_resource(share, resource);
		}
	}
	return (res);
}

/*
 * get_protocol_list(optionset, object)
 *
 * Get the protocol optionset list for the object and add them as
 * properties to optionset.
 */
static int
get_protocol_list(sa_optionset_t optionset, void *object)
{
	sa_property_t prop;
	sa_optionset_t opts;
	int ret = SA_OK;

	for (opts = sa_get_optionset(object, NULL);
	    opts != NULL;
	    opts = sa_get_next_optionset(opts)) {
		char *type;
		type = sa_get_optionset_attr(opts, "type");
		/*
		 * It is possible to have a non-protocol optionset. We
		 * skip any of those found.
		 */
		if (type == NULL)
			continue;
		prop = sa_create_property(type, "true");
		sa_free_attr_string(type);
		if (prop != NULL)
			prop = (sa_property_t)xmlAddChild((xmlNodePtr)optionset,
			    (xmlNodePtr)prop);
		/* If prop is NULL, don't bother continuing */
		if (prop == NULL) {
			ret = SA_NO_MEMORY;
			break;
		}
	}
	return (ret);
}

/*
 * sa_free_protoset(optionset)
 *
 * Free the protocol property optionset.
 */
static void
sa_free_protoset(sa_optionset_t optionset)
{
	if (optionset != NULL) {
		xmlUnlinkNode((xmlNodePtr) optionset);
		xmlFreeNode((xmlNodePtr) optionset);
	}
}

/*
 * sa_optionset_t sa_get_active_protocols(object)
 *
 * Return a list of the protocols that are active for the object.
 * This is currently an internal helper function, but could be
 * made visible if there is enough demand for it.
 *
 * The function finds the parent group and extracts the protocol
 * optionsets creating a new optionset with the protocols as properties.
 *
 * The caller must free the returned optionset.
 */

static sa_optionset_t
sa_get_active_protocols(void *object)
{
	sa_optionset_t options;
	sa_share_t share = NULL;
	sa_group_t group = NULL;
	sa_resource_t resource = NULL;
	int ret = SA_OK;

	if (object == NULL)
		return (NULL);
	options = (sa_optionset_t)xmlNewNode(NULL, (xmlChar *)"optionset");
	if (options == NULL)
		return (NULL);

	/*
	 * Find the objects up the tree that might have protocols
	 * enabled on them.
	 */
	if (sa_is_resource(object)) {
		resource = (sa_resource_t)object;
		share = sa_get_resource_parent(resource);
		group = sa_get_parent_group(share);
	} else if (sa_is_share(object)) {
		share = (sa_share_t)object;
		group = sa_get_parent_group(share);
	} else {
		group = (sa_group_t)group;
	}
	if (resource != NULL)
		ret = get_protocol_list(options, resource);
	if (ret == SA_OK && share != NULL)
		ret = get_protocol_list(options, share);
	if (ret == SA_OK && group != NULL)
		ret = get_protocol_list(options, group);

	/*
	 * If there was an error, we won't have a complete list so
	 * abandon everything.  The caller will have to deal with the
	 * issue.
	 */
	if (ret != SA_OK) {
		sa_free_protoset(options);
		options = NULL;
	}
	return (options);
}

/*
 * sa_enable_resource, protocol)
 *	Disable the specified share to the specified protocol.
 *	If protocol is NULL, then all protocols.
 */
int
sa_enable_resource(sa_resource_t resource, char *protocol)
{
	int ret = SA_OK;

	if (protocol != NULL) {
		ret = sa_proto_share_resource(protocol, resource);
	} else {
		sa_optionset_t protoset;
		sa_property_t prop;
		char *proto;
		int err;

		/* need to do all protocols */
		protoset = sa_get_active_protocols(resource);
		if (protoset == NULL)
			return (SA_NO_MEMORY);
		for (prop = sa_get_property(protoset, NULL);
		    prop != NULL;
		    prop = sa_get_next_property(prop)) {
			proto = sa_get_property_attr(prop, "type");
			if (proto == NULL) {
				ret = SA_NO_MEMORY;
				continue;
			}
			err = sa_proto_share_resource(proto, resource);
			if (err != SA_OK)
				ret = err;
			sa_free_attr_string(proto);
		}
		sa_free_protoset(protoset);
	}
	if (ret == SA_OK)
		(void) sa_set_resource_attr(resource, "shared", NULL);

	return (ret);
}

/*
 * sa_disable_resource(resource, protocol)
 *
 *	Disable the specified share for the specified protocol.  If
 *	protocol is NULL, then all protocols.  If the underlying
 *	protocol doesn't implement disable at the resource level, we
 *	disable at the share level.
 */
int
sa_disable_resource(sa_resource_t resource, char *protocol)
{
	int ret = SA_OK;

	if (protocol != NULL) {
		ret = sa_proto_unshare_resource(protocol, resource);
		if (ret == SA_NOT_IMPLEMENTED) {
			sa_share_t parent;
			/*
			 * The protocol doesn't implement unshare
			 * resource. That implies that resource names are
			 * simple aliases for this protocol so we need to
			 * unshare the share.
			 */
			parent = sa_get_resource_parent(resource);
			if (parent != NULL)
				ret = sa_disable_share(parent, protocol);
			else
				ret = SA_CONFIG_ERR;
		}
	} else {
		sa_optionset_t protoset;
		sa_property_t prop;
		char *proto;
		int err;

		/* need to do all protocols */
		protoset = sa_get_active_protocols(resource);
		if (protoset == NULL)
			return (SA_NO_MEMORY);
		for (prop = sa_get_property(protoset, NULL);
		    prop != NULL;
		    prop = sa_get_next_property(prop)) {
			proto = sa_get_property_attr(prop, "type");
			if (proto == NULL) {
				ret = SA_NO_MEMORY;
				continue;
			}
			err = sa_proto_unshare_resource(proto, resource);
			if (err == SA_NOT_SUPPORTED) {
				sa_share_t parent;
				parent = sa_get_resource_parent(resource);
				if (parent != NULL)
					err = sa_disable_share(parent, proto);
				else
					err = SA_CONFIG_ERR;
			}
			if (err != SA_OK)
				ret = err;
			sa_free_attr_string(proto);
		}
		sa_free_protoset(protoset);
	}
	if (ret == SA_OK)
		(void) sa_set_resource_attr(resource, "shared", NULL);

	return (ret);
}

/*
 * sa_set_resource_description(resource, content)
 *
 * Set the description of share to content.
 */

int
sa_set_resource_description(sa_resource_t resource, char *content)
{
	xmlNodePtr node;
	sa_group_t group;
	sa_share_t share;
	int ret = SA_OK;

	for (node = ((xmlNodePtr)resource)->children;
	    node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"description") == 0) {
			break;
		}
	}

	/* no existing description but want to add */
	if (node == NULL && content != NULL) {
		/* add a description */
		node = _sa_set_share_description(resource, content);
	} else if (node != NULL && content != NULL) {
		/* update a description */
		xmlNodeSetContent(node, (xmlChar *)content);
	} else if (node != NULL && content == NULL) {
		/* remove an existing description */
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}

	share = sa_get_resource_parent(resource);
	group = sa_get_parent_group(share);
	if (group != NULL &&
	    sa_is_persistent(share) && (!sa_group_is_zfs(group))) {
		sa_handle_impl_t impl_handle;
		impl_handle = (sa_handle_impl_t)sa_find_group_handle(group);
		if (impl_handle != NULL)
			ret = sa_commit_share(impl_handle->scfhandle,
			    group, share);
		else
			ret = SA_SYSTEM_ERR;
	}
	return (ret);
}

/*
 * sa_get_resource_description(share)
 *
 * Return the description text for the specified share if it
 * exists. NULL if no description exists.
 */

char *
sa_get_resource_description(sa_resource_t resource)
{
	xmlChar *description = NULL;
	xmlNodePtr node;

	for (node = ((xmlNodePtr)resource)->children; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"description") == 0)
			break;
	}
	if (node != NULL) {
		description = xmlNodeGetContent(node);
		fixproblemchars((char *)description);
	}
	return ((char *)description);
}
