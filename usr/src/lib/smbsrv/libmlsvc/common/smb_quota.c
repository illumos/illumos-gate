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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <attr.h>
#include <unistd.h>
#include <libuutil.h>
#include <libzfs.h>
#include <assert.h>
#include <stddef.h>
#include <strings.h>
#include <errno.h>
#include <synch.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_idmap.h>
#include <mlsvc.h>
#include <sys/avl.h>

/*
 * smb_quota subsystem interface - mlsvc.h
 * ---------------------------------------
 * Management of the smb_quota_fs_list (see below).
 * smb_quota_init
 * smb_quota_fini
 * smb_quota_add_fs
 * smb_quota_remove_fs
 *
 * smb_quota public interface - libmlsvc.h
 * ---------------------------------------
 * Handling of requests to query and set quota data on a filesystem.
 * smb_quota_query - query user/group quotas on a filesystem
 * smb_quota_set - set user/group quotas ona filesystem
 * smb_quota_free - delete the quota list created in smb_quota_query
 */

/*
 * Querying user & group quotas - smb_quota_query
 *
 * In order to fulfill the quota query requests that can be received
 * from clients, it is required that the quota data can be provided in
 * a well defined and consistent order, and that a request can specify
 * at which quota entry to begin the query.
 *
 * Quota Tree
 * Since the file system does not support the above, an avl tree is
 * populated with the file system's user and group quota data, and
 * then used to provide the data to respond to query requests. The
 * avl tree is indexed by the SID.
 * Each node of the avl tree is an smb_quota_t structure.
 *
 * Quota List
 * There is a list of avl trees, one per file system.
 * Each node in the list is an smb_quota_tree_t structure.
 * The list is created via a call to smb_quota_init() when the library
 * is initialized, and destroyed via a call to smb_quota_fini() when
 * the library is fini'd.
 *
 * An avl tree for a specific file system is created and added to the
 * list via a call to smb_quota_add_fs() when the file system is shared,
 * and removed from the list via a call to smb_quota_remove_fs() when
 * the file system is unshared.
 *
 * An avl tree is (re)populated, if required, whenever a quota request
 * (EXCLUDING a resume request) is received for its filesystem. The
 * avl tree is considered to be expired (needs to be repopulated) if
 * either of the following have occurred since it was last (re)populated:
 * - SMB_QUOTA_REFRESH seconds have elapsed OR
 * - a quota set operation has been performed on its file system
 *
 * In order to perform a smb_quota_query/set operation on a file system
 * the appropriate quota tree must be identified and locked via a call
 * to smb_quota_tree_lookup(), The quota tree is locked (qt_locked == B_TRUE)
 * until the caller releases it via a call to smb_quota_tree_release().
 */

/*
 * smb_quota_tree_t
 * Represents an avl tree of user quotas for a file system.
 *
 * qt_refcnt - a count of the number of users of the tree.
 * qt_refcnt is also incremented and decremented when the tree is
 * added to and removed from the quota list.
 * The tree cannot be deleted until this count is zero.
 *
 * qt_sharecnt - a count of the shares of the file system which the
 * tree represents.  smb_quota_remove_fs() cannot remove the tree from
 * removed from the quota list until this count is zero.
 *
 * qt_locked - B_TRUE if someone is currently using the tree, in
 * which case a lookup will wait for the tree to become available.
 */
typedef struct smb_quota_tree {
	list_node_t	qt_node;
	char		*qt_path;
	time_t		qt_timestamp;
	uint32_t	qt_refcnt;
	uint32_t	qt_sharecnt;
	boolean_t	qt_locked;
	avl_tree_t	qt_avl;
	mutex_t		qt_mutex;
}smb_quota_tree_t;

/*
 * smb_quota_fs_list
 * list of quota trees; one per shared file system.
 */
static list_t smb_quota_fs_list;
static boolean_t smb_quota_list_init = B_FALSE;
static boolean_t smb_quota_shutdown = B_FALSE;
static mutex_t smb_quota_list_mutex = DEFAULTMUTEX;
static cond_t smb_quota_list_condvar;
static uint32_t smb_quota_tree_cnt = 0;
static int smb_quota_fini_timeout = 1; /* seconds */

/*
 * smb_quota_zfs_handle_t
 * handle to zfs library and dataset
 */
typedef struct smb_quota_zfs_handle {
	libzfs_handle_t *z_lib;
	zfs_handle_t *z_fs;
} smb_quota_zfs_handle_t;

/*
 * smb_quota_zfs_arg_t
 * arg passed to zfs callback when querying quota properties
 */
typedef struct smb_quota_zfs_arg {
	zfs_userquota_prop_t qa_prop;
	avl_tree_t *qa_avl;
} smb_quota_zfs_arg_t;

static void smb_quota_add_ctrldir(const char *);
static void smb_quota_remove_ctrldir(const char *);

static smb_quota_tree_t *smb_quota_tree_create(const char *);
static void smb_quota_tree_delete(smb_quota_tree_t *);

static smb_quota_tree_t *smb_quota_tree_lookup(const char *);
static void smb_quota_tree_release(smb_quota_tree_t *);
static boolean_t smb_quota_tree_match(smb_quota_tree_t *, const char *);
static int smb_quota_sid_cmp(const void *, const void *);
static uint32_t smb_quota_tree_populate(smb_quota_tree_t *);
static boolean_t smb_quota_tree_expired(smb_quota_tree_t *);
static void smb_quota_tree_set_expired(smb_quota_tree_t *);

static uint32_t smb_quota_zfs_init(const char *, smb_quota_zfs_handle_t *);
static void smb_quota_zfs_fini(smb_quota_zfs_handle_t *);
static uint32_t smb_quota_zfs_get_quotas(smb_quota_tree_t *);
static int smb_quota_zfs_callback(void *, const char *, uid_t, uint64_t);
static uint32_t smb_quota_zfs_set_quotas(smb_quota_tree_t *, smb_quota_set_t *);
static int smb_quota_sidstr(uint32_t, zfs_userquota_prop_t, char *);
static uint32_t smb_quota_sidtype(smb_quota_tree_t *, char *);
static int smb_quota_getid(char *, uint32_t, uint32_t *);

static uint32_t smb_quota_query_all(smb_quota_tree_t *,
    smb_quota_query_t *, smb_quota_response_t *);
static uint32_t smb_quota_query_list(smb_quota_tree_t *,
    smb_quota_query_t *, smb_quota_response_t *);

#define	SMB_QUOTA_REFRESH		2
#define	SMB_QUOTA_CMD_LENGTH		21
#define	SMB_QUOTA_CMD_STR_LENGTH	SMB_SID_STRSZ+SMB_QUOTA_CMD_LENGTH

/*
 * In order to display the quota properties tab, windows clients
 * check for the existence of the quota control file.
 */
#define	SMB_QUOTA_CNTRL_DIR		".$EXTEND"
#define	SMB_QUOTA_CNTRL_FILE		"$QUOTA"
#define	SMB_QUOTA_CNTRL_INDEX_XATTR	"SUNWsmb:$Q:$INDEX_ALLOCATION"
/*
 * Note: this line needs to have the same format as what acl_totext() returns.
 */
#define	SMB_QUOTA_CNTRL_PERM		"everyone@:rw-p--aARWc--s:-------:allow"

/*
 * smb_quota_init
 * Initialize the list to hold the quota trees.
 */
void
smb_quota_init(void)
{
	(void) mutex_lock(&smb_quota_list_mutex);
	if (!smb_quota_list_init) {
		list_create(&smb_quota_fs_list, sizeof (smb_quota_tree_t),
		    offsetof(smb_quota_tree_t, qt_node));
		smb_quota_list_init = B_TRUE;
		smb_quota_shutdown = B_FALSE;
	}
	(void) mutex_unlock(&smb_quota_list_mutex);
}

/*
 * smb_quota_fini
 *
 * Wait for each quota tree to not be in use (qt_refcnt == 1)
 * then remove it from the list and delete it.
 */
void
smb_quota_fini(void)
{
	smb_quota_tree_t *qtree, *qtree_next;
	boolean_t remove;
	struct timespec tswait;
	tswait.tv_sec = smb_quota_fini_timeout;
	tswait.tv_nsec = 0;

	(void) mutex_lock(&smb_quota_list_mutex);
	smb_quota_shutdown = B_TRUE;

	if (!smb_quota_list_init) {
		(void) mutex_unlock(&smb_quota_list_mutex);
		return;
	}

	(void) cond_broadcast(&smb_quota_list_condvar);

	while (!list_is_empty(&smb_quota_fs_list)) {
		qtree = list_head(&smb_quota_fs_list);
		while (qtree != NULL) {
			qtree_next = list_next(&smb_quota_fs_list, qtree);

			(void) mutex_lock(&qtree->qt_mutex);
			remove = (qtree->qt_refcnt == 1);
			if (remove) {
				list_remove(&smb_quota_fs_list, qtree);
				--qtree->qt_refcnt;
			}
			(void) mutex_unlock(&qtree->qt_mutex);

			if (remove)
				smb_quota_tree_delete(qtree);

			qtree = qtree_next;
		}

		if (!list_is_empty(&smb_quota_fs_list)) {
			if (cond_reltimedwait(&smb_quota_list_condvar,
			    &smb_quota_list_mutex, &tswait) == ETIME) {
				syslog(LOG_WARNING,
				    "quota shutdown timeout expired");
				break;
			}
		}
	}

	if (list_is_empty(&smb_quota_fs_list)) {
		list_destroy(&smb_quota_fs_list);
		smb_quota_list_init = B_FALSE;
	}

	(void) mutex_unlock(&smb_quota_list_mutex);
}

/*
 * smb_quota_add_fs
 *
 * If there is not a quota tree representing the specified path,
 * create one and add it to the list.
 */
void
smb_quota_add_fs(const char *path)
{
	smb_quota_tree_t *qtree;

	(void) mutex_lock(&smb_quota_list_mutex);

	if (!smb_quota_list_init || smb_quota_shutdown) {
		(void) mutex_unlock(&smb_quota_list_mutex);
		return;
	}

	qtree = list_head(&smb_quota_fs_list);
	while (qtree != NULL) {
		if (smb_quota_tree_match(qtree, path)) {
			(void) mutex_lock(&qtree->qt_mutex);
			++qtree->qt_sharecnt;
			(void) mutex_unlock(&qtree->qt_mutex);
			break;
		}
		qtree = list_next(&smb_quota_fs_list, qtree);
	}

	if (qtree == NULL) {
		qtree = smb_quota_tree_create(path);
		if (qtree)
			list_insert_head(&smb_quota_fs_list, (void *)qtree);
	}

	if (qtree)
		smb_quota_add_ctrldir(path);

	(void) mutex_unlock(&smb_quota_list_mutex);
}

/*
 * smb_quota_remove_fs
 *
 * If this is the last share that the quota tree represents
 * (qtree->qt_sharecnt == 0) remove the qtree from the list.
 * The qtree will be deleted if/when there is nobody using it
 * (qtree->qt_refcnt == 0).
 */
void
smb_quota_remove_fs(const char *path)
{
	smb_quota_tree_t *qtree;
	boolean_t delete = B_FALSE;

	(void) mutex_lock(&smb_quota_list_mutex);

	if (!smb_quota_list_init || smb_quota_shutdown) {
		(void) mutex_unlock(&smb_quota_list_mutex);
		return;
	}

	qtree = list_head(&smb_quota_fs_list);
	while (qtree != NULL) {
		assert(qtree->qt_refcnt > 0);
		if (smb_quota_tree_match(qtree, path)) {
			(void) mutex_lock(&qtree->qt_mutex);
			--qtree->qt_sharecnt;
			if (qtree->qt_sharecnt == 0) {
				list_remove(&smb_quota_fs_list, (void *)qtree);
				smb_quota_remove_ctrldir(qtree->qt_path);
				--(qtree->qt_refcnt);
				delete = (qtree->qt_refcnt == 0);
			}
			(void) mutex_unlock(&qtree->qt_mutex);
			if (delete)
				smb_quota_tree_delete(qtree);
			break;
		}
		qtree = list_next(&smb_quota_fs_list, qtree);
	}
	(void) mutex_unlock(&smb_quota_list_mutex);
}

/*
 * smb_quota_query
 *
 * Get list of user/group quotas entries.
 * Request->qq_query_op determines whether to get quota entries
 * for the specified SIDs (smb_quota_query_list) OR to get all
 * quota entries, optionally starting at a specified SID.
 *
 * Returns NT_STATUS codes.
 */
uint32_t
smb_quota_query(smb_quota_query_t *request, smb_quota_response_t *reply)
{
	uint32_t status;
	smb_quota_tree_t *qtree;
	smb_quota_query_op_t query_op = request->qq_query_op;

	list_create(&reply->qr_quota_list, sizeof (smb_quota_t),
	    offsetof(smb_quota_t, q_list_node));

	qtree = smb_quota_tree_lookup(request->qq_root_path);
	if (qtree == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	/* If NOT resuming a previous query all, refresh qtree if required */
	if ((query_op != SMB_QUOTA_QUERY_ALL) || (request->qq_restart)) {
		status = smb_quota_tree_populate(qtree);
		if (status != NT_STATUS_SUCCESS) {
			smb_quota_tree_release(qtree);
			return (status);
		}
	}

	switch (query_op) {
	case SMB_QUOTA_QUERY_SIDLIST:
		status = smb_quota_query_list(qtree, request, reply);
		break;
	case SMB_QUOTA_QUERY_STARTSID:
	case SMB_QUOTA_QUERY_ALL:
		status = smb_quota_query_all(qtree, request, reply);
		break;
	case SMB_QUOTA_QUERY_INVALID_OP:
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	smb_quota_tree_release(qtree);

	return (status);
}

/*
 * smb_quota_set
 *
 * Set the list of quota entries.
 */
uint32_t
smb_quota_set(smb_quota_set_t *request)
{
	uint32_t status;
	smb_quota_tree_t *qtree;

	qtree = smb_quota_tree_lookup(request->qs_root_path);
	if (qtree == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	status = smb_quota_zfs_set_quotas(qtree, request);

	smb_quota_tree_set_expired(qtree);
	smb_quota_tree_release(qtree);

	return (status);
}

/*
 * smb_quota_free
 *
 * This method frees quota entries.
 */
void
smb_quota_free(smb_quota_response_t *reply)
{
	list_t *list = &reply->qr_quota_list;
	smb_quota_t *quota;

	while ((quota = list_head(list)) != NULL) {
		list_remove(list, quota);
		free(quota);
	}

	list_destroy(list);
}

/*
 * smb_quota_query_all
 *
 * Query quotas sequentially from tree, optionally starting at a
 * specified sid. If request->qq_single is TRUE only one quota
 * should be returned, otherwise up to request->qq_max_quota
 * should be returned.
 *
 * SMB_QUOTA_QUERY_STARTSID
 * The query should start at the startsid, the first sid in
 * request->qq_sid_list.
 *
 * SMQ_QUOTA_QUERY_ALL
 * If request->qq_restart the query should restart at the start
 * of the avl tree. Otherwise the first sid in request->qq_sid_list
 * is the resume sid and the query should start at the tree entry
 * after the one it refers to.
 *
 * Returns NT_STATUS codes.
 */
static uint32_t
smb_quota_query_all(smb_quota_tree_t *qtree, smb_quota_query_t *request,
    smb_quota_response_t *reply)
{
	avl_tree_t *avl_tree = &qtree->qt_avl;
	avl_index_t where;
	list_t *sid_list, *quota_list;
	smb_quota_sid_t *sid;
	smb_quota_t *quota, *quotal, key;
	uint32_t count;

	/* find starting sid */
	if (request->qq_query_op == SMB_QUOTA_QUERY_STARTSID) {
		sid_list = &request->qq_sid_list;
		sid = list_head(sid_list);
		(void) strlcpy(key.q_sidstr, sid->qs_sidstr, SMB_SID_STRSZ);
		quota = avl_find(avl_tree, &key, &where);
		if (quota == NULL)
			return (NT_STATUS_INVALID_PARAMETER);
	} else if (request->qq_restart) {
		quota = avl_first(avl_tree);
		if (quota == NULL)
			return (NT_STATUS_NO_MORE_ENTRIES);
	} else {
		sid_list = &request->qq_sid_list;
		sid = list_head(sid_list);
		(void) strlcpy(key.q_sidstr, sid->qs_sidstr, SMB_SID_STRSZ);
		quota = avl_find(avl_tree, &key, &where);
		if (quota == NULL)
			return (NT_STATUS_INVALID_PARAMETER);
		quota = AVL_NEXT(avl_tree, quota);
		if (quota == NULL)
			return (NT_STATUS_NO_MORE_ENTRIES);
	}

	if ((request->qq_single) && (request->qq_max_quota > 1))
		request->qq_max_quota = 1;

	quota_list = &reply->qr_quota_list;
	count = 0;
	while (quota) {
		if (count >= request->qq_max_quota)
			break;

		quotal = malloc(sizeof (smb_quota_t));
		if (quotal == NULL)
			return (NT_STATUS_NO_MEMORY);
		bcopy(quota, quotal, sizeof (smb_quota_t));

		list_insert_tail(quota_list, quotal);
		++count;

		quota = AVL_NEXT(avl_tree, quota);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_quota_query_list
 *
 * Iterate through request sid list querying the avl tree for each.
 * Insert an entry in the reply quota list for each sid.
 * For any sid that cannot be found in the avl tree, the reply
 * quota list entry should contain zeros.
 */
static uint32_t
smb_quota_query_list(smb_quota_tree_t *qtree, smb_quota_query_t *request,
    smb_quota_response_t *reply)
{
	avl_tree_t *avl_tree = &qtree->qt_avl;
	avl_index_t where;
	list_t *sid_list, *quota_list;
	smb_quota_sid_t *sid;
	smb_quota_t *quota, *quotal, key;

	quota_list = &reply->qr_quota_list;
	sid_list = &request->qq_sid_list;
	sid = list_head(sid_list);
	while (sid) {
		quotal = malloc(sizeof (smb_quota_t));
		if (quotal == NULL)
			return (NT_STATUS_NO_MEMORY);

		(void) strlcpy(key.q_sidstr, sid->qs_sidstr, SMB_SID_STRSZ);
		quota = avl_find(avl_tree, &key, &where);
		if (quota) {
			bcopy(quota, quotal, sizeof (smb_quota_t));
		} else {
			bzero(quotal, sizeof (smb_quota_t));
			(void) strlcpy(quotal->q_sidstr, sid->qs_sidstr,
			    SMB_SID_STRSZ);
		}

		list_insert_tail(quota_list, quotal);
		sid = list_next(sid_list, sid);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_quota_zfs_set_quotas
 *
 * This method sets the list of quota entries.
 *
 * A quota list or threshold value of SMB_QUOTA_UNLIMITED means that
 * the user / group does not have a quota limit. In ZFS this maps to
 * 0 (none).
 * A quota list or threshold value of (SMB_QUOTA_UNLIMITED - 1) means
 * that the user / group quota should be removed. In ZFS this maps to
 * 0 (none).
 */
static uint32_t
smb_quota_zfs_set_quotas(smb_quota_tree_t *qtree, smb_quota_set_t *request)
{
	smb_quota_zfs_handle_t zfs_hdl;
	char *typestr, qsetstr[SMB_QUOTA_CMD_STR_LENGTH];
	char qlimit[SMB_QUOTA_CMD_LENGTH];
	list_t *quota_list;
	smb_quota_t *quota;
	uint32_t id;
	uint32_t status = NT_STATUS_SUCCESS;
	uint32_t sidtype;

	status = smb_quota_zfs_init(request->qs_root_path, &zfs_hdl);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	quota_list = &request->qs_quota_list;
	quota = list_head(quota_list);

	while (quota) {
		if ((quota->q_limit == SMB_QUOTA_UNLIMITED) ||
		    (quota->q_limit == (SMB_QUOTA_UNLIMITED - 1))) {
			quota->q_limit = 0;
		}
		(void) snprintf(qlimit, SMB_QUOTA_CMD_LENGTH, "%llu",
		    quota->q_limit);

		sidtype = smb_quota_sidtype(qtree, quota->q_sidstr);
		switch (sidtype) {
		case SidTypeUser:
			typestr = "userquota";
			break;
		case SidTypeWellKnownGroup:
		case SidTypeGroup:
		case SidTypeAlias:
			typestr = "groupquota";
			break;
		default:
			syslog(LOG_WARNING, "Failed to set quota for %s: "
			    "%s (%d) not valid for quotas", quota->q_sidstr,
			    smb_sid_type2str(sidtype), sidtype);
			quota = list_next(quota_list, quota);
			continue;
		}

		if ((smb_quota_getid(quota->q_sidstr, sidtype, &id) == 0) &&
		    !(IDMAP_ID_IS_EPHEMERAL(id))) {
			(void) snprintf(qsetstr, SMB_QUOTA_CMD_STR_LENGTH,
			    "%s@%d", typestr, id);
		} else {
			(void) snprintf(qsetstr, SMB_QUOTA_CMD_STR_LENGTH,
			    "%s@%s", typestr, quota->q_sidstr);
		}

		errno = 0;
		if (zfs_prop_set(zfs_hdl.z_fs, qsetstr, qlimit) != 0) {
			syslog(LOG_WARNING, "Failed to set quota for %s: %s",
			    quota->q_sidstr, strerror(errno));
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		quota = list_next(quota_list, quota);
	}

	smb_quota_zfs_fini(&zfs_hdl);
	return (status);
}

/*
 * smb_quota_sidtype
 *
 * Determine the type of the sid. If the sid exists in
 * the qtree get its type from there, otherwise do an
 * lsa_lookup_sid().
 */
static uint32_t
smb_quota_sidtype(smb_quota_tree_t *qtree, char *sidstr)
{
	smb_quota_t key, *quota;
	avl_index_t where;
	smb_sid_t *sid = NULL;
	smb_account_t ainfo;
	uint32_t sidtype = SidTypeUnknown;

	(void) strlcpy(key.q_sidstr, sidstr, SMB_SID_STRSZ);
	quota = avl_find(&qtree->qt_avl, &key, &where);
	if (quota)
		return (quota->q_sidtype);

	sid = smb_sid_fromstr(sidstr);
	if (sid != NULL) {
		if (lsa_lookup_sid(sid, &ainfo) == NT_STATUS_SUCCESS) {
			sidtype = ainfo.a_type;
			smb_account_free(&ainfo);
		}
		smb_sid_free(sid);
	}
	return (sidtype);
}

/*
 * smb_quota_getid
 *
 * Get the user/group id for the sid.
 */
static int
smb_quota_getid(char *sidstr, uint32_t sidtype, uint32_t *id)
{
	int rc = 0;
	smb_sid_t *sid = NULL;
	int idtype;

	sid = smb_sid_fromstr(sidstr);
	if (sid == NULL)
		return (-1);

	switch (sidtype) {
	case SidTypeUser:
		idtype = SMB_IDMAP_USER;
		break;
	case SidTypeWellKnownGroup:
	case SidTypeGroup:
	case SidTypeAlias:
		idtype = SMB_IDMAP_GROUP;
		break;
	default:
		rc = -1;
		break;
	}

	if (rc == 0)
		rc = smb_idmap_getid(sid, id, &idtype);

	smb_sid_free(sid);

	return (rc);
}

/*
 * smb_quota_tree_lookup
 *
 * Find the quota tree in smb_quota_fs_list.
 *
 * If the tree is found but is locked, waits for it to become available.
 * If the tree is available, locks it and returns it.
 * Otherwise, returns NULL.
 */
static smb_quota_tree_t *
smb_quota_tree_lookup(const char *path)
{
	smb_quota_tree_t *qtree = NULL;

	assert(path);
	(void) mutex_lock(&smb_quota_list_mutex);

	qtree = list_head(&smb_quota_fs_list);
	while (qtree != NULL) {
		if (!smb_quota_list_init || smb_quota_shutdown) {
			(void) mutex_unlock(&smb_quota_list_mutex);
			return (NULL);
		}

		(void) mutex_lock(&qtree->qt_mutex);
		assert(qtree->qt_refcnt > 0);

		if (!smb_quota_tree_match(qtree, path)) {
			(void) mutex_unlock(&qtree->qt_mutex);
			qtree = list_next(&smb_quota_fs_list, qtree);
			continue;
		}

		if (qtree->qt_locked) {
			(void) mutex_unlock(&qtree->qt_mutex);
			(void) cond_wait(&smb_quota_list_condvar,
			    &smb_quota_list_mutex);
			qtree = list_head(&smb_quota_fs_list);
			continue;
		}

		++(qtree->qt_refcnt);
		qtree->qt_locked = B_TRUE;
		(void) mutex_unlock(&qtree->qt_mutex);
		break;
	};

	(void) mutex_unlock(&smb_quota_list_mutex);
	return (qtree);
}

/*
 * smb_quota_tree_release
 */
static void
smb_quota_tree_release(smb_quota_tree_t *qtree)
{
	boolean_t delete;

	(void) mutex_lock(&qtree->qt_mutex);
	assert(qtree->qt_locked);
	assert(qtree->qt_refcnt > 0);

	--(qtree->qt_refcnt);
	qtree->qt_locked = B_FALSE;
	delete = (qtree->qt_refcnt == 0);
	(void) mutex_unlock(&qtree->qt_mutex);

	(void) mutex_lock(&smb_quota_list_mutex);
	if (delete)
		smb_quota_tree_delete(qtree);
	(void) cond_broadcast(&smb_quota_list_condvar);
	(void) mutex_unlock(&smb_quota_list_mutex);
}

/*
 * smb_quota_tree_match
 *
 * Determine if qtree represents the file system identified by path
 */
static boolean_t
smb_quota_tree_match(smb_quota_tree_t *qtree, const char *path)
{
	return (strncmp(qtree->qt_path, path, MAXPATHLEN) == 0);
}

/*
 * smb_quota_tree_create
 *
 * Create and initialize an smb_quota_tree_t structure
 */
static smb_quota_tree_t *
smb_quota_tree_create(const char *path)
{
	smb_quota_tree_t *qtree;

	assert(MUTEX_HELD(&smb_quota_list_mutex));

	qtree = calloc(sizeof (smb_quota_tree_t), 1);
	if (qtree == NULL)
		return (NULL);

	qtree->qt_path = strdup(path);
	if (qtree->qt_path == NULL) {
		free(qtree);
		return (NULL);
	}

	qtree->qt_timestamp = 0;
	qtree->qt_locked = B_FALSE;
	qtree->qt_refcnt = 1;
	qtree->qt_sharecnt = 1;

	avl_create(&qtree->qt_avl, smb_quota_sid_cmp,
	    sizeof (smb_quota_t), offsetof(smb_quota_t, q_avl_node));

	++smb_quota_tree_cnt;
	return (qtree);
}

/*
 * smb_quota_tree_delete
 *
 * Free and delete the smb_quota_tree_t structure.
 * qtree must have no users (refcnt == 0).
 */
static void
smb_quota_tree_delete(smb_quota_tree_t *qtree)
{
	void *cookie = NULL;
	smb_quota_t *node;

	assert(MUTEX_HELD(&smb_quota_list_mutex));
	assert(qtree->qt_refcnt == 0);

	while ((node = avl_destroy_nodes(&qtree->qt_avl, &cookie)) != NULL)
		free(node);
	avl_destroy(&qtree->qt_avl);

	free(qtree->qt_path);
	free(qtree);

	--smb_quota_tree_cnt;
}

/*
 * smb_quota_sid_cmp
 *
 * Comparision function for nodes in an AVL tree which holds quota
 * entries indexed by SID.
 */
static int
smb_quota_sid_cmp(const void *l_arg, const void *r_arg)
{
	const char *l_sid = ((smb_quota_t *)l_arg)->q_sidstr;
	const char *r_sid = ((smb_quota_t *)r_arg)->q_sidstr;
	int ret;

	ret = strncasecmp(l_sid, r_sid, SMB_SID_STRSZ);

	if (ret > 0)
		return (1);
	if (ret < 0)
		return (-1);
	return (0);
}

/*
 * smb_quota_tree_populate
 *
 * If the quota tree needs to be (re)populated:
 * - delete the qtree's contents
 * - repopulate the qtree from zfs
 * - set the qtree's timestamp.
 */
static uint32_t
smb_quota_tree_populate(smb_quota_tree_t *qtree)
{
	void *cookie = NULL;
	void *node;
	uint32_t status;

	assert(qtree->qt_locked);

	if (!smb_quota_tree_expired(qtree))
		return (NT_STATUS_SUCCESS);

	while ((node = avl_destroy_nodes(&qtree->qt_avl, &cookie)) != NULL)
		free(node);

	status = smb_quota_zfs_get_quotas(qtree);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	qtree->qt_timestamp = time(NULL);

	return (NT_STATUS_SUCCESS);
}

static boolean_t
smb_quota_tree_expired(smb_quota_tree_t *qtree)
{
	time_t tnow = time(NULL);
	return ((tnow - qtree->qt_timestamp) > SMB_QUOTA_REFRESH);
}

static void
smb_quota_tree_set_expired(smb_quota_tree_t *qtree)
{
	qtree->qt_timestamp = 0;
}

/*
 * smb_quota_zfs_get_quotas
 *
 * Get user and group quotas from ZFS and use them to
 * populate the quota tree.
 */
static uint32_t
smb_quota_zfs_get_quotas(smb_quota_tree_t *qtree)
{
	smb_quota_zfs_handle_t zfs_hdl;
	smb_quota_zfs_arg_t arg;
	zfs_userquota_prop_t p;
	uint32_t status = NT_STATUS_SUCCESS;

	status = smb_quota_zfs_init(qtree->qt_path, &zfs_hdl);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	arg.qa_avl = &qtree->qt_avl;
	for (p = 0; p < ZFS_NUM_USERQUOTA_PROPS; p++) {
		arg.qa_prop = p;
		if (zfs_userspace(zfs_hdl.z_fs, p,
		    smb_quota_zfs_callback, &arg) != 0) {
			status = NT_STATUS_INTERNAL_ERROR;
			break;
		}
	}

	smb_quota_zfs_fini(&zfs_hdl);
	return (status);
}

/*
 * smb_quota_zfs_callback
 *
 * Find or create a node in the avl tree (arg->qa_avl) that matches
 * the SID derived from domain and rid. If no domain is specified,
 * lookup the sid (smb_quota_sidstr()).
 * Populate the node.
 * The property type (arg->qa_prop) determines which property 'space'
 * refers to.
 */
static int
smb_quota_zfs_callback(void *arg, const char *domain, uid_t rid, uint64_t space)
{
	smb_quota_zfs_arg_t *qarg = (smb_quota_zfs_arg_t *)arg;
	zfs_userquota_prop_t qprop = qarg->qa_prop;
	avl_tree_t *avl_tree = qarg->qa_avl;
	avl_index_t where;
	smb_quota_t *quota, key;

	if (domain == NULL || domain[0] == '\0') {
		if (smb_quota_sidstr(rid, qprop, key.q_sidstr) != 0)
			return (0);
	} else {
		(void) snprintf(key.q_sidstr, SMB_SID_STRSZ, "%s-%u",
		    domain, (uint32_t)rid);
	}

	quota = avl_find(avl_tree, &key, &where);
	if (quota == NULL) {
		quota = malloc(sizeof (smb_quota_t));
		if (quota == NULL)
			return (NT_STATUS_NO_MEMORY);
		bzero(quota, sizeof (smb_quota_t));
		quota->q_thresh = SMB_QUOTA_UNLIMITED;
		quota->q_limit = SMB_QUOTA_UNLIMITED;
		avl_insert(avl_tree, (void *)quota, where);
		(void) strlcpy(quota->q_sidstr, key.q_sidstr, SMB_SID_STRSZ);
	}

	switch (qprop) {
	case ZFS_PROP_USERUSED:
		quota->q_sidtype = SidTypeUser;
		quota->q_used = space;
		break;
	case ZFS_PROP_GROUPUSED:
		quota->q_sidtype = SidTypeGroup;
		quota->q_used = space;
		break;
	case ZFS_PROP_USERQUOTA:
		quota->q_sidtype = SidTypeUser;
		quota->q_limit = space;
		break;
	case ZFS_PROP_GROUPQUOTA:
		quota->q_sidtype = SidTypeGroup;
		quota->q_limit = space;
		break;
	default:
		break;
	}

	quota->q_thresh = quota->q_limit;

	return (0);
}

/*
 * smb_quota_sidstr
 *
 * Use idmap to get the sid for the specified id and return
 * the string version of the sid in sidstr.
 * sidstr must be a buffer of at least SMB_SID_STRSZ.
 */
static int
smb_quota_sidstr(uint32_t id, zfs_userquota_prop_t qprop, char *sidstr)
{
	int idtype;
	smb_sid_t *sid;

	switch (qprop) {
	case ZFS_PROP_USERUSED:
	case ZFS_PROP_USERQUOTA:
		idtype = SMB_IDMAP_USER;
		break;
	case ZFS_PROP_GROUPUSED:
	case ZFS_PROP_GROUPQUOTA:
		idtype = SMB_IDMAP_GROUP;
		break;
	default:
		return (-1);
	}

	if (smb_idmap_getsid(id, idtype, &sid) != IDMAP_SUCCESS)
		return (-1);

	smb_sid_tostr(sid, sidstr);
	smb_sid_free(sid);

	return (0);
}

/*
 * smb_quota_zfs_init
 *
 * Initialize zfs library and dataset handles
 */
static uint32_t
smb_quota_zfs_init(const char *path, smb_quota_zfs_handle_t *zfs_hdl)
{
	char dataset[MAXPATHLEN];

	if (smb_getdataset(path, dataset, MAXPATHLEN) != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	if ((zfs_hdl->z_lib = libzfs_init()) == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	zfs_hdl->z_fs = zfs_open(zfs_hdl->z_lib, dataset, ZFS_TYPE_DATASET);
	if (zfs_hdl->z_fs == NULL) {
		libzfs_fini(zfs_hdl->z_lib);
		return (NT_STATUS_ACCESS_DENIED);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_quota_zfs_fini
 *
 * Close zfs library and dataset handles
 */
static void
smb_quota_zfs_fini(smb_quota_zfs_handle_t *zfs_hdl)
{
	zfs_close(zfs_hdl->z_fs);
	libzfs_fini(zfs_hdl->z_lib);
}

/*
 * smb_quota_add_ctrldir
 *
 * In order to display the quota properties tab, windows clients
 * check for the existence of the quota control file, created
 * here as follows:
 * - Create SMB_QUOTA_CNTRL_DIR directory (with A_HIDDEN & A_SYSTEM
 *   attributes).
 * - Create the SMB_QUOTA_CNTRL_FILE file (with extended attribute
 *   SMB_QUOTA_CNTRL_INDEX_XATTR) in the SMB_QUOTA_CNTRL_DIR directory.
 * - Set the acl of SMB_QUOTA_CNTRL_FILE file to SMB_QUOTA_CNTRL_PERM.
 */
static void
smb_quota_add_ctrldir(const char *path)
{
	int newfd, dirfd, afd;
	nvlist_t *attr;
	char dir[MAXPATHLEN], file[MAXPATHLEN], *acl_text;
	acl_t *aclp, *existing_aclp;
	boolean_t qdir_created, prop_hidden = B_FALSE, prop_sys = B_FALSE;
	struct stat statbuf;

	assert(path != NULL);

	(void) snprintf(dir, MAXPATHLEN, ".%s/%s", path, SMB_QUOTA_CNTRL_DIR);
	(void) snprintf(file, MAXPATHLEN, "%s/%s", dir, SMB_QUOTA_CNTRL_FILE);
	if ((mkdir(dir, 0750) < 0) && (errno != EEXIST))
		return;
	qdir_created = (errno == EEXIST) ? B_FALSE : B_TRUE;

	if ((dirfd = open(dir, O_RDONLY)) < 0) {
		if (qdir_created)
			(void) remove(dir);
		return;
	}

	if (fgetattr(dirfd, XATTR_VIEW_READWRITE, &attr) != 0) {
		(void) close(dirfd);
		if (qdir_created)
			(void) remove(dir);
		return;
	}

	if ((nvlist_lookup_boolean_value(attr, A_HIDDEN, &prop_hidden) != 0) ||
	    (nvlist_lookup_boolean_value(attr, A_SYSTEM, &prop_sys) != 0)) {
		nvlist_free(attr);
		(void) close(dirfd);
		if (qdir_created)
			(void) remove(dir);
		return;
	}
	nvlist_free(attr);

	/*
	 * Before setting attr or acl we check if the they have already been
	 * set to what we want. If so we could be dealing with a received
	 * snapshot and setting these is not needed.
	 */

	if (!prop_hidden || !prop_sys) {
		if (nvlist_alloc(&attr, NV_UNIQUE_NAME, 0) == 0) {
			if ((nvlist_add_boolean_value(
			    attr, A_HIDDEN, 1) != 0) ||
			    (nvlist_add_boolean_value(
			    attr, A_SYSTEM, 1) != 0) ||
			    (fsetattr(dirfd, XATTR_VIEW_READWRITE, attr))) {
				nvlist_free(attr);
				(void) close(dirfd);
				if (qdir_created)
					(void) remove(dir);
				return;
			}
		}
		nvlist_free(attr);
	}

	(void) close(dirfd);

	if (stat(file, &statbuf) != 0) {
		if ((newfd = creat(file, 0640)) < 0) {
			if (qdir_created)
				(void) remove(dir);
			return;
		}
		(void) close(newfd);
	}

	afd = attropen(file, SMB_QUOTA_CNTRL_INDEX_XATTR, O_RDWR | O_CREAT,
	    0640);
	if (afd == -1) {
		(void) unlink(file);
		if (qdir_created)
			(void) remove(dir);
		return;
	}
	(void) close(afd);

	if (acl_get(file, 0, &existing_aclp) == -1) {
		(void) unlink(file);
		if (qdir_created)
			(void) remove(dir);
		return;
	}

	acl_text = acl_totext(existing_aclp, ACL_COMPACT_FMT);
	acl_free(existing_aclp);
	if (acl_text == NULL) {
		(void) unlink(file);
		if (qdir_created)
			(void) remove(dir);
		return;
	}

	aclp = NULL;
	if (strcmp(acl_text, SMB_QUOTA_CNTRL_PERM) != 0) {
		if (acl_fromtext(SMB_QUOTA_CNTRL_PERM, &aclp) != 0) {
			free(acl_text);
			(void) unlink(file);
			if (qdir_created)
				(void) remove(dir);
			return;
		}
		if (acl_set(file, aclp) == -1) {
			free(acl_text);
			(void) unlink(file);
			if (qdir_created)
				(void) remove(dir);
			acl_free(aclp);
			return;
		}
		acl_free(aclp);
	}
	free(acl_text);
}

/*
 * smb_quota_remove_ctrldir
 *
 * Remove SMB_QUOTA_CNTRL_FILE and SMB_QUOTA_CNTRL_DIR.
 */
static void
smb_quota_remove_ctrldir(const char *path)
{
	char dir[MAXPATHLEN], file[MAXPATHLEN];
	assert(path);

	(void) snprintf(dir, MAXPATHLEN, ".%s/%s", path, SMB_QUOTA_CNTRL_DIR);
	(void) snprintf(file, MAXPATHLEN, "%s/%s", dir, SMB_QUOTA_CNTRL_FILE);
	(void) unlink(file);
	(void) remove(dir);
}
