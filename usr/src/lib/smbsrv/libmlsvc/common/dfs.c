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

#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/fs_reparse.h>
#include <uuid/uuid.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_dfs.h>
#include <smbsrv/smb_share.h>
#include <dfs.h>

/*
 * default timeout (TTL) values (in second) for root and link
 */
#define	DFS_ROOT_TIMEOUT		300
#define	DFS_LINK_TIMEOUT		1800

/*
 * DFS link data format in reparse point
 *
 * ver:state:prop:timeout:guid:ntarget:cmntlen:comment
 *    [[:tserver:tshare:tstate:pclass:prank]...]
 */
#define	DFS_LINK_V1			1
#define	DFS_LINK_HDR_NFIELDS		7	/* # fields in header section */
#define	DFS_LINK_TRGT_NFIELDS		5	/* # fields for each target */

#define	DFS_ROOT_XATTR			"SUNWdfs.rootinfo"

#define	DFS_INFO_ALL			0

static void *dfs_intr_hdl = NULL;

static struct {
	int (*dfsops_remote_count)(uint32_t *);
} dfs_intr_ops;

/*
 * Namespace cache
 *
 * Caches links' UNC and filesystem path where the key is the UNC path.
 */
static smb_cache_t dfs_nscache;
static char dfs_nbname[NETBIOS_NAME_SZ];

/*
 * The name of cached namespace. This will be the only
 * exported namespace until hosting multiple namespaces
 * is supported
 */
static char dfs_cached_ns[MAXNAMELEN];
static mutex_t dfs_nsmtx;

/*
 * Lock for accessing root information (extended attribute)
 */
static rwlock_t dfs_root_rwl;

extern uint32_t srvsvc_shr_setdfsroot(smb_share_t *, boolean_t);

/*
 * Namespace functions
 */
static boolean_t dfs_namespace_findlink(const char *, char *, char *, size_t);
static void *dfs_namespace_cache(void *);
static boolean_t dfs_namespace_iscached(const char *);

/*
 * Root functions
 */
static int dfs_root_add(const char *, dfs_info_t *);
static uint32_t dfs_root_remove(const char *);
static uint32_t dfs_root_encode(dfs_info_t *, char **, size_t *);
static uint32_t dfs_root_decode(dfs_info_t *, char *, size_t, uint32_t);
static uint32_t dfs_root_isvalidstate(uint32_t);

static int dfs_root_xopen(const char *, int);
static void dfs_root_xclose(int);
static uint32_t dfs_root_xwrite(int, dfs_info_t *);
static uint32_t dfs_root_xread(int, dfs_info_t *, uint32_t);

/*
 * Link functions
 */
static uint32_t dfs_link_encode(dfs_info_t *, char *, size_t);
static uint32_t dfs_link_decode(dfs_info_t *, char *, uint32_t);
static uint32_t dfs_link_commit(const char *, dfs_info_t *);
static boolean_t dfs_link_isvalidstate(uint32_t);

/*
 * Target functions
 */
static void dfs_target_init(dfs_target_t *, const char *, const char *,
    uint32_t);
static int dfs_target_find(dfs_target_t *, uint32_t, const char *,
    const char *);
static boolean_t dfs_target_isvalidstate(uint32_t);

/*
 * Cache functions
 */
static uint32_t dfs_cache_add_byunc(const char *, const char *, uint32_t);
static void dfs_cache_populate(const char *, const char *);
static int dfs_cache_cmp(const void *, const void *);
static void dfs_cache_flush(const char *);
static uint32_t dfs_cache_nscount(void);

/*
 * Utility functions
 */
static boolean_t dfs_path_isdir(const char *);
static uint32_t dfs_modinfo(uint32_t, dfs_info_t *, dfs_info_t *, uint32_t);

/*
 * DFS module initializationr:
 *
 * - creates the namespace cache
 * - gets system's NetBIOS name
 */
void
dfs_init(void)
{
	smb_cache_create(&dfs_nscache, 0, dfs_cache_cmp, free, bcopy,
	    sizeof (dfs_nscnode_t));

	if (smb_getnetbiosname(dfs_nbname, sizeof (dfs_nbname)) != 0) {
		syslog(LOG_ERR, "dfs: can't get machine name");
		return;
	}

	bzero((void *)&dfs_intr_ops, sizeof (dfs_intr_ops));

	if ((dfs_intr_hdl = smb_dlopen()) == NULL)
		return;

	if ((dfs_intr_ops.dfsops_remote_count =
	    (int (*)())dlsym(dfs_intr_hdl, "smb_dfs_remote_count")) == NULL) {
		smb_dlclose(dfs_intr_hdl);
		dfs_intr_hdl = NULL;
		bzero((void *)&dfs_intr_ops, sizeof (dfs_intr_ops));
	}
}

/*
 * DFS module cleanup:
 *
 * - destroys the namespace cache
 */
void
dfs_fini(void)
{
	smb_dlclose(dfs_intr_hdl);
	smb_cache_destroy(&dfs_nscache);
}

/*
 * To successfully handle some of link/root requests, some
 * file system operations need to be performed. These operations
 * should take place on behalf of the connected user (typically
 * Administrator) and to do so we need to have an infrastructure
 * in place so that smbd can act as a client and sends request to
 * the kernel. Right now, we lack this infrastructure, so we make
 * a compromise by temporarily enabling some privileges for smbd
 * to be able to fulfill various link/root requests.
 */
void
dfs_setpriv(priv_op_t op)
{
	(void) priv_set(op, PRIV_EFFECTIVE,
	    PRIV_FILE_DAC_READ,
	    PRIV_FILE_DAC_WRITE,
	    PRIV_FILE_DAC_EXECUTE,
	    PRIV_FILE_DAC_SEARCH, NULL);
}

/*
 * ========================
 * Namespace API (public)
 * ========================
 */

/*
 * Launches a thread to cache the specified namespace
 */
void
dfs_namespace_load(const char *name)
{
	pthread_t thr;
	pthread_attr_t tattr;
	char *rootshr;
	int rc;

	if ((rootshr = strdup(name)) == NULL) {
		syslog(LOG_ERR, "dfs: failed to load %s namespace (no memory)",
		    name);
		return;
	}

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&thr, &tattr, dfs_namespace_cache, rootshr);
	(void) pthread_attr_destroy(&tattr);

	if (rc != 0)
		syslog(LOG_ERR, "dfs: fail to loading %s namespace (%d)",
		    name, rc);
}

/*
 * Flushes the cache when a DFS root share is removed
 */
void /*ARGSUSED*/
dfs_namespace_unload(const char *name)
{
	dfs_cache_flush(name);
}

/*
 * Returns the file system path for the given share if it
 * is a DFS root share.
 * If 'path' is NULL, this function only indicates whether
 * or not the given share represents a DFS namespace
 */
uint32_t
dfs_namespace_path(const char *name, char *path, size_t pathsz)
{
	smb_share_t si;

	if (smb_shr_get((char *)name, &si) != NERR_Success)
		return (ERROR_NOT_FOUND);

	if ((si.shr_flags & SMB_SHRF_DFSROOT) == 0)
		return (ERROR_NOT_FOUND);

	if (!dfs_namespace_iscached(name))
		return (ERROR_NOT_FOUND);

	if (path != NULL)
		(void) strlcpy(path, si.shr_path, pathsz);

	return (ERROR_SUCCESS);
}

/*
 * Returns the number of DFS root shares i.e. the number
 * of standalone namespaces.
 */
uint32_t
dfs_namespace_count(void)
{
	uint32_t nroot = 0;
	int rc;

	if (dfs_intr_ops.dfsops_remote_count != NULL &&
	    (rc = dfs_intr_ops.dfsops_remote_count(&nroot)) != 0) {
		/*
		 * If this call fails, let's assume there's at least one root
		 * namespace already configured.  The interposer library cannot
		 * confirm or deny the presence of a namespace, so let's take
		 * the safe approach and assume one exists.
		 */
		nroot = 1;
		syslog(LOG_WARNING, "dfs: dfsops_remote_count() failed: %d, "
		    "assuming one namespace exists", rc);
	}

	nroot += dfs_cache_nscount();

	return (nroot);
}

/*
 * Creates a DFS root with the given name and comment.
 *
 * This function does not create the root share, it
 * should already exist.
 */
uint32_t
dfs_namespace_add(const char *rootshr, const char *cmnt)
{
	dfs_info_t info;
	dfs_target_t t;
	smb_share_t si;
	uuid_t uuid;
	uint32_t status;

	if (*rootshr == '\\') {
		/* Windows has a special case here! */
		return (ERROR_BAD_PATHNAME);
	}

	if (smb_shr_get((char *)rootshr, &si) != NERR_Success)
		return (NERR_NetNameNotFound);

	(void) mutex_lock(&dfs_nsmtx);
	if (smb_strcasecmp(dfs_cached_ns, rootshr, 0) == 0) {
		/* This DFS root is already exported */
		(void) mutex_unlock(&dfs_nsmtx);
		return (ERROR_FILE_EXISTS);
	}

	if (*dfs_cached_ns != '\0') {
		syslog(LOG_WARNING, "dfs: trying to add %s namespace."
		    " Only one standalone namespace is supported."
		    " A namespace is already exported for %s",
		    rootshr, dfs_cached_ns);
		(void) mutex_unlock(&dfs_nsmtx);
		return (ERROR_NOT_SUPPORTED);
	}

	bzero(&info, sizeof (info));
	if (cmnt)
		(void) strlcpy(info.i_comment, cmnt, sizeof (info.i_comment));
	info.i_state = DFS_VOLUME_STATE_OK | DFS_VOLUME_FLAVOR_STANDALONE;
	info.i_timeout = DFS_ROOT_TIMEOUT;
	info.i_propflags = 0;

	uuid_generate_random(uuid);
	uuid_unparse(uuid, info.i_guid);

	dfs_target_init(&t, dfs_nbname, rootshr, DFS_STORAGE_STATE_ONLINE);

	info.i_ntargets = 1;
	info.i_targets = &t;

	if ((status = dfs_root_add(si.shr_path, &info)) != ERROR_SUCCESS) {
		(void) mutex_unlock(&dfs_nsmtx);
		return (status);
	}

	status = srvsvc_shr_setdfsroot(&si, B_TRUE);
	if (status == ERROR_SUCCESS) {
		(void) dfs_cache_add_byname(rootshr, NULL, DFS_OBJECT_ROOT);
		(void) strlcpy(dfs_cached_ns, rootshr, sizeof (dfs_cached_ns));
		(void) smb_config_setnum(SMB_CI_DFS_STDROOT_NUM, 1);
	}
	(void) mutex_unlock(&dfs_nsmtx);

	return (status);
}

/*
 * Removes the namespace and all the links in it.
 */
uint32_t
dfs_namespace_remove(const char *name)
{
	smb_cache_cursor_t cursor;
	dfs_nscnode_t nscnode;
	smb_share_t si;
	uint32_t status;

	if (smb_shr_get((char *)name, &si) != NERR_Success)
		return (ERROR_NOT_FOUND);

	if ((si.shr_flags & SMB_SHRF_DFSROOT) == 0)
		return (ERROR_NOT_FOUND);

	if ((status = dfs_root_remove(si.shr_path)) != ERROR_SUCCESS)
		return (status);

	status = srvsvc_shr_setdfsroot(&si, B_FALSE);
	if (status != ERROR_SUCCESS)
		syslog(LOG_WARNING, "dfs: failed to disable root share %s (%d)",
		    name, status);

	if (!dfs_namespace_iscached(name))
		return (ERROR_SUCCESS);

	smb_cache_iterinit(&dfs_nscache, &cursor);

	while (smb_cache_iterate(&dfs_nscache, &cursor, &nscnode)) {
		if (nscnode.nsc_type == DFS_OBJECT_ROOT)
			continue;
		status = dfs_link_remove(nscnode.nsc_fspath, NULL, NULL);
		if (status != ERROR_SUCCESS)
			syslog(LOG_WARNING, "dfs: failed to remove %s (%d)",
			    nscnode.nsc_fspath, status);
	}

	dfs_cache_flush(name);

	/* TODO: remove empty dirs */
	return (ERROR_SUCCESS);
}

/*
 * Determines the DFS namespace flavor.
 */
uint32_t
dfs_namespace_getflavor(const char *name)
{
	char rootdir[DFS_PATH_MAX];
	dfs_info_t info;

	if (dfs_namespace_path(name, rootdir, DFS_PATH_MAX) != ERROR_SUCCESS)
		return (0);

	/* get flavor info from state info (info level 2) */
	if (dfs_root_getinfo(rootdir, &info, 2) != ERROR_SUCCESS)
		return (0);

	return (info.i_state & DFS_VOLUME_FLAVORS);
}

/*
 * ==================
 * Root API (public)
 * ==================
 */

/*
 * Retrieves the information of the root specified by its path.
 *
 * Info level (1) only needs the UNC path which is not stored,
 * it is constructed so the function will return without
 * accessing the backend storage.
 */
uint32_t
dfs_root_getinfo(const char *rootdir, dfs_info_t *info, uint32_t infolvl)
{
	uint32_t status = ERROR_INTERNAL_ERROR;
	int xfd;

	bzero(info, sizeof (dfs_info_t));
	info->i_type = DFS_OBJECT_ROOT;

	if (infolvl == 1)
		return (ERROR_SUCCESS);

	(void) rw_rdlock(&dfs_root_rwl);
	if ((xfd = dfs_root_xopen(rootdir, O_RDONLY)) > 0) {
		status = dfs_root_xread(xfd, info, infolvl);
		dfs_root_xclose(xfd);
	}
	(void) rw_unlock(&dfs_root_rwl);

	return (status);
}

/*
 * Sets the provided information for the specified root or root target.
 * Root is specified by 'rootdir' and the target is specified by
 * (t_server, t_share) pair. Only information items needed for given
 * information level (infolvl) is valid in the passed DFS info structure
 * 'info'.
 */
uint32_t
dfs_root_setinfo(const char *rootdir, dfs_info_t *info, uint32_t infolvl)
{
	dfs_info_t curinfo;
	uint32_t status = ERROR_SUCCESS;
	int xfd;

	(void) rw_wrlock(&dfs_root_rwl);
	if ((xfd = dfs_root_xopen(rootdir, O_RDWR)) < 0) {
		(void) rw_unlock(&dfs_root_rwl);
		return (ERROR_INTERNAL_ERROR);
	}

	status = dfs_root_xread(xfd, &curinfo, DFS_INFO_ALL);
	if (status != ERROR_SUCCESS) {
		dfs_root_xclose(xfd);
		(void) rw_unlock(&dfs_root_rwl);
		return (status);
	}

	status = dfs_modinfo(DFS_OBJECT_ROOT, &curinfo, info, infolvl);
	if (status == ERROR_SUCCESS)
		status = dfs_root_xwrite(xfd, &curinfo);

	dfs_root_xclose(xfd);
	(void) rw_unlock(&dfs_root_rwl);

	dfs_info_free(&curinfo);
	return (status);
}

/*
 * ==================
 * Link API (public)
 * ==================
 */

/*
 * Gets the status of the given path as a link
 */
uint32_t
dfs_link_stat(const char *path, uint32_t *stat)
{
	if (smb_reparse_stat(path, stat) != 0)
		return (ERROR_INTERNAL_ERROR);

	switch (*stat) {
	case SMB_REPARSE_NOTFOUND:
		*stat = DFS_STAT_NOTFOUND;
		break;
	case SMB_REPARSE_NOTREPARSE:
		*stat = DFS_STAT_NOTLINK;
		break;
	case SMB_REPARSE_ISREPARSE:
		*stat = DFS_STAT_ISREPARSE;
		if (smb_reparse_svcget(path, DFS_REPARSE_SVCTYPE, NULL) == 0)
			*stat = DFS_STAT_ISDFS;
		break;
	default:
		*stat = DFS_STAT_UNKNOWN;
		break;
	}

	return (ERROR_SUCCESS);
}

/*
 * Creates a new DFS link or adds a new target to an existing link
 */
uint32_t
dfs_link_add(const char *path, const char *server, const char *share,
    const char *cmnt, uint32_t flags, boolean_t *newlink)
{
	dfs_info_t info;
	dfs_target_t *t;
	int ntargets;
	uint32_t status;
	uint32_t stat;

	*newlink = B_FALSE;

	if ((status = dfs_link_stat(path, &stat)) != ERROR_SUCCESS)
		return (status);

	switch (stat) {
	case DFS_STAT_NOTFOUND:
	case DFS_STAT_ISREPARSE:
		/* Create a new DFS link */

		status = dfs_link_getinfo(NULL, &info, DFS_INFO_ALL);
		if (status != ERROR_SUCCESS)
			return (status);

		(void) strlcpy(info.i_comment, (cmnt) ? cmnt : "",
		    sizeof (info.i_comment));
		*newlink = B_TRUE;
		break;

	case DFS_STAT_ISDFS:
		/* Add a target to an existing link */

		if (flags & DFS_ADD_VOLUME)
			return (ERROR_FILE_EXISTS);

		status = dfs_link_getinfo(path, &info, DFS_INFO_ALL);
		if (status != ERROR_SUCCESS)
			return (status);

		break;

	case DFS_STAT_NOTLINK:
		/* specified path points to a non-reparse object */
		return (ERROR_FILE_EXISTS);

	default:
		return (ERROR_INTERNAL_ERROR);
	}

	/* checks to see if the target already exists */
	ntargets = info.i_ntargets;
	if (dfs_target_find(info.i_targets, ntargets, server, share) != -1) {
		dfs_info_free(&info);
		return (ERROR_FILE_EXISTS);
	}

	/* add the new target */
	t = realloc(info.i_targets, (ntargets + 1) * sizeof (dfs_target_t));
	if (t == NULL) {
		dfs_info_free(&info);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	info.i_targets = t;
	dfs_target_init(&info.i_targets[ntargets], server, share,
	    DFS_STORAGE_STATE_ONLINE);
	info.i_ntargets++;

	status = dfs_link_commit(path, &info);

	dfs_info_free(&info);
	return (status);
}

/*
 * Removes a link or a link target from a DFS namespace. A link can be
 * removed regardless of the number of targets associated with it.
 *
 * 'server' and 'share' parameters specify a target, so if they are NULL
 * it means the link should be removed, otherwise the specified target
 * is removed if found.
 */
uint32_t
dfs_link_remove(const char *path, const char *server, const char *share)
{
	dfs_info_t info;
	uint32_t status, stat;
	int rc, idx;

	if ((status = dfs_link_stat(path, &stat)) != ERROR_SUCCESS)
		return (status);

	if (stat != DFS_STAT_ISDFS)
		return (ERROR_NOT_FOUND);

	if (server == NULL && share == NULL) {
		/* remove the link */
		if (smb_reparse_svcdel(path, DFS_REPARSE_SVCTYPE) != 0)
			return (ERROR_INTERNAL_ERROR);

		return (ERROR_SUCCESS);
	}

	/* remove the specified target in the link */

	status = dfs_link_getinfo(path, &info, DFS_INFO_ALL);
	if (status != ERROR_SUCCESS)
		return (status);

	/* checks to see if the target exists */
	idx = dfs_target_find(info.i_targets, info.i_ntargets, server, share);
	if (idx != -1) {
		bcopy(&info.i_targets[idx + 1], &info.i_targets[idx],
		    (info.i_ntargets - idx - 1) * sizeof (dfs_target_t));
		info.i_ntargets--;
	} else {
		dfs_info_free(&info);
		return (ERROR_FILE_NOT_FOUND);
	}

	if (info.i_ntargets == 0) {
		/* if last target, then remove the link */
		rc = smb_reparse_svcdel(path, DFS_REPARSE_SVCTYPE);
		status = (rc == 0) ? ERROR_SUCCESS : ERROR_INTERNAL_ERROR;
	} else {
		status = dfs_link_commit(path, &info);
	}

	dfs_info_free(&info);
	return (status);
}

/*
 * Sets the provided information for the specified link or link target.
 * Link is specified by 'path' and the target is specified by
 * (t_server, t_share) pair. Only information items needed for given
 * information level (infolvl) is valid in the passed DFS info structure
 * 'info'.
 */
uint32_t
dfs_link_setinfo(const char *path, dfs_info_t *info, uint32_t infolvl)
{
	dfs_info_t curinfo;
	uint32_t status;

	status = dfs_link_getinfo(path, &curinfo, DFS_INFO_ALL);
	if (status != ERROR_SUCCESS)
		return (status);

	status = dfs_modinfo(DFS_OBJECT_LINK, &curinfo, info, infolvl);
	if (status == ERROR_SUCCESS)
		status = dfs_link_commit(path, &curinfo);

	dfs_info_free(&curinfo);
	return (status);
}

/*
 * Gets the DFS link info.
 *
 * If path is NULL, it just does some initialization.
 *
 * Info level (1) only needs the UNC path which is not
 * stored, it is constructed so the function will return
 * without accessing the backend storage.
 */
uint32_t
dfs_link_getinfo(const char *path, dfs_info_t *info, uint32_t infolvl)
{
	char *link_data;
	uint32_t status;
	uuid_t uuid;
	int rc;

	bzero(info, sizeof (dfs_info_t));
	info->i_type = DFS_OBJECT_LINK;

	if (path == NULL) {
		info->i_state = DFS_VOLUME_STATE_OK;
		info->i_timeout = DFS_LINK_TIMEOUT;
		info->i_propflags = 0;
		uuid_generate_random(uuid);
		uuid_unparse(uuid, info->i_guid);
		return (ERROR_SUCCESS);
	}

	if (infolvl == 1)
		return (ERROR_SUCCESS);

	rc = smb_reparse_svcget(path, DFS_REPARSE_SVCTYPE, &link_data);
	if (rc != 0)
		return (ERROR_INTERNAL_ERROR);

	status = dfs_link_decode(info, link_data, infolvl);
	free(link_data);

	return (status);
}

/*
 * ===================
 * Cache API (public)
 * ===================
 */

/*
 * Adds an entry with given DFS name (root sharename) and relative path
 * to the share (relpath) and the specified entry type (i.e. root/link)
 * to the namespace cache.
 */
uint32_t
dfs_cache_add_byname(const char *name, const char *relpath, uint32_t type)
{
	char uncpath[DFS_PATH_MAX];
	char fspath[DFS_PATH_MAX];
	smb_share_t si;

	if (smb_shr_get((char *)name, &si) != NERR_Success)
		return (ERROR_NOT_FOUND);

	if (type == DFS_OBJECT_ROOT) {
		(void) snprintf(uncpath, DFS_PATH_MAX, "\\\\%s\\%s",
		    dfs_nbname, name);
		return (dfs_cache_add_byunc(uncpath, si.shr_path, type));
	}

	/* add link entry */
	(void) snprintf(fspath, DFS_PATH_MAX, "%s/%s", si.shr_path, relpath);
	(void) snprintf(uncpath, DFS_PATH_MAX, "\\\\%s\\%s\\%s", dfs_nbname,
	    name, relpath);

	/* relpath may contain '/' */
	(void) strsubst(uncpath, '/', '\\');

	return (dfs_cache_add_byunc(uncpath, fspath, type));
}

/*
 * Removes the namespace cache entry for the given link
 * in the namespace ('name') with 'relpath'
 */
void
dfs_cache_remove(const char *name, const char *relpath)
{
	dfs_nscnode_t dn;

	(void) snprintf(dn.nsc_uncpath, sizeof (dn.nsc_uncpath),
	    "\\\\%s\\%s\\%s", dfs_nbname, name, relpath);

	/* relpath may contain '/' */
	(void) strsubst(dn.nsc_uncpath, '/', '\\');

	smb_cache_remove(&dfs_nscache, &dn);
}

/*
 * Get the DFS data for the specified cache entry
 */
uint32_t
dfs_cache_getinfo(dfs_nscnode_t *dn, dfs_info_t *info, uint32_t infolvl)
{
	uint32_t status;

	if (dn->nsc_type == DFS_OBJECT_LINK)
		status = dfs_link_getinfo(dn->nsc_fspath, info, infolvl);
	else
		status = dfs_root_getinfo(dn->nsc_fspath, info, infolvl);

	(void) strlcpy(info->i_uncpath, dn->nsc_uncpath,
	    sizeof (info->i_uncpath));

	if (status == ERROR_SUCCESS)
		dfs_info_trace("dfs_cache_getinfo", info);

	return (status);
}

/*
 * Returns the number of cache entries i.e. the number of
 * root(s) and link(s)
 */
uint32_t
dfs_cache_num(void)
{
	return (smb_cache_num(&dfs_nscache));
}

void
dfs_cache_iterinit(smb_cache_cursor_t *cursor)
{
	smb_cache_iterinit(&dfs_nscache, cursor);
}

boolean_t
dfs_cache_iterate(smb_cache_cursor_t *cursor, dfs_nscnode_t *dn)
{
	return (smb_cache_iterate(&dfs_nscache, cursor, dn));
}

/*
 * ==================
 * Misc API (public)
 * ==================
 */

/*
 * This is the function that is called by smbd door server to
 * fullfil a GetReferrals request from smbsrv kernel module
 *
 * 'reftype' specifies the requested referral type. If it is
 * DFS_REFERRAL_ROOT then dfs_path should point to a namespace
 * root. If it is DFS_REFERRAL_LINK then dfs_path should CONTAIN
 * a link, in which case this function will find the link and
 * returns its target information.
 */
uint32_t
dfs_get_referrals(const char *dfs_path, dfs_reftype_t reftype,
    dfs_info_t *referrals)
{
	dfs_path_t path;
	smb_unc_t *unc;
	char linkpath[DFS_PATH_MAX];
	uint32_t status;

	status = dfs_path_parse(&path, dfs_path, DFS_OBJECT_ANY);
	if (status != ERROR_SUCCESS)
		return (status);

	dfs_setpriv(PRIV_ON);

	referrals->i_type = path.p_type;

	switch (reftype) {
	case DFS_REFERRAL_ROOT:
		if (path.p_type != DFS_OBJECT_ROOT) {
			status = ERROR_INVALID_PARAMETER;
			break;
		}

		status = dfs_root_getinfo((const char *)path.p_fspath,
		    referrals, DFS_INFO_ALL);
		(void) strlcpy(referrals->i_uncpath, dfs_path, DFS_PATH_MAX);
		break;

	case DFS_REFERRAL_LINK:
		if (path.p_type != DFS_OBJECT_LINK) {
			status = ERROR_INVALID_PARAMETER;
			break;
		}

		unc = &path.p_unc;
		if (!dfs_namespace_findlink(unc->unc_share, unc->unc_path,
		    linkpath, DFS_PATH_MAX)) {
			status = ERROR_NOT_FOUND;
			break;
		}

		status = dfs_link_getinfo(linkpath, referrals, DFS_INFO_ALL);
		(void) snprintf(referrals->i_uncpath, DFS_PATH_MAX, "/%s/%s/%s",
		    unc->unc_server, unc->unc_share, unc->unc_path);
		break;

	default:
		status = ERROR_INVALID_PARAMETER;
		break;
	}

	dfs_setpriv(PRIV_OFF);
	dfs_path_free(&path);
	return (status);
}

/*
 * Takes a DFS path in UNC format (dfs_path) and parse it into a dfs_path_t
 * structure.
 *
 * dfs_path_free() MUST be called to free the allocated memory in this
 * function.
 *
 * Returns:
 *
 * ERROR_INVALID_PARAMETER	path is not a valid UNC or not valid for the
 * 				specified object type
 * ERROR_NOT_ENOUGH_MEMORY	not enough memory to peform the parse
 * ERROR_NOT_FOUND		namespace specified does not exist
 */
uint32_t
dfs_path_parse(dfs_path_t *path, const char *dfs_path, uint32_t path_type)
{
	char rootdir[DFS_PATH_MAX];
	smb_unc_t *unc;
	uint32_t status = ERROR_SUCCESS;
	int rc;

	bzero(path, sizeof (dfs_path_t));
	unc = &path->p_unc;

	rc = smb_unc_init(dfs_path, unc);
	switch (rc) {
	case EINVAL:
		return (ERROR_INVALID_PARAMETER);
	case ENOMEM:
		return (ERROR_NOT_ENOUGH_MEMORY);
	default:
		break;
	}

	if (dfs_namespace_path(unc->unc_share, rootdir, DFS_PATH_MAX)
	    != ERROR_SUCCESS) {
		smb_unc_free(unc);
		return (ERROR_NOT_FOUND);
	}

	if (path_type == DFS_OBJECT_ANY)
		path->p_type = (unc->unc_path != NULL)
		    ? DFS_OBJECT_LINK : DFS_OBJECT_ROOT;
	else
		path->p_type = path_type;

	switch (path->p_type) {
	case DFS_OBJECT_LINK:
		if ((unc->unc_path == NULL) || (*unc->unc_path == '\0'))
			status = ERROR_NOT_FOUND;
		else
			(void) snprintf(path->p_fspath, sizeof (path->p_fspath),
			    "%s/%s", rootdir, unc->unc_path);
		break;

	case DFS_OBJECT_ROOT:
		if (unc->unc_path == NULL)
			(void) strlcpy(path->p_fspath, rootdir,
			    sizeof (path->p_fspath));
		else
			status = ERROR_INVALID_PARAMETER;
		break;

	default:
		status = ERROR_INVALID_PARAMETER;
	}

	if (status != ERROR_SUCCESS)
		smb_unc_free(unc);

	return (status);
}

/*
 * Frees the allocated memory for p_unc field of the passed path
 */
void
dfs_path_free(dfs_path_t *path)
{
	if (path != NULL)
		smb_unc_free(&path->p_unc);
}

/*
 * Free the allocated memory for targets in the given info
 * structure
 */
void
dfs_info_free(dfs_info_t *info)
{
	if (info)
		free(info->i_targets);
}

/*
 * Trace the given DFS info structure
 */
void
dfs_info_trace(const char *msg, dfs_info_t *info)
{
	dfs_target_t *t;
	int i;

	smb_tracef("%s", msg);
	if (info == NULL)
		return;

	smb_tracef("UNC\t%s", info->i_uncpath);
	smb_tracef("comment\t%s", info->i_comment);
	smb_tracef("GUID\t%s", info->i_guid);
	smb_tracef("state\t%X", info->i_state);
	smb_tracef("timeout\t%d", info->i_timeout);
	smb_tracef("props\t%X", info->i_propflags);
	smb_tracef("# targets\t%X", info->i_ntargets);

	if (info->i_targets == NULL)
		return;

	for (i = 0, t = info->i_targets; i < info->i_ntargets; i++, t++) {
		smb_tracef("[%d] \\\\%s\\%s", i, t->t_server, t->t_share);
		smb_tracef("[%d] state\t%X", i, t->t_state);
		smb_tracef("[%d] priority\t%d:%d", i, t->t_priority.p_class,
		    t->t_priority.p_rank);
	}
}

/*
 * Search the path specified by 'relpath' to see if it contains
 * a DFS link starting from the last component. If a link is found
 * the full path is returned in 'linkpath'
 */
static boolean_t
dfs_namespace_findlink(const char *name, char *relpath,
    char *linkpath, size_t bufsz)
{
	char rootdir[DFS_PATH_MAX];
	uint32_t stat;
	char *p;

	if (dfs_namespace_path(name, rootdir, DFS_PATH_MAX) != ERROR_SUCCESS)
		return (B_FALSE);

	(void) snprintf(linkpath, bufsz, "%s/%s", rootdir, relpath);

	for (;;) {
		if (dfs_link_stat(linkpath, &stat) != ERROR_SUCCESS)
			return (B_FALSE);

		if (stat == DFS_STAT_ISDFS)
			return (B_TRUE);

		if ((p = strrchr(relpath, '/')) == NULL)
			return (B_FALSE);
		*p = '\0';

		(void) snprintf(linkpath, bufsz, "%s/%s", rootdir, relpath);
	}

	/*NOTREACHED*/
	return (B_FALSE);
}

/*
 * Caches the specified namespace
 */
static void *
dfs_namespace_cache(void *arg)
{
	char *share = arg;
	char uncpath[DFS_PATH_MAX];
	smb_share_t si;

	if (smb_shr_get(share, &si) != NERR_Success) {
		free(share);
		return (NULL);
	}

	/*
	 * This check should be removed when multiple standalone
	 * namespaces are supported.
	 */
	(void) mutex_lock(&dfs_nsmtx);
	if (*dfs_cached_ns != '\0') {
		syslog(LOG_WARNING, "dfs: trying to load %s namespace."
		    " Only one standalone namespace is supported."
		    " A namespace is already exported for %s",
		    share, dfs_cached_ns);
		(void) mutex_unlock(&dfs_nsmtx);
		free(share);
		return (NULL);
	}
	(void) strlcpy(dfs_cached_ns, share, sizeof (dfs_cached_ns));
	(void) smb_config_setnum(SMB_CI_DFS_STDROOT_NUM, 1);
	(void) mutex_unlock(&dfs_nsmtx);

	(void) snprintf(uncpath, DFS_PATH_MAX, "\\\\%s\\%s", dfs_nbname, share);
	(void) dfs_cache_add_byunc(uncpath, si.shr_path, DFS_OBJECT_ROOT);

	dfs_cache_populate(uncpath, si.shr_path);

	free(share);
	return (NULL);
}

/*
 * Checks whether the given name matches the name of
 * the cached namespace.
 */
static boolean_t
dfs_namespace_iscached(const char *name)
{
	boolean_t iscached;

	(void) mutex_lock(&dfs_nsmtx);
	iscached = (smb_strcasecmp(name, dfs_cached_ns, 0) == 0);
	(void) mutex_unlock(&dfs_nsmtx);

	return (iscached);
}

static int
dfs_root_add(const char *rootdir, dfs_info_t *info)
{
	uint32_t status = ERROR_INTERNAL_ERROR;
	int xfd;

	(void) rw_wrlock(&dfs_root_rwl);
	if ((xfd = dfs_root_xopen(rootdir, O_CREAT | O_TRUNC | O_RDWR)) > 0) {
		status = dfs_root_xwrite(xfd, info);
		dfs_root_xclose(xfd);
	}
	(void) rw_unlock(&dfs_root_rwl);

	return (status);
}

/*
 * Deletes the specified root information
 */
static uint32_t
dfs_root_remove(const char *rootdir)
{
	int attrdirfd;
	int err = 0;

	(void) rw_wrlock(&dfs_root_rwl);

	if ((attrdirfd = attropen(rootdir, ".", O_RDONLY)) > 0) {
		if (unlinkat(attrdirfd, DFS_ROOT_XATTR, 0) == -1) {
			if (errno != ENOENT)
				err = errno;
		}
		(void) close(attrdirfd);
	} else {
		err = errno;
	}

	(void) rw_unlock(&dfs_root_rwl);

	if (err != 0) {
		syslog(LOG_DEBUG, "dfs: failed to remove root info %s (%d)",
		    rootdir, err);
		return (ERROR_INTERNAL_ERROR);
	}

	return (ERROR_SUCCESS);
}

/*
 * Opens DFS root directory's extended attribute with the given mode.
 */
static int
dfs_root_xopen(const char *rootdir, int oflag)
{
	int dfd;
	int xfd = -1;
	int err = 0;

	if ((dfd = open(rootdir, O_RDONLY)) > 0) {
		xfd = openat(dfd, DFS_ROOT_XATTR, oflag | O_XATTR, 0600);
		if (xfd == -1)
			err = errno;
		(void) close(dfd);
	} else {
		err = errno;
	}

	if (err != 0) {
		syslog(LOG_DEBUG, "dfs: failed to open root directory %s (%d)",
		    rootdir, err);
	}

	return (xfd);
}

/*
 * Closes given extended attribute file descriptor
 */
static void
dfs_root_xclose(int xfd)
{
	(void) close(xfd);
}

/*
 * Writes the given DFS data in the DFS root directory's
 * extended attribute specified with xfd file descriptor.
 */
static uint32_t
dfs_root_xwrite(int xfd, dfs_info_t *info)
{
	size_t nbytes;
	char *buf = NULL;
	size_t buflen;
	uint32_t status;

	if ((status = dfs_root_encode(info, &buf, &buflen)) != ERROR_SUCCESS)
		return (status);

	(void) lseek(xfd, 0, SEEK_SET);
	nbytes = write(xfd, buf, buflen);
	free(buf);

	return ((nbytes == buflen) ? ERROR_SUCCESS : ERROR_INTERNAL_ERROR);
}

/*
 * Reads DFS root information from its directory extended attribute
 * and parse it into given dfs_info_t structure
 */
static uint32_t
dfs_root_xread(int xfd, dfs_info_t *info, uint32_t infolvl)
{
	struct stat statbuf;
	uint32_t status;
	char *buf;

	if (fstat(xfd, &statbuf) != 0)
		return (ERROR_INTERNAL_ERROR);

	if ((buf = malloc(statbuf.st_size)) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (read(xfd, buf, statbuf.st_size) == statbuf.st_size)
		status = dfs_root_decode(info, buf, statbuf.st_size, infolvl);
	else
		status = ERROR_INTERNAL_ERROR;

	free(buf);
	return (status);
}

/*
 * Encodes (packs) DFS information in 'info' into a flat
 * buffer in a name-value format. This function allocates a
 * buffer with appropriate size to contain all the information
 * so the caller MUST free the allocated memory by calling free().
 */
static uint32_t
dfs_root_encode(dfs_info_t *info, char **buf, size_t *bufsz)
{
	dfs_target_t *t;
	nvlist_t *nvl;
	int rc;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	rc = nvlist_add_string(nvl, "comment", info->i_comment);
	rc |= nvlist_add_string(nvl, "guid", info->i_guid);
	rc |= nvlist_add_uint32(nvl, "state", info->i_state);
	rc |= nvlist_add_uint32(nvl, "timeout", info->i_timeout);
	rc |= nvlist_add_uint32(nvl, "propflags", info->i_propflags);
	t = info->i_targets;
	rc |= nvlist_add_string(nvl, "t_server", t->t_server);
	rc |= nvlist_add_string(nvl, "t_share", t->t_share);
	rc |= nvlist_add_uint32(nvl, "t_state", t->t_state);
	rc |= nvlist_add_uint32(nvl, "t_priority_class",
	    t->t_priority.p_class);
	rc |= nvlist_add_uint16(nvl, "t_priority_rank",
	    t->t_priority.p_rank);

	if (rc == 0)
		rc = nvlist_pack(nvl, buf, bufsz, NV_ENCODE_NATIVE, 0);

	nvlist_free(nvl);

	return ((rc == 0) ? ERROR_SUCCESS : ERROR_INTERNAL_ERROR);
}

/*
 * Decodes (unpack) provided buffer which contains a list of name-value
 * pairs into given dfs_info_t structure
 */
static uint32_t
dfs_root_decode(dfs_info_t *info, char *buf, size_t bufsz, uint32_t infolvl)
{
	nvlist_t *nvl;
	char *cmnt, *guid;
	char *t_server, *t_share;
	uint32_t t_state;
	uint32_t t_priority_class;
	uint16_t t_priority_rank;
	boolean_t decode_priority = B_FALSE;
	int rc;

	if (nvlist_unpack(buf, bufsz, &nvl, 0) != 0)
		return (ERROR_INTERNAL_ERROR);

	rc = nvlist_lookup_string(nvl, "comment", &cmnt);
	rc |= nvlist_lookup_string(nvl, "guid", &guid);
	rc |= nvlist_lookup_uint32(nvl, "state", &info->i_state);
	rc |= nvlist_lookup_uint32(nvl, "timeout", &info->i_timeout);
	rc |= nvlist_lookup_uint32(nvl, "propflags", &info->i_propflags);

	if (rc != 0) {
		nvlist_free(nvl);
		return (ERROR_INTERNAL_ERROR);
	}

	(void) strlcpy(info->i_comment, (cmnt) ? cmnt : "",
	    sizeof (info->i_comment));
	(void) strlcpy(info->i_guid, (guid) ? guid : "", sizeof (info->i_guid));

	info->i_targets = NULL;
	info->i_ntargets = 1;

	switch (infolvl) {
	case DFS_INFO_ALL:
	case 3:
	case 4:
		/* need target information */
		break;
	case 6:
	case 9:
		/* need target and priority information */
		decode_priority = B_TRUE;
		break;
	default:
		nvlist_free(nvl);
		return (ERROR_SUCCESS);
	}

	info->i_targets = malloc(sizeof (dfs_target_t));
	if (info->i_targets == NULL) {
		nvlist_free(nvl);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	rc = nvlist_lookup_string(nvl, "t_server", &t_server);
	rc |= nvlist_lookup_string(nvl, "t_share", &t_share);
	rc |= nvlist_lookup_uint32(nvl, "t_state", &t_state);
	if (rc != 0) {
		nvlist_free(nvl);
		free(info->i_targets);
		return (ERROR_INTERNAL_ERROR);
	}
	dfs_target_init(info->i_targets, t_server, t_share, t_state);

	if (decode_priority) {
		rc = nvlist_lookup_uint32(nvl, "t_priority_class",
		    &t_priority_class);
		if (rc == 0)
			rc = nvlist_lookup_uint16(nvl, "t_priority_rank",
			    &t_priority_rank);

		if (rc != 0 && rc != ENOENT) {
			nvlist_free(nvl);
			free(info->i_targets);
			return (ERROR_INTERNAL_ERROR);
		} else if (rc == 0) {
			info->i_targets->t_priority.p_class = t_priority_class;
			info->i_targets->t_priority.p_rank = t_priority_rank;
		}
	}

	nvlist_free(nvl);
	return (ERROR_SUCCESS);
}

/*
 * Determines if the passed state is valid for a DFS root
 *
 * This is based on test results against Win2003 and in some cases
 * does not match [MS-DFSNM] spec.
 */
static uint32_t
dfs_root_isvalidstate(uint32_t state)
{
	switch (state) {
	case DFS_VOLUME_STATE_OK:
	case DFS_VOLUME_STATE_RESYNCHRONIZE:
		return (ERROR_SUCCESS);

	case DFS_VOLUME_STATE_INCONSISTENT:
	case DFS_VOLUME_STATE_FORCE_SYNC:
		return (ERROR_INVALID_PARAMETER);

	case DFS_VOLUME_STATE_OFFLINE:
	case DFS_VOLUME_STATE_ONLINE:
	case DFS_VOLUME_STATE_STANDBY:
		return (ERROR_NOT_SUPPORTED);
	default:
		break;
	}

	return (ERROR_INVALID_PARAMETER);
}

/*
 * Decodes the link info from given string buffer (buf) into
 * dfs_info_t structure.
 */
static uint32_t
dfs_link_decode(dfs_info_t *info, char *buf, uint32_t infolvl)
{
	char *lfield[DFS_LINK_HDR_NFIELDS];
	dfs_target_t *t;
	uint32_t linkver;
	uint32_t cmntlen;
	uint32_t cpylen;
	int i, j;

	/*
	 * Header format
	 * ver:state:prop:timeout:guid:ntarget:cmntlen:comment:
	 */
	for (i = 0; i < DFS_LINK_HDR_NFIELDS; i++) {
		if ((lfield[i] = strsep((char **)&buf, ":")) == NULL)
			return (ERROR_INVALID_DATA);
	}

	i = 0;
	linkver = strtoul(lfield[i++], NULL, 10);
	if (linkver != DFS_LINK_V1)
		return (ERROR_INVALID_DATA);

	info->i_state = strtoul(lfield[i++], NULL, 10);
	info->i_propflags = strtoul(lfield[i++], NULL, 10);
	info->i_timeout = strtoul(lfield[i++], NULL, 10);
	(void) strlcpy(info->i_guid, lfield[i++], sizeof (info->i_guid));
	info->i_ntargets = strtoul(lfield[i++], NULL, 10);
	info->i_targets = NULL;

	cpylen = cmntlen = strtoul(lfield[i++], NULL, 10);

	if (cmntlen > sizeof (info->i_comment))
		cpylen = sizeof (info->i_comment);
	else if (cmntlen != 0)
		cpylen = cmntlen + 1;

	(void) strlcpy(info->i_comment, buf, cpylen);
	buf += (cmntlen + 1);

	switch (infolvl) {
	case DFS_INFO_ALL:
	case 3:
	case 4:
	case 6:
	case 9:
		/* need target information */
		break;
	default:
		return (ERROR_SUCCESS);
	}

	info->i_targets = calloc(info->i_ntargets, sizeof (dfs_target_t));
	if (info->i_targets == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	/*
	 * Format for each target
	 * server:share:state:class:rank
	 */
	for (i = 0, t = info->i_targets; i < info->i_ntargets; i++, t++) {
		for (j = 0; j < DFS_LINK_TRGT_NFIELDS; j++) {
			if ((lfield[j] = strsep((char **)&buf, ":")) == NULL) {
				dfs_info_free(info);
				return (ERROR_INVALID_DATA);
			}
		}

		(void) strlcpy(t->t_server, lfield[0], sizeof (t->t_server));
		(void) strlcpy(t->t_share, lfield[1], sizeof (t->t_share));
		t->t_state = strtoul(lfield[2], NULL, 10);
		t->t_priority.p_class = strtoul(lfield[3], NULL, 10);
		t->t_priority.p_rank = strtoul(lfield[4], NULL, 10);
	}

	return (ERROR_SUCCESS);
}

/*
 * Encodes given link information (info)
 */
static uint32_t
dfs_link_encode(dfs_info_t *info, char *buf, size_t bufsz)
{
	char linkdata[MAXREPARSELEN];
	dfs_target_t *t;
	int i, sz;

	/*
	 * Header format
	 * ver:state:prop:timeout:guid:ntarget:cmntlen:comment
	 */
	sz = snprintf(buf, bufsz, "%u:%u:%u:%u:%s:%u:%u:%s",
	    DFS_LINK_V1, info->i_state, info->i_propflags, info->i_timeout,
	    info->i_guid, info->i_ntargets,
	    strlen(info->i_comment), info->i_comment);

	if (sz > bufsz) {
		syslog(LOG_WARNING, "dfs: link data is too large");
		dfs_info_trace("DFS link encode", info);
		return (ERROR_INTERNAL_ERROR);
	}

	/*
	 * Format for each target
	 * :server:share:state:class:rank
	 */
	bufsz -= sz;
	for (i = 0, t = info->i_targets; i < info->i_ntargets; i++, t++) {
		if (strchr(t->t_server, ':') || strchr(t->t_share, ':'))
			return (ERROR_INVALID_NAME);

		sz = snprintf(linkdata, MAXREPARSELEN, ":%s:%s:%u:%u:%u",
		    t->t_server, t->t_share, t->t_state,
		    t->t_priority.p_class, t->t_priority.p_rank);
		if (sz > bufsz) {
			syslog(LOG_WARNING, "dfs: link data is too large");
			dfs_info_trace("DFS link encode", info);
			return (ERROR_INTERNAL_ERROR);
		}
		(void) strcat(buf, linkdata);
		bufsz -= sz;
	}

	return (ERROR_SUCCESS);
}

/*
 * Stores given information for the specified link
 */
static uint32_t
dfs_link_commit(const char *path, dfs_info_t *info)
{
	char linkdata[MAXREPARSELEN];
	uint32_t status;
	int rc;

	status = dfs_link_encode(info, linkdata, MAXREPARSELEN);
	if (status == ERROR_SUCCESS) {
		rc = smb_reparse_svcadd(path, DFS_REPARSE_SVCTYPE, linkdata);
		if (rc != 0)
			status = ERROR_INTERNAL_ERROR;
	}

	return (status);
}

/*
 * Determines if the passed state is valid for a link
 */
static boolean_t
dfs_link_isvalidstate(uint32_t state)
{
	return (state == DFS_VOLUME_STATE_OK ||
	    state == DFS_VOLUME_STATE_OFFLINE ||
	    state == DFS_VOLUME_STATE_ONLINE);
}

/*
 * Initializes the given target structure (t) with provided information.
 */
static void
dfs_target_init(dfs_target_t *t, const char *srv, const char *share,
    uint32_t state)
{
	(void) strlcpy(t->t_server, (srv) ? srv : "", sizeof (t->t_server));
	(void) strlcpy(t->t_share, (share) ? share : "", sizeof (t->t_share));
	t->t_state = state;
	t->t_priority.p_class = DfsSiteCostNormalPriorityClass;
	t->t_priority.p_rank = 0;
}

/*
 * Lookup the specified target (server, share) in the given
 * target list (targets). If there is a match its index is
 * returned, otherwise -1 will be returned.
 */
static int
dfs_target_find(dfs_target_t *targets, uint32_t ntargets,
    const char *server, const char *share)
{
	dfs_target_t *t;
	int i;

	for (i = 0, t = targets; i < ntargets; i++, t++) {
		if ((smb_strcasecmp(t->t_server, server, 0) == 0) &&
		    (smb_strcasecmp(t->t_share, share, 0) == 0))
			return (i);
	}

	return (-1);
}

/*
 * Determines if the passed state is valid for a link/root target
 */
static boolean_t
dfs_target_isvalidstate(uint32_t state)
{
	return (state == DFS_STORAGE_STATE_ONLINE ||
	    state == DFS_STORAGE_STATE_OFFLINE);
}

/*
 * Cache compare function, the key is UNC path
 */
static int
dfs_cache_cmp(const void *p1, const void *p2)
{
	smb_cache_node_t *cn1 = (smb_cache_node_t *)p1;
	smb_cache_node_t *cn2 = (smb_cache_node_t *)p2;
	dfs_nscnode_t *dn1 = cn1->cn_data;
	dfs_nscnode_t *dn2 = cn2->cn_data;
	int rc;

	rc = smb_strcasecmp(dn1->nsc_uncpath, dn2->nsc_uncpath, 0);

	if (rc < 0)
		return (-1);

	if (rc > 0)
		return (1);

	return (0);
}

/*
 * Adds an entry with given UNC and filesystem path and the specified
 * entry type (i.e. root/link) to the namespace cache.
 */
static uint32_t
dfs_cache_add_byunc(const char *uncpath, const char *fspath, uint32_t type)
{
	dfs_nscnode_t *dn;
	uint32_t status = ERROR_SUCCESS;

	if ((dn = malloc(sizeof (dfs_nscnode_t))) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	(void) strlcpy(dn->nsc_uncpath, uncpath, sizeof (dn->nsc_uncpath));
	(void) strlcpy(dn->nsc_fspath, fspath, sizeof (dn->nsc_fspath));
	dn->nsc_type = type;
	if (smb_cache_add(&dfs_nscache, dn, SMB_CACHE_ADD) != 0) {
		free(dn);
		status = ERROR_INTERNAL_ERROR;
	}

	return (status);
}

/*
 * starting from DFS root directory, scans the tree for DFS links
 * and adds them to the cache.
 */
static void
dfs_cache_populate(const char *unc_prefix, const char *dir)
{
	char fspath[DFS_PATH_MAX];
	char uncpath[DFS_PATH_MAX];
	char *fname;
	int nentries, i;
	struct dirent **entry_list;
	uint32_t stat;

	nentries = scandir(dir, &entry_list, NULL, NULL);
	if (nentries == -1)
		return;

	for (i = 0; i < nentries; i++) {
		fname = entry_list[i]->d_name;

		if (strcmp(fname, ".") == 0 ||
		    strcmp(fname, "..") == 0) {
			free(entry_list[i]);
			continue;
		}

		(void) snprintf(fspath, DFS_PATH_MAX, "%s/%s", dir, fname);
		(void) snprintf(uncpath, DFS_PATH_MAX, "%s\\%s", unc_prefix,
		    fname);

		if (dfs_path_isdir(fspath)) {
			dfs_cache_populate(uncpath, fspath);
		} else if (dfs_link_stat(fspath, &stat) == ERROR_SUCCESS) {
			if (stat == DFS_STAT_ISDFS)
				(void) dfs_cache_add_byunc(uncpath, fspath,
				    DFS_OBJECT_LINK);
		}

		free(entry_list[i]);
	}

	for (; i < nentries; i++)
		free(entry_list[i]);

	free(entry_list);
}

/*
 * If this namespace hasn't been cached then return
 * without flushing the cache; otherwise clear the
 * name and flush the cache.
 */
static void
dfs_cache_flush(const char *name)
{
	(void) mutex_lock(&dfs_nsmtx);
	if (smb_strcasecmp(name, dfs_cached_ns, 0) != 0) {
		(void) mutex_unlock(&dfs_nsmtx);
		return;
	}
	*dfs_cached_ns = '\0';
	(void) smb_config_setnum(SMB_CI_DFS_STDROOT_NUM, 0);
	(void) mutex_unlock(&dfs_nsmtx);

	smb_cache_flush(&dfs_nscache);
}

/*
 * Returns the number of cached namespaces
 */
static uint32_t
dfs_cache_nscount(void)
{
	uint32_t nscount;

	(void) mutex_lock(&dfs_nsmtx);
	nscount = (*dfs_cached_ns == '\0') ? 0 : 1;
	(void) mutex_unlock(&dfs_nsmtx);

	return (nscount);
}

/*
 * Determines whether the given path is a directory.
 */
static boolean_t
dfs_path_isdir(const char *path)
{
	struct stat statbuf;

	if (lstat(path, &statbuf) != 0)
		return (B_FALSE);

	return ((statbuf.st_mode & S_IFMT) == S_IFDIR);
}

/*
 * Validates the given state based on the object type (root/link), info
 * level, and whether it is the object's state or its target's state
 */
static uint32_t
dfs_isvalidstate(uint32_t state, uint32_t type, boolean_t target,
    uint32_t infolvl)
{
	uint32_t status = ERROR_SUCCESS;

	switch (infolvl) {
	case 101:
		if (type == DFS_OBJECT_ROOT) {
			if (!target)
				return (dfs_root_isvalidstate(state));

			if (!dfs_target_isvalidstate(state))
				status = ERROR_INVALID_PARAMETER;
			else if (state == DFS_STORAGE_STATE_OFFLINE)
				status = ERROR_NOT_SUPPORTED;
		} else {
			if (!target) {
				if (!dfs_link_isvalidstate(state))
					status = ERROR_INVALID_PARAMETER;
			} else {
				if (!dfs_target_isvalidstate(state))
					status = ERROR_INVALID_PARAMETER;
			}
		}
		break;

	case 105:
		if (state == 0)
			return (ERROR_SUCCESS);

		if (type == DFS_OBJECT_ROOT) {
			switch (state) {
			case DFS_VOLUME_STATE_OK:
			case DFS_VOLUME_STATE_OFFLINE:
			case DFS_VOLUME_STATE_ONLINE:
			case DFS_VOLUME_STATE_RESYNCHRONIZE:
			case DFS_VOLUME_STATE_STANDBY:
				status = ERROR_NOT_SUPPORTED;
				break;

			default:
				status = ERROR_INVALID_PARAMETER;
			}
		} else {
			switch (state) {
			case DFS_VOLUME_STATE_OK:
			case DFS_VOLUME_STATE_OFFLINE:
			case DFS_VOLUME_STATE_ONLINE:
				break;

			case DFS_VOLUME_STATE_RESYNCHRONIZE:
			case DFS_VOLUME_STATE_STANDBY:
				status = ERROR_NOT_SUPPORTED;
				break;

			default:
				status = ERROR_INVALID_PARAMETER;
			}
		}
		break;

	default:
		status = ERROR_INVALID_LEVEL;
	}

	return (status);
}

/*
 * Validates the given property flag mask based on the object
 * type (root/link) and namespace flavor.
 */
static uint32_t
dfs_isvalidpropflagmask(uint32_t propflag_mask, uint32_t type,
    uint32_t flavor)
{
	uint32_t flgs_not_supported;

	flgs_not_supported = DFS_PROPERTY_FLAG_ROOT_SCALABILITY
	    | DFS_PROPERTY_FLAG_CLUSTER_ENABLED
	    | DFS_PROPERTY_FLAG_ABDE;

	if (flavor == DFS_VOLUME_FLAVOR_STANDALONE) {
		if (type == DFS_OBJECT_LINK)
			flgs_not_supported |= DFS_PROPERTY_FLAG_SITE_COSTING;
		if (propflag_mask & flgs_not_supported)
			return (ERROR_NOT_SUPPORTED);
	}

	return (ERROR_SUCCESS);
}

/*
 * Based on the specified information level (infolvl) copy parts of the
 * information provided through newinfo into the existing information
 * (info) for the given object.
 */
static uint32_t
dfs_modinfo(uint32_t type, dfs_info_t *info, dfs_info_t *newinfo,
    uint32_t infolvl)
{
	boolean_t target_op = B_FALSE;
	uint32_t status = ERROR_SUCCESS;
	uint32_t state;
	int target_idx;

	if (newinfo->i_targets != NULL) {
		target_idx = dfs_target_find(info->i_targets, info->i_ntargets,
		    newinfo->i_targets->t_server, newinfo->i_targets->t_share);
		if (target_idx == -1)
			return (ERROR_FILE_NOT_FOUND);
		target_op = B_TRUE;
	}

	switch (infolvl) {
	case 100:
		(void) strlcpy(info->i_comment, newinfo->i_comment,
		    sizeof (newinfo->i_comment));
		break;

	case 101:
		state = (target_op)
		    ? newinfo->i_targets->t_state : newinfo->i_state;
		status = dfs_isvalidstate(state, type, target_op, 101);
		if (status != ERROR_SUCCESS)
			return (status);

		if (!target_op) {
			/*
			 * states specified by this mask should not be stored
			 */
			if (state & DFS_VOLUME_STATES_SRV_OPS)
				return (ERROR_SUCCESS);

			info->i_state = state;
		} else {
			info->i_targets[target_idx].t_state = state;
		}
		break;

	case 102:
		info->i_timeout = newinfo->i_timeout;
		break;

	case 103:
		info->i_propflags = newinfo->i_propflags;
		break;

	case 104:
		info->i_targets[target_idx].t_priority =
		    newinfo->i_targets->t_priority;
		break;

	case 105:
		status = dfs_isvalidstate(newinfo->i_state, type, B_FALSE, 105);
		if (status != ERROR_SUCCESS)
			return (status);

		status = dfs_isvalidpropflagmask(newinfo->i_propflag_mask, type,
		    newinfo->i_flavor);
		if (status != ERROR_SUCCESS)
			return (status);

		(void) strlcpy(info->i_comment, newinfo->i_comment,
		    sizeof (newinfo->i_comment));
		if (newinfo->i_state != 0)
			info->i_state = newinfo->i_state;
		info->i_timeout = newinfo->i_timeout;
		info->i_propflags = newinfo->i_propflags;
		break;

	default:
		status = ERROR_INVALID_LEVEL;
	}

	return (status);
}
