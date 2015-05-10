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
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * SMB/CIFS share cache implementation.
 */

#include <errno.h>
#include <synch.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <thread.h>
#include <pthread.h>
#include <assert.h>
#include <libshare.h>
#include <libzfs.h>
#include <priv_utils.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <dirent.h>
#include <dlfcn.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb.h>
#include <mlsvc.h>
#include <dfs.h>

#define	SMB_SHR_ERROR_THRESHOLD		3
#define	SMB_SHR_CSC_BUFSZ		64

typedef struct smb_transient {
	char		*name;
	char		*cmnt;
	char		*path;
	char		drive;
	boolean_t	check;
} smb_transient_t;

static smb_transient_t tshare[] = {
	{ "IPC$", "Remote IPC",		NULL,		'\0', B_FALSE },
	{ "c$",   "Default Share",	SMB_CVOL,	'C',  B_FALSE },
	{ "vss$", "VSS",		SMB_VSS,	'V',  B_TRUE }
};

static struct {
	char *value;
	uint32_t flag;
} cscopt[] = {
	{ "disabled",	SMB_SHRF_CSC_DISABLED },
	{ "manual",	SMB_SHRF_CSC_MANUAL },
	{ "auto",	SMB_SHRF_CSC_AUTO },
	{ "vdo",	SMB_SHRF_CSC_VDO }
};

/*
 * Cache functions and vars
 */
#define	SMB_SHR_HTAB_SZ			1024

/*
 * Cache handle
 *
 * Shares cache is a hash table.
 *
 * sc_cache		pointer to hash table handle
 * sc_cache_lck		synchronize cache read/write accesses
 * sc_state		cache state machine values
 * sc_nops		number of inflight/pending cache operations
 * sc_mtx		protects handle fields
 */
typedef struct smb_shr_cache {
	HT_HANDLE	*sc_cache;
	rwlock_t	sc_cache_lck;
	mutex_t		sc_mtx;
	cond_t		sc_cv;
	uint32_t	sc_state;
	uint32_t	sc_nops;
} smb_shr_cache_t;

/*
 * Cache states
 */
#define	SMB_SHR_CACHE_STATE_NONE	0
#define	SMB_SHR_CACHE_STATE_CREATED	1
#define	SMB_SHR_CACHE_STATE_DESTROYING	2

/*
 * Cache lock modes
 */
#define	SMB_SHR_CACHE_RDLOCK	0
#define	SMB_SHR_CACHE_WRLOCK	1

static smb_shr_cache_t smb_shr_cache;

static uint32_t smb_shr_cache_create(void);
static void smb_shr_cache_destroy(void);
static uint32_t smb_shr_cache_lock(int);
static void smb_shr_cache_unlock(void);
static int smb_shr_cache_count(void);
static smb_share_t *smb_shr_cache_iterate(smb_shriter_t *);

static smb_share_t *smb_shr_cache_findent(char *);
static uint32_t smb_shr_cache_addent(smb_share_t *);
static void smb_shr_cache_delent(char *);
static void smb_shr_cache_freent(HT_ITEM *);

static boolean_t smb_shr_is_empty(const char *);
static boolean_t smb_shr_is_dot_or_dotdot(const char *);

/*
 * sharemgr functions
 */
static void smb_shr_sa_loadgrp(sa_group_t);
static uint32_t smb_shr_sa_load(sa_share_t, sa_resource_t);
static uint32_t smb_shr_sa_loadbyname(char *);
static uint32_t smb_shr_sa_get(sa_share_t, sa_resource_t, smb_share_t *);

/*
 * .ZFS management functions
 */
static void smb_shr_zfs_add(smb_share_t *);
static void smb_shr_zfs_remove(smb_share_t *);
static void smb_shr_zfs_rename(smb_share_t *, smb_share_t *);

/*
 * share publishing
 */
#define	SMB_SHR_PUBLISH		0
#define	SMB_SHR_UNPUBLISH	1

typedef struct smb_shr_pitem {
	list_node_t	spi_lnd;
	char		spi_name[MAXNAMELEN];
	char		spi_container[MAXPATHLEN];
	char		spi_op;
} smb_shr_pitem_t;

/*
 * publish queue states
 */
#define	SMB_SHR_PQS_NOQUEUE	0
#define	SMB_SHR_PQS_READY	1	/* the queue is ready */
#define	SMB_SHR_PQS_PUBLISHING	2	/* publisher thread is running */
#define	SMB_SHR_PQS_STOPPING	3

/*
 * share publishing queue
 */
typedef struct smb_shr_pqueue {
	list_t		spq_list;
	mutex_t		spq_mtx;
	cond_t		spq_cv;
	uint32_t	spq_state;
} smb_shr_pqueue_t;

static smb_shr_pqueue_t ad_queue;

static int smb_shr_publisher_start(void);
static void smb_shr_publisher_stop(void);
static void smb_shr_publisher_send(smb_ads_handle_t *, list_t *, const char *);
static void smb_shr_publisher_queue(const char *, const char *, char);
static void *smb_shr_publisher(void *);
static void smb_shr_publisher_flush(list_t *);
static void smb_shr_publish(const char *, const char *);
static void smb_shr_unpublish(const char *, const char *);

/*
 * Utility/helper functions
 */
static uint32_t smb_shr_lookup(char *, smb_share_t *);
static uint32_t smb_shr_add_transient(char *, char *, char *);
static int smb_shr_enable_all_privs(void);
static int smb_shr_expand_subs(char **, smb_share_t *, smb_shr_execinfo_t *);
static char **smb_shr_tokenize_cmd(char *);
static void smb_shr_sig_abnormal_term(int);
static void smb_shr_sig_child(int);
static int smb_shr_encode(smb_share_t *, nvlist_t **);

/*
 * libshare handle and synchronization
 */
typedef struct smb_sa_handle {
	sa_handle_t	sa_handle;
	mutex_t		sa_mtx;
	boolean_t	sa_in_service;
} smb_sa_handle_t;

static smb_sa_handle_t smb_sa_handle;

static char smb_shr_exec_map[MAXPATHLEN];
static char smb_shr_exec_unmap[MAXPATHLEN];
static mutex_t smb_shr_exec_mtx;

/*
 * Semaphore held during temporary, process-wide changes
 * such as process privileges.  It is a seamaphore and
 * not a mutex so a child of fork can reset it.
 */
static sema_t smb_proc_sem = DEFAULTSEMA;

/*
 * Creates and initializes the cache and starts the publisher
 * thread.
 */
int
smb_shr_start(void)
{
	smb_transient_t	*ts;
	uint32_t	nerr;
	int		i;

	(void) mutex_lock(&smb_sa_handle.sa_mtx);
	smb_sa_handle.sa_in_service = B_TRUE;
	(void) mutex_unlock(&smb_sa_handle.sa_mtx);

	if (smb_shr_cache_create() != NERR_Success)
		return (ENOMEM);

	for (i = 0; i < sizeof (tshare)/sizeof (tshare[0]); ++i) {
		ts = &tshare[i];

		if (ts->check && smb_shr_is_empty(ts->path))
			continue;

		nerr = smb_shr_add_transient(ts->name, ts->cmnt, ts->path);
		if (nerr != NERR_Success)
			return (ENOMEM);
	}

	return (smb_shr_publisher_start());
}

void
smb_shr_stop(void)
{
	smb_shr_cache_destroy();
	smb_shr_publisher_stop();

	(void) mutex_lock(&smb_sa_handle.sa_mtx);
	smb_sa_handle.sa_in_service = B_FALSE;

	if (smb_sa_handle.sa_handle != NULL) {
		sa_fini(smb_sa_handle.sa_handle);
		smb_sa_handle.sa_handle = NULL;
	}

	(void) mutex_unlock(&smb_sa_handle.sa_mtx);
}

/*
 * Get a handle and exclusive access to the libshare API.
 */
sa_handle_t
smb_shr_sa_enter(void)
{
	(void) mutex_lock(&smb_sa_handle.sa_mtx);
	if (!smb_sa_handle.sa_in_service) {
		(void) mutex_unlock(&smb_sa_handle.sa_mtx);
		return (NULL);
	}

	if (smb_sa_handle.sa_handle != NULL &&
	    sa_needs_refresh(smb_sa_handle.sa_handle)) {
		sa_fini(smb_sa_handle.sa_handle);
		smb_sa_handle.sa_handle = NULL;
	}

	if (smb_sa_handle.sa_handle == NULL) {
		smb_sa_handle.sa_handle = sa_init(SA_INIT_SHARE_API);
		if (smb_sa_handle.sa_handle == NULL) {
			syslog(LOG_ERR, "share: failed to get libshare handle");
			(void) mutex_unlock(&smb_sa_handle.sa_mtx);
			return (NULL);
		}
	}

	return (smb_sa_handle.sa_handle);
}

/*
 * Release exclusive access to the libshare API.
 */
void
smb_shr_sa_exit(void)
{
	(void) mutex_unlock(&smb_sa_handle.sa_mtx);
}

/*
 * Return the total number of shares
 */
int
smb_shr_count(void)
{
	int n_shares = 0;

	if (smb_shr_cache_lock(SMB_SHR_CACHE_RDLOCK) == NERR_Success) {
		n_shares = smb_shr_cache_count();
		smb_shr_cache_unlock();
	}

	return (n_shares);
}

/*
 * smb_shr_iterinit
 *
 * Initialize given iterator for traversing hash table.
 */
void
smb_shr_iterinit(smb_shriter_t *shi)
{
	bzero(shi, sizeof (smb_shriter_t));
	shi->si_first = B_TRUE;
}

/*
 * smb_shr_iterate
 *
 * Iterate on the shares in the hash table. The iterator must be initialized
 * before the first iteration. On subsequent calls, the iterator must be
 * passed unchanged.
 *
 * Returns NULL on failure or when all shares are visited, otherwise
 * returns information of visited share.
 */
smb_share_t *
smb_shr_iterate(smb_shriter_t *shi)
{
	smb_share_t *share = NULL;
	smb_share_t *cached_si;

	if (shi == NULL)
		return (NULL);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_RDLOCK) == NERR_Success) {
		if ((cached_si = smb_shr_cache_iterate(shi)) != NULL) {
			share = &shi->si_share;
			bcopy(cached_si, share, sizeof (smb_share_t));
		}
		smb_shr_cache_unlock();
	}

	return (share);
}

/*
 * Adds the given share to cache, publishes the share in ADS
 * if it has an AD container, calls kernel to take a hold on
 * the shared file system. If it can't take a hold on the
 * shared file system, it's either because shared directory
 * does not exist or some other error has occurred, in any
 * case the share is removed from the cache.
 *
 * If the specified share is an autohome share which already
 * exists in the cache, just increments the reference count.
 */
uint32_t
smb_shr_add(smb_share_t *si)
{
	struct stat st;
	smb_share_t *cached_si;
	nvlist_t *shrlist;
	uint32_t status;
	int rc;

	assert(si != NULL);

	if (smb_name_validate_share(si->shr_name) != ERROR_SUCCESS)
		return (ERROR_INVALID_NAME);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) != NERR_Success)
		return (NERR_InternalError);

	cached_si = smb_shr_cache_findent(si->shr_name);
	if (cached_si) {
		if (si->shr_flags & SMB_SHRF_AUTOHOME) {
			cached_si->shr_refcnt++;
			status = NERR_Success;
		} else {
			status = NERR_DuplicateShare;
		}
		smb_shr_cache_unlock();
		return (status);
	}

	if (STYPE_ISDSK(si->shr_type)) {
		/*
		 * If share type is STYPE_DISKTREE then the path to the
		 * share should exist so that we can add the share to cache.
		 */
		rc = stat(si->shr_path, &st);
		if (rc != 0) {
			smb_shr_cache_unlock();
			return (NERR_ItemNotFound);
		}
	}

	if ((status = smb_shr_cache_addent(si)) != NERR_Success) {
		smb_shr_cache_unlock();
		return (status);
	}

	/* don't hold the lock across door call */
	smb_shr_cache_unlock();

	if ((rc = smb_shr_encode(si, &shrlist)) == 0) {
		/* send the share to kernel */
		rc = smb_kmod_share(shrlist);
		nvlist_free(shrlist);

		if (rc == 0) {
			smb_shr_publish(si->shr_name, si->shr_container);

			/* If path is ZFS, add the .zfs/shares/<share> entry. */
			smb_shr_zfs_add(si);

			if ((si->shr_flags & SMB_SHRF_DFSROOT) != 0)
				dfs_namespace_load(si->shr_name);

			return (NERR_Success);
		}
	}

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) == NERR_Success) {
		smb_shr_cache_delent(si->shr_name);
		smb_shr_cache_unlock();
	}

	/*
	 * rc == ENOENT means the shared directory doesn't exist
	 */
	return ((rc == ENOENT) ? NERR_UnknownDevDir : NERR_InternalError);
}

/*
 * Removes the specified share from cache, removes it from AD
 * if it has an AD container, and calls the kernel to release
 * the hold on the shared file system.
 *
 * If this is an autohome share then decrement the reference
 * count. If it reaches 0 then it proceeds with removing steps.
 */
uint32_t
smb_shr_remove(char *sharename)
{
	smb_share_t *si;
	char container[MAXPATHLEN];
	boolean_t dfsroot;
	nvlist_t *shrlist;

	assert(sharename != NULL);

	if (smb_name_validate_share(sharename) != ERROR_SUCCESS)
		return (ERROR_INVALID_NAME);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) != NERR_Success)
		return (NERR_InternalError);

	if ((si = smb_shr_cache_findent(sharename)) == NULL) {
		smb_shr_cache_unlock();
		return (NERR_NetNameNotFound);
	}

	if (STYPE_ISIPC(si->shr_type)) {
		/* IPC$ share cannot be removed */
		smb_shr_cache_unlock();
		return (ERROR_ACCESS_DENIED);
	}

	if (si->shr_flags & SMB_SHRF_AUTOHOME) {
		if ((--si->shr_refcnt) > 0) {
			smb_shr_cache_unlock();
			return (NERR_Success);
		}
	}

	/*
	 * If path is ZFS, remove the .zfs/shares/<share> entry.  Need
	 * to remove before cleanup of cache occurs.
	 */
	smb_shr_zfs_remove(si);
	(void) smb_shr_encode(si, &shrlist);

	(void) strlcpy(container, si->shr_container, sizeof (container));
	dfsroot = ((si->shr_flags & SMB_SHRF_DFSROOT) != 0);
	smb_shr_cache_delent(sharename);
	smb_shr_cache_unlock();

	smb_shr_unpublish(sharename, container);

	/* call kernel to release the hold on the shared file system */
	if (shrlist != NULL) {
		(void) smb_kmod_unshare(shrlist);
		nvlist_free(shrlist);
	}

	if (dfsroot)
		dfs_namespace_unload(sharename);

	return (NERR_Success);
}

/*
 * Rename a share. Check that the current name exists and the new name
 * doesn't exist. The rename is performed by deleting the current share
 * definition and creating a new share with the new name.
 */
uint32_t
smb_shr_rename(char *from_name, char *to_name)
{
	smb_share_t *from_si;
	smb_share_t to_si;
	uint32_t status;
	nvlist_t *shrlist;

	assert((from_name != NULL) && (to_name != NULL));

	if (smb_name_validate_share(from_name) != ERROR_SUCCESS ||
	    smb_name_validate_share(to_name) != ERROR_SUCCESS)
		return (ERROR_INVALID_NAME);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) != NERR_Success)
		return (NERR_InternalError);

	if ((from_si = smb_shr_cache_findent(from_name)) == NULL) {
		smb_shr_cache_unlock();
		return (NERR_NetNameNotFound);
	}

	if (STYPE_ISIPC(from_si->shr_type)) {
		/* IPC$ share cannot be renamed */
		smb_shr_cache_unlock();
		return (ERROR_ACCESS_DENIED);
	}

	if (smb_shr_cache_findent(to_name) != NULL) {
		smb_shr_cache_unlock();
		return (NERR_DuplicateShare);
	}

	bcopy(from_si, &to_si, sizeof (smb_share_t));
	(void) strlcpy(to_si.shr_name, to_name, sizeof (to_si.shr_name));


	/* If path is ZFS, rename the .zfs/shares/<share> entry. */
	smb_shr_zfs_rename(from_si, &to_si);

	if ((status = smb_shr_cache_addent(&to_si)) != NERR_Success) {
		smb_shr_cache_unlock();
		return (status);
	}

	smb_shr_cache_delent(from_name);
	smb_shr_cache_unlock();

	if (smb_shr_encode(from_si, &shrlist) == 0) {
		(void) smb_kmod_unshare(shrlist);
		nvlist_free(shrlist);

		if (smb_shr_encode(&to_si, &shrlist) == 0) {
			(void) smb_kmod_share(shrlist);
			nvlist_free(shrlist);
		}
	}

	smb_shr_unpublish(from_name, to_si.shr_container);
	smb_shr_publish(to_name, to_si.shr_container);

	return (NERR_Success);
}

/*
 * Load the information for the specified share into the supplied share
 * info structure.
 *
 * First looks up the cache to see if the specified share exists, if there
 * is a miss then it looks up sharemgr.
 */
uint32_t
smb_shr_get(char *sharename, smb_share_t *si)
{
	uint32_t status;

	if (sharename == NULL || *sharename == '\0')
		return (NERR_NetNameNotFound);

	if ((status = smb_shr_lookup(sharename, si)) == NERR_Success)
		return (status);

	if ((status = smb_shr_sa_loadbyname(sharename)) == NERR_Success)
		status = smb_shr_lookup(sharename, si);

	return (status);
}

/*
 * Modifies an existing share. Properties that can be modified are:
 *
 *   o comment
 *   o AD container
 *   o host access
 *   o abe
 */
uint32_t
smb_shr_modify(smb_share_t *new_si)
{
	smb_share_t *si;
	boolean_t adc_changed = B_FALSE;
	char old_container[MAXPATHLEN];
	uint32_t access, flag;
	nvlist_t *shrlist;

	assert(new_si != NULL);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) != NERR_Success)
		return (NERR_InternalError);

	if ((si = smb_shr_cache_findent(new_si->shr_name)) == NULL) {
		smb_shr_cache_unlock();
		return (NERR_NetNameNotFound);
	}

	if (STYPE_ISIPC(si->shr_type)) {
		/* IPC$ share cannot be modified */
		smb_shr_cache_unlock();
		return (ERROR_ACCESS_DENIED);
	}

	(void) strlcpy(si->shr_cmnt, new_si->shr_cmnt, sizeof (si->shr_cmnt));

	adc_changed = (strcmp(new_si->shr_container, si->shr_container) != 0);
	if (adc_changed) {
		/* save current container - needed for unpublishing */
		(void) strlcpy(old_container, si->shr_container,
		    sizeof (old_container));
		(void) strlcpy(si->shr_container, new_si->shr_container,
		    sizeof (si->shr_container));
	}

	flag = (new_si->shr_flags & SMB_SHRF_ABE);
	si->shr_flags &= ~SMB_SHRF_ABE;
	si->shr_flags |= flag;

	flag = (new_si->shr_flags & SMB_SHRF_CATIA);
	si->shr_flags &= ~SMB_SHRF_CATIA;
	si->shr_flags |= flag;

	flag = (new_si->shr_flags & SMB_SHRF_GUEST_OK);
	si->shr_flags &= ~SMB_SHRF_GUEST_OK;
	si->shr_flags |= flag;

	flag = (new_si->shr_flags & SMB_SHRF_DFSROOT);
	si->shr_flags &= ~SMB_SHRF_DFSROOT;
	si->shr_flags |= flag;

	flag = (new_si->shr_flags & SMB_SHRF_CSC_MASK);
	si->shr_flags &= ~SMB_SHRF_CSC_MASK;
	si->shr_flags |= flag;

	access = (new_si->shr_flags & SMB_SHRF_ACC_ALL);
	si->shr_flags &= ~SMB_SHRF_ACC_ALL;
	si->shr_flags |= access;

	if (access & SMB_SHRF_ACC_NONE)
		(void) strlcpy(si->shr_access_none, new_si->shr_access_none,
		    sizeof (si->shr_access_none));

	if (access & SMB_SHRF_ACC_RO)
		(void) strlcpy(si->shr_access_ro, new_si->shr_access_ro,
		    sizeof (si->shr_access_ro));

	if (access & SMB_SHRF_ACC_RW)
		(void) strlcpy(si->shr_access_rw, new_si->shr_access_rw,
		    sizeof (si->shr_access_rw));

	smb_shr_cache_unlock();

	if (smb_shr_encode(si, &shrlist) == 0) {
		(void) smb_kmod_unshare(shrlist);
		nvlist_free(shrlist);

		if (smb_shr_encode(new_si, &shrlist) == 0) {
			(void) smb_kmod_share(shrlist);
			nvlist_free(shrlist);
		}
	}

	if (adc_changed) {
		smb_shr_unpublish(new_si->shr_name, old_container);
		smb_shr_publish(new_si->shr_name, new_si->shr_container);
	}

	return (NERR_Success);
}

/*
 * smb_shr_exists
 *
 * Returns B_TRUE if the share exists. Otherwise returns B_FALSE
 */
boolean_t
smb_shr_exists(char *sharename)
{
	boolean_t exists = B_FALSE;

	if (sharename == NULL || *sharename == '\0')
		return (B_FALSE);

	if (smb_shr_cache_lock(SMB_SHR_CACHE_RDLOCK) == NERR_Success) {
		exists = (smb_shr_cache_findent(sharename) != NULL);
		smb_shr_cache_unlock();
	}

	return (exists);
}

/*
 * If the shared directory does not begin with a /, one will be
 * inserted as a prefix. If ipaddr is not zero, then also return
 * information about access based on the host level access lists, if
 * present. Also return access check if there is an IP address and
 * shr_accflags.
 *
 * The value of smb_chk_hostaccess is checked for an access match.
 * -1 is wildcard match
 * 0 is no match
 * 1 is match
 *
 * Precedence is none is checked first followed by ro then rw if
 * needed.  If x is wildcard (< 0) then check to see if the other
 * values are a match. If a match, that wins.
 */
uint32_t
smb_shr_hostaccess(smb_inaddr_t *ipaddr, char *none_list, char *ro_list,
    char *rw_list, uint32_t flag)
{
	uint32_t acc = SMB_SHRF_ACC_NONE;
	int none = 0;
	int ro = 0;
	int rw = 0;

	if (!smb_inet_iszero(ipaddr)) {
		if ((flag & SMB_SHRF_ACC_NONE) != 0)
			none = smb_chk_hostaccess(ipaddr, none_list);
		if ((flag & SMB_SHRF_ACC_RO) != 0)
			ro = smb_chk_hostaccess(ipaddr, ro_list);
		if ((flag & SMB_SHRF_ACC_RW) != 0)
			rw = smb_chk_hostaccess(ipaddr, rw_list);

		/* make first pass to get basic value */
		if (none != 0)
			acc = SMB_SHRF_ACC_NONE;
		else if (ro != 0)
			acc = SMB_SHRF_ACC_RO;
		else if (rw != 0)
			acc = SMB_SHRF_ACC_RW;

		/* make second pass to handle '*' case */
		if (none < 0) {
			acc = SMB_SHRF_ACC_NONE;
			if (ro > 0)
				acc = SMB_SHRF_ACC_RO;
			else if (rw > 0)
				acc = SMB_SHRF_ACC_RW;
		} else if (ro < 0) {
			acc = SMB_SHRF_ACC_RO;
			if (none > 0)
				acc = SMB_SHRF_ACC_NONE;
			else if (rw > 0)
				acc = SMB_SHRF_ACC_RW;
		} else if (rw < 0) {
			acc = SMB_SHRF_ACC_RW;
			if (none > 0)
				acc = SMB_SHRF_ACC_NONE;
			else if (ro > 0)
				acc = SMB_SHRF_ACC_RO;
		}
	}

	return (acc);
}

/*
 * smb_shr_is_special
 *
 * Special share reserved for interprocess communication (IPC$) or
 * remote administration of the server (ADMIN$). Can also refer to
 * administrative shares such as C$, D$, E$, and so forth.
 */
int
smb_shr_is_special(char *sharename)
{
	int len;

	if (sharename == NULL)
		return (0);

	if ((len = strlen(sharename)) == 0)
		return (0);

	if (sharename[len - 1] == '$')
		return (STYPE_SPECIAL);

	return (0);
}

/*
 * smb_shr_is_restricted
 *
 * Check whether or not there is a restriction on a share. Restricted
 * shares are generally STYPE_SPECIAL, for example, IPC$. All the
 * administration share names are restricted: C$, D$ etc. Returns B_TRUE
 * if the share is restricted. Otherwise B_FALSE is returned to indicate
 * that there are no restrictions.
 */
boolean_t
smb_shr_is_restricted(char *sharename)
{
	static char *restricted[] = {
		"IPC$"
	};

	int i;

	if (sharename == NULL)
		return (B_FALSE);

	for (i = 0; i < sizeof (restricted)/sizeof (restricted[0]); i++) {
		if (smb_strcasecmp(restricted[i], sharename, 0) == 0)
			return (B_TRUE);
	}

	return (smb_shr_is_admin(sharename));
}

/*
 * smb_shr_is_admin
 *
 * Check whether or not access to the share should be restricted to
 * administrators. This is a bit of a hack because what we're doing
 * is checking for the default admin shares: C$, D$ etc.. There are
 * other shares that have restrictions: see smb_shr_is_restricted().
 *
 * Returns B_TRUE if the shares is an admin share. Otherwise B_FALSE
 * is returned to indicate that there are no restrictions.
 */
boolean_t
smb_shr_is_admin(char *sharename)
{
	if (sharename == NULL)
		return (B_FALSE);

	if (strlen(sharename) == 2 &&
	    smb_isalpha(sharename[0]) && sharename[1] == '$') {
		return (B_TRUE);
	}

	return (B_FALSE);
}

char
smb_shr_drive_letter(const char *path)
{
	smb_transient_t	*ts;
	int i;

	if (path == NULL)
		return ('\0');

	for (i = 0; i < sizeof (tshare)/sizeof (tshare[0]); ++i) {
		ts = &tshare[i];

		if (ts->path == NULL)
			continue;

		if (strcasecmp(ts->path, path) == 0)
			return (ts->drive);
	}

	return ('\0');
}

/*
 * Returns true if the specified directory is empty,
 * otherwise returns false.
 */
static boolean_t
smb_shr_is_empty(const char *path)
{
	DIR *dirp;
	struct dirent *dp;

	if (path == NULL)
		return (B_TRUE);

	if ((dirp = opendir(path)) == NULL)
		return (B_TRUE);

	while ((dp = readdir(dirp)) != NULL) {
		if (!smb_shr_is_dot_or_dotdot(dp->d_name))
			return (B_FALSE);
	}

	(void) closedir(dirp);
	return (B_TRUE);
}

/*
 * Returns true if name is "." or "..", otherwise returns false.
 */
static boolean_t
smb_shr_is_dot_or_dotdot(const char *name)
{
	if (*name != '.')
		return (B_FALSE);

	if ((name[1] == '\0') || (name[1] == '.' && name[2] == '\0'))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * smb_shr_get_realpath
 *
 * Derive the real path for a share from the path provided by a client.
 * For instance, the real path of C:\ may be /cvol or the real path of
 * F:\home may be /vol1/home.
 *
 * clntpath - path provided by the Windows client is in the
 *            format of <drive letter>:\<dir>
 * realpath - path that will be stored as the directory field of
 *            the smb_share_t structure of the share.
 * maxlen   - maximum length of the realpath buffer
 *
 * Return LAN Manager network error code.
 */
uint32_t
smb_shr_get_realpath(const char *clntpath, char *realpath, int maxlen)
{
	const char *p;
	int len;

	if ((p = strchr(clntpath, ':')) != NULL)
		++p;
	else
		p = clntpath;

	(void) strlcpy(realpath, p, maxlen);
	(void) strcanon(realpath, "/\\");
	(void) strsubst(realpath, '\\', '/');

	len = strlen(realpath);
	if ((len > 1) && (realpath[len - 1] == '/'))
		realpath[len - 1] = '\0';

	return (NERR_Success);
}

void
smb_shr_list(int offset, smb_shrlist_t *list)
{
	smb_shriter_t iterator;
	smb_share_t *si;
	int n = 0;

	bzero(list, sizeof (smb_shrlist_t));
	smb_shr_iterinit(&iterator);

	while ((si = smb_shr_iterate(&iterator)) != NULL) {
		if (--offset > 0)
			continue;

		if ((si->shr_flags & SMB_SHRF_TRANS) &&
		    (!STYPE_ISIPC(si->shr_type))) {
			bcopy(si, &list->sl_shares[n], sizeof (smb_share_t));
			if (++n == LMSHARES_PER_REQUEST)
				break;
		}
	}

	list->sl_cnt = n;
}

/*
 * Executes the map/unmap command associated with a share.
 *
 * Returns 0 on success.  Otherwise non-zero for errors.
 */
int
smb_shr_exec(smb_shr_execinfo_t *subs)
{
	char cmd[MAXPATHLEN], **cmd_tokens, *path, *ptr;
	pid_t child_pid;
	int child_status;
	struct sigaction pact, cact;
	smb_share_t si;

	if (smb_shr_get(subs->e_sharename, &si) != 0)
		return (-1);

	*cmd = '\0';

	(void) mutex_lock(&smb_shr_exec_mtx);

	switch (subs->e_type) {
	case SMB_EXEC_MAP:
		(void) strlcpy(cmd, smb_shr_exec_map, sizeof (cmd));
		break;
	case SMB_EXEC_UNMAP:
		(void) strlcpy(cmd, smb_shr_exec_unmap, sizeof (cmd));
		break;
	default:
		(void) mutex_unlock(&smb_shr_exec_mtx);
		return (-1);
	}

	(void) mutex_unlock(&smb_shr_exec_mtx);

	if (*cmd == '\0')
		return (0);

	if (smb_proc_takesem() != 0)
		return (-1);

	pact.sa_handler = smb_shr_sig_child;
	pact.sa_flags = 0;
	(void) sigemptyset(&pact.sa_mask);
	sigaction(SIGCHLD, &pact, NULL);

	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);

	if ((child_pid = fork()) == -1) {
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
		smb_proc_givesem();
		return (-1);
	}

	if (child_pid == 0) {

		/* child process */

		cact.sa_handler = smb_shr_sig_abnormal_term;
		cact.sa_flags = 0;
		(void) sigemptyset(&cact.sa_mask);
		sigaction(SIGTERM, &cact, NULL);
		sigaction(SIGABRT, &cact, NULL);
		sigaction(SIGSEGV, &cact, NULL);

		if (priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_EXEC,
		    PRIV_FILE_DAC_EXECUTE, NULL))
			_exit(-1);

		if (smb_shr_enable_all_privs())
			_exit(-1);

		smb_proc_initsem();

		(void) trim_whitespace(cmd);
		(void) strcanon(cmd, " ");

		if ((cmd_tokens = smb_shr_tokenize_cmd(cmd)) != NULL) {

			if (smb_shr_expand_subs(cmd_tokens, &si, subs) != 0) {
				free(cmd_tokens[0]);
				free(cmd_tokens);
				_exit(-1);
			}

			ptr = cmd;
			path = strsep(&ptr, " ");

			(void) execv(path, cmd_tokens);
		}

		_exit(-1);
	}

	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_FORK, NULL);
	smb_proc_givesem();

	/* parent process */

	while (waitpid(child_pid, &child_status, 0) < 0) {
		if (errno != EINTR)
			break;

		/* continue if waitpid got interrupted by a signal */
		errno = 0;
		continue;
	}

	if (WIFEXITED(child_status))
		return (WEXITSTATUS(child_status));

	return (child_status);
}

/*
 * Locking for process-wide settings (i.e. privileges)
 */
void
smb_proc_initsem(void)
{
	(void) sema_init(&smb_proc_sem, 1, USYNC_THREAD, NULL);
}

int
smb_proc_takesem(void)
{
	return (sema_wait(&smb_proc_sem));
}

void
smb_proc_givesem(void)
{
	(void) sema_post(&smb_proc_sem);
}

/*
 * ============================================
 * Private helper/utility functions
 * ============================================
 */

/*
 * Looks up the given share in the cache and return
 * the info in 'si'
 */
static uint32_t
smb_shr_lookup(char *sharename, smb_share_t *si)
{
	smb_share_t *cached_si;
	uint32_t status = NERR_NetNameNotFound;

	if (sharename == NULL || *sharename == '\0')
		return (NERR_NetNameNotFound);
	if (smb_shr_cache_lock(SMB_SHR_CACHE_RDLOCK) == NERR_Success) {
		cached_si = smb_shr_cache_findent(sharename);
		if (cached_si != NULL) {
			bcopy(cached_si, si, sizeof (smb_share_t));
			status = NERR_Success;
		}

		smb_shr_cache_unlock();
	}
	return (status);
}

/*
 * Add IPC$ or Admin shares to the cache upon startup.
 */
static uint32_t
smb_shr_add_transient(char *name, char *cmnt, char *path)
{
	smb_share_t trans;
	uint32_t status = NERR_InternalError;

	if (name == NULL)
		return (status);

	bzero(&trans, sizeof (smb_share_t));
	(void) strlcpy(trans.shr_name, name, MAXNAMELEN);
	if (cmnt)
		(void) strlcpy(trans.shr_cmnt, cmnt, SMB_SHARE_CMNT_MAX);

	if (path)
		(void) strlcpy(trans.shr_path, path, MAXPATHLEN);

	if (strcasecmp(name, "IPC$") == 0)
		trans.shr_type = STYPE_IPC;

	trans.shr_flags = SMB_SHRF_TRANS;

	if (smb_shr_cache_lock(SMB_SHR_CACHE_WRLOCK) == NERR_Success) {
		status = smb_shr_cache_addent(&trans);
		smb_shr_cache_unlock();
	}

	return (status);
}

/*
 * ============================================
 * Cache management functions
 *
 * All cache functions are private
 * ============================================
 */

/*
 * Create the share cache (hash table).
 */
static uint32_t
smb_shr_cache_create(void)
{
	uint32_t status = NERR_Success;

	(void) mutex_lock(&smb_shr_cache.sc_mtx);
	switch (smb_shr_cache.sc_state) {
	case SMB_SHR_CACHE_STATE_NONE:
		smb_shr_cache.sc_cache = ht_create_table(SMB_SHR_HTAB_SZ,
		    MAXNAMELEN, 0);
		if (smb_shr_cache.sc_cache == NULL) {
			status = NERR_InternalError;
			break;
		}

		(void) ht_register_callback(smb_shr_cache.sc_cache,
		    smb_shr_cache_freent);
		smb_shr_cache.sc_nops = 0;
		smb_shr_cache.sc_state = SMB_SHR_CACHE_STATE_CREATED;
		break;

	default:
		assert(0);
		status = NERR_InternalError;
		break;
	}
	(void) mutex_unlock(&smb_shr_cache.sc_mtx);

	return (status);
}

/*
 * Destroy the share cache (hash table).
 * Wait for inflight/pending operations to finish or abort before
 * destroying the cache.
 */
static void
smb_shr_cache_destroy(void)
{
	(void) mutex_lock(&smb_shr_cache.sc_mtx);
	if (smb_shr_cache.sc_state == SMB_SHR_CACHE_STATE_CREATED) {
		smb_shr_cache.sc_state = SMB_SHR_CACHE_STATE_DESTROYING;
		while (smb_shr_cache.sc_nops > 0)
			(void) cond_wait(&smb_shr_cache.sc_cv,
			    &smb_shr_cache.sc_mtx);

		smb_shr_cache.sc_cache = NULL;
		smb_shr_cache.sc_state = SMB_SHR_CACHE_STATE_NONE;
	}
	(void) mutex_unlock(&smb_shr_cache.sc_mtx);
}

/*
 * If the cache is in "created" state, lock the cache for read
 * or read/write based on the specified mode.
 *
 * Whenever a lock is granted, the number of inflight cache
 * operations is incremented.
 */
static uint32_t
smb_shr_cache_lock(int mode)
{
	(void) mutex_lock(&smb_shr_cache.sc_mtx);
	if (smb_shr_cache.sc_state != SMB_SHR_CACHE_STATE_CREATED) {
		(void) mutex_unlock(&smb_shr_cache.sc_mtx);
		return (NERR_InternalError);
	}
	smb_shr_cache.sc_nops++;
	(void) mutex_unlock(&smb_shr_cache.sc_mtx);

	/*
	 * Lock has to be taken outside the mutex otherwise
	 * there could be a deadlock
	 */
	if (mode == SMB_SHR_CACHE_RDLOCK)
		(void) rw_rdlock(&smb_shr_cache.sc_cache_lck);
	else
		(void) rw_wrlock(&smb_shr_cache.sc_cache_lck);

	return (NERR_Success);
}

/*
 * Decrement the number of inflight operations and then unlock.
 */
static void
smb_shr_cache_unlock(void)
{
	(void) mutex_lock(&smb_shr_cache.sc_mtx);
	assert(smb_shr_cache.sc_nops > 0);
	smb_shr_cache.sc_nops--;
	(void) cond_broadcast(&smb_shr_cache.sc_cv);
	(void) mutex_unlock(&smb_shr_cache.sc_mtx);

	(void) rw_unlock(&smb_shr_cache.sc_cache_lck);
}

/*
 * Return the total number of shares
 */
static int
smb_shr_cache_count(void)
{
	return (ht_get_total_items(smb_shr_cache.sc_cache));
}

/*
 * looks up the given share name in the cache and if it
 * finds a match returns a pointer to the cached entry.
 * Note that since a pointer is returned this function
 * MUST be protected by smb_shr_cache_lock/unlock pair
 */
static smb_share_t *
smb_shr_cache_findent(char *sharename)
{
	HT_ITEM *item;

	(void) smb_strlwr(sharename);
	item = ht_find_item(smb_shr_cache.sc_cache, sharename);
	if (item && item->hi_data)
		return ((smb_share_t *)item->hi_data);

	return (NULL);
}

/*
 * Return a pointer to the first/next entry in
 * the cache based on the given iterator.
 *
 * Calls to this function MUST be protected by
 * smb_shr_cache_lock/unlock.
 */
static smb_share_t *
smb_shr_cache_iterate(smb_shriter_t *shi)
{
	HT_ITEM *item;

	if (shi->si_first) {
		item = ht_findfirst(smb_shr_cache.sc_cache, &shi->si_hashiter);
		shi->si_first = B_FALSE;
	} else {
		item = ht_findnext(&shi->si_hashiter);
	}

	if (item && item->hi_data)
		return ((smb_share_t *)item->hi_data);

	return (NULL);
}

/*
 * Add the specified share to the cache.  Memory needs to be allocated
 * for the cache entry and the passed information is copied to the
 * allocated space.
 */
static uint32_t
smb_shr_cache_addent(smb_share_t *si)
{
	smb_share_t *cache_ent;
	uint32_t status = NERR_Success;

	if ((cache_ent = malloc(sizeof (smb_share_t))) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	(void) smb_strlwr(si->shr_name);

	si->shr_type |= smb_shr_is_special(cache_ent->shr_name);

	if (smb_shr_is_admin(cache_ent->shr_name))
		si->shr_flags |= SMB_SHRF_ADMIN;

	bcopy(si, cache_ent, sizeof (smb_share_t));

	if (si->shr_flags & SMB_SHRF_AUTOHOME)
		cache_ent->shr_refcnt = 1;

	if (ht_add_item(smb_shr_cache.sc_cache, cache_ent->shr_name, cache_ent)
	    == NULL) {
		syslog(LOG_DEBUG, "share: %s: cache update failed",
		    cache_ent->shr_name);
		free(cache_ent);
		status = NERR_InternalError;
	}

	return (status);
}

/*
 * Delete the specified share from the cache.
 */
static void
smb_shr_cache_delent(char *sharename)
{
	(void) smb_strlwr(sharename);
	(void) ht_remove_item(smb_shr_cache.sc_cache, sharename);
}

/*
 * Call back to free the given cache entry.
 */
static void
smb_shr_cache_freent(HT_ITEM *item)
{
	if (item && item->hi_data)
		free(item->hi_data);
}

/*
 * ============================================
 * Interfaces to sharemgr
 *
 * All functions in this section are private
 * ============================================
 */

/*
 * Load shares from sharemgr
 */
/*ARGSUSED*/
void *
smb_shr_load(void *args)
{
	sa_handle_t handle;
	sa_group_t group, subgroup;
	char *gstate;
	boolean_t gdisabled;

	(void) mutex_lock(&smb_shr_exec_mtx);
	(void) smb_config_get_execinfo(smb_shr_exec_map, smb_shr_exec_unmap,
	    MAXPATHLEN);
	(void) mutex_unlock(&smb_shr_exec_mtx);

	if ((handle = smb_shr_sa_enter()) == NULL) {
		syslog(LOG_ERR, "smb_shr_load: load failed");
		return (NULL);
	}

	for (group = sa_get_group(handle, NULL);
	    group != NULL; group = sa_get_next_group(group)) {
		gstate = sa_get_group_attr(group, "state");
		if (gstate == NULL)
			continue;

		gdisabled = (strcasecmp(gstate, "disabled") == 0);
		sa_free_attr_string(gstate);
		if (gdisabled)
			continue;

		smb_shr_sa_loadgrp(group);

		for (subgroup = sa_get_sub_group(group);
		    subgroup != NULL;
		    subgroup = sa_get_next_group(subgroup)) {
			smb_shr_sa_loadgrp(subgroup);
		}

	}
	smb_shr_sa_exit();
	return (NULL);
}

/*
 * Load the shares contained in the specified group.
 *
 * Don't process groups on which the smb protocol is disabled.
 * The top level ZFS group won't have the smb protocol enabled
 * but sub-groups will.
 *
 * We will tolerate a limited number of errors and then give
 * up on the current group.  A typical error might be that the
 * shared directory no longer exists.
 */
static void
smb_shr_sa_loadgrp(sa_group_t group)
{
	sa_share_t share;
	sa_resource_t resource;
	int error_count = 0;

	if (sa_get_optionset(group, SMB_PROTOCOL_NAME) == NULL)
		return;

	for (share = sa_get_share(group, NULL);
	    share != NULL;
	    share = sa_get_next_share(share)) {
		for (resource = sa_get_share_resource(share, NULL);
		    resource != NULL;
		    resource = sa_get_next_resource(resource)) {
			if (smb_shr_sa_load(share, resource))
				++error_count;

			if (error_count > SMB_SHR_ERROR_THRESHOLD)
				break;
		}

		if (error_count > SMB_SHR_ERROR_THRESHOLD)
			break;
	}
}

/*
 * Load a share definition from sharemgr and add it to the cache.
 * If the share is already in the cache then it doesn't do anything.
 *
 * This function does not report duplicate shares as error since
 * a share might have been added by smb_shr_get() while load is
 * in progress.
 */
static uint32_t
smb_shr_sa_load(sa_share_t share, sa_resource_t resource)
{
	smb_share_t si;
	char *sharename;
	uint32_t status;
	boolean_t loaded;

	if ((sharename = sa_get_resource_attr(resource, "name")) == NULL)
		return (NERR_InternalError);

	loaded = smb_shr_exists(sharename);
	sa_free_attr_string(sharename);

	if (loaded)
		return (NERR_Success);

	if ((status = smb_shr_sa_get(share, resource, &si)) != NERR_Success) {
		syslog(LOG_DEBUG, "share: failed to load %s (%d)",
		    si.shr_name, status);
		return (status);
	}

	status = smb_shr_add(&si);
	if ((status != NERR_Success) && (status != NERR_DuplicateShare)) {
		syslog(LOG_DEBUG, "share: failed to cache %s (%d)",
		    si.shr_name, status);
		return (status);
	}

	return (NERR_Success);
}

static char *
smb_shr_sa_getprop(sa_optionset_t opts, char *propname)
{
	sa_property_t prop;
	char *val = NULL;

	prop = sa_get_property(opts, propname);
	if (prop != NULL)
		val = sa_get_property_attr(prop, "value");

	return (val);
}

/*
 * Read the specified share information from sharemgr and return
 * it in the given smb_share_t structure.
 *
 * Shares read from sharemgr are marked as permanent/persistent.
 */
static uint32_t
smb_shr_sa_get(sa_share_t share, sa_resource_t resource, smb_share_t *si)
{
	sa_optionset_t opts;
	char *val = NULL;
	char *path;
	char *rname;

	if ((path = sa_get_share_attr(share, "path")) == NULL)
		return (NERR_InternalError);

	if ((rname = sa_get_resource_attr(resource, "name")) == NULL) {
		sa_free_attr_string(path);
		return (NERR_InternalError);
	}

	bzero(si, sizeof (smb_share_t));
	si->shr_flags = SMB_SHRF_PERM;

	(void) strlcpy(si->shr_path, path, sizeof (si->shr_path));
	(void) strlcpy(si->shr_name, rname, sizeof (si->shr_name));
	sa_free_attr_string(path);
	sa_free_attr_string(rname);

	val = sa_get_resource_description(resource);
	if (val == NULL)
		val = sa_get_share_description(share);

	if (val != NULL) {
		(void) strlcpy(si->shr_cmnt, val, sizeof (si->shr_cmnt));
		sa_free_share_description(val);
	}

	opts = sa_get_derived_optionset(resource, SMB_PROTOCOL_NAME, 1);
	if (opts == NULL)
		return (NERR_Success);

	val = smb_shr_sa_getprop(opts, SHOPT_AD_CONTAINER);
	if (val != NULL) {
		(void) strlcpy(si->shr_container, val,
		    sizeof (si->shr_container));
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_CATIA);
	if (val != NULL) {
		smb_shr_sa_setflag(val, si, SMB_SHRF_CATIA);
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_ABE);
	if (val != NULL) {
		smb_shr_sa_setflag(val, si, SMB_SHRF_ABE);
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_GUEST);
	if (val != NULL) {
		smb_shr_sa_setflag(val, si, SMB_SHRF_GUEST_OK);
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_DFSROOT);
	if (val != NULL) {
		smb_shr_sa_setflag(val, si, SMB_SHRF_DFSROOT);
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_CSC);
	if (val != NULL) {
		smb_shr_sa_csc_option(val, si);
		free(val);
	}

	val = smb_shr_sa_getprop(opts, SHOPT_NONE);
	if (val != NULL) {
		(void) strlcpy(si->shr_access_none, val,
		    sizeof (si->shr_access_none));
		free(val);
		si->shr_flags |= SMB_SHRF_ACC_NONE;
	}

	val = smb_shr_sa_getprop(opts, SHOPT_RO);
	if (val != NULL) {
		(void) strlcpy(si->shr_access_ro, val,
		    sizeof (si->shr_access_ro));
		free(val);
		si->shr_flags |= SMB_SHRF_ACC_RO;
	}

	val = smb_shr_sa_getprop(opts, SHOPT_RW);
	if (val != NULL) {
		(void) strlcpy(si->shr_access_rw, val,
		    sizeof (si->shr_access_rw));
		free(val);
		si->shr_flags |= SMB_SHRF_ACC_RW;
	}

	sa_free_derived_optionset(opts);
	return (NERR_Success);
}

/*
 * Map a client-side caching (CSC) option to the appropriate share
 * flag.  Only one option is allowed; an error will be logged if
 * multiple options have been specified.  We don't need to do anything
 * about multiple values here because the SRVSVC will not recognize
 * a value containing multiple flags and will return the default value.
 *
 * If the option value is not recognized, it will be ignored: invalid
 * values will typically be caught and rejected by sharemgr.
 */
void
smb_shr_sa_csc_option(const char *value, smb_share_t *si)
{
	int i;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (strcasecmp(value, cscopt[i].value) == 0) {
			si->shr_flags |= cscopt[i].flag;
			break;
		}
	}

	switch (si->shr_flags & SMB_SHRF_CSC_MASK) {
	case 0:
	case SMB_SHRF_CSC_DISABLED:
	case SMB_SHRF_CSC_MANUAL:
	case SMB_SHRF_CSC_AUTO:
	case SMB_SHRF_CSC_VDO:
		break;

	default:
		syslog(LOG_INFO, "csc option conflict: 0x%08x",
		    si->shr_flags & SMB_SHRF_CSC_MASK);
		break;
	}
}

/*
 * Return the option name for the first CSC flag (there should be only
 * one) encountered in the share flags.
 */
char *
smb_shr_sa_csc_name(const smb_share_t *si)
{
	int i;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (si->shr_flags & cscopt[i].flag)
			return (cscopt[i].value);
	}

	return (NULL);
}

/*
 * Takes the value of a boolean share property and set/clear the
 * specified flag based on the property's value.
 */
void
smb_shr_sa_setflag(const char *value, smb_share_t *si, uint32_t flag)
{
	if ((strcasecmp(value, "true") == 0) || (strcmp(value, "1") == 0))
		si->shr_flags |= flag;
	else
		si->shr_flags &= ~flag;
}

/*
 * looks up sharemgr for the given share (resource) and loads
 * the definition into cache if lookup is successful
 */
static uint32_t
smb_shr_sa_loadbyname(char *sharename)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_resource_t resource;
	uint32_t status;

	if ((handle = smb_shr_sa_enter()) == NULL)
		return (NERR_InternalError);

	resource = sa_find_resource(handle, sharename);
	if (resource == NULL) {
		smb_shr_sa_exit();
		return (NERR_NetNameNotFound);
	}

	share = sa_get_resource_parent(resource);
	if (share == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	status = smb_shr_sa_load(share, resource);

	smb_shr_sa_exit();
	return (status);
}

/*
 * ============================================
 * Share publishing functions
 *
 * All the functions are private
 * ============================================
 */

static void
smb_shr_publish(const char *sharename, const char *container)
{
	smb_shr_publisher_queue(sharename, container, SMB_SHR_PUBLISH);
}

static void
smb_shr_unpublish(const char *sharename, const char *container)
{
	smb_shr_publisher_queue(sharename, container, SMB_SHR_UNPUBLISH);
}

/*
 * In domain mode, put a share on the publisher queue.
 * This is a no-op if the smb service is in Workgroup mode.
 */
static void
smb_shr_publisher_queue(const char *sharename, const char *container, char op)
{
	smb_shr_pitem_t *item = NULL;

	if (container == NULL || *container == '\0')
		return;

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return;

	(void) mutex_lock(&ad_queue.spq_mtx);
	switch (ad_queue.spq_state) {
	case SMB_SHR_PQS_READY:
	case SMB_SHR_PQS_PUBLISHING:
		break;
	default:
		(void) mutex_unlock(&ad_queue.spq_mtx);
		return;
	}
	(void) mutex_unlock(&ad_queue.spq_mtx);

	if ((item = malloc(sizeof (smb_shr_pitem_t))) == NULL)
		return;

	item->spi_op = op;
	(void) strlcpy(item->spi_name, sharename, sizeof (item->spi_name));
	(void) strlcpy(item->spi_container, container,
	    sizeof (item->spi_container));

	(void) mutex_lock(&ad_queue.spq_mtx);
	list_insert_tail(&ad_queue.spq_list, item);
	(void) cond_signal(&ad_queue.spq_cv);
	(void) mutex_unlock(&ad_queue.spq_mtx);
}

/*
 * Publishing won't be activated if the smb service is running in
 * Workgroup mode.
 */
static int
smb_shr_publisher_start(void)
{
	pthread_t publish_thr;
	pthread_attr_t tattr;
	int rc;

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return (0);

	(void) mutex_lock(&ad_queue.spq_mtx);
	if (ad_queue.spq_state != SMB_SHR_PQS_NOQUEUE) {
		(void) mutex_unlock(&ad_queue.spq_mtx);
		errno = EINVAL;
		return (-1);
	}

	list_create(&ad_queue.spq_list, sizeof (smb_shr_pitem_t),
	    offsetof(smb_shr_pitem_t, spi_lnd));
	ad_queue.spq_state = SMB_SHR_PQS_READY;
	(void) mutex_unlock(&ad_queue.spq_mtx);

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&publish_thr, &tattr, smb_shr_publisher, 0);
	(void) pthread_attr_destroy(&tattr);

	return (rc);
}

static void
smb_shr_publisher_stop(void)
{
	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		return;

	(void) mutex_lock(&ad_queue.spq_mtx);
	switch (ad_queue.spq_state) {
	case SMB_SHR_PQS_READY:
	case SMB_SHR_PQS_PUBLISHING:
		ad_queue.spq_state = SMB_SHR_PQS_STOPPING;
		(void) cond_signal(&ad_queue.spq_cv);
		break;
	default:
		break;
	}
	(void) mutex_unlock(&ad_queue.spq_mtx);
}

/*
 * This is the publisher daemon thread.  While running, the thread waits
 * on a conditional variable until notified that a share needs to be
 * [un]published or that the thread should be terminated.
 *
 * Entries may remain in the outgoing queue if the Active Directory
 * service is inaccessible, in which case the thread wakes up every 60
 * seconds to retry.
 */
/*ARGSUSED*/
static void *
smb_shr_publisher(void *arg)
{
	smb_ads_handle_t *ah;
	smb_shr_pitem_t *shr;
	list_t publist;
	timestruc_t pubretry;
	char hostname[MAXHOSTNAMELEN];

	(void) mutex_lock(&ad_queue.spq_mtx);
	if (ad_queue.spq_state != SMB_SHR_PQS_READY) {
		(void) mutex_unlock(&ad_queue.spq_mtx);
		return (NULL);
	}
	ad_queue.spq_state = SMB_SHR_PQS_PUBLISHING;
	(void) mutex_unlock(&ad_queue.spq_mtx);

	(void) smb_gethostname(hostname, MAXHOSTNAMELEN,
	    SMB_CASE_PRESERVE);

	list_create(&publist, sizeof (smb_shr_pitem_t),
	    offsetof(smb_shr_pitem_t, spi_lnd));

	for (;;) {
		(void) mutex_lock(&ad_queue.spq_mtx);

		while (list_is_empty(&ad_queue.spq_list) &&
		    (ad_queue.spq_state == SMB_SHR_PQS_PUBLISHING)) {
			if (list_is_empty(&publist)) {
				(void) cond_wait(&ad_queue.spq_cv,
				    &ad_queue.spq_mtx);
			} else {
				pubretry.tv_sec = 60;
				pubretry.tv_nsec = 0;
				(void) cond_reltimedwait(&ad_queue.spq_cv,
				    &ad_queue.spq_mtx, &pubretry);
				break;
			}
		}

		if (ad_queue.spq_state != SMB_SHR_PQS_PUBLISHING) {
			(void) mutex_unlock(&ad_queue.spq_mtx);
			break;
		}

		/*
		 * Transfer queued items to the local list so that
		 * the mutex can be released.
		 */
		while ((shr = list_head(&ad_queue.spq_list)) != NULL) {
			list_remove(&ad_queue.spq_list, shr);
			list_insert_tail(&publist, shr);
		}

		(void) mutex_unlock(&ad_queue.spq_mtx);

		if ((ah = smb_ads_open()) != NULL) {
			smb_shr_publisher_send(ah, &publist, hostname);
			smb_ads_close(ah);
		}
	}

	(void) mutex_lock(&ad_queue.spq_mtx);
	smb_shr_publisher_flush(&ad_queue.spq_list);
	list_destroy(&ad_queue.spq_list);
	ad_queue.spq_state = SMB_SHR_PQS_NOQUEUE;
	(void) mutex_unlock(&ad_queue.spq_mtx);

	smb_shr_publisher_flush(&publist);
	list_destroy(&publist);
	return (NULL);
}

/*
 * Remove items from the specified queue and [un]publish them.
 */
static void
smb_shr_publisher_send(smb_ads_handle_t *ah, list_t *publist, const char *host)
{
	smb_shr_pitem_t *shr;

	while ((shr = list_head(publist)) != NULL) {
		(void) mutex_lock(&ad_queue.spq_mtx);
		if (ad_queue.spq_state != SMB_SHR_PQS_PUBLISHING) {
			(void) mutex_unlock(&ad_queue.spq_mtx);
			return;
		}
		(void) mutex_unlock(&ad_queue.spq_mtx);

		list_remove(publist, shr);

		if (shr->spi_op == SMB_SHR_PUBLISH)
			(void) smb_ads_publish_share(ah, shr->spi_name,
			    NULL, shr->spi_container, host);
		else
			(void) smb_ads_remove_share(ah, shr->spi_name,
			    NULL, shr->spi_container, host);

		free(shr);
	}
}

/*
 * Flush all remaining items from the specified list/queue.
 */
static void
smb_shr_publisher_flush(list_t *lst)
{
	smb_shr_pitem_t *shr;

	while ((shr = list_head(lst)) != NULL) {
		list_remove(lst, shr);
		free(shr);
	}
}

/*
 * If the share path refers to a ZFS file system, add the
 * .zfs/shares/<share> object and call smb_quota_add_fs()
 * to initialize quota support for the share.
 */
static void
smb_shr_zfs_add(smb_share_t *si)
{
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	int ret;
	char buf[MAXPATHLEN];	/* dataset or mountpoint */

	if (smb_getdataset(si->shr_path, buf, MAXPATHLEN) != 0)
		return;

	if ((libhd = libzfs_init()) == NULL)
		return;

	if ((zfshd = zfs_open(libhd, buf, ZFS_TYPE_FILESYSTEM)) == NULL) {
		libzfs_fini(libhd);
		return;
	}

	errno = 0;
	ret = zfs_smb_acl_add(libhd, buf, si->shr_path, si->shr_name);
	if (ret != 0 && errno != EAGAIN && errno != EEXIST)
		syslog(LOG_INFO, "share: failed to add ACL object: %s: %s\n",
		    si->shr_name, strerror(errno));

	if (zfs_prop_get(zfshd, ZFS_PROP_MOUNTPOINT, buf, MAXPATHLEN,
	    NULL, NULL, 0, B_FALSE) == 0) {
		smb_quota_add_fs(buf);
	}


	zfs_close(zfshd);
	libzfs_fini(libhd);
}

/*
 * If the share path refers to a ZFS file system, remove the
 * .zfs/shares/<share> object, and call smb_quota_remove_fs()
 * to end quota support for the share.
 */
static void
smb_shr_zfs_remove(smb_share_t *si)
{
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	int ret;
	char buf[MAXPATHLEN];	/* dataset or mountpoint */

	if (smb_getdataset(si->shr_path, buf, MAXPATHLEN) != 0)
		return;

	if ((libhd = libzfs_init()) == NULL)
		return;

	if ((zfshd = zfs_open(libhd, buf, ZFS_TYPE_FILESYSTEM)) == NULL) {
		libzfs_fini(libhd);
		return;
	}

	errno = 0;
	ret = zfs_smb_acl_remove(libhd, buf, si->shr_path, si->shr_name);
	if (ret != 0 && errno != EAGAIN)
		syslog(LOG_INFO, "share: failed to remove ACL object: %s: %s\n",
		    si->shr_name, strerror(errno));

	if (zfs_prop_get(zfshd, ZFS_PROP_MOUNTPOINT, buf, MAXPATHLEN,
	    NULL, NULL, 0, B_FALSE) == 0) {
		smb_quota_remove_fs(buf);
	}

	zfs_close(zfshd);
	libzfs_fini(libhd);
}

/*
 * If the share path refers to a ZFS file system, rename the
 * .zfs/shares/<share> object.
 */
static void
smb_shr_zfs_rename(smb_share_t *from, smb_share_t *to)
{
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	int ret;
	char dataset[MAXPATHLEN];

	if (smb_getdataset(from->shr_path, dataset, MAXPATHLEN) != 0)
		return;

	if ((libhd = libzfs_init()) == NULL)
		return;

	if ((zfshd = zfs_open(libhd, dataset, ZFS_TYPE_FILESYSTEM)) == NULL) {
		libzfs_fini(libhd);
		return;
	}

	errno = 0;
	ret = zfs_smb_acl_rename(libhd, dataset, from->shr_path,
	    from->shr_name, to->shr_name);
	if (ret != 0 && errno != EAGAIN)
		syslog(LOG_INFO, "share: failed to rename ACL object: %s: %s\n",
		    from->shr_name, strerror(errno));

	zfs_close(zfshd);
	libzfs_fini(libhd);
}

/*
 * Enable all privileges in the inheritable set to execute command.
 */
static int
smb_shr_enable_all_privs(void)
{
	priv_set_t *pset;

	pset = priv_allocset();
	if (pset == NULL)
		return (-1);

	if (getppriv(PRIV_LIMIT, pset)) {
		priv_freeset(pset);
		return (-1);
	}

	if (setppriv(PRIV_ON, PRIV_INHERITABLE, pset)) {
		priv_freeset(pset);
		return (-1);
	}

	priv_freeset(pset);
	return (0);
}

/*
 * Tokenizes the command string and returns the list of tokens in an array.
 *
 * Returns NULL if there are no tokens.
 */
static char **
smb_shr_tokenize_cmd(char *cmdstr)
{
	char *cmd, *buf, *bp, *value;
	char **argv, **ap;
	int argc, i;

	if (cmdstr == NULL || *cmdstr == '\0')
		return (NULL);

	if ((buf = malloc(MAXPATHLEN)) == NULL)
		return (NULL);

	(void) strlcpy(buf, cmdstr, MAXPATHLEN);

	for (argc = 2, bp = cmdstr; *bp != '\0'; ++bp)
		if (*bp == ' ')
			++argc;

	if ((argv = calloc(argc, sizeof (char *))) == NULL) {
		free(buf);
		return (NULL);
	}

	ap = argv;
	for (bp = buf, i = 0; i < argc; ++i) {
		do {
			if ((value = strsep(&bp, " ")) == NULL)
				break;
		} while (*value == '\0');

		if (value == NULL)
			break;

		*ap++ = value;
	}

	/* get the filename of the command from the path */
	if ((cmd = strrchr(argv[0], '/')) != NULL)
		(void) strlcpy(argv[0], ++cmd, strlen(argv[0]));

	return (argv);
}

/*
 * Expands the command string for the following substitution tokens:
 *
 * %U - Windows username
 * %D - Name of the domain or workgroup of %U
 * %h - The server hostname
 * %M - The client hostname
 * %L - The server NetBIOS name
 * %m - The client NetBIOS name. This option is only valid for NetBIOS
 *      connections (port 139).
 * %I - The IP address of the client machine
 * %i - The local IP address to which the client is connected
 * %S - The name of the share
 * %P - The root directory of the share
 * %u - The UID of the Unix user
 *
 * Returns 0 on success.  Otherwise -1.
 */
static int
smb_shr_expand_subs(char **cmd_toks, smb_share_t *si, smb_shr_execinfo_t *subs)
{
	char *fmt, *sub_chr, *ptr;
	boolean_t unknown;
	char hostname[MAXHOSTNAMELEN];
	char ip_str[INET6_ADDRSTRLEN];
	char name[SMB_PI_MAX_HOST];
	smb_wchar_t wbuf[SMB_PI_MAX_HOST];
	int i;

	if (cmd_toks == NULL || *cmd_toks == NULL)
		return (-1);

	for (i = 1; cmd_toks[i]; i++) {
		fmt = cmd_toks[i];
		if (*fmt == '%') {
			sub_chr = fmt + 1;
			unknown = B_FALSE;

			switch (*sub_chr) {
			case 'U':
				ptr = strdup(subs->e_winname);
				break;
			case 'D':
				ptr = strdup(subs->e_userdom);
				break;
			case 'h':
				if (gethostname(hostname, MAXHOSTNAMELEN) != 0)
					unknown = B_TRUE;
				else
					ptr = strdup(hostname);
				break;
			case 'M':
				if (smb_getnameinfo(&subs->e_cli_ipaddr,
				    hostname, sizeof (hostname), 0) != 0)
					unknown = B_TRUE;
				else
					ptr = strdup(hostname);
				break;
			case 'L':
				if (smb_getnetbiosname(hostname,
				    NETBIOS_NAME_SZ) != 0)
					unknown = B_TRUE;
				else
					ptr = strdup(hostname);
				break;
			case 'm':
				if (*subs->e_cli_netbiosname == '\0')
					unknown = B_TRUE;
				else {
					(void) smb_mbstowcs(wbuf,
					    subs->e_cli_netbiosname,
					    SMB_PI_MAX_HOST - 1);

					if (ucstooem(name, wbuf,
					    SMB_PI_MAX_HOST, OEM_CPG_850) == 0)
						(void) strlcpy(name,
						    subs->e_cli_netbiosname,
						    SMB_PI_MAX_HOST);

					ptr = strdup(name);
				}
				break;
			case 'I':
				if (smb_inet_ntop(&subs->e_cli_ipaddr, ip_str,
				    SMB_IPSTRLEN(subs->e_cli_ipaddr.a_family))
				    != NULL)
					ptr = strdup(ip_str);
				else
					unknown = B_TRUE;
				break;
			case 'i':
				if (smb_inet_ntop(&subs->e_srv_ipaddr, ip_str,
				    SMB_IPSTRLEN(subs->e_srv_ipaddr.a_family))
				    != NULL)
					ptr = strdup(ip_str);
				else
					unknown = B_TRUE;
				break;
			case 'S':
				ptr = strdup(si->shr_name);
				break;
			case 'P':
				ptr = strdup(si->shr_path);
				break;
			case 'u':
				(void) snprintf(name, sizeof (name), "%u",
				    subs->e_uid);
				ptr = strdup(name);
				break;
			default:
				/* unknown sub char */
				unknown = B_TRUE;
				break;
			}

			if (unknown)
				ptr = strdup("");

		} else  /* first char of cmd's arg is not '%' char */
			ptr = strdup("");

		cmd_toks[i] = ptr;

		if (ptr == NULL) {
			for (i = 1; cmd_toks[i]; i++)
				free(cmd_toks[i]);

			return (-1);
		}
	}

	return (0);
}

/*ARGSUSED*/
static void
smb_shr_sig_abnormal_term(int sig_val)
{
	/*
	 * Calling _exit() prevents parent process from getting SIGTERM/SIGINT
	 * signal.
	 */
	_exit(-1);
}

/*ARGSUSED*/
static void
smb_shr_sig_child(int sig_val)
{
	/*
	 * Catch the signal and allow the exit status of the child process
	 * to be available for reaping.
	 */
}

/*
 * This is a temporary function which converts the given smb_share_t
 * structure to the nvlist format that will be provided by libsharev2
 */
static int
smb_shr_encode(smb_share_t *si, nvlist_t **nvlist)
{
	nvlist_t *list;
	nvlist_t *share;
	nvlist_t *smb;
	char *csc;
	int rc = 0;

	*nvlist = NULL;

	if ((rc = nvlist_alloc(&list, NV_UNIQUE_NAME, 0)) != 0)
		return (rc);

	if ((rc = nvlist_alloc(&share, NV_UNIQUE_NAME, 0)) != 0) {
		nvlist_free(list);
		return (rc);
	}

	if ((rc = nvlist_alloc(&smb, NV_UNIQUE_NAME, 0)) != 0) {
		nvlist_free(share);
		nvlist_free(list);
		return (rc);
	}

	/* global share properties */
	rc |= nvlist_add_string(share, "name", si->shr_name);
	rc |= nvlist_add_string(share, "path", si->shr_path);
	rc |= nvlist_add_string(share, "desc", si->shr_cmnt);

	/* smb protocol properties */
	rc = nvlist_add_string(smb, SHOPT_AD_CONTAINER, si->shr_container);
	if ((si->shr_flags & SMB_SHRF_ACC_NONE) != 0)
		rc |= nvlist_add_string(smb, SHOPT_NONE, si->shr_access_none);
	if ((si->shr_flags & SMB_SHRF_ACC_RO) != 0)
		rc |= nvlist_add_string(smb, SHOPT_RO, si->shr_access_ro);
	if ((si->shr_flags & SMB_SHRF_ACC_RW) != 0)
		rc |= nvlist_add_string(smb, SHOPT_RW, si->shr_access_rw);

	if ((si->shr_flags & SMB_SHRF_ABE) != 0)
		rc |= nvlist_add_string(smb, SHOPT_ABE, "true");
	if ((si->shr_flags & SMB_SHRF_CATIA) != 0)
		rc |= nvlist_add_string(smb, SHOPT_CATIA, "true");
	if ((si->shr_flags & SMB_SHRF_GUEST_OK) != 0)
		rc |= nvlist_add_string(smb, SHOPT_GUEST, "true");
	if ((si->shr_flags & SMB_SHRF_DFSROOT) != 0)
		rc |= nvlist_add_string(smb, SHOPT_DFSROOT, "true");

	if ((si->shr_flags & SMB_SHRF_AUTOHOME) != 0) {
		rc |= nvlist_add_string(smb, "Autohome", "true");
		rc |= nvlist_add_uint32(smb, "uid", si->shr_uid);
		rc |= nvlist_add_uint32(smb, "gid", si->shr_gid);
	}

	if ((csc = smb_shr_sa_csc_name(si)) != NULL)
		rc |= nvlist_add_string(smb, SHOPT_CSC, csc);

	rc |= nvlist_add_uint32(smb, "type", si->shr_type);

	rc |= nvlist_add_nvlist(share, "smb", smb);
	rc |= nvlist_add_nvlist(list, si->shr_name, share);

	nvlist_free(share);
	nvlist_free(smb);

	if (rc != 0)
		nvlist_free(list);
	else
		*nvlist = list;

	return (rc);
}
