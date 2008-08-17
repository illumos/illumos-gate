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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)smb_share.c	1.7	08/08/07 SMI"

/*
 * Lan Manager (SMB/CIFS) share interface implementation. This interface
 * returns Win32 error codes, usually network error values (lmerr.h).
 */

#include <errno.h>
#include <synch.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <thread.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <synch.h>
#include <pthread.h>
#include <ctype.h>
#include <assert.h>
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>

#include <libshare.h>

#include <smbsrv/lm.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/cifs.h>

#include <smbsrv/ctype.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/nterror.h>

/*
 * Cache functions and vars
 */
#define	SMB_SHARE_HTAB_SZ	1024

static HT_HANDLE *smb_shr_handle = NULL;
static rwlock_t smb_shr_lock;
static pthread_t smb_shr_populate_thr;

static uint32_t smb_shr_cache_create(void);
static void smb_shr_cache_destroy(void);
static void *smb_shr_cache_populate(void *);
static uint32_t smb_shr_cache_addent(smb_share_t *);
static void smb_shr_cache_delent(char *);
static uint32_t smb_shr_cache_chgent(smb_share_t *);
static void smb_shr_cache_freent(HT_ITEM *);
static uint32_t smb_shr_cache_loadent(sa_share_t, sa_resource_t);
static void smb_shr_cache_loadgrp(sa_group_t);

static void smb_shr_set_ahcnt(char *, int);
static void smb_shr_set_oemname(smb_share_t *);
static uint32_t smb_shr_create_autohome(smb_share_t *);
static uint32_t smb_shr_create_ipc(void);

/*
 * sharemgr functions
 */
static uint32_t smb_shr_sa_delent(smb_share_t *);
static uint32_t smb_shr_sa_addent(smb_share_t *);
static uint32_t smb_shr_sa_getent(sa_share_t, sa_resource_t, smb_share_t *);
static sa_group_t smb_shr_sa_getdefgrp(sa_handle_t);

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
	int		spq_cnt;
	list_t		spq_list;
	mutex_t		spq_mtx;
	cond_t		spq_cv;
	uint32_t	spq_state;
} smb_shr_pqueue_t;

static smb_shr_pqueue_t ad_queue;
static pthread_t smb_shr_publish_thr;

static int smb_shr_publisher_start(void);
static void smb_shr_publisher_stop(void);
static void smb_shr_publisher_send(smb_ads_handle_t *, list_t *, const char *);
static void *smb_shr_publisher(void *);
static void smb_shr_publish(const char *, const char *, char);


/*
 * smb_shr_start
 *
 * Starts the publisher thread and another thread which
 * populates the share cache by share information stored
 * by sharemgr
 */
int
smb_shr_start(void)
{
	pthread_attr_t tattr;
	int rc;

	if ((rc = smb_shr_publisher_start()) != 0)
		return (rc);

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smb_shr_populate_thr, &tattr,
	    smb_shr_cache_populate, 0);
	(void) pthread_attr_destroy(&tattr);

	return (rc);
}

void
smb_shr_stop(void)
{
	smb_shr_cache_destroy();
	smb_shr_publisher_stop();
}

/*
 * smb_shr_count
 *
 * Return the total number of shares
 */
int
smb_shr_count(void)
{
	int n_shares;

	(void) rw_rdlock(&smb_shr_lock);
	n_shares = ht_get_total_items(smb_shr_handle);
	(void) rw_unlock(&smb_shr_lock);

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
	HT_ITEM *item;
	smb_share_t *share = NULL;

	if (smb_shr_handle == NULL || shi == NULL)
		return (NULL);

	(void) rw_rdlock(&smb_shr_lock);
	if (shi->si_first) {
		item = ht_findfirst(smb_shr_handle, &shi->si_hashiter);
		shi->si_first = B_FALSE;
	} else {
		item = ht_findnext(&shi->si_hashiter);
	}

	if (item && item->hi_data) {
		share = &shi->si_share;
		bcopy(item->hi_data, share, sizeof (smb_share_t));
	}
	(void) rw_unlock(&smb_shr_lock);

	return (share);
}

/*
 * smb_shr_create
 *
 * Adds the given to cache and if 'store' is B_TRUE it's also
 * added to sharemgr
 */
uint32_t
smb_shr_create(smb_share_t *si, boolean_t store)
{
	uint32_t status = NERR_Success;
	int rc;

	assert(si != NULL);

	if (!smb_shr_chkname(si->shr_name))
		return (ERROR_INVALID_NAME);

	if (si->shr_flags & SMB_SHRF_AUTOHOME)
		return (smb_shr_create_autohome(si));

	if (smb_shr_exists(si->shr_name))
		return (NERR_DuplicateShare);

	if ((status = smb_shr_cache_addent(si)) != NERR_Success)
		return (status);

	if (store && (si->shr_flags & SMB_SHRF_PERM)) {
		if ((status = smb_shr_sa_addent(si)) != NERR_Success) {
			(void) smb_shr_cache_delent(si->shr_name);
			return (status);
		}
	}

	rc = smb_dwncall_share(SMB_SHROP_ADD, si->shr_path, si->shr_name);

	if (rc == 0) {
		smb_shr_publish(si->shr_name, si->shr_container,
		    SMB_SHR_PUBLISH);
		return (status);
	}

	smb_shr_cache_delent(si->shr_name);
	if (store && (si->shr_flags & SMB_SHRF_PERM))
		(void) smb_shr_sa_delent(si);

	/*
	 * rc == ENOENT means the shared directory doesn't exist
	 */
	return ((rc == ENOENT) ? NERR_UnknownDevDir : NERR_InternalError);
}

/*
 * smb_shr_delete
 *
 * Removes the specified share.
 */
uint32_t
smb_shr_delete(char *sharename, boolean_t store)
{
	smb_share_t si;
	uint32_t status = NERR_Success;

	assert(sharename != NULL);

	if ((status = smb_shr_get(sharename, &si)) != NERR_Success)
		return (status);

	if (si.shr_type & STYPE_IPC)
		return (ERROR_ACCESS_DENIED);

	if (si.shr_flags & SMB_SHRF_AUTOHOME) {
		si.shr_refcnt--;
		if (si.shr_refcnt > 0) {
			smb_shr_set_ahcnt(si.shr_name, si.shr_refcnt);
			return (status);
		}
	}

	if (store && (si.shr_flags & SMB_SHRF_PERM)) {
		if (smb_shr_sa_delent(&si) != NERR_Success)
			return (NERR_InternalError);
	}

	smb_shr_cache_delent(si.shr_name);
	smb_shr_publish(si.shr_name, si.shr_container, SMB_SHR_UNPUBLISH);
	(void) smb_dwncall_share(SMB_SHROP_DELETE, si.shr_path, si.shr_name);

	return (NERR_Success);
}

/*
 * smb_shr_rename
 *
 * Rename a share. Check that the current name exists and the new name
 * doesn't exist. The rename is performed by deleting the current share
 * definition and creating a new share with the new name.
 */
uint32_t
smb_shr_rename(char *from_name, char *to_name)
{
	smb_share_t si;
	uint32_t status;

	assert((from_name != NULL) && (to_name != NULL));

	if (!smb_shr_chkname(from_name) || !smb_shr_chkname(to_name))
		return (ERROR_INVALID_NAME);

	if (!smb_shr_exists(from_name))
		return (NERR_NetNameNotFound);

	if (smb_shr_exists(to_name))
		return (NERR_DuplicateShare);

	if ((status = smb_shr_get(from_name, &si)) != NERR_Success)
		return (status);

	if (si.shr_type & STYPE_IPC)
		return (ERROR_ACCESS_DENIED);

	(void) strlcpy(si.shr_name, to_name, sizeof (si.shr_name));
	if ((status = smb_shr_cache_addent(&si)) != NERR_Success)
		return (status);

	smb_shr_cache_delent(from_name);
	smb_shr_publish(from_name, si.shr_container, SMB_SHR_UNPUBLISH);
	smb_shr_publish(to_name, si.shr_container, SMB_SHR_PUBLISH);

	return (NERR_Success);
}

/*
 * smb_shr_get
 *
 * Load the information for the specified share into the supplied share
 * info structure.
 */
uint32_t
smb_shr_get(char *sharename, smb_share_t *si)
{
	HT_ITEM *item;

	(void) utf8_strlwr(sharename);

	(void) rw_rdlock(&smb_shr_lock);
	item = ht_find_item(smb_shr_handle, sharename);
	if (item == NULL || item->hi_data == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_NetNameNotFound);
	}

	bcopy(item->hi_data, si, sizeof (smb_share_t));
	(void) rw_unlock(&smb_shr_lock);

	return (NERR_Success);
}

/*
 * smb_shr_modify
 *
 * Modifies an existing share. Properties that can be modified are:
 *
 *   o comment
 *   o AD container
 */
uint32_t
smb_shr_modify(char *sharename, const char *cmnt,
    const char *ad_container, boolean_t store)
{
	smb_share_t si;
	uint32_t status;
	boolean_t cmnt_changed = B_FALSE;
	boolean_t adc_changed = B_FALSE;
	char shr_container[MAXPATHLEN];

	assert(sharename != NULL);

	if ((cmnt == NULL) && (ad_container == NULL))
		/* no changes */
		return (NERR_Success);

	if ((status = smb_shr_get(sharename, &si)) != NERR_Success)
		return (status);

	if (si.shr_type & STYPE_IPC)
		return (ERROR_ACCESS_DENIED);

	if (cmnt) {
		cmnt_changed = (strcmp(cmnt, si.shr_cmnt) != 0);
		if (cmnt_changed)
			(void) strlcpy(si.shr_cmnt, cmnt, sizeof (si.shr_cmnt));
	}

	if (ad_container) {
		adc_changed = (strcmp(ad_container, si.shr_container) != 0);
		if (adc_changed) {
			/* save current container needed for unpublishing */
			(void) strlcpy(shr_container, si.shr_container,
			    sizeof (shr_container));
			(void) strlcpy(si.shr_container, ad_container,
			    sizeof (si.shr_container));
		}
	}

	if (!cmnt_changed && !adc_changed)
		/* no changes */
		return (NERR_Success);

	if (store && (si.shr_flags & SMB_SHRF_PERM)) {
		if (smb_shr_sa_addent(&si) != NERR_Success)
			return (NERR_InternalError);
	}

	(void) smb_shr_cache_chgent(&si);

	if (adc_changed) {
		smb_shr_publish(si.shr_name, shr_container,
		    SMB_SHR_UNPUBLISH);
		smb_shr_publish(si.shr_name, si.shr_container,
		    SMB_SHR_PUBLISH);
	}

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
		    ((si->shr_type & STYPE_IPC) == 0)) {
			bcopy(si, &list->sl_shares[n], sizeof (smb_share_t));
			if (++n == LMSHARES_PER_REQUEST)
				break;
		}
	}

	list->sl_cnt = n;
}


/*
 * smb_shr_exists
 *
 * Returns B_TRUE if the share exists. Otherwise returns B_FALSE
 */
boolean_t
smb_shr_exists(char *sharename)
{
	boolean_t exists;

	if (sharename == NULL || *sharename == '\0')
		return (B_FALSE);

	(void) utf8_strlwr(sharename);

	(void) rw_rdlock(&smb_shr_lock);
	exists = (ht_find_item(smb_shr_handle, sharename) != NULL);
	(void) rw_unlock(&smb_shr_lock);

	return (exists);
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
		if (utf8_strcasecmp(restricted[i], sharename) == 0)
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
	    mts_isalpha(sharename[0]) && sharename[1] == '$') {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_shr_chkname
 *
 * Check if any invalid char is present in share name. According to
 * MSDN article #236388: "Err Msg: The Share Name Contains Invalid
 * Characters", the list of invalid character is:
 *
 * " / \ [ ] : | < > + ; , ? * =
 *
 * Also rejects if control characters are embedded.
 */
boolean_t
smb_shr_chkname(char *sharename)
{
	char *invalid = "\"/\\[]:|<>+;,?*=";
	char *cp;

	if (sharename == NULL)
		return (B_FALSE);

	if (strpbrk(sharename, invalid))
		return (B_FALSE);

	for (cp = sharename; *cp != '\0'; cp++) {
		if (iscntrl(*cp))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * smb_shr_get_realpath
 *
 * Derive the real path of a share from the path provided by a
 * Windows client application during the share addition.
 *
 * For instance, the real path of C:\ is /cvol and the
 * real path of F:\home is /vol1/home.
 *
 * clipath  - path provided by the Windows client is in the
 *            format of <drive letter>:\<dir>
 * realpath - path that will be stored as the directory field of
 *            the smb_share_t structure of the share.
 * maxlen   - maximum length fo the realpath buffer
 *
 * Return LAN Manager network error code.
 */
/*ARGSUSED*/
uint32_t
smb_shr_get_realpath(const char *clipath, char *realpath, int maxlen)
{
	/* XXX do this translation */
	return (NERR_Success);
}

/*
 * ============================================
 * Cache management functions
 * ============================================
 */

/*
 * smb_shr_cache_create
 *
 * Create the share hash table.
 */
static uint32_t
smb_shr_cache_create(void)
{
	if (smb_shr_handle == NULL) {
		(void) rwlock_init(&smb_shr_lock, USYNC_THREAD, 0);
		(void) rw_wrlock(&smb_shr_lock);

		smb_shr_handle = ht_create_table(SMB_SHARE_HTAB_SZ,
		    MAXNAMELEN, 0);
		if (smb_shr_handle == NULL) {
			(void) rw_unlock(&smb_shr_lock);
			return (NERR_InternalError);
		}

		(void) ht_register_callback(smb_shr_handle,
		    smb_shr_cache_freent);
		(void) rw_unlock(&smb_shr_lock);
	}

	return (NERR_Success);
}

/*
 * smb_shr_cache_destroy
 *
 * Destroys the share hash table.
 */
static void
smb_shr_cache_destroy(void)
{
	if (smb_shr_handle) {
		(void) rw_wrlock(&smb_shr_lock);
		ht_destroy_table(smb_shr_handle);
		(void) rw_unlock(&smb_shr_lock);
		(void) rwlock_destroy(&smb_shr_lock);
		smb_shr_handle = NULL;
	}
}

/*
 * smb_shr_cache_populate
 *
 * Load shares from sharemgr
 */
/*ARGSUSED*/
static void *
smb_shr_cache_populate(void *args)
{
	sa_handle_t handle;
	sa_group_t group, subgroup;
	char *gstate;
	boolean_t gdisabled;

	if (smb_shr_cache_create() != NERR_Success) {
		syslog(LOG_ERR, "share: failed creating the cache");
		return (NULL);
	}

	if (smb_shr_create_ipc() != NERR_Success) {
		syslog(LOG_ERR, "share: failed creating IPC$");
		return (NULL);
	}

	if ((handle = sa_init(SA_INIT_SHARE_API)) == NULL) {
		syslog(LOG_ERR, "share: failed connecting to backend");
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

		smb_shr_cache_loadgrp(group);
		for (subgroup = sa_get_sub_group(group);
		    subgroup != NULL;
		    subgroup = sa_get_next_group(subgroup)) {
			smb_shr_cache_loadgrp(subgroup);
		}

	}

	sa_fini(handle);
	return (NULL);
}

static uint32_t
smb_shr_cache_addent(smb_share_t *si)
{
	smb_share_t *cache_ent;
	uint32_t status = NERR_Success;

	/*
	 * allocate memory for the entry that needs to be cached.
	 */
	if ((cache_ent = malloc(sizeof (smb_share_t))) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	bcopy(si, cache_ent, sizeof (smb_share_t));

	(void) utf8_strlwr(cache_ent->shr_name);
	smb_shr_set_oemname(cache_ent);
	if ((si->shr_type & STYPE_IPC) == 0)
		cache_ent->shr_type = STYPE_DISKTREE;
	cache_ent->shr_type |= smb_shr_is_special(cache_ent->shr_name);

	(void) rw_wrlock(&smb_shr_lock);
	if (ht_add_item(smb_shr_handle, cache_ent->shr_name, cache_ent)
	    == NULL) {
		syslog(LOG_DEBUG, "share: failed adding %s to cache",
		    cache_ent->shr_name);
		free(cache_ent);
		status = NERR_InternalError;
	}
	(void) rw_unlock(&smb_shr_lock);

	return (status);
}

static void
smb_shr_cache_delent(char *sharename)
{
	(void) utf8_strlwr(sharename);
	(void) rw_wrlock(&smb_shr_lock);
	(void) ht_remove_item(smb_shr_handle, sharename);
	(void) rw_unlock(&smb_shr_lock);
}

static uint32_t
smb_shr_cache_chgent(smb_share_t *si)
{
	smb_share_t *cache_ent;
	uint32_t status = NERR_Success;

	/*
	 * allocate memory for the entry that needs to be cached.
	 */
	if ((cache_ent = malloc(sizeof (smb_share_t))) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	bcopy(si, cache_ent, sizeof (smb_share_t));
	(void) utf8_strlwr(cache_ent->shr_name);

	(void) rw_wrlock(&smb_shr_lock);
	if (ht_replace_item(smb_shr_handle, cache_ent->shr_name, cache_ent)
	    == NULL) {
		syslog(LOG_DEBUG, "share: failed modifying %s",
		    cache_ent->shr_name);
		free(cache_ent);
		status = NERR_InternalError;
	}
	(void) rw_unlock(&smb_shr_lock);

	return (status);
}

static uint32_t
smb_shr_create_autohome(smb_share_t *si)
{
	uint32_t status = NERR_Success;
	int rc;

	if (si->shr_refcnt == 0) {
		if ((status = smb_shr_cache_addent(si)) != NERR_Success)
			return (status);

		rc = smb_dwncall_share(SMB_SHROP_ADD, si->shr_path,
		    si->shr_name);

		if (rc != 0) {
			smb_shr_cache_delent(si->shr_name);
			return ((rc == ENOENT)
			    ? NERR_UnknownDevDir : NERR_InternalError);
		}

		smb_shr_publish(si->shr_name, si->shr_container,
		    SMB_SHR_PUBLISH);
	}

	si->shr_refcnt++;
	smb_shr_set_ahcnt(si->shr_name, si->shr_refcnt);
	return (status);
}

static uint32_t
smb_shr_create_ipc(void)
{
	smb_share_t ipc;

	bzero(&ipc, sizeof (smb_share_t));
	(void) strcpy(ipc.shr_name, "IPC$");
	(void) strcpy(ipc.shr_cmnt, "Remote IPC");
	ipc.shr_flags = SMB_SHRF_TRANS;
	ipc.shr_type = STYPE_IPC;
	return (smb_shr_cache_addent(&ipc));
}

/*
 * loads the given resource
 */
static uint32_t
smb_shr_cache_loadent(sa_share_t share, sa_resource_t resource)
{
	smb_share_t si;
	uint32_t status;

	if ((status = smb_shr_sa_getent(share, resource, &si)) != NERR_Success)
		return (status);

	if ((status = smb_shr_cache_addent(&si)) == NERR_Success)
		smb_shr_publish(si.shr_name, si.shr_container, SMB_SHR_PUBLISH);

	if (status != NERR_Success) {
		syslog(LOG_ERR, "share: failed loading %s (%d)", si.shr_name,
		    status);
	}

	return (status);
}

/*
 * smb_shr_cache_loadgrp
 *
 * Helper function for smb_shr_cache_populate.
 * It attempts to load the shares contained in the given group.
 * It will check to see if "smb" protocol is enabled or
 * not on the given group. This is needed in the ZFS case where
 * the top level ZFS group won't have "smb" protocol
 * enabled but the sub-groups will.
 */
static void
smb_shr_cache_loadgrp(sa_group_t group)
{
	sa_share_t share;
	sa_resource_t resource;

	/* Don't bother if "smb" isn't set on the group */
	if (sa_get_optionset(group, SMB_PROTOCOL_NAME) == NULL)
		return;

	for (share = sa_get_share(group, NULL);
	    share != NULL; share = sa_get_next_share(share)) {
		for (resource = sa_get_share_resource(share, NULL);
		    resource != NULL;
		    resource = sa_get_next_resource(resource)) {
			(void) smb_shr_cache_loadent(share, resource);
		}
	}
}

/*
 * smb_shr_cache_freent
 *
 * Call back to free given cache entry
 */
static void
smb_shr_cache_freent(HT_ITEM *item)
{
	if (item && item->hi_data)
		free(item->hi_data);
}

/*
 * smb_shr_set_ahcnt
 *
 * sets the autohome reference count for the given share
 */
static void
smb_shr_set_ahcnt(char *sharename, int refcnt)
{
	smb_share_t *si;
	HT_ITEM *item;

	(void) rw_wrlock(&smb_shr_lock);
	item = ht_find_item(smb_shr_handle, sharename);
	if (item == NULL || item->hi_data == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return;
	}

	si = (smb_share_t *)item->hi_data;
	si->shr_refcnt = refcnt;
	(void) rw_unlock(&smb_shr_lock);
}

/*
 * smb_shr_set_oemname
 *
 * Generates the OEM name of the given share. If it's
 * shorter than 13 chars it'll be saved in si->shr_oemname.
 * Otherwise si->shr_oemname will be empty and SMB_SHRF_LONGNAME
 * will be set in si->shr_flags.
 */
static void
smb_shr_set_oemname(smb_share_t *si)
{
	unsigned int cpid = oem_get_smb_cpid();
	mts_wchar_t *unibuf;
	char *oem_name;
	int length;

	length = strlen(si->shr_name) + 1;

	oem_name = malloc(length);
	unibuf = malloc(length * sizeof (mts_wchar_t));
	if ((oem_name == NULL) || (unibuf == NULL)) {
		free(oem_name);
		free(unibuf);
		return;
	}

	(void) mts_mbstowcs(unibuf, si->shr_name, length);

	if (unicodestooems(oem_name, unibuf, length, cpid) == 0)
		(void) strcpy(oem_name, si->shr_name);

	free(unibuf);

	if (strlen(oem_name) + 1 > SMB_SHARE_OEMNAME_MAX) {
		si->shr_flags |= SMB_SHRF_LONGNAME;
		*si->shr_oemname = '\0';
	} else {
		si->shr_flags &= ~SMB_SHRF_LONGNAME;
		(void) strlcpy(si->shr_oemname, oem_name,
		    SMB_SHARE_OEMNAME_MAX);
	}

	free(oem_name);
}

/*
 * ============================================
 * Interfaces to sharemgr
 * ============================================
 */

/*
 * Stores the given share in sharemgr
 */
static uint32_t
smb_shr_sa_addent(smb_share_t *si)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_group_t group;
	sa_resource_t resource;
	boolean_t share_created = B_FALSE;
	int err;

	if ((handle = sa_init(SA_INIT_SHARE_API)) == NULL)
		return (NERR_InternalError);

	share = sa_find_share(handle, si->shr_path);
	if (share == NULL) {
		group = smb_shr_sa_getdefgrp(handle);
		if (group == NULL) {
			sa_fini(handle);
			return (NERR_InternalError);
		}

		share = sa_add_share(group, si->shr_path, SA_SHARE_PERMANENT,
		    &err);
		if (share == NULL) {
			sa_fini(handle);
			return (NERR_InternalError);
		}
		share_created = B_TRUE;
	}

	resource = sa_get_share_resource(share, si->shr_name);
	if (resource == NULL) {
		resource = sa_add_resource(share, si->shr_name,
		    SA_SHARE_PERMANENT, &err);
		if (resource == NULL)
			goto failure;
	}

	if (sa_set_resource_attr(resource, "description", si->shr_cmnt)
	    != SA_OK) {
		goto failure;
	}

	if (sa_set_resource_attr(resource, SMB_SHROPT_AD_CONTAINER,
	    si->shr_container) != SA_OK) {
		goto failure;
	}

	sa_fini(handle);
	return (NERR_Success);

failure:
	if (share_created && (share != NULL))
		(void) sa_remove_share(share);

	if (resource != NULL)
		(void) sa_remove_resource(resource);

	sa_fini(handle);
	return (NERR_InternalError);
}

static uint32_t
smb_shr_sa_getent(sa_share_t share, sa_resource_t resource, smb_share_t *si)
{
	sa_property_t prop;
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
	/* Share is read from SMF so it should be permanent */
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

	prop = (sa_property_t)sa_get_property(opts, SMB_SHROPT_AD_CONTAINER);
	if (prop != NULL) {
		if ((val = sa_get_property_attr(prop, "value")) != NULL) {
			(void) strlcpy(si->shr_container, val,
			    sizeof (si->shr_container));
			free(val);
		}
	}
	sa_free_derived_optionset(opts);

	return (NERR_Success);
}

/*
 * Removes the share from sharemgr
 */
static uint32_t
smb_shr_sa_delent(smb_share_t *si)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_resource_t resource;

	if ((handle = sa_init(SA_INIT_SHARE_API)) == NULL)
		return (NERR_InternalError);

	if ((share = sa_find_share(handle, si->shr_path)) == NULL) {
		sa_fini(handle);
		return (NERR_InternalError);
	}

	if ((resource = sa_get_share_resource(share, si->shr_name)) == NULL) {
		sa_fini(handle);
		return (NERR_InternalError);
	}

	if (sa_remove_resource(resource) != SA_OK) {
		sa_fini(handle);
		return (NERR_InternalError);
	}

	sa_fini(handle);
	return (NERR_Success);
}

/*
 * smb_shr_sa_getdefgrp
 *
 * If default group for CIFS shares (i.e. "smb") exists
 * then it will return the group handle, otherwise it will
 * create the group and return the handle.
 *
 * All the shares created by CIFS clients (this is only possible
 * via RPC) will be added to "smb" groups.
 */
static sa_group_t
smb_shr_sa_getdefgrp(sa_handle_t handle)
{
	sa_group_t group = NULL;
	int err;

	group = sa_get_group(handle, SMB_DEFAULT_SHARE_GROUP);
	if (group != NULL)
		return (group);

	group = sa_create_group(handle, SMB_DEFAULT_SHARE_GROUP, &err);
	if (group == NULL)
		return (NULL);

	if (sa_create_optionset(group, SMB_DEFAULT_SHARE_GROUP) == NULL) {
		(void) sa_remove_group(group);
		group = NULL;
	}

	return (group);
}

/*
 * ============================================
 * Share publishing functions
 * ============================================
 */

/*
 * Put the share on publish queue.
 */
static void
smb_shr_publish(const char *sharename, const char *container, char op)
{
	smb_shr_pitem_t *item = NULL;

	if (container == NULL || *container == '\0')
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

	if ((item = malloc(sizeof (smb_shr_pitem_t))) == NULL) {
		syslog(LOG_DEBUG, "failed allocating share publish item");
		return;
	}

	item->spi_op = op;
	(void) strlcpy(item->spi_name, sharename, sizeof (item->spi_name));
	(void) strlcpy(item->spi_container, container,
	    sizeof (item->spi_container));

	(void) mutex_lock(&ad_queue.spq_mtx);
	list_insert_tail(&ad_queue.spq_list, item);
	ad_queue.spq_cnt++;
	(void) cond_signal(&ad_queue.spq_cv);
	(void) mutex_unlock(&ad_queue.spq_mtx);
}

static int
smb_shr_publisher_start(void)
{
	pthread_attr_t tattr;
	int rc;

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
	rc = pthread_create(&smb_shr_publish_thr, &tattr,
	    smb_shr_publisher, 0);
	(void) pthread_attr_destroy(&tattr);

	return (rc);
}

static void
smb_shr_publisher_stop(void)
{
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
 * This functions waits to be signaled and once running
 * will publish/unpublish any items in the ad_queue
 */
/*ARGSUSED*/
static void *
smb_shr_publisher(void *arg)
{
	smb_ads_handle_t *ah;
	smb_shr_pitem_t *shr;
	list_t publist;
	char hostname[MAXHOSTNAMELEN];

	(void) mutex_lock(&ad_queue.spq_mtx);
	if (ad_queue.spq_state == SMB_SHR_PQS_READY) {
		ad_queue.spq_state = SMB_SHR_PQS_PUBLISHING;
	} else {
		(void) mutex_unlock(&ad_queue.spq_mtx);
		return (NULL);
	}
	(void) mutex_unlock(&ad_queue.spq_mtx);

	(void) smb_gethostname(hostname, MAXHOSTNAMELEN, 0);
	list_create(&publist, sizeof (smb_shr_pitem_t),
	    offsetof(smb_shr_pitem_t, spi_lnd));

	for (;;) {
		(void) mutex_lock(&ad_queue.spq_mtx);
		while ((ad_queue.spq_cnt == 0) &&
		    (ad_queue.spq_state == SMB_SHR_PQS_PUBLISHING))
			(void) cond_wait(&ad_queue.spq_cv, &ad_queue.spq_mtx);

		if (ad_queue.spq_state != SMB_SHR_PQS_PUBLISHING) {
			(void) mutex_unlock(&ad_queue.spq_mtx);
			break;
		}

		if ((ah = smb_ads_open()) == NULL) {
			(void) mutex_unlock(&ad_queue.spq_mtx);
			continue;
		}

		/*
		 * Transfer queued items to the local list so the mutex
		 * can be quickly released
		 */
		while ((shr = list_head(&ad_queue.spq_list)) != NULL) {
			list_remove(&ad_queue.spq_list, shr);
			ad_queue.spq_cnt--;
			list_insert_tail(&publist, shr);
		}
		(void) mutex_unlock(&ad_queue.spq_mtx);

		smb_shr_publisher_send(ah, &publist, hostname);
		smb_ads_close(ah);
	}

	/* Remove any leftover items from publishing queue */
	(void) mutex_lock(&ad_queue.spq_mtx);
	while ((shr = list_head(&ad_queue.spq_list)) != NULL) {
		list_remove(&ad_queue.spq_list, shr);
		free(shr);
	}
	ad_queue.spq_cnt = 0;
	list_destroy(&ad_queue.spq_list);
	ad_queue.spq_state = SMB_SHR_PQS_NOQUEUE;
	(void) mutex_unlock(&ad_queue.spq_mtx);

	list_destroy(&publist);
	return (NULL);
}

/*
 * Takes item from the given list and [un]publish them one by one.
 * In each iteration it checks the status of the publisher thread
 * and if it's been stopped then it continues to just empty the list
 */
static void
smb_shr_publisher_send(smb_ads_handle_t *ah, list_t *publist, const char *host)
{
	smb_shr_pitem_t *shr;
	boolean_t publish = B_TRUE;

	while ((shr = list_head(publist)) != NULL) {
		list_remove(publist, shr);
		if (publish) {
			(void) mutex_unlock(&ad_queue.spq_mtx);
			if (ad_queue.spq_state != SMB_SHR_PQS_PUBLISHING)
				publish = B_FALSE;
			(void) mutex_unlock(&ad_queue.spq_mtx);

			if (shr->spi_op == SMB_SHR_PUBLISH)
				(void) smb_ads_publish_share(ah, shr->spi_name,
				    NULL, shr->spi_container, host);
			else
				(void) smb_ads_remove_share(ah, shr->spi_name,
				    NULL, shr->spi_container, host);
		}
		free(shr);
	}
}
