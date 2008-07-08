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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/mnttab.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <ctype.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>

#include <libshare.h>

#include <smbsrv/lm.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/cifs.h>

#include <smbsrv/ctype.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_fsd.h>

#define	SMB_SHARE_HTAB_SZ	1024

#define	SMB_SHARE_PUBLISH	0
#define	SMB_SHARE_UNPUBLISH	1

static HT_HANDLE *smb_shr_handle = NULL;
static rwlock_t smb_shr_lock;
static pthread_t smb_shr_cache_populatethr;

static uint32_t smb_shr_cache_create(void);
static void *smb_shr_cache_populate(void *);
static int smb_shr_del_shmgr(smb_share_t *);
static int smb_shr_set_shmgr(smb_share_t *);
static uint32_t smb_shr_set_refcnt(char *, int);
static void smb_shr_set_oemname(smb_share_t *);

typedef struct smb_shr_adinfo {
	TAILQ_ENTRY(smb_shr_adinfo) next;
	char name[MAXNAMELEN];
	char container[MAXPATHLEN];
	char flag;
} smb_shr_adinfo_t;

typedef struct smb_shr_adqueue {
	int nentries;
	TAILQ_HEAD(adqueue, smb_shr_adinfo) adlist;
} smb_shr_adqueue_t;

static smb_shr_adqueue_t ad_queue;
static int publish_on = 0;

static pthread_t smb_shr_publish_thr;
static mutex_t smb_shr_publish_mtx = PTHREAD_MUTEX_INITIALIZER;
static cond_t smb_shr_publish_cv = DEFAULTCV;

static void *smb_shr_publisher(void *);
static void smb_shr_stop_publish(void);
static void smb_shr_publish(smb_share_t *, char, int);

/*
 * Start loading lmshare information from sharemanager
 * and create the cache.
 */
int
smb_shr_start(void)
{
	int rc;

	rc = pthread_create(&smb_shr_publish_thr, NULL,
	    smb_shr_publisher, 0);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to start publisher thread, "
		    "share publishing is disabled");
	}

	rc = pthread_create(&smb_shr_cache_populatethr, NULL,
	    smb_shr_cache_populate, 0);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to start share loading, "
		    "existing shares will not be available");
	}

	return (rc);
}

void
smb_shr_stop(void)
{
	smb_shr_stop_publish();
}

/*
 * lmshare_load_shares
 *
 * Helper function for smb_shr_cache_populate. It attempts to load the shares
 * contained in the group.
 */

static void
lmshare_load_shares(sa_group_t group)
{
	sa_share_t share;
	sa_resource_t resource;
	smb_share_t si;
	char *path, *rname;

	/* Don't bother if "smb" isn't set on the group */
	if (sa_get_optionset(group, SMB_PROTOCOL_NAME) == NULL)
		return;

	for (share = sa_get_share(group, NULL);
	    share != NULL; share = sa_get_next_share(share)) {
		path = sa_get_share_attr(share, "path");
		if (path == NULL) {
			continue;
		}
		for (resource = sa_get_share_resource(share, NULL);
		    resource != NULL;
		    resource = sa_get_next_resource(resource)) {
			rname = sa_get_resource_attr(resource, "name");
			if (rname == NULL) {
				syslog(LOG_ERR, "Invalid share "
				    "resource for path: %s", path);
				continue;
			}
			smb_build_lmshare_info(rname, path, resource, &si);
			sa_free_attr_string(rname);
			if (smb_shr_add(&si, 0) != NERR_Success) {
				syslog(LOG_ERR, "Failed to load "
				    "share %s", si.shr_name);
			}
		}
		/* We are done with all shares for same path */
		sa_free_attr_string(path);
	}
}

/*
 * smb_shr_cache_populate
 *
 * Load shares from sharemanager.  The args argument is currently not
 * used. The function walks through all the groups in libshare and
 * calls lmshare_load_shares for each group found. It also looks for
 * sub-groups and calls lmshare_load_shares for each sub-group found.
 */

/*ARGSUSED*/
static void *
smb_shr_cache_populate(void *args)
{
	sa_handle_t handle;
	sa_group_t group, subgroup;
	char *gstate;

	if (smb_shr_cache_create() != NERR_Success) {
		syslog(LOG_ERR, "Failed to create share hash table");
		return (NULL);
	}

	handle = sa_init(SA_INIT_SHARE_API);
	if (handle == NULL) {
		syslog(LOG_ERR, "Failed to load share "
		    "information: no libshare handle");
		return (NULL);
	}

	for (group = sa_get_group(handle, NULL);
	    group != NULL; group = sa_get_next_group(group)) {
		gstate = sa_get_group_attr(group, "state");
		if (gstate == NULL)
			continue;
		if (strcasecmp(gstate, "disabled") == 0) {
			/* Skip disabled or unknown state group */
			sa_free_attr_string(gstate);
			continue;
		}
		sa_free_attr_string(gstate);

		/*
		 * Attempt to load the shares.  lmshare_load_shares
		 * will check to see if the protocol is enabled or
		 * not. We then want to check for any sub-groups on
		 * this group. This is needed in the ZFS case where
		 * the top level ZFS group won't have "smb" protocol
		 * enabled but the sub-groups will.
		 */
		lmshare_load_shares(group);
		for (subgroup = sa_get_sub_group(group);
		    subgroup != NULL;
		    subgroup = sa_get_next_group(subgroup)) {
			lmshare_load_shares(subgroup);
		}

	}

	sa_fini(handle);

	return (NULL);
}

/*
 * lmshare_callback
 *
 * Call back to free share structures stored
 * in shares' hash table.
 */
static void
lmshare_callback(HT_ITEM *item)
{
	if (item && item->hi_data)
		free(item->hi_data);
}

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
			syslog(LOG_ERR, "smb_shr_cache_create:"
			    " unable to create share table");
			(void) rw_unlock(&smb_shr_lock);
			return (NERR_InternalError);
		}
		(void) ht_register_callback(smb_shr_handle, lmshare_callback);
		(void) rw_unlock(&smb_shr_lock);
	}

	return (NERR_Success);
}

/*
 * smb_shr_add_adminshare
 *
 * add the admin share for the volume when the share database
 * for that volume is going to be loaded.
 */
uint32_t
smb_shr_add_adminshare(char *volname, unsigned char drive)
{
	smb_share_t si;
	uint32_t rc;

	if (drive == 0)
		return (NERR_InvalidDevice);

	bzero(&si, sizeof (smb_share_t));
	(void) strcpy(si.shr_path, volname);
	si.shr_flags = SMB_SHRF_TRANS | SMB_SHRF_ADMIN;
	(void) snprintf(si.shr_name, sizeof (si.shr_name), "%c$", drive);
	rc = smb_shr_add(&si, 0);

	return (rc);
}

/*
 * smb_shr_count
 *
 * Return the total number of shares, which should be the same value
 * that would be returned from a share enum request.
 */
int
smb_shr_count(void)
{
	int n_shares;

	n_shares = ht_get_total_items(smb_shr_handle);

	/* If we don't store IPC$ in hash table we should do this */
	n_shares++;

	return (n_shares);
}

/*
 * smb_shr_iterinit
 *
 * Initialize an iterator for traversing hash table.
 * 'mode' is used for filtering shares when iterating.
 */
void
smb_shr_iterinit(smb_shriter_t *shi, uint32_t mode)
{
	bzero(shi, sizeof (smb_shriter_t));
	shi->si_mode = mode;
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
 *
 * Note that there are some special shares, i.e. IPC$, that must also
 * be processed.
 */
smb_share_t *
smb_shr_iterate(smb_shriter_t *shi)
{
	HT_ITEM *item;
	smb_share_t *si;

	if (smb_shr_handle == NULL || shi == NULL)
		return (NULL);

	if (shi->si_counter == 0) {
		/*
		 * IPC$ is always first.
		 */
		(void) strcpy(shi->si_share.shr_name, "IPC$");
		smb_shr_set_oemname(&shi->si_share);
		shi->si_share.shr_flags = SMB_SHRF_TRANS;
		shi->si_share.shr_type = (int)(STYPE_IPC | STYPE_SPECIAL);
		shi->si_counter = 1;
		return (&(shi->si_share));
	}

	if (shi->si_counter == 1) {
		if ((item = ht_findfirst(
		    smb_shr_handle, &shi->si_hashiter)) == NULL) {
			return (NULL);
		}

		si = (smb_share_t *)(item->hi_data);
		++shi->si_counter;

		if (si->shr_flags & shi->si_mode) {
			bcopy(si, &(shi->si_share), sizeof (smb_share_t));
			return (&(shi->si_share));
		}
	}

	while ((item = ht_findnext(&shi->si_hashiter)) != NULL) {
		si = (smb_share_t *)(item->hi_data);
		++shi->si_counter;
		if (si->shr_flags & shi->si_mode) {
			bcopy(si, &(shi->si_share), sizeof (smb_share_t));
			return (&(shi->si_share));
		}
	}

	return (NULL);
}

/*
 * smb_shr_add
 *
 * Add a share. This is a wrapper round smb_shr_set that checks
 * whether or not the share already exists. If the share exists, an
 * error is returned.
 *
 * Don't check smb_shr_is_dir here: it causes rootfs to recurse.
 */
uint32_t
smb_shr_add(smb_share_t *si, int doshm)
{
	uint32_t status = NERR_Success;

	if (si == 0 || smb_shr_is_valid(si->shr_name) == 0)
		return (NERR_InvalidDevice);

	(void) utf8_strlwr(si->shr_name);

	if (smb_shr_exists(si->shr_name)) {
		/*
		 * Only autohome shares can be added multiple times
		 */
		if ((si->shr_flags & SMB_SHRF_AUTOHOME) == 0)
			return (NERR_DuplicateShare);
	}

	if (si->shr_refcnt == 0) {
		status = smb_shr_set(si, doshm);
		smb_shr_publish(si, SMB_SHARE_PUBLISH, 1);
	}

	if ((si->shr_flags & SMB_SHRF_AUTOHOME) && (status == NERR_Success)) {
		si->shr_refcnt++;
		status = smb_shr_set_refcnt(si->shr_name, si->shr_refcnt);
	}

	if (status)
		return (status);

	return (smb_dwncall_share(SMB_SHROP_ADD, si->shr_path, si->shr_name));
}

/*
 * smb_shr_del
 *
 * Remove a share. Ensure that all SMB trees associated with this share
 * are disconnected. If the share does not exist, an error is returned.
 */
uint32_t
smb_shr_del(char *share_name, int doshm)
{
	smb_share_t *si;
	HT_ITEM *item;
	uint32_t status;
	char path[MAXPATHLEN];

	if (share_name)
		(void) utf8_strlwr(share_name);

	if (smb_shr_is_valid(share_name) == 0 ||
	    smb_shr_exists(share_name) == 0) {
		return (NERR_NetNameNotFound);
	}

	(void) rw_wrlock(&smb_shr_lock);
	item = ht_find_item(smb_shr_handle, share_name);

	if (item == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_ItemNotFound);
	}

	si = (smb_share_t *)item->hi_data;
	if (si == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_InternalError);
	}

	if ((si->shr_flags & SMB_SHRF_AUTOHOME) == SMB_SHRF_AUTOHOME) {
		si->shr_refcnt--;
		if (si->shr_refcnt > 0) {
			status = smb_shr_set_refcnt(si->shr_name,
			    si->shr_refcnt);
			(void) rw_unlock(&smb_shr_lock);
			return (status);
		}
	}

	if (doshm && (smb_shr_del_shmgr(si) != 0)) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_InternalError);
	}

	smb_shr_publish(si, SMB_SHARE_UNPUBLISH, 1);

	/*
	 * Copy the path before the entry is removed from the hash table
	 */

	(void) strlcpy(path, si->shr_path, MAXPATHLEN);

	/* Delete from hash table */

	(void) ht_remove_item(smb_shr_handle, share_name);
	(void) rw_unlock(&smb_shr_lock);

	return (smb_dwncall_share(SMB_SHROP_DELETE, path, share_name));
}

/*
 * smb_shr_set_refcnt
 *
 * sets the autohome shr_refcnt for a share
 */
static uint32_t
smb_shr_set_refcnt(char *share_name, int refcnt)
{
	smb_share_t *si;
	HT_ITEM *item;

	if (share_name) {
		(void) utf8_strlwr(share_name);
	}
	(void) rw_wrlock(&smb_shr_lock);
	item = ht_find_item(smb_shr_handle, share_name);
	if (item == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_ItemNotFound);
	}

	si = (smb_share_t *)item->hi_data;
	if (si == NULL) {
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_InternalError);
	}
	si->shr_refcnt = refcnt;
	(void) rw_unlock(&smb_shr_lock);
	return (NERR_Success);
}

/*
 * smb_shr_ren
 *
 * Rename a share. Check that the current name exists and the new name
 * doesn't exist. The rename is performed by deleting the current share
 * definition and creating a new share with the new name.
 */
uint32_t
smb_shr_ren(char *from_name, char *to_name, int doshm)
{
	smb_share_t si;
	uint32_t nerr;

	if (smb_shr_is_valid(from_name) == 0 ||
	    smb_shr_is_valid(to_name) == 0)
		return (NERR_InvalidDevice);

	(void) utf8_strlwr(from_name);
	(void) utf8_strlwr(to_name);

	if (smb_shr_exists(from_name) == 0)
		return (NERR_NetNameNotFound);

	if (smb_shr_exists(to_name))
		return (NERR_DuplicateShare);

	if ((nerr = smb_shr_get(from_name, &si)) != NERR_Success)
		return (nerr);

	if ((nerr = smb_shr_del(from_name, doshm)) != NERR_Success)
		return (nerr);

	(void) strlcpy(si.shr_name, to_name, MAXNAMELEN);
	return (smb_shr_add(&si, 1));
}

/*
 * smb_shr_exists
 *
 * Returns 1 if the share exists. Otherwise returns 0.
 */
int
smb_shr_exists(char *share_name)
{
	if (share_name == 0 || *share_name == 0)
		return (0);

	if (ht_find_item(smb_shr_handle, share_name) == NULL)
		return (0);
	else
		return (1);
}

/*
 * smb_shr_is_special
 *
 * Simple check to determine if share name represents a special share,
 * i.e. the last character of the name is a '$'. Returns STYPE_SPECIAL
 * if the name is special. Otherwise returns 0.
 */
int
smb_shr_is_special(char *share_name)
{
	int len;

	if (share_name == 0)
		return (0);

	if ((len = strlen(share_name)) == 0)
		return (0);

	if (share_name[len - 1] == '$')
		return (STYPE_SPECIAL);
	else
		return (0);
}


/*
 * smb_shr_is_restricted
 *
 * Check whether or not there is a restriction on a share. Restricted
 * shares are generally STYPE_SPECIAL, for example, IPC$. All the
 * administration share names are restricted: C$, D$ etc. Returns 1
 * if the share is restricted. Otherwise 0 is returned to indicate
 * that there are no restrictions.
 */
int
smb_shr_is_restricted(char *share_name)
{
	static char *restricted[] = {
		"IPC$"
	};

	int i;

	for (i = 0; i < sizeof (restricted)/sizeof (restricted[0]); i++) {
		if (strcasecmp(restricted[i], share_name) == 0)
			return (1);
	}

	if (smb_shr_is_admin(share_name))
		return (1);

	return (0);
}


/*
 * smb_shr_is_admin
 *
 * Check whether or not access to the share should be restricted to
 * administrators. This is a bit of a hack because what we're doing
 * is checking for the default admin shares: C$, D$ etc.. There are
 * other shares that have restrictions: see smb_shr_is_restricted().
 *
 * Returns 1 if the shares is an admin share. Otherwise 0 is returned
 * to indicate that there are no restrictions.
 */
int
smb_shr_is_admin(char *share_name)
{
	if (share_name == 0)
		return (0);

	if (strlen(share_name) == 2 &&
	    mts_isalpha(share_name[0]) && share_name[1] == '$') {
		return (1);
	}

	return (0);
}


/*
 * smb_shr_is_valid
 *
 * Check if any invalid char is present in share name. According to
 * MSDN article #236388: "Err Msg: The Share Name Contains Invalid
 * Characters", the list of invalid character is:
 *
 * " / \ [ ] : | < > + ; , ? * =
 *
 * Also rejects if control characters are embedded.
 *
 * If the sharename is valid, return (1). Otherwise return (0).
 */
int
smb_shr_is_valid(char *share_name)
{
	char *invalid = "\"/\\[]:|<>+;,?*=";
	char *cp;

	if (share_name == 0)
		return (0);

	if (strpbrk(share_name, invalid))
		return (0);

	for (cp = share_name; *cp != '\0'; cp++)
		if (iscntrl(*cp))
			return (0);

	return (1);
}

/*
 * smb_shr_is_dir
 *
 * Check to determine if a share object represents a directory.
 *
 * Returns 1 if the path leads to a directory. Otherwise returns 0.
 */
int
smb_shr_is_dir(char *path)
{
	struct stat stat_info;

	if (stat(path, &stat_info) == 0)
		if (S_ISDIR(stat_info.st_mode))
			return (1);

	return (0);

}

/*
 * smb_shr_get
 *
 * Load the information for the specified share into the supplied share
 * info structure. If the shared directory does not begin with a /, one
 * will be inserted as a prefix.
 */
uint32_t
smb_shr_get(char *share_name, smb_share_t *si)
{
	int i, endidx;
	int dirlen;
	HT_ITEM *item;

	(void) rw_rdlock(&smb_shr_lock);

	(void) utf8_strlwr(share_name);
	if ((item = ht_find_item(smb_shr_handle, share_name)) == NULL) {
		bzero(si, sizeof (smb_share_t));
		(void) rw_unlock(&smb_shr_lock);
		return (NERR_NetNameNotFound);
	}

	(void) memcpy(si, item->hi_data, sizeof (smb_share_t));
	(void) rw_unlock(&smb_shr_lock);

	if (si->shr_path[0] == '\0')
		return (NERR_NetNameNotFound);

	if (si->shr_path[0] != '/') {
		dirlen = strlen(si->shr_path) + 1;
		endidx = (dirlen < MAXPATHLEN-1) ?
		    dirlen : MAXPATHLEN - 2;
		for (i = endidx; i >= 0; i--)
			si->shr_path[i+1] = si->shr_path[i];
		si->shr_path[MAXPATHLEN-1] = '\0';
		si->shr_path[0] = '/';
	}

	return (NERR_Success);
}

/*
 * Remove share from sharemanager repository.
 */
static int
smb_shr_del_shmgr(smb_share_t *si)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_resource_t resource;

	handle = sa_init(SA_INIT_SHARE_API);
	if (handle == NULL) {
		syslog(LOG_ERR, "Failed to get handle to "
		    "share lib");
		return (1);
	}
	share = sa_find_share(handle, si->shr_path);
	if (share == NULL) {
		syslog(LOG_ERR, "Failed to get share to delete");
		sa_fini(handle);
		return (1);
	}
	resource = sa_get_share_resource(share, si->shr_name);
	if (resource == NULL) {
		syslog(LOG_ERR, "Failed to get share resource to delete");
		sa_fini(handle);
		return (1);
	}
	if (sa_remove_resource(resource) != SA_OK) {
		syslog(LOG_ERR, "Failed to remove resource");
		sa_fini(handle);
		return (1);
	}
	sa_fini(handle);
	return (0);
}

static int
smb_shr_set_shmgr(smb_share_t *si)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_group_t group;
	sa_resource_t resource;
	int share_created = 0;
	int err;

	/* Add share to sharemanager */
	handle = sa_init(SA_INIT_SHARE_API);
	if (handle == NULL) {
		syslog(LOG_ERR, "Failed to get handle to share lib");
		return (1);
	}
	share = sa_find_share(handle, si->shr_path);
	if (share == NULL) {
		group = smb_get_smb_share_group(handle);
		if (group == NULL) {
			sa_fini(handle);
			return (1);
		}
		share = sa_add_share(group, si->shr_path, 0, &err);
		if (share == NULL) {
			sa_fini(handle);
			return (1);
		}
		share_created = 1;
	}
	resource = sa_get_share_resource(share, si->shr_name);
	if (resource == NULL) {
		resource = sa_add_resource(share, si->shr_name,
		    SA_SHARE_PERMANENT, &err);
		if (resource == NULL) {
			goto failure;
		}
	}
	if (sa_set_resource_attr(resource,
	    "description", si->shr_cmnt) != SA_OK) {
		syslog(LOG_ERR, "Falied to set resource "
		    "description in sharemgr");
		goto failure;
	}
	if (sa_set_resource_attr(resource,
	    SMB_SHROPT_AD_CONTAINER, si->shr_container) != SA_OK) {
		syslog(LOG_ERR, "Falied to set ad-container in sharemgr");
		goto failure;
	}

	sa_fini(handle);
	return (0);
failure:
	if (share_created && (share != NULL)) {
		if (sa_remove_share(share) != SA_OK) {
			syslog(LOG_ERR, "Failed to cleanup share");
		}
	}
	if (resource != NULL) {
		if (sa_remove_resource(resource) != SA_OK) {
			syslog(LOG_ERR, "Failed to cleanup share resource");
		}
	}
	sa_fini(handle);
	return (1);
}

/*
 * smb_shr_cache_delshare
 *
 * Delete the given share only from hash table
 */
static uint32_t
smb_shr_cache_delshare(char *share_name)
{
	if (share_name == 0)
		return (NERR_NetNameNotFound);

	(void) utf8_strlwr(share_name);

	if (smb_shr_is_valid(share_name) == 0 ||
	    smb_shr_exists(share_name) == 0) {
		return (NERR_NetNameNotFound);
	}

	(void) rw_wrlock(&smb_shr_lock);
	(void) ht_remove_item(smb_shr_handle, share_name);
	(void) rw_unlock(&smb_shr_lock);

	return (NERR_Success);
}

/*
 * smb_shr_set
 *
 * Adds the specified share into the system hash table
 * and also store its info in the corresponding disk
 * structure if it is not a temporary (SMB_SHRF_TRANS) share.
 * when the first share is going to be added, create shares
 * hash table if it is not already created.
 * If the share already exists, it will be replaced. If the
 * new share directory name does not begin with a /, one will be
 * inserted as a prefix.
 */
uint32_t
smb_shr_set(smb_share_t *si, int doshm)
{
	int i, endidx;
	int dirlen;
	smb_share_t *add_si;
	int res = NERR_Success;
	smb_share_t old_si;

	if (si->shr_path[0] != '/') {
		dirlen = strlen(si->shr_path) + 1;
		endidx = (dirlen < MAXPATHLEN - 1) ?
		    dirlen : MAXPATHLEN - 2;
		for (i = endidx; i >= 0; i--)
			si->shr_path[i+1] = si->shr_path[i];
		si->shr_path[MAXPATHLEN-1] = '\0';
		si->shr_path[0] = '/';
	}

	/* XXX Do we need to translate the directory here? to real path */
	if (smb_shr_is_dir(si->shr_path) == 0)
		return (NERR_UnknownDevDir);

	/*
	 * We should allocate memory for new entry because we
	 * don't know anything about the passed pointer i.e.
	 * it maybe destroyed by caller of this function while
	 * we only store a pointer to the data in hash table.
	 * Hash table doesn't do any allocation for the data that
	 * is being added.
	 */
	add_si = malloc(sizeof (smb_share_t));
	if (add_si == NULL) {
		syslog(LOG_ERR, "LmshareSetinfo: resource shortage");
		return (NERR_NoRoom);
	}

	(void) memcpy(add_si, si, sizeof (smb_share_t));

	/*
	 * If we can't find it, use the new one to get things in sync,
	 * but if there is an existing one, that is the one to
	 * unpublish.
	 */
	if (smb_shr_get(si->shr_name, &old_si) != NERR_Success)
		(void) memcpy(&old_si, si, sizeof (smb_share_t));

	if (doshm) {
		res = smb_shr_del(si->shr_name, doshm);
		if (res != NERR_Success) {
			free(add_si);
			syslog(LOG_ERR, "LmshareSetinfo: delete failed", res);
			return (res);
		}
	} else {
		/* Unpublish old share from AD */
		if ((add_si->shr_flags & SMB_SHRF_PERM) == SMB_SHRF_PERM)
			smb_shr_publish(&old_si, SMB_SHARE_UNPUBLISH, 1);
		(void) smb_shr_cache_delshare(si->shr_name);
	}

	smb_shr_set_oemname(add_si);

	/* if it's not transient it should be permanent */
	if ((add_si->shr_flags & SMB_SHRF_TRANS) == 0)
		add_si->shr_flags |= SMB_SHRF_PERM;


	add_si->shr_type = STYPE_DISKTREE;
	add_si->shr_type |= smb_shr_is_special(add_si->shr_name);

	(void) rw_wrlock(&smb_shr_lock);
	if (ht_add_item(smb_shr_handle, add_si->shr_name, add_si) == NULL) {
		syslog(LOG_ERR, "smb_shr_set[%s]: error in adding share",
		    add_si->shr_name);
		(void) rw_unlock(&smb_shr_lock);
		free(add_si);
		return (NERR_InternalError);
	}
	(void) rw_unlock(&smb_shr_lock);

	if ((add_si->shr_flags & SMB_SHRF_PERM) == SMB_SHRF_PERM) {
		if (doshm && (smb_shr_set_shmgr(add_si) != 0)) {
			syslog(LOG_ERR, "Update share %s in sharemgr failed",
			    add_si->shr_name);
			return (NERR_InternalError);
		}
		smb_shr_publish(add_si, SMB_SHARE_PUBLISH, 1);
	}

	return (res);
}

void
smb_shr_list(int offset, smb_shrlist_t *list)
{
	smb_shriter_t iterator;
	smb_share_t *si;
	int list_idx = 0;
	int i = 0;

	bzero(list, sizeof (smb_shrlist_t));
	smb_shr_iterinit(&iterator, SMB_SHRF_ALL);

	(void) smb_shr_iterate(&iterator);	/* To skip IPC$ */

	while ((si = smb_shr_iterate(&iterator)) != NULL) {
		if (smb_shr_is_special(si->shr_name)) {
			/*
			 * Don't return restricted shares.
			 */
			if (smb_shr_is_restricted(si->shr_name))
				continue;
		}

		if (i++ < offset)
			continue;

		(void) memcpy(&list->smbshr[list_idx], si,
		    sizeof (smb_share_t));
		if (++list_idx == LMSHARES_PER_REQUEST)
			break;
	}

	list->no = list_idx;
}

/*
 * Put the share on publish queue.
 */
static void
smb_shr_publish(smb_share_t *si, char flag, int poke)
{
	smb_shr_adinfo_t *item = NULL;

	if (publish_on == 0)
		return;

	if ((si == NULL) || (si->shr_container[0] == '\0'))
		return;

	(void) mutex_lock(&smb_shr_publish_mtx);
	item = (smb_shr_adinfo_t *)malloc(sizeof (smb_shr_adinfo_t));
	if (item == NULL) {
		syslog(LOG_ERR, "Failed to allocate share publish item");
		(void) mutex_unlock(&smb_shr_publish_mtx);
		return;
	}
	item->flag = flag;
	(void) strlcpy(item->name, si->shr_name, sizeof (item->name));
	(void) strlcpy(item->container, si->shr_container,
	    sizeof (item->container));
	/*LINTED - E_CONSTANT_CONDITION*/
	TAILQ_INSERT_TAIL(&ad_queue.adlist, item, next);
	ad_queue.nentries++;
	if (poke)
		(void) cond_signal(&smb_shr_publish_cv);
	(void) mutex_unlock(&smb_shr_publish_mtx);
}

void
smb_shr_stop_publish()
{
	(void) mutex_lock(&smb_shr_publish_mtx);
	publish_on = 0;
	(void) cond_signal(&smb_shr_publish_cv);
	(void) mutex_unlock(&smb_shr_publish_mtx);
}

/*
 * This functions waits to be signaled and once running
 * will publish/unpublish any items on list.
 * smb_shr_stop_publish when called will exit this thread.
 */
/*ARGSUSED*/
static void *
smb_shr_publisher(void *arg)
{
	smb_ads_handle_t *ah;
	smb_shr_adinfo_t *item;
	char hostname[MAXHOSTNAMELEN];
	char name[MAXNAMELEN];
	char container[MAXPATHLEN];
	char flag;

	/*LINTED - E_CONSTANT_CONDITION*/
	TAILQ_INIT(&ad_queue.adlist);
	ad_queue.nentries = 0;
	publish_on = 1;
	hostname[0] = '\0';

	for (;;) {
		(void) cond_wait(&smb_shr_publish_cv,
		    &smb_shr_publish_mtx);

		if (hostname[0] == '\0') {
			if (smb_gethostname(hostname, MAXHOSTNAMELEN, 0) != 0)
				continue;
		}

		if (publish_on == 0) {
			syslog(LOG_DEBUG, "lmshare: publisher exit");
			if (ad_queue.nentries == 0) {
				(void) mutex_unlock(&smb_shr_publish_mtx);
				break;
			}
			for (item = TAILQ_FIRST(&ad_queue.adlist); item;
			    item = TAILQ_FIRST(&ad_queue.adlist)) {
				/*LINTED - E_CONSTANT_CONDITION*/
				TAILQ_REMOVE(&ad_queue.adlist, item, next);
				(void) free(item);
			}
			ad_queue.nentries = 0;
			(void) mutex_unlock(&smb_shr_publish_mtx);
			break;
		}
		if (ad_queue.nentries == 0)
			continue;
		ah = smb_ads_open();
		if (ah == NULL) {
			/* We mostly have no AD config so just clear the list */
			for (item = TAILQ_FIRST(&ad_queue.adlist); item;
			    item = TAILQ_FIRST(&ad_queue.adlist)) {
				/*LINTED - E_CONSTANT_CONDITION*/
				TAILQ_REMOVE(&ad_queue.adlist, item, next);
				(void) free(item);
			}
			ad_queue.nentries = 0;
			continue;
		}
		TAILQ_FOREACH(item, &ad_queue.adlist, next) {
			(void) strlcpy(name, item->name, sizeof (name));
			(void) strlcpy(container, item->container,
			    sizeof (container));
			flag = item->flag;

			if (flag == SMB_SHARE_UNPUBLISH)
				(void) smb_ads_remove_share(ah, name, NULL,
				    container, hostname);
			else
				(void) smb_ads_publish_share(ah, name, NULL,
				    container, hostname);
		}
		for (item = TAILQ_FIRST(&ad_queue.adlist); item;
		    item = TAILQ_FIRST(&ad_queue.adlist)) {
			/*LINTED - E_CONSTANT_CONDITION*/
			TAILQ_REMOVE(&ad_queue.adlist, item, next);
			(void) free(item);
		}
		ad_queue.nentries = 0;
		if (ah != NULL) {
			smb_ads_close(ah);
			ah = NULL;
		}
	}

	syslog(LOG_DEBUG, "lmshare: Stopping publisher");
	return (NULL);
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
