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
#include <smbsrv/lmshare.h>
#include <smbsrv/cifs.h>

#include <smbsrv/ctype.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_fsd.h>

#define	LMSHR_HASHTAB_SZ	1024

static HT_HANDLE *lmshare_handle = NULL;

static rwlock_t lmshare_lock;
static pthread_t lmshare_load_thread;
static void *lmshare_load(void *);
static DWORD lmshare_create_table();
static int lmshare_delete_shmgr(struct lmshare_info *);
static int lmshare_setinfo_shmgr(struct lmshare_info *);
static DWORD lmshare_set_refcnt(char *share_name, int refcnt);

typedef struct lmshare_ad_item {
	TAILQ_ENTRY(lmshare_ad_item) next;
	char name[MAXNAMELEN];
	char container[MAXPATHLEN];
	char flag;
} lmshare_ad_item_t;

typedef struct lmshare_ad_queue {
	int nentries;
	TAILQ_HEAD(adqueue, lmshare_ad_item) adlist;
} lmshare_ad_queue_t;

static lmshare_ad_queue_t ad_queue;
static int publish_on = 0;

static pthread_t lmshare_publish_thread;
static mutex_t lmshare_publish_mutex = PTHREAD_MUTEX_INITIALIZER;
static cond_t lmshare_publish_cv = DEFAULTCV;

static void *lmshare_publisher(void *);
static void lmshare_stop_publish();

/*
 * Start loading lmshare information from sharemanager
 * and create the cache.
 */
int
lmshare_start()
{
	int rc;

	rc = pthread_create(&lmshare_publish_thread, NULL,
	    lmshare_publisher, 0);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to start publisher thread, "
		    "share publishing is disabled");
	}

	rc = pthread_create(&lmshare_load_thread, NULL,
	    lmshare_load, 0);
	if (rc != 0) {
		syslog(LOG_ERR, "Failed to start share loading, "
		    "existing shares will not be available");
	}

	return (rc);
}

void
lmshare_stop()
{
	lmshare_stop_publish();
}

/*
 * lmshare_load_shares
 *
 * Helper function for lmshare_load. It attempts to load the shares
 * contained in the group.
 */

static void
lmshare_load_shares(sa_group_t group)
{
	sa_share_t share;
	sa_resource_t resource;
	sa_optionset_t opts;
	lmshare_info_t si;
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
			opts = sa_get_derived_optionset(resource,
			    SMB_PROTOCOL_NAME, 1);
			smb_build_lmshare_info(rname, path, opts, &si);
			sa_free_derived_optionset(opts);
			sa_free_attr_string(rname);
			if (lmshare_add(&si, 0) != NERR_Success) {
				syslog(LOG_ERR, "Failed to load "
				    "share %s", si.share_name);
			}
		}
		/* We are done with all shares for same path */
		sa_free_attr_string(path);
	}
}

/*
 * lmshare_load
 *
 * Load shares from sharemanager.  The args argument is currently not
 * used. The function walks through all the groups in libshare and
 * calls lmshare_load_shares for each group found. It also looks for
 * sub-groups and calls lmshare_load_shares for each sub-group found.
 */

/*ARGSUSED*/
static void *
lmshare_load(void *args)
{
	sa_handle_t handle;
	sa_group_t group, subgroup;
	char *gstate;

	if (lmshare_create_table() != NERR_Success) {
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
		(void) free(item->hi_data);
}

/*
 * lmshare_create_table
 *
 * Create the share hash table.
 */
static DWORD
lmshare_create_table(void)
{
	if (lmshare_handle == NULL) {
		(void) rwlock_init(&lmshare_lock, USYNC_THREAD, 0);
		(void) rw_wrlock(&lmshare_lock);

		lmshare_handle = ht_create_table(LMSHR_HASHTAB_SZ,
		    MAXNAMELEN, 0);
		if (lmshare_handle == NULL) {
			syslog(LOG_ERR, "lmshare_create_table:"
			    " unable to create share table");
			(void) rw_unlock(&lmshare_lock);
			return (NERR_InternalError);
		}
		(void) ht_register_callback(lmshare_handle, lmshare_callback);
		(void) rw_unlock(&lmshare_lock);
	}

	return (NERR_Success);
}

/*
 * lmshare_add_adminshare
 *
 * add the admin share for the volume when the share database
 * for that volume is going to be loaded.
 */
DWORD
lmshare_add_adminshare(char *volname, unsigned char drive)
{
	struct lmshare_info si;
	DWORD rc;

	if (drive == 0)
		return (NERR_InvalidDevice);

	bzero(&si, sizeof (lmshare_info_t));
	(void) strcpy(si.directory, volname);
	si.mode = LMSHRM_TRANS;
	(void) snprintf(si.share_name, sizeof (si.share_name), "%c$", drive);
	rc = lmshare_add(&si, 0);

	return (rc);
}

/*
 * lmshare_num_shares
 *
 * Return the total number of shares, which should be the same value
 * that would be returned from a share enum request.
 */
int
lmshare_num_shares(void)
{
	int n_shares;

	n_shares = ht_get_total_items(lmshare_handle);

	/* If we don't store IPC$ in hash table we should do this */
	n_shares++;

	return (n_shares);
}

/*
 * lmshare_open_iterator
 *
 * Create and initialize an iterator for traversing hash table.
 * It gets a mode that can be LMSHR_IM_ALL to iterate through all
 * the shares stored in table or LMSHR_IM_PRES to iterate through
 * only presentable shares.
 *
 * It also accepts a local IP address. This is used in dual head
 * systems to only return the shares that belong to the head which
 * is specified by the 'ipaddr'. If ipaddr is 0 it'll return shares
 * of both heads.
 *
 * On success return pointer to the new iterator.
 * On failure return (NULL).
 */
lmshare_iterator_t *
lmshare_open_iterator(int mode)
{
	lmshare_iterator_t *shi;
	int sz = sizeof (lmshare_iterator_t) + sizeof (HT_ITERATOR);

	shi = malloc(sz);
	if (shi != NULL) {
		bzero(shi, sz);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		shi->iterator = (HT_ITERATOR *)
		    ((char *)shi + sizeof (lmshare_iterator_t));
		shi->mode = mode;
	} else {
		syslog(LOG_DEBUG, "Failed to create share iterator handle");
	}
	return (shi);
}

/*
 * lmshare_close_iterator
 *
 * Free memory allocated by the given iterator.
 */
void
lmshare_close_iterator(lmshare_iterator_t *shi)
{
	(void) free(shi);
}

/*
 * lmshare_iterate
 *
 * Iterate on the shares in the hash table. The iterator must be opened
 * before the first iteration. On subsequent calls, the iterator must be
 * passed unchanged.
 *
 * Returns NULL on failure or when all shares are visited, otherwise
 * returns information of visited share.
 *
 * Note that there are some special shares, i.e. IPC$, that must also
 * be processed.
 */
lmshare_info_t *
lmshare_iterate(lmshare_iterator_t *shi)
{
	HT_ITEM *item;
	lmshare_info_t *si;

	if (lmshare_handle == NULL || shi == NULL)
		return (NULL);

	if (shi->iteration == 0) {
		/*
		 * IPC$ is always first.
		 */
		(void) strcpy(shi->si.share_name, "IPC$");
		shi->si.mode = LMSHRM_TRANS;
		shi->si.stype = (int)(STYPE_IPC | STYPE_SPECIAL);
		shi->iteration = 1;
		return (&(shi->si));
	}

	if (shi->iteration == 1) {
		if ((item = ht_findfirst(
		    lmshare_handle, shi->iterator)) == NULL) {
			return (NULL);
		}

		si = (lmshare_info_t *)(item->hi_data);
		++shi->iteration;

		if (si->mode & shi->mode) {
			(void) memcpy(&(shi->si), si,
			    sizeof (lmshare_info_t));
			return (&(shi->si));
		}
	}

	while ((item = ht_findnext(shi->iterator)) != NULL) {
		si = (lmshare_info_t *)(item->hi_data);
		++shi->iteration;
		if (si->mode & shi->mode) {
			(void) memcpy(&(shi->si), si, sizeof (lmshare_info_t));

			return (&(shi->si));
		}
	}

	return (NULL);
}

/*
 * lmshare_add
 *
 * Add a share. This is a wrapper round lmshare_setinfo that checks
 * whether or not the share already exists. If the share exists, an
 * error is returned.
 *
 * Don't check lmshare_is_dir here: it causes rootfs to recurse.
 */
DWORD
lmshare_add(lmshare_info_t *si, int doshm)
{
	DWORD status = NERR_Success;

	if (si == 0 || lmshare_is_valid(si->share_name) == 0)
		return (NERR_InvalidDevice);

	(void) utf8_strlwr(si->share_name);

	if (lmshare_exists(si->share_name)) {
		if ((si->mode & LMSHRM_TRANS) == 0)
			return (NERR_DuplicateShare);
	}

	if (si->refcnt == 0) {
		status = lmshare_setinfo(si, doshm);
		lmshare_do_publish(si, LMSHR_PUBLISH, 1);
	}

	if ((si->mode & LMSHRM_TRANS) && (status == NERR_Success)) {
		si->refcnt++;
		status = lmshare_set_refcnt(si->share_name, si->refcnt);
	}

	if (status)
		return (status);

	return (smb_dwncall_share(LMSHR_ADD, si->directory, si->share_name));
}

/*
 * lmshare_delete
 *
 * Remove a share. Ensure that all SMB trees associated with this share
 * are disconnected. If the share does not exist, an error is returned.
 */
DWORD
lmshare_delete(char *share_name, int doshm)
{
	lmshare_info_t *si;
	HT_ITEM *item;
	DWORD status;
	char path[MAXPATHLEN];

	if (share_name)
		(void) utf8_strlwr(share_name);

	if (lmshare_is_valid(share_name) == 0 ||
	    lmshare_exists(share_name) == 0) {
		return (NERR_NetNameNotFound);
	}

	(void) rw_wrlock(&lmshare_lock);
	item = ht_find_item(lmshare_handle, share_name);

	if (item == NULL) {
		(void) rw_unlock(&lmshare_lock);
		return (NERR_ItemNotFound);
	}

	si = (lmshare_info_t *)item->hi_data;
	if (si == NULL) {
		(void) rw_unlock(&lmshare_lock);
		return (NERR_InternalError);
	}

	if ((si->mode & LMSHRM_TRANS) != 0) {
		si->refcnt--;
		if (si->refcnt > 0) {
			status = lmshare_set_refcnt(si->share_name, si->refcnt);
			(void) rw_unlock(&lmshare_lock);
			return (status);
		}
	}

	if (doshm && (lmshare_delete_shmgr(si) != 0)) {
		(void) rw_unlock(&lmshare_lock);
		return (NERR_InternalError);
	}

	lmshare_do_publish(si, LMSHR_UNPUBLISH, 1);

	/*
	 * Copy the path before the entry is removed from the hash table
	 */

	(void) strlcpy(path, si->directory, MAXPATHLEN);

	/* Delete from hash table */

	(void) ht_remove_item(lmshare_handle, share_name);
	(void) rw_unlock(&lmshare_lock);

	return (smb_dwncall_share(LMSHR_DELETE, path, share_name));
}

/*
 * lmshare_set_refcnt
 *
 * sets the autohome refcnt for a share
 */
static DWORD
lmshare_set_refcnt(char *share_name, int refcnt)
{
	lmshare_info_t *si;
	HT_ITEM *item;

	if (share_name) {
		(void) utf8_strlwr(share_name);
	}
	(void) rw_wrlock(&lmshare_lock);
	item = ht_find_item(lmshare_handle, share_name);
	if (item == NULL) {
		(void) rw_unlock(&lmshare_lock);
		return (NERR_ItemNotFound);
	}

	si = (lmshare_info_t *)item->hi_data;
	if (si == NULL) {
		(void) rw_unlock(&lmshare_lock);
		return (NERR_InternalError);
	}
	si->refcnt = refcnt;
	(void) rw_unlock(&lmshare_lock);
	return (NERR_Success);
}

/*
 * lmshare_rename
 *
 * Rename a share. Check that the current name exists and the new name
 * doesn't exist. The rename is performed by deleting the current share
 * definition and creating a new share with the new name.
 */
DWORD
lmshare_rename(char *from_name, char *to_name, int doshm)
{
	struct lmshare_info si;
	DWORD nerr;

	if (lmshare_is_valid(from_name) == 0 ||
	    lmshare_is_valid(to_name) == 0)
		return (NERR_InvalidDevice);

	(void) utf8_strlwr(from_name);
	(void) utf8_strlwr(to_name);

	if (lmshare_exists(from_name) == 0)
		return (NERR_NetNameNotFound);

	if (lmshare_exists(to_name))
		return (NERR_DuplicateShare);

	if ((nerr = lmshare_getinfo(from_name, &si)) != NERR_Success)
		return (nerr);

	if ((nerr = lmshare_delete(from_name, doshm)) != NERR_Success)
		return (nerr);

	(void) strlcpy(si.share_name, to_name, MAXNAMELEN);
	return (lmshare_add(&si, 1));
}

/*
 * lmshare_exists
 *
 * Returns 1 if the share exists. Otherwise returns 0.
 */
int
lmshare_exists(char *share_name)
{
	if (share_name == 0 || *share_name == 0)
		return (0);

	if (ht_find_item(lmshare_handle, share_name) == NULL)
		return (0);
	else
		return (1);
}

/*
 * lmshare_is_special
 *
 * Simple check to determine if share name represents a special share,
 * i.e. the last character of the name is a '$'. Returns STYPE_SPECIAL
 * if the name is special. Otherwise returns 0.
 */
int
lmshare_is_special(char *share_name)
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
 * lmshare_is_restricted
 *
 * Check whether or not there is a restriction on a share. Restricted
 * shares are generally STYPE_SPECIAL, for example, IPC$. All the
 * administration share names are restricted: C$, D$ etc. Returns 1
 * if the share is restricted. Otherwise 0 is returned to indicate
 * that there are no restrictions.
 */
int
lmshare_is_restricted(char *share_name)
{
	static char *restricted[] = {
		"IPC$"
	};

	int i;

	for (i = 0; i < sizeof (restricted)/sizeof (restricted[0]); i++) {
		if (strcasecmp(restricted[i], share_name) == 0)
			return (1);
	}

	if (lmshare_is_admin(share_name))
		return (1);

	return (0);
}


/*
 * lmshare_is_admin
 *
 * Check whether or not access to the share should be restricted to
 * administrators. This is a bit of a hack because what we're doing
 * is checking for the default admin shares: C$, D$ etc.. There are
 * other shares that have restrictions: see lmshare_is_restricted().
 *
 * Returns 1 if the shares is an admin share. Otherwise 0 is returned
 * to indicate that there are no restrictions.
 */
int
lmshare_is_admin(char *share_name)
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
 * lmshare_is_valid
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
lmshare_is_valid(char *share_name)
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
 * lmshare_is_dir
 *
 * Check to determine if a share object represents a directory.
 *
 * Returns 1 if the path leads to a directory. Otherwise returns 0.
 */
int
lmshare_is_dir(char *path)
{
	struct stat stat_info;

	if (stat(path, &stat_info) == 0)
		if (S_ISDIR(stat_info.st_mode))
			return (1);

	return (0);

}

/*
 * lmshare_getinfo
 *
 * Load the information for the specified share into the supplied share
 * info structure. If the shared directory does not begin with a /, one
 * will be inserted as a prefix.
 */
DWORD
lmshare_getinfo(char *share_name, struct lmshare_info *si)
{
	int i, endidx;
	int dirlen;
	HT_ITEM *item;

	(void) rw_rdlock(&lmshare_lock);

	(void) utf8_strlwr(share_name);
	if ((item = ht_find_item(lmshare_handle, share_name)) == NULL) {
		bzero(si, sizeof (lmshare_info_t));
		(void) rw_unlock(&lmshare_lock);
		return (NERR_NetNameNotFound);
	}

	(void) memcpy(si, item->hi_data, sizeof (lmshare_info_t));
	(void) rw_unlock(&lmshare_lock);

	if (si->directory[0] == '\0')
		return (NERR_NetNameNotFound);

	if (si->directory[0] != '/') {
		dirlen = strlen(si->directory) + 1;
		endidx = (dirlen < MAXPATHLEN-1) ?
		    dirlen : MAXPATHLEN - 2;
		for (i = endidx; i >= 0; i--)
			si->directory[i+1] = si->directory[i];
		si->directory[MAXPATHLEN-1] = '\0';
		si->directory[0] = '/';
	}

	return (NERR_Success);
}

/*
 * Remove share from sharemanager repository.
 */
static int
lmshare_delete_shmgr(struct lmshare_info *si)
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
	share = sa_find_share(handle, si->directory);
	if (share == NULL) {
		syslog(LOG_ERR, "Failed to get share to delete");
		sa_fini(handle);
		return (1);
	}
	resource = sa_get_share_resource(share, si->share_name);
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
lmshare_setinfo_shmgr(struct lmshare_info *si)
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
	share = sa_find_share(handle, si->directory);
	if (share == NULL) {
		group = smb_get_smb_share_group(handle);
		if (group == NULL) {
			sa_fini(handle);
			return (1);
		}
		share = sa_add_share(group, si->directory, 0, &err);
		if (share == NULL) {
			sa_fini(handle);
			return (1);
		}
		share_created = 1;
	}
	resource = sa_get_share_resource(share, si->share_name);
	if (resource == NULL) {
		resource = sa_add_resource(share, si->share_name,
		    SA_SHARE_PERMANENT, &err);
		if (resource == NULL) {
			goto failure;
		}
	}
	if (sa_set_resource_attr(resource,
	    "description", si->comment) != SA_OK) {
		syslog(LOG_ERR, "Falied to set resource "
		    "description in sharemgr");
		goto failure;
	}
	if (sa_set_resource_attr(resource,
	    SHOPT_AD_CONTAINER, si->container) != SA_OK) {
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
 * del_fromhash
 *
 * Delete the given share only from hash table
 */
static DWORD
del_fromhash(char *share_name)
{
	if (share_name == 0)
		return (NERR_NetNameNotFound);

	(void) utf8_strlwr(share_name);

	if (lmshare_is_valid(share_name) == 0 ||
	    lmshare_exists(share_name) == 0) {
		return (NERR_NetNameNotFound);
	}

	(void) rw_wrlock(&lmshare_lock);
	(void) ht_remove_item(lmshare_handle, share_name);
	(void) rw_unlock(&lmshare_lock);

	return (NERR_Success);
}

/*
 * lmshare_setinfo
 *
 * Adds the specified share into the system hash table
 * and also store its info in the corresponding disk
 * structure if it is not a temporary (LMSHRM_TRANS) share.
 * when the first share is going to be added, create shares
 * hash table if it is not already created.
 * If the share already exists, it will be replaced. If the
 * new share directory name does not begin with a /, one will be
 * inserted as a prefix.
 */
DWORD
lmshare_setinfo(lmshare_info_t *si, int doshm)
{
	int i, endidx;
	int dirlen;
	lmshare_info_t *add_si;
	int res = NERR_Success;
	lmshare_info_t old_si;

	if (si->directory[0] != '/') {
		dirlen = strlen(si->directory) + 1;
		endidx = (dirlen < MAXPATHLEN - 1) ?
		    dirlen : MAXPATHLEN - 2;
		for (i = endidx; i >= 0; i--)
			si->directory[i+1] = si->directory[i];
		si->directory[MAXPATHLEN-1] = '\0';
		si->directory[0] = '/';
	}

	/* XXX Do we need to translate the directory here? to real path */
	if (lmshare_is_dir(si->directory) == 0)
		return (NERR_UnknownDevDir);

	/*
	 * We should allocate memory for new entry because we
	 * don't know anything about the passed pointer i.e.
	 * it maybe destroyed by caller of this function while
	 * we only store a pointer to the data in hash table.
	 * Hash table doesn't do any allocation for the data that
	 * is being added.
	 */
	add_si = malloc(sizeof (lmshare_info_t));
	if (add_si == NULL) {
		syslog(LOG_ERR, "LmshareSetinfo: resource shortage");
		return (NERR_NoRoom);
	}

	(void) memcpy(add_si, si, sizeof (lmshare_info_t));

	/*
	 * If we can't find it, use the new one to get things in sync,
	 * but if there is an existing one, that is the one to
	 * unpublish.
	 */
	if (lmshare_getinfo(si->share_name, &old_si) != NERR_Success)
		(void) memcpy(&old_si, si, sizeof (lmshare_info_t));

	if (doshm) {
		res = lmshare_delete(si->share_name, doshm);
		if (res != NERR_Success) {
			free(add_si);
			syslog(LOG_ERR, "LmshareSetinfo: delete failed", res);
			return (res);
		}
	} else {
		/* Unpublish old share from AD */
		if ((si->mode & LMSHRM_TRANS) == 0) {
			lmshare_do_publish(&old_si, LMSHR_UNPUBLISH, 1);
		}
		(void) del_fromhash(si->share_name);
	}
	/* if it's not transient it should be permanent */
	if ((add_si->mode & LMSHRM_TRANS) == 0)
		add_si->mode |= LMSHRM_PERM;


	add_si->stype = STYPE_DISKTREE;
	add_si->stype |= lmshare_is_special(add_si->share_name);

	(void) rw_wrlock(&lmshare_lock);
	if (ht_add_item(lmshare_handle, add_si->share_name, add_si) == NULL) {
		syslog(LOG_ERR, "lmshare_setinfo[%s]: error in adding share",
		    add_si->share_name);
		(void) rw_unlock(&lmshare_lock);
		free(add_si);
		return (NERR_InternalError);
	}
	(void) rw_unlock(&lmshare_lock);

	if ((add_si->mode & LMSHRM_TRANS) == 0) {
		if (doshm && (lmshare_setinfo_shmgr(add_si) != 0)) {
			syslog(LOG_ERR, "Update share %s in sharemgr failed",
			    add_si->share_name);
			return (NERR_InternalError);
		}
		lmshare_do_publish(add_si, LMSHR_PUBLISH, 1);
	}

	return (res);
}

DWORD
lmshare_list(int offset, lmshare_list_t *list)
{
	lmshare_iterator_t *iterator;
	lmshare_info_t *si;
	int list_idx = 0;
	int i = 0;

	bzero(list, sizeof (lmshare_list_t));
	if ((iterator = lmshare_open_iterator(LMSHRM_ALL)) == NULL)
		return (NERR_InternalError);

	(void) lmshare_iterate(iterator);	/* To skip IPC$ */

	while ((si = lmshare_iterate(iterator)) != NULL) {
		if (lmshare_is_special(si->share_name)) {
			/*
			 * Don't return restricted shares.
			 */
			if (lmshare_is_restricted(si->share_name))
				continue;
		}

		if (i++ < offset)
			continue;

		(void) memcpy(&list->smbshr[list_idx], si,
		    sizeof (lmshare_info_t));
		if (++list_idx == LMSHARES_PER_REQUEST)
			break;
	}
	lmshare_close_iterator(iterator);

	list->no = list_idx;

	return (NERR_Success);
}

/*
 * Put the share on publish queue.
 */
void
lmshare_do_publish(lmshare_info_t *si, char flag, int poke)
{
	lmshare_ad_item_t *item = NULL;

	if (publish_on == 0)
		return;
	if ((si == NULL) || (si->container[0] == '\0'))
		return;
	(void) mutex_lock(&lmshare_publish_mutex);
	item = (lmshare_ad_item_t *)malloc(sizeof (lmshare_ad_item_t));
	if (item == NULL) {
		syslog(LOG_ERR, "Failed to allocate share publish item");
		(void) mutex_unlock(&lmshare_publish_mutex);
		return;
	}
	item->flag = flag;
	(void) strlcpy(item->name, si->share_name, sizeof (item->name));
	(void) strlcpy(item->container, si->container,
	    sizeof (item->container));
	/*LINTED - E_CONSTANT_CONDITION*/
	TAILQ_INSERT_TAIL(&ad_queue.adlist, item, next);
	ad_queue.nentries++;
	if (poke)
		(void) cond_signal(&lmshare_publish_cv);
	(void) mutex_unlock(&lmshare_publish_mutex);
}

void
lmshare_stop_publish()
{
	(void) mutex_lock(&lmshare_publish_mutex);
	publish_on = 0;
	(void) cond_signal(&lmshare_publish_cv);
	(void) mutex_unlock(&lmshare_publish_mutex);
}

/*
 * This functions waits to be signaled and once running
 * will publish/unpublish any items on list.
 * lmshare_stop_publish when called will exit this thread.
 */
/*ARGSUSED*/
static void *
lmshare_publisher(void *arg)
{
	ADS_HANDLE *ah;
	lmshare_ad_item_t *item;
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
		(void) cond_wait(&lmshare_publish_cv,
		    &lmshare_publish_mutex);

		if (hostname[0] == '\0') {
			if (smb_gethostname(hostname, MAXHOSTNAMELEN, 0) != 0)
				continue;
		}

		if (publish_on == 0) {
			syslog(LOG_DEBUG, "lmshare: publisher exit");
			if (ad_queue.nentries == 0) {
				(void) mutex_unlock(&lmshare_publish_mutex);
				break;
			}
			for (item = TAILQ_FIRST(&ad_queue.adlist); item;
			    item = TAILQ_FIRST(&ad_queue.adlist)) {
				/*LINTED - E_CONSTANT_CONDITION*/
				TAILQ_REMOVE(&ad_queue.adlist, item, next);
				(void) free(item);
			}
			ad_queue.nentries = 0;
			(void) mutex_unlock(&lmshare_publish_mutex);
			break;
		}
		if (ad_queue.nentries == 0)
			continue;
		ah = ads_open();
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

			if (flag == LMSHR_UNPUBLISH)
				(void) ads_remove_share(ah, name, NULL,
				    container, hostname);
			else
				(void) ads_publish_share(ah, name, NULL,
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
			ads_close(ah);
			ah = NULL;
		}
	}

	syslog(LOG_DEBUG, "lmshare: Stopping publisher");
	return (NULL);
}

/*
 * lmshare_get_realpath
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
 *            the lmshare_info_t structure of the share.
 * maxlen   - maximum length fo the realpath buffer
 *
 * Return LAN Manager network error code.
 */
/*ARGSUSED*/
DWORD
lmshare_get_realpath(const char *clipath, char *realpath, int maxlen)
{
	/* XXX do this translation */
	return (NERR_Success);
}
