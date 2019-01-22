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

/*
 * Creates and maintains a cache of mount points.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <thread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mnttab.h>
#include <sys/swap.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/*
 * The list of mount point entries in /etc/mnttab
 */

struct mntpnt_list {
	struct mntpnt_list	*next;
	char			*special;
	char			*mountp;
};

static struct mntpnt_list	*mntpoint_listp = NULL;
static rwlock_t			mntpoint_lock = DEFAULTRWLOCK;
static int			initialized = 0;
static mutex_t			init_lock = DEFAULTMUTEX;

static boolean_t	diff_mnttab(int send_event, struct mntpnt_list *firstp,
			    struct mntpnt_list *secondp);
static void		free_mnttab(struct mntpnt_list *listp);
static boolean_t	in_list(struct mntpnt_list *elementp,
			    struct mntpnt_list *listp);
static int		load_mnttab(int send_event);
static void		watch_mnttab();

/*
 * Search the list of devices from /etc/mnttab to find the mount point
 * for the specified device.
 */
int
inuse_mnt(char *slice, nvlist_t *attrs, int *errp)
{
	struct mntpnt_list	*listp;
	int			found = 0;

	*errp = 0;
	if (slice == NULL) {
	    return (found);
	}

	(void) mutex_lock(&init_lock);
	if (!initialized) {
	    thread_t	mnttab_thread;

	    /* load the mntpnt cache */
	    *errp = load_mnttab(B_FALSE);

	    if (*errp == 0) {
		/* start a thread to monitor the mnttab */
		*errp = thr_create(NULL, 0, (void *(*)(void *))watch_mnttab,
		    NULL, THR_NEW_LWP | THR_DAEMON, &mnttab_thread);
	    }

	    if (*errp == 0) {
		initialized = 1;
	    }
	}
	(void) mutex_unlock(&init_lock);

	(void) rw_rdlock(&mntpoint_lock);
	listp = mntpoint_listp;
	while (listp != NULL) {
	    if (libdiskmgt_str_eq(slice, listp->special)) {
		libdiskmgt_add_str(attrs, DM_USED_BY, DM_USE_MOUNT, errp);
		libdiskmgt_add_str(attrs, DM_USED_NAME, listp->mountp, errp);
		found = 1;
		break;
	    }
	    listp = listp->next;
	}
	(void) rw_unlock(&mntpoint_lock);

	return (found);
}

/*
 * Return true if the lists are different.  Send an event for each different
 * device.
 */
static boolean_t
diff_mnttab(int send_event, struct mntpnt_list *firstp,
    struct mntpnt_list *secondp)
{
	boolean_t		different = B_FALSE;
	struct mntpnt_list	*listp;

	listp = firstp;
	while (listp != NULL) {
	    if (! in_list(listp, secondp)) {
		/* not in new list, so was mounted and now unmounted */
		if (send_event) {
		    events_new_slice_event(listp->special, DM_EV_TCHANGE);
		}
		different = B_TRUE;
	    }
	    listp = listp->next;
	}

	listp = secondp;
	while (listp != NULL) {
	    if (! in_list(listp, firstp)) {
		/* not in orig list, so this is a new mount */
		if (send_event) {
		    events_new_slice_event(listp->special, DM_EV_TCHANGE);
		}
		different = B_TRUE;
	    }
	    listp = listp->next;
	}

	return (different);
}

/*
 * free_mnttab()
 *
 * Free the list of metadevices from /etc/mnttab.
 */
static void
free_mnttab(struct mntpnt_list	*listp) {

	struct mntpnt_list	*nextp;

	while (listp != NULL) {
		nextp = listp->next;
		free((void *)listp->special);
		free((void *)listp->mountp);
		free((void *)listp);
		listp = nextp;
	}
}

/*
 * Return true if the element is in the list.
 */
static boolean_t
in_list(struct mntpnt_list *elementp, struct mntpnt_list *listp)
{
	while (listp != NULL) {
	    if (libdiskmgt_str_eq(elementp->special, listp->special) &&
		libdiskmgt_str_eq(elementp->mountp, listp->mountp)) {
		return (B_TRUE);
	    }
	    listp = listp->next;
	}

	return (B_FALSE);
}

/*
 * load_mnttab()
 *
 * Create a list of devices from /etc/mnttab and swap.
 * return 1 if the list has changed, 0 if the list is still the same
 */
static int
load_mnttab(int send_event)
{

	struct mntpnt_list	*currp;
	FILE			*fp;
	struct mntpnt_list	*headp;
	int			num;
	struct mntpnt_list	*prevp;
	struct swaptable	*st;
	struct swapent		*swapent;
	int			err;
	int			i;

	headp = NULL;
	prevp = NULL;

	/* get the mnttab entries */
	if ((fp = fopen("/etc/mnttab", "r")) != NULL) {

		struct mnttab	entry;

		while (getmntent(fp, &entry) == 0) {

			/*
			 * Ignore entries that are incomplete or that are not
			 * devices (skips network mounts, automounter entries,
			 * /proc, etc.).
			 */
			if (entry.mnt_special == NULL ||
				entry.mnt_mountp == NULL ||
				strncmp(entry.mnt_special, "/dev", 4) != 0) {
				continue;
			}

			currp = (struct mntpnt_list *)calloc((size_t)1,
				(size_t)sizeof (struct mntpnt_list));

			if (currp == NULL) {
				/*
				 * out of memory, free what we have and return
				 */
				free_mnttab(headp);
				(void) fclose(fp);
				return (ENOMEM);
			}

			if (headp == NULL) {
				headp = currp;
			} else {
				prevp->next = currp;
			}

			currp->next = NULL;

			currp->special = strdup(entry.mnt_special);
			if (currp->special == NULL) {
				/*
				 * out of memory, free what we have and return
				 */
				free_mnttab(headp);
				(void) fclose(fp);
				return (ENOMEM);
			}

			currp->mountp = strdup(entry.mnt_mountp);
			if (currp->mountp == NULL) {
				/*
				 * out of memory, free what we have and return
				 */
				free_mnttab(headp);
				(void) fclose(fp);
				return (ENOMEM);
			}

			prevp = currp;
		}

		(void) fclose(fp);
	}

	/* get the swap entries */
	num = dm_get_swapentries(&st, &err);
	if (num < 0) {
		free_mnttab(headp);
		return (ENOMEM);
	}

	for (i = 0, swapent = st->swt_ent; i < num; i++, swapent++) {
		char		fullpath[MAXPATHLEN+1];

		currp = (struct mntpnt_list *)
		    calloc((size_t)1, (size_t)sizeof (struct mntpnt_list));

		if (currp == NULL) {
			/* out of memory, free what we have and return */
			dm_free_swapentries(st);
			free_mnttab(headp);
			return (ENOMEM);
		}

		if (headp == NULL) {
			headp = currp;
		} else {
			prevp->next = currp;
		}

		currp->next = NULL;

		if (*swapent->ste_path != '/') {
			(void) snprintf(fullpath, sizeof (fullpath), "/dev/%s",
			    swapent->ste_path);
		} else {
			(void) strlcpy(fullpath, swapent->ste_path,
			    sizeof (fullpath));
		}

		currp->special = strdup(fullpath);
		if (currp->special == NULL) {
			/* out of memory, free what we have and return */
			dm_free_swapentries(st);
			free_mnttab(headp);
			return (ENOMEM);
		}

		currp->mountp = strdup("swap");
		if (currp->mountp == NULL) {
			/* out of memory, free what we have and return */
			dm_free_swapentries(st);
			free_mnttab(headp);
			return (ENOMEM);
		}

		prevp = currp;
	}
	if (num)
		dm_free_swapentries(st);

	/* note that we unlock the mutex in both paths of this if statement */
	(void) rw_wrlock(&mntpoint_lock);
	if (diff_mnttab(send_event, mntpoint_listp, headp) == B_TRUE) {
		struct mntpnt_list	*tmpp;

		tmpp = mntpoint_listp;
		mntpoint_listp = headp;
		(void) rw_unlock(&mntpoint_lock);

		/* free the old list */
		free_mnttab(tmpp);
	} else {
		(void) rw_unlock(&mntpoint_lock);
		/* no change that we care about, so keep the current list */
		free_mnttab(headp);
	}
	return (0);
}

/*
 * This is a thread that runs forever, watching for changes in the mnttab
 * that would cause us to flush and reload the cache of mnt entries.  Only
 * changes to /dev devices will cause the cache to be flushed and reloaded.
 */
static void
watch_mnttab()
{
	struct pollfd fds[1];
	int res;

	if ((fds[0].fd = open("/etc/mnttab", O_RDONLY)) != -1) {

	    char buf[81];

	    /* do the initial read so we don't get the event right away */
	    (void) read(fds[0].fd, buf, (size_t)(sizeof (buf) - 1));
	    (void) lseek(fds[0].fd, 0, SEEK_SET);

	    fds[0].events = POLLRDBAND;
	    while (res = poll(fds, (nfds_t)1, -1)) {
		if (res <= 0)
		    continue;

		(void) load_mnttab(B_TRUE);

		(void) read(fds[0].fd, buf, (size_t)(sizeof (buf) - 1));
		(void) lseek(fds[0].fd, 0, SEEK_SET);
	    }
	}
}
