/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<ctype.h>
#include	<dirent.h>
#include	<dlfcn.h>
#include	<errno.h>
#include	<stdlib.h>
#include	<string.h>
#include	<strings.h>
#include	<synch.h>
#include	<sys/dkio.h>
#include	<sys/mkdev.h>
#include	<sys/stat.h>
#include	<sys/scsi/scsi.h>
#include	<sys/smedia.h>
#include	<sys/types.h>
#include	<sys/vol.h>
#include	<thread.h>
#include	<unistd.h>

/*
 * Local include files
 *
 * NOTE: Preserve the order of "vold.h", "dev.h", and "label.h".
 *       There are some dependencies that cause compiles to fail
 *       if the order is changed in any way.
 */

#include	"vold.h"
#include	"dev.h"
#include	"label.h"
#include	"name_factory.h"

extern int	vol_fd;
extern bool_t	support_nomedia;
extern void	obj_free(obj_t *obj);

#define	DEV_HASH_SIZE		64
static struct q		dev_q_hash[DEV_HASH_SIZE];

#define	DEV_ALLOC_CHUNK		10

static struct devsw	**devsw = NULL;
static int		ndevs = 0;
static int		nallocdevs = 0;

/*
 * This is the structure in which we maintain the list of all "paths" we've
 * seen for a particular device.  We use this to keep track of which
 * names we are managing so we can un manage them when someone
 * changes the configuration file.
 */
struct devpathl {
	struct q	q;
	char		*dpl_path;
	dev_t		dpl_rdev;
	char		*dpl_symtemplate;
	int		dpl_symidx;
	bool_t		dpl_seen;
	vol_t		*dpl_actvol;
};

static void	close_dev(struct devsw *, struct devpathl *);
static bool_t	dev_unmap(vol_t *);
void		dev_remove_ctldev(struct devs *);

/*
 * Driver calls this to add his dsw into the chain.  Called at
 * initialization time.
 */
void
dev_new(struct devsw *dsw)
{
	int		i, na;
	struct devsw	**ndevsw;


	for (i = 0; i < ndevs; i++) {
		if (devsw[i] == dsw) {
			return;
		}
	}

	if (ndevs == nallocdevs) {
		if (devsw == 0) {
			nallocdevs = DEV_ALLOC_CHUNK;
			devsw = (struct devsw **)calloc(nallocdevs,
				sizeof (struct devsw *));
		} else {
			na = nallocdevs;
			nallocdevs += DEV_ALLOC_CHUNK;
			ndevsw = (struct devsw **)calloc(nallocdevs,
				sizeof (struct devsw *));
			for (i = 0; i < na; i++) {
				ndevsw[i] = devsw[i];
			}
			free(devsw);
			devsw = ndevsw;
		}
	}
	devsw[ndevs++] = dsw;
}

/*
 * Call the driver specific routine to return an fd for a
 * device.
 */
int
dev_getfd(dev_t dev)
{
	struct devs 	*dp;
	struct devsw 	*dsw;


	dp = dev_getdp(dev);

	if ((dev == 0) || (dp == NULL)) {
		debug(1, "getfd: there's no mapping for device (%d.%d)\n",
		    major(dev), minor(dev));
		return (NULL);
	}
	dsw = dp->dp_dsw;

	return ((*dsw->d_getfd)(dev));
}


/*
 * Return the /vol/dev path to a device
 */
char *
dev_getpath(dev_t dev)
{
	struct devs 	*dp;


	dp = dev_getdp(dev);

	if ((dev == 0) || (dp == NULL)) {
		debug(1, "getpath: there's no mapping for device (%d.%d)\n",
		    major(dev), minor(dev));
		return (NULL);
	}
	return (path_make(dp->dp_rvn));
}

bool_t
dev_remount(struct vol *volumep)
{
	/*
	 * Reset the default device file descriptor
	 * after a medium inserted in the device has
	 * been repartitioned.
	 */

	struct devs 	*devicep;
	struct devsw	*device_swp;
	bool_t		result;

	result = TRUE;

	if (volumep == NULL) {
		debug(1, "dev_remount: volumep is null\n");
		result = FALSE;
	} else if (volumep->v_device == NODEV) {
		debug(1, "dev_remount: no device associated with volume \n");
		result = FALSE;
	}
	if (result == TRUE) {
		devicep = dev_getdp(volumep->v_device);
		if (devicep == NULL) {
			debug(1,
			"dev_remount: there's no mapping for device (%d.%d)\n",
			major(volumep->v_basedev), minor(volumep->v_basedev));
			result = FALSE;
		}
	}
	if (result == TRUE) {
		device_swp = devicep->dp_dsw;
		if ((device_swp != NULL) && (device_swp->d_remount != NULL)) {
			result = (*device_swp->d_remount)(volumep);
		} else {
			result = FALSE;
		}
	}
	return (result);
}

/*
 * Return the symbolic name of a device.
 */
char *
dev_symname(dev_t dev)
{
	struct devs	*dp;


	if ((dp = dev_getdp(dev)) == NULL) {
		return (NULL);
	}
	return (dp->dp_symname);
}


/*
 * Called from the config file processing code, when it hits
 * a 'use' tag.
 */
bool_t
dev_use(char *mtype, char *dtype, char *path,
    char *symname, char *user, char *group, char *mode,
    bool_t temp_flag, bool_t force_flag)
{
	static bool_t	dev_checksymname(char *);
	static void	dev_usepath(struct devsw *, char *, char *, int);
	static int	dev_avail_devidx(struct devsw *, char *, char *);
	extern uid_t	network_uid(char *);
	extern gid_t	network_gid(char *);
	struct devsw	*dsw;
	int		i;			/* devsw index */
	int		j;			/* match index */
	int		idx;
	char		**pl = NULL;
	int		match_found = 0;
	char		symbuf[MAXNAMELEN];
	bool_t		res = FALSE;

	debug(10,
	"dev_use: %s %s at %s, %s@, u/g=%s/%s, temp_flag=%s, force_flag=%s\n",
	    mtype, dtype, path, symname, user, group,
	    temp_flag ? "TRUE" : "FALSE", force_flag ? "TRUE" : "FALSE");

	/* scan each device type */
	for (i = 0; i < ndevs; i++) {

		dsw = devsw[i];

#ifdef	DEBUG_DEV_USE
		debug(11, "dev_use: comparing with %s %s\n", dsw->d_mtype,
		    dsw->d_dtype);
#endif
		if ((strcmp(dtype, dsw->d_dtype) == 0) &&
		    (strcmp(mtype, dsw->d_mtype) == 0)) {

			/*
			 * make sure the symname doesn't have
			 * more than one % in it.
			 */
			if (dev_checksymname(symname) == FALSE) {
				warning(gettext("dev_use: bad symname %s\n"),
				    symname);
				goto dun;
			}

			/* get a list of paths that match */
			if ((pl = match_path(path, dsw->d_test)) == NULL) {
				debug(5, "find_paths %s failed\n", path);
				break;
			}

			dsw->d_uid = network_uid(user);
			dsw->d_gid = network_gid(group);
			dsw->d_mode = strtol(mode, NULL, 0);
			if (temp_flag) {
				dsw->d_flags |= D_RMONEJECT;
			}

			/* for each match in the list call its driver */
			for (j = 0; pl[j] != NULL; j++) {

				idx = dev_avail_devidx(dsw, pl[j], symname);
				/*LINTED var fmt*/
				(void) snprintf(symbuf, sizeof (symbuf),
					symname, idx);

				if ((*dsw->d_use)(pl[j], symbuf) != FALSE) {
					match_found++;
					dev_usepath(dsw, pl[j], symname, idx);
				}
			}
			for (j = 0; pl[j] != NULL; j++) {
				free(pl[j]);
			}
			free(pl);

			if (match_found > 0) {
				res = TRUE;
				goto dun;	/* found at least one match */
			}
		}
	}

	if (force_flag) {
		res = TRUE;
		debug(10,
		    "dev_use: returning TRUE since \"force_flag\" set\n");
	} else {
		debug(10,
		    "either couldn't find a driver for %s \"%s\","
		    " or it's already managed\n",
		    mtype, path);
	}
dun:
	return (res);
}


/*
 * Check to make sure the symbolic name doesn't have more than one %d
 * in it.
 */
static bool_t
dev_checksymname(char *s)
{
	char	*p;
	int	cnt;


	for (cnt = 0, p = s; *p != '\0'; p++) {
		if (*p == '%') {
			/* deal with escaped % case */
			if (*(p+1) == '%') {
				p++;
				continue;
			}
			cnt++;
		}
	}

	if (cnt > 1) {
		return (FALSE);
	}
	return (TRUE);
}


/*
 * When we start to read the config file, we clear out all the
 * seen flags.
 */
void
dev_configstart()
{
	int		i;
	struct devsw	*dsw;
	struct devpathl	*dpl;

	/* clear all the "seen" bits */
	for (i = 0; i < ndevs; i++) {
		dsw = devsw[i];
		for (dpl = HEAD(struct devpathl, dsw->d_pathl);
		    dpl != NULL;
		    dpl = NEXT(struct devpathl, dpl)) {
			dpl->dpl_seen = FALSE;
		}
	}
}

/*
 * After we've read the config file, we check to see if we've
 * set all the seen flags.  If there any that we haven't set,
 * we call dsw_close on them to stop using that device.
 */
void
dev_configend()
{
	int			i;
	struct devsw		*dsw;
	struct devpathl		*dpl, *dpl_next;

	for (i = 0; i < ndevs; i++) {
		dsw = devsw[i];
		for (dpl = HEAD(struct devpathl, dsw->d_pathl);
		    dpl != NULL; dpl = dpl_next) {
			dpl_next = NEXT(struct devpathl, dpl);
			if (dpl->dpl_seen)
				continue;
			close_dev(dsw, dpl);
		}
	}
	match_path_cache_clear();
}

void
dev_close(dev_t dev)
{
	struct devs		*dp;
	struct devsw		*dsw;
	struct devpathl		*dpl, *dpl_next;

	if ((dp = dev_getdp(dev)) == NULL) {
		/* device is gone */
		return;
	}
	dsw = dp->dp_dsw;
	for (dpl = HEAD(struct devpathl, dsw->d_pathl);
	    dpl != NULL; dpl = dpl_next) {
		dpl_next = NEXT(struct devpathl, dpl);
		if (dev_search_dp(dpl->dpl_rdev) == dp) {
			close_dev(dsw, dpl);
			break;
		}
	}
}

void
dev_closeout(vol_t *v, bool_t ans)
{
	extern	void async_taskq_clean(struct devs *);
	int			i;
	struct devsw		*dsw;
	struct devpathl		*dpl, *dpl_next;
	struct devs		*dp;
	medium_handle_t		m;

	/* find corresponding devpathl entry */
	for (i = 0; i < ndevs; i++) {
		dsw = devsw[i];
		for (dpl = HEAD(struct devpathl, dsw->d_pathl);
		    dpl != NULL; dpl = dpl_next) {
			dpl_next = NEXT(struct devpathl, dpl);
			if (dpl->dpl_actvol == v)
				break;
		}
		if (dpl != NULL)
			break;
	}

	if (dpl == NULL)
		return;		/* shouldn't happen */

	m = NULL;
	if ((dp = dev_search_dp(dpl->dpl_rdev)) != NULL) {
		m = dp->dp_mediump;
		/*
		 * unlabelled medium will be released in dev_unhangvol.
		 * So we should not release it.
		 */
		if (dp->dp_vol != NULL &&
		    (dp->dp_vol->v_flags & V_UNLAB) != 0) {
			m = NULL;
		}
	}
	if (ans == TRUE) {
		(*dsw->d_close)(dpl->dpl_path, dpl->dpl_rdev);
		async_taskq_clean(dp);
	}
	if ((dp = dev_search_dp(dpl->dpl_rdev)) != NULL) {
		/*
		 * d_close() failed to release the
		 * device. we won't remove the device.
		 */
		dpl->dpl_actvol = NULL;
		if (dp->dp_vol != NULL)
			dp->dp_vol->v_ej_inprog = FALSE;
		noise("%s is busy. can not close the device.\n",
			dp->dp_symname);
		return;
	}
	/*
	 * device has gone now.
	 */
	if (m != NULL)
		clean_medium_and_volume(m);
	REMQUE(dsw->d_pathl, dpl);
	free(dpl->dpl_path);
	free(dpl->dpl_symtemplate);
	free(dpl);
}

static void
close_dev(struct devsw *dsw, struct devpathl *dpl)
{
	extern	void async_taskq_clean(struct devs *);
	struct devs		*dp;
	struct stat		st;
	medium_handle_t		m;

	/* if this guy wasn't seen this time close him down */
	debug(1, "close_dev: closing dev %s\n", dpl->dpl_path);

	if (dpl->dpl_actvol != NULL) {
		/* close in progress on this device */
		return;
	}

	dpl->dpl_actvol = NULL;

	if (dpl->dpl_rdev == NODEV) {
		if (stat(dpl->dpl_path, &st) == 0)
			dpl->dpl_rdev = st.st_rdev;
	}

	/*
	 * try umount the device anyway.
	 */
	dp = NULL;
	m = NULL;
	if ((dp = dev_search_dp(dpl->dpl_rdev)) != NULL) {
		m = dp->dp_mediump;
		if (dp->dp_vol != NULL) {
			dp->dp_vol->v_ej_inprog = TRUE;
			dp->dp_vol->v_ej_force = TRUE;
			dp->dp_vol->v_ejfail = FALSE;
			dp->dp_vol->v_clue.c_volume = 0;
			if (action(ACT_CLOSE, dp->dp_vol) != 0) {
				dpl->dpl_actvol = dp->dp_vol;
			} else {
				/*
				 * We are closing device directly. If the
				 * device is unlabelled, then volume will
				 * be gone by dev_unhangvol(via d_close).
				 * Therefore, we don't release medium.
				 */
				if (dp->dp_vol->v_flags & V_UNLAB)
					m = NULL;
			}
		}
	}
	/*
	 * if action was invoked, we are done. rest of the thing will
	 * be done by vol_reaper().
	 */
	if (dpl->dpl_actvol != NULL)
		return;

	/*
	 * action is not invoked. close it directly.
	 */
	(*dsw->d_close)(dpl->dpl_path, dpl->dpl_rdev);

	async_taskq_clean(dp);

	if ((dp = dev_search_dp(dpl->dpl_rdev)) != NULL) {
		/*
		 * d_close() failed to release the device. won't delete
		 * the device.
		 */
		dpl->dpl_actvol = NULL;
		noise("%s is busy. can not close the device.\n",
		    dp->dp_symname);
		return;
	}
	/*
	 * volume and medium is no longer necessary.
	 */
	if (m != NULL)
		clean_medium_and_volume(m);
	if (dpl->dpl_actvol == NULL) {
		REMQUE(dsw->d_pathl, dpl);
		free(dpl->dpl_path);
		free(dpl->dpl_symtemplate);
		free(dpl);
	}
}


/*
 * Maintain a list of "paths" which a particular driver is using.
 * This allows us to just reprocess the config file then see what
 * isn't being used anymore.
 */
static void
dev_usepath(struct devsw *dsw, char *path, char *template, int symidx)
{
	struct devpathl	*dpl;
	bool_t		found = FALSE;
	struct	stat st;

	for (dpl = HEAD(struct devpathl, dsw->d_pathl);
	    dpl != NULL;
	    dpl = NEXT(struct devpathl, dpl)) {
		if (strcmp(dpl->dpl_path, path) == 0) {
			found = TRUE;
			dpl->dpl_seen = TRUE;
			break;
		}
	}

	if (found == FALSE) {
		if (stat(path, &st) < 0)
			st.st_rdev = NODEV;
		dpl = vold_calloc(1, sizeof (struct devpathl));
		dpl->dpl_path = vold_strdup(path);
		dpl->dpl_rdev = st.st_rdev;
		dpl->dpl_symtemplate = vold_strdup(template);
		dpl->dpl_symidx = symidx;
		dpl->dpl_seen = TRUE;
		INSQUE(dsw->d_pathl, dpl);
		debug(4, "dev_usepath: new path %s\n", path);
	}
}

/*
 * look for the dev index we can use for the particular dev. If the
 * device has been managed, and the index has been assigned for the
 * particular device path, return the old index immediately.
 * Otherwise, first, we create bitmap indicates that which index has
 * been used. Once we created bitmap, we pick up the least unused
 * number from bitmap, and return it as the device number.
 * (eg N in cdromN).
 */
static int
dev_avail_devidx(struct devsw *dsw, char *path, char *template)
{
	struct devpathl	*dpl;
	int		idx, maxidx = -1;
	unsigned char	*bitmap;
	size_t		nbits = 32;
	boolean_t	found = B_FALSE;

	bitmap = vold_calloc(nbits/NBBY, sizeof (char));
	for (dpl = HEAD(struct devpathl, dsw->d_pathl);
	    dpl != NULL;
	    dpl = NEXT(struct devpathl, dpl)) {
		/*
		 * make sure we have same sym name.
		 */
		if (strcmp(dpl->dpl_symtemplate, template) != 0)
			continue;
		idx = dpl->dpl_symidx;
		if (strcmp(dpl->dpl_path, path) == 0) {
			/*
			 * We have symname and device pathname match.
			 * return old index for the device.
			 */
			found = B_TRUE;
			break;
		}
		while (idx > nbits) {
			bitmap = vold_realloc(bitmap, (nbits + 32)/NBBY);
			(void) memset(bitmap + (nbits/NBBY), 0, 32/NBBY);
			nbits += 32;
		}
		bitmap[idx/NBBY] |= (1 << (idx % NBBY));
		if (idx > maxidx) {
			maxidx = idx;
		}
	}
	if (!found) {
		/*
		 * find least unused number.
		 */
		for (idx = 0; idx < maxidx; idx++) {
			if ((bitmap[idx/NBBY] & (1 << (idx % NBBY))) == 0) {
				/* found free slot */
				found = B_TRUE;
				break;
			}
		}
	}
	free(bitmap);
	if (found) {
		return (idx);
	} else {
		return ((maxidx == -1) ? 0 : (maxidx + 1));
	}
}

/*
 * This interface is currently not well used.
 */
void
dev_error(struct ve_error *viee)
{
	struct devs	*dp = dev_getdp(viee->viee_dev);
	struct devsw	*dsw;


	if (dp != NULL) {
		dsw = dp->dp_dsw;
		(*dsw->d_error)(viee);
		dp->dp_vol->v_clue.c_error = viee;
		(void) action(ACT_ERROR, dp->dp_vol);
	}
}


/*
 * Given a dev, return the dp assocaited with it.
 */
struct devs *
dev_getdp(dev_t	dev)
{
	struct devs	*dp;

	ASSERT(dev != NODEV);
	ASSERT(dev != 0);

	dp = HEAD(struct devs, dev_q_hash[(uint_t)dev % DEV_HASH_SIZE]);
	while (dp != NULL) {
		if (dp->dp_dev == dev) {
			return (dp);
		}
		dp = NEXT(struct devs, dp);
	}
	return (NULL);
}

/*
 * search all the devs list.
 */
struct devs *
dev_search_dp(dev_t dev)
{
	struct devs	*dp;
	int		i, j;

	for (i = 0; i < DEV_HASH_SIZE; i++) {
		for (dp = HEAD(struct devs, dev_q_hash[i]);
		    dp != NULL; dp = NEXT(struct devs, dp)) {
			if (dp->dp_dev == dev) {
				return (dp);
			}
			for (j = 0; j < dp->dp_ndev; j++) {
				if (dp->dp_all_dev[j] == dev)
					return (dp);
			}
		}
	}
	return (NULL);
}

/*
 * search device list and return the number of asynch task which
 * is running.
 */
int
dev_nastask(void)
{
	struct devs	*dp;
	int 	i, nact;

	nact = 0;
	for (i = 0; i < DEV_HASH_SIZE; i++) {
		for (dp = HEAD(struct devs, dev_q_hash[i]); dp != NULL;
		    dp = NEXT(struct devs, dp)) {
			nact += dp->dp_asynctask;
		}
	}
	return (nact);
}

/*
 * Given a dp, return TRUE if there is a piece of media in that
 * device, FALSE otherwise.
 */
bool_t
dev_present(struct devs *dp)
{
	if (dp->dp_vol != NULL) {
		return (TRUE);
	}
	return (FALSE);
}


/*
 * Given a dev, return the associated dsw.
 */
static struct devsw *
dev_getdsw(dev_t dev)
{
	struct devs	*dp;


	if (dev == NODEV) {
		return (NULL);
	}

	dp = dev_getdp(dev);
	ASSERT(dp != NULL);
	return (dp->dp_dsw);
}


/*
 * Check to see if a volume is read-only.
 */
bool_t
dev_rdonly(dev_t dev)
{
	struct devs *dp;


	if (dev == NODEV) {
		return (FALSE);
	}
	dp = dev_getdp(dev);
	if (dp != NULL) {
		return (dp->dp_writeprot);
	}
	return (FALSE);
}


/*
 * Create a new dp, which represents path.
 */
struct devs *
dev_makedp(struct devsw *dsw, char *path)
{
	struct devs	*dp;
	struct stat	sb;


	if (stat(path, &sb) < 0) {
		debug(1, "dev_makedp: %s; %m\n", path);
		return (NULL);
	}
	dp = (struct devs *)calloc(1, sizeof (struct devs));
	dp->dp_path = strdup(path);
	dp->dp_dev = sb.st_rdev;
	dp->dp_dsw = dsw;
	dp->dp_lock = (dp_vol_lock_t *)malloc(sizeof (dp_vol_lock_t));
	(void) mutex_init(&dp->dp_lock->dp_vol_vg_mutex, USYNC_THREAD, 0);
	(void) cond_init(&dp->dp_lock->dp_vol_vg_cv, USYNC_THREAD, 0);
	if (dsw->d_flags & D_MEJECTABLE)
		dp->dp_flags |= DP_MEJECTABLE;
	debug(15, "dev_makedp: just added mapping for %s (%d,%d)\n",
	    path, major(sb.st_rdev), minor(sb.st_rdev));
	/* add it to the hash table */
	INSQUE(dev_q_hash[(uint_t)dp->dp_dev % DEV_HASH_SIZE], dp);
	return (dp);
}


/*
 * Free a dp.  Remove it from the hash queue and free storage associated
 * with it.  Assumes that the caller has already done the unhang.
 */
void
dev_freedp(struct devs *dp)
{
	/* remove "nomedia" device node */
	if (support_nomedia && dp->dp_cvn) {
		dev_remove_ctldev(dp);
	}

	REMQUE(dev_q_hash[dp->dp_dev % DEV_HASH_SIZE], dp);
	free(dp->dp_path);
	free(dp->dp_lock);
	free(dp);
}

/*
 * Do all the work associated with ejecting a volume, telling the
 * eject program the status, etc, etc.  This is called after all
 * the actions have run and returned a verdict.  The last check that
 * can change the results of our ejection is whether the media is
 * mounted with an unsafe filesystem.  This is done with unsafe_check().
 */
void
dev_eject(vol_t *v, bool_t ans)
{
	int			err;
	struct devs		*dp;
	struct devsw 		*dsw;
	struct vioc_eject	viej;
	dev_t			voldev;
	bool_t			force;
	struct dk_minfo		media;
	int			fd;

#ifdef	DEBUG
	debug(11, "dev_eject: ans = %s for %s\n", ans ? "TRUE" : "FALSE",
	    v->v_obj.o_name);
#endif
	dp = dev_getdp(v->v_basedev);
	if (dp == NULL) {
		debug(1, "volume %s already ejected!\n", v->v_obj.o_name);
		return;
	}

	dsw = dp->dp_dsw;

	force = v->v_ej_force;
	/*
	 * check to see if we have an "unsafe" file system mounted.
	 * Returns TRUE if volume is "unsafe" to eject.
	 */
	if ((ans != FALSE) && (force == FALSE)) {
		if (unsafe_check(v) != FALSE) {
			ans = FALSE;
		}
	}

	debug(1, "%sing ejection for \"%s\"\n", ans ? "approv" : "deny",
	    v->v_obj.o_name);

	viej.viej_unit = v->v_clue.c_volume;

	if (ans != FALSE) {
		viej.viej_state = VEJ_YES;
	} else {
		viej.viej_state = VEJ_NO;
	}

	if (force == FALSE && viej.viej_unit != 0) {
		if (ioctl(vol_fd, VOLIOCEJECT, &viej) < 0) {
			if (errno != EAGAIN)
				warning(gettext("ejection failed; %m\n"));
		}
	}

	/*
	 * Change our in progress flag...
	 */
	v->v_ej_inprog = FALSE;

	if ((ans == FALSE) && (force == FALSE)) {
		return;
	}

	voldev = v->v_basedev;

	if (dsw->d_eject != NULL) {
		debug(5, "dev_eject: calling dev-specific eject routine\n");
		(*dsw->d_eject)(dp);
	}

	/*
	 * Remove the mapping for the device.
	 */
	(void) dev_unmap(v);

	/*
	 * Update the database entry.
	 */
	change_location((obj_t *)v, "");
	(void) db_update((obj_t *)v);

	/*
	 * If this is a polling device, start up the polling
	 * again.
	 */
	if ((dsw->d_flags & D_POLL) && (dsw->d_poll != NULL)) {
		(*dsw->d_poll)(voldev);
	}

	dev_unhangvol(dp);

	dp->dp_writeprot = FALSE;

	/*
	 * if volume was unlabelled, it has gone by dev_unhangvol
	 */
	if (dp->dp_mediump != NULL && v->v_flags & V_RMONEJECT) {
		node_remove((obj_t *)v, TRUE, (uint_t *)&err);
		clean_medium_and_volume(v->v_mediump);
		dp->dp_mediump = NULL;
	}

	/* signal anything waiting */
	(void) mutex_lock(&dp->dp_lock->dp_vol_vg_mutex);
#ifdef	DEBUG
	debug(5, "dev_eject: signalling that eject's done on unit %d\n",
	    viej.viej_unit);
#endif
	(void) cond_broadcast(&dp->dp_lock->dp_vol_vg_cv);
	(void) mutex_unlock(&dp->dp_lock->dp_vol_vg_mutex);

	/*
	 * For diskette, create the "nomedia" node after eject(1).
	 */
	if (support_nomedia && strstr(dp->dp_path, "rdiskette")) {
		dev_create_ctldev(dp);
		return;
	}

	/* Create the "nomedia" node for empty removable media device. */
	if (support_nomedia) {
		if (fd = dev_getfd(dp->dp_dev)) {
			if (ioctl(fd, DKIOCGMEDIAINFO, &media) < 0) {
				dev_create_ctldev(dp);
			}
		}
	}
}

/*
 * This is for the error cases...  Something bad has happened, so
 * we just spit the thing back out at the user.
 */
void
dev_hard_eject(struct devs *dp)
{
	int	fd = dev_getfd(dp->dp_dev);

	(void) ioctl(fd, DKIOCEJECT, 0);
}


/*
 * Clean up the devmap associated with this volume.
 */
bool_t
dev_devmapfree(vol_t *v)
{
	uint_t		i;
	uint_t		dm_flag;
	minor_t		voldev;

	if (v->v_devmap == NULL) {
		return (TRUE);
	}

	if (dev_unmap(v) == FALSE) {
		return (FALSE);
	}

	for (i = 0; i < v->v_ndev; i++) {
		/*
		 * If the driver still has a mapping for this minor
		 * number, we can't reuse it.  We just mark the
		 * minor number as being an orphan.
		 */
		dm_flag = v->v_devmap[i].dm_flag;
		if (dm_flag & DM_MINOR_VALID) {
			if ((dm_flag & DM_MAPPED) == 0) {
				if (dm_flag & DM_MISSING) {
					voldev =
					    minor(v->v_devmap[i].dm_voldev);
					(void) ioctl(vol_fd,
						VOLIOCCANCEL, &voldev);
				}
				minor_free(minor(v->v_devmap[i].dm_voldev));
			} else {
				minor_clrvol(minor(v->v_devmap[i].dm_voldev));
			}
		}
		if (v->v_devmap[i].dm_path != NULL) {
			free(v->v_devmap[i].dm_path);
		}
	}
	v->v_ndev = 0;
	free(v->v_devmap);
	v->v_devmap = 0;
	return (TRUE);
}

/*
 * Build the devmap for this volume.
 */
void
dev_devmap(vol_t *v)
{
	struct devsw 	*dsw;
	int		n, p;
	ulong_t		fpart;
	struct stat	sb;

	dsw = dev_getdsw(v->v_basedev);
	if (dsw == NULL || dsw->d_devmap == NULL) {
		return;
	}

	fpart = v->v_parts;

	/*
	 * This can be considered an error case.  The device hasn't
	 * told us about any partitions, so we'll just use the default
	 * partition
	 */
	if (fpart == 0L) {
		debug(1, "dev_devmap: no partitions for %s (using s%d)\n",
		    v->v_obj.o_name, DEFAULT_PARTITION);
		if (v->v_devmap == NULL) {
			v->v_devmap = vold_calloc(1, sizeof (devmap_t));
			v->v_devmap[0].dm_voldev = minor_alloc(v);
			v->v_devmap[0].dm_flag |= DM_MINOR_VALID;
#ifdef	DEBUG
			debug(5,
				"dev_devmap: dm_voldev[0] set to (%d,%d)\n",
				    major(v->v_devmap[0].dm_voldev),
				    minor(v->v_devmap[0].dm_voldev));
#endif
		}
		v->v_ndev = 1;
		if (v->v_devmap[0].dm_path != NULL)
			free(v->v_devmap[0].dm_path);
		(*dsw->d_devmap)(v, DEFAULT_PARTITION, 0);
		if (stat(v->v_devmap[0].dm_path, &sb) < 0) {
			debug(1, "dev_devmap: %s; %m\n",
				v->v_devmap[0].dm_path);
			(void) dev_devmapfree(v);
			return;
		}
		v->v_devmap[0].dm_realdev = sb.st_rdev;
		return;
	}

	/*
	 * Allocate our devmap.
	 */
	if (v->v_devmap == NULL) {
		v->v_devmap = vold_calloc(V_NUMPAR, sizeof (devmap_t));
		for (n = 0; n < (int)v->v_ndev; n++) {
			v->v_devmap[n].dm_voldev = minor_alloc(v);
			v->v_devmap[n].dm_flag |= DM_MINOR_VALID;
		}
	}

	/*
	 * Have the driver tell us what device a partitular
	 * partition is.
	 */
	for (p = 0, n = 0; p < V_NUMPAR; p++) {
		if (fpart & (1<<p)) {
			if (v->v_devmap[n].dm_path != NULL)
				free(v->v_devmap[n].dm_path);
			(*dsw->d_devmap)(v, p, n);
			if ((v->v_devmap[n].dm_path == NULL) ||
			    (stat(v->v_devmap[n].dm_path, &sb) < 0)) {
				debug(1, "dev_devmap: %s; %m\n",
				    v->v_devmap[n].dm_path);
				(void) dev_devmapfree(v);
				return;
			}
			/*
			 * We just store dm_realdev here to cache it
			 * so we don't spend our life doing stats of
			 * the path.
			 */
			v->v_devmap[n].dm_realdev = sb.st_rdev;
			n++;
		}
	}
}

/*
 * Load the devmap for a volume down into the vol driver.  If the
 * location of the volume hasn't been "confirmed", we bag out...
 * unless ndelay is set.  The ndelay business is to support non-blocking
 * opens.  This was required so that you could eject a volume without
 * having to read or write it first.
 */
bool_t
dev_map(vol_t *v, bool_t ndelay)
{
	debug(11, "dev_map: entering for %s (ndelay = %s)\n",
	    v->v_obj.o_name, (ndelay ? "TRUE" : "FALSE"));

	if ((v->v_confirmed == FALSE) && (ndelay == FALSE)) {
		/* no location yet, and ??? (XXX: what is this) */
		debug(11, "dev_map: svcs not needed\n");
		return (FALSE);
	}

	/*
	 * always do this to ensure that dm_path is correct
	 */
	dev_devmap(v);

	return (dev_map_dropin(v));
}

bool_t
dev_map_dropin(vol_t *v)
{
	struct vioc_map	vim;			/* for VOLIOCMAP ioctl */
	minor_t		volume;			/* minor dev # index */
	uint_t		i;	/* dev linked list index */

	/* scan all nodes for this volume */
	for (i = 0; i < v->v_ndev; i++) {

		volume = minor(v->v_devmap[i].dm_voldev);

		(void) memset(&vim, 0, sizeof (struct vioc_map));

		/* has the location been confirmed ?? */
		if (v->v_confirmed) {
			vim.vim_basedev = v->v_basedev;
			vim.vim_dev = v->v_devmap[i].dm_realdev;
			vim.vim_path = v->v_devmap[i].dm_path;
			vim.vim_pathlen = strlen(vim.vim_path);
			/* clear the missing flag */
			v->v_flags &= ~V_MISSING;
			debug(11, "dev_map: clearing missing flag, unit %d\n",
			    volume);
		} else {
			vim.vim_basedev = NODEV;
			vim.vim_dev = NODEV;
			vim.vim_path = NULL;
			vim.vim_pathlen = 0;
		}
		vim.vim_unit = volume;
		vim.vim_id = v->v_obj.o_id;

		/* check for read-only */
		if (dev_rdonly(v->v_basedev) || (v->v_flags & V_RDONLY)) {
			vim.vim_flags |= VIM_RDONLY;
			debug(5, "dev_map: set RDONLY flag for mapping\n");
		}

		/* the driver needs to know if this is a floppy device */
		if (strcmp(v->v_mtype, FLOPPY_MTYPE) == 0) {
			vim.vim_flags |= VIM_FLOPPY;
		}

		debug(7, "dev_map: telling driver to MAP unit %d\n",
		    vim.vim_unit);
		if (ioctl(vol_fd, VOLIOCMAP, &vim) < 0) {
			debug(1, "dev_map: VOLIOCMAP; %m\n");
			return (FALSE);
		}
		v->v_devmap[i].dm_flag &= ~DM_MISSING;
		v->v_devmap[i].dm_flag |= DM_MAPPED;
	}
	debug(11, "dev_map: returning TRUE\n");
	return (TRUE);
}

/*
 * try map the missing volume. If it fails, mark the devmap
 * missing, and set V_MISSING so that check_missing will map
 * the entry accordingly.
 */
bool_t
dev_map_missing(vol_t *v, minor_t unit, bool_t ndelay)
{
	int	i;

	if (dev_map(v, ndelay) == TRUE)
		return (TRUE);
	if (v->v_devmap == NULL)
		return (TRUE);
	for (i = 0; i < v->v_ndev; i++) {
		if (unit == minor(v->v_devmap[i].dm_voldev))
			break;
	}
	if (i == v->v_ndev) {
		/*
		 * cannot find minor node in the devmap. what is
		 * this device??
		 */
		return (TRUE);
	}
	v->v_devmap[i].dm_flag &= ~DM_MAPPED;
	v->v_devmap[i].dm_flag |= DM_MISSING;
	if (v->v_flags & V_MISSING)
		return (TRUE);
	v->v_flags |= V_MISSING;
	return (FALSE);
}

/*
 * check the devmap which is being taken over, and see if anything
 * has been missing. If something exists, create the map. If the
 * missing device is being removed, cancel it.
 */
void
dev_handle_missing(vol_t *ov, vol_t *nv)
{
	int		i;
	minor_t		voldev;
	devmap_t	*dmp;
	struct reap	*r;
	struct devpathl	*dpl;

	/*
	 * If the old volume was unlabelled, the device may have been
	 * cancelled. we need to uncancel the device by mapping the
	 * new dev.
	 */
	if ((ov->v_flags & V_MISSING) == 0)
		return;
	if (ov->v_devmap == NULL)
		return;

	for (i = 0; i < ov->v_ndev; i++) {
		dmp = &ov->v_devmap[i];
		if ((dmp->dm_flag & (DM_REMOVE|DM_MISSING)) ==
		    (DM_REMOVE|DM_MISSING)) {
			/*
			 * unfortunately the medium inserted in the
			 * drive is not the same one as before. This
			 * particular mapping is being removed.
			 * Therefore, cancelling the volume since
			 * it's already missing.
			 */
			voldev = minor(dmp->dm_voldev);
			(void) ioctl(vol_fd, VOLIOCCANCEL, &voldev);
			continue;
		}
		/*
		 * drop the flag in the old devmap so that the
		 * dev_devmapfree won't do anything further.
		 */
		dmp->dm_flag &= ~DM_MISSING;
	}

	/*
	 * If devmap hasn't been created at this point, we delete the
	 * the reference from the queues.
	 */
	if (nv->v_devmap == NULL)
		nv = NULL;

	/*
	 * we may have reference to the old volume from repq.
	 * This could happen if volume was removed while
	 * ejecting(unmounting) medium. Change the reference.
	 */
	for (r = HEAD(struct reap, reapq); r != NULL;
	    r = NEXT(struct reap, r)) {
		if (r->r_v != ov)
			continue;
		r->r_v = nv;
		if (r->r_act == ACT_EJECT || r->r_act == ACT_CLOSE) {
			nv->v_clue = ov->v_clue;
			nv->v_eject = ov->v_eject;
			nv->v_ejfail = FALSE;
			nv->v_ej_force = FALSE;
			nv->v_ej_inprog = TRUE;
			nv->v_checkresp = ov->v_checkresp;
		}
	}

	/*
	 * we also may have reference from devpathl if device was
	 * being closed.
	 */
	for (i = 0; i < ndevs; i++) {
		for (dpl = HEAD(struct devpathl, devsw[i]->d_pathl);
		    dpl != NULL; dpl = NEXT(struct devpathl, dpl)) {
			if (dpl->dpl_actvol == ov) {
				dpl->dpl_actvol = nv;
			}
		}
	}
}

/*
 * Copy the devmap as much as possible so that we can
 * prevent the growth of minor node.
 */
void
dev_reset_devmap(vol_t *ov, vol_t *nv)
{
	int		i, j;
	minor_t		volume;
	devmap_t	*odmp, *ndmp;

	if (nv->v_devmap == NULL) {
		if (ov->v_devmap != NULL &&
		    ov->v_parts == nv->v_parts && ov->v_ndev == nv->v_ndev) {
			debug(5, "devmap_copy: using same devmap\n");
			/*
			 * minor hash has reference to the old volume.
			 * reset it to the new one.
			 */
			for (i = 0; i < ov->v_ndev; i++) {
				volume = minor(ov->v_devmap[i].dm_voldev);
				minor_chgvol(volume, nv);
			}
			/*
			 * reset devmap pointer, so that it will not be freed.
			 */
			nv->v_devmap = ov->v_devmap;
			ov->v_devmap = NULL;
			/*
			 * we still need to call dev_devmap() so that
			 * we have right dm_path etc.
			 */
		}
		dev_devmap(nv);
	}

	if (ov->v_devmap == NULL || nv->v_devmap == NULL)
		return;

	/*
	 * new devmap has been created. do what ever we can do.
	 */
	for (i = 0; i < ov->v_ndev; i++) {
		odmp = &ov->v_devmap[i];
		if (odmp->dm_realdev == 0)
			continue;
		for (j = 0; j < nv->v_ndev; j++) {
			ndmp = &nv->v_devmap[j];
			if (ndmp->dm_realdev == 0)
				continue;
			if (ndmp->dm_realdev == odmp->dm_realdev)
				break;
		}
		if (j == nv->v_ndev) {
			/*
			 * the old device doesn't exist in the new devmap
			 * flag DM_REMOVE.
			 */
			odmp->dm_flag |= DM_REMOVE;
			continue;
		}
		/*
		 * same device has been used in the new mapping.
		 * first release the new minor, and change the
		 * volume pointer from old minor to new volume.
		 */
		if (ndmp->dm_voldev != 0) {
			/*
			 * If they've already made mapping, then unmap it.
			 */
			volume = minor(ndmp->dm_voldev);
			if (ndmp->dm_flag & DM_MAPPED) {
				(void) ioctl(vol_fd, VOLIOCUNMAP, &volume);
				ndmp->dm_flag &= ~DM_MAPPED;
			}
			minor_free(volume);
		}
		ndmp->dm_voldev = odmp->dm_voldev;
		minor_chgvol(minor(ndmp->dm_voldev), nv);
		/* just make sure */
		ndmp->dm_flag |= DM_MINOR_VALID;
		/*
		 * clear DM_MAPPED so that subsequent call to
		 * dev_unmap against old volume won't unmap the device.
		 */
		odmp->dm_flag &= ~(DM_MAPPED|DM_MINOR_VALID);
	}
}

/*
 * Remove a mapping for a volume from the driver.  Normally called
 * on ejection.
 */
static bool_t
dev_unmap(vol_t *v)
{
	uint_t		i;
	minor_t		volume;

	if (v->v_flags & V_UNMAPPED)
		return (TRUE);

	v->v_flags |= V_UNMAPPED;

	/* scan all nodes for this volume */
	for (i = 0; i < v->v_ndev; i++) {

		if ((v->v_devmap[i].dm_flag & DM_MAPPED) == 0)
			continue;

		volume = minor(v->v_devmap[i].dm_voldev);

		debug(11, "dev_unmap: unit %d\n", volume);
		/*
		 * the V_ENXIO flag used to be checked for, here, but
		 * that didn't allow the setting of "s-enxio" to have
		 * an immediate effect, so that's now done when the property
		 * is set
		 */

		/*
		 * if it's an unlabeled device, we must cancel
		 * any pending i/o, because we'll never be able
		 * to give it back to them.
		 */
		if (v->v_flags & V_UNLAB) {
			debug(7,
			    "dev_unmap: telling driver to UNMAP minor# %d\n",
			    minor(v->v_devmap[0].dm_voldev));
			if (ioctl(vol_fd, VOLIOCCANCEL, &volume) < 0) {
				debug(1, "dev_unmap: cancel err on %s; %m\n",
				    v->v_obj.o_name);
			}
		}

		/*
		 * Do the actual unmapping.
		 */
		if (ioctl(vol_fd, VOLIOCUNMAP, &volume) != 0) {
			/*
			 * set the flag to say "don't reuse this minor
			 * number".  the purpose of this is to assign
			 * the minor number to some other piece of media
			 * while the driver is still mapping it (to
			 * return errors, for example.
			 *
			 * the minor_* code will garbage collect the
			 * minor numbers for us.
			 */
			v->v_flags &= ~V_UNMAPPED;
			if (errno == ENODEV)
				v->v_devmap[i].dm_flag &= ~DM_MAPPED;
			debug(1, "dev_unmap: VOLIOCUNMAP (%d) of \"%s\"; %m\n",
			    vol_fd, v->v_obj.o_name);
		} else {
			v->v_devmap[i].dm_flag &= ~DM_MAPPED;
		}
		free(v->v_devmap[i].dm_path);
		v->v_devmap[i].dm_path = 0;
	}
	v->v_confirmed = FALSE;
	change_location((obj_t *)v, "");
	return (TRUE);
}

/*
 * Built an arbitrary path in /vol/dev and return the vvnode pointing
 * to the lowest node.  This is used by the drivers who want to build
 * paths in /vol/dev and hang things off them.
 *
 * for each component in the path
 *	- check to see if we already have it
 *	- stat it in /dev
 *	- get the modes, et. al.
 *	- add it in.
 */
vvnode_t *
dev_dirpath(char *path)
{
	char		**ps;
	int		found = 0;
	int		comp;
	vvnode_t	*vn, *pvn;
	char		namebuf[MAXPATHLEN];
	char		devnamebuf[MAXPATHLEN];
	extern vvnode_t	*devroot;
	uint_t		err;


#ifdef	DEBUG
	debug(11, "dev_dirpath: entering for \"%s\"\n", path);
#endif
	ps = path_split(path);
	for (comp = 0; ps[comp] != NULL; comp++) {
		if (strcmp(ps[comp], "dev") == 0) {
			found++;
			break;
		}
	}
	comp++;
	if (found == 0) {
		/* this should mostly be a debug aid */
		fatal(gettext("dev_dirpath: %s does not have 'dev' in it!\n"),
		    path);
	}
	(void) strcpy(namebuf, "dev/");
	(void) strcpy(devnamebuf, "/dev/");
	pvn = devroot;
	for (; ps[comp] != NULL; comp++) {
		mode_t		mode;
		uid_t		uid;
		gid_t		gid;
		dirat_t		*da;

		(void) strcat(namebuf, ps[comp]);
		(void) strcat(devnamebuf, ps[comp]);
		if ((vn = node_lookup(namebuf)) == NULL) {
			/*
			 * XXX: here's where we need to create the /dev
			 * pathname and stat it to get the modes, uid
			 * and gid.
			 */
			mode = DEFAULT_ROOT_MODE;
			uid = DEFAULT_TOP_UID;
			gid = DEFAULT_TOP_GID;

			da = node_mkdirat(ps[comp], uid, gid, mode);
			if (pvn == NULL) {
				/*
				 * yes, this is ugly and irritating,
				 * but devroot will not get set until the
				 * node_lookup the first time through.
				 */
				pvn = devroot;
			}
			vn = node_mkobj(pvn, (obj_t *)da, NODE_TMPID,  &err);
			if (err != 0) {
				debug(3, "dev_dirpath: err %d on %s of %s\n",
					err, ps[comp], path);
				break;
			}
		}
		pvn = vn;
		(void) strcat(devnamebuf, "/");
		(void) strcat(namebuf, "/");
	}
	path_freeps(ps);
	return (vn);
}


/*
 * Given a dp, associate a volume with it in the name space.  This
 * just makes the block and character nodes appear in the /vol/dev
 * part of the name space, as specified by the driver. (and, it also
 * makes the symlink in .../dev/aliases)
 */
void
dev_hangvol(struct devs *dp, vol_t *v)
{
	vvnode_t	*vn;
	uint_t		err;
	uint_t		flgs = 0;
	char		*path;


	if (v->v_flags & V_UNLAB) {
		flgs = NODE_TMPID;
	}

	if (dp->dp_rvn != NULL) {
		vn = node_mkobj(dp->dp_rvn, (obj_t *)v, NODE_CHR|flgs, &err);
		if (err != 0) {
			debug(1,
		"dev_hangvol: node_mkobj (chr) failed for \"%s\" (err = %d)\n",
			    v->v_obj.o_name, err);
		}
		if (dp->dp_symname != NULL) {
			path = path_make(vn);
			dp->dp_symvn = node_symlink(
			    dev_dirpath("/dev/aliases"), dp->dp_symname,
				path, NODE_TMPID, NULL);
			free(path);
		}
	}

	if (dp->dp_bvn != NULL) {
		(void) node_mkobj(dp->dp_bvn, (obj_t *)v, NODE_BLK|flgs, &err);
		if (err != 0) {
			debug(1,
		"dev_hangvol: node_mkobj (blk) failed \"%s\" (err = %d)\n",
			    v->v_obj.o_name, err);
		}
	}

	dp->dp_vol = v;
}


/*
 * Remove any names in the name space that are associated with this
 * dp.
 */
void
dev_unhangvol(struct devs *dp)
{
	vol_t		*v;
	obj_t		*obj;

#ifdef	DEBUG
	if (dp->dp_vol) {
		debug(7, "dev_unhangvol: entering for \"%s\"\n",
		    dp->dp_vol->v_obj.o_name);
	} else {
		debug(7, "dev_unhangvol: entering for null obj\n");
	}
#endif
	if (dp->dp_rvn != NULL && dp->dp_rvn->vn_child != NULL) {
		node_unlink(dp->dp_rvn->vn_child);
		dp->dp_rvn->vn_child = NULL;
	}

	if (dp->dp_bvn != NULL && dp->dp_bvn->vn_child != NULL) {
		node_unlink(dp->dp_bvn->vn_child);
		dp->dp_bvn->vn_child = NULL;
	}

	if (dp->dp_symvn != NULL) {
		obj = dp->dp_symvn->vn_obj;
		node_unlink(dp->dp_symvn);
		obj_free(obj);
		dp->dp_symvn = NULL;
	}

	v = dp->dp_vol;
	if (v != NULL && v->v_flags & V_UNLAB) {
		if (v->v_mediump != NULL)
			clean_medium_and_volume(v->v_mediump);
		dp->dp_mediump = NULL;
	}
	dp->dp_vol = NULL;
}


/*
 * dev_rename: take care of aliases if we have a volume and
 * if it's been renamed.
 */
void
dev_rename(vol_t *v)
{
	struct devs	*dp;
	char		*path;
	obj_t		*obj;


	if ((v->v_basedev == NODEV) || (v->v_basedev == 0)) {
		return;
	}

	if ((dp = dev_getdp(v->v_basedev)) == NULL) {
		debug(1, "dev_rename: basedev 0x%x, no dp!\n", v->v_basedev);
		return;
	}
	if ((dp->dp_symvn != NULL) &&
	    (dp->dp_rvn != NULL) &&
	    (dp->dp_rvn->vn_child != NULL)) {
		obj = dp->dp_symvn->vn_obj;
		node_unlink(dp->dp_symvn);
		obj_free(obj);
		path = path_make(dp->dp_rvn->vn_child);
		dp->dp_symvn = node_symlink(
		    dev_dirpath("/dev/aliases"), dp->dp_symname,
		    path, 0, NULL);
		free(path);
	}
}


/*
 * Unlabeled media was just inserted in *dp, create a "fake"
 * vol_t to represent it.
 */
vol_t *
dev_unlabeled(struct devs *dp, enum laread_res rres, label *la)
{
	vol_t	*v;


	v = (vol_t *)calloc(1, sizeof (vol_t));

	switch (rres) {
	case L_UNRECOG:
		v->v_obj.o_name = strdup(DEFAULT_UNLAB);
		break;
	case L_UNFORMATTED:
		v->v_obj.o_name = strdup(DEFAULT_UNFORMAT);
		break;
	case L_NOTUNIQUE:
		v->v_obj.o_name = strdup(DEFAULT_NOTUNIQUE);
		break;
	default:
		v->v_obj.o_name = strdup("unknown_label_type");
		debug(1, "dev_unlabeled error: laread_res == %d\n", rres);
		break;
	}
	v->v_obj.o_dir = strdup("");
	v->v_obj.o_type = VV_CHR;
	v->v_obj.o_uid = default_uid;
	v->v_obj.o_gid = default_gid;
	v->v_obj.o_mode = DEFAULT_MODE;
	v->v_obj.o_atime = current_time;
	v->v_obj.o_ctime = current_time;
	v->v_obj.o_mtime = current_time;
	v->v_mtype = strdup(dp->dp_dsw->d_mtype);
	v->v_flags |= V_UNLAB;
	v->v_basedev = NODEV;

	/* set up properties */
	if (dp->dp_dsw->d_flags & D_RMONEJECT) {
		v->v_flags |= V_RMONEJECT;
	}
	if (dp->dp_flags & DP_MEJECTABLE) {
		v->v_flags |= V_MEJECTABLE;
	}

	/* ensure the "label type" index is "none" */
	la->l_type = -1;

	/* return pointer to vol structure created */
	return (v);
}


/*
 * Find the driver that controls this device and ask it to check
 * and see if something is there.  The driver is responsible for
 * generating the check event.
 * dev_check returns:
 * 0 if it didn't find anything
 * 1 if it found something and we already knew about it
 * 2 if it found something and we generated an insert event
 */
int
dev_check(dev_t dev)
{
	struct devs	*dp;
	int		rval = 0, nrval;
	int		i;

	if (dev == NODEV) {
		/*
		 * wildcard -- loop through all the
		 * devices that have a check routine.  If anyone
		 * returns true, we return true.  It's too bad we
		 * have to wander through the hash table to iterate
		 * through the devs... oh well.
		 */
		for (i = 0; i < DEV_HASH_SIZE; i++) {
			dp = HEAD(struct devs, dev_q_hash[i]);
			while (dp != NULL) {
				if (dp->dp_dsw->d_check != NULL) {
					debug(4,
					    "dev_check: check device %d.%d\n",
					    major(dp->dp_dev),
					    minor(dp->dp_dev));
					nrval = (*dp->dp_dsw->d_check)(dp);
					debug(10, "dev_check: check -> %d\n",
					    nrval);
					if (nrval != 0) {
						dp->dp_checkresp = TRUE;
					}
					if (nrval > rval) {
						rval = nrval;
					}
				}
				dp = NEXT(struct devs, dp);
			}
		}
		return (rval);
	}

	dp = dev_getdp(dev);
	if (dp == NULL) {
		debug(4, "check device %d.%d: device not managed\n",
			major(dev), minor(dev));
		return (0);
	}
	debug(4, "dev_check: check device %d.%d\n", major(dev), minor(dev));
	if (dp->dp_dsw->d_check != NULL) {
		rval = (*dp->dp_dsw->d_check)(dp);
	}

	if (rval != 0) {
		dp->dp_checkresp = TRUE;
	}

	debug(10, "dev_check: check -> %d\n", rval);

	return (rval);
}


/*
 * Return true if a device is being managed by volume management.
 */
int
dev_inuse(dev_t dev)
{

	if (dev == NODEV) {
		debug(4, "dev_inuse: NODEV: device not managed\n");
		return (FALSE);
	}

	if (dev_getdp(dev) == NULL) {
		debug(4, "dev_inuse: %d.%d: device not managed\n",
			major(dev), minor(dev));
		return (FALSE);
	}
	return (TRUE);
}


/*
 * Return the /dev pathname given the symbolic name of a device.
 */
char *
symname_to_dev(char *symname)
{
	int		i;
	struct devs	*dp;
	char		*res = NULL;


	for (i = 0; (i < DEV_HASH_SIZE) && (res == NULL); i++) {
		for (dp = HEAD(struct devs, dev_q_hash[(uint_t)i]);
		    dp != NULL;
		    dp = NEXT(struct devs, dp)) {

			/* just in case something doesn't have any symname */
			if (dp->dp_symname == NULL) {
				continue;	/* try the next one */
			}

			if (strcmp(dp->dp_symname, symname) == 0) {
				/* found it */
				res = dp->dp_path;
				break;		/* get outta here */
			}
		}
	}
	return (res);
}

int
dev_reset_symname(struct devs *dp,
		int		fd)
{
	/*
	 * Set the symbolic name of the device to a unique name.
	 * If the smedia_get_device_info() utility returns a vendor-specific
	 * device name beginning with "ZIP", "zip", "JAZ", or "jaz", use
	 * "zip" or "jaz" as the base symbolic name and append an integer
	 * to it that distinguishes it from other symbolic names that begin
	 * with the same string.  If smedia_get_device_info() doesn't return
	 * a vendor-specific device name beginning with "ZIP", "zip", "JAZ",
	 * or "jaz", use the generic device name as the base symbolic name
	 * and append an integer to it that distinguishes it from other
	 * symbolic names that begin with the same string.
	 */

	char 			*base_symbolic_namep;
	char 			*charp;
	smdevice_info_t		device_info;
	name_factory_result_t	name_factory_result;
	int			reset_result;
	int			smedia_result;
	smedia_handle_t		handle;

	base_symbolic_namep = NULL;
	handle = smedia_get_handle(fd);
	if (handle == NULL)
		return (-1);
	smedia_result = smedia_get_device_info(handle, &device_info);
	if ((smedia_result == 0) && (device_info.sm_product_name != NULL)) {
		base_symbolic_namep = strdup(device_info.sm_product_name);
		if (base_symbolic_namep != NULL) {
			if (strlen(base_symbolic_namep) > 3) {
				base_symbolic_namep[3] = '\0';
			}
			charp = base_symbolic_namep;
			while (*charp != '\0') {
				*charp = (char)tolower((int)*charp);
				charp++;
			}
		}
	}
	if (base_symbolic_namep != NULL &&
	    (strcmp(base_symbolic_namep, "zip") == 0 ||
	    strcmp(base_symbolic_namep, "jaz") == 0)) {
		name_factory_result = name_factory_make_name(dp->dp_symname,
			base_symbolic_namep, &charp);
		free(base_symbolic_namep);
		free(dp->dp_symname);
		dp->dp_symname = charp;
		if (name_factory_result == NAME_FACTORY_SUCCESS) {
			reset_result = 0;
		} else {
			reset_result = -1;
		}
	} else {
		if (base_symbolic_namep != NULL)
			free(base_symbolic_namep);
		reset_result = 0;
	}
	if (smedia_result == 0)
		(void) smedia_free_device_info(handle, &device_info);
	(void) smedia_release_handle(handle);
	return (reset_result);
}

/*
 * create "nomedia" device node
 */
void
dev_create_ctldev(struct devs *dp)
{
	char		path[MAXPATHLEN];
	char		pathtmp[MAXPATHLEN];
	char		*s, *nm;
	vvnode_t	*dvn;
	vol_t		*v;
	uint_t		error;

	debug(11, "dev_create_ctldev: entering\n");

	if (dp->dp_ctlvol != NULL) {
		debug(11, "dev_create_ctldev: dp->dp_ctlvol != NULL\n");
		return;
	}

	/*
	 * first try to create the default device node.
	 */
	(void) strcpy(path, dp->dp_path);

	/* remove slice info if device is not floppy */
	if (!strstr(dp->dp_path, "rdiskette")) {
		path[(strlen(path) - (2 * (sizeof (char))))] = '\0';
	}

	(void) strcat(path, "/nomedia");
	(void) strcpy(pathtmp, path);

	if ((s = strrchr(path, '/')) == NULL) {
		debug(11, "dev_create_ctldev: strrchr failed\n");
		return;
	}
	*s = '\0';
	nm = s + 1;
	if ((dvn = dev_dirpath(path)) == NULL) {
		debug(11, "dev_create_ctldev: dvn NULL\n");
		return;
	}
	v = vold_calloc(1, sizeof (vol_t));
	v->v_obj.o_name = vold_strdup(nm);
	v->v_obj.o_dir = vold_strdup(path);
	v->v_obj.o_type = VV_CHR;
	/* device owned by root */
	v->v_obj.o_uid = dp->dp_dsw->d_uid;
	v->v_obj.o_gid = dp->dp_dsw->d_gid;
	v->v_obj.o_mode = DEFAULT_MODE;
	v->v_obj.o_atime = current_time;
	v->v_obj.o_ctime = current_time;
	v->v_obj.o_mtime = current_time;
	v->v_mtype = vold_strdup(dp->dp_dsw->d_mtype);
	v->v_flags |= V_UNLAB|V_CTLVOL;
	if (dp->dp_flags & DP_MEJECTABLE) {
		v->v_flags |= V_MEJECTABLE;
	}
	dp->dp_cvn = node_mkobj(dvn, (obj_t *)v, NODE_TMPID|NODE_CHR, &error);
	dp->dp_ctlvol = v;
	change_location((obj_t *)v, dp->dp_path);
	v->v_confirmed = TRUE;
	v->v_fstype = V_UNKNOWN;
	v->v_parts = (1<<DEFAULT_PARTITION);
	v->v_ndev = 1;
	v->v_device = dp->dp_dev;
	/*
	 * create device mapping.
	 */
	dev_devmap(v);
	(void) dev_map_dropin(v);

	/*
	 * create symbolic link from aliases.
	 */
	if ((dvn = dev_dirpath(DEFAULT_ALIAS_DIR_NAME)) == NULL) {
		debug(11, "dev_create_ctldev: dvn NULL\n");
		return;
	}
	(void) strcpy(path, vold_root);
	(void) strlcat(path, pathtmp, sizeof (path));
	dp->dp_csymvn = node_symlink(dvn, dp->dp_symname,
		path, NODE_TMPID, NULL);
	/* cleanup */
	if (dp->dp_csymvn == NULL) {
		dev_remove_ctldev(dp);
	}

	debug(11, "dev_create_ctldev: returning\n");
}

void
dev_remove_ctldev(struct devs *dp)
{
	debug(11, "dev_remove_ctldev: entering\n");

	if (dp->dp_csymvn != NULL) {
		node_unlink(dp->dp_csymvn);
	}
	if (dp->dp_cvn != NULL) {
		node_unlink(dp->dp_cvn);
	}
	dp->dp_cvn = NULL;
	destroy_volume(dp->dp_ctlvol);
	dp->dp_ctlvol = NULL;

	debug(11, "dev_remove_ctldev: returning\n");
}
