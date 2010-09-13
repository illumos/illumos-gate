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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

/*
 * manipulate set list
 */

/*
 * global set list
 */
static	mutex_t		mhd_set_mx = DEFAULTMUTEX;
static	uint_t		mhd_nset = 0;
static	mhd_drive_set_t	**mhd_sets = NULL;

/*
 * add drive to set
 */
void
mhd_add_drive_to_set(
	mhd_drive_set_t		*sp,
	mhd_drive_t		*dp
)
{
	mhd_drive_list_t	*dlp = &sp->sr_drives;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(DRIVE_IS_IDLE(dp));

	/* add to set */
	mhd_add_drive(dlp, dp);

	/* adjust backlink */
	dp->dr_sp = sp;
}

/*
 * delete drive from set
 */
void
mhd_del_drive_from_set(
	mhd_drive_t		*dp
)
{
	mhd_drive_set_t		*sp = dp->dr_sp;
	mhd_drive_list_t	*dlp = &sp->sr_drives;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(DRIVE_IS_IDLE(dp));

	/* delete from set */
	mhd_del_drive(dlp, dp);

	/* adjust backlink */
	dp->dr_sp = NULL;
}

/*
 * find set in list
 */
static mhd_drive_set_t *
mhd_find_set(
	char	*setname
)
{
	uint_t	i;

	/* check lock */
	assert(MUTEX_HELD(&mhd_set_mx));

	/* look for set */
	for (i = 0; (i < mhd_nset); ++i) {
		mhd_drive_set_t	*sp = mhd_sets[i];

		if (strcmp(setname, sp->sr_name) == 0)
			return (sp);
	}

	/* not found */
	return (NULL);
}

/*
 * wait for operation to complete
 */
static void
mhd_wait_set(
	mhd_drive_set_t		*sp,
	mhd_drive_list_t	*dlp,
	mhd_state_t		state
)
{
	/* check lock */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));

	/* wait for complete */
	for (;;) {
		uint_t	cnt = 0;
		uint_t	i;

		/* kick threads */
		for (i = 0; (i < dlp->dl_ndrive); ++i) {
			mhd_drive_t	*dp = dlp->dl_drives[i];

			/* IDLE or ERRORED */
			if (state == DRIVE_IDLE) {
				if (DRIVE_IS_IDLE(dp))
					continue;
			}

			/* operation complete */
			else {
				if (! (dp->dr_state & state))
					continue;
			}

			/* kick thread */
			mhd_cv_broadcast(&dp->dr_cv);
			++cnt;
		}

		/* if complete, quit */
		if (cnt == 0)
			break;

		/* wait for something to happen */
		(void) mhd_cv_wait(&sp->sr_cv, &sp->sr_mx);
	}
}

/*
 * idle set
 */
static int
mhd_idle_set(
	mhd_drive_set_t		*sp,
	mhd_drive_list_t	*dlp,
	mhd_error_t		*mhep
)
{
	uint_t			i;

	/* check lock */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));

	/* disarm any failfast */
	if (dlp->dl_ndrive >= sp->sr_drives.dl_ndrive) {
		if (mhd_ff_disarm(sp, mhep) != 0)
			return (-1);
	}

	/* set IDLING */
	for (i = 0; (i < dlp->dl_ndrive); ++i) {
		mhd_drive_t	*dp = dlp->dl_drives[i];

		if (! DRIVE_IS_IDLE(dp)) {
			if (mhd_state(dp, DRIVE_IDLING, mhep) != 0)
				return (-1);
		}
	}

	/* wait for IDLE */
	mhd_wait_set(sp, dlp, DRIVE_IDLE);

	/* return success */
	return (0);
}

/*
 * create or update new set
 */
mhd_drive_set_t *
mhd_create_set(
	mhd_set_t		*mhsp,
	mhd_opts_t		options,
	mhd_drive_list_t	*dlp,
	mhd_error_t		*mhep
)
{
	char			*setname;
	mhd_drive_set_t		*sp;
	mhd_drive_list_t	*sp_dlp;
	mhd_drive_set_t		*null_sp;
	uint_t			i;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));

	/* get setname */
	if (mhsp == NULL)
		setname = "";
	else
		setname = mhsp->setname;

	/* find or create set */
	if ((sp = mhd_find_set(setname)) == NULL) {
		/* allocate and initialize set */
		sp = Zalloc(sizeof (*sp));
		sp->sr_name = Strdup(setname);
		mhd_mx_init(&sp->sr_mx);
		mhd_cv_init(&sp->sr_cv);
		sp->sr_ff = -1;

		/* append to set list */
		++mhd_nset;
		mhd_sets = Realloc(mhd_sets, (mhd_nset * sizeof (*mhd_sets)));
		mhd_sets[mhd_nset - 1] = sp;
	}
	sp_dlp = &sp->sr_drives;

	/* if just grabbing null set, return */
	if (mhsp == NULL)
		return (sp);
	assert(strcmp(setname, "") != 0);
	assert(mhep != NULL);

	/* get null set */
	null_sp = mhd_create_set(NULL, 0, NULL, NULL);
	assert(null_sp != NULL);
	assert(sp != null_sp);

	/* grab set lock */
	mhd_mx_lock(&sp->sr_mx);

	/* save options */
	if (options & MHD_SERIAL)
		sp->sr_options |= MHD_SERIAL;
	else
		sp->sr_options &= ~MHD_SERIAL;

	/* move drives no longer in set to null set */
	if (! (options & MHD_PARTIAL_SET)) {
		for (i = 0; (i < sp_dlp->dl_ndrive); /* void */) {
			mhd_drive_t	*dp = sp_dlp->dl_drives[i];
			uint_t		j;

			/* check still there */
			for (j = 0; (j < mhsp->drives.drives_len); ++j) {
				mhd_drivename_t	mhdp;

				mhdp = mhsp->drives.drives_val[j];
				if (strcmp(dp->dr_rname, mhdp) == 0)
					break;
			}
			if (j < mhsp->drives.drives_len) {
				++i;
				continue;
			}

			/* idle the drive */
			if (mhd_idle(dp, mhep) != 0)
				mhd_clrerror(mhep);

			/* move to null set */
			mhd_del_drive_from_set(dp);
			mhd_mx_unlock(&sp->sr_mx);
			mhd_mx_lock(&null_sp->sr_mx);
			mhd_add_drive_to_set(null_sp, dp);
			mhd_mx_unlock(&null_sp->sr_mx);
			mhd_mx_lock(&sp->sr_mx);
		}
	}

	/* add new drives to lists */
	for (i = 0; (i < mhsp->drives.drives_len); ++i) {
		mhd_drivename_t	mhdp = mhsp->drives.drives_val[i];
		uint_t		j;
		mhd_drive_t	*dp;

		/* check already there */
		for (j = 0; (j < dlp->dl_ndrive); ++j) {
			dp = dlp->dl_drives[j];
			if (strcmp(mhdp, dp->dr_rname) == 0)
				break;
		}
		if (j < dlp->dl_ndrive) {
			mhd_add_drive(dlp, dp);
			continue;
		}

		/* add drive to set */
		if ((dp = mhd_create_drive(sp, mhdp, NULL, mhep)) == NULL) {
			mhde_perror(mhep, "mhd_create_drive: %s", mhdp);
			continue;
		}
		mhd_add_drive(dlp, dp);
	}

	/* debug */
#ifdef	MHD_DEBUG
	if (mhd_debug > 0) {
		for (i = 0; (i < mhd_nset); ++i) {
			mhd_drive_set_t		*sp = mhd_sets[i];
			mhd_drive_list_t	*dlp = &sp->sr_drives;
			char			buf[10240];
			uint_t			j;

			(void) snprintf(buf, sizeof (buf), "set '%s':",
			    sp->sr_name);
			for (j = 0; (j < dlp->dl_ndrive); ++j) {
				mhd_drive_t	*dp = dlp->dl_drives[j];
				char		*p;

				if ((p = strrchr(dp->dr_rname, '/')) != NULL)
					++p;
				else
					p = dp->dr_rname;
				(void) strncat(buf, " ", sizeof (buf));
				(void) strncat(buf, p, sizeof (buf));
			}
			buf[sizeof (buf) - 1] = '\0';
			mhd_eprintf("%s\n", buf);
		}
	}
#endif	/* MHD_DEBUG */

	/* unlock, return set */
	mhd_mx_unlock(&sp->sr_mx);
	return (sp);
}

/*
 * find drive
 */
mhd_drive_t *
mhd_find_drive(
	char		*rname
)
{
	uint_t		i;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));

	/* for each set */
	for (i = 0; (i < mhd_nset); ++i) {
		mhd_drive_set_t		*sp = mhd_sets[i];
		mhd_drive_list_t	*dlp = &sp->sr_drives;
		uint_t			j;

		/* for each drive */
		for (j = 0; (j < dlp->dl_ndrive); ++j) {
			mhd_drive_t	*dp = dlp->dl_drives[j];

			if (strcmp(rname, dp->dr_rname) == 0)
				return (dp);
		}
	}

	/* not found */
	return (NULL);
}

/*
 * list all the drives
 */
int
mhd_list_drives(
	char		*path,
	mhd_did_flags_t	flags,
	mhd_list_res_t	*resultsp,
	mhd_error_t	*mhep
)
{
	mhd_state_t	state;
	uint_t		ndrive, i, j, c;

	/* grab lock */
	mhd_mx_lock(&mhd_set_mx);

	/* add path to list */
	if (mhd_create_drives(path, mhep) != 0) {
		mhd_mx_unlock(&mhd_set_mx);
		return (-1);
	}

	/* get what we want */
	state = 0;
	if (flags & MHD_DID_SERIAL)
		state |= DRIVE_SERIALING;
	if (flags & MHD_DID_TIME)
		state |= DRIVE_VTOCING;
	if (flags & MHD_DID_CINFO)
		state |= DRIVE_CINFOING;

	/* ident and count drives */
	for (ndrive = 0, i = 0; (i < mhd_nset); ++i) {
		mhd_drive_set_t		*sp = mhd_sets[i];
		mhd_drive_list_t	*dlp = &sp->sr_drives;

		/* count drives */
		ndrive += dlp->dl_ndrive;

		/* ident drives */
		if (state != 0) {
			mhd_mx_lock(&sp->sr_mx);
			for (j = 0; (j < dlp->dl_ndrive); ++j) {
				mhd_drive_t	*dp = dlp->dl_drives[j];

				if (mhd_state_set(dp, state, mhep) != 0) {
					mhd_mx_unlock(&sp->sr_mx);
					mhd_mx_unlock(&mhd_set_mx);
					return (-1);
				}
			}
			mhd_wait_set(sp, dlp, state);
			mhd_mx_unlock(&sp->sr_mx);
		}
	}

	/* build list */
	assert(resultsp->results.mhd_drive_info_list_t_len == 0);
	assert(resultsp->results.mhd_drive_info_list_t_val == NULL);
	resultsp->results.mhd_drive_info_list_t_len = ndrive;
	resultsp->results.mhd_drive_info_list_t_val = Zalloc(
	    ndrive * sizeof (*resultsp->results.mhd_drive_info_list_t_val));
	for (c = 0, i = 0; (i < mhd_nset); ++i) {
		mhd_drive_set_t		*sp = mhd_sets[i];
		mhd_drive_list_t	*dlp = &sp->sr_drives;

		mhd_mx_lock(&sp->sr_mx);
		for (j = 0; (j < dlp->dl_ndrive); ++j) {
			mhd_drive_t	*dp = dlp->dl_drives[j];
			mhd_drive_info_t *ip =
			    &resultsp->results.mhd_drive_info_list_t_val[c++];

			ip->dif_name = Strdup(dp->dr_rname);
			ip->dif_id = dp->dr_drive_id;
		}
		mhd_mx_unlock(&sp->sr_mx);
	}
	assert(c == ndrive);

	/* unlock, return count */
	mhd_mx_unlock(&mhd_set_mx);
	return (ndrive);
}

/*
 * release drives
 */
static int
mhd_release_set(
	mhd_drive_set_t		*sp,
	mhd_drive_list_t	*dlp,
	mhd_error_t		*mhep
)
{
	uint_t			i;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));

	/* idle set */
	if (mhd_idle_set(sp, dlp, mhep) != 0)
		return (-1);

	/* release drives */
	for (i = 0; (i < dlp->dl_ndrive); i++) {
		mhd_drive_t	*dp = dlp->dl_drives[i];

		if (mhd_state(dp, DRIVE_RELEASING, mhep) != 0)
			return (-1);
	}
	mhd_wait_set(sp, dlp, DRIVE_IDLE);

	/* return success */
	return (0);
}

/*
 * release drives in set
 */
int
mhd_release_drives(
	mhd_set_t		*mhsp,
	mhd_opts_t		options,
	mhd_error_t		*mhep
)
{
	mhd_drive_list_t	dl = mhd_null_list;
	mhd_drive_set_t		*sp;
	int			rval;

	/* grab global lock */
	mhd_mx_lock(&mhd_set_mx);

	/* create or update set */
	if ((sp = mhd_create_set(mhsp, options, &dl, mhep)) == NULL) {
		mhd_mx_unlock(&mhd_set_mx);
		mhd_free_list(&dl);
		return (-1);
	}

	/* lock set */
	mhd_mx_lock(&sp->sr_mx);

	/* release drives */
	rval = mhd_release_set(sp, &dl, mhep);

	/* unlock, return success */
out:
	mhd_mx_unlock(&sp->sr_mx);
	mhd_mx_unlock(&mhd_set_mx);
	mhd_free_list(&dl);
	return (rval);
}

/*
 * reserve drives
 */
static int
mhd_reserve_set(
	mhd_drive_set_t		*sp,
	mhd_drive_list_t	*dlp,
	mhd_error_t		*mhep
)
{
	mhd_msec_t		ff = sp->sr_timeouts.mh_ff;
	uint_t			retry, i, ok;
	int			rval = 0;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));

	/* idle set, idle everyone if cancelling failfast */
	if (ff == 0) {
		if (mhd_idle_set(sp, &sp->sr_drives, mhep) != 0)
			return (-1);
	} else {
		if (mhd_idle_set(sp, dlp, mhep) != 0)
			return (-1);
	}

	/*
	 * Try to take ownership of the drives twice. This helps
	 * to avoid the situation where the other machine retakes
	 * ownership of a majority drives back, but then kills itself
	 * leaving no owners.
	 */
	for (retry = 0; (retry < 2); ++retry) {
		for (i = 0; (i < dlp->dl_ndrive); i++) {
			mhd_drive_t	*dp = dlp->dl_drives[i];

			if ((retry == 0) ||
			    ((dp->dr_state == DRIVE_ERRORED) &&
			    (dp->dr_errnum == EACCES))) {
				if (mhd_state(dp, DRIVE_RESERVING, mhep) != 0)
					return (-1);
			}
		}
		mhd_wait_set(sp, dlp, DRIVE_IDLE);
	}

	/*
	 * Did the take ownership succeed on a majority of the drives?
	 */
	ok = 0;
	for (i = 0; (i < dlp->dl_ndrive); ++i) {
		mhd_drive_t	*dp = dlp->dl_drives[i];

		if (dp->dr_state == DRIVE_IDLE)
			++ok;
	}

	/*
	 * Let the replica majority be the deciding factor, if able to get
	 * at least a single drive reserved.
	 */
	if (ok == 0) {
		rval = mhd_error(mhep, MHD_E_MAJORITY, sp->sr_name);
		goto out;
	}

	/*
	 * Enable the failfast probes if we haven't given up yet.
	 */
	switch (sp->sr_ff_mode) {

	/* do nothing */
	default:
		assert(0);
		/* FALLTHROUGH */
	case MHD_FF_NONE:
		goto out;

	/* old style per drive failfast */
	case MHD_FF_DRIVER:
		for (i = 0; (i < dlp->dl_ndrive); i++) {
			mhd_drive_t	*dp = dlp->dl_drives[i];

			if (dp->dr_state != DRIVE_ERRORED) {
				if (mhd_state(dp, DRIVE_FAILFASTING,
				    mhep) != 0) {
					rval = -1;
					goto out;
				}
			}
		}
		mhd_wait_set(sp, dlp, DRIVE_IDLE);
		break;

	/* failfast probe threads */
	case MHD_FF_DEBUG:
	case MHD_FF_HALT:
	case MHD_FF_PANIC:
		if (ff != 0) {
			if (mhd_ff_open(sp, mhep) != 0) {
				rval = -1;
				goto out;
			}
			for (i = 0; (i < dlp->dl_ndrive); i++) {
				mhd_drive_t	*dp = dlp->dl_drives[i];

				if (mhd_state_set(dp, DRIVE_PROBING,
				    mhep) != 0) {
					rval = -1;
					goto out;
				}
				dp->dr_time = mhd_time();
			}
			(void) mhd_ff_rearm(sp, mhep);
		}
		break;
	}

	/* cleanup, return success */
out:
	if (rval != 0) {
		mhd_error_t	status = mhd_null_error;

		(void) mhd_release_set(sp, dlp, &status);
		mhd_clrerror(&status);
	}
	return (rval);
}

/*
 * reserve drives in set
 */
int
mhd_reserve_drives(
	mhd_set_t		*mhsp,
	mhd_mhiargs_t		*timeoutp,
	mhd_ff_mode_t		ff_mode,
	mhd_opts_t		options,
	mhd_error_t		*mhep
)
{
	mhd_drive_list_t	dl = mhd_null_list;
	mhd_drive_set_t		*sp;
	int			rval;

	/* grab global lock */
	mhd_mx_lock(&mhd_set_mx);

	/* create or update set */
	if ((sp = mhd_create_set(mhsp, options, &dl, mhep)) == NULL) {
		mhd_mx_unlock(&mhd_set_mx);
		mhd_free_list(&dl);
		return (-1);
	}

	/* lock set */
	mhd_mx_lock(&sp->sr_mx);

	/* can't change mode or timeouts of partial set */
	if ((dl.dl_ndrive != sp->sr_drives.dl_ndrive) &&
	    (options & MHD_PARTIAL_SET)) {
		if (ff_mode != sp->sr_ff_mode) {
			mhd_eprintf("%s: invalid ff_mode %d now %d\n",
			    sp->sr_name, ff_mode, sp->sr_ff_mode);
			ff_mode = sp->sr_ff_mode;
		}
		if (timeoutp->mh_ff < sp->sr_timeouts.mh_ff) {
			mhd_eprintf("%s: invalid mh_ff %d now %d\n",
			    sp->sr_name, timeoutp->mh_ff,
			    sp->sr_timeouts.mh_ff);
			timeoutp->mh_ff = sp->sr_timeouts.mh_ff;
		}
	}

	/* save timouts and mode */
	sp->sr_timeouts = *timeoutp;
	sp->sr_ff_mode = ff_mode;

	/* reserve drives */
	rval = mhd_reserve_set(sp, &dl, mhep);

	/* unlock, return success */
out:
	mhd_mx_unlock(&sp->sr_mx);
	mhd_mx_unlock(&mhd_set_mx);
	mhd_free_list(&dl);
	return (rval);
}

/*
 * status drives
 */
static int
mhd_status_set(
	mhd_drive_set_t		*sp,
	mhd_drive_list_t	*dlp,
	mhd_error_t		*mhep
)
{
	uint_t			i;

	/* check locks */
	assert(MUTEX_HELD(&mhd_set_mx));
	assert(MUTEX_HELD(&sp->sr_mx));

	/* status drives */
	for (i = 0; (i < dlp->dl_ndrive); i++) {
		mhd_drive_t	*dp = dlp->dl_drives[i];

		if (mhd_state_set(dp, DRIVE_STATUSING, mhep) != 0)
			return (-1);
	}
	mhd_wait_set(sp, dlp, DRIVE_STATUSING);

	/* return success */
	return (0);
}

/*
 * status drives in set
 */
int
mhd_status_drives(
	mhd_set_t		*mhsp,
	mhd_opts_t		options,
	mhd_drive_status_t	**status,
	mhd_error_t		*mhep
)
{
	mhd_drive_list_t	dl = mhd_null_list;
	mhd_drive_list_t	*dlp = &dl;
	mhd_drive_set_t		*sp;
	uint_t			i;
	int			rval = 0;

	/* grab global lock */
	mhd_mx_lock(&mhd_set_mx);

	/* create or update set */
	if ((sp = mhd_create_set(mhsp, options, &dl, mhep)) == NULL) {
		mhd_mx_unlock(&mhd_set_mx);
		mhd_free_list(&dl);
		return (-1);
	}

	/* lock set */
	mhd_mx_lock(&sp->sr_mx);

	/* status drives */
	if (mhd_status_set(sp, &dl, mhep) != 0) {
		rval = -1;
		goto out;
	}

	/* build list */
	*status = Zalloc(dlp->dl_ndrive * sizeof (**status));
	for (i = 0; (i < dlp->dl_ndrive); ++i) {
		mhd_drive_t		*dp = dlp->dl_drives[i];
		mhd_drive_status_t	*statusp = &(*status)[i];

		statusp->drive = Strdup(dp->dr_rname);
		statusp->errnum = dp->dr_errnum;
	}
	assert(i == dlp->dl_ndrive);
	rval = dlp->dl_ndrive;

	/* unlock, return count */
out:
	mhd_mx_unlock(&sp->sr_mx);
	mhd_mx_unlock(&mhd_set_mx);
	mhd_free_list(&dl);
	return (rval);
}
