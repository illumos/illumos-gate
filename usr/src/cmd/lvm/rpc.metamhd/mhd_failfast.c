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
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

#include <stropts.h>
#include "ff.h"

/*
 * manipulate failfast driver
 */

/*
 * disarm failfast
 */
int
mhd_ff_disarm(
	mhd_drive_set_t	*sp,
	mhd_error_t	*mhep
)
{
	struct strioctl	si;

	MHDPRINTF1(("%s: disarm\n", sp->sr_name));

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));

	/* ignore not open */
	if (sp->sr_ff < 0)
		return (0);

	/* disarm any existing failfast */
	(void) memset(&si, 0, sizeof (si));
	si.ic_cmd = FAILFAST_DISARM;
	si.ic_timout = INFTIM;
	if (ioctl(sp->sr_ff, I_STR, &si) != 0)
		return (mhd_error(mhep, errno, "/dev/ff"));

	/* return success */
	return (0);
}

/*
 * open failfast
 */
int
mhd_ff_open(
	mhd_drive_set_t	*sp,
	mhd_error_t	*mhep
)
{
	struct strioctl	si;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert((sp->sr_ff_mode == MHD_FF_DEBUG) ||
	    (sp->sr_ff_mode == MHD_FF_HALT) ||
	    (sp->sr_ff_mode == MHD_FF_PANIC));

	/* open if not already */
	if ((sp->sr_ff < 0) &&
	    ((sp->sr_ff = open("/dev/ff", O_RDWR, 0)) < 0)) {
		return (mhd_error(mhep, errno, "/dev/ff"));
	}

	/* disarm any existing failfast */
	if (mhd_ff_disarm(sp, mhep) != 0)
		return (-1);

	/* load setname */
	(void) memset(&si, 0, sizeof (si));
	si.ic_cmd = FAILFAST_SETNAME;
	si.ic_timout = INFTIM;
	si.ic_len = strlen(sp->sr_name);
	si.ic_dp = sp->sr_name;
	if (ioctl(sp->sr_ff, I_STR, &si) != 0)
		return (mhd_error(mhep, errno, "/dev/ff"));

	/* load failfast mode */
	(void) memset(&si, 0, sizeof (si));
	switch (sp->sr_ff_mode) {
	case MHD_FF_DEBUG:
		si.ic_cmd = FAILFAST_DEBUG_MODE;
		break;
	case MHD_FF_HALT:
		si.ic_cmd = FAILFAST_HALT_MODE;
		break;
	default:
		assert(0);
		/* FALLTHROUGH */
	case MHD_FF_PANIC:
		si.ic_cmd = FAILFAST_PANIC_MODE;
		break;
	}
	si.ic_timout = INFTIM;
	if (ioctl(sp->sr_ff, I_STR, &si) != 0)
		return (mhd_error(mhep, errno, "/dev/ff"));

	/* return success */
	return (0);
}

/*
 * close failfast
 */
int
mhd_ff_close(
	mhd_drive_set_t	*sp,
	mhd_error_t	*mhep
)
{
	int		rval = 0;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));

	/* ignore not open */
	if (sp->sr_ff < 0)
		return (0);

	/* disarm any existing failfast */
	if (mhd_ff_disarm(sp, mhep) != 0)
		rval = -1;

	/* close device */
	if (close(sp->sr_ff) != 0)
		rval = mhd_error(mhep, errno, "/dev/ff");
	sp->sr_ff = -1;

	/* return success */
	return (rval);
}

/*
 * reset failfast
 */
int
mhd_ff_rearm(
	mhd_drive_set_t	*sp,
	mhd_error_t	*mhep
)
{
	uint_t		ff = sp->sr_timeouts.mh_ff;
	struct strioctl	si;

	MHDPRINTF1(("%s: rearm\n", sp->sr_name));

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(sp->sr_ff >= 0);

	/* if timeout is 0, disarm */
	if (ff == 0)
		return (mhd_ff_disarm(sp, mhep));

	/* rearm failfast */
	(void) memset(&si, 0, sizeof (si));
	si.ic_cmd = FAILFAST_ARM;
	si.ic_timout = INFTIM;
	si.ic_len = sizeof (ff);
	si.ic_dp = (char *)&ff;
	if (ioctl(sp->sr_ff, I_STR, &si) != 0)
		return (mhd_error(mhep, errno, "/dev/ff"));

	/* return success */
	return (0);
}

/*
 * die right now
 */
void
mhd_ff_die(
	mhd_drive_set_t	*sp
)
{
	uint_t		ff = 0;
	struct strioctl	si;

	MHDPRINTF(("%s: die\n", sp->sr_name));

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(sp->sr_ff >= 0);

	/* rearm failfast for now */
	(void) memset(&si, 0, sizeof (si));
	si.ic_cmd = FAILFAST_ARM;
	si.ic_timout = INFTIM;
	si.ic_len = sizeof (ff);
	si.ic_dp = (char *)&ff;
	if (ioctl(sp->sr_ff, I_STR, &si) != 0)
		mhd_perror("/dev/ff");
}

/*
 * check set and reset failfast
 */
void
mhd_ff_check(
	mhd_drive_set_t		*sp
)
{
	mhd_drive_list_t	*dlp = &sp->sr_drives;
	mhd_msec_t		ff = sp->sr_timeouts.mh_ff;
	mhd_msec_t		now = mhd_time();
	uint_t			i, ok, cnt;

	/* check locks */
	assert(MUTEX_HELD(&sp->sr_mx));
	assert(sp->sr_ff >= 0);
	assert((sp->sr_ff_mode == MHD_FF_DEBUG) ||
	    (sp->sr_ff_mode == MHD_FF_HALT) ||
	    (sp->sr_ff_mode == MHD_FF_PANIC));

	/* see how many drives are within alloted time */
	for (ok = cnt = 0, i = 0; (i < dlp->dl_ndrive); ++i) {
		mhd_drive_t	*dp = dlp->dl_drives[i];

		if (dp->dr_state != DRIVE_PROBING)
			continue;
		++cnt;

		MHDPRINTF2(("%s: now %llu dr_time %llu diff %llu ff %llu\n",
		    dp->dr_rname, now, dp->dr_time, (now - dp->dr_time), ff));
		if ((now - dp->dr_time) <= ff)
			++ok;
	}

	/* check for majority */
	if ((cnt == 0) || (ok >= ((cnt / 2) + 1))) {
		mhd_error_t	status = mhd_null_error;

		if (mhd_ff_rearm(sp, &status) == 0)
			return;
		mhd_clrerror(&status);
	}

	/* die */
	mhd_eprintf("%s: failed majority cnt %d ok %d\n",
	    sp->sr_name, cnt, ok);
	mhd_ff_die(sp);
}
