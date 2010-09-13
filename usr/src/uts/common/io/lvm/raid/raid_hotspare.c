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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * NAME:	raid_hotspare.c
 * DESCRIPTION: RAID driver source file containing routines related to
 *		hospare operation.
 * ROUTINES PROVIDED FOR EXTERNAL USE:
 * raid_hs_release() - release a hotspare device
 *  raid_hotspares() - prompt the hospare daemon to attempt needed hotspare work
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/buf.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/lvm/md_raid.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern mdq_anchor_t	md_hs_daemon;
static daemon_request_t hotspare_request;

extern md_set_t		md_set[];
extern md_ops_t 	raid_md_ops;

/*
 * NAME:	raid_hs_release
 *
 * DESCRIPTION: Release the hotspare.
 *
 * PARAMETERS:	int error - indication of error on hotspare
 *		mr_unit_t  *un - raid unit
 *		mddb_recid_t  *recids - output records to commit revised hs info
 *		int hs_index - component to release
 *
 * LOCKS:	Expects Unit Writer Lock to be held across call.
 */
void
raid_hs_release(
	hs_cmds_t	cmd,
	mr_unit_t	*un,
	mddb_recid_t	*recids,
	int		hs_index
)
{
	mr_column_t	*col;

	col = &un->un_column[hs_index];

	/* close the hotspare device */
	if (col->un_devflags & MD_RAID_DEV_ISOPEN) {
		md_layered_close(col->un_dev, MD_OFLG_NULL);
		col->un_devflags &= ~MD_RAID_DEV_ISOPEN;
	}

	/* return the hotspare to the pool */
	(void) md_hot_spare_ifc(cmd, un->un_hsp_id, 0, 0, recids,
	    &col->un_hs_key, NULL, NULL);

	col->un_hs_pwstart = 0;
	col->un_hs_devstart = 0;
	col->un_hs_id = (mddb_recid_t)0;
	col->un_hs_key = 0;
}


/*
 * NAME:	check_comp_4_hs
 *
 * DESCRIPTION: Check whether the input component has an error and can be
 *		backed with a hot spare (RCS_ERRED state), and initiate
 *		a resync if so.
 *
 * PARAMETERS:	mr_unit_t *un - raid unit
 *		int hs_index	- component to check
 *
 * LOCKS:	Expects Unit Writer Lock to be held upon entrance.  Releases
 *		the lock prior to calling raid_resync_unit, then reacquires
 *		it before returning.
 */
static void
check_comp_4_hs(
	mr_unit_t *un,
	int hs_index
)
{
	mddb_recid_t	recids[3];
	minor_t		mnum = MD_SID(un);
	mdi_unit_t	*ui;
	rcs_state_t	state;
	diskaddr_t	size;
	int		err;
	mr_column_t	*col;
	md_error_t	mde = mdnullerror;
	char		devname[MD_MAX_CTDLEN];
	char		hs_devname[MD_MAX_CTDLEN];
	set_t		setno;
	md_dev64_t	tmpdev;
	diskaddr_t	tmpdaddr;


	/* initialize */
	setno = MD_UN2SET(un);
	ui = MDI_UNIT(mnum);
	md_unit_readerexit(ui);
	(void) md_io_writerlock(ui);
	un = (mr_unit_t *)md_unit_writerlock(ui);
	col = &un->un_column[hs_index];

	/*
	 * add a hotspare for erred column only if not resyncing
	 */
	if ((!(COLUMN_STATE(un, hs_index) & RCS_ERRED)) ||
	    (raid_state_cnt(un, (RCS_ERRED | RCS_LAST_ERRED)) != 1) ||
	    (raid_state_cnt(un, RCS_RESYNC) > 0)) {
		goto errout;
	}

	recids[0] = 0;
	recids[1] = 0;
	/* if there is already a hotspare then just return */
	if (HOTSPARED(un, hs_index) && (col->un_devstate & RCS_ERRED)) {
		raid_hs_release(HS_BAD, un, &recids[0], hs_index);
		cmn_err(CE_WARN, "md: %s: %s hotspare errored and released",
		    md_shortname(mnum),
		    md_devname(MD_MIN2SET(mnum), col->un_dev, NULL, 0));
		col->un_dev = col->un_orig_dev;
		col->un_pwstart = col->un_orig_pwstart;
		col->un_devstart = col->un_orig_devstart;
		raid_commit(un, recids);

		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_HS_FREED, SVM_TAG_METADEVICE,
		    setno, MD_SID(un));
	}
	ASSERT(!HOTSPARED(un, hs_index));

	state = col->un_devstate;
	size = col->un_pwstart + un->un_pwsize +
	    (un->un_segsize * un->un_segsincolumn);

again:
	/* quit if resync is already active */
	col->un_devflags |= MD_RAID_REGEN_RESYNC;
	if (resync_request(mnum, hs_index, 0, NULL))
		goto errout;

	recids[0] = 0;
	recids[1] = 0;

	tmpdev = col->un_dev;
	tmpdaddr = col->un_hs_pwstart;

	/* get a hotspare */
	if (md_hot_spare_ifc(HS_GET, un->un_hsp_id, size,
	    ((col->un_orig_pwstart >= 1) &&
	    (col->un_orig_pwstart != MD_DISKADDR_ERROR)),
	    &col->un_hs_id, &col->un_hs_key, &tmpdev, &tmpdaddr) != 0) {
		col->un_dev = tmpdev;
		col->un_hs_pwstart = tmpdaddr;
		release_resync_request(mnum);
		raid_set_state(un, hs_index, state, 1);
		goto errout;
	}

	col->un_hs_pwstart = tmpdaddr;

	/*
	 * record id is filled in by raid_commit, recids[0] filled in by
	 * md_hot_spare_ifc if needed
	 */
	recids[0] = col->un_hs_id;
	recids[1] = 0;

	/*
	 * close the device and open the hot spare.  The device should
	 * never be a hotspare here.
	 */
	if (col->un_devflags & MD_RAID_DEV_ISOPEN) {
		md_layered_close(col->un_orig_dev, MD_OFLG_NULL);
		col->un_devflags &= ~MD_RAID_DEV_ISOPEN;
	}
	/*
	 * Try open by device id
	 */
	tmpdev = md_resolve_bydevid(mnum, tmpdev, col->un_hs_key);
	if (md_layered_open(mnum, &tmpdev, MD_OFLG_NULL)) {
		md_dev64_t hs_dev = tmpdev;
		/* cannot open return to orig */
		raid_hs_release(HS_BAD, un, &recids[0], hs_index);
		release_resync_request(mnum);
		raid_set_state(un, hs_index, state, 1);
		col->un_dev = col->un_orig_dev;
		col->un_devstart = col->un_orig_devstart;
		col->un_pwstart = col->un_orig_pwstart;
		col->un_devflags &= ~MD_RAID_DEV_ISOPEN;
		raid_commit(un, recids);
		cmn_err(CE_WARN, "md: %s: open error of hotspare %s",
		    md_shortname(mnum),
		    md_devname(MD_MIN2SET(mnum), hs_dev, NULL, 0));
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_HS_FREED, SVM_TAG_HS, setno,
		    MD_SID(un));
		goto again;
	}

	col->un_dev = tmpdev;

	col->un_devflags |= MD_RAID_DEV_ISOPEN;

	/*
	 * move the values into the device fields.  Since in some cases
	 * the pwstart is not zero this must be added into the start of
	 * the hotspare to avoid over writting the label
	 */
	col->un_hs_pwstart += col->un_orig_pwstart;
	col->un_pwstart = col->un_hs_pwstart;
	col->un_hs_devstart = col->un_hs_pwstart + un->un_pwsize;
	col->un_devstart = col->un_hs_devstart;

	/* commit unit and hotspare records and release lock */
	raid_commit(un, recids);
	md_unit_writerexit(ui);
	md_io_writerexit(ui);

	err = raid_resync_unit(mnum, &mde);

	/* if resync fails, transition back to erred state and reset */
	if (err) {
		/* reaquire unit writerr lock */
		un = (mr_unit_t *)md_unit_writerlock(ui);

		raid_set_state(un, hs_index, RCS_ERRED, 0);

		/*
		 * close the hotspare and return it.  Then restore the
		 * original device back to the original state
		 */
		raid_hs_release(HS_FREE, un, &recids[0], hs_index);
		col->un_dev = col->un_orig_dev;
		col->un_devstart = col->un_orig_devstart;
		col->un_pwstart = col->un_orig_pwstart;
		raid_commit(un, recids);
		md_unit_writerexit(ui);
		un = (mr_unit_t *)md_unit_readerlock(ui);
		return;
	}

	setno = MD_MIN2SET(mnum);

	(void) md_devname(setno, col->un_orig_dev, devname,
		sizeof (devname));
	(void) md_devname(setno, col->un_dev, hs_devname,
		sizeof (hs_devname));

	cmn_err(CE_NOTE, "md: %s: hotspared device %s with %s",
	    md_shortname(mnum), devname, hs_devname);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_HOTSPARED, SVM_TAG_HS, setno,
	    MD_SID(un));
	(void) md_unit_readerlock(ui);
	return;

errout:
	md_unit_writerexit(ui);
	md_io_writerexit(ui);
	un = (mr_unit_t *)md_unit_readerlock(ui);
}

/*
 * NAME:	check_4_hs
 *
 * DESCRIPTION: Check every component of every raid unit for any device which
 *		needs to be backed with a hot spare.
 *
 * PARAMETERS:	daemon_request_t *dr - hotspare request daemon
 *
 * LOCKS:	Acquires and releases the Hotspare Request Lock and the RAID
 *		Driver Lock. Acquires the Unit Writer Lock which is released
 *		in check_comp_4_hs.
 */
static void
check_4_hs(daemon_request_t *dr)
{
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	md_link_t	*next;
	int		i;

	mutex_enter(&dr->dr_mx);	/* clear up front so can poke */
	dr->dr_pending = 0;		/* again in low level routine if */
	mutex_exit(&dr->dr_mx);		/* something found to do	*/

	/*
	 * Scan raid unit list and call component hotspare check routine for
	 * each component of each unit where resync is inactive.
	 */
	rw_enter(&raid_md_ops.md_link_rw.lock, RW_READER);
	for (next = raid_md_ops.md_head; next != NULL; next = next->ln_next) {
		ui = MDI_UNIT(next->ln_id);
		un = (mr_unit_t *)md_unit_readerlock(ui);
		if (!(un->c.un_status & MD_UN_RESYNC_ACTIVE) &&
		    (raid_state_cnt(un, RCS_RESYNC) == 0) &&
		    (UNIT_STATE(un) & RUS_ERRED) &&
		    (un->un_hsp_id != -1) &&
		    (raid_state_cnt(un, RCS_ERRED) == 1)) {
			for (i = 0; i < un->un_totalcolumncnt; i++)
				if (un->un_column[i].un_devstate == RCS_ERRED)
					check_comp_4_hs(un, i);
		}
		md_unit_readerexit(ui);
	}
	rw_exit(&raid_md_ops.md_link_rw.lock);
}

/*
 * NAME:	raid_hotspares
 *
 * DESCRIPTION: Initiate a check of all RAID devices for components which
 *		may require a hot spare, if it is not already running.
 *
 * PARAMETERS:	NONE
 *
 * LOCKS:	Acquires and releases the Hotspare Request Lock.
 */
intptr_t
raid_hotspares()
{
	/* if available, make request for hotspare to master daemon */
	mutex_enter(&hotspare_request.dr_mx);
	if (hotspare_request.dr_pending == 0) {
		hotspare_request.dr_pending = 1;
		daemon_request(&md_hs_daemon,
		    check_4_hs, (daemon_queue_t *)&hotspare_request, REQ_OLD);
	}
	mutex_exit(&hotspare_request.dr_mx);
	return (0);
}
