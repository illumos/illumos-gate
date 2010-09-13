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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * I/O support routines for DR
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/kmem.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>

#include <sys/dr.h>
#include <sys/dr_util.h>
#include <sys/drmach.h>

void
dr_init_io_unit(dr_io_unit_t *ip)
{
	dr_state_t	new_state;

	if (DR_DEV_IS_ATTACHED(&ip->sbi_cm)) {
		new_state = DR_STATE_CONFIGURED;
		ip->sbi_cm.sbdev_cond = SBD_COND_OK;
	} else if (DR_DEV_IS_PRESENT(&ip->sbi_cm)) {
		new_state = DR_STATE_CONNECTED;
		ip->sbi_cm.sbdev_cond = SBD_COND_OK;
	} else {
		new_state = DR_STATE_EMPTY;
	}
	dr_device_transition(&ip->sbi_cm, new_state);
}

/*ARGSUSED*/
void
dr_attach_io(dr_handle_t *hp, dr_common_unit_t *cp)
{
	sbd_error_t *err;

	dr_lock_status(hp->h_bd);
	err = drmach_configure(cp->sbdev_id, 0);
	dr_unlock_status(hp->h_bd);

	if (!err)
		err = drmach_io_post_attach(cp->sbdev_id);

	if (err)
		DRERR_SET_C(&cp->sbdev_error, &err);
}

/*
 * remove device nodes for the branch indicated by cp
 */
/*ARGSUSED*/
void
dr_detach_io(dr_handle_t *hp, dr_common_unit_t *cp)
{
	sbd_error_t *err;

	err = drmach_unconfigure(cp->sbdev_id, 0);

	if (!err)
		err = drmach_unconfigure(cp->sbdev_id, DEVI_BRANCH_DESTROY);

	if (!err)
		err = drmach_io_post_release(cp->sbdev_id);

	if (err) {
		dr_device_transition(cp, DR_STATE_CONFIGURED);
		DRERR_SET_C(&cp->sbdev_error, &err);
	}
}

/*ARGSUSED*/
int
dr_disconnect_io(dr_io_unit_t *ip)
{
	return (0);
}

/*ARGSUSED*/
int
dr_pre_attach_io(dr_handle_t *hp,
	dr_common_unit_t **devlist, int devnum)
{
	int		d;

	for (d = 0; d < devnum; d++) {
		dr_common_unit_t *cp = devlist[d];

		cmn_err(CE_CONT, "OS configure %s", cp->sbdev_path);
	}

	return (0);
}

/*ARGSUSED*/
int
dr_post_attach_io(dr_handle_t *hp,
	dr_common_unit_t **devlist, int devnum)
{
	return (0);
}

static int
dr_check_io_refs(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	register int	i, reftotal = 0;
	static fn_t	f = "dr_check_io_refs";

	for (i = 0; i < devnum; i++) {
		dr_io_unit_t	*ip = (dr_io_unit_t *)devlist[i];
		dev_info_t	*dip;
		int		ref;
		int		refcount_non_gldv3;
		sbd_error_t	*err;

		err = drmach_get_dip(ip->sbi_cm.sbdev_id, &dip);
		if (err)
			DRERR_SET_C(&ip->sbi_cm.sbdev_error, &err);
		else if (dip != NULL) {
			ref = 0;
			refcount_non_gldv3 = 0;
			ASSERT(e_ddi_branch_held(dip));
			dr_check_devices(dip, &ref, hp, NULL, NULL,
			    0, &refcount_non_gldv3);
			ASSERT(refcount_non_gldv3 >= 0);
			ASSERT(ref >= refcount_non_gldv3);
			/*
			 * Ignore reference counts of non-gldv3 network devices
			 * as Crossbow creates reference counts for non-active
			 * (unplumbed) instances.  Reference count check in
			 * detach() known to prevent device from detaching
			 * as necessary.
			 */
			ref -= refcount_non_gldv3;
			hp->h_err = NULL;
			if (ref) {
				dr_dev_err(CE_WARN, &ip->sbi_cm, ESBD_BUSY);
			}
			PR_IO("%s: dip(%s) ref = %d\n",
			    f, ddi_get_name(dip), ref);
			reftotal += ref;
		} else {
			PR_IO("%s: NO dip for id (0x%x)\n",
			    f, (uint_t)(uintptr_t)ip->sbi_cm.sbdev_id);
		}
	}

	return (reftotal);
}

int
dr_pre_release_io(dr_handle_t *hp,
	dr_common_unit_t **devlist, int devnum)
{
	static fn_t	f = "dr_pre_release_io";
	int	d;

	ASSERT(devnum > 0);

	/* fail if any I/O device pre-release fails */
	for (d = 0; d < devnum; d++) {
		dr_io_unit_t *ip = (dr_io_unit_t *)devlist[d];

		if ((hp->h_err = drmach_io_pre_release(
		    ip->sbi_cm.sbdev_id)) != 0) {
			return (-1);
		}
	}

	for (d = 0; d < devnum; d++) {
		dr_io_unit_t *ip = (dr_io_unit_t *)devlist[d];
		sbd_error_t *err;

		err = drmach_release(ip->sbi_cm.sbdev_id);
		if (err) {
			DRERR_SET_C(&ip->sbi_cm.sbdev_error,
			    &err);
			return (-1);
		}
	}

	/* fail if any I/O devices are still referenced */
	if (dr_check_io_refs(hp, devlist, devnum) > 0) {
		PR_IO("%s: failed - I/O devices ref'd\n", f);

		/* recover before return error */
		for (d = 0; d < devnum; d++) {
			dr_io_unit_t *ip = (dr_io_unit_t *)devlist[d];
			sbd_error_t *err;
			err = drmach_io_unrelease(ip->sbi_cm.sbdev_id);
			if (err) {
				DRERR_SET_C(&ip->sbi_cm.sbdev_error, &err);
				return (-1);
			}
		}
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
dr_pre_detach_io(dr_handle_t *hp,
	dr_common_unit_t **devlist, int devnum)
{
	int		d;

	ASSERT(devnum > 0);

	for (d = 0; d < devnum; d++) {
		dr_common_unit_t *cp = devlist[d];

		cmn_err(CE_CONT, "OS unconfigure %s", cp->sbdev_path);
	}

	return (0);
}

/*ARGSUSED*/
int
dr_post_detach_io(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	register int	i;
	int		rv = 0;
	static fn_t	f = "dr_post_detach_io";

	ASSERT(devnum > 0);
	for (i = 0; i < devnum; i++) {
		dr_common_unit_t	*cp = devlist[i];
		if (cp->sbdev_error != NULL) {
			PR_IO("%s: Failed\n", f);
			rv = -1;
			break;
		}
	}
	return (rv);
}

static void
dr_get_comp_cond(dr_io_unit_t *ip, dev_info_t *dip)
{
	if (dip == NULL) {
		ip->sbi_cm.sbdev_cond = SBD_COND_UNKNOWN;
		return;
	}

	if (DEVI(dip)->devi_flags & DEVI_RETIRED) {
		ip->sbi_cm.sbdev_cond = SBD_COND_FAILED;
		return;
	}

	if (DR_DEV_IS_ATTACHED(&ip->sbi_cm)) {
		ip->sbi_cm.sbdev_cond = SBD_COND_OK;
	} else if (DR_DEV_IS_PRESENT(&ip->sbi_cm)) {
		ip->sbi_cm.sbdev_cond = SBD_COND_OK;
	}
}

int
dr_io_status(dr_handle_t *hp, dr_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		i, ix;
	dr_board_t	*bp;
	sbd_io_stat_t	*isp;
	dr_io_unit_t	*ip;

	bp = hp->h_bd;

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= DR_DEVS_PRESENT(bp);

	for (i = ix = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		drmachid_t	 id;
		dev_info_t	*dip;
		sbd_error_t	*err;
		drmach_status_t	 pstat;

		if (DEVSET_IN_SET(devset, SBD_COMP_IO, i) == 0)
			continue;

		ip = dr_get_io_unit(bp, i);

		if (ip->sbi_cm.sbdev_state == DR_STATE_EMPTY) {
			/* present, but not fully initialized */
			continue;
		}

		id = ip->sbi_cm.sbdev_id;
		if (id == (drmachid_t)0)
			continue;

		err = drmach_status(ip->sbi_cm.sbdev_id, &pstat);
		if (err) {
			DRERR_SET_C(&ip->sbi_cm.sbdev_error, &err);
			return (-1);
		}

		dip = NULL;
		err = drmach_get_dip(id, &dip);
		if (err) {
			/* catch this in debug kernels */
			ASSERT(0);

			sbd_err_clear(&err);
			continue;
		}

		isp = &dsp->d_io;
		bzero((caddr_t)isp, sizeof (*isp));

		isp->is_cm.c_id.c_type = ip->sbi_cm.sbdev_type;
		isp->is_cm.c_id.c_unit = ip->sbi_cm.sbdev_unum;
		(void) strlcpy(isp->is_cm.c_id.c_name, pstat.type,
		    sizeof (isp->is_cm.c_id.c_name));

		dr_get_comp_cond(ip, dip);
		isp->is_cm.c_cond = ip->sbi_cm.sbdev_cond;
		isp->is_cm.c_busy = ip->sbi_cm.sbdev_busy | pstat.busy;
		isp->is_cm.c_time = ip->sbi_cm.sbdev_time;
		isp->is_cm.c_ostate = ip->sbi_cm.sbdev_ostate;
		isp->is_cm.c_sflags = 0;

		if (dip == NULL) {
			isp->is_pathname[0] = '\0';
			isp->is_referenced = 0;
			isp->is_unsafe_count = 0;
		} else {
			int		refcount = 0, idx = 0;
			uint64_t	unsafe_devs[SBD_MAX_UNSAFE];

			ASSERT(e_ddi_branch_held(dip));
			(void) ddi_pathname(dip, isp->is_pathname);

			/* check reference and unsafe counts on devices */
			isp->is_unsafe_count = 0;
			dr_check_devices(dip, &refcount, hp, unsafe_devs,
			    &idx, SBD_MAX_UNSAFE, NULL);
			while (idx > 0) {
				isp->is_unsafe_list[idx-1] = unsafe_devs[idx-1];
				--idx;
			}

			isp->is_referenced = (refcount == 0) ? 0 : 1;

			hp->h_err = NULL;
		}
		ix++;
		dsp++;
	}

	return (ix);
}
