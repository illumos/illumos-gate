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

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/kmem.h>
#include <sys/note.h>

#include <sys/sbdpriv.h>
#include <sys/sbd_io.h>
#include <sys/machsystm.h>


extern void sbd_errno_decode(int err, sbderror_t *ep, dev_info_t *dip);
extern sbd_state_t ostate_cvt(sbd_istate_t);

/*
 * Given a dev_info_t of a branch root, walk down the
 * branch to attach drivers
 */
/*ARGSUSED*/
void
sbd_attach_io(sbd_handle_t *hp, sbderror_t *ep, dev_info_t *dip, int unit)
{
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);

	ASSERT(e_ddi_branch_held(dip));

	(void) e_ddi_branch_configure(dip, NULL, 0);

	ASSERT(sbp->sb_iopath[unit] != NULL);

	(void) ddi_pathname(dip, sbp->sb_iopath[unit]);
}

/*
 * remove device nodes for the branch indicated by dip
 * Hold the status lock so that status can safely do ddi_pathname().
 */
/*ARGSUSED*/
void
sbd_detach_io(sbd_handle_t *hp, sbderror_t *ep, dev_info_t *dip, int unit)
{
	int rv;
	dev_info_t *fdip = NULL;
	sbd_board_t *sbp = SBDH2BD(hp->h_sbd);

	ASSERT(e_ddi_branch_held(dip));
	mutex_enter(&sbp->sb_slock);
	rv = e_ddi_branch_unconfigure(dip, &fdip, DEVI_BRANCH_EVENT);
	mutex_exit(&sbp->sb_slock);
	if (rv) {
		/*
		 * If non-NULL, fdip is returned held and must be released.
		 */
		if (fdip != NULL) {
			sbd_errno_decode(rv, ep, fdip);
			ddi_release_devi(fdip);
		} else {
			sbd_errno_decode(rv, ep, dip);
		}
	}
}

/*ARGSUSED*/
void
sbd_init_io_unit(sbd_board_t *sbp, int unit)
{
	sbd_istate_t	new_state;
	sbd_io_unit_t	*ip;
	dev_info_t	*dip;

	ip = SBD_GET_BOARD_IOUNIT(sbp, unit);

	if (SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_IO, unit)) {
		new_state = SBD_STATE_CONFIGURED;
	} else if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_IO, unit)) {
		new_state = SBD_STATE_CONNECTED;
	} else {
		new_state = SBD_STATE_EMPTY;
	}
	dip = sbp->sb_devlist[NIX(SBD_COMP_IO)][unit];
	ip->sbi_cm.sbdev_cond = sbd_get_comp_cond(dip);

	/*
	 * Any changes to this io component should be performed above
	 * this call to ensure the component is fully initialized
	 * before transitioning to the new state.
	 */
	SBD_DEVICE_TRANSITION(sbp, SBD_COMP_IO, unit, new_state);
}

/*ARGSUSED*/
int
sbd_disconnect_io(sbd_handle_t *hp, int unit)
{
	return (0);
}

int
sbd_pre_attach_io(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))
	_NOTE(ARGUNUSED(devlist))
	_NOTE(ARGUNUSED(devnum))

	return (0);
}

/*ARGSUSED*/
int
sbd_pre_detach_io(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	fn_t	f = "sbd_pre_detach_io";

	PR_IO("%s...\n", f);

	if (devnum <= 0)
		return (-1);

	/* fail if any I/O devices are referenced */
	if (sbd_check_io_refs(hp, devlist, devnum) > 0) {
		PR_IO("%s: failed - I/O devices ref'd\n", f);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
int
sbd_post_attach_io(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))
	_NOTE(ARGUNUSED(devlist))
	_NOTE(ARGUNUSED(devnum))

	return (0);
}

/*ARGSUSED*/
int
sbd_post_detach_io(sbd_handle_t *hp, sbd_devlist_t *devlist, int devnum)
{
	return (0);
}

/*ARGSUSED*/
int
sbd_io_status(sbd_handle_t *hp, sbd_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		i, ix;
	sbd_board_t	*sbp;
	sbd_io_stat_t	*isp;
	sbd_io_unit_t	*ip;
	sbd_istate_t	dstate;
	sbdp_handle_t	*hdp;
	sbderror_t	*ep;
	sbd_error_t	*sep;

	/*
	 * Only look for requested devices that are actually present.
	 */
	sbp = SBDH2BD(hp->h_sbd);

	ep = HD2MACHERR(hp);
	sep = kmem_zalloc(sizeof (sbd_error_t), KM_SLEEP);
	hdp = sbd_get_sbdp_handle(sbp, hp);

	/*
	 * Concurrent status and unconfigure, disconnect are allowed.
	 * To prevent DR code from accessing stale dips, check the
	 * present devset and access the dips with status lock held.
	 * Disconnect and unconfigure code change dip state with
	 * status lock (sb_slock) held.
	 */
	mutex_enter(&sbp->sb_slock);

	devset &= SBD_DEVS_PRESENT(sbp);

	for (i = ix = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dev_info_t	*dip;
		int		unit;
		int		namelen;
		int		refcount = 0;

		if (DEVSET_IN_SET(devset, SBD_COMP_IO, i) == 0)
			continue;
		/*
		 * Check to make sure the io component is in a state
		 * where its fully initialized.
		 */
		if (SBD_DEVICE_STATE(sbp, SBD_COMP_IO, i) == SBD_STATE_EMPTY)
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_IO)][i];
		if (dip == NULL)
			continue;

		isp = &dsp->d_io;

		bzero((caddr_t)isp, sizeof (*isp));
		namelen = sizeof (isp->is_name);
		(void) ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, OBP_DEVICETYPE,
		    (caddr_t)isp->is_name, &namelen);

		isp->is_unit = sbdp_get_unit_num(hdp, dip);
		if (isp->is_unit < 0) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				SBD_GET_PERR(hdp->h_err, SBD_HD2ERR(hp));
				break;
			}
		}
		unit = isp->is_unit;

		dstate = SBD_DEVICE_STATE(sbp, SBD_COMP_IO, unit);
		isp->is_ostate	= ostate_cvt(dstate);
		isp->is_type = SBD_COMP_IO;
		ip = SBD_GET_BOARD_IOUNIT(sbp, unit);
		ip->sbi_cm.sbdev_cond = sbd_get_comp_cond(dip);
		isp->is_cm.c_cond = ip->sbi_cm.sbdev_cond;
		isp->is_cm.c_busy = ip->sbi_cm.sbdev_busy;
		isp->is_cm.c_time = ip->sbi_cm.sbdev_time;


		/*
		 * This is safe to do as unconfigure and disconnect
		 * hold the status lock while changing dip state.
		 */
		(void) ddi_pathname(dip, isp->is_pathname);

		/*
		 * We use a dummy handle in which to collect
		 * the major numbers of unsafe devices.
		 */
		sbdp_check_devices(dip, &refcount, sep, NULL);

		isp->is_referenced = (refcount == 0) ? 0 : 1;

		isp->is_unsafe_count = 0;

		/*
		 * Reset error field since we don't care about
		 * errors at this level.  The unsafe devices
		 * will be reported in the structure.
		 */
		SBD_SET_ERR(ep, ESBD_NOERROR);
		ep->e_rsc[0] = '\0';

		ix++;
		dsp++;
	}

	mutex_exit(&sbp->sb_slock);

	kmem_free(sep, sizeof (sbd_error_t));
	sbd_release_sbdp_handle(hdp);

	return (ix);
}

/*ARGSUSED*/
int
sbd_io_cnt(sbd_handle_t *hp, sbd_devset_t devset)
{
	int		i, ix;
	sbd_board_t	*sbp;

	sbp = SBDH2BD(hp->h_sbd);

	/*
	 * Only look for requested devices that are actually present.
	 */
	devset &= SBD_DEVS_PRESENT(sbp);

	for (i = ix = 0; i < MAX_IO_UNITS_PER_BOARD; i++) {
		dev_info_t	*dip;

		if (DEVSET_IN_SET(devset, SBD_COMP_IO, i) == 0)
			continue;

		dip = sbp->sb_devlist[NIX(SBD_COMP_IO)][i];
		if (dip == NULL)
			continue;

		ix++;
	}

	return (ix);
}

int
sbd_check_io_refs(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	register int	i, reftotal = 0;
	fn_t	f = "sbd_check_io_refs";
	sbd_error_t *sep;
	sbderror_t *ep;

	sep = kmem_zalloc(sizeof (sbd_error_t), KM_SLEEP);
	ep = HD2MACHERR(hp);

	for (i = 0; i < devnum; i++) {
		dev_info_t	*dip;
		int		ref;
		int		refcount_non_gldv3;

		dip = devlist[i].dv_dip;
		ref = 0;
		refcount_non_gldv3 = 0;
		sbdp_check_devices(dip, &ref, sep, &refcount_non_gldv3);
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
		if (ref) {
			if (SBD_GET_ERR(ep) == 0) {
				SBD_GET_PERR(sep, ep);
			}
			SBD_GET_PERR(sep, &devlist[i].dv_error);
		}
		PR_IO("%s: dip(%s) ref = %d\n", f, ddi_get_name(dip), ref);
		reftotal += ref;
	}

	kmem_free(sep, sizeof (sbd_error_t));

	return (reftotal);
}

int
sbd_check_io_attached(dev_info_t *dip, void *arg)
{
	dev_info_t **tdip;

	tdip = (dev_info_t **)arg;

	if (dip == *tdip) {
		int state;

		state = ddi_get_devstate(dip);
		if (i_ddi_devi_attached(dip) || (state == DDI_DEVSTATE_UP)) {
			*tdip = NULL;
			return (DDI_WALK_TERMINATE);
		}
	}
	return (DDI_WALK_CONTINUE);
}

int
sbd_pre_release_io(sbd_handle_t *hp,
	sbd_devlist_t *devlist, int devnum)
{
	fn_t	f = "sbd_pre_release_io";
	int	rv = 0;
	int	i;

	ASSERT(devnum > 0);

	/* fail if any I/O devices are referenced */
	if ((rv = sbd_check_io_refs(hp, devlist, devnum)) > 0) {
		/*
		 * One of the devices may have failed check to see which
		 * and set in the main handle
		 */
		for (i = 0; i < devnum; i++) {
			if (SBD_GET_ERR(&devlist[i].dv_error) != 0) {
				(void) sbd_set_err_in_hdl(hp,
				    &devlist[i].dv_error);
				break;
			}
		}
		PR_IO("%s: failed - I/O devices ref'd\n", f);
	}

	return (rv);
}
