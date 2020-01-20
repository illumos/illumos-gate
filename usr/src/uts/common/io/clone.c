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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Clone Driver.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/sysinfo.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/mkdev.h>
#include <sys/open.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/policy.h>

int clnopen(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *crp);

static struct module_info clnm_info = { 0, "CLONE", 0, 0, 0, 0 };
static struct qinit clnrinit = { NULL, NULL, clnopen, NULL, NULL, &clnm_info,
    NULL };
static struct qinit clnwinit = { NULL, NULL, NULL, NULL, NULL, &clnm_info,
    NULL };
struct streamtab clninfo = { &clnrinit, &clnwinit };

static int cln_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int cln_attach(dev_info_t *, ddi_attach_cmd_t);
static dev_info_t *cln_dip;		/* private copy of devinfo pointer */

#define	CLONE_CONF_FLAG		(D_NEW|D_MP)

DDI_DEFINE_STREAM_OPS(clone_ops, nulldev, nulldev, cln_attach, nodev, nodev, \
    cln_info, CLONE_CONF_FLAG, &clninfo, ddi_quiesce_not_needed);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Clone Pseudodriver 'clone'",
	&clone_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	/*
	 * Since the clone driver's reference count is unreliable,
	 * make sure we are never unloaded.
	 */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
cln_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	cln_dip = devi;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
cln_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (cln_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)cln_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * Clone open.  Maj is the major device number of the streams
 * device to open.  Look up the device in the cdevsw[].  Attach
 * its qinit structures to the read and write queues and call its
 * open with the sflag set to CLONEOPEN.  Swap in a new vnode with
 * the real device number constructed from either
 *	a) for old-style drivers:
 *		maj and the minor returned by the device open, or
 *	b) for new-style drivers:
 *		the whole dev passed back as a reference parameter
 *		from the device open.
 */
int
clnopen(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	struct streamtab *str;
	dev_t newdev;
	int error = 0;
	major_t maj;
	minor_t emaj;
	struct qinit *rinit, *winit;
	cdevsw_impl_t *dp;
	uint32_t qflag;
	uint32_t sqtype;
	perdm_t *dmp;
	vnode_t *vp;

	if (sflag)
		return (ENXIO);

	/*
	 * Get the device to open.
	 */
	emaj = getminor(*devp); /* minor is major for a cloned driver */
	maj = etoimajor(emaj);	/* get internal major of cloned driver */

	if (maj >= devcnt)
		return (ENXIO);

	/*
	 * NOTE We call ddi_hold_installed_driver() here to attach
	 *	all instances of the driver, since we do not know
	 *	a priori which instance the Stream is associated with.
	 *
	 *	For Style-2 network drivers, we know that the association
	 *	happens at DL_ATTACH time. For other types of drivers,
	 *	open probably requires attaching instance 0 (pseudo dip).
	 *
	 *	To eliminate ddi_hold_installed_driver(), the following
	 *	should happen:
	 *
	 *	- GLD be modified to include gld_init(). The driver will
	 *	  register information for gld_open() to succeed. It will
	 *	  also inform framework if driver assigns instance=PPA.
	 *	- ddi_hold_devi_by_instance() be modified to actively
	 *	  attach the instance via top-down enumeration.
	 */
	if (ddi_hold_installed_driver(maj) == NULL)
		return (ENXIO);

	if ((str = STREAMSTAB(maj)) == NULL) {
		ddi_rele_driver(maj);
		return (ENXIO);
	}

	newdev = makedevice(emaj, 0);	/* create new style device number  */

	/*
	 * Check for security here. For DLPI style 2 network
	 * drivers, we need to apply the default network policy.
	 * Clone is weird in that the network driver isn't loaded
	 * and attached at spec_open() time, we need to load the
	 * driver to see if it is a network driver. Hence, we
	 * check security here (after ddi_hold_installed_driver
	 * call above).
	 */
	vp = makespecvp(newdev, VCHR);
	error = secpolicy_spec_open(crp, vp, flag);
	VN_RELE(vp);
	if (error) {
		ddi_rele_driver(maj);
		return (error);
	}

	/*
	 * Save so that we can restore the q on failure.
	 */
	rinit = rq->q_qinfo;
	winit = WR(rq)->q_qinfo;
	ASSERT(rq->q_syncq->sq_type == (SQ_CI|SQ_CO));
	ASSERT((rq->q_flag & QMT_TYPEMASK) == QMTSAFE);

	dp = &devimpl[maj];
	ASSERT(str == dp->d_str);

	qflag = dp->d_qflag;
	sqtype = dp->d_sqtype;

	/* create perdm_t if needed */
	if (NEED_DM(dp->d_dmp, qflag))
		dp->d_dmp = hold_dm(str, qflag, sqtype);

	dmp = dp->d_dmp;

	/*
	 * Set the syncq state what qattach started off with. This is safe
	 * since no other thread can access this queue at this point
	 * (stream open, close, push, and pop are single threaded
	 * by the framework.)
	 */
	leavesq(rq->q_syncq, SQ_OPENCLOSE);

	/*
	 * Substitute the real qinit values for the current ones.
	 */
	/* setq might sleep in kmem_alloc - avoid holding locks. */
	setq(rq, str->st_rdinit, str->st_wrinit, dmp, qflag, sqtype, B_FALSE);

	/*
	 * Open the attached module or driver.
	 *
	 * If there is an outer perimeter get exclusive access during
	 * the open procedure.
	 * Bump up the reference count on the queue.
	 */
	entersq(rq->q_syncq, SQ_OPENCLOSE);

	/*
	 * Call the device open with the stream flag CLONEOPEN.  The device
	 * will either fail this or return the device number.
	 */
	error = (*rq->q_qinfo->qi_qopen)(rq, &newdev, flag, CLONEOPEN, crp);
	if (error != 0)
		goto failed;

	*devp = newdev;
	if (getmajor(newdev) != emaj)
		goto bad_major;

	return (0);

bad_major:
	/*
	 * Close the device
	 */
	(void) (*rq->q_qinfo->qi_qclose)(rq, flag, crp);

#ifdef DEBUG
	cmn_err(CE_NOTE, "cannot clone major number %d(%s)->%d", emaj,
	    ddi_major_to_name(emaj), getmajor(newdev));
#endif
	error = ENXIO;

failed:
	/*
	 * open failed; pretty up to look like original
	 * queue.
	 */
	if (backq(WR(rq)) && backq(WR(rq))->q_next == WR(rq))
		qprocsoff(rq);
	leavesq(rq->q_syncq, SQ_OPENCLOSE);
	rq->q_next = WR(rq)->q_next = NULL;
	ASSERT(flush_syncq(rq->q_syncq, rq) == 0);
	ASSERT(flush_syncq(WR(rq)->q_syncq, WR(rq)) == 0);
	rq->q_ptr = WR(rq)->q_ptr = NULL;
	/* setq might sleep in kmem_alloc - avoid holding locks. */
	setq(rq, rinit, winit, NULL, QMTSAFE, SQ_CI|SQ_CO,
	    B_FALSE);

	/* Restore back to what qattach will expect */
	entersq(rq->q_syncq, SQ_OPENCLOSE);

	ddi_rele_driver(maj);
	return (error);
}
