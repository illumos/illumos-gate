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


#include <sys/types.h>
#include <sys/dld.h>
#include <inet/common.h>
#include <sys/stropts.h>
#include <sys/modctl.h>
#include <sys/avl.h>
#include <sys/softmac_impl.h>
#include <sys/softmac.h>

dev_info_t		*softmac_dip = NULL;

static int softmac_open(queue_t *, dev_t *, int, int, cred_t *);
static int softmac_close(queue_t *);
static void softmac_rput(queue_t *, mblk_t *);
static void softmac_rsrv(queue_t *);
static void softmac_wput(queue_t *, mblk_t *);
static void softmac_wsrv(queue_t *);
static int softmac_attach(dev_info_t *, ddi_attach_cmd_t);
static int softmac_detach(dev_info_t *, ddi_detach_cmd_t);
static int softmac_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct module_info softmac_modinfo = {
	0,
	SOFTMAC_DEV_NAME,
	0,
	INFPSZ,
	65536,
	1024
};

/*
 * hi-water mark is 1 because of the flow control mechanism implemented in
 * dld.  Refer to the comments in dld_str.c for details.
 */
static struct module_info softmac_dld_modinfo = {
	0,
	SOFTMAC_DEV_NAME,
	0,
	INFPSZ,
	1,
	0
};

static struct qinit softmac_urinit = {
	(pfi_t)softmac_rput,	/* qi_putp */
	(pfi_t)softmac_rsrv,	/* qi_srvp */
	softmac_open,		/* qi_qopen */
	softmac_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&softmac_modinfo	/* qi_minfo */
};

static struct qinit softmac_uwinit = {
	(pfi_t)softmac_wput,	/* qi_putp */
	(pfi_t)softmac_wsrv,	/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&softmac_modinfo	/* qi_minfo */
};

static struct streamtab softmac_tab = {
	&softmac_urinit,	/* st_rdinit */
	&softmac_uwinit		/* st_wrinit */
};

DDI_DEFINE_STREAM_OPS(softmac_ops, nulldev, nulldev, softmac_attach,
    softmac_detach, nodev, softmac_info, D_MP, &softmac_tab,
    ddi_quiesce_not_supported);

static struct qinit softmac_dld_r_qinit = {
	NULL, NULL, dld_open, dld_close, NULL, &softmac_dld_modinfo
};

static struct qinit softmac_dld_w_qinit = {
	(pfi_t)dld_wput, (pfi_t)dld_wsrv, NULL, NULL, NULL,
	&softmac_dld_modinfo
};

static struct fmodsw softmac_fmodsw = {
	SOFTMAC_DEV_NAME,
	&softmac_tab,
	D_MP
};

static struct modldrv softmac_modldrv = {
	&mod_driverops,
	"softmac driver",
	&softmac_ops
};

static struct modlstrmod softmac_modlstrmod = {
	&mod_strmodops,
	"softmac module",
	&softmac_fmodsw
};

static struct modlinkage softmac_modlinkage = {
	MODREV_1,
	&softmac_modlstrmod,
	&softmac_modldrv,
	NULL
};

int
_init(void)
{
	int	err;

	softmac_init();

	if ((err = mod_install(&softmac_modlinkage)) != 0) {
		softmac_fini();
		return (err);
	}

	return (0);
}

int
_fini(void)
{
	int err;

	if (softmac_busy())
		return (EBUSY);

	if ((err = mod_remove(&softmac_modlinkage)) != 0)
		return (err);

	softmac_fini();

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&softmac_modlinkage, modinfop));
}

static int
softmac_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	softmac_lower_t	*slp;
	/*
	 * This is a self-cloning driver so that each queue should only
	 * get opened once.
	 */
	if (rq->q_ptr != NULL)
		return (EBUSY);

	if (sflag == MODOPEN) {
		/*
		 * This is the softmac module pushed over an underlying
		 * legacy device.  Initialize the lower structure.
		 */
		if ((slp = kmem_zalloc(sizeof (*slp), KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		slp->sl_wq = WR(rq);
		cv_init(&slp->sl_cv, NULL, CV_DRIVER, NULL);
		mutex_init(&slp->sl_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&slp->sl_ctl_cv, NULL, CV_DRIVER, NULL);
		mutex_init(&slp->sl_ctl_mutex, NULL, MUTEX_DRIVER, NULL);
		slp->sl_pending_prim = DL_PRIM_INVAL;
		rq->q_ptr = WR(rq)->q_ptr = slp;
		qprocson(rq);
		return (0);
	}

	/*
	 * Regular device open of a softmac DLPI node.  We modify
	 * the queues' q_qinfo pointer such that all future STREAMS
	 * operations will go through dld's entry points (including
	 * dld_close()).
	 */
	rq->q_qinfo = &softmac_dld_r_qinit;
	WR(rq)->q_qinfo = &softmac_dld_w_qinit;
	return (dld_open(rq, devp, flag, sflag, credp));
}

static int
softmac_close(queue_t *rq)
{
	softmac_lower_t	*slp = rq->q_ptr;

	/*
	 * Call the appropriate delete routine depending on whether this is
	 * a module or device.
	 */
	ASSERT(WR(rq)->q_next != NULL);

	qprocsoff(rq);

	slp->sl_softmac = NULL;
	slp->sl_lh = NULL;

	ASSERT(slp->sl_ack_mp == NULL);
	ASSERT(slp->sl_ctl_inprogress == B_FALSE);
	ASSERT(slp->sl_pending_prim == DL_PRIM_INVAL);
	ASSERT(slp->sl_pending_ioctl == B_FALSE);

	cv_destroy(&slp->sl_cv);
	mutex_destroy(&slp->sl_mutex);
	cv_destroy(&slp->sl_ctl_cv);
	mutex_destroy(&slp->sl_ctl_mutex);

	kmem_free(slp, sizeof (*slp));
	return (0);
}

static void
softmac_rput(queue_t *rq, mblk_t *mp)
{
	softmac_lower_t *slp = rq->q_ptr;
	union DL_primitives *dlp;

	/*
	 * This is the softmac module.
	 */
	ASSERT(WR(rq)->q_next != NULL);
	ASSERT((mp->b_next == NULL) && (mp->b_prev == NULL));

	switch (DB_TYPE(mp)) {
	case M_DATA:
		/*
		 * Some drivers start to send up packets even if not in the
		 * DL_IDLE state, where sl_softmac is not set yet.  Drop the
		 * packet in this case.
		 */
		if (slp->sl_softmac == NULL) {
			freemsg(mp);
			return;
		}

		/*
		 * If this message is looped back from the legacy devices,
		 * drop it as the Nemo framework will be responsible for
		 * looping it back by the mac_txloop() function.
		 */
		if (mp->b_flag & MSGNOLOOP) {
			freemsg(mp);
			return;
		}

		/*
		 * This is the most common case.
		 */
		if (DB_REF(mp) == 1) {
			ASSERT(slp->sl_softmac != NULL);
			/*
			 * We don't need any locks to protect sl_handle
			 * because ip_input() can tolerate if sl_handle
			 * is reset to NULL when DL_CAPAB_POLL is
			 * disabled.
			 */
			mac_rx(slp->sl_softmac->smac_mh, NULL, mp);
			return;
		} else {
			softmac_rput_process_data(slp, mp);
		}
		break;
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (dlp->dl_primitive)) {
			freemsg(mp);
			break;
		}
		dlp = (union DL_primitives *)mp->b_rptr;
		if (dlp->dl_primitive == DL_UNITDATA_IND) {
			cmn_err(CE_WARN, "got unexpected %s message",
			    dl_primstr(DL_UNITDATA_IND));
			freemsg(mp);
			break;
		}
		/*FALLTHROUGH*/
	default:
		softmac_rput_process_notdata(rq, mp);
		break;
	}
}

/* ARGSUSED */
static void
softmac_rsrv(queue_t *rq)
{
}

static void
softmac_wput(queue_t *wq, mblk_t *mp)
{
	/*
	 * This is the softmac module
	 */
	ASSERT(wq->q_next != NULL);

	switch (DB_TYPE(mp)) {
	case M_IOCTL: {
		struct iocblk		*ioc = (struct iocblk *)mp->b_rptr;

		switch (ioc->ioc_cmd) {
		case SMAC_IOC_START: {
			softmac_lower_t		*slp = wq->q_ptr;
			smac_ioc_start_t	*arg;

			if (ioc->ioc_count != sizeof (*arg)) {
				miocnak(wq, mp, 0, EINVAL);
				break;
			}

			/*
			 * Assign the devname and perstream handle of the
			 * specific lower stream and return it as a part
			 * of the ioctl.
			 */
			arg = (smac_ioc_start_t *)mp->b_cont->b_rptr;
			arg->si_slp = slp;

			miocack(wq, mp, sizeof (*arg), 0);
			break;
		}
		default:
			miocnak(wq, mp, 0, EINVAL);
			break;
		}
		break;
	}
	default:
		freemsg(mp);
		break;
	}
}

static void
softmac_wsrv(queue_t *wq)
{
	softmac_lower_t *slp = wq->q_ptr;

	/*
	 * This is the softmac module
	 */
	ASSERT(wq->q_next != NULL);

	/*
	 * Inform that the tx resource is available; mac_tx_update() will
	 * inform all the upper streams sharing this lower stream.
	 */
	if (slp->sl_softmac != NULL)
		mac_tx_update(slp->sl_softmac->smac_mh);
}

static int
softmac_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ASSERT(ddi_get_instance(dip) == 0);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	softmac_dip = dip;

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
softmac_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	softmac_dip = NULL;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
softmac_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (softmac_dip != NULL) {
			*result = softmac_dip;
			return (DDI_SUCCESS);
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);

	}

	return (DDI_FAILURE);
}
