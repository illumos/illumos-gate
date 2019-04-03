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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#include <sys/types.h>
#include <inet/common.h>
#include <sys/stropts.h>
#include <sys/modctl.h>
#include <sys/dld.h>
#include <sys/softmac_impl.h>

dev_info_t		*softmac_dip = NULL;
static kmem_cache_t	*softmac_upper_cachep;

/*
 * This function is a generic open(9E) entry point into the softmac for
 * both the softmac module and the softmac driver.
 */
static int softmac_cmn_open(queue_t *, dev_t *, int, int, cred_t *);

/*
 * The following softmac_mod_xxx() functions are (9E) entry point functions for
 * the softmac module.
 */
static int softmac_mod_close(queue_t *, int, cred_t *);
static int softmac_mod_rput(queue_t *, mblk_t *);
static int softmac_mod_wput(queue_t *, mblk_t *);
static int softmac_mod_wsrv(queue_t *);

/*
 * The following softmac_drv_xxx() functions are (9E) entry point functions for
 * the softmac driver.
 */
static int softmac_drv_open(queue_t *, dev_t *, int, int, cred_t *);
static int softmac_drv_close(queue_t *, int, cred_t *);
static int softmac_drv_wput(queue_t *, mblk_t *);
static int softmac_drv_wsrv(queue_t *);

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
	softmac_mod_rput,		/* qi_putp */
	NULL,				/* qi_srvp */
	softmac_cmn_open,		/* qi_qopen */
	softmac_mod_close,		/* qi_qclose */
	NULL,				/* qi_qadmin */
	&softmac_modinfo		/* qi_minfo */
};

static struct qinit softmac_uwinit = {
	softmac_mod_wput,		/* qi_putp */
	softmac_mod_wsrv,		/* qi_srvp */
	NULL,				/* qi_qopen */
	NULL,				/* qi_qclose */
	NULL,				/* qi_qadmin */
	&softmac_modinfo		/* qi_minfo */
};

static struct streamtab softmac_tab = {
	&softmac_urinit,	/* st_rdinit */
	&softmac_uwinit		/* st_wrinit */
};

DDI_DEFINE_STREAM_OPS(softmac_ops, nulldev, nulldev, softmac_attach,
    softmac_detach, nodev, softmac_info, D_MP, &softmac_tab,
    ddi_quiesce_not_supported);

static struct qinit softmac_dld_r_qinit = {
	NULL, NULL, softmac_drv_open, softmac_drv_close, NULL,
	&softmac_dld_modinfo
};

static struct qinit softmac_dld_w_qinit = {
	softmac_drv_wput, softmac_drv_wsrv, NULL, NULL, NULL,
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

static void softmac_dedicated_rx(void *, mac_resource_handle_t, mblk_t *,
    mac_header_info_t *);

/*ARGSUSED*/
static int
softmac_upper_constructor(void *buf, void *arg, int kmflag)
{
	softmac_upper_t	*sup = buf;

	bzero(buf, sizeof (softmac_upper_t));

	mutex_init(&sup->su_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sup->su_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&sup->su_disp_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sup->su_disp_cv, NULL, CV_DEFAULT, NULL);
	list_create(&sup->su_req_list, sizeof (softmac_switch_req_t),
	    offsetof(softmac_switch_req_t, ssq_req_list_node));
	return (0);
}

/*ARGSUSED*/
static void
softmac_upper_destructor(void *buf, void *arg)
{
	softmac_upper_t	*sup = buf;

	ASSERT(sup->su_slp == NULL);
	ASSERT(sup->su_pending_head == NULL && sup->su_pending_tail == NULL);
	ASSERT(!sup->su_dlpi_pending);
	ASSERT(!sup->su_active);
	ASSERT(!sup->su_closing);
	ASSERT(sup->su_tx_flow_mp == NULL);
	ASSERT(sup->su_tx_inprocess == 0);
	ASSERT(sup->su_mode == SOFTMAC_UNKNOWN);
	ASSERT(!sup->su_tx_busy);
	ASSERT(!sup->su_bound);
	ASSERT(!sup->su_taskq_scheduled);
	ASSERT(sup->su_tx_notify_func == NULL);
	ASSERT(sup->su_tx_notify_arg == NULL);
	ASSERT(list_is_empty(&sup->su_req_list));

	list_destroy(&sup->su_req_list);
	mutex_destroy(&sup->su_mutex);
	cv_destroy(&sup->su_cv);
	mutex_destroy(&sup->su_disp_mutex);
	cv_destroy(&sup->su_disp_cv);
}

int
_init(void)
{
	int	err;

	mac_init_ops(NULL, SOFTMAC_DEV_NAME);
	softmac_init();

	softmac_upper_cachep = kmem_cache_create("softmac_upper_cache",
	    sizeof (softmac_upper_t), 0, softmac_upper_constructor,
	    softmac_upper_destructor, NULL, NULL, NULL, 0);
	ASSERT(softmac_upper_cachep != NULL);

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

	kmem_cache_destroy(softmac_upper_cachep);
	softmac_fini();

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&softmac_modlinkage, modinfop));
}

static int
softmac_cmn_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
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
		slp->sl_pending_prim = DL_PRIM_INVAL;
		rq->q_ptr = WR(rq)->q_ptr = slp;
		qprocson(rq);
		return (0);
	}

	/*
	 * Regular device open of a softmac DLPI node.  We modify
	 * the queues' q_qinfo pointer such that all future STREAMS
	 * operations will go through another set of entry points
	 */
	rq->q_qinfo = &softmac_dld_r_qinit;
	WR(rq)->q_qinfo = &softmac_dld_w_qinit;
	return (softmac_drv_open(rq, devp, flag, sflag, credp));
}

/* ARGSUSED */
static int
softmac_mod_close(queue_t *rq, int flags __unused, cred_t *credp __unused)
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
	ASSERT(slp->sl_pending_prim == DL_PRIM_INVAL);
	ASSERT(slp->sl_pending_ioctl == B_FALSE);

	cv_destroy(&slp->sl_cv);
	mutex_destroy(&slp->sl_mutex);

	kmem_free(slp, sizeof (*slp));
	return (0);
}

static int
softmac_mod_rput(queue_t *rq, mblk_t *mp)
{
	softmac_lower_t		*slp = rq->q_ptr;
	softmac_lower_rxinfo_t	*rxinfo;
	union DL_primitives	*dlp;

	/*
	 * This is the softmac module.
	 */
	ASSERT(WR(rq)->q_next != NULL);
	ASSERT((mp->b_next == NULL) && (mp->b_prev == NULL));

	switch (DB_TYPE(mp)) {
	case M_DATA: {

		/*
		 * If sl_rxinfo is non-NULL. This is dedicated-lower-stream
		 * created for fastpath. Directly call the rx callback.
		 */
		if ((rxinfo = slp->sl_rxinfo) != NULL) {
			rxinfo->slr_rx(rxinfo->slr_arg, NULL, mp, NULL);
			break;
		}

		/*
		 * A shared-lower-stream. Some driver starts to send up
		 * packets even it not in the DL_IDLE state, where
		 * sl_softmac is not set yet. Drop the packet in this case.
		 */
		if (slp->sl_softmac == NULL) {
			freemsg(mp);
			return (0);
		}

		/*
		 * If this message is looped back from the legacy devices,
		 * drop it as the Nemo framework will be responsible for
		 * looping it back by the mac_txloop() function.
		 */
		if (mp->b_flag & MSGNOLOOP) {
			freemsg(mp);
			return (0);
		}

		/*
		 * This is the most common case.
		 */
		if (DB_REF(mp) == 1) {
			ASSERT(slp->sl_softmac != NULL);
			mac_rx(slp->sl_softmac->smac_mh, NULL, mp);
			return (0);
		} else {
			softmac_rput_process_data(slp, mp);
		}
		break;
	}
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (dlp->dl_primitive)) {
			freemsg(mp);
			break;
		}
		dlp = (union DL_primitives *)mp->b_rptr;
		if (dlp->dl_primitive == DL_UNITDATA_IND) {

			if ((rxinfo = slp->sl_rxinfo) != NULL) {
				softmac_dedicated_rx(slp->sl_sup, NULL, mp,
				    NULL);
				break;
			}

			cmn_err(CE_WARN, "got unexpected %s message",
			    dl_primstr(DL_UNITDATA_IND));
			freemsg(mp);
			break;
		}
		/*FALLTHROUGH*/
	default:
		softmac_rput_process_notdata(rq, slp->sl_sup, mp);
		break;
	}
	return (0);
}

static int
softmac_mod_wput(queue_t *wq, mblk_t *mp)
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
	return (0);
}

static int
softmac_mod_wsrv(queue_t *wq)
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
	if (slp->sl_sup != NULL)
		qenable(slp->sl_sup->su_wq);
	else if (slp->sl_softmac != NULL)
		mac_tx_update(slp->sl_softmac->smac_mh);
	return (0);
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

/*ARGSUSED*/
static void
softmac_dedicated_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    mac_header_info_t *mhip)
{
	queue_t *rq = ((softmac_upper_t *)arg)->su_rq;

	if (canputnext(rq))
		putnext(rq, mp);
	else
		freemsg(mp);
}

/*ARGSUSED*/
static int
softmac_drv_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	softmac_upper_t	*sup = NULL;
	softmac_t	*softmac;
	int		err = 0;

	/*
	 * This is a softmac device created for a legacy device, find the
	 * associated softmac and initialize the softmac_upper_t structure.
	 */
	if ((err = softmac_hold(*devp, &softmac)) != 0)
		return (err);

	sup = kmem_cache_alloc(softmac_upper_cachep, KM_NOSLEEP);
	if (sup == NULL) {
		err = ENOMEM;
		goto fail;
	}

	ASSERT(list_is_empty(&sup->su_req_list));

	if ((sup->su_tx_flow_mp = allocb(1, BPRI_HI)) == NULL) {
		err = ENOMEM;
		goto fail;
	}

	sup->su_rq = rq;
	sup->su_wq = WR(rq);
	sup->su_softmac = softmac;
	sup->su_mode = SOFTMAC_UNKNOWN;

	sup->su_rxinfo.slr_arg = sup;
	sup->su_rxinfo.slr_rx = softmac_dedicated_rx;
	sup->su_direct_rxinfo.slr_arg = sup;
	sup->su_direct_rxinfo.slr_rx = softmac_dedicated_rx;

	if ((err = dld_str_open(rq, devp, sup)) != 0) {
		freeb(sup->su_tx_flow_mp);
		sup->su_tx_flow_mp = NULL;
		goto fail;
	}

	return (0);

fail:
	if (sup != NULL)
		kmem_cache_free(softmac_upper_cachep, sup);
	softmac_rele(softmac);
	return (err);
}

/* ARGSUSED */
static int
softmac_drv_close(queue_t *rq, int flags __unused, cred_t *credp __unused)
{
	softmac_upper_t	*sup = dld_str_private(rq);
	softmac_t	*softmac = sup->su_softmac;

	ASSERT(WR(rq)->q_next == NULL);

	qprocsoff(rq);

	ASSERT(sup->su_tx_inprocess == 0);

	/*
	 * Wait until the pending request are processed by the worker thread.
	 */
	mutex_enter(&sup->su_disp_mutex);
	sup->su_closing = B_TRUE;
	while (sup->su_dlpi_pending)
		cv_wait(&sup->su_disp_cv, &sup->su_disp_mutex);
	mutex_exit(&sup->su_disp_mutex);

	softmac_upperstream_close(sup);

	if (sup->su_tx_flow_mp != NULL) {
		freeb(sup->su_tx_flow_mp);
		sup->su_tx_flow_mp = NULL;
	}

	if (sup->su_active) {
		mutex_enter(&softmac->smac_active_mutex);
		softmac->smac_nactive--;
		mutex_exit(&softmac->smac_active_mutex);
		sup->su_active = B_FALSE;
	}

	sup->su_bound = B_FALSE;
	sup->su_softmac = NULL;
	sup->su_closing = B_FALSE;

	kmem_cache_free(softmac_upper_cachep, sup);

	softmac_rele(softmac);
	return (dld_str_close(rq));
}

static int
softmac_drv_wput(queue_t *wq, mblk_t *mp)
{
	softmac_upper_t	*sup = dld_str_private(wq);
	t_uscalar_t	prim;

	ASSERT(wq->q_next == NULL);

	switch (DB_TYPE(mp)) {
	case M_DATA:
	case M_MULTIDATA:
		softmac_wput_data(sup, mp);
		break;
	case M_PROTO:
	case M_PCPROTO:

		if (MBLKL(mp) < sizeof (t_uscalar_t)) {
			freemsg(mp);
			return (0);
		}

		prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;
		if (prim == DL_UNITDATA_REQ) {
			softmac_wput_data(sup, mp);
			return (0);
		}

		softmac_wput_nondata(sup, mp);
		break;
	default:
		softmac_wput_nondata(sup, mp);
		break;
	}
	return (0);
}

static int
softmac_drv_wsrv(queue_t *wq)
{
	softmac_upper_t	*sup = dld_str_private(wq);

	ASSERT(wq->q_next == NULL);

	mutex_enter(&sup->su_mutex);
	if (sup->su_mode != SOFTMAC_FASTPATH) {
		/*
		 * Bump su_tx_inprocess so that su_mode won't change.
		 */
		sup->su_tx_inprocess++;
		mutex_exit(&sup->su_mutex);
		(void) dld_wsrv(wq);
		mutex_enter(&sup->su_mutex);
		if (--sup->su_tx_inprocess == 0)
			cv_signal(&sup->su_cv);
	} else if (sup->su_tx_busy && SOFTMAC_CANPUTNEXT(sup->su_slp->sl_wq)) {
		/*
		 * The flow-conctol of the dedicated-lower-stream is
		 * relieved. If DLD_CAPAB_DIRECT is enabled, call tx_notify
		 * callback to relieve the flow-control of the specific client,
		 * otherwise relieve the flow-control of all the upper-stream
		 * using the traditional STREAM mechanism.
		 */
		if (sup->su_tx_notify_func != NULL) {
			sup->su_tx_inprocess++;
			mutex_exit(&sup->su_mutex);
			sup->su_tx_notify_func(sup->su_tx_notify_arg,
			    (mac_tx_cookie_t)sup);
			mutex_enter(&sup->su_mutex);
			if (--sup->su_tx_inprocess == 0)
				cv_signal(&sup->su_cv);
		}
		ASSERT(sup->su_tx_flow_mp == NULL);
		VERIFY((sup->su_tx_flow_mp = getq(wq)) != NULL);
		sup->su_tx_busy = B_FALSE;
	}
	mutex_exit(&sup->su_mutex);
	return (0);
}
