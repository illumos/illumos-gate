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
 * DM2S - Domain side Mailbox to synchronous serial device driver.
 *
 * Description:
 * -----------
 * It is a streams driver which simulates a sync serial device on
 * top of a mailbox type of communication. That is, it sends/receives
 * frames as mailbox messages. The mailbox communication is provided
 * by another driver, which exports the mailbox interfaces.
 *
 * Synchronization:
 * ---------------
 * This driver uses streams perimeters to simplify the synchronization.
 * An inner perimeter D_MTPERMOD which protects the entire module,
 * that is only one thread exists inside the perimeter, is used. As
 * this driver supports only one instance and is not a high-performance
 * driver, D_MTPERMOD is highly suitable.
 *
 * All transmission and reception of frames is done inside the service
 * procedures so that all streams related operations are protected
 * by the perimeters.
 *
 * The mailbox event handler is the only asynchronous callback which
 * needs to be protected outside of the streams perimeters. This is
 * done using the module private lock('ms_lock');
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/kmem.h>
#include <sys/consdev.h>
#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/dlpi.h>
#include <sys/stat.h>
#include <sys/ser_sync.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <sys/sdt.h>

#include <sys/scfd/scfdscpif.h>
#include <sys/dm2s.h>


#define	DM2S_MODNAME	"dm2s"			/* Module name */
#define	DM2S_TARGET_ID	0			/* Target ID of the peer */
#define	DM2S_ID_NUM	0x4D53			/* 'M''S' */
#define	DM2S_DEF_MTU	1504			/* Def. MTU size + PPP bytes */
#define	DM2S_MAXPSZ	DM2S_DEF_MTU		/* Set it to the default MTU */
#define	DM2S_LOWAT	(4 * 1024)		/* Low water mark */
#define	DM2S_HIWAT	(12 * 1024)		/* High water mark */
#define	DM2S_SM_TOUT	5000			/* Small timeout (5msec) */
#define	DM2S_LG_TOUT	50000			/* Large timeout (50msec) */
#define	DM2S_MB_TOUT	10000000		/* Mailbox timeout (10sec) */

/*
 * Global variables
 */
void		*dm2s_softstate = NULL;			/* Softstate pointer */


/*
 * Prototypes for the module related functions.
 */
int dm2s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
int dm2s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
int dm2s_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);

/*
 * Prototypes for the streams related functions.
 */
int dm2s_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr);
int dm2s_close(queue_t *rq, int flag, cred_t *cred);
int dm2s_wput(queue_t *wq, mblk_t *mp);
int dm2s_rsrv(queue_t *rq);
int dm2s_wsrv(queue_t *wq);

/*
 * Prototypes for the internal functions.
 */
void dm2s_start(queue_t *wq, dm2s_t *dm2sp);
void dm2s_event_handler(scf_event_t event, void *arg);
int dm2s_transmit(queue_t *wq, mblk_t *mp, target_id_t target, mkey_t key);
void dm2s_receive(dm2s_t *dm2sp);
void dm2s_wq_timeout(void *arg);
void dm2s_rq_timeout(void *arg);
void dm2s_bufcall_rcv(void *arg);
static clock_t dm2s_timeout_val(int error);
static void dm2s_cleanup(dm2s_t *dm2sp);
static int dm2s_mbox_init(dm2s_t *dm2sp);
static void dm2s_mbox_fini(dm2s_t *dm2sp);
static int dm2s_prep_scatgath(mblk_t *mp, uint32_t *numsg,
    mscat_gath_t *sgp, int maxsg);

#ifdef DEBUG
uint32_t dm2s_debug = DBG_WARN;
#endif /* DEBUG */


/*
 * Streams and module related structures.
 */
struct module_info dm2s_module_info = {
	DM2S_ID_NUM,		/* module ID number */
	DM2S_MODNAME,		/* module name. */
	0,			/* Minimum packet size (none) */
	DM2S_MAXPSZ,		/* Maximum packet size (none) */
	DM2S_HIWAT,		/* queue high water mark */
	DM2S_LOWAT		/* queue low water mark */
};

struct qinit dm2s_rinit = {
	putq,			/* qi_putp */
	dm2s_rsrv,		/* qi_srvp */
	dm2s_open,		/* qi_qopen */
	dm2s_close,		/* qi_qlcose */
	NULL,			/* qi_qadmin */
	&dm2s_module_info,	/* qi_minfo */
	NULL			/* qi_mstat */
};

struct qinit dm2s_winit = {
	dm2s_wput,		/* qi_putp */
	dm2s_wsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qlcose */
	NULL,			/* qi_qadmin */
	&dm2s_module_info,	/* qi_minfo */
	NULL			/* qi_mstat */
};


struct streamtab dm2s_streamtab = {
	&dm2s_rinit,
	&dm2s_winit,
	NULL,
	NULL
};

DDI_DEFINE_STREAM_OPS(dm2s_ops, nulldev, nulldev, dm2s_attach,
	dm2s_detach, nodev, dm2s_info, D_NEW | D_MP | D_MTPERMOD,
	&dm2s_streamtab, ddi_quiesce_not_supported);


struct modldrv modldrv = {
	&mod_driverops,
	"OPL Mbox to Serial Driver",
	&dm2s_ops
};

struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


/*
 * _init - Module's init routine.
 */
int
_init(void)
{
	int ret;

	if (ddi_soft_state_init(&dm2s_softstate, sizeof (dm2s_t), 1) != 0) {
		cmn_err(CE_WARN, "softstate initialization failed\n");
		return (DDI_FAILURE);
	}
	if ((ret = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "mod_install failed, error = %d", ret);
		ddi_soft_state_fini(&dm2s_softstate);
	}
	return (ret);
}

/*
 * _fini - Module's fini routine.
 */
int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) != 0) {
		return (ret);
	}
	ddi_soft_state_fini(&dm2s_softstate);
	return (ret);
}

/*
 * _info - Module's info routine.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * dm2s_attach - Module's attach routine.
 */
int
dm2s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	dm2s_t *dm2sp;
	char name[20];


	instance = ddi_get_instance(dip);

	/* Only one instance is supported. */
	if (instance != 0) {
		cmn_err(CE_WARN, "only one instance is supported");
		return (DDI_FAILURE);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}
	if (ddi_soft_state_zalloc(dm2s_softstate, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "softstate allocation failure");
		return (DDI_FAILURE);
	}
	dm2sp = (dm2s_t *)ddi_get_soft_state(dm2s_softstate, instance);
	if (dm2sp == NULL) {
		ddi_soft_state_free(dm2s_softstate, instance);
		cmn_err(CE_WARN, "softstate allocation failure.");
		return (DDI_FAILURE);
	}
	dm2sp->ms_dip = dip;
	dm2sp->ms_major = ddi_driver_major(dip);
	dm2sp->ms_ppa = instance;

	/*
	 * Get an interrupt block cookie corresponding to the
	 * interrupt priority of the event handler.
	 * Assert that the event priority is not re-defined to
	 * some higher priority.
	 */
	/* LINTED */
	ASSERT(SCF_EVENT_PRI == DDI_SOFTINT_LOW);
	if (ddi_get_soft_iblock_cookie(dip, SCF_EVENT_PRI,
	    &dm2sp->ms_ibcookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_get_soft_iblock_cookie failed.");
		goto error;
	}
	mutex_init(&dm2sp->ms_lock, NULL, MUTEX_DRIVER,
	    (void *)dm2sp->ms_ibcookie);

	dm2sp->ms_clean |= DM2S_CLEAN_LOCK;
	cv_init(&dm2sp->ms_wait, NULL, CV_DRIVER, NULL);
	dm2sp->ms_clean |= DM2S_CLEAN_CV;

	(void) sprintf(name, "%s%d", DM2S_MODNAME, instance);
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		cmn_err(CE_WARN, "Device node creation failed.");
		goto error;
	}

	dm2sp->ms_clean |= DM2S_CLEAN_NODE;
	ddi_set_driver_private(dip, (caddr_t)dm2sp);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
error:
	dm2s_cleanup(dm2sp);
	return (DDI_FAILURE);
}

/*
 * dm2s_info - Module's info routine.
 */
/*ARGSUSED*/
int
dm2s_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dm2s_t	*dm2sp;
	minor_t	minor;
	int	ret = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		minor = getminor((dev_t)arg);
		dm2sp = (dm2s_t *)ddi_get_soft_state(dm2s_softstate, minor);
		if (dm2sp == NULL) {
			*result = NULL;
		} else {
			*result = dm2sp->ms_dip;
			ret = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		minor = getminor((dev_t)arg);
		*result = (void *)(uintptr_t)minor;
		ret = DDI_SUCCESS;
		break;

	default:
		break;
	}
	return (ret);
}

/*
 * dm2s_detach - Module's detach routine.
 */
int
dm2s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	dm2s_t *dm2sp;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	dm2sp = (dm2s_t *)ddi_get_soft_state(dm2s_softstate, instance);
	if (dm2sp == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&dm2sp->ms_lock);

	/* Check if the mailbox is still in use. */
	if (dm2sp->ms_state & DM2S_MB_INITED) {
		mutex_exit(&dm2sp->ms_lock);
		cmn_err(CE_WARN, "Mailbox in use: Detach failed");
		return (DDI_FAILURE);
	}
	mutex_exit(&dm2sp->ms_lock);
	dm2s_cleanup(dm2sp);
	return (DDI_SUCCESS);
}

/*
 * dm2s_open - Device open routine.
 *
 * Only one open supported. Clone open is not supported.
 */
/* ARGSUSED */
int
dm2s_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	dm2s_t *dm2sp;
	int instance = getminor(*dev);
	int ret = 0;

	DPRINTF(DBG_DRV, ("dm2s_open: called\n"));
	if (sflag == CLONEOPEN)	{
		/* Clone open not supported */
		DPRINTF(DBG_WARN, ("dm2s_open: clone open not supported\n"));
		return (ENOTSUP);
	}

	if (rq->q_ptr != NULL) {
		DPRINTF(DBG_WARN, ("dm2s_open: already opened\n"));
		return (EBUSY);
	}

	if ((dm2sp = ddi_get_soft_state(dm2s_softstate, instance)) == NULL) {
		DPRINTF(DBG_WARN, ("dm2s_open: instance not found\n"));
		return (ENODEV);
	}

	mutex_enter(&dm2sp->ms_lock);
	if (dm2sp->ms_state & DM2S_OPENED) {
		/* Only one open supported */
		mutex_exit(&dm2sp->ms_lock);
		DPRINTF(DBG_WARN, ("dm2s_open: already opened\n"));
		return (EBUSY);
	}

	dm2sp->ms_state |= DM2S_OPENED;
	/* Initialize the mailbox. */
	if ((ret = dm2s_mbox_init(dm2sp)) != 0) {
		dm2sp->ms_state = 0;
		mutex_exit(&dm2sp->ms_lock);
		return (ret);
	}
	rq->q_ptr = WR(rq)->q_ptr = (void *)dm2sp;
	dm2sp->ms_rq = rq;
	dm2sp->ms_wq = WR(rq);
	mutex_exit(&dm2sp->ms_lock);

	if (ret == 0) {
		qprocson(rq);		/* now schedule our queue */
	}
	DPRINTF(DBG_DRV, ("dm2s_open: ret=%d\n", ret));
	return (ret);
}

/*
 * dm2s_close - Device close routine.
 */
/* ARGSUSED */
int
dm2s_close(queue_t *rq, int flag, cred_t *cred)
{
	dm2s_t *dm2sp = (dm2s_t *)rq->q_ptr;

	DPRINTF(DBG_DRV, ("dm2s_close: called\n"));
	if (dm2sp == NULL) {
		/* Already closed once */
		return (ENODEV);
	}

	/* Close the lower layer first */
	mutex_enter(&dm2sp->ms_lock);
	(void) scf_mb_flush(dm2sp->ms_target, dm2sp->ms_key, MB_FLUSH_ALL);
	dm2s_mbox_fini(dm2sp);
	mutex_exit(&dm2sp->ms_lock);

	/*
	 * Now we can assume that no asynchronous callbacks exist.
	 * Poison the stream head so that we can't be pushed again.
	 */
	(void) putnextctl(rq, M_HANGUP);
	qprocsoff(rq);
	if (dm2sp->ms_rbufcid != 0) {
		qunbufcall(rq, dm2sp->ms_rbufcid);
		dm2sp->ms_rbufcid = 0;
	}
	if (dm2sp->ms_rq_timeoutid != 0) {
		DTRACE_PROBE1(dm2s_rqtimeout__cancel, dm2s_t, dm2sp);
		(void) quntimeout(dm2sp->ms_rq, dm2sp->ms_rq_timeoutid);
		dm2sp->ms_rq_timeoutid = 0;
	}
	if (dm2sp->ms_wq_timeoutid != 0) {
		DTRACE_PROBE1(dm2s_wqtimeout__cancel, dm2s_t, dm2sp);
		(void) quntimeout(dm2sp->ms_wq, dm2sp->ms_wq_timeoutid);
		dm2sp->ms_wq_timeoutid = 0;
	}
	/*
	 * Now we can really mark it closed.
	 */
	mutex_enter(&dm2sp->ms_lock);
	dm2sp->ms_rq = dm2sp->ms_wq = NULL;
	dm2sp->ms_state &= ~DM2S_OPENED;
	mutex_exit(&dm2sp->ms_lock);

	rq->q_ptr = WR(rq)->q_ptr = NULL;
	(void) qassociate(rq, -1);
	DPRINTF(DBG_DRV, ("dm2s_close: successfully closed\n"));
	return (0);
}

/*
 * dm2s_rsrv - Streams read side service procedure.
 *
 * All messages are received in the service procedure
 * only. This is done to simplify the streams synchronization.
 */
int
dm2s_rsrv(queue_t *rq)
{
	mblk_t *mp;
	dm2s_t *dm2sp = (dm2s_t *)rq->q_ptr;

	DPRINTF(DBG_DRV, ("dm2s_rsrv: called\n"));
	ASSERT(dm2sp != NULL);
	mutex_enter(&dm2sp->ms_lock);

	/* Receive if there are any messages waiting in the mailbox. */
	dm2s_receive(dm2sp);
	mutex_exit(&dm2sp->ms_lock);

	/* Send the received messages up the stream. */
	while ((mp = getq(rq)) != NULL) {
		if (canputnext(rq)) {
			putnext(rq, mp);
		} else {
			(void) putbq(rq, mp);
			break;
		}
	}
	DPRINTF(DBG_DRV, ("dm2s_rsrv: return\n"));
	return (0);
}

/*
 * dm2s_wsrv - Streams write side service procedure.
 *
 * All messages are transmitted in the service procedure
 * only. This is done to simplify the streams synchronization.
 */
int
dm2s_wsrv(queue_t *wq)
{
	dm2s_t *dm2sp = (dm2s_t *)wq->q_ptr;

	DPRINTF(DBG_DRV, ("dm2s_wsrv: called\n"));
	ASSERT(dm2sp != NULL);
	/* Lets cancel any timeouts waiting to be scheduled. */
	if (dm2sp->ms_wq_timeoutid != 0) {
		DTRACE_PROBE1(dm2s_wqtimeout__cancel, dm2s_t, dm2sp);
		(void) quntimeout(dm2sp->ms_wq, dm2sp->ms_wq_timeoutid);
		dm2sp->ms_wq_timeoutid = 0;
	}
	mutex_enter(&dm2sp->ms_lock);
	dm2s_start(wq, dm2sp);
	mutex_exit(&dm2sp->ms_lock);
	DPRINTF(DBG_DRV, ("dm2s_wsrv: return\n"));
	return (0);
}

/*
 * dm2s_wput - Streams write side put routine.
 *
 * All M_DATA messages are queued so that they are transmitted in
 * the service procedure. This is done to simplify the streams
 * synchronization. Other messages are handled appropriately.
 */
int
dm2s_wput(queue_t *wq, mblk_t *mp)
{
	dm2s_t	*dm2sp = (dm2s_t *)wq->q_ptr;

	DPRINTF(DBG_DRV, ("dm2s_wput: called\n"));
	if (dm2sp == NULL) {
		return (ENODEV);   /* Can't happen. */
	}

	switch (mp->b_datap->db_type) {
	case (M_DATA):
		DPRINTF(DBG_DRV, ("dm2s_wput: M_DATA message\n"));
		while (mp->b_wptr == mp->b_rptr) {
			mblk_t *mp1;

			mp1 = unlinkb(mp);
			freemsg(mp);
			mp = mp1;
			if (mp == NULL) {
				return (0);
			}
		}

		/*
		 * Simply queue the message and handle it in the service
		 * procedure.
		 */
		(void) putq(wq, mp);
		qenable(wq);
		return (0);

	case (M_PROTO):
		DPRINTF(DBG_DRV, ("dm2s_wput: M_PROTO message\n"));
		/* We don't expect this */
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_wptr = mp->b_datap->db_base;
		*mp->b_wptr++ = EPROTO;
		qreply(wq, mp);
		return (EINVAL);

	case (M_IOCTL):
		DPRINTF(DBG_DRV, ("dm2s_wput: M_IOCTL message\n"));
		if (MBLKL(mp) < sizeof (struct iocblk)) {
			freemsg(mp);
			return (0);
		}
		/*
		 * No ioctls required to be supported by this driver, so
		 * return EINVAL for all ioctls.
		 */
		miocnak(wq, mp, 0, EINVAL);
		break;

	case (M_CTL):
		DPRINTF(DBG_DRV, ("dm2s_wput: M_CTL message\n"));
		/*
		 * No M_CTL messages need to supported by this driver,
		 * so simply ignore them.
		 */
		freemsg(mp);
		break;

	case (M_FLUSH):
		DPRINTF(DBG_DRV, (
		    "dm2s_wput: M_FLUSH message 0x%X\n", *mp->b_rptr));
		if (*mp->b_rptr & FLUSHW) {	/* Flush write-side */
			(void) scf_mb_flush(dm2sp->ms_target, dm2sp->ms_key,
			    MB_FLUSH_SEND);
			flushq(wq, FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			(void) scf_mb_flush(dm2sp->ms_target, dm2sp->ms_key,
			    MB_FLUSH_RECEIVE);
			flushq(RD(wq), FLUSHDATA);
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		DPRINTF(DBG_DRV, ("dm2s_wput: UNKNOWN message\n"));
		freemsg(mp);

	}
	return (0);
}

/*
 * dm2s_cleanup - Cleanup routine.
 */
static void
dm2s_cleanup(dm2s_t *dm2sp)
{
	char name[20];

	DPRINTF(DBG_DRV, ("dm2s_cleanup: called\n"));
	ASSERT(dm2sp != NULL);
	if (dm2sp->ms_clean & DM2S_CLEAN_NODE) {
		(void) sprintf(name, "%s%d", DM2S_MODNAME, dm2sp->ms_ppa);
		ddi_remove_minor_node(dm2sp->ms_dip, name);
	}
	if (dm2sp->ms_clean & DM2S_CLEAN_LOCK)
		mutex_destroy(&dm2sp->ms_lock);
	if (dm2sp->ms_clean & DM2S_CLEAN_CV)
		cv_destroy(&dm2sp->ms_wait);
	ddi_set_driver_private(dm2sp->ms_dip, NULL);
	ddi_soft_state_free(dm2s_softstate, dm2sp->ms_ppa);
}

/*
 * dm2s_mbox_init - Mailbox specific initialization.
 */
static int
dm2s_mbox_init(dm2s_t *dm2sp)
{
	int ret;
	clock_t tout = drv_usectohz(DM2S_MB_TOUT);

	ASSERT(MUTEX_HELD(&dm2sp->ms_lock));
	dm2sp->ms_target = DM2S_TARGET_ID;
	dm2sp->ms_key = DSCP_KEY;
	dm2sp->ms_state &= ~DM2S_MB_INITED;

	/* Iterate until mailbox gets connected */
	while (!(dm2sp->ms_state & DM2S_MB_CONN)) {
		DPRINTF(DBG_MBOX, ("dm2s_mbox_init: calling mb_init\n"));
		ret = scf_mb_init(dm2sp->ms_target, dm2sp->ms_key,
		    dm2s_event_handler, (void *)dm2sp);
		DPRINTF(DBG_MBOX, ("dm2s_mbox_init: mb_init ret=%d\n", ret));

		if (ret != 0) {
			DPRINTF(DBG_MBOX,
			    ("dm2s_mbox_init: failed ret =%d\n", ret));
			DTRACE_PROBE1(dm2s_mbox_fail, int, ret);
		} else {
			dm2sp->ms_state |= DM2S_MB_INITED;

			/* Block until the mailbox is ready to communicate. */
			while (!(dm2sp->ms_state &
			    (DM2S_MB_CONN | DM2S_MB_DISC))) {

				if (cv_wait_sig(&dm2sp->ms_wait,
				    &dm2sp->ms_lock) <= 0) {
					/* interrupted */
					ret = EINTR;
					break;
				}
			}
		}

		if ((ret != 0) || (dm2sp->ms_state & DM2S_MB_DISC)) {

			if (dm2sp->ms_state & DM2S_MB_INITED) {
				(void) scf_mb_fini(dm2sp->ms_target,
				    dm2sp->ms_key);
			}
			if (dm2sp->ms_state & DM2S_MB_DISC) {
				DPRINTF(DBG_WARN,
				    ("dm2s_mbox_init: mbox DISC_ERROR\n"));
				DTRACE_PROBE1(dm2s_mbox_fail,
				    int, DM2S_MB_DISC);
			}

			dm2sp->ms_state &= ~(DM2S_MB_INITED | DM2S_MB_DISC |
			    DM2S_MB_CONN);

			if (ret == EINTR) {
				return (ret);
			}

			/*
			 * If there was failure, then wait for
			 * DM2S_MB_TOUT secs and retry again.
			 */

			DPRINTF(DBG_MBOX, ("dm2s_mbox_init: waiting...\n"));
			ret = cv_reltimedwait_sig(&dm2sp->ms_wait,
			    &dm2sp->ms_lock, tout, TR_CLOCK_TICK);
			if (ret == 0) {
				/* if interrupted, return immediately. */
				DPRINTF(DBG_MBOX,
				    ("dm2s_mbox_init: interrupted\n"));
				return (EINTR);
			}
		}
	}

	/*
	 * Obtain the max size of a single message.
	 * NOTE: There is no mechanism to update the
	 * upperlayers dynamically, so we expect this
	 * size to be atleast the default MTU size.
	 */
	ret = scf_mb_ctrl(dm2sp->ms_target, dm2sp->ms_key,
	    SCF_MBOP_MAXMSGSIZE, &dm2sp->ms_mtu);

	if ((ret == 0) && (dm2sp->ms_mtu < DM2S_DEF_MTU)) {
		cmn_err(CE_WARN, "Max message size expected >= %d "
		    "but found %d\n", DM2S_DEF_MTU, dm2sp->ms_mtu);
		ret = EIO;
	}

	if (ret != 0) {
		dm2sp->ms_state &= ~DM2S_MB_INITED;
		(void) scf_mb_fini(dm2sp->ms_target, dm2sp->ms_key);
	}
	DPRINTF(DBG_MBOX, ("dm2s_mbox_init: mb_init ret=%d\n", ret));
	return (ret);
}

/*
 * dm2s_mbox_fini - Mailbox de-initialization.
 */
static void
dm2s_mbox_fini(dm2s_t *dm2sp)
{
	int ret;

	ASSERT(dm2sp != NULL);
	if (dm2sp->ms_state & DM2S_MB_INITED) {
		DPRINTF(DBG_MBOX, ("dm2s_mbox_fini: calling mb_fini\n"));
		ret =  scf_mb_fini(dm2sp->ms_target, dm2sp->ms_key);
		if (ret != 0) {
			cmn_err(CE_WARN,
			    "Failed to close the Mailbox error =%d", ret);
		}
		DPRINTF(DBG_MBOX, ("dm2s_mbox_fini: mb_fini ret=%d\n", ret));
		dm2sp->ms_state &= ~(DM2S_MB_INITED |DM2S_MB_CONN |
		    DM2S_MB_DISC);
	}
}

/*
 * dm2s_event_handler - Mailbox event handler.
 */
void
dm2s_event_handler(scf_event_t event, void *arg)
{
	dm2s_t *dm2sp = (dm2s_t *)arg;
	queue_t	*rq;

	ASSERT(dm2sp != NULL);
	mutex_enter(&dm2sp->ms_lock);
	if (!(dm2sp->ms_state & DM2S_MB_INITED)) {
		/*
		 * Ignore all events if the state flag indicates that the
		 * mailbox not initialized, this may happen during the close.
		 */
		mutex_exit(&dm2sp->ms_lock);
		DPRINTF(DBG_MBOX,
		    ("Event(0x%X) received - Mailbox not inited\n", event));
		return;
	}
	switch (event) {
	case SCF_MB_CONN_OK:
		/*
		 * Now the mailbox is ready to use, lets wake up
		 * any one waiting for this event.
		 */
		dm2sp->ms_state |= DM2S_MB_CONN;
		cv_broadcast(&dm2sp->ms_wait);
		DPRINTF(DBG_MBOX, ("Event received = CONN_OK\n"));
		break;

	case SCF_MB_MSG_DATA:
		if (!DM2S_MBOX_READY(dm2sp)) {
			DPRINTF(DBG_MBOX,
			    ("Event(MSG_DATA) received - Mailbox not READY\n"));
			break;
		}
		/*
		 * A message is available in the mailbox.
		 * Lets enable the read service procedure
		 * to receive this message.
		 */
		if (dm2sp->ms_rq != NULL) {
			qenable(dm2sp->ms_rq);
		}
		DPRINTF(DBG_MBOX, ("Event received = MSG_DATA\n"));
		break;

	case SCF_MB_SPACE:
		if (!DM2S_MBOX_READY(dm2sp)) {
			DPRINTF(DBG_MBOX,
			    ("Event(MB_SPACE) received - Mailbox not READY\n"));
			break;
		}

		/*
		 * Now the mailbox is ready to transmit, lets
		 * schedule the write service procedure.
		 */
		if (dm2sp->ms_wq != NULL) {
			qenable(dm2sp->ms_wq);
		}
		DPRINTF(DBG_MBOX, ("Event received = MB_SPACE\n"));
		break;
	case SCF_MB_DISC_ERROR:
		dm2sp->ms_state |= DM2S_MB_DISC;
		if (dm2sp->ms_state & DM2S_MB_CONN) {
			/*
			 * If it was previously connected,
			 * then send a hangup message.
			 */
			rq = dm2sp->ms_rq;
			if (rq != NULL) {
				mutex_exit(&dm2sp->ms_lock);
				/*
				 * Send a hangup message to indicate
				 * disconnect event.
				 */
				(void) putctl(rq, M_HANGUP);
				DTRACE_PROBE1(dm2s_hangup, dm2s_t, dm2sp);
				mutex_enter(&dm2sp->ms_lock);
			}
		} else {
			/*
			 * Signal if the open is waiting for a
			 * connection.
			 */
			cv_broadcast(&dm2sp->ms_wait);
		}
		DPRINTF(DBG_MBOX, ("Event received = DISC_ERROR\n"));
		break;
	default:
		cmn_err(CE_WARN, "Unexpected event received\n");
		break;
	}
	mutex_exit(&dm2sp->ms_lock);
}

/*
 * dm2s_start - Start transmission function.
 *
 * Send all queued messages. If the mailbox is busy, then
 * start a timeout as a polling mechanism. The timeout is useful
 * to not rely entirely on the SCF_MB_SPACE event.
 */
void
dm2s_start(queue_t *wq, dm2s_t *dm2sp)
{
	mblk_t *mp;
	int ret;

	DPRINTF(DBG_DRV, ("dm2s_start: called\n"));
	ASSERT(dm2sp != NULL);
	ASSERT(MUTEX_HELD(&dm2sp->ms_lock));

	while ((mp = getq(wq)) != NULL) {
		switch (mp->b_datap->db_type) {

		case M_DATA:
			ret = dm2s_transmit(wq, mp, dm2sp->ms_target,
			    dm2sp->ms_key);
			if (ret == EBUSY || ret == ENOSPC || ret == EAGAIN) {
				DPRINTF(DBG_MBOX,
				    ("dm2s_start: recoverable err=%d\n", ret));
				/*
				 * Start a timeout to retry again.
				 */
				if (dm2sp->ms_wq_timeoutid == 0) {
					DTRACE_PROBE1(dm2s_wqtimeout__start,
					    dm2s_t, dm2sp);
					dm2sp->ms_wq_timeoutid = qtimeout(wq,
					    dm2s_wq_timeout, (void *)dm2sp,
					    dm2s_timeout_val(ret));
				}
				return;
			} else if (ret != 0) {
				mutex_exit(&dm2sp->ms_lock);
				/*
				 * An error occurred with the transmission,
				 * flush pending messages and initiate a
				 * hangup.
				 */
				flushq(wq, FLUSHDATA);
				(void) putnextctl(RD(wq), M_HANGUP);
				DTRACE_PROBE1(dm2s_hangup, dm2s_t, dm2sp);
				DPRINTF(DBG_WARN,
				    ("dm2s_start: hangup transmit err=%d\n",
				    ret));
				mutex_enter(&dm2sp->ms_lock);
			}
			break;
		default:
			/*
			 * At this point, we don't expect any other messages.
			 */
			freemsg(mp);
			break;
		}
	}
}

/*
 * dm2s_receive - Read all messages from the mailbox.
 *
 * This function is called from the read service procedure, to
 * receive the messages awaiting in the mailbox.
 */
void
dm2s_receive(dm2s_t *dm2sp)
{
	queue_t	*rq = dm2sp->ms_rq;
	mblk_t	*mp;
	int	ret;
	uint32_t len;

	DPRINTF(DBG_DRV, ("dm2s_receive: called\n"));
	ASSERT(dm2sp != NULL);
	ASSERT(MUTEX_HELD(&dm2sp->ms_lock));
	if (rq == NULL) {
		return;
	}
	/*
	 * As the number of messages in the mailbox are pretty limited,
	 * it is safe to process all messages in one loop.
	 */
	while (DM2S_MBOX_READY(dm2sp) && ((ret = scf_mb_canget(dm2sp->ms_target,
	    dm2sp->ms_key, &len)) == 0)) {
		DPRINTF(DBG_MBOX, ("dm2s_receive: mb_canget len=%d\n", len));
		if (len == 0) {
			break;
		}
		mp = allocb(len, BPRI_MED);
		if (mp == NULL) {
			DPRINTF(DBG_WARN, ("dm2s_receive: allocb failed\n"));
			/*
			 * Start a bufcall so that we can retry again
			 * when memory becomes available.
			 */
			dm2sp->ms_rbufcid = qbufcall(rq, len, BPRI_MED,
			    dm2s_bufcall_rcv, dm2sp);
			if (dm2sp->ms_rbufcid == 0) {
				DPRINTF(DBG_WARN,
				    ("dm2s_receive: qbufcall failed\n"));
				/*
				 * if bufcall fails, start a timeout to
				 * initiate a re-try after some time.
				 */
				DTRACE_PROBE1(dm2s_rqtimeout__start,
				    dm2s_t, dm2sp);
				dm2sp->ms_rq_timeoutid = qtimeout(rq,
				    dm2s_rq_timeout, (void *)dm2sp,
				    drv_usectohz(DM2S_SM_TOUT));
			}
			break;
		}

		/*
		 * Only a single scatter/gather element is enough here.
		 */
		dm2sp->ms_sg_rcv.msc_dptr = (caddr_t)mp->b_wptr;
		dm2sp->ms_sg_rcv.msc_len = len;
		DPRINTF(DBG_MBOX, ("dm2s_receive: calling getmsg\n"));
		ret = scf_mb_getmsg(dm2sp->ms_target, dm2sp->ms_key, len, 1,
		    &dm2sp->ms_sg_rcv, 0);
		DPRINTF(DBG_MBOX, ("dm2s_receive: getmsg ret=%d\n", ret));
		if (ret != 0) {
			freemsg(mp);
			break;
		}
		DMPBYTES("dm2s: Getmsg: ", len, 1, &dm2sp->ms_sg_rcv);
		mp->b_wptr += len;
		/*
		 * Queue the messages in the rq, so that the service
		 * procedure handles sending the messages up the stream.
		 */
		(void) putq(rq, mp);
	}

	if ((!DM2S_MBOX_READY(dm2sp)) || (ret != ENOMSG && ret != EMSGSIZE)) {
		/*
		 * Some thing went wrong, flush pending messages
		 * and initiate a hangup.
		 * Note: flushing the wq initiates a faster close.
		 */
		mutex_exit(&dm2sp->ms_lock);
		flushq(WR(rq), FLUSHDATA);
		(void) putnextctl(rq, M_HANGUP);
		DTRACE_PROBE1(dm2s_hangup, dm2s_t, dm2sp);
		mutex_enter(&dm2sp->ms_lock);
		DPRINTF(DBG_WARN, ("dm2s_receive: encountered unknown "
		    "condition - hangup ret=%d\n", ret));
	}
}

/*
 * dm2s_transmit - Transmit a message.
 */
int
dm2s_transmit(queue_t *wq, mblk_t *mp, target_id_t target, mkey_t key)
{
	dm2s_t *dm2sp = (dm2s_t *)wq->q_ptr;
	int ret;
	uint32_t len;
	uint32_t numsg;

	DPRINTF(DBG_DRV, ("dm2s_transmit: called\n"));
	ASSERT(dm2sp != NULL);
	ASSERT(MUTEX_HELD(&dm2sp->ms_lock));
	/*
	 * Free the message if the mailbox is not in the connected state.
	 */
	if (!DM2S_MBOX_READY(dm2sp)) {
		DPRINTF(DBG_MBOX, ("dm2s_transmit: mailbox not ready yet\n"));
		freemsg(mp);
		return (EIO);
	}

	len = msgdsize(mp);
	if (len > dm2sp->ms_mtu) {
		/*
		 * Size is too big to send, free the message.
		 */
		DPRINTF(DBG_MBOX, ("dm2s_transmit: message too large\n"));
		DTRACE_PROBE2(dm2s_msg_too_big, dm2s_t, dm2sp, uint32_t, len);
		freemsg(mp);
		return (0);
	}

	if ((ret = dm2s_prep_scatgath(mp, &numsg, dm2sp->ms_sg_tx,
	    DM2S_MAX_SG)) != 0) {
		DPRINTF(DBG_MBOX, ("dm2s_transmit: prep_scatgath failed\n"));
		(void) putbq(wq, mp);
		return (EAGAIN);
	}
	DPRINTF(DBG_MBOX, ("dm2s_transmit: calling mb_putmsg numsg=%d len=%d\n",
	    numsg, len));
	ret = scf_mb_putmsg(target, key, len, numsg, dm2sp->ms_sg_tx, 0);
	if (ret == EBUSY || ret == ENOSPC) {
		DPRINTF(DBG_MBOX,
		    ("dm2s_transmit: mailbox busy ret=%d\n", ret));
		if (++dm2sp->ms_retries >= DM2S_MAX_RETRIES) {
			/*
			 * If maximum retries are reached, then free the
			 * message.
			 */
			DPRINTF(DBG_MBOX,
			    ("dm2s_transmit: freeing msg after max retries\n"));
			DTRACE_PROBE2(dm2s_retry_fail, dm2s_t, dm2sp, int, ret);
			freemsg(mp);
			dm2sp->ms_retries = 0;
			return (0);
		}
		DTRACE_PROBE2(dm2s_mb_busy, dm2s_t, dm2sp, int, ret);
		/*
		 * Queue it back, so that we can retry again.
		 */
		(void) putbq(wq, mp);
		return (ret);
	}
	DMPBYTES("dm2s: Putmsg: ", len, numsg, dm2sp->ms_sg_tx);
	dm2sp->ms_retries = 0;
	freemsg(mp);
	DPRINTF(DBG_DRV, ("dm2s_transmit: ret=%d\n", ret));
	return (ret);
}

/*
 * dm2s_bufcall_rcv - Bufcall callaback routine.
 *
 * It simply enables read side queue so that the service procedure
 * can retry receive operation.
 */
void
dm2s_bufcall_rcv(void *arg)
{
	dm2s_t *dm2sp = (dm2s_t *)arg;

	DPRINTF(DBG_DRV, ("dm2s_bufcall_rcv: called\n"));
	mutex_enter(&dm2sp->ms_lock);
	dm2sp->ms_rbufcid = 0;
	if (dm2sp->ms_rq != NULL) {
		qenable(dm2sp->ms_rq);
	}
	mutex_exit(&dm2sp->ms_lock);
}

/*
 * dm2s_rq_timeout - Timeout callback for the read side.
 *
 * It simply enables read side queue so that the service procedure
 * can retry the receive operation.
 */
void
dm2s_rq_timeout(void *arg)
{
	dm2s_t *dm2sp = (dm2s_t *)arg;

	DPRINTF(DBG_DRV, ("dm2s_rq_timeout: called\n"));
	mutex_enter(&dm2sp->ms_lock);
	dm2sp->ms_rq_timeoutid = 0;
	if (dm2sp->ms_rq != NULL) {
		qenable(dm2sp->ms_rq);
	}
	mutex_exit(&dm2sp->ms_lock);
}

/*
 * dm2s_wq_timeout - Timeout callback for the write.
 *
 * It simply enables write side queue so that the service procedure
 * can retry the transmission operation.
 */
void
dm2s_wq_timeout(void *arg)
{
	dm2s_t *dm2sp = (dm2s_t *)arg;

	DPRINTF(DBG_DRV, ("dm2s_wq_timeout: called\n"));
	mutex_enter(&dm2sp->ms_lock);
	dm2sp->ms_wq_timeoutid = 0;
	if (dm2sp->ms_wq != NULL) {
		qenable(dm2sp->ms_wq);
	}
	mutex_exit(&dm2sp->ms_lock);
}

/*
 * dm2s_prep_scatgath - Prepare scatter/gather elements for transmission
 * of a streams message.
 */
static int
dm2s_prep_scatgath(mblk_t *mp, uint32_t *numsg, mscat_gath_t *sgp, int maxsg)
{
	uint32_t num = 0;
	mblk_t *tmp = mp;

	while ((tmp != NULL) && (num < maxsg)) {
		sgp[num].msc_dptr = (caddr_t)tmp->b_rptr;
		sgp[num].msc_len = MBLKL(tmp);
		tmp = tmp->b_cont;
		num++;
	}

	if (tmp != NULL) {
		/*
		 * Number of scatter/gather elements available are not
		 * enough, so lets pullup the msg.
		 */
		if (pullupmsg(mp, -1) != 1) {
			return (EAGAIN);
		}
		sgp[0].msc_dptr = (caddr_t)mp->b_rptr;
		sgp[0].msc_len = MBLKL(mp);
		num = 1;
	}
	*numsg = num;
	return (0);
}

/*
 * dm2s_timeout_val -- Return appropriate timeout value.
 *
 * A small timeout value is returned for EBUSY and EAGAIN cases. This is
 * because the condition is expected to be recovered sooner.
 *
 * A larger timeout value is returned for ENOSPC case, as the condition
 * depends on the peer to release buffer space.
 * NOTE: there will also be an event(SCF_MB_SPACE) but a timeout is
 * used for reliability purposes.
 */
static clock_t
dm2s_timeout_val(int error)
{
	clock_t tval;

	ASSERT(error == EBUSY || error == ENOSPC || error == EAGAIN);

	if (error == EBUSY || error == EAGAIN) {
		tval = DM2S_SM_TOUT;
	} else {
		tval = DM2S_LG_TOUT;
	}
	return (drv_usectohz(tval));
}

#ifdef DEBUG

static void
dm2s_dump_bytes(char *str, uint32_t total_len,
    uint32_t num_sg, mscat_gath_t *sgp)
{
	int i, j;
	int nsg;
	int len, tlen = 0;
	mscat_gath_t *tp;
	uint8_t *datap;
#define	BYTES_PER_LINE	20
	char bytestr[BYTES_PER_LINE * 3 + 1];
	uint32_t digest = 0;

	if (!(dm2s_debug & DBG_MESG))
		return;
	ASSERT(num_sg != 0);

	for (nsg = 0; (nsg < num_sg) && (tlen < total_len); nsg++) {
		tp = &sgp[nsg];
		datap = (uint8_t *)tp->msc_dptr;
		len = tp->msc_len;
		for (i = 0; i < len; i++) {
			digest += datap[i];
		}
		tlen += len;
	}
	(void) sprintf(bytestr, "%s Packet: Size=%d  Digest=%d\n",
	    str, total_len, digest);
	DTRACE_PROBE1(dm2s_dump_digest, unsigned char *, bytestr);

	tlen = 0;
	for (nsg = 0; (nsg < num_sg) && (tlen < total_len); nsg++) {
		tp = &sgp[nsg];
		datap = (uint8_t *)tp->msc_dptr;
		len = tp->msc_len;
		for (i = 0; i < len; ) {
			for (j = 0; (j < BYTES_PER_LINE) &&
			    (i < len); j++, i++) {
				(void) sprintf(&bytestr[j * 3], "%02X ",
				    datap[i]);
				digest += datap[i];
			}
			if (j != 0) {
				DTRACE_PROBE1(dm2s_dump, unsigned char *,
				    bytestr);
			}
		}
		tlen += i;
	}
}

#endif	/* DEBUG */
