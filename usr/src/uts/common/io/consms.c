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


/*
 * Console mouse driver for Sun.
 * The console "zs" port is linked under us, with the "ms" module pushed
 * on top of it.
 *
 * This device merely provides a way to have "/dev/mouse" automatically
 * have the "ms" module present. Due to problems with the way the "specfs"
 * file system works, you can't use an indirect device (a "stat" on
 * "/dev/mouse" won't get the right snode, so you won't get the right time
 * of last access), and due to problems with the kernel window system code,
 * you can't use a "cons"-like driver ("/dev/mouse" won't be a streams device,
 * even though operations on it get turned into operations on the real stream).
 *
 * This module supports multiple mice connected to the system at the same time.
 * All the mice are linked under consms, and act as a mouse with replicated
 * clicks. Only USB and PS/2 mouse are supported to be virtual mouse now.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/consdev.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>
#include <sys/vuid_wheel.h>
#include <sys/msio.h>
#include <sys/consms.h>

static void consms_plink(queue_t *, mblk_t *);
static int consms_punlink(queue_t *, mblk_t *);
static void
consms_lqs_ack_complete(consms_lq_t *, mblk_t *);
static void consms_add_lq(consms_lq_t *);
static void consms_check_caps(void);
static mblk_t *consms_new_firm_event(ushort_t, int);

static void consms_mux_max_wheel_report(mblk_t *);
static void consms_mux_cache_states(mblk_t *);
static void consms_mux_link_msg(consms_msg_t *);
static consms_msg_t *consms_mux_unlink_msg(uint_t);
static consms_msg_t *consms_mux_find_msg(uint_t);

static void consms_mux_iocdata(consms_msg_t *, mblk_t *);
static void consms_mux_disp_iocdata(consms_response_t *, mblk_t *);
static int consms_mux_disp_ioctl(queue_t *, mblk_t *);
static void consms_mux_copyreq(queue_t *, consms_msg_t *, mblk_t *);
static void consms_mux_ack(consms_msg_t *, mblk_t *);
static void consms_mux_disp_data(mblk_t *);


static int	consmsopen(queue_t *, dev_t *, int, int, cred_t	*);
static int	consmsclose(queue_t *, int, cred_t *);
static int	consmsuwput(queue_t *, mblk_t *);
static int	consmslrput(queue_t *, mblk_t *);
static int	consmslwserv(queue_t *);

static struct module_info consmsm_info = {
	0,
	"consms",
	0,
	1024,
	2048,
	128
};

static struct qinit consmsurinit = {
	putq,
	(int (*)())NULL,
	consmsopen,
	consmsclose,
	(int (*)())NULL,
	&consmsm_info,
	NULL
};

static struct qinit consmsuwinit = {
	consmsuwput,
	(int (*)())NULL,
	consmsopen,
	consmsclose,
	(int (*)())NULL,
	&consmsm_info,
	NULL
};

static struct qinit consmslrinit = {
	consmslrput,
	(int (*)())NULL,
	(int (*)())NULL,
	(int (*)())NULL,
	(int (*)())NULL,
	&consmsm_info,
	NULL
};

static struct qinit consmslwinit = {
	putq,
	consmslwserv,
	(int (*)())NULL,
	(int (*)())NULL,
	(int (*)())NULL,
	&consmsm_info,
	NULL
};

static struct streamtab consms_str_info = {
	&consmsurinit,
	&consmsuwinit,
	&consmslrinit,
	&consmslwinit,
};

static void consmsioctl(queue_t *q, mblk_t *mp);
static int consms_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int consms_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int consms_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int consms_kstat_update(kstat_t *, int);

/*
 * Module global data are protected by the per-module inner perimeter.
 */
static queue_t		*upperqueue;	/* regular mouse queue above us */
static dev_info_t	*consms_dip;	/* private copy of devinfo pointer */
static long	consms_idle_stamp;	/* seconds tstamp of latest mouse op */

static consms_msg_t	*consms_mux_msg; /* ioctl messages being processed */
static	kmutex_t	consms_msg_lock; /* protect ioctl messages list */

static consms_state_t	consms_state;	/* the global virtual mouse state */
static	kmutex_t	consmslock;


/*
 * Normally, kstats of type KSTAT_TYPE_NAMED have multiple elements.  In
 * this case we use this type for a single element because the ioctl code
 * for it knows how to handle mixed kernel/user data models.  Also, it
 * will be easier to add new statistics later.
 */
static struct {
	kstat_named_t idle_sec;		/* seconds since last user op */
} consms_kstat = {
	{ "idle_sec", KSTAT_DATA_LONG, }
};


static struct cb_ops cb_consms_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&consms_str_info,	/* cb_stream */
	D_MP | D_MTPERMOD	/* cb_flag */
};

static struct dev_ops consms_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	consms_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	consms_attach,		/* devo_attach */
	consms_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&(cb_consms_ops),	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};


/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Mouse Driver for Sun 'consms' 5.57",
	&consms_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	mutex_init(&consmslock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&consms_msg_lock, NULL, MUTEX_DRIVER, NULL);
	error = mod_install(&modlinkage);
	if (error != 0) {
		mutex_destroy(&consmslock);
		mutex_destroy(&consms_msg_lock);
	}
	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0)
		return (error);
	mutex_destroy(&consmslock);
	mutex_destroy(&consms_msg_lock);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
consms_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	kstat_t	*ksp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "mouse", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	consms_dip = devi;
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi, DDI_NO_AUTODETACH, 1);

	ksp = kstat_create("consms", 0, "activity", "misc", KSTAT_TYPE_NAMED,
	    sizeof (consms_kstat) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *)&consms_kstat;
		ksp->ks_update = consms_kstat_update;
		kstat_install(ksp);
		consms_idle_stamp = gethrestime_sec();	/* initial value */
	}

	consms_state.consms_lqs = NULL;
	consms_state.consms_num_lqs = 0;

	/* default consms state values */
	consms_state.consms_vuid_format = VUID_FIRM_EVENT;
	consms_state.consms_num_buttons = 0;
	consms_state.consms_num_wheels = 0;
	consms_state.consms_wheel_state_bf |= VUID_WHEEL_STATE_ENABLED;
	consms_state.consms_ms_parms.jitter_thresh =
	    CONSMS_PARMS_DEFAULT_JITTER;
	consms_state.consms_ms_parms.speed_limit =
	    CONSMS_PARMS_DEFAULT_SPEED_LIMIT;
	consms_state.consms_ms_parms.speed_law =
	    CONSMS_PARMS_DEFAULT_SPEED_LAW;
	consms_state.consms_ms_sr.height = CONSMS_SR_DEFAULT_HEIGHT;
	consms_state.consms_ms_sr.width = CONSMS_SR_DEFAULT_WIDTH;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
consms_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
consms_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (consms_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) consms_dip;
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


/*ARGSUSED*/
static int
consmsopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	upperqueue = q;
	qprocson(q);
	return (0);
}

/*ARGSUSED*/
static int
consmsclose(queue_t *q, int flag, cred_t *crp)
{
	qprocsoff(q);
	upperqueue = NULL;
	return (0);
}

/*
 * Put procedure for upper write queue.
 */
static int
consmsuwput(queue_t *q, mblk_t *mp)
{
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
	consms_msg_t		*msg;
	int			error = 0;

	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		consmsioctl(q, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(RD(q), FLUSHDATA);
		if (consms_state.consms_num_lqs > 0) {
			consms_mux_disp_data(mp);
		} else {
			/*
			 * No lower queue; just reflect this back upstream.
			 */
			*mp->b_rptr &= ~FLUSHW;
			if (*mp->b_rptr & FLUSHR)
				qreply(q, mp);
			else
				freemsg(mp);
		}
		break;

	case M_DATA:
		if (consms_state.consms_num_lqs > 0) {
			consms_mux_disp_data(mp);
		} else {
			freemsg(mp);
		}
		break;

	case M_IOCDATA:
		if ((msg = consms_mux_find_msg(iocbp->ioc_id)) != NULL) {
			consms_mux_iocdata(msg, mp);
		} else {
			error = EINVAL;
		}
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error) {
		/*
		 * Pass an error message up.
		 */
		mp->b_datap->db_type = M_ERROR;
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_rptr = mp->b_datap->db_base;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		*mp->b_rptr = (char)error;
		qreply(q, mp);
	}
	return (0);
}

static void
consmsioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	int		error;
	mblk_t		*datap;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {

	case I_LINK:
	case I_PLINK:
		mutex_enter(&consmslock);
		consms_plink(q, mp);
		mutex_exit(&consmslock);
		return;

	case I_UNLINK:
	case I_PUNLINK:
		mutex_enter(&consmslock);
		if ((error = consms_punlink(q, mp)) != 0) {
			mutex_exit(&consmslock);
			miocnak(q, mp, 0, error);
			return;
		}
		mutex_exit(&consmslock);
		iocp->ioc_count = 0;
		break;

	case MSIOBUTTONS:	/* query the number of buttons */
		if ((consms_state.consms_num_lqs <= 0) ||
		    ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)) {
			miocnak(q, mp, 0, ENOMEM);
			return;
		}
		*(int *)datap->b_wptr = consms_state.consms_num_buttons;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	default:
		/*
		 * Pass this through, if there's something to pass it
		 * through to; otherwise, reject it.
		 */
		if (consms_state.consms_num_lqs <= 0) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}
		if ((error = consms_mux_disp_ioctl(q, mp)) != 0)
			miocnak(q, mp, 0, error);

		return;
	}

	/*
	 * Common exit path for calls that return a positive
	 * acknowledgment with a return value of 0.
	 */
	miocack(q, mp, iocp->ioc_count, 0);
}

/*
 * Service procedure for lower write queue.
 * Puts things on the queue below us, if it lets us.
 */
static int
consmslwserv(queue_t *q)
{
	mblk_t *mp;

	while (canput(q->q_next) && (mp = getq(q)) != NULL)
		putnext(q, mp);
	return (0);
}

/*
 * Put procedure for lower read queue.
 */
static int
consmslrput(queue_t *q, mblk_t *mp)
{
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
	struct copyreq		*copyreq = (struct copyreq *)mp->b_rptr;
	consms_msg_t		*msg;
	consms_lq_t		*lq = (consms_lq_t *)q->q_ptr;

	ASSERT(lq != NULL);

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(WR(q), FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);
		if (upperqueue != NULL)
			putnext(upperqueue, mp);	/* pass it through */
		else {
			/*
			 * No upper queue; just reflect this back downstream.
			 */
			*mp->b_rptr &= ~FLUSHR;
			if (*mp->b_rptr & FLUSHW)
				qreply(q, mp);
			else
				freemsg(mp);
		}
		break;

	case M_DATA:
		if (upperqueue != NULL)
			putnext(upperqueue, mp);
		else
			freemsg(mp);
		consms_idle_stamp = gethrestime_sec();
		break;

	case M_IOCACK:
	case M_IOCNAK:
		/*
		 * First, check to see if this device
		 * is still being initialized.
		 */
		if (lq->lq_ioc_reply_func != NULL) {
			mutex_enter(&consmslock);
			lq->lq_ioc_reply_func(lq, mp);
			mutex_exit(&consmslock);
			freemsg(mp);
			break;
		}

		/*
		 * This is normal ioctl ack for upper layer.
		 */
		if ((msg = consms_mux_find_msg(iocbp->ioc_id)) != NULL) {
			consms_mux_ack(msg, mp);
		} else {
			freemsg(mp);
		}
		consms_idle_stamp = gethrestime_sec();
		break;

	case M_COPYIN:
	case M_COPYOUT:
		if ((msg = consms_mux_find_msg(copyreq->cq_id)) != NULL) {
			consms_mux_copyreq(q, msg, mp);
		} else
			freemsg(mp);
		consms_idle_stamp = gethrestime_sec();
		break;

	case M_ERROR:
	case M_HANGUP:
	default:
		freemsg(mp);	/* anything useful here? */
		break;
	}
	return (0);
}

/* ARGSUSED */
static int
consms_kstat_update(kstat_t *ksp, int rw)
{
	if (rw == KSTAT_WRITE)
		return (EACCES);

	consms_kstat.idle_sec.value.l = gethrestime_sec() - consms_idle_stamp;
	return (0);
}

/*ARGSUSED*/
static int
consms_punlink(queue_t *q, mblk_t *mp)
{
	struct linkblk	*linkp;
	consms_lq_t	*lq;
	consms_lq_t	*prev_lq;

	ASSERT(MUTEX_HELD(&consmslock));

	linkp = (struct linkblk *)mp->b_cont->b_rptr;

	prev_lq = NULL;
	for (lq = consms_state.consms_lqs; lq != NULL; lq = lq->lq_next) {
		if (lq->lq_queue == linkp->l_qbot) {
			if (prev_lq)
				prev_lq->lq_next = lq->lq_next;
			else
				consms_state.consms_lqs = lq->lq_next;
			kmem_free(lq, sizeof (*lq));
			consms_state.consms_num_lqs--;

			/*
			 * Check to see if mouse capabilities
			 * have changed.
			 */
			consms_check_caps();

			return (0);
		}
		prev_lq = lq;
	}

	return (EINVAL);
}

/*
 * Link a specific mouse into our mouse list.
 */
static void
consms_plink(queue_t *q, mblk_t *mp)
{
	struct	linkblk	*linkp;
	consms_lq_t	*lq;
	queue_t		*lowq;

	ASSERT(MUTEX_HELD(&consmslock));

	linkp = (struct linkblk *)mp->b_cont->b_rptr;
	lowq = linkp->l_qbot;

	lq = kmem_zalloc(sizeof (*lq), KM_SLEEP);

	lowq->q_ptr = (void *)lq;
	OTHERQ(lowq)->q_ptr = (void *)lq;
	lq->lq_queue = lowq;
	lq->lq_pending_plink = mp;
	lq->lq_pending_queue = q;

	/*
	 * Set the number of buttons to 3 by default
	 * in case the following MSIOBUTTONS ioctl fails.
	 */
	lq->lq_num_buttons = 3;

	/*
	 * Begin to initialize this mouse.
	 */
	lq->lq_state = LQS_START;
	consms_lqs_ack_complete(lq, NULL);
}

/*
 * Initialize the newly hotplugged-in mouse,
 * e.g. get the number of buttons, set event
 * format. Then we add it into our list.
 */
static void
consms_lqs_ack_complete(consms_lq_t *lq, mblk_t *mp)
{
	mblk_t			*req = NULL;
	boolean_t		skipped = B_FALSE;
	wheel_state		*ws;
	Ms_screen_resolution	*sr;
	Ms_parms		*params;

	ASSERT(MUTEX_HELD(&consmslock));

	/*
	 * We try each ioctl even if the previous one fails
	 * until we reach LQS_DONE, and then add this lq
	 * into our lq list.
	 *
	 * If the message allocation fails, we skip this ioctl,
	 * set skipped flag to B_TRUE in order to skip the ioctl
	 * result, then we try next ioctl, go to next state.
	 */
	while ((lq->lq_state < LQS_DONE) && (req == NULL)) {
		switch (lq->lq_state) {
		case LQS_START:
			/*
			 * First, issue MSIOBUTTONS ioctl
			 * to get the number of buttons.
			 */
			req = mkiocb(MSIOBUTTONS);
			if (req && ((req->b_cont = allocb(sizeof (int),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req == NULL)
				skipped = B_TRUE;
			lq->lq_state++;
			break;

		case LQS_BUTTON_COUNT_PENDING:
			if (!skipped && mp && mp->b_cont &&
			    (mp->b_datap->db_type == M_IOCACK))
				lq->lq_num_buttons =
				    *(int *)mp->b_cont->b_rptr;

			/*
			 * Second, issue VUIDGWHEELCOUNT ioctl
			 * to get the count of wheels.
			 */
			req = mkiocb(VUIDGWHEELCOUNT);
			if (req && ((req->b_cont = allocb(sizeof (int),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req == NULL)
				skipped = B_TRUE;
			lq->lq_state++;
			break;

		case LQS_WHEEL_COUNT_PENDING:
			if (!skipped && mp && mp->b_cont &&
			    (mp->b_datap->db_type == M_IOCACK))
				lq->lq_num_wheels =
				    *(int *)mp->b_cont->b_rptr;

			/*
			 * Third, issue VUIDSFORMAT ioctl
			 * to set the event format.
			 */
			req = mkiocb(VUIDSFORMAT);
			if (req && ((req->b_cont = allocb(sizeof (int),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req) {
				*(int *)req->b_cont->b_wptr =
				    consms_state.consms_vuid_format;
				req->b_cont->b_wptr += sizeof (int);
			}
			lq->lq_state++;
			break;

		case LQS_SET_VUID_FORMAT_PENDING:
			/*
			 * Fourth, issue VUIDSWHEELSTATE ioctl
			 * to set the wheel state (enable or disable).
			 */
			req = mkiocb(VUIDSWHEELSTATE);
			if (req && ((req->b_cont = allocb(sizeof (wheel_state),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req) {
				ws = (wheel_state *)req->b_cont->b_wptr;
				ws->vers = VUID_WHEEL_STATE_VERS;
				ws->id = 0;	/* the first wheel */
				ws->stateflags =
				    consms_state.consms_wheel_state_bf & 1;
				req->b_cont->b_wptr += sizeof (wheel_state);
			}
			lq->lq_state++;
			break;

		case LQS_SET_WHEEL_STATE_PENDING:
			/*
			 * Fifth,  issue MSIOSETPARMS ioctl
			 * to set the parameters for USB mouse.
			 */
			req = mkiocb(MSIOSETPARMS);
			if (req && ((req->b_cont = allocb(sizeof (Ms_parms),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req) {
				params = (Ms_parms *)req->b_cont->b_wptr;
				*params = consms_state.consms_ms_parms;
				req->b_cont->b_wptr += sizeof (Ms_parms);
			}
			lq->lq_state++;
			break;

		case LQS_SET_PARMS_PENDING:
			/*
			 * Sixth, issue MSIOSRESOLUTION ioctl
			 * to set the screen resolution for absolute mouse.
			 */
			req = mkiocb(MSIOSRESOLUTION);
			if (req && ((req->b_cont =
			    allocb(sizeof (Ms_screen_resolution),
			    BPRI_MED)) == NULL)) {
				freemsg(req);
				req = NULL;
			}
			if (req) {
				sr =
				    (Ms_screen_resolution *)req->b_cont->b_wptr;
				*sr = consms_state.consms_ms_sr;
				req->b_cont->b_wptr +=
				    sizeof (Ms_screen_resolution);
			}
			lq->lq_state++;
			break;

		case LQS_SET_RESOLUTION_PENDING:
			/*
			 * All jobs are done, lq->lq_state is turned into
			 * LQS_DONE, and this lq is added into our list.
			 */
			lq->lq_state++;
			consms_add_lq(lq);
			break;
		}
	}

	if (lq->lq_state < LQS_DONE) {
		lq->lq_ioc_reply_func = consms_lqs_ack_complete;
		(void) putq(lq->lq_queue, req);
	}
}

/*
 * Add this specific lq into our list, finally reply
 * the previous pending I_PLINK ioctl. Also check to
 * see if mouse capabilities have changed, and send
 * a dynamical notification event to upper layer if
 * necessary.
 */
static void
consms_add_lq(consms_lq_t *lq)
{
	struct	iocblk		*iocp;

	ASSERT(MUTEX_HELD(&consmslock));

	lq->lq_ioc_reply_func = NULL;
	iocp = (struct iocblk *)lq->lq_pending_plink->b_rptr;
	iocp->ioc_error = 0;
	iocp->ioc_count = 0;
	iocp->ioc_rval = 0;
	lq->lq_pending_plink->b_datap->db_type = M_IOCACK;

	/* Reply to the I_PLINK ioctl. */
	qreply(lq->lq_pending_queue, lq->lq_pending_plink);

	lq->lq_pending_plink = NULL;
	lq->lq_pending_queue = NULL;

	/*
	 * Add this lq into list.
	 */
	consms_state.consms_num_lqs++;

	lq->lq_next = consms_state.consms_lqs;
	consms_state.consms_lqs = lq;

	/*
	 * Check to see if mouse capabilities
	 * have changed.
	 */
	consms_check_caps();

}


static void
consms_check_caps(void)
{
	consms_lq_t *lq;
	int	max_buttons = 0;
	int	max_wheels = 0;
	mblk_t	*mp;

	/*
	 * Check to see if the number of buttons
	 * and the number of wheels have changed.
	 */
	for (lq = consms_state.consms_lqs; lq != NULL; lq = lq->lq_next) {
		max_buttons = CONSMS_MAX(max_buttons, lq->lq_num_buttons);
		max_wheels = CONSMS_MAX(max_wheels, lq->lq_num_wheels);
	}

	if (max_buttons != consms_state.consms_num_buttons) {
		/*
		 * Since the number of buttons have changed,
		 * send a MOUSE_CAP_CHANGE_NUM_BUT dynamical
		 * notification event to upper layer.
		 */
		consms_state.consms_num_buttons = max_buttons;
		if (upperqueue != NULL) {
			if ((mp = consms_new_firm_event(
			    MOUSE_CAP_CHANGE_NUM_BUT,
			    consms_state.consms_num_buttons)) != NULL) {
				putnext(upperqueue, mp);
			}
		}
	}

	if (max_wheels != consms_state.consms_num_wheels) {
		/*
		 * Since the number of wheels have changed,
		 * send a MOUSE_CAP_CHANGE_NUM_WHEEL dynamical
		 * notification event to upper layer.
		 */
		consms_state.consms_num_wheels = max_wheels;
		if (upperqueue != NULL) {
			if ((mp = consms_new_firm_event(
			    MOUSE_CAP_CHANGE_NUM_WHEEL,
			    consms_state.consms_num_wheels)) != NULL) {
				putnext(upperqueue, mp);
			}
		}
	}
}

/*
 * Allocate a dynamical notification event.
 */
static mblk_t *
consms_new_firm_event(ushort_t id, int value)
{
	Firm_event *fep;
	mblk_t	*tmp;

	if ((tmp = allocb(sizeof (Firm_event), BPRI_HI)) != NULL) {
		fep = (Firm_event *)tmp->b_wptr;
		fep->id = id;
		fep->pair_type = FE_PAIR_NONE;
		fep->pair = '\0';
		fep->value = value;
		tmp->b_wptr += sizeof (Firm_event);
	}

	return (tmp);
}

/*
 * Start of dispatching interfaces as a multiplexor
 */

/*
 * There is a global msg list (consms_mux_msg),
 * which is used to link all ioctl messages from
 * upper layer, which are currently being processed.
 *
 * consms_mux_link_msg links a msg into the list,
 * consms_mux_unlink_msg unlinks a msg from the list,
 * consms_mux_find_msg finds a msg from the list
 * according to its unique id.
 *
 * The id of each msg is taken from stream's mp,
 * so the id is supposed to be unique.
 */
static void
consms_mux_link_msg(consms_msg_t *msg)
{
	mutex_enter(&consms_msg_lock);
	msg->msg_next = consms_mux_msg;
	consms_mux_msg = msg;
	mutex_exit(&consms_msg_lock);
}

static consms_msg_t *
consms_mux_unlink_msg(uint_t msg_id)
{
	consms_msg_t	*msg;
	consms_msg_t	*prev_msg;

	mutex_enter(&consms_msg_lock);
	prev_msg = NULL;
	for (msg = consms_mux_msg; msg != NULL;
	    prev_msg = msg, msg = msg->msg_next) {
		if (msg->msg_id == msg_id)
			break;
	}

	if (msg != NULL) {
		if (prev_msg != NULL) {
			prev_msg->msg_next = msg->msg_next;
		} else {
			consms_mux_msg = consms_mux_msg->msg_next;
		}
		msg->msg_next = NULL;
	}
	mutex_exit(&consms_msg_lock);

	return (msg);
}

static consms_msg_t *
consms_mux_find_msg(uint_t msg_id)
{
	consms_msg_t	*msg;

	mutex_enter(&consms_msg_lock);
	for (msg = consms_mux_msg; msg != NULL; msg = msg->msg_next) {
		if (msg->msg_id == msg_id)
			break;
	}
	mutex_exit(&consms_msg_lock);

	return (msg);
}

/*
 * Received ACK or NAK from lower mice
 *
 * For non-transparent ioctl, the msg->msg_rsp_list
 * is always NULL; for transparent ioctl, it
 * remembers the M_COPYIN/M_COPYOUT request
 * messages from lower mice. So here if msg->msg_rsp_list
 * is NULL (after receiving all ACK/NAKs), we
 * are done with this specific ioctl.
 *
 * As long as one of lower mice responds success,
 * we treat it success for a ioctl.
 */
static void
consms_mux_ack(consms_msg_t *msg, mblk_t *mp)
{
	mblk_t	*ack_mp;

	/* increment response_nums */
	msg->msg_num_responses++;

	if (mp->b_datap->db_type == M_IOCACK) {
		/*
		 * Received ACK from lower, then
		 * this is the last step for both
		 * non-transparent and transparent
		 * ioctl. We only need to remember
		 * one of the ACKs, finally reply
		 * this ACK to upper layer for this
		 * specific ioctl.
		 */
		ASSERT(msg->msg_rsp_list == NULL);
		if (msg->msg_ack_mp == NULL) {
			msg->msg_ack_mp = mp;
			mp = NULL;
		}
	}

	/*
	 * Check to see if all lower mice have responded
	 * to our dispatching ioctl.
	 */
	if (msg->msg_num_responses == msg->msg_num_requests) {
		if ((msg->msg_ack_mp == NULL) &&
		    (msg->msg_rsp_list == NULL)) {
			/*
			 * All are NAKed.
			 */
			ack_mp = mp;
			mp = NULL;
		} else if (msg->msg_rsp_list == NULL) {
			/*
			 * The last step and at least one ACKed.
			 */
			ack_mp = msg->msg_ack_mp;
			consms_mux_cache_states(msg->msg_request);
			consms_mux_max_wheel_report(ack_mp);
		} else {
			/*
			 * This is a NAK, but we have
			 * already received M_COPYIN
			 * or M_COPYOUT request from
			 * at least one of lower mice.
			 * (msg->msg_rsp_list != NULL)
			 *
			 * Still copyin or copyout.
			 */
			ack_mp = msg->msg_rsp_list->rsp_mp;
			consms_mux_max_wheel_report(ack_mp);
		}

		qreply(msg->msg_queue, ack_mp);

		if (msg->msg_rsp_list == NULL) {
			/*
			 * We are done with this ioctl.
			 */
			if (msg->msg_request)
				freemsg(msg->msg_request);
			(void) consms_mux_unlink_msg(msg->msg_id);
			kmem_free(msg, sizeof (*msg));
		}
	}

	if (mp) {
		freemsg(mp);
	}
}

/*
 * Received M_COPYIN or M_COPYOUT request from
 * lower mice for transparent ioctl
 *
 * We remember each M_COPYIN/M_COPYOUT into the
 * msg->msg_rsp_list, reply upper layer using the first
 * M_COPYIN/M_COPYOUT in the list after receiving
 * all responses from lower mice, even if some of
 * them return NAKs.
 */
static void
consms_mux_copyreq(queue_t *q, consms_msg_t *msg, mblk_t *mp)
{
	consms_response_t	*rsp;

	rsp = (consms_response_t *)kmem_zalloc(sizeof (*rsp), KM_SLEEP);
	rsp->rsp_mp = mp;
	rsp->rsp_queue = q;
	if (msg->msg_rsp_list) {
		rsp->rsp_next = msg->msg_rsp_list;
	}
	msg->msg_rsp_list = rsp;
	msg->msg_num_responses++;

	if (msg->msg_num_responses == msg->msg_num_requests) {
		consms_mux_max_wheel_report(msg->msg_rsp_list->rsp_mp);
		qreply(msg->msg_queue, msg->msg_rsp_list->rsp_mp);
	}
}

/*
 * Do the real job for updating M_COPYIN/M_COPYOUT
 * request with the mp of M_IOCDATA, then put it
 * down to lower mice.
 */
static void
consms_mux_disp_iocdata(consms_response_t *rsp, mblk_t *mp)
{
	mblk_t	*down_mp = rsp->rsp_mp;
	struct copyresp *copyresp = (struct copyresp *)mp->b_rptr;
	struct copyresp *newresp = (struct copyresp *)down_mp->b_rptr;

	/*
	 * Update the rval.
	 */
	newresp->cp_rval = copyresp->cp_rval;

	/*
	 * Update the db_type to M_IOCDATA.
	 */
	down_mp->b_datap->db_type = mp->b_datap->db_type;

	/*
	 * Update the b_cont.
	 */
	if (down_mp->b_cont != NULL) {
		freemsg(down_mp->b_cont);
		down_mp->b_cont = NULL;
	}
	if (mp->b_cont != NULL) {
		down_mp->b_cont = copymsg(mp->b_cont);
	}

	/*
	 * Put it down.
	 */
	(void) putq(WR(rsp->rsp_queue), down_mp);
}

/*
 * Dispatch M_IOCDATA down to all lower mice
 * for transparent ioctl.
 *
 * We update each M_COPYIN/M_COPYOUT in the
 * msg->msg_rsp_list with the M_IOCDATA.
 */
static void
consms_mux_iocdata(consms_msg_t *msg, mblk_t *mp)
{
	consms_response_t	*rsp;
	consms_response_t	*tmp;
	consms_response_t	*first;
	struct copyresp		*copyresp;
	int			request_nums;

	ASSERT(msg->msg_rsp_list != NULL);

	/*
	 * We should remember the ioc data for
	 * VUIDSWHEELSTATE, and MSIOSRESOLUTION,
	 * for we will cache the wheel state and
	 * the screen resolution later if ACKed.
	 */
	copyresp = (struct copyresp *)mp->b_rptr;
	if ((copyresp->cp_cmd == VUIDSWHEELSTATE) ||
	    (copyresp->cp_cmd == MSIOSRESOLUTION)) {
		freemsg(msg->msg_request);
		msg->msg_request = copymsg(mp);
	}

	/*
	 * Update request numbers and response numbers.
	 */
	msg->msg_num_requests = msg->msg_num_responses;
	msg->msg_num_responses = 0;
	request_nums = 1;

	/*
	 * Since we have use the first M_COPYIN/M_COPYOUT
	 * in the msg_rsp_list to reply upper layer, the mp
	 * of M_IOCDATA can be directly used for that.
	 */
	first = msg->msg_rsp_list;
	rsp = first->rsp_next;
	msg->msg_rsp_list = NULL;

	for (rsp = first->rsp_next; rsp != NULL; ) {
		tmp = rsp;
		rsp = rsp->rsp_next;
		consms_mux_disp_iocdata(tmp, mp);
		kmem_free(tmp, sizeof (*tmp));
		request_nums++;
	}

	/* Must set the request number before the last q. */
	msg->msg_num_requests = request_nums;

	/* the first one */
	(void) putq(WR(first->rsp_queue), mp);
	kmem_free(first, sizeof (*first));
}


/*
 * Here we update the number of wheels with
 * the virtual mouse for VUIDGWHEELCOUNT ioctl.
 */
static void
consms_mux_max_wheel_report(mblk_t *mp)
{
	struct iocblk		*iocp;
	int			num_wheels;

	if (mp == NULL || mp->b_cont == NULL)
		return;

	iocp = (struct iocblk *)mp->b_rptr;

	if ((iocp->ioc_cmd == VUIDGWHEELCOUNT) &&
	    (mp->b_datap->db_type == M_COPYOUT)) {
		num_wheels = *(int *)mp->b_cont->b_rptr;
		if (num_wheels < consms_state.consms_num_wheels) {
			*(int *)mp->b_cont->b_rptr =
			    consms_state.consms_num_wheels;
		}
	}
}

/*
 * Update the virtual mouse state variables with
 * the latest value from upper layer when these
 * set ioctls return success. Thus we can update
 * low mice with the latest state values during
 * hotplug.
 */
static void
consms_mux_cache_states(mblk_t *mp)
{
	struct iocblk		*iocp;
	Ms_parms		*parms;
	Ms_screen_resolution	*sr;
	wheel_state		*ws;

	if (mp == NULL || mp->b_cont == NULL)
		return;

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	case VUIDSFORMAT:
		consms_state.consms_vuid_format = *(int *)mp->b_cont->b_rptr;
		break;

	case MSIOSETPARMS:
		parms = (Ms_parms *)mp->b_cont->b_rptr;
		consms_state.consms_ms_parms = *parms;
		break;

	case MSIOSRESOLUTION:
		sr = (Ms_screen_resolution *)mp->b_cont->b_rptr;
		consms_state.consms_ms_sr = *sr;
		break;

	case VUIDSWHEELSTATE:
		ws = (wheel_state *)mp->b_cont->b_rptr;
		consms_state.consms_wheel_state_bf =
		    (ws->stateflags << ws->id) |
		    (consms_state.consms_wheel_state_bf & ~(1 << ws->id));
		break;
	}
}

/*
 * Dispatch ioctl mp (non-transparent and transparent)
 * down to all lower mice.
 *
 * First, create a pending message for this mp, link it into
 * the global messages list. Then wait for ACK/NAK for
 * non-transparent ioctl, COPYIN/COPYOUT for transparent
 * ioctl.
 */
static int
consms_mux_disp_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;
	consms_msg_t	*msg;
	consms_lq_t	*lq;
	mblk_t		*copy_mp;
	int		error = 0;

	iocp = (struct iocblk *)mp->b_rptr;
	msg = (consms_msg_t *)kmem_zalloc(sizeof (*msg), KM_SLEEP);
	msg->msg_id = iocp->ioc_id;
	msg->msg_request = mp;
	msg->msg_queue = q;
	msg->msg_num_requests = consms_state.consms_num_lqs;
	consms_mux_link_msg(msg);

	for (lq = consms_state.consms_lqs; lq != NULL; lq = lq->lq_next) {
		if ((copy_mp = copymsg(mp)) != NULL) {
			(void) putq(lq->lq_queue, copy_mp);
		} else {
			/*
			 * If copymsg fails, we ignore this lq and
			 * try next one. As long as one of them succeeds,
			 * we dispatch this ioctl down. And later as long
			 * as one of the lower drivers return success, we
			 * reply to this ioctl with success.
			 */
			msg->msg_num_requests--;
		}
	}

	if (msg->msg_num_requests <= 0) {
		/*
		 * Since copymsg fails for all lqs, we NAK this ioctl.
		 */
		(void) consms_mux_unlink_msg(msg->msg_id);
		kmem_free(msg, sizeof (*msg));
		error = ENOMEM;
	}

	return (error);
}

/*
 * Dispatch M_DATA and M_FLUSH message down to all
 * lower mice, and there are no acknowledgements
 * for them. Here we just copy the mp and then
 * put it into the lower queues.
 */
static void
consms_mux_disp_data(mblk_t *mp)
{
	consms_lq_t	*lq;
	mblk_t		*copy_mp;

	for (lq = consms_state.consms_lqs; lq != NULL; lq = lq->lq_next) {
		if ((copy_mp = copymsg(mp)) != NULL) {
			(void) putq(lq->lq_queue, copy_mp);
		}
	}

	freemsg(mp);
}
