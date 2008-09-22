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
 * sun4v console driver
 */

#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/termios.h>
#include <sys/modctl.h>
#include <sys/kbio.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cyclic.h>
#include <sys/intr.h>
#include <sys/spl.h>
#include <sys/qcn.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#include <sys/machsystm.h>
#include <sys/consdev.h>

/* dev_ops and cb_ops for device driver */
static int qcn_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int qcn_attach(dev_info_t *, ddi_attach_cmd_t);
static int qcn_detach(dev_info_t *, ddi_detach_cmd_t);
static int qcn_open(queue_t *, dev_t *, int, int, cred_t *);
static int qcn_close(queue_t *, int, cred_t *);
static int qcn_wput(queue_t *, mblk_t *);
static int qcn_wsrv(queue_t *);
static int qcn_rsrv(queue_t *);

/* other internal qcn routines */
static void qcn_ioctl(queue_t *, mblk_t *);
static void qcn_reioctl(void *);
static void qcn_ack(mblk_t *, mblk_t *, uint_t);
static void qcn_start(void);
static int qcn_transmit_write(queue_t *, mblk_t *);
static int qcn_transmit_putchr(queue_t *, mblk_t *);
static void qcn_receive_read(void);
static void qcn_receive_getchr(void);
static void qcn_flush(void);
static uint_t qcn_hi_intr(caddr_t arg);
static uint_t qcn_soft_intr(caddr_t arg1, caddr_t arg2);

/* functions required for polled io */
static boolean_t qcn_polledio_ischar(cons_polledio_arg_t arg);
static int qcn_polledio_getchar(cons_polledio_arg_t arg);
static void qcn_polledio_putchar(cons_polledio_arg_t arg, uchar_t c);
static void qcn_polledio_enter(cons_polledio_arg_t arg);
static void qcn_polledio_exit(cons_polledio_arg_t arg);


static boolean_t abort_charseq_recognize(uchar_t);

static qcn_t *qcn_state;
static uchar_t qcn_stopped = B_FALSE;
static int qcn_timeout_period = 20;	/* time out in seconds */
size_t qcn_input_dropped;	/* dropped input character counter */

#ifdef QCN_POLLING
static void qcn_poll_handler(void *unused);
static cyc_time_t qcn_poll_time;
static cyc_handler_t qcn_poll_cychandler = {
	qcn_poll_handler,
	NULL,
	CY_LOW_LEVEL		/* XXX need softint to make this high */
};
static cyclic_id_t qcn_poll_cycid = CYCLIC_NONE;
static uint64_t	qcn_poll_interval = 5;  /* milli sec */
static uint64_t sb_interval = 0;
uint_t qcn_force_polling = 0;
#endif

#define	QCN_MI_IDNUM		0xABCE
#define	QCN_MI_HIWAT		8192
#define	QCN_MI_LOWAT		128

/* streams structures */
static struct module_info minfo = {
	QCN_MI_IDNUM,	/* mi_idnum		*/
	"qcn",		/* mi_idname		*/
	0,		/* mi_minpsz		*/
	INFPSZ,		/* mi_maxpsz		*/
	QCN_MI_HIWAT,	/* mi_hiwat		*/
	QCN_MI_LOWAT	/* mi_lowat		*/
};

static struct qinit rinit = {
	putq,		/* qi_putp		*/
	qcn_rsrv,	/* qi_srvp		*/
	qcn_open,	/* qi_qopen		*/
	qcn_close,	/* qi_qclose		*/
	NULL,		/* qi_qadmin		*/
	&minfo,		/* qi_minfo		*/
	NULL		/* qi_mstat		*/
};

static struct qinit winit = {
	qcn_wput,	/* qi_putp		*/
	qcn_wsrv,	/* qi_srvp		*/
	qcn_open,	/* qi_qopen		*/
	qcn_close,	/* qi_qclose		*/
	NULL,		/* qi_qadmin		*/
	&minfo,		/* qi_minfo		*/
	NULL		/* qi_mstat		*/
};

static struct streamtab qcnstrinfo = {
	&rinit,
	&winit,
	NULL,
	NULL
};

/* standard device driver structures */
static struct cb_ops qcn_cb_ops = {
	nulldev,		/* open()		*/
	nulldev,		/* close()		*/
	nodev,			/* strategy()		*/
	nodev,			/* print()		*/
	nodev,			/* dump()		*/
	nodev,			/* read()		*/
	nodev,			/* write()		*/
	nodev,			/* ioctl()		*/
	nodev,			/* devmap()		*/
	nodev,			/* mmap()		*/
	nodev,			/* segmap()		*/
	nochpoll,		/* poll()		*/
	ddi_prop_op,		/* prop_op()		*/
	&qcnstrinfo,		/* cb_str		*/
	D_NEW | D_MP		/* cb_flag		*/
};

static struct dev_ops qcn_ops = {
	DEVO_REV,
	0,			/* refcnt		*/
	qcn_getinfo,		/* getinfo()		*/
	nulldev,		/* identify()		*/
	nulldev,		/* probe()		*/
	qcn_attach,		/* attach()		*/
	qcn_detach,		/* detach()		*/
	nodev,			/* reset()		*/
	&qcn_cb_ops,		/* cb_ops		*/
	(struct bus_ops *)NULL,	/* bus_ops		*/
	NULL,			/* power()		*/
	ddi_quiesce_not_needed,		/* quiesce()		*/
};

static struct modldrv modldrv = {
	&mod_driverops,
	"sun4v console driver",
	&qcn_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void*)&modldrv,
	NULL
};

/* driver configuration routines */
int
_init(void)
{
	int error;
	uint64_t	major, minor;

	qcn_state = kmem_zalloc(sizeof (qcn_t), KM_SLEEP);
	qcn_state->qcn_ring = contig_mem_alloc(RINGSIZE);
	if (qcn_state->qcn_ring == NULL)
		cmn_err(CE_PANIC, "console ring allocation failed");

	error = mod_install(&modlinkage);
	if (error != 0) {
		contig_mem_free(qcn_state->qcn_ring, RINGSIZE);
		kmem_free(qcn_state, sizeof (qcn_t));
		return (error);
	}
	/*
	 * check minor number to see if CONS_WRITE is supported
	 * if so, set up real address of the buffers for hv calls.
	 */

	if (((hsvc_version(HSVC_GROUP_CORE, &major, &minor) == 0) &&
	    (major == QCN_API_MAJOR) && (minor >= QCN_API_MINOR))) {
		qcn_state->cons_write_buffer =
		    contig_mem_alloc(CONS_WR_BUF_SIZE);
		if (qcn_state->cons_write_buffer != NULL) {
			qcn_state->cons_write_buf_ra =
			    va_to_pa(qcn_state->cons_write_buffer);
			qcn_state->cons_transmit = qcn_transmit_write;
			qcn_state->cons_receive = qcn_receive_read;
			qcn_state->cons_read_buf_ra =
			    va_to_pa((char *)RING_ADDR(qcn_state));
		}
	}
	if (qcn_state->cons_transmit == NULL) {
		qcn_state->cons_transmit = qcn_transmit_putchr;
		qcn_state->cons_receive = qcn_receive_getchr;
	}
	return (0);
}

int
_fini(void)
{
	/* can't remove console driver */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
qcn_add_intrs(void)
{
	dev_info_t	*devinfo = qcn_state->qcn_dip;
	int		actual, count = 0;
	int 		x, y, rc, inum = 0;


	/* get number of interrupts */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		return (DDI_FAILURE);
	}

	/* Allocate an array of interrupt handles */
	qcn_state->qcn_intr_size = count * sizeof (ddi_intr_handle_t);
	qcn_state->qcn_htable = kmem_zalloc(qcn_state->qcn_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc() */
	rc = ddi_intr_alloc(devinfo, qcn_state->qcn_htable,
	    DDI_INTR_TYPE_FIXED, inum, count, &actual,
	    DDI_INTR_ALLOC_STRICT);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		kmem_free(qcn_state->qcn_htable, qcn_state->qcn_intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(qcn_state->qcn_htable[x]);
		}

		kmem_free(qcn_state->qcn_htable, qcn_state->qcn_intr_size);
		return (DDI_FAILURE);
	}

	qcn_state->qcn_intr_cnt = actual;

	/* Get intr priority */
	if (ddi_intr_get_pri(qcn_state->qcn_htable[0],
	    &qcn_state->qcn_intr_pri) != DDI_SUCCESS) {
		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(qcn_state->qcn_htable[x]);
		}

		kmem_free(qcn_state->qcn_htable, qcn_state->qcn_intr_size);
		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler() */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(qcn_state->qcn_htable[x],
		    (ddi_intr_handler_t *)qcn_hi_intr,
		    (caddr_t)qcn_state, NULL) != DDI_SUCCESS) {

			for (y = 0; y < x; y++) {
				(void) ddi_intr_remove_handler(
				    qcn_state->qcn_htable[y]);
			}

			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(qcn_state->qcn_htable[y]);
			}

			kmem_free(qcn_state->qcn_htable,
			    qcn_state->qcn_intr_size);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

static void
qcn_remove_intrs(void)
{
	int x;
	for (x = 0; x < qcn_state->qcn_intr_cnt; x++) {
		(void) ddi_intr_disable(qcn_state->qcn_htable[x]);
		(void) ddi_intr_remove_handler(qcn_state->qcn_htable[x]);
		(void) ddi_intr_free(qcn_state->qcn_htable[x]);
	}
	kmem_free(qcn_state->qcn_htable, qcn_state->qcn_intr_size);
}

static void
qcn_intr_enable(void)
{
	int x;

	for (x = 0; x < qcn_state->qcn_intr_cnt; x++) {
		(void) ddi_intr_enable(qcn_state->qcn_htable[x]);
	}
}

/*
 * qcn_attach is called at startup time.
 * There is only once instance of this driver.
 */
static int
qcn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	extern int ddi_create_internal_pathname(dev_info_t *, char *,
	    int, minor_t);
	uint_t soft_prip;

#ifdef QCN_POLLING
	char *binding_name;
#endif
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_internal_pathname(dip, "qcn",
	    S_IFCHR, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	qcn_state->qcn_soft_pend = 0;
	qcn_state->qcn_hangup = 0;
	qcn_state->qcn_rbuf_overflow = 0;

	/* prepare some data structures in soft state */

	qcn_state->qcn_dip = dip;

	qcn_state->qcn_polling = 0;

#ifdef QCN_POLLING
	/*
	 * This test is for the sole purposes of allowing
	 * the console to work on older firmware releases.
	 */
	binding_name = ddi_binding_name(qcn_state->qcn_dip);
	if ((strcmp(binding_name, "qcn") == 0) ||
	    (qcn_force_polling))
		qcn_state->qcn_polling = 1;

	if (qcn_state->qcn_polling) {
		qcn_poll_time.cyt_when = 0ull;
		qcn_poll_time.cyt_interval =
		    qcn_poll_interval * 1000ull * 1000ull;
		mutex_enter(&cpu_lock);
		qcn_poll_cycid = cyclic_add(&qcn_poll_cychandler,
		    &qcn_poll_time);
		mutex_exit(&cpu_lock);
	}
#endif

	if (!qcn_state->qcn_polling) {
		if (qcn_add_intrs() != DDI_SUCCESS) {
			cmn_err(CE_WARN, "qcn_attach: add_intr failed\n");
			return (DDI_FAILURE);
		}
		if (ddi_intr_add_softint(dip, &qcn_state->qcn_softint_hdl,
		    DDI_INTR_SOFTPRI_MAX, qcn_soft_intr,
		    (caddr_t)qcn_state) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "qcn_attach: add_soft_intr failed\n");
			qcn_remove_intrs();
			return (DDI_FAILURE);
		}
		if (ddi_intr_get_softint_pri(qcn_state->qcn_softint_hdl,
		    &soft_prip) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "qcn_attach: softint_pri failed\n");
			(void) ddi_intr_remove_softint(
			    qcn_state->qcn_softint_hdl);
			qcn_remove_intrs();
			return (DDI_FAILURE);
		}

	mutex_init(&qcn_state->qcn_hi_lock, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)(qcn_state->qcn_intr_pri));
	}

	mutex_init(&qcn_state->qcn_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Fill in the polled I/O structure.
	 */
	qcn_state->qcn_polledio.cons_polledio_version = CONSPOLLEDIO_V1;
	qcn_state->qcn_polledio.cons_polledio_argument =
	    (cons_polledio_arg_t)qcn_state;
	qcn_state->qcn_polledio.cons_polledio_putchar = qcn_polledio_putchar;
	qcn_state->qcn_polledio.cons_polledio_getchar = qcn_polledio_getchar;
	qcn_state->qcn_polledio.cons_polledio_ischar = qcn_polledio_ischar;
	qcn_state->qcn_polledio.cons_polledio_enter = qcn_polledio_enter;
	qcn_state->qcn_polledio.cons_polledio_exit = qcn_polledio_exit;

	/*
	 *  Enable  interrupts
	 */
	if (!qcn_state->qcn_polling) {
		qcn_intr_enable();
	}
#ifdef QCN_DEBUG
	prom_printf("qcn_attach(): qcn driver attached\n");
#endif

	return (DDI_SUCCESS);

}

/* ARGSUSED */
static int
qcn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);


#ifdef QCN_DEBUG
	prom_printf("qcn_detach(): QCN driver detached\n");
#endif

#ifdef QCN_POLLING
	if (qcn_state->qcn_polling) {
		mutex_enter(&cpu_lock);
		if (qcn_poll_cycid != CYCLIC_NONE)
			cyclic_remove(qcn_poll_cycid);
		qcn_poll_cycid = CYCLIC_NONE;
		mutex_exit(&cpu_lock);
	}
#endif

	if (!qcn_state->qcn_polling)
		qcn_remove_intrs();

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
qcn_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;
	int instance = 0;
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (qcn_state) {
#ifdef QCN_DEBUG
			prom_printf("qcn_getinfo(): devt2dip %lx\n", arg);
#endif
			*result = (void *)qcn_state->qcn_dip;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
#ifdef QCN_DEBUG
		prom_printf("qcn_getinfo(): devt2instance %lx\n", arg);
#endif
		if (getminor((dev_t)arg) == 0) {
			*result = (void *)(uintptr_t)instance;
			error = DDI_SUCCESS;
		}
		break;
	}

	return (error);
}

/* streams open & close */
/* ARGSUSED */
static int
qcn_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	tty_common_t *tty;
	int unit = getminor(*devp);

#ifdef QCN_DEBUG
	prom_printf("qcn_open(): minor %x\n", unit);
#endif

	if (unit != 0)
		return (ENXIO);

	/* stream already open */
	if (q->q_ptr != NULL)
		return (DDI_SUCCESS);

	if (!qcn_state) {
		cmn_err(CE_WARN, "qcn_open: console was not configured by "
		    "autoconfig\n");
		return (ENXIO);
	}

	mutex_enter(&qcn_state->qcn_lock);
	tty = &(qcn_state->qcn_tty);

	tty->t_readq = q;
	tty->t_writeq = WR(q);

	/* Link the RD and WR Q's */
	q->q_ptr = WR(q)->q_ptr = (caddr_t)qcn_state;
	qcn_state->qcn_readq = RD(q);
	qcn_state->qcn_writeq = WR(q);
	qprocson(q);

	mutex_exit(&qcn_state->qcn_lock);

#ifdef QCN_DEBUG
	prom_printf("qcn_open: opened as dev %lx\n", *devp);
#endif

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
qcn_close(queue_t *q, int flag, cred_t *credp)
{

	ASSERT(qcn_state == q->q_ptr);

	if (qcn_state->qcn_wbufcid != 0) {
		unbufcall(qcn_state->qcn_wbufcid);
	}
	ttycommon_close(&qcn_state->qcn_tty);

	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	qcn_state->qcn_readq = NULL;
	qcn_state->qcn_writeq = NULL;

	return (DDI_SUCCESS);
}

/*
 * Put procedure for write queue.
 * Respond to M_IOCTL, M_DATA and M_FLUSH messages here;
 * It put's the data onto internal qcn_output_q.
 */
static int
qcn_wput(queue_t *q, mblk_t *mp)
{

#ifdef QCN_DEBUG
	struct iocblk *iocp;
	int i;
#endif

	ASSERT(qcn_state == q->q_ptr);

	if (!mp->b_datap) {
		cmn_err(CE_PANIC, "qcn_wput: null datap");
	}

#ifdef QCN_DEBUG
	prom_printf("qcn_wput(): QCN wput q=%X mp=%X rd=%X wr=%X type=%X\n",
	    q, mp, mp->b_rptr, mp->b_wptr, mp->b_datap->db_type);
#endif

	mutex_enter(&qcn_state->qcn_lock);

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
	case M_CTL:
#ifdef QCN_DEBUG
		iocp = (struct iocblk *)mp->b_rptr;
		prom_printf("qcn_wput(): M_IOCTL cmd=%X TIOC=%X\n",
		    iocp->ioc_cmd, TIOC);
#endif
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
		case TCSBRK:
			/*
			 * The change do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "qcn_start" will see it when it's done
			 * with the output before it. Poke the start
			 * routine, just in case.
			 */
			(void) putq(q, mp);
			qcn_start();
			break;
		default:
			mutex_exit(&qcn_state->qcn_lock);
			qcn_ioctl(q, mp);
			mutex_enter(&qcn_state->qcn_lock);
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;

	case M_STOP:
		qcn_stopped = B_TRUE;
		freemsg(mp);
		break;

	case M_START:
		qcn_stopped = B_FALSE;
		freemsg(mp);
		qenable(q);	/* Start up delayed messages */
		break;

	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
#ifdef QCN_DEBUG
		if (mp->b_rptr < mp->b_wptr) {
		prom_printf("qcn_wput(): DATA q=%X mp=%X rd=%X wr=%X\n",
		    q, mp, mp->b_rptr, mp->b_wptr);
		prom_printf("qcn_wput(): [");
		for (i = 0; i < mp->b_wptr-mp->b_rptr; i++) {
			prom_printf("%c", *(mp->b_rptr+i));
		}
		prom_printf("]\n");
		}
#endif /* QCN_DEBUG */
		(void) putq(q, mp);
		qcn_start();
		break;

	default:
		freemsg(mp);
	}

	mutex_exit(&qcn_state->qcn_lock);

	return (0);
}

/*
 * Process an "ioctl" message sent down to us.
 */
static void
qcn_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;
	tty_common_t	*tty;
	mblk_t		*datamp;
	int		data_size;
	int		error = 0;

#ifdef QCN_DEBUG
	prom_printf("qcn_ioctl(): q=%X mp=%X\n", q, mp);
#endif

	iocp = (struct iocblk *)mp->b_rptr;

	tty = &(qcn_state->qcn_tty);

	if (tty->t_iocpending != NULL) {
		freemsg(tty->t_iocpending);
		tty->t_iocpending = NULL;
	}

	/*
	 * Handle the POLLEDIO ioctls now because ttycommon_ioctl
	 * (below) frees up the message block (mp->b_cont) which
	 * contains the pointer used to pass back results.
	 */
	switch (iocp->ioc_cmd) {
	case CONSOPENPOLLEDIO:
		error = miocpullup(mp, sizeof (struct cons_polledio *));
		if (error != 0)
			break;

		*(struct cons_polledio **)mp->b_cont->b_rptr =
		    &qcn_state->qcn_polledio;

		mp->b_datap->db_type = M_IOCACK;
		break;

	case CONSCLOSEPOLLEDIO:
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_rval = 0;
		break;

	default:
		data_size = ttycommon_ioctl(tty, q, mp, &error);
		if (data_size != 0) {
			if (qcn_state->qcn_wbufcid)
				unbufcall(qcn_state->qcn_wbufcid);
			/* call qcn_reioctl() */
			qcn_state->qcn_wbufcid =
			    bufcall(data_size, BPRI_HI, qcn_reioctl, qcn_state);
			return;
		}
	}

	mutex_enter(&qcn_state->qcn_lock);

	if (error < 0) {
		iocp = (struct iocblk *)mp->b_rptr;
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {
		case TCSBRK:
		case TIOCSBRK:
		case TIOCCBRK:
		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count != TRANSPARENT)
				qcn_ack(mp, NULL, 0);
			else
				mcopyin(mp, NULL, sizeof (int), NULL);
			break;

		case TIOCMGET:
			datamp = allocb(sizeof (int), BPRI_MED);
			if (datamp == NULL) {
				error = EAGAIN;
				break;
			}

			*(int *)datamp->b_rptr = 0;

			if (iocp->ioc_count != TRANSPARENT)
				qcn_ack(mp, datamp, sizeof (int));
			else
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			break;

		default:
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_count = 0;
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	mutex_exit(&qcn_state->qcn_lock);
	qreply(q, mp);
}

static void
qcn_reioctl(void *unit)
{
	queue_t		*q;
	mblk_t		*mp;
	qcn_t		*qcnp = (qcn_t *)unit;

	if (!qcnp->qcn_wbufcid)
		return;

	qcnp->qcn_wbufcid = 0;
	if ((q = qcnp->qcn_tty.t_writeq) == NULL)
		return;

	if ((mp = qcnp->qcn_tty.t_iocpending) == NULL)
		return;

	qcnp->qcn_tty.t_iocpending = NULL;
	qcn_ioctl(q, mp);
}

static void
qcn_ack(mblk_t *mp, mblk_t *dp, uint_t size)
{
	struct iocblk  *iocp = (struct iocblk *)mp->b_rptr;

	mp->b_datap->db_type = M_IOCACK;
	iocp->ioc_count = size;
	iocp->ioc_error = 0;
	iocp->ioc_rval = 0;
	if (mp->b_cont != NULL)
		freeb(mp->b_cont);
	if (dp != NULL) {
		mp->b_cont = dp;
		dp->b_wptr += size;
	} else
		mp->b_cont = NULL;
}

static void
qcn_start(void)
{

	queue_t *q;
	mblk_t *mp;
	int rv;

	ASSERT(MUTEX_HELD(&qcn_state->qcn_lock));

	/*
	 * read stream queue and remove data from the queue and
	 * transmit them if possible
	 */
	q = qcn_state->qcn_writeq;
	ASSERT(q != NULL);
	while (mp = getq(q)) {
		if (mp->b_datap->db_type == M_IOCTL) {
			/*
			 * These are those IOCTLs queued up
			 * do it now
			 */
			mutex_exit(&qcn_state->qcn_lock);
			qcn_ioctl(q, mp);
			mutex_enter(&qcn_state->qcn_lock);
			continue;
		}
		/*
		 * M_DATA
		 */
		rv = qcn_state->cons_transmit(q, mp);
		if (rv == EBUSY || rv == EAGAIN)
			return;
	}
}

static int
qcn_transmit_write(queue_t *q, mblk_t *mp)
{
	mblk_t		*bp;
	size_t		len;
	uint64_t	i;
	uint64_t	retval = 0;

#ifdef QCN_DEBUG
	prom_printf("qcn_transmit_write(): q=%X mp=%X\n", q, mp);
#endif

	while (mp) {
		bp = mp;
		len = bp->b_wptr - bp->b_rptr;
		/*
		 * Use the console write call to send a block of characters to
		 * the console.
		 */
		i = (len > CONS_WR_BUF_SIZE) ? CONS_WR_BUF_SIZE : len;
		bcopy(bp->b_rptr, qcn_state->cons_write_buffer, i);
		retval = hv_cnwrite(qcn_state->cons_write_buf_ra, i, &i);

		if (retval == H_EOK) {
			len -= i;
			bp->b_rptr += i;
			/*
			 * if we have finished with this buf, free
			 * and get the next buf if present.
			 */
			if (len == 0) {
				mp = bp->b_cont;
				freeb(bp);
			}
		} else {
			(void) putbq(q, mp);

			switch (retval) {

			case H_EWOULDBLOCK :
				/*
				 * hypervisor cannot process the request -
				 * channel busy.  Try again later.
				 */
				return (EAGAIN);

			case H_EIO :
				return (EIO);
			default :
				return (ENXIO);
			}
		}
	}
	return (0);
}

static int
qcn_transmit_putchr(queue_t *q, mblk_t *mp)
{
	caddr_t		buf;
	mblk_t		*bp;
	size_t		len;
	uint64_t	i;

#ifdef QCN_DEBUG
	prom_printf("qcn_transmit_putchr(): q=%X mp=%X\n", q, mp);
#endif
	while (mp) {
		bp = mp;
		len = bp->b_wptr - bp->b_rptr;
		buf = (caddr_t)bp->b_rptr;
		for (i = 0; i < len; i++) {
			if (hv_cnputchar(buf[i]) == H_EWOULDBLOCK)
				break;
		}
		if (i != len) {
			bp->b_rptr += i;
			(void) putbq(q, mp);
			return (EAGAIN);
		}
		mp = bp->b_cont;
		freeb(bp);
	}
	return (0);
}

/*
 * called when SC first establishes console connection
 * drop all the data on the output queue
 */
static void
qcn_flush(void)
{
	queue_t *q;
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&qcn_state->qcn_lock));

	q = qcn_state->qcn_writeq;

	prom_printf("qcn_flush(): WARNING console output is dropped time=%lx\n",
	    gethrestime_sec());
	while (mp = getq(q))
		freemsg(mp);
}

static void
qcn_trigger_softint(void)
{
	/*
	 * if we are not currently servicing a software interrupt
	 * (qcn_soft_pend == 0), trigger the service routine to run.
	 */
	if (atomic_swap_uint(&qcn_state->qcn_soft_pend, QCN_SP_DO) ==
	    QCN_SP_IDL) {
		(void) ddi_intr_trigger_softint(
		    qcn_state->qcn_softint_hdl, NULL);
	}
}

/*ARGSUSED*/
static uint_t
qcn_soft_intr(caddr_t arg1, caddr_t arg2)
{
	mblk_t *mp;
	int	cc;
	int	overflow_check;

	do {
		(void) atomic_swap_uint(&qcn_state->qcn_soft_pend, QCN_SP_IP);
		mutex_enter(&qcn_state->qcn_hi_lock);
		cc = RING_CNT(qcn_state);
		mutex_exit(&qcn_state->qcn_hi_lock);
		if (cc <= 0) {
			goto out;
		}

		if ((mp = allocb(cc, BPRI_MED)) == NULL) {
			mutex_enter(&qcn_state->qcn_hi_lock);
			qcn_input_dropped += cc;
			mutex_exit(&qcn_state->qcn_hi_lock);
			cmn_err(CE_WARN, "qcn_intr: allocb"
			    "failed (console input dropped)");
			goto out;
		}

		mutex_enter(&qcn_state->qcn_hi_lock);
		do {
			/* put console input onto stream */
			*(char *)mp->b_wptr++ = RING_GET(qcn_state);
		} while (--cc);

		if ((overflow_check = qcn_state->qcn_rbuf_overflow) != 0) {
			qcn_state->qcn_rbuf_overflow = 0;
		}
		mutex_exit(&qcn_state->qcn_hi_lock);

		if (overflow_check) {
			cmn_err(CE_WARN, "qcn: Ring buffer overflow\n");
		}

		if (qcn_state->qcn_readq) {
			putnext(qcn_state->qcn_readq, mp);
		}
out:
		/*
		 * If there are pending transmits because hypervisor
		 * returned EWOULDBLOCK poke start now.
		 */

		if (qcn_state->qcn_writeq != NULL) {
			if (qcn_state->qcn_hangup) {
				(void) putctl(qcn_state->qcn_readq, M_HANGUP);
				flushq(qcn_state->qcn_writeq, FLUSHDATA);
				qcn_state->qcn_hangup = 0;
			} else {
				mutex_enter(&qcn_state->qcn_lock);
				qcn_start();
				mutex_exit(&qcn_state->qcn_lock);
			}
		}
		/*
		 * now loop if another interrupt came in (qcn_trigger_softint
		 * called) while we were processing the loop
		 */
	} while (atomic_swap_uint(&qcn_state->qcn_soft_pend, QCN_SP_IDL) ==
	    QCN_SP_DO);
	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED*/
static uint_t
qcn_hi_intr(caddr_t arg)
{
	mutex_enter(&qcn_state->qcn_hi_lock);

	qcn_state->cons_receive();

	mutex_exit(&qcn_state->qcn_hi_lock);
	qcn_trigger_softint();

	return (DDI_INTR_CLAIMED);
}

static void
qcn_receive_read(void)
{
	int64_t rv;
	uint8_t *bufp;
	int64_t	retcount = 0;
	int	i;

	do {
		/*
		 * Maximize available buffer size
		 */
		if (RING_CNT(qcn_state) <= 0) {
			RING_INIT(qcn_state);
		}
		rv = hv_cnread(qcn_state->cons_read_buf_ra +
		    RING_POFF(qcn_state),
		    RING_LEFT(qcn_state),
		    &retcount);
		bufp = RING_ADDR(qcn_state);
		if (rv == H_EOK) {
			/*
			 * if the alternate break sequence is enabled, test
			 * the buffer for the sequence and if it is there,
			 * enter the debugger.
			 */
			if (abort_enable == KIOCABORTALTERNATE) {
				for (i = 0; i < retcount; i++) {
					if (abort_charseq_recognize(*bufp++)) {
						abort_sequence_enter(
						    (char *)NULL);
					}
				}
			}

			/* put console input onto stream */
			if (retcount > 0) {
				/*
				 * the characters are already in the ring,
				 * just update the pointer so the characters
				 * can be retrieved.
				 */
				RING_UPD(qcn_state, retcount);
			}
		} else {
			switch (rv) {

			case H_EWOULDBLOCK :
				/*
				 * hypervisor cannot handle the request.
				 * Try again later.
				 */
				break;


			case H_BREAK :
				/*
				 * on break, unless alternate break sequence is
				 * enabled, enter the debugger
				 */
				if (abort_enable != KIOCABORTALTERNATE)
					abort_sequence_enter((char *)NULL);
				break;

			case H_HUP :
				qcn_state->qcn_hangup = 1;
				break;

			default :
				break;
			}
		}
	} while (rv == H_EOK);
}

static void
qcn_receive_getchr(void)
{
	int64_t rv;
	uint8_t	buf;

	do {
		rv = hv_cngetchar(&buf);
		if (rv == H_EOK) {
			if (abort_enable == KIOCABORTALTERNATE) {
				if (abort_charseq_recognize(buf)) {
					abort_sequence_enter((char *)NULL);
				}
			}

			/* put console input onto stream */
			if (RING_POK(qcn_state, 1)) {
				RING_PUT(qcn_state, buf);
			} else {
				qcn_state->qcn_rbuf_overflow++;
			}
		} else {
			if (rv == H_BREAK) {
				if (abort_enable != KIOCABORTALTERNATE)
					abort_sequence_enter((char *)NULL);
			}

			if (rv == H_HUP)  {
				qcn_state->qcn_hangup = 1;
			}
			return;
		}
	} while (rv == H_EOK);
}

#ifdef QCN_POLLING
/*ARGSUSED*/
static void
qcn_poll_handler(void *unused)
{
	mblk_t *mp;
	int64_t rv;
	uint8_t buf;
	int qcn_writeq_flush = 0;

	/* LINTED: E_CONSTANT_CONDITION */
	while (1) {
		rv = hv_cngetchar(&buf);
		if (rv == H_BREAK) {
			if (abort_enable != KIOCABORTALTERNATE)
				abort_sequence_enter((char *)NULL);
		}

		if (rv == H_HUP)  {
			if (qcn_state->qcn_readq) {
				(void) putctl(qcn_state->qcn_readq, M_HANGUP);
				qcn_writeq_flush = 1;
			}
			goto out;
		}

		if (rv != H_EOK)
			goto out;

		if (abort_enable == KIOCABORTALTERNATE) {
			if (abort_charseq_recognize(buf)) {
				abort_sequence_enter((char *)NULL);
			}
		}

		/* put console input onto stream */
		if (qcn_state->qcn_readq) {
			if ((mp = allocb(1, BPRI_MED)) == NULL) {
				qcn_input_dropped++;
				cmn_err(CE_WARN, "qcn_intr: allocb"
				    "failed (console input dropped)");
				return;
			}
			*(char *)mp->b_wptr++ = buf;
			putnext(qcn_state->qcn_readq, mp);
		}
	}
out:
/*
 * If there are pending transmits because hypervisor
 * returned EWOULDBLOCK poke start now.
 */

	mutex_enter(&qcn_state->qcn_lock);
	if (qcn_state->qcn_writeq != NULL) {
		if (qcn_writeq_flush) {
			flushq(qcn_state->qcn_writeq, FLUSHDATA);
		} else {
			qcn_start();
		}
	}
	mutex_exit(&qcn_state->qcn_lock);
}
#endif

/*
 * Check for abort character sequence, copied from zs_async.c
 */
#define	CNTRL(c) ((c)&037)

static boolean_t
abort_charseq_recognize(uchar_t ch)
{
	static int state = 0;
	static char sequence[] = { '\r', '~', CNTRL('b') };

	if (ch == sequence[state]) {
		if (++state >= sizeof (sequence)) {
			state = 0;
			return (B_TRUE);
		}
	} else {
		state = (ch == sequence[0]) ? 1 : 0;
	}
	return (B_FALSE);
}


static int
qcn_rsrv(queue_t *q)
{
	mblk_t	*mp;

	if (qcn_stopped == B_TRUE)
		return (0);

	mutex_enter(&qcn_state->qcn_lock);

	while ((mp = getq(q)) != NULL) {
		if (canputnext(q))
			putnext(q, mp);
		else if (mp->b_datap->db_type >= QPCTL)
			(void) putbq(q, mp);
	}

	mutex_exit(&qcn_state->qcn_lock);

	return (0);
}

/* ARGSUSED */
static int
qcn_wsrv(queue_t *q)
{
	if (qcn_stopped == B_TRUE)
		return (0);

	mutex_enter(&qcn_state->qcn_lock);

	if (qcn_state->qcn_writeq != NULL)
		qcn_start();

	mutex_exit(&qcn_state->qcn_lock);

	return (0);
}

static boolean_t
qcn_polledio_ischar(cons_polledio_arg_t arg)
{
	qcn_t *state = (qcn_t *)arg;

	if (state->qcn_char_available)
		return (B_TRUE);

	return (state->qcn_char_available =
	    (hv_cngetchar(&state->qcn_hold_char) == H_EOK));
}


static int
qcn_polledio_getchar(cons_polledio_arg_t arg)
{
	qcn_t *state = (qcn_t *)arg;

	while (!qcn_polledio_ischar(arg))
		drv_usecwait(10);

	state->qcn_char_available = B_FALSE;

	return ((int)state->qcn_hold_char);
}

static void
qcn_polledio_putchar(cons_polledio_arg_t arg, uchar_t c)
{
	if (c == '\n')
		qcn_polledio_putchar(arg, '\r');

	while (hv_cnputchar((uint8_t)c) == H_EWOULDBLOCK)
		drv_usecwait(10);
}

static void
qcn_polledio_enter(cons_polledio_arg_t arg)
{
	qcn_t *state = (qcn_t *)arg;

	state->qcn_char_available = B_FALSE;
}

/* ARGSUSED */
static void
qcn_polledio_exit(cons_polledio_arg_t arg)
{
}
