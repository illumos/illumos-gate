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
 * Serengeti console driver, see sys/sgcn.h for more information
 * This driver uses the QPAIR form of STREAMS Perimeters to serialize access
 * to the read and write STREAMS queues.
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
#include <sys/prom_plat.h>
#include <sys/sgsbbc.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/sgcn.h>
#include <sys/serengeti.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>

/*
 * Here we define several macros for accessing console IOSRAM
 */

#define	POINTER(base, field)	((caddr_t)&base.field)
#define	OFFSETOF(base, field)	((caddr_t)&base.field - (caddr_t)&base)

#define	RW_CONSOLE_READ		0xAAAA
#define	RW_CONSOLE_WRITE	0xBBBB

#define	CONSOLE_READ(buf, len)	sgcn_rw(RW_CONSOLE_READ, buf, len)
#define	CONSOLE_WRITE(buf, len)	sgcn_rw(RW_CONSOLE_WRITE, buf, len)

#define	SGCN_MI_IDNUM		0xABCD
#define	SGCN_MI_HIWAT		2048*2048
#define	SGCN_MI_LOWAT		128

/* dev_ops and cb_ops for device driver */
static int sgcn_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sgcn_attach(dev_info_t *, ddi_attach_cmd_t);
static int sgcn_detach(dev_info_t *, ddi_detach_cmd_t);
static int sgcn_open(queue_t *, dev_t *, int, int, cred_t *);
static int sgcn_close(queue_t *, int, cred_t *);
static int sgcn_wput(queue_t *, mblk_t *);
static int sgcn_wsrv(queue_t *);
static int sgcn_rsrv(queue_t *);

/* interrupt handlers */
static void sgcn_data_in_handler(caddr_t);
static void sgcn_space_2_out_handler(caddr_t);
static void sgcn_break_handler(caddr_t);

/* other internal sgcn routines */
static void sgcn_ioctl(queue_t *, mblk_t *);
static void sgcn_reioctl(void *);
static void sgcn_start(void);
static int sgcn_transmit(queue_t *, mblk_t *);
static void sgcn_flush(void);
static int sgcn_read_header(int, cnsram_header *);
static int sgcn_rw(int, caddr_t, int);
static void sgcn_log_error(int, int);

/* circular buffer routines */
static int circular_buffer_write(int, int, int, int, caddr_t, int);
static int circular_buffer_read(int, int, int, int, caddr_t, int);

static boolean_t abort_charseq_recognize(uchar_t);
static void sg_abort_seq_handler(char *);

static	sgcn_t *sgcn_state;
static uchar_t	sgcn_stopped = FALSE;
static int	sgcn_timeout_period = 20;	/* time out in seconds */

/* streams structures */
static struct module_info minfo = {
	SGCN_MI_IDNUM,	/* mi_idnum		*/
	"sgcn",		/* mi_idname		*/
	0,		/* mi_minpsz		*/
	INFPSZ,		/* mi_maxpsz		*/
	SGCN_MI_HIWAT,	/* mi_hiwat		*/
	SGCN_MI_LOWAT	/* mi_lowat		*/
};

static struct qinit rinit = {
	putq,		/* qi_putp		*/
	sgcn_rsrv,	/* qi_srvp		*/
	sgcn_open,	/* qi_qopen		*/
	sgcn_close,	/* qi_qclose		*/
	NULL,		/* qi_qadmin		*/
	&minfo,		/* qi_minfo		*/
	NULL		/* qi_mstat		*/
};

static struct qinit winit = {
	sgcn_wput,	/* qi_putp		*/
	sgcn_wsrv,	/* qi_srvp		*/
	sgcn_open,	/* qi_qopen		*/
	sgcn_close,	/* qi_qclose		*/
	NULL,		/* qi_qadmin		*/
	&minfo,		/* qi_minfo		*/
	NULL		/* qi_mstat		*/
};

static struct streamtab sgcnstrinfo = {
	&rinit,
	&winit,
	NULL,
	NULL
};

/* standard device driver structures */
static struct cb_ops sgcn_cb_ops = {
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
	&sgcnstrinfo,		/* cb_str		*/
	D_MP | D_MTQPAIR		/* cb_flag		*/
};

static struct dev_ops sgcn_ops = {
	DEVO_REV,
	0,			/* refcnt		*/
	sgcn_getinfo,		/* getinfo()		*/
	nulldev,		/* identify()		*/
	nulldev,		/* probe()		*/
	sgcn_attach,		/* attach()		*/
	sgcn_detach,		/* detach()		*/
	nodev,			/* reset()		*/
	&sgcn_cb_ops,		/* cb_ops		*/
	(struct bus_ops *)NULL,	/* bus_ops		*/
	NULL,			/* power()		*/
	ddi_quiesce_not_supported,	/* quiesce	*/
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Serengeti console driver",
	&sgcn_ops
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

	sgcn_state = kmem_zalloc(sizeof (sgcn_t), KM_SLEEP);

	error = mod_install(&modlinkage);

	if (error == 0) {
		mutex_init(&sgcn_state->sgcn_lock, NULL, MUTEX_DRIVER, NULL);
	} else {
		kmem_free(sgcn_state, sizeof (sgcn_t));
	}

	return (error);
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

/*
 * sgcn_attach is called at startup time.
 * There is only once instance of this driver.
 */
static int
sgcn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	extern int ddi_create_internal_pathname(
	    dev_info_t *, char *, int, minor_t);
	cnsram_header	header;
	int		rv;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_internal_pathname(dip, "sgcn", S_IFCHR, 0)
	    != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* prepare some data structures in soft state */
	mutex_enter(&sgcn_state->sgcn_lock);

	sgcn_state->sgcn_dip = dip;

	mutex_exit(&sgcn_state->sgcn_lock);

	/*
	 * We need to verify IOSRAM is intact at startup time. If by
	 * any chance IOSRAM is corrupted, that means SC is not ready.
	 * All we can do is stopping.
	 */
	rv = iosram_read(SBBC_CONSOLE_KEY, 0, (caddr_t)&header,
	    sizeof (cnsram_header));
	if (rv != 0)
		cmn_err(CE_PANIC, "sgcn_attach(): Reading from IOSRAM failed");
	if (header.cnsram_magic != CNSRAM_MAGIC)
		cmn_err(CE_PANIC, "sgcn_attach(): Wrong IOSRAM console buffer");
	if (!header.cnsram_in_end && !header.cnsram_in_begin)
		cmn_err(CE_PANIC, "sgcn_attach(): Wrong IOSRAM input buffer");
	if (!header.cnsram_out_end && !header.cnsram_out_begin)
		cmn_err(CE_PANIC, "sgcn_attach(): Wrong IOSRAM output buffer");
	/*
	 * XXX need to add extra check for version no.
	 */

	/* Allocate console input buffer */
	sgcn_state->sgcn_inbuf_size =
	    header.cnsram_in_end - header.cnsram_in_begin;
	sgcn_state->sgcn_inbuf =
	    kmem_alloc(sgcn_state->sgcn_inbuf_size, KM_SLEEP);
#ifdef SGCN_DEBUG
	prom_printf("Allocated %d(0x%X) bytes for console\n",
	    sgcn_state->sgcn_inbuf_size);
#endif

	(void) prom_serengeti_set_console_input(SGCN_CLNT_STR);

	abort_seq_handler = sg_abort_seq_handler;

#ifdef SGCN_DEBUG
	prom_printf("sgcn_attach(): SGCN driver attached\n");
#endif
	return (DDI_SUCCESS);

}

/* ARGSUSED */
static int
sgcn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	if (cmd == DDI_DETACH)
		return (DDI_FAILURE);

#ifdef SGCN_DEBUG
	prom_printf("sgcn_detach(): SGCN driver detached\n");
#endif
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sgcn_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (sgcn_state) {
			*result = (void *) sgcn_state->sgcn_dip;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		if (getminor((dev_t)arg) == 0) {
			*result = (void *)0;
			error = DDI_SUCCESS;
		}
		break;
	}

	return (error);
}

/* streams open & close */
/* ARGSUSED */
static int
sgcn_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	tty_common_t	*tty;
	int		unit = getminor(*devp);

	if (unit != 0)
		return (ENXIO);

	/* stream already open */
	if (q->q_ptr) {
		return (DDI_SUCCESS);
	}

	if (!sgcn_state) {
		cmn_err(CE_WARN, "sgcn_open(): sgcn is not configured by\
				autoconfig\n");
		return (ENXIO);
	}

	mutex_enter(&sgcn_state->sgcn_lock);
	tty = &(sgcn_state->sgcn_tty);

	tty->t_readq = q;
	tty->t_writeq = WR(q);

	/* Link the RD and WR Q's */

	q->q_ptr = WR(q)->q_ptr = (caddr_t)sgcn_state;
	sgcn_state->sgcn_readq = RD(q);
	sgcn_state->sgcn_writeq = WR(q);
	qprocson(q);

	mutex_exit(&sgcn_state->sgcn_lock);

	/* initialize interrupt handler */
	iosram_reg_intr(SBBC_CONSOLE_IN,
	    (sbbc_intrfunc_t)sgcn_data_in_handler, NULL,
	    &sgcn_state->sgcn_sbbc_in_state,
	    &sgcn_state->sgcn_sbbc_in_lock);
	iosram_reg_intr(SBBC_CONSOLE_SPACE_OUT,
	    (sbbc_intrfunc_t)sgcn_space_2_out_handler, NULL,
	    &sgcn_state->sgcn_sbbc_outspace_state,
	    &sgcn_state->sgcn_sbbc_outspace_lock);
	iosram_reg_intr(SBBC_CONSOLE_BRK,
	    (sbbc_intrfunc_t)sgcn_break_handler, NULL,
	    &sgcn_state->sgcn_sbbc_brk_state,
	    &sgcn_state->sgcn_sbbc_brk_lock);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sgcn_close(queue_t *q, int flag, cred_t *credp)
{
	int ret;

	ASSERT(sgcn_state == q->q_ptr);

	if (sgcn_state->sgcn_wbufcid != 0) {
		unbufcall(sgcn_state->sgcn_wbufcid);
	}

	ret = iosram_unreg_intr(SBBC_CONSOLE_BRK);
	ASSERT(ret == 0);

	ret = iosram_unreg_intr(SBBC_CONSOLE_SPACE_OUT);
	ASSERT(ret == 0);

	ret = iosram_unreg_intr(SBBC_CONSOLE_IN);
	ASSERT(ret == 0);

	ttycommon_close(&sgcn_state->sgcn_tty);

	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	sgcn_state->sgcn_readq = NULL;
	sgcn_state->sgcn_writeq = NULL;

	return (DDI_SUCCESS);
}

/*
 * Put procedure for write queue.
 * Respond to M_IOCTL, M_DATA and M_FLUSH messages here;
 * It put's the data onto internal sgcn_output_q.
 */
static int
sgcn_wput(queue_t *q, mblk_t *mp)
{

#ifdef SGCN_DEBUG
	struct iocblk *iocp;
	int i;
#endif

	ASSERT(sgcn_state == q->q_ptr);

	if (!mp->b_datap) {
		cmn_err(CE_PANIC, "sgcn_wput(): null datap");
	}

#ifdef SGCN_DEBUG
	prom_printf("sgcn_wput(): SGCN wput q=%X mp=%X rd=%X wr=%X type=%X\n",
	    q, mp, mp->b_rptr, mp->b_wptr, mp->b_datap->db_type);
#endif

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
	case M_CTL:
#ifdef SGCN_DEBUG
		iocp = (struct iocblk *)mp->b_rptr;
		prom_printf("sgcn_wput(): M_IOCTL cmd=%X TIOC=%X\n",
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
			 * "sgcn_start" will see it when it's done
			 * with the output before it. Poke the start
			 * routine, just in case.
			 */
			putq(q, mp);
			sgcn_start();
			break;
		default:
			sgcn_ioctl(q, mp);
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
		sgcn_stopped = TRUE;
		freemsg(mp);
		break;

	case M_START:
		sgcn_stopped = FALSE;
		freemsg(mp);
		qenable(q);	/* Start up delayed messages */
		break;

	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
#ifdef SGCN_DEBUG
		if (mp->b_rptr < mp->b_wptr) {
		prom_printf("sgcn_wput(): DATA q=%X mp=%X rd=%X wr=%X\n",
		    q, mp, mp->b_rptr, mp->b_wptr);
		prom_printf("sgcn_wput(): [[[[[");
		for (i = 0; i < mp->b_wptr-mp->b_rptr; i++) {
			prom_printf("%c", *(mp->b_rptr+i));
		}
		prom_printf("]]]]]\n");
		}
#endif /* SGCN_DEBUG */
		(void) putq(q, mp);
		sgcn_start();
		break;

	default:
		freemsg(mp);
	}

	return (0);
}

/*
 * Process an "ioctl" message sent down to us.
 */
static void
sgcn_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;
	tty_common_t	*tty;
	mblk_t		*datamp;
	int		data_size;
	int		error = 0;

#ifdef SGCN_DEBUG
	prom_printf("sgcn_ioctl(): q=%X mp=%X\n", q, mp);
#endif
	iocp = (struct iocblk *)mp->b_rptr;
	tty = &(sgcn_state->sgcn_tty);

	if (tty->t_iocpending != NULL) {
		freemsg(tty->t_iocpending);
		tty->t_iocpending = NULL;
	}
	data_size = ttycommon_ioctl(tty, q, mp, &error);
	if (data_size != 0) {
		if (sgcn_state->sgcn_wbufcid)
			unbufcall(sgcn_state->sgcn_wbufcid);
		/* call sgcn_reioctl() */
		sgcn_state->sgcn_wbufcid =
		    bufcall(data_size, BPRI_HI, sgcn_reioctl, sgcn_state);
		return;
	}

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
				mioc2ack(mp, NULL, 0, 0);
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
				mioc2ack(mp, datamp, sizeof (int), 0);
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
	qreply(q, mp);
}

static void
sgcn_reioctl(void *unit)
{
	queue_t		*q;
	mblk_t		*mp;
	sgcn_t		*sgcnp = (sgcn_t *)unit;

	if (!sgcnp->sgcn_wbufcid) {
		return;
	}
	sgcnp->sgcn_wbufcid = 0;
	if ((q = sgcnp->sgcn_tty.t_writeq) == NULL) {
		return;
	}

	if ((mp = sgcnp->sgcn_tty.t_iocpending) != NULL) {
		sgcnp->sgcn_tty.t_iocpending = NULL;
		sgcn_ioctl(q, mp);
	}
}

static void
sgcn_start()
{

	queue_t *q;
	mblk_t *mp;
	int retval;

	/*
	 * read stream queue and remove data from the queue and
	 * transmit them if possible
	 */
	q = sgcn_state->sgcn_writeq;
	ASSERT(q != NULL);
	while (mp = getq(q)) {
		switch (mp->b_datap->db_type) {
		case M_IOCTL:
			/*
			 * These are those IOCTLs queued up
			 * do it now
			 */
			sgcn_ioctl(q, mp);
			continue;
		default:
			/*
			 * M_DATA
			 * Copy it from stream queue buffer to
			 * sgcn buffer
			 */
			retval = sgcn_transmit(q, mp);

			if (retval == EBUSY) {
				/*
				 * Console output buffer is full for
				 * sgcn_timeout_period seconds, assume
				 * SC is dead, drop all console output
				 * data from stream queue.
				 */
				if (sgcn_state->sgcn_sc_active <
				    gethrestime_sec() - sgcn_timeout_period)
					sgcn_flush();
				return;
			} else if (retval == EAGAIN) {
				/*
				 * Console output just became full
				 * return
				 */
				mutex_enter(&sgcn_state->sgcn_lock);
				sgcn_state->sgcn_sc_active = gethrestime_sec();
				mutex_exit(&sgcn_state->sgcn_lock);
				return;
			} else {
				/* send more console output */
				mutex_enter(&sgcn_state->sgcn_lock);
				sgcn_state->sgcn_sc_active = gethrestime_sec();
				mutex_exit(&sgcn_state->sgcn_lock);
			}
		} /* switch */
	}

}

static int
sgcn_transmit(queue_t *q, mblk_t *mp)
{
	caddr_t		buf;
	mblk_t		*bp;
	int		len, oldlen;

#ifdef SGCN_DEBUG
	prom_printf("sgcn_transmit(): q=%X mp=%X\n", q, mp);
#endif
	do {
		bp = mp;
		oldlen = len = bp->b_wptr - bp->b_rptr;
		buf = (caddr_t)bp->b_rptr;
		len = CONSOLE_WRITE(buf, len);
		if (len > 0)
			iosram_send_intr(SBBC_CONSOLE_OUT);
		if (len >= 0 && len < oldlen) {
			/* IOSRAM is full, we are not done with mp yet */
			bp->b_rptr += len;
			(void) putbq(q, mp);
			if (len)
				return (EAGAIN);
			else
				return (EBUSY);
		}
		mp = bp->b_cont;
		freeb(bp);
	} while (mp);

	return (0);
}

/*
 * called when SC first establishes console connection
 * drop all the data on the output queue
 */
static void
sgcn_flush()
{
	queue_t *q;
	mblk_t *mp;

	q = sgcn_state->sgcn_writeq;

	prom_printf("sgcn_flush(): WARNING console output is dropped "
	    "time=%lX\n", gethrestime_sec());
	while (mp = getq(q)) {
		freemsg(mp);
	}

}

uint64_t sgcn_input_dropped;

/*
 * Interrupt handlers
 * All handlers register with SBBC driver and must follow SBBC interrupt
 * delivery conventions.
 */
/*
 * SC sends an interrupt when new data comes in
 */
/* ARGSUSED */
void
sgcn_data_in_handler(caddr_t arg)
{
	caddr_t		buf = sgcn_state->sgcn_inbuf;
	int		i, len;
	mblk_t		*mp;

	/*
	 * change interrupt state so that SBBC won't trigger
	 * another one.
	 */
	mutex_enter(&sgcn_state->sgcn_sbbc_in_lock);
	sgcn_state->sgcn_sbbc_in_state = SBBC_INTR_RUNNING;
	mutex_exit(&sgcn_state->sgcn_sbbc_in_lock);

	/* update sgcn_state for SC activity information */
	mutex_enter(&sgcn_state->sgcn_lock);
	sgcn_state->sgcn_sc_active = gethrestime_sec();
	mutex_exit(&sgcn_state->sgcn_lock);

	/* enter our perimeter */
	entersq(sgcn_state->sgcn_readq->q_syncq, SQ_CALLBACK);

	for (;;) {

		/* read from console input IOSRAM */
		len = CONSOLE_READ(buf, sgcn_state->sgcn_inbuf_size);

		if (len <= 0) {

			mutex_enter(&sgcn_state->sgcn_sbbc_in_lock);

			len = CONSOLE_READ(buf, sgcn_state->sgcn_inbuf_size);

			if (len <= 0) {
				sgcn_state->sgcn_sbbc_in_state = SBBC_INTR_IDLE;
				mutex_exit(&sgcn_state->sgcn_sbbc_in_lock);

				/* leave our perimeter */
				leavesq(sgcn_state->sgcn_readq->q_syncq,
				    SQ_CALLBACK);
				return;
			} else {
				mutex_exit(&sgcn_state->sgcn_sbbc_in_lock);
			}

		}

		iosram_send_intr(SBBC_CONSOLE_SPACE_IN);

		if (abort_enable == KIOCABORTALTERNATE) {
			for (i = 0; i < len; i ++) {
				if (abort_charseq_recognize(buf[i]))
					abort_sequence_enter((char *)NULL);
			}
		}

		/* put console input onto stream */
		if (sgcn_state->sgcn_readq) {
			if ((mp = allocb(len, BPRI_MED)) == (mblk_t *)NULL) {
				sgcn_input_dropped += len;
				cmn_err(CE_WARN,
				    "sgcn_data_in_handler(): allocb failed"
				    " (console input dropped.)");
			} else {
				bcopy(buf, mp->b_wptr, len);
				mp->b_wptr += len;
				putnext(sgcn_state->sgcn_readq, mp);
			}
		}
	}

}

/*
 * SC sends an interrupt when it takes output data
 * from a full IOSRAM
 */
/* ARGSUSED */
void
sgcn_space_2_out_handler(caddr_t arg)
{
	/*
	 * change interrupt state so that SBBC won't trigger
	 * another one.
	 */
	mutex_enter(&sgcn_state->sgcn_sbbc_outspace_lock);
	sgcn_state->sgcn_sbbc_outspace_state = SBBC_INTR_RUNNING;
	mutex_exit(&sgcn_state->sgcn_sbbc_outspace_lock);

	mutex_enter(&sgcn_state->sgcn_lock);
	sgcn_state->sgcn_sc_active = gethrestime_sec();
	mutex_exit(&sgcn_state->sgcn_lock);

	if (sgcn_state->sgcn_writeq != NULL)
		qenable(sgcn_state->sgcn_writeq);

	/* restore interrupt state */
	mutex_enter(&sgcn_state->sgcn_sbbc_outspace_lock);
	sgcn_state->sgcn_sbbc_outspace_state = SBBC_INTR_IDLE;
	mutex_exit(&sgcn_state->sgcn_sbbc_outspace_lock);
}

/*
 * SC sends an interrupt when it detects BREAK sequence
 */
/* ARGSUSED */
void
sgcn_break_handler(caddr_t arg)
{
	/*
	 * change interrupt state so that SBBC won't trigger
	 * another one.
	 */
	mutex_enter(&sgcn_state->sgcn_sbbc_brk_lock);
	sgcn_state->sgcn_sbbc_brk_state = SBBC_INTR_RUNNING;
	mutex_exit(&sgcn_state->sgcn_sbbc_brk_lock);

	if (abort_enable != KIOCABORTALTERNATE)
		abort_sequence_enter((char *)NULL);

	/* restore interrupt state */
	mutex_enter(&sgcn_state->sgcn_sbbc_brk_lock);
	sgcn_state->sgcn_sbbc_brk_state = SBBC_INTR_IDLE;
	mutex_exit(&sgcn_state->sgcn_sbbc_brk_lock);
}

/*
 * reporting errors in console driver sgcn.
 * since we can not trust console driver at this time, we need to
 * log errors in other system logs
 * error codes:
 *	EIO - iosram interface failed
 *	EPROTO - IOSRAM is corrupted
 *	EINVAL - invalid argument
 */
#define	SGCN_MAX_ERROR		100
static void
sgcn_log_error(int when, int what)
{
	char error_msg[256], error_code[256];
	static uint_t	error_counter = 0;

	error_counter ++;

	if (error_counter > SGCN_MAX_ERROR) {
		error_counter = 0;
		strcpy(error_msg, "!Too many sgcn errors");
	} else {
		(void) sprintf(error_code, "Error %d", what);

		(void) sprintf(error_msg, "!%s at %s",
		    (what == EIO) ? "IOSRAM interface failed" :
		    (what == EPROTO) ? "IOSRAM corrupted" :
		    (what == EINVAL) ? "Invalid argument" :
		    error_code,
		    (when == RW_CONSOLE_READ) ? "console input" :
		    (when == RW_CONSOLE_WRITE) ? "console output, dropped" :
		    "console I/O");
	}

	cmn_err(CE_WARN, error_msg);
}

static int
sgcn_read_header(int rw, cnsram_header *header)
{
	int	rv;

	/* check IOSRAM contents and read pointers */
	rv = iosram_read(SBBC_CONSOLE_KEY, 0, (caddr_t)header,
	    sizeof (cnsram_header));
	if (rv != 0) {
		return (-1);
	}

	/*
	 * Since the header is read in a byte-by-byte fashion
	 * using ddi_rep_get8, we need to re-read the producer
	 * or consumer pointer as integer in case it has changed
	 * after part of the previous value has been read.
	 */
	if (rw == RW_CONSOLE_READ) {
		rv = iosram_read(SBBC_CONSOLE_KEY,
		    OFFSETOF((*header), cnsram_in_wrptr),
		    POINTER((*header), cnsram_in_wrptr),
		    sizeof (header->cnsram_in_wrptr));
	} else if (rw == RW_CONSOLE_WRITE) {
		rv = iosram_read(SBBC_CONSOLE_KEY,
		    OFFSETOF((*header), cnsram_out_rdptr),
		    POINTER((*header), cnsram_out_rdptr),
		    sizeof (header->cnsram_out_rdptr));
	} else
		rv = -1;

	return (rv);
}

static int
sgcn_rw(int rw, caddr_t buf, int len)
{
	cnsram_header	header;
	int		rv, size, nbytes;

#ifdef SGCN_DEBUG
	prom_printf("sgcn_rw() rw = %X buf = %p len = %d\n",
	    rw, buf, len);
#endif /* SGCN_DEBUG */
	if (len == 0)
		return (0);

	/* sanity check */
	if (buf == NULL || len < 0) {
		sgcn_log_error(rw, EINVAL);
		return (-1);
	}

	/* check IOSRAM contents and read pointers */
	rv = sgcn_read_header(rw, &header);
	if (rv != 0) {
		sgcn_log_error(rw, EIO);
		return (-1);
	}
	if (header.cnsram_magic != CNSRAM_MAGIC) {
		sgcn_log_error(rw, EPROTO);
		return (-1);
	}

	if (rw == RW_CONSOLE_READ)
		size = header.cnsram_in_end - header.cnsram_in_begin;
	else if (rw == RW_CONSOLE_WRITE)
		size = header.cnsram_out_end - header.cnsram_out_begin;
	if (size < 0) {
		sgcn_log_error(rw, EPROTO);
		return (-1);
	}

	if (rw == RW_CONSOLE_READ)
		nbytes = circular_buffer_read(
		    header.cnsram_in_begin,
		    header.cnsram_in_end,
		    header.cnsram_in_rdptr,
		    header.cnsram_in_wrptr, buf, len);
	else if (rw == RW_CONSOLE_WRITE)
		nbytes = circular_buffer_write(
		    header.cnsram_out_begin,
		    header.cnsram_out_end,
		    header.cnsram_out_rdptr,
		    header.cnsram_out_wrptr, buf, len);

	/*
	 * error log was done in circular buffer routines,
	 * no need to call sgcn_log_error() here
	 */
	if (nbytes < 0)
		return (-1);

	if (nbytes == 0)
		return (0);

	if (rw == RW_CONSOLE_READ) {
		header.cnsram_in_rdptr =
		    (header.cnsram_in_rdptr - header.cnsram_in_begin
		    + nbytes)
		    % size + header.cnsram_in_begin;
		rv = iosram_write(SBBC_CONSOLE_KEY,
		    OFFSETOF(header, cnsram_in_rdptr),
		    POINTER(header, cnsram_in_rdptr),
		    sizeof (header.cnsram_in_rdptr));
	} else if (rw == RW_CONSOLE_WRITE) {
		header.cnsram_out_wrptr =
		    (header.cnsram_out_wrptr - header.cnsram_out_begin
		    + nbytes)
		    % size + header.cnsram_out_begin;
		rv = iosram_write(SBBC_CONSOLE_KEY,
		    OFFSETOF(header, cnsram_out_wrptr),
		    POINTER(header, cnsram_out_wrptr),
		    sizeof (header.cnsram_out_wrptr));
	}
	if (rv != 0) {
		sgcn_log_error(rw, EIO);
		return (-1);
	}

	return (nbytes);
}

/*
 * Circular buffer interfaces
 *
 * See sgcn.h for circular buffer structure
 *
 * The circular buffer is empty when read ptr == write ptr
 * and is full when read ptr is one ahead of write ptr
 */
/*
 * Write to circular buffer in IOSRAM
 * input:
 *	buf	buffer in main memory, contains data to be written
 *	len	length of data in bytes
 *	begin, end, rd, wr	buffer pointers
 * return value:
 *	actual bytes written.
 */
static int
circular_buffer_write(int begin, int end, int rd, int wr, caddr_t buf, int len)
{
	int		size, space, space_at_end;
	int		rv = 0;

	size = end - begin;
	if (size <= 0) {
		rv = EINVAL;
		goto out;
	}

	if ((len = ((len >= size) ? (size-1) : len)) == 0)
		return (0);	/* The buffer's full, so just return 0 now. */

	space = (rd - wr + size - 1) % size;
	len = min(len, space);
	space_at_end = end - wr;

	if (rd > wr || rd <= wr && space_at_end >= len) { /* one piece */
		/* write console data */
		rv = iosram_write(SBBC_CONSOLE_KEY, wr, buf, len);
		if (rv != 0) goto out;
	} else { /* break into two pieces because of circular buffer */
		/* write console data */
		if (space_at_end) {
			rv = iosram_write(SBBC_CONSOLE_KEY,
			    wr, buf, space_at_end);
			if (rv != 0) goto out;
		}
		if (len - space_at_end) {
			rv = iosram_write(SBBC_CONSOLE_KEY,
			    begin, buf+space_at_end, len-space_at_end);
			if (rv != 0) goto out;
		}
	}
	return (len);
out:
	sgcn_log_error(RW_CONSOLE_WRITE, rv);
	return (-1);
}

/*
 * Read from circular buffer in IOSRAM
 * input:
 *	buf	preallocated buffer in memory
 *	len	size of buf
 *	begin, end, rd, wr	buffer pointers
 * return value:
 *	actual bytes read
 */
/* ARGSUSED */
static int
circular_buffer_read(int begin, int end, int rd, int wr, caddr_t buf, int len)
{
	int		size, nbytes, nbytes_at_end;
	int		rv = 0;

	size = end - begin;
	if (size <= 0) {
		rv = EINVAL;
		goto out;
	}
	nbytes = (wr - rd + size) % size;

	nbytes = min(nbytes, len);

	if (wr > rd) { /* one piece */
		rv = iosram_read(SBBC_CONSOLE_KEY, rd, buf, nbytes);
		if (rv != 0) goto out;
	} else { /* break into two pieces because of circular buffer */
		nbytes_at_end = min(nbytes, end - rd);
		/* read console data */
		if (nbytes_at_end) {
			rv = iosram_read(SBBC_CONSOLE_KEY,
			    rd, buf, nbytes_at_end);
			if (rv != 0) goto out;
		}
		if (nbytes-nbytes_at_end) {
			rv = iosram_read(SBBC_CONSOLE_KEY,
			    begin, buf+nbytes_at_end, nbytes-nbytes_at_end);
			if (rv != 0) goto out;
		}
	}
	return (nbytes);
out:
	sgcn_log_error(RW_CONSOLE_READ, rv);
	return (-1);
}

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

static void
sg_abort_seq_handler(char *msg)
{
	char	key_switch;
	int	rv;

	/* read virtual keyswitch position from IOSRAM */
	rv = iosram_read(SBBC_KEYSWITCH_KEY, 0, &key_switch, 1);
	if (rv != 0) {
		/* default to not secure if read failed */
		cmn_err(CE_NOTE, "!Read keyswitch failed (%d)", rv);
		key_switch = 0;
	}
	if (key_switch & SG_KEYSWITCH_POSN_SECURE) {
		cmn_err(CE_NOTE, "!Keyswitch is in secure mode");
	} else {
		debug_enter(msg);
	}
}

static int
sgcn_rsrv(queue_t *q)
{
	mblk_t	*mp;

	if (sgcn_stopped == TRUE) {
		return (0);
	}

	mutex_enter(&sgcn_state->sgcn_lock);
	sgcn_state->sgcn_sc_active = gethrestime_sec();
	mutex_exit(&sgcn_state->sgcn_lock);

	while ((mp = getq(q)) != NULL) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else if (mp->b_datap->db_type >= QPCTL) {
			putbq(q, mp);
		}
	}

	return (0);
}

/* ARGSUSED */
static int
sgcn_wsrv(queue_t *q)
{
	if (sgcn_stopped == TRUE)
		return (0);

	mutex_enter(&sgcn_state->sgcn_lock);
	sgcn_state->sgcn_sc_active = gethrestime_sec();
	mutex_exit(&sgcn_state->sgcn_lock);

	if (sgcn_state->sgcn_writeq != NULL)
		sgcn_start();

	return (0);
}
