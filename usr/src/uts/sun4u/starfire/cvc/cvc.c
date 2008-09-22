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
 * MT STREAMS Virtual Console Device Driver
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/tty.h>
#include <sys/ptyvar.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <sys/conf.h>

#include <sys/starfire.h>
#include <sys/mman.h>
#include <vm/seg_kmem.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/cvc.h>
#include <sys/cpu_sgn.h>

extern void	prom_printf(char *fmt, ...);

static int	cvc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	cvc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	cvc_detach(dev_info_t *, ddi_detach_cmd_t);
static int	cvc_open(register queue_t *, dev_t *, int, int, cred_t *);
static int	cvc_close(queue_t *, int, cred_t *);
static int	cvc_wput(queue_t *, mblk_t *);
static int	cvc_wsrv(queue_t *);
static void	cvc_ioctl(queue_t *, mblk_t *);
static void	cvc_ack(mblk_t *, mblk_t *, uint_t);
static void	cvc_reioctl(void *);
static void	cvc_input_daemon(void);
static void	cvc_putc(register int);
static void	cvc_flush_buf(void *);
static void	cvc_bbsram_ops(volatile uchar_t *);

static caddr_t	cvc_iobuf_mapin(processorid_t);
static void	cvc_iobuf_mapout(processorid_t);
	void	cvc_assign_iocpu(processorid_t);

/*
 * Private copy of devinfo pointer; cvc_info uses it.
 */
static dev_info_t	*cvcdip;

/*
 * This buffer is used to manage mapping in the I/O buffer that CVC
 * uses when communicating with the SSP Client (netcon_server) via bbsram.
 */
static caddr_t	cvc_iobufp[NCPU];

typedef struct cvc_s {
	bufcall_id_t	cvc_wbufcid;
	tty_common_t	cvc_tty;
} cvc_t;

cvc_t	cvc_common_tty;

static struct module_info cvcm_info = {
	1313,		/* mi_idnum Bad luck number  ;-) */
	"cvc",		/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	2048,		/* mi_hiwat */
	2048		/* mi_lowat */
};

static struct qinit cvcrinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	cvc_open,	/* qi_qopen */
	cvc_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&cvcm_info,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct qinit cvcwinit = {
	cvc_wput,	/* qi_putp */
	cvc_wsrv,	/* qi_srvp */
	cvc_open,	/* qi_qopen */
	cvc_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&cvcm_info,	/* qi_minfo */
	NULL		/* qi_mstat */
};

struct streamtab	cvcinfo = {
	&cvcrinit,	/* st_rdinit */
	&cvcwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

#define	TIMEOUT_DELAY		100000

#define	BBSRAM_INPUT_BUF	((volatile char *)(cvc_iobufp[cvc_iocpu] \
					+ BBSRAM_INPUT_COUNT_OFF))

#define	BBSRAM_OUTPUT_BUF	((volatile char *)(cvc_iobufp[cvc_iocpu] \
					+ BBSRAM_OUTPUT_COUNT_OFF))

#define	BBSRAM_INPUT_COUNT	(*((volatile short *)BBSRAM_INPUT_BUF))

#define	BBSRAM_OUTPUT_COUNT	(*((volatile short *)BBSRAM_OUTPUT_BUF))

#define	CVC_OUT_MAXSPIN	1024

/* The bbsram control reg is located at the end of the I/O buffers */
#define	BBSRAM_CONTROL_REG	((volatile uchar_t *)(cvc_iobufp[cvc_iocpu] \
					+ CVC_IN_SIZE + CVC_OUT_SIZE))

static krwlock_t	cvclock;	/* lock protecting everything here */
static queue_t		*cvcinput_q;	/* queue for console input */
static queue_t		*cvcoutput_q;	/* queue for console output */
static int		cvc_instance = -1;
static int		cvc_stopped = 0;
static int		cvc_suspended = 0;
static int		cvc_hangup_ok = 0;

static kthread_id_t	cvc_input_daemon_thread;
static kmutex_t		cvcmutex;	/* protects input */
static kmutex_t		cvc_buf_mutex;	/* protects internal output buffer */
static kmutex_t		cvc_bbsram_input_mutex; /* protects BBSRAM inp buff */
static int		input_ok = 0;	/* true when stream is valid */
static int		stop_bbsram = 1; /* true when BBSRAM is not usable */
static int		stop_timeout = 0;
static uchar_t		cvc_output_buffer[MAX_XFER_OUTPUT]; /* output buffer */
static ushort_t		cvc_output_count = 0;
static int		via_bbsram = 0; /* toggle switch */
static timeout_id_t	cvc_timeout_id = (timeout_id_t)-1;
static processorid_t	cvc_iocpu = -1;	/* cpu id of cpu zero */

/*
 * Module linkage information for the kernel.
 */

DDI_DEFINE_STREAM_OPS(cvcops, nulldev, nulldev, cvc_attach, cvc_detach,
		    nodev, cvc_info, (D_MTPERQ | D_MP), &cvcinfo,
		    ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"CVC driver 'cvc'",
	&cvcops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = mod_install(&modlinkage);
	if (status == 0) {
		mutex_init(&cvcmutex, NULL, MUTEX_DEFAULT, NULL);
	}
	return (status);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * DDI glue routines.
 */

/* ARGSUSED */
static int
cvc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	static char	been_here = 0;

	if (cmd == DDI_RESUME) {
		cvc_suspended = 0;
		return (DDI_SUCCESS);
	}

	mutex_enter(&cvcmutex);
	if (!been_here) {
		been_here = 1;
		mutex_init(&cvc_buf_mutex, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&cvc_bbsram_input_mutex, NULL, MUTEX_DEFAULT, NULL);
		rw_init(&cvclock, NULL, RW_DRIVER, NULL);
		rw_enter(&cvclock, RW_WRITER);
		cvc_timeout_id = timeout(cvc_flush_buf, NULL,
		    drv_usectohz(TIMEOUT_DELAY));
		rw_exit(&cvclock);
		cvc_instance = ddi_get_instance(devi);
	} else {
#if defined(DEBUG)
		cmn_err(CE_NOTE,
		    "cvc_attach: called multiple times!! (instance = %d)",
		    ddi_get_instance(devi));
#endif /* DEBUG */
		return (DDI_SUCCESS);
	}
	mutex_exit(&cvcmutex);

	if (ddi_create_minor_node(devi, "cvc", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	cvcdip = devi;
	cvcinput_q = NULL;
	cvcoutput_q = NULL;
	return (DDI_SUCCESS);
}

static int
cvc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		cvc_suspended = 1;
	} else {
		if (cmd != DDI_DETACH) {
			return (DDI_FAILURE);
		}
		/*
		 * XXX this doesn't even begin to address the detach
		 * issues - it doesn't terminate the outstanding thread,
		 * it doesn't clean up mutexes, kill the timeout routine
		 * etc.
		 */
		if (cvc_instance == ddi_get_instance(dip)) {
			ddi_remove_minor_node(dip, NULL);
		}
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
cvc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (cvcdip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)cvcdip;
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

/* ARGSUSED */
static int
cvc_open(register queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	register int		unit = getminor(*devp);
	register int		err = 0;
	tty_common_t		*tty;
	cvc_t			*cp;
	static int		input_daemon_started;

	if (unit != 0)
		return (ENXIO);

	if (q->q_ptr)
		return (0);

	cp = (cvc_t *)&cvc_common_tty;
	bzero((caddr_t)cp, sizeof (cvc_t));
	cp->cvc_wbufcid = 0;
	tty = &cp->cvc_tty;
	tty->t_readq = q;
	tty->t_writeq = WR(q);
	WR(q)->q_ptr = q->q_ptr = (caddr_t)cp;
	cvcinput_q = RD(q);		/* save for cvc_redir */
	qprocson(q);
	mutex_enter(&cvcmutex);
	input_ok = 1;
	if (!input_daemon_started) {
		extern struct cpu	*SIGBCPU;	/* bugid4141050 */
		extern cpu_sgnblk_t	*cpu_sgnblkp[];

		input_daemon_started = 1;
		mutex_exit(&cvcmutex);

		ASSERT(cpu_sgnblkp[SIGBCPU->cpu_id] != NULL);
		cvc_assign_iocpu(SIGBCPU->cpu_id);

		cvc_input_daemon_thread = thread_create(NULL, 0,
		    cvc_input_daemon, NULL, 0, &p0, TS_RUN, minclsyspri);
	} else {
		mutex_exit(&cvcmutex);
	}
#ifdef lint
	cvc_input_daemon_thread = cvc_input_daemon_thread;
#endif
	return (err);
}

/* ARGSUSED */
static int
cvc_close(queue_t *q, int flag, cred_t *crp)
{
	register int		err = 0;
	register cvc_t		*cp;

	mutex_enter(&cvcmutex);
	input_ok = 0;
	mutex_exit(&cvcmutex);

	cp = q->q_ptr;
	if (cp->cvc_wbufcid != 0) {
		unbufcall(cp->cvc_wbufcid);
	}
	ttycommon_close(&cp->cvc_tty);
	WR(q)->q_ptr = q->q_ptr = NULL;
	cvcinput_q = NULL;
	bzero((caddr_t)cp, sizeof (cvc_t));
	qprocsoff(q);
	return (err);
}


/*
 * cvc_wput()
 *	cn driver does a strwrite of console output data to rconsvp which
 *	has been set by consconfig. The data enters the cvc stream at the
 *	streamhead and flows thru ttycompat and ldterm which have been
 *	pushed on the stream.  Console output data gets sent out either
 *	by cvcredir (if there is a cvcd running) or bbsram (if there
 *	isn't).
 *	Data is sent to the cvcredir via it's read q which is cvcoutput_q
 *	and was set in cvc_register().
 */
static int
cvc_wput(register queue_t *q, register mblk_t *mp)
{
	int		error = 0;

	rw_enter(&cvclock, RW_READER);
	switch (mp->b_datap->db_type) {

		case M_IOCTL:
		case M_CTL:
			cvc_ioctl(q, mp);
			break;

		case M_FLUSH:
			if (*mp->b_rptr & FLUSHW) {
				/*
				 * Flush our write queue.
				 */
				flushq(q, FLUSHDATA);
				*mp->b_rptr &= ~FLUSHW;
			}
			if (*mp->b_rptr & FLUSHR) {
				flushq(RD(q), FLUSHDATA);
				qreply(q, mp);
			} else
				freemsg(mp);
			break;

		case M_STOP:
			cvc_stopped = 1;
			freemsg(mp);
			break;

		case M_START:
			cvc_stopped = 0;
			freemsg(mp);
			qenable(q);  /* Start up delayed messages */
			break;

		case M_READ:
			/*
			 * ldterm handles this (VMIN/VTIME processing).
			 */
			freemsg(mp);
			break;
		default:
			cmn_err(CE_WARN, "cvc_wput: illegal mblk = 0x%p", mp);
			cmn_err(CE_WARN, "cvc_wput: type = 0x%x",
			    mp->b_datap->db_type);
			/* FALLTHROUGH */
#ifdef lint
			break;
#endif

		case M_DATA:
			if (cvc_stopped == 1 || cvc_suspended == 1) {
				(void) putq(q, mp);
				break;
			}
			if (cvcoutput_q != NULL && !via_bbsram) {
				/*
				 * Send it up past cvcredir module.
				 */
				putnext(cvcoutput_q, mp);
			} else {
				char	*msgp, c;
				mblk_t	*mp2 = mp;
				int count;

				while (mp2 != NULL) {
					count = mp2->b_wptr - mp2->b_rptr;
					msgp = (char *)mp2->b_rptr;
					while (count > 0) {
						count--;
						if ((c = *msgp++) != '\0') {
							/* don't print NULs */
							cvc_putc(c);
						}
					}
					mp2 = mp2->b_cont;
				}
				freemsg(mp);
			}
			break;

	}
	rw_exit(&cvclock);
	return (error);
}

static int cvc_wsrv_count = 0;

static int
cvc_wsrv(queue_t *q)
{
	register mblk_t *mp;

	cvc_wsrv_count++;

	if (cvc_stopped == 1 || cvc_suspended == 1) {
		return (0);
	}

	rw_enter(&cvclock, RW_READER);
	while ((mp = getq(q)) != NULL) {
		if (cvcoutput_q != NULL && !via_bbsram) {
			/*
			 * Send it up past cvcredir module.
			 */
			putnext(cvcoutput_q, mp);
		} else {
			char    *msgp, c;
			mblk_t  *mp2 = mp;
			int count;

			while (mp2 != NULL) {
				count = mp2->b_wptr - mp2->b_rptr;
				msgp = (char *)mp2->b_rptr;
				while (count > 0) {
					count--;
					if ((c = *msgp++) != '\0') {
						/* don't print NULs */
						cvc_putc(c);
					}
				}
				mp2 = mp2->b_cont;
			}
			freemsg(mp);
		}
	}
	rw_exit(&cvclock);
	return (0);
}


/*
 * cvc_ioctl()
 *	handle normal console ioctls.
 */
static void
cvc_ioctl(register queue_t *q, register mblk_t *mp)
{
	register struct iocblk		*iocp;
	register tty_common_t		*tty;
	register cvc_t			*cp;
	int				datasize;
	int				error = 0;
	mblk_t				*tmp;

	cp = q->q_ptr;
	tty = &cp->cvc_tty;
	if (tty->t_iocpending != NULL) {
		freemsg(tty->t_iocpending);
		tty->t_iocpending = NULL;
	}
	datasize = ttycommon_ioctl(tty, q, mp, &error);
	if (datasize != 0) {
		if (cp->cvc_wbufcid)
			unbufcall(cp->cvc_wbufcid);
		cp->cvc_wbufcid = bufcall(datasize, BPRI_HI, cvc_reioctl, cp);
		return;
	}
	if (error < 0) {
		iocp = (struct iocblk *)mp->b_rptr;
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {

		/*
		 *  Set modem bit ioctls.  These are NOPs for us, since we
		 * dont control any hardware.
		 */
		case TCSBRK:
		case TIOCSBRK:
		case TIOCCBRK:
		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count != TRANSPARENT) {
				mioc2ack(mp, NULL, 0, 0);
			} else {
				mcopyin(mp, NULL, sizeof (int), NULL);
			}
			/* qreply done below */
			break;

		/*
		 *  Get modem bits, we return 0 in mblk.
		 */
		case TIOCMGET:
			tmp = allocb(sizeof (int), BPRI_MED);
			if (tmp == NULL) {
				miocnak(q, mp, 0, EAGAIN);
				return;
			}
			*(int *)tmp->b_rptr = 0;

			if (iocp->ioc_count != TRANSPARENT)
				mioc2ack(mp, tmp, sizeof (int), 0);
			else
				mcopyout(mp, NULL, sizeof (int), NULL, tmp);
			/* qreply done below */
			break;

		default:
			/*
			 * If we don't understand it, it's an error. NAK it.
			 */
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	qreply(q, mp);

}


/*
 * cvc_redir()
 *	called from cvcredir:cvcr_wput() to handle console input
 *	data. This routine puts the cvcredir write (downstream) data
 *	onto the cvc read (upstream) queues.  Note that if `mp' is
 *	an M_IOCTL, then it may be reused by the caller to send back
 *	an M_IOCACK or M_IOCNAK.
 */
int
cvc_redir(mblk_t *mp)
{
	register struct iocblk	*iocp;
	register tty_common_t	*tty;
	register cvc_t		*cp;
	struct winsize		*ws;
	int			error;

	if (cvcinput_q == NULL) {
		cmn_err(CE_WARN, "cvc_redir: cvcinput_q NULL!");
		return (EINVAL);
	}

	if (DB_TYPE(mp) != M_IOCTL) {
		putnext(cvcinput_q, mp);
		return (0);
	}

	iocp = (struct iocblk *)mp->b_rptr;
	if (iocp->ioc_cmd == TIOCSWINSZ) {
		error = miocpullup(mp, sizeof (struct winsize));
		if (error != 0)
			return (error);

		ws = (struct winsize *)mp->b_cont->b_rptr;
		cp = cvcinput_q->q_ptr;
		tty = &cp->cvc_tty;
		mutex_enter(&tty->t_excl);
		if (bcmp(&tty->t_size, ws, sizeof (struct winsize)) != 0) {
			tty->t_size = *ws;
			mutex_exit(&tty->t_excl);
			(void) putnextctl1(cvcinput_q, M_PCSIG, SIGWINCH);
		} else
			mutex_exit(&tty->t_excl);
	} else {
		/*
		 * It must be a CVC_DISCONNECT, send hangup.
		 */
		ASSERT(iocp->ioc_cmd == CVC_DISCONNECT);
		if (cvc_hangup_ok)
			(void) putnextctl(cvcinput_q, M_HANGUP);
	}

	return (0);
}


/*
 * cvc_register()
 *	called from cvcredir to register it's queues.  cvc
 *	receives data from cn via the streamhead and sends it to cvcredir
 *	via pointers to cvcredir's queues.
 */
int
cvc_register(queue_t *q)
{
	int error = -1;

	if (cvcinput_q == NULL)
		cmn_err(CE_WARN, "cvc_register: register w/ no console open!");
	rw_enter(&cvclock, RW_WRITER);
	if (cvcoutput_q == NULL) {
		cvcoutput_q = RD(q);  /* Make sure its the upstream q */
		qprocson(cvcoutput_q);	/* must be done within cvclock */
		error = 0;
	} else {
		/*
		 * cmn_err will call us, so release lock.
		 */
		rw_exit(&cvclock);
		if (cvcoutput_q == q)
			cmn_err(CE_WARN, "cvc_register: duplicate q!");
		else
			cmn_err(CE_WARN, "cvc_register: nondup q = 0x%p",
			    q);
		return (error);
	}

	/*
	 * Unless "via_bbsram" is set, i/o will be going through cvcd, so
	 * stop flushing output to BBSRAM.
	 */
	if ((cvc_timeout_id != (timeout_id_t)-1) && (!via_bbsram)) {
		stop_timeout = 1;
		(void) untimeout(cvc_timeout_id);
		cvc_timeout_id = (timeout_id_t)-1;
		cvc_hangup_ok = 1;
	}
	rw_exit(&cvclock);
	return (error);
}


/*
 * cvc_unregister()
 *	called from cvcredir to clear pointers to its queues.
 *	cvcredir no longer wants to send or receive data.
 */
void
cvc_unregister(queue_t *q)
{
	rw_enter(&cvclock, RW_WRITER);
	if (q == cvcoutput_q) {
		qprocsoff(cvcoutput_q);	/* must be done within cvclock */
		cvcoutput_q = NULL;
	} else {
		rw_exit(&cvclock);
		cmn_err(CE_WARN, "cvc_unregister: q = 0x%p not registered", q);
		return;
	}

	/*
	 * i/o will not be going through cvcd, start flushing output to
	 * BBSRAM
	 */
	if (cvc_timeout_id == (timeout_id_t)-1) {
		stop_timeout = 0;
		cvc_timeout_id = timeout(cvc_flush_buf, NULL,
		    drv_usectohz(TIMEOUT_DELAY));
	}
	rw_exit(&cvclock);
}

/*
 * cvc_reioctl()
 *	Retry an "ioctl", now that "bufcall" claims we may be able
 *	to allocate the buffer we need.
 */
static void
cvc_reioctl(void *unit)
{
	register queue_t	*q;
	register mblk_t		*mp;
	register cvc_t		*cp = (cvc_t *)unit;

	/*
	 * The bufcall is no longer pending.
	 */
	if (!cp->cvc_wbufcid) {
		return;
	}
	cp->cvc_wbufcid = 0;
	if ((q = cp->cvc_tty.t_writeq) == NULL) {
		return;
	}
	if ((mp = cp->cvc_tty.t_iocpending) != NULL) {
		/* not pending any more */
		cp->cvc_tty.t_iocpending = NULL;
		cvc_ioctl(q, mp);
	}
}


/*
 * cvc_bbsram_ops()
 *	Process commands sent to cvc from netcon_server via BBSRAM
 */
static void
cvc_bbsram_ops(volatile unsigned char *op_reg)
{
	uchar_t	 op;

	if ((op = *op_reg) == 0)
		return;

	ASSERT(MUTEX_HELD(&cvc_bbsram_input_mutex));

	switch (op) {
	case CVC_BBSRAM_BREAK:		/* A console break (L1-A) */
		abort_sequence_enter((char *)NULL);
		break;
	case CVC_BBSRAM_DISCONNECT:	/* Break connection, hang up */
		if (cvcinput_q && cvc_hangup_ok)
			(void) putnextctl(cvcinput_q, M_HANGUP);
		break;
	case CVC_BBSRAM_VIA_NET:	/* console via network */
		via_bbsram = 0;
		/*
		 * stop periodic flushing of output to BBSRAM
		 * only if cvcredir/cvcd are present
		 */
		rw_enter(&cvclock, RW_WRITER);
		if (cvcoutput_q != NULL) {
			stop_timeout = 1;
			if (cvc_timeout_id != (timeout_id_t)-1) {
				(void) untimeout(cvc_timeout_id);
				cvc_timeout_id = (timeout_id_t)-1;
			}
		}
		rw_exit(&cvclock);
		break;
	case CVC_BBSRAM_VIA_BBSRAM:	/* console via bbsram */
		via_bbsram = 1;
		/* start periodic flushing of ouput to BBSRAM */
		rw_enter(&cvclock, RW_WRITER);
		if (cvc_timeout_id == (timeout_id_t)-1) {
			stop_timeout = 0;
			cvc_timeout_id = timeout(cvc_flush_buf,
			    NULL, drv_usectohz(TIMEOUT_DELAY));
		}
		rw_exit(&cvclock);
		break;
	case CVC_BBSRAM_CLOSE_NET:
		/*
		 * Send a hangup control message upstream to cvcd
		 * thru cvcredir.  This is an attempt to close
		 * out any existing network connection(if any).
		 * cvcoutput_q should point to the cvcredir's read
		 * queue.
		 */
		rw_enter(&cvclock, RW_READER);
		if (cvcoutput_q != NULL) {
			(void) putnextctl(cvcoutput_q, M_HANGUP);
		}
		rw_exit(&cvclock);
		break;
	default:
		cmn_err(CE_WARN, "cvc: unknown BBSRAM opcode %d\n",
		    (unsigned int)op);
		break;
	}
	*op_reg = 0;
}


/*
 * cvc_putc()
 *	Put a single character out to BBSRAM if space available.
 */
static void
cvc_putc(register int c)
{
	static int	output_lost = 0;

	if (c == '\n')
		cvc_putc('\r');

	mutex_enter(&cvc_buf_mutex);
	/*
	 * Just exit if the buffer is already full.
	 * It will be up to cvc_flush_buf() to flush the buffer.
	 */
	if (cvc_output_count == MAX_XFER_OUTPUT) {
		output_lost = 1;
		mutex_exit(&cvc_buf_mutex);
		return;
	}
	if (output_lost)
		prom_printf("WARNING: overflow of cvc output buffer, "
		    "output lost!");
	output_lost = 0;
	cvc_output_buffer[cvc_output_count] = (unsigned char)c;
	cvc_output_count++;
	if ((cvc_output_count == MAX_XFER_OUTPUT) || (c == '\n')) {
		/* flush cvc's internal output buffer to BBSRAM */

		/*
		 * Wait for the BBSRAM output buffer to be emptied.
		 * This may hang if netcon_server isn't running on the SSP
		 */
		int maxspin = CVC_OUT_MAXSPIN;
		while ((BBSRAM_OUTPUT_COUNT != 0) && --maxspin) {
			if (stop_bbsram) {
				mutex_exit(&cvc_buf_mutex);
				return;
			}
			DELAY(1000);
		}
		bcopy((caddr_t)cvc_output_buffer,
		    (caddr_t)(BBSRAM_OUTPUT_BUF - cvc_output_count),
		    cvc_output_count);

		BBSRAM_OUTPUT_COUNT = cvc_output_count;
		cvc_output_count = 0;
	}
	mutex_exit(&cvc_buf_mutex);
}


/*
 * cvc_flush_buf()
 *	Flush cvc's internal output buffer to BBSRAM at regular intervals.
 *	This should only be done if cvcd is not running or the user (via the cvc
 *	application on the SSP) has requested that i/o go through BBSRAM.
 */
/* ARGSUSED */
static void
cvc_flush_buf(void *notused)
{
	if (stop_timeout)
		return;

	mutex_enter(&cvc_buf_mutex);
	if (cvc_output_count != 0) {
		/*
		 * Wait for the BBSRAM output buffer to be emptied.
		 * This may hang if netcon_server isn't running on the SSP.
		 */
		int maxspin = CVC_OUT_MAXSPIN;
		while ((BBSRAM_OUTPUT_COUNT != 0) && --maxspin) {
			if (stop_bbsram)
				goto exit;
			DELAY(1000);
		}

		bcopy((caddr_t)cvc_output_buffer,
		    (caddr_t)BBSRAM_OUTPUT_BUF - cvc_output_count,
		    cvc_output_count);

		BBSRAM_OUTPUT_COUNT = cvc_output_count;
		cvc_output_count = 0;
	}
exit:
	mutex_exit(&cvc_buf_mutex);
	/* rw_enter(&cvclock, RW_WRITER); */
	cvc_timeout_id = timeout(cvc_flush_buf, NULL,
	    drv_usectohz(TIMEOUT_DELAY));
	/* rw_exit(&cvclock); */
}


/*
 * cvc_getstr()
 *	Poll BBSRAM for console input while available.
 */
static void
cvc_getstr(char *cp)
{
	short		count;
	volatile char	*lp;

	mutex_enter(&cvc_bbsram_input_mutex);
	/* Poll BBSRAM for input */
	do {
		if (stop_bbsram) {
			*cp = '\0';	/* set string to zero-length */
			mutex_exit(&cvc_bbsram_input_mutex);
			return;
		}
		/*
		 * Use a smaller delay between checks of BBSRAM for input
		 * when cvcd/cvcredir are not running or "via_bbsram" has
		 * been set.
		 * We don't go away completely when i/o is going through the
		 * network via cvcd since a command may be sent via BBSRAM
		 * to switch if the network is down or hung.
		 */
		if ((cvcoutput_q == NULL) || (via_bbsram))
			delay(drv_usectohz(100000));
		else
			delay(drv_usectohz(1000000));
		cvc_bbsram_ops(BBSRAM_CONTROL_REG);
		count = BBSRAM_INPUT_COUNT;
	} while (count == 0);

	lp = BBSRAM_INPUT_BUF - count;

	while (count--) {
		*cp++ = *lp++;
	}
	*cp = '\0';

	BBSRAM_INPUT_COUNT = 0;
	mutex_exit(&cvc_bbsram_input_mutex);
}


/*
 * cvc_input_daemon()
 *	this function runs as a separate kernel thread and polls BBSRAM for
 *	input, and possibly put it on read stream for the console.
 *	There are two poll rates (implemented in cvc_getstr):
 *		 100 000 uS (10 Hz) - no cvcd communications || via_bbsram
 *		1000 000 uS ( 1 Hz) - cvcd communications
 * 	This continues to run even if there are network console communications
 *	in order to handle out-of-band signaling.
 */
static void
cvc_input_daemon(void)
{
	char		linebuf[MAX_XFER_INPUT];
	char		*cp;
	mblk_t		*mbp;
	int		c;
	int		dropped_read = 0;

	for (;;) {
		cvc_getstr(linebuf);

		mbp = allocb(strlen(linebuf), BPRI_MED);
		if (mbp == NULL) {	/* drop it & go on if no buffer */
			if (!dropped_read) {
				cmn_err(CE_WARN,
				    "cvc_input_daemon: "
				    "dropping BBSRAM reads\n");
			}
			dropped_read++;
			continue;
		}
		if (dropped_read) {
			cmn_err(CE_WARN,
			    "cvc_input_daemon: dropped %d BBSRAM reads\n",
			    dropped_read);
			dropped_read = 0;
		}

		for (cp = linebuf; *cp != '\0'; cp++) {
			c = (int)*cp;
			if (c == '\r')
				c = '\n';
			c &= 0177;
			*mbp->b_wptr = (char)c;
			mbp->b_wptr++;
		}
		mutex_enter(&cvcmutex);
		if (input_ok) {
			if (cvcinput_q == NULL) {
				cmn_err(CE_WARN,
				    "cvc_input_daemon: cvcinput_q is NULL!");
			} else {
				putnext(cvcinput_q, mbp);
			}
		} else {
			freemsg(mbp);
		}
		mutex_exit(&cvcmutex);
	}

	/* NOTREACHED */
}


/*
 * cvc_bbsram_stop()
 *	Prevents accesses to BBSRAM. used by cvc_assign_iocpu() when
 *	mapping in BBSRAM to a virtual address.
 */
static void
cvc_bbsram_stop(void)
{
	stop_bbsram = 1;
	mutex_enter(&cvc_bbsram_input_mutex);
	mutex_enter(&cvc_buf_mutex);
}


/*
 * cvc_bbsram_start()
 *	Allow accesses to BBSRAM, used by cvc_assign_iocpu() after
 *	BBSRAM has been mapped to a virtual address.
 */
static void
cvc_bbsram_start(void)
{
	stop_bbsram = 0;
	mutex_exit(&cvc_buf_mutex);
	mutex_exit(&cvc_bbsram_input_mutex);
}


/*
 * cvc_assign_iocpu()
 *	Map in BBSRAM to a virtual address
 *	This called by the kernel with the cpu id of cpu zero.
 */
void
cvc_assign_iocpu(processorid_t newcpu)
{
	processorid_t	oldcpu = cvc_iocpu;

	if (newcpu == oldcpu)
		return;

	cvc_iobufp[newcpu] = cvc_iobuf_mapin(newcpu);

	cvc_bbsram_stop();

	cvc_iocpu = newcpu;

	cvc_bbsram_start();

	if (oldcpu != -1)
		cvc_iobuf_mapout(oldcpu);
}


/*
 * cvc_iobuf_mapin()
 *	Map in the cvc bbsram i/o buffer into kernel space.
 */
static caddr_t
cvc_iobuf_mapin(processorid_t cpu_id)
{
	caddr_t	cvaddr;
	uint64_t cvc_iobuf_physaddr;
	pfn_t pfn;
	uint_t num_pages;
	extern cpu_sgnblk_t *cpu_sgnblkp[];

	ASSERT(cpu_sgnblkp[cpu_id] != NULL);

	/*
	 * First construct the physical base address of the bbsram
	 * in Starfire PSI space associated with this cpu in question.
	 */
	cvc_iobuf_physaddr = STARFIRE_UPAID2UPS(cpu_id) | STARFIRE_PSI_BASE;

	/*
	 * Next add the cvc i/o buffer offset obtained from the
	 * sigblock to get cvc iobuf physical address
	 */
	cvc_iobuf_physaddr += cpu_sgnblkp[cpu_id]->sigb_cvc_off;

	/* Get the page frame number */
	pfn = (cvc_iobuf_physaddr >> MMU_PAGESHIFT);

	/* Calculate how many pages we need to map in */
	num_pages = mmu_btopr(((uint_t)(cvc_iobuf_physaddr
	    & MMU_PAGEOFFSET) + sizeof (sigb_cvc_t)));

	/*
	 * Map in the cvc iobuf
	 */
	cvaddr = vmem_alloc(heap_arena, ptob(num_pages), VM_SLEEP);

	hat_devload(kas.a_hat, cvaddr, mmu_ptob(num_pages), pfn,
	    PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);

	return ((caddr_t)(cvaddr + (uint_t)(cvc_iobuf_physaddr
	    & MMU_PAGEOFFSET)));
}


/*
 * cvc_iobuf_mapout()
 *	Map out the cvc iobuf from kernel space
 */
static void
cvc_iobuf_mapout(processorid_t cpu_id)
{
	caddr_t	cvaddr;
	size_t	num_pages;

	if ((cvaddr = cvc_iobufp[cpu_id]) == 0) {
		/* already unmapped - return */
		return;
	}

	/* Calculate how many pages we need to map out */
	num_pages = mmu_btopr(((size_t)((uint64_t)cvaddr & MMU_PAGEOFFSET) +
	    sizeof (sigb_cvc_t)));

	/* Get cvaddr to the start of the page boundary */
	cvaddr = (caddr_t)(((uint64_t)cvaddr & MMU_PAGEMASK));

	hat_unload(kas.a_hat, cvaddr, mmu_ptob(num_pages), HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, cvaddr, ptob(num_pages));

	cvc_iobufp[cpu_id] = NULL;
}
