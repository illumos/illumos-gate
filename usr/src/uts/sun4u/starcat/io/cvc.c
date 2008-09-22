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
#include <sys/open.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/kmem.h>
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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/modctl.h>

#include <sys/sc_cvc.h>
#include <sys/sc_cvcio.h>
#include <sys/iosramio.h>

static int	cvc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	cvc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	cvc_detach(dev_info_t *, ddi_detach_cmd_t);
static int	cvc_open(register queue_t *, dev_t *, int, int, cred_t *);
static int	cvc_close(queue_t *, int, cred_t *);
static int	cvc_wput(queue_t *, mblk_t *);
static int	cvc_wsrv(queue_t *);
static void	cvc_ioctl(queue_t *, mblk_t *);
static void	cvc_reioctl(void *);
static void	cvc_input_daemon(void);
static void	cvc_send_to_iosram(mblk_t **chainpp);
static void	cvc_flush_queue(void *);
static void	cvc_iosram_ops(uint8_t);
static void	cvc_getstr(char *cp);
static void	cvc_win_resize(int clear_flag);

#define	ESUCCESS 0
#ifndef	TRUE
#define	TRUE	1
#define	FALSE	0
#endif

/*
 * Private copy of devinfo pointer; cvc_info uses it.
 */
static dev_info_t	*cvcdip;

/*
 * This structure reflects the layout of data in CONI and CONO.  If you are
 * going to add fields that don't get written into those chunks, be sure to
 * place them _after_ the buffer field.
 */
typedef struct cvc_buf {
	ushort_t	count;
	uchar_t		buffer[MAX_XFER_COUTPUT];
} cvc_buf_t;

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

static krwlock_t	cvclock;	/* lock protecting everything here */
static queue_t		*cvcinput_q;	/* queue for console input */
static queue_t		*cvcoutput_q;	/* queue for console output */
static int		cvc_instance = -1;
static int		cvc_stopped = 0;
static int		cvc_suspended = 0;

kthread_id_t		cvc_input_daemon_thread; /* just to aid debugging */
static kmutex_t		cvcmutex;	/* protects input */
static kmutex_t		cvc_iosram_input_mutex; /* protects IOSRAM inp buff */
static int		input_ok = 0;	/* true when stream is valid */

static int		via_iosram = 0; /* toggle switch */
static timeout_id_t	cvc_timeout_id = (timeout_id_t)-1;
static int		input_daemon_started = 0;

/* debugging functions */
#ifdef DEBUG
uint32_t cvc_dbg_flags = 0x0;
static void cvc_dbg(uint32_t flag, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5);
#endif

/*
 * Module linkage information for the kernel.
 */

DDI_DEFINE_STREAM_OPS(cvcops, nulldev, nulldev, cvc_attach, cvc_detach,
		    nodev, cvc_info, (D_NEW|D_MTPERQ|D_MP), &cvcinfo,
		    ddi_quiesce_not_supported);

extern int nodev(), nulldev();
extern struct mod_ops mod_driverops;

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
_init()
{
	int	status;

	status = mod_install(&modlinkage);
	if (status == 0) {
		mutex_init(&cvcmutex, NULL, MUTEX_DEFAULT, NULL);
	}
	return (status);
}

int
_fini()
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
		if (cvcinput_q != NULL) {
			qenable(WR(cvcinput_q));
		}
		return (DDI_SUCCESS);
	}

	mutex_enter(&cvcmutex);
	if (!been_here) {
		been_here = 1;
		mutex_init(&cvc_iosram_input_mutex, NULL, MUTEX_DEFAULT, NULL);
		rw_init(&cvclock, NULL, RW_DRIVER, NULL);
		cvc_instance = ddi_get_instance(devi);
	} else {
#if defined(DEBUG)
		cmn_err(CE_NOTE,
		    "cvc_attach: called multiple times!! (instance = %d)",
		    ddi_get_instance(devi));
#endif /* DEBUG */
		mutex_exit(&cvcmutex);
		return (DDI_SUCCESS);
	}
	mutex_exit(&cvcmutex);

	if (ddi_create_minor_node(devi, "cvc", S_IFCHR,
	    0, NULL, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	cvcdip = devi;
	cvcinput_q = NULL;
	cvcoutput_q = NULL;

	CVC_DBG0(CVC_DBG_ATTACH, "Attached");

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

	CVC_DBG0(CVC_DBG_DETACH, "Detached");

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
	register int		err = DDI_SUCCESS;
	tty_common_t		*tty;
	cvc_t			*cp;

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

	/*
	 * Start the thread that handles input polling if it hasn't been started
	 * previously.
	 */
	if (!input_daemon_started) {
		input_daemon_started = 1;
		mutex_exit(&cvcmutex);

		cvc_input_daemon_thread = thread_create(NULL, 0,
		    cvc_input_daemon, NULL, 0, &p0, TS_RUN, minclsyspri);
		CVC_DBG0(CVC_DBG_IOSRAM_RD, "Started input daemon");
	} else {
		mutex_exit(&cvcmutex);
	}

	/*
	 * Set the console window size.
	 */
	mutex_enter(&cvc_iosram_input_mutex);
	cvc_win_resize(FALSE);
	mutex_exit(&cvc_iosram_input_mutex);

	CVC_DBG0(CVC_DBG_OPEN, "Plumbed successfully");

	return (err);
}

/* ARGSUSED */
static int
cvc_close(queue_t *q, int flag, cred_t *crp)
{
	register int		err = DDI_SUCCESS;
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

	CVC_DBG0(CVC_DBG_CLOSE, "Un-plumbed successfully");

	return (err);
}


/*
 * cvc_wput()
 *	cn driver does a strwrite of console output data to rconsvp which has
 *	been set by consconfig. The data enters the cvc stream at the streamhead
 *	and flows thru ttycompat and ldterm which have been pushed on the
 *	stream.  Console output data gets sent out either to cvcredir, if the
 *	network path is available and selected, or to IOSRAM otherwise.  Data is
 *	sent to cvcredir via its read queue (cvcoutput_q, which gets set in
 *	cvc_register()).  If the IOSRAM path is selected, or if previous mblks
 *	are currently queued up for processing, the new mblk will be queued
 *	and handled later on by cvc_wsrv.
 */
static int
cvc_wput(queue_t *q, mblk_t *mp)
{
	int		error = 0;

	rw_enter(&cvclock, RW_READER);

	CVC_DBG2(CVC_DBG_WPUT, "mp 0x%x db_type 0x%x",
	    mp, mp->b_datap->db_type);

	switch (mp->b_datap->db_type) {

		case M_IOCTL:
		case M_CTL: {
			struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

			switch (iocp->ioc_cmd) {
				/*
				 * These ioctls are only supposed to be
				 * processed after everything else that is
				 * already queued awaiting processing, so throw
				 * them on the queue and let cvc_wsrv handle
				 * them.
				 */
				case TCSETSW:
				case TCSETSF:
				case TCSETAW:
				case TCSETAF:
				case TCSBRK:
					putq(q, mp);
					break;

				default:
					cvc_ioctl(q, mp);
			}
			break;
		}

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
			cmn_err(CE_WARN, "cvc_wput: unexpected mblk type - mp ="
			    " 0x%p, type = 0x%x", mp, mp->b_datap->db_type);
			freemsg(mp);
			break;

		case M_DATA:
			/*
			 * If there are other mblks queued up for transmission,
			 * or we're using IOSRAM either because cvcredir hasn't
			 * registered yet or because we were configured that
			 * way, or cvc has been stopped or suspended, place this
			 * mblk on the input queue for future processing.
			 * Otherwise, hand it off to cvcredir for transmission
			 * via the network.
			 */
			if (q->q_first != NULL || cvcoutput_q == NULL ||
			    via_iosram || cvc_stopped == 1 ||
			    cvc_suspended == 1) {
				(void) putq(q, mp);
			} else {
				/*
				 * XXX - should canputnext be called here?
				 * Starfire's cvc doesn't do that, and it
				 * appears to work anyway.
				 */
				(void) putnext(cvcoutput_q, mp);
			}
			break;

	}
	rw_exit(&cvclock);
	return (error);
}

/*
 * cvc_wsrv()
 *	cvc_wsrv handles mblks that have been queued by cvc_wput either because
 *	the IOSRAM path was selected or the queue contained preceding mblks.  To
 *	optimize processing (particularly if the IOSRAM path is selected), all
 *	mblks are pulled off of the queue and chained together.  Then, if there
 *	are any mblks on the chain, they are either forwarded to cvcredir or
 *	sent for IOSRAM processing as appropriate given current circumstances.
 *	IOSRAM processing may not be able to handle all of the data in the
 *	chain, in which case the remaining data is placed back on the queue and
 *	a timeout routine is registered to reschedule cvc_wsrv in the future.
 *	Automatic scheduling of the queue is disabled (noenable(q)) while
 *	cvc_wsrv is running to avoid superfluous calls.
 */
static int
cvc_wsrv(queue_t *q)
{
	mblk_t *total_mp = NULL;
	mblk_t *mp;

	if (cvc_stopped == 1 || cvc_suspended == 1) {
		return (0);
	}

	rw_enter(&cvclock, RW_READER);
	noenable(q);

	/*
	 * If there's already a timeout registered for scheduling this routine
	 * in the future, it's a safe bet that we don't want to run right now.
	 */
	if (cvc_timeout_id != (timeout_id_t)-1) {
		enableok(q);
		rw_exit(&cvclock);
		return (0);
	}

	/*
	 * Start by linking all of the queued M_DATA mblks into a single chain
	 * so we can flush as much as possible to IOSRAM (if we choose that
	 * route).
	 */
	while ((mp = getq(q)) != NULL) {
		/*
		 * Technically, certain IOCTLs are supposed to be processed only
		 * after all preceding data has completely "drained".  In an
		 * attempt to support that, we delay processing of those IOCTLs
		 * until this point.  It is still possible that an IOCTL will be
		 * processed before all preceding data is drained, for instance
		 * in the case where not all of the preceding data would fit
		 * into IOSRAM and we have to place it back on the queue.
		 * However, since none of these IOCTLs really appear to have any
		 * relevance for cvc, and we weren't supporting delayed
		 * processing at _all_ previously, this partial implementation
		 * should suffice.  (Fully implementing the delayed IOCTL
		 * processing would be unjustifiably difficult given the nature
		 * of the underlying IOSRAM console protocol.)
		 */
		if (mp->b_datap->db_type == M_IOCTL) {
			cvc_ioctl(q, mp);
			continue;
		}

		/*
		 * We know that only M_IOCTL and M_DATA blocks are placed on our
		 * queue.  Since this block isn't an M_IOCTL, it must be M_DATA.
		 */
		if (total_mp != NULL) {
			linkb(total_mp, mp);
		} else {
			total_mp = mp;
		}
	}

	/*
	 * Do we actually have anything to do?
	 */
	if (total_mp == NULL) {
		enableok(q);
		rw_exit(&cvclock);
		return (0);
	}

	/*
	 * Yes, we do, so send the data to either cvcredir or IOSRAM as
	 * appropriate.  In the latter case, we might not be able to transmit
	 * everything right now, so re-queue the remainder.
	 */
	if (cvcoutput_q != NULL && !via_iosram) {
		CVC_DBG0(CVC_DBG_NETWORK_WR, "Sending to cvcredir.");
		/*
		 * XXX - should canputnext be called here?  Starfire's cvc
		 * doesn't do that, and it appears to work anyway.
		 */
		(void) putnext(cvcoutput_q, total_mp);
	} else {
		CVC_DBG0(CVC_DBG_IOSRAM_WR, "Send to IOSRAM.");
		cvc_send_to_iosram(&total_mp);
		if (total_mp != NULL) {
			(void) putbq(q, total_mp);
		}
	}

	/*
	 * If there is still data queued at this point, make sure the queue
	 * gets scheduled again after an appropriate delay (which has been
	 * somewhat arbitrarily selected as half of the SC's input polling
	 * frequency).
	 */
	enableok(q);
	if (q->q_first != NULL) {
		if (cvc_timeout_id == (timeout_id_t)-1) {
			cvc_timeout_id = timeout(cvc_flush_queue,
			    NULL, drv_usectohz(CVC_IOSRAM_POLL_USECS / 2));
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
	register cvc_t			*cp = q->q_ptr;
	int				datasize;
	int				error = 0;

	/*
	 * Let ttycommon_ioctl take the first shot at processing the ioctl.  If
	 * it fails because it can't allocate memory, schedule processing of the
	 * ioctl later when a proper buffer is available.  The mblk that
	 * couldn't be processed will have been stored in the tty structure by
	 * ttycommon_ioctl.
	 */
	datasize = ttycommon_ioctl(&cp->cvc_tty, q, mp, &error);
	if (datasize != 0) {
		if (cp->cvc_wbufcid) {
			unbufcall(cp->cvc_wbufcid);
		}
		cp->cvc_wbufcid = bufcall(datasize, BPRI_HI, cvc_reioctl, cp);
		return;
	}

	/*
	 * ttycommon_ioctl didn't do anything, but there's nothing we really
	 * support either with the exception of TCSBRK, which is supported
	 * only to appear a bit more like a serial device for software that
	 * expects TCSBRK to work.
	 */
	if (error != 0) {
		struct iocblk *iocp = (struct iocblk *)mp->b_rptr;

		if (iocp->ioc_cmd == TCSBRK) {
			miocack(q, mp, 0, 0);
		} else {
			miocnak(q, mp, 0, EINVAL);
		}
	} else {
		qreply(q, mp);
	}
}


/*
 * cvc_redir()
 *	called from cvcredir:cvcr_wput() to handle console input
 *	data. This routine puts the cvcredir write (downstream) data
 *	onto the cvc read (upstream) queues.
 */
int
cvc_redir(mblk_t *mp)
{
	register struct iocblk	*iocp;
	int			rv = 1;

	/*
	 * This function shouldn't be called if cvcredir hasn't registered yet.
	 */
	if (cvcinput_q == NULL) {
		/*
		 * Need to let caller know that it may be necessary for them to
		 * free the message buffer, so return 0.
		 */
		CVC_DBG0(CVC_DBG_REDIR, "redirection not enabled");
		cmn_err(CE_WARN, "cvc_redir: cvcinput_q NULL!");
		return (0);
	}

	CVC_DBG1(CVC_DBG_REDIR, "type 0x%x", mp->b_datap->db_type);
	if (mp->b_datap->db_type == M_DATA) {
		/*
		 * XXX - should canputnext be called here?  Starfire's cvc
		 * doesn't do that, and it appears to work anyway.
		 */
		CVC_DBG1(CVC_DBG_NETWORK_RD, "Sending mp 0x%x", mp);
		(void) putnext(cvcinput_q, mp);
	} else if (mp->b_datap->db_type == M_IOCTL) {
		/*
		 * The cvcredir driver filters out ioctl mblks we wouldn't
		 * understand, so we don't have to check for every conceivable
		 * ioc_cmd.  However, additional ioctls may be supported (again)
		 * some day, so the code is structured to check the value even
		 * though there's only one that is currently supported.
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		if (iocp->ioc_cmd == CVC_DISCONNECT) {
			(void) putnextctl(cvcinput_q, M_HANGUP);
		}
	} else {
		/*
		 * Since we don't know what this mblk is, we're not going to
		 * process it.
		 */
		CVC_DBG1(CVC_DBG_REDIR, "unrecognized mblk type: %d",
		    mp->b_datap->db_type);
		rv = 0;
	}

	return (rv);
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
 * cvc_iosram_ops()
 *	Process commands sent to cvc from netcon_server via IOSRAM
 */
static void
cvc_iosram_ops(uint8_t op)
{
	int		rval = ESUCCESS;
	static uint8_t	stale_op = 0;

	ASSERT(MUTEX_HELD(&cvc_iosram_input_mutex));

	CVC_DBG1(CVC_DBG_IOSRAM_CNTL, "cntl msg 0x%x", op);

	/*
	 * If this is a repeated notice of a command that was previously
	 * processed but couldn't be cleared due to EAGAIN (tunnel switch in
	 * progress), just clear the data_valid flag and return.
	 */
	if (op == stale_op) {
		if (iosram_set_flag(IOSRAM_KEY_CONC, IOSRAM_DATA_INVALID,
		    IOSRAM_INT_NONE) == 0) {
			stale_op = 0;
		}
		return;
	}
	stale_op = 0;

	switch (op) {
		case CVC_IOSRAM_BREAK:		/* A console break (L1-A) */
			abort_sequence_enter((char *)NULL);
			break;

		case CVC_IOSRAM_DISCONNECT:	/* Break connection, hang up */
			if (cvcinput_q)
				(void) putnextctl(cvcinput_q, M_HANGUP);
			break;

		case CVC_IOSRAM_VIA_NET:	/* console via network */
			via_iosram = 0;
			break;

		case CVC_IOSRAM_VIA_IOSRAM:	/* console via iosram */
			via_iosram = 1;
			/*
			 * Tell cvcd to close any network connection it has.
			 */
			rw_enter(&cvclock, RW_READER);
			if (cvcoutput_q != NULL) {
				(void) putnextctl(cvcoutput_q, M_HANGUP);
			}
			rw_exit(&cvclock);
			break;

		case CVC_IOSRAM_WIN_RESIZE:	/* console window size data */
			/*
			 * In the case of window resizing, we don't want to
			 * record a stale_op value because we should always use
			 * the most recent winsize info, which could change
			 * between the time that we fail to clear the flag and
			 * the next time we try to process the command.  So,
			 * we'll just let cvc_win_resize clear the data_valid
			 * flag itself (hence the TRUE parameter) and not worry
			 * about whether or not it succeeds.
			 */
			cvc_win_resize(TRUE);
			return;
			/* NOTREACHED */

		default:
			cmn_err(CE_WARN, "cvc: unknown IOSRAM opcode %d", op);
			break;
	}

	/*
	 * Clear CONC's data_valid flag to indicate that the chunk is available
	 * for further communications.  If the flag can't be cleared due to an
	 * error, record the op value so we'll know to ignore it when we see it
	 * on the next poll.
	 */
	rval = iosram_set_flag(IOSRAM_KEY_CONC, IOSRAM_DATA_INVALID,
	    IOSRAM_INT_NONE);
	if (rval != 0) {
		stale_op = op;
		if (rval != EAGAIN) {
			cmn_err(CE_WARN,
			    "cvc_iosram_ops: set flag for cntlbuf ret %d",
			    rval);
		}
	}
}


/*
 * cvc_send_to_iosram()
 *	Flush as much data as possible to the CONO chunk.  If successful, free
 *	any mblks that were completely transmitted, update the b_rptr field in
 *	the first remaining mblk if it was partially transmitted, and update the
 *	caller's pointer to the new head of the mblk chain.  Since the software
 *	that will be pulling this data out of IOSRAM (dxs on the SC) is just
 *	polling at some frequency, we avoid attempts to flush data to IOSRAM any
 *	faster than a large divisor of that polling frequency.
 *
 *	Note that "cvc_buf_t out" is only declared "static" to keep it from
 *	being allocated on the stack.  Allocating 1K+ structures on the stack
 *	seems rather antisocial.
 */
static void
cvc_send_to_iosram(mblk_t **chainpp)
{
	int			rval;
	uint8_t			dvalid;
	uchar_t			*cp;
	mblk_t			*mp;
	mblk_t			*last_empty_mp;
	static clock_t		last_flush = (clock_t)-1;
	static cvc_buf_t	out;   /* see note above about static */

	ASSERT(chainpp != NULL);

	/*
	 * We _do_ have something to do, right?
	 */
	if (*chainpp == NULL) {
		return;
	}

	/*
	 * We can actually increase throughput by throttling back on attempts to
	 * flush data to IOSRAM, since trying to write every little bit of data
	 * as it shows up will actually generate more delays waiting for the SC
	 * to pick up each of those bits.  Instead, we'll avoid attempting to
	 * write data to IOSRAM any faster than half of the polling frequency we
	 * expect the SC to be using.
	 */
	if (ddi_get_lbolt() - last_flush <
	    drv_usectohz(CVC_IOSRAM_POLL_USECS / 2)) {
		return;
	}

	/*
	 * If IOSRAM is inaccessible or the CONO chunk still holds data that
	 * hasn't been picked up by the SC, there's nothing we can do right now.
	 */
	rval = iosram_get_flag(IOSRAM_KEY_CONO, &dvalid, NULL);
	if ((rval != 0) || (dvalid == IOSRAM_DATA_VALID)) {
		if ((rval != 0) && (rval != EAGAIN)) {
			cmn_err(CE_WARN, "cvc_send_to_iosram: get_flag ret %d",
			    rval);
		}
		return;
	}

	/*
	 * Copy up to MAX_XFER_COUTPUT chars from the mblk chain into a buffer.
	 * Don't change any of the mblks just yet, since we can't be certain
	 * that we'll be successful in writing data to the CONO chunk.
	 */
	out.count = 0;
	mp = *chainpp;
	cp = mp->b_rptr;
	last_empty_mp = NULL;
	while ((mp != NULL) && (out.count < MAX_XFER_COUTPUT)) {
		/*
		 * Process as many of the characters in the current mblk as
		 * possible.
		 */
		while ((cp != mp->b_wptr) && (out.count < MAX_XFER_COUTPUT)) {
			out.buffer[out.count++] = *cp++;
		}

		/*
		 * Did we process that entire mblk?  If so, move on to the next
		 * one.  If not, we're done filling the buffer even if there's
		 * space left, because apparently there wasn't room to process
		 * the next character.
		 */
		if (cp != mp->b_wptr) {
			break;
		}

		/*
		 * When this loop terminates, last_empty_mp will point to the
		 * last mblk that was completely processed, mp will point to the
		 * following mblk (or NULL if no more mblks exist), and cp will
		 * point to the first untransmitted character in the mblk
		 * pointed to by mp.  We'll need this data to update the mblk
		 * chain if all of the data is successfully transmitted.
		 */
		last_empty_mp = mp;
		mp = mp->b_cont;
		cp = (mp != NULL) ? mp->b_rptr : NULL;
	}

	/*
	 * If we succeeded in preparing some data, try to transmit it through
	 * IOSRAM.  First write the count and the data, which can be done in a
	 * single operation thanks to the buffer structure we use, then set the
	 * data_valid flag if the first step succeeded.
	 */
	if (out.count != 0) {
		rval = iosram_wr(IOSRAM_KEY_CONO, COUNT_OFFSET,
		    CONSBUF_COUNT_SIZE + out.count, (caddr_t)&out);
		if ((rval != 0) && (rval != EAGAIN)) {
			cmn_err(CE_WARN, "cvc_putc: write ret %d", rval);
		}

		/* if the data write succeeded, set the data_valid flag */
		if (rval == 0) {
			rval = iosram_set_flag(IOSRAM_KEY_CONO,
			    IOSRAM_DATA_VALID, IOSRAM_INT_NONE);
			if ((rval != 0) && (rval != EAGAIN)) {
				cmn_err(CE_WARN,
				    "cvc_putc: set flags for outbuf ret %d",
				    rval);
			}
		}

		/*
		 * If we successfully transmitted any data, modify the caller's
		 * mblk chain to remove the data that was transmitted, freeing
		 * all mblks that were completely processed.
		 */
		if (rval == 0) {
			last_flush = ddi_get_lbolt();

			/*
			 * If any data is left over, update the b_rptr field of
			 * the first remaining mblk in case some of its data was
			 * processed.
			 */
			if (mp != NULL) {
				mp->b_rptr = cp;
			}

			/*
			 * If any mblks have been emptied, unlink them from the
			 * residual chain, free them, and update the caller's
			 * mblk pointer.
			 */
			if (last_empty_mp != NULL) {
				last_empty_mp->b_cont = NULL;
				freemsg(*chainpp);
				*chainpp = mp;
			}
		}
	}
}


/*
 * cvc_flush_queue()
 *	Tell the STREAMS subsystem to schedule cvc_wsrv to process the queue we
 *	use to gather console output.
 */
/* ARGSUSED */
static void
cvc_flush_queue(void *notused)
{
	rw_enter(&cvclock, RW_WRITER);
	if (cvcinput_q != NULL) {
		qenable(WR(cvcinput_q));
	}

	cvc_timeout_id = (timeout_id_t)-1;
	rw_exit(&cvclock);
}


/*
 * cvc_getstr()
 *	Poll IOSRAM for console input while available.
 */
static void
cvc_getstr(char *cp)
{
	short		count;
	uint8_t		command = 0;
	int		rval = ESUCCESS;
	uint8_t		dvalid = IOSRAM_DATA_INVALID;
	uint8_t		intrpending = 0;

	mutex_enter(&cvc_iosram_input_mutex);
	while (dvalid == IOSRAM_DATA_INVALID) {
		/*
		 * Check the CONC data_valid flag to see if a control message is
		 * available.
		 */
		rval = iosram_get_flag(IOSRAM_KEY_CONC, &dvalid, &intrpending);
		if ((rval != 0) && (rval != EAGAIN)) {
			cmn_err(CE_WARN,
			    "cvc_getstr: get flag for cntl ret %d", rval);
		}

		/*
		 * If a control message is available, try to read and process
		 * it.
		 */
		if ((dvalid == IOSRAM_DATA_VALID) && (rval == 0)) {
			/* read the control reg offset */
			rval = iosram_rd(IOSRAM_KEY_CONC,
			    CVC_CTL_OFFSET(command), CVC_CTL_SIZE(command),
			    (caddr_t)&command);
			if ((rval != 0) && (rval != EAGAIN)) {
				cmn_err(CE_WARN,
				    "cvc_getstr: read for command ret %d",
				    rval);
			}

			/* process the cntl msg and clear the data_valid flag */
			if (rval == 0) {
				cvc_iosram_ops(command);
			}
		}

		/*
		 * Check the CONI data_valid flag to see if console input data
		 * is available.
		 */
		rval = iosram_get_flag(IOSRAM_KEY_CONI, &dvalid, &intrpending);
		if ((rval != 0) && (rval != EAGAIN)) {
			cmn_err(CE_WARN,
			    "cvc_getstr: get flag for inbuf ret %d",
			    rval);
		}
		if ((rval != 0) || (dvalid != IOSRAM_DATA_VALID)) {
			goto retry;
		}

		/*
		 * Try to read the count.
		 */
		rval = iosram_rd(IOSRAM_KEY_CONI, COUNT_OFFSET,
		    CONSBUF_COUNT_SIZE, (caddr_t)&count);
		if (rval != 0) {
			if (rval != EAGAIN) {
				cmn_err(CE_WARN,
				    "cvc_getstr: read for count ret %d", rval);
			}
			goto retry;
		}

		/*
		 * If there is data to be read, try to read it.
		 */
		if (count != 0) {
			rval = iosram_rd(IOSRAM_KEY_CONI, DATA_OFFSET, count,
			    (caddr_t)cp);
			if (rval != 0) {
				if (rval != EAGAIN) {
					cmn_err(CE_WARN,
					    "cvc_getstr: read for count ret %d",
					    rval);
				}
				goto retry;
			}
			cp[count] = '\0';
		}

		/*
		 * Try to clear the data_valid flag to indicate that whatever
		 * was in CONI was read successfully.  If successful, and some
		 * data was read, break out of the loop to return to the caller.
		 */
		rval = iosram_set_flag(IOSRAM_KEY_CONI, IOSRAM_DATA_INVALID,
		    IOSRAM_INT_NONE);
		if (rval != 0) {
			if (rval != EAGAIN) {
				cmn_err(CE_WARN,
				    "cvc_getstr: set flag for inbuf ret %d",
				    rval);
			}
		} else if (count != 0) {
			CVC_DBG1(CVC_DBG_IOSRAM_RD, "Read 0x%x", count);
			break;
		}

		/*
		 * Use a smaller delay between checks of IOSRAM for input
		 * when cvcd/cvcredir are not running or "via_iosram" has
		 * been set.
		 * We don't go away completely when i/o is going through the
		 * network via cvcd since a command may be sent via IOSRAM
		 * to switch if the network is down or hung.
		 */
retry:
		if ((cvcoutput_q == NULL) || (via_iosram))
			delay(drv_usectohz(CVC_IOSRAM_POLL_USECS));
		else
			delay(drv_usectohz(CVC_IOSRAM_POLL_USECS * 10));

	}

	mutex_exit(&cvc_iosram_input_mutex);
}


/*
 * cvc_input_daemon()
 *	this function runs as a separate kernel thread and polls IOSRAM for
 *	input, and possibly put it on read stream for the console.
 *	There are two poll rates (implemented in cvc_getstr):
 *		 100 000 uS (10 Hz) - no cvcd communications || via_iosram
 *		1000 000 uS ( 1 Hz) - cvcd communications
 * 	This continues to run even if there are network console communications
 *	in order to handle out-of-band signaling.
 */
/* ARGSUSED */
static void
cvc_input_daemon(void)
{
	char		linebuf[MAX_XFER_CINPUT + 1];
	char		*cp;
	mblk_t		*mbp;
	int		c;
	int		dropped_read = 0;

	for (;;) {
		cvc_getstr(linebuf);

		mbp = allocb(strlen(linebuf), BPRI_MED);
		if (mbp == NULL) {	/* drop it & go on if no buffer */
			if (!dropped_read) {
				cmn_err(CE_WARN, "cvc_input_daemon: "
				    "dropping IOSRAM reads");
			}
			dropped_read++;
			continue;
		}

		if (dropped_read) {
			cmn_err(CE_WARN,
			    "cvc_input_daemon: dropped %d IOSRAM reads",
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
				/*
				 * XXX - should canputnext be called here?
				 * Starfire's cvc doesn't do that, and it
				 * appears to work anyway.
				 */
				(void) putnext(cvcinput_q, mbp);
			}
		} else {
			freemsg(mbp);
		}
		mutex_exit(&cvcmutex);
	}

	/* NOTREACHED */
}

/*
 * cvc_win_resize()
 *	cvc_win_resize will read winsize data from the CONC IOSRAM chunk and set
 *	the console window size accordingly.  If indicated by the caller, CONC's
 *	data_valid flag will also be cleared.  The flag isn't cleared in all
 *	cases because we need to process winsize data at startup without waiting
 *	for a command.
 */
static void
cvc_win_resize(int clear_flag)
{
	int		rval;
	uint16_t	rows;
	uint16_t	cols;
	uint16_t	xpixels;
	uint16_t	ypixels;
	tty_common_t	*tty;
	cvc_t		*cp;
	struct winsize	ws;

	/*
	 * Start by reading the new window size out of the CONC chunk and, if
	 * requested, clearing CONC's data_valid flag.  If any of that fails,
	 * return immediately.  (Note that the rather bulky condition in the
	 * two "if" statements takes advantage of C's short-circuit logic
	 * evaluation)
	 */
	if (((rval = iosram_rd(IOSRAM_KEY_CONC, CVC_CTL_OFFSET(winsize_rows),
	    CVC_CTL_SIZE(winsize_rows), (caddr_t)&rows)) != 0) ||
	    ((rval = iosram_rd(IOSRAM_KEY_CONC, CVC_CTL_OFFSET(winsize_cols),
	    CVC_CTL_SIZE(winsize_cols), (caddr_t)&cols)) != 0) ||
	    ((rval = iosram_rd(IOSRAM_KEY_CONC,
	    CVC_CTL_OFFSET(winsize_xpixels), CVC_CTL_SIZE(winsize_xpixels),
	    (caddr_t)&xpixels)) != 0) || ((rval = iosram_rd(IOSRAM_KEY_CONC,
	    CVC_CTL_OFFSET(winsize_ypixels), CVC_CTL_SIZE(winsize_ypixels),
	    (caddr_t)&ypixels)) != 0)) {
		if (rval != EAGAIN) {
			cmn_err(CE_WARN,
			    "cvc_win_resize: read for ctlbuf ret %d", rval);
		}
		return;
	}

	if (clear_flag && ((rval = iosram_set_flag(IOSRAM_KEY_CONC,
	    IOSRAM_DATA_INVALID, IOSRAM_INT_NONE)) != 0)) {
		if (rval != EAGAIN) {
			cmn_err(CE_WARN,
			    "cvc_win_resize: set_flag for ctlbuf ret %d", rval);
		}
		return;
	}

	/*
	 * Copy the parameters from IOSRAM to a winsize struct.
	 */
	ws.ws_row = rows;
	ws.ws_col = cols;
	ws.ws_xpixel = xpixels;
	ws.ws_ypixel = ypixels;

	/*
	 * This code was taken from Starfire, and it appears to work correctly.
	 * However, since the original developer felt it necessary to add the
	 * following comment, it's probably worth preserving:
	 *
	 * XXX I hope this is safe...
	 */
	cp = cvcinput_q->q_ptr;
	tty = &cp->cvc_tty;
	mutex_enter(&tty->t_excl);
	if (bcmp((caddr_t)&tty->t_size, (caddr_t)&ws,
	    sizeof (struct winsize))) {
		tty->t_size = ws;
		mutex_exit(&tty->t_excl);
		(void) putnextctl1(cvcinput_q, M_PCSIG,
			SIGWINCH);
	} else {
		mutex_exit(&tty->t_excl);
	}
}

#ifdef DEBUG

void
cvc_dbg(uint32_t flag, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = NULL;
	char buf[256];

	if (cvc_dbg_flags && ((cvc_dbg_flags & flag) == flag)) {
		switch (flag) {
		case CVC_DBG_ATTACH:
			s = "attach";
			break;
		case CVC_DBG_DETACH:
			s = "detach";
			break;
		case CVC_DBG_OPEN:
			s = "open";
			break;
		case CVC_DBG_CLOSE:
			s = "close";
			break;
		case CVC_DBG_IOCTL:
			s = "ioctl";
			break;
		case CVC_DBG_REDIR:
			s = "redir";
			break;
		case CVC_DBG_WPUT:
			s = "wput";
			break;
		case CVC_DBG_WSRV:
			s = "wsrv";
			break;
		case CVC_DBG_IOSRAM_WR:
			s = "iosram_wr";
			break;
		case CVC_DBG_IOSRAM_RD:
			s = "iosram_rd";
			break;
		case CVC_DBG_NETWORK_WR:
			s = "network_wr";
			break;
		case CVC_DBG_NETWORK_RD:
			s = "network_rd";
			break;
		case CVC_DBG_IOSRAM_CNTL:
			s = "iosram_cntlmsg";
			break;
		default:
			s = "Unknown debug flag";
			break;
		}

		sprintf(buf, "!%s_%s(%d): %s", ddi_driver_name(cvcdip), s,
		    cvc_instance, fmt);
		cmn_err(CE_NOTE, buf, a1, a2, a3, a4, a5);
	}
}

#endif /* DEBUG */
