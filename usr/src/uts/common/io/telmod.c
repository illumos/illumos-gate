/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module implements the "fast path" processing for the telnet protocol.
 * Since it only knows a very small number of the telnet protocol options,
 * the daemon is required to assist this module.  This module must be run
 * underneath logindmux, which handles switching messages between the
 * daemon and the pty master stream appropriately.  When an unknown telnet
 * option is received it is handled as a stop-and-wait operation.  The
 * module refuses to forward data in either direction, and waits for the
 * daemon to deal with the option, and forward any unprocessed data back
 * to the daemon.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/tihdr.h>
#include <sys/ptem.h>
#include <sys/logindmux.h>
#include <sys/telioctl.h>
#include <sys/termios.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/cryptmod.h>

#define	IAC	255

extern struct streamtab telmodinfo;

#define	TELMOD_ID	105
#define	SIMWAIT		(1*hz)

/*
 * Module state flags
 */
#define		TEL_IOCPASSTHRU	0x100
#define		TEL_STOPPED	0x80
#define		TEL_CRRCV	0x40
#define		TEL_CRSND	0x20
#define		TEL_GETBLK	0x10

/*
 * NOTE: values TEL_BINARY_IN and TEL_BINARY_OUT are defined in
 * telioctl.h, passed in the TEL_IOC_MODE ioctl and stored (bitwise)
 * in the module state flag.  So those values are not available
 * even though they are not defined here.
 */



/*
 * Per queue instances are single-threaded since the q_ptr
 * field of queues need to be shared among threads.
 */
static struct fmodsw fsw = {
	"telmod",
	&telmodinfo,
	D_MTQPAIR | D_MP
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"telnet module",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int	telmodopen(queue_t *, dev_t *, int, int, cred_t *);
static int	telmodclose(queue_t *, int, cred_t *);
static void	telmodrput(queue_t *, mblk_t *);
static void	telmodrsrv(queue_t *);
static void	telmodwput(queue_t *, mblk_t *);
static void	telmodwsrv(queue_t *);
static int	rcv_parse(queue_t *q, mblk_t *mp);
static int	snd_parse(queue_t *q, mblk_t *mp);
static void	telmod_timer(void *);
static void	telmod_buffer(void *);
static void	recover(queue_t *, mblk_t *, size_t);

static struct module_info telmodoinfo = {
	TELMOD_ID,				/* module id number */
	"telmod",				/* module name */
	0,					/* minimum packet size */
	INFPSZ,					/* maximum packet size */
	512,					/* hi-water mark */
	256					/* lo-water mark */
};

static struct qinit telmodrinit = {
	(int (*)())telmodrput,
	(int (*)())telmodrsrv,
	telmodopen,
	telmodclose,
	nulldev,
	&telmodoinfo,
	NULL
};

static struct qinit telmodwinit = {
	(int (*)())telmodwput,
	(int (*)())telmodwsrv,
	NULL,
	NULL,
	nulldev,
	&telmodoinfo,
	NULL
};

struct streamtab telmodinfo = {
	&telmodrinit,
	&telmodwinit,
	NULL,
	NULL
};

/*
 * Per-instance state struct for the telnet module.
 */
struct telmod_info {
	int		flags;
	bufcall_id_t	wbufcid;
	bufcall_id_t	rbufcid;
	timeout_id_t	wtimoutid;
	timeout_id_t	rtimoutid;
	mblk_t		*unbind_mp;

};

/*ARGSUSED*/
static void
dummy_callback(void *arg)
{}

/*
 * telmodopen -
 *	A variety of telnet options can never really be processed in the
 *	kernel.  For example, TELOPT_TTYPE, must be based in the TERM
 *	environment variable to the login process.  Also, data may already
 *	have reached the stream head before telmod was pushed on the stream.
 *	So when telmod is opened, it begins in stopped state, preventing
 *	further data passing either direction through it.  It sends a
 *	T_DATA_REQ messages up toward the daemon.  This is so the daemon
 *	can be sure that all data which was not processed by telmod
 *	(because it wasn't yet pushed) has been received at the stream head.
 */
/*ARGSUSED*/
static int
telmodopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	struct telmod_info	*tmip;
	mblk_t *bp;
	union T_primitives *tp;
	int	error;

	if (sflag != MODOPEN)
		return (EINVAL);

	if (q->q_ptr != NULL) {
		/* It's already attached. */
		return (0);
	}
	/*
	 * Allocate state structure.
	 */
	tmip = kmem_zalloc(sizeof (*tmip), KM_SLEEP);

	/*
	 * Cross-link.
	 */
	q->q_ptr = tmip;
	WR(q)->q_ptr = tmip;

	noenable(q);
	tmip->flags |= TEL_STOPPED;
	qprocson(q);

	/*
	 * Since TCP operates in the TLI-inspired brain-dead fashion,
	 * the connection will revert to bound state if the connection
	 * is reset by the client.  We must send a T_UNBIND_REQ in
	 * that case so the port doesn't get "wedged" (preventing
	 * inetd from being able to restart the listener).  Allocate
	 * it here, so that we don't need to worry about allocb()
	 * failures later.
	 */
	while ((tmip->unbind_mp = allocb(sizeof (union T_primitives),
	    BPRI_HI)) == NULL) {
		bufcall_id_t id = qbufcall(q, sizeof (union T_primitives),
		    BPRI_HI, dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			error = EINTR;
			goto fail;
		}
		qunbufcall(q, id);
	}
	tmip->unbind_mp->b_wptr = tmip->unbind_mp->b_rptr +
	    sizeof (struct T_unbind_req);
	tmip->unbind_mp->b_datap->db_type = M_PROTO;
	tp = (union T_primitives *)tmip->unbind_mp->b_rptr;
	tp->type = T_UNBIND_REQ;
	/*
	 * Send a M_PROTO msg of type T_DATA_REQ (this is unique for
	 * read queue since only write queue can get T_DATA_REQ).
	 * Readstream routine in telnet daemon will do a getmsg() till
	 * it receives this proto message
	 */
	while ((bp = allocb(sizeof (union T_primitives), BPRI_HI)) == NULL) {
		bufcall_id_t id = qbufcall(q, sizeof (union T_primitives),
		    BPRI_HI, dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			error = EINTR;
			goto fail;
		}
		qunbufcall(q, id);
	}
	bp->b_datap->db_type = M_PROTO;
	bp->b_wptr = bp->b_rptr + sizeof (union T_primitives);
	tp = (union T_primitives *)bp->b_rptr;
	tp->type = T_DATA_REQ;
	tp->data_req.MORE_flag = 0;

	putnext(q, bp);
	return (0);

fail:
	qprocsoff(q);
	if (tmip->unbind_mp != NULL) {
		freemsg(tmip->unbind_mp);
	}
	kmem_free(tmip, sizeof (struct telmod_info));
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (error);
}


/*
 * telmodclose - just the normal streams clean-up is required.
 */

/*ARGSUSED*/
static int
telmodclose(queue_t *q, int flag, cred_t *credp)
{
	struct telmod_info   *tmip = (struct telmod_info *)q->q_ptr;
	mblk_t	*mp;

	/*
	 * Flush any write-side data downstream.  Ignoring flow
	 * control at this point is known to be safe because the
	 * M_HANGUP below poisons the stream such that no modules can
	 * be pushed again.
	 */
	while (mp = getq(WR(q)))
		putnext(WR(q), mp);

	/* Poison the stream head so that we can't be pushed again. */
	(void) putnextctl(q, M_HANGUP);

	qprocsoff(q);
	if (tmip->wbufcid) {
		qunbufcall(q, tmip->wbufcid);
		tmip->wbufcid = 0;
	}
	if (tmip->rbufcid) {
		qunbufcall(q, tmip->rbufcid);
		tmip->rbufcid = 0;
	}
	if (tmip->wtimoutid) {
		(void) quntimeout(q, tmip->wtimoutid);
		tmip->wtimoutid = 0;
	}
	if (tmip->rtimoutid) {
		(void) quntimeout(q, tmip->rtimoutid);
		tmip->rtimoutid = 0;
	}
	if (tmip->unbind_mp != NULL) {
		freemsg(tmip->unbind_mp);
	}

	kmem_free(q->q_ptr, sizeof (struct telmod_info));
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * telmodrput:
 * Be sure to preserve data order.  If the daemon is waiting for additional
 * data (TEL_GETBLK state) forward new data.  Otherwise, apply normal
 * telnet protocol processing to M_DATA.  Take notice of TLI messages
 * indicating connection tear-down, and change them into M_HANGUP's.
 */
static void
telmodrput(queue_t *q, mblk_t *mp)
{
	mblk_t	*newmp;
	struct telmod_info    *tmip = (struct telmod_info *)q->q_ptr;
	union T_primitives *tip;

	if ((mp->b_datap->db_type < QPCTL) &&
	    ((q->q_first) || ((tmip->flags & TEL_STOPPED) &&
	    !(tmip->flags & TEL_GETBLK)) || !canputnext(q))) {
		(void) putq(q, mp);
		return;
	}

	switch (mp->b_datap->db_type) {
	case M_DATA:

		/*
		 * If the user level daemon requests for 1 more
		 * block of data (needs more data for protocol processing)
		 * create a M_CTL message block with the mp.
		 */
is_mdata:
		if (tmip->flags & TEL_GETBLK) {
			if ((newmp = allocb(sizeof (char), BPRI_MED)) == NULL) {
				recover(q, mp, msgdsize(mp));
				return;
			}
			newmp->b_datap->db_type = M_CTL;
			newmp->b_wptr = newmp->b_rptr + 1;
			*(newmp->b_rptr) = M_CTL_MAGIC_NUMBER;
			newmp->b_cont = mp;
			tmip->flags &= ~TEL_GETBLK;
			noenable(q);
			tmip->flags |= TEL_STOPPED;

			putnext(q, newmp);

			break;
		}
		/*
		 * call the protocol parsing routine which processes
		 * the data part of the message block first. Then it
		 * handles protocol and CR/LF processing.
		 * If an error is found inside allocb/dupb, recover
		 * routines inside rcv_parse will queue up the
		 * original message block in its service queue.
		 */
		(void) rcv_parse(q, mp);
		break;

	case M_FLUSH:
		/*
		 * Since M_FLUSH came from TCP, we mark it bound for
		 * daemon, not tty.  This only happens when TCP expects
		 * to do a connection reset.
		 */
		mp->b_flag |= MSGMARK;
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHALL);
		putnext(q, mp);
		break;

	case M_PCSIG:
	case M_ERROR:
		if (tmip->flags & TEL_GETBLK)
			tmip->flags &= ~TEL_GETBLK;
		/* FALLTHRU */
	case M_IOCACK:
	case M_IOCNAK:
	case M_SETOPTS:
		putnext(q, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		if (tmip->flags & TEL_GETBLK)
			tmip->flags &= ~TEL_GETBLK;

		tip = (union T_primitives *)mp->b_rptr;
		switch (tip->type) {

		case T_ORDREL_IND:
		case T_DISCON_IND:
			/* Make into M_HANGUP and putnext */
			ASSERT(mp->b_cont == NULL);
			mp->b_datap->db_type = M_HANGUP;
			mp->b_wptr = mp->b_rptr;
			if (mp->b_cont) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}
			/*
			 * If we haven't already, send T_UNBIND_REQ to prevent
			 * TCP from going into "BOUND" state and locking up the
			 * port.
			 */
			if (tip->type == T_DISCON_IND && tmip->unbind_mp !=
			    NULL) {
				putnext(q, mp);
				qreply(q, tmip->unbind_mp);
				tmip->unbind_mp = NULL;
			} else {
				putnext(q, mp);
			}
			break;

		case T_EXDATA_IND:
		case T_DATA_IND:	/* conform to TPI, but never happens */
			newmp = mp->b_cont;
			freeb(mp);
			mp = newmp;
			if (mp) {
				ASSERT(mp->b_datap->db_type == M_DATA);
				if (msgdsize(mp) != 0) {
					goto is_mdata;
				}
				freemsg(mp);
			}
			break;

		/*
		 * We only get T_OK_ACK when we issue the unbind, and it can
		 * be ignored safely.
		 */
		case T_OK_ACK:
			ASSERT(tmip->unbind_mp == NULL);
			freemsg(mp);
			break;

		default:
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "telmodrput: unexpected TLI primitive msg "
			    "type 0x%x", tip->type);
#endif
			freemsg(mp);
		}
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "telmodrput: unexpected msg type 0x%x",
		    mp->b_datap->db_type);
#endif
		freemsg(mp);
	}
}

/*
 * telmodrsrv:
 * Mostly we end up here because of M_DATA processing delayed due to flow
 * control or lack of memory.  XXX.sparker: TLI primitives here?
 */
static void
telmodrsrv(queue_t *q)
{
	mblk_t	*mp, *newmp;
	struct telmod_info    *tmip = (struct telmod_info *)q->q_ptr;
	union T_primitives *tip;

	while ((mp = getq(q)) != NULL) {
		if (((tmip->flags & TEL_STOPPED) &&
		    !(tmip->flags & TEL_GETBLK)) || !canputnext(q)) {
			(void) putbq(q, mp);
			return;
		}
		switch (mp->b_datap->db_type) {

		case M_DATA:
is_mdata:
			if (tmip->flags & TEL_GETBLK) {
				if ((newmp = allocb(sizeof (char),
				    BPRI_MED)) == NULL) {
					recover(q, mp, msgdsize(mp));
					return;
				}
				newmp->b_datap->db_type = M_CTL;
				newmp->b_wptr = newmp->b_rptr + 1;
				*(newmp->b_rptr) = M_CTL_MAGIC_NUMBER;
				newmp->b_cont = mp;
				tmip->flags &= ~TEL_GETBLK;
				noenable(q);
				tmip->flags |= TEL_STOPPED;

				putnext(q, newmp);

				break;
			}
			if (!rcv_parse(q, mp)) {
				return;
			}
			break;

		case M_PROTO:

			tip = (union T_primitives *)mp->b_rptr;

			/*
			 * Unless the M_PROTO message indicates data, clear
			 * TEL_GETBLK so that we stop passing our messages
			 * up to the telnet daemon.
			 */
			if (tip->type != T_DATA_IND &&
			    tip->type != T_EXDATA_IND)
				tmip->flags &= ~TEL_GETBLK;

			switch (tip->type) {
			case T_ORDREL_IND:
			case T_DISCON_IND:
			/* Make into M_HANGUP and putnext */
				ASSERT(mp->b_cont == NULL);
				mp->b_datap->db_type = M_HANGUP;
				mp->b_wptr = mp->b_rptr;
				if (mp->b_cont) {
					freemsg(mp->b_cont);
					mp->b_cont = NULL;
				}
				/*
				 * If we haven't already, send T_UNBIND_REQ
				 * to prevent TCP from going into "BOUND"
				 * state and locking up the port.
				 */
				if (tip->type == T_DISCON_IND &&
				    tmip->unbind_mp != NULL) {
					putnext(q, mp);
					qreply(q, tmip->unbind_mp);
					tmip->unbind_mp = NULL;
				} else {
					putnext(q, mp);
				}
				break;

			case T_DATA_IND: /* conform to TPI, but never happens */
			case T_EXDATA_IND:
				newmp = mp->b_cont;
				freeb(mp);
				mp = newmp;
				if (mp) {
					ASSERT(mp->b_datap->db_type == M_DATA);
					if (msgdsize(mp) != 0) {
						goto is_mdata;
					}
					freemsg(mp);
				}
				break;

			/*
			 * We only get T_OK_ACK when we issue the unbind, and
			 * it can be ignored safely.
			 */
			case T_OK_ACK:
				ASSERT(tmip->unbind_mp == NULL);
				freemsg(mp);
				break;

			default:
#ifdef DEBUG
				cmn_err(CE_NOTE,
				    "telmodrsrv: unexpected TLI primitive "
				    "msg type 0x%x", tip->type);
#endif
				freemsg(mp);
			}
			break;

		case M_SETOPTS:
			putnext(q, mp);
			break;

		default:
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "telmodrsrv: unexpected msg type 0x%x",
			    mp->b_datap->db_type);
#endif
			freemsg(mp);
		}
	}
}

/*
 * telmodwput:
 * M_DATA is processed and forwarded if we aren't stopped awaiting the daemon
 * to process something.  M_CTL's are data from the daemon bound for the
 * network.  We forward them immediately.  There are two classes of ioctl's
 * we must handle here also.  One is ioctl's forwarded by ptem which we
 * ignore.  The other is ioctl's issued by the daemon to control us.
 * Process them appropriately.  M_PROTO's we pass along, figuring they are
 * are TPI operations for TCP.  M_FLUSH requires careful processing, since
 * telnet cannot tolerate flushing its protocol requests.  Also the flushes
 * can be running either daemon<->TCP or application<->telmod.  We must
 * carefully deal with this.
 */
static void
telmodwput(
	queue_t *q,	/* Pointer to the read queue */
	mblk_t *mp)	/* Pointer to current message block */
{
	struct telmod_info	*tmip;
	struct iocblk *ioc;
	mblk_t *savemp;
	int rw;
	int error;

	tmip = (struct telmod_info *)q->q_ptr;

	switch (mp->b_datap->db_type) {
	case M_DATA:
		if (!canputnext(q) || (tmip->flags & TEL_STOPPED) ||
		    (q->q_first)) {
			noenable(q);
			(void) putq(q, mp);
			break;
		}
		/*
		 * This routine parses data generating from ptm side.
		 * Insert a null character if carraige return
		 * is not followed by line feed unless we are in binary mode.
		 * Also, duplicate IAC if found in the data.
		 */
		(void) snd_parse(q, mp);
		break;

	case M_CTL:
		if (((mp->b_wptr - mp->b_rptr) == 1) &&
		    (*(mp->b_rptr) == M_CTL_MAGIC_NUMBER)) {
			savemp = mp->b_cont;
			freeb(mp);
			mp = savemp;
		}
		putnext(q, mp);
		break;

	case M_IOCTL:
		ioc = (struct iocblk *)mp->b_rptr;
		switch (ioc->ioc_cmd) {

		/*
		 * This ioctl is issued by user level daemon to
		 * request one more message block to process protocol
		 */
		case TEL_IOC_GETBLK:
			if (!(tmip->flags & TEL_STOPPED)) {
				miocnak(q, mp, 0, EINVAL);
				break;
			}
			tmip->flags |= TEL_GETBLK;
			qenable(RD(q));
			enableok(RD(q));

			miocack(q, mp, 0, 0);
			break;

		/*
		 * This ioctl is issued by user level daemon to reenable the
		 * read and write queues. This is issued during startup time
		 * after setting up the mux links and also after processing
		 * the protocol.  It is also issued after each time an
		 * an unrecognized telnet option is forwarded to the daemon.
		 */
		case TEL_IOC_ENABLE:

			/*
			 * Send negative ack if TEL_STOPPED flag is not set
			 */
			if (!(tmip->flags & TEL_STOPPED)) {
				miocnak(q, mp, 0, EINVAL);
				break;
			}
			tmip->flags &= ~TEL_STOPPED;
			if (mp->b_cont) {
				(void) putbq(RD(q), mp->b_cont);
				mp->b_cont = 0;
			}

			qenable(RD(q));
			enableok(RD(q));
			qenable(q);
			enableok(q);

			miocack(q, mp, 0, 0);
			break;

		/*
		 * Set binary/normal mode for input and output
		 * according to the instructions from the daemon.
		 */
		case TEL_IOC_MODE:
			error = miocpullup(mp, sizeof (uchar_t));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			tmip->flags |= *(mp->b_cont->b_rptr) &
			    (TEL_BINARY_IN|TEL_BINARY_OUT);
			miocack(q, mp, 0, 0);
			break;

#ifdef DEBUG
		case TCSETAF:
		case TCSETSF:
		case TCSETA:
		case TCSETAW:
		case TCSETS:
		case TCSETSW:
		case TCSBRK:
		case TIOCSTI:
		case TIOCSWINSZ:
			miocnak(q, mp, 0, EINVAL);
			break;
#endif
		case CRYPTPASSTHRU:
			error = miocpullup(mp, sizeof (uchar_t));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			if (*(mp->b_cont->b_rptr) == 0x01)
				tmip->flags |= TEL_IOCPASSTHRU;
			else
				tmip->flags &= ~TEL_IOCPASSTHRU;

			miocack(q, mp, 0, 0);
			break;

		default:
			if (tmip->flags & TEL_IOCPASSTHRU) {
				putnext(q, mp);
			} else {
#ifdef DEBUG
				cmn_err(CE_NOTE,
				    "telmodwput: unexpected ioctl type 0x%x",
				    ioc->ioc_cmd);
#endif
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		}
		break;

	case M_FLUSH:
		/*
		 * Flushing is tricky:  We try to flush all we can, but certain
		 * data cannot be flushed.  Telnet protocol sequences cannot
		 * be flushed.  So, TCP's queues cannot be flushed since we
		 * cannot tell what might be telnet protocol data.  Then we
		 * must take care to create and forward out-of-band data
		 * indicating the flush to the far side.
		 */
		rw = *mp->b_rptr;
		if (rw & FLUSHR) {
			/*
			 * We cannot flush our read queue, since there may
			 * be telnet protocol bits in the queue, awaiting
			 * processing.  However, once it leaves this module
			 * it's guaranteed that all protocol data is in
			 * M_CTL, so we do flush read data beyond us, expecting
			 * them (actually logindmux) to do FLUSHDATAs also.
			 */
			*mp->b_rptr = rw & ~FLUSHW;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		if (rw & FLUSHW) {
			/*
			 * Since all telnet protocol data comes from the
			 * daemon, stored as M_CTL messages, flushq will
			 * do exactly what's needed:  Flush bytes which do
			 * not have telnet protocol data.
			 */
			flushq(q, FLUSHDATA);
		}
		break;

	case M_PCPROTO:
		putnext(q, mp);
		break;

	case M_PROTO:
		/* We may receive T_DISCON_REQ from the mux */
		if (!canputnext(q) || q->q_first != NULL)
			(void) putq(q, mp);
		else
			putnext(q, mp);
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "telmodwput: unexpected msg type 0x%x",
		    mp->b_datap->db_type);
#endif
		freemsg(mp);
		break;
	}
}

/*
 * telmodwsrv - module write service procedure
 */
static void
telmodwsrv(queue_t *q)
{
	mblk_t	*mp, *savemp;

	struct	telmod_info    *tmip = (struct telmod_info *)q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		if (!canputnext(q)) {
			ASSERT(mp->b_datap->db_type < QPCTL);
			(void) putbq(q, mp);
			return;
		}
		switch (mp->b_datap->db_type) {

		case M_DATA:
			if (tmip->flags & TEL_STOPPED) {
				(void) putbq(q, mp);
				return;
			}
			/*
			 * Insert a null character if carraige return
			 * is not followed by line feed
			 */
			if (!snd_parse(q, mp)) {
				return;
			}
			break;

		case M_CTL:
			if (((mp->b_wptr - mp->b_rptr) == 1) &&
			    (*(mp->b_rptr) == M_CTL_MAGIC_NUMBER)) {
				savemp = mp->b_cont;
				freeb(mp);
				mp = savemp;
			}
			putnext(q, mp);
			break;

		case M_PROTO:
			putnext(q, mp);
			break;

		default:
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "telmodwsrv: unexpected msg type 0x%x",
			    mp->b_datap->db_type);
#endif
			freemsg(mp);
		}

	}
}

/*
 * This routine is called from read put/service procedure and parses
 * message block to check for telnet protocol by detecting an IAC.
 * The routine processes the data part of the message block first and
 * then sends protocol followed after IAC to the telnet daemon. The
 * routine also processes CR/LF by eliminating LF/NULL followed after CR.
 *
 * Since the code to do this with streams mblks is complicated, some
 * explanations are in order.  If an IAC is found, a dupb() is done,
 * and the pointers are adjusted to create two streams message.  The
 * (possibly empty) first message contains preceeding data, and the
 * second begins with the IAC and contains the rest of the streams
 * message.
 *
 * The variables:
 * datamp:	Points to the head of a chain of mblks containing data
 *		which requires no expansion, and can be forwarded directly
 *		to the pty.
 * prevmp:	Points to the last mblk on the datamp chain, used to add
 *		to the chain headed by datamp.
 * newmp:	When an M_CTL header is required, this pointer references
 *		that "header" mblk.
 * protomp:	When an IAC is discovered, a dupb() is done on the first mblk
 *		containing an IAC.  protomp points to this dup'ed mblk.
 *		This mblk is eventually forwarded to the daemon.
 */
static int
rcv_parse(queue_t *q, mblk_t *mp)
{
	mblk_t	*protomp, *newmp, *datamp, *prevmp;
	unsigned char *tmp;
	size_t	msgsize;

	struct telmod_info    *tmip = (struct telmod_info *)q->q_ptr;

	datamp = mp;
	prevmp = protomp = 0;

	while (mp) {
		/*
		 * If the mblk is empty, just continue scanning.
		 */
		if (mp->b_rptr == mp->b_wptr) {
			prevmp = mp;
			mp = mp->b_cont;
			continue;
		}
		/*
		 * First check to see if we have received CR and are checking
		 * for a following LF/NULL.  If so, do what's necessary to
		 * trim the LF/NULL.  This case is for when the LF/NULL is
		 * at the beginning of a subsequent mblk.
		 */
		if (!(tmip->flags & TEL_BINARY_IN) &&
		    (tmip->flags & TEL_CRRCV)) {
			if ((*mp->b_rptr == '\n') || (*mp->b_rptr == '\0')) {
				if (mp->b_wptr == (mp->b_rptr + 1)) {
					tmip->flags &= ~TEL_CRRCV;
					if (prevmp) {
						prevmp->b_cont = mp->b_cont;
						freeb(mp);
						mp = prevmp->b_cont;
						continue;
					} else {
						datamp = mp->b_cont;
						freeb(mp);
						if (datamp == NULL) {
							/*
							 * Message contained
							 * only a '\0' after
							 * a '\r' in a previous
							 * message, so we can
							 * read more, even
							 * though we have
							 * nothing to putnext.
							 */
							return (1);
						} else {
							mp = datamp;
							continue;
						}
					}
				}
				mp->b_rptr += 1;
			}
			tmip->flags &= ~TEL_CRRCV;
		}
		tmp = mp->b_rptr;
		/*
		 * Now scan through the entire message block, for IACs
		 * and CR characters, which need processing.
		 */
		while (tmp < mp->b_wptr) {

			if (tmp[0] == IAC) {
				/*
				 * Telnet protocol - parse it now
				 * process data part of mblk
				 * before sending the protocol.
				 */
				if (tmp > mp->b_rptr) {
					if ((protomp = dupb(mp)) == NULL) {
						msgsize = msgdsize(datamp);
						recover(q, datamp, msgsize);
						return (0);
					}
					ASSERT(tmp >= mp->b_datap->db_base);
					ASSERT(tmp <= mp->b_datap->db_lim);
					ASSERT(tmp >=
					    protomp->b_datap->db_base);
					ASSERT(tmp <= protomp->b_datap->db_lim);
					mp->b_wptr = tmp;
					protomp->b_rptr = tmp;
					protomp->b_cont = mp->b_cont;
					mp->b_cont = 0;

					if (prevmp)
						prevmp->b_cont = mp;

				} else {
					protomp = mp;

					if (prevmp)
						prevmp->b_cont = 0;
					else
						datamp = 0;
				}
				if (datamp) {
					putnext(q, datamp);
				}
				/*
				 * create a 1 byte M_CTL message block with
				 * protomp and send it down.
				 */

				if ((newmp = allocb(sizeof (char),
				    BPRI_MED)) == NULL) {
					/*
					 * Save the dup'ed mp containing
					 * the protocol information which
					 * we couldn't get an M_CTL header
					 * for.
					 */
					msgsize = msgdsize(protomp);
					recover(q, protomp, msgsize);
					return (0);
				}
				newmp->b_datap->db_type = M_CTL;
				newmp->b_wptr = newmp->b_rptr + 1;
				*(newmp->b_rptr) = M_CTL_MAGIC_NUMBER;
				newmp->b_cont = protomp;
				noenable(q);
				tmip->flags |= TEL_STOPPED;
				putnext(q, newmp);

				return (0);
			}
			if (!(tmip->flags & TEL_BINARY_IN)) {
				/*
				 * Set TEL_CRRCV flag if last character is CR
				 */
				if ((tmp == (mp->b_wptr - 1)) &&
				    (tmp[0] == '\r')) {
					tmip->flags |= TEL_CRRCV;
					break;
				}

				/*
				 * If CR is followed by LF/NULL, get rid of
				 * LF/NULL and realign the message block.
				 */
				if ((tmp[0] == '\r') && ((tmp[1] == '\n') ||
				    (tmp[1] == '\0'))) {
					/*
					 * If CR is in the middle of a block,
					 * we need to get rid of LF and join
					 * the two pieces together.
					 */
					if (mp->b_wptr > (tmp + 2)) {
						bcopy(tmp + 2, tmp + 1,
						    (mp->b_wptr - tmp - 2));
						mp->b_wptr -= 1;
					} else {
						mp->b_wptr = tmp + 1;
					}

					if (prevmp)
						prevmp->b_cont = mp;
				}
			}
			tmp++;
		}
		prevmp = mp;
		mp = mp->b_cont;
	}
	putnext(q, datamp);

	return (1);
}

/*
 * This routine is called from write put/service procedures and processes
 * CR-LF. If CR is not followed by LF, it inserts a NULL character if we are
 * in non binary mode. Also, duplicate IAC(0xFF) if found in the mblk.
 * This routine is pessimistic:  It pre-allocates a buffer twice the size
 * of the incoming message, which is the maximum size a message can become
 * after IAC expansion.
 *
 * savemp:	Points at the original message, so it can be freed when
 *		processing is complete.
 * mp:		The current point of scanning the message.
 * newmp:	New message being created with the processed output.
 */
static int
snd_parse(queue_t *q, mblk_t *mp)
{
	unsigned char *tmp, *tmp1;
	mblk_t	*newmp, *savemp;
	struct  telmod_info    *tmip = (struct telmod_info *)q->q_ptr;
	size_t size = msgdsize(mp);

	savemp = mp;

	if (size == 0) {
		putnext(q, mp);
		return (1);
	}

	/*
	 * Extra byte to allocb() takes care of the case when there was
	 * a '\r' at the end of the previous message and there's a '\r'
	 * at the beginning of the current message.
	 */
	if ((newmp = allocb((2 * size)+1, BPRI_MED)) == NULL) {
		recover(q, mp, (2 * size)+1);
		return (0);
	}
	newmp->b_datap->db_type = M_DATA;

	tmp1 = newmp->b_rptr;
	while (mp) {
		if (!(tmip->flags & TEL_BINARY_OUT) &&
		    (tmip->flags & TEL_CRSND)) {
			if (*(mp->b_rptr) != '\n')
				*tmp1++ = '\0';
			tmip->flags &= ~TEL_CRSND;
		}
		tmp = mp->b_rptr;
		while (tmp < mp->b_wptr) {
			if (!(tmip->flags & TEL_BINARY_OUT)) {
				*tmp1++ = *tmp;
				if ((tmp == (mp->b_wptr - 1)) &&
				    (tmp[0] == '\r')) {
						tmip->flags |= TEL_CRSND;
						break;
				}
				if ((tmp[0] == '\r') &&
				    (tmp1 == newmp->b_wptr)) {
					/* XXX.sparker: can't happen */
					tmip->flags |= TEL_CRSND;
					break;
				}
				if ((tmp[0] == '\r') && (tmp[1] != '\n')) {
					*tmp1++ = '\0';
				}
			} else
				*tmp1++ = *tmp;

			if (tmp[0] == IAC) {
				*tmp1++ = IAC;
			}
			tmp++;
		}
		mp = mp->b_cont;
	}

	newmp->b_wptr = tmp1;

	putnext(q, newmp);
	freemsg(savemp);
	return (1);
}

static void
telmod_timer(void *arg)
{
	queue_t *q = arg;
	struct	telmod_info	*tmip = (struct telmod_info *)q->q_ptr;

	ASSERT(tmip);

	if (q->q_flag & QREADR) {
		ASSERT(tmip->rtimoutid);
		tmip->rtimoutid = 0;
	} else {
		ASSERT(tmip->wtimoutid);
		tmip->wtimoutid = 0;
	}
	enableok(q);
	qenable(q);
}

static void
telmod_buffer(void *arg)
{
	queue_t *q = arg;
	struct	telmod_info	*tmip = (struct telmod_info *)q->q_ptr;

	ASSERT(tmip);

	if (q->q_flag & QREADR) {
		ASSERT(tmip->rbufcid);
		tmip->rbufcid = 0;
	} else {
		ASSERT(tmip->wbufcid);
		tmip->wbufcid = 0;
	}
	enableok(q);
	qenable(q);
}

static void
recover(queue_t *q, mblk_t *mp, size_t size)
{
	bufcall_id_t bid;
	timeout_id_t tid;
	struct	telmod_info	*tmip = (struct telmod_info *)q->q_ptr;

	ASSERT(mp->b_datap->db_type < QPCTL);
	noenable(q);
	(void) putbq(q, mp);

	/*
	 * Make sure there is at most one outstanding request per queue.
	 */
	if (q->q_flag & QREADR) {
		if (tmip->rtimoutid || tmip->rbufcid) {
			return;
		}
	} else {
		if (tmip->wtimoutid || tmip->wbufcid) {
			return;
		}
	}
	if (!(bid = qbufcall(RD(q), size, BPRI_MED, telmod_buffer, q))) {
		tid = qtimeout(RD(q), telmod_timer, q, SIMWAIT);
		if (q->q_flag & QREADR)
			tmip->rtimoutid = tid;
		else
			tmip->wtimoutid = tid;
	} else	{
		if (q->q_flag & QREADR)
			tmip->rbufcid = bid;
		else
			tmip->wbufcid = bid;
	}
}
