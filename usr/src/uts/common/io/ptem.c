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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Description:
 *
 * The PTEM streams module is used as a pseudo driver emulator.  Its purpose
 * is to emulate the ioctl() functions of a terminal device driver.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/termio.h>
#include <sys/pcb.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/strtty.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/jioctl.h>
#include <sys/ptem.h>
#include <sys/ptms.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>

extern struct streamtab pteminfo;

static struct fmodsw fsw = {
	"ptem",
	&pteminfo,
	D_MTQPAIR | D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "pty hardware emulator", &fsw
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

/*
 * stream data structure definitions
 */
static int ptemopen(queue_t *, dev_t  *, int, int, cred_t *);
static int ptemclose(queue_t *, int, cred_t *);
static void ptemrput(queue_t *, mblk_t *);
static void ptemwput(queue_t *, mblk_t *);
static void ptemwsrv(queue_t *);

static struct module_info ptem_info = {
	0xabcd,
	"ptem",
	0,
	_TTY_BUFSIZ,
	_TTY_BUFSIZ,
	128
};

static struct qinit ptemrinit = {
	(int (*)()) ptemrput,
	NULL,
	ptemopen,
	ptemclose,
	NULL,
	&ptem_info,
	NULL
};

static struct qinit ptemwinit = {
	(int (*)()) ptemwput,
	(int (*)()) ptemwsrv,
	ptemopen,
	ptemclose,
	nulldev,
	&ptem_info,
	NULL
};

struct streamtab pteminfo = {
	&ptemrinit,
	&ptemwinit,
	NULL,
	NULL
};

static void	ptioc(queue_t *, mblk_t *, int);
static int	ptemwmsg(queue_t *, mblk_t *);

/*
 * ptemopen - open routine gets called when the module gets pushed onto the
 * stream.
 */
/* ARGSUSED */
static int
ptemopen(
	queue_t    *q,		/* pointer to the read side queue */
	dev_t   *devp,		/* pointer to stream tail's dev */
	int	oflag,		/* the user open(2) supplied flags */
	int	sflag,		/* open state flag */
	cred_t *credp)		/* credentials */
{
	struct ptem *ntp;	/* ptem entry for this PTEM module */
	mblk_t *mop;		/* an setopts mblk */
	struct stroptions *sop;
	struct termios *termiosp;
	int len;

	if (sflag != MODOPEN)
		return (EINVAL);

	if (q->q_ptr != NULL) {
		/* It's already attached. */
		return (0);
	}

	/*
	 * Allocate state structure.
	 */
	ntp = kmem_alloc(sizeof (*ntp), KM_SLEEP);

	/*
	 * Allocate a message block, used to pass the zero length message for
	 * "stty 0".
	 *
	 * NOTE: it's better to find out if such a message block can be
	 *	 allocated before it's needed than to not be able to
	 *	 deliver (for possible lack of buffers) when a hang-up
	 *	 occurs.
	 */
	if ((ntp->dack_ptr = allocb(4, BPRI_MED)) == NULL) {
		kmem_free(ntp, sizeof (*ntp));
		return (EAGAIN);
	}

	/*
	 * Initialize an M_SETOPTS message to set up hi/lo water marks on
	 * stream head read queue and add controlling tty if not set.
	 */
	mop = allocb(sizeof (struct stroptions), BPRI_MED);
	if (mop == NULL) {
		freemsg(ntp->dack_ptr);
		kmem_free(ntp, sizeof (*ntp));
		return (EAGAIN);
	}
	mop->b_datap->db_type = M_SETOPTS;
	mop->b_wptr += sizeof (struct stroptions);
	sop = (struct stroptions *)mop->b_rptr;
	sop->so_flags = SO_HIWAT | SO_LOWAT | SO_ISTTY;
	sop->so_hiwat = _TTY_BUFSIZ;
	sop->so_lowat = 256;

	/*
	 * Cross-link.
	 */
	ntp->q_ptr = q;
	q->q_ptr = ntp;
	WR(q)->q_ptr = ntp;

	/*
	 * Get termios defaults.  These are stored as
	 * a property in the "options" node.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(), 0, "ttymodes",
	    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
	    len == sizeof (struct termios)) {

		ntp->cflags = termiosp->c_cflag;
		kmem_free(termiosp, len);
	} else {
		/*
		 * Gack!  Whine about it.
		 */
		cmn_err(CE_WARN, "ptem: Couldn't get ttymodes property!");
	}
	ntp->wsz.ws_row = 0;
	ntp->wsz.ws_col = 0;
	ntp->wsz.ws_xpixel = 0;
	ntp->wsz.ws_ypixel = 0;

	ntp->state = 0;

	/*
	 * Commit to the open and send the M_SETOPTS off to the stream head.
	 */
	qprocson(q);
	putnext(q, mop);

	return (0);
}


/*
 * ptemclose - This routine gets called when the module gets popped off of the
 * stream.
 */
/* ARGSUSED */
static int
ptemclose(queue_t *q, int flag, cred_t *credp)
{
	struct ptem *ntp;	/* ptem entry for this PTEM module */

	qprocsoff(q);
	ntp = (struct ptem *)q->q_ptr;
	freemsg(ntp->dack_ptr);
	kmem_free(ntp, sizeof (*ntp));
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}


/*
 * ptemrput - Module read queue put procedure.
 *
 * This is called from the module or driver downstream.
 */
static void
ptemrput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;	/* M_IOCTL data */
	struct copyresp *resp;	/* transparent ioctl response struct */
	int error;

	switch (mp->b_datap->db_type) {
	case M_DELAY:
	case M_READ:
		freemsg(mp);
		break;

	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;

		switch (iocp->ioc_cmd) {
		case TCSBRK:
			/*
			 * Send a break message upstream.
			 *
			 * XXX:	Shouldn't the argument come into play in
			 *	determining whether or not so send an M_BREAK?
			 *	It certainly does in the write-side direction.
			 */
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}
			if (!(*(int *)mp->b_cont->b_rptr)) {
				if (!putnextctl(q, M_BREAK)) {
					/*
					 * Send an NAK reply back
					 */
					miocnak(q, mp, 0, EAGAIN);
					break;
				}
			}
			/*
			 * ACK it.
			 */
			mioc2ack(mp, NULL, 0, 0);
			qreply(q, mp);
			break;

		case JWINSIZE:
		case TIOCGWINSZ:
		case TIOCSWINSZ:
			ptioc(q, mp, RDSIDE);
			break;

		case TIOCSIGNAL:
			/*
			 * The following subtle logic is due to the fact that
			 * `mp' may be in any one of three distinct formats:
			 *
			 *	1. A transparent M_IOCTL with an intptr_t-sized
			 *	   payload containing the signal number.
			 *
			 *	2. An I_STR M_IOCTL with an int-sized payload
			 *	   containing the signal number.
			 *
			 *	3. An M_IOCDATA with an int-sized payload
			 *	   containing the signal number.
			 */
			if (iocp->ioc_count == TRANSPARENT) {
				intptr_t sig = *(intptr_t *)mp->b_cont->b_rptr;

				if (sig < 1 || sig >= NSIG) {
					/*
					 * it's transparent with pointer
					 * to the arg
					 */
					mcopyin(mp, NULL, sizeof (int), NULL);
					qreply(q, mp);
					break;
				}
			}
			ptioc(q, mp, RDSIDE);
			break;

		case TIOCREMOTE:
			if (iocp->ioc_count != TRANSPARENT)
				ptioc(q, mp, RDSIDE);
			else {
				mcopyin(mp, NULL, sizeof (int), NULL);
				qreply(q, mp);
			}
			break;

		default:
			putnext(q, mp);
			break;
		}
		break;

	case M_IOCDATA:
		resp = (struct copyresp *)mp->b_rptr;
		if (resp->cp_rval) {
			/*
			 * Just free message on failure.
			 */
			freemsg(mp);
			break;
		}

		/*
		 * Only need to copy data for the SET case.
		 */
		switch (resp->cp_cmd) {

		case TIOCSWINSZ:
		case TIOCSIGNAL:
		case TIOCREMOTE:
			ptioc(q, mp, RDSIDE);
			break;

		case JWINSIZE:
		case TIOCGWINSZ:
			mp->b_datap->db_type = M_IOCACK;
			mioc2ack(mp, NULL, 0, 0);
			qreply(q, mp);
			break;

		default:
			freemsg(mp);
			break;
	}
	break;

	case M_IOCACK:
	case M_IOCNAK:
		/*
		 * We only pass write-side ioctls through to the master that
		 * we've already ACKed or NAKed to the stream head.  Thus, we
		 * discard ones arriving from below, since they're redundant
		 * from the point of view of modules above us.
		 */
		freemsg(mp);
		break;

	case M_HANGUP:
		/*
		 * clear blocked state.
		 */
		{
			struct ptem *ntp = (struct ptem *)q->q_ptr;
			if (ntp->state & OFLOW_CTL) {
				ntp->state &= ~OFLOW_CTL;
				qenable(WR(q));
			}
		}
		/* FALLTHROUGH */
	default:
		putnext(q, mp);
		break;
	}
}


/*
 * ptemwput - Module write queue put procedure.
 *
 * This is called from the module or stream head upstream.
 *
 * XXX:	This routine is quite lazy about handling allocation failures,
 *	basically just giving up and reporting failure.  It really ought to
 *	set up bufcalls and only fail when it's absolutely necessary.
 */
static void
ptemwput(queue_t *q, mblk_t *mp)
{
	struct ptem *ntp = (struct ptem *)q->q_ptr;
	struct iocblk *iocp;	/* outgoing ioctl structure */
	struct copyresp *resp;
	unsigned char type = mp->b_datap->db_type;

	if (type >= QPCTL) {
		switch (type) {

		case M_IOCDATA:
			resp = (struct copyresp *)mp->b_rptr;
			if (resp->cp_rval) {
				/*
				 * Just free message on failure.
				 */
				freemsg(mp);
				break;
			}

			/*
			 * Only need to copy data for the SET case.
			 */
			switch (resp->cp_cmd) {

				case TIOCSWINSZ:
					ptioc(q, mp, WRSIDE);
					break;

				case JWINSIZE:
				case TIOCGWINSZ:
					mioc2ack(mp, NULL, 0, 0);
					qreply(q, mp);
					break;

				default:
					freemsg(mp);
			}
			break;

		case M_FLUSH:
			if (*mp->b_rptr & FLUSHW) {
				if ((ntp->state & IS_PTSTTY) &&
				    (*mp->b_rptr & FLUSHBAND))
					flushband(q, *(mp->b_rptr + 1),
					    FLUSHDATA);
				else
					flushq(q, FLUSHDATA);
			}
			putnext(q, mp);
			break;

		case M_READ:
			freemsg(mp);
			break;

		case M_STOP:
			/*
			 * Set the output flow control state.
			 */
			ntp->state |= OFLOW_CTL;
			putnext(q, mp);
			break;

		case M_START:
			/*
			 * Relieve the output flow control state.
			 */
			ntp->state &= ~OFLOW_CTL;
			putnext(q, mp);
			qenable(q);
			break;
		default:
			putnext(q, mp);
			break;
		}
		return;
	}
	/*
	 * If our queue is nonempty or flow control persists
	 * downstream or module in stopped state, queue this message.
	 */
	if (q->q_first != NULL || !bcanputnext(q, mp->b_band)) {
		/*
		 * Exception: ioctls, except for those defined to
		 * take effect after output has drained, should be
		 * processed immediately.
		 */
		switch (type) {

		case M_IOCTL:
			iocp = (struct iocblk *)mp->b_rptr;
			switch (iocp->ioc_cmd) {
			/*
			 * Queue these.
			 */
			case TCSETSW:
			case TCSETSF:
			case TCSETAW:
			case TCSETAF:
			case TCSBRK:
				break;

			/*
			 * Handle all others immediately.
			 */
			default:
				(void) ptemwmsg(q, mp);
				return;
			}
			break;

		case M_DELAY: /* tty delays not supported */
			freemsg(mp);
			return;

		case M_DATA:
			if ((mp->b_wptr - mp->b_rptr) < 0) {
				/*
				 * Free all bad length messages.
				 */
				freemsg(mp);
				return;
			} else if ((mp->b_wptr - mp->b_rptr) == 0) {
				if (!(ntp->state & IS_PTSTTY)) {
					freemsg(mp);
					return;
				}
			}
		}
		(void) putq(q, mp);
		return;
	}
	/*
	 * fast path into ptemwmsg to dispose of mp.
	 */
	if (!ptemwmsg(q, mp))
		(void) putq(q, mp);
}

/*
 * ptem write queue service procedure.
 */
static void
ptemwsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL) {
		if (!bcanputnext(q, mp->b_band) || !ptemwmsg(q, mp)) {
			(void) putbq(q, mp);
			break;
		}
	}
}


/*
 * This routine is called from both ptemwput and ptemwsrv to do the
 * actual work of dealing with mp.  ptmewput will have already
 * dealt with high priority messages.
 *
 * Return 1 if the message was processed completely and 0 if not.
 */
static int
ptemwmsg(queue_t *q, mblk_t *mp)
{
	struct ptem *ntp = (struct ptem *)q->q_ptr;
	struct iocblk *iocp;	/* outgoing ioctl structure */
	struct termio *termiop;
	struct termios *termiosp;
	mblk_t *dack_ptr;		/* disconnect message ACK block */
	mblk_t *pckt_msgp;		/* message sent to the PCKT module */
	mblk_t *dp;			/* ioctl reply data */
	tcflag_t cflags;
	int error;

	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		/*
		 * Note:  for each "set" type operation a copy
		 * of the M_IOCTL message is made and passed
		 * downstream.  Eventually the PCKT module, if
		 * it has been pushed, should pick up this message.
		 * If the PCKT module has not been pushed the master
		 * side stream head will free it.
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {

		case TCSETAF:
		case TCSETSF:
			/*
			 * Flush the read queue.
			 */
			if (putnextctl1(q, M_FLUSH, FLUSHR) == 0) {
				miocnak(q, mp, 0, EAGAIN);
				break;
			}
			/* FALLTHROUGH */

		case TCSETA:
		case TCSETAW:
		case TCSETS:
		case TCSETSW:

			switch (iocp->ioc_cmd) {
			case TCSETAF:
			case TCSETA:
			case TCSETAW:
				error = miocpullup(mp, sizeof (struct termio));
				if (error != 0) {
					miocnak(q, mp, 0, error);
					goto out;
				}
				cflags = ((struct termio *)
				    mp->b_cont->b_rptr)->c_cflag;
				ntp->cflags =
				    (ntp->cflags & 0xffff0000 | cflags);
				break;

			case TCSETSF:
			case TCSETS:
			case TCSETSW:
				error = miocpullup(mp, sizeof (struct termios));
				if (error != 0) {
					miocnak(q, mp, 0, error);
					goto out;
				}
				cflags = ((struct termios *)
				    mp->b_cont->b_rptr)->c_cflag;
				ntp->cflags = cflags;
				break;
			}

			if ((cflags & CBAUD) == B0) {
				/*
				 * Hang-up: Send a zero length message.
				 */
				dack_ptr = ntp->dack_ptr;

				if (dack_ptr) {
					ntp->dack_ptr = NULL;
					/*
					 * Send a zero length message
					 * downstream.
					 */
					putnext(q, dack_ptr);
				}
			} else {
				/*
				 * Make a copy of this message and pass it on
				 * to the PCKT module.
				 */
				if ((pckt_msgp = copymsg(mp)) == NULL) {
					miocnak(q, mp, 0, EAGAIN);
					break;
				}
				putnext(q, pckt_msgp);
			}
			/*
			 * Send ACK upstream.
			 */
			mioc2ack(mp, NULL, 0, 0);
			qreply(q, mp);
out:
			break;

		case TCGETA:
			dp = allocb(sizeof (struct termio), BPRI_MED);
			if (dp == NULL) {
				miocnak(q, mp, 0, EAGAIN);
				break;
			}
			termiop = (struct termio *)dp->b_rptr;
			termiop->c_cflag = (ushort_t)ntp->cflags;
			mioc2ack(mp, dp, sizeof (struct termio), 0);
			qreply(q, mp);
			break;

		case TCGETS:
			dp = allocb(sizeof (struct termios), BPRI_MED);
			if (dp == NULL) {
				miocnak(q, mp, 0, EAGAIN);
				break;
			}
			termiosp = (struct termios *)dp->b_rptr;
			termiosp->c_cflag = ntp->cflags;
			mioc2ack(mp, dp, sizeof (struct termios), 0);
			qreply(q, mp);
			break;

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				break;
			}

			/*
			 * Need a copy of this message to pass it on to
			 * the PCKT module.
			 */
			if ((pckt_msgp = copymsg(mp)) == NULL) {
				miocnak(q, mp, 0, EAGAIN);
				break;
			}
			/*
			 * Send a copy of the M_IOCTL to the PCKT module.
			 */
			putnext(q, pckt_msgp);

			/*
			 * TCSBRK meaningful if data part of message is 0
			 * cf. termio(7).
			 */
			if (!(*(int *)mp->b_cont->b_rptr))
				(void) putnextctl(q, M_BREAK);
			/*
			 * ACK the ioctl.
			 */
			mioc2ack(mp, NULL, 0, 0);
			qreply(q, mp);
			break;

		case JWINSIZE:
		case TIOCGWINSZ:
		case TIOCSWINSZ:
			ptioc(q, mp, WRSIDE);
			break;

		case TIOCSTI:
			/*
			 * Simulate typing of a character at the terminal.  In
			 * all cases, we acknowledge the ioctl and pass a copy
			 * of it along for the PCKT module to encapsulate.  If
			 * not in remote mode, we also process the ioctl
			 * itself, looping the character given as its argument
			 * back around to the read side.
			 */

			/*
			 * Need a copy of this message to pass on to the PCKT
			 * module.
			 */
			if ((pckt_msgp = copymsg(mp)) == NULL) {
				miocnak(q, mp, 0, EAGAIN);
				break;
			}
			if ((ntp->state & REMOTEMODE) == 0) {
				mblk_t *bp;

				error = miocpullup(mp, sizeof (char));
				if (error != 0) {
					freemsg(pckt_msgp);
					miocnak(q, mp, 0, error);
					break;
				}

				/*
				 * The permission checking has already been
				 * done at the stream head, since it has to be
				 * done in the context of the process doing
				 * the call.
				 */
				if ((bp = allocb(1, BPRI_MED)) == NULL) {
					freemsg(pckt_msgp);
					miocnak(q, mp, 0, EAGAIN);
					break;
				}
				/*
				 * XXX:	Is EAGAIN really the right response to
				 *	flow control blockage?
				 */
				if (!bcanputnext(RD(q), mp->b_band)) {
					freemsg(bp);
					freemsg(pckt_msgp);
					miocnak(q, mp, 0, EAGAIN);
					break;
				}
				*bp->b_wptr++ = *mp->b_cont->b_rptr;
				qreply(q, bp);
			}

			putnext(q, pckt_msgp);
			mioc2ack(mp, NULL, 0, 0);
			qreply(q, mp);
			break;

		case PTSSTTY:
			if (ntp->state & IS_PTSTTY) {
				miocnak(q, mp, 0, EEXIST);
			} else {
				ntp->state |= IS_PTSTTY;
				mioc2ack(mp, NULL, 0, 0);
				qreply(q, mp);
			}
			break;

		default:
			/*
			 * End of the line.  The slave driver doesn't see any
			 * ioctls that we don't explicitly pass along to it.
			 */
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		break;

	case M_DELAY: /* tty delays not supported */
		freemsg(mp);
		break;

	case M_DATA:
		if ((mp->b_wptr - mp->b_rptr) < 0) {
			/*
			 * Free all bad length messages.
			 */
			freemsg(mp);
			break;
		} else if ((mp->b_wptr - mp->b_rptr) == 0) {
			if (!(ntp->state & IS_PTSTTY)) {
				freemsg(mp);
				break;
			}
		}
		if (ntp->state & OFLOW_CTL)
			return (0);
		/* FALLTHROUGH */

	default:
		putnext(q, mp);
		break;

	}

	return (1);
}

/*
 * Message must be of type M_IOCTL or M_IOCDATA for this routine to be called.
 */
static void
ptioc(queue_t *q, mblk_t *mp, int qside)
{
	struct ptem *tp;
	struct iocblk *iocp;
	struct winsize *wb;
	struct jwinsize *jwb;
	mblk_t *tmp;
	mblk_t *pckt_msgp;	/* message sent to the PCKT module */
	int error;

	iocp = (struct iocblk *)mp->b_rptr;
	tp = (struct ptem *)q->q_ptr;

	switch (iocp->ioc_cmd) {

	case JWINSIZE:
		/*
		 * For compatibility:  If all zeros, NAK the message for dumb
		 * terminals.
		 */
		if ((tp->wsz.ws_row == 0) && (tp->wsz.ws_col == 0) &&
		    (tp->wsz.ws_xpixel == 0) && (tp->wsz.ws_ypixel == 0)) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		tmp = allocb(sizeof (struct jwinsize), BPRI_MED);
		if (tmp == NULL) {
			miocnak(q, mp, 0, EAGAIN);
			return;
		}

		if (iocp->ioc_count == TRANSPARENT)
			mcopyout(mp, NULL, sizeof (struct jwinsize), NULL, tmp);
		else
			mioc2ack(mp, tmp, sizeof (struct jwinsize), 0);

		jwb = (struct jwinsize *)mp->b_cont->b_rptr;
		jwb->bytesx = tp->wsz.ws_col;
		jwb->bytesy = tp->wsz.ws_row;
		jwb->bitsx = tp->wsz.ws_xpixel;
		jwb->bitsy = tp->wsz.ws_ypixel;

		qreply(q, mp);
		return;

	case TIOCGWINSZ:
		/*
		 * If all zeros NAK the message for dumb terminals.
		 */
		if ((tp->wsz.ws_row == 0) && (tp->wsz.ws_col == 0) &&
		    (tp->wsz.ws_xpixel == 0) && (tp->wsz.ws_ypixel == 0)) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		tmp = allocb(sizeof (struct winsize), BPRI_MED);
		if (tmp == NULL) {
			miocnak(q, mp, 0, EAGAIN);
			return;
		}

		mioc2ack(mp, tmp, sizeof (struct winsize), 0);

		wb = (struct winsize *)mp->b_cont->b_rptr;
		wb->ws_row = tp->wsz.ws_row;
		wb->ws_col = tp->wsz.ws_col;
		wb->ws_xpixel = tp->wsz.ws_xpixel;
		wb->ws_ypixel = tp->wsz.ws_ypixel;

		qreply(q, mp);
		return;

	case TIOCSWINSZ:
		error = miocpullup(mp, sizeof (struct winsize));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		wb = (struct winsize *)mp->b_cont->b_rptr;
		/*
		 * Send a SIGWINCH signal if the row/col information has
		 * changed.
		 */
		if ((tp->wsz.ws_row != wb->ws_row) ||
		    (tp->wsz.ws_col != wb->ws_col) ||
		    (tp->wsz.ws_xpixel != wb->ws_xpixel) ||
		    (tp->wsz.ws_ypixel != wb->ws_xpixel)) {
			/*
			 * SIGWINCH is always sent upstream.
			 */
			if (qside == WRSIDE)
				(void) putnextctl1(RD(q), M_SIG, SIGWINCH);
			else if (qside == RDSIDE)
				(void) putnextctl1(q, M_SIG, SIGWINCH);
			/*
			 * Message may have come in as an M_IOCDATA; pass it
			 * to the master side as an M_IOCTL.
			 */
			mp->b_datap->db_type = M_IOCTL;
			if (qside == WRSIDE) {
				/*
				 * Need a copy of this message to pass on to
				 * the PCKT module, only if the M_IOCTL
				 * orginated from the slave side.
				 */
				if ((pckt_msgp = copymsg(mp)) == NULL) {
					miocnak(q, mp, 0, EAGAIN);
					return;
				}
				putnext(q, pckt_msgp);
			}
			tp->wsz.ws_row = wb->ws_row;
			tp->wsz.ws_col = wb->ws_col;
			tp->wsz.ws_xpixel = wb->ws_xpixel;
			tp->wsz.ws_ypixel = wb->ws_ypixel;
		}

		mioc2ack(mp, NULL, 0, 0);
		qreply(q, mp);
		return;

	case TIOCSIGNAL: {
		/*
		 * This ioctl can emanate from the master side in remote
		 * mode only.
		 */
		int	sig;

		if (DB_TYPE(mp) == M_IOCTL && iocp->ioc_count != TRANSPARENT) {
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}
		}

		if (DB_TYPE(mp) == M_IOCDATA || iocp->ioc_count != TRANSPARENT)
			sig = *(int *)mp->b_cont->b_rptr;
		else
			sig = (int)*(intptr_t *)mp->b_cont->b_rptr;

		if (sig < 1 || sig >= NSIG) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		/*
		 * Send an M_PCSIG message up the slave's read side and
		 * respond back to the master with an ACK or NAK as
		 * appropriate.
		 */
		if (putnextctl1(q, M_PCSIG, sig) == 0) {
			miocnak(q, mp, 0, EAGAIN);
			return;
		}

		mioc2ack(mp, NULL, 0, 0);
		qreply(q, mp);
		return;
	}

	case TIOCREMOTE: {
		int	onoff;
		mblk_t	*mctlp;

		if (DB_TYPE(mp) == M_IOCTL) {
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}
		}

		onoff = *(int *)mp->b_cont->b_rptr;

		/*
		 * Send M_CTL up using the iocblk format.
		 */
		mctlp = mkiocb(onoff ? MC_NO_CANON : MC_DO_CANON);
		if (mctlp == NULL) {
			miocnak(q, mp, 0, EAGAIN);
			return;
		}
		mctlp->b_datap->db_type = M_CTL;
		putnext(q, mctlp);

		/*
		 * ACK the ioctl.
		 */
		mioc2ack(mp, NULL, 0, 0);
		qreply(q, mp);

		/*
		 * Record state change.
		 */
		if (onoff)
			tp->state |= REMOTEMODE;
		else
			tp->state &= ~REMOTEMODE;
		return;
	}

	default:
		putnext(q, mp);
		return;
	}
}
