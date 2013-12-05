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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Module to intercept old V7 and 4BSD "ioctl" calls.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/termios.h>
#include <sys/ttold.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/ttcompat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/policy.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/conf.h>
#include <sys/modctl.h>

/* See os/streamio.c */
extern int sgttyb_handling;

static struct streamtab ttcoinfo;

static struct fmodsw fsw = {
	"ttcompat",
	&ttcoinfo,
	D_MTQPAIR | D_MP
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"alt ioctl calls",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlstrmod, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int ttcompatopen(queue_t *, dev_t *, int, int, cred_t *);
static int ttcompatclose(queue_t *, int, cred_t *);
static void ttcompatrput(queue_t *, mblk_t *);
static void ttcompatwput(queue_t *, mblk_t *);

static struct module_info ttycompatmiinfo = {
	0,
	"ttcompat",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit ttycompatrinit = {
	(int (*)())ttcompatrput,
	NULL,
	ttcompatopen,
	ttcompatclose,
	NULL,
	&ttycompatmiinfo
};

static struct module_info ttycompatmoinfo = {
	42,
	"ttcompat",
	0,
	INFPSZ,
	300,
	200
};

static struct qinit ttycompatwinit = {
	(int (*)())ttcompatwput,
	NULL,
	ttcompatopen,
	ttcompatclose,
	NULL,
	&ttycompatmoinfo
};

static struct streamtab ttcoinfo = {
	&ttycompatrinit,
	&ttycompatwinit,
	NULL,
	NULL
};

/*
 * This is the termios structure that is used to reset terminal settings
 * when the underlying device is an instance of zcons.  It came from
 * cmd/init/init.c and should be kept in-sync with dflt_termios found therein.
 */
static const struct termios base_termios = {
	BRKINT|ICRNL|IXON|IMAXBEL,				/* iflag */
	OPOST|ONLCR|TAB3,					/* oflag */
	CS8|CREAD|B9600,					/* cflag */
	ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN,	/* lflag */
	CINTR, CQUIT, CERASE, CKILL, CEOF, 0, 0, 0, 0, 0, 0, 0,	/* c_cc vals */
	0, 0, 0, 0, 0, 0, 0
};


static void ttcompat_do_ioctl(ttcompat_state_t *, queue_t *, mblk_t *);
static void ttcompat_ioctl_ack(queue_t *, mblk_t *);
static void ttcopyout(queue_t *, mblk_t *);
static void ttcompat_ioctl_nak(queue_t *, mblk_t *);
static void from_compat(compat_state_t *, struct termios *);
static void to_compat(struct termios *, compat_state_t *);

/*
 * Open - get the current modes and translate them to the V7/4BSD equivalent.
 */
/*ARGSUSED*/
static int
ttcompatopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	ttcompat_state_t *tp;
	mblk_t *mp;
	mblk_t *datamp;
	struct iocblk *iocb;
	int error;

	if (q->q_ptr != NULL)  {
		tp = (ttcompat_state_t *)q->q_ptr;
		/* fail open if TIOCEXCL was done and its not privileged */
		if ((tp->t_new_lflags & XCLUDE) &&
		    secpolicy_excl_open(crp) != 0) {
			return (EBUSY);
		}
		return (0);		/* already attached */
	}
	tp = kmem_zalloc(sizeof (ttcompat_state_t), KM_SLEEP);
	tp->t_iocpending = NULL;
	tp->t_state = 0;
	tp->t_iocid = 0;
	tp->t_ioccmd = 0;
	tp->t_new_lflags = 0;
	tp->t_curstate.t_flags = 0;
	tp->t_curstate.t_ispeed = B0;
	tp->t_curstate.t_ospeed = B0;
	tp->t_curstate.t_erase = '\0';
	tp->t_curstate.t_kill = '\0';
	tp->t_curstate.t_intrc = '\0';
	tp->t_curstate.t_quitc = '\0';
	tp->t_curstate.t_startc = '\0';
	tp->t_curstate.t_stopc = '\0';
	tp->t_curstate.t_eofc = '\0';
	tp->t_curstate.t_brkc = '\0';
	tp->t_curstate.t_suspc = '\0';
	tp->t_curstate.t_dsuspc = '\0';
	tp->t_curstate.t_rprntc = '\0';
	tp->t_curstate.t_flushc = '\0';
	tp->t_curstate.t_werasc = '\0';
	tp->t_curstate.t_lnextc = '\0';
	tp->t_curstate.t_xflags = 0;
	tp->t_bufcallid = 0;
	tp->t_arg = 0;

	q->q_ptr = tp;
	WR(q)->q_ptr = tp;
	qprocson(q);

	/*
	 * Determine if the underlying device is a zcons instance.  If so,
	 * then issue a termios ioctl to reset the terminal settings.
	 */
	if (getmajor(q->q_stream->sd_vnode->v_rdev) !=
	    ddi_name_to_major("zcons"))
		return (0);

	/*
	 * Create the ioctl message.
	 */
	if ((mp = mkiocb(TCSETSF)) == NULL) {
		error = ENOMEM;
		goto common_error;
	}
	if ((datamp = allocb(sizeof (struct termios), BPRI_HI)) == NULL) {
		freemsg(mp);
		error = ENOMEM;
		goto common_error;
	}
	iocb = (struct iocblk *)mp->b_rptr;
	iocb->ioc_count = sizeof (struct termios);
	bcopy(&base_termios, datamp->b_rptr, sizeof (struct termios));
	datamp->b_wptr += sizeof (struct termios);
	mp->b_cont = datamp;

	/*
	 * Send the ioctl message on its merry way toward the driver.
	 * Set some state beforehand so we can properly wait for
	 * an acknowledgement.
	 */
	tp->t_state |= TS_IOCWAIT | TS_TIOCNAK;
	tp->t_iocid = iocb->ioc_id;
	tp->t_ioccmd = TCSETSF;
	putnext(WR(q), mp);

	/*
	 * Wait for an acknowledgement.  A NAK is treated as an error.
	 * The presence of the TS_TIOCNAK flag indicates that a NAK was
	 * received.
	 */
	while (tp->t_state & TS_IOCWAIT) {
		if (qwait_sig(q) == 0) {
			error = EINTR;
			goto common_error;
		}
	}
	if (!(tp->t_state & TS_TIOCNAK))
		return (0);
	error = ENOTTY;

common_error:
	qprocsoff(q);
	kmem_free(tp, sizeof (ttcompat_state_t));
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (error);
}

/* ARGSUSED1 */
static int
ttcompatclose(queue_t *q, int flag, cred_t *crp)
{
	ttcompat_state_t *tp = (ttcompat_state_t *)q->q_ptr;
	mblk_t *mp;

	/* Dump the state structure, then unlink it */
	qprocsoff(q);
	if (tp->t_bufcallid != 0) {
		qunbufcall(q, tp->t_bufcallid);
		tp->t_bufcallid = 0;
	}
	if ((mp = tp->t_iocpending) != NULL)
		freemsg(mp);
	kmem_free(tp, sizeof (ttcompat_state_t));
	q->q_ptr = NULL;

	return (0);
}

/*
 * Put procedure for input from driver end of stream (read queue).
 * Most messages just get passed to the next guy up; we intercept
 * "ioctl" replies, and if it's an "ioctl" whose reply we plan to do
 * something with, we do it.
 */
static void
ttcompatrput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {

	case M_IOCACK:
		ttcompat_ioctl_ack(q, mp);
		break;

	case M_IOCNAK:
		ttcompat_ioctl_nak(q, mp);
		break;

	default:
		putnext(q, mp);
		break;
	}
}

/*
 * Line discipline output queue put procedure: speeds M_IOCTL
 * messages.
 */
static void
ttcompatwput(queue_t *q, mblk_t *mp)
{
	ttcompat_state_t *tp;
	struct copyreq *cqp;
	struct copyresp *csp;
	struct iocblk *iocbp;

	tp = (ttcompat_state_t *)q->q_ptr;

	/*
	 * Process some M_IOCTL messages here; pass everything else down.
	 */
	switch (mp->b_datap->db_type) {

	default:
		putnext(q, mp);
		return;

	case M_IOCTL:
		iocbp = (struct iocblk *)mp->b_rptr;

		switch (iocbp->ioc_cmd) {

		default:
	/* these are ioctls with no arguments or are known to stream head */
	/* process them right away */
			ttcompat_do_ioctl(tp, q, mp);
			return;
		case TIOCSETN:
		case TIOCSLTC:
		case TIOCSETC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
		case TIOCFLUSH:
			if (iocbp->ioc_count != TRANSPARENT) {
				putnext(q, mp);
				return;
			}

			mp->b_datap->db_type = M_COPYIN;
			cqp = (struct copyreq *)mp->b_rptr;
			cqp->cq_addr = (caddr_t)*(intptr_t *)mp->b_cont->b_rptr;
			switch (iocbp->ioc_cmd) {
				case TIOCSETN:
					cqp->cq_size = sizeof (struct sgttyb);
					break;
				case TIOCSLTC:
					cqp->cq_size = sizeof (struct ltchars);
					break;
				case TIOCSETC:
					cqp->cq_size = sizeof (struct tchars);
					break;
				case TIOCLBIS:
				case TIOCLBIC:
				case TIOCLSET:
				case TIOCFLUSH:
					cqp->cq_size = sizeof (int);
					break;
				default:
					break;
			}
			cqp->cq_flag = 0;
			cqp->cq_private = NULL;
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
			mp->b_wptr = mp->b_rptr + sizeof (struct copyreq);
			tp->t_ioccmd = iocbp->ioc_cmd;
			tp->t_state |= TS_W_IN;
			qreply(q, mp);
			return;

		} /* switch ioc_cmd */
	case M_IOCDATA:
		csp = (struct copyresp *)mp->b_rptr;

		switch (csp->cp_cmd) {

		default:
			putnext(q, mp);
			return;

		case TIOCSETN:
		case TIOCSLTC:
		case TIOCSETC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
		case TIOCFLUSH:
			tp->t_state &= ~TS_W_IN;
			if (csp->cp_rval != 0) {	/* failure */
				freemsg(mp);
				return;
			}

			/* make it look like an ioctl */
			mp->b_datap->db_type = M_IOCTL;
			mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
			iocbp = (struct iocblk *)mp->b_rptr;
			iocbp->ioc_count = MBLKL(mp->b_cont);
			iocbp->ioc_error = 0;
			iocbp->ioc_rval = 0;
			ttcompat_do_ioctl(tp, q, mp);
			return;

		case TIOCGLTC:
		case TIOCLGET:
		case TIOCGETC:
			tp->t_state &= ~TS_W_OUT;
			if (csp->cp_rval != 0) {	/* failure */
				freemsg(mp);
				return;
			}

			iocbp = (struct iocblk *)mp->b_rptr;
			iocbp->ioc_count = 0;
			iocbp->ioc_error = 0;
			iocbp->ioc_rval = 0;
			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;

		} /* switch cp_cmd */
	} /* end message switch */
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
ttcompat_reioctl(void *arg)
{
	queue_t *q = arg;
	ttcompat_state_t *tp;
	mblk_t *mp;

	tp = (ttcompat_state_t *)q->q_ptr;
	tp->t_bufcallid = 0;

	if ((mp = tp->t_iocpending) != NULL) {
		tp->t_iocpending = NULL;	/* not pending any more */
		ttcompat_do_ioctl(tp, q, mp);
	}
}

/*
 * Handle old-style "ioctl" messages; pass the rest down unmolested.
 */
static void
ttcompat_do_ioctl(ttcompat_state_t *tp, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	int error;

	/*
	 * Most of the miocpullup()'s below aren't needed because the
	 * ioctls in question are actually transparent M_IOCDATA messages
	 * dummied to look like M_IOCTL messages.  However, for clarity and
	 * robustness against future changes, we've included them anyway.
	 */

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {

	/*
	 * "get"-style calls that get translated data from the "termios"
	 * structure.  Save the existing code and pass it down as a TCGETS.
	 */
	case TIOCGETC:
	case TIOCLGET:
	case TIOCGLTC:
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			return;
		}

		/*
		 * We can get here with t_arg != 0, iff the stream head
		 * has for some reason given up on the ioctl in progress.
		 * The most likely cause is an interrupted ioctl syscall.
		 * We will behave robustly because (given our perimeter)
		 * the ttcompat_state_t will get set up for the new ioctl,
		 * and when the response we were waiting for appears it
		 * will be passed on to the stream head which will discard
		 * it as non-current.
		 */
		ASSERT(mp->b_cont != NULL);
		tp->t_arg = *(intptr_t *)mp->b_cont->b_rptr;
		/* free the data buffer - it might not be sufficient */
		/* driver will allocate one for termios size */
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		iocp->ioc_count = 0;
		/* FALLTHRU */
	case TIOCGETP:
		goto dogets;

	/*
	 * "set"-style calls that set translated data into a "termios"
	 * structure.  Set our idea of the new state from the value
	 * given to us.  We then have to get the current state, so we
	 * turn this guy into a TCGETS and pass it down.  When the
	 * ACK comes back, we modify the state we got back and shove it
	 * back down as the appropriate type of TCSETS.
	 */
	case TIOCSETP:
	case TIOCSETN:
		error = miocpullup(mp, sizeof (struct sgttyb));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		tp->t_new_sgttyb = *((struct sgttyb *)mp->b_cont->b_rptr);
		goto dogets;

	case TIOCSETC:
		error = miocpullup(mp, sizeof (struct tchars));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		tp->t_new_tchars = *((struct tchars *)mp->b_cont->b_rptr);
		goto dogets;

	case TIOCSLTC:
		error = miocpullup(mp, sizeof (struct ltchars));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		tp->t_new_ltchars = *((struct ltchars *)mp->b_cont->b_rptr);
		goto dogets;

	case TIOCLBIS:
	case TIOCLBIC:
	case TIOCLSET:
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		tp->t_new_lflags = *(int *)mp->b_cont->b_rptr;
		goto dogets;

	/*
	 * "set"-style call that sets a particular bit in a "termios"
	 * structure.  We then have to get the current state, so we
	 * turn this guy into a TCGETS and pass it down.  When the
	 * ACK comes back, we modify the state we got back and shove it
	 * back down as the appropriate type of TCSETS.
	 */
	case TIOCHPCL:
	dogets:
		tp->t_ioccmd = iocp->ioc_cmd;
		tp->t_iocid = iocp->ioc_id;
		tp->t_state |= TS_IOCWAIT;
		iocp->ioc_cmd = TCGETS;
		iocp->ioc_count = 0;	/* no data returned unless we say so */
		break;

	/*
	 * "set"-style call that sets DTR.  Pretend that it was a TIOCMBIS
	 * with TIOCM_DTR set.
	 */
	case TIOCSDTR: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)
			goto allocfailure;
		*(int *)datap->b_wptr = TIOCM_DTR;
		datap->b_wptr += sizeof (int);
		iocp->ioc_cmd = TIOCMBIS;	/* turn it into a TIOCMBIS */
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;	/* attach the data */
		iocp->ioc_count = sizeof (int);	/* in case driver checks */
		break;
	}

	/*
	 * "set"-style call that clears DTR.  Pretend that it was a TIOCMBIC
	 * with TIOCM_DTR set.
	 */
	case TIOCCDTR: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)
			goto allocfailure;
		*(int *)datap->b_wptr = TIOCM_DTR;
		datap->b_wptr += sizeof (int);
		iocp->ioc_cmd = TIOCMBIC;	/* turn it into a TIOCMBIC */
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;	/* attach the data */
		iocp->ioc_count = sizeof (int);	/* in case driver checks */
		break;
	}

	/*
	 * Translate into the S5 form of TCFLSH.
	 */
	case TIOCFLUSH: {
		int flags;

		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}
		flags = *(int *)mp->b_cont->b_rptr;

		switch (flags&(FREAD|FWRITE)) {

		case 0:
		case FREAD|FWRITE:
			flags = 2;	/* flush 'em both */
			break;

		case FREAD:
			flags = 0;	/* flush read */
			break;

		case FWRITE:
			flags = 1;	/* flush write */
			break;
		}
		iocp->ioc_cmd = TCFLSH;	/* turn it into a TCFLSH */
		*(int *)mp->b_cont->b_rptr = flags;	/* fiddle the arg */
		break;
	}

	/*
	 * Turn into a TCXONC.
	 */
	case TIOCSTOP: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)
			goto allocfailure;
		*(int *)datap->b_wptr = 0;	/* stop */
		datap->b_wptr += sizeof (int);
		iocp->ioc_cmd = TCXONC;	/* turn it into a XONC */
		iocp->ioc_count = sizeof (int);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;	/* attach the data */
		break;
	}

	case TIOCSTART: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL)
			goto allocfailure;
		*(int *)datap->b_wptr = 1;	/* start */
		datap->b_wptr += sizeof (int);
		iocp->ioc_cmd = TCXONC;	/* turn it into a XONC */
		iocp->ioc_count = sizeof (int);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;	/* attach the data */
		break;
	}
	case TIOCSETD:
	case TIOCGETD:
	case DIOCSETP:
	case DIOCGETP:
	case LDOPEN:
	case LDCLOSE:
	case LDCHG:
	case LDSETT:
	case LDGETT:
		/*
		 * All of these ioctls are just ACK'd, except for
		 * TIOCSETD, which must be for line discipline zero.
		 */
		mp->b_datap->db_type = M_IOCACK;
		if (iocp->ioc_cmd == TIOCSETD) {
			iocp->ioc_error = miocpullup(mp, sizeof (uchar_t));
			if (iocp->ioc_error == 0 && (*mp->b_cont->b_rptr != 0))
				mp->b_datap->db_type = M_IOCNAK;
		}

		iocp->ioc_error = 0;
		iocp->ioc_count = 0;
		iocp->ioc_rval = 0;
		qreply(q, mp);
		return;
	case IOCTYPE:
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_count = 0;
		iocp->ioc_rval = TIOC;
		qreply(q, mp);
		return;
	case TIOCEXCL:
		/* check for binary value of XCLUDE flag ???? */
		tp->t_new_lflags |= XCLUDE;
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_count = 0;
		iocp->ioc_rval = 0;
		qreply(q, mp);
		return;
	case TIOCNXCL:
		tp->t_new_lflags &= ~XCLUDE;
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_count = 0;
		iocp->ioc_rval = 0;
		qreply(q, mp);
		return;
	}

	/*
	 * We don't reply to most calls, we just pass them down,
	 * possibly after modifying the arguments.
	 */
	putnext(q, mp);
	return;

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	if (tp->t_iocpending != NULL)
		freemsg(tp->t_iocpending);
	tp->t_iocpending = mp;	/* hold this ioctl */
	if (tp->t_bufcallid != 0)
		qunbufcall(q, tp->t_bufcallid);

	tp->t_bufcallid = qbufcall(q, sizeof (struct iocblk), BPRI_HI,
	    ttcompat_reioctl, q);
}

/*
 * Called when an M_IOCACK message is seen on the read queue; if this
 * is the response we were waiting for, we either:
 *    modify the data going up (if the "ioctl" read data); since in all
 *    cases, the old-style returned information is smaller than or the same
 *    size as the new-style returned information, we just overwrite the old
 *    stuff with the new stuff (beware of changing structure sizes, in case
 *    you invalidate this)
 * or
 *    take this data, modify it appropriately, and send it back down (if
 *    the "ioctl" wrote data).
 * In either case, we cancel the "wait"; the final response to a "write"
 * ioctl goes back up to the user.
 * If this wasn't the response we were waiting for, just pass it up.
 */
static void
ttcompat_ioctl_ack(queue_t *q, 	mblk_t *mp)
{
	ttcompat_state_t *tp;
	struct iocblk *iocp;
	mblk_t *datap;

	tp = (ttcompat_state_t *)q->q_ptr;
	iocp = (struct iocblk *)mp->b_rptr;

	if (!(tp->t_state&TS_IOCWAIT) || iocp->ioc_id != tp->t_iocid) {
		/*
		 * This isn't the reply we're looking for.  Move along.
		 */
		putnext(q, mp);
		return;
	}

	datap = mp->b_cont;	/* mblk containing data going up */

	switch (tp->t_ioccmd) {

	case TIOCGETP: {
		struct sgttyb *cb;

		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		datap->b_rptr = datap->b_wptr = datap->b_datap->db_base;
			/* recycle the reply's buffer */
		cb = (struct sgttyb *)datap->b_wptr;
		/*
		 * This is used for TIOCGETP handling of sg_ispeed and
		 * sg_ospeed.  If the current speed is over 38400 (the
		 * sgttyb limit), then we report 38400.  Note that
		 * when "compatibility with old releases" is enabled
		 * (sgttyb_handling == 0), then t_[io]speed will have
		 * garbled nonsense, as in prior releases.  (See
		 * to_compat() below).
		 */
		cb->sg_ispeed = tp->t_curstate.t_ispeed > B38400 ? B38400 :
		    tp->t_curstate.t_ispeed;
		cb->sg_ospeed = tp->t_curstate.t_ospeed > B38400 ? B38400 :
		    tp->t_curstate.t_ospeed;
		cb->sg_erase = tp->t_curstate.t_erase;
		cb->sg_kill = tp->t_curstate.t_kill;
		cb->sg_flags = tp->t_curstate.t_flags;
		datap->b_wptr += sizeof (struct sgttyb);
		iocp->ioc_count = sizeof (struct sgttyb);

		/* you are lucky - stream head knows how to copy you out */

		tp->t_state &= ~TS_IOCWAIT;	/* we got what we wanted */
		iocp->ioc_rval = 0;
		iocp->ioc_cmd =  tp->t_ioccmd;
		putnext(q, mp);
		return;
	}

	case TIOCGETC:
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		datap->b_rptr = datap->b_wptr = datap->b_datap->db_base;
			/* recycle the reply's buffer */
		bcopy(&tp->t_curstate.t_intrc, datap->b_wptr,
		    sizeof (struct tchars));
		datap->b_wptr += sizeof (struct tchars);
		break;

	case TIOCGLTC:
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		datap->b_rptr = datap->b_wptr = datap->b_datap->db_base;
			/* recycle the reply's buffer */
		bcopy(&tp->t_curstate.t_suspc, datap->b_wptr,
		    sizeof (struct ltchars));
		datap->b_wptr += sizeof (struct ltchars);
		break;

	case TIOCLGET:
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		datap->b_rptr = datap->b_wptr = datap->b_datap->db_base;
			/* recycle the reply's buffer */
		*(int *)datap->b_wptr =
		    ((unsigned)tp->t_curstate.t_flags) >> 16;
		datap->b_wptr += sizeof (int);
		break;

	case TIOCSETP:
	case TIOCSETN:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		tp->t_curstate.t_erase = tp->t_new_sgttyb.sg_erase;
		tp->t_curstate.t_kill = tp->t_new_sgttyb.sg_kill;
		/*
		 * For new-style handling, we ignore requests to set
		 * B38400 when the current speed is over B38400.  This
		 * means that we change the speed as requested if:
		 *	old style (sgttyb_handling == 0) is requested
		 *	the requested new speed isn't B38400
		 *	the current speed is at or below B38400
		 * Note that when old style is requested, both speeds
		 * in t_curstate are set to <= B38400 by to_compat, so
		 * the first test isn't needed here.
		 * Also note that we silently allow the user to set
		 * speeds above B38400 through this interface,
		 * regardless of the style setting.  This allows
		 * greater compatibility with current BSD releases.
		 */
		if (tp->t_new_sgttyb.sg_ispeed != B38400 ||
		    tp->t_curstate.t_ispeed <= B38400)
			tp->t_curstate.t_ispeed = tp->t_new_sgttyb.sg_ispeed;
		if (tp->t_new_sgttyb.sg_ospeed != B38400 ||
		    tp->t_curstate.t_ospeed <= B38400)
			tp->t_curstate.t_ospeed = tp->t_new_sgttyb.sg_ospeed;
		tp->t_curstate.t_flags =
		    (tp->t_curstate.t_flags & 0xffff0000) |
		    (tp->t_new_sgttyb.sg_flags & 0xffff);

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS or TCSETSF.
		 */
		iocp->ioc_cmd = (tp->t_ioccmd == TIOCSETP) ? TCSETSF : TCSETS;
		goto senddown;

	case TIOCSETC:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		bcopy(&tp->t_new_tchars,
		    &tp->t_curstate.t_intrc, sizeof (struct tchars));

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TIOCSLTC:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		bcopy(&tp->t_new_ltchars,
		    &tp->t_curstate.t_suspc, sizeof (struct ltchars));

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TIOCLBIS:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		tp->t_curstate.t_flags |= (tp->t_new_lflags << 16);

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TIOCLBIC:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		tp->t_curstate.t_flags &= ~(tp->t_new_lflags << 16);

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TIOCLSET:
		/*
		 * Get the current state from the GETS data, and
		 * update it.
		 */
		to_compat((struct termios *)datap->b_rptr, &tp->t_curstate);
		tp->t_curstate.t_flags &= 0xffff;
		tp->t_curstate.t_flags |= (tp->t_new_lflags << 16);

		/*
		 * Replace the data that came up with the updated data.
		 */
		from_compat(&tp->t_curstate, (struct termios *)datap->b_rptr);

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TIOCHPCL:
		/*
		 * Replace the data that came up with the updated data.
		 */
		((struct termios *)datap->b_rptr)->c_cflag |= HUPCL;

		/*
		 * Send it back down as a TCSETS.
		 */
		iocp->ioc_cmd = TCSETS;
		goto senddown;

	case TCSETSF:
		/*
		 * We're acknowledging the terminal reset ioctl that we sent
		 * when the module was opened.
		 */
		tp->t_state &= ~(TS_IOCWAIT | TS_TIOCNAK);
		freemsg(mp);
		return;

	default:
		cmn_err(CE_WARN, "ttcompat: Unexpected ioctl acknowledgment\n");
	}

	/*
	 * All the calls that return something return 0.
	 */
	tp->t_state &= ~TS_IOCWAIT;	/* we got what we wanted */
	iocp->ioc_rval = 0;

	/* copy out the data - ioctl transparency */
	iocp->ioc_cmd =  tp->t_ioccmd;
	ttcopyout(q, mp);
	return;

senddown:
	/*
	 * Send a "get state" reply back down, with suitably-modified
	 * state, as a "set state" "ioctl".
	 */
	tp->t_state &= ~TS_IOCWAIT;
	mp->b_datap->db_type = M_IOCTL;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
	putnext(WR(q), mp);
}
/* Called from ttcompatrput M_IOCACK processing. */
/* Copies out the data using M_COPYOUT messages */

static void
ttcopyout(queue_t *q, mblk_t *mp)
{
	struct copyreq *cqp;
	ttcompat_state_t *tp;

	tp = (ttcompat_state_t *)q->q_ptr;

	mp->b_datap->db_type = M_COPYOUT;
	cqp = (struct copyreq *)mp->b_rptr;
	cqp->cq_addr = (caddr_t)tp->t_arg; /* retrieve the 3rd argument */
	tp->t_arg = 0; /* clear it since we don't need it anymore */
	switch (tp->t_ioccmd) {
		case TIOCGLTC:
			cqp->cq_size = sizeof (struct ltchars);
			break;
		case TIOCGETC:
			cqp->cq_size = sizeof (struct tchars);
			break;
		case TIOCLGET:
			cqp->cq_size = sizeof (int);
			break;
		default:
			cmn_err(CE_WARN,
			    "ttcompat: Unknown ioctl to copyout\n");
			break;
		}
	cqp->cq_flag = 0;
	cqp->cq_private = NULL;
	tp->t_state |= TS_W_OUT;
	putnext(q, mp);
}


/*
 * Called when an M_IOCNAK message is seen on the read queue; if this is
 * the response we were waiting for, cancel the wait.  Pass the reply up;
 * if we were waiting for this response, we can't complete the "ioctl" and
 * the NAK will tell that to the guy above us.
 * If this wasn't the response we were waiting for, just pass it up.
 */
static void
ttcompat_ioctl_nak(queue_t *q, mblk_t *mp)
{
	ttcompat_state_t *tp;
	struct iocblk *iocp;

	iocp = (struct iocblk *)mp->b_rptr;
	tp = (ttcompat_state_t *)q->q_ptr;

	if (tp->t_state&TS_IOCWAIT && iocp->ioc_id == tp->t_iocid) {
		tp->t_state &= ~TS_IOCWAIT; /* this call isn't going through */
		tp->t_arg = 0;	/* we may have stashed the 3rd argument */
	}
	putnext(q, mp);
}

#define	FROM_COMPAT_CHAR(to, from) { if ((to = from) == 0377) to = 0; }

static void
from_compat(compat_state_t *csp, struct termios *termiosp)
{
	termiosp->c_iflag = 0;
	termiosp->c_oflag &= (ONLRET|ONOCR);

	termiosp->c_cflag = (termiosp->c_cflag &
	    (CRTSCTS|CRTSXOFF|PAREXT|LOBLK|HUPCL)) | CREAD;

	if (csp->t_ospeed > CBAUD) {
		termiosp->c_cflag |= ((csp->t_ospeed - CBAUD - 1) & CBAUD) |
		    CBAUDEXT;
	} else {
		termiosp->c_cflag |= csp->t_ospeed & CBAUD;
	}

	if (csp->t_ospeed != csp->t_ispeed) {
		if (csp->t_ispeed > (CIBAUD >> IBSHIFT)) {
			termiosp->c_cflag |= CIBAUDEXT |
			    (((csp->t_ispeed - (CIBAUD >> IBSHIFT) - 1) <<
			    IBSHIFT) & CIBAUD);
		} else {
			termiosp->c_cflag |= (csp->t_ispeed << IBSHIFT) &
			    CIBAUD;
		}
		/* hang up if ispeed=0 */
		if (csp->t_ispeed == 0)
			termiosp->c_cflag &= ~CBAUD & ~CBAUDEXT;
	}
	if (csp->t_ispeed == B110 || csp->t_xflags & STOPB)
		termiosp->c_cflag |= CSTOPB;
	termiosp->c_lflag = ECHOK;
	FROM_COMPAT_CHAR(termiosp->c_cc[VERASE], csp->t_erase);
	FROM_COMPAT_CHAR(termiosp->c_cc[VKILL], csp->t_kill);
	FROM_COMPAT_CHAR(termiosp->c_cc[VINTR], csp->t_intrc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VQUIT], csp->t_quitc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VSTART], csp->t_startc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VSTOP], csp->t_stopc);
	termiosp->c_cc[VEOL2] = 0;
	FROM_COMPAT_CHAR(termiosp->c_cc[VSUSP], csp->t_suspc);
	/* is this useful? */
	FROM_COMPAT_CHAR(termiosp->c_cc[VDSUSP], csp->t_dsuspc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VREPRINT], csp->t_rprntc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VDISCARD], csp->t_flushc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VWERASE], csp->t_werasc);
	FROM_COMPAT_CHAR(termiosp->c_cc[VLNEXT], csp->t_lnextc);
	termiosp->c_cc[VSTATUS] = 0;
	if (csp->t_flags & O_TANDEM)
		termiosp->c_iflag |= IXOFF;
	if (csp->t_flags & O_LCASE) {
		termiosp->c_iflag |= IUCLC;
		termiosp->c_oflag |= OLCUC;
		termiosp->c_lflag |= XCASE;
	}
	if (csp->t_flags & O_ECHO)
		termiosp->c_lflag |= ECHO;
	if (csp->t_flags & O_CRMOD) {
		termiosp->c_iflag |= ICRNL;
		termiosp->c_oflag |= ONLCR;
		switch (csp->t_flags & O_CRDELAY) {

		case O_CR1:
			termiosp->c_oflag |= CR2;
			break;

		case O_CR2:
			termiosp->c_oflag |= CR3;
			break;
		}
	} else {
		if ((csp->t_flags & O_NLDELAY) == O_NL1)
			termiosp->c_oflag |= ONLRET|CR1;	/* tty37 */
	}
	if ((csp->t_flags & O_NLDELAY) == O_NL2)
		termiosp->c_oflag |= NL1;
	/*
	 * When going into RAW mode, the special characters controlled by the
	 * POSIX IEXTEN bit no longer apply; when leaving, they do.
	 */
	if (csp->t_flags & O_RAW) {
		termiosp->c_cflag |= CS8;
		termiosp->c_iflag &= ~(ICRNL|IUCLC);
		termiosp->c_lflag &= ~(XCASE|IEXTEN);
	} else {
		termiosp->c_iflag |= IMAXBEL|BRKINT|IGNPAR;
		if (termiosp->c_cc[VSTOP] != 0 && termiosp->c_cc[VSTART] != 0)
			termiosp->c_iflag |= IXON;
		if (csp->t_flags & O_LITOUT)
			termiosp->c_cflag |= CS8;
		else {
			if (csp->t_flags & O_PASS8)
				termiosp->c_cflag |= CS8;
				/* XXX - what about 8 bits plus parity? */
			else {
				switch (csp->t_flags & (O_EVENP|O_ODDP)) {

				case 0:
					termiosp->c_iflag |= ISTRIP;
					termiosp->c_cflag |= CS8;
					break;

				case O_EVENP:
					termiosp->c_iflag |= INPCK|ISTRIP;
					termiosp->c_cflag |= CS7|PARENB;
					break;

				case O_ODDP:
					termiosp->c_iflag |= INPCK|ISTRIP;
					termiosp->c_cflag |= CS7|PARENB|PARODD;
					break;

				case O_EVENP|O_ODDP:
					termiosp->c_iflag |= ISTRIP;
					termiosp->c_cflag |= CS7|PARENB;
					break;
				}
			}
			if (!(csp->t_xflags & NOPOST))
				termiosp->c_oflag |= OPOST;
		}
		termiosp->c_lflag |= IEXTEN;
		if (!(csp->t_xflags & NOISIG))
			termiosp->c_lflag |= ISIG;
		if (!(csp->t_flags & O_CBREAK))
			termiosp->c_lflag |= ICANON;
		if (csp->t_flags & O_CTLECH)
			termiosp->c_lflag |= ECHOCTL;
	}
	switch (csp->t_flags & O_TBDELAY) {

	case O_TAB1:
		termiosp->c_oflag |= TAB1;
		break;

	case O_TAB2:
		termiosp->c_oflag |= TAB2;
		break;

	case O_XTABS:
		termiosp->c_oflag |= TAB3;
		break;
	}
	if (csp->t_flags & O_VTDELAY)
		termiosp->c_oflag |= FFDLY;
	if (csp->t_flags & O_BSDELAY)
		termiosp->c_oflag |= BSDLY;
	if (csp->t_flags & O_PRTERA)
		termiosp->c_lflag |= ECHOPRT;
	if (csp->t_flags & O_CRTERA)
		termiosp->c_lflag |= ECHOE;
	if (csp->t_flags & O_TOSTOP)
		termiosp->c_lflag |= TOSTOP;
	if (csp->t_flags & O_FLUSHO)
		termiosp->c_lflag |= FLUSHO;
	if (csp->t_flags & O_NOHANG)
		termiosp->c_cflag |= CLOCAL;
	if (csp->t_flags & O_CRTKIL)
		termiosp->c_lflag |= ECHOKE;
	if (csp->t_flags & O_PENDIN)
		termiosp->c_lflag |= PENDIN;
	if (!(csp->t_flags & O_DECCTQ))
		termiosp->c_iflag |= IXANY;
	if (csp->t_flags & O_NOFLSH)
		termiosp->c_lflag |= NOFLSH;
	if (termiosp->c_lflag & ICANON) {
		FROM_COMPAT_CHAR(termiosp->c_cc[VEOF], csp->t_eofc);
		FROM_COMPAT_CHAR(termiosp->c_cc[VEOL], csp->t_brkc);
	} else {
		termiosp->c_cc[VMIN] = 1;
		termiosp->c_cc[VTIME] = 0;
	}
}

#define	TO_COMPAT_CHAR(to, from) { if ((to = from) == 0) to = (uchar_t)0377; }

static void
to_compat(struct termios *termiosp, compat_state_t *csp)
{
	csp->t_xflags &= (NOISIG|NOPOST);
	csp->t_ospeed = termiosp->c_cflag & CBAUD;
	csp->t_ispeed = (termiosp->c_cflag & CIBAUD) >> IBSHIFT;
	if (sgttyb_handling > 0) {
		if (termiosp->c_cflag & CBAUDEXT)
			csp->t_ospeed += CBAUD + 1;
		if (termiosp->c_cflag & CIBAUDEXT)
			csp->t_ispeed += (CIBAUD >> IBSHIFT) + 1;
	}
	if (csp->t_ispeed == 0)
		csp->t_ispeed = csp->t_ospeed;
	if ((termiosp->c_cflag & CSTOPB) && csp->t_ispeed != B110)
		csp->t_xflags |= STOPB;
	TO_COMPAT_CHAR(csp->t_erase, termiosp->c_cc[VERASE]);
	TO_COMPAT_CHAR(csp->t_kill, termiosp->c_cc[VKILL]);
	TO_COMPAT_CHAR(csp->t_intrc, termiosp->c_cc[VINTR]);
	TO_COMPAT_CHAR(csp->t_quitc, termiosp->c_cc[VQUIT]);
	TO_COMPAT_CHAR(csp->t_startc, termiosp->c_cc[VSTART]);
	TO_COMPAT_CHAR(csp->t_stopc, termiosp->c_cc[VSTOP]);
	TO_COMPAT_CHAR(csp->t_suspc, termiosp->c_cc[VSUSP]);
	TO_COMPAT_CHAR(csp->t_dsuspc, termiosp->c_cc[VDSUSP]);
	TO_COMPAT_CHAR(csp->t_rprntc, termiosp->c_cc[VREPRINT]);
	TO_COMPAT_CHAR(csp->t_flushc, termiosp->c_cc[VDISCARD]);
	TO_COMPAT_CHAR(csp->t_werasc, termiosp->c_cc[VWERASE]);
	TO_COMPAT_CHAR(csp->t_lnextc, termiosp->c_cc[VLNEXT]);
	csp->t_flags &= (O_CTLECH|O_LITOUT|O_PASS8|O_ODDP|O_EVENP);
	if (termiosp->c_iflag & IXOFF)
		csp->t_flags |= O_TANDEM;
	if (!(termiosp->c_iflag &
	    (IMAXBEL|BRKINT|IGNPAR|PARMRK|INPCK|ISTRIP|
	    INLCR|IGNCR|ICRNL|IUCLC|IXON)) &&
	    !(termiosp->c_oflag & OPOST) &&
	    (termiosp->c_cflag & (CSIZE|PARENB)) == CS8 &&
	    !(termiosp->c_lflag & (ISIG|ICANON|XCASE|IEXTEN)))
		csp->t_flags |= O_RAW;
	else {
		if (!(termiosp->c_iflag & IXON)) {
			csp->t_startc = (uchar_t)0377;
			csp->t_stopc = (uchar_t)0377;
		}
		if ((termiosp->c_cflag & (CSIZE|PARENB)) == CS8 &&
		    !(termiosp->c_oflag & OPOST))
			csp->t_flags |= O_LITOUT;
		else {
			csp->t_flags &= ~O_LITOUT;
			if ((termiosp->c_cflag & (CSIZE|PARENB)) == CS8) {
				if (!(termiosp->c_iflag & ISTRIP))
					csp->t_flags |= O_PASS8;
			} else {
				csp->t_flags &= ~(O_ODDP|O_EVENP|O_PASS8);
				if (termiosp->c_cflag & PARODD)
					csp->t_flags |= O_ODDP;
				else if (termiosp->c_iflag & INPCK)
					csp->t_flags |= O_EVENP;
				else
					csp->t_flags |= O_ODDP|O_EVENP;
			}
			if (!(termiosp->c_oflag & OPOST))
				csp->t_xflags |= NOPOST;
			else
				csp->t_xflags &= ~NOPOST;
		}
		if (!(termiosp->c_lflag & ISIG))
			csp->t_xflags |= NOISIG;
		else
			csp->t_xflags &= ~NOISIG;
		if (!(termiosp->c_lflag & ICANON))
			csp->t_flags |= O_CBREAK;
		if (termiosp->c_lflag & ECHOCTL)
			csp->t_flags |= O_CTLECH;
		else
			csp->t_flags &= ~O_CTLECH;
	}
	if (termiosp->c_oflag & OLCUC)
		csp->t_flags |= O_LCASE;
	if (termiosp->c_lflag&ECHO)
		csp->t_flags |= O_ECHO;
	if (termiosp->c_oflag & ONLCR) {
		csp->t_flags |= O_CRMOD;
		switch (termiosp->c_oflag & CRDLY) {

		case CR2:
			csp->t_flags |= O_CR1;
			break;

		case CR3:
			csp->t_flags |= O_CR2;
			break;
		}
	} else {
		if ((termiosp->c_oflag & CR1) &&
		    (termiosp->c_oflag & ONLRET))
			csp->t_flags |= O_NL1;	/* tty37 */
	}
	if ((termiosp->c_oflag & ONLRET) && (termiosp->c_oflag & NL1))
		csp->t_flags |= O_NL2;
	switch (termiosp->c_oflag & TABDLY) {

	case TAB1:
		csp->t_flags |= O_TAB1;
		break;

	case TAB2:
		csp->t_flags |= O_TAB2;
		break;

	case XTABS:
		csp->t_flags |= O_XTABS;
		break;
	}
	if (termiosp->c_oflag & FFDLY)
		csp->t_flags |= O_VTDELAY;
	if (termiosp->c_oflag & BSDLY)
		csp->t_flags |= O_BSDELAY;
	if (termiosp->c_lflag & ECHOPRT)
		csp->t_flags |= O_PRTERA;
	if (termiosp->c_lflag & ECHOE)
		csp->t_flags |= (O_CRTERA|O_CRTBS);
	if (termiosp->c_lflag & TOSTOP)
		csp->t_flags |= O_TOSTOP;
	if (termiosp->c_lflag & FLUSHO)
		csp->t_flags |= O_FLUSHO;
	if (termiosp->c_cflag & CLOCAL)
		csp->t_flags |= O_NOHANG;
	if (termiosp->c_lflag & ECHOKE)
		csp->t_flags |= O_CRTKIL;
	if (termiosp->c_lflag & PENDIN)
		csp->t_flags |= O_PENDIN;
	if (!(termiosp->c_iflag & IXANY))
		csp->t_flags |= O_DECCTQ;
	if (termiosp->c_lflag & NOFLSH)
		csp->t_flags |= O_NOFLSH;
	if (termiosp->c_lflag & ICANON) {
		TO_COMPAT_CHAR(csp->t_eofc, termiosp->c_cc[VEOF]);
		TO_COMPAT_CHAR(csp->t_brkc, termiosp->c_cc[VEOL]);
	} else {
		termiosp->c_cc[VMIN] = 1;
		termiosp->c_cc[VTIME] = 0;
	}
}
