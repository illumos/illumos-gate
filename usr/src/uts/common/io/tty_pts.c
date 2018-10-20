/*
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * PTY - Stream "pseudo-tty" device.
 * This is the "slave" side.
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filio.h>
#include <sys/ioccom.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/tty.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/vnode.h>	/* 1/0 on the vomit meter */
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/procset.h>
#include <sys/cred.h>
#include <sys/ptyvar.h>
#include <sys/suntty.h>
#include <sys/stat.h>
#include <sys/policy.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

extern void gsignal(int pid, int sig);

extern	int npty;	/* number of pseudo-ttys configured in */
extern struct pty *pty_softc;

extern struct pollhead	ptcph;	/* poll head for ptcpoll() use */

#define	IFLAGS	(CS7|CREAD|PARENB)


/*
 * Most of these should be "void", but the people who defined the "streams"
 * data structure for S5 didn't understand data types.
 */

/*
 * Slave side.  This is a streams device.
 */
static int ptslopen(queue_t *, dev_t *, int flag, int, cred_t *);
static int ptslclose(queue_t *, int, cred_t *);
static int ptslrserv(queue_t *);

/*
 * To save instructions, since STREAMS ignores the return value
 * from this function, it is defined as void here. Kind of icky, but...
 */

static int ptslwput(queue_t *q, mblk_t *mp);

static struct module_info ptslm_info = {
	0,
	"ptys",
	0,
	INFPSZ,
	2048,
	200
};

static struct qinit ptslrinit = {
	putq,
	ptslrserv,
	ptslopen,
	ptslclose,
	NULL,
	&ptslm_info,
	NULL
};

static struct qinit ptslwinit = {
	ptslwput,
	NULL,
	NULL,
	NULL,
	NULL,
	&ptslm_info,
	NULL
};

struct	streamtab ptysinfo = {
	&ptslrinit,
	&ptslwinit,
	NULL,
	NULL
};

static void	ptslreioctl(void *);
static void	ptslioctl(struct pty *, queue_t *, mblk_t *);
static void	pt_sendstop(struct pty *);
static void	ptcpollwakeup(struct pty *, int);


static int ptsl_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ptsl_attach(dev_info_t *, ddi_attach_cmd_t);
static dev_info_t *ptsl_dip;	/* for dev-to-dip conversions */

DDI_DEFINE_STREAM_OPS(ptsl_ops, nulldev, nulldev,
    ptsl_attach, nodev, nodev, ptsl_info, D_MP, &ptysinfo,
    ddi_quiesce_not_supported);

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"tty pseudo driver slave 'ptsl'",
	&ptsl_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
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

static char	*tty_banks = PTY_BANKS;
static char	*tty_digits = PTY_DIGITS;

/* ARGSUSED */
static int
ptsl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	char	name[8];
	int	tty_num;
	char	*tty_digit = tty_digits;
	char	*tty_bank = tty_banks;

	for (tty_num = 0; tty_num < npty; tty_num++) {
		(void) sprintf(name, "tty%c%c", *tty_bank, *tty_digit);
		if (ddi_create_minor_node(devi, name, S_IFCHR,
		    tty_num, DDI_PSEUDO, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (-1);
		}
		if (*(++tty_digit) == '\0') {
			tty_digit = tty_digits;
			if (*(++tty_bank) == '\0')
				break;
		}
	}
	ptsl_dip = devi;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ptsl_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (ptsl_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)ptsl_dip;
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


/*
 * Open the slave side of a pty.
 */
/*ARGSUSED*/
static int
ptslopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *cred)
{
	minor_t unit;
	dev_t dev = *devp;
	struct pty *pty;

	unit = getminor(dev);
	if (unit >= npty)
		return (ENXIO);

	pty = &pty_softc[unit];

	mutex_enter(&pty->ptc_lock);
	/*
	 * Block waiting for controller to open, unless this is a no-delay
	 * open.
	 */
again:
	if (pty->pt_ttycommon.t_writeq == NULL) {
		pty->pt_ttycommon.t_iflag = 0;
		pty->pt_ttycommon.t_cflag = (B38400 << IBSHIFT)|B38400|IFLAGS;
		pty->pt_ttycommon.t_iocpending = NULL;
		pty->pt_wbufcid = 0;
		pty->pt_ttycommon.t_size.ws_row = 0;
		pty->pt_ttycommon.t_size.ws_col = 0;
		pty->pt_ttycommon.t_size.ws_xpixel = 0;
		pty->pt_ttycommon.t_size.ws_ypixel = 0;
	} else if ((pty->pt_ttycommon.t_flags & TS_XCLUDE) &&
	    secpolicy_excl_open(cred) != 0) {
		mutex_exit(&pty->ptc_lock);
		return (EBUSY);
	}
	if (!(flag & (FNONBLOCK|FNDELAY)) &&
	    !(pty->pt_ttycommon.t_cflag & CLOCAL)) {
		if (!(pty->pt_flags & PF_CARR_ON)) {
			pty->pt_flags |= PF_WOPEN;
			if (!cv_wait_sig(&pty->pt_cv_flags, &pty->ptc_lock)) {
				pty->pt_flags &= ~PF_WOPEN;
				mutex_exit(&pty->ptc_lock);
				return (EINTR);
			}
			goto again;
		}
	}

	pty->pt_sdev = dev;
	q->q_ptr = WR(q)->q_ptr = pty;
	pty->pt_flags &= ~PF_SLAVEGONE;
	pty->pt_ttycommon.t_readq = pty->pt_ttycommon.t_writeq = NULL;

	/*
	 * Slave is ready to accept messages but master still can't send
	 * messages to the slave queue since it is not plumbed
	 * yet. So do qprocson() and finish slave initialization.
	 */

	mutex_exit(&pty->ptc_lock);

	qprocson(q);

	/*
	 * Now it is safe to send messages to q, so wakeup master possibly
	 * waiting for slave queue to finish open.
	 */
	mutex_enter(&pty->ptc_lock);
	/*
	 * queue has already been setup with a pointer to
	 * the stream head that is being referenced
	 */
	pty->pt_vnode = strq2vp(q);
	VN_RELE(pty->pt_vnode);
	pty->pt_ttycommon.t_readq = q;
	pty->pt_ttycommon.t_writeq = WR(q);
	/* tell master device that slave is ready for writing */
	if (pty->pt_flags & PF_CARR_ON)
		cv_broadcast(&pty->pt_cv_readq);
	mutex_exit(&pty->ptc_lock);

	return (0);
}

static int
ptslclose(queue_t *q, int flag, cred_t *cred)
{
	struct pty *pty;
	bufcall_id_t pt_wbufcid = 0;

#ifdef lint
	flag = flag;
	cred = cred;
#endif

	if ((pty = (struct pty *)q->q_ptr) == NULL)
		return (ENODEV);	/* already been closed once */

	/*
	 * Prevent the queues from being uses by master device.
	 * This should be done before qprocsoff or writer may attempt
	 * to use the slave queue after qprocsoff removed it from the stream and
	 * before entering mutex_enter().
	 */
	mutex_enter(&pty->ptc_lock);
	pty->pt_ttycommon.t_readq = NULL;
	pty->pt_ttycommon.t_writeq = NULL;
	while (pty->pt_flags & PF_IOCTL) {
		pty->pt_flags |= PF_WAIT;
		cv_wait(&pty->pt_cv_flags, &pty->ptc_lock);
	}
	pty->pt_vnode = NULL;
	mutex_exit(&pty->ptc_lock);

	qprocsoff(q);

	mutex_enter(&pty->ptc_lock);
	/*
	 * ptc_lock mutex is not dropped across
	 * the call to the routine ttycommon_close
	 */
	ttycommon_close(&pty->pt_ttycommon);

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (pty->pt_wbufcid) {
		pt_wbufcid = pty->pt_wbufcid;
		pty->pt_wbufcid = 0;
	}

	/*
	 * Clear out all the slave-side state.
	 */
	pty->pt_flags &= ~(PF_WOPEN|PF_STOPPED|PF_NOSTOP);
	if (pty->pt_flags & PF_CARR_ON) {
		pty->pt_flags |= PF_SLAVEGONE;	/* let the controller know */
		ptcpollwakeup(pty, 0);	/* wake up readers/selectors */
		ptcpollwakeup(pty, FWRITE);	/* wake up writers/selectors */
		cv_broadcast(&pty->pt_cv_flags);
	}
	pty->pt_sdev = 0;
	q->q_ptr = WR(q)->q_ptr = NULL;
	mutex_exit(&pty->ptc_lock);

	if (pt_wbufcid)
		unbufcall(pt_wbufcid);

	return (0);
}

/*
 * Put procedure for write queue.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * queue up M_DATA messages for processing by the controller "read"
 * routine; discard everything else.
 */
static int
ptslwput(queue_t *q, mblk_t *mp)
{
	struct pty *pty;
	mblk_t *bp;

	pty = (struct pty *)q->q_ptr;

	mutex_enter(&pty->ptc_lock);

	switch (mp->b_datap->db_type) {

	case M_STOP:
		if (!(pty->pt_flags & PF_STOPPED)) {
			pty->pt_flags |= PF_STOPPED;
			pty->pt_send |= TIOCPKT_STOP;
			ptcpollwakeup(pty, 0);
		}
		freemsg(mp);
		break;

	case M_START:
		if (pty->pt_flags & PF_STOPPED) {
			pty->pt_flags &= ~PF_STOPPED;
			pty->pt_send = TIOCPKT_START;
			ptcpollwakeup(pty, 0);
		}
		ptcpollwakeup(pty, FREAD);	/* permit controller to read */
		freemsg(mp);
		break;

	case M_IOCTL:
		ptslioctl(pty, q, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			/*
			 * Set the "flush write" flag, so that we
			 * notify the controller if they're in packet
			 * or user control mode.
			 */
			if (!(pty->pt_send & TIOCPKT_FLUSHWRITE)) {
				pty->pt_send |= TIOCPKT_FLUSHWRITE;
				ptcpollwakeup(pty, 0);
			}
			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			/*
			 * Set the "flush read" flag, so that we
			 * notify the controller if they're in packet
			 * mode.
			 */
			if (!(pty->pt_send & TIOCPKT_FLUSHREAD)) {
				pty->pt_send |= TIOCPKT_FLUSHREAD;
				ptcpollwakeup(pty, 0);
			}
			flushq(RD(q), FLUSHDATA);
			mutex_exit(&pty->ptc_lock);
			qreply(q, mp);	/* give the read queues a crack at it */
			return (0);
		} else
			freemsg(mp);
		break;

	case M_DATA:
		/*
		 * Throw away any leading zero-length blocks, and queue it up
		 * for the controller to read.
		 */
		if (pty->pt_flags & PF_CARR_ON) {
			bp = mp;
			while ((bp->b_wptr - bp->b_rptr) == 0) {
				mp = bp->b_cont;
				freeb(bp);
				if (mp == NULL) {
					mutex_exit(&pty->ptc_lock);
					/* damp squib of a message */
					return (0);
				}
				bp = mp;
			}
			(void) putq(q, mp);
			ptcpollwakeup(pty, FREAD);	/* soup's on! */
		} else
			freemsg(mp);	/* nobody listening */
		break;

	case M_CTL:
		if ((*(int *)mp->b_rptr) == MC_CANONQUERY) {
			/*
			 * We're being asked whether we do canonicalization
			 * or not.  Send a reply back up indicating whether
			 * we do or not.
			 */
			(void) putctl1(RD(q), M_CTL,
			    (pty->pt_flags & PF_REMOTE) ?
			    MC_NOCANON : MC_DOCANON);
		}
		freemsg(mp);
		break;

	default:
		/*
		 * "No, I don't want a subscription to Chain Store Age,
		 * thank you anyway."
		 */
		freemsg(mp);
		break;
	}
	mutex_exit(&pty->ptc_lock);
	return (0);
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
ptslreioctl(void *arg)
{
	struct pty *pty = arg;
	queue_t *q;
	mblk_t *mp;

	mutex_enter(&pty->ptc_lock);
	/*
	 * The bufcall is no longer pending.
	 */
	if (pty->pt_wbufcid == 0) {
		mutex_exit(&pty->ptc_lock);
		return;
	}

	pty->pt_wbufcid = 0;
	if ((q = pty->pt_ttycommon.t_writeq) == NULL) {
		mutex_exit(&pty->ptc_lock);
		return;
	}
	if ((mp = pty->pt_ttycommon.t_iocpending) != NULL) {
		/* It's not pending any more. */
		pty->pt_ttycommon.t_iocpending = NULL;
		ptslioctl(pty, q, mp);
	}
	mutex_exit(&pty->ptc_lock);
}

/*
 * Process an "ioctl" message sent down to us.
 * Drops pty's ptc_lock mutex and then reacquire
 */
static void
ptslioctl(struct pty *pty, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	int cmd;
	size_t datasize;
	int error = 0;

	ASSERT(MUTEX_HELD(&pty->ptc_lock));

	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

	switch (cmd) {

	case TIOCSTI: {
		/*
		 * The permission checking has already been done at the stream
		 * head, since it has to be done in the context of the process
		 * doing the call.
		 */
		mblk_t *bp;

		error = miocpullup(mp, sizeof (char));
		if (error != 0)
			goto out;

		/*
		 * Simulate typing of a character at the terminal.
		 */
		if ((bp = allocb(1, BPRI_MED)) != NULL) {
			*bp->b_wptr++ = *mp->b_cont->b_rptr;
			if (!(pty->pt_flags & PF_REMOTE)) {
				if (!canput(pty->pt_ttycommon.t_readq)) {
					mutex_exit(&pty->ptc_lock);
					ttycommon_qfull(&pty->pt_ttycommon, q);
					mutex_enter(&pty->ptc_lock);
					freemsg(bp);
					error = EAGAIN;
					goto out;
				} else
					(void) putq(
					    pty->pt_ttycommon.t_readq, bp);
			} else {
				if (pty->pt_flags & PF_UCNTL) {
					/*
					 * XXX - flow control; don't overflow
					 * this "queue".
					 */
					if (pty->pt_stuffqfirst != NULL) {
						pty->pt_stuffqlast->b_next = bp;
						bp->b_prev = pty->pt_stuffqlast;
					} else {
						pty->pt_stuffqfirst = bp;
						bp->b_prev = NULL;
					}
					bp->b_next = NULL;
					pty->pt_stuffqlast = bp;
					pty->pt_stuffqlen++;
					ptcpollwakeup(pty, 0);
				}
			}
		} else {
			error = EAGAIN;
			goto out;
		}

		/*
		 * Turn the ioctl message into an ioctl ACK message.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		goto out;
	}

	case TIOCSSIZE: {
		tty_common_t *tc = &pty->pt_ttycommon;
		struct ttysize *tp;

		error = miocpullup(mp, sizeof (struct ttysize));
		if (error != 0)
			goto out;

		/*
		 * Set the window size, but don't send a SIGWINCH.
		 */
		tp = (struct ttysize *)mp->b_cont->b_rptr;
		tc->t_size.ws_row = tp->ts_lines;
		tc->t_size.ws_col = tp->ts_cols;
		tc->t_size.ws_xpixel = 0;
		tc->t_size.ws_ypixel = 0;

		/*
		 * Send an ACK back.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		goto out;
	}

	case TIOCGSIZE: {
		tty_common_t *tc = &pty->pt_ttycommon;
		mblk_t *datap;
		struct ttysize *tp;

		if ((datap = allocb(sizeof (struct ttysize),
		    BPRI_HI)) == NULL) {
			if (pty->pt_wbufcid) {
				if (pty->pt_ttycommon.t_iocpending)
					freemsg(pty->pt_ttycommon.t_iocpending);
				pty->pt_ttycommon.t_iocpending = mp;
				return;
			}
			pty->pt_wbufcid = bufcall(sizeof (struct ttysize),
			    BPRI_HI, ptslreioctl, pty);
			if (pty->pt_wbufcid == 0) {
				error = ENOMEM;
				goto out;
			}
			pty->pt_ttycommon.t_iocpending = mp;
			return;
		}
		/*
		 * Return the current size.
		 */
		tp = (struct ttysize *)datap->b_wptr;
		tp->ts_lines = tc->t_size.ws_row;
		tp->ts_cols = tc->t_size.ws_col;
		datap->b_wptr += sizeof (struct ttysize);
		iocp->ioc_count = sizeof (struct ttysize);

		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		mp->b_datap->db_type = M_IOCACK;
		goto out;
	}

	/*
	 * Imported from ttycommon_ioctl routine
	 */

	case TCSETSF: {
		tty_common_t *tc = &pty->pt_ttycommon;
		struct termios *cb;

		error = miocpullup(mp, sizeof (struct termios));
		if (error != 0)
			goto out;

		cb = (struct termios *)mp->b_cont->b_rptr;

		flushq(RD(q), FLUSHDATA);
		mutex_exit(&pty->ptc_lock);
		(void) putnextctl1(RD(q), M_FLUSH, FLUSHR);
		mutex_enter(&pty->ptc_lock);
		mutex_enter(&tc->t_excl);
		tc->t_iflag = cb->c_iflag;
		tc->t_cflag = cb->c_cflag;
		tc->t_stopc = cb->c_cc[VSTOP];
		tc->t_startc = cb->c_cc[VSTART];
		mutex_exit(&tc->t_excl);

		/*
		 * Turn the ioctl message into an ioctl ACK message.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		goto ioctldone;
	}

	case TCSETAF: {
		tty_common_t *tc = &pty->pt_ttycommon;
		struct termios *cb;

		error = miocpullup(mp, sizeof (struct termios));
		if (error != 0)
			goto out;

		cb = (struct termios *)mp->b_cont->b_rptr;

		flushq(RD(q), FLUSHDATA);
		mutex_exit(&pty->ptc_lock);
		(void) putnextctl1(RD(q), M_FLUSH, FLUSHR);
		mutex_enter(&pty->ptc_lock);
		mutex_enter(&tc->t_excl);
		tc->t_iflag = (tc->t_iflag & 0xffff0000 | cb->c_iflag);
		tc->t_cflag = (tc->t_cflag & 0xffff0000 | cb->c_cflag);
		mutex_exit(&tc->t_excl);

		/*
		 * Turn the ioctl message into an ioctl ACK message.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		goto ioctldone;
	}

	case TIOCSWINSZ: {
		tty_common_t *tc = &pty->pt_ttycommon;
		struct winsize *ws;

		error = miocpullup(mp, sizeof (struct winsize));
		if (error != 0)
			goto out;

		ws = (struct winsize *)mp->b_cont->b_rptr;
		/*
		 * If the window size changed, send a SIGWINCH.
		 */
		mutex_enter(&tc->t_excl);
		if (bcmp(&tc->t_size, ws, sizeof (struct winsize))) {
			tc->t_size = *ws;
			mutex_exit(&tc->t_excl);
			mutex_exit(&pty->ptc_lock);
			(void) putnextctl1(RD(q), M_PCSIG, SIGWINCH);
			mutex_enter(&pty->ptc_lock);
		} else
			mutex_exit(&tc->t_excl);

		/*
		 * Turn the ioctl message into an ioctl ACK message.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		goto ioctldone;
	}

	/*
	 * If they were just trying to drain output, that's OK.
	 * If they are actually trying to send a break it's an error.
	 */
	case TCSBRK:
		error = miocpullup(mp, sizeof (int));
		if (error != 0)
			goto out;

		if (*(int *)mp->b_cont->b_rptr != 0) {
			/*
			 * Turn the ioctl message into an ioctl ACK message.
			 */
			iocp->ioc_count = 0;	/* no data returned */
			mp->b_datap->db_type = M_IOCACK;
		} else {
			error = ENOTTY;
		}
		goto out;
	}

	/*
	 * The only way in which "ttycommon_ioctl" can fail is if the "ioctl"
	 * requires a response containing data to be returned to the user,
	 * and no mblk could be allocated for the data.
	 * No such "ioctl" alters our state.  Thus, we always go ahead and
	 * do any state-changes the "ioctl" calls for.  If we couldn't allocate
	 * the data, "ttycommon_ioctl" has stashed the "ioctl" away safely, so
	 * we just call "bufcall" to request that we be called back when we
	 * stand a better chance of allocating the data.
	 */
	if ((datasize =
	    ttycommon_ioctl(&pty->pt_ttycommon, q, mp, &error)) != 0) {
		if (pty->pt_wbufcid) {
			if (pty->pt_ttycommon.t_iocpending)
				freemsg(pty->pt_ttycommon.t_iocpending);
			pty->pt_ttycommon.t_iocpending = mp;
			return;
		}
		pty->pt_wbufcid = bufcall(datasize, BPRI_HI, ptslreioctl, pty);
		if (pty->pt_wbufcid == 0) {
			error = ENOMEM;
			goto out;
		}
		pty->pt_ttycommon.t_iocpending = mp;
		return;
	}

ioctldone:
	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (cmd) {

		case TCSETSF:
		case TCSETAF:
			/*
			 * Set the "flush read" flag, so that we
			 * notify the controller if they're in packet
			 * mode.
			 */
			if (!(pty->pt_send & TIOCPKT_FLUSHREAD)) {
				pty->pt_send |= TIOCPKT_FLUSHREAD;
				ptcpollwakeup(pty, 0);
			}
			/*FALLTHROUGH*/

		case TCSETSW:
		case TCSETAW:
			cmd = TIOCSETP;	/* map backwards to old codes */
			pt_sendstop(pty);
			break;

		case TCSETS:
		case TCSETA:
			cmd = TIOCSETN;	/* map backwards to old codes */
			pt_sendstop(pty);
			break;
		}
	}

	if (pty->pt_flags & PF_43UCNTL) {
		if (error < 0) {
			if ((cmd & ~0xff) == _IO('u', 0)) {
				if (cmd & 0xff) {
					pty->pt_ucntl = (uchar_t)cmd & 0xff;
					ptcpollwakeup(pty, FREAD);
				}
				error = 0; /* XXX */
				goto out;
			}
			error = ENOTTY;
		}
	} else {
		if ((pty->pt_flags & PF_UCNTL) &&
		    (cmd & (IOC_INOUT | 0xff00)) == (IOC_IN|('t'<<8)) &&
		    (cmd & 0xff)) {
			pty->pt_ucntl = (uchar_t)cmd & 0xff;
			ptcpollwakeup(pty, FREAD);
			goto out;
		}
		if (error < 0)
			error = ENOTTY;
	}

out:
	if (error != 0) {
		((struct iocblk *)mp->b_rptr)->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}

	mutex_exit(&pty->ptc_lock);
	qreply(q, mp);
	mutex_enter(&pty->ptc_lock);
}

/*
 * Service routine for read queue.
 * Just wakes the controller side up so it can write some more data
 * to that queue.
 */
static int
ptslrserv(queue_t *q)
{
	struct pty *pty = (struct pty *)q->q_ptr;
	mblk_t *mp;
	mblk_t *head = NULL, *tail = NULL;
	/*
	 * Build up the link list of messages, then drop
	 * drop the lock and do putnext()
	 */
	mutex_enter(&pty->ptc_lock);

	while ((mp = getq(q)) != NULL) {
		if ((mp->b_datap->db_type < QPCTL) && !canputnext(q)) {
			(void) putbq(q, mp);
			break;
		}
		if (!head) {
			head = mp;
			tail = mp;
		} else {
			tail->b_next = mp;
			tail = mp;
		}
	}

	if (q->q_count <= q->q_lowat)
		ptcpollwakeup((struct pty *)q->q_ptr, FWRITE);

	mutex_exit(&pty->ptc_lock);

	while (head) {
		mp = head;
		head = mp->b_next;
		mp->b_next = NULL;
		putnext(q, mp);
	}

	return (0);
}

static void
pt_sendstop(struct pty *pty)
{
	int stop;

	ASSERT(MUTEX_HELD(&pty->ptc_lock));

	if ((pty->pt_ttycommon.t_cflag&CBAUD) == 0) {
		if (pty->pt_flags & PF_CARR_ON) {
			/*
			 * Let the controller know, then wake up
			 * readers/selectors and writers/selectors.
			 */
			pty->pt_flags |= PF_SLAVEGONE;
			ptcpollwakeup(pty, 0);
			ptcpollwakeup(pty, FWRITE);
		}
	}

	stop = (pty->pt_ttycommon.t_iflag & IXON) &&
	    pty->pt_ttycommon.t_stopc == CTRL('s') &&
	    pty->pt_ttycommon.t_startc == CTRL('q');

	if (pty->pt_flags & PF_NOSTOP) {
		if (stop) {
			pty->pt_send &= ~TIOCPKT_NOSTOP;
			pty->pt_send |= TIOCPKT_DOSTOP;
			pty->pt_flags &= ~PF_NOSTOP;
			ptcpollwakeup(pty, 0);
		}
	} else {
		if (!stop) {
			pty->pt_send &= ~TIOCPKT_DOSTOP;
			pty->pt_send |= TIOCPKT_NOSTOP;
			pty->pt_flags |= PF_NOSTOP;
			ptcpollwakeup(pty, 0);
		}
	}
}

/*
 * Wake up controller side.  "flag" is 0 if a special packet or
 * user control mode message has been queued up (this data is readable,
 * so we also treat it as a regular data event; should we send SIGIO,
 * though?), FREAD if regular data has been queued up, or FWRITE if
 * the slave's read queue has drained sufficiently to allow writing.
 */
static void
ptcpollwakeup(struct pty *pty, int flag)
{
	ASSERT(MUTEX_HELD(&pty->ptc_lock));

	if (flag == 0) {
		/*
		 * "Exceptional condition" occurred.  This means that
		 * a "read" is now possible, so do a "read" wakeup.
		 */
		flag = FREAD;
		pollwakeup(&ptcph, POLLIN | POLLRDBAND);
		if (pty->pt_flags & PF_ASYNC)
			gsignal(pty->pt_pgrp, SIGURG);
	}
	if (flag & FREAD) {
		/*
		 * Wake up the parent process as there is regular
		 * data to read from slave's write queue
		 */
		pollwakeup(&ptcph, POLLIN | POLLRDNORM);
		cv_broadcast(&pty->pt_cv_writeq);
		if (pty->pt_flags & PF_ASYNC)
			gsignal(pty->pt_pgrp, SIGIO);
	}
	if (flag & FWRITE) {
		/*
		 * Wake up the parent process to write
		 * data into slave's read queue as the
		 * read queue has drained enough
		 */
		pollwakeup(&ptcph, POLLOUT | POLLWRNORM);
		cv_broadcast(&pty->pt_cv_readq);
		if (pty->pt_flags & PF_ASYNC)
			gsignal(pty->pt_pgrp, SIGIO);
	}
}
