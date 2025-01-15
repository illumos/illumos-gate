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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Mouse streams module.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/tty.h>
#include <sys/strtty.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/debug.h>

#include <sys/vuid_event.h>
#include <sys/msreg.h>
#include <sys/msio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/modctl.h>


/*
 * This is the loadable module wrapper.
 */

static struct streamtab ms_info;

static struct fmodsw fsw = {
	"ms",
	&ms_info,
	D_MP | D_MTPERMOD
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "streams module for mouse", &fsw
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
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	BYTECLIP(x)	(char)((x) > 127 ? 127 : ((x) < -128 ? -128 : (x)))

struct msdata {
	struct ms_softc	msd_softc;
	queue_t	*msd_readq;	/* upstream read queue */
	mblk_t	*msd_iocpending; /* "ioctl" awaiting buffer */
	int	msd_flags;	/* random flags */
	int	msd_iocid;	/* ID of "ioctl" being waited for */
	int	msd_iocerror;	/* error return from "ioctl" */
	char	msd_oldbutt;	/* button state at last sample */
	short	msd_state;	/* state counter for input routine */
	short	msd_jitter;
	timeout_id_t	msd_timeout_id;	/* id returned by timeout() */
	bufcall_id_t	msd_reioctl_id;	/* id returned by bufcall() */
	bufcall_id_t	msd_resched_id;	/* id returned by bufcall() */
	int	msd_baud_rate;	/* mouse baud rate */
	int	msd_rcnt_baud_chng; /* baud changed recently */
	int	msd_data_pkt_cnt; /* no of packets since last baud change */
	int	msd_qenable_more; /* enable msrserv if baud changed recently */
	int	msd_hold_baud_stup; /* # of packets to wait for baud setup */
};

#define	MS_OPEN		0x00000001	/* mouse is open for business */
#define	MS_IOCWAIT	0x00000002	/* "open" waiting for ioctl to finish */
#define	MS_IOCTOSS	0x00000004	/* Toss ioctl returns */

/*
 * Input routine states. See msinput().
 */
#define	MS_WAIT_BUTN	0
#define	MS_WAIT_X	1
#define	MS_WAIT_Y	2
#define	MS_WAIT_X2	3
#define	MS_WAIT_Y2	4
#define	MS_PKT_SZ	5

/*
 * This module supports mice runing at 1200, 4800 and 9600 baud rates.
 *
 * If there was a baud change recently, then we want to wait
 * for some time to make sure that no other baud change is on its way.
 * If the second baud rate change is done then the packets between
 * changes are garbage and are thrown away during the baud change.
 */
/*
 * The following #defines were tuned by experimentations.
 */
#define		MS_HOLD_BAUD_STUP	48
#define		MS_CNT_TOB1200		7


static int	ms_overrun_msg;	/* Message when overrun circular buffer */
static int	ms_overrun_cnt;	/* Increment when overrun circular buffer */

/*
 * Max pixel delta of jitter controlled. As this number increases the jumpiness
 * of the ms increases, i.e., the coarser the motion for medium speeds.
 */
static int	ms_jitter_thresh = 0;

/*
 * ms_jitter_thresh is the maximum number of jitters suppressed. Thus,
 * hz/ms_jitter_thresh is the maximum interval of jitters suppressed. As
 * ms_jitter_thresh increases, a wider range of jitter is suppressed. However,
 * the more inertia the mouse seems to have, i.e., the slower the mouse is to
 * react.
 */

/*
 * Measure how many (ms_speed_count) ms deltas exceed threshold
 * (ms_speedlimit). If ms_speedlaw then throw away deltas over ms_speedlimit.
 * This is to keep really bad mice that jump around from getting too far.
 */
static int	ms_speedlimit = 48;
static int	ms_speedlaw = 0;
static int	ms_speed_count;
static int	msjitterrate = 12;

#define	JITTER_TIMEOUT (hz/msjitterrate)

static clock_t	msjittertimeout; /* Timeout used when mstimeout in effect */

/*
 * Mouse buffer size in bytes.  Place here as variable so that one could
 * massage it using adb if it turns out to be too small.
 */
static int	MS_BUF_BYTES = 4096;


static int	MS_DEBUG;

static int msopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp);
static int msclose(queue_t *q, int flag, cred_t *credp);
static int mswput(queue_t *q, mblk_t *mp);
static int msrput(queue_t *q, mblk_t *mp);
static int msrserv(queue_t *q);

static struct module_info msmiinfo = {
	0,
	"ms",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit msrinit = {
	msrput,
	msrserv,
	msopen,
	msclose,
	NULL,
	&msmiinfo
};

static struct module_info msmoinfo = {
	0,
	"ms",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit mswinit = {
	mswput,
	NULL,
	msopen,
	msclose,
	NULL,
	&msmoinfo
};

static struct streamtab ms_info = {
	&msrinit,
	&mswinit,
	NULL,
	NULL,
};

static void	msresched(void *);
static void	msreioctl(void *);
static void	msioctl(queue_t *q, mblk_t *mp);
static int	ms_getparms(Ms_parms *data);
static int	ms_setparms(Ms_parms *data);
static void	msflush(struct msdata *msd);
static void	msinput(struct msdata *msd, char c);
static void	msincr(void *);

/*
 * Dummy qbufcall callback routine used by open and close.
 * The framework will wake up qwait_sig when we return from
 * this routine (as part of leaving the perimeters.)
 * (The framework enters the perimeters before calling the qbufcall() callback
 * and leaves the perimeters after the callback routine has executed. The
 * framework performs an implicit wakeup of any thread in qwait/qwait_sig
 * when it leaves the perimeter. See qwait(9F).)
 */
/* ARGSUSED */
static void
dummy_callback(void *arg)
{
}

/*
 * Open a mouse.
 */
/*ARGSUSED*/
static int
msopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	struct mousebuf *b;
	struct ms_softc *ms;
	struct msdata *msd;
	mblk_t	 *mp;
	mblk_t	 *datap;
	struct iocblk *iocb;
	struct termios *cb;
	int error = 0;

	if (q->q_ptr != NULL)
		return (0);		/* already attached */

	if (sflag != MODOPEN)
		return (EINVAL);

	/*
	 * Allocate an msdata structure.
	 */
	msd = kmem_zalloc(sizeof (struct msdata), KM_SLEEP);

	/*
	 * Set up queue pointers, so that the "put" procedure will accept
	 * the reply to the "ioctl" message we send down.
	 */
	q->q_ptr = msd;
	WR(q)->q_ptr = msd;

	qprocson(q);

	/*
	 * Setup tty modes.
	 */
	while ((mp = mkiocb(TCSETSF)) == NULL) {
		bufcall_id_t id = qbufcall(q, sizeof (struct iocblk),
		    BPRI_HI, dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			kmem_free(msd, sizeof (struct msdata));
			qprocsoff(q);

			return (EINTR);
		}
	}
	while ((datap = allocb(sizeof (struct termios), BPRI_HI)) == NULL) {
		bufcall_id_t id = qbufcall(q, sizeof (struct termios),
		    BPRI_HI, dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			freemsg(mp);
			kmem_free(msd, sizeof (struct msdata));
			qprocsoff(q);

			return (EINTR);
		}
	}


	iocb = (struct iocblk *)mp->b_rptr;
	iocb->ioc_count = sizeof (struct termios);

	cb = (struct termios *)datap->b_wptr;
	cb->c_iflag = 0;
	cb->c_oflag = 0;
	cb->c_cflag = CREAD|CS8|B9600;
	cb->c_lflag = 0;
	bzero(cb->c_cc, NCCS);

	datap->b_wptr += sizeof (*cb);
	datap->b_datap->db_type = M_DATA;
	mp->b_cont = datap;

	msd->msd_flags |= MS_IOCWAIT;	/* indicate that we're waiting for */
	msd->msd_iocid = iocb->ioc_id;	/* this response */
	msd->msd_baud_rate = B9600;
	msd->msd_rcnt_baud_chng = 1;
	msd->msd_data_pkt_cnt = 0;
	msd->msd_qenable_more = 0;
	msd->msd_hold_baud_stup = MS_HOLD_BAUD_STUP;
	putnext(WR(q), mp);

	ms = &msd->msd_softc;
	/*
	 * Now wait for it.  Let our read queue put routine wake us up
	 * when it arrives.
	 */
	while (msd->msd_flags & MS_IOCWAIT) {
		if (!qwait_sig(q)) {
			error = EINTR;
			goto error;
		}
	}
	if ((error = msd->msd_iocerror) != 0)
		goto error;

	/*
	 * Set up private data.
	 */
	msd->msd_state = MS_WAIT_BUTN;
	msd->msd_readq = q;
	msd->msd_iocpending = NULL;

	/*
	 * Allocate buffer and initialize data.
	 */
	if (ms->ms_buf == 0) {
		ms->ms_bufbytes = MS_BUF_BYTES;
		b = kmem_zalloc((uint_t)ms->ms_bufbytes, KM_SLEEP);
		b->mb_size = 1 + (ms->ms_bufbytes - sizeof (struct mousebuf))
		    / sizeof (struct mouseinfo);
		ms->ms_buf = b;
		ms->ms_vuidaddr = VKEY_FIRST;
		msjittertimeout = JITTER_TIMEOUT;
		msflush(msd);
	}

	msd->msd_flags = MS_OPEN;

	/*
	 * Tell the module below us that it should return input immediately.
	 */
	(void) putnextctl1(WR(q), M_CTL, MC_SERVICEIMM);

	return (0);

error:
	qprocsoff(q);
	kmem_free(msd, sizeof (struct msdata));

	return (error);
}

/*
 * Close the mouse
 */
/* ARGSUSED1 */
static int
msclose(queue_t *q, int flag, cred_t *credp)
{
	struct msdata *msd = (struct msdata *)q->q_ptr;
	struct ms_softc *ms;

	/*
	 * Tell the module below us that it need not return input immediately.
	 */
	(void) putnextctl1(q, M_CTL, MC_SERVICEDEF);

	qprocsoff(q);
	/*
	 * Since we're about to destroy our private data, turn off
	 * our open flag first, so we don't accept any more input
	 * and try to use that data.
	 */
	msd->msd_flags = 0;

	if (msd->msd_jitter) {
		(void) quntimeout(q, msd->msd_timeout_id);
		msd->msd_jitter = 0;
	}
	if (msd->msd_reioctl_id) {
		qunbufcall(q, msd->msd_reioctl_id);
		msd->msd_reioctl_id = 0;
	}
	if (msd->msd_resched_id) {
		qunbufcall(q, msd->msd_resched_id);
		msd->msd_resched_id = 0;
	}
	if (msd->msd_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(msd->msd_iocpending);
		msd->msd_iocpending = NULL;
	}
	ms = &msd->msd_softc;
	/* Free mouse buffer */
	if (ms->ms_buf != NULL)
		kmem_free(ms->ms_buf, (uint_t)ms->ms_bufbytes);
	/* Free msdata structure */
	kmem_free((void *)msd, sizeof (*msd));
	return (0);
}

/*
 * Read queue service routine.
 * Turn buffered mouse events into stream messages.
 */
static int
msrserv(queue_t *q)
{
	struct msdata *msd = (struct msdata *)q->q_ptr;
	struct ms_softc *ms;
	struct mousebuf *b;
	struct mouseinfo *mi;
	int    button_number;
	int    hwbit;
	mblk_t	 *bp;

	/*
	 * Handle the case of a queue which is backenabled before
	 * initialization is complete.
	 */
	if (!(msd->msd_flags & MS_OPEN)) {
		return (1);
	}

	ms = &msd->msd_softc;
	b = ms->ms_buf;
	if (msd->msd_rcnt_baud_chng && ms->ms_oldoff != b->mb_off) {
		int	no_pkt = b->mb_off - ms->ms_oldoff;
		int	i;
		no_pkt = no_pkt > 0 ? no_pkt : (b->mb_size - no_pkt);
		if (no_pkt < msd->msd_hold_baud_stup) {
			msd->msd_qenable_more = 1;
			return (0);
		} else {
			/*
			 * throw away packets in beginning (mostly garbage)
			 */
			for (i = 0; i < msd->msd_hold_baud_stup; i++) {
				ms->ms_oldoff++;	/* next event */
				/* circular buffer wraparound */
				if (ms->ms_oldoff >= b->mb_size)
					ms->ms_oldoff = 0;
			}
			msd->msd_rcnt_baud_chng = 0;
			msd->msd_data_pkt_cnt = 0;
			msd->msd_qenable_more = 0;
		}
	}
	while (canputnext(q) && ms->ms_oldoff != b->mb_off) {
		mi = &b->mb_info[ms->ms_oldoff];
		switch (ms->ms_readformat) {

		case MS_3BYTE_FORMAT: {
			char *cp;

			if ((bp = allocb(3, BPRI_HI)) != NULL) {
				cp = (char *)bp->b_wptr;

				*cp++ = 0x80 | mi->mi_buttons;
				/* Update read buttons */
				ms->ms_prevbuttons = mi->mi_buttons;

				*cp++ = mi->mi_x;
				*cp++ = -mi->mi_y;
				/* lower pri to avoid mouse droppings */
				bp->b_wptr = (uchar_t *)cp;
				putnext(q, bp);
			} else {
				if (msd->msd_resched_id)
					qunbufcall(q, msd->msd_resched_id);
				msd->msd_resched_id = qbufcall(q, 3, BPRI_HI,
				    msresched, msd);
				if (msd->msd_resched_id == 0)
					return (0);	/* try again later */
				/* bufcall failed; just pitch this event */
				/* or maybe flush queue? */
			}
			ms->ms_oldoff++;	/* next event */

			/* circular buffer wraparound */
			if (ms->ms_oldoff >= b->mb_size)
				ms->ms_oldoff = 0;
			break;
		}

		case MS_VUID_FORMAT: {
			Firm_event *fep;

			bp = NULL;
			switch (ms->ms_eventstate) {

			case EVENT_BUT3:
			case EVENT_BUT2:
			case EVENT_BUT1:
			    /* Test the button. Send an event if it changed. */
			    button_number = ms->ms_eventstate - EVENT_BUT1;
			    hwbit = MS_HW_BUT1 >> button_number;
			    if ((ms->ms_prevbuttons & hwbit) !=
				(mi->mi_buttons & hwbit)) {
			    if ((bp = allocb(sizeof (Firm_event),
						BPRI_HI)) != NULL) {
				    fep = (Firm_event *)bp->b_wptr;
				    fep->id = vuid_id_addr(ms->ms_vuidaddr) |
					vuid_id_offset(BUT(1) + button_number);
				    fep->pair_type = FE_PAIR_NONE;
				    fep->pair = 0;
				    /* Update read buttons and set value */
				    if (mi->mi_buttons & hwbit) {
					fep->value = 0;
					ms->ms_prevbuttons |= hwbit;
				    } else {
					fep->value = 1;
					ms->ms_prevbuttons &= ~hwbit;
				    }
				    fep->time = mi->mi_time;

				} else {
				    if (msd->msd_resched_id)
					qunbufcall(q, msd->msd_resched_id);
				    msd->msd_resched_id = qbufcall(q,
					sizeof (Firm_event),
					BPRI_HI, msresched, msd);
				    if (msd->msd_resched_id == 0)
					return (0);	/* try again later */
				    /* bufcall failed; just pitch this event */
				    /* or maybe flush queue? */
				    ms->ms_eventstate = EVENT_X;
				}
			    }
			    break;

			case EVENT_Y:
			    /* Send y if changed. */
			    if (mi->mi_y != 0) {

				if ((bp = allocb(sizeof (Firm_event),
						BPRI_HI)) != NULL) {
				    fep = (Firm_event *)bp->b_wptr;
				    fep->id = vuid_id_addr(ms->ms_vuidaddr) |
					    vuid_id_offset(LOC_Y_DELTA);
				    fep->pair_type = FE_PAIR_ABSOLUTE;
				    fep->pair = (uchar_t)LOC_Y_ABSOLUTE;
				    fep->value = -mi->mi_y;
				    fep->time = mi->mi_time;
				} else {
				    if (msd->msd_resched_id)
					qunbufcall(q, msd->msd_resched_id);
				    msd->msd_resched_id = qbufcall(q,
					sizeof (Firm_event),
					BPRI_HI, msresched, msd);
				    if (msd->msd_resched_id == 0)
					return (0);	/* try again later */
				    /* bufcall failed; just pitch this event */
				    /* or maybe flush queue? */
				    ms->ms_eventstate = EVENT_X;
				}
			    }
			    break;

			case EVENT_X:
			    /* Send x if changed. */
			    if (mi->mi_x != 0) {
				if ((bp = allocb(sizeof (Firm_event),
						BPRI_HI)) != NULL) {
				    fep = (Firm_event *)bp->b_wptr;
				    fep->id = vuid_id_addr(ms->ms_vuidaddr) |
					    vuid_id_offset(LOC_X_DELTA);
				    fep->pair_type = FE_PAIR_ABSOLUTE;
				    fep->pair = (uchar_t)LOC_X_ABSOLUTE;
				    fep->value = mi->mi_x;
				    fep->time = mi->mi_time;
				} else {
				    if (msd->msd_resched_id)
					qunbufcall(q, msd->msd_resched_id);
				    msd->msd_resched_id = qbufcall(q,
					sizeof (Firm_event),
					BPRI_HI, msresched, msd);
				    if (msd->msd_resched_id == 0)
					return (0);	/* try again later */
				    /* bufcall failed; just pitch this event */
				    /* or maybe flush queue? */
				    ms->ms_eventstate = EVENT_X;
				}
			    }
			    break;

			}
			if (bp != NULL) {
			    /* lower pri to avoid mouse droppings */
			    bp->b_wptr += sizeof (Firm_event);
			    putnext(q, bp);
			}
			if (ms->ms_eventstate == EVENT_X) {
			    ms->ms_eventstate = EVENT_BUT3;
			    ms->ms_oldoff++;	/* next event */

			    /* circular buffer wraparound */
			    if (ms->ms_oldoff >= b->mb_size)
				ms->ms_oldoff = 0;
			} else
			    ms->ms_eventstate--;
		}
		}
	}
	return (0);
}

static void
msresched(void *msdptr)
{
	queue_t *q;
	struct msdata *msd = msdptr;

	msd->msd_resched_id = 0;
	if ((q = msd->msd_readq) != 0)
		qenable(q);	/* run the service procedure */
}

/*
 * Line discipline output queue put procedure: handles M_IOCTL
 * messages.
 */
static int
mswput(queue_t *q, mblk_t *mp)
{

	/*
	 * Process M_FLUSH, and some M_IOCTL, messages here; pass
	 * everything else down.
	 */
	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(RD(q), FLUSHDATA);
		/* FALLTHROUGH */
	default:
		putnext(q, mp);	/* pass it down the line */
		break;

	case M_IOCTL:
		msioctl(q, mp);
		break;
	}
	return (0);
}

static void
msreioctl(void *msdptr)
{
	struct msdata *msd = msdptr;
	queue_t *q;
	mblk_t *mp;

	msd->msd_reioctl_id = 0;
	q = msd->msd_readq;
	if ((mp = msd->msd_iocpending) != NULL) {
		msd->msd_iocpending = NULL;	/* not pending any more */
		msioctl(WR(q), mp);
	}
}

static void
msioctl(queue_t *q, mblk_t *mp)
{
	struct msdata		*msd;
	struct ms_softc *ms;
	struct iocblk	*iocp;
	Vuid_addr_probe		*addr_probe;
	uint_t			ioctlrespsize;
	int			err = 0;
	mblk_t			*datap;

	msd = (struct msdata *)q->q_ptr;
	if (msd == NULL) {
		err = EINVAL;
		goto out;
	}
	ms = &msd->msd_softc;

	iocp = (struct iocblk *)mp->b_rptr;

	if (MS_DEBUG)
		printf("mswput(M_IOCTL,%x)\n", iocp->ioc_cmd);

	switch (iocp->ioc_cmd) {
	case VUIDSFORMAT:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;
		if (*(int *)mp->b_cont->b_rptr == ms->ms_readformat)
			break;
		ms->ms_readformat = *(int *)mp->b_cont->b_rptr;
		/*
		 * Flush mouse buffer because the messages upstream of us
		 * are in the old format.
		 */
		msflush(msd);
		break;

	case VUIDGFORMAT:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = ms->ms_readformat;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case VUIDSADDR:
	case VUIDGADDR:
		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;
		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		if (addr_probe->base != VKEY_FIRST) {
			err = ENODEV;
			break;
		}
		if (iocp->ioc_cmd == VUIDSADDR)
			ms->ms_vuidaddr = addr_probe->data.next;
		else
			addr_probe->data.current = ms->ms_vuidaddr;
		break;

	case MSIOGETPARMS:
		if (MS_DEBUG)
			printf("ms_getparms\n");

		if ((datap = allocb(sizeof (Ms_parms), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (Ms_parms);
			goto allocfailure;
		}
		err = ms_getparms((Ms_parms *)datap->b_wptr);
		datap->b_wptr += sizeof (Ms_parms);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (Ms_parms);
		break;

	case MSIOSETPARMS:
		if (MS_DEBUG)
			printf("ms_setparms\n");

		err = miocpullup(mp, sizeof (Ms_parms));
		if (err != 0)
			break;
		err = ms_setparms((Ms_parms *)mp->b_cont->b_rptr);
		break;

	default:
		putnext(q, mp);	/* pass it down the line */
		return;
	}

out:
	if (err != 0)
		miocnak(q, mp, 0, err);
	else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;	/* brain rot */
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);
	}
	return;

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	if (msd->msd_iocpending != NULL)
		freemsg(msd->msd_iocpending);
	msd->msd_iocpending = mp;
	if (msd->msd_reioctl_id)
		qunbufcall(q, msd->msd_reioctl_id);
	msd->msd_reioctl_id = qbufcall(q, ioctlrespsize, BPRI_HI,
	    msreioctl, msd);
}

static int
ms_getparms(Ms_parms *data)
{
	data->jitter_thresh = ms_jitter_thresh;
	data->speed_law = ms_speedlaw;
	data->speed_limit = ms_speedlimit;
	return (0);
}

static int
ms_setparms(Ms_parms *data)
{
	ms_jitter_thresh = data->jitter_thresh;
	ms_speedlaw = data->speed_law;
	ms_speedlimit = data->speed_limit;
	return (0);
}

static void
msflush(struct msdata *msd)
{
	struct ms_softc *ms = &msd->msd_softc;
	queue_t *q;

	ms->ms_oldoff = 0;
	ms->ms_eventstate = EVENT_BUT3;
	ms->ms_buf->mb_off = 0;
	ms->ms_prevbuttons = MS_HW_BUT1 | MS_HW_BUT2 | MS_HW_BUT3;
	msd->msd_oldbutt = ms->ms_prevbuttons;
	if ((q = msd->msd_readq) != NULL && q->q_next != NULL)
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
}


/*
 * Mouse read queue put procedure.
 */
static int
msrput(queue_t *q, mblk_t *mp)
{
	struct msdata *msd = (struct msdata *)q->q_ptr;
	mblk_t *bp;
	char *readp;
	mblk_t *imp;
	mblk_t *datap;
	struct iocblk *iocb;
	struct termios *cb;
	struct iocblk *iocp;

	if (msd == 0)
		return (0);

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(WR(q), FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);
		/* FALLTHROUGH */
	default:
		putnext(q, mp);
		return (0);

	case M_BREAK:
		if (msd->msd_flags & MS_IOCTOSS) {
			freemsg(mp);
			return (0);
		}

		if (msd->msd_rcnt_baud_chng && msd->msd_data_pkt_cnt == 0) {
			freemsg(mp);
			return (0);
		}

		/*
		 * If we are sampling a 4800 baud mouse at 9600,
		 * we want to wait for long time because there is no
		 * fixed timeframe for receiving break. If we are sampling
		 * a 1200 baud mouse at 4800 or 9600 baud rate then
		 * it is guaranteed that break will be received very soon.
		 */
		if (msd->msd_rcnt_baud_chng) {
			switch (msd->msd_baud_rate) {
			case B9600:
				msd->msd_hold_baud_stup = MS_HOLD_BAUD_STUP/2;
				msd->msd_baud_rate = B4800;
				break;

			case B4800:
				if (msd->msd_data_pkt_cnt <= MS_CNT_TOB1200) {
					msd->msd_hold_baud_stup =
						MS_HOLD_BAUD_STUP/6;
					msd->msd_baud_rate = B1200;
				} else {
					msd->msd_hold_baud_stup =
						MS_HOLD_BAUD_STUP;
					msd->msd_baud_rate = B9600;
				}
				break;

			case B1200:
			default:
				msd->msd_hold_baud_stup = MS_HOLD_BAUD_STUP;
				msd->msd_baud_rate = B9600;
				break;
			}
		} else {
			msd->msd_hold_baud_stup = MS_HOLD_BAUD_STUP;
			msd->msd_baud_rate = B9600;
		}

		/*
		 * Change baud rate.
		 */
		if ((imp = mkiocb(TCSETSF)) == NULL) {
			return (0);
		}
		if ((datap = allocb(sizeof (struct termios),
		    BPRI_HI)) == NULL) {
			freemsg(imp);
			return (0);
		}

		iocb = (struct iocblk *)imp->b_rptr;
		iocb->ioc_count = sizeof (struct termios);

		cb = (struct termios *)datap->b_rptr;
		cb->c_iflag = 0;
		cb->c_oflag = 0;
		cb->c_cflag = CREAD|CS8|msd->msd_baud_rate;
		cb->c_lflag = 0;
		bzero(cb->c_cc, NCCS);

		datap->b_wptr += sizeof (*cb);
		datap->b_datap->db_type = M_DATA;
		imp->b_cont = datap;

		msd->msd_flags |= MS_IOCTOSS|MS_IOCWAIT;
		msd->msd_iocid = iocb->ioc_id;
		msflush(msd);
		flushq(q, FLUSHALL);
		putnext(WR(q), imp);
		freemsg(mp);
		msd->msd_rcnt_baud_chng = 1;
		msd->msd_data_pkt_cnt = 0;
		if (MS_DEBUG)
			printf("baud %x\n", msd->msd_baud_rate);
		return (0);

	case M_IOCACK:
	case M_IOCNAK:
		/*
		 * If we are doing an "ioctl" ourselves, check if this
		 * is the reply to that code.  If so, wake up the
		 * "open" routine, and toss the reply, otherwise just
		 * pass it up.
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		if (!(msd->msd_flags & MS_IOCWAIT) ||
		    iocp->ioc_id != msd->msd_iocid) {
			/*
			 * This isn't the reply we're looking for.  Move along.
			 */
			putnext(q, mp);
		} else {
			msd->msd_flags &= ~MS_IOCWAIT;
			msd->msd_iocerror = iocp->ioc_error;
			/*
			 * If we sent down a request to change the baud rate.
			 * This is the reply.  Just ignore it.
			 */
			if (msd->msd_flags & MS_IOCTOSS) {
				msd->msd_flags &= ~MS_IOCTOSS;
				msflush(msd);
				flushq(q, FLUSHALL);
			}
			freemsg(mp);
		}
		return (0);

	case M_DATA:
		if ((msd->msd_flags & MS_IOCTOSS) ||
		    !(msd->msd_flags & MS_OPEN)) {
			freemsg(mp);
			return (0);
		}
		break;
	}

	/*
	 * A data message, consisting of bytes from the mouse.
	 * Hand each byte to our input routine.
	 */
	bp = mp;

	do {
		readp = (char *)bp->b_rptr;
		while (readp < (char *)bp->b_wptr) {
			if (msd->msd_rcnt_baud_chng)
				msd->msd_data_pkt_cnt++;
			msinput(msd, *readp++);
		}
		bp->b_rptr = (unsigned char *)readp;
	} while ((bp = bp->b_cont) != NULL);	/* next block, if any */

	freemsg(mp);
	return (0);
}

/*
 * Mouse input routine; process a byte received from a mouse and
 * assemble into a mouseinfo message for the window system.
 *
 * The MSC mice send a five-byte packet organized as
 *	button, dx, dy, dx, dy
 * where dx and dy can be any signed byte value. The mouseinfo message
 * is organized as
 *	dx, dy, button, timestamp
 * Our strategy is to add up the 2 dx and the 2 dy in the five-byte
 * packet, then send the mouseinfo message up.
 *
 * Basic algorithm: throw away bytes until we get a [potential]
 * button byte. Collect button; Collect dx1; Collect dy1; Collect dx2
 * and add it to dx1; Collect dy2 and add it to dy1; Send button,
 * dx, dy, timestamp.
 *
 * Watch out for overflow!
 */

static void
msinput(struct msdata *msd, char c)
{
	struct ms_softc *ms;
	struct mousebuf *b;
	struct mouseinfo *mi;
	int    jitter_radius;
	int    temp;

	ms = &msd->msd_softc;
	b = ms->ms_buf;
	if (b == NULL)
		return;

	mi = &b->mb_info[b->mb_off];

	switch (msd->msd_state) {

	case MS_WAIT_BUTN:
		if ((c & 0xf8) != 0x80) {
			if (MS_DEBUG)
				printf("Mouse input char %x discarded\n",
					(int)c & 0xff);
			if (msd->msd_rcnt_baud_chng) {
				msflush(msd);
				flushq(msd->msd_readq, FLUSHALL);
				msd->msd_hold_baud_stup++;
			}
			return;
		}

		/*
		 * Probably a button byte.
		 * Lower 3 bits are left, middle, right.
		 */
		mi->mi_buttons = c & (MS_HW_BUT1 | MS_HW_BUT2 | MS_HW_BUT3);
		break;

	case MS_WAIT_X:
		/*
		 * Delta X byte.  Add the delta X from this sample to
		 * the delta X we're accumulating in the current event.
		 */
		temp = (int)(mi->mi_x + c);
		mi->mi_x = BYTECLIP(temp);
		uniqtime32(&mi->mi_time); /* record time when sample arrived */
		break;

	case MS_WAIT_Y:
		/*
		 * Delta Y byte.  Add the delta Y from this sample to
		 * the delta Y we're accumulating in the current event.
		 * (Subtract, actually, because the mouse reports
		 * increasing Y up the screen.)
		 */
		temp = (int)(mi->mi_y - c);
		mi->mi_y = BYTECLIP(temp);
		break;

	case MS_WAIT_X2:
		/*
		 * Second delta X byte.
		 */
		temp = (int)(mi->mi_x + c);
		mi->mi_x = BYTECLIP(temp);
		uniqtime32(&mi->mi_time);
		break;

	case MS_WAIT_Y2:
		/*
		 * Second delta Y byte.
		 */
		temp = (int)(mi->mi_y - c);
		mi->mi_y = BYTECLIP(temp);
		break;

	}

	/*
	 * Done yet?
	 */
	if (msd->msd_state == MS_WAIT_Y2)
		msd->msd_state = MS_WAIT_BUTN;	/* BONG. Start again. */
	else {
		msd->msd_state += 1;
		return;
	}

	if (msd->msd_jitter) {
		(void) quntimeout(msd->msd_readq, msd->msd_timeout_id);
		msd->msd_jitter = 0;
	}

	if (mi->mi_buttons == msd->msd_oldbutt) {
		/*
		 * Buttons did not change; did position?
		 */
		if (mi->mi_x == 0 && mi->mi_y == 0) {
			/* no, position did not change - boring event */
			return;
		}

		/*
		 * Did the mouse move more than the jitter threshhold?
		 */
		jitter_radius = ms_jitter_thresh;
		if (ABS((int)mi->mi_x) <= jitter_radius &&
		    ABS((int)mi->mi_y) <= jitter_radius) {
			/*
			 * Mouse moved less than the jitter threshhold.
			 * Don't indicate an event; keep accumulating motions.
			 * After "msjittertimeout" ticks expire, treat
			 * the accumulated delta as the real delta.
			 */
			msd->msd_jitter = 1;
			msd->msd_timeout_id = qtimeout(msd->msd_readq,
			    msincr, msd, msjittertimeout);
			return;
		}
	}
	msd->msd_oldbutt = mi->mi_buttons;
	msincr(msd);
}

/*
 * Increment the mouse sample pointer.
 * Called either immediately after a sample or after a jitter timeout.
 */
static void
msincr(void *arg)
{
	struct msdata  *msd = arg;
	struct ms_softc *ms = &msd->msd_softc;
	struct mousebuf *b;
	struct mouseinfo *mi;
	char			oldbutt;
	short		xc, yc;
	int		wake;
	int		speedlimit = ms_speedlimit;
	int		xabs, yabs;

	/*
	 * No longer waiting for jitter timeout
	 */
	msd->msd_jitter = 0;

	b = ms->ms_buf;
	if (b == NULL)
		return;
	mi = &b->mb_info[b->mb_off];

	if (ms_speedlaw) {
		xabs = ABS((int)mi->mi_x);
		yabs = ABS((int)mi->mi_y);
		if (xabs > speedlimit || yabs > speedlimit)
			ms_speed_count++;
		if (xabs > speedlimit)
			mi->mi_x = 0;
		if (yabs > speedlimit)
			mi->mi_y = 0;
	}

	oldbutt = mi->mi_buttons;

	xc = yc = 0;

	/* See if we need to wake up anyone waiting for input */
	wake = b->mb_off == ms->ms_oldoff;

	/* Adjust circular buffer pointer */
	if (++b->mb_off >= b->mb_size) {
		b->mb_off = 0;
		mi = b->mb_info;
	} else {
		mi++;
	}

	/*
	 * If over-took read index then flush buffer so that mouse state
	 * is consistent.
	 */
	if (b->mb_off == ms->ms_oldoff) {
		if (ms_overrun_msg)
			cmn_err(CE_WARN,
				"Mouse buffer flushed when overrun.\n");
		msflush(msd);
		ms_overrun_cnt++;
		mi = b->mb_info;
	}

	/* Remember current buttons and fractional part of x & y */
	mi->mi_buttons = oldbutt;
	mi->mi_x = (char)xc;
	mi->mi_y = (char)yc;
	if (wake || msd->msd_qenable_more)
		qenable(msd->msd_readq);	/* run the service procedure */
}
