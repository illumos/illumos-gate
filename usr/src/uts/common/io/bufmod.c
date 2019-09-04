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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * STREAMS Buffering module
 *
 * This streams module collects incoming messages from modules below
 * it on the stream and buffers them up into a smaller number of
 * aggregated messages.  Its main purpose is to reduce overhead by
 * cutting down on the number of read (or getmsg) calls its client
 * user process makes.
 *  - only M_DATA is buffered.
 *  - multithreading assumes configured as D_MTQPAIR
 *  - packets are lost only if flag SB_NO_HEADER is clear and buffer
 *    allocation fails.
 *  - in order message transmission. This is enforced for messages other
 *    than high priority messages.
 *  - zero length messages on the read side are not passed up the
 *    stream but used internally for synchronization.
 * FLAGS:
 * - SB_NO_PROTO_CVT - no conversion of M_PROTO messages to M_DATA.
 *   (conversion is the default for backwards compatibility
 *    hence the negative logic).
 * - SB_NO_HEADER - no headers in buffered data.
 *   (adding headers is the default for backwards compatibility
 *    hence the negative logic).
 * - SB_DEFER_CHUNK - provides improved response time in question-answer
 *   applications. Buffering is not enabled until the second message
 *   is received on the read side within the sb_ticks interval.
 *   This option will often be used in combination with flag SB_SEND_ON_WRITE.
 * - SB_SEND_ON_WRITE - a write message results in any pending buffered read
 *   data being immediately sent upstream.
 * - SB_NO_DROPS - bufmod behaves transparently in flow control and propagates
 *   the blocked flow condition downstream. If this flag is clear (default)
 *   messages will be dropped if the upstream flow is blocked.
 */


#include	<sys/types.h>
#include	<sys/errno.h>
#include	<sys/debug.h>
#include	<sys/stropts.h>
#include	<sys/time.h>
#include	<sys/stream.h>
#include	<sys/conf.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/kmem.h>
#include	<sys/strsun.h>
#include	<sys/bufmod.h>
#include	<sys/modctl.h>
#include	<sys/isa_defs.h>

/*
 * Per-Stream state information.
 *
 * If sb_ticks is negative, we don't deliver chunks until they're
 * full.  If it's zero, we deliver every packet as it arrives.  (In
 * this case we force sb_chunk to zero, to make the implementation
 * easier.)  Otherwise, sb_ticks gives the number of ticks in a
 * buffering interval. The interval begins when the a read side data
 * message is received and a timeout is not active. If sb_snap is
 * zero, no truncation of the msg is done.
 */
struct sb {
	queue_t	*sb_rq;		/* our rq */
	mblk_t	*sb_mp;		/* partial chunk */
	mblk_t  *sb_head;	/* pre-allocated space for the next header */
	mblk_t	*sb_tail;	/* first mblk of last message appended */
	uint_t	sb_mlen;	/* sb_mp length */
	uint_t	sb_mcount;	/* input msg count in sb_mp */
	uint_t	sb_chunk;	/* max chunk size */
	clock_t	sb_ticks;	/* timeout interval */
	timeout_id_t sb_timeoutid; /* qtimeout() id */
	uint_t	sb_drops;	/* cumulative # discarded msgs */
	uint_t	sb_snap;	/* snapshot length */
	uint_t	sb_flags;	/* flags field */
	uint_t	sb_state;	/* state variable */
};

/*
 * Function prototypes.
 */
static	int	sbopen(queue_t *, dev_t *, int, int, cred_t *);
static	int	sbclose(queue_t *, int, cred_t *);
static	int	sbwput(queue_t *, mblk_t *);
static	int	sbrput(queue_t *, mblk_t *);
static	int	sbrsrv(queue_t *);
static	void	sbioctl(queue_t *, mblk_t *);
static	void	sbaddmsg(queue_t *, mblk_t *);
static	void	sbtick(void *);
static	void	sbclosechunk(struct sb *);
static	void	sbsendit(queue_t *, mblk_t *);

static struct module_info	sb_minfo = {
	21,		/* mi_idnum */
	"bufmod",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	1,		/* mi_hiwat */
	0		/* mi_lowat */
};

static struct qinit	sb_rinit = {
	sbrput,			/* qi_putp */
	sbrsrv,			/* qi_srvp */
	sbopen,			/* qi_qopen */
	sbclose,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sb_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit	sb_winit = {
	sbwput,			/* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sb_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab	sb_info = {
	&sb_rinit,	/* st_rdinit */
	&sb_winit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwinit */
};


/*
 * This is the loadable module wrapper.
 */

static struct fmodsw fsw = {
	"bufmod",
	&sb_info,
	D_MTQPAIR | D_MP
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "streams buffer mod", &fsw
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


/* ARGSUSED */
static int
sbopen(queue_t *rq, dev_t *dev, int oflag, int sflag, cred_t *crp)
{
	struct sb	*sbp;
	ASSERT(rq);

	if (sflag != MODOPEN)
		return (EINVAL);

	if (rq->q_ptr)
		return (0);

	/*
	 * Allocate and initialize per-Stream structure.
	 */
	sbp = kmem_alloc(sizeof (struct sb), KM_SLEEP);
	sbp->sb_rq = rq;
	sbp->sb_ticks = -1;
	sbp->sb_chunk = SB_DFLT_CHUNK;
	sbp->sb_tail = sbp->sb_mp = sbp->sb_head = NULL;
	sbp->sb_mlen = 0;
	sbp->sb_mcount = 0;
	sbp->sb_timeoutid = 0;
	sbp->sb_drops = 0;
	sbp->sb_snap = 0;
	sbp->sb_flags = 0;
	sbp->sb_state = 0;

	rq->q_ptr = WR(rq)->q_ptr = sbp;

	qprocson(rq);


	return (0);
}

/* ARGSUSED1 */
static int
sbclose(queue_t *rq, int flag, cred_t *credp)
{
	struct	sb	*sbp = (struct sb *)rq->q_ptr;

	ASSERT(sbp);

	qprocsoff(rq);
	/*
	 * Cancel an outstanding timeout
	 */
	if (sbp->sb_timeoutid != 0) {
		(void) quntimeout(rq, sbp->sb_timeoutid);
		sbp->sb_timeoutid = 0;
	}
	/*
	 * Free the current chunk.
	 */
	if (sbp->sb_mp) {
		freemsg(sbp->sb_mp);
		sbp->sb_tail = sbp->sb_mp = sbp->sb_head = NULL;
		sbp->sb_mlen = 0;
	}

	/*
	 * Free the per-Stream structure.
	 */
	kmem_free((caddr_t)sbp, sizeof (struct sb));
	rq->q_ptr = WR(rq)->q_ptr = NULL;

	return (0);
}

/*
 * the correction factor is introduced to compensate for
 * whatever assumptions the modules below have made about
 * how much traffic is flowing through the stream and the fact
 * that bufmod may be snipping messages with the sb_snap length.
 */
#define	SNIT_HIWAT(msgsize, fudge)	((4 * msgsize * fudge) + 512)
#define	SNIT_LOWAT(msgsize, fudge)	((2 * msgsize * fudge) + 256)


static void
sbioc(queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	struct sb *sbp = (struct sb *)wq->q_ptr;
	clock_t	ticks;
	mblk_t	*mop;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case SBIOCGCHUNK:
	case SBIOCGSNAP:
	case SBIOCGFLAGS:
	case SBIOCGTIME:
		miocack(wq, mp, 0, 0);
		return;

	case SBIOCSTIME:
#ifdef _SYSCALL32_IMPL
		if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
			struct timeval32 *t32;

			t32 = (struct timeval32 *)mp->b_cont->b_rptr;
			if (t32->tv_sec < 0 || t32->tv_usec < 0) {
				miocnak(wq, mp, 0, EINVAL);
				break;
			}
			ticks = TIMEVAL_TO_TICK(t32);
		} else
#endif /* _SYSCALL32_IMPL */
		{
			struct timeval *tb;

			tb = (struct timeval *)mp->b_cont->b_rptr;

			if (tb->tv_sec < 0 || tb->tv_usec < 0) {
				miocnak(wq, mp, 0, EINVAL);
				break;
			}
			ticks = TIMEVAL_TO_TICK(tb);
		}
		sbp->sb_ticks = ticks;
		if (ticks == 0)
			sbp->sb_chunk = 0;
		miocack(wq, mp, 0, 0);
		sbclosechunk(sbp);
		return;

	case SBIOCSCHUNK:
		/*
		 * set up hi/lo water marks on stream head read queue.
		 * unlikely to run out of resources. Fix at later date.
		 */
		if ((mop = allocb(sizeof (struct stroptions),
		    BPRI_MED)) != NULL) {
			struct stroptions *sop;
			uint_t chunk;

			chunk = *(uint_t *)mp->b_cont->b_rptr;
			mop->b_datap->db_type = M_SETOPTS;
			mop->b_wptr += sizeof (struct stroptions);
			sop = (struct stroptions *)mop->b_rptr;
			sop->so_flags = SO_HIWAT | SO_LOWAT;
			sop->so_hiwat = SNIT_HIWAT(chunk, 1);
			sop->so_lowat = SNIT_LOWAT(chunk, 1);
			qreply(wq, mop);
		}

		sbp->sb_chunk = *(uint_t *)mp->b_cont->b_rptr;
		miocack(wq, mp, 0, 0);
		sbclosechunk(sbp);
		return;

	case SBIOCSFLAGS:
		sbp->sb_flags = *(uint_t *)mp->b_cont->b_rptr;
		miocack(wq, mp, 0, 0);
		return;

	case SBIOCSSNAP:
		/*
		 * if chunking dont worry about effects of
		 * snipping of message size on head flow control
		 * since it has a relatively small bearing on the
		 * data rate onto the streamn head.
		 */
		if (!sbp->sb_chunk) {
			/*
			 * set up hi/lo water marks on stream head read queue.
			 * unlikely to run out of resources. Fix at later date.
			 */
			if ((mop = allocb(sizeof (struct stroptions),
			    BPRI_MED)) != NULL) {
				struct stroptions *sop;
				uint_t snap;
				int fudge;

				snap = *(uint_t *)mp->b_cont->b_rptr;
				mop->b_datap->db_type = M_SETOPTS;
				mop->b_wptr += sizeof (struct stroptions);
				sop = (struct stroptions *)mop->b_rptr;
				sop->so_flags = SO_HIWAT | SO_LOWAT;
				fudge = snap <= 100 ?   4 :
				    snap <= 400 ?   2 :
				    1;
				sop->so_hiwat = SNIT_HIWAT(snap, fudge);
				sop->so_lowat = SNIT_LOWAT(snap, fudge);
				qreply(wq, mop);
			}
		}

		sbp->sb_snap = *(uint_t *)mp->b_cont->b_rptr;
		miocack(wq, mp, 0, 0);
		return;

	default:
		ASSERT(0);
		return;
	}
}

/*
 * Write-side put procedure.  Its main task is to detect ioctls
 * for manipulating the buffering state and hand them to sbioctl.
 * Other message types are passed on through.
 */
static int
sbwput(queue_t *wq, mblk_t *mp)
{
	struct	sb	*sbp = (struct sb *)wq->q_ptr;
	struct copyresp *resp;

	if (sbp->sb_flags & SB_SEND_ON_WRITE)
		sbclosechunk(sbp);
	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		sbioctl(wq, mp);
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

		switch (resp->cp_cmd) {
		case SBIOCSTIME:
		case SBIOCSCHUNK:
		case SBIOCSFLAGS:
		case SBIOCSSNAP:
		case SBIOCGTIME:
		case SBIOCGCHUNK:
		case SBIOCGSNAP:
		case SBIOCGFLAGS:
			sbioc(wq, mp);
			break;

		default:
			putnext(wq, mp);
			break;
		}
		break;

	default:
		putnext(wq, mp);
		break;
	}
	return (0);
}

/*
 * Read-side put procedure.  It's responsible for buffering up incoming
 * messages and grouping them into aggregates according to the current
 * buffering parameters.
 */
static int
sbrput(queue_t *rq, mblk_t *mp)
{
	struct	sb	*sbp = (struct sb *)rq->q_ptr;

	ASSERT(sbp);

	switch (mp->b_datap->db_type) {
	case M_PROTO:
		if (sbp->sb_flags & SB_NO_PROTO_CVT) {
			sbclosechunk(sbp);
			sbsendit(rq, mp);
			break;
		} else {
			/*
			 * Convert M_PROTO to M_DATA.
			 */
			mp->b_datap->db_type = M_DATA;
		}
		/* FALLTHRU */

	case M_DATA:
		if ((sbp->sb_flags & SB_DEFER_CHUNK) &&
		    !(sbp->sb_state & SB_FRCVD)) {
			sbclosechunk(sbp);
			sbsendit(rq, mp);
			sbp->sb_state |= SB_FRCVD;
		} else
			sbaddmsg(rq, mp);

		if ((sbp->sb_ticks > 0) && !(sbp->sb_timeoutid))
			sbp->sb_timeoutid = qtimeout(sbp->sb_rq, sbtick,
			    sbp, sbp->sb_ticks);

		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			/*
			 * Reset timeout, flush the chunk currently in
			 * progress, and start a new chunk.
			 */
			if (sbp->sb_timeoutid) {
				(void) quntimeout(sbp->sb_rq,
				    sbp->sb_timeoutid);
				sbp->sb_timeoutid = 0;
			}
			if (sbp->sb_mp) {
				freemsg(sbp->sb_mp);
				sbp->sb_tail = sbp->sb_mp = sbp->sb_head = NULL;
				sbp->sb_mlen = 0;
				sbp->sb_mcount = 0;
			}
			flushq(rq, FLUSHALL);
		}
		putnext(rq, mp);
		break;

	case M_CTL:
		/*
		 * Zero-length M_CTL means our timeout() popped.
		 */
		if (MBLKL(mp) == 0) {
			freemsg(mp);
			sbclosechunk(sbp);
		} else {
			sbclosechunk(sbp);
			sbsendit(rq, mp);
		}
		break;

	default:
		if (mp->b_datap->db_type <= QPCTL) {
			sbclosechunk(sbp);
			sbsendit(rq, mp);
		} else {
			/* Note: out of band */
			putnext(rq, mp);
		}
		break;
	}
	return (0);
}

/*
 *  read service procedure.
 */
/* ARGSUSED */
static int
sbrsrv(queue_t *rq)
{
	mblk_t	*mp;

	/*
	 * High priority messages shouldn't get here but if
	 * one does, jam it through to avoid infinite loop.
	 */
	while ((mp = getq(rq)) != NULL) {
		if (!canputnext(rq) && (mp->b_datap->db_type <= QPCTL)) {
			/* should only get here if SB_NO_SROPS */
			(void) putbq(rq, mp);
			return (0);
		}
		putnext(rq, mp);
	}
	return (0);
}

/*
 * Handle write-side M_IOCTL messages.
 */
static void
sbioctl(queue_t *wq, mblk_t *mp)
{
	struct	sb	*sbp = (struct sb *)wq->q_ptr;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	struct	timeval	*t;
	clock_t	ticks;
	mblk_t	*mop;
	int	transparent = iocp->ioc_count;
	mblk_t	*datamp;
	int	error;

	switch (iocp->ioc_cmd) {
	case SBIOCSTIME:
		if (iocp->ioc_count == TRANSPARENT) {
#ifdef _SYSCALL32_IMPL
			if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				mcopyin(mp, NULL, sizeof (struct timeval32),
				    NULL);
			} else
#endif /* _SYSCALL32_IMPL */
			{
				mcopyin(mp, NULL, sizeof (*t), NULL);
			}
			qreply(wq, mp);
		} else {
			/*
			 * Verify argument length.
			 */
#ifdef _SYSCALL32_IMPL
			if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				struct timeval32 *t32;

				error = miocpullup(mp,
				    sizeof (struct timeval32));
				if (error != 0) {
					miocnak(wq, mp, 0, error);
					break;
				}
				t32 = (struct timeval32 *)mp->b_cont->b_rptr;
				if (t32->tv_sec < 0 || t32->tv_usec < 0) {
					miocnak(wq, mp, 0, EINVAL);
					break;
				}
				ticks = TIMEVAL_TO_TICK(t32);
			} else
#endif /* _SYSCALL32_IMPL */
			{
				error = miocpullup(mp, sizeof (struct timeval));
				if (error != 0) {
					miocnak(wq, mp, 0, error);
					break;
				}

				t = (struct timeval *)mp->b_cont->b_rptr;
				if (t->tv_sec < 0 || t->tv_usec < 0) {
					miocnak(wq, mp, 0, EINVAL);
					break;
				}
				ticks = TIMEVAL_TO_TICK(t);
			}
			sbp->sb_ticks = ticks;
			if (ticks == 0)
				sbp->sb_chunk = 0;
			miocack(wq, mp, 0, 0);
			sbclosechunk(sbp);
		}
		break;

	case SBIOCGTIME: {
		struct timeval *t;

		/*
		 * Verify argument length.
		 */
		if (transparent != TRANSPARENT) {
#ifdef _SYSCALL32_IMPL
			if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				error = miocpullup(mp,
				    sizeof (struct timeval32));
				if (error != 0) {
					miocnak(wq, mp, 0, error);
					break;
				}
			} else
#endif /* _SYSCALL32_IMPL */
			error = miocpullup(mp, sizeof (struct timeval));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}
		}

		/*
		 * If infinite timeout, return range error
		 * for the ioctl.
		 */
		if (sbp->sb_ticks < 0) {
			miocnak(wq, mp, 0, ERANGE);
			break;
		}

#ifdef _SYSCALL32_IMPL
		if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
			struct timeval32 *t32;

			if (transparent == TRANSPARENT) {
				datamp = allocb(sizeof (*t32), BPRI_MED);
				if (datamp == NULL) {
					miocnak(wq, mp, 0, EAGAIN);
					break;
				}
				mcopyout(mp, NULL, sizeof (*t32), NULL, datamp);
			}

			t32 = (struct timeval32 *)mp->b_cont->b_rptr;
			TICK_TO_TIMEVAL32(sbp->sb_ticks, t32);

			if (transparent == TRANSPARENT)
				qreply(wq, mp);
			else
				miocack(wq, mp, sizeof (*t32), 0);
		} else
#endif /* _SYSCALL32_IMPL */
		{
			if (transparent == TRANSPARENT) {
				datamp = allocb(sizeof (*t), BPRI_MED);
				if (datamp == NULL) {
					miocnak(wq, mp, 0, EAGAIN);
					break;
				}
				mcopyout(mp, NULL, sizeof (*t), NULL, datamp);
			}

			t = (struct timeval *)mp->b_cont->b_rptr;
			TICK_TO_TIMEVAL(sbp->sb_ticks, t);

			if (transparent == TRANSPARENT)
				qreply(wq, mp);
			else
				miocack(wq, mp, sizeof (*t), 0);
		}
		break;
	}

	case SBIOCCTIME:
		sbp->sb_ticks = -1;
		miocack(wq, mp, 0, 0);
		break;

	case SBIOCSCHUNK:
		if (iocp->ioc_count == TRANSPARENT) {
			mcopyin(mp, NULL, sizeof (uint_t), NULL);
			qreply(wq, mp);
		} else {
			/*
			 * Verify argument length.
			 */
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}

			/*
			 * set up hi/lo water marks on stream head read queue.
			 * unlikely to run out of resources. Fix at later date.
			 */
			if ((mop = allocb(sizeof (struct stroptions),
			    BPRI_MED)) != NULL) {
				struct stroptions *sop;
				uint_t chunk;

				chunk = *(uint_t *)mp->b_cont->b_rptr;
				mop->b_datap->db_type = M_SETOPTS;
				mop->b_wptr += sizeof (struct stroptions);
				sop = (struct stroptions *)mop->b_rptr;
				sop->so_flags = SO_HIWAT | SO_LOWAT;
				sop->so_hiwat = SNIT_HIWAT(chunk, 1);
				sop->so_lowat = SNIT_LOWAT(chunk, 1);
				qreply(wq, mop);
			}

			sbp->sb_chunk = *(uint_t *)mp->b_cont->b_rptr;
			miocack(wq, mp, 0, 0);
			sbclosechunk(sbp);
		}
		break;

	case SBIOCGCHUNK:
		/*
		 * Verify argument length.
		 */
		if (transparent != TRANSPARENT) {
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}
		}

		if (transparent == TRANSPARENT) {
			datamp = allocb(sizeof (uint_t), BPRI_MED);
			if (datamp == NULL) {
				miocnak(wq, mp, 0, EAGAIN);
				break;
			}
			mcopyout(mp, NULL, sizeof (uint_t), NULL, datamp);
		}

		*(uint_t *)mp->b_cont->b_rptr = sbp->sb_chunk;

		if (transparent == TRANSPARENT)
			qreply(wq, mp);
		else
			miocack(wq, mp, sizeof (uint_t), 0);
		break;

	case SBIOCSSNAP:
		if (iocp->ioc_count == TRANSPARENT) {
			mcopyin(mp, NULL, sizeof (uint_t), NULL);
			qreply(wq, mp);
		} else {
			/*
			 * Verify argument length.
			 */
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}

			/*
			 * if chunking dont worry about effects of
			 * snipping of message size on head flow control
			 * since it has a relatively small bearing on the
			 * data rate onto the streamn head.
			 */
			if (!sbp->sb_chunk) {
				/*
				 * set up hi/lo water marks on stream
				 * head read queue.  unlikely to run out
				 * of resources. Fix at later date.
				 */
				if ((mop = allocb(sizeof (struct stroptions),
				    BPRI_MED)) != NULL) {
					struct stroptions *sop;
					uint_t snap;
					int fudge;

					snap = *(uint_t *)mp->b_cont->b_rptr;
					mop->b_datap->db_type = M_SETOPTS;
					mop->b_wptr += sizeof (*sop);
					sop = (struct stroptions *)mop->b_rptr;
					sop->so_flags = SO_HIWAT | SO_LOWAT;
					fudge = (snap <= 100) ? 4 :
					    (snap <= 400) ? 2 : 1;
					sop->so_hiwat = SNIT_HIWAT(snap, fudge);
					sop->so_lowat = SNIT_LOWAT(snap, fudge);
					qreply(wq, mop);
				}
			}

			sbp->sb_snap = *(uint_t *)mp->b_cont->b_rptr;

			miocack(wq, mp, 0, 0);
		}
		break;

	case SBIOCGSNAP:
		/*
		 * Verify argument length
		 */
		if (transparent != TRANSPARENT) {
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}
		}

		if (transparent == TRANSPARENT) {
			datamp = allocb(sizeof (uint_t), BPRI_MED);
			if (datamp == NULL) {
				miocnak(wq, mp, 0, EAGAIN);
				break;
			}
			mcopyout(mp, NULL, sizeof (uint_t), NULL, datamp);
		}

		*(uint_t *)mp->b_cont->b_rptr = sbp->sb_snap;

		if (transparent == TRANSPARENT)
			qreply(wq, mp);
		else
			miocack(wq, mp, sizeof (uint_t), 0);
		break;

	case SBIOCSFLAGS:
		/*
		 * set the flags.
		 */
		if (iocp->ioc_count == TRANSPARENT) {
			mcopyin(mp, NULL, sizeof (uint_t), NULL);
			qreply(wq, mp);
		} else {
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}
			sbp->sb_flags = *(uint_t *)mp->b_cont->b_rptr;
			miocack(wq, mp, 0, 0);
		}
		break;

	case SBIOCGFLAGS:
		/*
		 * Verify argument length
		 */
		if (transparent != TRANSPARENT) {
			error = miocpullup(mp, sizeof (uint_t));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				break;
			}
		}

		if (transparent == TRANSPARENT) {
			datamp = allocb(sizeof (uint_t), BPRI_MED);
			if (datamp == NULL) {
				miocnak(wq, mp, 0, EAGAIN);
				break;
			}
			mcopyout(mp, NULL, sizeof (uint_t), NULL, datamp);
		}

		*(uint_t *)mp->b_cont->b_rptr = sbp->sb_flags;

		if (transparent == TRANSPARENT)
			qreply(wq, mp);
		else
			miocack(wq, mp, sizeof (uint_t), 0);
		break;


	default:
		putnext(wq, mp);
		break;
	}
}

/*
 * Given a length l, calculate the amount of extra storage
 * required to round it up to the next multiple of the alignment a.
 */
#define	RoundUpAmt(l, a)	((l) % (a) ? (a) - ((l) % (a)) : 0)
/*
 * Calculate additional amount of space required for alignment.
 */
#define	Align(l)		RoundUpAmt(l, sizeof (ulong_t))
/*
 * Smallest possible message size when headers are enabled.
 * This is used to calculate whether a chunk is nearly full.
 */
#define	SMALLEST_MESSAGE	sizeof (struct sb_hdr) + _POINTER_ALIGNMENT

/*
 * Process a read-side M_DATA message.
 *
 * If the currently accumulating chunk doesn't have enough room
 * for the message, close off the chunk, pass it upward, and start
 * a new one.  Then add the message to the current chunk, taking
 * account of the possibility that the message's size exceeds the
 * chunk size.
 *
 * If headers are enabled add an sb_hdr header and trailing alignment padding.
 *
 * To optimise performance the total number of msgbs should be kept
 * to a minimum. This is achieved by using any remaining space in message N
 * for both its own padding as well as the header of message N+1 if possible.
 * If there's insufficient space we allocate one message to hold this 'wrapper'.
 * (there's likely to be space beyond message N, since allocb would have
 * rounded up the required size to one of the dblk_sizes).
 *
 */
static void
sbaddmsg(queue_t *rq, mblk_t *mp)
{
	struct sb	*sbp;
	struct timeval	t;
	struct sb_hdr	hp;
	mblk_t *wrapper;	/* padding for msg N, header for msg N+1 */
	mblk_t *last;		/* last mblk of current message */
	size_t wrapperlen;	/* length of header + padding */
	size_t origlen;		/* data length before truncation */
	size_t pad;		/* bytes required to align header */

	sbp = (struct sb *)rq->q_ptr;

	origlen = msgdsize(mp);

	/*
	 * Truncate the message.
	 */
	if ((sbp->sb_snap > 0) && (origlen > sbp->sb_snap) &&
	    (adjmsg(mp, -(origlen - sbp->sb_snap)) == 1))
		hp.sbh_totlen = hp.sbh_msglen = sbp->sb_snap;
	else
		hp.sbh_totlen = hp.sbh_msglen = origlen;

	if (sbp->sb_flags & SB_NO_HEADER) {

		/*
		 * Would the inclusion of this message overflow the current
		 * chunk? If so close the chunk off and start a new one.
		 */
		if ((hp.sbh_totlen + sbp->sb_mlen) > sbp->sb_chunk)
			sbclosechunk(sbp);
		/*
		 * First message too big for chunk - just send it up.
		 * This will always be true when we're not chunking.
		 */
		if (hp.sbh_totlen > sbp->sb_chunk) {
			sbsendit(rq, mp);
			return;
		}

		/*
		 * We now know that the msg will fit in the chunk.
		 * Link it onto the end of the chunk.
		 * Since linkb() walks the entire chain, we keep a pointer to
		 * the first mblk of the last msgb added and call linkb on that
		 * that last message, rather than performing the
		 * O(n) linkb() operation on the whole chain.
		 * sb_head isn't needed in this SB_NO_HEADER mode.
		 */
		if (sbp->sb_mp)
			linkb(sbp->sb_tail, mp);
		else
			sbp->sb_mp = mp;

		sbp->sb_tail = mp;
		sbp->sb_mlen += hp.sbh_totlen;
		sbp->sb_mcount++;
	} else {
		/* Timestamp must be done immediately */
		uniqtime(&t);
		TIMEVAL_TO_TIMEVAL32(&hp.sbh_timestamp, &t);

		pad = Align(hp.sbh_totlen);
		hp.sbh_totlen += sizeof (hp);

		/* We can't fit this message on the current chunk. */
		if ((sbp->sb_mlen + hp.sbh_totlen) > sbp->sb_chunk)
			sbclosechunk(sbp);

		/*
		 * If we closed it (just now or during a previous
		 * call) then allocate the head of a new chunk.
		 */
		if (sbp->sb_head == NULL) {
			/* Allocate leading header of new chunk */
			sbp->sb_head = allocb(sizeof (hp), BPRI_MED);
			if (sbp->sb_head == NULL) {
				/*
				 * Memory allocation failure.
				 * This will need to be revisited
				 * since using certain flag combinations
				 * can result in messages being dropped
				 * silently.
				 */
				freemsg(mp);
				sbp->sb_drops++;
				return;
			}
			sbp->sb_mp = sbp->sb_head;
		}

		/*
		 * Set the header values and join the message to the
		 * chunk. The header values are copied into the chunk
		 * after we adjust for padding below.
		 */
		hp.sbh_drops = sbp->sb_drops;
		hp.sbh_origlen = origlen;
		linkb(sbp->sb_head, mp);
		sbp->sb_mcount++;
		sbp->sb_mlen += hp.sbh_totlen;

		/*
		 * There's no chance to fit another message on the
		 * chunk -- forgo the padding and close the chunk.
		 */
		if ((sbp->sb_mlen + pad + SMALLEST_MESSAGE) > sbp->sb_chunk) {
			(void) memcpy(sbp->sb_head->b_wptr, (char *)&hp,
			    sizeof (hp));
			sbp->sb_head->b_wptr += sizeof (hp);
			ASSERT(sbp->sb_head->b_wptr <=
			    sbp->sb_head->b_datap->db_lim);
			sbclosechunk(sbp);
			return;
		}

		/*
		 * We may add another message to this chunk -- adjust
		 * the headers for padding to be added below.
		 */
		hp.sbh_totlen += pad;
		(void) memcpy(sbp->sb_head->b_wptr, (char *)&hp, sizeof (hp));
		sbp->sb_head->b_wptr += sizeof (hp);
		ASSERT(sbp->sb_head->b_wptr <= sbp->sb_head->b_datap->db_lim);
		sbp->sb_mlen += pad;

		/*
		 * Find space for the wrapper. The wrapper consists of:
		 *
		 * 1) Padding for this message (this is to ensure each header
		 * begins on an 8 byte boundary in the userland buffer).
		 *
		 * 2) Space for the next message's header, in case the next
		 * next message will fit in this chunk.
		 *
		 * It may be possible to append the wrapper to the last mblk
		 * of the message, but only if we 'own' the data. If the dblk
		 * has been shared through dupmsg() we mustn't alter it.
		 */
		wrapperlen = (sizeof (hp) + pad);

		/* Is there space for the wrapper beyond the message's data ? */
		for (last = mp; last->b_cont; last = last->b_cont)
			;

		if ((wrapperlen <= MBLKTAIL(last)) &&
		    (last->b_datap->db_ref == 1)) {
			if (pad > 0) {
				/*
				 * Pad with zeroes to the next pointer boundary
				 * (we don't want to disclose kernel data to
				 * users), then advance wptr.
				 */
				(void) memset(last->b_wptr, 0, pad);
				last->b_wptr += pad;
			}
			/* Remember where to write the header information */
			sbp->sb_head = last;
		} else {
			/* Have to allocate additional space for the wrapper */
			wrapper = allocb(wrapperlen, BPRI_MED);
			if (wrapper == NULL) {
				sbclosechunk(sbp);
				return;
			}
			if (pad > 0) {
				/*
				 * Pad with zeroes (we don't want to disclose
				 * kernel data to users).
				 */
				(void) memset(wrapper->b_wptr, 0, pad);
				wrapper->b_wptr += pad;
			}
			/* Link the wrapper msg onto the end of the chunk */
			linkb(mp, wrapper);
			/* Remember to write the next header in this wrapper */
			sbp->sb_head = wrapper;
		}
	}
}

/*
 * Called from timeout().
 * Signal a timeout by passing a zero-length M_CTL msg in the read-side
 * to synchronize with any active module threads (open, close, wput, rput).
 */
static void
sbtick(void *arg)
{
	struct sb *sbp = arg;
	queue_t	*rq;

	ASSERT(sbp);

	rq = sbp->sb_rq;
	sbp->sb_timeoutid = 0;		/* timeout has fired */

	if (putctl(rq, M_CTL) == 0)	/* failure */
		sbp->sb_timeoutid = qtimeout(rq, sbtick, sbp, sbp->sb_ticks);
}

/*
 * Close off the currently accumulating chunk and pass
 * it upward.  Takes care of resetting timers as well.
 *
 * This routine is called both directly and as a result
 * of the chunk timeout expiring.
 */
static void
sbclosechunk(struct sb *sbp)
{
	mblk_t	*mp;
	queue_t	*rq;

	ASSERT(sbp);

	if (sbp->sb_timeoutid) {
		(void) quntimeout(sbp->sb_rq, sbp->sb_timeoutid);
		sbp->sb_timeoutid = 0;
	}

	mp = sbp->sb_mp;
	rq = sbp->sb_rq;

	/*
	 * If there's currently a chunk in progress, close it off
	 * and try to send it up.
	 */
	if (mp) {
		sbsendit(rq, mp);
	}

	/*
	 * Clear old chunk.  Ready for new msgs.
	 */
	sbp->sb_tail = sbp->sb_mp = sbp->sb_head = NULL;
	sbp->sb_mlen = 0;
	sbp->sb_mcount = 0;
	if (sbp->sb_flags & SB_DEFER_CHUNK)
		sbp->sb_state &= ~SB_FRCVD;

}

static void
sbsendit(queue_t *rq, mblk_t *mp)
{
	struct	sb	*sbp = (struct sb *)rq->q_ptr;

	if (!canputnext(rq)) {
		if (sbp->sb_flags & SB_NO_DROPS)
			(void) putq(rq, mp);
		else {
			freemsg(mp);
			sbp->sb_drops += sbp->sb_mcount;
		}
		return;
	}
	/*
	 * If there are messages on the q already, keep
	 * queueing them since they need to be processed in order.
	 */
	if (qsize(rq) > 0) {
		/* should only get here if SB_NO_DROPS */
		(void) putq(rq, mp);
	}
	else
		putnext(rq, mp);
}
