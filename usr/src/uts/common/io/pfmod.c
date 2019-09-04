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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * STREAMS Packet Filter Module
 *
 * This module applies a filter to messages arriving on its read
 * queue, passing on messages that the filter accepts adn discarding
 * the others.  It supports ioctls for setting the filter.
 *
 * On the write side, the module simply passes everything through
 * unchanged.
 *
 * Based on SunOS 4.x version.  This version has minor changes:
 *	- general SVR4 porting stuff
 *	- change name and prefixes from "nit" buffer to streams buffer
 *	- multithreading assumes configured as D_MTQPAIR
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/strsun.h>
#include <sys/pfmod.h>
#include <sys/modctl.h>

/*
 * Expanded version of the Packetfilt structure that includes
 * some additional fields that aid filter execution efficiency.
 */
struct epacketfilt {
	struct Pf_ext_packetfilt	pf;
#define	pf_Priority	pf.Pf_Priority
#define	pf_FilterLen	pf.Pf_FilterLen
#define	pf_Filter	pf.Pf_Filter
	/* pointer to word immediately past end of filter */
	ushort_t		*pf_FilterEnd;
	/* length in bytes of packet prefix the filter examines */
	ushort_t		pf_PByteLen;
};

/*
 * (Internal) packet descriptor for FilterPacket
 */
struct packdesc {
	ushort_t	*pd_hdr;	/* header starting address */
	uint_t		pd_hdrlen;	/* header length in shorts */
	ushort_t	*pd_body;	/* body starting address */
	uint_t		pd_bodylen;	/* body length in shorts */
};


/*
 * Function prototypes.
 */
static	int	pfopen(queue_t *, dev_t *, int, int, cred_t *);
static	int	pfclose(queue_t *, int, cred_t *);
static void	pfioctl(queue_t *wq, mblk_t *mp);
static	int	FilterPacket(struct packdesc *, struct epacketfilt *);
static int	pfwput(queue_t *, mblk_t *);
static int	pfrput(queue_t *, mblk_t *);

static struct module_info pf_minfo = {
	22,		/* mi_idnum */
	"pfmod",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	0,		/* mi_hiwat */
	0		/* mi_lowat */
};

static struct qinit pf_rinit = {
	pfrput,			/* qi_putp */
	NULL,
	pfopen,			/* qi_qopen */
	pfclose,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&pf_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit pf_winit = {
	pfwput,			/* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&pf_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab pf_info = {
	&pf_rinit,	/* st_rdinit */
	&pf_winit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwinit */
};

static struct fmodsw fsw = {
	"pfmod",
	&pf_info,
	D_MTQPAIR | D_MP
};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "streams packet filter module", &fsw
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

/*ARGSUSED*/
static int
pfopen(queue_t *rq, dev_t *dev, int oflag, int sflag, cred_t *crp)
{
	struct epacketfilt	*pfp;

	ASSERT(rq);

	if (sflag != MODOPEN)
		return (EINVAL);

	if (rq->q_ptr)
		return (0);

	/*
	 * Allocate and initialize per-Stream structure.
	 */
	pfp = kmem_alloc(sizeof (struct epacketfilt), KM_SLEEP);
	rq->q_ptr = WR(rq)->q_ptr = (char *)pfp;

	qprocson(rq);

	return (0);
}

/* ARGSUSED */
static int
pfclose(queue_t	*rq, int flags __unused, cred_t *credp __unused)
{
	struct	epacketfilt	*pfp = (struct epacketfilt *)rq->q_ptr;

	ASSERT(pfp);

	qprocsoff(rq);

	kmem_free(pfp, sizeof (struct epacketfilt));
	rq->q_ptr = WR(rq)->q_ptr = NULL;

	return (0);
}

/*
 * Write-side put procedure.  Its main task is to detect ioctls.
 * Other message types are passed on through.
 */
static int
pfwput(queue_t *wq, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		pfioctl(wq, mp);
		break;

	default:
		putnext(wq, mp);
		break;
	}
	return (0);
}

/*
 * Read-side put procedure.  It's responsible for applying the
 * packet filter and passing upstream message on or discarding it
 * depending upon the results.
 *
 * Upstream messages can start with zero or more M_PROTO mblks
 * which are skipped over before executing the packet filter
 * on any remaining M_DATA mblks.
 */
static int
pfrput(queue_t *rq, mblk_t *mp)
{
	struct	epacketfilt	*pfp = (struct epacketfilt *)rq->q_ptr;
	mblk_t	*mbp, *mpp;
	struct	packdesc	pd;
	int	need;

	ASSERT(pfp);

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_DATA:
		/*
		 * Skip over protocol information and find the start
		 * of the message body, saving the overall message
		 * start in mpp.
		 */
		for (mpp = mp; mp && (DB_TYPE(mp) == M_PROTO); mp = mp->b_cont)
			;

		/*
		 * Null body (exclusive of M_PROTO blocks) ==> accept.
		 * Note that a null body is not the same as an empty body.
		 */
		if (mp == NULL) {
			putnext(rq, mpp);
			break;
		}

		/*
		 * Pull the packet up to the length required by
		 * the filter.  Note that doing so destroys sharing
		 * relationships, which is unfortunate, since the
		 * results of pulling up here are likely to be useful
		 * for shared messages applied to a filter on a sibling
		 * stream.
		 *
		 * Most packet sources will provide the packet in two
		 * logical pieces: an initial header in a single mblk,
		 * and a body in a sequence of mblks hooked to the
		 * header.  We're prepared to deal with variant forms,
		 * but in any case, the pullup applies only to the body
		 * part.
		 */
		mbp = mp->b_cont;
		need = pfp->pf_PByteLen;
		if (mbp && (MBLKL(mbp) < need)) {
			int len = msgdsize(mbp);

			/* XXX discard silently on pullupmsg failure */
			if (pullupmsg(mbp, MIN(need, len)) == 0) {
				freemsg(mpp);
				break;
			}
		}

		/*
		 * Misalignment (not on short boundary) ==> reject.
		 */
		if (((uintptr_t)mp->b_rptr & (sizeof (ushort_t) - 1)) ||
		    (mbp != NULL &&
		    ((uintptr_t)mbp->b_rptr & (sizeof (ushort_t) - 1)))) {
			freemsg(mpp);
			break;
		}

		/*
		 * These assignments are distasteful, but necessary,
		 * since the packet filter wants to work in terms of
		 * shorts.  Odd bytes at the end of header or data can't
		 * participate in the filtering operation.
		 */
		pd.pd_hdr = (ushort_t *)mp->b_rptr;
		pd.pd_hdrlen = (mp->b_wptr - mp->b_rptr) / sizeof (ushort_t);
		if (mbp) {
			pd.pd_body = (ushort_t *)mbp->b_rptr;
			pd.pd_bodylen = (mbp->b_wptr - mbp->b_rptr) /
			    sizeof (ushort_t);
		} else {
			pd.pd_body = NULL;
			pd.pd_bodylen = 0;
		}

		/*
		 * Apply the filter.
		 */
		if (FilterPacket(&pd, pfp))
			putnext(rq, mpp);
		else
			freemsg(mpp);

		break;

	default:
		putnext(rq, mp);
		break;
	}
	return (0);
}

/*
 * Handle write-side M_IOCTL messages.
 */
static void
pfioctl(queue_t *wq, mblk_t *mp)
{
	struct	epacketfilt	*pfp = (struct epacketfilt *)wq->q_ptr;
	struct	Pf_ext_packetfilt	*upfp;
	struct	packetfilt	*opfp;
	ushort_t	*fwp;
	int	arg;
	int	maxoff = 0;
	int	maxoffreg = 0;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	int	error;

	switch (iocp->ioc_cmd) {
	case PFIOCSETF:
		/*
		 * Verify argument length. Since the size of packet filter
		 * got increased (ENMAXFILTERS was bumped up to 2047), to
		 * maintain backwards binary compatibility, we need to
		 * check for both possible sizes.
		 */
		switch (iocp->ioc_count) {
		case sizeof (struct Pf_ext_packetfilt):
			error = miocpullup(mp,
			    sizeof (struct Pf_ext_packetfilt));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				return;
			}
			upfp = (struct Pf_ext_packetfilt *)mp->b_cont->b_rptr;
			if (upfp->Pf_FilterLen > PF_MAXFILTERS) {
				miocnak(wq, mp, 0, EINVAL);
				return;
			}

			bcopy(upfp, pfp, sizeof (struct Pf_ext_packetfilt));
			pfp->pf_FilterEnd = &pfp->pf_Filter[pfp->pf_FilterLen];
			break;

		case sizeof (struct packetfilt):
			error = miocpullup(mp, sizeof (struct packetfilt));
			if (error != 0) {
				miocnak(wq, mp, 0, error);
				return;
			}
			opfp = (struct packetfilt *)mp->b_cont->b_rptr;
			/* this strange comparison keeps gcc from complaining */
			if (opfp->Pf_FilterLen - 1 >= ENMAXFILTERS) {
				miocnak(wq, mp, 0, EINVAL);
				return;
			}

			pfp->pf.Pf_Priority = opfp->Pf_Priority;
			pfp->pf.Pf_FilterLen = (unsigned int)opfp->Pf_FilterLen;

			bcopy(opfp->Pf_Filter, pfp->pf.Pf_Filter,
			    sizeof (opfp->Pf_Filter));
			pfp->pf_FilterEnd = &pfp->pf_Filter[pfp->pf_FilterLen];
			break;

		default:
			miocnak(wq, mp, 0, EINVAL);
			return;
		}

		/*
		 * Find and record maximum byte offset that the
		 * filter users.  We use this when executing the
		 * filter to determine how much of the packet
		 * body to pull up.  This code depends on the
		 * filter encoding.
		 */
		for (fwp = pfp->pf_Filter; fwp < pfp->pf_FilterEnd; fwp++) {
			arg = *fwp & ((1 << ENF_NBPA) - 1);
			switch (arg) {
			default:
				if ((arg -= ENF_PUSHWORD) > maxoff)
					maxoff = arg;
				break;

			case ENF_LOAD_OFFSET:
				/* Point to the offset */
				fwp++;
				if (*fwp > maxoffreg)
					maxoffreg = *fwp;
				break;

			case ENF_PUSHLIT:
			case ENF_BRTR:
			case ENF_BRFL:
				/* Skip over the literal. */
				fwp++;
				break;

			case ENF_PUSHZERO:
			case ENF_PUSHONE:
			case ENF_PUSHFFFF:
			case ENF_PUSHFF00:
			case ENF_PUSH00FF:
			case ENF_NOPUSH:
			case ENF_POP:
				break;
			}
		}

		/*
		 * Convert word offset to length in bytes.
		 */
		pfp->pf_PByteLen = (maxoff + maxoffreg + 1) * sizeof (ushort_t);
		miocack(wq, mp, 0, 0);
		break;

	default:
		putnext(wq, mp);
		break;
	}
}

/* #define	DEBUG	1 */
/* #define	INNERDEBUG	1 */

#ifdef	INNERDEBUG
#define	enprintf(a)	printf a
#else
#define	enprintf(a)
#endif

/*
 * Apply the packet filter given by pfp to the packet given by
 * pp.  Return nonzero iff the filter accepts the packet.
 *
 * The packet comes in two pieces, a header and a body, since
 * that's the most convenient form for our caller.  The header
 * is in contiguous memory, whereas the body is in a mbuf.
 * Our caller will have adjusted the mbuf chain so that its first
 * min(MLEN, length(body)) bytes are guaranteed contiguous.  For
 * the sake of efficiency (and some laziness) the filter is prepared
 * to examine only these two contiguous pieces.  Furthermore, it
 * assumes that the header length is even, so that there's no need
 * to glue the last byte of header to the first byte of data.
 */

#define	opx(i)	((i) >> ENF_NBPA)

static int
FilterPacket(struct packdesc *pp, struct epacketfilt *pfp)
{
	int		maxhdr = pp->pd_hdrlen;
	int		maxword = maxhdr + pp->pd_bodylen;
	ushort_t	*sp;
	ushort_t	*fp;
	ushort_t	*fpe;
	unsigned	op;
	unsigned	arg;
	unsigned	offreg = 0;
	ushort_t	stack[ENMAXFILTERS+1];

	fp = &pfp->pf_Filter[0];
	fpe = pfp->pf_FilterEnd;

	enprintf(("FilterPacket(%p, %p, %p, %p):\n", pp, pfp, fp, fpe));

	/*
	 * Push TRUE on stack to start.  The stack size is chosen such
	 * that overflow can't occur -- each operation can push at most
	 * one item on the stack, and the stack size equals the maximum
	 * program length.
	 */
	sp = &stack[ENMAXFILTERS];
	*sp = 1;

	while (fp < fpe) {
	op = *fp >> ENF_NBPA;
	arg = *fp & ((1 << ENF_NBPA) - 1);
	fp++;

	switch (arg) {
	default:
		arg -= ENF_PUSHWORD;
		/*
		 * Since arg is unsigned,
		 * if it were less than ENF_PUSHWORD before,
		 * it would now be huge.
		 */
		if (arg + offreg < maxhdr)
			*--sp = pp->pd_hdr[arg + offreg];
		else if (arg + offreg < maxword)
			*--sp = pp->pd_body[arg - maxhdr + offreg];
		else {
			enprintf(("=>0(len)\n"));
			return (0);
		}
		break;
	case ENF_PUSHLIT:
		*--sp = *fp++;
		break;
	case ENF_PUSHZERO:
		*--sp = 0;
		break;
	case ENF_PUSHONE:
		*--sp = 1;
		break;
	case ENF_PUSHFFFF:
		*--sp = 0xffff;
		break;
	case ENF_PUSHFF00:
		*--sp = 0xff00;
		break;
	case ENF_PUSH00FF:
		*--sp = 0x00ff;
		break;
	case ENF_LOAD_OFFSET:
		offreg = *fp++;
		break;
	case ENF_BRTR:
		if (*sp != 0)
			fp += *fp;
		else
			fp++;
		if (fp >= fpe) {
			enprintf(("BRTR: fp>=fpe\n"));
			return (0);
		}
		break;
	case ENF_BRFL:
		if (*sp == 0)
			fp += *fp;
		else
			fp++;
		if (fp >= fpe) {
			enprintf(("BRFL: fp>=fpe\n"));
			return (0);
		}
		break;
	case ENF_POP:
		++sp;
		if (sp > &stack[ENMAXFILTERS]) {
			enprintf(("stack underflow\n"));
			return (0);
		}
		break;
	case ENF_NOPUSH:
		break;
	}

	if (sp < &stack[2]) {	/* check stack overflow: small yellow zone */
		enprintf(("=>0(--sp)\n"));
		return (0);
	}

	if (op == ENF_NOP)
		continue;

	/*
	 * all non-NOP operators binary, must have at least two operands
	 * on stack to evaluate.
	 */
	if (sp > &stack[ENMAXFILTERS-2]) {
		enprintf(("=>0(sp++)\n"));
		return (0);
	}

	arg = *sp++;
	switch (op) {
	default:
		enprintf(("=>0(def)\n"));
		return (0);
	case opx(ENF_AND):
		*sp &= arg;
		break;
	case opx(ENF_OR):
		*sp |= arg;
		break;
	case opx(ENF_XOR):
		*sp ^= arg;
		break;
	case opx(ENF_EQ):
		*sp = (*sp == arg);
		break;
	case opx(ENF_NEQ):
		*sp = (*sp != arg);
		break;
	case opx(ENF_LT):
		*sp = (*sp < arg);
		break;
	case opx(ENF_LE):
		*sp = (*sp <= arg);
		break;
	case opx(ENF_GT):
		*sp = (*sp > arg);
		break;
	case opx(ENF_GE):
		*sp = (*sp >= arg);
		break;

	/* short-circuit operators */

	case opx(ENF_COR):
		if (*sp++ == arg) {
			enprintf(("=>COR %x\n", *sp));
			return (1);
		}
		break;
	case opx(ENF_CAND):
		if (*sp++ != arg) {
			enprintf(("=>CAND %x\n", *sp));
			return (0);
		}
		break;
	case opx(ENF_CNOR):
		if (*sp++ == arg) {
			enprintf(("=>COR %x\n", *sp));
			return (0);
		}
		break;
	case opx(ENF_CNAND):
		if (*sp++ != arg) {
			enprintf(("=>CNAND %x\n", *sp));
			return (1);
		}
		break;
	}
	}
	enprintf(("=>%x\n", *sp));
	return (*sp);
}
