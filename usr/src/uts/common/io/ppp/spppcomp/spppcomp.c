/*
 * spppcomp.c - STREAMS module for kernel-level compression and CCP support.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This module is derived from the original SVR4 STREAMS PPP compression
 * module originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * James Carlson <james.d.carlson@sun.com> and Adi Masputra
 * <adi.masputra@sun.com> rewrote and restructured the code for improved
 * performance and scalability.
 */

#define	RCSID	"$Id: spppcomp.c,v 1.0 2000/05/08 01:10:12 masputra Exp $"

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/kstat.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <net/vjcompress.h>

/* Defined for platform-neutral include file */
#define	PACKETPTR	mblk_t *
#include <net/ppp-comp.h>

#include "s_common.h"

#ifdef DEBUG
#define	SPC_DEBUG
#endif
#include "spppcomp.h"

/*
 * This is used to tag official Solaris sources.  Please do not define
 * "INTERNAL_BUILD" when building this software outside of Sun
 * Microsystems.
 */
#ifdef INTERNAL_BUILD
/* MODINFO is limited to 32 characters. */
const char spppcomp_module_description[] = "PPP 4.0 compression";
#else /* INTERNAL_BUILD */
const char spppcomp_module_description[] =
	"ANU PPP compression $Revision: 1.16$ ";

/* LINTED */
static const char buildtime[] = "Built " __DATE__ " at " __TIME__
#ifdef DEBUG
" DEBUG"
#endif
"\n";
#endif /* INTERNAL_BUILD */

static int	spppcomp_open(queue_t *, dev_t *, int, int, cred_t *);
static int	spppcomp_close(queue_t *, int, cred_t *);
static void	spppcomp_rput(queue_t *, mblk_t *);
static void	spppcomp_rsrv(queue_t *);
static void	spppcomp_wput(queue_t *, mblk_t *);
static void	spppcomp_wsrv(queue_t *);

#define	PPPCOMP_MI_MINPSZ	(0)
#define	PPPCOMP_MI_MAXPSZ	(INFPSZ)
#define	PPPCOMP_MI_HIWAT	(PPP_MTU * 20)
#define	PPPCOMP_MI_LOWAT	(PPP_MTU * 18)

static struct module_info spppcomp_modinfo = {
	COMP_MOD_ID,		/* mi_idnum */
	COMP_MOD_NAME,		/* mi_idname */
	PPPCOMP_MI_MINPSZ,	/* mi_minpsz */
	PPPCOMP_MI_MAXPSZ,	/* mi_maxpsz */
	PPPCOMP_MI_HIWAT,	/* mi_hiwat */
	PPPCOMP_MI_LOWAT	/* mi_lowat */
};

static struct qinit spppcomp_rinit = {
	(int (*)())spppcomp_rput, /* qi_putp */
	(int (*)())spppcomp_rsrv, /* qi_srvp */
	spppcomp_open,		/* qi_qopen */
	spppcomp_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&spppcomp_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit spppcomp_winit = {
	(int (*)())spppcomp_wput, /* qi_putp */
	(int (*)())spppcomp_wsrv, /* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&spppcomp_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

struct streamtab spppcomp_tab = {
	&spppcomp_rinit,	/* st_rdinit */
	&spppcomp_winit,	/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL			/* st_muxwinit */
};

/* Set non-zero to debug algorithm-specific problems alone. */
#define	ALG_DEBUG	0

#define	MAX_IPHLEN	(0x0f << 2)
#define	MAX_TCPHLEN	(0x0f << 2)
#define	MAX_TCPIPHLEN	(MAX_IPHLEN + MAX_TCPHLEN) /* max TCP/IP header size */
#define	MAX_VJHDR	(20)		/* max VJ compressed header size (?) */

#if 0
#define	DBGSTART	CE_CONT, COMP_MOD_NAME "%d: "
#define	CKDEBUG(x)	cmn_err x
#else
#define	DBGSTART	COMP_MOD_NAME "%d: "
#define	CKDEBUG(x)	printf x
#endif
#define	CPDEBUG(x)	(IS_CP_KDEBUG(cp) ? CKDEBUG(x) : (void)0)

/*
 * List of compressors we know about.
 */
#if DO_BSD_COMPRESS
extern struct compressor ppp_bsd_compress;
#endif
#if DO_DEFLATE
extern struct compressor ppp_deflate;
extern struct compressor ppp_deflate_draft;
#endif

struct compressor *ppp_compressors[] = {
#if DO_BSD_COMPRESS
	&ppp_bsd_compress,
#endif
#if DO_DEFLATE
	&ppp_deflate,
	&ppp_deflate_draft,
#endif
	NULL
};

/*
 * LCP_USE_DFLT() removed by James Carlson.  RFC 1661 section 6.6 has
 * this to say on the topic:
 *
 *    The Address and Control fields MUST NOT be compressed when sending
 *    any LCP packet.  This rule guarantees unambiguous recognition of
 *    LCP packets.
 */

static void	spppcomp_ioctl(queue_t *, mblk_t *, sppp_comp_t *);
static int	spppcomp_mctl(queue_t *, mblk_t *);
static mblk_t	*spppcomp_outpkt(queue_t *, mblk_t *);
static mblk_t	*spppcomp_inpkt(queue_t *, mblk_t *);
static int	spppcomp_kstat_update(kstat_t *, int);
static void	comp_ccp(queue_t *, mblk_t *, sppp_comp_t *, boolean_t);

/*
 * Values for checking inter-arrival times on interrupt stacks.  These
 * are used to prevent CPU hogging in interrupt context.
 */
#define	MIN_ARRIVAL_TIME	5000000	/* interarrival time in nanoseconds */
#define	MAX_FAST_ARRIVALS	10	/* maximum packet count */
hrtime_t spppcomp_min_arrival = MIN_ARRIVAL_TIME;

static const char *kstats_names[] = {
#ifdef SPCDEBUG_KSTATS_NAMES
	SPPPCOMP_KSTATS_NAMES,
	SPCDEBUG_KSTATS_NAMES
#else
	SPPPCOMP_KSTATS_NAMES
#endif
};
static const char *kstats64_names[] = { SPPPCOMP_KSTATS64_NAMES };

/*
 * spppcomp_open()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Common open procedure for module.
 */
/* ARGSUSED */
static int
spppcomp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	sppp_comp_t	*cp;

	if (q->q_ptr != NULL) {
		return (0);
	}
	if (sflag != MODOPEN) {
		return (EINVAL);
	}
	cp = kmem_zalloc(sizeof (sppp_comp_t), KM_SLEEP);
	q->q_ptr = WR(q)->q_ptr = (caddr_t)cp;

	cp->cp_mru = PPP_MRU;
	cp->cp_mtu = PPP_MTU;

	mutex_init(&cp->cp_pair_lock, NULL, MUTEX_DRIVER, NULL);
	vj_compress_init(&cp->cp_vj, -1);
	cp->cp_nxslots = -1;
	cp->cp_effort = -1;

	qprocson(q);
	return (0);
}

/*
 * spppcomp_close()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Common close procedure for module.
 */
/* ARGSUSED */
static int
spppcomp_close(queue_t *q, int flag, cred_t *credp)
{
	sppp_comp_t	*cp = q->q_ptr;

	qprocsoff(q);

	CPDEBUG((DBGSTART "close flags=0x%b\n",
	    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1), cp->cp_flags,
	    CP_FLAGSSTR));
	mutex_destroy(&cp->cp_pair_lock);
	if (cp->cp_kstats) {
		ASSERT(IS_CP_HASUNIT(cp));
		kstat_delete(cp->cp_kstats);
	}
	if (cp->cp_xstate != NULL) {
		(*cp->cp_xcomp->comp_free)(cp->cp_xstate);
	}
	if (cp->cp_rstate != NULL) {
		(*cp->cp_rcomp->decomp_free)(cp->cp_rstate);
	}
	kmem_free(cp, sizeof (sppp_comp_t));
	q->q_ptr = WR(q)->q_ptr = NULL;

	return (0);
}

/*
 * spppcomp_wput()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Write-side put procedure.  Packets from above us arrive here.
 *
 *	The data handling logic is a little tricky here.  We defer to
 *	the service routine if q_first isn't NULL (to preserve message
 *	ordering after deferring a previous message), bcanputnext() is
 *	FALSE (to handle flow control), or we need a lot of processing
 *	and we're in an interrupt context (on the theory that we're
 *	already on a very long call stack at that point).  Since many
 *	callers will be in a non-interrupt context, this means that
 *	most processing will be performed here in-line, and deferral
 *	occurs only when necessary.
 */
static void
spppcomp_wput(queue_t *q, mblk_t *mp)
{
	sppp_comp_t *cp = q->q_ptr;
	int flag;

	switch (MTYPE(mp)) {
	case M_DATA:
		if (q->q_first != NULL || !bcanputnext(q, mp->b_band) ||
		    ((cp->cp_flags & (COMP_VJC|CCP_COMP_RUN)) &&
		    servicing_interrupt())) {
#ifdef SPC_DEBUG
			cp->cp_out_queued++;
#endif
			if (!putq(q, mp))
				freemsg(mp);
		} else {
#ifdef SPC_DEBUG
			cp->cp_out_handled++;
#endif
			if ((mp = spppcomp_outpkt(q, mp)) != NULL)
				putnext(q, mp);
		}
		break;
	case M_IOCTL:
		spppcomp_ioctl(q, mp, cp);
		break;
	case M_CTL:
		mutex_enter(&cp->cp_pair_lock);
		flag = spppcomp_mctl(q, mp);
		mutex_exit(&cp->cp_pair_lock);
		if (flag != 0)
			putnext(q, mp);
		else
			freemsg(mp);
		break;
	case M_FLUSH:
		CPDEBUG((DBGSTART "wput M_FLUSH (0x%x) flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    *mp->b_rptr, cp->cp_flags,	CP_FLAGSSTR));
		/*
		 * Just discard pending data.  For CCP, any compressor
		 * dictionary sequencing problems caused by this will
		 * have to be handled by the compression protocol in
		 * use.  For VJ, we need to tell the compressor to
		 * start over.
		 */
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&cp->cp_pair_lock);
			flushq(q, FLUSHDATA);
			vj_compress_init(&cp->cp_vj, cp->cp_nxslots);
			mutex_exit(&cp->cp_pair_lock);
		}
		putnext(q, mp);
		break;
	default:
		if (bcanputnext(q, mp->b_band))
			putnext(q, mp);
		else if (!putq(q, mp))
			freemsg(mp);
		break;
	}
}

/*
 * spppcomp_wsrv()
 *
 * MT-Perimeters:
 *    exclusive inner
 *
 * Description:
 *    Write-side service procedure.
 */
static void
spppcomp_wsrv(queue_t *q)
{
	mblk_t		*mp;

	while ((mp = getq(q)) != NULL) {
		/*
		 * If the module below us is flow-controlled, then put
		 * this message back on the queue again.
		 */
		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			break;
		}
		if (MTYPE(mp) != M_DATA ||
		    (mp = spppcomp_outpkt(q, mp)) != NULL)
			putnext(q, mp);
	}
}

/*
 * spppcomp_outpkt()
 *
 * MT-Perimeters:
 *    exclusive inner
 *
 * Description:
 *    Process outgoing packet.  Returns new mblk_t pointer on success
 *    (caller should do putnext through q), NULL on failure (packet has
 *    been discarded).
 */
static mblk_t *
spppcomp_outpkt(queue_t *q, mblk_t *mp)
{
	mblk_t		*zmp;
	int		len;
	ushort_t	proto;
	sppp_comp_t	*cp = q->q_ptr;

	/*
	 * If the entire data size of the mblk is less than the length of the
	 * PPP header, then free it. We can't do much with such message anyway,
	 * since we can't determine what the PPP protocol is.
	 */
	len = msgsize(mp);
	if (MBLKL(mp) < PPP_HDRLEN) {
#ifdef SPC_DEBUG
		mutex_enter(&cp->cp_pair_lock);
		cp->cp_omsg_pull++;
		mutex_exit(&cp->cp_pair_lock);
#endif
		zmp = msgpullup(mp, PPP_HDRLEN);
		freemsg(mp);
		if ((mp = zmp) == NULL)
			goto msg_oerror;
	}

	proto = PPP_PROTOCOL(mp->b_rptr);

	/*
	 * Do VJ compression if requested.
	 */
	if (proto == PPP_IP && IS_COMP_VJC(cp) &&
	    MSG_BYTE(mp, PPP_HDRLEN+offsetof(struct ip, ip_p)) ==
	    IPPROTO_TCP) {
		uchar_t		*vjhdr;
		int		type;
		uint32_t	indata[(PPP_HDRLEN+MAX_TCPIPHLEN) /
		    sizeof (uint32_t)];
		uchar_t		*dp;
		int		tocopy, copied;
		mblk_t		*fmb;
		void		*srcp;
		int		thislen;


		tocopy = copied = MIN(len, sizeof (indata));
		/*
		 * If we can alter this dblk, and there's enough data
		 * here to work with, and it's nicely aligned, then
		 * avoid the data copy.
		 */
		if (DB_REF(mp) == 1 && MBLKL(mp) >= tocopy &&
		    ((uintptr_t)mp->b_rptr & 3) == 0) {
			/* Save off the address/control */
			indata[0] = *(uint32_t *)mp->b_rptr;
			srcp = (void *)(mp->b_rptr + PPP_HDRLEN);
		} else {
			fmb = mp;
			dp = (uchar_t *)indata;
			while (tocopy > 0) {
				thislen = MBLKL(fmb);
				if (tocopy > thislen) {
					bcopy(fmb->b_rptr, dp, thislen);
					dp += thislen;
					tocopy -= thislen;
					fmb = fmb->b_cont;
				} else {
					bcopy(fmb->b_rptr, dp, tocopy);
					break;
				}
			}
			srcp = (void *)(indata + PPP_HDRLEN/sizeof (*indata));
		}

		type = vj_compress_tcp((struct ip *)srcp, len - PPP_HDRLEN,
		    &cp->cp_vj, IS_COMP_VJCCID(cp), &vjhdr);

		/*
		 * If we're going to modify this packet, then we can't modify
		 * someone else's data.  Copy instead.
		 *
		 * (It would be nice to be able to avoid this data copy if CCP
		 * is also enabled.  That would require extensive
		 * modifications to the compression code.  Users should be
		 * told to disable VJ compression when using CCP.)
		 */
		if (type != TYPE_IP && DB_REF(mp) > 1) {
#ifdef SPC_DEBUG
			mutex_enter(&cp->cp_pair_lock);
			cp->cp_omsg_dcopy++;
			mutex_exit(&cp->cp_pair_lock);
#endif
			/* Copy just altered portion. */
			zmp = msgpullup(mp, copied);
			freemsg(mp);
			if ((mp = zmp) == NULL)
				goto msg_oerror;
		}

		switch (type) {
		case TYPE_UNCOMPRESSED_TCP:
			mp->b_rptr[3] = proto = PPP_VJC_UNCOMP;
			/* No need to update if it was done in place. */
			if (srcp ==
			    (void *)(indata + PPP_HDRLEN / sizeof (*indata))) {
				thislen = PPP_HDRLEN +
				    offsetof(struct ip, ip_p);
				zmp = mp;
				while (zmp != NULL) {
					if (MBLKL(zmp) > thislen) {
						zmp->b_rptr[thislen] =
						    ((struct ip *)srcp)->ip_p;
						break;
					}
					thislen -= MBLKL(zmp);
					zmp = zmp->b_cont;
				}
			}
			break;

		case TYPE_COMPRESSED_TCP:
			/* Calculate amount to remove from front */
			thislen = vjhdr - (uchar_t *)srcp;
			ASSERT(thislen >= 0);

			/* Try to do a cheap adjmsg by arithmetic first. */
			dp = mp->b_rptr + thislen;
			if (dp > mp->b_wptr) {
				if (!adjmsg(mp, thislen)) {
					freemsg(mp);
					goto msg_oerror;
				}
				dp = mp->b_rptr;
			}

			/*
			 * Now make sure first block is big enough to
			 * receive modified data.  If we modified in
			 * place, then no need to check or copy.
			 */
			copied -= thislen;
			ASSERT(copied >= PPP_HDRLEN);
			if (srcp !=
			    (void *)(indata + PPP_HDRLEN / sizeof (*indata)))
				copied = 0;
			mp->b_rptr = dp;
			if (MBLKL(mp) < copied) {
				zmp = msgpullup(mp, copied);
				freemsg(mp);
				if ((mp = zmp) == NULL)
					goto msg_oerror;
				dp = mp->b_rptr;
			}

			*dp++ = ((uchar_t *)indata)[0];	/* address */
			*dp++ = ((uchar_t *)indata)[1];	/* control  */
			*dp++ = 0;			/* protocol */
			*dp++ = proto = PPP_VJC_COMP;	/* protocol */
			copied -= PPP_HDRLEN;
			if (copied > 0) {
				bcopy(vjhdr, dp, copied);
			}
			break;
		}
	}

	/*
	 * Do packet compression if enabled.
	 */
	if (proto == PPP_CCP) {
		/*
		 * Handle any negotiation packets by changing compressor
		 * state.  Doing this here rather than with an ioctl keeps
		 * the negotiation and the data flow in sync.
		 */
		mutex_enter(&cp->cp_pair_lock);
		comp_ccp(q, mp, cp, B_FALSE);
		mutex_exit(&cp->cp_pair_lock);
	} else if (proto != PPP_LCP && IS_CCP_COMP_RUN(cp) &&
	    IS_CCP_ISUP(cp) && cp->cp_xstate != NULL) {
		mblk_t	*cmp = NULL;

		len = msgsize(mp);
		len = (*cp->cp_xcomp->compress)(cp->cp_xstate, &cmp, mp, len,
		    cp->cp_mtu + PPP_HDRLEN);

		if (cmp != NULL) {
			/* Success!  Discard uncompressed version */
			cmp->b_band = mp->b_band;
			freemsg(mp);
			mp = cmp;
		}
		if (len < 0) {
			/*
			 * Compressor failure; must discard this
			 * packet because the compressor dictionary is
			 * now corrupt.
			 */
			freemsg(mp);
			mutex_enter(&cp->cp_pair_lock);
			cp->cp_stats.ppp_oerrors++;
			mutex_exit(&cp->cp_pair_lock);
			(void) putnextctl1(RD(q), M_CTL, PPPCTL_OERROR);
			return (NULL);
		}
	}

	/*
	 * If either address and control field compression or protocol field
	 * compression is enabled, then we'll need a writable packet.  Copy if
	 * necessary.
	 */
	if ((cp->cp_flags & (COMP_AC|COMP_PROT)) && DB_REF(mp) > 1) {
#ifdef SPC_DEBUG
		mutex_enter(&cp->cp_pair_lock);
		cp->cp_omsg_dcopy++;
		mutex_exit(&cp->cp_pair_lock);
#endif
		zmp = copymsg(mp);
		freemsg(mp);
		if ((mp = zmp) == NULL)
			goto msg_oerror;
	}

	/*
	 * Do address/control and protocol compression if enabled.
	 */
	if (IS_COMP_AC(cp) && (proto != PPP_LCP)) {
		mp->b_rptr += 2;	/* drop address & ctrl fields */
		/*
		 * Protocol field compression omits the first byte if
		 * it would be 0x00, thus the check for < 0x100.
		 */
		if (proto < 0x100 && IS_COMP_PROT(cp)) {
			++mp->b_rptr;	/* drop high protocol byte */
		}
	} else if ((proto < 0x100) && IS_COMP_PROT(cp)) {
		/*
		 * shuffle up the address & ctrl fields
		 */
		mp->b_rptr[2] = mp->b_rptr[1];
		mp->b_rptr[1] = mp->b_rptr[0];
		++mp->b_rptr;
	}
	mutex_enter(&cp->cp_pair_lock);
	cp->cp_stats.ppp_opackets++;
	cp->cp_stats.ppp_obytes += msgsize(mp);
	mutex_exit(&cp->cp_pair_lock);

	CPDEBUG((DBGSTART "send (%ld bytes) flags=0x%b\n",
	    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1), msgsize(mp),
	    cp->cp_flags, CP_FLAGSSTR));
	return (mp);

msg_oerror:
	mutex_enter(&cp->cp_pair_lock);
	cp->cp_stats.ppp_oerrors++;
	mutex_exit(&cp->cp_pair_lock);
	(void) putnextctl1(RD(q), M_CTL, PPPCTL_OERROR);
	return (NULL);
}

/*
 * spppcomp_inner_ioctl()
 *
 * MT-Perimeters:
 *    exclusive inner; queue pair lock held.
 *
 * Description:
 *	Called by spppcomp_ioctl to handle state-affecting ioctls.
 *	Returns -1 if caller should do putnext, 0 for miocack, or >0
 *	for miocnak.  Must *NOT* do putnext in this routine, since
 *	lock is held here.
 */
static int
spppcomp_inner_ioctl(queue_t *q, mblk_t *mp)
{
	sppp_comp_t	*cp = q->q_ptr;
	int		flags;
	int		mask;
	int		rc;
	int		len;
	int		cmd;
	int		nxslots;
	int		nrslots;
	int		val;
	uchar_t		*opt_data;
	uint32_t	opt_len;
	struct compressor **comp;
	struct compressor *ccomp;
	struct iocblk	*iop;
	void		*xtemp;

	iop = (struct iocblk *)mp->b_rptr;
	rc = EINVAL;
	len = 0;
	switch (iop->ioc_cmd) {
	case PPPIO_CFLAGS:
		if (iop->ioc_count != 2 * sizeof (uint32_t) ||
		    mp->b_cont == NULL)
			break;

		flags = ((uint32_t *)mp->b_cont->b_rptr)[0];
		mask = ((uint32_t *)mp->b_cont->b_rptr)[1];

		cp->cp_flags = (cp->cp_flags & ~mask) | (flags & mask);

		if ((mask & CCP_ISOPEN) && !(flags & CCP_ISOPEN)) {
			cp->cp_flags &= ~CCP_ISUP & ~CCP_COMP_RUN &
			    ~CCP_DECOMP_RUN;
			if (cp->cp_xstate != NULL) {
				(*cp->cp_xcomp->comp_free)(cp->cp_xstate);
				cp->cp_xstate = NULL;
			}
			if (cp->cp_rstate != NULL) {
				(*cp->cp_rcomp->decomp_free)(cp->cp_rstate);
				cp->cp_rstate = NULL;
			}
		}

		CPDEBUG((DBGSTART
		    "PPPIO_CFLAGS xflags=0x%b xmask=0x%b flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    flags, CP_FLAGSSTR, mask,
		    CP_FLAGSSTR, cp->cp_flags, CP_FLAGSSTR));

		/* If we're not the last PPP-speaker, then pass along. */
		if (!IS_CP_LASTMOD(cp)) {
			return (-1);	/* putnext */
		}

		*(uint32_t *)mp->b_cont->b_rptr = cp->cp_flags;
		len = sizeof (uint32_t);
		rc = 0;
		break;

	case PPPIO_VJINIT:
		if (iop->ioc_count != 2 || mp->b_cont == NULL)
			break;
		/*
		 * Even though it's not passed along, we have to
		 * validate nrslots so that we don't agree to
		 * decompress anything we cannot.
		 */
		nxslots = mp->b_cont->b_rptr[0] + 1;
		nrslots = mp->b_cont->b_rptr[1] + 1;
		if (nxslots > MAX_STATES || nrslots > MAX_STATES)
			break;

		/* No need to lock here; just reading a word is atomic */
		/* mutex_enter(&cp->cp_pair_lock); */
		cp->cp_vj_last_ierrors = cp->cp_stats.ppp_ierrors;
		/* mutex_exit(&cp->cp_pair_lock); */
		vj_compress_init(&cp->cp_vj, nxslots);
		cp->cp_nxslots = nxslots;

		CPDEBUG((DBGSTART
		    "PPPIO_VJINIT txslots=%d rxslots=%d flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1), nxslots,
		    nrslots, cp->cp_flags, CP_FLAGSSTR));
		rc = 0;
		break;

	case PPPIO_XCOMP:
	case PPPIO_RCOMP:
		if (iop->ioc_count < 2 || mp->b_cont == NULL)
			break;
		/*
		 * The input data here is the raw CCP algorithm option
		 * from negotiation.  The format is always one byte of
		 * algorithm number, one byte of length, and
		 * (length-2) bytes of algorithm-dependent data.  The
		 * alloc routine is expected to parse and validate
		 * this.
		 */
		opt_data = mp->b_cont->b_rptr;
		opt_len = mp->b_cont->b_wptr - opt_data;
		if (opt_len > iop->ioc_count) {
			opt_len = iop->ioc_count;
		}
		len = mp->b_cont->b_rptr[1];
		if (len < 2 || len > opt_len)
			break;
		len = 0;
		for (comp = ppp_compressors; *comp != NULL; ++comp) {

			if ((*comp)->compress_proto != opt_data[0]) {
				continue;
			}
			rc = 0;
			if (iop->ioc_cmd == PPPIO_XCOMP) {
				/*
				 * A previous call may have fetched
				 * memory for a compressor that's now
				 * being retired or reset.  Free it
				 * using its mechanism for freeing
				 * stuff.
				 */
				if ((xtemp = cp->cp_xstate) != NULL) {
					cp->cp_flags &= ~CCP_ISUP &
					    ~CCP_COMP_RUN;
					cp->cp_xstate = NULL;
					(*cp->cp_xcomp->comp_free)(xtemp);
				}
				cp->cp_xcomp = *comp;
				cp->cp_xstate = (*comp)->comp_alloc(opt_data,
				    opt_len);

				if (cp->cp_xstate == NULL) {
					rc = ENOSR;
				}

				CPDEBUG((DBGSTART "PPPIO_XCOMP opt_proto=0x%x "
				    "opt_len=0x%d flags=0x%b\n",
				    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
				    (uchar_t)opt_data[0], opt_len,
				    cp->cp_flags,
				    CP_FLAGSSTR));
			} else {
				if ((xtemp = cp->cp_rstate) != NULL) {
					cp->cp_flags &= ~CCP_ISUP &
					    ~CCP_DECOMP_RUN;
					cp->cp_rstate = NULL;
					(*cp->cp_rcomp->decomp_free)(xtemp);
				}
				cp->cp_rcomp = *comp;
				cp->cp_rstate =
				    (*comp)->decomp_alloc(opt_data, opt_len);

				if (cp->cp_rstate == NULL) {
					rc = ENOSR;
				}

				CPDEBUG((DBGSTART "PPPIO_RCOMP opt_proto=0x%x "
				    "opt_len=0x%d flags=0x%b\n",
				    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
				    (uchar_t)opt_data[0], opt_len,
				    cp->cp_flags,
				    CP_FLAGSSTR));
			}
			if (rc == 0 && (*comp)->set_effort != NULL) {
				rc = (*(*comp)->set_effort)(cp->
				    cp_xcomp == *comp ? cp->cp_xstate : NULL,
				    cp->cp_rcomp == *comp ? cp->cp_rstate :
				    NULL, cp->cp_effort);
				if (rc != 0) {
					CKDEBUG((DBGSTART
					    "cannot set effort %d",
					    cp->cp_unit, cp->cp_effort));
					rc = 0;
				}
			}
			break;
		}
		break;

	case PPPIO_DEBUG:
		if (iop->ioc_count != sizeof (uint32_t) || mp->b_cont == NULL)
			break;

		cmd = *(uint32_t *)mp->b_cont->b_rptr;

		/* If it's not for us, then pass along. */
		if (cmd != PPPDBG_LOG + PPPDBG_COMP) {
			return (-1);	/* putnext */
		}
		cp->cp_flags |= CP_KDEBUG;

		CKDEBUG((DBGSTART "PPPIO_DEBUG log enabled flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    cp->cp_flags, CP_FLAGSSTR));
		rc = 0;
		break;

	case PPPIO_LASTMOD:
		cp->cp_flags |= CP_LASTMOD;
		CPDEBUG((DBGSTART "PPPIO_LASTMOD last module flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    cp->cp_flags, CP_FLAGSSTR));
		rc = 0;
		break;

	case PPPIO_COMPLEV:	/* set compression effort level */
		if (iop->ioc_count != sizeof (uint32_t) || mp->b_cont == NULL)
			break;
		val = *(uint32_t *)mp->b_cont->b_rptr;
		cp->cp_effort = val;
		/* Silently ignore if compressor doesn't understand this. */
		rc = 0;
		if ((ccomp = cp->cp_xcomp) != NULL &&
		    ccomp->set_effort != NULL) {
			rc = (*ccomp->set_effort)(cp->cp_xstate,
			    ccomp == cp->cp_rcomp ? cp->cp_rstate : NULL, val);
			if (rc != 0)
				break;
		}
		if ((ccomp = cp->cp_rcomp) != NULL && ccomp != cp->cp_xcomp &&
		    ccomp->set_effort != NULL)
			rc = (*ccomp->set_effort)(NULL, cp->cp_rstate, val);
		break;
	}
	if (rc == 0 && mp->b_cont != NULL)
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + len;
	return (rc);
}

/*
 * spppcomp_getcstat()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Called by spppcomp_ioctl as the result of receiving a PPPIO_GETCSTAT.
 */
static void
spppcomp_getcstat(queue_t *q, mblk_t *mp, sppp_comp_t *cp)
{
	mblk_t		*mpnext;
	struct ppp_comp_stats	*csp;

	ASSERT(cp != NULL);

	mpnext = allocb(sizeof (struct ppp_comp_stats), BPRI_MED);
	if (mpnext == NULL) {
		miocnak(q, mp, 0, ENOSR);
		return;
	}
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
	}
	mp->b_cont = mpnext;
	csp = (struct ppp_comp_stats *)mpnext->b_wptr;
	mpnext->b_wptr += sizeof (struct ppp_comp_stats);
	bzero((caddr_t)csp, sizeof (struct ppp_comp_stats));

	if (cp->cp_xstate != NULL) {
		(*cp->cp_xcomp->comp_stat)(cp->cp_xstate, &csp->c);
	}
	if (cp->cp_rstate != NULL) {
		(*cp->cp_rcomp->decomp_stat)(cp->cp_rstate, &csp->d);
	}

	miocack(q, mp, sizeof (struct ppp_comp_stats), 0);
}

/*
 * spppcomp_ioctl()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Called by spppcomp_wput as the result of receiving an M_IOCTL
 *    command.
 */
static void
spppcomp_ioctl(queue_t *q, mblk_t *mp, sppp_comp_t *cp)
{
	struct iocblk	*iop;
	int flag;

	ASSERT(cp != NULL);

	iop = (struct iocblk *)mp->b_rptr;
	switch (iop->ioc_cmd) {
	case PPPIO_CFLAGS:
	case PPPIO_VJINIT:
	case PPPIO_XCOMP:
	case PPPIO_RCOMP:
	case PPPIO_DEBUG:
	case PPPIO_LASTMOD:
	case PPPIO_COMPLEV:
		mutex_enter(&cp->cp_pair_lock);
		flag = spppcomp_inner_ioctl(q, mp);
		mutex_exit(&cp->cp_pair_lock);
		if (flag == -1) {
			putnext(q, mp);
		} else if (flag == 0) {
			miocack(q, mp,
			    mp->b_cont == NULL ? 0 : MBLKL(mp->b_cont), 0);
		} else {
			miocnak(q, mp, 0, flag);
		}
		break;

	case PPPIO_GETCSTAT:
		spppcomp_getcstat(q, mp, cp);
		break;

	case PPPIO_GTYPE:	/* get existing driver type */
		if (!IS_CP_LASTMOD(cp)) {
			putnext(q, mp);
			break;
		}
		freemsg(mp->b_next);
		mp->b_next = allocb(sizeof (uint32_t), BPRI_MED);
		if (mp->b_next == NULL) {
			miocnak(q, mp, 0, ENOSR);
		} else {
			*(uint32_t *)mp->b_cont->b_wptr = PPPTYP_HC;
			mp->b_cont->b_wptr += sizeof (uint32_t);
			miocack(q, mp, sizeof (uint32_t), 0);
		}
		break;

	default:
		putnext(q, mp);
		break;
	}
}

/*
 * spppcomp_mctl()
 *
 * MT-Perimeters:
 *    exclusive inner; queue pair lock held.
 *
 * Description:
 *	Called by spppcomp_wput as the result of receiving an M_CTL
 *	message from another STREAMS module, and returns non-zero if
 *	caller should do putnext or zero for freemsg.  Must *NOT* do
 *	putnext in this routine, since lock is held here.
 */
static int
spppcomp_mctl(queue_t *q, mblk_t *mp)
{
	sppp_comp_t		*cp = q->q_ptr;
	kstat_t			*ksp;
	char			unit[32];
	const char **cpp;
	kstat_named_t *knt;

	switch (*mp->b_rptr) {
	case PPPCTL_MTU:
		if (MBLKL(mp) < 4) {
			break;
		}
		cp->cp_mtu = ((ushort_t *)mp->b_rptr)[1];

		CPDEBUG((DBGSTART "PPPCTL_MTU (%d) flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    cp->cp_mtu, cp->cp_flags, CP_FLAGSSTR));
		break;
	case PPPCTL_MRU:
		if (MBLKL(mp) < 4) {
			break;
		}
		cp->cp_mru = ((ushort_t *)mp->b_rptr)[1];

		CPDEBUG((DBGSTART "PPPCTL_MRU (%d) flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    cp->cp_mru, cp->cp_flags, CP_FLAGSSTR));
		break;
	case PPPCTL_UNIT:
		if (MBLKL(mp) < 8) {
			break;
		}
		/* If PPPCTL_UNIT has already been issued, then ignore. */
		if (IS_CP_HASUNIT(cp)) {
			break;
		}
		ASSERT(cp->cp_kstats == NULL);
		cp->cp_unit = ((uint32_t *)mp->b_rptr)[1];

		/* Create kstats for this unit. */
		(void) sprintf(unit, "%s" "%d", COMP_MOD_NAME, cp->cp_unit);
		ksp = kstat_create(COMP_MOD_NAME, cp->cp_unit, unit, "net",
		    KSTAT_TYPE_NAMED, sizeof (spppcomp_kstats_t) /
		    sizeof (kstat_named_t), 0);

		if (ksp != NULL) {
			cp->cp_flags |= CP_HASUNIT;
			cp->cp_kstats = ksp;

			knt = (kstat_named_t *)ksp->ks_data;
			for (cpp = kstats_names;
			    cpp < kstats_names + Dim(kstats_names); cpp++) {
				kstat_named_init(knt, *cpp,
				    KSTAT_DATA_UINT32);
				knt++;
			}
			for (cpp = kstats64_names;
			    cpp < kstats64_names + Dim(kstats64_names); cpp++) {
				kstat_named_init(knt, *cpp,
				    KSTAT_DATA_UINT64);
				knt++;
			}
			ksp->ks_update = spppcomp_kstat_update;
			ksp->ks_private = (void *)cp;
			kstat_install(ksp);

			CPDEBUG((DBGSTART "PPPCTL_UNIT flags=0x%b\n",
			    cp->cp_unit, cp->cp_flags, CP_FLAGSSTR));
		}
		break;

	default:
		/* Forward unknown M_CTL messages along */
		return (1);
	}

	/*
	 * For known PPP M_CTL messages, forward along only if we're not the
	 * last PPP-aware module.
	 */
	if (IS_CP_LASTMOD(cp))
		return (0);
	return (1);
}

/*
 * spppcomp_rput()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Upper read-side put procedure.  Messages get here from below.
 *
 *	The data handling logic is a little more tricky here.  We
 *	defer to the service routine if q_first isn't NULL (to
 *	preserve message ordering after deferring a previous message),
 *	bcanputnext() is FALSE (to handle flow control), or we have
 *	done a lot of processing recently and we're about to do a lot
 *	more and we're in an interrupt context (on the theory that
 *	we're hogging the CPU in this case).
 */
static void
spppcomp_rput(queue_t *q, mblk_t *mp)
{
	sppp_comp_t		*cp = q->q_ptr;
	struct iocblk		*iop;
	struct ppp_stats64	*psp;
	boolean_t		inter;
	hrtime_t		curtime;

	switch (MTYPE(mp)) {
	case M_DATA:
		inter = servicing_interrupt();
		if (inter) {
			curtime = gethrtime();

			/*
			 * If little time has passed since last
			 * arrival, then bump the counter.
			 */
			if (curtime - cp->cp_lastfinish < spppcomp_min_arrival)
				cp->cp_fastin++;
			else
				cp->cp_fastin >>= 1;	/* a guess */
		}
		/*
		 * If we're not decompressing, then we'll be fast, so
		 * we don't have to worry about hogging here.  If we
		 * are decompressing, then we have to check the
		 * cp_fastin count.
		 */
		if ((!(cp->cp_flags & (CCP_DECOMP_RUN | DECOMP_VJC)) ||
		    cp->cp_fastin < MAX_FAST_ARRIVALS) &&
		    q->q_first == NULL && bcanputnext(q, mp->b_band)) {
#ifdef SPC_DEBUG
			cp->cp_in_handled++;
#endif
			if ((mp = spppcomp_inpkt(q, mp)) != NULL)
				putnext(q, mp);
			if (inter) {
				cp->cp_lastfinish = gethrtime();
			}
		} else {
			/* Deferring; provide a clean slate */
			cp->cp_fastin = 0;
#ifdef SPC_DEBUG
			cp->cp_in_queued++;
#endif
			if (!putq(q, mp))
				freemsg(mp);
		}
		break;
	case M_IOCACK:
		iop = (struct iocblk *)mp->b_rptr;
		/*
		 * Bundled with pppstats; no need to handle PPPIO_GETSTAT
		 * here since we'll never see it.
		 */
		if (iop->ioc_cmd == PPPIO_GETSTAT64 &&
		    iop->ioc_count == sizeof (struct ppp_stats64) &&
		    mp->b_cont != NULL) {
			/*
			 * This crock is to handle a badly-designed
			 * but well-known ioctl for ANU PPP.  Both
			 * link statistics and VJ statistics are
			 * requested together.
			 *
			 * Catch this on the way back from the
			 * spppasyn module so we can fill in the VJ
			 * stats.  This happens only when we have
			 * PPP-aware modules beneath us.
			 */
			psp = (struct ppp_stats64 *)mp->b_cont->b_rptr;
			psp->vj = cp->cp_vj.stats;
			CPDEBUG((DBGSTART
			    "PPPIO_GETSTAT64 (VJ filled) flags=0x%b\n",
			    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
			    cp->cp_flags, CP_FLAGSSTR));
		}
		putnext(q, mp);
		break;
	case M_CTL:
		/* Increase our statistics and forward it upstream. */
		mutex_enter(&cp->cp_pair_lock);
		if (*mp->b_rptr == PPPCTL_IERROR) {
			cp->cp_stats.ppp_ierrors++;
			cp->cp_ierr_low++;
		} else if (*mp->b_rptr == PPPCTL_OERROR) {
			cp->cp_stats.ppp_oerrors++;
			cp->cp_oerr_low++;
		}
		mutex_exit(&cp->cp_pair_lock);
		putnext(q, mp);
		break;

	case M_FLUSH:
		CPDEBUG((DBGSTART "rput M_FLUSH (0x%x) flags=0x%b\n",
		    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1),
		    *mp->b_rptr, cp->cp_flags,	CP_FLAGSSTR));
		/*
		 * Just discard pending data.  For CCP, any
		 * decompressor dictionary sequencing problems caused
		 * by this will have to be handled by the compression
		 * protocol in use.  For VJ, we need to give the
		 * decompressor a heads-up.
		 */
		if (*mp->b_rptr & FLUSHR) {
			mutex_enter(&cp->cp_pair_lock);
			flushq(q, FLUSHDATA);
			cp->cp_vj_last_ierrors = cp->cp_stats.ppp_ierrors;
			vj_uncompress_err(&cp->cp_vj);
			mutex_exit(&cp->cp_pair_lock);
		}
		putnext(q, mp);
		break;

	default:
		if (bcanputnext(q, mp->b_band))
			putnext(q, mp);
		else if (!putq(q, mp))
			freemsg(mp);
		break;
	}
}

/*
 * spppcomp_rsrv()
 *
 * MT-Perimeters:
 *    exclusive inner.
 *
 * Description:
 *    Upper read-side service procedure.  We handle data deferred from
 *    spppcomp_rput here.
 *
 *	The data on the queue are always compressed (unprocessed).
 *	The rput procedure tries to do decompression, but if it can't,
 *	it will put the unprocessed data on the queue for later
 *	handling.
 */
static void
spppcomp_rsrv(queue_t *q)
{
	mblk_t		*mp;

	while ((mp = getq(q)) != NULL) {
		/*
		 * If the module above us is flow-controlled, then put
		 * this message back on the queue again.
		 */
		if (!bcanputnext(q, mp->b_band)) {
			(void) putbq(q, mp);
			break;
		}
		if (MTYPE(mp) != M_DATA ||
		    (mp = spppcomp_inpkt(q, mp)) != NULL)
			putnext(q, mp);
	}
}

/*
 * spppcomp_inpkt()
 *
 * MT-Perimeters:
 *    exclusive inner
 *
 * Description:
 *    Process incoming packet.
 */
static mblk_t *
spppcomp_inpkt(queue_t *q, mblk_t *mp)
{
	ushort_t	proto;
	int		i;
	mblk_t		*zmp;
	mblk_t		*np;
	uchar_t		*dp;
	int		len;
	int		hlen;
	sppp_comp_t	*cp = q->q_ptr;

	len = msgsize(mp);

	mutex_enter(&cp->cp_pair_lock);
	cp->cp_stats.ppp_ibytes += len;
	cp->cp_stats.ppp_ipackets++;
	mutex_exit(&cp->cp_pair_lock);
	/*
	 * First work out the protocol and where the PPP header ends.
	 */
	i = 0;
	proto = MSG_BYTE(mp, 0);
	if (proto == PPP_ALLSTATIONS) {
		i = 2;
		proto = MSG_BYTE(mp, 2);
	}
	if ((proto & 1) == 0) {
		++i;
		proto = (proto << 8) + MSG_BYTE(mp, i);
	}
	hlen = i + 1;
	/*
	 * Now reconstruct a complete, contiguous PPP header at the
	 * start of the packet.
	 */
	if (hlen < (IS_DECOMP_AC(cp) ? 0 : 2) + (IS_DECOMP_PROT(cp) ? 1 : 2)) {
		/* count these? */
		goto bad;
	}
	if (mp->b_rptr + hlen > mp->b_wptr) {
		/*
		 * Header is known to be intact here; so adjmsg will do the
		 * right thing here.
		 */
		if (!adjmsg(mp, hlen)) {
			goto bad;
		}
		hlen = 0;
	}
	if (hlen != PPP_HDRLEN) {
		/*
		 * We need to put some bytes on the front of the packet
		 * to make a full-length PPP header. If we can put them
		 * in mp, we do, otherwise we tack another mblk on the
		 * front.
		 *
		 * XXX we really shouldn't need to carry around the address
		 * and control at this stage.  ACFC and PFC need to be
		 * reworked.
		 */
		dp = mp->b_rptr + hlen - PPP_HDRLEN;
		if ((dp < mp->b_datap->db_base) || (DB_REF(mp) > 1)) {

			np = allocb(PPP_HDRLEN, BPRI_MED);
			if (np == 0) {
				goto bad;
			}
			np->b_cont = mp;
			mp->b_rptr += hlen;
			mp = np;
			dp = mp->b_wptr;
			mp->b_wptr += PPP_HDRLEN;
		} else {
			mp->b_rptr = dp;
		}
		dp[0] = PPP_ALLSTATIONS;
		dp[1] = PPP_UI;
		dp[2] = (proto >> 8) & 0xff;
		dp[3] = proto & 0xff;
	}
	/*
	 * Now see if we have a compressed packet to decompress, or a
	 * CCP negotiation packet to take notice of.  It's guaranteed
	 * that at least PPP_HDRLEN bytes are contiguous in the first
	 * block now.
	 */
	proto = PPP_PROTOCOL(mp->b_rptr);
	if (proto == PPP_CCP) {
		len = msgsize(mp);
		if (mp->b_wptr < mp->b_rptr + len) {
#ifdef SPC_DEBUG
			mutex_enter(&cp->cp_pair_lock);
			cp->cp_imsg_ccp_pull++;
			mutex_exit(&cp->cp_pair_lock);
#endif
			zmp = msgpullup(mp, len);
			freemsg(mp);
			mp = zmp;
			if (mp == 0) {
				goto bad;
			}
		}
		mutex_enter(&cp->cp_pair_lock);
		comp_ccp(q, mp, cp, B_TRUE);
		mutex_exit(&cp->cp_pair_lock);
	} else if ((cp->cp_flags & (CCP_ISUP | CCP_DECOMP_RUN | CCP_ERR)) ==
	    (CCP_ISUP | CCP_DECOMP_RUN) && cp->cp_rstate != NULL) {
		int	rv;

		if ((proto == PPP_COMP) || (proto == PPP_COMPFRAG)) {
			rv = (*cp->cp_rcomp->decompress)(cp->cp_rstate, &mp);
			switch (rv) {
			case DECOMP_OK:
				break;
			case DECOMP_ERROR:
				cp->cp_flags |= CCP_ERROR;
				mutex_enter(&cp->cp_pair_lock);
				++cp->cp_stats.ppp_ierrors;
				mutex_exit(&cp->cp_pair_lock);
				(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
				break;
			case DECOMP_FATALERROR:
				cp->cp_flags |= CCP_FATALERROR;
				mutex_enter(&cp->cp_pair_lock);
				++cp->cp_stats.ppp_ierrors;
				mutex_exit(&cp->cp_pair_lock);
				(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
				break;
			}
			if (mp == NULL) {
				/* Decompress failed; data are gone. */
				return (NULL);
			}
		} else {
			/*
			 * For RFCs 1977 and 1979 (BSD Compress and Deflate),
			 * the compressor should send incompressible data
			 * without encapsulation and the receiver must update
			 * its decompression dictionary as though this data
			 * were received and decompressed.  This keeps the
			 * dictionaries in sync.
			 */
			rv = (*cp->cp_rcomp->incomp)(cp->cp_rstate, mp);
			if (rv < 0) {
				cp->cp_flags |= CCP_FATALERROR;
				mutex_enter(&cp->cp_pair_lock);
				++cp->cp_stats.ppp_ierrors;
				mutex_exit(&cp->cp_pair_lock);
				(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
			}
		}
	}
	/*
	 * Now do VJ decompression.
	 */
	proto = PPP_PROTOCOL(mp->b_rptr);
	if ((proto == PPP_VJC_COMP) || (proto == PPP_VJC_UNCOMP)) {

		len = msgsize(mp) - PPP_HDRLEN;

		if (!IS_DECOMP_VJC(cp) || (len <= 0)) {
			goto bad;
		}
		/*
		 * Advance past the ppp header.  Here we assume that the whole
		 * PPP header is in the first mblk.  (This should be true
		 * because the above code does pull-ups as necessary on raw
		 * data, and the decompressor engines all produce large blocks
		 * on output.)
		 */
		np = mp;
		dp = np->b_rptr + PPP_HDRLEN;
		if (dp >= mp->b_wptr) {
			np = np->b_cont;
			dp = np->b_rptr;
		}
		/*
		 * Make sure we have sufficient contiguous data at this point,
		 * which in most cases we will always do.
		 */
		hlen = (proto == PPP_VJC_COMP) ? MAX_VJHDR : MAX_TCPIPHLEN;
		if (hlen > len) {
			hlen = len;
		}
		if ((np->b_wptr < dp + hlen) || DB_REF(np) > 1) {
#ifdef SPC_DEBUG
			mutex_enter(&cp->cp_pair_lock);
			cp->cp_imsg_vj_pull++;
			mutex_exit(&cp->cp_pair_lock);
#endif
			zmp = msgpullup(mp, hlen + PPP_HDRLEN);
			freemsg(mp);
			mp = zmp;
			if (mp == NULL) {
				goto bad;
			}
			np = mp;
			dp = np->b_rptr + PPP_HDRLEN;
		}

		if (proto == PPP_VJC_COMP) {
			uchar_t		*iphdr;
			int		vjlen;
			uint_t		iphlen;
			int		errcnt;

			/*
			 * Decompress VJ-compressed packet.  First
			 * reset compressor if an input error has
			 * occurred.  (No need to lock statistics
			 * structure for read of a single word.)
			 */
			errcnt = cp->cp_stats.ppp_ierrors;
			if (errcnt != cp->cp_vj_last_ierrors) {
				cp->cp_vj_last_ierrors = errcnt;
				vj_uncompress_err(&cp->cp_vj);
			}

			vjlen = vj_uncompress_tcp(dp, np->b_wptr - dp, len,
			    &cp->cp_vj, &iphdr, &iphlen);

			if (vjlen < 0 || iphlen == 0) {
				/*
				 * so we don't reset next time
				 */
				mutex_enter(&cp->cp_pair_lock);
				++cp->cp_vj_last_ierrors;
				mutex_exit(&cp->cp_pair_lock);
				goto bad;
			}
			/*
			 * drop ppp and vj headers off
			 */
			if (mp != np) {
				freeb(mp);
				mp = np;
			}
			mp->b_rptr = dp + vjlen;
			/*
			 * allocate a new mblk for the ppp and
			 * ip headers
			 */
			np = allocb(iphlen + PPP_HDRLEN, BPRI_MED);
			if (np == NULL)
				goto bad;
			dp = np->b_rptr;
			/*
			 * reconstruct PPP header
			 */
			dp[0] = PPP_ALLSTATIONS;
			dp[1] = PPP_UI;
			dp[2] = PPP_IP >> 8;
			dp[3] = PPP_IP;
			/*
			 * prepend mblk with reconstructed TCP/IP header.
			 */
			bcopy((caddr_t)iphdr, (caddr_t)dp + PPP_HDRLEN, iphlen);
			np->b_wptr = dp + iphlen + PPP_HDRLEN;
			np->b_cont = mp;
			mp = np;
		} else {
			/*
			 * "Decompress" a VJ-uncompressed packet.
			 */
			mutex_enter(&cp->cp_pair_lock);
			cp->cp_vj_last_ierrors = cp->cp_stats.ppp_ierrors;
			mutex_exit(&cp->cp_pair_lock);
			if (!vj_uncompress_uncomp(dp, hlen, &cp->cp_vj)) {
				/*
				 * don't need to reset next time
				 */
				mutex_enter(&cp->cp_pair_lock);
				++cp->cp_vj_last_ierrors;
				mutex_exit(&cp->cp_pair_lock);
				goto bad;
			}
			/*
			 * fix up the PPP protocol field
			 */
			mp->b_rptr[3] = PPP_IP;
		}
	}
	CPDEBUG((DBGSTART "recv (%ld bytes) flags=0x%b\n",
	    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1), msgsize(mp),
	    cp->cp_flags, CP_FLAGSSTR));
	return (mp);

bad:
	if (mp != 0) {
		freemsg(mp);
	}
	mutex_enter(&cp->cp_pair_lock);
	cp->cp_stats.ppp_ierrors++;
	mutex_exit(&cp->cp_pair_lock);
	(void) putnextctl1(q, M_CTL, PPPCTL_IERROR);
	return (NULL);
}

/*
 * comp_ccp()
 *
 * Description:
 *    Called by spppcomp_outpkt and spppcomp_inpkt to handle a CCP
 *    negotiation packet being sent or received.  Here all the data in
 *    the packet is in a single mbuf.
 *
 *	Global state is updated.  Must be called with mutex held.
 */
/* ARGSUSED */
static void
comp_ccp(queue_t *q, mblk_t *mp, sppp_comp_t *cp, boolean_t rcvd)
{
	int	len;
	int	clen;
	uchar_t	*dp;

	len = msgsize(mp);
	if (len < PPP_HDRLEN + CCP_HDRLEN) {
		return;
	}
	dp = mp->b_rptr + PPP_HDRLEN;

	len -= PPP_HDRLEN;
	clen = CCP_LENGTH(dp);
	if (clen > len) {
		return;
	}

	CPDEBUG((DBGSTART "CCP code=%d flags=0x%b\n",
	    (IS_CP_HASUNIT(cp) ? cp->cp_unit : -1), CCP_CODE(dp),
	    cp->cp_flags, CP_FLAGSSTR));
	switch (CCP_CODE(dp)) {
	case CCP_CONFREQ:
	case CCP_TERMREQ:
	case CCP_TERMACK:
		cp->cp_flags &= ~CCP_ISUP;
		break;
	case CCP_CONFACK:
		if ((cp->cp_flags & (CCP_ISOPEN | CCP_ISUP)) == CCP_ISOPEN &&
		    clen >= CCP_HDRLEN + CCP_OPT_MINLEN &&
		    clen >= CCP_HDRLEN + CCP_OPT_LENGTH(dp + CCP_HDRLEN)) {

			int	rc;

			if (!rcvd) {
				rc = (*cp->cp_xcomp->comp_init)(cp->cp_xstate,
				    dp + CCP_HDRLEN, clen - CCP_HDRLEN,
				    cp->cp_unit, 0,
				    IS_CP_KDEBUG(cp) | ALG_DEBUG);

				if (cp->cp_xstate != NULL && rc != 0) {
					cp->cp_flags |= CCP_COMP_RUN;
				}
			} else {
				rc = (*cp->cp_rcomp->decomp_init)(cp->
				    cp_rstate, dp + CCP_HDRLEN,
				    clen - CCP_HDRLEN, cp->cp_unit, 0,
				    cp->cp_mru,
				    IS_CP_KDEBUG(cp) | ALG_DEBUG);

				if (cp->cp_rstate != NULL && rc != 0) {
					cp->cp_flags &= ~CCP_ERR;
					cp->cp_flags |= CCP_DECOMP_RUN;
				}
			}
		}
		break;
	case CCP_RESETACK:
		if (IS_CCP_ISUP(cp)) {
			if (!rcvd) {
				if (cp->cp_xstate != NULL &&
				    IS_CCP_COMP_RUN(cp)) {
					(*cp->cp_xcomp->comp_reset)(cp->
					    cp_xstate);
				}
			} else {
				if (cp->cp_rstate != NULL &&
				    IS_CCP_DECOMP_RUN(cp)) {
					(*cp->cp_rcomp->decomp_reset)(cp->
					    cp_rstate);
					cp->cp_flags &= ~CCP_ERROR;
				}
			}
		}
		break;
	}
}

/*
 * spppcomp_kstat_update()
 *
 * Description:
 *    Update per-unit kstat statistics.
 */
static int
spppcomp_kstat_update(kstat_t *ksp, int rw)
{
	sppp_comp_t		*cp = ksp->ks_private;
	spppcomp_kstats_t	*cpkp;
	struct vjstat		*sp;
	struct pppstat64	*psp;
	struct ppp_comp_stats		csp;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	cpkp = (spppcomp_kstats_t *)ksp->ks_data;
	bzero((caddr_t)&csp, sizeof (struct ppp_comp_stats));

	mutex_enter(&cp->cp_pair_lock);

	if (cp->cp_xstate != NULL) {
		(*cp->cp_xcomp->comp_stat)(cp->cp_xstate, &csp.c);
	}
	if (cp->cp_rstate != NULL) {
		(*cp->cp_rcomp->decomp_stat)(cp->cp_rstate, &csp.d);
	}

	sp = &cp->cp_vj.stats;

	cpkp->vj_out_pkts.value.ui32		= sp->vjs_packets;
	cpkp->vj_out_pkts_comp.value.ui32	= sp->vjs_compressed;
	cpkp->vj_cs_searches.value.ui32		= sp->vjs_searches;
	cpkp->vj_cs_misses.value.ui32		= sp->vjs_misses;
	cpkp->vj_in_pkts_uncomp.value.ui32	= sp->vjs_uncompressedin;
	cpkp->vj_in_pkts_comp.value.ui32	= sp->vjs_compressedin;
	cpkp->vj_in_error.value.ui32		= sp->vjs_errorin;
	cpkp->vj_in_tossed.value.ui32		= sp->vjs_tossed;

	psp = &cp->cp_stats;

	cpkp->out_bytes.value.ui64		= psp->ppp_obytes;
	cpkp->out_pkts.value.ui64		= psp->ppp_opackets;
	cpkp->out_errors.value.ui64		= psp->ppp_oerrors;
	cpkp->out_errors_low.value.ui32		= cp->cp_oerr_low;
	cpkp->out_uncomp_bytes.value.ui32	= csp.c.unc_bytes;
	cpkp->out_uncomp_pkts.value.ui32	= csp.c.unc_packets;
	cpkp->out_comp_bytes.value.ui32		= csp.c.comp_bytes;
	cpkp->out_comp_pkts.value.ui32		= csp.c.comp_packets;
	cpkp->out_incomp_bytes.value.ui32	= csp.c.inc_bytes;
	cpkp->out_incomp_pkts.value.ui32	= csp.c.inc_packets;

	cpkp->in_bytes.value.ui64		= psp->ppp_ibytes;
	cpkp->in_pkts.value.ui64		= psp->ppp_ipackets;
	cpkp->in_errors.value.ui64		= psp->ppp_ierrors;
	cpkp->in_errors_low.value.ui32		= cp->cp_ierr_low;
	cpkp->in_uncomp_bytes.value.ui32	= csp.d.unc_bytes;
	cpkp->in_uncomp_pkts.value.ui32		= csp.d.unc_packets;
	cpkp->in_comp_bytes.value.ui32		= csp.d.comp_bytes;
	cpkp->in_comp_pkts.value.ui32		= csp.d.comp_packets;
	cpkp->in_incomp_bytes.value.ui32	= csp.d.inc_bytes;
	cpkp->in_incomp_pkts.value.ui32		= csp.d.inc_packets;
#ifdef SPC_DEBUG
	cpkp->in_msg_ccp_pulledup.value.ui32	= cp->cp_imsg_ccp_pull;
	cpkp->in_msg_vj_pulledup.value.ui32	= cp->cp_imsg_vj_pull;
	cpkp->out_msg_pulledup.value.ui32	= cp->cp_omsg_pull;
	cpkp->out_msg_copied.value.ui32		= cp->cp_omsg_dcopy;
	cpkp->out_queued.value.ui32		= cp->cp_out_queued;
	cpkp->out_handled.value.ui32		= cp->cp_out_handled;
	cpkp->in_queued.value.ui32		= cp->cp_in_queued;
	cpkp->in_handled.value.ui32		= cp->cp_in_handled;
#endif
	mutex_exit(&cp->cp_pair_lock);
	return (0);
}
