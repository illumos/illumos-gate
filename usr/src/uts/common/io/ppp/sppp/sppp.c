/*
 * sppp.c - Solaris STREAMS PPP multiplexing pseudo-driver
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
 * This driver is derived from the original SVR4 STREAMS PPP driver
 * originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * Adi Masputra <adi.masputra@sun.com> rewrote and restructured the code
 * for improved performance and scalability.
 */

#define	RCSID	"$Id: sppp.c,v 1.0 2000/05/08 01:10:12 masputra Exp $"

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/kstat.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include "sppp.h"
#include "s_common.h"

/*
 * This is used to tag official Solaris sources.  Please do not define
 * "INTERNAL_BUILD" when building this software outside of Sun Microsystems.
 */
#ifdef INTERNAL_BUILD
/* MODINFO is limited to 32 characters. */
const char sppp_module_description[] = "PPP 4.0 mux";
#else /* INTERNAL_BUILD */
const char sppp_module_description[] = "ANU PPP mux";

/* LINTED */
static const char buildtime[] = "Built " __DATE__ " at " __TIME__
#ifdef DEBUG
" DEBUG"
#endif
"\n";
#endif /* INTERNAL_BUILD */

static void	sppp_inner_ioctl(queue_t *, mblk_t *);
static void	sppp_outer_ioctl(queue_t *, mblk_t *);
static queue_t	*sppp_send(queue_t *, mblk_t **, spppstr_t *);
static queue_t	*sppp_recv(queue_t *, mblk_t **, spppstr_t *);
static void	sppp_recv_nondata(queue_t *, mblk_t *, spppstr_t *);
static queue_t	*sppp_outpkt(queue_t *, mblk_t **, int, spppstr_t *);
static spppstr_t *sppp_inpkt(queue_t *, mblk_t *, spppstr_t *);
static int	sppp_kstat_update(kstat_t *, int);
static void 	sppp_release_pkts(sppa_t *, uint16_t);

/*
 * sps_list contains the list of active per-stream instance state structures
 * ordered on the minor device number (see sppp.h for details). All streams
 * opened to this driver are threaded together in this list.
 */
static spppstr_t *sps_list = NULL;
/*
 * ppa_list contains the list of active per-attachment instance state
 * structures ordered on the ppa id number (see sppp.h for details). All of
 * the ppa structures created once per PPPIO_NEWPPA ioctl are threaded together
 * in this list. There is exactly one ppa structure for a given PPP interface,
 * and multiple sps streams (upper streams) may share a ppa by performing
 * an attachment explicitly (PPPIO_ATTACH) or implicitly (DL_ATTACH_REQ).
 */
static sppa_t *ppa_list = NULL;

static const char *kstats_names[] = { SPPP_KSTATS_NAMES };
static const char *kstats64_names[] = { SPPP_KSTATS64_NAMES };

/*
 * map proto (which is an IANA defined ppp network protocol) to
 * a bit position indicated by NP_* in ppa_npflag
 */
static uint32_t
sppp_ppp2np(uint16_t proto)
{
	switch (proto) {
	case PPP_IP:
		return (NP_IP);
	case PPP_IPV6:
		return (NP_IPV6);
	default:
		return (0);
	}
}

/*
 * sppp_open()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer.
 *
 * Description:
 *    Common open procedure for module.
 */
/* ARGSUSED */
int
sppp_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	spppstr_t	*sps;
	spppstr_t	**nextmn;
	minor_t		mn;

	ASSERT(q != NULL && devp != NULL);
	ASSERT(sflag != MODOPEN);

	if (q->q_ptr != NULL) {
		return (0);		/* already open */
	}
	if (sflag != CLONEOPEN) {
		return (OPENFAIL);
	}
	/*
	 * The sps list is sorted using the minor number as the key. The
	 * following code walks the list to find the lowest valued minor
	 * number available to be used.
	 */
	mn = 0;
	for (nextmn = &sps_list; (sps = *nextmn) != NULL;
	    nextmn = &sps->sps_nextmn) {
		if (sps->sps_mn_id != mn) {
			break;
		}
		++mn;
	}
	sps = (spppstr_t *)kmem_zalloc(sizeof (spppstr_t), KM_SLEEP);
	ASSERT(sps != NULL);		/* KM_SLEEP must never return NULL */
	sps->sps_nextmn = *nextmn;	/* insert stream in global list */
	*nextmn = sps;
	sps->sps_mn_id = mn;		/* save minor id for this stream */
	sps->sps_rq = q;		/* save read queue pointer */
	sps->sps_sap = -1;		/* no sap bound to stream */
	sps->sps_dlstate = DL_UNATTACHED; /* dlpi state is unattached */
	sps->sps_npmode = NPMODE_DROP;	/* drop all packets initially */
	sps->sps_zoneid = crgetzoneid(credp);
	q->q_ptr = WR(q)->q_ptr = (caddr_t)sps;
	/*
	 * We explicitly disable the automatic queue scheduling for the
	 * write-side to obtain complete control over queuing during transmit.
	 * Packets will be queued at the upper write queue and the service
	 * routine will not be called until it gets scheduled by having the
	 * lower write service routine call the qenable(WR(uq)) for all streams
	 * attached to the same ppa instance.
	 */
	noenable(WR(q));
	*devp = makedevice(getmajor(*devp), mn);
	qprocson(q);
	return (0);
}

/*
 * Free storage used by a PPA.  This is not called until the last PPA
 * user closes their connection or reattaches to a different PPA.
 */
static void
sppp_free_ppa(sppa_t *ppa)
{
	sppa_t **nextppa;

	ASSERT(ppa->ppa_refcnt == 1);
	if (ppa->ppa_kstats != NULL) {
		kstat_delete(ppa->ppa_kstats);
		ppa->ppa_kstats = NULL;
	}
	mutex_destroy(&ppa->ppa_sta_lock);
	mutex_destroy(&ppa->ppa_npmutex);
	rw_destroy(&ppa->ppa_sib_lock);
	nextppa = &ppa_list;
	while (*nextppa != NULL) {
		if (*nextppa == ppa) {
			*nextppa = ppa->ppa_nextppa;
			break;
		}
		nextppa = &(*nextppa)->ppa_nextppa;
	}
	kmem_free(ppa, sizeof (*ppa));
}

/*
 * Create a new PPA.  Caller must be exclusive on outer perimeter.
 */
sppa_t *
sppp_create_ppa(uint32_t ppa_id, zoneid_t zoneid)
{
	sppa_t *ppa;
	sppa_t *curppa;
	sppa_t **availppa;
	char unit[32];		/* Unit name */
	const char **cpp;
	kstat_t *ksp;
	kstat_named_t *knt;

	/*
	 * NOTE: unit *must* be named for the driver
	 * name plus the ppa number so that netstat
	 * can find the statistics.
	 */
	(void) sprintf(unit, "%s" "%d", PPP_DRV_NAME, ppa_id);
	/*
	 * Make sure we can allocate a buffer to
	 * contain the ppa to be sent upstream, as
	 * well as the actual ppa structure and its
	 * associated kstat structure.
	 */
	ppa = (sppa_t *)kmem_zalloc(sizeof (sppa_t),
	    KM_NOSLEEP);
	ksp = kstat_create(PPP_DRV_NAME, ppa_id, unit, "net", KSTAT_TYPE_NAMED,
	    sizeof (sppp_kstats_t) / sizeof (kstat_named_t), 0);

	if (ppa == NULL || ksp == NULL) {
		if (ppa != NULL) {
			kmem_free(ppa, sizeof (sppa_t));
		}
		if (ksp != NULL) {
			kstat_delete(ksp);
		}
		return (NULL);
	}
	ppa->ppa_kstats = ksp;		/* chain kstat structure */
	ppa->ppa_ppa_id = ppa_id;	/* record ppa id */
	ppa->ppa_zoneid = zoneid;	/* zone that owns this PPA */
	ppa->ppa_mtu = PPP_MAXMTU;	/* 65535-(PPP_HDRLEN+PPP_FCSLEN) */
	ppa->ppa_mru = PPP_MAXMRU;	/* 65000 */

	mutex_init(&ppa->ppa_sta_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ppa->ppa_npmutex, NULL, MUTEX_DRIVER, NULL);
	rw_init(&ppa->ppa_sib_lock, NULL, RW_DRIVER, NULL);

	/*
	 * Prepare and install kstat counters.  Note that for netstat
	 * -i to work, there needs to be "ipackets", "opackets",
	 * "ierrors", and "oerrors" kstat named variables.
	 */
	knt = (kstat_named_t *)ksp->ks_data;
	for (cpp = kstats_names; cpp < kstats_names + Dim(kstats_names);
	    cpp++) {
		kstat_named_init(knt, *cpp, KSTAT_DATA_UINT32);
		knt++;
	}
	for (cpp = kstats64_names; cpp < kstats64_names + Dim(kstats64_names);
	    cpp++) {
		kstat_named_init(knt, *cpp, KSTAT_DATA_UINT64);
		knt++;
	}
	ksp->ks_update = sppp_kstat_update;
	ksp->ks_private = (void *)ppa;
	kstat_install(ksp);

	/* link to the next ppa and insert into global list */
	availppa = &ppa_list;
	while ((curppa = *availppa) != NULL) {
		if (ppa_id < curppa->ppa_ppa_id)
			break;
		availppa = &curppa->ppa_nextppa;
	}
	ppa->ppa_nextppa = *availppa;
	*availppa = ppa;
	return (ppa);
}

/*
 * sppp_close()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer.
 *
 * Description:
 *    Common close procedure for module.
 */
int
sppp_close(queue_t *q)
{
	spppstr_t	*sps;
	spppstr_t	**nextmn;
	spppstr_t	*sib;
	sppa_t		*ppa;
	mblk_t		*mp;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	qprocsoff(q);

	ppa = sps->sps_ppa;
	if (ppa == NULL) {
		ASSERT(!IS_SPS_CONTROL(sps));
		goto close_unattached;
	}
	if (IS_SPS_CONTROL(sps)) {
		uint32_t	cnt = 0;

		ASSERT(ppa != NULL);
		ASSERT(ppa->ppa_ctl == sps);
		ppa->ppa_ctl = NULL;
		/*
		 * STREAMS framework always issues I_UNLINK prior to close,
		 * since we only allow I_LINK under the control stream.
		 * A given ppa structure has at most one lower stream pointed
		 * by the ppa_lower_wq field, because we only allow a single
		 * linkage (I_LINK) to be done on the control stream.
		 */
		ASSERT(ppa->ppa_lower_wq == NULL);
		/*
		 * Walk through all of sibling streams attached to this ppa,
		 * and remove all references to this ppa. We have exclusive
		 * access for the entire driver here, so there's no need
		 * to hold ppa_sib_lock.
		 */
		cnt++;
		sib = ppa->ppa_streams;
		while (sib != NULL) {
			ASSERT(ppa == sib->sps_ppa);
			sib->sps_npmode = NPMODE_DROP;
			sib->sps_flags &= ~(SPS_PIOATTACH | SPS_CACHED);
			/*
			 * There should be a preallocated hangup
			 * message here.  Fetch it and send it up to
			 * the stream head.  This will cause IP to
			 * mark the interface as "down."
			 */
			if ((mp = sib->sps_hangup) != NULL) {
				sib->sps_hangup = NULL;
				/*
				 * M_HANGUP works with IP, but snoop
				 * is lame and requires M_ERROR.  Send
				 * up a clean error code instead.
				 *
				 * XXX if snoop is fixed, fix this, too.
				 */
				MTYPE(mp) = M_ERROR;
				*mp->b_wptr++ = ENXIO;
				putnext(sib->sps_rq, mp);
			}
			qenable(WR(sib->sps_rq));
			cnt++;
			sib = sib->sps_nextsib;
		}
		ASSERT(ppa->ppa_refcnt == cnt);
	} else {
		ASSERT(ppa->ppa_streams != NULL);
		ASSERT(ppa->ppa_ctl != sps);
		mp = NULL;
		if (sps->sps_sap == PPP_IP) {
			ppa->ppa_ip_cache = NULL;
			mp = create_lsmsg(PPP_LINKSTAT_IPV4_UNBOUND);
		} else if (sps->sps_sap == PPP_IPV6) {
			ppa->ppa_ip6_cache = NULL;
			mp = create_lsmsg(PPP_LINKSTAT_IPV6_UNBOUND);
		}
		/* Tell the daemon the bad news. */
		if (mp != NULL && ppa->ppa_ctl != NULL &&
		    (sps->sps_npmode == NPMODE_PASS ||
		    sps->sps_npmode == NPMODE_QUEUE)) {
			putnext(ppa->ppa_ctl->sps_rq, mp);
		} else {
			freemsg(mp);
		}
		/*
		 * Walk through all of sibling streams attached to the
		 * same ppa, and remove this stream from the sibling
		 * streams list. We have exclusive access for the
		 * entire driver here, so there's no need to hold
		 * ppa_sib_lock.
		 */
		sib = ppa->ppa_streams;
		if (sib == sps) {
			ppa->ppa_streams = sps->sps_nextsib;
		} else {
			while (sib->sps_nextsib != NULL) {
				if (sib->sps_nextsib == sps) {
					sib->sps_nextsib = sps->sps_nextsib;
					break;
				}
				sib = sib->sps_nextsib;
			}
		}
		sps->sps_nextsib = NULL;
		freemsg(sps->sps_hangup);
		sps->sps_hangup = NULL;
		/*
		 * Check if this is a promiscous stream. If the SPS_PROMISC bit
		 * is still set, it means that the stream is closed without
		 * ever having issued DL_DETACH_REQ or DL_PROMISCOFF_REQ.
		 * In this case, we simply decrement the promiscous counter,
		 * and it's safe to do it without holding ppa_sib_lock since
		 * we're exclusive (inner and outer) at this point.
		 */
		if (IS_SPS_PROMISC(sps)) {
			ASSERT(ppa->ppa_promicnt > 0);
			ppa->ppa_promicnt--;
		}
	}
	/* If we're the only one left, then delete now. */
	if (ppa->ppa_refcnt <= 1)
		sppp_free_ppa(ppa);
	else
		ppa->ppa_refcnt--;
close_unattached:
	q->q_ptr = WR(q)->q_ptr = NULL;
	for (nextmn = &sps_list; *nextmn != NULL;
	    nextmn = &(*nextmn)->sps_nextmn) {
		if (*nextmn == sps) {
			*nextmn = sps->sps_nextmn;
			break;
		}
	}
	kmem_free(sps, sizeof (spppstr_t));
	return (0);
}

static void
sppp_ioctl(struct queue *q, mblk_t *mp)
{
	spppstr_t	*sps;
	spppstr_t	*nextsib;
	sppa_t		*ppa;
	struct iocblk	*iop;
	mblk_t		*nmp;
	enum NPmode	npmode;
	struct ppp_idle	*pip;
	struct ppp_stats64 *psp;
	struct ppp_comp_stats *pcsp;
	hrtime_t	hrtime;
	int		sap;
	int		count = 0;
	int		error = EINVAL;

	sps = (spppstr_t *)q->q_ptr;
	ppa = sps->sps_ppa;

	iop = (struct iocblk *)mp->b_rptr;
	switch (iop->ioc_cmd) {
	case PPPIO_NPMODE:
		if (!IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		} else if (iop->ioc_count != 2 * sizeof (uint32_t) ||
		    (mp->b_cont == NULL)) {
			error = EPROTO;
			break;
		}
		ASSERT(ppa != NULL);
		ASSERT(mp->b_cont->b_rptr != NULL);
		ASSERT(sps->sps_npmode == NPMODE_PASS);
		sap = ((uint32_t *)mp->b_cont->b_rptr)[0];
		npmode = (enum NPmode)((uint32_t *)mp->b_cont->b_rptr)[1];
		/*
		 * Walk the sibling streams which belong to the same
		 * ppa, and try to find a stream with matching sap
		 * number.
		 */
		rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
		for (nextsib = ppa->ppa_streams; nextsib != NULL;
		    nextsib = nextsib->sps_nextsib) {
			if (nextsib->sps_sap == sap) {
				break;	/* found it */
			}
		}
		if (nextsib == NULL) {
			rw_exit(&ppa->ppa_sib_lock);
			break;		/* return EINVAL */
		} else {
			nextsib->sps_npmode = npmode;
			if ((nextsib->sps_npmode != NPMODE_QUEUE) &&
			    (WR(nextsib->sps_rq)->q_first != NULL)) {
				qenable(WR(nextsib->sps_rq));
			}
		}
		rw_exit(&ppa->ppa_sib_lock);
		error = 0;	/* return success */
		break;
	case PPPIO_GIDLE:
		if (ppa == NULL) {
			ASSERT(!IS_SPS_CONTROL(sps));
			error = ENOLINK;
			break;
		} else if (!IS_PPA_TIMESTAMP(ppa)) {
			break;		/* return EINVAL */
		}
		if ((nmp = allocb(sizeof (struct ppp_idle),
		    BPRI_MED)) == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			error = ENOSR;
			break;
		}
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = nmp;
		pip = (struct ppp_idle *)nmp->b_wptr;
		nmp->b_wptr += sizeof (struct ppp_idle);
		/*
		 * Get current timestamp and subtract the tx and rx
		 * timestamps to get the actual idle time to be
		 * returned.
		 */
		hrtime = gethrtime();
		pip->xmit_idle = (hrtime - ppa->ppa_lasttx) / 1000000000ul;
		pip->recv_idle = (hrtime - ppa->ppa_lastrx) / 1000000000ul;
		count = msgsize(nmp);
		error = 0;
		break;		/* return success (error is 0) */
	case PPPIO_GTYPE:
		nmp = allocb(sizeof (uint32_t), BPRI_MED);
		if (nmp == NULL) {
			error = ENOSR;
			break;
		}
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = nmp;
		/*
		 * Let the requestor know that we are the PPP
		 * multiplexer (PPPTYP_MUX).
		 */
		*(uint32_t *)nmp->b_wptr = PPPTYP_MUX;
		nmp->b_wptr += sizeof (uint32_t);
		count = msgsize(nmp);
		error = 0;		/* return success */
		break;
	case PPPIO_GETSTAT64:
		if (ppa == NULL) {
			break;		/* return EINVAL */
		} else if ((ppa->ppa_lower_wq != NULL) &&
		    !IS_PPA_LASTMOD(ppa)) {
			mutex_enter(&ppa->ppa_sta_lock);
			/*
			 * We match sps_ioc_id on the M_IOC{ACK,NAK},
			 * so if the response hasn't come back yet,
			 * new ioctls must be queued instead.
			 */
			if (IS_SPS_IOCQ(sps)) {
				mutex_exit(&ppa->ppa_sta_lock);
				if (!putq(q, mp)) {
					error = EAGAIN;
					break;
				}
				return;
			} else {
				ppa->ppa_ioctlsfwd++;
				/*
				 * Record the ioctl CMD & ID - this will be
				 * used to check the ACK or NAK responses
				 * coming from below.
				 */
				sps->sps_ioc_id = iop->ioc_id;
				sps->sps_flags |= SPS_IOCQ;
				mutex_exit(&ppa->ppa_sta_lock);
			}
			putnext(ppa->ppa_lower_wq, mp);
			return;	/* don't ack or nak the request */
		}
		nmp = allocb(sizeof (*psp), BPRI_MED);
		if (nmp == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			error = ENOSR;
			break;
		}
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = nmp;
		psp = (struct ppp_stats64 *)nmp->b_wptr;
		/*
		 * Copy the contents of ppp_stats64 structure for this
		 * ppa and return them to the caller.
		 */
		mutex_enter(&ppa->ppa_sta_lock);
		bcopy(&ppa->ppa_stats, psp, sizeof (*psp));
		mutex_exit(&ppa->ppa_sta_lock);
		nmp->b_wptr += sizeof (*psp);
		count = sizeof (*psp);
		error = 0;		/* return success */
		break;
	case PPPIO_GETCSTAT:
		if (ppa == NULL) {
			break;		/* return EINVAL */
		} else if ((ppa->ppa_lower_wq != NULL) &&
		    !IS_PPA_LASTMOD(ppa)) {
			mutex_enter(&ppa->ppa_sta_lock);
			/*
			 * See comments in PPPIO_GETSTAT64 case
			 * in sppp_ioctl().
			 */
			if (IS_SPS_IOCQ(sps)) {
				mutex_exit(&ppa->ppa_sta_lock);
				if (!putq(q, mp)) {
					error = EAGAIN;
					break;
				}
				return;
			} else {
				ppa->ppa_ioctlsfwd++;
				/*
				 * Record the ioctl CMD & ID - this will be
				 * used to check the ACK or NAK responses
				 * coming from below.
				 */
				sps->sps_ioc_id = iop->ioc_id;
				sps->sps_flags |= SPS_IOCQ;
				mutex_exit(&ppa->ppa_sta_lock);
			}
			putnext(ppa->ppa_lower_wq, mp);
			return;	/* don't ack or nak the request */
		}
		nmp = allocb(sizeof (struct ppp_comp_stats), BPRI_MED);
		if (nmp == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			error = ENOSR;
			break;
		}
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = nmp;
		pcsp = (struct ppp_comp_stats *)nmp->b_wptr;
		nmp->b_wptr += sizeof (struct ppp_comp_stats);
		bzero((caddr_t)pcsp, sizeof (struct ppp_comp_stats));
		count = msgsize(nmp);
		error = 0;		/* return success */
		break;
	}

	if (error == 0) {
		/* Success; tell the user. */
		miocack(q, mp, count, 0);
	} else {
		/* Failure; send error back upstream. */
		miocnak(q, mp, 0, error);
	}
}

/*
 * sppp_uwput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Upper write-side put procedure. Messages from above arrive here.
 */
void
sppp_uwput(queue_t *q, mblk_t *mp)
{
	queue_t		*nextq;
	spppstr_t	*sps;
	sppa_t		*ppa;
	struct iocblk	*iop;
	int		error;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	sps = (spppstr_t *)q->q_ptr;
	ppa = sps->sps_ppa;

	switch (MTYPE(mp)) {
	case M_PCPROTO:
	case M_PROTO:
		if (IS_SPS_CONTROL(sps)) {
			ASSERT(ppa != NULL);
			/*
			 * Intentionally change this to a high priority
			 * message so it doesn't get queued up. M_PROTO is
			 * specifically used for signalling between pppd and its
			 * kernel-level component(s), such as ppptun, so we
			 * make sure that it doesn't get queued up behind
			 * data messages.
			 */
			MTYPE(mp) = M_PCPROTO;
			if ((ppa->ppa_lower_wq != NULL) &&
			    canputnext(ppa->ppa_lower_wq)) {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_mctlsfwd++;
				mutex_exit(&ppa->ppa_sta_lock);
				putnext(ppa->ppa_lower_wq, mp);
			} else {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_mctlsfwderr++;
				mutex_exit(&ppa->ppa_sta_lock);
				freemsg(mp);
			}
		} else {
			(void) sppp_mproto(q, mp, sps);
			return;
		}
		break;
	case M_DATA:
		if ((nextq = sppp_send(q, &mp, sps)) != NULL)
			putnext(nextq, mp);
		break;
	case M_IOCTL:
		error = EINVAL;
		iop = (struct iocblk *)mp->b_rptr;
		switch (iop->ioc_cmd) {
		case DLIOCRAW:
		case DL_IOC_HDR_INFO:
		case PPPIO_ATTACH:
		case PPPIO_DEBUG:
		case PPPIO_DETACH:
		case PPPIO_LASTMOD:
		case PPPIO_MRU:
		case PPPIO_MTU:
		case PPPIO_USETIMESTAMP:
		case PPPIO_BLOCKNP:
		case PPPIO_UNBLOCKNP:
			qwriter(q, mp, sppp_inner_ioctl, PERIM_INNER);
			return;
		case I_LINK:
		case I_UNLINK:
		case PPPIO_NEWPPA:
			qwriter(q, mp, sppp_outer_ioctl, PERIM_OUTER);
			return;
		case PPPIO_NPMODE:
		case PPPIO_GIDLE:
		case PPPIO_GTYPE:
		case PPPIO_GETSTAT64:
		case PPPIO_GETCSTAT:
			/*
			 * These require additional auto variables to
			 * handle, so (for optimization reasons)
			 * they're moved off to a separate function.
			 */
			sppp_ioctl(q, mp);
			return;
		case PPPIO_GETSTAT:
			break;			/* 32 bit interface gone */
		default:
			if (iop->ioc_cr == NULL ||
			    secpolicy_ppp_config(iop->ioc_cr) != 0) {
				error = EPERM;
				break;
			} else if ((ppa == NULL) ||
			    (ppa->ppa_lower_wq == NULL)) {
				break;		/* return EINVAL */
			}
			mutex_enter(&ppa->ppa_sta_lock);
			/*
			 * See comments in PPPIO_GETSTAT64 case
			 * in sppp_ioctl().
			 */
			if (IS_SPS_IOCQ(sps)) {
				mutex_exit(&ppa->ppa_sta_lock);
				if (!putq(q, mp)) {
					error = EAGAIN;
					break;
				}
				return;
			} else {
				ppa->ppa_ioctlsfwd++;
				/*
				 * Record the ioctl CMD & ID -
				 * this will be used to check the
				 * ACK or NAK responses coming from below.
				 */
				sps->sps_ioc_id = iop->ioc_id;
				sps->sps_flags |= SPS_IOCQ;
				mutex_exit(&ppa->ppa_sta_lock);
			}
			putnext(ppa->ppa_lower_wq, mp);
			return;		/* don't ack or nak the request */
		}
		/* Failure; send error back upstream. */
		miocnak(q, mp, 0, error);
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
		}
		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * sppp_uwsrv()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Upper write-side service procedure. Note that this procedure does
 *    not get called when a message is placed on our write-side queue, since
 *    automatic queue scheduling has been turned off by noenable() when
 *    the queue was opened. We do this on purpose, as we explicitly control
 *    the write-side queue. Therefore, this procedure gets called when
 *    the lower write service procedure qenable() the upper write stream queue.
 */
void
sppp_uwsrv(queue_t *q)
{
	spppstr_t	*sps;
	sppa_t		*ppa;
	mblk_t		*mp;
	queue_t		*nextq;
	struct iocblk	*iop;

	ASSERT(q != NULL && q->q_ptr != NULL);
	sps = (spppstr_t *)q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		if (MTYPE(mp) == M_IOCTL) {
			ppa = sps->sps_ppa;
			if ((ppa == NULL) || (ppa->ppa_lower_wq == NULL)) {
				miocnak(q, mp, 0, EINVAL);
				continue;
			}

			iop = (struct iocblk *)mp->b_rptr;
			mutex_enter(&ppa->ppa_sta_lock);
			/*
			 * See comments in PPPIO_GETSTAT64 case
			 * in sppp_ioctl().
			 */
			if (IS_SPS_IOCQ(sps)) {
				mutex_exit(&ppa->ppa_sta_lock);
				if (putbq(q, mp) == 0)
					miocnak(q, mp, 0, EAGAIN);
				break;
			} else {
				ppa->ppa_ioctlsfwd++;
				sps->sps_ioc_id = iop->ioc_id;
				sps->sps_flags |= SPS_IOCQ;
				mutex_exit(&ppa->ppa_sta_lock);
				putnext(ppa->ppa_lower_wq, mp);
			}
		} else if ((nextq =
		    sppp_outpkt(q, &mp, msgdsize(mp), sps)) == NULL) {
			if (mp != NULL) {
				if (putbq(q, mp) == 0)
					freemsg(mp);
				break;
			}
		} else {
			putnext(nextq, mp);
		}
	}
}

void
sppp_remove_ppa(spppstr_t *sps)
{
	spppstr_t *nextsib;
	sppa_t *ppa = sps->sps_ppa;

	rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
	if (ppa->ppa_refcnt <= 1) {
		rw_exit(&ppa->ppa_sib_lock);
		sppp_free_ppa(ppa);
	} else {
		nextsib = ppa->ppa_streams;
		if (nextsib == sps) {
			ppa->ppa_streams = sps->sps_nextsib;
		} else {
			while (nextsib->sps_nextsib != NULL) {
				if (nextsib->sps_nextsib == sps) {
					nextsib->sps_nextsib =
					    sps->sps_nextsib;
					break;
				}
				nextsib = nextsib->sps_nextsib;
			}
		}
		ppa->ppa_refcnt--;
		/*
		 * And if this stream was marked as promiscuous
		 * (SPS_PROMISC), then we need to update the
		 * promiscuous streams count. This should only happen
		 * when DL_DETACH_REQ is issued prior to marking the
		 * stream as non-promiscuous, through
		 * DL_PROMISCOFF_REQ request.
		 */
		if (IS_SPS_PROMISC(sps)) {
			ASSERT(ppa->ppa_promicnt > 0);
			ppa->ppa_promicnt--;
		}
		rw_exit(&ppa->ppa_sib_lock);
	}
	sps->sps_nextsib = NULL;
	sps->sps_ppa = NULL;
	freemsg(sps->sps_hangup);
	sps->sps_hangup = NULL;
}

sppa_t *
sppp_find_ppa(uint32_t ppa_id)
{
	sppa_t *ppa;

	for (ppa = ppa_list; ppa != NULL; ppa = ppa->ppa_nextppa) {
		if (ppa->ppa_ppa_id == ppa_id) {
			break;	/* found the ppa */
		}
	}
	return (ppa);
}

/*
 * sppp_inner_ioctl()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer
 *
 * Description:
 *    Called by sppp_uwput as a result of receiving ioctls which require
 *    an exclusive access at the inner perimeter.
 */
static void
sppp_inner_ioctl(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps;
	sppa_t		*ppa;
	struct iocblk	*iop;
	mblk_t		*nmp;
	int		error = EINVAL;
	int		count = 0;
	int		dbgcmd;
	int		mru, mtu;
	uint32_t	ppa_id;
	hrtime_t	hrtime;
	uint16_t	proto;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);

	sps = (spppstr_t *)q->q_ptr;
	ppa = sps->sps_ppa;
	iop = (struct iocblk *)mp->b_rptr;
	switch (iop->ioc_cmd) {
	case DLIOCRAW:
		if (IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		}
		sps->sps_flags |= SPS_RAWDATA;
		error = 0;		/* return success */
		break;
	case DL_IOC_HDR_INFO:
		if (IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		} else if ((mp->b_cont == NULL) ||
		    *((t_uscalar_t *)mp->b_cont->b_rptr) != DL_UNITDATA_REQ ||
		    (MBLKL(mp->b_cont) < (sizeof (dl_unitdata_req_t) +
		    SPPP_ADDRL))) {
			error = EPROTO;
			break;
		} else if (ppa == NULL) {
			error = ENOLINK;
			break;
		}
		if ((nmp = allocb(PPP_HDRLEN, BPRI_MED)) == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			error = ENOMEM;
			break;
		}
		*(uchar_t *)nmp->b_wptr++ = PPP_ALLSTATIONS;
		*(uchar_t *)nmp->b_wptr++ = PPP_UI;
		*(uchar_t *)nmp->b_wptr++ = sps->sps_sap >> 8;
		*(uchar_t *)nmp->b_wptr++ = sps->sps_sap & 0xff;
		ASSERT(MBLKL(nmp) == PPP_HDRLEN);

		linkb(mp, nmp);
		sps->sps_flags |= SPS_FASTPATH;
		error = 0;		/* return success */
		count = msgsize(nmp);
		break;
	case PPPIO_ATTACH:
		if (IS_SPS_CONTROL(sps) || IS_SPS_PIOATTACH(sps) ||
		    (sps->sps_dlstate != DL_UNATTACHED) ||
		    (iop->ioc_count != sizeof (uint32_t))) {
			break;		/* return EINVAL */
		} else if (mp->b_cont == NULL) {
			error = EPROTO;
			break;
		}
		ASSERT(mp->b_cont->b_rptr != NULL);
		/* If there's something here, it's detached. */
		if (ppa != NULL) {
			sppp_remove_ppa(sps);
		}
		ppa_id = *(uint32_t *)mp->b_cont->b_rptr;
		ppa = sppp_find_ppa(ppa_id);
		/*
		 * If we can't find it, then it's either because the requestor
		 * has supplied a wrong ppa_id to be attached to, or because
		 * the control stream for the specified ppa_id has been closed
		 * before we get here.
		 */
		if (ppa == NULL) {
			error = ENOENT;
			break;
		}
		if (iop->ioc_cr == NULL ||
		    ppa->ppa_zoneid != crgetzoneid(iop->ioc_cr)) {
			error = EPERM;
			break;
		}
		/*
		 * Preallocate the hangup message so that we're always
		 * able to send this upstream in the event of a
		 * catastrophic failure.
		 */
		if ((sps->sps_hangup = allocb(1, BPRI_MED)) == NULL) {
			error = ENOSR;
			break;
		}
		/*
		 * There are two ways to attach a stream to a ppa: one is
		 * through DLPI (DL_ATTACH_REQ) and the other is through
		 * PPPIO_ATTACH. This is why we need to distinguish whether or
		 * not a stream was allocated via PPPIO_ATTACH, so that we can
		 * properly detach it when we receive PPPIO_DETACH ioctl
		 * request.
		 */
		sps->sps_flags |= SPS_PIOATTACH;
		sps->sps_ppa = ppa;
		/*
		 * Add this stream to the head of the list of sibling streams
		 * which belong to the same ppa as specified.
		 */
		rw_enter(&ppa->ppa_sib_lock, RW_WRITER);
		ppa->ppa_refcnt++;
		sps->sps_nextsib = ppa->ppa_streams;
		ppa->ppa_streams = sps;
		rw_exit(&ppa->ppa_sib_lock);
		error = 0;		/* return success */
		break;
	case PPPIO_BLOCKNP:
	case PPPIO_UNBLOCKNP:
		if (iop->ioc_cr == NULL ||
		    secpolicy_ppp_config(iop->ioc_cr) != 0) {
			error = EPERM;
			break;
		}
		error = miocpullup(mp, sizeof (uint16_t));
		if (error != 0)
			break;
		ASSERT(mp->b_cont->b_rptr != NULL);
		proto = *(uint16_t *)mp->b_cont->b_rptr;
		if (iop->ioc_cmd == PPPIO_BLOCKNP) {
			uint32_t npflagpos = sppp_ppp2np(proto);
			/*
			 * Mark proto as blocked in ppa_npflag until the
			 * corresponding queues for proto have been plumbed.
			 */
			if (npflagpos != 0) {
				mutex_enter(&ppa->ppa_npmutex);
				ppa->ppa_npflag |= (1 << npflagpos);
				mutex_exit(&ppa->ppa_npmutex);
			} else {
				error = EINVAL;
			}
		} else {
			/*
			 * reset ppa_npflag and release proto
			 * packets that were being held in control queue.
			 */
			sppp_release_pkts(ppa, proto);
		}
		break;
	case PPPIO_DEBUG:
		if (iop->ioc_cr == NULL ||
		    secpolicy_ppp_config(iop->ioc_cr) != 0) {
			error = EPERM;
			break;
		} else if (iop->ioc_count != sizeof (uint32_t)) {
			break;		/* return EINVAL */
		} else if (mp->b_cont == NULL) {
			error = EPROTO;
			break;
		}
		ASSERT(mp->b_cont->b_rptr != NULL);
		dbgcmd = *(uint32_t *)mp->b_cont->b_rptr;
		/*
		 * We accept PPPDBG_LOG + PPPDBG_DRIVER value as an indication
		 * that SPS_KDEBUG needs to be enabled for this upper stream.
		 */
		if (dbgcmd == PPPDBG_LOG + PPPDBG_DRIVER) {
			sps->sps_flags |= SPS_KDEBUG;
			error = 0;	/* return success */
			break;
		}
		/*
		 * Otherwise, for any other values, we send them down only if
		 * there is an attachment and if the attachment has something
		 * linked underneath it.
		 */
		if ((ppa == NULL) || (ppa->ppa_lower_wq == NULL)) {
			error = ENOLINK;
			break;
		}
		mutex_enter(&ppa->ppa_sta_lock);
		/*
		 * See comments in PPPIO_GETSTAT64 case
		 * in sppp_ioctl().
		 */
		if (IS_SPS_IOCQ(sps)) {
			mutex_exit(&ppa->ppa_sta_lock);
			if (!putq(q, mp)) {
				error = EAGAIN;
				break;
			}
			return;
		} else {
			ppa->ppa_ioctlsfwd++;
			/*
			 * Record the ioctl CMD & ID -
			 * this will be used to check the
			 * ACK or NAK responses coming from below.
			 */
			sps->sps_ioc_id = iop->ioc_id;
			sps->sps_flags |= SPS_IOCQ;
			mutex_exit(&ppa->ppa_sta_lock);
		}
		putnext(ppa->ppa_lower_wq, mp);
		return;			/* don't ack or nak the request */
	case PPPIO_DETACH:
		if (!IS_SPS_PIOATTACH(sps)) {
			break;		/* return EINVAL */
		}
		/*
		 * The SPS_PIOATTACH flag set on the stream tells us that
		 * the ppa field is still valid. In the event that the control
		 * stream be closed prior to this stream's detachment, the
		 * SPS_PIOATTACH flag would have been cleared from this stream
		 * during close; in that case we won't get here.
		 */
		ASSERT(ppa != NULL);
		ASSERT(ppa->ppa_ctl != sps);
		ASSERT(sps->sps_dlstate == DL_UNATTACHED);

		/*
		 * We don't actually detach anything until the stream is
		 * closed or reattached.
		 */

		sps->sps_flags &= ~SPS_PIOATTACH;
		error = 0;		/* return success */
		break;
	case PPPIO_LASTMOD:
		if (!IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		}
		ASSERT(ppa != NULL);
		ppa->ppa_flags |= PPA_LASTMOD;
		error = 0;		/* return success */
		break;
	case PPPIO_MRU:
		if (!IS_SPS_CONTROL(sps) ||
		    (iop->ioc_count != sizeof (uint32_t))) {
			break;		/* return EINVAL */
		} else if (mp->b_cont == NULL) {
			error = EPROTO;
			break;
		}
		ASSERT(ppa != NULL);
		ASSERT(mp->b_cont->b_rptr != NULL);
		mru = *(uint32_t *)mp->b_cont->b_rptr;
		if ((mru <= 0) || (mru > PPP_MAXMRU)) {
			error = EPROTO;
			break;
		}
		if (mru < PPP_MRU) {
			mru = PPP_MRU;
		}
		ppa->ppa_mru = (uint16_t)mru;
		/*
		 * If there's something beneath this driver for the ppa, then
		 * inform it (or them) of the MRU size. Only do this is we
		 * are not the last PPP module on the stream.
		 */
		if (!IS_PPA_LASTMOD(ppa) && (ppa->ppa_lower_wq != NULL)) {
			(void) putctl4(ppa->ppa_lower_wq, M_CTL, PPPCTL_MRU,
			    mru);
		}
		error = 0;		/* return success */
		break;
	case PPPIO_MTU:
		if (!IS_SPS_CONTROL(sps) ||
		    (iop->ioc_count != sizeof (uint32_t))) {
			break;		/* return EINVAL */
		} else if (mp->b_cont == NULL) {
			error = EPROTO;
			break;
		}
		ASSERT(ppa != NULL);
		ASSERT(mp->b_cont->b_rptr != NULL);
		mtu = *(uint32_t *)mp->b_cont->b_rptr;
		if ((mtu <= 0) || (mtu > PPP_MAXMTU)) {
			error = EPROTO;
			break;
		}
		ppa->ppa_mtu = (uint16_t)mtu;
		/*
		 * If there's something beneath this driver for the ppa, then
		 * inform it (or them) of the MTU size. Only do this if we
		 * are not the last PPP module on the stream.
		 */
		if (!IS_PPA_LASTMOD(ppa) && (ppa->ppa_lower_wq != NULL)) {
			(void) putctl4(ppa->ppa_lower_wq, M_CTL, PPPCTL_MTU,
			    mtu);
		}
		error = 0;		/* return success */
		break;
	case PPPIO_USETIMESTAMP:
		if (!IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		}
		if (!IS_PPA_TIMESTAMP(ppa)) {
			hrtime = gethrtime();
			ppa->ppa_lasttx = ppa->ppa_lastrx = hrtime;
			ppa->ppa_flags |= PPA_TIMESTAMP;
		}
		error = 0;
		break;
	}

	if (error == 0) {
		/* Success; tell the user */
		miocack(q, mp, count, 0);
	} else {
		/* Failure; send error back upstream */
		miocnak(q, mp, 0, error);
	}
}

/*
 * sppp_outer_ioctl()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer
 *
 * Description:
 *    Called by sppp_uwput as a result of receiving ioctls which require
 *    an exclusive access at the outer perimeter.
 */
static void
sppp_outer_ioctl(queue_t *q, mblk_t *mp)
{
	spppstr_t	*sps = q->q_ptr;
	spppstr_t	*nextsib;
	queue_t		*lwq;
	sppa_t		*ppa;
	struct iocblk	*iop;
	int		error = EINVAL;
	int		count = 0;
	uint32_t	ppa_id;
	mblk_t		*nmp;
	zoneid_t	zoneid;

	sps = (spppstr_t *)q->q_ptr;
	ppa = sps->sps_ppa;
	iop = (struct iocblk *)mp->b_rptr;
	switch (iop->ioc_cmd) {
	case I_LINK:
		if (!IS_SPS_CONTROL(sps)) {
			break;		/* return EINVAL */
		} else if (ppa->ppa_lower_wq != NULL) {
			error = EEXIST;
			break;
		}
		ASSERT(ppa->ppa_ctl != NULL);
		ASSERT(sps->sps_npmode == NPMODE_PASS);
		ASSERT(mp->b_cont != NULL && mp->b_cont->b_rptr != NULL);

		lwq = ((struct linkblk *)mp->b_cont->b_rptr)->l_qbot;
		ASSERT(lwq != NULL);

		ppa->ppa_lower_wq = lwq;
		lwq->q_ptr = RD(lwq)->q_ptr = (caddr_t)ppa;
		/*
		 * Unblock upper network streams which now feed this lower
		 * stream. We don't need to hold ppa_sib_lock here, since we
		 * are writer at the outer perimeter.
		 */
		if (WR(sps->sps_rq)->q_first != NULL)
			qenable(WR(sps->sps_rq));
		for (nextsib = ppa->ppa_streams; nextsib != NULL;
		    nextsib = nextsib->sps_nextsib) {
			nextsib->sps_npmode = NPMODE_PASS;
			if (WR(nextsib->sps_rq)->q_first != NULL) {
				qenable(WR(nextsib->sps_rq));
			}
		}

		/*
		 * Also unblock (run once) our lower read-side queue.  This is
		 * where packets received while doing the I_LINK may be
		 * languishing; see sppp_lrsrv.
		 */
		qenable(RD(lwq));

		/*
		 * Send useful information down to the modules which are now
		 * linked below this driver (for this particular ppa). Only
		 * do this if we are not the last PPP module on the stream.
		 */
		if (!IS_PPA_LASTMOD(ppa)) {
			(void) putctl8(lwq, M_CTL, PPPCTL_UNIT,
			    ppa->ppa_ppa_id);
			(void) putctl4(lwq, M_CTL, PPPCTL_MRU, ppa->ppa_mru);
			(void) putctl4(lwq, M_CTL, PPPCTL_MTU, ppa->ppa_mtu);
		}

		if (IS_SPS_KDEBUG(sps)) {
			SPDEBUG(PPP_DRV_NAME
			    "/%d: I_LINK lwq=0x%p sps=0x%p flags=0x%b ppa=0x%p "
			    "flags=0x%b\n", sps->sps_mn_id,
			    (void *)ppa->ppa_lower_wq, (void *)sps,
			    sps->sps_flags, SPS_FLAGS_STR,
			    (void *)ppa, ppa->ppa_flags,
			    PPA_FLAGS_STR);
		}
		error = 0;		/* return success */
		break;
	case I_UNLINK:
		ASSERT(IS_SPS_CONTROL(sps));
		ASSERT(ppa != NULL);
		lwq = ppa->ppa_lower_wq;
		ASSERT(mp->b_cont != NULL && mp->b_cont->b_rptr != NULL);
		ASSERT(lwq == ((struct linkblk *)mp->b_cont->b_rptr)->l_qbot);

		if (IS_SPS_KDEBUG(sps)) {
			SPDEBUG(PPP_DRV_NAME
			    "/%d: I_UNLINK lwq=0x%p sps=0x%p flags=0x%b "
			    "ppa=0x%p flags=0x%b\n", sps->sps_mn_id,
			    (void *)lwq, (void *)sps, sps->sps_flags,
			    SPS_FLAGS_STR, (void *)ppa, ppa->ppa_flags,
			    PPA_FLAGS_STR);
		}
		/*
		 * While accessing the outer perimeter exclusively, we
		 * disassociate our ppa's lower_wq from the lower stream linked
		 * beneath us, and we also disassociate our control stream from
		 * the q_ptr of the lower stream.
		 */
		lwq->q_ptr = RD(lwq)->q_ptr = NULL;
		ppa->ppa_lower_wq = NULL;
		/*
		 * Unblock streams which now feed back up the control stream,
		 * and acknowledge the request. We don't need to hold
		 * ppa_sib_lock here, since we are writer at the outer
		 * perimeter.
		 */
		if (WR(sps->sps_rq)->q_first != NULL)
			qenable(WR(sps->sps_rq));
		for (nextsib = ppa->ppa_streams; nextsib != NULL;
		    nextsib = nextsib->sps_nextsib) {
			if (WR(nextsib->sps_rq)->q_first != NULL) {
				qenable(WR(nextsib->sps_rq));
			}
		}
		error = 0;		/* return success */
		break;
	case PPPIO_NEWPPA:
		/*
		 * Do sanity check to ensure that we don't accept PPPIO_NEWPPA
		 * on a stream which DLPI is used (since certain DLPI messages
		 * will cause state transition reflected in sps_dlstate,
		 * changing it from its default DL_UNATTACHED value). In other
		 * words, we won't allow a network/snoop stream to become
		 * a control stream.
		 */
		if (iop->ioc_cr == NULL ||
		    secpolicy_ppp_config(iop->ioc_cr) != 0) {
			error = EPERM;
			break;
		} else if (IS_SPS_CONTROL(sps) || IS_SPS_PIOATTACH(sps) ||
		    (ppa != NULL) || (sps->sps_dlstate != DL_UNATTACHED)) {
			break;		/* return EINVAL */
		}
		/* Get requested unit number (if any) */
		if (iop->ioc_count == sizeof (uint32_t) && mp->b_cont != NULL)
			ppa_id = *(uint32_t *)mp->b_cont->b_rptr;
		else
			ppa_id = 0;
		/* Get mblk to use for response message */
		nmp = allocb(sizeof (uint32_t), BPRI_MED);
		if (nmp == NULL) {
			error = ENOSR;
			break;
		}
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
		}
		mp->b_cont = nmp;		/* chain our response mblk */
		/*
		 * Walk the global ppa list and determine the lowest
		 * available ppa_id number to be used.
		 */
		if (ppa_id == (uint32_t)-1)
			ppa_id = 0;
		zoneid = crgetzoneid(iop->ioc_cr);
		for (ppa = ppa_list; ppa != NULL; ppa = ppa->ppa_nextppa) {
			if (ppa_id == (uint32_t)-2) {
				if (ppa->ppa_ctl == NULL &&
				    ppa->ppa_zoneid == zoneid)
					break;
			} else {
				if (ppa_id < ppa->ppa_ppa_id)
					break;
				if (ppa_id == ppa->ppa_ppa_id)
					++ppa_id;
			}
		}
		if (ppa_id == (uint32_t)-2) {
			if (ppa == NULL) {
				error = ENXIO;
				break;
			}
			/* Clear timestamp and lastmod flags */
			ppa->ppa_flags = 0;
		} else {
			ppa = sppp_create_ppa(ppa_id, zoneid);
			if (ppa == NULL) {
				error = ENOMEM;
				break;
			}
		}

		sps->sps_ppa = ppa;		/* chain the ppa structure */
		sps->sps_npmode = NPMODE_PASS;	/* network packets may travel */
		sps->sps_flags |= SPS_CONTROL;	/* this is the control stream */

		ppa->ppa_refcnt++;		/* new PPA reference */
		ppa->ppa_ctl = sps;		/* back ptr to upper stream */
		/*
		 * Return the newly created ppa_id to the requestor and
		 * acnowledge the request.
		 */
		*(uint32_t *)nmp->b_wptr = ppa->ppa_ppa_id;
		nmp->b_wptr += sizeof (uint32_t);

		if (IS_SPS_KDEBUG(sps)) {
			SPDEBUG(PPP_DRV_NAME
			    "/%d: PPPIO_NEWPPA ppa_id=%d sps=0x%p flags=0x%b "
			    "ppa=0x%p flags=0x%b\n", sps->sps_mn_id, ppa_id,
			    (void *)sps, sps->sps_flags, SPS_FLAGS_STR,
			    (void *)ppa, ppa->ppa_flags,
			    PPA_FLAGS_STR);
		}
		count = msgsize(nmp);
		error = 0;
		break;
	}

	if (error == 0) {
		/* Success; tell the user. */
		miocack(q, mp, count, 0);
	} else {
		/* Failure; send error back upstream. */
		miocnak(q, mp, 0, error);
	}
}

/*
 * sppp_send()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Called by sppp_uwput to handle M_DATA message type.  Returns
 *    queue_t for putnext, or NULL to mean that the packet was
 *    handled internally.
 */
static queue_t *
sppp_send(queue_t *q, mblk_t **mpp, spppstr_t *sps)
{
	mblk_t	*mp;
	sppa_t	*ppa;
	int	is_promisc;
	int	msize;
	int	error = 0;
	queue_t	*nextq;

	ASSERT(mpp != NULL);
	mp = *mpp;
	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(sps != NULL);
	ASSERT(q->q_ptr == sps);
	/*
	 * We only let M_DATA through if the sender is either the control
	 * stream (for PPP control packets) or one of the network streams
	 * (for IP packets) in IP fastpath mode. If this stream is not attached
	 * to any ppas, then discard data coming down through this stream.
	 */
	ppa = sps->sps_ppa;
	if (ppa == NULL) {
		ASSERT(!IS_SPS_CONTROL(sps));
		error = ENOLINK;
	} else if (!IS_SPS_CONTROL(sps) && !IS_SPS_FASTPATH(sps)) {
		error = EPROTO;
	}
	if (error != 0) {
		merror(q, mp, error);
		return (NULL);
	}
	msize = msgdsize(mp);
	if (msize > (ppa->ppa_mtu + PPP_HDRLEN)) {
		/* Log, and send it anyway */
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_otoolongs++;
		mutex_exit(&ppa->ppa_sta_lock);
	} else if (msize < PPP_HDRLEN) {
		/*
		 * Log, and send it anyway. We log it because we get things
		 * in M_DATA form here, which tells us that the sender is
		 * either IP in fastpath transmission mode, or pppd. In both
		 * cases, they are currently expected to send the 4-bytes
		 * PPP header in front of any possible payloads.
		 */
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_orunts++;
		mutex_exit(&ppa->ppa_sta_lock);
	}

	if (IS_SPS_KDEBUG(sps)) {
		SPDEBUG(PPP_DRV_NAME
		    "/%d: M_DATA send (%d bytes) sps=0x%p flags=0x%b "
		    "ppa=0x%p flags=0x%b\n", sps->sps_mn_id, msize,
		    (void *)sps, sps->sps_flags, SPS_FLAGS_STR,
		    (void *)ppa, ppa->ppa_flags, PPA_FLAGS_STR);
	}
	/*
	 * Should there be any promiscuous stream(s), send the data up
	 * for each promiscuous stream that we recognize. Make sure that
	 * for fastpath, we skip the PPP header in the M_DATA mblk. We skip
	 * the control stream as we obviously never allow the control stream
	 * to become promiscous and bind to PPP_ALLSAP.
	 */
	rw_enter(&ppa->ppa_sib_lock, RW_READER);
	is_promisc = sps->sps_ppa->ppa_promicnt;
	if (is_promisc) {
		ASSERT(ppa->ppa_streams != NULL);
		sppp_dlprsendup(ppa->ppa_streams, mp, sps->sps_sap, B_TRUE);
	}
	rw_exit(&ppa->ppa_sib_lock);
	/*
	 * Only time-stamp the packet with hrtime if the upper stream
	 * is configured to do so.  PPP control (negotiation) messages
	 * are never considered link activity; only data is activity.
	 */
	if (!IS_SPS_CONTROL(sps) && IS_PPA_TIMESTAMP(ppa)) {
		ppa->ppa_lasttx = gethrtime();
	}
	/*
	 * If there's already a message in the write-side service queue,
	 * then queue this message there as well, otherwise, try to send
	 * it down to the module immediately below us.
	 */
	if (q->q_first != NULL ||
	    (nextq = sppp_outpkt(q, mpp, msize, sps)) == NULL) {
		mp = *mpp;
		if (mp != NULL && putq(q, mp) == 0) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_oqdropped++;
			mutex_exit(&ppa->ppa_sta_lock);
			freemsg(mp);
		}
		return (NULL);
	}
	return (nextq);
}

/*
 * sppp_outpkt()
 *
 * MT-Perimeters:
 *    shared inner, shared outer (if called from sppp_wput, sppp_dlunitdatareq).
 *    exclusive inner, shared outer (if called from sppp_wsrv).
 *
 * Description:
 *    Called from 1) sppp_uwput when processing a M_DATA fastpath message,
 *    or 2) sppp_uwsrv when processing the upper write-side service queue.
 *    For both cases, it prepares to send the data to the module below
 *    this driver if there is a lower stream linked underneath. If none, then
 *    the data will be sent upstream via the control channel to pppd.
 *
 * Returns:
 *	Non-NULL queue_t if message should be sent now, otherwise
 *	if *mpp == NULL, then message was freed, otherwise put *mpp
 *	(back) on the queue.  (Does not do putq/putbq, since it's
 *	called both from srv and put procedures.)
 */
static queue_t *
sppp_outpkt(queue_t *q, mblk_t **mpp, int msize, spppstr_t *sps)
{
	mblk_t		*mp;
	sppa_t		*ppa;
	enum NPmode	npmode;
	mblk_t		*mpnew;

	ASSERT(mpp != NULL);
	mp = *mpp;
	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(sps != NULL);

	ppa = sps->sps_ppa;
	npmode = sps->sps_npmode;

	if (npmode == NPMODE_QUEUE) {
		ASSERT(!IS_SPS_CONTROL(sps));
		return (NULL);	/* queue it for later */
	} else if (ppa == NULL || ppa->ppa_ctl == NULL ||
	    npmode == NPMODE_DROP || npmode == NPMODE_ERROR) {
		/*
		 * This can not be the control stream, as it must always have
		 * a valid ppa, and its npmode must always be NPMODE_PASS.
		 */
		ASSERT(!IS_SPS_CONTROL(sps));
		if (npmode == NPMODE_DROP) {
			freemsg(mp);
		} else {
			/*
			 * If we no longer have the control stream, or if the
			 * mode is set to NPMODE_ERROR, then we need to tell IP
			 * that the interface need to be marked as down. In
			 * other words, we tell IP to be quiescent.
			 */
			merror(q, mp, EPROTO);
		}
		*mpp = NULL;
		return (NULL);	/* don't queue it */
	}
	/*
	 * Do we have a driver stream linked underneath ? If not, we need to
	 * notify pppd that the link needs to be brought up and configure
	 * this upper stream to drop subsequent outgoing packets. This is
	 * for demand-dialing, in which case pppd has done the IP plumbing
	 * but hasn't linked the driver stream underneath us. Therefore, when
	 * a packet is sent down the IP interface, a notification message
	 * will be sent up the control stream to pppd in order for it to
	 * establish the physical link. The driver stream is then expected
	 * to be linked underneath after physical link establishment is done.
	 */
	if (ppa->ppa_lower_wq == NULL) {
		ASSERT(ppa->ppa_ctl != NULL);
		ASSERT(ppa->ppa_ctl->sps_rq != NULL);

		*mpp = NULL;
		mpnew = create_lsmsg(PPP_LINKSTAT_NEEDUP);
		if (mpnew == NULL) {
			freemsg(mp);
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			return (NULL);	/* don't queue it */
		}
		/* Include the data in the message for logging. */
		mpnew->b_cont = mp;
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_lsneedup++;
		mutex_exit(&ppa->ppa_sta_lock);
		/*
		 * We need to set the mode to NPMODE_DROP, but should only
		 * do so when this stream is not the control stream.
		 */
		if (!IS_SPS_CONTROL(sps)) {
			sps->sps_npmode = NPMODE_DROP;
		}
		putnext(ppa->ppa_ctl->sps_rq, mpnew);
		return (NULL);	/* don't queue it */
	}
	/*
	 * If so, then try to send it down. The lower queue is only ever
	 * detached while holding an exclusive lock on the whole driver,
	 * so we can be confident that the lower queue is still there.
	 */
	if (bcanputnext(ppa->ppa_lower_wq, mp->b_band)) {
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_stats.p.ppp_opackets++;
		if (IS_SPS_CONTROL(sps)) {
			ppa->ppa_opkt_ctl++;
		}
		ppa->ppa_stats.p.ppp_obytes += msize;
		mutex_exit(&ppa->ppa_sta_lock);
		return (ppa->ppa_lower_wq);	/* don't queue it */
	}
	return (NULL);	/* queue it for later */
}

/*
 * sppp_lwsrv()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Lower write-side service procedure. No messages are ever placed on
 *    the write queue here, this just back-enables all upper write side
 *    service procedures.
 */
void
sppp_lwsrv(queue_t *q)
{
	sppa_t		*ppa;
	spppstr_t	*nextsib;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ppa = (sppa_t *)q->q_ptr;
	ASSERT(ppa != NULL);

	rw_enter(&ppa->ppa_sib_lock, RW_READER);
	if ((nextsib = ppa->ppa_ctl) != NULL &&
	    WR(nextsib->sps_rq)->q_first != NULL)
		qenable(WR(nextsib->sps_rq));
	for (nextsib = ppa->ppa_streams; nextsib != NULL;
	    nextsib = nextsib->sps_nextsib) {
		if (WR(nextsib->sps_rq)->q_first != NULL) {
			qenable(WR(nextsib->sps_rq));
		}
	}
	rw_exit(&ppa->ppa_sib_lock);
}

/*
 * sppp_lrput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Lower read-side put procedure. Messages from below get here.
 *    Data messages are handled separately to limit stack usage
 *    going into IP.
 *
 *    Note that during I_UNLINK processing, it's possible for a downstream
 *    message to enable upstream data (due to pass_wput() removing the
 *    SQ_BLOCKED flag), and thus we must protect against a NULL sppa pointer.
 *    In this case, the only thing above us is passthru, and we might as well
 *    discard.
 */
void
sppp_lrput(queue_t *q, mblk_t *mp)
{
	sppa_t		*ppa;
	spppstr_t	*sps;

	if ((ppa = q->q_ptr) == NULL) {
		freemsg(mp);
		return;
	}

	sps = ppa->ppa_ctl;

	if (MTYPE(mp) != M_DATA) {
		sppp_recv_nondata(q, mp, sps);
	} else if (sps == NULL) {
		freemsg(mp);
	} else if ((q = sppp_recv(q, &mp, sps)) != NULL) {
		putnext(q, mp);
	}
}

/*
 * sppp_lrsrv()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Lower read-side service procedure.  This is run once after the I_LINK
 *    occurs in order to clean up any packets that came in while we were
 *    transferring in the lower stream.  Otherwise, it's not used.
 */
void
sppp_lrsrv(queue_t *q)
{
	mblk_t *mp;

	while ((mp = getq(q)) != NULL)
		sppp_lrput(q, mp);
}

/*
 * sppp_recv_nondata()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    All received non-data messages come through here.
 */
static void
sppp_recv_nondata(queue_t *q, mblk_t *mp, spppstr_t *ctlsps)
{
	sppa_t		*ppa;
	spppstr_t	*destsps;
	struct iocblk	*iop;

	ppa = (sppa_t *)q->q_ptr;
	ctlsps = ppa->ppa_ctl;

	switch (MTYPE(mp)) {
	case M_CTL:
		mutex_enter(&ppa->ppa_sta_lock);
		if (*mp->b_rptr == PPPCTL_IERROR) {
			ppa->ppa_stats.p.ppp_ierrors++;
			ppa->ppa_ierr_low++;
			ppa->ppa_mctlsknown++;
		} else if (*mp->b_rptr == PPPCTL_OERROR) {
			ppa->ppa_stats.p.ppp_oerrors++;
			ppa->ppa_oerr_low++;
			ppa->ppa_mctlsknown++;
		} else {
			ppa->ppa_mctlsunknown++;
		}
		mutex_exit(&ppa->ppa_sta_lock);
		freemsg(mp);
		break;
	case M_IOCTL:
		miocnak(q, mp, 0, EINVAL);
		break;
	case M_IOCACK:
	case M_IOCNAK:
		iop = (struct iocblk *)mp->b_rptr;
		ASSERT(iop != NULL);
		/*
		 * Attempt to match up the response with the stream that the
		 * request came from. If ioc_id doesn't match the one that we
		 * recorded, then discard this message.
		 */
		rw_enter(&ppa->ppa_sib_lock, RW_READER);
		if ((destsps = ctlsps) == NULL ||
		    destsps->sps_ioc_id != iop->ioc_id) {
			destsps = ppa->ppa_streams;
			while (destsps != NULL) {
				if (destsps->sps_ioc_id == iop->ioc_id) {
					break;	/* found the upper stream */
				}
				destsps = destsps->sps_nextsib;
			}
		}
		rw_exit(&ppa->ppa_sib_lock);
		if (destsps == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_ioctlsfwderr++;
			mutex_exit(&ppa->ppa_sta_lock);
			freemsg(mp);
			break;
		}
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_ioctlsfwdok++;

		/*
		 * Clear SPS_IOCQ and enable the lower write side queue,
		 * this would allow the upper stream service routine
		 * to start processing the queue for pending messages.
		 * sppp_lwsrv -> sppp_uwsrv.
		 */
		destsps->sps_flags &= ~SPS_IOCQ;
		mutex_exit(&ppa->ppa_sta_lock);
		qenable(WR(destsps->sps_rq));

		putnext(destsps->sps_rq, mp);
		break;
	case M_HANGUP:
		/*
		 * Free the original mblk_t. We don't really want to send
		 * a M_HANGUP message upstream, so we need to translate this
		 * message into something else.
		 */
		freemsg(mp);
		if (ctlsps == NULL)
			break;
		mp = create_lsmsg(PPP_LINKSTAT_HANGUP);
		if (mp == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			break;
		}
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_lsdown++;
		mutex_exit(&ppa->ppa_sta_lock);
		putnext(ctlsps->sps_rq, mp);
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			flushq(q, FLUSHDATA);
		}
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;
	default:
		if (ctlsps != NULL &&
		    (queclass(mp) == QPCTL) || canputnext(ctlsps->sps_rq)) {
			putnext(ctlsps->sps_rq, mp);
		} else {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_iqdropped++;
			mutex_exit(&ppa->ppa_sta_lock);
			freemsg(mp);
		}
		break;
	}
}

/*
 * sppp_recv()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Receive function called by sppp_lrput.  Finds appropriate
 *    receive stream and does accounting.
 */
static queue_t *
sppp_recv(queue_t *q, mblk_t **mpp, spppstr_t *ctlsps)
{
	mblk_t		*mp;
	int		len;
	sppa_t		*ppa;
	spppstr_t	*destsps;
	mblk_t		*zmp;
	uint32_t	npflagpos;

	ASSERT(mpp != NULL);
	mp = *mpp;
	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(ctlsps != NULL);
	ASSERT(IS_SPS_CONTROL(ctlsps));
	ppa = ctlsps->sps_ppa;
	ASSERT(ppa != NULL && ppa->ppa_ctl != NULL);

	len = msgdsize(mp);
	mutex_enter(&ppa->ppa_sta_lock);
	ppa->ppa_stats.p.ppp_ibytes += len;
	mutex_exit(&ppa->ppa_sta_lock);
	/*
	 * If the entire data size of the mblk is less than the length of the
	 * PPP header, then free it. We can't do much with such message anyway,
	 * since we can't really determine what the PPP protocol type is.
	 */
	if (len < PPP_HDRLEN) {
		/* Log, and free it */
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_irunts++;
		mutex_exit(&ppa->ppa_sta_lock);
		freemsg(mp);
		return (NULL);
	} else if (len > (ppa->ppa_mru + PPP_HDRLEN)) {
		/* Log, and accept it anyway */
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_itoolongs++;
		mutex_exit(&ppa->ppa_sta_lock);
	}
	/*
	 * We need at least be able to read the PPP protocol from the header,
	 * so if the first message block is too small, then we concatenate the
	 * rest of the following blocks into one message.
	 */
	if (MBLKL(mp) < PPP_HDRLEN) {
		zmp = msgpullup(mp, PPP_HDRLEN);
		freemsg(mp);
		mp = zmp;
		if (mp == NULL) {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_allocbfail++;
			mutex_exit(&ppa->ppa_sta_lock);
			return (NULL);
		}
		*mpp = mp;
	}
	/*
	 * Hold this packet in the control-queue until
	 * the matching network-layer upper stream for the PPP protocol (sap)
	 * has not been plumbed and configured
	 */
	npflagpos = sppp_ppp2np(PPP_PROTOCOL(mp->b_rptr));
	mutex_enter(&ppa->ppa_npmutex);
	if (npflagpos != 0 && (ppa->ppa_npflag & (1 << npflagpos))) {
		/*
		 * proto is currently blocked; Hold up to 4 packets
		 * in the kernel.
		 */
		if (ppa->ppa_holdpkts[npflagpos] > 3 ||
		    putq(ctlsps->sps_rq, mp) == 0)
			freemsg(mp);
		else
			ppa->ppa_holdpkts[npflagpos]++;
		mutex_exit(&ppa->ppa_npmutex);
		return (NULL);
	}
	mutex_exit(&ppa->ppa_npmutex);
	/*
	 * Try to find a matching network-layer upper stream for the specified
	 * PPP protocol (sap), and if none is found, send this frame up the
	 * control stream.
	 */
	destsps = sppp_inpkt(q, mp, ctlsps);
	if (destsps == NULL) {
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_ipkt_ctl++;
		mutex_exit(&ppa->ppa_sta_lock);
		if (canputnext(ctlsps->sps_rq)) {
			if (IS_SPS_KDEBUG(ctlsps)) {
				SPDEBUG(PPP_DRV_NAME
				    "/%d: M_DATA recv (%d bytes) sps=0x%p "
				    "flags=0x%b ppa=0x%p flags=0x%b\n",
				    ctlsps->sps_mn_id, len, (void *)ctlsps,
				    ctlsps->sps_flags, SPS_FLAGS_STR,
				    (void *)ppa, ppa->ppa_flags,
				    PPA_FLAGS_STR);
			}
			return (ctlsps->sps_rq);
		} else {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_iqdropped++;
			mutex_exit(&ppa->ppa_sta_lock);
			freemsg(mp);
			return (NULL);
		}
	}
	if (canputnext(destsps->sps_rq)) {
		if (IS_SPS_KDEBUG(destsps)) {
			SPDEBUG(PPP_DRV_NAME
			    "/%d: M_DATA recv (%d bytes) sps=0x%p flags=0x%b "
			    "ppa=0x%p flags=0x%b\n", destsps->sps_mn_id, len,
			    (void *)destsps, destsps->sps_flags,
			    SPS_FLAGS_STR, (void *)ppa, ppa->ppa_flags,
			    PPA_FLAGS_STR);
		}
		/*
		 * If fastpath is enabled on the network-layer stream, then
		 * make sure we skip over the PPP header, otherwise, we wrap
		 * the message in a DLPI message.
		 */
		if (IS_SPS_FASTPATH(destsps)) {
			mp->b_rptr += PPP_HDRLEN;
			return (destsps->sps_rq);
		} else {
			spppstr_t *uqs = (spppstr_t *)destsps->sps_rq->q_ptr;
			ASSERT(uqs != NULL);
			mp->b_rptr += PPP_HDRLEN;
			mp = sppp_dladdud(uqs, mp, uqs->sps_sap, B_FALSE);
			if (mp != NULL) {
				*mpp = mp;
				return (destsps->sps_rq);
			} else {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_allocbfail++;
				mutex_exit(&ppa->ppa_sta_lock);
				/* mp already freed by sppp_dladdud */
				return (NULL);
			}
		}
	} else {
		mutex_enter(&ppa->ppa_sta_lock);
		ppa->ppa_iqdropped++;
		mutex_exit(&ppa->ppa_sta_lock);
		freemsg(mp);
		return (NULL);
	}
}

/*
 * sppp_inpkt()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Find the destination upper stream for the received packet, called
 *    from sppp_recv.
 *
 * Returns:
 *    ptr to destination upper network stream, or NULL for control stream.
 */
/* ARGSUSED */
static spppstr_t *
sppp_inpkt(queue_t *q, mblk_t *mp, spppstr_t *ctlsps)
{
	spppstr_t	*destsps = NULL;
	sppa_t		*ppa;
	uint16_t	proto;
	int		is_promisc;

	ASSERT(q != NULL && q->q_ptr != NULL);
	ASSERT(mp != NULL && mp->b_rptr != NULL);
	ASSERT(IS_SPS_CONTROL(ctlsps));
	ppa = ctlsps->sps_ppa;
	ASSERT(ppa != NULL);
	/*
	 * From RFC 1661 (Section 2):
	 *
	 * The Protocol field is one or two octets, and its value identifies
	 * the datagram encapsulated in the Information field of the packet.
	 * The field is transmitted and received most significant octet first.
	 *
	 * The structure of this field is consistent with the ISO 3309
	 * extension mechanism for address fields.  All Protocols MUST be odd;
	 * the least significant bit of the least significant octet MUST equal
	 * "1".  Also, all Protocols MUST be assigned such that the least
	 * significant bit of the most significant octet equals "0". Frames
	 * received which don't comply with these rules MUST be treated as
	 * having an unrecognized Protocol.
	 *
	 * Protocol field values in the "0***" to "3***" range identify the
	 * network-layer protocol of specific packets, and values in the
	 * "8***" to "b***" range identify packets belonging to the associated
	 * Network Control Protocols (NCPs), if any.
	 *
	 * Protocol field values in the "4***" to "7***" range are used for
	 * protocols with low volume traffic which have no associated NCP.
	 * Protocol field values in the "c***" to "f***" range identify packets
	 * as link-layer Control Protocols (such as LCP).
	 */
	proto = PPP_PROTOCOL(mp->b_rptr);
	mutex_enter(&ppa->ppa_sta_lock);
	ppa->ppa_stats.p.ppp_ipackets++;
	mutex_exit(&ppa->ppa_sta_lock);
	/*
	 * We check if this is not a network-layer protocol, and if so,
	 * then send this packet up the control stream.
	 */
	if (proto > 0x7fff) {
		goto inpkt_done;	/* send it up the control stream */
	}
	/*
	 * Try to grab the destination upper stream from the network-layer
	 * stream cache for this ppa for PPP_IP (0x0021) or PPP_IPV6 (0x0057)
	 * protocol types. Otherwise, if the type is not known to the cache,
	 * or if its sap can't be matched with any of the upper streams, then
	 * send this packet up the control stream so that it can be rejected.
	 */
	if (proto == PPP_IP) {
		destsps = ppa->ppa_ip_cache;
	} else if (proto == PPP_IPV6) {
		destsps = ppa->ppa_ip6_cache;
	}
	/*
	 * Toss this one away up the control stream if there's no matching sap;
	 * this way the protocol can be rejected (destsps is NULL).
	 */

inpkt_done:
	/*
	 * Only time-stamp the packet with hrtime if the upper stream
	 * is configured to do so.  PPP control (negotiation) messages
	 * are never considered link activity; only data is activity.
	 */
	if (destsps != NULL && IS_PPA_TIMESTAMP(ppa)) {
		ppa->ppa_lastrx = gethrtime();
	}
	/*
	 * Should there be any promiscuous stream(s), send the data up for
	 * each promiscuous stream that we recognize. We skip the control
	 * stream as we obviously never allow the control stream to become
	 * promiscous and bind to PPP_ALLSAP.
	 */
	rw_enter(&ppa->ppa_sib_lock, RW_READER);
	is_promisc = ppa->ppa_promicnt;
	if (is_promisc) {
		ASSERT(ppa->ppa_streams != NULL);
		sppp_dlprsendup(ppa->ppa_streams, mp, proto, B_TRUE);
	}
	rw_exit(&ppa->ppa_sib_lock);
	return (destsps);
}

/*
 * sppp_kstat_update()
 *
 * Description:
 *    Update per-ppa kstat interface statistics.
 */
static int
sppp_kstat_update(kstat_t *ksp, int rw)
{
	register sppa_t		*ppa;
	register sppp_kstats_t	*pppkp;
	register struct pppstat64 *sp;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	ppa = (sppa_t *)ksp->ks_private;
	ASSERT(ppa != NULL);

	pppkp = (sppp_kstats_t *)ksp->ks_data;
	sp = &ppa->ppa_stats.p;

	mutex_enter(&ppa->ppa_sta_lock);
	pppkp->allocbfail.value.ui32	= ppa->ppa_allocbfail;
	pppkp->mctlsfwd.value.ui32	= ppa->ppa_mctlsfwd;
	pppkp->mctlsfwderr.value.ui32	= ppa->ppa_mctlsfwderr;
	pppkp->rbytes.value.ui32	= sp->ppp_ibytes;
	pppkp->rbytes64.value.ui64	= sp->ppp_ibytes;
	pppkp->ierrors.value.ui32	= sp->ppp_ierrors;
	pppkp->ierrors_lower.value.ui32	= ppa->ppa_ierr_low;
	pppkp->ioctlsfwd.value.ui32	= ppa->ppa_ioctlsfwd;
	pppkp->ioctlsfwdok.value.ui32	= ppa->ppa_ioctlsfwdok;
	pppkp->ioctlsfwderr.value.ui32	= ppa->ppa_ioctlsfwderr;
	pppkp->ipackets.value.ui32	= sp->ppp_ipackets;
	pppkp->ipackets64.value.ui64	= sp->ppp_ipackets;
	pppkp->ipackets_ctl.value.ui32	= ppa->ppa_ipkt_ctl;
	pppkp->iqdropped.value.ui32	= ppa->ppa_iqdropped;
	pppkp->irunts.value.ui32	= ppa->ppa_irunts;
	pppkp->itoolongs.value.ui32	= ppa->ppa_itoolongs;
	pppkp->lsneedup.value.ui32	= ppa->ppa_lsneedup;
	pppkp->lsdown.value.ui32	= ppa->ppa_lsdown;
	pppkp->mctlsknown.value.ui32	= ppa->ppa_mctlsknown;
	pppkp->mctlsunknown.value.ui32	= ppa->ppa_mctlsunknown;
	pppkp->obytes.value.ui32	= sp->ppp_obytes;
	pppkp->obytes64.value.ui64	= sp->ppp_obytes;
	pppkp->oerrors.value.ui32	= sp->ppp_oerrors;
	pppkp->oerrors_lower.value.ui32	= ppa->ppa_oerr_low;
	pppkp->opackets.value.ui32	= sp->ppp_opackets;
	pppkp->opackets64.value.ui64	= sp->ppp_opackets;
	pppkp->opackets_ctl.value.ui32	= ppa->ppa_opkt_ctl;
	pppkp->oqdropped.value.ui32	= ppa->ppa_oqdropped;
	pppkp->otoolongs.value.ui32	= ppa->ppa_otoolongs;
	pppkp->orunts.value.ui32	= ppa->ppa_orunts;
	mutex_exit(&ppa->ppa_sta_lock);

	return (0);
}

/*
 * Turn off proto in ppa_npflag to indicate that
 * the corresponding network protocol has been plumbed.
 * Release proto packets that were being held in the control
 * queue in anticipation of this event.
 */
static void
sppp_release_pkts(sppa_t *ppa, uint16_t proto)
{
	uint32_t npflagpos = sppp_ppp2np(proto);
	int count;
	mblk_t *mp;
	uint16_t mp_proto;
	queue_t *q;
	spppstr_t *destsps;

	ASSERT(ppa != NULL);

	if (npflagpos == 0 || (ppa->ppa_npflag & (1 << npflagpos)) == 0)
		return;

	mutex_enter(&ppa->ppa_npmutex);
	ppa->ppa_npflag &= ~(1 << npflagpos);
	count = ppa->ppa_holdpkts[npflagpos];
	ppa->ppa_holdpkts[npflagpos] = 0;
	mutex_exit(&ppa->ppa_npmutex);

	q = ppa->ppa_ctl->sps_rq;

	while (count > 0) {
		mp = getq(q);
		ASSERT(mp != NULL);

		mp_proto = PPP_PROTOCOL(mp->b_rptr);
		if (mp_proto !=  proto) {
			(void) putq(q, mp);
			continue;
		}
		count--;
		destsps = NULL;
		if (mp_proto == PPP_IP) {
			destsps = ppa->ppa_ip_cache;
		} else if (mp_proto == PPP_IPV6) {
			destsps = ppa->ppa_ip6_cache;
		}
		ASSERT(destsps != NULL);

		if (IS_SPS_FASTPATH(destsps)) {
			mp->b_rptr += PPP_HDRLEN;
		} else {
			spppstr_t *uqs = (spppstr_t *)destsps->sps_rq->q_ptr;
			ASSERT(uqs != NULL);
			mp->b_rptr += PPP_HDRLEN;
			mp = sppp_dladdud(uqs, mp, uqs->sps_sap, B_FALSE);
			if (mp == NULL) {
				mutex_enter(&ppa->ppa_sta_lock);
				ppa->ppa_allocbfail++;
				mutex_exit(&ppa->ppa_sta_lock);
				/* mp already freed by sppp_dladdud */
				continue;
			}
		}

		if (canputnext(destsps->sps_rq)) {
			putnext(destsps->sps_rq, mp);
		} else {
			mutex_enter(&ppa->ppa_sta_lock);
			ppa->ppa_iqdropped++;
			mutex_exit(&ppa->ppa_sta_lock);
			freemsg(mp);
			continue;
		}
	}
}
