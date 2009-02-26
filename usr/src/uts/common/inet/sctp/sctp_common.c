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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>

#include "sctp_impl.h"
#include "sctp_addr.h"
#include "sctp_asconf.h"

static struct kmem_cache *sctp_kmem_faddr_cache;
static void sctp_init_faddr(sctp_t *, sctp_faddr_t *, in6_addr_t *, mblk_t *);

/* Set the source address.  Refer to comments in sctp_get_ire(). */
void
sctp_set_saddr(sctp_t *sctp, sctp_faddr_t *fp)
{
	boolean_t v6 = !fp->isv4;
	boolean_t addr_set;

	fp->saddr = sctp_get_valid_addr(sctp, v6, &addr_set);
	/*
	 * If there is no source address avaialble, mark this peer address
	 * as unreachable for now.  When the heartbeat timer fires, it will
	 * call sctp_get_ire() to re-check if there is any source address
	 * available.
	 */
	if (!addr_set)
		fp->state = SCTP_FADDRS_UNREACH;
}

/*
 * Call this function to update the cached IRE of a peer addr fp.
 */
void
sctp_get_ire(sctp_t *sctp, sctp_faddr_t *fp)
{
	ire_t		*ire;
	ipaddr_t	addr4;
	in6_addr_t	laddr;
	sctp_saddr_ipif_t *sp;
	int		hdrlen;
	ts_label_t	*tsl;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	ip_stack_t	*ipst = sctps->sctps_netstack->netstack_ip;

	/* Remove the previous cache IRE */
	if ((ire = fp->ire) != NULL) {
		IRE_REFRELE_NOTR(ire);
		fp->ire = NULL;
	}

	/*
	 * If this addr is not reachable, mark it as unconfirmed for now, the
	 * state will be changed back to unreachable later in this function
	 * if it is still the case.
	 */
	if (fp->state == SCTP_FADDRS_UNREACH) {
		fp->state = SCTP_FADDRS_UNCONFIRMED;
	}

	tsl = crgetlabel(CONN_CRED(sctp->sctp_connp));

	if (fp->isv4) {
		IN6_V4MAPPED_TO_IPADDR(&fp->faddr, addr4);
		ire = ire_cache_lookup(addr4, sctp->sctp_zoneid, tsl, ipst);
		if (ire != NULL)
			IN6_IPADDR_TO_V4MAPPED(ire->ire_src_addr, &laddr);
	} else {
		ire = ire_cache_lookup_v6(&fp->faddr, sctp->sctp_zoneid, tsl,
		    ipst);
		if (ire != NULL)
			laddr = ire->ire_src_addr_v6;
	}

	if (ire == NULL) {
		dprint(3, ("ire2faddr: no ire for %x:%x:%x:%x\n",
		    SCTP_PRINTADDR(fp->faddr)));
		/*
		 * It is tempting to just leave the src addr
		 * unspecified and let IP figure it out, but we
		 * *cannot* do this, since IP may choose a src addr
		 * that is not part of this association... unless
		 * this sctp has bound to all addrs.  So if the ire
		 * lookup fails, try to find one in our src addr
		 * list, unless the sctp has bound to all addrs, in
		 * which case we change the src addr to unspec.
		 *
		 * Note that if this is a v6 endpoint but it does
		 * not have any v4 address at this point (e.g. may
		 * have been  deleted), sctp_get_valid_addr() will
		 * return mapped INADDR_ANY.  In this case, this
		 * address should be marked not reachable so that
		 * it won't be used to send data.
		 */
		sctp_set_saddr(sctp, fp);
		if (fp->state == SCTP_FADDRS_UNREACH)
			return;
		goto check_current;
	}

	/* Make sure the laddr is part of this association */
	if ((sp = sctp_saddr_lookup(sctp, &ire->ire_ipif->ipif_v6lcl_addr,
	    0)) != NULL && !sp->saddr_ipif_dontsrc) {
		if (sp->saddr_ipif_unconfirmed == 1)
			sp->saddr_ipif_unconfirmed = 0;
		fp->saddr = laddr;
	} else {
		dprint(2, ("ire2faddr: src addr is not part of assc\n"));

		/*
		 * Set the src to the first saddr and hope for the best.
		 * Note that we will still do the ire caching below.
		 * Otherwise, whenever we send a packet, we need to do
		 * the ire lookup again and still may not get the correct
		 * source address.  Note that this case should very seldomly
		 * happen.  One scenario this can happen is an app
		 * explicitly bind() to an address.  But that address is
		 * not the preferred source address to send to the peer.
		 */
		sctp_set_saddr(sctp, fp);
		if (fp->state == SCTP_FADDRS_UNREACH) {
			IRE_REFRELE(ire);
			return;
		}
	}

	/*
	 * Note that ire_cache_lookup_*() returns an ire with the tracing
	 * bits enabled.  This requires the thread holding the ire also
	 * do the IRE_REFRELE().  Thus we need to do IRE_REFHOLD_NOTR()
	 * and then IRE_REFRELE() the ire here to make the tracing bits
	 * work.
	 */
	IRE_REFHOLD_NOTR(ire);
	IRE_REFRELE(ire);

	/* Cache the IRE */
	fp->ire = ire;
	if (fp->ire->ire_type == IRE_LOOPBACK && !sctp->sctp_loopback)
		sctp->sctp_loopback = 1;

	/*
	 * Pull out RTO information for this faddr and use it if we don't
	 * have any yet.
	 */
	if (fp->srtt == -1 && ire->ire_uinfo.iulp_rtt != 0) {
		/* The cached value is in ms. */
		fp->srtt = MSEC_TO_TICK(ire->ire_uinfo.iulp_rtt);
		fp->rttvar = MSEC_TO_TICK(ire->ire_uinfo.iulp_rtt_sd);
		fp->rto = 3 * fp->srtt;

		/* Bound the RTO by configured min and max values */
		if (fp->rto < sctp->sctp_rto_min) {
			fp->rto = sctp->sctp_rto_min;
		}
		if (fp->rto > sctp->sctp_rto_max) {
			fp->rto = sctp->sctp_rto_max;
		}
	}

	/*
	 * Record the MTU for this faddr. If the MTU for this faddr has
	 * changed, check if the assc MTU will also change.
	 */
	if (fp->isv4) {
		hdrlen = sctp->sctp_hdr_len;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
	}
	if ((fp->sfa_pmss + hdrlen) != ire->ire_max_frag) {
		/* Make sure that sfa_pmss is a multiple of SCTP_ALIGN. */
		fp->sfa_pmss = (ire->ire_max_frag - hdrlen) & ~(SCTP_ALIGN - 1);
		if (fp->cwnd < (fp->sfa_pmss * 2)) {
			SET_CWND(fp, fp->sfa_pmss,
			    sctps->sctps_slow_start_initial);
		}
	}

check_current:
	if (fp == sctp->sctp_current)
		sctp_set_faddr_current(sctp, fp);
}

void
sctp_update_ire(sctp_t *sctp)
{
	ire_t		*ire;
	sctp_faddr_t	*fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		if ((ire = fp->ire) == NULL)
			continue;
		mutex_enter(&ire->ire_lock);

		/*
		 * If the cached IRE is going away, there is no point to
		 * update it.
		 */
		if (ire->ire_marks & IRE_MARK_CONDEMNED) {
			mutex_exit(&ire->ire_lock);
			IRE_REFRELE_NOTR(ire);
			fp->ire = NULL;
			continue;
		}

		/*
		 * Only record the PMTU for this faddr if we actually have
		 * done discovery. This prevents initialized default from
		 * clobbering any real info that IP may have.
		 */
		if (fp->pmtu_discovered) {
			if (fp->isv4) {
				ire->ire_max_frag = fp->sfa_pmss +
				    sctp->sctp_hdr_len;
			} else {
				ire->ire_max_frag = fp->sfa_pmss +
				    sctp->sctp_hdr6_len;
			}
		}

		if (sctps->sctps_rtt_updates != 0 &&
		    fp->rtt_updates >= sctps->sctps_rtt_updates) {
			/*
			 * If there is no old cached values, initialize them
			 * conservatively.  Set them to be (1.5 * new value).
			 * This code copied from ip_ire_advise().  The cached
			 * value is in ms.
			 */
			if (ire->ire_uinfo.iulp_rtt != 0) {
				ire->ire_uinfo.iulp_rtt =
				    (ire->ire_uinfo.iulp_rtt +
				    TICK_TO_MSEC(fp->srtt)) >> 1;
			} else {
				ire->ire_uinfo.iulp_rtt =
				    TICK_TO_MSEC(fp->srtt + (fp->srtt >> 1));
			}
			if (ire->ire_uinfo.iulp_rtt_sd != 0) {
				ire->ire_uinfo.iulp_rtt_sd =
				    (ire->ire_uinfo.iulp_rtt_sd +
				    TICK_TO_MSEC(fp->rttvar)) >> 1;
			} else {
				ire->ire_uinfo.iulp_rtt_sd =
				    TICK_TO_MSEC(fp->rttvar +
				    (fp->rttvar >> 1));
			}
			fp->rtt_updates = 0;
		}
		mutex_exit(&ire->ire_lock);
	}
}

/*
 * The sender must set the total length in the IP header.
 * If sendto == NULL, the current will be used.
 */
mblk_t *
sctp_make_mp(sctp_t *sctp, sctp_faddr_t *sendto, int trailer)
{
	mblk_t *mp;
	size_t ipsctplen;
	int isv4;
	sctp_faddr_t *fp;
	sctp_stack_t *sctps = sctp->sctp_sctps;
	boolean_t src_changed = B_FALSE;

	ASSERT(sctp->sctp_current != NULL || sendto != NULL);
	if (sendto == NULL) {
		fp = sctp->sctp_current;
	} else {
		fp = sendto;
	}
	isv4 = fp->isv4;

	/* Try to look for another IRE again. */
	if (fp->ire == NULL) {
		sctp_get_ire(sctp, fp);
		/*
		 * Although we still may not get an IRE, the source address
		 * may be changed in sctp_get_ire().  Set src_changed to
		 * true so that the source address is copied again.
		 */
		src_changed = B_TRUE;
	}

	/* There is no suitable source address to use, return. */
	if (fp->state == SCTP_FADDRS_UNREACH)
		return (NULL);
	ASSERT(!SCTP_IS_ADDR_UNSPEC(fp->isv4, fp->saddr));

	if (isv4) {
		ipsctplen = sctp->sctp_hdr_len;
	} else {
		ipsctplen = sctp->sctp_hdr6_len;
	}

	mp = allocb_cred(ipsctplen + sctps->sctps_wroff_xtra + trailer,
	    CONN_CRED(sctp->sctp_connp), sctp->sctp_cpid);
	if (mp == NULL) {
		ip1dbg(("sctp_make_mp: error making mp..\n"));
		return (NULL);
	}
	mp->b_rptr += sctps->sctps_wroff_xtra;
	mp->b_wptr = mp->b_rptr + ipsctplen;

	ASSERT(OK_32PTR(mp->b_wptr));

	if (isv4) {
		ipha_t *iph = (ipha_t *)mp->b_rptr;

		bcopy(sctp->sctp_iphc, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current || src_changed) {
			/* Fix the source and destination addresses. */
			IN6_V4MAPPED_TO_IPADDR(&fp->faddr, iph->ipha_dst);
			IN6_V4MAPPED_TO_IPADDR(&fp->saddr, iph->ipha_src);
		}
		/* set or clear the don't fragment bit */
		if (fp->df) {
			iph->ipha_fragment_offset_and_flags = htons(IPH_DF);
		} else {
			iph->ipha_fragment_offset_and_flags = 0;
		}
	} else {
		bcopy(sctp->sctp_iphc6, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current || src_changed) {
			/* Fix the source and destination addresses. */
			((ip6_t *)(mp->b_rptr))->ip6_dst = fp->faddr;
			((ip6_t *)(mp->b_rptr))->ip6_src = fp->saddr;
		}
	}
	ASSERT(sctp->sctp_connp != NULL);

	/*
	 * IP will not free this IRE if it is condemned.  SCTP needs to
	 * free it.
	 */
	if ((fp->ire != NULL) && (fp->ire->ire_marks & IRE_MARK_CONDEMNED)) {
		IRE_REFRELE_NOTR(fp->ire);
		fp->ire = NULL;
	}
	/* Stash the conn and ire ptr info. for IP */
	SCTP_STASH_IPINFO(mp, fp->ire);

	return (mp);
}

/*
 * Notify upper layers about preferred write offset, write size.
 */
void
sctp_set_ulp_prop(sctp_t *sctp)
{
	int hdrlen;
	struct sock_proto_props sopp;

	sctp_stack_t *sctps = sctp->sctp_sctps;

	if (sctp->sctp_current->isv4) {
		hdrlen = sctp->sctp_hdr_len;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
	}
	ASSERT(sctp->sctp_ulpd);

	ASSERT(sctp->sctp_current->sfa_pmss == sctp->sctp_mss);
	bzero(&sopp, sizeof (sopp));
	sopp.sopp_flags = SOCKOPT_MAXBLK|SOCKOPT_WROFF;
	sopp.sopp_wroff = sctps->sctps_wroff_xtra + hdrlen +
	    sizeof (sctp_data_hdr_t);
	sopp.sopp_maxblk = sctp->sctp_mss - sizeof (sctp_data_hdr_t);
	sctp->sctp_ulp_prop(sctp->sctp_ulpd, &sopp);
}

void
sctp_set_iplen(sctp_t *sctp, mblk_t *mp)
{
	uint16_t	sum = 0;
	ipha_t		*iph;
	ip6_t		*ip6h;
	mblk_t		*pmp = mp;
	boolean_t	isv4;

	isv4 = (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
	for (; pmp; pmp = pmp->b_cont)
		sum += pmp->b_wptr - pmp->b_rptr;

	if (isv4) {
		iph = (ipha_t *)mp->b_rptr;
		iph->ipha_length = htons(sum);
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		/*
		 * If an ip6i_t is present, the real IPv6 header
		 * immediately follows.
		 */
		if (ip6h->ip6_nxt == IPPROTO_RAW)
			ip6h = (ip6_t *)&ip6h[1];
		ip6h->ip6_plen = htons(sum - ((char *)&sctp->sctp_ip6h[1] -
		    sctp->sctp_iphc6));
	}
}

int
sctp_compare_faddrsets(sctp_faddr_t *a1, sctp_faddr_t *a2)
{
	int na1 = 0;
	int overlap = 0;
	int equal = 1;
	int onematch;
	sctp_faddr_t *fp1, *fp2;

	for (fp1 = a1; fp1; fp1 = fp1->next) {
		onematch = 0;
		for (fp2 = a2; fp2; fp2 = fp2->next) {
			if (IN6_ARE_ADDR_EQUAL(&fp1->faddr, &fp2->faddr)) {
				overlap++;
				onematch = 1;
				break;
			}
			if (!onematch) {
				equal = 0;
			}
		}
		na1++;
	}

	if (equal) {
		return (SCTP_ADDR_EQUAL);
	}
	if (overlap == na1) {
		return (SCTP_ADDR_SUBSET);
	}
	if (overlap) {
		return (SCTP_ADDR_OVERLAP);
	}
	return (SCTP_ADDR_DISJOINT);
}

/*
 * Returns 0 on success, -1 on memory allocation failure. If sleep
 * is true, this function should never fail.  The boolean parameter
 * first decides whether the newly created faddr structure should be
 * added at the beginning of the list or at the end.
 *
 * Note: caller must hold conn fanout lock.
 */
int
sctp_add_faddr(sctp_t *sctp, in6_addr_t *addr, int sleep, boolean_t first)
{
	sctp_faddr_t	*faddr;
	mblk_t		*timer_mp;

	if (is_system_labeled()) {
		ts_label_t *tsl;
		tsol_tpc_t *rhtp;
		int retv;

		tsl = crgetlabel(CONN_CRED(sctp->sctp_connp));
		ASSERT(tsl != NULL);

		/* find_tpc automatically does the right thing with IPv4 */
		rhtp = find_tpc(addr, IPV6_VERSION, B_FALSE);
		if (rhtp == NULL)
			return (EACCES);

		retv = EACCES;
		if (tsl->tsl_doi == rhtp->tpc_tp.tp_doi) {
			switch (rhtp->tpc_tp.host_type) {
			case UNLABELED:
				/*
				 * Can talk to unlabeled hosts if any of the
				 * following are true:
				 *   1. zone's label matches the remote host's
				 *	default label,
				 *   2. mac_exempt is on and the zone dominates
				 *	the remote host's label, or
				 *   3. mac_exempt is on and the socket is from
				 *	the global zone.
				 */
				if (blequal(&rhtp->tpc_tp.tp_def_label,
				    &tsl->tsl_label) ||
				    (sctp->sctp_mac_exempt &&
				    (sctp->sctp_zoneid == GLOBAL_ZONEID ||
				    bldominates(&tsl->tsl_label,
				    &rhtp->tpc_tp.tp_def_label))))
					retv = 0;
				break;
			case SUN_CIPSO:
				if (_blinrange(&tsl->tsl_label,
				    &rhtp->tpc_tp.tp_sl_range_cipso) ||
				    blinlset(&tsl->tsl_label,
				    rhtp->tpc_tp.tp_sl_set_cipso))
					retv = 0;
				break;
			}
		}
		TPC_RELE(rhtp);
		if (retv != 0)
			return (retv);
	}

	if ((faddr = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep)) == NULL)
		return (ENOMEM);
	timer_mp = sctp_timer_alloc((sctp), sctp_rexmit_timer, sleep);
	if (timer_mp == NULL) {
		kmem_cache_free(sctp_kmem_faddr_cache, faddr);
		return (ENOMEM);
	}
	((sctpt_t *)(timer_mp->b_rptr))->sctpt_faddr = faddr;

	sctp_init_faddr(sctp, faddr, addr, timer_mp);

	/* Check for subnet broadcast. */
	if (faddr->ire != NULL && faddr->ire->ire_type & IRE_BROADCAST) {
		IRE_REFRELE_NOTR(faddr->ire);
		sctp_timer_free(timer_mp);
		faddr->timer_mp = NULL;
		kmem_cache_free(sctp_kmem_faddr_cache, faddr);
		return (EADDRNOTAVAIL);
	}
	ASSERT(faddr->next == NULL);

	if (sctp->sctp_faddrs == NULL) {
		ASSERT(sctp->sctp_lastfaddr == NULL);
		/* only element on list; first and last are same */
		sctp->sctp_faddrs = sctp->sctp_lastfaddr = faddr;
	} else if (first) {
		ASSERT(sctp->sctp_lastfaddr != NULL);
		faddr->next = sctp->sctp_faddrs;
		sctp->sctp_faddrs = faddr;
	} else {
		sctp->sctp_lastfaddr->next = faddr;
		sctp->sctp_lastfaddr = faddr;
	}
	sctp->sctp_nfaddrs++;

	return (0);
}

sctp_faddr_t *
sctp_lookup_faddr(sctp_t *sctp, in6_addr_t *addr)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		if (IN6_ARE_ADDR_EQUAL(&fp->faddr, addr))
			break;
	}

	return (fp);
}

sctp_faddr_t *
sctp_lookup_faddr_nosctp(sctp_faddr_t *fp, in6_addr_t *addr)
{
	for (; fp; fp = fp->next) {
		if (IN6_ARE_ADDR_EQUAL(&fp->faddr, addr)) {
			break;
		}
	}

	return (fp);
}

/*
 * To change the currently used peer address to the specified one.
 */
void
sctp_set_faddr_current(sctp_t *sctp, sctp_faddr_t *fp)
{
	/* Now setup the composite header. */
	if (fp->isv4) {
		IN6_V4MAPPED_TO_IPADDR(&fp->faddr,
		    sctp->sctp_ipha->ipha_dst);
		IN6_V4MAPPED_TO_IPADDR(&fp->saddr, sctp->sctp_ipha->ipha_src);
		/* update don't fragment bit */
		if (fp->df) {
			sctp->sctp_ipha->ipha_fragment_offset_and_flags =
			    htons(IPH_DF);
		} else {
			sctp->sctp_ipha->ipha_fragment_offset_and_flags = 0;
		}
	} else {
		sctp->sctp_ip6h->ip6_dst = fp->faddr;
		sctp->sctp_ip6h->ip6_src = fp->saddr;
	}

	sctp->sctp_current = fp;
	sctp->sctp_mss = fp->sfa_pmss;

	/* Update the uppper layer for the change. */
	if (!SCTP_IS_DETACHED(sctp))
		sctp_set_ulp_prop(sctp);
}

void
sctp_redo_faddr_srcs(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		sctp_get_ire(sctp, fp);
	}
}

void
sctp_faddr_alive(sctp_t *sctp, sctp_faddr_t *fp)
{
	int64_t now = lbolt64;

	fp->strikes = 0;
	sctp->sctp_strikes = 0;
	fp->lastactive = now;
	fp->hb_expiry = now + SET_HB_INTVL(fp);
	fp->hb_pending = B_FALSE;
	if (fp->state != SCTP_FADDRS_ALIVE) {
		fp->state = SCTP_FADDRS_ALIVE;
		sctp_intf_event(sctp, fp->faddr, SCTP_ADDR_AVAILABLE, 0);
		/* Should have a full IRE now */
		sctp_get_ire(sctp, fp);

		/*
		 * If this is the primary, switch back to it now.  And
		 * we probably want to reset the source addr used to reach
		 * it.
		 */
		if (fp == sctp->sctp_primary) {
			ASSERT(fp->state != SCTP_FADDRS_UNREACH);
			sctp_set_faddr_current(sctp, fp);
			return;
		}
	}
}

int
sctp_is_a_faddr_clean(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
		if (fp->state == SCTP_FADDRS_ALIVE && fp->strikes == 0) {
			return (1);
		}
	}

	return (0);
}

/*
 * Returns 0 if there is at leave one other active faddr, -1 if there
 * are none. If there are none left, faddr_dead() will start killing the
 * association.
 * If the downed faddr was the current faddr, a new current faddr
 * will be chosen.
 */
int
sctp_faddr_dead(sctp_t *sctp, sctp_faddr_t *fp, int newstate)
{
	sctp_faddr_t *ofp;
	sctp_stack_t *sctps = sctp->sctp_sctps;

	if (fp->state == SCTP_FADDRS_ALIVE) {
		sctp_intf_event(sctp, fp->faddr, SCTP_ADDR_UNREACHABLE, 0);
	}
	fp->state = newstate;

	dprint(1, ("sctp_faddr_dead: %x:%x:%x:%x down (state=%d)\n",
	    SCTP_PRINTADDR(fp->faddr), newstate));

	if (fp == sctp->sctp_current) {
		/* Current faddr down; need to switch it */
		sctp->sctp_current = NULL;
	}

	/* Find next alive faddr */
	ofp = fp;
	for (fp = fp->next; fp != NULL; fp = fp->next) {
		if (fp->state == SCTP_FADDRS_ALIVE) {
			break;
		}
	}

	if (fp == NULL) {
		/* Continue from beginning of list */
		for (fp = sctp->sctp_faddrs; fp != ofp; fp = fp->next) {
			if (fp->state == SCTP_FADDRS_ALIVE) {
				break;
			}
		}
	}

	/*
	 * Find a new fp, so if the current faddr is dead, use the new fp
	 * as the current one.
	 */
	if (fp != ofp) {
		if (sctp->sctp_current == NULL) {
			dprint(1, ("sctp_faddr_dead: failover->%x:%x:%x:%x\n",
			    SCTP_PRINTADDR(fp->faddr)));
			/*
			 * Note that we don't need to reset the source addr
			 * of the new fp.
			 */
			sctp_set_faddr_current(sctp, fp);
		}
		return (0);
	}


	/* All faddrs are down; kill the association */
	dprint(1, ("sctp_faddr_dead: all faddrs down, killing assoc\n"));
	BUMP_MIB(&sctps->sctps_mib, sctpAborted);
	sctp_assoc_event(sctp, sctp->sctp_state < SCTPS_ESTABLISHED ?
	    SCTP_CANT_STR_ASSOC : SCTP_COMM_LOST, 0, NULL);
	sctp_clean_death(sctp, sctp->sctp_client_errno ?
	    sctp->sctp_client_errno : ETIMEDOUT);

	return (-1);
}

sctp_faddr_t *
sctp_rotate_faddr(sctp_t *sctp, sctp_faddr_t *ofp)
{
	sctp_faddr_t *nfp = NULL;

	if (ofp == NULL) {
		ofp = sctp->sctp_current;
	}

	/* Find the next live one */
	for (nfp = ofp->next; nfp != NULL; nfp = nfp->next) {
		if (nfp->state == SCTP_FADDRS_ALIVE) {
			break;
		}
	}

	if (nfp == NULL) {
		/* Continue from beginning of list */
		for (nfp = sctp->sctp_faddrs; nfp != ofp; nfp = nfp->next) {
			if (nfp->state == SCTP_FADDRS_ALIVE) {
				break;
			}
		}
	}

	/*
	 * nfp could only be NULL if all faddrs are down, and when
	 * this happens, faddr_dead() should have killed the
	 * association. Hence this assertion...
	 */
	ASSERT(nfp != NULL);
	return (nfp);
}

void
sctp_unlink_faddr(sctp_t *sctp, sctp_faddr_t *fp)
{
	sctp_faddr_t *fpp;

	if (!sctp->sctp_faddrs) {
		return;
	}

	if (fp->timer_mp != NULL) {
		sctp_timer_free(fp->timer_mp);
		fp->timer_mp = NULL;
		fp->timer_running = 0;
	}
	if (fp->rc_timer_mp != NULL) {
		sctp_timer_free(fp->rc_timer_mp);
		fp->rc_timer_mp = NULL;
		fp->rc_timer_running = 0;
	}
	if (fp->ire != NULL) {
		IRE_REFRELE_NOTR(fp->ire);
		fp->ire = NULL;
	}

	if (fp == sctp->sctp_faddrs) {
		goto gotit;
	}

	for (fpp = sctp->sctp_faddrs; fpp->next != fp; fpp = fpp->next)
		;

gotit:
	ASSERT(sctp->sctp_conn_tfp != NULL);
	mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
	if (fp == sctp->sctp_faddrs) {
		sctp->sctp_faddrs = fp->next;
	} else {
		fpp->next = fp->next;
	}
	mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	/* XXX faddr2ire? */
	kmem_cache_free(sctp_kmem_faddr_cache, fp);
	sctp->sctp_nfaddrs--;
}

void
sctp_zap_faddrs(sctp_t *sctp, int caller_holds_lock)
{
	sctp_faddr_t *fp, *fpn;

	if (sctp->sctp_faddrs == NULL) {
		ASSERT(sctp->sctp_lastfaddr == NULL);
		return;
	}

	ASSERT(sctp->sctp_lastfaddr != NULL);
	sctp->sctp_lastfaddr = NULL;
	sctp->sctp_current = NULL;
	sctp->sctp_primary = NULL;

	sctp_free_faddr_timers(sctp);

	if (sctp->sctp_conn_tfp != NULL && !caller_holds_lock) {
		/* in conn fanout; need to hold lock */
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
	}

	for (fp = sctp->sctp_faddrs; fp; fp = fpn) {
		fpn = fp->next;
		if (fp->ire != NULL)
			IRE_REFRELE_NOTR(fp->ire);
		kmem_cache_free(sctp_kmem_faddr_cache, fp);
		sctp->sctp_nfaddrs--;
	}

	sctp->sctp_faddrs = NULL;
	ASSERT(sctp->sctp_nfaddrs == 0);
	if (sctp->sctp_conn_tfp != NULL && !caller_holds_lock) {
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	}

}

void
sctp_zap_addrs(sctp_t *sctp)
{
	sctp_zap_faddrs(sctp, 0);
	sctp_free_saddrs(sctp);
}

/*
 * Initialize the IPv4 header. Loses any record of any IP options.
 */
int
sctp_header_init_ipv4(sctp_t *sctp, int sleep)
{
	sctp_hdr_t	*sctph;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * This is a simple initialization. If there's
	 * already a template, it should never be too small,
	 * so reuse it.  Otherwise, allocate space for the new one.
	 */
	if (sctp->sctp_iphc != NULL) {
		ASSERT(sctp->sctp_iphc_len >= SCTP_MAX_COMBINED_HEADER_LENGTH);
		bzero(sctp->sctp_iphc, sctp->sctp_iphc_len);
	} else {
		sctp->sctp_iphc_len = SCTP_MAX_COMBINED_HEADER_LENGTH;
		sctp->sctp_iphc = kmem_zalloc(sctp->sctp_iphc_len, sleep);
		if (sctp->sctp_iphc == NULL) {
			sctp->sctp_iphc_len = 0;
			return (ENOMEM);
		}
	}

	sctp->sctp_ipha = (ipha_t *)sctp->sctp_iphc;

	sctp->sctp_hdr_len = sizeof (ipha_t) + sizeof (sctp_hdr_t);
	sctp->sctp_ip_hdr_len = sizeof (ipha_t);
	sctp->sctp_ipha->ipha_length = htons(sizeof (ipha_t) +
	    sizeof (sctp_hdr_t));
	sctp->sctp_ipha->ipha_version_and_hdr_length =
	    (IP_VERSION << 4) | IP_SIMPLE_HDR_LENGTH_IN_WORDS;

	/*
	 * These two fields should be zero, and are already set above.
	 *
	 * sctp->sctp_ipha->ipha_ident,
	 * sctp->sctp_ipha->ipha_fragment_offset_and_flags.
	 */

	sctp->sctp_ipha->ipha_ttl = sctps->sctps_ipv4_ttl;
	sctp->sctp_ipha->ipha_protocol = IPPROTO_SCTP;

	sctph = (sctp_hdr_t *)(sctp->sctp_iphc + sizeof (ipha_t));
	sctp->sctp_sctph = sctph;

	return (0);
}

/*
 * Update sctp_sticky_hdrs based on sctp_sticky_ipp.
 * The headers include ip6i_t (if needed), ip6_t, any sticky extension
 * headers, and the maximum size sctp header (to avoid reallocation
 * on the fly for additional sctp options).
 * Returns failure if can't allocate memory.
 */
int
sctp_build_hdrs(sctp_t *sctp)
{
	char		*hdrs;
	uint_t		hdrs_len;
	ip6i_t		*ip6i;
	char		buf[SCTP_MAX_HDR_LENGTH];
	ip6_pkt_t	*ipp = &sctp->sctp_sticky_ipp;
	in6_addr_t	src;
	in6_addr_t	dst;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * save the existing sctp header and source/dest IP addresses
	 */
	bcopy(sctp->sctp_sctph6, buf, sizeof (sctp_hdr_t));
	src = sctp->sctp_ip6h->ip6_src;
	dst = sctp->sctp_ip6h->ip6_dst;
	hdrs_len = ip_total_hdrs_len_v6(ipp) + SCTP_MAX_HDR_LENGTH;
	ASSERT(hdrs_len != 0);
	if (hdrs_len > sctp->sctp_iphc6_len) {
		/* Need to reallocate */
		hdrs = kmem_zalloc(hdrs_len, KM_NOSLEEP);
		if (hdrs == NULL)
			return (ENOMEM);

		if (sctp->sctp_iphc6_len != 0)
			kmem_free(sctp->sctp_iphc6, sctp->sctp_iphc6_len);
		sctp->sctp_iphc6 = hdrs;
		sctp->sctp_iphc6_len = hdrs_len;
	}
	ip_build_hdrs_v6((uchar_t *)sctp->sctp_iphc6,
	    hdrs_len - SCTP_MAX_HDR_LENGTH, ipp, IPPROTO_SCTP);

	/* Set header fields not in ipp */
	if (ipp->ipp_fields & IPPF_HAS_IP6I) {
		ip6i = (ip6i_t *)sctp->sctp_iphc6;
		sctp->sctp_ip6h = (ip6_t *)&ip6i[1];
	} else {
		sctp->sctp_ip6h = (ip6_t *)sctp->sctp_iphc6;
	}
	/*
	 * sctp->sctp_ip_hdr_len will include ip6i_t if there is one.
	 */
	sctp->sctp_ip_hdr6_len = hdrs_len - SCTP_MAX_HDR_LENGTH;
	sctp->sctp_sctph6 = (sctp_hdr_t *)(sctp->sctp_iphc6 +
	    sctp->sctp_ip_hdr6_len);
	sctp->sctp_hdr6_len = sctp->sctp_ip_hdr6_len + sizeof (sctp_hdr_t);

	bcopy(buf, sctp->sctp_sctph6, sizeof (sctp_hdr_t));

	sctp->sctp_ip6h->ip6_src = src;
	sctp->sctp_ip6h->ip6_dst = dst;
	/*
	 * If the hoplimit was not set by ip_build_hdrs_v6(), we need to
	 * set it to the default value for SCTP.
	 */
	if (!(ipp->ipp_fields & IPPF_UNICAST_HOPS))
		sctp->sctp_ip6h->ip6_hops = sctps->sctps_ipv6_hoplimit;
	/*
	 * If we're setting extension headers after a connection
	 * has been established, and if we have a routing header
	 * among the extension headers, call ip_massage_options_v6 to
	 * manipulate the routing header/ip6_dst set the checksum
	 * difference in the sctp header template.
	 * (This happens in sctp_connect_ipv6 if the routing header
	 * is set prior to the connect.)
	 */

	if ((sctp->sctp_state >= SCTPS_COOKIE_WAIT) &&
	    (sctp->sctp_sticky_ipp.ipp_fields & IPPF_RTHDR)) {
		ip6_rthdr_t *rth;

		rth = ip_find_rthdr_v6(sctp->sctp_ip6h,
		    (uint8_t *)sctp->sctp_sctph6);
		if (rth != NULL) {
			(void) ip_massage_options_v6(sctp->sctp_ip6h, rth,
			    sctps->sctps_netstack);
		}
	}
	return (0);
}

/*
 * Initialize the IPv6 header. Loses any record of any IPv6 extension headers.
 */
int
sctp_header_init_ipv6(sctp_t *sctp, int sleep)
{
	sctp_hdr_t	*sctph;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * This is a simple initialization. If there's
	 * already a template, it should never be too small,
	 * so reuse it. Otherwise, allocate space for the new one.
	 * Ensure that there is enough space to "downgrade" the sctp_t
	 * to an IPv4 sctp_t. This requires having space for a full load
	 * of IPv4 options
	 */
	if (sctp->sctp_iphc6 != NULL) {
		ASSERT(sctp->sctp_iphc6_len >=
		    SCTP_MAX_COMBINED_HEADER_LENGTH);
		bzero(sctp->sctp_iphc6, sctp->sctp_iphc6_len);
	} else {
		sctp->sctp_iphc6_len = SCTP_MAX_COMBINED_HEADER_LENGTH;
		sctp->sctp_iphc6 = kmem_zalloc(sctp->sctp_iphc_len, sleep);
		if (sctp->sctp_iphc6 == NULL) {
			sctp->sctp_iphc6_len = 0;
			return (ENOMEM);
		}
	}
	sctp->sctp_hdr6_len = IPV6_HDR_LEN + sizeof (sctp_hdr_t);
	sctp->sctp_ip_hdr6_len = IPV6_HDR_LEN;
	sctp->sctp_ip6h = (ip6_t *)sctp->sctp_iphc6;

	/* Initialize the header template */

	sctp->sctp_ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	sctp->sctp_ip6h->ip6_plen = ntohs(sizeof (sctp_hdr_t));
	sctp->sctp_ip6h->ip6_nxt = IPPROTO_SCTP;
	sctp->sctp_ip6h->ip6_hops = sctps->sctps_ipv6_hoplimit;

	sctph = (sctp_hdr_t *)(sctp->sctp_iphc6 + IPV6_HDR_LEN);
	sctp->sctp_sctph6 = sctph;

	return (0);
}

static int
sctp_v4_label(sctp_t *sctp)
{
	uchar_t optbuf[IP_MAX_OPT_LENGTH];
	const cred_t *cr = CONN_CRED(sctp->sctp_connp);
	int added;

	if (tsol_compute_label(cr, sctp->sctp_ipha->ipha_dst, optbuf,
	    sctp->sctp_mac_exempt,
	    sctp->sctp_sctps->sctps_netstack->netstack_ip) != 0)
		return (EACCES);

	added = tsol_remove_secopt(sctp->sctp_ipha, sctp->sctp_hdr_len);
	if (added == -1)
		return (EACCES);
	sctp->sctp_hdr_len += added;
	sctp->sctp_sctph = (sctp_hdr_t *)((uchar_t *)sctp->sctp_sctph + added);
	sctp->sctp_ip_hdr_len += added;
	if ((sctp->sctp_v4label_len = optbuf[IPOPT_OLEN]) != 0) {
		sctp->sctp_v4label_len = (sctp->sctp_v4label_len + 3) & ~3;
		added = tsol_prepend_option(optbuf, sctp->sctp_ipha,
		    sctp->sctp_hdr_len);
		if (added == -1)
			return (EACCES);
		sctp->sctp_hdr_len += added;
		sctp->sctp_sctph = (sctp_hdr_t *)((uchar_t *)sctp->sctp_sctph +
		    added);
		sctp->sctp_ip_hdr_len += added;
	}
	return (0);
}

static int
sctp_v6_label(sctp_t *sctp)
{
	uchar_t optbuf[TSOL_MAX_IPV6_OPTION];
	const cred_t *cr = CONN_CRED(sctp->sctp_connp);

	if (tsol_compute_label_v6(cr, &sctp->sctp_ip6h->ip6_dst, optbuf,
	    sctp->sctp_mac_exempt,
	    sctp->sctp_sctps->sctps_netstack->netstack_ip) != 0)
		return (EACCES);
	if (tsol_update_sticky(&sctp->sctp_sticky_ipp, &sctp->sctp_v6label_len,
	    optbuf) != 0)
		return (EACCES);
	if (sctp_build_hdrs(sctp) != 0)
		return (EACCES);
	return (0);
}

/*
 * XXX implement more sophisticated logic
 */
int
sctp_set_hdraddrs(sctp_t *sctp)
{
	sctp_faddr_t *fp;
	int gotv4 = 0;
	int gotv6 = 0;

	ASSERT(sctp->sctp_faddrs != NULL);
	ASSERT(sctp->sctp_nsaddrs > 0);

	/* Set up using the primary first */
	if (IN6_IS_ADDR_V4MAPPED(&sctp->sctp_primary->faddr)) {
		IN6_V4MAPPED_TO_IPADDR(&sctp->sctp_primary->faddr,
		    sctp->sctp_ipha->ipha_dst);
		/* saddr may be unspec; make_mp() will handle this */
		IN6_V4MAPPED_TO_IPADDR(&sctp->sctp_primary->saddr,
		    sctp->sctp_ipha->ipha_src);
		if (!is_system_labeled() || sctp_v4_label(sctp) == 0) {
			gotv4 = 1;
			if (sctp->sctp_ipversion == IPV4_VERSION) {
				goto copyports;
			}
		}
	} else {
		sctp->sctp_ip6h->ip6_dst = sctp->sctp_primary->faddr;
		/* saddr may be unspec; make_mp() will handle this */
		sctp->sctp_ip6h->ip6_src = sctp->sctp_primary->saddr;
		if (!is_system_labeled() || sctp_v6_label(sctp) == 0)
			gotv6 = 1;
	}

	for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
		if (!gotv4 && IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
			IN6_V4MAPPED_TO_IPADDR(&fp->faddr,
			    sctp->sctp_ipha->ipha_dst);
			/* copy in the faddr_t's saddr */
			IN6_V4MAPPED_TO_IPADDR(&fp->saddr,
			    sctp->sctp_ipha->ipha_src);
			if (!is_system_labeled() || sctp_v4_label(sctp) == 0) {
				gotv4 = 1;
				if (sctp->sctp_ipversion == IPV4_VERSION ||
				    gotv6) {
					break;
				}
			}
		} else if (!gotv6 && !IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
			sctp->sctp_ip6h->ip6_dst = fp->faddr;
			/* copy in the faddr_t's saddr */
			sctp->sctp_ip6h->ip6_src = fp->saddr;
			if (!is_system_labeled() || sctp_v6_label(sctp) == 0) {
				gotv6 = 1;
				if (gotv4)
					break;
			}
		}
	}

copyports:
	if (!gotv4 && !gotv6)
		return (EACCES);

	/* copy in the ports for good measure */
	sctp->sctp_sctph->sh_sport = sctp->sctp_lport;
	sctp->sctp_sctph->sh_dport = sctp->sctp_fport;

	sctp->sctp_sctph6->sh_sport = sctp->sctp_lport;
	sctp->sctp_sctph6->sh_dport = sctp->sctp_fport;
	return (0);
}

/*
 * got_errchunk is set B_TRUE only if called from validate_init_params(), when
 * an ERROR chunk is already prepended the size of which needs updating for
 * additional unrecognized parameters. Other callers either prepend the ERROR
 * chunk with the correct size after calling this function, or they are calling
 * to add an invalid parameter to an INIT_ACK chunk, in that case no ERROR chunk
 * exists, the CAUSE blocks go into the INIT_ACK directly.
 *
 * *errmp will be non-NULL both when adding an additional CAUSE block to an
 * existing prepended COOKIE ERROR chunk (processing params of an INIT_ACK),
 * and when adding unrecognized parameters after the first, to an INIT_ACK
 * (processing params of an INIT chunk).
 */
void
sctp_add_unrec_parm(sctp_parm_hdr_t *uph, mblk_t **errmp,
    boolean_t got_errchunk)
{
	mblk_t *mp;
	sctp_parm_hdr_t *ph;
	size_t len;
	int pad;
	sctp_chunk_hdr_t *ecp;

	len = sizeof (*ph) + ntohs(uph->sph_len);
	if ((pad = len % SCTP_ALIGN) != 0) {
		pad = SCTP_ALIGN - pad;
		len += pad;
	}
	mp = allocb(len, BPRI_MED);
	if (mp == NULL) {
		return;
	}

	ph = (sctp_parm_hdr_t *)(mp->b_rptr);
	ph->sph_type = htons(PARM_UNRECOGNIZED);
	ph->sph_len = htons(len - pad);

	/* copy in the unrecognized parameter */
	bcopy(uph, ph + 1, ntohs(uph->sph_len));

	if (pad != 0)
		bzero((mp->b_rptr + len - pad), pad);

	mp->b_wptr = mp->b_rptr + len;
	if (*errmp != NULL) {
		/*
		 * Update total length if an ERROR chunk, then link
		 * this CAUSE block to the possible chain of CAUSE
		 * blocks attached to the ERROR chunk or INIT_ACK
		 * being created.
		 */
		if (got_errchunk) {
			/* ERROR chunk already prepended */
			ecp = (sctp_chunk_hdr_t *)((*errmp)->b_rptr);
			ecp->sch_len = htons(ntohs(ecp->sch_len) + len);
		}
		linkb(*errmp, mp);
	} else {
		*errmp = mp;
	}
}

/*
 * o Bounds checking
 * o Updates remaining
 * o Checks alignment
 */
sctp_parm_hdr_t *
sctp_next_parm(sctp_parm_hdr_t *current, ssize_t *remaining)
{
	int pad;
	uint16_t len;

	len = ntohs(current->sph_len);
	*remaining -= len;
	if (*remaining < sizeof (*current) || len < sizeof (*current)) {
		return (NULL);
	}
	if ((pad = len & (SCTP_ALIGN - 1)) != 0) {
		pad = SCTP_ALIGN - pad;
		*remaining -= pad;
	}
	/*LINTED pointer cast may result in improper alignment*/
	current = (sctp_parm_hdr_t *)((char *)current + len + pad);
	return (current);
}

/*
 * Sets the address parameters given in the INIT chunk into sctp's
 * faddrs; if psctp is non-NULL, copies psctp's saddrs. If there are
 * no address parameters in the INIT chunk, a single faddr is created
 * from the ip hdr at the beginning of pkt.
 * If there already are existing addresses hanging from sctp, merge
 * them in, if the old info contains addresses which are not present
 * in this new info, get rid of them, and clean the pointers if there's
 * messages which have this as their target address.
 *
 * We also re-adjust the source address list here since the list may
 * contain more than what is actually part of the association. If
 * we get here from sctp_send_cookie_echo(), we are on the active
 * side and psctp will be NULL and ich will be the INIT-ACK chunk.
 * If we get here from sctp_accept_comm(), ich will be the INIT chunk
 * and psctp will the listening endpoint.
 *
 * INIT processing: When processing the INIT we inherit the src address
 * list from the listener. For a loopback or linklocal association, we
 * delete the list and just take the address from the IP header (since
 * that's how we created the INIT-ACK). Additionally, for loopback we
 * ignore the address params in the INIT. For determining which address
 * types were sent in the INIT-ACK we follow the same logic as in
 * creating the INIT-ACK. We delete addresses of the type that are not
 * supported by the peer.
 *
 * INIT-ACK processing: When processing the INIT-ACK since we had not
 * included addr params for loopback or linklocal addresses when creating
 * the INIT, we just use the address from the IP header. Further, for
 * loopback we ignore the addr param list. We mark addresses of the
 * type not supported by the peer as unconfirmed.
 *
 * In case of INIT processing we look for supported address types in the
 * supported address param, if present. In both cases the address type in
 * the IP header is supported as well as types for addresses in the param
 * list, if any.
 *
 * Once we have the supported address types sctp_check_saddr() runs through
 * the source address list and deletes or marks as unconfirmed address of
 * types not supported by the peer.
 *
 * Returns 0 on success, sys errno on failure
 */
int
sctp_get_addrparams(sctp_t *sctp, sctp_t *psctp, mblk_t *pkt,
    sctp_chunk_hdr_t *ich, uint_t *sctp_options)
{
	sctp_init_chunk_t	*init;
	ipha_t			*iph;
	ip6_t			*ip6h;
	in6_addr_t		hdrsaddr[1];
	in6_addr_t		hdrdaddr[1];
	sctp_parm_hdr_t		*ph;
	ssize_t			remaining;
	int			isv4;
	int			err;
	sctp_faddr_t		*fp;
	int			supp_af = 0;
	boolean_t		check_saddr = B_TRUE;
	in6_addr_t		curaddr;
	sctp_stack_t		*sctps = sctp->sctp_sctps;

	if (sctp_options != NULL)
		*sctp_options = 0;

	/* extract the address from the IP header */
	isv4 = (IPH_HDR_VERSION(pkt->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)pkt->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_src, hdrsaddr);
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_dst, hdrdaddr);
		supp_af |= PARM_SUPP_V4;
	} else {
		ip6h = (ip6_t *)pkt->b_rptr;
		hdrsaddr[0] = ip6h->ip6_src;
		hdrdaddr[0] = ip6h->ip6_dst;
		supp_af |= PARM_SUPP_V6;
	}

	/*
	 * Unfortunately, we can't delay this because adding an faddr
	 * looks for the presence of the source address (from the ire
	 * for the faddr) in the source address list. We could have
	 * delayed this if, say, this was a loopback/linklocal connection.
	 * Now, we just end up nuking this list and taking the addr from
	 * the IP header for loopback/linklocal.
	 */
	if (psctp != NULL && psctp->sctp_nsaddrs > 0) {
		ASSERT(sctp->sctp_nsaddrs == 0);

		err = sctp_dup_saddrs(psctp, sctp, KM_NOSLEEP);
		if (err != 0)
			return (err);
	}
	/*
	 * We will add the faddr before parsing the address list as this
	 * might be a loopback connection and we would not have to
	 * go through the list.
	 *
	 * Make sure the header's addr is in the list
	 */
	fp = sctp_lookup_faddr(sctp, hdrsaddr);
	if (fp == NULL) {
		/* not included; add it now */
		err = sctp_add_faddr(sctp, hdrsaddr, KM_NOSLEEP, B_TRUE);
		if (err != 0)
			return (err);

		/* sctp_faddrs will be the hdr addr */
		fp = sctp->sctp_faddrs;
	}
	/* make the header addr the primary */

	if (cl_sctp_assoc_change != NULL && psctp == NULL)
		curaddr = sctp->sctp_current->faddr;

	sctp->sctp_primary = fp;
	sctp->sctp_current = fp;
	sctp->sctp_mss = fp->sfa_pmss;

	/* For loopback connections & linklocal get address from the header */
	if (sctp->sctp_loopback || sctp->sctp_linklocal) {
		if (sctp->sctp_nsaddrs != 0)
			sctp_free_saddrs(sctp);
		if ((err = sctp_saddr_add_addr(sctp, hdrdaddr, 0)) != 0)
			return (err);
		/* For loopback ignore address list */
		if (sctp->sctp_loopback)
			return (0);
		check_saddr = B_FALSE;
	}

	/* Walk the params in the INIT [ACK], pulling out addr params */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) -
	    sizeof (sctp_init_chunk_t);
	if (remaining < sizeof (*ph)) {
		if (check_saddr) {
			sctp_check_saddr(sctp, supp_af, psctp == NULL ?
			    B_FALSE : B_TRUE, hdrdaddr);
		}
		ASSERT(sctp_saddr_lookup(sctp, hdrdaddr, 0) != NULL);
		return (0);
	}

	init = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(init + 1);

	/* params will have already been byteordered when validating */
	while (ph != NULL) {
		if (ph->sph_type == htons(PARM_SUPP_ADDRS)) {
			int		plen;
			uint16_t	*p;
			uint16_t	addrtype;

			ASSERT(psctp != NULL);
			plen = ntohs(ph->sph_len);
			p = (uint16_t *)(ph + 1);
			while (plen > 0) {
				addrtype = ntohs(*p);
				switch (addrtype) {
					case PARM_ADDR6:
						supp_af |= PARM_SUPP_V6;
						break;
					case PARM_ADDR4:
						supp_af |= PARM_SUPP_V4;
						break;
					default:
						break;
				}
				p++;
				plen -= sizeof (*p);
			}
		} else if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				ipaddr_t ta;

				supp_af |= PARM_SUPP_V4;
				/*
				 * Screen out broad/multicasts & loopback.
				 * If the endpoint only accepts v6 address,
				 * go to the next one.
				 *
				 * Subnet broadcast check is done in
				 * sctp_add_faddr().  If the address is
				 * a broadcast address, it won't be added.
				 */
				bcopy(ph + 1, &ta, sizeof (ta));
				if (ta == 0 ||
				    ta == INADDR_BROADCAST ||
				    ta == htonl(INADDR_LOOPBACK) ||
				    CLASSD(ta) ||
				    sctp->sctp_connp->conn_ipv6_v6only) {
					goto next;
				}
				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);

				/* Check for duplicate. */
				if (sctp_lookup_faddr(sctp, &addr) != NULL)
					goto next;

				/* OK, add it to the faddr set */
				err = sctp_add_faddr(sctp, &addr, KM_NOSLEEP,
				    B_FALSE);
				/* Something is wrong...  Try the next one. */
				if (err != 0)
					goto next;
			}
		} else if (ph->sph_type == htons(PARM_ADDR6) &&
		    sctp->sctp_family == AF_INET6) {
			/* An v4 socket should not take v6 addresses. */
			if (remaining >= PARM_ADDR6_LEN) {
				in6_addr_t *addr6;

				supp_af |= PARM_SUPP_V6;
				addr6 = (in6_addr_t *)(ph + 1);
				/*
				 * Screen out link locals, mcast, loopback
				 * and bogus v6 address.
				 */
				if (IN6_IS_ADDR_LINKLOCAL(addr6) ||
				    IN6_IS_ADDR_MULTICAST(addr6) ||
				    IN6_IS_ADDR_LOOPBACK(addr6) ||
				    IN6_IS_ADDR_V4MAPPED(addr6)) {
					goto next;
				}
				/* Check for duplicate. */
				if (sctp_lookup_faddr(sctp, addr6) != NULL)
					goto next;

				err = sctp_add_faddr(sctp,
				    (in6_addr_t *)(ph + 1), KM_NOSLEEP,
				    B_FALSE);
				/* Something is wrong...  Try the next one. */
				if (err != 0)
					goto next;
			}
		} else if (ph->sph_type == htons(PARM_FORWARD_TSN)) {
			if (sctp_options != NULL)
				*sctp_options |= SCTP_PRSCTP_OPTION;
		} /* else; skip */

next:
		ph = sctp_next_parm(ph, &remaining);
	}
	if (check_saddr) {
		sctp_check_saddr(sctp, supp_af, psctp == NULL ? B_FALSE :
		    B_TRUE, hdrdaddr);
	}
	ASSERT(sctp_saddr_lookup(sctp, hdrdaddr, 0) != NULL);
	/*
	 * We have the right address list now, update clustering's
	 * knowledge because when we sent the INIT we had just added
	 * the address the INIT was sent to.
	 */
	if (psctp == NULL && cl_sctp_assoc_change != NULL) {
		uchar_t	*alist;
		size_t	asize;
		uchar_t	*dlist;
		size_t	dsize;

		asize = sizeof (in6_addr_t) * sctp->sctp_nfaddrs;
		alist = kmem_alloc(asize, KM_NOSLEEP);
		if (alist == NULL) {
			SCTP_KSTAT(sctps, sctp_cl_assoc_change);
			return (ENOMEM);
		}
		/*
		 * Just include the address the INIT was sent to in the
		 * delete list and send the entire faddr list. We could
		 * do it differently (i.e include all the addresses in the
		 * add list even if it contains the original address OR
		 * remove the original address from the add list etc.), but
		 * this seems reasonable enough.
		 */
		dsize = sizeof (in6_addr_t);
		dlist = kmem_alloc(dsize, KM_NOSLEEP);
		if (dlist == NULL) {
			kmem_free(alist, asize);
			SCTP_KSTAT(sctps, sctp_cl_assoc_change);
			return (ENOMEM);
		}
		bcopy(&curaddr, dlist, sizeof (curaddr));
		sctp_get_faddr_list(sctp, alist, asize);
		(*cl_sctp_assoc_change)(sctp->sctp_family, alist, asize,
		    sctp->sctp_nfaddrs, dlist, dsize, 1, SCTP_CL_PADDR,
		    (cl_sctp_handle_t)sctp);
		/* alist and dlist will be freed by the clustering module */
	}
	return (0);
}

/*
 * Returns 0 if the check failed and the restart should be refused,
 * 1 if the check succeeded.
 */
int
sctp_secure_restart_check(mblk_t *pkt, sctp_chunk_hdr_t *ich, uint32_t ports,
    int sleep, sctp_stack_t *sctps)
{
	sctp_faddr_t *fp, *fphead = NULL;
	sctp_parm_hdr_t *ph;
	ssize_t remaining;
	int isv4;
	ipha_t *iph;
	ip6_t *ip6h;
	in6_addr_t hdraddr[1];
	int retval = 0;
	sctp_tf_t *tf;
	sctp_t *sctp;
	int compres;
	sctp_init_chunk_t *init;
	int nadded = 0;

	/* extract the address from the IP header */
	isv4 = (IPH_HDR_VERSION(pkt->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)pkt->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_src, hdraddr);
	} else {
		ip6h = (ip6_t *)pkt->b_rptr;
		hdraddr[0] = ip6h->ip6_src;
	}

	/* Walk the params in the INIT [ACK], pulling out addr params */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) -
	    sizeof (sctp_init_chunk_t);
	if (remaining < sizeof (*ph)) {
		/* no parameters; restart OK */
		return (1);
	}
	init = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(init + 1);

	while (ph != NULL) {
		sctp_faddr_t *fpa = NULL;

		/* params will have already been byteordered when validating */
		if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);
				fpa = kmem_cache_alloc(sctp_kmem_faddr_cache,
				    sleep);
				if (fpa == NULL) {
					goto done;
				}
				bzero(fpa, sizeof (*fpa));
				fpa->faddr = addr;
				fpa->next = NULL;
			}
		} else if (ph->sph_type == htons(PARM_ADDR6)) {
			if (remaining >= PARM_ADDR6_LEN) {
				fpa = kmem_cache_alloc(sctp_kmem_faddr_cache,
				    sleep);
				if (fpa == NULL) {
					goto done;
				}
				bzero(fpa, sizeof (*fpa));
				bcopy(ph + 1, &fpa->faddr,
				    sizeof (fpa->faddr));
				fpa->next = NULL;
			}
		}
		/* link in the new addr, if it was an addr param */
		if (fpa != NULL) {
			if (fphead == NULL) {
				fphead = fpa;
			} else {
				fpa->next = fphead;
				fphead = fpa;
			}
		}

		ph = sctp_next_parm(ph, &remaining);
	}

	if (fphead == NULL) {
		/* no addr parameters; restart OK */
		return (1);
	}

	/*
	 * got at least one; make sure the header's addr is
	 * in the list
	 */
	fp = sctp_lookup_faddr_nosctp(fphead, hdraddr);
	if (fp == NULL) {
		/* not included; add it now */
		fp = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep);
		if (fp == NULL) {
			goto done;
		}
		bzero(fp, sizeof (*fp));
		fp->faddr = *hdraddr;
		fp->next = fphead;
		fphead = fp;
	}

	/*
	 * Now, we can finally do the check: For each sctp instance
	 * on the hash line for ports, compare its faddr set against
	 * the new one. If the new one is a strict subset of any
	 * existing sctp's faddrs, the restart is OK. However, if there
	 * is an overlap, this could be an attack, so return failure.
	 * If all sctp's faddrs are disjoint, this is a legitimate new
	 * association.
	 */
	tf = &(sctps->sctps_conn_fanout[SCTP_CONN_HASH(sctps, ports)]);
	mutex_enter(&tf->tf_lock);

	for (sctp = tf->tf_sctp; sctp; sctp = sctp->sctp_conn_hash_next) {
		if (ports != sctp->sctp_ports) {
			continue;
		}
		compres = sctp_compare_faddrsets(fphead, sctp->sctp_faddrs);
		if (compres <= SCTP_ADDR_SUBSET) {
			retval = 1;
			mutex_exit(&tf->tf_lock);
			goto done;
		}
		if (compres == SCTP_ADDR_OVERLAP) {
			dprint(1,
			    ("new assoc from %x:%x:%x:%x overlaps with %p\n",
			    SCTP_PRINTADDR(*hdraddr), (void *)sctp));
			/*
			 * While we still hold the lock, we need to
			 * figure out which addresses have been
			 * added so we can include them in the abort
			 * we will send back. Since these faddrs will
			 * never be used, we overload the rto field
			 * here, setting it to 0 if the address was
			 * not added, 1 if it was added.
			 */
			for (fp = fphead; fp; fp = fp->next) {
				if (sctp_lookup_faddr(sctp, &fp->faddr)) {
					fp->rto = 0;
				} else {
					fp->rto = 1;
					nadded++;
				}
			}
			mutex_exit(&tf->tf_lock);
			goto done;
		}
	}
	mutex_exit(&tf->tf_lock);

	/* All faddrs are disjoint; legit new association */
	retval = 1;

done:
	/* If are attempted adds, send back an abort listing the addrs */
	if (nadded > 0) {
		void *dtail;
		size_t dlen;

		dtail = kmem_alloc(PARM_ADDR6_LEN * nadded, KM_NOSLEEP);
		if (dtail == NULL) {
			goto cleanup;
		}

		ph = dtail;
		dlen = 0;
		for (fp = fphead; fp; fp = fp->next) {
			if (fp->rto == 0) {
				continue;
			}
			if (IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
				ipaddr_t addr4;

				ph->sph_type = htons(PARM_ADDR4);
				ph->sph_len = htons(PARM_ADDR4_LEN);
				IN6_V4MAPPED_TO_IPADDR(&fp->faddr, addr4);
				ph++;
				bcopy(&addr4, ph, sizeof (addr4));
				ph = (sctp_parm_hdr_t *)
				    ((char *)ph + sizeof (addr4));
				dlen += PARM_ADDR4_LEN;
			} else {
				ph->sph_type = htons(PARM_ADDR6);
				ph->sph_len = htons(PARM_ADDR6_LEN);
				ph++;
				bcopy(&fp->faddr, ph, sizeof (fp->faddr));
				ph = (sctp_parm_hdr_t *)
				    ((char *)ph + sizeof (fp->faddr));
				dlen += PARM_ADDR6_LEN;
			}
		}

		/* Send off the abort */
		sctp_send_abort(sctp, sctp_init2vtag(ich),
		    SCTP_ERR_RESTART_NEW_ADDRS, dtail, dlen, pkt, 0, B_TRUE);

		kmem_free(dtail, PARM_ADDR6_LEN * nadded);
	}

cleanup:
	/* Clean up */
	if (fphead) {
		sctp_faddr_t *fpn;
		for (fp = fphead; fp; fp = fpn) {
			fpn = fp->next;
			kmem_cache_free(sctp_kmem_faddr_cache, fp);
		}
	}

	return (retval);
}

/*
 * Reset any state related to transmitted chunks.
 */
void
sctp_congest_reset(sctp_t *sctp)
{
	sctp_faddr_t	*fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	mblk_t		*mp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		fp->ssthresh = sctps->sctps_initial_mtu;
		SET_CWND(fp, fp->sfa_pmss, sctps->sctps_slow_start_initial);
		fp->suna = 0;
		fp->pba = 0;
	}
	/*
	 * Clean up the transmit list as well since we have reset accounting
	 * on all the fps. Send event upstream, if required.
	 */
	while ((mp = sctp->sctp_xmit_head) != NULL) {
		sctp->sctp_xmit_head = mp->b_next;
		mp->b_next = NULL;
		if (sctp->sctp_xmit_head != NULL)
			sctp->sctp_xmit_head->b_prev = NULL;
		sctp_sendfail_event(sctp, mp, 0, B_TRUE);
	}
	sctp->sctp_xmit_head = NULL;
	sctp->sctp_xmit_tail = NULL;
	sctp->sctp_xmit_unacked = NULL;

	sctp->sctp_unacked = 0;
	/*
	 * Any control message as well. We will clean-up this list as well.
	 * This contains any pending ASCONF request that we have queued/sent.
	 * If we do get an ACK we will just drop it. However, given that
	 * we are restarting chances are we aren't going to get any.
	 */
	if (sctp->sctp_cxmit_list != NULL)
		sctp_asconf_free_cxmit(sctp, NULL);
	sctp->sctp_cxmit_list = NULL;
	sctp->sctp_cchunk_pend = 0;

	sctp->sctp_rexmitting = B_FALSE;
	sctp->sctp_rxt_nxttsn = 0;
	sctp->sctp_rxt_maxtsn = 0;

	sctp->sctp_zero_win_probe = B_FALSE;
}

static void
sctp_init_faddr(sctp_t *sctp, sctp_faddr_t *fp, in6_addr_t *addr,
    mblk_t *timer_mp)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	bcopy(addr, &fp->faddr, sizeof (*addr));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		fp->isv4 = 1;
		/* Make sure that sfa_pmss is a multiple of SCTP_ALIGN. */
		fp->sfa_pmss =
		    (sctps->sctps_initial_mtu - sctp->sctp_hdr_len) &
		    ~(SCTP_ALIGN - 1);
	} else {
		fp->isv4 = 0;
		fp->sfa_pmss =
		    (sctps->sctps_initial_mtu - sctp->sctp_hdr6_len) &
		    ~(SCTP_ALIGN - 1);
	}
	fp->cwnd = sctps->sctps_slow_start_initial * fp->sfa_pmss;
	fp->rto = MIN(sctp->sctp_rto_initial, sctp->sctp_init_rto_max);
	fp->srtt = -1;
	fp->rtt_updates = 0;
	fp->strikes = 0;
	fp->max_retr = sctp->sctp_pp_max_rxt;
	/* Mark it as not confirmed. */
	fp->state = SCTP_FADDRS_UNCONFIRMED;
	fp->hb_interval = sctp->sctp_hb_interval;
	fp->ssthresh = sctps->sctps_initial_ssthresh;
	fp->suna = 0;
	fp->pba = 0;
	fp->acked = 0;
	fp->lastactive = lbolt64;
	fp->timer_mp = timer_mp;
	fp->hb_pending = B_FALSE;
	fp->hb_enabled = B_TRUE;
	fp->df = 1;
	fp->pmtu_discovered = 0;
	fp->next = NULL;
	fp->ire = NULL;
	fp->T3expire = 0;
	(void) random_get_pseudo_bytes((uint8_t *)&fp->hb_secret,
	    sizeof (fp->hb_secret));
	fp->hb_expiry = lbolt64;
	fp->rxt_unacked = 0;

	sctp_get_ire(sctp, fp);
}

/*ARGSUSED*/
static int
faddr_constructor(void *buf, void *arg, int flags)
{
	sctp_faddr_t *fp = buf;

	fp->timer_mp = NULL;
	fp->timer_running = 0;

	fp->rc_timer_mp = NULL;
	fp->rc_timer_running = 0;

	return (0);
}

/*ARGSUSED*/
static void
faddr_destructor(void *buf, void *arg)
{
	sctp_faddr_t *fp = buf;

	ASSERT(fp->timer_mp == NULL);
	ASSERT(fp->timer_running == 0);

	ASSERT(fp->rc_timer_mp == NULL);
	ASSERT(fp->rc_timer_running == 0);
}

void
sctp_faddr_init(void)
{
	sctp_kmem_faddr_cache = kmem_cache_create("sctp_faddr_cache",
	    sizeof (sctp_faddr_t), 0, faddr_constructor, faddr_destructor,
	    NULL, NULL, NULL, 0);
}

void
sctp_faddr_fini(void)
{
	kmem_cache_destroy(sctp_kmem_faddr_cache);
}
