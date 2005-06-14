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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/random.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

static struct kmem_cache *sctp_kmem_faddr_cache;
static void sctp_init_faddr(sctp_t *, sctp_faddr_t *, in6_addr_t *);

/* Set the source address.  Refer to comments in sctp_ire2faddr(). */
static void
set_saddr(sctp_t *sctp, sctp_faddr_t *fp, boolean_t v6)
{
	if (sctp->sctp_bound_to_all) {
		V6_SET_ZERO(fp->saddr);
	} else {
		fp->saddr = sctp_get_valid_addr(sctp, v6);
		if (!v6 && IN6_IS_ADDR_V4MAPPED_ANY(&fp->saddr) ||
		    v6 && IN6_IS_ADDR_UNSPECIFIED(&fp->saddr)) {
			fp->state = SCTP_FADDRS_UNREACH;
			/* Disable heartbeat. */
			fp->hb_expiry = 0;
			fp->hb_pending = B_FALSE;
			fp->strikes = 0;
		}
	}
}

/*
 * Call this function to update the cached IRE of a peer addr fp.
 */
void
sctp_ire2faddr(sctp_t *sctp, sctp_faddr_t *fp)
{
	ire_t *ire;
	ipaddr_t addr4;
	in6_addr_t laddr;
	sctp_saddr_ipif_t *sp;
	uint_t	ipif_seqid;
	int hdrlen;

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

	if (fp->isv4) {
		IN6_V4MAPPED_TO_IPADDR(&fp->faddr, addr4);

		ire = ire_cache_lookup(addr4, sctp->sctp_zoneid);
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
			set_saddr(sctp, fp, B_FALSE);
			goto set_current;
		}
		ipif_seqid = ire->ire_ipif->ipif_seqid;
		dprint(2, ("ire2faddr: got ire for %x:%x:%x:%x, ",
			SCTP_PRINTADDR(fp->faddr)));
		dprint(2, ("src = %x\n", ire->ire_src_addr));
		IN6_IPADDR_TO_V4MAPPED(ire->ire_src_addr, &laddr);

		/* make sure the laddr is part of this association */
		if ((sp = sctp_ipif_lookup(sctp, ipif_seqid)) !=
		    NULL && !sp->saddr_ipif_dontsrc) {
			fp->saddr = laddr;
		} else {
			ip2dbg(("ire2faddr: src addr is not part of assc\n"));
			set_saddr(sctp, fp, B_FALSE);
		}
	} else {
		ire = ire_cache_lookup_v6(&fp->faddr, sctp->sctp_zoneid);
		if (ire == NULL) {
			dprint(3, ("ire2faddr: no ire for %x:%x:%x:%x\n",
			    SCTP_PRINTADDR(fp->faddr)));
			set_saddr(sctp, fp, B_TRUE);
			goto set_current;
		}
		ipif_seqid = ire->ire_ipif->ipif_seqid;
		dprint(2, ("ire2faddr: got ire for %x:%x:%x:%x, ",
		    SCTP_PRINTADDR(fp->faddr)));
		dprint(2, ("src=%x:%x:%x:%x\n",
		    SCTP_PRINTADDR(ire->ire_src_addr_v6)));
		laddr = ire->ire_src_addr_v6;

		/* make sure the laddr is part of this association */

		if ((sp = sctp_ipif_lookup(sctp, ipif_seqid)) !=
		    NULL && !sp->saddr_ipif_dontsrc) {
			fp->saddr = laddr;
		} else {
			dprint(2, ("ire2faddr: src addr is not part "
				"of assc\n"));
			set_saddr(sctp, fp, B_TRUE);
		}
	}

	/* Cache the IRE */
	IRE_REFHOLD_NOTR(ire);
	fp->ire = ire;
	if (fp->ire->ire_type == IRE_LOOPBACK && !sctp->sctp_loopback)
		sctp->sctp_loopback = 1;
	IRE_REFRELE(ire);

	/*
	 * Pull out RTO information for this faddr and use it if we don't
	 * have any yet.
	 */
	if (fp->srtt == -1 && ire->ire_uinfo.iulp_rtt != 0) {
		fp->srtt = ire->ire_uinfo.iulp_rtt;
		fp->rttvar = ire->ire_uinfo.iulp_rtt_sd;
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
			fp->cwnd = fp->sfa_pmss * sctp_slow_start_initial;
		}
	}

set_current:
	if (fp == sctp->sctp_current) {
		sctp_faddr2hdraddr(fp, sctp);
		sctp->sctp_mss = fp->sfa_pmss;
		if (!SCTP_IS_DETACHED(sctp)) {
			sctp_set_ulp_prop(sctp);
		}
	}
}

/*ARGSUSED*/
void
sctp_faddr2ire(sctp_t *sctp, sctp_faddr_t *fp)
{
	ire_t *ire;

	if ((ire = fp->ire) == NULL) {
		return;
	}

	mutex_enter(&ire->ire_lock);

	/* If the cached IRE is going sway, there is no point to update it. */
	if (ire->ire_marks & IRE_MARK_CONDEMNED) {
		mutex_exit(&ire->ire_lock);
		IRE_REFRELE_NOTR(ire);
		fp->ire = NULL;
		return;
	}

	/*
	 * Only record the PMTU for this faddr if we actually have
	 * done discovery. This prevents initialized default from
	 * clobbering any real info that IP may have.
	 */
	if (fp->pmtu_discovered) {
		if (fp->isv4) {
			ire->ire_max_frag = fp->sfa_pmss + sctp->sctp_hdr_len;
		} else {
			ire->ire_max_frag = fp->sfa_pmss + sctp->sctp_hdr6_len;
		}
	}

	if (fp->rtt_updates >= sctp_rtt_updates) {
		/*
		 * If there is no old cached values, initialize them
		 * conservatively.  Set them to be (1.5 * new value).
		 * This code copied from ip_ire_advise().
		 */
		if (ire->ire_uinfo.iulp_rtt != 0) {
			ire->ire_uinfo.iulp_rtt = (ire->ire_uinfo.iulp_rtt +
			    fp->srtt) >> 1;
		} else {
			ire->ire_uinfo.iulp_rtt = fp->srtt +
			    (fp->srtt >> 1);
		}
		if (ire->ire_uinfo.iulp_rtt_sd != 0) {
			ire->ire_uinfo.iulp_rtt_sd =
			    (ire->ire_uinfo.iulp_rtt_sd +
			    fp->rttvar) >> 1;
		} else {
			ire->ire_uinfo.iulp_rtt_sd = fp->rttvar +
			    (fp->rttvar >> 1);
		}
		fp->rtt_updates = 0;
	}

	mutex_exit(&ire->ire_lock);
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

	ASSERT(sctp->sctp_current != NULL || sendto != NULL);
	if (sendto == NULL) {
		fp = sctp->sctp_current;
	} else {
		fp = sendto;
	}
	isv4 = fp->isv4;

	/* Try to look for another IRE again. */
	if (fp->ire == NULL)
		sctp_ire2faddr(sctp, fp);

	/* There is no suitable source address to use, return. */
	if (fp->state == SCTP_FADDRS_UNREACH)
		return (NULL);

	if (isv4) {
		ipsctplen = sctp->sctp_hdr_len;
	} else {
		ipsctplen = sctp->sctp_hdr6_len;
	}

	mp = allocb(ipsctplen + sctp_wroff_xtra + trailer, BPRI_MED);
	if (mp == NULL) {
		ip1dbg(("sctp_make_mp: error makign mp..\n"));
		return (NULL);
	}
	mp->b_rptr += sctp_wroff_xtra;
	mp->b_wptr = mp->b_rptr + ipsctplen;

	ASSERT(OK_32PTR(mp->b_wptr));

	if (isv4) {
		ipha_t *iph = (ipha_t *)mp->b_rptr;

		bcopy(sctp->sctp_iphc, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current) {
			/* fiddle with the dst addr */
			IN6_V4MAPPED_TO_IPADDR(&fp->faddr, iph->ipha_dst);
			/* fix up src addr */
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&fp->saddr)) {
				IN6_V4MAPPED_TO_IPADDR(&fp->saddr,
				    iph->ipha_src);
			} else if (sctp->sctp_bound_to_all) {
				iph->ipha_src = INADDR_ANY;
			}
		}
		/* set or clear the don't fragment bit */
		if (fp->df) {
			iph->ipha_fragment_offset_and_flags = htons(IPH_DF);
		} else {
			iph->ipha_fragment_offset_and_flags = 0;
		}
	} else {
		bcopy(sctp->sctp_iphc6, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current) {
			/* fiddle with the dst addr */
			((ip6_t *)(mp->b_rptr))->ip6_dst = fp->faddr;
			/* fix up src addr */
			if (!IN6_IS_ADDR_UNSPECIFIED(&fp->saddr)) {
				((ip6_t *)(mp->b_rptr))->ip6_src = fp->saddr;
			} else if (sctp->sctp_bound_to_all) {
				bzero(&((ip6_t *)(mp->b_rptr))->ip6_src,
				    sizeof (in6_addr_t));
			}
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

	if (sctp->sctp_current->isv4) {
		hdrlen = sctp->sctp_hdr_len;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
	}
	ASSERT(sctp->sctp_ulpd);

	ASSERT(sctp->sctp_current->sfa_pmss == sctp->sctp_mss);
	sctp->sctp_ulp_prop(sctp->sctp_ulpd,
	    sctp_wroff_xtra + hdrlen + sizeof (sctp_data_hdr_t),
	    sctp->sctp_mss - sizeof (sctp_data_hdr_t));
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
 * is true, should never fail.
 * Caller must hold conn fanout lock.
 */
int
sctp_add_faddr(sctp_t *sctp, in6_addr_t *addr, int sleep)
{
	sctp_faddr_t *faddr;

	dprint(4, ("add_faddr: %x:%x:%x:%x %d\n", SCTP_PRINTADDR(*addr),
	    sleep));

	if ((faddr = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep)) == NULL) {
		return (-1);
	}

	sctp_init_faddr(sctp, faddr, addr);
	ASSERT(faddr->next == NULL);

	/* tack it on to the end */
	if (sctp->sctp_lastfaddr != NULL) {
		sctp->sctp_lastfaddr->next = faddr;
	} else {
		/* list is empty */
		ASSERT(sctp->sctp_faddrs == NULL);
		sctp->sctp_faddrs = faddr;
	}
	sctp->sctp_lastfaddr = faddr;

	return (0);
}

/*
 * Caller must hold conn fanout lock.
 */
int
sctp_add_faddr_first(sctp_t *sctp, in6_addr_t *addr, int sleep)
{
	sctp_faddr_t *faddr;

	dprint(4, ("add_faddr_first: %x:%x:%x:%x %d\n", SCTP_PRINTADDR(*addr),
	    sleep));

	if ((faddr = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep)) == NULL) {
		return (-1);
	}
	sctp_init_faddr(sctp, faddr, addr);
	ASSERT(faddr->next == NULL);

	/* Put it at the beginning of the list */
	if (sctp->sctp_faddrs != NULL) {
		faddr->next = sctp->sctp_faddrs;
	} else {
		sctp->sctp_lastfaddr = faddr;
	}
	sctp->sctp_faddrs = faddr;

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

void
sctp_faddr2hdraddr(sctp_faddr_t *fp, sctp_t *sctp)
{
	if (fp->isv4) {
		IN6_V4MAPPED_TO_IPADDR(&fp->faddr,
		    sctp->sctp_ipha->ipha_dst);
		/* Must not allow unspec src addr if not bound to all */
		if (IN6_IS_ADDR_V4MAPPED_ANY(&fp->saddr) &&
		    !sctp->sctp_bound_to_all) {
			/*
			 * set the src to the first v4 saddr and hope
			 * for the best
			 */
			fp->saddr = sctp_get_valid_addr(sctp, B_FALSE);
		}
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
		/* Must not allow unspec src addr if not bound to all */
		if (IN6_IS_ADDR_UNSPECIFIED(&fp->saddr) &&
		    !sctp->sctp_bound_to_all) {
			/*
			 * set the src to the first v6 saddr and hope
			 * for the best
			 */
			fp->saddr = sctp_get_valid_addr(sctp, B_TRUE);
		}
		sctp->sctp_ip6h->ip6_src = fp->saddr;
	}
}

void
sctp_redo_faddr_srcs(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		sctp_ire2faddr(sctp, fp);
	}

	sctp_faddr2hdraddr(sctp->sctp_current, sctp);
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

		/* If this is the primary, switch back to it now */
		if (fp == sctp->sctp_primary) {
			sctp->sctp_current = fp;
			sctp->sctp_mss = fp->sfa_pmss;
			/* Reset the addrs in the composite header */
			sctp_faddr2hdraddr(fp, sctp);
			if (!SCTP_IS_DETACHED(sctp)) {
				sctp_set_ulp_prop(sctp);
			}
		}
	}
	if (fp->ire == NULL) {
		/* Should have a full IRE now */
		sctp_ire2faddr(sctp, fp);
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
	for (fp = fp->next; fp; fp = fp->next) {
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

	if (fp != ofp) {
		if (sctp->sctp_current == NULL) {
			dprint(1, ("sctp_faddr_dead: failover->%x:%x:%x:%x\n",
			    SCTP_PRINTADDR(fp->faddr)));
			sctp->sctp_current = fp;
			sctp->sctp_mss = fp->sfa_pmss;

			/* Reset the addrs in the composite header */
			sctp_faddr2hdraddr(fp, sctp);

			if (!SCTP_IS_DETACHED(sctp)) {
				sctp_set_ulp_prop(sctp);
			}
		}
		return (0);
	}


	/* All faddrs are down; kill the association */
	dprint(1, ("sctp_faddr_dead: all faddrs down, killing assoc\n"));
	BUMP_MIB(&sctp_mib, sctpAborted);
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
	}

	sctp->sctp_faddrs = NULL;

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
	sctp->sctp_ipha->ipha_version_and_hdr_length
		= (IP_VERSION << 4) | IP_SIMPLE_HDR_LENGTH_IN_WORDS;

	/*
	 * These two fields should be zero, and are already set above.
	 *
	 * sctp->sctp_ipha->ipha_ident,
	 * sctp->sctp_ipha->ipha_fragment_offset_and_flags.
	 */

	sctp->sctp_ipha->ipha_ttl = sctp_ipv4_ttl;
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
	uint8_t		hoplimit;
	/*
	 * save the existing sctp header and source/dest IP addresses
	 */
	bcopy(sctp->sctp_sctph6, buf, sizeof (sctp_hdr_t));
	src = sctp->sctp_ip6h->ip6_src;
	dst = sctp->sctp_ip6h->ip6_dst;
	hoplimit = sctp->sctp_ip6h->ip6_hops;
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
	 * If IPV6_HOPLIMIT was set in ipp, use that value.
	 * For sticky options, if it does not exist use
	 * the default/saved value (which was set in ip_build_hdrs_v6())
	 * All this as per RFC 2922.
	 */
	if (!(ipp->ipp_fields & IPPF_HOPLIMIT))
		sctp->sctp_ip6h->ip6_hops = hoplimit;
	/*
	 * Set the IPv6 header payload length.
	 * If there's an ip6i_t included, don't count it in the length.
	 */
	sctp->sctp_ip6h->ip6_plen = sctp->sctp_hdr6_len - IPV6_HDR_LEN;
	if (ipp->ipp_fields & IPPF_HAS_IP6I)
		sctp->sctp_ip6h->ip6_plen -= sizeof (ip6i_t);
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
		if (rth != NULL)
			(void) ip_massage_options_v6(sctp->sctp_ip6h, rth);
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
	sctp->sctp_ip6h->ip6_hops = sctp_ipv6_hoplimit;

	sctph = (sctp_hdr_t *)(sctp->sctp_iphc6 + IPV6_HDR_LEN);
	sctp->sctp_sctph6 = sctph;

	return (0);
}

/*
 * XXX implement more sophisticated logic
 */
void
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
		gotv4 = 1;
		if (sctp->sctp_ipversion == IPV4_VERSION) {
			goto copyports;
		}
	} else {
		sctp->sctp_ip6h->ip6_dst = sctp->sctp_primary->faddr;
		/* saddr may be unspec; make_mp() will handle this */
		sctp->sctp_ip6h->ip6_src = sctp->sctp_primary->saddr;
		gotv6 = 1;
	}

	for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
		if (!gotv4 && IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
			IN6_V4MAPPED_TO_IPADDR(&fp->faddr,
			    sctp->sctp_ipha->ipha_dst);
			/* copy in the faddr_t's saddr */
			IN6_V4MAPPED_TO_IPADDR(&fp->saddr,
			    sctp->sctp_ipha->ipha_src);
			gotv4 = 1;
			if (sctp->sctp_ipversion == IPV4_VERSION || gotv6) {
				break;
			}
		} else if (!gotv6) {
			sctp->sctp_ip6h->ip6_dst = fp->faddr;
			/* copy in the faddr_t's saddr */
			sctp->sctp_ip6h->ip6_src = fp->saddr;
			gotv6 = 1;
			if (gotv4) {
				break;
			}
		}
	}

copyports:
	/* copy in the ports for good measure */
	sctp->sctp_sctph->sh_sport = sctp->sctp_lport;
	sctp->sctp_sctph->sh_dport = sctp->sctp_fport;

	sctp->sctp_sctph6->sh_sport = sctp->sctp_lport;
	sctp->sctp_sctph6->sh_dport = sctp->sctp_fport;
}

void
sctp_add_unrec_parm(sctp_parm_hdr_t *uph, mblk_t **errmp)
{
	mblk_t *mp;
	sctp_parm_hdr_t *ph;
	size_t len;
	int pad;

	len = sizeof (*ph) + ntohs(uph->sph_len);
	if ((pad = len % 4) != 0) {
		pad = 4 - pad;
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

	mp->b_wptr = mp->b_rptr + len;
	if (*errmp != NULL) {
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
 * Returns 0 on success, sys errno on failure
 */
int
sctp_get_addrparams(sctp_t *sctp, sctp_t *psctp, mblk_t *pkt,
    sctp_chunk_hdr_t *ich, uint_t *sctp_options)
{
	sctp_init_chunk_t	*init;
	ipha_t			*iph;
	ip6_t			*ip6h;
	in6_addr_t		hdraddr[1];
	sctp_parm_hdr_t		*ph;
	ssize_t			remaining;
	int			isv4;
	int			err;
	sctp_faddr_t		*fp;

	if (sctp_options != NULL)
		*sctp_options = 0;

	/* inherit laddrs, if given */
	if (psctp != NULL && psctp->sctp_nsaddrs > 0) {
		ASSERT(sctp->sctp_nsaddrs == 0);

		err = sctp_dup_saddrs(psctp, sctp, KM_NOSLEEP);
		if (err != 0)
			return (err);
	}

	/* extract the address from the IP header */
	isv4 = (IPH_HDR_VERSION(pkt->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)pkt->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_src, hdraddr);
	} else {
		ip6h = (ip6_t *)pkt->b_rptr;
		hdraddr[0] = ip6h->ip6_src;
	}

	/* For loopback connections ignore address list */
	if (sctp->sctp_loopback)
		goto get_from_iphdr;

	/* Walk the params in the INIT [ACK], pulling out addr params */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) -
	    sizeof (sctp_init_chunk_t);
	if (remaining < sizeof (*ph)) {
		/* no parameters */
		goto get_from_iphdr;
	}
	init = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(init + 1);

	while (ph != NULL) {
		/* params will have already been byteordered when validating */
		if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				ipaddr_t ta;

				/*
				 * Screen out broad/multicasts & loopback.
				 * If the endpoint only accepts v6 address,
				 * go to the next one.
				 */
				bcopy(ph + 1, &ta, sizeof (ta));
				if (ta == 0 ||
				    ta == INADDR_BROADCAST ||
				    ta == htonl(INADDR_LOOPBACK) ||
				    IN_MULTICAST(ta) ||
				    sctp->sctp_connp->conn_ipv6_v6only) {
					goto next;
				}
				/*
				 * XXX also need to check for subnet
				 * broadcasts. This should probably
				 * wait until we have full access
				 * to the ILL tables.
				 */

				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);
				/* Check for duplicate. */
				if (sctp_lookup_faddr(sctp, &addr) != NULL)
					goto next;

				/* OK, add it to the faddr set */
				if (sctp_add_faddr(sctp, &addr,
					KM_NOSLEEP) != 0) {
					return (ENOMEM);
				}
			}
		} else if (ph->sph_type == htons(PARM_ADDR6) &&
		    sctp->sctp_family == AF_INET6) {
			/* An v4 socket should not take v6 addresses. */
			if (remaining >= PARM_ADDR6_LEN) {
				in6_addr_t *addr6;

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

				if (sctp_add_faddr(sctp,
				    (in6_addr_t *)(ph + 1), KM_NOSLEEP) != 0) {
					return (ENOMEM);
				}
			}
		} else if (ph->sph_type == htons(PARM_FORWARD_TSN)) {
			if (sctp_options != NULL)
				*sctp_options |= SCTP_PRSCTP_OPTION;
		} /* else; skip */

next:
		ph = sctp_next_parm(ph, &remaining);
	}

get_from_iphdr:
	/* Make sure the header's addr is in the list */
	fp = sctp_lookup_faddr(sctp, hdraddr);
	if (fp == NULL) {
		/* not included; add it now */
		if (sctp_add_faddr_first(sctp, hdraddr, KM_NOSLEEP) == -1)
			return (ENOMEM);

		/* sctp_faddrs will be the hdr addr */
		fp = sctp->sctp_faddrs;
	}
	/* make the header addr the primary */
	sctp->sctp_primary = fp;
	sctp->sctp_current = fp;
	sctp->sctp_mss = fp->sfa_pmss;

	return (0);
}

/*
 * Returns 0 if the check failed and the restart should be refused,
 * 1 if the check succeeded.
 */
int
sctp_secure_restart_check(mblk_t *pkt, sctp_chunk_hdr_t *ich, uint32_t ports,
    int sleep)
{
	sctp_faddr_t *fp, *fpa, *fphead = NULL;
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
		/* params will have already been byteordered when validating */
		if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);
				fpa = kmem_cache_alloc(sctp_kmem_faddr_cache,
				    sleep);
				if (!fpa) {
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
				if (!fpa) {
					goto done;
				}
				bzero(fpa, sizeof (*fpa));
				bcopy(ph + 1, &fpa->faddr,
				    sizeof (fpa->faddr));
				fpa->next = NULL;
			}
		} else {
			/* else not addr param; skip */
			fpa = NULL;
		}
		/* link in the new addr, if it was an addr param */
		if (fpa) {
			if (!fphead) {
				fphead = fpa;
				fp = fphead;
			} else {
				fp->next = fpa;
				fp = fpa;
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
	if (!fp) {
		/* not included; add it now */
		fp = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep);
		if (!fp) {
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
	tf = &(sctp_conn_fanout[SCTP_CONN_HASH(ports)]);
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
			    SCTP_PRINTADDR(*hdraddr), sctp));
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

void
sctp_congest_reset(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
		fp->ssthresh = sctp_initial_mtu;
		fp->cwnd = fp->sfa_pmss * sctp_slow_start_initial;
		fp->suna = 0;
		fp->pba = 0;
	}
}

/*
 * Return zero if the buffers are identical in length and content.
 * This is used for comparing extension header buffers.
 * Note that an extension header would be declared different
 * even if all that changed was the next header value in that header i.e.
 * what really changed is the next extension header.
 */
boolean_t
sctp_cmpbuf(void *a, uint_t alen, boolean_t b_valid, void *b, uint_t blen)
{
	if (!b_valid)
		blen = 0;

	if (alen != blen)
		return (B_TRUE);
	if (alen == 0)
		return (B_FALSE);	/* Both zero length */
	return (bcmp(a, b, alen));
}

/*
 * Preallocate memory for sctp_savebuf(). Returns B_TRUE if ok.
 * Return B_FALSE if memory allocation fails - don't change any state!
 */
boolean_t
sctp_allocbuf(void **dstp, uint_t *dstlenp, boolean_t src_valid,
    void *src, uint_t srclen)
{
	void *dst;

	if (!src_valid)
		srclen = 0;

	ASSERT(*dstlenp == 0);
	if (src != NULL && srclen != 0) {
		dst = mi_zalloc(srclen);
		if (dst == NULL)
			return (B_FALSE);
	} else {
		dst = NULL;
	}
	if (*dstp != NULL) {
		mi_free(*dstp);
		*dstp = NULL;
		*dstlenp = 0;
	}
	*dstp = dst;
	if (dst != NULL)
		*dstlenp = srclen;
	else
		*dstlenp = 0;
	return (B_TRUE);
}

/*
 * Replace what is in *dst, *dstlen with the source.
 * Assumes sctp_allocbuf has already been called.
 */
void
sctp_savebuf(void **dstp, uint_t *dstlenp, boolean_t src_valid,
    void *src, uint_t srclen)
{
	if (!src_valid)
		srclen = 0;

	ASSERT(*dstlenp == srclen);
	if (src != NULL && srclen != 0) {
		bcopy(src, *dstp, srclen);
	}
}

static void
sctp_init_faddr(sctp_t *sctp, sctp_faddr_t *fp, in6_addr_t *addr)
{
	bcopy(addr, &fp->faddr, sizeof (*addr));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		fp->isv4 = 1;
		/* Make sure that sfa_pmss is a multiple of SCTP_ALIGN. */
		fp->sfa_pmss = (sctp_initial_mtu - sctp->sctp_hdr_len) &
			~(SCTP_ALIGN - 1);
	} else {
		fp->isv4 = 0;
		fp->sfa_pmss = (sctp_initial_mtu - sctp->sctp_hdr6_len) &
			~(SCTP_ALIGN - 1);
	}
	fp->cwnd = sctp_slow_start_initial * fp->sfa_pmss;
	fp->rto = MIN(sctp->sctp_rto_initial, sctp->sctp_init_rto_max);
	fp->srtt = -1;
	fp->rtt_updates = 0;
	fp->strikes = 0;
	fp->max_retr = sctp->sctp_pp_max_rxt;
	/* Mark it as not confirmed. */
	fp->state = SCTP_FADDRS_UNCONFIRMED;
	fp->hb_interval = sctp->sctp_hb_interval;
	fp->ssthresh = sctp_initial_ssthresh;
	fp->suna = 0;
	fp->pba = 0;
	fp->acked = 0;
	fp->lastactive = lbolt64;
	fp->timer_mp = NULL;
	fp->hb_pending = B_FALSE;
	fp->timer_running = 0;
	fp->df = 1;
	fp->pmtu_discovered = 0;
	fp->rc_timer_mp = NULL;
	fp->rc_timer_running = 0;
	fp->next = NULL;
	fp->ire = NULL;
	fp->T3expire = 0;
	(void) random_get_pseudo_bytes((uint8_t *)&fp->hb_secret,
	    sizeof (fp->hb_secret));
	fp->hb_expiry = lbolt64;

	sctp_ire2faddr(sctp, fp);
}

/*ARGSUSED*/
static void
faddr_destructor(void *buf, void *cdrarg)
{
	sctp_faddr_t *fp = buf;

	ASSERT(fp->timer_mp == NULL);
	ASSERT(fp->timer_running == 0);

	ASSERT(fp->rc_timer_mp == NULL);
	ASSERT(fp->rc_timer_running == 0);
}

void
sctp_faddr_init()
{
	sctp_kmem_faddr_cache = kmem_cache_create("sctp_faddr_cache",
	    sizeof (sctp_faddr_t), 0, NULL, faddr_destructor,
	    NULL, NULL, NULL, 0);
}

void
sctp_faddr_fini()
{
	kmem_cache_destroy(sctp_kmem_faddr_cache);
}
