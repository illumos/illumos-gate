/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/table.c,v 1.15 2000/08/11 08:24:38 sheldonh Exp $
 */

#include "defs.h"
#include <fcntl.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <inet/mib2.h>
#include <inet/ip.h>

/* This structure is used to store a disassembled routing socket message. */
struct rt_addrinfo {
	int	rti_addrs;
	struct sockaddr_storage *rti_info[RTAX_MAX];
};

static struct rt_spare *rts_better(struct rt_entry *);
static struct rt_spare rts_empty = EMPTY_RT_SPARE;
static void set_need_flash(void);
static void rtbad(struct rt_entry *, struct interface *);
static int rt_xaddrs(struct rt_addrinfo *, struct sockaddr_storage *,
    char *, int);
static struct interface *gwkludge_iflookup(in_addr_t, in_addr_t, in_addr_t);
static struct interface *lifp_iflookup(in_addr_t, const char *);

struct radix_node_head *rhead;		/* root of the radix tree */

/* Flash update needed.  _B_TRUE to suppress the 1st. */
boolean_t need_flash = _B_TRUE;

struct timeval age_timer;		/* next check of old routes */
struct timeval need_kern = {		/* need to update kernel table */
	EPOCH+MIN_WAITTIME-1, 0
};

static uint32_t	total_routes;

#define	ROUNDUP_LONG(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof (long) - 1))) : sizeof (long))

/*
 * It is desirable to "aggregate" routes, to combine differing routes of
 * the same metric and next hop into a common route with a smaller netmask
 * or to suppress redundant routes, routes that add no information to
 * routes with smaller netmasks.
 *
 * A route is redundant if and only if any and all routes with smaller
 * but matching netmasks and nets are the same.  Since routes are
 * kept sorted in the radix tree, redundant routes always come second.
 *
 * There are two kinds of aggregations.  First, two routes of the same bit
 * mask and differing only in the least significant bit of the network
 * number can be combined into a single route with a coarser mask.
 *
 * Second, a route can be suppressed in favor of another route with a more
 * coarse mask provided no incompatible routes with intermediate masks
 * are present.  The second kind of aggregation involves suppressing routes.
 * A route must not be suppressed if an incompatible route exists with
 * an intermediate mask, since the suppressed route would be covered
 * by the intermediate.
 *
 * This code relies on the radix tree walk encountering routes
 * sorted first by address, with the smallest address first.
 */

static struct ag_info ag_slots[NUM_AG_SLOTS], *ag_avail, *ag_corsest,
	*ag_finest;

#ifdef DEBUG_AG
#define	CHECK_AG() do { int acnt = 0; struct ag_info *cag;	\
	for (cag = ag_avail; cag != NULL; cag = cag->ag_fine)	\
		acnt++;						\
	for (cag = ag_corsest; cag != NULL; cag = cag->ag_fine)	\
		acnt++;						\
	if (acnt != NUM_AG_SLOTS)				\
		abort();					\
} while (_B_FALSE)
#else
#define	CHECK_AG()	(void)0
#endif


/*
 * Output the contents of an aggregation table slot.
 *	This function must always be immediately followed with the deletion
 *	of the target slot.
 */
static void
ag_out(struct ag_info *ag, void (*out)(struct ag_info *))
{
	struct ag_info *ag_cors;
	uint32_t bit;


	/* Forget it if this route should not be output for split-horizon. */
	if (ag->ag_state & AGS_SPLIT_HZ)
		return;

	/*
	 * If we output both the even and odd twins, then the immediate parent,
	 * if it is present, is redundant, unless the parent manages to
	 * aggregate into something coarser.
	 * On successive calls, this code detects the even and odd twins,
	 * and marks the parent.
	 *
	 * Note that the order in which the radix tree code emits routes
	 * ensures that the twins are seen before the parent is emitted.
	 */
	ag_cors = ag->ag_cors;
	if (ag_cors != NULL &&
	    ag_cors->ag_mask == (ag->ag_mask << 1) &&
	    ag_cors->ag_dst_h == (ag->ag_dst_h & ag_cors->ag_mask)) {
		ag_cors->ag_state |= ((ag_cors->ag_dst_h == ag->ag_dst_h) ?
		    AGS_REDUN0 : AGS_REDUN1);
	}

	/*
	 * Skip it if this route is itself redundant.
	 *
	 * It is ok to change the contents of the slot here, since it is
	 * always deleted next.
	 */
	if (ag->ag_state & AGS_REDUN0) {
		if (ag->ag_state & AGS_REDUN1)
			return;		/* quit if fully redundant */
		/* make it finer if it is half-redundant */
		bit = (-ag->ag_mask) >> 1;
		ag->ag_dst_h |= bit;
		ag->ag_mask |= bit;

	} else if (ag->ag_state & AGS_REDUN1) {
		/* make it finer if it is half-redundant */
		bit = (-ag->ag_mask) >> 1;
		ag->ag_mask |= bit;
	}
	out(ag);
}


static void
ag_del(struct ag_info *ag)
{
	CHECK_AG();

	if (ag->ag_cors == NULL)
		ag_corsest = ag->ag_fine;
	else
		ag->ag_cors->ag_fine = ag->ag_fine;

	if (ag->ag_fine == NULL)
		ag_finest = ag->ag_cors;
	else
		ag->ag_fine->ag_cors = ag->ag_cors;

	ag->ag_fine = ag_avail;
	ag_avail = ag;

	CHECK_AG();
}


/* Look for a route that can suppress the given route. */
static struct ag_info *
ag_find_suppressor(struct ag_info *ag)
{
	struct ag_info *ag_cors;
	in_addr_t dst_h = ag->ag_dst_h;

	for (ag_cors = ag->ag_cors; ag_cors != NULL;
	    ag_cors = ag_cors->ag_cors) {

		if ((dst_h & ag_cors->ag_mask) == ag_cors->ag_dst_h) {
			/*
			 * We found a route with a coarser mask that covers
			 * the given target.  It can suppress the target
			 * only if it has a good enough metric and it
			 * either has the same (gateway, ifp), or if its state
			 * includes AGS_CORS_GATE or the target's state
			 * includes AGS_FINE_GATE.
			 */
			if (ag_cors->ag_pref <= ag->ag_pref &&
			    (((ag->ag_nhop == ag_cors->ag_nhop) &&
			    (ag->ag_ifp == ag_cors->ag_ifp)) ||
			    ag_cors->ag_state & AGS_CORS_GATE ||
			    ag->ag_state & AGS_FINE_GATE)) {
				return (ag_cors);
			}
		}
	}

	return (NULL);
}


/*
 * Flush routes waiting for aggregation.
 * This must not suppress a route unless it is known that among all routes
 * with coarser masks that match it, the one with the longest mask is
 * appropriate.  This is ensured by scanning the routes in lexical order,
 * and with the most restrictive mask first among routes to the same
 * destination.
 */
void
ag_flush(in_addr_t lim_dst_h,	/* flush routes to here */
    in_addr_t lim_mask,		/* matching this mask */
    void (*out)(struct ag_info *))
{
	struct ag_info *ag, *ag_cors, *ag_supr;
	in_addr_t dst_h;


	for (ag = ag_finest; ag != NULL && ag->ag_mask >= lim_mask;
	    ag = ag_cors) {
		/* Get the next route now, before we delete ag. */
		ag_cors = ag->ag_cors;

		/* Work on only the specified routes. */
		dst_h = ag->ag_dst_h;
		if ((dst_h & lim_mask) != lim_dst_h)
			continue;

		/*
		 * Don't try to suppress the route if its state doesn't
		 * include AGS_SUPPRESS.
		 */
		if (!(ag->ag_state & AGS_SUPPRESS)) {
			ag_out(ag, out);
			ag_del(ag);
			continue;
		}

		ag_supr = ag_find_suppressor(ag);
		if (ag_supr == NULL) {
			/*
			 * We didn't find a route which suppresses the
			 * target, so the target can go out.
			 */
			ag_out(ag, out);
		} else {
			/*
			 * We found a route which suppresses the target, so
			 * don't output the target.
			 */
			if (TRACEACTIONS) {
				trace_misc("aggregated away %s",
				    rtname(htonl(ag->ag_dst_h), ag->ag_mask,
				    ag->ag_nhop));
				trace_misc("on coarser route %s",
				    rtname(htonl(ag_supr->ag_dst_h),
				    ag_supr->ag_mask, ag_supr->ag_nhop));
			}
			/*
			 * If the suppressed target was redundant, then
			 * mark the suppressor as redundant.
			 */
			if (AG_IS_REDUN(ag->ag_state) &&
			    ag_supr->ag_mask == (ag->ag_mask<<1)) {
				if (ag_supr->ag_dst_h == dst_h)
					ag_supr->ag_state |= AGS_REDUN0;
				else
					ag_supr->ag_state |= AGS_REDUN1;
			}
			if (ag->ag_tag != ag_supr->ag_tag)
				ag_supr->ag_tag = 0;
			if (ag->ag_nhop != ag_supr->ag_nhop)
				ag_supr->ag_nhop = 0;
		}

		/* The route has either been output or suppressed */
		ag_del(ag);
	}

	CHECK_AG();
}


/* Try to aggregate a route with previous routes. */
void
ag_check(in_addr_t dst,
    in_addr_t	mask,
    in_addr_t	gate,
    struct interface *ifp,
    in_addr_t	nhop,
    uint8_t	metric,
    uint8_t	pref,
    uint32_t	seqno,
    uint16_t	tag,
    uint16_t	state,
    void (*out)(struct ag_info *))	/* output using this */
{
	struct ag_info *ag, *nag, *ag_cors;
	in_addr_t xaddr;
	int tmp;
	struct interface *xifp;

	dst = ntohl(dst);

	/*
	 * Don't bother trying to aggregate routes with non-contiguous
	 * subnet masks.
	 *
	 * (X & -X) contains a single bit if and only if X is a power of 2.
	 * (X + (X & -X)) == 0 if and only if X is a power of 2.
	 */
	if ((mask & -mask) + mask != 0) {
		struct ag_info nc_ag;

		nc_ag.ag_dst_h = dst;
		nc_ag.ag_mask = mask;
		nc_ag.ag_gate = gate;
		nc_ag.ag_ifp = ifp;
		nc_ag.ag_nhop = nhop;
		nc_ag.ag_metric = metric;
		nc_ag.ag_pref = pref;
		nc_ag.ag_tag = tag;
		nc_ag.ag_state = state;
		nc_ag.ag_seqno = seqno;
		out(&nc_ag);
		return;
	}

	/* Search for the right slot in the aggregation table. */
	ag_cors = NULL;
	ag = ag_corsest;
	while (ag != NULL) {
		if (ag->ag_mask >= mask)
			break;

		/*
		 * Suppress old routes (i.e. combine with compatible routes
		 * with coarser masks) as we look for the right slot in the
		 * aggregation table for the new route.
		 * A route to an address less than the current destination
		 * will not be affected by the current route or any route
		 * seen hereafter.  That means it is safe to suppress it.
		 * This check keeps poor routes (e.g. with large hop counts)
		 * from preventing suppression of finer routes.
		 */
		if (ag_cors != NULL && ag->ag_dst_h < dst &&
		    (ag->ag_state & AGS_SUPPRESS) &&
		    ag_cors->ag_pref <= ag->ag_pref &&
		    (ag->ag_dst_h & ag_cors->ag_mask) == ag_cors->ag_dst_h &&
		    ((ag_cors->ag_nhop == ag->ag_nhop &&
		    (ag_cors->ag_ifp == ag->ag_ifp))||
		    (ag->ag_state & AGS_FINE_GATE) ||
		    (ag_cors->ag_state & AGS_CORS_GATE))) {
			/*
			 * If the suppressed target was redundant,
			 * then mark the suppressor redundant.
			 */
			if (AG_IS_REDUN(ag->ag_state) &&
			    ag_cors->ag_mask == (ag->ag_mask << 1)) {
				if (ag_cors->ag_dst_h == dst)
					ag_cors->ag_state |= AGS_REDUN0;
				else
					ag_cors->ag_state |= AGS_REDUN1;
			}
			if (ag->ag_tag != ag_cors->ag_tag)
				ag_cors->ag_tag = 0;
			if (ag->ag_nhop != ag_cors->ag_nhop)
				ag_cors->ag_nhop = 0;
			ag_del(ag);
			CHECK_AG();
		} else {
			ag_cors = ag;
		}
		ag = ag_cors->ag_fine;
	}

	/*
	 * If we find the even/odd twin of the new route, and if the
	 * masks and so forth are equal, we can aggregate them.
	 * We can probably promote one of the pair.
	 *
	 * Since the routes are encountered in lexical order,
	 * the new route must be odd.  However, the second or later
	 * times around this loop, it could be the even twin promoted
	 * from the even/odd pair of twins of the finer route.
	 */
	while (ag != NULL && ag->ag_mask == mask &&
	    ((ag->ag_dst_h ^ dst) & (mask<<1)) == 0) {

		/*
		 * Here we know the target route and the route in the current
		 * slot have the same netmasks and differ by at most the
		 * last bit.  They are either for the same destination, or
		 * for an even/odd pair of destinations.
		 */
		if (ag->ag_dst_h == dst) {
			if (ag->ag_nhop == nhop && ag->ag_ifp == ifp) {
				/*
				 * We have two routes to the same destination,
				 * with the same nexthop and interface.
				 * Routes are encountered in lexical order,
				 * so a route is never promoted until the
				 * parent route is already present.  So we
				 * know that the new route is a promoted (or
				 * aggregated) pair and the route already in
				 * the slot is the explicit route.
				 *
				 * Prefer the best route if their metrics
				 * differ, or the aggregated one if not,
				 * following a sort of longest-match rule.
				 */
				if (pref <= ag->ag_pref) {
					ag->ag_gate = gate;
					ag->ag_ifp = ifp;
					ag->ag_nhop = nhop;
					ag->ag_tag = tag;
					ag->ag_metric = metric;
					ag->ag_pref = pref;
					if (seqno > ag->ag_seqno)
						ag->ag_seqno = seqno;
					tmp = ag->ag_state;
					ag->ag_state = state;
					state = tmp;
				}

				/*
				 * Some bits are set if they are set on
				 * either route, except when the route is
				 * for an interface.
				 */
				if (!(ag->ag_state & AGS_IF))
					ag->ag_state |=
					    (state & (AGS_AGGREGATE_EITHER |
					    AGS_REDUN0 | AGS_REDUN1));

				return;
			} else {
				/*
				 * multiple routes to same dest/mask with
				 * differing gate nexthop/or ifp. Flush
				 * both out.
				 */
				break;
			}
		}

		/*
		 * If one of the routes can be promoted and the other can
		 * be suppressed, it may be possible to combine them or
		 * worthwhile to promote one.
		 *
		 * Any route that can be promoted is always
		 * marked to be eligible to be suppressed.
		 */
		if (!((state & AGS_AGGREGATE) &&
		    (ag->ag_state & AGS_SUPPRESS)) &&
		    !((ag->ag_state & AGS_AGGREGATE) && (state & AGS_SUPPRESS)))
			break;

		/*
		 * A pair of even/odd twin routes can be combined
		 * if either is redundant, or if they are via the
		 * same gateway and have the same metric.
		 */
		if (AG_IS_REDUN(ag->ag_state) || AG_IS_REDUN(state) ||
		    (ag->ag_nhop == nhop && ag->ag_ifp == ifp &&
		    ag->ag_pref == pref &&
		    (state & ag->ag_state & AGS_AGGREGATE) != 0)) {

			/*
			 * We have both the even and odd pairs.
			 * Since the routes are encountered in order,
			 * the route in the slot must be the even twin.
			 *
			 * Combine and promote (aggregate) the pair of routes.
			 */
			if (seqno < ag->ag_seqno)
				seqno = ag->ag_seqno;
			if (!AG_IS_REDUN(state))
				state &= ~AGS_REDUN1;
			if (AG_IS_REDUN(ag->ag_state))
				state |= AGS_REDUN0;
			else
				state &= ~AGS_REDUN0;
			state |= (ag->ag_state & AGS_AGGREGATE_EITHER);
			if (ag->ag_tag != tag)
				tag = 0;
			if (ag->ag_nhop != nhop)
				nhop = 0;

			/*
			 * Get rid of the even twin that was already
			 * in the slot.
			 */
			ag_del(ag);

		} else if (ag->ag_pref >= pref &&
		    (ag->ag_state & AGS_AGGREGATE)) {
			/*
			 * If we cannot combine the pair, maybe the route
			 * with the worse metric can be promoted.
			 *
			 * Promote the old, even twin, by giving its slot
			 * in the table to the new, odd twin.
			 */
			ag->ag_dst_h = dst;

			xaddr = ag->ag_gate;
			ag->ag_gate = gate;
			gate = xaddr;

			xifp = ag->ag_ifp;
			ag->ag_ifp = ifp;
			ifp = xifp;

			xaddr = ag->ag_nhop;
			ag->ag_nhop = nhop;
			nhop = xaddr;

			tmp = ag->ag_tag;
			ag->ag_tag = tag;
			tag = tmp;

			/*
			 * The promoted route is even-redundant only if the
			 * even twin was fully redundant.  It is not
			 * odd-redundant because the odd-twin will still be
			 * in the table.
			 */
			tmp = ag->ag_state;
			if (!AG_IS_REDUN(tmp))
				tmp &= ~AGS_REDUN0;
			tmp &= ~AGS_REDUN1;
			ag->ag_state = state;
			state = tmp;

			tmp = ag->ag_metric;
			ag->ag_metric = metric;
			metric = tmp;

			tmp = ag->ag_pref;
			ag->ag_pref = pref;
			pref = tmp;

			/* take the newest sequence number */
			if (seqno <= ag->ag_seqno)
				seqno = ag->ag_seqno;
			else
				ag->ag_seqno = seqno;

		} else {
			if (!(state & AGS_AGGREGATE))
				break;	/* cannot promote either twin */

			/*
			 * Promote the new, odd twin by shaving its
			 * mask and address.
			 * The promoted route is odd-redundant only if the
			 * odd twin was fully redundant.  It is not
			 * even-redundant because the even twin is still in
			 * the table.
			 */
			if (!AG_IS_REDUN(state))
				state &= ~AGS_REDUN1;
			state &= ~AGS_REDUN0;
			if (seqno < ag->ag_seqno)
				seqno = ag->ag_seqno;
			else
				ag->ag_seqno = seqno;
		}

		mask <<= 1;
		dst &= mask;

		if (ag_cors == NULL) {
			ag = ag_corsest;
			break;
		}
		ag = ag_cors;
		ag_cors = ag->ag_cors;
	}

	/*
	 * When we can no longer promote and combine routes,
	 * flush the old route in the target slot.  Also flush
	 * any finer routes that we know will never be aggregated by
	 * the new route.
	 *
	 * In case we moved toward coarser masks,
	 * get back where we belong
	 */
	if (ag != NULL && ag->ag_mask < mask) {
		ag_cors = ag;
		ag = ag->ag_fine;
	}

	/* Empty the target slot */
	if (ag != NULL && ag->ag_mask == mask) {
		ag_flush(ag->ag_dst_h, ag->ag_mask, out);
		ag = (ag_cors == NULL) ? ag_corsest : ag_cors->ag_fine;
	}

#ifdef DEBUG_AG
	if (ag == NULL && ag_cors != ag_finest)
		abort();
	if (ag_cors == NULL && ag != ag_corsest)
		abort();
	if (ag != NULL && ag->ag_cors != ag_cors)
		abort();
	if (ag_cors != NULL && ag_cors->ag_fine != ag)
		abort();
	CHECK_AG();
#endif

	/* Save the new route on the end of the table. */
	nag = ag_avail;
	ag_avail = nag->ag_fine;

	nag->ag_dst_h = dst;
	nag->ag_mask = mask;
	nag->ag_ifp = ifp;
	nag->ag_gate = gate;
	nag->ag_nhop = nhop;
	nag->ag_metric = metric;
	nag->ag_pref = pref;
	nag->ag_tag = tag;
	nag->ag_state = state;
	nag->ag_seqno = seqno;

	nag->ag_fine = ag;
	if (ag != NULL)
		ag->ag_cors = nag;
	else
		ag_finest = nag;
	nag->ag_cors = ag_cors;
	if (ag_cors == NULL)
		ag_corsest = nag;
	else
		ag_cors->ag_fine = nag;
	CHECK_AG();
}


static const char *
rtm_type_name(uchar_t type)
{
	static const char *rtm_types[] = {
		"RTM_ADD",
		"RTM_DELETE",
		"RTM_CHANGE",
		"RTM_GET",
		"RTM_LOSING",
		"RTM_REDIRECT",
		"RTM_MISS",
		"RTM_LOCK",
		"RTM_OLDADD",
		"RTM_OLDDEL",
		"RTM_RESOLVE",
		"RTM_NEWADDR",
		"RTM_DELADDR",
		"RTM_IFINFO",
		"RTM_CHGMADDR",
		"RTM_FREEMADDR"
	};
#define	NEW_RTM_PAT	"RTM type %#x"
	static char name0[sizeof (NEW_RTM_PAT) + 2];

	if (type > sizeof (rtm_types) / sizeof (rtm_types[0]) || type == 0) {
		(void) snprintf(name0, sizeof (name0), NEW_RTM_PAT, type);
		return (name0);
	} else {
		return (rtm_types[type-1]);
	}
#undef	NEW_RTM_PAT
}


static void
dump_rt_msg(const char *act, struct rt_msghdr *rtm, int mlen)
{
	const char *mtype;
	uchar_t *cp;
	int i, j;
	char buffer[16*3 + 1], *ibs;
	struct ifa_msghdr *ifam;
	struct if_msghdr *ifm;

	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_FREEADDR:
	case RTM_CHGADDR:
		mtype = "ifam";
		break;
	case RTM_IFINFO:
		mtype = "ifm";
		break;
	default:
		mtype = "rtm";
		break;
	}
	trace_misc("%s %s %d bytes", act, mtype, mlen);
	if (mlen > rtm->rtm_msglen) {
		trace_misc("%s: extra %d bytes ignored", mtype,
		    mlen - rtm->rtm_msglen);
		mlen = rtm->rtm_msglen;
	} else if (mlen < rtm->rtm_msglen) {
		trace_misc("%s: truncated by %d bytes", mtype,
		    rtm->rtm_msglen - mlen);
	}
	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_CHGADDR:
	case RTM_FREEADDR:
		ifam = (struct ifa_msghdr *)rtm;
		trace_misc("ifam: msglen %d version %d type %d addrs %X",
		    ifam->ifam_msglen, ifam->ifam_version, ifam->ifam_type,
		    ifam->ifam_addrs);
		trace_misc("ifam: flags %X index %d metric %d",
		    ifam->ifam_flags, ifam->ifam_index, ifam->ifam_metric);
		cp = (uchar_t *)(ifam + 1);
		break;
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		trace_misc("ifm: msglen %d version %d type %d addrs %X",
		    ifm->ifm_msglen, ifm->ifm_version, ifm->ifm_type,
		    ifm->ifm_addrs);
		ibs = if_bit_string(ifm->ifm_flags, _B_TRUE);
		if (ibs == NULL) {
			trace_misc("ifm: flags %#x index %d", ifm->ifm_flags,
			    ifm->ifm_index);
		} else {
			trace_misc("ifm: flags %s index %d", ibs,
			    ifm->ifm_index);
			free(ibs);
		}
		cp = (uchar_t *)(ifm + 1);
		break;
	default:
		trace_misc("rtm: msglen %d version %d type %d index %d",
		    rtm->rtm_msglen, rtm->rtm_version, rtm->rtm_type,
		    rtm->rtm_index);
		trace_misc("rtm: flags %X addrs %X pid %d seq %d",
		    rtm->rtm_flags, rtm->rtm_addrs, rtm->rtm_pid, rtm->rtm_seq);
		trace_misc("rtm: errno %d use %d inits %X", rtm->rtm_errno,
		    rtm->rtm_use, rtm->rtm_inits);
		cp = (uchar_t *)(rtm + 1);
		break;
	}
	i = mlen - (cp - (uint8_t *)rtm);
	while (i > 0) {
		buffer[0] = '\0';
		ibs = buffer;
		for (j = 0; j < 16 && i > 0; j++, i--)
			ibs += sprintf(ibs, " %02X", *cp++);
		trace_misc("addr%s", buffer);
	}
}

/*
 * Tell the kernel to add, delete or change a route
 * Pass k_state from khash in for diagnostic info.
 */
static void
rtioctl(int action,			/* RTM_DELETE, etc */
    in_addr_t dst,
    in_addr_t gate,
    in_addr_t mask,
    struct interface *ifp,
    uint8_t metric,
    int flags)
{
	static int rt_sock_seqno = 0;
	struct {
		struct rt_msghdr w_rtm;
		struct sockaddr_in w_dst;
		struct sockaddr_in w_gate;
		uint8_t w_space[512];
	} w;
	struct sockaddr_in w_mask;
	struct sockaddr_dl w_ifp;
	uint8_t *cp;
	long cc;
#define	PAT " %-10s %s metric=%d flags=%#x"
#define	ARGS rtm_type_name(action), rtname(dst, mask, gate), metric, flags

again:
	(void) memset(&w, 0, sizeof (w));
	(void) memset(&w_mask, 0, sizeof (w_mask));
	(void) memset(&w_ifp, 0, sizeof (w_ifp));
	cp = w.w_space;
	w.w_rtm.rtm_msglen = sizeof (struct rt_msghdr) +
	    2 * ROUNDUP_LONG(sizeof (struct sockaddr_in));
	w.w_rtm.rtm_version = RTM_VERSION;
	w.w_rtm.rtm_type = action;
	w.w_rtm.rtm_flags = flags;
	w.w_rtm.rtm_seq = ++rt_sock_seqno;
	w.w_rtm.rtm_addrs = RTA_DST|RTA_GATEWAY;
	if (metric != 0 || action == RTM_CHANGE) {
		w.w_rtm.rtm_rmx.rmx_hopcount = metric;
		w.w_rtm.rtm_inits |= RTV_HOPCOUNT;
	}
	w.w_dst.sin_family = AF_INET;
	w.w_dst.sin_addr.s_addr = dst;
	w.w_gate.sin_family = AF_INET;
	w.w_gate.sin_addr.s_addr = gate;
	if (mask == HOST_MASK) {
		w.w_rtm.rtm_flags |= RTF_HOST;
	} else {
		w.w_rtm.rtm_addrs |= RTA_NETMASK;
		w_mask.sin_family = AF_INET;
		w_mask.sin_addr.s_addr = htonl(mask);
		(void) memmove(cp, &w_mask, sizeof (w_mask));
		cp += ROUNDUP_LONG(sizeof (struct sockaddr_in));
		w.w_rtm.rtm_msglen += ROUNDUP_LONG(sizeof (struct sockaddr_in));
	}
	if (ifp == NULL)
		ifp = iflookup(gate);

	if (ifp == NULL || (ifp->int_phys == NULL)) {
		trace_misc("no ifp for" PAT, ARGS);
	} else {
		if (ifp->int_phys->phyi_index > UINT16_MAX) {
			trace_misc("ifindex %d is too big for sdl_index",
			    ifp->int_phys->phyi_index);
		} else {
			w_ifp.sdl_family = AF_LINK;
			w.w_rtm.rtm_addrs |= RTA_IFP;
			w_ifp.sdl_index = ifp->int_phys->phyi_index;
			(void) memmove(cp, &w_ifp, sizeof (w_ifp));
			w.w_rtm.rtm_msglen +=
			    ROUNDUP_LONG(sizeof (struct sockaddr_dl));
		}
	}


	if (!no_install) {
		if (TRACERTS)
			dump_rt_msg("write", &w.w_rtm, w.w_rtm.rtm_msglen);
		cc = write(rt_sock, &w, w.w_rtm.rtm_msglen);
		if (cc < 0) {
			if (errno == ESRCH && (action == RTM_CHANGE ||
			    action == RTM_DELETE)) {
				trace_act("route disappeared before" PAT, ARGS);
				if (action == RTM_CHANGE) {
					action = RTM_ADD;
					goto again;
				}
				return;
			}
			writelog(LOG_WARNING, "write(rt_sock)" PAT ": %s ",
			    ARGS, rip_strerror(errno));
			return;
		} else if (cc != w.w_rtm.rtm_msglen) {
			msglog("write(rt_sock) wrote %ld instead of %d for" PAT,
			    cc, w.w_rtm.rtm_msglen, ARGS);
			return;
		}
	}
	if (TRACEKERNEL)
		trace_misc("write kernel" PAT, ARGS);
#undef PAT
#undef ARGS
}


/* Hash table containing our image of the kernel forwarding table. */
#define	KHASH_SIZE 71			/* should be prime */
#define	KHASH(a, m) khash_bins[((a) ^ (m)) % KHASH_SIZE]
static struct khash *khash_bins[KHASH_SIZE];

#define	K_KEEP_LIM	30	/* k_keep */

static struct khash *
kern_find(in_addr_t dst, in_addr_t mask, in_addr_t gate,
    struct interface *ifp, struct khash ***ppk)
{
	struct khash *k, **pk;

	for (pk = &KHASH(dst, mask); (k = *pk) != NULL; pk = &k->k_next) {
		if (k->k_dst == dst && k->k_mask == mask &&
		    (gate == 0 || k->k_gate == gate) &&
		    (ifp == NULL || k->k_ifp == ifp)) {
			break;
		}
	}
	if (ppk != NULL)
		*ppk = pk;
	return (k);
}


/*
 * Find out if there is an alternate route to a given destination
 * off of a given interface.
 */
static struct khash *
kern_alternate(in_addr_t dst, in_addr_t mask, in_addr_t gate,
    struct interface *ifp, struct khash ***ppk)
{
	struct khash *k, **pk;

	for (pk = &KHASH(dst, mask); (k = *pk) != NULL; pk = &k->k_next) {
		if (k->k_dst == dst && k->k_mask == mask &&
		    (k->k_gate != gate) &&
		    (k->k_ifp == ifp)) {
			break;
		}
	}
	if (ppk != NULL)
		*ppk = pk;
	return (k);
}

static struct khash *
kern_add(in_addr_t dst, uint32_t mask, in_addr_t gate, struct interface *ifp)
{
	struct khash *k, **pk;

	k = kern_find(dst, mask, gate, ifp, &pk);
	if (k != NULL)
		return (k);

	k = rtmalloc(sizeof (*k), "kern_add");

	(void) memset(k, 0, sizeof (*k));
	k->k_dst = dst;
	k->k_mask = mask;
	k->k_state = KS_NEW;
	k->k_keep = now.tv_sec;
	k->k_gate = gate;
	k->k_ifp = ifp;
	*pk = k;

	return (k);
}

/* delete all khash entries that are wired through the interface ifp */
void
kern_flush_ifp(struct interface *ifp)
{
	struct khash *k, *kprev, *knext;
	int i;

	for (i = 0; i < KHASH_SIZE; i++) {
		kprev = NULL;
		for (k = khash_bins[i]; k != NULL; k = knext) {
			knext = k->k_next;
			if (k->k_ifp == ifp) {
				if (kprev != NULL)
					kprev->k_next = k->k_next;
				else
					khash_bins[i] = k->k_next;
				free(k);
				continue;
			}
			kprev = k;
		}
	}
}

/*
 * rewire khash entries that currently go through oldifp to
 * go through newifp.
 */
void
kern_rewire_ifp(struct interface *oldifp, struct interface *newifp)
{
	struct khash *k;
	int i;

	for (i = 0; i < KHASH_SIZE; i++) {
		for (k = khash_bins[i]; k; k = k->k_next) {
			if (k->k_ifp == oldifp) {
				k->k_ifp = newifp;
				trace_misc("kern_rewire_ifp k 0x%lx "
				    "from %s to %s", k, oldifp->int_name,
				    newifp->int_name);
			}
		}
	}
}

/*
 * Check that a static route it is still in the daemon table, and not
 * deleted by interfaces coming and going.  This is also the routine
 * responsible for adding new static routes to the daemon table.
 */
static void
kern_check_static(struct khash *k, struct interface *ifp)
{
	struct rt_entry *rt;
	struct rt_spare new;
	uint16_t rt_state = RS_STATIC;

	(void) memset(&new, 0, sizeof (new));
	new.rts_ifp = ifp;
	new.rts_gate = k->k_gate;
	new.rts_router = (ifp != NULL) ? ifp->int_addr : loopaddr;
	new.rts_metric = k->k_metric;
	new.rts_time = now.tv_sec;
	new.rts_origin = RO_STATIC;

	rt = rtget(k->k_dst, k->k_mask);
	if ((ifp != NULL && !IS_IFF_ROUTING(ifp->int_if_flags)) ||
	    (k->k_state & KS_PRIVATE))
		rt_state |= RS_NOPROPAGATE;

	if (rt != NULL) {
		if ((rt->rt_state & RS_STATIC) == 0) {
			/*
			 * We are already tracking this dest/mask
			 * via RIP/RDISC. Ignore the static route,
			 * because we don't currently have a good
			 * way to compare metrics on static routes
			 * with rip metrics, and therefore cannot
			 * mix and match the two.
			 */
			return;
		}
		rt_state |= rt->rt_state;
		if (rt->rt_state != rt_state)
			rtchange(rt, rt_state, &new, 0);
	} else {
		rtadd(k->k_dst, k->k_mask, rt_state, &new);
	}
}


/* operate on a kernel entry */
static void
kern_ioctl(struct khash *k,
    int action,			/* RTM_DELETE, etc */
    int flags)
{
	if (((k->k_state & (KS_IF|KS_PASSIVE)) == KS_IF) ||
	    (k->k_state & KS_DEPRE_IF)) {
		/*
		 * Prevent execution of RTM_DELETE, RTM_ADD or
		 * RTM_CHANGE of interface routes
		 */
		trace_act("Blocking execution of %s  %s --> %s ",
		    rtm_type_name(action),
		    addrname(k->k_dst, k->k_mask, 0), naddr_ntoa(k->k_gate));
		return;
	}

	switch (action) {
	case RTM_DELETE:
		k->k_state &= ~KS_DYNAMIC;
		if (k->k_state & KS_DELETED)
			return;
		k->k_state |= KS_DELETED;
		break;
	case RTM_ADD:
		k->k_state &= ~KS_DELETED;
		break;
	case RTM_CHANGE:
		if (k->k_state & KS_DELETED) {
			action = RTM_ADD;
			k->k_state &= ~KS_DELETED;
		}
		break;
	}

	/*
	 * We should be doing an RTM_CHANGE for a KS_CHANGE, but
	 * RTM_CHANGE in the kernel is not currently multipath-aware and
	 * assumes that RTF_GATEWAY implies that the gateway of the route for
	 * dst has to be changed. Moreover, the only change that in.routed
	 * wants to implement is a change in the ks_metric (rmx_hopcount)
	 * which the kernel ignores anway, so we skip the RTM_CHANGE operation
	 * on the kernel
	 */
	if (action != RTM_CHANGE) {
		rtioctl(action, k->k_dst, k->k_gate, k->k_mask, k->k_ifp,
		    k->k_metric, flags);
	}
}


/* add a route the kernel told us */
static void
rtm_add(struct rt_msghdr *rtm,
    struct rt_addrinfo *info,
    time_t keep,
    boolean_t interf_route,
    struct interface *ifptr)
{
	struct khash *k;
	struct interface *ifp = ifptr;
	in_addr_t mask, gate = 0;
	static struct msg_limit msg_no_ifp;

	if (rtm->rtm_flags & RTF_HOST) {
		mask = HOST_MASK;
	} else if (INFO_MASK(info) != 0) {
		mask = ntohl(S_ADDR(INFO_MASK(info)));
	} else {
		writelog(LOG_WARNING,
		    "ignore %s without mask", rtm_type_name(rtm->rtm_type));
		return;
	}

	/*
	 * Find the interface toward the gateway.
	 */
	if (INFO_GATE(info) != NULL)
		gate = S_ADDR(INFO_GATE(info));

	if (ifp == NULL) {
		if (INFO_GATE(info) != NULL)
			ifp = iflookup(gate);
		if (ifp == NULL) {
			msglim(&msg_no_ifp, gate,
			    "route %s --> %s nexthop is not directly connected",
			    addrname(S_ADDR(INFO_DST(info)), mask, 0),
			    naddr_ntoa(gate));
		}
	}

	k = kern_add(S_ADDR(INFO_DST(info)), mask, gate, ifp);

	if (k->k_state & KS_NEW)
		k->k_keep = now.tv_sec+keep;
	if (INFO_GATE(info) == 0) {
		trace_act("note %s without gateway",
		    rtm_type_name(rtm->rtm_type));
		k->k_metric = HOPCNT_INFINITY;
	} else if (INFO_GATE(info)->ss_family != AF_INET) {
		trace_act("note %s with gateway AF=%d",
		    rtm_type_name(rtm->rtm_type),
		    INFO_GATE(info)->ss_family);
		k->k_metric = HOPCNT_INFINITY;
	} else {
		k->k_gate = S_ADDR(INFO_GATE(info));
		k->k_metric = rtm->rtm_rmx.rmx_hopcount;
		if (k->k_metric < 0)
			k->k_metric = 0;
		else if (k->k_metric > HOPCNT_INFINITY-1)
			k->k_metric = HOPCNT_INFINITY-1;
	}

	if ((k->k_state & KS_NEW) && interf_route) {
		if (k->k_gate != 0 && findifaddr(k->k_gate) == NULL)
			k->k_state |= KS_DEPRE_IF;
		else
			k->k_state |= KS_IF;
	}

	k->k_state &= ~(KS_NEW | KS_DELETE | KS_ADD | KS_CHANGE | KS_DEL_ADD |
	    KS_STATIC | KS_GATEWAY | KS_DELETED | KS_PRIVATE | KS_CHECK);
	if (rtm->rtm_flags & RTF_GATEWAY)
		k->k_state |= KS_GATEWAY;
	if (rtm->rtm_flags & RTF_STATIC)
		k->k_state |= KS_STATIC;
	if (rtm->rtm_flags & RTF_PRIVATE)
		k->k_state |= KS_PRIVATE;


	if (rtm->rtm_flags & (RTF_DYNAMIC | RTF_MODIFIED)) {
		if (INFO_AUTHOR(info) != 0 &&
		    INFO_AUTHOR(info)->ss_family == AF_INET)
			ifp = iflookup(S_ADDR(INFO_AUTHOR(info)));
		else
			ifp = NULL;
		if (should_supply(ifp) && (ifp == NULL ||
		    !(ifp->int_state & IS_REDIRECT_OK))) {
			/*
			 * Routers are not supposed to listen to redirects,
			 * so delete it if it came via an unknown interface
			 * or the interface does not have special permission.
			 */
			k->k_state &= ~KS_DYNAMIC;
			k->k_state |= KS_DELETE;
			LIM_SEC(need_kern, 0);
			trace_act("mark for deletion redirected %s --> %s"
			    " via %s",
			    addrname(k->k_dst, k->k_mask, 0),
			    naddr_ntoa(k->k_gate),
			    ifp ? ifp->int_name : "unknown interface");
		} else {
			k->k_state |= KS_DYNAMIC;
			k->k_redirect_time = now.tv_sec;
			trace_act("accept redirected %s --> %s via %s",
			    addrname(k->k_dst, k->k_mask, 0),
			    naddr_ntoa(k->k_gate),
			    ifp ? ifp->int_name : "unknown interface");
		}
		return;
	}

	/*
	 * If it is not a static route, quit until the next comparison
	 * between the kernel and daemon tables, when it will be deleted.
	 */
	if (!(k->k_state & KS_STATIC)) {
		if (!(k->k_state & (KS_IF|KS_DEPRE_IF|KS_FILE)))
			k->k_state |= KS_DELETE;
		LIM_SEC(need_kern, k->k_keep);
		return;
	}

	/*
	 * Put static routes with real metrics into the daemon table so
	 * they can be advertised.
	 */

	kern_check_static(k, ifp);
}


/* deal with packet loss */
static void
rtm_lose(struct rt_msghdr *rtm, struct rt_addrinfo *info)
{
	struct rt_spare new, *rts, *losing_rts = NULL;
	struct rt_entry *rt;
	int i, spares;

	if (INFO_GATE(info) == NULL || INFO_GATE(info)->ss_family != AF_INET) {
		trace_act("ignore %s without gateway",
		    rtm_type_name(rtm->rtm_type));
		age(0);
		return;
	}

	rt = rtfind(S_ADDR(INFO_DST(info)));
	if (rt != NULL) {
		spares = 0;
		for (i = 0; i < rt->rt_num_spares;  i++) {
			rts = &rt->rt_spares[i];
			if (rts->rts_gate == S_ADDR(INFO_GATE(info))) {
				losing_rts = rts;
				continue;
			}
			if (rts->rts_gate != 0 && rts->rts_ifp != &dummy_ifp)
				spares++;
		}
	}
	if (rt == NULL || losing_rts == NULL) {
		trace_act("Ignore RTM_LOSING because no route found"
		    " for %s through %s",
		    naddr_ntoa(S_ADDR(INFO_DST(info))),
		    naddr_ntoa(S_ADDR(INFO_GATE(info))));
		return;
	}
	if (spares == 0) {
		trace_act("Got RTM_LOSING, but no alternatives to gw %s."
		    " deprecating route to metric 15",
		    naddr_ntoa(S_ADDR(INFO_GATE(info))));
		new = *losing_rts;
		new.rts_metric = HOPCNT_INFINITY - 1;
		rtchange(rt, rt->rt_state, &new, 0);
		return;
	}
	trace_act("Got RTM_LOSING. Found a route with %d alternates", spares);
	if (rdisc_ok)
		rdisc_age(S_ADDR(INFO_GATE(info)));
	age(S_ADDR(INFO_GATE(info)));
}


/*
 * Make the gateway slot of an info structure point to something
 * useful.  If it is not already useful, but it specifies an interface,
 * then fill in the sockaddr_in provided and point it there.
 */
static int
get_info_gate(struct sockaddr_storage **ssp, struct sockaddr_in *sin)
{
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)*ssp;
	struct interface *ifp;

	if (sdl == NULL)
		return (0);
	if ((sdl)->sdl_family == AF_INET)
		return (1);
	if ((sdl)->sdl_family != AF_LINK)
		return (0);

	ifp = ifwithindex(sdl->sdl_index, _B_TRUE);
	if (ifp == NULL)
		return (0);

	sin->sin_addr.s_addr = ifp->int_addr;
	sin->sin_family = AF_INET;
	/* LINTED */
	*ssp = (struct sockaddr_storage *)sin;

	return (1);
}


/*
 * Clean the kernel table by copying it to the daemon image.
 * Eventually the daemon will delete any extra routes.
 */
void
sync_kern(void)
{
	int i;
	struct khash *k;
	struct {
		struct T_optmgmt_req req;
		struct opthdr hdr;
	} req;
	union {
		struct T_optmgmt_ack ack;
		unsigned char space[64];
	} ack;
	struct opthdr *rh;
	struct strbuf cbuf, dbuf;
	int ipfd, nroutes, flags, r;
	mib2_ipRouteEntry_t routes[8];
	mib2_ipRouteEntry_t *rp;
	struct rt_msghdr rtm;
	struct rt_addrinfo info;
	struct sockaddr_in sin_dst;
	struct sockaddr_in sin_gate;
	struct sockaddr_in sin_mask;
	struct sockaddr_in sin_author;
	struct interface *ifp;
	char ifname[LIFNAMSIZ + 1];

	for (i = 0; i < KHASH_SIZE; i++) {
		for (k = khash_bins[i]; k != NULL; k = k->k_next) {
			if (!(k->k_state & (KS_IF|KS_DEPRE_IF)))
				k->k_state |= KS_CHECK;
		}
	}

	ipfd = open(IP_DEV_NAME, O_RDWR);
	if (ipfd == -1) {
		msglog("open " IP_DEV_NAME ": %s", rip_strerror(errno));
		goto hash_clean;
	}

	req.req.PRIM_type = T_OPTMGMT_REQ;
	req.req.OPT_offset = (caddr_t)&req.hdr - (caddr_t)&req;
	req.req.OPT_length = sizeof (req.hdr);
	req.req.MGMT_flags = T_CURRENT;

	req.hdr.level = MIB2_IP;
	req.hdr.name = 0;
	req.hdr.len = 0;

	cbuf.buf = (caddr_t)&req;
	cbuf.len = sizeof (req);

	if (putmsg(ipfd, &cbuf, NULL, 0) == -1) {
		msglog("T_OPTMGMT_REQ putmsg: %s", rip_strerror(errno));
		goto hash_clean;
	}

	for (;;) {
		cbuf.buf = (caddr_t)&ack;
		cbuf.maxlen = sizeof (ack);
		dbuf.buf = (caddr_t)routes;
		dbuf.maxlen = sizeof (routes);
		flags = 0;
		r = getmsg(ipfd, &cbuf, &dbuf, &flags);
		if (r == -1) {
			msglog("T_OPTMGMT_REQ getmsg: %s", rip_strerror(errno));
			goto hash_clean;
		}

		if (cbuf.len < sizeof (struct T_optmgmt_ack) ||
		    ack.ack.PRIM_type != T_OPTMGMT_ACK ||
		    ack.ack.MGMT_flags != T_SUCCESS ||
		    ack.ack.OPT_length < sizeof (struct opthdr)) {
			msglog("bad T_OPTMGMT response; len=%d prim=%d "
			    "flags=%d optlen=%d", cbuf.len, ack.ack.PRIM_type,
			    ack.ack.MGMT_flags, ack.ack.OPT_length);
			goto hash_clean;
		}
		/* LINTED */
		rh = (struct opthdr *)((caddr_t)&ack + ack.ack.OPT_offset);
		if (rh->level == 0 && rh->name == 0) {
			break;
		}
		if (rh->level != MIB2_IP || rh->name != MIB2_IP_21) {
			while (r == MOREDATA) {
				r = getmsg(ipfd, NULL, &dbuf, &flags);
			}
			continue;
		}
		break;
	}

	(void) memset(&rtm, 0, sizeof (rtm));
	(void) memset(&info, 0, sizeof (info));
	(void) memset(&sin_dst, 0, sizeof (sin_dst));
	(void) memset(&sin_gate, 0, sizeof (sin_gate));
	(void) memset(&sin_mask, 0, sizeof (sin_mask));
	(void) memset(&sin_author, 0, sizeof (sin_author));
	sin_dst.sin_family = AF_INET;
	/* LINTED */
	info.rti_info[RTAX_DST] = (struct sockaddr_storage *)&sin_dst;
	sin_gate.sin_family = AF_INET;
	/* LINTED */
	info.rti_info[RTAX_GATEWAY] = (struct sockaddr_storage *)&sin_gate;
	sin_mask.sin_family = AF_INET;
	/* LINTED */
	info.rti_info[RTAX_NETMASK] = (struct sockaddr_storage *)&sin_mask;
	sin_dst.sin_family = AF_INET;
	/* LINTED */
	info.rti_info[RTAX_AUTHOR] = (struct sockaddr_storage *)&sin_author;

	for (;;) {
		nroutes = dbuf.len / sizeof (mib2_ipRouteEntry_t);
		for (rp = routes; nroutes > 0; ++rp, nroutes--) {

			/*
			 * Ignore IRE cache, broadcast, and local address
			 * entries; they're not subject to routing socket
			 * control.
			 */
			if (rp->ipRouteInfo.re_ire_type &
			    (IRE_BROADCAST | IRE_CACHE | IRE_LOCAL))
				continue;

			/* ignore multicast and link local addresses */
			if (IN_MULTICAST(ntohl(rp->ipRouteDest)) ||
			    IN_LINKLOCAL(ntohl(rp->ipRouteDest))) {
				continue;
			}


#ifdef DEBUG_KERNEL_ROUTE_READ
			(void) fprintf(stderr, "route type %d, ire type %08X, "
			    "flags %08X: %s", rp->ipRouteType,
			    rp->ipRouteInfo.re_ire_type,
			    rp->ipRouteInfo.re_flags,
			    naddr_ntoa(rp->ipRouteDest));
			(void) fprintf(stderr, " %s",
			    naddr_ntoa(rp->ipRouteMask));
			(void) fprintf(stderr, " %s\n",
			    naddr_ntoa(rp->ipRouteNextHop));
#endif

			/* Fake up the needed entries */
			rtm.rtm_flags = rp->ipRouteInfo.re_flags;
			rtm.rtm_type = RTM_GET;
			rtm.rtm_rmx.rmx_hopcount = rp->ipRouteMetric1;

			(void) memset(ifname, 0, sizeof (ifname));
			if (rp->ipRouteIfIndex.o_length <
			    sizeof (rp->ipRouteIfIndex.o_bytes))
				rp->ipRouteIfIndex.o_bytes[
				    rp->ipRouteIfIndex.o_length] = '\0';
			(void) strncpy(ifname, rp->ipRouteIfIndex.o_bytes,
			    sizeof (ifname));

			/*
			 * First try to match up on gwkludge entries
			 * before trying to match ifp by name/nexthop.
			 */
			if ((ifp = gwkludge_iflookup(rp->ipRouteDest,
			    rp->ipRouteNextHop,
			    ntohl(rp->ipRouteMask))) == NULL) {
				ifp = lifp_iflookup(rp->ipRouteNextHop, ifname);
			}

#ifdef DEBUG_KERNEL_ROUTE_READ
			if (ifp != NULL) {
				(void) fprintf(stderr, "   found interface"
				    " %-4s #%-3d ", ifp->int_name,
				    (ifp->int_phys != NULL) ?
				    ifp->int_phys->phyi_index : 0);
				(void) fprintf(stderr, "%-15s-->%-15s \n",
				    naddr_ntoa(ifp->int_addr),
				    addrname(((ifp->int_if_flags &
				    IFF_POINTOPOINT) ?
				    ifp->int_dstaddr : htonl(ifp->int_net)),
				    ifp->int_mask, 1));
			}
#endif

			info.rti_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
			if (rp->ipRouteInfo.re_ire_type & IRE_HOST_REDIRECT)
				info.rti_addrs |= RTA_AUTHOR;
			sin_dst.sin_addr.s_addr = rp->ipRouteDest;
			sin_gate.sin_addr.s_addr = rp->ipRouteNextHop;
			sin_mask.sin_addr.s_addr = rp->ipRouteMask;
			sin_author.sin_addr.s_addr =
			    rp->ipRouteInfo.re_src_addr;

			/*
			 * Note static routes and interface routes, and also
			 * preload the image of the kernel table so that
			 * we can later clean it, as well as avoid making
			 * unneeded changes.  Keep the old kernel routes for a
			 * few seconds to allow a RIP or router-discovery
			 * response to be heard.
			 */
			rtm_add(&rtm, &info, MAX_WAITTIME,
			    ((rp->ipRouteInfo.re_ire_type &
			    (IRE_INTERFACE|IRE_LOOPBACK)) != 0), ifp);
		}
		if (r == 0) {
			break;
		}
		r = getmsg(ipfd, NULL, &dbuf, &flags);
	}

hash_clean:
	if (ipfd != -1)
		(void) close(ipfd);
	for (i = 0; i < KHASH_SIZE; i++) {
		for (k = khash_bins[i]; k != NULL; k = k->k_next) {

			/*
			 * KS_DELETED routes have been removed from the
			 * kernel, but we keep them around for reasons
			 * stated in del_static(), so we skip the check
			 * for KS_DELETED routes here.
			 */
			if ((k->k_state & (KS_CHECK|KS_DELETED)) == KS_CHECK) {

				if (!(k->k_state & KS_DYNAMIC)) {
					writelog(LOG_WARNING,
					    "%s --> %s disappeared from kernel",
					    addrname(k->k_dst, k->k_mask, 0),
					    naddr_ntoa(k->k_gate));
				}
				del_static(k->k_dst, k->k_mask, k->k_gate,
				    k->k_ifp, 1);

			}
		}
	}
}


/* Listen to announcements from the kernel */
void
read_rt(void)
{
	long cc;
	struct interface *ifp;
	struct sockaddr_in gate_sin;
	in_addr_t mask, gate;
	union {
		struct {
			struct rt_msghdr rtm;
			struct sockaddr_storage addrs[RTA_NUMBITS];
		} r;
		struct if_msghdr ifm;
	} m;
	char str[100], *strp;
	struct rt_addrinfo info;


	for (;;) {
		cc = read(rt_sock, &m, sizeof (m));
		if (cc <= 0) {
			if (cc < 0 && errno != EWOULDBLOCK)
				LOGERR("read(rt_sock)");
			return;
		}

		if (TRACERTS)
			dump_rt_msg("read", &m.r.rtm, cc);

		if (cc < m.r.rtm.rtm_msglen) {
			msglog("routing message truncated (%d < %d)",
			    cc, m.r.rtm.rtm_msglen);
		}

		if (m.r.rtm.rtm_version != RTM_VERSION) {
			msglog("bogus routing message version %d",
			    m.r.rtm.rtm_version);
			continue;
		}

		ifp = NULL;

		if (m.r.rtm.rtm_type == RTM_IFINFO ||
		    m.r.rtm.rtm_type == RTM_NEWADDR ||
		    m.r.rtm.rtm_type == RTM_DELADDR) {
			strp = if_bit_string(m.ifm.ifm_flags, _B_TRUE);
			if (strp == NULL) {
				strp = str;
				(void) sprintf(str, "%#x", m.ifm.ifm_flags);
			}
			ifp = ifwithindex(m.ifm.ifm_index,
			    m.r.rtm.rtm_type != RTM_DELADDR);
			if (ifp == NULL) {
				char ifname[LIFNAMSIZ], *ifnamep;

				ifnamep = if_indextoname(m.ifm.ifm_index,
				    ifname);
				if (ifnamep == NULL) {
					trace_act("note %s with flags %s"
					    " for unknown interface index #%d",
					    rtm_type_name(m.r.rtm.rtm_type),
					    strp, m.ifm.ifm_index);
				} else {
					trace_act("note %s with flags %s"
					    " for unknown interface %s",
					    rtm_type_name(m.r.rtm.rtm_type),
					    strp, ifnamep);
				}
			} else {
				trace_act("note %s with flags %s for %s",
				    rtm_type_name(m.r.rtm.rtm_type),
				    strp, ifp->int_name);
			}
			if (strp != str)
				free(strp);

			/*
			 * After being informed of a change to an interface,
			 * check them all now if the check would otherwise
			 * be a long time from now, if the interface is
			 * not known, or if the interface has been turned
			 * off or on.
			 */
			if (ifscan_timer.tv_sec-now.tv_sec >=
			    CHECK_BAD_INTERVAL || ifp == NULL ||
			    ((ifp->int_if_flags ^ m.ifm.ifm_flags) &
			    IFF_UP) != 0)
				ifscan_timer.tv_sec = now.tv_sec;
			continue;
		} else if (m.r.rtm.rtm_type == RTM_CHGADDR ||
		    m.r.rtm.rtm_type == RTM_FREEADDR) {
			continue;
		} else {
			if (m.r.rtm.rtm_index != 0)
				ifp = ifwithindex(m.r.rtm.rtm_index, 1);
		}

		(void) strlcpy(str, rtm_type_name(m.r.rtm.rtm_type),
		    sizeof (str));
		strp = &str[strlen(str)];
		if (m.r.rtm.rtm_type <= RTM_CHANGE)
			strp += snprintf(strp, sizeof (str) - (strp - str),
			    " from pid %d", (int)m.r.rtm.rtm_pid);

		/* LINTED */
		(void) rt_xaddrs(&info, (struct sockaddr_storage *)(&m.r.rtm +
		    1), (char *)&m + cc, m.r.rtm.rtm_addrs);

		if (INFO_DST(&info) == 0) {
			trace_act("ignore %s without dst", str);
			continue;
		}

		if (INFO_DST(&info)->ss_family != AF_INET) {
			trace_act("ignore %s for AF %d", str,
			    INFO_DST(&info)->ss_family);
			continue;
		}

		mask = ((INFO_MASK(&info) != 0) ?
		    ntohl(S_ADDR(INFO_MASK(&info))) :
		    (m.r.rtm.rtm_flags & RTF_HOST) ?
		    HOST_MASK : std_mask(S_ADDR(INFO_DST(&info))));

		strp += snprintf(strp, sizeof (str) - (strp - str), ": %s",
		    addrname(S_ADDR(INFO_DST(&info)), mask, 0));

		if (IN_MULTICAST(ntohl(S_ADDR(INFO_DST(&info)))) ||
		    IN_LINKLOCAL(ntohl(S_ADDR(INFO_DST(&info))))) {
			trace_act("ignore multicast/link local %s", str);
			continue;
		}

		if (m.r.rtm.rtm_flags & RTF_LLINFO) {
			trace_act("ignore ARP %s", str);
			continue;
		}

		if (get_info_gate(&INFO_GATE(&info), &gate_sin)) {
			gate = S_ADDR(INFO_GATE(&info));
			strp += snprintf(strp, sizeof (str) - (strp - str),
			    " --> %s", naddr_ntoa(gate));
		} else {
			gate = 0;
		}

		if (INFO_AUTHOR(&info) != 0)
			strp += snprintf(strp, sizeof (str) - (strp - str),
			    " by authority of %s",
			    saddr_ntoa(INFO_AUTHOR(&info)));

		switch (m.r.rtm.rtm_type) {
		case RTM_ADD:
		case RTM_CHANGE:
		case RTM_REDIRECT:
			if (m.r.rtm.rtm_errno != 0) {
				trace_act("ignore %s with \"%s\" error",
				    str, rip_strerror(m.r.rtm.rtm_errno));
			} else {
				trace_act("%s", str);
				rtm_add(&m.r.rtm, &info, 0,
				    !(m.r.rtm.rtm_flags & RTF_GATEWAY) &&
				    m.r.rtm.rtm_type != RTM_REDIRECT, ifp);

			}
			break;

		case RTM_DELETE:
			if (m.r.rtm.rtm_errno != 0 &&
			    m.r.rtm.rtm_errno != ESRCH) {
				trace_act("ignore %s with \"%s\" error",
				    str, rip_strerror(m.r.rtm.rtm_errno));
			} else {
				trace_act("%s", str);
				del_static(S_ADDR(INFO_DST(&info)), mask,
				    gate, ifp, 1);
			}
			break;

		case RTM_LOSING:
			trace_act("%s", str);
			rtm_lose(&m.r.rtm, &info);
			break;

		default:
			trace_act("ignore %s", str);
			break;
		}
	}
}


/*
 * Disassemble a routing message.  The result is an array of pointers
 * to sockaddr_storage structures stored in the info argument.
 *
 * ss is a pointer to the beginning of the data following the
 * rt_msghdr contained in the routing socket message, which consists
 * of a string of concatenated sockaddr structure of different types.
 *
 * Extended attributes can be appended at the end of the list.
 */
static int
rt_xaddrs(struct rt_addrinfo *info,
    struct sockaddr_storage *ss,
    char *lim,
    int addrs)
{
	int retv = 0;
	int i;
	int abit;
	int complaints;
	static int prev_complaints;

#define	XBAD_AF		0x1
#define	XBAD_SHORT	0x2
#define	XBAD_LONG	0x4

	(void) memset(info, 0, sizeof (*info));
	info->rti_addrs = addrs;
	complaints = 0;
	for (i = 0, abit = 1; i < RTAX_MAX && (char *)ss < lim;
	    i++, abit <<= 1) {
		if ((addrs & abit) == 0)
			continue;
		info->rti_info[i] = ss;
		/* Horrible interface here */
		switch (ss->ss_family) {
		case AF_UNIX:
			/* LINTED */
			ss = (struct sockaddr_storage *)(
			    (struct sockaddr_un *)ss + 1);
			break;
		case AF_INET:
			/* LINTED */
			ss = (struct sockaddr_storage *)(
			    (struct sockaddr_in *)ss + 1);
			break;
		case AF_LINK:
			/* LINTED */
			ss = (struct sockaddr_storage *)(
			    (struct sockaddr_dl *)ss + 1);
			break;
		case AF_INET6:
			/* LINTED */
			ss = (struct sockaddr_storage *)(
			    (struct sockaddr_in6 *)ss + 1);
			break;
		default:
			if (!(prev_complaints & XBAD_AF))
				writelog(LOG_WARNING,
				    "unknown address family %d "
				    "encountered", ss->ss_family);
			if (complaints & XBAD_AF)
				goto xaddr_done;
			/* LINTED */
			ss = (struct sockaddr_storage *)(
			    (struct sockaddr *)ss + 1);
			complaints |= XBAD_AF;
			info->rti_addrs &= abit - 1;
			addrs = info->rti_addrs;
			retv = -1;
			break;
		}
		if ((char *)ss > lim) {
			if (!(prev_complaints & XBAD_SHORT))
				msglog("sockaddr %d too short by %d "
				    "bytes", i + 1, (char *)ss - lim);
			complaints |= XBAD_SHORT;
			info->rti_info[i] = NULL;
			info->rti_addrs &= abit - 1;
			retv = -1;
			goto xaddr_done;
		}
	}

	while (((char *)ss + sizeof (rtm_ext_t)) <= lim) {
		rtm_ext_t *tp;
		char *nxt;

		/* LINTED: alignment */
		tp = (rtm_ext_t *)ss;
		nxt = (char *)(tp + 1) + tp->rtmex_len;

		if (!IS_P2ALIGNED(tp->rtmex_len, sizeof (uint32_t)) ||
		    nxt > lim) {
			break;
		}

		/* LINTED: alignment */
		ss = (struct sockaddr_storage *)nxt;
	}

	if ((char *)ss != lim) {
		if ((char *)ss > lim) {
			if (!(prev_complaints & XBAD_SHORT))
				msglog("routing message too short by %d bytes",
				    (char *)ss - lim);
			complaints |= XBAD_SHORT;
		} else if (!(prev_complaints & XBAD_LONG)) {
			msglog("%d bytes of routing message left over",
			    lim - (char *)ss);
			complaints |= XBAD_LONG;
		}
		retv = -1;
	}
xaddr_done:
	prev_complaints = complaints;
	return (retv);
}

/* after aggregating, note routes that belong in the kernel */
static void
kern_out(struct ag_info *ag)
{
	struct khash *k;
	struct interface *ifp;

	ifp = ag->ag_ifp;

	/*
	 * Do not install bad routes if they are not already present.
	 * This includes routes that had RS_NET_SYN for interfaces that
	 * recently died.
	 */
	if (ag->ag_metric == HOPCNT_INFINITY) {
		k = kern_find(htonl(ag->ag_dst_h), ag->ag_mask,
		    ag->ag_nhop, ag->ag_ifp, NULL);
		if (k == NULL)
			return;
	} else {
		k = kern_add(htonl(ag->ag_dst_h), ag->ag_mask, ag->ag_nhop,
		    ifp);
	}

	if (k->k_state & KS_NEW) {
		/* will need to add new entry to the kernel table */
		k->k_state = KS_ADD;
		if (ag->ag_state & AGS_GATEWAY)
			k->k_state |= KS_GATEWAY;
		if (ag->ag_state & AGS_IF)
			k->k_state |= KS_IF;
		if (ag->ag_state & AGS_PASSIVE)
			k->k_state |= KS_PASSIVE;
		if (ag->ag_state & AGS_FILE)
			k->k_state |= KS_FILE;
		k->k_gate = ag->ag_nhop;
		k->k_ifp = ifp;
		k->k_metric = ag->ag_metric;
		return;
	}

	if ((k->k_state & (KS_STATIC|KS_DEPRE_IF)) ||
	    ((k->k_state & (KS_IF|KS_PASSIVE)) == KS_IF)) {
		return;
	}

	/* modify existing kernel entry if necessary */
	if (k->k_gate == ag->ag_nhop && k->k_ifp == ag->ag_ifp &&
	    k->k_metric != ag->ag_metric) {
			/*
			 * Must delete bad interface routes etc.
			 * to change them.
			 */
			if (k->k_metric == HOPCNT_INFINITY)
				k->k_state |= KS_DEL_ADD;
			k->k_gate = ag->ag_nhop;
			k->k_metric = ag->ag_metric;
			k->k_state |= KS_CHANGE;
	}

	/*
	 * If the daemon thinks the route should exist, forget
	 * about any redirections.
	 * If the daemon thinks the route should exist, eventually
	 * override manual intervention by the operator.
	 */
	if ((k->k_state & (KS_DYNAMIC | KS_DELETED)) != 0) {
		k->k_state &= ~KS_DYNAMIC;
		k->k_state |= (KS_ADD | KS_DEL_ADD);
	}

	if ((k->k_state & KS_GATEWAY) && !(ag->ag_state & AGS_GATEWAY)) {
		k->k_state &= ~KS_GATEWAY;
		k->k_state |= (KS_ADD | KS_DEL_ADD);
	} else if (!(k->k_state & KS_GATEWAY) && (ag->ag_state & AGS_GATEWAY)) {
		k->k_state |= KS_GATEWAY;
		k->k_state |= (KS_ADD | KS_DEL_ADD);
	}

	/*
	 * Deleting-and-adding is necessary to change aspects of a route.
	 * Just delete instead of deleting and then adding a bad route.
	 * Otherwise, we want to keep the route in the kernel.
	 */
	if (k->k_metric == HOPCNT_INFINITY && (k->k_state & KS_DEL_ADD))
		k->k_state |= KS_DELETE;
	else
		k->k_state &= ~KS_DELETE;
#undef RT
}

/*
 * Update our image of the kernel forwarding table using the given
 * route from our internal routing table.
 */

/*ARGSUSED1*/
static int
walk_kern(struct radix_node *rn, void *argp)
{
#define	RT ((struct rt_entry *)rn)
	uint8_t metric, pref;
	uint_t ags = 0;
	int i;
	struct rt_spare *rts;

	/* Do not install synthetic routes */
	if (RT->rt_state & RS_NET_SYN)
		return (0);

	/*
	 * Do not install static routes here. Only
	 * read_rt->rtm_add->kern_add should install those
	 */
	if ((RT->rt_state & RS_STATIC) &&
	    (RT->rt_spares[0].rts_origin != RO_FILE))
		return (0);

	/* Do not clobber kernel if this is a route for a dead interface */
	if (RT->rt_state & RS_BADIF)
		return (0);

	if (!(RT->rt_state & RS_IF)) {
		/* This is an ordinary route, not for an interface. */

		/*
		 * aggregate, ordinary good routes without regard to
		 * their metric
		 */
		pref = 1;
		ags |= (AGS_GATEWAY | AGS_SUPPRESS | AGS_AGGREGATE);

		/*
		 * Do not install host routes directly to hosts, to avoid
		 * interfering with ARP entries in the kernel table.
		 */
		if (RT_ISHOST(RT) && ntohl(RT->rt_dst) == RT->rt_gate)
			return (0);

	} else {
		/*
		 * This is an interface route.
		 * Do not install routes for "external" remote interfaces.
		 */
		if (RT->rt_ifp != NULL && (RT->rt_ifp->int_state & IS_EXTERNAL))
			return (0);

		/* Interfaces should override received routes. */
		pref = 0;
		ags |= (AGS_IF | AGS_CORS_GATE);
		if (RT->rt_ifp != NULL &&
		    !(RT->rt_ifp->int_if_flags & IFF_LOOPBACK) &&
		    (RT->rt_ifp->int_state & (IS_PASSIVE|IS_ALIAS)) ==
		    IS_PASSIVE) {
			ags |= AGS_PASSIVE;
		}

		/*
		 * If it is not an interface, or an alias for an interface,
		 * it must be a "gateway."
		 *
		 * If it is a "remote" interface, it is also a "gateway" to
		 * the kernel if is not a alias.
		 */
		if (RT->rt_ifp == NULL || (RT->rt_ifp->int_state & IS_REMOTE)) {

			ags |= (AGS_GATEWAY | AGS_SUPPRESS);

			/*
			 * Do not aggregate IS_PASSIVE routes.
			 */
			if (!(RT->rt_ifp->int_state & IS_PASSIVE))
				ags |= AGS_AGGREGATE;
		}
	}

	metric = RT->rt_metric;
	if (metric == HOPCNT_INFINITY) {
		/* If the route is dead, try hard to aggregate. */
		pref = HOPCNT_INFINITY;
		ags |= (AGS_FINE_GATE | AGS_SUPPRESS);
		ags &= ~(AGS_IF | AGS_CORS_GATE);
	}

	/*
	 * dump all routes that have the same metric as rt_spares[0]
	 * into the kern_table, to be added to the kernel.
	 */
	for (i = 0; i < RT->rt_num_spares; i++) {
		rts = &RT->rt_spares[i];

		/* Do not install external routes */
		if (rts->rts_flags & RTS_EXTERNAL)
			continue;

		if (rts->rts_metric == metric) {
			ag_check(RT->rt_dst, RT->rt_mask,
			    rts->rts_router, rts->rts_ifp, rts->rts_gate,
			    metric, pref, 0, 0,
			    (rts->rts_origin & RO_FILE) ? (ags|AGS_FILE) : ags,
			    kern_out);
		}
	}
	return (0);
#undef RT
}


/* Update the kernel table to match the daemon table. */
static void
fix_kern(void)
{
	int i;
	struct khash *k, *pk, *knext;


	need_kern = age_timer;

	/* Walk daemon table, updating the copy of the kernel table. */
	(void) rn_walktree(rhead, walk_kern, NULL);
	ag_flush(0, 0, kern_out);

	for (i = 0; i < KHASH_SIZE; i++) {
		pk = NULL;
		for (k = khash_bins[i]; k != NULL;  k = knext) {
			knext = k->k_next;

			/* Do not touch local interface routes */
			if ((k->k_state & KS_DEPRE_IF) ||
			    (k->k_state & (KS_IF|KS_PASSIVE)) == KS_IF) {
				pk = k;
				continue;
			}

			/* Do not touch static routes */
			if (k->k_state & KS_STATIC) {
				kern_check_static(k, 0);
				pk = k;
				continue;
			}

			/* check hold on routes deleted by the operator */
			if (k->k_keep > now.tv_sec) {
				/* ensure we check when the hold is over */
				LIM_SEC(need_kern, k->k_keep);
				pk = k;
				continue;
			}

			if ((k->k_state & KS_DELETE) &&
			    !(k->k_state & KS_DYNAMIC)) {
				if ((k->k_dst == RIP_DEFAULT) &&
				    (k->k_ifp != NULL) &&
				    (kern_alternate(RIP_DEFAULT,
				    k->k_mask, k->k_gate, k->k_ifp,
				    NULL) == NULL))
					rdisc_restore(k->k_ifp);
				kern_ioctl(k, RTM_DELETE, 0);
				if (pk != NULL)
					pk->k_next = knext;
				else
					khash_bins[i] = knext;
				free(k);
				continue;
			}

			if (k->k_state & KS_DEL_ADD)
				kern_ioctl(k, RTM_DELETE, 0);

			if (k->k_state & KS_ADD) {
				if ((k->k_dst == RIP_DEFAULT) &&
				    (k->k_ifp != NULL))
					rdisc_suppress(k->k_ifp);
				kern_ioctl(k, RTM_ADD,
				    ((0 != (k->k_state & (KS_GATEWAY |
				    KS_DYNAMIC))) ? RTF_GATEWAY : 0));
			} else if (k->k_state & KS_CHANGE) {
				kern_ioctl(k, RTM_CHANGE,
				    ((0 != (k->k_state & (KS_GATEWAY |
				    KS_DYNAMIC))) ? RTF_GATEWAY : 0));
			}
			k->k_state &= ~(KS_ADD|KS_CHANGE|KS_DEL_ADD);

			/*
			 * Mark this route to be deleted in the next cycle.
			 * This deletes routes that disappear from the
			 * daemon table, since the normal aging code
			 * will clear the bit for routes that have not
			 * disappeared from the daemon table.
			 */
			k->k_state |= KS_DELETE;
			pk = k;
		}
	}
}


/* Delete a static route in the image of the kernel table. */
void
del_static(in_addr_t dst, in_addr_t mask, in_addr_t gate,
    struct interface *ifp, int gone)
{
	struct khash *k;
	struct rt_entry *rt;

	/*
	 * Just mark it in the table to be deleted next time the kernel
	 * table is updated.
	 * If it has already been deleted, mark it as such, and set its
	 * keep-timer so that it will not be deleted again for a while.
	 * This lets the operator delete a route added by the daemon
	 * and add a replacement.
	 */
	k = kern_find(dst, mask, gate, ifp, NULL);
	if (k != NULL && (gate == 0 || k->k_gate == gate)) {
		k->k_state &= ~(KS_STATIC | KS_DYNAMIC | KS_CHECK);
		k->k_state |= KS_DELETE;
		if (gone) {
			k->k_state |= KS_DELETED;
			k->k_keep = now.tv_sec + K_KEEP_LIM;
		}
	}

	rt = rtget(dst, mask);
	if (rt != NULL && (rt->rt_state & RS_STATIC))
		rtbad(rt, NULL);
}


/*
 * Delete all routes generated from ICMP Redirects that use a given gateway,
 * as well as old redirected routes.
 */
void
del_redirects(in_addr_t bad_gate, time_t old)
{
	int i;
	struct khash *k;
	boolean_t dosupply = should_supply(NULL);

	for (i = 0; i < KHASH_SIZE; i++) {
		for (k = khash_bins[i]; k != NULL; k = k->k_next) {
			if (!(k->k_state & KS_DYNAMIC) ||
			    (k->k_state & (KS_STATIC|KS_IF|KS_DEPRE_IF)))
				continue;

			if (k->k_gate != bad_gate && k->k_redirect_time > old &&
			    !dosupply)
				continue;

			k->k_state |= KS_DELETE;
			k->k_state &= ~KS_DYNAMIC;
			need_kern.tv_sec = now.tv_sec;
			trace_act("mark redirected %s --> %s for deletion",
			    addrname(k->k_dst, k->k_mask, 0),
			    naddr_ntoa(k->k_gate));
		}
	}
}

/* Start the daemon tables. */
void
rtinit(void)
{
	int i;
	struct ag_info *ag;

	/* Initialize the radix trees */
	rn_init();
	(void) rn_inithead((void**)&rhead, 32);

	/* mark all of the slots in the table free */
	ag_avail = ag_slots;
	for (ag = ag_slots, i = 1; i < NUM_AG_SLOTS; i++) {
		ag->ag_fine = ag+1;
		ag++;
	}
}


static struct sockaddr_in dst_sock = {AF_INET};
static struct sockaddr_in mask_sock = {AF_INET};


static void
set_need_flash(void)
{
	if (!need_flash) {
		need_flash = _B_TRUE;
		/*
		 * Do not send the flash update immediately.  Wait a little
		 * while to hear from other routers.
		 */
		no_flash.tv_sec = now.tv_sec + MIN_WAITTIME;
	}
}


/* Get a particular routing table entry */
struct rt_entry *
rtget(in_addr_t dst, in_addr_t mask)
{
	struct rt_entry *rt;

	dst_sock.sin_addr.s_addr = dst;
	mask_sock.sin_addr.s_addr = htonl(mask);
	rt = (struct rt_entry *)rhead->rnh_lookup(&dst_sock, &mask_sock, rhead);
	if (rt == NULL || rt->rt_dst != dst || rt->rt_mask != mask)
		return (NULL);

	return (rt);
}


/* Find a route to dst as the kernel would. */
struct rt_entry *
rtfind(in_addr_t dst)
{
	dst_sock.sin_addr.s_addr = dst;
	return ((struct rt_entry *)rhead->rnh_matchaddr(&dst_sock, rhead));
}

/* add a route to the table */
void
rtadd(in_addr_t	dst,
    in_addr_t	mask,
    uint16_t	state,			/* rt_state for the entry */
    struct	rt_spare *new)
{
	struct rt_entry *rt;
	in_addr_t smask;
	int i;
	struct rt_spare *rts;

	/* This is the only function that increments total_routes. */
	if (total_routes == MAX_ROUTES) {
		msglog("have maximum (%d) routes", total_routes);
		return;
	}

	rt = rtmalloc(sizeof (*rt), "rtadd");
	(void) memset(rt, 0, sizeof (*rt));
	rt->rt_spares = rtmalloc(SPARE_INC  * sizeof (struct rt_spare),
	    "rtadd");
	rt->rt_num_spares = SPARE_INC;
	(void) memset(rt->rt_spares, 0, SPARE_INC  * sizeof (struct rt_spare));
	for (rts = rt->rt_spares, i = rt->rt_num_spares; i != 0; i--, rts++)
		rts->rts_metric = HOPCNT_INFINITY;

	rt->rt_nodes->rn_key = (uint8_t *)&rt->rt_dst_sock;
	rt->rt_dst = dst;
	rt->rt_dst_sock.sin_family = AF_INET;
	if (mask != HOST_MASK) {
		smask = std_mask(dst);
		if ((smask & ~mask) == 0 && mask > smask)
			state |= RS_SUBNET;
	}
	mask_sock.sin_addr.s_addr = htonl(mask);
	rt->rt_mask = mask;
	rt->rt_spares[0] = *new;
	rt->rt_state = state;
	rt->rt_time = now.tv_sec;
	rt->rt_poison_metric = HOPCNT_INFINITY;
	rt->rt_seqno = update_seqno;

	if (TRACEACTIONS)
		trace_add_del("Add", rt);

	need_kern.tv_sec = now.tv_sec;
	set_need_flash();

	if (NULL == rhead->rnh_addaddr(&rt->rt_dst_sock, &mask_sock, rhead,
	    rt->rt_nodes)) {
		msglog("rnh_addaddr() failed for %s mask=%s",
		    naddr_ntoa(dst), naddr_ntoa(htonl(mask)));
		free(rt);
	}

	total_routes++;
}


/* notice a changed route */
void
rtchange(struct rt_entry *rt,
    uint16_t	state,			/* new state bits */
    struct rt_spare *new,
    char	*label)
{
	if (rt->rt_metric != new->rts_metric) {
		/*
		 * Fix the kernel immediately if it seems the route
		 * has gone bad, since there may be a working route that
		 * aggregates this route.
		 */
		if (new->rts_metric == HOPCNT_INFINITY) {
			need_kern.tv_sec = now.tv_sec;
			if (new->rts_time >= now.tv_sec - EXPIRE_TIME)
				new->rts_time = now.tv_sec - EXPIRE_TIME;
		}
		rt->rt_seqno = update_seqno;
		set_need_flash();
	}

	if (rt->rt_gate != new->rts_gate) {
		need_kern.tv_sec = now.tv_sec;
		rt->rt_seqno = update_seqno;
		set_need_flash();
	}

	state |= (rt->rt_state & RS_SUBNET);

	/* Keep various things from deciding ageless routes are stale. */
	if (!AGE_RT(state, rt->rt_spares[0].rts_origin, new->rts_ifp))
		new->rts_time = now.tv_sec;

	if (TRACEACTIONS)
		trace_change(rt, state, new,
		    label ? label : "Chg   ");

	rt->rt_state = state;
	/*
	 * If the interface state of the new primary route is good,
	 * turn off RS_BADIF flag
	 */
	if ((rt->rt_state & RS_BADIF) &&
	    IS_IFF_UP(new->rts_ifp->int_if_flags) &&
	    !(new->rts_ifp->int_state & (IS_BROKE | IS_SICK)))
		rt->rt_state &= ~(RS_BADIF);

	rt->rt_spares[0] = *new;
}


/* check for a better route among the spares */
static struct rt_spare *
rts_better(struct rt_entry *rt)
{
	struct rt_spare *rts, *rts1;
	int i;

	/* find the best alternative among the spares */
	rts = rt->rt_spares+1;
	for (i = rt->rt_num_spares, rts1 = rts+1; i > 2; i--, rts1++) {
		if (BETTER_LINK(rt, rts1, rts))
			rts = rts1;
	}

	return (rts);
}


/* switch to a backup route */
void
rtswitch(struct rt_entry *rt,
    struct rt_spare *rts)
{
	struct rt_spare swap;
	char label[10];

	/* Do not change permanent routes */
	if (0 != (rt->rt_state & (RS_MHOME | RS_STATIC |
	    RS_NET_SYN | RS_IF)))
		return;

	/* find the best alternative among the spares */
	if (rts == NULL)
		rts = rts_better(rt);

	/* Do not bother if it is not worthwhile. */
	if (!BETTER_LINK(rt, rts, rt->rt_spares))
		return;

	swap = rt->rt_spares[0];
	(void) snprintf(label, sizeof (label), "Use #%d",
	    (int)(rts - rt->rt_spares));
	rtchange(rt, rt->rt_state & ~(RS_NET_SYN), rts, label);

	if (swap.rts_metric == HOPCNT_INFINITY) {
		*rts = rts_empty;
	} else {
		*rts = swap;
	}

}


void
rtdelete(struct rt_entry *rt)
{
	struct rt_entry *deleted_rt;
	struct rt_spare *rts;
	int i;
	in_addr_t gate = rt->rt_gate; /* for debugging */

	if (TRACEACTIONS)
		trace_add_del("Del", rt);

	for (i = 0; i < rt->rt_num_spares; i++) {
		rts = &rt->rt_spares[i];
		rts_delete(rt, rts);
	}

	dst_sock.sin_addr.s_addr = rt->rt_dst;
	mask_sock.sin_addr.s_addr = htonl(rt->rt_mask);
	if (rt != (deleted_rt =
	    ((struct rt_entry *)rhead->rnh_deladdr(&dst_sock, &mask_sock,
	    rhead)))) {
		msglog("rnh_deladdr(%s) failed; found rt 0x%lx",
		    rtname(rt->rt_dst, rt->rt_mask, gate), deleted_rt);
		if (deleted_rt != NULL)
			free(deleted_rt);
	}
	total_routes--;
	free(rt->rt_spares);
	free(rt);

	if (dst_sock.sin_addr.s_addr == RIP_DEFAULT) {
		/*
		 * we just deleted the default route. Trigger rdisc_sort
		 * so that we can recover from any rdisc information that
		 * is valid
		 */
		rdisc_timer.tv_sec = 0;
	}
}

void
rts_delete(struct rt_entry *rt, struct rt_spare *rts)
{
	struct khash *k;

	trace_upslot(rt, rts, &rts_empty);
	k = kern_find(rt->rt_dst, rt->rt_mask,
	    rts->rts_gate, rts->rts_ifp, NULL);
	if (k != NULL &&
	    !(k->k_state & KS_DEPRE_IF) &&
	    ((k->k_state & (KS_IF|KS_PASSIVE)) != KS_IF)) {
		k->k_state |= KS_DELETE;
		need_kern.tv_sec = now.tv_sec;
	}

	*rts = rts_empty;
}

/*
 * Get rid of a bad route, and try to switch to a replacement.
 * If the route has gone bad because of a bad interface,
 * the information about the dead interface is available in badifp
 * for the purpose of sanity checks, if_flags checks etc.
 */
static void
rtbad(struct rt_entry *rt, struct interface *badifp)
{
	struct rt_spare new;
	uint16_t rt_state;


	if (badifp == NULL || (rt->rt_spares[0].rts_ifp == badifp)) {
		/* Poison the route */
		new = rt->rt_spares[0];
		new.rts_metric = HOPCNT_INFINITY;
		rt_state = rt->rt_state & ~(RS_IF | RS_LOCAL | RS_STATIC);
	}

	if (badifp != NULL) {
		/*
		 * Dont mark the rtentry bad unless the ifp for the primary
		 * route is the bad ifp
		 */
		if (rt->rt_spares[0].rts_ifp != badifp)
			return;
		/*
		 * badifp has just gone bad. We want to keep this
		 * rt_entry around so that we tell our rip-neighbors
		 * about the bad route, but we can't do anything
		 * to the kernel itself, so mark it as RS_BADIF
		 */
		trace_misc("rtbad:Setting RS_BADIF (%s)", badifp->int_name);
		rt_state |= RS_BADIF;
		new.rts_ifp = &dummy_ifp;
	}
	rtchange(rt, rt_state, &new, 0);
	rtswitch(rt, 0);
}


/*
 * Junk a RS_NET_SYN or RS_LOCAL route,
 *	unless it is needed by another interface.
 */
void
rtbad_sub(struct rt_entry *rt, struct interface *badifp)
{
	struct interface *ifp, *ifp1;
	struct intnet *intnetp;
	uint_t state;


	ifp1 = NULL;
	state = 0;

	if (rt->rt_state & RS_LOCAL) {
		/*
		 * Is this the route through loopback for the interface?
		 * If so, see if it is used by any other interfaces, such
		 * as a point-to-point interface with the same local address.
		 */
		for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
			/* Retain it if another interface needs it. */
			if (ifp->int_addr == rt->rt_ifp->int_addr) {
				state |= RS_LOCAL;
				ifp1 = ifp;
				break;
			}
		}

	}

	if (!(state & RS_LOCAL)) {
		/*
		 * Retain RIPv1 logical network route if there is another
		 * interface that justifies it.
		 */
		if (rt->rt_state & RS_NET_SYN) {
			for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
				if ((ifp->int_state & IS_NEED_NET_SYN) &&
				    rt->rt_mask == ifp->int_std_mask &&
				    rt->rt_dst == ifp->int_std_addr) {
					state |= RS_NET_SYN;
					ifp1 = ifp;
					break;
				}
			}
		}

		/* or if there is an authority route that needs it. */
		for (intnetp = intnets; intnetp != NULL;
		    intnetp = intnetp->intnet_next) {
			if (intnetp->intnet_addr == rt->rt_dst &&
			    intnetp->intnet_mask == rt->rt_mask) {
				state |= (RS_NET_SYN | RS_NET_INT);
				break;
			}
		}
	}

	if (ifp1 != NULL || (state & RS_NET_SYN)) {
		struct rt_spare new = rt->rt_spares[0];
		new.rts_ifp = ifp1;
		rtchange(rt, ((rt->rt_state & ~(RS_NET_SYN|RS_LOCAL)) | state),
		    &new, 0);
	} else {
		rtbad(rt, badifp);
	}
}

/*
 * Called while walking the table looking for sick interfaces
 * or after a time change.
 */
int
walk_bad(struct radix_node *rn,
    void *argp)
{
#define	RT ((struct rt_entry *)rn)
	struct rt_spare *rts;
	int i, j = -1;

	/* fix any spare routes through the interface */
	for (i = 1; i < RT->rt_num_spares; i++) {
		rts = &((struct rt_entry *)rn)->rt_spares[i];

		if (rts->rts_metric < HOPCNT_INFINITY &&
		    (rts->rts_ifp == NULL ||
		    (rts->rts_ifp->int_state & IS_BROKE)))
			rts_delete(RT, rts);
		else {
			if (rts->rts_origin != RO_NONE)
				j = i;
		}
	}

	/*
	 * Deal with the main route
	 * finished if it has been handled before or if its interface is ok
	 */
	if (RT->rt_ifp == NULL || !(RT->rt_ifp->int_state & IS_BROKE))
		return (0);

	/* Bad routes for other than interfaces are easy. */
	if (!(RT->rt_state & (RS_IF | RS_NET_SYN | RS_LOCAL))) {
		if (j > 0) {
			RT->rt_spares[0].rts_metric = HOPCNT_INFINITY;
			rtswitch(RT, NULL);
		} else {
			rtbad(RT, (struct interface *)argp);
		}
		return (0);
	}

	rtbad_sub(RT, (struct interface *)argp);
	return (0);
#undef RT
}

/*
 * Called while walking the table to replace a duplicate interface
 * with a backup.
 */
int
walk_rewire(struct radix_node *rn, void *argp)
{
	struct rt_entry *RT = (struct rt_entry *)rn;
	struct rewire_data *wire = (struct rewire_data *)argp;
	struct rt_spare *rts;
	int i;

	/* fix any spare routes through the interface */
	rts = RT->rt_spares;
	for (i = RT->rt_num_spares; i > 0; i--, rts++) {
		if (rts->rts_ifp == wire->if_old) {
			rts->rts_ifp = wire->if_new;
			if ((RT->rt_dst == RIP_DEFAULT) &&
			    (wire->if_old->int_state & IS_SUPPRESS_RDISC))
				rdisc_suppress(rts->rts_ifp);
			if ((rts->rts_metric += wire->metric_delta) >
			    HOPCNT_INFINITY)
				rts->rts_metric = HOPCNT_INFINITY;

			/*
			 * If the main route is getting a worse metric,
			 * then it may be time to switch to a backup.
			 */
			if (i == RT->rt_num_spares && wire->metric_delta > 0) {
				rtswitch(RT, NULL);
			}
		}
	}

	return (0);
}

/* Check the age of an individual route. */
static int
walk_age(struct radix_node *rn, void *argp)
{
#define	RT ((struct rt_entry *)rn)
	struct interface *ifp;
	struct rt_spare *rts;
	int i;
	in_addr_t age_bad_gate = *(in_addr_t *)argp;


	/*
	 * age all of the spare routes, including the primary route
	 * currently in use
	 */
	rts = RT->rt_spares;
	for (i = RT->rt_num_spares; i != 0; i--, rts++) {

		ifp = rts->rts_ifp;
		if (i == RT->rt_num_spares) {
			if (!AGE_RT(RT->rt_state, rts->rts_origin, ifp)) {
				/*
				 * Keep various things from deciding ageless
				 * routes are stale
				 */
				rts->rts_time = now.tv_sec;
				continue;
			}

			/* forget RIP routes after RIP has been turned off. */
			if (rip_sock < 0) {
				rts->rts_time = now_stale + 1;
			}
		}

		/* age failing routes */
		if (age_bad_gate == rts->rts_gate &&
		    rts->rts_time >= now_stale) {
			rts->rts_time -= SUPPLY_INTERVAL;
		}

		/* trash the spare routes when they go bad */
		if (rts->rts_origin == RO_RIP &&
		    ((rip_sock < 0) ||
		    (rts->rts_metric < HOPCNT_INFINITY &&
		    now_garbage > rts->rts_time)) &&
		    i != RT->rt_num_spares) {
			rts_delete(RT, rts);
		}
	}


	/* finished if the active route is still fresh */
	if (now_stale <= RT->rt_time)
		return (0);

	/* try to switch to an alternative */
	rtswitch(RT, NULL);

	/* Delete a dead route after it has been publically mourned. */
	if (now_garbage > RT->rt_time) {
		rtdelete(RT);
		return (0);
	}

	/* Start poisoning a bad route before deleting it. */
	if (now.tv_sec - RT->rt_time > EXPIRE_TIME) {
		struct rt_spare new = RT->rt_spares[0];

		new.rts_metric = HOPCNT_INFINITY;
		rtchange(RT, RT->rt_state, &new, 0);
	}
	return (0);
}


/* Watch for dead routes and interfaces. */
void
age(in_addr_t bad_gate)
{
	struct interface *ifp;
	int need_query = 0;

	/*
	 * If not listening to RIP, there is no need to age the routes in
	 * the table.
	 */
	age_timer.tv_sec = (now.tv_sec
	    + ((rip_sock < 0) ? NEVER : SUPPLY_INTERVAL));

	/*
	 * Check for dead IS_REMOTE interfaces by timing their
	 * transmissions.
	 */
	for (ifp = ifnet; ifp; ifp = ifp->int_next) {
		if (!(ifp->int_state & IS_REMOTE))
			continue;

		/* ignore unreachable remote interfaces */
		if (!check_remote(ifp))
			continue;

		/* Restore remote interface that has become reachable */
		if (ifp->int_state & IS_BROKE)
			if_ok(ifp, "remote ", _B_FALSE);

		if (ifp->int_act_time != NEVER &&
		    now.tv_sec - ifp->int_act_time > EXPIRE_TIME) {
			writelog(LOG_NOTICE,
			    "remote interface %s to %s timed out after"
			    " %ld:%ld",
			    ifp->int_name,
			    naddr_ntoa(ifp->int_dstaddr),
			    (now.tv_sec - ifp->int_act_time)/60,
			    (now.tv_sec - ifp->int_act_time)%60);
			if_sick(ifp, _B_FALSE);
		}

		/*
		 * If we have not heard from the other router
		 * recently, ask it.
		 */
		if (now.tv_sec >= ifp->int_query_time) {
			ifp->int_query_time = NEVER;
			need_query = 1;
		}
	}

	/* Age routes. */
	(void) rn_walktree(rhead, walk_age, &bad_gate);

	/*
	 * delete old redirected routes to keep the kernel table small
	 * and prevent blackholes
	 */
	del_redirects(bad_gate, now.tv_sec-STALE_TIME);

	/* Update the kernel routing table. */
	fix_kern();

	/* poke reticent remote gateways */
	if (need_query)
		rip_query();
}

void
kern_dump(void)
{
	int i;
	struct khash *k;

	for (i = 0; i < KHASH_SIZE; i++) {
		for (k = khash_bins[i]; k != NULL; k = k->k_next)
			trace_khash(k);
	}
}


static struct interface *
gwkludge_iflookup(in_addr_t dstaddr, in_addr_t addr, in_addr_t mask)
{
	uint32_t int_state;
	struct interface *ifp;

	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		int_state = ifp->int_state;

		if (!(int_state & IS_REMOTE))
			continue;

		if (ifp->int_dstaddr == dstaddr && ifp->int_addr == addr &&
		    ifp->int_mask == mask)
			return (ifp);
	}
	return (NULL);
}

/*
 * Lookup logical interface structure given the gateway address.
 * Returns null if no interfaces match the given name.
 */
static struct interface *
lifp_iflookup(in_addr_t addr, const char *name)
{
	struct physical_interface *phyi;
	struct interface *ifp;
	struct interface *best = NULL;

	if ((phyi = phys_byname(name)) == NULL)
		return (NULL);

	for (ifp = phyi->phyi_interface; ifp != NULL;
	    ifp = ifp->int_ilist.hl_next) {

#ifdef DEBUG_KERNEL_ROUTE_READ
		(void) fprintf(stderr, " checking interface"
		    " %-4s %-4s %-15s-->%-15s \n",
		    phyi->phyi_name, ifp->int_name,
		    naddr_ntoa(ifp->int_addr),
		    addrname(((ifp->int_if_flags & IFF_POINTOPOINT) ?
		    ifp->int_dstaddr : htonl(ifp->int_net)),
		    ifp->int_mask, 1));
#endif
		/* Exact match found */
		if (addr_on_ifp(addr, ifp, &best))
			return (ifp);
	}
	/* No exact match found but return any best match found */
	return (best);
}
