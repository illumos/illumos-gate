/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1995
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
 * $FreeBSD: src/sbin/routed/rdisc.c,v 1.8 2000/08/11 08:24:38 sheldonh Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <strings.h>

/*
 * The size of the control buffer passed to recvmsg() used to receive
 * ancillary data.
 */
#define	CONTROL_BUFSIZE	1024

/* router advertisement ICMP packet */
struct icmp_ad {
	uint8_t    icmp_type;		/* type of message */
	uint8_t    icmp_code;		/* type sub code */
	uint16_t   icmp_cksum;		/* ones complement cksum of struct */
	uint8_t    icmp_ad_num;	/* # of following router addresses */
	uint8_t    icmp_ad_asize;	/* 2--words in each advertisement */
	uint16_t   icmp_ad_life;	/* seconds of validity */
	struct icmp_ad_info {
	    in_addr_t  icmp_ad_addr;
	    uint32_t  icmp_ad_pref;
	} icmp_ad_info[1];
};

/* router solicitation ICMP packet */
struct icmp_so {
	uint8_t    icmp_type;		/* type of message */
	uint8_t    icmp_code;		/* type sub code */
	uint16_t   icmp_cksum;		/* ones complement cksum of struct */
	uint32_t   icmp_so_rsvd;
};

union ad_u {
	struct icmp icmp;
	struct icmp_ad ad;
	struct icmp_so so;
};


int	rdisc_sock = -1;		/* router-discovery raw socket */
int	rdisc_mib_sock = -1;		/* AF_UNIX mib info socket */
static struct interface *rdisc_sock_interface; /* current rdisc interface */

struct timeval rdisc_timer;
boolean_t rdisc_ok;				/* using solicited route */

#define	MAX_ADS		16
int max_ads; /* at least one per interface */
/* accumulated advertisements */
static struct dr *cur_drp;
struct dr *drs;

/*
 * adjust unsigned preference by interface metric,
 * without driving it to infinity
 */
#define	PREF(p, ifp) ((p) <= (uint32_t)(ifp)->int_metric ? ((p) != 0 ? 1 : 0) \
	: (p) - ((ifp)->int_metric))

static void rdisc_sort(void);

typedef enum { unicast, bcast, mcast } dstaddr_t;

/* dump an ICMP Router Discovery Advertisement Message */
static void
trace_rdisc(const char	*act,
    uint32_t from,
    uint32_t to,
    struct interface *ifp,
    union ad_u	*p,
    uint_t len)
{
	int i;
	n_long *wp, *lim;


	if (!TRACEPACKETS || ftrace == 0)
		return;

	lastlog();

	if (p->icmp.icmp_type == ICMP_ROUTERADVERT) {
		(void) fprintf(ftrace, "%s Router Ad"
		    " from %s to %s via %s life=%d\n",
		    act, naddr_ntoa(from), naddr_ntoa(to),
		    ifp ? ifp->int_name : "?",
		    ntohs(p->ad.icmp_ad_life));
		if (!TRACECONTENTS)
			return;

		wp = &p->ad.icmp_ad_info[0].icmp_ad_addr;
		lim = &wp[(len - sizeof (p->ad)) / sizeof (*wp)];
		for (i = 0; i < p->ad.icmp_ad_num && wp <= lim; i++) {
			(void) fprintf(ftrace, "\t%s preference=%ld",
			    naddr_ntoa(wp[0]), (long)ntohl(wp[1]));
			wp += p->ad.icmp_ad_asize;
		}
		(void) fputc('\n', ftrace);

	} else {
		trace_act("%s Router Solic. from %s to %s via %s rsvd=%#x",
		    act, naddr_ntoa(from), naddr_ntoa(to),
		    ifp ? ifp->int_name : "?",
		    ntohl(p->so.icmp_so_rsvd));
	}
}

/*
 * Prepare Router Discovery socket.
 */
static void
get_rdisc_sock(void)
{
	int on = 1;
	unsigned char ttl = 1;
	struct sockaddr_un laddr;
	int len;

	if (rdisc_sock < 0) {
		max_ads = MAX_ADS;
		drs = rtmalloc(max_ads * sizeof (struct dr), "get_rdisc_sock");
		(void) memset(drs, 0, max_ads * sizeof (struct dr));
		rdisc_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (rdisc_sock < 0)
			BADERR(_B_TRUE, "rdisc_sock = socket()");
		fix_sock(rdisc_sock, "rdisc_sock");

		if (setsockopt(rdisc_sock, IPPROTO_IP, IP_RECVIF, &on,
		    sizeof (on)))
			BADERR(_B_FALSE, "setsockopt(IP_RECVIF)");

		if (setsockopt(rdisc_sock, IPPROTO_IP, IP_MULTICAST_TTL,
		    &ttl, sizeof (ttl)) < 0)
			DBGERR(_B_TRUE,
			    "rdisc_sock setsockopt(IP_MULTICAST_TTL)");

		/*
		 * On Solaris also open an AF_UNIX socket to
		 * pass default router information to mib agent
		 */

		rdisc_mib_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (rdisc_mib_sock < 0) {
			BADERR(_B_TRUE, "rdisc_mib_sock = socket()");
		}

		bzero(&laddr, sizeof (laddr));
		laddr.sun_family = AF_UNIX;

		(void) strncpy(laddr.sun_path, RDISC_SNMP_SOCKET,
		    sizeof (laddr.sun_path));
		len = sizeof (struct sockaddr_un);

		(void) unlink(RDISC_SNMP_SOCKET);

		if (bind(rdisc_mib_sock, (struct sockaddr *)&laddr, len) < 0) {
			BADERR(_B_TRUE, "bind(rdisc_mib_sock)");
		}

		if (fcntl(rdisc_mib_sock, F_SETFL, O_NONBLOCK) < 0) {
			BADERR(_B_TRUE, "rdisc_mib_sock fcntl O_NONBLOCK");
		}

		fix_select();
	}
}


/*
 * Pick multicast group for router-discovery socket
 */
void
set_rdisc_mg(struct interface *ifp,
    int on)	/* 0=turn it off */
{
	struct ip_mreq m;
	boolean_t dosupply;

	if (rdisc_sock < 0) {
		/*
		 * Create the raw socket so that we can hear at least
		 * broadcast router discovery packets.
		 */
		if ((ifp->int_state & IS_NO_RDISC) == IS_NO_RDISC ||
		    !on)
			return;
		get_rdisc_sock();
	}

	if (!(ifp->int_if_flags & IFF_MULTICAST)) {
		/* Can't multicast, so no groups could have been joined. */
		ifp->int_state &= ~(IS_ALL_HOSTS | IS_ALL_ROUTERS);
		return;
	}

	dosupply = should_supply(ifp);

	(void) memset(&m, 0, sizeof (m));
	m.imr_interface.s_addr = ((ifp->int_if_flags & IFF_POINTOPOINT) &&
	    (ifp->int_dstaddr != 0) ? ifp->int_dstaddr : ifp->int_addr);
	if (dosupply || (ifp->int_state & IS_NO_ADV_IN) || !on) {
		/* stop listening to advertisements */
		if (ifp->int_state & IS_ALL_HOSTS) {
			m.imr_multiaddr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
			if (setsockopt(rdisc_sock, IPPROTO_IP,
			    IP_DROP_MEMBERSHIP, &m, sizeof (m)) < 0 &&
			    errno != EADDRNOTAVAIL && errno != ENOENT)
				LOGERR("IP_DROP_MEMBERSHIP ALLHOSTS");
			ifp->int_state &= ~IS_ALL_HOSTS;
		}

	} else if (!(ifp->int_state & IS_ALL_HOSTS)) {
		/* start listening to advertisements */
		m.imr_multiaddr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		if (setsockopt(rdisc_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    &m, sizeof (m)) < 0) {
			LOGERR("IP_ADD_MEMBERSHIP ALLHOSTS");
		} else {
			ifp->int_state |= IS_ALL_HOSTS;
		}
	}

	if (!dosupply || (ifp->int_state & IS_NO_ADV_OUT) ||
	    !IS_IFF_ROUTING(ifp->int_if_flags) || !on) {
		/* stop listening to solicitations */
		if (ifp->int_state & IS_ALL_ROUTERS) {
			m.imr_multiaddr.s_addr = htonl(INADDR_ALLRTRS_GROUP);
			if (setsockopt(rdisc_sock, IPPROTO_IP,
			    IP_DROP_MEMBERSHIP, &m, sizeof (m)) < 0 &&
			    errno != EADDRNOTAVAIL && errno != ENOENT)
				LOGERR("IP_DROP_MEMBERSHIP ALLROUTERS");
			ifp->int_state &= ~IS_ALL_ROUTERS;
		}

	} else if (!(ifp->int_state & IS_ALL_ROUTERS)) {
		/* start hearing solicitations */
		m.imr_multiaddr.s_addr = htonl(INADDR_ALLRTRS_GROUP);
		if (setsockopt(rdisc_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    &m, sizeof (m)) < 0) {
			LOGERR("IP_ADD_MEMBERSHIP ALLROUTERS");
		} else {
			ifp->int_state |= IS_ALL_ROUTERS;
		}
	}
}


/*
 * start or stop supplying routes to other systems.
 */
void
set_supplier(void)
{
	struct interface *ifp;
	struct dr *drp;
	static boolean_t supplystate = _B_FALSE;

	if (supplystate == (fwd_interfaces > 1))
		return;
	supplystate = fwd_interfaces > 1;

	trace_act("%d forwarding interfaces present; becoming %ssupplier",
	    fwd_interfaces, supplystate ? "" : "non-");

	if (supplystate) {
		/* Forget discovered routes. */
		for (drp = drs; drp < &drs[max_ads]; drp++) {
			drp->dr_recv_pref = DEF_PREFERENCELEVEL;
			drp->dr_life = 0;
		}
		rdisc_age(0);

		/*
		 * Do not start advertising until we have heard some
		 * RIP routes.
		 */
		LIM_SEC(rdisc_timer, now.tv_sec+MIN_WAITTIME);

		/* get rid of any redirects */
		del_redirects(0, 0);
	} else {
		/*
		 * Flush out all those advertisements we had sent by sending
		 * one with lifetime=0.
		 */
		rdisc_adv(_B_TRUE);
	}

	/*
	 * Switch router discovery multicast groups from soliciting
	 * to advertising or back.
	 */
	for (ifp = ifnet; ifp; ifp = ifp->int_next) {
		if (ifp->int_state & IS_BROKE)
			continue;
		ifp->int_rdisc_cnt = 0;
		ifp->int_rdisc_timer.tv_usec = rdisc_timer.tv_usec;
		ifp->int_rdisc_timer.tv_sec = now.tv_sec+MIN_WAITTIME;
		set_rdisc_mg(ifp, 1);
	}
}


/*
 * Age discovered routes and find the best one
 */
void
rdisc_age(in_addr_t bad_gate)
{
	time_t sec;
	struct dr *drp;
	struct rt_spare new;
	struct rt_entry *rt;

	/*
	 * If we are being told about a bad router,
	 * then age the discovered default route, and if there is
	 * no alternative, solicit a replacement.
	 */
	if (bad_gate != 0) {
		/*
		 * Look for the bad discovered default route.
		 * Age it and note its interface.
		 */
		for (drp = drs; drp < &drs[max_ads]; drp++) {
			if (drp->dr_ts == 0)
				continue;

			/*
			 * When we find the bad router, age the route
			 * to at most SUPPLY_INTERVAL.
			 * This is contrary to RFC 1256, but defends against
			 * black holes.
			 */
			if (drp->dr_gate == bad_gate) {
				sec = (now.tv_sec - drp->dr_life +
				    SUPPLY_INTERVAL);
				if (drp->dr_ts > sec) {
					trace_act("age 0.0.0.0 --> %s via %s",
					    naddr_ntoa(drp->dr_gate),
					    drp->dr_ifp->int_name);
					drp->dr_ts = sec;
				}
				break;
			}
		}
	} else if (should_supply(NULL)) {
		/*
		 * If switching from client to server, get rid of old
		 * default routes.
		 */
		if (cur_drp != NULL) {
			rt = rtget(RIP_DEFAULT, 0);
			/*
			 * If there is a current default router, and the
			 * there is no rt_spare entry, create one
			 * for cur_drp to prevent segmentation fault
			 * at rdisc_sort.
			 */
			if (rt == NULL) {
				(void) memset(&new, 0, sizeof (new));
				new.rts_ifp = cur_drp->dr_ifp;
				new.rts_gate = cur_drp->dr_gate;
				new.rts_router = cur_drp->dr_gate;
				new.rts_metric = HOPCNT_INFINITY-1;
				new.rts_time = now.tv_sec;
				new.rts_origin = RO_RDISC;
				rtadd(RIP_DEFAULT, 0, RS_NOPROPAGATE, &new);
			}

			rdisc_sort();
		}
		rdisc_adv(_B_FALSE);
	}

	rdisc_sol();
	if (cur_drp != NULL) {
		rt = rtget(RIP_DEFAULT, 0);
		if (rt == NULL) {
			(void) memset(&new, 0, sizeof (new));
			new.rts_ifp = cur_drp->dr_ifp;
			new.rts_gate = cur_drp->dr_gate;
			new.rts_router = cur_drp->dr_gate;
			new.rts_metric = HOPCNT_INFINITY-1;
			new.rts_time = now.tv_sec;
			new.rts_origin = RO_RDISC;
			rtadd(RIP_DEFAULT, 0, RS_NOPROPAGATE, &new);
		}
	}
	rdisc_sort();

	/*
	 * Delete old redirected routes to keep the kernel table small,
	 * and to prevent black holes.  Check that the kernel table
	 * matches the daemon table (i.e. has the default route).
	 * But only if RIP is not running and we are not dealing with
	 * a bad gateway, since otherwise age() will be called.
	 */
	if (rip_sock < 0 && bad_gate == 0)
		age(0);
}


/*
 * Zap all routes discovered via an interface that has gone bad
 * This should only be called when !(ifp->int_state & IS_DUP)
 * This is called by if_del and if_bad, and the interface pointer
 * might not be valid after this.
 */
void
if_bad_rdisc(struct interface *ifp)
{
	struct dr *drp;

	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ifp != ifp)
			continue;
		(void) memset(drp, 0, sizeof (*drp));
	}

	/* make a note to re-solicit, turn RIP on or off, etc. */
	rdisc_timer.tv_sec = 0;
}

/*
 * Rewire all routes discovered via an interface that has gone bad
 * This is only called by if_del.
 */
void
if_rewire_rdisc(struct interface *oldifp, struct interface *newifp)
{
	struct dr *drp;

	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ifp != oldifp)
			continue;
		drp->dr_ifp = newifp;
		drp->dr_pref += (newifp->int_metric - oldifp->int_metric);
		drp->dr_flags |= DR_CHANGED;
	}

	/* make a note to re-solicit, turn RIP on or off, etc. */
	rdisc_timer.tv_sec = 0;
}

/*
 * Mark an interface ok for router discovering.
 * This is called by if_ok and ifinit.
 */
void
if_ok_rdisc(struct interface *ifp)
{
	set_rdisc_mg(ifp, 1);

	ifp->int_rdisc_cnt = 0;
	ifp->int_rdisc_timer.tv_sec = now.tv_sec +
	    ((ifp->int_state & IS_NO_ADV_OUT) ?
	    MAX_SOLICITATION_DELAY : MIN_WAITTIME);
	if (timercmp(&rdisc_timer, &ifp->int_rdisc_timer, > /* cstyle */))
		rdisc_timer = ifp->int_rdisc_timer;
}

/*
 * Get rid of a dead discovered router
 */
static void
del_rdisc(struct dr *drp)
{
	struct interface *ifp;
	uint32_t gate;
	int i;
	struct rt_entry *rt;
	struct rt_spare *rts = NULL;

	del_redirects(gate = drp->dr_gate, 0);
	drp->dr_ts = 0;
	drp->dr_life = 0;

	rt = rtget(RIP_DEFAULT, 0);
	if (rt == NULL) {
		trace_act("could not find default route in table");
	} else {
		for (i = 0; i < rt->rt_num_spares; i++) {
			if ((rt->rt_spares[i].rts_gate == drp->dr_gate) &&
			    (rt->rt_spares[i].rts_origin == RO_RDISC)) {
				rts = &rt->rt_spares[i];
				break;
			}
		}
		if (rts != NULL)
			rts_delete(rt, rts);
		else
			trace_act("could not find default route "
			    "through %s in table", naddr_ntoa(drp->dr_gate));
	}

	/* Count the other discovered routers on the interface.  */
	i = 0;
	ifp = drp->dr_ifp;
	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ts != 0 && drp->dr_ifp == ifp)
			i++;
	}

	/*
	 * If that was the last good discovered router on the interface,
	 * then solicit a new one.
	 * This is contrary to RFC 1256, but defends against black holes.
	 */
	if (i != 0) {
		trace_act("discovered router %s via %s"
		    " is bad--have %d remaining",
		    naddr_ntoa(gate), ifp->int_name, i);
	} else if (ifp->int_rdisc_cnt >= MAX_SOLICITATIONS) {
		trace_act("last discovered router %s via %s"
		    " is bad--re-solicit",
		    naddr_ntoa(gate), ifp->int_name);
		ifp->int_rdisc_cnt = 0;
		ifp->int_rdisc_timer.tv_sec = 0;
		rdisc_sol();
	} else {
		trace_act("last discovered router %s via %s"
		    " is bad--wait to solicit",
		    naddr_ntoa(gate), ifp->int_name);
	}
}


/* Find the best discovered route, and discard stale routers. */
static void
rdisc_sort(void)
{
	struct dr *drp, *new_drp;
	struct rt_entry *rt;
	struct rt_spare new, *rts;
	struct interface *ifp;
	uint_t new_st = 0;
	uint32_t new_pref = DEF_PREFERENCELEVEL;
	int first_rdisc_slot = 0;
	int j;
	boolean_t spares_avail;
	void *ptr;
	size_t ptrsize;

	rt = rtget(RIP_DEFAULT, 0);

	/*
	 * If all the rt_spare entries are taken up with with default routes
	 * learnt from RIP (ie rts_origin = RO_RIP), bail out.
	 * NOTE:
	 *	We *always* prefer default routes learned via RIP
	 *	(ie RO_RIP) over those learnt via RDISC (ie RO_RDISC).
	 *	The rdisc machinery should not modify, replace or
	 *	remove any existing default routes with RO_RIP set.
	 */
	if (rt != NULL) {
		spares_avail = _B_FALSE;
		for (j = 0; j < rt->rt_num_spares; j++)  {
			rts = &rt->rt_spares[j];
			if (rts->rts_gate == 0 || rts->rts_origin != RO_RIP ||
			    rts->rts_ifp == &dummy_ifp) {
				spares_avail = _B_TRUE;
				break;
			}
		}
		if (!spares_avail) {
			ptrsize = (rt->rt_num_spares + SPARE_INC) *
			    sizeof (struct rt_spare);
			ptr = realloc(rt->rt_spares, ptrsize);
			if (ptr != NULL) {
				struct rt_spare *tmprts;

				rt->rt_spares = ptr;
				rts = &rt->rt_spares[rt->rt_num_spares];
				(void) memset(rts, 0,
				    (SPARE_INC * sizeof (struct rt_spare)));
				rt->rt_num_spares += SPARE_INC;
				for (tmprts = rts, j = SPARE_INC;
				    j != 0; j--, tmprts++)
					tmprts->rts_metric = HOPCNT_INFINITY;
				spares_avail = _B_TRUE;
			} else {
				return;
			}
		}
	}
	/* Find the best RDISC advertiser */
	rt = NULL;
	new_drp = NULL;
	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ts == 0)
			continue;
		ifp = drp->dr_ifp;

		/* Get rid of expired discovered routers. */
		if (drp->dr_ts + drp->dr_life <= now.tv_sec) {
			del_rdisc(drp);
			continue;
		}

		LIM_SEC(rdisc_timer, drp->dr_ts+drp->dr_life);

		/*
		 * Update preference with possibly changed interface
		 * metric.
		 */
		drp->dr_pref = PREF(drp->dr_recv_pref, ifp);

		/*
		 * Prefer the current route to prevent thrashing.
		 * Prefer shorter lifetimes to speed the detection of
		 * bad routers.
		 * Avoid sick interfaces.
		 */
		if (new_drp == NULL ||
		    (!((new_st ^ drp->dr_ifp->int_state) & IS_SICK) &&
		    (new_pref < drp->dr_pref ||
		    (new_pref == drp->dr_pref && (drp == cur_drp ||
		    (new_drp != cur_drp &&
		    new_drp->dr_life > drp->dr_life))))) ||
		    ((new_st & IS_SICK) &&
		    !(drp->dr_ifp->int_state & IS_SICK))) {
			new_drp = drp;
			new_st = drp->dr_ifp->int_state;
			new_pref = drp->dr_pref;
		}
	}

	/*
	 * switch to a better RDISC advertiser
	 */
	if ((new_drp != cur_drp) || (rt == NULL))  {
		rt = rtget(RIP_DEFAULT, 0);

		/*
		 * Purge the table of all the default routes that were
		 * learnt via RDISC, while keeping an eye the first available
		 * slot for the spare entry of new_drp
		 */
		if (rt != NULL) {
			int i;
			for (i = 0; i < rt->rt_num_spares; i++)  {
				rts = &rt->rt_spares[i];
				if ((rts->rts_gate == 0 ||
				    rts->rts_ifp == &dummy_ifp) &&
				    first_rdisc_slot == 0)
					first_rdisc_slot = i;
				if (rts->rts_origin == RO_RDISC) {
					rts_delete(rt, rts);
					if (first_rdisc_slot == 0) {
						first_rdisc_slot = i;
					}
				}
			}
		}

		/* Stop using RDISC routes if they are all bad */
		if (new_drp == NULL) {
			trace_act("turn off Router Discovery client");
			rdisc_ok = _B_FALSE;

		} else {
			if (cur_drp == NULL) {
				trace_act("turn on Router Discovery client"
				    " using %s via %s",
				    naddr_ntoa(new_drp->dr_gate),
				    new_drp->dr_ifp->int_name);
				rdisc_ok = _B_TRUE;
			}

			/* Prepare a spare entry for the new_drp */
			(void) memset(&new, 0, sizeof (new));
			new.rts_ifp = new_drp->dr_ifp;
			new.rts_gate = new_drp->dr_gate;
			new.rts_router = new_drp->dr_gate;
			new.rts_metric = HOPCNT_INFINITY-1;
			new.rts_time = now.tv_sec;
			new.rts_origin = RO_RDISC;
			/*
			 * If there is no existing default route, add it
			 * to rts_spare[0].
			 */
			if (rt == NULL) {
				rtadd(RIP_DEFAULT, 0, RS_NOPROPAGATE, &new);
			} else {

				/*
				 * Add the spare entry for the new_drp in
				 * the first available slot
				 */
				trace_act("Switching to "
				    "default router with better "
				    "preference %s via %s ",
				    naddr_ntoa(new_drp->dr_gate),
				    new_drp->dr_ifp->int_name);
				rt->rt_spares[first_rdisc_slot] = new;
				rt = NULL; /* redo rt_spares */
			}
		}

		/*
		 * Get ready to redo the entire table. The table should
		 * only include :
		 * 	a. empty rt_spare slots
		 * 	b. default routes learnt via RIP
		 * 	c. default route for the latest best RDISC advertiser
		 * 	d. default routes of other RDISC advertisers whose
		 *	dr_pref == best RDISC advertiser->dr_pref
		 */
		cur_drp = new_drp;
	}

	/* Redo the entire spare table (without touching RO_RIP entries) */
	if (rdisc_ok && rt == NULL) {
		int i;
		/*
		 * We've either just turned on router discovery,
		 * or switched to a router with better preference.
		 * Find all other default routers whose
		 * pref == cur_drp->dr_pref and add them as spares
		 */

		rt = rtget(RIP_DEFAULT, 0);

		for (drp = drs; drp < &drs[max_ads]; drp++) {
			boolean_t dr_done = _B_FALSE;
			int slot = -1;

			if (drp->dr_ts == 0)
				continue;

			if (drp->dr_pref != cur_drp->dr_pref &&
			    ((drp->dr_flags & DR_CHANGED) == 0))
				continue;

			/*
			 * Either pref matches cur_drp->dr_pref,
			 * or something has changed in this drp.
			 * In the former case, we may need to add
			 * this to rt_spares. In the latter case,
			 * if the pref has changed, need to take it
			 * out of rt_spares and the kernel.
			 *
			 * First, find an empty slot in rt_spares
			 * in case we have to add this drp to kernel.
			 * Also check if it is already there.
			 */
			for (i = 0; i < rt->rt_num_spares; i++) {
				if (rt->rt_spares[i].rts_gate == 0) {
					if (slot < 0)
						slot = i;
					continue;
				}
				if ((rt->rt_spares[i].rts_gate ==
				    drp->dr_gate) &&
				    (rt->rt_spares[i].rts_origin ==
				    RO_RDISC)) {
					/*
					 * a spare entry for this RDISC
					 * advertiser already exists. We need
					 * to check if this entry still belongs
					 * in the table
					 */
					dr_done = _B_TRUE;
					break;
				}
			}

			drp->dr_flags &= ~DR_CHANGED;

			if (drp->dr_pref != cur_drp->dr_pref) {
				if (dr_done) {
					/*
					 * The rt_spare of this RDISC advertiser
					 * needs to be removed as it no longer
					 * belongs in the table because its
					 * dr_pref is different than the latest
					 * RDISC advertiser's->dr_pref
					 */
					rts_delete(rt, &rt->rt_spares[i]);
				}
				continue;
			}

			if (slot < 0 && !dr_done)  {
				ptrsize = (rt->rt_num_spares + SPARE_INC) *
				    sizeof (struct rt_spare);
				ptr = realloc(rt->rt_spares, ptrsize);
				if (ptr != NULL) {
					struct rt_spare *tmprts;

					rt->rt_spares = ptr;
					slot = rt->rt_num_spares;
					rts = &rt->rt_spares[rt->rt_num_spares];
					(void) memset(rts, 0, (SPARE_INC *
					    sizeof (struct rt_spare)));
					rt->rt_num_spares += SPARE_INC;
					for (tmprts = rts, i = SPARE_INC;
					    i != 0; i--, tmprts++)
						tmprts->rts_metric =
						    HOPCNT_INFINITY;
				}
			}

			if (slot >= 0 && (dr_done != _B_TRUE)) {
				(void) memset(&new, 0, sizeof (new));
				new.rts_ifp = drp->dr_ifp;
				new.rts_gate = drp->dr_gate;
				new.rts_router = drp->dr_gate;
				new.rts_metric = HOPCNT_INFINITY-1;
				new.rts_time = now.tv_sec;
				new.rts_origin = RO_RDISC;
				rt->rt_spares[slot] = new;
				trace_act("spare default %s via %s",
				    naddr_ntoa(drp->dr_gate),
				    drp->dr_ifp->int_name);
			}
		}
	}

	/* turn RIP on or off */
	if (!rdisc_ok || rip_interfaces > 1) {
		rip_on(0);
	} else {
		rip_off();
	}
}


/* Handle a single address in an advertisement */
static void
parse_ad(uint32_t from,
    in_addr_t gate,
    uint32_t pref,		/* signed and in network order */
    ushort_t life,		/* in host byte order */
    struct interface *ifp)
{
	static struct msg_limit bad_gate;
	struct dr *drp, *new_drp;
	void *ptr;
	size_t ptrsize;

	if (gate == RIP_DEFAULT || !check_dst(gate)) {
		msglim(&bad_gate, from, "router %s advertising bad gateway %s",
		    naddr_ntoa(from), naddr_ntoa(gate));
		return;
	}

	/*
	 * ignore pointers to ourself and routes via unreachable networks
	 */
	if (ifwithaddr(gate, _B_TRUE, _B_FALSE) != 0) {
		trace_pkt("    discard Router Discovery Ad pointing at us");
		return;
	}
	if (!on_net(gate, ifp->int_net, ifp->int_mask)) {
		trace_pkt("    discard Router Discovery Ad"
		    " toward unreachable net");
		return;
	}
	/*
	 * Convert preference to an unsigned value
	 * and later bias it by the metric of the interface.
	 */
	pref = UNSIGN_PREF(ntohl(pref));

	if (pref == DEF_PREFERENCELEVEL || life < MIN_MAXADVERTISEINTERVAL) {
		pref = DEF_PREFERENCELEVEL;
		life = 0;
	}

	for (new_drp = NULL, drp = drs; drp < &drs[max_ads]; drp++) {
		/* accept new info for a familiar entry */
		if ((drp->dr_gate == gate) && (drp->dr_ifp == ifp)) {
			new_drp = drp;
			drp->dr_flags |= DR_CHANGED;
			break;
		}

		if (life == 0)
			continue;	/* do not worry about dead ads */

		if (drp->dr_ts == 0) {
			new_drp = drp;	/* use unused entry */

		} else if (new_drp == NULL) {
			/* look for an entry worse than the new one to reuse. */
			if ((!(ifp->int_state & IS_SICK) &&
			    (drp->dr_ifp->int_state & IS_SICK)) ||
			    (pref > drp->dr_pref &&
			    !((ifp->int_state ^ drp->dr_ifp->int_state) &
			    IS_SICK)))
				new_drp = drp;

		} else if (new_drp->dr_ts != 0) {
			/* look for the least valuable entry to reuse */
			if ((!(new_drp->dr_ifp->int_state & IS_SICK) &&
			    (drp->dr_ifp->int_state & IS_SICK)) ||
			    (new_drp->dr_pref > drp->dr_pref &&
			    !((new_drp->dr_ifp->int_state ^
			    drp->dr_ifp->int_state) & IS_SICK)))
				new_drp = drp;
		}
	}

	/* if all of the current entries are better, add more drs[] */
	if (new_drp == NULL) {
		ptrsize = (max_ads + MAX_ADS) * sizeof (struct dr);
		ptr = realloc(drs, ptrsize);
		if (ptr == NULL)
			return;
		drs = ptr;
		(void) memset(&drs[max_ads], 0, MAX_ADS * sizeof (struct dr));
		new_drp = &drs[max_ads];
		max_ads += MAX_ADS;
	}

	/*
	 * Pointer copy is safe here because if_del
	 * calls if_bad_rdisc first, so a non-NULL df_ifp
	 * is always a valid pointer.
	 */
	new_drp->dr_ifp = ifp;
	new_drp->dr_gate = gate;
	new_drp->dr_ts = now.tv_sec;
	new_drp->dr_life = life;
	new_drp->dr_recv_pref = pref;
	/* bias functional preference by metric of the interface */
	new_drp->dr_pref = PREF(pref, ifp);

	/* after hearing a good advertisement, stop asking */
	if (!(ifp->int_state & IS_SICK))
		ifp->int_rdisc_cnt = MAX_SOLICITATIONS;
}


/*
 * Compute the IP checksum. This assumes the packet is less than 32K long.
 */
static uint16_t
in_cksum(uint16_t *p, uint_t len)
{
	uint32_t sum = 0;
	int nwords = len >> 1;

	while (nwords-- != 0)
		sum += *p++;

	if (len & 1)
		sum += *(uchar_t *)p;

	/* end-around-carry */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (~sum);
}


/* Send a router discovery advertisement or solicitation ICMP packet. */
static void
send_rdisc(union ad_u *p,
    uint_t p_size,
    struct interface *ifp,
    in_addr_t dst,		/* 0 or unicast destination */
    dstaddr_t type)
{
	struct sockaddr_in sin;
	int flags = 0;
	const char *msg;
	int ifindex = 0;
	struct in_addr addr;

	/*
	 * Don't send Rdisc packets on duplicate interfaces, we
	 * don't want to generate duplicate packets.
	 */
	if (ifp->int_state & IS_DUP)
		return;

	(void) memset(&sin, 0, sizeof (sin));
	sin.sin_addr.s_addr = dst;
	sin.sin_family = AF_INET;

	switch (type) {
	case unicast:				/* unicast */
	default:
		flags = MSG_DONTROUTE;
		msg = "Send";
		break;

	case bcast:				/* broadcast */
		if (ifp->int_if_flags & IFF_POINTOPOINT) {
			msg = "Send pt-to-pt";
			if (ifp->int_dstaddr == 0)
				sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
			else
				sin.sin_addr.s_addr = ifp->int_dstaddr;
		} else {
			msg = "Send broadcast";
			sin.sin_addr.s_addr = ifp->int_brdaddr;
		}
		break;

	case mcast:				/* multicast */
		msg = "Send multicast";
		break;
	}

	if (rdisc_sock < 0)
		get_rdisc_sock();

	/* select the right interface. */
	ifindex = (type != mcast && ifp->int_phys != NULL) ?
	    ifp->int_phys->phyi_index : 0;

	if (rdisc_sock_interface != ifp) {
		/*
		 * For multicast, we have to choose the source
		 * address.  This is either the local address
		 * (non-point-to-point) or the remote address.
		 */
		addr.s_addr = (ifp->int_if_flags & IFF_POINTOPOINT) ?
		    ifp->int_dstaddr : ifp->int_addr;
		if (type == mcast &&
		    setsockopt(rdisc_sock, IPPROTO_IP, IP_MULTICAST_IF, &addr,
		    sizeof (addr)) == -1) {
			LOGERR("setsockopt(rdisc_sock, IP_MULTICAST_IF)");
			return;
		}
		rdisc_sock_interface = ifp;
	}

	trace_rdisc(msg, ifp->int_addr, sin.sin_addr.s_addr, ifp, p, p_size);

	if (0 > sendtoif(rdisc_sock, p, p_size, flags, &sin, ifindex)) {
		if (!(ifp->int_state & IS_BROKE))
			writelog(LOG_WARNING, "sendto(%s%s%s): %s",
			    ifp->int_name, ", ",
			    inet_ntoa(sin.sin_addr),
			    rip_strerror(errno));
		if (ifp != NULL)
			if_sick(ifp, _B_FALSE);
	}
}


/* Send an advertisement */
static void
send_adv(struct interface *ifp,
    in_addr_t dst,
    dstaddr_t type)
{
	union ad_u u;

	if ((ifp->int_state & (IS_SUPPRESS_RDISC|IS_FLUSH_RDISC)) ==
	    IS_SUPPRESS_RDISC)
		return;

	(void) memset(&u, 0, sizeof (u.ad));

	u.ad.icmp_type = ICMP_ROUTERADVERT;
	u.ad.icmp_code = ICMP_ROUTERADVERT_COMMON;
	u.ad.icmp_ad_num = 1;
	u.ad.icmp_ad_asize = sizeof (u.ad.icmp_ad_info[0])/4;

	u.ad.icmp_ad_life = (stopint || !should_supply(ifp) ||
	    (ifp->int_state & IS_SUPPRESS_RDISC)) ? 0 :
	    htons(ifp->int_rdisc_int*3);

	/* Send the configured preference as a network byte order value */
	u.ad.icmp_ad_info[0].icmp_ad_pref = htonl(ifp->int_rdisc_pref);

	u.ad.icmp_ad_info[0].icmp_ad_addr = ifp->int_addr;

	u.ad.icmp_cksum = in_cksum((uint16_t *)&u.ad, sizeof (u.ad));

	send_rdisc(&u, sizeof (u.ad), ifp, dst, type);

	if (ifp->int_state & IS_SUPPRESS_RDISC)
		ifp->int_state &= ~IS_FLUSH_RDISC;
}


/* Advertise as a default router by way of router discovery. */
void
rdisc_adv(boolean_t forceadv)
{
	struct interface *ifp;

	if (!forceadv && !should_supply(NULL))
		return;

	rdisc_timer.tv_sec = now.tv_sec + NEVER;

	for (ifp = ifnet; ifp; ifp = ifp->int_next) {
		if ((ifp->int_state & (IS_NO_ADV_OUT | IS_BROKE)) ||
		    (!forceadv && !IS_IFF_ROUTING(ifp->int_if_flags)))
			continue;

		/* skip interfaces we shouldn't use */
		if (IS_IFF_QUIET(ifp->int_if_flags))
			continue;

		if (!timercmp(&ifp->int_rdisc_timer, &now, > /* cstyle */) ||
		    stopint != 0 || forceadv) {
			send_adv(ifp, htonl(INADDR_ALLHOSTS_GROUP),
			    (ifp->int_state & IS_BCAST_RDISC) ? 1 : 2);
			ifp->int_rdisc_cnt++;

			intvl_random(&ifp->int_rdisc_timer,
			    (ifp->int_rdisc_int*3)/4, ifp->int_rdisc_int);
			if (ifp->int_rdisc_cnt < MAX_INITIAL_ADVERTS &&
			    (ifp->int_rdisc_timer.tv_sec >
			    MAX_INITIAL_ADVERT_INTERVAL)) {
				ifp->int_rdisc_timer.tv_sec =
				    MAX_INITIAL_ADVERT_INTERVAL;
			}
			timevaladd(&ifp->int_rdisc_timer, &now);
		}
		if (timercmp(&rdisc_timer, &ifp->int_rdisc_timer,
		    > /* cstyle */))
			rdisc_timer = ifp->int_rdisc_timer;
	}
}


/* Solicit for Router Discovery */
void
rdisc_sol(void)
{
	struct interface *ifp;
	union ad_u u;

	if (should_supply(NULL))
		return;

	rdisc_timer.tv_sec = now.tv_sec + NEVER;

	for (ifp = ifnet; ifp; ifp = ifp->int_next) {
		if (0 != (ifp->int_state & (IS_NO_SOL_OUT | IS_BROKE)) ||
		    ifp->int_rdisc_cnt >= MAX_SOLICITATIONS)
			continue;

		/* skip interfaces we shouldn't use */
		if (IS_IFF_QUIET(ifp->int_if_flags))
			continue;

		if (!timercmp(&ifp->int_rdisc_timer, &now, > /* cstyle */)) {
			(void) memset(&u, 0, sizeof (u.so));
			u.so.icmp_type = ICMP_ROUTERSOLICIT;
			u.so.icmp_cksum = in_cksum((uint16_t *)&u.so,
			    sizeof (u.so));
			send_rdisc(&u, sizeof (u.so), ifp,
			    htonl(INADDR_ALLRTRS_GROUP),
			    ((ifp->int_state&IS_BCAST_RDISC) ? bcast : mcast));

			if (++ifp->int_rdisc_cnt >= MAX_SOLICITATIONS)
				continue;

			ifp->int_rdisc_timer.tv_sec = SOLICITATION_INTERVAL;
			ifp->int_rdisc_timer.tv_usec = 0;
			timevaladd(&ifp->int_rdisc_timer, &now);
		}

		if (timercmp(&rdisc_timer, &ifp->int_rdisc_timer,
		    > /* cstyle */))
			rdisc_timer = ifp->int_rdisc_timer;
	}
}


/*
 * check the IP header of a possible Router Discovery ICMP packet
 * Returns 0 if bad
 */
static struct interface *
ck_icmp(const char *act,
    in_addr_t	from,
    struct interface *ifp,
    in_addr_t	to,
    union ad_u *p,
    uint_t	len)
{
	const char *type;


	if (p->icmp.icmp_type == ICMP_ROUTERADVERT) {
		type = "advertisement";
		if (p->icmp.icmp_code == ICMP_ROUTERADVERT_NOCOMMON)
			return (NULL); /* Mobile IP */
	} else if (p->icmp.icmp_type == ICMP_ROUTERSOLICIT) {
		type = "solicitation";
	} else {
		return (NULL);
	}

	if (p->icmp.icmp_code != ICMP_ROUTERADVERT_COMMON) {
		trace_pkt("unrecognized ICMP Router %s code=%d from %s to %s",
		    type, p->icmp.icmp_code, naddr_ntoa(from), naddr_ntoa(to));
		return (NULL);
	}

	trace_rdisc(act, from, to, ifp, p, len);

	if (ifp == NULL)
		trace_pkt("unknown interface for router-discovery %s from %s "
		    "to %s", type, naddr_ntoa(from), naddr_ntoa(to));

	return (ifp);
}


/* Read packets from the router discovery socket */
void
read_d(void)
{
#define	PKTLEN	512
	static struct msg_limit bad_asize, bad_len;
	struct sockaddr_in from;
	int n, cc, hlen;
	struct {
		union {
			struct ip ip;
			uint16_t s[PKTLEN/sizeof (uint16_t)];
			uint8_t	b[PKTLEN/sizeof (uint8_t)];
		} pkt;
	} buf;
	union ad_u *p;
	n_long *wp;
	struct interface *ifp;
	boolean_t needsort = _B_FALSE;
	struct msghdr msg;
	struct iovec iov;
	uint8_t ancillary_data[CONTROL_BUFSIZE];

	iov.iov_base = &buf;
	iov.iov_len = sizeof (buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &from;
	msg.msg_control = &ancillary_data;

	for (;;) {
		msg.msg_namelen = sizeof (from);
		msg.msg_controllen = sizeof (ancillary_data);
		cc = recvmsg(rdisc_sock, &msg, 0);
		if (cc <= 0) {
			if (cc < 0 && errno != EWOULDBLOCK)
				LOGERR("recvmsg(rdisc_sock)");
			break;
		}

		hlen = buf.pkt.ip.ip_hl << 2;
		if (cc < hlen + ICMP_MINLEN)
			continue;
		/* LINTED [alignment will be lw aligned] */
		p = (union ad_u *)&buf.pkt.b[hlen];
		cc -= hlen;

		/*
		 * If we could tell the interface on which a packet from
		 * address 0 arrived, we could deal with such solicitations.
		 */
		ifp = receiving_interface(&msg, _B_FALSE);
		ifp = ck_icmp("Recv", from.sin_addr.s_addr, ifp,
		    buf.pkt.ip.ip_dst.s_addr, p, cc);
		if (ifp == NULL)
			continue;

		if (IS_IFF_QUIET(ifp->int_if_flags)) {
			trace_misc("discard RDISC packet received over %s, %X",
			    ifp->int_name, ifp->int_if_flags);
			continue;
		}

		if (from.sin_addr.s_addr != 0 &&
		    ifwithaddr(from.sin_addr.s_addr, _B_FALSE, _B_FALSE)) {
			trace_pkt("    "
			    "discard our own Router Discovery message");
			continue;
		}

		/* The remote address *must* be directly connected. */
		if (!remote_address_ok(ifp, from.sin_addr.s_addr)) {
			trace_misc("discard rdisc message; source %s not on "
			    "interface %s", naddr_ntoa(from.sin_addr.s_addr),
			    ifp->int_name);
			continue;
		}

		switch (p->icmp.icmp_type) {
		case ICMP_ROUTERADVERT:
			if (ifp->int_state & IS_NO_ADV_IN)
				continue;

			if (p->ad.icmp_ad_asize*2*sizeof (wp[0]) <
			    sizeof (p->ad.icmp_ad_info[0])) {
				msglim(&bad_asize, from.sin_addr.s_addr,
				    "intolerable rdisc address size=%d",
				    p->ad.icmp_ad_asize);
				continue;
			}
			if (p->ad.icmp_ad_num == 0) {
				trace_pkt("    empty?");
				continue;
			}
			if (cc < (sizeof (p->ad) -
			    sizeof (p->ad.icmp_ad_info) +
			    (p->ad.icmp_ad_num *
			    sizeof (p->ad.icmp_ad_info[0])))) {
				msglim(&bad_len, from.sin_addr.s_addr,
				    "rdisc length %d does not match ad_num"
				    " %d", cc, p->ad.icmp_ad_num);
				continue;
			}

			needsort = _B_TRUE;
			wp = &p->ad.icmp_ad_info[0].icmp_ad_addr;
			for (n = 0; n < p->ad.icmp_ad_num; n++) {
				parse_ad(from.sin_addr.s_addr,
				    wp[0], wp[1],
				    ntohs(p->ad.icmp_ad_life), ifp);
				wp += p->ad.icmp_ad_asize;
			}
			break;


		case ICMP_ROUTERSOLICIT:
			if (!should_supply(ifp))
				continue;
			if ((ifp->int_state & IS_NO_ADV_OUT) ||
			    !IS_IFF_ROUTING(ifp->int_if_flags))
				continue;
			if (stopint != 0)
				continue;

			/*
			 * We should handle messages from address 0,
			 * but cannot due to kernel limitations.
			 */

			/* Respond with a point-to-point advertisement */
			send_adv(ifp, from.sin_addr.s_addr, 0);
			break;
		}
	}

	if (needsort)
		rdisc_sort();
}

void
rdisc_dump(void)
{
	struct dr *drp;

	for (drp = drs; drp < &drs[max_ads]; drp++)
		if (drp->dr_ts != 0)
			trace_dr(drp);
}

void
rdisc_suppress(struct interface *ifp)
{
	if (ifp->int_state & IS_ADV_OUT) {
		msglog("%s \"rdisc_adv\" specified, will not "
		    "suppress rdisc adv", ifp->int_name);
	} else {
		if (ifp->int_state & IS_SUPPRESS_RDISC)
			return;
		ifp->int_state |= (IS_SUPPRESS_RDISC|IS_FLUSH_RDISC);
		trace_misc("suppress rdisc adv on %s", ifp->int_name);
		rdisc_timer.tv_sec = 0;
	}
}

void
rdisc_restore(struct interface *ifp)
{
	if ((ifp->int_state & IS_SUPPRESS_RDISC) == 0)
		return;
	ifp->int_state &= ~(IS_SUPPRESS_RDISC|IS_FLUSH_RDISC);
	trace_misc("restoring rdisc adv on %s", ifp->int_name);
	rdisc_timer.tv_sec = 0;
}

void
process_d_mib_sock(void)
{

	socklen_t fromlen;
	struct sockaddr_un from;
	ssize_t	len;
	int command;
	struct dr *drp;
	rdisc_info_t rdisc_info;
	defr_t def_router;
	extern int max_ads;
	int num = 0;

	fromlen = (socklen_t)sizeof (from);
	len = recvfrom(rdisc_mib_sock, &command, sizeof (int), 0,
	    (struct sockaddr *)&from, &fromlen);

	if (len < sizeof (int) || command != RDISC_SNMP_INFO_REQ) {
		trace_misc("Bad command on rdisc_mib_sock");
		return;
	}

	/*
	 * Count number of good routers
	 */
	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ts != 0) {
			num++;
		}
	}

	rdisc_info.info_type = RDISC_SNMP_INFO_RESPONSE;
	rdisc_info.info_version = RDISC_SNMP_INFO_VER;
	rdisc_info.info_num_of_routers = num;

	(void) sendto(rdisc_mib_sock, &rdisc_info, sizeof (rdisc_info_t), 0,
	    (struct sockaddr *)&from, fromlen);

	for (drp = drs; drp < &drs[max_ads]; drp++) {
		if (drp->dr_ts != 0) {
			def_router.defr_info_type = RDISC_DEF_ROUTER_INFO;
			def_router.defr_version = RDISC_DEF_ROUTER_VER;
			def_router.defr_index =
			    drp->dr_ifp->int_phys->phyi_index;
			def_router.defr_life = drp->dr_life;
			def_router.defr_addr.s_addr = drp->dr_gate;
			def_router.defr_pref = drp->dr_pref;
			(void) sendto(rdisc_mib_sock, &def_router,
			    sizeof (defr_t), 0, (struct sockaddr *)&from,
			    fromlen);
		}
	}
}
