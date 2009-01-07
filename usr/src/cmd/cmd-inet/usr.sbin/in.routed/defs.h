/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 *	@(#)defs.h	8.1 (Berkeley) 6/5/93
 *
 * $FreeBSD: src/sbin/routed/defs.h,v 1.14 2000/08/11 08:24:38 sheldonh Exp $
 */

#ifndef	_DEFS_H
#define	_DEFS_H

/*
 * Definitions for RIPv2 routing process.
 *
 * This code is based on the 4.4BSD `routed` daemon, with extensions to
 * support:
 *	RIPv2, including variable length subnet masks.
 *	Router Discovery
 *	aggregate routes in the kernel tables.
 *	aggregate advertised routes.
 *	maintain spare routes for faster selection of another gateway
 *		when the current gateway dies.
 *	timers on routes with second granularity so that selection
 *		of a new route does not wait 30-60 seconds.
 *	tolerance of static routes.
 *	tell the kernel hop counts.
 *	use of per-interface ip_forwarding state.
 *
 * The vestigial support for other protocols has been removed.  There
 * is no likelihood that IETF RIPv1 or RIPv2 will ever be used with
 * other protocols.  The result is far smaller, faster, cleaner, and
 * perhaps understandable.
 *
 * The accumulation of special flags and kludges added over the many
 * years have been simplified and integrated.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <md5.h>
#include <libintl.h>
#include <locale.h>
#include "radix.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define	RIPVERSION RIPv2
#include <protocols/routed.h>


#define	DAY (24*60*60)
#define	NEVER DAY			/* a long time */
#define	EPOCH NEVER			/* bias time by this to avoid <0 */

/*
 * Scan the kernel regularly to see if any interfaces have appeared or been
 * turned off.
 */
#define	CHECK_BAD_INTERVAL	5	/* when an interface is known bad */
#define	CHECK_ACT_INTERVAL	30	/* when advertising */
#define	CHECK_QUIET_INTERVAL	300	/* when not */

/*
 * Limit the seconds in the timeval structure "s" to "l" seconds, but only
 * if l is less than the current seconds in s.  This is used to shorten
 * certain timers to ensure that scheduled events occur sooner than
 * originally scheduled.
 */
#define	LIM_SEC(s, l) ((s).tv_sec = MIN((s).tv_sec, (l)))

/*
 * Metric used for fake default routes.  It ought to be 15, but when
 * processing advertised routes, previous versions of `routed` added
 * to the received metric and discarded the route if the total was 16
 * or larger.
 */
#define	FAKE_METRIC (HOPCNT_INFINITY-2)


/* Router Discovery parameters */
#define	MAX_MAXADVERTISEINTERVAL	1800
#define	MIN_MAXADVERTISEINTERVAL	4
#define	DEF_MAXADVERTISEINTERVAL	600
#define	DEF_PREFERENCELEVEL		0
#define	MIN_PREFERENCELEVEL		0x80000000

#define	MAX_INITIAL_ADVERT_INTERVAL	16
#define	MAX_INITIAL_ADVERTS		3
#define	MAX_RESPONSE_DELAY		2

#define	MAX_SOLICITATION_DELAY		1
#define	SOLICITATION_INTERVAL		3
#define	MAX_SOLICITATIONS		3

/*
 * convert between signed, balanced around zero,
 * and unsigned zero-based preferences
 */
#define	SIGN_PREF(p) ((p) ^ MIN_PREFERENCELEVEL)
#define	UNSIGN_PREF(p) SIGN_PREF(p)

/*
 * Bloated packet size for systems that simply add authentication to
 * full-sized packets
 */
#define	OVER_MAXPACKETSIZE (MAXPACKETSIZE+sizeof (struct netinfo)*2)
/* typical packet buffers */
union pkt_buf {
	uint8_t	packet[OVER_MAXPACKETSIZE*2];
	struct	rip rip;
};

extern struct dr *drs;

/*
 * IF_NAME_LEN is the maximum size of interface names represented within
 * in.routed.  Regular Solaris interfaces have names of at most LIFNAMESIZ
 * characters, but in.routed has remote interfaces represented internally
 * as "remote(<gatewayname>)", where <gatewayname> is a hostname or IP
 * address.  IF_NAME_LEN needs to be large enough to also hold such
 * interface names as well.
 */
#define	IF_NAME_LEN	(MAXHOSTNAMELEN + sizeof ("remote()") + 1)

/*
 * No more routes than this, to protect ourself in case something goes
 * whacko and starts broadcasting zillions of bogus routes.
 */
#define	MAX_ROUTES  (128*1024)

enum origin {
	RO_NONE,	/* empty slot */
	RO_RIP,		/* learnt from RIP */
	RO_RDISC,	/* learnt from RDISC */
	RO_STATIC,	/* learnt from kernel */
	RO_LOOPBCK,	/* loopback route */
	RO_PTOPT,	/* point-to-point route */
	RO_NET_SYN,	/* fake net route for subnet */
	RO_IF,		/* interface route */
	RO_FILE		/* from /etc/gateways */
};

/*
 * Main, daemon routing table structure
 */
struct rt_spare {
	struct interface *rts_ifp;
	uint32_t	rts_gate;	/* forward packets here */
	uint32_t	rts_router;	/* on this router's authority */
	uint8_t		rts_metric;
	enum origin	rts_origin;
	uint16_t	rts_tag;
	time_t		rts_time;	/* timer to junk stale routes */
	uint32_t	rts_de_ag;	/* de-aggregation level */
	uint16_t	rts_flags;
};

#define	RTS_EXTERNAL	0x0001	/* handled by other routing protocol e.g. EGP */
#define	SPARE_INC	2
#define	EMPTY_RT_SPARE	{ NULL, 0, 0, HOPCNT_INFINITY, RO_NONE, 0, 0, 0, 0 }

struct rt_entry {
	struct radix_node rt_nodes[2];	/* radix tree glue */
	struct sockaddr_in rt_dst_sock;
	time_t		rt_poison_time;	/* advertised metric */
	in_addr_t	rt_mask;
	uint32_t	rt_seqno;	/* when last changed */
	uint16_t	rt_state;
#define	RS_IF		0x0001	/* for network interface */
#define	RS_NET_INT	0x0002	/* authority route */
#define	RS_NET_SYN	0x0004	/* fake net route for subnet */
#define	RS_NO_NET_SYN (RS_LOCAL | RS_IF)
#define	RS_SUBNET	0x0008	/* subnet route from any source */
#define	RS_LOCAL	0x0010	/* loopback for pt-to-pt */
#define	RS_MHOME	0x0020	/* from -m */
#define	RS_STATIC	0x0040	/* from the kernel */
#define	RS_NOPROPAGATE	0x0080	/* route which must not be propagated */
#define	RS_BADIF	0x0100	/* route through dead ifp */

	uint8_t		rt_poison_metric;	/* to notice maximum recently */
	uint_t		rt_num_spares;
	struct rt_spare  *rt_spares;
};
#define	rt_dst	    rt_dst_sock.sin_addr.s_addr
#define	rt_ifp	    rt_spares[0].rts_ifp
#define	rt_gate	    rt_spares[0].rts_gate
#define	rt_router   rt_spares[0].rts_router
#define	rt_metric   rt_spares[0].rts_metric
#define	rt_tag	    rt_spares[0].rts_tag
#define	rt_time	    rt_spares[0].rts_time
#define	rt_de_ag    rt_spares[0].rts_de_ag

#define	HOST_MASK	0xffffffffU
#define	RT_ISHOST(rt)	((rt)->rt_mask == HOST_MASK)

/*
 * Determine if a route should be aged.  Age all routes that are:
 * Not from -g, -m, nor static routes from the kernel
 * not unbroken interface routes but not broken interfaces
 * not learnt from RDISC or from /etc/gateways
 * nor non-passive, remote interfaces that are not aliases
 * (i.e. remote & metric=0)
 */
#define	AGE_RT(rt_state, rts_origin, ifp) \
	((!((rt_state) & (RS_MHOME | RS_STATIC | RS_NET_SYN)) && \
	(rts_origin != RO_RDISC) && \
	(rts_origin != RO_FILE)) && \
	(!((rt_state) & RS_IF) || \
	    (ifp) == NULL || \
		(((ifp)->int_state & IS_REMOTE) && \
		    !((ifp)->int_state & IS_PASSIVE))))

/*
 * true if A is better than B
 * Better if
 *	- A is not a poisoned route
 *	- and A is not stale
 *	- and either:
 *		- A has a shorter path
 *		- or the router is speaking for itself
 *		- or B has the same metric and isn't stale
 *		- or A is a host route advertised by a system for itself
 */
#define	BETTER_LINK(rt, A, B) ((A)->rts_metric < HOPCNT_INFINITY &&	\
			now_stale <= (A)->rts_time &&		\
			((A)->rts_metric < (B)->rts_metric ||	\
			((A)->rts_gate == (A)->rts_router &&	\
			(B)->rts_gate != (B)->rts_router) || \
			((A)->rts_metric == (B)->rts_metric &&	\
				now_stale > (B)->rts_time) ||	\
			(RT_ISHOST(rt) &&			\
				(rt)->rt_dst == (A)->rts_router &&	\
				(A)->rts_metric == (B)->rts_metric)))

struct hlinkage {
	void *hl_next;
	void **hl_prev;
};

/*
 * A "physical_interface" represents the actual hardware.  It is also
 * a container for a list of the interfaces that have the same ifIndex
 * number.  This will consist of zero or one "main" interface plus
 * zero or more IS_ALIAS interfaces.
 */
struct physical_interface {
	struct hlinkage phyi_link;
	uint32_t phyi_index;
	struct interface *phyi_interface;
	struct phyi_data {
		uint32_t	ipackets;	/* previous network stats */
		uint32_t	ierrors;
		uint32_t	opackets;
		uint32_t	oerrors;
		time_t	ts;		/* timestamp on network stats */
	} phyi_data;
	char phyi_name[IF_NAME_LEN+1];
};

/*
 * An "interface" is similar to a kernel ifnet structure, except it also
 * handles "logical" or "IS_REMOTE" interfaces (remote gateways).
 */
struct interface {
	/*
	 * We keep interfaces in a variety of data structures to
	 * optimize for different types of searches.
	 */
	struct hlinkage int_link;
#define	int_next	int_link.hl_next
	struct hlinkage int_ahash;	/* by address */
	struct hlinkage int_bhash;	/* by broadcast address */
	struct hlinkage int_nhash;	/* by name */
	struct hlinkage int_ilist;	/* ifIndex list */
	struct physical_interface *int_phys;	/* backpointer */
	char		int_name[IF_NAME_LEN+1];
	in_addr_t	int_addr;	/* address on this host (net order) */
	in_addr_t	int_brdaddr;	/* broadcast address (n) */
	in_addr_t	int_dstaddr;	/* other end of pt-to-pt link (n) */
	in_addr_t	int_net;	/* working network # (host order) */
	in_addr_t	int_mask;	/* working net mask (host order) */
	in_addr_t	int_ripv1_mask;	/* for inferring a mask (n) */
	in_addr_t	int_std_addr;	/* class A/B/C address (n) */
	in_addr_t	int_std_net;	/* class A/B/C network (h) */
	in_addr_t	int_std_mask;	/* class A/B/C netmask (h) */
	in_addr_t	int_ripout_addr; /* RIP pkts sent to this addr */
	uint64_t	int_if_flags;	/* some bits copied from kernel */
	uint32_t	int_state;
	time_t		int_act_time;	/* last thought healthy (IS_REMOTE) */
	time_t		int_query_time;	/* last query (IS_REMOTE) */
	uint32_t	int_transitions; /* times gone up-down */
	uint8_t		int_metric;
	uint8_t		int_d_metric;	/* for faked default route */
#define	MAX_AUTH_KEYS 5
	struct auth {			/* authentication info */
		time_t		start, end;
		uint16_t	type;
		/*
		 * Although the following key is just an array of bytes,
		 * in.routed is currently limited to ascii characters
		 * because of its configuration syntax and parsing.
		 */
		uint8_t		key[RIP_AUTH_PW_LEN +1];
		uint8_t		keyid;
		uint8_t		warnedflag;
	} int_auth[MAX_AUTH_KEYS];
	/* router discovery parameters */
	int		int_rdisc_pref;	/* signed preference to advertise */
	uint32_t	int_rdisc_int;	/* MaxAdvertiseInterval */
	uint32_t	int_rdisc_cnt;
	struct timeval int_rdisc_timer;
};

/* bits in int_state */
#define	IS_ALIAS	    0x00000001	/* interface alias */
#define	IS_SUBNET	    0x00000002	/* interface on subnetted network */
#define	IS_REMOTE	    0x00000004	/* interface is not on this machine */
#define	IS_PASSIVE	    0x00000008	/* remote and does not do RIP */
#define	IS_EXTERNAL	    0x00000010	/* handled by EGP or something */
#define	IS_CHECKED	    0x00000020	/* still exists */
#define	IS_ALL_HOSTS	    0x00000040	/* in INADDR_ALLHOSTS_GROUP */
#define	IS_ALL_ROUTERS	    0x00000080	/* in INADDR_ALLROUTERS_GROUP */
#define	IS_DISTRUST	    0x00000100	/* ignore untrusted routers */
#define	IS_REDIRECT_OK	    0x00000200	/* accept ICMP redirects */
#define	IS_BROKE	    0x00000400	/* seems to be broken */
#define	IS_SICK		    0x00000800	/* seems to be broken */
#define	IS_DUP		    0x00001000	/* duplicates another interface */
#define	IS_NEED_NET_SYN	    0x00002000	/* need RS_NET_SYN route */
#define	IS_NO_AG	    0x00004000	/* do not aggregate subnets */
#define	IS_NO_SUPER_AG	    0x00008000	/* do not aggregate networks */
#define	IS_NO_RIPV1_IN	    0x00010000	/* no RIPv1 input at all */
#define	IS_NO_RIPV2_IN	    0x00020000	/* no RIPv2 input at all */
#define	IS_NO_RIP_IN	(IS_NO_RIPV1_IN | IS_NO_RIPV2_IN)
#define	IS_RIP_IN_OFF(s) (((s) & IS_NO_RIP_IN) == IS_NO_RIP_IN)
#define	IS_NO_RIPV1_OUT	    0x00040000	/* no RIPv1 output at all */
#define	IS_NO_RIPV2_OUT	    0x00080000	/* no RIPv2 output at all */
#define	IS_NO_RIP_OUT	(IS_NO_RIPV1_OUT | IS_NO_RIPV2_OUT)
#define	IS_NO_RIP	(IS_NO_RIP_OUT | IS_NO_RIP_IN)
#define	IS_RIP_OUT_OFF(s) (((s) & IS_NO_RIP_OUT) == IS_NO_RIP_OUT)
#define	IS_RIP_OFF(s)	(((s) & IS_NO_RIP) == IS_NO_RIP)
#define	IS_NO_RIP_MCAST	    0x00100000	/* broadcast RIPv2 */
#define	IS_NO_ADV_IN	    0x00200000	/* do not listen to advertisements */
#define	IS_NO_SOL_OUT	    0x00400000	/* send no solicitations */
#define	IS_SOL_OUT	    0x00800000	/* send solicitations */
#define	GROUP_IS_SOL_OUT (IS_SOL_OUT | IS_NO_SOL_OUT)
#define	IS_NO_ADV_OUT	    0x01000000	/* do not advertise rdisc */
#define	IS_ADV_OUT	    0x02000000	/* advertise rdisc */
#define	GROUP_IS_ADV_OUT (IS_NO_ADV_OUT | IS_ADV_OUT)
#define	IS_BCAST_RDISC	    0x04000000	/* broadcast instead of multicast */
#define	IS_NO_RDISC	(IS_NO_ADV_IN | IS_NO_SOL_OUT | IS_NO_ADV_OUT)
#define	IS_PM_RDISC	    0x08000000	/* poor-man's router discovery */
#define	IS_NO_HOST	    0x10000000	/* disallow host routes */
#define	IS_SUPPRESS_RDISC   0x20000000  /* don't send rdisc advs */
#define	IS_FLUSH_RDISC	    0x40000000	/* flush client rdisc caches */

/*
 * passive interfaces are added through gwkludge
 */
#define	IS_PASSIVE_IFP(ifp) \
	(((ifp)->int_state & (IS_REMOTE|IS_PASSIVE|IS_EXTERNAL|IS_ALIAS)) == \
	    (IS_REMOTE|IS_PASSIVE))

/*
 * Is an IP interface up?
 */
#define	IS_IFF_UP(f)	(((f) & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING))

/*
 * This defines interfaces that we should not use for advertising or
 * soliciting routes by way of RIP and rdisc.  Interfaces marked this
 * way do not count for purposes of determining how many interfaces
 * this router has.
 */
#define	IS_IFF_QUIET(f)	((f) & (IFF_LOOPBACK|IFF_NORTEXCH|IFF_NOXMIT))

/*
 * This defines interfaces that we can use for advertising routes by way of
 * RIP and rdisc.
 */
#define	IS_IFF_ROUTING(f) \
	(((f) & IFF_ROUTER) && !((f) & (IFF_NORTEXCH|IFF_NOXMIT)))

/* Information for aggregating routes */
#define	NUM_AG_SLOTS	32
struct ag_info {
	struct ag_info *ag_fine;	/* slot with finer netmask */
	struct ag_info *ag_cors;	/* more coarse netmask */
	in_addr_t	ag_dst_h;	/* destination in host byte order */
	in_addr_t	ag_mask;
	in_addr_t	ag_gate;
	struct interface *ag_ifp;
	in_addr_t	ag_nhop;
	uint8_t		ag_metric;	/* metric to be advertised */
	uint8_t		ag_pref;	/* aggregate based on this */
	uint32_t	ag_seqno;
	uint16_t	ag_tag;
	uint16_t	ag_state;
#define	    AGS_SUPPRESS    0x001	/* combine with coarser mask */
#define	    AGS_AGGREGATE   0x002	/* synthesize combined routes */
#define	    AGS_REDUN0	    0x004	/* redundant, finer routes output */
#define	    AGS_REDUN1	    0x008
#define	    AG_IS_REDUN(state) (((state) & (AGS_REDUN0 | AGS_REDUN1)) \
				== (AGS_REDUN0 | AGS_REDUN1))
#define	    AGS_GATEWAY	    0x010	/* tell kernel RTF_GATEWAY */
#define	    AGS_IF	    0x020	/* for an interface */
#define	    AGS_RIPV2	    0x040	/* send only as RIPv2 */
#define	    AGS_FINE_GATE   0x080	/* ignore differing ag_gate when */
					/* this has the finer netmask */
#define	    AGS_CORS_GATE   0x100	/* ignore differing gate when this */
					/* has the coarser netmasks */
#define	    AGS_SPLIT_HZ    0x200	/* suppress for split horizon */
#define	    AGS_PASSIVE    0x400	/* passive "remote" interface route */
#define	    AGS_FILE	    0x800	/* from /etc/gateways */

	/* some bits are set if they are set on either route */
#define	    AGS_AGGREGATE_EITHER (AGS_RIPV2 | AGS_GATEWAY | \
					AGS_SUPPRESS | AGS_CORS_GATE)
};

struct khash {
	struct khash *k_next;
	in_addr_t	k_dst;
	in_addr_t	k_mask;
	in_addr_t	k_gate;
	struct interface *k_ifp;
	short		k_metric;
	ushort_t	k_state;	/* KS_* */
	time_t	k_keep;
	time_t	k_redirect_time;	/* when redirected route 1st seen */
};

/* bit flags for k_state; shared between table.c and trace.c */
#define	    KS_NEW	0x0001
#define	    KS_DELETE	0x0002		/* need to delete the route */
#define	    KS_ADD	0x0004		/* add to the kernel */
#define	    KS_CHANGE	0x0008		/* tell kernel to change the route */
#define	    KS_DEL_ADD	0x0010		/* delete & add to change the kernel */
#define	    KS_STATIC	0x0020		/* Static flag in kernel */
#define	    KS_GATEWAY	0x0040		/* G flag in kernel */
#define	    KS_DYNAMIC	0x0080		/* result of redirect */
#define	    KS_DELETED	0x0100		/* already deleted from kernel */
#define	    KS_PRIVATE	0x0200		/* Private flag in kernel */
#define	    KS_CHECK	0x0400
#define	    KS_IF	0x0800		/* interface route */
#define	    KS_PASSIVE	0x1000		/* passive remote interface route */
#define	    KS_DEPRE_IF	0x2000		/* IPMP deprecated interface route */
#define	    KS_FILE	0x4000		/* from /etc/gateways */

/* default router structure */
struct dr {			/* accumulated advertisements */
	struct interface *dr_ifp;
	in_addr_t	dr_gate;	/* gateway */
	time_t		dr_ts;		/* when received */
	time_t		dr_life;	/* lifetime in host byte order */
	uint32_t	dr_recv_pref;	/* received but biased preference */
	uint32_t	dr_pref;	/* preference adjusted by metric */
	uint32_t	dr_flags;
#define	DR_CHANGED	1		/* received new info for known dr */
};

/* parameters for interfaces */
struct parm {
	struct parm 	*parm_next;
	in_addr_t	parm_net;
	in_addr_t	parm_mask;
	in_addr_t	parm_ripout_addr;
	uint32_t	parm_int_state;
	int32_t		parm_rdisc_pref;	/* signed IRDP preference */
	uint32_t	parm_rdisc_int;		/* IRDP advertising interval */
	struct auth 	parm_auth[MAX_AUTH_KEYS];
	char		parm_name[IF_NAME_LEN+1];
	uint8_t		parm_d_metric;
};

/* authority for internal networks */
extern struct intnet {
	struct intnet *intnet_next;
	in_addr_t	intnet_addr;	/* network byte order */
	in_addr_t	intnet_mask;
	int8_t		intnet_metric;
} *intnets;

/*
 * Defined RIPv1 netmasks.  These come from ripv1_mask entries in
 * /etc/gateways of the form:
 *
 * ripv1_mask=<net>/<match>,<mask>
 *
 * The intended use of these structures is to give RIPv1 destinations which
 * are in <net>/<match> a netmask of <mask>, where <mask> > <match>.
 */
extern struct r1net {
	struct r1net *r1net_next;
	in_addr_t	r1net_net;	/* host order */
	in_addr_t	r1net_match;
	in_addr_t	r1net_mask;
} *r1nets;

/* trusted routers */
extern struct tgate {
	struct tgate *tgate_next;
	in_addr_t	tgate_addr;
#define	    MAX_TGATE_NETS 32
	struct tgate_net {
	    in_addr_t   net;	/* host order */
	    in_addr_t   mask;
	} tgate_nets[MAX_TGATE_NETS];
} *tgates;

enum output_type {OUT_QUERY, OUT_UNICAST, OUT_BROADCAST, OUT_MULTICAST,
	NO_OUT_MULTICAST, NO_OUT_RIPV2};

/* common output buffers */
extern struct ws_buf {
	struct rip	*buf;
	struct netinfo	*n;
	struct netinfo	*base;
	struct netinfo	*lim;
	enum output_type type;
} v12buf;

extern int	stopint;		/* !=0 to stop in.routed */

extern int	rip_sock;		/* RIP socket */
extern struct interface *rip_sock_interface; /* current output interface */
extern int	rt_sock;		/* routing socket */
extern int	rdisc_sock;		/* router-discovery raw socket */
extern int	rdisc_mib_sock;		/* AF_UNIX mib info socket */

extern boolean_t rip_enabled;		/* is rip on? */
extern boolean_t supplier;		/* process should supply updates */
extern boolean_t supplier_set;		/* -s or -q requested */
extern boolean_t save_space;		/* -S option 1=treat all RIP speakers */
extern boolean_t ridhosts;		/* 1=reduce host routes */
extern boolean_t mhome;			/* 1=want multi-homed host route */
extern boolean_t advertise_mhome; 	/* 1=must continue advertising it */
extern boolean_t auth_ok;		/* 1=ignore auth if we do not care */
extern boolean_t no_install;		/* 1=don't install in kernel */

extern struct timeval clk;		/* system clock's idea of time */
extern struct timeval epoch;		/* system clock when started */
extern struct timeval now;		/* current idea of time */
extern time_t	now_stale;
extern time_t	now_expire;
extern time_t	now_garbage;

extern struct timeval age_timer;	/* next check of old routes */
extern struct timeval no_flash;		/* inhibit flash update until then */
extern struct timeval rdisc_timer;	/* next advert. or solicitation */
extern boolean_t rdisc_ok;			/* using solicited route */

extern struct timeval ifscan_timer;	/* time to check interfaces */

extern in_addr_t loopaddr;		/* our address on loopback */
extern uint_t	tot_interfaces;		/* # of remote and local interfaces */
extern uint_t	rip_interfaces;		/* # of interfaces doing RIP */
extern uint_t	ripout_interfaces;	/* # of interfaces advertising RIP */
extern uint_t	fwd_interfaces;		/* # of interfaces ip_forwarding=1 */
extern struct interface	*ifnet;		/* all interfaces */
extern size_t hash_table_sizes[];	/* list of primes for hash tables */
extern boolean_t	have_ripv1_out;	/* have a RIPv1 interface */
extern boolean_t	need_flash;	/* flash update needed */
extern struct timeval	need_kern;	/* need to update kernel table */
extern uint32_t		update_seqno;	/* a route has changed */
extern struct interface dummy_ifp;	/* wildcard interface */

extern int	tracelevel, new_tracelevel;
#define	MAX_TRACELEVEL 5
#define	TRACERTS (tracelevel >= 5)	/* log routing socket contents */
#define	TRACEKERNEL (tracelevel >= 4)	/* log kernel changes */
#define	TRACECONTENTS (tracelevel >= 3)	/* display packet contents */
#define	TRACEPACKETS (tracelevel >= 2)	/* note packets */
#define	TRACEACTIONS (tracelevel != 0)
extern FILE	*ftrace;		/* output trace file */
extern char inittracename[MAXPATHLEN+1];

extern struct radix_node_head *rhead;

extern void fix_sock(int, const char *);
extern void fix_select(void);
extern void rip_off(void);
extern void rip_on(struct interface *);

extern void bufinit(void);
extern int  output(enum output_type, struct sockaddr_in *,
    struct interface *, struct rip *, int);
extern void clr_ws_buf(struct ws_buf *, struct auth *);
extern void rip_query(void);
extern void rip_bcast(int);
extern void supply(struct sockaddr_in *, struct interface *,
    enum output_type, int, int, boolean_t);

extern void	msglog(const char *, ...);
extern void	writelog(int, const char *, ...);
struct msg_limit {
	time_t	reuse;
	struct msg_sub {
		in_addr_t addr;
		time_t	until;
#define	MSG_SUBJECT_N 8
	} subs[MSG_SUBJECT_N];
};
extern void	msglim(struct msg_limit *, in_addr_t, const char *, ...);
#define	LOGERR(msg) msglog(msg ": %s", rip_strerror(errno))
extern void	logbad(boolean_t, const char *, ...);
#define	BADERR(dump, msg) logbad(dump, msg ": %s", rip_strerror(errno))
#ifdef DEBUG
#define	DBGERR(dump, msg) BADERR(dump, msg)
#else
#define	DBGERR(dump, msg) LOGERR(msg)
#endif
extern	char	*naddr_ntoa(in_addr_t);
extern const char *saddr_ntoa(struct sockaddr_storage *);
extern const char *rip_strerror(int errnum);
extern char *if_bit_string(uint_t, boolean_t);

extern void	*rtmalloc(size_t, const char *);
extern void	timevaladd(struct timeval *, struct timeval *);
extern void	intvl_random(struct timeval *, ulong_t, ulong_t);
extern boolean_t	getnet(const char *, in_addr_t *, in_addr_t *);
extern int	gethost(char *, in_addr_t *);
extern void	gwkludge(void);
extern const char *parse_parms(char *, boolean_t);
extern const char *insert_parm(struct parm *);
extern void	get_parms(struct interface *);

extern void	lastlog(void);
extern void	trace_close(int);
extern void	set_tracefile(const char *, const char *, int);
extern void	tracelevel_msg(const char *, int);
extern void	trace_off(const char *, ...);
extern void	set_tracelevel(void);
extern void	trace_flush(void);
extern void	trace_misc(const char *, ...);
extern void	trace_act(const char *, ...);
extern void	trace_pkt(const char *, ...);
extern void	trace_add_del(const char *, struct rt_entry *);
extern void	trace_change(struct rt_entry *, uint16_t, struct rt_spare *,
    const char *);
extern void	trace_if(const char *, struct interface *);
extern void	trace_khash(const struct khash *);
extern void	trace_dr(const struct dr *);
extern void	trace_upslot(struct rt_entry *, struct rt_spare *,
    struct rt_spare *);
extern void	trace_rip(const char *, const char *, struct sockaddr_in *,
    struct interface *, struct rip *, int);
extern char	*addrname(in_addr_t, in_addr_t, int);
extern char	*rtname(in_addr_t, in_addr_t, in_addr_t);

extern void	rdisc_age(in_addr_t);
extern void	set_rdisc_mg(struct interface *, int);
extern void	set_supplier(void);
extern void	if_bad_rdisc(struct interface *);
extern void	if_rewire_rdisc(struct interface *, struct interface *);
extern void	if_ok_rdisc(struct interface *);
extern int	read_rip(void);
extern void	input_route(in_addr_t, in_addr_t, struct rt_spare *,
    struct netinfo *, uint16_t);
extern void	read_rt(void);
extern void	read_d(void);
extern void	process_d_mib_sock(void);
extern void	rdisc_adv(boolean_t);
extern void	rdisc_sol(void);
extern struct interface *receiving_interface(struct msghdr *, boolean_t);
extern void	*find_ancillary(struct msghdr *, int);
extern boolean_t	should_supply(struct interface *);
extern void	rdisc_dump(void);
extern void	rdisc_suppress(struct interface *);
extern void	rdisc_restore(struct interface *);

extern void age_peer_info(void);

extern void	sigtrace_more(int);
extern void	sigtrace_less(int);
extern void	sigtrace_dump(int);

extern void	sync_kern(void);
extern void	age(in_addr_t);
extern void	kern_dump(void);
extern void	kern_flush_ifp(struct interface *);
extern void	kern_rewire_ifp(struct interface *, struct interface *);

extern void	ag_flush(in_addr_t, in_addr_t, void (*)(struct ag_info *));
extern void	ag_check(in_addr_t, in_addr_t, in_addr_t, struct interface *,
    in_addr_t, uint8_t, uint8_t, uint32_t, uint16_t, uint16_t,
    void (*)(struct ag_info *));
extern void	del_static(in_addr_t, in_addr_t, in_addr_t,
    struct interface *, int);
extern void	del_redirects(in_addr_t, time_t);
extern struct rt_entry *rtget(in_addr_t, in_addr_t);
extern struct rt_entry *rtfind(in_addr_t);
extern void	rtinit(void);
extern void	rtadd(in_addr_t, in_addr_t, uint16_t, struct rt_spare *);
extern void	rtchange(struct rt_entry *, uint16_t, struct rt_spare *,
    char *);
extern void	rtdelete(struct rt_entry *);
extern void	rts_delete(struct rt_entry *, struct rt_spare *);
extern void	rtbad_sub(struct rt_entry *, struct interface *);
extern void	rtswitch(struct rt_entry *, struct rt_spare *);

#define	S_ADDR(x)	(((struct sockaddr_in *)(x))->sin_addr.s_addr)
#define	INFO_DST(I)	((I)->rti_info[RTAX_DST])
#define	INFO_GATE(I)	((I)->rti_info[RTAX_GATEWAY])
#define	INFO_MASK(I)	((I)->rti_info[RTAX_NETMASK])
#define	INFO_AUTHOR(I)	((I)->rti_info[RTAX_AUTHOR])

struct rewire_data {
	struct interface *if_old;
	struct interface *if_new;
	int metric_delta;
};

extern char *qstring(const uchar_t *, int);
extern in_addr_t std_mask(in_addr_t);
extern int parse_quote(char **, const char *, char *, char *, int);
extern in_addr_t ripv1_mask_net(in_addr_t, const struct interface *);
extern in_addr_t ripv1_mask_host(in_addr_t, const struct interface *);
#define	on_net(a, net, mask)	(((ntohl(a) ^ (net)) & (mask)) == 0)
extern boolean_t check_dst(in_addr_t);
extern boolean_t remote_address_ok(struct interface *, in_addr_t);
extern struct interface *check_dup(const char *, in_addr_t, in_addr_t,
    in_addr_t, uint64_t, boolean_t);
extern boolean_t check_remote(struct interface *);
extern void iftbl_alloc(void);
extern void ifscan(void);
extern int walk_bad(struct radix_node *, void *);
extern int walk_rewire(struct radix_node *, void *);
extern void if_ok(struct interface *, const char *, boolean_t);
extern void if_sick(struct interface *, boolean_t);
extern void if_link(struct interface *, uint32_t);
extern struct interface *ifwithaddr(in_addr_t, boolean_t, boolean_t);
extern struct interface *ifwithindex(ulong_t, boolean_t);
extern struct interface *ifwithname(const char *);
extern struct physical_interface *phys_byname(const char *);
extern boolean_t addr_on_ifp(in_addr_t, struct interface *,
    struct interface **);
extern struct interface *findremoteif(in_addr_t);
extern struct interface *findifaddr(in_addr_t);
extern struct interface *iflookup(in_addr_t);
extern struct auth *find_auth(struct interface *);
extern void end_md5_auth(struct ws_buf *, struct auth *);
extern void rip_mcast_on(struct interface *);
extern void rip_mcast_off(struct interface *);
extern void trace_dump();
extern int sendtoif(int, const void *, uint_t, uint_t, struct sockaddr_in *,
    uint_t);

#ifdef	__cplusplus
}
#endif

#endif /* _DEFS_H */
