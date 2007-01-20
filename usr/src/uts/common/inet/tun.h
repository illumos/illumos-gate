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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_INET_TUN_H
#define	_INET_TUN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* tunneling module names */
#define	TUN_NAME	"tun"
#define	ATUN_NAME	"atun"
#define	TUN6TO4_NAME	"6to4tun"

/* IOCTL's for set/getting 6to4 Relay Router(RR) destination IPv4 Address */
#define	SIOCS6TO4TUNRRADDR	4	/* ipaddr_t */
#define	SIOCG6TO4TUNRRADDR	5	/* ipaddr_t */

#ifdef	_KERNEL

#include <sys/netstack.h>

#define	TUN_MODID	5134
#define	ATUN_MODID	5135
#define	TUN6TO4_MODID	5136

/*
 * We request ire information for the tunnel destination in order to obtain
 * its path MTU information.  We use that to calculate the link MTU of
 * tunnels.  If the path MTU of the tunnel destination becomes smaller than
 * the link MTU of the tunnel, then we will receive a packet too big (aka
 * fragmentation needed) ICMP error, and we will request new ire
 * information at that time.
 *
 * We also request the ire information periodically to make sure the link
 * MTU of a tunnel doesn't become stale if the path MTU of the tunnel
 * destination becomes larger than the link MTU of the tunnel.  The period
 * for the requests is ten minutes in accordance with rfc1191.
 */
#define	TUN_IRE_AGE	SEC_TO_TICK(600)
#define	TUN_IRE_TOO_OLD(atp)	(lbolt - (atp)->tun_ire_lastreq > TUN_IRE_AGE)

/*
 * The default MTU for automatic and 6to4 tunnels.  We make this as large
 * as possible.  These tunnels communicate with an unknown number of other
 * tunnel endpoints that have potentially differing path MTU's.  We let
 * IPv4 fragmentation take care of packets that are too large.
 */
#define	ATUN_MTU	(IP_MAXPACKET - sizeof (ipha_t))

struct	tunstat {
	struct	kstat_named	tuns_nocanput;
	struct	kstat_named	tuns_xmtretry;
	struct	kstat_named	tuns_allocbfail;

	struct	kstat_named	tuns_ipackets;	/* ifInUcastPkts */
	struct	kstat_named	tuns_opackets;	/* ifOutUcastPkts */
	struct	kstat_named	tuns_InErrors;
	struct	kstat_named	tuns_OutErrors;

	struct  kstat_named	tuns_rcvbytes;	/* # octets received */
						/* MIB - ifInOctets */
	struct  kstat_named	tuns_xmtbytes;  /* # octets transmitted */
						/* MIB - ifOutOctets */
	struct  kstat_named	tuns_multircv;	/* # multicast packets */
						/* delivered to upper layer */
						/* MIB - ifInNUcastPkts */
	struct  kstat_named	tuns_multixmt;	/* # multicast packets */
						/* requested to be sent */
						/* MIB - ifOutNUcastPkts */
	struct  kstat_named	tuns_InDiscard;	/* # rcv packets discarded */
						/* MIB - ifInDiscards */
	struct  kstat_named	tuns_OutDiscard; /* # xmt packets discarded */
						/* MIB - ifOutDiscards */
	struct	kstat_named	tuns_HCInOctets;
	struct	kstat_named	tuns_HCInUcastPkts;
	struct	kstat_named	tuns_HCInMulticastPkts;
	struct	kstat_named	tuns_HCOutOctets;
	struct	kstat_named	tuns_HCOutUcastPkts;
	struct	kstat_named	tuns_HCOutMulticastPkts;
};

typedef struct tun_stats_s {
	/* Protected by tun_global_lock. */
	struct tun_stats_s *ts_next;
	kmutex_t	ts_lock;		/* protects from here down */
	struct tun_s	*ts_atp;
	uint_t		ts_refcnt;
	uint_t		ts_lower;
	uint_t		ts_type;
	t_uscalar_t	ts_ppa;
	kstat_t		*ts_ksp;
} tun_stats_t;

/*  Used for recovery from memory allocation failure */
typedef struct eventid_s {
	bufcall_id_t	ev_wbufcid;		/* needed for recovery */
	bufcall_id_t	ev_rbufcid;		/* needed for recovery */
	timeout_id_t	ev_wtimoutid;		/* needed for recovery */
	timeout_id_t	ev_rtimoutid;		/* needed for recovery */
} eventid_t;

/* IPv6 destination option header for tunnel encapsulation limit option. */
struct tun_encap_limit {
	ip6_dest_t		tel_destopt;
	struct ip6_opt_tunnel	tel_telopt;
	char			tel_padn[3];
};
#define	IPV6_TUN_ENCAP_OPT_LEN	(sizeof (struct tun_encap_limit))

/* per-instance data structure */
/* Note: if t_recnt > 1, then t_indirect must be null */
typedef struct tun_s {
	struct tun_s	*tun_next;	/* For linked-list of tunnels by */
	struct tun_s	**tun_ptpn;	/* ip address. */

	/* Links v4-upper and v6-upper instances so they can share kstats. */
	struct tun_s	*tun_kstat_next;

	queue_t		*tun_wq;
	kmutex_t	tun_lock;		/* protects from here down */
	eventid_t	tun_events;
	t_uscalar_t	tun_state;		/* protected by qwriter */
	t_uscalar_t	tun_ppa;
	mblk_t		*tun_iocmp;
	ipsec_req_t	tun_secinfo;
	/*
	 * tun_polcy_index is used to keep track if a tunnel's policy
	 * was altered by ipsecconf(1m)/PF_POLICY instead of ioctl()s.
	 * (Only ioctl()s can update this field.)
	 */
	uint64_t	tun_policy_index;
	struct ipsec_tun_pol_s *tun_itp;
	uint64_t	tun_itp_gen;
	uint_t		tun_ipsec_overhead;	/* Length of IPsec headers. */
	uint_t		tun_flags;
	in6_addr_t	tun_laddr;
	in6_addr_t	tun_faddr;
	zoneid_t	tun_zoneid;
	uint32_t	tun_mtu;
	uint32_t	tun_notifications;	/* For DL_NOTIFY_IND */
	int16_t		tun_encap_lim;
	uint8_t		tun_hop_limit;
	uint32_t	tun_extra_offset;
	clock_t		tun_ire_lastreq;
	union {
		ipha_t	tun_u_ipha;
		struct {
			ip6_t			tun_u_ip6h;
			struct tun_encap_limit	tun_u_telopt;
		} tun_u_ip6hdrs;
		double	tun_u_aligner;
	} tun_u;
	dev_t		tun_dev;
#define	tun_ipha		tun_u.tun_u_ipha
#define	tun_ip6h		tun_u.tun_u_ip6hdrs.tun_u_ip6h
#define	tun_telopt		tun_u.tun_u_ip6hdrs.tun_u_telopt
	tun_stats_t	*tun_stats;
	char tun_lifname[LIFNAMSIZ];
	uint32_t tun_nocanput;		/* # input canput() returned false */
	uint32_t tun_xmtretry;		/* # output canput() returned false */
	uint32_t tun_allocbfail;	/* # esballoc/allocb failed */

	/*
	 *  MIB II variables
	 */
	uint32_t tun_InDiscard;
	uint32_t tun_InErrors;
	uint32_t tun_OutDiscard;
	uint32_t tun_OutErrors;

	uint64_t tun_HCInOctets;	/* # Total Octets received */
	uint64_t tun_HCInUcastPkts;	/* # Packets delivered */
	uint64_t tun_HCInMulticastPkts;	/* # Mulitcast Packets delivered */
	uint64_t tun_HCOutOctets;	/* # Total Octets sent */
	uint64_t tun_HCOutUcastPkts;	/* # Packets requested */
	uint64_t tun_HCOutMulticastPkts; /* Multicast Packets requested */
	netstack_t	*tun_netstack;
} tun_t;


/*
 * First 4 bits of flags are used to determine what version of IP is
 * is above the tunnel or below the tunnel
 */

#define	TUN_U_V4	0x01		/* upper protocol is v4 */
#define	TUN_U_V6	0x02		/* upper protocol is v6 */
#define	TUN_L_V4	0x04		/* lower protocol is v4 */
#define	TUN_L_V6	0x08		/* lower protocol is v6 */
#define	TUN_UPPER_MASK	(TUN_U_V4 | TUN_U_V6)
#define	TUN_LOWER_MASK	(TUN_L_V4 | TUN_L_V6)

/*
 * tunnel flags
 * TUN_BOUND is set when we get the ok ack back for the T_BIND_REQ
 */
#define	TUN_BOUND		0x010	/* tunnel is bound */
#define	TUN_BIND_SENT		0x020	/* our version of dl pending */
#define	TUN_SRC			0x040	/* Source address set */
#define	TUN_DST			0x080	/* Destination address set */
#define	TUN_AUTOMATIC		0x100	/* tunnel is an automatic tunnel */
#define	TUN_FASTPATH		0x200	/* fastpath has been acked */
#define	TUN_SECURITY		0x400	/* Security properties present */
#define	TUN_HOP_LIM		0x800	/* Hop limit non-default */
#define	TUN_ENCAP_LIM		0x1000	/* Encapsulation limit non-default */
#define	TUN_6TO4		0x2000	/* tunnel is 6to4 tunnel */
#define	TUN_COMPLEX_SECURITY	0x4000	/* tunnel has full tunnel-mode policy */

struct old_iftun_req {
	char		ifta_lifr_name[LIFNAMSIZ]; /* if name */
	struct sockaddr_storage ifta_saddr;	/* source address */
	struct sockaddr_storage ifta_daddr;	/* destination address */
	uint_t		ifta_flags;		/* See below */
	/* IP version information is read only */
	enum ifta_proto	ifta_upper;		/* IP version above tunnel */
	enum ifta_proto	ifta_lower;		/* IP version below tunnel */
	uint_t		ifta_vers;		/* Version number */
	uint32_t	ifta_secinfo[IFTUN_SECINFOLEN]; /* Security prefs. */
};

#define	OSIOCGTUNPARAM	_IOR('i',  147, struct old_iftun_req)
							/* get tunnel */
							/* parameters */
#define	OSIOCSTUNPARAM	_IOW('i',  148, struct old_iftun_req)
							/* set tunnel */
							/* parameters */

/*
 * Linked list of tunnels.
 */

#define	TUN_PPA_SZ	64
#define	TUN_LIST_HASH(ppa)	((ppa) % TUN_PPA_SZ)

#define	TUN_T_SZ	251
#define	TUN_BYADDR_LIST_HASH(a) (((a).s6_addr32[3]) % (TUN_T_SZ))

/*
 * tunnel stack instances
 */
struct tun_stack {
	netstack_t	*tuns_netstack;	/* Common netstack */

	/*
	 * protects global data structures such as tun_ppa_list
	 * also protects tun_t at ts_next and *ts_atp
	 * should be acquired before ts_lock
	 */
	kmutex_t	tuns_global_lock;
	tun_stats_t	*tuns_ppa_list[TUN_PPA_SZ];
	tun_t		*tuns_byaddr_list[TUN_T_SZ];

	ipaddr_t	tuns_relay_rtr_addr_v4;
};
typedef struct tun_stack tun_stack_t;


int	tun_open(queue_t *, dev_t *, int, int, cred_t *);
int	tun_close(queue_t *, int, cred_t *);
void	tun_rput(queue_t *q, mblk_t  *mp);
void	tun_rsrv(queue_t *q);
void	tun_wput(queue_t *q, mblk_t  *mp);
void	tun_wsrv(queue_t *q);

extern void tun_ipsec_load_complete(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TUN_H */
