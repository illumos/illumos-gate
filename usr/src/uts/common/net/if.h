/*
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NET_IF_H
#define	_NET_IF_H

/* if.h 1.26 90/05/29 SMI; from UCB 7.1 6/4/86		*/

#include <sys/feature_tests.h>

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#include <sys/socket.h>
#include <netinet/in.h>
#if defined(_LP64)
#include <sys/types32.h>
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structures defining a network interface, providing a packet
 * transport mechanism (ala level 0 of the PUP protocols).
 *
 * Each interface accepts output datagrams of a specified maximum
 * length, and provides higher level routines with input datagrams
 * received from its medium.
 *
 * Output occurs when the routine if_output is called, with three parameters:
 *	(*ifp->if_output)(ifp, m, dst)
 * Here m is the mbuf chain to be sent and dst is the destination address.
 * The output routine encapsulates the supplied datagram if necessary,
 * and then transmits it on its medium.
 *
 * On input, each interface unwraps the data received by it, and either
 * places it on the input queue of a internetwork datagram routine
 * and posts the associated software interrupt, or passes the datagram to a raw
 * packet input routine.
 *
 * Routines exist for locating interfaces by their addresses
 * or for locating a interface on a certain network, as well as more general
 * routing and gateway routines maintaining information used to locate
 * interfaces.  These routines live in the files if.c and route.c
 */

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)

/*
 * Structure defining a queue for a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */
struct ifnet {
	char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	short	if_unit;		/* sub-unit for lower level driver */
	short	if_mtu;			/* maximum transmission unit */
	short	if_flags;		/* up/down, broadcast, etc. */
	short	if_timer;		/* time 'til if_watchdog called */
	ushort_t if_promisc;		/* net # of requests for promisc mode */
	int	if_metric;		/* routing metric (external only) */
	struct	ifaddr *if_addrlist;	/* linked list of addresses per if */
	struct	ifqueue {
		struct	mbuf *ifq_head;
		struct	mbuf *ifq_tail;
		int	ifq_len;
		int	ifq_maxlen;
		int	ifq_drops;
	} if_snd;			/* output queue */
/* procedure handles */
	int	(*if_init)();		/* init routine */
	int	(*if_output)();		/* output routine */
	int	(*if_ioctl)();		/* ioctl routine */
	int	(*if_reset)();		/* bus reset routine */
	int	(*if_watchdog)();	/* timer routine */
/* generic interface statistics */
	int	if_ipackets;		/* packets received on interface */
	int	if_ierrors;		/* input errors on interface */
	int	if_opackets;		/* packets sent on interface */
	int	if_oerrors;		/* output errors on interface */
	int	if_collisions;		/* collisions on csma interfaces */
/* end statistics */
	struct	ifnet *if_next;
	struct	ifnet *if_upper;	/* next layer up */
	struct	ifnet *if_lower;	/* next layer down */
	int	(*if_input)();		/* input routine */
	int	(*if_ctlin)();		/* control input routine */
	int	(*if_ctlout)();		/* control output routine */
	struct map *if_memmap;		/* rmap for interface specific memory */
};

/*
 * NOTE : These flags are not directly used within IP.
 * ip_if.h has definitions derived from this which is used within IP.
 * If you define a flag here, you need to define one in ip_if.h before
 * using the new flag in IP. Don't use these flags directly in IP.
 */
#define	IFF_UP		0x0000000001	/* address is up */
#define	IFF_BROADCAST	0x0000000002	/* broadcast address valid */
#define	IFF_DEBUG	0x0000000004	/* turn on debugging */
#define	IFF_LOOPBACK	0x0000000008	/* is a loopback net */

#define	IFF_POINTOPOINT	0x0000000010	/* interface is point-to-point link */
#define	IFF_NOTRAILERS	0x0000000020	/* avoid use of trailers */
#define	IFF_RUNNING	0x0000000040	/* resources allocated */
#define	IFF_NOARP	0x0000000080	/* no address resolution protocol */

#define	IFF_PROMISC	0x0000000100	/* receive all packets */
#define	IFF_ALLMULTI	0x0000000200	/* receive all multicast packets */
#define	IFF_INTELLIGENT	0x0000000400	/* protocol code on board */
/*
 * The IFF_MULTICAST flag indicates that the network can support the
 * transmission and reception of higher-level (e.g., IP) multicast packets.
 * It is independent of hardware support for multicasting; for example,
 * point-to-point links or pure broadcast networks may well support
 * higher-level multicasts.
 */
#define	IFF_MULTICAST	0x0000000800	/* supports multicast */

#define	IFF_MULTI_BCAST	0x0000001000	/* multicast using broadcast address */
#define	IFF_UNNUMBERED	0x0000002000	/* non-unique address */
#define	IFF_DHCPRUNNING	0x0000004000	/* DHCP controls this interface */
#define	IFF_PRIVATE	0x0000008000	/* do not advertise */

/*
 * The following flags can't be grabbed or altered by SIOC[GS]IFFLAGS.
 * Should use SIOC[GS]LIFFLAGS which has a larger flags field.
 */
#define	IFF_NOXMIT	0x0000010000	/* Do not transmit packets */
#define	IFF_NOLOCAL	0x0000020000	/* No address - just on-link subnet */
#define	IFF_DEPRECATED	0x0000040000	/* Address is deprecated */
#define	IFF_ADDRCONF	0x0000080000	/* address from stateless addrconf */

#define	IFF_ROUTER	0x0000100000	/* router on this interface */
#define	IFF_NONUD	0x0000200000	/* No NUD on this interface */
#define	IFF_ANYCAST	0x0000400000	/* Anycast address */
#define	IFF_NORTEXCH	0x0000800000	/* Do not exchange routing info */

#define	IFF_IPV4	0x0001000000	/* IPv4 interface */
#define	IFF_IPV6	0x0002000000	/* IPv6 interface */
#define	IFF_NOACCEPT	0x0004000000	/* no-accept mode VRRP ill */
#define	IFF_NOFAILOVER	0x0008000000	/* in.mpathd(1M) test address */

#define	IFF_FAILED	0x0010000000	/* Interface has failed */
#define	IFF_STANDBY	0x0020000000	/* Interface is a hot-spare */
#define	IFF_INACTIVE	0x0040000000	/* Functioning but not used for data */
#define	IFF_OFFLINE	0x0080000000	/* Interface is offline */

/*
 * The IFF_XRESOLV flag is an evolving interface and is subject
 * to change without notice.
 */
#define	IFF_XRESOLV	0x0100000000ll	/* IPv6 external resolver */
#define	IFF_COS_ENABLED	0x0200000000ll	/* If interface supports CoS marking */
#define	IFF_PREFERRED	0x0400000000ll	/* Prefer as source address */
#define	IFF_TEMPORARY	0x0800000000ll	/* RFC3041 */

#define	IFF_FIXEDMTU	0x1000000000ll	/* MTU manually set with SIOCSLIFMTU */
#define	IFF_VIRTUAL	0x2000000000ll	/* Does not send or receive packets */
#define	IFF_DUPLICATE	0x4000000000ll	/* Local address already in use */
#define	IFF_IPMP	0x8000000000ll	/* IPMP IP interface */
#define	IFF_VRRP	0x10000000000ll	/* Managed by VRRP */

#define	IFF_NOLINKLOCAL	0x20000000000ll	/* No default linklocal */
#define	IFF_L3PROTECT	0x40000000000ll	/* Layer-3 protection enforced */

/* flags that cannot be changed by userland on any interface */
#define	IFF_CANTCHANGE \
	(IFF_BROADCAST | IFF_POINTOPOINT | IFF_RUNNING | IFF_PROMISC | \
	IFF_MULTICAST | IFF_MULTI_BCAST | IFF_UNNUMBERED | IFF_IPV4 | \
	IFF_IPV6 | IFF_IPMP | IFF_FIXEDMTU | IFF_VIRTUAL | \
	IFF_LOOPBACK | IFF_ALLMULTI | IFF_DUPLICATE | IFF_COS_ENABLED | \
	IFF_VRRP | IFF_NOLINKLOCAL | IFF_L3PROTECT)

/* flags that cannot be changed by userland on an IPMP interface */
#define	IFF_IPMP_CANTCHANGE 	IFF_FAILED

/* flags that can never be set on an IPMP interface */
#define	IFF_IPMP_INVALID	(IFF_STANDBY | IFF_INACTIVE | IFF_OFFLINE | \
	IFF_NOFAILOVER | IFF_NOARP | IFF_NONUD | IFF_XRESOLV | IFF_NOACCEPT)

/*
 * Output queues (ifp->if_snd) and internetwork datagram level (pup level 1)
 * input routines have queues of messages stored on ifqueue structures
 * (defined above).  Entries are added to and deleted from these structures
 * by these macros, which should be called with ipl raised to splimp().
 */
#define	IF_QFULL(ifq)		((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define	IF_DROP(ifq)		((ifq)->ifq_drops++)
#define	IF_ENQUEUE(ifq, m) { \
	(m)->m_act = 0; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_head = m; \
	else \
		(ifq)->ifq_tail->m_act = m; \
	(ifq)->ifq_tail = m; \
	(ifq)->ifq_len++; \
}
#define	IF_PREPEND(ifq, m) { \
	(m)->m_act = (ifq)->ifq_head; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_tail = (m); \
	(ifq)->ifq_head = (m); \
	(ifq)->ifq_len++; \
}

/*
 * Packets destined for level-1 protocol input routines
 * have a pointer to the receiving interface prepended to the data.
 * IF_DEQUEUEIF extracts and returns this pointer when dequeuing the packet.
 * IF_ADJ should be used otherwise to adjust for its presence.
 */
#define	IF_ADJ(m) { \
	(m)->m_off += sizeof (struct ifnet *); \
	(m)->m_len -= sizeof (struct ifnet *); \
	if ((m)->m_len == 0) { \
		struct mbuf *n; \
		MFREE((m), n); \
		(m) = n; \
	} \
}
#define	IF_DEQUEUEIF(ifq, m, ifp) { \
	(m) = (ifq)->ifq_head; \
	if (m) { \
		if (((ifq)->ifq_head = (m)->m_act) == 0) \
			(ifq)->ifq_tail = 0; \
		(m)->m_act = 0; \
		(ifq)->ifq_len--; \
		(ifp) = *(mtod((m), struct ifnet **)); \
		IF_ADJ(m); \
	} \
}
#define	IF_DEQUEUE(ifq, m) { \
	(m) = (ifq)->ifq_head; \
	if (m) { \
		if (((ifq)->ifq_head = (m)->m_act) == 0) \
			(ifq)->ifq_tail = 0; \
		(m)->m_act = 0; \
		(ifq)->ifq_len--; \
	} \
}

#define	IFQ_MAXLEN	50
#define	IFNET_SLOWHZ	1		/* granularity is 1 second */

/*
 * The ifaddr structure contains information about one address
 * of an interface.  They are maintained by the different address families,
 * are allocated and attached when an address is set, and are linked
 * together so all addresses for an interface can be located.
 */
struct ifaddr {
	struct	sockaddr ifa_addr;	/* address of interface */
	union {
		struct	sockaddr ifu_broadaddr;
		struct	sockaddr ifu_dstaddr;
	} ifa_ifu;
#define	ifa_broadaddr	ifa_ifu.ifu_broadaddr	/* broadcast address */
#define	ifa_dstaddr	ifa_ifu.ifu_dstaddr	/* other end of p-to-p link */
	struct	ifnet *ifa_ifp;		/* back-pointer to interface */
	struct	ifaddr *ifa_next;	/* next address for interface */
};

/*
 * For SIOCLIF*ND ioctls.
 *
 * The lnr_state_* fields use the ND_* neighbor reachability states.
 * The 3 different fields are for use with SIOCLIFSETND to cover the cases
 * when
 *	A new entry is created
 *	The entry already exists and the link-layer address is the same
 *	The entry already exists and the link-layer address differs
 *
 * Use ND_UNCHANGED to not change any state.
 */
#define	ND_MAX_HDW_LEN	64
typedef struct lif_nd_req {
	struct sockaddr_storage	lnr_addr;
	uint8_t			lnr_state_create;	/* When creating */
	uint8_t			lnr_state_same_lla;	/* Update same addr */
	uint8_t			lnr_state_diff_lla;	/* Update w/ diff. */
	int			lnr_hdw_len;
	int			lnr_flags;		/* See below */
	/* padding because ia32 "long long"s are only 4-byte aligned. */
	int			lnr_pad0;
	char			lnr_hdw_addr[ND_MAX_HDW_LEN];
} lif_nd_req_t;

/*
 * Neighbor reachability states
 * Used with SIOCLIF*ND ioctls.
 */
#define	ND_UNCHANGED	0	/* For ioctls that don't modify state */
#define	ND_INCOMPLETE	1	/* addr resolution in progress */
#define	ND_REACHABLE	2	/* have recently been reachable */
#define	ND_STALE	3	/* may be unreachable, don't do anything */
#define	ND_DELAY	4	/* wait for upper layer hint */
#define	ND_PROBE	5	/* send probes */
#define	ND_UNREACHABLE	6	/* delete this route */
#define	ND_INITIAL	7	/* ipv4: arp resolution has not been sent yet */

#define	ND_STATE_VALID_MIN	0
#define	ND_STATE_VALID_MAX	7

/*
 * lnr_flags value of lif_nd_req.
 * Used with SIOCLIF*ND ioctls.
 */
#define	NDF_ISROUTER_ON		0x1
#define	NDF_ISROUTER_OFF	0x2
#define	NDF_ANYCAST_ON		0x4
#define	NDF_ANYCAST_OFF		0x8
#define	NDF_PROXY_ON		0x10
#define	NDF_PROXY_OFF		0x20
/*
 * the NDF_STATIC entry ensures that an NCE will not be deleted, and is
 * used by non-ON applications like IPv6 test suites.
 */
#define	NDF_STATIC		0x40

/* For SIOC[GS]LIFLNKINFO */
typedef struct lif_ifinfo_req {
	uint8_t		lir_maxhops;
	uint32_t	lir_reachtime;		/* Reachable time in msec */
	uint32_t	lir_reachretrans;	/* Retransmission timer msec */
	uint32_t	lir_maxmtu;
} lif_ifinfo_req_t;

#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

/*
 * Maximum lengths of interface name and IPMP group name; these are the same
 * for historical reasons.  Note that the actual maximum length of a name is
 * one byte less than these constants since the kernel always sets the final
 * byte of lifr_name and lifr_groupname to NUL.
 */
#define	_LIFNAMSIZ	32

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)

#define	LIFNAMSIZ	_LIFNAMSIZ
#define	LIFGRNAMSIZ	LIFNAMSIZ

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 * Note: This data structure uses 64bit type uint64_t which is not
 *	 a valid type for strict ANSI/ISO C compilation for ILP32.
 *	 Applications with ioctls using this structure that insist on
 *	 building with strict ANSI/ISO C (-Xc) will need to be LP64.
 */
#if defined(_INT64_TYPE)
struct	lifreq {
	char	lifr_name[LIFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		int	lifru_addrlen;		/* for subnet/token etc */
		uint_t	lifru_ppa;		/* SIOCSLIFNAME */
	} lifr_lifru1;
#define	lifr_addrlen	lifr_lifru1.lifru_addrlen
#define	lifr_ppa	lifr_lifru1.lifru_ppa	/* Driver's ppa */
	uint_t		lifr_type;		/* IFT_ETHER, ... */
	union {
		struct	sockaddr_storage lifru_addr;
		struct	sockaddr_storage lifru_dstaddr;
		struct	sockaddr_storage lifru_broadaddr;
		struct	sockaddr_storage lifru_token;	/* With lifr_addrlen */
		struct	sockaddr_storage lifru_subnet;	/* With lifr_addrlen */
		int	lifru_index;		/* interface index */
		uint64_t lifru_flags;		/* Flags for SIOC?LIFFLAGS */
		int	lifru_metric;
		uint_t	lifru_mtu;
		int	lif_muxid[2];		/* mux id's for arp and ip */
		struct lif_nd_req	lifru_nd_req; /* SIOCLIF*ND */
		struct lif_ifinfo_req	lifru_ifinfo_req;
		char	lifru_groupname[LIFGRNAMSIZ]; /* SIOC[GS]LIFGROUPNAME */
		char	lifru_binding[LIFNAMSIZ]; /* SIOCGLIFBINDING */
		zoneid_t lifru_zoneid;		/* SIOC[GS]LIFZONE */
		uint_t	lifru_dadstate;		/* SIOCGLIFDADSTATE */
	} lifr_lifru;

#define	lifr_addr	lifr_lifru.lifru_addr	/* address */
#define	lifr_dstaddr	lifr_lifru.lifru_dstaddr /* other end of p-to-p link */
#define	lifr_broadaddr	lifr_lifru.lifru_broadaddr /* broadcast address */
#define	lifr_token	lifr_lifru.lifru_token	/* address token */
#define	lifr_subnet	lifr_lifru.lifru_subnet	/* subnet prefix */
#define	lifr_index	lifr_lifru.lifru_index	/* interface index */
#define	lifr_flags	lifr_lifru.lifru_flags	/* flags */
#define	lifr_metric	lifr_lifru.lifru_metric	/* metric */
#define	lifr_mtu	lifr_lifru.lifru_mtu	/* mtu */
#define	lifr_ip_muxid	lifr_lifru.lif_muxid[0]
#define	lifr_arp_muxid	lifr_lifru.lif_muxid[1]
#define	lifr_nd		lifr_lifru.lifru_nd_req	/* SIOCLIF*ND */
#define	lifr_ifinfo	lifr_lifru.lifru_ifinfo_req /* SIOC[GS]LIFLNKINFO */
#define	lifr_groupname	lifr_lifru.lifru_groupname
#define	lifr_binding	lifr_lifru.lifru_binding
#define	lifr_zoneid	lifr_lifru.lifru_zoneid
#define	lifr_dadstate	lifr_lifru.lifru_dadstate
};
#endif /* defined(_INT64_TYPE) */

/*
 * Argument structure for SIOCT* address testing ioctls.
 */
struct sioc_addrreq {
	struct sockaddr_storage	sa_addr;	/* Address to test */
	int			sa_res;		/* Result - 0/1 */
	int			sa_pad;
};

/*
 * Argument structure used by mrouted to get src-grp pkt counts using
 * SIOCGETLSGCNT. See <netinet/ip_mroute.h>.
 */
struct sioc_lsg_req {
	struct sockaddr_storage	slr_src;
	struct sockaddr_storage	slr_grp;
	uint_t			slr_pktcnt;
	uint_t			slr_bytecnt;
	uint_t			slr_wrong_if;
	uint_t			slr_pad;
};

/* Argument structure for SIOCGLIFDADSTATE ioctl */
typedef enum {
	DAD_IN_PROGRESS	= 0x1,
	DAD_DONE	= 0x2
} glif_dad_state_t;

/*
 * OBSOLETE: Replaced by struct lifreq. Supported for compatibility.
 *
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */
struct	ifreq {
#define	IFNAMSIZ	16
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		char	ifru_oname[IFNAMSIZ];	/* other if name */
		struct	sockaddr ifru_broadaddr;
		int	ifru_index;		/* interface index */
		uint_t	ifru_mtu;
		short	ifru_flags;
		int	ifru_metric;
		char	ifru_data[1];		/* interface dependent data */
		char	ifru_enaddr[6];
		int	if_muxid[2];		/* mux id's for arp and ip */

		/* Struct for flags/ppa */
		struct ifr_ppaflags {
			short ifrup_flags;	/* Space of ifru_flags. */
			short ifrup_filler;
			uint_t ifrup_ppa;
		} ifru_ppaflags;

		/* Struct for FDDI ioctl's */
		struct ifr_dnld_reqs {
			uint32_t	v_addr;
			uint32_t	m_addr;
			uint32_t	ex_addr;
			uint32_t	size;
		} ifru_dnld_req;

		/* Struct for FDDI stats */
		struct ifr_fddi_stats {
			uint32_t stat_size;
			uint32_t fddi_stats;
		} ifru_fddi_stat;

		struct ifr_netmapents {
			uint32_t map_ent_size,	/* size of netmap structure */
				entry_number;	/* index into netmap list */
			uint32_t fddi_map_ent;	/* pointer to user structure */
		} ifru_netmapent;

		/* Field for generic ioctl for fddi */

		struct ifr_fddi_gen_struct {
			uint32_t ifru_fddi_gioctl; /* field for gen ioctl */
			uint32_t ifru_fddi_gaddr;  /* Generic ptr to a field */
		} ifru_fddi_gstruct;

	} ifr_ifru;

#define	ifr_addr	ifr_ifru.ifru_addr	/* address */
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-to-p link */
#define	ifr_oname	ifr_ifru.ifru_oname	/* other if name */
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address */
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags */
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric */
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface */
#define	ifr_enaddr	ifr_ifru.ifru_enaddr	/* ethernet address */
#define	ifr_index	ifr_ifru.ifru_index	/* interface index */
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu */
/* For setting ppa */
#define	ifr_ppa		ifr_ifru.ifru_ppaflags.ifrup_ppa

/* FDDI specific */
#define	ifr_dnld_req	ifr_ifru.ifru_dnld_req
#define	ifr_fddi_stat	ifr_ifru.ifru_fddi_stat
#define	ifr_fddi_netmap	ifr_ifru.ifru_netmapent	/* FDDI network map entries */
#define	ifr_fddi_gstruct ifr_ifru.ifru_fddi_gstruct

#define	ifr_ip_muxid	ifr_ifru.if_muxid[0]
#define	ifr_arp_muxid	ifr_ifru.if_muxid[1]
};

/* Used by SIOCGLIFNUM. Uses same flags as in struct lifconf */
struct lifnum {
	sa_family_t	lifn_family;
	int		lifn_flags;	/* request specific interfaces */
	int		lifn_count;	/* Result */
};

/*
 * Structure used in SIOCGLIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible) for a given address family.
 * Using AF_UNSPEC will retrieve all address families.
 */
struct	lifconf {
	sa_family_t	lifc_family;
	int		lifc_flags;	/* request specific interfaces */
	int		lifc_len;	/* size of associated buffer */
	union {
		caddr_t	lifcu_buf;
		struct	lifreq *lifcu_req;
	} lifc_lifcu;
#define	lifc_buf lifc_lifcu.lifcu_buf	/* buffer address */
#define	lifc_req lifc_lifcu.lifcu_req	/* array of structures returned */
};

/*
 * Structure used in SIOCGLIFSRCOF to get the interface
 * configuration list for those interfaces that use an address
 * hosted on the interface (set in lifs_ifindex), as the source
 * address.
 */
struct lifsrcof {
	uint_t	lifs_ifindex;	/* interface of interest */
	size_t  lifs_maxlen;	/* size of buffer: input */
	size_t  lifs_len;	/* size of buffer: output */
	union {
		caddr_t	lifsu_buf;
		struct	lifreq *lifsu_req;
	} lifs_lifsu;
#define	lifs_buf lifs_lifsu.lifsu_buf /* buffer address */
#define	lifs_req lifs_lifsu.lifsu_req /* array returned */
};

/* Flags */
#define	LIFC_NOXMIT	0x01		/* Include IFF_NOXMIT interfaces */
#define	LIFC_EXTERNAL_SOURCE	0x02	/* Exclude the interfaces which can't */
					/* be used to communicate outside the */
					/* node (exclude interfaces which are */
					/* IFF_NOXMIT, IFF_NOLOCAL, */
					/* IFF_LOOPBACK, IFF_DEPRECATED, or */
					/* not IFF_UP). Has priority over */
					/* LIFC_NOXMIT. */
#define	LIFC_TEMPORARY	0x04		/* Include IFF_TEMPORARY interfaces */
#define	LIFC_ALLZONES	0x08		/* Include all zones */
					/* (must be issued from global zone) */
#define	LIFC_UNDER_IPMP	0x10		/* Include underlying IPMP interfaces */
#define	LIFC_ENABLED	0x20		/* Include only IFF_UP interfaces */

#if defined(_SYSCALL32)

struct	lifconf32 {
	sa_family_t	lifc_family;
	int		lifc_flags;	/* request specific interfaces */
	int32_t	lifc_len;		/* size of associated buffer */
	union {
		caddr32_t lifcu_buf;
		caddr32_t lifcu_req;
	} lifc_lifcu;
};

struct lifsrcof32 {
	uint_t	lifs_ifindex;	/* interface of interest */
	size32_t  lifs_maxlen;	/* size of buffer: input */
	size32_t  lifs_len;	/* size of buffer: output */
	union {
		caddr32_t lifsu_buf;
		caddr32_t lifsu_req;
	} lifs_lifsu;
};

#endif	/* _SYSCALL32 */

/*
 * IPMP group information, for use with SIOCGLIFGROUPINFO.
 */
typedef struct lifgroupinfo {
	char		gi_grname[LIFGRNAMSIZ];	/* group name (set by caller) */
	char		gi_grifname[LIFNAMSIZ];	/* IPMP meta-interface name */
	char		gi_m4ifname[LIFNAMSIZ];	/* v4 mcast interface name */
	char		gi_m6ifname[LIFNAMSIZ];	/* v6 mcast interface name */
	char		gi_bcifname[LIFNAMSIZ];	/* v4 bcast interface name */
	boolean_t	gi_v4;			/* group is plumbed for v4 */
	boolean_t	gi_v6; 			/* group is plumbed for v6 */
	uint_t		gi_nv4;			/* # of underlying v4 if's */
	uint_t		gi_nv6;			/* # of underlying v6 if's */
	uint_t		gi_mactype; 		/* DLPI mac type of group */
} lifgroupinfo_t;

/*
 * OBSOLETE: Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */
struct	ifconf {
	int	ifc_len;		/* size of associated buffer */
	union {
		caddr_t	ifcu_buf;
		struct	ifreq *ifcu_req;
	} ifc_ifcu;
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* buffer address */
#define	ifc_req	ifc_ifcu.ifcu_req	/* array of structures returned */
};

#if defined(_SYSCALL32)

struct	ifconf32 {
	int32_t	ifc_len;		/* size of associated buffer */
	union {
		caddr32_t ifcu_buf;
		caddr32_t ifcu_req;
	} ifc_ifcu;
};

#endif	/* _SYSCALL32 */

typedef struct if_data {
				/* generic interface information */
	uchar_t	ifi_type;	/* ethernet, tokenring, etc */
	uchar_t	ifi_addrlen;	/* media address length */
	uchar_t	ifi_hdrlen;	/* media header length */
	uint_t	ifi_mtu;	/* maximum transmission unit */
	uint_t	ifi_metric;	/* routing metric (external only) */
	uint_t	ifi_baudrate;	/* linespeed */
				/* volatile statistics */
	uint_t	ifi_ipackets;	/* packets received on interface */
	uint_t	ifi_ierrors;	/* input errors on interface */
	uint_t	ifi_opackets;	/* packets sent on interface */
	uint_t	ifi_oerrors;	/* output errors on interface */
	uint_t	ifi_collisions;	/* collisions on csma interfaces */
	uint_t	ifi_ibytes;	/* total number of octets received */
	uint_t	ifi_obytes;	/* total number of octets sent */
	uint_t	ifi_imcasts;	/* packets received via multicast */
	uint_t	ifi_omcasts;	/* packets sent via multicast */
	uint_t	ifi_iqdrops;	/* dropped on input, this interface */
	uint_t	ifi_noproto;	/* destined for unsupported protocol */
#if defined(_LP64)
	struct	timeval32 ifi_lastchange; /* last updated */
#else
	struct	timeval ifi_lastchange; /* last updated */
#endif
} if_data_t;

/*
 * Message format for use in obtaining information about interfaces
 * from the routing socket
 */
typedef struct if_msghdr {
	ushort_t ifm_msglen;	/* to skip over non-understood messages */
	uchar_t	ifm_version;	/* future binary compatibility */
	uchar_t	ifm_type;	/* message type */
	int	ifm_addrs;	/* like rtm_addrs */
	int	ifm_flags;	/* value of if_flags */
	ushort_t ifm_index;	/* index for associated ifp */
	struct	if_data ifm_data; /* statistics and other data about if */
} if_msghdr_t;

/*
 * Message format for use in obtaining information about interface addresses
 * from the routing socket
 */
typedef struct ifa_msghdr {
	ushort_t ifam_msglen;	/* to skip over non-understood messages */
	uchar_t	ifam_version;	/* future binary compatibility */
	uchar_t	ifam_type;	/* message type */
	int	ifam_addrs;	/* like rtm_addrs */
	int	ifam_flags;	/* route flags */
	ushort_t ifam_index;	/* index for associated ifp */
	int	ifam_metric;	/* value of ipif_metric */
} ifa_msghdr_t;

#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

/*
 * The if_nameindex structure holds the interface index value about
 * a single interface. An array of this structure is used to return
 * all interfaces and indexes.
 */
struct if_nameindex {
	unsigned 	if_index;	/* positive interface index */
	char		*if_name;	/* if name, e.g. "en0" */
};

/* Interface index identification API definitions */
extern	unsigned 		if_nametoindex(const char *);
extern	char			*if_indextoname(unsigned, char *);
extern	struct if_nameindex	*if_nameindex(void);
extern	void			if_freenameindex(struct if_nameindex *);

#define	IF_NAMESIZE	_LIFNAMSIZ
/*
 * If changing IF_MAX_INDEX to a value greater than UINT16_MAX, check if
 * struct sockaddr_dl needs to be modified as the interface index is placed
 * in this structure by the kernel.
 */
#define	IF_INDEX_MAX	UINT16_MAX

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_IF_H */
