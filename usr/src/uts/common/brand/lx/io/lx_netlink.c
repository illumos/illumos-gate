/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Compatibility for the Linux netlink(7) kernel/user transport, as well as
 * for in-kernel netlink(7) providers like rtnetlink(7).  See RFC 3549 for
 * details of the protocol, and the Linux man pages for details of the Linux
 * implementation that we're mimicking.
 */

#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/strsun.h>
#include <sys/tihdr.h>
#include <sys/sockio.h>
#include <sys/brand.h>
#include <sys/debug.h>
#include <sys/ucred.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_impl.h>
#include <inet/ip_ire.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_socket.h>
#include <sys/lx_impl.h>
#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <sys/policy.h>

/*
 * Flags in netlink header
 */
#define	LX_NETLINK_NLM_F_REQUEST		1
#define	LX_NETLINK_NLM_F_MULTI			2
#define	LX_NETLINK_NLM_F_ACK			4
#define	LX_NETLINK_NLM_F_ECHO			8
#define	LX_NETLINK_NLM_F_DUMP_INTR		16
#define	LX_NETLINK_NLM_F_ROOT			0x100
#define	LX_NETLINK_NLM_F_MATCH			0x200
#define	LX_NETLINK_NLM_F_ATOMIC			0x400

/*
 * Generic message type constants
 */
#define	LX_NETLINK_NLMSG_NONE			0
#define	LX_NETLINK_NLMSG_NOOP			1
#define	LX_NETLINK_NLMSG_ERROR			2
#define	LX_NETLINK_NLMSG_DONE			3
#define	LX_NETLINK_NLMSG_OVERRUN		4

/*
 * Protocol constants.
 */
#define	LX_NETLINK_ROUTE			0
#define	LX_NETLINK_UNUSED			1
#define	LX_NETLINK_USERSOCK			2
#define	LX_NETLINK_FIREWALL			3
#define	LX_NETLINK_SOCK_DIAG			4
#define	LX_NETLINK_NFLOG			5
#define	LX_NETLINK_XFRM				6
#define	LX_NETLINK_SELINUX			7
#define	LX_NETLINK_ISCSI			8
#define	LX_NETLINK_AUDIT			9
#define	LX_NETLINK_FIB_LOOKUP			10
#define	LX_NETLINK_CONNECTOR			11
#define	LX_NETLINK_NETFILTER			12
#define	LX_NETLINK_IP6_FW			13
#define	LX_NETLINK_DNRTMSG			14
#define	LX_NETLINK_KOBJECT_UEVENT		15
#define	LX_NETLINK_GENERIC			16
#define	LX_NETLINK_SCSITRANSPORT		18
#define	LX_NETLINK_ECRYPTFS			19
#define	LX_NETLINK_RDMA				20
#define	LX_NETLINK_CRYPTO			21

/*
 * rtnetlink(7) attribute-related constants
 */
#define	LX_NETLINK_NLA_ALIGNTO			4

#define	LX_NETLINK_RTM_NEWLINK			16
#define	LX_NETLINK_RTM_DELLINK			17
#define	LX_NETLINK_RTM_GETLINK			18
#define	LX_NETLINK_RTM_SETLINK			19
#define	LX_NETLINK_RTM_NEWADDR			20
#define	LX_NETLINK_RTM_DELADDR			21
#define	LX_NETLINK_RTM_GETADDR			22
#define	LX_NETLINK_RTM_NEWROUTE			24
#define	LX_NETLINK_RTM_DELROUTE			25
#define	LX_NETLINK_RTM_GETROUTE			26
#define	LX_NETLINK_RTM_NEWNEIGH			28
#define	LX_NETLINK_RTM_DELNEIGH			29
#define	LX_NETLINK_RTM_GETNEIGH			30
#define	LX_NETLINK_RTM_NEWRULE			32
#define	LX_NETLINK_RTM_DELRULE			33
#define	LX_NETLINK_RTM_GETRULE			34
#define	LX_NETLINK_RTM_NEWQDISC			36
#define	LX_NETLINK_RTM_DELQDISC			37
#define	LX_NETLINK_RTM_GETQDISC			38
#define	LX_NETLINK_RTM_NEWTCLASS		40
#define	LX_NETLINK_RTM_DELTCLASS		41
#define	LX_NETLINK_RTM_GETTCLASS		42
#define	LX_NETLINK_RTM_NEWTFILTER		44
#define	LX_NETLINK_RTM_DELTFILTER		45
#define	LX_NETLINK_RTM_GETTFILTER		46
#define	LX_NETLINK_RTM_NEWACTION		48
#define	LX_NETLINK_RTM_DELACTION		49
#define	LX_NETLINK_RTM_GETACTION		50
#define	LX_NETLINK_RTM_NEWPREFIX		52
#define	LX_NETLINK_RTM_GETMULTICAST		58
#define	LX_NETLINK_RTM_GETANYCAST		62
#define	LX_NETLINK_RTM_NEWNEIGHTBL		64
#define	LX_NETLINK_RTM_GETNEIGHTBL		66
#define	LX_NETLINK_RTM_SETNEIGHTBL		67
#define	LX_NETLINK_RTM_NEWNDUSEROPT		68
#define	LX_NETLINK_RTM_NEWADDRLABEL		72
#define	LX_NETLINK_RTM_DELADDRLABEL		73
#define	LX_NETLINK_RTM_GETADDRLABEL		74
#define	LX_NETLINK_RTM_GETDCB			78
#define	LX_NETLINK_RTM_SETDCB			79
#define	LX_NETLINK_RTM_NEWNETCONF		80
#define	LX_NETLINK_RTM_GETNETCONF		82
#define	LX_NETLINK_RTM_NEWMDB			84
#define	LX_NETLINK_RTM_DELMDB			85
#define	LX_NETLINK_RTM_GETMDB			86
#define	LX_NETLINK_RTM_MAX			87

/*
 * rtnetlink(7) attribute constants
 */
#define	LX_NETLINK_RTA_UNSPEC		0
#define	LX_NETLINK_RTA_DST		1
#define	LX_NETLINK_RTA_SRC		2
#define	LX_NETLINK_RTA_IIF		3
#define	LX_NETLINK_RTA_OIF		4
#define	LX_NETLINK_RTA_GATEWAY		5
#define	LX_NETLINK_RTA_PRIORITY		6
#define	LX_NETLINK_RTA_PREFSRC		7
#define	LX_NETLINK_RTA_METRICS		8
#define	LX_NETLINK_RTA_MULTIPATH	9
#define	LX_NETLINK_RTA_PROTOINFO	10
#define	LX_NETLINK_RTA_FLOW		11
#define	LX_NETLINK_RTA_CACHEINFO	12
#define	LX_NETLINK_RTA_SESSION		13
#define	LX_NETLINK_RTA_MP_ALGO		14
#define	LX_NETLINK_RTA_TABLE		15
#define	LX_NETLINK_RTA_MARK		16
#define	LX_NETLINK_RTA_MFC_STATS	17
#define	LX_NETLINK_MAX_RTA	LX_NETLINK_RTA_MFC_STATS

/*
 * rtnetlink(7) NEWLINK/DELLINK/GETLINK constants
 */
#define	LX_NETLINK_IFLA_UNSPEC			0
#define	LX_NETLINK_IFLA_ADDRESS			1
#define	LX_NETLINK_IFLA_BROADCAST		2
#define	LX_NETLINK_IFLA_IFNAME			3
#define	LX_NETLINK_IFLA_MTU			4
#define	LX_NETLINK_IFLA_LINK			5
#define	LX_NETLINK_IFLA_QDISC			6
#define	LX_NETLINK_IFLA_STATS			7
#define	LX_NETLINK_IFLA_COST			8
#define	LX_NETLINK_IFLA_PRIORITY		9
#define	LX_NETLINK_IFLA_MASTER			10
#define	LX_NETLINK_IFLA_WIRELESS		11
#define	LX_NETLINK_IFLA_PROTINFO		12
#define	LX_NETLINK_IFLA_TXQLEN			13
#define	LX_NETLINK_IFLA_MAP			14
#define	LX_NETLINK_IFLA_WEIGHT			15
#define	LX_NETLINK_IFLA_OPERSTATE		16
#define	LX_NETLINK_IFLA_LINKMODE		17
#define	LX_NETLINK_IFLA_LINKINFO		18
#define	LX_NETLINK_IFLA_NET_NS_PID		19
#define	LX_NETLINK_IFLA_IFALIAS			20
#define	LX_NETLINK_IFLA_NUM_VF			21
#define	LX_NETLINK_IFLA_VFINFO_LIST		22
#define	LX_NETLINK_IFLA_STATS64			23
#define	LX_NETLINK_IFLA_VF_PORTS		24
#define	LX_NETLINK_IFLA_PORT_SELF		25
#define	LX_NETLINK_IFLA_AF_SPEC			26
#define	LX_NETLINK_IFLA_GROUP			27
#define	LX_NETLINK_IFLA_NET_NS_FD		28
#define	LX_NETLINK_IFLA_EXT_MASK		29
#define	LX_NETLINK_IFLA_PROMISCUITY		30
#define	LX_NETLINK_IFLA_NUM_TX_QUEUES		31
#define	LX_NETLINK_IFLA_NUM_RX_QUEUES		32
#define	LX_NETLINK_IFLA_CARRIER			33
#define	LX_NETLINK_IFLA_PHYS_PORT_ID		34
#define	LX_NETLINK_IFLA_CARRIER_CHANGES		35
#define	LX_NETLINK_IFLA_MAX			36

/*
 * rtnetlink(7) NEWADDR/DELADDR/GETADDR constants
 */
#define	LX_NETLINK_IFA_UNSPEC			0
#define	LX_NETLINK_IFA_ADDRESS			1
#define	LX_NETLINK_IFA_LOCAL			2
#define	LX_NETLINK_IFA_LABEL			3
#define	LX_NETLINK_IFA_BROADCAST		4
#define	LX_NETLINK_IFA_ANYCAST			5
#define	LX_NETLINK_IFA_CACHEINFO		6
#define	LX_NETLINK_IFA_MULTICAST		7
#define	LX_NETLINK_IFA_FLAGS			8
#define	LX_NETLINK_IFA_MAX			9

#define	LX_NETLINK_IFA_F_SECONDARY		0x01
#define	LX_NETLINK_IFA_F_TEMPORARY		LX_NETLINK_IFA_F_SECONDARY
#define	LX_NETLINK_IFA_F_NODAD			0x02
#define	LX_NETLINK_IFA_F_OPTIMISTIC		0x04
#define	LX_NETLINK_IFA_F_DADFAILED		0x08
#define	LX_NETLINK_IFA_F_HOMEADDRESS		0x10
#define	LX_NETLINK_IFA_F_DEPRECATED		0x20
#define	LX_NETLINK_IFA_F_TENTATIVE		0x40
#define	LX_NETLINK_IFA_F_PERMANENT		0x80
#define	LX_NETLINK_IFA_F_MANAGETEMPADDR		0x100
#define	LX_NETLINK_IFA_F_NOPREFIXROUTE		0x200

/*
 * Linux interface flags.
 */
#define	LX_IFF_UP		(1<<0)
#define	LX_IFF_BROADCAST	(1<<1)
#define	LX_IFF_DEBUG		(1<<2)
#define	LX_IFF_LOOPBACK		(1<<3)
#define	LX_IFF_POINTOPOINT	(1<<4)
#define	LX_IFF_NOTRAILERS	(1<<5)
#define	LX_IFF_RUNNING		(1<<6)
#define	LX_IFF_NOARP		(1<<7)
#define	LX_IFF_PROMISC		(1<<8)
#define	LX_IFF_ALLMULTI		(1<<9)
#define	LX_IFF_MASTER		(1<<10)
#define	LX_IFF_SLAVE		(1<<11)
#define	LX_IFF_MULTICAST	(1<<12)
#define	LX_IFF_PORTSEL		(1<<13)
#define	LX_IFF_AUTOMEDIA	(1<<14)
#define	LX_IFF_DYNAMIC		(1<<15)
#define	LX_IFF_LOWER_UP		(1<<16)
#define	LX_IFF_DORMANT		(1<<17)
#define	LX_IFF_ECHO		(1<<18)

/* rtm_table */
#define	LX_ROUTE_TABLE_MAIN	254

/* rtm_type */
#define	LX_RTN_UNSPEC		0
#define	LX_RTN_UNICAST		1
#define	LX_RTN_LOCAL		2
#define	LX_RTN_BROADCAST	3
#define	LX_RTN_ANYCAST		4
#define	LX_RTN_MULTICAST	5
#define	LX_RTN_BLACKHOLE	6
#define	LX_RTN_UNREACHABLE	7
#define	LX_RTN_PROHIBIT		8
#define	LX_RTN_THROW		9
#define	LX_RTN_NAT		10
#define	LX_RTN_XRESOLVE		11

/* rtm_protocol */
#define	LX_RTPROT_UNSPEC	0
#define	LX_RTPROT_REDIRECT	1	/* From ICMP redir	*/
#define	LX_RTPROT_KERNEL	2	/* From kernel		*/
#define	LX_RTPROT_BOOT		3	/* From boot		*/
#define	LX_RTPROT_STATIC	4	/* From administrator	*/
#define	LX_RTPROT_NULL		0xff	/* Uninitialized	*/

/* rtm_scope */
#define	LX_RTSCOPE_UNIVERSE	0
#define	LX_RTSCOPE_SITE		200
#define	LX_RTSCOPE_LINK		253
#define	LX_RTSCOPE_HOST		254
#define	LX_RTSCOPE_NOWHERE	255


/*
 * Netlink sockopts
 */
#define	SOL_LX_NETLINK	270

/* See Linux include/uapi/linux/netlink.h */
#define	LX_NETLINK_SO_ADD_MEMBERSHIP	1
#define	LX_NETLINK_SO_DROP_MEMBERSHIP	2
#define	LX_NETLINK_SO_PKTINFO		3
#define	LX_NETLINK_SO_BROADCAST_ERROR	4
#define	LX_NETLINK_SO_NO_ENOBUFS	5
#define	LX_NETLINK_SO_RX_RING		6
#define	LX_NETLINK_SO_TX_RING		7
#define	LX_NETLINK_SO_LISTEN_ALL_NSID	8
#define	LX_NETLINK_SO_LIST_MEMBERSHIPS	9
#define	LX_NETLINK_SO_CAP_ACK 		10

/* Internal socket flags */
#define	LXNLF_RECVUCRED			0x1

/* nlmsg structure macros */
#define	LXNLMSG_ALIGNTO	4
#define	LXNLMSG_ALIGN(len)	\
	(((len) + LXNLMSG_ALIGNTO - 1) & ~(LXNLMSG_ALIGNTO - 1))
#define	LXNLMSG_HDRLEN	\
	((int)LXNLMSG_ALIGN(sizeof (lx_netlink_hdr_t)))
#define	LXNLMSG_LENGTH(len)	((len) + NLMSG_HDRLEN)
#define	LXNLMSG_SPACE(len)	NLMSG_ALIGN(NLMSG_LENGTH(len))
#define	LXNLMSG_DATA(nlh)	((void*)(((char *)nlh) + NLMSG_LENGTH(0)))
#define	LXNLMSG_PAYLOAD(nlh, len)	\
	((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define	LXATTR_PAYLOAD(lxa)	\
	((void*)((caddr_t)(lxa) + sizeof (lx_netlink_attr_t)))
#define	LXATTR_HDRLEN	LXNLMSG_ALIGN(sizeof (lx_netlink_attr_t))
#define	LXATTR_LEN(len)	(LXATTR_HDRLEN + LXNLMSG_ALIGN(len))

typedef struct lx_netlink_hdr {
	uint32_t lxnh_len;			/* length of message */
	uint16_t lxnh_type;			/* type of message */
	uint16_t lxnh_flags;			/* flags */
	uint32_t lxnh_seq;			/* sequence number */
	uint32_t lxnh_pid;			/* sending pid */
} lx_netlink_hdr_t;

typedef struct lx_netlink_err {
	lx_netlink_hdr_t	lxne_hdr;	/* header */
	int32_t			lxne_errno;	/* errno */
	lx_netlink_hdr_t	lxne_failed;	/* header of err */
} lx_netlink_err_t;

typedef struct lx_netlink_attr {
	uint16_t	lxna_len;		/* length of attribute */
	uint16_t	lxna_type;		/* type of attribute */
} lx_netlink_attr_t;

typedef struct lx_netlink_ifinfomsg {
	uint8_t		lxnl_ifi_family;	/* family: AF_UNSPEC */
	uint8_t		lxnl_ifi__pad;
	uint16_t	lxnl_ifi_type;		/* device type */
	uint32_t	lxnl_ifi_index;		/* interface index */
	uint32_t	lxnl_ifi_flags;		/* device flags */
	uint32_t 	lxnl_ifi_change;	/* unused; must be -1 */
} lx_netlink_ifinfomsg_t;

typedef struct lx_netlink_ifaddrmsg {
	uint8_t		lxnl_ifa_family;	/* address type */
	uint8_t		lxnl_ifa_prefixlen;	/* prefix length of address */
	uint8_t		lxnl_ifa_flags;		/* address flags */
	uint8_t		lxnl_ifa_scope;		/* address scope */
	uint8_t		lxnl_ifa_index;		/* interface index */
} lx_netlink_ifaddrmsg_t;

typedef struct lx_netlink_rtmsg {
	uint8_t		rtm_family;	/* route AF			*/
	uint8_t		rtm_dst_len;	/* destination addr length	*/
	uint8_t		rtm_src_len;	/* source addr length		*/
	uint8_t		rtm_tos;	/* TOS filter			*/
	uint8_t		rtm_table;	/* routing table ID		*/
	uint8_t		rtm_protocol;	/* routing protocol		*/
	uint8_t		rtm_scope;
	uint8_t		rtm_type;
	uint32_t	rtm_flags;
} lx_netlink_rtmsg_t;

typedef struct lx_netlink_sockaddr {
	sa_family_t	lxnl_family;		/* AF_LX_NETLINK */
	uint16_t	lxnl_pad;		/* padding */
	uint32_t	lxnl_port;		/* port id */
	uint32_t	lxnl_groups;		/* multicast groups mask */
} lx_netlink_sockaddr_t;

typedef struct lx_netlink_sock {
	struct lx_netlink_sock *lxns_next;	/* list of lx_netlink sockets */
	sock_upcalls_t *lxns_upcalls;		/* pointer to socket upcalls */
	sock_upper_handle_t lxns_uphandle;	/* socket upcall handle */
	ldi_handle_t lxns_iphandle;		/* handle to /dev/ip */
	ldi_handle_t lxns_ip6handle;		/* handle to /dev/ip6 */
	ldi_handle_t lxns_current;		/* current ip handle */
	int lxns_proto;				/* protocol */
	uint32_t lxns_port;			/* port identifier */
	uint32_t lxns_groups;			/* group subscriptions */
	uint32_t lxns_bufsize;			/* buffer size */
	uint32_t lxns_flags;			/* socket flags */
} lx_netlink_sock_t;

typedef struct lx_netlink_reply {
	lx_netlink_hdr_t lxnr_hdr;		/* header that we're reply to */
	lx_netlink_sock_t *lxnr_sock;		/* socket */
	uint32_t lxnr_seq;			/* sequence number */
	uint16_t lxnr_type;			/* type of reply */
	mblk_t *lxnr_mp;			/* current mblk */
	mblk_t *lxnr_err;			/* error mblk */
	mblk_t *lxnr_mp1;			/* T_UNITDATA_IND mblk */
	int lxnr_errno;				/* errno, if any */
} lx_netlink_reply_t;

static lx_netlink_sock_t *lx_netlink_head;	/* head of lx_netlink sockets */
static kmutex_t lx_netlink_lock;		/* lock to protect state */
static ldi_ident_t lx_netlink_ldi;		/* LDI handle */
static int lx_netlink_bufsize = 4096;		/* default buffer size */
static int lx_netlink_flowctrld;		/* # of times flow controlled */

typedef enum {
	LXNL_BIND,
	LXNL_SENDMSG
} lx_netlink_action_t;

#define	LX_UNSUP_BUFSZ	64

/*
 * On Linux, CAP_NET_ADMIN is required to take certain netlink actions.  This
 * restriction is loosened for certain protocol types, provided the activity is
 * limited to communicating directly with the kernel (rather than transmitting
 * to the various multicast groups)
 */
static int
lx_netlink_access(lx_netlink_sock_t *lns, cred_t *cr, lx_netlink_action_t act)
{
	/* Simple actions are allowed on these netlink protocols. */
	if (act != LXNL_SENDMSG) {
		switch (lns->lxns_proto) {
		case LX_NETLINK_ROUTE:
		case LX_NETLINK_AUDIT:
		case LX_NETLINK_KOBJECT_UEVENT:
			return (0);
		default:
			break;
		}
	}

	/* CAP_NET_ADMIN roughly maps to PRIV_SYS_IP_CONFIG. */
	if (secpolicy_ip_config(cr, B_FALSE) != 0) {
		return (EACCES);
	}

	return (0);
}

/*ARGSUSED*/
static void
lx_netlink_activate(sock_lower_handle_t handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls,
    int flags, cred_t *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;
	struct sock_proto_props sopp;

	sopp.sopp_flags = SOCKOPT_WROFF | SOCKOPT_RCVHIWAT |
	    SOCKOPT_RCVLOWAT | SOCKOPT_MAXADDRLEN | SOCKOPT_MAXPSZ |
	    SOCKOPT_MAXBLK | SOCKOPT_MINPSZ;
	sopp.sopp_wroff = 0;
	sopp.sopp_rxhiwat = SOCKET_RECVHIWATER;
	sopp.sopp_rxlowat = SOCKET_RECVLOWATER;
	sopp.sopp_maxaddrlen = sizeof (struct sockaddr_dl);
	sopp.sopp_maxpsz = INFPSZ;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_minpsz = 0;

	lxsock->lxns_upcalls = sock_upcalls;
	lxsock->lxns_uphandle = sock_handle;

	sock_upcalls->su_set_proto_props(sock_handle, &sopp);
}

/*ARGSUSED*/
static int
lx_netlink_setsockopt(sock_lower_handle_t handle, int level,
    int option_name, const void *optval, socklen_t optlen, struct cred *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;

	if (level == SOL_SOCKET && option_name == SO_RECVUCRED) {
		int *ival;
		if (optlen != sizeof (int)) {
			return (EINVAL);
		}
		ival = (int *)optval;
		if (*ival == 0) {
			lxsock->lxns_flags &= ~LXNLF_RECVUCRED;
		} else {
			lxsock->lxns_flags |= LXNLF_RECVUCRED;
		}
		return (0);
	} else if (level == SOL_SOCKET) {
		/* Punt on the other SOL_SOCKET options */
		return (0);
	} else if (level != SOL_LX_NETLINK) {
		return (EOPNOTSUPP);
	}

	switch (option_name) {
	case LX_NETLINK_SO_ADD_MEMBERSHIP:
	case LX_NETLINK_SO_DROP_MEMBERSHIP:
	case LX_NETLINK_SO_PKTINFO:
	case LX_NETLINK_SO_BROADCAST_ERROR:
	case LX_NETLINK_SO_NO_ENOBUFS:
	case LX_NETLINK_SO_RX_RING:
	case LX_NETLINK_SO_TX_RING:
		/* Blatant lie */
		return (0);
	default:
		return (EINVAL);
	}
}

/*ARGSUSED*/
static int
lx_netlink_getsockopt(sock_lower_handle_t handle, int level,
    int option_name, void *optval, socklen_t *optlen, cred_t *cr)
{
	if (level != SOL_LX_NETLINK) {
		return (EOPNOTSUPP);
	}

	switch (option_name) {
	case LX_NETLINK_SO_LIST_MEMBERSHIPS:
		/* Report that we have 0 members to allow systemd to proceed. */
		*optlen = 0;
		return (0);
	default:
		return (EINVAL);
	}
}

/*ARGSUSED*/
static int
lx_netlink_bind(sock_lower_handle_t handle, struct sockaddr *name,
    socklen_t namelen, struct cred *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;
	lx_netlink_sockaddr_t *lxsa = (lx_netlink_sockaddr_t *)name;

	if (namelen != sizeof (lx_netlink_sockaddr_t) ||
	    lxsa->lxnl_family != AF_LX_NETLINK) {
		return (EINVAL);
	}

	/*
	 * Perform access checks if attempting to bind on any multicast groups.
	 */
	if (lxsa->lxnl_groups != 0) {
		int err;

		if ((err = lx_netlink_access(lxsock, cr, LXNL_BIND)) != 0) {
			return (err);
		}

		/* Lie about group subscription for now */
		lxsock->lxns_groups = lxsa->lxnl_groups;
	}

	/*
	 * Linux netlink uses nl_port to identify distinct netlink sockets.
	 * Binding to an address of nl_port=0 triggers the kernel to
	 * automatically assign a free nl_port identifier.  Originally,
	 * consumers of lx_netlink were required to bind with that automatic
	 * address.  We now support non-zero values for nl_port although strict
	 * checking to identify conflicts is not performed.  Use of the
	 * id_space facility could be a convenient solution, if a need arose.
	 */
	if (lxsa->lxnl_port == 0) {
		/*
		 * Because we are not doing conflict detection, there is no
		 * need to expend effort selecting a unique port for automatic
		 * addressing during bind.
		 */
		lxsock->lxns_port = curproc->p_pid;
	} else {
		lxsock->lxns_port = lxsa->lxnl_port;
	}

	return (0);
}

/*ARGSUSED*/
static int
lx_netlink_getsockname(sock_lower_handle_t handle, struct sockaddr *sa,
    socklen_t *len, struct cred *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;
	lx_netlink_sockaddr_t *lxsa = (lx_netlink_sockaddr_t *)sa;

	if (*len < sizeof (lx_netlink_sockaddr_t))
		return (EINVAL);

	lxsa->lxnl_family = AF_LX_NETLINK;
	lxsa->lxnl_pad = 0;
	lxsa->lxnl_port = lxsock->lxns_port;
	lxsa->lxnl_groups = lxsock->lxns_groups;

	*len = sizeof (lx_netlink_sockaddr_t);

	return (0);
}

static mblk_t *
lx_netlink_alloc_mp1(lx_netlink_sock_t *lxsock)
{
	mblk_t *mp;
	size_t size;
	struct T_unitdata_ind *tunit;
	lx_netlink_sockaddr_t *lxsa;
	boolean_t send_ucred;

	/*
	 * Certain netlink clients (such as systemd) will set SO_RECVUCRED
	 * (via the Linux SCM_CREDENTIALS) on the expectation that all replies
	 * will contain credentials passed via cmsg.  They require this to
	 * authenticate those messages as having originated in the kernel by
	 * checking uc_pid == 0.
	 */
	VERIFY(lxsock != NULL);
	send_ucred = ((lxsock->lxns_flags & LXNLF_RECVUCRED) != 0);

	/*
	 * Message structure:
	 * +----------------------------+
	 * | struct T_unit_data_ind	|
	 * +----------------------------+
	 * | lx_netlink_sockaddr_t	|
	 * +----------------------------+  -+
	 * | struct cmsghdr (SCM_UCRED)	|   |
	 * +----------------------------+   +-(optional)
	 * | struct ucred_s (cmsg data)	|   |
	 * +----------------------------+  -+
	 */
	size = sizeof (*tunit) + sizeof (*lxsa);
	if (send_ucred) {
		size += sizeof (struct cmsghdr) +
		    ROUNDUP_cmsglen(sizeof (struct ucred_s));
	}
	mp = allocb(size, 0);
	if (mp == NULL) {
		return (NULL);
	}

	tunit = (struct T_unitdata_ind *)mp->b_rptr;
	lxsa = (lx_netlink_sockaddr_t *)((caddr_t)tunit + sizeof (*tunit));
	mp->b_wptr += size;

	mp->b_datap->db_type = M_PROTO;
	tunit->PRIM_type = T_UNITDATA_IND;
	tunit->SRC_length = sizeof (*lxsa);
	tunit->SRC_offset = sizeof (*tunit);

	lxsa->lxnl_family = AF_LX_NETLINK;
	lxsa->lxnl_port = 0;
	lxsa->lxnl_groups = 0;
	lxsa->lxnl_pad = 0;

	if (send_ucred) {
		struct cmsghdr *cmsg;
		struct ucred_s *ucred;

		cmsg = (struct cmsghdr *)((caddr_t)lxsa + sizeof (*lxsa));
		ucred = (struct ucred_s *)CMSG_CONTENT(cmsg);
		cmsg->cmsg_len = sizeof (*cmsg) + sizeof (*ucred);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_UCRED;
		bzero(ucred, sizeof (*ucred));
		ucred->uc_size = sizeof (*ucred);
		ucred->uc_zoneid = getzoneid();

		tunit->OPT_length = sizeof (*cmsg) +
		    ROUNDUP_cmsglen(sizeof (*ucred));
		tunit->OPT_offset = tunit->SRC_offset + tunit->SRC_length;
	} else {
		tunit->OPT_length = 0;
		tunit->OPT_offset = 0;
	}

	return (mp);
}

static lx_netlink_reply_t *
lx_netlink_reply(lx_netlink_sock_t *lxsock,
    lx_netlink_hdr_t *hdr, uint16_t type)
{
	lx_netlink_reply_t *reply;
	mblk_t *err, *mp1;

	/*
	 * We always allocate an error block to assure that even if subsequent
	 * allocations fail, we can return an error.
	 */
	if ((err = allocb(sizeof (lx_netlink_err_t), 0)) == NULL)
		return (NULL);

	if ((mp1 = lx_netlink_alloc_mp1(lxsock)) == NULL) {
		freeb(err);
		return (NULL);
	}

	reply = kmem_zalloc(sizeof (lx_netlink_reply_t), KM_SLEEP);
	reply->lxnr_err = err;
	reply->lxnr_sock = lxsock;
	reply->lxnr_hdr = *hdr;
	reply->lxnr_type = type;
	reply->lxnr_mp1 = mp1;

	return (reply);
}

static void
lx_netlink_reply_add(lx_netlink_reply_t *reply, void *payload, uint32_t size)
{
	lx_netlink_hdr_t *hdr;
	lx_netlink_sock_t *lxsock = reply->lxnr_sock;
	uint32_t aligned;
	mblk_t *mp = reply->lxnr_mp;

	if (reply->lxnr_errno)
		return;

	aligned = LXNLMSG_ALIGN(size);
	hdr = (lx_netlink_hdr_t *)mp->b_rptr;

	if (hdr->lxnh_len + aligned > lxsock->lxns_bufsize) {
		reply->lxnr_errno = E2BIG;
		return;
	}

	bcopy(payload, mp->b_wptr, size);
	hdr->lxnh_len += aligned;
	mp->b_wptr += aligned;
}

static void
lx_netlink_reply_msg(lx_netlink_reply_t *reply, void *payload, uint32_t size)
{
	lx_netlink_hdr_t *hdr;
	lx_netlink_sock_t *lxsock = reply->lxnr_sock;
	mblk_t *mp;

	if (reply->lxnr_errno)
		return;

	VERIFY(reply->lxnr_mp == NULL);

	if ((reply->lxnr_mp = mp = allocb(lxsock->lxns_bufsize, 0)) == NULL) {
		reply->lxnr_errno = ENOMEM;
		return;
	}

	bzero(mp->b_rptr, lxsock->lxns_bufsize);
	hdr = (lx_netlink_hdr_t *)mp->b_rptr;
	hdr->lxnh_flags = LX_NETLINK_NLM_F_MULTI;
	hdr->lxnh_len = LXNLMSG_ALIGN(sizeof (lx_netlink_hdr_t));
	hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
	hdr->lxnh_pid = lxsock->lxns_port;

	mp->b_wptr += LXNLMSG_ALIGN(sizeof (lx_netlink_hdr_t));

	if (payload == NULL) {
		/*
		 * A NULL payload denotes a "done" message.
		 */
		hdr->lxnh_type = LX_NETLINK_NLMSG_DONE;
	} else {
		hdr->lxnh_type = reply->lxnr_type;
		lx_netlink_reply_add(reply, payload, size);
	}
}

static void
lx_netlink_reply_attr(lx_netlink_reply_t *reply, uint16_t type,
    void *payload, uint32_t size)
{
	lx_netlink_attr_t attr;

	attr.lxna_len = size + sizeof (lx_netlink_attr_t);
	attr.lxna_type = type;

	lx_netlink_reply_add(reply, &attr, sizeof (attr));
	lx_netlink_reply_add(reply, payload, size);
}

static void
lx_netlink_reply_attr_string(lx_netlink_reply_t *reply,
    uint16_t type, const char *str)
{
	lx_netlink_reply_attr(reply, type, (void *)str, strlen(str) + 1);
}

static void
lx_netlink_reply_attr_int32(lx_netlink_reply_t *reply,
    uint16_t type, int32_t val)
{
	int32_t v = val;

	lx_netlink_reply_attr(reply, type, &v, sizeof (int32_t));
}

static int
lx_netlink_reply_ioctl(lx_netlink_reply_t *reply, int cmd, void *arg)
{
	int rval;

	if (reply->lxnr_errno != 0)
		return (reply->lxnr_errno);

	if ((rval = ldi_ioctl(reply->lxnr_sock->lxns_current,
	    cmd, (intptr_t)arg, FKIOCTL, kcred, NULL)) != 0) {
		reply->lxnr_errno = rval;
	}

	return (rval);
}

static void
lx_netlink_reply_sendup(lx_netlink_reply_t *reply, mblk_t *mp, mblk_t *mp1)
{
	lx_netlink_sock_t *lxsock = reply->lxnr_sock;
	int error;

	/*
	 * To prevent the stream head from coalescing messages and to indicate
	 * their origin, we send them as T_UNITDATA_IND messages, not as raw
	 * M_DATA.
	 */
	mp1->b_cont = mp;

	lxsock->lxns_upcalls->su_recv(lxsock->lxns_uphandle, mp1,
	    msgdsize(mp1), 0, &error, NULL);

	if (error != 0)
		lx_netlink_flowctrld++;
}

static void
lx_netlink_reply_send(lx_netlink_reply_t *reply)
{
	mblk_t *mp1;

	if (reply->lxnr_errno)
		return;

	if ((mp1 = lx_netlink_alloc_mp1(reply->lxnr_sock)) == NULL) {
		reply->lxnr_errno = ENOMEM;
		return;
	}

	lx_netlink_reply_sendup(reply, reply->lxnr_mp, mp1);
	reply->lxnr_mp = NULL;
}

static void
lx_netlink_reply_done(lx_netlink_reply_t *reply)
{
	lx_netlink_sock_t *lxsock = reply->lxnr_sock;
	mblk_t *mp;

	/*
	 * Denote that we're done via a message with a NULL payload.
	 */
	lx_netlink_reply_msg(reply, NULL, 0);

	if (reply->lxnr_errno) {
		/*
		 * If anything failed, we'll send up an error message.
		 */
		lx_netlink_hdr_t *hdr;
		lx_netlink_err_t *err;

		if (reply->lxnr_mp != NULL) {
			freeb(reply->lxnr_mp);
			reply->lxnr_mp = NULL;
		}

		mp = reply->lxnr_err;
		VERIFY(mp != NULL);
		reply->lxnr_err = NULL;
		err = (lx_netlink_err_t *)mp->b_rptr;
		hdr = &err->lxne_hdr;
		mp->b_wptr += sizeof (lx_netlink_err_t);

		err->lxne_failed = reply->lxnr_hdr;
		err->lxne_errno = reply->lxnr_errno;
		hdr->lxnh_type = LX_NETLINK_NLMSG_ERROR;
		hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
		hdr->lxnh_len = sizeof (lx_netlink_err_t);
		hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
		hdr->lxnh_pid = lxsock->lxns_port;
	} else {
		mp = reply->lxnr_mp;
		VERIFY(mp != NULL);
		reply->lxnr_mp = NULL;
	}

	lx_netlink_reply_sendup(reply, mp, reply->lxnr_mp1);

	if (reply->lxnr_mp != NULL)
		freeb(reply->lxnr_mp);

	if (reply->lxnr_err != NULL)
		freeb(reply->lxnr_err);

	kmem_free(reply, sizeof (lx_netlink_reply_t));
}

static int
lx_netlink_reply_error(lx_netlink_sock_t *lxsock,
    lx_netlink_hdr_t *hdr, int errno)
{
	/*
	 * The type of the message doesn't matter, as we're going to explicitly
	 * set lxnr_errno and therefore send only an error message.
	 */
	lx_netlink_reply_t *reply = lx_netlink_reply(lxsock, hdr, 0);

	if (reply == NULL)
		return (ENOMEM);

	reply->lxnr_errno = errno;
	lx_netlink_reply_done(reply);

	return (0);
}

static int
lx_netlink_parse_msg_attrs(mblk_t *mp, void **msgp, unsigned int msg_size,
    lx_netlink_attr_t **attrp, unsigned int *attr_max)
{
	lx_netlink_hdr_t *hdr = (lx_netlink_hdr_t *)mp->b_rptr;
	lx_netlink_attr_t *lxa;
	unsigned char *buf = mp->b_rptr + LXNLMSG_HDRLEN;
	unsigned int i;
	uint32_t buf_left = MBLKL(mp) - LXNLMSG_HDRLEN;
	uint32_t msg_left = hdr->lxnh_len;

	msg_size = LXNLMSG_ALIGN(msg_size);
	if (msg_size > buf_left || msg_size > msg_left) {
		return (-1);
	}

	*msgp = (void *)buf;
	buf += msg_size;
	buf_left -= msg_size;
	msg_left -= msg_size;

	/* Do not bother with attr parsing if not requested */
	if (attrp == NULL || *attr_max == 0) {
		return (0);
	}

	for (i = 0; i < *attr_max; i++) {
		if (buf_left < LXATTR_HDRLEN || msg_left < LXATTR_HDRLEN) {
			break;
		}

		lxa = (lx_netlink_attr_t *)buf;
		if (lxa->lxna_len > buf_left || lxa->lxna_len > msg_left) {
			return (-1);
		}

		attrp[i] = lxa;
		buf += lxa->lxna_len;
		buf_left -= lxa->lxna_len;
		msg_left -= lxa->lxna_len;
	}
	*attr_max = i;

	return (0);
}

/*
 * Takes an IPv4 address (in network byte order) and returns the address scope.
 */
static uint8_t
lx_ipv4_rtscope(in_addr_t nbo_addr)
{
	in_addr_t addr = ntohl(nbo_addr);
	if ((addr >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		return (LX_RTSCOPE_HOST);
	} else if ((addr & IN_AUTOCONF_MASK) == IN_AUTOCONF_NET) {
		return (LX_RTSCOPE_LINK);
	} else if ((addr & IN_PRIVATE8_MASK) == IN_PRIVATE8_NET ||
	    (addr & IN_PRIVATE12_MASK) == IN_PRIVATE12_NET ||
	    (addr & IN_PRIVATE16_MASK) == IN_PRIVATE16_NET) {
		return (LX_RTSCOPE_SITE);
	} else {
		return (LX_RTSCOPE_UNIVERSE);
	}
}

/*
 * Takes an IPv6 address and returns the address scope.
 */
static uint8_t
lx_ipv6_rtscope(const in6_addr_t *addr)
{
	if (IN6_ARE_ADDR_EQUAL(addr, &ipv6_loopback)) {
		return (LX_RTSCOPE_HOST);
	} else if (IN6_IS_ADDR_LINKLOCAL(addr)) {
		return (LX_RTSCOPE_LINK);
	} else if (IN6_IS_ADDR_SITELOCAL(addr)) {
		return (LX_RTSCOPE_SITE);
	} else {
		return (LX_RTSCOPE_UNIVERSE);
	}
}

static void
lx_netlink_getlink_lifreq(lx_netlink_reply_t *reply, struct lifreq *lifr)
{
	lx_netlink_ifinfomsg_t ifi;
	int i;
	char if_name[IFNAMSIZ];
	struct sockaddr_dl *sdl;
	struct sockaddr hwaddr;
	int hwaddr_size;
	boolean_t is_loopback;

	struct {
		int native;
		int lx;
	} flags[] = {
		{ IFF_UP, LX_IFF_UP },
		{ IFF_BROADCAST, LX_IFF_BROADCAST },
		{ IFF_DEBUG, LX_IFF_DEBUG },
		{ IFF_LOOPBACK, LX_IFF_LOOPBACK },
		{ IFF_POINTOPOINT, LX_IFF_POINTOPOINT },
		{ IFF_NOTRAILERS, LX_IFF_NOTRAILERS },
		{ IFF_RUNNING, LX_IFF_RUNNING },
		{ IFF_NOARP, LX_IFF_NOARP },
		{ IFF_PROMISC, LX_IFF_PROMISC },
		{ IFF_ALLMULTI, LX_IFF_ALLMULTI },
		{ IFF_MULTICAST, LX_IFF_MULTICAST },
		{ 0 }
	};

	/*
	 * illumos interfaces that contain a ':' are non-zero logical
	 * interfaces. We should only emit the name of the zeroth logical
	 * interface, since RTM_GETLINK only expects to see the name of
	 * devices. The addresses of all logical devices will be
	 * returned via an RTM_GETADDR.
	 */
	if (strchr(lifr->lifr_name, ':') != NULL)
		return;

	/*
	 * Most of the lx_netlink module is architected to emit information in
	 * an illumos-native manner.  Socket syscalls such as getsockname will
	 * not translate fields to values Linux programs would expect since
	 * that conversion is performed by the generic socket emulation.
	 *
	 * This is _not_ true of the actual protocol output from lx_netlink.
	 * Since translating it at the socket layer would be onerous, all
	 * output (including constants and names) is pre-translated to values
	 * valid for Linux.
	 */

	bzero(&ifi, sizeof (ifi));
	ifi.lxnl_ifi_family = AF_UNSPEC;
	ifi.lxnl_ifi_change = (uint32_t)-1;

	/* Convert the name to be Linux-friendly */
	(void) strlcpy(if_name, lifr->lifr_name, IFNAMSIZ);
	lx_ifname_convert(if_name, LX_IF_FROMNATIVE);
	is_loopback = (strncmp(if_name, "lo", 2) == 0);

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFINDEX, lifr) != 0)
		return;

	ifi.lxnl_ifi_index = lifr->lifr_index;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFFLAGS, lifr) != 0)
		return;

	for (i = 0; flags[i].native; i++) {
		if (lifr->lifr_flags & flags[i].native)
			ifi.lxnl_ifi_flags |= flags[i].lx;
	}

	/*
	 * Query the datalink address.
	 * The interface type will be included in the outgoing infomsg while
	 * the address itself will be output separately.
	 */
	sdl = (struct sockaddr_dl *)&lifr->lifr_addr;
	bzero(sdl, sizeof (*sdl));
	if (!is_loopback) {
		(void) lx_netlink_reply_ioctl(reply, SIOCGLIFHWADDR, lifr);
	} else {
		/* Simulate an empty hwaddr for loopback */
		sdl->sdl_type = DL_LOOP;
		sdl->sdl_alen = ETHERADDRL;
	}
	lx_stol_hwaddr(sdl, &hwaddr, &hwaddr_size);

	ifi.lxnl_ifi_type = hwaddr.sa_family;
	lx_netlink_reply_msg(reply, &ifi, sizeof (lx_netlink_ifinfomsg_t));

	lx_netlink_reply_attr_string(reply, LX_NETLINK_IFLA_IFNAME, if_name);

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFMTU, lifr) != 0)
		return;

	lx_netlink_reply_attr_int32(reply, LX_NETLINK_IFLA_MTU, lifr->lifr_mtu);

	if (hwaddr_size != 0) {
		lx_netlink_reply_attr(reply, LX_NETLINK_IFLA_ADDRESS,
		    hwaddr.sa_data, hwaddr_size);
	}

	/* Emulate a txqlen of 1. (0 for loopbacks) */
	lx_netlink_reply_attr_int32(reply, LX_NETLINK_IFLA_TXQLEN,
	    (is_loopback) ? 0 : 1);

	lx_netlink_reply_send(reply);
}

static void
lx_netlink_reply_eachfamily(lx_netlink_reply_t *reply,
    void (*func)(lx_netlink_reply_t *, struct lifreq *), boolean_t distinct)
{
	lx_netlink_sock_t *sock = reply->lxnr_sock;
	int nlifr, i;

	struct {
		int family;
		ldi_handle_t handle;
		struct lifconf lifc;
		struct lifnum lifn;
	} families[] = {
		{ AF_INET, sock->lxns_iphandle },
		{ AF_INET6, sock->lxns_ip6handle },
		{ AF_UNSPEC }
	}, *family, *check;

	for (family = families; family->family != AF_UNSPEC; family++) {
		struct lifconf *lifc = &family->lifc;
		struct lifnum *lifn = &family->lifn;

		lifn->lifn_family = family->family;
		sock->lxns_current = family->handle;

		if (lx_netlink_reply_ioctl(reply, SIOCGLIFNUM, lifn) != 0)
			break;

		lifc->lifc_family = lifn->lifn_family;
		lifc->lifc_flags = 0;
		lifc->lifc_len = lifn->lifn_count * sizeof (struct lifreq);
		if (lifn->lifn_count == 0) {
			lifc->lifc_buf = NULL;
			continue;
		}
		lifc->lifc_buf = kmem_alloc(lifc->lifc_len, KM_SLEEP);

		if (lx_netlink_reply_ioctl(reply, SIOCGLIFCONF, lifc) != 0)
			break;

		nlifr = lifc->lifc_len / sizeof (lifc->lifc_req[0]);

		for (i = 0; i < nlifr; i++) {
			if (!distinct) {
				func(reply, &lifc->lifc_req[i]);
				continue;
			}

			/*
			 * If we have been asked to provide each interface
			 * exactly once, we need to (annoyingly) check this
			 * name against others that we've already processed for
			 * other families.  Yes, this is quadratic time -- but
			 * the number of interfaces per family is expected to
			 * be very small.
			 */
			for (check = families; check != family; check++) {
				struct lifconf *clifc = &check->lifc;
				int cnlifr = clifc->lifc_len /
				    sizeof (clifc->lifc_req[0]), j;
				char *nm = lifc->lifc_req[i].lifr_name, *cnm;

				for (j = 0; j < cnlifr; j++) {
					cnm = clifc->lifc_req[j].lifr_name;

					if (strcmp(nm, cnm) == 0)
						break;
				}

				if (j != cnlifr)
					break;
			}

			if (check != family)
				continue;

			func(reply, &lifc->lifc_req[i]);
		}
	}

	for (family = families; family->family != AF_UNSPEC; family++) {
		struct lifconf *lifc = &family->lifc;

		if (lifc->lifc_buf != NULL)
			kmem_free(lifc->lifc_buf, lifc->lifc_len);
	}
}

/*ARGSUSED*/
static int
lx_netlink_getlink(lx_netlink_sock_t *lxsock, lx_netlink_hdr_t *hdr, mblk_t *mp)
{
	lx_netlink_reply_t *reply;

	reply = lx_netlink_reply(lxsock, hdr, LX_NETLINK_RTM_NEWLINK);

	if (reply == NULL)
		return (ENOMEM);

	lx_netlink_reply_eachfamily(reply, lx_netlink_getlink_lifreq, B_TRUE);
	lx_netlink_reply_done(reply);

	return (0);
}

static void
lx_netlink_getaddr_lifreq(lx_netlink_reply_t *reply, struct lifreq *lifr)
{
	lx_netlink_ifaddrmsg_t ifa;

	bzero(&ifa, sizeof (ifa));

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFINDEX, lifr) != 0)
		return;

	ifa.lxnl_ifa_index = lifr->lifr_index;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFFLAGS, lifr) != 0)
		return;

	/*
	 * Don't report on-link subnets
	 */
	if ((lifr->lifr_flags & IFF_NOLOCAL) != 0)
		return;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFSUBNET, lifr) != 0)
		return;

	ifa.lxnl_ifa_prefixlen = lifr->lifr_addrlen;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFADDR, lifr) != 0)
		return;

	if (lifr->lifr_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin;

		ifa.lxnl_ifa_family = LX_AF_INET;

		sin = (struct sockaddr_in *)&lifr->lifr_addr;
		ifa.lxnl_ifa_scope = lx_ipv4_rtscope(
		    sin->sin_addr.s_addr);

		lx_netlink_reply_msg(reply, &ifa,
		    sizeof (lx_netlink_ifaddrmsg_t));

		lx_netlink_reply_attr_int32(reply,
		    LX_NETLINK_IFA_ADDRESS, sin->sin_addr.s_addr);
	} else {
		struct sockaddr_in6 *sin;

		ifa.lxnl_ifa_family = LX_AF_INET6;

		sin = (struct sockaddr_in6 *)&lifr->lifr_addr;
		ifa.lxnl_ifa_scope = lx_ipv6_rtscope(&sin->sin6_addr);

		lx_netlink_reply_msg(reply, &ifa,
		    sizeof (lx_netlink_ifaddrmsg_t));

		lx_netlink_reply_attr(reply, LX_NETLINK_IFA_ADDRESS,
		    &sin->sin6_addr, sizeof (sin->sin6_addr));
	}

	lx_netlink_reply_send(reply);
}

/*ARGSUSED*/
static int
lx_netlink_getaddr(lx_netlink_sock_t *lxsock, lx_netlink_hdr_t *hdr, mblk_t *mp)
{
	lx_netlink_reply_t *reply;

	reply = lx_netlink_reply(lxsock, hdr, LX_NETLINK_RTM_NEWADDR);

	if (reply == NULL)
		return (ENOMEM);

	lx_netlink_reply_eachfamily(reply, lx_netlink_getaddr_lifreq, B_FALSE);
	lx_netlink_reply_done(reply);

	return (0);
}

struct lx_getroute_ctx {
	lx_netlink_reply_t *lgrtctx_reply;
	lx_netlink_rtmsg_t *lgrtctx_rtmsg;
	lx_netlink_attr_t *lgrtctx_attrs[LX_NETLINK_MAX_RTA];
	unsigned int lgrtctx_max_attr;
	lx_netlink_attr_t *lgrtctx_rtadst;
};

static void
lx_netlink_getroute_ipv4(ire_t *ire, struct lx_getroute_ctx *ctx)
{
	lx_netlink_reply_t *reply = ctx->lgrtctx_reply;
	lx_netlink_rtmsg_t *rtmsg = ctx->lgrtctx_rtmsg;
	lx_netlink_attr_t *rtadst = ctx->lgrtctx_rtadst;
	lx_netlink_rtmsg_t res;
	ill_t *ill = NULL;

	/* Certain IREs are too specific for netlink */
	if ((ire->ire_type & (IRE_BROADCAST | IRE_MULTICAST | IRE_NOROUTE |
	    IRE_LOOPBACK | IRE_LOCAL)) != 0 || ire->ire_testhidden != 0) {
		return;
	}
	/*
	 * When listing routes, CLONE entries are undesired.
	 * They are required for 'ip route get' on a local address.
	 */
	if (rtmsg->rtm_dst_len == 0 && (ire->ire_type & IRE_IF_CLONE) != 0) {
		return;
	}

	bzero(&res, sizeof (res));
	res.rtm_family = LX_AF_INET;
	res.rtm_table = LX_ROUTE_TABLE_MAIN;
	res.rtm_type = LX_RTN_UNICAST;
	res.rtm_dst_len = ire->ire_masklen;

	if (ire->ire_type & (IRE_IF_NORESOLVER|IRE_IF_RESOLVER)) {
		/* Interface-local networks considered kernel-created */
		res.rtm_protocol = LX_RTPROT_KERNEL;
		res.rtm_scope = LX_RTSCOPE_LINK;
	} else if (ire->ire_flags & RTF_STATIC) {
		res.rtm_protocol = LX_RTPROT_STATIC;
	}

	if (rtmsg->rtm_dst_len == 0x20 && rtadst != NULL) {
		/*
		 * SpecifY single-destination route.
		 * RTA_DST details will be added later
		 */
		res.rtm_dst_len = rtmsg->rtm_dst_len;
	}


	lx_netlink_reply_msg(reply, &res, sizeof (res));

	if (rtmsg->rtm_dst_len == 0x20 && rtadst != NULL) {
		/* Add RTA_DST details for single-destination route. */
		lx_netlink_reply_attr(reply, LX_NETLINK_RTA_DST,
		    LXATTR_PAYLOAD(rtadst), sizeof (ipaddr_t));
	} else if (ire->ire_masklen != 0) {
		lx_netlink_reply_attr(reply, LX_NETLINK_RTA_DST,
		    &ire->ire_addr, sizeof (ire->ire_addr));
	}

	if (ire->ire_ill != NULL) {
		ill = ire->ire_ill;
	} else if (ire->ire_dep_parent != NULL) {
		ill = ire->ire_dep_parent->ire_ill;
	}

	if (ill != NULL) {
		uint32_t ifindex, addr_src;

		ifindex = ill->ill_phyint->phyint_ifindex;
		lx_netlink_reply_attr(reply, LX_NETLINK_RTA_OIF,
		    &ifindex, sizeof (ifindex));

		addr_src = ill->ill_ipif->ipif_lcl_addr;
		lx_netlink_reply_attr(reply, LX_NETLINK_RTA_PREFSRC,
		    &addr_src, sizeof (addr_src));
	}

	if (ire->ire_flags & RTF_GATEWAY) {
		lx_netlink_reply_attr(reply, LX_NETLINK_RTA_GATEWAY,
		    &ire->ire_gateway_addr, sizeof (ire->ire_gateway_addr));
	}

	lx_netlink_reply_send(reply);
}

/*ARGSUSED*/
static int
lx_netlink_getroute(lx_netlink_sock_t *lxsock, lx_netlink_hdr_t *hdr,
    mblk_t *mp)
{
	struct lx_getroute_ctx ctx;
	lx_netlink_reply_t *reply;
	lx_netlink_rtmsg_t rtmsg, *rtmsgp;
	int rtmsg_size = sizeof (rtmsg);
	netstack_t *ns;
	int i;

	bzero(&ctx, sizeof (ctx));
	ctx.lgrtctx_max_attr = LX_NETLINK_MAX_RTA;

	if (lx_netlink_parse_msg_attrs(mp, (void **)&rtmsgp,
	    rtmsg_size, ctx.lgrtctx_attrs, &ctx.lgrtctx_max_attr) != 0) {
		return (EPROTO);
	}

	/*
	 * Older version of libnetlink send a truncated rtmsg struct for
	 * certain RTM_GETROUTE queries.  We must detect this condition and
	 * truncate our input to prevent later confusion.
	 */
	if (curproc->p_zone->zone_brand == &lx_brand &&
	    lx_kern_release_cmp(curproc->p_zone, "2.6.32") <= 0 &&
	    rtmsgp->rtm_dst_len == 0) {
		rtmsg_size = sizeof (rtmsg.rtm_family);
	}
	bzero(&rtmsg, sizeof (rtmsg));
	bcopy(rtmsgp, &rtmsg, rtmsg_size);
	ctx.lgrtctx_rtmsg = &rtmsg;

	/* If RTA_DST was passed, it effects later decisions */
	for (i = 0; i < ctx.lgrtctx_max_attr; i++) {
		lx_netlink_attr_t *attr = ctx.lgrtctx_attrs[i];

		if (attr->lxna_type == LX_NETLINK_RTA_DST &&
		    attr->lxna_len == LXATTR_LEN(sizeof (ipaddr_t))) {
			ctx.lgrtctx_rtadst = attr;
			break;
		}
	}

	reply = lx_netlink_reply(lxsock, hdr, LX_NETLINK_RTM_NEWROUTE);
	if (reply == NULL) {
		return (ENOMEM);
	}
	ctx.lgrtctx_reply = reply;

	/* Do not report anything outside the main table */
	if (rtmsg.rtm_table != LX_ROUTE_TABLE_MAIN &&
	    rtmsg.rtm_table != 0) {
		lx_netlink_reply_done(reply);
		return (0);
	}

	ns = netstack_get_current();
	if (ns == NULL) {
		lx_netlink_reply_done(reply);
		return (0);
	}
	if (rtmsg.rtm_family == LX_AF_INET || rtmsg.rtm_family == 0) {
		if (rtmsg.rtm_dst_len == 0x20 && ctx.lgrtctx_rtadst != NULL) {
			/* resolve route for host */
			ipaddr_t *dst = LXATTR_PAYLOAD(ctx.lgrtctx_rtadst);
			ire_t *ire_dst;

			ire_dst = ire_route_recursive_dstonly_v4(*dst, 0, 0,
			    ns->netstack_ip);
			lx_netlink_getroute_ipv4(ire_dst, &ctx);
			ire_refrele(ire_dst);
		} else {
			/* get route listing */
			ire_walk_v4(&lx_netlink_getroute_ipv4, &ctx, ALL_ZONES,
			    ns->netstack_ip);
		}
	}
	if (rtmsg.rtm_family == LX_AF_INET6) {
		/* punt on ipv6 for now */
		netstack_rele(ns);
		lx_netlink_reply_done(reply);
		return (EPROTO);
	}
	netstack_rele(ns);

	lx_netlink_reply_done(reply);
	return (0);
}


/*ARGSUSED*/
static int
lx_netlink_audit(lx_netlink_sock_t *lxsock, lx_netlink_hdr_t *hdr, mblk_t *mp)
{
	/*
	 * For all auditing messages, we return ECONNREFUSED, which seems to
	 * keep user-level auditing happy.  (Or at least, non-suicidal.)
	 */
	return (ECONNREFUSED);
}

/*ARGSUSED*/
static int
lx_netlink_kobject_uevent(lx_netlink_sock_t *lxsock,
    lx_netlink_hdr_t *hdr, mblk_t *mp)
{
	/*
	 * For udev, we just silently accept all writes and never actually
	 * reply with anything -- which appears to be sufficient for things
	 * to work.
	 */
	return (0);
}

/*ARGSUSED*/
static int
lx_netlink_send(sock_lower_handle_t handle, mblk_t *mp,
    struct nmsghdr *msg, cred_t *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;
	lx_netlink_hdr_t *hdr = (lx_netlink_hdr_t *)mp->b_rptr;
	int i, rval;

	static struct {
		int proto;
		uint16_t type;
		int (*func)(lx_netlink_sock_t *, lx_netlink_hdr_t *, mblk_t *);
	} handlers[] = {
		{ LX_NETLINK_ROUTE,
		    LX_NETLINK_RTM_GETLINK, lx_netlink_getlink },
		{ LX_NETLINK_ROUTE,
		    LX_NETLINK_RTM_GETADDR, lx_netlink_getaddr },
		{ LX_NETLINK_ROUTE,
		    LX_NETLINK_RTM_GETROUTE, lx_netlink_getroute },
		{ LX_NETLINK_AUDIT,
		    LX_NETLINK_NLMSG_NONE, lx_netlink_audit },
		{ LX_NETLINK_KOBJECT_UEVENT,
		    LX_NETLINK_NLMSG_NONE, lx_netlink_kobject_uevent },
		{ LX_NETLINK_NLMSG_NOOP, LX_NETLINK_NLMSG_NONE, NULL }
	};

	if (msg->msg_name != NULL) {
		lx_netlink_sockaddr_t *lxsa =
		    (lx_netlink_sockaddr_t *)msg->msg_name;

		if (msg->msg_namelen != sizeof (lx_netlink_sockaddr_t) ||
		    lxsa->lxnl_family != AF_LX_NETLINK) {
			return (EINVAL);
		}

		/*
		 * If this message is targeted beyond just the OS kernel, an
		 * access check must be made.
		 */
		if (lxsa->lxnl_port != 0 || lxsa->lxnl_groups != 0) {
			int err;
			char buf[LX_UNSUP_BUFSZ];

			err = lx_netlink_access(lxsock, cr, LXNL_SENDMSG);
			if (err != 0) {
				return (err);
			}

			/*
			 * Support for netlink messages beyond rtnetlink(7) is
			 * non-existent at this time.  These messages are
			 * tolerated, rather than tossing a potentially fatal
			 * error to the application.
			 */
			(void) snprintf(buf, LX_UNSUP_BUFSZ,
			    "netlink sendmsg addr port:%X groups:%08X",
			    lxsa->lxnl_port, lxsa->lxnl_groups);
			lx_unsupported(buf);
		}
	}

	if (DB_TYPE(mp) != M_DATA || MBLKL(mp) < sizeof (lx_netlink_hdr_t)) {
		freemsg(mp);
		return (EPROTO);
	}

	for (i = 0; handlers[i].func != NULL; i++) {
		if (lxsock->lxns_proto != handlers[i].proto)
			continue;

		if (handlers[i].type != LX_NETLINK_NLMSG_NONE &&
		    hdr->lxnh_type != handlers[i].type)
			continue;

		rval = handlers[i].func(lxsock, hdr, mp);
		freemsg(mp);

		return (rval);
	}

	/*
	 * An unrecognized message.  We will bounce up an EOPNOTSUPP reply.
	 */
	rval = lx_netlink_reply_error(lxsock, hdr, EOPNOTSUPP);
	freemsg(mp);

	return (rval);
}

/*ARGSUSED*/
static int
lx_netlink_close(sock_lower_handle_t handle, int flags, cred_t *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle, *sock, **prev;

	mutex_enter(&lx_netlink_lock);

	prev = &lx_netlink_head;

	for (sock = *prev; sock != lxsock; sock = sock->lxns_next)
		prev = &sock->lxns_next;

	*prev = sock->lxns_next;

	mutex_exit(&lx_netlink_lock);

	(void) ldi_close(lxsock->lxns_iphandle, FREAD, kcred);
	(void) ldi_close(lxsock->lxns_ip6handle, FREAD, kcred);
	kmem_free(lxsock, sizeof (lx_netlink_sock_t));

	return (0);
}

static sock_downcalls_t sock_lx_netlink_downcalls = {
	lx_netlink_activate,		/* sd_activate */
	sock_accept_notsupp,		/* sd_accept */
	lx_netlink_bind,		/* sd_bind */
	sock_listen_notsupp,		/* sd_listen */
	sock_connect_notsupp,		/* sd_connect */
	sock_getpeername_notsupp,	/* sd_getpeername */
	lx_netlink_getsockname,		/* sd_getsockname */
	lx_netlink_getsockopt,		/* sd_getsockopt */
	lx_netlink_setsockopt,		/* sd_setsockopt */
	lx_netlink_send,		/* sd_send */
	NULL,				/* sd_send_uio */
	NULL,				/* sd_recv_uio */
	NULL,				/* sd_poll */
	sock_shutdown_notsupp,		/* sd_shutdown */
	sock_clr_flowctrl_notsupp,	/* sd_setflowctrl */
	sock_ioctl_notsupp,		/* sd_ioctl */
	lx_netlink_close		/* sd_close */
};

/*ARGSUSED*/
static sock_lower_handle_t
lx_netlink_create(int family, int type, int proto,
    sock_downcalls_t **sock_downcalls, uint_t *smodep, int *errorp,
    int flags, cred_t *credp)
{
	lx_netlink_sock_t *lxsock;
	ldi_handle_t handle, handle6;
	cred_t *kcred = zone_kcred();
	int err;

	if (family != AF_LX_NETLINK ||
	    (type != SOCK_DGRAM && type != SOCK_RAW)) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	switch (proto) {
	case LX_NETLINK_ROUTE:
	case LX_NETLINK_AUDIT:
	case LX_NETLINK_KOBJECT_UEVENT:
		break;

	default:
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	if ((err = ldi_open_by_name(DEV_IP, FREAD, kcred,
	    &handle, lx_netlink_ldi)) != 0) {
		*errorp = err;
		return (NULL);
	}

	if ((err = ldi_open_by_name(DEV_IP6, FREAD, kcred,
	    &handle6, lx_netlink_ldi)) != 0) {
		(void) ldi_close(handle, FREAD, kcred);
		*errorp = err;
		return (NULL);
	}

	*sock_downcalls = &sock_lx_netlink_downcalls;
	*smodep = SM_ATOMIC;

	lxsock = kmem_zalloc(sizeof (lx_netlink_sock_t), KM_SLEEP);
	lxsock->lxns_iphandle = handle;
	lxsock->lxns_ip6handle = handle6;
	lxsock->lxns_bufsize = lx_netlink_bufsize;
	lxsock->lxns_proto = proto;

	mutex_enter(&lx_netlink_lock);

	lxsock->lxns_next = lx_netlink_head;
	lx_netlink_head = lxsock;

	mutex_exit(&lx_netlink_lock);

	return ((sock_lower_handle_t)lxsock);
}

static void
lx_netlink_init(void)
{
	major_t major = mod_name_to_major("ip");
	int err;

	VERIFY(major != DDI_MAJOR_T_NONE);

	err = ldi_ident_from_major(major, &lx_netlink_ldi);
	VERIFY(err == 0);
}

static void
lx_netlink_fini(void)
{
	ldi_ident_release(lx_netlink_ldi);
}

static smod_reg_t sinfo = {
	SOCKMOD_VERSION,
	"lx_netlink",
	SOCK_UC_VERSION,
	SOCK_DC_VERSION,
	lx_netlink_create,
	NULL
};

/* modldrv structure */
static struct modlsockmod sockmod = {
	&mod_sockmodops, "AF_LX_NETLINK socket module", &sinfo
};

/* modlinkage structure */
static struct modlinkage ml = {
	MODREV_1,
	&sockmod,
	NULL
};

int
_init(void)
{
	int err;

	lx_netlink_init();

	if ((err = mod_install(&ml)) != 0)
		lx_netlink_fini();

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int err = 0;

	mutex_enter(&lx_netlink_lock);

	if (lx_netlink_head != NULL)
		err = EBUSY;

	mutex_exit(&lx_netlink_lock);

	if (err == 0 && (err = mod_remove(&ml)) == 0)
		lx_netlink_fini();

	return (err);
}
