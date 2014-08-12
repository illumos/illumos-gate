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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
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
#include <inet/ip.h>
#include <inet/ip_impl.h>

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
#define	LX_NETLINK_RTA_UNSPEC			1
#define	LX_NETLINK_RTA_DST			2
#define	LX_NETLINK_RTA_SRC			3
#define	LX_NETLINK_RTA_IIF			4
#define	LX_NETLINK_RTA_OIF			5
#define	LX_NETLINK_RTA_GATEWAY			6
#define	LX_NETLINK_RTA_PRIORITY			7
#define	LX_NETLINK_RTA_PREFSRC			8
#define	LX_NETLINK_RTA_METRICS			9
#define	LX_NETLINK_RTA_MULTIPATH		10
#define	LX_NETLINK_RTA_PROTOINFO		11
#define	LX_NETLINK_RTA_FLOW			12
#define	LX_NETLINK_RTA_CACHEINFO		13
#define	LX_NETLINK_RTA_SESSION			14
#define	LX_NETLINK_RTA_MP_ALGO			15
#define	LX_NETLINK_RTA_TABLE			16
#define	LX_NETLINK_RTA_MARK			17
#define	LX_NETLINK_RTA_MFC_STATS		18

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
 * Linux address families.
 */
#define	LX_AF_INET		2
#define	LX_AF_INET6		10
#define	LX_AF_NETLINK		16

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
	uint8_t		lxnl_ifi_type;		/* device type */
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
	uint32_t lxns_bufsize;			/* buffer size */
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
static uint32_t lx_netlink_port;		/* next port identifier */
static int lx_netlink_bufsize = 4096;		/* default buffer size */
static int lx_netlink_flowctrld;		/* # of times flow controlled */

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
	if (level == SOL_SOCKET)
		return (0);

	return (EOPNOTSUPP);
}

/*ARGSUSED*/
static int
lx_netlink_bind(sock_lower_handle_t handle, struct sockaddr *name,
    socklen_t namelen, struct cred *cr)
{
	lx_netlink_sockaddr_t *lxsa = (lx_netlink_sockaddr_t *)name;

	if (namelen != sizeof (lx_netlink_sockaddr_t) ||
	    lxsa->lxnl_family != AF_LX_NETLINK) {
		return (EINVAL);
	}

	if (lxsa->lxnl_groups != 0 || lxsa->lxnl_port != 0)
		return (EOPNOTSUPP);

	return (0);
}

/*ARGSUSED*/
static int
lx_netlink_getsockname(sock_lower_handle_t handle, struct sockaddr *sa,
    socklen_t *len, struct cred *cr)
{
	lx_netlink_sock_t *lxsock = (lx_netlink_sock_t *)handle;
	lx_netlink_sockaddr_t *lxsa = (lx_netlink_sockaddr_t *)sa;
	proc_t *p = curthread->t_procp;

	if (*len < sizeof (lx_netlink_sockaddr_t))
		return (EINVAL);

	/*
	 * Make sure our lies are consistent with the lies told by other liars.
	 */
	if (p->p_brand != &native_brand && curthread != p->p_agenttp) {
		lxsa->lxnl_family = LX_AF_NETLINK;
	} else {
		lxsa->lxnl_family = AF_LX_NETLINK;
	}

	lxsa->lxnl_pad = 0;
	lxsa->lxnl_port = lxsock->lxns_port;
	lxsa->lxnl_groups = 0;

	*len = sizeof (lx_netlink_sockaddr_t);

	return (0);
}

static mblk_t *
lx_netlink_alloc_mp1()
{
	return (allocb(sizeof (struct T_unitdata_ind) +
	    sizeof (lx_netlink_sockaddr_t), 0));
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

	if ((mp1 = lx_netlink_alloc_mp1()) == NULL) {
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
	uint32_t align, alignto = LX_NETLINK_NLA_ALIGNTO;
	mblk_t *mp = reply->lxnr_mp;

	if (reply->lxnr_errno)
		return;

	align = (alignto - (size & (alignto - 1))) & (alignto - 1);

	hdr = (lx_netlink_hdr_t *)mp->b_rptr;

	if (hdr->lxnh_len + size + align > lxsock->lxns_bufsize) {
		reply->lxnr_errno = E2BIG;
		return;
	}

	bcopy(payload, mp->b_wptr, size);

	hdr->lxnh_len += size + align;
	mp->b_wptr += size + align;
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
	hdr->lxnh_len = sizeof (lx_netlink_hdr_t);
	hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
	hdr->lxnh_pid = lxsock->lxns_port;

	mp->b_wptr += sizeof (lx_netlink_hdr_t);

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
	lx_netlink_sockaddr_t *lxsa;
	struct T_unitdata_ind *tunit;
	int error;

	/*
	 * To prevent the stream head from coalescing messages and to indicate
	 * their origin, we send them as T_UNITDATA_IND messages, not as raw
	 * M_DATA.
	 */
	mp1->b_cont = mp;

	mp = mp1;
	mp->b_datap->db_type = M_PROTO;

	tunit = (struct T_unitdata_ind *)mp->b_rptr;
	tunit->PRIM_type = T_UNITDATA_IND;
	tunit->SRC_length = sizeof (lx_netlink_sockaddr_t);
	tunit->SRC_offset = sizeof (*tunit);
	tunit->OPT_length = 0;

	lxsa = (lx_netlink_sockaddr_t *)(mp->b_rptr + sizeof (*tunit));
	lxsa->lxnl_family = AF_LX_NETLINK;
	lxsa->lxnl_port = 0;
	lxsa->lxnl_groups = 0;
	lxsa->lxnl_pad = 0;

	mp->b_wptr += sizeof (*tunit) + sizeof (*lxsa);

	lxsock->lxns_upcalls->su_recv(lxsock->lxns_uphandle, mp,
	    msgdsize(mp), 0, &error, NULL);

	if (error != 0)
		lx_netlink_flowctrld++;
}

static void
lx_netlink_reply_send(lx_netlink_reply_t *reply)
{
	mblk_t *mp1;

	if (reply->lxnr_errno)
		return;

	if ((mp1 = lx_netlink_alloc_mp1()) == NULL) {
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
		err = (lx_netlink_err_t *)mp->b_rptr;
		hdr = &err->lxne_hdr;

		hdr->lxnh_type = LX_NETLINK_NLMSG_ERROR;
		hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
		hdr->lxnh_len = sizeof (lx_netlink_err_t);
		hdr->lxnh_seq = reply->lxnr_hdr.lxnh_seq;
		hdr->lxnh_pid = lxsock->lxns_port;
		err->lxne_failed = reply->lxnr_hdr;
		err->lxne_errno = reply->lxnr_errno;
		mp->b_wptr += sizeof (lx_netlink_err_t);
		reply->lxnr_err = NULL;
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

static void
lx_netlink_getlink_lifreq(lx_netlink_reply_t *reply, struct lifreq *lifr)
{
	lx_netlink_ifinfomsg_t ifi;
	int i;

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

	bzero(&ifi, sizeof (ifi));
	ifi.lxnl_ifi_type = AF_UNSPEC;
	ifi.lxnl_ifi_change = (uint32_t)-1;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFINDEX, lifr) != 0)
		return;

	ifi.lxnl_ifi_index = lifr->lifr_index;

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFFLAGS, lifr) != 0)
		return;

	for (i = 0; flags[i].native; i++) {
		if (lifr->lifr_flags & flags[i].native)
			ifi.lxnl_ifi_flags |= flags[i].lx;
	}

	lx_netlink_reply_msg(reply, &ifi, sizeof (lx_netlink_ifinfomsg_t));

	lx_netlink_reply_attr_string(reply,
	    LX_NETLINK_IFLA_IFNAME, lifr->lifr_name);

	if (lx_netlink_reply_ioctl(reply, SIOCGLIFMTU, lifr) != 0)
		return;

	lx_netlink_reply_attr_int32(reply, LX_NETLINK_IFLA_MTU, lifr->lifr_mtu);

	/*
	 * We don't have a notion of TX queue length (or not an easily
	 * accessible one, anyway), so we lie.  (Which is to say we lie more
	 * than we're already lying -- which is saying something.)
	 */
	lx_netlink_reply_attr_int32(reply, LX_NETLINK_IFLA_TXQLEN, 1);

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

	if (!(lifr->lifr_flags & IFF_NOLOCAL)) {
		if (lx_netlink_reply_ioctl(reply, SIOCGLIFSUBNET, lifr) != 0)
			return;

		ifa.lxnl_ifa_prefixlen = lifr->lifr_addrlen;

		if (lx_netlink_reply_ioctl(reply, SIOCGLIFADDR, lifr) != 0)
			return;

		if (lifr->lifr_addr.ss_family == AF_INET) {
			struct sockaddr_in *sin;

			ifa.lxnl_ifa_family = LX_AF_INET;

			lx_netlink_reply_msg(reply, &ifa,
			    sizeof (lx_netlink_ifaddrmsg_t));

			sin = (struct sockaddr_in *)&lifr->lifr_addr;

			lx_netlink_reply_attr_int32(reply,
			    LX_NETLINK_IFA_ADDRESS, sin->sin_addr.s_addr);
		} else {
			struct sockaddr_in6 *sin;

			ifa.lxnl_ifa_family = LX_AF_INET6;

			lx_netlink_reply_msg(reply, &ifa,
			    sizeof (lx_netlink_ifaddrmsg_t));

			sin = (struct sockaddr_in6 *)&lifr->lifr_addr;

			lx_netlink_reply_attr(reply, LX_NETLINK_IFA_ADDRESS,
			    &sin->sin6_addr, sizeof (sin->sin6_addr));
		}
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
		{ LX_NETLINK_AUDIT,
		    LX_NETLINK_NLMSG_NONE, lx_netlink_audit },
		{ LX_NETLINK_KOBJECT_UEVENT,
		    LX_NETLINK_NLMSG_NONE, lx_netlink_kobject_uevent },
		{ LX_NETLINK_NLMSG_NOOP, LX_NETLINK_NLMSG_NONE, NULL }
	};

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
	sock_getsockopt_notsupp,	/* sd_getsockopt */
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
	lxsock->lxns_port = ++lx_netlink_port;
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
