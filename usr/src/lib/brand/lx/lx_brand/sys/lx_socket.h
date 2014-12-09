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
 * Copyright 2006 Sun Microsystems, Inc.	All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_LX_SOCKET_H
#define	_SYS_LX_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/lx_types.h>

/*
 * Linux address family definitions
 * Some of these are not supported
 */
#define	LX_AF_UNSPEC		0  /* Unspecified */
#define	LX_AF_UNIX		1  /* local file/pipe name */
#define	LX_AF_INET		2  /* IP protocol family */
#define	LX_AF_AX25		3  /* Amateur Radio AX.25 */
#define	LX_AF_IPX		4  /* Novell Internet Protocol */
#define	LX_AF_APPLETALK		5  /* Appletalk */
#define	LX_AF_NETROM		6  /* Amateur radio */
#define	LX_AF_BRIDGE		7  /* Multiprotocol bridge */
#define	LX_AF_ATMPVC		8  /* ATM PVCs */
#define	LX_AF_X25		9  /* X.25 */
#define	LX_AF_INET6		10 /* IPV 6 */
#define	LX_AF_ROSE		11 /* Amateur Radio X.25 */
#define	LX_AF_DECnet		12 /* DECnet */
#define	LX_AF_NETBEUI		13 /* 802.2LLC */
#define	LX_AF_SECURITY		14 /* Security callback */
#define	LX_AF_KEY		15 /* key management */
#define	LX_AF_ROUTE		16 /* Alias to emulate 4.4BSD */
#define	LX_AF_PACKET		17 /* Packet family */
#define	LX_AF_ASH		18 /* Ash ? */
#define	LX_AF_ECONET		19 /* Acorn Econet */
#define	LX_AF_ATMSVC		20 /* ATM SVCs */
#define	LX_AF_SNA		22 /* Linux SNA */
#define	LX_AF_IRDA		23 /* IRDA sockets */
#define	LX_AF_PPPOX		24 /* PPPoX sockets */
#define	LX_AF_WANPIPE		25 /* Wanpipe API sockets */
#define	LX_AF_BLUETOOTH		31 /* Bluetooth sockets */
#define	LX_AF_MAX		32 /* MAX socket type  */

#define	AF_NOTSUPPORTED		-1
#define	AF_INVAL		-2

/*
 * Linux ARP protocol hardware identifiers
 */
#define	LX_ARPHRD_ETHER		1	/* Ethernet */
#define	LX_ARPHRD_LOOPBACK	772	/* Loopback */
#define	LX_ARPHRD_VOID		0xffff	/* Unknown */

/*
 * Linux socket type definitions
 */
#define	LX_SOCK_STREAM		1  /* Connection-based byte streams */
#define	LX_SOCK_DGRAM		2  /* Connectionless, datagram */
#define	LX_SOCK_RAW		3  /* Raw protocol interface */
#define	LX_SOCK_RDM		4  /* Reliably-delivered message */
#define	LX_SOCK_SEQPACKET	5  /* Sequenced packet stream */
#define	LX_SOCK_PACKET		10 /* Linux specific */
#define	LX_SOCK_MAX		11

/*
 * The Linux socket type can be or-ed with other flags (e.g. SOCK_CLOEXEC).
 */
#define	LX_SOCK_TYPE_MASK	0xf

/*
 * Linux flags for socket, socketpair and accept4. These are or-ed into the
 * socket type value. In the Linux net.h header these come from fcntl.h (note
 * that they are in octal in the Linux header).
 */
#define	LX_SOCK_CLOEXEC		0x80000
#define	LX_SOCK_NONBLOCK	0x800

#define	SOCK_NOTSUPPORTED	-1
#define	SOCK_INVAL		-2

/*
 * IP Protocol levels. Some of these match the Illumos IPPROTO_* values.
 */
#define	LX_IPPROTO_IP		0
#define	LX_IPPROTO_ICMP		1
#define	LX_IPPROTO_IGMP		2
#define	LX_IPPROTO_TCP		6
#define	LX_IPPROTO_UDP		17
#define	LX_IPPROTO_IPV6		41
#define	LX_IPPROTO_RAW		255

/*
 * Options for use with [gs]etsockopt at the IP level.
 * IPPROTO_IP
 */
#define	LX_IP_TOS		1
#define	LX_IP_TTL		2
#define	LX_IP_HDRINCL		3
#define	LX_IP_OPTIONS		4
#define	LX_IP_ROUTER_ALERT	5
#define	LX_IP_RECVOPTS		6
#define	LX_IP_RETOPTS		7
#define	LX_IP_PKTINFO		8
#define	LX_IP_PKTOPTIONS	9
#define	LX_IP_MTU_DISCOVER	10
#define	LX_IP_RECVERR		11
#define	LX_IP_RECVTTL		12
#define	LX_IP_RECVTOS		13
#define	LX_IP_MTU		14
#define	LX_IP_FREEBIND		15
#define	LX_IP_IPSEC_POLICY	16
#define	LX_IP_XFRM_POLICY	17
#define	LX_IP_PASSSEC		18
#define	LX_IP_TRANSPARENT	19
#define	LX_IP_ORIGDSTADDR	20
#define	LX_IP_MINTTL		21
#define	LX_IP_NODEFRAG		22
/* Linux apparently leaves a gap here */
#define	LX_IP_MULTICAST_IF	32
#define	LX_IP_MULTICAST_TTL	33
#define	LX_IP_MULTICAST_LOOP	34
#define	LX_IP_ADD_MEMBERSHIP	35
#define	LX_IP_DROP_MEMBERSHIP	36
#define	LX_IP_UNBLOCK_SOURC	37
#define	LX_IP_BLOCK_SOURCE	38
#define	LX_IP_ADD_SOURCE_MEMBERSHIP 39
#define	LX_IP_DROP_SOURCE_MEMBERSHIP 40
#define	LX_IP_MSFILTER		41
#define	LX_MCAST_JOIN_GROUP	42
#define	LX_MCAST_BLOCK_SOURCE	43
#define	LX_MCAST_UNBLOCK_SOURCE	44
#define	LX_MCAST_LEAVE_GROUP	45
#define	LX_MCAST_JOIN_SOURCE_GROUP 46
#define	LX_MCAST_LEAVE_SOURCE_GROUP 47
#define	LX_MCAST_MSFILTER	48
#define	LX_IP_MULTICAST_ALL	49
#define	LX_IP_UNICAST_IF	50


/*
 * Options for use with [gs]etsockopt at the IP level.
 * IPPROTO_IPV6
 */

#define	LX_IPV6_ADDRFORM	1
#define	LX_IPV6_2292PKTINFO	2
#define	LX_IPV6_2292HOPOPTS	3
#define	LX_IPV6_2292DSTOPTS	4
#define	LX_IPV6_2292RTHDR	5
#define	LX_IPV6_2292PKTOPTIONS	6
#define	LX_IPV6_CHECKSUM	7
#define	LX_IPV6_2292HOPLIMIT	8
#define	LX_IPV6_NEXTHOP		9
#define	LX_IPV6_AUTHHDR		10
#define	LX_IPV6_UNICAST_HOPS	16
#define	LX_IPV6_MULTICAST_IF	17
#define	LX_IPV6_MULTICAST_HOPS	18
#define	LX_IPV6_MULTICAST_LOOP	19
#define	LX_IPV6_JOIN_GROUP	20
#define	LX_IPV6_LEAVE_GROUP	21
#define	LX_IPV6_ROUTER_ALERT	22
#define	LX_IPV6_MTU_DISCOVER	23
#define	LX_IPV6_MTU		24
#define	LX_IPV6_RECVERR		25
#define	LX_IPV6_V6ONLY		26
#define	LX_IPV6_JOIN_ANYCAST	27
#define	LX_IPV6_LEAVE_ANYCAST	28
#define	LX_IPV6_IPSEC_POLICY	34
#define	LX_IPV6_XFRM_POLICY	35

#define	LX_IPV6_RECVPKTINFO	49
#define	LX_IPV6_PKTINFO		50
#define	LX_IPV6_RECVHOPLIMIT	51
#define	LX_IPV6_HOPLIMIT	52
#define	LX_IPV6_RECVHOPOPTS	53
#define	LX_IPV6_HOPOPTS		54
#define	LX_IPV6_RTHDRDSTOPTS	55
#define	LX_IPV6_RECVRTHDR	56
#define	LX_IPV6_RTHDR		57
#define	LX_IPV6_RECVDSTOPTS	58
#define	LX_IPV6_DSTOPTS		59
#define	LX_IPV6_RECVTCLASS	66
#define	LX_IPV6_TCLASS		67

/*
 * Options for use with [gs]etsockopt at the TCP level.
 * IPPROTO_TCP
 */
#define	LX_TCP_NODELAY		1  /* Don't delay send to coalesce packets  */
#define	LX_TCP_MAXSEG		2  /* Set maximum segment size  */
#define	LX_TCP_CORK		3  /* Control sending of partial frames  */
#define	LX_TCP_KEEPIDLE		4  /* Start keeplives after this period */
#define	LX_TCP_KEEPINTVL	5  /* Interval between keepalives */
#define	LX_TCP_KEEPCNT		6  /* Number of keepalives before death */
#define	LX_TCP_SYNCNT		7  /* Number of SYN retransmits */
#define	LX_TCP_LINGER2		8  /* Life time of orphaned FIN-WAIT-2 state */
#define	LX_TCP_DEFER_ACCEPT	9  /* Wake up listener only when data arrive */
#define	LX_TCP_WINDOW_CLAMP	10 /* Bound advertised window */
#define	LX_TCP_INFO		11 /* Information about this connection. */
#define	LX_TCP_QUICKACK		12 /* Bock/reenable quick ACKs.  */
#define	LX_TCP_CONGESTION	13 /* Congestion control algorithm */
#define	LX_TCP_MD5SIG		14 /* TCP MD5 Signature (RFC2385) */
#define	LX_TCP_THIN_LINEAR_TIMEOUTS 16 /* Use linear timeouts on thin streams */
#define	LX_TCP_THIN_DUPACK	17 /* Fast retrans. after 1 dupack */
#define	LX_TCP_USER_TIMEOUT	18 /* How long for loss retry before timeout */
#define	LX_TCP_REPAIR		19 /* TCP socket under repair */
#define	LX_TCP_REPAIR_QUEUE	20
#define	LX_TCP_QUEUE_SEQ	21
#define	LX_TCP_REPAIR_OPTIONS	22
#define	LX_TCP_FASTOPEN		23 /* Enable FastOpen on listeners */
#define	LX_TCP_TIMESTAMP	24
#define	LX_TCP_NOTSENT_LOWAT	25 /* limit number of unsent bytes */

/*
 * Options for use with [gs]etsockopt at the IGMP level.
 * IPPROTO_IGMP
 */
#define	LX_IGMP_MINLEN				8
#define	LX_IGMP_MAX_HOST_REPORT_DELAY		10
#define	LX_IGMP_HOST_MEMBERSHIP_QUERY		0x11
#define	LX_IGMP_HOST_MEMBERSHIP_REPORT		0x12
#define	LX_IGMP_DVMRP				0x13
#define	LX_IGMP_PIM				0x14
#define	LX_IGMP_TRACE				0x15
#define	LX_IGMP_HOST_NEW_MEMBERSHIP_REPORT	0x16
#define	LX_IGMP_HOST_LEAVE_MESSAGE		0x17
#define	LX_IGMP_MTRACE_RESP			0x1e
#define	LX_IGMP_MTRACE				0x1f

/*
 * Options for use with [gs]etsockopt at the SOL_SOCKET level.
 */
#define	LX_SOL_SOCKET				1

#define	LX_SCM_RIGHTS				1
#define	LX_SCM_CRED				2

#define	LX_SO_DEBUG				1
#define	LX_SO_REUSEADDR				2
#define	LX_SO_TYPE				3
#define	LX_SO_ERROR				4
#define	LX_SO_DONTROUTE				5
#define	LX_SO_BROADCAST				6
#define	LX_SO_SNDBUF				7
#define	LX_SO_RCVBUF				8
#define	LX_SO_KEEPALIVE				9
#define	LX_SO_OOBINLINE				10
#define	LX_SO_NO_CHECK				11
#define	LX_SO_PRIORITY				12
#define	LX_SO_LINGER				13
#define	LX_SO_BSDCOMPAT				14
#define	LX_SO_REUSEPORT				15
/*
 * For Linux see unix(7) man page SO_PASSCRED description. For Illumos see
 * socket.h(3HEAD) man page SO_RECVUCRED description.
 */
#define	LX_SO_PASSCRED				16
#define	LX_SO_PEERCRED				17
#define	LX_SO_RCVLOWAT				18
#define	LX_SO_SNDLOWAT				19
#define	LX_SO_RCVTIMEO				20
#define	LX_SO_SNDTIMEO				21
/* Security levels - as per NRL IPv6 - don't actually do anything */
#define	LX_SO_SECURITY_AUTHENTICATION		22
#define	LX_SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define	LX_SO_SECURITY_ENCRYPTION_NETWORK	24
#define	LX_SO_BINDTODEVICE			25
/* Socket filtering */
#define	LX_SO_ATTACH_FILTER			26
#define	LX_SO_DETACH_FILTER			27
#define	LX_SO_PEERNAME				28
#define	LX_SO_TIMESTAMP				29
#define	LX_SCM_TIMESTAMP			LX_SO_TIMESTAMP
#define	LX_SO_ACCEPTCONN			30

#define	LX_SO_PEERSEC				31
#define	LX_SO_SNDBUFFORCE			32
#define	LX_SO_RCVBUFFORCE			33
#define	LX_SO_PASSSEC				34
#define	LX_SO_TIMESTAMPNS			35
#define	LX_SCM_TIMESTAMPNS			LX_SO_TIMESTAMPNS
#define	LX_SO_MARK				36
#define	LX_SO_TIMESTAMPING			37
#define	LX_SCM_TIMESTAMPING			LX_SO_TIMESTAMPING
#define	LX_SO_PROTOCOL				38
#define	LX_SO_DOMAIN				39
#define	LX_SO_RXQ_OVFL				40
#define	LX_SO_WIFI_STATUS			41
#define	LX_SCM_WIFI_STATUS			LX_SO_WIFI_STATUS
#define	LX_SO_PEEK_OFF				42
#define	LX_SO_NOFCS				43
#define	LX_SO_LOCK_FILTER			44
#define	LX_SO_SELECT_ERR_QUEUE			45
#define	LX_SO_BUSY_POLL				46
#define	LX_SO_MAX_PACING_RATE			47
#define	LX_SO_BPF_EXTENSIONS			48

/*
 * Options for use with [gs]etsockopt at the RAW level.
 * IPPROTO_RAW
 */
#define	LX_ICMP_FILTER				1

/*
 * Linux socketcall indices.
 * These constitute all 17 socket related system calls
 *
 * These system calls are called via a single system call socketcall().
 * The first arg being the endex of the system call type
 */
#define	LX_SOCKET		1
#define	LX_BIND			2
#define	LX_CONNECT		3
#define	LX_LISTEN		4
#define	LX_ACCEPT		5
#define	LX_GETSOCKNAME		6
#define	LX_GETPEERNAME		7
#define	LX_SOCKETPAIR		8
#define	LX_SEND			9
#define	LX_RECV			10
#define	LX_SENDTO		11
#define	LX_RECVFROM		12
#define	LX_SHUTDOWN		13
#define	LX_SETSOCKOPT		14
#define	LX_GETSOCKOPT		15
#define	LX_SENDMSG		16
#define	LX_RECVMSG		17
#define	LX_ACCEPT4		18
#define	LX_RECVMMSG		19
#define	LX_SENDMMSG		20

/*
 * Linux socket flags for use with recv(2)/send(2)/recvmsg(2)/sendmsg(2)
 */
#define	LX_MSG_OOB		1
#define	LX_MSG_PEEK		2
#define	LX_MSG_DONTROUTE	4
#define	LX_MSG_CTRUNC		8
#define	LX_MSG_PROXY		0x10
#define	LX_MSG_TRUNC		0x20
#define	LX_MSG_DONTWAIT		0x40
#define	LX_MSG_EOR		0x80
#define	LX_MSG_WAITALL		0x100
#define	LX_MSG_FIN		0x200
#define	LX_MSG_SYN		0x400
#define	LX_MSG_CONFIRM		0x800
#define	LX_MSG_RST		0x1000
#define	LX_MSG_ERRQUEUE		0x2000
#define	LX_MSG_NOSIGNAL		0x4000
#define	LX_MSG_MORE		0x8000
#define	LX_MSG_WAITFORONE	0x10000
#define	LX_MSG_FASTOPEN		0x20000000
#define	LX_MSG_CMSG_CLOEXEC	0x40000000

struct lx_msghdr {
	void		*msg_name;		/* optional address */
	socklen_t	msg_namelen;		/* size of address */
	struct iovec	*msg_iov;		/* scatter/gather array */
	int		msg_iovlen;		/* # elements in msg_iov */
	void		*msg_control;		/* ancillary data */
	socklen_t	msg_controllen;		/* ancillary data buffer len */
	int		msg_flags;		/* flags on received message */
};

struct lx_ucred {
	pid_t		lxu_pid;
	lx_uid_t	lxu_uid;
	lx_gid_t	lxu_gid;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SOCKET_H */
