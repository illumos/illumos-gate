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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_LX_SOCKET_H
#define	_SYS_LX_SOCKET_H

#ifdef	__cplusplus
extern "C" {
#endif

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
 * PF_PACKET protocol definitions.
 */
#define	LX_ETH_P_802_3	0x0001
#define	LX_ETH_P_ALL	0x0003
#define	LX_ETH_P_802_2	0x0004
#define	LX_ETH_P_IP	0x0800
#define	LX_ETH_P_ARP	0x0806
#define	LX_ETH_P_IPV6	0x86DD

/*
 * IP Protocol levels. Some of these match the Illumos IPPROTO_* values.
 */
#define	LX_IPPROTO_IP		0
#define	LX_IPPROTO_ICMP		1
#define	LX_IPPROTO_IGMP		2
#define	LX_IPPROTO_TCP		6
#define	LX_IPPROTO_UDP		17
#define	LX_IPPROTO_IPV6		41
#define	LX_IPPROTO_ICMPV6	58
#define	LX_IPPROTO_RAW		255

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
 * Linux socket flags for use with recv(2)/send(2)/recvmsg(2)/sendmsg(2)
 */
#define	LX_MSG_OOB		0x1
#define	LX_MSG_PEEK		0x2
#define	LX_MSG_DONTROUTE	0x4
#define	LX_MSG_CTRUNC		0x8
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

typedef struct lx_msghdr {
	void		*msg_name;	/* optional address */
	socklen_t	msg_namelen;	/* size of address */
	struct iovec	*msg_iov;	/* scatter/gather array */
	int		msg_iovlen;	/* # elements in msg_iov */
	void		*msg_control;	/* ancillary data */
	socklen_t	msg_controllen;	/* ancillary data buffer len */
	int		msg_flags;	/* flags on received message */
} lx_msghdr_t;


#if defined(_LP64)

typedef struct lx_msghdr32 {
	caddr32_t	msg_name;	/* optional address */
	uint32_t	msg_namelen;	/* size of address */
	caddr32_t	msg_iov;	/* scatter/gather array */
	int32_t		msg_iovlen;	/* # elements in msg_iov */
	caddr32_t	msg_control;	/* ancillary data */
	uint32_t	msg_controllen;	/* ancillary data buffer len */
	int32_t		msg_flags;	/* flags on received message */
} lx_msghdr32_t;

#endif

typedef struct lx_sockaddr_in6 {
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;  /* Depends on scope of sin6_addr */
	/* one 32-bit field shorter than illumos */
} lx_sockaddr_in6_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SOCKET_H */
