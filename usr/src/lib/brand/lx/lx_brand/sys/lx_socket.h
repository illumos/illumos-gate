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
 */

#ifndef _SYS_LX_SOCKET_H
#define	_SYS_LX_SOCKET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#define	SOCK_NOTSUPPORTED	-1
#define	SOCK_INVAL		-2

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
#define	LX_IP_MULTICAST_IF	32
#define	LX_IP_MULTICAST_TTL	33
#define	LX_IP_MULTICAST_LOOP	34
#define	LX_IP_ADD_MEMBERSHIP	35
#define	LX_IP_DROP_MEMBERSHIP	36

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
/* To add :#define	LX_SO_REUSEPORT 15 */
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
