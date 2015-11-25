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
 * Copyright 2015 Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_LX_SOCKET_H
#define	_SYS_LX_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/lx_types.h>

#define	LX_DEV_LOG			"/dev/log"
#define	LX_DEV_LOG_REDIRECT		"/var/run/.dev_log_redirect"
#define	LX_DEV_LOG_REDIRECT_LEN		18 /* len appended to /dev/log len */
#define	LX_DEV_LOG_REDIRECT_TOT_LEN	26

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
#define	LX_AF_MAX		33 /* MAX socket type  */

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
 * PF_PACKET protocol definitions.
 */
#define	LX_ETH_P_802_3	0x0001
#define	LX_ETH_P_ALL	0x0003
#define	LX_ETH_P_802_2	0x0004
#define	LX_ETH_P_IP	0x0800
#define	LX_ETH_P_ARP	0x0806
#define	LX_ETH_P_IPV6	0x86DD

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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SOCKET_H */
