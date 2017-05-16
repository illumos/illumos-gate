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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#ifndef	_SYS_SOCKET_H
#define	_SYS_SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/feature_tests.h>
#include <sys/socket_impl.h>
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#ifndef	_KERNEL
#include <sys/netconfig.h>
#endif	/* !_KERNEL */
#include <netinet/in.h>
#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_SOCKLEN_T
#define	_SOCKLEN_T

/*
 * The socklen definitions are reproduced in netinet/in.h for the inet6_
 * functions.  Exposing all of sys/socket.h via netinet/in.h breaks existing
 * applications and is not required by austin.
 */
#if defined(_XPG4_2) && !defined(_XPG5) && !defined(_LP64)
typedef	size_t		socklen_t;
#else
typedef	uint32_t	socklen_t;
#endif	/* defined(_XPG4_2) && !defined(_XPG5) && !defined(_LP64) */

#if defined(_XPG4_2) || defined(_BOOT)
typedef	socklen_t	*_RESTRICT_KYWD Psocklen_t;
#else
typedef	void		*_RESTRICT_KYWD Psocklen_t;
#endif	/* defined(_XPG4_2) || defined(_BOOT) */

#endif	/* _SOCKLEN_T */

/*
 * Definitions related to sockets: types, address families, options.
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#ifndef	NC_TPI_CLTS
#define	NC_TPI_CLTS	1		/* must agree with netconfig.h */
#define	NC_TPI_COTS	2		/* must agree with netconfig.h */
#define	NC_TPI_COTS_ORD	3		/* must agree with netconfig.h */
#define	NC_TPI_RAW	4		/* must agree with netconfig.h */
#endif	/* !NC_TPI_CLTS */
#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Types
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	SOCK_STREAM	NC_TPI_COTS	/* stream socket */
#define	SOCK_DGRAM	NC_TPI_CLTS	/* datagram socket */
#define	SOCK_RAW	NC_TPI_RAW	/* raw-protocol interface */
#else
#define	SOCK_STREAM	2		/* stream socket */
#define	SOCK_DGRAM	1		/* datagram socket */
#define	SOCK_RAW	4		/* raw-protocol interface */
#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */
#define	SOCK_RDM	5		/* reliably-delivered message */
#define	SOCK_SEQPACKET	6		/* sequenced packet stream */
#define	SOCK_TYPE_MASK	0xffff		/* type reside in these bits only */

/*
 * Flags for socket() and accept4()
 */
#define	SOCK_CLOEXEC	0x080000	/* like open(2) O_CLOEXEC for socket */
#define	SOCK_NONBLOCK	0x100000	/* like O_NONBLOCK */
#define	SOCK_NDELAY	0x200000	/* like O_NDELAY */

/*
 * Option flags per-socket.
 */
#define	SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	SO_LINGER	0x0080		/* linger on close if data present */
#define	SO_OOBINLINE	0x0100		/* leave received OOB data in line */
#define	SO_DGRAM_ERRIND	0x0200		/* Application wants delayed error */
#define	SO_RECVUCRED	0x0400		/* Application wants ucred of sender */

/*
 * Socket options are passed using a signed integer, but it is also rare
 * for more than one to ever be passed at the same time with setsockopt
 * and only one at a time can be retrieved with getsockopt.
 *
 * Since the lower numbers cannot be renumbered for compatibility reasons,
 * it would seem that we need to start a new number space (0x40000000 -
 * 0x7fffffff) for those that don't need to be stored as a bit flag
 * somewhere. This limits the flag options to 30 but that seems to be
 * plenty, anyway. 0x40000000 is reserved for future use.
 */
#define	SO_ATTACH_FILTER	0x40000001
#define	SO_DETACH_FILTER	0x40000002

#ifdef _KERNEL
#define	SO_SND_COPYAVOID 0x0800		/* Internal: use zero-copy */
#define	SO_SND_BUFINFO	0x1000		/* Internal: get buffer info */
					/* when doing zero-copy */

struct so_snd_bufinfo {
	ushort_t	sbi_wroff; 	/* Write offset */
	ssize_t		sbi_maxblk;	/* Max size of a single mblk */
	ssize_t		sbi_maxpsz;	/* Max total size of a mblk chain */
	ushort_t	sbi_tail;	/* Extra space available at the end */
};
#endif /* _KERNEL */

/*
 * N.B.: The following definition is present only for compatibility
 * with release 3.0.  It will disappear in later releases.
 */
#define	SO_DONTLINGER	(~SO_LINGER)	/* ~SO_LINGER */

/*
 * Additional options, not kept in so_options.
 */
#define	SO_SNDBUF	0x1001		/* send buffer size */
#define	SO_RCVBUF	0x1002		/* receive buffer size */
#define	SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	SO_SNDTIMEO	0x1005		/* send timeout */
#define	SO_RCVTIMEO	0x1006		/* receive timeout */
#define	SO_ERROR	0x1007		/* get error status and clear */
#define	SO_TYPE		0x1008		/* get socket type */
#define	SO_PROTOTYPE	0x1009		/* get/set protocol type */
#define	SO_ANON_MLP	0x100a		/* create MLP on anonymous bind */
#define	SO_MAC_EXEMPT	0x100b		/* allow dominated unlabeled peers */
#define	SO_DOMAIN	0x100c		/* get socket domain */
#define	SO_RCVPSH	0x100d		/* receive interval to push data */

/* "Socket"-level control message types: */
#define	SCM_RIGHTS	0x1010		/* access rights (array of int) */
#define	SO_SECATTR	0x1011		/* socket's security attributes */
#define	SCM_UCRED	0x1012		/* sender's ucred */
#define	SO_TIMESTAMP	0x1013		/* socket-level timestamp option */
#define	SCM_TIMESTAMP	SO_TIMESTAMP	/* socket control message timestamp */
#define	SO_ALLZONES	0x1014		/* bind in all zones */
#define	SO_EXCLBIND	0x1015		/* exclusive binding */
#define	SO_MAC_IMPLICIT	0x1016		/* hide mac labels on wire */
#define	SO_VRRP		0x1017		/* VRRP control socket */

#ifdef	_KERNEL
#define	SO_SRCADDR	0x2001		/* Internal: AF_UNIX source address */
#define	SO_FILEP	0x2002		/* Internal: AF_UNIX file pointer */
#define	SO_UNIX_CLOSE	0x2003		/* Internal: AF_UNIX peer closed */
#endif	/* _KERNEL */

/*
 * Socket filter options
 */
#define	FIL_ATTACH	0x1		/* attach filter */
#define	FIL_DETACH	0x2		/* detach filter */
#define	FIL_LIST	0x3		/* list attached filters */

#define	FILNAME_MAX	32
/*
 * Structure returned by FIL_LIST
 */
struct fil_info {
	int	fi_flags;		/* see below (FILF_*) */
	int	fi_pos;			/* position (0 is bottom) */
	char	fi_name[FILNAME_MAX];	/* filter name */
};

#define	FILF_PROG	0x1		/* programmatic attach */
#define	FILF_AUTO	0x2		/* automatic attach */
#define	FILF_BYPASS	0x4		/* filter is not active */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
/*
 * new socket open flags to identify socket and acceptor streams
 */
#define	SO_ACCEPTOR	0x20000		/* acceptor socket */
#define	SO_SOCKSTR	0x40000		/* normal socket stream */
#define	SO_FALLBACK	0x80000		/* fallback to TPI socket */

/*
 * Flags for socket_create() and socket_newconn()
 */
#define	SOCKET_SLEEP	KM_SLEEP
#define	SOCKET_NOSLEEP	KM_NOSLEEP

#endif	/* _KERNEL */

/*
 * Structure used for manipulating linger option.
 */
struct	linger {
	int	l_onoff;		/* option on/off */
	int	l_linger;		/* linger time */
};

/*
 * Levels for (get/set)sockopt() that don't apply to a specific protocol.
 */
#define	SOL_SOCKET	0xffff		/* options for socket level */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	SOL_ROUTE	0xfffe		/* options for routing socket level */
#endif
#define	SOL_PACKET	0xfffd		/* options for packet level */
#define	SOL_FILTER	0xfffc		/* options for socket filter level */

/*
 * Address families.
 *
 * Some of these constant names are copied for the DTrace IP provider in
 * usr/src/lib/libdtrace/common/{ip.d.in, ip.sed.in}, which should be kept
 * in sync.
 */
#define	AF_UNSPEC	0		/* unspecified */
#define	AF_UNIX		1		/* local to host (pipes, portals) */
#define	AF_LOCAL	AF_UNIX		/* Synonym for AF_UNIX */
#define	AF_FILE		AF_UNIX		/* Synonym for AF_UNIX */
#define	AF_INET		2		/* internetwork: UDP, TCP, etc. */
#define	AF_IMPLINK	3		/* arpanet imp addresses */
#define	AF_PUP		4		/* pup protocols: e.g. BSP */
#define	AF_CHAOS	5		/* mit CHAOS protocols */
#define	AF_NS		6		/* XEROX NS protocols */
#define	AF_NBS		7		/* nbs protocols */
#define	AF_ECMA		8		/* european computer manufacturers */
#define	AF_DATAKIT	9		/* datakit protocols */
#define	AF_CCITT	10		/* CCITT protocols, X.25 etc */
#define	AF_SNA		11		/* IBM SNA */
#define	AF_DECnet	12		/* DECnet */
#define	AF_DLI		13		/* Direct data link interface */
#define	AF_LAT		14		/* LAT */
#define	AF_HYLINK	15		/* NSC Hyperchannel */
#define	AF_APPLETALK	16		/* Apple Talk */
#define	AF_NIT		17		/* Network Interface Tap */
#define	AF_802		18		/* IEEE 802.2, also ISO 8802 */
#define	AF_OSI		19		/* umbrella for all families used */
#define	AF_X25		20		/* CCITT X.25 in particular */
#define	AF_OSINET	21		/* AFI = 47, IDI = 4 */
#define	AF_GOSIP	22		/* U.S. Government OSI */
#define	AF_IPX		23		/* Novell Internet Protocol */
#define	AF_ROUTE	24		/* Internal Routing Protocol */
#define	AF_LINK		25		/* Link-layer interface */
#define	AF_INET6	26		/* Internet Protocol, Version 6 */
#define	AF_KEY		27		/* Security Association DB socket */
#define	AF_NCA		28		/* NCA socket */
#define	AF_POLICY	29		/* Security Policy DB socket */
#define	AF_INET_OFFLOAD	30		/* Sun private; do not use */
#define	AF_TRILL	31		/* TRILL interface */
#define	AF_PACKET	32		/* PF_PACKET Linux socket interface */

#define	AF_MAX		32

/*
 * Protocol families, same as address families for now.
 */
#define	PF_UNSPEC	AF_UNSPEC
#define	PF_UNIX		AF_UNIX
#define	PF_LOCAL	PF_UNIX
#define	PF_FILE		PF_UNIX
#define	PF_INET		AF_INET
#define	PF_IMPLINK	AF_IMPLINK
#define	PF_PUP		AF_PUP
#define	PF_CHAOS	AF_CHAOS
#define	PF_NS		AF_NS
#define	PF_NBS		AF_NBS
#define	PF_ECMA		AF_ECMA
#define	PF_DATAKIT	AF_DATAKIT
#define	PF_CCITT	AF_CCITT
#define	PF_SNA		AF_SNA
#define	PF_DECnet	AF_DECnet
#define	PF_DLI		AF_DLI
#define	PF_LAT		AF_LAT
#define	PF_HYLINK	AF_HYLINK
#define	PF_APPLETALK	AF_APPLETALK
#define	PF_NIT		AF_NIT
#define	PF_802		AF_802
#define	PF_OSI		AF_OSI
#define	PF_X25		AF_X25
#define	PF_OSINET	AF_OSINET
#define	PF_GOSIP	AF_GOSIP
#define	PF_IPX		AF_IPX
#define	PF_ROUTE	AF_ROUTE
#define	PF_LINK		AF_LINK
#define	PF_INET6	AF_INET6
#define	PF_KEY		AF_KEY
#define	PF_NCA		AF_NCA
#define	PF_POLICY	AF_POLICY
#define	PF_INET_OFFLOAD	AF_INET_OFFLOAD	/* Sun private; do not use */
#define	PF_TRILL	AF_TRILL
#define	PF_PACKET	AF_PACKET

#define	PF_MAX		AF_MAX

/*
 * Maximum queue length specifiable by listen.
 */
#define	SOMAXCONN	128

/*
 * Message header for recvmsg and sendmsg calls.
 */
struct msghdr {
	void		*msg_name;		/* optional address */
	socklen_t	msg_namelen;		/* size of address */
	struct iovec	*msg_iov;		/* scatter/gather array */
	int		msg_iovlen;		/* # elements in msg_iov */

#if defined(_XPG4_2) || defined(_KERNEL)
	void		*msg_control;		/* ancillary data */
	socklen_t	msg_controllen;		/* ancillary data buffer len */
	int		msg_flags;		/* flags on received message */
#else
	caddr_t		msg_accrights;	/* access rights sent/received */
	int		msg_accrightslen;
#endif	/* defined(_XPG4_2) || defined(_KERNEL) */
};

#if	defined(_KERNEL) || defined(_FAKE_KERNEL)

/*
 *	N.B.:  we assume that omsghdr and nmsghdr are isomorphic, with
 *	the sole exception that nmsghdr has the additional msg_flags
 *	field at the end.
 */
struct omsghdr {
	void		*msg_name;	/* optional address */
	socklen_t	msg_namelen;	/* size of address */
	struct	iovec	*msg_iov;	/* scatter/gather array */
	int		msg_iovlen;	/* # elements in msg_iov */
	caddr_t		msg_accrights;	/* access rights sent/received */
	int		msg_accrightslen;
};

#define	nmsghdr		msghdr

#if defined(_SYSCALL32)

struct omsghdr32 {
	caddr32_t	msg_name;	/* optional address */
	uint32_t	msg_namelen;	/* size of address */
	caddr32_t	msg_iov;	/* scatter/gather array */
	int32_t		msg_iovlen;	/* # elements in msg_iov */
	caddr32_t	msg_accrights;	/* access rights sent/received */
	uint32_t	msg_accrightslen;
};

struct msghdr32 {
	caddr32_t	msg_name;	/* optional address */
	uint32_t	msg_namelen;	/* size of address */
	caddr32_t	msg_iov;	/* scatter/gather array */
	int32_t		msg_iovlen;	/* # elements in msg_iov */
	caddr32_t	msg_control;	/* ancillary data */
	uint32_t	msg_controllen;	/* ancillary data buffer len */
	int32_t		msg_flags;	/* flags on received message */
};

#define	nmsghdr32	msghdr32

#endif	/* _SYSCALL32 */
#endif	/* _KERNEL */

#define	MSG_OOB		0x1		/* process out-of-band data */
#define	MSG_PEEK	0x2		/* peek at incoming message */
#define	MSG_DONTROUTE	0x4		/* send without using routing tables */
/* Added for XPGv2 compliance */
#define	MSG_EOR		0x8		/* Terminates a record */
#define	MSG_CTRUNC	0x10		/* Control data truncated */
#define	MSG_TRUNC	0x20		/* Normal data truncated */
#define	MSG_WAITALL	0x40		/* Wait for complete recv or error */
#define	MSG_DUPCTRL	0x800		/* Save control message for use with */
					/* with left over data */
/* End of XPGv2 compliance */
#define	MSG_DONTWAIT	0x80		/* Don't block for this recv */
#define	MSG_NOTIFICATION 0x100		/* Notification, not data */
#define	MSG_XPG4_2	0x8000		/* Private: XPG4.2 flag */

#define	MSG_MAXIOVLEN	16

#ifdef _KERNEL

/*
 * Internal-only MSG_... flags
 */

#define	MSG_SENDTO_NOXLATE	0x08000000	/* Skip so_ux_addr_xlate */

#define	MSG_MBLK_QUICKRELE	0x10000000	/* free mblk chain */
						/* in timely manner */
#define	MSG_USERSPACE		0x20000000	/* buffer from user space */

#endif /* _KERNEL */


/* Added for XPGv2 compliance */
#define	SHUT_RD		0
#define	SHUT_WR		1
#define	SHUT_RDWR	2

struct cmsghdr {
	socklen_t	cmsg_len;	/* data byte count, including hdr */
	int		cmsg_level;	/* originating protocol */
	int		cmsg_type;	/* protocol-specific type */
};

#if defined(_XPG4_2) || defined(_KERNEL)
#if defined(__sparc)
/* To maintain backward compatibility, alignment needs to be 8 on sparc. */
#define	_CMSG_HDR_ALIGNMENT	8
#else
/* for __i386 (and other future architectures) */
#define	_CMSG_HDR_ALIGNMENT	4
#endif	/* defined(__sparc) */
#endif	/* defined(_XPG4_2) || defined(_KERNEL) */

#if defined(_XPG4_2)
/*
 * The cmsg headers (and macros dealing with them) were made available as
 * part of UNIX95 and hence need to be protected with a _XPG4_2 define.
 */
#define	_CMSG_DATA_ALIGNMENT	(sizeof (int))
#define	_CMSG_HDR_ALIGN(x)	(((uintptr_t)(x) + _CMSG_HDR_ALIGNMENT - 1) & \
				    ~(_CMSG_HDR_ALIGNMENT - 1))
#define	_CMSG_DATA_ALIGN(x)	(((uintptr_t)(x) + _CMSG_DATA_ALIGNMENT - 1) & \
				    ~(_CMSG_DATA_ALIGNMENT - 1))
#define	CMSG_DATA(c)							\
	((unsigned char *)_CMSG_DATA_ALIGN((struct cmsghdr *)(c) + 1))

#define	CMSG_FIRSTHDR(m)						\
	(((m)->msg_controllen < sizeof (struct cmsghdr)) ?		\
	    (struct cmsghdr *)0 : (struct cmsghdr *)((m)->msg_control))

#define	CMSG_NXTHDR(m, c)						\
	(((c) == 0) ? CMSG_FIRSTHDR(m) :			\
	((((uintptr_t)_CMSG_HDR_ALIGN((char *)(c) +			\
	((struct cmsghdr *)(c))->cmsg_len) + sizeof (struct cmsghdr)) >	\
	(((uintptr_t)((struct msghdr *)(m))->msg_control) +		\
	((uintptr_t)((struct msghdr *)(m))->msg_controllen))) ?		\
	((struct cmsghdr *)0) :						\
	((struct cmsghdr *)_CMSG_HDR_ALIGN((char *)(c) +		\
	    ((struct cmsghdr *)(c))->cmsg_len))))

/* Amount of space + padding needed for a message of length l */
#define	CMSG_SPACE(l)							\
	((unsigned int)_CMSG_HDR_ALIGN(sizeof (struct cmsghdr) + (l)))

/* Value to be used in cmsg_len, does not include trailing padding */
#define	CMSG_LEN(l)							\
	((unsigned int)_CMSG_DATA_ALIGN(sizeof (struct cmsghdr)) + (l))

#endif	/* _XPG4_2 */

#ifdef	_XPG4_2
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname bind __xnet_bind
#pragma redefine_extname connect __xnet_connect
#pragma redefine_extname recvmsg __xnet_recvmsg
#pragma redefine_extname sendmsg __xnet_sendmsg
#pragma redefine_extname sendto __xnet_sendto
#pragma redefine_extname socket __xnet_socket
#pragma redefine_extname socketpair __xnet_socketpair
#pragma redefine_extname getsockopt __xnet_getsockopt
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	bind	__xnet_bind
#define	connect	__xnet_connect
#define	recvmsg	__xnet_recvmsg
#define	sendmsg	__xnet_sendmsg
#define	sendto	__xnet_sendto
#define	socket	__xnet_socket
#define	socketpair	__xnet_socketpair
#define	getsockopt	__xnet_getsockopt
#endif	/* __PRAGMA_REDEFINE_EXTNAME */

#endif	/* _XPG4_2 */

#if defined(_XPG4_2) && !defined(_XPG5)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname listen __xnet_listen
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	listen	__xnet_listen
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif /* (_XPG4_2) && !defined(_XPG5) */

#if !defined(_KERNEL) || defined(_BOOT)
extern int accept(int, struct sockaddr *_RESTRICT_KYWD, Psocklen_t);
extern int accept4(int, struct sockaddr *_RESTRICT_KYWD, Psocklen_t, int);
extern int bind(int, const struct sockaddr *, socklen_t);
extern int connect(int, const struct sockaddr *, socklen_t);
extern int getpeername(int, struct sockaddr *_RESTRICT_KYWD, Psocklen_t);
extern int getsockname(int, struct sockaddr *_RESTRICT_KYWD, Psocklen_t);
extern int getsockopt(int, int, int, void *_RESTRICT_KYWD, Psocklen_t);
extern int listen(int, int);	/* XXX - fixme???  where do I go */
extern int socketpair(int, int, int, int *);
extern ssize_t recv(int, void *, size_t, int);
extern ssize_t recvfrom(int, void *_RESTRICT_KYWD, size_t, int,
	struct sockaddr *_RESTRICT_KYWD, Psocklen_t);
extern ssize_t recvmsg(int, struct msghdr *, int);
extern ssize_t send(int, const void *, size_t, int);
extern ssize_t sendmsg(int, const struct msghdr *, int);
extern ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *,
	socklen_t);
extern int setsockopt(int, int, int, const void *, socklen_t);
extern int shutdown(int, int);
extern int socket(int, int, int);

#if !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__)
extern int sockatmark(int);
#endif /* !defined(_XPG4_2) || defined(_XPG6) || defined(__EXTENSIONS__) */
#endif	/* !defined(_KERNEL) || defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOCKET_H */
