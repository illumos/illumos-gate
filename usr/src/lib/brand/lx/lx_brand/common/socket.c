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
 * Copyright 2014 Joyent, Inc. All rights reserved.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <alloca.h>
#include <ucred.h>
#include <limits.h>

#include <sys/param.h>
#include <sys/brand.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_socket.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>

/*
 * This string is used to prefix all abstract namespace Unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN 11

#define	LX_DEV_LOG			"/dev/log"
#define	LX_DEV_LOG_REDIRECT		"/var/run/.dev_log_redirect"
#define	LX_DEV_LOG_REDIRECT_LEN		18

typedef enum {
	lxa_none,
	lxa_abstract,
	lxa_devlog
} lx_addr_type_t;

#ifdef __i386

static int lx_socket32(ulong_t *);
static int lx_bind32(ulong_t *);
static int lx_connect32(ulong_t *);
static int lx_listen32(ulong_t *);
static int lx_accept32(ulong_t *);
static int lx_getsockname32(ulong_t *);
static int lx_getpeername32(ulong_t *);
static int lx_socketpair32(ulong_t *);
static int lx_send(ulong_t *);
static int lx_recv(ulong_t *);
static int lx_sendto32(ulong_t *);
static int lx_recvfrom32(ulong_t *);
static int lx_shutdown32(ulong_t *);
static int lx_setsockopt32(ulong_t *);
static int lx_getsockopt32(ulong_t *);
static int lx_sendmsg32(ulong_t *);
static int lx_recvmsg32(ulong_t *);
static int lx_accept4_32(ulong_t *);
static int lx_recvmmsg32(ulong_t *);
static int lx_sendmmsg32(ulong_t *);

typedef int (*sockfn_t)(ulong_t *);

static struct {
	sockfn_t s_fn;	/* Function implementing the subcommand */
	int s_nargs;	/* Number of arguments the function takes */
} sockfns[] = {
	lx_socket32, 3,
	lx_bind32, 3,
	lx_connect32, 3,
	lx_listen32, 2,
	lx_accept32, 3,
	lx_getsockname32, 3,
	lx_getpeername32, 3,
	lx_socketpair32, 4,
	lx_send, 4,
	lx_recv, 4,
	lx_sendto32, 6,
	lx_recvfrom32, 6,
	lx_shutdown32, 2,
	lx_setsockopt32, 5,
	lx_getsockopt32, 5,
	lx_sendmsg32, 3,
	lx_recvmsg32, 3,
	lx_accept4_32, 4,
	lx_recvmmsg32, 5,
	lx_sendmmsg32, 4
};
#endif /* __i386 */

/*
 * What follows are a series of tables we use to translate Linux constants
 * into equivalent Illumos constants and back again.  I wish this were
 * cleaner, more programmatic, and generally nicer.  Sadly, life is messy,
 * and Unix networking even more so.
 */
static const int ltos_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_CCITT, AF_IPX,
	AF_APPLETALK, AF_NOTSUPPORTED, AF_OSI, AF_NOTSUPPORTED,
	AF_X25, AF_INET6, AF_CCITT, AF_DECnet,
	AF_802, AF_POLICY, AF_KEY, AF_LX_NETLINK,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_SNA, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)

static const int ltos_socktype[LX_SOCK_PACKET + 1] = {
	SOCK_NOTSUPPORTED, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
	SOCK_RDM, SOCK_SEQPACKET, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED,
	SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED, SOCK_NOTSUPPORTED
};

#define	LTOS_SOCKTYPE(t)	\
	((t) <= LX_SOCK_PACKET ? ltos_socktype[(t)] : SOCK_INVAL)

static const int stol_socktype[SOCK_SEQPACKET + 1] = {
	SOCK_NOTSUPPORTED, LX_SOCK_DGRAM, LX_SOCK_STREAM, SOCK_NOTSUPPORTED,
	LX_SOCK_RAW, LX_SOCK_RDM, LX_SOCK_SEQPACKET
};

/*
 * Linux socket option type definitions
 *
 * The protocol `levels` are well defined (see in.h) The option values are
 * not so well defined. Linux often uses different values vs. Illumos
 * although they mean the same thing. For example, IP_TOS in Linux is
 * defined as value 1 but in Illumos it is defined as value 3. This table
 * maps all the Protocol levels to their options and maps them between
 * Linux and Illumos and vice versa.  Hence the reason for the complexity.
 */

typedef struct lx_proto_opts {
	const int *proto;	/* Linux to Illumos mapping table */
	int maxentries;		/* max entries in this table */
} lx_proto_opts_t;

#define	OPTNOTSUP	-1	/* we don't support it */

/*
 * Linux					Illumos
 * -----					-------
 * IP_TOS                     1			IP_TOS      3
 * IP_TTL                     2			IP_TTL      4
 * IP_HDRINCL                 3			IP_HDRINCL  2
 * IP_OPTIONS                 4			IP_OPTIONS  1
 * IP_ROUTER_ALERT            5
 * IP_RECVOPTS                6			IP_RECVOPTS 5
 * IP_RETOPTS                 7			IP_RETOPTS  8
 * IP_PKTINFO                 8
 * IP_PKTOPTIONS              9
 * IP_MTU_DISCOVER            10		emulated for traceroute
 * IP_RECVERR                 11		emulated for traceroute
 * IP_RECVTTL                 12		IP_RECVTTL  11
 * IP_RECVTOS                 13
 * IP_MTU                     14
 * IP_FREEBIND                15
 * IP_IPSEC_POLICY            16
 * IP_XFRM_POLICY             17
 * IP_PASSSEC                 18
 * IP_TRANSPARENT             19
 * IP_ORIGDSTADDR             20
 * IP_MINTTL                  21
 * IP_NODEFRAG                22
 *
 *    apparent gap
 *
 * IP_MULTICAST_IF            32		IP_MULTICAST_IF    16
 * IP_MULTICAST_TTL           33		IP_MULTICAST_TTL   17
 * IP_MULTICAST_LOOP          34		IP_MULTICAST_LOOP  18
 * IP_ADD_MEMBERSHIP          35		IP_ADD_MEMBERSHIP  19
 * IP_DROP_MEMBERSHIP         36		IP_DROP_MEMBERSHIP 20
 * IP_UNBLOCK_SOURCE          37		IP_UNBLOCK_SOURCE  22
 * IP_BLOCK_SOURCE            38		IP_BLOCK_SOURCE    21
 * IP_ADD_SOURCE_MEMBERSHIP   39		IP_ADD_SOURCE_MEMBERSHIP 23
 * IP_DROP_SOURCE_MEMBERSHIP  40		IP_DROP_SOURCE_MEMBERSHIP 24
 * IP_MSFILTER                41
 * MCAST_JOIN_GROUP           42		-> MCAST_JOIN_GROUP
 * MCAST_BLOCK_SOURCE         43		-> MCAST_BLOCK_SOURCE
 * MCAST_UNBLOCK_SOURCE       44		-> MCAST_UNBLOCK_SOURCE
 * MCAST_LEAVE_GROUP          45		-> MCAST_LEAVE_GROUP
 * MCAST_JOIN_SOURCE_GROUP    46		-> MCAST_JOIN_SOURCE_GROUP
 * MCAST_LEAVE_SOURCE_GROUP   47		-> MCAST_LEAVE_SOURCE_GROUP
 * MCAST_MSFILTER             48
 * IP_MULTICAST_ALL           49
 * IP_UNICAST_IF              50
 *
 * The Illumos options preceeded by '->' can be added but we might also need
 * emulation to convert the ip_mreq_source struct.
 */
static const int ltos_ip_sockopts[LX_IP_UNICAST_IF + 1] = {
	OPTNOTSUP, IP_TOS, IP_TTL, IP_HDRINCL,			/* 3 */
	IP_OPTIONS, OPTNOTSUP, IP_RECVOPTS, IP_RETOPTS,		/* 7 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 11 */
	IP_RECVTTL, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 15 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 19 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 23 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 27 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 31 */
	IP_MULTICAST_IF, IP_MULTICAST_TTL,			/* 33 */
	IP_MULTICAST_LOOP, IP_ADD_MEMBERSHIP,			/* 35 */
	IP_DROP_MEMBERSHIP, IP_UNBLOCK_SOURCE,			/* 37 */
	IP_BLOCK_SOURCE, IP_ADD_SOURCE_MEMBERSHIP,		/* 39 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 43 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 47 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP				/* 50 */
};

/*
 *
 * TCP socket option mapping:
 *
 * Linux					Illumos
 * -----					-------
 * TCP_NODELAY                1                 TCP_NODELAY      1
 * TCP_MAXSEG                 2                 TCP_MAXSEG       2
 * TCP_CORK                   3                 TCP_CORK         24
 * TCP_KEEPIDLE               4                 TCP_KEEPIDLE     34
 * TCP_KEEPINTVL              5                 TCP_KEEPINTVL    36
 * TCP_KEEPCNT                6                 TCP_KEEPCNT      35
 * TCP_SYNCNT                 7
 * TCP_LINGER2                8                 TCP_LINGER2      28
 * TCP_DEFER_ACCEPT           9
 * TCP_WINDOW_CLAMP           10
 * TCP_INFO                   11
 * TCP_QUICKACK               12
 * TCP_CONGESTION             13
 * TCP_MD5SIG                 14
 * TCP_THIN_LINEAR_TIMEOUTS   16
 * TCP_THIN_DUPACK            17
 * TCP_USER_TIMEOUT           18
 * TCP_REPAIR                 19
 * TCP_REPAIR_QUEUE           20
 * TCP_QUEUE_SEQ              21
 * TCP_REPAIR_OPTIONS         22
 * TCP_FASTOPEN               23
 * TCP_TIMESTAMP              24
 * TCP_NOTSENT_LOWAT          25
 */

static const int ltos_tcp_sockopts[LX_TCP_NOTSENT_LOWAT + 1] = {
	OPTNOTSUP, TCP_NODELAY, TCP_MAXSEG, TCP_CORK,		/* 0-3 */
	TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, OPTNOTSUP,	/* 4-7 */
	TCP_LINGER2, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 8-11 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 12-15 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 16-19 */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,		/* 20-23 */
	OPTNOTSUP, OPTNOTSUP					/* 24-25 */
};

static const int ltos_igmp_sockopts[IGMP_MTRACE + 1] = {
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IGMP_MINLEN, OPTNOTSUP, OPTNOTSUP, /* XXX: was IGMP_TIMER_SCALE */
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, IGMP_MEMBERSHIP_QUERY,
	IGMP_V1_MEMBERSHIP_REPORT, IGMP_DVMRP,
	IGMP_PIM, OPTNOTSUP, IGMP_V2_MEMBERSHIP_REPORT,
	IGMP_V2_LEAVE_GROUP, OPTNOTSUP, OPTNOTSUP,
	OPTNOTSUP, OPTNOTSUP, OPTNOTSUP, OPTNOTSUP,
	IGMP_MTRACE_RESP, IGMP_MTRACE
};

/*
 * Socket option mapping:
 *
 * Linux				Illumos
 * -----				-------
 * SO_DEBUG               1		SO_DEBUG       0x0001
 * SO_REUSEADDR           2		SO_REUSEADDR   0x0004
 * SO_TYPE                3		SO_TYPE        0x1008
 * SO_ERROR               4		SO_ERROR       0x1007
 * SO_DONTROUTE           5		SO_DONTROUTE   0x0010
 * SO_BROADCAST           6		SO_BROADCAST   0x0020
 * SO_SNDBUF              7		SO_SNDBUF      0x1001
 * SO_RCVBUF              8		SO_RCVBUF      0x1002
 * SO_KEEPALIVE           9		SO_KEEPALIVE   0x0008
 * SO_OOBINLINE          10		SO_OOBINLINE   0x0100
 * SO_NO_CHECK           11
 * SO_PRIORITY           12
 * SO_LINGER             13		SO_LINGER      0x0080
 * SO_BSDCOMPAT          14		ignored by linux, emulation returns 0
 * SO_REUSEPORT          15
 * SO_PASSCRED           16		SO_RECVUCRED   0x0400
 * SO_PEERCRED           17		emulated with getpeerucred
 * SO_RCVLOWAT           18		SO_RCVLOWAT    0x1004
 * SO_SNDLOWAT           19		SO_SNDLOWAT    0x1003
 * SO_RCVTIMEO           20		SO_RCVTIMEO    0x1006
 * SO_SNDTIMEO           21		SO_SNDTIMEO    0x1005
 * SO_SECURITY_AUTHENTICATION       22
 * SO_SECURITY_ENCRYPTION_TRANSPORT 23
 * SO_SECURITY_ENCRYPTION_NETWORK   24
 * SO_BINDTODEVICE       25
 * SO_ATTACH_FILTER      26		SO_ATTACH_FILTER 0x40000001
 * SO_DETACH_FILTER      27		SO_DETACH_FILTER 0x40000002
 * SO_PEERNAME           28
 * SO_TIMESTAMP          29		SO_TIMESTAMP    0x1013
 * SO_ACCEPTCONN         30		SO_ACCEPTCONN   0x0002
 * SO_PEERSEC            31
 * SO_SNDBUFFORCE        32
 * SO_RCVBUFFORCE        33
 * SO_PASSSEC            34
 * SO_TIMESTAMPNS        35
 * SO_MARK               36
 * SO_TIMESTAMPING       37
 * SO_PROTOCOL           38		SO_PROTOTYPE    0x1009
 * SO_DOMAIN             39		SO_DOMAIN       0x100c
 * SO_RXQ_OVFL           40
 * SO_WIFI_STATUS        41
 * SO_PEEK_OFF           42
 * SO_NOFCS              43
 * SO_LOCK_FILTER        44
 * SO_SELECT_ERR_QUEUE   45
 * SO_BUSY_POLL          46
 * SO_MAX_PACING_RATE    47
 * SO_BPF_EXTENSIONS     48
 */
static const int ltos_socket_sockopts[LX_SO_BPF_EXTENSIONS + 1] = {
	OPTNOTSUP,	SO_DEBUG,	SO_REUSEADDR,	SO_TYPE,	/* 3 */
	SO_ERROR,	SO_DONTROUTE,	SO_BROADCAST,	SO_SNDBUF,	/* 7 */
	SO_RCVBUF,	SO_KEEPALIVE,	SO_OOBINLINE,	OPTNOTSUP,	/* 11 */
	OPTNOTSUP,	SO_LINGER,	OPTNOTSUP,	OPTNOTSUP,	/* 15 */
	SO_RECVUCRED,	OPTNOTSUP,	SO_RCVLOWAT,	SO_SNDLOWAT,	/* 19 */
	SO_RCVTIMEO,	SO_SNDTIMEO,	OPTNOTSUP,	OPTNOTSUP,	/* 23 */
	OPTNOTSUP,	OPTNOTSUP, SO_ATTACH_FILTER, SO_DETACH_FILTER,	/* 27 */
	OPTNOTSUP,	SO_TIMESTAMP,	SO_ACCEPTCONN,	OPTNOTSUP,	/* 31 */
	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	/* 35 */
	OPTNOTSUP,	OPTNOTSUP,	SO_PROTOTYPE,	SO_DOMAIN,	/* 39 */
	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	/* 43 */
	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	OPTNOTSUP,	/* 47 */
	OPTNOTSUP							/* 48 */
};

/*
 * See the Linux raw.7 man page for description of the socket options.
 *    In Linux ICMP_FILTER is defined as 1 in include/uapi/linux/icmp.h
 */
static const int ltos_raw_sockopts[LX_ICMP_FILTER + 1] = {
	OPTNOTSUP, OPTNOTSUP
};

#define	PROTO_SOCKOPTS(opts)    \
	{ (opts), sizeof ((opts)) / sizeof ((opts)[0]) }

/*
 * [gs]etsockopt options mapping tables
 */
static lx_proto_opts_t ip_sockopts_tbl = PROTO_SOCKOPTS(ltos_ip_sockopts);
static lx_proto_opts_t socket_sockopts_tbl =
    PROTO_SOCKOPTS(ltos_socket_sockopts);
static lx_proto_opts_t igmp_sockopts_tbl = PROTO_SOCKOPTS(ltos_igmp_sockopts);
static lx_proto_opts_t tcp_sockopts_tbl = PROTO_SOCKOPTS(ltos_tcp_sockopts);
static lx_proto_opts_t raw_sockopts_tbl = PROTO_SOCKOPTS(ltos_raw_sockopts);

/*
 * Lifted from socket.h, since these definitions are contained within
 * _KERNEL guards.
 */
#define	_CMSG_HDR_ALIGNMENT	4
#define	_CMSG_HDR_ALIGN(x)	(((uintptr_t)(x) + _CMSG_HDR_ALIGNMENT - 1) & \
				    ~(_CMSG_HDR_ALIGNMENT - 1))
#define	_CMSG_DATA_ALIGN(x)						\
	(((uintptr_t)(x) + sizeof (int) - 1) & ~(sizeof (int) - 1))

#define	CMSG_FIRSTHDR(m)						\
	(((m)->msg_controllen < sizeof (struct cmsghdr)) ?		\
	    (struct cmsghdr *)0 : (struct cmsghdr *)((m)->msg_control))

#define	CMSG_NXTHDR(m, c)						\
	(((c) == 0) ? CMSG_FIRSTHDR(m) :			\
	((((uintptr_t)_CMSG_HDR_ALIGN((char *)(c) +			\
	((struct cmsghdr *)(c))->cmsg_len) + sizeof (struct cmsghdr)) >	\
	(((uintptr_t)((struct lx_msghdr *)(m))->msg_control) +		\
	((uintptr_t)((struct lx_msghdr *)(m))->msg_controllen))) ?	\
	((struct cmsghdr *)0) :						\
	((struct cmsghdr *)_CMSG_HDR_ALIGN((char *)(c) +		\
	    ((struct cmsghdr *)(c))->cmsg_len))))

#define	CMSG_LEN(l)							\
	((unsigned int)_CMSG_DATA_ALIGN(sizeof (struct cmsghdr)) + (l))

#define	CMSG_DATA(c)							\
	((unsigned char *)_CMSG_DATA_ALIGN((struct cmsghdr *)(c) + 1))

#define	LX_TO_SOL	1
#define	SOL_TO_LX	2

#define	LX_AF_NETLINK			16
#define	LX_NETLINK_KOBJECT_UEVENT	15
#define	LX_NETLINK_ROUTE		0

typedef struct {
	sa_family_t	nl_family;
	unsigned short	nl_pad;
	uint32_t	nl_pid;
	uint32_t	nl_groups;
} lx_sockaddr_nl_t;

#if defined(_LP64)
/*
 * For 32-bit code the Illumos and Linux cmsghdr structure definition is the
 * same, but for 64-bit Linux code the cmsg_len value is a long instead of an
 * int. As a result, we need to go through a bunch of work to transform the
 * csmgs back and forth.
 */
typedef struct {
	long	cmsg_len;
	int	cmsg_level;
	int	cmsg_type;
} lx_cmsghdr64_t;

/*
 * When converting from Illumos to Linux we don't know in advance how many
 * control msgs we recv, but we do know that the Linux header is 4 bytes
 * bigger, plus any additional alignment bytes. We'll take a guess and assume
 * there is not 64 msgs (1 is common) and alloc an extra 256 bytes.
 */
#define	LX_CMSG_EXTRA	256

#define	LX_CMSG_HDR_ALIGN(x)						\
	(((uintptr_t)(x) + sizeof (long) - 1) & ~(sizeof (long) - 1))

#define	LX_CMSG_DATA_ALIGN(x)						\
	(((uintptr_t)(x) + sizeof (int) - 1) & ~(sizeof (int)  - 1))

#define	LX_CMSG_DATA(c)							\
	((unsigned char *)LX_CMSG_DATA_ALIGN((lx_cmsghdr64_t *)(c) + 1))

#define	LX_CMSG_FIRSTHDR(m) 						\
	(((m)->msg_controllen < sizeof (lx_cmsghdr64_t)) ?		\
	(lx_cmsghdr64_t *)NULL : (lx_cmsghdr64_t *)((m)->msg_control))

#define	LX_CMSG_LEN(l) (LX_CMSG_HDR_ALIGN(sizeof (lx_cmsghdr64_t)) + (l))

#define	LX_CMSG_NXTHDR(m, c)						\
	(((c) == 0) ? LX_CMSG_FIRSTHDR(m) :				\
	((((uintptr_t)LX_CMSG_HDR_ALIGN((char *)(c) +			\
	((lx_cmsghdr64_t *)(c))->cmsg_len) + sizeof (lx_cmsghdr64_t)) >	\
	(((uintptr_t)((struct lx_msghdr *)(m))->msg_control) +		\
	((uintptr_t)((struct lx_msghdr *)(m))->msg_controllen))) ?	\
	((lx_cmsghdr64_t *)0) :						\
	((lx_cmsghdr64_t *)LX_CMSG_HDR_ALIGN((char *)(c) +		\
	((lx_cmsghdr64_t *)(c))->cmsg_len))))


static void
ltos_xform_cmsgs(struct lx_msghdr *msg, struct cmsghdr *ntv_cmsg)
{
	lx_cmsghdr64_t *lcmsg, *last;
	struct cmsghdr *cmsg, *lp;
	int nlen = 0;

	cmsg = ntv_cmsg;
	lcmsg = LX_CMSG_FIRSTHDR(msg);
	while (lcmsg != NULL) {
		cmsg->cmsg_len =
		    CMSG_LEN(lcmsg->cmsg_len - sizeof (lx_cmsghdr64_t));
		cmsg->cmsg_level = lcmsg->cmsg_level;
		cmsg->cmsg_type = lcmsg->cmsg_type;

		bcopy((void *)LX_CMSG_DATA(lcmsg), (void *)CMSG_DATA(cmsg),
		    lcmsg->cmsg_len - sizeof (lx_cmsghdr64_t));

		last = lcmsg;
		lcmsg = LX_CMSG_NXTHDR(msg, last);

		lp = cmsg;
		cmsg = CMSG_NXTHDR(msg, lp);

		nlen += (int)((uint64_t)cmsg - (uint64_t)lp);
	}

	msg->msg_control = ntv_cmsg;
	msg->msg_controllen = nlen;
}

static int
stol_xform_cmsgs(struct lx_msghdr *msg, lx_cmsghdr64_t *lx_cmsg)
{
	lx_cmsghdr64_t *lcmsg, *last;
	struct cmsghdr *cmsg, *lp;
	int nlen = 0;
	int err = 0;

	lcmsg = lx_cmsg;
	cmsg = CMSG_FIRSTHDR(msg);
	while (cmsg != NULL && err == 0) {
		lcmsg->cmsg_len =
		    LX_CMSG_LEN(cmsg->cmsg_len - sizeof (struct cmsghdr));
		lcmsg->cmsg_level = cmsg->cmsg_level;
		lcmsg->cmsg_type = cmsg->cmsg_type;

		bcopy((void *)CMSG_DATA(cmsg), (void *)LX_CMSG_DATA(lcmsg),
		    cmsg->cmsg_len - sizeof (struct cmsghdr));

		lp = cmsg;
		cmsg = CMSG_NXTHDR(msg, lp);

		last = lcmsg;
		lcmsg = LX_CMSG_NXTHDR(msg, last);

		nlen += (int)((uint64_t)lcmsg - (uint64_t)last);

		if (nlen > (msg->msg_controllen + LX_CMSG_EXTRA))
			err = ENOTSUP;
	}

	if (err) {
		lx_unsupported("stol_xform_cmsgs exceeded the allocation "
		    "%d %d\n", nlen, (msg->msg_controllen + LX_CMSG_EXTRA));
	} else {
		msg->msg_control = lx_cmsg;
		msg->msg_controllen = nlen;
	}
	return (err);
}
#endif

static int
convert_cmsgs(int direction, struct lx_msghdr *msg, void *new_cmsg,
    char *caller)
{
	struct cmsghdr *cmsg, *last;
	int err = 0;
	int level = 0;
	int type = 0;

#if defined(_LP64)
	if (direction == LX_TO_SOL) {
		ltos_xform_cmsgs(msg, (struct cmsghdr *)new_cmsg);
	}
#endif

	cmsg = CMSG_FIRSTHDR(msg);
	while (cmsg != NULL && err == 0) {
		level = cmsg->cmsg_level;
		type = cmsg->cmsg_type;

		if (direction == LX_TO_SOL) {
			if (cmsg->cmsg_level == LX_SOL_SOCKET) {
				cmsg->cmsg_level = SOL_SOCKET;
				if (cmsg->cmsg_type == LX_SCM_RIGHTS)
					cmsg->cmsg_type = SCM_RIGHTS;
				else if (cmsg->cmsg_type == LX_SCM_CRED)
					cmsg->cmsg_type = SCM_UCRED;
				else if (cmsg->cmsg_type == LX_SCM_TIMESTAMP)
					cmsg->cmsg_type = SCM_TIMESTAMP;
				else
					err = ENOTSUP;
			} else {
				err = ENOTSUP;
			}
		} else {
			if (cmsg->cmsg_level == SOL_SOCKET) {
				cmsg->cmsg_level = LX_SOL_SOCKET;
				if (cmsg->cmsg_type == SCM_RIGHTS)
					cmsg->cmsg_type = LX_SCM_RIGHTS;
				else if (cmsg->cmsg_type == SCM_UCRED)
					cmsg->cmsg_type = LX_SCM_CRED;
				else if (cmsg->cmsg_type == SCM_TIMESTAMP)
					cmsg->cmsg_type = LX_SCM_TIMESTAMP;
				else
					err = ENOTSUP;
			} else {
				err = ENOTSUP;
			}
		}

		last = cmsg;
		cmsg = CMSG_NXTHDR(msg, last);
	}
	if (err)
		lx_unsupported("Unsupported socket control message %d "
		    "(%d) in %s\n.", type, level, caller);

#if defined(_LP64)
	if (direction == SOL_TO_LX && err == 0) {
		err = stol_xform_cmsgs(msg, (lx_cmsghdr64_t *)new_cmsg);
	}
#endif

	return (err);
}

/*
 * We may need a different size socket address vs. the one passed in.
 */
static int
calc_addr_size(struct sockaddr *a, int nlen, lx_addr_type_t *type)
{
	struct sockaddr name;
	size_t fsize = sizeof (name.sa_family);

	if (uucopy(a, &name, sizeof (struct sockaddr)) != 0)
		return (-errno);

	if (name.sa_family != AF_UNIX) {
		*type = lxa_none;
		return (nlen);
	}

	/*
	 * Handle Linux abstract sockets, which are Unix sockets whose path
	 * begins with a NULL character.
	 */
	if (name.sa_data[0] == '\0') {
		*type = lxa_abstract;
		return (nlen + ABST_PRFX_LEN);
	}

	/*
	 * For /dev/log, we need to create the Unix domain socket away from
	 * the (unwritable) /dev.
	 */
	if (strncmp(name.sa_data, LX_DEV_LOG, nlen - fsize) == 0) {
		*type = lxa_devlog;
		return (nlen + LX_DEV_LOG_REDIRECT_LEN);
	}

	*type = lxa_none;
	return (nlen);
}

/*
 * If inaddr is an abstract namespace Unix socket, this function expects addr
 * to have enough memory to hold the expanded socket name, ie it must be of
 * size *len + ABST_PRFX_LEN. If inaddr is a netlink socket then we expect
 * addr to have enough memory to hold an Unix socket address.
 */
static int
convert_sockaddr(struct sockaddr *addr, socklen_t *len,
	struct sockaddr *inaddr, socklen_t inlen, lx_addr_type_t type)
{
	sa_family_t family;
	int lx_in6_len;
	int size;
	int i, orig_len;

	/*
	 * Note that if the buffer at inaddr is ever smaller than inlen bytes,
	 * we may erroneously return EFAULT rather than a possible EINVAL
	 * as the copy comes before the various checks as to whether inlen
	 * is of the proper length for the socket type.
	 *
	 * This isn't an issue at present because all callers to this routine
	 * do meet that constraint.
	 */
	if ((int)inlen < 0)
		return (-EINVAL);
	if (uucopy(inaddr, addr, inlen) != 0)
		return (-errno);

	family = LTOS_FAMILY(addr->sa_family);

	switch (family) {
		case (sa_family_t)AF_NOTSUPPORTED:
			return (-EPROTONOSUPPORT);
		case (sa_family_t)AF_INVAL:
			return (-EAFNOSUPPORT);
		case AF_INET:
			size = sizeof (struct sockaddr);

			if (inlen < size)
				return (-EINVAL);

			*len = size;
			break;

		case AF_INET6:
			/*
			 * The Solaris sockaddr_in6 has one more 32-bit
			 * field than the Linux version.
			 */
			size = sizeof (struct sockaddr_in6);
			lx_in6_len = size - sizeof (uint32_t);

			if (inlen != lx_in6_len)
				return (-EINVAL);

			*len = (sizeof (struct sockaddr_in6));
			bzero((char *)addr + lx_in6_len, sizeof	(uint32_t));
			break;

		case AF_UNIX:
			if (inlen > sizeof (struct sockaddr_un))
				return (-EINVAL);

			*len = inlen;

			/*
			 * In order to support /dev/log -- a Unix domain socket
			 * used for logging that has had its path hard-coded
			 * far and wide -- we need to relocate the socket
			 * into a writable filesystem.  This also necessitates
			 * some cleanup in bind(); see lx_bind() for details.
			 */
			if (type == lxa_devlog) {
				*len = inlen + LX_DEV_LOG_REDIRECT_LEN;
				strcpy(addr->sa_data, LX_DEV_LOG_REDIRECT);
				break;
			}

			/*
			 * Linux supports abstract Unix sockets, which are
			 * simply sockets that do not exist on the file system.
			 * These sockets are denoted by beginning the path with
			 * a NULL character. To support these, we strip out the
			 * leading NULL character and change the path to point
			 * to a real place in /tmp directory, by prepending
			 * ABST_PRFX and replacing all illegal characters with
			 * '_'.
			 */
			if (type == lxa_abstract) {
				/*
				 * inlen is the entire size of the sockaddr_un
				 * data structure, including the sun_family, so
				 * we need to subtract this out. We subtract
				 * 1 since we want to overwrite the leadin NULL
				 * character, and thus do not include it in the
				 * length.
				 */
				orig_len = inlen - sizeof (addr->sa_family) - 1;

				/*
				 * Since abstract paths can contain illegal
				 * filename characters, we simply replace these
				 * with '_'
				 */
				for (i = 1; i < orig_len + 1; i++) {
					if (addr->sa_data[i] == '\0' ||
					    addr->sa_data[i] == '/')
						addr->sa_data[i] = '_';
				}

				/*
				 * prepend ABST_PRFX to file name, minus the
				 * leading NULL character. This places the
				 * socket as a hidden file in the /tmp
				 * directory.
				 */
				(void) memmove(addr->sa_data + ABST_PRFX_LEN,
				    addr->sa_data + 1, orig_len);
				bcopy(ABST_PRFX, addr->sa_data, ABST_PRFX_LEN);

				/*
				 * Since abstract socket paths may not be NULL
				 * terminated, we must explicitly NULL terminate
				 * our string.
				 */
				addr->sa_data[orig_len + ABST_PRFX_LEN] = '\0';

				/*
				 * Make len reflect the new len of our string.
				 * Although we removed the NULL character at the
				 * beginning of the string, we added a NULL
				 * character to the end, so the net gain in
				 * length is simply ABST_PRFX_LEN.
				 */
				*len = inlen + ABST_PRFX_LEN;
			}
			break;

		default:
			*len = inlen;
	}

	addr->sa_family = family;
	return (0);
}

static int
convert_sock_args(int in_dom, int in_type, int in_protocol, int *out_dom,
    int *out_type, int *out_options)
{
	int domain, type, options;

	if (in_dom < 0 || in_type < 0 || in_protocol < 0)
		return (-EINVAL);

	domain = LTOS_FAMILY(in_dom);
	if (domain == AF_NOTSUPPORTED || domain == AF_UNSPEC)
		return (-EAFNOSUPPORT);
	if (domain == AF_INVAL)
		return (-EINVAL);

	type = LTOS_SOCKTYPE(in_type & LX_SOCK_TYPE_MASK);
	if (type == SOCK_NOTSUPPORTED)
		return (-ESOCKTNOSUPPORT);
	if (type == SOCK_INVAL)
		return (-EINVAL);

	/*
	 * Linux does not allow the app to specify IP Protocol for raw
	 * sockets.  Solaris does, so bail out here.
	 */
	if (domain == AF_INET && type == SOCK_RAW && in_protocol == IPPROTO_IP)
		return (-ESOCKTNOSUPPORT);

	options = 0;
	if (in_type & LX_SOCK_NONBLOCK)
		options |= SOCK_NONBLOCK;
	if (in_type & LX_SOCK_CLOEXEC)
		options |= SOCK_CLOEXEC;

	*out_dom = domain;
	*out_type = type;
	*out_options = options;
	return (0);
}

static int
convert_sockflags(int lx_flags, char *call)
{
	int solaris_flags = 0;

	if (lx_flags & LX_MSG_OOB) {
		solaris_flags |= MSG_OOB;
		lx_flags &= ~LX_MSG_OOB;
	}

	if (lx_flags & LX_MSG_PEEK) {
		solaris_flags |= MSG_PEEK;
		lx_flags &= ~LX_MSG_PEEK;
	}

	if (lx_flags & LX_MSG_DONTROUTE) {
		solaris_flags |= MSG_DONTROUTE;
		lx_flags &= ~LX_MSG_DONTROUTE;
	}

	if (lx_flags & LX_MSG_CTRUNC) {
		solaris_flags |= MSG_CTRUNC;
		lx_flags &= ~LX_MSG_CTRUNC;
	}

	if (lx_flags & LX_MSG_PROXY) {
		lx_unsupported("%s: unsupported socket flag MSG_PROXY", call);
		lx_flags &= ~LX_MSG_PROXY;
	}

	if (lx_flags & LX_MSG_TRUNC) {
		solaris_flags |= MSG_TRUNC;
		lx_flags &= ~LX_MSG_TRUNC;
	}

	if (lx_flags & LX_MSG_DONTWAIT) {
		solaris_flags |= MSG_DONTWAIT;
		lx_flags &= ~LX_MSG_DONTWAIT;
	}

	if (lx_flags & LX_MSG_EOR) {
		solaris_flags |= MSG_EOR;
		lx_flags &= ~LX_MSG_EOR;
	}

	if (lx_flags & LX_MSG_WAITALL) {
		solaris_flags |= MSG_WAITALL;
		lx_flags &= ~LX_MSG_WAITALL;
	}

	if (lx_flags & LX_MSG_FIN) {
		lx_unsupported("%s: unsupported socket flag MSG_FIN", call);
		lx_flags &= ~LX_MSG_FIN;
	}

	if (lx_flags & LX_MSG_SYN) {
		lx_unsupported("%s: unsupported socket flag MSG_SYN", call);
		lx_flags &= ~LX_MSG_SYN;
	}

	if (lx_flags & LX_MSG_CONFIRM) {
		/*
		 * See the Linux arp.7 and sendmsg.2 man pages. We can ignore
		 * this option.
		 */
		lx_flags &= ~LX_MSG_CONFIRM;
	}

	if (lx_flags & LX_MSG_RST) {
		lx_unsupported("%s: unsupported socket flag MSG_RST", call);
		lx_flags &= ~LX_MSG_RST;
	}

	if (lx_flags & LX_MSG_ERRQUEUE) {
		lx_unsupported("%s: unsupported socket flag MSG_ERRQUEUE",
		    call);
		lx_flags &= ~LX_MSG_ERRQUEUE;
	}

	if (lx_flags & LX_MSG_NOSIGNAL) {
		/* MSG_NOSIGNAL handled within each caller */
		lx_flags &= ~LX_MSG_NOSIGNAL;
	}

	if (lx_flags & LX_MSG_MORE) {
		lx_unsupported("%s: unsupported socket flag MSG_MORE", call);
		lx_flags &= ~LX_MSG_MORE;
	}

	if (lx_flags & LX_MSG_WAITFORONE) {
		lx_unsupported("%s: unsupported socket flag MSG_WAITFORONE",
		    call);
		lx_flags &= ~LX_MSG_WAITFORONE;
	}

	if (lx_flags & LX_MSG_FASTOPEN) {
		lx_unsupported("%s: unsupported socket flag MSG_FASTOPEN",
		    call);
		lx_flags &= ~LX_MSG_FASTOPEN;
	}

	if (lx_flags & LX_MSG_CMSG_CLOEXEC) {
		lx_unsupported("%s: unsupported socket flag MSG_CMSG_CLOEXEC",
		    call);
		lx_flags &= ~LX_MSG_CMSG_CLOEXEC;
	}

	if (lx_flags != 0)
		lx_unsupported("%s: unknown socket flag(s) 0x%x", call,
		    lx_flags);

	return (solaris_flags);
}

long
lx_socket(int domain, int type, int protocol)
{
	int options;
	int fd;
	int err;

	err = convert_sock_args(domain, type, protocol,
	    &domain, &type, &options);
	if (err != 0)
		return (err);

	lx_debug("\tsocket(%d, %d, %d)", domain, type, protocol);

	fd = socket(domain, type | options, protocol);

	if (fd >= 0)
		return (fd);

	if (errno == EPROTONOSUPPORT)
		return (-ESOCKTNOSUPPORT);

	return (-errno);
}

long
lx_bind(int sockfd, void *np, int nl)
{
	struct stat64 statbuf;
	struct sockaddr *name;
	socklen_t len;
	int r, r2, ret, tmperrno;
	int nlen;
	lx_addr_type_t type;
	struct stat sb;

	if ((nlen = calc_addr_size(np, nl, &type)) < 0)
		return (nlen);

	if ((name = SAFE_ALLOCA(nlen)) == NULL)
		return (-EINVAL);

	if ((r = convert_sockaddr(name, &len, np, nl, type)) < 0)
		return (r);

	/*
	 * There are two types of Unix domain sockets for which we need to
	 * do some special handling with respect to bind:  abstract namespace
	 * sockets and /dev/log.  Abstract namespace sockets are simply Unix
	 * domain sockets that do not exist on the filesystem; we emulate them
	 * by changing their paths in convert_sockaddr() to point to real
	 * file names in the  filesystem.  /dev/log is a special Unix domain
	 * socket that is used for system logging.  On us, /dev isn't writable,
	 * so we rewrite these sockets in convert_sockaddr() to point to a
	 * writable file (defined by LX_DEV_LOG_REDIRECT).  In both cases, we
	 * introduce a new problem with respect to cleanup:  abstract namespace
	 * sockets don't need to be cleaned up (when they are closed they are
	 * removed) and /dev/log can't be cleaned up because it's in the
	 * non-writable /dev.  We solve these problems by cleaning up here in
	 * lx_bind():  before we create the socket, we check to see if it
	 * exists.  If it does, we attempt to connect to it to see if it is in
	 * use, or just left over from a previous lx_bind() call. If we are
	 * unable to connect, we assume it is not in use and remove the file,
	 * then continue on as if the file never existed.
	 */
	if ((type == lxa_abstract || type == lxa_devlog) &&
	    stat(name->sa_data, &sb) == 0 && S_ISSOCK(sb.st_mode)) {
		if ((r2 = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
			return (-ENOSR);
		ret = connect(r2, name, len);
		tmperrno = errno;
		if (close(r2) < 0)
			return (-EINVAL);

		/*
		 * if we can't connect to the socket, assume no one is using it
		 * and remove it, otherwise assume it is in use and return
		 * EADDRINUSE.
		 */
		if ((ret < 0) && (tmperrno == ECONNREFUSED)) {
			if (unlink(name->sa_data) < 0) {
				return (-EADDRINUSE);
			}
		} else {
			return (-EADDRINUSE);
		}
	}

	lx_debug("\tbind(%d, 0x%p, %d)", sockfd, name, len);

	if (name->sa_family == AF_UNIX)
		lx_debug("\t\tAF_UNIX, path = %s", name->sa_data);

	r = bind(sockfd, name, len);

	/*
	 * Linux returns EADDRINUSE for attempts to bind to Unix domain
	 * sockets that aren't sockets.
	 */
	if ((r < 0) && (errno == EINVAL) && (name->sa_family == AF_UNIX) &&
	    ((stat64(name->sa_data, &statbuf) == 0) &&
	    (!S_ISSOCK(statbuf.st_mode))))
		return (-EADDRINUSE);

	return ((r < 0) ? -errno : r);
}

long
lx_connect(int sockfd, void *np, int nl)
{
	struct sockaddr *name;
	socklen_t len;
	int r;
	int nlen;
	lx_addr_type_t type;

	if ((nlen = calc_addr_size(np, nl, &type)) < 0)
		return (nlen);

	if ((name = SAFE_ALLOCA(nlen)) == NULL)
		return (-EINVAL);

	if ((r = convert_sockaddr(name, &len, np, nl, type)) < 0)
		return (r);

	lx_debug("\tconnect(%d, 0x%p, %d)", sockfd, name, len);

	if (name->sa_family == AF_UNIX)
		lx_debug("\t\tAF_UNIX, path = %s", name->sa_data);

	r = connect(sockfd, name, len);

	return ((r < 0) ? -errno : r);
}

long
lx_listen(int sockfd, int backlog)
{
	int r;

	lx_debug("\tlisten(%d, %d)", sockfd, backlog);
	r = listen(sockfd, backlog);

	return ((r < 0) ? -errno : r);
}

long
lx_accept(int sockfd, void *name, int *nlp)
{
	socklen_t namelen = 0;
	int r;

	lx_debug("\taccept(%d, 0x%p, 0x%p", sockfd, (struct sockaddr *)name,
	    nlp);

	/*
	 * The Linux man page says that -1 is returned and errno is set to
	 * EFAULT if the "name" address is bad, but it is silent on what to
	 * set errno to if the "namelen" address is bad.  Experimentation
	 * shows that Linux (at least the 2.4.21 kernel in CentOS) actually
	 * sets errno to EINVAL in both cases.
	 *
	 * Note that we must first check the name pointer, as the Linux
	 * docs state nothing is copied out if the "name" pointer is NULL.
	 * If it is NULL, we don't care about the namelen pointer's value
	 * or about dereferencing it.
	 *
	 * Happily, Solaris' accept(3SOCKET) treats NULL name pointers and
	 * zero namelens the same way.
	 */
	if ((name != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept namelen = %d", namelen);

	if ((r = accept(sockfd, (struct sockaddr *)name, &namelen)) < 0)
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept namelen returned %d bytes", namelen);

	/*
	 * In Linux, accept()ed sockets do not inherit anything set by
	 * fcntl(), so filter those out.
	 */
	if (fcntl(r, F_SETFL, 0) < 0)
		return (-errno);

	/*
	 * Once again, a bad "namelen" address sets errno to EINVAL, not
	 * EFAULT.  If namelen was zero, there's no need to copy a zero back
	 * out.
	 *
	 * Logic might dictate that we should check if we can write to
	 * the namelen pointer earlier so we don't accept a pending connection
	 * only to fail the call because we can't write the namelen value back
	 * out. However, testing shows Linux does indeed fail the call after
	 * accepting the connection so we must behave in a compatible manner.
	 */
	if ((name != NULL) && (namelen != 0) &&
	    (uucopy(&namelen, (void *)nlp, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	return (r);
}

long
lx_getsockname(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name = NULL;
	socklen_t namelen, namelen_orig;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

	lx_debug("\tgetsockname(%d, 0x%p, 0x%p (=%d))", sockfd,
	    (struct sockaddr *)np, nlp, namelen);

	if (namelen > 0) {
		if ((name = SAFE_ALLOCA(namelen)) == NULL)
			return (-EINVAL);
		bzero(name, namelen);
	}

	if (getsockname(sockfd, name, &namelen) < 0)
		return (-errno);

	/*
	 * If the name that getsockname() wants to return is larger
	 * than namelen, getsockname() will copy out the maximum amount
	 * of data possible and then update namelen to indicate the
	 * actually size of all the data that it wanted to copy out.
	 */
	if (uucopy(name, np, namelen_orig) != 0)
		return (-errno);
	if (uucopy(&namelen, (void *)nlp, sizeof (socklen_t)) != 0)
		return (-errno);

	return (0);
}

long
lx_getpeername(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name;
	socklen_t namelen;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);

	lx_debug("\tgetpeername(%d, 0x%p, 0x%p (=%d))", sockfd,
	    (struct sockaddr *)np, nlp, namelen);

	/* LTP can pass -1 but we'll limit the allocation to a page */
	if ((uint32_t)namelen > 4096)
		return (-EINVAL);

	/*
	 * Linux returns EFAULT in this case, even if the namelen parameter
	 * is 0 (some test cases use -1, so we check for that too).  This check
	 * will not catch other illegal addresses, but the benefit catching a
	 * non-null illegal address here is not worth the cost of another
	 * system call.
	 */
	if (np == NULL || np == (void *)-1)
		return (-EFAULT);

	if ((name = SAFE_ALLOCA(namelen)) == NULL)
		return (-EINVAL);
	if ((getpeername(sockfd, name, &namelen)) < 0)
		return (-errno);

	if (uucopy(name, np, namelen) != 0)
		return (-errno);

	if (uucopy(&namelen, (void *)nlp, sizeof (socklen_t)) != 0)
		return (-errno);

	return (0);
}

long
lx_socketpair(int domain, int type, int protocol, int *sv)
{
	int options;
	int fds[2];
	int r;

	r = convert_sock_args(domain, type, protocol, &domain, &type, &options);
	if (r != 0)
		return (r);

	lx_debug("\tsocketpair(%d, %d, %d, 0x%p)", domain, type, protocol, sv);

	r = socketpair(domain, type | options, protocol, fds);

	if (r == 0) {
		if (uucopy(fds, sv, sizeof (fds)) != 0) {
			r = errno;
			(void) close(fds[0]);
			(void) close(fds[1]);
			return (-r);
		}
		return (0);
	}

	if (errno == EPROTONOSUPPORT)
		return (-ESOCKTNOSUPPORT);

	return (-errno);
}

long
lx_sendto(int sockfd, void *buf, size_t len, int flags, void *lto, int tolen)
{
	struct sockaddr *to = NULL;
	ssize_t r;
	socklen_t tlen = (socklen_t)tolen;
	int nlen;
	lx_addr_type_t type;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	if (lto != NULL) {
		if (tolen < 0)
			return (-EINVAL);

		if ((nlen = calc_addr_size(lto, tolen, &type)) < 0)
			return (nlen);

		if ((to = SAFE_ALLOCA(nlen)) == NULL)
			return (-EINVAL);

		if ((r = convert_sockaddr(to, &tlen, lto, tlen, type)) < 0)
			return (r);
	}


	lx_debug("\tsendto(%d, 0x%p, 0x%d, 0x%x, 0x%x, %d)", sockfd, buf, len,
	    flags, to, tlen);

	flags = convert_sockflags(flags, "sendto");

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("sendto(): could not ignore SIGPIPE to "
			    "emulate LX_MSG_NOSIGNAL");
	}

	r = sendto(sockfd, buf, len, flags, to, tolen);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("sendto(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	if (r < 0) {
		/*
		 * according to the man page and LTP, the expected error in
		 * this case is EPIPE.
		 */
		if (errno == ENOTCONN)
			return (-EPIPE);
		else
			return (-errno);
	}
	return (r);
}

long
lx_recvfrom(int sockfd, void *buf, size_t len, int flags, void *from,
    int *from_lenp)
{
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecvfrom(%d, 0x%p, 0x%d, 0x%x, 0x%p, 0x%p)", sockfd, buf,
	    len, flags, from, from_lenp);

	/* LTP expects EINVAL when from_len == -1 */
	if (from_lenp != NULL) {
		int flen;

		if (uucopy(from_lenp, &flen, sizeof (int)) != 0)
			return (-errno);
		if (flen == -1)
			return (-EINVAL);
	}

	flags = convert_sockflags(flags, "recvfrom");

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("recvfrom(): could not ignore SIGPIPE "
			    "to emulate LX_MSG_NOSIGNAL");
	}

	r = recvfrom(sockfd, buf, len, flags, (struct sockaddr *)from,
	    from_lenp);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("recvfrom(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	return ((r < 0) ? -errno : r);
}

long
lx_shutdown(int sockfd, int how)
{
	int r;

	lx_debug("\tshutdown(%d, %d)", sockfd, how);
	r = shutdown(sockfd, how);

	return ((r < 0) ? -errno : r);
}

static lx_proto_opts_t *
get_proto_opt_tbl(int level)
{
	switch (level) {
	case LX_IPPROTO_IP:	return (&ip_sockopts_tbl);
	case LX_SOL_SOCKET:	return (&socket_sockopts_tbl);
	case LX_IPPROTO_IGMP:	return (&igmp_sockopts_tbl);
	case LX_IPPROTO_TCP:	return (&tcp_sockopts_tbl);
	case LX_IPPROTO_RAW:	return (&raw_sockopts_tbl);
	default:
		lx_unsupported("Unsupported sockopt level %d", level);
		return (NULL);
	}
}

long
lx_setsockopt(int sockfd, int level, int optname, void *optval, int optlen)
{
	int internal_opt;
	uchar_t internal_uchar;
	int r;
	lx_proto_opts_t *proto_opts;
	boolean_t converted = B_FALSE;

	lx_debug("\tsetsockopt(%d, %d, %d, 0x%p, %d)", sockfd, level, optname,
	    optval, optlen);

	/*
	 * The kernel returns EFAULT for all invalid addresses except NULL,
	 * for which it returns EINVAL.  Linux wants EFAULT for NULL too.
	 */
	if (optval == NULL)
		return (-EFAULT);

	if (level > LX_IPPROTO_RAW || level == LX_IPPROTO_UDP)
		return (-ENOPROTOOPT);

	if ((proto_opts = get_proto_opt_tbl(level)) == NULL)
		return (-ENOPROTOOPT);

	if (optname <= 0 || optname >= proto_opts->maxentries) {
		lx_unsupported("Unsupported sockopt %d, proto %d", optname,
		    level);
		return (-ENOPROTOOPT);
	}

	if (level == LX_IPPROTO_IP) {
		/*
		 * Ping sets this option to receive errors on raw sockets.
		 * Currently we just ignore it to make ping happy. From the
		 * Linux ip.7 man page:
		 *    For raw sockets, IP_RECVERR enables passing of all
		 *    received ICMP errors to the application.
		 */
		if (optname == LX_IP_RECVERR &&
		    strcmp(lx_cmd_name, "ping") == 0)
			return (0);

		if (optname == LX_IP_RECVERR &&
		    strcmp(lx_cmd_name, "traceroute") == 0)
			return (0);

		if (optname == LX_IP_MTU_DISCOVER &&
		    strcmp(lx_cmd_name, "traceroute") == 0) {
			/*
			 * The native traceroute uses IP_DONTFRAG. Set this
			 * and ignore LX_IP_MTU_DISCOVER for traceroute.
			 */
			optname = IP_DONTFRAG;
			converted = B_TRUE;
		}

		/*
		 * For IP_MULTICAST_TTL and IP_MULTICAST_LOOP, Linux defines
		 * the option value to be an integer while we define it to be
		 * an unsigned character.  To prevent the kernel from spitting
		 * back an error on an illegal length, verify that the option
		 * value is less than UCHAR_MAX and then swizzle it.
		 */
		if (optname == LX_IP_MULTICAST_TTL ||
		    optname == LX_IP_MULTICAST_LOOP) {
			if (optlen != sizeof (int))
				return (-EINVAL);

			if (uucopy(optval, &internal_opt, sizeof (int)) != 0)
				return (-errno);

			if (internal_opt > UCHAR_MAX)
				return (-EINVAL);

			internal_uchar = (uchar_t)internal_opt;
			optval = &internal_uchar;
			optlen = sizeof (uchar_t);
		}
	} else if (level == LX_SOL_SOCKET) {
		/* Linux ignores this option. */
		if (optname == LX_SO_BSDCOMPAT)
			return (0);

		level = SOL_SOCKET;
	} else if (level == LX_IPPROTO_RAW) {
		/*
		 * Ping sets this option. Currently we just ignore it to make
		 * ping happy.
		 */
		if (optname == LX_ICMP_FILTER &&
		    strcmp(lx_cmd_name, "ping") == 0)
			return (0);
	}

	if (!converted) {
		int orig_optname = optname;

		/*
		 * Do a table lookup of the Illumos equivalent of the given
		 * option.
		 */
		optname = proto_opts->proto[optname];
		if (optname == OPTNOTSUP) {
			lx_unsupported("unsupported sockopt %d, proto %d",
			    orig_optname, level);
			return (-ENOPROTOOPT);
		}
	}

	r = setsockopt(sockfd, level, optname, optval, optlen);

	return ((r < 0) ? -errno : r);
}

long
lx_getsockopt(int sockfd, int level, int optname, void *optval, int *optlenp)
{
	int r;
	int orig_optname;
	lx_proto_opts_t *proto_opts;

	lx_debug("\tgetsockopt(%d, %d, %d, 0x%p, 0x%p)", sockfd, level, optname,
	    optval, optlenp);

	/*
	 * According to the Linux man page, a NULL optval should indicate
	 * (as in Solaris) that no return value is expected.  Instead, it
	 * actually triggers an EFAULT error.
	 */
	if (optval == NULL)
		return (-EFAULT);

	if (level > LX_IPPROTO_RAW || level == LX_IPPROTO_UDP)
		return (-EOPNOTSUPP);

	if ((proto_opts = get_proto_opt_tbl(level)) == NULL)
		return (-ENOPROTOOPT);

	if (optname <= 0 || optname >= (proto_opts->maxentries)) {
		lx_unsupported("Unsupported sockopt %d, proto %d", optname,
		    level);
		return (-ENOPROTOOPT);
	}

	if ((level == LX_IPPROTO_TCP) && (optname == LX_TCP_CORK)) {
		/*
		 * We don't support TCP_CORK but some apps rely on it.  So,
		 * rather than return an error we just return 0.  This
		 * isn't exactly a lie, since this option really isn't set,
		 * but it's not the whole truth either.  Fortunately, we
		 * aren't under oath.
		 */
		r = 0;
		if (uucopy(&r, optval, sizeof (int)) != 0)
			return (-errno);
		r = sizeof (int);
		if (uucopy(&r, optlenp, sizeof (int)) != 0)
			return (-errno);
		return (0);
	}
	if ((level == LX_SOL_SOCKET) && (optname == LX_SO_PEERCRED)) {
		struct lx_ucred	lx_ucred;
		ucred_t		*ucp;

		/*
		 * We don't support SO_PEERCRED, but we do have equivalent
		 * functionality in getpeerucred() so invoke that here.
		 */

		/* Verify there's going to be enough room for the results. */
		if (uucopy(optlenp, &r, sizeof (int)) != 0)
			return (-errno);
		if (r < sizeof (struct lx_ucred))
			return (-EOVERFLOW);

		/*
		 * We allocate a ucred_t ourselves rather than allow
		 * getpeerucred() to do it for us because getpeerucred()
		 * uses malloc(3C) and we'd rather use SAFE_ALLOCA().
		 */
		if ((ucp = (ucred_t *)SAFE_ALLOCA(ucred_size())) == NULL)
			return (-ENOMEM);

		/* Get the credential for the remote end of this socket. */
		if (getpeerucred(sockfd, &ucp) != 0)
			return (-errno);
		if (((lx_ucred.lxu_pid = ucred_getpid(ucp)) == -1) ||
		    ((lx_ucred.lxu_uid = ucred_geteuid(ucp)) == (uid_t)-1) ||
		    ((lx_ucred.lxu_gid = ucred_getegid(ucp)) == (gid_t)-1)) {
			return (-errno);
		}

		/* Copy out the results. */
		if ((uucopy(&lx_ucred, optval, sizeof (lx_ucred))) != 0)
			return (-errno);
		r = sizeof (lx_ucred);
		if ((uucopy(&r, optlenp, sizeof (int))) != 0)
			return (-errno);
		return (0);
	}

	orig_optname = optname;

	optname = proto_opts->proto[optname];
	if (optname == OPTNOTSUP) {
		lx_unsupported("unsupported sockopt %d, proto %d",
		    orig_optname, level);
		return (-ENOPROTOOPT);
	}

	if (level == LX_SOL_SOCKET)
		level = SOL_SOCKET;

	r = getsockopt(sockfd, level, optname, optval, optlenp);

	if (r == 0 && level == SOL_SOCKET) {
		switch (optname) {
		case SO_TYPE:
			/* translate our type back to Linux */
			*(int *)optval = stol_socktype[(*(int *)optval)];
			break;

		case SO_ERROR:
			*(int *)optval = lx_errno(*(int *)optval);
			break;
		}
	}

	return ((r < 0) ? -errno : r);
}

/*
 * libc routines that issue these system calls.  We bypass the libsocket
 * wrappers since they explicitly turn off the MSG_XPG_2 flag we need for
 * Linux compatibility.
 */
extern int _so_sendmsg();
extern int _so_recvmsg();

long
lx_sendmsg(int sockfd, void *lmp, int flags)
{
	struct lx_msghdr msg;
	struct cmsghdr *cmsg;
	void *new_cmsg = NULL;
	int r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\tsendmsg(%d, 0x%p, 0x%x)", sockfd, lmp, flags);

	flags = convert_sockflags(flags, "sendmsg");

	if ((uucopy(lmp, &msg, sizeof (msg))) != 0)
		return (-errno);

	if (msg.msg_name != NULL && msg.msg_namelen < sizeof (struct sockaddr))
		return (-EINVAL);

	/*
	 * If there are control messages bundled in this message, we need
	 * to convert them from Linux to Solaris.
	 */
	if (msg.msg_control != NULL) {
		if (msg.msg_controllen == 0) {
			cmsg = NULL;
		} else {
			cmsg = SAFE_ALLOCA(msg.msg_controllen);
			if (cmsg == NULL)
				return (-EINVAL);
#if defined(_LP64)
			/*
			 * We don't know in advance how many control msgs
			 * there are, but we do know that the native header is
			 * 4 bytes smaller than the Linux header, so allocating
			 * the same size will over-estimate what we actually
			 * need.
			 */
			new_cmsg = SAFE_ALLOCA(msg.msg_controllen);
			if (new_cmsg == NULL)
				return (-EINVAL);
#endif
		}
		if ((uucopy(msg.msg_control, cmsg,
		    msg.msg_controllen)) != 0)
			return (-errno);
		msg.msg_control = cmsg;
		if ((r = convert_cmsgs(LX_TO_SOL, &msg, new_cmsg,
		    "sendmsg()")) != 0)
			return (-r);
	}

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("sendmsg(): could not ignore SIGPIPE to "
			    "emulate LX_MSG_NOSIGNAL");
	}

	r = _so_sendmsg(sockfd, (struct msghdr *)&msg, flags | MSG_XPG4_2);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("sendmsg(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	if (r < 0) {
		/*
		 * according to the man page and LTP, the expected error in
		 * this case is EPIPE.
		 */
		if (errno == ENOTCONN)
			return (-EPIPE);
		else
			return (-errno);
	}

	return (r);
}

long
lx_recvmsg(int sockfd, void *lmp, int flags)
{
	struct lx_msghdr msg;
	struct cmsghdr *cmsg = NULL;
	void *new_cmsg = NULL;
	int r, err;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecvmsg(%d, 0x%p, 0x%x)", sockfd, lmp, flags);

	flags = convert_sockflags(flags, "recvmsg");

	if ((uucopy(lmp, &msg, sizeof (msg))) != 0)
		return (-errno);

	/*
	 * If we are expecting to have to convert any control messages,
	 * then we should receive them into our address space instead of
	 * the app's.
	 */
	if (msg.msg_control != NULL) {
		cmsg = msg.msg_control;
		if (msg.msg_controllen == 0) {
			msg.msg_control = NULL;
		} else {
			msg.msg_control = SAFE_ALLOCA(msg.msg_controllen);
			if (msg.msg_control == NULL)
				return (-EINVAL);
#if defined(_LP64)
			new_cmsg = SAFE_ALLOCA(msg.msg_controllen +
			    LX_CMSG_EXTRA);
			if (new_cmsg == NULL)
				return (-EINVAL);
#endif
		}
	}

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("recvmsg(): could not ignore SIGPIPE to "
			    "emulate LX_MSG_NOSIGNAL");
	}

	r = _so_recvmsg(sockfd, (struct msghdr *)&msg, flags | MSG_XPG4_2);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("recvmsg(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	if (r >= 0 && msg.msg_controllen >= sizeof (struct cmsghdr)) {
		/*
		 * If there are control messages bundled in this message,
		 * we need to convert them from Linux to Solaris.
		 */
		if ((err = convert_cmsgs(SOL_TO_LX, &msg, new_cmsg,
		    "recvmsg()")) != 0)
			return (-err);

		if ((uucopy(msg.msg_control, cmsg,
		    msg.msg_controllen)) != 0)
			return (-errno);
	}

	msg.msg_control = cmsg;

	/*
	 * A handful of the values in the msghdr are set by the recvmsg()
	 * call, so copy their values back to the caller.  Rather than iterate,
	 * just copy the whole structure back.
	 */
	if (uucopy(&msg, lmp, sizeof (msg)) != 0)
		return (-errno);

	return ((r < 0) ? -errno : r);
}

/*
 * Based on the lx_accept code with the addition of the flags handling.
 * See internal comments in that function for more explanation.
 */
long
lx_accept4(int sockfd, void *name, int *nlp, int lx_flags)
{
	socklen_t namelen = 0;
	int flags = 0;
	int r;

	lx_debug("\taccept4(%d, 0x%p, 0x%p 0x%x", sockfd, name, nlp, lx_flags);

	if ((name != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept4 namelen = %d", namelen);

	if (lx_flags & LX_SOCK_NONBLOCK)
		flags |= SOCK_NONBLOCK;

	if (lx_flags & LX_SOCK_CLOEXEC)
		flags |= SOCK_CLOEXEC;

	if ((r = accept4(sockfd, (struct sockaddr *)name, &namelen, flags)) < 0)
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept4 namelen returned %d bytes", namelen);

	if ((name != NULL) && (namelen != 0) &&
	    (uucopy(&namelen, (void *)nlp, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	return (r);
}

#ifdef __i386

static int
lx_socket32(ulong_t *args)
{
	return (lx_socket((int)args[0], (int)args[1], (int)args[2]));
}

static int
lx_bind32(ulong_t *args)
{
	return (lx_bind((int)args[0], (struct sockaddr *)args[1],
	    (int)args[2]));
}

static int
lx_connect32(ulong_t *args)
{
	return (lx_connect((int)args[0], (struct sockaddr *)args[1],
	    (int)args[2]));
}

static int
lx_listen32(ulong_t *args)
{
	return (lx_listen((int)args[0], (int)args[1]));
}

static int
lx_accept32(ulong_t *args)
{
	return (lx_accept((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
}

static int
lx_getsockname32(ulong_t *args)
{
	return (lx_getsockname((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
}

static int
lx_getpeername32(ulong_t *args)
{
	return (lx_getpeername((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2]));
}

static int
lx_socketpair32(ulong_t *args)
{
	return (lx_socketpair((int)args[0], (int)args[1], (int)args[2],
	    (int *)args[3]));
}

static ssize_t
lx_send(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\tsend(%d, 0x%p, 0x%d, 0x%x)", sockfd, buf, len, flags);

	flags = convert_sockflags(flags, "send");

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("send(): could not ignore SIGPIPE to "
			    "emulate LX_MSG_NOSIGNAL");
	}

	r = send(sockfd, buf, len, flags);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("send(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	return ((r < 0) ? -errno : r);
}

static ssize_t
lx_recv(ulong_t *args)
{
	int sockfd = (int)args[0];
	void *buf = (void *)args[1];
	size_t len = (size_t)args[2];
	int flags = (int)args[3];
	ssize_t r;

	int nosigpipe = flags & LX_MSG_NOSIGNAL;
	struct sigaction newact, oact;

	lx_debug("\trecv(%d, 0x%p, 0x%d, 0x%x)", sockfd, buf, len, flags);

	flags = convert_sockflags(flags, "recv");

	/*
	 * If nosigpipe is set, we want to emulate the Linux action of
	 * not sending a SIGPIPE to the caller if the remote socket has
	 * already been closed.
	 *
	 * As SIGPIPE is a directed signal sent only to the thread that
	 * performed the action, we can emulate this behavior by momentarily
	 * resetting the action for SIGPIPE to SIG_IGN, performing the socket
	 * call, and resetting the action back to its previous value.
	 */
	if (nosigpipe) {
		newact.sa_handler = SIG_IGN;
		newact.sa_flags = 0;
		(void) sigemptyset(&newact.sa_mask);

		if (sigaction(SIGPIPE, &newact, &oact) < 0)
			lx_err_fatal("recv(): could not ignore SIGPIPE to "
			    "emulate LX_MSG_NOSIGNAL");
	}

	r = recv(sockfd, buf, len, flags);

	if ((nosigpipe) && (sigaction(SIGPIPE, &oact, NULL) < 0))
		lx_err_fatal("recv(): could not reset SIGPIPE handler to "
		    "emulate LX_MSG_NOSIGNAL");

	return ((r < 0) ? -errno : r);
}

static ssize_t
lx_sendto32(ulong_t *args)
{
	return (lx_sendto((int)args[0], (void *)args[1], (size_t)args[2],
	    (int)args[3], (struct sockaddr *)args[4], (int)args[5]));
}

static ssize_t
lx_recvfrom32(ulong_t *args)
{
	return (lx_recvfrom((int)args[0], (void *)args[1], (size_t)args[2],
	    (int)args[3], (struct sockaddr *)args[4], (int *)args[5]));
}

static int
lx_shutdown32(ulong_t *args)
{
	return (lx_shutdown((int)args[0], (int)args[1]));
}

static int
lx_setsockopt32(ulong_t *args)
{
	return (lx_setsockopt((int)args[0], (int)args[1], (int)args[2],
	    (void *)args[3], (int)args[4]));
}

static int
lx_getsockopt32(ulong_t *args)
{
	return (lx_getsockopt((int)args[0], (int)args[1], (int)args[2],
	    (void *)args[3], (int *)args[4]));
}

static int
lx_sendmsg32(ulong_t *args)
{
	return (lx_sendmsg((int)args[0], (void *)args[1], (int)args[2]));
}

static int
lx_recvmsg32(ulong_t *args)
{
	return (lx_recvmsg((int)args[0], (void *)args[1], (int)args[2]));
}

static int
lx_accept4_32(ulong_t *args)
{
	return (lx_accept4((int)args[0], (struct sockaddr *)args[1],
	    (int *)args[2], (int)args[3]));
}

static int
lx_recvmmsg32(ulong_t *args)
{
	lx_unsupported("Unsupported socketcall: recvmmsg\n.");
	return (-EINVAL);
}

static int
lx_sendmmsg32(ulong_t *args)
{
	lx_unsupported("Unsupported socketcall: sendmmsg\n.");
	return (-EINVAL);
}

long
lx_socketcall(uintptr_t p1, uintptr_t p2)
{
	int subcmd = (int)p1 - 1; /* subcommands start at 1 - not 0 */
	ulong_t args[6];
	int r;

	if (subcmd < 0 || subcmd >= LX_SENDMMSG)
		return (-EINVAL);

	/*
	 * Copy the arguments to the subcommand in from the app's address
	 * space, returning EFAULT if we get a bogus pointer.
	 */
	if (uucopy((void *)p2, args,
	    sockfns[subcmd].s_nargs * sizeof (ulong_t)))
		return (-errno);

	r = (sockfns[subcmd].s_fn)(args);

	return (r);
}

#endif /* __i386 */
