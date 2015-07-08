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
 * Copyright 2015 Joyent, Inc. All rights reserved.
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
#include <netinet/icmp6.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/lx_debug.h>
#include <sys/lx_syscall.h>
#include <sys/lx_socket.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <netpacket/packet.h>

/*
 * This string is used to prefix all abstract namespace Unix sockets, ie all
 * abstract namespace sockets are converted to regular sockets in the /tmp
 * directory with .ABSK_ prefixed to their names.
 */
#define	ABST_PRFX "/tmp/.ABSK_"
#define	ABST_PRFX_LEN 11

#define	LX_DEV_LOG			"/dev/log"
#define	LX_DEV_LOG_REDIRECT		"/var/run/.dev_log_redirect"
#define	LX_DEV_LOG_REDIRECT_LEN		18 /* len appended to /dev/log len */
#define	LX_DEV_LOG_REDIRECT_TOT_LEN	26

typedef enum {
	lxa_none,
	lxa_abstract,
	lxa_devlog
} lx_addr_type_t;

#ifdef __i386

static int lx_socket32(ulong_t *);
static int lx_bind32(ulong_t *);
static int lx_listen32(ulong_t *);
static int lx_accept32(ulong_t *);
static int lx_getsockname32(ulong_t *);
static int lx_getpeername32(ulong_t *);
static int lx_socketpair32(ulong_t *);
static int lx_shutdown32(ulong_t *);
static int lx_setsockopt32(ulong_t *);
static int lx_getsockopt32(ulong_t *);
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
	NULL, 3,
	lx_listen32, 2,
	lx_accept32, 3,
	lx_getsockname32, 3,
	lx_getpeername32, 3,
	lx_socketpair32, 4,
	NULL, 4,
	NULL, 4,
	NULL, 6,
	NULL, 6,
	lx_shutdown32, 2,
	lx_setsockopt32, 5,
	lx_getsockopt32, 5,
	NULL, 3,
	NULL, 3,
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
	AF_UNSPEC, AF_UNIX, AF_INET, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_INET6, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_LX_NETLINK,
	AF_PACKET, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED
};

#define	LX_AF_INET6	10
#define	LX_AF_NETLINK	16
#define	LX_AF_PACKET	17

static const int stol_family[LX_AF_MAX + 1] =  {
	AF_UNSPEC, AF_UNIX, AF_INET, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, LX_AF_INET6, AF_NOTSUPPORTED, AF_NOTSUPPORTED,
	AF_NOTSUPPORTED, AF_NOTSUPPORTED, AF_NOTSUPPORTED, LX_AF_PACKET,
	LX_AF_NETLINK
};

#define	LTOS_FAMILY(d) ((d) <= LX_AF_MAX ? ltos_family[(d)] : AF_INVAL)
#define	STOL_FAMILY(d) ((d) <= LX_AF_MAX ? stol_family[(d)] : AF_INVAL)

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
 *
 * For a certain subset of sockopts, Linux will implicitly truncate optval
 * input, so long as optlen meets a minimum size.  Because illumos is strict
 * about optlen, we must cap optlen for those options.
 */

typedef struct lx_sockopt_map {
	const int lsm_opt;	/* Illumos-native equivalent */
	const int lsm_lcap;	/* Cap optlen to this size. (Ignored if 0) */
} lx_sockopt_map_t;

typedef struct lx_proto_opts {
	const lx_sockopt_map_t *proto;	/* Linux to Illumos mapping table */
	int maxentries;			/* max entries in this table */
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
static const lx_sockopt_map_t ltos_ip_sockopts[LX_IP_UNICAST_IF + 1] = {
	{ OPTNOTSUP, 0 },
	{ IP_TOS, sizeof (int) },
	{ IP_TTL, sizeof (int) },
	{ IP_HDRINCL, sizeof (int) },
	{ IP_OPTIONS, 0 },
	{ OPTNOTSUP, 0 },
	{ IP_RECVOPTS, sizeof (int) },
	{ IP_RETOPTS, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IP_RECVTTL, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IP_MULTICAST_IF, sizeof (int) },
	{ IP_MULTICAST_TTL, sizeof (int) },
	{ IP_MULTICAST_LOOP, sizeof (int) },
	{ IP_ADD_MEMBERSHIP, 0 },
	{ IP_DROP_MEMBERSHIP, 0 },
	{ IP_UNBLOCK_SOURCE, 0 },
	{ IP_BLOCK_SOURCE, 0 },
	{ IP_ADD_SOURCE_MEMBERSHIP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }
};

/*
 * Linux			Illumos
 * -----			-------
 *
 * IPV6_ADDRFORM	1
 * IPV6_2292PKTINFO	2
 * IPV6_2292HOPOPTS	3
 * IPV6_2292DSTOPTS	4
 * IPV6_2292RTHDR	5
 * IPV6_2292PKTOPTIONS	6
 * IPV6_CHECKSUM	7	IPV6_CHECKSUM  0x18
 * IPV6_2292HOPLIMIT	8
 * IPV6_NEXTHOP		9
 * IPV6_AUTHHDR		10
 * IPV6_UNICAST_HOPS	16	IPV6_UNICAST_HOPS  0x5
 * IPV6_MULTICAST_IF	17	IPV6_MULTICAST_IF  0x6
 * IPV6_MULTICAST_HOPS	18	IPV6_MULTICAST_HOPS  0x7
 * IPV6_MULTICAST_LOOP	19	IPV6_MULTICAST_LOOP  0x8
 * IPV6_JOIN_GROUP	20
 * IPV6_LEAVE_GROUP	21
 * IPV6_ROUTER_ALERT	22
 * IPV6_MTU_DISCOVER	23
 * IPV6_MTU		24	(discarded)
 * IPV6_RECVERR		25
 * IPV6_V6ONLY		26	IPV6_V6ONLY  0x27
 * IPV6_JOIN_ANYCAST	27
 * IPV6_LEAVE_ANYCAST	28
 * IPV6_IPSEC_POLICY	34
 * IPV6_XFRM_POLICY	35
 *
 * IPV6_RECVPKTINFO	49	IPV6_RECVPKTINFO  0x12
 * IPV6_PKTINFO		50	IPV6_PKTINFO  0xb
 * IPV6_RECVHOPLIMIT	51	IPV6_RECVHOPLIMIT  0x13
 * IPV6_HOPLIMIT	52	IPV6_HOPLIMIT  0xc
 * IPV6_RECVHOPOPTS	53
 * IPV6_HOPOPTS		54
 * IPV6_RTHDRDSTOPTS	55
 * IPV6_RECVRTHDR	56
 * IPV6_RTHDR		57
 * IPV6_RECVDSTOPTS	58
 * IPV6_DSTOPTS		59
 * IPV6_RECVTCLASS	66
 * IPV6_TCLASS		67	IPV6_TCLASS  0x26
 */


static const lx_sockopt_map_t ltos_ipv6_sockopts[LX_IPV6_TCLASS + 1] = {
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IPV6_CHECKSUM, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IPV6_UNICAST_HOPS, sizeof (int) },
	{ IPV6_MULTICAST_IF, sizeof (int) },
	{ IPV6_MULTICAST_HOPS, sizeof (int) },
	{ IPV6_MULTICAST_LOOP, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IPV6_V6ONLY, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IPV6_RECVPKTINFO, sizeof (int) },
	{ IPV6_PKTINFO, 0 },
	{ IPV6_RECVHOPLIMIT, sizeof (int) },
	{ IPV6_HOPLIMIT, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IPV6_TCLASS, sizeof (int) }
};

/*
 * Linux			Illumos
 * -----			-------
 *
 * ICMP6_FILTER	1		ICMP6_FILTER	1
 */

static const lx_sockopt_map_t ltos_icmpv6_sockopts[LX_ICMP6_FILTER + 1] = {
	{ OPTNOTSUP, 0 },
	{ ICMP6_FILTER, 0 }
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

static const lx_sockopt_map_t ltos_tcp_sockopts[LX_TCP_NOTSENT_LOWAT + 1] = {
	{ OPTNOTSUP, 0 },
	{ TCP_NODELAY, sizeof (int) },
	{ TCP_MAXSEG, sizeof (int) },
	{ TCP_CORK, sizeof (int) },
	{ TCP_KEEPIDLE, sizeof (int) },
	{ TCP_KEEPINTVL, sizeof (int) },
	{ TCP_KEEPCNT, sizeof (int) },
	{ OPTNOTSUP, 0 },
	{ TCP_LINGER2, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }
};

static const lx_sockopt_map_t ltos_igmp_sockopts[IGMP_MTRACE + 1] = {
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IGMP_MINLEN, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IGMP_MEMBERSHIP_QUERY, 0 },
	{ IGMP_V1_MEMBERSHIP_REPORT, 0 },
	{ IGMP_DVMRP, 0 },
	{ IGMP_PIM, 0 },
	{ OPTNOTSUP, 0 },
	{ IGMP_V2_MEMBERSHIP_REPORT, 0 },
	{ IGMP_V2_LEAVE_GROUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ IGMP_MTRACE_RESP, 0 },
	{ IGMP_MTRACE, 0 }
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
 * SO_SNDBUFFORCE        32		SO_SNDBUF (FORCE is a lie)
 * SO_RCVBUFFORCE        33		SO_RCVBUF (FORCE is a lie)
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
static const lx_sockopt_map_t ltos_socket_sockopts[LX_SO_BPF_EXTENSIONS + 1] = {
	{ OPTNOTSUP, 0 },
	{ SO_DEBUG, sizeof (int) },
	{ SO_REUSEADDR, sizeof (int) },
	{ SO_TYPE, 0 },
	{ SO_ERROR, 0 },
	{ SO_DONTROUTE, sizeof (int) },
	{ SO_BROADCAST, sizeof (int) },
	{ SO_SNDBUF, sizeof (int) },
	{ SO_RCVBUF, sizeof (int) },
	{ SO_KEEPALIVE, sizeof (int) },
	{ SO_OOBINLINE, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ SO_LINGER, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ SO_RECVUCRED, sizeof (int) },
	{ OPTNOTSUP, 0 },
	{ SO_RCVLOWAT, sizeof (int) },
	{ SO_SNDLOWAT, sizeof (int) },
	{ SO_RCVTIMEO, 0 },
	{ SO_SNDTIMEO, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ SO_ATTACH_FILTER, 0 },
	{ SO_DETACH_FILTER, 0 },
	{ OPTNOTSUP, 0 },
	{ SO_TIMESTAMP, sizeof (int) },
	{ SO_ACCEPTCONN, 0 },
	{ OPTNOTSUP, 0 },
	{ SO_SNDBUF, sizeof (int) },
	{ SO_RCVBUF, sizeof (int) },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ SO_PROTOTYPE, 0 },
	{ SO_DOMAIN, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }
};

/*
 * See the Linux raw.7 man page for description of the socket options.
 *    In Linux ICMP_FILTER is defined as 1 in include/uapi/linux/icmp.h
 */
static const lx_sockopt_map_t ltos_raw_sockopts[LX_IPV6_CHECKSUM + 1] = {
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }
};

/*
 * PF_PACKET sockopts
 * Linux				Illumos
 * -----				-------
 * PACKET_ADD_MEMBERSHIP	1	PACKET_ADD_MEMBERSHIP	0x2
 * PACKET_DROP_MEMBERSHIP	2	PACKET_DROP_MEMBERSHIP	0x3
 * PACKET_RECV_OUTPUT		3
 * PACKET_RX_RING		5
 * PACKET_STATISTICS		6	PACKET_STATISTICS	0x5
 */

static const lx_sockopt_map_t ltos_packet_sockopts[LX_PACKET_STATISTICS + 1] = {
	{ OPTNOTSUP, 0 },
	{ PACKET_ADD_MEMBERSHIP, 0 },
	{ PACKET_DROP_MEMBERSHIP, 0 },
	{ OPTNOTSUP, 0 }, { OPTNOTSUP, 0 }, { OPTNOTSUP, 0 },
	{ PACKET_STATISTICS, 0 }
};

#define	PROTO_SOCKOPTS(opts)    \
	{ (opts), sizeof ((opts)) / sizeof ((opts)[0]) }

/*
 * [gs]etsockopt options mapping tables
 */
static lx_proto_opts_t ip_sockopts_tbl = PROTO_SOCKOPTS(ltos_ip_sockopts);
static lx_proto_opts_t ipv6_sockopts_tbl = PROTO_SOCKOPTS(ltos_ipv6_sockopts);
static lx_proto_opts_t icmpv6_sockopts_tbl =
    PROTO_SOCKOPTS(ltos_icmpv6_sockopts);
static lx_proto_opts_t socket_sockopts_tbl =
    PROTO_SOCKOPTS(ltos_socket_sockopts);
static lx_proto_opts_t igmp_sockopts_tbl = PROTO_SOCKOPTS(ltos_igmp_sockopts);
static lx_proto_opts_t tcp_sockopts_tbl = PROTO_SOCKOPTS(ltos_tcp_sockopts);
static lx_proto_opts_t raw_sockopts_tbl = PROTO_SOCKOPTS(ltos_raw_sockopts);
static lx_proto_opts_t packet_sockopts_tbl =
    PROTO_SOCKOPTS(ltos_packet_sockopts);
/* lx_netlink does straight passthrough, so fake a table for it */
static lx_proto_opts_t netlink_sockopts_tbl = {
	NULL,
	LX_SOL_NETLINK_MAX_ENTRY
};


/* Needed for SO_ATTACH_FILTER */
struct lx_bpf_program {
    unsigned short bf_len;
    caddr_t bf_insns;
};


#define	LX_TO_SOL	1
#define	SOL_TO_LX	2

#define	LX_NETLINK_KOBJECT_UEVENT	15
#define	LX_NETLINK_ROUTE		0

typedef struct {
	sa_family_t	nl_family;
	unsigned short	nl_pad;
	uint32_t	nl_pid;
	uint32_t	nl_groups;
} lx_sockaddr_nl_t;

typedef struct {
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;  /* Depends on scope of sin6_addr */
	/* one 32-bit field shorter than illumos */
} lx_sockaddr_in6_t;

/*
 * We may need a different size socket address vs. the one passed in.
 */
static int
calc_addr_size(struct sockaddr *a, int nlen, lx_addr_type_t *type)
{
	struct sockaddr name;
	sa_family_t family;
	size_t fsize = sizeof (name.sa_family);
	int copylen = MIN(nlen, sizeof (struct sockaddr));

	if (uucopy(a, &name, copylen) != 0)
		return (-errno);
	family = LTOS_FAMILY(name.sa_family);

	if (family != AF_UNIX) {
		*type = lxa_none;

		if (family == AF_INET6)
			return (sizeof (struct sockaddr_in6));
		else if (nlen < sizeof (struct sockaddr))
			return (sizeof (struct sockaddr));
		else
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

static int
convert_pkt_proto(int protocol)
{
	switch (ntohs(protocol)) {
	case LX_ETH_P_802_2:
		return (ETH_P_802_2);
	case LX_ETH_P_IP:
		return (ETH_P_IP);
	case LX_ETH_P_ARP:
		return (ETH_P_ARP);
	case LX_ETH_P_IPV6:
		return (ETH_P_IPV6);
	case LX_ETH_P_ALL:
	case LX_ETH_P_802_3:
		return (ETH_P_ALL);
	default:
		return (-1);
	}
}

/*
 * If inaddr is an abstract namespace Unix socket, this function expects addr
 * to have enough memory to hold the expanded socket name, ie it must be of
 * size *len + ABST_PRFX_LEN. If inaddr is a netlink socket then we expect
 * addr to have enough memory to hold an Unix socket address.
 */
static int
ltos_sockaddr(struct sockaddr *addr, socklen_t *len,
    struct sockaddr *inaddr, socklen_t inlen, lx_addr_type_t type)
{
	sa_family_t family;
	struct sockaddr_ll *sll;
	int proto;
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
			 * The illumos sockaddr_in6 has one more 32-bit field
			 * than the Linux version.  We assume the caller has
			 * zeroed the sockaddr we're copying into.
			 */
			if (inlen != sizeof (lx_sockaddr_in6_t))
				return (-EINVAL);

			*len = sizeof (struct sockaddr_in6);
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

		case AF_PACKET:
			sll = (struct sockaddr_ll *)addr;
			if ((proto = convert_pkt_proto(sll->sll_protocol)) < 0)
				return (-EINVAL);
			sll->sll_protocol = proto;
			*len = inlen;
			break;

		default:
			*len = inlen;
	}

	addr->sa_family = family;
	return (0);
}

static int
stol_sockaddr(struct sockaddr *addr, socklen_t *len,
    struct sockaddr *inaddr, socklen_t inlen, socklen_t orig)
{
	int size = inlen;

	switch (inaddr->sa_family) {
	case AF_INET:
		if (inlen > sizeof (struct sockaddr))
			return (EINVAL);
		break;

	case AF_INET6:
		if (inlen != sizeof (struct sockaddr_in6))
			return (EINVAL);
		/*
		 * The linux sockaddr_in6 is shorter than illumos.
		 * We just truncate the extra field on the way out
		 */
		size = (sizeof (lx_sockaddr_in6_t));
		inlen = (sizeof (lx_sockaddr_in6_t));
		break;

	case AF_UNIX:
		if (inlen > sizeof (struct sockaddr_un))
			return (EINVAL);
		break;

	case (sa_family_t)AF_NOTSUPPORTED:
		return (EPROTONOSUPPORT);

	case (sa_family_t)AF_INVAL:
		return (EAFNOSUPPORT);

	default:
		break;
	}

	inaddr->sa_family = STOL_FAMILY(inaddr->sa_family);

	/*
	 * If inlen is larger than orig, copy out the maximum amount of
	 * data possible and then update *len to indicate the actual
	 * size of all the data that it wanted to copy out.
	 */
	size = (orig > 0 && orig < size) ? orig : size;

	if (uucopy(inaddr, addr, size) < 0)
		return (errno);

	if (uucopy(&inlen, len, sizeof (socklen_t)) < 0)
		return (errno);

	return (0);
}

static int
convert_sock_args(int in_dom, int in_type, int in_protocol, int *out_dom,
    int *out_type, int *out_options, int *out_protocol)
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
	 * sockets.  Illumos does, so bail out here.
	 */
	if (domain == AF_INET && type == SOCK_RAW && in_protocol == IPPROTO_IP)
		return (-ESOCKTNOSUPPORT);

	options = 0;
	if (in_type & LX_SOCK_NONBLOCK)
		options |= SOCK_NONBLOCK;
	if (in_type & LX_SOCK_CLOEXEC)
		options |= SOCK_CLOEXEC;

	/*
	 * The protocol definitions for PF_PACKET differ between Linux and
	 * illumos.
	 */
	if (domain == PF_PACKET &&
	    (in_protocol = convert_pkt_proto(in_protocol)) < 0)
		return (EINVAL);

	*out_dom = domain;
	*out_type = type;
	*out_options = options;
	*out_protocol = in_protocol;
	return (0);
}

long
lx_socket(int domain, int type, int protocol)
{
	int options;
	int fd;
	int err;

	err = convert_sock_args(domain, type, protocol,
	    &domain, &type, &options, &protocol);
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
	bzero(name, nlen);

	if ((r = ltos_sockaddr(name, &len, np, nl, type)) < 0)
		return (r);

	/*
	 * There are two types of Unix domain sockets for which we need to
	 * do some special handling with respect to bind:  abstract namespace
	 * sockets and /dev/log.  Abstract namespace sockets are simply Unix
	 * domain sockets that do not exist on the filesystem; we emulate them
	 * by changing their paths in ltos_sockaddr() to point to real
	 * file names in the  filesystem.  /dev/log is a special Unix domain
	 * socket that is used for system logging.  On us, /dev isn't writable,
	 * so we rewrite these sockets in ltos_sockaddr() to point to a
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
	socklen_t namelen = 0, origlen;
	struct sockaddr *saddr;
	int r, err;
	int size;

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
	 * Happily, illumos' accept(3SOCKET) treats NULL name pointers and
	 * zero namelens the same way.
	 */
	if ((name != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);
	origlen = namelen;

	if (name != NULL) {
		/*
		 * Use sizeof (struct sockaddr_in6) as the minimum temporary
		 * name allocation.  This will allow families such as AF_INET6
		 * to work properly when their namelen differs between LX and
		 * illumos.
		 */
		size = sizeof (struct sockaddr_in6);
		if (namelen > size)
			size = namelen;

		saddr = SAFE_ALLOCA(size);
		if (saddr == NULL)
			return (-EINVAL);
		bzero(saddr, size);
	} else {
		saddr = NULL;
	}

	lx_debug("\taccept namelen = %d", namelen);

	if ((r = accept(sockfd, saddr, &namelen)) < 0)
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
	if ((name != NULL) && (namelen != 0)) {
		err = stol_sockaddr((struct sockaddr *)name, (socklen_t *)nlp,
		    saddr, namelen, origlen);
		if (err != 0) {
			close(r);
			return ((err == EFAULT) ? -EINVAL : -err);
		}
	}

	return (r);
}

long
lx_getsockname(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name = NULL;
	socklen_t namelen, namelen_orig;
	struct stat sb;
	int err;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

	lx_debug("\tgetsockname(%d, 0x%p, 0x%p (=%d))", sockfd,
	    (struct sockaddr *)np, nlp, namelen);

	if (fstat(sockfd, &sb) == 0 && !S_ISSOCK(sb.st_mode))
		return (-ENOTSOCK);

	/*
	 * Use sizeof (struct sockaddr_in6) as the minimum temporary
	 * name allocation.  This will allow families such as AF_INET6
	 * to work properly when their namelen differs between LX and
	 * illumos.
	 */
	if (namelen <= 0)
		return (-EBADF);
	else if (namelen < sizeof (struct sockaddr_in6))
		namelen = sizeof (struct sockaddr_in6);

	if ((name = SAFE_ALLOCA(namelen)) == NULL)
		return (-ENOMEM);
	bzero(name, namelen);

	if (getsockname(sockfd, name, &namelen) < 0)
		return (-errno);

	/*
	 * See our other handling for LX_DEV_LOG_REDIRECT. We need to change
	 * the name back to /dev/log since some code depends on that.
	 */
	if (namelen == (LX_DEV_LOG_REDIRECT_TOT_LEN + sizeof (ushort_t) + 1) &&
	    namelen_orig >=
	    (LX_DEV_LOG_REDIRECT_TOT_LEN + sizeof (ushort_t) + 1) &&
	    strcmp(name->sa_data, LX_DEV_LOG_REDIRECT) == 0) {
		/* we don't check len since we know /dev/log is shorter */
		(void) strcpy(name->sa_data, LX_DEV_LOG);
		namelen = strlen(LX_DEV_LOG) + sizeof (ushort_t) + 1;
	}

	/*
	 * If the name that getsockname() wants to return is larger
	 * than namelen, getsockname() will copy out the maximum amount
	 * of data possible and then update namelen to indicate the
	 * actually size of all the data that it wanted to copy out.
	 */
	err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp, name,
	    namelen, namelen_orig);
	return ((err != 0) ? -err : 0);
}

long
lx_getpeername(int sockfd, void *np, int *nlp)
{
	struct sockaddr *name;
	socklen_t namelen, namelen_orig;
	int err;

	if (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0)
		return (-errno);
	namelen_orig = namelen;

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

	/*
	 * Use sizeof (struct sockaddr_in6) as the minimum temporary
	 * name allocation.  This will allow families such as AF_INET6
	 * to work properly when their namelen differs between LX and
	 * illumos.
	 */
	if (namelen < sizeof (struct sockaddr_in6))
		namelen = sizeof (struct sockaddr_in6);

	name = SAFE_ALLOCA(namelen);
	if (name == NULL)
		return (-EINVAL);
	bzero(name, namelen);

	if ((getpeername(sockfd, name, &namelen)) < 0)
		return (-errno);

	err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp,
	    name, namelen, namelen_orig);
	if (err != 0)
		return (-err);

	return (0);
}

long
lx_socketpair(int domain, int type, int protocol, int *sv)
{
	int options;
	int fds[2];
	int r;

	r = convert_sock_args(domain, type, protocol, &domain, &type, &options,
	    &protocol);
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
	case LX_IPPROTO_IPV6:	return (&ipv6_sockopts_tbl);
	case LX_IPPROTO_ICMPV6:	return (&icmpv6_sockopts_tbl);
	case LX_IPPROTO_RAW:	return (&raw_sockopts_tbl);
	case LX_SOL_PACKET:	return (&packet_sockopts_tbl);
	case LX_SOL_NETLINK:	return (&netlink_sockopts_tbl);
	default:
		lx_unsupported("Unsupported sockopt level %d", level);
		return (NULL);
	}
}

long
lx_setsockopt(int sockfd, int level, int optname, void *optval, int optlen)
{
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

	if (level > LX_SOL_NETLINK || level == LX_IPPROTO_UDP)
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

		if (optname == LX_IP_MTU_DISCOVER) {
			/*
			 * Native programs such as traceroute use IP_DONTFRAG
			 * instead.  Set that and ignore this flag.
			 */
			optname = IP_DONTFRAG;
			converted = B_TRUE;
		}

		/*
		 * For IP_MULTICAST_TTL and IP_MULTICAST_LOOP, Linux defines
		 * the option value to be an integer while we define it to be
		 * an unsigned character.  To prevent the kernel from spitting
		 * back an error on an illegal length, verify that the option
		 * value is less than UCHAR_MAX before truncating optlen.
		 */
		if (optname == LX_IP_MULTICAST_TTL ||
		    optname == LX_IP_MULTICAST_LOOP) {
			int optcopy = 0;

			if (optlen > sizeof (int) || optlen <= 0)
				return (-EINVAL);

			if (uucopy(optval, &optcopy, optlen) != 0)
				return (-errno);

			if (optcopy > UCHAR_MAX)
				return (-EINVAL);

			/*
			 * With optval validated, only optlen must be changed.
			 */
			optlen = sizeof (uchar_t);
		}
	} else if (level == LX_IPPROTO_IPV6) {
		/*
		 * There isn't a good translation for IPV6_MTU and certain apps
		 * such as bind9 will bail if it cannot be set.  We just lie
		 * about the success for now.
		 */
		if (optname == LX_IPV6_MTU)
			return (0);
	} else if (level == LX_IPPROTO_ICMPV6) {
		if (optname == LX_ICMP6_FILTER && optval != NULL) {
			int i;
			icmp6_filter_t *filter;
			/*
			 * Surprise! Linux's ICMP6_FILTER is inverted, when
			 * compared to illumos
			 */
			if (optlen != sizeof (icmp6_filter_t))
				return (-EINVAL);
			if ((filter = SAFE_ALLOCA(optlen)) == NULL)
				return (-ENOMEM);
			if (uucopy(optval, filter, optlen) != 0)
				return (-EFAULT);
			for (i = 0; i < 8; i++)
				filter->__icmp6_filt[i] ^= 0xffffffff;
			optval = filter;
		}
	} else if (level == LX_IPPROTO_TCP && optname == LX_TCP_DEFER_ACCEPT) {
		/*
		 * Emulate TCP_DEFER_ACCEPT using the datafilt(7M) socket
		 * filter but we can't emulate the timeout aspect so treat any
		 * non-zero value as enabling and zero as disabling.
		 */
		int val;

		if (optlen != sizeof (val))
			return (-EINVAL);
		if (uucopy(optval, &val, optlen) != 0)
			return (-EFAULT);
		if (val < 0)
			return (-EINVAL);

		if (val > 0) {
			if (setsockopt(sockfd, SOL_FILTER, FIL_ATTACH,
			    "datafilt", 9) < 0) {
				if (errno != EEXIST)
					return (-errno);
			}
		} else {
			if (setsockopt(sockfd, SOL_FILTER, FIL_DETACH,
			    "datafilt", 9) < 0) {
				if (errno != ENXIO)
					return (-errno);
			}
		}
		return (0);
	} else if (level == LX_SOL_SOCKET) {
		/* Linux ignores this option. */
		if (optname == LX_SO_BSDCOMPAT)
			return (0);

		if (optname == LX_SO_TIMESTAMP) {
			struct sockaddr nm;
			socklen_t nmlen = sizeof (nm);

			/*
			 * SO_TIMESTAMP is not supported on AF_UNIX sockets
			 * but we have some of those which apps use for
			 * logging, etc., so pretend this worked.
			 */
			if (getsockname(sockfd, &nm, &nmlen) == 0 &&
			    nm.sa_family == AF_UNIX) {
				return (0);
			}
		}

		/* Convert bpf program struct */
		if (optname == LX_SO_ATTACH_FILTER) {
			struct lx_bpf_program *lbp;
			struct bpf_program *bp;
			if (optlen != sizeof (*lbp))
				return (-EINVAL);
			if ((bp = SAFE_ALLOCA(sizeof (*bp))) == NULL ||
			    (lbp = SAFE_ALLOCA(sizeof (*lbp))) == NULL)
				return (-ENOMEM);
			if (uucopy(optval, lbp, sizeof (*lbp)) != 0)
				return (-errno);
			bp->bf_len = lbp->bf_len;
			bp->bf_insns = (struct bpf_insn *)lbp->bf_insns;
			optval = bp;
		}

		level = SOL_SOCKET;
	} else if (level == LX_IPPROTO_RAW) {
		/*
		 * Ping sets this option. Currently we just ignore it to make
		 * ping happy.
		 */
		if (optname == LX_ICMP_FILTER &&
		    strcmp(lx_cmd_name, "ping") == 0)
			return (0);
		/*
		 * Ping6 tries to set the IPV6_CHECKSUM offset in a way that
		 * illumos won't allow.  Quietly ignore this to prevent it from
		 * complaining.
		 */
		if (optname == LX_IPV6_CHECKSUM &&
		    strcmp(lx_cmd_name, "ping6") == 0)
			return (0);
	} else if (level == LX_SOL_PACKET) {
		level = SOL_PACKET;
		if (optname == LX_PACKET_ADD_MEMBERSHIP ||
		    optname == LX_PACKET_DROP_MEMBERSHIP) {
			/* Convert Linux mr_type to illumos */
			struct packet_mreq *mr;
			if (optlen != sizeof (*mr))
				return (-EINVAL);
			mr = SAFE_ALLOCA(sizeof (*mr));
			if (uucopy(optval, mr, sizeof (*mr)) != 0)
				return (-errno);
			if (--mr->mr_type > PACKET_MR_ALLMULTI)
				return (-EINVAL);
			optval = mr;
		}
	} else if (level == LX_SOL_NETLINK) {
		/* Just pass netlink options straight through */
		converted = B_TRUE;
	}

	if (!converted) {
		const lx_sockopt_map_t *mapping;
		/*
		 * Do a table lookup of the Illumos equivalent of the given
		 * option.
		 */
		mapping = &proto_opts->proto[optname];
		if (mapping->lsm_opt == OPTNOTSUP) {
			lx_unsupported("unsupported sockopt %d, proto %d",
			    optname, level);
			return (-ENOPROTOOPT);
		}
		optname = mapping->lsm_opt;
		/* Truncate the optlen if needed/allowed */
		if (mapping->lsm_lcap != 0 && optlen > mapping->lsm_lcap) {
			optlen = mapping->lsm_lcap;
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
	 * (as in illumos) that no return value is expected.  Instead, it
	 * actually triggers an EFAULT error.
	 */
	if (optval == NULL)
		return (-EFAULT);

	if (level > LX_SOL_PACKET || level == LX_IPPROTO_UDP)
		return (-EOPNOTSUPP);

	if ((proto_opts = get_proto_opt_tbl(level)) == NULL)
		return (-ENOPROTOOPT);

	if (optname <= 0 || optname >= (proto_opts->maxentries)) {
		lx_unsupported("Unsupported sockopt %d, proto %d", optname,
		    level);
		return (-ENOPROTOOPT);
	}

	if (level == LX_IPPROTO_TCP) {
		if (optname == LX_TCP_CORK) {
			/*
			 * We don't support TCP_CORK but some apps rely on it.
			 * So, rather than return an error we just return 0.
			 * This isn't exactly a lie, since this option really
			 * isn't set, but it's not the whole truth either.
			 * Fortunately, we aren't under oath.
			 */
			r = 0;
			if (uucopy(&r, optval, sizeof (int)) != 0)
				return (-errno);
			r = sizeof (int);
			if (uucopy(&r, optlenp, sizeof (int)) != 0)
				return (-errno);
			return (0);
		} else if (optname == LX_TCP_DEFER_ACCEPT) {
			/*
			 * We do support TCP_DEFER_ACCEPT using the
			 * datafilt(7M) socket filter but we don't emulate the
			 * timeout aspect so treat the existence as 1 and
			 * absence as 0.
			 */
			struct fil_info fi[10];
			int i, tot, len, r;

			len = sizeof (fi);
			if (getsockopt(sockfd, SOL_FILTER, FIL_LIST, fi,
			    &len) < 0)
				return (-errno);

			tot = len / sizeof (struct fil_info);
			r = 0;
			for (i = 0; i < tot; i++) {
				if (fi[i].fi_flags == FILF_PROG &&
				    strcmp(fi[i].fi_name, "datafilt") == 0) {
					r = 1;
					break;
				}
			}

			if (uucopy(&r, optval, sizeof (int)) != 0)
				return (-errno);
			r = sizeof (int);
			if (uucopy(&r, optlenp, sizeof (int)) != 0)
				return (-errno);
			return (0);
		}
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
	if ((level == LX_IPPROTO_ICMPV6) && (optname == LX_ICMP6_FILTER)) {
		icmp6_filter_t *filter;
		int i;

		/* Verify there's going to be enough room for the results. */
		if (uucopy(optlenp, &r, sizeof (int)) != 0)
			return (-errno);
		if (r < sizeof (icmp6_filter_t))
			return (-EINVAL);
		if ((filter = SAFE_ALLOCA(sizeof (icmp6_filter_t))) == NULL)
			return (-ENOMEM);

		r = getsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, filter,
		    optlenp);
		if (r != 0)
			return (-errno);

		/*
		 * ICMP6_FILTER is inverted on Linux. Make it so before copying
		 * back to caller's buffer.
		 */
		for (i = 0; i < 8; i++)
			filter->__icmp6_filt[i] ^= 0xffffffff;
		if ((uucopy(filter, optval, sizeof (icmp6_filter_t))) != 0)
			return (-errno);
		return (0);
	}
	if (level == LX_SOL_PACKET)
		level = SOL_PACKET;
	else if (level == LX_SOL_SOCKET)
		level = SOL_SOCKET;

	orig_optname = optname;

	optname = proto_opts->proto[optname].lsm_opt;
	if (optname == OPTNOTSUP) {
		lx_unsupported("unsupported sockopt %d, proto %d",
		    orig_optname, level);
		return (-ENOPROTOOPT);
	}

	r = getsockopt(sockfd, level, optname, optval, optlenp);

	if (r == 0 && level == SOL_SOCKET) {
		switch (optname) {
		case SO_TYPE:
			/* translate our type back to Linux */
			*(int *)optval = stol_socktype[(*(int *)optval)];
			break;

		case SO_ERROR:
			*(int *)optval = lx_errno(*(int *)optval, -1);
			break;
		}
	}

	return ((r < 0) ? -errno : r);
}


/*
 * Based on the lx_accept code with the addition of the flags handling.
 * See internal comments in that function for more explanation.
 */
long
lx_accept4(int sockfd, void *np, int *nlp, int lx_flags)
{
	socklen_t namelen, namelen_orig;
	struct sockaddr *name = NULL;
	int flags = 0;
	int r, err;

	lx_debug("\taccept4(%d, 0x%p, 0x%p 0x%x", sockfd, np, nlp, lx_flags);

	if ((np != NULL) &&
	    (uucopy((void *)nlp, &namelen, sizeof (socklen_t)) != 0))
		return ((errno == EFAULT) ? -EINVAL : -errno);

	namelen_orig = namelen;
	lx_debug("\taccept4 namelen = %d", namelen);

	if (np != NULL) {
		/*
		 * Use sizeof (struct sockaddr_in6) as the minimum temporary
		 * name allocation.  This will allow families such as AF_INET6
		 * to work properly when their namelen differs between LX and
		 * illumos.
		 */
		if (namelen < sizeof (struct sockaddr_in6))
			namelen = sizeof (struct sockaddr_in6);

		name = SAFE_ALLOCA(namelen);
		if (name == NULL)
			return (-EINVAL);
		bzero(name, namelen);
	}

	if (lx_flags & LX_SOCK_NONBLOCK)
		flags |= SOCK_NONBLOCK;

	if (lx_flags & LX_SOCK_CLOEXEC)
		flags |= SOCK_CLOEXEC;

	if ((r = accept4(sockfd, name, &namelen, flags)) < 0)
		return ((errno == EFAULT) ? -EINVAL : -errno);

	lx_debug("\taccept4 namelen returned %d bytes", namelen);

	if (np != NULL && namelen != 0) {
		err = stol_sockaddr((struct sockaddr *)np, (socklen_t *)nlp,
		    name, namelen, namelen_orig);
		if (err != 0) {
			close(r);
			return ((err == EFAULT) ? -EINVAL : -err);
		}
	}
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

	/* Bail out if we are trying to call an IKE function */
	if (sockfns[subcmd].s_fn == NULL) {
		lx_err_fatal("lx_socketcall: deprecated subcmd: %d", subcmd);
	}

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
