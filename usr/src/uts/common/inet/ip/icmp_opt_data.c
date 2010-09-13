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
 */

#include <sys/types.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/xti_xtiopt.h>
#include <sys/xti_inet.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

#include <netinet/tcp.h>
#include <netinet/ip_mroute.h>
#include <inet/optcom.h>
#include <inet/rawip_impl.h>

/*
 * Table of all known options handled on a ICMP protocol stack.
 *
 * Note: This table contains options processed by both ICMP and IP levels
 *       and is the superset of options that can be performed on a ICMP over IP
 *       stack.
 */
opdes_t	icmp_opt_arr[] = {

{ SO_DEBUG,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_USELOOPBACK, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

#ifdef	SO_PROTOTYPE
	/*
	 * icmp will only allow IPPROTO_ICMP for non-privileged streams
	 * that check is made on an adhoc basis.
	 */
{ SO_PROTOTYPE, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
#endif

{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_RCVTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_DGRAM_ERRIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_TIMESTAMP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_MAC_EXEMPT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_MAC_IMPLICIT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },

{ SO_ALLZONES, SOL_SOCKET, OA_R, OA_RW, OP_CONFIG, 0, sizeof (int),
	0 },
{ SO_DOMAIN,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },
{ T_IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },

{ IP_HDRINCL,	IPPROTO_IP, OA_R,  OA_RW, OP_RAW, 0,
	sizeof (int), 0 },
{ IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ T_IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_TTL,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_MULTICAST_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct in_addr), 0 /* INADDR_ANY */ },

{ IP_MULTICAST_LOOP, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (uchar_t), -1 /* not initialized */},

{ IP_MULTICAST_TTL, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (uchar_t), -1 /* not initialized */ },

{ IP_ADD_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq), -1 /* not initialized */ },

{ IP_DROP_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq), 0 },

{ IP_BLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq_source), -1 },

{ IP_UNBLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq_source), -1 },

{ IP_ADD_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct ip_mreq_source), -1 },

{ IP_DROP_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct ip_mreq_source), -1 },

{ IP_SEC_OPT, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },

{ IP_BOUND_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_UNSPEC_SRC, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IP_BROADCAST_TTL, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0, sizeof (uchar_t),
	0 /* disabled */ },

{ IP_RECVIF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_PKTINFO, IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in_pktinfo), -1 /* not initialized */ },

{ IP_DONTFRAG, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_NEXTHOP, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (in_addr_t), -1 /* not initialized */ },

{ MRT_INIT, IPPROTO_IP, 0, OA_X, OP_CONFIG,
	OP_NODEFAULT, sizeof (int),
	-1 /* not initialized */ },

{ MRT_DONE, IPPROTO_IP, 0, OA_X, OP_CONFIG,
	OP_NODEFAULT, 0, -1 /* not initialized */ },

{ MRT_ADD_VIF, IPPROTO_IP, 0, OA_X, OP_CONFIG, OP_NODEFAULT,
	sizeof (struct vifctl), -1 /* not initialized */ },

{ MRT_DEL_VIF, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, OP_NODEFAULT,
	sizeof (vifi_t), -1 /* not initialized */ },

{ MRT_ADD_MFC, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, OP_NODEFAULT,
	sizeof (struct mfcctl), -1 /* not initialized */ },

{ MRT_DEL_MFC, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, OP_NODEFAULT,
	sizeof (struct mfcctl), -1 /* not initialized */ },

{ MRT_VERSION, 	IPPROTO_IP, OA_R, OA_R, OP_NP, OP_NODEFAULT,
	sizeof (int), -1 /* not initialized */ },

{ MRT_ASSERT, 	IPPROTO_IP, 0, OA_RW, OP_CONFIG,
	OP_NODEFAULT,
	sizeof (int), -1 /* not initialized */ },

{ MCAST_JOIN_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_BLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_UNBLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_JOIN_SOURCE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_SOURCE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },

{ IPV6_MULTICAST_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_MULTICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */ },

{ IPV6_MULTICAST_LOOP, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */},

{ IPV6_JOIN_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ipv6_mreq), -1 /* not initialized */ },

{ IPV6_LEAVE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ipv6_mreq), -1 /* not initialized */ },

{ IPV6_UNICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IPV6_BOUND_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IPV6_UNSPEC_SRC, IPPROTO_IPV6, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_CHECKSUM, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	-1 },

{ ICMP6_FILTER, IPPROTO_ICMPV6, OA_RW, OA_RW, OP_NP, OP_DEF_FN|OP_VARLEN,
	sizeof (icmp6_filter_t), 0 },
{ IPV6_PKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in6_pktinfo), -1 /* not initialized */ },
{ IPV6_HOPLIMIT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (int), -1 /* not initialized */ },
{ IPV6_NEXTHOP, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (sin6_t), -1 /* not initialized */ },
{ IPV6_HOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	MAX_EHDR_LEN, -1 /* not initialized */ },
{ IPV6_DSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	MAX_EHDR_LEN, -1 /* not initialized */ },
{ IPV6_RTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	MAX_EHDR_LEN, -1 /* not initialized */ },
{ IPV6_RTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	MAX_EHDR_LEN, -1 /* not initialized */ },
{ IPV6_TCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (int), -1 /* not initialized */ },
{ IPV6_PATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct ip6_mtuinfo), -1 },
{ IPV6_DONTFRAG, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_USE_MIN_MTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_V6ONLY, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_RECVPKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPLIMIT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ _OLD_IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVPATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVTCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_SEC_OPT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },
{ IPV6_SRC_PREFERENCES, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (uint32_t), IPV6_PREFER_SRC_DEFAULT },

{ MCAST_JOIN_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_BLOCK_SOURCE, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_UNBLOCK_SOURCE, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_JOIN_SOURCE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_SOURCE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct group_source_req),
	-1 /* not initialized */ },
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers and is used only by
 * XTI interfaces.
 */
optlevel_t	icmp_valid_levels_arr[] = {
	XTI_GENERIC,
	SOL_SOCKET,
	IPPROTO_ICMP,
	IPPROTO_IP,
	IPPROTO_IPV6,
	IPPROTO_ICMPV6
};

#define	ICMP_VALID_LEVELS_CNT	A_CNT(icmp_valid_levels_arr)
#define	ICMP_OPT_ARR_CNT		A_CNT(icmp_opt_arr)

uint_t	icmp_max_optsize; /* initialized when ICMP driver is loaded */

/*
 * Initialize option database object for ICMP
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t icmp_opt_obj = {
	icmp_opt_default,	/* ICMP default value function pointer */
	icmp_tpi_opt_get,	/* ICMP get function pointer */
	icmp_tpi_opt_set,	/* ICMP set function pointer */
	ICMP_OPT_ARR_CNT,	/* ICMP option database count of entries */
	icmp_opt_arr,		/* ICMP option database */
	ICMP_VALID_LEVELS_CNT,	/* ICMP valid level count of entries */
	icmp_valid_levels_arr	/* ICMP valid level array */
};
