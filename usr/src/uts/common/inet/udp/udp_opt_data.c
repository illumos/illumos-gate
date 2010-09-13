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

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/udp_impl.h>
/*
 * MK_XXX Following 2 includes temporary to import ip6_rthdr_t
 *        definition. May not be needed if we fix ip6_dg_snd_attrs_t
 *        to do all extension headers in identical manner.
 */
#include <net/if.h>
#include <inet/ip6.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <inet/optcom.h>

/*
 * Table of all known options handled on a UDP protocol stack.
 *
 * Note: This table contains options processed by both UDP and IP levels
 *       and is the superset of options that can be performed on a UDP over IP
 *       stack.
 */
opdes_t	udp_opt_arr[] = {

{ SO_DEBUG,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_USELOOPBACK, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_RCVTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_DGRAM_ERRIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_RECVUCRED, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_ALLZONES, SOL_SOCKET, OA_R, OA_RW, OP_CONFIG, 0, sizeof (int),
	0 },
{ SO_VRRP, SOL_SOCKET, OA_RW, OA_RW, OP_CONFIG, 0, sizeof (int), 0 },
{ SO_TIMESTAMP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_ANON_MLP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
    0 },
{ SO_MAC_EXEMPT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
    0 },
{ SO_MAC_IMPLICIT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
    0 },
/*
 * The maximum size reported here depends on the maximum value for
 * ucredsize; unfortunately, we can't add ucredsize here so we need
 * to estimate here.  Before it was 512 or 384 + NGROUPS_UMAX * sizeof (gid_t);
 * as we're changing NGROUPS_UMAX we now codify this here using NGROUPS_UMAX.
 */
{ SCM_UCRED, SOL_SOCKET, OA_W, OA_W, OP_NP, OP_VARLEN|OP_NODEFAULT,
    384 + NGROUPS_UMAX * sizeof (gid_t), 0 },
{ SO_EXCLBIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DOMAIN,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_PROTOTYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },
{ T_IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },

{ IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ T_IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_TTL,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_RECVOPTS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_RECVDSTADDR, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ IP_RECVIF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_RECVSLLA, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_RECVTTL,	IPPROTO_IP,  OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ IP_MULTICAST_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct in_addr),	0 /* INADDR_ANY */ },

{ IP_MULTICAST_LOOP, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (uchar_t), -1 /* not initialized */},

{ IP_MULTICAST_TTL, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (uchar_t), -1 /* not initialized */ },

{ IP_ADD_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq), -1 /* not initialized */ },

{ IP_DROP_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq), -1 /* not initialized */ },

{ IP_BLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq_source), -1 /* not initialized */ },

{ IP_UNBLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, OP_NODEFAULT,
	sizeof (struct ip_mreq_source), -1 /* not initialized */ },

{ IP_ADD_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct ip_mreq_source), -1 },

{ IP_DROP_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	OP_NODEFAULT, sizeof (struct ip_mreq_source), -1 },

{ IP_SEC_OPT, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },

{ IP_BOUND_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_DHCPINIT_IF, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (int), 0 },

{ IP_UNSPEC_SRC, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IP_BROADCAST_TTL, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0, sizeof (uchar_t),
	0 /* disabled */ },

{ IP_PKTINFO, IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in_pktinfo), -1 /* not initialized */ },
{ IP_NEXTHOP, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (in_addr_t),	-1 /* not initialized  */ },

{ IP_DONTFRAG, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

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

{ IPV6_LEAVE_GROUP,	IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	OP_NODEFAULT,
	sizeof (struct ipv6_mreq), -1 /* not initialized */ },

{ IPV6_UNICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IPV6_BOUND_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IPV6_UNSPEC_SRC, IPPROTO_IPV6, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_PKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in6_pktinfo), -1 /* not initialized */ },
{ IPV6_HOPLIMIT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
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
	OP_NODEFAULT,
	sizeof (int), -1 /* not initialized */ },
{ IPV6_PATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
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
{ IPV6_RECVPATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	0, sizeof (int), 0 },
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

{ UDP_ANONPRIVBIND, IPPROTO_UDP, OA_R, OA_RW, OP_PRIVPORT, 0,
	sizeof (int), 0 },
{ UDP_EXCLBIND, IPPROTO_UDP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ UDP_RCVHDR, IPPROTO_UDP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ UDP_NAT_T_ENDPOINT, IPPROTO_UDP, OA_RW, OA_RW, OP_PRIVPORT, 0, sizeof (int),
	0 },
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers and is used only by
 * XTI interfaces.
 */
optlevel_t	udp_valid_levels_arr[] = {
	XTI_GENERIC,
	SOL_SOCKET,
	IPPROTO_UDP,
	IPPROTO_IP,
	IPPROTO_IPV6
};

#define	UDP_VALID_LEVELS_CNT	A_CNT(udp_valid_levels_arr)
#define	UDP_OPT_ARR_CNT		A_CNT(udp_opt_arr)

uint_t udp_max_optsize; /* initialized when UDP driver is loaded */

/*
 * Initialize option database object for UDP
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t udp_opt_obj = {
	udp_opt_default,	/* UDP default value function pointer */
	udp_tpi_opt_get,	/* UDP get function pointer */
	udp_tpi_opt_set,	/* UDP set function pointer */
	UDP_OPT_ARR_CNT,	/* UDP option database count of entries */
	udp_opt_arr,		/* UDP option database */
	UDP_VALID_LEVELS_CNT,	/* UDP valid level count of entries */
	udp_valid_levels_arr	/* UDP valid level array */
};
