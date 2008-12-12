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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/xti_inet.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/ip_mroute.h>
#include <inet/optcom.h>


extern int	ip_opt_default(queue_t *q, int level, int name, uchar_t *ptr);
extern int	ip_opt_get(queue_t *q, int level, int name, uchar_t *ptr);
extern int	ip_opt_set(queue_t *q, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *dummy, cred_t *cr, mblk_t *first_mp);

/*
 * Table of all known options handled on a IP protocol stack.
 *
 * Note: Not all of these options are available through all protocol stacks
 *	 For example, multicast options are not accessible in TCP over IP.
 *	 The filtering for that happens in option table at transport level.
 *	 Also, this table excludes any options processed exclusively at the
 *	 transport protocol level.
 */
opdes_t		ip_opt_arr[] = {

{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_PROTOTYPE, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_ANON_MLP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_MAC_EXEMPT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},

{ SO_ALLZONES, SOL_SOCKET, OA_R, OA_RW, OP_CONFIG, 0, sizeof (int),
	0 },


{ IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },
{ T_IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },

{ IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ T_IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_TTL,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_MULTICAST_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct in_addr),	0 /* INADDR_ANY */ },

{ IP_MULTICAST_LOOP, IPPROTO_IP, OA_RW, OA_RW, OP_NP, (OP_DEF_FN),
	sizeof (uchar_t), -1 /* not initialized */},

{ IP_MULTICAST_TTL, IPPROTO_IP, OA_RW, OA_RW, OP_NP, (OP_DEF_FN),
	sizeof (uchar_t), -1 /* not initialized */ },

{ IP_ADD_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, (OP_NODEFAULT),
	sizeof (struct ip_mreq), -1 /* not initialized */ },

{ IP_DROP_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP, (OP_NODEFAULT),
	sizeof (struct ip_mreq), -1 /* not initialized */ },

{ IP_BLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, (OP_NODEFAULT),
	sizeof (struct ip_mreq_source), -1 /* not initialized */ },

{ IP_UNBLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP, (OP_NODEFAULT),
	sizeof (struct ip_mreq_source), -1 /* not initialized */ },

{ IP_ADD_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct ip_mreq_source), -1 },

{ IP_DROP_SOURCE_MEMBERSHIP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct ip_mreq_source), -1 },

{ IP_RECVOPTS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_RECVDSTADDR, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},

{ IP_RECVIF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_PKTINFO, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_RECVSLLA, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_BOUND_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_DONTFAILOVER_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct in_addr),	0 /* not initialized */ },

{ IP_DHCPINIT_IF, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (int), 0 },

{ IP_UNSPEC_SRC, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IP_SEC_OPT, IPPROTO_IP, OA_RW, OA_RW, OP_NP, (OP_NODEFAULT),
	sizeof (ipsec_req_t), -1 /* not initialized */ },

{ IP_NEXTHOP, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (in_addr_t),	-1 /* not initialized */ },

{ MRT_INIT, IPPROTO_IP, 0, OA_X, OP_CONFIG,
	(OP_NODEFAULT), sizeof (int), -1 /* not initialized */ },

{ MRT_DONE, IPPROTO_IP, 0, OA_X, OP_CONFIG,
	(OP_NODEFAULT), 0, -1 /* not initialized */ },

{ MRT_ADD_VIF, IPPROTO_IP, 0, OA_X, OP_CONFIG, (OP_NODEFAULT),
	sizeof (struct vifctl), -1 /* not initialized */ },

{ MRT_DEL_VIF, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, (OP_NODEFAULT),
	sizeof (vifi_t), -1 /* not initialized */ },

{ MRT_ADD_MFC, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, (OP_NODEFAULT),
	sizeof (struct mfcctl), -1 /* not initialized */ },

{ MRT_DEL_MFC, 	IPPROTO_IP, 0, OA_X, OP_CONFIG, (OP_NODEFAULT),
	sizeof (struct mfcctl), -1 /* not initialized */ },

{ MRT_VERSION, 	IPPROTO_IP, OA_R, OA_R, OP_NP, (OP_NODEFAULT),
	sizeof (int), -1 /* not initialized */ },

{ MRT_ASSERT, 	IPPROTO_IP, 0, OA_RW, OP_CONFIG, (OP_NODEFAULT),
	sizeof (int), -1 /* not initialized */ },

{ MCAST_JOIN_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_BLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_UNBLOCK_SOURCE, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_JOIN_SOURCE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_SOURCE_GROUP, IPPROTO_IP, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },

{ IPV6_MULTICAST_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_MULTICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_DEF_FN), sizeof (int), -1 /* not initialized */ },

{ IPV6_MULTICAST_LOOP, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_DEF_FN), sizeof (int), -1 /* not initialized */},

{ IPV6_JOIN_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP, (OP_NODEFAULT),
	sizeof (struct ipv6_mreq), -1 /* not initialized */ },

{ IPV6_LEAVE_GROUP,	IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT),
	sizeof (struct ipv6_mreq), -1 /* not initialized */ },

{ IPV6_UNICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_DEF_FN), sizeof (int), -1 /* not initialized */ },

{ IPV6_BOUND_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IPV6_BOUND_PIF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IPV6_DONTFAILOVER_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IPV6_UNSPEC_SRC, IPPROTO_IPV6, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

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
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_DSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_TCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (int), -1 /* not initialized */ },
{ IPV6_PATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct ip6_mtuinfo), -1 },
{ IPV6_DONTFRAG, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_USE_MIN_MTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), -1 },
{ IPV6_V6ONLY, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

/* Enable receipt of ancillary data */
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
{ IPV6_RECVTCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVPATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_SEC_OPT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, (OP_NODEFAULT),
	sizeof (ipsec_req_t), -1 /* not initialized */ },
{ IPV6_SRC_PREFERENCES, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (uint32_t), IPV6_PREFER_SRC_DEFAULT },

{ MCAST_JOIN_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_req),
	-1 /* not initialized */ },
{ MCAST_BLOCK_SOURCE, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_UNBLOCK_SOURCE, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_JOIN_SOURCE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
{ MCAST_LEAVE_SOURCE_GROUP, IPPROTO_IPV6, OA_X, OA_X, OP_NP,
	(OP_NODEFAULT), sizeof (struct group_source_req),
	-1 /* not initialized */ },
};


#define	IP_OPT_ARR_CNT		A_CNT(ip_opt_arr)


/*
 * Initialize option database object for IP
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t ip_opt_obj = {
	ip_opt_default,		/* IP default value function pointer */
	ip_opt_get,		/* IP get function pointer */
	ip_opt_set,		/* IP set function pointer */
	B_FALSE,		/* IP is NOT a tpi provider */
	IP_OPT_ARR_CNT,		/* IP option database count of entries */
	ip_opt_arr,		/* IP option database */
	0,			/* 0 - not needed if not top tpi provider */
	(optlevel_t *)0		/* null - not needed if not top tpi provider */
};
