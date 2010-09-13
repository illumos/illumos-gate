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

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_mroute.h>
#include <inet/optcom.h>
#include <inet/rts_impl.h>

#include <inet/rts_impl.h>
/*
 * Table of all known options handled on a RTS protocol stack.
 *
 * Note: This table contains options processed by both RTS and IP levels
 *       and is the superset of options that can be performed on a RTS over IP
 *       stack.
 */
opdes_t	rts_opt_arr[] = {

{ SO_DEBUG,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_USELOOPBACK, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_RCVTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_PROTOTYPE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DOMAIN,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ RT_AWARE,	SOL_ROUTE, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers and is used only by
 * XTI interfaces.
 */
optlevel_t	rts_valid_levels_arr[] = {
	XTI_GENERIC,
	SOL_SOCKET,
	IPPROTO_IP,
	IPPROTO_IPV6
};

#define	RTS_VALID_LEVELS_CNT	A_CNT(rts_valid_levels_arr)

#define	RTS_OPT_ARR_CNT		A_CNT(rts_opt_arr)

uint_t rts_max_optsize; /* initialized in _init() */

/*
 * Intialize option database object for RTS
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t rts_opt_obj = {
	rts_opt_default,	/* RTS default value function pointer */
	rts_tpi_opt_get,	/* RTS get function pointer */
	rts_tpi_opt_set,	/* RTS set function pointer */
	RTS_OPT_ARR_CNT,	/* RTS option database count of entries */
	rts_opt_arr,		/* RTS option database */
	RTS_VALID_LEVELS_CNT,	/* RTS valid level count of entries */
	rts_valid_levels_arr	/* RTS valid level array */
};
