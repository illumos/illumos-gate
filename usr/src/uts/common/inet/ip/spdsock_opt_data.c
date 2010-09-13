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
#define	_SUN_TPI_VERSION 1
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/xti_xtiopt.h>

#include <net/pfpolicy.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <inet/optcom.h>
#include <inet/ipsec_impl.h>
#include <inet/spdsock.h>

/*
 * Table of all known options handled on a spdsock (PF_KEY) protocol stack.
 *
 * Note: This table contains options processed by both SPDSOCK and IP levels
 *       and is the superset of options that can be performed on a SPDSOCK over
 *	 IP stack.
 */

opdes_t spdsock_opt_arr[] = {
	{ SO_SNDBUF, SOL_SOCKET, OA_RW, OA_RW, 0,
	    (t_uscalar_t)sizeof (int), 0 },
	{ SO_RCVBUF, SOL_SOCKET, OA_RW, OA_RW, 0,
	    (t_uscalar_t)sizeof (int), 0 },
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers.
 */
optlevel_t	spdsock_valid_levels_arr[] = {
	SOL_SOCKET
};

#define	SPDSOCK_VALID_LEVELS_CNT	A_CNT(spdsock_valid_levels_arr)

#define	SPDSOCK_OPT_ARR_CNT		A_CNT(spdsock_opt_arr)

uint_t spdsock_max_optsize; /* initialized in spdsock_ddi_init() */

/*
 * Intialize option database object for SPDSOCK
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t spdsock_opt_obj = {
	NULL,			/* SPDSOCK default value function pointer */
	spdsock_opt_get,	/* SPDSOCK get function pointer */
	spdsock_opt_set,	/* SPDSOCK set function pointer */
	SPDSOCK_OPT_ARR_CNT,	/* SPDSOCK option database count of entries */
	spdsock_opt_arr,	/* SPDSOCK option database */
	SPDSOCK_VALID_LEVELS_CNT, /* SPDSOCK valid level count of entries */
	spdsock_valid_levels_arr  /* SPDSOCK valid level array */
};
