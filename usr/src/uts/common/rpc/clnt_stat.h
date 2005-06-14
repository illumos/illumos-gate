/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1986 - 1991, 1994, 1996, 1997, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * clnt_stat.h - Client side remote procedure call enum
 *
 */

#ifndef	_RPC_CLNT_STAT_H
#define	_RPC_CLNT_STAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

enum clnt_stat {
	RPC_SUCCESS = 0,			/* call succeeded */
	/*
	 * local errors
	 */
	RPC_CANTENCODEARGS = 1,		/* can't encode arguments */
	RPC_CANTDECODERES = 2,		/* can't decode results */
	RPC_CANTSEND = 3,			/* failure in sending call */
	RPC_CANTRECV = 4,
	/* failure in receiving result */
	RPC_TIMEDOUT = 5,			/* call timed out */
	RPC_INTR = 18,			/* call interrupted */
	RPC_UDERROR = 23,			/* recv got uderr indication */
	/*
	 * remote errors
	 */
	RPC_VERSMISMATCH = 6,		/* rpc versions not compatible */
	RPC_AUTHERROR = 7,		/* authentication error */
	RPC_PROGUNAVAIL = 8,		/* program not available */
	RPC_PROGVERSMISMATCH = 9,	/* program version mismatched */
	RPC_PROCUNAVAIL = 10,		/* procedure unavailable */
	RPC_CANTDECODEARGS = 11,		/* decode arguments error */
	RPC_SYSTEMERROR = 12,		/* generic "other problem" */

	/*
	 * rpc_call & clnt_create errors
	 */
	RPC_UNKNOWNHOST = 13,		/* unknown host name */
	RPC_UNKNOWNPROTO = 17,		/* unknown protocol */
	RPC_UNKNOWNADDR = 19,		/* Remote address unknown */
	RPC_NOBROADCAST = 21,		/* Broadcasting not supported */

	/*
	 * rpcbind errors
	 */
	RPC_RPCBFAILURE = 14,		/* the pmapper failed in its call */
#define	RPC_PMAPFAILURE RPC_RPCBFAILURE
	RPC_PROGNOTREGISTERED = 15,	/* remote program is not registered */
	RPC_N2AXLATEFAILURE = 22,
	/* Name to address translation failed */
	/*
	 * Misc error in the TLI library
	 */
	RPC_TLIERROR = 20,
	/*
	 * unspecified error
	 */
	RPC_FAILED = 16,
	/*
	 * asynchronous errors
	 */
	RPC_INPROGRESS = 24,
	RPC_STALERACHANDLE = 25,
	RPC_CANTCONNECT = 26,		/* couldn't make connection (cots) */
	RPC_XPRTFAILED = 27,		/* received discon from remote (cots) */
	RPC_CANTCREATESTREAM = 28,	/* can't push rpc module (cots) */
	/*
	 * non blocking mode errors
	 */
	RPC_CANTSTORE = 29		/* fail to store a pending message */

};

#ifdef __cplusplus
}
#endif

#endif	/* !_RPC_CLNT_STAT_H */
