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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clnt_perror.c
 */
#include <sys/types.h>
#include <sys/t_lock.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/inttypes.h>

/*
 * Return an ascii string which matches the RPC clnt stat passed in.
 */
const char *
clnt_sperrno(const enum clnt_stat stat)
{
	switch (stat) {
	case RPC_SUCCESS:
		return ("RPC: Success");
	case RPC_CANTENCODEARGS:
		return ("RPC: Can't encode arguments");
	case RPC_CANTDECODERES:
		return ("RPC: Can't decode result");
	case RPC_CANTSEND:
		return ("RPC: Unable to send");
	case RPC_CANTRECV:
		return ("RPC: Unable to receive");
	case RPC_TIMEDOUT:
		return ("RPC: Timed out");
	case RPC_INTR:
		return ("RPC: Interrupted");
	case RPC_UDERROR:
		return ("RPC: Unitdata error");
	case RPC_VERSMISMATCH:
		return ("RPC: Incompatible versions of RPC");
	case RPC_AUTHERROR:
		return ("RPC: Authentication error");
	case RPC_PROGUNAVAIL:
		return ("RPC: Program unavailable");
	case RPC_PROGVERSMISMATCH:
		return ("RPC: Program/version mismatch");
	case RPC_PROCUNAVAIL:
		return ("RPC: Procedure unavailable");
	case RPC_CANTDECODEARGS:
		return ("RPC: Server can't decode arguments");
	case RPC_SYSTEMERROR:
		return ("RPC: Remote system error");
	case RPC_UNKNOWNHOST:
		return ("RPC: Unknown host");
	case RPC_UNKNOWNPROTO:
		return ("RPC: Unknown protocol");
	case RPC_UNKNOWNADDR:
		return ("RPC: Remote address unknown");
	case RPC_NOBROADCAST:
		return ("RPC: Broadcasting not supported");
	case RPC_PMAPFAILURE:
		return ("RPC: Port mapper failure");
	case RPC_PROGNOTREGISTERED:
		return ("RPC: Program not registered");
	case RPC_N2AXLATEFAILURE:
		return ("RPC: Name to address translation failed");
	case RPC_TLIERROR:
		return ("RPC: TLI error");
	case RPC_FAILED:
		return ("RPC: Failed (unspecified error)");
	case RPC_INPROGRESS:
		return ("RPC: Operation in progress");
	case RPC_STALERACHANDLE:
		return ("RPC: Stale RAC handle");
	case RPC_CANTCONNECT:
		return ("RPC: Couldn't make connection");
	case RPC_XPRTFAILED:
		return ("RPC: Received disconnect from remote");
	case RPC_CANTCREATESTREAM:
		return ("RPC: Can't push RPC module");
	case RPC_CANTSTORE:
		return ("RPC: Can't store pending message");
	}
	return ("RPC: (unknown error code)");
}

/*
 * Return string reply error info. For use after clnt_call().
 * It allocates the  buffer of size MAXPATHLEN and assumes
 * caller's responsibility to free the memory after use.
 */
char *
clnt_sperror(const CLIENT *cl, const char *s)
{
	struct rpc_err e;
#ifdef notyet
	char *err;
#endif
	char *str;
	char *strstart;

	str = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	strstart = str;

	CLNT_GETERR((CLIENT *) cl, &e);

	(void) sprintf(str, "%s: ", s);
	str += strlen(str);

	(void) strcpy(str, clnt_sperrno(e.re_status));
	str += strlen(str);

	switch (e.re_status) {
	case RPC_SUCCESS:
	case RPC_CANTENCODEARGS:
	case RPC_CANTDECODERES:
	case RPC_TIMEDOUT:
	case RPC_PROGUNAVAIL:
	case RPC_PROCUNAVAIL:
	case RPC_CANTDECODEARGS:
	case RPC_SYSTEMERROR:
	case RPC_UNKNOWNHOST:
	case RPC_UNKNOWNPROTO:
	case RPC_UNKNOWNADDR:
	case RPC_NOBROADCAST:
	case RPC_RPCBFAILURE:
	case RPC_PROGNOTREGISTERED:
	case RPC_FAILED:
	case RPC_INPROGRESS:
		break;

#ifdef notyet
	case RPC_N2AXLATEFAILURE:
		(void) sprintf(str, "; %s", netdir_sperror());
		break;
#endif

	case RPC_TLIERROR:
#ifdef notyet
		(void) sprintf(str, "; %s", t_errlist[e.re_terrno]);
#else
		(void) sprintf(str, "; %d", e.re_terrno);
#endif
		str += strlen(str);
		if (e.re_errno) {
#ifdef notyet
			(void) sprintf(str, "; %s", strerror(e.re_errno));
#else
			(void) sprintf(str, "; %d", e.re_errno);
#endif
		}
		break;

	case RPC_CANTSEND:
	case RPC_CANTRECV:
		if (e.re_errno) {
#ifdef notyet
			(void) sprintf(str, "; errno = %s",
			    strerror(e.re_errno));
#else
			(void) sprintf(str, "; errno = %d", e.re_errno);
#endif
			str += strlen(str);
		}
		if (e.re_terrno) {
#ifdef notyet
			(void) sprintf(str, "; %s", t_errlist[e.re_terrno]);
#else
			(void) sprintf(str, "; %d", e.re_terrno);
#endif
		}
		break;

	case RPC_VERSMISMATCH:
		(void) sprintf(str,
		    "; low version = %" PRIu32 ", high version = %" PRIu32,
		    e.re_vers.low, e.re_vers.high);
		break;

#ifdef notyet
	case RPC_AUTHERROR:
		err = auth_errmsg(e.re_why);
		(void) sprintf(str, "; why = ");
		str += strlen(str);
		if (err != NULL) {
			(void) sprintf(str, "%s", err);
		} else {
			(void) sprintf(str,
			    "(unknown authentication error - %d)",
			    (int)e.re_why);
		}
		break;
#endif

	case RPC_PROGVERSMISMATCH:
		(void) sprintf(str,
		    "; low version = %" PRIu32 ", high version = %" PRIu32,
		    e.re_vers.low, e.re_vers.high);
		break;

	default:	/* unknown */
		(void) sprintf(str, "; s1 = %" PRIu32 ", s2 = %" PRIu32,
		    e.re_lb.s1, e.re_lb.s2);
		break;
	}
	return (strstart);
}
