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
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clnt_perror.c
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#ifndef KERNEL
#include <stdio.h>
#include <libintl.h>
#include <string.h>
#endif

#include <rpc/types.h>
#include <rpc/trace.h>
#include <rpc/auth.h>
#include <sys/tiuser.h>
#include <rpc/clnt.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

extern char *netdir_sperror();

const char __nsl_dom[]  = "SUNW_OST_NETRPC";

#ifndef KERNEL

#define	ERRBUFSZ	512

static char *
__buf()
{
	char *buf;
	static char buf_main[ERRBUFSZ];
	static pthread_key_t perror_key;

	trace1(TR___buf, 0);
	buf = thr_main()? buf_main :
		thr_get_storage(&perror_key, ERRBUFSZ, free);
	if (buf == NULL)
		syslog(LOG_WARNING,
		"clnt_sperror: malloc failed when trying to create buffer\n");
	trace1(TR___buf, 1);
	return (buf);
}

static char *
auth_errmsg(stat)
	enum auth_stat stat;
{
	trace1(TR_auth_errmsg, 0);
	switch (stat) {
	case AUTH_OK:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Authentication OK"));
	case AUTH_BADCRED:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Invalid client credential"));
	case AUTH_REJECTEDCRED:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Server rejected credential"));
	case AUTH_BADVERF:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Invalid client verifier"));
	case AUTH_REJECTEDVERF:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Server rejected verifier"));
	case AUTH_TOOWEAK:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Client credential too weak"));
	case AUTH_INVALIDRESP:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Invalid server verifier"));
	case AUTH_FAILED:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Failed (unspecified error)"));

	/* kerberos specific */
	case AUTH_DECODE:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Could not decode authenticator"));
	case AUTH_TIMEEXPIRE:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Time of credential expired"));
	case AUTH_TKT_FILE:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom,
			"Something wrong with kerberos ticket file"));
	case AUTH_NET_ADDR:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom,
		"Incorrect network address in kerberos ticket"));
	case AUTH_KERB_GENERIC:
		trace1(TR_auth_errmsg, 1);
		return (dgettext(__nsl_dom, "Kerberos generic error"));
	}
	trace1(TR_auth_errmsg, 1);
	return (dgettext(__nsl_dom, "Unknown authentication error"));
}

/*
 * Return string reply error info. For use after clnt_call()
 */

#define	REMAINDER	(ERRBUFSZ - (str - strstart))

char *
clnt_sperror(cl, s)
	const CLIENT *cl;
	const char *s;
{
	struct rpc_err e;
	char *err;
	char *str = __buf();
	char *strstart = str;

	trace2(TR_clnt_sperror, 0, cl);
	if (str == NULL) {
		trace2(TR_clnt_sperror, 1, cl);
		return (NULL);
	}
	CLNT_GETERR((CLIENT *) cl, &e);

	(void) snprintf(str, ERRBUFSZ, "%s: ", s);
	str += strlcat(str, clnt_sperrno(e.re_status), ERRBUFSZ);

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
		break;

	case RPC_N2AXLATEFAILURE:
		(void) snprintf(str, REMAINDER, "; %s", netdir_sperror());
		str += strlen(str);
		break;

	case RPC_TLIERROR:
		(void) snprintf(str, REMAINDER, "; %s", t_errlist[e.re_terrno]);
		str += strlen(str);
		if (e.re_errno) {
			(void) snprintf(str, REMAINDER,
			    "; %s", strerror(e.re_errno));
			str += strlen(str);
		}
		break;

	case RPC_CANTSTORE:
	case RPC_CANTSEND:
	case RPC_CANTRECV:
		if (e.re_errno) {
			(void) snprintf(str, REMAINDER, "; errno = %s",
					strerror(e.re_errno));
			str += strlen(str);
		}
		if (e.re_terrno) {
			(void) snprintf(str, REMAINDER,
				"; %s", t_errlist[e.re_terrno]);
			str += strlen(str);
		}
		break;

	case RPC_VERSMISMATCH:
		(void) snprintf(str, REMAINDER,
				"; low version = %lu, high version = %lu",
				e.re_vers.low, e.re_vers.high);
		str += strlen(str);
		break;

	case RPC_AUTHERROR:
		err = auth_errmsg(e.re_why);
		(void) snprintf(str, REMAINDER, "; why = ");
		str += strlen(str);
		if (err != NULL) {
			(void) snprintf(str, REMAINDER, "%s", err);
		} else {
			(void) snprintf(str, REMAINDER,
				"(unknown authentication error - %d)",
				(int)e.re_why);
		}
		str += strlen(str);
		break;

	case RPC_PROGVERSMISMATCH:
		(void) snprintf(str, REMAINDER,
				"; low version = %lu, high version = %lu",
				e.re_vers.low, e.re_vers.high);
		str += strlen(str);
		break;

	default:	/* unknown */
		(void) snprintf(str, REMAINDER, "; s1 = %lu, s2 = %lu",
				e.re_lb.s1, e.re_lb.s2);
		str += strlen(str);
		break;
	}
	trace2(TR_clnt_sperror, 1, cl);
	return (strstart);
}
#undef	REMAINDER

void
clnt_perror(cl, s)
	const CLIENT *cl;
	const char *s;
{
	trace2(TR_clnt_perror, 0, cl);
	(void) fprintf(stderr, "%s\n", clnt_sperror(cl, s));
	trace2(TR_clnt_perror, 1, cl);
}

void
clnt_perrno(num)
	enum clnt_stat num;
{
	trace1(TR_clnt_perrno, 0);
	(void) fprintf(stderr, "%s\n", clnt_sperrno(num));
	trace1(TR_clnt_perrno, 1);
}

/*
 * Why a client handle could not be created
 */
char *
clnt_spcreateerror(s)
	const char *s;
{
	char *errstr;
	char *str = __buf();

	trace1(TR_clnt_spcreateerror, 0);
	if (str == NULL) {
		trace1(TR_clnt_spcreateerror, 1);
		return (NULL);
	}
	(void) snprintf(str, ERRBUFSZ, "%s: ", s);
	(void) strlcat(str, clnt_sperrno(rpc_createerr.cf_stat), ERRBUFSZ);

	switch (rpc_createerr.cf_stat) {
	case RPC_N2AXLATEFAILURE:
		(void) strlcat(str, " - ", ERRBUFSZ);
		(void) strlcat(str, netdir_sperror(), ERRBUFSZ);
		break;

	case RPC_RPCBFAILURE:
		(void) strlcat(str, " - ", ERRBUFSZ);
		(void) strlcat(str,
			clnt_sperrno(rpc_createerr.cf_error.re_status),
			ERRBUFSZ);
		break;

	case RPC_SYSTEMERROR:
		(void) strlcat(str, " - ", ERRBUFSZ);
		errstr = strerror(rpc_createerr.cf_error.re_errno);
		if (errstr != NULL)
			(void) strlcat(str, errstr, ERRBUFSZ);
		else
			(void) snprintf(&str[strlen(str)],
			    ERRBUFSZ - strlen(str), "Error %d",
			    rpc_createerr.cf_error.re_errno);
		break;

	case RPC_TLIERROR:
		(void) strlcat(str, " - ", ERRBUFSZ);
		if ((rpc_createerr.cf_error.re_terrno > 0) &&
			(rpc_createerr.cf_error.re_terrno < t_nerr)) {
			(void) strlcat(str,
				t_errlist[rpc_createerr.cf_error.re_terrno],
				ERRBUFSZ);
			if (rpc_createerr.cf_error.re_terrno == TSYSERR) {
				char *err;
				err = strerror(rpc_createerr.cf_error.re_errno);
				if (err) {
					strlcat(str, " (", ERRBUFSZ);
					strlcat(str, err, ERRBUFSZ);
					strlcat(str, ")", ERRBUFSZ);
				}
			}
		} else {
			(void) snprintf(&str[strlen(str)],
			    ERRBUFSZ - strlen(str),
			    dgettext(__nsl_dom,  "TLI Error %d"),
			    rpc_createerr.cf_error.re_terrno);
		}
		errstr = strerror(rpc_createerr.cf_error.re_errno);
		if (errstr != NULL)
			(void) strlcat(str, errstr, ERRBUFSZ);
		else
			(void) snprintf(&str[strlen(str)],
			    ERRBUFSZ - strlen(str), "Error %d",
			    rpc_createerr.cf_error.re_errno);
		break;

	case RPC_AUTHERROR:
		(void) strlcat(str, " - ", ERRBUFSZ);
		(void) strlcat(str,
			auth_errmsg(rpc_createerr.cf_error.re_why), ERRBUFSZ);
		break;
	}
	trace1(TR_clnt_spcreateerror, 1);
	return (str);
}

void
clnt_pcreateerror(s)
	const char *s;
{
	trace1(TR_clnt_pcreateerror, 0);
	(void) fprintf(stderr, "%s\n", clnt_spcreateerror(s));
	trace1(TR_clnt_pcreateerror, 1);
}
#endif /* ! KERNEL */

/*
 * This interface for use by rpc_call() and rpc_broadcast()
 */
const char *
clnt_sperrno(stat)
	const enum clnt_stat stat;
{
	trace1(TR_clnt_sperrno, 0);
	switch (stat) {
	case RPC_SUCCESS:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Success"));
	case RPC_CANTENCODEARGS:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Can't encode arguments"));
	case RPC_CANTDECODERES:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Can't decode result"));
	case RPC_CANTSTORE:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Can't store request"));
	case RPC_CANTSEND:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Unable to send"));
	case RPC_CANTRECV:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Unable to receive"));
	case RPC_TIMEDOUT:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Timed out"));
	case RPC_VERSMISMATCH:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom,
			"RPC: Incompatible versions of RPC"));
	case RPC_AUTHERROR:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Authentication error"));
	case RPC_PROGUNAVAIL:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Program unavailable"));
	case RPC_PROGVERSMISMATCH:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Program/version mismatch"));
	case RPC_PROCUNAVAIL:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Procedure unavailable"));
	case RPC_CANTDECODEARGS:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom,
			"RPC: Server can't decode arguments"));

	case RPC_SYSTEMERROR:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Remote system error"));
	case RPC_UNKNOWNHOST:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Unknown host"));
	case RPC_UNKNOWNPROTO:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Unknown protocol"));
	case RPC_RPCBFAILURE:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Rpcbind failure"));
	case RPC_N2AXLATEFAILURE:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom,
			"RPC: Name to address translation failed"));
	case RPC_NOBROADCAST:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Broadcast not supported"));
	case RPC_PROGNOTREGISTERED:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Program not registered"));
	case RPC_UNKNOWNADDR:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom,
			"RPC: Remote server address unknown"));
	case RPC_TLIERROR:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Miscellaneous tli error"));
	case RPC_FAILED:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Failed (unspecified error)"));
	case RPC_INPROGRESS:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: RAC call in progress"));
	case RPC_STALERACHANDLE:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Stale RAC handle"));
	case RPC_CANTCONNECT:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Couldn't make connection"));
	case RPC_XPRTFAILED:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom,
			"RPC: Received disconnect from remote"));
	case RPC_CANTCREATESTREAM:
		trace1(TR_clnt_sperrno, 1);
		return (dgettext(__nsl_dom, "RPC: Can't push RPC module"));
	}
	trace1(TR_clnt_sperrno, 1);
	return (dgettext(__nsl_dom, "RPC: (unknown error code)"));
}
