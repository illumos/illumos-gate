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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <stdio.h>
#include <libintl.h>
#include <string.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <sys/tiuser.h>
#include <rpc/clnt.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

extern char *netdir_sperror();

const char __nsl_dom[]  = "SUNW_OST_NETRPC";

#define	ERRBUFSZ	512

static char *
__buf(void)
{
	char *buf;
	static char buf_main[ERRBUFSZ];
	static pthread_key_t perror_key = PTHREAD_ONCE_KEY_NP;

	buf = thr_main()? buf_main :
		thr_get_storage(&perror_key, ERRBUFSZ, free);
	if (buf == NULL)
		syslog(LOG_WARNING,
		"clnt_sperror: malloc failed when trying to create buffer\n");
	return (buf);
}

static char *
auth_errmsg(enum auth_stat stat)
{
	switch (stat) {
	case AUTH_OK:
		return (dgettext(__nsl_dom, "Authentication OK"));
	case AUTH_BADCRED:
		return (dgettext(__nsl_dom, "Invalid client credential"));
	case AUTH_REJECTEDCRED:
		return (dgettext(__nsl_dom, "Server rejected credential"));
	case AUTH_BADVERF:
		return (dgettext(__nsl_dom, "Invalid client verifier"));
	case AUTH_REJECTEDVERF:
		return (dgettext(__nsl_dom, "Server rejected verifier"));
	case AUTH_TOOWEAK:
		return (dgettext(__nsl_dom, "Client credential too weak"));
	case AUTH_INVALIDRESP:
		return (dgettext(__nsl_dom, "Invalid server verifier"));
	case AUTH_FAILED:
		return (dgettext(__nsl_dom, "Failed (unspecified error)"));

	/* kerberos specific */
	case AUTH_DECODE:
		return (dgettext(__nsl_dom, "Could not decode authenticator"));
	case AUTH_TIMEEXPIRE:
		return (dgettext(__nsl_dom, "Time of credential expired"));
	case AUTH_TKT_FILE:
		return (dgettext(__nsl_dom,
			"Something wrong with kerberos ticket file"));
	case AUTH_NET_ADDR:
		return (dgettext(__nsl_dom,
		"Incorrect network address in kerberos ticket"));
	case AUTH_KERB_GENERIC:
		return (dgettext(__nsl_dom, "Kerberos generic error"));
	}
	return (dgettext(__nsl_dom, "Unknown authentication error"));
}

/*
 * Return string reply error info. For use after clnt_call()
 */

#define	REMAINDER	(ERRBUFSZ - (str - strstart))

char *
clnt_sperror(const CLIENT *cl, const char *s)
{
	struct rpc_err e;
	char *err;
	char *str = __buf();
	char *strstart = str;

	if (str == NULL)
		return (NULL);
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
	return (strstart);
}
#undef	REMAINDER

void
clnt_perror(const CLIENT *cl, const char *s)
{
	(void) fprintf(stderr, "%s\n", clnt_sperror(cl, s));
}

void
clnt_perrno(const enum clnt_stat num)
{
	(void) fprintf(stderr, "%s\n", clnt_sperrno(num));
}

/*
 * Why a client handle could not be created
 */
char *
clnt_spcreateerror(const char *s)
{
	char *errstr;
	char *str = __buf();

	if (str == NULL)
		return (NULL);
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
					(void) strlcat(str, " (", ERRBUFSZ);
					(void) strlcat(str, err, ERRBUFSZ);
					(void) strlcat(str, ")", ERRBUFSZ);
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
	return (str);
}

void
clnt_pcreateerror(const char *s)
{
	(void) fprintf(stderr, "%s\n", clnt_spcreateerror(s));
}

/*
 * This interface for use by rpc_call() and rpc_broadcast()
 */
const char *
clnt_sperrno(const enum clnt_stat stat)
{
	switch (stat) {
	case RPC_SUCCESS:
		return (dgettext(__nsl_dom, "RPC: Success"));
	case RPC_CANTENCODEARGS:
		return (dgettext(__nsl_dom, "RPC: Can't encode arguments"));
	case RPC_CANTDECODERES:
		return (dgettext(__nsl_dom, "RPC: Can't decode result"));
	case RPC_CANTSTORE:
		return (dgettext(__nsl_dom, "RPC: Can't store request"));
	case RPC_CANTSEND:
		return (dgettext(__nsl_dom, "RPC: Unable to send"));
	case RPC_CANTRECV:
		return (dgettext(__nsl_dom, "RPC: Unable to receive"));
	case RPC_TIMEDOUT:
		return (dgettext(__nsl_dom, "RPC: Timed out"));
	case RPC_VERSMISMATCH:
		return (dgettext(__nsl_dom,
			"RPC: Incompatible versions of RPC"));
	case RPC_AUTHERROR:
		return (dgettext(__nsl_dom, "RPC: Authentication error"));
	case RPC_PROGUNAVAIL:
		return (dgettext(__nsl_dom, "RPC: Program unavailable"));
	case RPC_PROGVERSMISMATCH:
		return (dgettext(__nsl_dom, "RPC: Program/version mismatch"));
	case RPC_PROCUNAVAIL:
		return (dgettext(__nsl_dom, "RPC: Procedure unavailable"));
	case RPC_CANTDECODEARGS:
		return (dgettext(__nsl_dom,
			"RPC: Server can't decode arguments"));

	case RPC_SYSTEMERROR:
		return (dgettext(__nsl_dom, "RPC: Remote system error"));
	case RPC_UNKNOWNHOST:
		return (dgettext(__nsl_dom, "RPC: Unknown host"));
	case RPC_UNKNOWNPROTO:
		return (dgettext(__nsl_dom, "RPC: Unknown protocol"));
	case RPC_RPCBFAILURE:
		return (dgettext(__nsl_dom, "RPC: Rpcbind failure"));
	case RPC_N2AXLATEFAILURE:
		return (dgettext(__nsl_dom,
			"RPC: Name to address translation failed"));
	case RPC_NOBROADCAST:
		return (dgettext(__nsl_dom, "RPC: Broadcast not supported"));
	case RPC_PROGNOTREGISTERED:
		return (dgettext(__nsl_dom, "RPC: Program not registered"));
	case RPC_UNKNOWNADDR:
		return (dgettext(__nsl_dom,
			"RPC: Remote server address unknown"));
	case RPC_TLIERROR:
		return (dgettext(__nsl_dom, "RPC: Miscellaneous tli error"));
	case RPC_FAILED:
		return (dgettext(__nsl_dom, "RPC: Failed (unspecified error)"));
	case RPC_INPROGRESS:
		return (dgettext(__nsl_dom, "RPC: RAC call in progress"));
	case RPC_STALERACHANDLE:
		return (dgettext(__nsl_dom, "RPC: Stale RAC handle"));
	case RPC_CANTCONNECT:
		return (dgettext(__nsl_dom, "RPC: Couldn't make connection"));
	case RPC_XPRTFAILED:
		return (dgettext(__nsl_dom,
			"RPC: Received disconnect from remote"));
	case RPC_CANTCREATESTREAM:
		return (dgettext(__nsl_dom, "RPC: Can't push RPC module"));
	}
	return (dgettext(__nsl_dom, "RPC: (unknown error code)"));
}
