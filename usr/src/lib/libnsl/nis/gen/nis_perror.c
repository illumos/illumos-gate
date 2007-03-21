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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sccsid[] = "@(#)nis_perror.c 1.11 91/03/14 Copyr 1990 Sun Micro";
 *
 * nis_perror.c
 *
 * This module returns a string based on the NIS status that is passed.
 */

#include "mt.h"
#include <stdio.h>
#include <syslog.h>
#include <malloc.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include "nis_local.h"


char *
nis_sperrno(nis_error stat)
{
	char	*res;

	switch (stat) {
		case NIS_SUCCESS :
			res = "Success";
			break;
		case NIS_S_SUCCESS :
			res = "Probable success";
			break;
		case NIS_NOTFOUND :
			res = "Not found";
			break;
		case NIS_S_NOTFOUND :
			res = "Probably not found";
			break;
		case NIS_CACHEEXPIRED :
			res = "Cache expired";
			break;
		case NIS_NAMEUNREACHABLE :
			res = "NIS+ servers unreachable";
			break;
		case NIS_UNKNOWNOBJ :
			res = "Unknown object";
			break;
		case NIS_TRYAGAIN :
			res = "Server busy, try again";
			break;
		case NIS_SYSTEMERROR :
			res = "Generic system error";
			break;
		case NIS_CHAINBROKEN :
			res = "First/Next chain broken";
			break;
		case NIS_PERMISSION :
			res = "Permission denied";
			break;
		case NIS_NOTOWNER :
			res = "Not owner";
			break;
		case NIS_NOT_ME :
			res = "Name not served by this server";
			break;
		case NIS_NOMEMORY :
			res = "Server out of memory";
			break;
		case NIS_NAMEEXISTS :
			res = "Object with same name exists";
			break;
		case NIS_NOTMASTER :
			res = "Not master server for this domain";
			break;
		case NIS_INVALIDOBJ :
			res = "Invalid object for operation";
			break;
		case NIS_BADNAME :
			res = "Malformed Name, or illegal name";
			break;
		case NIS_NOCALLBACK :
			res = "Unable to create callback";
			break;
		case NIS_CBRESULTS :
			res = "Results sent to callback proc";
			break;
		case NIS_NOSUCHNAME :
			res = "Not Found, no such name";
			break;
		case NIS_NOTUNIQUE :
			res = "Name/entry isn't unique";
			break;
		case NIS_IBMODERROR :
			res = "Modification failed";
			break;
		case NIS_NOSUCHTABLE :
			res = "Database for table does not exist";
			break;
		case NIS_TYPEMISMATCH :
			res = "Entry/Table type mismatch";
			break;
		case NIS_LINKNAMEERROR :
			res = "Link Points to illegal name";
			break;
		case NIS_PARTIAL :
			res = "Partial Success";
			break;
		case NIS_TOOMANYATTRS :
			res = "Too many attributes";
			break;
		case NIS_RPCERROR :
			res = "Error in RPC subsystem";
			break;
		case NIS_BADATTRIBUTE :
			res = "Missing or malformed attribute";
			break;
		case NIS_NOTSEARCHABLE :
			res = "Named object is not searchable";
			break;
		case NIS_CBERROR :
			res = "Error while talking to callback proc";
			break;
		case NIS_FOREIGNNS :
			res = "Non-NIS+ namespace encountered";
			break;
		case NIS_BADOBJECT :
			res = "Illegal object type for operation";
			break;
		case NIS_NOTSAMEOBJ :
			res = "Passed object is not the same object on server";
			break;
		case NIS_MODFAIL :
			res = "Modify operation failed";
			break;
		case NIS_BADREQUEST :
			res = "Query illegal for named table";
			break;
		case NIS_NOTEMPTY :
			res =
			"Attempt to remove a non-empty table or directory";
			break;
		case NIS_COLDSTART_ERR :
			res =
	    "Error in accessing NIS+ cold start file... is NIS+ installed?";
			break;
		case NIS_RESYNC :
			res = "Full resync required for directory";
			break;
		case NIS_FAIL :
			res = "NIS+ operation failed";
			break;
		case NIS_UNAVAIL :
			res = "NIS+ service is unavailable or not installed";
			break;
		case NIS_SRVAUTH :
			res = "Unable to authenticate NIS+ server";
			break;
		case NIS_CLNTAUTH :
			res = "Unable to authenticate NIS+ client";
			break;
		case NIS_NOFILESPACE :
			res = "No file space on server";
			break;
		case NIS_NOPROC :
			res = "Unable to create process on server";
			break;
		case NIS_DUMPLATER :
			res = "Master server busy, full dump rescheduled.";
			break;
		default :
			res = "?";
			break;
	}
	return (res);
}


void
nis_perror(nis_error stat, char *str)
{
	char	*err;

	err = nis_sperrno(stat);
	if (*err != '?')
		(void) fprintf(stderr, "%s: %s.\n", str, err);
	else
		(void) fprintf(stderr, "%s: unknown error %d\n", str, stat);
}


char *
do_cpy(char *s1, char *s2, int *n)
{
	while (*s2) {
		if ((*n) <= 0) break;
		*s1++ = *s2++;
		(*n)--;
	}
	*s1 = '\0';
	return (s1);
}


char *
nis_sperror_r(nis_error stat, char *str, char buf[], int len)
{
	char		*err;
	char 		*p;
	char		stat_str[20];

	len--; /* reserve 1 space for null terminator */
	p = do_cpy(buf, str, &len);
	p = do_cpy(p, ": ", &len);
	err = nis_sperrno(stat);
	if (*err != '?') {
		p = do_cpy(p, err, &len);
	} else {
		p = do_cpy(p, "unknown error ", &len);
		(void) sprintf(stat_str, "%d", stat);
		p = do_cpy(p, stat_str, &len);
	}
	p = do_cpy(p, ".", &len);
	return (buf);
}


char *
nis_sperror(nis_error stat, char *str)
{
	static 	pthread_key_t err_buf_key = PTHREAD_ONCE_KEY_NP;
	char 	*err_buf;
#define	ERR_BUF_SIZE 128
	static	char	err_buf_main[ERR_BUF_SIZE];

	if (thr_main())
		err_buf = err_buf_main;
	else {
		err_buf = thr_get_storage(&err_buf_key, ERR_BUF_SIZE, free);
		if (err_buf == NULL) {
			syslog(LOG_ERR, "nis_sperror: Client out of memory.");
			return ("");
		}
	}
	return (nis_sperror_r(stat, str, err_buf, ERR_BUF_SIZE));
}


void
nis_lerror(nis_error stat, char *str)
{
	char	*err;

	err = nis_sperrno(stat);
	if (*err != '?')
		syslog(LOG_ERR, "%s: %s.", str, err);
	else
		syslog(LOG_ERR, "%s: unknown error %d.", str, stat);
}
