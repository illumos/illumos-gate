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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <sys/types.h>
#include <nss_dbdefs.h>
#include <rpc/trace.h>
#include <string.h>
#include <prof_attr.h>

/* externs from parse.c */
extern char *_strtok_escape(char *, char *, char **);

static int profattr_stayopen;
/*
 * Unsynchronized, but it affects only
 * efficiency, not correctness
 */

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_profattr(nss_db_params_t *p)
{
	trace1(TR__nss_initf_profattr, 0);
	p->name    = NSS_DBNAM_PROFATTR;
	p->default_config = NSS_DEFCONF_PROFATTR;
	trace1(TR__nss_initf_profattr, 1);
}


/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
int
str2profattr(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	char		*last = (char *)NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	profstr_t	*prof = (profstr_t *)ent;

	trace3(TR_str2profattr, 0, lenstr, buflen);
	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer)) {
		trace3(TR_str2profattr, 1, lenstr, buflen);
		return (NSS_STR_PARSE_PARSE);
	}
	if (lenstr >= buflen) {
		trace3(TR_str2profattr, 1, lenstr, buflen);
		return (NSS_STR_PARSE_ERANGE);
	}
	strncpy(buffer, instr, buflen);
	/*
	 * Remove newline that nis (yp_match) puts at the
	 * end of the entry it retrieves from the map.
	 */
	if (buffer[lenstr] == '\n') {
		buffer[lenstr] = '\0';
	}

	prof->name = _strtok_escape(buffer, sep, &last);
	prof->res1 = _strtok_escape(NULL, sep, &last);
	prof->res2 = _strtok_escape(NULL, sep, &last);
	prof->desc = _strtok_escape(NULL, sep, &last);
	prof->attr = _strtok_escape(NULL, sep, &last);

	return (0);
}


void
_setprofattr(void)
{
	trace1(TR_setprofattr, 0);
	profattr_stayopen = 0;
	nss_setent(&db_root, _nss_initf_profattr, &context);
	trace1(TR_setprofattr, 0);
}


void
_endprofattr(void)
{
	trace1(TR_endprofattr, 0);
	profattr_stayopen = 0;
	nss_endent(&db_root, _nss_initf_profattr, &context);
	nss_delete(&db_root);
	trace1(TR_endprofattr, 0);
}


profstr_t *
_getprofattr(profstr_t *result, char *buffer, int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t    res;

	trace2(TR_getprofattr, 0, buflen);
	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2profattr);
	res = nss_getent(&db_root, _nss_initf_profattr, &context, &arg);
	arg.status = res;
	*h_errnop = arg.h_errno;
	trace2(TR_getprofattr, 1, buflen);
	return ((profstr_t *)NSS_XbyY_FINI(&arg));
}


profstr_t *
_getprofnam(const char *name, profstr_t *result, char *buffer, int buflen,
    int *errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t    res;

	trace2(TR_getprofnam, 0, buflen);
	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2profattr);
	arg.key.name = name;
	arg.stayopen = profattr_stayopen;
	res = nss_search(&db_root, _nss_initf_profattr,
	    NSS_DBOP_PROFATTR_BYNAME, &arg);
	arg.status = res;
	*errnop = arg.h_errno;
	trace2(TR_getprofnam, 1, buflen);
	return ((profstr_t *)NSS_XbyY_FINI(&arg));
}
