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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <sys/types.h>
#include <nss_dbdefs.h>
#include <string.h>
#include <auth_attr.h>


/* externs from parse.c */
extern char *_strtok_escape(char *, char *, char **);

static int authattr_stayopen = 0;
/*
 * Unsynchronized, but it affects only
 * efficiency, not correctness
 */

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

void
_nss_initf_authattr(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_AUTHATTR;
	p->default_config = NSS_DEFCONF_AUTHATTR;
}


/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
int
str2authattr(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	char		*last = NULL;
	char		*sep = KV_TOKEN_DELIMIT;
	authstr_t	*auth = (authstr_t *)ent;

	if (lenstr >= buflen)
		return (NSS_STR_PARSE_ERANGE);

	if (instr != buffer)
		(void) strncpy(buffer, instr, buflen);

	/*
	 * Remove newline that nis (yp_match) puts at the
	 * end of the entry it retrieves from the map.
	 */
	if (buffer[lenstr] == '\n')
		buffer[lenstr] = '\0';

	/* quick exit do not entry fill if not needed */
	if (ent == (void *)NULL)
		return (NSS_STR_PARSE_SUCCESS);

	auth->name = _strtok_escape(buffer, sep, &last);
	auth->res1 = _strtok_escape(NULL, sep, &last);
	auth->res2 = _strtok_escape(NULL, sep, &last);
	auth->short_desc = _strtok_escape(NULL, sep, &last);
	auth->long_desc = _strtok_escape(NULL, sep, &last);
	auth->attr = _strtok_escape(NULL, sep, &last);

	return (0);
}


void
_setauthattr(void)
{
	authattr_stayopen = 0;
	nss_setent(&db_root, _nss_initf_authattr, &context);
}


void
_endauthattr(void)
{
	authattr_stayopen = 0;
	nss_endent(&db_root, _nss_initf_authattr, &context);
	nss_delete(&db_root);
}


authstr_t *
_getauthattr(authstr_t *result, char *buffer, int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2authattr);
	res = nss_getent(&db_root, _nss_initf_authattr, &context, &arg);
	arg.status = res;
	*h_errnop = arg.h_errno;
	return ((authstr_t *)NSS_XbyY_FINI(&arg));
}


authstr_t *
_getauthnam(const char *name, authstr_t *result, char *buffer, int buflen,
    int *errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t    res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2authattr);
	arg.key.name = name;
	arg.stayopen = authattr_stayopen;
	res = nss_search(&db_root, _nss_initf_authattr,
	    NSS_DBOP_AUTHATTR_BYNAME, &arg);
	arg.status = res;
	*errnop = arg.h_errno;
	return ((authstr_t *)NSS_XbyY_FINI(&arg));
}
