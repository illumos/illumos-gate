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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <nss_dbdefs.h>

static int str2bootent(const char *, int, void *, char *, int);

static DEFINE_NSS_DB_ROOT(db_root);

static void
_nss_initf_bootparams(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_BOOTPARAMS;
	p->default_config = NSS_DEFCONF_BOOTPARAMS;
}

int
bootparams_getbyname(
    char *name,	/* lookup key */
    char *linebuf,	/* buffer to put the answer in */
    int linelen	/* max # of bytes to put into linebuf */
)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, linebuf, linebuf, linelen, str2bootent);
	arg.key.name = name;
	res = nss_search(&db_root, _nss_initf_bootparams,
			NSS_DBOP_BOOTPARAMS_BYNAME, &arg);
	(void) NSS_XbyY_FINI(&arg);
	return (arg.status = res);
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a buffer in the caller's space.
 * instring and buffer should be separate areas.
 * The calling routine does all the real parsing; we just check limits and
 * store the entry in the buffer we were passed by the caller.
 * NOTE: we expect the data we're passed (in instr) has had the host's name
 * stripped off the begining.
 */
/* ARGSUSED */
static int
str2bootent(
    const char *instr,
    int lenstr,
    void *ent,		/* really (char *) */
    char *buffer,
    int buflen
)
{
	const char	*p, *limit;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer)) {
		return (NSS_STR_PARSE_PARSE);
	}
	p = instr;
	limit = p + lenstr;

	/* Skip over leading whitespace */
	while (p < limit && isspace(*p)) {
		p++;
	}
	if (p >= limit) {
		/* Syntax error -- no data! */
		return (NSS_STR_PARSE_PARSE);
	}
	lenstr -= (p - instr);
	if (buflen <= lenstr) {		/* not enough buffer */
		return (NSS_STR_PARSE_ERANGE);
	}
	(void) memcpy(buffer, p, lenstr);
	buffer[lenstr] = '\0';

	return (NSS_STR_PARSE_SUCCESS);
}
