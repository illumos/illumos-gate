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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <nss_dbdefs.h>
#include <syslog.h>
#include <ns.h>

#ifndef	NSS_DBNAM__PRINTERS	/* not in nss_dbdefs.h because it's private */
#define	NSS_DBNAM__PRINTERS	"_printers"
#endif

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

static int printers_stayopen;
static char *private_ns = NULL;

static void
_nss_initf_printers(p)
    nss_db_params_t *p;
{
	if (private_ns != NULL) {
		/*
		 * because we need to support a legacy interface that allows
		 * us to select a specific name service, we need to dummy up
		 * the parameters to use a private nsswitch database and set
		 * the * default_config entry to the name service we are
		 * looking into.
		 */
		p->name = NSS_DBNAM__PRINTERS;		/* "_printers" */
		p->default_config = normalize_ns_name(private_ns);
	} else {
		/* regular behaviour */
		p->name = NSS_DBNAM_PRINTERS;	 /* "printers" */
		p->default_config = NSS_DEFCONF_PRINTERS;
	}
	syslog(LOG_DEBUG, "database: %s, default: %s",
		(p->name ? p->name : "NULL"),
		(p->default_config ? p->default_config : "NULL"));
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
/* ARGSUSED */
static int
str2printer(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	if (lenstr + 1 > buflen)
		return (NSS_STR_PARSE_ERANGE);

	/* skip entries that begin with '#' */
	if (instr[0] == '#')
		return (NSS_STR_PARSE_PARSE);

	/*
	 * We copy the input string into the output buffer
	 */
	(void) memcpy(buffer, instr, lenstr);
	buffer[lenstr] = '\0';

	return (NSS_STR_PARSE_SUCCESS);
}


int
setprinterentry(int stayopen, char *ns)
{
	printers_stayopen |= stayopen;
	private_ns = ns;
	nss_setent(&db_root, _nss_initf_printers, &context);
	private_ns = NULL;
	return (0);
}


int
endprinterentry()
{
	printers_stayopen = 0;
	nss_endent(&db_root, _nss_initf_printers, &context);
	nss_delete(&db_root);
	private_ns = NULL;
	return (0);
}


/* ARGSUSED2 */
int
getprinterentry(char *linebuf, int linelen, char *ns)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	private_ns = ns;
	NSS_XbyY_INIT(&arg, linebuf, linebuf, linelen, str2printer);
	res = nss_getent(&db_root, _nss_initf_printers, &context, &arg);
	(void) NSS_XbyY_FINI(&arg);
	private_ns = NULL;

	return (arg.status = res);
}


int
getprinterbyname(char *name, char *linebuf, int linelen, char *ns)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	private_ns = ns;
	NSS_XbyY_INIT(&arg, linebuf, linebuf, linelen, str2printer);
	arg.key.name = name;
	res = nss_search(&db_root, _nss_initf_printers,
			NSS_DBOP_PRINTERS_BYNAME, &arg);
	(void) NSS_XbyY_FINI(&arg);
	private_ns = NULL;

	return (arg.status = res);
}
