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
 * Copyright (c) 2018 Peter Tribble.
 * Copyright (c) 2014 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
#include "getent.h"

static const char *cmdname;

struct table {
	char	*name;			/* name of the table */
	int	(*func)(const char **);	/* function to do the lookup */
};

static struct table t[] = {
	{ "passwd",	dogetpw },
	{ "shadow",	dogetsp },
	{ "group",	dogetgr },
	{ "hosts",	dogethost },
	{ "ipnodes",	dogetipnodes },
	{ "services",	dogetserv },
	{ "protocols",	dogetproto },
	{ "ethers",	dogetethers },
	{ "networks",	dogetnet },
	{ "netmasks",	dogetnetmask },
	{ "project",	dogetproject },
	{ "auth_attr",	dogetauthattr },
	{ "exec_attr",	dogetexecattr },
	{ "prof_attr",	dogetprofattr },
	{ "user_attr",	dogetuserattr },
	{ NULL,		NULL }
};

static	void usage(void) __NORETURN;

int
main(int argc, const char **argv)
{
	struct table *p;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEXT"
#endif

	(void) textdomain(TEXT_DOMAIN);

	cmdname = argv[0];

	if (argc < 2)
		usage();

	for (p = t; p->name != NULL; p++) {
		if (strcmp(argv[1], p->name) == 0) {
			int rc;

			rc = (*p->func)(&argv[2]);
			switch (rc) {
			case EXC_SYNTAX:
				(void) fprintf(stderr,
				    gettext("Syntax error\n"));
				break;
			case EXC_ENUM_NOT_SUPPORTED:
				(void) fprintf(stderr,
	gettext("Enumeration not supported on %s\n"), argv[1]);
				break;
			case EXC_NAME_NOT_FOUND:
				break;
			}
			exit(rc);
		}
	}
	(void) fprintf(stderr, gettext("Unknown database: %s\n"), argv[1]);
	usage();
	/* NOTREACHED */
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s database [ key ... ]\n"), cmdname);
	exit(EXC_SYNTAX);
}
