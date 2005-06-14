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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <deflt.h>
#include <locale.h>
#include <libintl.h>
#include "packer.h"

char options[] = "s:d:";

char *pname;

void
fatal(char *msg)
{
	(void) fprintf(stderr, "%s: Fatal error: %s. Database not remade.\n",
	    pname, msg);
	exit(-1);
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: %s [-s dict1,...,dictn ] [-d dest-path ]\n", pname);
	exit(-1);
}

int
main(int argc, char *argv[])
{
	char   *default_dbdst = NULL;
	char   *default_dbsrc = NULL;
	char   *p;

	char   *dbdst = NULL;
	char   *dbsrc = NULL;
	size_t dbsrc_len = 0;
	int    c;
	int    result;

	(void) setlocale(LC_ALL, "");

	if ((pname = strrchr(argv[0], '/')) == NULL)
		pname = argv[0];
	else
		pname++;

	if (defopen(PWADMIN) == 0) {
		if ((p = defread("DICTIONLIST=")) != NULL)
			default_dbsrc = strdup(p);
		if ((p = defread("DICTIONDBDIR=")) != NULL)
			default_dbdst = strdup(p);
		(void) defopen(NULL);
	}

	if (default_dbdst == NULL)
		default_dbdst = CRACK_DIR;

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 's':
			if (dbsrc != NULL) {
				dbsrc_len += strlen(optarg) + 2; /* ',' + \0 */
				if ((dbsrc = realloc(dbsrc, dbsrc_len)) == NULL)
					fatal(strerror(errno));
				(void) strlcat(dbsrc, ",", dbsrc_len);
				(void) strlcat(dbsrc, optarg, dbsrc_len);
			} else {
				if ((dbsrc = strdup(optarg)) == NULL)
					fatal(strerror(errno));
				dbsrc_len = strlen(optarg) + 1;
			}
			break;
		case 'd':
			dbdst = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	if (optind != argc)
		usage();

	if (dbdst == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: using default database location: %s.\n"),
		    pname, default_dbdst);
		dbdst = default_dbdst;
	}

	if (dbsrc == NULL)
		if ((dbsrc = default_dbsrc) == NULL)
			fatal(gettext("No source databases defined"));
		else
			(void) fprintf(stderr,
			    gettext("%s: using default dictionary list: %s.\n"),
			    pname, default_dbsrc);

	if ((result = lock_db(dbdst)) == 0) {
		PWRemove(dbdst);
		result = build_dict_database(dbsrc, dbdst);
		unlock_db();
	}
	if (result != 0)
		fatal(strerror(errno));
	return (0);
}
