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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <locale.h>
#include <stdio.h>

#include "libfru.h"
#include "prtfru.h"


static void
usage(const char *command)
{
	(void) fprintf(stderr,
		gettext("Usage:  %s [ -d ] | [ -clx ] [ container ]\n"),
		command);
}

int
main(int argc, char *argv[])
{
	char  *command = argv[0], *searchpath = NULL;

	int   containers_only = 0, dtd = 0, list_only = 0, nodtd = 0, option,
		status, xml = 0;


	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;	/*  "getopt" should not print to "stderr"  */
	while ((option = getopt(argc, argv, "cdlx")) != EOF) {
		switch (option) {
		case 'c':
			containers_only = 1;
			nodtd = 1;
			break;
		case 'd':
			dtd = 1;
			break;
		case 'l':
			list_only = 1;
			nodtd = 1;
			break;
		case 'x':
			xml = 1;
			nodtd = 1;
			break;
		default:
			usage(command);
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (dtd) {
		if (nodtd || (argc > 0)) {
			usage(command);
			(void) fprintf(stderr,
			    gettext("Specify \"-d\" alone\n"));
			return (1);
		}

		return (output_dtd());
	}

	switch (argc) {
	case 0:
		break;
	case 1:
		searchpath = argv[0];
		if (!searchpath[0]) {
			usage(command);
			(void) fprintf(stderr,
			    gettext("\"container\" should not be empty\n"));
			return (1);
		}
		break;
	default:
		usage(command);
		return (1);
	}


	/*
	 * Select the data source and print all the data
	 */
	if ((status = fru_open_data_source("picl")) != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Error opening FRU ID data source:  %s\n"),
		    fru_strerror(status));
		return (1);
	}

	return (prtfru(searchpath, containers_only, list_only, xml));
}
