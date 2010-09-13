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
 * Copyright (c) 1983-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acctctl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "lastcomm.h"

int
main(int argc, char *argv[])
{
	int res;
	int opt;
	char *filename = NULL;
	char buf[PATH_MAX];
	ea_file_t ef;
	int xflag = 0;

	while ((opt = getopt(argc, argv, "f:x")) != EOF) {
		switch (opt) {
		case 'f':
			filename = optarg;
			break;
		case 'x':
			xflag = 1;
			break;
		default:
			(void) fprintf(stderr,
			    gettext("Usage:\tlastcomm [-x] [-f filename]"
			    " [command] ... [user] ... [terminal] ...\n"));
			exit(2);
		}
	}

	if (xflag) {
		/*
		 * User wants to see extended accounting statistics.
		 */
		if (filename) {
			return (lc_exacct(filename, argc, argv, optind));
		} else {
			if (acctctl(AC_PROC | AC_FILE_GET, buf, PATH_MAX) < 0) {
				(void) fprintf(stderr, gettext("lastcomm: "
				    "cannot open extended accounting file: "
				    "%s\n"), strerror(errno));
				return (1);
			} else {
				return (lc_exacct(buf, argc, argv, optind));
			}
		}
	}
	if (filename == NULL) {
		/*
		 * If no option is specified, then first try to open current
		 * extended process accounting file and then old-style process
		 * accounting.
		 */
		if (acctctl(AC_PROC | AC_FILE_GET, buf, PATH_MAX) < 0)
			return (lc_pacct("/var/adm/pacct", argc, argv, optind));
		else
			return (lc_exacct(buf, argc, argv, optind));
	} else {
		/*
		 * If accounting file was specified and we don't know its
		 * format, then first try to open it as an extended accounting
		 * file and then as an old-style accounting file.
		 */
		if ((res = ea_open(&ef, filename, EXACCT_CREATOR,
		    EO_TAIL | EO_VALID_HDR, O_RDONLY, 0)) >= 0)
			(void) ea_close(&ef);

		if (res < 0)
			return (lc_pacct(filename, argc, argv, optind));
		else
			return (lc_exacct(filename, argc, argv, optind));
	}
}
