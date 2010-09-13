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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<errno.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/param.h>
#include	<sys/priocntl.h>
#include	<sys/types.h>

#include	"dispadmin.h"

static char usage[] = "usage:	dispadmin -l\n";

int
main(int argc, char *argv[])
{
	int lflag = 0;
	int c;

	while ((c = getopt(argc, argv, "lc:")) != -1) {
		switch (c) {

		case 'l':
			lflag++;
			break;

		case 'c':
			if (strcmp(optarg, "SDC") != 0)
				fatalerr("error: %s executed for %s class, "
				    "%s is actually sub-command for %s class\n",
				    argv[0], optarg, argv[0], "SDC");

			fatalerr("error: no scheduling-class specific options"
			    " for SDC\n");
			break;

		case '?':
			fatalerr(usage);
		default:
			break;
		}
	}

	if (!lflag)
		fatalerr(usage);

	(void) printf("SDC\t(System Duty-Cycle Class)\n");
	return (0);
}
