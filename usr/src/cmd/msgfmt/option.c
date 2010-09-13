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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "common.h"

int
parse_option(int *pargc, char ***pargv, struct flags *flag)
{
	char	c;
	char	*arg;
	int	argc = *pargc;
	char	**argv = *pargv;

	argv++;
	while (--argc > 1) {
		arg = *argv;
		if (*arg == '-') {
			if (!*(arg + 1)) {
				/* not an option */
				break;
			}
loop:
			if ((c = *++arg) == '\0') {
				/* next argument */
				argv++;
				continue;
			} else if (c != '-') {
				/* Sun option */
				switch (c) {
				case 'D':
					/*
					 * add directory to list for input
					 * files search.
					 */
					if (*(arg + 1)) {
						/*
						 * no spaces between -D and
						 * optarg
						 */
						flag->idir = ++arg;
						argv++;
						continue;
					}
					if (--argc > 1) {
						if (!flag->idir)
							flag->idir = *++argv;
						else
							++argv;
						argv++;
						continue;
					}
					/* not enough args */
					return (-1);
					/* NOTREACHED */
				case 'f':
					/*
					 * Use fuzzy entry
					 */
					flag->fuzzy = 1;
					goto loop;
					/* NOTREACHED */
				case 'o':
					/*
					 * Specify output file name
					 */
					if (*(arg + 1)) {
						/*
						 * no spaces between -o and
						 * optarg
						 */
						flag->ofile = ++arg;
						argv++;
						continue;
					}
					if (--argc > 1) {
						flag->ofile = *++argv;
						argv++;
						continue;
					}
					/* not enough args */
					return (-1);
				case 'g':
					/*
					 * GNU mode
					 */
					flag->gnu_p = 1;
					goto loop;
				case 's':
					/*
					 * Sun mode
					 */
					flag->sun_p = 1;
					goto loop;
				case 'v':
					/*
					 * verbose mode
					 */
					flag->verbose = 1;
					goto loop;
				default:
					/* illegal option */
					return (-1);
				}
				/* NOTREACHED */
			}

			if (*(arg + 1) == '\0') {
				/* option end */
				argv++;
				argc--;
				break;
			}

			/* GNU options */
			arg++;
			if (strncmp(arg, "directory=", 10) == 0) {
				/*
				 * add directory to list for input
				 * files search.
				 */
				if (flag->idir) {
					/*
					 * inputdir has already been specified
					 */
					argv++;
					continue;
				}
				arg += 10;
				if (*arg == '\0') {
					/* illegal option */
					return (-1);
				}
				flag->idir = arg;
				argv++;
				continue;
			}
			if (strcmp(arg, "use-fuzzy") == 0) {
				/*
				 * Use fuzzy entry
				 */
				flag->fuzzy = 1;
				argv++;
				continue;
			}
			if (strncmp(arg, "output-file=", 12) == 0) {
				/*
				 * Specify output file name
				 */
				arg += 12;
				if (*arg == '\0') {
					/* illegal option */
					return (-1);
				}
				flag->ofile = arg;
				argv++;
				continue;
			}
			if (strcmp(arg, "strict") == 0) {
				/*
				 * strict mode
				 */
				flag->strict = 1;
				argv++;
				continue;
			}
			if (strcmp(arg, "verbose") == 0) {
				/*
				 * verbose mode
				 */
				flag->verbose = 1;
				argv++;
				continue;
			}
			/* illegal option */
			return (-1);
		}
		break;
	}

	if (argc == 0)
		return (-1);

	*pargc = argc;
	*pargv = argv;
	return (0);
}
