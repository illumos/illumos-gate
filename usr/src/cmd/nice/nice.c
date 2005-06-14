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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
**	nice
*/


#include	<stdio.h>
#include	<locale.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>


static void usage(void);

int
main(int argc, char *argv[])
{
	long	nicarg = 10;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


	if (argc < 2)
		usage();


	if (argv[1][0] == '-') {
		if (strcmp(argv[1], "--") == 0) {
			argv++;
			argc--;
		} else {
			register char	*p = argv[1];
			char	*nicarg_str;
			char 	*end_ptr;

			if (*++p == 'n') {	/* -n55 new form, XCU4 */
				/*
				 * for situations like -n-10
				 * else case assigns p instead of argv
				 */
				if (!(*++p)) {
					/* Next arg is priority */
					argv++;
					argc--;
					if (argc < 2)
						usage();
					nicarg_str = argv[1];
				} else {
					/* Priority embedded eg. -n-10 */
					nicarg_str = p;
				}
			} else {	/* -55 obs form, XCU4 */
				nicarg_str = &argv[1][1];
			}
			nicarg = strtol(nicarg_str, &end_ptr, 10);
			if (*end_ptr) {
				(void) fprintf(stderr,
				gettext("nice: argument must be numeric.\n"));
				usage();
			}

			if( --argc < 2 )
				usage();

			argv++;
			if (strcmp(argv[1], "--") == 0) {
				argv++;
				argc--;
			}
		}
	}

	if (argc < 2)
		usage();

	errno = 0;
	if (nice(nicarg) == -1) {
		/*
		 * Could be an error or a legitimate return value.
		 * The only error we care about is EINVAL, which will
		 * be returned by the scheduling class we are in if
		 * nice is invalid for this class.
		 * For any error other than EINVAL
		 * we will go ahead and exec the command even though
		 * the priority change failed.
		 */
		if (errno == EINVAL) {
			(void) fprintf(stderr, gettext(
			    "nice: invalid operation; "
			    "scheduling class does not support nice\n"));
			return (2);
		}
	}
	(void) execvp(argv[1], &argv[1]);
	(void) fprintf(stderr, gettext("%s: %s\n"), strerror(errno), argv[1]);
	/*
	 * POSIX.2 exit status:
	 * 127 if utility is not found.
	 * 126 if utility cannot be invoked.
	 */
	return (errno == ENOENT || errno == ENOTDIR ? 127 : 126);
}

static void
usage()
{
	(void) fprintf(stderr,
	gettext("nice: usage: nice [-n increment] utility [argument ...]\n"));
	exit(2);
}
