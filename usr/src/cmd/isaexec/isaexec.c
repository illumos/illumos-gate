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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <unistd.h>
#include <locale.h>

/*ARGSUSED*/
int
main(int argc, char **argv, char **envp)
{
	const char *execname;
	const char *fname;

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get the exec name.
	 */
	if ((execname = getexecname()) == NULL) {
		(void) fprintf(stderr,
				gettext("%s: getexecname() failed\n"),
				argv[0]);
		return (1);
	}

	/*
	 * Get the base name of the executable.
	 */
	fname = strrchr(execname, '/');
	fname = (fname != NULL) ? (fname+1) : execname;

	if (isaexec(execname, argv, envp) == -1) {
		if (errno == ENOENT) {
			(void) fprintf(stderr,
					gettext("%s: cannot find/execute \"%s\""
						" in ISA subdirectories\n"),
					argv[0], fname);
			return (1);
		}
	}

	(void) fprintf(stderr,
			gettext("%s: isaexec(\"%s\") failed\n"),
			argv[0], fname);
	return (1);
}
