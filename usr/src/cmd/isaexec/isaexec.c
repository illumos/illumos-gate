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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/systeminfo.h>

/*ARGSUSED*/
int
main(int argc, char **argv, char **envp)
{
	const char *execname;
	const char *fname;
	char *isalist;
	ssize_t isalen;
	char *pathname;
	ssize_t len;
	char scratch[1];
	char *str;

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get the isa list.
	 */
	if ((isalen = sysinfo(SI_ISALIST, scratch, 1)) == -1 ||
	    (isalist = malloc(isalen)) == NULL ||
	    sysinfo(SI_ISALIST, isalist, isalen) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: cannot find the ISA list\n"),
		    argv[0]);
		return (1);
	}

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
	 * Allocate a path name buffer.  The sum of the lengths of the
	 * execname and isalist strings is guaranteed to be big enough.
	 */
	len = strlen(execname) + isalen;
	if ((pathname = malloc(len)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: malloc(%d) failed\n"),
		    argv[0], (int)len);
		return (1);
	}

	/*
	 * Break the exec name into directory and file name components.
	 */
	(void) strcpy(pathname, execname);
	if ((str = strrchr(pathname, '/')) != NULL) {
		*++str = '\0';
		fname = execname + (str - pathname);
	} else {
		fname = execname;
		*pathname = '\0';
	}
	len = strlen(pathname);

	/*
	 * For each name in the isa list, look for an executable file
	 * with the given file name in the corresponding subdirectory.
	 */
	str = strtok(isalist, " ");
	do {
		(void) strcpy(pathname+len, str);
		(void) strcat(pathname+len, "/");
		(void) strcat(pathname+len, fname);
		if (access(pathname, X_OK) == 0) {
			/*
			 * File exists and is marked executable.  Attempt
			 * to execute the file from the subdirectory,
			 * using the user-supplied argv and envp.
			 */
			(void) execve(pathname, argv, envp);
			(void) fprintf(stderr,
			    gettext("%s: execve(\"%s\") failed\n"),
			    argv[0], pathname);
		}
	} while ((str = strtok(NULL, " ")) != NULL);

	(void) fprintf(stderr,
	    gettext("%s: cannot find/execute \"%s\" in ISA subdirectories\n"),
	    argv[0], fname);

	return (1);
}
