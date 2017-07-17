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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * openchild.c
 *
 * Open two pipes to a child process, one for reading, one for writing.
 * The pipes are accessed by FILE pointers. This is NOT a public
 * interface, but for internal use only!
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

static char *basename(char *);
static char SHELL[] = "/bin/sh";

/*
 * returns pid, or -1 for failure
 */
int
_openchild(char *command, FILE **fto, FILE **ffrom)
{
	int i;
	int pid;
	int pdto[2];
	int pdfrom[2];
	char *com;


	if (pipe(pdto) < 0) {
		goto error1;
	}
	if (pipe(pdfrom) < 0) {
		goto error2;
	}
	switch (pid = fork()) {
	case -1:
		goto error3;

	case 0:
		/*
		 * child: read from pdto[0], write into pdfrom[1]
		 */
		(void) close(0);
		(void) dup(pdto[0]);
		(void) close(1);
		(void) dup(pdfrom[1]);

		/*
		 * adding this closelog for bug id 1238429
		 */
		closelog();
		closefrom(3);

		com = malloc((unsigned)strlen(command) + 6);
		if (com == NULL) {
			exit(1);
		}
		(void) sprintf(com, "exec %s", command);
		execl(SHELL, basename(SHELL), "-c", com, NULL);
		exit(1);

	default:
		/*
		 * parent: write into pdto[1], read from pdfrom[0]
		 */
		*fto = fdopen(pdto[1], "w");
		(void) close(pdto[0]);
		*ffrom = fdopen(pdfrom[0], "r");
		(void) close(pdfrom[1]);
		break;
	}
	return (pid);

	/*
	 * error cleanup and return
	 */
error3:
printf("openchild: error3");
	(void) close(pdfrom[0]);
	(void) close(pdfrom[1]);
error2:
printf("openchild: error2");
	(void) close(pdto[0]);
	(void) close(pdto[1]);
error1:
printf("openchild: error1");
	return (-1);
}

static char *
basename(char *path)
{
	char *p;

	p = strrchr(path, '/');
	if (p == NULL) {
		return (path);
	} else {
		return (p + 1);
	}
}
