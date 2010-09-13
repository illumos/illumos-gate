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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Finger server.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <ctype.h>

#define	MAXARGS 10

void fatal(char *prog, char *s);

int
main(argc, argv)
	int argc;
	char *argv[];
{
	register char *sp;
	char line[512];
	struct sockaddr_storage sin;
	pid_t pid, w;
	int i, p[2], status;
	FILE *fp;
	char *av[MAXARGS + 1];

	i = sizeof (sin);
	if (getpeername(0, (struct sockaddr *)&sin, &i) < 0)
		fatal(argv[0], "getpeername");
	line[0] = '\0';
	if (fgets(line, sizeof (line), stdin) == NULL)
		exit(1);
	sp = line;
	av[0] = "finger";
	i = 1;

	/* skip past leading white space */
	while (isspace(*sp))
		sp++;

	/*
	 * The finger protocol says a "/W" switch means verbose output.
	 * We explicitly set either the "long" or "short" output flags
	 * to the finger program so that we don't have to know what what
	 * the "finger" program's default is.
	 */
	if (*sp == '/' && (sp[1] == 'W' || sp[1] == 'w')) {
		sp += 2;
		av[i++] = "-l";
	} else {
		av[i++] = "-s";
	}

	/* look for username arguments */
	while (i < MAXARGS) {

		/* skip over leading white space */
		while (isspace(*sp))
			sp++;

		/* check for end of "command line" */
		if (*sp == '\0')
			break;

		/* pick up another name argument */
		av[i++] = sp;
		while ((*sp != '\0') && !isspace(*sp))
			sp++;

		/* check again for end of "command line" */
		if (*sp == '\0')
			break;
		else
			*sp++ = '\0';
	}

	av[i] = (char *)0;
	if (pipe(p) < 0)
		fatal(argv[0], "pipe");

	if ((pid = fork()) == 0) {
		close(p[0]);
		if (p[1] != 1) {
			dup2(p[1], 1);
			close(p[1]);
		}
		execv("/usr/bin/finger", av);
		printf("No local finger program found\n");
		fflush(stdout);
		_exit(1);
	}
	if (pid == (pid_t)-1)
		fatal(argv[0], "fork");
	close(p[1]);
	if ((fp = fdopen(p[0], "r")) == NULL)
		fatal(argv[0], "fdopen");
	while ((i = getc(fp)) != EOF) {
		if (i == '\n')
			putchar('\r');
		putchar(i);
	}
	fclose(fp);
	while ((w = wait(&status)) != pid && w != (pid_t)-1)
		;
	return (0);
}

void
fatal(prog, s)
	char *prog, *s;
{

	fprintf(stderr, "%s: ", prog);
	perror(s);
	exit(1);
}
