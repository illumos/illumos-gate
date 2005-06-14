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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * runat: run a command in attribute directory.
 *
 * runat file [command]
 *
 * when command is not specified an interactive shell is started
 * in the attribute directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libintl.h>
#include <errno.h>
#include <strings.h>

static void
usage()
{
	(void) fprintf(stderr, gettext("usage: runat filename [command]\n"));
}

int
main(int argc, char *argv[])
{
	int fd;
	int dirfd;
	int i;
	int argslen;
	char *shell;
	char *args[4];
	char *cmdargs;

	if (argc < 2) {
		usage();
		exit(127);
	}

	if ((fd = open64(argv[1], O_RDONLY)) == -1) {
		(void) fprintf(stderr,
		    gettext("runat: cannot open %s: %s\n"), argv[1],
		    strerror(errno));
		exit(125);
	}

	if ((dirfd = openat64(fd, ".", O_RDONLY|O_XATTR)) == -1) {
		(void) fprintf(stderr,
		    gettext("runat: cannot open attribute"
		    " directory for %s: %s\n"), argv[1], strerror(errno));
		exit(125);
	}

	(void) close(fd);

	if (fchdir(dirfd) == -1) {
		(void) fprintf(stderr,
		    gettext("runat: cannot fchdir to attribute"
		    " directory: %s\n"), strerror(errno));
		exit(125);
	}

	if (argc < 3) {
		shell = getenv("SHELL");
		if (shell == NULL) {
			(void) fprintf(stderr,
			    gettext(
			    "runat: shell not found, using /bin/sh\n"));
			shell = "/bin/sh";
		}

		(void) execl(shell, shell, NULL);
		(void) fprintf(stderr,
		    gettext("runat: Failed to exec %s: %s\n"), shell,
		    strerror(errno));
		return (126);
	}

	/*
	 * Count up the size of all of the args
	 */

	for (i = 2, argslen = 0; i < argc; i++) {
		argslen += strlen(argv[i]) + 1;
	}

	cmdargs = calloc(1, argslen);
	if (cmdargs == NULL) {
		(void) fprintf(stderr, gettext(
		    "runat: failed to allocate memory for"
		    " command arguments: %s\n"), strerror(errno));
		exit(126);
	}


	/*
	 * create string with all of the args concatenated together
	 * This is done so that the shell will interpret the args
	 * and do globbing if necessary.
	 */
	for (i = 2; i < argc; i++) {
		if (strlcat(cmdargs, argv[i], argslen) >= argslen) {
			(void) fprintf(stderr, gettext(
			    "runat: arguments won't fit in"
			    " allocated buffer\n"));
			exit(126);
		}

		/*
		 * tack on a space if there are more args
		 */
		if ((i + 1) < argc) {
			if (strlcat(cmdargs, " ", argslen) >= argslen) {
				(void) fprintf(stderr, gettext(
				    "runat: arguments won't fit in"
				    " allocated buffer\n"));
				exit(126);
			}
		}

	}

	args[0] = "/bin/sh";
	args[1] = "-c";
	args[2] = cmdargs;
	args[3] = NULL;
	(void) execvp(args[0], args);
	(void) fprintf(stderr, gettext("runat: Failed to exec %s: %s\n"),
	    argv[0], strerror(errno));
	return (126);
}
