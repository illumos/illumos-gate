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

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "conf.h"

#define	CF_DEFSIZE	32	/* Starting table size */
#define	CF_GROW		2	/* Table size multiplier on grow */

static FILE *
open_conf_pipe(const char *cmd, char *argv[], pid_t *pidp)
{
	int pfds[2];
	pid_t pid;
	struct sigaction act;

	/* Create a pipe and fork a child process to run the command */

	if (pipe(pfds) == -1) {
		logerror("failed to create pipe");
		return (NULL);
	}

	if ((pid = fork1()) == -1) {
		logerror("failed to fork1");
		goto err;
	}

	/* If we're in the child, run the command and output to the pipe */

	if (pid == 0) {
		/*
		 * We must set up to ignore these signals, which may be
		 * propogated from the calling process.
		 */

		act.sa_handler = SIG_IGN;

		(void) sigaction(SIGHUP, &act, NULL);
		(void) sigaction(SIGALRM, &act, NULL);
		(void) sigaction(SIGUSR1, &act, NULL);

		(void) close(pfds[0]);
		(void) close(STDOUT_FILENO);

		if (dup2(pfds[1], STDOUT_FILENO) == -1) {
			logerror("failed to dup to stdout");
			(void) close(pfds[1]);
			_exit(127);
		}

		(void) execvp(cmd, argv);
		logerror("failed to parse configuration file");
		_exit(127);
		/*NOTREACHED*/
	}

	/* If we're in the parent, open the read end of the pipe and return */

	*pidp = pid;
	(void) close(pfds[1]);
	return (fdopen(pfds[0], "r"));

err:
	(void) close(pfds[0]);
	(void) close(pfds[1]);
	return (NULL);
}

static void
close_conf_pipe(FILE *fp, pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			break;
	}

	(void) fclose(fp);
}

static int
grow_conf_file(conf_t *cf)
{
	int ndsize = cf->cf_dsize ? cf->cf_dsize * CF_GROW : CF_DEFSIZE;
	void *ndtab = realloc(cf->cf_dtab, sizeof (char *) * ndsize);

	register char *p;
	int odsize, lines, i;

	if (ndtab == NULL) {
		logerror("failed to allocate config file table");
		return (-1);
	}

	lines = ndsize - cf->cf_dsize;
	odsize = cf->cf_dsize;

	cf->cf_dtab = (char **)ndtab;
	cf->cf_dsize = ndsize;

	for (i = 0; i < lines; i++) {
		if ((p = (char *)malloc(BUFSIZ)) == NULL) {
			logerror("failed to allocate config file buffer");
			return (-1);
		}

		cf->cf_dtab[odsize + i] = p;
	}

	return (0);
}

int
conf_open(conf_t *cf, const char *cmd, char *argv[])
{
	char *line, *p;
	pid_t pid;
	FILE *fp;

	(void) memset(cf, 0, sizeof (conf_t));

	if ((fp = open_conf_pipe(cmd, argv, &pid)) == NULL)
		return (-1);

	for (;;) {
		/* If we need to grow the table, do so now */

		if (cf->cf_lines >= cf->cf_dsize) {
			if (grow_conf_file(cf) == -1)
				goto err;
		}

		line = cf->cf_dtab[cf->cf_lines];

		/* Read the next line, and break out if we're done */

		if (fgets(line, BUFSIZ, fp) == NULL)
			break;

		/* Strip newline and bump line counter */

		if ((p = strchr(line, '\n')) != NULL)
			*p = '\0';

		cf->cf_lines++;
	}

	close_conf_pipe(fp, pid);
	return (0);

err:
	close_conf_pipe(fp, pid);
	return (-1);
}

void
conf_rewind(conf_t *cf)
{
	cf->cf_ptr = 0;
}

char *
conf_read(conf_t *cf)
{
	if (cf->cf_ptr < cf->cf_lines)
		return (cf->cf_dtab[cf->cf_ptr++]);

	return (NULL);
}

void
conf_close(conf_t *cf)
{
	int i;

	if (cf->cf_dtab != NULL) {
		for (i = 0; i < cf->cf_dsize; i++)
			free(cf->cf_dtab[i]);
		free(cf->cf_dtab);
	}
}
