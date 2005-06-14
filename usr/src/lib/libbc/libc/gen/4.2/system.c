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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/file.h>

extern int execl();

int
system(s)
char	*s;
{
	int	status;
	pid_t	pid, w;
	register void (*istat)(), (*qstat)();
	char	path[256];
	char 	*c;

	while (*s == ' ' || *s == '\t')
		s++;

	if (strncmp(s, "/usr/ucb", strlen("/usr/ucb")) == 0) {
		/* check if command is under /usr/ucb, if not
		 * replace /usr/ucb with /usr/bin.
 		 */
		strcpy(path, s);
		if ((c = strchr(path, ' ')) != NULL)
			*c ='\0';
		if (access(path, F_OK) == -1) {
			strncpy(path, "/usr/bin", strlen("/usr/bin"));
			if (c != NULL) *c = ' ';
			s = path;
		}
	}
	else if (strncmp(s, "/bin", strlen("/bin")) == 0 ||
		 strncmp(s, "/usr/bin", strlen("/usr/bin")) == 0) {
		/* if /usr/bin is specified, first check if a command
		 * with the same name exists under /usr/ucb */
		strcpy(path, "/usr/ucb");
		if (strncmp(s, "/bin", strlen("/bin")) == 0) 
			strcat(path, strchr(s+1, '/'));
		else {
			c = strchr(s+1, '/');
			strcat(path, strchr(c+1, '/'));
		}
		if ((c = strchr(path, ' ')) != NULL)
			*c ='\0';
		if (access(path, F_OK) == 0) {
			if (c != NULL) *c = ' ';
			s = path;
		}
	}	

	if ((pid = vfork()) == 0) {
		(void) execl("/bin/sh", "sh", "-c", s, (char *)0);
		_exit(127);
	}
	if (pid == -1) {
		return (-1);
	}
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	w = waitpid(pid, &status, 0);
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	return ((w == -1) ? -1: status);
}
