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
 *
 * Copyright 1985 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 *  under.c - program to execute a command under a given directory
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rpc/rpc.h>
#include <nfs/nfs.h>
#include <rpcsvc/mount.h>
#include <sys/time.h>

static char **Argv;		/* saved argument vector (for ps) */
static char *LastArgv;		/* saved end-of-argument vector */

int	Debug = 0;

int child = 0;			/* pid of the executed process */
int ChildDied = 0;		/* true when above is valid */
int HasHelper = 0;		/* must kill helpers (interactive mode) */
time_t time_now;
/*
 *  SETPROCTITLE -- set the title of this process for "ps"
 *
 *	Does nothing if there were not enough arguments on the command
 * 	line for the information.
 *
 *	Side Effects:
 *		Clobbers argv[] of our main procedure.
 */
void
setproctitle(user, host)
	char *user, *host;
{
	register char *tohere;

	tohere = Argv[0];
	if ((int)(LastArgv == (char *)NULL) || 
			(int)(strlen(user)+strlen(host)+3) > (int)(LastArgv - tohere))
		return;
	*tohere++ = '-';		/* So ps prints (rpc.rexd)	*/
	sprintf(tohere, "%s@%s", user, host);
	while (*tohere++)		/* Skip to end of printf output	*/
		;
	while (tohere < LastArgv)	/* Avoid confusing ps		*/
		*tohere++ = ' ';
}


void
main(argc, argv)
	int argc;
	char **argv;
{
	static char usage[] = "Usage: under [-d] dir command...\n";
	char *dir, *p;
	char hostname[255];
	char *tmpdir, *subdir, *parsefs();
	char dirbuf[1024];
	char error[1024];
	int status;
	int len;

	if (argc < 3)
	{
		fprintf(stderr, usage);
		exit(1);
	}

	/*
	 * argv start and extent for setproctitle()
	 */
	Argv = argv;
	if (argc > 0)
		LastArgv = argv[argc-1] + strlen(argv[argc-1]);
	else
		LastArgv = NULL;

	gethostname(hostname, 255);
	strcat(hostname, ":/");
	len = strlen(hostname);
	if ( strcmp( argv[1], "-d" ) == 0 )
	{
		Debug = 1;
		argv++;
	}
	dir = argv[1];
	if ( (int)strlen(dir) > len &&  (int)strncmp(dir, hostname, len) == 0)
		dir = strchr(dir, ':') + 1;
	else if (p = strchr(dir, ':'))
	{
		if (p[1] != '/')
		{
			fprintf(stderr, "under: %s invalid name\n", dir);
			exit(1);
		}

		tmpdir = mktemp("/tmp/underXXXXXX");

                if ( Debug && errno )    
		{
			if ( errno != ENOENT )
                        printf("mktemp of %s returned %d %s\n",
                                        tmpdir, errno, strerror(errno));
		}
		errno = 0;	/* XXX access() call in mktemp sets errno = ENOENT */
              
		if (mkdir(tmpdir, 0777))
		{
			perror(tmpdir);
			exit(1);
		}

                if ( Debug && errno )    
                        printf("mkdir of %s returned %d %s\n",
                                        tmpdir, errno, strerror(errno));
              
		subdir = parsefs(dir, error);
		if (subdir == NULL)
		{
			exit(1);
		}
		time_now = time((long *) 0);
		if (mount_nfs(dir, tmpdir, error))
		{
			exit(1);
		}
		strcpy(dirbuf, tmpdir);
		strcat(dirbuf, "/");
		strcat(dirbuf, subdir);
		status = runcmd(dirbuf, argv[2], &argv[2]);
		if (umount_nfs(dir, tmpdir))
			fprintf(stderr, "under: couldn't umount %s\n", dir);
		rmdir(tmpdir);
		exit(status);
	}
		
	setgid(getgid());
	setuid(getuid());
	if (chdir(dir))
	{
		perror(dir);
		exit(1);
	}
	execvp(argv[2], &argv[2]);
	perror(argv[2]);
	exit(1);
	/* NOTREACHED */
}

typedef void (*sig_t)();

int
runcmd(dir, cmd, args)
	char	*dir;
	char	*cmd;
	char	**args;
{
	int pid, child, status;
	sig_t sigint, sigquit;

	sigint = sigset(SIGINT, SIG_IGN);
	sigquit = sigset(SIGQUIT, SIG_IGN);
	pid = fork();
	if (pid == -1)
		return (0177);
	if (pid == 0)
	{
		setgid(getgid());
		setuid(getuid());
		if (chdir(dir))
		{
			perror(dir);
			exit(1);
		}
		(void) sigset(SIGINT, sigint);
		(void) sigset(SIGQUIT, sigquit);
		execvp(cmd, args);
		perror(cmd);
		exit(1);
	}
	while ((child = wait(&status)) != pid && child != -1)
		;
	(void) sigset(SIGINT, sigint);
	(void) sigset(SIGQUIT, sigquit);
	if (child == -1)
		return (0177);
	if (status & 0377)
		return (status & 0377);
	return ((status >> 8) & 0377);
}
