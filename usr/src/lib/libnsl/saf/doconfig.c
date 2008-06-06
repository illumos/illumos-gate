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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ulimit.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stropts.h>
#include <ctype.h>
#include <sys/conf.h>
#include <errno.h>
#include <signal.h>
#include "sac.h"

#define	COMMENT	'#'
#define	NOWAIT	0
#define	WAIT	1

static char	*eatwhite(char *);
static int	doassign(char *);
static int	dopush(int, char *);
static int	dopop(int, char *);
static int	dorun(char *, int);

/*
 * doconfig - the configuration script interpreter, if all is ok,
 *	      return 0.  If there is a "system" error, return -1.
 *	      If there is an error performing a command, or there
 *	      is a syntax error, return the line number in error.
 *
 *	args:	fd - file descriptor to push and pop from
 *		script - name of the configuration script
 *		rflag - restriction flag to determine what "commands"
 *			can be run
 */

int
doconfig(int fd, char *script, long rflag)
{
	int line;		/* line counter */
	struct stat statbuf;	/* place for stat */
	FILE *fp;		/* file pointer for config script */
	char buf[BUFSIZ + 1];	/* scratch buffer */
	char *bp;		/* scratch pointer */
	char *p;		/* scratch pointer */

	/* if the script does not exist, then there is nothing to do */
	if (stat(script, &statbuf) < 0)
		return (0);

	fp = fopen(script, "rF");
	if (fp == NULL)
		return (-1);

	line = 0;
	while (fgets(buf, BUFSIZ, fp)) {
		line++;
		p = strchr(buf, '\n');
		/* if no \n, then line is too long */
		if (p == NULL) {
			(void) fclose(fp);
			return (line);
		}
		*p = '\0';

		/* remove comments */
		p = strchr(buf, COMMENT);
		if (p)
			*p = '\0';

		/* remove leading whitespace */
		bp = eatwhite(buf);
		/* see if anything is left */
		if (*bp == '\0')
			continue;

		/* remove trailing whitespace */
		p = &buf[strlen(buf) - 1];
		while (*p && isspace(*p))
			*p-- = '\0';

		/* get the command */
		p = bp;
		while (*p && !isspace(*p))
			p++;
		if (*p)
			*p++ = '\0';
		/* skip any whitespace here too (between command and args) */
		p = eatwhite(p);

		if (strcmp(bp, "assign") == 0) {
			if ((rflag & NOASSIGN) || doassign(p)) {
				(void) fclose(fp);
				return (line);
			}
		} else if (strcmp(bp, "push") == 0) {
			if (dopush(fd, p)) {
				(void) fclose(fp);
				return (line);
			}
		} else if (strcmp(bp, "pop") == 0) {
			if (dopop(fd, p)) {
				(void) fclose(fp);
				return (line);
			}
		} else if (strcmp(bp, "run") == 0) {
			if ((rflag & NORUN) || dorun(p, NOWAIT)) {
				(void) fclose(fp);
				return (line);
			}
		} else if (strcmp(bp, "runwait") == 0) {
			if ((rflag & NORUN) || dorun(p, WAIT)) {
				(void) fclose(fp);
				return (line);
			}
		} else {
			/* unknown command */
			(void) fclose(fp);
			return (line);
		}
	}
	if (!feof(fp)) {
		(void) fclose(fp);
		return (-1);
	}
	(void) fclose(fp);
	return (0);
}


/*
 * doassign - handle an `assign' command
 *
 *	args:	p - assignment string
 */


static int
doassign(char *p)
{
	char *var;		/* environment variable to be assigned */
	char val[BUFSIZ];	/* and the value to be assigned to it */
	char scratch[BUFSIZ];	/* scratch buffer */
	char delim;		/* delimiter char seen (for quoted strings ) */
	char *tp;		/* scratch pointer */

	if (*p == '\0')
		return (-1);
	var = p;
	/* skip first token, but stop if we see a '=' */
	while (*p && !isspace(*p) && (*p != '='))
		p++;

	/* if we found end of string, it's an error */
	if (*p == '\0')
		return (-1);

	/* if we found a space, look for the '=', otherwise it's an error */
	if (isspace(*p)) {
		*p++ = '\0';
		while (*p && isspace(*p))
			p++;
		if (*p == '\0')
			return (-1);
		if (*p == '=')
			p++;
		else
			return (-1);
	} else {
		/* skip over '=' */
		*p = '\0';
		p++;
	}

	/* skip over any whitespace */
	p = eatwhite(p);
	if (*p == '\'' || *p == '"') {
		/* handle quoted values */
		delim = *p++;
		tp = val;
		for (;;) {
			if (*p == '\0') {
				return (-1);
			} else if (*p == delim) {
				if (*(p - 1) != '\\')
					break;
				else
					*(tp - 1) = *p++;
			} else
				*tp++ = *p++;
		}
		*tp = '\0';
		/*
		 * these assignments make the comment below true
		 * (values of tp and p
		 */
		tp = ++p;
		p = val;
	} else {
		tp = p;
		/* look for end of token */
		while (*tp && !isspace(*tp))
			tp++;
	}

/*
 * at this point, p points to the value, and tp points to the
 * end of the token.  check to make sure there is no garbage on
 * the end of the line
 */

	if (*tp)
		return (-1);
	(void) snprintf(scratch, sizeof (scratch), "%s=%s", var, p);
	/* note: need to malloc fresh space so putenv works */
	tp = malloc(strlen(scratch) + 1);
	if (tp == NULL)
		return (-1);
	(void) strcpy(tp, scratch);
	if (putenv(tp))
		return (-1);
	return (0);
}


/*
 * dopush - handle a `push' command
 *
 *	args:	fd - file descriptor to push on
 *		p - list of modules to push
 */


static int
dopush(int fd, char *p)
{
	char *tp;	/* scratch pointer */
	int i;		/* scratch variable */
	int npush;	/* count # of modules pushed */

	if (*p == '\0')
		return (-1);
	npush = 0;
	for (;;) {
		if (*p == '\0')		/* found end of line */
			return (0);
		p = eatwhite(p);
		if (*p == '\0')
			return (-1);
		tp = p;
		while (*tp && !isspace(*tp) && (*tp != ','))
			tp++;
		if (*tp)
			*tp++ = '\0';
		if (ioctl(fd, I_PUSH, p) < 0) {

/*
 * try to pop all that we've done, if pop fails it doesn't matter because
 * nothing can be done anyhow
 */

			for (i = 0; i < npush; ++i)
				(void) ioctl(fd, I_POP, 0);
			return (-1);
		}
		/* count the number of modules we've pushed */
		npush++;
		p = tp;
	}
}


/*
 * dopop - handle a `pop' command
 *
 *	args:	fd - file descriptor to pop from
 *		p - name of module to pop to or ALL (null means pop top only)
 */


static int
dopop(int fd, char *p)
{
	char *modp;		/* module name from argument to pop */
	char buf[FMNAMESZ + 1];	/* scratch buffer */

	if (*p == '\0') {
		/* just a pop with no args */
		if (ioctl(fd, I_POP, 0) < 0)
			return (-1);
		return (0);
	}

	/* skip any whitespace in between */
	p = eatwhite(p);
	modp = p;
	/* find end of module name */
	while (*p && !isspace(*p))
		p++;

	if (*p)		/* if not end of line, extra junk on line */
		return (-1);
	if (strcmp(modp, "ALL") == 0) {
		/* it's the magic name, pop them all */
		while (ioctl(fd, I_POP, 0) == 0)
			;
		/* After all popped, we'll get an EINVAL, which is expected */
		if (errno != EINVAL)
			return (-1);
		return (0);
	}
	/* check to see if the named module is on the stream */
	if (ioctl(fd, I_FIND, modp) != 1)
		return (-1);

	/* pop them until the right one is on top */
	for (;;) {
		if (ioctl(fd, I_LOOK, buf) < 0)
			return (-1);
		if (strcmp(modp, buf) == 0)
			/* we're done */
			return (0);
		if (ioctl(fd, I_POP, 0) < 0)
			return (-1);
	}
	/* NOTREACHED */
}


/*
 * dorun - handle a `run' command
 *
 *	args:	p - command line to run
 *		waitflag - flag indicating whether a wait should be done
 */


static int
dorun(char *p, int waitflg)
{
	char *tp;		/* scratch pointer */
	char *ep;		/* scratch pointer (end of token) */
	char savech;		/* hold area */
	int status;		/* return status from wait */
	pid_t pid;		/* pid of child proc */
	pid_t rpid;		/* returned pid from wait */
	void (*func)();		/* return from signal */

	if (*p == '\0')
		return (-1);

	/*
	 * get first token
	 */

	for (tp = p; *tp && !isspace(*tp); ++tp)
		;
	savech = '\0';
	if (*tp) {
		savech = *tp;
		*tp = '\0';
	}

	/*
	 * look for built-in's
	 */

	if (strcmp(p, "cd") == 0) {
		*tp = savech;
		tp = eatwhite(tp);
		if (*tp == '\0')
			/* if nothing there, try to cd to $HOME */
			tp = getenv("HOME");
		if (chdir(tp) < 0)
			return (-1);
	} else if (strcmp(p, "ulimit") == 0) {
		*tp = savech;
		tp = eatwhite(tp);
		/* must have an argument */
		if (*tp == '\0')
			return (-1);
		/* make sure nothing appears on line after arg */
		for (ep = tp; *ep && !isspace(*ep); ++ep)
			;
		ep = eatwhite(ep);
		if (*ep)
			return (-1);
		if (!isdigit(*tp))
			return (-1);

		if (ulimit(2, atoi(tp)) < 0)
			return (-1);
	} else if (strcmp(p, "umask") == 0) {
		*tp = savech;
		tp = eatwhite(tp);
		/* must have an argument */
		if (*tp == '\0')
			return (-1);
		/* make sure nothing appears on line after arg */
		for (ep = tp; *ep && !isspace(*ep); ++ep)
			;
		ep = eatwhite(ep);
		if (*ep)
			return (-1);
		if (!isdigit(*tp))
			return (-1);
		(void) umask(strtol(tp, NULL, 8));
	} else {
		/* not a built-in */
		*tp = savech;
		func = signal(SIGCLD, SIG_DFL);
		if ((pid = fork()) < 0) {
			(void) signal(SIGCLD, func);
			return (-1);
		}
		if (pid) {
			if (waitflg == WAIT) {
				status = 0;
				rpid = -1;
				while (rpid != pid)
					rpid = wait(&status);
				if (status) {
					/* child failed */
					(void) signal(SIGCLD, func);
					return (-1);
				}
			}
			(void) signal(SIGCLD, func);
		} else {
			/* set IFS for security */
			(void) putenv("IFS=\" \"");
			/*
			 * need to close all files to prevent unauthorized
			 * access in the children.  Setup stdin, stdout,
			 * and stderr to /dev/null.
			 */
			closefrom(0);
			/* stdin */
			if (open("/dev/null", O_RDWR) != 0)
				return (-1);
			/* stdout */
			if (dup(0) != 1)
				return (-1);
			/* stderr */
			if (dup(0) != 2)
				return (-1);
			(void) execl("/usr/bin/sh", "sh", "-c", p, NULL);
			/*
			 * if we get here, there is a problem - remember that
			 * this is the child
			 */
			exit(1);
		}
	}
	return (0);
}


/*
 * eatwhite - swallow any leading whitespace, return pointer to first
 *	      non-white space character or to terminating null character
 *	      if nothing else is there
 *
 *	args:	p - string to parse
 */

static char *
eatwhite(char *p)
{
	while (*p && isspace(*p))
		p++;
	return (p);
}
