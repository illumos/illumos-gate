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
 * Copyright 1988-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <signal.h>
#include <stdio.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <utmpx.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <pwd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <locale.h>
#include <syslog.h>
#include <sys/wait.h>
#include <limits.h>

/*
 * utmpx defines wider fields for user and line.  For compatibility of output,
 * we are limiting these to the old maximums in utmp. Define UTMPX_NAMELEN
 * to use the full lengths.
 */
#ifndef UTMPX_NAMELEN
/* XXX - utmp -fix name length */
#define	NMAX	(_POSIX_LOGIN_NAME_MAX - 1)
#define	LMAX	12
#else /* UTMPX_NAMELEN */
#define	NMAX	(sizeof (((struct utmpx *)0)->ut_user)
#define	LMAX	(sizeof (((struct utmpx *)0)->ut_line)
#endif /* UTMPX_NAMELEN */

static char	mesg[3000];
static char	*infile;
static int	gflag;
static struct	group *pgrp;
static char	*grpname;
static char	line[MAXNAMLEN+1] = "???";
static char	systm[MAXNAMLEN+1];
static time_t	tloc;
static struct	utsname utsn;
static char	who[9]	= "???";
static char	time_buf[50];
#define	DATE_FMT	"%a %b %e %H:%M:%S"

static void sendmes(struct utmpx *);
static int chkgrp(char *);
static char *copy_str_till(char *, char *, char, int);

int
main(int argc, char *argv[])
{
	int	i = 0;
	struct utmpx *p;
	FILE	*f;
	char	*ptr, *start;
	struct	passwd *pwd;
	char	*term_name;
	int	c;
	int	aflag = 0;
	int	errflg = 0;

	(void) setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "g:a")) != EOF)
		switch (c) {
		case 'a':
			aflag++;
			break;
		case 'g':
			if (gflag) {
				(void) fprintf(stderr,
				    "Only one group allowed\n");
				exit(1);
			}
			if ((pgrp = getgrnam(grpname = optarg)) == NULL) {
				(void) fprintf(stderr, "Unknown group %s\n",
				    grpname);
				exit(1);
			}
			gflag++;
			break;
		case '?':
			errflg++;
			break;
		}

	if (errflg) {
		(void) fprintf(stderr,
		    "Usage: wall [-a] [-g group] [files...]\n");
		return (1);
	}

	if (optind < argc)
		infile = argv[optind];

	if (uname(&utsn) == -1) {
		(void) fprintf(stderr, "wall: uname() failed, %s\n",
		    strerror(errno));
		exit(2);
	}
	(void) strcpy(systm, utsn.nodename);

	/*
	 * Get the name of the terminal wall is running from.
	 */

	if ((term_name = ttyname(fileno(stderr))) != NULL) {
		/*
		 * skip the leading "/dev/" in term_name
		 */
		(void) strncpy(line, &term_name[5], sizeof (line) - 1);
	}

	if (who[0] == '?') {
		if (pwd = getpwuid(getuid()))
			(void) strncpy(&who[0], pwd->pw_name, sizeof (who));
	}

	f = stdin;
	if (infile) {
		f = fopen(infile, "r");
		if (f == NULL) {
			(void) fprintf(stderr, "Cannot open %s\n", infile);
			exit(1);
		}
	}

	start = &mesg[0];
	ptr = start;
	while ((ptr - start) < 3000) {
		size_t n;

		if (fgets(ptr, &mesg[sizeof (mesg)] - ptr, f) == NULL)
			break;
		if ((n = strlen(ptr)) == 0)
			break;
		ptr += n;
	}
	(void) fclose(f);

	/*
	 * If the request is from the rwall daemon then use the caller's
	 * name and host.  We determine this if all of the following is true:
	 *	1) First 5 characters are "From "
	 *	2) Next non-white characters are of the form "name@host:"
	 */
	if (strcmp(line, "???") == 0) {
		char rwho[MAXNAMLEN+1];
		char rsystm[MAXNAMLEN+1];
		char *cp;

		if (strncmp(mesg, "From ", 5) == 0) {
			cp = &mesg[5];
			cp = copy_str_till(rwho, cp, '@', MAXNAMLEN + 1);
			if (rwho[0] != '\0') {
				cp = copy_str_till(rsystm, ++cp, ':',
				    MAXNAMLEN + 1);
				if (rsystm[0] != '\0') {
					(void) strcpy(systm, rsystm);
					(void) strncpy(rwho, who, 9);
					(void) strcpy(line, "rpc.rwalld");
				}
			}
		}
	}
	(void) time(&tloc);
	(void) strftime(time_buf, sizeof (time_buf),
			    DATE_FMT, localtime(&tloc));

	setutxent();
	while ((p = getutxent()) != NULL) {
		if (p->ut_type != USER_PROCESS)
			continue;
		/*
		 * if (-a option OR NOT pty window login), send the message
		 */
		if (aflag || !nonuser(*p))
			sendmes(p);
	}
	endutxent();

	(void) alarm(60);
	do {
		i = (int)wait((int *)0);
	} while (i != -1 || errno != ECHILD);

	return (0);
}

/*
 * Copy src to destination upto but not including the delim.
 * Leave dst empty if delim not found or whitespace encountered.
 * Return pointer to next character (delim, whitespace, or '\0')
 */
static char *
copy_str_till(char *dst, char *src, char delim, int len)
{
	int i = 0;

	while (*src != '\0' && i < len) {
		if (isspace(*src)) {
			dst[0] = '\0';
			return (src);
		}
		if (*src == delim) {
			dst[i] = '\0';
			return (src);
		}
		dst[i++] = *src++;
	}
	dst[0] = '\0';
	return (src);
}

/*
 * Note to future maintainers: with the change of wall to use the
 * getutxent() API, the forked children (created by this function)
 * must call _exit as opposed to exit. This is necessary to avoid
 * unwanted fflushing of getutxent's stdio stream (caused by atexit
 * processing).
 */
static void
sendmes(struct utmpx *p)
{
	int i;
	char *s;
	static char device[LMAX + 6];
	char *bp;
	int ibp;
	FILE *f;
	int fd;

	if (gflag)
		if (!chkgrp(p->ut_user))
			return;
	while ((i = (int)fork()) == -1) {
		(void) alarm(60);
		(void) wait((int *)0);
		(void) alarm(0);
	}

	if (i)
		return;

	(void) signal(SIGHUP, SIG_IGN);
	(void) alarm(60);
	s = &device[0];
	(void) snprintf(s, sizeof (device), "/dev/%.*s", LMAX, p->ut_line);

	/* check if the device is really a tty */
	if ((fd = open(s, O_WRONLY|O_NOCTTY|O_NONBLOCK)) == -1) {
		(void) fprintf(stderr, "Cannot send to %.*s on %s\n",
		    NMAX, p->ut_user, s);
		perror("open");
		(void) fflush(stderr);
		_exit(1);
	} else {
		if (!isatty(fd)) {
			(void) fprintf(stderr,
			    "Cannot send to device %.*s %s\n",
			    LMAX, p->ut_line,
			    "because it's not a tty");
			openlog("wall", 0, LOG_AUTH);
			syslog(LOG_CRIT, "%.*s in utmpx is not a tty\n",
			    LMAX, p->ut_line);
			closelog();
			(void) fflush(stderr);
			_exit(1);
		}
	}
#ifdef DEBUG
	(void) close(fd);
	f = fopen("wall.debug", "a");
#else
	f = fdopen(fd, "w");
#endif
	if (f == NULL) {
		(void) fprintf(stderr, "Cannot send to %-.*s on %s\n",
		    NMAX, &p->ut_user[0], s);
		perror("open");
		(void) fflush(stderr);
		_exit(1);
	}
	(void) fprintf(f,
	    "\07\07\07Broadcast Message from %s (%s) on %s %19.19s",
	    who, line, systm, time_buf);
	if (gflag)
		(void) fprintf(f, " to group %s", grpname);
	(void) fprintf(f, "...\n");
#ifdef DEBUG
	(void) fprintf(f, "DEBUG: To %.8s on %s\n", p->ut_user, s);
#endif
	i = strlen(mesg);
	for (bp = mesg; --i >= 0; bp++) {
		ibp = (unsigned int)((unsigned char) *bp);
		if (*bp == '\n')
			(void) putc('\r', f);
		if (isprint(ibp) || *bp == '\r' || *bp == '\013' ||
		    *bp == ' ' || *bp == '\t' || *bp == '\n' || *bp == '\007') {
			(void) putc(*bp, f);
		} else {
			if (!isascii(*bp)) {
				(void) fputs("M-", f);
				*bp = toascii(*bp);
			}
			if (iscntrl(*bp)) {
				(void) putc('^', f);
				(void) putc(*bp + 0100, f);
			}
			else
				(void) putc(*bp, f);
		}

		if (*bp == '\n')
			(void) fflush(f);

		if (ferror(f) || feof(f)) {
			(void) printf("\n\007Write failed\n");
			(void) fflush(stdout);
			_exit(1);
		}
	}
	(void) fclose(f);
	(void) close(fd);
	_exit(0);
}


static int
chkgrp(char *name)
{
	int i;
	char *p;

	for (i = 0; pgrp->gr_mem[i] && pgrp->gr_mem[i][0]; i++) {
		for (p = name; *p && *p != ' '; p++);
		*p = 0;
		if (strncmp(name, pgrp->gr_mem[i], 8) == 0)
			return (1);
	}

	return (0);
}
