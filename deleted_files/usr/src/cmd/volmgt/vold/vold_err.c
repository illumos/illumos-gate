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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<unistd.h>
#include	<time.h>
#include	<syslog.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<thread.h>
#include	<synch.h>
#include	"vold.h"


/* flags to errmsg() */
#define	ER_STDERR	0x1
#define	ER_SYSLOG	0x2
#define	ER_NOSTAMP	0x4

static void	errmsg(int, uint_t, char *, const char *, va_list);

static FILE	*logfile;

static mutex_t	err_mutex;

#define	FATALMSG	"fatal: "
#define	QUITMSG		"exiting: "
#define	WARNMSG		"warning: "
#define	INFOMSG		"info: "
#define	DEBUGMSG	"debug[%d]: "
#define	NFSTRMSG	"unfs: "

#define	DEBUGMSG_LEN	128

void
setlog(char *path)
{
#ifdef	NEED_ALL_LOG_INFO
	int	fflags;
#endif


	/* let's init our mutex here (since there's no better place) */
	(void) mutex_init(&err_mutex, USYNC_THREAD, 0);

	/* open the logfile */
	if (strcmp(path, "-") == 0) {
		logfile = stderr;
	} else if ((logfile = fopen(path, "a")) == NULL) {
		perror(path);
		exit(-1);			/* bail out! */
	}

	/* set logfile mode to "rw-r--r--" */
	if (chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0) {
		perror("vold failed to chmod logfile");
	}

	setbuf(logfile, NULL);

#ifdef	NEED_ALL_LOG_INFO
	/* for debugging, set the "FLUSH" bit using fcntl */
	if ((fflags = fcntl(fileno(logfile), F_GETFL)) < 0) {
		debug(1, "setlog: error: can't get file status flags\n");
	} else {
		fflags |= O_SYNC;
		if (fcntl(fileno(logfile), F_SETFL, fflags) < 0) {
			debug(1, "setlog: error: can't set O_SYNC flag\n");
		} else {
			(void) fprintf(stderr,
			    "DEBUG: just set O_SYNC flag for \"%s\"\n",
			    path);
		}
	}
#endif	/* NEED_ALL_LOG_INFO */
}

void
flushlog()
{
	/* keep this REALLY simple because it's called on SEGV, et. al */
	(void) fflush(logfile);
}

void
fatal(const char *fmt, ...)
{
	va_list		ap;
	int		err = errno;

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, ER_STDERR|ER_SYSLOG, FATALMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);

	exit(-1);
}

void
quit(const char *fmt, ...)
{
	va_list		ap;
	int		err = errno;

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, 0, QUITMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);

	exit(0);
}


void
noise(const char *fmt, ...)
{
	va_list		ap;
	int		err = errno;

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, ER_SYSLOG|ER_STDERR, WARNMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);
}

void
warning(const char *fmt, ...)
{
	extern int	verbose;
	va_list		ap;
	int		err = errno;
	int		flag = 0;


	if (verbose) {
		flag = ER_STDERR;
	}

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, flag, WARNMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);
}


void
info(const char *fmt, ...)
{
	extern int	verbose;
	va_list		ap;
	int		err = errno;


	if (verbose == 0) {
		return;
	}

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, 0, INFOMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);
}


void
debug(uint_t level, const char *fmt, ...)
{
	extern int	debug_level;
	va_list		ap;
	char		dbgmsg[DEBUGMSG_LEN];
	int		err = errno;



	if (level > debug_level) {
		return;
	}

	(void) mutex_lock(&err_mutex);

	(void) sprintf(dbgmsg, DEBUGMSG, level);
	va_start(ap, fmt);
	errmsg(err, 0, dbgmsg, fmt, ap);
	(void) fflush(logfile);			/* kinda' overkill, but ... */
	va_end(ap);

	(void) mutex_unlock(&err_mutex);
}


void
nfstrace(const char *fmt, ...)
{
	extern int	trace;
	va_list		ap;
	int		err = errno;



	if (trace == 0) {
		return;
	}

	(void) mutex_lock(&err_mutex);

	va_start(ap, fmt);
	errmsg(err, ER_NOSTAMP, NFSTRMSG, fmt, ap);
	va_end(ap);

	(void) mutex_unlock(&err_mutex);
}


/*ARGSUSED*/
void
dbxtrap(const char *s)
{
#ifndef	lint
	int a = 0;
#endif
}


/*
 * this routine must *NOT* be void, since the ASSERT() macro in vold.h
 *  doesn't like that
 */
int
failass(char *a, char *f, int l)
{
	int		do_fatal = 1;


	dbxtrap("assertion failed");
	if (do_fatal) {
		fatal("assertion failed: %s, file: %s, line: %d\n", a, f, l);
	}
	return (0);
}

static void
errmsg(int err, uint_t flags, char *tag, const char *fmt, va_list ap)
{
	const char	*p;
	char		msg[BUFSIZ];
	char		*errmsg;
	char		*s;
	time_t		t;
#ifdef	DEBUG
	struct tm	tm;
#else
	char		tbuf[CTBSIZE];
#endif


	if (logfile == NULL) {
		logfile = stderr;
	}

	errmsg = strerror(err);

	(void) memset(msg, 0, BUFSIZ);

	if ((flags & ER_NOSTAMP) == 0) {

		/* stick the time into the msg */
		(void) time(&t);
#ifdef	DEBUG
		(void) localtime_r(&t, &tm);
		(void) sprintf(msg, "%02d/%02d/%02d %02d:%02d:%02d @%2d ",
		    tm.tm_mon+1, tm.tm_mday, tm.tm_year % 100,
		    tm.tm_hour, tm.tm_min, tm.tm_sec, thr_self());
#else
		s = ctime_r(&t, tbuf, CTBSIZE);
		s[24] = ' ';
		(void) strcpy(msg, s);
#endif
		/* stick our tag into the msg */
		(void) strcat(msg, tag);
	}

	/* scan for %m and replace with errno msg */
	s = &msg[strlen(msg)];
	p = fmt;
	while (*p != NULLC) {
		if ((*p == '%') && (*(p+1) == 'm')) {
			(void) strcat(s, errmsg);
			p += 2;
			s += strlen(errmsg);
			continue;
		}
		*s++ = *p++;
	}
	*s = '\0';	/* don't forget the null byte */

	/* write off to log file */
	(void) vfprintf(logfile, msg, ap);

	/* write to stderr */
	if ((logfile != stderr) && (flags & ER_STDERR)) {
		(void) vfprintf(stdout, msg, ap);
	}

	/* write to syslog (already opened in main()) */
	if (flags & ER_SYSLOG) {
		(void) vsyslog(LOG_DAEMON|LOG_ERR, fmt, ap);
	}
}
