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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * error/logging/cleanup functions for ttymon.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <signal.h>
#include <syslog.h>
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

const char *appname = "ttymon";

void
openttymonlog(void)
{
	int	fd, ret;
	char	logfile[MAXPATHLEN];

	/* the log file resides in /var/saf/pmtag/ */
	(void) snprintf(logfile, sizeof (logfile), "%s%s/%s", LOGDIR, Tag,
	    LOGFILE);

	Logfp = NULL;
	(void) close(0);
	if ((fd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0444)) != -1)
		if ((ret = fcntl(fd, F_DUPFD, 3)) == 3) {
			/* set close-on-exec flag */
			if (fcntl(ret, F_SETFD, FD_CLOEXEC) == 0) {
				Logfp = fdopen(ret, "a+");
			}
		}
	if (!Logfp) {
		cons_printf("ttymon cannot create log file \"%s\": %s\n",
		    logfile, strerror(errno));
		exit(1);
	}
	log(" ");
	log("********** ttymon starting **********");

#ifdef	DEBUG
	log("fd(log)\t = %d", fileno(Logfp));
#endif
}

static void
roll_log(void)
{
	char logf[MAXPATHLEN];
	char ologf[MAXPATHLEN];
	char tlogf[MAXPATHLEN];
	FILE *nlogfp;
	struct stat buf;

	(void) fprintf(Logfp, "Restarting log file\n");
	(void) snprintf(logf, sizeof (logf), "%s%s/%s", LOGDIR, Tag, LOGFILE);

	(void) snprintf(ologf, sizeof (ologf), "%s%s/%s", LOGDIR, Tag,
	    OLOGFILE);

	(void) snprintf(tlogf, sizeof (tlogf), "%s%s/%s", LOGDIR, Tag,
	    TLOGFILE);

	if (!stat(ologf, &buf) && rename(ologf, tlogf)) {
		(void) fprintf(Logfp, "rename old to tmp file failed\n");
	} else if (!stat(logf, &buf) && rename(logf, ologf)) {
		(void) fprintf(Logfp, "rename log to old file failed\n");
		/* Restore old log file */
		if (!stat(tlogf, &buf) && rename(tlogf, ologf))
			(void) fprintf(Logfp,
			    "rename tmp to old file failed\n");
	} else if ((nlogfp = fopen(logf, "w")) != NULL) {
		(void) fclose(Logfp);
		Logfp = nlogfp;
		/* reset close-on-exec */
		(void) fcntl(fileno(Logfp), F_SETFD, 1);
	} else {
		(void) fprintf(Logfp, "log file open failed\n");
		/* Restore current and old log file */
		if (!stat(ologf, &buf) && rename(ologf, logf))
			(void) fprintf(Logfp,
			    "rename old to log file failed\n");
		else if (!stat(tlogf, &buf) && rename(tlogf, ologf))
			(void) fprintf(Logfp,
			    "rename tmp to old file failed\n");
	}

	(void) unlink(tlogf); /* remove any stale tmp logfile */
}


/*
 * vlog(msg) - common message routine.
 *	    - if Logfp is NULL, write message to stderr or CONSOLE
 */
static void
vlog(const char *fmt, va_list ap)
{
	char *timestamp;	/* current time in readable form */
	time_t clock;		/* current time in seconds */
	int	fd;
	struct stat buf;

	if (Logfp) {
		if ((fstat(fileno(Logfp), &buf) != -1) &&
		    (buf.st_size >= Logmaxsz) && !Splflag) {
			Splflag = 1;
			roll_log();
			Splflag = 0;
		}

		(void) time(&clock);
		timestamp = ctime(&clock);
		*(strchr(timestamp, '\n')) = '\0';
		(void) fprintf(Logfp, "%s; %ld; ", timestamp, getpid());
		(void) vfprintf(Logfp, fmt, ap);
		if (fmt[strlen(fmt) - 1] != '\n')
			(void) fputc('\n', Logfp);
		(void) fflush(Logfp);
	} else if (isatty(STDERR_FILENO)) {
		(void) fprintf(stderr, "%s: ", appname);
		(void) vfprintf(stderr, fmt, ap);
		if (fmt[strlen(fmt) - 1] != '\n')
			(void) fputc('\n', stderr);
		(void) fflush(stderr);
	} else if ((fd = open(CONSOLE, O_WRONLY|O_NOCTTY)) != -1) {
		FILE *f = fdopen(fd, "w");

		(void) fprintf(f, "%s: ", appname);
		(void) vfprintf(f, fmt, ap);
		if (fmt[strlen(fmt) - 1] != '\n')
			(void) fputc('\n', f);
		(void) fclose(f);
	} else {
		vsyslog(LOG_CRIT, fmt, ap);
	}
}

/*
 * log(fmt, ...) - put a message into the log file
 *	    - if Logfp is NULL, write message to stderr or CONSOLE
 */
/*PRINTFLIKE1*/
void
log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}


/*
 * fatal(fmt, ...) - put a message into the log file, then exit.
 */
/*PRINTFLIKE1*/
void
fatal(const char *fmt, ...)
{
	if (fmt) {
		va_list ap;
		va_start(ap, fmt);
		vlog(fmt, ap);
		va_end(ap);
	}
	log("********** ttymon exiting ***********");
	exit(1);
}

#ifdef DEBUG

/*
 * opendebug - open debugging file, sets global file pointer Debugfp
 *	arg:   getty - if TRUE, ttymon is in getty_mode and use a different
 *		       debug file
 */

void
opendebug(int getty_mode)
{
	int  fd, ret;
	char	debugfile[BUFSIZ];

	if (!getty_mode) {
		(void) strcpy(debugfile, LOGDIR);
		(void) strcat(debugfile, Tag);
		(void) strcat(debugfile, "/");
		(void) strcat(debugfile, DBGFILE);
		if ((Debugfp = fopen(debugfile, "a+")) == NULL)
			fatal("open debug file failed");
	} else {
		if ((fd = open(EX_DBG, O_WRONLY|O_APPEND|O_CREAT)) < 0)
			fatal("open %s failed: %s", EX_DBG, errno);

		if (fd >= 3) {
			ret = fd;
		} else {
			if ((ret = fcntl(fd, F_DUPFD, 3)) < 0)
				fatal("F_DUPFD fcntl failed: %s",
				    strerror(errno));

		}
		if ((Debugfp = fdopen(ret, "a+")) == NULL)
			fatal("fdopen failed: %s", strerror(errno));

		if (ret != fd)
			(void) close(fd);
	}
	/* set close-on-exec flag */
	if (fcntl(fileno(Debugfp), F_SETFD, 1) == -1)
		fatal("F_SETFD fcntl failed: %s", strerror(errno));
}

/*
 * debug(msg) - put a message into debug file
 */

void
debug(const char *fmt, ...)
{
	va_list ap;
	char *timestamp;	/* current time in readable form */
	time_t clock;		/* current time in seconds */

	(void) time(&clock);
	timestamp = ctime(&clock);
	*(strchr(timestamp, '\n')) = '\0';

	(void) fprintf(Debugfp, "%s; %ld; ", timestamp, getpid());

	va_start(ap, fmt);
	(void) vfprintf(Debugfp, fmt, ap);
	va_end(ap);

	(void) fprintf(Debugfp, "\n");
	(void) fflush(Debugfp);
}
#endif
