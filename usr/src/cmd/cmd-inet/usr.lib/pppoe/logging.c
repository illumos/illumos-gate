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
 * PPPoE Server-mode daemon log file support.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <sys/types.h>

#include "common.h"
#include "logging.h"

/* Not all functions are used by all applications.  Let lint know this. */
/*LINTLIBRARY*/

const char *prog_name = "none";	/* Subsystem name for syslog */
int log_level;			/* Higher number for more detail. */

static int curlogfd = -1;	/* Current log file */
static const char *curfname;	/* Name of current log file */
static const char *stderr_name = "stderr";

#define	SMALLSTR	254	/* Don't allocate for most strings. */

/*
 * Returns -1 on error (with errno set), 0 on blocked write (file
 * system full), or N (buffer length) on success.
 */
static int
dowrite(int fd, const void *buf, int len)
{
	int retv;
	const uint8_t *bp = (uint8_t *)buf;

	while (len > 0) {
		retv = write(fd, bp, len);
		if (retv == 0) {
			break;
		}
		if (retv == -1) {
			if (errno != EINTR)
				break;
		} else {
			bp += retv;
			len -= retv;
		}
	}
	if (len <= 0)
		return (bp - (uint8_t *)buf);
	return (retv);
}

/* A close that avoids closing stderr */
static int
doclose(void)
{
	int	retval = 0;

	if (curlogfd == -1)
		return (0);
	if ((curlogfd != STDERR_FILENO) || (curfname != stderr_name))
		retval = close(curlogfd);
	curlogfd = -1;
	return (retval);
}

/*
 * Log levels are 0 for no messages, 1 for errors, 2 for warnings, 3
 * for informational messages, and 4 for debugging messages.
 */
static void
vlogat(int loglev, const char *fmt, va_list args)
{
	char timbuf[64];
	char regbuf[SMALLSTR+2];
	char *ostr;
	int timlen;
	int slen;
	char *nstr;
	int err1, err2;
	int sloglev;
	int retv;
	va_list args2;
	static int xlate_loglev[] = {
		LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG
	};

	if (loglev >= log_level)
		return;

	timbuf[0] = '\0';
	timlen = 0;
	if (curlogfd >= 0) {
		time_t now = time(NULL);

		/*
		 * Form a time/date string for file (non-syslog) logging.
		 * Caution: string broken in two so that SCCS doesn't mangle
		 * the %-T-% sequence.
		 */
		timlen = strftime(timbuf, sizeof (timbuf), "%Y/%m/%d %T"
		    "%Z: ", localtime(&now));
	}

	/* Try formatting once into the small buffer. */
	va_copy(args2, args);
	slen = vsnprintf(regbuf, SMALLSTR, fmt, args);
	if (slen < SMALLSTR) {
		ostr = regbuf;
	} else {
		/*
		 * Length returned by vsnprintf doesn't include null,
		 * and may also be missing a terminating \n.
		 */
		ostr = alloca(slen + 2);
		slen = vsnprintf(ostr, slen + 1, fmt, args2);
	}

	/* Don't bother logging empty lines. */
	if (slen <= 0)
		return;

	/* Tack on a \n if needed. */
	if (ostr[slen - 1] != '\n') {
		ostr[slen++] = '\n';
		ostr[slen] = '\0';
	}

	/* Translate our log levels into syslog standard values */
	assert(loglev >= 0 && loglev < Dim(xlate_loglev));
	sloglev = xlate_loglev[loglev];

	/* Log each line separately */
	for (; *ostr != '\0'; ostr = nstr + 1) {
		nstr = strchr(ostr, '\n');

		/* Ignore zero-length lines. */
		if (nstr == ostr)
			continue;

		slen = nstr - ostr + 1;

		/*
		 * If we're supposed to be logging to a file, then try
		 * that first.  Ditch the file and revert to syslog if
		 * any errors occur.
		 */
		if (curlogfd >= 0) {
			if ((retv = dowrite(curlogfd, timbuf, timlen)) > 0)
				retv = dowrite(curlogfd, ostr, slen);

			/*
			 * If we've successfully logged this line,
			 * then go do the next one.
			 */
			if (retv > 0)
				continue;

			/* Save errno (if any) and close log file */
			err1 = errno;
			if (doclose() == -1)
				err2 = errno;
			else
				err2 = 0;

			/*
			 * Recursion is safe here because we cleared
			 * out curlogfd above.
			 */
			if (retv == -1)
				logerr("write log %s: %s", curfname,
				    mystrerror(err1));
			else
				logerr("cannot write %s", curfname);
			if (err2 == 0)
				logdbg("closed log %s", curfname);
			else
				logerr("closing log %s: %s", curfname,
				    mystrerror(err2));
		}
		syslog(sloglev, "%.*s", slen, ostr);
	}
}

/* Log at debug level */
void
logdbg(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogat(LOGLVL_DBG, fmt, args);
	va_end(args);
}

/* Log informational messages */
void
loginfo(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogat(LOGLVL_INFO, fmt, args);
	va_end(args);
}

/* Log warning messages */
void
logwarn(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogat(LOGLVL_WARN, fmt, args);
	va_end(args);
}

/* Log error messages */
void
logerr(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogat(LOGLVL_ERR, fmt, args);
	va_end(args);
}

/* Log a strerror message */
void
logstrerror(const char *emsg)
{
	logerr("%s: %s\n", emsg, mystrerror(errno));
}

void
log_to_stderr(int dbglvl)
{
	log_level = dbglvl;
	if (curlogfd >= 0)
		close_log_files();
	curlogfd = STDERR_FILENO;
	curfname = stderr_name;
}

/*
 * Set indicated log file and debug level.
 */
void
log_for_service(const char *fname, int dbglvl)
{
	int err1, err2;
	boolean_t closed;

	log_level = dbglvl;
	if (fname != NULL &&
	    (*fname == '\0' || strcasecmp(fname, "syslog") == 0))
		fname = NULL;
	if (fname == NULL && curfname == NULL)
		return;
	err1 = err2 = 0;
	closed = B_FALSE;
	if (curlogfd >= 0) {
		if (fname == curfname ||
		    (fname != NULL && strcmp(fname, curfname) == 0)) {
			curfname = fname;
			return;
		}
		if (doclose() == -1)
			err1 = errno;
		closed = B_TRUE;
	}
	if (fname != NULL) {
		curlogfd = open(fname, O_WRONLY|O_APPEND|O_CREAT, 0600);
		if (curlogfd == -1)
			err2 = errno;
	}
	if (closed) {
		if (err1 == 0)
			logdbg("closed log %s", curfname);
		else
			logerr("closing log %s: %s", curfname,
			    mystrerror(err1));
	}
	if (fname != NULL) {
		if (err2 == 0)
			logdbg("opened log %s", fname);
		else
			logerr("opening log %s: %s", fname, mystrerror(err2));
	}
	curfname = fname;
}

/*
 * Close any open log file.  This is used for SIGHUP (to support log
 * file rotation) and when execing.
 */
void
close_log_files(void)
{
	int err = 0;

	if (curlogfd >= 0) {
		if (doclose() == -1)
			err = errno;
		if (err == 0)
			logdbg("closed log %s", curfname);
		else
			logerr("closing log %s: %s", curfname,
			    mystrerror(err));
	}
}

/*
 * Reopen syslog connection; in case it was closed.
 */
void
reopen_log(void)
{
	openlog(prog_name, LOG_PID | LOG_NDELAY | LOG_NOWAIT, LOG_DAEMON);
	/* I control the log level */
	(void) setlogmask(LOG_UPTO(LOG_DEBUG));
}
