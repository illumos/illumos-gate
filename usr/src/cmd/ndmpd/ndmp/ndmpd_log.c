/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <pthread.h>
#include <errno.h>
#include "ndmpd_log.h"
#include "ndmpd.h"
#include "ndmpd_common.h"

#define	LOG_PATH	"/var/log/ndmp"
#define	LOG_FNAME	"ndmplog.%d"
#define	LOG_FILE_CNT	5
#define	LOG_FILE_SIZE	4 * 1024 * 1024
#define	LOG_SIZE_INT	256

static boolean_t debug = B_FALSE;
static boolean_t log_to_stderr = B_FALSE;
static FILE *logfp;
static int ndmp_synclog = 1;


/*
 * Since we use buffered file I/O for log file, the thread may lose CPU.
 * At this time, another thread can destroy the contents of the buffer
 * that must be written to the log file.  The following mutex is used
 * to allow only one thread to write into the log file.
 */
static mutex_t log_lock;

static char *priority_str[] = {
	"EMERGENCY",
	"ALERT",
	"CRITICAL",
	"ERROR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG",
};


/*
 * mk_pathname
 *
 * Append the NDMP working directory path to the specified file
 */
static char *
mk_pathname(char *fname, char *path, int idx)
{
	static char buf[PATH_MAX];
	static char name[NAME_MAX];
	char *fmt;
	int len;

	len = strnlen(path, PATH_MAX);
	fmt = (path[len - 1] == '/') ? "%s%s" : "%s/%s";

	/* LINTED variable format specifier */
	(void) snprintf(name, NAME_MAX, fname, idx);

	/* LINTED variable format specifier */
	(void) snprintf(buf, PATH_MAX, fmt, path, name);
	return (buf);
}


/*
 * openlogfile
 *
 * Open the NDMP log file
 */
static int
openlogfile(char *fname, char *mode)
{
	assert(fname != NULL && *fname != '\0' &&
	    mode != NULL && *mode != '\0');

	if ((logfp = fopen(fname, mode)) == NULL) {
		perror("Error opening logfile");
		return (-1);
	}
	(void) mutex_init(&log_lock, 0, NULL);

	return (0);
}


/*
 * log_write_cur_time
 *
 * Add the current time for each log entry
 */
static void
log_write_cur_time(void)
{
	struct tm tm;
	time_t secs;

	secs = time(NULL);
	(void) localtime_r(&secs, &tm);
	(void) fprintf(logfp, "%2d/%02d %2d:%02d:%02d ",
	    tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}


/*
 * add_newline
 *
 * The new line at the end of each log
 */
static void
add_newline(char *fmt)
{
	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fputc('\n', logfp);
}


/*
 * log_append
 *
 * Append the message to the end of the log
 */
static void
log_append(char *msg)
{
	log_write_cur_time();
	(void) fwrite(msg, 1, strlen(msg), logfp);
	add_newline(msg);
	if (ndmp_synclog)
		(void) fflush(logfp);
}


/*
 * ndmp_log_openfile
 *
 * Open the log file either for append or write mode. This function should
 * be called while ndmpd is still running single-threaded and in foreground.
 */
int
ndmp_log_open_file(boolean_t to_stderr, boolean_t override_debug)
{
	char *fname, *mode, *lpath;
	char oldfname[PATH_MAX];
	struct stat64 st;
	int i;

	log_to_stderr = to_stderr;

	/* read debug property if it isn't overriden by cmd line option */
	if (override_debug)
		debug = B_TRUE;
	else
		debug = ndmpd_get_prop_yorn(NDMP_DEBUG_MODE) ? B_TRUE : B_FALSE;

	/* Create the debug path if it doesn't exist */
	lpath = ndmpd_get_prop(NDMP_DEBUG_PATH);
	if ((lpath == NULL) || (*lpath == NULL))
		lpath = LOG_PATH;

	if (stat64(lpath, &st) < 0) {
		if (mkdirp(lpath, 0755) < 0) {
			(void) fprintf(stderr,
			    "Could not create log path %s: %s\n",
			    lpath, strerror(errno));
			lpath = "/var";
		}
	}

	/*
	 * NDMP log file name will be {logfilename}.0 to {logfilename}.5, where
	 * {logfilename}.0 will always be the latest and the {logfilename}.5
	 * will be the oldest available file on the system. We keep maximum of 5
	 * log files. With the new session the files are shifted to next number
	 * and if the last file {logfilename}.5 exist, it will be overwritten
	 * with {logfilename}.4.
	 */
	if (debug) {
		i = LOG_FILE_CNT - 1;
		while (i >= 0) {
			fname = mk_pathname(LOG_FNAME, lpath, i);
			(void) strncpy(oldfname, fname, PATH_MAX);
			if (stat64(oldfname, &st) == -1) {
				i--;
				continue;
			}

			fname = mk_pathname(LOG_FNAME, lpath, i + 1);
			if (rename(oldfname, fname))
				(void) fprintf(stderr,
				    "Could not rename %s to %s: %s\n",
				    oldfname, fname, strerror(errno));
			i--;
		}
	}

	fname = mk_pathname(LOG_FNAME, lpath, 0);

	/*
	 * Append only if debug is not enable.
	 */
	if (debug)
		mode = "w";
	else
		mode = "a";

	return (openlogfile(fname, mode));
}

/*
 * ndmp_log_close_file
 *
 * Close the log file
 */
void
ndmp_log_close_file(void)
{
	if (logfp != NULL) {
		(void) fclose(logfp);
		logfp = NULL;
	}
	(void) mutex_destroy(&log_lock);
}

void
ndmp_log(ulong_t priority, char *ndmp_log_info, char *fmt, ...)
{
	int c;
	va_list args;
	char *f, *b;
	char ndmp_log_buf[PATH_MAX+KILOBYTE];
	char ndmp_syslog_buf[PATH_MAX+KILOBYTE];
	char buf[PATH_MAX+KILOBYTE];
	char *errstr;

	if ((priority == LOG_DEBUG) && !debug)
		return;

	(void) mutex_lock(&log_lock);

	if (priority > 7)
		priority = LOG_ERR;

	va_start(args, fmt);
	/* Replace text error messages if fmt contains %m */
	b = buf;
	f = fmt;
	while (((c = *f++) != '\0') && (c != '\n') &&
	    (b < &buf[PATH_MAX+KILOBYTE])) {
		if (c != '%') {
			*b++ = c;
			continue;
		}
		if ((c = *f++) != 'm') {
			*b++ = '%';
			*b++ = c;
			continue;
		}

		if ((errstr = strerror(errno)) == NULL) {
			(void) snprintf(b, &buf[PATH_MAX+KILOBYTE] - b,
			    "error %d", errno);
		} else {
			while ((*errstr != '\0') &&
			    (b < &buf[PATH_MAX+KILOBYTE])) {
				if (*errstr == '%') {
					(void) strncpy(b, "%%", 2);
					b += 2;
				} else {
					*b++ = *errstr;
				}
				errstr++;
			}
			*b = '\0';
		}
		b += strlen(b);
	}
	*b = '\0';

	/* LINTED variable format specifier */
	(void) vsnprintf(ndmp_syslog_buf, sizeof (ndmp_syslog_buf), buf, args);
	va_end(args);

	/* Send all logs other than debug, to syslog log file. */
	if (priority != LOG_DEBUG)
		syslog(priority, "%s", ndmp_syslog_buf);

	/* ndmp_log_buf will have priority string and log info also */
	(void) snprintf(ndmp_log_buf, sizeof (ndmp_log_buf), "%s: %s:%s",
	    priority_str[priority], ndmp_log_info, ndmp_syslog_buf);

	if (logfp != NULL)
		log_append(ndmp_log_buf);

	/* if ndmpd is running in foreground print log message to stderr */
	if (log_to_stderr)
		(void) fprintf(stderr, "%s\n", ndmp_log_buf);

	(void) mutex_unlock(&log_lock);
}
