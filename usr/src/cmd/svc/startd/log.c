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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2011 Nexenta Systems. All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

/*
 * log.c - debugging and logging functions
 *
 * Logging destinations
 *   svc.startd(8) supports three logging destinations:  the system log, a
 *   daemon-specific log (in the /var/svc/log hierarchy by default), and to the
 *   standard output (redirected to the /var/svc/log/svc.startd.log file by
 *   default).  Any or all of these destinations may be used to
 *   communicate a specific message; the audiences for each destination differ.
 *
 *   Generic messages associated with svc.startd(8) are made by the
 *   log_framework() and log_error() functions.  For these messages, svc.startd
 *   logs under its own name and under the LOG_DAEMON facility when issuing
 *   events to the system log.  By design, severities below LOG_NOTICE are never
 *   issued to the system log.
 *
 *   Messages associated with a specific service instance are logged using the
 *   log_instance() or log_instance_fmri() functions.  These messages are always
 *   sent to the appropriate per-instance log file.
 *
 *   In the case of verbose or debug boot, the log_transition() function
 *   displays messages regarding instance transitions to the system console,
 *   until the expected login services are available.
 *
 *   Finally, log_console() displays messages to the system consoles and
 *   the master restarter log file.  This is used when booting to a milestone
 *   other than 'all'.
 *
 * Logging detail
 *   The constants for severity from <syslog.h> are reused, with a specific
 *   convention here.  (It is worth noting that the #define values for the LOG_
 *   levels are such that more important severities have lower values.)  The
 *   severity determines the importance of the event, and its addressibility by
 *   the administrator.  Each severity level's use is defined below, along with
 *   an illustrative example.
 *
 *   LOG_EMERG		Not used presently.
 *
 *   LOG_ALERT		An unrecoverable operation requiring external
 *			intervention has occurred.   Includes an inability to
 *			write to the smf(7) repository (due to svc.configd(8)
 *			absence, due to permissions failures, etc.).  Message
 *			should identify component at fault.
 *
 *   LOG_CRIT		An unrecoverable operation internal to svc.startd(8)
 *			has occurred.  Failure should be recoverable by restart
 *			of svc.startd(8).
 *
 *   LOG_ERR		An smf(7) event requiring administrative intervention
 *			has occurred.  Includes instance being moved to the
 *			maintenance state.
 *
 *   LOG_WARNING	A potentially destabilizing smf(7) event not requiring
 *			administrative intervention has occurred.
 *
 *   LOG_NOTICE		A noteworthy smf(7) event has occurred.  Includes
 *			individual instance failures.
 *
 *   LOG_INFO		A noteworthy operation internal to svc.startd(8) has
 *			occurred.  Includes recoverable failures or otherwise
 *			unexpected outcomes.
 *
 *   LOG_DEBUG		An internal operation only of interest to a
 *			svc.startd(8) developer has occurred.
 *
 *  Logging configuration
 *    The preferred approach is to set the logging property values
 *    in the options property group of the svc.startd default instance.  The
 *    valid values are "quiet", "verbose", and "debug".  "quiet" is the default;
 *    "verbose" and "debug" allow LOG_INFO and LOG_DEBUG logging requests to
 *    reach the svc.startd.log file, respectively.
 */

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <libgen.h>
#include <libintl.h>
#include <libuutil.h>
#include <locale.h>
#include <malloc.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <zone.h>

#include "startd.h"


#define	LOGBUF_SZ	(60 * 80)			/* 60 lines */

static FILE *logfile = NULL;

/*
 * This parameter can be modified using mdb to turn on & off extended
 * internal debug logging. Although a performance loss can be expected.
 */
static int internal_debug_flags = 0x0;

#ifndef NDEBUG
/*
 * This is a circular buffer for all (even those not emitted externally)
 * logging messages.  To read it properly you should start after the first
 * null, go until the second, and then go back to the beginning until the
 * first null.  Or use ::startd_log in mdb.
 */
static char logbuf[LOGBUF_SZ] = "";
static pthread_mutex_t logbuf_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static void
xstrftime_poststart(char *buf, size_t bufsize, struct timeval *time)
{
	long sec, usec;

	sec = time->tv_sec - st->st_start_time.tv_sec;
	usec = time->tv_usec - st->st_start_time.tv_usec;

	if (usec < 0) {
		sec -= 1;
		usec += 1000000;
	}

	(void) snprintf(buf, bufsize, "start + %d.%02ds", sec, usec / 10000);
}

static void
vlog_prefix(int severity, const char *prefix, const char *format, va_list args)
{
	char buf[512], *cp;
	char timebuf[LOG_DATE_SIZE];
	struct timeval now;
	struct tm ltime;

#ifdef NDEBUG
	if (severity > st->st_log_level_min)
		return;
#endif

	if (gettimeofday(&now, NULL) != 0)
		(void) fprintf(stderr, "gettimeofday(3C) failed: %s\n",
		    strerror(errno));

	if (st->st_log_timezone_known)
		(void) strftime(timebuf, sizeof (timebuf), "%b %e %T",
		    localtime_r(&now.tv_sec, &ltime));
	else
		xstrftime_poststart(timebuf, sizeof (timebuf), &now);

	(void) snprintf(buf, sizeof (buf), "%s/%d%s: ", timebuf, pthread_self(),
	    prefix);
	cp = strchr(buf, '\0');
	(void) vsnprintf(cp, sizeof (buf) - (cp - buf), format, args);

#ifndef NDEBUG
	/* Copy into logbuf. */
	(void) pthread_mutex_lock(&logbuf_mutex);
	if (strlen(logbuf) + strlen(buf) + 1 <= sizeof (logbuf))
		(void) strcat(logbuf, buf);
	else
		(void) strlcpy(logbuf, buf, sizeof (logbuf));
	(void) pthread_mutex_unlock(&logbuf_mutex);

	if (severity > st->st_log_level_min)
		return;
#endif

	if (st->st_log_flags & STARTD_LOG_FILE && logfile) {
		(void) fputs(buf, logfile);
		(void) fflush(logfile);
	}
	if (st->st_log_flags & STARTD_LOG_TERMINAL)
		(void) fputs(buf, stdout);
	if (st->st_log_flags & STARTD_LOG_SYSLOG && st->st_log_timezone_known)
		vsyslog(severity, format, args);
}

/*PRINTFLIKE2*/
void
log_error(int severity, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_prefix(severity, " ERROR", format, args);
	va_end(args);
}

/*PRINTFLIKE2*/
void
log_framework(int severity, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_prefix(severity, "", format, args);
	va_end(args);
}

/*
 * log_framework2() differs from log_framework() by the fact that
 * some checking are done before logging the messages in the internal
 * buffer for performance reasons.
 * The messages aren't logged if:
 * - severity >= LOG_DEBUG and
 * - st_log_level_min < LOG_DEBUG and
 * - internal_debug_flags is not set for 'flags'
 */
void
log_framework2(int severity, int flags, const char *format, ...)
{
	va_list args;

	if ((severity < LOG_DEBUG) ||
	    (internal_debug_flags & flags) ||
	    st->st_log_level_min >= LOG_DEBUG) {
		va_start(args, format);
		vlog_prefix(severity, "", format, args);
		va_end(args);
	}
}

/*
 * void log_preexec()
 *
 * log_preexec() should be invoked prior to any exec(2) calls, to prevent the
 * logfile and syslogd file descriptors from being leaked to child processes.
 * Why openlog(3C) lacks a close-on-exec option is a minor mystery.
 */
void
log_preexec()
{
	closelog();
}

/*
 * void setlog()
 *   Close file descriptors and redirect output.
 */
void
setlog(const char *logstem)
{
	int fd;
	char logfile[PATH_MAX];

	closefrom(0);

	(void) open("/dev/null", O_RDONLY);

	(void) snprintf(logfile, PATH_MAX, "%s/%s", st->st_log_prefix, logstem);

	(void) umask(fmask);
	fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	(void) umask(dmask);

	if (fd == -1)
		return;

	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);

	if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
		startd_close(fd);
}

static int
log_dir_writeable(const char *path)
{
	int fd;
	struct statvfs svb;

	if ((fd = open(path, O_RDONLY, 0644)) == -1)
		return (-1);

	if (fstatvfs(fd, &svb) == -1)
		return (-1);

	if (svb.f_flag & ST_RDONLY) {
		(void) close(fd);

		fd = -1;
	}

	return (fd);
}

static void
vlog_instance(const char *fmri, const char *logstem, boolean_t canlog,
    const char *format, va_list args)
{
	char logfile[PATH_MAX];
	char *message;
	char omessage[1024];
	int fd, err;
	char timebuf[LOG_DATE_SIZE];
	struct tm ltime;
	struct timeval now;

	(void) snprintf(logfile, PATH_MAX, "%s/%s", st->st_log_prefix,
	    logstem);

	(void) umask(fmask);
	fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	err = errno;
	(void) umask(dmask);

	if (fd == -1) {
		if (canlog)
			log_error(LOG_NOTICE, "Could not log for %s: open(%s) "
			    "failed with %s.\n", fmri, logfile, strerror(err));

		return;
	}

	(void) vsnprintf(omessage, sizeof (omessage), format, args);

	if (gettimeofday(&now, NULL) != 0)
		(void) fprintf(stderr, "gettimeofday(3C) failed: %s\n",
		    strerror(errno));

	if (st->st_log_timezone_known)
		(void) strftime(timebuf, sizeof (timebuf), "%b %e %T",
		    localtime_r(&now.tv_sec, &ltime));
	else
		xstrftime_poststart(timebuf, sizeof (timebuf), &now);

	message = uu_msprintf("[ %s %s ]\n", timebuf, omessage);

	if (message == NULL) {
		if (canlog)
			log_error(LOG_NOTICE, "Could not log for %s: %s.\n",
			    fmri, uu_strerror(uu_error()));
	} else {
		if (write(fd, message, strlen(message)) < 0 && canlog)
			log_error(LOG_NOTICE, "Could not log for %s: write(%d) "
			    "failed with %s.\n", fmri, fd,
			    strerror(errno));

		uu_free(message);
	}

	if (close(fd) != 0 && canlog)
		log_framework(LOG_NOTICE, "close(%d) failed: %s.\n", fd,
		    strerror(errno));
}

/*
 * void log_instance(const restarter_inst_t *, boolean_t, const char *, ...)
 *
 * The log_instance() format is "[ month day time message ]".  (The
 * brackets distinguish svc.startd messages from method output.)  We avoid
 * calling log_*() functions on error when canlog is not set, since we may
 * be called from a child process.
 *
 * When adding new calls to this function, consider: If this is called before
 * any instances have started, then it should be called with canlog clear,
 * lest we spew errors to the console when booted on the miniroot.
 */
/*PRINTFLIKE3*/
void
log_instance(const restarter_inst_t *inst, boolean_t canlog,
    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_instance(inst->ri_i.i_fmri, inst->ri_logstem, canlog, format,
	    args);
	va_end(args);
}

/*
 * void log_instance_fmri(const char *, const char *,boolean_t, const char *,
 *    ...)
 *
 * The log_instance_fmri() format is "[ month day time message ]".  (The
 * brackets distinguish svc.startd messages from method output.)  We avoid
 * calling log_*() functions on error when canlog is not set, since we may
 * be called from a child process.
 *
 * For new calls to this function, see the warning in log_instance()'s
 * comment.
 */
/*PRINTFLIKE4*/
void
log_instance_fmri(const char *fmri, const char *logstem, boolean_t canlog,
    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_instance(fmri, logstem, canlog, format, args);
	va_end(args);
}

/*
 * void log_transition(const restarter_inst_t *, start_outcome_t)
 *
 * The log_transition() format is
 *
 *   [ _service_fmri_ _participle_ (_common_name_) ]
 *
 * Again, brackets separate messages from specific service instance output to
 * the console.
 */
void
log_transition(const restarter_inst_t *inst, start_outcome_t outcome)
{
	char *message;
	char omessage[1024];
	char *action;
	int severity;

	if (outcome == START_REQUESTED) {
		char *cname = NULL;

		cname = inst->ri_common_name;
		if (cname == NULL)
			cname = inst->ri_C_common_name;

		if (!(st->st_boot_flags & STARTD_BOOT_VERBOSE))
			return;

		if (inst->ri_start_index > 1)
			return;

		if (cname)
			(void) snprintf(omessage, sizeof (omessage), " (%s)",
			    cname);
		else
			*omessage = '\0';

		action = gettext("starting");

		message = uu_msprintf("[ %s %s%s ]\n",
		    inst->ri_i.i_fmri + strlen("svc:/"), action,
		    omessage);

		severity = LOG_INFO;
	} else {
		switch (outcome) {
		case DEGRADE_REQUESTED:
			action = gettext("transitioned to degraded by "
			    "request (see 'svcs -xv' for details)");
			break;
		case MAINT_REQUESTED:
			action = gettext("transitioned to maintenance by "
			    "request (see 'svcs -xv' for details)");
			break;
		case START_FAILED_REPEATEDLY:
			action = gettext("failed repeatedly: transitioned to "
			    "maintenance (see 'svcs -xv' for details)");
			break;
		case START_FAILED_CONFIGURATION:
			action = gettext("misconfigured: transitioned to "
			    "maintenance (see 'svcs -xv' for details)");
			break;
		case START_FAILED_FATAL:
			action = gettext("failed fatally: transitioned to "
			    "maintenance (see 'svcs -xv' for details)");
			break;
		case START_FAILED_TIMEOUT_FATAL:
			action = gettext("timed out: transitioned to "
			    "maintenance (see 'svcs -xv' for details)");
			break;
		case START_FAILED_DEGRADED:
			action = gettext("transitioned to degraded "
			    "(see 'svcs -xv' for details)");
			break;
		case START_FAILED_OTHER:
			action = gettext("failed: transitioned to "
			    "maintenance (see 'svcs -xv' for details)");
			break;
		case START_REQUESTED:
			assert(outcome != START_REQUESTED);
			/*FALLTHROUGH*/
		default:
			action = gettext("outcome unknown?");
		}

		message = uu_msprintf("[ %s %s ]\n",
		    inst->ri_i.i_fmri + strlen("svc:/"), action);

		severity = LOG_ERR;
	}


	if (message == NULL) {
		log_error(LOG_NOTICE,
		    "Could not log boot message for %s: %s.\n",
		    inst->ri_i.i_fmri, uu_strerror(uu_error()));
	} else {
		/*
		 * All significant errors should to go to syslog to
		 * communicate appropriate information even for systems
		 * without a console connected during boot.  Send the
		 * message to stderr only if the severity is lower than
		 * (indicated by >) LOG_ERR.
		 */
		if (!st->st_log_login_reached && severity > LOG_ERR) {
			/*LINTED*/
			if (fprintf(stderr, message) < 0)
				log_error(LOG_NOTICE, "Could not log for %s: "
				    "fprintf() failed with %s.\n",
				    inst->ri_i.i_fmri, strerror(errno));
		} else {
			log_framework(severity, "%s %s\n",
			    inst->ri_i.i_fmri + strlen("svc:/"), action);
		}

		uu_free(message);
	}
}

/*
 * log_console - log a message to the consoles and to syslog
 *
 * This logs a message as-is to the console (and auxiliary consoles),
 * as well as to the master restarter log.
 */
/*PRINTFLIKE2*/
void
log_console(int severity, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_prefix(severity, "", format, args);
	va_end(args);

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	va_end(args);
}

/*
 * void log_init()
 *
 * Set up the log files, if necessary, for the current invocation.  This
 * function should be called before any other functions in this file.  Set the
 * syslog(3C) logging mask such that severities of the importance of
 * LOG_NOTICE and above are passed through, but lower severity messages are
 * masked out.
 *
 * It may be called multiple times to change the logging configuration due to
 * administrative request.
 */
void
log_init()
{
	int dirfd, logfd;
	char *dir;
	struct stat sb;

	if (st->st_start_time.tv_sec == 0) {
		if (getzoneid() != GLOBAL_ZONEID) {
			st->st_start_time.tv_sec = time(NULL);
		} else {
			/*
			 * We need to special-case the BOOT_TIME utmp entry, and
			 * drag that value out of the kernel if it's there.
			 */
			kstat_ctl_t *kc;
			kstat_t *ks;
			kstat_named_t *boot;

			if (((kc = kstat_open()) != 0) &&
			    ((ks = kstat_lookup(kc, "unix", 0, "system_misc"))
			    != NULL) &&
			    (kstat_read(kc, ks, NULL) != -1) &&
			    ((boot = kstat_data_lookup(ks, "boot_time")) !=
			    NULL)) {
				/*
				 * If we're here, then we've successfully found
				 * the boot_time kstat... use its value.
				 */
				st->st_start_time.tv_sec = boot->value.ul;
			} else {
				st->st_start_time.tv_sec = time(NULL);
			}

			if (kc)
				(void) kstat_close(kc);
		}
	}

	/*
	 * Establish our timezone if the appropriate directory is available.
	 */
	if (!st->st_log_timezone_known && stat(FS_TIMEZONE_DIR, &sb) == 0) {
		tzset();
		st->st_log_timezone_known = 1;
	}

	/*
	 * Establish our locale if the appropriate directory is available.  Set
	 * the locale string from the environment so we can extract template
	 * information correctly, if the locale directories aren't yet
	 * available.
	 */
	if (st->st_locale != NULL)
		free(st->st_locale);

	if ((st->st_locale = getenv("LC_ALL")) == NULL)
		if ((st->st_locale = getenv("LC_MESSAGES")) == NULL)
			st->st_locale = getenv("LANG");

	if (!st->st_log_locale_known && stat(FS_LOCALE_DIR, &sb) == 0) {
		(void) setlocale(LC_ALL, "");
		st->st_locale = setlocale(LC_MESSAGES, NULL);
		if (st->st_locale)
			st->st_log_locale_known = 1;

		(void) textdomain(TEXT_DOMAIN);
	}

	if (st->st_locale) {
		st->st_locale = safe_strdup(st->st_locale);
		xstr_sanitize(st->st_locale);
	}

	if (logfile) {
		(void) fclose(logfile);
		logfile = NULL;
	}

	/*
	 * Set syslog(3C) behaviour in all cases.
	 */
	closelog();
	openlog("svc.startd", LOG_PID | LOG_CONS, LOG_DAEMON);
	(void) setlogmask(LOG_UPTO(LOG_NOTICE));

	if ((dirfd = log_dir_writeable(LOG_PREFIX_NORMAL)) == -1) {
		if ((dirfd = log_dir_writeable(LOG_PREFIX_EARLY)) == -1)
			return;
		else
			dir = LOG_PREFIX_EARLY;
	} else {
		dir = LOG_PREFIX_NORMAL;
	}

	st->st_log_prefix = dir;

	(void) umask(fmask);
	if ((logfd = openat(dirfd, STARTD_DEFAULT_LOG,
	    O_CREAT | O_RDWR | O_APPEND, 0644)) == -1) {
		(void) close(dirfd);
		(void) umask(dmask);
		return;
	}

	(void) close(dirfd);
	(void) umask(dmask);

	if ((logfile = fdopen(logfd, "a")) == NULL)
		if (errno != EROFS)
			log_error(LOG_WARNING, "can't open logfile %s/%s",
			    dir, STARTD_DEFAULT_LOG);

	if (logfile &&
	    fcntl(fileno(logfile), F_SETFD, FD_CLOEXEC) == -1)
		log_error(LOG_WARNING,
		    "couldn't mark logfile close-on-exec: %s\n",
		    strerror(errno));
}
