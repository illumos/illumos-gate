/***************************************************************************
 * CVSID: $Id$
 *
 * logger.c : Logging
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2006 Danny Kukawka, <danny.kukawka@web.de>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#include "logger.h"

/**
 * @defgroup HalDaemonLogging Logging system
 * @ingroup HalDaemon
 * @brief Logging system for the HAL daemon
 * @{
 */


static int priority;
static const char *file;
static int line;
static const char *function;

static int log_pid  = 0;
static int is_enabled = 1;
static int syslog_enabled = 0;


/** Disable all logging
 *
 */
void
logger_disable (void)
{
	is_enabled = 0;
}

/** Enable all logging
 *
 */
void
logger_enable (void)
{
	is_enabled = 1;
}

/** enable usage of syslog for logging
 *
 */
void
logger_enable_syslog (void)
{
	syslog_enabled = 1;
}

/** disable usage of syslog for logging
 *
 */
void
logger_disable_syslog (void)
{
	syslog_enabled = 0;
}

/** allow setup logger from a addon/prober via the env
 *
 */
void
setup_logger (void)
{
        if ((getenv ("HALD_VERBOSE")) != NULL) {
                is_enabled = 1;
		log_pid = 1;
	}
        else
                is_enabled = 0;

        if ((getenv ("HALD_USE_SYSLOG")) != NULL)
		syslog_enabled = 1;
        else
                syslog_enabled = 0;
}

/** Setup logging entry
 *
 *  @param  priority            Logging priority, one of HAL_LOGPRI_*
 *  @param  file                Name of file where the log entry originated
 *  @param  line                Line number of file
 *  @param  function            Name of function
 */
void
logger_setup (int _priority, const char *_file, int _line, const char *_function)
{
	priority = _priority;
	file = _file;
	line = _line;
	function = _function;
}

/** Emit logging entry
 *
 *  @param  format              Message format string, printf style
 *  @param  ...                 Parameters for message, printf style
 */
void
logger_emit (const char *format, ...)
{
	va_list args;
	char buf[512];
	char *pri;
	char tbuf[256];
	char logmsg[1024];
	struct timeval tnow;
	struct tm *tlocaltime;
	struct timezone tzone;
	static pid_t pid = -1;

	if (!is_enabled)
		return;

	va_start (args, format);
	vsnprintf (buf, sizeof (buf), format, args);

	switch (priority) {
		case HAL_LOGPRI_TRACE:
			pri = "[T]";
			break;
		case HAL_LOGPRI_DEBUG:
			pri = "[D]";
			break;
		case HAL_LOGPRI_INFO:
			pri = "[I]";
			break;
		case HAL_LOGPRI_WARNING:
			pri = "[W]";
			break;
		default:		/* explicit fallthrough */
		case HAL_LOGPRI_ERROR:
			pri = "[E]";
			break;
	}

	gettimeofday (&tnow, &tzone);
	tlocaltime = localtime (&tnow.tv_sec);
	strftime (tbuf, sizeof (tbuf), "%H:%M:%S", tlocaltime);

	if (log_pid) {
        	if ((int) pid == -1)
                	pid = getpid ();
		snprintf (logmsg, sizeof(logmsg), "[%d]: %s.%03d %s %s:%d: %s\n", pid, tbuf, (int)(tnow.tv_usec/1000), pri, file, line, buf);
	} else {
		snprintf (logmsg, sizeof(logmsg), "%s.%03d %s %s:%d: %s\n", tbuf, (int)(tnow.tv_usec/1000), pri, file, line, buf);
	}

	/** @todo Make programmatic interface to logging */
	if (priority != HAL_LOGPRI_TRACE && !syslog_enabled ) {
		fprintf (stderr, "%s", logmsg );
	} else if (priority != HAL_LOGPRI_TRACE && syslog_enabled ) {
		/* use syslog for debug/log messages if HAL started as daemon */
		switch (priority) {
			case HAL_LOGPRI_DEBUG:
			case HAL_LOGPRI_INFO:
				syslog(LOG_INFO, "%s", logmsg );
				break;
			case HAL_LOGPRI_WARNING:
				syslog(LOG_WARNING, "%s", logmsg );
				break;
			default:		 /* explicit fallthrough */
			case HAL_LOGPRI_ERROR:
				syslog(LOG_ERR, "%s", logmsg );
				break;
		}
	}

	va_end (args);
}

void
logger_forward_debug (const char *format, ...)
{
	va_list args;
        char buf[512];
        char tbuf[256];
        struct timeval tnow;
        struct tm *tlocaltime;
        struct timezone tzone;
        static pid_t pid = -1;

        if (!is_enabled)
                return;

        if ((int) pid == -1)
                pid = getpid ();

	va_start (args, format);
        vsnprintf (buf, sizeof (buf), format, args);

        gettimeofday (&tnow, &tzone);
        tlocaltime = localtime (&tnow.tv_sec);
        strftime (tbuf, sizeof (tbuf), "%H:%M:%S", tlocaltime);

        if (syslog_enabled)
                syslog (LOG_INFO, "%d: %s.%03d: %s", pid, tbuf, (int)(tnow.tv_usec/1000), buf);
        else
                fprintf (stderr, "%d: %s.%03d: %s", pid, tbuf, (int)(tnow.tv_usec/1000), buf);

        va_end (args);
}

/** @} */
