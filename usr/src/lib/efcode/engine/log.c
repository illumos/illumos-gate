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

/*
 * Daemon log message.  This can direct log messages to either stdout,
 * an error log file or syslog (or any combination).
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <fcode/private.h>
#include <fcode/log.h>

#define	LOG_LINESIZE		256
#define	LOG_EMIT_BUFSIZE	LOG_LINESIZE

static FILE *error_log_fp = NULL;
static int syslog_opened = 0;
static int error_log_flags;
static int syslog_log_flags;
static int do_emit_flag = -1;
static int daemon_log_flag;
static int min_syslog_level = LOG_ERR;

static int log_to_stdout(int);
static int log_to_error_log(int);
static int log_to_syslog(int);
static int msg_level_to_syslog(int);

/*
 * Complicated by not wanting to do any emit processing if no one's actually
 * going to see it.
 */
void
log_emit(char c)
{
	static char emit_buf[LOG_EMIT_BUFSIZE];
	static char *emit_p = emit_buf;
	static int lastnl = 1;

	/*
	 * No one has set the do_emit_flag, go ahead and figure it out.
	 */
	if (do_emit_flag < 0) {
		do_emit_flag = (log_to_stdout(MSG_EMIT) |
		    log_to_error_log(MSG_EMIT) | log_to_syslog(MSG_EMIT));
	}

	if (!do_emit_flag)
		return;

	/*
	 * Check for buffer overflow.
	 */
	if (emit_p >= &emit_buf[LOG_EMIT_BUFSIZE - 1]) {
		*emit_p = '\0';
		log_message(MSG_EMIT, "emit: %s\n", emit_buf);
		emit_p = emit_buf;
		lastnl = 1;
	}

	/*
	 * Fcode emit's may output both CR/LF, we go ahead and eat multiple
	 * ones in succession.
	 */
	if (c == '\n' || c == '\r') {
		if (!lastnl) {
			*emit_p = '\0';
			log_message(MSG_EMIT, "emit: %s\n", emit_buf);
			emit_p = emit_buf;
		}
		lastnl = 1;
	} else {
		lastnl = 0;
		*emit_p++ = c;
	}
}

/*
 * If stdout is a tty and this is MSG_EMIT, we should have alredy output it.
 * If running as daemon, output to stdout is a waste of time.
 */
static int
log_to_stdout(int msg_level)
{
	if (isatty(fileno(stdin)) && (msg_level & MSG_EMIT) != 0)
		return (0);
	return (daemon_log_flag == 0);
}

/*
 * Can't turn off FATAL or ERROR messages to error log file.
 */
static int
log_to_error_log(int msg_level)
{
	if (!error_log_fp)
		return (0);
	if (msg_level & (MSG_FATAL|MSG_ERROR))
		return (1);
	return (msg_level & error_log_flags);
}

/*
 * Can't turn off FATAL or ERROR messages to syslog.
 */
static int
log_to_syslog(int msg_level)
{
	if (!syslog_opened)
		return (0);
	if (msg_level & (MSG_FATAL|MSG_ERROR))
		return (1);
	return (msg_level & syslog_log_flags);
}

/*
 * Turn internal MSG level to syslog msg level.  Don't return a msg level
 * lower priority than min_syslog_level.
 */
static int
msg_level_to_syslog(int msg_level)
{
	if (min_syslog_level <= LOG_ERR)
		return (min_syslog_level);
	if (msg_level & (MSG_FATAL|MSG_ERROR))
		return (LOG_ERR);
	if (min_syslog_level <= LOG_WARNING)
		return (min_syslog_level);
	if (msg_level & MSG_WARN)
		return (LOG_WARNING);
	if (min_syslog_level <= LOG_NOTICE)
		return (min_syslog_level);
	if (msg_level & MSG_NOTE)
		return (LOG_NOTICE);
	if (min_syslog_level <= LOG_INFO)
		return (min_syslog_level);
	if (msg_level & MSG_INFO)
		return (LOG_INFO);
	return (min(min_syslog_level, LOG_DEBUG));
}

/*
 * Log a message to the appropriate places.
 */
void
log_message(int msg_level, char *fmt, ...)
{
	va_list ap;
	char msg[LOG_LINESIZE], *p;
	static char log_msg[LOG_LINESIZE];

	va_start(ap, fmt);

	vsprintf(msg, fmt, ap);

	if (log_to_stdout(msg_level)) {
		printf(msg);
		fflush(stdout);
	}
	if (log_to_error_log(msg_level)) {
		fprintf(error_log_fp, msg);
		fflush(error_log_fp);
	}
	if (log_to_syslog(msg_level)) {
		if (strlen(log_msg) + strlen(msg) > LOG_LINESIZE - 1) {
			syslog(msg_level_to_syslog(msg_level), log_msg);
			log_msg[0] = '\0';
		}
		strcat(log_msg, msg);
		if ((p = strchr(log_msg, '\n')) != NULL) {
			*p = '\0';
			syslog(msg_level_to_syslog(msg_level), log_msg);
			log_msg[0] = '\0';
		}
	}
}

/*
 * Output debug message
 */
void
debug_msg(int debug_level, char *fmt, ...)
{
	va_list ap;
	char msg[LOG_LINESIZE];

	if ((debug_level & get_interpreter_debug_level()) == 0)
		return;

	va_start(ap, fmt);

	vsprintf(msg, fmt, ap);

	log_message(MSG_DEBUG, msg);
}

/*
 * Log a perror message to the appropriate places.
 */
void
log_perror(int msg_level, char *fmt, ...)
{
	va_list ap;
	char msg[LOG_LINESIZE], tmp[LOG_LINESIZE];

	va_start(ap, fmt);

	vsprintf(msg, fmt, ap);
	sprintf(tmp, "%s: %s\n", msg, strerror(errno));
	log_message(msg_level, tmp);
}

void
set_min_syslog_level(int level)
{
	min_syslog_level = level;
}

char *error_log_name;

void
open_error_log(char *fname, int errflags)
{
	if ((error_log_fp = fopen(fname, "a")) == NULL) {
		log_perror(MSG_FATAL, fname);
		exit(1);
	}
	error_log_name = STRDUP(fname);
	error_log_flags = errflags;
	do_emit_flag = (log_to_stdout(MSG_EMIT) | log_to_error_log(MSG_EMIT) |
	    log_to_syslog(MSG_EMIT));
}

void
open_syslog_log(char *logname, int logflags)
{
	openlog(logname, LOG_PID, LOG_DAEMON);
	syslog_log_flags = logflags;
	do_emit_flag = (log_to_stdout(MSG_EMIT) | log_to_error_log(MSG_EMIT) |
	    log_to_syslog(MSG_EMIT));
	syslog_opened = 1;
}

/*
 * Turn on/off syslog LOG_DAEMON flag to syslog messages.  Also controls
 * outputting to stdout, which is a waste of time when we're running as a
 * daemon.
 */
void
set_daemon_log_flag(int flag)
{
	if (flag)
		daemon_log_flag = LOG_DAEMON;
	else
		daemon_log_flag = 0;
}

int
parse_msg_flags(char *flags)
{
	int msgflags = 0;
	char c;

	while ((c = *flags++) != '\0') {
		switch (c) {
		case 'f': msgflags |= MSG_FATAL; break;
		case 'e': msgflags |= MSG_ERROR; break;
		case 'w': msgflags |= MSG_WARN;  break;
		case 'i': msgflags |= MSG_INFO;  break;
		case 'd': msgflags |= MSG_DEBUG; break;
		case 'D': msgflags |= MSG_FC_DEBUG; break;

		default:
			log_message(MSG_ERROR, "Invalid msglvl flag: %c\n", c);
			break;
		}
	}
	return (msgflags);
}

#define	MAXERRBUF	256
char error_buffer[MAXERRBUF];

static void
dot_error_buffer(fcode_env_t *env)
{
	log_message(MSG_INFO, "%s\n", error_buffer);
}

static void
set_error_log(fcode_env_t *env)
{
	char *fname;
	FILE *fp;

	parse_word(env);
	fname = pop_a_string(env, NULL);
	if (fname != NULL) {
		if ((fp = fopen(fname, "a")) == NULL) {
			log_perror(MSG_ERROR, "Can't open '%s'\n", fname);
			return;
		}
		if (error_log_fp)
			fclose(error_log_fp);
		if (error_log_name)
			FREE(error_log_name);
		error_log_fp = fp;
		error_log_name = STRDUP(fname);
		error_log_flags = MSG_FATAL|MSG_ERROR|MSG_WARN|MSG_INFO|
		    MSG_DEBUG|MSG_FC_DEBUG;
	} else if (error_log_name)
		log_message(MSG_INFO, "%s\n", error_log_name);
	else
		log_message(MSG_INFO, "NULL\n");
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	".error-buffer",	dot_error_buffer);
	FORTH(0,	"set-error-log",	set_error_log);
}
