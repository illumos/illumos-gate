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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Logging support for the DR Daemon
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "drd.h"

#define	DRD_MAX_MSG_LEN		512
#define	DRD_MAX_TIME_LEN	32

static char *log_prio_str[] = {
	"EMERG: ",	/* LOG_EMERG */
	"ALERT: ",	/* LOG_ALERT */
	"CRIT: ",	/* LOG_CRIT */
	"ERROR: ",	/* LOG_ERR */
	"WARNING: ",	/* LOG_WARNING */
	"NOTICE: ",	/* LOG_NOTICE */
	"INFO: ",	/* LOG_INFO */
	""		/* LOG_DEBUG */
};

/*
 * Generate a timestamp string in the provided buffer.
 * If any errors are encountered, the function returns
 * with the buffer containing an empty string.
 */
static void
drd_timestamp(char *buf, size_t buflen)
{
	struct tm	ltime;
	struct timeval	now;

	if ((buf == NULL) || (buflen == 0))
		return;

	buf[0] = '\0';

	if (gettimeofday(&now, NULL) != 0) {
		(void) fprintf(stderr, "gettimeofday failed: %s\n",
		    strerror(errno));
		return;
	}

	if (localtime_r(&now.tv_sec, &ltime) == NULL) {
		(void) fprintf(stderr, "localtime_r failed: %s\n",
		    strerror(errno));
		return;
	}

	if (strftime(buf, buflen, "%b %e %T ", &ltime) == 0) {
		(void) fprintf(stderr, "strftime failed: buffer[%d] too "
		    "small\n", buflen);
		/*
		 * On failure, the contents of the buffer
		 * are indeterminate. Restore it to a known
		 * state before returning.
		 */
		buf[0] = '\0';
	}
}

static void
drd_log_msg(int prio, char *fmt, va_list vap)
{
	char msgbuf[DRD_MAX_MSG_LEN];
	char timebuf[DRD_MAX_TIME_LEN] = "";

	/* generate a timestamp for the SMF log */
	drd_timestamp(timebuf, sizeof (timebuf));

	(void) vsnprintf(msgbuf, DRD_MAX_MSG_LEN, fmt, vap);

	/*
	 * Print the message to stderr. In daemon mode, it
	 * will be sent to the SMF log. In standalone mode,
	 * it will be sent to the controlling terminal.
	 */
	(void) fprintf(stderr, "%s%s%s\n", timebuf, log_prio_str[prio], msgbuf);

	if (drd_daemonized)
		syslog(prio, msgbuf);
}

void
drd_err(char *fmt, ...)
{
	va_list vap;

	va_start(vap, fmt);
	drd_log_msg(LOG_ERR, fmt, vap);
	va_end(vap);
}

void
drd_info(char *fmt, ...)
{
	va_list vap;

	va_start(vap, fmt);
	drd_log_msg(LOG_INFO, fmt, vap);
	va_end(vap);
}

void
drd_dbg(char *fmt, ...)
{
	va_list vap;

	if (!drd_debug) {
		/* not debugging */
		return;
	}

	va_start(vap, fmt);
	drd_log_msg(LOG_DEBUG, fmt, vap);
	va_end(vap);
}
