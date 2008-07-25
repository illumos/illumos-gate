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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Logging support for the FPS Daemon
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>

#include <fpsapi.h>

#include "fpsd.h"

#define	FPSD_MAX_MSG_HDR_LEN	256
#define	FPSD_MAX_TIME_LEN	32

mutex_t log_mutex;

static char *log_prio_str[] = {
	"ERROR: ",	/* LOG_ERR */
	"WARNING: ",	/* LOG_WARNING */
	"INFO: ",	/* LOG_INFO */
	"DEBUG: "	/* LOG_DEBUG */
};

/*
 * Generate a timestamp string in the provided buffer.
 * If any errors are encountered, the function returns
 * with the buffer containing an empty string.
 */
static void
fpsd_timestamp(char *buf, size_t buflen)
{
	struct	tm	ltime;
	struct	timeval	now;

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
fpsd_log_msg(int prio, const char *fmt, va_list vap)
{
	char msgbuf[FPSD_MAX_MSG_HDR_LEN];
	char timebuf[FPSD_MAX_TIME_LEN] = "";

	if ((prio > debug_level) || (prio < 0))
		return;
	if ((fpsd.d_fg) || (!fpsd.d_daemon)) {
		/* generate a timestamp for output */
		fpsd_timestamp(timebuf, sizeof (timebuf));
		(void) snprintf(msgbuf, sizeof (msgbuf), "%s  %s %s ",
		    timebuf, FPS_DAEMON_NAME, log_prio_str[prio]);
	}

	/* In debug mode, messages will be sent to the controlling terminal */

	if (fpsd.d_fg || !fpsd.d_daemon) {
		(void) fprintf(stderr, "%s", msgbuf);
		(void) vfprintf(stderr, fmt, vap);
		return;
	}

	switch (prio) {

		case FPS_ERROR: /* Log into syslog */
			vsyslog(LOG_ERR, fmt, vap);
			break;

		case FPS_WARNING:
			vsyslog(LOG_WARNING, fmt, vap);
			break;

		case FPS_INFO:
			vsyslog(LOG_INFO, fmt, vap);
			break;

		case FPS_DEBUG:
			vsyslog(LOG_DEBUG, fmt, vap);
			break;
	}

}

void
fpsd_message(int return_code, int msg_type, char *fmt,  ...)
{
	va_list vap;
	(void) mutex_lock(&log_mutex);
	va_start(vap, fmt);
	fpsd_log_msg(msg_type, fmt, vap);
	va_end(vap);
	(void) mutex_unlock(&log_mutex);

	if (return_code > 0)  {
		terminate_process();
		_exit(return_code);
	}
}
