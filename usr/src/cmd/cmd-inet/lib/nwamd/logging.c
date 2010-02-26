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
 */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "util.h"

/*
 * logging.c - contains various logging functions.
 */

boolean_t debug = B_TRUE;

/*
 * This idea for having this function is so that you can drop a dtrace probe
 * here and trace complete strings (not just those containing formatting).  Its
 * important that we actually format the debug strings so we could trace them
 * even if we choose not to send them to syslog.
 */
static void
log_out(int severity, const char *str)
{
	if (severity == LOG_DEBUG && !debug)
		return;

	syslog(severity, str);
}

static void
log_format(int severity, const char *fmt, va_list ap, char *buf, int bufsize)
{
	int offset;
	char vbuf[256];

	if (buf == NULL) {
		buf = vbuf;
		bufsize = sizeof (vbuf);
	}

	offset = snprintf(buf, bufsize, "%d: ", pthread_self());
	(void) vsnprintf(buf + offset, bufsize - offset, fmt, ap);

	log_out(severity, buf);
}

/*
 * This function takes a syslog severity and uses it to determine what to do
 * with the message (currently send it to syslog).
 */
void
nlog(int severity, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_format(severity, fmt, ap, NULL, 0);
	va_end(ap);
}

void
pfail(const char *fmt, ...)
{
	char *msg;
	va_list ap;

	msg = malloc(256);

	va_start(ap, fmt);
	log_format(LOG_ERR, fmt, ap, msg, 256);
	va_end(ap);

	if (msg == NULL)
		msg = "ran out of memory exiting.  see log.";

	(void) puts(msg);
	exit(EXIT_FAILURE);
}
