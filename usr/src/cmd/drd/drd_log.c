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
#include <syslog.h>

#include "drd.h"

#define	DRD_MAX_MSG_LEN		512

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

static void
drd_log_msg(int priority, char *fmt, va_list vap)
{
	char	msg_str[DRD_MAX_MSG_LEN];

	(void) vsnprintf(msg_str, DRD_MAX_MSG_LEN, fmt, vap);

	if (!drd_daemonized) {
		fprintf(stderr, "%s%s\n", log_prio_str[priority], msg_str);
		return;
	}

	syslog(priority, msg_str);
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
