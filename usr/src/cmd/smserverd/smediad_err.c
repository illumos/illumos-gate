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


#include	<stdio.h>
#include	<stdlib.h>
#include	<stdarg.h>
#include	<unistd.h>
#include	<time.h>
#include	<syslog.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/smedia.h>
#include	"smserver.h"

#define	DEBUGMSG	"Level[%d]: %s"

void
fatal(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_CRIT, fmt, ap);
	va_end(ap);

	exit(-1);
}

void
quit(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_ERR, fmt, ap);
	va_end(ap);

	exit(0);
}


void
noise(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
warning(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_WARNING, fmt, ap);
	va_end(ap);
}


void
info(const char *fmt, ...)
{
	extern int	verbose;
	va_list		ap;

	if (verbose == 0) {
		return;
	}

	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_INFO, fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE2*/
void
debug(uint_t level, const char *fmt, ...)
{
	extern int	debug_level;
	va_list		ap;
	char		dbgmsg[BUFSIZ];

	if (level > debug_level) {
		return;
	}

	(void) snprintf(dbgmsg, sizeof (dbgmsg), DEBUGMSG, level, fmt);
	va_start(ap, fmt);
	(void) vsyslog(LOG_DAEMON|LOG_DEBUG, dbgmsg, ap);
	va_end(ap);
}
