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

#include <stdio.h>
#include <sys/varargs.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#define	MAX_LOG_LEN 2048


void
log(int priority, const char *routine, char *msg, ...)
{
	char header[MAX_LOG_LEN+1];
	char message[MAX_LOG_LEN+1];
	int oldErrno = 0;
	va_list ap;


	oldErrno = errno;

	(void) memset(&header,  0, MAX_LOG_LEN+1);
	(void) memset(&message, 0, MAX_LOG_LEN+1);

	(void) va_start(ap, msg);

	(void) snprintf(header, MAX_LOG_LEN, "%s: %s: %s",
	"MP-API (SUN) Plugin",
	routine,
	msg);

	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vsnprintf(message, MAX_LOG_LEN, header, ap);
	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) syslog(LOG_USER|LOG_DEBUG, message);

	(void) va_end(ap);

	errno = oldErrno;

	oldErrno = priority;
}
