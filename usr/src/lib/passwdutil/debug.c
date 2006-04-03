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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

#define	DEBUG_NONE	0
#define	DEBUG_SYSLOG	1
#define	DEBUG_STDERR	2

/* Change and recompile or modify with a debugger */
int debug_enabled = 0;

/*PRINTFLIKE1*/
void
debug(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	switch (debug_enabled) {
	case DEBUG_NONE:
		break;
	case DEBUG_SYSLOG:
		vsyslog(LOG_DEBUG, fmt, ap);
		break;
	case DEBUG_STDERR:
		(void) vfprintf(stderr, fmt, ap);
		(void) fprintf(stderr, "\n");
		break;
	}
	va_end(ap);
}
