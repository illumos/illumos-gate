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
 * Copyright 2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>

#include "msgs.h"

#ifdef APPTRACE
FILE *tracestream = stderr;
#endif

/*PRINTFLIKE1*/
void
err_msg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#ifdef APPTRACE
/*PRINTFLIKE1*/
void
traceall_msg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(tracestream, fmt, ap);
	va_end(ap);
}
#endif

/*PRINTFLIKE1*/
void
print_n_flush(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vfprintf(stdout, fmt, ap);
	va_end(ap);
	(void) fflush(stdout);
}
