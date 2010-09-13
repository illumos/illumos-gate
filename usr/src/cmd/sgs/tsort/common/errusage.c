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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include  "errmsg.h"
#include  <stdio.h>
#include  <stdarg.h>
#include  <locale.h>

#define	USAGENO  255	/* exit value for usage messages */

/*
 *	This routine prints the standard command usage message.
 */

/* PRINTFLIKE1 */
void
errusage(char *format, ...)
{
	va_list	ap;

	(void) fputs(gettext("Usage:  "), stderr);
	if (Err.vsource && Err.source) {
		(void) fputs(Err.source, stderr);
		(void) fputc(' ', stderr);
	}
	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	(void) fputc('\n', stderr);
	(void) errexit(USAGENO);
	erraction(EEXIT);
}
