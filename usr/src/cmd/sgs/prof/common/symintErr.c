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

#include "symint.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

/*
 * symintFcns.c -- symbol information interface routines.
 *
 * these routines form a symbol information access
 * interface, for the profilers to get at object file
 * information.  this interface was designed to aid
 * in the COFF to ELF conversion of prof, lprof and friends.
 *
 */


/*
 * _err_exit(format_s, va_alist)
 * format_s	- printf(3C) arg string.
 * va_alist	- varargs(3EXT) printf() arguments.
 *
 * does not return - prints message and calls exit(3).
 *
 *
 * this routine spits out a message (passed as above)
 * and exits.
 */

/* PRINTFLIKE1 */
void
_err_exit(char *format_s, ...)
{
	va_list ap;

	(void) fprintf(stderr, "fatal error: ");
	va_start(ap, format_s);
	(void) vfprintf(stderr, format_s, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");

	exit(1);
}
