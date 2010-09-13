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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/modctl.h>
#include <errno.h>

/*PRINTFLIKE1*/
void
error(char *fmt, ...)
{
	va_list args;

	int error;

	error = errno;

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	(void) fprintf(stderr, ": ");
	if (errno == ENOSPC)
		(void) fprintf(stderr,
		    "Out of memory or no room in system tables\n");
	else
		perror("");
	va_end(args);
	exit(error);
}

/*PRINTFLIKE1*/
void
fatal(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);
	exit(-1);
}
