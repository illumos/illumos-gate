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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	vsscanf.c
 *
 *	Copyright 1985, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *	
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_vsscan.c 1.2 1994/06/17 18:19:41 ant Exp $";
#endif
#endif

#include <mks.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

extern int mks_vfscanf ANSI((FILE *, char *, va_list));

LDEFN int
m_vsscanf(buf, fmt, vp)
char *buf, *fmt;
va_list vp;
{
	static FILE *fp = NULL;

	/* Either open or reuse a temporary file.  Note temporary files
	 * opened by tmpfile() will be automatically closed and removed 
	 * when the program terminates (so says ANSI C).
	 */
	if (fp == NULL && (fp = tmpfile()) == NULL)
		return -1;
	else
		(void) rewind(fp);

	/* Write out the contents of the buffer to the temporary file. */
	(void) fputs(buf, fp);

	/* Rewind in preparation for reading. */
	(void) rewind(fp);

	return (mks_vfscanf(fp, fmt, vp));
}
