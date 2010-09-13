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
 *	ticerror.c		Terminal Information Compiler
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	Portions of this code Copyright 1982 by Pavel Curtis.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] = "$Header: /rd/src/tic/rcs/ticerror.c 1.14 1995/06/22 18:11:44 ant Exp $";
#endif
#endif

#include "tic.h"
#include <stdarg.h>

int warnings = 0;

/*f
 *	Display warning message.
 */
void
warning (char const *f, ...)
{
	va_list ap;
	char *fmt = m_msgdup((char *) f);

	va_start(ap, f);

	(void) fprintf(
		stderr, m_textmsg(3101, "%s: Warning in \"%s\" line %u,\n", "W _ filename line_num"),
		_cmdname, source_file, curr_line
	);

	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fputc('\n', stderr);

	m_msgfree(fmt);
	warnings++;
	return;
}

/*f
 *	Display error message.
 */
void
err_abort (char const *f, ...)
{
	va_list ap;
	char *fmt = m_msgdup((char *) f);

	va_start(ap, f);

	(void) fprintf(
		stderr, m_textmsg(3102, "%s: Error in \"%s\" line %u,\n", "E _ filename line_num"), 
		_cmdname, source_file, curr_line
	);

	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fputc('\n', stderr);

	m_msgfree(fmt);
	exit(1);
}

