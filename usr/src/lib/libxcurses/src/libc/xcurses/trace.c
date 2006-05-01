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
 * trace.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All right reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/trace.c 1.3 1995/06/12 20:24:05 ant Exp $";
#endif
#endif

#include <private.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static int __m_tracing = FALSE;

/*f
 *  Write a formatted string into a trace file.
 */
void
__m_trace(const char *fmt, ...)
{
	va_list vp;
	static FILE *fp;
	static int initialized = FALSE;

	if (!__m_tracing)
		return;

	if (!initialized) {
		fp = fopen("trace.out", "wF");
		if (fp == (FILE *) 0) {
			fprintf(stderr, "Program cannot open \"trace.out\".\n");
			exit(1);
		}
		initialized = TRUE;
	}

	va_start(vp, fmt);
	(void) vfprintf(fp, fmt, vp);
	va_end(vp);
	fputc('\n', fp);
}

int
(__m_return_code)(const char *s, int code)
{
	switch (code) {
	case OK:
		__m_trace("%s returned OK.", s);
		break;
	case ERR:
		__m_trace("%s returned ERR.", s);
		break;
	case KEY_CODE_YES:
		__m_trace("%s returned KEY_CODE_YES.", s);
		break;
	default:
		__m_trace("%s returned code %d", s, code);
	}

	return code;
}

int
(__m_return_int)(const char *s, int value)
{
	__m_trace("%s returned %d", s, value);

	return value;
}

chtype
(__m_return_chtype)(const char *s, chtype ch)
{
	__m_trace("%s returned %lx", s, ch);

	return ch;
}

void *
(__m_return_pointer)(const char *s, const void *ptr)
{
	if (ptr == (void *) 0)
		__m_trace("%s returned NULL.", s);
	else
		__m_trace("%s returned %p.", s, ptr);

	return (void *) ptr;
}

#undef __m_return_void

void
__m_return_void(const char *s)
{
	__m_trace("%s returns void.");
}

/*f
 *  Turn tracing on
 */
void
traceon()
{
    	__m_tracing = TRUE;
	__m_trace("traceon()\ntraceon() returns void.");
}

/*f
 *  Turn tracing off
 */
void
traceoff()
{
	__m_trace("traceoff()\ntraceoff() returns void.");
    	__m_tracing = FALSE;
}

