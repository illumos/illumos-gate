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
 * Copyright 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Id: m_errorx.c 1.9 1995/02/08 15:03:16 rob Exp $";
#endif
#endif

#include <mks.h>
#include <errno.h>
#include <string.h>

#ifndef	ERRORFN

#define	ERRORFN	m_errorexit
#define	DONE	exit(1)

/* Default error msg routine in library */
M_ERROR(m_errorexit);

#endif	/* ERRORFN */

/*f
 * Print error message with command name and trailing newline.
 * Leading ! indicates format errno on the end.
 * The value of errno is restored on completion.
 */
void
ERRORFN(const char *fmt, va_list args)
{
	int saveerrno = errno;
	int syserr = 0;

	if (_cmdname != NULL)
		fprintf(stderr, "%s: ", _cmdname);
	fmt = m_strmsg(fmt);
	if (*fmt == '!') {
		fmt++;
		syserr++;
	}
	vfprintf(stderr, fmt, args);
	if (syserr) {
		char *str;

		/* Do eprintf-like stuff */
		str = strerror(saveerrno);
		if (*str == '\0')
			fprintf(stderr, ": errno = %d", saveerrno);
		else
			fprintf(stderr,": %s", str);
	}
	fputc('\n', stderr);
	errno = saveerrno;
	DONE;
}


