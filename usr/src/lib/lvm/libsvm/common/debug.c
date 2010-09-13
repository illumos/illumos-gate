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
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* The following defines are for tracing output (from libsmpicommon) */

#define	LOG		0x1	/* write message to log file */
#define	SCR		0x2	/* write message to the screen */
#define	LOGSCR		LOG|SCR /* write message to the log and screen */
#define	LEVEL0		0x0001  /* message level 0 */
#define	LEVEL1		0x0002  /* message level 1 */
#define	LEVEL2		0x0004  /* message level 2 */
#define	LEVEL3		0x0010  /* message level 3 */

extern int get_trace_level(void);
extern int write_status(unsigned char, unsigned int, char *, ...);

const char libsvm_str[] = "LIB_SVM: ";
const int libsvm_len = sizeof (libsvm_str);

/*PRINTFLIKE1*/
void
debug_printf(char *fmt, ...)
{
	va_list ap;
	char *cp;
	char *buf;

	if (get_trace_level() > 5) {
		if ((buf = calloc(PATH_MAX, sizeof (char))) == NULL)
			return;
		(void) strcpy(buf, libsvm_str);
		/*
		 * libsvm_len - 1 is because the length includes NULL
		 */

		cp = buf + (libsvm_len - 1);
		va_start(ap, fmt);
		if (vsnprintf(cp, (PATH_MAX - (libsvm_len - 1)),
		    fmt, ap) >= 0) {
			(void) write_status(LOGSCR, LEVEL0, buf);
		}
		free(buf);
		va_end(ap);
	}
}
