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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#if defined(__STDC__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#define WHO_AM_I	I_AM_OZ		/* to get oam.h to unfold */
#include "oam.h"
#include "lpd.h"

/*
 * Report fatal error and exit
 */
/*VARARGS1*/
void
#if defined (__STDC__)
fatal(char *fmt, ...)
#else
fatal(fmt, va_alist)
char	*fmt;
va_dcl
#endif
{
	va_list	argp;

	if (Rhost)
		(void)printf("%s: ", Lhost);
	printf("%s: ", Name);
	if (Printer)
		(void)printf("%s: ", Printer);
#if defined (__STDC__)
	va_start(argp, fmt);
#else
	va_start(argp);
#endif
	(void)vprintf(fmt, argp);
	va_end(argp);
	putchar('\n');
	fflush(stdout);
	done(1);		/* defined by invoker */
	/*NOTREACHED*/
}

/*
 * Format lp error message to stderr
 * (this will probably change to remain compatible with LP)
 */
/*VARARGS1*/
void
#if defined (__STDC__)
_lp_msg(long msgid, va_list argp)
#else
_lp_msg(msgid, argp)
long	msgid;
va_list	argp;
#endif
{
	char	 label[20];

	(void)vsprintf(_m_, agettxt(msgid, _a_, MSGSIZ), argp);
	strcpy(label, "UX:");
	(void)strlcat(label, basename(Name), sizeof (label));
	fmtmsg(label, ERROR, _m_, agettxt(msgid+1, _a_, MSGSIZ));
}

/*
 * Format lp error message to stderr
 */
/*VARARGS1*/
void
#if defined (__STDC__)
lp_msg(long msgid, ...)
#else
lp_msg(msgid, va_alist)
long	msgid;
va_dcl
#endif
{
	va_list	argp;

#if defined (__STDC__)
	va_start(argp, msgid);
#else
	va_start(argp);
#endif
	_lp_msg(msgid, argp);
	va_end(argp);
}

/*
 * Report lp error message to stderr and exit
 */
/*VARARGS1*/
void
#if defined (__STDC__)
lp_fatal(long msgid, ...)
#else
lp_fatal(msgid, va_alist)
long	msgid;
va_dcl
#endif
{
	va_list	argp;

#if defined (__STDC__)
	va_start(argp, msgid);
#else
	va_start(argp);
#endif
	_lp_msg(msgid, argp);
	va_end(argp);

	done(1);			/* Supplied by caller */
	/*NOTREACHED*/
}
