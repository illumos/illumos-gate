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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 2.	*/
/*
    NAME
	Tout - Print surrogate debug output

    SYNOPSIS
	void Tout(char *subname, char *msg, ...)

    DESCRIPTION
	Tout prints debugging output if surrogate tracing
	has been turned on (-T specified). The message will
	also go to the debug output if debugging is turned
	on (-x specified). The subroutine name is printed
	if it is not a null string.
*/
#include "mail.h"
#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* VARARGS2 PRINTFLIKE2 */
void
#ifdef __STDC__
Tout(char *subname, char *fmt, ...)
#else
# ifdef lint
Tout(Xsubname, Xfmt, va_alist)
char *Xsubname, *Xfmt;
va_dcl
# else
Tout(va_alist)
va_dcl
# endif
#endif
{
#ifndef __STDC__
        char    *subname;
        char    *fmt;
#endif
        va_list args;

#if !defined(__STDC__) && defined(lint)
	subname = Xsubname;
	fmt = Xfmt;
#endif

        if (debug > 0) {
#ifdef __STDC__
                va_start(args, fmt);
#else
                va_start(args);
                subname = va_arg(args, char *);
                fmt = va_arg(args, char *);
#endif
                if (subname && *subname) {
                        fprintf(dbgfp,"%s(): ", subname);
                }
                vfprintf(dbgfp, fmt, args);
                va_end(args);
        }

        if (flgT) {
#ifdef __STDC__
                va_start(args, fmt);
#else
                va_start(args);
                subname = va_arg(args, char *);
                fmt = va_arg(args, char *);
#endif
                vfprintf(stdout, fmt, args);
                va_end(args);
        }
}
