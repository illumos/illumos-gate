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


#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 1.	*/
/*
    NAME
	Dout - Print debug output

    SYNOPSIS
	void Dout(char *subname, int level, char *msg, ...)

    DESCRIPTION
	Dout prints debugging output if debugging is turned
	on (-x specified) and the level of this message is
	lower than the value of the global variable debug.
	The subroutine name is printed if it is not a null
	string.
*/
#include "mail.h"
#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* VARARGS3 PRINTFLIKE3 */
void
#ifdef __STDC__
Dout(char *subname, int level, char *fmt, ...)
#else
# ifdef lint
Dout(Xsubname, Xlevel, Xfmt, va_alist)
char *Xsubname, *Xfmt;
int Xlevel;
va_dcl
# else
Dout(va_alist)
va_dcl
# endif
#endif
{
#ifndef __STDC__
	char    *subname;
	int	level;
	char    *fmt;
#endif
	va_list args;

#ifndef __STDC__
#ifdef lint
	subname = Xsubname;
	level = Xlevel;
	fmt = Xfmt;
# endif
#endif

#ifdef __STDC__
	va_start(args, fmt);
#else
	va_start(args);
	subname = va_arg(args, char *);
	level = va_arg(args, int);
	fmt = va_arg(args, char *);
#endif

	if (debug > level) {
		if (subname && *subname) {
			fprintf(dbgfp,"%s(): ", subname);
		}
		vfprintf(dbgfp, fmt, args);
	}
	va_end(args);
}
