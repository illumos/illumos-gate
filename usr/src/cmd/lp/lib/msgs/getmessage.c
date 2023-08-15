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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/* LINTLIBRARY */
/*
*/

#if	defined(__STDC__)
# include	<stdarg.h>
#else
# include	<varargs.h>
#endif

/* VARARGS */
#if	defined(__STDC__)
int getmessage ( char * buf, short type, ... )
#else
int getmessage (buf, type, va_alist)
    char	*buf;
    short	type;
    va_dcl
#endif
{
    va_list	arg;
    int		rval;
    int	_getmessage();

#if	defined(__STDC__)
    va_start(arg, type);
#else
    va_start(arg);
#endif

    rval = _getmessage(buf, type, arg);
    va_end(arg);
    return(rval);
}
