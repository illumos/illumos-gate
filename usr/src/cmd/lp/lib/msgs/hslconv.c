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

# include	<string.h>

static char		_lp_hextable[17] = "0123456789ABCDEF";

#if	defined(__STDC__)
char * ltos ( char * s, unsigned long l)
#else
char * ltos (s, l)
    char	*s;
    unsigned long	l;
#endif
{
    int	i = 7;

    while (i >=	0)
    {
	s[i--] = _lp_hextable[l % 16];
	l /= 16;
    }
    s += 8;
    return(s);
}

#if	defined(__STDC__)
char * htos ( char * s, unsigned short h)
#else
char * htos (s, h)
    char	*s;
    unsigned short	h;
#endif
{
    int	i = 3;

    while (i >= 0)
    {
	s[i--] = _lp_hextable[(long)h % 16];
	h = (long) h / 16;
    }
    s += 4;
    return(s);
}

#if	defined(__STDC__)
unsigned long stol ( char * s )
#else
unsigned long stol (s)
    char	*s;
#endif
{
    int			i = 0;
    unsigned long	l = 0;

    while (i < 8)
    {
	l <<= 4;
	l += strchr(_lp_hextable, s[i++]) - _lp_hextable;
    }
    return(l);
}

#if	defined(__STDC__)
unsigned short stoh ( char * s )
#else
unsigned short stoh (s)
    char	*s;
#endif
{
    int			i = 0;
    unsigned short	h = 0;

    while (i < 4)
    {
	h <<= 4;
	h += strchr(_lp_hextable, s[i++]) - _lp_hextable;
    }
    return(h);
}
