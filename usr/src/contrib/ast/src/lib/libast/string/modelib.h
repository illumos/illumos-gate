/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * mode_t common definitions
 */

#ifndef _MODELIB_H
#define _MODELIB_H

#include <ast.h>
#include <ls.h>
#include <modex.h>

#define MODELEN	10
#define PERMLEN	24

#define modetab	_mode_table_	/* data hiding				*/
#define permmap	_mode_permmap_	/* data hiding				*/

struct modeop			/* ops for each char in mode string	*/
{
	int	mask1;		/* first mask				*/
	int	shift1;		/* first shift count			*/
	int	mask2;		/* second mask				*/
	int	shift2;		/* second shift count			*/
	char*	name;		/* mode char using mask/shift as index	*/
};

extern struct modeop	modetab[];
extern int		permmap[];

#endif
