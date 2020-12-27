/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * common preprocessor comment handler
 */

#include "pplib.h"

void
ppcomment(char* head, char* comment, char* tail, int line)
{
	NoP(line);
	ppprintf("%s%-.*s%s", head, MAXTOKEN - 4, comment, tail);
}
