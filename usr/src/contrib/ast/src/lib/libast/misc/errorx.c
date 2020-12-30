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

#include "lclib.h"

/*
 * low level for ERROR_translate()
 * this fills in NiL arg defaults and calls error_info.translate
 */

char*
errorx(const char* loc, const char* cmd, const char* cat, const char* msg)
{
	char*	s;

	if (!error_info.translate)
		error_info.translate = translate; /* 2007-03-19 OLD_Error_info_t workaround */
	if (ERROR_translating())
	{
		if (!loc)
			loc = (const char*)locales[AST_LC_MESSAGES]->code;
		if (!cmd)
			cmd = (const char*)error_info.id;
		if (!cat)
			cat = (const char*)error_info.catalog;
		if (s = (*error_info.translate)(loc, cmd, cat, msg))
			return s;
	}
	return (char*)msg;
}
