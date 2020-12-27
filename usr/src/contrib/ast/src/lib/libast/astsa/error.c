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
 * standalone mini error implementation
 */

#include <ast.h>
#include <error.h>

Error_info_t	error_info;

void
errorv(const char* id, int level, va_list ap)
{
	char*	a;
	char*	s;
	int	flags;

	if (level < 0)
		flags = 0;
	else
	{
		flags = level & ~ERROR_LEVEL;
		level &= ERROR_LEVEL;
	}
	a = va_arg(ap, char*);
	if (level && ((s = error_info.id) || (s = (char*)id)))
	{
		if (!(flags & ERROR_USAGE))
			sfprintf(sfstderr, "%s: ", s);
		else if (strcmp(a, "%s"))
			sfprintf(sfstderr, "Usage: %s ", s);
	}
	if (flags & ERROR_USAGE)
		/*nop*/;
	else if (level < 0)
		sfprintf(sfstderr, "debug%d: ", level);
	else if (level)
	{
		if (level == ERROR_WARNING)
		{
			sfprintf(sfstderr, "warning: ");
			error_info.warnings++;
		}
		else
		{
			error_info.errors++;
			if (level == ERROR_PANIC)
				sfprintf(sfstderr, "panic: ");
		}
		if (error_info.line)
		{
			if (error_info.file && *error_info.file)
				sfprintf(sfstderr, "\"%s\", ", error_info.file);
			sfprintf(sfstderr, "line %d: ", error_info.line);
		}
	}
	sfvprintf(sfstderr, a, ap);
	sfprintf(sfstderr, "\n");
	if (level >= ERROR_FATAL)
		exit(level - ERROR_FATAL + 1);
}

void
error(int level, ...)
{
	va_list	ap;

	va_start(ap, level);
	errorv(NiL, level, ap);
	va_end(ap);
}

int
errorf(void* handle, void* discipline, int level, ...)
{
	va_list	ap;

	va_start(ap, level);
	errorv((discipline && handle) ? *((char**)handle) : (char*)handle, level, ap);
	va_end(ap);
	return 0;
}
