/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * command initialization
 */

#include <cmd.h>
#include <shcmd.h>

int
_cmd_init(int argc, char** argv, Shbltin_t* context, const char* catalog, int flags)
{
	register char*	cp;

	if (argc <= 0)
		return -1;
	if (context)
	{
		if (flags & ERROR_CALLBACK)
		{
			flags &= ~ERROR_CALLBACK;
			flags |= ERROR_NOTIFY;
		}
		else if (flags & ERROR_NOTIFY)
		{
			context->notify = 1;
			flags &= ~ERROR_NOTIFY;
		}
		error_info.flags |= flags;
	}
	if (cp = strrchr(argv[0], '/'))
		cp++;
	else
		cp = argv[0];
	error_info.id = cp;
	if (!error_info.catalog)
		error_info.catalog = catalog;
	opt_info.index = 0;
	return 0;
}

#if __OBSOLETE__ < 20080101

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

#undef	cmdinit

extern void
cmdinit(char** argv, Shbltin_t* context, const char* catalog, int flags)
{
	_cmd_init(0, argv, context, catalog, flags);
}

#endif
