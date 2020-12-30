/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * cmdarg library private definitions
 */

#ifndef _CMDLIB_H
#define _CMDLIB_H	1

#define _CMDARG_PRIVATE_ \
	struct \
	{ \
	size_t		args;		/* total args			*/ \
	size_t		commands;	/* total commands		*/ \
	}		total; \
	Error_f		errorf;		/* optional error callback	*/ \
	Cmdrun_f	runf;		/* exec function		*/ \
	int		argcount;	/* current arg count		*/ \
	int		argmax;		/* max # args			*/ \
	int		echo;		/* just an echo			*/ \
	int		flags;		/* CMD_* flags			*/ \
	int		insertlen;	/* strlen(insert)		*/ \
	int		offset;		/* post arg offset		*/ \
	Cmddisc_t*	disc;		/* discipline			*/ \
	char**		argv;		/* exec argv			*/ \
	char**		firstarg;	/* first argv file arg		*/ \
	char**		insertarg;	/* argv before insert		*/ \
	char**		postarg;	/* start of post arg list	*/ \
	char**		nextarg;	/* next argv file arg		*/ \
	char*		nextstr;	/* next string ends before here	*/ \
	char*		laststr;	/* last string ends before here	*/ \
	char*		insert;		/* replace with current arg	*/ \
	char		buf[1];		/* argv and arg buffer		*/

#include <cmdarg.h>

#endif
