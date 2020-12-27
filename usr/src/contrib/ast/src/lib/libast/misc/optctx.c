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
 * _opt_infop_ context control
 *
 * allocate new context:
 *	new_context = optctx(0, 0);
 * free new context:
 *	optctx(0, new_context);
 * switch to new_context:
 *	old_context = optctx(new_context, 0);
 * switch to old_context and free new_context:
 *	optctx(old_context, new_context);
 */

#include <optlib.h>

static Opt_t*	freecontext;

Opt_t*
optctx(Opt_t* p, Opt_t* o)
{
	if (o)
	{
		if (freecontext)
			free(o);
		else
			freecontext = o;
		if (!p)
			return 0;
	}
	if (p)
	{
		o = _opt_infop_;
		_opt_infop_ = p;
	}
	else
	{
		if (o = freecontext)
			freecontext = 0;
		else if (!(o = newof(0, Opt_t, 1, 0)))
			return 0;
		memset(o, 0, sizeof(Opt_t));
		o->state = _opt_infop_->state;
	}
	return o;
}
