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
 * return p stat info
 */

#include "reglib.h"

regstat_t*
regstat(const regex_t* p)
{
	register Rex_t*	e;

	p->env->stats.re_flags = p->env->flags;
	p->env->stats.re_info = 0;
	e = p->env->rex;
	if (e && e->type == REX_BM)
	{
		p->env->stats.re_record = p->env->rex->re.bm.size;
		e = e->next;
	}
	else
		p->env->stats.re_record = 0;
	if (e && e->type == REX_BEG)
		e = e->next;
	if (e && e->type == REX_STRING)
		e = e->next;
	if (!e || e->type == REX_END && !e->next)
		p->env->stats.re_info |= REG_LITERAL;
	p->env->stats.re_record = (p && p->env && p->env->rex->type == REX_BM) ? p->env->rex->re.bm.size : -1;
	return &p->env->stats;
}
