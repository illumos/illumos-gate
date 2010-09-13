/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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

	e = p->env->rex;
	if (e && e->type == REX_BM)
		e = e->next;
	if (e && e->type == REX_BEG)
		e = e->next;
	if (e && e->type == REX_STRING)
		e = e->next;
	if (!e || e->type == REX_END && !e->next)
		p->env->stats.re_flags |= REG_LITERAL;
	p->env->stats.re_record = (p && p->env && p->env->rex->type == REX_BM) ? p->env->rex->re.bm.size : -1;
	return &p->env->stats;
}
