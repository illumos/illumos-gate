/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor context switch
 *
 *	args		op				return
 *	(0,0)		free current context		0
 *	(0,1)		save current context		current
 *	(p,0)		free context p			0
 *	(p,1)		make p current context		previous
 */

#include "pplib.h"

void*
ppcontext(void* context, int flags)
{
	struct ppcontext*	np = (struct ppcontext*)context;
	struct ppcontext*	op;

	if (flags & 01)
	{
		if (!(op = pp.context)) op = pp.context = newof(0, struct ppcontext, 1, 0);
		memcpy(op, _PP_CONTEXT_BASE_, sizeof(struct ppcontext));
	}
	else
	{
		if (!(op = np)) op = (struct ppcontext*)_PP_CONTEXT_BASE_;
		if (op->filtab) hashfree(op->filtab);
		if (op->prdtab) hashfree(op->prdtab);
		if (op->symtab) hashfree(op->symtab);
		if (op->date) free(op->date);
		if (op->time) free(op->time);
		if (np)
		{
			free(np);
			np = 0;
		}
		memzero(op, sizeof(struct ppcontext));
		op = 0;
	}
	if (np) memcpy(_PP_CONTEXT_BASE_, np, sizeof(struct ppcontext));
	return((void*)op);
}
