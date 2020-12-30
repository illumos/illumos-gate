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
 * dtopen() with handle placed in specific vm region
 */

#include <dt.h>

typedef struct Dc_s
{
	Dtdisc_t	ndisc;
	Dtdisc_t*	odisc;
	Vmalloc_t*	vm;
} Dc_t;

static int
eventf(Dt_t* dt, int op, void* data, Dtdisc_t* disc)
{
	Dc_t*	dc = (Dc_t*)disc;
	int	r;

	if (dc->odisc->eventf && (r = (*dc->odisc->eventf)(dt, op, data, dc->odisc)))
		return r;
	return op == DT_ENDOPEN ? 1 : 0;
}

static void*
memoryf(Dt_t* dt, void* addr, size_t size, Dtdisc_t* disc)
{
	return vmresize(((Dc_t*)disc)->vm, addr, size, VM_RSMOVE);
}

/*
 * open a dictionary using disc->memoryf if set or vm otherwise
 */

Dt_t*
_dtnew(Vmalloc_t* vm, Dtdisc_t* disc, Dtmethod_t* meth, unsigned long version)
{
	Dt_t*		dt;
	Dc_t		dc;

	dc.odisc = disc;
	dc.ndisc = *disc;
	dc.ndisc.eventf = eventf;
	if (!dc.ndisc.memoryf)
		dc.ndisc.memoryf = memoryf;
	dc.vm = vm;
	if (dt = _dtopen(&dc.ndisc, meth, version))
		dtdisc(dt, disc, DT_SAMECMP|DT_SAMEHASH);
	return dt;
}

#undef dtnew

Dt_t*
dtnew(Vmalloc_t* vm, Dtdisc_t* disc, Dtmethod_t* meth)
{
	return _dtnew(vm, disc, meth, 20050420L);
}
