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
#if defined(_UWIN) && defined(_BLD_ast)

void _STUB_vmdisc(){}

#else

#include	"vmhdr.h"

/*	Change the discipline for a region.  The old discipline
**	is returned.  If the new discipline is NULL then the
**	discipline is not changed.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/
#if __STD_C
Vmdisc_t* vmdisc(Vmalloc_t* vm, Vmdisc_t* disc)
#else
Vmdisc_t* vmdisc(vm, disc)
Vmalloc_t*	vm;
Vmdisc_t*	disc;
#endif
{
	Vmdisc_t*	old = vm->disc;

	if(disc)
	{	if(old->exceptf &&
		   (*old->exceptf)(vm,VM_DISC,(Void_t*)disc,old) != 0 )
			return NIL(Vmdisc_t*);
		vm->disc = disc;
	}
	return old;
}

#endif
