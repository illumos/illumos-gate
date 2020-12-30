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

void _STUB_vmregion(){}

#else

#include	"vmhdr.h"

/*	Return the containing region of an allocated piece of memory.
**	Beware: this only works with Vmbest, Vmdebug and Vmprofile.
**
**	10/31/2009: Add handling of shared/persistent memory regions.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/
#if __STD_C
Vmalloc_t* vmregion(Void_t* addr)
#else
Vmalloc_t* vmregion(addr)
Void_t*	addr;
#endif
{
	Vmalloc_t	*vm;
	Vmdata_t	*vd;

	if(!addr)
		return NIL(Vmalloc_t*);

	vd = SEG(BLOCK(addr))->vmdt;

	_vmlock(NIL(Vmalloc_t*), 1);
	for(vm = Vmheap; vm; vm = vm->next)
		if(vm->data == vd)
			break;
	_vmlock(NIL(Vmalloc_t*), 0);

	return vm;
}

#endif
