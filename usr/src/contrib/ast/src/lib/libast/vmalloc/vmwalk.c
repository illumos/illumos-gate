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

void _STUB_vmwalk(){}

#else

#include	"vmhdr.h"

/*	Walks all segments created in region(s)
**
**	Written by Kiem-Phong Vo, kpv@research.att.com (02/08/96)
*/

#if __STD_C
int vmwalk(Vmalloc_t* vm, int(*segf)(Vmalloc_t*, Void_t*, size_t, Vmdisc_t*, Void_t*), Void_t* handle )
#else
int vmwalk(vm, segf, handle)
Vmalloc_t*	vm;
int(*		segf)(/* Vmalloc_t*, Void_t*, size_t, Vmdisc_t*, Void_t* */);
Void_t*		handle;
#endif
{	
	reg Seg_t	*seg;
	reg int		rv = 0;

	if(!vm)
	{	_vmlock(NIL(Vmalloc_t*), 1);
		for(vm = Vmheap; vm; vm = vm->next)
		{	SETLOCK(vm, 0);
			for(seg = vm->data->seg; seg; seg = seg->next)
				if((rv = (*segf)(vm, seg->addr, seg->extent, vm->disc, handle)) < 0 )
					break;
			CLRLOCK(vm, 0);
		}
		_vmlock(NIL(Vmalloc_t*), 0);
	}
	else
	{	SETLOCK(vm, 0);
		for(seg = vm->data->seg; seg; seg = seg->next)
			if((rv = (*segf)(vm, seg->addr, seg->extent, vm->disc, handle)) < 0 )
				break;
		CLRLOCK(vm, 0);
	}

	return rv;
}

#endif
