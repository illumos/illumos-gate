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
#if defined(_UWIN) && defined(_BLD_ast)

void _STUB_vmsegment(){}

#else

#include	"vmhdr.h"

/*	Get the segment containing this address
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 02/07/95
*/

#if __STD_C
Void_t* vmsegment(Vmalloc_t* vm, Void_t* addr)
#else
Void_t* vmsegment(vm, addr)
Vmalloc_t*	vm;	/* region	*/
Void_t*		addr;	/* address	*/
#endif
{
	reg Seg_t*	seg;
	reg Vmdata_t*	vd = vm->data;
	reg int		inuse;

	SETINUSE(vd, inuse);
	if(!(vd->mode&VM_TRUST))
	{	if(ISLOCK(vd,0))
		{	CLRINUSE(vd, inuse);
			return NIL(Void_t*);
		}
		SETLOCK(vd,0);
	}

	for(seg = vd->seg; seg; seg = seg->next)
		if((Vmuchar_t*)addr >= (Vmuchar_t*)seg->addr &&
		   (Vmuchar_t*)addr <  (Vmuchar_t*)seg->baddr )
			break;

	CLRLOCK(vd,0);
	CLRINUSE(vd, inuse);
	return seg ? (Void_t*)seg->addr : NIL(Void_t*);
}

#endif
