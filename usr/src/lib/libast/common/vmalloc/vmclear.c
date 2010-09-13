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

void _STUB_vmclear(){}

#else

#include	"vmhdr.h"

/*	Clear out all allocated space.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/
#if __STD_C
int vmclear(Vmalloc_t* vm)
#else
int vmclear(vm)
Vmalloc_t*	vm;
#endif
{
	reg Seg_t*	seg;
	reg Seg_t*	next;
	reg Block_t*	tp;
	reg size_t	size, s;
	reg Vmdata_t*	vd = vm->data;
	reg int		inuse;

	SETINUSE(vd, inuse);
	if(!(vd->mode&VM_TRUST) )
	{	if(ISLOCK(vd,0))
		{	CLRINUSE(vd, inuse);
			return -1;
		}
		SETLOCK(vd,0);
	}

	vd->free = vd->wild = NIL(Block_t*);
	vd->pool = 0;

	if(vd->mode&(VM_MTBEST|VM_MTDEBUG|VM_MTPROFILE) )
	{	vd->root = NIL(Block_t*);
		for(s = 0; s < S_TINY; ++s)
			TINY(vd)[s] = NIL(Block_t*);
		for(s = 0; s <= S_CACHE; ++s)
			CACHE(vd)[s] = NIL(Block_t*);
	}

	for(seg = vd->seg; seg; seg = next)
	{	next = seg->next;

		tp = SEGBLOCK(seg);
		size = seg->baddr - ((Vmuchar_t*)tp) - 2*sizeof(Head_t);

		SEG(tp) = seg;
		SIZE(tp) = size;
		if((vd->mode&(VM_MTLAST|VM_MTPOOL)) )
			seg->free = tp;
		else
		{	SIZE(tp) |= BUSY|JUNK;
			LINK(tp) = CACHE(vd)[C_INDEX(SIZE(tp))];
			CACHE(vd)[C_INDEX(SIZE(tp))] = tp;
		}

		tp = BLOCK(seg->baddr);
		SEG(tp) = seg;
		SIZE(tp) = BUSY;
	}

	CLRLOCK(vd,0);
	CLRINUSE(vd, inuse);
	return 0;
}

#endif
