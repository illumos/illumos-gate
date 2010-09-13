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

void _STUB_vmdcheap(){}

#else

#include	"vmhdr.h"

/*	A discipline to get memory from the heap.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/
#if __STD_C
static Void_t* heapmem(Vmalloc_t* vm, Void_t* caddr,
			size_t csize, size_t nsize,
			Vmdisc_t* disc)
#else
static Void_t* heapmem(vm, caddr, csize, nsize, disc)
Vmalloc_t*	vm;	/* region doing allocation from 	*/
Void_t*		caddr;	/* current low address			*/
size_t		csize;	/* current size				*/
size_t		nsize;	/* new size				*/
Vmdisc_t*	disc;	/* discipline structure			*/
#endif
{
	NOTUSED(vm);
	NOTUSED(disc);

	if(csize == 0)
		return vmalloc(Vmheap,nsize);
	else if(nsize == 0)
		return vmfree(Vmheap,caddr) >= 0 ? caddr : NIL(Void_t*);
	else	return vmresize(Vmheap,caddr,nsize,0);
}

static Vmdisc_t _Vmdcheap = { heapmem, NIL(Vmexcept_f), 0 };
__DEFINE__(Vmdisc_t*,Vmdcheap,&_Vmdcheap);

#ifdef NoF
NoF(vmdcheap)
#endif

#endif
