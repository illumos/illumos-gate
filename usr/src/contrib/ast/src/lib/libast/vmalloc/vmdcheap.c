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
	if(csize == 0 && nsize == 0)
		return NIL(Void_t*);
	else if(csize == 0)
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
