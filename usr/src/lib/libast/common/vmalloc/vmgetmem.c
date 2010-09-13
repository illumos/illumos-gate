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

void _STUB_vmgetmem(){}

#else

#include	"vmhdr.h"

/*
 * vm open/close/resize - a handy default for discipline memory functions
 *
 *	vmgetmem(0,0,0)		open new region
 *	vmgetmem(r,0,0)		free region
 *	vmgetmem(r,0,n)		allocate n bytes initialized to 0
 *	vmgetmem(r,p,0)		free p
 *	vmgetmem(r,p,n)		realloc p to n bytes
 *
 * Written by Glenn S. Fowler.
 */

#if __STD_C
Void_t* vmgetmem(Vmalloc_t* vm, Void_t* data, size_t size)
#else
Void_t* vmgetmem(vm, data, size)
Vmalloc_t*	vm;
Void_t*		data;
size_t		size;
#endif
{
	if (!vm)
		return vmopen(Vmdcheap, Vmbest, 0);
	if (data || size)
		return vmresize(vm, data, size, VM_RSMOVE|VM_RSCOPY|VM_RSZERO);
	vmclose(vm);
	return 0;
}

#endif
