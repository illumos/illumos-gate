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

void _STUB_vmpool(){}

#else

#include	"vmhdr.h"

#define POOLFREE	0x55555555L	/* block free indicator	 */

/*	Method for pool allocation.
**	All elements in a pool have the same size.
**	The following fields of Vmdata_t are used as:
**		pool:	size of a block.
**		free:	list of free blocks.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

#if __STD_C
static Void_t* poolalloc(Vmalloc_t* vm, reg size_t size, int local)
#else
static Void_t* poolalloc(vm, size, local )
Vmalloc_t*	vm;
reg size_t	size;
int		local;
#endif
{
	reg Block_t	*tp, *next;
	reg size_t	s;
	reg Seg_t	*seg;
	reg Vmdata_t	*vd = vm->data;

	if(size <= 0)
		return NIL(Void_t*);

	if(size != vd->pool)
	{	if(vd->pool <= 0)
			vd->pool = size;
		else	return NIL(Void_t*);
	}

	SETLOCK(vm, local);

	if((tp = vd->free) ) /* there is a ready free block */
	{	vd->free = SEGLINK(tp);
		goto done;
	}

	size = ROUND(size,ALIGN);

	/* look thru all segments for a suitable free block */
	for(tp = NIL(Block_t*), seg = vd->seg; seg; seg = seg->next)
	{	if((tp = seg->free) &&
		   (s = (SIZE(tp) & ~BITS) + sizeof(Head_t)) >= size )
			goto got_blk;
	}

	if((tp = (*_Vmextend)(vm,ROUND(size,vd->incr),NIL(Vmsearch_f))) )
	{	s = (SIZE(tp) & ~BITS) + sizeof(Head_t);
		seg = SEG(tp);
		goto got_blk;
	}
	else	goto done;

got_blk: /* if get here, (tp, s, seg) must be well-defined */
	next = (Block_t*)((Vmuchar_t*)tp+size);
	if((s -= size) <= (size + sizeof(Head_t)) )
	{	for(; s >= size; s -= size)
		{	SIZE(next) = POOLFREE;
			SEGLINK(next) = vd->free;
			vd->free = next;
			next = (Block_t*)((Vmuchar_t*)next + size);
		}
		seg->free = NIL(Block_t*);
	}
	else
	{	SIZE(next) = s - sizeof(Head_t);
		SEG(next) = seg;
		seg->free = next;
	}

done:
	if(!local && (vd->mode&VM_TRACE) && _Vmtrace && tp)
		(*_Vmtrace)(vm,NIL(Vmuchar_t*),(Vmuchar_t*)tp,vd->pool,0);

	CLRLOCK(vm, local);

	return (Void_t*)tp;
}

#if __STD_C
static long pooladdr(Vmalloc_t* vm, reg Void_t* addr, int local)
#else
static long pooladdr(vm, addr, local)
Vmalloc_t*	vm;
reg Void_t*	addr;
int		local;
#endif
{
	Block_t		*bp, *tp;
	Vmuchar_t	*laddr, *baddr;
	size_t		size;
	Seg_t		*seg;
	long		offset;
	Vmdata_t*	vd = vm->data;

	SETLOCK(vm, local);

	offset = -1L;
	for(seg = vd->seg; seg; seg = seg->next)
	{	laddr = (Vmuchar_t*)SEGBLOCK(seg);
		baddr = seg->baddr-sizeof(Head_t);
		if((Vmuchar_t*)addr < laddr || (Vmuchar_t*)addr >= baddr)
			continue;

		/* the block that has this address */
		size = ROUND(vd->pool,ALIGN);
		tp = (Block_t*)(laddr + (((Vmuchar_t*)addr-laddr)/size)*size );

		/* see if this block has been freed */
		if(SIZE(tp) == POOLFREE) /* may be a coincidence - make sure */
			for(bp = vd->free; bp; bp = SEGLINK(bp))
				if(bp == tp)
					goto done;

		offset = (Vmuchar_t*)addr - (Vmuchar_t*)tp;
		goto done;
	}

done :
	CLRLOCK(vm, local);

	return offset;
}

#if __STD_C
static int poolfree(reg Vmalloc_t* vm, reg Void_t* data, int local )
#else
static int poolfree(vm, data, local)
Vmalloc_t*	vm;
Void_t*		data;
int		local;
#endif
{
	Block_t		*bp;
	Vmdata_t	*vd = vm->data;

	if(!data)
		return 0;
	if(vd->pool <= 0)
		return -1;

	SETLOCK(vm, local);

	/**/ASSERT(KPVADDR(vm, data, pooladdr) == 0);
	bp = (Block_t*)data;
	SIZE(bp) = POOLFREE;
	SEGLINK(bp) = vd->free;
	vd->free = bp;

	if(!local && (vd->mode&VM_TRACE) && _Vmtrace)
		(*_Vmtrace)(vm, (Vmuchar_t*)data, NIL(Vmuchar_t*), vd->pool, 0);

	CLRLOCK(vm, local);

	return 0;
}

#if __STD_C
static Void_t* poolresize(Vmalloc_t* vm, Void_t* data, size_t size, int type, int local )
#else
static Void_t* poolresize(vm, data, size, type, local )
Vmalloc_t*	vm;
Void_t*		data;
size_t		size;
int		type;
int		local;
#endif
{
	Vmdata_t	*vd = vm->data;

	NOTUSED(type);

	if(!data)
	{	data = poolalloc(vm, size, local);
		if(data && (type&VM_RSZERO) )
			memset(data, 0, size);
		return data;
	}
	if(size == 0)
	{	(void)poolfree(vm, data, local);
		return NIL(Void_t*);
	}
	if(size != vd->pool)
		return NIL(Void_t*);

	SETLOCK(vm, local);

	/**/ASSERT(KPVADDR(vm, data, pooladdr) == 0);

	if(!local && (vd->mode&VM_TRACE) && _Vmtrace)
		(*_Vmtrace)(vm, (Vmuchar_t*)data, (Vmuchar_t*)data, size, 0);

	CLRLOCK(vm, local);

	return data;
}

#if __STD_C
static long poolsize(Vmalloc_t* vm, Void_t* addr, int local)
#else
static long poolsize(vm, addr, local)
Vmalloc_t*	vm;
Void_t*		addr;
int		local;
#endif
{
	return pooladdr(vm, addr, local) == 0 ? (long)vm->data->pool : -1L;
}

#if __STD_C
static int poolcompact(Vmalloc_t* vm, int local)
#else
static int poolcompact(vm, local)
Vmalloc_t*	vm;
int		local;
#endif
{
	ssize_t		s;
	Block_t		*fp;
	Seg_t		*seg, *next;
	Vmdata_t	*vd = vm->data;

	SETLOCK(vm, local);

	for(seg = vd->seg; seg; seg = next)
	{	next = seg->next;

		if(!(fp = seg->free))
			continue;

		seg->free = NIL(Block_t*);
		if(seg->size == (s = SIZE(fp)&~BITS))
			s = seg->extent;
		else	s += sizeof(Head_t);

		if((*_Vmtruncate)(vm,seg,s,1) == s)
			seg->free = fp;
	}

	if(!local && (vd->mode&VM_TRACE) && _Vmtrace)
		(*_Vmtrace)(vm, (Vmuchar_t*)0, (Vmuchar_t*)0, 0, 0);

	CLRLOCK(vm, local);

	return 0;
}

#if __STD_C
static Void_t* poolalign(Vmalloc_t* vm, size_t size, size_t align, int local)
#else
static Void_t* poolalign(vm, size, align, local)
Vmalloc_t*	vm;
size_t		size;
size_t		align;
int		local;
#endif
{
	NOTUSED(vm);
	NOTUSED(size);
	NOTUSED(align);
	return NIL(Void_t*);
}

/* Public interface */
static Vmethod_t _Vmpool =
{
	poolalloc,
	poolresize,
	poolfree,
	pooladdr,
	poolsize,
	poolcompact,
	poolalign,
	VM_MTPOOL
};

__DEFINE__(Vmethod_t*,Vmpool,&_Vmpool);

#ifdef NoF
NoF(vmpool)
#endif

#endif
