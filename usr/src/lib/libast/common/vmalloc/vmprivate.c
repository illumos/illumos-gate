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

void _STUB_vmprivate(){}

#else

#include	"vmhdr.h"

static char*	Version = "\n@(#)$Id: Vmalloc (AT&T Research) 2010-01-01 $\0\n";

/*	Private code used in the vmalloc library
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

/* Get more memory for a region */
#if __STD_C
static Block_t* vmextend(reg Vmalloc_t* vm, size_t size, Vmsearch_f searchf )
#else
static Block_t* vmextend(vm, size, searchf )
reg Vmalloc_t*	vm;		/* region to increase in size	*/
size_t		size;		/* desired amount of space	*/
Vmsearch_f	searchf;	/* tree search function		*/
#endif
{
	reg size_t	s;
	reg Seg_t*	seg;
	reg Block_t	*bp, *t;
	reg Vmuchar_t*	addr = (Vmuchar_t*)Version; /* shut compiler warning */
	reg Vmdata_t*	vd = vm->data;
	reg Vmemory_f	memoryf = vm->disc->memoryf;
	reg Vmexcept_f	exceptf = vm->disc->exceptf;

	GETPAGESIZE(_Vmpagesize);

#if DEBUG /* trace all allocation calls through the heap */
	if(!_Vmtrace && vm == Vmheap && (vd->mode&VM_TRUST) )
		VMOPTIONS();
#endif

	if(vd->incr <= 0) /* this is just _Vmheap on the first call */
		vd->incr = VMHEAPINCR;

	/* Get slightly more for administrative data */
	s = size + sizeof(Seg_t) + sizeof(Block_t) + sizeof(Head_t) + 2*ALIGN;
	if(s <= size)	/* size was too large and we have wrapped around */
		return NIL(Block_t*);
	if((size = ROUND(s,vd->incr)) < s)
		return NIL(Block_t*);

	/* increase the rounding factor to reduce # of future extensions */
	if(size > 2*vd->incr && vm->disc->round < vd->incr)
		vd->incr *= 2;

	/* see if we can extend the current segment */
	if(!(seg = vd->seg) )
		addr = NIL(Vmuchar_t*);
	else
	{	if(!vd->wild || SEG(vd->wild) != seg)
			s = 0;
		else
		{	s = SIZE(vd->wild) + sizeof(Head_t);
			if((s = (s/vd->incr)*vd->incr) == size)
				size += vd->incr;
		}
		addr = (Vmuchar_t*)(*memoryf)(vm,seg->addr,seg->extent,
					  seg->extent+size-s,vm->disc);
		if(!addr)
			seg = NIL(Seg_t*);
		else
		{	/**/ASSERT(addr == (Vmuchar_t*)seg->addr);
			addr += seg->extent;
			size -= s;
		}
	}

	while(!addr)	/* try to get space */
	{	if((addr = (Vmuchar_t*)(*memoryf)(vm,NIL(Void_t*),0,size,vm->disc)) )
			break;

		/* check with exception handler to see if we should continue */
		if(!exceptf)
			return NIL(Block_t*);
		else
		{	int	rv, lock;
			lock = vd->mode&VM_LOCK;
			vd->mode &= ~VM_LOCK;
			rv = (*exceptf)(vm,VM_NOMEM,(Void_t*)size,vm->disc);
			vd->mode |= lock;
			if(rv <= 0)
			{	if(rv == 0)
					vd->mode |= VM_AGAIN;
				return NIL(Block_t*);
			}
		}
	}

	if(seg)
	{	/* extending current segment */
		bp = BLOCK(seg->baddr);

		if(vd->mode&(VM_MTBEST|VM_MTDEBUG|VM_MTPROFILE) )
		{	/**/ ASSERT((SIZE(bp)&~BITS) == 0);
			/**/ ASSERT(SEG(bp) == seg);
			if(!ISPFREE(SIZE(bp)) )
				SIZE(bp) = size - sizeof(Head_t);
			else
			{	/**/ ASSERT(searchf);
				bp = LAST(bp);
				if(bp == vd->wild)
					vd->wild = NIL(Block_t*);
				else	REMOVE(vd,bp,INDEX(SIZE(bp)),t,(*searchf));
				SIZE(bp) += size;
			}
		}
		else
		{	if(seg->free)
			{	bp = seg->free;
				seg->free = NIL(Block_t*);
				SIZE(bp) += size;
			}
			else
			{	SEG(bp) = seg;
				SIZE(bp) = size - sizeof(Head_t);
			}
		}

		seg->size += size;
		seg->extent += size;
		seg->baddr += size;
	}
	else
	{	/* creating a new segment */
		reg Seg_t	*sp, *lastsp;

		if((s = (size_t)(VLONG(addr)%ALIGN)) != 0)
			addr += ALIGN-s;

		seg = (Seg_t*)addr;
		seg->vmdt = vd;
		seg->addr = (Void_t*)(addr - (s ? ALIGN-s : 0));
		seg->extent = size;
		seg->baddr = addr + size - (s ? 2*ALIGN : 0);
		seg->free = NIL(Block_t*);
		bp = SEGBLOCK(seg);
		SEG(bp) = seg;
		SIZE(bp) = seg->baddr - (Vmuchar_t*)bp - 2*sizeof(Head_t);

		/* NOTE: for Vmbest, Vmdebug and Vmprofile the region's segment list
		   is reversely ordered by addresses. This is so that we can easily
		   check for the wild block.
		*/
		lastsp = NIL(Seg_t*);
		sp = vd->seg;
		if(vd->mode&(VM_MTBEST|VM_MTDEBUG|VM_MTPROFILE))
			for(; sp; lastsp = sp, sp = sp->next)
				if(seg->addr > sp->addr)
					break;
		seg->next = sp;
		if(lastsp)
			lastsp->next = seg;
		else	vd->seg = seg;

		seg->size = SIZE(bp);
	}

	/* make a fake header for possible segmented memory */
	t = NEXT(bp);
	SEG(t) = seg;
	SIZE(t) = BUSY;

	/* see if the wild block is still wild */
	if((t = vd->wild) && (seg = SEG(t)) != vd->seg)
	{	CLRPFREE(SIZE(NEXT(t)));
		if(vd->mode&(VM_MTBEST|VM_MTDEBUG|VM_MTPROFILE) )
		{	SIZE(t) |= BUSY|JUNK;
			LINK(t) = CACHE(vd)[C_INDEX(SIZE(t))];
			CACHE(vd)[C_INDEX(SIZE(t))] = t;
		}
		else	seg->free = t;

		vd->wild = NIL(Block_t*);
	}

	return bp;
}

/* Truncate a segment if possible */
#if __STD_C
static ssize_t vmtruncate(Vmalloc_t* vm, Seg_t* seg, size_t size, int exact)
#else
static ssize_t vmtruncate(vm, seg, size, exact)
Vmalloc_t*	vm;	/* containing region		*/
Seg_t*		seg;	/* the one to be truncated	*/
size_t		size;	/* amount of free space		*/
int		exact;
#endif
{
	reg Void_t*	caddr;
	reg Seg_t*	last;
	reg Vmdata_t*	vd = vm->data;
	reg Vmemory_f	memoryf = vm->disc->memoryf;

	caddr = seg->addr;

	if(size < seg->size)
	{	reg ssize_t	less;

		if(exact)
			less = size;
		else /* keep truncated amount to discipline requirements */
		{	if((less = vm->disc->round) <= 0)
				less = _Vmpagesize;
			less = (size/less)*less;
			less = (less/vd->incr)*vd->incr;
			if(less > 0 && size > (size_t)less && (size-(size_t)less) < sizeof(Block_t) )
				less = (size_t)less <= vd->incr ? 0 : (size_t)less - vd->incr;
		}

		if(less <= 0 ||
		   (*memoryf)(vm,caddr,seg->extent,seg->extent-less,vm->disc) != caddr)
			return 0;

		seg->extent -= less;
		seg->size -= less;
		seg->baddr -= less;
		SEG(BLOCK(seg->baddr)) = seg;
		SIZE(BLOCK(seg->baddr)) = BUSY;

		return less;
	}
	else
	{	/* unlink segment from region */
		if(seg == vd->seg)
		{	vd->seg = seg->next;
			last = NIL(Seg_t*);
		}
		else
		{	for(last = vd->seg; last->next != seg; last = last->next)
				;
			last->next = seg->next;
		}

		/* now delete it */
		if((*memoryf)(vm,caddr,seg->extent,0,vm->disc) == caddr)
			return size;

		/* space reduction failed, reinsert segment */
		if(last)
		{	seg->next = last->next;
			last->next = seg;
		}
		else
		{	seg->next = vd->seg;
			vd->seg = seg;
		}
		return 0;
	}
}

/* Externally visible names but local to library */
Vmextern_t	_Vmextern =
{	vmextend,						/* _Vmextend	*/
	vmtruncate,						/* _Vmtruncate	*/
	0,							/* _Vmpagesize	*/
	NIL(char*(*)_ARG_((char*,const char*,int))),		/* _Vmstrcpy	*/
	NIL(char*(*)_ARG_((Vmulong_t,int))),			/* _Vmitoa	*/
	NIL(void(*)_ARG_((Vmalloc_t*,
			  Vmuchar_t*,Vmuchar_t*,size_t,size_t))), /* _Vmtrace	*/
	NIL(void(*)_ARG_((Vmalloc_t*)))				/* _Vmpfclose	*/
};

#endif
