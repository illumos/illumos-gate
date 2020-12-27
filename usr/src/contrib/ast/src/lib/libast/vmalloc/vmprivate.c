/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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

void _STUB_vmprivate(){}

#else

#include	"vmhdr.h"

static char*	Version = "\n@(#)$Id: Vmalloc (AT&T Labs - Research) 2011-08-08 $\0\n";


/*	Private code used in the vmalloc library
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

/* Get more memory for a region */
#if __STD_C
static Block_t* _vmextend(reg Vmalloc_t* vm, size_t size, Vmsearch_f searchf )
#else
static Block_t* _vmextend(vm, size, searchf )
reg Vmalloc_t*	vm;		/* region to increase in size	*/
size_t		size;		/* desired amount of space	*/
Vmsearch_f	searchf;	/* tree search function		*/
#endif
{
	reg size_t	s;
	reg Seg_t*	seg;
	reg Block_t	*bp, *tp, *np;
	reg Vmuchar_t*	addr = (Vmuchar_t*)Version; /* shut compiler warning */
	reg Vmdata_t*	vd = vm->data;

	GETPAGESIZE(_Vmpagesize);

	if(vd->incr <= 0) /* this is just _Vmheap on the first call */
		vd->incr = _Vmpagesize*sizeof(Void_t*);

	/* Get slightly more for administrative data */
	s = size + sizeof(Seg_t) + sizeof(Block_t) + sizeof(Head_t) + 2*ALIGN;
	if(s <= size)	/* size was too large and we have wrapped around */
		return NIL(Block_t*);
	if((size = ROUND(s,vd->incr)) < s)
		return NIL(Block_t*);

	/* increase the rounding factor to reduce # of future extensions */
	if(size > 2*vd->incr && vm->disc->round < vd->incr)
		vd->incr *= 2;

	if(!(seg = vd->seg) ) /* there is no current segment */
		addr = NIL(Vmuchar_t*);
	else /* see if we can extend the current segment */
	{	addr = (Vmuchar_t*)(*vm->disc->memoryf)(vm,seg->addr,seg->extent,
					  		seg->extent+size,vm->disc);
		if(addr == (Vmuchar_t*)seg->addr)
			addr += seg->extent; /* seg successfully extended */
		else	seg = NIL(Seg_t*); /* a new segment was created */
	}

	if(!addr) /* create a new segment */
	{	if(!(addr = (Vmuchar_t*)(*vm->disc->memoryf)(vm, NIL(Void_t*), 0, size, vm->disc)) )
		{	if(vm->disc->exceptf) /* announce that no more memory is available */
			{
				CLRLOCK(vm, 0);
				(void)(*vm->disc->exceptf)(vm, VM_NOMEM, (Void_t*)size, vm->disc);
				SETLOCK(vm, 0);
			}
			return NIL(Block_t*);
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
				else	REMOVE(vd,bp,INDEX(SIZE(bp)),tp,(*searchf));
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
	tp = NEXT(bp);
	SEG(tp) = seg;
	SIZE(tp) = BUSY;

	/* see if the wild block is still wild */
	if((tp = vd->wild) && (seg = SEG(tp)) != vd->seg)
	{	np = NEXT(tp);
		CLRPFREE(SIZE(np));
		if(vd->mode&(VM_MTBEST|VM_MTDEBUG|VM_MTPROFILE) )
		{	SIZE(tp) |= BUSY|JUNK;
			LINK(tp) = CACHE(vd)[C_INDEX(SIZE(tp))];
			CACHE(vd)[C_INDEX(SIZE(tp))] = tp;
		}
		else	seg->free = tp;

		vd->wild = NIL(Block_t*);
	}

	return bp;
}

/* Truncate a segment if possible */
#if __STD_C
static ssize_t _vmtruncate(Vmalloc_t* vm, Seg_t* seg, size_t size, int exact)
#else
static ssize_t _vmtruncate(vm, seg, size, exact)
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
			if(less > 0 && (ssize_t)size > less && (size-less) < sizeof(Block_t) )
				less = less <= (ssize_t)vd->incr ? 0 : less - vd->incr;
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

int _vmlock(Vmalloc_t* vm, int locking)
{
	if(!vm) /* some sort of global locking */
	{	if(!locking) /* turn off lock */
			asolock(&_Vmlock, 1, ASO_UNLOCK);
		else	asolock(&_Vmlock, 1, ASO_SPINLOCK);
	}
	else if(vm->data->mode&VM_SHARE)
	{	if(!locking) /* turning off the lock */
			asolock(&vm->data->lock, 1, ASO_UNLOCK);
		else	asolock(&vm->data->lock, 1, ASO_SPINLOCK);
	}
	else
	{	if(!locking)
			vm->data->lock = 0;
		else	vm->data->lock = 1;
	}
	return 0;
}


/* Externally visible names but local to library */
Vmextern_t	_Vmextern =
{	_vmextend,						/* _Vmextend	*/
	_vmtruncate,						/* _Vmtruncate	*/
	0,							/* _Vmpagesize	*/
	NIL(char*(*)_ARG_((char*,const char*,int))),		/* _Vmstrcpy	*/
	NIL(char*(*)_ARG_((Vmulong_t,int))),			/* _Vmitoa	*/
	NIL(void(*)_ARG_((Vmalloc_t*,
			  Vmuchar_t*,Vmuchar_t*,size_t,size_t))), /* _Vmtrace	*/
	NIL(void(*)_ARG_((Vmalloc_t*)))				/* _Vmpfclose	*/
};

#endif
