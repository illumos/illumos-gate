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

void _STUB_vmbest(){}

#else

#include	"vmhdr.h"

/*	Best-fit allocation method. This is based on a best-fit strategy
**	using a splay tree for storage of lists of free blocks of the same
**	size. Recent free blocks may be cached for fast reuse.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

#ifdef DEBUG
static int	N_free;		/* # of free calls			*/
static int	N_alloc;	/* # of alloc calls			*/
static int	N_resize;	/* # of resize calls			*/
static int	N_wild;		/* # allocated from the wild block	*/
static int	N_last;		/* # allocated from last free block	*/
static int	N_reclaim;	/* # of bestreclaim calls		*/

#undef	VM_TRUST		/* always check for locking, etc.s	*/
#define	VM_TRUST	0
#endif /*DEBUG*/

#if _BLD_posix
#define logmsg(d,a ...)	logsrc(d,__FILE__,__LINE__,a)

extern int	logsrc(int, const char*, int, const char*, ...);
#endif /*_BLD_posix*/

#define COMPACT		8	/* factor to decide when to compact	*/

/* Check to see if a block is in the free tree */
#if __STD_C
static int vmintree(Block_t* node, Block_t* b)
#else
static int vmintree(node,b)
Block_t*	node;
Block_t*	b;
#endif
{	Block_t*	t;

	for(t = node; t; t = LINK(t))
		if(t == b)
			return 1;
	if(LEFT(node) && vmintree(LEFT(node),b))
		return 1;
	if(RIGHT(node) && vmintree(RIGHT(node),b))
		return 1;
	return 0;
}

#if __STD_C
static int vmonlist(Block_t* list, Block_t* b)
#else
static int vmonlist(list,b)
Block_t*	list;
Block_t*	b;
#endif
{
	for(; list; list = LINK(list))
		if(list == b)
			return 1;
	return 0;
}

/* Check to see if a block is known to be free */
#if __STD_C
static int vmisfree(Vmdata_t* vd, Block_t* b)
#else
static int vmisfree(vd,b)
Vmdata_t*	vd;
Block_t*	b;
#endif
{
	if(SIZE(b) & (BUSY|JUNK|PFREE))
		return 0;

	if(b == vd->wild)
		return 1;

	if(SIZE(b) < MAXTINY)
		return vmonlist(TINY(vd)[INDEX(SIZE(b))], b);

	if(vd->root)
		return vmintree(vd->root, b);

	return 0;
}

/* Check to see if a block is known to be junked */
#if __STD_C
static int vmisjunk(Vmdata_t* vd, Block_t* b)
#else
static int vmisjunk(vd,b)
Vmdata_t*	vd;
Block_t*	b;
#endif
{
	Block_t*	t;

	if((SIZE(b)&BUSY) == 0 || (SIZE(b)&JUNK) == 0)
		return 0;

	if(b == vd->free) /* recently freed */
		return 1;

	/* check the list that b is supposed to be in */
	for(t = CACHE(vd)[C_INDEX(SIZE(b))]; t; t = LINK(t))
		if(t == b)
			return 1;

	/* on occasions, b may be put onto the catch-all list */
	if(C_INDEX(SIZE(b)) < S_CACHE)
		for(t = CACHE(vd)[S_CACHE]; t; t = LINK(t))
			if(t == b)
				return 1;

	return 0;
}

/* check to see if the free tree is in good shape */
#if __STD_C
static int vmchktree(Block_t* node)
#else
static int vmchktree(node)
Block_t*	node;
#endif
{	Block_t*	t;

	if(SIZE(node) & BITS)
		{ /**/ASSERT(0); return -1; }

	for(t = LINK(node); t; t = LINK(t))
		if(SIZE(t) != SIZE(node))
			{ /**/ASSERT(0); return -1; }

	if((t = LEFT(node)) )
	{	if(SIZE(t) >= SIZE(node) )
			{ /**/ASSERT(0); return -1; }
		else	return vmchktree(t);
	}
	if((t = RIGHT(node)) )
	{	if(SIZE(t) <= SIZE(node) )
			{ /**/ASSERT(0); return -1; }
		else	return vmchktree(t);
	}

	return 0;
}

#if __STD_C
int _vmbestcheck(Vmdata_t* vd, Block_t* freeb)
#else
int _vmbestcheck(vd, freeb)
Vmdata_t*	vd;
Block_t*	freeb; /* known to be free but not on any free list */
#endif
{
	reg Seg_t	*seg;
	reg Block_t	*b, *endb, *nextb;
	int		rv = 0;

	if(!CHECK())
		return 0;

	/* make sure the free tree is still in shape */
	if(vd->root && vmchktree(vd->root) < 0 )
		{ rv = -1; /**/ASSERT(0); }

	for(seg = vd->seg; seg && rv == 0; seg = seg->next)
	{	b = SEGBLOCK(seg);
		endb = (Block_t*)(seg->baddr - sizeof(Head_t));
		for(; b < endb && rv == 0; b = nextb)
		{	nextb = (Block_t*)((Vmuchar_t*)DATA(b) + (SIZE(b)&~BITS) );

			if(!ISBUSY(SIZE(b)) ) /* a completely free block */
			{	/* there should be no marked bits of any type */
				if(SIZE(b) & (BUSY|JUNK|PFREE) )
					{ rv = -1; /**/ASSERT(0); }

				/* next block must be busy and marked PFREE */
				if(!ISBUSY(SIZE(nextb)) || !ISPFREE(SIZE(nextb)) )
					{ rv = -1; /**/ASSERT(0); }

				/* must have a self-reference pointer */
				if(*SELF(b) != b)
					{ rv = -1; /**/ASSERT(0); }

				/* segment pointer should be well-defined */
				if(!TINIEST(b) && SEG(b) != seg)
					{ rv = -1; /**/ASSERT(0); }

				/* must be on a free list */
				if(b != freeb && !vmisfree(vd, b) )
					{ rv = -1; /**/ASSERT(0); }
			}
			else
			{	/* segment pointer should be well-defined */
				if(SEG(b) != seg)
					{ rv = -1; /**/ASSERT(0); }

				/* next block should not be marked PFREE */
				if(ISPFREE(SIZE(nextb)) )
					{ rv = -1; /**/ASSERT(0); }

				/* if PFREE, last block should be free */
				if(ISPFREE(SIZE(b)) && LAST(b) != freeb &&
				   !vmisfree(vd, LAST(b)) )
					{ rv = -1; /**/ASSERT(0); }

				/* if free but unreclaimed, should be junk */
				if(ISJUNK(SIZE(b)) && !vmisjunk(vd, b))
					{ rv = -1; /**/ASSERT(0); }
			}
		}
	}

	return rv;
}

/* Tree rotation functions */
#define RROTATE(x,y)	(LEFT(x) = RIGHT(y), RIGHT(y) = (x), (x) = (y))
#define LROTATE(x,y)	(RIGHT(x) = LEFT(y), LEFT(y) = (x), (x) = (y))
#define RLINK(s,x)	((s) = LEFT(s) = (x))
#define LLINK(s,x)	((s) = RIGHT(s) = (x))

/* Find and delete a suitable element in the free tree. */
#if __STD_C
static Block_t* bestsearch(Vmdata_t* vd, reg size_t size, Block_t* wanted)
#else
static Block_t* bestsearch(vd, size, wanted)
Vmdata_t*	vd;
reg size_t	size;
Block_t*	wanted;
#endif
{
	reg size_t	s;
	reg Block_t	*t, *root, *l, *r;
	Block_t		link;

	/* extracting a tiniest block from its list */
	if((root = wanted) && size == TINYSIZE)
	{	reg Seg_t*	seg;

		l = TLEFT(root);
		if((r = LINK(root)) )
			TLEFT(r) = l;
		if(l)
			LINK(l) = r;
		else	TINY(vd)[0] = r;

		seg = vd->seg;
		if(!seg->next)
			SEG(root) = seg;
		else for(;; seg = seg->next)
		{	if((Vmuchar_t*)root > (Vmuchar_t*)seg->addr &&
			   (Vmuchar_t*)root < seg->baddr)
			{	SEG(root) = seg;
				break;
			}
		}

		return root;
	}

	/**/ASSERT(!vd->root || vmchktree(vd->root) == 0);

	/* find the right one to delete */
	l = r = &link;
	if((root = vd->root) ) do
	{	/**/ ASSERT(!ISBITS(size) && !ISBITS(SIZE(root)));
		if(size == (s = SIZE(root)) )
			break;
		if(size < s)
		{	if((t = LEFT(root)) )
			{	if(size <= (s = SIZE(t)) )
				{	RROTATE(root,t);
					if(size == s)
						break;
					t = LEFT(root);
				}
				else
				{	LLINK(l,t);
					t = RIGHT(t);
				}
			}
			RLINK(r,root);
		}
		else
		{	if((t = RIGHT(root)) )
			{	if(size >= (s = SIZE(t)) )
				{	LROTATE(root,t);
					if(size == s)
						break;
					t = RIGHT(root);
				}
				else
				{	RLINK(r,t);
					t = LEFT(t);
				}
			}
			LLINK(l,root);
		}
		/**/ ASSERT(root != t);
	} while((root = t) );

	if(root)	/* found it, now isolate it */
	{	RIGHT(l) = LEFT(root);
		LEFT(r) = RIGHT(root);
	}
	else		/* nothing exactly fit	*/
	{	LEFT(r) = NIL(Block_t*);
		RIGHT(l) = NIL(Block_t*);

		/* grab the least one from the right tree */
		if((root = LEFT(&link)) )
		{	while((t = LEFT(root)) )
				RROTATE(root,t);
			LEFT(&link) = RIGHT(root);
		}
	}

	if(root && (r = LINK(root)) )
	{	/* head of a link list, use next one for root */
		LEFT(r) = RIGHT(&link);
		RIGHT(r) = LEFT(&link);
	}
	else if(!(r = LEFT(&link)) )
		r = RIGHT(&link);
	else /* graft left tree to right tree */
	{	while((t = LEFT(r)) )
			RROTATE(r,t);
		LEFT(r) = RIGHT(&link);
	}
	vd->root = r; /**/ASSERT(!r || !ISBITS(SIZE(r)));

	/**/ASSERT(!vd->root || vmchktree(vd->root) == 0);
	/**/ASSERT(!wanted || wanted == root);

	return root;
}

/* Reclaim all delayed free blocks into the free tree */
#if __STD_C
static int bestreclaim(reg Vmdata_t* vd, Block_t* wanted, int c)
#else
static int bestreclaim(vd, wanted, c)
reg Vmdata_t*	vd;
Block_t*	wanted;
int		c;
#endif
{
	reg size_t	size, s;
	reg Block_t	*fp, *np, *t, *list;
	reg int		n, saw_wanted;
	reg Seg_t	*seg;

	/**/COUNT(N_reclaim);
	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);

	if((fp = vd->free) )
	{	LINK(fp) = CACHE(vd)[S_CACHE]; CACHE(vd)[S_CACHE] = fp;
		vd->free = NIL(Block_t*);
	}

	saw_wanted = wanted ? 0 : 1;
	for(n = S_CACHE; n >= c; --n)
	{	list = CACHE(vd)[n]; CACHE(vd)[n] = NIL(Block_t*);
		while((fp = list) )
		{	/* Note that below here we allow ISJUNK blocks to be
			** forward-merged even though they are not removed from
			** the list immediately. In this way, the list is
			** scanned only once. It works because the LINK and SIZE
			** fields are not destroyed during the merging. This can
			** be seen by observing that a tiniest block has a 2-word
			** header and a 2-word body. Merging a tiniest block
			** (1seg) and the next block (2seg) looks like this:
			**	1seg  size  link  left  2seg size link left ....
			**	1seg  size  link  left  rite xxxx xxxx .... self
			** After the merge, the 2seg word is replaced by the RIGHT
			** pointer of the new block and somewhere beyond the
			** two xxxx fields, the SELF pointer will replace some
			** other word. The important part is that the two xxxx
			** fields are kept intact.
			*/
			list = LINK(list); /**/ASSERT(!vmonlist(list,fp));

			size = SIZE(fp);
			if(!ISJUNK(size))	/* already done */
				continue;

			if(_Vmassert & VM_region)
			{	/* see if this address is from region */
				for(seg = vd->seg; seg; seg = seg->next)
					if(fp >= SEGBLOCK(seg) && fp < (Block_t*)seg->baddr )
						break;
				if(!seg) /* must be a bug in application code! */
				{	/**/ ASSERT(seg != NIL(Seg_t*));
					continue;
				}
			}

			if(ISPFREE(size))	/* backward merge */
			{	fp = LAST(fp);
#if _BLD_posix
				if (fp < (Block_t*)0x00120000)
				{
					logmsg(0, "bestreclaim fp=%p", fp);
					ASSERT(!fp);
				}
#endif
				s = SIZE(fp); /**/ASSERT(!(s&BITS));
				REMOVE(vd,fp,INDEX(s),t,bestsearch);
				size = (size&~BITS) + s + sizeof(Head_t);
			}
			else	size &= ~BITS;

			for(;;)	/* forward merge */
			{	np = (Block_t*)((Vmuchar_t*)fp+size+sizeof(Head_t));
#if _BLD_posix
				if (np < (Block_t*)0x00120000)
				{
					logmsg(0, "bestreclaim np=%p", np);
					ASSERT(!np);
				}
#endif
				s = SIZE(np);	/**/ASSERT(s > 0);
				if(!ISBUSY(s))
				{	/**/ASSERT((s&BITS) == 0);
					if(np == vd->wild)
						vd->wild = NIL(Block_t*);
					else	REMOVE(vd,np,INDEX(s),t,bestsearch);
				}
				else if(ISJUNK(s))
				{	/* reclaim any touched junk list */
					if((int)C_INDEX(s) < c)
						c = C_INDEX(s);
					SIZE(np) = 0;
					CLRBITS(s);
				}
				else	break;
				size += s + sizeof(Head_t);
			}
			SIZE(fp) = size;

			/* tell next block that this one is free */
			np = NEXT(fp);	/**/ASSERT(ISBUSY(SIZE(np)));
					/**/ASSERT(!ISJUNK(SIZE(np)));
			SETPFREE(SIZE(np));
			*(SELF(fp)) = fp;

			if(fp == wanted) /* to be consumed soon */
			{	/**/ASSERT(!saw_wanted); /* should be seen just once */
				saw_wanted = 1;
				continue;
			}

			/* wilderness preservation */
			if(np->body.data >= vd->seg->baddr)
			{	vd->wild = fp;
				continue;
			}

			/* tiny block goes to tiny list */
			if(size < MAXTINY)
			{	s = INDEX(size);
				np = LINK(fp) = TINY(vd)[s];
				if(s == 0)	/* TINIEST block */
				{	if(np)
						TLEFT(np) = fp;
					TLEFT(fp) = NIL(Block_t*);
				}
				else
				{	if(np)
						LEFT(np)  = fp;
					LEFT(fp) = NIL(Block_t*);
					SETLINK(fp);
				}
				TINY(vd)[s] = fp;
				continue;
			}

			LEFT(fp) = RIGHT(fp) = LINK(fp) = NIL(Block_t*);
			if(!(np = vd->root) )	/* inserting into an empty tree	*/
			{	vd->root = fp;
				continue;
			}

			size = SIZE(fp);
			while(1)	/* leaf insertion */
			{	/**/ASSERT(np != fp);
				if((s = SIZE(np)) > size)
				{	if((t = LEFT(np)) )
					{	/**/ ASSERT(np != t);
						np = t;
					}
					else
					{	LEFT(np) = fp;
						break;
					}
				}
				else if(s < size)
				{	if((t = RIGHT(np)) )
					{	/**/ ASSERT(np != t);
						np = t;
					}
					else
					{	RIGHT(np) = fp;
						break;
					}
				}
				else /* s == size */
				{	if((t = LINK(np)) )
					{	LINK(fp) = t;
						LEFT(t) = fp;
					}
					LINK(np) = fp;
					LEFT(fp) = np;
					SETLINK(fp);
					break;
				}
			}
		}
	}

	/**/ASSERT(!wanted || saw_wanted == 1);
	/**/ASSERT(_vmbestcheck(vd, wanted) == 0);
	return saw_wanted;
}

#if __STD_C
static int bestcompact(Vmalloc_t* vm)
#else
static int bestcompact(vm)
Vmalloc_t*	vm;
#endif
{
	reg Seg_t	*seg, *next;
	reg Block_t	*bp, *t;
	reg size_t	size, segsize, round;
	reg int		local, inuse;
	reg Vmdata_t*	vd = vm->data;

	SETINUSE(vd, inuse);

	if(!(local = vd->mode&VM_TRUST) )
	{	GETLOCAL(vd,local);
		if(ISLOCK(vd,local))
		{	CLRINUSE(vd, inuse);
			return -1;
		}
		SETLOCK(vd,local);
	}

	bestreclaim(vd,NIL(Block_t*),0);

	for(seg = vd->seg; seg; seg = next)
	{	next = seg->next;

		bp = BLOCK(seg->baddr);
		if(!ISPFREE(SIZE(bp)) )
			continue;

		bp = LAST(bp);	/**/ASSERT(vmisfree(vd,bp));
		size = SIZE(bp);
		if(bp == vd->wild)
		{	/* During large block allocations, _Vmextend might
			** have been enlarged the rounding factor. Reducing
			** it a bit help avoiding getting large raw memory.
			*/
			if((round = vm->disc->round) == 0)
				round = _Vmpagesize;
			if(size > COMPACT*vd->incr && vd->incr > round)
				vd->incr /= 2;

			/* for the bottom segment, we don't necessarily want
			** to return raw memory too early. vd->pool has an
			** approximation of the average size of recently freed
			** blocks. If this is large, the application is managing
			** large blocks so we throttle back memory chopping
			** to avoid thrashing the underlying memory system.
			*/
			if(size <= COMPACT*vd->incr || size <= COMPACT*vd->pool)
				continue;

			vd->wild = NIL(Block_t*);
			vd->pool = 0;
		}
		else	REMOVE(vd,bp,INDEX(size),t,bestsearch);
		CLRPFREE(SIZE(NEXT(bp)));

		if(size < (segsize = seg->size))
			size += sizeof(Head_t);

		if((size = (*_Vmtruncate)(vm,seg,size,0)) > 0)
		{	if(size >= segsize) /* entire segment deleted */
				continue;
			/**/ASSERT(SEG(BLOCK(seg->baddr)) == seg);

			if((size = (seg->baddr - ((Vmuchar_t*)bp) - sizeof(Head_t))) > 0)
				SIZE(bp) = size - sizeof(Head_t);
			else	bp = NIL(Block_t*);
		}

		if(bp)
		{	/**/ ASSERT(SIZE(bp) >= BODYSIZE);
			/**/ ASSERT(SEGWILD(bp));
			/**/ ASSERT(!vd->root || !vmintree(vd->root,bp));
			SIZE(bp) |= BUSY|JUNK;
			LINK(bp) = CACHE(vd)[C_INDEX(SIZE(bp))];
			CACHE(vd)[C_INDEX(SIZE(bp))] = bp;
		}
	}

	if(!local && _Vmtrace && (vd->mode&VM_TRACE) && VMETHOD(vd) == VM_MTBEST)
		(*_Vmtrace)(vm, (Vmuchar_t*)0, (Vmuchar_t*)0, 0, 0);

	CLRLOCK(vd,local); /**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);

	CLRINUSE(vd, inuse);
	return 0;
}

#if __STD_C
static Void_t* bestalloc(Vmalloc_t* vm, reg size_t size )
#else
static Void_t* bestalloc(vm,size)
Vmalloc_t*	vm;	/* region allocating from	*/
reg size_t	size;	/* desired block size		*/
#endif
{
	reg Vmdata_t*	vd = vm->data;
	reg size_t	s;
	reg int		n;
	reg Block_t	*tp, *np;
	reg int		local, inuse;
	size_t		orgsize = 0;

	VMOPTIONS();

	/**/COUNT(N_alloc);

	SETINUSE(vd, inuse);

	if(!(local = vd->mode&VM_TRUST))
	{	GETLOCAL(vd,local);	/**/ASSERT(!ISLOCK(vd,local));
		if(ISLOCK(vd,local) )
		{	CLRINUSE(vd, inuse);
			return NIL(Void_t*);
		}
		SETLOCK(vd,local);
		orgsize = size;
	}

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	/**/ ASSERT(HEADSIZE == sizeof(Head_t));
	/**/ ASSERT(BODYSIZE == sizeof(Body_t));
	/**/ ASSERT((ALIGN%(BITS+1)) == 0 );
	/**/ ASSERT((sizeof(Head_t)%ALIGN) == 0 );
	/**/ ASSERT((sizeof(Body_t)%ALIGN) == 0 );
	/**/ ASSERT((BODYSIZE%ALIGN) == 0 );
	/**/ ASSERT(sizeof(Block_t) == (sizeof(Body_t)+sizeof(Head_t)) );

	/* for ANSI requirement that malloc(0) returns non-NULL pointer */
	size = size <= BODYSIZE ? BODYSIZE : ROUND(size,ALIGN);

	if((tp = vd->free) )	/* reuse last free piece if appropriate */
	{	/**/ASSERT(ISBUSY(SIZE(tp)) );
		/**/ASSERT(ISJUNK(SIZE(tp)) );
		/**/COUNT(N_last);

		vd->free = NIL(Block_t*);
		if((s = SIZE(tp)) >= size && s < (size << 1) )
		{	if(s >= size + (sizeof(Head_t)+BODYSIZE) )
			{	SIZE(tp) = size;
				np = NEXT(tp);
				SEG(np) = SEG(tp);
				SIZE(np) = ((s&~BITS) - (size+sizeof(Head_t)))|JUNK|BUSY;
				vd->free = np;
				SIZE(tp) |= s&BITS;
			}
			CLRJUNK(SIZE(tp));
			goto done;
		}

		LINK(tp) = CACHE(vd)[S_CACHE];
		CACHE(vd)[S_CACHE] = tp;
	}

	for(;;)
	{	for(n = S_CACHE; n >= 0; --n)	/* best-fit except for coalescing */
		{	bestreclaim(vd,NIL(Block_t*),n);
			if(vd->root && (tp = bestsearch(vd,size,NIL(Block_t*))) )
				goto got_block;
		}

		/**/ASSERT(!vd->free);
		if((tp = vd->wild) && SIZE(tp) >= size)
		{	/**/COUNT(N_wild);
			vd->wild = NIL(Block_t*);
			goto got_block;
		}
	
		KPVCOMPACT(vm,bestcompact);
		if((tp = (*_Vmextend)(vm,size,bestsearch)) )
			goto got_block;
		else if(vd->mode&VM_AGAIN)
			vd->mode &= ~VM_AGAIN;
		else
		{	CLRLOCK(vd,local);
			CLRINUSE(vd, inuse);
			return NIL(Void_t*);
		}
	}

got_block:
	/**/ ASSERT(!ISBITS(SIZE(tp)));
	/**/ ASSERT(SIZE(tp) >= size);
	/**/ ASSERT((SIZE(tp)%ALIGN) == 0);
	/**/ ASSERT(!vd->free);

	/* tell next block that we are no longer a free block */
	CLRPFREE(SIZE(NEXT(tp)));	/**/ ASSERT(ISBUSY(SIZE(NEXT(tp))));

	if((s = SIZE(tp)-size) >= (sizeof(Head_t)+BODYSIZE) )
	{	SIZE(tp) = size;

		np = NEXT(tp);
		SEG(np) = SEG(tp);
		SIZE(np) = (s - sizeof(Head_t)) | BUSY|JUNK;

		if(VMWILD(vd,np))
		{	SIZE(np) &= ~BITS;
			*SELF(np) = np; /**/ASSERT(ISBUSY(SIZE(NEXT(np))));
			SETPFREE(SIZE(NEXT(np)));
			vd->wild = np;
		}
		else	vd->free = np;
	}

	SETBUSY(SIZE(tp));

done:
	if(!local && (vd->mode&VM_TRACE) && _Vmtrace && VMETHOD(vd) == VM_MTBEST)
		(*_Vmtrace)(vm,NIL(Vmuchar_t*),(Vmuchar_t*)DATA(tp),orgsize,0);

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	CLRLOCK(vd,local);
	ANNOUNCE(local, vm, VM_ALLOC, DATA(tp), vm->disc);

	CLRINUSE(vd, inuse);
	return DATA(tp);
}

#if __STD_C
static long bestaddr(Vmalloc_t* vm, Void_t* addr )
#else
static long bestaddr(vm, addr)
Vmalloc_t*	vm;	/* region allocating from	*/
Void_t*		addr;	/* address to check		*/
#endif
{
	reg Seg_t*	seg;
	reg Block_t	*b, *endb;
	reg long	offset;
	reg Vmdata_t*	vd = vm->data;
	reg int		local, inuse;

	SETINUSE(vd, inuse);

	if(!(local = vd->mode&VM_TRUST) )
	{	GETLOCAL(vd,local); /**/ASSERT(!ISLOCK(vd,local));
		if(ISLOCK(vd,local))
		{	CLRINUSE(vd, inuse);
			return -1L;
		}
		SETLOCK(vd,local);
	}

	offset = -1L; b = endb = NIL(Block_t*);
	for(seg = vd->seg; seg; seg = seg->next)
	{	b = SEGBLOCK(seg);
		endb = (Block_t*)(seg->baddr - sizeof(Head_t));
		if((Vmuchar_t*)addr > (Vmuchar_t*)b &&
		   (Vmuchar_t*)addr < (Vmuchar_t*)endb)
			break;
	}

	if(local && !(vd->mode&VM_TRUST) ) /* from bestfree or bestresize */
	{	b = BLOCK(addr);
		if(seg && SEG(b) == seg && ISBUSY(SIZE(b)) && !ISJUNK(SIZE(b)) )
			offset = 0;
		if(offset != 0 && vm->disc->exceptf)
			(void)(*vm->disc->exceptf)(vm,VM_BADADDR,addr,vm->disc);
	}
	else if(seg)
	{	while(b < endb)
		{	reg Vmuchar_t*	data = (Vmuchar_t*)DATA(b);
			reg size_t	size = SIZE(b)&~BITS;

			if((Vmuchar_t*)addr >= data && (Vmuchar_t*)addr < data+size)
			{	if(ISJUNK(SIZE(b)) || !ISBUSY(SIZE(b)))
					offset = -1L;
				else	offset = (Vmuchar_t*)addr - data;
				goto done;
			}

			b = (Block_t*)((Vmuchar_t*)DATA(b) + size);
		}
	}

done:	
	CLRLOCK(vd,local);
	CLRINUSE(vd, inuse);
	return offset;
}

#if __STD_C
static int bestfree(Vmalloc_t* vm, Void_t* data )
#else
static int bestfree(vm, data )
Vmalloc_t*	vm;
Void_t*		data;
#endif
{
	reg Vmdata_t*	vd = vm->data;
	reg Block_t	*bp;
	reg size_t	s;
	reg int		local, inuse;

#ifdef DEBUG
	if((local = (int)integralof(data)) >= 0 && local <= 0xf)
	{	int	vmassert = _Vmassert;
		_Vmassert = local ? local : vmassert ? vmassert : (VM_check|VM_abort);
		_vmbestcheck(vd, NIL(Block_t*));
		_Vmassert = local ? local : vmassert;
		return 0;
	}
#endif

	if(!data) /* ANSI-ism */
		return 0;

	/**/COUNT(N_free);

	SETINUSE(vd, inuse);

	if(!(local = vd->mode&VM_TRUST) )
	{	GETLOCAL(vd,local);	/**/ASSERT(!ISLOCK(vd,local));
		if(ISLOCK(vd,local) || KPVADDR(vm,data,bestaddr) != 0 )
		{	CLRINUSE(vd, inuse);
			return -1;
		}
		SETLOCK(vd,local);
	}

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	bp = BLOCK(data); s = SIZE(bp);

	/* Keep an approximate average free block size.
	** This is used in bestcompact() to decide when to release
	** raw memory back to the underlying memory system.
	*/
	vd->pool = (vd->pool + (s&~BITS))/2;

	if(ISBUSY(s) && !ISJUNK(s))
	{	SETJUNK(SIZE(bp));
	        if(s < MAXCACHE)
	        {       /**/ASSERT(!vmonlist(CACHE(vd)[INDEX(s)], bp) );
	                LINK(bp) = CACHE(vd)[INDEX(s)];
	                CACHE(vd)[INDEX(s)] = bp;
	        }
	        else if(!vd->free)
	                vd->free = bp;
	        else
	        {       /**/ASSERT(!vmonlist(CACHE(vd)[S_CACHE], bp) );
	                LINK(bp) = CACHE(vd)[S_CACHE];
	                CACHE(vd)[S_CACHE] = bp;
	        }
	
		/* coalesce on freeing large blocks to avoid fragmentation */
		if(SIZE(bp) >= 2*vd->incr)
		{	bestreclaim(vd,NIL(Block_t*),0);
			if(vd->wild && SIZE(vd->wild) >= COMPACT*vd->incr)
				KPVCOMPACT(vm,bestcompact);
		}
	}

	if(!local && _Vmtrace && (vd->mode&VM_TRACE) && VMETHOD(vd) == VM_MTBEST )
		(*_Vmtrace)(vm,(Vmuchar_t*)data,NIL(Vmuchar_t*), (s&~BITS), 0);

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	CLRLOCK(vd,local);
	ANNOUNCE(local, vm, VM_FREE, data, vm->disc);

	CLRINUSE(vd, inuse);
	return 0;
}

#if __STD_C
static Void_t* bestresize(Vmalloc_t* vm, Void_t* data, reg size_t size, int type)
#else
static Void_t* bestresize(vm,data,size,type)
Vmalloc_t*	vm;		/* region allocating from	*/
Void_t*		data;		/* old block of data		*/
reg size_t	size;		/* new size			*/
int		type;		/* !=0 to move, <0 for not copy */
#endif
{
	reg Block_t	*rp, *np, *t;
	int		local, inuse;
	size_t		s, bs, oldsize = 0, orgsize = 0;
	Void_t		*oldd, *orgdata = NIL(Void_t*);
	Vmdata_t	*vd = vm->data;

	/**/COUNT(N_resize);

	SETINUSE(vd, inuse);

	if(!data)
	{	if((data = bestalloc(vm,size)) )
		{	oldsize = 0;
			size = size <= BODYSIZE ? BODYSIZE : ROUND(size,ALIGN);
		}
		goto done;
	}
	if(size == 0)
	{	(void)bestfree(vm,data);
		CLRINUSE(vd, inuse);
		return NIL(Void_t*);
	}

	if(!(local = vd->mode&VM_TRUST) )
	{	GETLOCAL(vd,local); /**/ASSERT(!ISLOCK(vd,local));
		if(ISLOCK(vd,local) || (!local && KPVADDR(vm,data,bestaddr) != 0 ) )
		{	CLRINUSE(vd, inuse);
			return NIL(Void_t*);
		}
		SETLOCK(vd,local);

		orgdata = data;	/* for tracing */
		orgsize = size;
	}

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	size = size <= BODYSIZE ? BODYSIZE : ROUND(size,ALIGN);
	rp = BLOCK(data);	/**/ASSERT(ISBUSY(SIZE(rp)) && !ISJUNK(SIZE(rp)));
	oldsize = SIZE(rp); CLRBITS(oldsize);
	if(oldsize < size)
	{	np = (Block_t*)((Vmuchar_t*)rp + oldsize + sizeof(Head_t));
		do	/* forward merge as much as possible */
		{	s = SIZE(np); /**/ASSERT(!ISPFREE(s));
			if(np == vd->free)
			{	vd->free = NIL(Block_t*);
				CLRBITS(s);
			}
			else if(ISJUNK(s) )
			{
				if(!bestreclaim(vd,np,C_INDEX(s)) )
					/**/ASSERT(0); /* oops: did not see np! */
				s = SIZE(np); /**/ASSERT(s%ALIGN == 0);
			}
			else if(!ISBUSY(s) )
			{	if(np == vd->wild)
					vd->wild = NIL(Block_t*);
				else	REMOVE(vd,np,INDEX(s),t,bestsearch); 
			}
			else	break;

			SIZE(rp) += (s += sizeof(Head_t)); /**/ASSERT((s%ALIGN) == 0);
			np = (Block_t*)((Vmuchar_t*)np + s);
			CLRPFREE(SIZE(np));
		} while(SIZE(rp) < size);

		if(SIZE(rp) < size && size > vd->incr && SEGWILD(rp) )
		{	reg Seg_t*	seg;

			s = (size - SIZE(rp)) + sizeof(Head_t); s = ROUND(s,vd->incr);
			seg = SEG(rp);
			if((*vm->disc->memoryf)(vm,seg->addr,seg->extent,seg->extent+s,
				      vm->disc) == seg->addr )
			{	SIZE(rp) += s;
				seg->extent += s;
				seg->size += s;
				seg->baddr += s;
				s  = (SIZE(rp)&~BITS) + sizeof(Head_t);
				np = (Block_t*)((Vmuchar_t*)rp + s);
				SEG(np) = seg;
				SIZE(np) = BUSY;
			}
		}
	}

	if((s = SIZE(rp)) >= (size + (BODYSIZE+sizeof(Head_t))) )
	{	SIZE(rp) = size;
		np = NEXT(rp);
		SEG(np) = SEG(rp);
		SIZE(np) = (((s&~BITS)-size) - sizeof(Head_t))|BUSY|JUNK;
		CPYBITS(SIZE(rp),s);
		rp = np;
		goto do_free;
	}
	else if((bs = s&~BITS) < size)
	{	if(!(type&(VM_RSMOVE|VM_RSCOPY)) )
			data = NIL(Void_t*); /* old data is not moveable */
		else
		{	oldd = data;
			if((data = KPVALLOC(vm,size,bestalloc)) )
			{	if(type&VM_RSCOPY)
					memcpy(data, oldd, bs);

			do_free: /* reclaim these right away */
				SETJUNK(SIZE(rp));
				LINK(rp) = CACHE(vd)[S_CACHE];
				CACHE(vd)[S_CACHE] = rp;
				bestreclaim(vd, NIL(Block_t*), S_CACHE);
			}
		}
	}

	if(!local && _Vmtrace && data && (vd->mode&VM_TRACE) && VMETHOD(vd) == VM_MTBEST)
		(*_Vmtrace)(vm, (Vmuchar_t*)orgdata, (Vmuchar_t*)data, orgsize, 0);

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	CLRLOCK(vd,local);
	ANNOUNCE(local, vm, VM_RESIZE, data, vm->disc);

done:	if(data && (type&VM_RSZERO) && (size = SIZE(BLOCK(data))&~BITS) > oldsize )
		memset((Void_t*)((Vmuchar_t*)data + oldsize), 0, size-oldsize);

	CLRINUSE(vd, inuse);
	return data;
}

#if __STD_C
static long bestsize(Vmalloc_t* vm, Void_t* addr )
#else
static long bestsize(vm, addr)
Vmalloc_t*	vm;	/* region allocating from	*/
Void_t*		addr;	/* address to check		*/
#endif
{
	reg Seg_t*	seg;
	reg Block_t	*b, *endb;
	reg long	size;
	reg Vmdata_t*	vd = vm->data;
	reg int		inuse;

	SETINUSE(vd, inuse);

	if(!(vd->mode&VM_TRUST) )
	{	if(ISLOCK(vd,0))
		{	CLRINUSE(vd, inuse);
			return -1L;
		}
		SETLOCK(vd,0);
	}

	size = -1L;
	for(seg = vd->seg; seg; seg = seg->next)
	{	b = SEGBLOCK(seg);
		endb = (Block_t*)(seg->baddr - sizeof(Head_t));
		if((Vmuchar_t*)addr <= (Vmuchar_t*)b ||
		   (Vmuchar_t*)addr >= (Vmuchar_t*)endb)
			continue;
		while(b < endb)
		{	if(addr == DATA(b))
			{	if(!ISBUSY(SIZE(b)) || ISJUNK(SIZE(b)) )
					size = -1L;
				else	size = (long)SIZE(b)&~BITS;
				goto done;
			}
			else if((Vmuchar_t*)addr <= (Vmuchar_t*)b)
				break;

			b = (Block_t*)((Vmuchar_t*)DATA(b) + (SIZE(b)&~BITS) );
		}
	}

done:
	CLRLOCK(vd,0);
	CLRINUSE(vd, inuse);
	return size;
}

#if __STD_C
static Void_t* bestalign(Vmalloc_t* vm, size_t size, size_t align)
#else
static Void_t* bestalign(vm, size, align)
Vmalloc_t*	vm;
size_t		size;
size_t		align;
#endif
{
	reg Vmuchar_t	*data;
	reg Block_t	*tp, *np;
	reg Seg_t*	seg;
	reg int		local, inuse;
	reg size_t	s, extra, orgsize = 0, orgalign = 0;
	reg Vmdata_t*	vd = vm->data;

	if(size <= 0 || align <= 0)
		return NIL(Void_t*);

	SETINUSE(vd, inuse);

	if(!(local = vd->mode&VM_TRUST) )
	{	GETLOCAL(vd,local); /**/ASSERT(!ISLOCK(vd,local));
		if(ISLOCK(vd,local) )
		{	CLRINUSE(vd, inuse);
			return NIL(Void_t*);
		}
		SETLOCK(vd,local);
		orgsize = size;
		orgalign = align;
	}

	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	size = size <= BODYSIZE ? BODYSIZE : ROUND(size,ALIGN);
	align = MULTIPLE(align,ALIGN);

	/* hack so that dbalign() can store header data */
	if(VMETHOD(vd) != VM_MTDEBUG)
		extra = 0;
	else
	{	extra = DB_HEAD;
		while(align < extra || (align - extra) < sizeof(Block_t))
			align *= 2;
	}

	/* reclaim all free blocks now to avoid fragmentation */
	bestreclaim(vd,NIL(Block_t*),0);

	s = size + 2*(align+sizeof(Head_t)+extra); 
	if(!(data = (Vmuchar_t*)KPVALLOC(vm,s,bestalloc)) )
		goto done;

	tp = BLOCK(data);
	seg = SEG(tp);

	/* get an aligned address that we can live with */
	if((s = (size_t)((VLONG(data)+extra)%align)) != 0)
		data += align-s; /**/ASSERT(((VLONG(data)+extra)%align) == 0);

	if((np = BLOCK(data)) != tp ) /* need to free left part */
	{	if(((Vmuchar_t*)np - (Vmuchar_t*)tp) < (ssize_t)(sizeof(Block_t)+extra) )
		{	data += align;
			np = BLOCK(data);
		} /**/ASSERT(((VLONG(data)+extra)%align) == 0);

		s  = (Vmuchar_t*)np - (Vmuchar_t*)tp;
		SIZE(np) = ((SIZE(tp)&~BITS) - s)|BUSY;
		SEG(np) = seg;

		SIZE(tp) = (s - sizeof(Head_t)) | (SIZE(tp)&BITS) | JUNK;
		/**/ ASSERT(SIZE(tp) >= sizeof(Body_t) );
		LINK(tp) = CACHE(vd)[C_INDEX(SIZE(tp))];
		CACHE(vd)[C_INDEX(SIZE(tp))] = tp;
	}

	/* free left-over if too big */
	if((s = SIZE(np) - size) >= sizeof(Block_t))
	{	SIZE(np) = size;

		tp = NEXT(np);
		SIZE(tp) = ((s & ~BITS) - sizeof(Head_t)) | BUSY | JUNK;
		SEG(tp) = seg;
		LINK(tp) = CACHE(vd)[C_INDEX(SIZE(tp))];
		CACHE(vd)[C_INDEX(SIZE(tp))] = tp;

		SIZE(np) |= s&BITS;
	}

	bestreclaim(vd,NIL(Block_t*),0); /* coalesce all free blocks */

	if(!local && !(vd->mode&VM_TRUST) && _Vmtrace && (vd->mode&VM_TRACE) )
		(*_Vmtrace)(vm,NIL(Vmuchar_t*),data,orgsize,orgalign);

done:
	/**/ASSERT(_vmbestcheck(vd, NIL(Block_t*)) == 0);
	CLRLOCK(vd,local);
	ANNOUNCE(local, vm, VM_ALLOC, (Void_t*)data, vm->disc);

	CLRINUSE(vd, inuse);
	return (Void_t*)data;
}


#if _mem_win32
#if _PACKAGE_ast
#include		<ast_windows.h>
#else
#include		<windows.h>
#endif
#endif /* _lib_win32 */

#if _mem_mmap_anon
#include		<sys/mman.h>
#ifndef MAP_ANON
#define	MAP_ANON	MAP_ANONYMOUS
#endif
#endif /* _mem_mmap_anon */

#if _mem_mmap_zero
#include		<sys/fcntl.h>
#include		<sys/mman.h>
typedef struct _mmapdisc_s
{	Vmdisc_t	disc;
	int		fd;
	off_t		offset;
} Mmapdisc_t;

#ifndef OPEN_MAX
#define	OPEN_MAX	64
#endif
#define OPEN_PRIVATE	(3*OPEN_MAX/4)
#endif /* _mem_mmap_zero */

/* failure mode of mmap, sbrk and brk */
#ifndef MAP_FAILED
#define MAP_FAILED	((Void_t*)(-1))
#endif
#define BRK_FAILED	((Void_t*)(-1))

/* make sure that allocated memory are addressable */

#if _PACKAGE_ast
#include	<sig.h>
#else
#include	<signal.h>
typedef void	(*Sig_handler_t)(int);
#endif

static int	Gotsegv = 0;

#if __STD_C
static void sigsegv(int sig)
#else
static void sigsegv(sig)
int	sig;
#endif
{
	if(sig == SIGSEGV)
		Gotsegv = 1;
}

#if __STD_C
static int okaddr(Void_t* addr, size_t nsize)
#else
static int okaddr(addr, nsize)
Void_t*	addr;
size_t	nsize;
#endif
{
	Sig_handler_t	segv;
	int		rv;

	Gotsegv = 0; /* catch segment fault */
	segv = signal(SIGSEGV, sigsegv);

	if(Gotsegv == 0)
		rv = *((char*)addr);
	if(Gotsegv == 0)
		rv += *(((char*)addr)+nsize-1);
	if(Gotsegv == 0)
		rv = rv == 0 ? 0 : 1;
	else	rv = -1;

	signal(SIGSEGV, segv); /* restore signal catcher */
	Gotsegv = 0;

	return rv;
}

/* A discipline to get raw memory using sbrk/VirtualAlloc/mmap */
#if __STD_C
static Void_t* sbrkmem(Vmalloc_t* vm, Void_t* caddr,
			size_t csize, size_t nsize, Vmdisc_t* disc)
#else
static Void_t* sbrkmem(vm, caddr, csize, nsize, disc)
Vmalloc_t*	vm;	/* region doing allocation from		*/
Void_t*		caddr;	/* current address			*/
size_t		csize;	/* current size				*/
size_t		nsize;	/* new size				*/
Vmdisc_t*	disc;	/* discipline structure			*/
#endif
{
#undef _done_sbrkmem

#if !defined(_done_sbrkmem) && defined(_mem_win32)
#define _done_sbrkmem	1
	NOTUSED(vm);
	NOTUSED(disc);
	if(csize == 0)
		return (Void_t*)VirtualAlloc(0,nsize,MEM_COMMIT,PAGE_READWRITE);
	else if(nsize == 0)
		return VirtualFree((LPVOID)caddr,0,MEM_RELEASE) ? caddr : NIL(Void_t*);
	else	return NIL(Void_t*);
#endif /* MUST_WIN32 */

#if !defined(_done_sbrkmem) && (_mem_sbrk || _mem_mmap_zero || _mem_mmap_anon)
#define _done_sbrkmem	1
	Vmuchar_t	*addr;
#if _mem_mmap_zero
	Mmapdisc_t	*mmdc = (Mmapdisc_t*)disc;
#else
	NOTUSED(disc);
#endif
	NOTUSED(vm);

	if(csize == 0) /* allocating new memory */
	{

#if _mem_sbrk	/* try using sbrk() and brk() */
		if(!(_Vmassert & VM_mmap))
		{
			addr = (Vmuchar_t*)sbrk(0); /* old break value */
			if(addr && addr != (Vmuchar_t*)BRK_FAILED )
			{
				if((addr+nsize) < addr)
					return NIL(Void_t*);
				if(brk(addr+nsize) == 0 ) 
				{	if(okaddr(addr,nsize) >= 0)
						return addr;
					(void)brk(addr); /* release reserved address */
				}
			}
		}
#endif /* _mem_sbrk */

#if _mem_mmap_anon /* anonymous mmap */
		addr = (Vmuchar_t*)mmap(0, nsize, PROT_READ|PROT_WRITE,
                                        MAP_ANON|MAP_PRIVATE, -1, 0);
		if(addr && addr != (Vmuchar_t*)MAP_FAILED)
		{	if(okaddr(addr,nsize) >= 0)
				return addr;
			(void)munmap((char*)addr, nsize); /* release reserved address */
		}
#endif /* _mem_mmap_anon */

#if _mem_mmap_zero /* mmap from /dev/zero */
		if(mmdc->fd < 0)
		{	int	fd;
			if(mmdc->fd != -1)
				return NIL(Void_t*);
			if((fd = open("/dev/zero", O_RDONLY)) < 0 )
			{	mmdc->fd = -2;
				return NIL(Void_t*);
			}
			if(fd >= OPEN_PRIVATE || (mmdc->fd = dup2(fd,OPEN_PRIVATE)) < 0 )
				mmdc->fd = fd;
			else	close(fd);
#ifdef FD_CLOEXEC
			fcntl(mmdc->fd, F_SETFD, FD_CLOEXEC);
#endif
		}
		addr = (Vmuchar_t*)mmap(0, nsize, PROT_READ|PROT_WRITE,
					MAP_PRIVATE, mmdc->fd, mmdc->offset);
		if(addr && addr != (Vmuchar_t*)MAP_FAILED)
		{	if(okaddr(addr, nsize) >= 0)
			{	mmdc->offset += nsize;
				return addr;
			}
			(void)munmap((char*)addr, nsize); /* release reserved address */
		}
#endif /* _mem_mmap_zero */

		return NIL(Void_t*);
	}
	else
	{

#if _mem_sbrk
		addr = (Vmuchar_t*)sbrk(0);
		if(!addr || addr == (Vmuchar_t*)BRK_FAILED)
			addr = caddr;
		else if(((Vmuchar_t*)caddr+csize) == addr) /* in sbrk-space */
		{	if(nsize <= csize)
				addr -= csize-nsize;
			else if((addr += nsize-csize) < (Vmuchar_t*)caddr)
				return NIL(Void_t*); /* wrapped around address */
			else	return brk(addr) == 0 ? caddr : NIL(Void_t*);
		}
#else
		addr = caddr;
#endif /* _mem_sbrk */

#if _mem_mmap_zero || _mem_mmap_anon
		if(((Vmuchar_t*)caddr+csize) > addr) /* in mmap-space */
			if(nsize == 0 && munmap(caddr,csize) == 0)
				return caddr;
#endif /* _mem_mmap_zero || _mem_mmap_anon */

		return NIL(Void_t*);
	}
#endif /*_done_sbrkmem*/

#if !_done_sbrkmem /* use native malloc/free as a last resort */
	/**/ASSERT(_std_malloc); /* _std_malloc should be well-defined */
	NOTUSED(vm);
	NOTUSED(disc);
	if(csize == 0)
		return (Void_t*)malloc(nsize);
	else if(nsize == 0)
	{	free(caddr);
		return caddr;
	}
	else	return NIL(Void_t*);
#endif /* _done_sbrkmem */
}

#if _mem_mmap_zero
static Mmapdisc_t _Vmdcsbrk = { { sbrkmem, NIL(Vmexcept_f), 64*1024 }, -1, 0 };
#else
static Vmdisc_t _Vmdcsbrk = { sbrkmem, NIL(Vmexcept_f), 0 };
#endif

static Vmethod_t _Vmbest =
{
	bestalloc,
	bestresize,
	bestfree,
	bestaddr,
	bestsize,
	bestcompact,
	bestalign,
	VM_MTBEST
};

/* The heap region */
static Vmdata_t	_Vmdata =
{
	VM_MTBEST|VM_TRUST,		/* mode		*/
	0,				/* incr		*/
	0,				/* pool		*/
	NIL(Seg_t*),			/* seg		*/
	NIL(Block_t*),			/* free		*/
	NIL(Block_t*),			/* wild		*/
	NIL(Block_t*),			/* root		*/
};
Vmalloc_t _Vmheap =
{
	{ bestalloc,
	  bestresize,
	  bestfree,
	  bestaddr,
	  bestsize,
	  bestcompact,
	  bestalign,
	  VM_MTBEST
	},
	NIL(char*),			/* file		*/
	0,				/* line		*/
	0,				/* func		*/
	(Vmdisc_t*)(&_Vmdcsbrk),	/* disc		*/
	&_Vmdata,			/* data		*/
	NIL(Vmalloc_t*)			/* next		*/
};

__DEFINE__(Vmalloc_t*, Vmheap, &_Vmheap);
__DEFINE__(Vmalloc_t*, Vmregion, &_Vmheap);
__DEFINE__(Vmethod_t*, Vmbest, &_Vmbest);
__DEFINE__(Vmdisc_t*,  Vmdcsbrk, (Vmdisc_t*)(&_Vmdcsbrk) );

#ifdef NoF
NoF(vmbest)
#endif

#endif
