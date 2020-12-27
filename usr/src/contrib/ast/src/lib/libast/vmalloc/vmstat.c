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

void _STUB_vmstat(){}

#else

#include	"vmhdr.h"

/*	Get statistics from a region.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

#if __STD_C
int vmstat(Vmalloc_t* vm, Vmstat_t* st)
#else
int vmstat(vm, st)
Vmalloc_t*	vm;
Vmstat_t*	st;
#endif
{
	size_t		s;
	Seg_t		*seg;
	Block_t		*b, *endb;
	Vmdata_t	*vd;
	Void_t		*d;

	if(!st) /* just checking lock state of region */
		return (vm ? vm : Vmregion)->data->lock;

	memset(st, 0, sizeof(Vmstat_t));

	if(!vm)
	{	/* getting data for malloc */
#if ( !_std_malloc || !_BLD_ast ) && !_AST_std_malloc
		extern int	_mallocstat(Vmstat_t*);
		return _mallocstat(st);
#else
		return -1;
#endif
	}

	SETLOCK(vm, 0);

	st->n_busy = st->n_free = 0;
	st->s_busy = st->s_free = st->m_busy = st->m_free = 0;
	st->n_seg = 0;
	st->extent = 0;

	vd = vm->data;
	st->mode = vd->mode;
	s = 0;
	if(vd->mode&VM_MTLAST)
		st->n_busy = 0;
	else if((vd->mode&VM_MTPOOL) && (s = vd->pool) > 0)
	{	s = ROUND(s,ALIGN);
		for(b = vd->free; b; b = SEGLINK(b))
			st->n_free += 1;
	}

	for(seg = vd->seg; seg; seg = seg->next)
	{	st->n_seg += 1;
		st->extent += seg->extent;

		b = SEGBLOCK(seg);
		endb = BLOCK(seg->baddr);

		if(vd->mode&(VM_MTDEBUG|VM_MTBEST|VM_MTPROFILE))
		{	while(b < endb)
			{	s = SIZE(b)&~BITS;
				if(ISJUNK(SIZE(b)) || !ISBUSY(SIZE(b)))
				{	if(s > st->m_free)
						st->m_free = s;
					st->s_free += s;
					st->n_free += 1;
				}
				else	/* get the real size */
				{	d = DATA(b);
					if(vd->mode&VM_MTDEBUG)
						s = DBSIZE(DB2DEBUG(d));
					else if(vd->mode&VM_MTPROFILE)
						s = PFSIZE(d);
					if(s > st->m_busy)
						st->m_busy = s;
					st->s_busy += s;
					st->n_busy += 1;
				}

				b = (Block_t*)((Vmuchar_t*)DATA(b) + (SIZE(b)&~BITS) );
			}
			/**/ASSERT(st->extent >= (st->s_busy + st->s_free));
		}
		else if(vd->mode&VM_MTLAST)
		{	if((s = seg->free ? (SIZE(seg->free) + sizeof(Head_t)) : 0) > 0)
			{	st->s_free += s;
				st->n_free += 1;
			}
			if((s = ((char*)endb - (char*)b) - s) > 0)
			{	st->s_busy += s;
				st->n_busy += 1;
			}
		}
		else if((vd->mode&VM_MTPOOL) && s > 0)
		{	if(seg->free)
				st->n_free += (SIZE(seg->free)+sizeof(Head_t))/s;
			st->n_busy += ((seg->baddr - (Vmuchar_t*)b) - sizeof(Head_t))/s;
		}
	}

	if((vd->mode&VM_MTPOOL) && s > 0)
	{	st->n_busy -= st->n_free;
		if(st->n_busy > 0)
			st->s_busy = (st->m_busy = vd->pool)*st->n_busy;
		if(st->n_free > 0)
			st->s_free = (st->m_free = vd->pool)*st->n_free;
	}

	CLRLOCK(vm, 0);

	return 0;
}

#endif
