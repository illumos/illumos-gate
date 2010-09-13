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
#include	"dthdr.h"

/*	Extract objects of a dictionary.
**
**	Written by Kiem-Phong Vo (5/25/96).
*/

#if __STD_C
Dtlink_t* dtextract(reg Dt_t* dt)
#else
Dtlink_t* dtextract(dt)
reg Dt_t*	dt;
#endif
{
	reg Dtlink_t	*list, **s, **ends;

	if(dt->data->type&(DT_OSET|DT_OBAG) )
		list = dt->data->here;
	else if(dt->data->type&(DT_SET|DT_BAG))
	{	list = dtflatten(dt);
		for(ends = (s = dt->data->htab) + dt->data->ntab; s < ends; ++s)
			*s = NIL(Dtlink_t*);
	}
	else /*if(dt->data->type&(DT_LIST|DT_STACK|DT_QUEUE))*/
	{	list = dt->data->head;
		dt->data->head = NIL(Dtlink_t*);
	}

	dt->data->type &= ~DT_FLATTEN;
	dt->data->size = 0;
	dt->data->here = NIL(Dtlink_t*);

	return list;
}
