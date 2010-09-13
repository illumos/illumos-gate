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

/* Set attributes of a tree.
**
** Written by Kiem-Phong Vo (09/17/2001)
*/

#if __STD_C
static Dtlink_t* treebalance(Dtlink_t* list, int size)
#else
static Dtlink_t* treebalance(list, size)
Dtlink_t*	list;
int		size;
#endif
{
	int		n;
	Dtlink_t	*l, *mid;

	if(size <= 2)
		return list;

	for(l = list, n = size/2 - 1; n > 0; n -= 1)
		l = l->right;

	mid = l->right; l->right = NIL(Dtlink_t*);
	mid->left  = treebalance(list, (n = size/2) );
	mid->right = treebalance(mid->right, size - (n + 1));
	return mid;
}

#if __STD_C
int dttreeset(Dt_t* dt, int minp, int balance)
#else
int dttreeset(dt, minp, balance)
Dt_t*	dt;
int	minp;
int	balance;
#endif
{
	int	size;

	if(dt->meth->type != DT_OSET)
		return -1;

	size = dtsize(dt);

	if(minp < 0)
	{	for(minp = 0; minp < DT_MINP; ++minp)
			if((1 << minp) >= size)
				break;
		if(minp <= DT_MINP-4)	/* use log(size) + 4 */
			minp += 4;
	}

	if((dt->data->minp = minp + (minp%2)) > DT_MINP)
		dt->data->minp = DT_MINP;

	if(balance)
		dt->data->here = treebalance(dtflatten(dt), size);

	return 0;
}
