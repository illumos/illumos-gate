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

/*	List, Stack, Queue.
**
**	Written by Kiem-Phong Vo (05/25/96)
*/

#if __STD_C
static Void_t* dtlist(reg Dt_t* dt, reg Void_t* obj, reg int type)
#else
static Void_t* dtlist(dt, obj, type)
reg Dt_t*	dt;
reg Void_t*	obj;
reg int		type;
#endif
{
	reg int		lk, sz, ky;
	reg Dtcompar_f	cmpf;
	reg Dtdisc_t*	disc;
	reg Dtlink_t	*r, *t;
	reg Void_t	*key, *k;

	UNFLATTEN(dt);
	disc = dt->disc; _DTDSC(disc,ky,sz,lk,cmpf);
	dt->type &= ~DT_FOUND;

	if(!obj)
	{	if(type&(DT_LAST|DT_FIRST) )
		{	if((r = dt->data->head) )
			{	if(type&DT_LAST)
					r = r->left;
				dt->data->here = r;
			}
			return r ? _DTOBJ(r,lk) : NIL(Void_t*);
		}
		else if(type&(DT_DELETE|DT_DETACH))
		{	if((dt->data->type&DT_LIST) || !(r = dt->data->head))
				return NIL(Void_t*);
			else	goto dt_delete;
		}
		else if(type&DT_CLEAR)
		{	if(disc->freef || disc->link < 0)
			{	for(r = dt->data->head; r; r = t)
				{	t = r->right;
					if(disc->freef)
						(*disc->freef)(dt,_DTOBJ(r,lk),disc);
					if(disc->link < 0)
						(*dt->memoryf)(dt,(Void_t*)r,0,disc);
				}
			}
			dt->data->head = dt->data->here = NIL(Dtlink_t*);
			dt->data->size = 0;
			return NIL(Void_t*);
		}
		else	return NIL(Void_t*);
	}

	if(type&(DT_INSERT|DT_ATTACH))
	{	if(disc->makef && (type&DT_INSERT) &&
		   !(obj = (*disc->makef)(dt,obj,disc)) )
			return NIL(Void_t*);
		if(lk >= 0)
			r = _DTLNK(obj,lk);
		else
		{	r = (Dtlink_t*)(*dt->memoryf)
				(dt,NIL(Void_t*),sizeof(Dthold_t),disc);
			if(r)
				((Dthold_t*)r)->obj = obj;
			else
			{	if(disc->makef && disc->freef && (type&DT_INSERT))
					(*disc->freef)(dt,obj,disc);
				return NIL(Void_t*);
			}
		}

		if(dt->data->type&DT_LIST)
		{	if((t = dt->data->here) && t != dt->data->head)
			{	r->left = t->left;
				t->left->right = r;
				r->right = t;
				t->left = r;
			}
			else	goto dt_stack;
		}
		else if(dt->data->type&DT_STACK)
		{ dt_stack:
			r->right = t = dt->data->head;
			if(t)
			{	r->left = t->left;
				t->left = r;
			}
			else	r->left = r;
			dt->data->head = r;
		}
		else /* if(dt->data->type&DT_QUEUE) */
		{	if((t = dt->data->head) )
			{	t->left->right = r;
				r->left = t->left;
				t->left = r;
			}
			else
			{	dt->data->head = r;
				r->left = r;
			}
			r->right = NIL(Dtlink_t*);
		}

		if(dt->data->size >= 0)
			dt->data->size += 1;

		dt->data->here = r;
		return _DTOBJ(r,lk);
	}

	if((type&DT_MATCH) || !(r = dt->data->here) || _DTOBJ(r,lk) != obj)
	{	key = (type&DT_MATCH) ? obj : _DTKEY(obj,ky,sz);
		for(r = dt->data->head; r; r = r->right)
		{	k = _DTOBJ(r,lk); k = _DTKEY(k,ky,sz);
			if(_DTCMP(dt,key,k,disc,cmpf,sz) == 0)
				break;
		}
	}

	if(!r)
		return NIL(Void_t*);
	dt->type |= DT_FOUND;

	if(type&(DT_DELETE|DT_DETACH))
	{ dt_delete:
		if(r->right)
			r->right->left = r->left;
		if(r == (t = dt->data->head) )
		{	dt->data->head = r->right;
			if(dt->data->head)
				dt->data->head->left = t->left;
		}
		else
		{	r->left->right = r->right;
			if(r == t->left)
				t->left = r->left;
		}

		dt->data->here = r == dt->data->here ? r->right : NIL(Dtlink_t*);
		dt->data->size -= 1;

		obj = _DTOBJ(r,lk);
		if(disc->freef && (type&DT_DELETE))
			(*disc->freef)(dt,obj,disc);
		if(disc->link < 0)
			(*dt->memoryf)(dt,(Void_t*)r,0,disc);
		return obj;
	}
	else if(type&DT_NEXT)
		r = r->right;
	else if(type&DT_PREV)
		r = r == dt->data->head ? NIL(Dtlink_t*) : r->left;

	dt->data->here = r;
	return r ? _DTOBJ(r,lk) : NIL(Void_t*);
}

#ifndef KPVDEL	/* to be remove next round */
#define static 
#endif
static Dtmethod_t _Dtlist  = { dtlist, DT_LIST  };
static Dtmethod_t _Dtstack = { dtlist, DT_STACK };
static Dtmethod_t _Dtqueue = { dtlist, DT_QUEUE };

__DEFINE__(Dtmethod_t*,Dtlist,&_Dtlist);
__DEFINE__(Dtmethod_t*,Dtstack,&_Dtstack);
__DEFINE__(Dtmethod_t*,Dtqueue,&_Dtqueue);

#ifdef NoF
NoF(dtlist)
#endif
