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
#include	"dthdr.h"

/*	Ordered set/multiset
**	dt:	dictionary being searched
**	obj:	the object to look for.
**	type:	search type.
**
**      Written by Kiem-Phong Vo (5/25/96)
*/

typedef struct _dttree_s
{	Dtdata_t	data;
	Dtlink_t*	root;	/* tree root */
} Dttree_t;

#ifdef CDT_DEBUG
int dttreeprint(Dt_t* dt, Dtlink_t* here, int lev, char* (*objprintf)(Void_t*) )
{
	int		k, rv;
	char		*obj, *endb, buf[1024];
	Dtdisc_t	*disc = dt->disc;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	if(!here && !(here = tree->root) )
		return -1;

	endb = buf; /* indentation */
	for(k = 0; k < lev; ++k)
		{ *endb++ = ' '; *endb++ = ' '; }

	*endb++ = '(';
	obj = (*objprintf)(_DTOBJ(disc, here));
	k = strlen(obj); memcpy(endb, obj, k); endb += k;
	*endb++ = ')';
	*endb++ = ':';
	*endb++ = ' ';

	*endb++ = '<';
	if(here->_left)
		obj = (*objprintf)(_DTOBJ(disc,here->_left)); 
	else	obj = "NIL";
	k = strlen(obj); memcpy(endb, obj, k); endb += k;
	*endb++ = '>';
	*endb++ = ' ';

	*endb++ = '<';
	if(here->_rght)
		obj = (*objprintf)(_DTOBJ(disc,here->_rght)); 
	else	obj = "NIL";
	k = strlen(obj); memcpy(endb, obj, k); endb += k;
	*endb++ = '>';
	*endb++ = '\n';
	write(2, buf, endb-buf);

	if(here->_left)
		dttreeprint(dt, here->_left, lev+1, objprintf);
	if(here->_rght)
		dttreeprint(dt, here->_rght, lev+1, objprintf);

	return 0;
}
#endif

/* terminal object: DT_FIRST|DT_LAST */
#if __STD_C
Void_t* tfirstlast(Dt_t* dt, int type)
#else
Void_t* tfirstlast(dt, type)
Dt_t*	dt;
int	type;
#endif
{
	Dtlink_t	*t, *root;
	Dtdisc_t	*disc = dt->disc;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	if(!(root = tree->root) )
		return NIL(Void_t*);

	if(type&DT_LAST)
	{	while((t = root->_rght) )
			LROTATE(root,t);
	}
	else /* type&DT_FIRST */
	{	while((t = root->_left) )
			RROTATE(root,t);
	}
	tree->root = root;

	return _DTOBJ(disc, root);
}

/* DT_CLEAR */
#if __STD_C
static Void_t* tclear(Dt_t* dt)
#else
static Void_t* tclear(dt)
Dt_t*	dt;
#endif
{
	Dtlink_t	*root, *t;
	Dtdisc_t	*disc = dt->disc;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	root = tree->root;
	tree->root = NIL(Dtlink_t*);
	tree->data.size = 0;

	if(root && (disc->link < 0 || disc->freef) )
	{	do
		{	while((t = root->_left) )
				RROTATE(root,t);
			t = root->_rght;
			_dtfree(dt, root, DT_DELETE);
		} while((root = t) );
	}

	return NIL(Void_t*);
}

#if __STD_C
static Void_t* tlist(Dt_t* dt, Dtlink_t* list, int type)
#else
static Void_t* tlist(dt, list, type)
Dt_t*   	dt;
Dtlink_t*	list;    
int     	type;
#endif
{
	Void_t		*obj;
	Dtlink_t	*last, *r, *t;
	Dttree_t	*tree = (Dttree_t*)dt->data;
	Dtdisc_t	*disc = dt->disc;

	if(type&(DT_FLATTEN|DT_EXTRACT) )
	{	if((list = tree->root) )
		{	while((t = list->_left) ) /* make smallest object root */
				RROTATE(list, t);
			for(r = (last = list)->_rght; r; r = (last = r)->_rght)
			{	while((t = r->_left) ) /* no left children */
					RROTATE(r,t);
				last->_rght = r;
			}
		}

		if(type&DT_FLATTEN)
			tree->root = list;
		else
		{	tree->root = NIL(Dtlink_t*);
			dt->data->size = 0;
		}
	}
	else /* if(type&DT_RESTORE) */
	{	dt->data->size = 0;
		for(r = list; r; r = t)
		{	t = r->_rght;
			obj = _DTOBJ(disc,r);
			if((*dt->meth->searchf)(dt, (Void_t*)r, DT_RELINK) == obj )
				dt->data->size += 1;
		}
	}

	return (Void_t*)list;
}

#if __STD_C /* compute tree depth and number of nodes */
static ssize_t tsize(Dtlink_t* root, ssize_t lev, Dtstat_t* st)
#else
static ssize_t tsize(root, lev, st)
Dtlink_t*	root;
ssize_t		lev;
Dtstat_t*	st;
#endif
{
	ssize_t		size, z;

	if(!root) /* nothing to do */
		return 0;

	if(lev >= DT_MAXRECURSE) /* avoid blowing the stack */
		return -1;

	if(st)
	{	st->mlev = lev > st->mlev ? lev : st->mlev;
		if(lev < DT_MAXSIZE)
		{	st->msize = lev > st->msize ? lev : st->msize;
			st->lsize[lev] += 1; /* count #objects per level */
		}
	}

	size = 1;

	if((z = tsize(root->_left, lev+1, st)) < 0)
		return -1;
	else	size += z;

	if((z = tsize(root->_rght, lev+1, st)) < 0)
		return -1;
	else	size += z;

	return size;
}

#if __STD_C
static Void_t* tstat(Dt_t* dt, Dtstat_t* st)
#else
static Void_t* tstat(dt, st)
Dt_t*		dt;
Dtstat_t*	st;
#endif
{
	ssize_t		size;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	if(!st)
		return (Void_t*)dt->data->size;
	else
	{	memset(st, 0, sizeof(Dtstat_t));
		size = tsize(tree->root, 0, st);
		/**/DEBUG_ASSERT((dt->data->type&DT_SHARE) || size == dt->data->size);
		st->meth  = dt->meth->type;
		st->size  = size;
		st->space = sizeof(Dttree_t) + (dt->disc->link >= 0 ? 0 : size*sizeof(Dthold_t));
		return (Void_t*)size;
	}
}

#if __STD_C /* make a list into a balanced tree */
static Dtlink_t* tbalance(Dtlink_t* list, ssize_t size)
#else
static Dtlink_t* tbalance(list, size)
Dtlink_t*	list;
ssize_t		size;
#endif
{
	ssize_t		n;
	Dtlink_t	*l, *mid;

	if(size <= 2)
		return list;

	for(l = list, n = size/2 - 1; n > 0; n -= 1)
		l = l->_rght;

	mid = l->_rght; l->_rght = NIL(Dtlink_t*);
	mid->_left = tbalance(list, (n = size/2) );
	mid->_rght = tbalance(mid->_rght, size - (n + 1));
	return mid;
}

static void toptimize(Dt_t* dt)
{
	ssize_t		size;
	Dtlink_t	*l, *list;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	if((list = (Dtlink_t*)tlist(dt, NIL(Void_t*), DT_FLATTEN)) )
	{	for(size = 0, l = list; l; l = l->_rght)
			size += 1;
		tree->root = tbalance(list, size);
	}
}

static Dtlink_t* troot(Dt_t* dt, Dtlink_t* list, Dtlink_t* link, Void_t* obj, int type)
{
	Dtlink_t	*root, *last, *t, *r, *l;
	Void_t		*key, *o, *k;
	Dtdisc_t	*disc = dt->disc;

	key = _DTKEY(disc, obj); /* key of object */

	if(type&(DT_ATMOST|DT_ATLEAST) ) /* find the left-most or right-most element */
	{	list->_left = link->_rght;
		list->_rght = link->_left;
		if(type&DT_ATMOST)
		{	while((l = list->_left) )
			{	while((r = l->_rght) ) /* get the max elt of left subtree */
					LROTATE(l,r);
				list->_left = l;

				o = _DTOBJ(disc,l); k = _DTKEY(disc,o);
				if(_DTCMP(dt, key, k, disc) != 0 )
					break;
				else	RROTATE(list,l);
			}
		}
		else
		{	while((r = list->_rght) )
			{	while((l = r->_left) ) /* get the min elt of right subtree */
					RROTATE(r,l);
				list->_rght = r;

				o = _DTOBJ(disc,r); k = _DTKEY(disc,o);
				if(_DTCMP(dt, key, k, disc) != 0 )
					break;
				else	LROTATE(list,r);
			}
		}
		link->_rght = list->_left;
		link->_left = list->_rght;
		return list;
	}

	last = list; list->_left = list->_rght = NIL(Dtlink_t*);
	root = NIL(Dtlink_t*);

	while(!root && (t = link->_rght) ) /* link->_rght is the left subtree <= obj */
	{	while((r = t->_rght) ) /* make t the maximum element */
			LROTATE(t,r);

		o = _DTOBJ(disc,t); k = _DTKEY(disc,o);
		if(_DTCMP(dt, key, k, disc) != 0 )
		{	link->_rght = t; /* no more of this group in subtree */
			break;
		}
		else if((type & (DT_REMOVE|DT_NEXT|DT_PREV)) && o == obj)
		{	link->_rght = t->_left; /* found the exact object */
			root = t;
		}
		else /* add t to equal list in an order-preserving manner */
		{	link->_rght = t->_left;
			t->_left = t->_rght = NIL(Dtlink_t*);
			if(type&DT_NEXT )
				{ last->_left = t; last = t; }
			else	{ t->_rght = list; list = t; }
		}
	}

	while(!root && (t = link->_left) ) /* link->_left is the right subtree >= obj */
	{	while((l = t->_left) ) /* make t the minimum element */
			RROTATE(t,l);

		o = _DTOBJ(disc,t); k = _DTKEY(disc,o);
		if(_DTCMP(dt, key, k, disc) != 0 )
		{	link->_left = t; /* no more of this group in subtree */
			break; 
		}
		else if((type & (DT_REMOVE|DT_NEXT|DT_PREV)) && o == obj)
		{	link->_left = t->_rght; /* found the exact object */
			root = t;
		}
		else /* add t to equal list in an order-preserving manner */
		{	link->_left = t->_rght;
			t->_left = t->_rght = NIL(Dtlink_t*);
			if(type&DT_NEXT )
				{ t->_left = list; list = t; }
			else	{ last->_rght = t; last = t; }
		}
	}

	if(!root) /* always set a non-trivial root */
	{	root = list;
		if(type&DT_NEXT)
			list = list->_left;
		else	list = list->_rght;
	}

	if(list) /* add the rest of the equal-list to the proper subtree */
	{	if(type&DT_NEXT) 
		{	last->_left = link->_rght;
			link->_rght = list;
		}
		else
		{	last->_rght = link->_left;
			link->_left = list;
		}
	}

	return root;
}

#if __STD_C
static Void_t* dttree(Dt_t* dt, Void_t* obj, int type)
#else
static Void_t* dttree(dt,obj,type)
Dt_t*		dt;
Void_t* 	obj;
int		type;
#endif
{
	int		cmp;
	Void_t		*o, *k, *key;
	Dtlink_t	*root, *t, *l, *r, *me, link;
	Dtdisc_t	*disc = dt->disc;
	Dttree_t	*tree = (Dttree_t*)dt->data;

	type = DTTYPE(dt, type); /* map type for upward compatibility */
	if(!(type&DT_OPERATIONS) )
		return NIL(Void_t*);

	DTSETLOCK(dt);

	if(type&(DT_FIRST|DT_LAST) )
		DTRETURN(obj, tfirstlast(dt, type));
	else if(type&(DT_EXTRACT|DT_RESTORE|DT_FLATTEN))
		DTRETURN(obj, tlist(dt, (Dtlink_t*)obj, type));
	else if(type&DT_CLEAR)
		DTRETURN(obj, tclear(dt));
	else if(type&DT_STAT)
	{	toptimize(dt); /* balance tree to avoid deep recursion */
		DTRETURN(obj, tstat(dt, (Dtstat_t*)obj));
	}

	if(!obj) /* from here on, an object prototype is required */
		DTRETURN(obj, NIL(Void_t*));

	if(type&DT_RELINK) /* relinking objects after some processing */
	{	me = (Dtlink_t*)obj;
		obj = _DTOBJ(disc,me);
		key = _DTKEY(disc,obj);
	}
	else
	{	me = NIL(Dtlink_t*);
		if(type&DT_MATCH) /* no prototype object given, just the key */
		{	key = obj;
			obj = NIL(Void_t*);
		}
		else	key = _DTKEY(disc,obj); /* get key from prototype object */
	}

	memset(&link, 0, sizeof(link));
	l = r = &link; /* link._rght(_left) will be LEFT(RIGHT) tree after splaying */
	if((root = tree->root) && _DTOBJ(disc,root) != obj) /* splay-search for a matching object */
	{	while(1)
		{	o = _DTOBJ(disc,root); k = _DTKEY(disc,o);
			if((cmp = _DTCMP(dt,key,k,disc)) == 0)
				break;
			else if(cmp < 0)
			{	if((t = root->_left) )
				{	o = _DTOBJ(disc,t); k = _DTKEY(disc,o);
					if((cmp = _DTCMP(dt,key,k,disc)) < 0)
					{	rrotate(root,t);
						rlink(r,t);
						if(!(root = t->_left) )
							break;
					}
					else if(cmp == 0)
					{	rlink(r,root);
						root = t;
						break;
					}
					else /* if(cmp > 0) */
					{	llink(l,t);
						rlink(r,root);
						if(!(root = t->_rght) )
							break;
					}
				}
				else
				{	rlink(r,root);
					root = NIL(Dtlink_t*);
					break;
				}
			}
			else /* if(cmp > 0) */
			{	if((t = root->_rght) )
				{	o = _DTOBJ(disc,t); k = _DTKEY(disc,o);
					if((cmp = _DTCMP(dt,key,k,disc)) > 0)
					{	lrotate(root,t);
						llink(l,t);
						if(!(root = t->_rght) )
							break;
					}
					else if(cmp == 0)
					{	llink(l,root);
						root = t;
						break;
					}
					else /* if(cmp < 0) */
					{	rlink(r,t);
						llink(l,root);
						if(!(root = t->_left) )
							break;
					}
				}
				else
				{	llink(l,root);
					root = NIL(Dtlink_t*);
					break;
				}
			}
		}
	}
	l->_rght = root ? root->_left : NIL(Dtlink_t*);
	r->_left = root ? root->_rght : NIL(Dtlink_t*);

	if(root)
	{	if(dt->meth->type&DT_OBAG ) /* may need to reset root to the right object */
		{	if((type&(DT_ATLEAST|DT_ATMOST)) ||
			   ((type&(DT_NEXT|DT_PREV|DT_REMOVE)) && _DTOBJ(disc,root) != obj) )
				root = troot(dt, root, &link, obj, type);
		}

		if(type&(DT_SEARCH|DT_MATCH|DT_ATMOST|DT_ATLEAST))
		{ has_root: /* reconstitute the tree */
			root->_left = link._rght;
			root->_rght = link._left;
			tree->root = root;
			DTRETURN(obj, _DTOBJ(disc,root));
		}
		else if(type&DT_NEXT)
		{	root->_left = link._rght;
			root->_rght = NIL(Dtlink_t*);
			link._rght = root;
		dt_next:
			if((root = link._left) )	
			{	while((t = root->_left) )
					RROTATE(root,t);
				link._left = root->_rght;
				goto has_root;
			}
			else	goto no_root;
		}
		else if(type&DT_PREV)
		{	root->_rght = link._left;
			root->_left = NIL(Dtlink_t*);
			link._left = root;
		dt_prev:
			if((root = link._rght) )
			{	while((t = root->_rght) )
					LROTATE(root,t);
				link._rght = root->_left;
				goto has_root;
			}
			else	goto no_root;
		}
		else if(type&DT_REMOVE) /* remove a particular element in the tree */
		{	if(_DTOBJ(disc,root) == obj)
				goto dt_delete;
			else
			{	root->_left = link._rght;
				root->_rght = link._left;
				tree->root = root; 
				DTRETURN(obj, NIL(Void_t*));
			}
		}
		else if(type&(DT_DELETE|DT_DETACH))
		{ dt_delete: /* remove an object from the dictionary */
			obj = _DTOBJ(disc,root);
			_dtfree(dt, root, type);
			dt->data->size -= 1;
			goto no_root;
		}
		else if(type&(DT_INSERT|DT_APPEND|DT_ATTACH))
		{	if(dt->meth->type&DT_OSET)
			{	type |= DT_SEARCH; /* for announcement */
				goto has_root;
			}
			else
			{	root->_left = NIL(Dtlink_t*);
				root->_rght = link._left;
				link._left = root;
				goto dt_insert;
			}
		}
		else if(type&DT_RELINK) /* a duplicate */
		{	if(dt->meth->type&DT_OSET)
				_dtfree(dt, me, DT_DELETE);
			else
			{	me->_left = NIL(Dtlink_t*);
				me->_rght = link._left;
				link._left = me;
			}
			goto has_root;
		}
	}
	else /* no matching object, tree has been split to LEFT&RIGHT subtrees */
	{	if(type&(DT_SEARCH|DT_MATCH))
		{ no_root: 
			if(!(l = link._rght) ) /* no LEFT subtree */
				tree->root = link._left; /* tree is RIGHT tree */
			else
			{	while((t = l->_rght) ) /* maximize root of LEFT tree */
				{	if(t->_rght)
						LLSHIFT(l,t);
					else	LROTATE(l,t);
				}
				l->_rght = link._left; /* hook RIGHT tree to LEFT root */
				tree->root = l; /* LEFT tree is now the entire tree */
			}

			if(type&(DT_DELETE|DT_DETACH|DT_REMOVE))
				DTRETURN(obj, obj);
			else	DTRETURN(obj, NIL(Void_t*));
		}
		else if(type&(DT_NEXT|DT_ATLEAST) )
			goto dt_next;
		else if(type&(DT_PREV|DT_ATMOST) )
			goto dt_prev;
		else if(type&(DT_DELETE|DT_DETACH|DT_REMOVE))
		{	obj = NIL(Void_t*);
			goto no_root;
		}
		else if(type&(DT_INSERT|DT_APPEND|DT_ATTACH))
		{ dt_insert:
			if(!(root = _dtmake(dt, obj, type)) )
			{	obj = NIL(Void_t*);
				goto no_root;
			}
			else
			{	dt->data->size += 1;
				goto has_root;
			}
		}
		else if(type&DT_RELINK)
		{	root = me;
			goto has_root;
		}
	}
	DTRETURN(obj, NIL(Void_t*));

dt_return:
	DTANNOUNCE(dt,obj,type);
	DTCLRLOCK(dt);
	return obj;
}

static int treeevent(Dt_t* dt, int event, Void_t* arg)
{
	Dttree_t	*tree = (Dttree_t*)dt->data;

	if(event == DT_OPEN)
	{	if(tree) /* already initialized */
			return 0;
		if(!(tree = (Dttree_t*)(*dt->memoryf)(dt, 0, sizeof(Dttree_t), dt->disc)) )
		{	DTERROR(dt, "Error in allocating a tree data structure");
			return -1;
		}
		memset(tree, 0, sizeof(Dttree_t));
		dt->data = (Dtdata_t*)tree;
		return 1;
	}
	else if(event == DT_CLOSE)
	{	if(!tree)
			return 0;
		if(tree->root)
			(void)tclear(dt);
		(void)(*dt->memoryf)(dt, (Void_t*)tree, 0, dt->disc);
                dt->data = NIL(Dtdata_t*);
                return 0;
	}
	else if(event == DT_OPTIMIZE) /* balance the search tree */
	{	toptimize(dt);
		return 0;
	}
	else	return 0;
}

#if _UWIN

Void_t* dtfinger(Dt_t* dt)
{
	return (dt && dt->meth && (dt->meth->type & DT_ORDERED)) ? (Void_t*)((Dttree_t*)dt->data)->root : NIL(Void_t*);
}

#endif

/* make this method available */
static Dtmethod_t	_Dtoset =  { dttree, DT_OSET, treeevent, "Dtoset" };
static Dtmethod_t	_Dtobag =  { dttree, DT_OBAG, treeevent, "Dtobag" };
__DEFINE__(Dtmethod_t*,Dtoset,&_Dtoset);
__DEFINE__(Dtmethod_t*,Dtobag,&_Dtobag);

/* backwards compatibility */
#undef	Dttree
#if defined(__EXPORT__)
__EXPORT__
#endif
__DEFINE__(Dtmethod_t*,Dttree,&_Dtoset);

#ifdef NoF
NoF(dttree)
#endif
