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
static char*     Version = "\n@(#)$Id: cdt (AT&T Labs - Research) 2011-11-11 $\0\n";

/* 	Make a new dictionary
**
**	Written by Kiem-Phong Vo (5/25/96)
*/

/* map operation bits from the 2005 version to the current version */
static int _dttype2005(Dt_t* dt, int type)
{
	if (type == DT_DELETE && (dt->meth->type&(DT_OBAG|DT_BAG)))
		type = DT_REMOVE;
	return type;
}

#if __STD_C
Dt_t* _dtopen(Dtdisc_t* disc, Dtmethod_t* meth, unsigned long version)
#else
Dt_t*	_dtopen(disc, meth, version)
Dtdisc_t*	disc;
Dtmethod_t*	meth;
unsigned long	version;
#endif
{
	Dtdata_t	*data;
	Dt_t		*dt, pdt;
	int		ev, type;

	if(!disc || !meth)
		return NIL(Dt_t*);

	dt = NIL(Dt_t*);
	data = NIL(Dtdata_t*);
	type = meth->type;

	memset(&pdt, 0, sizeof(Dt_t));
	pdt.searchf = meth->searchf;
	pdt.meth = meth;
	dtdisc(&pdt,disc,0); /* note that this sets pdt.memoryf */

	if(disc->eventf)
	{	if((ev = (*disc->eventf)(&pdt,DT_OPEN,(Void_t*)(&data),disc)) < 0)
			return NIL(Dt_t*); /* something bad happened */
		else if(ev > 0)
		{	if(data) /* shared data are being restored */
			{	if((data->type & DT_METHODS) != meth->type)
				{	DTERROR(&pdt, "Error in matching methods to restore dictionary");
					return NIL(Dt_t*);
				}
				pdt.data = data;
			}
		}
		else
		{	if(data) /* dt should be allocated with dt->data */
				type |= DT_INDATA;
		}
	}

	if(!pdt.data) /* allocate method-specific data */
		if((*meth->eventf)(&pdt, DT_OPEN, NIL(Void_t*)) < 0 || !pdt.data )
			return NIL(Dt_t*);
	pdt.data->type |= type;

	/* now allocate/initialize the actual dictionary structure */
	if(pdt.data->type&DT_INDATA)
		dt = &pdt.data->dict;
	else if(!(dt = (Dt_t*) malloc(sizeof(Dt_t))) )
	{	(void)(*meth->eventf)(&pdt, DT_CLOSE, NIL(Void_t*));
		DTERROR(&pdt, "Error in allocating a new dictionary");
		return NIL(Dt_t*);
	}

	*dt = pdt;

	dt->user = &dt->data->user; /* space allocated for application usage */

	if(disc->eventf) /* signal opening is done */
		(void)(*disc->eventf)(dt, DT_ENDOPEN, (Void_t*)0, disc);

	/* set mapping of operation bits between versions as needed */
	if(version < 20111111L)
		dt->typef = _dttype2005;

	return dt;
}

#undef dtopen /* deal with binary upward compatibility for op bits */
#if __STD_C
Dt_t* dtopen(Dtdisc_t* disc, Dtmethod_t* meth)
#else
Dt_t*	dtopen(disc, meth)
Dtdisc_t*	disc;
Dtmethod_t*	meth;
#endif
{
	return _dtopen(disc, meth, 20050420L);
}

/* below are private functions used across CDT modules */
Dtlink_t* _dtmake(Dt_t* dt, Void_t* obj, int type)
{
	Dthold_t	*h;
	Dtdisc_t	*disc = dt->disc;

	/* if obj is a prototype, make a real one */
	if(!(type&DT_ATTACH) && disc->makef && !(obj = (*disc->makef)(dt, obj, disc)) )
		return NIL(Dtlink_t*);

	if(disc->link >= 0) /* holder is embedded in obj itself */
		return _DTLNK(disc, obj);

	/* create a holder to hold obj */
	if((h = (Dthold_t*)(dt->memoryf)(dt, NIL(Void_t*), sizeof(Dthold_t), disc)) )
		h->obj = obj;
	else
	{	DTERROR(dt, "Error in allocating an object holder");
		if(!(type&DT_ATTACH) && disc->makef && disc->freef)
			(void)(*disc->freef)(dt, obj, disc); /* free just-made obj */
	}

	return (Dtlink_t*)h;
}

void _dtfree(Dt_t* dt, Dtlink_t* l, int type)
{
	Dtdisc_t	*disc = dt->disc;

	if(!(type&DT_DETACH) && disc->freef) /* free object */
		(void)(*disc->freef)(dt, _DTOBJ(disc,l), disc);

	if(disc->link < 0) /* free holder */
		(void)(*dt->memoryf)(dt, (Void_t*)l, 0, disc);
}

int dtuserlock(Dt_t* dt, unsigned int key, int type)
{
	if(type > 0)
		return asolock(&dt->data->user.lock, key, ASO_LOCK);
	else if(type < 0)
		return asolock(&dt->data->user.lock, key, ASO_UNLOCK);
	else	return asolock(&dt->data->user.lock, key, ASO_TRYLOCK);
}

Void_t* dtuserdata(Dt_t* dt, Void_t* data, unsigned int key)
{
	if(key == 0)
		return dt->data->user.data;
	else if(dtuserlock(dt, key, 1) < 0 )
		return NIL(Void_t*);
	else
	{	dt->data->user.data = data;
		dtuserlock(dt, key, -1);
		return data;
	}
}
