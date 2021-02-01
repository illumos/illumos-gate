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
/*
 * hsearch() for systems that have <search.h> but no hsearch()
 * why would such a system provide the interface but not the
 * implementation? that's what happens when one slimes their
 * way through standards compliance
 *
 * NOTE: please excuse the crude feature test
 */

#if !_UWIN

void _STUB_hsearch(){}

#else

#if _PACKAGE_ast
#include	<ast.h>
#endif

#define hcreate		______hcreate
#define hdestroy	______hdestroy
#define hsearch		______hsearch

#include	<search.h>

#undef	hcreate
#undef	hdestroy
#undef	hsearch

#include	"dthdr.h"

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

/*	POSIX hsearch library based on libdt
**	Written by Kiem-Phong Vo (AT&T Research, 07/19/95)
*/

/* type of objects in hash table */
typedef struct _hash_s
{	Dtlink_t	link;
	ENTRY		item;
} Hash_t;

/* object delete function */
#if __STD_C
static void hashfree(Dt_t* dt, Void_t* obj, Dtdisc_t* disc)
#else
static void hashfree(dt, obj, disc)
Dt_t*		dt;
Void_t*		obj;
Dtdisc_t*	disc;
#endif
{
	free(((Hash_t*)obj)->item.key);
	free(obj);
}

static Dt_t*	Hashtab;	/* object dictionary	*/
static Dtdisc_t	Hashdisc =	/* discipline		*/
{	sizeof(Dtlink_t), -1,
	0,
	NIL(Dtmake_f), hashfree,
	NIL(Dtcompar_f),	/* always use strcmp	*/
	NIL(Dthash_f),
	NIL(Dtmemory_f),
	NIL(Dtevent_f)
};

extern
#if __STD_C
int hcreate(size_t nel)
#else
int hcreate(nel)
size_t	nel;
#endif
{
	if(Hashtab)	/* already opened */
		return 0;

	if(!(Hashtab = dtopen(&Hashdisc,Dtset)) )
		return 0;

	return 1;
}

extern void hdestroy()
{	if(Hashtab)
		dtclose(Hashtab);
	Hashtab = NIL(Dt_t*);
}

extern
#if __STD_C
ENTRY* hsearch(ENTRY item, ACTION action)
#else
ENTRY* hsearch(item, action)
ENTRY	item;
ACTION	action;
#endif
{
	reg Hash_t*	o;

	if(!Hashtab)
		return NIL(ENTRY*);

	if(!(o = (Hash_t*)dtmatch(Hashtab,item.key)) && action == ENTER &&
	   (o = (Hash_t*)malloc(sizeof(Hash_t)) ) )
	{	o->item = item;
		o = (Hash_t*)dtinsert(Hashtab,o);
	}

	return o ? &(o->item) : NIL(ENTRY*);
}

#endif
