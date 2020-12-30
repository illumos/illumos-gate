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
#ifndef _CDT_H
#define _CDT_H		1

/*	Public interface for the dictionary library
**
**      Written by Kiem-Phong Vo
*/

#ifndef CDT_VERSION
#ifdef _API_ast
#define CDT_VERSION		_API_ast
#else
#define CDT_VERSION		20111111L
#endif /*_AST_api*/
#endif /*CDT_VERSION*/
#ifndef AST_PLUGIN_VERSION
#define AST_PLUGIN_VERSION(v)	(v)
#endif
#define CDT_PLUGIN_VERSION	AST_PLUGIN_VERSION(20111111L)

#if _PACKAGE_ast
#include	<ast_std.h>
#else
#include	<ast_common.h>
#include	<string.h>
#endif

/* commonly used integers */
#define DT_ZERO		((unsigned int)0)  /* all zero bits	*/
#define DT_ONES		(~DT_ZERO)	   /* all one bits	*/
#define DT_HIBIT	(~(DT_ONES >> 1) ) /* highest 1 bit	*/
#define DT_LOBIT	((unsigned int)1)  /* lowest 1 bit	*/
#define DT_NBITS	(sizeof(unsigned int)*8) /* #bits	*/

/* type of an integer with the same size as a pointer */
#define Dtuint_t	uintptr_t

/* various types used by CDT */
typedef struct _dtlink_s	Dtlink_t;
typedef struct _dthold_s	Dthold_t;
typedef struct _dtdisc_s	Dtdisc_t;
typedef struct _dtmethod_s	Dtmethod_t;
typedef struct _dtdata_s	Dtdata_t;
typedef struct _dtuser_s	Dtuser_t;
typedef struct _dt_s		Dt_t;
typedef struct _dtstat_s	Dtstat_t;
typedef Void_t*			(*Dtsearch_f)_ARG_((Dt_t*,Void_t*,int));
typedef Void_t* 		(*Dtmake_f)_ARG_((Dt_t*,Void_t*,Dtdisc_t*));
typedef void 			(*Dtfree_f)_ARG_((Dt_t*,Void_t*,Dtdisc_t*));
typedef int			(*Dtcompar_f)_ARG_((Dt_t*,Void_t*,Void_t*,Dtdisc_t*));
typedef unsigned int		(*Dthash_f)_ARG_((Dt_t*,Void_t*,Dtdisc_t*));
typedef Void_t*			(*Dtmemory_f)_ARG_((Dt_t*,Void_t*,size_t,Dtdisc_t*));
typedef int			(*Dtevent_f)_ARG_((Dt_t*,int,Void_t*,Dtdisc_t*));
typedef int			(*Dttype_f)_ARG_((Dt_t*,int));

struct _dtuser_s /* for application to access and use */
{	unsigned int	lock;	/* used by dtapplock	*/
	Void_t*		data;	/* for whatever data	*/
};

struct _dtlink_s
{	
#if CDT_VERSION < 20111111L
	Dtlink_t*	right;	/* right child		*/
	union
	{ unsigned int	_hash;	/* hash value		*/
	  Dtlink_t*	_left;	/* left child		*/
	} hl;
#else
	union
	{ Dtlink_t*	__rght;	/* right child or next	*/
	  Dtlink_t*	__ptbl;	/* Dtrehash parent tbl	*/
	} rh;
	union
	{ Dtlink_t*	__left;	/* left child or prev	*/
	  unsigned int	__hash;	/* hash value of object	*/
	} lh;
#endif
};

/* private structure to hold an object */
struct _dthold_s
{	Dtlink_t	hdr;	/* header to hold obj	*/
	Void_t*		obj;	/* application object	*/
};

/* method to manipulate dictionary structure */
struct _dtmethod_s 
{	Dtsearch_f	searchf; /* search function	*/
	unsigned int	type;	 /* type of operation	*/
	int		(*eventf)_ARG_((Dt_t*, int, Void_t*));
	char*		name;	 /* name of method	*/
	char*		description; /* description */
};

/* structure to hold methods that manipulate an object */
struct _dtdisc_s
{	int		key;	/* where the key resides 	*/
	int		size;	/* key size and type		*/
	int		link;	/* offset to Dtlink_t field	*/
	Dtmake_f	makef;	/* object constructor		*/
	Dtfree_f	freef;	/* object destructor		*/
	Dtcompar_f	comparf;/* to compare two objects	*/
	Dthash_f	hashf;	/* to compute hash value 	*/
	Dtmemory_f	memoryf;/* to allocate/free memory	*/
	Dtevent_f	eventf;	/* to process events		*/
};

#define DTDISC(dc,ky,sz,lk,mkf,frf,cmpf,hshf,memf,evf) \
	( (dc)->key = (int)(ky), (dc)->size = (int)(sz), (dc)->link = (int)(lk), \
	  (dc)->makef = (mkf), (dc)->freef = (frf), \
	  (dc)->comparf = (cmpf), (dc)->hashf = (hshf), \
	  (dc)->memoryf = (memf), (dc)->eventf = (evf) )

#ifdef offsetof
#define DTOFFSET(struct_s, member)	offsetof(struct_s, member)
#else
#define DTOFFSET(struct_s, member)	((int)(&((struct_s*)0)->member))
#endif

/* the dictionary structure itself */
struct _dt_s
{	Dtsearch_f	searchf;/* search function		*/
	Dtdisc_t*	disc;	/* object type definitition	*/
	Dtdata_t*	data;	/* sharable data		*/
	Dtmemory_f	memoryf;/* for memory allocation	*/
	Dtmethod_t*	meth;	/* storage method		*/
	ssize_t		nview;	/* #parent view dictionaries	*/
	Dt_t*		view;	/* next on viewpath		*/
	Dt_t*		walk;	/* dictionary being walked	*/
	Dtuser_t*	user;	/* for user's usage		*/
	Dttype_f	typef;	/* for binary compatibility	*/
};

/* structure to get status of a dictionary */
#define DT_MAXRECURSE	1024	/* limit to avoid stack overflow	*/ 
#define DT_MAXSIZE	256	/* limit for size of below arrays	*/
struct _dtstat_s
{	unsigned int	meth;	/* method type				*/
	ssize_t		size;	/* total # of elements in dictionary	*/
	ssize_t		space;	/* memory usage of data structure	*/
	ssize_t		mlev;	/* max #levels in tree or hash table	*/
	ssize_t		msize;	/* max #defined elts in below arrays	*/
	ssize_t		lsize[DT_MAXSIZE]; /* #objects by level		*/
	ssize_t		tsize[DT_MAXSIZE]; /* #tables by level		*/
};

/* supported storage methods */
#define DT_SET		0000000001 /* unordered set, unique elements	*/
#define DT_BAG		0000000002 /* unordered set, repeated elements	*/
#define DT_OSET		0000000004 /* ordered set			*/
#define DT_OBAG		0000000010 /* ordered multiset			*/
#define DT_LIST		0000000020 /* linked list			*/
#define DT_STACK	0000000040 /* stack: insert/delete at top	*/
#define DT_QUEUE	0000000100 /* queue: insert top, delete at tail	*/
#define DT_DEQUE	0000000200 /* deque: insert top, append at tail	*/
#define DT_RHSET	0000000400 /* rhset: sharable unique objects	*/
#define DT_RHBAG	0000001000 /* rhbag: sharable repeated objects	*/
#define DT_METHODS	0000001777 /* all currently supported methods	*/
#define DT_ORDERED	(DT_OSET|DT_OBAG)

/* asserts to dtdisc() to improve performance when changing disciplines */
#define DT_SAMECMP	0000000001 /* compare functions are equivalent	*/
#define DT_SAMEHASH	0000000002 /* hash functions are equivalent	*/

/* operation types */
#define DT_INSERT	0000000001 /* insert object if not found	*/
#define DT_DELETE	0000000002 /* delete a matching object if any	*/
#define DT_SEARCH	0000000004 /* look for an object		*/
#define DT_NEXT		0000000010 /* look for next element		*/
#define DT_PREV		0000000020 /* find previous element		*/
#define DT_FIRST	0000000200 /* get first object			*/
#define DT_LAST		0000000400 /* get last object			*/
#define DT_MATCH	0000001000 /* find object matching key		*/
#define DT_ATTACH	0000004000 /* attach an object to dictionary	*/
#define DT_DETACH	0000010000 /* detach an object from dictionary	*/
#define DT_APPEND	0000020000 /* append an object			*/
#define DT_ATLEAST	0000040000 /* find the least elt >= object	*/
#define DT_ATMOST	0000100000 /* find the biggest elt <= object	*/
#define DT_REMOVE	0002000000 /* remove a specific object		*/
#define DT_TOANNOUNCE	(DT_INSERT|DT_DELETE|DT_SEARCH|DT_NEXT|DT_PREV|DT_FIRST|DT_LAST|DT_MATCH|DT_ATTACH|DT_DETACH|DT_APPEND|DT_ATLEAST|DT_ATMOST|DT_REMOVE)

#define DT_RELINK	0000002000 /* re-inserting (dtdisc,dtmethod...)	*/
#define DT_FLATTEN	0000000040 /* flatten objects into a list	*/
#define DT_CLEAR	0000000100 /* clearing all objects		*/
#define DT_EXTRACT	0000200000 /* FLATTEN and clear dictionary	*/
#define DT_RESTORE	0000400000 /* reinsert a list of elements	*/
#define DT_STAT		0001000000 /* get statistics of dictionary	*/
#define DT_OPERATIONS	(DT_TOANNOUNCE|DT_RELINK|DT_FLATTEN|DT_CLEAR|DT_EXTRACT|DT_RESTORE|DT_STAT)

/* these bits may combine with the DT_METHODS and DT_OPERATIONS bits */
#define DT_INDATA	0010000000 /* Dt_t was allocated with Dtdata_t	*/
#define DT_SHARE	0020000000 /* concurrent access mode 		*/
#define DT_ANNOUNCE	0040000000 /* announcing a successful operation	*/
				   /* the actual event will be this bit */
				   /* combined with the operation bit	*/
#define DT_OPTIMIZE	0100000000 /* optimizing data structure		*/

/* events for discipline and method event-handling functions */
#define DT_OPEN		1	/* a dictionary is being opened		*/
#define DT_ENDOPEN	5	/* end of dictionary opening		*/
#define DT_CLOSE	2	/* a dictionary is being closed		*/
#define DT_ENDCLOSE	6	/* end of dictionary closing		*/
#define DT_DISC		3	/* discipline is about to be changed	*/
#define DT_METH		4	/* method is about to be changed	*/
#define DT_HASHSIZE	7	/* initialize hash table size		*/
#define DT_ERROR	0xbad	/* announcing an error			*/

_BEGIN_EXTERNS_	/* data structures and functions */
#if _BLD_cdt && defined(__EXPORT__)
#define extern	__EXPORT__
#endif
#if !_BLD_cdt && defined(__IMPORT__)
#define extern	__IMPORT__
#endif

extern Dtmethod_t* 	Dtset;
extern Dtmethod_t* 	Dtbag;
extern Dtmethod_t* 	Dtoset;
extern Dtmethod_t* 	Dtobag;
extern Dtmethod_t*	Dtlist;
extern Dtmethod_t*	Dtstack;
extern Dtmethod_t*	Dtqueue;
extern Dtmethod_t*	Dtdeque;

#if _PACKAGE_ast /* dtplugin() for proprietary and non-standard methods -- requires -ldll */

#define dtplugin(name)	((Dtmethod_t*)dllmeth("cdt", name, CDT_PLUGIN_VERSION))

#define Dtrhbag		dtplugin("rehash:Dtrhbag")
#define Dtrhset		dtplugin("rehash:Dtrhset")

#else

#if CDTPROPRIETARY

extern Dtmethod_t*	Dtrhset;
extern Dtmethod_t*	Dtrhbag;

#endif /*CDTPROPRIETARY*/

#endif /*_PACKAGE_ast*/

#undef extern

#if _BLD_cdt && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern Dt_t*		dtopen _ARG_((Dtdisc_t*, Dtmethod_t*));
extern int		dtclose _ARG_((Dt_t*));
extern Dt_t*		dtview _ARG_((Dt_t*, Dt_t*));
extern Dtdisc_t*	dtdisc _ARG_((Dt_t* dt, Dtdisc_t*, int));
extern Dtmethod_t*	dtmethod _ARG_((Dt_t*, Dtmethod_t*));
extern int		dtwalk _ARG_((Dt_t*, int(*)(Dt_t*,Void_t*,Void_t*), Void_t*));
extern int		dtcustomize _ARG_((Dt_t*, int, int));
extern unsigned int	dtstrhash _ARG_((unsigned int, Void_t*, ssize_t));
extern int		dtuserlock _ARG_((Dt_t*, unsigned int, int));
extern Void_t*		dtuserdata _ARG_((Dt_t*, Void_t*, unsigned int));

/* deal with upward binary compatibility (operation bit translation, etc.) */
extern Dt_t*		_dtopen _ARG_((Dtdisc_t*, Dtmethod_t*, unsigned long));
#define dtopen(dc,mt)	_dtopen((dc), (mt), CDT_VERSION)

#undef extern

#if _PACKAGE_ast && !defined(_CDTLIB_H)

#if _BLD_dll && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern void*		dllmeth(const char*, const char*, unsigned long);

#undef	extern

#endif

_END_EXTERNS_

/* internal functions for translating among holder, object and key */
#define _DT(dt)		((Dt_t*)(dt))

#define _DTLNK(dc,o)	((Dtlink_t*)((char*)(o) + (dc)->link) ) /* get link from obj */

#define _DTO(dc,l)	(Void_t*)((char*)(l) - (dc)->link) /* get object from link */
#define _DTOBJ(dc,l)	((dc)->link >= 0 ? _DTO(dc,l) : ((Dthold_t*)(l))->obj )

#define _DTK(dc,o)	((char*)(o) + (dc)->key) /* get key from object */
#define _DTKEY(dc,o)	(Void_t*)((dc)->size >= 0 ? _DTK(dc,o) : *((char**)_DTK(dc,o)) ) 

#define _DTCMP(dt,k1,k2,dc) \
			((dc)->comparf  ? (*(dc)->comparf)((dt), (k1), (k2), (dc)) : \
			 (dc)->size > 0 ? memcmp((Void_t*)(k1), ((Void_t*)k2), (dc)->size) : \
					  strcmp((char*)(k1), ((char*)k2)) )

#define _DTHSH(dt,ky,dc) ((dc)->hashf   ? (*(dc)->hashf)((dt), (ky), (dc)) : \
					  dtstrhash(0, (ky), (dc)->size) )

#define dtvnext(d)	(_DT(d)->view)
#define dtvcount(d)	(_DT(d)->nview)
#define dtvhere(d)	(_DT(d)->walk)

#define dtlink(d,e)	(((Dtlink_t*)(e))->rh.__rght)
#define dtobj(d,e)	_DTOBJ(_DT(d)->disc, (e))

#define dtfirst(d)	(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_FIRST)
#define dtnext(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_NEXT)
#define dtatleast(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_ATLEAST)
#define dtlast(d)	(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_LAST)
#define dtprev(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_PREV)
#define dtatmost(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_ATMOST)
#define dtsearch(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_SEARCH)
#define dtmatch(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_MATCH)
#define dtinsert(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_INSERT)
#define dtappend(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_APPEND)
#define dtdelete(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_DELETE)
#define dtremove(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_REMOVE)
#define dtattach(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_ATTACH)
#define dtdetach(d,o)	(*(_DT(d)->searchf))((d),(Void_t*)(o),DT_DETACH)
#define dtclear(d)	(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_CLEAR)

#define dtflatten(d)	(Dtlink_t*)(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_FLATTEN)
#define dtextract(d)	(Dtlink_t*)(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_EXTRACT)
#define dtrestore(d,l)	(Dtlink_t*)(*(_DT(d)->searchf))((d),(Void_t*)(l),DT_RESTORE)

#define dtstat(d,s)	(ssize_t)(*(_DT(d)->searchf))((d),(Void_t*)(s),DT_STAT)
#define dtsize(d)	(ssize_t)(*(_DT(d)->searchf))((d),(Void_t*)(0),DT_STAT)

#define DT_PRIME	17109811 /* 2#00000001 00000101 00010011 00110011 */
#define dtcharhash(h,c) (((unsigned int)(h) + (unsigned int)(c)) * DT_PRIME )

#endif /* _CDT_H */
