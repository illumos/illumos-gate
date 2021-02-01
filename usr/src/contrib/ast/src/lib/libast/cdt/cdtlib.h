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
#ifndef _CDTLIB_H
#define _CDTLIB_H	1

/*	cdt library/method implementation header
**	this header is exported to the method libraries
**	Written by Kiem-Phong Vo (5/25/96)
*/

#if _PACKAGE_ast
#include	<ast.h>
#if !_BLD_cdt
#include	<dlldefs.h>
#endif
#endif

#include	<cdt.h>
#include	<unistd.h>
#include	<aso.h>

#include	"debug.h"

/* short-hand notations */
#define NIL(t)	((t)0)
#define reg	register

/* min #bits for a hash table. (1<<this) is table size */
#define DT_HTABLE	10

/* convenient types */
#if !defined(uint)
#define uint	unsigned int
#endif
#if !defined(uchar)
#define uchar	unsigned char
#endif

/* This struct holds private method data created on DT_OPEN */
struct _dtdata_s
{	unsigned int	lock;	/* general dictionary lock	*/
	Dtuser_t	user;	/* application's data		*/
	unsigned int	type;	/* method type, control flags	*/
	ssize_t		size;	/* number of objects		*/
	Dt_t		dict;	/* when DT_INDATA is requested	*/
};

/* this structure holds the plugin information */
typedef struct _dtlib_s
{
	char*		name;		/* short name */
	char*		description;	/* short description */
	char*		release;	/* release info */
	char*		prefix;		/* name prefix */
	Dtmethod_t**	methods;	/* method list */
} Dtlib_t;

#if _BLD_cdt

#if defined(__STDC__)
#define CDTLIB(m)	__DEFINE__(Dtmethod_t*,m,&_##m);
#else
#define CDTLIB(m)	__DEFINE__(Dtmethod_t*,m,&_/**/m);
#endif

#else

#if defined(__STDC__)
#define CDTLIB(m) \
	void* cdt_lib(const char* name, Dtdisc_t* disc, const char* type) \
	{ \
		int	i; \
		int	n; \
		if (!type) \
			return &cdt_lib_##m; \
		n = strlen(cdt_lib_##m.prefix); \
		if (!strncmp(type, cdt_lib_##m.prefix, n)) \
			type += n; \
		for (i = 0; cdt_lib_##m.methods[i]; i++) \
			if (!strcmp(type, cdt_lib_##m.methods[i]->name + n)) \
				return cdt_lib_##m.methods[i]; \
		return 0; \
	} \
	unsigned long plugin_version(void) { return CDT_PLUGIN_VERSION; }
#else
#define CDTLIB(m) \
	void* cdt_lib(name, disc, type) const char* name; Dtdisc_t* disc; const char* type; \
	{ \
		int	i; \
		int	n; \
		if (!type) \
			return &cdt_lib_/**/m; \
		n = strlen(cdt_lib_/**/m.prefix); \
		if (!strncmp(type, cdt_lib_/**/m.prefix, n)) \
			type += n; \
		for (i = 0; cdt_lib_/**/m.methods[i]; i++) \
			if (!strcmp(type, cdt_lib_/**/m.methods[i]->name + n)) \
				return cdt_lib_/**/m.methods[i]; \
		return 0; \
	} \
	unsigned long plugin_version() { return CDT_PLUGIN_VERSION; }
#endif

#endif /* _BLD_cdt */

/* these macros lock/unlock dictionaries. DTRETURN substitutes for "return" */
#define DTSETLOCK(dt)		(((dt)->data->type&DT_SHARE) ? asolock(&(dt)->data->lock,1,ASO_SPINLOCK) : 0 )
#define DTCLRLOCK(dt)		(((dt)->data->type&DT_SHARE) ? asolock(&(dt)->data->lock,1,ASO_UNLOCK) : 0 )
#define DTRETURN(ob,rv)		do { (ob) = (rv); goto dt_return; } while(0)
#define DTERROR(dt, mesg) 	(!((dt)->disc && (dt)->disc->eventf) ? 0 : \
				  (*(dt)->disc->eventf)((dt),DT_ERROR,(Void_t*)(mesg),(dt)->disc) )

/* announce completion of an operation of type (ty) on some object (ob) in dictionary (dt) */
#define DTANNOUNCE(dt,ob,ty)	( ((ob) && ((ty)&DT_TOANNOUNCE) && ((dt)->data->type&DT_ANNOUNCE) && \
				   (dt)->disc && (dt)->disc->eventf ) ? \
					(*(dt)->disc->eventf)((dt), DT_ANNOUNCE|(ty), (ob), (dt)->disc) : 0 )

/* map bits for upward compabitibility */
#define DTTYPE(dt,ty)		((dt)->typef ? (*(dt)->typef)((dt), (ty)) : (ty) )

/* short-hands for fields in Dtlink_t.
** note that __hash is used as a hash value
** or as the position in the parent table.
*/
#define _left	lh.__left
#define _hash	lh.__hash	
#define _ppos	lh.__hash

#define _rght	rh.__rght
#define _ptbl	rh.__ptbl

/* tree rotation/linking functions */
#define rrotate(x,y)	((x)->_left = (y)->_rght, (y)->_rght = (x))
#define lrotate(x,y)	((x)->_rght = (y)->_left, (y)->_left = (x))
#define rlink(r,x)	((r) = (r)->_left = (x) )
#define llink(l,x)	((l) = (l)->_rght = (x) )

#define RROTATE(x,y)	(rrotate(x,y), (x) = (y))
#define LROTATE(x,y)	(lrotate(x,y), (x) = (y))
#define RRSHIFT(x,t)	((t) = (x)->_left->_left, (x)->_left->_left = (t)->_rght, \
			 (t)->_rght = (x), (x) = (t) )
#define LLSHIFT(x,t)	((t) = (x)->_rght->_rght, (x)->_rght->_rght = (t)->_left, \
			 (t)->_left = (x), (x) = (t) )

_BEGIN_EXTERNS_

#if _BLD_cdt && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern Dtlink_t*	_dtmake _ARG_((Dt_t*, Void_t*, int));
extern void		_dtfree _ARG_((Dt_t*, Dtlink_t*, int));
extern int		_dtlock _ARG_((Dt_t*, int));

#undef	extern

#if !_PACKAGE_ast
extern Void_t*		malloc _ARG_((size_t));
extern Void_t*		realloc _ARG_((Void_t*, size_t));
extern void		free _ARG_((Void_t*));
#endif
_END_EXTERNS_

#endif /* _CDTLIB_H */
