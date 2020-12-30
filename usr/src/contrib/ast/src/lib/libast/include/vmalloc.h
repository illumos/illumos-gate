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
#ifndef _VMALLOC_H
#define _VMALLOC_H	1

/*	Public header file for the virtual malloc package.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/1994.
*/

#define VMALLOC_VERSION	20110808L

#if _PACKAGE_ast
#include	<ast_std.h>
#else
#include	<ast_common.h>
#endif

typedef struct _vmalloc_s	Vmalloc_t;
typedef struct _vmstat_s	Vmstat_t;
typedef struct _vmdisc_s	Vmdisc_t;
typedef struct _vmethod_s	Vmethod_t;
typedef struct _vmdata_s	Vmdata_t;
typedef Void_t*	(*Vmemory_f)_ARG_((Vmalloc_t*, Void_t*, size_t, size_t, Vmdisc_t*));
typedef int	(*Vmexcept_f)_ARG_((Vmalloc_t*, int, Void_t*, Vmdisc_t*));

struct _vmstat_s
{	int	n_busy;			/* number of busy blocks	*/
	int	n_free;			/* number of free blocks	*/
	size_t	s_busy;			/* total amount of busy space	*/
	size_t	s_free;			/* total amount of free space	*/
	size_t	m_busy;			/* largest busy piece		*/
	size_t	m_free;			/* largest free piece		*/
	int	n_seg;			/* number of segments		*/
	size_t	extent;			/* total size of region		*/
	int	n_region;		/* #parallel regions (Vmregion)	*/
	int	n_open;			/* #calls that finds open reg	*/
	int	n_lock;			/* #calls where reg was locked	*/
	int	n_probe;		/* #probes to find a region	*/
	int	mode;			/* region mode bits		*/
};

struct _vmdisc_s
{	Vmemory_f	memoryf;	/* memory manipulator		*/
	Vmexcept_f	exceptf;	/* exception handler		*/
	size_t		round;		/* rounding requirement		*/
	size_t		size;		/* actual size of discipline	*/
};

struct _vmethod_s
{	Void_t*		(*allocf)_ARG_((Vmalloc_t*,size_t,int));
	Void_t*		(*resizef)_ARG_((Vmalloc_t*,Void_t*,size_t,int,int));
	int		(*freef)_ARG_((Vmalloc_t*,Void_t*,int));
	long		(*addrf)_ARG_((Vmalloc_t*,Void_t*,int));
	long		(*sizef)_ARG_((Vmalloc_t*,Void_t*,int));
	int		(*compactf)_ARG_((Vmalloc_t*,int));
	Void_t*		(*alignf)_ARG_((Vmalloc_t*,size_t,size_t,int));
	unsigned short	meth;
};

struct _vmalloc_s
{	Vmethod_t	meth;		/* method for allocation	*/
	char*		file;		/* file name			*/
	int		line;		/* line number			*/
	char*		func;		/* calling function		*/
	Vmdisc_t*	disc;		/* discipline to get space	*/
	Vmdata_t*	data;		/* the real region data		*/
	Vmalloc_t*	next;		/* linked list of regions	*/
};

#define VM_TRUST	0000000		/* obsolete			*/
#define VM_TRACE	0000001		/* generate traces of calls	*/
#define VM_DBCHECK	0000002		/* check for boundary overwrite	*/
#define VM_DBABORT	0000004		/* abort on any warning		*/
#define VM_SHARE	0000010		/* sharable across processes	*/
#define VM_MEMORYF	0000020		/* vm was allocated by memoryf	*/
#define VM_FLAGS	0000017		/* user-settable flags		*/

#define VM_MTBEST	0000100		/* Vmbest method		*/
#define VM_MTPOOL	0000200		/* Vmpool method		*/
#define VM_MTLAST	0000400		/* Vmlast method		*/
#define VM_MTDEBUG	0001000		/* Vmdebug method		*/
#define VM_MTPROFILE	0002000		/* Vmdebug method		*/
#define VM_METHODS	0003700		/* available allocation methods	*/

#define VM_RSCOPY	0000001		/* copy old contents		*/
#define VM_RSMOVE	0000002		/* old contents is moveable	*/
#define VM_RSZERO	0000004		/* clear new space		*/

/* exception types */
#define VM_OPEN		1		/* region being opened		*/
#define VM_ENDOPEN	2		/* end of region opening	*/
#define VM_CLOSE	3		/* announce being closed	*/
#define VM_ENDCLOSE	4		/* end of region closing	*/
#define VM_DISC		5		/* discipline being changed	*/
#define VM_NOMEM	6		/* can't obtain memory		*/
#define VM_BADADDR	(-1)		/* currently a no-op		*/

/* for application-specific data in shared/persistent regions */
#define VM_MMGET	0		/* get data value (void*)	*/
#define VM_MMSET	1		/* set data value (void*)	*/
#define VM_MMADD	2		/* add data value (long)	*/

_BEGIN_EXTERNS_	 /* public data */
#if _BLD_vmalloc && defined(__EXPORT__)
#define extern	extern __EXPORT__
#endif
#if !_BLD_vmalloc && defined(__IMPORT__)
#define extern	extern __IMPORT__
#endif

extern Vmethod_t*	Vmbest;		/* best allocation		*/
extern Vmethod_t*	Vmlast;		/* last-block allocation	*/
extern Vmethod_t*	Vmpool;		/* pool allocation		*/
extern Vmethod_t*	Vmdebug;	/* allocation with debugging	*/
extern Vmethod_t*	Vmprofile;	/* profiling memory usage	*/

extern Vmdisc_t*	Vmdcsystem;	/* get memory from the OS	*/
extern Vmdisc_t*	Vmdcheap;	/* get memory from Vmheap	*/
extern Vmdisc_t*	Vmdcsbrk;	/* like Vmdcsystem - legacy use	*/

extern Vmalloc_t	_Vmheap;	/* heap region - use with care! */
extern Vmalloc_t*	Vmheap;		/* = &_Vmheap - safe to use	*/
extern Vmalloc_t*	Vmregion;	/* malloc region		*/

#undef extern
_END_EXTERNS_

_BEGIN_EXTERNS_ /* public functions */
#if _BLD_vmalloc && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern Vmalloc_t*	vmopen _ARG_(( Vmdisc_t*, Vmethod_t*, int ));
extern int		vmclose _ARG_(( Vmalloc_t* ));
extern int		vmclear _ARG_(( Vmalloc_t* ));
extern int		vmcompact _ARG_(( Vmalloc_t* ));

extern Vmdisc_t*	vmdisc _ARG_(( Vmalloc_t*, Vmdisc_t* ));

extern Vmalloc_t*	vmmopen _ARG_(( char*, int, ssize_t ));
extern Void_t*		vmmvalue _ARG_(( Vmalloc_t*, int, Void_t*, int ));
extern void		vmmrelease _ARG_(( Vmalloc_t*, int ));
extern Void_t*		vmmaddress _ARG_(( size_t ));

extern Void_t*		vmalloc _ARG_(( Vmalloc_t*, size_t ));
extern Void_t*		vmalign _ARG_(( Vmalloc_t*, size_t, size_t ));
extern Void_t*		vmresize _ARG_(( Vmalloc_t*, Void_t*, size_t, int ));
extern Void_t*		vmgetmem _ARG_(( Vmalloc_t*, Void_t*, size_t ));
extern int		vmfree _ARG_(( Vmalloc_t*, Void_t* ));

extern long		vmaddr _ARG_(( Vmalloc_t*, Void_t* ));
extern long		vmsize _ARG_(( Vmalloc_t*, Void_t* ));

extern Vmalloc_t*	vmregion _ARG_(( Void_t* ));
extern Void_t*		vmsegment _ARG_(( Vmalloc_t*, Void_t* ));
extern int		vmset _ARG_(( Vmalloc_t*, int, int ));

extern Void_t*		vmdbwatch _ARG_(( Void_t* ));
extern int		vmdbcheck _ARG_(( Vmalloc_t* ));
extern int		vmdebug _ARG_(( int ));

extern int		vmprofile _ARG_(( Vmalloc_t*, int ));

extern int		vmtrace _ARG_(( int ));
extern int		vmtrbusy _ARG_((Vmalloc_t*));

extern int		vmstat _ARG_((Vmalloc_t*, Vmstat_t*));

extern int		vmwalk _ARG_((Vmalloc_t*,
					int(*)(Vmalloc_t*,Void_t*,size_t,Vmdisc_t*,Void_t*), Void_t*));
extern char*		vmstrdup _ARG_((Vmalloc_t*, const char*));

#if !defined(_BLD_vmalloc) && !defined(_AST_STD_H) && \
	!defined(__stdlib_h) && !defined(__STDLIB_H) && \
	!defined(_STDLIB_INCLUDED) && !defined(_INC_STDLIB)
extern Void_t*		malloc _ARG_(( size_t ));
extern Void_t*		realloc _ARG_(( Void_t*, size_t ));
extern void		free _ARG_(( Void_t* ));
extern void		cfree _ARG_(( Void_t* ));
extern Void_t*		calloc _ARG_(( size_t, size_t ));
extern Void_t*		memalign _ARG_(( size_t, size_t ));
extern Void_t*		valloc _ARG_(( size_t ));
#endif
extern int		setregmax _ARG_(( int ));

#undef extern
_END_EXTERNS_

/* to coerce any value to a Vmalloc_t*, make ANSI happy */
#define _VM_(vm)	((Vmalloc_t*)(vm))

/* enable recording of where a call originates from */
#ifdef VMFL

#if defined(__FILE__)
#define _VMFILE_(vm)	(_VM_(vm)->file = (char*)__FILE__)
#else
#define _VMFILE_(vm)	(_VM_(vm)->file = (char*)0)
#endif

#if defined(__LINE__)
#define _VMLINE_(vm)	(_VM_(vm)->line = __LINE__)
#else
#define _VMLINE_(vm)	(_VM_(vm)->line = 0)
#endif

#if defined(__FUNCTION__)
#define _VMFUNC_(vm)	(_VM_(vm)->func = (char*)__FUNCTION__)
#else
#define _VMFUNC_(vm)	(_VM_(vm)->func = (char*)0)
#endif

#define _VMFL_(vm)	(_VMFILE_(vm), _VMLINE_(vm), _VMFUNC_(vm))

#define vmalloc(vm,sz)		(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.allocf))((vm),(sz),0) )
#define vmresize(vm,d,sz,type)	(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.resizef))\
					((vm),(Void_t*)(d),(sz),(type),0) )
#define vmfree(vm,d)		(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.freef))((vm),(Void_t*)(d),0) )
#define vmalign(vm,sz,align)	(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.alignf))((vm),(sz),(align),0) )

#undef malloc
#undef realloc
#undef calloc
#undef free
#undef memalign
#undef valloc

#if _map_malloc

#define malloc(s)		(_VMFL_(Vmregion), _ast_malloc((size_t)(s)) )
#define realloc(d,s)		(_VMFL_(Vmregion), _ast_realloc((Void_t*)(d),(size_t)(s)) )
#define calloc(n,s)		(_VMFL_(Vmregion), _ast_calloc((size_t)n, (size_t)(s)) )
#define free(d)			(_VMFL_(Vmregion), _ast_free((Void_t*)(d)) )
#define memalign(a,s)		(_VMFL_(Vmregion), _ast_memalign((size_t)(a),(size_t)(s)) )
#define valloc(s)		(_VMFL_(Vmregion), _ast_valloc((size_t)(s) )

#else

#if !_std_malloc

#if __STD_C || defined(__STDPP__) || defined(__GNUC__)

#define malloc(s)		(_VMFL_(Vmregion), malloc((size_t)(s)) )
#define realloc(d,s)		(_VMFL_(Vmregion), realloc((Void_t*)(d),(size_t)(s)) )
#define calloc(n,s)		(_VMFL_(Vmregion), calloc((size_t)n, (size_t)(s)) )
#define free(d)			(_VMFL_(Vmregion), free((Void_t*)(d)) )
#define memalign(a,s)		(_VMFL_(Vmregion), memalign((size_t)(a),(size_t)(s)) )
#define valloc(s)		(_VMFL_(Vmregion), valloc((size_t)(s) )
#ifndef strdup
#define strdup(s)		( _VMFL_(Vmregion), (strdup)((char*)(s)) )
#endif

#else

#define _VMNM_(a,b,c,d,e,f)	a/**/b/**/c/**/d/**/e/**/f
#define malloc(s)		(_VMFL_(Vmregion), _VMNM_(mallo,/,*,*,/,c)\
						((size_t)(s)) )
#define realloc(d,s)		(_VMFL_(Vmregion), _VMNM_(reallo,/,*,*,/,c)\
						((Void_t*)(d),(size_t)(s)) )
#define calloc(n,s)		(_VMFL_(Vmregion), _VMNM_(callo,/,*,*,/,c)\
						((size_t)n, (size_t)(s)) )
#define free(d)			(_VMFL_(Vmregion), _VMNM_(fre,/,*,*,/,e)((Void_t*)(d)) )
#define memalign(a,s)		(_VMFL_(Vmregion), _VMNM_(memalig,/,*,*,/,n)\
						((size_t)(a),(size_t)(s)) )
#define valloc(s)		(_VMFL_(Vmregion), _VMNM_(vallo,/,*,*,/,c)\
						((size_t)(s) )
#ifndef strdup
#define strdup(s)		( _VMFL_(Vmregion), _VMNM_(strdu,/,*,*,/,p)\
						((char*)(s)) )
#endif

#endif /*__STD_C || defined(__STDPP__) || defined(__GNUC__)*/

#define cfree(d)		free(d)

#endif /*!_std_malloc*/

#endif /*_map_malloc*/

#endif /*VMFL*/

/* non-debugging/profiling allocation calls */
#ifndef vmalloc
#define vmalloc(vm,sz)		(*(_VM_(vm)->meth.allocf))((vm),(sz),0)
#endif

#ifndef vmresize
#define vmresize(vm,d,sz,type)	(*(_VM_(vm)->meth.resizef))\
					((vm),(Void_t*)(d),(sz),(type),0)
#endif

#ifndef vmfree
#define vmfree(vm,d)		(*(_VM_(vm)->meth.freef))((vm),(Void_t*)(d),0)
#endif

#ifndef vmalign
#define vmalign(vm,sz,align)	(*(_VM_(vm)->meth.alignf))((vm),(sz),(align),0)
#endif

#define vmaddr(vm,addr)		(*(_VM_(vm)->meth.addrf))((vm),(Void_t*)(addr),0)
#define vmsize(vm,addr)		(*(_VM_(vm)->meth.sizef))((vm),(Void_t*)(addr),0)
#define vmcompact(vm)		(*(_VM_(vm)->meth.compactf))((vm),0)
#define vmoldof(v,p,t,n,x)	(t*)vmresize((v), (p), sizeof(t)*(n)+(x), \
					(VM_RSMOVE) )
#define vmnewof(v,p,t,n,x)	(t*)vmresize((v), (p), sizeof(t)*(n)+(x), \
					(VM_RSMOVE|VM_RSCOPY|VM_RSZERO) )

#define vmdata(vm)		((Void_t*)(_VM_(vm)->data) )
#define vmlocked(vm)		(*((unsigned int*)(_VM_(vm)->data)) )

#endif /* _VMALLOC_H */
