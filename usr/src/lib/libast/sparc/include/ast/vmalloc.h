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
#ifndef _VMALLOC_H
#define _VMALLOC_H	1

/*	Public header file for the virtual malloc package.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

#define VMALLOC_VERSION	20100101L

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
};

struct _vmdisc_s
{	Vmemory_f	memoryf;	/* memory manipulator		*/
	Vmexcept_f	exceptf;	/* exception handler		*/
	size_t		round;		/* rounding requirement		*/
};

struct _vmethod_s
{	Void_t*		(*allocf)_ARG_((Vmalloc_t*,size_t));
	Void_t*		(*resizef)_ARG_((Vmalloc_t*,Void_t*,size_t,int));
	int		(*freef)_ARG_((Vmalloc_t*,Void_t*));
	long		(*addrf)_ARG_((Vmalloc_t*,Void_t*));
	long		(*sizef)_ARG_((Vmalloc_t*,Void_t*));
	int		(*compactf)_ARG_((Vmalloc_t*));
	Void_t*		(*alignf)_ARG_((Vmalloc_t*,size_t,size_t));
	unsigned short	meth;
};

struct _vmalloc_s
{	Vmethod_t	meth;		/* method for allocation	*/
	char*		file;		/* file name			*/
	int		line;		/* line number			*/
	Void_t*		func;		/* calling function		*/
	Vmdisc_t*	disc;		/* discipline to get space	*/
	Vmdata_t*	data;		/* the real region data		*/
	Vmalloc_t*	next;		/* linked list of regions	*/
#ifdef _VM_PRIVATE_
	_VM_PRIVATE_
#endif
};

#undef	VM_FLAGS			/* solaris sys kernel clash	*/

#define VM_TRUST	0000001		/* forgo some security checks	*/
#define VM_TRACE	0000002		/* generate trace 		*/
#define VM_DBCHECK	0000004		/* check for boundary overwrite	*/
#define VM_DBABORT	0000010		/* abort on any warning		*/
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
#define VM_OPEN		0		/* region being opened		*/
#define VM_CLOSE	1		/* announce being closed	*/
#define VM_NOMEM	2		/* can't obtain memory		*/
#define VM_BADADDR	3		/* bad addr in vmfree/vmresize	*/
#define VM_DISC		4		/* discipline being changed	*/
#define VM_ALLOC	5		/* announcement from vmalloc()	*/
#define VM_FREE		6		/* announcement from vmfree()	*/
#define VM_RESIZE	7		/* announcement from vmresize()	*/

_BEGIN_EXTERNS_	 /* public data */
#if _BLD_vmalloc && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif
#if !_BLD_vmalloc && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern Vmethod_t*	Vmbest;		/* best allocation		*/
extern Vmethod_t*	Vmlast;		/* last-block allocation	*/
extern Vmethod_t*	Vmpool;		/* pool allocation		*/
extern Vmethod_t*	Vmdebug;	/* allocation with debugging	*/
extern Vmethod_t*	Vmprofile;	/* profiling memory usage	*/

extern Vmdisc_t*	Vmdcheap;	/* heap discipline		*/
extern Vmdisc_t*	Vmdcsbrk;	/* sbrk discipline		*/

extern Vmalloc_t*	Vmheap;		/* heap region			*/
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

extern Vmalloc_t*	vmmopen _ARG_(( char*, Void_t*, size_t ));
extern Void_t*		vmmset _ARG_((Vmalloc_t*, int, Void_t*, int));

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
					int(*)(Vmalloc_t*,Void_t*,size_t,Vmdisc_t*,Void_t*),
					Void_t*));
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

#undef extern
_END_EXTERNS_

/* to coerce any value to a Vmalloc_t*, make ANSI happy */
#define _VM_(vm)	((Vmalloc_t*)(vm))

/* enable recording of where a call originates from */
#ifdef VMFL

#if defined(__FILE__)
#define _VMFILE_(vm)	(_VM_(vm)->file = (char*)__FILE__)
#else
#define _VMFILE_(vm)	(_VM_(vm)->file = 0)
#endif

#if defined(__LINE__)
#define _VMLINE_(vm)	(_VM_(vm)->line = __LINE__)
#else
#define _VMLINE_(vm)	(_VM_(vm)->line = 0)
#endif

#if defined(__FUNCTION__)
#define _VMFUNC_(vm)	(_VM_(vm)->func = (Void_t*)__FUNCTION__)
#else
#define _VMFUNC_(vm)	(_VM_(vm)->func = 0)
#endif

#define _VMFL_(vm)	(_VMFILE_(vm), _VMLINE_(vm), _VMFUNC_(vm))

#define vmalloc(vm,sz)		(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.allocf))((vm),(sz)) )
#define vmresize(vm,d,sz,type)	(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.resizef))\
					((vm),(Void_t*)(d),(sz),(type)) )
#define vmfree(vm,d)		(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.freef))((vm),(Void_t*)(d)) )
#define vmalign(vm,sz,align)	(_VMFL_(vm), \
				 (*(_VM_(vm)->meth.alignf))((vm),(sz),(align)) )

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
#define malloc(s)		( _VMFL_(Vmregion), (malloc)((size_t)(s)) )
#define realloc(d,s)		( _VMFL_(Vmregion), (realloc)((Void_t*)(d),(size_t)(s)) )
#define calloc(n,s)		( _VMFL_(Vmregion), (calloc)((size_t)n, (size_t)(s)) )
#define free(d)			( _VMFL_(Vmregion), (free)((Void_t*)(d)) )
#define memalign(a,s)		( _VMFL_(Vmregion), (memalign)((size_t)(a),(size_t)(s)) )
#define valloc(s)		( _VMFL_(Vmregion), (valloc)((size_t)(s)) )
#ifndef strdup
#define strdup(s)		( _VMFL_(Vmregion), (strdup)((char*)(s)) )
#endif

#else

#define _VMNM_(a,b,c,d,e,f)	a/**/b/**/c/**/d/**/e/**/f
#define malloc(s)		( _VMFL_(Vmregion), _VMNM_(mallo,/,*,*,/,c)\
						( (size_t)(s)) )
#define realloc(d,s)		( _VMFL_(Vmregion), _VMNM_(reallo,/,*,*,/,c)\
						( (Void_t*)(d),(size_t)(s)) )
#define calloc(n,s)		( _VMFL_(Vmregion), _VMNM_(callo,/,*,*,/,c)\
						( (size_t)n, (size_t)(s)) )
#define free(d)			( _VMFL_(Vmregion), _VMNM_(fre,/,*,*,/,e)((Void_t*)(d)) )
#define memalign(a,s)		( _VMFL_(Vmregion), _VMNM_(memalig,/,*,*,/,n)\
						( (size_t)(a),(size_t)(s)) )
#define valloc(s)		( _VMFL_(Vmregion), _VMNM_(vallo,/,*,*,/,c)\
						( (size_t)(s)) )
#ifndef strdup
#define strdup(s)		( _VMFL_(Vmregion), _VMNM_(strdu,/,*,*,/,p)\
						((char*)(s)) )
#endif

#endif /*__STD_C || defined(__STDPP__) || defined(__GNUC__)*/

#define cfree(d)		free(d)

#endif /* !_std_malloc */

#endif /* _map_malloc */

#endif /*VMFL*/

/* non-debugging/profiling allocation calls */
#ifndef vmalloc
#define vmalloc(vm,sz)		(*(_VM_(vm)->meth.allocf))((vm),(sz))
#endif

#ifndef vmresize
#define vmresize(vm,d,sz,type)	(*(_VM_(vm)->meth.resizef))\
					((vm),(Void_t*)(d),(sz),(type))
#endif

#ifndef vmfree
#define vmfree(vm,d)		(*(_VM_(vm)->meth.freef))((vm),(Void_t*)(d))
#endif

#ifndef vmalign
#define vmalign(vm,sz,align)	(*(_VM_(vm)->meth.alignf))((vm),(sz),(align))
#endif

#define vmaddr(vm,addr)		(*(_VM_(vm)->meth.addrf))((vm),(Void_t*)(addr))
#define vmsize(vm,addr)		(*(_VM_(vm)->meth.sizef))((vm),(Void_t*)(addr))
#define vmcompact(vm)		(*(_VM_(vm)->meth.compactf))((vm))
#define vmoldof(v,p,t,n,x)	(t*)vmresize((v), (p), sizeof(t)*(n)+(x), \
					(VM_RSMOVE) )
#define vmnewof(v,p,t,n,x)	(t*)vmresize((v), (p), sizeof(t)*(n)+(x), \
					(VM_RSMOVE|VM_RSCOPY|VM_RSZERO) )
#define vmdata(vm)		((Void_t*)(_VM_(vm)->data))

#endif /* _VMALLOC_H */
