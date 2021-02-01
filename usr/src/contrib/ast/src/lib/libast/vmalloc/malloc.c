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
#if defined(_UWIN) && defined(_BLD_ast)

void _STUB_malloc(){}

#else

#if _UWIN

#define calloc		______calloc
#define _ast_free	______free
#define malloc		______malloc
#define mallinfo	______mallinfo
#define mallopt		______mallopt
#define mstats		______mstats
#define realloc		______realloc

#define _STDLIB_H_	1

extern int		atexit(void(*)(void));
extern char*		getenv(const char*);

#endif

#include	"vmhdr.h"
#include	<errno.h>

#if _UWIN

#include	<malloc.h>

#define _map_malloc	1
#define _mal_alloca	1

#undef	calloc
#define calloc		_ast_calloc
#undef	_ast_free
#define free		_ast_free
#undef	malloc
#define malloc		_ast_malloc
#undef	mallinfo
typedef struct ______mallinfo Mallinfo_t;
#undef	mallopt
#undef	mstats
typedef struct ______mstats Mstats_t;
#undef	realloc
#define realloc		_ast_realloc

#endif

#if __STD_C
#define F0(f,t0)		f(t0)
#define F1(f,t1,a1)		f(t1 a1)
#define F2(f,t1,a1,t2,a2)	f(t1 a1, t2 a2)
#else
#define F0(f,t0)		f()
#define F1(f,t1,a1)		f(a1) t1 a1;
#define F2(f,t1,a1,t2,a2)	f(a1, a2) t1 a1; t2 a2;
#endif

/*
 * define _AST_std_malloc=1 to force the standard malloc
 * if _map_malloc is also defined then _ast_malloc etc.
 * will simply call malloc etc.
 */

#if !defined(_AST_std_malloc) && __CYGWIN__
#define _AST_std_malloc	1
#endif

/*	malloc compatibility functions
**
**	These are aware of debugging/profiling and are driven by the
**	VMALLOC_OPTIONS environment variable which is a comma or space
**	separated list of [no]name[=value] options:
**
**	    abort	if Vmregion==Vmdebug then VM_DBABORT is set,
**			otherwise _BLD_DEBUG enabled assertions abort()
**			on failure
**	    break	try sbrk() block allocator first
**	    check	if Vmregion==Vmbest then the region is checked every op
**	    free	disable addfreelist()
**	    keep	disable free -- if code works with this enabled then it
**	    		probably accesses free'd data
**	    method=m	sets Vmregion=m if not defined, m (Vm prefix optional)
**			may be one of { best debug last profile }
**	    mmap	try mmap() block allocator first
**	    period=n	sets Vmregion=Vmdebug if not defined, if
**			Vmregion==Vmdebug the region is checked every n ops
**	    profile=f	sets Vmregion=Vmprofile if not set, if
**			Vmregion==Vmprofile then profile info printed to file f
**	    start=n	sets Vmregion=Vmdebug if not defined, if
**			Vmregion==Vmdebug region checking starts after n ops
**	    trace=f	enables tracing to file f
**	    warn=f	sets Vmregion=Vmdebug if not defined, if
**			Vmregion==Vmdebug then warnings printed to file f
**	    watch=a	sets Vmregion=Vmdebug if not defined, if
**			Vmregion==Vmdebug then address a is watched
**
**	Output files are created if they don't exist. &n and /dev/fd/n name
**	the file descriptor n which must be open for writing. The pattern %p
**	in a file name is replaced by the process ID.
**
**	VMALLOC_OPTIONS combines the features of these previously used env vars:
**	    { VMCHECK VMDEBUG VMETHOD VMPROFILE VMTRACE }
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 01/16/94.
*/

#if _sys_stat
#include	<sys/stat.h>
#endif
#include	<fcntl.h>

#ifdef S_IRUSR
#define CREAT_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#else
#define CREAT_MODE	0644
#endif

static Vmulong_t	_Vmdbstart = 0;
static Vmulong_t	_Vmdbcheck = 0;
static Vmulong_t	_Vmdbtime = 0;
static int		_Vmpffd = -1;

#if ( !_std_malloc || !_BLD_ast ) && !_AST_std_malloc

#if !_map_malloc
#undef calloc
#undef cfree
#undef free
#undef mallinfo
#undef malloc
#undef mallopt
#undef memalign
#undef mstats
#undef realloc
#undef valloc

#if _malloc_hook

#include <malloc.h>

#undef	calloc
#undef	cfree
#undef	free
#undef	malloc
#undef	memalign
#undef	realloc

#define calloc		_ast_calloc
#define cfree		_ast_cfree
#define free		_ast_free
#define malloc		_ast_malloc
#define memalign	_ast_memalign
#define realloc		_ast_realloc

#endif

#endif

#if _WINIX

#include <ast_windows.h>

#if _UWIN

#define VMRECORD(p)	_vmrecord(p)
#define VMBLOCK		{ int _vmblock = _sigblock();
#define VMUNBLOCK	_sigunblock(_vmblock); }

extern int		_sigblock(void);
extern void		_sigunblock(int);
extern unsigned long	_record[2048];

__inline Void_t* _vmrecord(Void_t* p)
{
	register unsigned long	v = ((unsigned long)p)>>16; 

	_record[v>>5] |= 1<<((v&0x1f));
	return p;
}

#else

#define getenv(s)	lcl_getenv(s)

static char*
lcl_getenv(const char* s)
{
	int		n;
	static char	buf[512];

	if (!(n = GetEnvironmentVariable(s, buf, sizeof(buf))) || n > sizeof(buf))
		return 0;
	return buf;
}

#endif /* _UWIN */

#endif /* _WINIX */

#ifndef VMRECORD
#define VMRECORD(p)	(p)
#define VMBLOCK
#define VMUNBLOCK
#endif

#if defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif

static int		_Vmflinit = 0;
#define VMFLINIT() \
	{ if(!_Vmflinit)	vmflinit(); \
	  if(_Vmdbcheck) \
	  { if(_Vmdbtime < _Vmdbstart) _Vmdbtime += 1; \
	    else if((_Vmdbtime += 1) < _Vmdbstart) _Vmdbtime = _Vmdbstart; \
	    if(_Vmdbtime >= _Vmdbstart && (_Vmdbtime % _Vmdbcheck) == 0 && \
	       Vmregion->meth.meth == VM_MTDEBUG) \
		vmdbcheck(Vmregion); \
	  } \
	}

#if __STD_C
static int vmflinit(void)
#else
static int vmflinit()
#endif
{
	char*		file;
	int		line;
	Void_t*		func;

	/* this must be done now to avoid any inadvertent recursion (more below) */
	_Vmflinit = 1;
	VMFLF(Vmregion,file,line,func);

	/* if getenv() calls malloc(), the options may not affect the eventual region */
	VMOPTIONS();

	/* reset file and line number to correct values for the call */
	Vmregion->file = file;
	Vmregion->line = line;
	Vmregion->func = func;

	return 0;
}

/* use multiple regions to reduce blocking by concurrent threads  */
#if _mem_mmap_anon || _mem_mmap_zero
static Vmalloc_t	*Region[64];	/* list of concurrent regions	*/
static unsigned int	Regmax = 64;	/* max number of regions	*/
#else
static Vmalloc_t*	Region[1];	/* list of concurrent regions	*/
static unsigned int	Regmax = 0;
#endif
static unsigned int	Regnum = 0; 	/* current #concurrent regions	*/

/* statistics */
static unsigned int	Regopen = 0; 	/* #allocation calls opened	*/
static unsigned int	Reglock = 0; 	/* #allocation calls locked	*/
static unsigned int	Regprobe = 0; 	/* #probes to find a region	*/

int setregmax(int regmax)
{
	int	oldmax = Regmax;

	if(regmax >= Regnum && regmax <= sizeof(Region)/sizeof(Region[0]))
		Regmax = regmax;

	return oldmax;
}

/* return statistics */
int _mallocstat(Vmstat_t* st)
{
	Vmstat_t	vmst;
	int		k;

	if(vmstat(Vmregion, st) < 0) /* add up all stats */
		return -1;
	for(k = 0; k < Regnum; ++k)
	{	if(!Region[k])
			continue;
		if(vmstat(Region[k], &vmst) < 0 )
			return -1;
		st->n_busy += vmst.n_busy;
		st->n_free += vmst.n_free;
		st->s_busy += vmst.s_busy;
		st->s_free += vmst.s_free;
		st->m_busy += vmst.m_busy;
		st->m_free += vmst.m_free;
		st->n_seg  += vmst.n_seg;
		st->extent += vmst.extent;
	}

	st->n_region = Regnum+1;
	st->n_open = Regopen;
	st->n_lock = Reglock;
	st->n_probe = Regprobe;

	return 0;
}

/* find the region that a block was allocated from */
static Vmalloc_t* regionof(Void_t* addr)
{
	int	k;

#if USE_NATIVE
#define CAUTIOUS	1
#else
#define CAUTIOUS	0
#endif
	if(CAUTIOUS || Vmregion->meth.meth != VM_MTBEST )
	{	/* addr will not be dereferenced here */
		if(vmaddr(Vmregion,addr) == 0 )
			return Vmregion;
		for(k = 0; k < Regnum; ++k)
			if(Region[k] && vmaddr(Region[k], addr) == 0 )
				return Region[k];
		return NIL(Vmalloc_t*);
	}
	else
	{	/* fast, but susceptible to bad data */
		Vmdata_t *vd = SEG(BLOCK(addr))->vmdt;
		if(Vmregion->data == vd )
			return Vmregion;
		for(k = 0; k < Regnum; ++k)
			if(Region[k] && Region[k]->data == vd)
				return Region[k];
		return NIL(Vmalloc_t*);
	}
}

/* manage a cache of free objects */
typedef struct _regfree_s
{	struct _regfree_s*	next;
} Regfree_t;
static Regfree_t	*Regfree;

static void addfreelist(Regfree_t* data)
{
	unsigned int	k;
	Regfree_t	*head;

	for(k = 0;; ASOLOOP(k) )
	{	data->next = head = Regfree;
		if(asocasptr(&Regfree, head, data) == (Void_t*)head )
			return;
	}
}

static void clrfreelist()
{
	Regfree_t	*list, *next;
	Vmalloc_t	*vm;

	if(!(list = Regfree) )
		return; /* nothing to do */

	if(asocasptr(&Regfree, list, NIL(Regfree_t*)) != list )
		return; /* somebody else is doing it */

	for(; list; list = next)
	{	next = list->next;
		if(vm = regionof((Void_t*)list))
		{	if(asocasint(&vm->data->lock, 0, 1) == 0) /* can free this now */
			{	(void)(*vm->meth.freef)(vm, (Void_t*)list, 1);
				vm->data->lock = 0;
			}
			else	addfreelist(list); /* ah well, back in the queue */
		}
	}
}

/* get a suitable region to allocate from */
typedef struct _regdisc_s
{	Vmdisc_t	disc;
	char		slop[64]; /* to absorb any extra data in Vmdcsystem */
} Regdisc_t;

static int regexcept(Vmalloc_t* vm, int type, Void_t* data, Vmdisc_t* disc)
{
	if(type == VM_OPEN)
	{	if(data) /* make vmopen allocate all memory using discipline */
			*(Void_t**)data = data; /* just make it non-NULL */
		return 0;
	}
	return 0;
}

static Vmalloc_t* getregion(int* local)
{
	Vmalloc_t		*vm;
	int			p, pos;

	static unsigned int	Rand = 0xdeadbeef; /* a cheap prng */
#define RAND()			(Rand = Rand*16777617 + 3)

	clrfreelist();

	if(Regmax <= 0 )
	{	/* uni-process/thread */
		*local = 1;
		Vmregion->data->lock = 1;
		return Vmregion;
	}
	else if(asocasint(&Vmregion->data->lock, 0, 1) == 0 )
	{	/* Vmregion is open, so use it */
		*local = 1;
		asoincint(&Regopen);
		return Vmregion;
	}

	asoincint(&Regprobe); /* probe Region[] to find an open region */
	if(Regnum == 0)
		pos = 0;
	else for(pos = p = RAND()%Regnum;; )
	{	if(Region[p] && asocasint(&Region[p]->data->lock, 0, 1) == 0 )
		{	*local = 1;
			asoincint(&Regopen);
			return Region[p];
		}
		if((p = (p+1)%Regnum) == pos )
			break;
	}

	/* grab the next open slot for a new region */
	while((p = Regnum) < Regmax)
		if(asocasint(&Regnum, p, p+1) == p )
			break;
	if(p < Regmax) /* this slot is now ours */
	{	static Regdisc_t	Regdisc;
		if(!Regdisc.disc.exceptf) /* one time initialization */
		{	GETPAGESIZE(_Vmpagesize);
			memcpy(&Regdisc, Vmdcsystem, Vmdcsystem->size);
			Regdisc.disc.round = ROUND(_Vmpagesize, 64*1024);
			Regdisc.disc.exceptf = regexcept;
		}

		/**/ASSERT(Region[p] == NIL(Vmalloc_t*));
		if((vm = vmopen(&Regdisc.disc, Vmbest, VM_SHARE)) != NIL(Vmalloc_t*) )
		{	vm->data->lock = 1; /* lock new region now */
			*local = 1;
			asoincint(&Regopen);
			return (Region[p] = vm);
		}
		else	Region[p] = Vmregion; /* better than nothing */
	}

	/* must return something */
	vm = Region[pos] ? Region[pos] : Vmregion;
	if(asocasint(&vm->data->lock, 0, 1) == 0)
	{	*local = 1;
		asoincint(&Regopen);
	}
	else
	{	*local = 0;
		asoincint(&Reglock);
	}
	return vm;
}

#if __STD_C
extern Void_t* calloc(reg size_t n_obj, reg size_t s_obj)
#else
extern Void_t* calloc(n_obj, s_obj)
reg size_t	n_obj;
reg size_t	s_obj;
#endif
{
	Void_t		*addr;
	Vmalloc_t	*vm;
	int		local = 0;
	VMFLINIT();

	vm = getregion(&local);
	addr = (*vm->meth.resizef)(vm, NIL(Void_t*), n_obj*s_obj, VM_RSZERO, local);
	if(local)
	{	/**/ASSERT(vm->data->lock == 1);
		vm->data->lock = 0;
	}
	return VMRECORD(addr);
}

#if __STD_C
extern Void_t* malloc(reg size_t size)
#else
extern Void_t* malloc(size)
reg size_t	size;
#endif
{
	Void_t		*addr;
	Vmalloc_t	*vm;
	int		local = 0;
	VMFLINIT();

	vm = getregion(&local);
	addr = (*vm->meth.allocf)(vm, size, local);
	if(local)
	{	/**/ASSERT(vm->data->lock == 1);
		vm->data->lock = 0;
	}
	return VMRECORD(addr);
}

#if __STD_C
extern Void_t* realloc(reg Void_t* data, reg size_t size)
#else
extern Void_t* realloc(data,size)
reg Void_t*	data;	/* block to be reallocated	*/
reg size_t	size;	/* new size			*/
#endif
{
	ssize_t		copy;
	Void_t		*addr;
	Vmalloc_t	*vm;
	VMFLINIT();

	if(!data)
		return malloc(size);
	else if((vm = regionof(data)) )
	{	if(vm == Vmregion && vm != Vmheap) /* no multiple region usage here */
		{	addr = (*vm->meth.resizef)(vm, data, size, VM_RSCOPY|VM_RSMOVE, 0);
			return VMRECORD(addr);
		}
		if(asocasint(&vm->data->lock, 0, 1) == 0 ) /* region is open */
		{	addr = (*vm->meth.resizef)(vm, data, size, VM_RSCOPY|VM_RSMOVE, 1);
			vm->data->lock = 0;
			return VMRECORD(addr);
		}
		else if(Regmax > 0 && Vmregion == Vmheap && (addr = malloc(size)) )
		{	if((copy = SIZE(BLOCK(data))&~BITS) > size )
				copy = size;	
			memcpy(addr, data, copy);
			addfreelist((Regfree_t*)data);
			return VMRECORD(addr);
		}
		else /* this may block but it is the best that we can do now */
		{	addr = (*vm->meth.resizef)(vm, data, size, VM_RSCOPY|VM_RSMOVE, 0);
			return VMRECORD(addr);
		}
	}
	else /* not our data */
	{
#if USE_NATIVE
#undef	realloc /* let the native realloc() take care of it */
#if __STD_C
		extern Void_t*	realloc(Void_t*, size_t);
#else
		extern Void_t*	realloc();
#endif
		return realloc(data, size);
#else 
		return NIL(Void_t*);
#endif
	}
}

#if __STD_C
extern void free(reg Void_t* data)
#else
extern void free(data)
reg Void_t*	data;
#endif
{
	Vmalloc_t	*vm;
	VMFLINIT();

	if(!data || (_Vmassert & VM_keep))
		return;
	else if((vm = regionof(data)) )
	{	
		if(vm == Vmregion && Vmregion != Vmheap || (_Vmassert & VM_free))
			(void)(*vm->meth.freef)(vm, data, 0);
		else	addfreelist((Regfree_t*)data);
		return;
	}
	else /* not our data */
	{
#if USE_NATIVE
#undef	free /* let the native free() take care of it */
#if __STD_C
		extern void	free(Void_t*);
#else
		extern void	free();
#endif
		free(data);
#endif
		return;
	}
}

#if __STD_C
extern void cfree(reg Void_t* data)
#else
extern void cfree(data)
reg Void_t*	data;
#endif
{
	free(data);
}

#if __STD_C
extern Void_t* memalign(reg size_t align, reg size_t size)
#else
extern Void_t* memalign(align, size)
reg size_t	align;
reg size_t	size;
#endif
{
	Void_t		*addr;
	Vmalloc_t	*vm;
	int		local = 0;
	VMFLINIT();

	vm = getregion(&local);
	VMBLOCK
	addr = (*vm->meth.alignf)(vm, size, align, local);
	if(local)
	{	/**/ASSERT(vm->data->lock == 1);
		vm->data->lock = 0;
	}
	VMUNBLOCK
	return VMRECORD(addr);
}

#if __STD_C
extern int posix_memalign(reg Void_t **memptr, reg size_t align, reg size_t size)
#else
extern int posix_memalign(memptr, align, size)
reg Void_t**	memptr;
reg size_t	align;
reg size_t	size;
#endif
{
	Void_t	*mem;

	if(align == 0 || (align%sizeof(Void_t*)) != 0 || ((align-1)&align) != 0 )
		return EINVAL;

	if(!(mem = memalign(align, size)) )
		return ENOMEM;

	*memptr = mem;
	return 0;
}

#if __STD_C
extern Void_t* valloc(reg size_t size)
#else
extern Void_t* valloc(size)
reg size_t	size;
#endif
{
	VMFLINIT();

	GETPAGESIZE(_Vmpagesize);
	return VMRECORD(memalign(_Vmpagesize, size));
}

#if __STD_C
extern Void_t* pvalloc(reg size_t size)
#else
extern Void_t* pvalloc(size)
reg size_t	size;
#endif
{
	VMFLINIT();

	GETPAGESIZE(_Vmpagesize);
	return VMRECORD(memalign(_Vmpagesize, ROUND(size,_Vmpagesize)) );
}

#if !_PACKAGE_ast
#if __STD_C
char* strdup(const char* s)
#else
char* strdup(s)
char*	s;
#endif
{
	char	*ns;
	size_t	n;

	if(!s)
		return NIL(char*);
	else
	{	n = strlen(s);
		if((ns = malloc(n+1)) )
			memcpy(ns,s,n+1);
		return ns;
	}
}
#endif /* _PACKAGE_ast */

#if !_lib_alloca || _mal_alloca
#ifndef _stk_down
#define _stk_down	0
#endif
typedef struct _alloca_s	Alloca_t;
union _alloca_u
{	struct
	{	char*		addr;
		Alloca_t*	next;
	} head;
	char	array[ALIGN];
};
struct _alloca_s
{	union _alloca_u	head;
	Vmuchar_t	data[1];
};

#if __STD_C
extern Void_t* alloca(size_t size)
#else
extern Void_t* alloca(size)
size_t	size;
#endif
{	char		array[ALIGN];
	char*		file;
	int		line;
	Void_t*		func;
	Alloca_t*	f;
	Vmalloc_t	*vm;
	static Alloca_t* Frame;

	VMFLINIT();

	VMFLF(Vmregion,file,line,func); /* save info before freeing frames */

	while(Frame) /* free unused frames */
	{	if(( _stk_down && &array[0] > Frame->head.head.addr) ||
		   (!_stk_down && &array[0] < Frame->head.head.addr) )
		{	f = Frame; Frame = f->head.head.next;
			if((vm = regionof(f)) )
				(void)(*vm->meth.freef)(vm, f, 0);
			/* else: something bad happened. just keep going */
		}
		else	break;
	}

	Vmregion->file = file; /* restore file/line info before allocation */
	Vmregion->line = line;
	Vmregion->func = func;

	f = (Alloca_t*)(*Vmregion->meth.allocf)(Vmregion, size+sizeof(Alloca_t)-1, 0);

	/* if f is NULL, this mimics a stack overflow with a memory error! */
	f->head.head.addr = &array[0];
	f->head.head.next = Frame;
	Frame = f;

	return (Void_t*)f->data;
}
#endif /*!_lib_alloca || _mal_alloca*/

#if _map_malloc

/* not sure of all the implications -- 0 is conservative for now */
#define USE_NATIVE	0	/* native free/realloc on non-vmalloc ptrs */

#else

#if _malloc_hook

static void vm_free_hook(void* ptr, const void* caller)
{
	free(ptr);
}

static void* vm_malloc_hook(size_t size, const void* caller)
{
	void*	r;

	r = malloc(size);
	return r;
}

static void* vm_memalign_hook(size_t align, size_t size, const void* caller)
{
	void*	r;

	r = memalign(align, size);
	return r;
}

static void* vm_realloc_hook(void* ptr, size_t size, const void* caller)
{
	void*	r;

	r = realloc(ptr, size);
	return r;
}

static void vm_initialize_hook(void)
{
	__free_hook = vm_free_hook;
	__malloc_hook = vm_malloc_hook;
	__memalign_hook = vm_memalign_hook;
	__realloc_hook = vm_realloc_hook;
}

void	(*__malloc_initialize_hook)(void) = vm_initialize_hook;

#if 0 /* 2012-02-29 this may be needed to cover shared libs */

void __attribute__ ((constructor)) vm_initialize_initialize_hook(void)
{
	vm_initialize_hook();
	__malloc_initialize_hook = vm_initialize_hook;
}

#endif

#else

/* intercept _* __* __libc_* variants */

#if __lib__malloc
extern Void_t*	F2(_calloc, size_t,n, size_t,m) { return calloc(n, m); }
extern Void_t	F1(_cfree, Void_t*,p) { free(p); }
extern Void_t	F1(_free, Void_t*,p) { free(p); }
extern Void_t*	F1(_malloc, size_t,n) { return malloc(n); }
#if _lib_memalign
extern Void_t*	F2(_memalign, size_t,a, size_t,n) { return memalign(a, n); }
#endif
#if _lib_pvalloc
extern Void_t*	F1(_pvalloc, size_t,n) { return pvalloc(n); }
#endif
extern Void_t*	F2(_realloc, Void_t*,p, size_t,n) { return realloc(p, n); }
#if _lib_valloc
extern Void_t*	F1(_valloc, size_t,n) { return valloc(n); }
#endif
#endif

#if _lib___malloc
extern Void_t*	F2(__calloc, size_t,n, size_t,m) { return calloc(n, m); }
extern Void_t	F1(__cfree, Void_t*,p) { free(p); }
extern Void_t	F1(__free, Void_t*,p) { free(p); }
extern Void_t*	F1(__malloc, size_t,n) { return malloc(n); }
#if _lib_memalign
extern Void_t*	F2(__memalign, size_t,a, size_t,n) { return memalign(a, n); }
#endif
#if _lib_pvalloc
extern Void_t*	F1(__pvalloc, size_t,n) { return pvalloc(n); }
#endif
extern Void_t*	F2(__realloc, Void_t*,p, size_t,n) { return realloc(p, n); }
#if _lib_valloc
extern Void_t*	F1(__valloc, size_t,n) { return valloc(n); }
#endif
#endif

#if _lib___libc_malloc
extern Void_t*	F2(__libc_calloc, size_t,n, size_t,m) { return calloc(n, m); }
extern Void_t	F1(__libc_cfree, Void_t*,p) { free(p); }
extern Void_t	F1(__libc_free, Void_t*,p) { free(p); }
extern Void_t*	F1(__libc_malloc, size_t,n) { return malloc(n); }
#if _lib_memalign
extern Void_t*	F2(__libc_memalign, size_t,a, size_t,n) { return memalign(a, n); }
#endif
#if _lib_pvalloc
extern Void_t*	F1(__libc_pvalloc, size_t,n) { return pvalloc(n); }
#endif
extern Void_t*	F2(__libc_realloc, Void_t*,p, size_t,n) { return realloc(p, n); }
#if _lib_valloc
extern Void_t*	F1(__libc_valloc, size_t,n) { return valloc(n); }
#endif
#endif

#endif /* _malloc_hook */

#endif /* _map_malloc */

#undef	extern

#if _hdr_malloc /* need the mallint interface for statistics, etc. */

#undef	calloc
#define calloc		______calloc
#undef	cfree
#define cfree		______cfree
#undef	free
#define free		______free
#undef	malloc
#define malloc		______malloc
#undef	pvalloc
#define pvalloc		______pvalloc
#undef	realloc
#define realloc		______realloc
#undef	valloc
#define valloc		______valloc

#if !_UWIN

#include	<malloc.h>

typedef struct mallinfo Mallinfo_t;
typedef struct mstats Mstats_t;

#endif

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#if _lib_mallopt
#if __STD_C
extern int mallopt(int cmd, int value)
#else
extern int mallopt(cmd, value)
int	cmd;
int	value;
#endif
{
	VMFLINIT();
	return 0;
}
#endif /*_lib_mallopt*/

#if _lib_mallinfo && _mem_arena_mallinfo
#if __STD_C
extern Mallinfo_t mallinfo(void)
#else
extern Mallinfo_t mallinfo()
#endif
{
	Vmstat_t	sb;
	Mallinfo_t	mi;

	VMFLINIT();
	memset(&mi,0,sizeof(mi));
	if(vmstat(Vmregion,&sb) >= 0)
	{	mi.arena = sb.extent;
		mi.ordblks = sb.n_busy+sb.n_free;
		mi.uordblks = sb.s_busy;
		mi.fordblks = sb.s_free;
	}
	return mi;
}
#endif /* _lib_mallinfo */

#if _lib_mstats && _mem_bytes_total_mstats
#if __STD_C
extern Mstats_t mstats(void)
#else
extern Mstats_t mstats()
#endif
{
	Vmstat_t	sb;
	Mstats_t	ms;

	VMFLINIT();
	memset(&ms,0,sizeof(ms));
	if(vmstat(Vmregion,&sb) >= 0)
	{	ms.bytes_total = sb.extent;
		ms.chunks_used = sb.n_busy;
		ms.bytes_used = sb.s_busy;
		ms.chunks_free = sb.n_free;
		ms.bytes_free = sb.s_free;
	}
	return ms;
}
#endif /*_lib_mstats*/

#undef	extern

#endif/*_hdr_malloc*/

#else

/*
 * even though there is no malloc override, still provide
 * _ast_* counterparts for object compatibility
 */

#define setregmax(n)

#undef	calloc
extern Void_t*	calloc _ARG_((size_t, size_t));

#undef	cfree
extern void	cfree _ARG_((Void_t*));

#undef	free
extern void	free _ARG_((Void_t*));

#undef	malloc
extern Void_t*	malloc _ARG_((size_t));

#if _lib_memalign
#undef	memalign
extern Void_t*	memalign _ARG_((size_t, size_t));
#endif

#if _lib_pvalloc
#undef	pvalloc
extern Void_t*	pvalloc _ARG_((size_t));
#endif

#undef	realloc
extern Void_t*	realloc _ARG_((Void_t*, size_t));

#if _lib_valloc
#undef	valloc
extern Void_t*	valloc _ARG_((size_t));
#endif

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#if !_malloc_hook

extern Void_t	F1(_ast_free, Void_t*,p) { free(p); }
extern Void_t*	F1(_ast_malloc, size_t,n) { return malloc(n); }
#if _lib_memalign
extern Void_t*	F2(_ast_memalign, size_t,a, size_t,n) { return memalign(a, n); }
#endif
extern Void_t*	F2(_ast_realloc, Void_t*,p, size_t,n) { return realloc(p, n); }

#endif

extern Void_t*	F2(_ast_calloc, size_t,n, size_t,m) { return calloc(n, m); }
extern Void_t	F1(_ast_cfree, Void_t*,p) { free(p); }
#if _lib_pvalloc
extern Void_t*	F1(_ast_pvalloc, size_t,n) { return pvalloc(n); }
#endif
#if _lib_valloc
extern Void_t*	F1(_ast_valloc, size_t,n) { return valloc(n); }
#endif

#undef	extern

#if _hdr_malloc

#undef	mallinfo
#undef	mallopt
#undef	mstats

#define calloc		______calloc
#define cfree		______cfree
#define free		______free
#define malloc		______malloc
#define pvalloc		______pvalloc
#define realloc		______realloc
#define valloc		______valloc

#if !_UWIN

#if !_malloc_hook

#include	<malloc.h>

#endif

typedef struct mallinfo Mallinfo_t;
typedef struct mstats Mstats_t;

#endif

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#if _lib_mallopt
extern int	F2(_ast_mallopt, int,cmd, int,value) { return mallopt(cmd, value); }
#endif

#if _lib_mallinfo && _mem_arena_mallinfo
extern Mallinfo_t	F0(_ast_mallinfo, void) { return mallinfo(); }
#endif

#if _lib_mstats && _mem_bytes_total_mstats
extern Mstats_t		F0(_ast_mstats, void) { return mstats(); }
#endif

#undef	extern

#endif /*_hdr_malloc*/

#endif /*!_std_malloc*/

#if __STD_C
static Vmulong_t atou(char** sp)
#else
static Vmulong_t atou(sp)
char**	sp;
#endif
{
	char*		s = *sp;
	Vmulong_t	v = 0;

	if(s[0] == '0' && (s[1] == 'x' || s[1] == 'X') )
	{	for(s += 2; *s; ++s)
		{	if(*s >= '0' && *s <= '9')
				v = (v << 4) + (*s - '0');
			else if(*s >= 'a' && *s <= 'f')
				v = (v << 4) + (*s - 'a') + 10;
			else if(*s >= 'A' && *s <= 'F')
				v = (v << 4) + (*s - 'A') + 10;
			else break;
		}
	}
	else
	{	for(; *s; ++s)
		{	if(*s >= '0' && *s <= '9')
				v = v*10 + (*s - '0');
			else break;
		}
	}

	*sp = s;
	return v;
}

#if __STD_C
static char* insertpid(char* begs, char* ends)
#else
static char* insertpid(begs,ends)
char*	begs;
char*	ends;
#endif
{	int	pid;
	char*	s;

	if((pid = getpid()) < 0)
		return NIL(char*);

	s = ends;
	do
	{	if(s == begs)
			return NIL(char*);
		*--s = '0' + pid%10;
	} while((pid /= 10) > 0);
	while(s < ends)
		*begs++ = *s++;

	return begs;
}

#define FD_PRIVATE	(3*OPEN_MAX/4)

#if __STD_C
int _vmfd(int fd)
#else
int _vmfd(fd)
int	fd;
#endif
{
	int	pd;

	if (fd >= 0)
	{
		if (fd < FD_PRIVATE && (pd = fcntl(fd, F_DUPFD, FD_PRIVATE)) >= 0)
		{
			close(fd);
			fd = pd;
		}
#ifdef FD_CLOEXEC
		fcntl(fd,  F_SETFD, FD_CLOEXEC);
#endif
	}
	return fd;
}

#if __STD_C
static int createfile(char* file)
#else
static int createfile(file)
char*	file;
#endif
{
	char	buf[1024];
	char	*next, *endb;
	int	fd;

	next = buf;
	endb = buf + sizeof(buf);
	while(*file)
	{	if(*file == '%')
		{	switch(file[1])
			{
			case 'p' :
				if(!(next = insertpid(next,endb)) )
					return -1;
				file += 2;
				break;
			default :
				goto copy;
			}
		}
		else
		{ copy:
			*next++ = *file++;
		}

		if(next >= endb)
			return -1;
	}

	*next = '\0';
	file = buf;
	if (*file == '&' && *(file += 1) || strncmp(file, "/dev/fd/", 8) == 0 && *(file += 8))
		fd = dup((int)atou(&file));
	else if (*file)
	{
#if _PACKAGE_ast
		fd = open(file, O_WRONLY|O_CREAT|O_TRUNC, CREAT_MODE);
#else
		fd = creat(file, CREAT_MODE);
#endif
		fd = _vmfd(fd);
	}
	else
		return -1;
#if _PACKAGE_ast
#ifdef FD_CLOEXEC
	if (fd >= 0)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#endif
	return fd;
}

#if __STD_C
static void pfprint(void)
#else
static void pfprint()
#endif
{
	if(Vmregion->meth.meth == VM_MTPROFILE)
		vmprofile(Vmregion,_Vmpffd);
}

/*
 * initialize runtime options from the VMALLOC_OPTIONS env var
 */

#define COPY(t,e,f)	while ((*t = *f++) && t < e) t++

#if __STD_C
void _vmoptions(void)
#else
void _vmoptions()
#endif
{
	Vmalloc_t*	vm = 0;
	char*		trace = 0;
	char*		s;
	char*		t;
	char*		v;
	Vmulong_t	n;
	int		fd;
	char		buf[1024];

	_Vmoptions = 1;
	t = buf;
	v = &buf[sizeof(buf)-1];
	if (s = getenv("VMALLOC_OPTIONS"))
		COPY(t, v, s);
	if (t > buf)
	{
		*t = 0;
		s = buf;
		for (;;)
		{
			while (*s == ',' || *s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
				s++;
			if (!*(t = s))
				break;
			v = 0;
			while (*s)
				if (*s == ',' || *s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
				{
					*s++ = 0;
					break;
				}
				else if (!v && *s == '=')
				{
					*s++ = 0;
					if (!*(v = s))
						v = 0;
				}
				else
					s++;
			if (t[0] == 'n' && t[1] == 'o')
				continue;
			switch (t[0])
			{
			case 'a':		/* abort */
				if (!vm)
					vm = vmopen(Vmdcsystem, Vmdebug, 0);
				if (vm && vm->meth.meth == VM_MTDEBUG)
					vmset(vm, VM_DBABORT, 1);
				else
					_Vmassert |= VM_abort;
				break;
			case 'b':		/* break */
				_Vmassert |= VM_break;
				break;
			case 'c':		/* check */
				_Vmassert |= VM_check;
				break;
			case 'f':		/* free */
				_Vmassert |= VM_free;
				break;
			case 'k':		/* keep */
				_Vmassert |= VM_keep;
				break;
			case 'm':
				if (v)
					switch (t[1])
					{
					case 'e': /* method=METHOD */
						if (!vm)
						{
							if ((v[0] == 'V' || v[0] == 'v') && (v[1] == 'M' || v[1] == 'm'))
								v += 2;
							if (strcmp(v, "debug") == 0)
								vm = vmopen(Vmdcsystem, Vmdebug, 0);
							else if (strcmp(v, "profile") == 0)
								vm = vmopen(Vmdcsystem, Vmprofile, 0);
							else if (strcmp(v, "last") == 0)
								vm = vmopen(Vmdcsystem, Vmlast, 0);
							else if (strcmp(v, "best") == 0)
								vm = Vmheap;
						}
						break;
					case 'm': /* mmap */
						_Vmassert |= VM_mmap;
						break;
					}
				break;
			case 'p':
				if (v)
					switch (t[1])
					{
					case 'e':	/* period=<count> */
						if (!vm)
							vm = vmopen(Vmdcsystem, Vmdebug, 0);
						if (vm && vm->meth.meth == VM_MTDEBUG)
							_Vmdbcheck = atou(&v);
						break;
					case 'r':	/* profile=<path> */
						if (!vm)
							vm = vmopen(Vmdcsystem, Vmprofile, 0);
						if (v && vm && vm->meth.meth == VM_MTPROFILE)
							_Vmpffd = createfile(v);
						break;
					}
				break;
			case 's':		/* start=<count> */
				if (!vm)
					vm = vmopen(Vmdcsystem, Vmdebug, 0);
				if (v && vm && vm->meth.meth == VM_MTDEBUG)
					_Vmdbstart = atou(&v);
				break;
			case 't':		/* trace=<path> */
				trace = v;
				break;
			case 'w':
				if (t[1] == 'a')
					switch (t[2])
					{
					case 'r':	/* warn=<path> */
						if (!vm)
							vm = vmopen(Vmdcsystem, Vmdebug, 0);
						if (v && vm && vm->meth.meth == VM_MTDEBUG && (fd = createfile(v)) >= 0)
							vmdebug(fd);
						break;
					case 't':	/* watch=<addr> */
						if (!vm)
							vm = vmopen(Vmdcsystem, Vmdebug, 0);
						if (v && vm && vm->meth.meth == VM_MTDEBUG && (n = atou(&v)) >= 0)
							vmdbwatch((Void_t*)n);
						break;
					}
				break;
			}
		}
	}

	/* slip in the new region now so that malloc() will work fine */

	if (vm)
	{
		if (vm->meth.meth == VM_MTDEBUG)
			_Vmdbcheck = 1;
		Vmregion = vm;
	}

	/* enable tracing -- this currently disables multiple regions */

	if (trace)
	{
		setregmax(0);
		if ((fd = createfile(trace)) >= 0)
		{
			vmset(Vmregion, VM_TRACE, 1);
			vmtrace(fd);
		}
	}
	else if (Vmregion != Vmheap || asometh(0, 0)->type == ASO_SIGNAL)
		setregmax(0);

	/* make sure that profile data is output upon exiting */

	if (vm && vm->meth.meth == VM_MTPROFILE)
	{	
		if (_Vmpffd < 0)
			_Vmpffd = 2;
		/* this may wind up calling malloc(), but region is ok now */
		atexit(pfprint);
	}
	else if (_Vmpffd >= 0)
	{	
		close(_Vmpffd);
		_Vmpffd = -1;
	}
}

/*
 * ast semi-private workaround for system functions
 * that misbehave by passing bogus addresses to free()
 *
 * not prototyped in any header to keep it ast semi-private
 *
 * to keep malloc() data by disabling free()
 *	extern _vmkeep(int);
 *	int r = _vmkeep(1);
 * and to restore to the previous state
 *	(void)_vmkeep(r);
 */

int
#if __STD_C
_vmkeep(int v)
#else
_vmkeep(v)
int	v;
#endif
{
	int	r;

	r = !!(_Vmassert & VM_keep);
	if (v)
		_Vmassert |= VM_keep;
	else
		_Vmassert &= ~VM_keep;
	return r;
}

#endif /*_UWIN*/
