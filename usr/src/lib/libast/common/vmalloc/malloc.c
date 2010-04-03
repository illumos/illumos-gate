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
**	VMALLOC_OPTIONS environment variable which is a space-separated
**	list of [no]name[=value] options:
**
**	    abort	if Vmregion==Vmdebug then VM_DBABORT is set,
**			otherwise _BLD_debug enabled assertions abort()
**			on failure
**	    check	if Vmregion==Vmbest then the region is checked every op
**	    method=m	sets Vmregion=m if not defined, m (Vm prefix optional)
**			may be one of { best debug last profile }
**	    mmap	prefer mmap() over brk() for region allocation
**	    period=n	sets Vmregion=Vmdebug if not defined, if
**			Vmregion==Vmdebug the region is checked every n ops
**	    profile=f	sets Vmregion=Vmprofile if not set, if
**			Vmregion==Vmprofile then profile info printed to file f
**	    region	if Vmregion==Vmbest then block free verifies
**			that the block belongs to the region
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
**	    { VMDEBUG VMETHOD VMPROFILE VMTRACE }
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

#if __STD_C
extern Void_t* calloc(reg size_t n_obj, reg size_t s_obj)
#else
extern Void_t* calloc(n_obj, s_obj)
reg size_t	n_obj;
reg size_t	s_obj;
#endif
{
	VMFLINIT();
	return VMRECORD((*Vmregion->meth.resizef)(Vmregion,NIL(Void_t*),n_obj*s_obj,VM_RSZERO));
}

#if __STD_C
extern Void_t* malloc(reg size_t size)
#else
extern Void_t* malloc(size)
reg size_t	size;
#endif
{
	VMFLINIT();
	return VMRECORD((*Vmregion->meth.allocf)(Vmregion,size));
}

#if __STD_C
extern Void_t* realloc(reg Void_t* data, reg size_t size)
#else
extern Void_t* realloc(data,size)
reg Void_t*	data;	/* block to be reallocated	*/
reg size_t	size;	/* new size			*/
#endif
{
#if USE_NATIVE
#undef	realloc
#if __STD_C
	extern Void_t*	realloc(Void_t*, size_t);
#else
	extern Void_t*	realloc();
#endif
#endif

	VMFLINIT();

#if _PACKAGE_ast
	if(data && Vmregion->meth.meth != VM_MTDEBUG &&
#if !USE_NATIVE
	   !(Vmregion->data->mode&VM_TRUST) &&
#endif
	   (*Vmregion->meth.addrf)(Vmregion,data) != 0 )
	{	
#if USE_NATIVE
		return realloc(data, size);
#else
		Void_t*	newdata;
		if((newdata = (*Vmregion->meth.allocf)(Vmregion,size)) )
			memcpy(newdata,data,size);
		return VMRECORD(newdata);
#endif
	}
#endif

#if USE_NATIVE
	{	Void_t*	newdata;
		if (newdata = (*Vmregion->meth.resizef)(Vmregion,data,size,VM_RSCOPY|VM_RSMOVE))
			return newdata;
		return VMRECORD(realloc(data, size));
	}
#else
	return VMRECORD((*Vmregion->meth.resizef)(Vmregion,data,size,VM_RSCOPY|VM_RSMOVE));
#endif
}

#if __STD_C
extern void free(reg Void_t* data)
#else
extern void free(data)
reg Void_t*	data;
#endif
{
#if USE_NATIVE
#undef	free
#if __STD_C
	extern void	free(Void_t*);
#else
	extern void	free();
#endif
#endif

	VMFLINIT();

#if _PACKAGE_ast
	if(data && Vmregion->meth.meth != VM_MTDEBUG &&
#if !USE_NATIVE
	   !(Vmregion->data->mode&VM_TRUST) &&
#endif
	   (*Vmregion->meth.addrf)(Vmregion,data) != 0)
	{
#if USE_NATIVE
		free(data);
#endif
		return;
	}
#endif

#if USE_NATIVE
	if ((*Vmregion->meth.freef)(Vmregion,data) != 0)
		free(data);
#else
	(void)(*Vmregion->meth.freef)(Vmregion,data);
#endif
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
	Void_t*	addr;

	VMFLINIT();
	VMBLOCK
	addr = VMRECORD((*Vmregion->meth.alignf)(Vmregion,size,align));
	VMUNBLOCK
	return addr;
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
	return VMRECORD((*Vmregion->meth.alignf)(Vmregion,size,_Vmpagesize));
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
	return VMRECORD((*Vmregion->meth.alignf)(Vmregion,ROUND(size,_Vmpagesize),_Vmpagesize));
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
	reg Alloca_t*	f;
	static Alloca_t* Frame;

	VMFLINIT();
	VMFLF(Vmregion,file,line,func);
	while(Frame)
	{	if(( _stk_down && &array[0] > Frame->head.head.addr) ||
		   (!_stk_down && &array[0] < Frame->head.head.addr) )
		{	f = Frame;
			Frame = f->head.head.next;
			(void)(*Vmregion->meth.freef)(Vmregion,f);
		}
		else	break;
	}

	Vmregion->file = file;
	Vmregion->line = line;
	Vmregion->func = func;
	f = (Alloca_t*)(*Vmregion->meth.allocf)(Vmregion,size+sizeof(Alloca_t)-1);

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

extern Void_t*	F2(_ast_calloc, size_t,n, size_t,m) { return calloc(n, m); }
extern Void_t	F1(_ast_cfree, Void_t*,p) { free(p); }
extern Void_t	F1(_ast_free, Void_t*,p) { free(p); }
extern Void_t*	F1(_ast_malloc, size_t,n) { return malloc(n); }
#if _lib_memalign
extern Void_t*	F2(_ast_memalign, size_t,a, size_t,n) { return memalign(a, n); }
#endif
#if _lib_pvalloc
extern Void_t*	F1(_ast_pvalloc, size_t,n) { return pvalloc(n); }
#endif
extern Void_t*	F2(_ast_realloc, Void_t*,p, size_t,n) { return realloc(p, n); }
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

#include	<malloc.h>

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
#if _PACKAGE_ast
		fd = open(file, O_WRONLY|O_CREAT|O_TRUNC, CREAT_MODE);
#else
		fd = creat(file, CREAT_MODE);
#endif
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
#if 1 /* backwards compatibility until 2011 */
	else
	{
		char*	p;

		if (s = getenv("VMDEBUG"))
		{
			switch (*s++)
			{
			case 0:
				break;
			case 'a':
				p = " abort";
				COPY(t, v, p);
				break;
			case 'w':
				p = " warn";
				COPY(t, v, p);
				break;
			case '0':
				if (*s-- == 'x')
				{
					p = " watch=";
					COPY(t, v, p);
					COPY(t, v, s);
					break;
				}
				/*FALLTHROUGH*/
			default:
				p = " period=";
				COPY(t, v, p);
				COPY(t, v, s);
				break;
			}
		}
		if ((s = getenv("VMETHOD")) && *s)
		{
			p = " method=";
			COPY(t, v, p);
			COPY(t, v, s);
		}
		if ((s = getenv("VMPROFILE")) && *s)
		{
			p = " profile=";
			COPY(t, v, p);
			COPY(t, v, s);
		}
		if ((s = getenv("VMTRACE")) && *s)
		{
			p = " trace=";
			COPY(t, v, p);
			COPY(t, v, s);
		}
	}
#endif
	if (t > buf)
	{
		*t = 0;
		s = buf;
		for (;;)
		{
			while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
				s++;
			if (!*(t = s))
				break;
			v = 0;
			while (*s)
				if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
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
					vm = vmopen(Vmdcsbrk, Vmdebug, 0);
				if (vm && vm->meth.meth == VM_MTDEBUG)
					vmset(vm, VM_DBABORT, 1);
				else
					_Vmassert |= VM_abort;
				break;
			case 'c':		/* check */
				_Vmassert |= VM_check;
				break;
			case 'm':
				switch (t[1])
				{
				case 'e':	/* method=<method> */
					if (v && !vm)
					{
						if ((v[0] == 'V' || v[0] == 'v') && (v[1] == 'M' || v[1] == 'm'))
							v += 2;
						if (strcmp(v, "debug") == 0)
							vm = vmopen(Vmdcsbrk, Vmdebug, 0);
						else if (strcmp(v, "profile") == 0)
							vm = vmopen(Vmdcsbrk, Vmprofile, 0);
						else if (strcmp(v, "last") == 0)
							vm = vmopen(Vmdcsbrk, Vmlast, 0);
						else if (strcmp(v, "best") == 0)
							vm = Vmheap;
					}
					break;
				case 'm':	/* mmap */
#if _mem_mmap_anon || _mem_mmap_zero
					_Vmassert |= VM_mmap;
#endif
					break;
				}
				break;
			case 'p':
				if (v)
					switch (t[1])
					{
					case 'e':	/* period=<count> */
						if (!vm)
							vm = vmopen(Vmdcsbrk, Vmdebug, 0);
						if (vm && vm->meth.meth == VM_MTDEBUG)
							_Vmdbcheck = atou(&v);
						break;
					case 'r':	/* profile=<path> */
						if (!vm)
							vm = vmopen(Vmdcsbrk, Vmprofile, 0);
						if (v && vm && vm->meth.meth == VM_MTPROFILE)
							_Vmpffd = createfile(v);
						break;
					}
				break;
			case 'r':		/* region */
				_Vmassert |= VM_region;
				break;
			case 's':		/* start=<count> */
				if (!vm)
					vm = vmopen(Vmdcsbrk, Vmdebug, 0);
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
							vm = vmopen(Vmdcsbrk, Vmdebug, 0);
						if (v && vm && vm->meth.meth == VM_MTDEBUG && (fd = createfile(v)) >= 0)
							vmdebug(fd);
						break;
					case 't':	/* watch=<addr> */
						if (!vm)
							vm = vmopen(Vmdcsbrk, Vmdebug, 0);
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

	/* enable tracing */

	if (trace && (fd = createfile(trace)) >= 0)
	{
		vmset(Vmregion, VM_TRACE, 1);
		vmtrace(fd);
	}

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

#endif /*_UWIN*/
