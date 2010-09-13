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

void _STUB_vmmopen(){}

#else

#include	"vmhdr.h"

#if _sys_stat
#include	<sys/stat.h>
#endif
#include	<fcntl.h>

#ifdef S_IRUSR
#define CREAT_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#else
#define CREAT_MODE	0644
#endif

#if _lib_mmap
#include	<sys/mman.h>
#else
#define mmap(a,b,c,d,e,f)	MAP_FAILED
#define munmap(a,b)		MAP_FAILED
#endif

/* Create a region to allocate based on mmap()
**
** Written by Kiem-Phong Vo (kpv@research.att.com)
*/

#ifndef MAP_FAILED
#define MAP_FAILED	(void*)(-1)
#endif

#define	MM_MAGIC	(('V'<<24) | ('M'<<16) | ('A'<<8) | ('P'))
#define MM_ROUND	(64*1024)
#define MM_START	ROUND(sizeof(Mmvm_t),ALIGN)

typedef struct _user_s
{	struct _user_s*	next;	/* link list		*/
	int		key;	/* identifying key	*/
	Void_t*		data;	/* data to be returned	*/
} User_t;

typedef struct _mmvm_s
{
	Vmulong_t	magic;	/* magic bytes		*/
	Void_t*		base;	/* base of the map	*/
	size_t		size;	/* current size		*/
	size_t		busy;	/* amount in use	*/
	size_t		round;	/* amount to round to	*/
	User_t*		user;	/* some user data	*/
} Mmvm_t;

typedef struct _mmvmdisc_s
{
	Vmdisc_t	disc;	/* Vmalloc discipline	*/
	int		fd;	/* file descriptor	*/
	Mmvm_t*		mm;	/* mmap data		*/
} Mmvmdisc_t;

#if __STD_C
static int mmvminit(char* file, Void_t* addr, size_t round, Mmvm_t* mm)
#else
static int mmvminit(file, addr, round, mm)
char*	file;	/* file to map data from	*/
Void_t*	addr;	/* desired starting address	*/
size_t	round;	/* amount to round requests 	*/
Mmvm_t*	mm;	/* to return some mapped info	*/
#endif
{
	int		fd;
	off_t		size;
	Void_t		*base;
	Mmvm_t		*hdr;

	base = NIL(Void_t*);
	if((fd = open(file, O_RDWR, CREAT_MODE)) >= 0)
	{	if((size = lseek(fd, (off_t)0, 2)) < 0)
			goto done;
		else if(size == 0)
			goto new_f;

		/* read the header */
		if(lseek(fd, (off_t)0, 0) != (off_t)0)
			goto done;
		if(read(fd, mm, sizeof(Mmvm_t)) != sizeof(Mmvm_t))
			goto done;
		if(mm->magic != MM_MAGIC || !mm->base ||
		   (off_t)mm->size != size || mm->busy > mm->size )
			goto done;
		base = (Void_t*)mmap(mm->base, mm->size, PROT_READ|PROT_WRITE,
				     MAP_FIXED|MAP_SHARED, fd, (off_t)0 );
		if(base == (Void_t*)MAP_FAILED)
			base = NIL(Void_t*);
	}
	else
	{	if((fd = open(file, O_RDWR|O_CREAT, CREAT_MODE)) < 0)
			goto done;

	new_f:	/* create an initial set of data */
		size = round;
		if(lseek(fd, size-1, 0) != (size-1) || write(fd, "", 1) != 1 )
			goto done;

		base = (Void_t*)mmap(addr, (size_t)size, PROT_READ|PROT_WRITE,
				     (addr ? MAP_FIXED : 0)|MAP_SHARED, fd, (off_t)0 );
		if(base == (Void_t*)MAP_FAILED)
			base = NIL(Void_t*);
		if(!base)
			goto done;

		/* write magic number */
		hdr = (Mmvm_t*)base;
		hdr->magic = MM_MAGIC;
		hdr->base  = base;
		hdr->size  = size;
		hdr->busy  = MM_START;
		hdr->round = round;
		hdr->user  = NIL(User_t*);
		memcpy(mm, hdr, sizeof(Mmvm_t));
	}

done:
	if(!base)
	{	if(fd >= 0)
			close(fd);
		fd = -1;
	}

	return fd;
}


#if __STD_C
static Void_t* mmvmmemory(Vmalloc_t* vm, Void_t* caddr,
			size_t csize, size_t nsize, Vmdisc_t* disc)
#else
static Void_t* mmvmmemory(vm, caddr, csize, nsize, disc)
Vmalloc_t*	vm;
Void_t*		caddr;
size_t		csize;
size_t		nsize;
Vmdisc_t*	disc;
#endif
{
	Mmvmdisc_t	*mmdc = (Mmvmdisc_t*)disc;

	if(mmdc->fd < 0 || !mmdc->mm)
		return NIL(Void_t*);

#define MMADDR(b)	((Void_t*)(((Vmuchar_t*)b) + MM_START) )
	if(caddr && caddr != MMADDR(mmdc->mm->base) )
		return NIL(Void_t*);
	if(nsize < csize)
		return NIL(Void_t*);

	if(nsize > mmdc->mm->size-MM_START)
	{	/* base and size of new map */
		caddr = mmdc->mm->base;
		csize = MM_START + nsize +
			((nsize % disc->round) < (disc->round/2) ? disc->round/2 : 0);
		csize = ROUND(csize, disc->round);

		/* make room for new space */
		if(lseek(mmdc->fd, (off_t)(csize-1), 0) != (off_t)(csize-1) ||
		   write(mmdc->fd, "", 1) != 1 )
			return NIL(Void_t*);
		
		/* remap the space */
		(void)munmap(caddr, mmdc->mm->size);
		caddr = (Void_t*)mmap(caddr, csize, PROT_READ|PROT_WRITE,
				     MAP_FIXED|MAP_SHARED, mmdc->fd, (off_t)0 );
		if(caddr == (Void_t*)MAP_FAILED)
			caddr = NIL(Void_t*);
		if(caddr)
			mmdc->mm->size = csize;
		else	/* bad problem */
		{	close(mmdc->fd);
			mmdc->fd = -1;
			mmdc->mm = NIL(Mmvm_t*);
			return NIL(Void_t*);
		}
	}

	mmdc->mm->busy = nsize+MM_START;
	return (Void_t*)(((Vmuchar_t*)mmdc->mm->base) + MM_START);
}


#if __STD_C
static int mmvmexcept(Vmalloc_t* vm, int type, Void_t* data, Vmdisc_t* disc)
#else
static int mmvmexcept(vm, type, data, disc)
Vmalloc_t*	vm;
int		type;
Void_t*		data;
Vmdisc_t*	disc;
#endif
{
	Mmvmdisc_t	*mmdc = (Mmvmdisc_t*)disc;
	Vmuchar_t	*base;

	if(type == VM_OPEN)
	{	if(mmdc->mm->busy > MM_START)
		{	base = ((Vmuchar_t*)mmdc->mm->base) + MM_START;
			*((Void_t**)data) = (Void_t*)base;
			return 1;
		}
		else	return 0;
	}
	else if(type == VM_CLOSE)
	{	(void)munmap(mmdc->mm->base, mmdc->mm->size);
		(void)close(mmdc->fd);
		vmfree(Vmheap, mmdc);
		return 1; /* freeing of mapped data is already done */
	}
	else	return 0;
}


#if __STD_C
Vmalloc_t* vmmopen(char* file, Void_t* base, size_t round)
#else
Vmalloc_t* vmmopen(file, base, round)
char*		file;	/* file mapping data from	*/
Void_t* 	base;	/* desired starting address	*/
size_t		round;	/* amount to round requests	*/
#endif
{
	Vmalloc_t	*vm;
	Mmvmdisc_t	*mmdc;
	Mmvm_t		mm;
	int		fd;

	if(!file)
		return NIL(Vmalloc_t*);

	/* set the amount to round up to on each memory request */
	GETPAGESIZE(_Vmpagesize);
	if(round < MM_ROUND)
		round = MM_ROUND;
	round = ROUND(round, _Vmpagesize);

	if((fd = mmvminit(file, base, round, &mm)) < 0)
		return NIL(Vmalloc_t*);

	if(!(mmdc = (Mmvmdisc_t*)vmalloc(Vmheap, sizeof(Mmvmdisc_t))) )
	{	close(fd);
		return NIL(Vmalloc_t*);
	}

	mmdc->disc.memoryf = mmvmmemory;
	mmdc->disc.exceptf = mmvmexcept;
	mmdc->disc.round   = mm.round;
	mmdc->fd = fd;
	mmdc->mm = (Mmvm_t*)mm.base;

	if(!(vm = vmopen(&mmdc->disc, Vmbest, VM_TRUST)) )
	{	mmvmexcept(NIL(Vmalloc_t*), VM_CLOSE, NIL(Void_t*), &mmdc->disc);	
		return NIL(Vmalloc_t*);
	}

	return vm;
}


#if __STD_C
Void_t* vmmset(Vmalloc_t* vm, int key, Void_t* data, int set)
#else
Void_t* vmmset(vm, data, key, set)
Vmalloc_t*	vm;	/* a region based on vmmmopen	*/
int		key;	/* key of data to be set	*/
Void_t*		data;	/* data to be set		*/
int		set;	/* 1 for setting, 0 for getting	*/
#endif
{
	User_t	*u;
	Mmvm_t	*mmvm = ((Mmvmdisc_t*)vm->disc)->mm;

	for(u = mmvm->user; u; u = u->next)
		if(u->key == key)
			break;
	if(!set)
		return u ? u->data : NIL(Void_t*);
	else if(u)
	{	Void_t* old = u->data;
		u->data = data;
		return old;
	}
	else if(!(u = (User_t*)vmalloc(vm, sizeof(User_t))) )
		return NIL(Void_t*);
	else
	{	u->data = data;
		u->key  = key;
		u->next = mmvm->user;
		mmvm->user = u;
		return data;
	}
}

#endif
