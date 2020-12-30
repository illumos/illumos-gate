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

void _STUB_vmmapopen(){}

#else

#include	"vmhdr.h"
#include	<sys/types.h>
#include	<string.h>
#if _hdr_unistd
#include	<unistd.h>
#endif

#undef	ALIGN	/* some sys/param.h define this */

#include	<sys/mman.h>	/* mmap() headers	*/
#include	<sys/file.h>
#include	<sys/stat.h>
#include	<fcntl.h>

#include	<sys/shm.h>	/* shm headers		*/
#include	<sys/ipc.h>

#undef	ALIGN
#define ALIGN	sizeof(struct _align_s)

/* Create a region to allocate based on mmap() or shmget().
** Both ways provide for share memory allocation.
** mmap() also allows for allocating persistent data.
**
** Written by Kiem-Phong Vo (kpv@research.att.com)
*/

#define MM_INIT		001	/* initialization mode	*/

#define MM_RELEASE	010	/* release share mem	*/
#define MM_CLEANUP	020	/* clean up resources	*/

/* magic word signaling region is being initialized */
#define MM_LETMEDOIT	((unsigned int)(('N'<<24) | ('B'<<16) | ('&'<<8) | ('I')) )

/* magic word signaling file/segment is ready */
#define	MM_MAGIC	((unsigned int)(('P'<<24) | ('&'<<16) | ('N'<<8) | ('8')) )

/* default mimimum region size */
#define MM_MINSIZE	(64*_Vmpagesize)

/* macros to get the data section and size */
#define MMHEAD(file)	ROUND(sizeof(Mmvm_t)+strlen(file), ALIGN)
#define MMDATA(mmvm)	((Vmuchar_t*)(mmvm)->base + MMHEAD(mmvm->file))
#define MMSIZE(mmvm)	((mmvm)->size - MMHEAD(mmvm->file))

#ifdef S_IRUSR
#define FILE_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#else
#define FILE_MODE	0644
#endif

/* to store key/value pairs for application */
typedef struct _mmuser_s	Mmuser_t;
struct _mmuser_s
{	Mmuser_t*	next;	/* link list		*/
	int		key;	/* identifying key	*/
	Void_t*		val;	/* associated value	*/
};

typedef struct _mmvm_s
{	unsigned int	magic;	/* magic bytes		*/
	Void_t*		base;	/* address to map to	*/
	ssize_t		size;	/* total data size	*/
	ssize_t		busy;	/* amount in use	*/
	Mmuser_t*	user;	/* stored (key,val)'s	*/
	int		proj;	/* project number	*/
	char		file[1];/* file name		*/
} Mmvm_t;

typedef struct _mmdisc_s
{	Vmdisc_t	disc;	/* Vmalloc discipline	*/
	int		flag;	/* various modes	*/
	Mmvm_t*		mmvm;	/* shared memory data	*/
	ssize_t		size;	/* desired file size	*/
	int		shmid;	/* ID of the shared mem	*/
	int		proj;	/* shm project ID 	*/
	char		file[1];/* backing store/ftok()	*/
} Mmdisc_t;

#if DEBUG
#include	<stdio.h>
#include	<string.h>
int _vmmdump(Vmalloc_t* vm, int fd)
{
	char		mesg[1024];
	Mmdisc_t	*mmdc = (Mmdisc_t*)vm->disc;

	fd = fd < 0 ? 2 : fd;
	sprintf(mesg, "File: %s\n", mmdc->file ); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Project: %10d\n", mmdc->proj); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Memory:  %#010lx\n", mmdc->mmvm); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Size:    %10d\n", mmdc->size); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Shmid:   %10d\n", mmdc->shmid); write(fd, mesg, strlen(mesg));

	sprintf(mesg, "File header:\n"); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Magic:   %10d\n", mmdc->mmvm->magic); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Base:    %#010lx\n", mmdc->mmvm->base); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Size:    %10d\n", mmdc->mmvm->size); write(fd, mesg, strlen(mesg));
	sprintf(mesg, "Busy:    %10d\n", mmdc->mmvm->busy); write(fd, mesg, strlen(mesg));
	return 0;
}
#endif /*DEBUG*/

/* fix the mapped address for a region */
static Mmvm_t* mmfix(Mmvm_t* mmvm, Mmdisc_t* mmdc, int fd)
{
	Void_t	*base = mmvm->base;
	ssize_t	size = mmvm->size;

	if(base != (Void_t*)mmvm) /* mmvm is not right yet */
	{	/**/ASSERT(!base || (base && (VLONG(base)%_Vmpagesize) == 0) );
		if(mmdc->proj < 0)
		{	munmap((Void_t*)mmvm, size); 
			mmvm = (Mmvm_t*)mmap(base, size, (PROT_READ|PROT_WRITE),
					     (MAP_FIXED|MAP_SHARED), fd, (off_t)0 );
		}
		else
		{	shmdt((Void_t*)mmvm);
			mmvm = (Mmvm_t*)shmat(mmdc->shmid, base, 0);
		}
		if(!mmvm || mmvm == (Mmvm_t*)(-1) )
			mmvm = NIL(Mmvm_t*);
	}

	return mmvm;
}

/* initialize region data */
static int mminit(Mmdisc_t* mmdc)
{
	Void_t		*base;
	int		try, k;
	int		fd = -1;
	key_t		key = -1;
	ssize_t		extent, size = 0;
	Mmvm_t		*mmvm = NIL(Mmvm_t*);
	int		rv = -1;

	if(mmdc->mmvm) /* already done this */
		return 0;

	/* fixed size region so make it reasonably large */
	if((size = mmdc->size) < MM_MINSIZE )
		size =  MM_MINSIZE;
	size += MMHEAD(mmdc->file) + ALIGN;
	size  = ROUND(size, _Vmpagesize);

	/* this op can happen simultaneously in different processes */
	if((fd = open(mmdc->file, O_RDWR|O_CREAT, FILE_MODE)) < 0)
		return -1;

	/* get/create the initial segment of data */
	if(mmdc->proj < 0 ) /* proj < 0 means doing mmap() */
	{	/* Note that the location being written to is always zero! */
		if((extent = (ssize_t)lseek(fd, (off_t)0, SEEK_END)) < 0)
			goto done;
		if(extent < size) /* make the file size large enough */
			if(lseek(fd, (off_t)size, 0) != (off_t)size || write(fd, "", 1) != 1 )
				goto done;

		/* map the file into memory */
		mmvm = (Mmvm_t*)mmap(NIL(Void_t*), size, (PROT_READ|PROT_WRITE),
		 		     MAP_SHARED, fd, (off_t)0 );
	}
	else 
	{	/* make the key and get/create an id for the share mem segment */
		if((key = ftok(mmdc->file, mmdc->proj)) < 0 )
			goto done;
		if((mmdc->shmid = shmget(key, size, IPC_CREAT|FILE_MODE)) < 0 )
			goto done;

		/* map the data segment into memory */
		mmvm = (Mmvm_t*)shmat(mmdc->shmid, NIL(Void_t*), 0);
	}

	if(!mmvm || mmvm == (Mmvm_t*)(-1) ) /* initial mapping failed */
		goto done;

	/* all processes compete for the chore to initialize data */
	if(asocasint(&mmvm->magic, 0, MM_LETMEDOIT) == 0 ) /* lucky winner: us! */
	{	if(!(base = vmmaddress(size)) ) /* get a suitable base for the map */
			base = (Void_t*)mmvm;
		mmdc->flag |= MM_INIT;
		mmvm->base = base;
		mmvm->size = size;
		mmvm->busy = 0;
		mmvm->proj = mmdc->proj;
		strcpy(mmvm->file, mmdc->file);
		if(mmdc->proj < 0 ) /* flush to file */
			msync((Void_t*)mmvm, MMHEAD(mmvm->file), MS_SYNC);

		if(mmvm->base != (Void_t*)mmvm) /* not yet at the right address */
			if(!(mmvm = mmfix(mmvm, mmdc, fd)) )
				goto done;
		rv = 0; /* success, return this value to indicate a new map */
	}
	else /* wait for someone else to finish initialization */
	{	/**/ASSERT(!(mmdc->flag&MM_INIT));
		if(mmvm->magic != MM_LETMEDOIT && mmvm->magic != MM_MAGIC)
			goto done;

		for(try = 0, k = 0;; ASOLOOP(k) ) /* waiting */
		{	if(asocasint(&mmvm->magic, MM_MAGIC, MM_MAGIC) == MM_MAGIC )
				break;
			else if((try += 1) <= 0 ) /* too many tries */
				goto done;
		}

		/* mapped the wrong memory */
		if(mmvm->proj != mmdc->proj || strcmp(mmvm->file, mmdc->file) != 0 )
			goto done;

		if(mmvm->base != (Void_t*)mmvm) /* not yet at the right address */
			if(!(mmvm = mmfix(mmvm, mmdc, fd)) )
				goto done;
		rv = 1; /* success, return this value to indicate a finished map */
	}

done:	(void)close(fd);

	if(rv >= 0 ) /* successful construction of region */
	{	/**/ASSERT(mmvm && mmvm != (Mmvm_t*)(-1));
		mmdc->mmvm = mmvm;
	}
	else if(mmvm && mmvm != (Mmvm_t*)(-1)) /* error, remove map */
	{	if(mmdc->proj < 0)
			(void)munmap((Void_t*)mmvm, size);
		else	(void)shmdt((Void_t*)mmvm);
	}

	return rv;
}

#if __STD_C /* end a file mapping */
static int mmend(Mmdisc_t* mmdc)
#else
static int mmend(mmdc)
Mmdisc_t*	mmdc;
#endif
{
	Mmvm_t		*mmvm;
	struct shmid_ds	shmds;

	if(!(mmvm = mmdc->mmvm) )
		return 0;

	if(mmdc->proj < 0 )
	{	(void)msync(mmvm->base, mmvm->size, MS_ASYNC);
		if(mmdc->flag&MM_RELEASE)
		{	if(mmvm->base )
				(void)munmap(mmvm->base, mmvm->size);
		}
		if(mmdc->flag&MM_CLEANUP)
			(void)unlink(mmdc->file);
	}
	else 
	{	if(mmdc->flag&MM_RELEASE)
		{	if(mmvm->base )
				(void)shmdt(mmvm->base);
		}
		if(mmdc->flag&MM_CLEANUP)
		{	if(mmdc->shmid >= 0 )
				(void)shmctl(mmdc->shmid, IPC_RMID, &shmds);
		}
	}

	mmdc->mmvm = NIL(Mmvm_t*);
	return 0;
}

#if __STD_C
static Void_t* mmgetmem(Vmalloc_t* vm, Void_t* caddr,
			size_t csize, size_t nsize, Vmdisc_t* disc)
#else
static Void_t* mmgetmem(vm, caddr, csize, nsize, disc)
Vmalloc_t*	vm;
Void_t*		caddr;
size_t		csize;
size_t		nsize;
Vmdisc_t*	disc;
#endif
{
	Mmvm_t		*mmvm;
	Mmdisc_t	*mmdc = (Mmdisc_t*)disc;

	if(!(mmvm = mmdc->mmvm) ) /* bad data */
		return NIL(Void_t*);

	/* this region allows only a single busy block! */
	if(caddr) /* resizing/freeing an existing block */
	{	if(caddr == MMDATA(mmvm) && nsize <= MMSIZE(mmvm) )
		{	mmvm->busy = nsize;
			return MMDATA(mmvm);
		}
		else	return NIL(Void_t*);
	}
	else /* requesting a new block */
	{	if(mmvm->busy == 0 )
		{	mmvm->busy = nsize;
			return MMDATA(mmvm);
		}
		else	return NIL(Void_t*);
	}
}

#if __STD_C
static int mmexcept(Vmalloc_t* vm, int type, Void_t* data, Vmdisc_t* disc)
#else
static int mmexcept(vm, type, data, disc)
Vmalloc_t*	vm;
int		type;
Void_t*		data;
Vmdisc_t*	disc;
#endif
{
	int		rv;
	Void_t		*base;
	Mmdisc_t	*mmdc = (Mmdisc_t*)disc;

	if(type == VM_OPEN)
	{	if(data) /* VM_OPEN event at start of vmopen() */
		{	if((rv = mminit(mmdc)) < 0 ) /* initialization failed */
				return -1;
			else if(rv == 0) /* just started a new map */
			{	/**/ASSERT(mmdc->flag&MM_INIT);
				/**/ASSERT(mmdc->mmvm->magic == MM_LETMEDOIT);
				return 0;
			}
			else /* an existing map was reconstructed */
			{	/**/ASSERT(!(mmdc->flag&MM_INIT));
				/**/ASSERT(mmdc->mmvm->magic == MM_MAGIC);
				*((Void_t**)data) = MMDATA(mmdc->mmvm);
				return 1;
			}
		}
		else	return 0;
	}
	else if(type == VM_ENDOPEN) /* at end of vmopen() */
	{	if(mmdc->flag&MM_INIT) /* this is the initializing process! */
		{	/**/ASSERT(mmdc->mmvm->magic == MM_LETMEDOIT);
			asocasint(&mmdc->mmvm->magic, MM_LETMEDOIT, MM_MAGIC);

			if(mmdc->proj < 0) /* sync data to file now */
				msync((Void_t*)mmdc->mmvm, MMHEAD(mmdc->file), MS_SYNC);
		} /**/ASSERT(mmdc->mmvm->magic == MM_MAGIC);
		return 0;
	}
	else if(type == VM_CLOSE)
		return 1; /* tell vmclose not to free memory segments */
	else if(type == VM_ENDCLOSE) /* this is the final closing event */
	{	(void)mmend(mmdc);
		(void)vmfree(Vmheap, mmdc);
		return 0; /* all done */
	}
	else	return 0;
}

#if __STD_C
Vmalloc_t* vmmopen(char* file, int proj, ssize_t size )
#else
Vmalloc_t* vmmopen(file, proj, size )
char*		file;	/* file for key or data backing */
int		proj;	/* project ID, < 0 doing mmap	*/
ssize_t		size;	/* desired size for mem segment	*/
#endif
{
	Vmalloc_t	*vm;
	Mmdisc_t	*mmdc;

	GETPAGESIZE(_Vmpagesize);

	if(!file || !file[0] )
		return NIL(Vmalloc_t*);

	/* create discipline structure for getting memory from mmap */
	if(!(mmdc = vmalloc(Vmheap, sizeof(Mmdisc_t)+strlen(file))) )
		return NIL(Vmalloc_t*);
	memset(mmdc, 0, sizeof(Mmdisc_t));
	mmdc->disc.memoryf = mmgetmem;
	mmdc->disc.exceptf = mmexcept;
	mmdc->disc.round   = _Vmpagesize; /* round request to this size */
	mmdc->mmvm = NIL(Mmvm_t*);
	mmdc->size = size;
	mmdc->shmid = -1;
	mmdc->flag = 0;
	mmdc->proj = proj;
	strcpy(mmdc->file, file);

	/* now open the Vmalloc_t handle to return to application */
	if(!(vm = vmopen(&mmdc->disc, Vmbest, VM_SHARE)) )
	{	(void)mmend(mmdc);
		(void)vmfree(Vmheap, mmdc);
		return NIL(Vmalloc_t*);
	}
	else
	{	/**/ASSERT(mmdc->mmvm && mmdc->mmvm->magic == MM_MAGIC);
		return vm;
	}
}

/* to store (key,value) data in the map */
#if __STD_C
Void_t* vmmvalue(Vmalloc_t* vm, int key, Void_t* val, int oper)
#else
Void_t* vmmvalue(vm, key, val, oper)
Vmalloc_t*	vm;	/* a region based on vmmapopen	*/
int		key;	/* key of data to be set	*/
Void_t*		val;	/* data to be set		*/
int		oper;	/* operation type		*/
#endif
{
	Mmuser_t	*u;
	Mmdisc_t	*mmdc = (Mmdisc_t*)vm->disc;
	Mmvm_t		*mmvm = mmdc->mmvm;

	/* check to see if operation is well-defined */
	if(oper != VM_MMGET && oper != VM_MMSET && oper != VM_MMADD)
		return NIL(Void_t*);

	SETLOCK(vm, 0);

	/* find the key */
	for(u = mmvm->user; u; u = u->next)
		if(u->key == key)
			break;

	if(!u && (oper == VM_MMSET || oper == VM_MMADD) )
	{	if((u = KPVALLOC(vm, sizeof(Mmuser_t), vm->meth.allocf)) )
		{	u->val  = NIL(Void_t*);
			u->key  = key;
			u->next = mmvm->user;
			mmvm->user = u;
		}
	}

	if(u) /* update data and set value to return */
	{	if(oper == VM_MMSET)
			u->val = val;
		else if(oper == VM_MMADD)
			u->val = (Void_t*)((long)(u->val) + (long)(val));
		val = u->val;
	}
	else	val = NIL(Void_t*);

	CLRLOCK(vm, 0);

	return val;
}

void vmmrelease(Vmalloc_t* vm, int type)
{
	Mmdisc_t	*mmdc = (Mmdisc_t*)vm->disc;

	mmdc->flag |= MM_RELEASE;
	if(type > 0)
		mmdc->flag |= MM_CLEANUP;
}

/* suggest an address usable for mapping memory */
Void_t* vmmaddress(size_t size)
{
#if !defined(_map_min) || !defined(_map_max) || !defined(_map_dir)
	return NIL(Void_t*);
#else
	Void_t			*avail;
	static Vmuchar_t	*min = (Vmuchar_t*)_map_min;
	static Vmuchar_t	*max = (Vmuchar_t*)_map_max;

	GETPAGESIZE(_Vmpagesize);
	size = ROUND(size, _Vmpagesize);

	if(_map_dir == 0 || (min+size) > max)
		avail = NIL(Void_t*);
	else if(_map_dir > 0)
	{	avail = (Void_t*)min;
		min += size;
	}
	else 
	{	max -= size;
		avail = (Void_t*)max;
	}

	return avail;
#endif
}

#endif
