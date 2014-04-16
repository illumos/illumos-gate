/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* Copyright 2013 OmniTI Computer Consulting, Inc. All rights reserved. */
/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_MMAN_H
#define	_SYS_MMAN_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if	!defined(_ASM) && !defined(_KERNEL)
#include <sys/types.h>
#endif	/* !_ASM && !_KERNEL */

/*
 * Protections are chosen from these bits, or-ed together.
 * Note - not all implementations literally provide all possible
 * combinations.  PROT_WRITE is often implemented as (PROT_READ |
 * PROT_WRITE) and (PROT_EXECUTE as PROT_READ | PROT_EXECUTE).
 * However, no implementation will permit a write to succeed
 * where PROT_WRITE has not been set.  Also, no implementation will
 * allow any access to succeed where prot is specified as PROT_NONE.
 */
#define	PROT_READ	0x1		/* pages can be read */
#define	PROT_WRITE	0x2		/* pages can be written */
#define	PROT_EXEC	0x4		/* pages can be executed */

#ifdef	_KERNEL
#define	PROT_USER	0x8		/* pages are user accessable */
#define	PROT_ZFOD	(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_USER)
#define	PROT_ALL	(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_USER)
#endif	/* _KERNEL */

#define	PROT_NONE	0x0		/* pages cannot be accessed */

/* sharing types:  must choose either SHARED or PRIVATE */
#define	MAP_SHARED	1		/* share changes */
#define	MAP_PRIVATE	2		/* changes are private */
#define	MAP_TYPE	0xf		/* mask for share type */

/* other flags to mmap (or-ed in to MAP_SHARED or MAP_PRIVATE) */
#define	MAP_FILE	0		/* map from file (default) */
#define	MAP_FIXED	0x10		/* user assigns address */
/* Not implemented */
#define	MAP_RENAME	0x20		/* rename private pages to file */
#define	MAP_NORESERVE	0x40		/* don't reserve needed swap area */
/* Note that 0x80 is _MAP_LOW32, defined below */
#define	MAP_ANON	0x100		/* map anonymous pages directly */
#define	MAP_ANONYMOUS	MAP_ANON	/* (source compatibility) */
#define	MAP_ALIGN	0x200		/* addr specifies alignment */
#define	MAP_TEXT	0x400		/* map code segment */
#define	MAP_INITDATA	0x800		/* map data segment */

#ifdef _KERNEL
#define	_MAP_TEXTREPL	0x1000
#define	_MAP_RANDOMIZE	0x2000
#endif /* _KERNEL */

#if	(_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2)
/* these flags are used by memcntl */
#define	PROC_TEXT	(PROT_EXEC | PROT_READ)
#define	PROC_DATA	(PROT_READ | PROT_WRITE | PROT_EXEC)
#define	SHARED		0x10
#define	PRIVATE		0x20
#define	VALID_ATTR  (PROT_READ|PROT_WRITE|PROT_EXEC|SHARED|PRIVATE)
#endif	/* (_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2) */

#if	(_POSIX_C_SOURCE <= 2) || defined(_XPG4_2)
#ifdef	_KERNEL
#define	PROT_EXCL	0x20
#endif	/* _KERNEL */

#define	_MAP_LOW32	0x80	/* force mapping in lower 4G of address space */
#define	MAP_32BIT	_MAP_LOW32

/*
 * For the sake of backward object compatibility, we use the _MAP_NEW flag.
 * This flag will be automatically or'ed in by the C library for all
 * new mmap calls.  Previous binaries with old mmap calls will continue
 * to get 0 or -1 for return values.  New mmap calls will get the mapped
 * address as the return value if successful and -1 on errors.  By default,
 * new mmap calls automatically have the kernel assign the map address
 * unless the MAP_FIXED flag is given.
 */
#define	_MAP_NEW	0x80000000	/* users should not need to use this */
#endif	/* (_POSIX_C_SOURCE <= 2) */


#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
/* External flags for mmapobj syscall (Exclusive of MAP_* flags above) */
#define	MMOBJ_PADDING		0x10000
#define	MMOBJ_INTERPRET		0x20000

#define	MMOBJ_ALL_FLAGS		(MMOBJ_PADDING | MMOBJ_INTERPRET)

/*
 * Values for mr_flags field of mmapobj_result_t below.
 * The bottom 16 bits are mutually exclusive and thus only one
 * of them can be set at a time.  Use MR_GET_TYPE below to check this value.
 * The top 16 bits are used for flags which are not mutually exclusive and
 * thus more than one of these flags can be set for a given mmapobj_result_t.
 *
 * MR_PADDING being set indicates that this memory range represents the user
 * requested padding.
 *
 * MR_HDR_ELF being set indicates that the ELF header of the mapped object
 * is mapped at mr_addr + mr_offset.
 *
 * MR_HDR_AOUT being set indicates that the AOUT (4.x) header of the mapped
 * object is mapped at mr_addr + mr_offset.
 */

/*
 * External flags for mr_flags field below.
 */
#define	MR_PADDING	0x1
#define	MR_HDR_ELF	0x2
#define	MR_HDR_AOUT	0x3

/*
 * Internal flags for mr_flags field below.
 */
#ifdef	_KERNEL
#define	MR_RESV	0x80000000	/* overmapped /dev/null */
#endif	/* _KERNEL */

#define	MR_TYPE_MASK 0x0000ffff
#define	MR_GET_TYPE(val)	((val) & MR_TYPE_MASK)

#if	!defined(_ASM)
typedef struct mmapobj_result {
	caddr_t		mr_addr;	/* mapping address */
	size_t		mr_msize;	/* mapping size */
	size_t		mr_fsize;	/* file size */
	size_t		mr_offset;	/* offset into file */
	uint_t		mr_prot;	/* the protections provided */
	uint_t		mr_flags;	/* info on the mapping */
} mmapobj_result_t;

#if defined(_KERNEL) || defined(_SYSCALL32)
typedef struct mmapobj_result32 {
	caddr32_t	mr_addr;	/* mapping address */
	size32_t	mr_msize;	/* mapping size */
	size32_t	mr_fsize;	/* file size */
	size32_t	mr_offset;	/* offset into file */
	uint_t		mr_prot;	/* the protections provided */
	uint_t		mr_flags;	/* info on the mapping */
} mmapobj_result32_t;
#endif	/* defined(_KERNEL) || defined(_SYSCALL32) */
#endif	/* !defined(_ASM) */
#endif	/* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#if	!defined(_ASM) && !defined(_KERNEL)
/*
 * large file compilation environment setup
 *
 * In the LP64 compilation environment, map large file interfaces
 * back to native versions where possible.
 */

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	mmap	mmap64
#else
#define	mmap			mmap64
#endif
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	mmap64	mmap
#else
#define	mmap64			mmap
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	getpagesizes	getpagesizes2
#else
#define	getpagesizes	getpagesizes2
#endif

/*
 * Except for old binaries mmap() will return the resultant
 * address of mapping on success and (caddr_t)-1 on error.
 */
#if (_POSIX_C_SOURCE > 2) || defined(_XPG4_2)
extern void *mmap(void *, size_t, int, int, int, off_t);
extern int munmap(void *, size_t);
extern int mprotect(void *, size_t, int);
extern int msync(void *, size_t, int);
#if (!defined(_XPG4_2) || (_POSIX_C_SOURCE > 2)) || defined(__EXTENSIONS__)
extern int mlock(const void *, size_t);
extern int munlock(const void *, size_t);
#endif	/* (!defined(_XPG4_2) || (_POSIX_C_SOURCE > 2))... */
/* transitional large file interface version */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern void *mmap64(void *, size_t, int, int, int, off64_t);
#endif	/* _LARGEFILE64_SOURCE... */
#else	/* (_POSIX_C_SOURCE > 2) || defined(_XPG4_2) */
extern caddr_t mmap(caddr_t, size_t, int, int, int, off_t);
extern int munmap(caddr_t, size_t);
extern int mprotect(caddr_t, size_t, int);
extern int msync(caddr_t, size_t, int);
extern int mlock(caddr_t, size_t);
extern int munlock(caddr_t, size_t);
extern int mincore(caddr_t, size_t, char *);
extern int memcntl(caddr_t, size_t, int, caddr_t, int, int);
extern int madvise(caddr_t, size_t, int);
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
extern int getpagesizes(size_t *, int);
extern int getpagesizes2(size_t *, int);
extern int mmapobj(int, uint_t, mmapobj_result_t *, uint_t *, void *);
/* guard visibility of uint64_t */
#if defined(_INT64_TYPE)
extern int meminfo(const uint64_t *, int, const uint_t *, int, uint64_t *,
	uint_t *);
#endif /* defined(_INT64_TYPE) */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */
/* transitional large file interface version */
#ifdef	_LARGEFILE64_SOURCE
extern caddr_t mmap64(caddr_t, size_t, int, int, int, off64_t);
#endif
#endif	/* (_POSIX_C_SOURCE > 2)  || defined(_XPG4_2) */

#if (!defined(_XPG4_2) || (_POSIX_C_SOURCE > 2)) || defined(__EXTENSIONS__)
extern int mlockall(int);
extern int munlockall(void);
extern int shm_open(const char *, int, mode_t);
extern int shm_unlink(const char *);
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
extern int posix_madvise(void *, size_t, int);
#endif

/* mmap failure value */
#define	MAP_FAILED	((void *) -1)


#endif	/* !_ASM && !_KERNEL */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#if !defined(_ASM)
/*
 * structure for memcntl hat advise operations.
 */
struct memcntl_mha {
	uint_t 		mha_cmd;	/* command(s) */
	uint_t		mha_flags;
	size_t		mha_pagesize;
};

#if defined(_SYSCALL32)
struct memcntl_mha32 {
	uint_t 		mha_cmd;	/* command(s) */
	uint_t		mha_flags;
	size32_t	mha_pagesize;
};
#endif	/* _SYSCALL32 */
#endif	/* !defined(_ASM) */
#endif	/* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#if	(_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * advice to madvise
 *
 * Note, if more than 4 bits worth of advice (eg. 16) are specified then
 * changes will be necessary to the struct vpage.
 */
#define	MADV_NORMAL		0	/* no further special treatment */
#define	MADV_RANDOM		1	/* expect random page references */
#define	MADV_SEQUENTIAL		2	/* expect sequential page references */
#define	MADV_WILLNEED		3	/* will need these pages */
#define	MADV_DONTNEED		4	/* don't need these pages */
#define	MADV_FREE		5	/* contents can be freed */
#define	MADV_ACCESS_DEFAULT	6	/* default access */
#define	MADV_ACCESS_LWP		7	/* next LWP to access heavily */
#define	MADV_ACCESS_MANY	8	/* many processes to access heavily */
#define	MADV_PURGE		9	/* contents will be purged */

#endif	/* (_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2) ...  */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
/* advice to posix_madvise */
/* these values must be kept in sync with the MADV_* values, above */
#define	POSIX_MADV_NORMAL	0	/* MADV_NORMAL */
#define	POSIX_MADV_RANDOM	1	/* MADV_RANDOM */
#define	POSIX_MADV_SEQUENTIAL	2	/* MADV_SEQUENTIAL */
#define	POSIX_MADV_WILLNEED	3	/* MADV_WILLNEED */
#define	POSIX_MADV_DONTNEED	4	/* MADV_DONTNEED */
#endif

/* flags to msync */
#define	MS_OLDSYNC	0x0		/* old value of MS_SYNC */
					/* modified for UNIX98 compliance */
#define	MS_SYNC		0x4		/* wait for msync */
#define	MS_ASYNC	0x1		/* return immediately */
#define	MS_INVALIDATE	0x2		/* invalidate caches */

#if	(_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2) || defined(__EXTENSIONS__)
/* functions to mctl */
#define	MC_SYNC		1		/* sync with backing store */
#define	MC_LOCK		2		/* lock pages in memory */
#define	MC_UNLOCK	3		/* unlock pages from memory */
#define	MC_ADVISE	4		/* give advice to management */
#define	MC_LOCKAS	5		/* lock address space in memory */
#define	MC_UNLOCKAS	6		/* unlock address space from memory */
#define	MC_HAT_ADVISE	7		/* advise hat map size */
#define	MC_INHERIT_ZERO	8		/* zero out regions on fork() */

/* sub-commands for MC_HAT_ADVISE */
#define	MHA_MAPSIZE_VA		0x1	/* set preferred page size */
#define	MHA_MAPSIZE_BSSBRK	0x2	/* set preferred page size */
					/* for last bss adjacent to */
					/* brk area and brk area itself */
#define	MHA_MAPSIZE_STACK	0x4	/* set preferred page size */
					/* processes main stack */

#endif	/* (_POSIX_C_SOURCE <= 2) && !defined(_XPG4_2) ... */

#if (!defined(_XPG4_2) || (_POSIX_C_SOURCE > 2)) || defined(__EXTENSIONS__)
/* flags to mlockall */
#define	MCL_CURRENT	0x1		/* lock current mappings */
#define	MCL_FUTURE	0x2		/* lock future mappings */
#endif /* (!defined(_XPG4_2) || (_POSIX_C_SOURCE)) || defined(__EXTENSIONS__) */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

/* definitions for meminfosys syscall */
#define	MISYS_MEMINFO		0x0

#if !defined(_ASM)

#if defined(_INT64_TYPE)
/* private structure for meminfo */
typedef struct meminfo {
	const uint64_t *mi_inaddr;	/* array of input addresses */
	const uint_t *mi_info_req;	/* array of types of info requested */
	uint64_t *mi_outdata;		/* array of results are placed */
	uint_t *mi_validity;		/* array of bitwise result codes */
	int mi_info_count;		/* number of pieces of info requested */
} meminfo_t;
#endif /* defined(_INT64_TYPE) */

#if defined(_SYSCALL32)
typedef struct meminfo32 {
	caddr32_t mi_inaddr;	/* array of input addresses */
	caddr32_t mi_info_req;	/* array of types of information requested */
	caddr32_t mi_outdata;	/* array of results are placed */
	caddr32_t mi_validity;	/* array of bitwise result codes */
	int32_t mi_info_count;	/* number of pieces of information requested */
} meminfo32_t;
#endif /* defined(_SYSCALL32) */

#endif /* !defined(_ASM) */

/*
 * info_req request type definitions for meminfo
 * request types starting with MEMINFO_V are used for Virtual addresses
 * and should not be mixed with MEMINFO_PLGRP which is targeted for Physical
 * addresses
 */
#define	MEMINFO_SHIFT		16
#define	MEMINFO_MASK		(0xFF << MEMINFO_SHIFT)
#define	MEMINFO_VPHYSICAL	(0x01 << MEMINFO_SHIFT)	/* get physical addr */
#define	MEMINFO_VLGRP		(0x02 << MEMINFO_SHIFT) /* get lgroup */
#define	MEMINFO_VPAGESIZE	(0x03 << MEMINFO_SHIFT) /* size of phys page */
#define	MEMINFO_VREPLCNT	(0x04 << MEMINFO_SHIFT) /* no. of replica */
#define	MEMINFO_VREPL		(0x05 << MEMINFO_SHIFT) /* physical replica */
#define	MEMINFO_VREPL_LGRP	(0x06 << MEMINFO_SHIFT) /* lgrp of replica */
#define	MEMINFO_PLGRP		(0x07 << MEMINFO_SHIFT) /* lgroup for paddr */

/* maximum number of addresses meminfo() can process at a time */
#define	MAX_MEMINFO_CNT	256

/* maximum number of request types */
#define	MAX_MEMINFO_REQ	31

#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MMAN_H */
