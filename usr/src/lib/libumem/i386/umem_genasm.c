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
/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Don't Panic! If you find the blocks of assembly that follow confusing and
 * you're questioning why they exist, please go read section 8 of the umem.c big
 * theory statement. Next familiarize yourself with the malloc and free
 * implementations in libumem's malloc.c.
 *
 * What follows is the i386 implementation of the thread caching automatic
 * assembly generation. With i386 a function only has three registers it's
 * allowed to change without restoring them: eax, ecx, and edx. All others have
 * to be preserved. Since the set of registers we have available is so small, we
 * have to make use of esi, ebx, and edi and save their original values to the
 * stack.
 *
 * Malloc register usage:
 * 	o. esi: Size of the malloc (passed into us and modified)
 * 	o. edi: Size of the cache
 * 	o. eax: Buffer to return
 * 	o. ebx: Scratch space and temporary values
 * 	o. ecx: Pointer to the tmem_t in the ulwp_t.
 * 	o. edx: Pointer to the tmem_t array of roots
 *
 * Free register usage:
 * 	o. esi: Size of the malloc (passed into us and modified)
 * 	o. edi: Size of the cache
 * 	o. eax: Buffer to free
 * 	o. ebx: Scratch space and temporary values
 * 	o. ecx: Pointer to the tmem_t in the ulwp_t.
 * 	o. edx: Pointer to the tmem_t array of roots
 *
 * Once we determine what cache we are using, we increment %edx to the
 * appropriate offset and set %edi with the size of the cache. This means that
 * when we break out to the normal buffer allocation point %edx contains the
 * head of the linked list and %edi is the amount that we have to adjust the
 * total amount cached by the thread.
 *
 * Each block of assembly has psuedocode that describes its purpose.
 */

#include <inttypes.h>
#include <strings.h>
#include <umem_impl.h>
#include "umem_base.h"

#include <atomic.h>

const int umem_genasm_supported = 1;
static uintptr_t umem_genasm_mptr = (uintptr_t)&_malloc;
static size_t umem_genasm_msize = 512;
static uintptr_t umem_genasm_fptr = (uintptr_t)&_free;
static size_t umem_genasm_fsize = 512;
static uintptr_t umem_genasm_omptr = (uintptr_t)umem_malloc;
static uintptr_t umem_genasm_ofptr = (uintptr_t)umem_malloc_free;
/*
 * The maximum number of caches we can support. We use a single byte addl so
 * this is 255 (UINT8_MAX) / sizeof (uintptr_t). In this case 63
 */
#define	UMEM_GENASM_MAX32	63

#define	PTC_JMPADDR(dest, src)	(dest - (src + 4))
#define	PTC_ROOT_SIZE	sizeof (uintptr_t)
#define	MULTINOP	0x0000441f0f

/*
 * void *ptcmalloc(size_t orig_size);
 *
 * size_t size = orig_size + 8;
 *
 * if (size < orig_size)
 * 	goto tomalloc;		! This is overflow
 *
 * if (size > cache_size)
 * 	goto tomalloc;
 *
 * tmem_t *t = (uintptr_t)curthread() + umem_thr_offset;
 * void **roots = t->tm_roots;
 */
#define	PTC_MALINIT_JOUT	0x0e
#define	PTC_MALINIT_MCS	0x14
#define	PTC_MALINIT_JOV	0x1a
#define	PTC_MALINIT_SOFF	0x27
static const uint8_t malinit[] = {
	0x55,					/* pushl %ebp */
	0x89, 0xe5,				/* movl %esp, %ebp */
	0x57,					/* pushl %edi */
	0x56,					/* pushl %esi */
	0x53,					/* pushl %ebx */
	0x8b, 0x75, 0x08,			/* movl 0x8(%ebp), %esi */
	0x83, 0xc6, 0x08,			/* addl $0x8,%esi */
	0x0f, 0x82, 0x00, 0x00, 0x00, 0x00, 	/* jc +$JMP (errout) */
	0x81, 0xfe, 0x00, 0x00, 0x00, 0x00, 	/* cmpl sizeof ($C0), %esi */
	0x0f, 0x87, 0x00, 0x00, 0x00, 0x00,	/* ja +$JMP (errout) */
	0x65, 0x8b, 0x0d, 0x00, 0x00, 0x00, 0x00, 	/* movl %gs:0x0,%ecx */
	0x81, 0xc1, 0x00, 0x00,	0x00, 0x00, 	/* addl $OFF, %ecx */
	0x8d, 0x51, 0x04			/* leal 0x4(%ecx), %edx */
};

/*
 * void ptcfree(void *buf);
 *
 * if (buf == NULL)
 * 	return;
 *
 * malloc_data_t *tag = buf;
 * tag--;
 * int size = tag->malloc_size;
 * int tagtval = UMEM_MALLOC_DECODE(tag->malloc_tag, size);
 *
 * if (tagval != MALLOC_MAGIC)
 * 	goto tofree;
 *
 * if (size > cache_max)
 * 	goto tofree;
 *
 * tmem_t *t = (uintptr_t)curthread() + umem_thr_offset;
 * void **roots = t->tm_roots;
 */
#define	PTC_FRINI_JDONE	0x0d
#define	PTC_FRINI_JFREE	0x23
#define	PTC_FRINI_MCS	0x29
#define	PTC_FRINI_JOV	0x2f
#define	PTC_FRINI_SOFF	0x3c
static const uint8_t freeinit[] = {
	0x55,					/* pushl %ebp */
	0x89, 0xe5,				/* movl %esp, %ebp */
	0x57,					/* pushl %edi */
	0x56,					/* pushl %esi */
	0x53,					/* pushl %ebx */
	0x8b, 0x45, 0x08,			/* movl 0x8(%ebp), %eax */
	0x85, 0xc0,				/* testl %eax, %eax */
	0x0f, 0x84, 0x00, 0x00, 0x00, 0x00,	/* je $JDONE (done) */
	0x83, 0xe8, 0x08,			/* subl $0x8,%eax */
	0x8b, 0x30,				/* movl (%eax),%esi */
	0x8b, 0x50, 0x04,			/* movl 0x4(%eax),%edx */
	0x01, 0xf2,				/* addl %esi,%edx */
	0x81, 0xfa, 0x00, 0xc0, 0x10, 0x3a,	/* cmpl MAGIC32, %edx */
	0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,	/* jne +JFREE (goto freebuf) */

	0x81, 0xfe, 0x00, 0x00, 0x00, 0x00, 	/* cmpl sizeof ($C0), %esi */
	0x0f, 0x87, 0x00, 0x00, 0x00, 0x00,	/* ja +$JMP (errout) */
	0x65, 0x8b, 0x0d, 0x00, 0x0, 0x00, 0x00, /* movl %gs:0x0,%ecx */
	0x81, 0xc1, 0x00, 0x00,	0x00, 0x00,	/* addl $0xOFF, %ecx */
	0x8d, 0x51, 0x04			/* leal 0x4(%ecx),%edx */
};

/*
 * if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 * } else ...				! goto next cache
 */
#define	PTC_INICACHE_CMP	0x02
#define	PTC_INICACHE_SIZE 0x09
#define	PTC_INICACHE_JMP	0x0e
static const uint8_t inicache[] = {
	0x81, 0xfe, 0xff, 0x00, 0x00, 0x00, 	/* cmpl sizeof ($C0), %esi */
	0x77, 0x0a,				/* ja +0xa */
	0xbf, 0xff, 0x00, 0x00, 0x00, 		/* movl sizeof ($C0), %edi */
	0xe9, 0x00, 0x00, 0x00, 0x00		/* jmp +$JMP (allocbuf) */
};

/*
 * if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 *	roots += $CACHE_NUM;
 * } else ...				! goto next cache
 */
#define	PTC_GENCACHE_CMP	0x02
#define	PTC_GENCACHE_NUM	0x0a
#define	PTC_GENCACHE_SIZE 0x0c
#define	PTC_GENCACHE_JMP	0x11
static const uint8_t gencache[] = {
	0x81, 0xfe, 0x00, 0x00, 0x00, 0x00, 	/* cmpl sizeof ($CACHE), %esi */
	0x77, 0x0d,				/* ja +0xd (next cache) */
	0x83, 0xc2, 0x00,			/* addl $4*$ii, %edx */
	0xbf, 0x00, 0x00, 0x00, 0x00, 		/* movl sizeof ($CACHE), %edi */
	0xe9, 0x00, 0x00, 0x00, 0x00 		/* jmp +$JMP (allocbuf) */
};

/*
 * else if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 *	roots += $CACHE_NUM;
 * } else {
 *	goto tofunc; 			! goto tomalloc if ptcmalloc.
 * }					! goto tofree if ptcfree.
 */
#define	PTC_FINCACHE_CMP 0x02
#define	PTC_FINCACHE_JMP	0x07
#define	PTC_FINCACHE_NUM 0x0a
#define	PTC_FINCACHE_SIZE 0x0c
static const uint8_t fincache[] = {
	0x81, 0xfe, 0xff, 0x00, 0x00, 0x00,	/* cmpl sizeof ($CLAST), %esi */
	0x77, 0x00,				/* ja +$JMP (to errout) */
	0x83, 0xc2, 0x00,			/* addl $4*($NCACHES-1), %edx */
	0xbf, 0x00, 0x00, 0x00, 0x00, 		/* movl sizeof ($CLAST), %edi */
};

/*
 * if (*root == NULL)
 * 	goto tomalloc;
 *
 * malloc_data_t *ret = *root;
 * *root = *(void **)ret;
 * t->tm_size += csize;
 * ret->malloc_size = size;
 *
 * ret->malloc_data = UMEM_MALLOC_ENCODE(MALLOC_SECOND_MAGIC, size);
 * ret++;
 *
 * return ((void *)ret);
 * tomalloc:
 * 	return (malloc(orig_size));
 */
#define	PTC_MALFINI_ALLABEL	0x00
#define	PTC_MALFINI_JMLABEL	0x20
#define	PTC_MALFINI_JMADDR	0x25
static const uint8_t malfini[] = {
	/* allocbuf: */
	0x8b, 0x02,			/* movl (%edx), %eax */
	0x85, 0xc0,			/* testl %eax, %eax */
	0x74, 0x1a,			/* je +0x1a (errout) */
	0x8b, 0x18,			/* movl (%eax), %esi */
	0x89, 0x1a,			/* movl %esi, (%edx) */
	0x29, 0x39,			/* subl %edi, (%ecx) */
	0x89, 0x30,			/* movl %esi, ($eax) */
	0xba, 0x00, 0xc0, 0x10, 0x3a,	/* movl $0x3a10c000,%edx */
	0x29, 0xf2,			/* subl %esi, %edx */
	0x89, 0x50, 0x04,		/* movl %edx, 0x4(%eax) */
	0x83, 0xc0, 0x08,		/* addl %0x8, %eax */
	0x5b,				/* popl %ebx */
	0x5e,				/* popl %esi */
	0x5f,				/* popl %edi */
	0xc9,				/* leave */
	0xc3,				/* ret */
	/* errout: */
	0x5b,				/* popl %ebx */
	0x5e,				/* popl %esi */
	0x5f,				/* popl %edi */
	0xc9,				/* leave */
	0xe9, 0x00, 0x00, 0x00, 0x00	/* jmp $malloc */
};

/*
 * if (t->tm_size + csize > umem_ptc_size)
 * 	goto tofree;
 *
 * t->tm_size += csize
 * *(void **)tag = *root;
 * *root = tag;
 * return;
 * tofree:
 * 	free(buf);
 * 	return;
 */
#define	PTC_FRFINI_RBUFLABEL	0x00
#define	PTC_FRFINI_CACHEMAX	0x06
#define	PTC_FRFINI_DONELABEL	0x14
#define	PTC_FRFINI_JFLABEL	0x19
#define	PTC_FRFINI_JFADDR	0x1e
static const uint8_t freefini[] = {
	/* freebuf: */
	0x8b, 0x19,				/* movl (%ecx),%ebx */
	0x01, 0xfb,				/* addl %edi,%ebx */
	0x81, 0xfb, 0x00, 0x00, 0x00, 0x00, 	/* cmpl maxsize, %ebx */
	0x73, 0x0d,				/* jae +0xd <tofree> */
	0x01, 0x39,				/* addl %edi,(%ecx) */
	0x8b, 0x3a,				/* movl (%edx),%edi */
	0x89, 0x38,				/* movl %edi,(%eax) */
	0x89, 0x02,				/* movl %eax,(%edx) */
	/* done: */
	0x5b,					/* popl %ebx */
	0x5e,					/* popl %esi */
	0x5f,					/* popl %edi */
	0xc9,					/* leave */
	0xc3,					/* ret */
	/* realfree: */
	0x5b,					/* popl %ebx */
	0x5e,					/* popl %esi */
	0x5f,					/* popl %edi */
	0xc9,					/* leave */
	0xe9, 0x00, 0x00, 0x00, 0x00		/* jmp free */
};

/*
 * Construct the initial part of malloc. off contains the offset from curthread
 * to the root of the tmem structure. ep is the address of the label to error
 * and jump to free. csize is the size of the largest umem_cache in ptcumem.
 */
static int
genasm_malinit(uint8_t *bp, uint32_t off, uint32_t ep, uint32_t csize)
{
	uint32_t addr;

	bcopy(malinit, bp, sizeof (malinit));
	addr = PTC_JMPADDR(ep, PTC_MALINIT_JOUT);
	bcopy(&addr, bp + PTC_MALINIT_JOUT, sizeof (addr));
	bcopy(&csize, bp + PTC_MALINIT_MCS, sizeof (csize));
	addr = PTC_JMPADDR(ep, PTC_MALINIT_JOV);
	bcopy(&addr, bp + PTC_MALINIT_JOV, sizeof (addr));
	bcopy(&off, bp + PTC_MALINIT_SOFF, sizeof (off));

	return (sizeof (malinit));
}

static int
genasm_frinit(uint8_t *bp, uint32_t off, uint32_t dp, uint32_t ep, uint32_t mc)
{
	uint32_t addr;

	bcopy(freeinit, bp, sizeof (freeinit));
	addr = PTC_JMPADDR(dp, PTC_FRINI_JDONE);
	bcopy(&addr, bp + PTC_FRINI_JDONE, sizeof (addr));
	addr = PTC_JMPADDR(ep, PTC_FRINI_JFREE);
	bcopy(&addr, bp + PTC_FRINI_JFREE, sizeof (addr));
	bcopy(&mc, bp + PTC_FRINI_MCS, sizeof (mc));
	addr = PTC_JMPADDR(ep, PTC_FRINI_JOV);
	bcopy(&addr, bp + PTC_FRINI_JOV, sizeof (addr));
	bcopy(&off, bp + PTC_FRINI_SOFF, sizeof (off));
	return (sizeof (freeinit));
}

/*
 * Create the initial cache entry of the specified size. The value of ap tells
 * us what the address of the label to try and allocate a buffer. This value is
 * an offset from the current base to that value.
 */
static int
genasm_firstcache(uint8_t *bp, uint32_t csize, uint32_t ap)
{
	uint32_t addr;

	bcopy(inicache, bp, sizeof (inicache));
	bcopy(&csize, bp + PTC_INICACHE_CMP, sizeof (csize));
	bcopy(&csize, bp + PTC_INICACHE_SIZE, sizeof (csize));
	addr = PTC_JMPADDR(ap, PTC_INICACHE_JMP);
	ASSERT(addr != 0);
	bcopy(&addr, bp + PTC_INICACHE_JMP, sizeof (addr));

	return (sizeof (inicache));
}

static int
genasm_gencache(uint8_t *bp, int num, uint32_t csize, uint32_t ap)
{
	uint32_t addr;
	uint8_t	coff;

	ASSERT(256 / PTC_ROOT_SIZE > num);
	ASSERT(num != 0);
	bcopy(gencache, bp, sizeof (gencache));
	bcopy(&csize, bp + PTC_GENCACHE_CMP, sizeof (csize));
	bcopy(&csize, bp + PTC_GENCACHE_SIZE, sizeof (csize));
	coff = num * PTC_ROOT_SIZE;
	bcopy(&coff, bp + PTC_GENCACHE_NUM, sizeof (coff));
	addr = PTC_JMPADDR(ap, PTC_GENCACHE_JMP);
	bcopy(&addr, bp + PTC_GENCACHE_JMP, sizeof (addr));

	return (sizeof (gencache));
}

static int
genasm_lastcache(uint8_t *bp, int num, uint32_t csize, uint32_t ep)
{
	uint8_t addr;

	ASSERT(ep <= 0xff && ep > 7);
	ASSERT(256 / PTC_ROOT_SIZE > num);
	bcopy(fincache, bp, sizeof (fincache));
	bcopy(&csize, bp + PTC_FINCACHE_CMP, sizeof (csize));
	bcopy(&csize, bp + PTC_FINCACHE_SIZE, sizeof (csize));
	addr = num * PTC_ROOT_SIZE;
	bcopy(&addr, bp + PTC_FINCACHE_NUM, sizeof (addr));
	addr = ep - PTC_FINCACHE_JMP - 1;
	bcopy(&addr, bp + PTC_FINCACHE_JMP, sizeof (addr));

	return (sizeof (fincache));
}

static int
genasm_malfini(uint8_t *bp, uintptr_t mptr)
{
	uint32_t addr;

	bcopy(malfini, bp, sizeof (malfini));
	addr = PTC_JMPADDR(mptr, ((uintptr_t)bp + PTC_MALFINI_JMADDR));
	bcopy(&addr, bp + PTC_MALFINI_JMADDR, sizeof (addr));

	return (sizeof (malfini));
}

static int
genasm_frfini(uint8_t *bp, uint32_t maxthr, uintptr_t fptr)
{
	uint32_t addr;

	bcopy(freefini, bp, sizeof (freefini));
	bcopy(&maxthr, bp + PTC_FRFINI_CACHEMAX, sizeof (maxthr));
	addr = PTC_JMPADDR(fptr, ((uintptr_t)bp + PTC_FRFINI_JFADDR));
	bcopy(&addr, bp + PTC_FRFINI_JFADDR, sizeof (addr));

	return (sizeof (freefini));
}

/*
 * The malloc inline assembly is constructed as follows:
 *
 * o Malloc prologue assembly
 * o Generic first-cache check
 * o n Generic cache checks (where n = _tmem_get_entries() - 2)
 * o Generic last-cache check
 * o Malloc epilogue assembly
 *
 * Generally there are at least three caches. When there is only one cache we
 * only use the generic last-cache. In the case where there are two caches, we
 * just leave out the middle ones.
 */
static int
genasm_malloc(void *base, size_t len, int nents, int *umem_alloc_sizes)
{
	int ii, off;
	uint8_t *bp;
	size_t total;
	uint32_t allocoff, erroff;

	total = sizeof (malinit) + sizeof (malfini) + sizeof (fincache);

	if (nents >= 2)
		total += sizeof (inicache) + sizeof (gencache) * (nents - 2);

	if (total > len)
		return (1);

	erroff = total - sizeof (malfini) + PTC_MALFINI_JMLABEL;
	allocoff = total - sizeof (malfini) + PTC_MALFINI_ALLABEL;

	bp = base;

	off = genasm_malinit(bp, umem_tmem_off, erroff,
	    umem_alloc_sizes[nents-1]);
	bp += off;
	allocoff -= off;
	erroff -= off;

	if (nents > 1) {
		off = genasm_firstcache(bp, umem_alloc_sizes[0], allocoff);
		bp += off;
		allocoff -= off;
		erroff -= off;
	}

	for (ii = 1; ii < nents - 1; ii++) {
		off = genasm_gencache(bp, ii, umem_alloc_sizes[ii], allocoff);
		bp += off;
		allocoff -= off;
		erroff -= off;
	}

	bp += genasm_lastcache(bp, nents - 1, umem_alloc_sizes[nents - 1],
	    erroff);
	bp += genasm_malfini(bp, umem_genasm_omptr);
	ASSERT(((uintptr_t)bp - total) == (uintptr_t)base);

	return (0);
}

static int
genasm_free(void *base, size_t len, int nents, int *umem_alloc_sizes)
{
	uint8_t *bp;
	int ii, off;
	size_t total;
	uint32_t rbufoff, retoff, erroff;

	/* Assume that nents has already been audited for us */
	total = sizeof (freeinit) + sizeof (freefini) + sizeof (fincache);
	if (nents >= 2)
		total += sizeof (inicache) + sizeof (gencache) * (nents - 2);

	if (total > len)
		return (1);

	erroff = total - (sizeof (freefini) - PTC_FRFINI_JFLABEL);
	rbufoff = total - (sizeof (freefini) - PTC_FRFINI_RBUFLABEL);
	retoff = total - (sizeof (freefini) - PTC_FRFINI_DONELABEL);

	bp = base;

	off = genasm_frinit(bp, umem_tmem_off, retoff, erroff,
	    umem_alloc_sizes[nents - 1]);
	bp += off;
	erroff -= off;
	rbufoff -= off;

	if (nents > 1) {
		off = genasm_firstcache(bp, umem_alloc_sizes[0], rbufoff);
		bp += off;
		erroff -= off;
		rbufoff -= off;
	}

	for (ii = 1; ii < nents - 1; ii++) {
		off = genasm_gencache(bp, ii, umem_alloc_sizes[ii], rbufoff);
		bp += off;
		rbufoff -= off;
		erroff -= off;
	}

	bp += genasm_lastcache(bp, nents - 1, umem_alloc_sizes[nents - 1],
	    erroff);
	bp += genasm_frfini(bp, umem_ptc_size, umem_genasm_ofptr);
	ASSERT(((uintptr_t)bp - total) == (uintptr_t)base);

	return (0);
}

int
umem_genasm(int *alloc_sizes, umem_cache_t **caches, int ncaches)
{
	int nents, i;
	uint8_t *mptr;
	uint8_t *fptr;
	uint64_t v, *vptr;

	mptr = (void *)((uintptr_t)umem_genasm_mptr + 5);
	fptr = (void *)((uintptr_t)umem_genasm_fptr + 5);
	if (umem_genasm_mptr == 0 || umem_genasm_msize == 0 ||
	    umem_genasm_fptr == 0 || umem_genasm_fsize == 0)
		return (1);

	/*
	 * The total number of caches that we can service is the minimum of:
	 *  o the amount supported by libc
	 *  o the total number of umem caches
	 *  o we use a single byte addl, so it's 255 / sizeof (uintptr_t). For
	 *    32-bit, this is 63.
	 */
	nents = _tmem_get_nentries();

	if (UMEM_GENASM_MAX32 < nents)
		nents = UMEM_GENASM_MAX32;

	if (ncaches < nents)
		nents = ncaches;

	/* Based on our constraints, this is not an error */
	if (nents == 0 || umem_ptc_size == 0)
		return (0);

	/* Take into account the jump */
	if (genasm_malloc(mptr, umem_genasm_msize, nents,
	    alloc_sizes) != 0)
		return (1);

	if (genasm_free(fptr, umem_genasm_fsize, nents,
	    alloc_sizes) != 0)
		return (1);

	/* nop out the jump with a multibyte jump */
	vptr = (void *)umem_genasm_mptr;
	v = MULTINOP;
	v |= *vptr & (0xffffffULL << 40);
	(void) atomic_swap_64(vptr, v);
	vptr = (void *)umem_genasm_fptr;
	v = MULTINOP;
	v |= *vptr & (0xffffffULL << 40);
	(void) atomic_swap_64(vptr, v);

	for (i = 0; i < nents; i++)
		caches[i]->cache_flags |= UMF_PTC;

	return (0);
}
