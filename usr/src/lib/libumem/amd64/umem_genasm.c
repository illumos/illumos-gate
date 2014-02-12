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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * Don't Panic! If you find the blocks of assembly that follow confusing and
 * you're questioning why they exist, please go read section 8 of the umem.c big
 * theory statement. Next familiarize yourself with the malloc and free
 * implementations in libumem's malloc.c.
 *
 * What follows is the amd64 implementation of the thread caching automatic
 * assembly generation. The amd64 calling conventions are documented in the
 * 64-bit System V ABI. For our purposes what matters is that our first argument
 * will come in rdi. Our functions have to preserve rbp, rbx, and r12->r15. We
 * are free to do whatever we want with rax, rcx, rdx, rsi, rdi, and r8->r11.
 *
 * For both our implementation of malloc and free we only use the registers we
 * don't have to preserve.
 *
 * Malloc register usage:
 * 	o. rdi: Original size to malloc. This never changes and is preserved.
 * 	o. rsi: Adjusted malloc size for malloc_data_tag(s).
 * 	o. rcx: Pointer to the tmem_t in the ulwp_t.
 * 	o. rdx: Pointer to the tmem_t array of roots
 * 	o. r8:  Size of the cache
 * 	o. r9:  Scratch register
 *
 * Free register usage:
 *	o. rdi: Original buffer to free. This never changes and is preserved.
 *	o. rax: The actual buffer, adjusted for the hidden malloc_data_t(s).
 * 	o. rcx: Pointer to the tmem_t in the ulwp_t.
 * 	o. rdx: Pointer to the tmem_t array of roots
 * 	o. r8:  Size of the cache
 * 	o. r9:  Scratch register
 *
 * Once we determine what cache we are using, we increment %rdx to the
 * appropriate offset and set %r8 with the size of the cache. This means that
 * when we break out to the normal buffer allocation point %rdx contains the
 * head of the linked list and %r8 is the amount that we have to adjust the
 * thread's cached amount by.
 *
 * Each block of assembly has psuedocode that describes its purpose.
 */

#include <atomic.h>
#include <inttypes.h>
#include <sys/types.h>
#include <strings.h>
#include <umem_impl.h>
#include "umem_base.h"

#include <stdio.h>

const int umem_genasm_supported = 1;
static uintptr_t umem_genasm_mptr = (uintptr_t)&_malloc;
static size_t umem_genasm_msize = 576;
static uintptr_t umem_genasm_fptr = (uintptr_t)&_free;
static size_t umem_genasm_fsize = 576;
static uintptr_t umem_genasm_omptr = (uintptr_t)umem_malloc;
static uintptr_t umem_genasm_ofptr = (uintptr_t)umem_malloc_free;

#define	UMEM_GENASM_MAX64	(UINT32_MAX / sizeof (uintptr_t))
#define	PTC_JMPADDR(dest, src)	(dest - (src + 4))
#define	PTC_ROOT_SIZE	sizeof (uintptr_t)
#define	MULTINOP	0x0000441f0f

/*
 * void *ptcmalloc(size_t orig_size);
 *
 * size_t size = orig_size + 8;
 * if (size > UMEM_SECOND_ALIGN)
 * 	size += 8;
 *
 * if (size < orig_size)
 * 	goto tomalloc;		! This is overflow
 *
 * if (size > cache_max)
 * 	goto tomalloc
 *
 * tmem_t *t = (uintptr_t)curthread() + umem_thr_offset;
 * void **roots = t->tm_roots;
 */
#define	PTC_MALINIT_JOUT	0x13
#define	PTC_MALINIT_MCS	0x1a
#define	PTC_MALINIT_JOV	0x20
#define	PTC_MALINIT_SOFF	0x30
static const uint8_t malinit[] =  {
	0x48, 0x8d, 0x77, 0x08,		/* leaq 0x8(%rdi),%rsi */
	0x48, 0x83, 0xfe, 0x10,		/* cmpq $0x10, %rsi */
	0x76, 0x04,			/* jbe +0x4 */
	0x48, 0x8d, 0x77, 0x10,		/* leaq 0x10(%rdi),%rsi */
	0x48, 0x39, 0xfe,		/* cmpq %rdi,%rsi */
	0x0f, 0x82, 0x00, 0x00, 0x00, 0x00,	/* jb +errout */
	0x48, 0x81, 0xfe,
	0x00, 0x00, 0x00, 0x00,		/* cmpq sizeof ($CACHE), %rsi */
	0x0f, 0x87, 0x00, 0x00, 0x00, 0x00,	/* ja +errout */
	0x64, 0x48, 0x8b, 0x0c, 0x25,
	0x00, 0x00, 0x00, 0x00,		/* movq %fs:0x0,%rcx */
	0x48, 0x81, 0xc1,
	0x00, 0x00, 0x00, 0x00,		/* addq $SOFF, %rcx */
	0x48, 0x8d, 0x51, 0x08,		/* leaq 0x8(%rcx),%rdx */
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
 * int tagval = UMEM_MALLOC_DECODE(tag->malloc_tag, size);
 * if (tagval == MALLOC_SECOND_MAGIC) {
 * 	tag--;
 * } else if (tagval != MALLOC_MAGIC) {
 * 	goto tofree;
 * }
 *
 * if (size > cache_max)
 * 	goto tofree;
 *
 * tmem_t *t = (uintptr_t)curthread() + umem_thr_offset;
 * void **roots = t->tm_roots;
 */
#define	PTC_FRINI_JDONE	0x05
#define	PTC_FRINI_JFREE	0x25
#define	PTC_FRINI_MCS	0x30
#define	PTC_FRINI_JOV	0x36
#define	PTC_FRINI_SOFF	0x46
static const uint8_t freeinit[] = {
	0x48, 0x85, 0xff,		/* testq %rdi,%rdi */
	0x0f, 0x84, 0x00, 0x00, 0x00, 0x00,	/* jmp $JDONE (done) */
	0x8b, 0x77, 0xf8,		/* movl -0x8(%rdi),%esi */
	0x8b, 0x47, 0xfc,		/* movl -0x4(%rdi),%eax */
	0x01, 0xf0,			/* addl %esi,%eax */
	0x3d, 0x00, 0x70, 0xba, 0x16,	/* cmpl $MALLOC_2_MAGIC, %eax */
	0x75, 0x06,			/* jne +0x6 (checkover) */
	0x48, 0x8d, 0x47, 0xf0,		/* leaq -0x10(%rdi),%eax */
	0xeb, 0x0f,			/* jmp +0xf (freebuf) */
	0x3d, 0x00, 0xc0, 0x10, 0x3a,	/* cmpl $MALLOC_MAGIC, %eax */
	0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,	/* jmp +JFREE (goto torfree) */
	0x48, 0x8d, 0x47, 0xf8,		/* leaq -0x8(%rdi),%rax */
	0x48, 0x81, 0xfe,
	0x00, 0x00, 0x00, 0x00,		/* cmpq sizeof ($CACHE), %rsi */
	0x0f, 0x87, 0x00, 0x00, 0x00, 0x00,	/* ja +errout */
	0x64, 0x48, 0x8b, 0x0c, 0x25,
	0x00, 0x00, 0x00, 0x00,		/* movq %fs:0x0,%rcx */
	0x48, 0x81, 0xc1,
	0x00, 0x00, 0x00, 0x00,		/* addq $SOFF, %rcx */
	0x48, 0x8d, 0x51, 0x08,		/* leaq 0x8(%rcx),%rdx */
};

/*
 * if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 * } else ...				! goto next cache
 */
#define	PTC_INICACHE_CMP	0x03
#define	PTC_INICACHE_SIZE	0x0c
#define	PTC_INICACHE_JMP	0x11
static const uint8_t inicache[] = {
	0x48, 0x81, 0xfe,
	0x00, 0x00, 0x00, 0x00,		/* cmpq sizeof ($CACHE), %rsi */
	0x77, 0x0c,			/* ja +0xc (next cache) */
	0x49, 0xc7, 0xc0,
	0x00, 0x00, 0x00, 0x00,		/* movq sizeof ($CACHE), %r8 */
	0xe9, 0x00, 0x00, 0x00, 0x00,	/* jmp $JMP (allocbuf) */
};

/*
 * if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 *	roots += $CACHE_NUM;
 * } else ...				! goto next cache
 */
#define	PTC_GENCACHE_CMP	0x03
#define	PTC_GENCACHE_SIZE	0x0c
#define	PTC_GENCACHE_NUM	0x13
#define	PTC_GENCACHE_JMP	0x18
static const uint8_t gencache[] = {
	0x48, 0x81, 0xfe,
	0x00, 0x00, 0x00, 0x00,		/* cmpq sizeof ($CACHE), %rsi */
	0x77, 0x14,			/* ja +0xc (next cache) */
	0x49, 0xc7, 0xc0,
	0x00, 0x00, 0x00, 0x00,		/* movq sizeof ($CACHE), %r8 */
	0x48, 0x81, 0xc2,
	0x00, 0x00, 0x00, 0x00,		/* addq $8*ii, %rdx */
	0xe9, 0x00, 0x00, 0x00, 0x00	/* jmp +$JMP (allocbuf ) */
};

/*
 * else if (size <= $CACHE_SIZE) {
 *	csize = $CACHE_SIZE;
 *	roots += $CACHE_NUM;
 * } else {
 *	goto tofunc; 			! goto tomalloc if ptcmalloc.
 * }					! goto tofree if ptcfree.
 */
#define	PTC_FINCACHE_CMP	0x03
#define	PTC_FINCACHE_JMP	0x08
#define	PTC_FINCACHE_SIZE	0x0c
#define	PTC_FINCACHE_NUM	0x13
static const uint8_t fincache[] = {
	0x48, 0x81, 0xfe,
	0x00, 0x00, 0x00, 0x00,		/* cmpq sizeof ($CACHE), %rsi */
	0x77, 0x00,			/* ja +JMP (to real malloc) */
	0x49, 0xc7, 0xc0,
	0x00, 0x00, 0x00, 0x00,		/* movq sizeof ($CACHE), %r8 */
	0x48, 0x81, 0xc2,
	0x00, 0x00, 0x00, 0x00,		/* addq $8*ii, %rdx */

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
 * if (size > UMEM_SECOND_ALIGN) {
 *	ret->malloc_data = UMEM_MALLOC_ENCODE(MALLOC_SECOND_MAGIC, size);
 *	ret += 2;
 * } else {
 *	ret->malloc_data = UMEM_MALLOC_ENCODE(MALLOC_SECOND_MAGIC, size);
 *	ret += 1;
 * }
 *
 * return ((void *)ret);
 * tomalloc:
 * 	return (malloc(orig_size));
 */
#define	PTC_MALFINI_ALLABEL	0x00
#define	PTC_MALFINI_JMLABEL	0x40
#define	PTC_MALFINI_JMADDR	0x41
static const uint8_t malfini[] = {
	0x48, 0x8b, 0x02,		/* movl (%rdx),%rax */
	0x48, 0x85, 0xc0,		/* testq %rax,%rax */
	0x74, 0x38,			/* je +0x38 (errout) */
	0x4c, 0x8b, 0x08,		/* movq (%rax),%r9 */
	0x4c, 0x89, 0x0a,		/* movq %r9,(%rdx) */
	0x4c, 0x29, 0x01,		/* subq %rsi,(%rcx) */
	0x48, 0x83, 0xfe, 0x10,		/* cmpq $0x10,%rsi */
	0x76, 0x15,			/* jbe +0x15 */
	0x41, 0xb9, 0x00, 0x70, 0xba, 0x16, /* movl $MALLOC_MAGIC_2, %r9d */
	0x89, 0x70, 0x08,		/* movl %r9d,0x8(%rax) */
	0x41, 0x29, 0xf1,		/* subl %esi, %r9d */
	0x44, 0x89, 0x48, 0x0c,		/* movl %r9d, 0xc(%rax) */
	0x48, 0x83, 0xc0, 0x10,		/* addq $0x10, %rax */
	0xc3,				/* ret */
	0x41, 0xb9, 0x00, 0xc0, 0x10, 0x3a,	/* movl %MALLOC_MAGIC, %r9d */
	0x89, 0x30,			/* movl %esi,(%rax) */
	0x41, 0x29, 0xf1,		/* subl %esi,%r9d */
	0x44, 0x89, 0x48, 0x04,		/* movl %r9d,0x4(%rax) */
	0x48, 0x83, 0xc0, 0x08,		/* addq $0x8,%rax */
	0xc3,				/* ret */
	0xe9, 0x00, 0x00, 0x00, 0x00	/* jmp $MALLOC */
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
#define	PTC_FRFINI_CACHEMAX	0x09
#define	PTC_FRFINI_DONELABEL	0x1b
#define	PTC_FRFINI_JFLABEL	0x1c
#define	PTC_FRFINI_JFADDR	0x1d
static const uint8_t freefini[] = {
	0x4c, 0x8b, 0x09,		/* movq (%rcx),%r9 */
	0x4d, 0x01, 0xc1,		/* addq %r8, %r9 */
	0x49, 0x81, 0xf9,
	0x00, 0x00, 0x00, 0x00,		/* cmpl $THR_CACHE_MAX, %r9 */
	0x77, 0x0d,			/* jae +0xd (torfree) */
	0x4c, 0x01, 0x01,		/* addq %r8,(%rcx) */
	0x4c, 0x8b, 0x0a,		/* movq (%rdx),%r9 */
	0x4c, 0x89, 0x08,		/* movq %r9,(%rax) */
	0x48, 0x89, 0x02,		/* movq %rax,(%rdx) */
	0xc3,				/* ret */
	0xe9, 0x00, 0x00, 0x00, 0x00	/* jmp free */
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
genasm_frinit(uint8_t *bp, uint32_t off, uint32_t dp, uint32_t ep, uint32_t mcs)
{
	uint32_t addr;

	bcopy(freeinit, bp, sizeof (freeinit));
	addr = PTC_JMPADDR(dp, PTC_FRINI_JDONE);
	bcopy(&addr, bp + PTC_FRINI_JDONE, sizeof (addr));
	addr = PTC_JMPADDR(ep, PTC_FRINI_JFREE);
	bcopy(&addr, bp + PTC_FRINI_JFREE, sizeof (addr));
	bcopy(&mcs, bp + PTC_FRINI_MCS, sizeof (mcs));
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
	uint32_t coff;

	ASSERT(UINT32_MAX / PTC_ROOT_SIZE > num);
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
	uint8_t eap;
	uint32_t coff;

	ASSERT(ep <= 0xff && ep > 7);
	ASSERT(UINT32_MAX / PTC_ROOT_SIZE > num);
	bcopy(fincache, bp, sizeof (fincache));
	bcopy(&csize, bp + PTC_FINCACHE_CMP, sizeof (csize));
	bcopy(&csize, bp + PTC_FINCACHE_SIZE, sizeof (csize));
	coff = num * PTC_ROOT_SIZE;
	bcopy(&coff, bp + PTC_FINCACHE_NUM, sizeof (coff));
	eap = ep - PTC_FINCACHE_JMP - 1;
	bcopy(&eap, bp + PTC_FINCACHE_JMP, sizeof (eap));

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

/*ARGSUSED*/
int
umem_genasm(int *cp, umem_cache_t **caches, int nc)
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
	 *  o we use a single byte addl, so it's MAX_UINT32 / sizeof (uintptr_t)
	 *    For 64-bit, this is MAX_UINT32 >> 3, a lot.
	 */
	nents = _tmem_get_nentries();

	if (UMEM_GENASM_MAX64 < nents)
		nents = UMEM_GENASM_MAX64;

	if (nc < nents)
		nents = nc;

	/* Based on our constraints, this is not an error */
	if (nents == 0 || umem_ptc_size == 0)
		return (0);

	/* Take into account the jump */
	if (genasm_malloc(mptr, umem_genasm_msize, nents, cp) != 0)
		return (1);

	if (genasm_free(fptr, umem_genasm_fsize, nents, cp) != 0)
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
