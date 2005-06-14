/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Cylink Corporation © 1998
 * 
 * This software is licensed by Cylink to the Internet Software Consortium to
 * promote implementation of royalty free public key cryptography within IETF
 * standards.  Cylink wishes to expressly thank the contributions of Dr.
 * Martin Hellman, Whitfield Diffie, Ralph Merkle and Stanford University for
 * their contributions to Internet Security.  In accordance with the terms of
 * this license, ISC is authorized to distribute and sublicense this software
 * for the practice of IETF standards.  
 *
 * The software includes BigNum, written by Colin Plumb and licensed by Philip
 * R. Zimmermann for royalty free use and distribution with Cylink's
 * software.  Use of BigNum as a stand alone product or component is
 * specifically prohibited.
 *
 * Disclaimer of All Warranties. THIS SOFTWARE IS BEING PROVIDED "AS IS",
 * WITHOUT ANY EXPRESSED OR IMPLIED WARRANTY OF ANY KIND WHATSOEVER. IN
 * PARTICULAR, WITHOUT LIMITATION ON THE GENERALITY OF THE FOREGOING, CYLINK
 * MAKES NO REPRESENTATION OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Cylink or its representatives shall not be liable for tort, indirect,
 * special or consequential damages such as loss of profits or loss of
 * goodwill from the use or inability to use the software for any purpose or
 * for any reason whatsoever.
 *
 * EXPORT LAW: Export of the Foundations Suite may be subject to compliance
 * with the rules and regulations promulgated from time to time by the Bureau
 * of Export Administration, United States Department of Commerce, which
 * restrict the export and re-export of certain products and technical data.
 * If the export of the Foundations Suite is controlled under such rules and
 * regulations, then the Foundations Suite shall not be exported or
 * re-exported, directly or indirectly, (a) without all export or re-export
 * licenses and governmental approvals required by any applicable laws, or (b)
 * in violation of any applicable prohibition against the export or re-export
 * of any part of the Foundations Suite. All export licenses for software
 * containing the Foundations Suite are the sole responsibility of the licensee.
 */
 
/*
 * bn32.c - the high-level bignum interface
 *
 * Like lbn32.c, this reserves the string "32" for textual replacement.
 * The string must not appear anywhere unless it is intended to be replaced
 * to generate other bignum interface functions.
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H 0
#endif
#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Some compilers complain about #if FOO if FOO isn't defined,
 * so do the ANSI-mandated thing explicitly...
 */
#ifndef NO_ASSERT_H
#define NO_ASSERT_H 0
#endif
#ifndef NO_STRING_H
#define NO_STRING_H 0
#endif
#ifndef HAVE_STRINGS_H
#define HAVE_STRINGS_H 0
#endif
#ifndef NEED_MEMORY_H
#define NEED_MEMORY_H 0
#endif

#if !NO_ASSERT_H
#include <assert.h>
#else
#define assert(x) (void)0
#endif

#if !NO_STRING_H
#include <string.h>	/* for memmove() in bnMakeOdd */
#elif HAVE_STRINGS_H
#include <strings.h>
#endif
#if NEED_MEMORY_H
#include <memory.h>
#endif

/*
 * This was useful during debugging, so it's left in here.
 * You can ignore it.  DBMALLOC is generally undefined.
 */
#ifndef DBMALLOC
#define DBAMLLOC 0
#endif
#if DBMALLOC
#include "../dbmalloc/malloc.h"
#define MALLOCDB malloc_chain_check(1)
#else
#define MALLOCDB (void)0
#endif

#include "lbn.h"
#include "lbn32.h"
#include "lbnmem.h"
#include "bn32.h"
#include "bn.h"

/* Work-arounds for some particularly broken systems */
#include "kludge.h"	/* For memmove() */
#include <port_after.h>

/* Functions */
void
bnInit_32(void)
{
	bnEnd = bnEnd_32;
	bnPrealloc = bnPrealloc_32;
	bnCopy = bnCopy_32;
	bnNorm = bnNorm_32;
	bnExtractBigBytes = bnExtractBigBytes_32;
	bnInsertBigBytes = bnInsertBigBytes_32;
	bnExtractLittleBytes = bnExtractLittleBytes_32;
	bnInsertLittleBytes = bnInsertLittleBytes_32;
	bnLSWord = bnLSWord_32;
	bnBits = bnBits_32;
	bnAdd = bnAdd_32;
	bnSub = bnSub_32;
	bnCmpQ = bnCmpQ_32;
	bnSetQ = bnSetQ_32;
	bnAddQ = bnAddQ_32;
	bnSubQ = bnSubQ_32;
	bnCmp = bnCmp_32;
	bnSquare = bnSquare_32;
	bnMul = bnMul_32;
	bnMulQ = bnMulQ_32;
	bnDivMod = bnDivMod_32;
	bnMod = bnMod_32;
	bnModQ = bnModQ_32;
	bnExpMod = bnExpMod_32;
	bnDoubleExpMod = bnDoubleExpMod_32;
	bnTwoExpMod = bnTwoExpMod_32;
	bnGcd = bnGcd_32;
	bnInv = bnInv_32;
	bnLShift = bnLShift_32;
	bnRShift = bnRShift_32;
	bnMakeOdd = bnMakeOdd_32;
}

void
bnEnd_32(struct BigNum *bn)
{
	if (bn->ptr) {
		LBNFREE((BNWORD32 *)bn->ptr, bn->allocated);
		bn->ptr = 0;
	}
	bn->size = 0;
	bn->allocated = 0;

	MALLOCDB;
}

/* Internal function.  It operates in words. */
static int
bnResize_32(struct BigNum *bn, unsigned len)
{
	void *p;

	/* Round size up: most mallocs impose 8-byte granularity anyway */
	len = (len + (8/sizeof(BNWORD32) - 1)) & ~(8/sizeof(BNWORD32) - 1);
	p = LBNREALLOC((BNWORD32 *)bn->ptr, bn->allocated, len);
	if (!p)
		return -1;
	bn->ptr = p;
	bn->allocated = len;

	MALLOCDB;

	return 0;
}

#define bnSizeCheck(bn, size) \
	if (bn->allocated < size && bnResize_32(bn, size) < 0) \
		return -1

int
bnPrealloc_32(struct BigNum *bn, unsigned bits)
{
	bits = (bits + 32-1)/32;
	bnSizeCheck(bn, bits);
	MALLOCDB;
	return 0;
}

int
bnCopy_32(struct BigNum *dest, struct BigNum const *src)
{
	bnSizeCheck(dest, src->size);
	dest->size = src->size;
	lbnCopy_32((BNWORD32 *)dest->ptr, (BNWORD32 *)src->ptr, src->size);
	MALLOCDB;
	return 0;
}

void
bnNorm_32(struct BigNum *bn)
{
	bn->size = lbnNorm_32((BNWORD32 *)bn->ptr, bn->size);
}

/*
 * Convert a bignum to big-endian bytes.  Returns, in big-endian form, a
 * substring of the bignum starting from lsbyte and "len" bytes long.
 * Unused high-order (leading) bytes are filled with 0.
 */
void
bnExtractBigBytes_32(struct BigNum const *bn, unsigned char *dest,
                  unsigned lsbyte, unsigned len)
{
	unsigned s = bn->size * (32 / 8);

	/* Fill unused leading bytes with 0 */
	while (s < lsbyte+len) {
		*dest++ = 0;
		len--;
	}

	if (len)
		lbnExtractBigBytes_32((BNWORD32 *)bn->ptr, dest, lsbyte, len);
	MALLOCDB;
}

int
bnInsertBigBytes_32(struct BigNum *bn, unsigned char const *src,
                 unsigned lsbyte, unsigned len)
{
	unsigned s = bn->size;
	unsigned words = (len+lsbyte+sizeof(BNWORD32)-1) / sizeof(BNWORD32);

	/* Pad with zeros as required */
	bnSizeCheck(bn, words);

	if (s < words) {
		lbnZero_32((BNWORD32 *)bn->ptr BIGLITTLE(-s,+s), words-s);
		s = words;
	}

	lbnInsertBigBytes_32((BNWORD32 *)bn->ptr, src, lsbyte, len);

	bn->size = lbnNorm_32((BNWORD32 *)bn->ptr, s);

	MALLOCDB;
	return 0;
}


/*
 * Convert a bignum to little-endian bytes.  Returns, in little-endian form, a
 * substring of the bignum starting from lsbyte and "len" bytes long.
 * Unused high-order (trailing) bytes are filled with 0.
 */
void
bnExtractLittleBytes_32(struct BigNum const *bn, unsigned char *dest,
                  unsigned lsbyte, unsigned len)
{
	unsigned s = bn->size * (32 / 8);

	/* Fill unused leading bytes with 0 */
	while (s < lsbyte+len)
		dest[--len] = 0;

	if (len)
		lbnExtractLittleBytes_32((BNWORD32 *)bn->ptr, dest,
		                         lsbyte, len);
	MALLOCDB;
}

int
bnInsertLittleBytes_32(struct BigNum *bn, unsigned char const *src,
                       unsigned lsbyte, unsigned len)
{
	unsigned s = bn->size;
	unsigned words = (len+lsbyte+sizeof(BNWORD32)-1) / sizeof(BNWORD32);

	/* Pad with zeros as required */
	bnSizeCheck(bn, words);

	if (s < words) {
		lbnZero_32((BNWORD32 *)bn->ptr BIGLITTLE(-s,+s), words-s);
		s = words;
	}

	lbnInsertLittleBytes_32((BNWORD32 *)bn->ptr, src, lsbyte, len);

	bn->size = lbnNorm_32((BNWORD32 *)bn->ptr, s);

	MALLOCDB;
	return 0;
}

/* Return the least-significant word of the input. */
unsigned
bnLSWord_32(struct BigNum const *src)
{
	return src->size ? (unsigned)((BNWORD32 *)src->ptr)[BIGLITTLE(-1,0)]: 0;
}

unsigned
bnBits_32(struct BigNum const *src)
{
	return lbnBits_32((BNWORD32 *)src->ptr, src->size);
}

int
bnAdd_32(struct BigNum *dest, struct BigNum const *src)
{
	unsigned s = src->size, d = dest->size;
	BNWORD32 t;

	if (!s)
		return 0;

	bnSizeCheck(dest, s);

	if (d < s) {
		lbnZero_32((BNWORD32 *)dest->ptr BIGLITTLE(-d,+d), s-d);
		dest->size = d = s;
		MALLOCDB;
	}
	t = lbnAddN_32((BNWORD32 *)dest->ptr, (BNWORD32 *)src->ptr, s);
	MALLOCDB;
	if (t) {
		if (d > s) {
			t = lbnAdd1_32((BNWORD32 *)dest->ptr BIGLITTLE(-s,+s),
			               d-s, t);
			MALLOCDB;
		}
		if (t) {
			bnSizeCheck(dest, d+1);
			((BNWORD32 *)dest->ptr)[BIGLITTLE(-1-d,d)] = t;
			dest->size = d+1;
		}
	}
	return 0;
}

/*
 * dest -= src.
 * If dest goes negative, this produces the absolute value of
 * the difference (the negative of the true value) and returns 1.
 * Otherwise, it returls 0.
 */
int
bnSub_32(struct BigNum *dest, struct BigNum const *src)
{
	unsigned s = src->size, d = dest->size;
	BNWORD32 t;

	if (d < s  &&  d < (s = lbnNorm_32((BNWORD32 *)src->ptr, s))) {
		bnSizeCheck(dest, s);
		lbnZero_32((BNWORD32 *)dest->ptr BIGLITTLE(-d,+d), s-d);
		dest->size = d = s;
		MALLOCDB;
	}
	if (!s)
		return 0;
	t = lbnSubN_32((BNWORD32 *)dest->ptr, (BNWORD32 *)src->ptr, s);
	MALLOCDB;
	if (t) {
		if (d > s) {
			t = lbnSub1_32((BNWORD32 *)dest->ptr BIGLITTLE(-s,+s),
			               d-s, t);
			MALLOCDB;
		}
		if (t) {
			lbnNeg_32((BNWORD32 *)dest->ptr, d);
			dest->size = lbnNorm_32((BNWORD32 *)dest->ptr,
			                        dest->size);
			MALLOCDB;
			return 1;
		}
	}
	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, dest->size);
	return 0;
}

/*
 * Compare the BigNum to the given value, which must be < 65536.
 * Returns -1. 0 or 1 if a<b, a == b or a>b.
 * a <=> b --> bnCmpQ(a,b) <=> 0
 */
int
bnCmpQ_32(struct BigNum const *a, unsigned b)
{
	unsigned t;
	BNWORD32 v;

	t = lbnNorm_32((BNWORD32 *)a->ptr, a->size);
	/* If a is more than one word long or zero, it's easy... */
	if (t != 1)
		return (t > 1) ? 1 : (b ? -1 : 0);
	v = (unsigned)((BNWORD32 *)a->ptr)[BIGLITTLE(-1,0)];
	return (v > b) ? 1 : ((v < b) ? -1 : 0);
}

int
bnSetQ_32(struct BigNum *dest, unsigned src)
{
	if (src) {
		bnSizeCheck(dest, 1);

		((BNWORD32 *)dest->ptr)[BIGLITTLE(-1,0)] = (BNWORD32)src;
		dest->size = 1;
	} else {
		dest->size = 0;
	}
	return 0;
}

int
bnAddQ_32(struct BigNum *dest, unsigned src)
{
	BNWORD32 t;

	if (!dest->size)
		return bnSetQ(dest, src);
	
	t = lbnAdd1_32((BNWORD32 *)dest->ptr, dest->size, (BNWORD32)src);
	MALLOCDB;
	if (t) {
		src = dest->size;
		bnSizeCheck(dest, src+1);
		((BNWORD32 *)dest->ptr)[BIGLITTLE(-1-src,src)] = t;
		dest->size = src+1;
	}
	return 0;
}

/*
 * Return value as for bnSub: 1 if subtract underflowed, in which
 * case the return is the negative of the computed value.
 */
int
bnSubQ_32(struct BigNum *dest, unsigned src)
{
	BNWORD32 t;

	if (!dest->size)
		return bnSetQ(dest, src) < 0 ? -1 : (src != 0);

	t = lbnSub1_32((BNWORD32 *)dest->ptr, dest->size, src);
	MALLOCDB;
	if (t) {
		/* Underflow. <= 1 word, so do it simply. */
		lbnNeg_32((BNWORD32 *)dest->ptr, 1);
		dest->size = 1;
		return 1;
	}
/* Try to normalize?  Needing this is going to be very rare. */
/*		dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, dest->size); */
	return 0;
}

/*
 * Compare two BigNums.  Returns -1. 0 or 1 if a<b, a == b or a>b.
 * a <=> b --> bnCmp(a,b) <=> 0
 */
int
bnCmp_32(struct BigNum const *a, struct BigNum const *b)
{
	unsigned s, t;

	s = lbnNorm_32((BNWORD32 *)a->ptr, a->size);
	t = lbnNorm_32((BNWORD32 *)b->ptr, b->size);
	
	if (s != t)
		return s > t ? 1 : -1;
	return lbnCmp_32((BNWORD32 *)a->ptr, (BNWORD32 *)b->ptr, s);
}

int
bnSquare_32(struct BigNum *dest, struct BigNum const *src)
{
	unsigned s;
	BNWORD32 *srcbuf;

	s = lbnNorm_32((BNWORD32 *)src->ptr, src->size);
	if (!s) {
		dest->size = 0;
		return 0;
	}
	bnSizeCheck(dest, 2*s);

	if (src == dest) {
		LBNALLOC(srcbuf, s);
		if (!srcbuf)
			return -1;
		lbnCopy_32(srcbuf, (BNWORD32 *)src->ptr, s);
		lbnSquare_32((BNWORD32 *)dest->ptr, (BNWORD32 *)srcbuf, s);
		LBNFREE(srcbuf, s);
	} else {
		lbnSquare_32((BNWORD32 *)dest->ptr, (BNWORD32 *)src->ptr, s);
	}

	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, 2*s);
	MALLOCDB;
	return 0;
}

int
bnMul_32(struct BigNum *dest, struct BigNum const *a, struct BigNum const *b)
{
	unsigned s, t;
	BNWORD32 *srcbuf;

	s = lbnNorm_32((BNWORD32 *)a->ptr, a->size);
	t = lbnNorm_32((BNWORD32 *)b->ptr, b->size);

	if (!s || !t) {
		dest->size = 0;
		return 0;
	}

	if (a == b)
		return bnSquare_32(dest, a);

	bnSizeCheck(dest, s+t);

	if (dest == a) {
		LBNALLOC(srcbuf, s);
		if (!srcbuf)
			return -1;
		lbnCopy_32(srcbuf, (BNWORD32 *)a->ptr, s);
		lbnMul_32((BNWORD32 *)dest->ptr, srcbuf, s,
		                                 (BNWORD32 *)b->ptr, t);
		LBNFREE(srcbuf, s);
	} else if (dest == b) {
		LBNALLOC(srcbuf, t);
		if (!srcbuf)
			return -1;
		lbnCopy_32(srcbuf, (BNWORD32 *)b->ptr, t);
		lbnMul_32((BNWORD32 *)dest->ptr, (BNWORD32 *)a->ptr, s,
		                                 srcbuf, t);
		LBNFREE(srcbuf, t);
	} else {
		lbnMul_32((BNWORD32 *)dest->ptr, (BNWORD32 *)a->ptr, s,
		                                 (BNWORD32 *)b->ptr, t);
	}
	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, s+t);
	MALLOCDB;
	return 0;
}

int
bnMulQ_32(struct BigNum *dest, struct BigNum const *a, unsigned b)
{
	unsigned s;

	s = lbnNorm_32((BNWORD32 *)a->ptr, a->size);
	if (!s || !b) {
		dest->size = 0;
		return 0;
	}
	if (b == 1)
		return bnCopy_32(dest, a);
	bnSizeCheck(dest, s+1);
	lbnMulN1_32((BNWORD32 *)dest->ptr, (BNWORD32 *)a->ptr, s, b);
	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, s+1);
	MALLOCDB;
	return 0;
}

int
bnDivMod_32(struct BigNum *q, struct BigNum *r, struct BigNum const *n,
            struct BigNum const *d)
{
	unsigned dsize, nsize;
	BNWORD32 qhigh;

	dsize = lbnNorm_32((BNWORD32 *)d->ptr, d->size);
	nsize = lbnNorm_32((BNWORD32 *)n->ptr, n->size);

	if (nsize < dsize) {
		q->size = 0;	/* No quotient */
		r->size = nsize;
		return 0;	/* Success */
	}

	bnSizeCheck(q, nsize-dsize);

	if (r != n) {	/* You are allowed to reduce in place */
		bnSizeCheck(r, nsize);
		lbnCopy_32((BNWORD32 *)r->ptr, (BNWORD32 *)n->ptr, nsize);
	}
		
	qhigh = lbnDiv_32((BNWORD32 *)q->ptr, (BNWORD32 *)r->ptr, nsize,
	                  (BNWORD32 *)d->ptr, dsize);
	nsize -= dsize;
	if (qhigh) {
		bnSizeCheck(q, nsize+1);
		*((BNWORD32 *)q->ptr BIGLITTLE(-nsize-1,+nsize)) = qhigh;
		q->size = nsize+1;
	} else {
		q->size = lbnNorm_32((BNWORD32 *)q->ptr, nsize);
	}
	r->size = lbnNorm_32((BNWORD32 *)r->ptr, dsize);
	MALLOCDB;
	return 0;
}

int
bnMod_32(struct BigNum *dest, struct BigNum const *src, struct BigNum const *d)
{
	unsigned dsize, nsize;

	nsize = lbnNorm_32((BNWORD32 *)src->ptr, src->size);
	dsize = lbnNorm_32((BNWORD32 *)d->ptr, d->size);


	if (dest != src) {
		bnSizeCheck(dest, nsize);
		lbnCopy_32((BNWORD32 *)dest->ptr, (BNWORD32 *)src->ptr, nsize);
	}

	if (nsize < dsize) {
		dest->size = nsize;	/* No quotient */
		return 0;
	}

	(void)lbnDiv_32((BNWORD32 *)dest->ptr BIGLITTLE(-dsize,+dsize),
	                (BNWORD32 *)dest->ptr, nsize,
	                (BNWORD32 *)d->ptr, dsize);
	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, dsize);
	MALLOCDB;
	return 0;
}

unsigned
bnModQ_32(struct BigNum const *src, unsigned d)
{
	unsigned s;

	s = lbnNorm_32((BNWORD32 *)src->ptr, src->size);
	if (!s)
		return 0;
	
	return lbnModQ_32((BNWORD32 *)src->ptr, s, d);
}

int
bnExpMod_32(struct BigNum *dest, struct BigNum const *n,
	struct BigNum const *exp, struct BigNum const *mod)
{
	unsigned nsize, esize, msize;

	nsize = lbnNorm_32((BNWORD32 *)n->ptr, n->size);
	esize = lbnNorm_32((BNWORD32 *)exp->ptr, exp->size);
	msize = lbnNorm_32((BNWORD32 *)mod->ptr, mod->size);

	if (!msize || (((BNWORD32 *)mod->ptr)[BIGLITTLE(-1,0)] & 1) == 0)
		return -1;	/* Illegal modulus! */

	bnSizeCheck(dest, msize);

	/* Special-case base of 2 */
	if (nsize == 1 && ((BNWORD32 *)n->ptr)[BIGLITTLE(-1,0)] == 2) {
		if (lbnTwoExpMod_32((BNWORD32 *)dest->ptr,
				    (BNWORD32 *)exp->ptr, esize,
				    (BNWORD32 *)mod->ptr, msize) < 0)
			return -1;
	} else {
		if (lbnExpMod_32((BNWORD32 *)dest->ptr,
		                 (BNWORD32 *)n->ptr, nsize,
				 (BNWORD32 *)exp->ptr, esize,
				 (BNWORD32 *)mod->ptr, msize) < 0)
		return -1;
	}

	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, msize);
	MALLOCDB;
	return 0;
}

int
bnDoubleExpMod_32(struct BigNum *dest,
	struct BigNum const *n1, struct BigNum const *e1,
	struct BigNum const *n2, struct BigNum const *e2,
	struct BigNum const *mod)
{
	unsigned n1size, e1size, n2size, e2size, msize;

	n1size = lbnNorm_32((BNWORD32 *)n1->ptr, n1->size);
	e1size = lbnNorm_32((BNWORD32 *)e1->ptr, e1->size);
	n2size = lbnNorm_32((BNWORD32 *)n2->ptr, n2->size);
	e2size = lbnNorm_32((BNWORD32 *)e2->ptr, e2->size);
	msize = lbnNorm_32((BNWORD32 *)mod->ptr, mod->size);

	if (!msize || (((BNWORD32 *)mod->ptr)[BIGLITTLE(-1,0)] & 1) == 0)
		return -1;	/* Illegal modulus! */

	bnSizeCheck(dest, msize);

	if (lbnDoubleExpMod_32((BNWORD32 *)dest->ptr,
		(BNWORD32 *)n1->ptr, n1size, (BNWORD32 *)e1->ptr, e1size,
		(BNWORD32 *)n2->ptr, n2size, (BNWORD32 *)e2->ptr, e2size,
		(BNWORD32 *)mod->ptr, msize) < 0)
		return -1;

	dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, msize);
	MALLOCDB;
	return 0;
}

int
bnTwoExpMod_32(struct BigNum *n, struct BigNum const *exp,
	struct BigNum const *mod)
{
	unsigned esize, msize;

	esize = lbnNorm_32((BNWORD32 *)exp->ptr, exp->size);
	msize = lbnNorm_32((BNWORD32 *)mod->ptr, mod->size);

	if (!msize || (((BNWORD32 *)mod->ptr)[BIGLITTLE(-1,0)] & 1) == 0)
		return -1;	/* Illegal modulus! */

	bnSizeCheck(n, msize);

	if (lbnTwoExpMod_32((BNWORD32 *)n->ptr, (BNWORD32 *)exp->ptr, esize,
	                    (BNWORD32 *)mod->ptr, msize) < 0)
		return -1;

	n->size = lbnNorm_32((BNWORD32 *)n->ptr, msize);
	MALLOCDB;
	return 0;
}

int
bnGcd_32(struct BigNum *dest, struct BigNum const *a, struct BigNum const *b)
{
	BNWORD32 *tmp;
	unsigned asize, bsize;
	int i;

	/* Kind of silly, but we might as well permit it... */
	if (a == b)
		return dest == a ? 0 : bnCopy(dest, a);

	/* Ensure a is not the same as "dest" */
	if (a == dest) {
		a = b;
		b = dest;
	}

	asize = lbnNorm_32((BNWORD32 *)a->ptr, a->size);
	bsize = lbnNorm_32((BNWORD32 *)b->ptr, b->size);

	bnSizeCheck(dest, bsize+1);

	/* Copy a to tmp */
	LBNALLOC(tmp, asize+1);
	if (!tmp)
		return -1;
	lbnCopy_32(tmp, (BNWORD32 *)a->ptr, asize);

	/* Copy b to dest,if necessary */
	if (dest != b)
		lbnCopy_32((BNWORD32 *)dest->ptr,
			   (BNWORD32 *)b->ptr, bsize);
	if (bsize > asize || (bsize == asize &&
	        lbnCmp_32((BNWORD32 *)b->ptr, (BNWORD32 *)a->ptr, asize) > 0))
	{
		i = lbnGcd_32((BNWORD32 *)dest->ptr, bsize, tmp, asize);
		if (i >= 0) {
			dest->size = (unsigned)i;
		} else {
			lbnCopy_32((BNWORD32 *)dest->ptr, tmp,
				   (unsigned)-i);
			dest->size = (unsigned)-i;
		}
	} else {
		i = lbnGcd_32(tmp, asize, (BNWORD32 *)dest->ptr, bsize);
		if (i <= 0) {
			dest->size = (unsigned)-i;
		} else {
			lbnCopy_32((BNWORD32 *)dest->ptr, tmp,
				   (unsigned)i);
			dest->size = (unsigned)i;
		}
	}
	LBNFREE(tmp, asize+1);
	MALLOCDB;
	return 0;
}

int
bnInv_32(struct BigNum *dest, struct BigNum const *src,
         struct BigNum const *mod)
{
	unsigned s, m;
	int i;

	s = lbnNorm_32((BNWORD32 *)src->ptr, src->size);
	m = lbnNorm_32((BNWORD32 *)mod->ptr, mod->size);

	/* lbnInv_32 requires that the input be less than the modulus */
	if (m < s ||
	    (m==s && lbnCmp_32((BNWORD32 *)src->ptr, (BNWORD32 *)mod->ptr, s)))
	{
		bnSizeCheck(dest, s + (m==s));
		if (dest != src)
			lbnCopy_32((BNWORD32 *)dest->ptr,
			           (BNWORD32 *)src->ptr, s);
		/* Pre-reduce modulo the modulus */
		(void)lbnDiv_32((BNWORD32 *)dest->ptr BIGLITTLE(-m,+m),
			        (BNWORD32 *)dest->ptr, s,
		                (BNWORD32 *)mod->ptr, m);
		s = lbnNorm_32((BNWORD32 *)dest->ptr, m);
		MALLOCDB;
	} else {
		bnSizeCheck(dest, m+1);
		if (dest != src)
			lbnCopy_32((BNWORD32 *)dest->ptr,
			           (BNWORD32 *)src->ptr, s);
	}

	i = lbnInv_32((BNWORD32 *)dest->ptr, s, (BNWORD32 *)mod->ptr, m);
	if (i == 0)
		dest->size = lbnNorm_32((BNWORD32 *)dest->ptr, m);

	MALLOCDB;
	return i;
}

/*
 * Shift a bignum left the appropriate number of bits,
 * multiplying by 2^amt.
 */
int 
bnLShift_32(struct BigNum *dest, unsigned amt)
{
	unsigned s = dest->size;
	BNWORD32 carry;

	if (amt % 32) {
		carry = lbnLshift_32(dest->ptr, s, amt % 32);
		if (carry) {
			s++;
			bnSizeCheck(dest, s);
			((BNWORD32 *)dest->ptr)[BIGLITTLE(-s,s-1)] = carry;
		}
	}

	amt /= 32;
	if (amt) {
		bnSizeCheck(dest, s+amt);
		memmove((BNWORD32 *)dest->ptr BIGLITTLE(-s-amt, +amt),
		        (BNWORD32 *)dest->ptr BIG(-s),
			s * sizeof(BNWORD32));
		lbnZero_32((BNWORD32 *)dest->ptr, amt);
		s += amt;
	}
	dest->size = s;
	MALLOCDB;
	return 0;
}

/*
 * Shift a bignum right the appropriate number of bits,
 * dividing by 2^amt.
 */
void bnRShift_32(struct BigNum *dest, unsigned amt)
{
	unsigned s = dest->size;

	if (amt >= 32) {
		memmove(
		        (BNWORD32 *)dest->ptr BIG(-s+amt/32),
			(BNWORD32 *)dest->ptr BIGLITTLE(-s, +amt/32),
			s-amt/32 * sizeof(BNWORD32));
		s -= amt/32;
		amt %= 32;
	}

	if (amt)
		(void)lbnRshift_32(dest->ptr, s, amt);

	dest->size = lbnNorm_32(dest->ptr, s);
	MALLOCDB;
}

/*
 * Shift a bignum right until it is odd, and return the number of
 * bits shifted.  n = d * 2^s.  Replaces n with d and returns s.
 * Returns 0 when given 0.  (Another valid answer is infinity.)
 */
unsigned
bnMakeOdd_32(struct BigNum *n)
{
	unsigned size;
	unsigned s;	/* shift amount */
	BNWORD32 *p;
	BNWORD32 t;

	p = (BNWORD32 *)n->ptr;
	size = lbnNorm_32(p, n->size);
	if (!size)
		return 0;

	t = BIGLITTLE(p[-1],p[0]);
	s = 0;

	/* See how many words we have to shift */
	if (!t) {
		/* Shift by words */
		do {
			
			s++;
			BIGLITTLE(--p,p++);
		} while ((t = BIGLITTLE(p[-1],p[0])) == 0);
		size -= s;
		s *= 32;
		memmove((BNWORD32 *)n->ptr BIG(-size), p BIG(-size),
			size * sizeof(BNWORD32));
		p = (BNWORD32 *)n->ptr;
		MALLOCDB;
	}

	assert(t);

	/* Now count the bits */
	while ((t & 1) == 0) {
		t >>= 1;
		s++;
	}

	/* Shift the bits */
	if (s & (32-1)) {
		lbnRshift_32(p, size, s & (32-1));
		/* Renormalize */
		if (BIGLITTLE(*(p-size),*(p+(size-1))) == 0)
			--size;
	}
	n->size = size;

	MALLOCDB;
	return s;
}
