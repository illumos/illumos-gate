/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The basic framework for this code came from the reference
 * implementation for MD5.  That implementation is Copyright (C)
 * 1991-2, RSA Data Security, Inc. Created 1991. All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 * NOTE: Cleaned-up and optimized, version of SHA1, based on the FIPS 180-1
 * standard, available at http://www.itl.nist.gov/div897/pubs/fip180-1.htm
 * Not as fast as one would like -- further optimizations are encouraged
 * and appreciated.
 */

#include <sys/types.h>
#include <strings.h>
#include <sys/sha1.h>
#include <sys/sha1_consts.h>

#define	RCSID	"$Id: $"
#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

static void Encode(uint8_t *, uint32_t *, size_t);
static void SHA1Transform(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
    SHA1_CTX *, const uint8_t *);

static uint8_t PADDING[64] = { 0x80, /* all zeros */ };

/*
 * F, G, and H are the basic SHA1 functions.
 */
#define	F(b, c, d)	(((b) & (c)) | ((~b) & (d)))
#define	G(b, c, d)	((b) ^ (c) ^ (d))
#define	H(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define	ROTATE_LEFT(x, n)	\
	(((x) << (n)) | ((x) >> ((sizeof (x) * NBBY)-(n))))

/*
 * SHA1Init()
 *
 * purpose: initializes the sha1 context and begins and sha1 digest operation
 *   input: SHA1_CTX *	: the context to initializes.
 *  output: void
 */

void
SHA1Init(SHA1_CTX *ctx)
{
	ctx->count[0] = ctx->count[1] = 0;

	/*
	 * load magic initialization constants. Tell lint
	 * that these constants are unsigned by using U.
	 */

	ctx->state[0] = 0x67452301U;
	ctx->state[1] = 0xefcdab89U;
	ctx->state[2] = 0x98badcfeU;
	ctx->state[3] = 0x10325476U;
	ctx->state[4] = 0xc3d2e1f0U;
}

/*
 * SHA1Update()
 *
 * purpose: continues an sha1 digest operation, using the message block
 *          to update the context.
 *   input: SHA1_CTX *	: the context to update
 *          uint8_t *	: the message block
 *          uint32_t    : the length of the message block in bytes
 *  output: void
 */

void
SHA1Update(SHA1_CTX *ctx, const uint8_t *input, uint32_t input_len)
{
	uint32_t i, buf_index, buf_len;

	/* check for noop */
	if (input_len == 0)
		return;

	/* compute number of bytes mod 64 */
	buf_index = (ctx->count[1] >> 3) & 0x3F;

	/* update number of bits */
	if ((ctx->count[1] += (input_len << 3)) < (input_len << 3))
		ctx->count[0]++;

	ctx->count[0] += (input_len >> 29);

	buf_len = 64 - buf_index;

	/* transform as many times as possible */
	i = 0;
	if (input_len >= buf_len) {

		/*
		 * general optimization:
		 *
		 * only do initial bcopy() and SHA1Transform() if
		 * buf_index != 0.  if buf_index == 0, we're just
		 * wasting our time doing the bcopy() since there
		 * wasn't any data left over from a previous call to
		 * SHA1Update().
		 */

		if (buf_index) {
			bcopy(input, &ctx->buf_un.buf8[buf_index], buf_len);


			SHA1Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx->state[4], ctx,
			    ctx->buf_un.buf8);

			i = buf_len;
		}

		for (; i + 63 < input_len; i += 64)
			SHA1Transform(ctx->state[0], ctx->state[1],
			    ctx->state[2], ctx->state[3], ctx->state[4],
			    ctx, &input[i]);

		/*
		 * general optimization:
		 *
		 * if i and input_len are the same, return now instead
		 * of calling bcopy(), since the bcopy() in this case
		 * will be an expensive nop.
		 */

		if (input_len == i)
			return;

		buf_index = 0;
	}

	/* buffer remaining input */
	bcopy(&input[i], &ctx->buf_un.buf8[buf_index], input_len - i);
}

/*
 * SHA1Final()
 *
 * purpose: ends an sha1 digest operation, finalizing the message digest and
 *          zeroing the context.
 *   input: uint8_t *	: a buffer to store the digest in
 *          SHA1_CTX *  : the context to finalize, save, and zero
 *  output: void
 */

void
SHA1Final(uint8_t *digest, SHA1_CTX *ctx)
{
	uint8_t		bitcount_be[sizeof (ctx->count)];
	uint32_t	index = (ctx->count[1] >> 3) & 0x3f;

	/* store bit count, big endian */
	Encode(bitcount_be, ctx->count, sizeof (bitcount_be));

	/* pad out to 56 mod 64 */
	SHA1Update(ctx, PADDING, ((index < 56) ? 56 : 120) - index);

	/* append length (before padding) */
	SHA1Update(ctx, bitcount_be, sizeof (bitcount_be));

	/* store state in digest */
	Encode(digest, ctx->state, sizeof (ctx->state));

	/* zeroize sensitive information */
	bzero(ctx, sizeof (*ctx));
}

/*
 * sparc optimization:
 *
 * on the sparc, we can load big endian 32-bit data easily.  note that
 * special care must be taken to ensure the address is 32-bit aligned.
 * in the interest of speed, we don't check to make sure, since
 * careful programming can guarantee this for us.
 */

#if	defined(__sparc)

#define	LOAD_LITTLE_32(addr)	(*(uint32_t *)(addr))

#else	/* little endian -- will work on big endian, but slowly */

#define	LOAD_LITTLE_32(addr)	\
	(((addr)[0] << 24) | ((addr)[1] << 16) | ((addr)[2] << 8) | (addr)[3])
#endif

/*
 * sparc register window optimization:
 *
 * `a', `b', `c', `d', and `e' are passed into SHA1Transform
 * explicitly since it increases the number of registers available to
 * the compiler.  under this scheme, these variables can be held in
 * %i0 - %i4, which leaves more local and out registers available.
 */

/*
 * SHA1Transform()
 *
 * purpose: sha1 transformation -- updates the digest based on `block'
 *   input: uint32_t	: bytes  1 -  4 of the digest
 *          uint32_t	: bytes  5 -  8 of the digest
 *          uint32_t	: bytes  9 - 12 of the digest
 *          uint32_t	: bytes 12 - 16 of the digest
 *          uint32_t	: bytes 16 - 20 of the digest
 *          SHA1_CTX *	: the context to update
 *          uint8_t [64]: the block to use to update the digest
 *  output: void
 */

void
SHA1Transform(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
    SHA1_CTX *ctx, const uint8_t blk[64])
{
	/*
	 * sparc optimization:
	 *
	 * while it is somewhat counter-intuitive, on sparc, it is
	 * more efficient to place all the constants used in this
	 * function in an array and load the values out of the array
	 * than to manually load the constants.  this is because
	 * setting a register to a 32-bit value takes two ops in most
	 * cases: a `sethi' and an `or', but loading a 32-bit value
	 * from memory only takes one `ld' (or `lduw' on v9).  while
	 * this increases memory usage, the compiler can find enough
	 * other things to do while waiting to keep the pipeline does
	 * not stall.  additionally, it is likely that many of these
	 * constants are cached so that later accesses do not even go
	 * out to the bus.
	 *
	 * this array is declared `static' to keep the compiler from
	 * having to bcopy() this array onto the stack frame of
	 * SHA1Transform() each time it is called -- which is
	 * unacceptably expensive.
	 *
	 * the `const' is to ensure that callers are good citizens and
	 * do not try to munge the array.  since these routines are
	 * going to be called from inside multithreaded kernelland,
	 * this is a good safety check. -- `sha1_consts' will end up in
	 * .rodata.
	 *
	 * unfortunately, loading from an array in this manner hurts
	 * performance under intel.  so, there is a macro,
	 * SHA1_CONST(), used in SHA1Transform(), that either expands to
	 * a reference to this array, or to the actual constant,
	 * depending on what platform this code is compiled for.
	 */

#if	defined(__sparc)
	static const uint32_t sha1_consts[] = {
		SHA1_CONST_0,	SHA1_CONST_1,	SHA1_CONST_2,	SHA1_CONST_3,
	};
#endif

	/*
	 * general optimization:
	 *
	 * use individual integers instead of using an array.  this is a
	 * win, although the amount it wins by seems to vary quite a bit.
	 */

	uint32_t	w_0, w_1, w_2,  w_3,  w_4,  w_5,  w_6,  w_7;
	uint32_t	w_8, w_9, w_10, w_11, w_12, w_13, w_14, w_15;

	/*
	 * sparc optimization:
	 *
	 * if `block' is already aligned on a 4-byte boundary, use
	 * LOAD_LITTLE_32() directly.  otherwise, bcopy() into a
	 * buffer that *is* aligned on a 4-byte boundary and then do
	 * the LOAD_LITTLE_32() on that buffer.  benchmarks have shown
	 * that using the bcopy() is better than loading the bytes
	 * individually and doing the endian-swap by hand.
	 *
	 * even though it's quite tempting to assign to do:
	 *
	 * blk = bcopy(ctx->buf_un.buf32, blk, sizeof (ctx->buf_un.buf32));
	 *
	 * and only have one set of LOAD_LITTLE_32()'s, the compiler
	 * *does not* like that, so please resist the urge.
	 */

#if	defined(__sparc)
	if ((uintptr_t)blk & 0x3) {		/* not 4-byte aligned? */
		bcopy(blk, ctx->buf_un.buf32,  sizeof (ctx->buf_un.buf32));
		w_15 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 15);
		w_14 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 14);
		w_13 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 13);
		w_12 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 12);
		w_11 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 11);
		w_10 = LOAD_LITTLE_32(ctx->buf_un.buf32 + 10);
		w_9  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  9);
		w_8  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  8);
		w_7  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  7);
		w_6  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  6);
		w_5  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  5);
		w_4  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  4);
		w_3  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  3);
		w_2  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  2);
		w_1  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  1);
		w_0  = LOAD_LITTLE_32(ctx->buf_un.buf32 +  0);
	} else {
		/*LINTED*/
		w_15 = LOAD_LITTLE_32(blk + 60);
		/*LINTED*/
		w_14 = LOAD_LITTLE_32(blk + 56);
		/*LINTED*/
		w_13 = LOAD_LITTLE_32(blk + 52);
		/*LINTED*/
		w_12 = LOAD_LITTLE_32(blk + 48);
		/*LINTED*/
		w_11 = LOAD_LITTLE_32(blk + 44);
		/*LINTED*/
		w_10 = LOAD_LITTLE_32(blk + 40);
		/*LINTED*/
		w_9  = LOAD_LITTLE_32(blk + 36);
		/*LINTED*/
		w_8  = LOAD_LITTLE_32(blk + 32);
		/*LINTED*/
		w_7  = LOAD_LITTLE_32(blk + 28);
		/*LINTED*/
		w_6  = LOAD_LITTLE_32(blk + 24);
		/*LINTED*/
		w_5  = LOAD_LITTLE_32(blk + 20);
		/*LINTED*/
		w_4  = LOAD_LITTLE_32(blk + 16);
		/*LINTED*/
		w_3  = LOAD_LITTLE_32(blk + 12);
		/*LINTED*/
		w_2  = LOAD_LITTLE_32(blk +  8);
		/*LINTED*/
		w_1  = LOAD_LITTLE_32(blk +  4);
		/*LINTED*/
		w_0  = LOAD_LITTLE_32(blk +  0);
	}
#else
	w_15 = LOAD_LITTLE_32(blk + 60);
	w_14 = LOAD_LITTLE_32(blk + 56);
	w_13 = LOAD_LITTLE_32(blk + 52);
	w_12 = LOAD_LITTLE_32(blk + 48);
	w_11 = LOAD_LITTLE_32(blk + 44);
	w_10 = LOAD_LITTLE_32(blk + 40);
	w_9  = LOAD_LITTLE_32(blk + 36);
	w_8  = LOAD_LITTLE_32(blk + 32);
	w_7  = LOAD_LITTLE_32(blk + 28);
	w_6  = LOAD_LITTLE_32(blk + 24);
	w_5  = LOAD_LITTLE_32(blk + 20);
	w_4  = LOAD_LITTLE_32(blk + 16);
	w_3  = LOAD_LITTLE_32(blk + 12);
	w_2  = LOAD_LITTLE_32(blk +  8);
	w_1  = LOAD_LITTLE_32(blk +  4);
	w_0  = LOAD_LITTLE_32(blk +  0);
#endif
	/*
	 * general optimization:
	 *
	 * even though this approach is described in the standard as
	 * being slower algorithmically, it is 30-40% faster than the
	 * "faster" version under SPARC, because this version has more
	 * of the constraints specified at compile-time and uses fewer
	 * variables (and therefore has better register utilization)
	 * than its "speedier" brother.  (i've tried both, trust me)
	 *
	 * for either method given in the spec, there is an "assignment"
	 * phase where the following takes place:
	 *
	 *	tmp = (main_computation);
	 *	e = d; d = c; c = rotate_left(b, 30); b = a; a = tmp;
	 *
	 * we can make the algorithm go faster by not doing this work,
	 * but just pretending that `d' is now `e', etc. this works
	 * really well and obviates the need for a temporary variable.
	 * however, we still explictly perform the rotate action,
	 * since it is cheaper on SPARC to do it once than to have to
	 * do it over and over again.
	 */

	/* round 1 */
	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_0 + SHA1_CONST(0); /* 0 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_1 + SHA1_CONST(0); /* 1 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_2 + SHA1_CONST(0); /* 2 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_3 + SHA1_CONST(0); /* 3 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_4 + SHA1_CONST(0); /* 4 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_5 + SHA1_CONST(0); /* 5 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_6 + SHA1_CONST(0); /* 6 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_7 + SHA1_CONST(0); /* 7 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_8 + SHA1_CONST(0); /* 8 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_9 + SHA1_CONST(0); /* 9 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_10 + SHA1_CONST(0); /* 10 */
	b = ROTATE_LEFT(b, 30);

	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_11 + SHA1_CONST(0); /* 11 */
	a = ROTATE_LEFT(a, 30);

	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_12 + SHA1_CONST(0); /* 12 */
	e = ROTATE_LEFT(e, 30);

	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_13 + SHA1_CONST(0); /* 13 */
	d = ROTATE_LEFT(d, 30);

	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_14 + SHA1_CONST(0); /* 14 */
	c = ROTATE_LEFT(c, 30);

	e = ROTATE_LEFT(a, 5) + F(b, c, d) + e + w_15 + SHA1_CONST(0); /* 15 */
	b = ROTATE_LEFT(b, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 16 */
	d = ROTATE_LEFT(e, 5) + F(a, b, c) + d + w_0 + SHA1_CONST(0);
	a = ROTATE_LEFT(a, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 17 */
	c = ROTATE_LEFT(d, 5) + F(e, a, b) + c + w_1 + SHA1_CONST(0);
	e = ROTATE_LEFT(e, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 18 */
	b = ROTATE_LEFT(c, 5) + F(d, e, a) + b + w_2 + SHA1_CONST(0);
	d = ROTATE_LEFT(d, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 19 */
	a = ROTATE_LEFT(b, 5) + F(c, d, e) + a + w_3 + SHA1_CONST(0);
	c = ROTATE_LEFT(c, 30);

	/* round 2 */
	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 20 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_4 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 21 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_5 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 22 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_6 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 23 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_7 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 24 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_8 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 25 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_9 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 26 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_10 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 27 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_11 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 28 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_12 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 29 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_13 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 30 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_14 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 31 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_15 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 32 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_0 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 33 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_1 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 34 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_2 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 35 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_3 + SHA1_CONST(1);
	b = ROTATE_LEFT(b, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 36 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_4 + SHA1_CONST(1);
	a = ROTATE_LEFT(a, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 37 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_5 + SHA1_CONST(1);
	e = ROTATE_LEFT(e, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 38 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_6 + SHA1_CONST(1);
	d = ROTATE_LEFT(d, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 39 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_7 + SHA1_CONST(1);
	c = ROTATE_LEFT(c, 30);

	/* round 3 */
	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 40 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_8 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 41 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_9 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 42 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_10 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 43 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_11 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 44 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_12 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 45 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_13 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 46 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_14 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 47 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_15 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 48 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_0 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 49 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_1 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 50 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_2 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 51 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_3 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 52 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_4 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 53 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_5 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 54 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_6 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 55 */
	e = ROTATE_LEFT(a, 5) + H(b, c, d) + e + w_7 + SHA1_CONST(2);
	b = ROTATE_LEFT(b, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 56 */
	d = ROTATE_LEFT(e, 5) + H(a, b, c) + d + w_8 + SHA1_CONST(2);
	a = ROTATE_LEFT(a, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 57 */
	c = ROTATE_LEFT(d, 5) + H(e, a, b) + c + w_9 + SHA1_CONST(2);
	e = ROTATE_LEFT(e, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 58 */
	b = ROTATE_LEFT(c, 5) + H(d, e, a) + b + w_10 + SHA1_CONST(2);
	d = ROTATE_LEFT(d, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 59 */
	a = ROTATE_LEFT(b, 5) + H(c, d, e) + a + w_11 + SHA1_CONST(2);
	c = ROTATE_LEFT(c, 30);

	/* round 4 */
	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 60 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_12 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 61 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_13 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 62 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_14 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 63 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_15 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_0 = ROTATE_LEFT((w_13 ^ w_8 ^ w_2 ^ w_0), 1);		/* 64 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_0 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_1 = ROTATE_LEFT((w_14 ^ w_9 ^ w_3 ^ w_1), 1);		/* 65 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_1 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_2 = ROTATE_LEFT((w_15 ^ w_10 ^ w_4 ^ w_2), 1);	/* 66 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_2 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_3 = ROTATE_LEFT((w_0 ^ w_11 ^ w_5 ^ w_3), 1);		/* 67 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_3 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_4 = ROTATE_LEFT((w_1 ^ w_12 ^ w_6 ^ w_4), 1);		/* 68 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_4 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_5 = ROTATE_LEFT((w_2 ^ w_13 ^ w_7 ^ w_5), 1);		/* 69 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_5 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_6 = ROTATE_LEFT((w_3 ^ w_14 ^ w_8 ^ w_6), 1);		/* 70 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_6 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_7 = ROTATE_LEFT((w_4 ^ w_15 ^ w_9 ^ w_7), 1);		/* 71 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_7 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_8 = ROTATE_LEFT((w_5 ^ w_0 ^ w_10 ^ w_8), 1);		/* 72 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_8 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_9 = ROTATE_LEFT((w_6 ^ w_1 ^ w_11 ^ w_9), 1);		/* 73 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_9 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_10 = ROTATE_LEFT((w_7 ^ w_2 ^ w_12 ^ w_10), 1);	/* 74 */
	a = ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_10 + SHA1_CONST(3);
	c = ROTATE_LEFT(c, 30);

	w_11 = ROTATE_LEFT((w_8 ^ w_3 ^ w_13 ^ w_11), 1);	/* 75 */
	e = ROTATE_LEFT(a, 5) + G(b, c, d) + e + w_11 + SHA1_CONST(3);
	b = ROTATE_LEFT(b, 30);

	w_12 = ROTATE_LEFT((w_9 ^ w_4 ^ w_14 ^ w_12), 1);	/* 76 */
	d = ROTATE_LEFT(e, 5) + G(a, b, c) + d + w_12 + SHA1_CONST(3);
	a = ROTATE_LEFT(a, 30);

	w_13 = ROTATE_LEFT((w_10 ^ w_5 ^ w_15 ^ w_13), 1);	/* 77 */
	c = ROTATE_LEFT(d, 5) + G(e, a, b) + c + w_13 + SHA1_CONST(3);
	e = ROTATE_LEFT(e, 30);

	w_14 = ROTATE_LEFT((w_11 ^ w_6 ^ w_0 ^ w_14), 1);	/* 78 */
	b = ROTATE_LEFT(c, 5) + G(d, e, a) + b + w_14 + SHA1_CONST(3);
	d = ROTATE_LEFT(d, 30);

	w_15 = ROTATE_LEFT((w_12 ^ w_7 ^ w_1 ^ w_15), 1);	/* 79 */

	ctx->state[0] += ROTATE_LEFT(b, 5) + G(c, d, e) + a + w_15 +
	    SHA1_CONST(3);
	ctx->state[1] += b;
	ctx->state[2] += ROTATE_LEFT(c, 30);
	ctx->state[3] += d;
	ctx->state[4] += e;

	/* zeroize sensitive information */
	w_0 = w_1 = w_2 = w_3 = w_4 = w_5 = w_6 = w_7 = w_8 = 0;
	w_9 = w_10 = w_11 = w_12 = w_13 = w_14 = w_15 = 0;
}

/*
 * devpro compiler optimization:
 *
 * the compiler can generate better code if it knows that `input' and
 * `output' do not point to the same source.  there is no portable
 * way to tell the compiler this, but the sun compiler recognizes the
 * `_Restrict' keyword to indicate this condition.  use it if possible.
 */

#ifdef	__RESTRICT
#define	restrict	_Restrict
#else
#define	restrict	/* nothing */
#endif

/*
 * Encode()
 *
 * purpose: to convert a list of numbers from little endian to big endian
 *   input: uint8_t *	: place to store the converted big endian numbers
 *	    uint32_t *	: place to get numbers to convert from
 *          size_t	: the length of the input in bytes
 *  output: void
 */

static void
Encode(uint8_t *restrict output, uint32_t *restrict input, size_t len)
{
	size_t		i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {

#if	defined(__sparc)

		/*LINTED*/
		*(uint32_t *)(output + j) = input[i];

#else	/* little endian -- will work on big endian, but slowly */

		output[j]	= (input[i] >> 24) & 0xff;
		output[j + 1]	= (input[i] >> 16) & 0xff;
		output[j + 2]	= (input[i] >>  8) & 0xff;
		output[j + 3]	= input[i] & 0xff;

#endif
	}
}
