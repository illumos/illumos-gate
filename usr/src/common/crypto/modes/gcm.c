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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 * Copyright 2023-2026 RackTop Systems, Inc.
 */

/*
 * This file implements GCM and GMAC, as decribed in
 *	NIST Special Publication 800-38D
 *	Recommendation for Block Cipher Modes of Operation:
 *	Galois/Counter Mode (GCM) and GMAC
 *
 * Briefly, GMAC uses GCM just for "authentication" (sign/verify),
 * discarding the ouptut data (cipher/clear) that GCM would produce.
 *
 * Some functions below serve both GCM and GMAC, adjusting behavior
 * based on (ctx->gcm_flags & GMAC_MODE) to skip output production
 * or actions needed only when actually doing encrypt or decrypt.
 *
 * Some non-obvious things to note:
 *
 * The struct member gcm_len_a_len_c[] is an array of two uint64_t
 * (AAD length and input data length, in that order, in BITS).
 * The values are needed in that form for a hash computation that
 * happens in the "final" function for GCM or GMAC.  Just before the
 * "final" hash computation, the values are converted to big-endian
 * form as required by the altgorithm specification. Before that
 * point those values are in host order (always BITS).
 *
 * The calling framework (one of uts/common/crypto/io/aes.c
 * or lib/pkcs11/pkcs11_softtoken/common/softAESCrypt.c)
 * uses different "alloc", "init", and "final" functions
 * for GCM vs GMAC.  See calls to:
 *	gcm_alloc_ctx, gmac_alloc_ctx,
 *	gcm_init_ctx,  gmac_init_ctx,
 *	gcm_encrypt_final, gmac_mode_final
 * Operation of the GCM vs GMAC varints of those functions are
 * similar other than encrypt/decrypt in GCM, skipped in GMAC.
 */

#ifndef _KERNEL
#include <strings.h>
#include <limits.h>
#include <security/cryptoki.h>
#endif	/* _KERNEL */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/byteorder.h>

#ifdef __amd64

#ifdef _KERNEL
#include <sys/cpuvar.h>		/* cpu_t, CPU */
#include <sys/x86_archext.h>	/* x86_featureset, X86FSET_*, CPUID_* */
#include <sys/disp.h>		/* kpreempt_disable(), kpreempt_enable */
/* Workaround for no XMM kernel thread save/restore */
#define	KPREEMPT_DISABLE	kpreempt_disable()
#define	KPREEMPT_ENABLE		kpreempt_enable()

#else
#include <sys/auxv.h>		/* getisax() */
#include <sys/auxv_386.h>	/* AV_386_PCLMULQDQ bit */
#define	KPREEMPT_DISABLE
#define	KPREEMPT_ENABLE
#endif	/* _KERNEL */

extern void gcm_mul_pclmulqdq(uint64_t *x_in, uint64_t *y, uint64_t *res);
static int intel_pclmulqdq_instruction_present(void);
#endif	/* __amd64 */

struct aes_block {
	uint64_t a;
	uint64_t b;
};


/*
 * gcm_mul()
 * Perform a carry-less multiplication (that is, use XOR instead of the
 * multiply operator) on *x_in and *y and place the result in *res.
 *
 * Byte swap the input (*x_in and *y) and the output (*res).
 *
 * Note: x_in, y, and res all point to 16-byte numbers (an array of two
 * 64-bit integers).
 */
void
gcm_mul(uint64_t *x_in, uint64_t *y, uint64_t *res)
{
#ifdef __amd64
	if (intel_pclmulqdq_instruction_present()) {
		KPREEMPT_DISABLE;
		gcm_mul_pclmulqdq(x_in, y, res);
		KPREEMPT_ENABLE;
	} else
#endif	/* __amd64 */
	{
		static const uint64_t R = 0xe100000000000000ULL;
		struct aes_block z = {0, 0};
		struct aes_block v;
		uint64_t x;
		int i, j;

		v.a = ntohll(y[0]);
		v.b = ntohll(y[1]);

		for (j = 0; j < 2; j++) {
			x = ntohll(x_in[j]);
			for (i = 0; i < 64; i++, x <<= 1) {
				if (x & 0x8000000000000000ULL) {
					z.a ^= v.a;
					z.b ^= v.b;
				}
				if (v.b & 1ULL) {
					v.b = (v.a << 63)|(v.b >> 1);
					v.a = (v.a >> 1) ^ R;
				} else {
					v.b = (v.a << 63)|(v.b >> 1);
					v.a = v.a >> 1;
				}
			}
		}
		res[0] = htonll(z.a);
		res[1] = htonll(z.b);
	}
}


#define	GHASH(c, d, t) \
	xor_block((uint8_t *)(d), (uint8_t *)(c)->gcm_ghash); \
	gcm_mul((uint64_t *)(void *)(c)->gcm_ghash, (c)->gcm_H, \
	(uint64_t *)(void *)(t));

/*
 * helper factored out of gcm_mode_encrypt_contiguous_blocks
 */
static inline void
gcm_encrypt_block(gcm_ctx_t *ctx, uint8_t *datap, crypto_data_t *out,
    size_t block_size, uint8_t *blockp, void *iov_or_mp, offset_t *offset,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);

	/*
	 * Increment counter. Counter bits are confined
	 * to the bottom 32 bits of the counter block.
	 */
	counter = ntohll(ctx->gcm_cb[1] & counter_mask);
	counter = htonll(counter + 1);
	counter &= counter_mask;
	ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb,
	    (uint8_t *)ctx->gcm_tmp);
	xor_block(blockp, (uint8_t *)ctx->gcm_tmp);

	if (out == NULL) {
		if (ctx->gcm_remainder_len > 0) {
			bcopy(blockp, ctx->gcm_copy_to,
			    ctx->gcm_remainder_len);
			bcopy(blockp + ctx->gcm_remainder_len, datap,
			    block_size - ctx->gcm_remainder_len);
		}
	} else {
		uint8_t *tmpp = (uint8_t *)ctx->gcm_tmp;
		crypto_get_ptrs(out, iov_or_mp, offset, &out_data_1,
		    &out_data_1_len, &out_data_2, block_size);

		/* copy block to where it belongs */
		if (out_data_1_len == block_size) {
			copy_block(tmpp, out_data_1);
		} else {
			bcopy(tmpp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(tmpp + out_data_1_len,
				    out_data_2,
				    block_size - out_data_1_len);
			}
		}
		/* update offset */
		out->cd_offset += block_size;
	}
}

/*
 * Encrypt multiple blocks of data in GCM mode.  Decrypt for GCM mode
 * is done in another function: gcm_mode_decrypt_contiguous_blocks().
 *
 * When doing GCM, gcm_processed_data_len is advanced (which is the
 * encrypted/decrypted data bytes, excluding AAD).  When this is doing
 * GMAC (serving C_Sign) it advances the "input" pointers instead:
 * gcm_len_a_len_c[0] is the ADD input length, and
 * gcm_len_a_len_c[1] is the data input length.
 * (Details at the top of this file).
 */
int
gcm_mode_encrypt_contiguous_blocks(gcm_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	void *iov_or_mp;
	offset_t offset;

	if (length + ctx->gcm_remainder_len < block_size) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->gcm_remainder + ctx->gcm_remainder_len,
		    length);
		ctx->gcm_remainder_len += length;
		ctx->gcm_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	if (out != NULL)
		crypto_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->gcm_remainder_len > 0) {
			need = block_size - ctx->gcm_remainder_len;

			if (need > remainder)
				return (CRYPTO_DATA_LEN_RANGE);

			bcopy(datap, &((uint8_t *)ctx->gcm_remainder)
			    [ctx->gcm_remainder_len], need);

			blockp = (uint8_t *)ctx->gcm_remainder;
		} else {
			blockp = datap;
		}

		if ((ctx->gcm_flags & GMAC_MODE) != 0) {
			/* add AAD to the hash */
			ctx->gcm_len_a_len_c[0] +=
			    CRYPTO_BYTES2BITS(block_size);
			GHASH(ctx, blockp, ctx->gcm_ghash);
		} else {
			gcm_encrypt_block(ctx, datap, out, block_size, blockp,
			    &iov_or_mp, &offset, encrypt_block, copy_block,
			    xor_block);
			/* add ciphertext to the hash */
			ctx->gcm_processed_data_len += block_size;
			GHASH(ctx, ctx->gcm_tmp, ctx->gcm_ghash);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->gcm_remainder_len != 0) {
			datap += need;
			ctx->gcm_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < block_size) {
			bcopy(datap, ctx->gcm_remainder, remainder);
			ctx->gcm_remainder_len = remainder;
			ctx->gcm_copy_to = datap;
			goto out;
		}
		ctx->gcm_copy_to = NULL;

	} while (remainder > 0);

out:
	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
int
gcm_encrypt_final(gcm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	uint8_t *ghash, *macp;
	int i, rv;

	if (out->cd_length <
	    (ctx->gcm_remainder_len + ctx->gcm_tag_len)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	ghash = (uint8_t *)ctx->gcm_ghash;

	if (ctx->gcm_remainder_len > 0) {
		uint64_t counter;
		uint8_t *tmpp = (uint8_t *)ctx->gcm_tmp;

		/*
		 * Here is where we deal with data that is not a
		 * multiple of the block size.
		 */

		/*
		 * Increment counter.
		 */
		counter = ntohll(ctx->gcm_cb[1] & counter_mask);
		counter = htonll(counter + 1);
		counter &= counter_mask;
		ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

		encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb,
		    (uint8_t *)ctx->gcm_tmp);

		macp = (uint8_t *)ctx->gcm_remainder;
		bzero(macp + ctx->gcm_remainder_len,
		    block_size - ctx->gcm_remainder_len);

		/* XOR with counter block */
		for (i = 0; i < ctx->gcm_remainder_len; i++) {
			macp[i] ^= tmpp[i];
		}

		/* add ciphertext to the hash */
		GHASH(ctx, macp, ghash);

		ctx->gcm_processed_data_len += ctx->gcm_remainder_len;
	}

	/*
	 * The gcm_len_a_len_c values are in host order until final,
	 * where we convert them to network order before GHASH
	 */
	ctx->gcm_len_a_len_c[0] = htonll(ctx->gcm_len_a_len_c[0]);
	ctx->gcm_len_a_len_c[1] =
	    htonll(CRYPTO_BYTES2BITS(ctx->gcm_processed_data_len));
	GHASH(ctx, ctx->gcm_len_a_len_c, ghash);
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_J0,
	    (uint8_t *)ctx->gcm_J0);
	xor_block((uint8_t *)ctx->gcm_J0, ghash);

	if (ctx->gcm_remainder_len > 0) {
		rv = crypto_put_output_data(macp, out, ctx->gcm_remainder_len);
		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}
	out->cd_offset += ctx->gcm_remainder_len;
	ctx->gcm_remainder_len = 0;
	rv = crypto_put_output_data(ghash, out, ctx->gcm_tag_len);
	if (rv != CRYPTO_SUCCESS)
		return (rv);
	out->cd_offset += ctx->gcm_tag_len;

	return (CRYPTO_SUCCESS);
}

/*
 * This is used in the AES encrypt operations when we're using them
 * for MAC computations. In these cases encrypted data is discarded
 * and we keep only the final data block (used as the MAC).
 */
int
gmac_mode_final(gcm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *ghash;
	int rv;

	/* Unlike encrypt_final, this has no output but the tag. */
	if (out->cd_length < ctx->gcm_tag_len)
		return (CRYPTO_DATA_LEN_RANGE);

	ghash = (uint8_t *)ctx->gcm_ghash;

	if (ctx->gcm_remainder_len > 0) {
		uint8_t *macp;

		/*
		 * Here is where we deal with data that is not a
		 * multiple of the block size.
		 *
		 * Not encrypting, so no counter, gcm_cb[].
		 */

		macp = (uint8_t *)ctx->gcm_remainder;
		bzero(macp + ctx->gcm_remainder_len,
		    block_size - ctx->gcm_remainder_len);

		ctx->gcm_len_a_len_c[0] +=
		    CRYPTO_BYTES2BITS(ctx->gcm_remainder_len);
		ctx->gcm_remainder_len = 0;
		/* add AAD to the hash */
		GHASH(ctx, macp, ghash);
	}

	/*
	 * We've stored the total auth data in bits here, but before we
	 * add it to the hash, we need to convert to network order.
	 * GMAC keeps gcm_len_a_len_c[1] = 0.
	 */
	ctx->gcm_len_a_len_c[0] = htonll(ctx->gcm_len_a_len_c[0]);
	GHASH(ctx, ctx->gcm_len_a_len_c, ghash);
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_J0,
	    (uint8_t *)ctx->gcm_J0);
	xor_block((uint8_t *)ctx->gcm_J0, ghash);

	rv = crypto_put_output_data(ghash, out, ctx->gcm_tag_len);
	if (rv != CRYPTO_SUCCESS)
		return (rv);
	out->cd_offset += ctx->gcm_tag_len;

	return (CRYPTO_SUCCESS);
}

/*
 * This will only deal with decrypting the last block of the input that
 * might not be a multiple of block length.
 */
static void
gcm_decrypt_incomplete_block(gcm_ctx_t *ctx, size_t block_size, size_t index,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *datap, *outp, *counterp;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	int i;

	/*
	 * Increment counter.
	 * Counter bits are confined to the bottom 32 bits
	 */
	counter = ntohll(ctx->gcm_cb[1] & counter_mask);
	counter = htonll(counter + 1);
	counter &= counter_mask;
	ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

	datap = (uint8_t *)ctx->gcm_remainder;
	outp = &((ctx->gcm_pt_buf)[index]);
	counterp = (uint8_t *)ctx->gcm_tmp;

	/* authentication tag */
	bzero((uint8_t *)ctx->gcm_tmp, block_size);
	bcopy(datap, (uint8_t *)ctx->gcm_tmp, ctx->gcm_remainder_len);

	/* add ciphertext to the hash */
	GHASH(ctx, ctx->gcm_tmp, ctx->gcm_ghash);

	/* decrypt remaining ciphertext */
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb, counterp);

	/* XOR with counter block */
	for (i = 0; i < ctx->gcm_remainder_len; i++) {
		outp[i] = datap[i] ^ counterp[i];
	}
}

/*
 * See notes above gcm_mode_encrypt_contiguous_blocks for GMAC
 * cases (serving C_Verify here) -- same applies here.
 */
int
gcm_mode_decrypt_contiguous_blocks(gcm_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t new_len;
	uint8_t *new;

	if ((ctx->gcm_flags & GMAC_MODE) != 0 &&
	    ctx->gcm_remainder_len != 0) {
		/*
		 * For GMAC we need to hash the AAD as we go because
		 * we don't save the data for _final like GCM does.
		 */
		uint8_t *macp, *ghash;

		macp = (uint8_t *)ctx->gcm_remainder;
		ghash = (uint8_t *)ctx->gcm_ghash;

		bzero(macp + ctx->gcm_remainder_len,
		    block_size - ctx->gcm_remainder_len);

		/* remainder AAD len in bits */
		ctx->gcm_len_a_len_c[0] +=
		    CRYPTO_BYTES2BITS(ctx->gcm_remainder_len);
		/* add AAD to the hash */
		GHASH(ctx, macp, ghash);
	}

	/*
	 * Copy contiguous ciphertext input blocks to plaintext buffer.
	 * Ciphertext will be decrypted in the final.
	 */
	if (length > 0) {
		new_len = ctx->gcm_pt_buf_len + length;
#ifdef _KERNEL
		new = kmem_alloc(new_len, ctx->gcm_kmflag);
		bcopy(ctx->gcm_pt_buf, new, ctx->gcm_pt_buf_len);
		kmem_free(ctx->gcm_pt_buf, ctx->gcm_pt_buf_len);
#else
		new = malloc(new_len);
		bcopy(ctx->gcm_pt_buf, new, ctx->gcm_pt_buf_len);
		free(ctx->gcm_pt_buf);
#endif
		if (new == NULL)
			return (CRYPTO_HOST_MEMORY);

		ctx->gcm_pt_buf = new;
		ctx->gcm_pt_buf_len = new_len;
		bcopy(data, &ctx->gcm_pt_buf[ctx->gcm_processed_data_len],
		    length);
		ctx->gcm_processed_data_len += length;
	}

	ctx->gcm_remainder_len = 0;
	return (CRYPTO_SUCCESS);
}

int
gcm_decrypt_final(gcm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t pt_len;
	size_t remainder;
	uint8_t *ghash;
	uint8_t *blockp;
	uint8_t *cbp;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	int processed = 0, rv;

	ASSERT3U(ctx->gcm_processed_data_len, ==, ctx->gcm_pt_buf_len);

	pt_len = ctx->gcm_processed_data_len - ctx->gcm_tag_len;
	ghash = (uint8_t *)ctx->gcm_ghash;
	blockp = ctx->gcm_pt_buf;
	remainder = pt_len;

	if ((ctx->gcm_flags & GMAC_MODE) != 0) {
		ASSERT3U(remainder, ==, 0);
	}

	while (remainder > 0) {
		/* Incomplete last block */
		if (remainder < block_size) {
			bcopy(blockp, ctx->gcm_remainder, remainder);
			ctx->gcm_remainder_len = remainder;
			/*
			 * not expecting anymore ciphertext, just
			 * compute plaintext for the remaining input
			 */
			gcm_decrypt_incomplete_block(ctx, block_size,
			    processed, encrypt_block, xor_block);
			ctx->gcm_remainder_len = 0;
			goto out;
		}
		/* add ciphertext to the hash */
		GHASH(ctx, blockp, ghash);

		/*
		 * Increment counter.
		 * Counter bits are confined to the bottom 32 bits
		 */
		counter = ntohll(ctx->gcm_cb[1] & counter_mask);
		counter = htonll(counter + 1);
		counter &= counter_mask;
		ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

		cbp = (uint8_t *)ctx->gcm_tmp;
		encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb, cbp);

		/* XOR with ciphertext */
		xor_block(cbp, blockp);

		processed += block_size;
		blockp += block_size;
		remainder -= block_size;
	}

out:
	/*
	 * We've stored the total auth data in bits here, but before we
	 * add it to the hash, we need to change byte order.
	 */
	ctx->gcm_len_a_len_c[0] = htonll(ctx->gcm_len_a_len_c[0]);
	ctx->gcm_len_a_len_c[1] = htonll(CRYPTO_BYTES2BITS(pt_len));
	GHASH(ctx, ctx->gcm_len_a_len_c, ghash);
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_J0,
	    (uint8_t *)ctx->gcm_J0);
	xor_block((uint8_t *)ctx->gcm_J0, ghash);

	/* compare the input authentication tag with what we calculated */
	if (bcmp(&ctx->gcm_pt_buf[pt_len], ghash, ctx->gcm_tag_len)) {
		/* They don't match */
		return (CRYPTO_INVALID_MAC);
	} else {
		rv = crypto_put_output_data(ctx->gcm_pt_buf, out, pt_len);
		if (rv != CRYPTO_SUCCESS)
			return (rv);
		out->cd_offset += pt_len;
	}
	return (CRYPTO_SUCCESS);
}

static int
gcm_validate_args(CK_AES_GCM_PARAMS *gcm_param)
{
	size_t tag_len;

	/*
	 * Check the length of the authentication tag (in bits).
	 */
	tag_len = gcm_param->ulTagBits;
	switch (tag_len) {
	case 32:
	case 64:
	case 96:
	case 104:
	case 112:
	case 120:
	case 128:
		break;
	default:
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if (gcm_param->ulIvLen == 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	return (CRYPTO_SUCCESS);
}

static void
gcm_format_initial_blocks(uchar_t *iv, ulong_t iv_len,
    gcm_ctx_t *ctx, size_t block_size,
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *cb;
	ulong_t remainder = iv_len;
	ulong_t processed = 0;
	uint8_t *datap, *ghash;
	uint64_t len_a_len_c[2];

	ghash = (uint8_t *)ctx->gcm_ghash;
	cb = (uint8_t *)ctx->gcm_cb;
	if (iv_len == 12) {
		bcopy(iv, cb, 12);
		cb[12] = 0;
		cb[13] = 0;
		cb[14] = 0;
		cb[15] = 1;
		/* J0 will be used again in the final */
		copy_block(cb, (uint8_t *)ctx->gcm_J0);
	} else {
		/* GHASH the IV */
		do {
			if (remainder < block_size) {
				bzero(cb, block_size);
				bcopy(&(iv[processed]), cb, remainder);
				datap = (uint8_t *)cb;
				remainder = 0;
			} else {
				datap = (uint8_t *)(&(iv[processed]));
				processed += block_size;
				remainder -= block_size;
			}
			GHASH(ctx, datap, ghash);
		} while (remainder > 0);

		len_a_len_c[0] = 0;
		len_a_len_c[1] = htonll(CRYPTO_BYTES2BITS(iv_len));
		GHASH(ctx, len_a_len_c, ctx->gcm_J0);

		/* J0 will be used again in the final */
		copy_block((uint8_t *)ctx->gcm_J0, (uint8_t *)cb);
	}
}

/*
 * The following function is called at encrypt or decrypt init time
 * for AES GCM mode.
 */
int
gcm_init(gcm_ctx_t *ctx, unsigned char *iv, size_t iv_len,
    unsigned char *auth_data, size_t auth_data_len, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *ghash, *datap, *authp;
	size_t remainder, processed;

	/* encrypt zero block to get subkey H */
	bzero(ctx->gcm_H, sizeof (ctx->gcm_H));
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_H,
	    (uint8_t *)ctx->gcm_H);

	gcm_format_initial_blocks(iv, iv_len, ctx, block_size,
	    copy_block, xor_block);

	authp = (uint8_t *)ctx->gcm_tmp;
	ghash = (uint8_t *)ctx->gcm_ghash;
	bzero(authp, block_size);
	bzero(ghash, block_size);

	processed = 0;
	remainder = auth_data_len;
	do {
		if (remainder < block_size) {
			if ((ctx->gcm_flags & GMAC_MODE) != 0) {
				/*
				 * GMAC does not encrypt or decrypt, and
				 * therefore doesn't keep any out buffer,
				 * so gcm_remainder holds any remainder
				 * that GMAC needs to handle.
				 */
				bcopy(&(auth_data[processed]),
				    ctx->gcm_remainder, remainder);
				ctx->gcm_remainder_len = remainder;
				break;
			}
			/*
			 * There's not a block full of data, pad rest of
			 * buffer with zero
			 */
			bzero(authp, block_size);
			bcopy(&(auth_data[processed]), authp, remainder);
			datap = (uint8_t *)authp;
			remainder = 0;
		} else {
			datap = (uint8_t *)(&(auth_data[processed]));
			processed += block_size;
			remainder -= block_size;
		}

		/* add auth data to the hash */
		GHASH(ctx, datap, ghash);

	} while (remainder > 0);

	if ((ctx->gcm_flags & GMAC_MODE) != 0) {
		ctx->gcm_len_a_len_c[0] =
		    CRYPTO_BYTES2BITS(auth_data_len - remainder);
	}

	return (CRYPTO_SUCCESS);
}

int
gcm_init_ctx(gcm_ctx_t *gcm_ctx, char *param, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	int rv;
	CK_AES_GCM_PARAMS *gcm_param;

	if (param != NULL) {
		gcm_param = (CK_AES_GCM_PARAMS *)(void *)param;

		if ((rv = gcm_validate_args(gcm_param)) != 0) {
			return (rv);
		}

		gcm_ctx->gcm_tag_len = gcm_param->ulTagBits;
		gcm_ctx->gcm_tag_len >>= 3;
		gcm_ctx->gcm_processed_data_len = 0;

		/* these values are in bits */
		gcm_ctx->gcm_len_a_len_c[0] =
		    CRYPTO_BYTES2BITS(gcm_param->ulAADLen);

		rv = CRYPTO_SUCCESS;
		gcm_ctx->gcm_flags |= GCM_MODE;
	} else {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto out;
	}

	if (gcm_init(gcm_ctx, gcm_param->pIv, gcm_param->ulIvLen,
	    gcm_param->pAAD, gcm_param->ulAADLen, block_size,
	    encrypt_block, copy_block, xor_block) != 0) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
	}
out:
	return (rv);
}

int
gmac_init_ctx(gcm_ctx_t *gcm_ctx, char *param, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	int rv;
	CK_AES_GMAC_PARAMS *gmac_param;

	if (param == NULL)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	gmac_param = (CK_AES_GMAC_PARAMS *)(void *)param;

	gcm_ctx->gcm_tag_len = CRYPTO_BITS2BYTES(AES_GMAC_TAG_BITS);
	gcm_ctx->gcm_processed_data_len = 0;

	/* these values are in bits */
	gcm_ctx->gcm_len_a_len_c[0] = 0;
	gcm_ctx->gcm_len_a_len_c[1] = 0;

	rv = CRYPTO_SUCCESS;
	gcm_ctx->gcm_flags |= GMAC_MODE;

	if (gcm_init(gcm_ctx, gmac_param->pIv, AES_GMAC_IV_LEN,
	    gmac_param->pAAD, gmac_param->ulAADLen, block_size,
	    encrypt_block, copy_block, xor_block) != 0) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
	}

	return (rv);
}

void *
gcm_alloc_ctx(int kmflag)
{
	gcm_ctx_t *gcm_ctx;

	/* Free in crypto_free_mode_ctx() */
#ifdef _KERNEL
	if ((gcm_ctx = kmem_zalloc(sizeof (gcm_ctx_t), kmflag)) == NULL)
#else
	if ((gcm_ctx = calloc(1, sizeof (gcm_ctx_t))) == NULL)
#endif
		return (NULL);

	gcm_ctx->gcm_flags = GCM_MODE;
	return (gcm_ctx);
}

void *
gmac_alloc_ctx(int kmflag)
{
	gcm_ctx_t *gcm_ctx;

	/* Free in crypto_free_mode_ctx() */
#ifdef _KERNEL
	if ((gcm_ctx = kmem_zalloc(sizeof (gcm_ctx_t), kmflag)) == NULL)
#else
	if ((gcm_ctx = calloc(1, sizeof (gcm_ctx_t))) == NULL)
#endif
		return (NULL);

	gcm_ctx->gcm_flags = GMAC_MODE;
	return (gcm_ctx);
}

void
gcm_set_kmflag(gcm_ctx_t *ctx, int kmflag)
{
	ctx->gcm_kmflag = kmflag;
}


#ifdef __amd64
/*
 * Return 1 if executing on Intel with PCLMULQDQ instructions,
 * otherwise 0 (i.e., Intel without PCLMULQDQ or AMD64).
 * Cache the result, as the CPU can't change.
 *
 * Note: the userland version uses getisax().  The kernel version uses
 * is_x86_featureset().
 */
static int
intel_pclmulqdq_instruction_present(void)
{
	static int	cached_result = -1;

	if (cached_result == -1) { /* first time */
#ifdef _KERNEL
		cached_result =
		    is_x86_feature(x86_featureset, X86FSET_PCLMULQDQ);
#else
		uint_t		ui = 0;

		(void) getisax(&ui, 1);
		cached_result = (ui & AV_386_PCLMULQDQ) != 0;
#endif	/* _KERNEL */
	}

	return (cached_result);
}
#endif	/* __amd64 */
