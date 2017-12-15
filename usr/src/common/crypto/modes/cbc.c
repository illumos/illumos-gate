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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _KERNEL
#include <strings.h>
#include <limits.h>
#include <assert.h>
#include <security/cryptoki.h>
#endif

#include <sys/debug.h>
#include <sys/types.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <aes/aes_impl.h>

/* These are the CMAC Rb constants from NIST SP 800-38B */
#define	CONST_RB_128	0x87
#define	CONST_RB_64	0x1B

/*
 * Algorithm independent CBC functions.
 */
int
cbc_encrypt_contiguous_blocks(cbc_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->cbc_remainder_len < ctx->max_remain) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->cbc_remainder + ctx->cbc_remainder_len,
		    length);
		ctx->cbc_remainder_len += length;
		ctx->cbc_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	lastp = (uint8_t *)ctx->cbc_iv;
	if (out != NULL)
		crypto_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->cbc_remainder_len > 0) {
			need = block_size - ctx->cbc_remainder_len;

			if (need > remainder)
				return (CRYPTO_DATA_LEN_RANGE);

			bcopy(datap, &((uint8_t *)ctx->cbc_remainder)
			    [ctx->cbc_remainder_len], need);

			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			blockp = datap;
		}

		if (out == NULL) {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block.
			 */
			xor_block(lastp, blockp);
			encrypt(ctx->cbc_keysched, blockp, blockp);

			ctx->cbc_lastp = blockp;
			lastp = blockp;

			if ((ctx->cbc_flags & CMAC_MODE) == 0 &&
			    ctx->cbc_remainder_len > 0) {
				bcopy(blockp, ctx->cbc_copy_to,
				    ctx->cbc_remainder_len);
				bcopy(blockp + ctx->cbc_remainder_len, datap,
				    need);
			}
		} else {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block.
			 */
			xor_block(blockp, lastp);
			encrypt(ctx->cbc_keysched, lastp, lastp);

			/*
			 * CMAC doesn't output until encrypt_final
			 */
			if ((ctx->cbc_flags & CMAC_MODE) == 0) {
				crypto_get_ptrs(out, &iov_or_mp, &offset,
				    &out_data_1, &out_data_1_len,
				    &out_data_2, block_size);

				/* copy block to where it belongs */
				if (out_data_1_len == block_size) {
					copy_block(lastp, out_data_1);
				} else {
					bcopy(lastp, out_data_1,
					    out_data_1_len);
					if (out_data_2 != NULL) {
						bcopy(lastp + out_data_1_len,
						    out_data_2,
						    block_size -
						    out_data_1_len);
					}
				}
				/* update offset */
				out->cd_offset += block_size;
			}
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->cbc_remainder_len != 0) {
			datap += need;
			ctx->cbc_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < ctx->max_remain) {
			bcopy(datap, ctx->cbc_remainder, remainder);
			ctx->cbc_remainder_len = remainder;
			ctx->cbc_copy_to = datap;
			goto out;
		}
		ctx->cbc_copy_to = NULL;

	} while (remainder > 0);

out:
	/*
	 * Save the last encrypted block in the context.
	 */
	if (ctx->cbc_lastp != NULL) {
		copy_block((uint8_t *)ctx->cbc_lastp, (uint8_t *)ctx->cbc_iv);
		ctx->cbc_lastp = (uint8_t *)ctx->cbc_iv;
	}

	return (CRYPTO_SUCCESS);
}

#define	OTHER(a, ctx) \
	(((a) == (ctx)->cbc_lastblock) ? (ctx)->cbc_iv : (ctx)->cbc_lastblock)

/* ARGSUSED */
int
cbc_decrypt_contiguous_blocks(cbc_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->cbc_remainder_len < block_size) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->cbc_remainder + ctx->cbc_remainder_len,
		    length);
		ctx->cbc_remainder_len += length;
		ctx->cbc_copy_to = datap;
		return (CRYPTO_SUCCESS);
	}

	lastp = ctx->cbc_lastp;
	if (out != NULL)
		crypto_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->cbc_remainder_len > 0) {
			need = block_size - ctx->cbc_remainder_len;

			if (need > remainder)
				return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

			bcopy(datap, &((uint8_t *)ctx->cbc_remainder)
			    [ctx->cbc_remainder_len], need);

			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			blockp = datap;
		}

		/* LINTED: pointer alignment */
		copy_block(blockp, (uint8_t *)OTHER((uint64_t *)lastp, ctx));

		if (out != NULL) {
			decrypt(ctx->cbc_keysched, blockp,
			    (uint8_t *)ctx->cbc_remainder);
			blockp = (uint8_t *)ctx->cbc_remainder;
		} else {
			decrypt(ctx->cbc_keysched, blockp, blockp);
		}

		/*
		 * XOR the previous cipher block or IV with the
		 * currently decrypted block.
		 */
		xor_block(lastp, blockp);

		/* LINTED: pointer alignment */
		lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);

		if (out != NULL) {
			crypto_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2, block_size);

			bcopy(blockp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(blockp + out_data_1_len, out_data_2,
				    block_size - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += block_size;

		} else if (ctx->cbc_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->cbc_copy_to, ctx->cbc_remainder_len);
			bcopy(blockp + ctx->cbc_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->cbc_remainder_len != 0) {
			datap += need;
			ctx->cbc_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < block_size) {
			bcopy(datap, ctx->cbc_remainder, remainder);
			ctx->cbc_remainder_len = remainder;
			ctx->cbc_lastp = lastp;
			ctx->cbc_copy_to = datap;
			return (CRYPTO_SUCCESS);
		}
		ctx->cbc_copy_to = NULL;

	} while (remainder > 0);

	ctx->cbc_lastp = lastp;
	return (CRYPTO_SUCCESS);
}

int
cbc_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *))
{
	/*
	 * Copy IV into context.
	 *
	 * If cm_param == NULL then the IV comes from the
	 * cd_miscdata field in the crypto_data structure.
	 */
	if (param != NULL) {
#ifdef _KERNEL
		ASSERT(param_len == block_size);
#else
		assert(param_len == block_size);
#endif
		copy_block((uchar_t *)param, cbc_ctx->cbc_iv);
	}

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_flags |= CBC_MODE;
	cbc_ctx->max_remain = block_size;
	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static void *
cbc_cmac_alloc_ctx(int kmflag, uint32_t mode)
{
	cbc_ctx_t *cbc_ctx;
	uint32_t modeval = mode & (CBC_MODE|CMAC_MODE);

	/* Only one of the two modes can be set */
	VERIFY(modeval == CBC_MODE || modeval == CMAC_MODE);

#ifdef _KERNEL
	if ((cbc_ctx = kmem_zalloc(sizeof (cbc_ctx_t), kmflag)) == NULL)
#else
	if ((cbc_ctx = calloc(1, sizeof (cbc_ctx_t))) == NULL)
#endif
		return (NULL);

	cbc_ctx->cbc_flags = mode;
	return (cbc_ctx);
}

void *
cbc_alloc_ctx(int kmflag)
{
	return (cbc_cmac_alloc_ctx(kmflag, CBC_MODE));
}

/*
 * Algorithms for supporting AES-CMAC
 * NOTE: CMAC is generally just a wrapper for CBC
 */

void *
cmac_alloc_ctx(int kmflag)
{
	return (cbc_cmac_alloc_ctx(kmflag, CMAC_MODE));
}


/*
 * Typically max_remain is set to block_size - 1, since we usually
 * will process the data once we have a full block.  However with CMAC,
 * we must preprocess the final block of data.  Since we cannot know
 * when we've received the final block of data until the _final() method
 * is called, we must not process the last block of data until we know
 * it is the last block, or we receive a new block of data.  As such,
 * max_remain for CMAC is block_size + 1.
 */
int
cmac_init_ctx(cbc_ctx_t *cbc_ctx, size_t block_size)
{
	/*
	 * CMAC is only approved for block sizes 64 and 128 bits /
	 * 8 and 16 bytes.
	 */

	if (block_size != 16 && block_size != 8)
		return (CRYPTO_INVALID_CONTEXT);

	/*
	 * For CMAC, cbc_iv is always 0.
	 */

	cbc_ctx->cbc_iv[0] = 0;
	cbc_ctx->cbc_iv[1] = 0;

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_flags |= CMAC_MODE;

	cbc_ctx->max_remain = block_size + 1;
	return (CRYPTO_SUCCESS);
}

/*
 * Left shifts blocks by one and returns the leftmost bit
 */
static uint8_t
cmac_left_shift_block_by1(uint8_t *block, size_t block_size)
{
	uint8_t carry = 0, old;
	size_t i;
	for (i = block_size; i > 0; i--) {
		old = carry;
		carry = (block[i - 1] & 0x80) ? 1 : 0;
		block[i - 1] = (block[i - 1] << 1) | old;
	}
	return (carry);
}

/*
 * Generate subkeys to preprocess the last block according to RFC 4493.
 * Store the final block_size MAC generated in 'out'.
 */
int
cmac_mode_final(cbc_ctx_t *cbc_ctx, crypto_data_t *out,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t buf[AES_BLOCK_LEN] = {0};
	uint8_t *M_last = (uint8_t *)cbc_ctx->cbc_remainder;
	size_t length = cbc_ctx->cbc_remainder_len;
	size_t block_size = cbc_ctx->max_remain - 1;
	uint8_t const_rb;

	if (length > block_size)
		return (CRYPTO_INVALID_CONTEXT);

	if (out->cd_length < block_size)
		return (CRYPTO_DATA_LEN_RANGE);

	if (block_size == 16)
		const_rb = CONST_RB_128;
	else if (block_size == 8)
		const_rb = CONST_RB_64;
	else
		return (CRYPTO_INVALID_CONTEXT);

	/* k_0 = E_k(0) */
	encrypt_block(cbc_ctx->cbc_keysched, buf, buf);

	if (cmac_left_shift_block_by1(buf, block_size))
		buf[block_size - 1] ^= const_rb;

	if (length == block_size) {
		/* Last block complete, so m_n = k_1 + m_n' */
		xor_block(buf, M_last);
		xor_block(cbc_ctx->cbc_lastp, M_last);
		encrypt_block(cbc_ctx->cbc_keysched, M_last, M_last);
	} else {
		/* Last block incomplete, so m_n = k_2 + (m_n' | 100...0_bin) */
		if (cmac_left_shift_block_by1(buf, block_size))
			buf[block_size - 1] ^= const_rb;

		M_last[length] = 0x80;
		bzero(M_last + length + 1, block_size - length - 1);
		xor_block(buf, M_last);
		xor_block(cbc_ctx->cbc_lastp, M_last);
		encrypt_block(cbc_ctx->cbc_keysched, M_last, M_last);
	}

	/*
	 * zero out the sub-key.
	 */
#ifndef _KERNEL
	explicit_bzero(&buf, sizeof (buf));
#else
	bzero(&buf, sizeof (buf));
#endif
	return (crypto_put_output_data(M_last, out, block_size));
}
