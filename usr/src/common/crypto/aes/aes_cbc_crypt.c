/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <sys/strsun.h>
#include "aes_cbc_crypt.h"
#include "aes_impl.h"
#ifndef	_KERNEL
#include <strings.h>
#endif	/* !_KERNEL */

static int aes_ctr_mode_contiguous_blocks(aes_ctx_t *, char *, size_t,
    crypto_data_t *);

/*
 * Initialize by setting iov_or_mp to point to the current iovec or mp,
 * and by setting current_offset to an offset within the current iovec or mp .
 */
static void
aes_init_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		*current_offset = out->cd_offset;
		break;

	case CRYPTO_DATA_UIO: {
		uio_t *uiop = out->cd_uio;
		uintptr_t vec_idx;

		offset = out->cd_offset;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len);

		*current_offset = offset;
		*iov_or_mp = (void *)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;

		offset = out->cd_offset;
		for (mp = out->cd_mp; mp != NULL && offset >= MBLKL(mp);
			offset -= MBLKL(mp), mp = mp->b_cont);

		*current_offset = offset;
		*iov_or_mp = mp;
		break;

	}
	} /* end switch */
}

/*
 * Get pointers for where in the output to copy a block of encrypted or
 * decrypted data.  The iov_or_mp argument stores a pointer to the current
 * iovec or mp, and offset stores an offset into the current iovec or mp.
 */
static void
aes_get_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset,
    uint8_t **out_data_1, size_t *out_data_1_len, uint8_t **out_data_2,
    size_t amt)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW: {
		iovec_t *iov;

		offset = *current_offset;
		iov = &out->cd_raw;
		if ((offset + amt) <= iov->iov_len) {
			/* one AES block fits */
			*out_data_1 = (uint8_t *)iov->iov_base + offset;
			*out_data_1_len = amt;
			*out_data_2 = NULL;
			*current_offset = offset + amt;
		}
		break;
	}

	case CRYPTO_DATA_UIO: {
		uio_t *uio = out->cd_uio;
		iovec_t *iov;
		offset_t offset;
		uintptr_t vec_idx;
		uint8_t *p;

		offset = *current_offset;
		vec_idx = (uintptr_t)(*iov_or_mp);
		iov = &uio->uio_iov[vec_idx];
		p = (uint8_t *)iov->iov_base + offset;
		*out_data_1 = p;

		if (offset + amt <= iov->iov_len) {
			/* can fit one AES block into this iov */
			*out_data_1_len = amt;
			*out_data_2 = NULL;
			*current_offset = offset + amt;
		} else {
			/* one AES block spans two iovecs */
			*out_data_1_len = iov->iov_len - offset;
			if (vec_idx == uio->uio_iovcnt)
				return;
			vec_idx++;
			iov = &uio->uio_iov[vec_idx];
			*out_data_2 = (uint8_t *)iov->iov_base;
			*current_offset = amt - *out_data_1_len;
		}
		*iov_or_mp = (void *)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;
		uint8_t *p;

		offset = *current_offset;
		mp = (mblk_t *)*iov_or_mp;
		p = mp->b_rptr + offset;
		*out_data_1 = p;
		if ((p + amt) <= mp->b_wptr) {
			/* can fit one AES block into this mblk */
			*out_data_1_len = amt;
			*out_data_2 = NULL;
			*current_offset = offset + amt;
		} else {
			/* one AES block spans two mblks */
			*out_data_1_len = mp->b_wptr - p;
			if ((mp = mp->b_cont) == NULL)
				return;
			*out_data_2 = mp->b_rptr;
			*current_offset = (amt - *out_data_1_len);
		}
		*iov_or_mp = mp;
		break;
	}
	} /* end switch */
}

static int
aes_cbc_encrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{

/* EXPORT DELETE START */

	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[4];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->ac_remainder_len < AES_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->ac_remainder + ctx->ac_remainder_len,
		    length);
		ctx->ac_remainder_len += length;
		ctx->ac_copy_to = datap;
		return (0);
	}

	lastp = (uint8_t *)ctx->ac_iv;
	if (out != NULL)
		aes_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->ac_remainder_len > 0) {
			need = AES_BLOCK_LEN - ctx->ac_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)ctx->ac_remainder)
			    [ctx->ac_remainder_len], need);

			blockp = (uint8_t *)ctx->ac_remainder;
		} else {
			blockp = datap;
		}

		/* don't write on the plaintext */
		if (out != NULL) {
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				tmp[0] = *(uint32_t *)blockp;
				/* LINTED: pointer alignment */
				tmp[1] = *(uint32_t *)&blockp[4];
				/* LINTED: pointer alignment */
				tmp[2] = *(uint32_t *)&blockp[8];
				/* LINTED: pointer alignment */
				tmp[3] = *(uint32_t *)&blockp[12];
			} else {
				uint8_t *tmp8 = (uint8_t *)tmp;

				AES_COPY_BLOCK(blockp, tmp8);
			}
			blockp = (uint8_t *)tmp;
		}

		if (ctx->ac_flags & AES_CBC_MODE) {
			/*
			 * XOR the previous cipher block or IV with the
			 * current clear block. Check for alignment.
			 */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(lastp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[0] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[0];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[4] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[4];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[8] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[8];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[12] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[12];
			} else {
				AES_XOR_BLOCK(lastp, blockp);
			}
		}

		if (out == NULL) {
			aes_encrypt_block(ctx->ac_keysched, blockp, blockp);

			ctx->ac_lastp = blockp;
			lastp = blockp;

			if (ctx->ac_remainder_len > 0) {
				bcopy(blockp, ctx->ac_copy_to,
				    ctx->ac_remainder_len);
				bcopy(blockp + ctx->ac_remainder_len, datap,
				    need);
			}
		} else {
			aes_encrypt_block(ctx->ac_keysched, blockp, lastp);
			aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2, AES_BLOCK_LEN);

			/* copy block to where it belongs */
			bcopy(lastp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(lastp + out_data_1_len, out_data_2,
				    AES_BLOCK_LEN - out_data_1_len);
			}
			/* update offset */
			out->cd_offset += AES_BLOCK_LEN;
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->ac_remainder_len != 0) {
			datap += need;
			ctx->ac_remainder_len = 0;
		} else {
			datap += AES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < AES_BLOCK_LEN) {
			bcopy(datap, ctx->ac_remainder, remainder);
			ctx->ac_remainder_len = remainder;
			ctx->ac_copy_to = datap;
			goto out;
		}
		ctx->ac_copy_to = NULL;

	} while (remainder > 0);

out:
	/*
	 * Save the last encrypted block in the context - but only for
	 * the CBC mode of operation.
	 */
	if ((ctx->ac_flags & AES_CBC_MODE) && (ctx->ac_lastp != NULL)) {
		uint8_t *iv8 = (uint8_t *)ctx->ac_iv;
		uint8_t *last8 = (uint8_t *)ctx->ac_lastp;

		if (IS_P2ALIGNED(ctx->ac_lastp, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)iv8 = *(uint32_t *)last8;
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[4] = *(uint32_t *)&last8[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[8] = *(uint32_t *)&last8[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[12] = *(uint32_t *)&last8[12];
		} else {
			AES_COPY_BLOCK(last8, iv8);
		}
		ctx->ac_lastp = (uint8_t *)ctx->ac_iv;
	}

/* EXPORT DELETE END */

	return (0);
}

#define	OTHER(a, ctx) \
	(((a) == (ctx)->ac_lastblock) ? (ctx)->ac_iv : (ctx)->ac_lastblock)

/*
 * Encrypt multiple blocks of data.
 */
/* ARGSUSED */
int
aes_encrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	if (ctx->ac_flags & AES_CTR_MODE)
		return (aes_ctr_mode_contiguous_blocks(ctx, data, length, out));
	return (aes_cbc_encrypt_contiguous_blocks(ctx, data, length, out));
}

/* ARGSUSED */
static int
aes_cbc_decrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{

/* EXPORT DELETE START */

	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[4];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->ac_remainder_len < AES_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->ac_remainder + ctx->ac_remainder_len,
		    length);
		ctx->ac_remainder_len += length;
		ctx->ac_copy_to = datap;
		return (0);
	}

	lastp = ctx->ac_lastp;
	if (out != NULL)
		aes_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->ac_remainder_len > 0) {
			need = AES_BLOCK_LEN - ctx->ac_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)ctx->ac_remainder)
			    [ctx->ac_remainder_len], need);

			blockp = (uint8_t *)ctx->ac_remainder;
		} else {
			blockp = datap;
		}

		if (ctx->ac_flags & AES_CBC_MODE) {

			/* Save current ciphertext block */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t))) {
				uint32_t *tmp32;

				/* LINTED: pointer alignment */
				tmp32 = (uint32_t *)OTHER((uint64_t *)lastp,
				    ctx);

				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)blockp;
				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)&blockp[4];
				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)&blockp[8];
				/* LINTED: pointer alignment */
				*tmp32++ = *(uint32_t *)&blockp[12];
			} else {
				uint8_t *tmp8;
				/* LINTED: pointer alignment */
				tmp8 = (uint8_t *)OTHER((uint64_t *)lastp, ctx);

				AES_COPY_BLOCK(blockp, tmp8);
			}
		}

		if (out != NULL) {
			aes_decrypt_block(ctx->ac_keysched, blockp,
			    (uint8_t *)tmp);
			blockp = (uint8_t *)tmp;
		} else {
			aes_decrypt_block(ctx->ac_keysched, blockp, blockp);
		}

		if (ctx->ac_flags & AES_CBC_MODE) {
			/*
			 * XOR the previous cipher block or IV with the
			 * currently decrypted block.  Check for alignment.
			 */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(lastp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)blockp ^= *(uint32_t *)lastp;
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[4] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[4];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[8] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[8];
				/* LINTED: pointer alignment */
				*(uint32_t *)&blockp[12] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&lastp[12];
			} else {
				AES_XOR_BLOCK(lastp, blockp);
			}

			/* LINTED: pointer alignment */
			lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);
		}

		if (out != NULL) {
			aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2, AES_BLOCK_LEN);

			/* copy temporary block to where it belongs */
			bcopy(&tmp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy((uint8_t *)&tmp + out_data_1_len,
				    out_data_2, AES_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += AES_BLOCK_LEN;

		} else if (ctx->ac_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->ac_copy_to, ctx->ac_remainder_len);
			bcopy(blockp + ctx->ac_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->ac_remainder_len != 0) {
			datap += need;
			ctx->ac_remainder_len = 0;
		} else {
			datap += AES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < AES_BLOCK_LEN) {
			bcopy(datap, ctx->ac_remainder, remainder);
			ctx->ac_remainder_len = remainder;
			ctx->ac_lastp = lastp;
			ctx->ac_copy_to = datap;
			return (0);
		}
		ctx->ac_copy_to = NULL;

	} while (remainder > 0);

	ctx->ac_lastp = lastp;

/* EXPORT DELETE END */

	return (0);
}

/*
 * Decrypt multiple blocks of data.
 */
int
aes_decrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	if (ctx->ac_flags & AES_CTR_MODE)
		return (aes_ctr_mode_contiguous_blocks(ctx, data, length, out));
	return (aes_cbc_decrypt_contiguous_blocks(ctx, data, length, out));
}

/* ARGSUSED */
int
aes_counter_final(aes_ctx_t *ctx, crypto_data_t *out)
{
/* EXPORT DELETE START */

	uint8_t *lastp;
	uint32_t counter_block[4];
	uint8_t tmp[AES_BLOCK_LEN];
	int i;
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (out->cd_length < ctx->ac_remainder_len)
		return (CRYPTO_ARGUMENTS_BAD);

	/* ac_iv is the counter block */
	aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_iv,
	    (uint8_t *)counter_block);

	lastp = (uint8_t *)counter_block;

	/* copy remainder to temporary buffer */
	bcopy(ctx->ac_remainder, tmp, ctx->ac_remainder_len);

	/* XOR with counter block */
	for (i = 0; i < ctx->ac_remainder_len; i++) {
		tmp[i] ^= lastp[i];
	}

	aes_init_ptrs(out, &iov_or_mp, &offset);
	aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
	    &out_data_1_len, &out_data_2, ctx->ac_remainder_len);

	/* copy temporary block to where it belongs */
	bcopy(tmp, out_data_1, out_data_1_len);
	if (out_data_2 != NULL) {
		bcopy((uint8_t *)tmp + out_data_1_len,
		    out_data_2, ctx->ac_remainder_len - out_data_1_len);
	}
	out->cd_offset += ctx->ac_remainder_len;
	ctx->ac_remainder_len = 0;

/* EXPORT DELETE END */

	return (0);
}

/*
 * Encrypt and decrypt multiple blocks of data in counter mode.
 */
/* ARGSUSED */
int
aes_ctr_mode_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{

/* EXPORT DELETE START */

	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[4];
	uint32_t counter_block[4];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;
	uint64_t counter;
#ifdef _LITTLE_ENDIAN
	uint8_t *p;
#endif

	if (length + ctx->ac_remainder_len < AES_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->ac_remainder + ctx->ac_remainder_len,
		    length);
		ctx->ac_remainder_len += length;
		ctx->ac_copy_to = datap;
		return (0);
	}

	lastp = (uint8_t *)ctx->ac_cb;
	if (out != NULL)
		aes_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->ac_remainder_len > 0) {
			need = AES_BLOCK_LEN - ctx->ac_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)ctx->ac_remainder)
			    [ctx->ac_remainder_len], need);

			blockp = (uint8_t *)ctx->ac_remainder;
		} else {
			blockp = datap;
		}

		/* don't write on the plaintext */
		if (out != NULL) {
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				tmp[0] = *(uint32_t *)blockp;
				/* LINTED: pointer alignment */
				tmp[1] = *(uint32_t *)&blockp[4];
				/* LINTED: pointer alignment */
				tmp[2] = *(uint32_t *)&blockp[8];
				/* LINTED: pointer alignment */
				tmp[3] = *(uint32_t *)&blockp[12];
			} else {
				uint8_t *tmp8 = (uint8_t *)tmp;

				AES_COPY_BLOCK(blockp, tmp8);
			}
			blockp = (uint8_t *)tmp;
		}


		/* ac_cb is the counter block */
		aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_cb,
		    (uint8_t *)counter_block);

		lastp = (uint8_t *)counter_block;

		/*
		 * Increment counter. Counter bits are confined
		 * to the bottom 64 bits of the counter block.
		 */
		counter = ctx->ac_cb[1] & ctx->ac_counter_mask;
#ifdef _LITTLE_ENDIAN
		p = (uint8_t *)&counter;
		counter = (((uint64_t)p[0] << 56) |
		    ((uint64_t)p[1] << 48) |
		    ((uint64_t)p[2] << 40) |
		    ((uint64_t)p[3] << 32) |
		    ((uint64_t)p[4] << 24) |
		    ((uint64_t)p[5] << 16) |
		    ((uint64_t)p[6] << 8) |
		    (uint64_t)p[7]);
#endif
		counter++;
#ifdef _LITTLE_ENDIAN
		counter = (((uint64_t)p[0] << 56) |
		    ((uint64_t)p[1] << 48) |
		    ((uint64_t)p[2] << 40) |
		    ((uint64_t)p[3] << 32) |
		    ((uint64_t)p[4] << 24) |
		    ((uint64_t)p[5] << 16) |
		    ((uint64_t)p[6] << 8) |
		    (uint64_t)p[7]);
#endif
		counter &= ctx->ac_counter_mask;
		ctx->ac_cb[1] =
		    (ctx->ac_cb[1] & ~(ctx->ac_counter_mask)) | counter;

		/*
		 * XOR the previous cipher block or IV with the
		 * current clear block. Check for alignment.
		 */
		if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(lastp, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[0] ^=
			/* LINTED: pointer alignment */
			    *(uint32_t *)&lastp[0];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[4] ^=
			/* LINTED: pointer alignment */
			    *(uint32_t *)&lastp[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[8] ^=
			/* LINTED: pointer alignment */
			    *(uint32_t *)&lastp[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[12] ^=
			/* LINTED: pointer alignment */
			    *(uint32_t *)&lastp[12];
		} else {
			AES_XOR_BLOCK(lastp, blockp);
		}

		ctx->ac_lastp = blockp;
		lastp = blockp;

		if (out == NULL) {
			if (ctx->ac_remainder_len > 0) {
				bcopy(blockp, ctx->ac_copy_to,
				    ctx->ac_remainder_len);
				bcopy(blockp + ctx->ac_remainder_len, datap,
				    need);
			}
		} else {
			aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2, AES_BLOCK_LEN);

			/* copy block to where it belongs */
			bcopy(lastp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(lastp + out_data_1_len, out_data_2,
				    AES_BLOCK_LEN - out_data_1_len);
			}
			/* update offset */
			out->cd_offset += AES_BLOCK_LEN;
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->ac_remainder_len != 0) {
			datap += need;
			ctx->ac_remainder_len = 0;
		} else {
			datap += AES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < AES_BLOCK_LEN) {
			bcopy(datap, ctx->ac_remainder, remainder);
			ctx->ac_remainder_len = remainder;
			ctx->ac_copy_to = datap;
			goto out;
		}
		ctx->ac_copy_to = NULL;

	} while (remainder > 0);

out:

/* EXPORT DELETE END */

	return (0);
}
