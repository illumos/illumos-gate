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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <sys/strsun.h>
#include "aes_cbc_crypt.h"
#include "aes_impl.h"
#ifndef	_KERNEL
#include <limits.h>
#include <strings.h>
#endif	/* !_KERNEL */

static int aes_ctr_ccm_mode_contiguous_blocks(aes_ctx_t *, char *, size_t,
    crypto_data_t *);
static void
encode_adata_len(ulong_t auth_data_len, uint8_t *encoded, size_t *encoded_len);
static void
aes_ccm_format_initial_blocks(uchar_t *nonce, ulong_t nonceSize,
    ulong_t authDataSize, uint8_t *b0, aes_ctx_t *aes_ctx);
static int
aes_ccm_decrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out);

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
		    offset -= uiop->uio_iov[vec_idx++].iov_len)
			;

		*current_offset = offset;
		*iov_or_mp = (void *)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;

		offset = out->cd_offset;
		for (mp = out->cd_mp; mp != NULL && offset >= MBLKL(mp);
		    offset -= MBLKL(mp), mp = mp->b_cont)
			;

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
		return (aes_ctr_ccm_mode_contiguous_blocks(ctx, data, length,
		    out));
	else if (ctx->ac_flags & AES_CCM_MODE)
		return (aes_ctr_ccm_mode_contiguous_blocks(ctx, data, length,
		    out));
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
		return (aes_ctr_ccm_mode_contiguous_blocks(ctx, data, length,
		    out));
	else if (ctx->ac_flags & AES_CCM_MODE)
		return (aes_ccm_decrypt_contiguous_blocks(ctx, data, length,
		    out));
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
 * Encrypt multiple blocks of data in CCM mode.  Decrypt for CCM mode
 * is done in another function.
 */
/* ARGSUSED */
int
aes_ctr_ccm_mode_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
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
	uint8_t *mac_buf;
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

	if (ctx->ac_flags & AES_CCM_MODE) {
		mac_buf = (uint8_t *)ctx->ac_ccm_mac_buf;
	}

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

		if (ctx->ac_flags & AES_CCM_MODE) {
			/*
			 * do CBC MAC
			 *
			 * XOR the previous cipher block current clear block.
			 * mac_buf always contain previous cipher block.
			 */
			if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)&mac_buf[0] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&blockp[0];
				/* LINTED: pointer alignment */
				*(uint32_t *)&mac_buf[4] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&blockp[4];
				/* LINTED: pointer alignment */
				*(uint32_t *)&mac_buf[8] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&blockp[8];
				/* LINTED: pointer alignment */
				*(uint32_t *)&mac_buf[12] ^=
				/* LINTED: pointer alignment */
				    *(uint32_t *)&blockp[12];
			} else {
				AES_XOR_BLOCK(blockp, mac_buf);
			}
			aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);
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
		if (ctx->ac_flags & AES_CCM_MODE) {
			ctx->ac_ccm_processed_data_len += AES_BLOCK_LEN;
		}

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

/*
 * The following function should be call at encrypt or decrypt init time
 * for AES CCM mode.
 */
int
aes_ccm_init(aes_ctx_t *ctx, unsigned char *nonce, size_t nonce_len,
    unsigned char *auth_data, size_t auth_data_len)
{
/* EXPORT DELETE START */
	uint8_t *mac_buf, *datap, *ivp, *authp;
	uint32_t iv[4], tmp[4];
	size_t remainder, processed;
	uint8_t encoded_a[10]; /* max encoded auth data length is 10 octets */
	size_t encoded_a_len = 0;

	mac_buf = (uint8_t *)&(ctx->ac_ccm_mac_buf);

	/*
	 * Format the 1st block for CBC-MAC and construct the
	 * 1st counter block.
	 *
	 * aes_ctx->ac_iv is used for storing the counter block
	 * mac_buf will store b0 at this time.
	 */
	aes_ccm_format_initial_blocks(nonce, nonce_len,
	    auth_data_len, mac_buf, ctx);

	/* The IV for CBC MAC for AES CCM mode is always zero */
	bzero(iv, AES_BLOCK_LEN);
	ivp = (uint8_t *)iv;

	if (IS_P2ALIGNED(ivp, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[0] ^= *(uint32_t *)&ivp[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[4] ^= *(uint32_t *)&ivp[4];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[8] ^= *(uint32_t *)&ivp[8];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[12] ^= *(uint32_t *)&ivp[12];
	} else {
		AES_XOR_BLOCK(ivp, mac_buf);
	}

	/* encrypt the nonce */
	aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);

	/* take care of the associated data, if any */
	if (auth_data_len == 0) {
		return (0);
	}

	encode_adata_len(auth_data_len, encoded_a, &encoded_a_len);

	remainder = auth_data_len;

	/* 1st block: it contains encoded associated data, and some data */
	authp = (uint8_t *)tmp;
	bzero(authp, AES_BLOCK_LEN);
	bcopy(encoded_a, authp, encoded_a_len);
	processed = AES_BLOCK_LEN - encoded_a_len;
	if (processed > auth_data_len) {
		/* in case auth_data is very small */
		processed = auth_data_len;
	}
	bcopy(auth_data, authp+encoded_a_len, processed);
	/* xor with previous buffer */
	if (IS_P2ALIGNED(authp, sizeof (uint32_t)) &&
	    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[0] ^= *(uint32_t *)&authp[0];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[4] ^= *(uint32_t *)&authp[4];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[8] ^= *(uint32_t *)&authp[8];
		/* LINTED: pointer alignment */
		*(uint32_t *)&mac_buf[12] ^= *(uint32_t *)&authp[12];
	} else {
		AES_XOR_BLOCK(authp, mac_buf);
	}
	aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);
	remainder -= processed;
	if (remainder == 0) {
		/* a small amount of associated data, it's all done now */
		return (0);
	}

	do {
		if (remainder < AES_BLOCK_LEN) {
			/*
			 * There's not a block full of data, pad rest of
			 * buffer with zero
			 */
			bzero(authp, AES_BLOCK_LEN);
			bcopy(&(auth_data[processed]), authp, remainder);
			datap = (uint8_t *)authp;
			remainder = 0;
		} else {
			datap = (uint8_t *)(&(auth_data[processed]));
			processed += AES_BLOCK_LEN;
			remainder -= AES_BLOCK_LEN;
		}

		/* xor with previous buffer */
		if (IS_P2ALIGNED(datap, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[0] ^= *(uint32_t *)&datap[0];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[4] ^= *(uint32_t *)&datap[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[8] ^= *(uint32_t *)&datap[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[12] ^= *(uint32_t *)&datap[12];
		} else {
			AES_XOR_BLOCK(datap, mac_buf);
		}

		aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);

	} while (remainder > 0);

/* EXPORT DELETE END */
	return (0);
}

void
calculate_ccm_mac(aes_ctx_t *ctx, uint8_t **ccm_mac)
{
/* EXPORT DELETE START */
	uint64_t counter;
	uint32_t counter_block[4];
	uint8_t *counterp, *mac_buf;
	int i;

	mac_buf = (uint8_t *)ctx->ac_ccm_mac_buf;

	/* first counter block start with index 0 */
	counter = 0;
	ctx->ac_cb[1] = (ctx->ac_cb[1] & ~(ctx->ac_counter_mask)) | counter;

	aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_cb,
	    (uint8_t *)counter_block);

	counterp = (uint8_t *)counter_block;

	/* calculate XOR of MAC with first counter block */
	for (i = 0; i < ctx->ac_ccm_mac_len; i++) {
		(*ccm_mac)[i] = mac_buf[i] ^ counterp[i];
	}
/* EXPORT DELETE END */
}

/* ARGSUSED */
int
aes_ccm_encrypt_final(aes_ctx_t *ctx, crypto_data_t *out)
{
/* EXPORT DELETE START */

	uint8_t *lastp, *mac_buf, *ccm_mac_p, *macp;
	uint32_t counter_block[4];
	uint32_t tmp[4];
	uint8_t ccm_mac[AES_BLOCK_LEN];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;
	int i;

	if (out->cd_length < (ctx->ac_remainder_len + ctx->ac_ccm_mac_len)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * When we get here, the number of bytes of payload processed
	 * plus whatever data remains, if any,
	 * should be the same as the number of bytes that's being
	 * passed in the argument during init time.
	 */
	if ((ctx->ac_ccm_processed_data_len + ctx->ac_remainder_len)
	    != (ctx->ac_ccm_data_len)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	mac_buf = (uint8_t *)ctx->ac_ccm_mac_buf;

	if (ctx->ac_remainder_len > 0) {

		macp = (uint8_t *)tmp;
		bzero(macp, AES_BLOCK_LEN);

		/* copy remainder to temporary buffer */
		bcopy(ctx->ac_remainder, macp, ctx->ac_remainder_len);

		/* calculate the CBC MAC */
		if (IS_P2ALIGNED(macp, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[0] ^= *(uint32_t *)&macp[0];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[4] ^= *(uint32_t *)&macp[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[8] ^= *(uint32_t *)&macp[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[12] ^= *(uint32_t *)&macp[12];
		} else {
			AES_XOR_BLOCK(macp, mac_buf);
		}
		aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);

		/* calculate the counter mode */
		aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_cb,
		    (uint8_t *)counter_block);

		lastp = (uint8_t *)counter_block;

		/* copy remainder to temporary buffer */
		bcopy(ctx->ac_remainder, macp, ctx->ac_remainder_len);

		/* XOR with counter block */
		for (i = 0; i < ctx->ac_remainder_len; i++) {
			macp[i] ^= lastp[i];
		}
		ctx->ac_ccm_processed_data_len += ctx->ac_remainder_len;
	}

	/* Calculate the CCM MAC */
	ccm_mac_p = ccm_mac;
	calculate_ccm_mac(ctx, &ccm_mac_p);

	aes_init_ptrs(out, &iov_or_mp, &offset);
	aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
	    &out_data_1_len, &out_data_2,
	    ctx->ac_remainder_len + ctx->ac_ccm_mac_len);

	if (ctx->ac_remainder_len > 0) {

		/* copy temporary block to where it belongs */
		if (out_data_2 == NULL) {
			/* everything will fit in out_data_1 */
			bcopy(macp, out_data_1, ctx->ac_remainder_len);
			bcopy(ccm_mac, out_data_1 + ctx->ac_remainder_len,
			    ctx->ac_ccm_mac_len);
		} else {

			if (out_data_1_len < ctx->ac_remainder_len) {

				size_t data_2_len_used;

				bcopy(macp, out_data_1, out_data_1_len);

				data_2_len_used = ctx->ac_remainder_len
				    - out_data_1_len;

				bcopy((uint8_t *)macp + out_data_1_len,
				    out_data_2, data_2_len_used);
				bcopy(ccm_mac, out_data_2 + data_2_len_used,
				    ctx->ac_ccm_mac_len);
			} else {
				bcopy(macp, out_data_1, out_data_1_len);
				if (out_data_1_len == ctx->ac_remainder_len) {
					/* mac will be in out_data_2 */
					bcopy(ccm_mac, out_data_2,
					    ctx->ac_ccm_mac_len);
				} else {
					size_t len_not_used
					    = out_data_1_len -
					    ctx->ac_remainder_len;
					/*
					 * part of mac in will be in
					 * out_data_1, part of the mac will be
					 * in out_data_2
					 */
					bcopy(ccm_mac,
					    out_data_1 + ctx->ac_remainder_len,
					    len_not_used);
					bcopy(ccm_mac+len_not_used, out_data_2,
					    ctx->ac_ccm_mac_len - len_not_used);

				}
			}
		}
	} else {
		/* copy block to where it belongs */
		bcopy(ccm_mac, out_data_1, out_data_1_len);
		if (out_data_2 != NULL) {
			bcopy(ccm_mac + out_data_1_len, out_data_2,
			    AES_BLOCK_LEN - out_data_1_len);
		}
	}
	out->cd_offset += ctx->ac_remainder_len + ctx->ac_ccm_mac_len;
	ctx->ac_remainder_len = 0;

/* EXPORT DELETE END */

	return (0);
}

int
aes_ccm_validate_args(CK_AES_CCM_PARAMS *ccm_param, boolean_t is_encrypt_init)
{

/* EXPORT DELETE START */
	size_t macSize, nonceSize;
	uint8_t q;
	uint64_t maxValue;

	/*
	 * Check the length of the MAC.  Only valid length
	 * lengths for the MAC are: 4, 6, 8, 10, 12, 14, 16
	 */
	macSize = ccm_param->ulMACSize;
	if ((macSize < 4) || (macSize > 16) || ((macSize % 2) != 0)) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/* Check the nonce value.  Valid values are 7, 8, 9, 10, 11, 12, 13 */
	nonceSize = ccm_param->ulNonceSize;
	if ((nonceSize < 7) || (nonceSize > 13)) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	q = (uint8_t)((15 - nonceSize) & 0xFF);


	/*
	 * If it is decrypt, need to make sure size of ciphertext is at least
	 * bigger than MAC len
	 */
	if ((!is_encrypt_init) && (ccm_param->ulDataSize < macSize)) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	/*
	 * Check to make sure the length of the payload is within the
	 * range of values allowed by q
	 */
	if (q < 8) {
		maxValue = 1ULL << (q * 8);
	} else {
		maxValue = ULONG_MAX;
	}

	if (ccm_param->ulDataSize > maxValue) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

/* EXPORT DELETE END */
	return (0);
}

/*
 * Format the first block used in CBC-MAC (B0) and the initial counter
 * block based on formating functions and counter generation functions
 * specified in RFC 3610 and NIST publication 800-38C, appendix A
 *
 * b0 is the first block used in CBC-MAC
 * cb0 is the first counter block
 *
 * It's assumed that the arguments b0 and cb0 are preallocated AES blocks
 *
 */
static void
aes_ccm_format_initial_blocks(uchar_t *nonce, ulong_t nonceSize,
    ulong_t authDataSize, uint8_t *b0, aes_ctx_t *aes_ctx)
{
/* EXPORT DELETE START */
	uint64_t payloadSize;
	uint8_t t, q, have_adata = 0;
	size_t limit;
	int i, j, k;
	uint64_t mask = 0;
	uint8_t *cb;
#ifdef _LITTLE_ENDIAN
	uint8_t *p8;
#endif	/* _LITTLE_ENDIAN */

	q = (uint8_t)((15 - nonceSize) & 0xFF);
	t = (uint8_t)((aes_ctx->ac_ccm_mac_len) & 0xFF);

	/* Construct the first octect of b0 */
	if (authDataSize > 0) {
		have_adata = 1;
	}
	b0[0] = (have_adata << 6) | (((t - 2)  / 2) << 3) | (q - 1);

	/* copy the nonce value into b0 */
	bcopy(nonce, &(b0[1]), nonceSize);

	/* store the length of the payload into b0 */
	bzero(&(b0[1+nonceSize]), q);

	payloadSize = aes_ctx->ac_ccm_data_len;
	limit = 8 < q ? 8 : q;

	for (i = 0, j = 0, k = 15; i < limit; i++, j += 8, k--) {
		b0[k] = (uint8_t)((payloadSize >> j) & 0xFF);
	}

	/* format the counter block */

	cb = (uint8_t *)aes_ctx->ac_cb;

	cb[0] = 0x07 & (q-1); /* first byte */

	/* copy the nonce value into the counter block */
	bcopy(nonce, &(cb[1]), nonceSize);

	bzero(&(cb[1+nonceSize]), q);

	/* Create the mask for the counter field based on the size of nonce */
	q <<= 3;
	while (q-- > 0) {
		mask |= (1ULL << q);
	}

#ifdef _LITTLE_ENDIAN
	p8 = (uint8_t *)&mask;
	mask = (((uint64_t)p8[0] << 56) |
	    ((uint64_t)p8[1] << 48) |
	    ((uint64_t)p8[2] << 40) |
	    ((uint64_t)p8[3] << 32) |
	    ((uint64_t)p8[4] << 24) |
	    ((uint64_t)p8[5] << 16) |
	    ((uint64_t)p8[6] << 8) |
	    (uint64_t)p8[7]);
#endif
	aes_ctx->ac_counter_mask = mask;

	/*
	 * During calculation, we start using counter block 1, we will
	 * set it up right here.
	 * We can just set the last byte to have the value 1, because
	 * even with the bigest nonce of 13, the last byte of the
	 * counter block will be used for the counter value.
	 */
	cb[15] = 0x01;

/* EXPORT DELETE END */

}

/*
 * Encode the length of the associated data as
 * specified in RFC 3610 and NIST publication 800-38C, appendix A
 */
static void
encode_adata_len(ulong_t auth_data_len, uint8_t *encoded, size_t *encoded_len)
{

/* EXPORT DELETE START */

	if (auth_data_len < ((1ULL<<16) - (1ULL<<8))) {
		/* 0 < a < (2^16-2^8) */
		*encoded_len = 2;
		encoded[0] = (auth_data_len & 0xff00) >> 8;
		encoded[1] = auth_data_len & 0xff;

	} else if ((auth_data_len >= ((1ULL<<16) - (1ULL<<8))) &&
	    (auth_data_len < (1ULL << 31))) {
		/* (2^16-2^8) <= a < 2^32 */
		*encoded_len = 6;
		encoded[0] = 0xff;
		encoded[1] = 0xfe;
		encoded[2] = (auth_data_len & 0xff000000) >> 24;
		encoded[3] = (auth_data_len & 0xff0000) >> 16;
		encoded[4] = (auth_data_len & 0xff00) >> 8;
		encoded[5] = auth_data_len & 0xff;
#ifdef _LP64
	} else {
		/* 2^32 <= a < 2^64 */
		*encoded_len = 10;
		encoded[0] = 0xff;
		encoded[1] = 0xff;
		encoded[2] = (auth_data_len & 0xff00000000000000) >> 56;
		encoded[3] = (auth_data_len & 0xff000000000000) >> 48;
		encoded[4] = (auth_data_len & 0xff0000000000) >> 40;
		encoded[5] = (auth_data_len & 0xff00000000) >> 32;
		encoded[6] = (auth_data_len & 0xff000000) >> 24;
		encoded[7] = (auth_data_len & 0xff0000) >> 16;
		encoded[8] = (auth_data_len & 0xff00) >> 8;
		encoded[9] = auth_data_len & 0xff;
#endif	/* _LP64 */
	}
/* EXPORT DELETE END */
}

/*
 * This will only deal with decrypting the last block of the input that
 * might not be multiples of AES_BLOCK_LEN
 */
static void
aes_ccm_decrypt_incomplete_block(aes_ctx_t *ctx)
{

/* EXPORT DELETE START */
	uint8_t *datap, counter_block[AES_BLOCK_LEN], *outp, *counterp;
	int i;

	datap = (uint8_t *)ctx->ac_remainder;
	outp = &((ctx->ac_ccm_pt_buf)[ctx->ac_ccm_processed_data_len]);

	aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_cb,
	    counter_block);

	counterp = (uint8_t *)counter_block;

	/* XOR with counter block */
	for (i = 0; i < ctx->ac_remainder_len; i++) {
		outp[i] = datap[i] ^ counterp[i];
	}
/* EXPORT DELETE END */
}

/*
 * This will decrypt the cipher text.  However, the plaintext won't be
 * returned to the caller.  It will be returned when decrypt_final() is
 * called if the MAC matches
 */
/* ARGSUSED */
static int
aes_ccm_decrypt_contiguous_blocks(aes_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{

/* EXPORT DELETE START */

	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint32_t counter_block[4];
	uint8_t *cbp;
	uint64_t counter;
	size_t pt_len, total_decrypted_len, mac_len, pm_len, pd_len;
	uint32_t tmp[4];
	uint8_t *resultp;
#ifdef _LITTLE_ENDIAN
	uint8_t *p;
#endif	/* _LITTLE_ENDIAN */


	pm_len = ctx->ac_ccm_processed_mac_len;

	if (pm_len > 0) {
		uint8_t *tmp;
		/*
		 * all ciphertext has been processed, just waiting for
		 * part of the value of the mac
		 */
		if ((pm_len + length) > ctx->ac_ccm_mac_len) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		tmp = (uint8_t *)ctx->ac_ccm_mac_input_buf;

		bcopy(datap, tmp + pm_len, length);

		ctx->ac_ccm_processed_mac_len += length;
		return (0);
	}

	/*
	 * If we decrypt the given data, what total amount of data would
	 * have been decrypted?
	 */
	pd_len = ctx->ac_ccm_processed_data_len;
	total_decrypted_len = pd_len + length + ctx->ac_remainder_len;

	if (total_decrypted_len >
	    (ctx->ac_ccm_data_len + ctx->ac_ccm_mac_len)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	pt_len = ctx->ac_ccm_data_len;

	if (total_decrypted_len > pt_len) {
		/*
		 * part of the input will be the MAC, need to isolate that
		 * to be dealt with later.  The left-over data in
		 * ac_remainder_len from last time will not be part of the
		 * MAC.  Otherwise, it would have already been taken out
		 * when this call is made last time.
		 */
		size_t pt_part = pt_len - pd_len - ctx->ac_remainder_len;

		mac_len = length - pt_part;

		ctx->ac_ccm_processed_mac_len = mac_len;
		bcopy(data + pt_part, ctx->ac_ccm_mac_input_buf, mac_len);

		if (pt_part + ctx->ac_remainder_len < AES_BLOCK_LEN) {
			/*
			 * since this is last of the ciphertext, will
			 * just decrypt with it here
			 */
			bcopy(datap, &((uint8_t *)ctx->ac_remainder)
			    [ctx->ac_remainder_len], pt_part);
			ctx->ac_remainder_len += pt_part;
			aes_ccm_decrypt_incomplete_block(ctx);
			ctx->ac_remainder_len = 0;
			ctx->ac_ccm_processed_data_len += pt_part;
			return (0);
		} else {
			/* let rest of the code handle this */
			length = pt_part;
		}
	} else if (length + ctx->ac_remainder_len < AES_BLOCK_LEN) {
			/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)ctx->ac_remainder + ctx->ac_remainder_len,
		    length);
		ctx->ac_remainder_len += length;
		ctx->ac_copy_to = datap;
		return (0);
	}

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

		/* Calculate the counter mode, ac_cb is the counter block */
		aes_encrypt_block(ctx->ac_keysched, (uint8_t *)ctx->ac_cb,
		    (uint8_t *)counter_block);
		cbp = (uint8_t *)counter_block;

		/*
		 * Increment counter.
		 * Counter bits are confined to the bottom 64 bits
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

		/* XOR with the ciphertext */
		if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(cbp, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[0] ^= *(uint32_t *)&cbp[0];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[4] ^= *(uint32_t *)&cbp[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[8] ^= *(uint32_t *)&cbp[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&blockp[12] ^= *(uint32_t *)&cbp[12];
		} else {
			AES_XOR_BLOCK(cbp, blockp);
		}

		/* Copy the plaintext to the "holding buffer" */
		resultp = (uint8_t *)ctx->ac_ccm_pt_buf +
		    ctx->ac_ccm_processed_data_len;
		if (IS_P2ALIGNED(blockp, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(resultp, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&resultp[0] = *(uint32_t *)blockp;
			/* LINTED: pointer alignment */
			*(uint32_t *)&resultp[4] = *(uint32_t *)&blockp[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&resultp[8] = *(uint32_t *)&blockp[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&resultp[12] = *(uint32_t *)&blockp[12];
		} else {
			AES_COPY_BLOCK(blockp, resultp);
		}

		ctx->ac_ccm_processed_data_len += AES_BLOCK_LEN;

		ctx->ac_lastp = blockp;

		/* Update pointer to next block of data to be processed. */
		if (ctx->ac_remainder_len != 0) {
			datap += need;
			ctx->ac_remainder_len = 0;
		} else {
			datap += AES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block */
		if (remainder > 0 && remainder < AES_BLOCK_LEN) {
			bcopy(datap, ctx->ac_remainder, remainder);
			ctx->ac_remainder_len = remainder;
			ctx->ac_copy_to = datap;
			if (ctx->ac_ccm_processed_mac_len > 0) {
				/*
				 * not expecting anymore ciphertext, just
				 * compute plaintext for the remaining input
				 */
				aes_ccm_decrypt_incomplete_block(ctx);
				ctx->ac_ccm_processed_data_len += remainder;
				ctx->ac_remainder_len = 0;
			}
			goto out;
		}
		ctx->ac_copy_to = NULL;

	} while (remainder > 0);

out:
/* EXPORT DELETE END */

	return (0);
}

int
aes_ccm_decrypt_final(aes_ctx_t *ctx, crypto_data_t *out)
{
/* EXPORT DELETE START */
	size_t mac_remain, pt_len;
	uint8_t *pt, *mac_buf, *macp, *ccm_mac_p;
	uint8_t ccm_mac[AES_BLOCK_LEN];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1, *out_data_2;
	size_t out_data_1_len;
	uint32_t tmp[4];

	pt_len = ctx->ac_ccm_data_len;

	/* Make sure output buffer can fit all of the plaintext */
	if (out->cd_length < pt_len) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	pt = ctx->ac_ccm_pt_buf;
	mac_remain = ctx->ac_ccm_processed_data_len;
	mac_buf = (uint8_t *)ctx->ac_ccm_mac_buf;

	macp = (uint8_t *)tmp;

	while (mac_remain > 0) {

		if (mac_remain < AES_BLOCK_LEN) {
			bzero(tmp, AES_BLOCK_LEN);
			bcopy(pt, tmp, mac_remain);
			mac_remain = 0;
		} else {
			if (IS_P2ALIGNED(pt, sizeof (uint32_t)) &&
			    IS_P2ALIGNED(macp, sizeof (uint32_t))) {
				/* LINTED: pointer alignment */
				*(uint32_t *)&macp[0] = *(uint32_t *)pt;
				/* LINTED: pointer alignment */
				*(uint32_t *)&macp[4] = *(uint32_t *)&pt[4];
				/* LINTED: pointer alignment */
				*(uint32_t *)&macp[8] = *(uint32_t *)&pt[8];
				/* LINTED: pointer alignment */
				*(uint32_t *)&macp[12] = *(uint32_t *)&pt[12];
			} else {
				AES_COPY_BLOCK(pt, macp);
			}
			mac_remain -= AES_BLOCK_LEN;
			pt += AES_BLOCK_LEN;
		}

		/* calculate the CBC MAC */
		if (IS_P2ALIGNED(macp, sizeof (uint32_t)) &&
		    IS_P2ALIGNED(mac_buf, sizeof (uint32_t))) {
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[0] ^= *(uint32_t *)&macp[0];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[4] ^= *(uint32_t *)&macp[4];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[8] ^= *(uint32_t *)&macp[8];
			/* LINTED: pointer alignment */
			*(uint32_t *)&mac_buf[12] ^= *(uint32_t *)&macp[12];
		} else {
			AES_XOR_BLOCK(macp, mac_buf);
		}
		aes_encrypt_block(ctx->ac_keysched, mac_buf, mac_buf);
	}

	/* Calculate the CCM MAC */
	ccm_mac_p = ccm_mac;
	calculate_ccm_mac(ctx, &ccm_mac_p);

	/* compare the input CCM MAC value with what we calculated */
	if (bcmp(ctx->ac_ccm_mac_input_buf, ccm_mac, ctx->ac_ccm_mac_len)) {
		/* They don't match */
		return (CRYPTO_DATA_LEN_RANGE);
	} else {
		aes_init_ptrs(out, &iov_or_mp, &offset);
		aes_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
		    &out_data_1_len, &out_data_2, pt_len);
		bcopy(ctx->ac_ccm_pt_buf, out_data_1, out_data_1_len);
		if (out_data_2 != NULL) {
			bcopy((ctx->ac_ccm_pt_buf) + out_data_1_len,
			    out_data_2, pt_len - out_data_1_len);
		}
		out->cd_offset += pt_len;
	}

/* EXPORT DELETE END */
	return (0);
}
