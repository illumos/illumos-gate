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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <sys/strsun.h>
#include "des_cbc_crypt.h"
#include "des_impl.h"
#ifndef	_KERNEL
#include <strings.h>
#endif	/* !_KERNEL */


/*
 * Initialize by setting iov_or_mp to point to the current iovec or mp,
 * and by setting current_offset to an offset within the current iovec or mp .
 */
static void
des_init_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		*current_offset = out->cd_offset;
		break;

	case CRYPTO_DATA_UIO: {
		uio_t *uiop = out->cd_uio;
		uint_t vec_idx;

		offset = out->cd_offset;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len);

		*current_offset = offset;
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
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
des_get_ptrs(crypto_data_t *out, void **iov_or_mp, offset_t *current_offset,
    uint8_t **out_data_1, size_t *out_data_1_len, uint8_t **out_data_2)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW: {
		iovec_t *iov;

		offset = *current_offset;
		iov = &out->cd_raw;
		if ((offset + DES_BLOCK_LEN) <= iov->iov_len) {
			/* one DES block fits */
			*out_data_1 = (uint8_t *)iov->iov_base + offset;
			*out_data_1_len = DES_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + DES_BLOCK_LEN;
		}
		break;
	}

	case CRYPTO_DATA_UIO: {
		uio_t *uio = out->cd_uio;
		iovec_t *iov;
		offset_t offset;
		uint_t vec_idx;
		uint8_t *p;

		offset = *current_offset;
		vec_idx = (uint_t)(uintptr_t)(*iov_or_mp);
		iov = &uio->uio_iov[vec_idx];
		p = (uint8_t *)iov->iov_base + offset;
		*out_data_1 = p;

		if (offset + DES_BLOCK_LEN <= iov->iov_len) {
			/* can fit one DES block into this iov */
			*out_data_1_len = DES_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + DES_BLOCK_LEN;
		} else {
			/* one DES block spans two iovecs */
			*out_data_1_len = iov->iov_len - offset;
			if (vec_idx == uio->uio_iovcnt)
				return;
			vec_idx++;
			iov = &uio->uio_iov[vec_idx];
			*out_data_2 = (uint8_t *)iov->iov_base;
			*current_offset = DES_BLOCK_LEN - *out_data_1_len;
		}
		*iov_or_mp = (void *)(uintptr_t)vec_idx;
		break;
	}

	case CRYPTO_DATA_MBLK: {
		mblk_t *mp;
		uint8_t *p;

		offset = *current_offset;
		mp = (mblk_t *)*iov_or_mp;
		p = mp->b_rptr + offset;
		*out_data_1 = p;
		if ((p + DES_BLOCK_LEN) <= mp->b_wptr) {
			/* can fit one DES block into this mblk */
			*out_data_1_len = DES_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + DES_BLOCK_LEN;
		} else {
			/* one DES block spans two mblks */
			*out_data_1_len = mp->b_wptr - p;
			if ((mp = mp->b_cont) == NULL)
				return;
			*out_data_2 = mp->b_rptr;
			*current_offset = (DES_BLOCK_LEN - *out_data_1_len);
		}
		*iov_or_mp = mp;
		break;
	}
	} /* end switch */
}

/*
 * Encrypt multiple blocks of data.
 */
int
des_encrypt_contiguous_blocks(des_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{
/* EXPORT DELETE START */
	void (*func)(void *, uint8_t *, uint8_t *, boolean_t);
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[2];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->dc_remainder_len < DES_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->dc_remainder + ctx->dc_remainder_len,
		    length);
		ctx->dc_remainder_len += length;
		ctx->dc_copy_to = datap;
		return (0);
	}

	/*
	 * Most of this routine is generic CBC except for the
	 * following code that has to switch between DES and DES3.
	 */
	func = (ctx->dc_flags & DES3_STRENGTH) ?
	    des3_crunch_block : des_crunch_block;

	lastp = (uint8_t *)&ctx->dc_iv;
	if (out != NULL)
		des_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->dc_remainder_len > 0) {
			need = DES_BLOCK_LEN - ctx->dc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->dc_remainder)
			    [ctx->dc_remainder_len], need);

			blockp = (uint8_t *)&ctx->dc_remainder;
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
			} else {
#ifdef _BIG_ENDIAN
				tmp[0] = (((uint32_t)blockp[0] << 24) |
				    ((uint32_t)blockp[1] << 16) |
				    ((uint32_t)blockp[2] << 8) |
				    (uint32_t)blockp[3]);

				tmp[1] = (((uint32_t)blockp[4] << 24) |
				    ((uint32_t)blockp[5] << 16) |
				    ((uint32_t)blockp[6] << 8) |
				    (uint32_t)blockp[7]);
#else
				tmp[1] = (((uint32_t)blockp[7] << 24) |
				    ((uint32_t)blockp[6] << 16) |
				    ((uint32_t)blockp[5] << 8) |
				    (uint32_t)blockp[4]);

				tmp[0] = (((uint32_t)blockp[3] << 24) |
				    ((uint32_t)blockp[2] << 16) |
				    ((uint32_t)blockp[1] << 8) |
				    (uint32_t)blockp[0]);
#endif /* _BIG_ENDIAN */
			}
			blockp = (uint8_t *)tmp;
		}

		if (ctx->dc_flags & DES_CBC_MODE) {
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
			} else {
				DES_XOR_BLOCK(lastp, blockp);
			}
		}

		if (out == NULL) {
			(func)(ctx->dc_keysched, blockp, blockp, B_FALSE);

			ctx->dc_lastp = blockp;
			lastp = blockp;

			if (ctx->dc_remainder_len > 0) {
				bcopy(blockp, ctx->dc_copy_to,
				    ctx->dc_remainder_len);
				bcopy(blockp + ctx->dc_remainder_len, datap,
				    need);
			}
		} else {
			(func)(ctx->dc_keysched, blockp, lastp, B_FALSE);
			des_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);

			/* copy block to where it belongs */
			bcopy(lastp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(lastp + out_data_1_len, out_data_2,
				    DES_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += DES_BLOCK_LEN;
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->dc_remainder_len != 0) {
			datap += need;
			ctx->dc_remainder_len = 0;
		} else {
			datap += DES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < DES_BLOCK_LEN) {
			bcopy(datap, (uchar_t *)&ctx->dc_remainder, remainder);
			ctx->dc_remainder_len = remainder;
			ctx->dc_copy_to = datap;
			goto out;
		}
		ctx->dc_copy_to = NULL;

	} while (remainder > 0);

out:
	if (ctx->dc_lastp != NULL) {
		if (IS_P2ALIGNED(ctx->dc_lastp, sizeof (uint32_t))) {
			uint8_t *iv8 = (uint8_t *)&ctx->dc_iv;
			uint8_t *last8 = (uint8_t *)ctx->dc_lastp;

			/* LINTED: pointer alignment */
			*(uint32_t *)iv8 = *(uint32_t *)last8;
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[4] = *(uint32_t *)&last8[4];
		} else {
			uint64_t tmp64;
			uint8_t *tmp = ctx->dc_lastp;

#ifdef _BIG_ENDIAN
			tmp64 = (((uint64_t)tmp[0] << 56) |
			    ((uint64_t)tmp[1] << 48) |
			    ((uint64_t)tmp[2] << 40) |
			    ((uint64_t)tmp[3] << 32) |
			    ((uint64_t)tmp[4] << 24) |
			    ((uint64_t)tmp[5] << 16) |
			    ((uint64_t)tmp[6] << 8) |
			    (uint64_t)tmp[7]);
#else
			tmp64 = (((uint64_t)tmp[7] << 56) |
			    ((uint64_t)tmp[6] << 48) |
			    ((uint64_t)tmp[5] << 40) |
			    ((uint64_t)tmp[4] << 32) |
			    ((uint64_t)tmp[3] << 24) |
			    ((uint64_t)tmp[2] << 16) |
			    ((uint64_t)tmp[1] << 8) |
			    (uint64_t)tmp[0]);
#endif /* _BIG_ENDIAN */

			ctx->dc_iv = tmp64;
		}
		ctx->dc_lastp = (uint8_t *)&ctx->dc_iv;
	}
/* EXPORT DELETE END */

	return (0);
}

#define	OTHER(a, ctx) \
	(((a) == &(ctx)->dc_lastblock) ? &(ctx)->dc_iv : &(ctx)->dc_lastblock)

/*
 * Decrypt multiple blocks of data.
 */
int
des_decrypt_contiguous_blocks(des_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out)
{
/* EXPORT DELETE START */
	void (*func)(void *, uint8_t *, uint8_t *, boolean_t);
	size_t remainder = length;
	size_t need;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	uint32_t tmp[2];
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;

	if (length + ctx->dc_remainder_len < DES_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->dc_remainder + ctx->dc_remainder_len,
		    length);
		ctx->dc_remainder_len += length;
		ctx->dc_copy_to = datap;
		return (0);
	}

	/*
	 * Most of this routine is generic CBC except for the
	 * following code that has to switch between DES and DES3.
	 */
	func = (ctx->dc_flags & DES3_STRENGTH) ?
	    des3_crunch_block : des_crunch_block;

	lastp = ctx->dc_lastp;
	if (out != NULL)
		des_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->dc_remainder_len > 0) {
			need = DES_BLOCK_LEN - ctx->dc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->dc_remainder)
			    [ctx->dc_remainder_len], need);

			blockp = (uint8_t *)&ctx->dc_remainder;
		} else {
			blockp = datap;
		}

		if (ctx->dc_flags & DES_CBC_MODE) {

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
			} else {
				uint64_t tmp64;

#ifdef _BIG_ENDIAN
				tmp64 = (((uint64_t)blockp[0] << 56) |
				    ((uint64_t)blockp[1] << 48) |
				    ((uint64_t)blockp[2] << 40) |
				    ((uint64_t)blockp[3] << 32) |
				    ((uint64_t)blockp[4] << 24) |
				    ((uint64_t)blockp[5] << 16) |
				    ((uint64_t)blockp[6] << 8) |
				    (uint64_t)blockp[7]);
#else
				tmp64 = (((uint64_t)blockp[7] << 56) |
				    ((uint64_t)blockp[6] << 48) |
				    ((uint64_t)blockp[5] << 40) |
				    ((uint64_t)blockp[4] << 32) |
				    ((uint64_t)blockp[3] << 24) |
				    ((uint64_t)blockp[2] << 16) |
				    ((uint64_t)blockp[1] << 8) |
				    (uint64_t)blockp[0]);
#endif /* _BIG_ENDIAN */

				/* LINTED: pointer alignment */
				*OTHER((uint64_t *)lastp, ctx) = tmp64;
			}
		}

		if (out != NULL) {
			(func)(ctx->dc_keysched, blockp, (uint8_t *)tmp,
			    B_TRUE);
			blockp = (uint8_t *)tmp;
		} else {
			(func)(ctx->dc_keysched, blockp, blockp, B_TRUE);
		}

		if (ctx->dc_flags & DES_CBC_MODE) {
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
			} else {
				DES_XOR_BLOCK(lastp, blockp);
			}

			/* LINTED: pointer alignment */
			lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);
		}

		if (out != NULL) {
			des_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);
			/* copy temporary block to where it belongs */
			bcopy(&tmp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy((uint8_t *)&tmp + out_data_1_len,
				    out_data_2, DES_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += DES_BLOCK_LEN;

		} else if (ctx->dc_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->dc_copy_to, ctx->dc_remainder_len);
			bcopy(blockp + ctx->dc_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->dc_remainder_len != 0) {
			datap += need;
			ctx->dc_remainder_len = 0;
		} else {
			datap += DES_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < DES_BLOCK_LEN) {
			bcopy(datap, (uchar_t *)&ctx->dc_remainder, remainder);
			ctx->dc_remainder_len = remainder;
			ctx->dc_lastp = lastp;
			ctx->dc_copy_to = datap;
			return (0);
		}
		ctx->dc_copy_to = NULL;

	} while (remainder > 0);

	ctx->dc_lastp = lastp;
/* EXPORT DELETE END */
	return (0);
}
