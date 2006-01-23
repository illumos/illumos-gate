/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/crypto/common.h>
#include <sys/strsun.h>
#include "blowfish_cbc_crypt.h"
#include "blowfish_impl.h"
#ifndef	_KERNEL
#include <strings.h>
#endif	/* !_KERNEL */


#define	BLOWFISH_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7]

#define	BLOWFISH_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]

/*
 * Initialize by setting iov_or_mp to point to the current iovec or mp,
 * and by setting current_offset to an offset within the current iovec or mp .
 */
static void
blowfish_init_ptrs(crypto_data_t *out, void **iov_or_mp,
    offset_t *current_offset)
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
blowfish_get_ptrs(crypto_data_t *out, void **iov_or_mp,
    offset_t *current_offset, uint8_t **out_data_1, size_t *out_data_1_len,
    uint8_t **out_data_2)
{
	offset_t offset;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW: {
		iovec_t *iov;

		offset = *current_offset;
		iov = &out->cd_raw;
		if ((offset + BLOWFISH_BLOCK_LEN) <= iov->iov_len) {
			/* one BLOWFISH block fits */
			*out_data_1 = (uint8_t *)iov->iov_base + offset;
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
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

		if (offset + BLOWFISH_BLOCK_LEN <= iov->iov_len) {
			/* can fit one BLOWFISH block into this iov */
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
		} else {
			/* one BLOWFISH block spans two iovecs */
			*out_data_1_len = iov->iov_len - offset;
			if (vec_idx == uio->uio_iovcnt)
				return;
			vec_idx++;
			iov = &uio->uio_iov[vec_idx];
			*out_data_2 = (uint8_t *)iov->iov_base;
			*current_offset = BLOWFISH_BLOCK_LEN - *out_data_1_len;
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
		if ((p + BLOWFISH_BLOCK_LEN) <= mp->b_wptr) {
			/* can fit one BLOWFISH block into this mblk */
			*out_data_1_len = BLOWFISH_BLOCK_LEN;
			*out_data_2 = NULL;
			*current_offset = offset + BLOWFISH_BLOCK_LEN;
		} else {
			/* one BLOWFISH block spans two mblks */
			*out_data_1_len = mp->b_wptr - p;
			if ((mp = mp->b_cont) == NULL)
				return;
			*out_data_2 = mp->b_rptr;
			*current_offset = BLOWFISH_BLOCK_LEN - *out_data_1_len;
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
blowfish_encrypt_contiguous_blocks(blowfish_ctx_t *ctx, char *data,
    size_t length, crypto_data_t *out)
{
/* EXPORT DELETE START */
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

	if (length + ctx->bc_remainder_len < BLOWFISH_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->bc_remainder + ctx->bc_remainder_len,
		    length);
		ctx->bc_remainder_len += length;
		ctx->bc_copy_to = datap;
		return (0);
	}

	lastp = (uint8_t *)&ctx->bc_iv;
	if (out != NULL)
		blowfish_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->bc_remainder_len > 0) {
			need = BLOWFISH_BLOCK_LEN - ctx->bc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->bc_remainder)
			    [ctx->bc_remainder_len], need);

			blockp = (uint8_t *)&ctx->bc_remainder;
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
				uint8_t *tmp8 = (uint8_t *)tmp;

				BLOWFISH_COPY_BLOCK(blockp, tmp8);

			}
			blockp = (uint8_t *)tmp;
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {
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
				BLOWFISH_XOR_BLOCK(lastp, blockp);
			}
		}

		if (out == NULL) {
			blowfish_encrypt_block(ctx->bc_keysched, blockp,
			    blockp);

			ctx->bc_lastp = blockp;
			lastp = blockp;

			if (ctx->bc_remainder_len > 0) {
				bcopy(blockp, ctx->bc_copy_to,
				    ctx->bc_remainder_len);
				bcopy(blockp + ctx->bc_remainder_len, datap,
				    need);
			}
		} else {
			blowfish_encrypt_block(ctx->bc_keysched, blockp, lastp);
			blowfish_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);

			/* copy block to where it belongs */
			bcopy(lastp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy(lastp + out_data_1_len, out_data_2,
				    BLOWFISH_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += BLOWFISH_BLOCK_LEN;
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->bc_remainder_len != 0) {
			datap += need;
			ctx->bc_remainder_len = 0;
		} else {
			datap += BLOWFISH_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < BLOWFISH_BLOCK_LEN) {
			bcopy(datap, &ctx->bc_remainder, remainder);
			ctx->bc_remainder_len = remainder;
			ctx->bc_copy_to = datap;
			goto out;
		}
		ctx->bc_copy_to = NULL;

	} while (remainder > 0);

out:
	if (ctx->bc_lastp != NULL) {
		uint8_t *iv8 = (uint8_t *)&ctx->bc_iv;
		uint8_t *last8 = (uint8_t *)ctx->bc_lastp;

		if (IS_P2ALIGNED(ctx->bc_lastp, sizeof (uint32_t))) {

			/* LINTED: pointer alignment */
			*(uint32_t *)iv8 = *(uint32_t *)last8;
			/* LINTED: pointer alignment */
			*(uint32_t *)&iv8[4] = *(uint32_t *)&last8[4];
		} else {
			BLOWFISH_COPY_BLOCK(last8, iv8);
		}
		ctx->bc_lastp = (uint8_t *)&ctx->bc_iv;
	}
/* EXPORT DELETE END */

	return (0);
}

#define	OTHER(a, ctx) \
	(((a) == &(ctx)->bc_lastblock) ? &(ctx)->bc_iv : &(ctx)->bc_lastblock)

int
blowfish_decrypt_contiguous_blocks(blowfish_ctx_t *ctx, char *data,
    size_t length, crypto_data_t *out)
{
/* EXPORT DELETE START */
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

	if (length + ctx->bc_remainder_len < BLOWFISH_BLOCK_LEN) {
		/* accumulate bytes here and return */
		bcopy(datap,
		    (uint8_t *)&ctx->bc_remainder + ctx->bc_remainder_len,
		    length);
		ctx->bc_remainder_len += length;
		ctx->bc_copy_to = datap;
		return (0);
	}

	lastp = ctx->bc_lastp;
	if (out != NULL)
		blowfish_init_ptrs(out, &iov_or_mp, &offset);

	do {
		/* Unprocessed data from last call. */
		if (ctx->bc_remainder_len > 0) {
			need = BLOWFISH_BLOCK_LEN - ctx->bc_remainder_len;

			if (need > remainder)
				return (1);

			bcopy(datap, &((uint8_t *)&ctx->bc_remainder)
			    [ctx->bc_remainder_len], need);

			blockp = (uint8_t *)&ctx->bc_remainder;
		} else {
			blockp = datap;
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {

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
				uint8_t *tmp8;
				/* LINTED: pointer alignment */
				tmp8 = (uint8_t *)OTHER((uint64_t *)lastp, ctx);

				BLOWFISH_COPY_BLOCK(blockp, tmp8);
			}
		}

		if (out != NULL) {
			blowfish_decrypt_block(ctx->bc_keysched, blockp,
			    (uint8_t *)tmp);
			blockp = (uint8_t *)tmp;
		} else {
			blowfish_decrypt_block(ctx->bc_keysched, blockp,
			    blockp);
		}

		if (ctx->bc_flags & BLOWFISH_CBC_MODE) {
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
				BLOWFISH_XOR_BLOCK(lastp, blockp);
			}

			/* LINTED: pointer alignment */
			lastp = (uint8_t *)OTHER((uint64_t *)lastp, ctx);
		}

		if (out != NULL) {
			blowfish_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
			    &out_data_1_len, &out_data_2);
			/* copy temporary block to where it belongs */
			bcopy(&tmp, out_data_1, out_data_1_len);
			if (out_data_2 != NULL) {
				bcopy((uint8_t *)&tmp + out_data_1_len,
				    out_data_2,
				    BLOWFISH_BLOCK_LEN - out_data_1_len);
			}

			/* update offset */
			out->cd_offset += BLOWFISH_BLOCK_LEN;
		} else if (ctx->bc_remainder_len > 0) {
			/* copy temporary block to where it belongs */
			bcopy(blockp, ctx->bc_copy_to, ctx->bc_remainder_len);
			bcopy(blockp + ctx->bc_remainder_len, datap, need);
		}

		/* Update pointer to next block of data to be processed. */
		if (ctx->bc_remainder_len != 0) {
			datap += need;
			ctx->bc_remainder_len = 0;
		} else {
			datap += BLOWFISH_BLOCK_LEN;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < BLOWFISH_BLOCK_LEN) {
			bcopy(datap, (uchar_t *)&ctx->bc_remainder, remainder);
			ctx->bc_remainder_len = remainder;
			ctx->bc_lastp = lastp;
			ctx->bc_copy_to = datap;
			return (0);
		}
		ctx->bc_copy_to = NULL;

	} while (remainder > 0);

	ctx->bc_lastp = lastp;
/* EXPORT DELETE END */
	return (0);
}
