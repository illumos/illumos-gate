
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

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/note.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/dca.h>

#if defined(__i386) || defined(__amd64)
#include <sys/byteorder.h>
#define	UNALIGNED_POINTERS_PERMITTED
#endif

/*
 * 3DES implementation.
 */

static int dca_3desstart(dca_t *, uint32_t, dca_request_t *);
static void dca_3desdone(dca_request_t *, int);


int
dca_3des(crypto_ctx_t *ctx, crypto_data_t *in,
    crypto_data_t *out, crypto_req_handle_t req, int flags)
{
	int			len;
	int			rv;
	dca_request_t		*reqp = ctx->cc_provider_private;
	dca_request_t		*des_ctx = ctx->cc_provider_private;
	dca_t			*dca = ctx->cc_provider;
	crypto_data_t		*nin = &reqp->dr_ctx.in_dup;

	len = dca_length(in);
	if (len % DESBLOCK) {
		DBG(dca, DWARN, "input not an integral number of DES blocks");
		(void) dca_free_context(ctx);
		if (flags & DR_DECRYPT) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		} else {
			return (CRYPTO_DATA_LEN_RANGE);
		}
	}

	/*
	 * If cd_miscdata non-null then this contains the IV.
	 */
	if (in->cd_miscdata != NULL) {
#ifdef UNALIGNED_POINTERS_PERMITTED
		uint32_t	*p = (uint32_t *)in->cd_miscdata;
		des_ctx->dr_ctx.iv[0] = htonl(p[0]);
		des_ctx->dr_ctx.iv[1] = htonl(p[1]);
#else
		uchar_t	*p = (uchar_t *)in->cd_miscdata;
		des_ctx->dr_ctx.iv[0] = p[0]<<24 | p[1]<<16 | p[2]<<8 | p[3];
		des_ctx->dr_ctx.iv[1] = p[4]<<24 | p[5]<<16 | p[6]<<8 | p[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}

	if (len > dca_length(out)) {
		DBG(dca, DWARN, "inadequate output space (need %d, got %d)",
		    len, dca_length(out));
		out->cd_length = len;
		/* Do not free the context since the app will call again */
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((rv = dca_verifyio(in, out)) != CRYPTO_SUCCESS) {
		(void) dca_free_context(ctx);
		return (rv);
	}

	/* special handling for null-sized input buffers */
	if (len == 0) {
		out->cd_length = 0;
		(void) dca_free_context(ctx);
		return (CRYPTO_SUCCESS);
	}

	/*
	 * Make a local copy of the input crypto_data_t structure. This
	 * allows it to be manipulated locally and for dealing with in-place
	 * data (ie in == out). Note that "nin" has been pre-allocated,
	 * and only fields are copied, not actual data.
	 */
	if ((rv = dca_dupcrypto(in, nin)) != CRYPTO_SUCCESS) {
		(void) dca_free_context(ctx);
		return (rv);
	}

	/* Set output to zero ready to take the processed data */
	out->cd_length = 0;

	reqp->dr_kcf_req = req;
	reqp->dr_in = nin;
	reqp->dr_out = out;
	reqp->dr_job_stat = DS_3DESJOBS;
	reqp->dr_byte_stat = DS_3DESBYTES;

	rv = dca_3desstart(dca, flags, reqp);

	/* Context will be freed in the kCF callback function otherwise */
	if (rv != CRYPTO_QUEUED && rv != CRYPTO_BUFFER_TOO_SMALL) {
		(void) dca_free_context(ctx);
	}
	return (rv);
}


void
dca_3desctxfree(void *arg)
{
	crypto_ctx_t	*ctx = (crypto_ctx_t *)arg;
	dca_request_t	*des_ctx = ctx->cc_provider_private;

	if (des_ctx == NULL)
		return;

	des_ctx->dr_ctx.atomic = 0;
	des_ctx->dr_ctx.ctx_cm_type = 0;
	ctx->cc_provider_private = NULL;

	if (des_ctx->destroy)
		dca_destroyreq(des_ctx);
	else
		/* Return it to the pool */
		dca_freereq(des_ctx);
}

int
dca_3desupdate(crypto_ctx_t *ctx, crypto_data_t *in,
    crypto_data_t *out, crypto_req_handle_t req, int flags)
{
	int			len;
	int			rawlen;
	int			rv;
	dca_request_t		*reqp = ctx->cc_provider_private;
	dca_request_t		*des_ctx = ctx->cc_provider_private;
	dca_t			*dca = ctx->cc_provider;
	crypto_data_t		*nin = &reqp->dr_ctx.in_dup;

	rawlen = dca_length(in) + des_ctx->dr_ctx.residlen;

	len = ROUNDDOWN(rawlen, DESBLOCK);
	/*
	 * If cd_miscdata non-null then this contains the IV.
	 */
	if (in->cd_miscdata != NULL) {
#ifdef UNALIGNED_POINTERS_PERMITTED
		uint32_t	*p = (uint32_t *)in->cd_miscdata;
		des_ctx->dr_ctx.iv[0] = htonl(p[0]);
		des_ctx->dr_ctx.iv[1] = htonl(p[1]);
#else
		uchar_t	*p = (uchar_t *)in->cd_miscdata;
		des_ctx->dr_ctx.iv[0] = p[0]<<24 | p[1]<<16 | p[2]<<8 | p[3];
		des_ctx->dr_ctx.iv[1] = p[4]<<24 | p[5]<<16 | p[6]<<8 | p[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}

	if (len > dca_length(out)) {
		DBG(dca, DWARN, "not enough output space (need %d, got %d)",
		    len, dca_length(out));
		out->cd_length = len;
		/* Do not free the context since the app will call again */
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if ((rv = dca_verifyio(in, out)) != CRYPTO_SUCCESS) {
		(void) dca_free_context(ctx);
		return (rv);
	}

	reqp->dr_kcf_req = req;

	/*
	 * From here on out, we are committed.
	 */

	if (len == 0) {
		/*
		 * No blocks being encrypted, so we just accumulate the
		 * input for the next pass and return.
		 */
		if ((rv = dca_getbufbytes(in, 0,
		    (rawlen % DESBLOCK) - des_ctx->dr_ctx.residlen,
		    des_ctx->dr_ctx.resid + des_ctx->dr_ctx.residlen)) !=
		    CRYPTO_SUCCESS) {
			DBG(dca, DWARN,
	    "dca_3desupdate: dca_getbufbytes() failed for residual only pass");
			dca_freereq(reqp);
			return (rv);
		}
		des_ctx->dr_ctx.residlen = rawlen % DESBLOCK;

		out->cd_length = 0;
		/*
		 * Do not free the context here since it will be done
		 * in the final function
		 */
		return (CRYPTO_SUCCESS);
	}

	/*
	 * Set up rbuf for previous residual data.
	 */
	if (des_ctx->dr_ctx.residlen) {
		bcopy(des_ctx->dr_ctx.resid, des_ctx->dr_ctx.activeresid,
		    des_ctx->dr_ctx.residlen);
		des_ctx->dr_ctx.activeresidlen = des_ctx->dr_ctx.residlen;
	}

	/*
	 * Locate and save residual data for next encrypt_update.
	 */
	if ((rv = dca_getbufbytes(in, len - des_ctx->dr_ctx.residlen,
	    rawlen % DESBLOCK, des_ctx->dr_ctx.resid)) != CRYPTO_SUCCESS) {
		DBG(dca, DWARN, "dca_3desupdate: dca_getbufbytes() failed");
		(void) dca_free_context(ctx);
		return (rv);
	}

	/* Calculate new residual length. */
	des_ctx->dr_ctx.residlen = rawlen % DESBLOCK;

	/*
	 * Make a local copy of the input crypto_data_t structure. This
	 * allows it to be manipulated locally and for dealing with in-place
	 * data (ie in == out).
	 */
	if ((rv = dca_dupcrypto(in, nin)) != CRYPTO_SUCCESS) {
		(void) dca_free_context(ctx);
		return (rv);
	}

	/* Set output to zero ready to take the processed data */
	out->cd_length = 0;

	reqp->dr_in = nin;
	reqp->dr_out = out;
	reqp->dr_job_stat = DS_3DESJOBS;
	reqp->dr_byte_stat = DS_3DESBYTES;

	rv = dca_3desstart(dca, flags, reqp);

	/*
	 * As this is multi-part the context is cleared on success
	 * (CRYPTO_QUEUED) in dca_3desfinal().
	 */

	if (rv != CRYPTO_QUEUED && rv != CRYPTO_BUFFER_TOO_SMALL) {
		(void) dca_free_context(ctx);
	}
	return (rv);
}

int
dca_3desfinal(crypto_ctx_t *ctx, crypto_data_t *out, int mode)
{
	dca_request_t	*des_ctx = ctx->cc_provider_private;
	dca_t		*dca = ctx->cc_provider;
	int		rv = CRYPTO_SUCCESS;

	ASSERT(ctx->cc_provider_private != NULL);
	/*
	 * There must be no unprocessed ciphertext/plaintext.
	 * This happens if the length of the last data is
	 * not a multiple of the DES block length.
	 */
	if (des_ctx->dr_ctx.residlen != 0) {
		DBG(dca, DWARN, "dca_3desfinal: invalid nonzero residual");
		if (mode & DR_DECRYPT) {
			rv = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
		} else {
			rv = CRYPTO_DATA_LEN_RANGE;
		}
	}
	(void) dca_free_context(ctx);
	out->cd_length = 0;
	return (rv);
}

int
dca_3desatomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *input, crypto_data_t *output,
    int kmflag, crypto_req_handle_t req, int mode)
{
	crypto_ctx_t	ctx;	/* on the stack */
	int		rv;

	ctx.cc_provider = provider;
	ctx.cc_session = session_id;

	/*
	 * Input must be a multiple of the block size. This test only
	 * works for non-padded mechanisms when the blocksize is 2^N.
	 */
	if ((dca_length(input) & (DESBLOCK - 1)) != 0) {
		DBG(NULL, DWARN, "dca_3desatomic: input not multiple of BS");
		if (mode & DR_DECRYPT) {
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		} else {
			return (CRYPTO_DATA_LEN_RANGE);
		}
	}

	rv = dca_3desctxinit(&ctx, mechanism, key, kmflag, mode);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "dca_3desatomic: dca_3desctxinit() failed");
		return (rv);
	}

	/*
	 * Set the atomic flag so that the hardware callback function
	 * will free the context.
	 */
	((dca_request_t *)ctx.cc_provider_private)->dr_ctx.atomic = 1;

	/* check for inplace ops */
	if (input == output) {
		((dca_request_t *)ctx.cc_provider_private)->dr_flags
		    |= DR_INPLACE;
	}

	rv = dca_3des(&ctx, input, output, req, mode);
	if ((rv != CRYPTO_QUEUED) && (rv != CRYPTO_SUCCESS)) {
		DBG(NULL, DWARN, "dca_3desatomic: dca_3des() failed");
		output->cd_length = 0;
	}

	/*
	 * The features of dca_3desfinal() are implemented within
	 * dca_3desdone() due to the asynchronous nature of dca_3des().
	 */

	/*
	 * The context will be freed in the hardware callback function if it
	 * is queued
	 */
	if (rv != CRYPTO_QUEUED)
		dca_3desctxfree(&ctx);

	return (rv);
}

int
dca_3desstart(dca_t *dca, uint32_t flags, dca_request_t *reqp)
{
	size_t		len;
	crypto_data_t	*in = reqp->dr_in;
	int		rv;
	dca_request_t	*ctx = reqp;
	uint32_t	iv[2];

	/*
	 * Preconditions:
	 * 1) in and out point to the "right" buffers.
	 * 2) in->b_bcount - in->b_resid == initial offset
	 * 3) likewise for out
	 * 4) there is enough space in the output
	 * 5) we perform a block for block encrypt
	 */
	len = ctx->dr_ctx.activeresidlen + dca_length(in);
	len = ROUNDDOWN(min(len, MAXPACKET), DESBLOCK);
	reqp->dr_pkt_length = (uint16_t)len;

	/* collect IVs for this pass */
	iv[0] = ctx->dr_ctx.iv[0];
	iv[1] = ctx->dr_ctx.iv[1];

	/*
	 * And also, for decrypt, collect the IV for the next pass.  For
	 * decrypt, the IV must be collected BEFORE decryption, or else
	 * we will lose it.  (For encrypt, we grab the IV AFTER encryption,
	 * in dca_3desdone.
	 */
	if (flags & DR_DECRYPT) {
		uchar_t		ivstore[DESBLOCK];
#ifdef UNALIGNED_POINTERS_PERMITTED
		uint32_t	*ivp = (uint32_t *)ivstore;
#else
		uchar_t		*ivp = ivstore;
#endif	/* UNALIGNED_POINTERS_PERMITTED */

		/* get last 8 bytes of ciphertext for IV of next op */
		/*
		 * If we're processing only a DESBLOCKS worth of data
		 * and there is active residual present then it will be
		 * needed for the IV also.
		 */
		if ((len == DESBLOCK) && ctx->dr_ctx.activeresidlen) {
			/* Bring the active residual into play */
			bcopy(ctx->dr_ctx.activeresid, ivstore,
			    ctx->dr_ctx.activeresidlen);
			rv = dca_getbufbytes(in, 0,
			    DESBLOCK - ctx->dr_ctx.activeresidlen,
			    ivstore + ctx->dr_ctx.activeresidlen);
		} else {
			rv = dca_getbufbytes(in,
			    len - DESBLOCK - ctx->dr_ctx.activeresidlen,
			    DESBLOCK, ivstore);
		}

		if (rv != CRYPTO_SUCCESS) {
			DBG(dca, DWARN,
			    "dca_3desstart: dca_getbufbytes() failed");
			return (rv);
		}

		/* store as a pair of native 32-bit values */
#ifdef UNALIGNED_POINTERS_PERMITTED
		ctx->dr_ctx.iv[0] = htonl(ivp[0]);
		ctx->dr_ctx.iv[1] = htonl(ivp[1]);
#else
		ctx->dr_ctx.iv[0] =
		    ivp[0]<<24 | ivp[1]<<16 | ivp[2]<<8 | ivp[3];
		ctx->dr_ctx.iv[1] =
		    ivp[4]<<24 | ivp[5]<<16 | ivp[6]<<8 | ivp[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}

	/* For now we force a pullup.  Add direct DMA later. */
	reqp->dr_flags &= ~(DR_SCATTER | DR_GATHER);
	if ((len < dca_mindma) || (ctx->dr_ctx.activeresidlen > 0) ||
	    dca_sgcheck(dca, reqp->dr_in, DCA_SG_CONTIG) ||
	    dca_sgcheck(dca, reqp->dr_out, DCA_SG_WALIGN)) {
		reqp->dr_flags |= DR_SCATTER | DR_GATHER;
	}

	/* Try to do direct DMA. */
	if (!(reqp->dr_flags & (DR_SCATTER | DR_GATHER))) {
		if (dca_bindchains(reqp, len, len) == DDI_SUCCESS) {
			reqp->dr_in->cd_offset += len;
			reqp->dr_in->cd_length -= len;
		} else {
			DBG(dca, DWARN,
			    "dca_3desstart: dca_bindchains() failed");
			return (CRYPTO_DEVICE_ERROR);
		}
	}

	/* gather the data into the device */
	if (reqp->dr_flags & DR_GATHER) {
		rv = dca_resid_gather(in, (char *)ctx->dr_ctx.activeresid,
		    &ctx->dr_ctx.activeresidlen, reqp->dr_ibuf_kaddr, len);
		if (rv != CRYPTO_SUCCESS) {
			DBG(dca, DWARN,
			    "dca_3desstart: dca_resid_gather() failed");
			return (rv);
		}
		/*
		 * Setup for scattering the result back out
		 * The output buffer is a multi-entry chain for x86 and
		 * a single entry chain for Sparc.
		 * Use the actual length if the first entry is sufficient.
		 */
		(void) ddi_dma_sync(reqp->dr_ibuf_dmah, 0, len,
		    DDI_DMA_SYNC_FORDEV);
		if (dca_check_dma_handle(dca, reqp->dr_ibuf_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			reqp->destroy = TRUE;
			return (CRYPTO_DEVICE_ERROR);
		}

		reqp->dr_in_paddr = reqp->dr_ibuf_head.dc_buffer_paddr;
		reqp->dr_in_next = reqp->dr_ibuf_head.dc_next_paddr;
		if (len > reqp->dr_ibuf_head.dc_buffer_length)
			reqp->dr_in_len = reqp->dr_ibuf_head.dc_buffer_length;
		else
			reqp->dr_in_len = len;
	}
	/*
	 * Setup for scattering the result back out
	 * The output buffer is a multi-entry chain for x86 and
	 * a single entry chain for Sparc.
	 * Use the actual length if the first entry is sufficient.
	 */
	if (reqp->dr_flags & DR_SCATTER) {
		reqp->dr_out_paddr = reqp->dr_obuf_head.dc_buffer_paddr;
		reqp->dr_out_next = reqp->dr_obuf_head.dc_next_paddr;
		if (len > reqp->dr_obuf_head.dc_buffer_length)
			reqp->dr_out_len = reqp->dr_obuf_head.dc_buffer_length;
		else
			reqp->dr_out_len = len;
	}

	reqp->dr_flags |= flags;
	reqp->dr_callback = dca_3desdone;

	/* write out the context structure */
	PUTCTX32(reqp, CTX_3DESIVHI, iv[0]);
	PUTCTX32(reqp, CTX_3DESIVLO, iv[1]);

	/* schedule the work by doing a submit */
	return (dca_start(dca, reqp, MCR1, 1));
}

void
dca_3desdone(dca_request_t *reqp, int errno)
{
	crypto_data_t	*out = reqp->dr_out;
	dca_request_t	*ctx = reqp;
	ASSERT(ctx != NULL);

	if (errno == CRYPTO_SUCCESS) {
		size_t		off;
		/*
		 * Save the offset: this has to be done *before* dca_scatter
		 * modifies the buffer.  We take the initial offset into the
		 * first buf, and add that to the total packet size to find
		 * the end of the packet.
		 */
		off = dca_length(out) + reqp->dr_pkt_length - DESBLOCK;

		if (reqp->dr_flags & DR_SCATTER) {
			(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0,
			    reqp->dr_out_len, DDI_DMA_SYNC_FORKERNEL);
			if (dca_check_dma_handle(reqp->dr_dca,
			    reqp->dr_obuf_dmah, DCA_FM_ECLASS_NONE) !=
			    DDI_SUCCESS) {
				reqp->destroy = TRUE;
				errno = CRYPTO_DEVICE_ERROR;
				goto errout;
			}

			errno = dca_scatter(reqp->dr_obuf_kaddr,
			    reqp->dr_out, reqp->dr_out_len, 0);
			if (errno != CRYPTO_SUCCESS) {
				DBG(NULL, DWARN,
				    "dca_3desdone: dca_scatter() failed");
				goto errout;
			}

		} else {
			/* we've processed some more data */
			out->cd_length += reqp->dr_pkt_length;
		}


		/*
		 * For encryption only, we have to grab the IV for the
		 * next pass AFTER encryption.
		 */
		if (reqp->dr_flags & DR_ENCRYPT) {
			uchar_t		ivstore[DESBLOCK];
#ifdef UNALIGNED_POINTERS_PERMITTED
			uint32_t	*iv = (uint32_t *)ivstore;
#else
			uchar_t		*iv = ivstore;
#endif	/* UNALIGNED_POINTERS_PERMITTED */

			/* get last 8 bytes for IV of next op */
			errno = dca_getbufbytes(out, off, DESBLOCK,
			    (uchar_t *)iv);
			if (errno != CRYPTO_SUCCESS) {
				DBG(NULL, DWARN,
				    "dca_3desdone: dca_getbufbytes() failed");
				goto errout;
			}

			/* store as a pair of native 32-bit values */
#ifdef UNALIGNED_POINTERS_PERMITTED
			ctx->dr_ctx.iv[0] = htonl(iv[0]);
			ctx->dr_ctx.iv[1] = htonl(iv[1]);
#else
			ctx->dr_ctx.iv[0] =
			    iv[0]<<24 | iv[1]<<16 | iv[2]<<8 | iv[3];
			ctx->dr_ctx.iv[1] =
			    iv[4]<<24 | iv[5]<<16 | iv[6]<<8 | iv[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
		}

		/*
		 * If there is more to do, then reschedule another
		 * pass.
		 */
		if (dca_length(reqp->dr_in) >= 8) {
			errno = dca_3desstart(reqp->dr_dca, reqp->dr_flags,
			    reqp);
			if (errno == CRYPTO_QUEUED) {
				return;
			}
		}
	}

errout:

	/*
	 * If this is an atomic operation perform the final function
	 * tasks (equivalent to to dca_3desfinal()).
	 */
	if (reqp->dr_ctx.atomic) {
		if ((errno == CRYPTO_SUCCESS) && (ctx->dr_ctx.residlen != 0)) {
			DBG(NULL, DWARN,
			    "dca_3desdone: invalid nonzero residual");
			if (reqp->dr_flags & DR_DECRYPT) {
				errno = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
			} else {
				errno = CRYPTO_DATA_LEN_RANGE;
			}
		}
	}

	ASSERT(reqp->dr_kcf_req != NULL);
	/* notify framework that request is completed */
	crypto_op_notification(reqp->dr_kcf_req, errno);
	DBG(NULL, DINTR,
	    "dca_3desdone: returning %d to the kef via crypto_op_notification",
	    errno);

	/* This has to be done after notifing the framework */
	if (reqp->dr_ctx.atomic) {
		reqp->dr_context = NULL;
		reqp->dr_ctx.atomic = 0;
		reqp->dr_ctx.ctx_cm_type = 0;
		if (reqp->destroy)
			dca_destroyreq(reqp);
		else
			dca_freereq(reqp);
	}
}

/* ARGSUSED */
int
dca_3desctxinit(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag, int flags)
{
	dca_request_t	*des_ctx;
	dca_t		*dca = ctx->cc_provider;
#ifdef UNALIGNED_POINTERS_PERMITTED
	uint32_t	*param;
	uint32_t	*value32;
#else
	uchar_t		*param;
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	uchar_t		*value;
	size_t		paramsz;
	unsigned	len;
	int		i, j;

	paramsz = mechanism->cm_param_len;
#ifdef UNALIGNED_POINTERS_PERMITTED
	param = (uint32_t *)mechanism->cm_param;
#else
	param = (uchar_t *)mechanism->cm_param;
#endif	/* UNALIGNED_POINTERS_PERMITTED */

	if ((paramsz != 0) && (paramsz != DES_IV_LEN)) {
		DBG(NULL, DWARN,
		    "dca_3desctxinit: parameter(IV) length not %d (%d)",
		    DES_IV_LEN, paramsz);
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if ((des_ctx = dca_getreq(dca, MCR1, 1)) == NULL) {
		dca_error(dca, "unable to allocate request for 3DES");
		return (CRYPTO_HOST_MEMORY);
	}
	/*
	 * Identify and store the IV as a pair of native 32-bit words.
	 *
	 * If cm_param == NULL then the IV comes from the cd_miscdata field
	 * in the crypto_data structure.
	 */
	if (param != NULL) {
		ASSERT(paramsz == DES_IV_LEN);
#ifdef UNALIGNED_POINTERS_PERMITTED
		des_ctx->dr_ctx.iv[0] = htonl(param[0]);
		des_ctx->dr_ctx.iv[1] = htonl(param[1]);
#else
		des_ctx->dr_ctx.iv[0] = param[0]<<24 | param[1]<<16 |
		    param[2]<<8 | param[3];
		des_ctx->dr_ctx.iv[1] = param[4]<<24 | param[5]<<16 |
		    param[6]<<8 | param[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */
	}
	des_ctx->dr_ctx.residlen = 0;
	des_ctx->dr_ctx.activeresidlen = 0;
	des_ctx->dr_ctx.ctx_cm_type = mechanism->cm_type;
	ctx->cc_provider_private = des_ctx;

	if (key->ck_format != CRYPTO_KEY_RAW) {
		DBG(NULL, DWARN,
	"dca_3desctxinit: only raw crypto key type support with DES/3DES");
		dca_3desctxfree(ctx);
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	len = key->ck_length;
	value = (uchar_t *)key->ck_data;

	if (flags & DR_TRIPLE) {
		/* 3DES */
		switch (len) {
		case 192:
			for (i = 0; i < 6; i++) {
				des_ctx->dr_ctx.key[i] = 0;
				for (j = 0; j < 4; j++) {
					des_ctx->dr_ctx.key[i] <<= 8;
					des_ctx->dr_ctx.key[i] |= *value;
					value++;
				}
			}
			break;

		case 128:
			for (i = 0; i < 4; i++) {
				des_ctx->dr_ctx.key[i] = 0;
				for (j = 0; j < 4; j++) {
					des_ctx->dr_ctx.key[i] <<= 8;
					des_ctx->dr_ctx.key[i] |= *value;
					value++;
				}
			}
			des_ctx->dr_ctx.key[4] = des_ctx->dr_ctx.key[0];
			des_ctx->dr_ctx.key[5] = des_ctx->dr_ctx.key[1];
			break;

		default:
			DBG(NULL, DWARN, "Incorrect 3DES keysize (%d)", len);
			dca_3desctxfree(ctx);
			return (CRYPTO_KEY_SIZE_RANGE);
		}
	} else {
		/* single DES */
		if (len != 64) {
			DBG(NULL, DWARN, "Incorrect DES keysize (%d)", len);
			dca_3desctxfree(ctx);
			return (CRYPTO_KEY_SIZE_RANGE);
		}

#ifdef UNALIGNED_POINTERS_PERMITTED
		value32 = (uint32_t *)value;
		des_ctx->dr_ctx.key[0] = htonl(value32[0]);
		des_ctx->dr_ctx.key[1] = htonl(value32[1]);
#else
		des_ctx->dr_ctx.key[0] =
		    value[0]<<24 | value[1]<<16 | value[2]<<8 | value[3];
		des_ctx->dr_ctx.key[1] =
		    value[4]<<24 | value[5]<<16 | value[6]<<8 | value[7];
#endif	/* UNALIGNED_POINTERS_PERMITTED */

		/* for single des just repeat des key */
		des_ctx->dr_ctx.key[4] =
		    des_ctx->dr_ctx.key[2] = des_ctx->dr_ctx.key[0];
		des_ctx->dr_ctx.key[5] =
		    des_ctx->dr_ctx.key[3] = des_ctx->dr_ctx.key[1];
	}

	/*
	 * Setup the context here so that we do not need to setup it up
	 * for every update
	 */
	PUTCTX16(des_ctx, CTX_LENGTH, CTX_3DES_LENGTH);
	PUTCTX16(des_ctx, CTX_CMD, CMD_3DES);
	PUTCTX32(des_ctx, CTX_3DESDIRECTION,
	    flags & DR_ENCRYPT ? CTX_3DES_ENCRYPT : CTX_3DES_DECRYPT);
	PUTCTX32(des_ctx, CTX_3DESKEY1HI, des_ctx->dr_ctx.key[0]);
	PUTCTX32(des_ctx, CTX_3DESKEY1LO, des_ctx->dr_ctx.key[1]);
	PUTCTX32(des_ctx, CTX_3DESKEY2HI, des_ctx->dr_ctx.key[2]);
	PUTCTX32(des_ctx, CTX_3DESKEY2LO, des_ctx->dr_ctx.key[3]);
	PUTCTX32(des_ctx, CTX_3DESKEY3HI, des_ctx->dr_ctx.key[4]);
	PUTCTX32(des_ctx, CTX_3DESKEY3LO, des_ctx->dr_ctx.key[5]);

	return (CRYPTO_SUCCESS);
}
