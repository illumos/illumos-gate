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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/dca.h>

/*
 * DSA implementation.
 */

static void dca_dsa_sign_done(dca_request_t *, int);
static void dca_dsa_verify_done(dca_request_t *, int);


int dca_dsa_sign(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *sig,
    crypto_req_handle_t req);
int dca_dsa_verify(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *sig,
    crypto_req_handle_t req);
int dca_dsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag, int mode);


int
dca_dsa_sign(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *sig,
    crypto_req_handle_t req)
{
	dca_request_t	*reqp = ctx->cc_provider_private;
	dca_t		*dca = ctx->cc_provider;
	int		err;
	int		rv = CRYPTO_QUEUED;
	caddr_t		kaddr;
	size_t		buflen;

	buflen = dca_length(data);
	if (buflen != SHA1LEN) {
		DBG(dca, DWARN, "dca_dsa_sign: data length != %d", SHA1LEN);
		rv = CRYPTO_DATA_LEN_RANGE;
		goto errout;
	}

	/* Return length needed to store the output. */
	if (dca_length(sig) < DSASIGLEN) {
		DBG(dca, DWARN,
		    "dca_dsa_sign: output buffer too short (%d < %d)",
		    dca_length(sig), DSASIGLEN);
		sig->cd_length = DSASIGLEN;
		rv = CRYPTO_BUFFER_TOO_SMALL;
		goto errout;
	}

	/*
	 * Don't change the data values of the data crypto_data_t structure
	 * yet. Only reset the sig cd_length to zero before writing to it.
	 */

	reqp->dr_job_stat = DS_DSASIGN;
	reqp->dr_byte_stat = -1;
	reqp->dr_in = data;
	reqp->dr_out = sig;
	reqp->dr_callback = dca_dsa_sign_done;

	reqp->dr_kcf_req = req;
	/* dca_gather() increments cd_offset & dec. cd_length by SHA1LEN. */
	err = dca_gather(data, reqp->dr_ibuf_kaddr, SHA1LEN, 1);
	if (err != CRYPTO_SUCCESS) {
		DBG(dca, DWARN, "dca_dsa_sign: dca_gather() failed");
		rv = err;
		goto errout;
	}


	/* sync the input buffer */
	(void) ddi_dma_sync(reqp->dr_ibuf_dmah, 0, SHA1LEN,
		DDI_DMA_SYNC_FORDEV);
	if (dca_check_dma_handle(dca, reqp->dr_ibuf_dmah,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		reqp->destroy = TRUE;
		rv = CRYPTO_DEVICE_ERROR;
		goto errout;
	}

	reqp->dr_in_paddr = reqp->dr_ibuf_paddr;
	reqp->dr_in_next = 0;
	reqp->dr_in_len = SHA1LEN;
	reqp->dr_pkt_length = buflen;

	/*
	 * The output requires *two* buffers, r followed by s.
	 */
	kaddr = reqp->dr_ctx_kaddr + reqp->dr_offset;

	/* r */
	reqp->dr_out_paddr = reqp->dr_obuf_paddr;
	reqp->dr_out_len = DSAPARTLEN;
	reqp->dr_out_next = reqp->dr_ctx_paddr + reqp->dr_offset;

	/* s */
	PUTDESC32(reqp, kaddr, DESC_BUFADDR,
	    reqp->dr_obuf_paddr + DSAPARTLEN);
	PUTDESC32(reqp, kaddr, DESC_NEXT, 0);
	PUTDESC16(reqp, kaddr, DESC_RSVD, 0);
	PUTDESC16(reqp, kaddr, DESC_LENGTH, DSAPARTLEN);

	/* schedule the work by doing a submit */
	rv = dca_start(dca, reqp, MCR2, 1);

errout:

	if (rv != CRYPTO_QUEUED && rv != CRYPTO_BUFFER_TOO_SMALL)
		(void) dca_free_context(ctx);

	return (rv);
}

static void
dca_dsa_sign_done(dca_request_t *reqp, int errno)
{
	if (errno == CRYPTO_SUCCESS) {
		(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0, DSASIGLEN,
		    DDI_DMA_SYNC_FORKERNEL);
		if (dca_check_dma_handle(reqp->dr_dca, reqp->dr_obuf_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			reqp->destroy = TRUE;
			errno = CRYPTO_DEVICE_ERROR;
			goto errout;
		}
		/*
		 * Set the sig cd_length to zero so it's ready to take the
		 * signature. Have already confirmed its size is adequate.
		 */
		reqp->dr_out->cd_length = 0;
		errno = dca_scatter(reqp->dr_obuf_kaddr,
		    reqp->dr_out, DSAPARTLEN, 1);
		if (errno != CRYPTO_SUCCESS) {
			DBG(reqp->dr_dca, DWARN,
			    "dca_dsa_sign_done: dca_scatter() failed");
			goto errout;
		}
		errno = dca_scatter(reqp->dr_obuf_kaddr+DSAPARTLEN,
		    reqp->dr_out, DSAPARTLEN, 1);
		if (errno != CRYPTO_SUCCESS) {
			DBG(reqp->dr_dca, DWARN,
			    "dca_dsa_sign_done: dca_scatter() failed");
		}
	}
errout:
	ASSERT(reqp->dr_kcf_req != NULL);

	/* notify framework that request is completed */
	crypto_op_notification(reqp->dr_kcf_req, errno);
	DBG(reqp->dr_dca, DINTR,
	    "dca_dsa_sign_done: rtn 0x%x to kef via crypto_op_notification",
	    errno);

	/*
	 * For non-atomic operations, reqp will be freed in the kCF
	 * callback function since it may be needed again if
	 * CRYPTO_BUFFER_TOO_SMALL is returned to kCF
	 */
	if (reqp->dr_ctx.atomic) {
		crypto_ctx_t ctx;
		ctx.cc_provider_private = reqp;
		dca_dsactxfree(&ctx);
	}
}

int
dca_dsa_verify(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *sig,
    crypto_req_handle_t req)
{
	dca_request_t	*reqp = ctx->cc_provider_private;
	dca_t		*dca = ctx->cc_provider;
	int		err;
	int		rv = CRYPTO_QUEUED;
	caddr_t		kaddr;

	/* Impossible for verify to be an in-place operation. */
	if (sig == NULL) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	if (dca_length(data) != SHA1LEN) {
		DBG(dca, DWARN, "dca_dsa_verify: input length != %d", SHA1LEN);
		rv = CRYPTO_DATA_LEN_RANGE;
		goto errout;
	}

	if (dca_length(sig) != DSASIGLEN) {
		DBG(dca, DWARN, "dca_dsa_verify: signature length != %d",
		    DSASIGLEN);
		rv = CRYPTO_SIGNATURE_LEN_RANGE;
		goto errout;
	}

	/* Don't change the data & sig values for verify. */

	reqp->dr_job_stat = DS_DSAVERIFY;
	reqp->dr_byte_stat = -1;

	/*
	 * Grab h, r and s.
	 */
	err = dca_gather(data, reqp->dr_ibuf_kaddr, SHA1LEN, 1);
	if (err != CRYPTO_SUCCESS) {
		DBG(dca, DWARN,
		    "dca_dsa_vrfy: dca_gather() failed for h");
		rv = err;
		goto errout;
	}
	err = dca_gather(sig, reqp->dr_ibuf_kaddr+SHA1LEN, DSAPARTLEN, 1);
	if (err != CRYPTO_SUCCESS) {
		DBG(dca, DWARN,
		    "dca_dsa_vrfy: dca_gather() failed for r");
		rv = err;
		goto errout;
	}
	err = dca_gather(sig, reqp->dr_ibuf_kaddr+SHA1LEN+DSAPARTLEN,
	    DSAPARTLEN, 1);
	if (err != CRYPTO_SUCCESS) {
		DBG(dca, DWARN,
		    "dca_dsa_vrfy: dca_gather() failed for s");
		rv = err;
		goto errout;
	}
	/*
	 * As dca_gather() increments the cd_offset and decrements
	 * the cd_length as it copies the data rewind the values ready for
	 * the final compare.
	 */
	sig->cd_offset -= (DSAPARTLEN * 2);
	sig->cd_length += (DSAPARTLEN * 2);
	/* sync the input buffer */
	(void) ddi_dma_sync(reqp->dr_ibuf_dmah, 0, SHA1LEN + DSAPARTLEN,
	    DDI_DMA_SYNC_FORDEV);

	if (dca_check_dma_handle(dca, reqp->dr_ibuf_dmah,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		reqp->destroy = TRUE;
		rv = CRYPTO_DEVICE_ERROR;
		goto errout;
	}

	reqp->dr_in = data;
	reqp->dr_out = sig;
	reqp->dr_kcf_req = req;
	reqp->dr_flags |= DR_SCATTER | DR_GATHER;
	reqp->dr_callback = dca_dsa_verify_done;

	/*
	 * Input requires three buffers.  m, followed by r, followed by s.
	 * In order to deal with things cleanly, we reverse the signature
	 * into the buffer and then fix up the pointers.
	 */
	reqp->dr_pkt_length = SHA1LEN;

	reqp->dr_in_paddr = reqp->dr_ibuf_paddr;
	reqp->dr_in_len = SHA1LEN;
	reqp->dr_in_next = reqp->dr_ctx_paddr + reqp->dr_offset;

	reqp->dr_out_paddr = reqp->dr_obuf_paddr;
	reqp->dr_out_len = DSAPARTLEN;
	reqp->dr_out_next = 0;

	/* setup 1st chain for r */
	kaddr = reqp->dr_ctx_kaddr + reqp->dr_offset;
	PUTDESC32(reqp, kaddr, DESC_BUFADDR, reqp->dr_ibuf_paddr + SHA1LEN);
	PUTDESC32(reqp, kaddr, DESC_NEXT,
	    reqp->dr_ctx_paddr + reqp->dr_offset + DESC_SIZE);
	PUTDESC16(reqp, kaddr, DESC_RSVD, 0);
	PUTDESC16(reqp, kaddr, DESC_LENGTH, DSAPARTLEN);

	/* and 2nd chain for s */
	kaddr = reqp->dr_ctx_kaddr + reqp->dr_offset + DESC_SIZE;
	PUTDESC32(reqp, kaddr, DESC_BUFADDR, reqp->dr_ibuf_paddr +
	    SHA1LEN + DSAPARTLEN);
	PUTDESC32(reqp, kaddr, DESC_NEXT, 0);
	PUTDESC16(reqp, kaddr, DESC_RSVD, 0);
	PUTDESC16(reqp, kaddr, DESC_LENGTH, DSAPARTLEN);

	/* schedule the work by doing a submit */
	rv = dca_start(dca, reqp, MCR2, 1);

errout:
	if (rv != CRYPTO_QUEUED && rv != CRYPTO_BUFFER_TOO_SMALL) {
		(void) dca_free_context(ctx);
	}
	return (rv);
}

static void
dca_dsa_verify_done(dca_request_t *reqp, int errno)
{
	if (errno == CRYPTO_SUCCESS) {
		int		count = DSAPARTLEN;
		crypto_data_t	*sig = reqp->dr_out;
		caddr_t		daddr;

		(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0, count,
		    DDI_DMA_SYNC_FORKERNEL);
		if (dca_check_dma_handle(reqp->dr_dca, reqp->dr_obuf_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			reqp->destroy = TRUE;
			errno = CRYPTO_DEVICE_ERROR;
			goto errout;
		}

		/* Can only handle a contiguous data buffer currently. */
		if (dca_sgcheck(reqp->dr_dca, sig, DCA_SG_CONTIG)) {
			errno = CRYPTO_SIGNATURE_INVALID;
			goto errout;
		}

		if ((daddr = dca_bufdaddr(sig)) == NULL) {
			errno = CRYPTO_ARGUMENTS_BAD;
			goto errout;
		}

		if (dca_bcmp_reverse(daddr, reqp->dr_obuf_kaddr,
		    DSAPARTLEN) != 0) {
			/* VERIFY FAILED */
			errno = CRYPTO_SIGNATURE_INVALID;
		}
	}
errout:
	ASSERT(reqp->dr_kcf_req != NULL);

	/* notify framework that request is completed */

	crypto_op_notification(reqp->dr_kcf_req, errno);
	DBG(reqp->dr_dca, DINTR,
	    "dca_dsa_verify_done: rtn 0x%x to kef via crypto_op_notification",
	    errno);

	/*
	 * For non-atomic operations, reqp will be freed in the kCF
	 * callback function since it may be needed again if
	 * CRYPTO_BUFFER_TOO_SMALL is returned to kCF
	 */
	if (reqp->dr_ctx.atomic) {
		crypto_ctx_t ctx;
		ctx.cc_provider_private = reqp;
		dca_dsactxfree(&ctx);
	}
}

/* ARGSUSED */
int
dca_dsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag, int mode)
{
	crypto_object_attribute_t	*attr;
	unsigned			plen = 0, qlen = 0, glen = 0, xlen = 0;
	uchar_t				*p, *q, *g, *x;
	dca_request_t			*reqp = NULL;
	dca_t				*dca = (dca_t *)ctx->cc_provider;
	int				rv = CRYPTO_SUCCESS;
	unsigned			pbits, padjlen;
	uint16_t			ctxlen;
	caddr_t				kaddr;

	if ((reqp = dca_getreq(dca, MCR2, 1)) == NULL) {
		dca_error(dca,
		    "dca_dsainit: unable to allocate request for DSA");
		rv = CRYPTO_HOST_MEMORY;
		goto errout;
	}

	ctx->cc_provider_private = reqp;
	reqp->dr_ctx.ctx_cm_type = mechanism->cm_type;

	if ((attr = dca_get_key_attr(key)) == NULL) {
		DBG(NULL, DWARN, "dca_dsainit: key attributes missing");
		rv = CRYPTO_KEY_TYPE_INCONSISTENT;
		goto errout;
	}

	/* Prime */
	if (dca_attr_lookup_uint8_array(attr, key->ck_count, CKA_PRIME,
	    (void *) &p, &plen)) {
		DBG(NULL, DWARN, "dca_dsainit: prime key value not present");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	/* Subprime */
	if (dca_attr_lookup_uint8_array(attr, key->ck_count, CKA_SUBPRIME,
	    (void *) &q, &qlen)) {
		DBG(NULL, DWARN, "dca_dsainit: subprime key value not present");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	/* Base */
	if (dca_attr_lookup_uint8_array(attr, key->ck_count, CKA_BASE,
	    (void *) &g, &glen)) {
		DBG(NULL, DWARN, "dca_dsainit: base key value not present");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	/* Value */
	if (dca_attr_lookup_uint8_array(attr, key->ck_count, CKA_VALUE,
	    (void *) &x, &xlen)) {
		DBG(NULL, DWARN, "dca_dsainit: value key not present");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	if (plen == 0 || qlen == 0 || glen == 0 || xlen == 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	if (plen > DSA_MAX_KEY_LEN) {
		/* maximum 1Kbit key */
		DBG(NULL, DWARN, "dca_dsainit: maximum 1Kbit key (%d)", plen);
		rv = CRYPTO_KEY_SIZE_RANGE;
		goto errout;
	}

	if (qlen > DSAPARTLEN) {
		DBG(NULL, DWARN, "dca_dsainit: q is too long (%d)", qlen);
		rv = CRYPTO_KEY_SIZE_RANGE;
		goto errout;
	}

	if (mode == DCA_DSA_SIGN && xlen > DSAPARTLEN) {
		DBG(NULL, DWARN,
		    "dca_dsainit: private key is too long (%d)", xlen);
		rv = CRYPTO_KEY_SIZE_RANGE;
		goto errout;
	}

	/*
	 * Setup the key partion of the request.
	 */

	pbits = dca_bitlen(p, plen);
	padjlen = dca_padfull(pbits);

	/* accounts for leading context words */
	if (mode == DCA_DSA_SIGN) {
		ctxlen = CTX_DSABIGNUMS + DSAPARTLEN + (padjlen * 2) +
		    DSAPARTLEN;
		PUTCTX16(reqp, CTX_CMD, CMD_DSASIGN);
	} else {
		ctxlen = CTX_DSABIGNUMS + DSAPARTLEN + (padjlen * 3);
		PUTCTX16(reqp, CTX_CMD, CMD_DSAVERIFY);
	}

	PUTCTX16(reqp, CTX_LENGTH, ctxlen);
	PUTCTX16(reqp, CTX_DSAMSGTYPE, CTX_DSAMSGTYPE_SHA1);
	PUTCTX16(reqp, CTX_DSARSVD, 0);
	if (mode == DCA_DSA_SIGN)
		PUTCTX16(reqp, CTX_DSARNG, CTX_DSARNG_GEN);
	else
		PUTCTX16(reqp, CTX_DSARNG, 0);
	PUTCTX16(reqp, CTX_DSAPLEN, pbits);

	kaddr = reqp->dr_ctx_kaddr + CTX_DSABIGNUMS;

	/* store the bignums */
	dca_reverse(q, kaddr, qlen, DSAPARTLEN);
	kaddr += DSAPARTLEN;

	dca_reverse(p, kaddr, plen, padjlen);
	kaddr += padjlen;

	dca_reverse(g, kaddr, glen, padjlen);
	kaddr += padjlen;

	if (mode == DCA_DSA_SIGN) {
		dca_reverse(x, kaddr, xlen, DSAPARTLEN);
		kaddr += DSAPARTLEN;
	} else {
		dca_reverse(x, kaddr, xlen, padjlen);
		kaddr += padjlen;
	}

	return (CRYPTO_SUCCESS);

errout:

	dca_dsactxfree(ctx);
	return (rv);
}

void
dca_dsactxfree(void *arg)
{
	crypto_ctx_t	*ctx = (crypto_ctx_t *)arg;
	dca_request_t	*reqp = ctx->cc_provider_private;

	if (reqp == NULL)
		return;

	reqp->dr_ctx.ctx_cm_type = 0;
	reqp->dr_ctx.atomic = 0;
	if (reqp->destroy)
		dca_destroyreq(reqp);
	else
		dca_freereq(reqp);

	ctx->cc_provider_private = NULL;
}

int
dca_dsaatomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *sig,
    int kmflag, crypto_req_handle_t req, int mode)
{
	crypto_ctx_t	ctx;	/* on the stack */
	int		rv;

	ctx.cc_provider = provider;
	ctx.cc_session = session_id;

	rv = dca_dsainit(&ctx, mechanism, key, kmflag, mode);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "dca_dsaatomic: dca_dsainit() failed");
		return (rv);
	}

	/*
	 * Set the atomic flag so that the hardware callback function
	 * will free the context.
	 */
	((dca_request_t *)ctx.cc_provider_private)->dr_ctx.atomic = 1;

	if (mode == DCA_DSA_SIGN) {
		rv = dca_dsa_sign(&ctx, data, sig, req);
	} else {
		ASSERT(mode == DCA_DSA_VRFY);
		rv = dca_dsa_verify(&ctx, data, sig, req);
	}

	/*
	 * The context will be freed in the hardware callback function if it
	 * is queued
	 */
	if (rv != CRYPTO_QUEUED)
		dca_dsactxfree(&ctx);

	return (rv);
}
