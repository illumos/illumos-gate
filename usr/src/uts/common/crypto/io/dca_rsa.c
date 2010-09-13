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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/note.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/dca.h>


static void dca_rsaverifydone(dca_request_t *, int);
static void dca_rsadone(dca_request_t *, int);

/* Exported function prototypes */
int dca_rsastart(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t, int);
int dca_rsainit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *, int);
void dca_rsactxfree(void *);
int dca_rsaatomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    int, crypto_req_handle_t, int);

/* Local function prototypes */
static int dca_pkcs1_padding(dca_t *dca, caddr_t buf, int flen, int tlen,
    int private);
static int dca_pkcs1_unpadding(char *buf, int *tlen, int flen, int mode);
static int dca_x509_padding(caddr_t buf, int flen, int tlen);
static int dca_x509_unpadding(char *buf, int tlen, int flen, int mode);
static int decrypt_error_code(int mode, int decrypt, int verify, int def);


int dca_rsastart(crypto_ctx_t *ctx, crypto_data_t *in, crypto_data_t *out,
    crypto_req_handle_t req, int mode)
{
	dca_request_t		*reqp = ctx->cc_provider_private;
	dca_t			*dca = ctx->cc_provider;
	caddr_t			daddr;
	int			rv = CRYPTO_QUEUED;
	int			len;

	/* We don't support non-contiguous buffers for RSA */
	if (dca_sgcheck(dca, in, DCA_SG_CONTIG) ||
	    dca_sgcheck(dca, out, DCA_SG_CONTIG)) {
		rv = CRYPTO_NOT_SUPPORTED;
		goto errout;
	}

	len = dca_length(in);

	/* Extracting the key attributes is now done in dca_rsainit(). */
	if (mode == DCA_RSA_ENC || mode == DCA_RSA_SIGN ||
	    mode == DCA_RSA_SIGNR) {
		/*
		 * Return length needed to store the output.
		 * For sign, sign-recover, and encrypt, the output buffer
		 * should not be smaller than modlen since PKCS or X_509
		 * padding will be applied
		 */
		if (dca_length(out) < reqp->dr_ctx.modlen) {
			DBG(dca, DWARN,
			    "dca_rsastart: output buffer too short (%d < %d)",
			    dca_length(out), reqp->dr_ctx.modlen);
			out->cd_length = reqp->dr_ctx.modlen;
			rv = CRYPTO_BUFFER_TOO_SMALL;
			goto errout;
		}
	}
	if (out != in && out->cd_length > reqp->dr_ctx.modlen)
		out->cd_length = reqp->dr_ctx.modlen;

	/* The input length should not be bigger than the modulus */
	if (len > reqp->dr_ctx.modlen) {
		rv = decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_LEN_RANGE,
		    CRYPTO_SIGNATURE_LEN_RANGE, CRYPTO_DATA_LEN_RANGE);
		goto errout;
	}

	/*
	 * For decryption, verify, and verifyRecover, the input length should
	 * not be less than the modulus
	 */
	if (len < reqp->dr_ctx.modlen && (mode == DCA_RSA_DEC ||
	    mode == DCA_RSA_VRFY || mode == DCA_RSA_VRFYR)) {
		rv = decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_LEN_RANGE,
		    CRYPTO_SIGNATURE_LEN_RANGE, CRYPTO_DATA_LEN_RANGE);
		goto errout;
	}

	/*
	 * For decryption and verifyRecover, the output buffer should not
	 * be less than the modulus
	 */
	if (out->cd_length < reqp->dr_ctx.modlen && (mode == DCA_RSA_DEC ||
	    mode == DCA_RSA_VRFYR) &&
	    reqp->dr_ctx.ctx_cm_type == RSA_X_509_MECH_INFO_TYPE) {
		out->cd_length = reqp->dr_ctx.modlen;
		rv = CRYPTO_BUFFER_TOO_SMALL;
		goto errout;
	}

	/* For decrypt and verify, the input should not be less than output */
	if (out && len < out->cd_length) {
		if ((rv = decrypt_error_code(mode,
		    CRYPTO_ENCRYPTED_DATA_LEN_RANGE,
		    CRYPTO_SIGNATURE_LEN_RANGE, CRYPTO_SUCCESS)) !=
		    CRYPTO_SUCCESS)
			goto errout;
	}

	if ((daddr = dca_bufdaddr(in)) == NULL && len > 0) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	if (dca_numcmp(daddr, len, (char *)reqp->dr_ctx.mod,
	    reqp->dr_ctx.modlen) > 0) {
		DBG(dca, DWARN,
		    "dca_rsastart: input larger (numerically) than modulus!");
		rv = decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_INVALID,
		    CRYPTO_SIGNATURE_INVALID, CRYPTO_DATA_INVALID);
		goto errout;
	}

	reqp->dr_byte_stat = -1;
	reqp->dr_in = in;
	reqp->dr_out = out;
	reqp->dr_kcf_req = req;
	if (mode == DCA_RSA_VRFY)
		reqp->dr_callback = dca_rsaverifydone;
	else
		reqp->dr_callback = dca_rsadone;

	dca_reverse(daddr, reqp->dr_ibuf_kaddr, len, reqp->dr_pkt_length);
	if (mode == DCA_RSA_ENC || mode == DCA_RSA_SIGN ||
	    mode == DCA_RSA_SIGNR) {
		/*
		 * Needs to pad appropriately for encrypt, sign, and
		 * sign_recover
		 */
		if (reqp->dr_ctx.ctx_cm_type == RSA_PKCS_MECH_INFO_TYPE) {
			if ((rv = dca_pkcs1_padding(dca, reqp->dr_ibuf_kaddr,
			    len, reqp->dr_ctx.modlen, reqp->dr_ctx.pqfix)) !=
			    CRYPTO_QUEUED)
				goto errout;
		} else if (reqp->dr_ctx.ctx_cm_type ==
		    RSA_X_509_MECH_INFO_TYPE) {
			if ((rv = dca_x509_padding(reqp->dr_ibuf_kaddr,
			    len, reqp->dr_pkt_length)) != CRYPTO_QUEUED)
				goto errout;
		}
	}
	reqp->dr_ctx.mode = mode;

	/*
	 * Since the max RSA input size is 256 bytes (2048 bits), the firstx
	 * page (at least 4096 bytes) in the pre-mapped buffer is large enough.
	 * Therefore, we use this first page for RSA.
	 */
	reqp->dr_in_paddr = reqp->dr_ibuf_head.dc_buffer_paddr;
	reqp->dr_in_next = 0;
	reqp->dr_in_len = reqp->dr_pkt_length;
	reqp->dr_out_paddr = reqp->dr_obuf_head.dc_buffer_paddr;
	reqp->dr_out_next = 0;
	reqp->dr_out_len = reqp->dr_pkt_length;

	/* schedule the work by doing a submit */
	rv = dca_start(dca, reqp, MCR2, 1);


errout:
	if (rv != CRYPTO_QUEUED && rv != CRYPTO_BUFFER_TOO_SMALL)
		(void) dca_free_context(ctx);

	return (rv);
}

void
dca_rsadone(dca_request_t *reqp, int errno)
{
	if (errno == CRYPTO_SUCCESS) {
		int	outsz = reqp->dr_out->cd_length;
		caddr_t	daddr;

		(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0, reqp->dr_out_len,
		    DDI_DMA_SYNC_FORKERNEL);
		if (dca_check_dma_handle(reqp->dr_dca, reqp->dr_obuf_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			reqp->destroy = TRUE;
			errno = CRYPTO_DEVICE_ERROR;
			goto errout;
		}

		if (reqp->dr_ctx.mode == DCA_RSA_DEC ||
		    reqp->dr_ctx.mode == DCA_RSA_VRFY ||
		    reqp->dr_ctx.mode == DCA_RSA_VRFYR) {
			/*
			 * Needs to unpad appropriately for decrypt, verify,
			 * and verify_recover
			 */
			if (reqp->dr_ctx.ctx_cm_type ==
			    RSA_PKCS_MECH_INFO_TYPE) {
				errno = dca_pkcs1_unpadding(
				    reqp->dr_obuf_kaddr, &outsz,
				    reqp->dr_ctx.modlen, reqp->dr_ctx.mode);

				/* check for bad data errors */
				if (errno != CRYPTO_SUCCESS &&
				    errno != CRYPTO_BUFFER_TOO_SMALL) {
					goto errout;
				}
				if (dca_bufdaddr(reqp->dr_out) == NULL) {
					errno = CRYPTO_BUFFER_TOO_SMALL;
				}
				if (errno == CRYPTO_BUFFER_TOO_SMALL) {
					reqp->dr_out->cd_length = outsz;
					goto errout;
				}
				/* Reset the output data length */
				reqp->dr_out->cd_length = outsz;
			} else if (reqp->dr_ctx.ctx_cm_type ==
			    RSA_X_509_MECH_INFO_TYPE) {
				if ((errno = dca_x509_unpadding(
				    reqp->dr_obuf_kaddr, outsz,
				    reqp->dr_pkt_length, reqp->dr_ctx.mode)) !=
				    CRYPTO_SUCCESS)
					goto errout;
			}
		}

		if ((daddr = dca_bufdaddr(reqp->dr_out)) == NULL) {
			DBG(reqp->dr_dca, DINTR,
			    "dca_rsadone: reqp->dr_out is bad");
			errno = CRYPTO_ARGUMENTS_BAD;
			goto errout;
		}
		/*
		 * Note that there may be some number of null bytes
		 * at the end of the source (result), but we don't care
		 * about them -- they are place holders only and are
		 * truncated here.
		 */
		dca_reverse(reqp->dr_obuf_kaddr, daddr, outsz, outsz);
	}
errout:
	ASSERT(reqp->dr_kcf_req != NULL);

	/* notify framework that request is completed */
	crypto_op_notification(reqp->dr_kcf_req, errno);
	DBG(reqp->dr_dca, DINTR,
	    "dca_rsadone: returning 0x%x to the kef via crypto_op_notification",
	    errno);

	/*
	 * For non-atomic operations, reqp will be freed in the kCF
	 * callback function since it may be needed again if
	 * CRYPTO_BUFFER_TOO_SMALL is returned to kCF
	 */
	if (reqp->dr_ctx.atomic) {
		crypto_ctx_t ctx;
		ctx.cc_provider_private = reqp;
		dca_rsactxfree(&ctx);
	}
}

void
dca_rsaverifydone(dca_request_t *reqp, int errno)
{
	if (errno == CRYPTO_SUCCESS) {
		char	scratch[RSA_MAX_KEY_LEN];
		int	outsz = reqp->dr_out->cd_length;
		caddr_t	daddr;

		/*
		 * ASSUMPTION: the signature length was already
		 * checked on the way in, and it is a valid length.
		 */
		(void) ddi_dma_sync(reqp->dr_obuf_dmah, 0, outsz,
		    DDI_DMA_SYNC_FORKERNEL);
		if (dca_check_dma_handle(reqp->dr_dca, reqp->dr_obuf_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			reqp->destroy = TRUE;
			errno = CRYPTO_DEVICE_ERROR;
			goto errout;
		}

		if (reqp->dr_ctx.mode == DCA_RSA_DEC ||
		    reqp->dr_ctx.mode == DCA_RSA_VRFY ||
		    reqp->dr_ctx.mode == DCA_RSA_VRFYR) {
			/*
			 * Needs to unpad appropriately for decrypt, verify,
			 * and verify_recover
			 */
			if (reqp->dr_ctx.ctx_cm_type ==
			    RSA_PKCS_MECH_INFO_TYPE) {
				errno = dca_pkcs1_unpadding(
				    reqp->dr_obuf_kaddr, &outsz,
				    reqp->dr_ctx.modlen, reqp->dr_ctx.mode);

				/* check for bad data errors */
				if (errno != CRYPTO_SUCCESS &&
				    errno != CRYPTO_BUFFER_TOO_SMALL) {
					goto errout;
				}
				if (dca_bufdaddr(reqp->dr_out) == NULL) {
					errno = CRYPTO_BUFFER_TOO_SMALL;
				}
				if (errno == CRYPTO_BUFFER_TOO_SMALL) {
					reqp->dr_out->cd_length = outsz;
					goto errout;
				}
				/* Reset the output data length */
				reqp->dr_out->cd_length = outsz;
			} else if (reqp->dr_ctx.ctx_cm_type ==
			    RSA_X_509_MECH_INFO_TYPE) {
				if ((errno = dca_x509_unpadding(
				    reqp->dr_obuf_kaddr, outsz,
				    reqp->dr_pkt_length, reqp->dr_ctx.mode)) !=
				    CRYPTO_SUCCESS)
					goto errout;
			}
		}

		dca_reverse(reqp->dr_obuf_kaddr, scratch, outsz, outsz);

		if ((daddr = dca_bufdaddr(reqp->dr_out)) == NULL) {
			errno = CRYPTO_ARGUMENTS_BAD;
			goto errout;
		}
		if (dca_numcmp(daddr, reqp->dr_out->cd_length, scratch,
		    outsz) != 0) {
			/* VERIFY FAILED */
			errno = CRYPTO_SIGNATURE_INVALID;
		}
	}
errout:
	ASSERT(reqp->dr_kcf_req != NULL);

	/* notify framework that request is completed */
	crypto_op_notification(reqp->dr_kcf_req, errno);
	DBG(reqp->dr_dca, DINTR,
	    "dca_rsaverifydone: rtn 0x%x to the kef via crypto_op_notification",
	    errno);

	/*
	 * For non-atomic operations, reqp will be freed in the kCF
	 * callback function since it may be needed again if
	 * CRYPTO_BUFFER_TOO_SMALL is returned to kCF
	 */
	if (reqp->dr_ctx.atomic) {
		crypto_ctx_t ctx;
		ctx.cc_provider_private = reqp;
		dca_rsactxfree(&ctx);
	}
}

/*
 * Setup either a public or a private RSA key for subsequent uses
 */
int
dca_rsainit(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, int kmflag)
{
	crypto_object_attribute_t	*attr;
	unsigned			expname = 0;
	void				*attrdata;
	int rv;

	uchar_t			*exp;
	uchar_t			*p;
	uchar_t			*q;
	uchar_t			*dp;
	uchar_t			*dq;
	uchar_t			*pinv;

	unsigned		explen = 0;
	unsigned		plen = 0;
	unsigned		qlen = 0;
	unsigned		dplen = 0;
	unsigned		dqlen = 0;
	unsigned		pinvlen = 0;

	unsigned		modbits, expbits, pbits, qbits;
	unsigned		modfix, expfix, pqfix = 0;
	uint16_t		ctxlen;
	caddr_t			kaddr;
	dca_request_t		*reqp = NULL;
	dca_t			*dca = (dca_t *)ctx->cc_provider;

	DBG(NULL, DENTRY, "dca_rsainit: start");

	if ((reqp = dca_getreq(dca, MCR2, 1)) == NULL) {
		DBG(NULL, DWARN,
		    "dca_rsainit: unable to allocate request for RSA");
		rv = CRYPTO_HOST_MEMORY;
		goto errout;
	}

	reqp->dr_ctx.ctx_cm_type = mechanism->cm_type;
	ctx->cc_provider_private = reqp;

	/*
	 * Key type can be either RAW, or REFERENCE, or ATTR_LIST (VALUE).
	 * Only ATTR_LIST is supported on Deimos for RSA.
	 */
	if ((attr = dca_get_key_attr(key)) == NULL) {
		DBG(NULL, DWARN, "dca_rsainit: key attributes missing");
		rv = CRYPTO_KEY_TYPE_INCONSISTENT;
		goto errout;
	}

	if (dca_find_attribute(attr, key->ck_count, CKA_PUBLIC_EXPONENT))
		expname = CKA_PUBLIC_EXPONENT;

	/*
	 * RSA public key has only public exponent. RSA private key must have
	 * private exponent. However, it may also have public exponent.
	 * Thus, the existance of a private exponent indicates a private key.
	 */
	if (dca_find_attribute(attr, key->ck_count, CKA_PRIVATE_EXPONENT))
		expname = CKA_PRIVATE_EXPONENT;

	if (!expname) {
		DBG(NULL, DWARN, "dca_rsainit: no exponent in key");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	/* Modulus */
	if ((rv = dca_attr_lookup_uint8_array(attr, key->ck_count, CKA_MODULUS,
	    &attrdata, &(reqp->dr_ctx.modlen))) != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "dca_rsainit: failed to retrieve modulus");
		goto errout;
	}
	if ((reqp->dr_ctx.modlen == 0) ||
	    (reqp->dr_ctx.modlen > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "dca_rsainit: bad modulus size");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}
	if ((reqp->dr_ctx.mod = kmem_alloc(reqp->dr_ctx.modlen, kmflag)) ==
	    NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto errout;
	}
	bcopy(attrdata, reqp->dr_ctx.mod, reqp->dr_ctx.modlen);

	/* Exponent */
	if ((rv = dca_attr_lookup_uint8_array(attr, key->ck_count, expname,
	    (void **) &exp, &explen)) != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "dca_rsainit: failed to retrieve exponent");
		goto errout;
	}
	if ((explen == 0) || (explen > RSA_MAX_KEY_LEN)) {
		DBG(NULL, DWARN, "dca_rsainit: bad exponent size");
		rv = CRYPTO_ARGUMENTS_BAD;
		goto errout;
	}

	/* Lookup private attributes */
	if (expname == CKA_PRIVATE_EXPONENT) {
		/* Prime 1 */
		(void) dca_attr_lookup_uint8_array(attr, key->ck_count,
		    CKA_PRIME_1, (void **)&q, &qlen);

		/* Prime 2 */
		(void) dca_attr_lookup_uint8_array(attr, key->ck_count,
		    CKA_PRIME_2, (void **)&p, &plen);

		/* Exponent 1 */
		(void) dca_attr_lookup_uint8_array(attr, key->ck_count,
		    CKA_EXPONENT_1, (void **)&dq, &dqlen);

		/* Exponent 2 */
		(void) dca_attr_lookup_uint8_array(attr, key->ck_count,
		    CKA_EXPONENT_2, (void **)&dp, &dplen);

		/* Coefficient */
		(void) dca_attr_lookup_uint8_array(attr, key->ck_count,
		    CKA_COEFFICIENT, (void **)&pinv, &pinvlen);
	}

	modbits = dca_bitlen(reqp->dr_ctx.mod, reqp->dr_ctx.modlen);
	expbits = dca_bitlen(exp, explen);

	if ((modfix = dca_padfull(modbits)) == 0) {
		DBG(NULL, DWARN, "dca_rsainit: modulus too long");
		rv = CRYPTO_KEY_SIZE_RANGE;
		goto errout;
	}
	expfix =  ROUNDUP(explen, sizeof (uint32_t));

	if (plen && qlen && dplen && dqlen && pinvlen) {
		unsigned pfix, qfix;
		qbits = dca_bitlen(q, qlen);
		pbits = dca_bitlen(p, plen);
		qfix = dca_padhalf(qbits);
		pfix = dca_padhalf(pbits);
		if (pfix & qfix)
			pqfix = max(pfix, qfix);
	}

	if (pqfix) {
		reqp->dr_job_stat = DS_RSAPRIVATE;
		reqp->dr_pkt_length = 2 * pqfix;
	} else {
		reqp->dr_job_stat = DS_RSAPUBLIC;
		reqp->dr_pkt_length = modfix;
	}

	if (pqfix) {
		/*
		 * NOTE: chip's notion of p vs. q is reversed from
		 * PKCS#11.  We use the chip's notion in our variable
		 * naming.
		 */
		ctxlen = 8 + pqfix * 5;

		/* write out the context structure */
		PUTCTX16(reqp, CTX_CMD, CMD_RSAPRIVATE);
		PUTCTX16(reqp, CTX_LENGTH, ctxlen);
		/* exponent and modulus length in bits!!! */
		PUTCTX16(reqp, CTX_RSAQLEN, qbits);
		PUTCTX16(reqp, CTX_RSAPLEN, pbits);

		kaddr = reqp->dr_ctx_kaddr + CTX_RSABIGNUMS;

		/* store the bignums */
		dca_reverse(p, kaddr, plen, pqfix);
		kaddr += pqfix;

		dca_reverse(q, kaddr, qlen, pqfix);
		kaddr += pqfix;

		dca_reverse(dp, kaddr, dplen, pqfix);
		kaddr += pqfix;

		dca_reverse(dq, kaddr, dqlen, pqfix);
		kaddr += pqfix;

		dca_reverse(pinv, kaddr, pinvlen, pqfix);
		kaddr += pqfix;
	} else {
		ctxlen = 8 + modfix + expfix;
		/* write out the context structure */
		PUTCTX16(reqp, CTX_CMD, CMD_RSAPUBLIC);
		PUTCTX16(reqp, CTX_LENGTH, (uint16_t)ctxlen);
		/* exponent and modulus length in bits!!! */
		PUTCTX16(reqp, CTX_RSAEXPLEN, expbits);
		PUTCTX16(reqp, CTX_RSAMODLEN, modbits);

		kaddr = reqp->dr_ctx_kaddr + CTX_RSABIGNUMS;

		/* store the bignums */
		dca_reverse(reqp->dr_ctx.mod, kaddr, reqp->dr_ctx.modlen,
		    modfix);
		kaddr += modfix;

		dca_reverse(exp, kaddr, explen, expfix);
		kaddr += expfix;
	}

	reqp->dr_ctx.pqfix = pqfix;

errout:
	if (rv != CRYPTO_SUCCESS)
		dca_rsactxfree(ctx);

	return (rv);
}

void
dca_rsactxfree(void *arg)
{
	crypto_ctx_t	*ctx = (crypto_ctx_t *)arg;
	dca_request_t	*reqp = ctx->cc_provider_private;

	if (reqp == NULL)
		return;

	if (reqp->dr_ctx.mod)
		kmem_free(reqp->dr_ctx.mod, reqp->dr_ctx.modlen);

	reqp->dr_ctx.mode = 0;
	reqp->dr_ctx.ctx_cm_type = 0;
	reqp->dr_ctx.mod = NULL;
	reqp->dr_ctx.modlen = 0;
	reqp->dr_ctx.pqfix = 0;
	reqp->dr_ctx.atomic = 0;

	if (reqp->destroy)
		dca_destroyreq(reqp);
	else
		dca_freereq(reqp);

	ctx->cc_provider_private = NULL;
}

int
dca_rsaatomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *input, crypto_data_t *output,
    int kmflag, crypto_req_handle_t req, int mode)
{
	crypto_ctx_t	ctx;	/* on the stack */
	int		rv;

	ctx.cc_provider = provider;
	ctx.cc_session = session_id;

	rv = dca_rsainit(&ctx, mechanism, key, kmflag);
	if (rv != CRYPTO_SUCCESS) {
		DBG(NULL, DWARN, "dca_rsaatomic: dca_rsainit() failed");
		/* The content of ctx should have been freed already */
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

	rv = dca_rsastart(&ctx, input, output, req, mode);

	/*
	 * The context will be freed in the hardware callback function if it
	 * is queued
	 */
	if (rv != CRYPTO_QUEUED)
		dca_rsactxfree(&ctx);

	return (rv);
}


/*
 * For RSA_PKCS padding and unpadding:
 * 1. The minimum padding is 11 bytes.
 * 2. The first and the last bytes must 0.
 * 3. The second byte is 1 for private and 2 for public keys.
 * 4. Pad with 0xff for private and non-zero random for public keys.
 */
static int
dca_pkcs1_padding(dca_t *dca, caddr_t buf, int flen, int tlen, int private)
{
	int i;

	DBG(NULL, DENTRY,
	    "dca_pkcs1_padding: tlen: %d, flen: %d: private: %d\n",
	    tlen, flen, private);

	if (flen > tlen - 11)
		return (CRYPTO_DATA_LEN_RANGE);

	if (private) {
		/* Padding for private encrypt */
		buf[flen] = '\0';
		for (i = flen + 1; i < tlen - 2; i++) {
			buf[i] = (unsigned char) 0xff;
		}
		buf[tlen - 2] = 1;
		buf[tlen - 1] = 0;
	} else {
		/* Padding for public encrypt */
		buf[flen] = '\0';

		if (dca_random_buffer(dca, &buf[flen+1], tlen - flen - 3) !=
		    CRYPTO_SUCCESS)
			return (CRYPTO_RANDOM_NO_RNG);

		buf[tlen - 2] = 2;
		buf[tlen - 1] = 0;
	}

	return (CRYPTO_QUEUED);
}

static int
dca_pkcs1_unpadding(char *buf, int *tlen, int flen, int mode)
{
	int i;
	const unsigned char *p;
	unsigned char type;

	DBG(NULL, DENTRY, "dca_pkcs1_unpadding: tlen: %d, flen: %d\n",
	    *tlen, flen);

	p = (unsigned char *) buf + (flen-1);
	if (*(p--) != 0)
		return decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_INVALID,
		    CRYPTO_SIGNATURE_INVALID, CRYPTO_DATA_INVALID);

	/* It is ok if the data length is 0 after removing the padding */
	type = *(p--);
	if (type == 01) {
		for (i = flen - 3; i >= 0; i--) {
			if (*p != 0xff) {
				if (*p == '\0') {
					p--;
					break;
				} else {
					return decrypt_error_code(mode,
					    CRYPTO_ENCRYPTED_DATA_INVALID,
					    CRYPTO_SIGNATURE_INVALID,
					    CRYPTO_DATA_INVALID);
				}
			}
			p--;
		}
	} else if (type == 02) {
		for (i = flen - 3; i >= 0; i--) {
			if (*p == '\0') {
				p--;
				break;
			}
			p--;
		}
	} else {
		return decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_INVALID,
		    CRYPTO_SIGNATURE_INVALID, CRYPTO_DATA_INVALID);
	}

	/* i < 0 means did not find the end of the padding */
	if (i < 0)
		return decrypt_error_code(mode, CRYPTO_ENCRYPTED_DATA_INVALID,
		    CRYPTO_SIGNATURE_INVALID, CRYPTO_DATA_INVALID);

	if (i > *tlen) {
		*tlen = i;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if (flen - i < 11)
		return decrypt_error_code(mode,
		    CRYPTO_ENCRYPTED_DATA_LEN_RANGE,
		    CRYPTO_SIGNATURE_LEN_RANGE, CRYPTO_DATA_LEN_RANGE);

	/* Return the unpadded length to the caller */
	*tlen = i;

	return (CRYPTO_SUCCESS);
}

/*
 * For RSA_X_509 padding and unpadding, pad all 0s before actual data.
 * Note that the data will be in reverse order.
 */
static int
dca_x509_padding(caddr_t buf, int flen, int tlen)
{
	DBG(NULL, DENTRY, "dca_x509_padding: tlen: %d, flen: %d\n",
	    tlen, flen);

	bzero(buf+tlen, tlen - flen);

	return (CRYPTO_QUEUED);
}

/* ARGSUSED */
static int
dca_x509_unpadding(char *buf, int tlen, int flen, int mode)
{
	int i;
	const unsigned char *p;

	DBG(NULL, DENTRY, "dca_x509_unpadding: tlen: %d, flen: %d\n",
	    tlen, flen);

	p = (unsigned char *) buf + flen;
	for (i = tlen; i < flen; i++) {
		if (*(--p) != 0)
			return (CRYPTO_SIGNATURE_INVALID);
	}

	return (CRYPTO_SUCCESS);
}

static int decrypt_error_code(int mode, int decrypt, int verify, int def)
{
	switch (mode) {
	case DCA_RSA_DEC:
		return (decrypt);
	case DCA_RSA_VRFY:
	case DCA_RSA_VRFYR:
		return (verify);
	default:
		return (def);
	}
}
