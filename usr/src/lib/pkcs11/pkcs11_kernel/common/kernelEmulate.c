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

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelEmulate.h"

/*
 * Helper routine to know if this is a HMAC. We can't just check
 * the CKF_SIGN mech flag as it is set for non-HMAC mechs too.
 */
boolean_t
is_hmac(CK_MECHANISM_TYPE mechanism)
{
	switch (mechanism) {
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
		return (B_TRUE);

	default:
		return (B_FALSE);
	}
}

/*
 * Helper routine to allocate an emulation structure for the session.
 * buflen indicates the size of the scratch buffer to be allocated.
 */
CK_RV
emulate_buf_init(kernel_session_t *session_p, int buflen, int opflag)
{
	digest_buf_t *bufp;
	crypto_active_op_t *opp;

	opp = (opflag & OP_DIGEST) ? &(session_p->digest) : \
	    ((opflag & OP_SIGN) ? &(session_p->sign) : &(session_p->verify));

	bufp = opp->context;

	if (bufp != NULL) {
		bufp->indata_len = 0;
		/*
		 * We can reuse the context structure, digest_buf_t.
		 * See if we can reuse the scratch buffer in the context too.
		 */
		if (buflen > bufp->buf_len) {
			free(bufp->buf);
			bufp->buf = NULL;
		}
	} else {
		bufp = opp->context = calloc(1, sizeof (digest_buf_t));
		if (bufp == NULL) {
			return (CKR_HOST_MEMORY);
		}
	}

	if (bufp->buf == NULL) {
		bufp->buf = malloc(buflen);
		if (bufp->buf == NULL) {
			free(bufp);
			opp->context = NULL;
			return (CKR_HOST_MEMORY);
		}
		bufp->buf_len = buflen;
	}

	return (CKR_OK);
}

/*
 * Setup the support necessary to do this operation in a
 * single part. We allocate a buffer to accumulate the
 * input data from later calls. We also get ready for
 * the case where we have to do it in software by initializing
 * a standby context. The opflag tells if this is a sign or verify.
 */
CK_RV
emulate_init(kernel_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    crypto_key_t *keyp, int opflag)
{
	CK_RV rv;
	crypto_active_op_t *opp;

	if ((rv = emulate_buf_init(session_p, EDIGEST_LENGTH, opflag)) !=
	    CKR_OK)
		return (rv);

	opp = (opflag & OP_SIGN) ? &(session_p->sign) : &(session_p->verify);

	opflag |= OP_INIT;
	rv = do_soft_hmac_init(get_spp(opp), pMechanism, keyp->ck_data,
	    keyp->ck_length >> 3, opflag);

	return (rv);
}

#define	DO_SOFT_UPDATE(opp, pPart, ulPartLen, opflag)		\
	if ((opflag) & OP_DIGEST) {				\
		rv = do_soft_digest(get_spp(opp), NULL, pPart,	\
		    ulPartLen, NULL, NULL, opflag);		\
	} else {						\
		rv = do_soft_hmac_update(get_spp(opp), pPart,	\
		    ulPartLen, opflag);				\
	}

/*
 * Accumulate the input data in the buffer, allocating a bigger
 * buffer if needed. If we reach the maximum input data size
 * that can be accumulated, start using the software from then on.
 * The opflag tells if this is a digest, sign or verify.
 */
CK_RV
emulate_update(kernel_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, int opflag)
{
	CK_RV rv;
	digest_buf_t *bufp;
	boolean_t use_soft = B_FALSE;
	crypto_active_op_t *opp;

	opp = (opflag & OP_DIGEST) ? &(session_p->digest) : \
	    ((opflag & OP_SIGN) ? &(session_p->sign) : &(session_p->verify));

	if (!SLOT_HAS_LIMITED_HASH(session_p))
		return (CKR_ARGUMENTS_BAD);

	if (opp->flags & CRYPTO_EMULATE_USING_SW) {
		opflag |= OP_UPDATE;
		DO_SOFT_UPDATE(opp, pPart, ulPartLen, opflag);
		opp->flags |= CRYPTO_EMULATE_UPDATE_DONE;
		return (rv);
	}

	bufp = opp->context;
	if (bufp == NULL) {
		return (CKR_FUNCTION_FAILED);
	}

	/* Did we exceed the maximum allowed? */
	if (bufp->indata_len + ulPartLen > SLOT_MAX_INDATA_LEN(session_p)) {
		use_soft = B_TRUE;
	} else if (ulPartLen > (bufp->buf_len - bufp->indata_len))  {
		int siz = ulPartLen < bufp->buf_len ?
		    bufp->buf_len * 2 : bufp->buf_len + ulPartLen;
		uint8_t *old = bufp->buf;

		bufp->buf = realloc(bufp->buf, siz);
		if (bufp->buf == NULL) {
			/* Try harder rather than failing */
			bufp->buf =  old;
			use_soft = B_TRUE;
		} else
			bufp->buf_len = siz;
	}

	if (use_soft) {
		opp->flags |= CRYPTO_EMULATE_USING_SW;

		if (opflag & OP_DIGEST) {
			CK_MECHANISM_PTR pMechanism;

			pMechanism = &(opp->mech);
			rv = do_soft_digest(get_spp(opp), pMechanism, NULL, 0,
			    NULL, NULL, OP_INIT);
			if (rv != CKR_OK)
				return (rv);
		}

		opflag |= OP_UPDATE;
		DO_SOFT_UPDATE(opp, bufp->buf, bufp->indata_len, opflag);
		opp->flags |= CRYPTO_EMULATE_UPDATE_DONE;
		if (rv == CKR_OK) {
			DO_SOFT_UPDATE(opp, pPart, ulPartLen, opflag);
		}

		return (rv);
	}

	/* accumulate the update data */
	bcopy(pPart, bufp->buf + bufp->indata_len, ulPartLen);
	bufp->indata_len += ulPartLen;

	return (CKR_OK);
}
