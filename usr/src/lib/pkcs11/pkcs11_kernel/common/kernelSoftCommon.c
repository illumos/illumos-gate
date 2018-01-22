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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include <security/pkcs11t.h>
#include "softSession.h"
#include "softObject.h"
#include "softOps.h"
#include "softMAC.h"
#include "kernelSoftCommon.h"

/*
 * Do the operation(s) specified by opflag.
 */
CK_RV
do_soft_digest(void **s, CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen,
    int opflag)
{
	soft_session_t *session_p;
	CK_RV rv = CKR_ARGUMENTS_BAD;

	session_p = *((soft_session_t **)s);
	if (session_p == NULL) {
		if (!(opflag & OP_INIT)) {
			return (CKR_ARGUMENTS_BAD);
		}

		session_p = calloc(1, sizeof (soft_session_t));
		/*
		 * Initialize the lock for the newly created session.
		 * We do only the minimum needed setup for the
		 * soft_digest* routines to succeed.
		 */
		if (pthread_mutex_init(&session_p->session_mutex, NULL) != 0) {
			free(session_p);
			return (CKR_CANT_LOCK);
		}

		*s = session_p;
	} else if (opflag & OP_INIT) {
		free_soft_ctx(session_p, OP_DIGEST);
	}

	if (opflag & OP_INIT) {
		rv = soft_digest_init(session_p, pMechanism);
		if (rv != CKR_OK)
			return (rv);
	}

	if (opflag & OP_SINGLE) {
		rv = soft_digest(session_p, pData, ulDataLen,
		    pDigest, pulDigestLen);
	} else {
		if (opflag & OP_UPDATE) {
			rv = soft_digest_update(session_p, pData, ulDataLen);
			if (rv != CKR_OK)
				return (rv);
		}

		if (opflag & OP_FINAL) {
			rv = soft_digest_final(session_p,
			    pDigest, pulDigestLen);
		}
	}

	return (rv);
}

/*
 * opflag specifies whether this is a sign or verify.
 */
CK_RV
do_soft_hmac_init(void **s, CK_MECHANISM_PTR pMechanism,
    CK_BYTE_PTR kval, CK_ULONG klen, int opflag)
{
	CK_RV rv;
	soft_object_t keyobj;
	secret_key_obj_t skeyobj;
	soft_object_t *key_p;
	soft_session_t *session_p;

	session_p = *((soft_session_t **)s);
	if (session_p == NULL) {
		session_p = calloc(1, sizeof (soft_session_t));
		/* See comments in do_soft_digest() above */
		if (pthread_mutex_init(&session_p->session_mutex, NULL) != 0) {
			free(session_p);
			return (CKR_CANT_LOCK);
		}

		*s = session_p;
	} else if (opflag & OP_INIT) {
		free_soft_ctx(session_p, opflag);
	}

	/* Do the minimum needed setup for the call to succeed */
	key_p = &keyobj;
	bzero(key_p, sizeof (soft_object_t));
	key_p->class = CKO_SECRET_KEY;
	key_p->key_type = CKK_GENERIC_SECRET;

	bzero(&skeyobj, sizeof (secret_key_obj_t));
	OBJ_SEC(key_p) = &skeyobj;
	OBJ_SEC_VALUE(key_p) = kval;
	OBJ_SEC_VALUE_LEN(key_p) = klen;

	rv = soft_hmac_sign_verify_init_common(session_p, pMechanism,
	    key_p, opflag & OP_SIGN);

	return (rv);
}

/*
 * opflag specifies whether this is a sign or verify.
 */
CK_RV
do_soft_hmac_update(void **s, CK_BYTE_PTR pData, CK_ULONG ulDataLen, int opflag)
{
	soft_session_t *session_p;

	session_p = *((soft_session_t **)s);
	if (session_p == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	return (soft_hmac_sign_verify_update(session_p,
	    pData, ulDataLen, opflag & OP_SIGN));
}

/*
 * opflag specifies whether this is a final or single.
 */
CK_RV
do_soft_hmac_sign(void **s, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen, int opflag)
{
	CK_RV rv;
	soft_session_t *session_p;
	CK_BYTE hmac[SHA512_DIGEST_LENGTH]; /* use the maximum size */

	session_p = *((soft_session_t **)s);
	if (session_p == NULL || !(opflag & OP_SINGLE || opflag & OP_FINAL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	rv = soft_hmac_sign_verify_common(session_p, pData, ulDataLen,
	    (pSignature != NULL ? hmac : NULL), pulSignatureLen, B_TRUE);

	if ((rv == CKR_OK) && (pSignature != NULL)) {
		(void) memcpy(pSignature, hmac, *pulSignatureLen);
	}

	return (rv);
}

/*
 * opflag specifies whether this is a final or single.
 */
CK_RV
do_soft_hmac_verify(void **s, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, int opflag)
{
	CK_RV rv;
	CK_ULONG len;
	soft_session_t *session_p;
	soft_hmac_ctx_t *hmac_ctx;
	CK_BYTE hmac[SHA512_DIGEST_LENGTH]; /* use the maximum size */

	session_p = *((soft_session_t **)s);
	if (session_p == NULL || !(opflag & OP_SINGLE || opflag & OP_FINAL)) {
		return (CKR_ARGUMENTS_BAD);
	}

	hmac_ctx = (soft_hmac_ctx_t *)session_p->verify.context;
	len = hmac_ctx->hmac_len;

	rv = soft_hmac_sign_verify_common(session_p, pData,
	    ulDataLen, hmac, &len, B_FALSE);

	if (rv == CKR_OK) {
		if (len != ulSignatureLen) {
			rv = CKR_SIGNATURE_LEN_RANGE;
		}

		if (memcmp(hmac, pSignature, len) != 0) {
			rv = CKR_SIGNATURE_INVALID;
		}
	}

	return (rv);
}

/*
 * Helper routine to handle the case when the ctx is abandoned.
 */
void
free_soft_ctx(void *s, int opflag)
{
	soft_session_t *session_p;

	session_p = (soft_session_t *)s;
	if (session_p == NULL)
		return;

	if (opflag & OP_SIGN) {
		freezero(session_p->sign.context,
		    sizeof (soft_hmac_ctx_t));
		session_p->sign.context = NULL;
		session_p->sign.flags = 0;
	} else if (opflag & OP_VERIFY) {
		freezero(session_p->verify.context,
		    sizeof (soft_hmac_ctx_t));
		session_p->verify.context = NULL;
		session_p->verify.flags = 0;
	} else {
		free(session_p->digest.context);
		session_p->digest.context = NULL;
		session_p->digest.flags = 0;
	}
}
