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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <strings.h>
#include <md5.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include "softGlobal.h"
#include "softOps.h"
#include "softSession.h"
#include "softObject.h"


/*
 * soft_digest_init()
 *
 * Arguments:
 *	session_p:	pointer to soft_session_t struct
 *	pMechanism:	pointer to CK_MECHANISM struct provided by application
 *
 * Description:
 *	called by C_DigestInit(). This function allocates space for
 *	context, then calls the corresponding software provided digest
 *	init routine based on the mechanism.
 *
 * Returns:
 *	CKR_OK: success
 *	CKR_HOST_MEMORY: run out of system memory
 *	CKR_MECHANISM_INVALID: invalid mechanism type
 */
CK_RV
soft_digest_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism)
{

	switch (pMechanism->mechanism) {

	case CKM_MD5:
		(void) pthread_mutex_lock(&session_p->session_mutex);

		session_p->digest.context = malloc(sizeof (MD5_CTX));

		if (session_p->digest.context == NULL) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		session_p->digest.mech.mechanism = CKM_MD5;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		MD5Init((MD5_CTX *)session_p->digest.context);

		break;

	case CKM_SHA_1:

		(void) pthread_mutex_lock(&session_p->session_mutex);

		session_p->digest.context = malloc(sizeof (SHA1_CTX));

		if (session_p->digest.context == NULL) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		session_p->digest.mech.mechanism = CKM_SHA_1;
		session_p->digest.mech.pParameter = pMechanism->pParameter;
		session_p->digest.mech.ulParameterLen =
		    pMechanism->ulParameterLen;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		SHA1Init((SHA1_CTX *)session_p->digest.context);

		break;

	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:

		(void) pthread_mutex_lock(&session_p->session_mutex);

		session_p->digest.context = malloc(sizeof (SHA2_CTX));

		if (session_p->digest.context == NULL) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			return (CKR_HOST_MEMORY);
		}

		switch (pMechanism->mechanism) {
		case CKM_SHA256:
			session_p->digest.mech.mechanism = CKM_SHA256;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			SHA2Init(SHA256,
			    (SHA2_CTX *)session_p->digest.context);
			break;

		case CKM_SHA384:
			session_p->digest.mech.mechanism = CKM_SHA384;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			SHA2Init(SHA384,
			    (SHA2_CTX *)session_p->digest.context);
			break;

		case CKM_SHA512:
			session_p->digest.mech.mechanism = CKM_SHA512;
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			SHA2Init(SHA512,
			    (SHA2_CTX *)session_p->digest.context);
			break;
		}
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	return (CKR_OK);
}


/*
 * soft_digest_common()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *	pData:		pointer to the input data to be digested
 *	ulDataLen:	length of the input data
 *	pDigest:	pointer to the output data after digesting
 *	pulDigestLen:	length of the output data
 *
 * Description:
 *      called by soft_digest() or soft_digest_final(). This function
 *      determines the length of output buffer and calls the corresponding
 *	software provided digest routine based on the mechanism.
 *
 * Returns:
 *      CKR_OK: success
 *      CKR_MECHANISM_INVALID: invalid mechanism type
 *      CKR_BUFFER_TOO_SMALL: the output buffer provided by application
 *			      is too small
 */
CK_RV
soft_digest_common(soft_session_t *session_p, CK_BYTE_PTR pData,
    CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{

	CK_ULONG digestLen = 0;
	size_t len = 0;

	/*
	 * Determine the output data length based on the mechanism
	 */
	switch (session_p->digest.mech.mechanism) {

	case CKM_MD5:
		digestLen = 16;
		break;

	case CKM_SHA_1:
		digestLen = 20;
		break;

	case CKM_SHA256:
		digestLen = 32;
		break;

	case CKM_SHA384:
		digestLen = 48;
		break;

	case CKM_SHA512:
		digestLen = 64;
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	if (pDigest == NULL) {
		/*
		 * Application only wants to know the length of the
		 * buffer needed to hold the message digest.
		 */
		*pulDigestLen = digestLen;
		return (CKR_OK);
	}

	if (*pulDigestLen < digestLen) {
		/*
		 * Application provides buffer too small to hold the
		 * digest message. Return the length of buffer needed
		 * to the application.
		 */
		*pulDigestLen = digestLen;
		return (CKR_BUFFER_TOO_SMALL);
	}

	/*
	 * Call the corresponding system provided software digest routine.
	 * If the soft_digest_common() is called by soft_digest_final()
	 * the pData is NULL, and the ulDataLen is zero.
	 */
	switch (session_p->digest.mech.mechanism) {

	case CKM_MD5:
		if (pData != NULL) {
			/*
			 * this is called by soft_digest()
			 */
#ifdef	__sparcv9
			MD5Update((MD5_CTX *)session_p->digest.context,
			    /* LINTED */
			    pData, (uint_t)ulDataLen);
#else	/* !__sparcv9 */
			MD5Update((MD5_CTX *)session_p->digest.context,
			    pData, ulDataLen);
#endif	/* __sparcv9 */
			MD5Final(pDigest, (MD5_CTX *)session_p->digest.context);
		} else {
			/*
			 * this is called by soft_digest_final()
			 */
			MD5Final(pDigest, (MD5_CTX *)session_p->digest.context);
			len = sizeof (MD5_CTX);
		}
		break;

	case CKM_SHA_1:
		if (pData != NULL) {
			/*
			 * this is called by soft_digest()
			 */

#ifdef	__sparcv9
			SHA1Update((SHA1_CTX *)session_p->digest.context,
			    /* LINTED */
			    pData, (uint32_t)ulDataLen);
#else	/* !__sparcv9 */
			SHA1Update((SHA1_CTX *)session_p->digest.context,
			    pData, ulDataLen);
#endif	/* __sparcv9 */
			SHA1Final(pDigest,
			    (SHA1_CTX *)session_p->digest.context);
		} else {
			/*
			 * this is called by soft_digest_final()
			 */
			SHA1Final(pDigest,
			    (SHA1_CTX *)session_p->digest.context);
			len = sizeof (SHA1_CTX);
		}
		break;
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		if (pData != NULL) {
			/*
			 * this is called by soft_digest()
			 */

			SHA2Update((SHA2_CTX *)session_p->digest.context,
			    pData, ulDataLen);

			SHA2Final(pDigest,
			    (SHA2_CTX *)session_p->digest.context);
		} else {
			/*
			 * this is called by soft_digest_final()
			 */
			SHA2Final(pDigest,
			    (SHA2_CTX *)session_p->digest.context);
			len = sizeof (SHA2_CTX);
		}

		break;
	}

	/* Paranoia on behalf of C_DigestKey callers: bzero the context */
	if (session_p->digest.flags & CRYPTO_KEY_DIGESTED) {
		explicit_bzero(session_p->digest.context, len);
		session_p->digest.flags &= ~CRYPTO_KEY_DIGESTED;
	}
	*pulDigestLen = digestLen;
	(void) pthread_mutex_lock(&session_p->session_mutex);
	free(session_p->digest.context);
	session_p->digest.context = NULL;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}


/*
 * soft_digest()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pData:		pointer to the input data to be digested
 *      ulDataLen:	length of the input data
 *      pDigest:	pointer to the output data after digesting
 *      pulDigestLen:	length of the output data
 *
 * Description:
 *      called by C_Digest(). This function calls soft_digest_common().
 *
 * Returns:
 *      see return values in soft_digest_common().
 */
CK_RV
soft_digest(soft_session_t *session_p, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{

	return (soft_digest_common(session_p, pData, ulDataLen,
	    pDigest, pulDigestLen));
}


/*
 * soft_digest_update()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pPart:		pointer to the input data to be digested
 *      ulPartLen:	length of the input data
 *
 * Description:
 *      called by C_DigestUpdate(). This function calls the corresponding
 *	software provided digest update routine based on the mechanism.
 *
 * Returns:
 *      CKR_OK: success
 *      CKR_MECHANISM_INVALID: invalid MECHANISM type.
 */
CK_RV
soft_digest_update(soft_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen)
{

	switch (session_p->digest.mech.mechanism) {

	case CKM_MD5:
#ifdef	__sparcv9
		MD5Update((MD5_CTX *)session_p->digest.context,
		    /* LINTED */
		    pPart, (uint_t)ulPartLen);
#else	/* !__sparcv9 */
		MD5Update((MD5_CTX *)session_p->digest.context,
		    pPart, ulPartLen);
#endif	/* __sparcv9 */
		break;

	case CKM_SHA_1:
#ifdef	__sparcv9
		SHA1Update((SHA1_CTX *)session_p->digest.context,
		    /* LINTED */
		    pPart, (uint32_t)ulPartLen);
#else	/* !__sparcv9 */
		SHA1Update((SHA1_CTX *)session_p->digest.context,
		    pPart, ulPartLen);
#endif	/* __sparcv9 */
		break;

	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		SHA2Update((SHA2_CTX *)session_p->digest.context,
		    pPart, ulPartLen);
		break;

	default:
		return (CKR_MECHANISM_INVALID);
	}

	return (CKR_OK);
}


/*
 * soft_digest_final()
 *
 * Arguments:
 *      session_p:	pointer to soft_session_t struct
 *      pDigest:	pointer to the output data after digesting
 *      pulDigestLen:	length of the output data
 *
 * Description:
 *      called by C_DigestFinal(). This function calls soft_digest_common().
 *
 * Returns:
 *	see return values in soft_digest_common().
 */
CK_RV
soft_digest_final(soft_session_t *session_p, CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen)
{

	return (soft_digest_common(session_p, NULL, 0,
	    pDigest, pulDigestLen));
}

/*
 * Perform digest init operation internally for the support of
 * CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA1_KEY_DERIVATION
 * and CKM_MD5_KEY_DERIVATION mechanisms.
 *
 * This function is called with the session being held, and without
 * its mutex taken.
 */
CK_RV
soft_digest_init_internal(soft_session_t *session_p,
    CK_MECHANISM_PTR pMechanism)
{

	CK_RV rv;

	(void) pthread_mutex_lock(&session_p->session_mutex);

	/* Check to see if digest operation is already active */
	if (session_p->digest.flags & CRYPTO_OPERATION_ACTIVE) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return (CKR_OPERATION_ACTIVE);
	}

	session_p->digest.flags = CRYPTO_OPERATION_ACTIVE;

	(void) pthread_mutex_unlock(&session_p->session_mutex);

	rv = soft_digest_init(session_p, pMechanism);

	if (rv != CKR_OK) {
		(void) pthread_mutex_lock(&session_p->session_mutex);
		session_p->digest.flags &= ~CRYPTO_OPERATION_ACTIVE;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
	}

	return (rv);
}

/*
 * Call soft_digest_update() function with the value of a secret key.
 */
CK_RV
soft_digest_key(soft_session_t *session_p, soft_object_t *key_p)
{

	CK_RV rv;

	/* Only secret key is allowed to be digested */
	if (key_p->class != CKO_SECRET_KEY)
		return (CKR_KEY_INDIGESTIBLE);

	if ((OBJ_SEC_VALUE(key_p) == NULL) ||
	    (OBJ_SEC_VALUE_LEN(key_p) == 0))
		return (CKR_KEY_SIZE_RANGE);

	rv = soft_digest_update(session_p, OBJ_SEC_VALUE(key_p),
	    OBJ_SEC_VALUE_LEN(key_p));

	return (rv);

}

/*
 * This function releases allocated digest context. The caller
 * may (lock_held == B_TRUE) or may not (lock_held == B_FALSE)
 * hold a session mutex.
 */
void
soft_digest_cleanup(soft_session_t *session_p, boolean_t lock_held)
{
	boolean_t lock_true = B_TRUE;

	if (!lock_held)
		(void) pthread_mutex_lock(&session_p->session_mutex);

	if (session_p->digest.context != NULL) {
		free(session_p->digest.context);
		session_p->digest.context = NULL;
	}

	session_p->digest.flags = 0;

	if (!lock_held)
		SES_REFRELE(session_p, lock_true);

}
