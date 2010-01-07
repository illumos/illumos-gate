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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <arcfour.h>
#include "softSession.h"
#include "softObject.h"
#include "softCrypt.h"


/*
 * Allocate the ARCFour key stream for the active encryption or decryption
 * operation.
 */
CK_RV
soft_arcfour_crypt_init(soft_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    soft_object_t *key_p, boolean_t encrypt)
{

	uint8_t *keyval;
	int keyvallen;
	ARCFour_key *keystream;
	crypto_active_op_t *active_op;

#ifdef	__sparcv9
	/* LINTED */
	keyvallen = (int)OBJ_SEC_VALUE_LEN(key_p);
#else	/* !__sparcv9 */
	keyvallen = OBJ_SEC_VALUE_LEN(key_p);
#endif	/* __sparcv9 */

	if ((keyvallen < ARCFOUR_MIN_KEY_BYTES) ||
	    (keyvallen > ARCFOUR_MAX_KEY_BYTES))
		return (CKR_KEY_SIZE_RANGE);

	keyval = OBJ_SEC_VALUE(key_p);

	if (keyval == NULL)
		return (CKR_KEY_TYPE_INCONSISTENT);

	keystream = malloc(sizeof (ARCFour_key));
	if (keystream == NULL) {
		return (CKR_HOST_MEMORY);
	}
	arcfour_key_init(keystream, keyval, keyvallen);

	(void) pthread_mutex_lock(&session_p->session_mutex);
	active_op = (encrypt) ? &(session_p->encrypt) : &(session_p->decrypt);
	active_op->context = keystream;
	active_op->mech.mechanism = pMechanism->mechanism;
	(void) pthread_mutex_unlock(&session_p->session_mutex);

	return (CKR_OK);
}


/*
 * soft_arcfour_crypt()
 *
 * Arguments:
 *      active_op:	pointer to the active operation in the session
 *	input:		pointer to the input data to be transformed
 *	inputlen:	length of the input.
 *	output:		pointer to the output storage.
 *	outputlenp:	pointer to the length of the output
 *
 * Description:
 *      Encrypts/Decrypts the 'input' and gets the result in the 'output'
 *
 * Returns:
 *      CKR_OK: success
 *      CKR_BUFFER_TOO_SMALL: the output buffer provided by application
 *			      is too small
 *      CKR_ARGUMENTS_BAD: keystream is a NULL pointer, cipher is not
 *                         initialized
 */
CK_RV
soft_arcfour_crypt(crypto_active_op_t *active_op, CK_BYTE_PTR input,
    CK_ULONG inputlen, CK_BYTE_PTR output, CK_ULONG_PTR outputlenp)
{
	ARCFour_key *keystream = active_op->context;

	if (keystream == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * If application asks for the length of the output buffer
	 * to hold the transformed text
	 */
	if (output == NULL) {
		*outputlenp = inputlen;
		return (CKR_OK);
	}

	/* Is the application-supplied buffer large enough? */
	if (*outputlenp < inputlen) {
		*outputlenp = inputlen;
		return (CKR_BUFFER_TOO_SMALL);
	}
	arcfour_crypt(keystream, input, output, inputlen);
	*outputlenp = inputlen;

	return (CKR_OK);
}
