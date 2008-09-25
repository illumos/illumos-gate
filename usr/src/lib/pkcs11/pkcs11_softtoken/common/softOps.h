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

#ifndef _SOFTOPS_H
#define	_SOFTOPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>
#include "softObject.h"
#include "softSession.h"

/*
 * Function Prototypes.
 */
CK_RV soft_digest_init(soft_session_t *, CK_MECHANISM_PTR);

CK_RV soft_digest(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

CK_RV soft_digest_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

CK_RV soft_digest_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_digest_init_internal(soft_session_t *, CK_MECHANISM_PTR);

CK_RV soft_digest_key(soft_session_t *, soft_object_t *);

CK_RV soft_encrypt_init(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *);

CK_RV soft_encrypt(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

CK_RV soft_encrypt_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_encrypt_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_encrypt_init_internal(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *);

CK_RV soft_decrypt_init(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *);

CK_RV soft_decrypt(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

CK_RV soft_decrypt_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_decrypt_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_sign_init(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *);

CK_RV soft_sign(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

CK_RV soft_sign_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

CK_RV soft_sign_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_verify_init(soft_session_t *, CK_MECHANISM_PTR, soft_object_t *);

CK_RV soft_verify(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG);

CK_RV soft_verify_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

CK_RV soft_verify_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

CK_RV soft_sign_recover_init(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *);

CK_RV soft_sign_recover(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

CK_RV soft_verify_recover_init(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *);

CK_RV soft_verify_recover(soft_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
	CK_ULONG_PTR);

void soft_crypt_cleanup(soft_session_t *, boolean_t, boolean_t);

void soft_sign_verify_cleanup(soft_session_t *, boolean_t, boolean_t);

void soft_digest_cleanup(soft_session_t *, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTOPS_H */
