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

#ifndef _SOFTRSA_H
#define	_SOFTRSA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <bignum.h>
#include "softObject.h"
#include "softSession.h"
#include "rsa_impl.h"


typedef struct soft_rsa_ctx {
	soft_object_t *key;
} soft_rsa_ctx_t;

/*
 * Function Prototypes.
 */

/* RSA */

CK_RV soft_rsa_encrypt(soft_object_t *, CK_BYTE_PTR, uint32_t, CK_BYTE_PTR,
	int);

CK_RV soft_rsa_decrypt(soft_object_t *, CK_BYTE_PTR, uint32_t, CK_BYTE_PTR);

CK_RV soft_rsa_crypt_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_rsa_encrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE);

CK_RV soft_rsa_decrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE);

CK_RV soft_rsa_sign_verify_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_rsa_verify_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_TYPE);

CK_RV soft_rsa_sign_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE);

CK_RV soft_rsa_digest_sign_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE, boolean_t);

CK_RV soft_rsa_digest_verify_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_TYPE, boolean_t);

CK_RV soft_rsa_genkey_pair(soft_object_t *, soft_object_t *);

CK_RV soft_rsa_verify_recover(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);


#ifdef	__cplusplus
}
#endif

#endif /* _SOFTRSA_H */
