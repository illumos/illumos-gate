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
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _KMSCRYPT_H
#define	_KMSCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#ifdef USESOLARIS_AES
#include <modes/modes.h>
#else
#include <aes_cbc_crypt.h>
#define	CBC_MODE AES_CBC_MODE
#endif
#include <aes_impl.h>
#include "kmsObject.h"
#include "kmsSession.h"

typedef struct kms_aes_ctx {
	void *key_sched;		/* pointer to key schedule */
	size_t keysched_len;		/* Length of the key schedule */
	uint8_t ivec[AES_BLOCK_LEN];	/* initialization vector */
	uint8_t data[AES_BLOCK_LEN];	/* for use by update */
	size_t remain_len;			/* for use by update */
	void *aes_cbc;			/* to be used by CBC mode */
} kms_aes_ctx_t;

/*
 * Function Prototypes.
 */
void *aes_cbc_ctx_init(void *, size_t, uint8_t *);

CK_RV kms_aes_crypt_init_common(kms_session_t *, CK_MECHANISM_PTR,
	kms_object_t *, boolean_t);

CK_RV kms_aes_encrypt_common(kms_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV kms_aes_decrypt_common(kms_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV kms_aes_encrypt_final(kms_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV kms_aes_decrypt_final(kms_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

void kms_crypt_cleanup(kms_session_t *, boolean_t, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _KMSCRYPT_H */
