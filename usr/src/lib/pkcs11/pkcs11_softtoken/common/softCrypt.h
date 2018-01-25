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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _SOFTCRYPT_H
#define	_SOFTCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <modes/modes.h>
#include <aes_impl.h>
#include <blowfish_impl.h>
#include <des_impl.h>
#include "softObject.h"
#include "softSession.h"

#define	DES_MAC_LEN	(DES_BLOCK_LEN / 2)

typedef struct soft_des_ctx {
	void *key_sched;		/* pointer to key schedule */
	size_t keysched_len;		/* Length of the key schedule */
	uint8_t ivec[DES_BLOCK_LEN];	/* initialization vector */
	uint8_t data[DES_BLOCK_LEN];	/* for use by update */
	size_t remain_len;		/* for use by update */
	void *des_cbc;			/* to be used by CBC mode */
	CK_KEY_TYPE key_type;		/* used to determine DES or DES3 */
	size_t mac_len;			/* digest len in bytes */
} soft_des_ctx_t;

typedef struct soft_blowfish_ctx {
	void *key_sched;		/* pointer to key schedule */
	size_t keysched_len;		/* Length of the key schedule */
	uint8_t ivec[BLOWFISH_BLOCK_LEN];	/* initialization vector */
	uint8_t data[BLOWFISH_BLOCK_LEN];	/* for use by update */
	size_t remain_len;			/* for use by update */
	void *blowfish_cbc;			/* to be used by CBC mode */
} soft_blowfish_ctx_t;

/*
 * For sign/verify operations, the hash generated is AES_BLOCK_LEN bytes long,
 * however for CKM_AES_CMAC_GENERAL, one can specify a smaller hash size if
 * desired (the output being the output of CKM_AES_CMAC truncated to the
 * specified size).  Since this size is specified in the C_{Sign,Verify}Init()
 * call, we must carry it through to the C_{Sign,Verify}Final() call via
 * the mac_len field.
 *
 * Note that the context pointed to by aes_ctx is cleaned up as part of the
 * soft_aes_encrypt() calls.
 */
typedef struct soft_aes_sign_ctx {
	aes_ctx_t	*aes_ctx;
	size_t		mac_len;
} soft_aes_sign_ctx_t;

/*
 * Function Prototypes.
 */
void *des_cbc_ctx_init(void *, size_t, uint8_t *, CK_KEY_TYPE);

CK_RV soft_des_crypt_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_des_encrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_des_decrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_des_sign_verify_common(soft_session_t *, CK_BYTE_PTR,
	CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR,
	boolean_t, boolean_t);

CK_RV soft_des_sign_verify_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_des_mac_sign_verify_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

void soft_add_pkcs7_padding(CK_BYTE *, int, CK_ULONG);

CK_RV soft_remove_pkcs7_padding(CK_BYTE *, CK_ULONG, CK_ULONG *);

CK_RV soft_arcfour_crypt_init(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_arcfour_crypt(crypto_active_op_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_crypt_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_aes_encrypt(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_decrypt(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_encrypt_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_decrypt_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_encrypt_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_decrypt_final(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);

CK_RV soft_aes_decrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_aes_sign_verify_common(soft_session_t *, CK_BYTE_PTR,
	CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR,
	boolean_t, boolean_t);

CK_RV soft_aes_sign_verify_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_aes_mac_sign_verify_update(soft_session_t *, CK_BYTE_PTR, CK_ULONG);

void soft_aes_free_ctx(aes_ctx_t *);

void *blowfish_cbc_ctx_init(void *, size_t, uint8_t *);

CK_RV soft_blowfish_crypt_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_blowfish_encrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_blowfish_decrypt_common(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTCRYPT_H */
