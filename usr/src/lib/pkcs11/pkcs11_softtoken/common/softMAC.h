/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTMAC_H
#define	_SOFTMAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <security/pkcs11t.h>
#include "softSession.h"
#include "softObject.h"

#define	MD5_HASH_SIZE		16	/* MD5 digest length in bytes */
#define	SHA1_HASH_SIZE		20	/* SHA_1 digest length in bytes */
#define	MD5_HMAC_BLOCK_SIZE	64    	/* MD5 block size */
#define	MD5_HMAC_INTS_PER_BLOCK (MD5_HMAC_BLOCK_SIZE/sizeof (uint32_t))
#define	SHA1_HMAC_BLOCK_SIZE	64	/* SHA1-HMAC block size */
#define	SHA1_HMAC_INTS_PER_BLOCK	(SHA1_HMAC_BLOCK_SIZE/sizeof (uint32_t))
#define	SHA256_HMAC_INTS_PER_BLOCK	\
	(SHA256_HMAC_BLOCK_SIZE/sizeof (uint64_t))
#define	SHA512_HMAC_INTS_PER_BLOCK	\
	(SHA512_HMAC_BLOCK_SIZE/sizeof (uint64_t))


#define	MD5_SSL_PAD_SIZE	48	/* MD5 SSL pad length in bytes */
/* 48 (MD5 SSL pad length in bytes) + 16 (key length in bytes) = 64 */
#define	MD5_SSL_PAD_AND_KEY_SIZE	64

#define	SHA1_SSL_PAD_SIZE	40 /* SHA1 SSL pad length in bytes */
/* 40 (SHA1 SSL pad length in bytes) + 20 (key length in bytes) = 104 */
#define	SHA1_SSL_PAD_AND_KEY_SIZE	60

/*
 * Context for MD5-HMAC and MD5-HMAC-GENERAL mechanisms.
 */
typedef struct md5_hc_ctx {
	MD5_CTX		hc_icontext;    /* inner MD5 context */
	MD5_CTX		hc_ocontext;    /* outer MD5 context */
} md5_hc_ctx_t;

/*
 * Context for SHA1-HMAC and SHA1-HMAC-GENERAL mechanisms.
 */
typedef struct sha1_hc_ctx {
	SHA1_CTX	hc_icontext;    /* inner SHA1 context */
	SHA1_CTX	hc_ocontext;    /* outer SHA1 context */
} sha1_hc_ctx_t;

typedef struct sha2_hc_ctx {
	SHA2_CTX	hc_icontext;    /* inner SHA2 context */
	SHA2_CTX	hc_ocontext;    /* outer SHA2 context */
} sha2_hc_ctx_t;

/*
 * Generic Context struct for HMAC.
 */
typedef struct soft_hmac_ctx {
	size_t	hmac_len;    	/* digest len in bytes */
	union {
		md5_hc_ctx_t	md5_ctx;
		sha1_hc_ctx_t	sha1_ctx;
		sha2_hc_ctx_t	sha2_ctx;
	} hc_ctx_u;
} soft_hmac_ctx_t;


/* Generic MAC envelop macros. Substitute HASH with MD5, SHA1, & SHA2 mechs */

#define	SOFT_MAC_INIT_CTX(HASH, mac_ctx, ipad, opad, len)		\
	/* Perform HASH on ipad */					\
	HASH##Init(&((mac_ctx)->hc_icontext));				\
	HASH##Update(&((mac_ctx)->hc_icontext), ipad, len);		\
	/* Perform HASH on opad */					\
	HASH##Init(&((mac_ctx)->hc_ocontext));				\
	HASH##Update(&((mac_ctx)->hc_ocontext), opad, len);

#define	SOFT_MAC_UPDATE(HASH, mac_ctx, pPart, PartLen)			\
	HASH##Update(&((mac_ctx)->hc_icontext), pPart, PartLen);

#define	SOFT_MAC_FINAL(HASH, mac_ctx, mac)				\
	HASH##Final((mac), &((mac_ctx)->hc_icontext));			\
	HASH##Update(&((mac_ctx)->hc_ocontext), (mac), HASH##_HASH_SIZE);\
	HASH##Final((mac), &((mac_ctx)->hc_ocontext));

#define	SOFT_MAC_FINAL_2(HASH, mac_ctx, mac)				\
	SHA2Final((mac), &((mac_ctx)->hc_icontext));			\
	SHA2Update(&((mac_ctx)->hc_ocontext), (mac), HASH##_DIGEST_LENGTH); \
	SHA2Final((mac), &((mac_ctx)->hc_ocontext));

#define	CKM_TO_SHA2(ckm_value)	\
	(ckm_value % 0x10) + (((ckm_value - 0x250) / 0x10) * 3)

/*
 * Function Prototypes.
 */
CK_RV soft_hmac_sign_verify_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV mac_init_ctx(soft_session_t *session_p, soft_object_t *,
	soft_hmac_ctx_t *, CK_MECHANISM_TYPE);

CK_RV soft_hmac_sign_verify_common(soft_session_t *, CK_BYTE_PTR,
	CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_hmac_sign_verify_update(soft_session_t *, CK_BYTE_PTR,
	CK_ULONG, boolean_t);

void md5_hmac_ctx_init(md5_hc_ctx_t *, uint32_t *, uint32_t *);

void sha1_hmac_ctx_init(sha1_hc_ctx_t *, uint32_t *, uint32_t *);

void sha2_hmac_ctx_init(uint_t mech, sha2_hc_ctx_t *, uint64_t *, uint64_t *,
    uint_t, uint_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTMAC_H */
