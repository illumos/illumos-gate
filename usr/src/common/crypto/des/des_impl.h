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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DES_IMPL_H
#define	_DES_IMPL_H

/*
 * Common definitions used by DES
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DES_BLOCK_LEN	8

#define	DES_COPY_BLOCK(src, dst) \
	(dst)[0] = (src)[0]; \
	(dst)[1] = (src)[1]; \
	(dst)[2] = (src)[2]; \
	(dst)[3] = (src)[3]; \
	(dst)[4] = (src)[4]; \
	(dst)[5] = (src)[5]; \
	(dst)[6] = (src)[6]; \
	(dst)[7] = (src)[7];

#define	DES_XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]

typedef enum des_strength {
	DES = 1,
	DES2,
	DES3
} des_strength_t;

#define	DES3_STRENGTH	0x08000000

#define	DES_KEYSIZE	8
#define	DES_MINBITS	64
#define	DES_MAXBITS	64
#define	DES_MINBYTES	(DES_MINBITS / 8)
#define	DES_MAXBYTES	(DES_MAXBITS / 8)
#define	DES_IV_LEN	8

#define	DES2_KEYSIZE	(2 * DES_KEYSIZE)
#define	DES2_MINBITS	(2 * DES_MINBITS)
#define	DES2_MAXBITS	(2 * DES_MAXBITS)
#define	DES2_MINBYTES	(DES2_MINBITS / 8)
#define	DES2_MAXBYTES	(DES2_MAXBITS / 8)

#define	DES3_KEYSIZE	(3 * DES_KEYSIZE)
#define	DES3_MINBITS	(2 * DES_MINBITS)	/* DES3 handles CKK_DES2 keys */
#define	DES3_MAXBITS	(3 * DES_MAXBITS)
#define	DES3_MINBYTES	(DES3_MINBITS / 8)
#define	DES3_MAXBYTES	(DES3_MAXBITS / 8)

extern int des_encrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern int des_decrypt_contiguous_blocks(void *, char *, size_t,
    crypto_data_t *);
extern uint64_t des_crypt_impl(uint64_t *, uint64_t, int);
extern void des_ks(uint64_t *, uint64_t);
extern int des_crunch_block(const void *, const uint8_t *, uint8_t *,
    boolean_t);
extern int des3_crunch_block(const void *, const uint8_t *, uint8_t *,
    boolean_t);
extern void des_init_keysched(uint8_t *, des_strength_t, void *);
extern void *des_alloc_keysched(size_t *, des_strength_t, int);
extern boolean_t des_keycheck(uint8_t *, des_strength_t, uint8_t *);
extern void des_parity_fix(uint8_t *, des_strength_t, uint8_t *);
extern void des_copy_block(uint8_t *, uint8_t *);
extern void des_xor_block(uint8_t *, uint8_t *);
extern int des_encrypt_block(const void *, const uint8_t *, uint8_t *);
extern int des3_encrypt_block(const void *, const uint8_t *, uint8_t *);
extern int des_decrypt_block(const void *, const uint8_t *, uint8_t *);
extern int des3_decrypt_block(const void *, const uint8_t *, uint8_t *);

/*
 * The following definitions and declarations are only used by DES FIPS POST
 */
#ifdef _DES_FIPS_POST

#include <modes/modes.h>
#include <fips/fips_post.h>

/* DES FIPS Declarations */
#define	FIPS_DES_ENCRYPT_LENGTH		8  /*  64-bits */
#define	FIPS_DES_DECRYPT_LENGTH		8  /*  64-bits */
#define	FIPS_DES3_ENCRYPT_LENGTH	8  /*  64-bits */
#define	FIPS_DES3_DECRYPT_LENGTH	8  /*  64-bits */

#ifdef _KERNEL
typedef enum des_mech_type {
	DES_ECB_MECH_INFO_TYPE,		/* SUN_CKM_DES_ECB */
	DES_CBC_MECH_INFO_TYPE,		/* SUN_CKM_DES_CBC */
	DES_CFB_MECH_INFO_TYPE,		/* SUN_CKM_DES_CFB */
	DES3_ECB_MECH_INFO_TYPE,	/* SUN_CKM_DES3_ECB */
	DES3_CBC_MECH_INFO_TYPE,	/* SUN_CKM_DES3_CBC */
	DES3_CFB_MECH_INFO_TYPE		/* SUN_CKM_DES3_CFB */
} des_mech_type_t;


#undef	CKM_DES_ECB
#undef	CKM_DES3_ECB
#undef	CKM_DES_CBC
#undef	CKM_DES3_CBC

#define	CKM_DES_ECB		DES_ECB_MECH_INFO_TYPE
#define	CKM_DES3_ECB		DES3_ECB_MECH_INFO_TYPE
#define	CKM_DES_CBC		DES_CBC_MECH_INFO_TYPE
#define	CKM_DES3_CBC		DES3_CBC_MECH_INFO_TYPE
#endif

/* DES3 FIPS functions */
extern int fips_des3_post(void);

#ifndef _KERNEL
#ifdef _DES_IMPL
struct soft_des_ctx;
extern struct soft_des_ctx *des_build_context(uint8_t *, uint8_t *,
	CK_KEY_TYPE, CK_MECHANISM_TYPE);
extern void fips_des_free_context(struct soft_des_ctx *);
extern CK_RV fips_des_encrypt(struct soft_des_ctx *, CK_BYTE_PTR,
	CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE);
extern CK_RV fips_des_decrypt(struct soft_des_ctx *, CK_BYTE_PTR,
	CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_MECHANISM_TYPE);
#endif /* _DES_IMPL */
#else
extern des_ctx_t *des_build_context(uint8_t *, uint8_t *,
	des_mech_type_t);
extern void fips_des_free_context(des_ctx_t *);
extern int fips_des_encrypt(des_ctx_t *, uint8_t *,
	ulong_t, uint8_t *, ulong_t *, des_mech_type_t);
extern int fips_des_decrypt(des_ctx_t *, uint8_t *,
	ulong_t, uint8_t *, ulong_t *, des_mech_type_t);
#endif /* _KERNEL */
#endif /* _DES_FIPS_POST */

#ifdef	__cplusplus
}
#endif

#endif	/* _DES_IMPL_H */
