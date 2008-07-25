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

#ifndef	_COMMON_CRYPTO_MODES_H
#define	_COMMON_CRYPTO_MODES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/rwlock.h>
#include <sys/kmem.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>

#define	ECB_MODE			0x00000002
#define	CBC_MODE			0x00000004
#define	CTR_MODE			0x00000008
#define	CCM_MODE			0x00000010

/*
 * cc_keysched:		Pointer to key schedule.
 *
 * cc_keysched_len:	Length of the key schedule.
 *
 * cc_remainder:	This is for residual data, i.e. data that can't
 *			be processed because there are too few bytes.
 *			Must wait until more data arrives.
 *
 * cc_remainder_len:	Number of bytes in cc_remainder.
 *
 * cc_iv:		Scratch buffer that sometimes contains the IV.
 *
 * cc_lastblock:	Scratch buffer.
 *
 * cc_lastp:		Pointer to previous block of ciphertext.
 *
 * cc_copy_to:		Pointer to where encrypted residual data needs
 *			to be copied.
 *
 * cc_flags:		PROVIDER_OWNS_KEY_SCHEDULE
 *			When a context is freed, it is necessary
 *			to know whether the key schedule was allocated
 *			by the caller, or internally, e.g. an init routine.
 *			If allocated by the latter, then it needs to be freed.
 *
 *			ECB_MODE, CBC_MODE, CTR_MODE, or CCM_MODE
 */
struct common_ctx {
	void *cc_keysched;
	size_t cc_keysched_len;
	uint64_t cc_iv[2];
	uint64_t cc_lastblock[2];
	uint64_t cc_remainder[2];
	size_t cc_remainder_len;
	uint8_t *cc_lastp;
	uint8_t *cc_copy_to;
	uint32_t cc_flags;
};

typedef struct common_ctx ecb_ctx_t;
typedef struct common_ctx cbc_ctx_t;
typedef struct common_ctx common_ctx_t;

typedef struct ctr_ctx {
	struct common_ctx ctr_common;
	uint32_t ctr_tmp[4];
} ctr_ctx_t;

/*
 * ctr_cb                Counter block.
 *
 * ctr_counter_mask      Mask of counter bits in the last 8 bytes of the
 *                       counter block.
 */

#define	ctr_keysched		ctr_common.cc_keysched
#define	ctr_keysched_len	ctr_common.cc_keysched_len
#define	ctr_cb			ctr_common.cc_iv
#define	ctr_counter_mask	ctr_common.cc_lastblock[0]
#define	ctr_remainder		ctr_common.cc_remainder
#define	ctr_remainder_len	ctr_common.cc_remainder_len
#define	ctr_lastp		ctr_common.cc_lastp
#define	ctr_copy_to		ctr_common.cc_copy_to
#define	ctr_flags		ctr_common.cc_flags

/*
 *
 * ccm_mac_len:		Stores length of the MAC in CCM mode.
 * ccm_mac_buf:		Stores the intermediate value for MAC in CCM encrypt.
 *			In CCM decrypt, stores the input MAC value.
 * ccm_data_len:	Length of the plaintext for CCM mode encrypt, or
 *			length of the ciphertext for CCM mode decrypt.
 * ccm_processed_data_len:
 *			Length of processed plaintext in CCM mode encrypt,
 *			or length of processed ciphertext for CCM mode decrypt.
 * ccm_processed_mac_len:
 *			Length of MAC data accumulated in CCM mode decrypt.
 *
 * ccm_pt_buf:		Only used in CCM mode decrypt.  It stores the
 *			decrypted plaintext to be returned when
 *			MAC verification succeeds in decrypt_final.
 *			Memory for this should be allocated in the AES module.
 *
 */
typedef struct ccm_ctx {
	struct common_ctx ccm_common;
	uint32_t ccm_tmp[4];
	size_t ccm_mac_len;
	uint64_t ccm_mac_buf[2];
	size_t ccm_data_len;
	size_t ccm_processed_data_len;
	size_t ccm_processed_mac_len;
	uint8_t *ccm_pt_buf;
	uint64_t ccm_mac_input_buf[2];
} ccm_ctx_t;

#define	ccm_keysched		ccm_common.cc_keysched
#define	ccm_keysched_len	ccm_common.cc_keysched_len
#define	ccm_cb			ccm_common.cc_iv
#define	ccm_counter_mask	ccm_common.cc_lastblock[0]
#define	ccm_remainder		ccm_common.cc_remainder
#define	ccm_remainder_len	ccm_common.cc_remainder_len
#define	ccm_lastp		ccm_common.cc_lastp
#define	ccm_copy_to		ccm_common.cc_copy_to
#define	ccm_flags		ccm_common.cc_flags

typedef struct aes_ctx {
	union {
		ecb_ctx_t acu_ecb;
		cbc_ctx_t acu_cbc;
		ctr_ctx_t acu_ctr;
#ifdef _KERNEL
		ccm_ctx_t acu_ccm;
#endif
	} acu;
} aes_ctx_t;

#define	ac_flags		acu.acu_ecb.cc_flags
#define	ac_remainder_len	acu.acu_ecb.cc_remainder_len
#define	ac_keysched		acu.acu_ecb.cc_keysched
#define	ac_keysched_len		acu.acu_ecb.cc_keysched_len
#define	ac_iv			acu.acu_ecb.cc_iv
#define	ac_lastp		acu.acu_ecb.cc_lastp
#define	ac_pt_buf		acu.acu_ccm.ccm_pt_buf
#define	ac_mac_len		acu.acu_ccm.ccm_mac_len
#define	ac_data_len		acu.acu_ccm.ccm_data_len
#define	ac_processed_mac_len	acu.acu_ccm.ccm_processed_mac_len
#define	ac_processed_data_len	acu.acu_ccm.ccm_processed_data_len

typedef struct blowfish_ctx {
	union {
		ecb_ctx_t bcu_ecb;
		cbc_ctx_t bcu_cbc;
	} bcu;
} blowfish_ctx_t;

#define	bc_flags		bcu.bcu_ecb.cc_flags
#define	bc_remainder_len	bcu.bcu_ecb.cc_remainder_len
#define	bc_keysched		bcu.bcu_ecb.cc_keysched
#define	bc_keysched_len		bcu.bcu_ecb.cc_keysched_len
#define	bc_iv			bcu.bcu_ecb.cc_iv
#define	bc_lastp		bcu.bcu_ecb.cc_lastp

typedef struct des_ctx {
	union {
		ecb_ctx_t dcu_ecb;
		cbc_ctx_t dcu_cbc;
	} dcu;
} des_ctx_t;

#define	dc_flags		dcu.dcu_ecb.cc_flags
#define	dc_remainder_len	dcu.dcu_ecb.cc_remainder_len
#define	dc_keysched		dcu.dcu_ecb.cc_keysched
#define	dc_keysched_len		dcu.dcu_ecb.cc_keysched_len
#define	dc_iv			dcu.dcu_ecb.cc_iv
#define	dc_lastp		dcu.dcu_ecb.cc_lastp

extern int ecb_cipher_contiguous_blocks(cbc_ctx_t *, char *, size_t,
    crypto_data_t *, size_t, int (*cipher)(const void *, const uint8_t *,
    uint8_t *));

extern int cbc_encrypt_contiguous_blocks(cbc_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*encrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int cbc_decrypt_contiguous_blocks(cbc_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*decrypt)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int ctr_mode_contiguous_blocks(ctr_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*cipher)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int ccm_mode_encrypt_contiguous_blocks(ccm_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int ccm_mode_decrypt_contiguous_blocks(ccm_ctx_t *, char *, size_t,
    crypto_data_t *, size_t,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

int ccm_encrypt_final(ccm_ctx_t *, crypto_data_t *, size_t,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int ccm_decrypt_final(ccm_ctx_t *, crypto_data_t *, size_t,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern int ctr_mode_final(ctr_ctx_t *, crypto_data_t *,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *));

extern int cbc_init_ctx(cbc_ctx_t *, char *, size_t, size_t,
    void (*copy_block)(uint8_t *, uint64_t *));

extern int ctr_init_ctx(ctr_ctx_t *, ulong_t, uint8_t *,
    void (*copy_block)(uint8_t *, uint8_t *));

extern int ccm_init_ctx(ccm_ctx_t *, char *, int, boolean_t, size_t,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *));

extern void calculate_ccm_mac(ccm_ctx_t *, uint8_t *,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *));

extern void crypto_init_ptrs(crypto_data_t *, void **, offset_t *);
extern void crypto_get_ptrs(crypto_data_t *, void **, offset_t *,
    uint8_t **, size_t *, uint8_t **, size_t);

extern void *ecb_alloc_ctx(int);
extern void *cbc_alloc_ctx(int);
extern void *ctr_alloc_ctx(int);
extern void *ccm_alloc_ctx(int);
extern void crypto_free_mode_ctx(void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _COMMON_CRYPTO_MODES_H */
