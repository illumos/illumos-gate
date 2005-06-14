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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CRYPTO_SPI_H
#define	_SYS_CRYPTO_SPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CSPI: Cryptographic Service Provider Interface.
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/crypto/common.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	CRYPTO_SPI_VERSION_1	1

/*
 * Provider-private handle. This handle is specified by a provider
 * when it registers by means of the pi_provider_handle field of
 * the crypto_provider_info structure, and passed to the provider
 * when its entry points are invoked.
 */
typedef void *crypto_provider_handle_t;

/*
 * Context templates can be used to by software providers to pre-process
 * keying material, such as key schedules. They are allocated by
 * a software provider create_ctx_template(9E) entry point, and passed
 * as argument to initialization and atomic provider entry points.
 */
typedef void *crypto_spi_ctx_template_t;

/*
 * Request handles are used by the kernel to identify an asynchronous
 * request being processed by a provider. It is passed by the kernel
 * to a hardware provider when submitting a request, and must be
 * specified by a provider when calling crypto_op_notification(9F)
 */
typedef void *crypto_req_handle_t;

/*
 * The context structure is passed from the kernel to a provider.
 * It contains the information needed to process a multi-part or
 * single part operation. The context structure is not used
 * by atomic operations.
 *
 * Parameters needed to perform a cryptographic operation, such
 * as keys, mechanisms, input and output buffers, are passed
 * as separate arguments to Provider routines.
 */
typedef struct crypto_ctx {
	crypto_provider_handle_t cc_provider;
	crypto_session_id_t	cc_session;
	void			*cc_provider_private;	/* owned by provider */
	void			*cc_framework_private;	/* owned by framework */
} crypto_ctx_t;

/*
 * Extended provider information.
 */

/*
 * valid values for ei_flags field of extended info structure
 * They match the RSA Security, Inc PKCS#11 tokenInfo flags.
 */
#define	CRYPTO_EXTF_RNG					0x00000001
#define	CRYPTO_EXTF_WRITE_PROTECTED			0x00000002
#define	CRYPTO_EXTF_LOGIN_REQUIRED			0x00000004
#define	CRYPTO_EXTF_USER_PIN_INITIALIZED		0x00000008
#define	CRYPTO_EXTF_CLOCK_ON_TOKEN			0x00000040
#define	CRYPTO_EXTF_PROTECTED_AUTHENTICATION_PATH	0x00000100
#define	CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS		0x00000200
#define	CRYPTO_EXTF_TOKEN_INITIALIZED			0x00000400
#define	CRYPTO_EXTF_USER_PIN_COUNT_LOW			0x00010000
#define	CRYPTO_EXTF_USER_PIN_FINAL_TRY			0x00020000
#define	CRYPTO_EXTF_USER_PIN_LOCKED			0x00040000
#define	CRYPTO_EXTF_USER_PIN_TO_BE_CHANGED		0x00080000
#define	CRYPTO_EXTF_SO_PIN_COUNT_LOW			0x00100000
#define	CRYPTO_EXTF_SO_PIN_FINAL_TRY			0x00200000
#define	CRYPTO_EXTF_SO_PIN_LOCKED			0x00400000
#define	CRYPTO_EXTF_SO_PIN_TO_BE_CHANGED		0x00800000

#endif /* _KERNEL */

#define	CRYPTO_EXT_SIZE_LABEL		32
#define	CRYPTO_EXT_SIZE_MANUF		32
#define	CRYPTO_EXT_SIZE_MODEL		16
#define	CRYPTO_EXT_SIZE_SERIAL		16
#define	CRYPTO_EXT_SIZE_TIME		16

#ifdef _KERNEL

typedef struct crypto_provider_ext_info {
	uchar_t			ei_label[CRYPTO_EXT_SIZE_LABEL];
	uchar_t			ei_manufacturerID[CRYPTO_EXT_SIZE_MANUF];
	uchar_t			ei_model[CRYPTO_EXT_SIZE_MODEL];
	uchar_t			ei_serial_number[CRYPTO_EXT_SIZE_SERIAL];
	ulong_t			ei_flags;
	ulong_t			ei_max_session_count;
	ulong_t			ei_max_pin_len;
	ulong_t			ei_min_pin_len;
	ulong_t			ei_total_public_memory;
	ulong_t			ei_free_public_memory;
	ulong_t			ei_total_private_memory;
	ulong_t			ei_free_private_memory;
	crypto_version_t	ei_hardware_version;
	crypto_version_t	ei_firmware_version;
	uchar_t			ei_time[CRYPTO_EXT_SIZE_TIME];
} crypto_provider_ext_info_t;

/*
 * The crypto_control_ops structure contains pointers to control
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_control_ops {
	void (*provider_status)(crypto_provider_handle_t, uint_t *);
} crypto_control_ops_t;

/*
 * The crypto_ctx_ops structure contains points to context and context
 * templates management operations for cryptographic providers. It is
 * passed through the crypto_ops(9S) structure when providers register
 * with the kernel using crypto_register_provider(9F).
 */
typedef struct crypto_ctx_ops {
	int (*create_ctx_template)(crypto_provider_handle_t,
	    crypto_mechanism_t *, crypto_key_t *,
	    crypto_spi_ctx_template_t *, size_t *, crypto_req_handle_t);
	int (*free_context)(crypto_ctx_t *);
} crypto_ctx_ops_t;

/*
 * The crypto_digest_ops structure contains pointers to digest
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_digest_ops {
	int (*digest_init)(crypto_ctx_t *, crypto_mechanism_t *,
	    crypto_req_handle_t);
	int (*digest)(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
	    crypto_req_handle_t);
	int (*digest_update)(crypto_ctx_t *, crypto_data_t *,
	    crypto_req_handle_t);
	int (*digest_key)(crypto_ctx_t *, crypto_key_t *, crypto_req_handle_t);
	int (*digest_final)(crypto_ctx_t *, crypto_data_t *,
	    crypto_req_handle_t);
	int (*digest_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_data_t *,
	    crypto_data_t *, crypto_req_handle_t);
} crypto_digest_ops_t;

/*
 * The crypto_cipher_ops structure contains pointers to encryption
 * and decryption operations for cryptographic providers.  It is
 * passed through the crypto_ops(9S) structure when providers register
 * with the kernel using crypto_register_provider(9F).
 */
typedef struct crypto_cipher_ops {
	int (*encrypt_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*encrypt)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*encrypt_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*encrypt_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*encrypt_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

	int (*decrypt_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*decrypt)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*decrypt_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*decrypt_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*decrypt_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
} crypto_cipher_ops_t;

/*
 * The crypto_mac_ops structure contains pointers to MAC
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_mac_ops {
	int (*mac_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*mac)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*mac_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*mac_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*mac_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*mac_verify_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
} crypto_mac_ops_t;

/*
 * The crypto_sign_ops structure contains pointers to signing
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_sign_ops {
	int (*sign_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*sign)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*sign_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*sign_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*sign_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*sign_recover_init)(crypto_ctx_t *, crypto_mechanism_t *,
	    crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*sign_recover)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*sign_recover_atomic)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
	    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
} crypto_sign_ops_t;

/*
 * The crypto_verify_ops structure contains pointers to verify
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_verify_ops {
	int (*verify_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*verify)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*verify_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*verify_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*verify_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*verify_recover_init)(crypto_ctx_t *, crypto_mechanism_t *,
	    crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
	int (*verify_recover)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*verify_recover_atomic)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
	    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_req_handle_t);
} crypto_verify_ops_t;

/*
 * The crypto_dual_ops structure contains pointers to dual
 * cipher and sign/verify operations for cryptographic providers.
 * It is passed through the crypto_ops(9S) structure when
 * providers register with the kernel using
 * crypto_register_provider(9F).
 */
typedef struct crypto_dual_ops {
	int (*digest_encrypt_update)(
	    crypto_ctx_t *, crypto_ctx_t *, crypto_data_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*decrypt_digest_update)(
	    crypto_ctx_t *, crypto_ctx_t *, crypto_data_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*sign_encrypt_update)(
	    crypto_ctx_t *, crypto_ctx_t *, crypto_data_t *,
	    crypto_data_t *, crypto_req_handle_t);
	int (*decrypt_verify_update)(
	    crypto_ctx_t *, crypto_ctx_t *, crypto_data_t *,
	    crypto_data_t *, crypto_req_handle_t);
} crypto_dual_ops_t;

/*
 * The crypto_dual_cipher_mac_ops structure contains pointers to dual
 * cipher and MAC operations for cryptographic providers.
 * It is passed through the crypto_ops(9S) structure when
 * providers register with the kernel using
 * crypto_register_provider(9F).
 */
typedef struct crypto_dual_cipher_mac_ops {
	int (*encrypt_mac_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *,
	    crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*encrypt_mac)(crypto_ctx_t *,
	    crypto_data_t *, crypto_dual_data_t *, crypto_data_t *,
	    crypto_req_handle_t);
	int (*encrypt_mac_update)(crypto_ctx_t *,
	    crypto_data_t *, crypto_dual_data_t *, crypto_req_handle_t);
	int (*encrypt_mac_final)(crypto_ctx_t *,
	    crypto_dual_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*encrypt_mac_atomic)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *,
	    crypto_key_t *, crypto_data_t *, crypto_dual_data_t *,
	    crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);

	int (*mac_decrypt_init)(crypto_ctx_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *,
	    crypto_key_t *, crypto_spi_ctx_template_t,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*mac_decrypt)(crypto_ctx_t *,
	    crypto_dual_data_t *, crypto_data_t *, crypto_data_t *,
	    crypto_req_handle_t);
	int (*mac_decrypt_update)(crypto_ctx_t *,
	    crypto_dual_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*mac_decrypt_final)(crypto_ctx_t *,
	    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
	int (*mac_decrypt_atomic)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_dual_data_t *,
	    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
	int (*mac_verify_decrypt_atomic)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
	    crypto_mechanism_t *, crypto_key_t *, crypto_dual_data_t *,
	    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
	    crypto_spi_ctx_template_t, crypto_req_handle_t);
} crypto_dual_cipher_mac_ops_t;

/*
 * The crypto_random_number_ops structure contains pointers to random
 * number operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_random_number_ops {
	int (*seed_random)(crypto_provider_handle_t, crypto_session_id_t,
	    uchar_t *, size_t, crypto_req_handle_t);
	int (*generate_random)(crypto_provider_handle_t, crypto_session_id_t,
	    uchar_t *, size_t, crypto_req_handle_t);
} crypto_random_number_ops_t;

/*
 * The crypto_session_ops structure contains pointers to session
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_session_ops {
	int (*session_open)(crypto_provider_handle_t, crypto_session_id_t *,
	    crypto_req_handle_t);
	int (*session_close)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_req_handle_t);
	int (*session_login)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_user_type_t, char *, size_t, crypto_req_handle_t);
	int (*session_logout)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_req_handle_t);
} crypto_session_ops_t;

/*
 * The crypto_object_ops structure contains pointers to object
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_object_ops {
	int (*object_create)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
	    crypto_req_handle_t);
	int (*object_copy)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_object_id_t, crypto_object_attribute_t *, uint_t,
	    crypto_object_id_t *, crypto_req_handle_t);
	int (*object_destroy)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_object_id_t, crypto_req_handle_t);
	int (*object_get_size)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_object_id_t, size_t *, crypto_req_handle_t);
	int (*object_get_attribute_value)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_object_id_t,
	    crypto_object_attribute_t *, uint_t, crypto_req_handle_t);
	int (*object_set_attribute_value)(crypto_provider_handle_t,
	    crypto_session_id_t, crypto_object_id_t,
	    crypto_object_attribute_t *,  uint_t, crypto_req_handle_t);
	int (*object_find_init)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_object_attribute_t *, uint_t, void **,
	    crypto_req_handle_t);
	int (*object_find)(crypto_provider_handle_t, void *,
	    crypto_object_id_t *, uint_t, uint_t *, crypto_req_handle_t);
	int (*object_find_final)(crypto_provider_handle_t, void *,
	    crypto_req_handle_t);
} crypto_object_ops_t;

/*
 * The crypto_key_ops structure contains pointers to key
 * operations for cryptographic providers.  It is passed through
 * the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_key_ops {
	int (*key_generate)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_object_attribute_t *, uint_t,
	    crypto_object_id_t *, crypto_req_handle_t);
	int (*key_generate_pair)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_object_attribute_t *, uint_t,
	    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
	    crypto_object_id_t *, crypto_req_handle_t);
	int (*key_wrap)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_object_id_t *,
	    uchar_t *, size_t *, crypto_req_handle_t);
	int (*key_unwrap)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, uchar_t *, size_t *,
	    crypto_object_attribute_t *, uint_t,
	    crypto_object_id_t *, crypto_req_handle_t);
	int (*key_derive)(crypto_provider_handle_t, crypto_session_id_t,
	    crypto_mechanism_t *, crypto_key_t *, crypto_object_attribute_t *,
	    uint_t, crypto_object_id_t *, crypto_req_handle_t);
	int (*key_check)(crypto_provider_handle_t, crypto_mechanism_t *,
	    crypto_key_t *);
} crypto_key_ops_t;

/*
 * The crypto_provider_management_ops structure contains pointers
 * to management operations for cryptographic providers.  It is passed
 * through the crypto_ops(9S) structure when providers register with the
 * kernel using crypto_register_provider(9F).
 */
typedef struct crypto_provider_management_ops {
	int (*ext_info)(crypto_provider_handle_t,
	    crypto_provider_ext_info_t *, crypto_req_handle_t);
	int (*init_token)(crypto_provider_handle_t, char *, size_t,
	    char *, crypto_req_handle_t);
	int (*init_pin)(crypto_provider_handle_t, crypto_session_id_t,
	    char *, size_t, crypto_req_handle_t);
	int (*set_pin)(crypto_provider_handle_t, crypto_session_id_t,
	    char *, size_t, char *, size_t, crypto_req_handle_t);
} crypto_provider_management_ops_t;

/*
 * The crypto_ops(9S) structure contains the structures containing
 * the pointers to functions implemented by cryptographic providers.
 * It is specified as part of the crypto_provider_info(9S)
 * supplied by a provider when it registers with the kernel
 * by calling crypto_register_provider(9F).
 */
typedef struct crypto_ops {
	crypto_control_ops_t			*control_ops;
	crypto_digest_ops_t			*digest_ops;
	crypto_cipher_ops_t			*cipher_ops;
	crypto_mac_ops_t			*mac_ops;
	crypto_sign_ops_t			*sign_ops;
	crypto_verify_ops_t			*verify_ops;
	crypto_dual_ops_t			*dual_ops;
	crypto_dual_cipher_mac_ops_t		*dual_cipher_mac_ops;
	crypto_random_number_ops_t		*random_ops;
	crypto_session_ops_t			*session_ops;
	crypto_object_ops_t			*object_ops;
	crypto_key_ops_t			*key_ops;
	crypto_provider_management_ops_t	*provider_ops;
	crypto_ctx_ops_t			*ctx_ops;
} crypto_ops_t;

/*
 * Provider device specification passed during registration.
 *
 * Software providers set the pi_provider_type field of provider_info_t
 * to CRYPTO_SW_PROVIDER, and set the pd_sw field of
 * crypto_provider_dev_t to the address of their modlinkage.
 *
 * Hardware providers set the pi_provider_type field of provider_info_t
 * to CRYPTO_HW_PROVIDER, and set the pd_hw field of
 * crypto_provider_dev_t to the dev_info structure corresponding
 * to the device instance being registered.
 *
 * Logical providers set the pi_provider_type field of provider_info_t
 * to CRYPTO_LOGICAL_PROVIDER, and set the pd_hw field of
 * crypto_provider_dev_t to the dev_info structure corresponding
 * to the device instance being registered.
 */

typedef union crypto_provider_dev {
	struct modlinkage	*pd_sw; /* for CRYPTO_SW_PROVIDER */
	dev_info_t		*pd_hw; /* for CRYPTO_HW_PROVIDER */
} crypto_provider_dev_t;

/*
 * The mechanism info structure crypto_mech_info_t contains a function group
 * bit mask cm_func_group_mask. This field, of type crypto_func_group_t,
 * specifies the provider entry point that can be used a particular
 * mechanism. The function group mask is a combination of the following values.
 */

typedef uint32_t crypto_func_group_t;

#endif /* _KERNEL */

#define	CRYPTO_FG_ENCRYPT		0x00000001 /* encrypt_init() */
#define	CRYPTO_FG_DECRYPT		0x00000002 /* decrypt_init() */
#define	CRYPTO_FG_DIGEST		0x00000004 /* digest_init() */
#define	CRYPTO_FG_SIGN			0x00000008 /* sign_init() */
#define	CRYPTO_FG_SIGN_RECOVER		0x00000010 /* sign_recover_init() */
#define	CRYPTO_FG_VERIFY		0x00000020 /* verify_init() */
#define	CRYPTO_FG_VERIFY_RECOVER	0x00000040 /* verify_recover_init() */
#define	CRYPTO_FG_GENERATE		0x00000080 /* key_generate() */
#define	CRYPTO_FG_GENERATE_KEY_PAIR	0x00000100 /* key_generate_pair() */
#define	CRYPTO_FG_WRAP			0x00000200 /* key_wrap() */
#define	CRYPTO_FG_UNWRAP		0x00000400 /* key_unwrap() */
#define	CRYPTO_FG_DERIVE		0x00000800 /* key_derive() */
#define	CRYPTO_FG_MAC			0x00001000 /* mac_init() */
#define	CRYPTO_FG_ENCRYPT_MAC		0x00002000 /* encrypt_mac_init() */
#define	CRYPTO_FG_MAC_DECRYPT		0x00004000 /* decrypt_mac_init() */
#define	CRYPTO_FG_ENCRYPT_ATOMIC	0x00008000 /* encrypt_atomic() */
#define	CRYPTO_FG_DECRYPT_ATOMIC	0x00010000 /* decrypt_atomic() */
#define	CRYPTO_FG_MAC_ATOMIC		0x00020000 /* mac_atomic() */
#define	CRYPTO_FG_DIGEST_ATOMIC		0x00040000 /* digest_atomic() */
#define	CRYPTO_FG_SIGN_ATOMIC		0x00080000 /* sign_atomic() */
#define	CRYPTO_FG_SIGN_RECOVER_ATOMIC   0x00100000 /* sign_recover_atomic() */
#define	CRYPTO_FG_VERIFY_ATOMIC		0x00200000 /* verify_atomic() */
#define	CRYPTO_FG_VERIFY_RECOVER_ATOMIC	0x00400000 /* verify_recover_atomic() */
#define	CRYPTO_FG_ENCRYPT_MAC_ATOMIC	0x00800000 /* encrypt_mac_atomic() */
#define	CRYPTO_FG_MAC_DECRYPT_ATOMIC	0x01000000 /* mac_decrypt_atomic() */
#define	CRYPTO_FG_RESERVED		0x80000000

/*
 * Maximum length of the pi_provider_description field of the
 * crypto_provider_info structure.
 */
#define	CRYPTO_PROVIDER_DESCR_MAX_LEN	64

#ifdef _KERNEL

/* Bit mask for all the simple operations */
#define	CRYPTO_FG_SIMPLEOP_MASK	(CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | \
    CRYPTO_FG_DIGEST | CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY | CRYPTO_FG_MAC | \
    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC |		\
    CRYPTO_FG_MAC_ATOMIC | CRYPTO_FG_DIGEST_ATOMIC | CRYPTO_FG_SIGN_ATOMIC | \
    CRYPTO_FG_VERIFY_ATOMIC)

/* Bit mask for all the dual operations */
#define	CRYPTO_FG_MAC_CIPHER_MASK	(CRYPTO_FG_ENCRYPT_MAC |	\
    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_MAC_ATOMIC | 		\
    CRYPTO_FG_MAC_DECRYPT_ATOMIC)

/* Add other combos to CRYPTO_FG_DUAL_MASK */
#define	CRYPTO_FG_DUAL_MASK	CRYPTO_FG_MAC_CIPHER_MASK

/*
 * The crypto_mech_info structure specifies one of the mechanisms
 * supported by a cryptographic provider. The pi_mechanisms field of
 * the crypto_provider_info structure contains a pointer to an array
 * of crypto_mech_info's.
 */
typedef struct crypto_mech_info {
	crypto_mech_name_t	cm_mech_name;
	crypto_mech_type_t	cm_mech_number;
	crypto_func_group_t	cm_func_group_mask;
	ssize_t			cm_min_key_length;
	ssize_t			cm_max_key_length;
	crypto_keysize_unit_t	cm_keysize_unit; /* for cm_xxx_key_length */
} crypto_mech_info_t;

/*
 * crypto_kcf_provider_handle_t is a handle allocated by the kernel.
 * It is returned after the provider registers with
 * crypto_register_provider(), and must be specified by the provider
 * when calling crypto_unregister_provider(), and
 * crypto_provider_notification().
 */
typedef uint_t crypto_kcf_provider_handle_t;

/*
 * Provider information. Passed as argument to crypto_register_provider(9F).
 * Describes the provider and its capabilities. Multiple providers can
 * register for the same device instance. In this case, the same
 * pi_provider_dev must be specified with a different pi_provider_handle.
 */
typedef struct crypto_provider_info {
	uint_t				pi_interface_version;
	char				*pi_provider_description;
	crypto_provider_type_t		pi_provider_type;
	crypto_provider_dev_t		pi_provider_dev;
	crypto_provider_handle_t	pi_provider_handle;
	crypto_ops_t			*pi_ops_vector;
	uint_t				pi_mech_list_count;
	crypto_mech_info_t		*pi_mechanisms;
	uint_t				pi_logical_provider_count;
	crypto_kcf_provider_handle_t	*pi_logical_providers;
} crypto_provider_info_t;

/*
 * Provider status passed by a provider to crypto_provider_notification(9F)
 * and returned by the provider_stauts(9E) entry point.
 */
#define	CRYPTO_PROVIDER_READY		0
#define	CRYPTO_PROVIDER_BUSY		1
#define	CRYPTO_PROVIDER_FAILED		2

/*
 * Functions exported by Solaris to cryptographic providers. Providers
 * call these functions to register and unregister, notify the kernel
 * of state changes, and notify the kernel when a asynchronous request
 * completed.
 */
extern int crypto_register_provider(crypto_provider_info_t *,
		crypto_kcf_provider_handle_t *);
extern int crypto_unregister_provider(crypto_kcf_provider_handle_t);
extern void crypto_provider_notification(crypto_kcf_provider_handle_t, uint_t);
extern void crypto_op_notification(crypto_req_handle_t, int);
extern int crypto_kmflag(crypto_req_handle_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRYPTO_SPI_H */
