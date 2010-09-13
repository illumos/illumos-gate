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
 *
 * cryptmod.h
 * STREAMS based crypto module definitions.
 *
 * This is a Sun-private and undocumented interface.
 */

#ifndef _SYS_CRYPTMOD_H
#define	_SYS_CRYPTMOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/types32.h>
#ifdef _KERNEL
#include <sys/crypto/api.h>
#endif /* _KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * IOCTLs.
 */
#define	CRYPTIOC (('C' << 24) | ('R' << 16) | ('Y' << 8) | 0x00)

#define	CRYPTIOCSETUP		(CRYPTIOC | 0x01)
#define	CRYPTIOCSTOP		(CRYPTIOC | 0x02)
#define	CRYPTIOCSTARTENC	(CRYPTIOC | 0x03)
#define	CRYPTIOCSTARTDEC	(CRYPTIOC | 0x04)

#define	CRYPTPASSTHRU		(CRYPTIOC | 0x80)

/*
 * Crypto method definitions, to be used with the CRIOCSETUP ioctl.
 */
#define	CRYPT_METHOD_NONE		0
#define	CRYPT_METHOD_DES_CFB		101
#define	CRYPT_METHOD_DES_CBC_NULL	102
#define	CRYPT_METHOD_DES_CBC_MD5	103
#define	CRYPT_METHOD_DES_CBC_CRC	104
#define	CRYPT_METHOD_DES3_CBC_SHA1	105
#define	CRYPT_METHOD_ARCFOUR_HMAC_MD5	106
#define	CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP	107
#define	CRYPT_METHOD_AES128		108
#define	CRYPT_METHOD_AES256		109

#define	CR_METHOD_OK(m) ((m) == CRYPT_METHOD_NONE || \
			((m) >= CRYPT_METHOD_DES_CFB && \
			(m) <= CRYPT_METHOD_AES256))

#define	IS_RC4_METHOD(m) ((m) == CRYPT_METHOD_ARCFOUR_HMAC_MD5 || \
			(m) == CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP)

#define	IS_AES_METHOD(m) ((m) == CRYPT_METHOD_AES128 || \
			(m) == CRYPT_METHOD_AES256)

/*
 * Direction mask values, also to be used with the CRIOCSETUP ioctl.
 */
#define	CRYPT_ENCRYPT  0x01
#define	CRYPT_DECRYPT  0x02

#define	CR_DIRECTION_OK(d) ((d) & (CRYPT_ENCRYPT | CRYPT_DECRYPT))

/*
 * Define constants for the 'ivec_usage' fields.
 */
#define	IVEC_NEVER 0x00
#define	IVEC_REUSE 0x01
#define	IVEC_ONETIME 0x02

#define	CR_IVUSAGE_OK(iv)	\
	((iv) == IVEC_NEVER || (iv) == IVEC_REUSE || (iv) == IVEC_ONETIME)

#define	CRYPT_SHA1_BLOCKSIZE 64
#define	CRYPT_SHA1_HASHSIZE 20
#define	CRYPT_DES3_KEYBYTES 21
#define	CRYPT_DES3_KEYLENGTH 24
#define	CRYPT_ARCFOUR_KEYBYTES 16
#define	CRYPT_ARCFOUR_KEYLENGTH 16
#define	CRYPT_AES128_KEYBYTES 16
#define	CRYPT_AES128_KEYLENGTH 16
#define	CRYPT_AES256_KEYBYTES 32
#define	CRYPT_AES256_KEYLENGTH 32

#define	AES_TRUNCATED_HMAC_LEN 12

/*
 * Max size of initialization vector and key.
 * 256 bytes = 2048 bits.
 */
#define	CRYPT_MAX_KEYLEN 256
#define	CRYPT_MAX_IVLEN  256

typedef uint8_t	crkeylen_t;
typedef uint8_t	crivlen_t;

typedef uchar_t crmeth_t;
typedef uchar_t cropt_t;
typedef uchar_t crdir_t;
typedef uchar_t crivuse_t;

/*
 * Define values for the option mask field.
 * These can be extended to alter the behavior
 * of the module.  For example, when used by kerberized
 * Unix r commands (rlogind, rshd), all msgs must be
 * prepended with 4 bytes of clear text data that represent
 * the 'length' of the cipher text that follows.
 */
#define	CRYPTOPT_NONE		0x00
#define	CRYPTOPT_RCMD_MODE_V1	0x01
#define	CRYPTOPT_RCMD_MODE_V2	0x02

#define	ANY_RCMD_MODE(m) ((m) & (CRYPTOPT_RCMD_MODE_V1 |\
			CRYPTOPT_RCMD_MODE_V2))

/* Define the size of the length field used in 'rcmd' mode */
#define	RCMD_LEN_SZ	sizeof (uint32_t)

#define	CR_OPTIONS_OK(opt) ((opt) == CRYPTOPT_NONE || \
			ANY_RCMD_MODE(opt))
/*
 * Structure used by userland apps to pass data into crypto module
 * with the CRIOCSETUP iotcl.
 */
struct cr_info_t {
	uchar_t		key[CRYPT_MAX_KEYLEN];
	uchar_t		ivec[CRYPT_MAX_IVLEN];
	crkeylen_t	keylen;
	crivlen_t	iveclen;
	crivuse_t	ivec_usage;
	crdir_t		direction_mask;
	crmeth_t	crypto_method;
	cropt_t		option_mask;
};

#if defined(_KERNEL)

#define	RCMDV1_USAGE	1026
#define	ARCFOUR_DECRYPT_USAGE 1032
#define	ARCFOUR_ENCRYPT_USAGE 1028
#define	AES_ENCRYPT_USAGE 1028
#define	AES_DECRYPT_USAGE 1032

#define	DEFAULT_DES_BLOCKLEN 8
#define	DEFAULT_AES_BLOCKLEN 16
#define	ARCFOUR_EXP_SALT "fortybits"

struct cipher_data_t {
	char		*key;
	char		*block;
	char		*ivec;
	char		*saveblock;
	crypto_mech_type_t mech_type;
	crypto_key_t    *ckey;		/* initial encryption key */
	crypto_key_t    d_encr_key;	/* derived encr key */
	crypto_key_t    d_hmac_key;	/* derived hmac key */
	crypto_ctx_template_t enc_tmpl;
	crypto_ctx_template_t hmac_tmpl;
	crypto_context_t ctx;
	size_t		bytes;
	crkeylen_t	blocklen;
	crkeylen_t	keylen;
	crkeylen_t	ivlen;
	crivuse_t	ivec_usage;
	crmeth_t	method;
	cropt_t		option_mask;
};

struct rcmd_state_t {
	size_t	pt_len;    /* Plain text length */
	size_t	cd_len;    /* Cipher Data length */
	size_t	cd_rcvd;   /* Cipher Data bytes received so far */
	uint32_t next_len;
	mblk_t  *c_msg;	/* mblk that will contain the new data */
};

/* Values for "ready" mask. */
#define	CRYPT_WRITE_READY 0x01
#define	CRYPT_READ_READY  0x02

/*
 * State information for the streams module.
 */
struct tmodinfo {
	struct cipher_data_t	enc_data;
	struct cipher_data_t	dec_data;
	struct rcmd_state_t	rcmd_state;
	uchar_t			ready;
};

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRYPTMOD_H */
