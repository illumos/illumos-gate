/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

#ifndef _SMB_KCRYPT_H_
#define	_SMB_KCRYPT_H_

/*
 * SMB signing routines used in {smb,smb2}_signing.c
 * Two implementations of these (kernel/user) in:
 *	uts/common/fs/smbsrv/smb_sign_kcf.c
 *	lib/smbsrv/libfksmbsrv/common/fksmb_sign_pkcs.c
 */

#ifdef	_KERNEL
#include <sys/crypto/api.h>
#else
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#endif
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	AES128_KEY_LENGTH	16	/* AES128 key length in bytes */
#define	AES256_KEY_LENGTH	32	/* AES256 key length in bytes */
#define	MD5_DIGEST_LENGTH	16	/* MD5 digest length in bytes */
#define	SHA256_DIGEST_LENGTH	32	/* SHA256 digest length in bytes */
#define	SHA512_DIGEST_LENGTH	64	/* SHA512 digest length in bytes */
#define	SMB2_SIG_SIZE		16
#define	SMB2_KEYLEN		16	/* SMB2/3 Signing Key length */
#define	SMB2_SSN_KEYLEN		16	/* Max size of the SMB2 Session Key */

#define	SMB3_AES_CCM_NONCE_SIZE	11
#define	SMB3_AES_GCM_NONCE_SIZE	12

#ifdef	_KERNEL

/* KCF variant */
typedef crypto_mechanism_t	smb_crypto_mech_t;
typedef crypto_context_t	smb_sign_ctx_t;

typedef union {
	CK_AES_CCM_PARAMS	ccm;
	CK_AES_GCM_PARAMS	gcm;
} smb_crypto_param_t;

typedef struct smb_enc_ctx {
	smb_crypto_mech_t mech;
	smb_crypto_param_t param;
	crypto_key_t ckey;
	crypto_context_t ctx;
	/* crypto_ctx_template_t *TODO */
} smb_enc_ctx_t;

#else	/* _KERNEL */

/* PKCS11 variant */
typedef CK_MECHANISM		smb_crypto_mech_t;
typedef CK_SESSION_HANDLE	smb_sign_ctx_t;

typedef union {
	CK_CCM_PARAMS	ccm;
	CK_GCM_PARAMS	gcm;
} smb_crypto_param_t;

typedef struct smb_enc_ctx {
	smb_crypto_mech_t mech;
	smb_crypto_param_t param;
	CK_OBJECT_HANDLE key;
	CK_SESSION_HANDLE ctx;
} smb_enc_ctx_t;

#endif	/* _KERNEL */

/*
 * SMB signing routines used in smb_signing.c
 */
int smb_md5_getmech(smb_crypto_mech_t *);
int smb_md5_init(smb_sign_ctx_t *, smb_crypto_mech_t *);
int smb_md5_update(smb_sign_ctx_t, void *, size_t);
int smb_md5_final(smb_sign_ctx_t, uint8_t *);

/*
 * SMB2/3 signing routines used in smb2_signing.c
 * Two implementations of these (kernel/user) in:
 *	uts/common/fs/smbsrv/smb2_sign_kcf.c
 *	lib/smbsrv/libfksmbsrv/common/fksmb_sign_pkcs.c
 */

int smb2_hmac_getmech(smb_crypto_mech_t *);
int smb2_hmac_init(smb_sign_ctx_t *, smb_crypto_mech_t *, uint8_t *, size_t);
int smb2_hmac_update(smb_sign_ctx_t, uint8_t *, size_t);
int smb2_hmac_final(smb_sign_ctx_t, uint8_t *);

int smb2_hmac_one(smb_crypto_mech_t *mech, uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len, uint8_t *mac, size_t mac_len);

int smb3_cmac_getmech(smb_crypto_mech_t *);
int smb3_cmac_init(smb_sign_ctx_t *, smb_crypto_mech_t *, uint8_t *, size_t);
int smb3_cmac_update(smb_sign_ctx_t, uint8_t *, size_t);
int smb3_cmac_final(smb_sign_ctx_t, uint8_t *);

int smb3_kdf(uint8_t *outbuf, uint32_t outbuf_len,
    uint8_t *key, size_t key_len,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len);

int smb3_aes_ccm_getmech(smb_crypto_mech_t *);
int smb3_aes_gcm_getmech(smb_crypto_mech_t *);
void smb3_crypto_init_ccm_param(smb_enc_ctx_t *,
    uint8_t *, size_t, uint8_t *, size_t, size_t);
void smb3_crypto_init_gcm_param(smb_enc_ctx_t *,
    uint8_t *, size_t, uint8_t *, size_t);

int smb3_encrypt_init(smb_enc_ctx_t *, uint8_t *, size_t);
int smb3_encrypt_uio(smb_enc_ctx_t *, uio_t *, uio_t *);
void smb3_enc_ctx_done(smb_enc_ctx_t *);

int smb3_decrypt_init(smb_enc_ctx_t *, uint8_t *, size_t);
int smb3_decrypt_uio(smb_enc_ctx_t *, uio_t *, uio_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KCRYPT_H_ */
