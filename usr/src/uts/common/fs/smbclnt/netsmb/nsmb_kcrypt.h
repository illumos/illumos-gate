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
 * Copyright 2022-2024 RackTop Systems, Inc.
 */

#ifndef _NSMB_KCRYPT_H_
#define	_NSMB_KCRYPT_H_

/*
 * SMB crypto routines used in signing and encryption.
 * Two implementations of these (kernel/user) in:
 *	uts/common/fs/smbclient/netsmb/nsmb_*_kcf.c
 *	lib/smbclnt/libfknsmb/common/fksmb_*_pkcs.c
 *
 * Might want to later factor these out from client and server,
 * but that severely amplifies the test burden when working on
 * either one, so keeping them separate for now.  Do try to keep
 * the *_kcrypt.h structs consistent between this and smbsrv.
 */

#ifdef	_KERNEL
#include <sys/crypto/api.h>
#else
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#endif
#include <sys/stream.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MD5_DIGEST_LENGTH	16	/* MD5 digest length in bytes */
#define	SHA256_DIGEST_LENGTH	32	/* SHA256 digest length in bytes */
#define	SHA512_DIGEST_LENGTH	64	/* SHA512 digest length in bytes */
#define	SMB2_SIG_SIZE		16
#define	SMB2_KEYLEN		16	/* SMB2/3 Signing Key length */
#define	SMB3_KEYLEN		16	/* Only AES128 for now */

#define	SMB3_AES_CCM_NONCE_SIZE	11
#define	SMB3_AES_GCM_NONCE_SIZE	12

#ifdef	_KERNEL

/* KCF variant */
typedef crypto_mechanism_t	smb_crypto_mech_t;
typedef crypto_context_t	smb_sign_ctx_t;

typedef union {
	CK_AES_CCM_PARAMS	ccm;
	CK_AES_GCM_PARAMS	gcm;
	ulong_t			hmac;
	CK_AES_GMAC_PARAMS	gmac;
} smb_crypto_param_t;

typedef struct smb_enc_ctx {
	smb_crypto_mech_t mech;
	smb_crypto_param_t param;
	crypto_key_t ckey;
	crypto_context_t ctx;
} smb_enc_ctx_t;

#else	/* _KERNEL */

/* PKCS11 variant */
typedef CK_MECHANISM		smb_crypto_mech_t;
typedef CK_SESSION_HANDLE	smb_sign_ctx_t;

typedef union {
	CK_CCM_PARAMS		ccm;
	CK_GCM_PARAMS		gcm;
	CK_MAC_GENERAL_PARAMS	hmac;
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
int nsmb_md5_getmech(smb_crypto_mech_t *);
int nsmb_md5_init(smb_sign_ctx_t *, smb_crypto_mech_t *);
int nsmb_md5_update(smb_sign_ctx_t, void *, size_t);
int nsmb_md5_final(smb_sign_ctx_t, uint8_t *);

/*
 * SMB2/3 signing routines used in smb2_signing.c
 * Two implementations of these (kernel/user) in:
 *	uts/common/fs/smbsrv/smb2_sign_kcf.c
 *	lib/smbsrv/libfksmbsrv/common/fksmb_sign_pkcs.c
 */

int nsmb_hmac_getmech(smb_crypto_mech_t *);
int nsmb_hmac_init(smb_sign_ctx_t *, smb_crypto_mech_t *, uint8_t *, size_t);
int nsmb_hmac_update(smb_sign_ctx_t, uint8_t *, size_t);
int nsmb_hmac_final(smb_sign_ctx_t, uint8_t *);

int nsmb_hmac_one(smb_crypto_mech_t *mech, uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len, uint8_t *mac, size_t mac_len);

int nsmb_cmac_getmech(smb_crypto_mech_t *);
int nsmb_cmac_init(smb_sign_ctx_t *, smb_crypto_mech_t *, uint8_t *, size_t);
int nsmb_cmac_update(smb_sign_ctx_t, uint8_t *, size_t);
int nsmb_cmac_final(smb_sign_ctx_t, uint8_t *);

int nsmb_kdf(uint8_t *outbuf, uint32_t outbuf_len,
    uint8_t *key, size_t key_len,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len);

int nsmb_aes_ccm_getmech(smb_crypto_mech_t *);
int nsmb_aes_gcm_getmech(smb_crypto_mech_t *);
void nsmb_crypto_init_ccm_param(smb_enc_ctx_t *,
    uint8_t *, size_t, uint8_t *, size_t, size_t);
void nsmb_crypto_init_gcm_param(smb_enc_ctx_t *,
    uint8_t *, size_t, uint8_t *, size_t);

int nsmb_encrypt_init(smb_enc_ctx_t *, uint8_t *, size_t);
int nsmb_encrypt_mblks(smb_enc_ctx_t *, mblk_t *, size_t);
int nsmb_encrypt_uio(smb_enc_ctx_t *, uio_t *, uio_t *);
void nsmb_enc_ctx_done(smb_enc_ctx_t *);

int nsmb_decrypt_init(smb_enc_ctx_t *, uint8_t *, size_t);
int nsmb_decrypt_mblks(smb_enc_ctx_t *, mblk_t *, size_t);
int nsmb_decrypt_uio(smb_enc_ctx_t *, uio_t *, uio_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _NSMB_KCRYPT_H_ */
