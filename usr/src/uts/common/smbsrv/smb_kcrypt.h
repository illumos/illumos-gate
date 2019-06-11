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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

#define	MD5_DIGEST_LENGTH	16	/* MD5 digest length in bytes */
#define	SHA256_DIGEST_LENGTH	32	/* SHA256 digest length in bytes */
#define	SMB2_SIG_SIZE		16
#define	SMB2_KEYLEN		16
#define	SMB3_KEYLEN		16	/* AES-128 keys */

#ifdef	_KERNEL
/* KCF variant */
typedef crypto_mechanism_t	smb_crypto_mech_t;
typedef crypto_context_t	smb_sign_ctx_t;
typedef struct smb3_enc_ctx {
	crypto_context_t ctx;
	crypto_data_t output;
	size_t len;
} smb3_enc_ctx_t;
typedef CK_AES_CCM_PARAMS	smb3_crypto_param_t;
#else	/* _KERNEL */
/* PKCS11 variant */
typedef CK_MECHANISM		smb_crypto_mech_t;
typedef CK_SESSION_HANDLE	smb_sign_ctx_t;
typedef struct smb_enc_ctx {
	CK_SESSION_HANDLE ctx;
	uint8_t *output;
	CK_ULONG len;
} smb3_enc_ctx_t;
/*
 * CCM in PKCS has not been implemented.
 * We just need an opaque type with space to refer to.
 */
typedef struct pkcs_ccm_param {
	uint8_t buf[100];
} smb3_crypto_param_t;
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

int smb3_cmac_getmech(smb_crypto_mech_t *);
int smb3_cmac_init(smb_sign_ctx_t *, smb_crypto_mech_t *, uint8_t *, size_t);
int smb3_cmac_update(smb_sign_ctx_t, uint8_t *, size_t);
int smb3_cmac_final(smb_sign_ctx_t, uint8_t *);

int smb3_do_kdf(void *, void *, size_t, uint8_t *, uint32_t);

int smb3_encrypt_getmech(smb_crypto_mech_t *);
void smb3_crypto_init_param(smb3_crypto_param_t *, uint8_t *, size_t,
    uint8_t *, size_t, size_t);

int smb3_encrypt_init(smb3_enc_ctx_t *, smb_crypto_mech_t *,
    smb3_crypto_param_t *, uint8_t *, size_t, uint8_t *, size_t);
int smb3_encrypt_update(smb3_enc_ctx_t *, uint8_t *, size_t);
int smb3_encrypt_final(smb3_enc_ctx_t *, uint8_t *);
void smb3_encrypt_cancel(smb3_enc_ctx_t *);

int smb3_decrypt_init(smb3_enc_ctx_t *, smb_crypto_mech_t *,
    smb3_crypto_param_t *, uint8_t *, size_t);
int smb3_decrypt_update(smb3_enc_ctx_t *, uint8_t *, size_t);
int smb3_decrypt_final(smb3_enc_ctx_t *, uint8_t *, size_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KCRYPT_H_ */
