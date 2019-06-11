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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Helper functions for SMB3 encryption using PKCS#11
 *
 * There are two implementations of these functions:
 * This one (for user space) and another for kernel.
 * See: uts/common/fs/smbsrv/smb3_encrypt_kcf.c
 *
 * NOTE: CCM is not implemented in PKCS yet, so these are just stubs.
 */

#include <smbsrv/smb_kcrypt.h>
#include <smbsrv/smb2_kproto.h>

/*
 * SMB3 encryption helpers:
 * (getmech, init, update, final)
 */

/* ARGSUSED */
int
smb3_encrypt_getmech(smb_crypto_mech_t *mech)
{
	cmn_err(CE_NOTE, "fksmbsrv does not support SMB3 Encryption");
	return (-1);
}

/* ARGSUSED */
void
smb3_crypto_init_param(smb3_crypto_param_t *param,
    uint8_t *nonce, size_t noncesize, uint8_t *auth, size_t authsize,
    size_t datasize)
{
}

/*
 * Start the KCF session, load the key
 */

/* ARGSUSED */
static int
smb3_crypto_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len, smb3_crypto_param_t *param,
    boolean_t is_encrypt)
{
	return (-1);
}

/* ARGSUSED */
int
smb3_encrypt_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    smb3_crypto_param_t *param, uint8_t *key, size_t keylen,
    uint8_t *buf, size_t buflen)
{
	return (smb3_crypto_init(ctxp, mech, key, keylen, param, B_TRUE));
}

int
smb3_decrypt_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    smb3_crypto_param_t *param, uint8_t *key, size_t keylen)
{
	return (smb3_crypto_init(ctxp, mech, key, keylen, param, B_FALSE));
}

/*
 * Digest one segment
 */

/* ARGSUSED */
int
smb3_encrypt_update(smb3_enc_ctx_t *ctxp, uint8_t *in, size_t len)
{
	return (-1);
}

/* ARGSUSED */
int
smb3_decrypt_update(smb3_enc_ctx_t *ctxp, uint8_t *in, size_t len)
{
	return (-1);
}

/* ARGSUSED */
int
smb3_encrypt_final(smb3_enc_ctx_t *ctxp, uint8_t *digest16)
{
	return (-1);
}

/* ARGSUSED */
int
smb3_decrypt_final(smb3_enc_ctx_t *ctxp, uint8_t *buf, size_t buflen)
{
	return (-1);
}

/* ARGSUSED */
void
smb3_encrypt_cancel(smb3_enc_ctx_t *ctxp)
{
}
