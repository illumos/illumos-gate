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
 * Copyright 2020 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB3 encryption using the
 * Kernel Cryptographic Framework (KCF)
 *
 * There are two implementations of these functions:
 * This one (for kernel) and another for user space:
 * See: lib/smbsrv/libfksmbsrv/common/fksmb_encrypt_pkcs.c
 */

#include <sys/crypto/api.h>
#include <smbsrv/smb_kcrypt.h>
#include <smbsrv/smb2_kproto.h>
#include <sys/cmn_err.h>

/*
 * Common function to see if a mech is available.
 */
static int
find_mech(smb_crypto_mech_t *mech, const char *name)
{
	crypto_mech_type_t t;

	t = crypto_mech2id(name);
	if (t == CRYPTO_MECH_INVALID) {
		cmn_err(CE_NOTE, "smb: no kcf mech: %s", name);
		return (-1);
	}
	mech->cm_type = t;
	return (0);
}

/*
 * SMB3 encryption helpers:
 * (getmech, init, update, final)
 */

int
smb3_aes_ccm_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_CCM));
}

int
smb3_aes_gcm_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_GCM));
}

void
smb3_crypto_init_ccm_param(smb3_crypto_param_t *param,
    uint8_t *nonce, size_t noncesize, uint8_t *auth, size_t authsize,
    size_t datasize)
{
	param->ccm.ulMACSize = SMB2_SIG_SIZE;
	param->ccm.ulNonceSize = noncesize;
	param->ccm.nonce = nonce;
	param->ccm.ulDataSize = datasize;
	param->ccm.ulAuthDataSize = authsize;
	param->ccm.authData = auth;
}

void
smb3_crypto_init_gcm_param(smb3_crypto_param_t *param,
    uint8_t *nonce, size_t noncesize, uint8_t *auth, size_t authsize)
{
	ASSERT3U(noncesize, ==, 12);
	param->gcm.pIv = nonce;
	param->gcm.ulIvLen = noncesize;		/* should be 12 bytes */
	/* tform hdr size - (protcolo id + signing) == 32 bytes */
	param->gcm.ulTagBits = SMB2_SIG_SIZE << 3; /* convert bytes to bits */
	param->gcm.pAAD = auth;			/* auth data */
	param->gcm.ulAADLen = authsize;		/* auth data len */
}

/*
 * Start the KCF session, load the key
 */
static int
smb3_crypto_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len, smb3_crypto_param_t *param,
    boolean_t is_encrypt)
{
	crypto_key_t ckey;
	int rv;

	bzero(&ckey, sizeof (ckey));
	ckey.ck_format = CRYPTO_KEY_RAW;
	ckey.ck_data = key;
	ckey.ck_length = key_len * 8; /* in bits */

	mech->cm_param = (caddr_t)param;
	mech->cm_param_len = sizeof (*param);

	if (is_encrypt)
		rv = crypto_encrypt_init(mech, &ckey, NULL, &ctxp->ctx, NULL);
	else
		rv = crypto_decrypt_init(mech, &ckey, NULL, &ctxp->ctx, NULL);

	if (rv != CRYPTO_SUCCESS) {
		if (is_encrypt)
			cmn_err(CE_WARN,
			    "crypto_encrypt_init failed: 0x%x", rv);
		else
			cmn_err(CE_WARN,
			    "crypto_decrypt_init failed: 0x%x", rv);
	}

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

int
smb3_encrypt_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    smb3_crypto_param_t *param, uint8_t *key, size_t keylen,
    uint8_t *buf, size_t buflen)
{

	bzero(&ctxp->output, sizeof (ctxp->output));
	ctxp->output.cd_format = CRYPTO_DATA_RAW;
	ctxp->output.cd_length = buflen;
	ctxp->output.cd_raw.iov_len = buflen;
	ctxp->output.cd_raw.iov_base = (void *)buf;

	return (smb3_crypto_init(ctxp, mech, key, keylen,
	    param, B_TRUE));
}

int
smb3_decrypt_init(smb3_enc_ctx_t *ctxp, smb_crypto_mech_t *mech,
    smb3_crypto_param_t *param, uint8_t *key, size_t keylen)
{
	return (smb3_crypto_init(ctxp, mech, key, keylen,
	    param, B_FALSE));
}

/*
 * Digest one segment
 */
int
smb3_encrypt_update(smb3_enc_ctx_t *ctxp, uint8_t *in, size_t len)
{
	crypto_data_t data;
	int rv;

	bzero(&data, sizeof (data));
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_length = len;
	data.cd_raw.iov_base = (void *)in;
	data.cd_raw.iov_len = len;

	rv = crypto_encrypt_update(ctxp->ctx, &data, &ctxp->output, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_encrypt_update failed: 0x%x", rv);
		crypto_cancel_ctx(ctxp->ctx);
		return (-1);
	}

	len = ctxp->output.cd_length;
	ctxp->len -= len;
	ctxp->output.cd_offset += len;
	ctxp->output.cd_length = ctxp->len;

	return (0);
}

int
smb3_decrypt_update(smb3_enc_ctx_t *ctxp, uint8_t *in, size_t len)
{
	crypto_data_t data;
	int rv;

	bzero(&data, sizeof (data));
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_length = len;
	data.cd_raw.iov_base = (void *)in;
	data.cd_raw.iov_len = len;

	/*
	 * AES_CCM does not output data until decrypt_final,
	 * and only does so if the signature matches.
	 */
	rv = crypto_decrypt_update(ctxp->ctx, &data, NULL, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_decrypt_update failed: 0x%x", rv);
		crypto_cancel_ctx(ctxp->ctx);
		return (-1);
	}

	return (0);
}

int
smb3_encrypt_final(smb3_enc_ctx_t *ctxp, uint8_t *digest16)
{
	crypto_data_t out;
	int rv;
	uint8_t buf[SMB2_SIG_SIZE + 16] = {0};
	size_t outlen;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = sizeof (buf);
	out.cd_raw.iov_len = sizeof (buf);
	out.cd_raw.iov_base = (void *)buf;

	rv = crypto_encrypt_final(ctxp->ctx, &out, 0);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_encrypt_final failed: 0x%x", rv);
		return (-1);
	}

	/*
	 * For some reason AES module processes ccm_encrypt_final and
	 * gcm_encrypt_final differently.
	 * For GCM it restores original offset (which is 0) and updates
	 * cd_length to size of residual data + mac len.
	 * For CCM it does nothing, what means offset is updated and cd_length
	 * is decreased by size of residual data + mac len.
	 */
	if (out.cd_offset == 0) {
		/* GCM */
		outlen = out.cd_length - SMB2_SIG_SIZE;
	} else {
		/* CCM */
		outlen = out.cd_offset - SMB2_SIG_SIZE;
	}

	if (outlen > 0)
		bcopy(buf, ctxp->output.cd_raw.iov_base +
		    ctxp->output.cd_offset, outlen);
	bcopy(buf + outlen, digest16, SMB2_SIG_SIZE);

	return (0);
}

int
smb3_decrypt_final(smb3_enc_ctx_t *ctxp, uint8_t *buf, size_t buflen)
{
	crypto_data_t out;
	int rv;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = buflen;
	out.cd_raw.iov_len = buflen;
	out.cd_raw.iov_base = (void *)buf;

	rv = crypto_decrypt_final(ctxp->ctx, &out, NULL);

	if (rv != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "crypto_decrypt_final failed: 0x%x", rv);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

void
smb3_encrypt_cancel(smb3_enc_ctx_t *ctxp)
{
	crypto_cancel_ctx(ctxp->ctx);
}
