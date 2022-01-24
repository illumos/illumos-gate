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
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * Helper functions for SMB signing using the
 * Kernel Cryptographic Framework (KCF)
 *
 * There are two implementations of these functions:
 * This one (for kernel) and another for user space:
 * See: lib/smbsrv/libfksmbsrv/common/fksmb_sign_pkcs.c
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/crypto/api.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kcrypt.h>

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
 * SMB1 signing helpers:
 * (getmech, init, update, final)
 */

int
smb_md5_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_MD5));
}

/*
 * Start the KCF session, load the key
 */
int
smb_md5_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech)
{
	int rv;

	rv = crypto_digest_init(mech, ctxp, NULL);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb_md5_update(smb_sign_ctx_t ctx, void *buf, size_t len)
{
	crypto_data_t data;
	int rv;

	bzero(&data, sizeof (data));
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_length = len;
	data.cd_raw.iov_base = buf;
	data.cd_raw.iov_len = len;

	rv = crypto_digest_update(ctx, &data, 0);

	if (rv != CRYPTO_SUCCESS) {
		crypto_cancel_ctx(ctx);
		return (-1);
	}

	return (0);
}

/*
 * Get the final digest.
 */
int
smb_md5_final(smb_sign_ctx_t ctx, uint8_t *digest16)
{
	crypto_data_t out;
	int rv;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = MD5_DIGEST_LENGTH;
	out.cd_raw.iov_len = MD5_DIGEST_LENGTH;
	out.cd_raw.iov_base = (void *)digest16;

	rv = crypto_digest_final(ctx, &out, 0);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * SMB2 signing helpers:
 * (getmech, init, update, final)
 */

int
smb2_hmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_SHA256_HMAC));
}

/*
 * Start the KCF session, load the key
 */
int
smb2_hmac_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len)
{
	crypto_key_t ckey;
	int rv;

	bzero(&ckey, sizeof (ckey));
	ckey.ck_format = CRYPTO_KEY_RAW;
	ckey.ck_data = key;
	ckey.ck_length = key_len * 8; /* in bits */

	rv = crypto_mac_init(mech, &ckey, NULL, ctxp, NULL);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb2_hmac_update(smb_sign_ctx_t ctx, uint8_t *in, size_t len)
{
	crypto_data_t data;
	int rv;

	bzero(&data, sizeof (data));
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_length = len;
	data.cd_raw.iov_base = (void *)in;
	data.cd_raw.iov_len = len;

	rv = crypto_mac_update(ctx, &data, 0);

	if (rv != CRYPTO_SUCCESS) {
		crypto_cancel_ctx(ctx);
		return (-1);
	}

	return (0);
}

/*
 * Note, the SMB2 signature is the first 16 bytes of the
 * 32-byte SHA256 HMAC digest.  This is specifically for
 * SMB2 signing, and NOT a generic HMAC function.
 */
int
smb2_hmac_final(smb_sign_ctx_t ctx, uint8_t *digest16)
{
	uint8_t full_digest[SHA256_DIGEST_LENGTH];
	crypto_data_t out;
	int rv;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = SHA256_DIGEST_LENGTH;
	out.cd_raw.iov_len = SHA256_DIGEST_LENGTH;
	out.cd_raw.iov_base = (void *)full_digest;

	rv = crypto_mac_final(ctx, &out, 0);
	if (rv == CRYPTO_SUCCESS)
		bcopy(full_digest, digest16, 16);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * One-shot HMAC function used in smb3_kdf
 */
int
smb2_hmac_one(smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len,
    uint8_t *mac, size_t mac_len)
{
	crypto_key_t ckey;
	crypto_data_t cdata;
	crypto_data_t cmac;
	int rv;

	bzero(&ckey, sizeof (ckey));
	ckey.ck_format = CRYPTO_KEY_RAW;
	ckey.ck_data = key;
	ckey.ck_length = key_len * 8; /* in bits */

	bzero(&cdata, sizeof (cdata));
	cdata.cd_format = CRYPTO_DATA_RAW;
	cdata.cd_length = data_len;
	cdata.cd_raw.iov_base = (void *)data;
	cdata.cd_raw.iov_len = data_len;

	bzero(&cmac, sizeof (cmac));
	cmac.cd_format = CRYPTO_DATA_RAW;
	cmac.cd_length = mac_len;
	cmac.cd_raw.iov_base = (void *)mac;
	cmac.cd_raw.iov_len = mac_len;

	rv = crypto_mac(mech, &cdata, &ckey, NULL, &cmac, NULL);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * SMB3 signing helpers:
 * (getmech, init, update, final)
 */

int
smb3_cmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_CMAC));
}

/*
 * Start the KCF session, load the key
 */
int
smb3_cmac_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len)
{
	crypto_key_t ckey;
	int rv;

	bzero(&ckey, sizeof (ckey));
	ckey.ck_format = CRYPTO_KEY_RAW;
	ckey.ck_data = key;
	ckey.ck_length = key_len * 8; /* in bits */

	rv = crypto_mac_init(mech, &ckey, NULL, ctxp, NULL);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb3_cmac_update(smb_sign_ctx_t ctx, uint8_t *in, size_t len)
{
	crypto_data_t data;
	int rv;

	bzero(&data, sizeof (data));
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_length = len;
	data.cd_raw.iov_base = (void *)in;
	data.cd_raw.iov_len = len;

	rv = crypto_mac_update(ctx, &data, 0);

	if (rv != CRYPTO_SUCCESS) {
		crypto_cancel_ctx(ctx);
		return (-1);
	}

	return (0);
}

/*
 * Note, the SMB2 signature is just the AES CMAC digest.
 * (both are 16 bytes long)
 */
int
smb3_cmac_final(smb_sign_ctx_t ctx, uint8_t *digest16)
{
	crypto_data_t out;
	int rv;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = SMB2_SIG_SIZE;
	out.cd_raw.iov_len = SMB2_SIG_SIZE;
	out.cd_raw.iov_base = (void *)digest16;

	rv = crypto_mac_final(ctx, &out, 0);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}
