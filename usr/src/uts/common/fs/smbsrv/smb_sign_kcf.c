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
 * Copyright 2022-2023 RackTop Systems, Inc.
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
	return (find_mech(mech, SUN_CKM_SHA256_HMAC_GENERAL));
}

int
smb3_cmac_getmech(smb_crypto_mech_t *mech)
{
	return (find_mech(mech, SUN_CKM_AES_CMAC));
}

/*
 * Note, the SMB2 signature is the first 16 bytes of the digest,
 * even in the case of SHA256 HMAC (32-byte digest).
 *
 * CMAC has no parameter.
 */
void
smb2_sign_init_hmac_param(smb_crypto_mech_t *mech, smb_crypto_param_t *param,
    ulong_t hmac_len)
{
	param->hmac = hmac_len;

	mech->cm_param = (caddr_t)&param->hmac;
	mech->cm_param_len = sizeof (param->hmac);
}

/*
 * Digest a whole message as described by: crypto_data_t *input
 * and store the resulting MAC in *mac_buf / mac_len.
 * Returns zero on success, else non-zero.
 */
static int
smb2_mac(smb_crypto_mech_t *mech, uint8_t *key, size_t key_len,
    crypto_data_t *input, void *mac_buf, size_t mac_len)
{
	crypto_data_t out_cd = {
	    .cd_format = CRYPTO_DATA_RAW,
	    .cd_length = mac_len,
	    .cd_raw.iov_len = mac_len,
	    .cd_raw.iov_base = mac_buf
	};
	crypto_key_t ckey = {
	    .ck_format = CRYPTO_KEY_RAW,
	    .ck_data = key,
	    .ck_length = key_len * 8 /* in bits */
	};
	int rv;

	rv = crypto_mac(mech, input, &ckey, NULL, &out_cd, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_mac failed: 0x%x", rv);
		return (-1);
	}

	return (0);
}

/*
 * Digest a whole message with scatter/gather (UIO)
 * Returns zero on success, else non-zero.
 */
int
smb2_mac_uio(smb_crypto_mech_t *mech, uint8_t *key, size_t key_len,
    uio_t *in_uio, uint8_t *digest16)
{
	crypto_data_t in_cd = {
	    .cd_format = CRYPTO_DATA_UIO,
	    .cd_length = in_uio->uio_resid,
	    .cd_uio = in_uio
	};

	return (smb2_mac(mech, key, key_len, &in_cd, digest16, SMB2_SIG_SIZE));
}

/*
 * Digest a whole message that fits in a single buffer
 */
int
smb2_mac_raw(smb_crypto_mech_t *mech,
    uint8_t *key, size_t key_len,
    uint8_t *data, size_t data_len,
    uint8_t *mac, size_t mac_len)
{
	crypto_data_t in_cd = {
	    .cd_format = CRYPTO_DATA_RAW,
	    .cd_length = data_len,
	    .cd_raw.iov_base = (void *)data,
	    .cd_raw.iov_len = data_len
	};

	return (smb2_mac(mech, key, key_len, &in_cd, mac, mac_len));
}
