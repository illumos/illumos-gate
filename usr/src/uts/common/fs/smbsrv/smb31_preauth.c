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
 * Copyright 2020 RackTop Systems, Inc.
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2.h>
#include <sys/crypto/api.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kcrypt.h>

/*
 * SMB 3.1.1 Preauth Integrity
 */
int
smb3_sha512_getmech(smb_crypto_mech_t *mech)
{
	crypto_mech_type_t t;

	t = crypto_mech2id(SUN_CKM_SHA512);
	if (t == CRYPTO_MECH_INVALID) {
		cmn_err(CE_NOTE, "smb: no kcf mech: %s", SUN_CKM_SHA512);
		return (-1);
	}
	mech->cm_type = t;
	return (0);
}

/*
 * (called from smb2_negotiate_common)
 */
void
smb31_preauth_init_mech(smb_session_t *s)
{
	smb_crypto_mech_t *mech;
	int rc;

	ASSERT3S(s->dialect, >=, SMB_VERS_3_11);

	if (s->preauth_mech != NULL)
		return;

	mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
	rc = smb3_sha512_getmech(mech);
	if (rc != 0) {
		kmem_free(mech, sizeof (*mech));
		return;
	}
	s->preauth_mech = mech;
}

void
smb31_preauth_fini(smb_session_t *s)
{
	smb_crypto_mech_t *mech;

	if ((mech = s->preauth_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->preauth_mech = NULL;
	}
}

/*
 * Start the KCF session, load the key
 */
int
smb_sha512_init(smb_sign_ctx_t *ctxp, smb_crypto_mech_t *mech)
{
	int rv;

	rv = crypto_digest_init(mech, ctxp, NULL);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb_sha512_update(smb_sign_ctx_t ctx, void *buf, size_t len)
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
smb_sha512_final(smb_sign_ctx_t ctx, uint8_t *digest)
{
	crypto_data_t out;
	int rv;

	bzero(&out, sizeof (out));
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_length = SHA512_DIGEST_LENGTH;
	out.cd_raw.iov_len = SHA512_DIGEST_LENGTH;
	out.cd_raw.iov_base = (void *)digest;

	rv = crypto_digest_final(ctx, &out, 0);

	return (rv == CRYPTO_SUCCESS ? 0 : -1);
}

int
smb31_preauth_sha512_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint8_t *in_hashval, uint8_t *out_hashval)
{
	smb_session_t *s = sr->session;
	smb_sign_ctx_t ctx = 0;
	struct mbuf *mbuf = mbc->chain;
	int rc;

	ASSERT3U(s->smb31_preauth_hashid, !=, 0);

	if (s->preauth_mech == NULL)
		return (-1);

	if ((rc = smb_sha512_init(&ctx, s->preauth_mech)) != 0)
		return (rc);

	/* Digest current hashval */
	rc = smb_sha512_update(ctx, in_hashval, SHA512_DIGEST_LENGTH);
	if (rc != 0)
		return (rc);

	while (mbuf != NULL) {
		rc = smb_sha512_update(ctx, mbuf->m_data, mbuf->m_len);
		if (rc != 0)
			return (rc);
		mbuf = mbuf->m_next;
	}

	rc = smb_sha512_final(ctx, out_hashval);
	return (rc);
}
