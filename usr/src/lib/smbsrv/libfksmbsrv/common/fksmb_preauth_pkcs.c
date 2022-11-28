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
 * Copyright 2021 RackTop Systems, Inc.
 */

#include <stdlib.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_kcrypt.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

/*
 * SMB 3.1.1 Preauth Integrity
 */
static int
getmech_sha512(smb_crypto_mech_t *mech)
{
	ulong_t mid = CKM_SHA512;
	CK_SESSION_HANDLE hdl;
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mid, &hdl);
	if (rv != CKR_OK) {
		cmn_err(CE_NOTE, "PKCS#11: no mech 0x%x",
		    (unsigned int)mid);
		return (-1);
	}
	(void) C_CloseSession(hdl);

	mech->mechanism = mid;
	mech->pParameter = NULL;
	mech->ulParameterLen = 0;
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
	rc = getmech_sha512(mech);
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
	CK_RV rv;

	rv = SUNW_C_GetMechSession(mech->mechanism, ctxp);
	if (rv != CKR_OK)
		return (-1);

	rv = C_DigestInit(*ctxp, mech);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Digest one segment
 */
int
smb_sha512_update(smb_sign_ctx_t ctx, void *buf, size_t len)
{
	CK_RV rv;

	rv = C_DigestUpdate(ctx, buf, len);
	if (rv != CKR_OK)
		(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
}

/*
 * Get the final digest.
 */
int
smb_sha512_final(smb_sign_ctx_t ctx, uint8_t *digest)
{
	CK_ULONG len = SHA512_DIGEST_LENGTH;
	CK_RV rv;

	rv = C_DigestFinal(ctx, digest, &len);
	(void) C_CloseSession(ctx);

	return (rv == CKR_OK ? 0 : -1);
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
