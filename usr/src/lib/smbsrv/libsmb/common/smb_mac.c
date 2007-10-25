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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB MAC Signing support.
 */

#include <strings.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

#include <smbsrv/libsmb.h>

#include <smbsrv/smb.h>

/*
 * smb_mac_init
 *
 * Calculates the MAC key using the specified user session
 * key (NTLM or NTLMv2).
 *
 * Returns SMBAUTH_SUCCESS if key generation was successful,
 * SMBAUTH_FAILURE if not.
 */
int
smb_mac_init(smb_sign_ctx_t *sign_ctx, smb_auth_info_t *auth)
{
	unsigned char S16[SMBAUTH_SESSION_KEY_SZ];

	if (smb_auth_gen_session_key(auth, S16) != SMBAUTH_SUCCESS)
		return (SMBAUTH_FAILURE);
	bcopy(S16, sign_ctx->ssc_mackey, SMBAUTH_SESSION_KEY_SZ);
	bcopy(auth->cs, &(sign_ctx->ssc_mackey[SMBAUTH_SESSION_KEY_SZ]),
	    auth->cs_len);
	sign_ctx->ssc_keylen = SMBAUTH_SESSION_KEY_SZ + auth->cs_len;
	return (SMBAUTH_SUCCESS);
}

/*
 * smb_mac_calc
 *
 * Calculates MAC signature for the given buffer and returns
 * it in the mac_sign parameter.
 *
 * The MAC signature is calculated as follows:
 *
 * data = concat(MAC_Key, MAC_Key_Len, SMB_Msg, SMB_Msg_Len);
 * hash = MD5(data);
 * MAC  = head(hash, 8);
 *
 * The tricky part is that a sequence number should be used
 * in calculation instead of the signature field in the
 * SMB header.
 *
 * Returns SMBAUTH_SUCCESS if cryptology framework use was successful,
 * SMBAUTH_FAILURE if not.
 */
int
smb_mac_calc(smb_sign_ctx_t *sign_ctx, const unsigned char *buf,
    size_t buf_len, unsigned char *mac_sign)
{
	CK_RV rv;
	CK_MECHANISM mechanism;
	CK_SESSION_HANDLE hSession;
	unsigned long diglen = MD_DIGEST_LEN;
	int rc = SMBAUTH_FAILURE;

	int offset_end_of_sig = (SMB_SIG_OFFS + SMB_SIG_SIZE);
	unsigned char seq_buf[SMB_SIG_SIZE];
	unsigned char mac[16];

	/*
	 * put seq_num into the first 4 bytes and
	 * zero out the next 4 bytes
	 */
	bcopy(&sign_ctx->ssc_seqnum, seq_buf, 4);
	bzero(seq_buf + 4, 4);

	mechanism.mechanism = CKM_MD5;
	mechanism.pParameter = 0;
	mechanism.ulParameterLen = 0;

	rv = SUNW_C_GetMechSession(mechanism.mechanism, &hSession);
	if (rv != CKR_OK)
		return (SMBAUTH_FAILURE);

	/* Initialize the digest operation in the session */
	rv = C_DigestInit(hSession, &mechanism);
	if (rv != CKR_OK)
		goto smbmacdone;

	/* init with the MAC key */
	rv = C_DigestUpdate(hSession, sign_ctx->ssc_mackey,
	    sign_ctx->ssc_keylen);
	if (rv != CKR_OK)
		goto smbmacdone;

	/* copy in SMB packet info till signature field */
	rv = C_DigestUpdate(hSession, (CK_BYTE_PTR)buf, SMB_SIG_OFFS);
	if (rv != CKR_OK)
		goto smbmacdone;

	/* copy in the seq_buf instead of the signature */
	rv = C_DigestUpdate(hSession, seq_buf, sizeof (seq_buf));
	if (rv != CKR_OK)
		goto smbmacdone;

	/* copy in the rest of the packet, skipping the signature */
	rv = C_DigestUpdate(hSession, (CK_BYTE_PTR)buf + offset_end_of_sig,
	    buf_len - offset_end_of_sig);
	if (rv != CKR_OK)
		goto smbmacdone;

	rv = C_DigestFinal(hSession, mac, &diglen);
	if (rv != CKR_OK)
		goto smbmacdone;

	bcopy(mac, mac_sign, SMB_SIG_SIZE);
	rc = SMBAUTH_SUCCESS;

smbmacdone:
	(void) C_CloseSession(hSession);
	return (rc);
}

/*
 * smb_mac_chk
 *
 * Calculates MAC signature for the given buffer
 * and compares it to the signature in the given context.
 * Return 1 if the signature are match, otherwise, return (0);
 */
int
smb_mac_chk(smb_sign_ctx_t *sign_ctx,
			const unsigned char *buf, size_t buf_len)
{
	unsigned char mac_sign[SMB_SIG_SIZE];

	/* calculate mac signature */
	if (smb_mac_calc(sign_ctx, buf, buf_len, mac_sign) != SMBAUTH_SUCCESS)
		return (0);

	/* compare the signatures */
	if (memcmp(sign_ctx->ssc_sign, mac_sign, SMB_SIG_SIZE) == 0)
		return (1);

	return (0);
}

/*
 * smb_mac_sign
 *
 * Calculates MAC signature for the given buffer,
 * and write it to the buffer's signature field.
 *
 * Returns SMBAUTH_SUCCESS if cryptology framework use was successful,
 * SMBAUTH_FAILURE if not.
 */
int
smb_mac_sign(smb_sign_ctx_t *sign_ctx, unsigned char *buf, size_t buf_len)
{
	unsigned char mac_sign[SMB_SIG_SIZE];

	/* calculate mac signature */
	if (smb_mac_calc(sign_ctx, buf, buf_len, mac_sign) != SMBAUTH_SUCCESS)
		return (SMBAUTH_FAILURE);

	/* put mac signature in the header's signature field */
	(void) memcpy(buf + SMB_SIG_OFFS, mac_sign, SMB_SIG_SIZE);
	return (SMBAUTH_SUCCESS);
}

void
smb_mac_inc_seqnum(smb_sign_ctx_t *sign_ctx)
{
	sign_ctx->ssc_seqnum++;
}

void
smb_mac_dec_seqnum(smb_sign_ctx_t *sign_ctx)
{
	sign_ctx->ssc_seqnum--;
}
