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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * These routines provide the SMB MAC signing for the SMB server.
 * The routines calculate the signature of a SMB message in an mbuf chain.
 *
 * The following table describes the client server
 * signing registry relationship
 *
 *		| Required	| Enabled     | Disabled
 * -------------+---------------+------------ +--------------
 * Required	| Signed	| Signed      | Fail
 * -------------+---------------+-------------+-----------------
 * Enabled	| Signed	| Signed      | Not Signed
 * -------------+---------------+-------------+----------------
 * Disabled	| Fail		| Not Signed  | Not Signed
 */

#include <sys/uio.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_signing.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>

#define	SMB_SIG_SIZE	8
#define	SMB_SIG_OFFS	14
#define	SMB_HDRLEN	32

#ifdef _LITTLE_ENDIAN
#define	htolel(x)	((uint32_t)(x))
#else
#define	htolel(x)	BSWAP_32(x)
#endif

static int
smb_sign_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint32_t seqnum, unsigned char *sig);

#ifdef DEBUG
uint32_t smb_sign_debug_search = 10;

/*
 * Debug code to search +/- for the correct sequence number.
 * If found, correct sign->seqnum and return 0, else return -1
 */
static int
smb_sign_find_seqnum(
    smb_request_t *sr,
    struct mbuf_chain *mbc,
    unsigned char *mac_sig,
    unsigned char *sr_sig)
{
	struct smb_sign *sign = &sr->session->signing;
	uint32_t i, t;

	for (i = 1; i < smb_sign_debug_search; i++) {
		t = sr->sr_seqnum + i;
		(void) smb_sign_calc(sr, mbc, t, mac_sig);
		if (memcmp(mac_sig, sr_sig, SMB_SIG_SIZE) == 0) {
			goto found;
		}
		t = sr->sr_seqnum - i;
		(void) smb_sign_calc(sr, mbc, t, mac_sig);
		if (memcmp(mac_sig, sr_sig, SMB_SIG_SIZE) == 0) {
			goto found;
		}
	}
	cmn_err(CE_WARN, "smb_sign_find_seqnum: failed after %d", i);
	return (-1);

found:
	cmn_err(CE_WARN, "smb_sign_find_seqnum: found! %d <- %d",
	    sign->seqnum, t);
	sign->seqnum = t;
	return (0);
}
#endif

/*
 * Called during session destroy.
 */
static void
smb_sign_fini(smb_session_t *s)
{
	smb_sign_mech_t *mech;

	if ((mech = s->sign_mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->sign_mech = NULL;
	}
}

/*
 * smb_sign_begin
 *
 * Intializes MAC key based on the user session key and
 * NTLM response and store it in the signing structure.
 * This is what begins SMB signing.
 */
int
smb_sign_begin(smb_request_t *sr, smb_token_t *token)
{
	smb_arg_sessionsetup_t *sinfo = sr->sr_ssetup;
	smb_session_t *session = sr->session;
	struct smb_sign *sign = &session->signing;
	smb_sign_mech_t *mech;
	int rc;

	/*
	 * We should normally have a session key here because
	 * our caller filters out Anonymous and Guest logons.
	 * However, buggy clients could get us here without a
	 * session key, in which case: just don't sign.
	 */
	if (token->tkn_ssnkey.val == NULL || token->tkn_ssnkey.len == 0)
		return (0);

	/*
	 * Session-level initialization (once per session)
	 */
	smb_rwx_rwenter(&session->s_lock, RW_WRITER);

	/*
	 * Signing may already have been setup by a prior logon,
	 * in which case we're done here.
	 */
	if (sign->mackey != NULL) {
		smb_rwx_rwexit(&session->s_lock);
		return (0);
	}

	/*
	 * Get the mech handle
	 */
	if (session->sign_mech == NULL) {
		mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
		rc = smb_md5_getmech(mech);
		if (rc != 0) {
			kmem_free(mech, sizeof (*mech));
			smb_rwx_rwexit(&session->s_lock);
			return (rc);
		}
		session->sign_mech = mech;
		session->sign_fini = smb_sign_fini;
	}

	/*
	 * Compute and store the signing (MAC) key.
	 *
	 * With extended security, the MAC key is the same as the
	 * session key (and we'll have sinfo->ssi_ntpwlen == 0).
	 * With non-extended security, it's the concatenation of
	 * the session key and the "NT response" we received.
	 */
	sign->mackey_len = token->tkn_ssnkey.len + sinfo->ssi_ntpwlen;
	sign->mackey = kmem_alloc(sign->mackey_len, KM_SLEEP);
	bcopy(token->tkn_ssnkey.val, sign->mackey, token->tkn_ssnkey.len);
	if (sinfo->ssi_ntpwlen > 0) {
		bcopy(sinfo->ssi_ntpwd, sign->mackey + token->tkn_ssnkey.len,
		    sinfo->ssi_ntpwlen);
	}

	session->signing.seqnum = 0;
	sr->sr_seqnum = 2;
	sr->reply_seqnum = 1;
	sign->flags = 0;

	if (session->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED) {
		sign->flags |= SMB_SIGNING_ENABLED;
		if (session->secmode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED)
			sign->flags |= SMB_SIGNING_CHECK;
	}

	smb_rwx_rwexit(&session->s_lock);
	return (0);
}

/*
 * smb_sign_calc
 *
 * Calculates MAC signature for the given buffer and returns
 * it in the mac_sign parameter.
 *
 * The sequence number is placed in the first four bytes of the signature
 * field of the signature and the other 4 bytes are zeroed.
 * The signature is the first 8 bytes of the MD5 result of the
 * concatenated MAC key and the SMB message.
 *
 * MACsig = head(MD5(concat(MACKey, SMBMsg)), 8)
 *
 * where
 *
 *	MACKey = concat( UserSessionKey, NTLMResp )
 *
 * and
 *
 *	SMBMsg is the SMB message containing the sequence number.
 *
 * Return 0 if success
 *
 */
static int
smb_sign_calc(smb_request_t *sr, struct mbuf_chain *mbc,
    uint32_t seqnum, unsigned char *mac_sign)
{
	smb_session_t *s = sr->session;
	struct smb_sign *sign = &s->signing;
	smb_sign_ctx_t ctx = 0;
	uchar_t digest[MD5_DIGEST_LENGTH];
	uchar_t *hdrp;
	struct mbuf *mbuf = mbc->chain;
	int offset = mbc->chain_offset;
	int size;
	int rc;

	/*
	 * This union is a little bit of trickery to:
	 * (1) get the sequence number int aligned, and
	 * (2) reduce the number of digest calls, at the
	 * cost of a copying 32 bytes instead of 8.
	 * Both sides of this union are 2+32 bytes.
	 */
	union {
		struct {
			uint8_t skip[2]; /* not used - just alignment */
			uint8_t raw[SMB_HDRLEN];  /* header length (32) */
		} r;
		struct {
			uint8_t skip[2]; /* not used - just alignment */
			uint8_t hdr[SMB_SIG_OFFS]; /* sig. offset (14) */
			uint32_t sig[2]; /* MAC signature, aligned! */
			uint16_t ids[5]; /* pad, Tid, Pid, Uid, Mid */
		} s;
	} smbhdr;

	if (s->sign_mech == NULL || sign->mackey == NULL)
		return (-1);

	if ((rc = smb_md5_init(&ctx, s->sign_mech)) != 0)
		return (rc);

	/* Digest the MAC Key */
	rc = smb_md5_update(ctx, sign->mackey, sign->mackey_len);
	if (rc != 0)
		return (rc);

	/*
	 * Make an aligned copy of the SMB header,
	 * fill in the sequence number, and digest.
	 */
	hdrp = (unsigned char *)&smbhdr.r.raw;
	size = SMB_HDRLEN;
	if (smb_mbc_peek(mbc, offset, "#c", size, hdrp) != 0)
		return (-1);
	smbhdr.s.sig[0] = htolel(seqnum);
	smbhdr.s.sig[1] = 0;

	rc = smb_md5_update(ctx, &smbhdr.r.raw, size);
	if (rc != 0)
		return (rc);

	/*
	 * Digest the rest of the SMB packet, starting at the data
	 * just after the SMB header.
	 */
	offset += size;
	while (mbuf != NULL && (offset >= mbuf->m_len)) {
		offset -= mbuf->m_len;
		mbuf = mbuf->m_next;
	}
	if (mbuf != NULL && (size = (mbuf->m_len - offset)) > 0) {
		rc = smb_md5_update(ctx, &mbuf->m_data[offset], size);
		if (rc != 0)
			return (rc);
		offset = 0;
		mbuf = mbuf->m_next;
	}
	while (mbuf != NULL) {
		rc = smb_md5_update(ctx, mbuf->m_data, mbuf->m_len);
		if (rc != 0)
			return (rc);
		mbuf = mbuf->m_next;
	}
	rc = smb_md5_final(ctx, digest);
	if (rc == 0)
		bcopy(digest, mac_sign, SMB_SIG_SIZE);

	return (rc);
}


/*
 * smb_sign_check_request
 *
 * Calculates MAC signature for the request mbuf chain
 * using the next expected sequence number and compares
 * it to the given signature.
 *
 * Note it does not check the signature for secondary transactions
 * as their sequence number is the same as the original request.
 *
 * Return 0 if the signature verifies, otherwise, returns -1;
 *
 */
int
smb_sign_check_request(smb_request_t *sr)
{
	struct mbuf_chain mbc = sr->command;
	unsigned char mac_sig[SMB_SIG_SIZE];

	/*
	 * Don't check secondary transactions - we dont know the sequence
	 * number.
	 */
	if (sr->smb_com == SMB_COM_TRANSACTION_SECONDARY ||
	    sr->smb_com == SMB_COM_TRANSACTION2_SECONDARY ||
	    sr->smb_com == SMB_COM_NT_TRANSACT_SECONDARY)
		return (0);

	/* Reset the offset to begining of header */
	mbc.chain_offset = sr->orig_request_hdr;

	/* calculate mac signature */
	if (smb_sign_calc(sr, &mbc, sr->sr_seqnum, mac_sig) != 0)
		return (-1);

	/* compare the signatures */
	if (memcmp(mac_sig, sr->smb_sig, SMB_SIG_SIZE) == 0) {
		/* They match! OK, we're done. */
		return (0);
	}

	DTRACE_PROBE2(smb__signature__mismatch, smb_request_t, sr,
	    unsigned char *, mac_sig);
	cmn_err(CE_NOTE, "smb_sign_check_request: bad signature");

	/*
	 * check nearby sequence numbers in debug mode
	 */
#ifdef	DEBUG
	if (smb_sign_debug) {
		return (smb_sign_find_seqnum(sr, &mbc, mac_sig, sr->smb_sig));
	}
#endif
	return (-1);
}

/*
 * smb_sign_check_secondary
 *
 * Calculates MAC signature for the secondary transaction mbuf chain
 * and compares it to the given signature.
 * Return 0 if the signature verifies, otherwise, returns -1;
 *
 */
int
smb_sign_check_secondary(smb_request_t *sr, unsigned int reply_seqnum)
{
	struct mbuf_chain mbc = sr->command;
	unsigned char mac_sig[SMB_SIG_SIZE];
	int rtn = 0;

	/* Reset the offset to begining of header */
	mbc.chain_offset = sr->orig_request_hdr;

	/* calculate mac signature */
	if (smb_sign_calc(sr, &mbc, reply_seqnum - 1, mac_sig) != 0)
		return (-1);


	/* compare the signatures */
	if (memcmp(mac_sig, sr->smb_sig, SMB_SIG_SIZE) != 0) {
		cmn_err(CE_WARN, "SmbSignCheckSecond: bad signature");
		rtn = -1;
	}
	/* Save the reply sequence number */
	sr->reply_seqnum = reply_seqnum;

	return (rtn);
}

/*
 * smb_sign_reply
 *
 * Calculates MAC signature for the given mbuf chain,
 * and write it to the signature field in the mbuf.
 *
 */
void
smb_sign_reply(smb_request_t *sr, struct mbuf_chain *reply)
{
	struct mbuf_chain mbc;
	unsigned char mac[SMB_SIG_SIZE];

	if (reply)
		mbc = *reply;
	else
		mbc = sr->reply;

	/* Reset offset to start of reply */
	mbc.chain_offset = 0;

	/*
	 * Calculate MAC signature
	 */
	if (smb_sign_calc(sr, &mbc, sr->reply_seqnum, mac) != 0) {
		cmn_err(CE_WARN, "smb_sign_reply: error in smb_sign_calc");
		return;
	}

	/*
	 * Put signature in the response
	 */
	(void) smb_mbc_poke(&mbc, SMB_SIG_OFFS, "#c",
	    SMB_SIG_SIZE, mac);
}
