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

#define	SSN_KEY_LEN	16
#define	SMB_SIG_SIZE	8
#define	SMB_SIG_OFFS	14
#define	SMB_HDRLEN	32

#ifdef _LITTLE_ENDIAN
#define	htolel(x)	((uint32_t)(x))
#else
#define	htolel(x)	BSWAP_32(x)
#endif

int
smb_sign_calc(struct mbuf_chain *mbc,
    struct smb_sign *sign,
    uint32_t seqnum,
    unsigned char *mac_sign);

#ifdef DEBUG
static void
smb_sign_find_seqnum(
    uint32_t seqnum,
    struct smb_sign *sign,
    struct mbuf_chain *command,
    unsigned char *mac_sig,
    unsigned char *sr_sig,
    boolean_t *found)
{
int start_seqnum;
int i;

	/* Debug code to hunt for the sequence number */
	*found = B_FALSE;
	start_seqnum = seqnum - 10;
	if (start_seqnum < 0)
		start_seqnum = 0;
	for (i = start_seqnum; i <= start_seqnum + 20; i++) {
		(void) smb_sign_calc(command, sign, i, mac_sig);
		if (memcmp(mac_sig, sr_sig, SMB_SIG_SIZE) == 0) {
			sign->seqnum = i;
			*found = B_TRUE;
			break;
		}
		cmn_err(CE_WARN, "smb_sign_find_seqnum: seqnum:%d mismatch", i);
	}
	cmn_err(CE_WARN, "smb_sign_find_seqnum: found=%d", *found);
}
#endif

/*
 * Called during session destroy.
 */
static void
smb_sign_fini(smb_session_t *s)
{
	smb_sign_mech_t *mech;

	if ((mech = s->signing.mech) != NULL) {
		kmem_free(mech, sizeof (*mech));
		s->signing.mech = NULL;
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
	if (sign->mech == NULL) {
		mech = kmem_zalloc(sizeof (*mech), KM_SLEEP);
		rc = smb_md5_getmech(mech);
		if (rc != 0) {
			kmem_free(mech, sizeof (*mech));
			smb_rwx_rwexit(&session->s_lock);
			return (rc);
		}
		sign->mech = mech;
		session->sign_fini = smb_sign_fini;
	}

	/*
	 * Compute and store the signing (MAC) key.
	 *
	 * With extended security, the MAC key is the same as the
	 * session key (and we'll have sinfo->ssi_cspwlen == 0).
	 * With non-extended security, it's the concatenation of
	 * the session key and the "NT response" we received.
	 * (NB: no extended security yet)
	 */
	sign->mackey_len = SSN_KEY_LEN + sinfo->ssi_cspwlen;
	sign->mackey = kmem_alloc(sign->mackey_len, KM_SLEEP);
	bcopy(token->tkn_session_key, sign->mackey, SSN_KEY_LEN);
	if (sinfo->ssi_cspwlen > 0) {
		bcopy(sinfo->ssi_cspwd, sign->mackey + SSN_KEY_LEN,
		    sinfo->ssi_cspwlen);
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
int
smb_sign_calc(struct mbuf_chain *mbc,
    struct smb_sign *sign,
    uint32_t seqnum,
    unsigned char *mac_sign)
{
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

	if (sign->mech == NULL || sign->mackey == NULL)
		return (-1);

	if ((rc = smb_md5_init(&ctx, sign->mech)) != 0)
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
	struct mbuf_chain command = sr->command;
	unsigned char mac_sig[SMB_SIG_SIZE];
	struct smb_sign *sign = &sr->session->signing;
	int rtn = 0;
	boolean_t found = B_TRUE;

	/*
	 * Don't check secondary transactions - we dont know the sequence
	 * number.
	 */
	if (sr->smb_com == SMB_COM_TRANSACTION_SECONDARY ||
	    sr->smb_com == SMB_COM_TRANSACTION2_SECONDARY ||
	    sr->smb_com == SMB_COM_NT_TRANSACT_SECONDARY)
		return (0);

	/* Reset the offset to begining of header */
	command.chain_offset = sr->orig_request_hdr;

	/* calculate mac signature */
	if (smb_sign_calc(&command, sign, sr->sr_seqnum, mac_sig) != 0)
		return (-1);

	/* compare the signatures */
	if (memcmp(mac_sig, sr->smb_sig, SMB_SIG_SIZE) != 0) {
		DTRACE_PROBE2(smb__signing__req, smb_request_t, sr,
		    smb_sign_t *, sr->smb_sig);
		cmn_err(CE_NOTE, "smb_sign_check_request: bad signature");
		/*
		 * check nearby sequence numbers in debug mode
		 */
#ifdef	DEBUG
		if (smb_sign_debug)
			smb_sign_find_seqnum(sr->sr_seqnum, sign,
			    &command, mac_sig, sr->smb_sig, &found);
		else
#endif
			found = B_FALSE;

		if (found == B_FALSE)
			rtn = -1;
	}
	return (rtn);
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
	struct mbuf_chain command = sr->command;
	unsigned char mac_sig[SMB_SIG_SIZE];
	struct smb_sign *sign = &sr->session->signing;
	int rtn = 0;

	/* Reset the offset to begining of header */
	command.chain_offset = sr->orig_request_hdr;

	/* calculate mac signature */
	if (smb_sign_calc(&command, sign, reply_seqnum - 1,
	    mac_sig) != 0)
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
	struct mbuf_chain resp;
	struct smb_sign *sign = &sr->session->signing;
	unsigned char signature[SMB_SIG_SIZE];

	if (reply)
		resp = *reply;
	else
		resp = sr->reply;

	/* Reset offset to start of reply */
	resp.chain_offset = 0;

	/*
	 * Calculate MAC signature
	 */
	if (smb_sign_calc(&resp, sign, sr->reply_seqnum, signature) != 0) {
		cmn_err(CE_WARN, "smb_sign_reply: error in smb_sign_calc");
		return;
	}

	/*
	 * Put signature in the response
	 */
	(void) smb_mbc_poke(&resp, SMB_SIG_OFFS, "#c",
	    SMB_SIG_SIZE, signature);
}
