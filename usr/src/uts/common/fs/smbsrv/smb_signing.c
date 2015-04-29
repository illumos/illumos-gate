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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <smbsrv/msgbuf.h>
#include <sys/crypto/api.h>

#define	SMBAUTH_SESSION_KEY_SZ 16
#define	SMB_SIG_SIZE	8
#define	SMB_SIG_OFFS	14

int
smb_sign_calc(struct mbuf_chain *mbc,
    struct smb_sign *sign,
    uint32_t seqnum,
    unsigned char *mac_sign);

#ifdef DEBUG
void smb_sign_find_seqnum(
    uint32_t seqnum,
    struct smb_sign *sign,
    struct mbuf_chain *command,
    unsigned char *mac_sig,
    unsigned char *sr_sig,
    boolean_t *found);
#define	SMB_CHECK_SEQNUM(seqnum, sign, command, mac_sig, sr_sig, found) \
{ \
	if (smb_sign_debug) \
		smb_sign_find_seqnum(seqnum, sign, \
		    command, mac_sig, sr_sig, found); \
}
#else
#define	SMB_CHECK_SEQNUM(seqnum, sign, command, mac_sig, sr_sig, found) \
	{ \
		*found = 0; \
	}
#endif

#ifdef DEBUG
void
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

/* This holds the MD5 mechanism */
static	crypto_mechanism_t crypto_mech = {CRYPTO_MECHANISM_INVALID, 0, 0};

void
smb_sign_g_init(void)
{
	/*
	 * Initialise the crypto mechanism to MD5 if it not
	 * already initialised.
	 */
	if (crypto_mech.cm_type == CRYPTO_MECHANISM_INVALID) {
		crypto_mech.cm_type = crypto_mech2id(SUN_CKM_MD5);
	}
}

/*
 * smb_sign_init
 *
 * Intializes MAC key based on the user session key and
 * NTLM response and store it in the signing structure.
 */
void
smb_sign_init(smb_request_t *sr, smb_session_key_t *session_key,
	char *resp, int resp_len)
{
	struct smb_sign *sign = &sr->session->signing;

	if (crypto_mech.cm_type == CRYPTO_MECHANISM_INVALID) {
		/*
		 * There is no MD5 crypto mechanism
		 * so turn off signing
		 */
		sr->sr_cfg->skc_signing_enable = 0;
		sr->session->secmode &=
		    (~NEGOTIATE_SECURITY_SIGNATURES_ENABLED);
		cmn_err(CE_WARN,
		    "SmbSignInit: signing disabled (no MD5)");
		return;
	}

	/* MAC key = concat (SessKey, NTLMResponse) */

	bcopy(session_key, sign->mackey, sizeof (smb_session_key_t));
	bcopy(resp, &(sign->mackey[sizeof (smb_session_key_t)]),
	    resp_len);
	sign->mackey_len = sizeof (smb_session_key_t) + resp_len;

	sr->session->signing.seqnum = 0;
	sr->sr_seqnum = 2;
	sr->reply_seqnum = 1;
	sign->flags = SMB_SIGNING_ENABLED;
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
 * Return 0 if  success else -1
 *
 */
int
smb_sign_calc(struct mbuf_chain *mbc,
    struct smb_sign *sign,
    uint32_t seqnum,
    unsigned char *mac_sign)
{
	uint32_t seq_buf[2] = {0, 0};
	unsigned char mac[16];
	struct mbuf *mbuf = mbc->chain;
	int offset = mbc->chain_offset;
	int size;
	int status;

	crypto_data_t data;
	crypto_data_t digest;
	crypto_context_t crypto_ctx;

	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_offset = 0;
	data.cd_length = (size_t)-1;
	data.cd_miscdata = 0;

	digest.cd_format = CRYPTO_DATA_RAW;
	digest.cd_offset = 0;
	digest.cd_length = (size_t)-1;
	digest.cd_miscdata = 0;
	digest.cd_raw.iov_base = (char *)mac;
	digest.cd_raw.iov_len = sizeof (mac);

	status = crypto_digest_init(&crypto_mech, &crypto_ctx, 0);
	if (status != CRYPTO_SUCCESS)
		goto error;

	/*
	 * Put the sequence number into the first 4 bytes
	 * of the signature field in little endian format.
	 * We are using a buffer to represent the signature
	 * rather than modifying the SMB message.
	 */
#ifdef __sparc
	{
		uint32_t temp;
		((uint8_t *)&temp)[0] = ((uint8_t *)&seqnum)[3];
		((uint8_t *)&temp)[1] = ((uint8_t *)&seqnum)[2];
		((uint8_t *)&temp)[2] = ((uint8_t *)&seqnum)[1];
		((uint8_t *)&temp)[3] = ((uint8_t *)&seqnum)[0];

		seq_buf[0] = temp;
	}
#else
	seq_buf[0] = seqnum;
#endif

	/* Digest the MACKey */
	data.cd_raw.iov_base = (char *)sign->mackey;
	data.cd_raw.iov_len = sign->mackey_len;
	data.cd_length = sign->mackey_len;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		goto error;

	/* Find start of data in chain */
	while (offset >= mbuf->m_len) {
		offset -= mbuf->m_len;
		mbuf = mbuf->m_next;
	}

	/* Digest the SMB packet up to the signature field */
	size = SMB_SIG_OFFS;
	while (size >= mbuf->m_len - offset) {
		data.cd_raw.iov_base = &mbuf->m_data[offset];
		data.cd_raw.iov_len = mbuf->m_len - offset;
		data.cd_length = mbuf->m_len - offset;
		status = crypto_digest_update(crypto_ctx, &data, 0);
		if (status != CRYPTO_SUCCESS)
			goto error;

		size -= mbuf->m_len - offset;
		mbuf = mbuf->m_next;
		offset = 0;
	}
	if (size > 0) {
		data.cd_raw.iov_base = &mbuf->m_data[offset];
		data.cd_raw.iov_len = size;
		data.cd_length = size;
		status = crypto_digest_update(crypto_ctx, &data, 0);
		if (status != CRYPTO_SUCCESS)
			goto error;
		offset += size;
	}

	/*
	 * Digest in the seq_buf instead of the signature
	 * which has the sequence number
	 */

	data.cd_raw.iov_base = (char *)seq_buf;
	data.cd_raw.iov_len = SMB_SIG_SIZE;
	data.cd_length = SMB_SIG_SIZE;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		goto error;

	/* Find the end of the signature field  */
	offset += SMB_SIG_SIZE;
	while (offset >= mbuf->m_len) {
		offset -= mbuf->m_len;
		mbuf = mbuf->m_next;
	}
	/* Digest the rest of the SMB packet */
	while (mbuf) {
		data.cd_raw.iov_base = &mbuf->m_data[offset];
		data.cd_raw.iov_len = mbuf->m_len - offset;
		data.cd_length = mbuf->m_len - offset;
		status = crypto_digest_update(crypto_ctx, &data, 0);
		if (status != CRYPTO_SUCCESS)
			goto error;
		mbuf = mbuf->m_next;
		offset = 0;
	}
	digest.cd_length = SMBAUTH_SESSION_KEY_SZ;
	status = crypto_digest_final(crypto_ctx, &digest, 0);
	if (status != CRYPTO_SUCCESS)
		goto error;
	bcopy(mac, mac_sign, SMB_SIG_SIZE);
	return (0);
error:
	cmn_err(CE_WARN, "SmbSignCalc: crypto error %d", status);
	return (-1);

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
		SMB_CHECK_SEQNUM(sr->sr_seqnum, sign, &command,
		    mac_sig, sr->smb_sig, &found);
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
	struct mbuf *mbuf;
	int size = SMB_SIG_SIZE;
	unsigned char *sig_ptr = signature;
	int offset = 0;

	if (reply)
		resp = *reply;
	else
		resp = sr->reply;

	/* Reset offset to start of reply */
	resp.chain_offset = 0;
	mbuf = resp.chain;

	/*
	 * Calculate MAC signature
	 */
	if (smb_sign_calc(&resp, sign, sr->reply_seqnum, signature) != 0) {
		cmn_err(CE_WARN, "smb_sign_reply: error in smb_sign_calc");
		return;
	}

	/*
	 * Put signature in the response
	 *
	 * First find start of signature in chain (offset + signature offset)
	 */
	offset += SMB_SIG_OFFS;
	while (offset >= mbuf->m_len) {
		offset -= mbuf->m_len;
		mbuf = mbuf->m_next;
	}

	while (size >= mbuf->m_len - offset) {
		(void) memcpy(&mbuf->m_data[offset],
		    sig_ptr, mbuf->m_len - offset);
		offset = 0;
		sig_ptr += mbuf->m_len - offset;
		size -= mbuf->m_len - offset;
		mbuf = mbuf->m_next;
	}
	if (size > 0) {
		(void) memcpy(&mbuf->m_data[offset], sig_ptr, size);
	}
}
