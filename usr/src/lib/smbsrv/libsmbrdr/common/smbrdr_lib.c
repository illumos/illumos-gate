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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides some common functionality for SMB Redirector
 * module.
 */

#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <smbsrv/ntstatus.h>
#include <smbrdr.h>

static DWORD smbrdr_handle_setup(smbrdr_handle_t *, unsigned char,
    struct sdb_session *, struct sdb_logon *, struct sdb_netuse *);
static int smbrdr_hdr_setup(smbrdr_handle_t *);
static DWORD smbrdr_hdr_process(smbrdr_handle_t *, smb_hdr_t *);
static int smbrdr_sign(smb_sign_ctx_t *, smb_msgbuf_t *);
static int smbrdr_sign_chk(smb_sign_ctx_t *, smb_msgbuf_t *, unsigned char *);

void smbrdr_lock_transport() { nb_lock(); }
void smbrdr_unlock_transport() { nb_unlock(); }

/*
 * smbrdr_request_init
 *
 * Setup a handle with given information and then
 * setup a SMB header structure.
 *
 * Returns:
 *
 *	NT_STATUS_NO_MEMORY		no memory for creating request
 *	NT_STATUS_INTERNAL_ERROR	header encode failed or crypto failed
 *	NT_STATUS_SUCCESS		successful
 */
DWORD
smbrdr_request_init(smbrdr_handle_t *srh,
			unsigned char cmd,
			struct sdb_session *session,
			struct sdb_logon *logon,
			struct sdb_netuse *netuse)
{
	DWORD status;

	status = smbrdr_handle_setup(srh, cmd, session, logon, netuse);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	if (smbrdr_hdr_setup(srh) < SMB_HEADER_LEN) {
		smbrdr_handle_free(srh);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_send
 *
 * Send the SMB packet pointed by the given handle over
 * network.
 *
 * Returns:
 *
 *	NT_STATUS_INTERNAL_ERROR		crypto framework failure
 *	NT_STATUS_UNEXPECTED_NETWORK_ERROR	send failed
 *	NT_STATUS_SUCCESS			successful
 */
DWORD
smbrdr_send(smbrdr_handle_t *srh)
{
	int rc;

	if (smbrdr_sign(&srh->srh_session->sign_ctx, &srh->srh_mbuf) !=
	    SMBAUTH_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_send[%d]: signing failed",
		    srh->srh_cmd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = nb_send(srh->srh_session->sock, srh->srh_buf,
	    smb_msgbuf_used(&srh->srh_mbuf));

	if (rc < 0) {
		/*
		 * Make the sequence number of the next SMB request even
		 * to avoid DC from failing the next SMB request with
		 * ACCESS_DENIED.
		 */
		smb_mac_dec_seqnum(&srh->srh_session->sign_ctx);
		return (NT_STATUS_UNEXPECTED_NETWORK_ERROR);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_rcv
 *
 * Receive a SMB response and decode the packet header.
 *
 * "Implementing CIFS" book, SMB requests always have an even sequence
 * number and replies always have an odd.
 *
 * With the original code, if the SMB Redirector skip the counter increment
 * in the event of any failure during SmbSessionSetupAndX, it causes the
 * domain controller to fail the next SMB request(odd sequence number)
 * with ACCESS_DENIED.
 *
 * Smbrdr module should use the same sequence number (i.e. ssc_seqnum of the
 * SMB Sign context) for generating the MAC signature for all incoming
 * responses per SmbTransact request. Otherwise, the validation will fail.
 * It is now fixed by decrementing the sequence number prior to validating
 * the subsequent responses for a single request.
 *
 * Returns:
 *
 *	status code returned by smbrdr_hdr_process()
 *	NT_STATUS_UNEXPECTED_NETWORK_ERROR	receive failed
 *	NT_STATUS_SUCCESS					successful
 */
DWORD
smbrdr_rcv(smbrdr_handle_t *srh, int is_first_rsp)
{
	smb_hdr_t smb_hdr;
	DWORD status;
	int rc;
	smb_sign_ctx_t *sign_ctx = &srh->srh_session->sign_ctx;

	rc = nb_rcv(srh->srh_session->sock, srh->srh_buf, SMBRDR_REQ_BUFSZ, 0);
	if (rc < 0) {
		smb_mac_inc_seqnum(sign_ctx);
		return (NT_STATUS_UNEXPECTED_NETWORK_ERROR);
	}

	smb_msgbuf_init(&srh->srh_mbuf, srh->srh_buf, rc, srh->srh_mbflags);

	status = smbrdr_hdr_process(srh, &smb_hdr);
	if (status != NT_STATUS_SUCCESS) {
		smb_mac_inc_seqnum(sign_ctx);
		return (status);
	}

	if (!is_first_rsp)
		smb_mac_dec_seqnum(sign_ctx);

	if (!smbrdr_sign_chk(sign_ctx,
	    &srh->srh_mbuf, smb_hdr.extra.extra.security_sig)) {
		syslog(LOG_DEBUG, "smbrdr_rcv[%d]: bad signature",
		    srh->srh_cmd);
		return (NT_STATUS_INVALID_NETWORK_RESPONSE);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_exchange
 *
 * Send the SMB packet pointed by the given handle over
 * network. Receive the response and decode the packet header.
 *
 * From "Implementing CIFS" book, SMB requests always have an even sequence
 * number and replies always have an odd.
 *
 * With the original code, if the SMB Redirector skips the counter increment
 * in the event of any failure during SmbSessionSetupAndX, it causes the
 * domain controller to fail the next SMB request(odd sequence number)
 * with ACCESS_DENIED.
 *
 * Returns:
 *
 *	status code returned by smbrdr_hdr_process()
 *	NT_STATUS_INTERNAL_ERROR		crypto framework failure
 *	NT_STATUS_UNEXPECTED_NETWORK_ERROR	send/receive failed
 *	NT_STATUS_SUCCESS			successful
 */
DWORD
smbrdr_exchange(smbrdr_handle_t *srh, smb_hdr_t *smb_hdr, long timeout)
{
	smb_sign_ctx_t *sign_ctx;
	smb_msgbuf_t *mb;
	DWORD status;
	int rc;

	mb = &srh->srh_mbuf;
	sign_ctx = &srh->srh_session->sign_ctx;

	if (smbrdr_sign(sign_ctx, mb) != SMBAUTH_SUCCESS) {
		syslog(LOG_DEBUG, "smbrdr_exchange[%d]: signing failed",
		    srh->srh_cmd);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = nb_exchange(srh->srh_session->sock,
	    srh->srh_buf, smb_msgbuf_used(mb),
	    srh->srh_buf, SMBRDR_REQ_BUFSZ, timeout);

	if (rc < 0) {
		syslog(LOG_DEBUG, "smbrdr_exchange[%d]: failed (%d)",
		    srh->srh_cmd, rc);

		if (srh->srh_cmd != SMB_COM_ECHO) {
			/*
			 * Since SMB echo is used to check the session
			 * status then don't destroy the session if it's
			 * SMB echo.
			 */
			srh->srh_session->state = SDB_SSTATE_STALE;
		}
		smb_mac_inc_seqnum(sign_ctx);
		return (NT_STATUS_UNEXPECTED_NETWORK_ERROR);
	}

	/* initialize for processing response */
	smb_msgbuf_init(mb, srh->srh_buf, rc, srh->srh_mbflags);

	status = smbrdr_hdr_process(srh, smb_hdr);
	if (status != NT_STATUS_SUCCESS) {
		smb_mac_inc_seqnum(sign_ctx);
		return (status);
	}

	/* Signature validation */
	if (!smbrdr_sign_chk(sign_ctx, mb, smb_hdr->extra.extra.security_sig)) {
		syslog(LOG_DEBUG, "smbrdr_exchange[%d]: bad signature",
		    srh->srh_cmd);
		return (NT_STATUS_INVALID_NETWORK_RESPONSE);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_handle_free
 *
 * Frees the memories allocated for the given handle.
 */
void
smbrdr_handle_free(smbrdr_handle_t *srh)
{
	if (srh) {
		smb_msgbuf_term(&srh->srh_mbuf);
		free(srh->srh_buf);
	}
}


/*
 * smbrdr_sign_init
 *
 * This function is called from SessionSetup and initialize the
 * signing context for the session if the connected user isn't
 * anonymous. This has to call before smbrdr_request_init()
 * because it modifies smb_flags2.
 *
 * The following description is taken out from the "Implementing CIFS"
 * book(pg. 304):
 *
 * "Once the MAC signing has been initialized within a session, all
 * messages are numbered using the same counters and signed using
 * the same Session Key.  This is true even if additional SESSION
 * SETUP ANDX exchanges occur."
 *
 * The original SMB packet signing implementation calculates a MAC
 * key each time the SMB Redirector sends the SmbSessionSetupAndx
 * request for any non-anonymous/non-guest user which is not desired
 * whenever there is a change in the user session key.
 *
 * If NTLMv2 authentication is used, the MAC key generated for each
 * SessionSetup is unique. Since the domain controller expects the
 * signature of all incoming requests are signed by the same MAC key
 * (i.e. the one that generated for the first non-anonymous SessionSetup),
 * access denied is returned for any subsequent SmbSessionSetupAndX
 * request.
 */
int
smbrdr_sign_init(struct sdb_session *session, struct sdb_logon *logon)
{
	smb_sign_ctx_t *sign_ctx;
	int rc = 0;

	sign_ctx = &session->sign_ctx;

	if ((sign_ctx->ssc_flags & SMB_SCF_REQUIRED) &&
	    !(sign_ctx->ssc_flags & SMB_SCF_STARTED) &&
	    (logon->type != SDB_LOGON_ANONYMOUS)) {
		if (smb_mac_init(sign_ctx, &logon->auth) != SMBAUTH_SUCCESS)
			return (-1);

		sign_ctx->ssc_flags |=
		    (SMB_SCF_STARTED | SMB_SCF_KEY_ISSET_THIS_LOGON);
		session->smb_flags2 |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE;
		rc = 1;
	}

	return (rc);
}

/*
 * smbrdr_sign_fini
 *
 * Invalidate the MAC key if the first non-anonymous/non-guest user logon
 * fail.
 */
void
smbrdr_sign_fini(struct sdb_session *session)
{
	smb_sign_ctx_t *sign_ctx = &session->sign_ctx;

	if (sign_ctx->ssc_flags & SMB_SCF_KEY_ISSET_THIS_LOGON) {
		sign_ctx->ssc_flags &= ~SMB_SCF_STARTED;
		sign_ctx->ssc_flags &= ~SMB_SCF_KEY_ISSET_THIS_LOGON;
		sign_ctx->ssc_seqnum = 0;
	}
}

/*
 * smbrdr_sign_unset_key
 *
 * The SMB_SCF_KEY_ISSET_THIS_LOGON should be unset upon the successful
 * SmbSessionSetupAndX request for the first non-anonymous/non-guest
 * logon.
 */
void
smbrdr_sign_unset_key(struct sdb_session *session)
{
	smb_sign_ctx_t *sign_ctx = &session->sign_ctx;

	sign_ctx->ssc_flags &= ~SMB_SCF_KEY_ISSET_THIS_LOGON;
}

/*
 * smbrdr_handle_setup
 *
 * Allocates a buffer for sending/receiving a SMB request.
 * Initialize a smb_msgbuf structure with the allocated buffer.
 * Setup given handle (srh) with the specified information.
 *
 * Returns:
 *
 *	NT_STATUS_NO_MEMORY		not enough memory
 *	NT_STATUS_SUCCESS		successful
 */
static DWORD
smbrdr_handle_setup(smbrdr_handle_t *srh,
			unsigned char cmd,
			struct sdb_session *session,
			struct sdb_logon *logon,
			struct sdb_netuse *netuse)
{
	srh->srh_buf = (unsigned char *)malloc(SMBRDR_REQ_BUFSZ);
	if (srh->srh_buf == NULL)
		return (NT_STATUS_NO_MEMORY);

	bzero(srh->srh_buf, SMBRDR_REQ_BUFSZ);

	srh->srh_mbflags = (session->remote_caps & CAP_UNICODE)
	    ? SMB_MSGBUF_UNICODE : 0;

	smb_msgbuf_init(&srh->srh_mbuf, srh->srh_buf,
	    SMBRDR_REQ_BUFSZ, srh->srh_mbflags);

	srh->srh_cmd = cmd;
	srh->srh_session = session;
	srh->srh_user = logon;
	srh->srh_tree = netuse;

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_hdr_setup
 *
 * Build an SMB header based on the information in the given handle.
 * The SMB header is described in section 3.2 of the CIFS spec.
 * As this is a canned function, no error checking is performed here.
 * The return value from smb_msgbuf_encode is simply returned to the caller.
 */
static int
smbrdr_hdr_setup(smbrdr_handle_t *srh)
{
	static unsigned short my_pid = 0;

	if (!my_pid)
		my_pid = getpid();

	return (smb_msgbuf_encode(&srh->srh_mbuf, "Mb4.bw12.wwww",
	    srh->srh_cmd,
	    srh->srh_session->smb_flags,
	    srh->srh_session->smb_flags2,
	    (srh->srh_tree) ? srh->srh_tree->tid : 0,
	    my_pid,
	    (srh->srh_user) ? srh->srh_user->uid : 0,
	    0 /* mid */));
}

/*
 * Canned SMB header decode.
 */
static int
smb_decode_nt_hdr(smb_msgbuf_t *mb, smb_hdr_t *hdr)
{
	return (smb_msgbuf_decode(mb, SMB_HEADER_NT_FMT,
	    &hdr->command,
	    &hdr->status.ntstatus,
	    &hdr->flags,
	    &hdr->flags2,
	    &hdr->pid_high,
	    SMB_SIG_SIZE,
	    &hdr->extra.extra.security_sig,
	    &hdr->tid,
	    &hdr->pid,
	    &hdr->uid,
	    &hdr->mid));
}

/*
 * smbrdr_hdr_process
 *
 * Assuming 'srh->srh_mbuf' contains a response from a Windows client,
 * decodes the 32 bytes SMB header.
 *
 * Buffer overflow typically means that the server has more data than
 * it could fit in the response buffer.  The client can use subsequent
 * SmbReadX requests to obtain the remaining data (KB 193839).
 *
 * Returns:
 *
 *  NT_STATUS_INVALID_NETWORK_RESPONSE	error decoding the header
 *  NT_STATUS_REPLY_MESSAGE_MISMATCH	response doesn't match the request
 *  NT_STATUS_SUCCESS			successful
 *  smb_hdr->status.ntstatus		error returned by server
 */
static DWORD
smbrdr_hdr_process(smbrdr_handle_t *srh, smb_hdr_t *smb_hdr)
{
	int rc;

	rc = smb_decode_nt_hdr(&srh->srh_mbuf, smb_hdr);
	if (rc < SMB_HEADER_LEN) {
		syslog(LOG_DEBUG, "smbrdr[%d]: invalid header (%d)",
		    srh->srh_cmd, rc);
		return (NT_STATUS_INVALID_NETWORK_RESPONSE);
	}

	switch (NT_SC_VALUE(smb_hdr->status.ntstatus)) {
	case NT_STATUS_SUCCESS:
	case NT_STATUS_BUFFER_OVERFLOW:
		break;

	default:
		syslog(LOG_DEBUG, "smbrdr[%d]: request failed (%s)",
		    srh->srh_cmd, xlate_nt_status(smb_hdr->status.ntstatus));
		return (smb_hdr->status.ntstatus);
	}

	if (smb_hdr->command != srh->srh_cmd) {
		syslog(LOG_DEBUG, "smbrdr[%d]: reply mismatch (%d)",
		    srh->srh_cmd, smb_hdr->command);
		return (NT_STATUS_REPLY_MESSAGE_MISMATCH);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smbrdr_sign
 *
 * Signs the given outgoing packet according to the
 * specified signing context.
 *
 * The client and server each maintain an integer counter
 * which they initialize to zero. Both counters are
 * incremented for every SMB message - that's once for a
 * request and once for a reply. As a result, requests sent
 * by SMB Redirector always have an even sequence number
 * and replies from the Windows server always have an odd
 * number.
 *
 * Based on the observed Windows 2003 behavior, any SMB
 * request will fail with NT_STATUS_ACCESS_DENIED if its
 * sequence number is not even.
 *
 * The function can fail if there is trouble with the cryptographic
 * framework and if that happens SMBAUTH_FAILURE is returned.  In the
 * normal case SMBAUTH_SUCCESS is returned.
 */
static int
smbrdr_sign(smb_sign_ctx_t *sign_ctx, smb_msgbuf_t *mb)
{
	if (sign_ctx->ssc_flags & SMB_SCF_STARTED) {
		if (sign_ctx->ssc_seqnum % 2) {
			syslog(LOG_DEBUG, "smbrdr_sign: invalid sequence (%d)",
			    sign_ctx->ssc_seqnum);
		}
		if (smb_mac_sign(sign_ctx, smb_msgbuf_base(mb),
		    smb_msgbuf_used(mb)) != SMBAUTH_SUCCESS)
			return (SMBAUTH_FAILURE);
		sign_ctx->ssc_seqnum++;
	}
	return (SMBAUTH_SUCCESS);
}


/*
 * smbrdr_sign_chk
 *
 * Validates SMB MAC signature in the in-coming message.
 * Return 1 if the signature are match; otherwise, return 0;
 *
 * When packet signing is enabled, the sequence number kept in the
 * sign_ctx structure will be incremented when a SMB request is
 * sent and upon the receipt of the first SmbTransact response
 * if SMB fragmentation occurs.
 */
static int
smbrdr_sign_chk(smb_sign_ctx_t *sign_ctx, smb_msgbuf_t *mb,
		unsigned char *signature)
{
	int sign_ok = 1;

	if (sign_ctx->ssc_flags & SMB_SCF_STARTED) {
		(void) memcpy(sign_ctx->ssc_sign, signature, SMB_SIG_SIZE);
		sign_ok = smb_mac_chk(sign_ctx, smb_msgbuf_base(mb),
		    smb_msgbuf_size(mb));
		sign_ctx->ssc_seqnum++;
	}

	return (sign_ok);
}
