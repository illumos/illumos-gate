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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_NEGOTIATE
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2.h>

static int smb2_negotiate_common(smb_request_t *, uint16_t);

uint32_t smb2srv_capabilities =
	SMB2_CAP_DFS |
	SMB2_CAP_LARGE_MTU;

/*
 * These are not intended as customer tunables, but dev. & test folks
 * might want to adjust them (with caution).
 *
 * smb2_tcp_bufsize is the TCP buffer size, applied to the network socket
 * with setsockopt SO_SNDBUF, SO_RCVBUF.  These set the TCP window size.
 * This is also used as a "sanity limit" for internal send/reply message
 * allocations.  Note that with compounding SMB2 messages may contain
 * multiple requests/responses.  This size should be large enough for
 * at least a few SMB2 requests, and at least 2X smb2_max_rwsize.
 *
 * smb2_max_rwsize is what we put in the SMB2 negotiate response to tell
 * the client the largest read and write request size we'll support.
 * One megabyte is a compromise between efficiency on fast networks
 * and memory consumption (for the buffers) on the server side.
 *
 * smb2_max_trans is the largest "transact" send or receive, which is
 * used for directory listings and info set/get operations.
 */
uint32_t smb2_tcp_bufsize = (1<<22);	/* 4MB */
uint32_t smb2_max_rwsize = (1<<20);	/* 1MB */
uint32_t smb2_max_trans  = (1<<16);	/* 64KB */

/*
 * List of all SMB2 versions we implement.  Note that the
 * highest version we support may be limited by the
 * _cfg.skc_max_protocol setting.
 */
static uint16_t smb2_versions[] = {
	0x202,	/* SMB 2.002 */
	0x210,	/* SMB 2.1 */
};
static uint16_t smb2_nversions =
    sizeof (smb2_versions) / sizeof (smb2_versions[0]);

static boolean_t
smb2_supported_version(smb_session_t *s, uint16_t version)
{
	int i;

	if (version > s->s_cfg.skc_max_protocol)
		return (B_FALSE);
	for (i = 0; i < smb2_nversions; i++)
		if (version == smb2_versions[i])
			return (B_TRUE);
	return (B_FALSE);
}

/*
 * Helper for the (SMB1) smb_com_negotiate().  This is the
 * very unusual protocol interaction where an SMB1 negotiate
 * gets an SMB2 negotiate response.  This is the normal way
 * clients first find out if the server supports SMB2.
 *
 * Note: This sends an SMB2 reply _itself_ and then returns
 * SDRC_NO_REPLY so the caller will not send an SMB1 reply.
 * Also, this is called directly from the reader thread, so
 * we know this is the only thread using this session.
 *
 * The caller frees this request.
 */
smb_sdrc_t
smb1_negotiate_smb2(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	smb_arg_negotiate_t *negprot = sr->sr_negprot;
	uint16_t smb2_version;
	uint16_t secmode2;
	int rc;

	/*
	 * Note: In the SMB1 negotiate command handler, we
	 * agreed with one of the SMB2 dialects.  If that
	 * dialect was "SMB 2.002", we'll respond here with
	 * version 0x202 and negotiation is done.  If that
	 * dialect was "SMB 2.???", we'll respond here with
	 * the "wildcard" version 0x2FF, and the client will
	 * come back with an SMB2 negotiate.
	 */
	switch (negprot->ni_dialect) {
	case DIALECT_SMB2002:	/* SMB 2.002 (a.k.a. SMB2.0) */
		smb2_version = 0x202;
		s->dialect = smb2_version;
		s->s_state = SMB_SESSION_STATE_NEGOTIATED;
		/* Allow normal SMB2 requests now. */
		s->newrq_func = smb2sr_newrq;

		/*
		 * Translate SMB1 sec. mode to SMB2.
		 */
		secmode2 = 0;
		if (s->secmode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)
			secmode2 |= SMB2_NEGOTIATE_SIGNING_ENABLED;
		if (s->secmode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED)
			secmode2 |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
		s->secmode = secmode2;
		break;
	case DIALECT_SMB2XXX:	/* SMB 2.??? (wildcard vers) */
		/*
		 * Expecting an SMB2 negotiate next, so keep the
		 * initial s->newrq_func.  Note that secmode is
		 * fiction good enough to pass the signing check
		 * in smb2_negotiate_common().  We'll check the
		 * real secmode when the 2nd negotiate comes.
		 */
		smb2_version = 0x2FF;
		s->secmode = SMB2_NEGOTIATE_SIGNING_ENABLED;
		break;
	default:
		return (SDRC_DROP_VC);
	}

	/*
	 * We did not decode an SMB2 header, so make sure
	 * the SMB2 header fields are initialized.
	 * (Most are zero from smb_request_alloc.)
	 * Also, the SMB1 common dispatch code reserved space
	 * for an SMB1 header, which we need to undo here.
	 */
	sr->smb2_reply_hdr = sr->reply.chain_offset = 0;
	sr->smb2_cmd_code = SMB2_NEGOTIATE;

	rc = smb2_negotiate_common(sr, smb2_version);
	if (rc != 0)
		return (SDRC_DROP_VC);

	return (SDRC_NO_REPLY);
}

/*
 * SMB2 Negotiate gets special handling.  This is called directly by
 * the reader thread (see smbsr_newrq_initial) with what _should_ be
 * an SMB2 Negotiate.  Only the "\feSMB" header has been checked
 * when this is called, so this needs to check the SMB command,
 * if it's Negotiate execute it, then send the reply, etc.
 *
 * Since this is called directly from the reader thread, we
 * know this is the only thread currently using this session.
 * This has to duplicate some of what smb2sr_work does as a
 * result of bypassing the normal dispatch mechanism.
 *
 * The caller always frees this request.
 */
int
smb2_newrq_negotiate(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	int i, rc;
	uint16_t struct_size;
	uint16_t best_version;
	uint16_t version_cnt;
	uint16_t cl_versions[8];

	sr->smb2_cmd_hdr = sr->command.chain_offset;
	rc = smb2_decode_header(sr);
	if (rc != 0)
		return (rc);

	if ((sr->smb2_cmd_code != SMB2_NEGOTIATE) ||
	    (sr->smb2_next_command != 0))
		return (SDRC_DROP_VC);

	/*
	 * Decode SMB2 Negotiate (fixed-size part)
	 */
	rc = smb_mbc_decodef(
	    &sr->command, "www..l16.8.",
	    &struct_size,	/* w */
	    &version_cnt,	/* w */
	    &s->secmode,	/* w */
	    /* reserved 	(..) */
	    &s->capabilities);	/* l */
	    /* clnt_uuid	 16. */
	    /* start_time	  8. */
	if (rc != 0)
		return (rc);
	if (struct_size != 36 || version_cnt > 8)
		return (SDRC_DROP_VC);

	/*
	 * Decode SMB2 Negotiate (variable part)
	 */
	rc = smb_mbc_decodef(&sr->command,
	    "#w", version_cnt, cl_versions);
	if (rc != 0)
		return (SDRC_DROP_VC);

	/*
	 * The client offers an array of protocol versions it
	 * supports, which we have decoded into cl_versions[].
	 * We walk the array and pick the highest supported.
	 */
	best_version = 0;
	for (i = 0; i < version_cnt; i++)
		if (smb2_supported_version(s, cl_versions[i]) &&
		    best_version < cl_versions[i])
			best_version = cl_versions[i];
	if (best_version == 0)
		return (SDRC_DROP_VC);
	s->dialect = best_version;

	/* Allow normal SMB2 requests now. */
	s->s_state = SMB_SESSION_STATE_NEGOTIATED;
	s->newrq_func = smb2sr_newrq;

	rc = smb2_negotiate_common(sr, best_version);
	if (rc != 0)
		return (SDRC_DROP_VC);

	return (0);
}

/*
 * Common parts of SMB2 Negotiate, used for both the
 * SMB1-to-SMB2 style, and straight SMB2 style.
 * Do negotiation decisions, encode, send the reply.
 */
static int
smb2_negotiate_common(smb_request_t *sr, uint16_t version)
{
	timestruc_t boot_tv, now_tv;
	smb_session_t *s = sr->session;
	int rc;
	uint16_t secmode;

	sr->smb2_status = 0;

	/*
	 * Negotiation itself.  First the Security Mode.
	 * The caller stashed the client's secmode in s->secmode,
	 * which we validate, and then replace with the server's
	 * secmode, which is all we care about after this.
	 */
	secmode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (sr->sr_cfg->skc_signing_required) {
		secmode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
		/* Make sure client at least enables signing. */
		if ((s->secmode & secmode) == 0) {
			sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
		}
	}
	s->secmode = secmode;

	s->cmd_max_bytes = smb2_tcp_bufsize;
	s->reply_max_bytes = smb2_tcp_bufsize;

	/*
	 * "The number of credits held by the client MUST be considered
	 * as 1 when the connection is established." [MS-SMB2]
	 * We leave credits at 1 until the first successful
	 * session setup is completed.
	 */
	s->s_cur_credits = s->s_max_credits = 1;
	sr->smb2_credit_response = 1;

	boot_tv.tv_sec = smb_get_boottime();
	boot_tv.tv_nsec = 0;
	now_tv.tv_sec = gethrestime_sec();
	now_tv.tv_nsec = 0;

	/*
	 * SMB2 negotiate reply
	 */
	sr->smb2_hdr_flags = SMB2_FLAGS_SERVER_TO_REDIR;
	(void) smb2_encode_header(sr, B_FALSE);
	if (sr->smb2_status != 0) {
		smb2sr_put_error(sr, sr->smb2_status);
		smb2_send_reply(sr);
		return (-1); /* will drop */
	}

	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wwww#cllllTTwwl#c",
	    65,	/* StructSize */	/* w */
	    s->secmode,			/* w */
	    version,			/* w */
	    0, /* reserved */		/* w */
	    UUID_LEN,			/* # */
	    &s->s_cfg.skc_machine_uuid, /* c */
	    smb2srv_capabilities,	/* l */
	    smb2_max_trans,		/* l */
	    smb2_max_rwsize,		/* l */
	    smb2_max_rwsize,		/* l */
	    &now_tv,			/* T */
	    &boot_tv,			/* T */
	    128, /* SecBufOff */	/* w */
	    sr->sr_cfg->skc_negtok_len,	/* w */
	    0,	/* reserved */		/* l */
	    sr->sr_cfg->skc_negtok_len,	/* # */
	    sr->sr_cfg->skc_negtok);	/* c */

	smb2_send_reply(sr);

	(void) ksocket_setsockopt(s->sock, SOL_SOCKET,
	    SO_SNDBUF, (const void *)&smb2_tcp_bufsize,
	    sizeof (smb2_tcp_bufsize), CRED());
	(void) ksocket_setsockopt(s->sock, SOL_SOCKET,
	    SO_RCVBUF, (const void *)&smb2_tcp_bufsize,
	    sizeof (smb2_tcp_bufsize), CRED());

	return (rc);
}

/*
 * SMB2 Dispatch table handler, which will run if we see an
 * SMB2_NEGOTIATE after the initial negotiation is done.
 * That would be a protocol error.
 */
smb_sdrc_t
smb2_negotiate(smb_request_t *sr)
{
	sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
	return (SDRC_ERROR);
}

/*
 * VALIDATE_NEGOTIATE_INFO [MS-SMB2] 2.2.32.6
 */
uint32_t
smb2_fsctl_vneginfo(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_session_t *s = sr->session;
	int rc;

	/*
	 * The spec. says to parse the VALIDATE_NEGOTIATE_INFO here
	 * and verify that the original negotiate was not modified.
	 * The only tampering we need worry about is secmode, and
	 * we're not taking that from the client, so don't bother.
	 *
	 * One interesting requirement here is that we MUST reply
	 * with exactly the same information as we returned in our
	 * original reply to the SMB2 negotiate on this session.
	 * If we don't the client closes the connection.
	 */

	rc = smb_mbc_encodef(
	    fsctl->out_mbc, "l#cww",
	    smb2srv_capabilities,	/* l */
	    UUID_LEN,			/* # */
	    &s->s_cfg.skc_machine_uuid, /* c */
	    s->secmode,			/* w */
	    s->dialect);		/* w */
	if (rc)
		return (NT_STATUS_INTERNAL_ERROR);

	return (0);
}
