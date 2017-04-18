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
 */

/*
 * Dispatch function for SMB2_NEGOTIATE
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2.h>

static int smb2_negotiate_common(smb_request_t *, uint16_t);

uint32_t smb2srv_capabilities =
	SMB2_CAP_DFS |
	SMB2_CAP_LEASING |
	SMB2_CAP_LARGE_MTU |
	SMB2_CAP_ENCRYPTION;

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
 * For now, we're using contiguous allocations, so keep this at 64KB
 * so that (even with message overhead) allocations stay below 128KB,
 * avoiding kmem_alloc -> page_create_va thrashing.
 *
 * smb2_max_trans is the largest "transact" send or receive, which is
 * used for directory listings and info set/get operations.
 */
uint32_t smb2_tcp_bufsize = (1<<22);	/* 4MB */
uint32_t smb2_max_rwsize = (1<<16);	/* 64KB */
uint32_t smb2_max_trans  = (1<<16);	/* 64KB */

/*
 * With clients (e.g. HP scanners) that don't advertise SMB2_CAP_LARGE_MTU
 * (including all clients using dialect < SMB 2.1), use a "conservative" value
 * for max r/w size because some older clients misbehave with larger values.
 * 64KB is recommended in the [MS-SMB2] spec.  (3.3.5.3.1 SMB 2.1 or SMB 3.x
 * Support) as the minimum so we'll use that.
 */
uint32_t smb2_old_rwsize = (1<<16);	/* 64KB */

/*
 * List of all SMB2 versions we implement.  Note that the
 * versions we support may be limited by the
 * _cfg.skc_max_protocol and min_protocol settings.
 */
static uint16_t smb2_versions[] = {
	0x202,	/* SMB 2.002 */
	0x210,	/* SMB 2.1 */
	0x300,	/* SMB 3.0 */
};
static uint16_t smb2_nversions =
    sizeof (smb2_versions) / sizeof (smb2_versions[0]);

static boolean_t
smb2_supported_version(smb_session_t *s, uint16_t version)
{
	int i;

	if (version > s->s_cfg.skc_max_protocol ||
	    version < s->s_cfg.skc_min_protocol)
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
		smb2_version = SMB_VERS_2_002;
		s->dialect = smb2_version;
		s->s_state = SMB_SESSION_STATE_NEGOTIATED;
		/* Allow normal SMB2 requests now. */
		s->newrq_func = smb2sr_newrq;
		break;
	case DIALECT_SMB2XXX:	/* SMB 2.??? (wildcard vers) */
		/*
		 * Expecting an SMB2 negotiate next, so keep the
		 * initial s->newrq_func.
		 */
		smb2_version = 0x2FF;
		break;
	default:
		return (SDRC_DROP_VC);
	}

	/*
	 * Clients that negotiate SMB2 from SMB1 have not yet had the
	 * opportunity to provide us with a secmode. However, any
	 * client that negotiates SMB2 should support signing, so
	 * this should be fiction good enough to pass the signing
	 * check in smb2_negotiate_common(). Even if the client
	 * doesn't support signing and we require it, we'll fail them
	 * later when they fail to sign the packet. For 2.???,
	 * we'll check the real secmode when the 2nd negotiate comes.
	 */
	s->cli_secmode = SMB2_NEGOTIATE_SIGNING_ENABLED;

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
	smb2_send_reply(sr);
	if (rc != 0)
		return (SDRC_DROP_VC);

	/*
	 * We sent the reply, so tell the SMB1 dispatch
	 * it should NOT (also) send a reply.
	 */
	return (SDRC_NO_REPLY);
}

static uint16_t
smb2_find_best_dialect(smb_session_t *s, uint16_t cl_versions[],
    uint16_t version_cnt)
{
	uint16_t best_version = 0;
	int i;

	for (i = 0; i < version_cnt; i++)
		if (smb2_supported_version(s, cl_versions[i]) &&
		    best_version < cl_versions[i])
			best_version = cl_versions[i];

	return (best_version);
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
 *
 * Return value is 0 for success, and anything else will
 * terminate the reader thread (drop the connection).
 */
int
smb2_newrq_negotiate(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	int rc;
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
		return (-1);

	/*
	 * Decode SMB2 Negotiate (fixed-size part)
	 */
	rc = smb_mbc_decodef(
	    &sr->command, "www..l16c8.",
	    &struct_size,	/* w */
	    &version_cnt,	/* w */
	    &s->cli_secmode,	/* w */
	    /* reserved		(..) */
	    &s->capabilities,	/* l */
	    s->clnt_uuid);	/* 16c */
	    /* start_time	  8. */
	if (rc != 0)
		return (rc);
	if (struct_size != 36 || version_cnt > 8)
		return (-1);

	/*
	 * Decode SMB2 Negotiate (variable part)
	 */
	rc = smb_mbc_decodef(&sr->command,
	    "#w", version_cnt, cl_versions);
	if (rc != 0)
		return (rc);

	DTRACE_SMB2_START(op__Negotiate, smb_request_t *, sr);

	/*
	 * The client offers an array of protocol versions it
	 * supports, which we have decoded into cl_versions[].
	 * We walk the array and pick the highest supported.
	 */
	best_version = smb2_find_best_dialect(s, cl_versions, version_cnt);
	if (best_version == 0) {
		cmn_err(CE_NOTE, "clnt %s no supported dialect",
		    sr->session->ip_addr_str);
		sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
		rc = -1;
		goto errout;
	}
	s->dialect = best_version;

	/* Allow normal SMB2 requests now. */
	s->s_state = SMB_SESSION_STATE_NEGOTIATED;
	s->newrq_func = smb2sr_newrq;

	rc = smb2_negotiate_common(sr, best_version);

errout:
	/* sr->smb2_status was set */
	DTRACE_SMB2_DONE(op__Negotiate, smb_request_t *, sr);

	smb2_send_reply(sr);

	return (rc);
}

/*
 * Common parts of SMB2 Negotiate, used for both the
 * SMB1-to-SMB2 style, and straight SMB2 style.
 * Do negotiation decisions and encode the reply.
 * The caller does the network send.
 *
 * Return value is 0 for success, and anything else will
 * terminate the reader thread (drop the connection).
 */
static int
smb2_negotiate_common(smb_request_t *sr, uint16_t version)
{
	timestruc_t boot_tv, now_tv;
	smb_session_t *s = sr->session;
	int rc;
	uint32_t max_rwsize;
	uint16_t secmode;

	sr->smb2_status = 0;

	/*
	 * Negotiation itself.  First the Security Mode.
	 */
	secmode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (sr->sr_cfg->skc_signing_required) {
		secmode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
		/* Make sure client at least enables signing. */
		if ((s->cli_secmode & secmode) == 0) {
			sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
		}
	}
	s->srv_secmode = secmode;

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
		/* smb2_send_reply(sr); in caller */
		return (-1); /* will drop */
	}

	/*
	 * If the version is 0x2FF, we haven't completed negotiate.
	 * Don't initialize until we have our final request.
	 */
	if (version != 0x2FF)
		smb2_sign_init_mech(s);

	/*
	 * [MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request
	 *
	 * Only set CAP_ENCRYPTION if this is 3.0 or 3.0.2 and
	 * the client has it set.
	 */

	if (s->dialect < SMB_VERS_3_0 ||
	    !SMB3_CLIENT_ENCRYPTS(sr) ||
	    smb3_encrypt_init_mech(s) != 0)
		s->srv_cap = smb2srv_capabilities & ~SMB2_CAP_ENCRYPTION;
	else
		s->srv_cap = smb2srv_capabilities;

	/*
	 * See notes above smb2_max_rwsize, smb2_old_rwsize
	 */
	if (s->capabilities & SMB2_CAP_LARGE_MTU)
		max_rwsize = smb2_max_rwsize;
	else
		max_rwsize = smb2_old_rwsize;

	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wwww#cllllTTwwl#c",
	    65,	/* StructSize */	/* w */
	    s->srv_secmode,		/* w */
	    version,			/* w */
	    0, /* reserved */		/* w */
	    UUID_LEN,			/* # */
	    &s->s_cfg.skc_machine_uuid, /* c */
	    s->srv_cap,			/* l */
	    smb2_max_trans,		/* l */
	    max_rwsize,			/* l */
	    max_rwsize,			/* l */
	    &now_tv,			/* T */
	    &boot_tv,			/* T */
	    128, /* SecBufOff */	/* w */
	    sr->sr_cfg->skc_negtok_len,	/* w */
	    0,	/* reserved */		/* l */
	    sr->sr_cfg->skc_negtok_len,	/* # */
	    sr->sr_cfg->skc_negtok);	/* c */

	/* smb2_send_reply(sr); in caller */

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
smb2_nego_validate(smb_request_t *sr, smb_fsctl_t *fsctl)
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

	/* dialects[8] taken from cl_versions[8] in smb2_newrq_negotiate */
	uint32_t capabilities;
	uint16_t secmode, num_dialects, dialects[8];
	uint8_t clnt_guid[16];

	if (fsctl->InputCount < 24)
		goto drop;

	(void) smb_mbc_decodef(fsctl->in_mbc, "l16cww",
	    &capabilities, /* l */
	    &clnt_guid, /* 16c */
	    &secmode, /* w */
	    &num_dialects); /* w */

	if (num_dialects == 0 || num_dialects > 8)
		goto drop;
	if (secmode != s->cli_secmode)
		goto drop;
	if (capabilities != s->capabilities)
		goto drop;
	if (memcmp(clnt_guid, s->clnt_uuid, sizeof (clnt_guid)) != 0)
		goto drop;

	if (fsctl->InputCount < (24 + num_dialects * sizeof (*dialects)))
		goto drop;

	rc = smb_mbc_decodef(fsctl->in_mbc, "#w", num_dialects, dialects);
	if (rc != 0)
		goto drop;

	if (smb2_find_best_dialect(s, dialects, num_dialects) != s->dialect)
		goto drop;

	rc = smb_mbc_encodef(
	    fsctl->out_mbc, "l#cww",
	    s->srv_cap,			/* l */
	    UUID_LEN,			/* # */
	    &s->s_cfg.skc_machine_uuid, /* c */
	    s->srv_secmode,		/* w */
	    s->dialect);		/* w */
	if (rc == 0)
		return (rc);

drop:
	smb_session_disconnect(s);
	return (NT_STATUS_ACCESS_DENIED);
}
