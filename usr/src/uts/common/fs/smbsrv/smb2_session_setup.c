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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_SESSION_SETUP
 *
 * Note that the Capabilities supplied in this request are an inferior
 * subset of those given to us previously in the SMB2 Negotiate request.
 * We need to remember the full set of capabilities from SMB2 Negotiate,
 * and therefore ignore the subset of capabilities supplied here.
 */

#include <smbsrv/smb2_kproto.h>

static void smb2_ss_adjust_credits(smb_request_t *);

smb_sdrc_t
smb2_session_setup(smb_request_t *sr)
{
	smb_arg_sessionsetup_t	*sinfo;
	uint16_t StructureSize;
	uint8_t  Flags;
	uint8_t  SecurityMode;
	uint32_t Capabilities;	/* ignored - see above */
	uint32_t Channel;
	uint16_t SecBufOffset;
	uint16_t SecBufLength;
	uint64_t PrevSessionId;
	uint16_t SessionFlags;
	uint32_t status;
	int skip;
	int rc = 0;

	sinfo = smb_srm_zalloc(sr, sizeof (smb_arg_sessionsetup_t));
	sr->sr_ssetup = sinfo;

	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbbllwwq",
	    &StructureSize,	/* w */
	    &Flags,		/* b */
	    &SecurityMode,	/* b */
	    &Capabilities,	/* l */
	    &Channel,		/* l */
	    &SecBufOffset,	/* w */
	    &SecBufLength,	/* w */
	    &PrevSessionId);	/* q */
	if (rc)
		return (SDRC_ERROR);

	/*
	 * We're normally positioned at the security buffer now,
	 * but there could be some padding before it.
	 */
	skip = (SecBufOffset + sr->smb2_cmd_hdr) -
	    sr->smb_data.chain_offset;
	if (skip < 0)
		return (SDRC_ERROR);
	if (skip > 0)
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);

	/*
	 * Get the security buffer
	 */
	sinfo->ssi_iseclen = SecBufLength;
	sinfo->ssi_isecblob = smb_srm_zalloc(sr, sinfo->ssi_iseclen);
	rc = smb_mbc_decodef(&sr->smb_data, "#c",
	    sinfo->ssi_iseclen, sinfo->ssi_isecblob);
	if (rc)
		return (SDRC_ERROR);

	/*
	 * The real auth. work happens in here.
	 */
	status = smb_authenticate_ext(sr);

	SecBufOffset = SMB2_HDR_SIZE + 8;
	SecBufLength = sinfo->ssi_oseclen;
	SessionFlags = 0;

	switch (status) {

	case NT_STATUS_SUCCESS:	/* Authenticated */
		if (sr->uid_user->u_flags & SMB_USER_FLAG_GUEST)
			SessionFlags |= SMB2_SESSION_FLAG_IS_GUEST;
		if (sr->uid_user->u_flags & SMB_USER_FLAG_ANON)
			SessionFlags |= SMB2_SESSION_FLAG_IS_NULL;
		smb2_ss_adjust_credits(sr);
		break;

	/*
	 * This is not really an error, but tells the client
	 * it should send another session setup request.
	 * Not smb2_put_error because we send a payload.
	 */
	case NT_STATUS_MORE_PROCESSING_REQUIRED:
		sr->smb2_status = status;
		break;

	default:
		SecBufLength = 0;
		sr->smb2_status = status;
		break;
	}

	/*
	 * SMB2 Session Setup reply
	 */

	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wwww#c",
	    9,	/* StructSize */	/* w */
	    SessionFlags,		/* w */
	    SecBufOffset,		/* w */
	    SecBufLength,		/* w */
	    SecBufLength,		/* # */
	    sinfo->ssi_osecblob);	/* c */
	if (rc)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * After a successful authentication, raise s_max_credits up to the
 * normal maximum that clients are allowed to request.  Also, if we
 * haven't yet given them their initial credits, do that now.
 *
 * Normally, clients will request some credits with session setup,
 * but in case they don't request enough to raise s_cur_credits
 * up to the configured initial_credits, increase the requested
 * credits of this SR sufficiently to make that happen.  The actual
 * increase happens in the dispatch code after we return.
 */
static void
smb2_ss_adjust_credits(smb_request_t *sr)
{
	smb_session_t *s = sr->session;

	mutex_enter(&s->s_credits_mutex);
	s->s_max_credits = s->s_cfg.skc_maximum_credits;

	if (s->s_cur_credits < s->s_cfg.skc_initial_credits) {
		uint16_t grant;

		/* How many credits we want to grant with this SR. */
		grant = s->s_cfg.skc_initial_credits - s->s_cur_credits;

		/*
		 * Do we need to increase the smb2_credit_request?
		 * One might prefer to read this expression as:
		 *	((credit_request - credit_charge) < grant)
		 * but we know credit_charge == 1 and would rather not
		 * deal with a possibly negative value on the left,
		 * so adding credit_charge to both sides...
		 */
		if (sr->smb2_credit_request < (grant + 1)) {
			sr->smb2_credit_request = (grant + 1);
		}
	}

	mutex_exit(&s->s_credits_mutex);
}
