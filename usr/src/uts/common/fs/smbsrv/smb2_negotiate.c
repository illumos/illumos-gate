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
 * Copyright 2013-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_NEGOTIATE
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb2.h>
#include <sys/random.h>

/*
 * Note from [MS-SMB2] Sec. 2.2.3:  Windows servers return
 * invalid parameter if the dialect count is greater than 64
 * This is here (and not in smb2.h) because this is technically
 * an implementation detail, not protocol specification.
 */
#define	SMB2_NEGOTIATE_MAX_DIALECTS	64

static int smb2_negotiate_common(smb_request_t *, uint16_t);

/* List of supported capabilities.  Can be patched for testing. */
uint32_t smb2srv_capabilities =
	SMB2_CAP_DFS |
	SMB2_CAP_LEASING |
	SMB2_CAP_LARGE_MTU |
	SMB2_CAP_PERSISTENT_HANDLES |
	SMB2_CAP_ENCRYPTION;

/* These are the only capabilities defined for SMB2.X */
#define	SMB_2X_CAPS (SMB2_CAP_DFS | SMB2_CAP_LEASING | SMB2_CAP_LARGE_MTU)

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
	0x302,	/* SMB 3.02 */
	0x311,	/* SMB 3.11 */
};
static uint16_t smb2_nversions =
    sizeof (smb2_versions) / sizeof (smb2_versions[0]);

enum smb2_neg_ctx_type {
	SMB2_PREAUTH_INTEGRITY_CAPS		= 1,
	SMB2_ENCRYPTION_CAPS			= 2,
	SMB2_COMPRESSION_CAPS			= 3,	/* not imlemented */
	SMB2_NETNAME_NEGOTIATE_CONTEXT_ID	= 5	/* not imlemented */
};

typedef struct smb2_negotiate_ctx {
	uint16_t	type;
	uint16_t	datalen;
} smb2_neg_ctx_t;

#define	SMB31_PREAUTH_CTX_SALT_LEN	32

/*
 * SMB 3.1.1 originally specified a single hashing algorithm - SHA-512 - and
 * two encryption ones - AES-128-CCM and AES-128-GCM.
 * Windows Server 2022 and Windows 11 introduced two further encryption
 * algorithms - AES-256-CCM and AES-256-GCM.
 */
#define	MAX_HASHID_NUM	(1)
#define	MAX_CIPHER_NUM	(8)

typedef struct smb2_preauth_integrity_caps {
	uint16_t	picap_hash_count;
	uint16_t	picap_salt_len;
	uint16_t	picap_hash_id;
	uint8_t		picap_salt[SMB31_PREAUTH_CTX_SALT_LEN];
} smb2_preauth_caps_t;

typedef struct smb2_encryption_caps {
	uint16_t	encap_cipher_count;
	uint16_t	encap_cipher_ids[MAX_CIPHER_NUM];
} smb2_encrypt_caps_t;

/*
 * The contexts we support
 */
typedef struct smb2_preauth_neg_ctx {
	smb2_neg_ctx_t		neg_ctx;
	smb2_preauth_caps_t	preauth_caps;
} smb2_preauth_neg_ctx_t;

typedef struct smb2_encrypt_neg_ctx {
	smb2_neg_ctx_t		neg_ctx;
	smb2_encrypt_caps_t	encrypt_caps;
} smb2_encrypt_neg_ctx_t;

typedef struct smb2_neg_ctxs {
	uint32_t		offset;
	uint16_t		count;
	smb2_preauth_neg_ctx_t	preauth_ctx;
	smb2_encrypt_neg_ctx_t	encrypt_ctx;
} smb2_neg_ctxs_t;

#define	NEG_CTX_INFO_OFFSET	(SMB2_HDR_SIZE + 28)
#define	NEG_CTX_OFFSET_OFFSET	(SMB2_HDR_SIZE + 64)
#define	NEG_CTX_MAX_COUNT	(16)
#define	NEG_CTX_MAX_DATALEN	(256)

#define	STATUS_SMB_NO_PREAUTH_INEGRITY_HASH_OVERLAP	(0xC05D0000)

#define	STATUS_PREAUTH_HASH_OVERLAP \
    STATUS_SMB_NO_PREAUTH_INEGRITY_HASH_OVERLAP

typedef struct smb2_arg_negotiate {
	struct smb2_neg_ctxs	neg_in_ctxs;
	struct smb2_neg_ctxs	neg_out_ctxs;
	uint16_t		neg_dialect_cnt;
	uint16_t		neg_dialects[SMB2_NEGOTIATE_MAX_DIALECTS];
	uint16_t		neg_highest_dialect;
} smb2_arg_negotiate_t;


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
 * This function should be called only for dialect >= 0x311
 * Negotiate context list should contain exactly one
 * SMB2_PREAUTH_INTEGRITY_CAPS context.
 * Otherwise STATUS_INVALID_PARAMETER.
 * It should contain at least 1 hash algorith what server does support.
 * Otehrwise STATUS_SMB_NO_PREAUTH_INEGRITY_HASH_OVERLAP.
 */
static uint32_t
smb31_decode_neg_ctxs(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	smb2_arg_negotiate_t *nego = sr->arg.other;
	smb2_neg_ctxs_t *neg_ctxs = &nego->neg_in_ctxs;
	smb2_preauth_caps_t *picap = &neg_ctxs->preauth_ctx.preauth_caps;
	smb2_encrypt_caps_t *encap = &neg_ctxs->encrypt_ctx.encrypt_caps;
	boolean_t found_sha512 = B_FALSE;
	boolean_t found_cipher = B_FALSE;
	uint32_t ciphers = sr->sr_server->sv_cfg.skc_encrypt_ciphers;
	uint32_t status = 0;
	int32_t skip;
	int found_preauth_ctx = 0;
	int found_encrypt_ctx = 0;
	int cnt, i;
	int rc;

	/*
	 * There should be exactly 1 SMB2_PREAUTH_INTEGRITY_CAPS negotiate ctx.
	 * SMB2_ENCRYPTION_CAPS is optional one.
	 * If there is no contexts or there are to many then stop parsing.
	 */
	cnt = neg_ctxs->count;
	if (cnt < 1 || cnt > NEG_CTX_MAX_COUNT) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * Cannot proceed parsing if the first context isn't aligned by 8.
	 */
	if (neg_ctxs->offset % 8 != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	if ((skip = neg_ctxs->offset - sr->command.chain_offset) != 0 &&
	    smb_mbc_decodef(&sr->command, "#.", skip) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * Parse negotiate contexts. Ignore non-decoding errors to fill
	 * as much as possible data for dtrace probe.
	 */
	for (i = 0; i < cnt; i++) {
		smb2_neg_ctx_t neg_ctx;
		int32_t ctx_end_off;
		int32_t ctx_next_off;

		if (i > 0) {
			if ((skip = ctx_next_off - ctx_end_off) != 0 &&
			    smb_mbc_decodef(&sr->command, "#.", skip) != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}
		}

		rc = smb_mbc_decodef(
		    &sr->command, "ww4.",
		    &neg_ctx.type,	/* w */
		    &neg_ctx.datalen);	/* w */
		if (rc != 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}

		/*
		 * We got something crazy
		 */
		if (neg_ctx.datalen > NEG_CTX_MAX_DATALEN) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}

		ctx_end_off = sr->command.chain_offset + neg_ctx.datalen;
		ctx_next_off = P2ROUNDUP(ctx_end_off, 8);

		switch (neg_ctx.type) {
		case SMB2_PREAUTH_INTEGRITY_CAPS:
			memcpy(&neg_ctxs->preauth_ctx.neg_ctx, &neg_ctx,
			    sizeof (neg_ctx));

			if (found_preauth_ctx++ != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				continue;
			}

			rc = smb_mbc_decodef(
			    &sr->command, "ww",
			    &picap->picap_hash_count,	/* w */
			    &picap->picap_salt_len);	/* w */
			if (rc != 0 || picap->picap_hash_count >
			    MAX_HASHID_NUM) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}

			/*
			 * Get hash id
			 */
			rc = smb_mbc_decodef(
			    &sr->command, "#w",
			    picap->picap_hash_count,
			    &picap->picap_hash_id);	/* w */
			if (rc != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}

			/*
			 * Get salt
			 */
			rc = smb_mbc_decodef(
			    &sr->command, "#c",
			    sizeof (picap->picap_salt),
			    &picap->picap_salt[0]);	/* w */
			if (rc != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}

			/*
			 * In SMB 0x311 there should be exactly 1 preauth
			 * negotiate context, and there should be exactly 1
			 * hash value in the list - SHA512.
			 */
			if (picap->picap_hash_count != 1) {
				status = NT_STATUS_INVALID_PARAMETER;
				continue;
			}

			if (picap->picap_hash_id == SMB3_HASH_SHA512)
				found_sha512 = B_TRUE;
			break;
		case SMB2_ENCRYPTION_CAPS:
			memcpy(&neg_ctxs->preauth_ctx.neg_ctx, &neg_ctx,
			    sizeof (neg_ctx));

			if (found_encrypt_ctx++ != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				continue;
			}

			rc = smb_mbc_decodef(
			    &sr->command, "w",
			    &encap->encap_cipher_count);	/* w */
			if (rc != 0 || encap->encap_cipher_count >
			    MAX_CIPHER_NUM) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}

			/*
			 * Get cipher list
			 */
			rc = smb_mbc_decodef(
			    &sr->command, "#w",
			    encap->encap_cipher_count,
			    &encap->encap_cipher_ids[0]);	/* w */
			if (rc != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}

			/*
			 * Select the first enabled cipher.
			 * Client should list more prioritized ciphers first.
			 */
			for (int k = 0; k < encap->encap_cipher_count; k++) {
				uint16_t c = encap->encap_cipher_ids[k];

				if (c <= SMB3_CIPHER_MAX &&
				    (SMB3_CIPHER_BIT(c) & ciphers) != 0) {
					s->smb31_enc_cipherid = c;
					found_cipher = B_TRUE;
					break;
				}
			}
			break;
		default:
			;
		}
	}

	if (status)
		goto errout;

	/* Not found mandatory SMB2_PREAUTH_INTEGRITY_CAPS ctx */
	if (found_preauth_ctx != 1 || found_encrypt_ctx > 1) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	if (!found_sha512) {
		status = STATUS_PREAUTH_HASH_OVERLAP;
		goto errout;
	}

	s->smb31_preauth_hashid = SMB3_HASH_SHA512;

	if (!found_cipher)
		s->smb31_enc_cipherid = 0;

	/* Initialize out = in */
	nego->neg_out_ctxs = nego->neg_in_ctxs;

errout:
	return (status);
}

static int
smb31_encode_neg_ctxs(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	smb2_arg_negotiate_t *nego = sr->arg.other;
	smb2_neg_ctxs_t *neg_ctxs = &nego->neg_out_ctxs;
	smb2_preauth_caps_t *picap = &neg_ctxs->preauth_ctx.preauth_caps;
	smb2_encrypt_caps_t *encap = &neg_ctxs->encrypt_ctx.encrypt_caps;
	uint16_t salt_len = sizeof (picap->picap_salt);
	uint32_t preauth_ctx_len = 6 + salt_len;
	uint32_t enc_ctx_len = 4;
	uint32_t neg_ctx_off = NEG_CTX_OFFSET_OFFSET +
	    P2ROUNDUP(sr->sr_cfg->skc_negtok_len, 8);
	uint32_t rc;

	if ((rc = smb_mbc_put_align(&sr->reply, 8)) != 0)
		return (rc);

	ASSERT3S(neg_ctx_off, ==, sr->reply.chain_offset);

	picap->picap_hash_id = s->smb31_preauth_hashid;
	picap->picap_salt_len = salt_len;

	(void) random_get_pseudo_bytes(picap->picap_salt, salt_len);

	rc = smb_mbc_encodef(
	    &sr->reply, "ww4.",
	    SMB2_PREAUTH_INTEGRITY_CAPS,
	    preauth_ctx_len
	    /* 4. */); /* reserved */
	if (rc != 0)
		return (rc);

	rc = smb_mbc_encodef(
	    &sr->reply, "www#c",
	    1,				/* hash algo count */
	    salt_len,			/* salt length */
	    s->smb31_preauth_hashid,	/* hash id */
	    salt_len,			/* salt length */
	    picap->picap_salt);
	if (rc != 0)
		return (rc);

	/*
	 * If we did not get SMB2_ENCRYPTION_CAPS, don't send one.
	 */
	if (encap->encap_cipher_count == 0)
		return (0);

	/*
	 * Encode SMB2_ENCRYPTION_CAPS response.
	 */
	if ((rc = smb_mbc_put_align(&sr->reply, 8)) != 0)
		return (rc);

	rc = smb_mbc_encodef(
	    &sr->reply, "ww4.",
	    SMB2_ENCRYPTION_CAPS,
	    enc_ctx_len
	    /* 4. */); /* reserved */

	rc = smb_mbc_encodef(
	    &sr->reply, "ww",
	    1,				/* cipher count */
	    s->smb31_enc_cipherid);	/* encrypt. cipher id */

	return (rc);
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
 * Otherwise, this is similar to smb2_newrq_negotiate().
 *
 * The caller frees this request.
 */
smb_sdrc_t
smb1_negotiate_smb2(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	smb_arg_negotiate_t *negprot = sr->sr_negprot;
	uint16_t smb2_version;

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
	 * We did not decode an SMB2 header, so make sure
	 * the SMB2 header fields are initialized.
	 * (Most are zero from smb_request_alloc.)
	 * Also, the SMB1 common dispatch code reserved space
	 * for an SMB1 header, which we need to undo here.
	 */
	sr->smb2_reply_hdr = sr->reply.chain_offset = 0;
	sr->smb2_cmd_code = SMB2_NEGOTIATE;
	sr->smb2_hdr_flags = SMB2_FLAGS_SERVER_TO_REDIR;

	/*
	 * Also setup SMB2 negotiate args (empty here).
	 * SMB1 args free'd by smb_srm_fini(sr)
	 */
	sr->arg.other = smb_srm_zalloc(sr, sizeof (smb2_arg_negotiate_t));

	(void) smb2_encode_header(sr, B_FALSE);
	if (smb2_negotiate_common(sr, smb2_version) != 0)
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;
	if (sr->smb2_status != 0)
		smb2sr_put_error(sr, sr->smb2_status);
	(void) smb2_encode_header(sr, B_TRUE);

	smb2_send_reply(sr);

	/*
	 * We sent the reply, so tell the SMB1 dispatch
	 * it should NOT (also) send a reply.
	 */
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
 *
 * Return value is 0 for success, and anything else will
 * terminate the reader thread (drop the connection).
 */
int
smb2_newrq_negotiate(smb_request_t *sr)
{
	smb_session_t *s = sr->session;
	smb2_arg_negotiate_t *nego;
	int rc;
	uint32_t nctx_status = 0;
	uint32_t status = 0;
	uint32_t neg_ctx_off;
	uint16_t neg_ctx_cnt;
	uint16_t struct_size;
	uint16_t dialect_cnt;
	uint16_t best_version;

	nego = smb_srm_zalloc(sr, sizeof (smb2_arg_negotiate_t));
	sr->arg.other = nego;	// for dtrace

	sr->smb2_cmd_hdr = sr->command.chain_offset;
	rc = smb2_decode_header(sr);
	if (rc != 0)
		return (rc);

	if (sr->smb2_hdr_flags & SMB2_FLAGS_SERVER_TO_REDIR)
		return (-1);

	if ((sr->smb2_cmd_code != SMB2_NEGOTIATE) ||
	    (sr->smb2_next_command != 0))
		return (-1);

	/*
	 * Decode SMB2 Negotiate (fixed-size part)
	 */
	rc = smb_mbc_decodef(
	    &sr->command, "www..l16clw..",
	    &struct_size,	/* w */
	    &dialect_cnt,	/* w */
	    &s->cli_secmode,	/* w */
	    /* reserved		(..) */
	    &s->capabilities,	/* l */
	    s->clnt_uuid,	/* 16c */
	    &neg_ctx_off,	/* l */
	    &neg_ctx_cnt);	/* w */
	    /* reserverd	(..) */
	if (rc != 0)
		return (rc);
	if (struct_size != 36)
		return (-1);

	/*
	 * Decode SMB2 Negotiate (variable part)
	 *
	 * Be somewhat tolerant while decoding the variable part
	 * so we can return errors instead of dropping the client.
	 * Will limit decoding to the size of cli_dialects here,
	 * and do error checks on the decoded dialect_cnt after the
	 * dtrace start probe.
	 */
	if (dialect_cnt > SMB2_NEGOTIATE_MAX_DIALECTS)
		nego->neg_dialect_cnt = SMB2_NEGOTIATE_MAX_DIALECTS;
	else
		nego->neg_dialect_cnt = dialect_cnt;
	if (nego->neg_dialect_cnt > 0) {
		rc = smb_mbc_decodef(&sr->command, "#w",
		    nego->neg_dialect_cnt,
		    nego->neg_dialects);
		if (rc != 0)
			return (rc);	// short msg
	}

	best_version = smb2_find_best_dialect(s, nego->neg_dialects,
	    nego->neg_dialect_cnt);

	if (best_version >= SMB_VERS_3_11) {
		nego->neg_in_ctxs.offset = neg_ctx_off;
		nego->neg_in_ctxs.count  = neg_ctx_cnt;
		nctx_status = smb31_decode_neg_ctxs(sr);
		/* check nctx_status below */
	}

	DTRACE_SMB2_START(op__Negotiate, smb_request_t *, sr);

	sr->smb2_credit_response = 1;
	sr->smb2_hdr_flags |= SMB2_FLAGS_SERVER_TO_REDIR;
	(void) smb2_encode_header(sr, B_FALSE);

	/*
	 * NOW start validating things (NOT before here)
	 */

	/*
	 * [MS-SMB2] 3.3.5.2.4 Verifying the Signature
	 * "If the SMB2 header of the SMB2 NEGOTIATE request has the
	 * SMB2_FLAGS_SIGNED bit set in the Flags field, the server
	 * MUST fail the request with STATUS_INVALID_PARAMETER."
	 */
	if ((sr->smb2_hdr_flags & SMB2_FLAGS_SIGNED) != 0) {
		sr->smb2_hdr_flags &= ~SMB2_FLAGS_SIGNED;
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * [MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request
	 * "If the DialectCount of the SMB2 NEGOTIATE Request is 0, the
	 * server MUST fail the request with STATUS_INVALID_PARAMETER."
	 * Checking the decoded value here, not the constrained one.
	 */
	if (dialect_cnt == 0 ||
	    dialect_cnt > SMB2_NEGOTIATE_MAX_DIALECTS) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * We decoded the offered dialects above, and
	 * determined which was the highest we support.
	 *
	 * [MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request
	 * "If a common dialect is not found, the server MUST fail
	 * the request with STATUS_NOT_SUPPORTED."
	 */
	if (best_version == 0) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto errout;
	}

	/*
	 * Check for problems with the negotiate contexts.
	 */
	if (nctx_status != 0) {
		status = nctx_status;
		goto errout;
	}

	/* Allow normal SMB2 requests now. */
	s->dialect = best_version;
	s->s_state = SMB_SESSION_STATE_NEGOTIATED;
	s->newrq_func = smb2sr_newrq;

	if (smb2_negotiate_common(sr, best_version) != 0)
		status = NT_STATUS_INTERNAL_ERROR;

	if (s->dialect >= SMB_VERS_3_11 && status == 0) {
		if (smb31_encode_neg_ctxs(sr) != 0)
			status = NT_STATUS_INTERNAL_ERROR;
	}

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Negotiate, smb_request_t *, sr);

	if (sr->smb2_status != 0)
		smb2sr_put_error(sr, sr->smb2_status);
	(void) smb2_encode_header(sr, B_TRUE);

	if (s->dialect >= SMB_VERS_3_11 && sr->smb2_status == 0) {
		ASSERT3U(s->smb31_preauth_hashid, !=, 0);
		if (smb31_preauth_sha512_calc(sr, &sr->reply,
		    s->smb31_preauth_hashval,
		    s->smb31_preauth_hashval) != 0)
			cmn_err(CE_WARN, "(1) Preauth hash calculation "
			    "failed");
	}

	smb2_send_reply(sr);

	return (rc);
}

/*
 * Common parts of SMB2 Negotiate, used for both the
 * SMB1-to-SMB2 style, and straight SMB2 style.
 * Do negotiation decisions and encode the reply.
 * The caller does the network send.
 *
 * Return value is 0 for success, else error.
 */
static int
smb2_negotiate_common(smb_request_t *sr, uint16_t version)
{
	timestruc_t boot_tv, now_tv;
	smb_session_t *s = sr->session;
	smb2_arg_negotiate_t *nego = sr->arg.other;
	int rc;
	uint32_t max_rwsize;
	uint16_t secmode;
	uint16_t neg_ctx_cnt = 0;
	uint32_t neg_ctx_off = 0;

	/*
	 * Negotiation itself.  First the Security Mode.
	 */
	secmode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (sr->sr_cfg->skc_signing_required)
		secmode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
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
	 * If the version is 0x2FF, we haven't completed negotiate.
	 * Don't initialize until we have our final request.
	 */
	if (version != 0x2FF)
		smb2_sign_init_mech(s);
	if (version >= 0x311)
		smb31_preauth_init_mech(s);

	/*
	 * [MS-SMB2] 3.3.5.4 Receiving an SMB2 NEGOTIATE Request
	 *
	 * The SMB2.x capabilities are returned without regard for
	 * what capabilities the client provided in the request.
	 * The SMB3.x capabilities returned are the traditional
	 * logical AND of server and client capabilities, except
	 * for the SMB2.x capabilities which are what the server
	 * supports (regardless of the client capabilities).
	 *
	 * One additional check: If KCF is missing something we
	 * require for encryption, turn off that capability.
	 */
	if (s->dialect < SMB_VERS_2_1) {
		/* SMB 2.002 */
		s->srv_cap = smb2srv_capabilities & SMB2_CAP_DFS;
	} else if (s->dialect < SMB_VERS_3_0) {
		/* SMB 2.x */
		s->srv_cap = smb2srv_capabilities & SMB_2X_CAPS;
	} else {
		/* SMB 3.0 or later */
		s->srv_cap = smb2srv_capabilities &
		    (SMB_2X_CAPS | s->capabilities);

		if (s->dialect < SMB_VERS_3_11)
			s->smb31_enc_cipherid = SMB3_CIPHER_AES128_CCM;
		/* else from negotiate context */

		if ((s->srv_cap & SMB2_CAP_ENCRYPTION) != 0 &&
		    smb3_encrypt_init_mech(s) != 0) {
			s->srv_cap &= ~SMB2_CAP_ENCRYPTION;
		}

		if (s->dialect >= SMB_VERS_3_11) {
			smb2_encrypt_caps_t *encap =
			    &nego->neg_in_ctxs.encrypt_ctx.encrypt_caps;

			neg_ctx_cnt = 1; // always have preauth

			if (encap->encap_cipher_count != 0)
				neg_ctx_cnt++;

			neg_ctx_off = NEG_CTX_OFFSET_OFFSET +
			    P2ROUNDUP(sr->sr_cfg->skc_negtok_len, 8);

			ASSERT3U(s->smb31_preauth_hashid, !=, 0);

			if (smb31_preauth_sha512_calc(sr, &sr->command,
			    s->smb31_preauth_hashval,
			    s->smb31_preauth_hashval) != 0)
				cmn_err(CE_WARN, "(0) Preauth hash calculation "
				    "failed");
		}
	}

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
	    neg_ctx_cnt,		/* w */
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
	    neg_ctx_off,		/* l */
	    sr->sr_cfg->skc_negtok_len,	/* # */
	    sr->sr_cfg->skc_negtok);	/* c */

	/* Note: smb31_encode_neg_ctxs() follows in caller */

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
	 *
	 * One interesting requirement here is that we MUST reply
	 * with exactly the same information as we returned in our
	 * original reply to the SMB2 negotiate on this session.
	 * If we don't the client closes the connection.
	 */

	uint32_t capabilities;
	uint16_t secmode;
	uint16_t num_dialects;
	uint16_t dialects[SMB2_NEGOTIATE_MAX_DIALECTS];
	uint8_t clnt_guid[16];

	if (s->dialect >= SMB_VERS_3_11)
		goto drop;

	/*
	 * [MS-SMB2] 3.3.5.2.4 Verifying the Signature
	 *
	 * If the dialect is SMB3 and the message was successfully
	 * decrypted we MUST skip processing of the signature.
	 */
	if (!sr->encrypted && (sr->smb2_hdr_flags & SMB2_FLAGS_SIGNED) == 0)
		goto drop;

	if (fsctl->InputCount < 24)
		goto drop;

	(void) smb_mbc_decodef(fsctl->in_mbc, "l16cww",
	    &capabilities, /* l */
	    &clnt_guid, /* 16c */
	    &secmode, /* w */
	    &num_dialects); /* w */

	if (num_dialects == 0 || num_dialects > SMB2_NEGOTIATE_MAX_DIALECTS)
		goto drop;
	if (secmode != s->cli_secmode)
		goto drop;
	if (capabilities != s->capabilities)
		goto drop;
	if (memcmp(clnt_guid, s->clnt_uuid, sizeof (clnt_guid)) != 0)
		goto drop;

	rc = smb_mbc_decodef(fsctl->in_mbc, "#w", num_dialects, dialects);
	if (rc != 0)
		goto drop;

	/*
	 * MS-SMB2 says we should compare the dialects array with the
	 * one sent previously, but that appears to be unnecessary
	 * as long as we end up with the same dialect.
	 */
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
