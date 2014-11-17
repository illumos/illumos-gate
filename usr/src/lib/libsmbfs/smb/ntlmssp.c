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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NT Lan Manager Security Support Provider (NTLMSSP)
 *
 * Based on information from the "Davenport NTLM" page:
 * http://davenport.sourceforge.net/ntlm.html
 */


#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>

#include "private.h"
#include "charsets.h"
#include "smb_crypt.h"
#include "spnego.h"
#include "derparse.h"
#include "ssp.h"
#include "ntlm.h"
#include "ntlmssp.h"

/* A shorter alias for a crazy long name from [MS-NLMP] */
#define	NTLMSSP_NEGOTIATE_NTLM2 \
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

typedef struct ntlmssp_state {
	uint32_t ss_flags;
	char *ss_target_name;	/* Primary domain or server name */
	struct mbuf *ss_target_info;
	uchar_t	ss_kxkey[NTLM_HASH_SZ];
} ntlmssp_state_t;

/*
 * So called "security buffer".
 * A lot like an RPC string.
 */
struct sec_buf {
	uint16_t sb_length;
	uint16_t sb_maxlen;
	uint32_t sb_offset;
};
#define	ID_SZ 8
static const char ntlmssp_id[ID_SZ] = "NTLMSSP";

static int
ntlm_rand_ssn_key(struct smb_ctx *ctx,
	ntlmssp_state_t *ssp_st, struct mbdata *ek_mbp);

/*
 * Get a "security buffer" (header part)
 */
static int
md_get_sb_hdr(struct mbdata *mbp, struct sec_buf *sb)
{
	int err;

	(void) md_get_uint16le(mbp, &sb->sb_length);
	(void) md_get_uint16le(mbp, &sb->sb_maxlen);
	err = md_get_uint32le(mbp, &sb->sb_offset);

	return (err);
}

/*
 * Get a "security buffer" (data part), where
 * the data is delivered as an mbuf.
 */
static int
md_get_sb_data(struct mbdata *mbp, struct sec_buf *sb, struct mbuf **mp)
{
	struct mbdata tmp_mb;
	int err;

	/*
	 * Setup tmp_mb to point to the start of the header.
	 * This is a dup ref - do NOT free it.
	 */
	mb_initm(&tmp_mb, mbp->mb_top);

	/* Skip data up to the offset. */
	err = md_get_mem(&tmp_mb, NULL, sb->sb_offset, MB_MSYSTEM);
	if (err)
		return (err);

	/* Get the data (as an mbuf). */
	err = md_get_mbuf(&tmp_mb, sb->sb_maxlen, mp);

	return (err);
}

/*
 * Put a "security buffer" (header part)
 */
static int
mb_put_sb_hdr(struct mbdata *mbp, struct sec_buf *sb)
{
	int err;

	(void) mb_put_uint16le(mbp, sb->sb_length);
	(void) mb_put_uint16le(mbp, sb->sb_maxlen);
	err = mb_put_uint32le(mbp, sb->sb_offset);

	return (err);
}

/*
 * Put a "security buffer" (data part), where
 * the data is an mbuf.  Note: consumes m.
 */
static int
mb_put_sb_data(struct mbdata *mbp, struct sec_buf *sb, struct mbuf *m)
{
	int cnt0;
	int err = 0;

	sb->sb_offset = cnt0 = mbp->mb_count;
	if (m != NULL)
		err = mb_put_mbuf(mbp, m);
	sb->sb_maxlen = sb->sb_length = mbp->mb_count - cnt0;

	return (err);
}

/*
 * Put a "security buffer" (data part), where
 * the data is a string (OEM or unicode).
 *
 * The string is NOT null terminated.
 */
static int
mb_put_sb_string(struct mbdata *mbp, struct sec_buf *sb,
	const char *str, int unicode)
{
	int err, trim;
	struct mbdata tmp_mb;

	bzero(&tmp_mb, sizeof (tmp_mb));

	if (str != NULL && *str != '\0') {
		/*
		 * Put the string into a temp. mbuf,
		 * then chop off the null terminator
		 * before appending to caller's mbp.
		 */
		err = mb_init(&tmp_mb);
		if (err)
			return (err);
		err = mb_put_string(&tmp_mb, str, unicode);
		if (err)
			return (err);

		trim = (unicode) ? 2 : 1;
		if (tmp_mb.mb_cur->m_len < trim)
			trim = 0;
		tmp_mb.mb_cur->m_len -= trim;
	}

	err = mb_put_sb_data(mbp, sb, tmp_mb.mb_top);
	/*
	 * Note: tmp_mb.mb_top (if any) is consumed,
	 * so do NOT free it (no mb_done)
	 */
	return (err);
}

/*
 * Build a Type 1 message
 *
 * This message has a header section containing offsets to
 * data later in the message.  We use the common trick of
 * building it in two parts and then concatenatening.
 */
int
ntlmssp_put_type1(struct ssp_ctx *sp, struct mbdata *out_mb)
{
	struct type1hdr {
		char h_id[ID_SZ];
		uint32_t h_type;
		uint32_t h_flags;
		struct sec_buf h_cldom;
		struct sec_buf h_wksta;
	} hdr;
	struct mbdata mb2;	/* 2nd part */
	int err;
	struct smb_ctx *ctx = sp->smb_ctx;
	ntlmssp_state_t *ssp_st = sp->sp_private;

	if ((err = mb_init(&mb2)) != 0)
		return (err);
	mb2.mb_count = sizeof (hdr);

	/*
	 * The initial negotiation flags represent the union of all
	 * options we support.  The server selects from these.
	 * See: [MS-NLMP 2.2.2.5 NEGOTIATE]
	 */
	ssp_st->ss_flags =
	    NTLMSSP_NEGOTIATE_UNICODE |
	    NTLMSSP_NEGOTIATE_OEM |
	    NTLMSSP_REQUEST_TARGET |
	    NTLMSSP_NEGOTIATE_SIGN |
	    NTLMSSP_NEGOTIATE_SEAL |
	    /* NTLMSSP_NEGOTIATE_LM_KEY (never) */
	    NTLMSSP_NEGOTIATE_NTLM |
	    /* NTLMSSP_NEGOTIATE_ALWAYS_SIGN (set below) */
	    NTLMSSP_NEGOTIATE_NTLM2 |
	    NTLMSSP_NEGOTIATE_128 |
	    NTLMSSP_NEGOTIATE_KEY_EXCH |
	    NTLMSSP_NEGOTIATE_56;

	if (ctx->ct_vcflags & SMBV_WILL_SIGN) {
		ssp_st->ss_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
		ctx->ct_hflags2 |= SMB_FLAGS2_SECURITY_SIGNATURE;
	}

	bcopy(ntlmssp_id, &hdr.h_id, ID_SZ);
	hdr.h_type = NTLMSSP_MSGTYPE_NEGOTIATE;
	hdr.h_flags = ssp_st->ss_flags;

	/*
	 * We could put the client domain, client name strings
	 * here, (always in OEM format, upper-case), and set
	 * NTLMSSP_NEGOTIATE_OEM_..._SUPPLIED, but Windows
	 * leaves these NULL so let's do the same.
	 */
	(void) mb_put_sb_string(&mb2, &hdr.h_cldom, NULL, 0);
	(void) mb_put_sb_string(&mb2, &hdr.h_wksta, NULL, 0);

	/*
	 * Marshal the header (in LE order)
	 * then concatenate the 2nd part.
	 */
	(void) mb_put_mem(out_mb, &hdr.h_id, ID_SZ, MB_MSYSTEM);
	(void) mb_put_uint32le(out_mb, hdr.h_type);
	(void) mb_put_uint32le(out_mb, hdr.h_flags);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_cldom);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_wksta);

	err = mb_put_mbuf(out_mb, mb2.mb_top);

	return (err);
}

/*
 * Parse a Type 2 message
 */
int
ntlmssp_get_type2(struct ssp_ctx *sp, struct mbdata *in_mb)
{
	struct type2hdr {
		char h_id[ID_SZ];
		uint32_t h_type;
		struct sec_buf h_target_name;
		uint32_t h_flags;
		uint8_t h_challenge[8];
		uint32_t h_context[2];		/* optional */
		struct sec_buf h_target_info;	/* optional */
	} hdr;
	struct mbdata top_mb, tmp_mb;
	struct mbuf *m;
	int err, uc;
	int min_hdr_sz = offsetof(struct type2hdr, h_context);
	struct smb_ctx *ctx = sp->smb_ctx;
	ntlmssp_state_t *ssp_st = sp->sp_private;
	char *buf = NULL;

	if (m_totlen(in_mb->mb_top) < min_hdr_sz) {
		err = EBADRPC;
		goto out;
	}

	/*
	 * Save the mbdata pointers before we consume anything.
	 * Careful to NOT free this (would be dup. free)
	 * We use this below to find data based on offsets
	 * from the start of the header.
	 */
	top_mb = *in_mb;

	/* Parse the fixed size header stuff. */
	bzero(&hdr, sizeof (hdr));
	(void) md_get_mem(in_mb, &hdr.h_id, ID_SZ, MB_MSYSTEM);
	(void) md_get_uint32le(in_mb, &hdr.h_type);
	if (hdr.h_type != NTLMSSP_MSGTYPE_CHALLENGE) {
		err = EPROTO;
		goto out;
	}
	(void) md_get_sb_hdr(in_mb, &hdr.h_target_name);
	(void) md_get_uint32le(in_mb, &hdr.h_flags);
	(void) md_get_mem(in_mb, &hdr.h_challenge, NTLM_CHAL_SZ, MB_MSYSTEM);

	/*
	 * Save flags, server challenge for later.
	 */
	ssp_st->ss_flags = hdr.h_flags;
	bcopy(&hdr.h_challenge, ctx->ct_srv_chal, NTLM_CHAL_SZ);

	/*
	 * Turn off flags that might have been given but
	 * that we don't want to send with authenticate.
	 */
	uc = hdr.h_flags & NTLMSSP_NEGOTIATE_UNICODE;
	ssp_st->ss_flags &= ~NTLMSSP_NEGOTIATE_VERSION;

	/*
	 * Now find out if the optional parts are there.
	 */
	if ((m_totlen(top_mb.mb_top) > sizeof (hdr)) &&
	    (hdr.h_target_name.sb_offset >= sizeof (hdr))) {
		(void) md_get_uint32le(in_mb, &hdr.h_context[0]);
		(void) md_get_uint32le(in_mb, &hdr.h_context[1]);
		(void) md_get_sb_hdr(in_mb, &hdr.h_target_info);
	}

	/*
	 * Get the target name string.  (Server name or
	 * Primary domain name.)  First get a copy of the
	 * data from the offset/length indicated in the
	 * security buffer header; then parse the string.
	 */
	err = md_get_sb_data(&top_mb, &hdr.h_target_name, &m);
	if (err)
		goto out;
	mb_initm(&tmp_mb, m);
	err = md_get_string(&tmp_mb, &ssp_st->ss_target_name, uc);
	mb_done(&tmp_mb);

	/*
	 * Get the target info blob, if present.
	 */
	if (hdr.h_target_info.sb_offset >= sizeof (hdr)) {
		err = md_get_sb_data(&top_mb, &hdr.h_target_info,
		    &ssp_st->ss_target_info);
	}

out:
	if (buf != NULL)
		free(buf);

	return (err);
}

/*
 * Build a Type 3 message
 *
 * This message has a header section containing offsets to
 * data later in the message.  We use the common trick of
 * building it in two parts and then concatenatening.
 */
int
ntlmssp_put_type3(struct ssp_ctx *sp, struct mbdata *out_mb)
{
	struct type3hdr {
		char h_id[ID_SZ];
		uint32_t h_type;
		struct sec_buf h_lm_resp;
		struct sec_buf h_nt_resp;
		struct sec_buf h_domain;
		struct sec_buf h_user;
		struct sec_buf h_wksta;
		struct sec_buf h_ssn_key;
		uint32_t h_flags;
		/* Version struct (ommitted) */
		uchar_t h_mic[NTLM_HASH_SZ];
	} hdr;
	struct mbdata lm_mbc;	/* LM response */
	struct mbdata nt_mbc;	/* NT response */
	struct mbdata ti_mbc;	/* target info */
	struct mbdata ek_mbc;	/* encrypted session key */
	struct mbdata mb2;	/* payload */
	int err, uc;
	struct smb_ctx *ctx = sp->smb_ctx;
	ntlmssp_state_t *ssp_st = sp->sp_private;
	uchar_t *pmic;

	bzero(&hdr, sizeof (hdr));
	bzero(&lm_mbc, sizeof (lm_mbc));
	bzero(&nt_mbc, sizeof (nt_mbc));
	bzero(&ti_mbc, sizeof (ti_mbc));
	bzero(&ek_mbc, sizeof (ek_mbc));
	bzero(&mb2, sizeof (mb2));

	/*
	 * Fill in the NTLMSSP header, etc.
	 */
	if ((err = mb_init(&mb2)) != 0)
		goto out;
	mb2.mb_count = sizeof (hdr);
	uc = ssp_st->ss_flags & NTLMSSP_NEGOTIATE_UNICODE;

	bcopy(ntlmssp_id, &hdr.h_id, ID_SZ);
	hdr.h_type = NTLMSSP_MSGTYPE_AUTHENTICATE;
	hdr.h_flags = ssp_st->ss_flags;

	/*
	 * Put the NTLMv2/LMv2 or NTLM/LM (v1) responses,
	 * and compute the session key, etc.
	 */
	if (ctx->ct_authflags & SMB_AT_ANON) {
		/*
		 * We're setting up a NULL session, meaning
		 * the lm_mbc, nt_mbc parts remain empty.
		 * Let's add the "anon" flag (hint).
		 * As there is no session key, disable the
		 * fancy session key stuff.
		 */
		hdr.h_flags |= NTLMSSP_NEGOTIATE_NULL_SESSION;
		ssp_st->ss_flags &= ~(
		    NTLMSSP_NEGOTIATE_NTLM2 |
		    NTLMSSP_NEGOTIATE_KEY_EXCH);
		err = 0;
	} else if (ctx->ct_authflags & SMB_AT_NTLM2) {
		/*
		 * Doing NTLMv2/LMv2
		 */
		err = ntlm_build_target_info(ctx,
		    ssp_st->ss_target_info, &ti_mbc);
		if (err)
			goto out;
		err = ntlm_put_v2_responses(ctx, &ti_mbc,
		    &lm_mbc, &nt_mbc);
		if (err)
			goto out;
		/* The "key exg. key" is the session base key */
		memcpy(ssp_st->ss_kxkey, ctx->ct_ssn_key, NTLM_HASH_SZ);

	} else if (ssp_st->ss_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		/*
		 * Doing NTLM ("v1x") which is NTLM with
		 * "Extended Session Security"
		 */
		err = ntlm_put_v1x_responses(ctx,
		    &lm_mbc, &nt_mbc);
		if (err)
			goto out;
		/* Compute the "Key exchange key". */
		ntlm2_kxkey(ctx, &lm_mbc, ssp_st->ss_kxkey);
	} else {
		/*
		 * Doing plain old NTLM (and LM if enabled)
		 */
		err = ntlm_put_v1_responses(ctx,
		    &lm_mbc, &nt_mbc);
		if (err)
			goto out;
		/* The "key exg. key" is the session base key */
		memcpy(ssp_st->ss_kxkey, ctx->ct_ssn_key, NTLM_HASH_SZ);
	}

	/*
	 * Compute the "Exported Session Key" and (possibly)
	 * the "Encrypted Random Sesion Key".
	 * [MS-NLMP 3.1.5.1.2]
	 */
	if (ssp_st->ss_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		err = ntlm_rand_ssn_key(ctx, ssp_st, &ek_mbc);
		if (err)
			goto out;
	} else {
		/* ExportedSessionKey is the KeyExchangeKey */
		memcpy(ctx->ct_ssn_key, ssp_st->ss_kxkey, NTLM_HASH_SZ);
		/* EncryptedRandomSessionKey remains NULL */
	}

	err = mb_put_sb_data(&mb2, &hdr.h_lm_resp, lm_mbc.mb_top);
	lm_mbc.mb_top = NULL; /* consumed */
	if (err)
		goto out;
	err = mb_put_sb_data(&mb2, &hdr.h_nt_resp, nt_mbc.mb_top);
	nt_mbc.mb_top = NULL; /* consumed */
	if (err)
		goto out;

	/*
	 * Put the "target" (domain), user, workstation
	 */
	err = mb_put_sb_string(&mb2, &hdr.h_domain, ctx->ct_domain, uc);
	if (err)
		goto out;
	err = mb_put_sb_string(&mb2, &hdr.h_user, ctx->ct_user, uc);
	if (err)
		goto out;
	err = mb_put_sb_string(&mb2, &hdr.h_wksta, ctx->ct_locname, uc);
	if (err)
		goto out;

	/*
	 * Put the "Encrypted Random Session Key", if any.
	 * (ek_mbc.mb_top may be NULL)
	 */
	err = mb_put_sb_data(&mb2, &hdr.h_ssn_key, ek_mbc.mb_top);
	ek_mbc.mb_top = NULL; /* consumed (if any) */
	if (err)
		goto out;

	/*
	 * Marshal the header (in LE order)
	 * then concatenate the 2nd part.
	 */
	(void) mb_put_mem(out_mb, &hdr.h_id, ID_SZ, MB_MSYSTEM);
	(void) mb_put_uint32le(out_mb, hdr.h_type);

	(void) mb_put_sb_hdr(out_mb, &hdr.h_lm_resp);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_nt_resp);

	(void) mb_put_sb_hdr(out_mb, &hdr.h_domain);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_user);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_wksta);

	(void) mb_put_sb_hdr(out_mb, &hdr.h_ssn_key);
	(void) mb_put_uint32le(out_mb, hdr.h_flags);

	/* Put zeros for the MIC - filled in later */
	pmic = mb_reserve(out_mb, NTLM_HASH_SZ);

	/* Put the payload. */
	err = mb_put_mbuf(out_mb, mb2.mb_top);
	mb2.mb_top = NULL; /* consumed */

	/*
	 * Compute the MIC and stuff that in...
	 * The MIC is apparently optional.
	 */
	(void) pmic;

out:
	mb_done(&mb2);
	mb_done(&lm_mbc);
	mb_done(&nt_mbc);
	mb_done(&ti_mbc);
	mb_done(&ek_mbc);

	return (err);
}

/*
 * Helper for ntlmssp_put_type3 when doing key exchange.
 *
 * "ExportedSessionKey" is what we give to the "application"
 * layer, which in here means the MAC key for SMB signing.
 * With "key exchange", we replace the ExportedSessionKey
 * with random data and send that (encrypted) to the peer.
 */
static int
ntlm_rand_ssn_key(
	struct smb_ctx *ctx,
	ntlmssp_state_t *ssp_st,
	struct mbdata *ek_mbp)
{

	uchar_t *encr_ssn_key;
	int err;

	if ((err = mb_init(ek_mbp)) != 0)
		return (err);
	encr_ssn_key = mb_reserve(ek_mbp, NTLM_HASH_SZ);

	/* Set "ExportedSessionKey to NONCE(16) */
	(void) smb_get_urandom(ctx->ct_ssn_key, NTLM_HASH_SZ);

	/* Set "EncryptedRandomSessionKey" to RC4(...) */
	err = smb_encrypt_RC4(encr_ssn_key, NTLM_HASH_SZ,
	    ssp_st->ss_kxkey, NTLM_HASH_SZ,
	    ctx->ct_ssn_key, NTLM_HASH_SZ);

	return (err);
}

/*
 * ntlmssp_final
 *
 * Called after successful authentication.
 * Setup the MAC key for signing.
 */
int
ntlmssp_final(struct ssp_ctx *sp)
{
	struct smb_ctx *ctx = sp->smb_ctx;
	int err = 0;

	/*
	 * MAC_key is just the session key, but
	 * Only on the first successful auth.
	 */
	if ((ctx->ct_hflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) &&
	    (ctx->ct_mackey == NULL)) {
		ctx->ct_mackeylen = NTLM_HASH_SZ;
		ctx->ct_mackey = malloc(ctx->ct_mackeylen);
		if (ctx->ct_mackey == NULL) {
			ctx->ct_mackeylen = 0;
			err = ENOMEM;
			goto out;
		}
		memcpy(ctx->ct_mackey, ctx->ct_ssn_key, NTLM_HASH_SZ);
		/*
		 * Apparently, the server used seq. no. zero
		 * for our previous message, so next is two.
		 */
		ctx->ct_mac_seqno = 2;
	}

out:
	return (err);
}

/*
 * ntlmssp_next_token
 *
 * See ssp.c: ssp_ctx_next_token
 */
int
ntlmssp_next_token(struct ssp_ctx *sp, struct mbdata *in_mb,
	struct mbdata *out_mb)
{
	int err;

	if (out_mb == NULL) {
		/* final call on successful auth. */
		err = ntlmssp_final(sp);
		goto out;
	}

	/* Will build an ouptut token. */
	err = mb_init(out_mb);
	if (err)
		goto out;

	/*
	 * When called with in_mb == NULL, it means
	 * this is the first call for this session,
	 * so put a Type 1 (initialize) token.
	 */
	if (in_mb == NULL) {
		err = ntlmssp_put_type1(sp, out_mb);
		goto out;
	}

	/*
	 * This is not the first call, so
	 * parse the response token we received.
	 * It should be a Type 2 (challenge).
	 * Then put a Type 3 (authenticate)
	 */
	err = ntlmssp_get_type2(sp, in_mb);
	if (err)
		goto out;

	err = ntlmssp_put_type3(sp, out_mb);

out:
	if (err)
		DPRINT("ret: %d", err);
	return (err);
}

/*
 * ntlmssp_ctx_destroy
 *
 * Destroy mechanism-specific data.
 */
void
ntlmssp_destroy(struct ssp_ctx *sp)
{
	ntlmssp_state_t *ssp_st;

	ssp_st = sp->sp_private;
	if (ssp_st != NULL) {
		sp->sp_private = NULL;
		free(ssp_st->ss_target_name);
		m_freem(ssp_st->ss_target_info);
		free(ssp_st);
	}
}

/*
 * ntlmssp_init_clnt
 *
 * Initialize a new NTLMSSP client context.
 */
int
ntlmssp_init_client(struct ssp_ctx *sp)
{
	ntlmssp_state_t *ssp_st;

	if ((sp->smb_ctx->ct_authflags &
	    (SMB_AT_NTLM2 | SMB_AT_NTLM1 | SMB_AT_ANON)) == 0) {
		DPRINT("No NTLM authflags");
		return (EINVAL);
	}

	ssp_st = calloc(1, sizeof (*ssp_st));
	if (ssp_st == NULL)
		return (ENOMEM);

	sp->sp_nexttok = ntlmssp_next_token;
	sp->sp_destroy = ntlmssp_destroy;
	sp->sp_private = ssp_st;

	return (0);
}
