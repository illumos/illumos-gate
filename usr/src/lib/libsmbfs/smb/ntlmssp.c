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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "spnego.h"
#include "derparse.h"
#include "ssp.h"
#include "ntlm.h"
#include "ntlmssp.h"

typedef struct ntlmssp_state {
	uint32_t ss_flags;
	char *ss_target_name;
	struct mbuf *ss_target_info;
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

/*
 * Get a "security buffer" (header part)
 */
static int
mb_get_sb_hdr(struct mbdata *mbp, struct sec_buf *sb)
{
	int err;

	(void) mb_get_uint16le(mbp, &sb->sb_length);
	(void) mb_get_uint16le(mbp, &sb->sb_maxlen);
	err = mb_get_uint32le(mbp, &sb->sb_offset);

	return (err);
}

/*
 * Get a "security buffer" (data part), where
 * the data is delivered as an mbuf.
 */
static int
mb_get_sb_data(struct mbdata *mbp, struct sec_buf *sb, struct mbuf **mp)
{
	struct mbdata tmp_mb;
	int err;

	/*
	 * Setup tmp_mb to point to the start of the header.
	 * This is a dup ref - do NOT free it.
	 */
	mb_initm(&tmp_mb, mbp->mb_top);

	/* Skip data up to the offset. */
	err = mb_get_mem(&tmp_mb, NULL, sb->sb_offset);
	if (err)
		return (err);

	/* Get the data (as an mbuf). */
	err = mb_get_mbuf(&tmp_mb, sb->sb_maxlen, mp);

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
	int cnt0, err;

	sb->sb_offset = cnt0 = mbp->mb_count;
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
	const char *s, int unicode)
{
	int err, trim;
	struct mbdata tmp_mb;

	/*
	 * Put the string into a temp. mbuf,
	 * then chop off the null terminator
	 * before appending to caller's mbp.
	 */
	err = mb_init(&tmp_mb, M_MINSIZE);
	if (err)
		return (err);
	err = mb_put_dstring(&tmp_mb, s, unicode);
	if (err)
		return (err);

	trim = (unicode) ? 2 : 1;
	if (tmp_mb.mb_cur->m_len < trim)
		return (EFAULT);
	tmp_mb.mb_cur->m_len -= trim;

	err = mb_put_sb_data(mbp, sb, tmp_mb.mb_top);
	/*
	 * Note: tmp_mb.mb_top is consumed,
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
	char *ucdom = NULL;
	char *ucwks = NULL;

	if ((err = mb_init(&mb2, M_MINSIZE)) != 0)
		return (err);
	mb2.mb_count = sizeof (hdr);

	/*
	 * Initialize the negotiation flags, and
	 * save what we sent.  For reference:
	 * [MS-NLMP] spec. (also ntlmssp.h)
	 */
	ssp_st->ss_flags =
	    NTLMSSP_REQUEST_TARGET |
	    NTLMSSP_NEGOTIATE_NTLM |
	    NTLMSSP_NEGOTIATE_TARGET_INFO |
	    NTLMSSP_NEGOTIATE_128 |
	    NTLMSSP_NEGOTIATE_56;

	if (ctx->ct_hflags2 & SMB_FLAGS2_UNICODE)
		ssp_st->ss_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	else
		ssp_st->ss_flags |= NTLMSSP_NEGOTIATE_OEM;

	if (ctx->ct_vcflags & SMBV_WILL_SIGN) {
		ssp_st->ss_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
		ctx->ct_hflags2 |= SMB_FLAGS2_SECURITY_SIGNATURE;
	}

	bcopy(ntlmssp_id, &hdr.h_id, ID_SZ);
	hdr.h_type = 1; /* Type 1 */
	hdr.h_flags = ssp_st->ss_flags;

	/*
	 * Put the client domain, client name strings.
	 * These are always in OEM format, upper-case.
	 */
	ucdom  = utf8_str_toupper(ctx->ct_domain);
	ucwks  = utf8_str_toupper(ctx->ct_locname);
	if (ucdom == NULL || ucwks == NULL) {
		err = ENOMEM;
		goto out;
	}
	err = mb_put_sb_string(&mb2, &hdr.h_cldom, ucdom, 0);
	if (err)
		goto out;
	err = mb_put_sb_string(&mb2, &hdr.h_wksta, ucwks, 0);
	if (err)
		goto out;

	/*
	 * Marshal the header (in LE order)
	 * then concatenate the 2nd part.
	 */
	(void) mb_put_mem(out_mb, &hdr.h_id, ID_SZ);
	(void) mb_put_uint32le(out_mb, hdr.h_type);
	(void) mb_put_uint32le(out_mb, hdr.h_flags);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_cldom);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_wksta);

	err = mb_put_mbuf(out_mb, mb2.mb_top);

out:
	free(ucdom);
	free(ucwks);

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
	(void) mb_get_mem(in_mb, &hdr.h_id, ID_SZ);
	(void) mb_get_uint32le(in_mb, &hdr.h_type);
	if (hdr.h_type != 2) {
		err = EPROTO;
		goto out;
	}
	(void) mb_get_sb_hdr(in_mb, &hdr.h_target_name);
	(void) mb_get_uint32le(in_mb, &hdr.h_flags);
	(void) mb_get_mem(in_mb, &hdr.h_challenge, NTLM_CHAL_SZ);

	/*
	 * Save flags, challenge for later.
	 */
	ssp_st->ss_flags = hdr.h_flags;
	uc = hdr.h_flags & NTLMSSP_NEGOTIATE_UNICODE;
	bcopy(&hdr.h_challenge, ctx->ct_ntlm_chal, NTLM_CHAL_SZ);

	/*
	 * Now find out if the optional parts are there.
	 */
	if ((m_totlen(top_mb.mb_top) > sizeof (hdr)) &&
	    (hdr.h_target_name.sb_offset >= sizeof (hdr))) {
		(void) mb_get_uint32le(in_mb, &hdr.h_context[0]);
		(void) mb_get_uint32le(in_mb, &hdr.h_context[1]);
		(void) mb_get_sb_hdr(in_mb, &hdr.h_target_info);
	}

	/*
	 * Get the target name string.  First get a copy of
	 * the data from the offset/length indicated in the
	 * security buffer header; then parse the string.
	 */
	err = mb_get_sb_data(&top_mb, &hdr.h_target_name, &m);
	if (err)
		goto out;
	mb_initm(&tmp_mb, m);
	err = mb_get_string(&tmp_mb, &ssp_st->ss_target_name, uc);
	mb_done(&tmp_mb);

	/*
	 * Get the target info blob, if present.
	 */
	if (hdr.h_target_info.sb_offset >= sizeof (hdr)) {
		err = mb_get_sb_data(&top_mb, &hdr.h_target_info,
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
	} hdr;
	struct mbdata lm_mbc, nt_mbc, ti_mbc;
	struct mbdata mb2;	/* 2nd part */
	int err, uc;
	char *ucdom = NULL;	/* user's domain */
	char *ucuser = NULL;	/* user name */
	char *ucwksta = NULL;	/* workstation */
	struct smb_ctx *ctx = sp->smb_ctx;
	ntlmssp_state_t *ssp_st = sp->sp_private;

	bzero(&lm_mbc, sizeof (lm_mbc));
	bzero(&nt_mbc, sizeof (nt_mbc));
	bzero(&ti_mbc, sizeof (ti_mbc));
	bzero(&mb2, sizeof (mb2));

	/*
	 * Convert the user name to upper-case, as that's what's
	 * used when computing LMv2 and NTLMv2 responses.  Also
	 * domain, workstation
	 */
	ucdom  = utf8_str_toupper(ctx->ct_domain);
	ucuser = utf8_str_toupper(ctx->ct_user);
	ucwksta = utf8_str_toupper(ctx->ct_locname);
	if (ucdom == NULL || ucuser == NULL || ucwksta == NULL) {
		err = ENOMEM;
		goto out;
	}

	if ((err = mb_init(&mb2, M_MINSIZE)) != 0)
		goto out;
	mb2.mb_count = sizeof (hdr);
	uc = ssp_st->ss_flags & NTLMSSP_NEGOTIATE_UNICODE;

	bcopy(ntlmssp_id, &hdr.h_id, ID_SZ);
	hdr.h_type = 3; /* Type 3 */

	/*
	 * Put the LMv2,NTLMv2 responses, or
	 * possibly LM, NTLM (v1) responses.
	 */
	if (ctx->ct_authflags & SMB_AT_NTLM2) {
		/* Build the NTLMv2 "target info" blob. */
		err = ntlm_build_target_info(ctx,
		    ssp_st->ss_target_info, &ti_mbc);
		if (err)
			goto out;
		err = ntlm_put_v2_responses(ctx, &ti_mbc,
		    &lm_mbc, &nt_mbc);
	} else {
		err = ntlm_put_v1_responses(ctx,
		    &lm_mbc, &nt_mbc);
	}
	if (err)
		goto out;

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
	err = mb_put_sb_string(&mb2, &hdr.h_domain, ucdom, uc);
	if (err)
		goto out;
	err = mb_put_sb_string(&mb2, &hdr.h_user, ucuser, uc);
	if (err)
		goto out;
	err = mb_put_sb_string(&mb2, &hdr.h_wksta, ucwksta, uc);
	if (err)
		goto out;

	/*
	 * Marshal the header (in LE order)
	 * then concatenate the 2nd part.
	 */
	(void) mb_put_mem(out_mb, &hdr.h_id, ID_SZ);
	(void) mb_put_uint32le(out_mb, hdr.h_type);

	(void) mb_put_sb_hdr(out_mb, &hdr.h_lm_resp);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_nt_resp);

	(void) mb_put_sb_hdr(out_mb, &hdr.h_domain);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_user);
	(void) mb_put_sb_hdr(out_mb, &hdr.h_wksta);

	err = mb_put_mbuf(out_mb, mb2.mb_top);
	mb2.mb_top = NULL; /* consumed */

out:
	free(ucdom);
	free(ucuser);
	free(ucwksta);

	mb_done(&mb2);
	mb_done(&lm_mbc);
	mb_done(&nt_mbc);

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
	err = mb_init(out_mb, M_MINSIZE);
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
	    (SMB_AT_NTLM2 | SMB_AT_NTLM1)) == 0) {
		DPRINT("No NTLM authflags");
		return (ENOTSUP);
	}

	ssp_st = calloc(1, sizeof (*ssp_st));
	if (ssp_st == NULL)
		return (ENOMEM);

	sp->sp_nexttok = ntlmssp_next_token;
	sp->sp_destroy = ntlmssp_destroy;
	sp->sp_private = ssp_st;

	return (0);
}
