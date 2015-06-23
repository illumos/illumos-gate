/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB Negotiate Protocol, and related.
 */

#include <errno.h>
#include <stdio.h>
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
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "smb_crypt.h"
#include "private.h"

/*
 * SMB dialects that we know about.
 */
struct smb_dialect {
	int		d_id;
	const char	*d_name;
};
static struct smb_dialect smb_dialects[] = {
	{SMB_DIALECT_CORE,	"PC NETWORK PROGRAM 1.0"},
	{SMB_DIALECT_LANMAN1_0,	"LANMAN1.0"},
	{SMB_DIALECT_LANMAN2_0,	"LM1.2X002"},
	{SMB_DIALECT_LANMAN2_1,	"LANMAN2.1"},
	{SMB_DIALECT_NTLM0_12,	"NT LM 0.12"},
	{-1,			NULL}
};

#define	SMB_DIALECT_MAX \
	(sizeof (smb_dialects) / sizeof (struct smb_dialect) - 2)

static const uint32_t smb_clnt_caps_mask =
    SMB_CAP_UNICODE |
    SMB_CAP_LARGE_FILES |
    SMB_CAP_NT_SMBS |
    SMB_CAP_STATUS32 |
    SMB_CAP_EXT_SECURITY;

/*
 * SMB Negotiate Protocol
 * Based on code from the driver: smb_smb.c
 *
 * If using Extended Security, oblob (output)
 * will hold the initial security "hint".
 */
int
smb_negprot(struct smb_ctx *ctx, struct mbdata *oblob)
{
	struct smb_sopt *sv = &ctx->ct_sopt;
	struct smb_iods *is = &ctx->ct_iods;
	struct smb_rq	*rqp;
	struct mbdata	*mbp;
	struct smb_dialect *dp;
	int err, len;
	uint8_t wc, eklen;
	uint16_t dindex, bc;
	int will_sign = 0;

	/*
	 * Initialize: vc_hflags and vc_hflags2.
	 * Note: ctx->ct_hflags* are copied into the
	 * (per request) rqp->rq_hflags* by smb_rq_init.
	 *
	 * Like Windows, set FLAGS2_UNICODE in our first request,
	 * even though technically we don't yet know whether the
	 * server supports Unicode.  Will clear this flag below
	 * if we find out it doesn't.  Need to do this because
	 * some servers reject all non-Unicode requests.
	 */
	ctx->ct_hflags =
	    SMB_FLAGS_CASELESS |
	    SMB_FLAGS_CANONICAL_PATHNAMES;
	ctx->ct_hflags2 =
	    SMB_FLAGS2_KNOWS_LONG_NAMES |
	    SMB_FLAGS2_KNOWS_EAS |
	    /* SMB_FLAGS2_IS_LONG_NAME |? */
	    /* EXT_SEC (see below) */
	    SMB_FLAGS2_ERR_STATUS |
	    SMB_FLAGS2_UNICODE;

	/*
	 * Sould we offer extended security?
	 * We'll turn this back off below if
	 * the server doesn't support it.
	 */
	if (ctx->ct_vopt & SMBVOPT_EXT_SEC)
		ctx->ct_hflags2 |= SMB_FLAGS2_EXT_SEC;

	/*
	 * The initial UID needs to be zero,
	 * or Windows XP says "bad user".
	 * The initial TID is all ones, but
	 * we don't use it or store it here
	 * because the driver handles that.
	 */
	is->is_smbuid = 0;

	/*
	 * In case we're reconnecting,
	 * free previous stuff.
	 */
	ctx->ct_mac_seqno = 0;
	if (ctx->ct_mackey != NULL) {
		free(ctx->ct_mackey);
		ctx->ct_mackey = NULL;
		ctx->ct_mackeylen = 0;
	}

	sv = &ctx->ct_sopt;
	bzero(sv, sizeof (struct smb_sopt));

	err = smb_rq_init(ctx, SMB_COM_NEGOTIATE, &rqp);
	if (err)
		return (err);

	/*
	 * Build the SMB request.
	 */
	mbp = &rqp->rq_rq;
	mb_put_uint8(mbp, 0);			/* word count */
	smb_rq_bstart(rqp);
	for (dp = smb_dialects; dp->d_id != -1; dp++) {
		mb_put_uint8(mbp, SMB_DT_DIALECT);
		mb_put_astring(mbp, dp->d_name);
	}
	smb_rq_bend(rqp);

	/*
	 * This does the OTW call
	 */
	err = smb_rq_internal(ctx, rqp);
	if (err) {
		DPRINT("call failed, err %d", err);
		goto errout;
	}
	if (rqp->rq_status != 0) {
		DPRINT("nt status 0x%x", rqp->rq_status);
		err = EBADRPC;
		goto errout;
	}

	/*
	 * Decode the response
	 *
	 * Comments to right show names as described in
	 * The Microsoft SMB Protocol spec. [MS-SMB]
	 * section 2.2.3
	 */
	mbp = &rqp->rq_rp;
	(void) md_get_uint8(mbp, &wc);
	err = md_get_uint16le(mbp, &dindex);
	if (err || dindex > SMB_DIALECT_MAX) {
		DPRINT("err %d dindex %d", err, (int)dindex);
		goto errout;
	}
	dp = smb_dialects + dindex;
	sv->sv_proto = dp->d_id;
	DPRINT("Dialect %s", dp->d_name);
	if (dp->d_id < SMB_DIALECT_NTLM0_12) {
		/* XXX: User-visible warning too? */
		DPRINT("old dialect %s", dp->d_name);
		goto errout;
	}
	if (wc != 17) {
		DPRINT("bad wc %d", (int)wc);
		goto errout;
	}
	md_get_uint8(mbp, &sv->sv_sm);		/* SecurityMode */
	md_get_uint16le(mbp, &sv->sv_maxmux);	/* MaxMpxCount */
	md_get_uint16le(mbp, &sv->sv_maxvcs);	/* MaxCountVCs */
	md_get_uint32le(mbp, &sv->sv_maxtx);	/* MaxBufferSize */
	md_get_uint32le(mbp, &sv->sv_maxraw);	/* MaxRawSize */
	md_get_uint32le(mbp, &sv->sv_skey);	/* SessionKey */
	md_get_uint32le(mbp, &sv->sv_caps);	/* Capabilities */
	md_get_mem(mbp, NULL, 8, MB_MSYSTEM);	/* SystemTime(s) */
	md_get_uint16le(mbp, (uint16_t *)&sv->sv_tz);
	md_get_uint8(mbp, &eklen);	/* EncryptionKeyLength */
	err = md_get_uint16le(mbp, &bc);	/* ByteCount */
	if (err)
		goto errout;

	/* BEGIN CSTYLED */
	/*
	 * Will we do SMB signing?  Or block the connection?
	 * The table below describes this logic.  References:
	 * [Windows Server Protocols: MS-SMB, sec. 3.2.4.2.3]
	 * http://msdn.microsoft.com/en-us/library/cc212511.aspx
	 * http://msdn.microsoft.com/en-us/library/cc212929.aspx
	 *
	 * Srv/Cli     | Required | Enabled    | If Required | Disabled
	 * ------------+----------+------------+-------------+-----------
	 * Required    | Signed   | Signed     | Signed      | Blocked [1]
	 * ------------+----------+------------+-------------+-----------
	 * Enabled     | Signed   | Signed     | Not Signed  | Not Signed
	 * ------------+----------+------------+-------------+-----------
	 * If Required | Signed   | Not Signed | Not Signed  | Not Signed
	 * ------------+----------+------------+-------------+-----------
	 * Disabled    | Blocked  | Not Signed | Not Signed  | Not Signed
	 *
	 * [1] Like Windows 2003 and later, we don't really implement
	 * the "Disabled" setting.  Instead we implement "If Required",
	 * so we always sign if the server requires signing.
	 */
	/* END CSTYLED */

	if (sv->sv_sm & SMB_SM_SIGS_REQUIRE) {
		/*
		 * Server requires signing.  We will sign,
		 * even if local setting is "disabled".
		 */
		will_sign = 1;
	} else if (sv->sv_sm & SMB_SM_SIGS) {
		/*
		 * Server enables signing (client's option).
		 * If enabled locally, do signing.
		 */
		if (ctx->ct_vopt & SMBVOPT_SIGNING_ENABLED)
			will_sign = 1;
		/* else not signing. */
	} else {
		/*
		 * Server does not support signing.
		 * If we "require" it, bail now.
		 */
		if (ctx->ct_vopt & SMBVOPT_SIGNING_REQUIRED) {
			DPRINT("Client requires signing "
			    "but server has it disabled.");
			err = EBADRPC;
			goto errout;
		}
	}

	if (will_sign) {
		ctx->ct_vcflags |= SMBV_WILL_SIGN;
	}
	DPRINT("Security signatures: %d", will_sign);

	/* See comment above re. FLAGS2_UNICODE */
	if (sv->sv_caps & SMB_CAP_UNICODE)
		ctx->ct_vcflags |= SMBV_UNICODE;
	else
		ctx->ct_hflags2 &= ~SMB_FLAGS2_UNICODE;

	if ((sv->sv_caps & SMB_CAP_STATUS32) == 0) {
		/*
		 * They don't do NT error codes.
		 *
		 * If we send requests with
		 * SMB_FLAGS2_ERR_STATUS set in
		 * Flags2, Windows 98, at least,
		 * appears to send replies with that
		 * bit set even though it sends back
		 * DOS error codes.  (They probably
		 * just use the request header as
		 * a template for the reply header,
		 * and don't bother clearing that bit.)
		 *
		 * Therefore, we clear that bit in
		 * our vc_hflags2 field.
		 */
		ctx->ct_hflags2 &= ~SMB_FLAGS2_ERR_STATUS;
	}
	if (dp->d_id == SMB_DIALECT_NTLM0_12 &&
	    sv->sv_maxtx < 4096 &&
	    (sv->sv_caps & SMB_CAP_NT_SMBS) == 0) {
		ctx->ct_vcflags |= SMBV_WIN95;
		DPRINT("Win95 detected");
	}

	/*
	 * The rest of the message varies depending on
	 * whether we've negotiated "extended security".
	 *
	 * With extended security, we have:
	 *	Server_GUID	(length 16)
	 *	Security_BLOB
	 * Otherwise we have:
	 *	EncryptionKey (length is eklen)
	 *	PrimaryDomain
	 */
	if (sv->sv_caps & SMB_CAP_EXT_SECURITY) {
		struct mbuf *m;
		DPRINT("Ext.Security: yes");

		/*
		 * Skip the server GUID.
		 */
		err = md_get_mem(mbp, NULL, SMB_GUIDLEN, MB_MSYSTEM);
		if (err)
			goto errout;
		/*
		 * Remainder is the security blob.
		 * Note: eklen "must be ignored" [MS-SMB]
		 */
		len = (int)bc - SMB_GUIDLEN;
		if (len < 0)
			goto errout;

		/*
		 * Get the (optional) SPNEGO "hint".
		 */
		err = md_get_mbuf(mbp, len, &m);
		if (err)
			goto errout;
		mb_initm(oblob, m);
		oblob->mb_count = len;
	} else {
		DPRINT("Ext.Security: no");
		ctx->ct_hflags2 &= ~SMB_FLAGS2_EXT_SEC;

		/*
		 * Save the "Encryption Key" (the challenge).
		 *
		 * Sanity check: make sure the sec. blob length
		 * isn't bigger than the byte count.
		 */
		if (bc < eklen || eklen < NTLM_CHAL_SZ) {
			err = EBADRPC;
			goto errout;
		}
		err = md_get_mem(mbp, ctx->ct_srv_chal,
		    NTLM_CHAL_SZ, MB_MSYSTEM);
		/*
		 * Server domain follows (ignored)
		 * Note: NOT aligned(2) - unusual!
		 */
	}

	smb_rq_done(rqp);

	/*
	 * A few sanity checks on what we received,
	 * becuse we will send these in ssnsetup.
	 *
	 * Maximum outstanding requests (we care),
	 * and Max. VCs (we only use one).  Also,
	 * MaxBufferSize lower limit per spec.
	 */
	if (sv->sv_maxmux < 1)
		sv->sv_maxmux = 1;
	if (sv->sv_maxvcs < 1)
		sv->sv_maxvcs = 1;
	if (sv->sv_maxtx < 1024)
		sv->sv_maxtx = 1024;

	/*
	 * Maximum transfer size.
	 * Sanity checks:
	 *
	 * Let's be conservative about an upper limit here.
	 * Win2k uses 16644 (and others) so 32k should be a
	 * reasonable sanity limit for this value.
	 *
	 * Note that this limit does NOT affect READX/WRITEX
	 * with CAP_LARGE_..., which we nearly always use.
	 */
	is->is_txmax = sv->sv_maxtx;
	if (is->is_txmax > 0x8000)
		is->is_txmax = 0x8000;

	/*
	 * Max read/write sizes, WITHOUT overhead.
	 * This is just the payload size, so we must
	 * leave room for the SMB headers, etc.
	 * This is just the ct_txmax value, but
	 * reduced and rounded down.  Tricky bit:
	 *
	 * Servers typically give us a value that's
	 * some nice "round" number, i.e 0x4000 plus
	 * some overhead, i.e. Win2k: 16644==0x4104
	 * Subtract for the SMB header (32) and the
	 * SMB command word and byte vectors (34?),
	 * then round down to a 512 byte multiple.
	 */
	len = is->is_txmax - 68;
	len &= 0xFE00;
	/* XXX: Not sure yet which of these to keep. */
	is->is_rwmax = len;
	is->is_rxmax = len;
	is->is_wxmax = len;

	/*
	 * Most of the "capability" bits we offer in session setup
	 * are just copied from those offered by the server.
	 */
	ctx->ct_clnt_caps = sv->sv_caps & smb_clnt_caps_mask;

	/* Get the client nonce. */
	(void) smb_get_urandom(ctx->ct_clnonce, NTLM_CHAL_SZ);

	return (0);

errout:
	smb_rq_done(rqp);
	if (err == 0)
		err = EBADRPC;
	return (err);
}
