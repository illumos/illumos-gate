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
 * Signing support, using libmd
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/md5.h>

#include <netsmb/mchain.h>
#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>

#include "private.h"

#define	SMBSIGOFF	14	/* SMB signature offset */
#define	SMBSIGLEN	8	/* SMB signature length */

/*
 * Set this to a small number to debug sequence numbers
 * that seem to get out of step.
 */
#ifdef DEBUG
int nsmb_signing_fudge = 4;
#endif

/*
 * Compute MD5 digest of packet data, using the stored MAC key.
 *
 * See similar code in the driver:
 *	uts/common/fs/smbclnt/netsmb/smb_signing.c
 * and on the server side:
 *	uts/common/fs/smbsrv/smb_signing.c
 */
static int
smb_compute_MAC(struct smb_ctx *ctx, mbuf_t *m,
	uint32_t seqno, uchar_t *signature)
{
	MD5_CTX md5;
	uchar_t digest[MD5_DIGEST_LENGTH];

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
			uint8_t hdr[SMBSIGOFF]; /* sig. offset (14) */
			uint32_t sig[2]; /* MAC signature, aligned! */
			uint16_t ids[5]; /* pad, Tid, Pid, Uid, Mid */
		} s;
	} smbhdr;

	if (m->m_len < SMB_HDRLEN)
		return (EIO);
	if (ctx->ct_mackey == NULL)
		return (EINVAL);

	/*
	 * Make an aligned copy of the SMB header
	 * and fill in the sequence number.
	 */
	bcopy(m->m_data, smbhdr.r.raw, SMB_HDRLEN);
	smbhdr.s.sig[0] = htolel(seqno);
	smbhdr.s.sig[1] = 0;

	/*
	 * Compute the MAC: MD5(concat(Key, message))
	 */
	MD5Init(&md5);

	/* Digest the MAC Key */
	MD5Update(&md5, ctx->ct_mackey, ctx->ct_mackeylen);

	/* Digest the (copied) SMB header */
	MD5Update(&md5, smbhdr.r.raw, SMB_HDRLEN);

	/* Digest the rest of the first mbuf */
	if (m->m_len > SMB_HDRLEN) {
		MD5Update(&md5, m->m_data + SMB_HDRLEN,
		    m->m_len - SMB_HDRLEN);
	}
	m = m->m_next;

	/* Digest rest of the SMB message. */
	while (m) {
		MD5Update(&md5, m->m_data, m->m_len);
		m = m->m_next;
	}

	/* Final */
	MD5Final(digest, &md5);

	/*
	 * Finally, store the signature.
	 * (first 8 bytes of the digest)
	 */
	if (signature)
		bcopy(digest, signature, SMBSIGLEN);

	return (0);
}

/*
 * Sign a request with HMAC-MD5.
 */
int
smb_rq_sign(struct smb_rq *rqp)
{
	struct smb_ctx *ctx = rqp->rq_ctx;
	mbuf_t *m = rqp->rq_rq.mb_top;
	uint8_t *sigloc;
	int err;

	/*
	 * Our mblk allocation ensures this,
	 * but just in case...
	 */
	if (m->m_len < SMB_HDRLEN)
		return (EIO);
	sigloc = (uchar_t *)m->m_data + SMBSIGOFF;

	if (ctx->ct_mackey == NULL) {
		/*
		 * Signing is required, but we have no key yet
		 * fill in with the magic fake signing value.
		 * This happens with SPNEGO, NTLMSSP, ...
		 */
		bcopy("BSRSPLY", sigloc, 8);
		return (0);
	}

	/*
	 * This will compute the MAC and store it
	 * directly into the message at sigloc.
	 */
	rqp->rq_seqno = ctx->ct_mac_seqno;
	ctx->ct_mac_seqno += 2;
	err = smb_compute_MAC(ctx, m, rqp->rq_seqno, sigloc);
	if (err) {
		DPRINT("compute MAC, err %d", err);
		bzero(sigloc, SMBSIGLEN);
		return (ENOTSUP);
	}
	return (0);
}

/*
 * Verify reply signature.
 */
int
smb_rq_verify(struct smb_rq *rqp)
{
	struct smb_ctx *ctx = rqp->rq_ctx;
	mbuf_t *m = rqp->rq_rp.mb_top;
	uint8_t sigbuf[SMBSIGLEN];
	uint8_t *sigloc;
	uint32_t rseqno;
	int err, fudge;

	/*
	 * Note ct_mackey and ct_mackeylen gets initialized by
	 * smb_smb_ssnsetup.  It's normal to have a null MAC key
	 * during extended security session setup.
	 */
	if (ctx->ct_mackey == NULL)
		return (0);

	/*
	 * Let caller deal with empty reply or short messages by
	 * returning zero.  Caller will fail later, in parsing.
	 */
	if (m == NULL) {
		DPRINT("empty reply");
		return (0);
	}
	if (m->m_len < SMB_HDRLEN) {
		DPRINT("short reply");
		return (0);
	}

	sigloc = (uchar_t *)m->m_data + SMBSIGOFF;
	rseqno = rqp->rq_seqno + 1;

	DPRINT("rq_rseqno = 0x%x", rseqno);

	err = smb_compute_MAC(ctx, m, rseqno, sigbuf);
	if (err) {
		DPRINT("compute MAC, err %d", err);
		/*
		 * If we can't compute a MAC, then there's
		 * no point trying other seqno values.
		 */
		return (EBADRPC);
	}

	/*
	 * Compare the computed signature with the
	 * one found in the message (at sigloc)
	 */
	if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
		return (0);

	DPRINT("BAD signature, MID=0x%x", rqp->rq_mid);

#ifdef DEBUG
	/*
	 * For diag purposes, we check whether the client/server idea
	 * of the sequence # has gotten a bit out of sync.
	 */
	for (fudge = 1; fudge <= nsmb_signing_fudge; fudge++) {
		smb_compute_MAC(ctx, m, rseqno + fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
			break;
		smb_compute_MAC(ctx, m, rseqno - fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0) {
			fudge = -fudge;
			break;
		}
	}
	if (fudge <= nsmb_signing_fudge) {
		DPRINT("rseqno=%d, but %d would have worked",
		    rseqno, rseqno + fudge);
	}
#endif
	return (EBADRPC);
}
