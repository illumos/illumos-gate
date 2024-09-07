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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Support for SMB2 "signing" (message integrity)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/md4.h>
#include <sys/md5.h>
#include <sys/des.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sdt.h>

#include <netsmb/nsmb_kcrypt.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_rq.h>

#define	SMB2_SIG_OFF	48
#define	SMB2_SIG_LEN	16

typedef struct smb_mac_ops {
	int (*mac_init)(smb_sign_ctx_t *, smb_crypto_mech_t *,
			uint8_t *, size_t);
	int (*mac_update)(smb_sign_ctx_t, uint8_t *, size_t);
	int (*mac_final)(smb_sign_ctx_t, uint8_t *);
} smb_mac_ops_t;

static smb_mac_ops_t
smb2_sign_ops = {
	nsmb_hmac_init,
	nsmb_hmac_update,
	nsmb_hmac_final
};

static struct smb_mac_ops
smb3_sign_ops = {
	nsmb_cmac_init,
	nsmb_cmac_update,
	nsmb_cmac_final
};

/*
 * smb2_sign_init
 *
 * Get the mechanism info and initilize SMB2 or SMB3 signing.
 */
int
smb2_sign_init(smb_vc_t *vcp)
{
	uint_t copysize;
	int rc;

	ASSERT(vcp->vc_ssnkey != NULL);
	ASSERT(vcp->vc_mackey == NULL);

	if (SMB_DIALECT(vcp) < SMB2_DIALECT_0300)
		rc = nsmb_hmac_getmech(&vcp->vc_signmech);
	else
		rc = nsmb_cmac_getmech(&vcp->vc_signmech);
	if (rc != 0)
		return (EAUTH);

	/*
	 * Convert the session key to the MAC key.
	 *
	 * For SMB2, the signing key is just the first 16 bytes
	 * of the session key (truncated or padded with zeros).
	 * For SMB3, the signing key is a "KDF" hash of the
	 * session key.   [MS-SMB2] 3.2.5.3.1
	 */
	vcp->vc_mackeylen = SMB2_SIG_LEN;
	vcp->vc_mackey = kmem_zalloc(vcp->vc_mackeylen, KM_SLEEP);
	if (SMB_DIALECT(vcp) < SMB2_DIALECT_0300) {
		copysize = vcp->vc_ssnkeylen;
		if (copysize > vcp->vc_mackeylen)
			copysize = vcp->vc_mackeylen;
		bcopy(vcp->vc_ssnkey, vcp->vc_mackey, copysize);

		vcp->vc_sign_ops = &smb2_sign_ops;
	} else {
		rc = nsmb_kdf(vcp->vc_mackey, SMB3_KEYLEN,
		    vcp->vc_ssnkey, vcp->vc_ssnkeylen,
		    (uint8_t *)"SMB2AESCMAC", 12,
		    (uint8_t *)"SmbSign", 8);
		if (rc != 0)
			return (EAUTH);
		vcp->vc_sign_ops = &smb3_sign_ops;
	}

	return (0);
}

/*
 * Compute MAC signature of packet data, using the stored MAC key.
 *
 * The signature is in the last 16 bytes of the SMB2 header.
 * The signature algorighm is to compute HMAC SHA256 over the
 * entire command, with the signature field set to zeros.
 *
 * See similar code for the server side:
 * uts/common/fs/smbsrv/smb2_signing.c : smb2_sign_calc
 */
static int
smb2_compute_MAC(struct smb_vc *vcp, mblk_t *mp, uchar_t *signature)
{
	uint8_t tmp_hdr[SMB2_HDR_SIZE];
	smb_sign_ctx_t ctx = 0;
	smb_mac_ops_t *ops;
	mblk_t *m = mp;
	int size;
	int rc;

	if (vcp->vc_mackey == NULL)
		return (-1);
	if ((ops = vcp->vc_sign_ops) == NULL)
		return (-1);

	rc = ops->mac_init(&ctx, &vcp->vc_signmech,
	    vcp->vc_mackey, vcp->vc_mackeylen);
	if (rc != 0)
		return (rc);

	/* Our caller should ensure mp has a contiguous header */
	ASSERT(m != NULL);
	ASSERT(MBLKL(m) >= SMB2_HDRLEN);

	/*
	 * Copy of the SMB2 header, zero out the signature, and digest.
	 */
	size = SMB2_HDRLEN;
	bcopy(m->b_rptr, tmp_hdr, size);
	bzero(tmp_hdr + SMB2_SIG_OFF, SMB2_SIG_LEN);
	rc = ops->mac_update(ctx, tmp_hdr, size);
	if (rc != 0)
		return (rc);

	/*
	 * Digest the rest of the SMB2 header packet, starting at
	 * the data just after the SMB2 header.
	 */
	size = MBLKL(m) - SMB2_HDRLEN;
	rc = ops->mac_update(ctx, m->b_rptr + SMB2_HDRLEN, size);
	if (rc != 0)
		return (rc);
	m = m->b_cont;

	/* Digest rest of the SMB2 message. */
	while (m != NULL) {
		size = MBLKL(m);
		if (size > 0) {
			rc = ops->mac_update(ctx, m->b_rptr, size);
			if (rc != 0)
				return (rc);
		}
		m = m->b_cont;
	}
	rc = ops->mac_final(ctx, signature);

	return (rc);
}

/*
 * Sign a request with HMAC-MD5.
 */
void
smb2_rq_sign(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rq.mb_top;
	uint8_t *sigloc;
	int rc;

	/*
	 * smb_rq_new() ensures this,
	 * but just in case..
	 */
	ASSERT(MBLKL(mp) >= SMB2_HDRLEN);
	sigloc = mp->b_rptr + SMB2_SIG_OFF;

	if (vcp->vc_mackey == NULL)
		return;

	/*
	 * This will compute the MAC and store it
	 * directly into the message at sigloc.
	 */
	rc = smb2_compute_MAC(vcp, mp, sigloc);
	if (rc != 0) {
		SMBSDEBUG("Crypto error %d", rc);
		bzero(sigloc, SMB2_SIG_LEN);
	}
}

/*
 * Verify reply signature.
 */
int
smb2_rq_verify(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rp.md_top;
	uint8_t sigbuf[SMB2_SIG_LEN];
	uint8_t *sigloc;
	int rc;

	/*
	 * Note vc_mackey and vc_mackeylen gets filled in by
	 * smb_usr_iod_work as the connection comes in.
	 */
	if (vcp->vc_mackey == NULL) {
		SMBSDEBUG("no mac key\n");
		return (0);
	}

	/*
	 * Let caller deal with empty reply or short messages by
	 * returning zero.  Caller will fail later, in parsing.
	 */
	if (mp == NULL) {
		SMBSDEBUG("empty reply\n");
		return (0);
	}

	/* smb2_iod_process ensures this */
	ASSERT(MBLKL(mp) >= SMB2_HDRLEN);
	sigloc = mp->b_rptr + SMB2_SIG_OFF;

	/*
	 * Compute the expected signature in sigbuf.
	 */
	rc = smb2_compute_MAC(vcp, mp, sigbuf);
	if (rc != 0) {
		SMBSDEBUG("Crypto error %d", rc);
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
	if (bcmp(sigbuf, sigloc, SMB2_SIG_LEN) == 0)
		return (0);

	SMBERROR("BAD signature, Server=%s MID=0x%llx\n",
	    vcp->vc_srvname, (long long)rqp->sr2_messageid);

	return (EBADRPC);
}
