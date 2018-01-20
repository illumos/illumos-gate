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
 */

/*
 * Support for SMB "signing" (message integrity)
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

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_signing.h>

#ifdef DEBUG
/*
 * Set this to a small number to debug sequence numbers
 * that seem to get out of step.
 */
int nsmb_signing_fudge = 0;
#endif

/* Mechanism definitions */
static  smb_sign_mech_t smb_mech_md5;

void
smb_crypto_mech_init(void)
{
	if (smb_md5_getmech(&smb_mech_md5) != 0)
		cmn_err(CE_NOTE, "nsmb can't get md5 mech");
}

/*
 * This is called just after session setup completes,
 * at the top of smb_iod_vc_work().  Initialize signing.
 */
int
smb_sign_init(smb_vc_t *vcp)
{

	ASSERT(vcp->vc_ssnkey != NULL);
	ASSERT(vcp->vc_mackey == NULL);

	/*
	 * Convert the session key to the MAC key.
	 * SMB1 uses the whole session key.
	 */
	vcp->vc_mackeylen = vcp->vc_ssnkeylen;
	vcp->vc_mackey = kmem_zalloc(vcp->vc_mackeylen, KM_SLEEP);
	bcopy(vcp->vc_ssnkey, vcp->vc_mackey, vcp->vc_mackeylen);

	/* The initial sequence number is two. */
	vcp->vc_next_seq = 2;

	return (0);
}


#define	SMBSIGLEN	8	/* SMB signature length */
#define	SMBSIGOFF	14	/* SMB signature offset */

/*
 * Compute HMAC-MD5 of packet data, using the stored MAC key.
 *
 * See similar code for the server side:
 * uts/common/fs/smbsrv/smb_signing.c : smb_sign_calc
 */
static int
smb_compute_MAC(struct smb_vc *vcp, mblk_t *mp,
	uint32_t seqno, uchar_t *signature)
{
	uchar_t digest[MD5_DIGEST_LENGTH];
	smb_sign_ctx_t ctx = 0;
	mblk_t *m = mp;
	int size;
	int rc;

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

	/* Later: check vcp->sign_mech == NULL */
	if (vcp->vc_mackey == NULL)
		return (-1);

	if ((rc = smb_md5_init(&ctx, &smb_mech_md5)) != 0)
		return (rc);

	/* Digest the MAC Key */
	rc = smb_md5_update(ctx, vcp->vc_mackey, vcp->vc_mackeylen);
	if (rc != 0)
		return (rc);

	ASSERT(m != NULL);
	ASSERT(MBLKL(m) >= SMB_HDRLEN);

	/*
	 * Make an aligned copy of the SMB header,
	 * fill in the sequence number, and digest.
	 */
	size = SMB_HDRLEN;
	if (MBLKL(m) < size)
		(void) pullupmsg(m, size);
	bcopy(m->b_rptr, smbhdr.r.raw, size);
	smbhdr.s.sig[0] = htolel(seqno);
	smbhdr.s.sig[1] = 0;

	rc = smb_md5_update(ctx, &smbhdr.r.raw, size);
	if (rc != 0)
		return (rc);

	/*
	 * Digest the rest of the SMB header packet, starting at
	 * the data just after the SMB header.
	 */
	size = MBLKL(m) - SMB_HDRLEN;
	rc = smb_md5_update(ctx, m->b_rptr + SMB_HDRLEN, size);
	if (rc != 0)
		return (rc);
	m = m->b_cont;

	/* Digest rest of the SMB message. */
	while (m != NULL) {
		size = MBLKL(m);
		if (size > 0) {
			rc = smb_md5_update(ctx, m->b_rptr, size);
			if (rc != 0)
				return (rc);
		}
		m = m->b_cont;
	}
	rc = smb_md5_final(ctx, digest);
	if (rc != 0)
		return (rc);

	/*
	 * Finally, store the signature.
	 * (first 8 bytes of the mac)
	 */
	if (signature)
		bcopy(digest, signature, SMBSIGLEN);

	return (0);
}

/*
 * Sign a request with HMAC-MD5.
 */
void
smb_rq_sign(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rq.mb_top;
	uint8_t *sigloc;
	int status;

	/*
	 * Our mblk allocation ensures this,
	 * but just in case...
	 */
	if (MBLKL(mp) < SMB_HDRLEN) {
		if (!pullupmsg(mp, SMB_HDRLEN))
			return;
	}
	sigloc = mp->b_rptr + SMBSIGOFF;

	if (vcp->vc_mackey == NULL) {
		/*
		 * Signing is required, but we have no key yet
		 * fill in with the magic fake signing value.
		 * This happens with SPNEGO, NTLMSSP, ...
		 */
		bcopy("BSRSPLY", sigloc, 8);
		return;
	}

	/*
	 * This will compute the MAC and store it
	 * directly into the message at sigloc.
	 */
	status = smb_compute_MAC(vcp, mp, rqp->sr_seqno, sigloc);
	if (status != 0) {
		SMBSDEBUG("Crypto error %d", status);
		bzero(sigloc, SMBSIGLEN);
	}
}

/*
 * Verify reply signature.
 */
int
smb_rq_verify(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rp.md_top;
	uint8_t sigbuf[SMBSIGLEN];
	uint8_t *sigloc;
	int fudge, rsn, status;

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
	if (MBLKL(mp) < SMB_HDRLEN) {
		if (!pullupmsg(mp, SMB_HDRLEN))
			return (0);
	}
	sigloc = mp->b_rptr + SMBSIGOFF;

	/*
	 * Compute the expected signature in sigbuf.
	 */
	rsn = rqp->sr_rseqno;
	status = smb_compute_MAC(vcp, mp, rsn, sigbuf);
	if (status != 0) {
		SMBSDEBUG("Crypto error %d", status);
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

	SMBERROR("BAD signature, Server=%s MID=0x%x Seq=%d\n",
	    vcp->vc_srvname, rqp->sr_mid, rsn);

#ifdef DEBUG
	/*
	 * For diag purposes, we check whether the client/server idea
	 * of the sequence # has gotten a bit out of sync.
	 */
	for (fudge = 1; fudge <= nsmb_signing_fudge; fudge++) {
		(void) smb_compute_MAC(vcp, mp, rsn + fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
			break;
		(void) smb_compute_MAC(vcp, mp, rsn - fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0) {
			fudge = -fudge;
			break;
		}
	}
	if (fudge <= nsmb_signing_fudge) {
		SMBERROR("MID=0x%x, Seq=%d, but %d would have worked\n",
		    rqp->sr_mid, rsn, rsn + fudge);
	}
#endif
	return (EBADRPC);
}
