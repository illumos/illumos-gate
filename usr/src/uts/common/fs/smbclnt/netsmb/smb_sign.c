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
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
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

#ifdef DEBUG
/*
 * Set this to a small number to debug sequence numbers
 * that seem to get out of step.
 */
int nsmb_signing_fudge = 0;
#endif

/* Mechanism definitions */
static  crypto_mechanism_t crypto_mech_md5 = { CRYPTO_MECH_INVALID };

void
smb_crypto_mech_init(void)
{
	crypto_mech_md5.cm_type = crypto_mech2id(SUN_CKM_MD5);
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
	crypto_context_t crypto_ctx;
	crypto_data_t key;
	crypto_data_t data;
	crypto_data_t digest;
	uchar_t mac[16];
	int status;
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

	ASSERT(mp != NULL);
	ASSERT(MBLKL(mp) >= SMB_HDRLEN);
	ASSERT(vcp->vc_mackey != NULL);

	/*
	 * Make an aligned copy of the SMB header
	 * and fill in the sequence number.
	 */
	bcopy(mp->b_rptr, smbhdr.r.raw, SMB_HDRLEN);
	smbhdr.s.sig[0] = htolel(seqno);
	smbhdr.s.sig[1] = 0;

	/*
	 * Compute the MAC: MD5(concat(Key, message))
	 */
	if (crypto_mech_md5.cm_type == CRYPTO_MECH_INVALID) {
		SMBSDEBUG("crypto_mech_md5 invalid\n");
		return (CRYPTO_MECHANISM_INVALID);
	}
	status = crypto_digest_init(&crypto_mech_md5, &crypto_ctx, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest the MAC Key */
	key.cd_format = CRYPTO_DATA_RAW;
	key.cd_offset = 0;
	key.cd_length = vcp->vc_mackeylen;
	key.cd_miscdata = 0;
	key.cd_raw.iov_base = (char *)vcp->vc_mackey;
	key.cd_raw.iov_len = vcp->vc_mackeylen;
	status = crypto_digest_update(crypto_ctx, &key, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest the (copied) SMB header */
	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_offset = 0;
	data.cd_length = SMB_HDRLEN;
	data.cd_miscdata = 0;
	data.cd_raw.iov_base = (char *)smbhdr.r.raw;
	data.cd_raw.iov_len = SMB_HDRLEN;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Digest rest of the SMB message. */
	data.cd_format = CRYPTO_DATA_MBLK;
	data.cd_offset = SMB_HDRLEN;
	data.cd_length = msgdsize(mp) - SMB_HDRLEN;
	data.cd_miscdata = 0;
	data.cd_mp = mp;
	status = crypto_digest_update(crypto_ctx, &data, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/* Final */
	digest.cd_format = CRYPTO_DATA_RAW;
	digest.cd_offset = 0;
	digest.cd_length = sizeof (mac);
	digest.cd_miscdata = 0;
	digest.cd_raw.iov_base = (char *)mac;
	digest.cd_raw.iov_len = sizeof (mac);
	status = crypto_digest_final(crypto_ctx, &digest, 0);
	if (status != CRYPTO_SUCCESS)
		return (status);

	/*
	 * Finally, store the signature.
	 * (first 8 bytes of the mac)
	 */
	if (signature)
		bcopy(mac, signature, SMBSIGLEN);

	return (0);
}

/*
 * Sign a request with HMAC-MD5.
 */
int
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
			return (0);
	}
	sigloc = mp->b_rptr + SMBSIGOFF;

	if (vcp->vc_mackey == NULL) {
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
	status = smb_compute_MAC(vcp, mp, rqp->sr_seqno, sigloc);
	if (status != CRYPTO_SUCCESS) {
		SMBSDEBUG("Crypto error %d", status);
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
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *mp = rqp->sr_rp.md_top;
	uint8_t sigbuf[SMBSIGLEN];
	uint8_t *sigloc;
	int status;
	int fudge;

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

	SMBSDEBUG("sr_rseqno = 0x%x\n", rqp->sr_rseqno);

	status = smb_compute_MAC(vcp, mp, rqp->sr_rseqno, sigbuf);
	if (status != CRYPTO_SUCCESS) {
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

	SMBSDEBUG("BAD signature, MID=0x%x\n", rqp->sr_mid);

#ifdef DEBUG
	/*
	 * For diag purposes, we check whether the client/server idea
	 * of the sequence # has gotten a bit out of sync.
	 */
	for (fudge = 1; fudge <= nsmb_signing_fudge; fudge++) {
		smb_compute_MAC(vcp, mp, rqp->sr_rseqno + fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0)
			break;
		smb_compute_MAC(vcp, mp, rqp->sr_rseqno - fudge, sigbuf);
		if (bcmp(sigbuf, sigloc, SMBSIGLEN) == 0) {
			fudge = -fudge;
			break;
		}
	}
	if (fudge <= nsmb_signing_fudge) {
		SMBSDEBUG("sr_rseqno=%d, but %d would have worked\n",
		    rqp->sr_rseqno, rqp->sr_rseqno + fudge);
	}
#endif
	return (EBADRPC);
}
