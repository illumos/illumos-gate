/*
 * Copyright (c) 2000, Boris Popov
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
 *
 * $Id: rq.c,v 1.4 2004/12/13 00:25:23 lindak Exp $
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sysexits.h>
#include <libintl.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include "private.h"

#define	MIN_REPLY_SIZE 4096

static uint32_t smb_map_doserr(uint8_t, uint16_t);

/*
 * Create and initialize a request structure, for either an
 * "internal" request (one that does not use the driver) or
 * a regular "driver" request, that uses driver ioctls.
 *
 * The two kinds are built a little differently:
 * Driver requests are composed starting with the
 * first word of the "variable word vector" section.
 * The driver prepends the SMB header and word count.
 * The driver also needs an output buffer to receive
 * the response, filled in via copyout in the ioctl.
 *
 * Internal requests are composed entirely in this library.
 * Space for the SMB header is reserved here, and later
 * filled in by smb_rq_internal before the send/receive.
 */
int
smb_rq_init(struct smb_ctx *ctx, uchar_t cmd, struct smb_rq **rqpp)
{
	struct smb_rq *rqp;

	rqp = malloc(sizeof (*rqp));
	if (rqp == NULL)
		goto errout;
	bzero(rqp, sizeof (*rqp));
	rqp->rq_cmd = cmd;
	rqp->rq_ctx = ctx;

	/*
	 * Setup the request buffer.
	 * Do the reply buffer later.
	 */
	if (mb_init(&rqp->rq_rq))
		goto errout;

	/* Space for the SMB header. (filled in later) */
	mb_put_mem(&rqp->rq_rq, NULL, SMB_HDRLEN, MB_MSYSTEM);

	/*
	 * Copy the ctx flags here, so the caller can
	 * update the req flags before the OTW call.
	 */
	rqp->rq_hflags = ctx->ct_hflags;
	rqp->rq_hflags2 = ctx->ct_hflags2;

	*rqpp = rqp;
	return (0);

errout:
	if (rqp) {
		smb_rq_done(rqp);
		free(rqp);
	}
	return (ENOMEM);
}

void
smb_rq_done(struct smb_rq *rqp)
{
	mb_done(&rqp->rq_rp);
	mb_done(&rqp->rq_rq);
	free(rqp);
}

/*
 * Reserve space for the word count, which is filled in later by
 * smb_rq_wend().  Also initialize the counter that it uses
 * to figure out what value to fill in.
 *
 * Note that the word count happens to be 8-bits,
 * which can lead to confusion.
 */
void
smb_rq_wstart(struct smb_rq *rqp)
{
	struct mbdata *mbp = &rqp->rq_rq;

	(void) mb_fit(mbp, 1, &rqp->rq_wcntp);
	rqp->rq_wcbase = mbp->mb_count;
}

/*
 * Fill in the word count, in the space reserved by
 * smb_rq_wstart().
 */
void
smb_rq_wend(struct smb_rq *rqp)
{
	struct mbdata *mbp = &rqp->rq_rq;
	int wcnt;

	if (rqp->rq_wcntp == NULL) {
		DPRINT("no wcount ptr\n");
		return;
	}
	wcnt = mbp->mb_count - rqp->rq_wcbase;
	if (wcnt > 0x1ff)
		DPRINT("word count too large (%d)\n", wcnt);
	if (wcnt & 1)
		DPRINT("odd word count\n");
	wcnt >>= 1;

	/*
	 * Fill in the word count (8-bits).
	 * Also store it in the rq, in case
	 * we're using the ioctl path.
	 */
	*rqp->rq_wcntp = (char)wcnt;
}

/*
 * Reserve space for the byte count, which is filled in later by
 * smb_rq_bend().  Also initialize the counter that it uses
 * to figure out what value to fill in.
 *
 * Note that the byte count happens to be 16-bits,
 * which can lead to confusion.
 */
void
smb_rq_bstart(struct smb_rq *rqp)
{
	struct mbdata *mbp = &rqp->rq_rq;

	(void) mb_fit(mbp, 2, &rqp->rq_bcntp);
	rqp->rq_bcbase = mbp->mb_count;
}

/*
 * Fill in the byte count, in the space reserved by
 * smb_rq_bstart().
 */
void
smb_rq_bend(struct smb_rq *rqp)
{
	struct mbdata *mbp = &rqp->rq_rq;
	int bcnt;

	if (rqp->rq_bcntp == NULL) {
		DPRINT("no bcount ptr\n");
		return;
	}
	bcnt = mbp->mb_count - rqp->rq_bcbase;
	if (bcnt > 0xffff)
		DPRINT("byte count too large (%d)\n", bcnt);
	/*
	 * Fill in the byte count (16-bits).
	 * Also store it in the rq, in case
	 * we're using the ioctl path.
	 *
	 * The pointer is char * type due to
	 * typical off-by-one alignment.
	 */
	rqp->rq_bcntp[0] = bcnt & 0xFF;
	rqp->rq_bcntp[1] = (bcnt >> 8);
}

int
smb_rq_simple(struct smb_rq *rqp)
{
	struct smbioc_rq krq;
	struct mbdata *mbp;
	mbuf_t *m;
	char *data;
	uint32_t len;
	size_t rpbufsz;
	int error;

	bzero(&krq, sizeof (krq));
	krq.ioc_cmd = rqp->rq_cmd;

	/*
	 * Make the SMB request body contiguous,
	 * and fill in the ioctl request.
	 */
	mbp = smb_rq_getrequest(rqp);
	error = m_lineup(mbp->mb_top, &mbp->mb_top);
	if (error)
		return (error);

	data = mtod(mbp->mb_top, char *);
	len = m_totlen(mbp->mb_top);

	/*
	 * _rq_init left space for the SMB header,
	 * which makes mb_count the offset from
	 * the beginning of the header (useful).
	 * However, in this code path the driver
	 * prepends the header, so we skip it.
	 */
	krq.ioc_tbufsz = len - SMB_HDRLEN;
	krq.ioc_tbuf  = data + SMB_HDRLEN;

	/*
	 * Setup a buffer to hold the reply,
	 * at least MIN_REPLY_SIZE, or larger
	 * if the caller increased rq_rpbufsz.
	 */
	mbp = smb_rq_getreply(rqp);
	rpbufsz = rqp->rq_rpbufsz;
	if (rpbufsz < MIN_REPLY_SIZE)
		rpbufsz = MIN_REPLY_SIZE;
	if ((error = m_get(rpbufsz, &m)) != 0)
		return (error);
	mb_initm(mbp, m);
	krq.ioc_rbufsz = rpbufsz;
	krq.ioc_rbuf = mtod(m, char *);

	/*
	 * Call the driver
	 */
	if (nsmb_ioctl(rqp->rq_ctx->ct_dev_fd, SMBIOC_REQUEST, &krq) == -1)
		return (errno);

	/*
	 * Initialize returned mbdata.
	 * SMB header already parsed.
	 */
	m->m_len = krq.ioc_rbufsz;

	return (0);
}


int
smb_t2_request(int dev_fd, int setupcount, uint16_t *setup,
	const char *name,
	int tparamcnt, void *tparam,
	int tdatacnt, void *tdata,
	int *rparamcnt, void *rparam,
	int *rdatacnt, void *rdata,
	int *buffer_oflow)
{
	smbioc_t2rq_t *krq;
	int i;

	krq = (smbioc_t2rq_t *)malloc(sizeof (smbioc_t2rq_t));
	bzero(krq, sizeof (*krq));

	if (setupcount < 0 || setupcount >= SMBIOC_T2RQ_MAXSETUP) {
		/* Bogus setup count, or too many setup words */
		return (EINVAL);
	}
	for (i = 0; i < setupcount; i++)
		krq->ioc_setup[i] = setup[i];
	krq->ioc_setupcnt = setupcount;
	strcpy(krq->ioc_name, name);
	krq->ioc_tparamcnt = tparamcnt;
	krq->ioc_tparam = tparam;
	krq->ioc_tdatacnt = tdatacnt;
	krq->ioc_tdata = tdata;

	krq->ioc_rparamcnt = *rparamcnt;
	krq->ioc_rdatacnt = *rdatacnt;
	krq->ioc_rparam = rparam;
	krq->ioc_rdata  = rdata;

	if (nsmb_ioctl(dev_fd, SMBIOC_T2RQ, krq) == -1) {
		return (errno);
	}

	*rparamcnt = krq->ioc_rparamcnt;
	*rdatacnt = krq->ioc_rdatacnt;
	*buffer_oflow = (krq->ioc_rpflags2 & SMB_FLAGS2_ERR_STATUS) &&
	    (krq->ioc_error == NT_STATUS_BUFFER_OVERFLOW);
	free(krq);

	return (0);
}


/*
 * Do an over-the-wire call without using the nsmb driver.
 * This is all "internal" to this library, and used only
 * for connection setup (negotiate protocol, etc.)
 */
int
smb_rq_internal(struct smb_ctx *ctx, struct smb_rq *rqp)
{
	static const uint8_t ffsmb[4] = SMB_SIGNATURE;
	struct smb_iods *is = &ctx->ct_iods;
	uint32_t sigbuf[2];
	struct mbdata mbtmp, *mbp;
	int err, save_mlen;
	uint8_t ctmp;

	rqp->rq_uid = is->is_smbuid;
	rqp->rq_tid = SMB_TID_UNKNOWN;
	rqp->rq_mid = is->is_next_mid++;

	/*
	 * Fill in the NBT and SMB headers
	 * Using mbtmp so we can rewind without
	 * affecting the passed request mbdata.
	 */
	bcopy(&rqp->rq_rq, &mbtmp, sizeof (mbtmp));
	mbp = &mbtmp;
	mbp->mb_cur = mbp->mb_top;
	mbp->mb_pos = mbp->mb_cur->m_data;
	mbp->mb_count = 0;
	/* Have to save and restore m_len */
	save_mlen = mbp->mb_cur->m_len;
	mbp->mb_cur->m_len = 0;

	/*
	 * rewind done; fill it in
	 */
	mb_put_mem(mbp, ffsmb, SMB_SIGLEN, MB_MSYSTEM);
	mb_put_uint8(mbp, rqp->rq_cmd);
	mb_put_uint32le(mbp, 0);	/* status */
	mb_put_uint8(mbp, rqp->rq_hflags);
	mb_put_uint16le(mbp, rqp->rq_hflags2);
	/* pid_hi(2), signature(8), reserved(2) */
	mb_put_mem(mbp, NULL, 12, MB_MZERO);
	mb_put_uint16le(mbp, rqp->rq_tid);
	mb_put_uint16le(mbp, 0);	/* pid_lo */
	mb_put_uint16le(mbp, rqp->rq_uid);
	mb_put_uint16le(mbp, rqp->rq_mid);

	/* Restore original m_len */
	mbp->mb_cur->m_len = save_mlen;

	/*
	 * Sign the message, if flags2 indicates.
	 */
	if (rqp->rq_hflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
		smb_rq_sign(rqp);
	}

	/*
	 * Send it, wait for the reply.
	 */
	if ((err = smb_ssn_send(ctx, &rqp->rq_rq)) != 0)
		return (err);

	if ((err = smb_ssn_recv(ctx, &rqp->rq_rp)) != 0)
		return (err);

	/*
	 * Should have an SMB header, at least.
	 */
	mbp = &rqp->rq_rp;
	if (mbp->mb_cur->m_len < SMB_HDRLEN) {
		DPRINT("len < 32");
		return (EBADRPC);
	}

	/*
	 * If the request was signed, validate the
	 * signature on the response.
	 */
	if (rqp->rq_hflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
		err = smb_rq_verify(rqp);
		if (err) {
			DPRINT("bad signature");
			return (err);
		}
	}

	/*
	 * Decode the SMB header.
	 */
	md_get_mem(mbp, (char *)sigbuf, 4, MB_MSYSTEM);
	if (0 != bcmp(sigbuf, ffsmb, 4)) {
		DPRINT("not SMB");
		return (EBADRPC);
	}
	md_get_uint8(mbp, &ctmp);	/* SMB cmd */
	md_get_uint32le(mbp, &rqp->rq_status);
	md_get_uint8(mbp, &rqp->rq_hflags);
	md_get_uint16le(mbp, &rqp->rq_hflags2);
	/* pid_hi(2), signature(8), reserved(2) */
	md_get_mem(mbp, NULL, 12, MB_MSYSTEM);
	md_get_uint16le(mbp, &rqp->rq_tid);
	md_get_uint16le(mbp, NULL);	/* pid_lo */
	md_get_uint16le(mbp, &rqp->rq_uid);
	md_get_uint16le(mbp, &rqp->rq_mid);

	/*
	 * Figure out the status return.
	 * Caller looks at rq_status.
	 */
	if ((rqp->rq_hflags2 & SMB_FLAGS2_ERR_STATUS) == 0) {
		uint16_t	serr;
		uint8_t		class;

		class = rqp->rq_status & 0xff;
		serr  = rqp->rq_status >> 16;
		rqp->rq_status = smb_map_doserr(class, serr);
	}

	return (0);
}

/*
 * Map old DOS errors (etc.) to NT status codes.
 * We probably don't need this anymore, since
 * the oldest server we talk to is NT.  But if
 * later find we do need this, add support here
 * for the DOS errors we care about.
 */
static uint32_t
smb_map_doserr(uint8_t class, uint16_t serr)
{
	if (class == 0 && serr == 0)
		return (0);

	DPRINT("class 0x%x serr 0x%x", (int)class, (int)serr);
	return (NT_STATUS_UNSUCCESSFUL);
}
