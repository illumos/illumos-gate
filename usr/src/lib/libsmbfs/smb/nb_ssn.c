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
 */

/*
 * NetBIOS session service functions
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>
#include <netsmb/mchain.h>

#include "private.h"
#include "charsets.h"

static int nb_ssn_send(struct smb_ctx *, struct mbdata *, int, int);
static int nb_ssn_recv(struct smb_ctx *, struct mbdata *, int *, int *);
static int nb_ssn_pollin(struct smb_ctx *, int);

/*
 * Send a data message.
 */
int
smb_ssn_send(struct smb_ctx *ctx, struct mbdata *mbp)
{
	return (nb_ssn_send(ctx, mbp, 0, mbp->mb_count));
}

/*
 * Send a NetBIOS message, after
 * prepending the 4-byte header.
 */
static int
nb_ssn_send(struct smb_ctx *ctx, struct mbdata *mbp,
	    int mtype, int mlen)
{
	mbuf_t *m;
	uint32_t hdr, hdrbuf;
	int err;

	m = mbp->mb_top;
	if (m == NULL)
		return (EINVAL);

	/*
	 * Prepend the NetBIOS header.
	 * Our mbufs leave space for this.
	 */
	hdr = (mtype << 24) | mlen;
	hdrbuf = htonl(hdr);
	m->m_data -= 4;
	m->m_len  += 4;
	bcopy(&hdrbuf, m->m_data, 4);

	/*
	 * Get contiguous data (so TCP won't fragment)
	 * Note: replaces mb_top.
	 */
	err = m_lineup(mbp->mb_top, &mbp->mb_top);
	if (err)
		return (err);
	m = mbp->mb_top;

	/*
	 * Send it.
	 */
	if (t_snd(ctx->ct_tran_fd, m->m_data, m->m_len, 0) < 0) {
		if (t_errno == TSYSERR)
			err = errno;
		else
			err = EPROTO;
		DPRINT("t_snd: t_errno %d, err %d", t_errno, err);
		return (err);
	}

	return (0);
}

/*
 * Receive a data message.  Discard anything else.
 * Caller must deal with EAGAIN, EINTR.
 */
int
smb_ssn_recv(struct smb_ctx *ctx, struct mbdata *mbp)
{
	int err, mtype, mlen;
	err = nb_ssn_recv(ctx, mbp, &mtype, &mlen);
	if (err)
		return (err);
	if (mtype != NB_SSN_MESSAGE) {
		DPRINT("discard type 0x%x", mtype);
		mb_done(mbp);
		return (EAGAIN);
	}
	if (mlen == 0) {
		DPRINT("zero length");
		mb_done(mbp);
		return (EAGAIN);
	}

	return (0);
}

/*
 * Receive a NetBIOS message, any type.
 * Give caller type and length.
 */
static int
nb_ssn_recv(struct smb_ctx *ctx, struct mbdata *mb,
	    int *mtype, int *mlen)
{
	char *buf;
	uint32_t hdr, hdrbuf;
	int cnt, len, err, moreflag;
	int fd = ctx->ct_tran_fd;
	int tmo = smb_recv_timeout * 1000;

	/*
	 * Start by getting the header
	 * (four bytes)
	 */
	if ((err = nb_ssn_pollin(ctx, tmo)) != 0) {
		DPRINT("pollin err %d", err);
		return (err);
	}
	moreflag = 0;
	cnt = t_rcv(fd, &hdrbuf, sizeof (hdrbuf), &moreflag);
	if (cnt < 0) {
		err = get_xti_err(fd);
		DPRINT("t_errno %d err %d", t_errno, err);
		return (err);
	}

	if (cnt != sizeof (hdrbuf)) {
		DPRINT("hdr cnt %d", cnt);
		return (EPROTO);
	}

	/*
	 * Decode the header, get the length.
	 */
	hdr = ntohl(hdrbuf);
	*mtype = (hdr >> 24) & 0xff;
	*mlen = hdr & 0xffffff;

	if (mlen == 0)
		return (0);

	/*
	 * Get a message buffer, read the payload
	 */
	if ((err = mb_init_sz(mb, *mlen)) != 0)
		return (err);
	buf = mb->mb_top->m_data;
	len = *mlen;
	while (len > 0) {
		if (!moreflag) {
			if ((err = nb_ssn_pollin(ctx, tmo)) != 0) {
				DPRINT("pollin err %d", err);
				return (err);
			}
		}

		moreflag = 0;
		cnt = t_rcv(fd, buf, len, &moreflag);
		if (cnt < 0) {
			err = get_xti_err(fd);
			DPRINT("t_errno %d err %d", t_errno, err);
			return (err);
		}
		buf += cnt;
		len -= cnt;
	}
	mb->mb_top->m_len = *mlen;
	mb->mb_count = *mlen;

	return (0);
}

int
get_xti_err(int fd)
{
	int look;
	if (t_errno == TSYSERR)
		return (errno);

	if (t_errno == TLOOK) {
		look = t_look(fd);
		switch (look) {
		case T_DISCONNECT:
			(void) t_rcvdis(fd, NULL);
			(void) t_snddis(fd, NULL);
			return (ECONNRESET);
		case T_ORDREL:
			/* Received orderly release indication */
			(void) t_rcvrel(fd);
			/* Send orderly release indicator */
			(void) t_sndrel(fd);
			return (ECONNRESET);
		}
	}
	return (EPROTO);
}

/*
 * Wait for data we can receive.
 * Timeout is mSec., as for poll(2)
 */
static int
nb_ssn_pollin(struct smb_ctx *ctx, int tmo)
{
	struct pollfd pfd[1];
	int cnt, err;

	pfd[0].fd = ctx->ct_tran_fd;
	pfd[0].events = POLLIN | POLLPRI;
	pfd[0].revents = 0;
	cnt = poll(pfd, 1, tmo);
	switch (cnt) {
	case 0:
		err = ETIME;
		break;
	case -1:
		err = errno;
		break;
	default:
		err = 0;
		break;
	}
	return (err);
}

/*
 * Send a NetBIOS session request and
 * wait for the response.
 */
int
nb_ssn_request(struct smb_ctx *ctx, char *srvname)
{
	struct mbdata req, res;
	struct nb_name lcl, srv;
	int err, mtype, mlen;
	char *ucwks;

	bzero(&req, sizeof (req));
	bzero(&res, sizeof (res));

	if ((err = mb_init(&req)) != 0)
		goto errout;

	ucwks = utf8_str_toupper(ctx->ct_locname);
	if (ucwks == NULL) {
		err = ENOMEM;
		goto errout;
	}

	/* Local NB name. */
	snprintf(lcl.nn_name, NB_NAMELEN, "%-15.15s", ucwks);
	lcl.nn_type = NBT_WKSTA;
	lcl.nn_scope = ctx->ct_nb->nb_scope;

	/* Server NB name */
	snprintf(srv.nn_name, NB_NAMELEN, "%-15.15s", srvname);
	srv.nn_type = NBT_SERVER;
	srv.nn_scope = ctx->ct_nb->nb_scope;

	/*
	 * Build the request.  Header is prepended later.
	 */
	if ((err = nb_name_encode(&req, &srv)) != 0)
		goto errout;
	if ((err = nb_name_encode(&req, &lcl)) != 0)
		goto errout;

	/*
	 * Send it, wait for the reply.
	 */
	err = nb_ssn_send(ctx, &req, NB_SSN_REQUEST, req.mb_count);
	if (err) {
		DPRINT("send, err %d", err);
		goto errout;
	}
	err = nb_ssn_recv(ctx, &res, &mtype, &mlen);
	if (err) {
		DPRINT("recv, err %d", err);
		goto errout;
	}

	if (mtype != NB_SSN_POSRESP) {
		DPRINT("recv, mtype 0x%x", mtype);
		err = ECONNREFUSED;
		goto errout;
	}

	return (0);

errout:
	mb_done(&res);
	mb_done(&req);
	return (err);
}
