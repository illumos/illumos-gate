/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <signal.h>
#include <assert.h>
#include "tx.h"


/*
 * Snd_conn_req - send connect request message to transport provider.
 * All signals for the caller are blocked during the call to simplify design.
 * (This is OK for a bounded amount of time this routine is expected to
 * execute).  Also, assumes tiptr->ti_lock is held.
 */
int
_t_snd_conn_req(
	struct _ti_user *tiptr,
	const struct t_call *call,
	struct strbuf *ctlbufp)
{
	struct T_conn_req *creq;
	int size;
	int fd;

	assert(MUTEX_HELD(&tiptr->ti_lock));
	fd = tiptr->ti_fd;

	if (tiptr->ti_servtype == T_CLTS) {
		t_errno = TNOTSUPPORT;
		return (-1);
	}

	if (_t_is_event(fd, tiptr) < 0)
		return (-1);

	/* LINTED pointer cast */
	creq = (struct T_conn_req *)ctlbufp->buf;
	creq->PRIM_type = T_CONN_REQ;
	creq->DEST_length = call->addr.len;
	creq->DEST_offset = 0;
	creq->OPT_length = call->opt.len;
	creq->OPT_offset = 0;
	size = (int)sizeof (struct T_conn_req); /* size without any buffers */

	if (call->addr.len) {
		if (_t_aligned_copy(ctlbufp, call->addr.len, size,
		    call->addr.buf, &creq->DEST_offset) < 0) {
			/*
			 * Aligned copy will overflow buffer allocated based
			 * based on transport maximum address size.
			 * return error.
			 */
			t_errno = TBADADDR;
			return (-1);
		}
		size = creq->DEST_offset + creq->DEST_length;
	}
	if (call->opt.len) {
		if (_t_aligned_copy(ctlbufp, call->opt.len, size,
		    call->opt.buf, &creq->OPT_offset) < 0) {
			/*
			 * Aligned copy will overflow buffer allocated based
			 * on maximum option size in transport.
			 * return error.
			 */
			t_errno = TBADOPT;
			return (-1);
		}
		size = creq->OPT_offset + creq->OPT_length;
	}
	if (call->udata.len) {
		if ((tiptr->ti_cdatasize == T_INVALID /* -2 */) ||
		    ((tiptr->ti_cdatasize != T_INFINITE /* -1 */) &&
			(call->udata.len > (uint32_t)tiptr->ti_cdatasize))) {
			/*
			 * user data not valid with connect or it
			 * exceeds the limits specified by the transport
			 * provider.
			 */
			t_errno = TBADDATA;
			return (-1);
		}
	}

	ctlbufp->len = size;

	/*
	 * Assumes signals are blocked so putmsg() will not block
	 * indefinitely
	 */
	if (putmsg(fd, ctlbufp,
	    (struct strbuf *)(call->udata.len? &call->udata: NULL), 0) < 0) {
		t_errno = TSYSERR;
		return (-1);
	}

	if (_t_is_ok(fd, tiptr, T_CONN_REQ) < 0)
		return (-1);
	return (0);
}



/*
 * Rcv_conn_con - get connection confirmation off
 * of read queue
 * Note:
 *      - called holding the tiptr->ti_lock
 */
int
_t_rcv_conn_con(
	struct _ti_user *tiptr,
	struct t_call *call,
	struct strbuf *ctlbufp,
	int api_semantics)
{
	struct strbuf databuf;
	union T_primitives *pptr;
	int retval, fd, sv_errno;
	int didralloc;

	int flg = 0;

	fd = tiptr->ti_fd;

	if (tiptr->ti_servtype == T_CLTS) {
		t_errno = TNOTSUPPORT;
		return (-1);
	}

	/*
	 * see if there is something in look buffer
	 */
	if (tiptr->ti_lookcnt > 0) {
		t_errno = TLOOK;
		return (-1);
	}

	ctlbufp->len = 0;
	/*
	 * Acquire databuf for use in sending/receiving data part
	 */
	if (_t_acquire_databuf(tiptr, &databuf, &didralloc) < 0)
		return (-1);

	/*
	 * This is a call that may block indefinitely so we drop the
	 * lock and allow signals in MT case here and reacquire it.
	 * Error case should roll back state changes done above
	 * (happens to be no state change here)
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	if ((retval = getmsg(fd, ctlbufp, &databuf, &flg)) < 0) {
		sv_errno = errno;
		if (errno == EAGAIN)
			t_errno = TNODATA;
		else
			t_errno = TSYSERR;
		sig_mutex_lock(&tiptr->ti_lock);
		errno = sv_errno;
		goto err_out;
	}
	sig_mutex_lock(&tiptr->ti_lock);

	if (databuf.len == -1) databuf.len = 0;

	/*
	 * did we get entire message
	 */
	if (retval > 0) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	/*
	 * is cntl part large enough to determine message type?
	 */
	if (ctlbufp->len < (int)sizeof (t_scalar_t)) {
		t_errno = TSYSERR;
		errno = EPROTO;
		goto err_out;
	}

	/* LINTED pointer cast */
	pptr = (union T_primitives *)ctlbufp->buf;

	switch (pptr->type) {

	case T_CONN_CON:

		if ((ctlbufp->len < (int)sizeof (struct T_conn_con)) ||
		    (pptr->conn_con.OPT_length != 0 &&
		    (ctlbufp->len < (int)(pptr->conn_con.OPT_length +
		    pptr->conn_con.OPT_offset)))) {
			t_errno = TSYSERR;
			errno = EPROTO;
			goto err_out;
		}

		if (call != NULL) {
			/*
			 * Note: Buffer overflow is an error in XTI
			 * only if netbuf.maxlen > 0
			 */
			if (_T_IS_TLI(api_semantics) || call->addr.maxlen > 0) {
				if (TLEN_GT_NLEN(pptr->conn_con.RES_length,
				    call->addr.maxlen)) {
					t_errno = TBUFOVFLW;
					goto err_out;
				}
				(void) memcpy(call->addr.buf,
				    ctlbufp->buf + pptr->conn_con.RES_offset,
				    (size_t)pptr->conn_con.RES_length);
				call->addr.len = pptr->conn_con.RES_length;
			}
			if (_T_IS_TLI(api_semantics) || call->opt.maxlen > 0) {
				if (TLEN_GT_NLEN(pptr->conn_con.OPT_length,
				    call->opt.maxlen)) {
					t_errno = TBUFOVFLW;
					goto err_out;
				}
				(void) memcpy(call->opt.buf,
				    ctlbufp->buf + pptr->conn_con.OPT_offset,
				    (size_t)pptr->conn_con.OPT_length);
				call->opt.len = pptr->conn_con.OPT_length;
			}
			if (_T_IS_TLI(api_semantics) ||
			    call->udata.maxlen > 0) {
				if (databuf.len > (int)call->udata.maxlen) {
					t_errno = TBUFOVFLW;
					goto err_out;
				}
				(void) memcpy(call->udata.buf, databuf.buf,
				    (size_t)databuf.len);
				call->udata.len = databuf.len;
			}
			/*
			 * since a confirmation seq number
			 * is -1 by default
			 */
			call->sequence = (int)-1;
		}
		if (didralloc)
			free(databuf.buf);
		else
			tiptr->ti_rcvbuf = databuf.buf;
		return (0);

	case T_DISCON_IND:

		/*
		 * if disconnect indication then append it to
		 * the "look bufffer" list.
		 * This may result in MT case for the process
		 * signal mask to be temporarily masked to
		 * ensure safe memory allocation.
		 */

		if (_t_register_lookevent(tiptr, databuf.buf, databuf.len,
					ctlbufp->buf, ctlbufp->len) < 0) {
			t_errno = TSYSERR;
			errno = ENOMEM;
			goto err_out;
		}
		t_errno = TLOOK;
		goto err_out;

	default:
		break;
	}

	t_errno = TSYSERR;
	errno = EPROTO;
err_out:
	if (didralloc)
		free(databuf.buf);
	else
		tiptr->ti_rcvbuf = databuf.buf;
	return (-1);
}
