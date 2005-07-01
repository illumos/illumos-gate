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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5 */

#include "mt.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <syslog.h>
#include "tx.h"

int
_tx_listen(int fd, struct t_call *call, int api_semantics)
{
	struct strbuf ctlbuf;
	struct strbuf databuf;
	int retval;
	union T_primitives *pptr;
	struct _ti_user *tiptr;
	int sv_errno;
	int didalloc, didralloc;
	int flg = 0;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype == T_CLTS) {
		sv_errno = errno;
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}
	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (!(tiptr->ti_state == T_IDLE ||
		    tiptr->ti_state == T_INCON)) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

		if (tiptr->ti_qlen == 0) {
			t_errno = TBADQLEN;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

		if (tiptr->ti_ocnt == tiptr->ti_qlen) {
			if (!(tiptr->ti_flags & TX_TQFULL_NOTIFIED)) {
				tiptr->ti_flags |= TX_TQFULL_NOTIFIED;
				t_errno = TQFULL;
				sig_mutex_unlock(&tiptr->ti_lock);
				return (-1);
			}
		}

	}

	/*
	 * check if something in look buffer
	 */
	if (tiptr->ti_lookcnt > 0) {
		t_errno = TLOOK;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	/*
	 * Acquire ctlbuf for use in sending/receiving control part
	 * of the message.
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}
	/*
	 * Acquire databuf for use in sending/receiving data part
	 */
	if (_t_acquire_databuf(tiptr, &databuf, &didralloc) < 0) {
		int sv_errno = errno;

		if (didalloc)
			free(ctlbuf.buf);
		else
			tiptr->ti_ctlbuf = ctlbuf.buf;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	/*
	 * This is a call that may block indefinitely so we drop the
	 * lock and allow signals in MT case here and reacquire it.
	 * Error case should roll back state changes done above
	 * (happens to be no state change here)
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	if ((retval = getmsg(fd, &ctlbuf, &databuf, &flg)) < 0) {
		if (errno == EAGAIN)
			t_errno = TNODATA;
		else
			t_errno = TSYSERR;
		sv_errno = errno;
		sig_mutex_lock(&tiptr->ti_lock);
		errno = sv_errno;
		goto err_out;
	}
	sig_mutex_lock(&tiptr->ti_lock);

	if (databuf.len == -1) databuf.len = 0;

	/*
	 * did I get entire message?
	 */
	if (retval > 0) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	/*
	 * is ctl part large enough to determine type
	 */
	if (ctlbuf.len < (int)sizeof (t_scalar_t)) {
		t_errno = TSYSERR;
		errno = EPROTO;
		goto err_out;
	}

	/* LINTED pointer cast */
	pptr = (union T_primitives *)ctlbuf.buf;

	switch (pptr->type) {

	case T_CONN_IND:
		if ((ctlbuf.len < (int)sizeof (struct T_conn_ind)) ||
		    (ctlbuf.len < (int)(pptr->conn_ind.OPT_length
		    + pptr->conn_ind.OPT_offset))) {
			t_errno = TSYSERR;
			errno = EPROTO;
			goto err_out;
		}
		/*
		 * Change state and increment outstanding connection
		 * indication count and instantiate "sequence" return
		 * parameter.
		 * Note: It is correct semantics accoring to spec to
		 * do this despite possibility of TBUFOVFLW error later.
		 * The spec treats TBUFOVFLW error in general as a special case
		 * which can be ignored by applications that do not
		 * really need the stuff returned in 'netbuf' structures.
		 */
		_T_TX_NEXTSTATE(T_LISTN, tiptr,
				"t_listen:invalid state event T_LISTN");
		tiptr->ti_ocnt++;
		call->sequence = pptr->conn_ind.SEQ_number;

		if (_T_IS_TLI(api_semantics) || call->addr.maxlen > 0) {
			if (TLEN_GT_NLEN(pptr->conn_ind.SRC_length,
			    call->addr.maxlen)) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(call->addr.buf, ctlbuf.buf +
			    (size_t)pptr->conn_ind.SRC_offset,
			(unsigned int)pptr->conn_ind.SRC_length);
			call->addr.len = pptr->conn_ind.SRC_length;
		}
		if (_T_IS_TLI(api_semantics) || call->opt.maxlen > 0) {
			if (TLEN_GT_NLEN(pptr->conn_ind.OPT_length,
			    call->opt.maxlen)) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(call->opt.buf, ctlbuf.buf +
			    pptr->conn_ind.OPT_offset,
			    (size_t)pptr->conn_ind.OPT_length);
			call->opt.len = pptr->conn_ind.OPT_length;
		}
		if (_T_IS_TLI(api_semantics) || call->udata.maxlen > 0) {
			if (databuf.len > (int)call->udata.maxlen) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(call->udata.buf, databuf.buf,
			    (size_t)databuf.len);
			call->udata.len = databuf.len;
		}

		if (didalloc)
			free(ctlbuf.buf);
		else
			tiptr->ti_ctlbuf = ctlbuf.buf;
		if (didralloc)
			free(databuf.buf);
		else
			tiptr->ti_rcvbuf = databuf.buf;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (0);

	case T_DISCON_IND:
		/*
		 * Append to the events in the "look buffer"
		 * list of events. This routine may defer signals.
		 */
		if (_t_register_lookevent(tiptr, databuf.buf,
					databuf.len, ctlbuf.buf,
					ctlbuf.len) < 0) {
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
	sv_errno = errno;

	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	if (didralloc)
		free(databuf.buf);
	else
		tiptr->ti_rcvbuf = databuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	errno = sv_errno;
	return (-1);
}
