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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5.2.1 */

#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <signal.h>
#include <syslog.h>
#include <assert.h>
#include "tx.h"

int
_tx_accept(
	int fd,
	int resfd,
	const struct t_call *call,
	int api_semantics
)
{
	struct T_conn_res *cres;
	struct strfdinsert strfdinsert;
	int size, retval, sv_errno;
	struct _ti_user *tiptr;
	struct _ti_user *restiptr;
	sigset_t mask;
	struct strbuf ctlbuf;
	int didalloc;
	t_scalar_t conn_res_prim;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	if ((restiptr = _t_checkfd(resfd, 0, api_semantics)) == NULL)
		return (-1);

	/*
	 * We need to block signals to perform the I_FDINSERT operation
	 * (sending T_CONN_RES downstream) which is non-idempotent.
	 * Note that sig_mutex_lock() only defers signals, it does not
	 * block them, so interruptible syscalls could still get EINTR.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype == T_CLTS) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		return (-1);
	}

	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 *
		 * For fd == resfd, state should be T_INCON
		 * For fd != resfd,
		 *	    fd state should be T_INCON
		 *	    resfd state should be T_IDLE (bound endpoint) or
		 *	    it can be T_UNBND. The T_UNBND case is not (yet?)
		 *	    allowed in the published XTI spec but fixed by the
		 *	    corrigenda.
		 */
		if ((fd == resfd && tiptr->ti_state != T_INCON) ||
		    (fd != resfd &&
			((tiptr->ti_state != T_INCON) ||
		    !(restiptr->ti_state == T_IDLE ||
			restiptr->ti_state == T_UNBND)))) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			return (-1);
		}

		/*
		 * XTI says:
		 * If fd != resfd, and a resfd bound to a protocol address is
		 * passed, then it better not have a qlen > 0.
		 * That is, an endpoint bound as if it will be a listener
		 * cannot be used as an acceptor.
		 */
		if (fd != resfd && restiptr->ti_state == T_IDLE &&
		    restiptr->ti_qlen > 0) {
			t_errno = TRESQLEN;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			return (-1);
		}

		if (fd == resfd && tiptr->ti_ocnt > 1) {
			t_errno = TINDOUT;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			return (-1);
		}

		/*
		 * Note: TRESADDR error is specified by XTI. It happens
		 * when resfd is bound and fd and resfd are not BOUND to
		 * the same protocol address. TCP obviously does allow
		 * two endpoints to bind to the same address. Why is the
		 * need for this error considering there is an address switch
		 * that can be done for the endpoint at accept time ? Go
		 * figure and ask the XTI folks.
		 * We interpret this to be a transport specific error condition
		 * to be be coveyed by the transport provider in T_ERROR_ACK
		 * to T_CONN_RES on transports that allow two endpoints to
		 * be bound to the same address and have trouble with the
		 * idea of accepting connections on a resfd that has a qlen > 0
		 */
	}

	if (fd != resfd) {
		if ((retval = ioctl(resfd, I_NREAD, &size)) < 0) {
			sv_errno = errno;

			t_errno = TSYSERR;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			errno = sv_errno;
			return (-1);
		}
		if (retval > 0) {
			t_errno = TBADF;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			return (-1);
		}
	}

	/*
	 * Acquire ctlbuf for use in sending/receiving control part
	 * of the message.
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		return (-1);
	}

	/*
	 * In Unix98 t_accept() need not return [TLOOK] if connect/disconnect
	 * indications are present. TLI and Unix95 need to return error.
	 */
	if (_T_API_VER_LT(api_semantics, TX_XTI_XNS5_API)) {
		if (_t_is_event(fd, tiptr) < 0)
			goto err_out;
	}

	/* LINTED pointer cast */
	cres = (struct T_conn_res *)ctlbuf.buf;
	cres->OPT_length = call->opt.len;
	cres->OPT_offset = 0;
	cres->SEQ_number = call->sequence;
	if ((restiptr->ti_flags & V_ACCEPTOR_ID) != 0) {
		cres->ACCEPTOR_id = restiptr->acceptor_id;
		cres->PRIM_type = conn_res_prim = T_CONN_RES;
	} else {
		/* I_FDINSERT should use O_T_CONN_RES. */
		cres->ACCEPTOR_id = 0;
		cres->PRIM_type = conn_res_prim = O_T_CONN_RES;
	}

	size = (int)sizeof (struct T_conn_res);

	if (call->opt.len) {
		if (_t_aligned_copy(&ctlbuf, call->opt.len, size,
		    call->opt.buf, &cres->OPT_offset) < 0) {
			/*
			 * Aligned copy will overflow buffer allocated based
			 * transport maximum options length.
			 * return error.
			 */
			t_errno = TBADOPT;
			goto err_out;
		}
		size = cres->OPT_offset + cres->OPT_length;
	}

	if (call->udata.len) {
		if ((tiptr->ti_cdatasize == T_INVALID /* -2 */) ||
		    ((tiptr->ti_cdatasize != T_INFINITE /* -1 */) &&
			(call->udata.len > (uint32_t)tiptr->ti_cdatasize))) {
			/*
			 * user data not valid with connect or it
			 * exceeds the limits specified by the transport
			 * provider
			 */
			t_errno = TBADDATA;
			goto err_out;
		}
	}


	ctlbuf.len = size;

	/*
	 * Assumes signals are blocked so putmsg() will not block
	 * indefinitely
	 */
	if ((restiptr->ti_flags & V_ACCEPTOR_ID) != 0) {
		/*
		 * Assumes signals are blocked so putmsg() will not block
		 * indefinitely
		 */
		if (putmsg(fd, &ctlbuf,
		    (struct strbuf *)(call->udata.len? &call->udata: NULL), 0) <
		    0) {
			if (errno == EAGAIN)
				t_errno = TFLOW;
			else
				t_errno = TSYSERR;
			goto err_out;
		}
	} else {
		strfdinsert.ctlbuf.maxlen = ctlbuf.maxlen;
		strfdinsert.ctlbuf.len = ctlbuf.len;
		strfdinsert.ctlbuf.buf = ctlbuf.buf;

		strfdinsert.databuf.maxlen = call->udata.maxlen;
		strfdinsert.databuf.len =
		    (call->udata.len? call->udata.len: -1);
		strfdinsert.databuf.buf = call->udata.buf;
		strfdinsert.fildes = resfd;
		strfdinsert.offset = (int)sizeof (t_scalar_t);
		strfdinsert.flags = 0;		/* could be EXPEDITED also */

		if (ioctl(fd, I_FDINSERT, &strfdinsert) < 0) {
			if (errno == EAGAIN)
				t_errno = TFLOW;
			else
				t_errno = TSYSERR;
			goto err_out;
		}
	}

	if (_t_is_ok(fd, tiptr, conn_res_prim) < 0) {
		/*
		 * At the TPI level, the error returned in a T_ERROR_ACK
		 * received in response to a T_CONN_RES for a listener and
		 * acceptor endpoints not being the same kind of endpoints
		 * has changed to a new t_errno code introduced with
		 * XTI (TPROVMISMATCH). We need to adjust TLI error code
		 * to be same as before.
		 */
		if (_T_IS_TLI(api_semantics) && t_errno == TPROVMISMATCH) {
			/* TLI only */
			t_errno = TBADF;
		}
		goto err_out;
	}

	if (tiptr->ti_ocnt == 1) {
		if (fd == resfd) {
			_T_TX_NEXTSTATE(T_ACCEPT1, tiptr,
				"t_accept: invalid state event T_ACCEPT1");
		} else {
			_T_TX_NEXTSTATE(T_ACCEPT2, tiptr,
				"t_accept: invalid state event T_ACCEPT2");
			/*
			 * XXX Here we lock the resfd lock also. This
			 * is an instance of holding two locks without
			 * any enforcement of a locking hiararchy.
			 * There is potential for deadlock in incorrect
			 * or buggy programs here but this is the safer
			 * choice in this case. Correct programs will not
			 * deadlock.
			 */
			sig_mutex_lock(&restiptr->ti_lock);
			_T_TX_NEXTSTATE(T_PASSCON, restiptr,
				"t_accept: invalid state event T_PASSCON");
			sig_mutex_unlock(&restiptr->ti_lock);
		}
	} else {
		_T_TX_NEXTSTATE(T_ACCEPT3, tiptr,
				"t_accept: invalid state event T_ACCEPT3");
		if (fd != resfd)
			sig_mutex_lock(&restiptr->ti_lock);
		_T_TX_NEXTSTATE(T_PASSCON, restiptr,
				"t_accept: invalid state event T_PASSCON");
		if (fd != resfd)
			sig_mutex_unlock(&restiptr->ti_lock);
	}

	tiptr->ti_ocnt--;
	tiptr->ti_flags &= ~TX_TQFULL_NOTIFIED;

	/*
	 * Update attributes which may have been negotiated during
	 * connection establishment for protocols where we suspect
	 * such negotiation is likely (e.g. OSI). We do not do it for
	 * all endpoints for performance reasons. Also, this code is
	 * deliberately done after user level state changes so even
	 * the (unlikely) failure case reflects a connected endpoint.
	 */
	if (restiptr->ti_tsdusize != 0) {
		if (_t_do_postconn_sync(resfd, restiptr) < 0)
			goto err_out;
	}

	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
	return (0);
	/* NOTREACHED */
err_out:
	sv_errno = errno;
	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
	errno = sv_errno;
	return (-1);
}
