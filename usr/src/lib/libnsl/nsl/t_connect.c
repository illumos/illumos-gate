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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7 */

#include "mt.h"
#include <stropts.h>
#include <stdlib.h>
#include <sys/timod.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <xti.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include "tx.h"

/*
 * If a system call fails with EINTR after T_CONN_REQ is sent out,
 * we change state for caller to continue with t_rcvconnect(). This
 * semantics is not documented for TLI but is the direction taken with
 * XTI so we adopt it. With this the call establishment is completed
 * by calling t_rcvconnect() even for synchronous endpoints.
 */
int
_tx_connect(
	int fd,
	const struct t_call *sndcall,
	struct t_call *rcvcall,
	int api_semantics
)
{
	int fctlflg;
	struct _ti_user *tiptr;
	sigset_t mask;
	struct strbuf ctlbuf;
	int sv_errno;
	int didalloc;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	sig_mutex_lock(&tiptr->ti_lock);
	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (tiptr->ti_state != T_IDLE) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
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
		errno = sv_errno;
		return (-1);
	}
	/*
	 * Block all signals until T_CONN_REQ sent and
	 * acked with T_OK_ACK/ERROR_ACK
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	if (_t_snd_conn_req(tiptr, sndcall, &ctlbuf) < 0) {
		sv_errno = errno;
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		/*
		 * At the TPI level, the error returned in a T_ERROR_ACK
		 * received in response to a T_CONN_REQ for an attempt to
		 * establish a duplicate conection has changed to a
		 * new t_errno code introduced with XTI (ADDRBUSY).
		 * We need to adjust TLI error code to be same as before.
		 */
		if (_T_IS_TLI(api_semantics) && t_errno == TADDRBUSY)
			/* TLI only */
			t_errno = TBADADDR;

		goto err_out;
	}
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);

	if ((fctlflg = fcntl(fd, F_GETFL, 0)) < 0) {
		t_errno = TSYSERR;
		goto err_out;
	}

	if (fctlflg & (O_NDELAY | O_NONBLOCK)) {
		_T_TX_NEXTSTATE(T_CONNECT2, tiptr,
				"t_connect: invalid state event T_CONNECT2");
		t_errno = TNODATA;
		goto err_out;
	}

	/*
	 * Note: The following call to _t_rcv_conn_con blocks awaiting
	 * T_CONN_CON from remote client. Therefore it drops the
	 * tiptr->lock during the call (and reacquires it)
	 */
	if (_t_rcv_conn_con(tiptr, rcvcall, &ctlbuf, api_semantics) < 0) {
		if ((t_errno == TSYSERR && errno == EINTR) ||
		    t_errno == TLOOK) {
			_T_TX_NEXTSTATE(T_CONNECT2, tiptr,
				"t_connect: invalid state event T_CONNECT2");
		} else if (t_errno == TBUFOVFLW) {
			_T_TX_NEXTSTATE(T_CONNECT1, tiptr,
				"t_connect: invalid state event T_CONNECT1");
		}
		goto err_out;
	}
	_T_TX_NEXTSTATE(T_CONNECT1, tiptr,
				"t_connect: invalid state event T_CONNECT1");
	/*
	 * Update attributes which may have been negotiated during
	 * connection establishment for protocols where we suspect
	 * such negotiation is likely (e.g. OSI). We do not do it for
	 * all endpoints for performance reasons. Also, this code is
	 * deliberately done after user level state changes so even
	 * the (unlikely) failure case reflects a connected endpoint.
	 */
	if (tiptr->ti_tsdusize != 0) {
		if (_t_do_postconn_sync(fd, tiptr) < 0)
		    goto err_out;
	}


	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	return (0);

err_out:
	sv_errno = errno;
	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);

	errno = sv_errno;
	return (-1);
}
