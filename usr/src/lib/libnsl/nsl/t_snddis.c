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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.3.1 */

#include "mt.h"
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
#include "tx.h"

int
_tx_snddis(int fd, const struct t_call *call, int api_semantics)
{
	struct T_discon_req dreq;
	struct strbuf ctlbuf;
	struct strbuf databuf;
	struct _ti_user *tiptr;
	int sv_errno;
	int retval;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype == T_CLTS) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 * Note: This is documented in TLI man page but never
		 * done.
		 */
		if (!(tiptr->ti_state == T_DATAXFER ||
		    tiptr->ti_state == T_OUTCON ||
		    tiptr->ti_state == T_OUTREL ||
		    tiptr->ti_state == T_INREL ||
		    (tiptr->ti_state == T_INCON && tiptr->ti_ocnt > 0))) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

		/*
		 * Following check only done for XTI as it may be a risk
		 * to existing buggy TLI applications.
		 */
	}

	if (call != NULL && call->udata.len) {
		if ((tiptr->ti_ddatasize == T_INVALID /* -2 */) ||
		    ((tiptr->ti_ddatasize != T_INFINITE /* -1*/) &&
			(call->udata.len >
			    (uint32_t)tiptr->ti_ddatasize))) {
			/*
			 * user data not valid with disconnect or it
			 * exceeds the limits specified by the
			 * transport provider
			 */
			t_errno = TBADDATA;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}
	}

	/*
	 * If disconnect is done on a listener, the 'call' parameter
	 * must be non-null
	 */
	if ((tiptr->ti_state == T_INCON) &&
	    (call == NULL)) {
		t_errno = TBADSEQ;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	/*
	 * look at look buffer to see if there is a discon there
	 */

	if (_t_look_locked(fd, tiptr, 0, api_semantics) == T_DISCONNECT) {
		t_errno = TLOOK;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if ((tiptr->ti_lookcnt > 0) && (call == 0))
		_t_flush_lookevents(tiptr); /* flush but not on listener */

	do {
		retval = ioctl(fd, I_FLUSH, FLUSHW);
	} while (retval < 0 && errno == EINTR);
	if (retval < 0) {
		sv_errno = errno;
		t_errno = TSYSERR;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	ctlbuf.len = (int)sizeof (struct T_discon_req);
	ctlbuf.maxlen = (int)sizeof (struct T_discon_req);
	ctlbuf.buf = (char *)&dreq;

	dreq.PRIM_type = T_DISCON_REQ;
	dreq.SEQ_number = (call? call->sequence: -1);

	databuf.maxlen = (call? call->udata.len: 0);
	databuf.len = (call? call->udata.len: 0);
	databuf.buf = (call? call->udata.buf: NULL);

	/*
	 * Calls to send data (write or putmsg) can potentially
	 * block, for MT case, we drop the lock and enable signals here
	 * and acquire it back
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	if (putmsg(fd, &ctlbuf, (databuf.len? &databuf: NULL), 0) < 0) {
		t_errno = TSYSERR;
		return (-1);
	}
	sig_mutex_lock(&tiptr->ti_lock);

	if (_t_is_ok(fd, tiptr, T_DISCON_REQ) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	tiptr->ti_flags &= ~(MORE|EXPEDITED);

	if (tiptr->ti_ocnt <= 1) {
		if (tiptr->ti_state == T_INCON) {
			tiptr->ti_ocnt--;
			tiptr->ti_flags &= ~TX_TQFULL_NOTIFIED;
		}
		_T_TX_NEXTSTATE(T_SNDDIS1, tiptr,
				"t_snddis: invalid state event T_SNDDIS1");
	} else {
		if (tiptr->ti_state == T_INCON) {
			tiptr->ti_ocnt--;
			tiptr->ti_flags &= ~TX_TQFULL_NOTIFIED;
		}
		_T_TX_NEXTSTATE(T_SNDDIS2, tiptr,
				"t_snddis: invalid state event T_SNDDIS2");
	}

	sig_mutex_unlock(&tiptr->ti_lock);
	return (0);
}
