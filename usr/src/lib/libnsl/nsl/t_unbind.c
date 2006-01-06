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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3.4.1 */

#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <signal.h>
#include <syslog.h>
#include "tx.h"


int
_tx_unbind(int fd, int api_semantics)
{
	struct _ti_user *tiptr;
	sigset_t mask;
	int sv_errno, retval, didalloc;
	struct strbuf ctlbuf;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (tiptr->ti_state != T_IDLE) {
			t_errno = TOUTSTATE;
			return (-1);
		}
	}

	/*
	 * Since unbind is not an idempotent operation, we
	 * block signals around the call.
	 * Note that sig_mutex_lock() only defers signals, it does not
	 * block them, so interruptible syscalls could still get EINTR.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&tiptr->ti_lock);
	/*
	 * Acquire buffer for use in sending/receiving the message.
	 * Note: assumes (correctly) that ti_ctlsize is large enough
	 * to hold sizeof (struct T_unbind_req/ack)
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		return (-1);
	}

	retval = _tx_unbind_locked(fd, tiptr, &ctlbuf);

	sv_errno = errno;
	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
	errno = sv_errno;
	return (retval);
}

int
_tx_unbind_locked(int fd, struct _ti_user *tiptr, struct strbuf *ctlbufp)
{
	struct T_unbind_req *unbind_reqp;
	int retlen;

	if (_t_is_event(fd, tiptr) < 0)
		return (-1);

	/* LINTED pointer cast */
	unbind_reqp = (struct T_unbind_req *)ctlbufp->buf;
	unbind_reqp->PRIM_type = T_UNBIND_REQ;

	if (_t_do_ioctl(fd, (char *)unbind_reqp,
	    (int)sizeof (struct T_unbind_req), TI_UNBIND, &retlen) < 0) {
		goto err_out;
	}

	if (ioctl(fd, I_FLUSH, FLUSHRW) < 0) {
		t_errno = TSYSERR;
		goto err_out;
	}

	/*
	 * clear more and expedited data bits
	 */
	tiptr->ti_flags &= ~(MORE|EXPEDITED);

	_T_TX_NEXTSTATE(T_UNBIND, tiptr,
			"t_unbind: invalid state event T_UNBIND");

	return (0);

err_out:
	return (-1);
}
