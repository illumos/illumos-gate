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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3.4.1 */

#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
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
_tx_bind(
	int fd,
	const struct t_bind *req,
	struct t_bind *ret,
	int api_semantics
)
{
	struct T_bind_req *bind_reqp;
	struct T_bind_ack *bind_ackp;
	int size, sv_errno, retlen;
	struct _ti_user *tiptr;
	sigset_t mask;

	int didalloc;
	int use_xpg41tpi;
	struct strbuf ctlbuf;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	/*
	 * We block all signals since TI_BIND, which sends a TPI message
	 * O_T_BIND_REQ down, is not an idempotetent operation
	 * Note that sig_mutex_lock() only defers signals, it does not
	 * block them, so interruptible syscalls could still get EINTR.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&tiptr->ti_lock);
	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (tiptr->ti_state != T_UNBND) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			return (-1);
		}
	}
	/*
	 * Acquire buffer for use in sending/receiving the message.
	 * Note: assumes (correctly) that ti_ctlsize is large enough
	 * to hold sizeof (struct T_bind_req/ack)
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		return (-1);
	}

	/* LINTED pointer cast */
	bind_reqp = (struct T_bind_req *)ctlbuf.buf;
	size = (int)sizeof (struct T_bind_req);

	use_xpg41tpi = (_T_IS_XTI(api_semantics)) &&
		((tiptr->ti_prov_flag & XPG4_1) != 0);
	if (use_xpg41tpi)
		/* XTI call and provider knows the XTI inspired TPI */
		bind_reqp->PRIM_type = T_BIND_REQ;
	else
		/* TLI caller old TPI provider */
		bind_reqp->PRIM_type = O_T_BIND_REQ;

	bind_reqp->ADDR_length = (req == NULL? 0: req->addr.len);
	bind_reqp->ADDR_offset = 0;
	bind_reqp->CONIND_number = (req == NULL? 0: req->qlen);


	if (bind_reqp->ADDR_length) {
		if (_t_aligned_copy(&ctlbuf, (int)bind_reqp->ADDR_length, size,
		    req->addr.buf, &bind_reqp->ADDR_offset) < 0) {
			/*
			 * Aligned copy will overflow buffer allocated based
			 * on transport maximum address length.
			 * return error.
			 */
			t_errno = TBADADDR;
			goto err_out;
		}
		size = bind_reqp->ADDR_offset + bind_reqp->ADDR_length;
	}

	if (_t_do_ioctl(fd, ctlbuf.buf, size, TI_BIND, &retlen) < 0) {
		goto err_out;
	}

	if (retlen < (int)sizeof (struct T_bind_ack)) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	/* LINTED pointer cast */
	bind_ackp = (struct T_bind_ack *)ctlbuf.buf;

	if ((req != NULL) && req->addr.len != 0 &&
	    (use_xpg41tpi == 0) && (_T_IS_XTI(api_semantics))) {
		/*
		 * Best effort to do XTI on old TPI.
		 *
		 * Match address requested or unbind and fail with
		 * TADDRBUSY.
		 *
		 * XXX - Hack alert ! Should we do this at all ?
		 * Not "supported" as may not work if encoding of
		 * address is different in the returned address. This
		 * will also have trouble with TCP/UDP wildcard port
		 * requests
		 */
		if ((req->addr.len != bind_ackp->ADDR_length) ||
		    (memcmp(req->addr.buf, ctlbuf.buf +
		    bind_ackp->ADDR_offset, req->addr.len) != 0)) {
			(void) _tx_unbind_locked(fd, tiptr, &ctlbuf);
			t_errno = TADDRBUSY;
			goto err_out;
		}
	}

	tiptr->ti_ocnt = 0;
	tiptr->ti_flags &= ~TX_TQFULL_NOTIFIED;

	_T_TX_NEXTSTATE(T_BIND, tiptr, "t_bind: invalid state event T_BIND");

	if (ret != NULL) {
		if (_T_IS_TLI(api_semantics) || ret->addr.maxlen > 0) {
			if (TLEN_GT_NLEN(bind_reqp->ADDR_length,
			    ret->addr.maxlen)) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(ret->addr.buf,
			    ctlbuf.buf + bind_ackp->ADDR_offset,
			    (size_t)bind_ackp->ADDR_length);
			ret->addr.len = bind_ackp->ADDR_length;
		}
		ret->qlen = bind_ackp->CONIND_number;
	}

	tiptr->ti_qlen = (uint_t)bind_ackp->CONIND_number;

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
