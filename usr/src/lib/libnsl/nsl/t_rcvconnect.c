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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */

#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <stropts.h>
#include <xti.h>
#include <sys/timod.h>
#include "tx.h"


/*
 * t_rcvconnect() is documented to be only called with non-blocking
 * endpoints for asynchronous connection establishment. However, the
 * direction taken by XTI is to allow it to be called if t_connect()
 * fails with TSYSERR/EINTR and state is T_OUTCON (i.e. T_CONN_REQ was
 * sent down). This implies that an interrupted synchronous connection
 * establishment which was interrupted after connection request was transmitted
 * can now be completed by calling t_rcvconnect()
 */
int
_tx_rcvconnect(int fd, struct t_call *call, int api_semantics)
{
	struct _ti_user *tiptr;
	int retval, sv_errno;
	struct strbuf ctlbuf;
	int didalloc;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	sig_mutex_lock(&tiptr->ti_lock);

	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (tiptr->ti_state != T_OUTCON) {
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

	retval = _t_rcv_conn_con(tiptr, call, &ctlbuf, api_semantics);
	if (retval == 0 || t_errno == TBUFOVFLW) {
		_T_TX_NEXTSTATE(T_RCVCONNECT, tiptr,
			"t_rcvconnect: Invalid state on event T_RCVCONNECT");
		/*
		 * Update attributes which may have been negotiated during
		 * connection establishment for protocols where we suspect
		 * such negotiation is likely (e.g. OSI). We do not do it for
		 * all endpoints for performance reasons. Also, this code is
		 * deliberately done after user level state changes so even
		 * the (unlikely) failure case reflects a connected endpoint.
		 */
		if (tiptr->ti_tsdusize != 0)
			if (_t_do_postconn_sync(fd, tiptr) < 0)
				retval = -1;
	}
	sv_errno = errno;
	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	sig_mutex_unlock(&tiptr->ti_lock);
	errno = sv_errno;
	return (retval);
}
