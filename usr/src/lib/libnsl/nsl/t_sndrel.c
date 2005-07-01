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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4 */

/*
 * t_sndrel.c and t_sndreldata.c are very similar and contain common code.
 * Any changes to either of them should be reviewed to see whether they
 * are applicable to the other file.
 */
#include "mt.h"
#include <errno.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include "tx.h"

int
_tx_sndrel(int fd, int api_semantics)
{
	struct T_ordrel_req orreq;
	struct strbuf ctlbuf;
	struct _ti_user *tiptr;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype != T_COTS_ORD) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if (_T_IS_XTI(api_semantics)) {
		/*
		 * User level state verification only done for XTI
		 * because doing for TLI may break existing applications
		 */
		if (!(tiptr->ti_state == T_DATAXFER ||
		    tiptr->ti_state == T_INREL)) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

		if (_t_look_locked(fd, tiptr, 0,
		    api_semantics) == T_DISCONNECT) {
			t_errno = TLOOK;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

	}

	orreq.PRIM_type = T_ORDREL_REQ;
	ctlbuf.maxlen = (int)sizeof (struct T_ordrel_req);
	ctlbuf.len = (int)sizeof (struct T_ordrel_req);
	ctlbuf.buf = (caddr_t)&orreq;

	/*
	 * Calls to send data (write or putmsg) can potentially
	 * block, for MT case, we drop the lock and enable signals here
	 * and acquire it back
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	if (putmsg(fd, &ctlbuf, NULL, 0) < 0) {
		if (errno == EAGAIN)
			t_errno = TFLOW;
		else
			t_errno = TSYSERR;
		return (-1);
	}
	sig_mutex_lock(&tiptr->ti_lock);
	_T_TX_NEXTSTATE(T_SNDREL, tiptr,
				"t_sndrel: invalid state on event T_SNDREL");
	sig_mutex_unlock(&tiptr->ti_lock);
	return (0);
}
