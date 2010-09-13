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

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <assert.h>
#include "tx.h"

int
_tx_sndreldata(int fd, struct t_discon *discon, int api_semantics)
{
	struct T_ordrel_req orreq;
	struct strbuf ctlbuf;
	struct _ti_user *tiptr;

	assert(api_semantics == TX_XTI_XNS5_API);
	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype != T_COTS_ORD) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

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

	/*
	 * Someday there could be transport providers that support T_ORDRELDATA
	 * Until that happens, this function returns TBADDATA if user data
	 * was specified. If no user data is specified, this function
	 * behaves as t_sndrel()
	 * Note: Currently only mOSI ("minimal OSI") provider is specified
	 * to use T_ORDRELDATA so probability of needing it is minimal.
	 */

	if (discon && discon->udata.len) {
		t_errno = TBADDATA;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
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
			"t_sndreldata: invalid state on event T_SNDREL");
	sig_mutex_unlock(&tiptr->ti_lock);
	return (0);
}
