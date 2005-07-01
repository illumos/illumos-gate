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

/*
 * t_sndudata.c and t_sndvudata.c are very similar and contain common code.
 * Any changes to either of them should be reviewed to see whether they
 * are applicable to the other file.
 */
#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <syslog.h>
#include "tx.h"

int
_tx_sndudata(int fd, const struct t_unitdata *unitdata, int api_semantics)
{
	struct T_unitdata_req *udreq;
	struct strbuf ctlbuf;
	int size;
	struct _ti_user *tiptr;
	int sv_errno;
	int didalloc;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype != T_CLTS) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

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

	if (((int)unitdata->udata.len == 0) &&
	    !(tiptr->ti_prov_flag & (SENDZERO|OLD_SENDZERO))) {
		t_errno = TBADDATA;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if ((tiptr->ti_maxpsz > 0) &&
	    (unitdata->udata.len > (uint32_t)tiptr->ti_maxpsz)) {
		if (_T_IS_TLI(api_semantics)) {
			t_errno = TSYSERR;
			errno = EPROTO;
		} else
			t_errno = TBADDATA;
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
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

	/* LINTED pointer cast */
	udreq = (struct T_unitdata_req *)ctlbuf.buf;

	udreq->PRIM_type = T_UNITDATA_REQ;
	udreq->DEST_length = unitdata->addr.len;
	udreq->DEST_offset = 0;
	udreq->OPT_length = unitdata->opt.len;
	udreq->OPT_offset = 0;
	size = (int)sizeof (struct T_unitdata_req);

	if (unitdata->addr.len) {
		if (_t_aligned_copy(&ctlbuf, unitdata->addr.len, size,
		    unitdata->addr.buf, &udreq->DEST_offset) < 0) {
			/*
			 * Aligned copy based will overflow buffer
			 * allocated based on maximum transport address
			 * size information
			 */
			t_errno = TSYSERR;
			errno = EPROTO;
			goto err_out;
		}
		size = udreq->DEST_offset + udreq->DEST_length;
	}
	if (unitdata->opt.len) {
		if (_t_aligned_copy(&ctlbuf, unitdata->opt.len, size,
		    unitdata->opt.buf, &udreq->OPT_offset) < 0) {
			/*
			 * Aligned copy based will overflow buffer
			 * allocated based on maximum transport option
			 * size information
			 */
			t_errno = TSYSERR;
			errno = EPROTO;
			goto err_out;
		}
		size = udreq->OPT_offset + udreq->OPT_length;
	}

	if (size > (int)ctlbuf.maxlen) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	ctlbuf.len = size;

	/*
	 * Calls to send data (write or putmsg) can potentially
	 * block, for MT case, we drop the lock and enable signals here
	 * and acquire it back.
	 * At this point, we are sure SENDZERO is supported and the
	 * putmsg below may send a zero length message,
	 * (i.e with valid control part, but zero data part)
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	if (putmsg(fd, &ctlbuf, (struct strbuf *)&unitdata->udata, 0) < 0) {
		if (errno == EAGAIN)
			t_errno = TFLOW;
		else
			t_errno = TSYSERR;
		sv_errno = errno;
		sig_mutex_lock(&tiptr->ti_lock);
		errno = sv_errno;
		goto err_out;
	}
	sig_mutex_lock(&tiptr->ti_lock);

	_T_TX_NEXTSTATE(T_SNDUDATA, tiptr,
			"t_sndudata: invalid state event T_SNDUDATA");
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
