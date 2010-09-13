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
#include <string.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <syslog.h>
#include <assert.h>
#include "tx.h"

int
_tx_rcvuderr(int fd, struct t_uderr *uderr, int api_semantics)
{
	struct strbuf ctlbuf, databuf;
	int flg;
	int retval;
	union T_primitives *pptr;
	struct _ti_user *tiptr;
	int sv_errno;
	int didalloc;
	int use_lookbufs = 0;


	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype != T_CLTS) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}
	/*
	 * is there a unitdata error indication in look buffer
	 */
	if (tiptr->ti_lookcnt > 0) {
		ctlbuf.len = tiptr->ti_lookbufs.tl_lookclen;
		ctlbuf.buf = tiptr->ti_lookbufs.tl_lookcbuf;
		/* Note: cltbuf.maxlen not used in this case */

		/* LINTED pointer cast */
		assert(((union T_primitives *)ctlbuf.buf)->type
			== T_UDERROR_IND);

		databuf.maxlen = 0;
		databuf.len = 0;
		databuf.buf = NULL;

		use_lookbufs = 1;

	} else {
		if ((retval = _t_look_locked(fd, tiptr, 0,
		    api_semantics)) < 0) {
			sv_errno = errno;
			sig_mutex_unlock(&tiptr->ti_lock);
			errno = sv_errno;
			return (-1);
		}
		if (retval != T_UDERR) {
			t_errno = TNOUDERR;
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

		databuf.maxlen = 0;
		databuf.len = 0;
		databuf.buf = NULL;

		flg = 0;

		/*
		 * Since we already verified that a unitdata error
		 * indication is pending, we assume that this getmsg()
		 * will not block indefinitely.
		 */
		if ((retval = getmsg(fd, &ctlbuf, &databuf, &flg)) < 0) {

			t_errno = TSYSERR;
			goto err_out;
		}
		/*
		 * did I get entire message?
		 */
		if (retval > 0) {
			t_errno = TSYSERR;
			errno = EIO;
			goto err_out;
		}

	}

	/* LINTED pointer cast */
	pptr = (union T_primitives *)ctlbuf.buf;

	if ((ctlbuf.len < (int)sizeof (struct T_uderror_ind)) ||
	    (pptr->type != T_UDERROR_IND)) {
		t_errno = TSYSERR;
		errno = EPROTO;
		goto err_out;
	}

	if (uderr) {
		if (_T_IS_TLI(api_semantics) || uderr->addr.maxlen > 0) {
			if (TLEN_GT_NLEN(pptr->uderror_ind.DEST_length,
			    uderr->addr.maxlen)) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(uderr->addr.buf, ctlbuf.buf +
			    pptr->uderror_ind.DEST_offset,
			    (size_t)pptr->uderror_ind.DEST_length);
			uderr->addr.len =
			    (unsigned int)pptr->uderror_ind.DEST_length;
		}
		if (_T_IS_TLI(api_semantics) || uderr->addr.maxlen > 0) {
			if (TLEN_GT_NLEN(pptr->uderror_ind.OPT_length,
			    uderr->opt.maxlen)) {
				t_errno = TBUFOVFLW;
				goto err_out;
			}
			(void) memcpy(uderr->opt.buf, ctlbuf.buf +
			    pptr->uderror_ind.OPT_offset,
			    (size_t)pptr->uderror_ind.OPT_length);
			uderr->opt.len =
			    (unsigned int)pptr->uderror_ind.OPT_length;
		}
		uderr->error = pptr->uderror_ind.ERROR_type;
	}

	_T_TX_NEXTSTATE(T_RCVUDERR, tiptr,
			"t_rcvuderr: invalid state event T_RCVUDERR");
	if (use_lookbufs)
		_t_free_looklist_head(tiptr);
	else {
		if (didalloc)
			free(ctlbuf.buf);
		else
			tiptr->ti_ctlbuf = ctlbuf.buf;
	}
	sig_mutex_unlock(&tiptr->ti_lock);
	return (0);

err_out:
	sv_errno = errno;

	if (use_lookbufs)
		_t_free_looklist_head(tiptr);
	else {
		if (didalloc)
			free(ctlbuf.buf);
		else
			tiptr->ti_ctlbuf = ctlbuf.buf;
	}
	sig_mutex_unlock(&tiptr->ti_lock);
	errno = sv_errno;
	return (-1);
}
