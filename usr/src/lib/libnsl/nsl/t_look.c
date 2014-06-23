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
 * Copyright 2014 Gary Mills
 */

#include "mt.h"
#include <errno.h>
#include <unistd.h>
#include <sys/stream.h>
#include <stropts.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <assert.h>
#include "tx.h"

int
_tx_look(int fd, int api_semantics)
{
	int state;
	int sv_errno;
	int do_expinline_peek;	 /* unusual XTI specific processing */
	struct _ti_user *tiptr;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (_T_IS_XTI(api_semantics))
		do_expinline_peek = 1;
	else
		do_expinline_peek = 0;
	state = _t_look_locked(fd, tiptr, do_expinline_peek, api_semantics);

	sv_errno = errno;

	sig_mutex_unlock(&tiptr->ti_lock);
	errno = sv_errno;
	return (state);
}

/*
 * _t_look_locked() assumes tiptr->ti_lock lock is already held and signals
 * already blocked in MT case.
 * Intended for use by other TLI routines only.
 */
int
_t_look_locked(
	int fd,
	struct _ti_user *tiptr,
	int do_expinline_peek,
	int api_semantics
)
{
	struct strpeek strpeek;
	int retval;
	union T_primitives *pptr;
	t_scalar_t type;
	t_scalar_t ctltype;

	assert(MUTEX_HELD(&tiptr->ti_lock));

#ifdef notyet
	if (_T_IS_XTI(api_semantics)) {
		/*
		 * XTI requires the strange T_GODATA and T_GOEXDATA
		 * events which are almost brain-damaged but thankfully
		 * not tested. Anyone feeling the need for those should
		 * consider the need for using non-blocking endpoint.
		 * Probably introduced at the behest of some weird-os
		 * vendor which did not understand the non-blocking endpoint
		 * option.
		 * We choose not to implment these mis-features.
		 * Here is the plan-of-action (POA)if we are ever forced
		 * to implement these.
		 * - When returning TFLOW set state to indicate if it was
		 *   a normal or expedited data send attempt.
		 * - In routines that set TFLOW, clear the above set state
		 *   on each entry/reentry
		 * - In this routine, if that state flag is set,
		 * do a I_CANPUT on appropriate band to to see if it
		 * is writeable. If that indicates that the band is
		 * writeable, return T_GODATA or T_GOEXDATA event.
		 *
		 * Actions are also influenced by whether T_EXDATA_REQ stays
		 * band 1 or goes to band 0 if EXPINLINE is set
		 *
		 * We will also need to sort out if "write side" events
		 * (such as T_GODATA/T_GOEXDATA) take precedence over
		 * all other events (all read side) or not.
		 */
	}
#endif /* notyet */

	strpeek.ctlbuf.maxlen = (int)sizeof (ctltype);
	strpeek.ctlbuf.len = 0;
	strpeek.ctlbuf.buf = (char *)&ctltype;
	strpeek.databuf.maxlen = 0;
	strpeek.databuf.len = 0;
	strpeek.databuf.buf = NULL;
	strpeek.flags = 0;

	do {
		retval = ioctl(fd, I_PEEK, &strpeek);
	} while (retval < 0 && errno == EINTR);

	if (retval < 0) {
		/*
		 * XTI semantics (also identical to documented
		 * TLI semantics).
		 */
		t_errno = TSYSERR;
		return (-1);
	}

	/*
	 * if something there and cntl part also there
	 */
	if ((tiptr->ti_lookcnt > 0) ||
	    ((retval > 0) && (strpeek.ctlbuf.len >=
	    (int)sizeof (t_scalar_t)))) {
		/* LINTED pointer cast */
		pptr = (union T_primitives *)strpeek.ctlbuf.buf;
		if (tiptr->ti_lookcnt > 0) {
			/* LINTED pointer cast */
			type = *((t_scalar_t *)tiptr->ti_lookbufs.tl_lookcbuf);
			/*
			 * If message on stream head is a T_DISCON_IND, that
			 * has priority over a T_ORDREL_IND in the look
			 * buffer.
			 * (This assumes that T_ORDREL_IND can only be in the
			 * first look buffer in the list)
			 */
			if ((type == T_ORDREL_IND) && retval &&
			    (pptr->type == T_DISCON_IND)) {
				type = pptr->type;
				/*
				 * Blow away T_ORDREL_IND
				 */
				_t_free_looklist_head(tiptr);
			}
		} else
			type = pptr->type;

		switch (type) {

		case T_CONN_IND:
			return (T_LISTEN);

		case T_CONN_CON:
			return (T_CONNECT);

		case T_DISCON_IND:
			return (T_DISCONNECT);

		case T_DATA_IND: {
			int event = T_DATA;
			int retval, exp_on_q;

			if (do_expinline_peek &&
			    (tiptr->ti_prov_flag & EXPINLINE)) {
				assert(_T_IS_XTI(api_semantics));
				retval = _t_expinline_queued(fd, &exp_on_q);
				if (retval < 0) {
					t_errno = TSYSERR;
					return (-1);
				}
				if (exp_on_q)
					event = T_EXDATA;
			}
			return (event);
		}

		case T_UNITDATA_IND:
			return (T_DATA);

		case T_EXDATA_IND:
			return (T_EXDATA);

		case T_UDERROR_IND:
			return (T_UDERR);

		case T_ORDREL_IND:
			return (T_ORDREL);

		default:
			t_errno = TSYSERR;
			errno = EPROTO;
			return (-1);
		}
	}

	/*
	 * if something there put no control part
	 * it must be data on the stream head.
	 */
	if ((retval > 0) && (strpeek.ctlbuf.len <= 0)) {
		int event = T_DATA;
		int retval, exp_on_q;

		if (do_expinline_peek &&
		    (tiptr->ti_prov_flag & EXPINLINE)) {
			assert(_T_IS_XTI(api_semantics));
			retval = _t_expinline_queued(fd, &exp_on_q);
			if (retval < 0)
				return (-1);
			if (exp_on_q)
				event = T_EXDATA;
		}
		return (event);
	}

	/*
	 * if msg there and control
	 * part not large enough to determine type?
	 * it must be illegal TLI message
	 */
	if ((retval > 0) && (strpeek.ctlbuf.len > 0)) {
		t_errno = TSYSERR;
		errno = EPROTO;
		return (-1);
	}
	return (0);
}
