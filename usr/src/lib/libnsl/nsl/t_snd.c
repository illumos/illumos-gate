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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3.1.2 */

/*
 * t_snd.c and t_sndv.c are very similar and contain common code.
 * Any changes to either of them should be reviewed to see whether they
 * are applicable to the other file.
 */
#include "mt.h"
#include <unistd.h>
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
_tx_snd(int fd, char *buf, unsigned nbytes, int flags, int api_semantics)
{
	struct T_data_req datareq;
	struct strbuf ctlbuf, databuf;
	unsigned int bytes_sent, bytes_remaining, bytes_to_send;
	char *curptr;
	struct _ti_user *tiptr;
	int band;
	int retval, lookevent;
	int sv_errno;
	int doputmsg = 0;
	int32_t tsdu_limit;

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
		 */
		if (! (tiptr->ti_state == T_DATAXFER ||
		    tiptr->ti_state == T_INREL)) {
			t_errno = TOUTSTATE;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}
		/*
		 * XXX
		 * Is it OK to do this TBADFLAG check when XTI spec
		 * is being extended with new and interesting flags
		 * everyday ?
		 */
		if ((flags & ~(TX_ALL_VALID_FLAGS)) != 0) {
			t_errno = TBADFLAG;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}
		if (flags & T_EXPEDITED)
			tsdu_limit = tiptr->ti_etsdusize;
		else {
			/* normal data */
			tsdu_limit = tiptr->ti_tsdusize;
		}

		if ((tsdu_limit > 0) && /* limit meaningful and ... */
		    (nbytes > (uint32_t)tsdu_limit)) {
			t_errno = TBADDATA;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}

		/*
		 * Check for incoming disconnect or orderly release
		 * Did anyone say "performance" ? Didn't hear that.
		 */
		lookevent = _t_look_locked(fd, tiptr, 0, api_semantics);
		if (lookevent < 0) {
			sv_errno = errno;
			sig_mutex_unlock(&tiptr->ti_lock);
			errno = sv_errno;
			return (-1);
		}
		/*
		 * XNS 4 required the TLOOK error to be returned if there
		 * is any incoming T_ORDREL. XNS 5 does not require an
		 * error to be returned in such a case.
		 */
		if (lookevent == T_DISCONNECT ||
		    (api_semantics == TX_XTI_XNS4_API &&
		    lookevent == T_ORDREL)) {
			t_errno = TLOOK;
			sig_mutex_unlock(&tiptr->ti_lock);
			return (-1);
		}
	}

	/* sending zero length data when not allowed */
	if (nbytes == 0 && !(tiptr->ti_prov_flag & (SENDZERO|OLD_SENDZERO))) {
		t_errno = TBADDATA;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	doputmsg = (tiptr->ti_tsdusize != 0) || (flags & T_EXPEDITED);

	if (doputmsg) {
		/*
		 * Initialize ctlbuf for use in sending/receiving control part
		 * of the message.
		 */
		ctlbuf.maxlen = (int)sizeof (struct T_data_req);
		ctlbuf.len = (int)sizeof (struct T_data_req);
		ctlbuf.buf = (char *)&datareq;

		band = TI_NORMAL; /* band 0 */
		if (flags & T_EXPEDITED) {
			datareq.PRIM_type = T_EXDATA_REQ;
			if (! (tiptr->ti_prov_flag & EXPINLINE))
				band = TI_EXPEDITED; /* band > 0 */
		} else
			datareq.PRIM_type = T_DATA_REQ;
	}

	bytes_remaining = nbytes;
	curptr = buf;

	/*
	 * Calls to send data (write or putmsg) can potentially
	 * block, for MT case, we drop the lock and enable signals here
	 * and acquire it back
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	do {
		bytes_to_send = bytes_remaining;
		if (doputmsg) {
			/*
			 * transport provider supports TSDU concept
			 * (unlike TCP) or it is expedited data.
			 * In this case do the fragmentation
			 */
			if (bytes_to_send > (unsigned int)tiptr->ti_maxpsz) {
				datareq.MORE_flag = 1;
				bytes_to_send = (unsigned int)tiptr->ti_maxpsz;
			} else {
				if (flags&T_MORE)
					datareq.MORE_flag = 1;
				else
					datareq.MORE_flag = 0;
			}
			databuf.maxlen = bytes_to_send;
			databuf.len = bytes_to_send;
			databuf.buf = curptr;
			retval = putpmsg(fd, &ctlbuf, &databuf, band, MSG_BAND);
			if (retval == 0)
				bytes_sent = bytes_to_send;
		} else {
			/*
			 * transport provider does *not* support TSDU concept
			 * (e.g. TCP) and it is not expedited data. A
			 * perf. optimization is used. Note: the T_MORE
			 * flag is ignored here even if set by the user.
			 */
			retval = write(fd, curptr, bytes_to_send);
			if (retval >= 0) {
				/* Amount that was actually sent */
				bytes_sent = retval;
			}
		}

		if (retval < 0) {
			if (nbytes == bytes_remaining) {
				/*
				 * Error on *first* putmsg/write attempt.
				 * Return appropriate error
				 */
				if (errno == EAGAIN)
					t_errno = TFLOW;
				else
					t_errno = TSYSERR;
				return (-1); /* return error */
			}
			/*
			 * Not the first putmsg/write
			 * [ partial completion of t_snd() case.
			 *
			 * Error on putmsg/write attempt but
			 * some data was transmitted so don't
			 * return error. Don't attempt to
			 * send more (break from loop) but
			 * return OK.
			 */
			break;
		}
		bytes_remaining = bytes_remaining - bytes_sent;
		curptr = curptr + bytes_sent;
	} while (bytes_remaining != 0);

	_T_TX_NEXTSTATE(T_SND, tiptr, "t_snd: invalid state event T_SND");
	return (nbytes - bytes_remaining);
}
