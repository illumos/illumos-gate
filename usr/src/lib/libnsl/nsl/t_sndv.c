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
#include <assert.h>
#include <syslog.h>
#include "tx.h"


/*
 * t_snd.c and t_sndv.c are very similar and contain common code.
 * Any changes to either of them should be reviewed to see whether they
 * are applicable to the other file.
 */
int
_tx_sndv(int fd, const struct t_iovec *tiov, unsigned int tiovcount,
    int flags, int api_semantics)
{
	struct T_data_req datareq;
	struct strbuf ctlbuf, databuf;
	unsigned int bytes_sent, bytes_remaining, bytes_to_send, nbytes;
	char *curptr;
	struct iovec iov[T_IOV_MAX];
	int iovcount;
	char *dataptr;
	int first_time;
	struct _ti_user *tiptr;
	int band;
	int retval, lookevent;
	int sv_errno;
	int doputmsg = 0;
	int32_t tsdu_limit;

	assert(api_semantics == TX_XTI_XNS5_API);
	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	if (tiptr->ti_servtype == T_CLTS) {
		t_errno = TNOTSUPPORT;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if (tiovcount == 0 || tiovcount > T_IOV_MAX) {
		t_errno = TBADDATA;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	if (!(tiptr->ti_state == T_DATAXFER ||
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

	/*
	 * nbytes is the sum of the bytecounts in the tiov vector
	 * A value larger than INT_MAX is truncated to INT_MAX by
	 * _t_bytecount_upto_intmax()
	 */
	nbytes = _t_bytecount_upto_intmax(tiov, tiovcount);

	if ((tsdu_limit > 0) && /* limit meaningful and ... */
	    (nbytes > (uint32_t)tsdu_limit)) {
		t_errno = TBADDATA;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
	}

	/*
	 * Check for incoming disconnect only. XNS Issue 5 makes it optional
	 * to check for incoming orderly release
	 */
	lookevent = _t_look_locked(fd, tiptr, 0, api_semantics);
	if (lookevent < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}
	if (lookevent == T_DISCONNECT) {
		t_errno = TLOOK;
		sig_mutex_unlock(&tiptr->ti_lock);
		return (-1);
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
			if (!(tiptr->ti_prov_flag & EXPINLINE))
				band = TI_EXPEDITED; /* band > 0 */
		} else
			datareq.PRIM_type = T_DATA_REQ;
		/*
		 * Allocate a databuffer into which we will gather the
		 * input vector data, and make a call to putmsg(). We
		 * do this since we don't have the equivalent of a putmsgv()
		 */
		if (nbytes != 0) {
			if ((dataptr = malloc((size_t)nbytes)) == NULL) {
				sv_errno = errno;
				sig_mutex_unlock(&tiptr->ti_lock);
				errno = sv_errno;
				t_errno = TSYSERR;
				return (-1); /* error */
			}
			/*
			 * Gather the input buffers, into the single linear
			 * buffer allocated above, while taking care to see
			 * that no more than INT_MAX bytes will be copied.
			 */
			_t_gather(dataptr, tiov, tiovcount);
			curptr = dataptr; /* Initialize for subsequent use */
		} else {
			dataptr = NULL;
			curptr = NULL;
		}
	}

	bytes_remaining = nbytes;
	/*
	 * Calls to send data (write or putmsg) can potentially
	 * block, for MT case, we drop the lock and enable signals here
	 * and acquire it back
	 */
	sig_mutex_unlock(&tiptr->ti_lock);
	first_time = 1;
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
			if (retval == 0) {
				bytes_sent = bytes_to_send;
				curptr = curptr + bytes_sent;
			}
		} else {
			/*
			 * transport provider does *not* support TSDU concept
			 * (e.g. TCP) and it is not expedited data. A
			 * perf. optimization is used. Note: the T_MORE
			 * flag is ignored here even if set by the user.
			 */
			/*
			 * The first time, setup the tiovec for doing a writev
			 * call. We assume that T_IOV_MAX <= IOV_MAX.
			 * Since writev may return a partial count, we need
			 * the loop. After the first time, we just adjust
			 * the iov vector to not include the already
			 * written bytes.
			 */
			if (first_time) {
				first_time = 0;
				_t_copy_tiov_to_iov(tiov, tiovcount, iov,
				    &iovcount);
			} else {
				/*
				 * bytes_sent - value set below in the previous
				 * iteration of the loop is used now.
				 */
				_t_adjust_iov(bytes_sent, iov, &iovcount);
			}
			retval = (int)writev(fd, iov, iovcount);
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
				if (dataptr)
					free(dataptr);
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
	} while (bytes_remaining != 0);

	if (dataptr != NULL)
		free(dataptr);
	_T_TX_NEXTSTATE(T_SND, tiptr, "t_snd: invalid state event T_SND");
	return (nbytes - bytes_remaining);
}
