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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <signal.h>
#include <syslog.h>
#include <stropts.h>
#include "tx.h"

/*
 * The following is based on XTI standard.
 */
#define	ALIGN_XTI_opthdr_size	(sizeof (t_uscalar_t))

#define	ROUNDUP_XTI_opthdr(p)	(((p) +\
		(ALIGN_XTI_opthdr_size-1)) & ~(ALIGN_XTI_opthdr_size-1))
#define	ISALIGNED_XTI_opthdr(p)	\
	(((ulong_t)(p) & (ALIGN_XTI_opthdr_size - 1)) == 0)

int
_tx_optmgmt(
	int fd,
	const struct t_optmgmt *req,
	struct t_optmgmt *ret,
	int api_semantics
)
{
	int size, sv_errno;
	struct strbuf ctlbuf;
	struct T_optmgmt_req *optreq;
	struct T_optmgmt_ack *optack;
	struct _ti_user *tiptr;
	sigset_t mask;
	int didalloc, retlen;
	struct t_opthdr *opt, *next_opt;
	struct t_opthdr *opt_start, *opt_end;
	t_uscalar_t first_opt_level;
	t_scalar_t optlen;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	/*
	 * We block all signals during the TI_OPTMGMT operation
	 * as option change being done could potentially be a
	 * non-idempotent operation.
	 * Note that sig_mutex_lock() only defers signals, it does not
	 * block them, so interruptible syscalls could still get EINTR.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&tiptr->ti_lock);

	/*
	 * Acquire buf for use in sending/receiving of the message.
	 * Note: assumes (correctly) that ti_ctlsize is large enough
	 * to hold sizeof (struct T_bind_req)
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		return (-1);
	}

	/*
	 * effective option length in local variable "optlen"
	 * Note: can change for XTI for T_ALLOPT. XTI spec states
	 * that options after the T_ALLOPT option are to be ignored
	 * therefore we trncate the option buffer there and modify
	 * the effective length accordingly later.
	 */
	optlen = req->opt.len;

	if (_T_IS_XTI(api_semantics) && (optlen > 0)) {
		/*
		 * Verify integrity of option buffer according to
		 * XTI t_optmgmt() semantics.
		 */

		if (req->opt.buf == NULL ||
		    optlen < (t_scalar_t)sizeof (struct t_opthdr)) {
			/* option buffer should atleast have an t_opthdr */
			t_errno = TBADOPT;
			goto err_out;
		}

		/* LINTED pointer cast */
		opt_start = (struct t_opthdr *)req->opt.buf;

		/*
		 * XXX We interpret that an option has to start on an
		 * aligned buffer boundary. This is not very explcit in
		 * XTI spec in text but the picture in Section 6.2 shows
		 * "opt.buf" at start of buffer and in combination with
		 * text can be construed to be restricting it to start
		 * on an aligned boundary. [Whether similar restriction
		 * applies to output buffer "ret->opt.buf" is an "interesting
		 * question" but we ignore it for now as that is the problem
		 * for the application not our implementation which will
		 * does not enforce any alignment requirement.]
		 *
		 * If start of buffer is not aligned, we signal an error.
		 */
		if (!(ISALIGNED_XTI_opthdr(opt_start))) {
			t_errno = TBADOPT;
			goto err_out;
		}

		/* LINTED pointer cast */
		opt_end = (struct t_opthdr *)((char *)opt_start +
						optlen);

		/*
		 * Make sure we have enough in the message to dereference
		 * the option header.
		 */
		if ((uchar_t *)opt_start + sizeof (struct t_opthdr)
		    > (uchar_t *)opt_end) {
			t_errno = TBADOPT;
			goto err_out;
		}
		/*
		 * If there are multiple options, they all have to be
		 * the same level (so says XTI semantics).
		 */
		first_opt_level = opt_start->level;

		for (opt = opt_start; opt < opt_end; opt = next_opt) {
			/*
			 * Make sure we have enough in the message to
			 * dereference the option header.
			 */
			if ((uchar_t *)opt_start + sizeof (struct t_opthdr)
			    > (uchar_t *)opt_end) {
				t_errno = TBADOPT;
				goto err_out;
			}
			/*
			 * We now compute pointer to next option in buffer
			 * 'next_opt' the next_opt computation above below
			 * 'opt->len' initialized by application which cannot
			 * be trusted. The usual value too large will be
			 * captured by the loop termination condition above.
			 * We check for the following which it will miss.
			 *	(1)pointer space wraparound arithmetic overflow
			 *	(2)last option in buffer with 'opt->len' being
			 *	  too large
			 *	(only reason 'next_opt' should equal or exceed
			 *	'opt_end' for last option is roundup unless
			 *	length is too-large/invalid)
			 *	(3) we also enforce the XTI restriction that
			 *	   all options in the buffer have to be the
			 *	   same level.
			 */
			/* LINTED pointer cast */
			next_opt = (struct t_opthdr *)((uchar_t *)opt +
			    ROUNDUP_XTI_opthdr(opt->len));

			if ((uchar_t *)next_opt < (uchar_t *)opt || /* (1) */
			    ((next_opt >= opt_end) &&
				(((uchar_t *)next_opt - (uchar_t *)opt_end) >=
				    ALIGN_XTI_opthdr_size)) || /* (2) */
			    (opt->level != first_opt_level)) { /* (3) */
				t_errno = TBADOPT;
				goto err_out;
			}

			/*
			 * XTI semantics: options in the buffer after
			 * the T_ALLOPT option can be ignored
			 */
			if (opt->name == T_ALLOPT) {
				if (next_opt < opt_end) {
					/*
					 * there are options following, ignore
					 * them and truncate input
					 */
					optlen = (t_scalar_t)((uchar_t *)
					    next_opt - (uchar_t *)opt_start);
					opt_end = next_opt;
				}
			}
		}
	}

	/* LINTED pointer cast */
	optreq = (struct T_optmgmt_req *)ctlbuf.buf;
	if (_T_IS_XTI(api_semantics))
		optreq->PRIM_type = T_OPTMGMT_REQ;
	else
		optreq->PRIM_type = T_SVR4_OPTMGMT_REQ;

	optreq->OPT_length = optlen;
	optreq->OPT_offset = 0;
	optreq->MGMT_flags = req->flags;
	size = (int)sizeof (struct T_optmgmt_req);

	if (optlen) {
		if (_t_aligned_copy(&ctlbuf, optlen, size,
		    req->opt.buf, &optreq->OPT_offset) < 0) {
			/*
			 * Aligned copy will overflow buffer allocated
			 * based on maximum transport option size information
			 */
			t_errno = TBADOPT;
			goto err_out;
		}
		size = optreq->OPT_offset + optreq->OPT_length;
	}

	if (_t_do_ioctl(fd, ctlbuf.buf, size, TI_OPTMGMT, &retlen) < 0)
		goto err_out;

	if (retlen < (int)sizeof (struct T_optmgmt_ack)) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	/* LINTED pointer cast */
	optack = (struct T_optmgmt_ack *)ctlbuf.buf;

	if (_T_IS_TLI(api_semantics) || ret->opt.maxlen > 0) {
		if (TLEN_GT_NLEN(optack->OPT_length, ret->opt.maxlen)) {
			t_errno = TBUFOVFLW;
			goto err_out;
		}
		(void) memcpy(ret->opt.buf,
		    (char *)(ctlbuf.buf + optack->OPT_offset),
		    (unsigned int) optack->OPT_length);
		ret->opt.len = optack->OPT_length;
	}

	/*
	 * Note: TPI is not clear about what really is carries in the
	 * T_OPTMGMT_ACK MGMT_flags fields. For T_OPTMGMT_ACK in response
	 * to T_SVR4_OPTMGMT_REQ, the Internet protocols in Solaris 2.X return
	 * the result code only (T_SUCCESS). For T_OPTMGMT_ACK in response
	 * to T_OPTMGMT_REQ, currently "worst status" code required for
	 * XTI is carried from the set of options OR'd with request flag.
	 * (This can change in future and "worst status" computation done
	 * with a scan in this routine.
	 *
	 * Note: Even for T_OPTMGMT_ACK is response to T_SVR4_OPTMGMT_REQ,
	 * removing request flag should be OK though it will not be set.
	 */
	ret->flags = optack->MGMT_flags & ~req->flags;

	/*
	 * NOTE:
	 * There is no real change of state in state table for option
	 * management. The state change macro is used below only for its
	 * debugging and logging capabilities.
	 * The TLI "(mis)feature" (option management only in T_IDLE state)
	 * has been deprecated in XTI and our state table reflect updated for
	 * both TLI and XTI to reflect that.
	 * TLI semantics can be enforced by the transport providers that
	 * desire it at TPI level.
	 * There is no need to enforce this in the library since
	 * sane transport providers that do allow it (e.g TCP and it *needs*
	 * to allow it) should be allowed to work fine.
	 * The only transport providers that return TOUTSTATE for TLI
	 * t_optmgmt() are the drivers used for conformance testing to the
	 * broken TLI standard.
	 * These are /dev/{ticots,ticotsord,ticlts} used by the Sparc ABI test
	 * suite. Others are /dev/{tivc,tidg} used by the SVVS test suite.
	 */

	_T_TX_NEXTSTATE(T_OPTMGMT, tiptr,
	    "t_optmgmt: invalid state event T_OPTMGMT");

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
