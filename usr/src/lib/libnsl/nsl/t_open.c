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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5.3.3 */

#include "mt.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/stat.h>
#include <xti.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <limits.h>
#include "tx.h"

/*
 * If _tx_open is called for transport that doesn't understand T_CAPABILITY_REQ
 * TPI message, call to _t_create may fail the first time it is called with
 * given transport (in the rare case when transport shuts down the stream with
 * M_ERROR in reply to unknown T_CAPABILITY_REQ). In this case we may reopen the
 * stream again since timod will emulate T_CAPABILITY_REQ behaviour.
 *
 * _t_create sends T_CAPABILITY_REQ through TI_CAPABILITY ioctl.
 */

int
_tx_open(const char *path, int flags, struct t_info *info, int api_semantics)
{
	int retval, fd, sv_errno;
	int sv_terrno;
	int sv_errno_global;
	struct _ti_user *tiptr;
	sigset_t mask;
	int t_create_first_attempt = 1;
	int ticap_ioctl_failed = 0;

	if (!(flags & O_RDWR)) {
		t_errno = TBADFLAG;
		return (-1);
	}

	sv_errno_global = errno;
	sv_terrno = t_errno;

retry:
	if ((fd = open(path, flags)) < 0) {
		t_errno = TSYSERR;
		if (_T_IS_XTI(api_semantics) && errno == ENOENT)
			/* XTI only */
			t_errno = TBADNAME;
		return (-1);
	}
	/*
	 * is module already pushed
	 */
	do {
		retval = ioctl(fd, I_FIND, "timod");
	} while (retval < 0 && errno == EINTR);

	if (retval < 0) {
		sv_errno = errno;

		t_errno = TSYSERR;
		(void) close(fd);
		errno = sv_errno;
		return (-1);
	}

	if (retval == 0) {
		/*
		 * "timod" not already on stream, then push it
		 */
		do {
			/*
			 * Assumes (correctly) that I_PUSH  is
			 * atomic w.r.t signals (EINTR error)
			 */
			retval = ioctl(fd, I_PUSH, "timod");
		} while (retval < 0 && errno == EINTR);

		if (retval < 0) {
			int sv_errno = errno;

			t_errno = TSYSERR;
			(void) close(fd);
			errno = sv_errno;
			return (-1);
		}
	}

	/*
	 * _t_create() requires that all signals be blocked.
	 * Note that sig_mutex_lock() only defers signals, it does not
	 * block them, so interruptible syscalls could still get EINTR.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&_ti_userlock);
	/*
	 * Call to _t_create may fail either because transport doesn't
	 * understand T_CAPABILITY_REQ or for some other reason. It is nearly
	 * impossible to distinguish between these cases so it is implicitly
	 * assumed that it is always save to close and reopen the same stream
	 * and that open/close doesn't have side effects. _t_create may fail
	 * only once if its' failure is caused by unimplemented
	 * T_CAPABILITY_REQ.
	 */
	tiptr = _t_create(fd, info, api_semantics, &ticap_ioctl_failed);
	if (tiptr == NULL) {
		/*
		 * If _t_create failed due to fail of ti_capability_req we may
		 * try to reopen the stream in the hope that timod will emulate
		 * TI_CAPABILITY and it will succeed when called again.
		 */
		if (t_create_first_attempt == 1 && ticap_ioctl_failed == 1) {
			t_create_first_attempt = 0;
			(void) close(fd);
			errno = sv_errno_global;
			t_errno = sv_terrno;
			sig_mutex_unlock(&_ti_userlock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			goto retry;
		} else {
			int sv_errno = errno;
			(void) close(fd);
			sig_mutex_unlock(&_ti_userlock);
			(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
			errno = sv_errno;
			return (-1);
		}
	}

	/*
	 * _t_create synchronizes state witk kernel timod and
	 * already sets it to T_UNBND - what it needs to be
	 * be on T_OPEN event. No _T_TX_NEXTSTATE needed here.
	 */
	sig_mutex_unlock(&_ti_userlock);
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);

	do {
		retval = ioctl(fd, I_FLUSH, FLUSHRW);
	} while (retval < 0 && errno == EINTR);

	/*
	 * We ignore other error cases (retval < 0) - assumption is
	 * that I_FLUSH failures is temporary (e.g. ENOSR) or
	 * otherwise benign failure on a this newly opened file
	 * descriptor and not a critical failure.
	 */

	return (fd);
}
