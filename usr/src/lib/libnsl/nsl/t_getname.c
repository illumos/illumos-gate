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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <sys/stream.h>
#include <xti.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <assert.h>
#include <signal.h>
#include "tx.h"

static int __tx_tlitpi_getprotaddr_locked(struct _ti_user *tiptr,
	struct t_bind *boundaddr, struct t_bind *peer);


static int __tx_getname_locked(int fd, struct netbuf *name, int type);

int
_tx_getname(int fd, struct netbuf *name, int type, int api_semantics)
{
	struct _ti_user *tiptr;
	int retval, sv_errno;

	assert(_T_IS_TLI(api_semantics)); /* TLI only interface */
	if (!name || ((type != LOCALNAME) && (type != REMOTENAME))) {
		errno = EINVAL;
		return (-1);
	}

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == 0)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	retval = __tx_getname_locked(fd, name, type);

	if (retval < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	sig_mutex_unlock(&tiptr->ti_lock);

	return (0);
}


static int
__tx_getname_locked(int fd, struct netbuf *name, int type)
{
	int retval;

	do {
		retval = ioctl(fd,
		    (type == LOCALNAME) ? TI_GETMYNAME : TI_GETPEERNAME, name);
	} while (retval < 0 && errno == EINTR);

	if (retval < 0) {
		t_errno = TSYSERR;
		return (-1);
	}
	return (0);
}



int
_tx_getprotaddr(
	int fd,
	struct t_bind *boundaddr,
	struct t_bind *peeraddr,
	int api_semantics)
{
	struct _ti_user *tiptr;
	int retval, sv_errno;
	struct T_addr_req *addreqp;
	struct T_addr_ack *addrackp;
	int didalloc;
	struct strbuf ctlbuf;
	int retlen;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == 0)
		return (-1);

	sig_mutex_lock(&tiptr->ti_lock);

	if ((tiptr->ti_prov_flag & XPG4_1) == 0) {
		/*
		 * Provider does not support XTI inspired TPI so we
		 * try to do operation assuming TLI inspired TPI
		 */
		retval = __tx_tlitpi_getprotaddr_locked(tiptr, boundaddr,
			peeraddr);
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (retval);
	}

	/*
	 * Acquire buffer for use in sending/receiving the message.
	 * Note: assumes (correctly) that ti_ctlsize is large enough
	 * to hold sizeof (struct T_addr_req/ack)
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	/* LINTED pointer cast */
	addreqp = (struct T_addr_req *)ctlbuf.buf;
	addreqp->PRIM_type = T_ADDR_REQ;

	do {
		retval = _t_do_ioctl(fd, ctlbuf.buf,
			(int)sizeof (struct T_addr_req), TI_GETADDRS, &retlen);
	} while (retval < 0 && errno == EINTR);

	/* retval can now be either 0 or -1 */
	if (retval < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		goto err_out;
	}
	sig_mutex_unlock(&tiptr->ti_lock);

	if (retlen < (int)sizeof (struct T_addr_ack)) {
		t_errno = TSYSERR;
		errno = EIO;
		retval = -1;
		goto err_out;
	}

	/* LINTED pointer cast */
	addrackp = (struct T_addr_ack *)ctlbuf.buf;

	/*
	 * We assume null parameters are OK and not errors
	 */
	if (boundaddr != NULL && boundaddr->addr.maxlen > 0) {
		if (TLEN_GT_NLEN(addrackp->LOCADDR_length,
		    boundaddr->addr.maxlen)) {
			t_errno = TBUFOVFLW;
			retval = -1;
			goto err_out;
		}
		boundaddr->addr.len = addrackp->LOCADDR_length;
		(void) memcpy(boundaddr->addr.buf,
		    ctlbuf.buf + addrackp->LOCADDR_offset,
		    (size_t)addrackp->LOCADDR_length);
	}

	/*
	 * Note: In states where there is no remote end of the connection
	 * the T_ADDR_REQ primitive does not return a remote address. However,
	 * in protcols such as TCP, the transport connection is established
	 * before the TLI/XTI level association is established. Therefore,
	 * in state T_OUTCON, the transport may return a remote address where
	 * TLI/XTI level thinks there is no remote end and therefore
	 * no remote address should be returned. We therefore do not look at
	 * address returned by transport provider in T_OUTCON state.
	 * Tested by XTI test suite.
	 */
	if (tiptr->ti_state != T_OUTCON &&
	    peeraddr != NULL && peeraddr->addr.maxlen > 0) {
		if (TLEN_GT_NLEN(addrackp->REMADDR_length,
		    peeraddr->addr.maxlen)) {
			t_errno = TBUFOVFLW;
			retval = -1;
			goto err_out;
		}
		peeraddr->addr.len = addrackp->REMADDR_length;
		(void) memcpy(peeraddr->addr.buf,
		    ctlbuf.buf + addrackp->REMADDR_offset,
		    (size_t)addrackp->REMADDR_length);
	}

err_out:
	if (didalloc)
		free(ctlbuf.buf);
	else
		tiptr->ti_ctlbuf = ctlbuf.buf;
	return (retval);
}

static int
__tx_tlitpi_getprotaddr_locked(
	struct _ti_user *tiptr,
	struct t_bind *boundaddr,
	struct t_bind *peeraddr)
{
	if (boundaddr) {
		boundaddr->addr.len = 0;
		if (tiptr->ti_state >= TS_IDLE) {
			/*
			 * assume bound endpoint .
			 * Note: TI_GETMYNAME can return
			 * a finite length all zeroes address for unbound
			 * endpoint so we avoid relying on it for bound
			 * endpoints for XTI t_getprotaddr() semantics.
			 */
			if (__tx_getname_locked(tiptr->ti_fd, &boundaddr->addr,
			    LOCALNAME) < 0)
				return (-1);

		}
	}
	if (peeraddr) {

		peeraddr->addr.len = 0;

		if (tiptr->ti_state >= TS_DATA_XFER) {
			/*
			 * assume connected endpoint.
			 * The TI_GETPEERNAME call can fail with error
			 * if endpoint is not connected so we don't call it
			 * for XTI t_getprotaddr() semantics
			 */
			if (__tx_getname_locked(tiptr->ti_fd, &peeraddr->addr,
			    REMOTENAME) < 0)
				return (-1);
		}
	}
	return (0);
}
