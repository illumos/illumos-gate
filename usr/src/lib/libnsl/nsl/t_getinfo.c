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

int
_tx_getinfo(int fd, struct t_info *info, int api_semantics)
{
	struct T_info_req *inforeqp;
	struct T_info_ack *infoackp;
	int retlen;
	struct _ti_user *tiptr;
	int retval, sv_errno, didalloc;
	struct strbuf ctlbuf;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == 0)
		return (-1);
	sig_mutex_lock(&tiptr->ti_lock);

	/*
	 * Acquire buffer for use in sending/receiving the message.
	 * Note: assumes (correctly) that ti_ctlsize is large enough
	 * to hold sizeof (struct T_info_req/ack)
	 */
	if (_t_acquire_ctlbuf(tiptr, &ctlbuf, &didalloc) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = sv_errno;
		return (-1);
	}

	/* LINTED pointer cast */
	inforeqp =  (struct T_info_req *)ctlbuf.buf;
	inforeqp->PRIM_type = T_INFO_REQ;

	do {
		retval = _t_do_ioctl(fd, ctlbuf.buf,
			(int)sizeof (struct T_info_req), TI_GETINFO, &retlen);
	} while (retval < 0 && errno == EINTR);

	if (retval < 0)
		goto err_out;

	if (retlen != (int)sizeof (struct T_info_ack)) {
		t_errno = TSYSERR;
		errno = EIO;
		goto err_out;
	}

	/* LINTED pointer cast */
	infoackp = (struct T_info_ack *)ctlbuf.buf;

	info->addr = infoackp->ADDR_size;
	info->options = infoackp->OPT_size;
	info->tsdu = infoackp->TSDU_size;
	info->etsdu = infoackp->ETSDU_size;
	info->connect = infoackp->CDATA_size;
	info->discon = infoackp->DDATA_size;
	info->servtype = infoackp->SERV_type;

	if (_T_IS_XTI(api_semantics)) {
		/* XTI ONLY - TLI t_info struct does not have "flags" */
		info->flags = 0;
		if (infoackp->PROVIDER_flag & (SENDZERO|OLD_SENDZERO))
			info->flags |= T_SENDZERO;
	}
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
