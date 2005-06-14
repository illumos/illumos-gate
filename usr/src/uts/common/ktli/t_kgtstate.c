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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel TLI-like function to get the state of an
 * endpoint.
 *
 * Returns:
 * 	0 on success and "state" is set to the current state,
 * 	or a positive error code.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>


int
t_kgetstate(TIUSER *tiptr, int *state)
{
	struct T_info_ack	inforeq;
	struct strioctl		strioc;
	int 			retval;
	vnode_t 		*vp;
	file_t			*fp;
	int			error;

	error = 0;
	retval = 0;
	fp = tiptr->fp;
	vp = fp->f_vnode;

	if (state == NULL)
		return (EINVAL);

	inforeq.PRIM_type = T_INFO_REQ;
	strioc.ic_cmd = TI_GETINFO;
	strioc.ic_timout = 0;
	strioc.ic_dp = (char *)&inforeq;
	strioc.ic_len = (int)sizeof (struct T_info_req);

	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K, CRED(),
	    &retval);
	if (error)
		return (error);

	if (retval) {
		if ((retval & 0xff) == TSYSERR)
			error = (retval >> 8) & 0xff;
		else
			error = t_tlitosyserr(retval & 0xff);
		return (error);
	}

	if (strioc.ic_len != sizeof (struct T_info_ack))
		return (EPROTO);

	switch (inforeq.CURRENT_state) {
	case TS_UNBND:
		*state = T_UNBND;
		break;

	case TS_IDLE:
		*state = T_IDLE;
		break;

	case TS_WRES_CIND:
		*state = T_INCON;
		break;

	case TS_WCON_CREQ:
		*state = T_OUTCON;
		break;

	case TS_DATA_XFER:
		*state = T_DATAXFER;
		break;

	case TS_WIND_ORDREL:
		*state = T_OUTREL;
		break;

	case TS_WREQ_ORDREL:
		*state = T_INREL;
		break;

	default:
		error = EPROTO;
		break;
	}
	return (error);
}
