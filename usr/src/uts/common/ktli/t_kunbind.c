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
 * Kernel TLI-like function to unbind a transport endpoint
 * to an address.
 *
 * Returns 0 on success and ret is set if non-NULL,
 * else positive error code.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/vnode.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>


int
t_kunbind(TIUSER *tiptr)
{
	struct T_unbind_req	*unbind_req;
	struct T_ok_ack		*ok_ack;
	int			unbindsz;
	vnode_t			*vp;
	file_t			*fp;
	char			*buf;
	struct strioctl		strioc;
	int			retval;
	int			error;

	error = 0;
	retval = 0;
	fp = tiptr->fp;
	vp = fp->f_vnode;

	/*
	 * send the ioctl request and wait
	 * for a reply.
	 */
	unbindsz = MAX(TUNBINDREQSZ, TOKACKSZ);
	buf = kmem_alloc(unbindsz, KM_SLEEP);
	/* LINTED pointer alignment */
	unbind_req = (struct T_unbind_req *)buf;
	unbind_req->PRIM_type = T_UNBIND_REQ;

	strioc.ic_cmd = TI_UNBIND;
	strioc.ic_timout = 0;
	strioc.ic_dp = buf;
	strioc.ic_len = (int)TUNBINDREQSZ;

	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K, CRED(),
	    &retval);
	if (error)
		goto badbind;

	if (retval) {
		if ((retval & 0xff) == TSYSERR)
			error = (retval >> 8) & 0xff;
		else
			error = t_tlitosyserr(retval & 0xff);
		goto badbind;
	}

	/* LINTED pointer alignment */
	ok_ack = (struct T_ok_ack *)strioc.ic_dp;
	if (strioc.ic_len < TOKACKSZ ||
	    ok_ack->PRIM_type != T_OK_ACK ||
	    ok_ack->CORRECT_prim != T_UNBIND_REQ)
		error = EIO;

badbind:
	kmem_free(buf, unbindsz);
	return (error);
}
