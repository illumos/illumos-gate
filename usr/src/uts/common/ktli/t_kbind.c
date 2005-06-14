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
 * Kernel TLI-like function to bind a transport endpoint
 * to an address.
 *
 * Returns 0 on success or positive error code.
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
t_kbind(TIUSER *tiptr, struct t_bind *req, struct t_bind *ret)
{
	struct T_bind_req	*bind_req;
	struct T_bind_ack	*bind_ack;
	int 			bindsz;
	vnode_t 		*vp;
	file_t 			*fp;
	char 			*buf;
	struct strioctl 	strioc;
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
	bindsz = (req == NULL) ? 0 : req->addr.len;
	bindsz = MAX(bindsz, tiptr->tp_info.addr);
	bindsz += MAX(TBINDREQSZ, TBINDACKSZ);
	buf = kmem_alloc(bindsz, KM_SLEEP);

	/* LINTED pointer alignment */
	bind_req = (struct T_bind_req *)buf;
	bind_req->PRIM_type = T_BIND_REQ;
	bind_req->ADDR_length = (req == NULL ? 0 : req->addr.len);
	bind_req->ADDR_offset = TBINDREQSZ;
	bind_req->CONIND_number = (req == NULL ? 0 : req->qlen);

	if (bind_req->ADDR_length)
		bcopy(req->addr.buf, buf + bind_req->ADDR_offset,
		    bind_req->ADDR_length);

	strioc.ic_cmd = TI_BIND;
	strioc.ic_timout = 0;
	strioc.ic_dp = buf;
	strioc.ic_len = (int)TBINDREQSZ + bind_req->ADDR_length;

	/*
	 * Usually ioctl()s are performed with the credential of the caller;
	 * in this particular case we specifically use the credential of
	 * the opener as this call is typically done in the context of a user
	 * process but on behalf of the kernel, e.g., a client connection
	 * to a server which is later shared by different users.
	 * At open time, we make sure to set fp->f_cred to kcred if such is
	 * the case.
	 */
	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K, fp->f_cred,
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
	bind_ack = (struct T_bind_ack *)strioc.ic_dp;
	if (strioc.ic_len < TBINDACKSZ || bind_ack->ADDR_length == 0) {
		error = EIO;
		goto badbind;
	}

	/*
	 * copy bind data into users buffer
	 */
	if (ret) {
		if (ret->addr.maxlen > bind_ack->ADDR_length)
			ret->addr.len = bind_ack->ADDR_length;
		else
			ret->addr.len = ret->addr.maxlen;

		bcopy(buf + bind_ack->ADDR_offset, ret->addr.buf,
		    ret->addr.len);

		ret->qlen = bind_ack->CONIND_number;
	}

badbind:
	kmem_free(buf, bindsz);
	return (error);
}
