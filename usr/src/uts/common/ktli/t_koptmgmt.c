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
/*	  All Rights Reserved	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * kTLI variant of t_optmgmt(3NSL)
 * Returns 0 on success or an errno value.
 * Similar to libnsl t_optmgmt.c
 *
 * Note: This expects the caller's struct t_optmgmt to contain the
 * XTI version of struct T_opthdr (used with T_OPTMGMT_REQ == 27)
 * not the old "struct opthdr" (used with T_SVR4_OPTMGMT_REQ == 9)
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
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/kmem.h>

int
t_koptmgmt(TIUSER *tiptr, struct t_optmgmt *req, struct t_optmgmt *ret)
{
	struct strioctl		strioc;
	struct T_optmgmt_req	*opt_req;
	struct T_optmgmt_ack	*opt_ack;
	file_t			*fp;
	vnode_t			*vp;
	char			*ctlbuf = NULL;
	char			*opt_data;
	t_scalar_t		optlen;
	int			ctlsize;
	int			retval;
	int			error;

	fp = tiptr->fp;
	vp = fp->f_vnode;

	optlen = req->opt.len;
	if (optlen > 0) {
		if (req->opt.buf == NULL)
			return (EINVAL);
		if (optlen < (t_scalar_t)sizeof (struct T_opthdr)) {
			/* option buffer should atleast have an t_opthdr */
			return (EINVAL);
		}
		/* sanity limit */
		if (optlen > 4096) {
			return (EINVAL);
		}
	}

	ctlsize = sizeof (*opt_req) + optlen;
	ctlbuf = kmem_alloc(ctlsize, KM_SLEEP);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	opt_req = (struct T_optmgmt_req *)ctlbuf;
	opt_req->PRIM_type = T_OPTMGMT_REQ;
	opt_req->MGMT_flags = req->flags;
	opt_req->OPT_length = optlen;
	opt_req->OPT_offset = sizeof (*opt_req);
	if (optlen > 0) {
		opt_data = ctlbuf + sizeof (*opt_req);
		bcopy(req->opt.buf, opt_data, optlen);
	}

	strioc.ic_cmd = TI_OPTMGMT;
	strioc.ic_timout = 0;
	strioc.ic_dp = ctlbuf;
	strioc.ic_len = ctlsize;

	error = strdoioctl(vp->v_stream, &strioc, FNATIVE, K_TO_K,
	    fp->f_cred, &retval);
	if (error)
		goto errout;

	if (retval) {
		if ((retval & 0xff) == TSYSERR)
			error = (retval >> 8) & 0xff;
		else
			error = t_tlitosyserr(retval & 0xff);
		goto errout;
	}

	if (strioc.ic_len < sizeof (struct T_optmgmt_ack)) {
		error = EPROTO;
		goto errout;
	}

	/* LINTED pointer cast */
	opt_ack = (struct T_optmgmt_ack *)ctlbuf;
	if (opt_ack->PRIM_type != T_OPTMGMT_ACK) {
		error = EPROTO;
		goto errout;
	}

	if (ret->opt.maxlen > 0) {
		if (opt_ack->OPT_length > ret->opt.maxlen) {
			error = EMSGSIZE;
			goto errout;
		}
		ret->opt.len = opt_ack->OPT_offset;
		opt_data = ctlbuf + opt_ack->OPT_offset;
		bcopy(opt_data, ret->opt.buf, ret->opt.len);
	}
	ret->flags = opt_ack->MGMT_flags;

errout:
	if (ctlbuf != NULL)
		kmem_free(ctlbuf, ctlsize);
	return (error);
}
