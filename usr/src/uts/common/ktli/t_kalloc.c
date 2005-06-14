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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
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
 * Kernel TLI-like function to allocate memory for the various TLI
 * primitives.
 *
 * Returns 0 on success or a positive error value.  On success, ptr is
 * set the structure required.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/t_kuser.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>

static void _alloc_buf(struct netbuf *, t_scalar_t);

int
t_kalloc(TIUSER *tiptr, int struct_type, int fields, char **ptr)
{
	union structptrs {
		char *caddr;
		struct t_bind *bind;
		struct t_call *call;
		struct t_discon *dis;
		struct t_optmgmt *opt;
		struct t_kunitdata *udata;
		struct t_uderr *uderr;
		struct t_info *info;
	} p;
	t_scalar_t dsize;

	if (ptr == NULL)
		return (EINVAL);

	/*
	 * allocate appropriate structure and the specified
	 * fields within each structure.  Initialize the
	 * 'buf' and 'maxlen' fields of each.
	 */
	switch (struct_type) {
	case T_BIND:
		p.bind = kmem_zalloc(sizeof (struct t_bind), KM_SLEEP);
		if (fields & T_ADDR)
			_alloc_buf(&p.bind->addr, tiptr->tp_info.addr);
		*ptr = ((char *)p.bind);
		return (0);

	case T_CALL:
		p.call = kmem_zalloc(sizeof (struct t_call), KM_SLEEP);
		if (fields & T_ADDR)
			_alloc_buf(&p.call->addr, tiptr->tp_info.addr);
		if (fields & T_OPT)
			_alloc_buf(&p.call->opt, tiptr->tp_info.options);
		if (fields & T_UDATA) {
			dsize = MAX(tiptr->tp_info.connect,
			    tiptr->tp_info.discon);
			_alloc_buf(&p.call->opt, dsize);
		}
		*ptr = ((char *)p.call);
		return (0);

	case T_OPTMGMT:
		p.opt = kmem_zalloc(sizeof (struct t_optmgmt), KM_SLEEP);
		if (fields & T_OPT)
			_alloc_buf(&p.opt->opt, tiptr->tp_info.options);
		*ptr = ((char *)p.opt);
		return (0);

	case T_DIS:
		p.dis = kmem_zalloc(sizeof (struct t_discon), KM_SLEEP);
		if (fields & T_UDATA)
			_alloc_buf(&p.dis->udata, tiptr->tp_info.discon);
		*ptr = ((char *)p.dis);
		return (0);

	case T_UNITDATA:
		p.udata = kmem_zalloc(sizeof (struct t_kunitdata), KM_SLEEP);
		if (fields & T_ADDR)
			_alloc_buf(&p.udata->addr, tiptr->tp_info.addr);
		else
			p.udata->addr.maxlen = p.udata->addr.len = 0;

		if (fields & T_OPT)
			_alloc_buf(&p.udata->opt, tiptr->tp_info.options);
		else
			p.udata->opt.maxlen = p.udata->opt.len = 0;

		if (fields & T_UDATA) {
			p.udata->udata.udata_mp = NULL;
			p.udata->udata.buf = NULL;
			p.udata->udata.maxlen = tiptr->tp_info.tsdu;
			p.udata->udata.len = 0;
		} else {
			p.udata->udata.maxlen = p.udata->udata.len = 0;
		}
		*ptr = (char *)p.udata;
		return (0);

	case T_UDERROR:
		p.uderr = kmem_zalloc(sizeof (struct t_uderr), KM_SLEEP);
		if (fields & T_ADDR)
			_alloc_buf(&p.uderr->addr, tiptr->tp_info.addr);
		if (fields & T_OPT)
			_alloc_buf(&p.uderr->opt, tiptr->tp_info.options);
		*ptr = (char *)p.uderr;
		return (0);

	case T_INFO:
		p.info = kmem_zalloc(sizeof (struct t_info), KM_SLEEP);
		*ptr = (char *)p.info;
		return (0);

	default:
		return (EINVAL);
	}
}


static void
_alloc_buf(struct netbuf *buf, t_scalar_t n)
{
	switch (n) {
	case -1:
		buf->buf = kmem_zalloc(1024, KM_SLEEP);
		buf->maxlen = 1024;
		buf->len = 0;
		break;

	case 0:
	case -2:
		buf->buf = NULL;
		buf->maxlen = 0;
		buf->len = 0;
		break;

	default:
		buf->buf = kmem_zalloc(n, KM_SLEEP);
		buf->maxlen = n;
		buf->len = 0;
		break;
	}
}
