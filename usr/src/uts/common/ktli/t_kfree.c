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
 * Free the specified kernel tli data structure.
 *
 * Returns:
 * 	0 on success or
 * 	positive error code.
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
#include <sys/t_kuser.h>
#include <sys/kmem.h>


/*ARGSUSED*/
int
t_kfree(TIUSER *tiptr, char *ptr, int struct_type)
{
	union structptrs {
		struct t_bind		*bind;
		struct t_call		*call;
		struct t_discon		*dis;
		struct t_optmgmt	*opt;
		struct t_kunitdata	*udata;
		struct t_uderr		*uderr;
	} p;
	int error = 0;

	/*
	 * Free all the buffers associated with the appropriate
	 * fields of each structure.
	 */

	switch (struct_type) {
	case T_BIND:
		/* LINTED pointer alignment */
		p.bind = (struct t_bind *)ptr;
		if (p.bind->addr.buf != NULL)
			kmem_free(p.bind->addr.buf, p.bind->addr.maxlen);
		kmem_free(ptr, sizeof (struct t_bind));
		break;

	case T_CALL:
		/* LINTED pointer alignment */
		p.call = (struct t_call *)ptr;
		if (p.call->addr.buf != NULL)
			kmem_free(p.call->addr.buf, p.call->addr.maxlen);
		if (p.call->opt.buf != NULL)
			kmem_free(p.call->opt.buf, p.call->opt.maxlen);
		if (p.call->udata.buf != NULL)
			kmem_free(p.call->udata.buf, p.call->udata.maxlen);
		kmem_free(ptr, sizeof (struct t_call));
		break;

	case T_OPTMGMT:
		/* LINTED pointer alignment */
		p.opt = (struct t_optmgmt *)ptr;
		if (p.opt->opt.buf != NULL)
			kmem_free(p.opt->opt.buf, p.opt->opt.maxlen);
		kmem_free(ptr, sizeof (struct t_optmgmt));
		break;

	case T_DIS:
		/* LINTED pointer alignment */
		p.dis = (struct t_discon *)ptr;
		if (p.dis->udata.buf != NULL)
			kmem_free(p.dis->udata.buf, p.dis->udata.maxlen);
		kmem_free(ptr, sizeof (struct t_discon));
		break;

	case T_UNITDATA:
		/* LINTED pointer alignment */
		p.udata = (struct t_kunitdata *)ptr;

		if (p.udata->udata.udata_mp) {
			KTLILOG(2, "t_kfree: freeing mblk_t %x, ",
			    p.udata->udata.udata_mp);
			KTLILOG(2, "ref %d\n",
			    p.udata->udata.udata_mp->b_datap->db_ref);
			freemsg(p.udata->udata.udata_mp);
		}
		if (p.udata->opt.buf != NULL)
			kmem_free(p.udata->opt.buf, p.udata->opt.maxlen);
		if (p.udata->addr.buf != NULL) {
			KTLILOG(2, "t_kfree: freeing address %x, ",
			    p.udata->addr.buf);
			KTLILOG(2, "len %d\n", p.udata->addr.maxlen);
			kmem_free(p.udata->addr.buf, p.udata->addr.maxlen);
		}
		KTLILOG(2, "t_kfree: freeing t_kunitdata\n", 0);
		kmem_free(ptr, sizeof (struct t_kunitdata));
		break;

	case T_UDERROR:
		/* LINTED pointer alignment */
		p.uderr = (struct t_uderr *)ptr;
		if (p.uderr->addr.buf != NULL)
			kmem_free(p.uderr->addr.buf, p.uderr->addr.maxlen);
		if (p.uderr->opt.buf != NULL)
			kmem_free(p.uderr->opt.buf, p.uderr->opt.maxlen);
		kmem_free(ptr, sizeof (struct t_uderr));
		break;

	case T_INFO:
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
