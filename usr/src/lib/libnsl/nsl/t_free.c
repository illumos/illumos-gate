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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

#include "mt.h"
#include <xti.h>
#include <errno.h>
#include <stropts.h>
#include <stdlib.h>
#include <sys/types.h>
#include "tx.h"

int
_tx_free(char *ptr, int struct_type, int api_semantics)
{
	union structptrs {
		struct t_bind *bind;
		struct t_call *call;
		struct t_discon *dis;
		struct t_optmgmt *opt;
		struct t_unitdata *udata;
		struct t_uderr *uderr;
	} p;

	/*
	 * Free all the buffers associated with the appropriate
	 * fields of each structure.
	 */

	switch (struct_type) {

	case T_BIND:
		/* LINTED pointer cast */
		p.bind = (struct t_bind *)ptr;
		if (p.bind->addr.buf != NULL)
			free(p.bind->addr.buf);
		break;

	case T_CALL:
		/* LINTED pointer cast */
		p.call = (struct t_call *)ptr;
		if (p.call->addr.buf != NULL)
			free(p.call->addr.buf);
		if (p.call->opt.buf != NULL)
			free(p.call->opt.buf);
		if (p.call->udata.buf != NULL)
			free(p.call->udata.buf);
		break;

	case T_OPTMGMT:
		/* LINTED pointer cast */
		p.opt = (struct t_optmgmt *)ptr;
		if (p.opt->opt.buf != NULL)
			free(p.opt->opt.buf);
		break;

	case T_DIS:
		/* LINTED pointer cast */
		p.dis = (struct t_discon *)ptr;
		if (p.dis->udata.buf != NULL)
			free(p.dis->udata.buf);
		break;

	case T_UNITDATA:
		/* LINTED pointer cast */
		p.udata = (struct t_unitdata *)ptr;
		if (p.udata->addr.buf != NULL)
			free(p.udata->addr.buf);
		if (p.udata->opt.buf != NULL)
			free(p.udata->opt.buf);
		if (p.udata->udata.buf != NULL)
			free(p.udata->udata.buf);
		break;

	case T_UDERROR:
		/* LINTED pointer cast */
		p.uderr = (struct t_uderr *)ptr;
		if (p.uderr->addr.buf != NULL)
			free(p.uderr->addr.buf);
		if (p.uderr->opt.buf != NULL)
			free(p.uderr->opt.buf);
		break;

	case T_INFO:
		break;

	default:
		if (_T_IS_XTI(api_semantics)) {
			t_errno = TNOSTRUCTYPE;
		} else {	/* TX_TLI_API */
			t_errno = TSYSERR;
			errno = EINVAL;
		}
		return (-1);
	}

	free(ptr);
	return (0);
}
