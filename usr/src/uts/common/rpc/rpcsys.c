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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/types.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <rpc/rpcsys.h>
#include <sys/model.h>


/*ARGSUSED*/
int
rpcsys(enum rpcsys_op opcode, void *arg)
{
	switch (opcode) {
	case KRPC_REVAUTH:
		/* revoke the cached credentials for the given uid */
		{
		STRUCT_DECL(krpc_revauth, nra);
		int result;

		STRUCT_INIT(nra, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nra), STRUCT_SIZE(nra)))
			return (set_errno(EFAULT));

		result = sec_clnt_revoke(STRUCT_FGET(nra, rpcsec_flavor_1),
				STRUCT_FGET(nra, uid_1), CRED(),
				STRUCT_FGETP(nra, flavor_data_1),
				get_udatamodel());
		return ((result != 0) ? set_errno(result) : 0);
		}

	default:
		return (set_errno(EINVAL));
	}
}
