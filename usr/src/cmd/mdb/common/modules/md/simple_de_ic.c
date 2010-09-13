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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"

/* ARGSUSED */
int
simple_de_ic(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mddb_de_ic_t	value;
	char	*s = "addr+";
	uint_t	noaddr = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		noaddr = 1;
	} else {
		if (mdb_vread(&value, sizeof (mddb_de_ic_t), addr) !=
		    sizeof (mddb_de_ic_t)) {
			mdb_warn("failed to read mddb_de_ic_t at %ll#r\n",
			    addr);
			return (DCMD_ERR);
		}
		mdb_printf(" at %#lr", addr);
	}

	if (noaddr) {
		mdb_printf("\n\tde_recid%20s%-25#r\n",
			s, (uintptr_t)&value.de_recid - (uintptr_t)&value);
	} else {
		mdb_printf("\n\tde_recid: %28#r\n", value.de_recid);
	}

	return (DCMD_OK);
}
