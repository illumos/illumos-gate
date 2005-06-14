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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"

mddb_set_t set_db;

/* print out the correct set */
int
print_set(uintptr_t addr)
{
	char		machine[1024];

	if (mdb_vread(&set_db, sizeof (mddb_set_t), addr) == -1) {
		if (addr != NULL) {
			mdb_warn("failed to read mddb_set_t at 0x%p\n", addr);
			return (DCMD_ERR);
		} else {
			return (DCMD_OK);
		}
	}

	if (set_db.s_setname != 0) {
		if (mdb_readstr(machine, 1024,
			(uintptr_t)set_db.s_setname) == -1) {
			mdb_warn("failed to read setname at 0x%p\n",
			    set_db.s_setname);
		} else {
			mdb_printf("Setname: %s Setno: %u\t%p\n",
			    machine, set_db.s_setno, addr);
		}
	} else {
		mdb_printf("Setname: NULL Setno: %u\t%p\n",
		    set_db.s_setno, addr);
	}

	mdb_inc_indent(2);
	mdb_printf("s_un = %p\n", mdset[set_db.s_setno].s_un);
	mdb_printf("s_hsp = %p\n", mdset[set_db.s_setno].s_hsp);
	mdb_dec_indent(2);
	return (DCMD_OK);
}

/*
 * print all sets or the specified set with -s option
 * usage: ::metaset
 */
/* ARGSUSED */
int
metaset(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	snarf_sets();

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("md_sets", "metaset", argc,
		    argv) == -1) {
			mdb_warn("failed to walk sets");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	print_set(addr);

	return (DCMD_OK);
}
