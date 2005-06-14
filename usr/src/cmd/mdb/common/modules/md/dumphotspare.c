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

static void
printhsp(hot_spare_pool_t hsp, uintptr_t hsp_addr)
{
	int 	i = 0;
	uintptr_t	hs_addr;
	int	recid;

	mdb_inc_indent(2);
	mdb_printf("hsp_next: %p\n", hsp.hsp_next);
	mdb_printf("hsp_link:\n");
	mdb_inc_indent(2);
	mdb_printf("ln_next: %p\n", hsp.hsp_link.ln_next);
	mdb_printf("ln_setno: %u\n", hsp.hsp_link.ln_setno);
	mdb_printf("ln_id: %u\n", hsp.hsp_link.ln_id);
	mdb_inc_indent(2);
	mdb_printf("--- on disk structures ---\n");
	mdb_printf("hsp_revision:   %u\n", hsp.hsp_revision);
	mdb_printf("hsp_self_id:    %u \n", hsp.hsp_self_id);
	mdb_printf("hsp_record_id:  %d \n", hsp.hsp_record_id);
	mdb_printf("hsp_refcount:   %d\n", hsp.hsp_refcount);
	mdb_printf("hsp_nhotspares: %d # Number of slices in the pool\n",
	    hsp.hsp_nhotspares);
	mdb_inc_indent(1);

	hs_addr = hsp_addr + ((uintptr_t)&hsp.hsp_hotspares - (uintptr_t)&hsp);

	for (i = 0; i < hsp.hsp_nhotspares; i++) {
		if (mdb_vread(&recid, sizeof (int), hs_addr) !=
		    sizeof (int)) {
			mdb_warn("failed to read recid at %p\n", hs_addr);
			break;
		}
		mdb_printf("hsp_hotspares[%d]: %d", i, recid);
		mdb_printf(" # should match an hs_record_id in s_hs list\n");
		hs_addr += (uintptr_t)sizeof (int);
	}
	mdb_dec_indent(1);
	mdb_printf("--- end of on disk ---\n");
	mdb_dec_indent(2);
	mdb_dec_indent(2);
	mdb_dec_indent(2);
}

static void
process_hsp(uintptr_t addr)
{
	hot_spare_pool_t	hsp;

	if (mdb_vread(&hsp, sizeof (hot_spare_pool_t), addr) !=
	    sizeof (hot_spare_pool_t)) {
		mdb_warn("failed to read hot_spare_pool_t at %p\n", addr);
		return;
	}
	mdb_inc_indent(2);
	mdb_printf("%p\n", addr);
	printhsp(hsp, addr);
	mdb_dec_indent(2);
}
/*
 * Dump out the hotspare pools
 * usage: ::dumphotspare
 */
int
dumphotspare(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)	/* ensure no options */
		return (DCMD_USAGE);

	snarf_sets();

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("hotsparepool", "dumphotspare", argc,
		    argv) == -1) {
			mdb_warn("failed to walk hotsparepool");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	process_hsp(addr);

	return (DCMD_OK);
}
