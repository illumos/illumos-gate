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

#include "dis.h"

extern mdb_tgt_addr_t ia32dis_ins2str(mdb_disasm_t *, mdb_tgt_t *,
    mdb_tgt_as_t, char *, size_t, mdb_tgt_addr_t);

/*ARGSUSED*/
static void
ia32dis_destroy(mdb_disasm_t *dp)
{
	/* Nothing to do here */
}

static mdb_tgt_addr_t
ia32dis_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t pc, uint_t n)
{
	mdb_tgt_addr_t *hist, addr, naddr;
	mdb_tgt_addr_t res = pc;
	GElf_Sym sym;
	int cur, nseen;
	char c;

	if (mdb_lookup_by_addr(pc, MDB_SYM_FUZZY, &c, 1, &sym) < 0 ||
	    sym.st_value == pc)
		return (pc); /* we need to be in the middle of a symbol */

	hist = mdb_zalloc(sizeof (mdb_tgt_addr_t) * n, UM_SLEEP);

	for (cur = 0, nseen = 0, addr = sym.st_value; addr < pc; addr = naddr) {
		hist[cur] = addr;
		cur = (cur + 1) % n;
		nseen++;

		if (mdb_tgt_aread(t, as, &c, 1, addr) != 1 ||
		    (naddr = ia32dis_ins2str(dp, t, as, &c, 1, addr)) == addr)
			goto done; /* no progress or can't read - give up */
	}

	if (addr != pc) {
		/*
		 * We scanned past %pc, but didn't find an instruction that
		 * started at %pc.  This means that either the caller specified
		 * an invalid address, or we ran into something other than code
		 * during our scan.  Virtually any combination of bytes can be
		 * construed as a valid Intel instruction, so any non-code bytes
		 * we encounter will have thrown off the scan.
		 */
		goto done;
	}

	res = hist[(cur + n - MIN(n, nseen)) % n];

done:
	mdb_free(hist, sizeof (mdb_tgt_addr_t) * n);
	return (res);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
ia32dis_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t pc)
{
	mdb_tgt_addr_t npc;
	char c;

	if ((npc = ia32dis_ins2str(dp, t, as, &c, 1, pc)) == pc)
		return (pc);

	/*
	 * Probe the address to make sure we can read something from it - we
	 * want the address we return to actually contain something.
	 */
	if (mdb_tgt_aread(t, as, &c, 1, npc) != 1)
		return (pc);

	return (npc);
}

static const mdb_dis_ops_t ia32dis_ops = {
	ia32dis_destroy,
	ia32dis_ins2str,
	ia32dis_previns,
	ia32dis_nextins
};

int
ia32_create(mdb_disasm_t *dp)
{
	dp->dis_name = "ia32";
	dp->dis_desc = "Intel 32-bit disassembler";
	dp->dis_ops = &ia32dis_ops;
	dp->dis_data = (void *)DIS_IA32;

	return (0);
}

int
amd64_create(mdb_disasm_t *dp)
{
	dp->dis_name = "amd64";
	dp->dis_desc = "AMD64 and IA32e 64-bit disassembler";
	dp->dis_ops = &ia32dis_ops;
	dp->dis_data = (void *)DIS_AMD64;

	return (0);
}
