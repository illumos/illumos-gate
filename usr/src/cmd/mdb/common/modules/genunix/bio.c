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

#include <mdb/mdb_modapi.h>
#include <sys/buf.h>
#include <sys/var.h>
#include <vm/page.h>

#include "bio.h"

typedef struct buf_walk {
	uintptr_t bw_hbufbase;		/* Base address of hbuf buckets */
	struct hbuf *bw_hbufs;		/* Snapshot of hbuf buckets */
	size_t bw_nhbufs;		/* Number of hbuf buckets */
	size_t bw_hbufi;		/* Current hbuf index */
	buf_t *bw_bufp;			/* Current buffer */
} buf_walk_t;

int
buf_walk_init(mdb_walk_state_t *wsp)
{
	struct hbuf *hbufs;
	struct var v;

	uintptr_t hbuf_addr;
	size_t nbytes;

	buf_walk_t *bwp;

	if (wsp->walk_addr != 0) {
		mdb_warn("only global buf walk supported\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&v, "v") == -1) {
		mdb_warn("failed to read var struct");
		return (WALK_ERR);
	}

	if (mdb_readvar(&hbuf_addr, "hbuf") == -1) {
		mdb_warn("failed to read hbuf pointer");
		return (WALK_ERR);
	}

	nbytes = sizeof (struct hbuf) * v.v_hbuf;
	hbufs = mdb_alloc(nbytes, UM_SLEEP);

	if (mdb_vread(hbufs, nbytes, hbuf_addr) != nbytes) {
		mdb_warn("failed to read hbufs");
		mdb_free(hbufs, nbytes);
		return (WALK_ERR);
	}

	bwp = mdb_alloc(sizeof (buf_walk_t), UM_SLEEP);

	bwp->bw_hbufbase = hbuf_addr;
	bwp->bw_hbufs = hbufs;
	bwp->bw_nhbufs = v.v_hbuf;
	bwp->bw_hbufi = 0;
	bwp->bw_bufp = mdb_alloc(sizeof (buf_t), UM_SLEEP);

	wsp->walk_addr = (uintptr_t)hbufs[0].b_forw;
	wsp->walk_data = bwp;

	return (WALK_NEXT);
}

int
buf_walk_step(mdb_walk_state_t *wsp)
{
	buf_walk_t *bwp = wsp->walk_data;
	uintptr_t addr;

	/*
	 * If the next buf_t address we want is NULL or points back at the
	 * hbuf itself, advance to the next hash bucket.  When we reach
	 * bw_nhbufs, we're done.
	 */
	while (wsp->walk_addr == 0 || wsp->walk_addr == (bwp->bw_hbufbase +
	    bwp->bw_hbufi * sizeof (struct hbuf))) {

		if (++bwp->bw_hbufi == bwp->bw_nhbufs)
			return (WALK_DONE);

		wsp->walk_addr = (uintptr_t)
		    bwp->bw_hbufs[bwp->bw_hbufi].b_forw;
	}

	/*
	 * When we have a buf_t address, read the buffer and invoke our
	 * walk callback.  We keep the next buf_t address in wsp->walk_addr.
	 */
	addr = wsp->walk_addr;
	(void) mdb_vread(bwp->bw_bufp, sizeof (buf_t), addr);
	wsp->walk_addr = (uintptr_t)bwp->bw_bufp->b_forw;

	return (wsp->walk_callback(addr, bwp->bw_bufp, wsp->walk_cbdata));
}

void
buf_walk_fini(mdb_walk_state_t *wsp)
{
	buf_walk_t *bwp = wsp->walk_data;

	mdb_free(bwp->bw_hbufs, sizeof (struct hbuf) * bwp->bw_nhbufs);
	mdb_free(bwp->bw_bufp, sizeof (buf_t));
	mdb_free(bwp, sizeof (buf_walk_t));
}

/*ARGSUSED*/
int
bufpagefind(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t b_addr = addr;
	uintptr_t arg;

	page_t p;
	buf_t b;

	if (argc != 1)
		return (DCMD_USAGE);

	if (argv->a_type == MDB_TYPE_IMMEDIATE)
		arg = (uintptr_t)argv->a_un.a_val;
	else
		arg = (uintptr_t)mdb_strtoull(argv->a_un.a_str);

	if (mdb_vread(&b, sizeof (buf_t), b_addr) == -1)
		return (DCMD_ERR);

	for (addr = (uintptr_t)b.b_pages; addr != 0;
	    addr = (uintptr_t)p.p_next) {

		if (addr == arg) {
			mdb_printf("buf %p has page %p on b_pages list\n",
			    b_addr, addr);
			break;
		}

		if (mdb_vread(&p, sizeof (page_t), addr) == -1)
			return (DCMD_ERR);
	}

	return (DCMD_OK);
}
