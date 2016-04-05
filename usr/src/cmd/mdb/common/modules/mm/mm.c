/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <sys/time.h>
#include <sys/mem.h>

typedef struct kmemlog_walk {
	uintptr_t kmlw_addr;
	mm_logentry_t *kmlw_entries;
	int kmlw_nentries;
	int kmlw_entry;
	int kmlw_oldest;
} kmemlog_walk_t;

static int
kmemlog_walk_init(mdb_walk_state_t *wsp)
{
	kmemlog_walk_t *kw;
	GElf_Sym sym;

	if (mdb_lookup_by_name("mm_kmemlog", &sym) != 0) {
		mdb_warn("couldn't find symbol 'mm_kmemlog'");
		return (WALK_ERR);
	}

	kw = mdb_zalloc(sizeof (kmemlog_walk_t), UM_SLEEP);
	kw->kmlw_entries = mdb_zalloc(sym.st_size, UM_SLEEP);
	kw->kmlw_addr = sym.st_value;

	if (mdb_vread(kw->kmlw_entries, sym.st_size, sym.st_value) == -1) {
		mdb_warn("couldn't read log at %p", sym.st_value);
		mdb_free(kw->kmlw_entries, sym.st_size);
		mdb_free(kw, sizeof (kmemlog_walk_t));
		return (WALK_ERR);
	}

	kw->kmlw_nentries = sym.st_size / sizeof (mm_logentry_t);

	mdb_readvar(&kw->kmlw_entry, "mm_kmemlogent");
	kw->kmlw_oldest = kw->kmlw_entry;
	wsp->walk_data = kw;

	return (WALK_NEXT);
}

static int
kmemlog_walk_step(mdb_walk_state_t *wsp)
{
	kmemlog_walk_t *kw = wsp->walk_data;
	mm_logentry_t *ent;
	int rval = WALK_NEXT;

	ent = &kw->kmlw_entries[kw->kmlw_entry];

	if (++kw->kmlw_entry == kw->kmlw_nentries)
		kw->kmlw_entry = 0;

	if (ent->mle_hrtime != 0) {
		rval = wsp->walk_callback(kw->kmlw_addr + ((uintptr_t)ent -
		    (uintptr_t)kw->kmlw_entries), ent, wsp->walk_cbdata);
	}

	if (rval == WALK_NEXT && kw->kmlw_entry == kw->kmlw_oldest)
		return (WALK_DONE);

	return (rval);
}

static void
kmemlog_walk_fini(mdb_walk_state_t *wsp)
{
	kmemlog_walk_t *kw = wsp->walk_data;

	mdb_free(kw->kmlw_entries, kw->kmlw_nentries * sizeof (mm_logentry_t));
	mdb_free(kw, sizeof (kmemlog_walk_t));
}

static int
kmemlog(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mm_logentry_t ent;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("kmemlog", "kmemlog", argc, argv) == -1) {
			mdb_warn("can't walk 'kmemlog'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%?s %-20s %?s %5s %s\n",
		    "ADDR", "TIME", "VADDR", "PID", "PSARGS");
	}

	if (mdb_vread(&ent, sizeof (ent), addr) == -1) {
		mdb_warn("can't read mm_logentry_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %-20Y %?p %5d %s\n",
	    addr, ent.mle_hrestime.tv_sec, ent.mle_vaddr, ent.mle_pid,
	    ent.mle_psargs);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "kmemlog", NULL, "print log of writes via /dev/kmem", kmemlog },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "kmemlog", "walk entries in /dev/kmem write log",
		kmemlog_walk_init, kmemlog_walk_step, kmemlog_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
