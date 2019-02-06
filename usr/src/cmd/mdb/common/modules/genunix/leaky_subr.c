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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>

#include <sys/fs/ufs_inode.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <vm/seg_vn.h>
#include <vm/as.h>
#include <vm/seg_map.h>
#include <mdb/mdb_ctf.h>

#include "kmem.h"
#include "leaky_impl.h"

/*
 * This file defines the genunix target for leaky.c.  There are three types
 * of buffers in the kernel's heap:  TYPE_VMEM, for kmem_oversize allocations,
 * TYPE_KMEM, for kmem_cache_alloc() allocations bufctl_audit_ts, and
 * TYPE_CACHE, for kmem_cache_alloc() allocation without bufctl_audit_ts.
 *
 * See "leaky_impl.h" for the target interface definition.
 */

#define	TYPE_VMEM	0		/* lkb_data is the vmem_seg's size */
#define	TYPE_CACHE	1		/* lkb_cid is the bufctl's cache */
#define	TYPE_KMEM	2		/* lkb_cid is the bufctl's cache */

#define	LKM_CTL_BUFCTL	0	/* normal allocation, PTR is bufctl */
#define	LKM_CTL_VMSEG	1	/* oversize allocation, PTR is vmem_seg_t */
#define	LKM_CTL_CACHE	2	/* normal alloc, non-debug, PTR is cache */
#define	LKM_CTL_MASK	3L

#define	LKM_CTL(ptr, type)	(LKM_CTLPTR(ptr) | (type))
#define	LKM_CTLPTR(ctl)		((uintptr_t)(ctl) & ~(LKM_CTL_MASK))
#define	LKM_CTLTYPE(ctl)	((uintptr_t)(ctl) &  (LKM_CTL_MASK))

static int kmem_lite_count = 0;	/* cache of the kernel's version */

/*ARGSUSED*/
static int
leaky_mtab(uintptr_t addr, const kmem_bufctl_audit_t *bcp, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = (uintptr_t)bcp->bc_addr;
	lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_BUFCTL);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_mtab_addr(uintptr_t addr, void *ignored, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = addr;

	return (WALK_NEXT);
}

static int
leaky_seg(uintptr_t addr, const vmem_seg_t *seg, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = seg->vs_start;
	lm->lkm_limit = seg->vs_end;
	lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_VMSEG);

	return (WALK_NEXT);
}

static int
leaky_vmem_interested(const vmem_t *vmem)
{
	if (strcmp(vmem->vm_name, "kmem_oversize") != 0 &&
	    strcmp(vmem->vm_name, "static_alloc") != 0)
		return (0);
	return (1);
}

static int
leaky_vmem(uintptr_t addr, const vmem_t *vmem, leak_mtab_t **lmp)
{
	if (!leaky_vmem_interested(vmem))
		return (WALK_NEXT);

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)leaky_seg, lmp, addr) == -1)
		mdb_warn("can't walk vmem_alloc for kmem_oversize (%p)", addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_estimate_vmem(uintptr_t addr, const vmem_t *vmem, size_t *est)
{
	if (!leaky_vmem_interested(vmem))
		return (WALK_NEXT);

	*est += (int)(vmem->vm_kstat.vk_alloc.value.ui64 -
	    vmem->vm_kstat.vk_free.value.ui64);

	return (WALK_NEXT);
}

static int
leaky_interested(const kmem_cache_t *c)
{
	vmem_t vmem;

	/*
	 * ignore HAT-related caches that happen to derive from kmem_default
	 */
	if (strcmp(c->cache_name, "sfmmu1_cache") == 0 ||
	    strcmp(c->cache_name, "sf_hment_cache") == 0 ||
	    strcmp(c->cache_name, "pa_hment_cache") == 0)
		return (0);

	if (mdb_vread(&vmem, sizeof (vmem), (uintptr_t)c->cache_arena) == -1) {
		mdb_warn("cannot read arena %p for cache '%s'",
		    (uintptr_t)c->cache_arena, c->cache_name);
		return (0);
	}

	/*
	 * If this cache isn't allocating from the kmem_default,
	 * kmem_firewall, or static vmem arenas, we're not interested.
	 */
	if (strcmp(vmem.vm_name, "kmem_default") != 0 &&
	    strcmp(vmem.vm_name, "kmem_firewall") != 0 &&
	    strcmp(vmem.vm_name, "static") != 0)
		return (0);

	return (1);
}

static int
leaky_estimate(uintptr_t addr, const kmem_cache_t *c, size_t *est)
{
	if (!leaky_interested(c))
		return (WALK_NEXT);

	*est += kmem_estimate_allocated(addr, c);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_cache(uintptr_t addr, const kmem_cache_t *c, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = *lmp;
	mdb_walk_cb_t cb;
	const char *walk;
	int audit = (c->cache_flags & KMF_AUDIT);

	if (!leaky_interested(c))
		return (WALK_NEXT);

	if (audit) {
		walk = "bufctl";
		cb = (mdb_walk_cb_t)leaky_mtab;
	} else {
		walk = "kmem";
		cb = (mdb_walk_cb_t)leaky_mtab_addr;
	}
	if (mdb_pwalk(walk, cb, lmp, addr) == -1) {
		mdb_warn("can't walk kmem for cache %p (%s)", addr,
		    c->cache_name);
		return (WALK_DONE);
	}

	for (; lm < *lmp; lm++) {
		lm->lkm_limit = lm->lkm_base + c->cache_bufsize;
		if (!audit)
			lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_CACHE);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_scan_buffer(uintptr_t addr, const void *ignored, const kmem_cache_t *c)
{
	leaky_grep(addr, c->cache_bufsize);

	/*
	 * free, constructed KMF_LITE buffers keep their first uint64_t in
	 * their buftag's redzone.
	 */
	if (c->cache_flags & KMF_LITE) {
		/* LINTED alignment */
		kmem_buftag_t *btp = KMEM_BUFTAG(c, addr);
		leaky_grep((uintptr_t)&btp->bt_redzone,
		    sizeof (btp->bt_redzone));
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_scan_cache(uintptr_t addr, const kmem_cache_t *c, void *ignored)
{
	if (!leaky_interested(c))
		return (WALK_NEXT);

	/*
	 * Scan all of the free, constructed buffers, since they may have
	 * pointers to allocated objects.
	 */
	if (mdb_pwalk("freemem_constructed",
	    (mdb_walk_cb_t)leaky_scan_buffer, (void *)c, addr) == -1) {
		mdb_warn("can't walk freemem_constructed for cache %p (%s)",
		    addr, c->cache_name);
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_modctl(uintptr_t addr, const struct modctl *m, int *ignored)
{
	struct module mod;
	char name[MODMAXNAMELEN];

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_vread(&mod, sizeof (mod), (uintptr_t)m->mod_mp) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)m->mod_modname) == -1)
		(void) mdb_snprintf(name, sizeof (name), "0x%p", addr);

	leaky_grep((uintptr_t)m->mod_mp, sizeof (struct module));
	leaky_grep((uintptr_t)mod.data, mod.data_size);
	leaky_grep((uintptr_t)mod.bss, mod.bss_size);

	return (WALK_NEXT);
}

static int
leaky_thread(uintptr_t addr, const kthread_t *t, unsigned long *pagesize)
{
	uintptr_t size, base = (uintptr_t)t->t_stkbase;
	uintptr_t stk = (uintptr_t)t->t_stk;

	/*
	 * If this thread isn't in memory, we can't look at its stack.  This
	 * may result in false positives, so we print a warning.
	 */
	if (!(t->t_schedflag & TS_LOAD)) {
		mdb_printf("findleaks: thread %p's stack swapped out; "
		    "false positives possible\n", addr);
		return (WALK_NEXT);
	}

	if (t->t_state != TS_FREE)
		leaky_grep(base, stk - base);

	/*
	 * There is always gunk hanging out between t_stk and the page
	 * boundary.  If this thread structure wasn't kmem allocated,
	 * this will include the thread structure itself.  If the thread
	 * _is_ kmem allocated, we'll be able to get to it via allthreads.
	 */
	size = *pagesize - (stk & (*pagesize - 1));

	leaky_grep(stk, size);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_kstat(uintptr_t addr, vmem_seg_t *seg, void *ignored)
{
	leaky_grep(seg->vs_start, seg->vs_end - seg->vs_start);

	return (WALK_NEXT);
}

static void
leaky_kludge(void)
{
	GElf_Sym sym;
	mdb_ctf_id_t id, rid;

	int max_mem_nodes;
	uintptr_t *counters;
	size_t ncounters;
	ssize_t hwpm_size;
	int idx;

	/*
	 * Because of DR, the page counters (which live in the kmem64 segment)
	 * can point into kmem_alloc()ed memory.  The "page_counters" array
	 * is multi-dimensional, and each entry points to an array of
	 * "hw_page_map_t"s which is "max_mem_nodes" in length.
	 *
	 * To keep this from having too much grotty knowledge of internals,
	 * we use CTF data to get the size of the structure.  For simplicity,
	 * we treat the page_counters array as a flat array of pointers, and
	 * use its size to determine how much to scan.  Unused entries will
	 * be NULL.
	 */
	if (mdb_lookup_by_name("page_counters", &sym) == -1) {
		mdb_warn("unable to lookup page_counters");
		return;
	}

	if (mdb_readvar(&max_mem_nodes, "max_mem_nodes") == -1) {
		mdb_warn("unable to read max_mem_nodes");
		return;
	}

	if (mdb_ctf_lookup_by_name("unix`hw_page_map_t", &id) == -1 ||
	    mdb_ctf_type_resolve(id, &rid) == -1 ||
	    (hwpm_size = mdb_ctf_type_size(rid)) < 0) {
		mdb_warn("unable to lookup unix`hw_page_map_t");
		return;
	}

	counters = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);

	if (mdb_vread(counters, sym.st_size, (uintptr_t)sym.st_value) == -1) {
		mdb_warn("unable to read page_counters");
		return;
	}

	ncounters = sym.st_size / sizeof (counters);

	for (idx = 0; idx < ncounters; idx++) {
		uintptr_t addr = counters[idx];
		if (addr != 0)
			leaky_grep(addr, hwpm_size * max_mem_nodes);
	}
}

int
leaky_subr_estimate(size_t *estp)
{
	uintptr_t panicstr;
	int state;

	if ((state = mdb_get_state()) == MDB_STATE_RUNNING) {
		mdb_warn("findleaks: can only be run on a system "
		    "dump or under kmdb; see dumpadm(1M)\n");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&panicstr, "panicstr") == -1) {
		mdb_warn("can't read variable 'panicstr'");
		return (DCMD_ERR);
	}

	if (state != MDB_STATE_STOPPED && panicstr == 0) {
		mdb_warn("findleaks: cannot be run on a live dump.\n");
		return (DCMD_ERR);
	}

	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)leaky_estimate, estp) == -1) {
		mdb_warn("couldn't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	if (*estp == 0) {
		mdb_warn("findleaks: no buffers found\n");
		return (DCMD_ERR);
	}

	if (mdb_walk("vmem", (mdb_walk_cb_t)leaky_estimate_vmem, estp) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
leaky_subr_fill(leak_mtab_t **lmpp)
{
	if (mdb_walk("vmem", (mdb_walk_cb_t)leaky_vmem, lmpp) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)leaky_cache, lmpp) == -1) {
		mdb_warn("couldn't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kmem_lite_count, "kmem_lite_count") == -1) {
		mdb_warn("couldn't read 'kmem_lite_count'");
		kmem_lite_count = 0;
	} else if (kmem_lite_count > 16) {
		mdb_warn("kmem_lite_count nonsensical, ignored\n");
		kmem_lite_count = 0;
	}

	return (DCMD_OK);
}

int
leaky_subr_run(void)
{
	unsigned long ps = PAGESIZE;
	uintptr_t kstat_arena;
	uintptr_t dmods;

	leaky_kludge();

	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)leaky_scan_cache,
	    NULL) == -1) {
		mdb_warn("couldn't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	if (mdb_walk("modctl", (mdb_walk_cb_t)leaky_modctl, NULL) == -1) {
		mdb_warn("couldn't walk 'modctl'");
		return (DCMD_ERR);
	}

	/*
	 * If kmdb is loaded, we need to walk it's module list, since kmdb
	 * modctl structures can reference kmem allocations.
	 */
	if ((mdb_readvar(&dmods, "kdi_dmods") != -1) && (dmods != 0))
		(void) mdb_pwalk("modctl", (mdb_walk_cb_t)leaky_modctl,
		    NULL, dmods);

	if (mdb_walk("thread", (mdb_walk_cb_t)leaky_thread, &ps) == -1) {
		mdb_warn("couldn't walk 'thread'");
		return (DCMD_ERR);
	}

	if (mdb_walk("deathrow", (mdb_walk_cb_t)leaky_thread, &ps) == -1) {
		mdb_warn("couldn't walk 'deathrow'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kstat_arena, "kstat_arena") == -1) {
		mdb_warn("couldn't read 'kstat_arena'");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)leaky_kstat,
	    NULL, kstat_arena) == -1) {
		mdb_warn("couldn't walk kstat vmem arena");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
leaky_subr_add_leak(leak_mtab_t *lmp)
{
	uintptr_t addr = LKM_CTLPTR(lmp->lkm_bufctl);
	size_t depth;

	switch (LKM_CTLTYPE(lmp->lkm_bufctl)) {
	case LKM_CTL_VMSEG: {
		vmem_seg_t vs;

		if (mdb_vread(&vs, sizeof (vs), addr) == -1) {
			mdb_warn("couldn't read leaked vmem_seg at addr %p",
			    addr);
			return;
		}
		depth = MIN(vs.vs_depth, VMEM_STACK_DEPTH);

		leaky_add_leak(TYPE_VMEM, addr, vs.vs_start, vs.vs_timestamp,
		    vs.vs_stack, depth, 0, (vs.vs_end - vs.vs_start));
		break;
	}
	case LKM_CTL_BUFCTL: {
		kmem_bufctl_audit_t bc;

		if (mdb_vread(&bc, sizeof (bc), addr) == -1) {
			mdb_warn("couldn't read leaked bufctl at addr %p",
			    addr);
			return;
		}

		depth = MIN(bc.bc_depth, KMEM_STACK_DEPTH);

		/*
		 * The top of the stack will be kmem_cache_alloc+offset.
		 * Since the offset in kmem_cache_alloc() isn't interesting
		 * we skip that frame for the purposes of uniquifying stacks.
		 *
		 * We also use the cache pointer as the leaks's cid, to
		 * prevent the coalescing of leaks from different caches.
		 */
		if (depth > 0)
			depth--;
		leaky_add_leak(TYPE_KMEM, addr, (uintptr_t)bc.bc_addr,
		    bc.bc_timestamp, bc.bc_stack + 1, depth,
		    (uintptr_t)bc.bc_cache, 0);
		break;
	}
	case LKM_CTL_CACHE: {
		kmem_cache_t cache;
		kmem_buftag_lite_t bt;
		pc_t caller;
		int depth = 0;

		/*
		 * For KMF_LITE caches, we can get the allocation PC
		 * out of the buftag structure.
		 */
		if (mdb_vread(&cache, sizeof (cache), addr) != -1 &&
		    (cache.cache_flags & KMF_LITE) &&
		    kmem_lite_count > 0 &&
		    mdb_vread(&bt, sizeof (bt),
		    /* LINTED alignment */
		    (uintptr_t)KMEM_BUFTAG(&cache, lmp->lkm_base)) != -1) {
			caller = bt.bt_history[0];
			depth = 1;
		}
		leaky_add_leak(TYPE_CACHE, lmp->lkm_base, lmp->lkm_base, 0,
		    &caller, depth, addr, addr);
		break;
	}
	default:
		mdb_warn("internal error: invalid leak_bufctl_t\n");
		break;
	}
}

static void
leaky_subr_caller(const pc_t *stack, uint_t depth, char *buf, uintptr_t *pcp)
{
	int i;
	GElf_Sym sym;
	uintptr_t pc = 0;

	buf[0] = 0;

	for (i = 0; i < depth; i++) {
		pc = stack[i];

		if (mdb_lookup_by_addr(pc,
		    MDB_SYM_FUZZY, buf, MDB_SYM_NAMLEN, &sym) == -1)
			continue;
		if (strncmp(buf, "kmem_", 5) == 0)
			continue;
		if (strncmp(buf, "vmem_", 5) == 0)
			continue;
		*pcp = pc;

		return;
	}

	/*
	 * We're only here if the entire call chain begins with "kmem_";
	 * this shouldn't happen, but we'll just use the last caller.
	 */
	*pcp = pc;
}

int
leaky_subr_bufctl_cmp(const leak_bufctl_t *lhs, const leak_bufctl_t *rhs)
{
	char lbuf[MDB_SYM_NAMLEN], rbuf[MDB_SYM_NAMLEN];
	uintptr_t lcaller, rcaller;
	int rval;

	leaky_subr_caller(lhs->lkb_stack, lhs->lkb_depth, lbuf, &lcaller);
	leaky_subr_caller(rhs->lkb_stack, lhs->lkb_depth, rbuf, &rcaller);

	if (rval = strcmp(lbuf, rbuf))
		return (rval);

	if (lcaller < rcaller)
		return (-1);

	if (lcaller > rcaller)
		return (1);

	if (lhs->lkb_data < rhs->lkb_data)
		return (-1);

	if (lhs->lkb_data > rhs->lkb_data)
		return (1);

	return (0);
}

/*
 * Global state variables used by the leaky_subr_dump_* routines.  Note that
 * they are carefully cleared before use.
 */
static int lk_vmem_seen;
static int lk_cache_seen;
static int lk_kmem_seen;
static size_t lk_ttl;
static size_t lk_bytes;

void
leaky_subr_dump_start(int type)
{
	switch (type) {
	case TYPE_VMEM:
		lk_vmem_seen = 0;
		break;
	case TYPE_CACHE:
		lk_cache_seen = 0;
		break;
	case TYPE_KMEM:
		lk_kmem_seen = 0;
		break;
	default:
		break;
	}

	lk_ttl = 0;
	lk_bytes = 0;
}

void
leaky_subr_dump(const leak_bufctl_t *lkb, int verbose)
{
	const leak_bufctl_t *cur;
	kmem_cache_t cache;
	size_t min, max, size;
	char sz[30];
	char c[MDB_SYM_NAMLEN];
	uintptr_t caller;

	if (verbose) {
		lk_ttl = 0;
		lk_bytes = 0;
	}

	switch (lkb->lkb_type) {
	case TYPE_VMEM:
		if (!verbose && !lk_vmem_seen) {
			lk_vmem_seen = 1;
			mdb_printf("%-16s %7s %?s %s\n",
			    "BYTES", "LEAKED", "VMEM_SEG", "CALLER");
		}

		min = max = lkb->lkb_data;

		for (cur = lkb; cur != NULL; cur = cur->lkb_next) {
			size = cur->lkb_data;

			if (size < min)
				min = size;
			if (size > max)
				max = size;

			lk_ttl++;
			lk_bytes += size;
		}

		if (min == max)
			(void) mdb_snprintf(sz, sizeof (sz), "%ld", min);
		else
			(void) mdb_snprintf(sz, sizeof (sz), "%ld-%ld",
			    min, max);

		if (!verbose) {
			leaky_subr_caller(lkb->lkb_stack, lkb->lkb_depth,
			    c, &caller);

			if (caller != 0) {
				(void) mdb_snprintf(c, sizeof (c),
				    "%a", caller);
			} else {
				(void) mdb_snprintf(c, sizeof (c),
				    "%s", "?");
			}
			mdb_printf("%-16s %7d %?p %s\n", sz, lkb->lkb_dups + 1,
			    lkb->lkb_addr, c);
		} else {
			mdb_arg_t v;

			if (lk_ttl == 1)
				mdb_printf("kmem_oversize leak: 1 vmem_seg, "
				    "%ld bytes\n", lk_bytes);
			else
				mdb_printf("kmem_oversize leak: %d vmem_segs, "
				    "%s bytes each, %ld bytes total\n",
				    lk_ttl, sz, lk_bytes);

			v.a_type = MDB_TYPE_STRING;
			v.a_un.a_str = "-v";

			if (mdb_call_dcmd("vmem_seg", lkb->lkb_addr,
			    DCMD_ADDRSPEC, 1, &v) == -1) {
				mdb_warn("'%p::vmem_seg -v' failed",
				    lkb->lkb_addr);
			}
		}
		return;

	case TYPE_CACHE:
		if (!verbose && !lk_cache_seen) {
			lk_cache_seen = 1;
			if (lk_vmem_seen)
				mdb_printf("\n");
			mdb_printf("%-?s %7s %?s %s\n",
			    "CACHE", "LEAKED", "BUFFER", "CALLER");
		}

		if (mdb_vread(&cache, sizeof (cache), lkb->lkb_data) == -1) {
			/*
			 * This _really_ shouldn't happen; we shouldn't
			 * have been able to get this far if this
			 * cache wasn't readable.
			 */
			mdb_warn("can't read cache %p for leaked "
			    "buffer %p", lkb->lkb_data, lkb->lkb_addr);
			return;
		}

		lk_ttl += lkb->lkb_dups + 1;
		lk_bytes += (lkb->lkb_dups + 1) * cache.cache_bufsize;

		caller = (lkb->lkb_depth == 0) ? 0 : lkb->lkb_stack[0];
		if (caller != 0) {
			(void) mdb_snprintf(c, sizeof (c), "%a", caller);
		} else {
			(void) mdb_snprintf(c, sizeof (c),
			    "%s", (verbose) ? "" : "?");
		}

		if (!verbose) {
			mdb_printf("%0?p %7d %0?p %s\n", lkb->lkb_cid,
			    lkb->lkb_dups + 1, lkb->lkb_addr, c);
		} else {
			if (lk_ttl == 1)
				mdb_printf("%s leak: 1 buffer, %ld bytes,\n",
				    cache.cache_name, lk_bytes);
			else
				mdb_printf("%s leak: %d buffers, "
				    "%ld bytes each, %ld bytes total,\n",
				    cache.cache_name, lk_ttl,
				    cache.cache_bufsize, lk_bytes);

			mdb_printf("    sample addr %p%s%s\n",
			    lkb->lkb_addr, (caller == 0) ? "" : ", caller ", c);
		}
		return;

	case TYPE_KMEM:
		if (!verbose && !lk_kmem_seen) {
			lk_kmem_seen = 1;
			if (lk_vmem_seen || lk_cache_seen)
				mdb_printf("\n");
			mdb_printf("%-?s %7s %?s %s\n",
			    "CACHE", "LEAKED", "BUFCTL", "CALLER");
		}

		if (mdb_vread(&cache, sizeof (cache), lkb->lkb_cid) == -1) {
			/*
			 * This _really_ shouldn't happen; we shouldn't
			 * have been able to get this far if this
			 * cache wasn't readable.
			 */
			mdb_warn("can't read cache %p for leaked "
			    "bufctl %p", lkb->lkb_cid, lkb->lkb_addr);
			return;
		}

		lk_ttl += lkb->lkb_dups + 1;
		lk_bytes += (lkb->lkb_dups + 1) * cache.cache_bufsize;

		if (!verbose) {
			leaky_subr_caller(lkb->lkb_stack, lkb->lkb_depth,
			    c, &caller);

			if (caller != 0) {
				(void) mdb_snprintf(c, sizeof (c),
				    "%a", caller);
			} else {
				(void) mdb_snprintf(c, sizeof (c),
				    "%s", "?");
			}
			mdb_printf("%0?p %7d %0?p %s\n", lkb->lkb_cid,
			    lkb->lkb_dups + 1, lkb->lkb_addr, c);
		} else {
			mdb_arg_t v;

			if (lk_ttl == 1)
				mdb_printf("%s leak: 1 buffer, %ld bytes\n",
				    cache.cache_name, lk_bytes);
			else
				mdb_printf("%s leak: %d buffers, "
				    "%ld bytes each, %ld bytes total\n",
				    cache.cache_name, lk_ttl,
				    cache.cache_bufsize, lk_bytes);

			v.a_type = MDB_TYPE_STRING;
			v.a_un.a_str = "-v";

			if (mdb_call_dcmd("bufctl", lkb->lkb_addr,
			    DCMD_ADDRSPEC, 1, &v) == -1) {
				mdb_warn("'%p::bufctl -v' failed",
				    lkb->lkb_addr);
			}
		}
		return;

	default:
		return;
	}
}

void
leaky_subr_dump_end(int type)
{
	int i;
	int width;
	const char *leaks;

	switch (type) {
	case TYPE_VMEM:
		if (!lk_vmem_seen)
			return;

		width = 16;
		leaks = "kmem_oversize leak";
		break;

	case TYPE_CACHE:
		if (!lk_cache_seen)
			return;

		width = sizeof (uintptr_t) * 2;
		leaks = "buffer";
		break;

	case TYPE_KMEM:
		if (!lk_kmem_seen)
			return;

		width = sizeof (uintptr_t) * 2;
		leaks = "buffer";
		break;

	default:
		return;
	}

	for (i = 0; i < 72; i++)
		mdb_printf("-");
	mdb_printf("\n%*s %7ld %s%s, %ld byte%s\n",
	    width, "Total", lk_ttl, leaks, (lk_ttl == 1) ? "" : "s",
	    lk_bytes, (lk_bytes == 1) ? "" : "s");
}

int
leaky_subr_invoke_callback(const leak_bufctl_t *lkb, mdb_walk_cb_t cb,
    void *cbdata)
{
	kmem_bufctl_audit_t bc;
	vmem_seg_t vs;

	switch (lkb->lkb_type) {
	case TYPE_VMEM:
		if (mdb_vread(&vs, sizeof (vs), lkb->lkb_addr) == -1) {
			mdb_warn("unable to read vmem_seg at %p",
			    lkb->lkb_addr);
			return (WALK_NEXT);
		}
		return (cb(lkb->lkb_addr, &vs, cbdata));

	case TYPE_CACHE:
		return (cb(lkb->lkb_addr, NULL, cbdata));

	case TYPE_KMEM:
		if (mdb_vread(&bc, sizeof (bc), lkb->lkb_addr) == -1) {
			mdb_warn("unable to read bufctl at %p",
			    lkb->lkb_addr);
			return (WALK_NEXT);
		}
		return (cb(lkb->lkb_addr, &bc, cbdata));
	default:
		return (WALK_NEXT);
	}
}
