/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include "umem.h"

#include <sys/vmem_impl_user.h>
#include <umem_impl.h>

#include <alloca.h>
#include <limits.h>
#include <mdb/mdb_whatis.h>
#include <thr_uberdata.h>

#include "misc.h"
#include "leaky.h"
#include "dist.h"

#include "umem_pagesize.h"

#define	UM_ALLOCATED		0x1
#define	UM_FREE			0x2
#define	UM_BUFCTL		0x4
#define	UM_HASH			0x8

int umem_ready;

static int umem_stack_depth_warned;
static uint32_t umem_max_ncpus;
uint32_t umem_stack_depth;

size_t umem_pagesize;

#define	UMEM_READVAR(var)				\
	(umem_readvar(&(var), #var) == -1 &&		\
	    (mdb_warn("failed to read "#var), 1))

int
umem_update_variables(void)
{
	size_t pagesize;

	/*
	 * Figure out which type of umem is being used; if it's not there
	 * yet, succeed quietly.
	 */
	if (umem_set_standalone() == -1) {
		umem_ready = 0;
		return (0);		/* umem not there yet */
	}

	/*
	 * Solaris 9 used a different name for umem_max_ncpus.  It's
	 * cheap backwards compatibility to check for both names.
	 */
	if (umem_readvar(&umem_max_ncpus, "umem_max_ncpus") == -1 &&
	    umem_readvar(&umem_max_ncpus, "max_ncpus") == -1) {
		mdb_warn("unable to read umem_max_ncpus or max_ncpus");
		return (-1);
	}
	if (UMEM_READVAR(umem_ready))
		return (-1);
	if (UMEM_READVAR(umem_stack_depth))
		return (-1);
	if (UMEM_READVAR(pagesize))
		return (-1);

	if (umem_stack_depth > UMEM_MAX_STACK_DEPTH) {
		if (umem_stack_depth_warned == 0) {
			mdb_warn("umem_stack_depth corrupted (%d > %d)\n",
			    umem_stack_depth, UMEM_MAX_STACK_DEPTH);
			umem_stack_depth_warned = 1;
		}
		umem_stack_depth = 0;
	}

	umem_pagesize = pagesize;

	return (0);
}

static int
umem_ptc_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		if (mdb_layered_walk("ulwp", wsp) == -1) {
			mdb_warn("couldn't walk 'ulwp'");
			return (WALK_ERR);
		}
	}

	return (WALK_NEXT);
}

static int
umem_ptc_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t this;
	int rval;

	if (wsp->walk_layer != NULL) {
		this = (uintptr_t)((ulwp_t *)wsp->walk_layer)->ul_self +
		    (uintptr_t)wsp->walk_arg;
	} else {
		this = wsp->walk_addr + (uintptr_t)wsp->walk_arg;
	}

	for (;;) {
		if (mdb_vread(&this, sizeof (void *), this) == -1) {
			mdb_warn("couldn't read ptc buffer at %p", this);
			return (WALK_ERR);
		}

		if (this == NULL)
			break;

		rval = wsp->walk_callback(this, &this, wsp->walk_cbdata);

		if (rval != WALK_NEXT)
			return (rval);
	}

	return (wsp->walk_layer != NULL ? WALK_NEXT : WALK_DONE);
}

/*ARGSUSED*/
static int
umem_init_walkers(uintptr_t addr, const umem_cache_t *c, int *sizes)
{
	mdb_walker_t w;
	char descr[64];
	char name[64];
	int i;

	(void) mdb_snprintf(descr, sizeof (descr),
	    "walk the %s cache", c->cache_name);

	w.walk_name = c->cache_name;
	w.walk_descr = descr;
	w.walk_init = umem_walk_init;
	w.walk_step = umem_walk_step;
	w.walk_fini = umem_walk_fini;
	w.walk_init_arg = (void *)addr;

	if (mdb_add_walker(&w) == -1)
		mdb_warn("failed to add %s walker", c->cache_name);

	if (!(c->cache_flags & UMF_PTC))
		return (WALK_NEXT);

	/*
	 * For the per-thread cache walker, the address is the offset in the
	 * tm_roots[] array of the ulwp_t.
	 */
	for (i = 0; sizes[i] != 0; i++) {
		if (sizes[i] == c->cache_bufsize)
			break;
	}

	if (sizes[i] == 0) {
		mdb_warn("cache %s is cached per-thread, but could not find "
		    "size in umem_alloc_sizes\n", c->cache_name);
		return (WALK_NEXT);
	}

	if (i >= NTMEMBASE) {
		mdb_warn("index for %s (%d) exceeds root slots (%d)\n",
		    c->cache_name, i, NTMEMBASE);
		return (WALK_NEXT);
	}

	(void) mdb_snprintf(name, sizeof (name),
	    "umem_ptc_%d", c->cache_bufsize);
	(void) mdb_snprintf(descr, sizeof (descr),
	    "walk the per-thread cache for %s", c->cache_name);

	w.walk_name = name;
	w.walk_descr = descr;
	w.walk_init = umem_ptc_walk_init;
	w.walk_step = umem_ptc_walk_step;
	w.walk_fini = NULL;
	w.walk_init_arg = (void *)offsetof(ulwp_t, ul_tmem.tm_roots[i]);

	if (mdb_add_walker(&w) == -1)
		mdb_warn("failed to add %s walker", w.walk_name);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static void
umem_statechange_cb(void *arg)
{
	static int been_ready = 0;
	GElf_Sym sym;
	int *sizes;

#ifndef _KMDB
	leaky_cleanup(1);	/* state changes invalidate leaky state */
#endif

	if (umem_update_variables() == -1)
		return;

	if (been_ready)
		return;

	if (umem_ready != UMEM_READY)
		return;

	been_ready = 1;

	/*
	 * In order to determine the tm_roots offset of any cache that is
	 * cached per-thread, we need to have the umem_alloc_sizes array.
	 * Read this, assuring that it is zero-terminated.
	 */
	if (umem_lookup_by_name("umem_alloc_sizes", &sym) == -1) {
		mdb_warn("unable to lookup 'umem_alloc_sizes'");
		return;
	}

	sizes = mdb_zalloc(sym.st_size + sizeof (int), UM_SLEEP | UM_GC);

	if (mdb_vread(sizes, sym.st_size, (uintptr_t)sym.st_value) == -1) {
		mdb_warn("couldn't read 'umem_alloc_sizes'");
		return;
	}

	(void) mdb_walk("umem_cache", (mdb_walk_cb_t)umem_init_walkers, sizes);
}

int
umem_abort_messages(void)
{
	char *umem_error_buffer;
	uint_t umem_error_begin;
	GElf_Sym sym;
	size_t bufsize;

	if (UMEM_READVAR(umem_error_begin))
		return (DCMD_ERR);

	if (umem_lookup_by_name("umem_error_buffer", &sym) == -1) {
		mdb_warn("unable to look up umem_error_buffer");
		return (DCMD_ERR);
	}

	bufsize = (size_t)sym.st_size;

	umem_error_buffer = mdb_alloc(bufsize+1, UM_SLEEP | UM_GC);

	if (mdb_vread(umem_error_buffer, bufsize, (uintptr_t)sym.st_value)
	    != bufsize) {
		mdb_warn("unable to read umem_error_buffer");
		return (DCMD_ERR);
	}
	/* put a zero after the end of the buffer to simplify printing */
	umem_error_buffer[bufsize] = 0;

	if ((umem_error_begin % bufsize) == 0)
		mdb_printf("%s\n", umem_error_buffer);
	else {
		umem_error_buffer[(umem_error_begin % bufsize) - 1] = 0;
		mdb_printf("%s%s\n",
		    &umem_error_buffer[umem_error_begin % bufsize],
		    umem_error_buffer);
	}

	return (DCMD_OK);
}

static void
umem_log_status(const char *name, umem_log_header_t *val)
{
	umem_log_header_t my_lh;
	uintptr_t pos = (uintptr_t)val;
	size_t size;

	if (pos == NULL)
		return;

	if (mdb_vread(&my_lh, sizeof (umem_log_header_t), pos) == -1) {
		mdb_warn("\nunable to read umem_%s_log pointer %p",
		    name, pos);
		return;
	}

	size = my_lh.lh_chunksize * my_lh.lh_nchunks;

	if (size % (1024 * 1024) == 0)
		mdb_printf("%s=%dm ", name, size / (1024 * 1024));
	else if (size % 1024 == 0)
		mdb_printf("%s=%dk ", name, size / 1024);
	else
		mdb_printf("%s=%d ", name, size);
}

typedef struct umem_debug_flags {
	const char	*udf_name;
	uint_t		udf_flags;
	uint_t		udf_clear;	/* if 0, uses udf_flags */
} umem_debug_flags_t;

umem_debug_flags_t umem_status_flags[] = {
	{ "random",	UMF_RANDOMIZE,	UMF_RANDOM },
	{ "default",	UMF_AUDIT | UMF_DEADBEEF | UMF_REDZONE | UMF_CONTENTS },
	{ "audit",	UMF_AUDIT },
	{ "guards",	UMF_DEADBEEF | UMF_REDZONE },
	{ "nosignal",	UMF_CHECKSIGNAL },
	{ "firewall",	UMF_FIREWALL },
	{ "lite",	UMF_LITE },
	{ NULL }
};

/*ARGSUSED*/
int
umem_status(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *argv)
{
	int umem_logging;

	umem_log_header_t *umem_transaction_log;
	umem_log_header_t *umem_content_log;
	umem_log_header_t *umem_failure_log;
	umem_log_header_t *umem_slab_log;

	mdb_printf("Status:\t\t%s\n",
	    umem_ready == UMEM_READY_INIT_FAILED ? "initialization failed" :
	    umem_ready == UMEM_READY_STARTUP ? "uninitialized" :
	    umem_ready == UMEM_READY_INITING ? "initialization in process" :
	    umem_ready == UMEM_READY ? "ready and active" :
	    umem_ready == 0 ? "not loaded into address space" :
	    "unknown (umem_ready invalid)");

	if (umem_ready == 0)
		return (DCMD_OK);

	mdb_printf("Concurrency:\t%d\n", umem_max_ncpus);

	if (UMEM_READVAR(umem_logging))
		goto err;
	if (UMEM_READVAR(umem_transaction_log))
		goto err;
	if (UMEM_READVAR(umem_content_log))
		goto err;
	if (UMEM_READVAR(umem_failure_log))
		goto err;
	if (UMEM_READVAR(umem_slab_log))
		goto err;

	mdb_printf("Logs:\t\t");
	umem_log_status("transaction", umem_transaction_log);
	umem_log_status("content", umem_content_log);
	umem_log_status("fail", umem_failure_log);
	umem_log_status("slab", umem_slab_log);
	if (!umem_logging)
		mdb_printf("(inactive)");
	mdb_printf("\n");

	mdb_printf("Message buffer:\n");
	return (umem_abort_messages());

err:
	mdb_printf("Message buffer:\n");
	(void) umem_abort_messages();
	return (DCMD_ERR);
}

typedef struct {
	uintptr_t ucw_first;
	uintptr_t ucw_current;
} umem_cache_walk_t;

int
umem_cache_walk_init(mdb_walk_state_t *wsp)
{
	umem_cache_walk_t *ucw;
	umem_cache_t c;
	uintptr_t cp;
	GElf_Sym sym;

	if (umem_lookup_by_name("umem_null_cache", &sym) == -1) {
		mdb_warn("couldn't find umem_null_cache");
		return (WALK_ERR);
	}

	cp = (uintptr_t)sym.st_value;

	if (mdb_vread(&c, sizeof (umem_cache_t), cp) == -1) {
		mdb_warn("couldn't read cache at %p", cp);
		return (WALK_ERR);
	}

	ucw = mdb_alloc(sizeof (umem_cache_walk_t), UM_SLEEP);

	ucw->ucw_first = cp;
	ucw->ucw_current = (uintptr_t)c.cache_next;
	wsp->walk_data = ucw;

	return (WALK_NEXT);
}

int
umem_cache_walk_step(mdb_walk_state_t *wsp)
{
	umem_cache_walk_t *ucw = wsp->walk_data;
	umem_cache_t c;
	int status;

	if (mdb_vread(&c, sizeof (umem_cache_t), ucw->ucw_current) == -1) {
		mdb_warn("couldn't read cache at %p", ucw->ucw_current);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(ucw->ucw_current, &c, wsp->walk_cbdata);

	if ((ucw->ucw_current = (uintptr_t)c.cache_next) == ucw->ucw_first)
		return (WALK_DONE);

	return (status);
}

void
umem_cache_walk_fini(mdb_walk_state_t *wsp)
{
	umem_cache_walk_t *ucw = wsp->walk_data;
	mdb_free(ucw, sizeof (umem_cache_walk_t));
}

typedef struct {
	umem_cpu_t *ucw_cpus;
	uint32_t ucw_current;
	uint32_t ucw_max;
} umem_cpu_walk_state_t;

int
umem_cpu_walk_init(mdb_walk_state_t *wsp)
{
	umem_cpu_t *umem_cpus;

	umem_cpu_walk_state_t *ucw;

	if (umem_readvar(&umem_cpus, "umem_cpus") == -1) {
		mdb_warn("failed to read 'umem_cpus'");
		return (WALK_ERR);
	}

	ucw = mdb_alloc(sizeof (*ucw), UM_SLEEP);

	ucw->ucw_cpus = umem_cpus;
	ucw->ucw_current = 0;
	ucw->ucw_max = umem_max_ncpus;

	wsp->walk_data = ucw;
	return (WALK_NEXT);
}

int
umem_cpu_walk_step(mdb_walk_state_t *wsp)
{
	umem_cpu_t cpu;
	umem_cpu_walk_state_t *ucw = wsp->walk_data;

	uintptr_t caddr;

	if (ucw->ucw_current >= ucw->ucw_max)
		return (WALK_DONE);

	caddr = (uintptr_t)&(ucw->ucw_cpus[ucw->ucw_current]);

	if (mdb_vread(&cpu, sizeof (umem_cpu_t), caddr) == -1) {
		mdb_warn("failed to read cpu %d", ucw->ucw_current);
		return (WALK_ERR);
	}

	ucw->ucw_current++;

	return (wsp->walk_callback(caddr, &cpu, wsp->walk_cbdata));
}

void
umem_cpu_walk_fini(mdb_walk_state_t *wsp)
{
	umem_cpu_walk_state_t *ucw = wsp->walk_data;

	mdb_free(ucw, sizeof (*ucw));
}

int
umem_cpu_cache_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("umem_cpu_cache doesn't support global walks");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("umem_cpu", wsp) == -1) {
		mdb_warn("couldn't walk 'umem_cpu'");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;

	return (WALK_NEXT);
}

int
umem_cpu_cache_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = (uintptr_t)wsp->walk_data;
	const umem_cpu_t *cpu = wsp->walk_layer;
	umem_cpu_cache_t cc;

	caddr += cpu->cpu_cache_offset;

	if (mdb_vread(&cc, sizeof (umem_cpu_cache_t), caddr) == -1) {
		mdb_warn("couldn't read umem_cpu_cache at %p", caddr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(caddr, &cc, wsp->walk_cbdata));
}

int
umem_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;
	umem_cache_t c;

	if (caddr == NULL) {
		mdb_warn("umem_slab doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&c, sizeof (c), caddr) == -1) {
		mdb_warn("couldn't read umem_cache at %p", caddr);
		return (WALK_ERR);
	}

	wsp->walk_data =
	    (void *)(caddr + offsetof(umem_cache_t, cache_nullslab));
	wsp->walk_addr = (uintptr_t)c.cache_nullslab.slab_next;

	return (WALK_NEXT);
}

int
umem_slab_walk_partial_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;
	umem_cache_t c;

	if (caddr == NULL) {
		mdb_warn("umem_slab_partial doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&c, sizeof (c), caddr) == -1) {
		mdb_warn("couldn't read umem_cache at %p", caddr);
		return (WALK_ERR);
	}

	wsp->walk_data =
	    (void *)(caddr + offsetof(umem_cache_t, cache_nullslab));
	wsp->walk_addr = (uintptr_t)c.cache_freelist;

	/*
	 * Some consumers (umem_walk_step(), in particular) require at
	 * least one callback if there are any buffers in the cache.  So
	 * if there are *no* partial slabs, report the last full slab, if
	 * any.
	 *
	 * Yes, this is ugly, but it's cleaner than the other possibilities.
	 */
	if ((uintptr_t)wsp->walk_data == wsp->walk_addr)
		wsp->walk_addr = (uintptr_t)c.cache_nullslab.slab_prev;

	return (WALK_NEXT);
}

int
umem_slab_walk_step(mdb_walk_state_t *wsp)
{
	umem_slab_t s;
	uintptr_t addr = wsp->walk_addr;
	uintptr_t saddr = (uintptr_t)wsp->walk_data;
	uintptr_t caddr = saddr - offsetof(umem_cache_t, cache_nullslab);

	if (addr == saddr)
		return (WALK_DONE);

	if (mdb_vread(&s, sizeof (s), addr) == -1) {
		mdb_warn("failed to read slab at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if ((uintptr_t)s.slab_cache != caddr) {
		mdb_warn("slab %p isn't in cache %p (in cache %p)\n",
		    addr, caddr, s.slab_cache);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)s.slab_next;

	return (wsp->walk_callback(addr, &s, wsp->walk_cbdata));
}

int
umem_cache(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *argv)
{
	umem_cache_t c;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("umem_cache", "umem_cache", ac, argv) == -1) {
			mdb_warn("can't walk umem_cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-?s %-25s %4s %8s %8s %8s\n", "ADDR", "NAME",
		    "FLAG", "CFLAG", "BUFSIZE", "BUFTOTL");

	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read umem_cache at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %-25s %04x %08x %8ld %8lld\n", addr, c.cache_name,
	    c.cache_flags, c.cache_cflags, c.cache_bufsize, c.cache_buftotal);

	return (DCMD_OK);
}

static int
addrcmp(const void *lhs, const void *rhs)
{
	uintptr_t p1 = *((uintptr_t *)lhs);
	uintptr_t p2 = *((uintptr_t *)rhs);

	if (p1 < p2)
		return (-1);
	if (p1 > p2)
		return (1);
	return (0);
}

static int
bufctlcmp(const umem_bufctl_audit_t **lhs, const umem_bufctl_audit_t **rhs)
{
	const umem_bufctl_audit_t *bcp1 = *lhs;
	const umem_bufctl_audit_t *bcp2 = *rhs;

	if (bcp1->bc_timestamp > bcp2->bc_timestamp)
		return (-1);

	if (bcp1->bc_timestamp < bcp2->bc_timestamp)
		return (1);

	return (0);
}

typedef struct umem_hash_walk {
	uintptr_t *umhw_table;
	size_t umhw_nelems;
	size_t umhw_pos;
	umem_bufctl_t umhw_cur;
} umem_hash_walk_t;

int
umem_hash_walk_init(mdb_walk_state_t *wsp)
{
	umem_hash_walk_t *umhw;
	uintptr_t *hash;
	umem_cache_t c;
	uintptr_t haddr, addr = wsp->walk_addr;
	size_t nelems;
	size_t hsize;

	if (addr == NULL) {
		mdb_warn("umem_hash doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read cache at addr %p", addr);
		return (WALK_ERR);
	}

	if (!(c.cache_flags & UMF_HASH)) {
		mdb_warn("cache %p doesn't have a hash table\n", addr);
		return (WALK_DONE);		/* nothing to do */
	}

	umhw = mdb_zalloc(sizeof (umem_hash_walk_t), UM_SLEEP);
	umhw->umhw_cur.bc_next = NULL;
	umhw->umhw_pos = 0;

	umhw->umhw_nelems = nelems = c.cache_hash_mask + 1;
	hsize = nelems * sizeof (uintptr_t);
	haddr = (uintptr_t)c.cache_hash_table;

	umhw->umhw_table = hash = mdb_alloc(hsize, UM_SLEEP);
	if (mdb_vread(hash, hsize, haddr) == -1) {
		mdb_warn("failed to read hash table at %p", haddr);
		mdb_free(hash, hsize);
		mdb_free(umhw, sizeof (umem_hash_walk_t));
		return (WALK_ERR);
	}

	wsp->walk_data = umhw;

	return (WALK_NEXT);
}

int
umem_hash_walk_step(mdb_walk_state_t *wsp)
{
	umem_hash_walk_t *umhw = wsp->walk_data;
	uintptr_t addr = NULL;

	if ((addr = (uintptr_t)umhw->umhw_cur.bc_next) == NULL) {
		while (umhw->umhw_pos < umhw->umhw_nelems) {
			if ((addr = umhw->umhw_table[umhw->umhw_pos++]) != NULL)
				break;
		}
	}
	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&umhw->umhw_cur, sizeof (umem_bufctl_t), addr) == -1) {
		mdb_warn("couldn't read umem_bufctl_t at addr %p", addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(addr, &umhw->umhw_cur, wsp->walk_cbdata));
}

void
umem_hash_walk_fini(mdb_walk_state_t *wsp)
{
	umem_hash_walk_t *umhw = wsp->walk_data;

	if (umhw == NULL)
		return;

	mdb_free(umhw->umhw_table, umhw->umhw_nelems * sizeof (uintptr_t));
	mdb_free(umhw, sizeof (umem_hash_walk_t));
}

/*
 * Find the address of the bufctl structure for the address 'buf' in cache
 * 'cp', which is at address caddr, and place it in *out.
 */
static int
umem_hash_lookup(umem_cache_t *cp, uintptr_t caddr, void *buf, uintptr_t *out)
{
	uintptr_t bucket = (uintptr_t)UMEM_HASH(cp, buf);
	umem_bufctl_t *bcp;
	umem_bufctl_t bc;

	if (mdb_vread(&bcp, sizeof (umem_bufctl_t *), bucket) == -1) {
		mdb_warn("unable to read hash bucket for %p in cache %p",
		    buf, caddr);
		return (-1);
	}

	while (bcp != NULL) {
		if (mdb_vread(&bc, sizeof (umem_bufctl_t),
		    (uintptr_t)bcp) == -1) {
			mdb_warn("unable to read bufctl at %p", bcp);
			return (-1);
		}
		if (bc.bc_addr == buf) {
			*out = (uintptr_t)bcp;
			return (0);
		}
		bcp = bc.bc_next;
	}

	mdb_warn("unable to find bufctl for %p in cache %p\n", buf, caddr);
	return (-1);
}

int
umem_get_magsize(const umem_cache_t *cp)
{
	uintptr_t addr = (uintptr_t)cp->cache_magtype;
	GElf_Sym mt_sym;
	umem_magtype_t mt;
	int res;

	/*
	 * if cpu 0 has a non-zero magsize, it must be correct.  caches
	 * with UMF_NOMAGAZINE have disabled their magazine layers, so
	 * it is okay to return 0 for them.
	 */
	if ((res = cp->cache_cpu[0].cc_magsize) != 0 ||
	    (cp->cache_flags & UMF_NOMAGAZINE))
		return (res);

	if (umem_lookup_by_name("umem_magtype", &mt_sym) == -1) {
		mdb_warn("unable to read 'umem_magtype'");
	} else if (addr < mt_sym.st_value ||
	    addr + sizeof (mt) - 1 > mt_sym.st_value + mt_sym.st_size - 1 ||
	    ((addr - mt_sym.st_value) % sizeof (mt)) != 0) {
		mdb_warn("cache '%s' has invalid magtype pointer (%p)\n",
		    cp->cache_name, addr);
		return (0);
	}
	if (mdb_vread(&mt, sizeof (mt), addr) == -1) {
		mdb_warn("unable to read magtype at %a", addr);
		return (0);
	}
	return (mt.mt_magsize);
}

/*ARGSUSED*/
static int
umem_estimate_slab(uintptr_t addr, const umem_slab_t *sp, size_t *est)
{
	*est -= (sp->slab_chunks - sp->slab_refcnt);

	return (WALK_NEXT);
}

/*
 * Returns an upper bound on the number of allocated buffers in a given
 * cache.
 */
size_t
umem_estimate_allocated(uintptr_t addr, const umem_cache_t *cp)
{
	int magsize;
	size_t cache_est;

	cache_est = cp->cache_buftotal;

	(void) mdb_pwalk("umem_slab_partial",
	    (mdb_walk_cb_t)umem_estimate_slab, &cache_est, addr);

	if ((magsize = umem_get_magsize(cp)) != 0) {
		size_t mag_est = cp->cache_full.ml_total * magsize;

		if (cache_est >= mag_est) {
			cache_est -= mag_est;
		} else {
			mdb_warn("cache %p's magazine layer holds more buffers "
			    "than the slab layer.\n", addr);
		}
	}
	return (cache_est);
}

#define	READMAG_ROUNDS(rounds) { \
	if (mdb_vread(mp, magbsize, (uintptr_t)ump) == -1) { \
		mdb_warn("couldn't read magazine at %p", ump); \
		goto fail; \
	} \
	for (i = 0; i < rounds; i++) { \
		maglist[magcnt++] = mp->mag_round[i]; \
		if (magcnt == magmax) { \
			mdb_warn("%d magazines exceeds fudge factor\n", \
			    magcnt); \
			goto fail; \
		} \
	} \
}

static int
umem_read_magazines(umem_cache_t *cp, uintptr_t addr,
    void ***maglistp, size_t *magcntp, size_t *magmaxp)
{
	umem_magazine_t *ump, *mp;
	void **maglist = NULL;
	int i, cpu;
	size_t magsize, magmax, magbsize;
	size_t magcnt = 0;

	/*
	 * Read the magtype out of the cache, after verifying the pointer's
	 * correctness.
	 */
	magsize = umem_get_magsize(cp);
	if (magsize == 0) {
		*maglistp = NULL;
		*magcntp = 0;
		*magmaxp = 0;
		return (0);
	}

	/*
	 * There are several places where we need to go buffer hunting:
	 * the per-CPU loaded magazine, the per-CPU spare full magazine,
	 * and the full magazine list in the depot.
	 *
	 * For an upper bound on the number of buffers in the magazine
	 * layer, we have the number of magazines on the cache_full
	 * list plus at most two magazines per CPU (the loaded and the
	 * spare).  Toss in 100 magazines as a fudge factor in case this
	 * is live (the number "100" comes from the same fudge factor in
	 * crash(1M)).
	 */
	magmax = (cp->cache_full.ml_total + 2 * umem_max_ncpus + 100) * magsize;
	magbsize = offsetof(umem_magazine_t, mag_round[magsize]);

	if (magbsize >= PAGESIZE / 2) {
		mdb_warn("magazine size for cache %p unreasonable (%x)\n",
		    addr, magbsize);
		return (-1);
	}

	maglist = mdb_alloc(magmax * sizeof (void *), UM_SLEEP);
	mp = mdb_alloc(magbsize, UM_SLEEP);
	if (mp == NULL || maglist == NULL)
		goto fail;

	/*
	 * First up: the magazines in the depot (i.e. on the cache_full list).
	 */
	for (ump = cp->cache_full.ml_list; ump != NULL; ) {
		READMAG_ROUNDS(magsize);
		ump = mp->mag_next;

		if (ump == cp->cache_full.ml_list)
			break; /* cache_full list loop detected */
	}

	dprintf(("cache_full list done\n"));

	/*
	 * Now whip through the CPUs, snagging the loaded magazines
	 * and full spares.
	 */
	for (cpu = 0; cpu < umem_max_ncpus; cpu++) {
		umem_cpu_cache_t *ccp = &cp->cache_cpu[cpu];

		dprintf(("reading cpu cache %p\n",
		    (uintptr_t)ccp - (uintptr_t)cp + addr));

		if (ccp->cc_rounds > 0 &&
		    (ump = ccp->cc_loaded) != NULL) {
			dprintf(("reading %d loaded rounds\n", ccp->cc_rounds));
			READMAG_ROUNDS(ccp->cc_rounds);
		}

		if (ccp->cc_prounds > 0 &&
		    (ump = ccp->cc_ploaded) != NULL) {
			dprintf(("reading %d previously loaded rounds\n",
			    ccp->cc_prounds));
			READMAG_ROUNDS(ccp->cc_prounds);
		}
	}

	dprintf(("magazine layer: %d buffers\n", magcnt));

	mdb_free(mp, magbsize);

	*maglistp = maglist;
	*magcntp = magcnt;
	*magmaxp = magmax;

	return (0);

fail:
	if (mp)
		mdb_free(mp, magbsize);
	if (maglist)
		mdb_free(maglist, magmax * sizeof (void *));

	return (-1);
}

typedef struct umem_read_ptc_walk {
	void **urpw_buf;
	size_t urpw_cnt;
	size_t urpw_max;
} umem_read_ptc_walk_t;

/*ARGSUSED*/
static int
umem_read_ptc_walk_buf(uintptr_t addr,
    const void *ignored, umem_read_ptc_walk_t *urpw)
{
	if (urpw->urpw_cnt == urpw->urpw_max) {
		size_t nmax = urpw->urpw_max ? (urpw->urpw_max << 1) : 1;
		void **new = mdb_zalloc(nmax * sizeof (void *), UM_SLEEP);

		if (nmax > 1) {
			size_t osize = urpw->urpw_max * sizeof (void *);
			bcopy(urpw->urpw_buf, new, osize);
			mdb_free(urpw->urpw_buf, osize);
		}

		urpw->urpw_buf = new;
		urpw->urpw_max = nmax;
	}

	urpw->urpw_buf[urpw->urpw_cnt++] = (void *)addr;

	return (WALK_NEXT);
}

static int
umem_read_ptc(umem_cache_t *cp,
    void ***buflistp, size_t *bufcntp, size_t *bufmaxp)
{
	umem_read_ptc_walk_t urpw;
	char walk[60];
	int rval;

	if (!(cp->cache_flags & UMF_PTC))
		return (0);

	(void) mdb_snprintf(walk, sizeof (walk), "umem_ptc_%d",
	    cp->cache_bufsize);

	urpw.urpw_buf = *buflistp;
	urpw.urpw_cnt = *bufcntp;
	urpw.urpw_max = *bufmaxp;

	if ((rval = mdb_walk(walk,
	    (mdb_walk_cb_t)umem_read_ptc_walk_buf, &urpw)) == -1) {
		mdb_warn("couldn't walk %s", walk);
	}

	*buflistp = urpw.urpw_buf;
	*bufcntp = urpw.urpw_cnt;
	*bufmaxp = urpw.urpw_max;

	return (rval);
}

static int
umem_walk_callback(mdb_walk_state_t *wsp, uintptr_t buf)
{
	return (wsp->walk_callback(buf, NULL, wsp->walk_cbdata));
}

static int
bufctl_walk_callback(umem_cache_t *cp, mdb_walk_state_t *wsp, uintptr_t buf)
{
	umem_bufctl_audit_t *b;
	UMEM_LOCAL_BUFCTL_AUDIT(&b);

	/*
	 * if UMF_AUDIT is not set, we know that we're looking at a
	 * umem_bufctl_t.
	 */
	if (!(cp->cache_flags & UMF_AUDIT) ||
	    mdb_vread(b, UMEM_BUFCTL_AUDIT_SIZE, buf) == -1) {
		(void) memset(b, 0, UMEM_BUFCTL_AUDIT_SIZE);
		if (mdb_vread(b, sizeof (umem_bufctl_t), buf) == -1) {
			mdb_warn("unable to read bufctl at %p", buf);
			return (WALK_ERR);
		}
	}

	return (wsp->walk_callback(buf, b, wsp->walk_cbdata));
}

typedef struct umem_walk {
	int umw_type;

	uintptr_t umw_addr;		/* cache address */
	umem_cache_t *umw_cp;
	size_t umw_csize;

	/*
	 * magazine layer
	 */
	void **umw_maglist;
	size_t umw_max;
	size_t umw_count;
	size_t umw_pos;

	/*
	 * slab layer
	 */
	char *umw_valid;	/* to keep track of freed buffers */
	char *umw_ubase;	/* buffer for slab data */
} umem_walk_t;

static int
umem_walk_init_common(mdb_walk_state_t *wsp, int type)
{
	umem_walk_t *umw;
	int csize;
	umem_cache_t *cp;
	size_t vm_quantum;

	size_t magmax, magcnt;
	void **maglist = NULL;
	uint_t chunksize, slabsize;
	int status = WALK_ERR;
	uintptr_t addr = wsp->walk_addr;
	const char *layered;

	type &= ~UM_HASH;

	if (addr == NULL) {
		mdb_warn("umem walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	dprintf(("walking %p\n", addr));

	/*
	 * The number of "cpus" determines how large the cache is.
	 */
	csize = UMEM_CACHE_SIZE(umem_max_ncpus);
	cp = mdb_alloc(csize, UM_SLEEP);

	if (mdb_vread(cp, csize, addr) == -1) {
		mdb_warn("couldn't read cache at addr %p", addr);
		goto out2;
	}

	/*
	 * It's easy for someone to hand us an invalid cache address.
	 * Unfortunately, it is hard for this walker to survive an
	 * invalid cache cleanly.  So we make sure that:
	 *
	 *	1. the vmem arena for the cache is readable,
	 *	2. the vmem arena's quantum is a power of 2,
	 *	3. our slabsize is a multiple of the quantum, and
	 *	4. our chunksize is >0 and less than our slabsize.
	 */
	if (mdb_vread(&vm_quantum, sizeof (vm_quantum),
	    (uintptr_t)&cp->cache_arena->vm_quantum) == -1 ||
	    vm_quantum == 0 ||
	    (vm_quantum & (vm_quantum - 1)) != 0 ||
	    cp->cache_slabsize < vm_quantum ||
	    P2PHASE(cp->cache_slabsize, vm_quantum) != 0 ||
	    cp->cache_chunksize == 0 ||
	    cp->cache_chunksize > cp->cache_slabsize) {
		mdb_warn("%p is not a valid umem_cache_t\n", addr);
		goto out2;
	}

	dprintf(("buf total is %d\n", cp->cache_buftotal));

	if (cp->cache_buftotal == 0) {
		mdb_free(cp, csize);
		return (WALK_DONE);
	}

	/*
	 * If they ask for bufctls, but it's a small-slab cache,
	 * there is nothing to report.
	 */
	if ((type & UM_BUFCTL) && !(cp->cache_flags & UMF_HASH)) {
		dprintf(("bufctl requested, not UMF_HASH (flags: %p)\n",
		    cp->cache_flags));
		mdb_free(cp, csize);
		return (WALK_DONE);
	}

	/*
	 * Read in the contents of the magazine layer
	 */
	if (umem_read_magazines(cp, addr, &maglist, &magcnt, &magmax) != 0)
		goto out2;

	/*
	 * Read in the contents of the per-thread caches, if any
	 */
	if (umem_read_ptc(cp, &maglist, &magcnt, &magmax) != 0)
		goto out2;

	/*
	 * We have all of the buffers from the magazines and from the
	 * per-thread cache (if any);  if we are walking allocated buffers,
	 * sort them so we can bsearch them later.
	 */
	if (type & UM_ALLOCATED)
		qsort(maglist, magcnt, sizeof (void *), addrcmp);

	wsp->walk_data = umw = mdb_zalloc(sizeof (umem_walk_t), UM_SLEEP);

	umw->umw_type = type;
	umw->umw_addr = addr;
	umw->umw_cp = cp;
	umw->umw_csize = csize;
	umw->umw_maglist = maglist;
	umw->umw_max = magmax;
	umw->umw_count = magcnt;
	umw->umw_pos = 0;

	/*
	 * When walking allocated buffers in a UMF_HASH cache, we walk the
	 * hash table instead of the slab layer.
	 */
	if ((cp->cache_flags & UMF_HASH) && (type & UM_ALLOCATED)) {
		layered = "umem_hash";

		umw->umw_type |= UM_HASH;
	} else {
		/*
		 * If we are walking freed buffers, we only need the
		 * magazine layer plus the partially allocated slabs.
		 * To walk allocated buffers, we need all of the slabs.
		 */
		if (type & UM_ALLOCATED)
			layered = "umem_slab";
		else
			layered = "umem_slab_partial";

		/*
		 * for small-slab caches, we read in the entire slab.  For
		 * freed buffers, we can just walk the freelist.  For
		 * allocated buffers, we use a 'valid' array to track
		 * the freed buffers.
		 */
		if (!(cp->cache_flags & UMF_HASH)) {
			chunksize = cp->cache_chunksize;
			slabsize = cp->cache_slabsize;

			umw->umw_ubase = mdb_alloc(slabsize +
			    sizeof (umem_bufctl_t), UM_SLEEP);

			if (type & UM_ALLOCATED)
				umw->umw_valid =
				    mdb_alloc(slabsize / chunksize, UM_SLEEP);
		}
	}

	status = WALK_NEXT;

	if (mdb_layered_walk(layered, wsp) == -1) {
		mdb_warn("unable to start layered '%s' walk", layered);
		status = WALK_ERR;
	}

out1:
	if (status == WALK_ERR) {
		if (umw->umw_valid)
			mdb_free(umw->umw_valid, slabsize / chunksize);

		if (umw->umw_ubase)
			mdb_free(umw->umw_ubase, slabsize +
			    sizeof (umem_bufctl_t));

		if (umw->umw_maglist)
			mdb_free(umw->umw_maglist, umw->umw_max *
			    sizeof (uintptr_t));

		mdb_free(umw, sizeof (umem_walk_t));
		wsp->walk_data = NULL;
	}

out2:
	if (status == WALK_ERR)
		mdb_free(cp, csize);

	return (status);
}

int
umem_walk_step(mdb_walk_state_t *wsp)
{
	umem_walk_t *umw = wsp->walk_data;
	int type = umw->umw_type;
	umem_cache_t *cp = umw->umw_cp;

	void **maglist = umw->umw_maglist;
	int magcnt = umw->umw_count;

	uintptr_t chunksize, slabsize;
	uintptr_t addr;
	const umem_slab_t *sp;
	const umem_bufctl_t *bcp;
	umem_bufctl_t bc;

	int chunks;
	char *kbase;
	void *buf;
	int i, ret;

	char *valid, *ubase;

	/*
	 * first, handle the 'umem_hash' layered walk case
	 */
	if (type & UM_HASH) {
		/*
		 * We have a buffer which has been allocated out of the
		 * global layer. We need to make sure that it's not
		 * actually sitting in a magazine before we report it as
		 * an allocated buffer.
		 */
		buf = ((const umem_bufctl_t *)wsp->walk_layer)->bc_addr;

		if (magcnt > 0 &&
		    bsearch(&buf, maglist, magcnt, sizeof (void *),
		    addrcmp) != NULL)
			return (WALK_NEXT);

		if (type & UM_BUFCTL)
			return (bufctl_walk_callback(cp, wsp, wsp->walk_addr));

		return (umem_walk_callback(wsp, (uintptr_t)buf));
	}

	ret = WALK_NEXT;

	addr = umw->umw_addr;

	/*
	 * If we're walking freed buffers, report everything in the
	 * magazine layer before processing the first slab.
	 */
	if ((type & UM_FREE) && magcnt != 0) {
		umw->umw_count = 0;		/* only do this once */
		for (i = 0; i < magcnt; i++) {
			buf = maglist[i];

			if (type & UM_BUFCTL) {
				uintptr_t out;

				if (cp->cache_flags & UMF_BUFTAG) {
					umem_buftag_t *btp;
					umem_buftag_t tag;

					/* LINTED - alignment */
					btp = UMEM_BUFTAG(cp, buf);
					if (mdb_vread(&tag, sizeof (tag),
					    (uintptr_t)btp) == -1) {
						mdb_warn("reading buftag for "
						    "%p at %p", buf, btp);
						continue;
					}
					out = (uintptr_t)tag.bt_bufctl;
				} else {
					if (umem_hash_lookup(cp, addr, buf,
					    &out) == -1)
						continue;
				}
				ret = bufctl_walk_callback(cp, wsp, out);
			} else {
				ret = umem_walk_callback(wsp, (uintptr_t)buf);
			}

			if (ret != WALK_NEXT)
				return (ret);
		}
	}

	/*
	 * Handle the buffers in the current slab
	 */
	chunksize = cp->cache_chunksize;
	slabsize = cp->cache_slabsize;

	sp = wsp->walk_layer;
	chunks = sp->slab_chunks;
	kbase = sp->slab_base;

	dprintf(("kbase is %p\n", kbase));

	if (!(cp->cache_flags & UMF_HASH)) {
		valid = umw->umw_valid;
		ubase = umw->umw_ubase;

		if (mdb_vread(ubase, chunks * chunksize,
		    (uintptr_t)kbase) == -1) {
			mdb_warn("failed to read slab contents at %p", kbase);
			return (WALK_ERR);
		}

		/*
		 * Set up the valid map as fully allocated -- we'll punch
		 * out the freelist.
		 */
		if (type & UM_ALLOCATED)
			(void) memset(valid, 1, chunks);
	} else {
		valid = NULL;
		ubase = NULL;
	}

	/*
	 * walk the slab's freelist
	 */
	bcp = sp->slab_head;

	dprintf(("refcnt is %d; chunks is %d\n", sp->slab_refcnt, chunks));

	/*
	 * since we could be in the middle of allocating a buffer,
	 * our refcnt could be one higher than it aught.  So we
	 * check one further on the freelist than the count allows.
	 */
	for (i = sp->slab_refcnt; i <= chunks; i++) {
		uint_t ndx;

		dprintf(("bcp is %p\n", bcp));

		if (bcp == NULL) {
			if (i == chunks)
				break;
			mdb_warn(
			    "slab %p in cache %p freelist too short by %d\n",
			    sp, addr, chunks - i);
			break;
		}

		if (cp->cache_flags & UMF_HASH) {
			if (mdb_vread(&bc, sizeof (bc), (uintptr_t)bcp) == -1) {
				mdb_warn("failed to read bufctl ptr at %p",
				    bcp);
				break;
			}
			buf = bc.bc_addr;
		} else {
			/*
			 * Otherwise the buffer is (or should be) in the slab
			 * that we've read in; determine its offset in the
			 * slab, validate that it's not corrupt, and add to
			 * our base address to find the umem_bufctl_t.  (Note
			 * that we don't need to add the size of the bufctl
			 * to our offset calculation because of the slop that's
			 * allocated for the buffer at ubase.)
			 */
			uintptr_t offs = (uintptr_t)bcp - (uintptr_t)kbase;

			if (offs > chunks * chunksize) {
				mdb_warn("found corrupt bufctl ptr %p"
				    " in slab %p in cache %p\n", bcp,
				    wsp->walk_addr, addr);
				break;
			}

			bc = *((umem_bufctl_t *)((uintptr_t)ubase + offs));
			buf = UMEM_BUF(cp, bcp);
		}

		ndx = ((uintptr_t)buf - (uintptr_t)kbase) / chunksize;

		if (ndx > slabsize / cp->cache_bufsize) {
			/*
			 * This is very wrong; we have managed to find
			 * a buffer in the slab which shouldn't
			 * actually be here.  Emit a warning, and
			 * try to continue.
			 */
			mdb_warn("buf %p is out of range for "
			    "slab %p, cache %p\n", buf, sp, addr);
		} else if (type & UM_ALLOCATED) {
			/*
			 * we have found a buffer on the slab's freelist;
			 * clear its entry
			 */
			valid[ndx] = 0;
		} else {
			/*
			 * Report this freed buffer
			 */
			if (type & UM_BUFCTL) {
				ret = bufctl_walk_callback(cp, wsp,
				    (uintptr_t)bcp);
			} else {
				ret = umem_walk_callback(wsp, (uintptr_t)buf);
			}
			if (ret != WALK_NEXT)
				return (ret);
		}

		bcp = bc.bc_next;
	}

	if (bcp != NULL) {
		dprintf(("slab %p in cache %p freelist too long (%p)\n",
		    sp, addr, bcp));
	}

	/*
	 * If we are walking freed buffers, the loop above handled reporting
	 * them.
	 */
	if (type & UM_FREE)
		return (WALK_NEXT);

	if (type & UM_BUFCTL) {
		mdb_warn("impossible situation: small-slab UM_BUFCTL walk for "
		    "cache %p\n", addr);
		return (WALK_ERR);
	}

	/*
	 * Report allocated buffers, skipping buffers in the magazine layer.
	 * We only get this far for small-slab caches.
	 */
	for (i = 0; ret == WALK_NEXT && i < chunks; i++) {
		buf = (char *)kbase + i * chunksize;

		if (!valid[i])
			continue;		/* on slab freelist */

		if (magcnt > 0 &&
		    bsearch(&buf, maglist, magcnt, sizeof (void *),
		    addrcmp) != NULL)
			continue;		/* in magazine layer */

		ret = umem_walk_callback(wsp, (uintptr_t)buf);
	}
	return (ret);
}

void
umem_walk_fini(mdb_walk_state_t *wsp)
{
	umem_walk_t *umw = wsp->walk_data;
	uintptr_t chunksize;
	uintptr_t slabsize;

	if (umw == NULL)
		return;

	if (umw->umw_maglist != NULL)
		mdb_free(umw->umw_maglist, umw->umw_max * sizeof (void *));

	chunksize = umw->umw_cp->cache_chunksize;
	slabsize = umw->umw_cp->cache_slabsize;

	if (umw->umw_valid != NULL)
		mdb_free(umw->umw_valid, slabsize / chunksize);
	if (umw->umw_ubase != NULL)
		mdb_free(umw->umw_ubase, slabsize + sizeof (umem_bufctl_t));

	mdb_free(umw->umw_cp, umw->umw_csize);
	mdb_free(umw, sizeof (umem_walk_t));
}

/*ARGSUSED*/
static int
umem_walk_all(uintptr_t addr, const umem_cache_t *c, mdb_walk_state_t *wsp)
{
	/*
	 * Buffers allocated from NOTOUCH caches can also show up as freed
	 * memory in other caches.  This can be a little confusing, so we
	 * don't walk NOTOUCH caches when walking all caches (thereby assuring
	 * that "::walk umem" and "::walk freemem" yield disjoint output).
	 */
	if (c->cache_cflags & UMC_NOTOUCH)
		return (WALK_NEXT);

	if (mdb_pwalk(wsp->walk_data, wsp->walk_callback,
	    wsp->walk_cbdata, addr) == -1)
		return (WALK_DONE);

	return (WALK_NEXT);
}

#define	UMEM_WALK_ALL(name, wsp) { \
	wsp->walk_data = (name); \
	if (mdb_walk("umem_cache", (mdb_walk_cb_t)umem_walk_all, wsp) == -1) \
		return (WALK_ERR); \
	return (WALK_DONE); \
}

int
umem_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_arg != NULL)
		wsp->walk_addr = (uintptr_t)wsp->walk_arg;

	if (wsp->walk_addr == NULL)
		UMEM_WALK_ALL("umem", wsp);
	return (umem_walk_init_common(wsp, UM_ALLOCATED));
}

int
bufctl_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		UMEM_WALK_ALL("bufctl", wsp);
	return (umem_walk_init_common(wsp, UM_ALLOCATED | UM_BUFCTL));
}

int
freemem_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		UMEM_WALK_ALL("freemem", wsp);
	return (umem_walk_init_common(wsp, UM_FREE));
}

int
freectl_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		UMEM_WALK_ALL("freectl", wsp);
	return (umem_walk_init_common(wsp, UM_FREE | UM_BUFCTL));
}

typedef struct bufctl_history_walk {
	void		*bhw_next;
	umem_cache_t	*bhw_cache;
	umem_slab_t	*bhw_slab;
	hrtime_t	bhw_timestamp;
} bufctl_history_walk_t;

int
bufctl_history_walk_init(mdb_walk_state_t *wsp)
{
	bufctl_history_walk_t *bhw;
	umem_bufctl_audit_t bc;
	umem_bufctl_audit_t bcn;

	if (wsp->walk_addr == NULL) {
		mdb_warn("bufctl_history walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&bc, sizeof (bc), wsp->walk_addr) == -1) {
		mdb_warn("unable to read bufctl at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	bhw = mdb_zalloc(sizeof (*bhw), UM_SLEEP);
	bhw->bhw_timestamp = 0;
	bhw->bhw_cache = bc.bc_cache;
	bhw->bhw_slab = bc.bc_slab;

	/*
	 * sometimes the first log entry matches the base bufctl;  in that
	 * case, skip the base bufctl.
	 */
	if (bc.bc_lastlog != NULL &&
	    mdb_vread(&bcn, sizeof (bcn), (uintptr_t)bc.bc_lastlog) != -1 &&
	    bc.bc_addr == bcn.bc_addr &&
	    bc.bc_cache == bcn.bc_cache &&
	    bc.bc_slab == bcn.bc_slab &&
	    bc.bc_timestamp == bcn.bc_timestamp &&
	    bc.bc_thread == bcn.bc_thread)
		bhw->bhw_next = bc.bc_lastlog;
	else
		bhw->bhw_next = (void *)wsp->walk_addr;

	wsp->walk_addr = (uintptr_t)bc.bc_addr;
	wsp->walk_data = bhw;

	return (WALK_NEXT);
}

int
bufctl_history_walk_step(mdb_walk_state_t *wsp)
{
	bufctl_history_walk_t *bhw = wsp->walk_data;
	uintptr_t addr = (uintptr_t)bhw->bhw_next;
	uintptr_t baseaddr = wsp->walk_addr;
	umem_bufctl_audit_t *b;
	UMEM_LOCAL_BUFCTL_AUDIT(&b);

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(b, UMEM_BUFCTL_AUDIT_SIZE, addr) == -1) {
		mdb_warn("unable to read bufctl at %p", bhw->bhw_next);
		return (WALK_ERR);
	}

	/*
	 * The bufctl is only valid if the address, cache, and slab are
	 * correct.  We also check that the timestamp is decreasing, to
	 * prevent infinite loops.
	 */
	if ((uintptr_t)b->bc_addr != baseaddr ||
	    b->bc_cache != bhw->bhw_cache ||
	    b->bc_slab != bhw->bhw_slab ||
	    (bhw->bhw_timestamp != 0 && b->bc_timestamp >= bhw->bhw_timestamp))
		return (WALK_DONE);

	bhw->bhw_next = b->bc_lastlog;
	bhw->bhw_timestamp = b->bc_timestamp;

	return (wsp->walk_callback(addr, b, wsp->walk_cbdata));
}

void
bufctl_history_walk_fini(mdb_walk_state_t *wsp)
{
	bufctl_history_walk_t *bhw = wsp->walk_data;

	mdb_free(bhw, sizeof (*bhw));
}

typedef struct umem_log_walk {
	umem_bufctl_audit_t *ulw_base;
	umem_bufctl_audit_t **ulw_sorted;
	umem_log_header_t ulw_lh;
	size_t ulw_size;
	size_t ulw_maxndx;
	size_t ulw_ndx;
} umem_log_walk_t;

int
umem_log_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t lp = wsp->walk_addr;
	umem_log_walk_t *ulw;
	umem_log_header_t *lhp;
	int maxndx, i, j, k;

	/*
	 * By default (global walk), walk the umem_transaction_log.  Otherwise
	 * read the log whose umem_log_header_t is stored at walk_addr.
	 */
	if (lp == NULL && umem_readvar(&lp, "umem_transaction_log") == -1) {
		mdb_warn("failed to read 'umem_transaction_log'");
		return (WALK_ERR);
	}

	if (lp == NULL) {
		mdb_warn("log is disabled\n");
		return (WALK_ERR);
	}

	ulw = mdb_zalloc(sizeof (umem_log_walk_t), UM_SLEEP);
	lhp = &ulw->ulw_lh;

	if (mdb_vread(lhp, sizeof (umem_log_header_t), lp) == -1) {
		mdb_warn("failed to read log header at %p", lp);
		mdb_free(ulw, sizeof (umem_log_walk_t));
		return (WALK_ERR);
	}

	ulw->ulw_size = lhp->lh_chunksize * lhp->lh_nchunks;
	ulw->ulw_base = mdb_alloc(ulw->ulw_size, UM_SLEEP);
	maxndx = lhp->lh_chunksize / UMEM_BUFCTL_AUDIT_SIZE - 1;

	if (mdb_vread(ulw->ulw_base, ulw->ulw_size,
	    (uintptr_t)lhp->lh_base) == -1) {
		mdb_warn("failed to read log at base %p", lhp->lh_base);
		mdb_free(ulw->ulw_base, ulw->ulw_size);
		mdb_free(ulw, sizeof (umem_log_walk_t));
		return (WALK_ERR);
	}

	ulw->ulw_sorted = mdb_alloc(maxndx * lhp->lh_nchunks *
	    sizeof (umem_bufctl_audit_t *), UM_SLEEP);

	for (i = 0, k = 0; i < lhp->lh_nchunks; i++) {
		caddr_t chunk = (caddr_t)
		    ((uintptr_t)ulw->ulw_base + i * lhp->lh_chunksize);

		for (j = 0; j < maxndx; j++) {
			/* LINTED align */
			ulw->ulw_sorted[k++] = (umem_bufctl_audit_t *)chunk;
			chunk += UMEM_BUFCTL_AUDIT_SIZE;
		}
	}

	qsort(ulw->ulw_sorted, k, sizeof (umem_bufctl_audit_t *),
	    (int(*)(const void *, const void *))bufctlcmp);

	ulw->ulw_maxndx = k;
	wsp->walk_data = ulw;

	return (WALK_NEXT);
}

int
umem_log_walk_step(mdb_walk_state_t *wsp)
{
	umem_log_walk_t *ulw = wsp->walk_data;
	umem_bufctl_audit_t *bcp;

	if (ulw->ulw_ndx == ulw->ulw_maxndx)
		return (WALK_DONE);

	bcp = ulw->ulw_sorted[ulw->ulw_ndx++];

	return (wsp->walk_callback((uintptr_t)bcp - (uintptr_t)ulw->ulw_base +
	    (uintptr_t)ulw->ulw_lh.lh_base, bcp, wsp->walk_cbdata));
}

void
umem_log_walk_fini(mdb_walk_state_t *wsp)
{
	umem_log_walk_t *ulw = wsp->walk_data;

	mdb_free(ulw->ulw_base, ulw->ulw_size);
	mdb_free(ulw->ulw_sorted, ulw->ulw_maxndx *
	    sizeof (umem_bufctl_audit_t *));
	mdb_free(ulw, sizeof (umem_log_walk_t));
}

typedef struct allocdby_bufctl {
	uintptr_t abb_addr;
	hrtime_t abb_ts;
} allocdby_bufctl_t;

typedef struct allocdby_walk {
	const char *abw_walk;
	uintptr_t abw_thread;
	size_t abw_nbufs;
	size_t abw_size;
	allocdby_bufctl_t *abw_buf;
	size_t abw_ndx;
} allocdby_walk_t;

int
allocdby_walk_bufctl(uintptr_t addr, const umem_bufctl_audit_t *bcp,
    allocdby_walk_t *abw)
{
	if ((uintptr_t)bcp->bc_thread != abw->abw_thread)
		return (WALK_NEXT);

	if (abw->abw_nbufs == abw->abw_size) {
		allocdby_bufctl_t *buf;
		size_t oldsize = sizeof (allocdby_bufctl_t) * abw->abw_size;

		buf = mdb_zalloc(oldsize << 1, UM_SLEEP);

		bcopy(abw->abw_buf, buf, oldsize);
		mdb_free(abw->abw_buf, oldsize);

		abw->abw_size <<= 1;
		abw->abw_buf = buf;
	}

	abw->abw_buf[abw->abw_nbufs].abb_addr = addr;
	abw->abw_buf[abw->abw_nbufs].abb_ts = bcp->bc_timestamp;
	abw->abw_nbufs++;

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
allocdby_walk_cache(uintptr_t addr, const umem_cache_t *c, allocdby_walk_t *abw)
{
	if (mdb_pwalk(abw->abw_walk, (mdb_walk_cb_t)allocdby_walk_bufctl,
	    abw, addr) == -1) {
		mdb_warn("couldn't walk bufctl for cache %p", addr);
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

static int
allocdby_cmp(const allocdby_bufctl_t *lhs, const allocdby_bufctl_t *rhs)
{
	if (lhs->abb_ts < rhs->abb_ts)
		return (1);
	if (lhs->abb_ts > rhs->abb_ts)
		return (-1);
	return (0);
}

static int
allocdby_walk_init_common(mdb_walk_state_t *wsp, const char *walk)
{
	allocdby_walk_t *abw;

	if (wsp->walk_addr == NULL) {
		mdb_warn("allocdby walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	abw = mdb_zalloc(sizeof (allocdby_walk_t), UM_SLEEP);

	abw->abw_thread = wsp->walk_addr;
	abw->abw_walk = walk;
	abw->abw_size = 128;	/* something reasonable */
	abw->abw_buf =
	    mdb_zalloc(abw->abw_size * sizeof (allocdby_bufctl_t), UM_SLEEP);

	wsp->walk_data = abw;

	if (mdb_walk("umem_cache",
	    (mdb_walk_cb_t)allocdby_walk_cache, abw) == -1) {
		mdb_warn("couldn't walk umem_cache");
		allocdby_walk_fini(wsp);
		return (WALK_ERR);
	}

	qsort(abw->abw_buf, abw->abw_nbufs, sizeof (allocdby_bufctl_t),
	    (int(*)(const void *, const void *))allocdby_cmp);

	return (WALK_NEXT);
}

int
allocdby_walk_init(mdb_walk_state_t *wsp)
{
	return (allocdby_walk_init_common(wsp, "bufctl"));
}

int
freedby_walk_init(mdb_walk_state_t *wsp)
{
	return (allocdby_walk_init_common(wsp, "freectl"));
}

int
allocdby_walk_step(mdb_walk_state_t *wsp)
{
	allocdby_walk_t *abw = wsp->walk_data;
	uintptr_t addr;
	umem_bufctl_audit_t *bcp;
	UMEM_LOCAL_BUFCTL_AUDIT(&bcp);

	if (abw->abw_ndx == abw->abw_nbufs)
		return (WALK_DONE);

	addr = abw->abw_buf[abw->abw_ndx++].abb_addr;

	if (mdb_vread(bcp, UMEM_BUFCTL_AUDIT_SIZE, addr) == -1) {
		mdb_warn("couldn't read bufctl at %p", addr);
		return (WALK_DONE);
	}

	return (wsp->walk_callback(addr, bcp, wsp->walk_cbdata));
}

void
allocdby_walk_fini(mdb_walk_state_t *wsp)
{
	allocdby_walk_t *abw = wsp->walk_data;

	mdb_free(abw->abw_buf, sizeof (allocdby_bufctl_t) * abw->abw_size);
	mdb_free(abw, sizeof (allocdby_walk_t));
}

/*ARGSUSED*/
int
allocdby_walk(uintptr_t addr, const umem_bufctl_audit_t *bcp, void *ignored)
{
	char c[MDB_SYM_NAMLEN];
	GElf_Sym sym;
	int i;

	mdb_printf("%0?p %12llx ", addr, bcp->bc_timestamp);
	for (i = 0; i < bcp->bc_depth; i++) {
		if (mdb_lookup_by_addr(bcp->bc_stack[i],
		    MDB_SYM_FUZZY, c, sizeof (c), &sym) == -1)
			continue;
		if (is_umem_sym(c, "umem_"))
			continue;
		mdb_printf("%s+0x%lx",
		    c, bcp->bc_stack[i] - (uintptr_t)sym.st_value);
		break;
	}
	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
allocdby_common(uintptr_t addr, uint_t flags, const char *w)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	mdb_printf("%-?s %12s %s\n", "BUFCTL", "TIMESTAMP", "CALLER");

	if (mdb_pwalk(w, (mdb_walk_cb_t)allocdby_walk, NULL, addr) == -1) {
		mdb_warn("can't walk '%s' for %p", w, addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
allocdby(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (allocdby_common(addr, flags, "allocdby"));
}

/*ARGSUSED*/
int
freedby(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (allocdby_common(addr, flags, "freedby"));
}

typedef struct whatis_info {
	mdb_whatis_t *wi_w;
	const umem_cache_t *wi_cache;
	const vmem_t *wi_vmem;
	vmem_t *wi_msb_arena;
	size_t wi_slab_size;
	int wi_slab_found;
	uint_t wi_freemem;
} whatis_info_t;

/* call one of our dcmd functions with "-v" and the provided address */
static void
whatis_call_printer(mdb_dcmd_f *dcmd, uintptr_t addr)
{
	mdb_arg_t a;
	a.a_type = MDB_TYPE_STRING;
	a.a_un.a_str = "-v";

	mdb_printf(":\n");
	(void) (*dcmd)(addr, DCMD_ADDRSPEC, 1, &a);
}

static void
whatis_print_umem(whatis_info_t *wi, uintptr_t maddr, uintptr_t addr,
    uintptr_t baddr)
{
	mdb_whatis_t *w = wi->wi_w;
	const umem_cache_t *cp = wi->wi_cache;
	int quiet = (mdb_whatis_flags(w) & WHATIS_QUIET);

	int call_printer = (!quiet && (cp->cache_flags & UMF_AUDIT));

	mdb_whatis_report_object(w, maddr, addr, "");

	if (baddr != 0 && !call_printer)
		mdb_printf("bufctl %p ", baddr);

	mdb_printf("%s from %s",
	    (wi->wi_freemem == FALSE) ? "allocated" : "freed", cp->cache_name);

	if (call_printer && baddr != 0) {
		whatis_call_printer(bufctl, baddr);
		return;
	}
	mdb_printf("\n");
}

/*ARGSUSED*/
static int
whatis_walk_umem(uintptr_t addr, void *ignored, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	uintptr_t cur;
	size_t size = wi->wi_cache->cache_bufsize;

	while (mdb_whatis_match(w, addr, size, &cur))
		whatis_print_umem(wi, cur, addr, NULL);

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_walk_bufctl(uintptr_t baddr, const umem_bufctl_t *bcp, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	uintptr_t cur;
	uintptr_t addr = (uintptr_t)bcp->bc_addr;
	size_t size = wi->wi_cache->cache_bufsize;

	while (mdb_whatis_match(w, addr, size, &cur))
		whatis_print_umem(wi, cur, addr, baddr);

	return (WHATIS_WALKRET(w));
}


static int
whatis_walk_seg(uintptr_t addr, const vmem_seg_t *vs, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	size_t size = vs->vs_end - vs->vs_start;
	uintptr_t cur;

	/* We're not interested in anything but alloc and free segments */
	if (vs->vs_type != VMEM_ALLOC && vs->vs_type != VMEM_FREE)
		return (WALK_NEXT);

	while (mdb_whatis_match(w, vs->vs_start, size, &cur)) {
		mdb_whatis_report_object(w, cur, vs->vs_start, "");

		/*
		 * If we're not printing it seperately, provide the vmem_seg
		 * pointer if it has a stack trace.
		 */
		if ((mdb_whatis_flags(w) & WHATIS_QUIET) &&
		    ((mdb_whatis_flags(w) & WHATIS_BUFCTL) != 0 ||
		    (vs->vs_type == VMEM_ALLOC && vs->vs_depth != 0))) {
			mdb_printf("vmem_seg %p ", addr);
		}

		mdb_printf("%s from %s vmem arena",
		    (vs->vs_type == VMEM_ALLOC) ? "allocated" : "freed",
		    wi->wi_vmem->vm_name);

		if (!mdb_whatis_flags(w) & WHATIS_QUIET)
			whatis_call_printer(vmem_seg, addr);
		else
			mdb_printf("\n");
	}

	return (WHATIS_WALKRET(w));
}

static int
whatis_walk_vmem(uintptr_t addr, const vmem_t *vmem, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;
	const char *nm = vmem->vm_name;
	wi->wi_vmem = vmem;

	if (mdb_whatis_flags(w) & WHATIS_VERBOSE)
		mdb_printf("Searching vmem arena %s...\n", nm);

	if (mdb_pwalk("vmem_seg",
	    (mdb_walk_cb_t)whatis_walk_seg, wi, addr) == -1) {
		mdb_warn("can't walk vmem seg for %p", addr);
		return (WALK_NEXT);
	}

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_walk_slab(uintptr_t saddr, const umem_slab_t *sp, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	/* It must overlap with the slab data, or it's not interesting */
	if (mdb_whatis_overlaps(w,
	    (uintptr_t)sp->slab_base, wi->wi_slab_size)) {
		wi->wi_slab_found++;
		return (WALK_DONE);
	}
	return (WALK_NEXT);
}

static int
whatis_walk_cache(uintptr_t addr, const umem_cache_t *c, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;
	char *walk, *freewalk;
	mdb_walk_cb_t func;
	int do_bufctl;

	/* Override the '-b' flag as necessary */
	if (!(c->cache_flags & UMF_HASH))
		do_bufctl = FALSE;	/* no bufctls to walk */
	else if (c->cache_flags & UMF_AUDIT)
		do_bufctl = TRUE;	/* we always want debugging info */
	else
		do_bufctl = ((mdb_whatis_flags(w) & WHATIS_BUFCTL) != 0);

	if (do_bufctl) {
		walk = "bufctl";
		freewalk = "freectl";
		func = (mdb_walk_cb_t)whatis_walk_bufctl;
	} else {
		walk = "umem";
		freewalk = "freemem";
		func = (mdb_walk_cb_t)whatis_walk_umem;
	}

	wi->wi_cache = c;

	if (mdb_whatis_flags(w) & WHATIS_VERBOSE)
		mdb_printf("Searching %s...\n", c->cache_name);

	/*
	 * If more then two buffers live on each slab, figure out if we're
	 * interested in anything in any slab before doing the more expensive
	 * umem/freemem (bufctl/freectl) walkers.
	 */
	wi->wi_slab_size = c->cache_slabsize - c->cache_maxcolor;
	if (!(c->cache_flags & UMF_HASH))
		wi->wi_slab_size -= sizeof (umem_slab_t);

	if ((wi->wi_slab_size / c->cache_chunksize) > 2) {
		wi->wi_slab_found = 0;
		if (mdb_pwalk("umem_slab", (mdb_walk_cb_t)whatis_walk_slab, wi,
		    addr) == -1) {
			mdb_warn("can't find umem_slab walker");
			return (WALK_DONE);
		}
		if (wi->wi_slab_found == 0)
			return (WALK_NEXT);
	}

	wi->wi_freemem = FALSE;
	if (mdb_pwalk(walk, func, wi, addr) == -1) {
		mdb_warn("can't find %s walker", walk);
		return (WALK_DONE);
	}

	if (mdb_whatis_done(w))
		return (WALK_DONE);

	/*
	 * We have searched for allocated memory; now search for freed memory.
	 */
	if (mdb_whatis_flags(w) & WHATIS_VERBOSE)
		mdb_printf("Searching %s for free memory...\n", c->cache_name);

	wi->wi_freemem = TRUE;

	if (mdb_pwalk(freewalk, func, wi, addr) == -1) {
		mdb_warn("can't find %s walker", freewalk);
		return (WALK_DONE);
	}

	return (WHATIS_WALKRET(w));
}

static int
whatis_walk_touch(uintptr_t addr, const umem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena == wi->wi_msb_arena ||
	    (c->cache_cflags & UMC_NOTOUCH))
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

static int
whatis_walk_metadata(uintptr_t addr, const umem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena != wi->wi_msb_arena)
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

static int
whatis_walk_notouch(uintptr_t addr, const umem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena == wi->wi_msb_arena ||
	    !(c->cache_cflags & UMC_NOTOUCH))
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

/*ARGSUSED*/
static int
whatis_run_umem(mdb_whatis_t *w, void *ignored)
{
	whatis_info_t wi;

	bzero(&wi, sizeof (wi));
	wi.wi_w = w;

	/* umem's metadata is allocated from the umem_internal_arena */
	if (umem_readvar(&wi.wi_msb_arena, "umem_internal_arena") == -1)
		mdb_warn("unable to readvar \"umem_internal_arena\"");

	/*
	 * We process umem caches in the following order:
	 *
	 *	non-UMC_NOTOUCH, non-metadata	(typically the most interesting)
	 *	metadata			(can be huge with UMF_AUDIT)
	 *	UMC_NOTOUCH, non-metadata	(see umem_walk_all())
	 */
	if (mdb_walk("umem_cache", (mdb_walk_cb_t)whatis_walk_touch,
	    &wi) == -1 ||
	    mdb_walk("umem_cache", (mdb_walk_cb_t)whatis_walk_metadata,
	    &wi) == -1 ||
	    mdb_walk("umem_cache", (mdb_walk_cb_t)whatis_walk_notouch,
	    &wi) == -1) {
		mdb_warn("couldn't find umem_cache walker");
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
whatis_run_vmem(mdb_whatis_t *w, void *ignored)
{
	whatis_info_t wi;

	bzero(&wi, sizeof (wi));
	wi.wi_w = w;

	if (mdb_walk("vmem_postfix",
	    (mdb_walk_cb_t)whatis_walk_vmem, &wi) == -1) {
		mdb_warn("couldn't find vmem_postfix walker");
		return (1);
	}
	return (0);
}

int
umem_init(void)
{
	mdb_walker_t w = {
		"umem_cache", "walk list of umem caches", umem_cache_walk_init,
		umem_cache_walk_step, umem_cache_walk_fini
	};

	if (mdb_add_walker(&w) == -1) {
		mdb_warn("failed to add umem_cache walker");
		return (-1);
	}

	if (umem_update_variables() == -1)
		return (-1);

	/* install a callback so that our variables are always up-to-date */
	(void) mdb_callback_add(MDB_CALLBACK_STCHG, umem_statechange_cb, NULL);
	umem_statechange_cb(NULL);

	/*
	 * Register our ::whatis callbacks.
	 */
	mdb_whatis_register("umem", whatis_run_umem, NULL,
	    WHATIS_PRIO_ALLOCATOR, WHATIS_REG_NO_ID);
	mdb_whatis_register("vmem", whatis_run_vmem, NULL,
	    WHATIS_PRIO_ALLOCATOR, WHATIS_REG_NO_ID);

	return (0);
}

typedef struct umem_log_cpu {
	uintptr_t umc_low;
	uintptr_t umc_high;
} umem_log_cpu_t;

int
umem_log_walk(uintptr_t addr, const umem_bufctl_audit_t *b, umem_log_cpu_t *umc)
{
	int i;

	for (i = 0; i < umem_max_ncpus; i++) {
		if (addr >= umc[i].umc_low && addr < umc[i].umc_high)
			break;
	}

	if (i == umem_max_ncpus)
		mdb_printf("   ");
	else
		mdb_printf("%3d", i);

	mdb_printf(" %0?p %0?p %16llx %0?p\n", addr, b->bc_addr,
	    b->bc_timestamp, b->bc_thread);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
umem_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	umem_log_header_t lh;
	umem_cpu_log_header_t clh;
	uintptr_t lhp, clhp;
	umem_log_cpu_t *umc;
	int i;

	if (umem_readvar(&lhp, "umem_transaction_log") == -1) {
		mdb_warn("failed to read 'umem_transaction_log'");
		return (DCMD_ERR);
	}

	if (lhp == NULL) {
		mdb_warn("no umem transaction log\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&lh, sizeof (umem_log_header_t), lhp) == -1) {
		mdb_warn("failed to read log header at %p", lhp);
		return (DCMD_ERR);
	}

	clhp = lhp + ((uintptr_t)&lh.lh_cpu[0] - (uintptr_t)&lh);

	umc = mdb_zalloc(sizeof (umem_log_cpu_t) * umem_max_ncpus,
	    UM_SLEEP | UM_GC);

	for (i = 0; i < umem_max_ncpus; i++) {
		if (mdb_vread(&clh, sizeof (clh), clhp) == -1) {
			mdb_warn("cannot read cpu %d's log header at %p",
			    i, clhp);
			return (DCMD_ERR);
		}

		umc[i].umc_low = clh.clh_chunk * lh.lh_chunksize +
		    (uintptr_t)lh.lh_base;
		umc[i].umc_high = (uintptr_t)clh.clh_current;

		clhp += sizeof (umem_cpu_log_header_t);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%3s %-?s %-?s %16s %-?s\n", "CPU", "ADDR",
		    "BUFADDR", "TIMESTAMP", "THREAD");
	}

	/*
	 * If we have been passed an address, we'll just print out that
	 * log entry.
	 */
	if (flags & DCMD_ADDRSPEC) {
		umem_bufctl_audit_t *bp;
		UMEM_LOCAL_BUFCTL_AUDIT(&bp);

		if (mdb_vread(bp, UMEM_BUFCTL_AUDIT_SIZE, addr) == -1) {
			mdb_warn("failed to read bufctl at %p", addr);
			return (DCMD_ERR);
		}

		(void) umem_log_walk(addr, bp, umc);

		return (DCMD_OK);
	}

	if (mdb_walk("umem_log", (mdb_walk_cb_t)umem_log_walk, umc) == -1) {
		mdb_warn("can't find umem log walker");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

typedef struct bufctl_history_cb {
	int		bhc_flags;
	int		bhc_argc;
	const mdb_arg_t	*bhc_argv;
	int		bhc_ret;
} bufctl_history_cb_t;

/*ARGSUSED*/
static int
bufctl_history_callback(uintptr_t addr, const void *ign, void *arg)
{
	bufctl_history_cb_t *bhc = arg;

	bhc->bhc_ret =
	    bufctl(addr, bhc->bhc_flags, bhc->bhc_argc, bhc->bhc_argv);

	bhc->bhc_flags &= ~DCMD_LOOPFIRST;

	return ((bhc->bhc_ret == DCMD_OK)? WALK_NEXT : WALK_DONE);
}

void
bufctl_help(void)
{
	mdb_printf("%s\n",
"Display the contents of umem_bufctl_audit_ts, with optional filtering.\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -v    Display the full content of the bufctl, including its stack trace\n"
"  -h    retrieve the bufctl's transaction history, if available\n"
"  -a addr\n"
"        filter out bufctls not involving the buffer at addr\n"
"  -c caller\n"
"        filter out bufctls without the function/PC in their stack trace\n"
"  -e earliest\n"
"        filter out bufctls timestamped before earliest\n"
"  -l latest\n"
"        filter out bufctls timestamped after latest\n"
"  -t thread\n"
"        filter out bufctls not involving thread\n");
}

int
bufctl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	uint_t history = FALSE;
	uint_t in_history = FALSE;
	uintptr_t caller = NULL, thread = NULL;
	uintptr_t laddr, haddr, baddr = NULL;
	hrtime_t earliest = 0, latest = 0;
	int i, depth;
	char c[MDB_SYM_NAMLEN];
	GElf_Sym sym;
	umem_bufctl_audit_t *bcp;
	UMEM_LOCAL_BUFCTL_AUDIT(&bcp);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'h', MDB_OPT_SETBITS, TRUE, &history,
	    'H', MDB_OPT_SETBITS, TRUE, &in_history,		/* internal */
	    'c', MDB_OPT_UINTPTR, &caller,
	    't', MDB_OPT_UINTPTR, &thread,
	    'e', MDB_OPT_UINT64, &earliest,
	    'l', MDB_OPT_UINT64, &latest,
	    'a', MDB_OPT_UINTPTR, &baddr, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (in_history && !history)
		return (DCMD_USAGE);

	if (history && !in_history) {
		mdb_arg_t *nargv = mdb_zalloc(sizeof (*nargv) * (argc + 1),
		    UM_SLEEP | UM_GC);
		bufctl_history_cb_t bhc;

		nargv[0].a_type = MDB_TYPE_STRING;
		nargv[0].a_un.a_str = "-H";		/* prevent recursion */

		for (i = 0; i < argc; i++)
			nargv[i + 1] = argv[i];

		/*
		 * When in history mode, we treat each element as if it
		 * were in a seperate loop, so that the headers group
		 * bufctls with similar histories.
		 */
		bhc.bhc_flags = flags | DCMD_LOOP | DCMD_LOOPFIRST;
		bhc.bhc_argc = argc + 1;
		bhc.bhc_argv = nargv;
		bhc.bhc_ret = DCMD_OK;

		if (mdb_pwalk("bufctl_history", bufctl_history_callback, &bhc,
		    addr) == -1) {
			mdb_warn("unable to walk bufctl_history");
			return (DCMD_ERR);
		}

		if (bhc.bhc_ret == DCMD_OK && !(flags & DCMD_PIPE_OUT))
			mdb_printf("\n");

		return (bhc.bhc_ret);
	}

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		if (verbose) {
			mdb_printf("%16s %16s %16s %16s\n"
			    "%<u>%16s %16s %16s %16s%</u>\n",
			    "ADDR", "BUFADDR", "TIMESTAMP", "THREAD",
			    "", "CACHE", "LASTLOG", "CONTENTS");
		} else {
			mdb_printf("%<u>%-?s %-?s %-12s %5s %s%</u>\n",
			    "ADDR", "BUFADDR", "TIMESTAMP", "THRD", "CALLER");
		}
	}

	if (mdb_vread(bcp, UMEM_BUFCTL_AUDIT_SIZE, addr) == -1) {
		mdb_warn("couldn't read bufctl at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * Guard against bogus bc_depth in case the bufctl is corrupt or
	 * the address does not really refer to a bufctl.
	 */
	depth = MIN(bcp->bc_depth, umem_stack_depth);

	if (caller != NULL) {
		laddr = caller;
		haddr = caller + sizeof (caller);

		if (mdb_lookup_by_addr(caller, MDB_SYM_FUZZY, c, sizeof (c),
		    &sym) != -1 && caller == (uintptr_t)sym.st_value) {
			/*
			 * We were provided an exact symbol value; any
			 * address in the function is valid.
			 */
			laddr = (uintptr_t)sym.st_value;
			haddr = (uintptr_t)sym.st_value + sym.st_size;
		}

		for (i = 0; i < depth; i++)
			if (bcp->bc_stack[i] >= laddr &&
			    bcp->bc_stack[i] < haddr)
				break;

		if (i == depth)
			return (DCMD_OK);
	}

	if (thread != NULL && (uintptr_t)bcp->bc_thread != thread)
		return (DCMD_OK);

	if (earliest != 0 && bcp->bc_timestamp < earliest)
		return (DCMD_OK);

	if (latest != 0 && bcp->bc_timestamp > latest)
		return (DCMD_OK);

	if (baddr != 0 && (uintptr_t)bcp->bc_addr != baddr)
		return (DCMD_OK);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#r\n", addr);
		return (DCMD_OK);
	}

	if (verbose) {
		mdb_printf(
		    "%<b>%16p%</b> %16p %16llx %16d\n"
		    "%16s %16p %16p %16p\n",
		    addr, bcp->bc_addr, bcp->bc_timestamp, bcp->bc_thread,
		    "", bcp->bc_cache, bcp->bc_lastlog, bcp->bc_contents);

		mdb_inc_indent(17);
		for (i = 0; i < depth; i++)
			mdb_printf("%a\n", bcp->bc_stack[i]);
		mdb_dec_indent(17);
		mdb_printf("\n");
	} else {
		mdb_printf("%0?p %0?p %12llx %5d", addr, bcp->bc_addr,
		    bcp->bc_timestamp, bcp->bc_thread);

		for (i = 0; i < depth; i++) {
			if (mdb_lookup_by_addr(bcp->bc_stack[i],
			    MDB_SYM_FUZZY, c, sizeof (c), &sym) == -1)
				continue;
			if (is_umem_sym(c, "umem_"))
				continue;
			mdb_printf(" %a\n", bcp->bc_stack[i]);
			break;
		}

		if (i >= depth)
			mdb_printf("\n");
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
bufctl_audit(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_arg_t a;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc != 0)
		return (DCMD_USAGE);

	a.a_type = MDB_TYPE_STRING;
	a.a_un.a_str = "-v";

	return (bufctl(addr, flags, 1, &a));
}

typedef struct umem_verify {
	uint64_t *umv_buf;		/* buffer to read cache contents into */
	size_t umv_size;		/* number of bytes in umv_buf */
	int umv_corruption;		/* > 0 if corruption found. */
	int umv_besilent;		/* report actual corruption sites */
	struct umem_cache umv_cache;	/* the cache we're operating on */
} umem_verify_t;

/*
 * verify_pattern()
 *	verify that buf is filled with the pattern pat.
 */
static int64_t
verify_pattern(uint64_t *buf_arg, size_t size, uint64_t pat)
{
	/*LINTED*/
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf;

	for (buf = buf_arg; buf < bufend; buf++)
		if (*buf != pat)
			return ((uintptr_t)buf - (uintptr_t)buf_arg);
	return (-1);
}

/*
 * verify_buftag()
 *	verify that btp->bt_bxstat == (bcp ^ pat)
 */
static int
verify_buftag(umem_buftag_t *btp, uintptr_t pat)
{
	return (btp->bt_bxstat == ((intptr_t)btp->bt_bufctl ^ pat) ? 0 : -1);
}

/*
 * verify_free()
 *	verify the integrity of a free block of memory by checking
 *	that it is filled with 0xdeadbeef and that its buftag is sane.
 */
/*ARGSUSED1*/
static int
verify_free(uintptr_t addr, const void *data, void *private)
{
	umem_verify_t *umv = (umem_verify_t *)private;
	uint64_t *buf = umv->umv_buf;	/* buf to validate */
	int64_t corrupt;		/* corruption offset */
	umem_buftag_t *buftagp;		/* ptr to buftag */
	umem_cache_t *cp = &umv->umv_cache;
	int besilent = umv->umv_besilent;

	/*LINTED*/
	buftagp = UMEM_BUFTAG(cp, buf);

	/*
	 * Read the buffer to check.
	 */
	if (mdb_vread(buf, umv->umv_size, addr) == -1) {
		if (!besilent)
			mdb_warn("couldn't read %p", addr);
		return (WALK_NEXT);
	}

	if ((corrupt = verify_pattern(buf, cp->cache_verify,
	    UMEM_FREE_PATTERN)) >= 0) {
		if (!besilent)
			mdb_printf("buffer %p (free) seems corrupted, at %p\n",
			    addr, (uintptr_t)addr + corrupt);
		goto corrupt;
	}

	if ((cp->cache_flags & UMF_HASH) &&
	    buftagp->bt_redzone != UMEM_REDZONE_PATTERN) {
		if (!besilent)
			mdb_printf("buffer %p (free) seems to "
			    "have a corrupt redzone pattern\n", addr);
		goto corrupt;
	}

	/*
	 * confirm bufctl pointer integrity.
	 */
	if (verify_buftag(buftagp, UMEM_BUFTAG_FREE) == -1) {
		if (!besilent)
			mdb_printf("buffer %p (free) has a corrupt "
			    "buftag\n", addr);
		goto corrupt;
	}

	return (WALK_NEXT);
corrupt:
	umv->umv_corruption++;
	return (WALK_NEXT);
}

/*
 * verify_alloc()
 *	Verify that the buftag of an allocated buffer makes sense with respect
 *	to the buffer.
 */
/*ARGSUSED1*/
static int
verify_alloc(uintptr_t addr, const void *data, void *private)
{
	umem_verify_t *umv = (umem_verify_t *)private;
	umem_cache_t *cp = &umv->umv_cache;
	uint64_t *buf = umv->umv_buf;	/* buf to validate */
	/*LINTED*/
	umem_buftag_t *buftagp = UMEM_BUFTAG(cp, buf);
	uint32_t *ip = (uint32_t *)buftagp;
	uint8_t *bp = (uint8_t *)buf;
	int looks_ok = 0, size_ok = 1;	/* flags for finding corruption */
	int besilent = umv->umv_besilent;

	/*
	 * Read the buffer to check.
	 */
	if (mdb_vread(buf, umv->umv_size, addr) == -1) {
		if (!besilent)
			mdb_warn("couldn't read %p", addr);
		return (WALK_NEXT);
	}

	/*
	 * There are two cases to handle:
	 * 1. If the buf was alloc'd using umem_cache_alloc, it will have
	 *    0xfeedfacefeedface at the end of it
	 * 2. If the buf was alloc'd using umem_alloc, it will have
	 *    0xbb just past the end of the region in use.  At the buftag,
	 *    it will have 0xfeedface (or, if the whole buffer is in use,
	 *    0xfeedface & bb000000 or 0xfeedfacf & 000000bb depending on
	 *    endianness), followed by 32 bits containing the offset of the
	 *    0xbb byte in the buffer.
	 *
	 * Finally, the two 32-bit words that comprise the second half of the
	 * buftag should xor to UMEM_BUFTAG_ALLOC
	 */

	if (buftagp->bt_redzone == UMEM_REDZONE_PATTERN)
		looks_ok = 1;
	else if (!UMEM_SIZE_VALID(ip[1]))
		size_ok = 0;
	else if (bp[UMEM_SIZE_DECODE(ip[1])] == UMEM_REDZONE_BYTE)
		looks_ok = 1;
	else
		size_ok = 0;

	if (!size_ok) {
		if (!besilent)
			mdb_printf("buffer %p (allocated) has a corrupt "
			    "redzone size encoding\n", addr);
		goto corrupt;
	}

	if (!looks_ok) {
		if (!besilent)
			mdb_printf("buffer %p (allocated) has a corrupt "
			    "redzone signature\n", addr);
		goto corrupt;
	}

	if (verify_buftag(buftagp, UMEM_BUFTAG_ALLOC) == -1) {
		if (!besilent)
			mdb_printf("buffer %p (allocated) has a "
			    "corrupt buftag\n", addr);
		goto corrupt;
	}

	return (WALK_NEXT);
corrupt:
	umv->umv_corruption++;
	return (WALK_NEXT);
}

/*ARGSUSED2*/
int
umem_verify(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC) {
		int check_alloc = 0, check_free = 0;
		umem_verify_t umv;

		if (mdb_vread(&umv.umv_cache, sizeof (umv.umv_cache),
		    addr) == -1) {
			mdb_warn("couldn't read umem_cache %p", addr);
			return (DCMD_ERR);
		}

		umv.umv_size = umv.umv_cache.cache_buftag +
		    sizeof (umem_buftag_t);
		umv.umv_buf = mdb_alloc(umv.umv_size, UM_SLEEP | UM_GC);
		umv.umv_corruption = 0;

		if ((umv.umv_cache.cache_flags & UMF_REDZONE)) {
			check_alloc = 1;
			if (umv.umv_cache.cache_flags & UMF_DEADBEEF)
				check_free = 1;
		} else {
			if (!(flags & DCMD_LOOP)) {
				mdb_warn("cache %p (%s) does not have "
				    "redzone checking enabled\n", addr,
				    umv.umv_cache.cache_name);
			}
			return (DCMD_ERR);
		}

		if (flags & DCMD_LOOP) {
			/*
			 * table mode, don't print out every corrupt buffer
			 */
			umv.umv_besilent = 1;
		} else {
			mdb_printf("Summary for cache '%s'\n",
			    umv.umv_cache.cache_name);
			mdb_inc_indent(2);
			umv.umv_besilent = 0;
		}

		if (check_alloc)
			(void) mdb_pwalk("umem", verify_alloc, &umv, addr);
		if (check_free)
			(void) mdb_pwalk("freemem", verify_free, &umv, addr);

		if (flags & DCMD_LOOP) {
			if (umv.umv_corruption == 0) {
				mdb_printf("%-*s %?p clean\n",
				    UMEM_CACHE_NAMELEN,
				    umv.umv_cache.cache_name, addr);
			} else {
				char *s = "";	/* optional s in "buffer[s]" */
				if (umv.umv_corruption > 1)
					s = "s";

				mdb_printf("%-*s %?p %d corrupt buffer%s\n",
				    UMEM_CACHE_NAMELEN,
				    umv.umv_cache.cache_name, addr,
				    umv.umv_corruption, s);
			}
		} else {
			/*
			 * This is the more verbose mode, when the user has
			 * type addr::umem_verify.  If the cache was clean,
			 * nothing will have yet been printed. So say something.
			 */
			if (umv.umv_corruption == 0)
				mdb_printf("clean\n");

			mdb_dec_indent(2);
		}
	} else {
		/*
		 * If the user didn't specify a cache to verify, we'll walk all
		 * umem_cache's, specifying ourself as a callback for each...
		 * this is the equivalent of '::walk umem_cache .::umem_verify'
		 */
		mdb_printf("%<u>%-*s %-?s %-20s%</b>\n", UMEM_CACHE_NAMELEN,
		    "Cache Name", "Addr", "Cache Integrity");
		(void) (mdb_walk_dcmd("umem_cache", "umem_verify", 0, NULL));
	}

	return (DCMD_OK);
}

typedef struct vmem_node {
	struct vmem_node *vn_next;
	struct vmem_node *vn_parent;
	struct vmem_node *vn_sibling;
	struct vmem_node *vn_children;
	uintptr_t vn_addr;
	int vn_marked;
	vmem_t vn_vmem;
} vmem_node_t;

typedef struct vmem_walk {
	vmem_node_t *vw_root;
	vmem_node_t *vw_current;
} vmem_walk_t;

int
vmem_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t vaddr, paddr;
	vmem_node_t *head = NULL, *root = NULL, *current = NULL, *parent, *vp;
	vmem_walk_t *vw;

	if (umem_readvar(&vaddr, "vmem_list") == -1) {
		mdb_warn("couldn't read 'vmem_list'");
		return (WALK_ERR);
	}

	while (vaddr != NULL) {
		vp = mdb_zalloc(sizeof (vmem_node_t), UM_SLEEP);
		vp->vn_addr = vaddr;
		vp->vn_next = head;
		head = vp;

		if (vaddr == wsp->walk_addr)
			current = vp;

		if (mdb_vread(&vp->vn_vmem, sizeof (vmem_t), vaddr) == -1) {
			mdb_warn("couldn't read vmem_t at %p", vaddr);
			goto err;
		}

		vaddr = (uintptr_t)vp->vn_vmem.vm_next;
	}

	for (vp = head; vp != NULL; vp = vp->vn_next) {

		if ((paddr = (uintptr_t)vp->vn_vmem.vm_source) == NULL) {
			vp->vn_sibling = root;
			root = vp;
			continue;
		}

		for (parent = head; parent != NULL; parent = parent->vn_next) {
			if (parent->vn_addr != paddr)
				continue;
			vp->vn_sibling = parent->vn_children;
			parent->vn_children = vp;
			vp->vn_parent = parent;
			break;
		}

		if (parent == NULL) {
			mdb_warn("couldn't find %p's parent (%p)\n",
			    vp->vn_addr, paddr);
			goto err;
		}
	}

	vw = mdb_zalloc(sizeof (vmem_walk_t), UM_SLEEP);
	vw->vw_root = root;

	if (current != NULL)
		vw->vw_current = current;
	else
		vw->vw_current = root;

	wsp->walk_data = vw;
	return (WALK_NEXT);
err:
	for (vp = head; head != NULL; vp = head) {
		head = vp->vn_next;
		mdb_free(vp, sizeof (vmem_node_t));
	}

	return (WALK_ERR);
}

int
vmem_walk_step(mdb_walk_state_t *wsp)
{
	vmem_walk_t *vw = wsp->walk_data;
	vmem_node_t *vp;
	int rval;

	if ((vp = vw->vw_current) == NULL)
		return (WALK_DONE);

	rval = wsp->walk_callback(vp->vn_addr, &vp->vn_vmem, wsp->walk_cbdata);

	if (vp->vn_children != NULL) {
		vw->vw_current = vp->vn_children;
		return (rval);
	}

	do {
		vw->vw_current = vp->vn_sibling;
		vp = vp->vn_parent;
	} while (vw->vw_current == NULL && vp != NULL);

	return (rval);
}

/*
 * The "vmem_postfix" walk walks the vmem arenas in post-fix order; all
 * children are visited before their parent.  We perform the postfix walk
 * iteratively (rather than recursively) to allow mdb to regain control
 * after each callback.
 */
int
vmem_postfix_walk_step(mdb_walk_state_t *wsp)
{
	vmem_walk_t *vw = wsp->walk_data;
	vmem_node_t *vp = vw->vw_current;
	int rval;

	/*
	 * If this node is marked, then we know that we have already visited
	 * all of its children.  If the node has any siblings, they need to
	 * be visited next; otherwise, we need to visit the parent.  Note
	 * that vp->vn_marked will only be zero on the first invocation of
	 * the step function.
	 */
	if (vp->vn_marked) {
		if (vp->vn_sibling != NULL)
			vp = vp->vn_sibling;
		else if (vp->vn_parent != NULL)
			vp = vp->vn_parent;
		else {
			/*
			 * We have neither a parent, nor a sibling, and we
			 * have already been visited; we're done.
			 */
			return (WALK_DONE);
		}
	}

	/*
	 * Before we visit this node, visit its children.
	 */
	while (vp->vn_children != NULL && !vp->vn_children->vn_marked)
		vp = vp->vn_children;

	vp->vn_marked = 1;
	vw->vw_current = vp;
	rval = wsp->walk_callback(vp->vn_addr, &vp->vn_vmem, wsp->walk_cbdata);

	return (rval);
}

void
vmem_walk_fini(mdb_walk_state_t *wsp)
{
	vmem_walk_t *vw = wsp->walk_data;
	vmem_node_t *root = vw->vw_root;
	int done;

	if (root == NULL)
		return;

	if ((vw->vw_root = root->vn_children) != NULL)
		vmem_walk_fini(wsp);

	vw->vw_root = root->vn_sibling;
	done = (root->vn_sibling == NULL && root->vn_parent == NULL);
	mdb_free(root, sizeof (vmem_node_t));

	if (done) {
		mdb_free(vw, sizeof (vmem_walk_t));
	} else {
		vmem_walk_fini(wsp);
	}
}

typedef struct vmem_seg_walk {
	uint8_t vsw_type;
	uintptr_t vsw_start;
	uintptr_t vsw_current;
} vmem_seg_walk_t;

/*ARGSUSED*/
int
vmem_seg_walk_common_init(mdb_walk_state_t *wsp, uint8_t type, char *name)
{
	vmem_seg_walk_t *vsw;

	if (wsp->walk_addr == NULL) {
		mdb_warn("vmem_%s does not support global walks\n", name);
		return (WALK_ERR);
	}

	wsp->walk_data = vsw = mdb_alloc(sizeof (vmem_seg_walk_t), UM_SLEEP);

	vsw->vsw_type = type;
	vsw->vsw_start = wsp->walk_addr + OFFSETOF(vmem_t, vm_seg0);
	vsw->vsw_current = vsw->vsw_start;

	return (WALK_NEXT);
}

/*
 * vmem segments can't have type 0 (this should be added to vmem_impl.h).
 */
#define	VMEM_NONE	0

int
vmem_alloc_walk_init(mdb_walk_state_t *wsp)
{
	return (vmem_seg_walk_common_init(wsp, VMEM_ALLOC, "alloc"));
}

int
vmem_free_walk_init(mdb_walk_state_t *wsp)
{
	return (vmem_seg_walk_common_init(wsp, VMEM_FREE, "free"));
}

int
vmem_span_walk_init(mdb_walk_state_t *wsp)
{
	return (vmem_seg_walk_common_init(wsp, VMEM_SPAN, "span"));
}

int
vmem_seg_walk_init(mdb_walk_state_t *wsp)
{
	return (vmem_seg_walk_common_init(wsp, VMEM_NONE, "seg"));
}

int
vmem_seg_walk_step(mdb_walk_state_t *wsp)
{
	vmem_seg_t seg;
	vmem_seg_walk_t *vsw = wsp->walk_data;
	uintptr_t addr = vsw->vsw_current;
	static size_t seg_size = 0;
	int rval;

	if (!seg_size) {
		if (umem_readvar(&seg_size, "vmem_seg_size") == -1) {
			mdb_warn("failed to read 'vmem_seg_size'");
			seg_size = sizeof (vmem_seg_t);
		}
	}

	if (seg_size < sizeof (seg))
		bzero((caddr_t)&seg + seg_size, sizeof (seg) - seg_size);

	if (mdb_vread(&seg, seg_size, addr) == -1) {
		mdb_warn("couldn't read vmem_seg at %p", addr);
		return (WALK_ERR);
	}

	vsw->vsw_current = (uintptr_t)seg.vs_anext;
	if (vsw->vsw_type != VMEM_NONE && seg.vs_type != vsw->vsw_type) {
		rval = WALK_NEXT;
	} else {
		rval = wsp->walk_callback(addr, &seg, wsp->walk_cbdata);
	}

	if (vsw->vsw_current == vsw->vsw_start)
		return (WALK_DONE);

	return (rval);
}

void
vmem_seg_walk_fini(mdb_walk_state_t *wsp)
{
	vmem_seg_walk_t *vsw = wsp->walk_data;

	mdb_free(vsw, sizeof (vmem_seg_walk_t));
}

#define	VMEM_NAMEWIDTH	22

int
vmem(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vmem_t v, parent;
	uintptr_t paddr;
	int ident = 0;
	char c[VMEM_NAMEWIDTH];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("vmem", "vmem", argc, argv) == -1) {
			mdb_warn("can't walk vmem");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-?s %-*s %10s %12s %9s %5s\n",
		    "ADDR", VMEM_NAMEWIDTH, "NAME", "INUSE",
		    "TOTAL", "SUCCEED", "FAIL");

	if (mdb_vread(&v, sizeof (v), addr) == -1) {
		mdb_warn("couldn't read vmem at %p", addr);
		return (DCMD_ERR);
	}

	for (paddr = (uintptr_t)v.vm_source; paddr != NULL; ident += 2) {
		if (mdb_vread(&parent, sizeof (parent), paddr) == -1) {
			mdb_warn("couldn't trace %p's ancestry", addr);
			ident = 0;
			break;
		}
		paddr = (uintptr_t)parent.vm_source;
	}

	(void) mdb_snprintf(c, VMEM_NAMEWIDTH, "%*s%s", ident, "", v.vm_name);

	mdb_printf("%0?p %-*s %10llu %12llu %9llu %5llu\n",
	    addr, VMEM_NAMEWIDTH, c,
	    v.vm_kstat.vk_mem_inuse, v.vm_kstat.vk_mem_total,
	    v.vm_kstat.vk_alloc, v.vm_kstat.vk_fail);

	return (DCMD_OK);
}

void
vmem_seg_help(void)
{
	mdb_printf("%s\n",
"Display the contents of vmem_seg_ts, with optional filtering.\n"
"\n"
"A vmem_seg_t represents a range of addresses (or arbitrary numbers),\n"
"representing a single chunk of data.  Only ALLOC segments have debugging\n"
"information.\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -v    Display the full content of the vmem_seg, including its stack trace\n"
"  -s    report the size of the segment, instead of the end address\n"
"  -c caller\n"
"        filter out segments without the function/PC in their stack trace\n"
"  -e earliest\n"
"        filter out segments timestamped before earliest\n"
"  -l latest\n"
"        filter out segments timestamped after latest\n"
"  -m minsize\n"
"        filer out segments smaller than minsize\n"
"  -M maxsize\n"
"        filer out segments larger than maxsize\n"
"  -t thread\n"
"        filter out segments not involving thread\n"
"  -T type\n"
"        filter out segments not of type 'type'\n"
"        type is one of: ALLOC/FREE/SPAN/ROTOR/WALKER\n");
}


/*ARGSUSED*/
int
vmem_seg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vmem_seg_t vs;
	uintptr_t *stk = vs.vs_stack;
	uintptr_t sz;
	uint8_t t;
	const char *type = NULL;
	GElf_Sym sym;
	char c[MDB_SYM_NAMLEN];
	int no_debug;
	int i;
	int depth;
	uintptr_t laddr, haddr;

	uintptr_t caller = NULL, thread = NULL;
	uintptr_t minsize = 0, maxsize = 0;

	hrtime_t earliest = 0, latest = 0;

	uint_t size = 0;
	uint_t verbose = 0;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &caller,
	    'e', MDB_OPT_UINT64, &earliest,
	    'l', MDB_OPT_UINT64, &latest,
	    's', MDB_OPT_SETBITS, TRUE, &size,
	    'm', MDB_OPT_UINTPTR, &minsize,
	    'M', MDB_OPT_UINTPTR, &maxsize,
	    't', MDB_OPT_UINTPTR, &thread,
	    'T', MDB_OPT_STR, &type,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		if (verbose) {
			mdb_printf("%16s %4s %16s %16s %16s\n"
			    "%<u>%16s %4s %16s %16s %16s%</u>\n",
			    "ADDR", "TYPE", "START", "END", "SIZE",
			    "", "", "THREAD", "TIMESTAMP", "");
		} else {
			mdb_printf("%?s %4s %?s %?s %s\n", "ADDR", "TYPE",
			    "START", size? "SIZE" : "END", "WHO");
		}
	}

	if (mdb_vread(&vs, sizeof (vs), addr) == -1) {
		mdb_warn("couldn't read vmem_seg at %p", addr);
		return (DCMD_ERR);
	}

	if (type != NULL) {
		if (strcmp(type, "ALLC") == 0 || strcmp(type, "ALLOC") == 0)
			t = VMEM_ALLOC;
		else if (strcmp(type, "FREE") == 0)
			t = VMEM_FREE;
		else if (strcmp(type, "SPAN") == 0)
			t = VMEM_SPAN;
		else if (strcmp(type, "ROTR") == 0 ||
		    strcmp(type, "ROTOR") == 0)
			t = VMEM_ROTOR;
		else if (strcmp(type, "WLKR") == 0 ||
		    strcmp(type, "WALKER") == 0)
			t = VMEM_WALKER;
		else {
			mdb_warn("\"%s\" is not a recognized vmem_seg type\n",
			    type);
			return (DCMD_ERR);
		}

		if (vs.vs_type != t)
			return (DCMD_OK);
	}

	sz = vs.vs_end - vs.vs_start;

	if (minsize != 0 && sz < minsize)
		return (DCMD_OK);

	if (maxsize != 0 && sz > maxsize)
		return (DCMD_OK);

	t = vs.vs_type;
	depth = vs.vs_depth;

	/*
	 * debug info, when present, is only accurate for VMEM_ALLOC segments
	 */
	no_debug = (t != VMEM_ALLOC) ||
	    (depth == 0 || depth > VMEM_STACK_DEPTH);

	if (no_debug) {
		if (caller != NULL || thread != NULL || earliest != 0 ||
		    latest != 0)
			return (DCMD_OK);		/* not enough info */
	} else {
		if (caller != NULL) {
			laddr = caller;
			haddr = caller + sizeof (caller);

			if (mdb_lookup_by_addr(caller, MDB_SYM_FUZZY, c,
			    sizeof (c), &sym) != -1 &&
			    caller == (uintptr_t)sym.st_value) {
				/*
				 * We were provided an exact symbol value; any
				 * address in the function is valid.
				 */
				laddr = (uintptr_t)sym.st_value;
				haddr = (uintptr_t)sym.st_value + sym.st_size;
			}

			for (i = 0; i < depth; i++)
				if (vs.vs_stack[i] >= laddr &&
				    vs.vs_stack[i] < haddr)
					break;

			if (i == depth)
				return (DCMD_OK);
		}

		if (thread != NULL && (uintptr_t)vs.vs_thread != thread)
			return (DCMD_OK);

		if (earliest != 0 && vs.vs_timestamp < earliest)
			return (DCMD_OK);

		if (latest != 0 && vs.vs_timestamp > latest)
			return (DCMD_OK);
	}

	type = (t == VMEM_ALLOC ? "ALLC" :
	    t == VMEM_FREE ? "FREE" :
	    t == VMEM_SPAN ? "SPAN" :
	    t == VMEM_ROTOR ? "ROTR" :
	    t == VMEM_WALKER ? "WLKR" :
	    "????");

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#r\n", addr);
		return (DCMD_OK);
	}

	if (verbose) {
		mdb_printf("%<b>%16p%</b> %4s %16p %16p %16d\n",
		    addr, type, vs.vs_start, vs.vs_end, sz);

		if (no_debug)
			return (DCMD_OK);

		mdb_printf("%16s %4s %16d %16llx\n",
		    "", "", vs.vs_thread, vs.vs_timestamp);

		mdb_inc_indent(17);
		for (i = 0; i < depth; i++) {
			mdb_printf("%a\n", stk[i]);
		}
		mdb_dec_indent(17);
		mdb_printf("\n");
	} else {
		mdb_printf("%0?p %4s %0?p %0?p", addr, type,
		    vs.vs_start, size? sz : vs.vs_end);

		if (no_debug) {
			mdb_printf("\n");
			return (DCMD_OK);
		}

		for (i = 0; i < depth; i++) {
			if (mdb_lookup_by_addr(stk[i], MDB_SYM_FUZZY,
			    c, sizeof (c), &sym) == -1)
				continue;
			if (is_umem_sym(c, "vmem_"))
				continue;
			break;
		}
		mdb_printf(" %a\n", stk[i]);
	}
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
showbc(uintptr_t addr, const umem_bufctl_audit_t *bcp, hrtime_t *newest)
{
	char name[UMEM_CACHE_NAMELEN + 1];
	hrtime_t delta;
	int i, depth;

	if (bcp->bc_timestamp == 0)
		return (WALK_DONE);

	if (*newest == 0)
		*newest = bcp->bc_timestamp;

	delta = *newest - bcp->bc_timestamp;
	depth = MIN(bcp->bc_depth, umem_stack_depth);

	if (mdb_readstr(name, sizeof (name), (uintptr_t)
	    &bcp->bc_cache->cache_name) <= 0)
		(void) mdb_snprintf(name, sizeof (name), "%a", bcp->bc_cache);

	mdb_printf("\nT-%lld.%09lld  addr=%p  %s\n",
	    delta / NANOSEC, delta % NANOSEC, bcp->bc_addr, name);

	for (i = 0; i < depth; i++)
		mdb_printf("\t %a\n", bcp->bc_stack[i]);

	return (WALK_NEXT);
}

int
umalog(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *logname = "umem_transaction_log";
	hrtime_t newest = 0;

	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc > 0) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);
		if (strcmp(argv->a_un.a_str, "fail") == 0)
			logname = "umem_failure_log";
		else if (strcmp(argv->a_un.a_str, "slab") == 0)
			logname = "umem_slab_log";
		else
			return (DCMD_USAGE);
	}

	if (umem_readvar(&addr, logname) == -1) {
		mdb_warn("failed to read %s log header pointer");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("umem_log", (mdb_walk_cb_t)showbc, &newest, addr) == -1) {
		mdb_warn("failed to walk umem log");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * As the final lure for die-hard crash(1M) users, we provide ::umausers here.
 * The first piece is a structure which we use to accumulate umem_cache_t
 * addresses of interest.  The umc_add is used as a callback for the umem_cache
 * walker; we either add all caches, or ones named explicitly as arguments.
 */

typedef struct umclist {
	const char *umc_name;			/* Name to match (or NULL) */
	uintptr_t *umc_caches;			/* List of umem_cache_t addrs */
	int umc_nelems;				/* Num entries in umc_caches */
	int umc_size;				/* Size of umc_caches array */
} umclist_t;

static int
umc_add(uintptr_t addr, const umem_cache_t *cp, umclist_t *umc)
{
	void *p;
	int s;

	if (umc->umc_name == NULL ||
	    strcmp(cp->cache_name, umc->umc_name) == 0) {
		/*
		 * If we have a match, grow our array (if necessary), and then
		 * add the virtual address of the matching cache to our list.
		 */
		if (umc->umc_nelems >= umc->umc_size) {
			s = umc->umc_size ? umc->umc_size * 2 : 256;
			p = mdb_alloc(sizeof (uintptr_t) * s, UM_SLEEP | UM_GC);

			bcopy(umc->umc_caches, p,
			    sizeof (uintptr_t) * umc->umc_size);

			umc->umc_caches = p;
			umc->umc_size = s;
		}

		umc->umc_caches[umc->umc_nelems++] = addr;
		return (umc->umc_name ? WALK_DONE : WALK_NEXT);
	}

	return (WALK_NEXT);
}

/*
 * The second piece of ::umausers is a hash table of allocations.  Each
 * allocation owner is identified by its stack trace and data_size.  We then
 * track the total bytes of all such allocations, and the number of allocations
 * to report at the end.  Once we have a list of caches, we walk through the
 * allocated bufctls of each, and update our hash table accordingly.
 */

typedef struct umowner {
	struct umowner *umo_head;		/* First hash elt in bucket */
	struct umowner *umo_next;		/* Next hash elt in chain */
	size_t umo_signature;			/* Hash table signature */
	uint_t umo_num;				/* Number of allocations */
	size_t umo_data_size;			/* Size of each allocation */
	size_t umo_total_size;			/* Total bytes of allocation */
	int umo_depth;				/* Depth of stack trace */
	uintptr_t *umo_stack;			/* Stack trace */
} umowner_t;

typedef struct umusers {
	const umem_cache_t *umu_cache;		/* Current umem cache */
	umowner_t *umu_hash;			/* Hash table of owners */
	uintptr_t *umu_stacks;			/* stacks for owners */
	int umu_nelems;				/* Number of entries in use */
	int umu_size;				/* Total number of entries */
} umusers_t;

static void
umu_add(umusers_t *umu, const umem_bufctl_audit_t *bcp,
    size_t size, size_t data_size)
{
	int i, depth = MIN(bcp->bc_depth, umem_stack_depth);
	size_t bucket, signature = data_size;
	umowner_t *umo, *umoend;

	/*
	 * If the hash table is full, double its size and rehash everything.
	 */
	if (umu->umu_nelems >= umu->umu_size) {
		int s = umu->umu_size ? umu->umu_size * 2 : 1024;
		size_t umowner_size = sizeof (umowner_t);
		size_t trace_size = umem_stack_depth * sizeof (uintptr_t);
		uintptr_t *new_stacks;

		umo = mdb_alloc(umowner_size * s, UM_SLEEP | UM_GC);
		new_stacks = mdb_alloc(trace_size * s, UM_SLEEP | UM_GC);

		bcopy(umu->umu_hash, umo, umowner_size * umu->umu_size);
		bcopy(umu->umu_stacks, new_stacks, trace_size * umu->umu_size);
		umu->umu_hash = umo;
		umu->umu_stacks = new_stacks;
		umu->umu_size = s;

		umoend = umu->umu_hash + umu->umu_size;
		for (umo = umu->umu_hash; umo < umoend; umo++) {
			umo->umo_head = NULL;
			umo->umo_stack = &umu->umu_stacks[
			    umem_stack_depth * (umo - umu->umu_hash)];
		}

		umoend = umu->umu_hash + umu->umu_nelems;
		for (umo = umu->umu_hash; umo < umoend; umo++) {
			bucket = umo->umo_signature & (umu->umu_size - 1);
			umo->umo_next = umu->umu_hash[bucket].umo_head;
			umu->umu_hash[bucket].umo_head = umo;
		}
	}

	/*
	 * Finish computing the hash signature from the stack trace, and then
	 * see if the owner is in the hash table.  If so, update our stats.
	 */
	for (i = 0; i < depth; i++)
		signature += bcp->bc_stack[i];

	bucket = signature & (umu->umu_size - 1);

	for (umo = umu->umu_hash[bucket].umo_head; umo; umo = umo->umo_next) {
		if (umo->umo_signature == signature) {
			size_t difference = 0;

			difference |= umo->umo_data_size - data_size;
			difference |= umo->umo_depth - depth;

			for (i = 0; i < depth; i++) {
				difference |= umo->umo_stack[i] -
				    bcp->bc_stack[i];
			}

			if (difference == 0) {
				umo->umo_total_size += size;
				umo->umo_num++;
				return;
			}
		}
	}

	/*
	 * If the owner is not yet hashed, grab the next element and fill it
	 * in based on the allocation information.
	 */
	umo = &umu->umu_hash[umu->umu_nelems++];
	umo->umo_next = umu->umu_hash[bucket].umo_head;
	umu->umu_hash[bucket].umo_head = umo;

	umo->umo_signature = signature;
	umo->umo_num = 1;
	umo->umo_data_size = data_size;
	umo->umo_total_size = size;
	umo->umo_depth = depth;

	for (i = 0; i < depth; i++)
		umo->umo_stack[i] = bcp->bc_stack[i];
}

/*
 * When ::umausers is invoked without the -f flag, we simply update our hash
 * table with the information from each allocated bufctl.
 */
/*ARGSUSED*/
static int
umause1(uintptr_t addr, const umem_bufctl_audit_t *bcp, umusers_t *umu)
{
	const umem_cache_t *cp = umu->umu_cache;

	umu_add(umu, bcp, cp->cache_bufsize, cp->cache_bufsize);
	return (WALK_NEXT);
}

/*
 * When ::umausers is invoked with the -f flag, we print out the information
 * for each bufctl as well as updating the hash table.
 */
static int
umause2(uintptr_t addr, const umem_bufctl_audit_t *bcp, umusers_t *umu)
{
	int i, depth = MIN(bcp->bc_depth, umem_stack_depth);
	const umem_cache_t *cp = umu->umu_cache;

	mdb_printf("size %d, addr %p, thread %p, cache %s\n",
	    cp->cache_bufsize, addr, bcp->bc_thread, cp->cache_name);

	for (i = 0; i < depth; i++)
		mdb_printf("\t %a\n", bcp->bc_stack[i]);

	umu_add(umu, bcp, cp->cache_bufsize, cp->cache_bufsize);
	return (WALK_NEXT);
}

/*
 * We sort our results by allocation size before printing them.
 */
static int
umownercmp(const void *lp, const void *rp)
{
	const umowner_t *lhs = lp;
	const umowner_t *rhs = rp;

	return (rhs->umo_total_size - lhs->umo_total_size);
}

/*
 * The main engine of ::umausers is relatively straightforward: First we
 * accumulate our list of umem_cache_t addresses into the umclist_t. Next we
 * iterate over the allocated bufctls of each cache in the list.  Finally,
 * we sort and print our results.
 */
/*ARGSUSED*/
int
umausers(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int mem_threshold = 8192;	/* Minimum # bytes for printing */
	int cnt_threshold = 100;	/* Minimum # blocks for printing */
	int audited_caches = 0;		/* Number of UMF_AUDIT caches found */
	int do_all_caches = 1;		/* Do all caches (no arguments) */
	int opt_e = FALSE;		/* Include "small" users */
	int opt_f = FALSE;		/* Print stack traces */

	mdb_walk_cb_t callback = (mdb_walk_cb_t)umause1;
	umowner_t *umo, *umoend;
	int i, oelems;

	umclist_t umc;
	umusers_t umu;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	bzero(&umc, sizeof (umc));
	bzero(&umu, sizeof (umu));

	while ((i = mdb_getopts(argc, argv,
	    'e', MDB_OPT_SETBITS, TRUE, &opt_e,
	    'f', MDB_OPT_SETBITS, TRUE, &opt_f, NULL)) != argc) {

		argv += i;	/* skip past options we just processed */
		argc -= i;	/* adjust argc */

		if (argv->a_type != MDB_TYPE_STRING || *argv->a_un.a_str == '-')
			return (DCMD_USAGE);

		oelems = umc.umc_nelems;
		umc.umc_name = argv->a_un.a_str;
		(void) mdb_walk("umem_cache", (mdb_walk_cb_t)umc_add, &umc);

		if (umc.umc_nelems == oelems) {
			mdb_warn("unknown umem cache: %s\n", umc.umc_name);
			return (DCMD_ERR);
		}

		do_all_caches = 0;
		argv++;
		argc--;
	}

	if (opt_e)
		mem_threshold = cnt_threshold = 0;

	if (opt_f)
		callback = (mdb_walk_cb_t)umause2;

	if (do_all_caches) {
		umc.umc_name = NULL; /* match all cache names */
		(void) mdb_walk("umem_cache", (mdb_walk_cb_t)umc_add, &umc);
	}

	for (i = 0; i < umc.umc_nelems; i++) {
		uintptr_t cp = umc.umc_caches[i];
		umem_cache_t c;

		if (mdb_vread(&c, sizeof (c), cp) == -1) {
			mdb_warn("failed to read cache at %p", cp);
			continue;
		}

		if (!(c.cache_flags & UMF_AUDIT)) {
			if (!do_all_caches) {
				mdb_warn("UMF_AUDIT is not enabled for %s\n",
				    c.cache_name);
			}
			continue;
		}

		umu.umu_cache = &c;
		(void) mdb_pwalk("bufctl", callback, &umu, cp);
		audited_caches++;
	}

	if (audited_caches == 0 && do_all_caches) {
		mdb_warn("UMF_AUDIT is not enabled for any caches\n");
		return (DCMD_ERR);
	}

	qsort(umu.umu_hash, umu.umu_nelems, sizeof (umowner_t), umownercmp);
	umoend = umu.umu_hash + umu.umu_nelems;

	for (umo = umu.umu_hash; umo < umoend; umo++) {
		if (umo->umo_total_size < mem_threshold &&
		    umo->umo_num < cnt_threshold)
			continue;
		mdb_printf("%lu bytes for %u allocations with data size %lu:\n",
		    umo->umo_total_size, umo->umo_num, umo->umo_data_size);
		for (i = 0; i < umo->umo_depth; i++)
			mdb_printf("\t %a\n", umo->umo_stack[i]);
	}

	return (DCMD_OK);
}

struct malloc_data {
	uint32_t malloc_size;
	uint32_t malloc_stat; /* == UMEM_MALLOC_ENCODE(state, malloc_size) */
};

#ifdef _LP64
#define	UMI_MAX_BUCKET		(UMEM_MAXBUF - 2*sizeof (struct malloc_data))
#else
#define	UMI_MAX_BUCKET		(UMEM_MAXBUF - sizeof (struct malloc_data))
#endif

typedef struct umem_malloc_info {
	size_t um_total;	/* total allocated buffers */
	size_t um_malloc;	/* malloc buffers */
	size_t um_malloc_size;	/* sum of malloc buffer sizes */
	size_t um_malloc_overhead; /* sum of in-chunk overheads */

	umem_cache_t *um_cp;

	uint_t *um_bucket;
} umem_malloc_info_t;

static void
umem_malloc_print_dist(uint_t *um_bucket, size_t minmalloc, size_t maxmalloc,
    size_t maxbuckets, size_t minbucketsize, int geometric)
{
	uint64_t um_malloc;
	int minb = -1;
	int maxb = -1;
	int buckets;
	int nbucks;
	int i;
	int b;
	const int *distarray;

	minb = (int)minmalloc;
	maxb = (int)maxmalloc;

	nbucks = buckets = maxb - minb + 1;

	um_malloc = 0;
	for (b = minb; b <= maxb; b++)
		um_malloc += um_bucket[b];

	if (maxbuckets != 0)
		buckets = MIN(buckets, maxbuckets);

	if (minbucketsize > 1) {
		buckets = MIN(buckets, nbucks/minbucketsize);
		if (buckets == 0) {
			buckets = 1;
			minbucketsize = nbucks;
		}
	}

	if (geometric)
		distarray = dist_geometric(buckets, minb, maxb, minbucketsize);
	else
		distarray = dist_linear(buckets, minb, maxb);

	dist_print_header("malloc size", 11, "count");
	for (i = 0; i < buckets; i++) {
		dist_print_bucket(distarray, i, um_bucket, um_malloc, 11);
	}
	mdb_printf("\n");
}

/*
 * A malloc()ed buffer looks like:
 *
 *	<----------- mi.malloc_size --->
 *	<----------- cp.cache_bufsize ------------------>
 *	<----------- cp.cache_chunksize -------------------------------->
 *	+-------+-----------------------+---------------+---------------+
 *	|/tag///| mallocsz		|/round-off/////|/debug info////|
 *	+-------+---------------------------------------+---------------+
 *		<-- usable space ------>
 *
 * mallocsz is the argument to malloc(3C).
 * mi.malloc_size is the actual size passed to umem_alloc(), which
 * is rounded up to the smallest available cache size, which is
 * cache_bufsize.  If there is debugging or alignment overhead in
 * the cache, that is reflected in a larger cache_chunksize.
 *
 * The tag at the beginning of the buffer is either 8-bytes or 16-bytes,
 * depending upon the ISA's alignment requirements.  For 32-bit allocations,
 * it is always a 8-byte tag.  For 64-bit allocations larger than 8 bytes,
 * the tag has 8 bytes of padding before it.
 *
 * 32-byte, 64-byte buffers <= 8 bytes:
 *	+-------+-------+--------- ...
 *	|/size//|/stat//| mallocsz ...
 *	+-------+-------+--------- ...
 *			^
 *			pointer returned from malloc(3C)
 *
 * 64-byte buffers > 8 bytes:
 *	+---------------+-------+-------+--------- ...
 *	|/padding///////|/size//|/stat//| mallocsz ...
 *	+---------------+-------+-------+--------- ...
 *					^
 *					pointer returned from malloc(3C)
 *
 * The "size" field is "malloc_size", which is mallocsz + the padding.
 * The "stat" field is derived from malloc_size, and functions as a
 * validation that this buffer is actually from malloc(3C).
 */
/*ARGSUSED*/
static int
um_umem_buffer_cb(uintptr_t addr, void *buf, umem_malloc_info_t *ump)
{
	struct malloc_data md;
	size_t m_addr = addr;
	size_t overhead = sizeof (md);
	size_t mallocsz;

	ump->um_total++;

#ifdef _LP64
	if (ump->um_cp->cache_bufsize > UMEM_SECOND_ALIGN) {
		m_addr += overhead;
		overhead += sizeof (md);
	}
#endif

	if (mdb_vread(&md, sizeof (md), m_addr) == -1) {
		mdb_warn("unable to read malloc header at %p", m_addr);
		return (WALK_NEXT);
	}

	switch (UMEM_MALLOC_DECODE(md.malloc_stat, md.malloc_size)) {
	case MALLOC_MAGIC:
#ifdef _LP64
	case MALLOC_SECOND_MAGIC:
#endif
		mallocsz = md.malloc_size - overhead;

		ump->um_malloc++;
		ump->um_malloc_size += mallocsz;
		ump->um_malloc_overhead += overhead;

		/* include round-off and debug overhead */
		ump->um_malloc_overhead +=
		    ump->um_cp->cache_chunksize - md.malloc_size;

		if (ump->um_bucket != NULL && mallocsz <= UMI_MAX_BUCKET)
			ump->um_bucket[mallocsz]++;

		break;
	default:
		break;
	}

	return (WALK_NEXT);
}

int
get_umem_alloc_sizes(int **out, size_t *out_num)
{
	GElf_Sym sym;

	if (umem_lookup_by_name("umem_alloc_sizes", &sym) == -1) {
		mdb_warn("unable to look up umem_alloc_sizes");
		return (-1);
	}

	*out = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);
	*out_num = sym.st_size / sizeof (int);

	if (mdb_vread(*out, sym.st_size, sym.st_value) == -1) {
		mdb_warn("unable to read umem_alloc_sizes (%p)", sym.st_value);
		*out = NULL;
		return (-1);
	}

	return (0);
}


static int
um_umem_cache_cb(uintptr_t addr, umem_cache_t *cp, umem_malloc_info_t *ump)
{
	if (strncmp(cp->cache_name, "umem_alloc_", strlen("umem_alloc_")) != 0)
		return (WALK_NEXT);

	ump->um_cp = cp;

	if (mdb_pwalk("umem", (mdb_walk_cb_t)um_umem_buffer_cb, ump, addr) ==
	    -1) {
		mdb_warn("can't walk 'umem' for cache %p", addr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

void
umem_malloc_dist_help(void)
{
	mdb_printf("%s\n",
	    "report distribution of outstanding malloc()s");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -b maxbins\n"
"        Use at most maxbins bins for the data\n"
"  -B minbinsize\n"
"        Make the bins at least minbinsize bytes apart\n"
"  -d    dump the raw data out, without binning\n"
"  -g    use geometric binning instead of linear binning\n");
}

/*ARGSUSED*/
int
umem_malloc_dist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	umem_malloc_info_t mi;
	uint_t geometric = 0;
	uint_t dump = 0;
	size_t maxbuckets = 0;
	size_t minbucketsize = 0;

	size_t minalloc = 0;
	size_t maxalloc = UMI_MAX_BUCKET;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &dump,
	    'g', MDB_OPT_SETBITS, TRUE, &geometric,
	    'b', MDB_OPT_UINTPTR, &maxbuckets,
	    'B', MDB_OPT_UINTPTR, &minbucketsize,
	    0) != argc)
		return (DCMD_USAGE);

	bzero(&mi, sizeof (mi));
	mi.um_bucket = mdb_zalloc((UMI_MAX_BUCKET + 1) * sizeof (*mi.um_bucket),
	    UM_SLEEP | UM_GC);

	if (mdb_walk("umem_cache", (mdb_walk_cb_t)um_umem_cache_cb,
	    &mi) == -1) {
		mdb_warn("unable to walk 'umem_cache'");
		return (DCMD_ERR);
	}

	if (dump) {
		int i;
		for (i = minalloc; i <= maxalloc; i++)
			mdb_printf("%d\t%d\n", i, mi.um_bucket[i]);

		return (DCMD_OK);
	}

	umem_malloc_print_dist(mi.um_bucket, minalloc, maxalloc,
	    maxbuckets, minbucketsize, geometric);

	return (DCMD_OK);
}

void
umem_malloc_info_help(void)
{
	mdb_printf("%s\n",
	    "report information about malloc()s by cache.  ");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -b maxbins\n"
"        Use at most maxbins bins for the data\n"
"  -B minbinsize\n"
"        Make the bins at least minbinsize bytes apart\n"
"  -d    dump the raw distribution data without binning\n"
#ifndef _KMDB
"  -g    use geometric binning instead of linear binning\n"
#endif
	    "");
}
int
umem_malloc_info(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	umem_cache_t c;
	umem_malloc_info_t mi;

	int skip = 0;

	size_t maxmalloc;
	size_t overhead;
	size_t allocated;
	size_t avg_malloc;
	size_t overhead_pct;	/* 1000 * overhead_percent */

	uint_t verbose = 0;
	uint_t dump = 0;
	uint_t geometric = 0;
	size_t maxbuckets = 0;
	size_t minbucketsize = 0;

	int *alloc_sizes;
	int idx;
	size_t num;
	size_t minmalloc;

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &dump,
	    'g', MDB_OPT_SETBITS, TRUE, &geometric,
	    'b', MDB_OPT_UINTPTR, &maxbuckets,
	    'B', MDB_OPT_UINTPTR, &minbucketsize,
	    0) != argc)
		return (DCMD_USAGE);

	if (dump || geometric || (maxbuckets != 0) || (minbucketsize != 0))
		verbose = 1;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("umem_cache", "umem_malloc_info",
		    argc, argv) == -1) {
			mdb_warn("can't walk umem_cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (!mdb_vread(&c, sizeof (c), addr)) {
		mdb_warn("unable to read cache at %p", addr);
		return (DCMD_ERR);
	}

	if (strncmp(c.cache_name, "umem_alloc_", strlen("umem_alloc_")) != 0) {
		if (!(flags & DCMD_LOOP))
			mdb_warn("umem_malloc_info: cache \"%s\" is not used "
			    "by malloc()\n", c.cache_name);
		skip = 1;
	}

	/*
	 * normally, print the header only the first time.  In verbose mode,
	 * print the header on every non-skipped buffer
	 */
	if ((!verbose && DCMD_HDRSPEC(flags)) || (verbose && !skip))
		mdb_printf("%<ul>%-?s %6s %6s %8s %8s %10s %10s %6s%</ul>\n",
		    "CACHE", "BUFSZ", "MAXMAL",
		    "BUFMALLC", "AVG_MAL", "MALLOCED", "OVERHEAD", "%OVER");

	if (skip)
		return (DCMD_OK);

	maxmalloc = c.cache_bufsize - sizeof (struct malloc_data);
#ifdef _LP64
	if (c.cache_bufsize > UMEM_SECOND_ALIGN)
		maxmalloc -= sizeof (struct malloc_data);
#endif

	bzero(&mi, sizeof (mi));
	mi.um_cp = &c;
	if (verbose)
		mi.um_bucket =
		    mdb_zalloc((UMI_MAX_BUCKET + 1) * sizeof (*mi.um_bucket),
		    UM_SLEEP | UM_GC);

	if (mdb_pwalk("umem", (mdb_walk_cb_t)um_umem_buffer_cb, &mi, addr) ==
	    -1) {
		mdb_warn("can't walk 'umem'");
		return (DCMD_ERR);
	}

	overhead = mi.um_malloc_overhead;
	allocated = mi.um_malloc_size;

	/* do integer round off for the average */
	if (mi.um_malloc != 0)
		avg_malloc = (allocated + (mi.um_malloc - 1)/2) / mi.um_malloc;
	else
		avg_malloc = 0;

	/*
	 * include per-slab overhead
	 *
	 * Each slab in a given cache is the same size, and has the same
	 * number of chunks in it;  we read in the first slab on the
	 * slab list to get the number of chunks for all slabs.  To
	 * compute the per-slab overhead, we just subtract the chunk usage
	 * from the slabsize:
	 *
	 * +------------+-------+-------+ ... --+-------+-------+-------+
	 * |////////////|	|	| ...	|	|///////|///////|
	 * |////color///| chunk	| chunk	| ...	| chunk	|/color/|/slab//|
	 * |////////////|	|	| ...	|	|///////|///////|
	 * +------------+-------+-------+ ... --+-------+-------+-------+
	 * |		\_______chunksize * chunks_____/		|
	 * \__________________________slabsize__________________________/
	 *
	 * For UMF_HASH caches, there is an additional source of overhead;
	 * the external umem_slab_t and per-chunk bufctl structures.  We
	 * include those in our per-slab overhead.
	 *
	 * Once we have a number for the per-slab overhead, we estimate
	 * the actual overhead by treating the malloc()ed buffers as if
	 * they were densely packed:
	 *
	 *	additional overhead = (# mallocs) * (per-slab) / (chunks);
	 *
	 * carefully ordering the multiply before the divide, to avoid
	 * round-off error.
	 */
	if (mi.um_malloc != 0) {
		umem_slab_t slab;
		uintptr_t saddr = (uintptr_t)c.cache_nullslab.slab_next;

		if (mdb_vread(&slab, sizeof (slab), saddr) == -1) {
			mdb_warn("unable to read slab at %p\n", saddr);
		} else {
			long chunks = slab.slab_chunks;
			if (chunks != 0 && c.cache_chunksize != 0 &&
			    chunks <= c.cache_slabsize / c.cache_chunksize) {
				uintmax_t perslab =
				    c.cache_slabsize -
				    (c.cache_chunksize * chunks);

				if (c.cache_flags & UMF_HASH) {
					perslab += sizeof (umem_slab_t) +
					    chunks *
					    ((c.cache_flags & UMF_AUDIT) ?
					    sizeof (umem_bufctl_audit_t) :
					    sizeof (umem_bufctl_t));
				}
				overhead +=
				    (perslab * (uintmax_t)mi.um_malloc)/chunks;
			} else {
				mdb_warn("invalid #chunks (%d) in slab %p\n",
				    chunks, saddr);
			}
		}
	}

	if (allocated != 0)
		overhead_pct = (1000ULL * overhead) / allocated;
	else
		overhead_pct = 0;

	mdb_printf("%0?p %6ld %6ld %8ld %8ld %10ld %10ld %3ld.%01ld%%\n",
	    addr, c.cache_bufsize, maxmalloc,
	    mi.um_malloc, avg_malloc, allocated, overhead,
	    overhead_pct / 10, overhead_pct % 10);

	if (!verbose)
		return (DCMD_OK);

	if (!dump)
		mdb_printf("\n");

	if (get_umem_alloc_sizes(&alloc_sizes, &num) == -1)
		return (DCMD_ERR);

	for (idx = 0; idx < num; idx++) {
		if (alloc_sizes[idx] == c.cache_bufsize)
			break;
		if (alloc_sizes[idx] == 0) {
			idx = num;	/* 0-terminated array */
			break;
		}
	}
	if (idx == num) {
		mdb_warn(
		    "cache %p's size (%d) not in umem_alloc_sizes\n",
		    addr, c.cache_bufsize);
		return (DCMD_ERR);
	}

	minmalloc = (idx == 0)? 0 : alloc_sizes[idx - 1];
	if (minmalloc > 0) {
#ifdef _LP64
		if (minmalloc > UMEM_SECOND_ALIGN)
			minmalloc -= sizeof (struct malloc_data);
#endif
		minmalloc -= sizeof (struct malloc_data);
		minmalloc += 1;
	}

	if (dump) {
		for (idx = minmalloc; idx <= maxmalloc; idx++)
			mdb_printf("%d\t%d\n", idx, mi.um_bucket[idx]);
		mdb_printf("\n");
	} else {
		umem_malloc_print_dist(mi.um_bucket, minmalloc, maxmalloc,
		    maxbuckets, minbucketsize, geometric);
	}

	return (DCMD_OK);
}
