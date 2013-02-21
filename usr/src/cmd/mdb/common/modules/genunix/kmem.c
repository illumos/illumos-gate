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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_whatis.h>
#include <sys/cpuvar.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <sys/machelf.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/panic.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <vm/page.h>

#include "avl.h"
#include "combined.h"
#include "dist.h"
#include "kmem.h"
#include "list.h"

#define	dprintf(x) if (mdb_debug_level) { \
	mdb_printf("kmem debug: ");  \
	/*CSTYLED*/\
	mdb_printf x ;\
}

#define	KM_ALLOCATED		0x01
#define	KM_FREE			0x02
#define	KM_BUFCTL		0x04
#define	KM_CONSTRUCTED		0x08	/* only constructed free buffers */
#define	KM_HASH			0x10

static int mdb_debug_level = 0;

/*ARGSUSED*/
static int
kmem_init_walkers(uintptr_t addr, const kmem_cache_t *c, void *ignored)
{
	mdb_walker_t w;
	char descr[64];

	(void) mdb_snprintf(descr, sizeof (descr),
	    "walk the %s cache", c->cache_name);

	w.walk_name = c->cache_name;
	w.walk_descr = descr;
	w.walk_init = kmem_walk_init;
	w.walk_step = kmem_walk_step;
	w.walk_fini = kmem_walk_fini;
	w.walk_init_arg = (void *)addr;

	if (mdb_add_walker(&w) == -1)
		mdb_warn("failed to add %s walker", c->cache_name);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
kmem_debug(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_debug_level ^= 1;

	mdb_printf("kmem: debugging is now %s\n",
	    mdb_debug_level ? "on" : "off");

	return (DCMD_OK);
}

int
kmem_cache_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name("kmem_caches", &sym) == -1) {
		mdb_warn("couldn't find kmem_caches");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)sym.st_value;

	return (list_walk_init_named(wsp, "cache list", "cache"));
}

int
kmem_cpu_cache_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("kmem_cpu_cache doesn't support global walks");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("cpu", wsp) == -1) {
		mdb_warn("couldn't walk 'cpu'");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;

	return (WALK_NEXT);
}

int
kmem_cpu_cache_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = (uintptr_t)wsp->walk_data;
	const cpu_t *cpu = wsp->walk_layer;
	kmem_cpu_cache_t cc;

	caddr += OFFSETOF(kmem_cache_t, cache_cpu[cpu->cpu_seqid]);

	if (mdb_vread(&cc, sizeof (kmem_cpu_cache_t), caddr) == -1) {
		mdb_warn("couldn't read kmem_cpu_cache at %p", caddr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(caddr, &cc, wsp->walk_cbdata));
}

static int
kmem_slab_check(void *p, uintptr_t saddr, void *arg)
{
	kmem_slab_t *sp = p;
	uintptr_t caddr = (uintptr_t)arg;
	if ((uintptr_t)sp->slab_cache != caddr) {
		mdb_warn("slab %p isn't in cache %p (in cache %p)\n",
		    saddr, caddr, sp->slab_cache);
		return (-1);
	}

	return (0);
}

static int
kmem_partial_slab_check(void *p, uintptr_t saddr, void *arg)
{
	kmem_slab_t *sp = p;

	int rc = kmem_slab_check(p, saddr, arg);
	if (rc != 0) {
		return (rc);
	}

	if (!KMEM_SLAB_IS_PARTIAL(sp)) {
		mdb_warn("slab %p is not a partial slab\n", saddr);
		return (-1);
	}

	return (0);
}

static int
kmem_complete_slab_check(void *p, uintptr_t saddr, void *arg)
{
	kmem_slab_t *sp = p;

	int rc = kmem_slab_check(p, saddr, arg);
	if (rc != 0) {
		return (rc);
	}

	if (!KMEM_SLAB_IS_ALL_USED(sp)) {
		mdb_warn("slab %p is not completely allocated\n", saddr);
		return (-1);
	}

	return (0);
}

typedef struct {
	uintptr_t kns_cache_addr;
	int kns_nslabs;
} kmem_nth_slab_t;

static int
kmem_nth_slab_check(void *p, uintptr_t saddr, void *arg)
{
	kmem_nth_slab_t *chkp = arg;

	int rc = kmem_slab_check(p, saddr, (void *)chkp->kns_cache_addr);
	if (rc != 0) {
		return (rc);
	}

	return (chkp->kns_nslabs-- == 0 ? 1 : 0);
}

static int
kmem_complete_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;

	wsp->walk_addr = (uintptr_t)(caddr +
	    offsetof(kmem_cache_t, cache_complete_slabs));

	return (list_walk_init_checked(wsp, "slab list", "slab",
	    kmem_complete_slab_check, (void *)caddr));
}

static int
kmem_partial_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;

	wsp->walk_addr = (uintptr_t)(caddr +
	    offsetof(kmem_cache_t, cache_partial_slabs));

	return (avl_walk_init_checked(wsp, "slab list", "slab",
	    kmem_partial_slab_check, (void *)caddr));
}

int
kmem_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;

	if (caddr == NULL) {
		mdb_warn("kmem_slab doesn't support global walks\n");
		return (WALK_ERR);
	}

	combined_walk_init(wsp);
	combined_walk_add(wsp,
	    kmem_complete_slab_walk_init, list_walk_step, list_walk_fini);
	combined_walk_add(wsp,
	    kmem_partial_slab_walk_init, avl_walk_step, avl_walk_fini);

	return (WALK_NEXT);
}

static int
kmem_first_complete_slab_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;
	kmem_nth_slab_t *chk;

	chk = mdb_alloc(sizeof (kmem_nth_slab_t),
	    UM_SLEEP | UM_GC);
	chk->kns_cache_addr = caddr;
	chk->kns_nslabs = 1;
	wsp->walk_addr = (uintptr_t)(caddr +
	    offsetof(kmem_cache_t, cache_complete_slabs));

	return (list_walk_init_checked(wsp, "slab list", "slab",
	    kmem_nth_slab_check, chk));
}

int
kmem_slab_walk_partial_init(mdb_walk_state_t *wsp)
{
	uintptr_t caddr = wsp->walk_addr;
	kmem_cache_t c;

	if (caddr == NULL) {
		mdb_warn("kmem_slab_partial doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&c, sizeof (c), caddr) == -1) {
		mdb_warn("couldn't read kmem_cache at %p", caddr);
		return (WALK_ERR);
	}

	combined_walk_init(wsp);

	/*
	 * Some consumers (umem_walk_step(), in particular) require at
	 * least one callback if there are any buffers in the cache.  So
	 * if there are *no* partial slabs, report the first full slab, if
	 * any.
	 *
	 * Yes, this is ugly, but it's cleaner than the other possibilities.
	 */
	if (c.cache_partial_slabs.avl_numnodes == 0) {
		combined_walk_add(wsp, kmem_first_complete_slab_walk_init,
		    list_walk_step, list_walk_fini);
	} else {
		combined_walk_add(wsp, kmem_partial_slab_walk_init,
		    avl_walk_step, avl_walk_fini);
	}

	return (WALK_NEXT);
}

int
kmem_cache(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *argv)
{
	kmem_cache_t c;
	const char *filter = NULL;

	if (mdb_getopts(ac, argv,
	    'n', MDB_OPT_STR, &filter,
	    NULL) != ac) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("kmem_cache", "kmem_cache", ac, argv) == -1) {
			mdb_warn("can't walk kmem_cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-?s %-25s %4s %6s %8s %8s\n", "ADDR", "NAME",
		    "FLAG", "CFLAG", "BUFSIZE", "BUFTOTL");

	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read kmem_cache at %p", addr);
		return (DCMD_ERR);
	}

	if ((filter != NULL) && (strstr(c.cache_name, filter) == NULL))
		return (DCMD_OK);

	mdb_printf("%0?p %-25s %04x %06x %8ld %8lld\n", addr, c.cache_name,
	    c.cache_flags, c.cache_cflags, c.cache_bufsize, c.cache_buftotal);

	return (DCMD_OK);
}

void
kmem_cache_help(void)
{
	mdb_printf("%s", "Print kernel memory caches.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -n name\n"
"        name of kmem cache (or matching partial name)\n"
"\n"
"Column\tDescription\n"
"\n"
"ADDR\t\taddress of kmem cache\n"
"NAME\t\tname of kmem cache\n"
"FLAG\t\tvarious cache state flags\n"
"CFLAG\t\tcache creation flags\n"
"BUFSIZE\tobject size in bytes\n"
"BUFTOTL\tcurrent total buffers in cache (allocated and free)\n");
}

#define	LABEL_WIDTH	11
static void
kmem_slabs_print_dist(uint_t *ks_bucket, size_t buffers_per_slab,
    size_t maxbuckets, size_t minbucketsize)
{
	uint64_t total;
	int buckets;
	int i;
	const int *distarray;
	int complete[2];

	buckets = buffers_per_slab;

	total = 0;
	for (i = 0; i <= buffers_per_slab; i++)
		total += ks_bucket[i];

	if (maxbuckets > 1)
		buckets = MIN(buckets, maxbuckets);

	if (minbucketsize > 1) {
		/*
		 * minbucketsize does not apply to the first bucket reserved
		 * for completely allocated slabs
		 */
		buckets = MIN(buckets, 1 + ((buffers_per_slab - 1) /
		    minbucketsize));
		if ((buckets < 2) && (buffers_per_slab > 1)) {
			buckets = 2;
			minbucketsize = (buffers_per_slab - 1);
		}
	}

	/*
	 * The first printed bucket is reserved for completely allocated slabs.
	 * Passing (buckets - 1) excludes that bucket from the generated
	 * distribution, since we're handling it as a special case.
	 */
	complete[0] = buffers_per_slab;
	complete[1] = buffers_per_slab + 1;
	distarray = dist_linear(buckets - 1, 1, buffers_per_slab - 1);

	mdb_printf("%*s\n", LABEL_WIDTH, "Allocated");
	dist_print_header("Buffers", LABEL_WIDTH, "Slabs");

	dist_print_bucket(complete, 0, ks_bucket, total, LABEL_WIDTH);
	/*
	 * Print bucket ranges in descending order after the first bucket for
	 * completely allocated slabs, so a person can see immediately whether
	 * or not there is fragmentation without having to scan possibly
	 * multiple screens of output. Starting at (buckets - 2) excludes the
	 * extra terminating bucket.
	 */
	for (i = buckets - 2; i >= 0; i--) {
		dist_print_bucket(distarray, i, ks_bucket, total, LABEL_WIDTH);
	}
	mdb_printf("\n");
}
#undef LABEL_WIDTH

/*ARGSUSED*/
static int
kmem_first_slab(uintptr_t addr, const kmem_slab_t *sp, boolean_t *is_slab)
{
	*is_slab = B_TRUE;
	return (WALK_DONE);
}

/*ARGSUSED*/
static int
kmem_first_partial_slab(uintptr_t addr, const kmem_slab_t *sp,
    boolean_t *is_slab)
{
	/*
	 * The "kmem_partial_slab" walker reports the first full slab if there
	 * are no partial slabs (for the sake of consumers that require at least
	 * one callback if there are any buffers in the cache).
	 */
	*is_slab = KMEM_SLAB_IS_PARTIAL(sp);
	return (WALK_DONE);
}

typedef struct kmem_slab_usage {
	int ksu_refcnt;			/* count of allocated buffers on slab */
	boolean_t ksu_nomove;		/* slab marked non-reclaimable */
} kmem_slab_usage_t;

typedef struct kmem_slab_stats {
	const kmem_cache_t *ks_cp;
	int ks_slabs;			/* slabs in cache */
	int ks_partial_slabs;		/* partially allocated slabs in cache */
	uint64_t ks_unused_buffers;	/* total unused buffers in cache */
	int ks_max_buffers_per_slab;	/* max buffers per slab */
	int ks_usage_len;		/* ks_usage array length */
	kmem_slab_usage_t *ks_usage;	/* partial slab usage */
	uint_t *ks_bucket;		/* slab usage distribution */
} kmem_slab_stats_t;

/*ARGSUSED*/
static int
kmem_slablist_stat(uintptr_t addr, const kmem_slab_t *sp,
    kmem_slab_stats_t *ks)
{
	kmem_slab_usage_t *ksu;
	long unused;

	ks->ks_slabs++;
	ks->ks_bucket[sp->slab_refcnt]++;

	unused = (sp->slab_chunks - sp->slab_refcnt);
	if (unused == 0) {
		return (WALK_NEXT);
	}

	ks->ks_partial_slabs++;
	ks->ks_unused_buffers += unused;

	if (ks->ks_partial_slabs > ks->ks_usage_len) {
		kmem_slab_usage_t *usage;
		int len = ks->ks_usage_len;

		len = (len == 0 ? 16 : len * 2);
		usage = mdb_zalloc(len * sizeof (kmem_slab_usage_t), UM_SLEEP);
		if (ks->ks_usage != NULL) {
			bcopy(ks->ks_usage, usage,
			    ks->ks_usage_len * sizeof (kmem_slab_usage_t));
			mdb_free(ks->ks_usage,
			    ks->ks_usage_len * sizeof (kmem_slab_usage_t));
		}
		ks->ks_usage = usage;
		ks->ks_usage_len = len;
	}

	ksu = &ks->ks_usage[ks->ks_partial_slabs - 1];
	ksu->ksu_refcnt = sp->slab_refcnt;
	ksu->ksu_nomove = (sp->slab_flags & KMEM_SLAB_NOMOVE);
	return (WALK_NEXT);
}

static void
kmem_slabs_header()
{
	mdb_printf("%-25s %8s %8s %9s %9s %6s\n",
	    "", "", "Partial", "", "Unused", "");
	mdb_printf("%-25s %8s %8s %9s %9s %6s\n",
	    "Cache Name", "Slabs", "Slabs", "Buffers", "Buffers", "Waste");
	mdb_printf("%-25s %8s %8s %9s %9s %6s\n",
	    "-------------------------", "--------", "--------", "---------",
	    "---------", "------");
}

int
kmem_slabs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kmem_cache_t c;
	kmem_slab_stats_t stats;
	mdb_walk_cb_t cb;
	int pct;
	int tenths_pct;
	size_t maxbuckets = 1;
	size_t minbucketsize = 0;
	const char *filter = NULL;
	const char *name = NULL;
	uint_t opt_v = FALSE;
	boolean_t buckets = B_FALSE;
	boolean_t skip = B_FALSE;

	if (mdb_getopts(argc, argv,
	    'B', MDB_OPT_UINTPTR, &minbucketsize,
	    'b', MDB_OPT_UINTPTR, &maxbuckets,
	    'n', MDB_OPT_STR, &filter,
	    'N', MDB_OPT_STR, &name,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if ((maxbuckets != 1) || (minbucketsize != 0)) {
		buckets = B_TRUE;
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("kmem_cache", "kmem_slabs", argc,
		    argv) == -1) {
			mdb_warn("can't walk kmem_cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read kmem_cache at %p", addr);
		return (DCMD_ERR);
	}

	if (name == NULL) {
		skip = ((filter != NULL) &&
		    (strstr(c.cache_name, filter) == NULL));
	} else if (filter == NULL) {
		skip = (strcmp(c.cache_name, name) != 0);
	} else {
		/* match either -n or -N */
		skip = ((strcmp(c.cache_name, name) != 0) &&
		    (strstr(c.cache_name, filter) == NULL));
	}

	if (!(opt_v || buckets) && DCMD_HDRSPEC(flags)) {
		kmem_slabs_header();
	} else if ((opt_v || buckets) && !skip) {
		if (DCMD_HDRSPEC(flags)) {
			kmem_slabs_header();
		} else {
			boolean_t is_slab = B_FALSE;
			const char *walker_name;
			if (opt_v) {
				cb = (mdb_walk_cb_t)kmem_first_partial_slab;
				walker_name = "kmem_slab_partial";
			} else {
				cb = (mdb_walk_cb_t)kmem_first_slab;
				walker_name = "kmem_slab";
			}
			(void) mdb_pwalk(walker_name, cb, &is_slab, addr);
			if (is_slab) {
				kmem_slabs_header();
			}
		}
	}

	if (skip) {
		return (DCMD_OK);
	}

	bzero(&stats, sizeof (kmem_slab_stats_t));
	stats.ks_cp = &c;
	stats.ks_max_buffers_per_slab = c.cache_maxchunks;
	/* +1 to include a zero bucket */
	stats.ks_bucket = mdb_zalloc((stats.ks_max_buffers_per_slab + 1) *
	    sizeof (*stats.ks_bucket), UM_SLEEP);
	cb = (mdb_walk_cb_t)kmem_slablist_stat;
	(void) mdb_pwalk("kmem_slab", cb, &stats, addr);

	if (c.cache_buftotal == 0) {
		pct = 0;
		tenths_pct = 0;
	} else {
		uint64_t n = stats.ks_unused_buffers * 10000;
		pct = (int)(n / c.cache_buftotal);
		tenths_pct = pct - ((pct / 100) * 100);
		tenths_pct = (tenths_pct + 5) / 10; /* round nearest tenth */
		if (tenths_pct == 10) {
			pct += 100;
			tenths_pct = 0;
		}
	}

	pct /= 100;
	mdb_printf("%-25s %8d %8d %9lld %9lld %3d.%1d%%\n", c.cache_name,
	    stats.ks_slabs, stats.ks_partial_slabs, c.cache_buftotal,
	    stats.ks_unused_buffers, pct, tenths_pct);

	if (maxbuckets == 0) {
		maxbuckets = stats.ks_max_buffers_per_slab;
	}

	if (((maxbuckets > 1) || (minbucketsize > 0)) &&
	    (stats.ks_slabs > 0)) {
		mdb_printf("\n");
		kmem_slabs_print_dist(stats.ks_bucket,
		    stats.ks_max_buffers_per_slab, maxbuckets, minbucketsize);
	}

	mdb_free(stats.ks_bucket, (stats.ks_max_buffers_per_slab + 1) *
	    sizeof (*stats.ks_bucket));

	if (!opt_v) {
		return (DCMD_OK);
	}

	if (opt_v && (stats.ks_partial_slabs > 0)) {
		int i;
		kmem_slab_usage_t *ksu;

		mdb_printf("  %d complete (%d), %d partial:",
		    (stats.ks_slabs - stats.ks_partial_slabs),
		    stats.ks_max_buffers_per_slab,
		    stats.ks_partial_slabs);

		for (i = 0; i < stats.ks_partial_slabs; i++) {
			ksu = &stats.ks_usage[i];
			mdb_printf(" %d%s", ksu->ksu_refcnt,
			    (ksu->ksu_nomove ? "*" : ""));
		}
		mdb_printf("\n\n");
	}

	if (stats.ks_usage_len > 0) {
		mdb_free(stats.ks_usage,
		    stats.ks_usage_len * sizeof (kmem_slab_usage_t));
	}

	return (DCMD_OK);
}

void
kmem_slabs_help(void)
{
	mdb_printf("%s",
"Display slab usage per kmem cache.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -n name\n"
"        name of kmem cache (or matching partial name)\n"
"  -N name\n"
"        exact name of kmem cache\n"
"  -b maxbins\n"
"        Print a distribution of allocated buffers per slab using at\n"
"        most maxbins bins. The first bin is reserved for completely\n"
"        allocated slabs. Setting maxbins to zero (-b 0) has the same\n"
"        effect as specifying the maximum allocated buffers per slab\n"
"        or setting minbinsize to 1 (-B 1).\n"
"  -B minbinsize\n"
"        Print a distribution of allocated buffers per slab, making\n"
"        all bins (except the first, reserved for completely allocated\n"
"        slabs) at least minbinsize buffers apart.\n"
"  -v    verbose output: List the allocated buffer count of each partial\n"
"        slab on the free list in order from front to back to show how\n"
"        closely the slabs are ordered by usage. For example\n"
"\n"
"          10 complete, 3 partial (8): 7 3 1\n"
"\n"
"        means there are thirteen slabs with eight buffers each, including\n"
"        three partially allocated slabs with less than all eight buffers\n"
"        allocated.\n"
"\n"
"        Buffer allocations are always from the front of the partial slab\n"
"        list. When a buffer is freed from a completely used slab, that\n"
"        slab is added to the front of the partial slab list. Assuming\n"
"        that all buffers are equally likely to be freed soon, the\n"
"        desired order of partial slabs is most-used at the front of the\n"
"        list and least-used at the back (as in the example above).\n"
"        However, if a slab contains an allocated buffer that will not\n"
"        soon be freed, it would be better for that slab to be at the\n"
"        front where all of its buffers can be allocated. Taking a slab\n"
"        off the partial slab list (either with all buffers freed or all\n"
"        buffers allocated) reduces cache fragmentation.\n"
"\n"
"        A slab's allocated buffer count representing a partial slab (9 in\n"
"        the example below) may be marked as follows:\n"
"\n"
"        9*   An asterisk indicates that kmem has marked the slab non-\n"
"        reclaimable because the kmem client refused to move one of the\n"
"        slab's buffers. Since kmem does not expect to completely free the\n"
"        slab, it moves it to the front of the list in the hope of\n"
"        completely allocating it instead. A slab marked with an asterisk\n"
"        stays marked for as long as it remains on the partial slab list.\n"
"\n"
"Column\t\tDescription\n"
"\n"
"Cache Name\t\tname of kmem cache\n"
"Slabs\t\t\ttotal slab count\n"
"Partial Slabs\t\tcount of partially allocated slabs on the free list\n"
"Buffers\t\ttotal buffer count (Slabs * (buffers per slab))\n"
"Unused Buffers\tcount of unallocated buffers across all partial slabs\n"
"Waste\t\t\t(Unused Buffers / Buffers) does not include space\n"
"\t\t\t  for accounting structures (debug mode), slab\n"
"\t\t\t  coloring (incremental small offsets to stagger\n"
"\t\t\t  buffer alignment), or the per-CPU magazine layer\n");
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
bufctlcmp(const kmem_bufctl_audit_t **lhs, const kmem_bufctl_audit_t **rhs)
{
	const kmem_bufctl_audit_t *bcp1 = *lhs;
	const kmem_bufctl_audit_t *bcp2 = *rhs;

	if (bcp1->bc_timestamp > bcp2->bc_timestamp)
		return (-1);

	if (bcp1->bc_timestamp < bcp2->bc_timestamp)
		return (1);

	return (0);
}

typedef struct kmem_hash_walk {
	uintptr_t *kmhw_table;
	size_t kmhw_nelems;
	size_t kmhw_pos;
	kmem_bufctl_t kmhw_cur;
} kmem_hash_walk_t;

int
kmem_hash_walk_init(mdb_walk_state_t *wsp)
{
	kmem_hash_walk_t *kmhw;
	uintptr_t *hash;
	kmem_cache_t c;
	uintptr_t haddr, addr = wsp->walk_addr;
	size_t nelems;
	size_t hsize;

	if (addr == NULL) {
		mdb_warn("kmem_hash doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read cache at addr %p", addr);
		return (WALK_ERR);
	}

	if (!(c.cache_flags & KMF_HASH)) {
		mdb_warn("cache %p doesn't have a hash table\n", addr);
		return (WALK_DONE);		/* nothing to do */
	}

	kmhw = mdb_zalloc(sizeof (kmem_hash_walk_t), UM_SLEEP);
	kmhw->kmhw_cur.bc_next = NULL;
	kmhw->kmhw_pos = 0;

	kmhw->kmhw_nelems = nelems = c.cache_hash_mask + 1;
	hsize = nelems * sizeof (uintptr_t);
	haddr = (uintptr_t)c.cache_hash_table;

	kmhw->kmhw_table = hash = mdb_alloc(hsize, UM_SLEEP);
	if (mdb_vread(hash, hsize, haddr) == -1) {
		mdb_warn("failed to read hash table at %p", haddr);
		mdb_free(hash, hsize);
		mdb_free(kmhw, sizeof (kmem_hash_walk_t));
		return (WALK_ERR);
	}

	wsp->walk_data = kmhw;

	return (WALK_NEXT);
}

int
kmem_hash_walk_step(mdb_walk_state_t *wsp)
{
	kmem_hash_walk_t *kmhw = wsp->walk_data;
	uintptr_t addr = NULL;

	if ((addr = (uintptr_t)kmhw->kmhw_cur.bc_next) == NULL) {
		while (kmhw->kmhw_pos < kmhw->kmhw_nelems) {
			if ((addr = kmhw->kmhw_table[kmhw->kmhw_pos++]) != NULL)
				break;
		}
	}
	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&kmhw->kmhw_cur, sizeof (kmem_bufctl_t), addr) == -1) {
		mdb_warn("couldn't read kmem_bufctl_t at addr %p", addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(addr, &kmhw->kmhw_cur, wsp->walk_cbdata));
}

void
kmem_hash_walk_fini(mdb_walk_state_t *wsp)
{
	kmem_hash_walk_t *kmhw = wsp->walk_data;

	if (kmhw == NULL)
		return;

	mdb_free(kmhw->kmhw_table, kmhw->kmhw_nelems * sizeof (uintptr_t));
	mdb_free(kmhw, sizeof (kmem_hash_walk_t));
}

/*
 * Find the address of the bufctl structure for the address 'buf' in cache
 * 'cp', which is at address caddr, and place it in *out.
 */
static int
kmem_hash_lookup(kmem_cache_t *cp, uintptr_t caddr, void *buf, uintptr_t *out)
{
	uintptr_t bucket = (uintptr_t)KMEM_HASH(cp, buf);
	kmem_bufctl_t *bcp;
	kmem_bufctl_t bc;

	if (mdb_vread(&bcp, sizeof (kmem_bufctl_t *), bucket) == -1) {
		mdb_warn("unable to read hash bucket for %p in cache %p",
		    buf, caddr);
		return (-1);
	}

	while (bcp != NULL) {
		if (mdb_vread(&bc, sizeof (kmem_bufctl_t),
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
kmem_get_magsize(const kmem_cache_t *cp)
{
	uintptr_t addr = (uintptr_t)cp->cache_magtype;
	GElf_Sym mt_sym;
	kmem_magtype_t mt;
	int res;

	/*
	 * if cpu 0 has a non-zero magsize, it must be correct.  caches
	 * with KMF_NOMAGAZINE have disabled their magazine layers, so
	 * it is okay to return 0 for them.
	 */
	if ((res = cp->cache_cpu[0].cc_magsize) != 0 ||
	    (cp->cache_flags & KMF_NOMAGAZINE))
		return (res);

	if (mdb_lookup_by_name("kmem_magtype", &mt_sym) == -1) {
		mdb_warn("unable to read 'kmem_magtype'");
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
kmem_estimate_slab(uintptr_t addr, const kmem_slab_t *sp, size_t *est)
{
	*est -= (sp->slab_chunks - sp->slab_refcnt);

	return (WALK_NEXT);
}

/*
 * Returns an upper bound on the number of allocated buffers in a given
 * cache.
 */
size_t
kmem_estimate_allocated(uintptr_t addr, const kmem_cache_t *cp)
{
	int magsize;
	size_t cache_est;

	cache_est = cp->cache_buftotal;

	(void) mdb_pwalk("kmem_slab_partial",
	    (mdb_walk_cb_t)kmem_estimate_slab, &cache_est, addr);

	if ((magsize = kmem_get_magsize(cp)) != 0) {
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
	if (mdb_vread(mp, magbsize, (uintptr_t)kmp) == -1) { \
		mdb_warn("couldn't read magazine at %p", kmp); \
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

int
kmem_read_magazines(kmem_cache_t *cp, uintptr_t addr, int ncpus,
    void ***maglistp, size_t *magcntp, size_t *magmaxp, int alloc_flags)
{
	kmem_magazine_t *kmp, *mp;
	void **maglist = NULL;
	int i, cpu;
	size_t magsize, magmax, magbsize;
	size_t magcnt = 0;

	/*
	 * Read the magtype out of the cache, after verifying the pointer's
	 * correctness.
	 */
	magsize = kmem_get_magsize(cp);
	if (magsize == 0) {
		*maglistp = NULL;
		*magcntp = 0;
		*magmaxp = 0;
		return (WALK_NEXT);
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
	magmax = (cp->cache_full.ml_total + 2 * ncpus + 100) * magsize;
	magbsize = offsetof(kmem_magazine_t, mag_round[magsize]);

	if (magbsize >= PAGESIZE / 2) {
		mdb_warn("magazine size for cache %p unreasonable (%x)\n",
		    addr, magbsize);
		return (WALK_ERR);
	}

	maglist = mdb_alloc(magmax * sizeof (void *), alloc_flags);
	mp = mdb_alloc(magbsize, alloc_flags);
	if (mp == NULL || maglist == NULL)
		goto fail;

	/*
	 * First up: the magazines in the depot (i.e. on the cache_full list).
	 */
	for (kmp = cp->cache_full.ml_list; kmp != NULL; ) {
		READMAG_ROUNDS(magsize);
		kmp = mp->mag_next;

		if (kmp == cp->cache_full.ml_list)
			break; /* cache_full list loop detected */
	}

	dprintf(("cache_full list done\n"));

	/*
	 * Now whip through the CPUs, snagging the loaded magazines
	 * and full spares.
	 *
	 * In order to prevent inconsistent dumps, rounds and prounds
	 * are copied aside before dumping begins.
	 */
	for (cpu = 0; cpu < ncpus; cpu++) {
		kmem_cpu_cache_t *ccp = &cp->cache_cpu[cpu];
		short rounds, prounds;

		if (KMEM_DUMPCC(ccp)) {
			rounds = ccp->cc_dump_rounds;
			prounds = ccp->cc_dump_prounds;
		} else {
			rounds = ccp->cc_rounds;
			prounds = ccp->cc_prounds;
		}

		dprintf(("reading cpu cache %p\n",
		    (uintptr_t)ccp - (uintptr_t)cp + addr));

		if (rounds > 0 &&
		    (kmp = ccp->cc_loaded) != NULL) {
			dprintf(("reading %d loaded rounds\n", rounds));
			READMAG_ROUNDS(rounds);
		}

		if (prounds > 0 &&
		    (kmp = ccp->cc_ploaded) != NULL) {
			dprintf(("reading %d previously loaded rounds\n",
			    prounds));
			READMAG_ROUNDS(prounds);
		}
	}

	dprintf(("magazine layer: %d buffers\n", magcnt));

	if (!(alloc_flags & UM_GC))
		mdb_free(mp, magbsize);

	*maglistp = maglist;
	*magcntp = magcnt;
	*magmaxp = magmax;

	return (WALK_NEXT);

fail:
	if (!(alloc_flags & UM_GC)) {
		if (mp)
			mdb_free(mp, magbsize);
		if (maglist)
			mdb_free(maglist, magmax * sizeof (void *));
	}
	return (WALK_ERR);
}

static int
kmem_walk_callback(mdb_walk_state_t *wsp, uintptr_t buf)
{
	return (wsp->walk_callback(buf, NULL, wsp->walk_cbdata));
}

static int
bufctl_walk_callback(kmem_cache_t *cp, mdb_walk_state_t *wsp, uintptr_t buf)
{
	kmem_bufctl_audit_t b;

	/*
	 * if KMF_AUDIT is not set, we know that we're looking at a
	 * kmem_bufctl_t.
	 */
	if (!(cp->cache_flags & KMF_AUDIT) ||
	    mdb_vread(&b, sizeof (kmem_bufctl_audit_t), buf) == -1) {
		(void) memset(&b, 0, sizeof (b));
		if (mdb_vread(&b, sizeof (kmem_bufctl_t), buf) == -1) {
			mdb_warn("unable to read bufctl at %p", buf);
			return (WALK_ERR);
		}
	}

	return (wsp->walk_callback(buf, &b, wsp->walk_cbdata));
}

typedef struct kmem_walk {
	int kmw_type;

	uintptr_t kmw_addr;		/* cache address */
	kmem_cache_t *kmw_cp;
	size_t kmw_csize;

	/*
	 * magazine layer
	 */
	void **kmw_maglist;
	size_t kmw_max;
	size_t kmw_count;
	size_t kmw_pos;

	/*
	 * slab layer
	 */
	char *kmw_valid;	/* to keep track of freed buffers */
	char *kmw_ubase;	/* buffer for slab data */
} kmem_walk_t;

static int
kmem_walk_init_common(mdb_walk_state_t *wsp, int type)
{
	kmem_walk_t *kmw;
	int ncpus, csize;
	kmem_cache_t *cp;
	size_t vm_quantum;

	size_t magmax, magcnt;
	void **maglist = NULL;
	uint_t chunksize, slabsize;
	int status = WALK_ERR;
	uintptr_t addr = wsp->walk_addr;
	const char *layered;

	type &= ~KM_HASH;

	if (addr == NULL) {
		mdb_warn("kmem walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	dprintf(("walking %p\n", addr));

	/*
	 * First we need to figure out how many CPUs are configured in the
	 * system to know how much to slurp out.
	 */
	mdb_readvar(&ncpus, "max_ncpus");

	csize = KMEM_CACHE_SIZE(ncpus);
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
		mdb_warn("%p is not a valid kmem_cache_t\n", addr);
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
	if ((type & KM_BUFCTL) && !(cp->cache_flags & KMF_HASH)) {
		dprintf(("bufctl requested, not KMF_HASH (flags: %p)\n",
		    cp->cache_flags));
		mdb_free(cp, csize);
		return (WALK_DONE);
	}

	/*
	 * If they want constructed buffers, but there's no constructor or
	 * the cache has DEADBEEF checking enabled, there is nothing to report.
	 */
	if ((type & KM_CONSTRUCTED) && (!(type & KM_FREE) ||
	    cp->cache_constructor == NULL ||
	    (cp->cache_flags & (KMF_DEADBEEF | KMF_LITE)) == KMF_DEADBEEF)) {
		mdb_free(cp, csize);
		return (WALK_DONE);
	}

	/*
	 * Read in the contents of the magazine layer
	 */
	if (kmem_read_magazines(cp, addr, ncpus, &maglist, &magcnt,
	    &magmax, UM_SLEEP) == WALK_ERR)
		goto out2;

	/*
	 * We have all of the buffers from the magazines;  if we are walking
	 * allocated buffers, sort them so we can bsearch them later.
	 */
	if (type & KM_ALLOCATED)
		qsort(maglist, magcnt, sizeof (void *), addrcmp);

	wsp->walk_data = kmw = mdb_zalloc(sizeof (kmem_walk_t), UM_SLEEP);

	kmw->kmw_type = type;
	kmw->kmw_addr = addr;
	kmw->kmw_cp = cp;
	kmw->kmw_csize = csize;
	kmw->kmw_maglist = maglist;
	kmw->kmw_max = magmax;
	kmw->kmw_count = magcnt;
	kmw->kmw_pos = 0;

	/*
	 * When walking allocated buffers in a KMF_HASH cache, we walk the
	 * hash table instead of the slab layer.
	 */
	if ((cp->cache_flags & KMF_HASH) && (type & KM_ALLOCATED)) {
		layered = "kmem_hash";

		kmw->kmw_type |= KM_HASH;
	} else {
		/*
		 * If we are walking freed buffers, we only need the
		 * magazine layer plus the partially allocated slabs.
		 * To walk allocated buffers, we need all of the slabs.
		 */
		if (type & KM_ALLOCATED)
			layered = "kmem_slab";
		else
			layered = "kmem_slab_partial";

		/*
		 * for small-slab caches, we read in the entire slab.  For
		 * freed buffers, we can just walk the freelist.  For
		 * allocated buffers, we use a 'valid' array to track
		 * the freed buffers.
		 */
		if (!(cp->cache_flags & KMF_HASH)) {
			chunksize = cp->cache_chunksize;
			slabsize = cp->cache_slabsize;

			kmw->kmw_ubase = mdb_alloc(slabsize +
			    sizeof (kmem_bufctl_t), UM_SLEEP);

			if (type & KM_ALLOCATED)
				kmw->kmw_valid =
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
		if (kmw->kmw_valid)
			mdb_free(kmw->kmw_valid, slabsize / chunksize);

		if (kmw->kmw_ubase)
			mdb_free(kmw->kmw_ubase, slabsize +
			    sizeof (kmem_bufctl_t));

		if (kmw->kmw_maglist)
			mdb_free(kmw->kmw_maglist,
			    kmw->kmw_max * sizeof (uintptr_t));

		mdb_free(kmw, sizeof (kmem_walk_t));
		wsp->walk_data = NULL;
	}

out2:
	if (status == WALK_ERR)
		mdb_free(cp, csize);

	return (status);
}

int
kmem_walk_step(mdb_walk_state_t *wsp)
{
	kmem_walk_t *kmw = wsp->walk_data;
	int type = kmw->kmw_type;
	kmem_cache_t *cp = kmw->kmw_cp;

	void **maglist = kmw->kmw_maglist;
	int magcnt = kmw->kmw_count;

	uintptr_t chunksize, slabsize;
	uintptr_t addr;
	const kmem_slab_t *sp;
	const kmem_bufctl_t *bcp;
	kmem_bufctl_t bc;

	int chunks;
	char *kbase;
	void *buf;
	int i, ret;

	char *valid, *ubase;

	/*
	 * first, handle the 'kmem_hash' layered walk case
	 */
	if (type & KM_HASH) {
		/*
		 * We have a buffer which has been allocated out of the
		 * global layer. We need to make sure that it's not
		 * actually sitting in a magazine before we report it as
		 * an allocated buffer.
		 */
		buf = ((const kmem_bufctl_t *)wsp->walk_layer)->bc_addr;

		if (magcnt > 0 &&
		    bsearch(&buf, maglist, magcnt, sizeof (void *),
		    addrcmp) != NULL)
			return (WALK_NEXT);

		if (type & KM_BUFCTL)
			return (bufctl_walk_callback(cp, wsp, wsp->walk_addr));

		return (kmem_walk_callback(wsp, (uintptr_t)buf));
	}

	ret = WALK_NEXT;

	addr = kmw->kmw_addr;

	/*
	 * If we're walking freed buffers, report everything in the
	 * magazine layer before processing the first slab.
	 */
	if ((type & KM_FREE) && magcnt != 0) {
		kmw->kmw_count = 0;		/* only do this once */
		for (i = 0; i < magcnt; i++) {
			buf = maglist[i];

			if (type & KM_BUFCTL) {
				uintptr_t out;

				if (cp->cache_flags & KMF_BUFTAG) {
					kmem_buftag_t *btp;
					kmem_buftag_t tag;

					/* LINTED - alignment */
					btp = KMEM_BUFTAG(cp, buf);
					if (mdb_vread(&tag, sizeof (tag),
					    (uintptr_t)btp) == -1) {
						mdb_warn("reading buftag for "
						    "%p at %p", buf, btp);
						continue;
					}
					out = (uintptr_t)tag.bt_bufctl;
				} else {
					if (kmem_hash_lookup(cp, addr, buf,
					    &out) == -1)
						continue;
				}
				ret = bufctl_walk_callback(cp, wsp, out);
			} else {
				ret = kmem_walk_callback(wsp, (uintptr_t)buf);
			}

			if (ret != WALK_NEXT)
				return (ret);
		}
	}

	/*
	 * If they want constructed buffers, we're finished, since the
	 * magazine layer holds them all.
	 */
	if (type & KM_CONSTRUCTED)
		return (WALK_DONE);

	/*
	 * Handle the buffers in the current slab
	 */
	chunksize = cp->cache_chunksize;
	slabsize = cp->cache_slabsize;

	sp = wsp->walk_layer;
	chunks = sp->slab_chunks;
	kbase = sp->slab_base;

	dprintf(("kbase is %p\n", kbase));

	if (!(cp->cache_flags & KMF_HASH)) {
		valid = kmw->kmw_valid;
		ubase = kmw->kmw_ubase;

		if (mdb_vread(ubase, chunks * chunksize,
		    (uintptr_t)kbase) == -1) {
			mdb_warn("failed to read slab contents at %p", kbase);
			return (WALK_ERR);
		}

		/*
		 * Set up the valid map as fully allocated -- we'll punch
		 * out the freelist.
		 */
		if (type & KM_ALLOCATED)
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

		if (cp->cache_flags & KMF_HASH) {
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

			bc = *((kmem_bufctl_t *)((uintptr_t)ubase + offs));
			buf = KMEM_BUF(cp, bcp);
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
		} else if (type & KM_ALLOCATED) {
			/*
			 * we have found a buffer on the slab's freelist;
			 * clear its entry
			 */
			valid[ndx] = 0;
		} else {
			/*
			 * Report this freed buffer
			 */
			if (type & KM_BUFCTL) {
				ret = bufctl_walk_callback(cp, wsp,
				    (uintptr_t)bcp);
			} else {
				ret = kmem_walk_callback(wsp, (uintptr_t)buf);
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
	if (type & KM_FREE)
		return (WALK_NEXT);

	if (type & KM_BUFCTL) {
		mdb_warn("impossible situation: small-slab KM_BUFCTL walk for "
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

		ret = kmem_walk_callback(wsp, (uintptr_t)buf);
	}
	return (ret);
}

void
kmem_walk_fini(mdb_walk_state_t *wsp)
{
	kmem_walk_t *kmw = wsp->walk_data;
	uintptr_t chunksize;
	uintptr_t slabsize;

	if (kmw == NULL)
		return;

	if (kmw->kmw_maglist != NULL)
		mdb_free(kmw->kmw_maglist, kmw->kmw_max * sizeof (void *));

	chunksize = kmw->kmw_cp->cache_chunksize;
	slabsize = kmw->kmw_cp->cache_slabsize;

	if (kmw->kmw_valid != NULL)
		mdb_free(kmw->kmw_valid, slabsize / chunksize);
	if (kmw->kmw_ubase != NULL)
		mdb_free(kmw->kmw_ubase, slabsize + sizeof (kmem_bufctl_t));

	mdb_free(kmw->kmw_cp, kmw->kmw_csize);
	mdb_free(kmw, sizeof (kmem_walk_t));
}

/*ARGSUSED*/
static int
kmem_walk_all(uintptr_t addr, const kmem_cache_t *c, mdb_walk_state_t *wsp)
{
	/*
	 * Buffers allocated from NOTOUCH caches can also show up as freed
	 * memory in other caches.  This can be a little confusing, so we
	 * don't walk NOTOUCH caches when walking all caches (thereby assuring
	 * that "::walk kmem" and "::walk freemem" yield disjoint output).
	 */
	if (c->cache_cflags & KMC_NOTOUCH)
		return (WALK_NEXT);

	if (mdb_pwalk(wsp->walk_data, wsp->walk_callback,
	    wsp->walk_cbdata, addr) == -1)
		return (WALK_DONE);

	return (WALK_NEXT);
}

#define	KMEM_WALK_ALL(name, wsp) { \
	wsp->walk_data = (name); \
	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)kmem_walk_all, wsp) == -1) \
		return (WALK_ERR); \
	return (WALK_DONE); \
}

int
kmem_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_arg != NULL)
		wsp->walk_addr = (uintptr_t)wsp->walk_arg;

	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("kmem", wsp);
	return (kmem_walk_init_common(wsp, KM_ALLOCATED));
}

int
bufctl_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("bufctl", wsp);
	return (kmem_walk_init_common(wsp, KM_ALLOCATED | KM_BUFCTL));
}

int
freemem_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("freemem", wsp);
	return (kmem_walk_init_common(wsp, KM_FREE));
}

int
freemem_constructed_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("freemem_constructed", wsp);
	return (kmem_walk_init_common(wsp, KM_FREE | KM_CONSTRUCTED));
}

int
freectl_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("freectl", wsp);
	return (kmem_walk_init_common(wsp, KM_FREE | KM_BUFCTL));
}

int
freectl_constructed_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		KMEM_WALK_ALL("freectl_constructed", wsp);
	return (kmem_walk_init_common(wsp,
	    KM_FREE | KM_BUFCTL | KM_CONSTRUCTED));
}

typedef struct bufctl_history_walk {
	void		*bhw_next;
	kmem_cache_t	*bhw_cache;
	kmem_slab_t	*bhw_slab;
	hrtime_t	bhw_timestamp;
} bufctl_history_walk_t;

int
bufctl_history_walk_init(mdb_walk_state_t *wsp)
{
	bufctl_history_walk_t *bhw;
	kmem_bufctl_audit_t bc;
	kmem_bufctl_audit_t bcn;

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
	kmem_bufctl_audit_t bc;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&bc, sizeof (bc), addr) == -1) {
		mdb_warn("unable to read bufctl at %p", bhw->bhw_next);
		return (WALK_ERR);
	}

	/*
	 * The bufctl is only valid if the address, cache, and slab are
	 * correct.  We also check that the timestamp is decreasing, to
	 * prevent infinite loops.
	 */
	if ((uintptr_t)bc.bc_addr != baseaddr ||
	    bc.bc_cache != bhw->bhw_cache ||
	    bc.bc_slab != bhw->bhw_slab ||
	    (bhw->bhw_timestamp != 0 && bc.bc_timestamp >= bhw->bhw_timestamp))
		return (WALK_DONE);

	bhw->bhw_next = bc.bc_lastlog;
	bhw->bhw_timestamp = bc.bc_timestamp;

	return (wsp->walk_callback(addr, &bc, wsp->walk_cbdata));
}

void
bufctl_history_walk_fini(mdb_walk_state_t *wsp)
{
	bufctl_history_walk_t *bhw = wsp->walk_data;

	mdb_free(bhw, sizeof (*bhw));
}

typedef struct kmem_log_walk {
	kmem_bufctl_audit_t *klw_base;
	kmem_bufctl_audit_t **klw_sorted;
	kmem_log_header_t klw_lh;
	size_t klw_size;
	size_t klw_maxndx;
	size_t klw_ndx;
} kmem_log_walk_t;

int
kmem_log_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t lp = wsp->walk_addr;
	kmem_log_walk_t *klw;
	kmem_log_header_t *lhp;
	int maxndx, i, j, k;

	/*
	 * By default (global walk), walk the kmem_transaction_log.  Otherwise
	 * read the log whose kmem_log_header_t is stored at walk_addr.
	 */
	if (lp == NULL && mdb_readvar(&lp, "kmem_transaction_log") == -1) {
		mdb_warn("failed to read 'kmem_transaction_log'");
		return (WALK_ERR);
	}

	if (lp == NULL) {
		mdb_warn("log is disabled\n");
		return (WALK_ERR);
	}

	klw = mdb_zalloc(sizeof (kmem_log_walk_t), UM_SLEEP);
	lhp = &klw->klw_lh;

	if (mdb_vread(lhp, sizeof (kmem_log_header_t), lp) == -1) {
		mdb_warn("failed to read log header at %p", lp);
		mdb_free(klw, sizeof (kmem_log_walk_t));
		return (WALK_ERR);
	}

	klw->klw_size = lhp->lh_chunksize * lhp->lh_nchunks;
	klw->klw_base = mdb_alloc(klw->klw_size, UM_SLEEP);
	maxndx = lhp->lh_chunksize / sizeof (kmem_bufctl_audit_t) - 1;

	if (mdb_vread(klw->klw_base, klw->klw_size,
	    (uintptr_t)lhp->lh_base) == -1) {
		mdb_warn("failed to read log at base %p", lhp->lh_base);
		mdb_free(klw->klw_base, klw->klw_size);
		mdb_free(klw, sizeof (kmem_log_walk_t));
		return (WALK_ERR);
	}

	klw->klw_sorted = mdb_alloc(maxndx * lhp->lh_nchunks *
	    sizeof (kmem_bufctl_audit_t *), UM_SLEEP);

	for (i = 0, k = 0; i < lhp->lh_nchunks; i++) {
		kmem_bufctl_audit_t *chunk = (kmem_bufctl_audit_t *)
		    ((uintptr_t)klw->klw_base + i * lhp->lh_chunksize);

		for (j = 0; j < maxndx; j++)
			klw->klw_sorted[k++] = &chunk[j];
	}

	qsort(klw->klw_sorted, k, sizeof (kmem_bufctl_audit_t *),
	    (int(*)(const void *, const void *))bufctlcmp);

	klw->klw_maxndx = k;
	wsp->walk_data = klw;

	return (WALK_NEXT);
}

int
kmem_log_walk_step(mdb_walk_state_t *wsp)
{
	kmem_log_walk_t *klw = wsp->walk_data;
	kmem_bufctl_audit_t *bcp;

	if (klw->klw_ndx == klw->klw_maxndx)
		return (WALK_DONE);

	bcp = klw->klw_sorted[klw->klw_ndx++];

	return (wsp->walk_callback((uintptr_t)bcp - (uintptr_t)klw->klw_base +
	    (uintptr_t)klw->klw_lh.lh_base, bcp, wsp->walk_cbdata));
}

void
kmem_log_walk_fini(mdb_walk_state_t *wsp)
{
	kmem_log_walk_t *klw = wsp->walk_data;

	mdb_free(klw->klw_base, klw->klw_size);
	mdb_free(klw->klw_sorted, klw->klw_maxndx *
	    sizeof (kmem_bufctl_audit_t *));
	mdb_free(klw, sizeof (kmem_log_walk_t));
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
allocdby_walk_bufctl(uintptr_t addr, const kmem_bufctl_audit_t *bcp,
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
allocdby_walk_cache(uintptr_t addr, const kmem_cache_t *c, allocdby_walk_t *abw)
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

	if (mdb_walk("kmem_cache",
	    (mdb_walk_cb_t)allocdby_walk_cache, abw) == -1) {
		mdb_warn("couldn't walk kmem_cache");
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
	kmem_bufctl_audit_t bc;
	uintptr_t addr;

	if (abw->abw_ndx == abw->abw_nbufs)
		return (WALK_DONE);

	addr = abw->abw_buf[abw->abw_ndx++].abb_addr;

	if (mdb_vread(&bc, sizeof (bc), addr) == -1) {
		mdb_warn("couldn't read bufctl at %p", addr);
		return (WALK_DONE);
	}

	return (wsp->walk_callback(addr, &bc, wsp->walk_cbdata));
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
allocdby_walk(uintptr_t addr, const kmem_bufctl_audit_t *bcp, void *ignored)
{
	char c[MDB_SYM_NAMLEN];
	GElf_Sym sym;
	int i;

	mdb_printf("%0?p %12llx ", addr, bcp->bc_timestamp);
	for (i = 0; i < bcp->bc_depth; i++) {
		if (mdb_lookup_by_addr(bcp->bc_stack[i],
		    MDB_SYM_FUZZY, c, sizeof (c), &sym) == -1)
			continue;
		if (strncmp(c, "kmem_", 5) == 0)
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

/*
 * Return a string describing the address in relation to the given thread's
 * stack.
 *
 * - If the thread state is TS_FREE, return " (inactive interrupt thread)".
 *
 * - If the address is above the stack pointer, return an empty string
 *   signifying that the address is active.
 *
 * - If the address is below the stack pointer, and the thread is not on proc,
 *   return " (below sp)".
 *
 * - If the address is below the stack pointer, and the thread is on proc,
 *   return " (possibly below sp)".  Depending on context, we may or may not
 *   have an accurate t_sp.
 */
static const char *
stack_active(const kthread_t *t, uintptr_t addr)
{
	uintptr_t panicstk;
	GElf_Sym sym;

	if (t->t_state == TS_FREE)
		return (" (inactive interrupt thread)");

	/*
	 * Check to see if we're on the panic stack.  If so, ignore t_sp, as it
	 * no longer relates to the thread's real stack.
	 */
	if (mdb_lookup_by_name("panic_stack", &sym) == 0) {
		panicstk = (uintptr_t)sym.st_value;

		if (t->t_sp >= panicstk && t->t_sp < panicstk + PANICSTKSIZE)
			return ("");
	}

	if (addr >= t->t_sp + STACK_BIAS)
		return ("");

	if (t->t_state == TS_ONPROC)
		return (" (possibly below sp)");

	return (" (below sp)");
}

/*
 * Additional state for the kmem and vmem ::whatis handlers
 */
typedef struct whatis_info {
	mdb_whatis_t *wi_w;
	const kmem_cache_t *wi_cache;
	const vmem_t *wi_vmem;
	vmem_t *wi_msb_arena;
	size_t wi_slab_size;
	uint_t wi_slab_found;
	uint_t wi_kmem_lite_count;
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
whatis_print_kmf_lite(uintptr_t btaddr, size_t count)
{
#define	KMEM_LITE_MAX	16
	pc_t callers[KMEM_LITE_MAX];
	pc_t uninit = (pc_t)KMEM_UNINITIALIZED_PATTERN;

	kmem_buftag_t bt;
	intptr_t stat;
	const char *plural = "";
	int i;

	/* validate our arguments and read in the buftag */
	if (count == 0 || count > KMEM_LITE_MAX ||
	    mdb_vread(&bt, sizeof (bt), btaddr) == -1)
		return;

	/* validate the buffer state and read in the callers */
	stat = (intptr_t)bt.bt_bufctl ^ bt.bt_bxstat;

	if (stat != KMEM_BUFTAG_ALLOC && stat != KMEM_BUFTAG_FREE)
		return;

	if (mdb_vread(callers, count * sizeof (pc_t),
	    btaddr + offsetof(kmem_buftag_lite_t, bt_history)) == -1)
		return;

	/* If there aren't any filled in callers, bail */
	if (callers[0] == uninit)
		return;

	plural = (callers[1] == uninit) ? "" : "s";

	/* Everything's done and checked; print them out */
	mdb_printf(":\n");

	mdb_inc_indent(8);
	mdb_printf("recent caller%s: %a", plural, callers[0]);
	for (i = 1; i < count; i++) {
		if (callers[i] == uninit)
			break;
		mdb_printf(", %a", callers[i]);
	}
	mdb_dec_indent(8);
}

static void
whatis_print_kmem(whatis_info_t *wi, uintptr_t maddr, uintptr_t addr,
    uintptr_t baddr)
{
	mdb_whatis_t *w = wi->wi_w;

	const kmem_cache_t *cp = wi->wi_cache;
	/* LINTED pointer cast may result in improper alignment */
	uintptr_t btaddr = (uintptr_t)KMEM_BUFTAG(cp, addr);
	int quiet = (mdb_whatis_flags(w) & WHATIS_QUIET);
	int call_printer = (!quiet && (cp->cache_flags & KMF_AUDIT));

	mdb_whatis_report_object(w, maddr, addr, "");

	if (baddr != 0 && !call_printer)
		mdb_printf("bufctl %p ", baddr);

	mdb_printf("%s from %s",
	    (wi->wi_freemem == FALSE) ? "allocated" : "freed", cp->cache_name);

	if (baddr != 0 && call_printer) {
		whatis_call_printer(bufctl, baddr);
		return;
	}

	/* for KMF_LITE caches, try to print out the previous callers */
	if (!quiet && (cp->cache_flags & KMF_LITE))
		whatis_print_kmf_lite(btaddr, wi->wi_kmem_lite_count);

	mdb_printf("\n");
}

/*ARGSUSED*/
static int
whatis_walk_kmem(uintptr_t addr, void *ignored, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	uintptr_t cur;
	size_t size = wi->wi_cache->cache_bufsize;

	while (mdb_whatis_match(w, addr, size, &cur))
		whatis_print_kmem(wi, cur, addr, NULL);

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_walk_bufctl(uintptr_t baddr, const kmem_bufctl_t *bcp, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	uintptr_t cur;
	uintptr_t addr = (uintptr_t)bcp->bc_addr;
	size_t size = wi->wi_cache->cache_bufsize;

	while (mdb_whatis_match(w, addr, size, &cur))
		whatis_print_kmem(wi, cur, addr, baddr);

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
		    (!(mdb_whatis_flags(w) & WHATIS_BUFCTL) ||
		    (vs->vs_type == VMEM_ALLOC && vs->vs_depth != 0))) {
			mdb_printf("vmem_seg %p ", addr);
		}

		mdb_printf("%s from the %s vmem arena",
		    (vs->vs_type == VMEM_ALLOC) ? "allocated" : "freed",
		    wi->wi_vmem->vm_name);

		if (!(mdb_whatis_flags(w) & WHATIS_QUIET))
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

	int identifier = ((vmem->vm_cflags & VMC_IDENTIFIER) != 0);
	int idspace = ((mdb_whatis_flags(w) & WHATIS_IDSPACE) != 0);

	if (identifier != idspace)
		return (WALK_NEXT);

	wi->wi_vmem = vmem;

	if (mdb_whatis_flags(w) & WHATIS_VERBOSE)
		mdb_printf("Searching vmem arena %s...\n", nm);

	if (mdb_pwalk("vmem_seg",
	    (mdb_walk_cb_t)whatis_walk_seg, wi, addr) == -1) {
		mdb_warn("can't walk vmem_seg for %p", addr);
		return (WALK_NEXT);
	}

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_walk_slab(uintptr_t saddr, const kmem_slab_t *sp, whatis_info_t *wi)
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
whatis_walk_cache(uintptr_t addr, const kmem_cache_t *c, whatis_info_t *wi)
{
	mdb_whatis_t *w = wi->wi_w;

	char *walk, *freewalk;
	mdb_walk_cb_t func;
	int do_bufctl;

	int identifier = ((c->cache_flags & KMC_IDENTIFIER) != 0);
	int idspace = ((mdb_whatis_flags(w) & WHATIS_IDSPACE) != 0);

	if (identifier != idspace)
		return (WALK_NEXT);

	/* Override the '-b' flag as necessary */
	if (!(c->cache_flags & KMF_HASH))
		do_bufctl = FALSE;	/* no bufctls to walk */
	else if (c->cache_flags & KMF_AUDIT)
		do_bufctl = TRUE;	/* we always want debugging info */
	else
		do_bufctl = ((mdb_whatis_flags(w) & WHATIS_BUFCTL) != 0);

	if (do_bufctl) {
		walk = "bufctl";
		freewalk = "freectl";
		func = (mdb_walk_cb_t)whatis_walk_bufctl;
	} else {
		walk = "kmem";
		freewalk = "freemem";
		func = (mdb_walk_cb_t)whatis_walk_kmem;
	}

	wi->wi_cache = c;

	if (mdb_whatis_flags(w) & WHATIS_VERBOSE)
		mdb_printf("Searching %s...\n", c->cache_name);

	/*
	 * If more then two buffers live on each slab, figure out if we're
	 * interested in anything in any slab before doing the more expensive
	 * kmem/freemem (bufctl/freectl) walkers.
	 */
	wi->wi_slab_size = c->cache_slabsize - c->cache_maxcolor;
	if (!(c->cache_flags & KMF_HASH))
		wi->wi_slab_size -= sizeof (kmem_slab_t);

	if ((wi->wi_slab_size / c->cache_chunksize) > 2) {
		wi->wi_slab_found = 0;
		if (mdb_pwalk("kmem_slab", (mdb_walk_cb_t)whatis_walk_slab, wi,
		    addr) == -1) {
			mdb_warn("can't find kmem_slab walker");
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
whatis_walk_touch(uintptr_t addr, const kmem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena == wi->wi_msb_arena ||
	    (c->cache_cflags & KMC_NOTOUCH))
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

static int
whatis_walk_metadata(uintptr_t addr, const kmem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena != wi->wi_msb_arena)
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

static int
whatis_walk_notouch(uintptr_t addr, const kmem_cache_t *c, whatis_info_t *wi)
{
	if (c->cache_arena == wi->wi_msb_arena ||
	    !(c->cache_cflags & KMC_NOTOUCH))
		return (WALK_NEXT);

	return (whatis_walk_cache(addr, c, wi));
}

static int
whatis_walk_thread(uintptr_t addr, const kthread_t *t, mdb_whatis_t *w)
{
	uintptr_t cur;
	uintptr_t saddr;
	size_t size;

	/*
	 * Often, one calls ::whatis on an address from a thread structure.
	 * We use this opportunity to short circuit this case...
	 */
	while (mdb_whatis_match(w, addr, sizeof (kthread_t), &cur))
		mdb_whatis_report_object(w, cur, addr,
		    "allocated as a thread structure\n");

	/*
	 * Now check the stack
	 */
	if (t->t_stkbase == NULL)
		return (WALK_NEXT);

	/*
	 * This assumes that t_stk is the end of the stack, but it's really
	 * only the initial stack pointer for the thread.  Arguments to the
	 * initial procedure, SA(MINFRAME), etc. are all after t_stk.  So
	 * that 't->t_stk::whatis' reports "part of t's stack", we include
	 * t_stk in the range (the "+ 1", below), but the kernel should
	 * really include the full stack bounds where we can find it.
	 */
	saddr = (uintptr_t)t->t_stkbase;
	size = (uintptr_t)t->t_stk - saddr + 1;
	while (mdb_whatis_match(w, saddr, size, &cur))
		mdb_whatis_report_object(w, cur, cur,
		    "in thread %p's stack%s\n", addr, stack_active(t, cur));

	return (WHATIS_WALKRET(w));
}

static void
whatis_modctl_match(mdb_whatis_t *w, const char *name,
    uintptr_t base, size_t size, const char *where)
{
	uintptr_t cur;

	/*
	 * Since we're searching for addresses inside a module, we report
	 * them as symbols.
	 */
	while (mdb_whatis_match(w, base, size, &cur))
		mdb_whatis_report_address(w, cur, "in %s's %s\n", name, where);
}

static int
whatis_walk_modctl(uintptr_t addr, const struct modctl *m, mdb_whatis_t *w)
{
	char name[MODMAXNAMELEN];
	struct module mod;
	Shdr shdr;

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_vread(&mod, sizeof (mod), (uintptr_t)m->mod_mp) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)m->mod_modname) == -1)
		(void) mdb_snprintf(name, sizeof (name), "0x%p", addr);

	whatis_modctl_match(w, name,
	    (uintptr_t)mod.text, mod.text_size, "text segment");
	whatis_modctl_match(w, name,
	    (uintptr_t)mod.data, mod.data_size, "data segment");
	whatis_modctl_match(w, name,
	    (uintptr_t)mod.bss, mod.bss_size, "bss segment");

	if (mdb_vread(&shdr, sizeof (shdr), (uintptr_t)mod.symhdr) == -1) {
		mdb_warn("couldn't read symbol header for %p's module", addr);
		return (WALK_NEXT);
	}

	whatis_modctl_match(w, name,
	    (uintptr_t)mod.symtbl, mod.nsyms * shdr.sh_entsize, "symtab");
	whatis_modctl_match(w, name,
	    (uintptr_t)mod.symspace, mod.symsize, "symtab");

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_walk_memseg(uintptr_t addr, const struct memseg *seg, mdb_whatis_t *w)
{
	uintptr_t cur;

	uintptr_t base = (uintptr_t)seg->pages;
	size_t size = (uintptr_t)seg->epages - base;

	while (mdb_whatis_match(w, base, size, &cur)) {
		/* round our found pointer down to the page_t base. */
		size_t offset = (cur - base) % sizeof (page_t);

		mdb_whatis_report_object(w, cur, cur - offset,
		    "allocated as a page structure\n");
	}

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_run_modules(mdb_whatis_t *w, void *arg)
{
	if (mdb_walk("modctl", (mdb_walk_cb_t)whatis_walk_modctl, w) == -1) {
		mdb_warn("couldn't find modctl walker");
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
whatis_run_threads(mdb_whatis_t *w, void *ignored)
{
	/*
	 * Now search all thread stacks.  Yes, this is a little weak; we
	 * can save a lot of work by first checking to see if the
	 * address is in segkp vs. segkmem.  But hey, computers are
	 * fast.
	 */
	if (mdb_walk("thread", (mdb_walk_cb_t)whatis_walk_thread, w) == -1) {
		mdb_warn("couldn't find thread walker");
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
whatis_run_pages(mdb_whatis_t *w, void *ignored)
{
	if (mdb_walk("memseg", (mdb_walk_cb_t)whatis_walk_memseg, w) == -1) {
		mdb_warn("couldn't find memseg walker");
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
whatis_run_kmem(mdb_whatis_t *w, void *ignored)
{
	whatis_info_t wi;

	bzero(&wi, sizeof (wi));
	wi.wi_w = w;

	if (mdb_readvar(&wi.wi_msb_arena, "kmem_msb_arena") == -1)
		mdb_warn("unable to readvar \"kmem_msb_arena\"");

	if (mdb_readvar(&wi.wi_kmem_lite_count,
	    "kmem_lite_count") == -1 || wi.wi_kmem_lite_count > 16)
		wi.wi_kmem_lite_count = 0;

	/*
	 * We process kmem caches in the following order:
	 *
	 *	non-KMC_NOTOUCH, non-metadata	(typically the most interesting)
	 *	metadata			(can be huge with KMF_AUDIT)
	 *	KMC_NOTOUCH, non-metadata	(see kmem_walk_all())
	 */
	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)whatis_walk_touch,
	    &wi) == -1 ||
	    mdb_walk("kmem_cache", (mdb_walk_cb_t)whatis_walk_metadata,
	    &wi) == -1 ||
	    mdb_walk("kmem_cache", (mdb_walk_cb_t)whatis_walk_notouch,
	    &wi) == -1) {
		mdb_warn("couldn't find kmem_cache walker");
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

typedef struct kmem_log_cpu {
	uintptr_t kmc_low;
	uintptr_t kmc_high;
} kmem_log_cpu_t;

typedef struct kmem_log_data {
	uintptr_t kmd_addr;
	kmem_log_cpu_t *kmd_cpu;
} kmem_log_data_t;

int
kmem_log_walk(uintptr_t addr, const kmem_bufctl_audit_t *b,
    kmem_log_data_t *kmd)
{
	int i;
	kmem_log_cpu_t *kmc = kmd->kmd_cpu;
	size_t bufsize;

	for (i = 0; i < NCPU; i++) {
		if (addr >= kmc[i].kmc_low && addr < kmc[i].kmc_high)
			break;
	}

	if (kmd->kmd_addr) {
		if (b->bc_cache == NULL)
			return (WALK_NEXT);

		if (mdb_vread(&bufsize, sizeof (bufsize),
		    (uintptr_t)&b->bc_cache->cache_bufsize) == -1) {
			mdb_warn(
			    "failed to read cache_bufsize for cache at %p",
			    b->bc_cache);
			return (WALK_ERR);
		}

		if (kmd->kmd_addr < (uintptr_t)b->bc_addr ||
		    kmd->kmd_addr >= (uintptr_t)b->bc_addr + bufsize)
			return (WALK_NEXT);
	}

	if (i == NCPU)
		mdb_printf("   ");
	else
		mdb_printf("%3d", i);

	mdb_printf(" %0?p %0?p %16llx %0?p\n", addr, b->bc_addr,
	    b->bc_timestamp, b->bc_thread);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
kmem_log(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kmem_log_header_t lh;
	kmem_cpu_log_header_t clh;
	uintptr_t lhp, clhp;
	int ncpus;
	uintptr_t *cpu;
	GElf_Sym sym;
	kmem_log_cpu_t *kmc;
	int i;
	kmem_log_data_t kmd;
	uint_t opt_b = FALSE;

	if (mdb_getopts(argc, argv,
	    'b', MDB_OPT_SETBITS, TRUE, &opt_b, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&lhp, "kmem_transaction_log") == -1) {
		mdb_warn("failed to read 'kmem_transaction_log'");
		return (DCMD_ERR);
	}

	if (lhp == NULL) {
		mdb_warn("no kmem transaction log\n");
		return (DCMD_ERR);
	}

	mdb_readvar(&ncpus, "ncpus");

	if (mdb_vread(&lh, sizeof (kmem_log_header_t), lhp) == -1) {
		mdb_warn("failed to read log header at %p", lhp);
		return (DCMD_ERR);
	}

	clhp = lhp + ((uintptr_t)&lh.lh_cpu[0] - (uintptr_t)&lh);

	cpu = mdb_alloc(sizeof (uintptr_t) * NCPU, UM_SLEEP | UM_GC);

	if (mdb_lookup_by_name("cpu", &sym) == -1) {
		mdb_warn("couldn't find 'cpu' array");
		return (DCMD_ERR);
	}

	if (sym.st_size != NCPU * sizeof (uintptr_t)) {
		mdb_warn("expected 'cpu' to be of size %d; found %d\n",
		    NCPU * sizeof (uintptr_t), sym.st_size);
		return (DCMD_ERR);
	}

	if (mdb_vread(cpu, sym.st_size, (uintptr_t)sym.st_value) == -1) {
		mdb_warn("failed to read cpu array at %p", sym.st_value);
		return (DCMD_ERR);
	}

	kmc = mdb_zalloc(sizeof (kmem_log_cpu_t) * NCPU, UM_SLEEP | UM_GC);
	kmd.kmd_addr = NULL;
	kmd.kmd_cpu = kmc;

	for (i = 0; i < NCPU; i++) {

		if (cpu[i] == NULL)
			continue;

		if (mdb_vread(&clh, sizeof (clh), clhp) == -1) {
			mdb_warn("cannot read cpu %d's log header at %p",
			    i, clhp);
			return (DCMD_ERR);
		}

		kmc[i].kmc_low = clh.clh_chunk * lh.lh_chunksize +
		    (uintptr_t)lh.lh_base;
		kmc[i].kmc_high = (uintptr_t)clh.clh_current;

		clhp += sizeof (kmem_cpu_log_header_t);
	}

	mdb_printf("%3s %-?s %-?s %16s %-?s\n", "CPU", "ADDR", "BUFADDR",
	    "TIMESTAMP", "THREAD");

	/*
	 * If we have been passed an address, print out only log entries
	 * corresponding to that address.  If opt_b is specified, then interpret
	 * the address as a bufctl.
	 */
	if (flags & DCMD_ADDRSPEC) {
		kmem_bufctl_audit_t b;

		if (opt_b) {
			kmd.kmd_addr = addr;
		} else {
			if (mdb_vread(&b,
			    sizeof (kmem_bufctl_audit_t), addr) == -1) {
				mdb_warn("failed to read bufctl at %p", addr);
				return (DCMD_ERR);
			}

			(void) kmem_log_walk(addr, &b, &kmd);

			return (DCMD_OK);
		}
	}

	if (mdb_walk("kmem_log", (mdb_walk_cb_t)kmem_log_walk, &kmd) == -1) {
		mdb_warn("can't find kmem log walker");
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
	mdb_printf("%s",
"Display the contents of kmem_bufctl_audit_ts, with optional filtering.\n\n");
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
	kmem_bufctl_audit_t bc;
	uint_t verbose = FALSE;
	uint_t history = FALSE;
	uint_t in_history = FALSE;
	uintptr_t caller = NULL, thread = NULL;
	uintptr_t laddr, haddr, baddr = NULL;
	hrtime_t earliest = 0, latest = 0;
	int i, depth;
	char c[MDB_SYM_NAMLEN];
	GElf_Sym sym;

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
			mdb_printf("%<u>%-?s %-?s %-12s %-?s %s%</u>\n",
			    "ADDR", "BUFADDR", "TIMESTAMP", "THREAD", "CALLER");
		}
	}

	if (mdb_vread(&bc, sizeof (bc), addr) == -1) {
		mdb_warn("couldn't read bufctl at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * Guard against bogus bc_depth in case the bufctl is corrupt or
	 * the address does not really refer to a bufctl.
	 */
	depth = MIN(bc.bc_depth, KMEM_STACK_DEPTH);

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
			if (bc.bc_stack[i] >= laddr && bc.bc_stack[i] < haddr)
				break;

		if (i == depth)
			return (DCMD_OK);
	}

	if (thread != NULL && (uintptr_t)bc.bc_thread != thread)
		return (DCMD_OK);

	if (earliest != 0 && bc.bc_timestamp < earliest)
		return (DCMD_OK);

	if (latest != 0 && bc.bc_timestamp > latest)
		return (DCMD_OK);

	if (baddr != 0 && (uintptr_t)bc.bc_addr != baddr)
		return (DCMD_OK);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	if (verbose) {
		mdb_printf(
		    "%<b>%16p%</b> %16p %16llx %16p\n"
		    "%16s %16p %16p %16p\n",
		    addr, bc.bc_addr, bc.bc_timestamp, bc.bc_thread,
		    "", bc.bc_cache, bc.bc_lastlog, bc.bc_contents);

		mdb_inc_indent(17);
		for (i = 0; i < depth; i++)
			mdb_printf("%a\n", bc.bc_stack[i]);
		mdb_dec_indent(17);
		mdb_printf("\n");
	} else {
		mdb_printf("%0?p %0?p %12llx %0?p", addr, bc.bc_addr,
		    bc.bc_timestamp, bc.bc_thread);

		for (i = 0; i < depth; i++) {
			if (mdb_lookup_by_addr(bc.bc_stack[i],
			    MDB_SYM_FUZZY, c, sizeof (c), &sym) == -1)
				continue;
			if (strncmp(c, "kmem_", 5) == 0)
				continue;
			mdb_printf(" %a\n", bc.bc_stack[i]);
			break;
		}

		if (i >= depth)
			mdb_printf("\n");
	}

	return (DCMD_OK);
}

typedef struct kmem_verify {
	uint64_t *kmv_buf;		/* buffer to read cache contents into */
	size_t kmv_size;		/* number of bytes in kmv_buf */
	int kmv_corruption;		/* > 0 if corruption found. */
	int kmv_besilent;		/* report actual corruption sites */
	struct kmem_cache kmv_cache;	/* the cache we're operating on */
} kmem_verify_t;

/*
 * verify_pattern()
 * 	verify that buf is filled with the pattern pat.
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
verify_buftag(kmem_buftag_t *btp, uintptr_t pat)
{
	return (btp->bt_bxstat == ((intptr_t)btp->bt_bufctl ^ pat) ? 0 : -1);
}

/*
 * verify_free()
 * 	verify the integrity of a free block of memory by checking
 * 	that it is filled with 0xdeadbeef and that its buftag is sane.
 */
/*ARGSUSED1*/
static int
verify_free(uintptr_t addr, const void *data, void *private)
{
	kmem_verify_t *kmv = (kmem_verify_t *)private;
	uint64_t *buf = kmv->kmv_buf;	/* buf to validate */
	int64_t corrupt;		/* corruption offset */
	kmem_buftag_t *buftagp;		/* ptr to buftag */
	kmem_cache_t *cp = &kmv->kmv_cache;
	int besilent = kmv->kmv_besilent;

	/*LINTED*/
	buftagp = KMEM_BUFTAG(cp, buf);

	/*
	 * Read the buffer to check.
	 */
	if (mdb_vread(buf, kmv->kmv_size, addr) == -1) {
		if (!besilent)
			mdb_warn("couldn't read %p", addr);
		return (WALK_NEXT);
	}

	if ((corrupt = verify_pattern(buf, cp->cache_verify,
	    KMEM_FREE_PATTERN)) >= 0) {
		if (!besilent)
			mdb_printf("buffer %p (free) seems corrupted, at %p\n",
			    addr, (uintptr_t)addr + corrupt);
		goto corrupt;
	}
	/*
	 * When KMF_LITE is set, buftagp->bt_redzone is used to hold
	 * the first bytes of the buffer, hence we cannot check for red
	 * zone corruption.
	 */
	if ((cp->cache_flags & (KMF_HASH | KMF_LITE)) == KMF_HASH &&
	    buftagp->bt_redzone != KMEM_REDZONE_PATTERN) {
		if (!besilent)
			mdb_printf("buffer %p (free) seems to "
			    "have a corrupt redzone pattern\n", addr);
		goto corrupt;
	}

	/*
	 * confirm bufctl pointer integrity.
	 */
	if (verify_buftag(buftagp, KMEM_BUFTAG_FREE) == -1) {
		if (!besilent)
			mdb_printf("buffer %p (free) has a corrupt "
			    "buftag\n", addr);
		goto corrupt;
	}

	return (WALK_NEXT);
corrupt:
	kmv->kmv_corruption++;
	return (WALK_NEXT);
}

/*
 * verify_alloc()
 * 	Verify that the buftag of an allocated buffer makes sense with respect
 * 	to the buffer.
 */
/*ARGSUSED1*/
static int
verify_alloc(uintptr_t addr, const void *data, void *private)
{
	kmem_verify_t *kmv = (kmem_verify_t *)private;
	kmem_cache_t *cp = &kmv->kmv_cache;
	uint64_t *buf = kmv->kmv_buf;	/* buf to validate */
	/*LINTED*/
	kmem_buftag_t *buftagp = KMEM_BUFTAG(cp, buf);
	uint32_t *ip = (uint32_t *)buftagp;
	uint8_t *bp = (uint8_t *)buf;
	int looks_ok = 0, size_ok = 1;	/* flags for finding corruption */
	int besilent = kmv->kmv_besilent;

	/*
	 * Read the buffer to check.
	 */
	if (mdb_vread(buf, kmv->kmv_size, addr) == -1) {
		if (!besilent)
			mdb_warn("couldn't read %p", addr);
		return (WALK_NEXT);
	}

	/*
	 * There are two cases to handle:
	 * 1. If the buf was alloc'd using kmem_cache_alloc, it will have
	 *    0xfeedfacefeedface at the end of it
	 * 2. If the buf was alloc'd using kmem_alloc, it will have
	 *    0xbb just past the end of the region in use.  At the buftag,
	 *    it will have 0xfeedface (or, if the whole buffer is in use,
	 *    0xfeedface & bb000000 or 0xfeedfacf & 000000bb depending on
	 *    endianness), followed by 32 bits containing the offset of the
	 *    0xbb byte in the buffer.
	 *
	 * Finally, the two 32-bit words that comprise the second half of the
	 * buftag should xor to KMEM_BUFTAG_ALLOC
	 */

	if (buftagp->bt_redzone == KMEM_REDZONE_PATTERN)
		looks_ok = 1;
	else if (!KMEM_SIZE_VALID(ip[1]))
		size_ok = 0;
	else if (bp[KMEM_SIZE_DECODE(ip[1])] == KMEM_REDZONE_BYTE)
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

	if (verify_buftag(buftagp, KMEM_BUFTAG_ALLOC) == -1) {
		if (!besilent)
			mdb_printf("buffer %p (allocated) has a "
			    "corrupt buftag\n", addr);
		goto corrupt;
	}

	return (WALK_NEXT);
corrupt:
	kmv->kmv_corruption++;
	return (WALK_NEXT);
}

/*ARGSUSED2*/
int
kmem_verify(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC) {
		int check_alloc = 0, check_free = 0;
		kmem_verify_t kmv;

		if (mdb_vread(&kmv.kmv_cache, sizeof (kmv.kmv_cache),
		    addr) == -1) {
			mdb_warn("couldn't read kmem_cache %p", addr);
			return (DCMD_ERR);
		}

		kmv.kmv_size = kmv.kmv_cache.cache_buftag +
		    sizeof (kmem_buftag_t);
		kmv.kmv_buf = mdb_alloc(kmv.kmv_size, UM_SLEEP | UM_GC);
		kmv.kmv_corruption = 0;

		if ((kmv.kmv_cache.cache_flags & KMF_REDZONE)) {
			check_alloc = 1;
			if (kmv.kmv_cache.cache_flags & KMF_DEADBEEF)
				check_free = 1;
		} else {
			if (!(flags & DCMD_LOOP)) {
				mdb_warn("cache %p (%s) does not have "
				    "redzone checking enabled\n", addr,
				    kmv.kmv_cache.cache_name);
			}
			return (DCMD_ERR);
		}

		if (flags & DCMD_LOOP) {
			/*
			 * table mode, don't print out every corrupt buffer
			 */
			kmv.kmv_besilent = 1;
		} else {
			mdb_printf("Summary for cache '%s'\n",
			    kmv.kmv_cache.cache_name);
			mdb_inc_indent(2);
			kmv.kmv_besilent = 0;
		}

		if (check_alloc)
			(void) mdb_pwalk("kmem", verify_alloc, &kmv, addr);
		if (check_free)
			(void) mdb_pwalk("freemem", verify_free, &kmv, addr);

		if (flags & DCMD_LOOP) {
			if (kmv.kmv_corruption == 0) {
				mdb_printf("%-*s %?p clean\n",
				    KMEM_CACHE_NAMELEN,
				    kmv.kmv_cache.cache_name, addr);
			} else {
				char *s = "";	/* optional s in "buffer[s]" */
				if (kmv.kmv_corruption > 1)
					s = "s";

				mdb_printf("%-*s %?p %d corrupt buffer%s\n",
				    KMEM_CACHE_NAMELEN,
				    kmv.kmv_cache.cache_name, addr,
				    kmv.kmv_corruption, s);
			}
		} else {
			/*
			 * This is the more verbose mode, when the user has
			 * type addr::kmem_verify.  If the cache was clean,
			 * nothing will have yet been printed. So say something.
			 */
			if (kmv.kmv_corruption == 0)
				mdb_printf("clean\n");

			mdb_dec_indent(2);
		}
	} else {
		/*
		 * If the user didn't specify a cache to verify, we'll walk all
		 * kmem_cache's, specifying ourself as a callback for each...
		 * this is the equivalent of '::walk kmem_cache .::kmem_verify'
		 */
		mdb_printf("%<u>%-*s %-?s %-20s%</b>\n", KMEM_CACHE_NAMELEN,
		    "Cache Name", "Addr", "Cache Integrity");
		(void) (mdb_walk_dcmd("kmem_cache", "kmem_verify", 0, NULL));
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

	if (mdb_readvar(&vaddr, "vmem_list") == -1) {
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
	vsw->vsw_start = wsp->walk_addr + offsetof(vmem_t, vm_seg0);
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
		if (mdb_readvar(&seg_size, "vmem_seg_size") == -1) {
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
	vmem_kstat_t *vkp = &v.vm_kstat;
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
	    vkp->vk_mem_inuse.value.ui64, vkp->vk_mem_total.value.ui64,
	    vkp->vk_alloc.value.ui64, vkp->vk_fail.value.ui64);

	return (DCMD_OK);
}

void
vmem_seg_help(void)
{
	mdb_printf("%s",
"Display the contents of vmem_seg_ts, with optional filtering.\n\n"
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
	pc_t *stk = vs.vs_stack;
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
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	if (verbose) {
		mdb_printf("%<b>%16p%</b> %4s %16p %16p %16d\n",
		    addr, type, vs.vs_start, vs.vs_end, sz);

		if (no_debug)
			return (DCMD_OK);

		mdb_printf("%16s %4s %16p %16llx\n",
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
			if (strncmp(c, "vmem_", 5) == 0)
				continue;
			break;
		}
		mdb_printf(" %a\n", stk[i]);
	}
	return (DCMD_OK);
}

typedef struct kmalog_data {
	uintptr_t	kma_addr;
	hrtime_t	kma_newest;
} kmalog_data_t;

/*ARGSUSED*/
static int
showbc(uintptr_t addr, const kmem_bufctl_audit_t *bcp, kmalog_data_t *kma)
{
	char name[KMEM_CACHE_NAMELEN + 1];
	hrtime_t delta;
	int i, depth;
	size_t bufsize;

	if (bcp->bc_timestamp == 0)
		return (WALK_DONE);

	if (kma->kma_newest == 0)
		kma->kma_newest = bcp->bc_timestamp;

	if (kma->kma_addr) {
		if (mdb_vread(&bufsize, sizeof (bufsize),
		    (uintptr_t)&bcp->bc_cache->cache_bufsize) == -1) {
			mdb_warn(
			    "failed to read cache_bufsize for cache at %p",
			    bcp->bc_cache);
			return (WALK_ERR);
		}

		if (kma->kma_addr < (uintptr_t)bcp->bc_addr ||
		    kma->kma_addr >= (uintptr_t)bcp->bc_addr + bufsize)
			return (WALK_NEXT);
	}

	delta = kma->kma_newest - bcp->bc_timestamp;
	depth = MIN(bcp->bc_depth, KMEM_STACK_DEPTH);

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
kmalog(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *logname = "kmem_transaction_log";
	kmalog_data_t kma;

	if (argc > 1)
		return (DCMD_USAGE);

	kma.kma_newest = 0;
	if (flags & DCMD_ADDRSPEC)
		kma.kma_addr = addr;
	else
		kma.kma_addr = NULL;

	if (argc > 0) {
		if (argv->a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);
		if (strcmp(argv->a_un.a_str, "fail") == 0)
			logname = "kmem_failure_log";
		else if (strcmp(argv->a_un.a_str, "slab") == 0)
			logname = "kmem_slab_log";
		else
			return (DCMD_USAGE);
	}

	if (mdb_readvar(&addr, logname) == -1) {
		mdb_warn("failed to read %s log header pointer");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("kmem_log", (mdb_walk_cb_t)showbc, &kma, addr) == -1) {
		mdb_warn("failed to walk kmem log");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * As the final lure for die-hard crash(1M) users, we provide ::kmausers here.
 * The first piece is a structure which we use to accumulate kmem_cache_t
 * addresses of interest.  The kmc_add is used as a callback for the kmem_cache
 * walker; we either add all caches, or ones named explicitly as arguments.
 */

typedef struct kmclist {
	const char *kmc_name;			/* Name to match (or NULL) */
	uintptr_t *kmc_caches;			/* List of kmem_cache_t addrs */
	int kmc_nelems;				/* Num entries in kmc_caches */
	int kmc_size;				/* Size of kmc_caches array */
} kmclist_t;

static int
kmc_add(uintptr_t addr, const kmem_cache_t *cp, kmclist_t *kmc)
{
	void *p;
	int s;

	if (kmc->kmc_name == NULL ||
	    strcmp(cp->cache_name, kmc->kmc_name) == 0) {
		/*
		 * If we have a match, grow our array (if necessary), and then
		 * add the virtual address of the matching cache to our list.
		 */
		if (kmc->kmc_nelems >= kmc->kmc_size) {
			s = kmc->kmc_size ? kmc->kmc_size * 2 : 256;
			p = mdb_alloc(sizeof (uintptr_t) * s, UM_SLEEP | UM_GC);

			bcopy(kmc->kmc_caches, p,
			    sizeof (uintptr_t) * kmc->kmc_size);

			kmc->kmc_caches = p;
			kmc->kmc_size = s;
		}

		kmc->kmc_caches[kmc->kmc_nelems++] = addr;
		return (kmc->kmc_name ? WALK_DONE : WALK_NEXT);
	}

	return (WALK_NEXT);
}

/*
 * The second piece of ::kmausers is a hash table of allocations.  Each
 * allocation owner is identified by its stack trace and data_size.  We then
 * track the total bytes of all such allocations, and the number of allocations
 * to report at the end.  Once we have a list of caches, we walk through the
 * allocated bufctls of each, and update our hash table accordingly.
 */

typedef struct kmowner {
	struct kmowner *kmo_head;		/* First hash elt in bucket */
	struct kmowner *kmo_next;		/* Next hash elt in chain */
	size_t kmo_signature;			/* Hash table signature */
	uint_t kmo_num;				/* Number of allocations */
	size_t kmo_data_size;			/* Size of each allocation */
	size_t kmo_total_size;			/* Total bytes of allocation */
	int kmo_depth;				/* Depth of stack trace */
	uintptr_t kmo_stack[KMEM_STACK_DEPTH];	/* Stack trace */
} kmowner_t;

typedef struct kmusers {
	uintptr_t kmu_addr;			/* address of interest */
	const kmem_cache_t *kmu_cache;		/* Current kmem cache */
	kmowner_t *kmu_hash;			/* Hash table of owners */
	int kmu_nelems;				/* Number of entries in use */
	int kmu_size;				/* Total number of entries */
} kmusers_t;

static void
kmu_add(kmusers_t *kmu, const kmem_bufctl_audit_t *bcp,
    size_t size, size_t data_size)
{
	int i, depth = MIN(bcp->bc_depth, KMEM_STACK_DEPTH);
	size_t bucket, signature = data_size;
	kmowner_t *kmo, *kmoend;

	/*
	 * If the hash table is full, double its size and rehash everything.
	 */
	if (kmu->kmu_nelems >= kmu->kmu_size) {
		int s = kmu->kmu_size ? kmu->kmu_size * 2 : 1024;

		kmo = mdb_alloc(sizeof (kmowner_t) * s, UM_SLEEP | UM_GC);
		bcopy(kmu->kmu_hash, kmo, sizeof (kmowner_t) * kmu->kmu_size);
		kmu->kmu_hash = kmo;
		kmu->kmu_size = s;

		kmoend = kmu->kmu_hash + kmu->kmu_size;
		for (kmo = kmu->kmu_hash; kmo < kmoend; kmo++)
			kmo->kmo_head = NULL;

		kmoend = kmu->kmu_hash + kmu->kmu_nelems;
		for (kmo = kmu->kmu_hash; kmo < kmoend; kmo++) {
			bucket = kmo->kmo_signature & (kmu->kmu_size - 1);
			kmo->kmo_next = kmu->kmu_hash[bucket].kmo_head;
			kmu->kmu_hash[bucket].kmo_head = kmo;
		}
	}

	/*
	 * Finish computing the hash signature from the stack trace, and then
	 * see if the owner is in the hash table.  If so, update our stats.
	 */
	for (i = 0; i < depth; i++)
		signature += bcp->bc_stack[i];

	bucket = signature & (kmu->kmu_size - 1);

	for (kmo = kmu->kmu_hash[bucket].kmo_head; kmo; kmo = kmo->kmo_next) {
		if (kmo->kmo_signature == signature) {
			size_t difference = 0;

			difference |= kmo->kmo_data_size - data_size;
			difference |= kmo->kmo_depth - depth;

			for (i = 0; i < depth; i++) {
				difference |= kmo->kmo_stack[i] -
				    bcp->bc_stack[i];
			}

			if (difference == 0) {
				kmo->kmo_total_size += size;
				kmo->kmo_num++;
				return;
			}
		}
	}

	/*
	 * If the owner is not yet hashed, grab the next element and fill it
	 * in based on the allocation information.
	 */
	kmo = &kmu->kmu_hash[kmu->kmu_nelems++];
	kmo->kmo_next = kmu->kmu_hash[bucket].kmo_head;
	kmu->kmu_hash[bucket].kmo_head = kmo;

	kmo->kmo_signature = signature;
	kmo->kmo_num = 1;
	kmo->kmo_data_size = data_size;
	kmo->kmo_total_size = size;
	kmo->kmo_depth = depth;

	for (i = 0; i < depth; i++)
		kmo->kmo_stack[i] = bcp->bc_stack[i];
}

/*
 * When ::kmausers is invoked without the -f flag, we simply update our hash
 * table with the information from each allocated bufctl.
 */
/*ARGSUSED*/
static int
kmause1(uintptr_t addr, const kmem_bufctl_audit_t *bcp, kmusers_t *kmu)
{
	const kmem_cache_t *cp = kmu->kmu_cache;

	kmu_add(kmu, bcp, cp->cache_bufsize, cp->cache_bufsize);
	return (WALK_NEXT);
}

/*
 * When ::kmausers is invoked with the -f flag, we print out the information
 * for each bufctl as well as updating the hash table.
 */
static int
kmause2(uintptr_t addr, const kmem_bufctl_audit_t *bcp, kmusers_t *kmu)
{
	int i, depth = MIN(bcp->bc_depth, KMEM_STACK_DEPTH);
	const kmem_cache_t *cp = kmu->kmu_cache;
	kmem_bufctl_t bufctl;

	if (kmu->kmu_addr) {
		if (mdb_vread(&bufctl, sizeof (bufctl),  addr) == -1)
			mdb_warn("couldn't read bufctl at %p", addr);
		else if (kmu->kmu_addr < (uintptr_t)bufctl.bc_addr ||
		    kmu->kmu_addr >= (uintptr_t)bufctl.bc_addr +
		    cp->cache_bufsize)
			return (WALK_NEXT);
	}

	mdb_printf("size %d, addr %p, thread %p, cache %s\n",
	    cp->cache_bufsize, addr, bcp->bc_thread, cp->cache_name);

	for (i = 0; i < depth; i++)
		mdb_printf("\t %a\n", bcp->bc_stack[i]);

	kmu_add(kmu, bcp, cp->cache_bufsize, cp->cache_bufsize);
	return (WALK_NEXT);
}

/*
 * We sort our results by allocation size before printing them.
 */
static int
kmownercmp(const void *lp, const void *rp)
{
	const kmowner_t *lhs = lp;
	const kmowner_t *rhs = rp;

	return (rhs->kmo_total_size - lhs->kmo_total_size);
}

/*
 * The main engine of ::kmausers is relatively straightforward: First we
 * accumulate our list of kmem_cache_t addresses into the kmclist_t. Next we
 * iterate over the allocated bufctls of each cache in the list.  Finally,
 * we sort and print our results.
 */
/*ARGSUSED*/
int
kmausers(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int mem_threshold = 8192;	/* Minimum # bytes for printing */
	int cnt_threshold = 100;	/* Minimum # blocks for printing */
	int audited_caches = 0;		/* Number of KMF_AUDIT caches found */
	int do_all_caches = 1;		/* Do all caches (no arguments) */
	int opt_e = FALSE;		/* Include "small" users */
	int opt_f = FALSE;		/* Print stack traces */

	mdb_walk_cb_t callback = (mdb_walk_cb_t)kmause1;
	kmowner_t *kmo, *kmoend;
	int i, oelems;

	kmclist_t kmc;
	kmusers_t kmu;

	bzero(&kmc, sizeof (kmc));
	bzero(&kmu, sizeof (kmu));

	while ((i = mdb_getopts(argc, argv,
	    'e', MDB_OPT_SETBITS, TRUE, &opt_e,
	    'f', MDB_OPT_SETBITS, TRUE, &opt_f, NULL)) != argc) {

		argv += i;	/* skip past options we just processed */
		argc -= i;	/* adjust argc */

		if (argv->a_type != MDB_TYPE_STRING || *argv->a_un.a_str == '-')
			return (DCMD_USAGE);

		oelems = kmc.kmc_nelems;
		kmc.kmc_name = argv->a_un.a_str;
		(void) mdb_walk("kmem_cache", (mdb_walk_cb_t)kmc_add, &kmc);

		if (kmc.kmc_nelems == oelems) {
			mdb_warn("unknown kmem cache: %s\n", kmc.kmc_name);
			return (DCMD_ERR);
		}

		do_all_caches = 0;
		argv++;
		argc--;
	}

	if (flags & DCMD_ADDRSPEC) {
		opt_f = TRUE;
		kmu.kmu_addr = addr;
	} else {
		kmu.kmu_addr = NULL;
	}

	if (opt_e)
		mem_threshold = cnt_threshold = 0;

	if (opt_f)
		callback = (mdb_walk_cb_t)kmause2;

	if (do_all_caches) {
		kmc.kmc_name = NULL; /* match all cache names */
		(void) mdb_walk("kmem_cache", (mdb_walk_cb_t)kmc_add, &kmc);
	}

	for (i = 0; i < kmc.kmc_nelems; i++) {
		uintptr_t cp = kmc.kmc_caches[i];
		kmem_cache_t c;

		if (mdb_vread(&c, sizeof (c), cp) == -1) {
			mdb_warn("failed to read cache at %p", cp);
			continue;
		}

		if (!(c.cache_flags & KMF_AUDIT)) {
			if (!do_all_caches) {
				mdb_warn("KMF_AUDIT is not enabled for %s\n",
				    c.cache_name);
			}
			continue;
		}

		kmu.kmu_cache = &c;
		(void) mdb_pwalk("bufctl", callback, &kmu, cp);
		audited_caches++;
	}

	if (audited_caches == 0 && do_all_caches) {
		mdb_warn("KMF_AUDIT is not enabled for any caches\n");
		return (DCMD_ERR);
	}

	qsort(kmu.kmu_hash, kmu.kmu_nelems, sizeof (kmowner_t), kmownercmp);
	kmoend = kmu.kmu_hash + kmu.kmu_nelems;

	for (kmo = kmu.kmu_hash; kmo < kmoend; kmo++) {
		if (kmo->kmo_total_size < mem_threshold &&
		    kmo->kmo_num < cnt_threshold)
			continue;
		mdb_printf("%lu bytes for %u allocations with data size %lu:\n",
		    kmo->kmo_total_size, kmo->kmo_num, kmo->kmo_data_size);
		for (i = 0; i < kmo->kmo_depth; i++)
			mdb_printf("\t %a\n", kmo->kmo_stack[i]);
	}

	return (DCMD_OK);
}

void
kmausers_help(void)
{
	mdb_printf(
	    "Displays the largest users of the kmem allocator, sorted by \n"
	    "trace.  If one or more caches is specified, only those caches\n"
	    "will be searched.  By default, all caches are searched.  If an\n"
	    "address is specified, then only those allocations which include\n"
	    "the given address are displayed.  Specifying an address implies\n"
	    "-f.\n"
	    "\n"
	    "\t-e\tInclude all users, not just the largest\n"
	    "\t-f\tDisplay individual allocations.  By default, users are\n"
	    "\t\tgrouped by stack\n");
}

static int
kmem_ready_check(void)
{
	int ready;

	if (mdb_readvar(&ready, "kmem_ready") < 0)
		return (-1); /* errno is set for us */

	return (ready);
}

void
kmem_statechange(void)
{
	static int been_ready = 0;

	if (been_ready)
		return;

	if (kmem_ready_check() <= 0)
		return;

	been_ready = 1;
	(void) mdb_walk("kmem_cache", (mdb_walk_cb_t)kmem_init_walkers, NULL);
}

void
kmem_init(void)
{
	mdb_walker_t w = {
		"kmem_cache", "walk list of kmem caches", kmem_cache_walk_init,
		list_walk_step, list_walk_fini
	};

	/*
	 * If kmem is ready, we'll need to invoke the kmem_cache walker
	 * immediately.  Walkers in the linkage structure won't be ready until
	 * _mdb_init returns, so we'll need to add this one manually.  If kmem
	 * is ready, we'll use the walker to initialize the caches.  If kmem
	 * isn't ready, we'll register a callback that will allow us to defer
	 * cache walking until it is.
	 */
	if (mdb_add_walker(&w) != 0) {
		mdb_warn("failed to add kmem_cache walker");
		return;
	}

	kmem_statechange();

	/* register our ::whatis handlers */
	mdb_whatis_register("modules", whatis_run_modules, NULL,
	    WHATIS_PRIO_EARLY, WHATIS_REG_NO_ID);
	mdb_whatis_register("threads", whatis_run_threads, NULL,
	    WHATIS_PRIO_EARLY, WHATIS_REG_NO_ID);
	mdb_whatis_register("pages", whatis_run_pages, NULL,
	    WHATIS_PRIO_EARLY, WHATIS_REG_NO_ID);
	mdb_whatis_register("kmem", whatis_run_kmem, NULL,
	    WHATIS_PRIO_ALLOCATOR, 0);
	mdb_whatis_register("vmem", whatis_run_vmem, NULL,
	    WHATIS_PRIO_ALLOCATOR, 0);
}

typedef struct whatthread {
	uintptr_t	wt_target;
	int		wt_verbose;
} whatthread_t;

static int
whatthread_walk_thread(uintptr_t addr, const kthread_t *t, whatthread_t *w)
{
	uintptr_t current, data;

	if (t->t_stkbase == NULL)
		return (WALK_NEXT);

	/*
	 * Warn about swapped out threads, but drive on anyway
	 */
	if (!(t->t_schedflag & TS_LOAD)) {
		mdb_warn("thread %p's stack swapped out\n", addr);
		return (WALK_NEXT);
	}

	/*
	 * Search the thread's stack for the given pointer.  Note that it would
	 * be more efficient to follow ::kgrep's lead and read in page-sized
	 * chunks, but this routine is already fast and simple.
	 */
	for (current = (uintptr_t)t->t_stkbase; current < (uintptr_t)t->t_stk;
	    current += sizeof (uintptr_t)) {
		if (mdb_vread(&data, sizeof (data), current) == -1) {
			mdb_warn("couldn't read thread %p's stack at %p",
			    addr, current);
			return (WALK_ERR);
		}

		if (data == w->wt_target) {
			if (w->wt_verbose) {
				mdb_printf("%p in thread %p's stack%s\n",
				    current, addr, stack_active(t, current));
			} else {
				mdb_printf("%#lr\n", addr);
				return (WALK_NEXT);
			}
		}
	}

	return (WALK_NEXT);
}

int
whatthread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	whatthread_t w;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	w.wt_verbose = FALSE;
	w.wt_target = addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &w.wt_verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_walk("thread", (mdb_walk_cb_t)whatthread_walk_thread, &w)
	    == -1) {
		mdb_warn("couldn't walk threads");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}
