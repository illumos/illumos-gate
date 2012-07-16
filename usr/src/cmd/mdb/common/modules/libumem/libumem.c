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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include "umem.h"
#include <libproc.h>
#include <mdb/mdb_modapi.h>

#include "kgrep.h"
#include "leaky.h"
#include "misc.h"
#include "proc_kludges.h"

#include <umem_impl.h>
#include <sys/vmem_impl_user.h>
#include <thr_uberdata.h>
#include <stdio.h>

#include "umem_pagesize.h"

typedef struct datafmt {
	char	*hdr1;
	char	*hdr2;
	char	*dashes;
	char	*fmt;
} datafmt_t;

static datafmt_t ptcfmt[] = {
	{ "   ",	"tid",		"---",		"%3u "		},
	{ " memory",	" cached",	"-------",	"%7lH "		},
	{ "  %",	"cap",		"---",		"%3u "		},
	{ "  %",	NULL,		"---",		"%3u "		},
	{ NULL,		NULL,		NULL,		NULL		}
};

static datafmt_t umemfmt[] = {
	{ "cache                    ", "name                     ",
	"-------------------------", "%-25s "				},
	{ "   buf",	"  size",	"------",	"%6u "		},
	{ "    buf",	" in use",	"-------",	"%7u "		},
	{ "    buf",	" in ptc",	"-------",	"%7s "		},
	{ "    buf",	"  total",	"-------",	"%7u "		},
	{ " memory",	" in use",	"-------",	"%7H "		},
	{ "    alloc",	"  succeed",	"---------",	"%9u "		},
	{ "alloc",	" fail",	"-----",	"%5llu"		},
	{ NULL,		NULL,		NULL,		NULL		}
};

static datafmt_t vmemfmt[] = {
	{ "vmem                     ", "name                     ",
	"-------------------------", "%-*s "				},
	{ "   memory",	"   in use",	"---------",	"%9H "		},
	{ "    memory",	"     total",	"----------",	"%10H "		},
	{ "   memory",	"   import",	"---------",	"%9H "		},
	{ "    alloc",	"  succeed",	"---------",	"%9llu "	},
	{ "alloc",	" fail",	"-----",	"%5llu "	},
	{ NULL,		NULL,		NULL,		NULL		}
};

/*ARGSUSED*/
static int
umastat_cpu_avail(uintptr_t addr, const umem_cpu_cache_t *ccp, int *avail)
{
	if (ccp->cc_rounds > 0)
		*avail += ccp->cc_rounds;
	if (ccp->cc_prounds > 0)
		*avail += ccp->cc_prounds;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_cpu_alloc(uintptr_t addr, const umem_cpu_cache_t *ccp, int *alloc)
{
	*alloc += ccp->cc_alloc;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_slab_avail(uintptr_t addr, const umem_slab_t *sp, int *avail)
{
	*avail += sp->slab_chunks - sp->slab_refcnt;

	return (WALK_NEXT);
}

typedef struct umastat_vmem {
	uintptr_t kv_addr;
	struct umastat_vmem *kv_next;
	int kv_meminuse;
	int kv_alloc;
	int kv_fail;
} umastat_vmem_t;

/*ARGSUSED*/
static int
umastat_cache_nptc(uintptr_t addr, const umem_cache_t *cp, int *nptc)
{
	if (!(cp->cache_flags & UMF_PTC))
		return (WALK_NEXT);

	(*nptc)++;
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_cache_hdr(uintptr_t addr, const umem_cache_t *cp, void *ignored)
{
	if (!(cp->cache_flags & UMF_PTC))
		return (WALK_NEXT);

	mdb_printf("%3d ", cp->cache_bufsize);
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_lwp_ptc(uintptr_t addr, void *buf, int *nbufs)
{
	(*nbufs)++;
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_lwp_cache(uintptr_t addr, const umem_cache_t *cp, ulwp_t *ulwp)
{
	char walk[60];
	int nbufs = 0;

	if (!(cp->cache_flags & UMF_PTC))
		return (WALK_NEXT);

	(void) snprintf(walk, sizeof (walk), "umem_ptc_%d", cp->cache_bufsize);

	if (mdb_pwalk(walk, (mdb_walk_cb_t)umastat_lwp_ptc,
	    &nbufs, (uintptr_t)ulwp->ul_self) == -1) {
		mdb_warn("unable to walk '%s'", walk);
		return (WALK_ERR);
	}

	mdb_printf("%3d ", ulwp->ul_tmem.tm_size ?
	    (nbufs * cp->cache_bufsize * 100) / ulwp->ul_tmem.tm_size : 0);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_lwp(uintptr_t addr, const ulwp_t *ulwp, void *ignored)
{
	size_t size;
	datafmt_t *dfp = ptcfmt;

	mdb_printf((dfp++)->fmt, ulwp->ul_lwpid);
	mdb_printf((dfp++)->fmt, ulwp->ul_tmem.tm_size);

	if (umem_readvar(&size, "umem_ptc_size") == -1) {
		mdb_warn("unable to read 'umem_ptc_size'");
		return (WALK_ERR);
	}

	mdb_printf((dfp++)->fmt, (ulwp->ul_tmem.tm_size * 100) / size);

	if (mdb_walk("umem_cache",
	    (mdb_walk_cb_t)umastat_lwp_cache, (void *)ulwp) == -1) {
		mdb_warn("can't walk 'umem_cache'");
		return (WALK_ERR);
	}

	mdb_printf("\n");

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_cache_ptc(uintptr_t addr, const void *ignored, int *nptc)
{
	(*nptc)++;
	return (WALK_NEXT);
}

static int
umastat_cache(uintptr_t addr, const umem_cache_t *cp, umastat_vmem_t **kvp)
{
	umastat_vmem_t *kv;
	datafmt_t *dfp = umemfmt;
	char buf[10];
	int magsize;

	int avail, alloc, total, nptc = 0;
	size_t meminuse = (cp->cache_slab_create - cp->cache_slab_destroy) *
	    cp->cache_slabsize;

	mdb_walk_cb_t cpu_avail = (mdb_walk_cb_t)umastat_cpu_avail;
	mdb_walk_cb_t cpu_alloc = (mdb_walk_cb_t)umastat_cpu_alloc;
	mdb_walk_cb_t slab_avail = (mdb_walk_cb_t)umastat_slab_avail;

	magsize = umem_get_magsize(cp);

	alloc = cp->cache_slab_alloc + cp->cache_full.ml_alloc;
	avail = cp->cache_full.ml_total * magsize;
	total = cp->cache_buftotal;

	(void) mdb_pwalk("umem_cpu_cache", cpu_alloc, &alloc, addr);
	(void) mdb_pwalk("umem_cpu_cache", cpu_avail, &avail, addr);
	(void) mdb_pwalk("umem_slab_partial", slab_avail, &avail, addr);

	if (cp->cache_flags & UMF_PTC) {
		char walk[60];

		(void) snprintf(walk, sizeof (walk),
		    "umem_ptc_%d", cp->cache_bufsize);

		if (mdb_walk(walk,
		    (mdb_walk_cb_t)umastat_cache_ptc, &nptc) == -1) {
			mdb_warn("unable to walk '%s'", walk);
			return (WALK_ERR);
		}

		(void) snprintf(buf, sizeof (buf), "%d", nptc);
	}

	for (kv = *kvp; kv != NULL; kv = kv->kv_next) {
		if (kv->kv_addr == (uintptr_t)cp->cache_arena)
			goto out;
	}

	kv = mdb_zalloc(sizeof (umastat_vmem_t), UM_SLEEP | UM_GC);
	kv->kv_next = *kvp;
	kv->kv_addr = (uintptr_t)cp->cache_arena;
	*kvp = kv;
out:
	kv->kv_meminuse += meminuse;
	kv->kv_alloc += alloc;
	kv->kv_fail += cp->cache_alloc_fail;

	mdb_printf((dfp++)->fmt, cp->cache_name);
	mdb_printf((dfp++)->fmt, cp->cache_bufsize);
	mdb_printf((dfp++)->fmt, total - avail);
	mdb_printf((dfp++)->fmt, cp->cache_flags & UMF_PTC ? buf : "-");
	mdb_printf((dfp++)->fmt, total);
	mdb_printf((dfp++)->fmt, meminuse);
	mdb_printf((dfp++)->fmt, alloc);
	mdb_printf((dfp++)->fmt, cp->cache_alloc_fail);
	mdb_printf("\n");

	return (WALK_NEXT);
}

static int
umastat_vmem_totals(uintptr_t addr, const vmem_t *v, umastat_vmem_t *kv)
{
	while (kv != NULL && kv->kv_addr != addr)
		kv = kv->kv_next;

	if (kv == NULL || kv->kv_alloc == 0)
		return (WALK_NEXT);

	mdb_printf("Total [%s]%*s %6s %7s %7s %7s %7H %9u %5u\n", v->vm_name,
	    17 - strlen(v->vm_name), "", "", "", "", "",
	    kv->kv_meminuse, kv->kv_alloc, kv->kv_fail);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
umastat_vmem(uintptr_t addr, const vmem_t *v, void *ignored)
{
	datafmt_t *dfp = vmemfmt;
	uintptr_t paddr;
	vmem_t parent;
	int ident = 0;

	for (paddr = (uintptr_t)v->vm_source; paddr != NULL; ident += 4) {
		if (mdb_vread(&parent, sizeof (parent), paddr) == -1) {
			mdb_warn("couldn't trace %p's ancestry", addr);
			ident = 0;
			break;
		}
		paddr = (uintptr_t)parent.vm_source;
	}

	mdb_printf("%*s", ident, "");
	mdb_printf((dfp++)->fmt, 25 - ident, v->vm_name);
	mdb_printf((dfp++)->fmt, v->vm_kstat.vk_mem_inuse);
	mdb_printf((dfp++)->fmt, v->vm_kstat.vk_mem_total);
	mdb_printf((dfp++)->fmt, v->vm_kstat.vk_mem_import);
	mdb_printf((dfp++)->fmt, v->vm_kstat.vk_alloc);
	mdb_printf((dfp++)->fmt, v->vm_kstat.vk_fail);

	mdb_printf("\n");

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
umastat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	umastat_vmem_t *kv = NULL;
	datafmt_t *dfp;
	int nptc = 0, i;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * We need to determine if we have any caches that have per-thread
	 * caching enabled.
	 */
	if (mdb_walk("umem_cache",
	    (mdb_walk_cb_t)umastat_cache_nptc, &nptc) == -1) {
		mdb_warn("can't walk 'umem_cache'");
		return (DCMD_ERR);
	}

	if (nptc) {
		for (dfp = ptcfmt; dfp->hdr2 != NULL; dfp++)
			mdb_printf("%s ", dfp->hdr1);

		for (i = 0; i < nptc; i++)
			mdb_printf("%s ", dfp->hdr1);

		mdb_printf("\n");

		for (dfp = ptcfmt; dfp->hdr2 != NULL; dfp++)
			mdb_printf("%s ", dfp->hdr2);

		if (mdb_walk("umem_cache",
		    (mdb_walk_cb_t)umastat_cache_hdr, NULL) == -1) {
			mdb_warn("can't walk 'umem_cache'");
			return (DCMD_ERR);
		}

		mdb_printf("\n");

		for (dfp = ptcfmt; dfp->hdr2 != NULL; dfp++)
			mdb_printf("%s ", dfp->dashes);

		for (i = 0; i < nptc; i++)
			mdb_printf("%s ", dfp->dashes);

		mdb_printf("\n");

		if (mdb_walk("ulwp", (mdb_walk_cb_t)umastat_lwp, NULL) == -1) {
			mdb_warn("can't walk 'ulwp'");
			return (DCMD_ERR);
		}

		mdb_printf("\n");
	}

	for (dfp = umemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s%s", dfp == umemfmt ? "" : " ", dfp->hdr1);
	mdb_printf("\n");

	for (dfp = umemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s%s", dfp == umemfmt ? "" : " ", dfp->hdr2);
	mdb_printf("\n");

	for (dfp = umemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s%s", dfp == umemfmt ? "" : " ", dfp->dashes);
	mdb_printf("\n");

	if (mdb_walk("umem_cache", (mdb_walk_cb_t)umastat_cache, &kv) == -1) {
		mdb_warn("can't walk 'umem_cache'");
		return (DCMD_ERR);
	}

	for (dfp = umemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s%s", dfp == umemfmt ? "" : " ", dfp->dashes);
	mdb_printf("\n");

	if (mdb_walk("vmem", (mdb_walk_cb_t)umastat_vmem_totals, kv) == -1) {
		mdb_warn("can't walk 'vmem'");
		return (DCMD_ERR);
	}

	for (dfp = umemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr1);
	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->hdr2);
	mdb_printf("\n");

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");

	if (mdb_walk("vmem", (mdb_walk_cb_t)umastat_vmem, NULL) == -1) {
		mdb_warn("can't walk 'vmem'");
		return (DCMD_ERR);
	}

	for (dfp = vmemfmt; dfp->hdr1 != NULL; dfp++)
		mdb_printf("%s ", dfp->dashes);
	mdb_printf("\n");
	return (DCMD_OK);
}

/*
 * kmdb doesn't use libproc, and thus doesn't have any prmap_t's to walk.
 * We have other ways to grep kmdb's address range.
 */
#ifndef _KMDB

typedef struct ugrep_walk_data {
	kgrep_cb_func *ug_cb;
	void *ug_cbdata;
} ugrep_walk_data_t;

/*ARGSUSED*/
int
ugrep_mapping_cb(uintptr_t addr, const void *prm_arg, void *data)
{
	ugrep_walk_data_t *ug = data;
	const prmap_t *prm = prm_arg;

	return (ug->ug_cb(prm->pr_vaddr, prm->pr_vaddr + prm->pr_size,
	    ug->ug_cbdata));
}

int
kgrep_subr(kgrep_cb_func *cb, void *cbdata)
{
	ugrep_walk_data_t ug;

	prockludge_add_walkers();

	ug.ug_cb = cb;
	ug.ug_cbdata = cbdata;

	if (mdb_walk(KLUDGE_MAPWALK_NAME, ugrep_mapping_cb, &ug) == -1) {
		mdb_warn("Unable to walk "KLUDGE_MAPWALK_NAME);
		return (DCMD_ERR);
	}

	prockludge_remove_walkers();
	return (DCMD_OK);
}

size_t
kgrep_subr_pagesize(void)
{
	return (PAGESIZE);
}

#endif /* !_KMDB */

static const mdb_dcmd_t dcmds[] = {

	/* from libumem.c */
	{ "umastat", NULL, "umem allocator stats", umastat },

	/* from misc.c */
	{ "umem_debug", NULL, "toggle umem dcmd/walk debugging", umem_debug},

	/* from umem.c */
	{ "umem_status", NULL, "Print umem status and message buffer",
		umem_status },
	{ "allocdby", ":", "given a thread, print its allocated buffers",
		allocdby },
	{ "bufctl", ":[-vh] [-a addr] [-c caller] [-e earliest] [-l latest] "
		"[-t thd]", "print or filter a bufctl", bufctl, bufctl_help },
	{ "bufctl_audit", ":", "print a bufctl_audit", bufctl_audit },
	{ "freedby", ":", "given a thread, print its freed buffers", freedby },
	{ "umalog", "[ fail | slab ]",
	    "display umem transaction log and stack traces", umalog },
	{ "umausers", "[-ef] [cache ...]", "display current medium and large "
		"users of the umem allocator", umausers },
	{ "umem_cache", "?", "print a umem cache", umem_cache },
	{ "umem_log", "?", "dump umem transaction log", umem_log },
	{ "umem_malloc_dist", "[-dg] [-b maxbins] [-B minbinsize]",
		"report distribution of outstanding malloc()s",
		umem_malloc_dist, umem_malloc_dist_help },
	{ "umem_malloc_info", "?[-dg] [-b maxbins] [-B minbinsize]",
		"report information about malloc()s by cache",
		umem_malloc_info, umem_malloc_info_help },
	{ "umem_verify", "?", "check integrity of umem-managed memory",
		umem_verify },
	{ "vmem", "?", "print a vmem_t", vmem },
	{ "vmem_seg", ":[-sv] [-c caller] [-e earliest] [-l latest] "
		"[-m minsize] [-M maxsize] [-t thread] [-T type]",
		"print or filter a vmem_seg", vmem_seg, vmem_seg_help },

#ifndef _KMDB
	/* from ../genunix/kgrep.c + libumem.c */
	{ "ugrep", KGREP_USAGE, "search user address space for a pointer",
	    kgrep, kgrep_help },

	/* from ../genunix/leaky.c + leaky_subr.c */
	{ "findleaks", FINDLEAKS_USAGE, "search for potential memory leaks",
	    findleaks, findleaks_help },
#endif

	{ NULL }
};

static const mdb_walker_t walkers[] = {

	/* from umem.c */
	{ "allocdby", "given a thread, walk its allocated bufctls",
		allocdby_walk_init, allocdby_walk_step, allocdby_walk_fini },
	{ "bufctl", "walk a umem cache's bufctls",
		bufctl_walk_init, umem_walk_step, umem_walk_fini },
	{ "bufctl_history", "walk the available history of a bufctl",
		bufctl_history_walk_init, bufctl_history_walk_step,
		bufctl_history_walk_fini },
	{ "freectl", "walk a umem cache's free bufctls",
		freectl_walk_init, umem_walk_step, umem_walk_fini },
	{ "freedby", "given a thread, walk its freed bufctls",
		freedby_walk_init, allocdby_walk_step, allocdby_walk_fini },
	{ "freemem", "walk a umem cache's free memory",
		freemem_walk_init, umem_walk_step, umem_walk_fini },
	{ "umem", "walk a umem cache",
		umem_walk_init, umem_walk_step, umem_walk_fini },
	{ "umem_cpu", "walk the umem CPU structures",
		umem_cpu_walk_init, umem_cpu_walk_step, umem_cpu_walk_fini },
	{ "umem_cpu_cache", "given a umem cache, walk its per-CPU caches",
		umem_cpu_cache_walk_init, umem_cpu_cache_walk_step, NULL },
	{ "umem_hash", "given a umem cache, walk its allocated hash table",
		umem_hash_walk_init, umem_hash_walk_step, umem_hash_walk_fini },
	{ "umem_log", "walk the umem transaction log",
		umem_log_walk_init, umem_log_walk_step, umem_log_walk_fini },
	{ "umem_slab", "given a umem cache, walk its slabs",
		umem_slab_walk_init, umem_slab_walk_step, NULL },
	{ "umem_slab_partial",
	    "given a umem cache, walk its partially allocated slabs (min 1)",
		umem_slab_walk_partial_init, umem_slab_walk_step, NULL },
	{ "vmem", "walk vmem structures in pre-fix, depth-first order",
		vmem_walk_init, vmem_walk_step, vmem_walk_fini },
	{ "vmem_alloc", "given a vmem_t, walk its allocated vmem_segs",
		vmem_alloc_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_free", "given a vmem_t, walk its free vmem_segs",
		vmem_free_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_postfix", "walk vmem structures in post-fix, depth-first order",
		vmem_walk_init, vmem_postfix_walk_step, vmem_walk_fini },
	{ "vmem_seg", "given a vmem_t, walk all of its vmem_segs",
		vmem_seg_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },
	{ "vmem_span", "given a vmem_t, walk its spanning vmem_segs",
		vmem_span_walk_init, vmem_seg_walk_step, vmem_seg_walk_fini },

#ifndef _KMDB
	/* from ../genunix/leaky.c + leaky_subr.c */
	{ "leak", "given a leak ctl, walk other leaks w/ that stacktrace",
		leaky_walk_init, leaky_walk_step, leaky_walk_fini },
	{ "leakbuf", "given a leak ctl, walk addr of leaks w/ that stacktrace",
		leaky_walk_init, leaky_buf_walk_step, leaky_walk_fini },
#endif

	{ NULL }
};

static const mdb_modinfo_t modinfo = {MDB_API_VERSION, dcmds, walkers};

const mdb_modinfo_t *
_mdb_init(void)
{
	if (umem_init() != 0)
		return (NULL);

	return (&modinfo);
}

void
_mdb_fini(void)
{
#ifndef _KMDB
	leaky_cleanup(1);
#endif
}
