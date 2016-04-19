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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/swap.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <sys/thread.h>
#include <sys/swap.h>
#include <sys/memlist.h>
#include <sys/vnode.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#if defined(__i386) || defined(__amd64)
#include <sys/balloon_impl.h>
#endif

#include "avl.h"
#include "memory.h"

/*
 * Page walker.
 * By default, this will walk all pages in the system.  If given an
 * address, it will walk all pages belonging to the vnode at that
 * address.
 */

/*
 * page_walk_data
 *
 * pw_hashleft is set to -1 when walking a vnode's pages, and holds the
 * number of hash locations remaining in the page hash table when
 * walking all pages.
 *
 * The astute reader will notice that pw_hashloc is only used when
 * reading all pages (to hold a pointer to our location in the page
 * hash table), and that pw_first is only used when reading the pages
 * belonging to a particular vnode (to hold a pointer to the first
 * page).  While these could be combined to be a single pointer, they
 * are left separate for clarity.
 */
typedef struct page_walk_data {
	long		pw_hashleft;
	void		**pw_hashloc;
	uintptr_t	pw_first;
} page_walk_data_t;

int
page_walk_init(mdb_walk_state_t *wsp)
{
	page_walk_data_t	*pwd;
	void	**ptr;
	size_t	hashsz;
	vnode_t	vn;

	if (wsp->walk_addr == NULL) {

		/*
		 * Walk all pages
		 */

		if ((mdb_readvar(&ptr, "page_hash") == -1) ||
		    (mdb_readvar(&hashsz, "page_hashsz") == -1) ||
		    (ptr == NULL) || (hashsz == 0)) {
			mdb_warn("page_hash, page_hashsz not found or invalid");
			return (WALK_ERR);
		}

		/*
		 * Since we are walking all pages, initialize hashleft
		 * to be the remaining number of entries in the page
		 * hash.  hashloc is set the start of the page hash
		 * table.  Setting the walk address to 0 indicates that
		 * we aren't currently following a hash chain, and that
		 * we need to scan the page hash table for a page.
		 */
		pwd = mdb_alloc(sizeof (page_walk_data_t), UM_SLEEP);
		pwd->pw_hashleft = hashsz;
		pwd->pw_hashloc = ptr;
		wsp->walk_addr = 0;
	} else {

		/*
		 * Walk just this vnode
		 */

		if (mdb_vread(&vn, sizeof (vnode_t), wsp->walk_addr) == -1) {
			mdb_warn("unable to read vnode_t at %#lx",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		/*
		 * We set hashleft to -1 to indicate that we are
		 * walking a vnode, and initialize first to 0 (it is
		 * used to terminate the walk, so it must not be set
		 * until after we have walked the first page).  The
		 * walk address is set to the first page.
		 */
		pwd = mdb_alloc(sizeof (page_walk_data_t), UM_SLEEP);
		pwd->pw_hashleft = -1;
		pwd->pw_first = 0;

		wsp->walk_addr = (uintptr_t)vn.v_pages;
	}

	wsp->walk_data = pwd;

	return (WALK_NEXT);
}

int
page_walk_step(mdb_walk_state_t *wsp)
{
	page_walk_data_t	*pwd = wsp->walk_data;
	page_t		page;
	uintptr_t	pp;

	pp = wsp->walk_addr;

	if (pwd->pw_hashleft < 0) {

		/* We're walking a vnode's pages */

		/*
		 * If we don't have any pages to walk, we have come
		 * back around to the first one (we finished), or we
		 * can't read the page we're looking at, we are done.
		 */
		if (pp == NULL || pp == pwd->pw_first)
			return (WALK_DONE);
		if (mdb_vread(&page, sizeof (page_t), pp) == -1) {
			mdb_warn("unable to read page_t at %#lx", pp);
			return (WALK_ERR);
		}

		/*
		 * Set the walk address to the next page, and if the
		 * first page hasn't been set yet (i.e. we are on the
		 * first page), set it.
		 */
		wsp->walk_addr = (uintptr_t)page.p_vpnext;
		if (pwd->pw_first == NULL)
			pwd->pw_first = pp;

	} else if (pwd->pw_hashleft > 0) {

		/* We're walking all pages */

		/*
		 * If pp (the walk address) is NULL, we scan through
		 * the page hash table until we find a page.
		 */
		if (pp == NULL) {

			/*
			 * Iterate through the page hash table until we
			 * find a page or reach the end.
			 */
			do {
				if (mdb_vread(&pp, sizeof (uintptr_t),
				    (uintptr_t)pwd->pw_hashloc) == -1) {
					mdb_warn("unable to read from %#p",
					    pwd->pw_hashloc);
					return (WALK_ERR);
				}
				pwd->pw_hashleft--;
				pwd->pw_hashloc++;
			} while (pwd->pw_hashleft && (pp == NULL));

			/*
			 * We've reached the end; exit.
			 */
			if (pp == NULL)
				return (WALK_DONE);
		}

		if (mdb_vread(&page, sizeof (page_t), pp) == -1) {
			mdb_warn("unable to read page_t at %#lx", pp);
			return (WALK_ERR);
		}

		/*
		 * Set the walk address to the next page.
		 */
		wsp->walk_addr = (uintptr_t)page.p_hash;

	} else {
		/* We've finished walking all pages. */
		return (WALK_DONE);
	}

	return (wsp->walk_callback(pp, &page, wsp->walk_cbdata));
}

void
page_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (page_walk_data_t));
}

/*
 * allpages walks all pages in the system in order they appear in
 * the memseg structure
 */

#define	PAGE_BUFFER	128

int
allpages_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("allpages only supports global walks.\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("memseg", wsp) == -1) {
		mdb_warn("couldn't walk 'memseg'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (page_t) * PAGE_BUFFER, UM_SLEEP);
	return (WALK_NEXT);
}

int
allpages_walk_step(mdb_walk_state_t *wsp)
{
	const struct memseg *msp = wsp->walk_layer;
	page_t *buf = wsp->walk_data;
	size_t pg_read, i;
	size_t pg_num = msp->pages_end - msp->pages_base;
	const page_t *pg_addr = msp->pages;

	while (pg_num > 0) {
		pg_read = MIN(pg_num, PAGE_BUFFER);

		if (mdb_vread(buf, pg_read * sizeof (page_t),
		    (uintptr_t)pg_addr) == -1) {
			mdb_warn("can't read page_t's at %#lx", pg_addr);
			return (WALK_ERR);
		}
		for (i = 0; i < pg_read; i++) {
			int ret = wsp->walk_callback((uintptr_t)&pg_addr[i],
			    &buf[i], wsp->walk_cbdata);

			if (ret != WALK_NEXT)
				return (ret);
		}
		pg_num -= pg_read;
		pg_addr += pg_read;
	}

	return (WALK_NEXT);
}

void
allpages_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (page_t) * PAGE_BUFFER);
}

/*
 * Hash table + LRU queue.
 * This table is used to cache recently read vnodes for the memstat
 * command, to reduce the number of mdb_vread calls.  This greatly
 * speeds the memstat command on on live, large CPU count systems.
 */

#define	VN_SMALL	401
#define	VN_LARGE	10007
#define	VN_HTABLE_KEY(p, hp)	((p) % ((hp)->vn_htable_buckets))

struct vn_htable_list {
	uint_t vn_flag;				/* v_flag from vnode	*/
	uintptr_t vn_ptr;			/* pointer to vnode	*/
	struct vn_htable_list *vn_q_next;	/* queue next pointer	*/
	struct vn_htable_list *vn_q_prev;	/* queue prev pointer	*/
	struct vn_htable_list *vn_h_next;	/* hash table pointer	*/
};

/*
 * vn_q_first        -> points to to head of queue: the vnode that was most
 *                      recently used
 * vn_q_last         -> points to the oldest used vnode, and is freed once a new
 *                      vnode is read.
 * vn_htable         -> hash table
 * vn_htable_buf     -> contains htable objects
 * vn_htable_size    -> total number of items in the hash table
 * vn_htable_buckets -> number of buckets in the hash table
 */
typedef struct vn_htable {
	struct vn_htable_list  *vn_q_first;
	struct vn_htable_list  *vn_q_last;
	struct vn_htable_list **vn_htable;
	struct vn_htable_list  *vn_htable_buf;
	int vn_htable_size;
	int vn_htable_buckets;
} vn_htable_t;


/* allocate memory, initilize hash table and LRU queue */
static void
vn_htable_init(vn_htable_t *hp, size_t vn_size)
{
	int i;
	int htable_size = MAX(vn_size, VN_LARGE);

	if ((hp->vn_htable_buf = mdb_zalloc(sizeof (struct vn_htable_list)
	    * htable_size, UM_NOSLEEP|UM_GC)) == NULL) {
		htable_size = VN_SMALL;
		hp->vn_htable_buf = mdb_zalloc(sizeof (struct vn_htable_list)
		    * htable_size, UM_SLEEP|UM_GC);
	}

	hp->vn_htable = mdb_zalloc(sizeof (struct vn_htable_list *)
	    * htable_size, UM_SLEEP|UM_GC);

	hp->vn_q_first  = &hp->vn_htable_buf[0];
	hp->vn_q_last   = &hp->vn_htable_buf[htable_size - 1];
	hp->vn_q_first->vn_q_next = &hp->vn_htable_buf[1];
	hp->vn_q_last->vn_q_prev = &hp->vn_htable_buf[htable_size - 2];

	for (i = 1; i < (htable_size-1); i++) {
		hp->vn_htable_buf[i].vn_q_next = &hp->vn_htable_buf[i + 1];
		hp->vn_htable_buf[i].vn_q_prev = &hp->vn_htable_buf[i - 1];
	}

	hp->vn_htable_size = htable_size;
	hp->vn_htable_buckets = htable_size;
}


/*
 * Find the vnode whose address is ptr, and return its v_flag in vp->v_flag.
 * The function tries to find needed information in the following order:
 *
 * 1. check if ptr is the first in queue
 * 2. check if ptr is in hash table (if so move it to the top of queue)
 * 3. do mdb_vread, remove last queue item from queue and hash table.
 *    Insert new information to freed object, and put this object in to the
 *    top of the queue.
 */
static int
vn_get(vn_htable_t *hp, struct vnode *vp, uintptr_t ptr)
{
	int hkey;
	struct vn_htable_list *hent, **htmp, *q_next, *q_prev;
	struct vn_htable_list  *q_first = hp->vn_q_first;

	/* 1. vnode ptr is the first in queue, just get v_flag and return */
	if (q_first->vn_ptr == ptr) {
		vp->v_flag = q_first->vn_flag;

		return (0);
	}

	/* 2. search the hash table for this ptr */
	hkey = VN_HTABLE_KEY(ptr, hp);
	hent = hp->vn_htable[hkey];
	while (hent && (hent->vn_ptr != ptr))
		hent = hent->vn_h_next;

	/* 3. if hent is NULL, we did not find in hash table, do mdb_vread */
	if (hent == NULL) {
		struct vnode vn;

		if (mdb_vread(&vn, sizeof (vnode_t), ptr) == -1) {
			mdb_warn("unable to read vnode_t at %#lx", ptr);
			return (-1);
		}

		/* we will insert read data into the last element in queue */
		hent = hp->vn_q_last;

		/* remove last hp->vn_q_last object from hash table */
		if (hent->vn_ptr) {
			htmp = &hp->vn_htable[VN_HTABLE_KEY(hent->vn_ptr, hp)];
			while (*htmp != hent)
				htmp = &(*htmp)->vn_h_next;
			*htmp = hent->vn_h_next;
		}

		/* insert data into new free object */
		hent->vn_ptr  = ptr;
		hent->vn_flag = vn.v_flag;

		/* insert new object into hash table */
		hent->vn_h_next = hp->vn_htable[hkey];
		hp->vn_htable[hkey] = hent;
	}

	/* Remove from queue. hent is not first, vn_q_prev is not NULL */
	q_next = hent->vn_q_next;
	q_prev = hent->vn_q_prev;
	if (q_next == NULL)
		hp->vn_q_last = q_prev;
	else
		q_next->vn_q_prev = q_prev;
	q_prev->vn_q_next = q_next;

	/* Add to the front of queue */
	hent->vn_q_prev = NULL;
	hent->vn_q_next = q_first;
	q_first->vn_q_prev = hent;
	hp->vn_q_first = hent;

	/* Set v_flag in vnode pointer from hent */
	vp->v_flag = hent->vn_flag;

	return (0);
}

/* Summary statistics of pages */
typedef struct memstat {
	struct vnode    *ms_kvp;	/* Cached address of kernel vnode */
	struct vnode    *ms_unused_vp;	/* Unused pages vnode pointer	  */
	struct vnode    *ms_zvp;	/* Cached address of zio vnode    */
	uint64_t	ms_kmem;	/* Pages of kernel memory	  */
	uint64_t	ms_zfs_data;	/* Pages of zfs data		  */
	uint64_t	ms_anon;	/* Pages of anonymous memory	  */
	uint64_t	ms_vnode;	/* Pages of named (vnode) memory  */
	uint64_t	ms_exec;	/* Pages of exec/library memory	  */
	uint64_t	ms_cachelist;	/* Pages on the cachelist (free)  */
	uint64_t	ms_bootpages;	/* Pages on the bootpages list    */
	uint64_t	ms_total;	/* Pages on page hash		  */
	vn_htable_t	*ms_vn_htable;	/* Pointer to hash table	  */
	struct vnode	ms_vn;		/* vnode buffer			  */
} memstat_t;

#define	MS_PP_ISKAS(pp, stats)				\
	((pp)->p_vnode == (stats)->ms_kvp)

#define	MS_PP_ISZFS_DATA(pp, stats)			\
	(((stats)->ms_zvp != NULL) && ((pp)->p_vnode == (stats)->ms_zvp))

/*
 * Summarize pages by type and update stat information
 */

/* ARGSUSED */
static int
memstat_callback(page_t *page, page_t *pp, memstat_t *stats)
{
	struct vnode *vp = &stats->ms_vn;

	if (PP_ISBOOTPAGES(pp))
		stats->ms_bootpages++;
	else if (pp->p_vnode == NULL || pp->p_vnode == stats->ms_unused_vp)
		return (WALK_NEXT);
	else if (MS_PP_ISKAS(pp, stats))
		stats->ms_kmem++;
	else if (MS_PP_ISZFS_DATA(pp, stats))
		stats->ms_zfs_data++;
	else if (PP_ISFREE(pp))
		stats->ms_cachelist++;
	else if (vn_get(stats->ms_vn_htable, vp, (uintptr_t)pp->p_vnode))
		return (WALK_ERR);
	else if (IS_SWAPFSVP(vp))
		stats->ms_anon++;
	else if ((vp->v_flag & VVMEXEC) != 0)
		stats->ms_exec++;
	else
		stats->ms_vnode++;

	stats->ms_total++;

	return (WALK_NEXT);
}

/* ARGSUSED */
int
memstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pgcnt_t total_pages, physmem;
	ulong_t freemem;
	memstat_t stats;
	GElf_Sym sym;
	vn_htable_t ht;
	struct vnode *kvps;
	uintptr_t vn_size = 0;
#if defined(__i386) || defined(__amd64)
	bln_stats_t bln_stats;
	ssize_t bln_size;
#endif

	bzero(&stats, sizeof (memstat_t));

	/*
	 * -s size, is an internal option. It specifies the size of vn_htable.
	 * Hash table size is set in the following order:
	 * If user has specified the size that is larger than VN_LARGE: try it,
	 * but if malloc failed default to VN_SMALL. Otherwise try VN_LARGE, if
	 * failed to allocate default to VN_SMALL.
	 * For a better efficiency of hash table it is highly recommended to
	 * set size to a prime number.
	 */
	if ((flags & DCMD_ADDRSPEC) || mdb_getopts(argc, argv,
	    's', MDB_OPT_UINTPTR, &vn_size, NULL) != argc)
		return (DCMD_USAGE);

	/* Initialize vnode hash list and queue */
	vn_htable_init(&ht, vn_size);
	stats.ms_vn_htable = &ht;

	/* Total physical memory */
	if (mdb_readvar(&total_pages, "total_pages") == -1) {
		mdb_warn("unable to read total_pages");
		return (DCMD_ERR);
	}

	/* Artificially limited memory */
	if (mdb_readvar(&physmem, "physmem") == -1) {
		mdb_warn("unable to read physmem");
		return (DCMD_ERR);
	}

	/* read kernel vnode array pointer */
	if (mdb_lookup_by_obj(MDB_OBJ_EXEC, "kvps",
	    (GElf_Sym *)&sym) == -1) {
		mdb_warn("unable to read kvps");
		return (DCMD_ERR);
	}
	kvps = (struct vnode *)(uintptr_t)sym.st_value;
	stats.ms_kvp =  &kvps[KV_KVP];

	/*
	 * Read the zio vnode pointer.
	 */
	stats.ms_zvp = &kvps[KV_ZVP];

	/*
	 * If physmem != total_pages, then the administrator has limited the
	 * number of pages available in the system.  Excluded pages are
	 * associated with the unused pages vnode.  Read this vnode so the
	 * pages can be excluded in the page accounting.
	 */
	if (mdb_lookup_by_obj(MDB_OBJ_EXEC, "unused_pages_vp",
	    (GElf_Sym *)&sym) == -1) {
		mdb_warn("unable to read unused_pages_vp");
		return (DCMD_ERR);
	}
	stats.ms_unused_vp = (struct vnode *)(uintptr_t)sym.st_value;

	/* walk all pages, collect statistics */
	if (mdb_walk("allpages", (mdb_walk_cb_t)memstat_callback,
	    &stats) == -1) {
		mdb_warn("can't walk memseg");
		return (DCMD_ERR);
	}

#define	MS_PCT_TOTAL(x)	((ulong_t)((((5 * total_pages) + ((x) * 1000ull))) / \
		((physmem) * 10)))

	mdb_printf("Page Summary                Pages                MB"
	    "  %%Tot\n");
	mdb_printf("------------     ----------------  ----------------"
	    "  ----\n");
	mdb_printf("Kernel           %16llu  %16llu  %3lu%%\n",
	    stats.ms_kmem,
	    (uint64_t)stats.ms_kmem * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_kmem));

	if (stats.ms_bootpages != 0) {
		mdb_printf("Boot pages       %16llu  %16llu  %3lu%%\n",
		    stats.ms_bootpages,
		    (uint64_t)stats.ms_bootpages * PAGESIZE / (1024 * 1024),
		    MS_PCT_TOTAL(stats.ms_bootpages));
	}

	if (stats.ms_zfs_data != 0) {
		mdb_printf("ZFS File Data    %16llu  %16llu  %3lu%%\n",
		    stats.ms_zfs_data,
		    (uint64_t)stats.ms_zfs_data * PAGESIZE / (1024 * 1024),
		    MS_PCT_TOTAL(stats.ms_zfs_data));
	}

	mdb_printf("Anon             %16llu  %16llu  %3lu%%\n",
	    stats.ms_anon,
	    (uint64_t)stats.ms_anon * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_anon));
	mdb_printf("Exec and libs    %16llu  %16llu  %3lu%%\n",
	    stats.ms_exec,
	    (uint64_t)stats.ms_exec * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_exec));
	mdb_printf("Page cache       %16llu  %16llu  %3lu%%\n",
	    stats.ms_vnode,
	    (uint64_t)stats.ms_vnode * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_vnode));
	mdb_printf("Free (cachelist) %16llu  %16llu  %3lu%%\n",
	    stats.ms_cachelist,
	    (uint64_t)stats.ms_cachelist * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_cachelist));

	/*
	 * occasionally, we double count pages above.  To avoid printing
	 * absurdly large values for freemem, we clamp it at zero.
	 */
	if (physmem > stats.ms_total)
		freemem = physmem - stats.ms_total;
	else
		freemem = 0;

#if defined(__i386) || defined(__amd64)
	/* Are we running under Xen?  If so, get balloon memory usage. */
	if ((bln_size = mdb_readvar(&bln_stats, "bln_stats")) != -1) {
		if (freemem > bln_stats.bln_hv_pages)
			freemem -= bln_stats.bln_hv_pages;
		else
			freemem = 0;
	}
#endif

	mdb_printf("Free (freelist)  %16lu  %16llu  %3lu%%\n", freemem,
	    (uint64_t)freemem * PAGESIZE / (1024 * 1024),
	    MS_PCT_TOTAL(freemem));

#if defined(__i386) || defined(__amd64)
	if (bln_size != -1) {
		mdb_printf("Balloon          %16lu  %16llu  %3lu%%\n",
		    bln_stats.bln_hv_pages,
		    (uint64_t)bln_stats.bln_hv_pages * PAGESIZE / (1024 * 1024),
		    MS_PCT_TOTAL(bln_stats.bln_hv_pages));
	}
#endif

	mdb_printf("\nTotal            %16lu  %16lu\n",
	    physmem,
	    (uint64_t)physmem * PAGESIZE / (1024 * 1024));

	if (physmem != total_pages) {
		mdb_printf("Physical         %16lu  %16lu\n",
		    total_pages,
		    (uint64_t)total_pages * PAGESIZE / (1024 * 1024));
	}

#undef MS_PCT_TOTAL

	return (DCMD_OK);
}

void
pagelookup_help(void)
{
	mdb_printf(
	    "Finds the page with name { %<b>vp%</b>, %<b>offset%</b> }.\n"
	    "\n"
	    "Can be invoked three different ways:\n\n"
	    "    ::pagelookup -v %<b>vp%</b> -o %<b>offset%</b>\n"
	    "    %<b>vp%</b>::pagelookup -o %<b>offset%</b>\n"
	    "    %<b>offset%</b>::pagelookup -v %<b>vp%</b>\n"
	    "\n"
	    "The latter two forms are useful in pipelines.\n");
}

int
pagelookup(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t vp = -(uintptr_t)1;
	uint64_t offset = -(uint64_t)1;

	uintptr_t pageaddr;
	int hasaddr = (flags & DCMD_ADDRSPEC);
	int usedaddr = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_UINTPTR, &vp,
	    'o', MDB_OPT_UINT64, &offset,
	    0) != argc) {
		return (DCMD_USAGE);
	}

	if (vp == -(uintptr_t)1) {
		if (offset == -(uint64_t)1) {
			mdb_warn(
			    "pagelookup: at least one of -v vp or -o offset "
			    "required.\n");
			return (DCMD_USAGE);
		}
		vp = addr;
		usedaddr = 1;
	} else if (offset == -(uint64_t)1) {
		offset = mdb_get_dot();
		usedaddr = 1;
	}
	if (usedaddr && !hasaddr) {
		mdb_warn("pagelookup: address required\n");
		return (DCMD_USAGE);
	}
	if (!usedaddr && hasaddr) {
		mdb_warn(
		    "pagelookup: address specified when both -v and -o were "
		    "passed");
		return (DCMD_USAGE);
	}

	pageaddr = mdb_page_lookup(vp, offset);
	if (pageaddr == 0) {
		mdb_warn("pagelookup: no page for {vp = %p, offset = %llp)\n",
		    vp, offset);
		return (DCMD_OK);
	}
	mdb_printf("%#lr\n", pageaddr);		/* this is PIPE_OUT friendly */
	return (DCMD_OK);
}

/*ARGSUSED*/
int
page_num2pp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t pp;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	pp = mdb_pfn2page((pfn_t)addr);
	if (pp == 0) {
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", pp);
	} else {
		mdb_printf("%lx has page_t at %#lx\n", (pfn_t)addr, pp);
	}

	return (DCMD_OK);
}

int
page(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	page_t	p;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("page", "page", argc, argv) == -1) {
			mdb_warn("can't walk pages");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %?s %16s %8s %3s %3s %2s %2s %2s%</u>\n",
		    "PAGE", "VNODE", "OFFSET", "SELOCK",
		    "LCT", "COW", "IO", "FS", "ST");
	}

	if (mdb_vread(&p, sizeof (page_t), addr) == -1) {
		mdb_warn("can't read page_t at %#lx", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx %?p %16llx %8x %3d %3d %2x %2x %2x\n",
	    addr, p.p_vnode, p.p_offset, p.p_selock, p.p_lckcnt, p.p_cowcnt,
	    p.p_iolock_state, p.p_fsdata, p.p_state);

	return (DCMD_OK);
}

int
swap_walk_init(mdb_walk_state_t *wsp)
{
	void	*ptr;

	if ((mdb_readvar(&ptr, "swapinfo") == -1) || ptr == NULL) {
		mdb_warn("swapinfo not found or invalid");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ptr;

	return (WALK_NEXT);
}

int
swap_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t	sip;
	struct swapinfo	si;

	sip = wsp->walk_addr;

	if (sip == NULL)
		return (WALK_DONE);

	if (mdb_vread(&si, sizeof (struct swapinfo), sip) == -1) {
		mdb_warn("unable to read swapinfo at %#lx", sip);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)si.si_next;

	return (wsp->walk_callback(sip, &si, wsp->walk_cbdata));
}

int
swapinfof(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct swapinfo	si;
	char		*name;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("swapinfo", "swapinfo", argc, argv) == -1) {
			mdb_warn("can't walk swapinfo");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %?s %9s %9s %s%</u>\n",
		    "ADDR", "VNODE", "PAGES", "FREE", "NAME");
	}

	if (mdb_vread(&si, sizeof (struct swapinfo), addr) == -1) {
		mdb_warn("can't read swapinfo at %#lx", addr);
		return (DCMD_ERR);
	}

	name = mdb_alloc(si.si_pnamelen, UM_SLEEP | UM_GC);
	if (mdb_vread(name, si.si_pnamelen, (uintptr_t)si.si_pname) == -1)
		name = "*error*";

	mdb_printf("%0?lx %?p %9d %9d %s\n",
	    addr, si.si_vp, si.si_npgs, si.si_nfpgs, name);

	return (DCMD_OK);
}

int
memlist_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t	mlp;
	struct memlist	ml;

	mlp = wsp->walk_addr;

	if (mlp == NULL)
		return (WALK_DONE);

	if (mdb_vread(&ml, sizeof (struct memlist), mlp) == -1) {
		mdb_warn("unable to read memlist at %#lx", mlp);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ml.ml_next;

	return (wsp->walk_callback(mlp, &ml, wsp->walk_cbdata));
}

int
memlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct memlist	ml;

	if (!(flags & DCMD_ADDRSPEC)) {
		uintptr_t ptr;
		uint_t list = 0;
		int i;
		static const char *lists[] = {
			"phys_install",
			"phys_avail",
			"virt_avail"
		};

		if (mdb_getopts(argc, argv,
		    'i', MDB_OPT_SETBITS, (1 << 0), &list,
		    'a', MDB_OPT_SETBITS, (1 << 1), &list,
		    'v', MDB_OPT_SETBITS, (1 << 2), &list, NULL) != argc)
			return (DCMD_USAGE);

		if (!list)
			list = 1;

		for (i = 0; list; i++, list >>= 1) {
			if (!(list & 1))
				continue;
			if ((mdb_readvar(&ptr, lists[i]) == -1) ||
			    (ptr == NULL)) {
				mdb_warn("%s not found or invalid", lists[i]);
				return (DCMD_ERR);
			}

			mdb_printf("%s:\n", lists[i]);
			if (mdb_pwalk_dcmd("memlist", "memlist", 0, NULL,
			    ptr) == -1) {
				mdb_warn("can't walk memlist");
				return (DCMD_ERR);
			}
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %16s %16s%</u>\n", "ADDR", "BASE", "SIZE");

	if (mdb_vread(&ml, sizeof (struct memlist), addr) == -1) {
		mdb_warn("can't read memlist at %#lx", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx %16llx %16llx\n", addr, ml.ml_address, ml.ml_size);

	return (DCMD_OK);
}

int
seg_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("seg walk must begin at struct as *\n");
		return (WALK_ERR);
	}

	/*
	 * this is really just a wrapper to AVL tree walk
	 */
	wsp->walk_addr = (uintptr_t)&((struct as *)wsp->walk_addr)->a_segtree;
	return (avl_walk_init(wsp));
}

/*ARGSUSED*/
int
seg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct seg s;

	if (argc != 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %?s %?s %?s %s%</u>\n",
		    "SEG", "BASE", "SIZE", "DATA", "OPS");
	}

	if (mdb_vread(&s, sizeof (s), addr) == -1) {
		mdb_warn("failed to read seg at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?lx %?p %a\n",
	    addr, s.s_base, s.s_size, s.s_data, s.s_ops);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pmap_walk_count_pages(uintptr_t addr, const void *data, void *out)
{
	pgcnt_t *nres = out;

	(*nres)++;

	return (WALK_NEXT);
}

static int
pmap_walk_seg(uintptr_t addr, const struct seg *seg, uintptr_t segvn)
{

	mdb_printf("%0?p %0?p %7dk", addr, seg->s_base, seg->s_size / 1024);

	if (segvn == (uintptr_t)seg->s_ops && seg->s_data != NULL) {
		struct segvn_data svn;
		pgcnt_t nres = 0;

		svn.vp = NULL;
		(void) mdb_vread(&svn, sizeof (svn), (uintptr_t)seg->s_data);

		/*
		 * Use the segvn_pages walker to find all of the in-core pages
		 * for this mapping.
		 */
		if (mdb_pwalk("segvn_pages", pmap_walk_count_pages, &nres,
		    (uintptr_t)seg->s_data) == -1) {
			mdb_warn("failed to walk segvn_pages (s_data=%p)",
			    seg->s_data);
		}
		mdb_printf(" %7ldk", (nres * PAGESIZE) / 1024);

		if (svn.vp != NULL) {
			char buf[29];

			mdb_vnode2path((uintptr_t)svn.vp, buf, sizeof (buf));
			mdb_printf(" %s", buf);
		} else {
			mdb_printf(" [ anon ]");
		}
	} else {
		mdb_printf(" %8s [ &%a ]", "?", seg->s_ops);
	}

	mdb_printf("\n");
	return (WALK_NEXT);
}

static int
pmap_walk_seg_quick(uintptr_t addr, const struct seg *seg, uintptr_t segvn)
{
	mdb_printf("%0?p %0?p %7dk", addr, seg->s_base, seg->s_size / 1024);

	if (segvn == (uintptr_t)seg->s_ops && seg->s_data != NULL) {
		struct segvn_data svn;

		svn.vp = NULL;
		(void) mdb_vread(&svn, sizeof (svn), (uintptr_t)seg->s_data);

		if (svn.vp != NULL) {
			mdb_printf(" %0?p", svn.vp);
		} else {
			mdb_printf(" [ anon ]");
		}
	} else {
		mdb_printf(" [ &%a ]", seg->s_ops);
	}

	mdb_printf("\n");
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
pmap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t segvn;
	proc_t proc;
	uint_t quick = FALSE;
	mdb_walk_cb_t cb = (mdb_walk_cb_t)pmap_walk_seg;

	GElf_Sym sym;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'q', MDB_OPT_SETBITS, TRUE, &quick, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&proc, sizeof (proc), addr) == -1) {
		mdb_warn("failed to read proc at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("segvn_ops", &sym) == 0)
		segvn = (uintptr_t)sym.st_value;
	else
		segvn = NULL;

	mdb_printf("%?s %?s %8s ", "SEG", "BASE", "SIZE");

	if (quick) {
		mdb_printf("VNODE\n");
		cb = (mdb_walk_cb_t)pmap_walk_seg_quick;
	} else {
		mdb_printf("%8s %s\n", "RES", "PATH");
	}

	if (mdb_pwalk("seg", cb, (void *)segvn, (uintptr_t)proc.p_as) == -1) {
		mdb_warn("failed to walk segments of as %p", proc.p_as);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

typedef struct anon_walk_data {
	uintptr_t *aw_levone;
	uintptr_t *aw_levtwo;
	size_t aw_minslot;
	size_t aw_maxslot;
	pgcnt_t aw_nlevone;
	pgcnt_t aw_levone_ndx;
	size_t aw_levtwo_ndx;
	struct anon_map	*aw_ampp;
	struct anon_map aw_amp;
	struct anon_hdr	aw_ahp;
	int		aw_all;	/* report all anon pointers, even NULLs */
} anon_walk_data_t;

int
anon_walk_init_common(mdb_walk_state_t *wsp, ulong_t minslot, ulong_t maxslot)
{
	anon_walk_data_t *aw;

	if (wsp->walk_addr == NULL) {
		mdb_warn("anon walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	aw = mdb_alloc(sizeof (anon_walk_data_t), UM_SLEEP);
	aw->aw_ampp = (struct anon_map *)wsp->walk_addr;

	if (mdb_vread(&aw->aw_amp, sizeof (aw->aw_amp), wsp->walk_addr) == -1) {
		mdb_warn("failed to read anon map at %p", wsp->walk_addr);
		mdb_free(aw, sizeof (anon_walk_data_t));
		return (WALK_ERR);
	}

	if (mdb_vread(&aw->aw_ahp, sizeof (aw->aw_ahp),
	    (uintptr_t)(aw->aw_amp.ahp)) == -1) {
		mdb_warn("failed to read anon hdr ptr at %p", aw->aw_amp.ahp);
		mdb_free(aw, sizeof (anon_walk_data_t));
		return (WALK_ERR);
	}

	/* update min and maxslot with the given constraints */
	maxslot = MIN(maxslot, aw->aw_ahp.size);
	minslot = MIN(minslot, maxslot);

	if (aw->aw_ahp.size <= ANON_CHUNK_SIZE ||
	    (aw->aw_ahp.flags & ANON_ALLOC_FORCE)) {
		aw->aw_nlevone = maxslot;
		aw->aw_levone_ndx = minslot;
		aw->aw_levtwo = NULL;
	} else {
		aw->aw_nlevone =
		    (maxslot + ANON_CHUNK_OFF) >> ANON_CHUNK_SHIFT;
		aw->aw_levone_ndx = 0;
		aw->aw_levtwo =
		    mdb_zalloc(ANON_CHUNK_SIZE * sizeof (uintptr_t), UM_SLEEP);
	}

	aw->aw_levone =
	    mdb_alloc(aw->aw_nlevone * sizeof (uintptr_t), UM_SLEEP);
	aw->aw_all = (wsp->walk_arg == ANON_WALK_ALL);

	mdb_vread(aw->aw_levone, aw->aw_nlevone * sizeof (uintptr_t),
	    (uintptr_t)aw->aw_ahp.array_chunk);

	aw->aw_levtwo_ndx = 0;
	aw->aw_minslot = minslot;
	aw->aw_maxslot = maxslot;

out:
	wsp->walk_data = aw;
	return (0);
}

int
anon_walk_step(mdb_walk_state_t *wsp)
{
	anon_walk_data_t *aw = (anon_walk_data_t *)wsp->walk_data;
	struct anon anon;
	uintptr_t anonptr;
	ulong_t slot;

	/*
	 * Once we've walked through level one, we're done.
	 */
	if (aw->aw_levone_ndx >= aw->aw_nlevone) {
		return (WALK_DONE);
	}

	if (aw->aw_levtwo == NULL) {
		anonptr = aw->aw_levone[aw->aw_levone_ndx];
		aw->aw_levone_ndx++;
	} else {
		if (aw->aw_levtwo_ndx == 0) {
			uintptr_t levtwoptr;

			/* The first time through, skip to our first index. */
			if (aw->aw_levone_ndx == 0) {
				aw->aw_levone_ndx =
				    aw->aw_minslot / ANON_CHUNK_SIZE;
				aw->aw_levtwo_ndx =
				    aw->aw_minslot % ANON_CHUNK_SIZE;
			}

			levtwoptr = (uintptr_t)aw->aw_levone[aw->aw_levone_ndx];

			if (levtwoptr == NULL) {
				if (!aw->aw_all) {
					aw->aw_levtwo_ndx = 0;
					aw->aw_levone_ndx++;
					return (WALK_NEXT);
				}
				bzero(aw->aw_levtwo,
				    ANON_CHUNK_SIZE * sizeof (uintptr_t));

			} else if (mdb_vread(aw->aw_levtwo,
			    ANON_CHUNK_SIZE * sizeof (uintptr_t), levtwoptr) ==
			    -1) {
				mdb_warn("unable to read anon_map %p's "
				    "second-level map %d at %p",
				    aw->aw_ampp, aw->aw_levone_ndx,
				    levtwoptr);
				return (WALK_ERR);
			}
		}
		slot = aw->aw_levone_ndx * ANON_CHUNK_SIZE + aw->aw_levtwo_ndx;
		anonptr = aw->aw_levtwo[aw->aw_levtwo_ndx];

		/* update the indices for next time */
		aw->aw_levtwo_ndx++;
		if (aw->aw_levtwo_ndx == ANON_CHUNK_SIZE) {
			aw->aw_levtwo_ndx = 0;
			aw->aw_levone_ndx++;
		}

		/* make sure the slot # is in the requested range */
		if (slot >= aw->aw_maxslot) {
			return (WALK_DONE);
		}
	}

	if (anonptr != NULL) {
		mdb_vread(&anon, sizeof (anon), anonptr);
		return (wsp->walk_callback(anonptr, &anon, wsp->walk_cbdata));
	}
	if (aw->aw_all) {
		return (wsp->walk_callback(NULL, NULL, wsp->walk_cbdata));
	}
	return (WALK_NEXT);
}

void
anon_walk_fini(mdb_walk_state_t *wsp)
{
	anon_walk_data_t *aw = (anon_walk_data_t *)wsp->walk_data;

	if (aw->aw_levtwo != NULL)
		mdb_free(aw->aw_levtwo, ANON_CHUNK_SIZE * sizeof (uintptr_t));

	mdb_free(aw->aw_levone, aw->aw_nlevone * sizeof (uintptr_t));
	mdb_free(aw, sizeof (anon_walk_data_t));
}

int
anon_walk_init(mdb_walk_state_t *wsp)
{
	return (anon_walk_init_common(wsp, 0, ULONG_MAX));
}

int
segvn_anon_walk_init(mdb_walk_state_t *wsp)
{
	const uintptr_t		svd_addr = wsp->walk_addr;
	uintptr_t		amp_addr;
	uintptr_t		seg_addr;
	struct segvn_data	svd;
	struct anon_map		amp;
	struct seg		seg;

	if (svd_addr == NULL) {
		mdb_warn("segvn_anon walk doesn't support global walks\n");
		return (WALK_ERR);
	}
	if (mdb_vread(&svd, sizeof (svd), svd_addr) == -1) {
		mdb_warn("segvn_anon walk: unable to read segvn_data at %p",
		    svd_addr);
		return (WALK_ERR);
	}
	if (svd.amp == NULL) {
		mdb_warn("segvn_anon walk: segvn_data at %p has no anon map\n",
		    svd_addr);
		return (WALK_ERR);
	}
	amp_addr = (uintptr_t)svd.amp;
	if (mdb_vread(&amp, sizeof (amp), amp_addr) == -1) {
		mdb_warn("segvn_anon walk: unable to read amp %p for "
		    "segvn_data %p", amp_addr, svd_addr);
		return (WALK_ERR);
	}
	seg_addr = (uintptr_t)svd.seg;
	if (mdb_vread(&seg, sizeof (seg), seg_addr) == -1) {
		mdb_warn("segvn_anon walk: unable to read seg %p for "
		    "segvn_data %p", seg_addr, svd_addr);
		return (WALK_ERR);
	}
	if ((seg.s_size + (svd.anon_index << PAGESHIFT)) > amp.size) {
		mdb_warn("anon map %p is too small for segment %p\n",
		    amp_addr, seg_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = amp_addr;
	return (anon_walk_init_common(wsp,
	    svd.anon_index, svd.anon_index + (seg.s_size >> PAGESHIFT)));
}


typedef struct {
	u_offset_t		svs_offset;
	uintptr_t		svs_page;
} segvn_sparse_t;
#define	SEGVN_MAX_SPARSE	((128 * 1024) / sizeof (segvn_sparse_t))

typedef struct {
	uintptr_t		svw_svdp;
	struct segvn_data	svw_svd;
	struct seg		svw_seg;
	size_t			svw_walkoff;
	ulong_t			svw_anonskip;
	segvn_sparse_t		*svw_sparse;
	size_t			svw_sparse_idx;
	size_t			svw_sparse_count;
	size_t			svw_sparse_size;
	uint8_t			svw_sparse_overflow;
	uint8_t			svw_all;
} segvn_walk_data_t;

static int
segvn_sparse_fill(uintptr_t addr, const void *pp_arg, void *arg)
{
	segvn_walk_data_t	*const	svw = arg;
	const page_t		*const	pp = pp_arg;
	const u_offset_t		offset = pp->p_offset;
	segvn_sparse_t		*const	cur =
	    &svw->svw_sparse[svw->svw_sparse_count];

	/* See if the page is of interest */
	if ((u_offset_t)(offset - svw->svw_svd.offset) >= svw->svw_seg.s_size) {
		return (WALK_NEXT);
	}
	/* See if we have space for the new entry, then add it. */
	if (svw->svw_sparse_count >= svw->svw_sparse_size) {
		svw->svw_sparse_overflow = 1;
		return (WALK_DONE);
	}
	svw->svw_sparse_count++;
	cur->svs_offset = offset;
	cur->svs_page = addr;
	return (WALK_NEXT);
}

static int
segvn_sparse_cmp(const void *lp, const void *rp)
{
	const segvn_sparse_t *const	l = lp;
	const segvn_sparse_t *const	r = rp;

	if (l->svs_offset < r->svs_offset) {
		return (-1);
	}
	if (l->svs_offset > r->svs_offset) {
		return (1);
	}
	return (0);
}

/*
 * Builds on the "anon_all" walker to walk all resident pages in a segvn_data
 * structure.  For segvn_datas without an anon structure, it just looks up
 * pages in the vnode.  For segvn_datas with an anon structure, NULL slots
 * pass through to the vnode, and non-null slots are checked for residency.
 */
int
segvn_pages_walk_init(mdb_walk_state_t *wsp)
{
	segvn_walk_data_t	*svw;
	struct segvn_data	*svd;

	if (wsp->walk_addr == NULL) {
		mdb_warn("segvn walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	svw = mdb_zalloc(sizeof (*svw), UM_SLEEP);
	svw->svw_svdp = wsp->walk_addr;
	svw->svw_anonskip = 0;
	svw->svw_sparse_idx = 0;
	svw->svw_walkoff = 0;
	svw->svw_all = (wsp->walk_arg == SEGVN_PAGES_ALL);

	if (mdb_vread(&svw->svw_svd, sizeof (svw->svw_svd), wsp->walk_addr) ==
	    -1) {
		mdb_warn("failed to read segvn_data at %p", wsp->walk_addr);
		mdb_free(svw, sizeof (*svw));
		return (WALK_ERR);
	}

	svd = &svw->svw_svd;
	if (mdb_vread(&svw->svw_seg, sizeof (svw->svw_seg),
	    (uintptr_t)svd->seg) == -1) {
		mdb_warn("failed to read seg at %p (from %p)",
		    svd->seg, &((struct segvn_data *)(wsp->walk_addr))->seg);
		mdb_free(svw, sizeof (*svw));
		return (WALK_ERR);
	}

	if (svd->amp == NULL && svd->vp == NULL) {
		/* make the walk terminate immediately;  no pages */
		svw->svw_walkoff = svw->svw_seg.s_size;

	} else if (svd->amp == NULL &&
	    (svw->svw_seg.s_size >> PAGESHIFT) >= SEGVN_MAX_SPARSE) {
		/*
		 * If we don't have an anon pointer, and the segment is large,
		 * we try to load the in-memory pages into a fixed-size array,
		 * which is then sorted and reported directly.  This is much
		 * faster than doing a mdb_page_lookup() for each possible
		 * offset.
		 *
		 * If the allocation fails, or there are too many pages
		 * in-core, we fall back to looking up the pages individually.
		 */
		svw->svw_sparse = mdb_alloc(
		    SEGVN_MAX_SPARSE * sizeof (*svw->svw_sparse), UM_NOSLEEP);
		if (svw->svw_sparse != NULL) {
			svw->svw_sparse_size = SEGVN_MAX_SPARSE;

			if (mdb_pwalk("page", segvn_sparse_fill, svw,
			    (uintptr_t)svd->vp) == -1 ||
			    svw->svw_sparse_overflow) {
				mdb_free(svw->svw_sparse, SEGVN_MAX_SPARSE *
				    sizeof (*svw->svw_sparse));
				svw->svw_sparse = NULL;
			} else {
				qsort(svw->svw_sparse, svw->svw_sparse_count,
				    sizeof (*svw->svw_sparse),
				    segvn_sparse_cmp);
			}
		}

	} else if (svd->amp != NULL) {
		const char *const layer = (!svw->svw_all && svd->vp == NULL) ?
		    "segvn_anon" : "segvn_anon_all";
		/*
		 * If we're not printing all offsets, and the segvn_data has
		 * no backing VP, we can use the "segvn_anon" walker, which
		 * efficiently skips NULL slots.
		 *
		 * Otherwise, we layer over the "segvn_anon_all" walker
		 * (which reports all anon slots, even NULL ones), so that
		 * segvn_pages_walk_step() knows the precise offset for each
		 * element.  It uses that offset information to look up the
		 * backing pages for NULL anon slots.
		 */
		if (mdb_layered_walk(layer, wsp) == -1) {
			mdb_warn("segvn_pages: failed to layer \"%s\" "
			    "for segvn_data %p", layer, svw->svw_svdp);
			mdb_free(svw, sizeof (*svw));
			return (WALK_ERR);
		}
	}

	wsp->walk_data = svw;
	return (WALK_NEXT);
}

int
segvn_pages_walk_step(mdb_walk_state_t *wsp)
{
	segvn_walk_data_t	*const	svw = wsp->walk_data;
	struct seg		*const	seg = &svw->svw_seg;
	struct segvn_data	*const	svd = &svw->svw_svd;
	uintptr_t		pp;
	page_t			page;

	/* If we've walked off the end of the segment, we're done. */
	if (svw->svw_walkoff >= seg->s_size) {
		return (WALK_DONE);
	}

	/*
	 * If we've got a sparse page array, just send it directly.
	 */
	if (svw->svw_sparse != NULL) {
		u_offset_t off;

		if (svw->svw_sparse_idx >= svw->svw_sparse_count) {
			pp = NULL;
			if (!svw->svw_all) {
				return (WALK_DONE);
			}
		} else {
			segvn_sparse_t	*const svs =
			    &svw->svw_sparse[svw->svw_sparse_idx];
			off = svs->svs_offset - svd->offset;
			if (svw->svw_all && svw->svw_walkoff != off) {
				pp = NULL;
			} else {
				pp = svs->svs_page;
				svw->svw_sparse_idx++;
			}
		}

	} else if (svd->amp == NULL || wsp->walk_addr == NULL) {
		/*
		 * If there's no anon, or the anon slot is NULL, look up
		 * <vp, offset>.
		 */
		if (svd->vp != NULL) {
			pp = mdb_page_lookup((uintptr_t)svd->vp,
			    svd->offset + svw->svw_walkoff);
		} else {
			pp = NULL;
		}

	} else {
		const struct anon	*const	anon = wsp->walk_layer;

		/*
		 * We have a "struct anon"; if it's not swapped out,
		 * look up the page.
		 */
		if (anon->an_vp != NULL || anon->an_off != 0) {
			pp = mdb_page_lookup((uintptr_t)anon->an_vp,
			    anon->an_off);
			if (pp == 0 && mdb_get_state() != MDB_STATE_RUNNING) {
				mdb_warn("walk segvn_pages: segvn_data %p "
				    "offset %ld, anon page <%p, %llx> not "
				    "found.\n", svw->svw_svdp, svw->svw_walkoff,
				    anon->an_vp, anon->an_off);
			}
		} else {
			if (anon->an_pvp == NULL) {
				mdb_warn("walk segvn_pages: useless struct "
				    "anon at %p\n", wsp->walk_addr);
			}
			pp = NULL;	/* nothing at this offset */
		}
	}

	svw->svw_walkoff += PAGESIZE;	/* Update for the next call */
	if (pp != NULL) {
		if (mdb_vread(&page, sizeof (page_t), pp) == -1) {
			mdb_warn("unable to read page_t at %#lx", pp);
			return (WALK_ERR);
		}
		return (wsp->walk_callback(pp, &page, wsp->walk_cbdata));
	}
	if (svw->svw_all) {
		return (wsp->walk_callback(NULL, NULL, wsp->walk_cbdata));
	}
	return (WALK_NEXT);
}

void
segvn_pages_walk_fini(mdb_walk_state_t *wsp)
{
	segvn_walk_data_t	*const	svw = wsp->walk_data;

	if (svw->svw_sparse != NULL) {
		mdb_free(svw->svw_sparse, SEGVN_MAX_SPARSE *
		    sizeof (*svw->svw_sparse));
	}
	mdb_free(svw, sizeof (*svw));
}

/*
 * Grumble, grumble.
 */
#define	SMAP_HASHFUNC(vp, off)	\
	((((uintptr_t)(vp) >> 6) + ((uintptr_t)(vp) >> 3) + \
	((off) >> MAXBSHIFT)) & smd_hashmsk)

int
vnode2smap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	long smd_hashmsk;
	int hash;
	uintptr_t offset = 0;
	struct smap smp;
	uintptr_t saddr, kaddr;
	uintptr_t smd_hash, smd_smap;
	struct seg seg;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_readvar(&smd_hashmsk, "smd_hashmsk") == -1) {
		mdb_warn("failed to read smd_hashmsk");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&smd_hash, "smd_hash") == -1) {
		mdb_warn("failed to read smd_hash");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&smd_smap, "smd_smap") == -1) {
		mdb_warn("failed to read smd_hash");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kaddr, "segkmap") == -1) {
		mdb_warn("failed to read segkmap");
		return (DCMD_ERR);
	}

	if (mdb_vread(&seg, sizeof (seg), kaddr) == -1) {
		mdb_warn("failed to read segkmap at %p", kaddr);
		return (DCMD_ERR);
	}

	if (argc != 0) {
		const mdb_arg_t *arg = &argv[0];

		if (arg->a_type == MDB_TYPE_IMMEDIATE)
			offset = arg->a_un.a_val;
		else
			offset = (uintptr_t)mdb_strtoull(arg->a_un.a_str);
	}

	hash = SMAP_HASHFUNC(addr, offset);

	if (mdb_vread(&saddr, sizeof (saddr),
	    smd_hash + hash * sizeof (uintptr_t)) == -1) {
		mdb_warn("couldn't read smap at %p",
		    smd_hash + hash * sizeof (uintptr_t));
		return (DCMD_ERR);
	}

	do {
		if (mdb_vread(&smp, sizeof (smp), saddr) == -1) {
			mdb_warn("couldn't read smap at %p", saddr);
			return (DCMD_ERR);
		}

		if ((uintptr_t)smp.sm_vp == addr && smp.sm_off == offset) {
			mdb_printf("vnode %p, offs %p is smap %p, vaddr %p\n",
			    addr, offset, saddr, ((saddr - smd_smap) /
			    sizeof (smp)) * MAXBSIZE + seg.s_base);
			return (DCMD_OK);
		}

		saddr = (uintptr_t)smp.sm_hash;
	} while (saddr != NULL);

	mdb_printf("no smap for vnode %p, offs %p\n", addr, offset);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
addr2smap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t kaddr;
	struct seg seg;
	struct segmap_data sd;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_readvar(&kaddr, "segkmap") == -1) {
		mdb_warn("failed to read segkmap");
		return (DCMD_ERR);
	}

	if (mdb_vread(&seg, sizeof (seg), kaddr) == -1) {
		mdb_warn("failed to read segkmap at %p", kaddr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&sd, sizeof (sd), (uintptr_t)seg.s_data) == -1) {
		mdb_warn("failed to read segmap_data at %p", seg.s_data);
		return (DCMD_ERR);
	}

	mdb_printf("%p is smap %p\n", addr,
	    ((addr - (uintptr_t)seg.s_base) >> MAXBSHIFT) *
	    sizeof (struct smap) + (uintptr_t)sd.smd_sm);

	return (DCMD_OK);
}
