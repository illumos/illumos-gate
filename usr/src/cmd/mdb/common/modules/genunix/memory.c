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

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <vm/page.h>
#include <sys/thread.h>
#include <sys/swap.h>
#include <sys/memlist.h>
#include <sys/vnode.h>
#if defined(__i386) || defined(__amd64)
#include <sys/balloon_impl.h>
#endif

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

	if (pp->p_vnode == NULL || pp->p_vnode == stats->ms_unused_vp)
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
	ulong_t pagesize;
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

	/* Grab base page size */
	if (mdb_readvar(&pagesize, "_pagesize") == -1) {
		mdb_warn("unable to read _pagesize");
		return (DCMD_ERR);
	}

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
	    (uint64_t)stats.ms_kmem * pagesize / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_kmem));

	if (stats.ms_zfs_data != 0)
		mdb_printf("ZFS File Data    %16llu  %16llu  %3lu%%\n",
		    stats.ms_zfs_data,
		    (uint64_t)stats.ms_zfs_data * pagesize / (1024 * 1024),
		    MS_PCT_TOTAL(stats.ms_zfs_data));

	mdb_printf("Anon             %16llu  %16llu  %3lu%%\n",
	    stats.ms_anon,
	    (uint64_t)stats.ms_anon * pagesize / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_anon));
	mdb_printf("Exec and libs    %16llu  %16llu  %3lu%%\n",
	    stats.ms_exec,
	    (uint64_t)stats.ms_exec * pagesize / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_exec));
	mdb_printf("Page cache       %16llu  %16llu  %3lu%%\n",
	    stats.ms_vnode,
	    (uint64_t)stats.ms_vnode * pagesize / (1024 * 1024),
	    MS_PCT_TOTAL(stats.ms_vnode));
	mdb_printf("Free (cachelist) %16llu  %16llu  %3lu%%\n",
	    stats.ms_cachelist,
	    (uint64_t)stats.ms_cachelist * pagesize / (1024 * 1024),
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
	    (uint64_t)freemem * pagesize / (1024 * 1024),
	    MS_PCT_TOTAL(freemem));

#if defined(__i386) || defined(__amd64)
	if (bln_size != -1) {
		mdb_printf("Balloon          %16lu  %16llu  %3lu%%\n",
		    bln_stats.bln_hv_pages,
		    (uint64_t)bln_stats.bln_hv_pages * pagesize / (1024 * 1024),
		    MS_PCT_TOTAL(bln_stats.bln_hv_pages));
	}
#endif

	mdb_printf("\nTotal            %16lu  %16lu\n",
	    physmem,
	    (uint64_t)physmem * pagesize / (1024 * 1024));

	if (physmem != total_pages) {
		mdb_printf("Physical         %16lu  %16lu\n",
		    total_pages,
		    (uint64_t)total_pages * pagesize / (1024 * 1024));
	}

#undef MS_PCT_TOTAL

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

	wsp->walk_addr = (uintptr_t)ml.next;

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

	mdb_printf("%0?lx %16llx %16llx\n", addr, ml.address, ml.size);

	return (DCMD_OK);
}
