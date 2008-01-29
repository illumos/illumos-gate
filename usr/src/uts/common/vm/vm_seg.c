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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * VM - segment management.
 */

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/vmsystm.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/callb.h>
#include <sys/mem_config.h>
#include <sys/mman.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_spt.h>
#include <vm/seg_vn.h>
/*
 * kstats for segment advise
 */
segadvstat_t segadvstat = {
	{ "MADV_FREE_hit",	KSTAT_DATA_ULONG },
	{ "MADV_FREE_miss",	KSTAT_DATA_ULONG },
};

kstat_named_t *segadvstat_ptr = (kstat_named_t *)&segadvstat;
uint_t segadvstat_ndata = sizeof (segadvstat) / sizeof (kstat_named_t);

/* #define	PDEBUG */
#if defined(PDEBUG) || defined(lint) || defined(__lint)
int pdebug = 0;
#else
#define	pdebug		0
#endif	/* PDEBUG */

#define	PPRINTF				if (pdebug) printf
#define	PPRINT(x)			PPRINTF(x)
#define	PPRINT1(x, a)			PPRINTF(x, a)
#define	PPRINT2(x, a, b)		PPRINTF(x, a, b)
#define	PPRINT3(x, a, b, c)		PPRINTF(x, a, b, c)
#define	PPRINT4(x, a, b, c, d)		PPRINTF(x, a, b, c, d)
#define	PPRINT5(x, a, b, c, d, e)	PPRINTF(x, a, b, c, d, e)

#define	P_HASHMASK		(p_hashsize - 1)
#define	P_BASESHIFT		6

/*
 * entry in the segment page cache
 */
struct seg_pcache {
	struct seg_pcache *p_hnext;	/* list for hashed blocks */
	struct seg_pcache *p_hprev;
	int		p_active;	/* active count */
	int		p_ref;		/* ref bit */
	size_t		p_len;		/* segment length */
	caddr_t		p_addr;		/* base address */
	struct seg 	*p_seg;		/* segment */
	struct page	**p_pp;		/* pp shadow list */
	enum seg_rw	p_rw;		/* rw */
	uint_t		p_flags;	/* bit flags */
	int		(*p_callback)(struct seg *, caddr_t, size_t,
			    struct page **, enum seg_rw);
};

struct seg_phash {
	struct seg_pcache *p_hnext;	/* list for hashed blocks */
	struct seg_pcache *p_hprev;
	int p_qlen;			/* Q length */
	kmutex_t p_hmutex;		/* protects hash bucket */
};

static int seg_preap_time = 20;	/* reclaim every 20 secs */
static int seg_pmaxqlen = 5;	/* max Q length in hash list */
static int seg_ppcount = 5;	/* max # of purges per reclaim interval */
static int seg_plazy = 1;	/* if 1, pages are cached after pageunlock */
static pgcnt_t seg_pwindow;	/* max # of pages that can be cached */
static pgcnt_t seg_plocked;	/* # of pages which are cached by pagelock */
static pgcnt_t seg_plocked_window; /* # pages from window */
int seg_preapahead;

static uint_t seg_pdisable = 0;	/* if not 0, caching temporarily disabled */

static int seg_pupdate_active = 1;	/* background reclaim thread */
static clock_t seg_preap_interval;	/* reap interval in ticks */

static kmutex_t seg_pcache;	/* protects the whole pagelock cache */
static kmutex_t seg_pmem;	/* protects window counter */
static ksema_t seg_pasync_sem;	/* sema for reclaim thread */
static struct seg_phash *p_hashtab;
static int p_hashsize = 0;

#define	p_hash(seg) \
	(P_HASHMASK & \
	((uintptr_t)(seg) >> P_BASESHIFT))

#define	p_match(pcp, seg, addr, len, rw) \
	(((pcp)->p_seg == (seg) && \
	(pcp)->p_addr == (addr) && \
	(pcp)->p_rw == (rw) && \
	(pcp)->p_len == (len)) ? 1 : 0)

#define	p_match_pp(pcp, seg, addr, len, pp, rw) \
	(((pcp)->p_seg == (seg) && \
	(pcp)->p_addr == (addr) && \
	(pcp)->p_pp == (pp) && \
	(pcp)->p_rw == (rw) && \
	(pcp)->p_len == (len)) ? 1 : 0)


/*
 * lookup an address range in pagelock cache. Return shadow list
 * and bump up active count.
 */
struct page **
seg_plookup(struct seg *seg, caddr_t addr, size_t len, enum seg_rw rw)
{
	struct seg_pcache *pcp;
	struct seg_phash *hp;

	/*
	 * Skip pagelock cache, while DR is in progress or
	 * seg_pcache is off.
	 */
	if (seg_pdisable || seg_plazy == 0) {
		return (NULL);
	}

	hp = &p_hashtab[p_hash(seg)];
	mutex_enter(&hp->p_hmutex);
	for (pcp = hp->p_hnext; pcp != (struct seg_pcache *)hp;
	    pcp = pcp->p_hnext) {
		if (p_match(pcp, seg, addr, len, rw)) {
			pcp->p_active++;
			mutex_exit(&hp->p_hmutex);

			PPRINT5("seg_plookup hit: seg %p, addr %p, "
			    "len %lx, count %d, pplist %p \n",
			    (void *)seg, (void *)addr, len, pcp->p_active,
			    (void *)pcp->p_pp);

			return (pcp->p_pp);
		}
	}
	mutex_exit(&hp->p_hmutex);

	PPRINT("seg_plookup miss:\n");

	return (NULL);
}

/*
 * mark address range inactive. If the cache is off or the address
 * range is not in the cache we call the segment driver to reclaim
 * the pages. Otherwise just decrement active count and set ref bit.
 */
void
seg_pinactive(struct seg *seg, caddr_t addr, size_t len, struct page **pp,
    enum seg_rw rw, int (*callback)(struct seg *, caddr_t, size_t,
    struct page **, enum seg_rw))
{
	struct seg_pcache *pcp;
	struct seg_phash *hp;

	if (seg_plazy == 0) {
		(void) (*callback)(seg, addr, len, pp, rw);
		return;
	}
	hp = &p_hashtab[p_hash(seg)];
	mutex_enter(&hp->p_hmutex);
	for (pcp = hp->p_hnext; pcp != (struct seg_pcache *)hp;
	    pcp = pcp->p_hnext) {
		if (p_match_pp(pcp, seg, addr, len, pp, rw)) {
			pcp->p_active--;
			ASSERT(pcp->p_active >= 0);
			if (pcp->p_active == 0 && seg_pdisable) {
				int npages;

				ASSERT(callback == pcp->p_callback);
				/* free the entry */
				hp->p_qlen--;
				pcp->p_hprev->p_hnext = pcp->p_hnext;
				pcp->p_hnext->p_hprev = pcp->p_hprev;
				mutex_exit(&hp->p_hmutex);
				npages = pcp->p_len >> PAGESHIFT;
				mutex_enter(&seg_pmem);
				seg_plocked -= npages;
				if ((pcp->p_flags & SEGP_FORCE_WIRED) == 0) {
					seg_plocked_window -= npages;
				}
				mutex_exit(&seg_pmem);
				kmem_free(pcp, sizeof (struct seg_pcache));
				goto out;
			}
			pcp->p_ref = 1;
			mutex_exit(&hp->p_hmutex);
			return;
		}
	}
	mutex_exit(&hp->p_hmutex);
out:
	(void) (*callback)(seg, addr, len, pp, rw);
}

/*
 * The seg_pinsert_check() is used by segment drivers to predict whether
 * a call to seg_pinsert will fail and thereby avoid wasteful pre-processing.
 */

int
seg_pinsert_check(struct seg *seg, size_t len, uint_t flags)
{
	struct seg_phash *hp;

	if (seg_plazy == 0) {
		return (SEGP_FAIL);
	}
	if (seg_pdisable != 0) {
		return (SEGP_FAIL);
	}
	ASSERT((len & PAGEOFFSET) == 0);
	hp = &p_hashtab[p_hash(seg)];
	if (hp->p_qlen > seg_pmaxqlen && (flags & SEGP_FORCE_WIRED) == 0) {
		return (SEGP_FAIL);
	}
	/*
	 * If the SEGP_FORCE_WIRED flag is set,
	 * we skip the check for seg_pwindow.
	 */
	if ((flags & SEGP_FORCE_WIRED) == 0) {
		pgcnt_t npages;

		npages = len >> PAGESHIFT;
		if ((seg_plocked_window + npages) > seg_pwindow) {
			return (SEGP_FAIL);
		}
	}
	return (SEGP_SUCCESS);
}


/*
 * insert address range with shadow list into pagelock cache. If
 * the cache is off or caching is temporarily disabled or the allowed
 * 'window' is exceeded - return SEGP_FAIL. Otherwise return
 * SEGP_SUCCESS.
 */
int
seg_pinsert(struct seg *seg, caddr_t addr, size_t len, struct page **pp,
    enum seg_rw rw, uint_t flags, int (*callback)(struct seg *, caddr_t,
    size_t, struct page **, enum seg_rw))
{
	struct seg_pcache *pcp;
	struct seg_phash *hp;
	pgcnt_t npages;

	if (seg_plazy == 0) {
		return (SEGP_FAIL);
	}
	if (seg_pdisable != 0) {
		return (SEGP_FAIL);
	}
	ASSERT((len & PAGEOFFSET) == 0);
	hp = &p_hashtab[p_hash(seg)];
	if (hp->p_qlen > seg_pmaxqlen && (flags & SEGP_FORCE_WIRED) == 0) {
		return (SEGP_FAIL);
	}
	npages = len >> PAGESHIFT;
	mutex_enter(&seg_pmem);
	/*
	 * If the SEGP_FORCE_WIRED flag is set,
	 * we skip the check for seg_pwindow.
	 */
	if ((flags & SEGP_FORCE_WIRED) == 0) {
		seg_plocked_window += npages;
		if (seg_plocked_window > seg_pwindow) {
			seg_plocked_window -= npages;
			mutex_exit(&seg_pmem);
			return (SEGP_FAIL);
		}
	}
	seg_plocked += npages;
	mutex_exit(&seg_pmem);

	pcp = kmem_alloc(sizeof (struct seg_pcache), KM_SLEEP);
	pcp->p_seg = seg;
	pcp->p_addr = addr;
	pcp->p_len = len;
	pcp->p_pp = pp;
	pcp->p_rw = rw;
	pcp->p_callback = callback;
	pcp->p_active = 1;
	pcp->p_flags = flags;

	PPRINT4("seg_pinsert: seg %p, addr %p, len %lx, pplist %p\n",
	    (void *)seg, (void *)addr, len, (void *)pp);

	hp = &p_hashtab[p_hash(seg)];
	mutex_enter(&hp->p_hmutex);
	hp->p_qlen++;
	pcp->p_hnext = hp->p_hnext;
	pcp->p_hprev = (struct seg_pcache *)hp;
	hp->p_hnext->p_hprev = pcp;
	hp->p_hnext = pcp;
	mutex_exit(&hp->p_hmutex);
	return (SEGP_SUCCESS);
}

/*
 * purge all entries from the pagelock cache if not active
 * and not recently used. Drop all locks and call through
 * the address space into the segment driver to reclaim
 * the pages. This makes sure we get the address space
 * and segment driver locking right.
 */
static void
seg_ppurge_all(int force)
{
	struct seg_pcache *delcallb_list = NULL;
	struct seg_pcache *pcp;
	struct seg_phash *hp;
	int purge_count = 0;
	pgcnt_t npages = 0;
	pgcnt_t npages_window = 0;

	/*
	 * if the cache if off or empty, return
	 */
	if (seg_plazy == 0 || seg_plocked == 0) {
		return;
	}
	for (hp = p_hashtab; hp < &p_hashtab[p_hashsize]; hp++) {
		mutex_enter(&hp->p_hmutex);
		pcp = hp->p_hnext;

		/*
		 * While 'force' is set, seg_pasync_thread is not
		 * throttled.  This is to speedup flushing of seg_pcache
		 * in preparation for DR.
		 *
		 * In normal case, when 'force' is not set, we throttle
		 * seg_pasync_thread so that we don't spend all the time
		 * time in purging the cache.
		 */
		while ((pcp != (struct seg_pcache *)hp) &&
		    (force || (purge_count <= seg_ppcount))) {

			/*
			 * purge entries which are not active and
			 * have not been used recently and
			 * have the SEGP_ASYNC_FLUSH flag.
			 *
			 * In the 'force' case, we ignore the
			 * SEGP_ASYNC_FLUSH flag.
			 */
			if (!(pcp->p_flags & SEGP_ASYNC_FLUSH))
				pcp->p_ref = 1;
			if (force)
				pcp->p_ref = 0;
			if (!pcp->p_ref && !pcp->p_active) {
				struct as *as = pcp->p_seg->s_as;

				/*
				 * try to get the readers lock on the address
				 * space before taking out the cache element.
				 * This ensures as_pagereclaim() can actually
				 * call through the address space and free
				 * the pages. If we don't get the lock, just
				 * skip this entry. The pages will be reclaimed
				 * by the segment driver at unmap time.
				 */
				if (AS_LOCK_TRYENTER(as, &as->a_lock,
				    RW_READER)) {
					hp->p_qlen--;
					pcp->p_hprev->p_hnext = pcp->p_hnext;
					pcp->p_hnext->p_hprev = pcp->p_hprev;
					pcp->p_hprev = delcallb_list;
					delcallb_list = pcp;
					purge_count++;
				}
			} else {
				pcp->p_ref = 0;
			}
			pcp = pcp->p_hnext;
		}
		mutex_exit(&hp->p_hmutex);
		if (!force && purge_count > seg_ppcount)
			break;
	}

	/*
	 * run the delayed callback list. We don't want to hold the
	 * cache lock during a call through the address space.
	 */
	while (delcallb_list != NULL) {
		struct as *as;

		pcp = delcallb_list;
		delcallb_list = pcp->p_hprev;
		as = pcp->p_seg->s_as;

		PPRINT4("seg_ppurge_all: purge seg %p, addr %p, len %lx, "
		    "pplist %p\n", (void *)pcp->p_seg, (void *)pcp->p_addr,
		    pcp->p_len, (void *)pcp->p_pp);

		as_pagereclaim(as, pcp->p_pp, pcp->p_addr,
		    pcp->p_len, pcp->p_rw);
		AS_LOCK_EXIT(as, &as->a_lock);
		npages += pcp->p_len >> PAGESHIFT;
		if ((pcp->p_flags & SEGP_FORCE_WIRED) == 0) {
			npages_window += pcp->p_len >> PAGESHIFT;
		}
		kmem_free(pcp, sizeof (struct seg_pcache));
	}
	mutex_enter(&seg_pmem);
	seg_plocked -= npages;
	seg_plocked_window -= npages_window;
	mutex_exit(&seg_pmem);
}

/*
 * Remove cached pages for segment(s) entries from hashtable.
 * The segments are identified by a given clients callback
 * function.
 * This is useful for multiple seg's cached on behalf of
 * dummy segment (ISM/DISM) with common callback function.
 * The clients callback function may return status indicating
 * that the last seg's entry has been purged. In such a case
 * the seg_ppurge_seg() stops searching hashtable and exits.
 * Otherwise all hashtable entries are scanned.
 */
void
seg_ppurge_seg(int (*callback)(struct seg *, caddr_t, size_t,
    struct page **, enum seg_rw))
{
	struct seg_pcache *pcp, *npcp;
	struct seg_phash *hp;
	pgcnt_t npages = 0;
	pgcnt_t npages_window = 0;
	int	done = 0;

	/*
	 * if the cache if off or empty, return
	 */
	if (seg_plazy == 0 || seg_plocked == 0) {
		return;
	}
	mutex_enter(&seg_pcache);
	seg_pdisable++;
	mutex_exit(&seg_pcache);

	for (hp = p_hashtab; hp < &p_hashtab[p_hashsize]; hp++) {

		mutex_enter(&hp->p_hmutex);
		pcp = hp->p_hnext;
		while (pcp != (struct seg_pcache *)hp) {

			/*
			 * purge entries which are not active
			 */
			npcp = pcp->p_hnext;
			if (!pcp->p_active && pcp->p_callback == callback) {
				hp->p_qlen--;
				pcp->p_hprev->p_hnext = pcp->p_hnext;
				pcp->p_hnext->p_hprev = pcp->p_hprev;

				if ((*pcp->p_callback)(pcp->p_seg, pcp->p_addr,
				    pcp->p_len, pcp->p_pp, pcp->p_rw)) {
					done = 1;
				}

				npages += pcp->p_len >> PAGESHIFT;
				if ((pcp->p_flags & SEGP_FORCE_WIRED) == 0) {
					npages_window +=
					    pcp->p_len >> PAGESHIFT;
				}
				kmem_free(pcp, sizeof (struct seg_pcache));
			}
			pcp = npcp;
			if (done)
				break;
		}
		mutex_exit(&hp->p_hmutex);
		if (done)
			break;
	}

	mutex_enter(&seg_pcache);
	seg_pdisable--;
	mutex_exit(&seg_pcache);

	mutex_enter(&seg_pmem);
	seg_plocked -= npages;
	seg_plocked_window -= npages_window;
	mutex_exit(&seg_pmem);
}

/*
 * purge all entries for a given segment. Since we
 * callback into the segment driver directly for page
 * reclaim the caller needs to hold the right locks.
 */
void
seg_ppurge(struct seg *seg)
{
	struct seg_pcache *delcallb_list = NULL;
	struct seg_pcache *pcp;
	struct seg_phash *hp;
	pgcnt_t npages = 0;
	pgcnt_t npages_window = 0;

	if (seg_plazy == 0) {
		return;
	}
	hp = &p_hashtab[p_hash(seg)];
	mutex_enter(&hp->p_hmutex);
	pcp = hp->p_hnext;
	while (pcp != (struct seg_pcache *)hp) {
		if (pcp->p_seg == seg) {
			if (pcp->p_active) {
				break;
			}
			hp->p_qlen--;
			pcp->p_hprev->p_hnext = pcp->p_hnext;
			pcp->p_hnext->p_hprev = pcp->p_hprev;
			pcp->p_hprev = delcallb_list;
			delcallb_list = pcp;
		}
		pcp = pcp->p_hnext;
	}
	mutex_exit(&hp->p_hmutex);
	while (delcallb_list != NULL) {
		pcp = delcallb_list;
		delcallb_list = pcp->p_hprev;

		PPRINT4("seg_ppurge: purge seg %p, addr %p, len %lx, "
		    "pplist %p\n", (void *)seg, (void *)pcp->p_addr,
		    pcp->p_len, (void *)pcp->p_pp);

		ASSERT(seg == pcp->p_seg);
		(void) (*pcp->p_callback)(seg, pcp->p_addr,
		    pcp->p_len, pcp->p_pp, pcp->p_rw);
		npages += pcp->p_len >> PAGESHIFT;
		if ((pcp->p_flags & SEGP_FORCE_WIRED) == 0) {
			npages_window += pcp->p_len >> PAGESHIFT;
		}
		kmem_free(pcp, sizeof (struct seg_pcache));
	}
	mutex_enter(&seg_pmem);
	seg_plocked -= npages;
	seg_plocked_window -= npages_window;
	mutex_exit(&seg_pmem);
}

static void seg_pinit_mem_config(void);

/*
 * setup the pagelock cache
 */
static void
seg_pinit(void)
{
	struct seg_phash *hp;
	int i;
	uint_t physmegs;

	sema_init(&seg_pasync_sem, 0, NULL, SEMA_DEFAULT, NULL);

	mutex_enter(&seg_pcache);
	if (p_hashtab == NULL) {
		physmegs = physmem >> (20 - PAGESHIFT);

		/* If p_hashsize was not set in /etc/system ... */
		if (p_hashsize == 0) {
			/*
			 * Choose p_hashsize based on physmem.
			 */
			if (physmegs < 64) {
				p_hashsize = 64;
			} else if (physmegs < 1024) {
				p_hashsize = 1024;
			} else if (physmegs < 10 * 1024) {
				p_hashsize = 8192;
			} else if (physmegs < 20 * 1024) {
				p_hashsize = 2 * 8192;
				seg_pmaxqlen = 16;
			} else {
				p_hashsize = 128 * 1024;
				seg_pmaxqlen = 128;
			}
		}

		p_hashtab = kmem_zalloc(p_hashsize * sizeof (struct seg_phash),
		    KM_SLEEP);
		for (i = 0; i < p_hashsize; i++) {
			hp = (struct seg_phash *)&p_hashtab[i];
			hp->p_hnext = (struct seg_pcache *)hp;
			hp->p_hprev = (struct seg_pcache *)hp;
			mutex_init(&hp->p_hmutex, NULL, MUTEX_DEFAULT, NULL);
		}
		if (seg_pwindow == 0) {
			if (physmegs < 24) {
				/* don't use cache */
				seg_plazy = 0;
			} else if (physmegs < 64) {
				seg_pwindow = physmem >> 5; /* 3% of memory */
			} else if (physmegs < 10 * 1024) {
				seg_pwindow = physmem >> 3; /* 12% of memory */
			} else {
				seg_pwindow = physmem >> 1;
			}
		}
	}
	mutex_exit(&seg_pcache);

	seg_pinit_mem_config();
}

/*
 * called by pageout if memory is low
 */
void
seg_preap(void)
{
	/*
	 * if the cache if off or empty, return
	 */
	if (seg_plocked == 0 || seg_plazy == 0) {
		return;
	}
	sema_v(&seg_pasync_sem);
}

static void seg_pupdate(void *);

/*
 * run as a backgroud thread and reclaim pagelock
 * pages which have not been used recently
 */
void
seg_pasync_thread(void)
{
	callb_cpr_t cpr_info;
	kmutex_t pasync_lock;	/* just for CPR stuff */

	mutex_init(&pasync_lock, NULL, MUTEX_DEFAULT, NULL);

	CALLB_CPR_INIT(&cpr_info, &pasync_lock, callb_generic_cpr,
	    "seg_pasync");

	if (seg_preap_interval == 0) {
		seg_preap_interval = seg_preap_time * hz;
	} else {
		seg_preap_interval *= hz;
	}
	if (seg_plazy && seg_pupdate_active) {
		(void) timeout(seg_pupdate, NULL, seg_preap_interval);
	}

	for (;;) {
		mutex_enter(&pasync_lock);
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		mutex_exit(&pasync_lock);
		sema_p(&seg_pasync_sem);
		mutex_enter(&pasync_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &pasync_lock);
		mutex_exit(&pasync_lock);

		seg_ppurge_all(0);
	}
}

static void
seg_pupdate(void *dummy)
{
	sema_v(&seg_pasync_sem);

	if (seg_plazy && seg_pupdate_active) {
		(void) timeout(seg_pupdate, dummy, seg_preap_interval);
	}
}

static struct kmem_cache *seg_cache;

/*
 * Initialize segment management data structures.
 */
void
seg_init(void)
{
	kstat_t *ksp;

	seg_cache = kmem_cache_create("seg_cache", sizeof (struct seg), 0,
	    NULL, NULL, NULL, NULL, NULL, 0);

	ksp = kstat_create("unix", 0, "segadvstat", "vm", KSTAT_TYPE_NAMED,
	    segadvstat_ndata, KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *)segadvstat_ptr;
		kstat_install(ksp);
	}

	seg_pinit();
}

/*
 * Allocate a segment to cover [base, base+size]
 * and attach it to the specified address space.
 */
struct seg *
seg_alloc(struct as *as, caddr_t base, size_t size)
{
	struct seg *new;
	caddr_t segbase;
	size_t segsize;

	segbase = (caddr_t)((uintptr_t)base & (uintptr_t)PAGEMASK);
	segsize = (((uintptr_t)(base + size) + PAGEOFFSET) & PAGEMASK) -
	    (uintptr_t)segbase;

	if (!valid_va_range(&segbase, &segsize, segsize, AH_LO))
		return ((struct seg *)NULL);	/* bad virtual addr range */

	if (as != &kas &&
	    valid_usr_range(segbase, segsize, 0, as,
	    as->a_userlimit) != RANGE_OKAY)
		return ((struct seg *)NULL);	/* bad virtual addr range */

	new = kmem_cache_alloc(seg_cache, KM_SLEEP);
	new->s_ops = NULL;
	new->s_data = NULL;
	new->s_szc = 0;
	new->s_flags = 0;
	if (seg_attach(as, segbase, segsize, new) < 0) {
		kmem_cache_free(seg_cache, new);
		return ((struct seg *)NULL);
	}
	/* caller must fill in ops, data */
	return (new);
}

/*
 * Attach a segment to the address space.  Used by seg_alloc()
 * and for kernel startup to attach to static segments.
 */
int
seg_attach(struct as *as, caddr_t base, size_t size, struct seg *seg)
{
	seg->s_as = as;
	seg->s_base = base;
	seg->s_size = size;

	/*
	 * as_addseg() will add the segment at the appropraite point
	 * in the list. It will return -1 if there is overlap with
	 * an already existing segment.
	 */
	return (as_addseg(as, seg));
}

/*
 * Unmap a segment and free it from its associated address space.
 * This should be called by anybody who's finished with a whole segment's
 * mapping.  Just calls SEGOP_UNMAP() on the whole mapping .  It is the
 * responsibility of the segment driver to unlink the the segment
 * from the address space, and to free public and private data structures
 * associated with the segment.  (This is typically done by a call to
 * seg_free()).
 */
void
seg_unmap(struct seg *seg)
{
#ifdef DEBUG
	int ret;
#endif /* DEBUG */

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	/* Shouldn't have called seg_unmap if mapping isn't yet established */
	ASSERT(seg->s_data != NULL);

	/* Unmap the whole mapping */
#ifdef DEBUG
	ret = SEGOP_UNMAP(seg, seg->s_base, seg->s_size);
	ASSERT(ret == 0);
#else
	SEGOP_UNMAP(seg, seg->s_base, seg->s_size);
#endif /* DEBUG */
}

/*
 * Free the segment from its associated as. This should only be called
 * if a mapping to the segment has not yet been established (e.g., if
 * an error occurs in the middle of doing an as_map when the segment
 * has already been partially set up) or if it has already been deleted
 * (e.g., from a segment driver unmap routine if the unmap applies to the
 * entire segment). If the mapping is currently set up then seg_unmap() should
 * be called instead.
 */
void
seg_free(struct seg *seg)
{
	register struct as *as = seg->s_as;
	struct seg *tseg = as_removeseg(as, seg);

	ASSERT(tseg == seg);

	/*
	 * If the segment private data field is NULL,
	 * then segment driver is not attached yet.
	 */
	if (seg->s_data != NULL)
		SEGOP_FREE(seg);

	kmem_cache_free(seg_cache, seg);
}

/*ARGSUSED*/
static void
seg_p_mem_config_post_add(
	void *arg,
	pgcnt_t delta_pages)
{
	/* Nothing to do. */
}

void
seg_p_enable(void)
{
	mutex_enter(&seg_pcache);
	ASSERT(seg_pdisable != 0);
	seg_pdisable--;
	mutex_exit(&seg_pcache);
}

/*
 * seg_p_disable - disables seg_pcache, and then attempts to empty the
 * cache.
 * Returns SEGP_SUCCESS if the cache was successfully emptied, or
 * SEGP_FAIL if the cache could not be emptied.
 */
int
seg_p_disable(void)
{
	pgcnt_t	old_plocked;
	int stall_count = 0;

	mutex_enter(&seg_pcache);
	seg_pdisable++;
	ASSERT(seg_pdisable != 0);
	mutex_exit(&seg_pcache);

	/*
	 * Attempt to empty the cache. Terminate if seg_plocked does not
	 * diminish with SEGP_STALL_THRESHOLD consecutive attempts.
	 */
	while (seg_plocked != 0) {
		old_plocked = seg_plocked;
		seg_ppurge_all(1);
		if (seg_plocked == old_plocked) {
			if (stall_count++ > SEGP_STALL_THRESHOLD) {
				return (SEGP_FAIL);
			}
		} else
			stall_count = 0;
		if (seg_plocked != 0)
			delay(hz/SEGP_PREDEL_DELAY_FACTOR);
	}
	return (SEGP_SUCCESS);
}

/*
 * Attempt to purge seg_pcache.  May need to return before this has
 * completed to allow other pre_del callbacks to unlock pages. This is
 * ok because:
 *	1) The seg_pdisable flag has been set so at least we won't
 *	cache anymore locks and the locks we couldn't purge
 *	will not be held if they do get released by a subsequent
 *	pre-delete callback.
 *
 *	2) The rest of the memory delete thread processing does not
 *	depend on the changes made in this pre-delete callback. No
 *	panics will result, the worst that will happen is that the
 *	DR code will timeout and cancel the delete.
 */
/*ARGSUSED*/
static int
seg_p_mem_config_pre_del(
	void *arg,
	pgcnt_t delta_pages)
{
	if (seg_p_disable() != SEGP_SUCCESS)
		cmn_err(CE_NOTE,
		    "!Pre-delete couldn't purge"" pagelock cache - continuing");
	return (0);
}

/*ARGSUSED*/
static void
seg_p_mem_config_post_del(
	void *arg,
	pgcnt_t delta_pages,
	int cancelled)
{
	seg_p_enable();
}

static kphysm_setup_vector_t seg_p_mem_config_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	seg_p_mem_config_post_add,
	seg_p_mem_config_pre_del,
	seg_p_mem_config_post_del,
};

static void
seg_pinit_mem_config(void)
{
	int ret;

	ret = kphysm_setup_func_register(&seg_p_mem_config_vec, (void *)NULL);
	/*
	 * Want to catch this in the debug kernel. At run time, if the
	 * callbacks don't get run all will be OK as the disable just makes
	 * it more likely that the pages can be collected.
	 */
	ASSERT(ret == 0);
}

extern struct seg_ops segvn_ops;
extern struct seg_ops segspt_shmops;

/*
 * Verify that segment is not a shared anonymous segment which reserves
 * swap.  zone.max-swap accounting (zone->zone_max_swap) cannot be transfered
 * from one zone to another if any segments are shared.  This is because the
 * last process to exit will credit the swap reservation.  This could lead
 * to the swap being reserved by one zone, and credited to another.
 */
boolean_t
seg_can_change_zones(struct seg *seg)
{
	struct segvn_data *svd;

	if (seg->s_ops == &segspt_shmops)
		return (B_FALSE);

	if (seg->s_ops == &segvn_ops) {
		svd = (struct segvn_data *)seg->s_data;
		if (svd->type == MAP_SHARED &&
		    svd->amp != NULL &&
		    svd->amp->swresv > 0)
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Return swap reserved by a segment backing a private mapping.
 */
size_t
seg_swresv(struct seg *seg)
{
	struct segvn_data *svd;
	size_t swap = 0;

	if (seg->s_ops == &segvn_ops) {
		svd = (struct segvn_data *)seg->s_data;
		if (svd->type == MAP_PRIVATE && svd->swresv > 0)
			swap = svd->swresv;
	}
	return (swap);
}
