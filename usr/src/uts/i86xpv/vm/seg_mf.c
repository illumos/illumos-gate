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

/*
 * Machine frame segment driver.  This segment driver allows dom0 processes to
 * map pages of other domains or Xen (e.g. during save/restore).  ioctl()s on
 * the privcmd driver provide the MFN values backing each mapping, and we map
 * them into the process's address space at this time.  Demand-faulting is not
 * supported by this driver due to the requirements upon some of the ioctl()s.
 */


#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/lgrp.h>
#include <sys/hypervisor.h>

#include <vm/page.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>

#include <vm/hat_pte.h>
#include <vm/hat_i86.h>
#include <vm/seg_mf.h>

#include <sys/fs/snode.h>

#define	VTOCVP(vp)	(VTOS(vp)->s_commonvp)

typedef struct segmf_mfn_s {
	mfn_t		m_mfn;
} segmf_mfn_t;

/* g_flags */
#define	SEGMF_GFLAGS_WR		0x1
#define	SEGMF_GFLAGS_MAPPED	0x2
typedef struct segmf_gref_s {
	uint64_t	g_ptep;
	grant_ref_t	g_gref;
	uint32_t	g_flags;
	grant_handle_t	g_handle;
} segmf_gref_t;

typedef union segmf_mu_u {
	segmf_mfn_t	m;
	segmf_gref_t	g;
} segmf_mu_t;

typedef enum {
	SEGMF_MAP_EMPTY = 0,
	SEGMF_MAP_MFN,
	SEGMF_MAP_GREF
} segmf_map_type_t;

typedef struct segmf_map_s {
	segmf_map_type_t	t_type;
	segmf_mu_t		u;
} segmf_map_t;

struct segmf_data {
	kmutex_t	lock;
	struct vnode	*vp;
	uchar_t		prot;
	uchar_t		maxprot;
	size_t		softlockcnt;
	domid_t		domid;
	segmf_map_t	*map;
};

static struct seg_ops segmf_ops;

static int segmf_fault_gref_range(struct seg *seg, caddr_t addr, size_t len);

static struct segmf_data *
segmf_data_zalloc(struct seg *seg)
{
	struct segmf_data *data = kmem_zalloc(sizeof (*data), KM_SLEEP);

	mutex_init(&data->lock, "segmf.lock", MUTEX_DEFAULT, NULL);
	seg->s_ops = &segmf_ops;
	seg->s_data = data;
	return (data);
}

int
segmf_create(struct seg *seg, void *args)
{
	struct segmf_crargs *a = args;
	struct segmf_data *data;
	struct as *as = seg->s_as;
	pgcnt_t i, npages = seg_pages(seg);
	int error;

	hat_map(as->a_hat, seg->s_base, seg->s_size, HAT_MAP);

	data = segmf_data_zalloc(seg);
	data->vp = specfind(a->dev, VCHR);
	data->prot = a->prot;
	data->maxprot = a->maxprot;

	data->map = kmem_alloc(npages * sizeof (segmf_map_t), KM_SLEEP);
	for (i = 0; i < npages; i++) {
		data->map[i].t_type = SEGMF_MAP_EMPTY;
	}

	error = VOP_ADDMAP(VTOCVP(data->vp), 0, as, seg->s_base, seg->s_size,
	    data->prot, data->maxprot, MAP_SHARED, CRED(), NULL);

	if (error != 0)
		hat_unload(as->a_hat,
		    seg->s_base, seg->s_size, HAT_UNLOAD_UNMAP);
	return (error);
}

/*
 * Duplicate a seg and return new segment in newseg.
 */
static int
segmf_dup(struct seg *seg, struct seg *newseg)
{
	struct segmf_data *data = seg->s_data;
	struct segmf_data *ndata;
	pgcnt_t npages = seg_pages(newseg);
	size_t sz;

	ndata = segmf_data_zalloc(newseg);

	VN_HOLD(data->vp);
	ndata->vp = data->vp;
	ndata->prot = data->prot;
	ndata->maxprot = data->maxprot;
	ndata->domid = data->domid;

	sz = npages * sizeof (segmf_map_t);
	ndata->map = kmem_alloc(sz, KM_SLEEP);
	bcopy(data->map, ndata->map, sz);

	return (VOP_ADDMAP(VTOCVP(ndata->vp), 0, newseg->s_as,
	    newseg->s_base, newseg->s_size, ndata->prot, ndata->maxprot,
	    MAP_SHARED, CRED(), NULL));
}

/*
 * We only support unmapping the whole segment, and we automatically unlock
 * what we previously soft-locked.
 */
static int
segmf_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	struct segmf_data *data = seg->s_data;
	offset_t off;

	if (addr < seg->s_base || addr + len > seg->s_base + seg->s_size ||
	    (len & PAGEOFFSET) || ((uintptr_t)addr & PAGEOFFSET))
		panic("segmf_unmap");

	if (addr != seg->s_base || len != seg->s_size)
		return (ENOTSUP);

	hat_unload(seg->s_as->a_hat, addr, len,
	    HAT_UNLOAD_UNMAP | HAT_UNLOAD_UNLOCK);

	off = (offset_t)seg_page(seg, addr);

	ASSERT(data->vp != NULL);

	(void) VOP_DELMAP(VTOCVP(data->vp), off, seg->s_as, addr, len,
	    data->prot, data->maxprot, MAP_SHARED, CRED(), NULL);

	seg_free(seg);
	return (0);
}

static void
segmf_free(struct seg *seg)
{
	struct segmf_data *data = seg->s_data;
	pgcnt_t npages = seg_pages(seg);

	kmem_free(data->map, npages * sizeof (segmf_map_t));
	VN_RELE(data->vp);
	mutex_destroy(&data->lock);
	kmem_free(data, sizeof (*data));
}

static int segmf_faultpage_debug = 0;
/*ARGSUSED*/
static int
segmf_faultpage(struct hat *hat, struct seg *seg, caddr_t addr,
    enum fault_type type, uint_t prot)
{
	struct segmf_data *data = seg->s_data;
	uint_t hat_flags = HAT_LOAD_NOCONSIST;
	mfn_t mfn;
	x86pte_t pte;
	segmf_map_t *map;
	uint_t idx;


	idx = seg_page(seg, addr);
	map = &data->map[idx];
	ASSERT(map->t_type == SEGMF_MAP_MFN);

	mfn = map->u.m.m_mfn;

	if (type == F_SOFTLOCK) {
		mutex_enter(&freemem_lock);
		data->softlockcnt++;
		mutex_exit(&freemem_lock);
		hat_flags |= HAT_LOAD_LOCK;
	} else
		hat_flags |= HAT_LOAD;

	if (segmf_faultpage_debug > 0) {
		uprintf("segmf_faultpage: addr %p domid %x mfn %lx prot %x\n",
		    (void *)addr, data->domid, mfn, prot);
		segmf_faultpage_debug--;
	}

	/*
	 * Ask the HAT to load a throwaway mapping to page zero, then
	 * overwrite it with our foreign domain mapping. It gets removed
	 * later via hat_unload()
	 */
	hat_devload(hat, addr, MMU_PAGESIZE, (pfn_t)0,
	    PROT_READ | HAT_UNORDERED_OK, hat_flags);

	pte = mmu_ptob((x86pte_t)mfn) | PT_VALID | PT_USER | PT_FOREIGN;
	if (prot & PROT_WRITE)
		pte |= PT_WRITABLE;

	if (HYPERVISOR_update_va_mapping_otherdomain((uintptr_t)addr, pte,
	    UVMF_INVLPG | UVMF_ALL, data->domid) != 0) {
		hat_flags = HAT_UNLOAD_UNMAP;

		if (type == F_SOFTLOCK) {
			hat_flags |= HAT_UNLOAD_UNLOCK;
			mutex_enter(&freemem_lock);
			data->softlockcnt--;
			mutex_exit(&freemem_lock);
		}

		hat_unload(hat, addr, MMU_PAGESIZE, hat_flags);
		return (FC_MAKE_ERR(EFAULT));
	}

	return (0);
}

static int
seg_rw_to_prot(enum seg_rw rw)
{
	switch (rw) {
	case S_READ:
		return (PROT_READ);
	case S_WRITE:
		return (PROT_WRITE);
	case S_EXEC:
		return (PROT_EXEC);
	case S_OTHER:
	default:
		break;
	}
	return (PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void
segmf_softunlock(struct hat *hat, struct seg *seg, caddr_t addr, size_t len)
{
	struct segmf_data *data = seg->s_data;

	hat_unlock(hat, addr, len);

	mutex_enter(&freemem_lock);
	ASSERT(data->softlockcnt >= btopr(len));
	data->softlockcnt -= btopr(len);
	mutex_exit(&freemem_lock);

	if (data->softlockcnt == 0) {
		struct as *as = seg->s_as;

		if (AS_ISUNMAPWAIT(as)) {
			mutex_enter(&as->a_contents);
			if (AS_ISUNMAPWAIT(as)) {
				AS_CLRUNMAPWAIT(as);
				cv_broadcast(&as->a_cv);
			}
			mutex_exit(&as->a_contents);
		}
	}
}

static int
segmf_fault_range(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
    enum fault_type type, enum seg_rw rw)
{
	struct segmf_data *data = seg->s_data;
	int error = 0;
	caddr_t a;

	if ((data->prot & seg_rw_to_prot(rw)) == 0)
		return (FC_PROT);

	/* loop over the address range handling each fault */

	for (a = addr; a < addr + len; a += PAGESIZE) {
		error = segmf_faultpage(hat, seg, a, type, data->prot);
		if (error != 0)
			break;
	}

	if (error != 0 && type == F_SOFTLOCK) {
		size_t done = (size_t)(a - addr);

		/*
		 * Undo what's been done so far.
		 */
		if (done > 0)
			segmf_softunlock(hat, seg, addr, done);
	}

	return (error);
}

/*
 * We never demand-fault for seg_mf.
 */
/*ARGSUSED*/
static int
segmf_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
    enum fault_type type, enum seg_rw rw)
{
	return (FC_MAKE_ERR(EFAULT));
}

/*ARGSUSED*/
static int
segmf_faulta(struct seg *seg, caddr_t addr)
{
	return (0);
}

/*ARGSUSED*/
static int
segmf_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	return (EINVAL);
}

/*ARGSUSED*/
static int
segmf_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	return (EINVAL);
}

/*ARGSUSED*/
static int
segmf_kluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	return (-1);
}

/*ARGSUSED*/
static int
segmf_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	return (0);
}

/*
 * XXPV	Hmm.  Should we say that mf mapping are "in core?"
 */

/*ARGSUSED*/
static size_t
segmf_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{
	size_t v;

	for (v = 0, len = (len + PAGEOFFSET) & PAGEMASK; len;
	    len -= PAGESIZE, v += PAGESIZE)
		*vec++ = 1;
	return (v);
}

/*ARGSUSED*/
static int
segmf_lockop(struct seg *seg, caddr_t addr,
    size_t len, int attr, int op, ulong_t *lockmap, size_t pos)
{
	return (0);
}

static int
segmf_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	struct segmf_data *data = seg->s_data;
	pgcnt_t pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;

	if (pgno != 0) {
		do
			protv[--pgno] = data->prot;
		while (pgno != 0)
			;
	}
	return (0);
}

static u_offset_t
segmf_getoffset(struct seg *seg, caddr_t addr)
{
	return (addr - seg->s_base);
}

/*ARGSUSED*/
static int
segmf_gettype(struct seg *seg, caddr_t addr)
{
	return (MAP_SHARED);
}

/*ARGSUSED1*/
static int
segmf_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	struct segmf_data *data = seg->s_data;

	*vpp = VTOCVP(data->vp);
	return (0);
}

/*ARGSUSED*/
static int
segmf_advise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
{
	return (0);
}

/*ARGSUSED*/
static void
segmf_dump(struct seg *seg)
{}

/*ARGSUSED*/
static int
segmf_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
segmf_setpagesize(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOTSUP);
}

static int
segmf_getmemid(struct seg *seg, caddr_t addr, memid_t *memid)
{
	struct segmf_data *data = seg->s_data;

	memid->val[0] = (uintptr_t)VTOCVP(data->vp);
	memid->val[1] = (uintptr_t)seg_page(seg, addr);
	return (0);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t *
segmf_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}

/*ARGSUSED*/
static int
segmf_capable(struct seg *seg, segcapability_t capability)
{
	return (0);
}

/*
 * Add a set of contiguous foreign MFNs to the segment. soft-locking them.  The
 * pre-faulting is necessary due to live migration; in particular we must
 * return an error in response to IOCTL_PRIVCMD_MMAPBATCH rather than faulting
 * later on a bad MFN.  Whilst this isn't necessary for the other MMAP
 * ioctl()s, we lock them too, as they should be transitory.
 */
int
segmf_add_mfns(struct seg *seg, caddr_t addr, mfn_t mfn,
    pgcnt_t pgcnt, domid_t domid)
{
	struct segmf_data *data = seg->s_data;
	pgcnt_t base;
	faultcode_t fc;
	pgcnt_t i;
	int error = 0;

	if (seg->s_ops != &segmf_ops)
		return (EINVAL);

	/*
	 * Don't mess with dom0.
	 *
	 * Only allow the domid to be set once for the segment.
	 * After that attempts to add mappings to this segment for
	 * other domains explicitly fails.
	 */

	if (domid == 0 || domid == DOMID_SELF)
		return (EACCES);

	mutex_enter(&data->lock);

	if (data->domid == 0)
		data->domid = domid;

	if (data->domid != domid) {
		error = EINVAL;
		goto out;
	}

	base = seg_page(seg, addr);

	for (i = 0; i < pgcnt; i++) {
		data->map[base + i].t_type = SEGMF_MAP_MFN;
		data->map[base + i].u.m.m_mfn = mfn++;
	}

	fc = segmf_fault_range(seg->s_as->a_hat, seg, addr,
	    pgcnt * MMU_PAGESIZE, F_SOFTLOCK, S_OTHER);

	if (fc != 0) {
		error = fc_decode(fc);
		for (i = 0; i < pgcnt; i++) {
			data->map[base + i].t_type = SEGMF_MAP_EMPTY;
		}
	}

out:
	mutex_exit(&data->lock);
	return (error);
}

int
segmf_add_grefs(struct seg *seg, caddr_t addr, uint_t flags,
    grant_ref_t *grefs, uint_t cnt, domid_t domid)
{
	struct segmf_data *data;
	segmf_map_t *map;
	faultcode_t fc;
	uint_t idx;
	uint_t i;
	int e;

	if (seg->s_ops != &segmf_ops)
		return (EINVAL);

	/*
	 * Don't mess with dom0.
	 *
	 * Only allow the domid to be set once for the segment.
	 * After that attempts to add mappings to this segment for
	 * other domains explicitly fails.
	 */

	if (domid == 0 || domid == DOMID_SELF)
		return (EACCES);

	data = seg->s_data;
	idx = seg_page(seg, addr);
	map = &data->map[idx];
	e = 0;

	mutex_enter(&data->lock);

	if (data->domid == 0)
		data->domid = domid;

	if (data->domid != domid) {
		e = EINVAL;
		goto out;
	}

	/* store away the grefs passed in then fault in the pages */
	for (i = 0; i < cnt; i++) {
		map[i].t_type = SEGMF_MAP_GREF;
		map[i].u.g.g_gref = grefs[i];
		map[i].u.g.g_handle = 0;
		map[i].u.g.g_flags = 0;
		if (flags & SEGMF_GREF_WR) {
			map[i].u.g.g_flags |= SEGMF_GFLAGS_WR;
		}
	}
	fc = segmf_fault_gref_range(seg, addr, cnt);
	if (fc != 0) {
		e = fc_decode(fc);
		for (i = 0; i < cnt; i++) {
			data->map[i].t_type = SEGMF_MAP_EMPTY;
		}
	}

out:
	mutex_exit(&data->lock);
	return (e);
}

int
segmf_release_grefs(struct seg *seg, caddr_t addr, uint_t cnt)
{
	gnttab_unmap_grant_ref_t mapop[SEGMF_MAX_GREFS];
	struct segmf_data *data;
	segmf_map_t *map;
	uint_t idx;
	long e;
	int i;
	int n;


	if (cnt > SEGMF_MAX_GREFS) {
		return (-1);
	}

	idx = seg_page(seg, addr);
	data = seg->s_data;
	map = &data->map[idx];

	bzero(mapop, sizeof (gnttab_unmap_grant_ref_t) * cnt);

	/*
	 * for each entry which isn't empty and is currently mapped,
	 * set it up for an unmap then mark them empty.
	 */
	n = 0;
	for (i = 0; i < cnt; i++) {
		ASSERT(map[i].t_type != SEGMF_MAP_MFN);
		if ((map[i].t_type == SEGMF_MAP_GREF) &&
		    (map[i].u.g.g_flags & SEGMF_GFLAGS_MAPPED)) {
			mapop[n].handle = map[i].u.g.g_handle;
			mapop[n].host_addr = map[i].u.g.g_ptep;
			mapop[n].dev_bus_addr = 0;
			n++;
		}
		map[i].t_type = SEGMF_MAP_EMPTY;
	}

	/* if there's nothing to unmap, just return */
	if (n == 0) {
		return (0);
	}

	e = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &mapop, n);
	if (e != 0) {
		return (-1);
	}

	return (0);
}


void
segmf_add_gref_pte(struct seg *seg, caddr_t addr, uint64_t pte_ma)
{
	struct segmf_data *data;
	uint_t idx;

	idx = seg_page(seg, addr);
	data = seg->s_data;

	data->map[idx].u.g.g_ptep = pte_ma;
}


static int
segmf_fault_gref_range(struct seg *seg, caddr_t addr, size_t cnt)
{
	gnttab_map_grant_ref_t mapop[SEGMF_MAX_GREFS];
	struct segmf_data *data;
	segmf_map_t *map;
	uint_t idx;
	int e;
	int i;


	if (cnt > SEGMF_MAX_GREFS) {
		return (-1);
	}

	data = seg->s_data;
	idx = seg_page(seg, addr);
	map = &data->map[idx];

	bzero(mapop, sizeof (gnttab_map_grant_ref_t) * cnt);

	ASSERT(map->t_type == SEGMF_MAP_GREF);

	/*
	 * map in each page passed in into the user apps AS. We do this by
	 * passing the MA of the actual pte of the mapping to the hypervisor.
	 */
	for (i = 0; i < cnt; i++) {
		mapop[i].host_addr = map[i].u.g.g_ptep;
		mapop[i].dom = data->domid;
		mapop[i].ref = map[i].u.g.g_gref;
		mapop[i].flags = GNTMAP_host_map | GNTMAP_application_map |
		    GNTMAP_contains_pte;
		if (!(map[i].u.g.g_flags & SEGMF_GFLAGS_WR)) {
			mapop[i].flags |= GNTMAP_readonly;
		}
	}
	e = xen_map_gref(GNTTABOP_map_grant_ref, mapop, cnt, B_TRUE);
	if ((e != 0) || (mapop[0].status != GNTST_okay)) {
		return (FC_MAKE_ERR(EFAULT));
	}

	/* save handle for segmf_release_grefs() and mark it as mapped */
	for (i = 0; i < cnt; i++) {
		ASSERT(mapop[i].status == GNTST_okay);
		map[i].u.g.g_handle = mapop[i].handle;
		map[i].u.g.g_flags |= SEGMF_GFLAGS_MAPPED;
	}

	return (0);
}

static struct seg_ops segmf_ops = {
	segmf_dup,
	segmf_unmap,
	segmf_free,
	segmf_fault,
	segmf_faulta,
	segmf_setprot,
	segmf_checkprot,
	(int (*)())segmf_kluster,
	(size_t (*)(struct seg *))NULL,	/* swapout */
	segmf_sync,
	segmf_incore,
	segmf_lockop,
	segmf_getprot,
	segmf_getoffset,
	segmf_gettype,
	segmf_getvp,
	segmf_advise,
	segmf_dump,
	segmf_pagelock,
	segmf_setpagesize,
	segmf_getmemid,
	segmf_getpolicy,
	segmf_capable,
	seg_inherit_notsup
};
