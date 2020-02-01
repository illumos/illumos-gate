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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * sun4v LDC Link Layer Shared Memory Routines
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/debug.h>
#include <sys/cyclic.h>
#include <sys/machsystm.h>
#include <sys/vm.h>
#include <sys/machcpuvar.h>
#include <sys/mmu.h>
#include <sys/pte.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>
#include <sys/vm_machparam.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <sys/hypervisor_api.h>
#include <sys/ldc.h>
#include <sys/ldc_impl.h>

/* LDC variables used by shared memory routines */
extern ldc_soft_state_t *ldcssp;
extern int ldc_max_retries;
extern clock_t ldc_delay;

#ifdef DEBUG
extern int ldcdbg;
#endif

/* LDC internal functions used by shared memory routines */
extern void i_ldc_reset(ldc_chan_t *ldcp, boolean_t force_reset);
extern int i_ldc_h2v_error(int h_error);

#ifdef DEBUG
extern void ldcdebug(int64_t id, const char *fmt, ...);
#endif

/* Memory synchronization internal functions */
static int i_ldc_mem_acquire_release(ldc_mem_handle_t mhandle,
    uint8_t direction, uint64_t offset, size_t size);
static int i_ldc_dring_acquire_release(ldc_dring_handle_t dhandle,
    uint8_t direction, uint64_t start, uint64_t end);
static int i_ldc_mem_map(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint8_t mtype, uint8_t perm, caddr_t *vaddr,
    caddr_t *raddr);
static int i_ldc_mem_bind_handle(ldc_mem_handle_t mhandle, caddr_t vaddr,
    size_t len, uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie,
    uint32_t *ccount);

/*
 * LDC framework supports mapping remote domain's memory
 * either directly or via shadow memory pages. Default
 * support is currently implemented via shadow copy.
 * Direct map can be enabled by setting 'ldc_shmem_enabled'
 */
int ldc_shmem_enabled = 1;

/*
 * Use of directly mapped shared memory for LDC descriptor
 * rings is permitted if this variable is non-zero.
 */
int ldc_dring_shmem_enabled = 1;

/*
 * The major and minor versions required to use directly
 * mapped shared memory for LDC descriptor rings. The
 * ldc_dring_shmem_hv_force variable, if set to a non-zero
 * value, overrides the hypervisor API version check.
 */
static int ldc_dring_shmem_hv_major = 1;
static int ldc_dring_shmem_hv_minor = 1;
static int ldc_dring_shmem_hv_force = 0;

/*
 * The results of the hypervisor service group API check.
 * A non-zero value indicates the HV includes support for
 * descriptor ring shared memory.
 */
static int ldc_dring_shmem_hv_ok = 0;

/*
 * Pages exported for remote access over each channel is
 * maintained in a table registered with the Hypervisor.
 * The default number of entries in the table is set to
 * 'ldc_mtbl_entries'.
 */
uint64_t ldc_maptable_entries = LDC_MTBL_ENTRIES;

#define	IDX2COOKIE(idx, pg_szc, pg_shift)				\
	(((pg_szc) << LDC_COOKIE_PGSZC_SHIFT) | ((idx) << (pg_shift)))

/*
 * Pages imported over each channel are maintained in a global (per-guest)
 * mapin table. Starting with HV LDC API version 1.2, HV supports APIs to
 * obtain information about the total size of the memory that can be direct
 * mapped through this mapin table. The minimum size of the mapin area that we
 * expect is defined below.
 */
#define	GIGABYTE		((uint64_t)(1 << 30))
uint64_t ldc_mapin_size_min = GIGABYTE;

/* HV LDC API version that supports mapin size info */
#define	LDC_MAPIN_VER_MAJOR	1
#define	LDC_MAPIN_VER_MINOR	2

/*
 * Sets ldc_dring_shmem_hv_ok to a non-zero value if the HV LDC
 * API version supports directly mapped shared memory or if it has
 * been explicitly enabled via ldc_dring_shmem_hv_force.
 */
void
i_ldc_mem_set_hsvc_vers(uint64_t major, uint64_t minor)
{
	if ((major == ldc_dring_shmem_hv_major &&
	    minor >= ldc_dring_shmem_hv_minor) ||
	    (major > ldc_dring_shmem_hv_major) ||
	    (ldc_dring_shmem_hv_force != 0)) {
		ldc_dring_shmem_hv_ok = 1;
	}
}

/*
 * initialize mapin table.
 */
void
i_ldc_init_mapin(ldc_soft_state_t *ldcssp, uint64_t major, uint64_t minor)
{
	int		rv;
	uint64_t	sz;
	uint64_t	table_type = LDC_MAPIN_TYPE_REGULAR;

	/* set mapin size to default. */
	ldcssp->mapin_size = LDC_DIRECT_MAP_SIZE_DEFAULT;

	/* Check if the HV supports mapin size API. */
	if ((major == LDC_MAPIN_VER_MAJOR &&
	    minor < LDC_MAPIN_VER_MINOR) ||
	    (major < LDC_MAPIN_VER_MAJOR)) {
		/* Older version of HV. */
		return;
	}

	/* Get info about the mapin size supported by HV */
	rv = hv_ldc_mapin_size_max(table_type, &sz);
	if (rv != 0) {
		cmn_err(CE_NOTE, "Failed to get mapin information\n");
		return;
	}

	/* Save the table size */
	ldcssp->mapin_size = sz;

	D1(DBG_ALL_LDCS, "%s: mapin_size read from HV is (0x%llx)\n",
	    __func__, sz);
}

/*
 * Allocate a memory handle for the channel and link it into the list
 * Also choose which memory table to use if this is the first handle
 * being assigned to this channel
 */
int
ldc_mem_alloc_handle(ldc_handle_t handle, ldc_mem_handle_t *mhandle)
{
	ldc_chan_t	*ldcp;
	ldc_mhdl_t	*mhdl;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_alloc_handle: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* check to see if channel is initalized */
	if ((ldcp->tstate & ~TS_IN_RESET) < TS_INIT) {
		DWARN(ldcp->id,
		    "ldc_mem_alloc_handle: (0x%llx) channel not initialized\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EINVAL);
	}

	/* allocate handle for channel */
	mhdl = kmem_cache_alloc(ldcssp->memhdl_cache, KM_SLEEP);

	/* initialize the lock */
	mutex_init(&mhdl->lock, NULL, MUTEX_DRIVER, NULL);

	mhdl->myshadow = B_FALSE;
	mhdl->memseg = NULL;
	mhdl->ldcp = ldcp;
	mhdl->status = LDC_UNBOUND;

	/* insert memory handle (@ head) into list */
	if (ldcp->mhdl_list == NULL) {
		ldcp->mhdl_list = mhdl;
		mhdl->next = NULL;
	} else {
		/* insert @ head */
		mhdl->next = ldcp->mhdl_list;
		ldcp->mhdl_list = mhdl;
	}

	/* return the handle */
	*mhandle = (ldc_mem_handle_t)mhdl;

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "ldc_mem_alloc_handle: (0x%llx) allocated handle 0x%llx\n",
	    ldcp->id, mhdl);

	return (0);
}

/*
 * Free memory handle for the channel and unlink it from the list
 */
int
ldc_mem_free_handle(ldc_mem_handle_t mhandle)
{
	ldc_mhdl_t	*mhdl, *phdl;
	ldc_chan_t	*ldcp;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_free_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;

	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED) {
		DWARN(ldcp->id,
		    "ldc_mem_free_handle: cannot free, 0x%llx hdl bound\n",
		    mhdl);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}
	mutex_exit(&mhdl->lock);

	mutex_enter(&ldcp->mlist_lock);

	phdl = ldcp->mhdl_list;

	/* first handle */
	if (phdl == mhdl) {
		ldcp->mhdl_list = mhdl->next;
		mutex_destroy(&mhdl->lock);
		kmem_cache_free(ldcssp->memhdl_cache, mhdl);

		D1(ldcp->id,
		    "ldc_mem_free_handle: (0x%llx) freed handle 0x%llx\n",
		    ldcp->id, mhdl);
	} else {
		/* walk the list - unlink and free */
		while (phdl != NULL) {
			if (phdl->next == mhdl) {
				phdl->next = mhdl->next;
				mutex_destroy(&mhdl->lock);
				kmem_cache_free(ldcssp->memhdl_cache, mhdl);
				D1(ldcp->id,
				    "ldc_mem_free_handle: (0x%llx) freed "
				    "handle 0x%llx\n", ldcp->id, mhdl);
				break;
			}
			phdl = phdl->next;
		}
	}

	if (phdl == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_free_handle: invalid handle 0x%llx\n", mhdl);
		mutex_exit(&ldcp->mlist_lock);
		return (EINVAL);
	}

	mutex_exit(&ldcp->mlist_lock);

	return (0);
}

/*
 * Bind a memory handle to a virtual address.
 * The virtual address is converted to the corresponding real addresses.
 * Returns pointer to the first ldc_mem_cookie and the total number
 * of cookies for this virtual address. Other cookies can be obtained
 * using the ldc_mem_nextcookie() call. If the pages are stored in
 * consecutive locations in the table, a single cookie corresponding to
 * the first location is returned. The cookie size spans all the entries.
 *
 * If the VA corresponds to a page that is already being exported, reuse
 * the page and do not export it again. Bump the page's use count.
 */
int
ldc_mem_bind_handle(ldc_mem_handle_t mhandle, caddr_t vaddr, size_t len,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount)
{
	/*
	 * Check if direct shared memory map is enabled, if not change
	 * the mapping type to SHADOW_MAP.
	 */
	if (ldc_shmem_enabled == 0)
		mtype = LDC_SHADOW_MAP;

	return (i_ldc_mem_bind_handle(mhandle, vaddr, len, mtype, perm,
	    cookie, ccount));
}

static int
i_ldc_mem_bind_handle(ldc_mem_handle_t mhandle, caddr_t vaddr, size_t len,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t	*ldcp;
	ldc_mtbl_t	*mtbl;
	ldc_memseg_t	*memseg;
	ldc_mte_t	tmp_mte;
	uint64_t	index, prev_index = 0;
	int64_t		cookie_idx;
	uintptr_t	raddr, ra_aligned;
	uint64_t	psize, poffset, v_offset;
	uint64_t	pg_shift, pg_size, pg_size_code, pg_mask;
	pgcnt_t		npages;
	caddr_t		v_align, addr;
	int		i, rv;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_bind_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;
	ldcp = mhdl->ldcp;

	/* clear count */
	*ccount = 0;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_BOUND || mhdl->memseg != NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_bind_handle: (0x%x) handle already bound\n",
		    mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(ldcp->id,
		    "ldc_mem_bind_handle: addr/size is not 8-byte aligned\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	mutex_enter(&ldcp->lock);

	/*
	 * If this channel is binding a memory handle for the
	 * first time allocate it a memory map table and initialize it
	 */
	if ((mtbl = ldcp->mtbl) == NULL) {

		/* Allocate and initialize the map table structure */
		mtbl = kmem_zalloc(sizeof (ldc_mtbl_t), KM_SLEEP);
		mtbl->num_entries = mtbl->num_avail = ldc_maptable_entries;
		mtbl->size = ldc_maptable_entries * sizeof (ldc_mte_slot_t);
		mtbl->next_entry = 0;
		mtbl->contigmem = B_TRUE;

		/* Allocate the table itself */
		mtbl->table = (ldc_mte_slot_t *)
		    contig_mem_alloc_align(mtbl->size, MMU_PAGESIZE);
		if (mtbl->table == NULL) {

			/* allocate a page of memory using kmem_alloc */
			mtbl->table = kmem_alloc(MMU_PAGESIZE, KM_SLEEP);
			mtbl->size = MMU_PAGESIZE;
			mtbl->contigmem = B_FALSE;
			mtbl->num_entries = mtbl->num_avail =
			    mtbl->size / sizeof (ldc_mte_slot_t);
			DWARN(ldcp->id,
			    "ldc_mem_bind_handle: (0x%llx) reduced tbl size "
			    "to %lx entries\n", ldcp->id, mtbl->num_entries);
		}

		/* zero out the memory */
		bzero(mtbl->table, mtbl->size);

		/* initialize the lock */
		mutex_init(&mtbl->lock, NULL, MUTEX_DRIVER, NULL);

		/* register table for this channel */
		rv = hv_ldc_set_map_table(ldcp->id,
		    va_to_pa(mtbl->table), mtbl->num_entries);
		if (rv != 0) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_bind_handle: (0x%lx) err %d mapping tbl",
			    ldcp->id, rv);
			if (mtbl->contigmem)
				contig_mem_free(mtbl->table, mtbl->size);
			else
				kmem_free(mtbl->table, mtbl->size);
			mutex_destroy(&mtbl->lock);
			kmem_free(mtbl, sizeof (ldc_mtbl_t));
			mutex_exit(&ldcp->lock);
			mutex_exit(&mhdl->lock);
			return (EIO);
		}

		ldcp->mtbl = mtbl;

		D1(ldcp->id,
		    "ldc_mem_bind_handle: (0x%llx) alloc'd map table 0x%llx\n",
		    ldcp->id, ldcp->mtbl->table);
	}

	mutex_exit(&ldcp->lock);

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);
	pg_mask = ~(pg_size - 1);

	D1(ldcp->id, "ldc_mem_bind_handle: (0x%llx) binding "
	    "va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    ldcp->id, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	v_align = (caddr_t)(((uintptr_t)vaddr) & ~(pg_size - 1));
	v_offset = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len+v_offset)/pg_size;
	npages = ((len+v_offset)%pg_size == 0) ? npages : npages+1;

	D1(ldcp->id, "ldc_mem_bind_handle: binding "
	    "(0x%llx) v=0x%llx,val=0x%llx,off=0x%x,pgs=0x%x\n",
	    ldcp->id, vaddr, v_align, v_offset, npages);

	/* lock the memory table - exclusive access to channel */
	mutex_enter(&mtbl->lock);

	if (npages > mtbl->num_avail) {
		D1(ldcp->id, "ldc_mem_bind_handle: (0x%llx) no table entries\n",
		    ldcp->id);
		mutex_exit(&mtbl->lock);
		mutex_exit(&mhdl->lock);
		return (ENOMEM);
	}

	/* Allocate a memseg structure */
	memseg = mhdl->memseg =
	    kmem_cache_alloc(ldcssp->memseg_cache, KM_SLEEP);

	/* Allocate memory to store all pages and cookies */
	memseg->pages = kmem_zalloc((sizeof (ldc_page_t) * npages), KM_SLEEP);
	memseg->cookies =
	    kmem_zalloc((sizeof (ldc_mem_cookie_t) * npages), KM_SLEEP);

	D2(ldcp->id, "ldc_mem_bind_handle: (0x%llx) processing 0x%llx pages\n",
	    ldcp->id, npages);

	addr = v_align;

	/*
	 * Table slots are used in a round-robin manner. The algorithm permits
	 * inserting duplicate entries. Slots allocated earlier will typically
	 * get freed before we get back to reusing the slot.Inserting duplicate
	 * entries should be OK as we only lookup entries using the cookie addr
	 * i.e. tbl index, during export, unexport and copy operation.
	 *
	 * One implementation what was tried was to search for a duplicate
	 * page entry first and reuse it. The search overhead is very high and
	 * in the vnet case dropped the perf by almost half, 50 to 24 mbps.
	 * So it does make sense to avoid searching for duplicates.
	 *
	 * But during the process of searching for a free slot, if we find a
	 * duplicate entry we will go ahead and use it, and bump its use count.
	 */

	/* index to start searching from */
	index = mtbl->next_entry;
	cookie_idx = -1;

	tmp_mte.ll = 0;	/* initialise fields to 0 */

	if (mtype & LDC_DIRECT_MAP) {
		tmp_mte.mte_r = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_w = (perm & LDC_MEM_W) ? 1 : 0;
		tmp_mte.mte_x = (perm & LDC_MEM_X) ? 1 : 0;
	}

	if (mtype & LDC_SHADOW_MAP) {
		tmp_mte.mte_cr = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_cw = (perm & LDC_MEM_W) ? 1 : 0;
	}

	if (mtype & LDC_IO_MAP) {
		tmp_mte.mte_ir = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_iw = (perm & LDC_MEM_W) ? 1 : 0;
	}

	D1(ldcp->id, "ldc_mem_bind_handle mte=0x%llx\n", tmp_mte.ll);

	tmp_mte.mte_pgszc = pg_size_code;

	/* initialize each mem table entry */
	for (i = 0; i < npages; i++) {

		/* check if slot is available in the table */
		while (mtbl->table[index].entry.ll != 0) {

			index = (index + 1) % mtbl->num_entries;

			if (index == mtbl->next_entry) {
				/* we have looped around */
				DWARN(DBG_ALL_LDCS,
				    "ldc_mem_bind_handle: (0x%llx) cannot find "
				    "entry\n", ldcp->id);
				*ccount = 0;

				/* NOTE: free memory, remove previous entries */
				/* this shouldnt happen as num_avail was ok */

				mutex_exit(&mtbl->lock);
				mutex_exit(&mhdl->lock);
				return (ENOMEM);
			}
		}

		/* get the real address */
		raddr = va_to_pa((void *)addr);
		ra_aligned = ((uintptr_t)raddr & pg_mask);

		/* build the mte */
		tmp_mte.mte_rpfn = ra_aligned >> pg_shift;

		D1(ldcp->id, "ldc_mem_bind_handle mte=0x%llx\n", tmp_mte.ll);

		/* update entry in table */
		mtbl->table[index].entry = tmp_mte;

		D2(ldcp->id, "ldc_mem_bind_handle: (0x%llx) stored MTE 0x%llx"
		    " into loc 0x%llx\n", ldcp->id, tmp_mte.ll, index);

		/* calculate the size and offset for this export range */
		if (i == 0) {
			/* first page */
			psize = min((pg_size - v_offset), len);
			poffset = v_offset;

		} else if (i == (npages - 1)) {
			/* last page */
			psize =	(((uintptr_t)(vaddr + len)) &
			    ((uint64_t)(pg_size-1)));
			if (psize == 0)
				psize = pg_size;
			poffset = 0;

		} else {
			/* middle pages */
			psize = pg_size;
			poffset = 0;
		}

		/* store entry for this page */
		memseg->pages[i].index = index;
		memseg->pages[i].raddr = raddr;
		memseg->pages[i].mte = &(mtbl->table[index]);

		/* create the cookie */
		if (i == 0 || (index != prev_index + 1)) {
			cookie_idx++;
			memseg->cookies[cookie_idx].addr =
			    IDX2COOKIE(index, pg_size_code, pg_shift);
			memseg->cookies[cookie_idx].addr |= poffset;
			memseg->cookies[cookie_idx].size = psize;

		} else {
			memseg->cookies[cookie_idx].size += psize;
		}

		D1(ldcp->id, "ldc_mem_bind_handle: bound "
		    "(0x%llx) va=0x%llx, idx=0x%llx, "
		    "ra=0x%llx(sz=0x%x,off=0x%x)\n",
		    ldcp->id, addr, index, raddr, psize, poffset);

		/* decrement number of available entries */
		mtbl->num_avail--;

		/* increment va by page size */
		addr += pg_size;

		/* increment index */
		prev_index = index;
		index = (index + 1) % mtbl->num_entries;

		/* save the next slot */
		mtbl->next_entry = index;
	}

	mutex_exit(&mtbl->lock);

	/* memory handle = bound */
	mhdl->mtype = mtype;
	mhdl->perm = perm;
	mhdl->status = LDC_BOUND;

	/* update memseg_t */
	memseg->vaddr = vaddr;
	memseg->raddr = memseg->pages[0].raddr;
	memseg->size = len;
	memseg->npages = npages;
	memseg->ncookies = cookie_idx + 1;
	memseg->next_cookie = (memseg->ncookies > 1) ? 1 : 0;

	/* return count and first cookie */
	*ccount = memseg->ncookies;
	cookie->addr = memseg->cookies[0].addr;
	cookie->size = memseg->cookies[0].size;

	D1(ldcp->id,
	    "ldc_mem_bind_handle: (0x%llx) bound 0x%llx, va=0x%llx, "
	    "pgs=0x%llx cookies=0x%llx\n",
	    ldcp->id, mhdl, vaddr, npages, memseg->ncookies);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Return the next cookie associated with the specified memory handle
 */
int
ldc_mem_nextcookie(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t	*ldcp;
	ldc_memseg_t	*memseg;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_nextcookie: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	if (cookie == 0) {
		DWARN(ldcp->id,
		    "ldc_mem_nextcookie:(0x%llx) invalid cookie arg\n",
		    ldcp->id);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	if (memseg->next_cookie != 0) {
		cookie->addr = memseg->cookies[memseg->next_cookie].addr;
		cookie->size = memseg->cookies[memseg->next_cookie].size;
		memseg->next_cookie++;
		if (memseg->next_cookie == memseg->ncookies)
			memseg->next_cookie = 0;

	} else {
		DWARN(ldcp->id,
		    "ldc_mem_nextcookie:(0x%llx) no more cookies\n", ldcp->id);
		cookie->addr = 0;
		cookie->size = 0;
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	D1(ldcp->id,
	    "ldc_mem_nextcookie: (0x%llx) cookie addr=0x%llx,sz=0x%llx\n",
	    ldcp->id, cookie->addr, cookie->size);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Unbind the virtual memory region associated with the specified
 * memory handle. Allassociated cookies are freed and the corresponding
 * RA space is no longer exported.
 */
int
ldc_mem_unbind_handle(ldc_mem_handle_t mhandle)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t	*ldcp;
	ldc_mtbl_t	*mtbl;
	ldc_memseg_t	*memseg;
	uint64_t	cookie_addr;
	uint64_t	pg_shift, pg_size_code;
	int		i, rv, retries;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unbind_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_UNBOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unbind_handle: (0x%x) handle is not bound\n",
		    mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	ldcp = mhdl->ldcp;
	mtbl = ldcp->mtbl;

	memseg = mhdl->memseg;

	/* lock the memory table - exclusive access to channel */
	mutex_enter(&mtbl->lock);

	/* undo the pages exported */
	for (i = 0; i < memseg->npages; i++) {

		/* clear the entry from the table */
		memseg->pages[i].mte->entry.ll = 0;

		/* check for mapped pages, revocation cookie != 0 */
		if (memseg->pages[i].mte->cookie) {

			pg_size_code = page_szc(MMU_PAGESIZE);
			pg_shift = page_get_shift(pg_size_code);
			cookie_addr = IDX2COOKIE(memseg->pages[i].index,
			    pg_size_code, pg_shift);

			D1(ldcp->id, "ldc_mem_unbind_handle: (0x%llx) revoke "
			    "cookie 0x%llx, rcookie 0x%llx\n", ldcp->id,
			    cookie_addr, memseg->pages[i].mte->cookie);

			retries = 0;
			do {
				rv = hv_ldc_revoke(ldcp->id, cookie_addr,
				    memseg->pages[i].mte->cookie);

				if (rv != H_EWOULDBLOCK)
					break;

				drv_usecwait(ldc_delay);

			} while (retries++ < ldc_max_retries);

			if (rv) {
				DWARN(ldcp->id,
				    "ldc_mem_unbind_handle: (0x%llx) cannot "
				    "revoke mapping, cookie %llx\n", ldcp->id,
				    cookie_addr);
			}
		}

		mtbl->num_avail++;
	}
	mutex_exit(&mtbl->lock);

	/* free the allocated memseg and page structures */
	kmem_free(memseg->pages, (sizeof (ldc_page_t) * memseg->npages));
	kmem_free(memseg->cookies,
	    (sizeof (ldc_mem_cookie_t) * memseg->npages));
	kmem_cache_free(ldcssp->memseg_cache, memseg);

	/* uninitialize the memory handle */
	mhdl->memseg = NULL;
	mhdl->status = LDC_UNBOUND;

	D1(ldcp->id, "ldc_mem_unbind_handle: (0x%llx) unbound handle 0x%llx\n",
	    ldcp->id, mhdl);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Get information about the dring. The base address of the descriptor
 * ring along with the type and permission are returned back.
 */
int
ldc_mem_info(ldc_mem_handle_t mhandle, ldc_mem_info_t *minfo)
{
	ldc_mhdl_t	*mhdl;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_info: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	if (minfo == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_info: invalid args\n");
		return (EINVAL);
	}

	mutex_enter(&mhdl->lock);

	minfo->status = mhdl->status;
	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED) {
		minfo->vaddr = mhdl->memseg->vaddr;
		minfo->raddr = mhdl->memseg->raddr;
		minfo->mtype = mhdl->mtype;
		minfo->perm = mhdl->perm;
	}
	mutex_exit(&mhdl->lock);

	return (0);
}

/*
 * Copy data either from or to the client specified virtual address
 * space to or from the exported memory associated with the cookies.
 * The direction argument determines whether the data is read from or
 * written to exported memory.
 */
int
ldc_mem_copy(ldc_handle_t handle, caddr_t vaddr, uint64_t off, size_t *size,
    ldc_mem_cookie_t *cookies, uint32_t ccount, uint8_t direction)
{
	ldc_chan_t	*ldcp;
	uint64_t	local_voff, local_valign;
	uint64_t	cookie_addr, cookie_size;
	uint64_t	pg_shift, pg_size, pg_size_code;
	uint64_t	export_caddr, export_poff, export_psize, export_size;
	uint64_t	local_ra, local_poff, local_psize;
	uint64_t	copy_size, copied_len = 0, total_bal = 0, idx = 0;
	pgcnt_t		npages;
	size_t		len = *size;
	int		i, rv = 0;

	uint64_t	chid;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_copy: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;
	chid = ldcp->id;

	/* check to see if channel is UP */
	if (ldcp->tstate != TS_UP) {
		DWARN(chid, "ldc_mem_copy: (0x%llx) channel is not UP\n",
		    chid);
		return (ECONNRESET);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(chid,
		    "ldc_mem_copy: addr/sz is not 8-byte aligned\n");
		return (EINVAL);
	}

	/* Find the size of the exported memory */
	export_size = 0;
	for (i = 0; i < ccount; i++)
		export_size += cookies[i].size;

	/* check to see if offset is valid */
	if (off > export_size) {
		DWARN(chid,
		    "ldc_mem_copy: (0x%llx) start offset > export mem size\n",
		    chid);
		return (EINVAL);
	}

	/*
	 * Check to see if the export size is smaller than the size we
	 * are requesting to copy - if so flag an error
	 */
	if ((export_size - off) < *size) {
		DWARN(chid,
		    "ldc_mem_copy: (0x%llx) copy size > export mem size\n",
		    chid);
		return (EINVAL);
	}

	total_bal = min(export_size, *size);

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);

	D1(chid, "ldc_mem_copy: copying data "
	    "(0x%llx) va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    chid, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	local_valign = (((uintptr_t)vaddr) & ~(pg_size - 1));
	local_voff = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len+local_voff)/pg_size;
	npages = ((len+local_voff)%pg_size == 0) ? npages : npages+1;

	D1(chid,
	    "ldc_mem_copy: (0x%llx) v=0x%llx,val=0x%llx,off=0x%x,pgs=0x%x\n",
	    chid, vaddr, local_valign, local_voff, npages);

	local_ra = va_to_pa((void *)local_valign);
	local_poff = local_voff;
	local_psize = min(len, (pg_size - local_voff));

	len -= local_psize;

	/*
	 * find the first cookie in the list of cookies
	 * if the offset passed in is not zero
	 */
	for (idx = 0; idx < ccount; idx++) {
		cookie_size = cookies[idx].size;
		if (off < cookie_size)
			break;
		off -= cookie_size;
	}

	cookie_addr = cookies[idx].addr + off;
	cookie_size = cookies[idx].size - off;

	export_caddr = cookie_addr & ~(pg_size - 1);
	export_poff = cookie_addr & (pg_size - 1);
	export_psize = min(cookie_size, (pg_size - export_poff));

	for (;;) {

		copy_size = min(export_psize, local_psize);

		D1(chid,
		    "ldc_mem_copy:(0x%llx) dir=0x%x, caddr=0x%llx,"
		    " loc_ra=0x%llx, exp_poff=0x%llx, loc_poff=0x%llx,"
		    " exp_psz=0x%llx, loc_psz=0x%llx, copy_sz=0x%llx,"
		    " total_bal=0x%llx\n",
		    chid, direction, export_caddr, local_ra, export_poff,
		    local_poff, export_psize, local_psize, copy_size,
		    total_bal);

		rv = hv_ldc_copy(chid, direction,
		    (export_caddr + export_poff), (local_ra + local_poff),
		    copy_size, &copied_len);

		if (rv != 0) {
			int		error = EIO;
			uint64_t	rx_hd, rx_tl;

			DWARN(chid,
			    "ldc_mem_copy: (0x%llx) err %d during copy\n",
			    (unsigned long long)chid, rv);
			DWARN(chid,
			    "ldc_mem_copy: (0x%llx) dir=0x%x, caddr=0x%lx, "
			    "loc_ra=0x%lx, exp_poff=0x%lx, loc_poff=0x%lx,"
			    " exp_psz=0x%lx, loc_psz=0x%lx, copy_sz=0x%lx,"
			    " copied_len=0x%lx, total_bal=0x%lx\n",
			    chid, direction, export_caddr, local_ra,
			    export_poff, local_poff, export_psize, local_psize,
			    copy_size, copied_len, total_bal);

			*size = *size - total_bal;

			/*
			 * check if reason for copy error was due to
			 * a channel reset. we need to grab the lock
			 * just in case we have to do a reset.
			 */
			mutex_enter(&ldcp->lock);
			mutex_enter(&ldcp->tx_lock);

			rv = hv_ldc_rx_get_state(ldcp->id,
			    &rx_hd, &rx_tl, &(ldcp->link_state));
			if (ldcp->link_state == LDC_CHANNEL_DOWN ||
			    ldcp->link_state == LDC_CHANNEL_RESET) {
				i_ldc_reset(ldcp, B_FALSE);
				error = ECONNRESET;
			}

			mutex_exit(&ldcp->tx_lock);
			mutex_exit(&ldcp->lock);

			return (error);
		}

		ASSERT(copied_len <= copy_size);

		D2(chid, "ldc_mem_copy: copied=0x%llx\n", copied_len);
		export_poff += copied_len;
		local_poff += copied_len;
		export_psize -= copied_len;
		local_psize -= copied_len;
		cookie_size -= copied_len;

		total_bal -= copied_len;

		if (copy_size != copied_len)
			continue;

		if (export_psize == 0 && total_bal != 0) {

			if (cookie_size == 0) {
				idx++;
				cookie_addr = cookies[idx].addr;
				cookie_size = cookies[idx].size;

				export_caddr = cookie_addr & ~(pg_size - 1);
				export_poff = cookie_addr & (pg_size - 1);
				export_psize =
				    min(cookie_size, (pg_size-export_poff));
			} else {
				export_caddr += pg_size;
				export_poff = 0;
				export_psize = min(cookie_size, pg_size);
			}
		}

		if (local_psize == 0 && total_bal != 0) {
			local_valign += pg_size;
			local_ra = va_to_pa((void *)local_valign);
			local_poff = 0;
			local_psize = min(pg_size, len);
			len -= local_psize;
		}

		/* check if we are all done */
		if (total_bal == 0)
			break;
	}


	D1(chid,
	    "ldc_mem_copy: (0x%llx) done copying sz=0x%llx\n",
	    chid, *size);

	return (0);
}

/*
 * Copy data either from or to the client specified virtual address
 * space to or from HV physical memory.
 *
 * The direction argument determines whether the data is read from or
 * written to HV memory. direction values are LDC_COPY_IN/OUT similar
 * to the ldc_mem_copy interface
 */
int
ldc_mem_rdwr_cookie(ldc_handle_t handle, caddr_t vaddr, size_t *size,
    caddr_t paddr, uint8_t direction)
{
	ldc_chan_t	*ldcp;
	uint64_t	local_voff, local_valign;
	uint64_t	pg_shift, pg_size, pg_size_code;
	uint64_t	target_pa, target_poff, target_psize, target_size;
	uint64_t	local_ra, local_poff, local_psize;
	uint64_t	copy_size, copied_len = 0;
	pgcnt_t		npages;
	size_t		len = *size;
	int		rv = 0;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_rdwr_cookie: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* check to see if channel is UP */
	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_mem_rdwr_cookie: (0x%llx) channel is not UP\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (ECONNRESET);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(ldcp->id,
		    "ldc_mem_rdwr_cookie: addr/size is not 8-byte aligned\n");
		mutex_exit(&ldcp->lock);
		return (EINVAL);
	}

	target_size = *size;

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);

	D1(ldcp->id, "ldc_mem_rdwr_cookie: copying data "
	    "(0x%llx) va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    ldcp->id, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	local_valign = ((uintptr_t)vaddr) & ~(pg_size - 1);
	local_voff = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len + local_voff) / pg_size;
	npages = ((len + local_voff) % pg_size == 0) ? npages : npages+1;

	D1(ldcp->id, "ldc_mem_rdwr_cookie: (0x%llx) v=0x%llx, "
	    "val=0x%llx,off=0x%x,pgs=0x%x\n",
	    ldcp->id, vaddr, local_valign, local_voff, npages);

	local_ra = va_to_pa((void *)local_valign);
	local_poff = local_voff;
	local_psize = min(len, (pg_size - local_voff));

	len -= local_psize;

	target_pa = ((uintptr_t)paddr) & ~(pg_size - 1);
	target_poff = ((uintptr_t)paddr) & (pg_size - 1);
	target_psize = pg_size - target_poff;

	for (;;) {

		copy_size = min(target_psize, local_psize);

		D1(ldcp->id,
		    "ldc_mem_rdwr_cookie: (0x%llx) dir=0x%x, tar_pa=0x%llx,"
		    " loc_ra=0x%llx, tar_poff=0x%llx, loc_poff=0x%llx,"
		    " tar_psz=0x%llx, loc_psz=0x%llx, copy_sz=0x%llx,"
		    " total_bal=0x%llx\n",
		    ldcp->id, direction, target_pa, local_ra, target_poff,
		    local_poff, target_psize, local_psize, copy_size,
		    target_size);

		rv = hv_ldc_copy(ldcp->id, direction,
		    (target_pa + target_poff), (local_ra + local_poff),
		    copy_size, &copied_len);

		if (rv != 0) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_rdwr_cookie: (0x%lx) err %d during copy\n",
			    ldcp->id, rv);
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_rdwr_cookie: (0x%llx) dir=%lld, "
			    "tar_pa=0x%llx, loc_ra=0x%llx, tar_poff=0x%llx, "
			    "loc_poff=0x%llx, tar_psz=0x%llx, loc_psz=0x%llx, "
			    "copy_sz=0x%llx, total_bal=0x%llx\n",
			    ldcp->id, direction, target_pa, local_ra,
			    target_poff, local_poff, target_psize, local_psize,
			    copy_size, target_size);

			*size = *size - target_size;
			mutex_exit(&ldcp->lock);
			return (i_ldc_h2v_error(rv));
		}

		D2(ldcp->id, "ldc_mem_rdwr_cookie: copied=0x%llx\n",
		    copied_len);
		target_poff += copied_len;
		local_poff += copied_len;
		target_psize -= copied_len;
		local_psize -= copied_len;

		target_size -= copied_len;

		if (copy_size != copied_len)
			continue;

		if (target_psize == 0 && target_size != 0) {
			target_pa += pg_size;
			target_poff = 0;
			target_psize = min(pg_size, target_size);
		}

		if (local_psize == 0 && target_size != 0) {
			local_valign += pg_size;
			local_ra = va_to_pa((void *)local_valign);
			local_poff = 0;
			local_psize = min(pg_size, len);
			len -= local_psize;
		}

		/* check if we are all done */
		if (target_size == 0)
			break;
	}

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "ldc_mem_rdwr_cookie: (0x%llx) done copying sz=0x%llx\n",
	    ldcp->id, *size);

	return (0);
}

/*
 * Map an exported memory segment into the local address space. If the
 * memory range was exported for direct map access, a HV call is made
 * to allocate a RA range. If the map is done via a shadow copy, local
 * shadow memory is allocated and the base VA is returned in 'vaddr'. If
 * the mapping is a direct map then the RA is returned in 'raddr'.
 */
int
ldc_mem_map(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie, uint32_t ccount,
    uint8_t mtype, uint8_t perm, caddr_t *vaddr, caddr_t *raddr)
{
	/*
	 * Check if direct map over shared memory is enabled, if not change
	 * the mapping type to SHADOW_MAP.
	 */
	if (ldc_shmem_enabled == 0)
		mtype = LDC_SHADOW_MAP;

	return (i_ldc_mem_map(mhandle, cookie, ccount, mtype, perm,
	    vaddr, raddr));
}

static int
i_ldc_mem_map(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint8_t mtype, uint8_t perm, caddr_t *vaddr,
    caddr_t *raddr)
{

	int		i, j, idx, rv, retries;
	ldc_chan_t	*ldcp;
	ldc_mhdl_t	*mhdl;
	ldc_memseg_t	*memseg;
	caddr_t		tmpaddr;
	uint64_t	map_perm = perm;
	uint64_t	pg_size, pg_shift, pg_size_code, pg_mask;
	uint64_t	exp_size = 0, base_off, map_size, npages;
	uint64_t	cookie_addr, cookie_off, cookie_size;
	tte_t		ldc_tte;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_map: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED ||
	    mhdl->memseg != NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_map: (0x%llx) handle bound/mapped\n", mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	ldcp = mhdl->ldcp;

	mutex_enter(&ldcp->lock);

	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) channel is not UP\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		mutex_exit(&mhdl->lock);
		return (ECONNRESET);
	}

	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP|LDC_IO_MAP)) == 0) {
		DWARN(ldcp->id, "ldc_mem_map: invalid map type\n");
		mutex_exit(&ldcp->lock);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	D1(ldcp->id, "ldc_mem_map: (0x%llx) cookie = 0x%llx,0x%llx\n",
	    ldcp->id, cookie->addr, cookie->size);

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);
	pg_mask = ~(pg_size - 1);

	/* calculate the number of pages in the exported cookie */
	base_off = cookie[0].addr & (pg_size - 1);
	for (idx = 0; idx < ccount; idx++)
		exp_size += cookie[idx].size;
	map_size = P2ROUNDUP((exp_size + base_off), pg_size);
	npages = (map_size >> pg_shift);

	/* Allocate memseg structure */
	memseg = mhdl->memseg =
	    kmem_cache_alloc(ldcssp->memseg_cache, KM_SLEEP);

	/* Allocate memory to store all pages and cookies */
	memseg->pages =	kmem_zalloc((sizeof (ldc_page_t) * npages), KM_SLEEP);
	memseg->cookies =
	    kmem_zalloc((sizeof (ldc_mem_cookie_t) * ccount), KM_SLEEP);

	D2(ldcp->id, "ldc_mem_map: (0x%llx) exp_size=0x%llx, map_size=0x%llx,"
	    "pages=0x%llx\n", ldcp->id, exp_size, map_size, npages);

	/*
	 * Check to see if the client is requesting direct or shadow map
	 * If direct map is requested, try to map remote memory first,
	 * and if that fails, revert to shadow map
	 */
	if (mtype == LDC_DIRECT_MAP) {

		/* Allocate kernel virtual space for mapping */
		memseg->vaddr = vmem_xalloc(heap_arena, map_size,
		    pg_size, 0, 0, NULL, NULL, VM_NOSLEEP);
		if (memseg->vaddr == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_map: (0x%lx) memory map failed\n",
			    ldcp->id);
			kmem_free(memseg->cookies,
			    (sizeof (ldc_mem_cookie_t) * ccount));
			kmem_free(memseg->pages,
			    (sizeof (ldc_page_t) * npages));
			kmem_cache_free(ldcssp->memseg_cache, memseg);

			mutex_exit(&ldcp->lock);
			mutex_exit(&mhdl->lock);
			return (ENOMEM);
		}

		/* Unload previous mapping */
		hat_unload(kas.a_hat, memseg->vaddr, map_size,
		    HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK);

		/* for each cookie passed in - map into address space */
		idx = 0;
		cookie_size = 0;
		tmpaddr = memseg->vaddr;

		for (i = 0; i < npages; i++) {

			if (cookie_size == 0) {
				ASSERT(idx < ccount);
				cookie_addr = cookie[idx].addr & pg_mask;
				cookie_off = cookie[idx].addr & (pg_size - 1);
				cookie_size =
				    P2ROUNDUP((cookie_off + cookie[idx].size),
				    pg_size);
				idx++;
			}

			D1(ldcp->id, "ldc_mem_map: (0x%llx) mapping "
			    "cookie 0x%llx, bal=0x%llx\n", ldcp->id,
			    cookie_addr, cookie_size);

			/* map the cookie into address space */
			for (retries = 0; retries < ldc_max_retries;
			    retries++) {

				rv = hv_ldc_mapin(ldcp->id, cookie_addr,
				    &memseg->pages[i].raddr, &map_perm);
				if (rv != H_EWOULDBLOCK && rv != H_ETOOMANY)
					break;

				drv_usecwait(ldc_delay);
			}

			if (rv || memseg->pages[i].raddr == 0) {
				DWARN(ldcp->id,
				    "ldc_mem_map: (0x%llx) hv mapin err %d\n",
				    ldcp->id, rv);

				/* remove previous mapins */
				hat_unload(kas.a_hat, memseg->vaddr, map_size,
				    HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK);
				for (j = 0; j < i; j++) {
					rv = hv_ldc_unmap(
					    memseg->pages[j].raddr);
					if (rv) {
						DWARN(ldcp->id,
						    "ldc_mem_map: (0x%llx) "
						    "cannot unmap ra=0x%llx\n",
						    ldcp->id,
						    memseg->pages[j].raddr);
					}
				}

				/* free kernel virtual space */
				vmem_free(heap_arena, (void *)memseg->vaddr,
				    map_size);

				/* direct map failed - revert to shadow map */
				mtype = LDC_SHADOW_MAP;
				break;

			} else {

				D1(ldcp->id,
				    "ldc_mem_map: (0x%llx) vtop map 0x%llx -> "
				    "0x%llx, cookie=0x%llx, perm=0x%llx\n",
				    ldcp->id, tmpaddr, memseg->pages[i].raddr,
				    cookie_addr, perm);

				/*
				 * NOTE: Calling hat_devload directly, causes it
				 * to look for page_t using the pfn. Since this
				 * addr is greater than the memlist, it treates
				 * it as non-memory
				 */
				sfmmu_memtte(&ldc_tte,
				    (pfn_t)(memseg->pages[i].raddr >> pg_shift),
				    PROT_READ | PROT_WRITE | HAT_NOSYNC, TTE8K);

				D1(ldcp->id,
				    "ldc_mem_map: (0x%llx) ra 0x%llx -> "
				    "tte 0x%llx\n", ldcp->id,
				    memseg->pages[i].raddr, ldc_tte);

				sfmmu_tteload(kas.a_hat, &ldc_tte, tmpaddr,
				    NULL, HAT_LOAD_LOCK);

				cookie_size -= pg_size;
				cookie_addr += pg_size;
				tmpaddr += pg_size;
			}
		}
	}

	if (mtype == LDC_SHADOW_MAP) {
		if (*vaddr == NULL) {
			memseg->vaddr = kmem_zalloc(exp_size, KM_SLEEP);
			mhdl->myshadow = B_TRUE;

			D1(ldcp->id, "ldc_mem_map: (0x%llx) allocated "
			    "shadow page va=0x%llx\n", ldcp->id, memseg->vaddr);
		} else {
			/*
			 * Use client supplied memory for memseg->vaddr
			 * WARNING: assuming that client mem is >= exp_size
			 */
			memseg->vaddr = *vaddr;
		}

		/* Save all page and cookie information */
		for (i = 0, tmpaddr = memseg->vaddr; i < npages; i++) {
			memseg->pages[i].raddr = va_to_pa(tmpaddr);
			tmpaddr += pg_size;
		}

	}

	/* save all cookies */
	bcopy(cookie, memseg->cookies, ccount * sizeof (ldc_mem_cookie_t));

	/* update memseg_t */
	memseg->raddr = memseg->pages[0].raddr;
	memseg->size = (mtype == LDC_SHADOW_MAP) ? exp_size : map_size;
	memseg->npages = npages;
	memseg->ncookies = ccount;
	memseg->next_cookie = 0;

	/* memory handle = mapped */
	mhdl->mtype = mtype;
	mhdl->perm = perm;
	mhdl->status = LDC_MAPPED;

	D1(ldcp->id, "ldc_mem_map: (0x%llx) mapped 0x%llx, ra=0x%llx, "
	    "va=0x%llx, pgs=0x%llx cookies=0x%llx\n",
	    ldcp->id, mhdl, memseg->raddr, memseg->vaddr,
	    memseg->npages, memseg->ncookies);

	if (mtype == LDC_SHADOW_MAP)
		base_off = 0;
	if (raddr)
		*raddr = (caddr_t)(memseg->raddr | base_off);
	if (vaddr)
		*vaddr = (caddr_t)((uintptr_t)memseg->vaddr | base_off);

	mutex_exit(&ldcp->lock);
	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Unmap a memory segment. Free shadow memory (if any).
 */
int
ldc_mem_unmap(ldc_mem_handle_t mhandle)
{
	int		i, rv;
	ldc_mhdl_t	*mhdl = (ldc_mhdl_t *)mhandle;
	ldc_chan_t	*ldcp;
	ldc_memseg_t	*memseg;

	if (mhdl == 0 || mhdl->status != LDC_MAPPED) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unmap: (0x%llx) handle is not mapped\n",
		    mhandle);
		return (EINVAL);
	}

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	D1(ldcp->id, "ldc_mem_unmap: (0x%llx) unmapping handle 0x%llx\n",
	    ldcp->id, mhdl);

	/* if we allocated shadow memory - free it */
	if (mhdl->mtype == LDC_SHADOW_MAP && mhdl->myshadow) {
		kmem_free(memseg->vaddr, memseg->size);
	} else if (mhdl->mtype == LDC_DIRECT_MAP) {

		/* unmap in the case of DIRECT_MAP */
		hat_unload(kas.a_hat, memseg->vaddr, memseg->size,
		    HAT_UNLOAD_UNLOCK);

		for (i = 0; i < memseg->npages; i++) {
			rv = hv_ldc_unmap(memseg->pages[i].raddr);
			if (rv) {
				DWARN(DBG_ALL_LDCS,
				    "ldc_mem_map: (0x%lx) hv unmap err %d\n",
				    ldcp->id, rv);
			}
		}

		vmem_free(heap_arena, (void *)memseg->vaddr, memseg->size);
	}

	/* free the allocated memseg and page structures */
	kmem_free(memseg->pages, (sizeof (ldc_page_t) * memseg->npages));
	kmem_free(memseg->cookies,
	    (sizeof (ldc_mem_cookie_t) * memseg->ncookies));
	kmem_cache_free(ldcssp->memseg_cache, memseg);

	/* uninitialize the memory handle */
	mhdl->memseg = NULL;
	mhdl->status = LDC_UNBOUND;

	D1(ldcp->id, "ldc_mem_unmap: (0x%llx) unmapped handle 0x%llx\n",
	    ldcp->id, mhdl);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Internal entry point for LDC mapped memory entry consistency
 * semantics. Acquire copies the contents of the remote memory
 * into the local shadow copy. The release operation copies the local
 * contents into the remote memory. The offset and size specify the
 * bounds for the memory range being synchronized.
 */
static int
i_ldc_mem_acquire_release(ldc_mem_handle_t mhandle, uint8_t direction,
    uint64_t offset, size_t size)
{
	int		err;
	ldc_mhdl_t	*mhdl;
	ldc_chan_t	*ldcp;
	ldc_memseg_t	*memseg;
	caddr_t		local_vaddr;
	size_t		copy_size;

	if (mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status != LDC_MAPPED || mhdl->ldcp == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: not mapped memory\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* do nothing for direct map */
	if (mhdl->mtype == LDC_DIRECT_MAP) {
		mutex_exit(&mhdl->lock);
		return (0);
	}

	/* do nothing if COPY_IN+MEM_W and COPY_OUT+MEM_R */
	if ((direction == LDC_COPY_IN && (mhdl->perm & LDC_MEM_R) == 0) ||
	    (direction == LDC_COPY_OUT && (mhdl->perm & LDC_MEM_W) == 0)) {
		mutex_exit(&mhdl->lock);
		return (0);
	}

	if (offset >= mhdl->memseg->size ||
	    (offset + size) > mhdl->memseg->size) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: memory out of range\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* get the channel handle and memory segment */
	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	if (mhdl->mtype == LDC_SHADOW_MAP) {

		local_vaddr = memseg->vaddr + offset;
		copy_size = size;

		/* copy to/from remote from/to local memory */
		err = ldc_mem_copy((ldc_handle_t)ldcp, local_vaddr, offset,
		    &copy_size, memseg->cookies, memseg->ncookies,
		    direction);
		if (err || copy_size != size) {
			DWARN(ldcp->id,
			    "i_ldc_mem_acquire_release: copy failed\n");
			mutex_exit(&mhdl->lock);
			return (err);
		}
	}

	mutex_exit(&mhdl->lock);

	return (0);
}

/*
 * Ensure that the contents in the remote memory seg are consistent
 * with the contents if of local segment
 */
int
ldc_mem_acquire(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size)
{
	return (i_ldc_mem_acquire_release(mhandle, LDC_COPY_IN, offset, size));
}


/*
 * Ensure that the contents in the local memory seg are consistent
 * with the contents if of remote segment
 */
int
ldc_mem_release(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size)
{
	return (i_ldc_mem_acquire_release(mhandle, LDC_COPY_OUT, offset, size));
}

/*
 * Allocate a descriptor ring. The size of each each descriptor
 * must be 8-byte aligned and the entire ring should be a multiple
 * of MMU_PAGESIZE.
 */
int
ldc_mem_dring_create(uint32_t len, uint32_t dsize, ldc_dring_handle_t *dhandle)
{
	ldc_dring_t *dringp;
	size_t size = (dsize * len);

	D1(DBG_ALL_LDCS, "ldc_mem_dring_create: len=0x%x, size=0x%x\n",
	    len, dsize);

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid dhandle\n");
		return (EINVAL);
	}

	if (len == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid length\n");
		return (EINVAL);
	}

	/* descriptor size should be 8-byte aligned */
	if (dsize == 0 || (dsize & 0x7)) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid size\n");
		return (EINVAL);
	}

	*dhandle = 0;

	/* Allocate a desc ring structure */
	dringp = kmem_zalloc(sizeof (ldc_dring_t), KM_SLEEP);

	/* Initialize dring */
	dringp->length = len;
	dringp->dsize = dsize;

	/* round off to multiple of pagesize */
	dringp->size = (size & MMU_PAGEMASK);
	if (size & MMU_PAGEOFFSET)
		dringp->size += MMU_PAGESIZE;

	dringp->status = LDC_UNBOUND;

	/* allocate descriptor ring memory */
	dringp->base = kmem_zalloc(dringp->size, KM_SLEEP);

	/* initialize the desc ring lock */
	mutex_init(&dringp->lock, NULL, MUTEX_DRIVER, NULL);

	/* Add descriptor ring to the head of global list */
	mutex_enter(&ldcssp->lock);
	dringp->next = ldcssp->dring_list;
	ldcssp->dring_list = dringp;
	mutex_exit(&ldcssp->lock);

	*dhandle = (ldc_dring_handle_t)dringp;

	D1(DBG_ALL_LDCS, "ldc_mem_dring_create: dring allocated\n");

	return (0);
}


/*
 * Destroy a descriptor ring.
 */
int
ldc_mem_dring_destroy(ldc_dring_handle_t dhandle)
{
	ldc_dring_t *dringp;
	ldc_dring_t *tmp_dringp;

	D1(DBG_ALL_LDCS, "ldc_mem_dring_destroy: entered\n");

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_destroy: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (dringp->status == LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_destroy: desc ring is bound\n");
		return (EACCES);
	}

	mutex_enter(&dringp->lock);
	mutex_enter(&ldcssp->lock);

	/* remove from linked list - if not bound */
	tmp_dringp = ldcssp->dring_list;
	if (tmp_dringp == dringp) {
		ldcssp->dring_list = dringp->next;
		dringp->next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->next == dringp) {
				tmp_dringp->next = dringp->next;
				dringp->next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_destroy: invalid descriptor\n");
			mutex_exit(&ldcssp->lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcssp->lock);

	/* free the descriptor ring */
	kmem_free(dringp->base, dringp->size);

	mutex_exit(&dringp->lock);

	/* destroy dring lock */
	mutex_destroy(&dringp->lock);

	/* free desc ring object */
	kmem_free(dringp, sizeof (ldc_dring_t));

	return (0);
}

/*
 * Bind a previously allocated dring to a channel. The channel should
 * be OPEN in order to bind the ring to the channel. Returns back a
 * descriptor ring cookie. The descriptor ring is exported for remote
 * access by the client at the other end of the channel. An entry for
 * dring pages is stored in map table (via call to ldc_mem_bind_handle).
 */
int
ldc_mem_dring_bind(ldc_handle_t handle, ldc_dring_handle_t dhandle,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount)
{
	int		err;
	ldc_chan_t	*ldcp;
	ldc_dring_t	*dringp;
	ldc_mem_handle_t mhandle;

	/* check to see if channel is initalized */
	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_bind: invalid cookie arg\n");
		return (EINVAL);
	}

	/* ensure the mtype is valid */
	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP)) == 0) {
		DWARN(ldcp->id, "ldc_mem_dring_bind: invalid map type\n");
		return (EINVAL);
	}

	/* no need to bind as direct map if it's not HV supported or enabled */
	if (!ldc_dring_shmem_hv_ok || !ldc_dring_shmem_enabled) {
		mtype = LDC_SHADOW_MAP;
	}

	mutex_enter(&dringp->lock);

	if (dringp->status == LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: (0x%llx) descriptor ring is bound\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if ((perm & LDC_MEM_RW) == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid permissions\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP|LDC_IO_MAP)) == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_bind: invalid type\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	dringp->ldcp = ldcp;

	/* create an memory handle */
	err = ldc_mem_alloc_handle(handle, &mhandle);
	if (err || mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: (0x%llx) error allocating mhandle\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (err);
	}
	dringp->mhdl = mhandle;

	/* bind the descriptor ring to channel */
	err = i_ldc_mem_bind_handle(mhandle, dringp->base, dringp->size,
	    mtype, perm, cookie, ccount);
	if (err) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_bind: (0x%llx) error binding mhandle\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (err);
	}

	/*
	 * For now return error if we get more than one cookie
	 * FUTURE: Return multiple cookies ..
	 */
	if (*ccount > 1) {
		(void) ldc_mem_unbind_handle(mhandle);
		(void) ldc_mem_free_handle(mhandle);

		dringp->ldcp = NULL;
		dringp->mhdl = 0;
		*ccount = 0;

		mutex_exit(&dringp->lock);
		return (EAGAIN);
	}

	/* Add descriptor ring to channel's exported dring list */
	mutex_enter(&ldcp->exp_dlist_lock);
	dringp->ch_next = ldcp->exp_dring_list;
	ldcp->exp_dring_list = dringp;
	mutex_exit(&ldcp->exp_dlist_lock);

	dringp->status = LDC_BOUND;

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Return the next cookie associated with the specified dring handle
 */
int
ldc_mem_dring_nextcookie(ldc_dring_handle_t dhandle, ldc_mem_cookie_t *cookie)
{
	int		rv = 0;
	ldc_dring_t	*dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_nextcookie: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;
	mutex_enter(&dringp->lock);

	if (dringp->status != LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_nextcookie: descriptor ring 0x%llx "
		    "is not bound\n", dringp);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	ldcp = dringp->ldcp;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_nextcookie:(0x%llx) invalid cookie arg\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	rv = ldc_mem_nextcookie((ldc_mem_handle_t)dringp->mhdl, cookie);
	mutex_exit(&dringp->lock);

	return (rv);
}

/*
 * Unbind a previously bound dring from a channel.
 */
int
ldc_mem_dring_unbind(ldc_dring_handle_t dhandle)
{
	ldc_dring_t	*dringp;
	ldc_dring_t	*tmp_dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unbind: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	mutex_enter(&dringp->lock);

	if (dringp->status == LDC_UNBOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: descriptor ring 0x%llx is unbound\n",
		    dringp);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}
	ldcp = dringp->ldcp;

	mutex_enter(&ldcp->exp_dlist_lock);

	tmp_dringp = ldcp->exp_dring_list;
	if (tmp_dringp == dringp) {
		ldcp->exp_dring_list = dringp->ch_next;
		dringp->ch_next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->ch_next == dringp) {
				tmp_dringp->ch_next = dringp->ch_next;
				dringp->ch_next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->ch_next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_unbind: invalid descriptor\n");
			mutex_exit(&ldcp->exp_dlist_lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcp->exp_dlist_lock);

	(void) ldc_mem_unbind_handle((ldc_mem_handle_t)dringp->mhdl);
	(void) ldc_mem_free_handle((ldc_mem_handle_t)dringp->mhdl);

	dringp->ldcp = NULL;
	dringp->mhdl = 0;
	dringp->status = LDC_UNBOUND;

	mutex_exit(&dringp->lock);

	return (0);
}

#ifdef	DEBUG
void
i_ldc_mem_inject_dring_clear(ldc_chan_t *ldcp)
{
	ldc_dring_t	*dp;
	ldc_mhdl_t	*mhdl;
	ldc_mtbl_t	*mtbl;
	ldc_memseg_t	*memseg;
	uint64_t	cookie_addr;
	uint64_t	pg_shift, pg_size_code;
	int		i, rv, retries;

	/* has a map table been allocated? */
	if ((mtbl = ldcp->mtbl) == NULL)
		return;

	/* lock the memory table - exclusive access to channel */
	mutex_enter(&mtbl->lock);

	/* lock the exported dring list */
	mutex_enter(&ldcp->exp_dlist_lock);

	for (dp = ldcp->exp_dring_list; dp != NULL; dp = dp->ch_next) {
		if ((mhdl = (ldc_mhdl_t *)dp->mhdl) == NULL)
			continue;

		if ((memseg = mhdl->memseg) == NULL)
			continue;

		/* undo the pages exported */
		for (i = 0; i < memseg->npages; i++) {

			/* clear the entry from the table */
			memseg->pages[i].mte->entry.ll = 0;

			pg_size_code = page_szc(MMU_PAGESIZE);
			pg_shift = page_get_shift(pg_size_code);
			cookie_addr = IDX2COOKIE(memseg->pages[i].index,
			    pg_size_code, pg_shift);

			retries = 0;
			do {
				rv = hv_ldc_revoke(ldcp->id, cookie_addr,
				    memseg->pages[i].mte->cookie);

				if (rv != H_EWOULDBLOCK)
					break;

				drv_usecwait(ldc_delay);

			} while (retries++ < ldc_max_retries);

			if (rv != 0) {
				DWARN(ldcp->id,
				    "i_ldc_mem_inject_dring_clear(): "
				    "hv_ldc_revoke failed: "
				    "channel: 0x%lx, cookie addr: 0x%p,"
				    "cookie: 0x%lx, rv: %d",
				    ldcp->id, cookie_addr,
				    memseg->pages[i].mte->cookie, rv);
			}

			mtbl->num_avail++;
		}
	}

	mutex_exit(&ldcp->exp_dlist_lock);
	mutex_exit(&mtbl->lock);
}
#endif

/*
 * Get information about the dring. The base address of the descriptor
 * ring along with the type and permission are returned back.
 */
int
ldc_mem_dring_info(ldc_dring_handle_t dhandle, ldc_mem_info_t *minfo)
{
	ldc_dring_t	*dringp;
	int		rv;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_info: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	mutex_enter(&dringp->lock);

	if (dringp->mhdl) {
		rv = ldc_mem_info(dringp->mhdl, minfo);
		if (rv) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_info: error reading mem info\n");
			mutex_exit(&dringp->lock);
			return (rv);
		}
	} else {
		minfo->vaddr = dringp->base;
		minfo->raddr = 0;
		minfo->status = dringp->status;
	}

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Map an exported descriptor ring into the local address space. If the
 * descriptor ring was exported for direct map access, a HV call is made
 * to allocate a RA range. If the map is done via a shadow copy, local
 * shadow memory is allocated.
 */
int
ldc_mem_dring_map(ldc_handle_t handle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint32_t len, uint32_t dsize, uint8_t mtype,
    ldc_dring_handle_t *dhandle)
{
	int		err;
	ldc_chan_t	*ldcp = (ldc_chan_t *)handle;
	ldc_mem_handle_t mhandle;
	ldc_dring_t	*dringp;
	size_t		dring_size;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: invalid dhandle\n");
		return (EINVAL);
	}

	/* check to see if channel is initalized */
	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) invalid cookie\n",
		    ldcp->id);
		return (EINVAL);
	}

	/* FUTURE: For now we support only one cookie per dring */
	ASSERT(ccount == 1);

	if (cookie->size < (dsize * len)) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) invalid dsize/len\n",
		    ldcp->id);
		return (EINVAL);
	}

	/* ensure the mtype is valid */
	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP)) == 0) {
		DWARN(ldcp->id, "ldc_mem_dring_map: invalid map type\n");
		return (EINVAL);
	}

	/* do not attempt direct map if it's not HV supported or enabled */
	if (!ldc_dring_shmem_hv_ok || !ldc_dring_shmem_enabled) {
		mtype = LDC_SHADOW_MAP;
	}

	*dhandle = 0;

	/* Allocate an dring structure */
	dringp = kmem_zalloc(sizeof (ldc_dring_t), KM_SLEEP);

	D1(ldcp->id,
	    "ldc_mem_dring_map: 0x%x,0x%x,0x%x,0x%llx,0x%llx\n",
	    mtype, len, dsize, cookie->addr, cookie->size);

	/* Initialize dring */
	dringp->length = len;
	dringp->dsize = dsize;

	/* round of to multiple of page size */
	dring_size = len * dsize;
	dringp->size = (dring_size & MMU_PAGEMASK);
	if (dring_size & MMU_PAGEOFFSET)
		dringp->size += MMU_PAGESIZE;

	dringp->ldcp = ldcp;

	/* create an memory handle */
	err = ldc_mem_alloc_handle(handle, &mhandle);
	if (err || mhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: cannot alloc hdl err=%d\n",
		    err);
		kmem_free(dringp, sizeof (ldc_dring_t));
		return (ENOMEM);
	}

	dringp->mhdl = mhandle;
	dringp->base = NULL;

	/* map the dring into local memory */
	err = i_ldc_mem_map(mhandle, cookie, ccount, mtype, LDC_MEM_RW,
	    &(dringp->base), NULL);
	if (err || dringp->base == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: cannot map desc ring err=%d\n", err);
		(void) ldc_mem_free_handle(mhandle);
		kmem_free(dringp, sizeof (ldc_dring_t));
		return (ENOMEM);
	}

	/* initialize the desc ring lock */
	mutex_init(&dringp->lock, NULL, MUTEX_DRIVER, NULL);

	/* Add descriptor ring to channel's imported dring list */
	mutex_enter(&ldcp->imp_dlist_lock);
	dringp->ch_next = ldcp->imp_dring_list;
	ldcp->imp_dring_list = dringp;
	mutex_exit(&ldcp->imp_dlist_lock);

	dringp->status = LDC_MAPPED;

	*dhandle = (ldc_dring_handle_t)dringp;

	return (0);
}

/*
 * Unmap a descriptor ring. Free shadow memory (if any).
 */
int
ldc_mem_dring_unmap(ldc_dring_handle_t dhandle)
{
	ldc_dring_t	*dringp;
	ldc_dring_t	*tmp_dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unmap: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (dringp->status != LDC_MAPPED) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unmap: not a mapped desc ring\n");
		return (EINVAL);
	}

	mutex_enter(&dringp->lock);

	ldcp = dringp->ldcp;

	mutex_enter(&ldcp->imp_dlist_lock);

	/* find and unlink the desc ring from channel import list */
	tmp_dringp = ldcp->imp_dring_list;
	if (tmp_dringp == dringp) {
		ldcp->imp_dring_list = dringp->ch_next;
		dringp->ch_next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->ch_next == dringp) {
				tmp_dringp->ch_next = dringp->ch_next;
				dringp->ch_next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->ch_next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_unmap: invalid descriptor\n");
			mutex_exit(&ldcp->imp_dlist_lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcp->imp_dlist_lock);

	/* do a LDC memory handle unmap and free */
	(void) ldc_mem_unmap(dringp->mhdl);
	(void) ldc_mem_free_handle((ldc_mem_handle_t)dringp->mhdl);

	dringp->status = 0;
	dringp->ldcp = NULL;

	mutex_exit(&dringp->lock);

	/* destroy dring lock */
	mutex_destroy(&dringp->lock);

	/* free desc ring object */
	kmem_free(dringp, sizeof (ldc_dring_t));

	return (0);
}

/*
 * Internal entry point for descriptor ring access entry consistency
 * semantics. Acquire copies the contents of the remote descriptor ring
 * into the local shadow copy. The release operation copies the local
 * contents into the remote dring. The start and end locations specify
 * bounds for the entries being synchronized.
 */
static int
i_ldc_dring_acquire_release(ldc_dring_handle_t dhandle,
    uint8_t direction, uint64_t start, uint64_t end)
{
	int			err;
	ldc_dring_t		*dringp;
	ldc_chan_t		*ldcp;
	ldc_mhdl_t		*mhdl;
	uint64_t		soff;
	size_t			copy_size;

	if (dhandle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;
	mutex_enter(&dringp->lock);

	if (dringp->status != LDC_MAPPED || dringp->ldcp == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: not a mapped desc ring\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if (start >= dringp->length || end >= dringp->length) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: index out of range\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	mhdl = (ldc_mhdl_t *)dringp->mhdl;
	if (mhdl == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: invalid memory handle\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if (mhdl->mtype != LDC_SHADOW_MAP) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: invalid mtype: %d\n",
		    mhdl->mtype);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	/* get the channel handle */
	ldcp = dringp->ldcp;

	copy_size = (start <= end) ? (((end - start) + 1) * dringp->dsize) :
	    ((dringp->length - start) * dringp->dsize);

	/* Calculate the relative offset for the first desc */
	soff = (start * dringp->dsize);

	/* copy to/from remote from/to local memory */
	D1(ldcp->id, "i_ldc_dring_acquire_release: c1 off=0x%llx sz=0x%llx\n",
	    soff, copy_size);
	err = i_ldc_mem_acquire_release((ldc_mem_handle_t)dringp->mhdl,
	    direction, soff, copy_size);
	if (err) {
		DWARN(ldcp->id,
		    "i_ldc_dring_acquire_release: copy failed\n");
		mutex_exit(&dringp->lock);
		return (err);
	}

	/* do the balance */
	if (start > end) {
		copy_size = ((end + 1) * dringp->dsize);
		soff = 0;

		/* copy to/from remote from/to local memory */
		D1(ldcp->id, "i_ldc_dring_acquire_release: c2 "
		    "off=0x%llx sz=0x%llx\n", soff, copy_size);
		err = i_ldc_mem_acquire_release((ldc_mem_handle_t)dringp->mhdl,
		    direction, soff, copy_size);
		if (err) {
			DWARN(ldcp->id,
			    "i_ldc_dring_acquire_release: copy failed\n");
			mutex_exit(&dringp->lock);
			return (err);
		}
	}

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Ensure that the contents in the local dring are consistent
 * with the contents if of remote dring
 */
int
ldc_mem_dring_acquire(ldc_dring_handle_t dhandle, uint64_t start, uint64_t end)
{
	return (i_ldc_dring_acquire_release(dhandle, LDC_COPY_IN, start, end));
}

/*
 * Ensure that the contents in the remote dring are consistent
 * with the contents if of local dring
 */
int
ldc_mem_dring_release(ldc_dring_handle_t dhandle, uint64_t start, uint64_t end)
{
	return (i_ldc_dring_acquire_release(dhandle, LDC_COPY_OUT, start, end));
}
