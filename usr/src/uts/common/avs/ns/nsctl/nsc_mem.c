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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/map.h>
#include <sys/errno.h>
#include <sys/ddi.h>


#define	__NSC_GEN__
#include "nsc_dev.h"
#include "nsc_gen.h"
#include "nsc_mem.h"
#include "../nsctl.h"
#ifdef DS_DDICT
#include "../contract.h"
#endif


static size_t _nsc_rm_size;
caddr_t _nsc_rm_base;
caddr_t _nsc_rm_nvmem_base;
size_t	_nsc_rmhdr_size;

static kmutex_t _nsc_mem_lock;
static nsc_mem_t *_nsc_anon_mem;
static nsc_mem_t *_nsc_rmhdr_mem;

nsc_mem_t *_nsc_mem_top;

nsc_rmhdr_t *_nsc_rmhdr_ptr;
nsc_rmmap_t *_nsc_global_map;
nsc_mem_t *_nsc_local_mem;

static void *_nsc_mem_alloc(size_t *, int, nsc_mem_t *);
static void *_nsc_rm_alloc(size_t *, nsc_mem_t *);
static int _nsc_mem_free(void *, size_t);
static int _nsc_rm_free(void *, size_t);
static size_t _nsc_rm_avail(nsc_mem_t *);

extern void nscsetup(void);
extern void _nsc_mark_pages(caddr_t, size_t, int);
extern int  _nsc_lock_all_rm(void);
extern void _nsc_unlock_all_rm(void);
extern void _nsc_set_max_devices(int);

/*
 * void
 * _nsc_init_mem (void)
 *	Initialise memory allocation system.
 *
 * Calling/Exit State:
 *	Called at driver initialisation time to allocate necessary
 *	data structures.
 */
void
_nsc_init_mem()
{
	mutex_init(&_nsc_mem_lock, NULL, MUTEX_DRIVER, NULL);

	_nsc_anon_mem = nsc_register_mem("anon:kmem", NSC_MEM_LOCAL, 0);
	_nsc_local_mem = nsc_register_mem("nsctl:kmem", NSC_MEM_LOCAL, 0);

	if (!_nsc_anon_mem)
		cmn_err(CE_PANIC, "nsctl: nsc_init_mem");
}


/*
 * void
 * _nsc_deinit_mem (void)
 *	De-initialise memory alloation system.
 *
 * Calling/Exit State:
 *	Called at driver unload time to de-allocate
 *	resources.
 */


void
_nsc_deinit_mem()
{
	if (_nsc_rm_nvmem_base)
		nsc_kmem_free(_nsc_rm_base, _nsc_rmhdr_size);

	_nsc_rm_nvmem_base = NULL;
	_nsc_rm_base = NULL;
}

/*
 * int
 * _nsc_clear_dirty(int force)
 *	mark the global area clean by clearing the header dirty bit number.
 *
 *	returns 0 if successfully cleared, valid errno otherwise
 *
 *	this function should only be called at system shutdown.
 */
/*ARGSUSED*/
int
_nsc_clear_dirty(int force)
{
	int rc = 0;

#ifdef DEBUG
	ulong_t longzeros = 0;
	if (force) {
		if (_nsc_rm_nvmem_base) {
			if (nsc_commit_mem((void *)&longzeros,
			    (void *)&((nsc_rmhdr_t *)
			    _nsc_rm_nvmem_base)->rh_dirty,
			    sizeof (ulong_t), nsc_cm_errhdlr) < 0) {
				cmn_err(CE_WARN,
				    "nsctl: _nsc_clear_magic: "
				    "hdr force clear failed 0x%p",
				    (void *)_nsc_rm_nvmem_base);
			} else {
				cmn_err(CE_WARN,
				    "nsctl: _nsc_clear_magic: "
				    "hdr force cleared 0x%p",
				    (void *)_nsc_rm_nvmem_base);
				_nsc_rmhdr_ptr->rh_dirty = 0;
			}

			return (0);
		} else
			return (EINVAL);
	}

	if (_nsc_rm_nvmem_base) {
		if (_nsc_global_lock_init) {
			mutex_enter(&_nsc_global_lock);
			if (!_nsc_check_mapinuse()) {
				if (nsc_commit_mem((void *)&longzeros,
				    (void *)&((nsc_rmhdr_t *)
				    _nsc_rm_nvmem_base)->rh_dirty,
				    sizeof (ulong_t), nsc_cm_errhdlr) < 0) {
					cmn_err(CE_WARN,
					    "nsctl: _nsc_clear_magic: "
					    "hdr clear failed 0x%p",
					    (void *)_nsc_rm_nvmem_base);
				} else {
					cmn_err(CE_WARN,
					    "nsctl: _nsc_clear_magic: "
					    "hdr cleared 0x%p",
					    (void *)_nsc_rm_nvmem_base);
					_nsc_rmhdr_ptr->rh_dirty = 0;
				}
				rc = 0;
			} else {
				cmn_err(CE_WARN,
	"nsctl: _nsc_clear_magic: global area in use. cannot clear magic");
				rc = EBUSY;
			}
			mutex_exit(&_nsc_global_lock);
		} else {
			cmn_err(CE_WARN,
			"nsctl: _nsc_clear_magic: cannot clear magic");
			rc = EINVAL;
		}
	} else
		rc = EINVAL;
#else

	rc = ENOTTY;

#endif /* DEBUG */

	return (rc);
}

/*
 * int
 * _nsc_check_mapinuse()
 *	check if any global maps are still inuse;
 *
 *	return 1 if any non-nsctl map is in use, 0 otherwise
 *	should be called with _nsc_global_lock held
 *
 * 	for nvmem support.  if a client of nsctl is still
 * 	using the global maps then the global area will not
 *	be marked clean.
 */
int
_nsc_check_mapinuse(void)
{
	nsc_rmmap_t *rmap = _nsc_rmhdr_ptr->map;
	nsc_rmmap_t *rmapend;

	rmapend = (nsc_rmmap_t *)
	    ((char *)_nsc_rmhdr_ptr + _nsc_rmhdr_ptr->size);

	for (; rmap < rmapend; ++rmap)
		if ((rmap->inuse) && !(_nsc_is_nsctl_map(rmap->name)))
			return (1);

	return (0);

}

/* names of maps in the global area that belong to nsctl */
static char *nsctl_mapnames[] = {
	"nsc_global",
	"nsc_lock"
};

int
_nsc_is_nsctl_map(char *mapname)
{
	int i;

	for (i = 0; i < sizeof (nsctl_mapnames)/sizeof (char *); ++i)
		if (strncmp(mapname, nsctl_mapnames[i], _NSC_MAXNAME) == 0)
			return (1);

	return (0);
}


/*
 * nsc_mem_t *
 * nsc_register_mem(char *name, int type, int flag)
 *	Register a category of memory usage.
 *
 * Calling/Exit State:
 *	Returns a token for use in future calls to nsc_kmem_alloc.
 *		type is NSC_MEM_LOCAL, or NSC_MEM_GLOBAL.
 *		flag is passed through to kmem_alloc on allocate.
 *
 * Description:
 *	The parameters associated with a category can be changed
 *	by making a subsequent call to nsc_register_mem.
 */
nsc_mem_t *
nsc_register_mem(char *name, int type, int flag)
{
	nsc_mem_t *mp, *new;

	new = kmem_zalloc(sizeof (*new), KM_NOSLEEP);

	mutex_enter(&_nsc_mem_lock);

	for (mp = _nsc_mem_top; mp; mp = mp->next)
		if (strcmp(mp->name, name) == 0)
			break;

	if (!mp && !(mp = new)) {
		mutex_exit(&_nsc_mem_lock);
		return (NULL);
	}

	mp->type = type;
	mp->flag = flag;

	mp->hwm = mp->used;
	mp->pagehwm = mp->pages;
	mp->nalloc -= mp->nfree;
	mp->nfree = 0;

	if (!mp->name) {
		mp->name = name;
		mp->next = _nsc_mem_top;
		_nsc_mem_top = mp;
	}

	mutex_exit(&_nsc_mem_lock);

	if (new && mp != new)
		kmem_free(new, sizeof (*new));

	return (mp);
}


/*
 * void
 * nsc_unregister_mem(nsc_mem_t *)
 *	Un-register a category of memory usage.
 *
 * Description:
 *	The specified category is un-registered. For correct
 *	operation this should only be called when all memory
 *	associated with the category has been free'd.
 */
void
nsc_unregister_mem(nsc_mem_t *mp)
{
	nsc_mem_t **mpp;

	if (!mp)
		return;

	mutex_enter(&_nsc_mem_lock);

	for (mpp = &_nsc_mem_top; *mpp; mpp = &(*mpp)->next)
		if (*mpp == mp)
			break;

	if (*mpp != NULL) {
		*mpp = mp->next;
		kmem_free(mp, sizeof (*mp));
	}

	mutex_exit(&_nsc_mem_lock);
}

/*
 * void
 * _nsc_global_setup
 *	Setup global variables.
 *
 * Calling/Exit State:
 *	Called to setup the global header.
 */
void
_nsc_global_setup()
{
	nsc_rmhdr_t *hdr = (void *)_nsc_rm_base;
	size_t size;

	if (!hdr || !_nsc_global_lock_init || _nsc_rmhdr_ptr)
		return;

	mutex_enter(&_nsc_global_lock);

	if (!hdr->magic || (_nsc_rm_nvmem_base && !hdr->rh_dirty)) {
		size = sizeof (nsc_rmhdr_t) +
		    (sizeof (nsc_rmmap_t) * (_NSC_GLSLOT - 1));

		size = (size + _NSC_GLALIGN) & ~_NSC_GLALIGN;
		bzero(_nsc_rm_base, size);

		hdr->magic = _NSCTL_HDRMAGIC;
		hdr->ver = _NSCTL_HDRVER3;
		hdr->size = size;
		hdr->maxdev = nsc_max_devices();

		hdr->map[0].inuse = _NSC_GLSLOT;
		if (_nsc_rm_nvmem_base) {
			if (hdr->rh_dirty) { /* corrupted */
				cmn_err(CE_WARN,
				    "nsctl: _nsc_global_setup: nv bad header");
				mutex_exit(&_nsc_global_lock);
				return;
			}
			if (nsc_commit_mem((void *)_nsc_rm_base,
			    (void *)_nsc_rm_nvmem_base,
			    size, nsc_cm_errhdlr) < 0)
				cmn_err(CE_WARN,
				    "_nsc_global_setup: "
				    "nvmem header not updated");
		}
	}

	_nsc_rmhdr_ptr = hdr;
	mutex_exit(&_nsc_global_lock);

	if (hdr->magic != _NSCTL_HDRMAGIC || (hdr->ver != _NSCTL_HDRVER &&
	    hdr->ver != _NSCTL_HDRVER3)) {
		cmn_err(CE_WARN, "nsctl: _nsc_global_setup: bad header");
		return;
	}

	if (hdr->ver == _NSCTL_HDRVER3 && hdr->maxdev != nsc_max_devices()) {
		_nsc_set_max_devices(hdr->maxdev);
		cmn_err(CE_WARN,
		    "nsctl: _nsc_global_setup: setting nsc_max_devices to %d",
		    hdr->maxdev);
	}

	if (!_nsc_rmmap_init(hdr->map, "nsc_global", _NSC_GLSLOT,
	    _nsc_rm_size - hdr->size, hdr->size)) {
		cmn_err(CE_WARN,
		    "nsctl: _nsc_global_setup: global map init failed");
		return;
	}

	_nsc_global_map = hdr->map;

	(void) nsc_kmem_alloc(hdr->size, 0, _nsc_rmhdr_mem);
}

/*
 * int
 * _nsc_need_global_mem ()
 *	Expected global memory usage.
 *
 * Calling/Exit State:
 *	Returns the amount of global memory expected to be
 *	used by internal data structures.
 *
 * Remarks:
 *	This is provided purely as a configuration aid to
 *	systems without global memory and as such is not
 *	declared in nsctl.h.
 */
int
_nsc_need_global_mem()
{
	int size = sizeof (nsc_rmhdr_t) +
	    (sizeof (nsc_rmmap_t) * (_NSC_GLSLOT - 1));

	size = (size + _NSC_GLALIGN) & ~_NSC_GLALIGN;
	return (size);
}


/*
 * void *
 * nsc_kmem_alloc (size_t size, int flag, nsc_mem_t *mem)
 *	Allocate memory of the specified type.
 *
 * Calling/Exit State:
 *	Returns a pointer to a word aligned area of memory.
 *	If mem is zero then an anonymous category is used.
 *
 * Description:
 *	Allocates the required memory and updates the usage
 *	statistics stored in mem.
 *
 * Remarks:
 *	VME memory is guaranteed to be eight byte aligned.
 */
void *
nsc_kmem_alloc(size_t size, int flag, nsc_mem_t *mem)
{
	void *vp;

	if (!mem)
		mem = _nsc_anon_mem;

	if ((vp = _nsc_mem_alloc(&size, flag, mem)) == NULL)
		return (NULL);

	mutex_enter(&_nsc_mem_lock);

	mem->nalloc++;
	mem->used += size;
	mem->pages += btopr(size);

	if (mem->used > mem->hwm)
		mem->hwm = mem->used;
	if (mem->pages > mem->pagehwm)
		mem->pagehwm = mem->pages;

	mutex_exit(&_nsc_mem_lock);
	return (vp);
}


/*
 * void *
 * _nsc_mem_alloc (size_t *sizep, int flag, nsc_mem_t *mem)
 *	Allocate memory of the specified type.
 *
 * Calling/Exit State:
 *	Returns a pointer to a word aligned area of memory.
 *
 * Description:
 *	Uses the type field to determine whether to allocate RM,
 *	VME or kernel memory. For types other then RM a copy of
 *	mem is stored immediately prior to the returned area.
 *	size is updated to reflect the header.
 *
 * Remarks:
 *	A two word header is user for VME memory to ensure
 *	eight byte alignment.
 */
static void *
_nsc_mem_alloc(size_t *sizep, int flag, nsc_mem_t *mem)
{
	size_t size = *sizep;
	void *vp;

	if (mem->type & NSC_MEM_GLOBAL)
		return (_nsc_rm_alloc(sizep, mem));

	flag |= mem->flag;
	size += sizeof (nsc_mem_t *);

	if (flag & KM_NOSLEEP)
		flag &= ~KM_SLEEP;

	vp = kmem_alloc(size, flag);
	if (!vp)
		return (NULL);

	*sizep = size;

	*(nsc_mem_t **)vp = mem;

	return (void *)((nsc_mem_t **)vp + 1);
}


/*
 * void
 * nsc_kmem_free (void *addr, size_t size)
 *	Free a previously allocated area of memory.
 *
 * Calling/Exit State:
 *	The memory specified by addr is returned to the free pool.
 *
 * Description:
 *	Updates the usage statistics appropriately.
 */
void
nsc_kmem_free(void *addr, size_t size)
{
	caddr_t caddr = (caddr_t)addr;
	caddr_t rm_base;
	int rc;

	if (_nsc_rm_nvmem_base)
		rm_base = _nsc_rm_nvmem_base;
	else
		rm_base = _nsc_rm_base;

	if (rm_base <= caddr && caddr < rm_base + _nsc_rm_size)
		rc = _nsc_rm_free(addr, size);
	else
		rc = _nsc_mem_free(addr, size);

	if (rc < 0)
		cmn_err(CE_PANIC, "nsctl: nsc_kmem_free: invalid free");
}


/*
 * nsc_mem_t *
 * _nsc_mem_free (void *addr, size_t size)
 *	Free a previously allocated area of memory.
 *
 * Calling/Exit State:
 *	Frees the VME or kernel memory at addr and updates
 *	the associated mem structure.
 */
static int
_nsc_mem_free(void *addr, size_t size)
{
	nsc_mem_t *mp, *tp;

	addr = (void *)((nsc_mem_t **)addr - 1);
	size += sizeof (nsc_mem_t *);

	mutex_enter(&_nsc_mem_lock);

	mp = *(nsc_mem_t **)addr;

	for (tp = _nsc_mem_top; tp; tp = tp->next)
		if (tp == mp)
			break;

	if (tp == NULL) {
		mutex_exit(&_nsc_mem_lock);
		return (-1);
	}

	mp->nfree++;
	mp->used -= size;
	mp->pages -= btopr(size);

	*(nsc_mem_t **)addr = NULL;

	mutex_exit(&_nsc_mem_lock);

	kmem_free(addr, size);

	return (0);
}


/*
 * void *
 * nsc_kmem_zalloc(size_t size, int flags, nsc_mem_t *mem)
 *	Allocate and zero memory.
 *
 * Calling/Exit State:
 *	Same as nsc_kmem_alloc(), except that the memory is zeroed.
 */
void *
nsc_kmem_zalloc(size_t size, int flag, nsc_mem_t *mem)
{
	void *vp = nsc_kmem_alloc(size, flag, mem);

	if (vp)
		bzero((char *)vp, size);

	return (vp);
}


/*
 * void
 * nsc_mem_sizes (nsc_mem_t *mem, size_t *usedp, size_t *hwmp, size_t *reqp)
 *	Access size information for category.
 *
 * Calling/Exit State:
 *	If the corresponding pointer is non-zero returns
 *	respectively, the number of bytes currently allocated, the
 *	high water mark in bytes and an estimate of the number of
 *	bytes needed for the category assuming that each request
 *	is satisfied from a different page.
 *
 * Remarks:
 *	The reqp parameter is used to estimate the amount of special
 *	purpose memory needed to support the category.
 */
void
nsc_mem_sizes(nsc_mem_t *mem, size_t *usedp, size_t *hwmp, size_t *reqp)
{
	if (!mem)
		mem = _nsc_anon_mem;

	if (usedp)
		*usedp = mem->used;
	if (hwmp)
		*hwmp = mem->hwm;
	if (reqp)
		*reqp = (size_t)ptob(mem->pagehwm);
}


/*
 * size_t
 * nsc_mem_avail (nsc_mem_t *mem)
 *	Memory available for use by category.
 *
 * Calling/Exit State:
 *	Returns the number of bytes of memory currently
 *	available for use by the category.
 *
 * Remarks:
 *	Reduces the memory available to allow for one unit
 *	of allocation overhead.
 *
 *	Only implemented for NSC_MEM_GLOBAL.
 */
size_t
nsc_mem_avail(nsc_mem_t *mem)
{
	if (!mem)
		mem = _nsc_anon_mem;

	if (mem->type & NSC_MEM_GLOBAL)
		return (_nsc_rm_avail(mem));

#ifdef DEBUG
	cmn_err(CE_WARN, "nsc_mem_avail: called for non-global memory!");
#endif

	return (0);
}


/*
 * void
 * _nsc_global_zero (ulong_t offset, size_t size)
 *	Zero global memory.
 *
 * Description:
 *	Zeroes an area of global memory at the specified offset.
 */

#define	ZSIZE 4096
static char _nsc_nvmem_zeroes[ZSIZE];

static void
_nsc_global_zero(ulong_t offset, size_t size)
{
	int i;
	int rc;
	int failed = 0;

	if (_nsc_rm_nvmem_base) {
		for (i = 0; i < (int)(size / ZSIZE); ++i) {
			rc = nsc_commit_mem((void *)_nsc_nvmem_zeroes,
			    (void *)(_nsc_rm_nvmem_base + offset +
			    i * ZSIZE),
			    ZSIZE, nsc_cm_errhdlr);

			if (rc < 0)
				++failed;

		}
		rc = nsc_commit_mem((void *)_nsc_nvmem_zeroes,
		    (void *)(_nsc_rm_nvmem_base + offset + i * ZSIZE),
		    size % ZSIZE,
		    nsc_cm_errhdlr);
		if ((rc <  0) || failed)
			cmn_err(CE_WARN, "_nsc_global_zero: clear mem failed");
		return;
	}

	if (_nsc_rm_base)
		bzero(_nsc_rm_base + offset, size);
}


/*
 * void *
 * _nsc_rm_alloc (size_t *sizep, nsc_mem_t *mem)
 *	Allocate next available section of RM.
 *
 * Calling/Exit State:
 *	Returns a pointer to an area of global memory.
 *
 * Description:
 *	Only one allocation request is allowed for each
 *	category of global memory.
 */
static void *
_nsc_rm_alloc(size_t *sizep, nsc_mem_t *mem)
{
	size_t avail, size = (*sizep);
	ulong_t offset = 0;
	caddr_t	retaddr;

	if (!_nsc_global_map) {
		cmn_err(CE_WARN, "_nsc_rm_alloc: no map");
		return (NULL);
	}

	mutex_enter(&_nsc_mem_lock);

	if (mem->base || mem->pend) {
		mutex_exit(&_nsc_mem_lock);
		cmn_err(CE_WARN, "_nsc_rm_alloc: invalid alloc");
		return (NULL);
	}

	mem->pend = 1;
	mutex_exit(&_nsc_mem_lock);

	size = (size + _NSC_GLALIGN) & ~_NSC_GLALIGN;

	/* CONSTCOND */

	while (1) {
		if (strcmp(mem->name, "nsctl:rmhdr") == 0)
			break;

		offset = _nsc_rmmap_alloc(_nsc_global_map,
		    mem->name, size, _nsc_global_zero);

		if (offset)
			break;

		if (mem->type & NSC_MEM_RESIZE) {
			avail = _nsc_rmmap_size(_nsc_global_map, mem->name);

			if (avail && avail != size) {
				size = avail;
				continue;
			}
		}

		mem->pend = 0;
		cmn_err(CE_WARN,
		    "_nsc_rm_alloc: alloc %ld bytes - %ld available",
		    size, _nsc_rm_avail(mem));
		return (NULL);
	}

	_nsc_mark_pages(_nsc_rm_base + offset, size, 1);

	if (_nsc_rm_nvmem_base)
		retaddr = _nsc_rm_nvmem_base + offset;
	else
		retaddr = _nsc_rm_base + offset;

	mutex_enter(&_nsc_mem_lock);

	mem->base = retaddr;
	mem->pend = 0;

	mutex_exit(&_nsc_mem_lock);

	(*sizep) = size;
	return (retaddr);
}


/*
 * nsc_mem_t *
 * _nsc_rm_free (void *addr, size_t size)
 *	Free an area of RM.
 *
 * Calling/Exit State:
 *	Returns 0 on success, -1 on failure.
 */
static int
_nsc_rm_free(void *addr, size_t size)
{
	caddr_t caddr = (caddr_t)addr;
	nsc_mem_t *mp;

	mutex_enter(&_nsc_mem_lock);

	for (mp = _nsc_mem_top; mp; mp = mp->next)
		if (mp->base == caddr)
			break;

	if (!mp) {
		mutex_exit(&_nsc_mem_lock);
		return (-1);
	}

	mp->nfree++;
	mp->used -= size;
	mp->pages -= btopr(size);
	mp->pend = 1;

	if (!mp->used)
		mp->base = 0;

	mutex_exit(&_nsc_mem_lock);

	if (_nsc_global_map)
		_nsc_rmmap_free(_nsc_global_map, mp->name, mp);

	_nsc_mark_pages(addr, size, 0);

	mp->pend = 0;
	return (0);
}


/*
 * static size_t
 * _nsc_rm_avail (mem)
 *	Amount of RM available.
 *
 * Calling/Exit State:
 *	Returns 0 if the specified category has already been
 *	allocated. Returns the size of the region if it already
 *	exists, otherwise the number of bytes of global memory
 *	available.
 */
static size_t
_nsc_rm_avail(nsc_mem_t *mem)
{
	size_t size;

	if (!_nsc_global_map || mem->base || mem->pend)
		return (0);

	if ((size = _nsc_rmmap_size(_nsc_global_map, mem->name)) != 0)
		return (size);

	return (_nsc_rmmap_avail(_nsc_global_map));
}


/*
 * nvram support
 * given a map address, return the address of the copy
 * in nvram.
 * Assumes that _nsc_rm_nvmem_base is valid.
 */
nsc_rmmap_t *
_nsc_global_nvmemmap_lookup(nsc_rmmap_t *hp)
{
	size_t offset;

	/* LINTED */
	offset = (caddr_t)hp - _nsc_rm_base;
	return ((nsc_rmmap_t *)(_nsc_rm_nvmem_base + offset));
}

int
_nsc_get_global_sizes(void *arg, int *rvp)
{
	if (!_nsc_rmhdr_ptr)
		return (EINVAL);

	if (copyout(&_nsc_rmhdr_ptr->size, arg,
		sizeof (_nsc_rmhdr_ptr->size)) < 0)
		return (EFAULT);

	*rvp = 0;
	return (0);
}

int
_nsc_get_global_data(void *arg, int *rvp)
{
	size_t size;

	if (!_nsc_rmhdr_ptr)
		return (EINVAL);

	size = _nsc_rmhdr_ptr->size;

	if (copyout(_nsc_rmhdr_ptr, arg, size) < 0)
		return (EFAULT);

	if (_nsc_rm_nvmem_base) {
		char *taddr;

		if ((taddr = kmem_alloc(size, KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		if (copyout(taddr, (char *)arg + size, size) < 0) {
			kmem_free(taddr, size);
			return (EFAULT);
		}

		kmem_free(taddr, size);
	}

	*rvp = 0;
	return (0);
}
