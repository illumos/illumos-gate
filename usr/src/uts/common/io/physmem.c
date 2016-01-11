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
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/devops.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/errno.h>
#include <vm/seg_dev.h>
#include <vm/seg_vn.h>
#include <vm/page.h>
#include <sys/fs/swapnode.h>
#include <sys/sysmacros.h>
#include <sys/fcntl.h>
#include <sys/vmsystm.h>
#include <sys/physmem.h>
#include <sys/vfs_opreg.h>

static dev_info_t		*physmem_dip = NULL;

/*
 * Linked list element hanging off physmem_proc_hash below, which holds all
 * the information for a given segment which has been setup for this process.
 * This is a simple linked list as we are assuming that for a given process
 * the setup ioctl will only be called a handful of times.  If this assumption
 * changes in the future, a quicker to traverse data structure should be used.
 */
struct physmem_hash {
	struct physmem_hash *ph_next;
	uint64_t ph_base_pa;
	caddr_t ph_base_va;
	size_t ph_seg_len;
	struct vnode *ph_vnode;
};

/*
 * Hash of all of the processes which have setup mappings with the driver with
 * pointers to per process data.
 */
struct physmem_proc_hash {
	struct proc *pph_proc;
	struct physmem_hash *pph_hash;
	struct physmem_proc_hash *pph_next;
};


/* Needs to be a power of two for simple hash algorithm */
#define	PPH_SIZE	8
struct physmem_proc_hash *pph[PPH_SIZE];

/*
 * Lock which protects the pph hash above.  To add an element (either a new
 * process or a new segment) the WRITE lock must be held.  To traverse the
 * list, only a READ lock is needed.
 */
krwlock_t pph_rwlock;

#define	PHYSMEM_HASH(procp) ((int)((((uintptr_t)procp) >> 8) & (PPH_SIZE - 1)))

/*
 * Need to keep a reference count of how many processes have the driver
 * open to prevent it from disappearing.
 */
uint64_t physmem_vnodecnt;
kmutex_t physmem_mutex;		/* protects phsymem_vnodecnt */

static int physmem_getpage(struct vnode *vp, offset_t off, size_t len,
    uint_t *protp, page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *cr, caller_context_t *ct);

static int physmem_addmap(struct vnode *vp, offset_t off, struct as *as,
    caddr_t addr, size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    struct cred *cred, caller_context_t *ct);

static int physmem_delmap(struct vnode *vp, offset_t off, struct as *as,
    caddr_t addr, size_t len, uint_t prot, uint_t maxprot, uint_t flags,
    struct cred *cred, caller_context_t *ct);

static void physmem_inactive(vnode_t *vp, cred_t *crp, caller_context_t *ct);

const fs_operation_def_t physmem_vnodeops_template[] = {
	VOPNAME_GETPAGE,	{ .vop_getpage = physmem_getpage },
	VOPNAME_ADDMAP,		{ .vop_addmap = physmem_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = physmem_delmap },
	VOPNAME_INACTIVE,	{ .vop_inactive = physmem_inactive },
	NULL,			NULL
};

vnodeops_t *physmem_vnodeops = NULL;

/*
 * Removes the current process from the hash if the process has no more
 * physmem segments active.
 */
void
physmem_remove_hash_proc()
{
	int index;
	struct physmem_proc_hash **walker;
	struct physmem_proc_hash *victim = NULL;

	index = PHYSMEM_HASH(curproc);
	rw_enter(&pph_rwlock, RW_WRITER);
	walker = &pph[index];
	while (*walker != NULL) {
		if ((*walker)->pph_proc == curproc &&
		    (*walker)->pph_hash == NULL) {
			victim = *walker;
			*walker = victim->pph_next;
			break;
		}
		walker = &((*walker)->pph_next);
	}
	rw_exit(&pph_rwlock);
	if (victim != NULL)
		kmem_free(victim, sizeof (struct physmem_proc_hash));
}

/*
 * Add a new entry to the hash for the given process to cache the
 * address ranges that it is working on.  If this is the first hash
 * item to be added for this process, we will create the head pointer
 * for this process.
 * Returns 0 on success, ERANGE when the physical address is already in the
 * hash.
 */
int
physmem_add_hash(struct physmem_hash *php)
{
	int index;
	struct physmem_proc_hash *iterator;
	struct physmem_proc_hash *newp = NULL;
	struct physmem_hash *temp;
	int ret = 0;

	index = PHYSMEM_HASH(curproc);

insert:
	rw_enter(&pph_rwlock, RW_WRITER);
	iterator = pph[index];
	while (iterator != NULL) {
		if (iterator->pph_proc == curproc) {
			/*
			 * check to make sure a single process does not try to
			 * map the same region twice.
			 */
			for (temp = iterator->pph_hash; temp != NULL;
			    temp = temp->ph_next) {
				if ((php->ph_base_pa >= temp->ph_base_pa &&
				    php->ph_base_pa < temp->ph_base_pa +
				    temp->ph_seg_len) ||
				    (temp->ph_base_pa >= php->ph_base_pa &&
				    temp->ph_base_pa < php->ph_base_pa +
				    php->ph_seg_len)) {
					ret = ERANGE;
					break;
				}
			}
			if (ret == 0) {
				php->ph_next = iterator->pph_hash;
				iterator->pph_hash = php;
			}
			rw_exit(&pph_rwlock);
			/* Need to check for two threads in sync */
			if (newp != NULL)
				kmem_free(newp, sizeof (*newp));
			return (ret);
		}
		iterator = iterator->pph_next;
	}

	if (newp != NULL) {
		newp->pph_proc = curproc;
		newp->pph_next = pph[index];
		newp->pph_hash = php;
		php->ph_next = NULL;
		pph[index] = newp;
		rw_exit(&pph_rwlock);
		return (0);
	}

	rw_exit(&pph_rwlock);
	/* Dropped the lock so we could use KM_SLEEP */
	newp = kmem_zalloc(sizeof (struct physmem_proc_hash), KM_SLEEP);
	goto insert;
}

/*
 * Will return the pointer to the physmem_hash struct if the setup routine
 * has previously been called for this memory.
 * Returns NULL on failure.
 */
struct physmem_hash *
physmem_get_hash(uint64_t req_paddr, size_t len, proc_t *procp)
{
	int index;
	struct physmem_proc_hash *proc_hp;
	struct physmem_hash *php;

	ASSERT(rw_lock_held(&pph_rwlock));

	index = PHYSMEM_HASH(procp);
	proc_hp = pph[index];
	while (proc_hp != NULL) {
		if (proc_hp->pph_proc == procp) {
			php = proc_hp->pph_hash;
			while (php != NULL) {
				if ((req_paddr >= php->ph_base_pa) &&
				    (req_paddr + len <=
				    php->ph_base_pa + php->ph_seg_len)) {
					return (php);
				}
				php = php->ph_next;
			}
		}
		proc_hp = proc_hp->pph_next;
	}
	return (NULL);
}

int
physmem_validate_cookie(uint64_t p_cookie)
{
	int index;
	struct physmem_proc_hash *proc_hp;
	struct physmem_hash *php;

	ASSERT(rw_lock_held(&pph_rwlock));

	index = PHYSMEM_HASH(curproc);
	proc_hp = pph[index];
	while (proc_hp != NULL) {
		if (proc_hp->pph_proc == curproc) {
			php = proc_hp->pph_hash;
			while (php != NULL) {
				if ((uint64_t)(uintptr_t)php == p_cookie) {
					return (1);
				}
				php = php->ph_next;
			}
		}
		proc_hp = proc_hp->pph_next;
	}
	return (0);
}

/*
 * Remove the given vnode from the pph hash.  If it exists in the hash the
 * process still has to be around as the vnode is obviously still around and
 * since it's a physmem vnode, it must be in the hash.
 * If it is not in the hash that must mean that the setup ioctl failed.
 * Return 0 in this instance, 1 if it is in the hash.
 */
int
physmem_remove_vnode_hash(vnode_t *vp)
{
	int index;
	struct physmem_proc_hash *proc_hp;
	struct physmem_hash **phpp;
	struct physmem_hash *victim;

	index = PHYSMEM_HASH(curproc);
	/* synchronize with the map routine */
	rw_enter(&pph_rwlock, RW_WRITER);
	proc_hp = pph[index];
	while (proc_hp != NULL) {
		if (proc_hp->pph_proc == curproc) {
			phpp = &proc_hp->pph_hash;
			while (*phpp != NULL) {
				if ((*phpp)->ph_vnode == vp) {
					victim = *phpp;
					*phpp = victim->ph_next;

					rw_exit(&pph_rwlock);
					kmem_free(victim, sizeof (*victim));
					return (1);
				}
				phpp = &(*phpp)->ph_next;
			}
		}
		proc_hp = proc_hp->pph_next;
	}
	rw_exit(&pph_rwlock);

	/* not found */
	return (0);
}

int
physmem_setup_vnops()
{
	int error;
	char *name = "physmem";
	if (physmem_vnodeops != NULL)
		cmn_err(CE_PANIC, "physmem vnodeops already set\n");
	error = vn_make_ops(name, physmem_vnodeops_template, &physmem_vnodeops);
	if (error != 0) {
		cmn_err(CE_WARN, "physmem_setup_vnops: bad vnode ops template");
	}
	return (error);
}

/*
 * The guts of the PHYSMEM_SETUP ioctl.
 * Create a segment in the address space with the specified parameters.
 * If pspp->user_va is NULL, as_gap will be used to find an appropriate VA.
 * We do not do bounds checking on the requested physical addresses, if they
 * do not exist in the system, they will not be mappable.
 * Returns 0 on success with the following error codes on failure:
 *	ENOMEM - The VA range requested was already mapped if pspp->user_va is
 *		non-NULL or the system was unable to find enough VA space for
 *		the desired length if user_va was NULL>
 *	EINVAL - The requested PA, VA, or length was not PAGESIZE aligned.
 */
int
physmem_setup_addrs(struct physmem_setup_param *pspp)
{
	struct as *as = curproc->p_as;
	struct segvn_crargs vn_a;
	int ret = 0;
	uint64_t base_pa;
	size_t len;
	caddr_t uvaddr;
	struct vnode *vp;
	struct physmem_hash *php;

	ASSERT(pspp != NULL);
	base_pa = pspp->req_paddr;
	len = pspp->len;
	uvaddr = (caddr_t)(uintptr_t)pspp->user_va;

	/* Sanity checking */
	if (!IS_P2ALIGNED(base_pa, PAGESIZE))
		return (EINVAL);
	if (!IS_P2ALIGNED(len, PAGESIZE))
		return (EINVAL);
	if (uvaddr != NULL && !IS_P2ALIGNED(uvaddr, PAGESIZE))
		return (EINVAL);

	php = kmem_zalloc(sizeof (struct physmem_hash), KM_SLEEP);

	/* Need to bump vnode count so that the driver can not be unloaded */
	mutex_enter(&physmem_mutex);
	physmem_vnodecnt++;
	mutex_exit(&physmem_mutex);

	vp = vn_alloc(KM_SLEEP);
	ASSERT(vp != NULL);	/* SLEEP can't return NULL */
	vn_setops(vp, physmem_vnodeops);

	php->ph_vnode = vp;

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)base_pa;
	vn_a.type = MAP_SHARED;
	vn_a.prot = PROT_ALL;
	vn_a.maxprot = PROT_ALL;
	vn_a.flags = 0;
	vn_a.cred = NULL;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	as_rangelock(as);
	if (uvaddr != NULL) {
		if (as_gap(as, len, &uvaddr, &len, AH_LO, NULL) == -1) {
			ret = ENOMEM;
fail:
			as_rangeunlock(as);
			vn_free(vp);
			kmem_free(php, sizeof (*php));
			mutex_enter(&physmem_mutex);
			physmem_vnodecnt--;
			mutex_exit(&physmem_mutex);
			return (ret);
		}
	} else {
		/* We pick the address for the user */
		map_addr(&uvaddr, len, 0, 1, 0);
		if (uvaddr == NULL) {
			ret = ENOMEM;
			goto fail;
		}
	}
	ret = as_map(as, uvaddr, len, segvn_create, &vn_a);

	if (ret == 0) {
		as_rangeunlock(as);
		php->ph_base_pa = base_pa;
		php->ph_base_va = uvaddr;
		php->ph_seg_len = len;
		pspp->user_va = (uint64_t)(uintptr_t)uvaddr;
		pspp->cookie = (uint64_t)(uintptr_t)php;
		ret = physmem_add_hash(php);
		if (ret == 0)
			return (0);

		/* Note that the call to as_unmap will free the vnode */
		(void) as_unmap(as, uvaddr, len);
		kmem_free(php, sizeof (*php));
		return (ret);
	}

	goto fail;
	/*NOTREACHED*/
}

/*
 * The guts of the PHYSMEM_MAP ioctl.
 * Map the given PA to the appropriate VA if PHYSMEM_SETUP ioctl has already
 * been called for this PA range.
 * Returns 0 on success with the following error codes on failure:
 *	EPERM - The requested page is long term locked, and thus repeated
 *		requests to allocate this page will likely fail.
 *	EAGAIN - The requested page could not be allocated, but it is believed
 *		that future attempts could succeed.
 *	ENOMEM - There was not enough free memory in the system to safely
 *		map the requested page.
 *	EINVAL - The requested paddr was not PAGESIZE aligned or the
 *		PHYSMEM_SETUP ioctl was not called for this page.
 *	ENOENT - The requested page was iniside the kernel cage, and the
 *		PHYSMEM_CAGE flag was not set.
 *	EBUSY - The requested page is retired and the PHYSMEM_RETIRE flag
 *		was not set.
 */
static int
physmem_map_addrs(struct physmem_map_param *pmpp)
{
	caddr_t uvaddr;
	page_t *pp;
	uint64_t req_paddr;
	struct vnode *vp;
	int ret = 0;
	struct physmem_hash *php;
	uint_t flags = 0;

	ASSERT(pmpp != NULL);
	req_paddr = pmpp->req_paddr;

	if (!IS_P2ALIGNED(req_paddr, PAGESIZE))
		return (EINVAL);
	/* Find the vnode for this map request */
	rw_enter(&pph_rwlock, RW_READER);
	php = physmem_get_hash(req_paddr, PAGESIZE, curproc);
	if (php == NULL) {
		rw_exit(&pph_rwlock);
		return (EINVAL);
	}
	vp = php->ph_vnode;
	uvaddr = php->ph_base_va + (req_paddr - php->ph_base_pa);
	rw_exit(&pph_rwlock);

	pp = page_numtopp_nolock(btop((size_t)req_paddr));
	if (pp == NULL) {
		pmpp->ret_va = NULL;
		return (EPERM);
	}

	/*
	 * Check to see if page already mapped correctly.  This can happen
	 * when we failed to capture a page previously and it was captured
	 * asynchronously for us.  Return success in this case.
	 */
	if (pp->p_vnode == vp) {
		ASSERT(pp->p_offset == (u_offset_t)req_paddr);
		pmpp->ret_va = (uint64_t)(uintptr_t)uvaddr;
		return (0);
	}

	/*
	 * physmem should be responsible for checking for cage
	 * and prom pages.
	 */
	if (pmpp->flags & PHYSMEM_CAGE)
		flags = CAPTURE_GET_CAGE;
	if (pmpp->flags & PHYSMEM_RETIRED)
		flags |= CAPTURE_GET_RETIRED;

	ret = page_trycapture(pp, 0, flags | CAPTURE_PHYSMEM, curproc);

	if (ret != 0) {
		pmpp->ret_va = NULL;
		return (ret);
	} else {
		pmpp->ret_va = (uint64_t)(uintptr_t)uvaddr;
		return (0);
	}
}

/*
 * Map the given page into the process's address space if possible.
 * We actually only hash the page in on the correct vnode as the page
 * will be mapped via segvn_pagefault.
 * returns 0 on success
 * returns 1 if there is no need to map this page anymore (process exited)
 * returns -1 if we failed to map the page.
 */
int
map_page_proc(page_t *pp, void *arg, uint_t flags)
{
	struct vnode *vp;
	proc_t *procp = (proc_t *)arg;
	int ret;
	u_offset_t paddr = (u_offset_t)ptob(pp->p_pagenum);
	struct physmem_hash *php;

	ASSERT(pp != NULL);

	/*
	 * Check against availrmem to make sure that we're not low on memory.
	 * We check again here as ASYNC requests do not do this check elsewhere.
	 * We return 1 as we don't want the page to have the PR_CAPTURE bit
	 * set or be on the page capture hash.
	 */
	if (swapfs_minfree > availrmem + 1) {
		page_free(pp, 1);
		return (1);
	}

	/*
	 * If this is an asynchronous request for the current process,
	 * we can not map the page as it's possible that we are also in the
	 * process of unmapping the page which could result in a deadlock
	 * with the as lock.
	 */
	if ((flags & CAPTURE_ASYNC) && (curproc == procp)) {
		page_free(pp, 1);
		return (-1);
	}

	/* only return zeroed out pages */
	pagezero(pp, 0, PAGESIZE);

	rw_enter(&pph_rwlock, RW_READER);
	php = physmem_get_hash(paddr, PAGESIZE, procp);
	if (php == NULL) {
		rw_exit(&pph_rwlock);
		/*
		 * Free the page as there is no longer a valid outstanding
		 * request for this page.
		 */
		page_free(pp, 1);
		return (1);
	}

	vp = php->ph_vnode;

	/*
	 * We need to protect against a possible deadlock here where we own
	 * the vnode page hash mutex and want to acquire it again as there
	 * are locations in the code, where we unlock a page while holding
	 * the mutex which can lead to the page being captured and eventually
	 * end up here.
	 */
	if (mutex_owned(page_vnode_mutex(vp))) {
		rw_exit(&pph_rwlock);
		page_free(pp, 1);
		return (-1);
	}

	ret = page_hashin(pp, vp, paddr, NULL);
	rw_exit(&pph_rwlock);
	if (ret == 0) {
		page_free(pp, 1);
		return (-1);
	}

	page_downgrade(pp);

	mutex_enter(&freemem_lock);
	availrmem--;
	mutex_exit(&freemem_lock);

	return (0);
}

/*
 * The guts of the PHYSMEM_DESTROY ioctl.
 * The cookie passed in will provide all of the information needed to
 * free up the address space and physical memory associated with the
 * corresponding PHSYMEM_SETUP ioctl.
 * Returns 0 on success with the following error codes on failure:
 *	EINVAL - The cookie supplied is not valid.
 */
int
physmem_destroy_addrs(uint64_t p_cookie)
{
	struct as *as = curproc->p_as;
	size_t len;
	caddr_t uvaddr;

	rw_enter(&pph_rwlock, RW_READER);
	if (physmem_validate_cookie(p_cookie) == 0) {
		rw_exit(&pph_rwlock);
		return (EINVAL);
	}

	len = ((struct physmem_hash *)(uintptr_t)p_cookie)->ph_seg_len;
	uvaddr = ((struct physmem_hash *)(uintptr_t)p_cookie)->ph_base_va;
	rw_exit(&pph_rwlock);

	(void) as_unmap(as, uvaddr, len);

	return (0);
}

/*
 * If the page has been hashed into the physmem vnode, then just look it up
 * and return it via pl, otherwise return ENOMEM as the map ioctl has not
 * succeeded on the given page.
 */
/*ARGSUSED*/
static int
physmem_getpage(struct vnode *vp, offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr, enum seg_rw rw,
    struct cred *cr, caller_context_t *ct)
{
	page_t *pp;

	ASSERT(len == PAGESIZE);
	ASSERT(AS_READ_HELD(seg->s_as));

	/*
	 * If the page is in the hash, then we successfully claimed this
	 * page earlier, so return it to the caller.
	 */
	pp = page_lookup(vp, off, SE_SHARED);
	if (pp != NULL) {
		pl[0] = pp;
		pl[1] = NULL;
		*protp = PROT_ALL;
		return (0);
	}
	return (ENOMEM);
}

/*
 * We can not allow a process mapping /dev/physmem pages to fork as there can
 * only be a single mapping to a /dev/physmem page at a given time.  Thus, the
 * return of EINVAL when we are not working on our own address space.
 * Otherwise we return zero as this function is required for normal operation.
 */
/*ARGSUSED*/
static int
physmem_addmap(struct vnode *vp, offset_t off, struct as *as,
    caddr_t addr, size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    struct cred *cred, caller_context_t *ct)
{
	if (curproc->p_as != as) {
		return (EINVAL);
	}
	return (0);
}

/* Will always get called for removing a whole segment. */
/*ARGSUSED*/
static int
physmem_delmap(struct vnode *vp, offset_t off, struct as *as,
    caddr_t addr, size_t len, uint_t prot, uint_t maxprot, uint_t flags,
    struct cred *cred, caller_context_t *ct)
{
	/*
	 * Release our hold on the vnode so that the final VN_RELE will
	 * call physmem_inactive to clean things up.
	 */
	VN_RELE(vp);

	return (0);
}

/*
 * Clean up all the pages belonging to this vnode and then free it.
 */
/*ARGSUSED*/
static void
physmem_inactive(vnode_t *vp, cred_t *crp, caller_context_t *ct)
{
	page_t *pp;

	/*
	 * Remove the vnode from the hash now, to prevent asynchronous
	 * attempts to map into this vnode.  This avoids a deadlock
	 * where two threads try to get into this logic at the same
	 * time and try to map the pages they are destroying into the
	 * other's address space.
	 * If it's not in the hash, just free it.
	 */
	if (physmem_remove_vnode_hash(vp) == 0) {
		ASSERT(vp->v_pages == NULL);
		vn_free(vp);
		physmem_remove_hash_proc();
		mutex_enter(&physmem_mutex);
		physmem_vnodecnt--;
		mutex_exit(&physmem_mutex);
		return;
	}

	/*
	 * At this point in time, no other logic can be adding or removing
	 * pages from the vnode, otherwise the v_pages list could be inaccurate.
	 */

	while ((pp = vp->v_pages) != NULL) {
		page_t *rpp;
		if (page_tryupgrade(pp)) {
			/*
			 * set lckcnt for page_destroy to do availrmem
			 * accounting
			 */
			pp->p_lckcnt = 1;
			page_destroy(pp, 0);
		} else {
			/* failure to lock should be transient */
			rpp = page_lookup(vp, ptob(pp->p_pagenum), SE_SHARED);
			if (rpp != pp) {
				page_unlock(rpp);
				continue;
			}
			page_unlock(pp);
		}
	}
	vn_free(vp);
	physmem_remove_hash_proc();
	mutex_enter(&physmem_mutex);
	physmem_vnodecnt--;
	mutex_exit(&physmem_mutex);
}

/*ARGSUSED*/
static int
physmem_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;

	switch (cmd) {
	case PHYSMEM_SETUP:
		{
			struct physmem_setup_param psp;
			if (ddi_copyin((void *)arg, &psp,
			    sizeof (struct physmem_setup_param), 0))
				return (EFAULT);
			ret = physmem_setup_addrs(&psp);
			if (ddi_copyout(&psp, (void *)arg, sizeof (psp), 0))
				return (EFAULT);
		}
		break;
	case PHYSMEM_MAP:
		{
			struct physmem_map_param pmp;
			if (ddi_copyin((void *)arg, &pmp,
			    sizeof (struct physmem_map_param), 0))
				return (EFAULT);
			ret = physmem_map_addrs(&pmp);
			if (ddi_copyout(&pmp, (void *)arg, sizeof (pmp), 0))
				return (EFAULT);
		}
		break;
	case PHYSMEM_DESTROY:
		{
			uint64_t cookie;
			if (ddi_copyin((void *)arg, &cookie,
			    sizeof (uint64_t), 0))
				return (EFAULT);
			ret = physmem_destroy_addrs(cookie);
		}
		break;
	default:
		return (ENOTSUP);
	}
	return (ret);
}

/*ARGSUSED*/
static int
physmem_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int ret;
	static int msg_printed = 0;

	if ((flag & (FWRITE | FREAD)) != (FWRITE | FREAD)) {
		return (EINVAL);
	}

	/* need to make sure we have the right privileges */
	if ((ret = secpolicy_resource(credp)) != 0)
		return (ret);
	if ((ret = secpolicy_lock_memory(credp)) != 0)
		return (ret);

	if (msg_printed == 0) {
		cmn_err(CE_NOTE, "!driver has been opened. This driver may "
		    "take out long term locks on pages which may impact "
		    "dynamic reconfiguration events");
		msg_printed = 1;
	}

	return (0);
}

/*ARGSUSED*/
static int
physmem_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
physmem_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **resultp)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = physmem_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(ulong_t)getminor((dev_t)arg);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
physmem_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int i;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	physmem_dip = dip;

	/* Initialize driver specific data */
	if (physmem_setup_vnops()) {
		ddi_remove_minor_node(dip, ddi_get_name(dip));
		return (DDI_FAILURE);
	}

	for (i = 0; i < PPH_SIZE; i++)
		pph[i] = NULL;

	page_capture_register_callback(PC_PHYSMEM, 10000,
	    map_page_proc);

	return (DDI_SUCCESS);
}

static int
physmem_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(physmem_dip == dip);

	mutex_enter(&physmem_mutex);
	if (physmem_vnodecnt == 0) {
		if (physmem_vnodeops != NULL) {
			vn_freevnodeops(physmem_vnodeops);
			physmem_vnodeops = NULL;
			page_capture_unregister_callback(PC_PHYSMEM);
		}
	} else {
		ret = EBUSY;
	}
	mutex_exit(&physmem_mutex);
	if (ret == DDI_SUCCESS)
		ddi_remove_minor_node(dip, ddi_get_name(dip));
	return (ret);
}

static struct cb_ops physmem_cb_ops = {
	physmem_open,	/* open */
	physmem_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	physmem_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* cb_str */
	D_NEW | D_MP | D_DEVMAP,
	CB_REV,
	NULL,
	NULL
};

static struct dev_ops physmem_ops = {
	DEVO_REV,
	0,
	physmem_getinfo,
	nulldev,
	nulldev,
	physmem_attach,
	physmem_detach,
	nodev,
	&physmem_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"physmem driver",
	&physmem_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
