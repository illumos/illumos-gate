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
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <vm/seg.h>
#include <sys/fs/swapnode.h>
#include <fs/fs_subr.h>
#include <sys/cmn_err.h>
#include <sys/mem_config.h>
#include <sys/atomic.h>

extern const fs_operation_def_t swap_vnodeops_template[];

/*
 * swapfs_minfree is the amount of physical memory (actually remaining
 * availrmem) that we want to keep free for the rest of the system.  This
 * means that swapfs can only grow to availrmem - swapfs_minfree.  This
 * can be set as just constant value or a certain percentage of installed
 * physical memory. It is set in swapinit().
 *
 * Users who want to change the amount of memory that can be used as swap
 * space should do so by setting swapfs_desfree at boot time,
 * not swapfs_minfree.
 */

pgcnt_t swapfs_desfree = 0;
pgcnt_t swapfs_minfree = 0;
pgcnt_t swapfs_reserve = 0;

#ifdef SWAPFS_DEBUG
int swapfs_debug;
#endif /* SWAPFS_DEBUG */


static int swapfs_vpcount;
static kmutex_t swapfs_lock;
static struct async_reqs *sw_ar, *sw_pendlist, *sw_freelist;

static struct vnode **swap_vnodes;	/* ptr's to swap vnodes */

static void swap_init_mem_config(void);

static pgcnt_t initial_swapfs_desfree;
static pgcnt_t initial_swapfs_minfree;
static pgcnt_t initial_swapfs_reserve;

static int swap_sync(struct vfs *vfsp, short flag, struct cred *cr);

static void
swapfs_recalc_save_initial(void)
{
	initial_swapfs_desfree = swapfs_desfree;
	initial_swapfs_minfree = swapfs_minfree;
	initial_swapfs_reserve = swapfs_reserve;
}

static int
swapfs_recalc(pgcnt_t pgs)
{
	pgcnt_t new_swapfs_desfree;
	pgcnt_t new_swapfs_minfree;
	pgcnt_t new_swapfs_reserve;

	new_swapfs_desfree = initial_swapfs_desfree;
	new_swapfs_minfree = initial_swapfs_minfree;
	new_swapfs_reserve = initial_swapfs_reserve;

	if (new_swapfs_desfree == 0)
		new_swapfs_desfree = btopr(7 * 512 * 1024); /* 3-1/2Mb */;

	if (new_swapfs_minfree == 0) {
		/*
		 * Set swapfs_minfree to be an eighth of physical, but
		 * capped at 512 MiB.
		 */
		new_swapfs_minfree = MIN(btopr(512 * 1024 * 1024), pgs >> 3);
	}

	/*
	 * priv processes can reserve memory as swap as long as availrmem
	 * remains greater than swapfs_minfree; in the case of non-priv
	 * processes, memory can be reserved as swap only if availrmem
	 * doesn't fall below (swapfs_minfree + swapfs_reserve). Thus,
	 * swapfs_reserve amount of memswap is not available to non-priv
	 * processes. This protects daemons such as automounter dying
	 * as a result of application processes eating away almost entire
	 * membased swap. This safeguard becomes useless if apps are run
	 * with root access.
	 *
	 * set swapfs_reserve to a minimum of 4Mb or 1/128 of physmem whichever
	 * is greater up to the limit of 128 MB.
	 */
	if (new_swapfs_reserve == 0)
		new_swapfs_reserve = MIN(btopr(128 * 1024 * 1024),
		    MAX(btopr(4 * 1024 * 1024), pgs >> 7));

	/* Test basic numeric viability. */
	if (new_swapfs_minfree > pgs)
		return (0);

	/* Equivalent test to anon_resvmem() check. */
	if (availrmem < new_swapfs_minfree) {
		/*
		 * If ism pages are being used, then there must be agreement
		 * between these two policies.
		 */
		if ((availrmem > segspt_minfree) && (segspt_minfree > 0)) {
			new_swapfs_minfree = segspt_minfree;
		} else {
			return (0);
		}
	}

	swapfs_desfree = new_swapfs_desfree;
	swapfs_minfree = new_swapfs_minfree;
	swapfs_reserve = new_swapfs_reserve;

	return (1);
}

/*ARGSUSED1*/
int
swapinit(int fstype, char *name)
{
	/* reserve for mp */
	ssize_t sw_freelist_size = klustsize / PAGESIZE * 2;
	int i, error;

	static const fs_operation_def_t swap_vfsops[] = {
		VFSNAME_SYNC, { .vfs_sync = swap_sync },
		NULL, NULL
	};

	SWAPFS_PRINT(SWAP_SUBR, "swapinit\n", 0, 0, 0, 0, 0);
	mutex_init(&swapfs_lock, NULL, MUTEX_DEFAULT, NULL);

	swap_vnodes = kmem_zalloc(MAX_SWAP_VNODES * sizeof (struct vnode *),
	    KM_SLEEP);

	swapfs_recalc_save_initial();
	if (!swapfs_recalc(physmem))
		cmn_err(CE_PANIC, "swapfs_minfree(%lu) > physmem(%lu)",
		    swapfs_minfree, physmem);

	/*
	 * Arrange for a callback on memory size change.
	 */
	swap_init_mem_config();

	sw_ar = (struct async_reqs *)
	    kmem_zalloc(sw_freelist_size*sizeof (struct async_reqs), KM_SLEEP);

	error = vfs_setfsops(fstype, swap_vfsops, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "swapinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, swap_vnodeops_template, &swap_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "swapinit: bad vnode ops template");
		return (error);
	}
	sw_freelist = sw_ar;
	for (i = 0; i < sw_freelist_size - 1; i++)
		sw_ar[i].a_next = &sw_ar[i + 1];

	return (0);
}

/*
 * Get a swapfs vnode corresponding to the specified identifier.
 */
struct vnode *
swapfs_getvp(ulong_t vidx)
{
	struct vnode *vp;

	vp = swap_vnodes[vidx];
	if (vp) {
		return (vp);
	}

	mutex_enter(&swapfs_lock);
	vp = swap_vnodes[vidx];
	if (vp == NULL) {
		vp = vn_alloc(KM_SLEEP);
		vn_setops(vp, swap_vnodeops);
		vp->v_type = VREG;
		vp->v_flag |= (VISSWAP|VISSWAPFS);
		swap_vnodes[vidx] = vp;
		swapfs_vpcount++;
	}
	mutex_exit(&swapfs_lock);
	return (vp);
}

int swap_lo;

/*ARGSUSED*/
static int
swap_sync(struct vfs *vfsp, short flag, struct cred *cr)
{
	struct vnode *vp;
	int i;

	if (!(flag & SYNC_ALL))
		return (1);

	/*
	 * assumes that we are the only one left to access this so that
	 * no need to use swapfs_lock (since it's staticly defined)
	 */
	for (i = 0; i < MAX_SWAP_VNODES; i++) {
		vp = swap_vnodes[i];
		if (vp) {
			VN_HOLD(vp);
			(void) VOP_PUTPAGE(vp, (offset_t)0, 0,
			    (B_ASYNC | B_FREE), kcred, NULL);
			VN_RELE(vp);
		}
	}
	return (0);
}

extern int sw_pending_size;

/*
 * Take an async request off the pending queue
 */
struct async_reqs *
sw_getreq()
{
	struct async_reqs *arg;

	mutex_enter(&swapfs_lock);
	arg = sw_pendlist;
	if (arg) {
		sw_pendlist = arg->a_next;
		arg->a_next = NULL;
		sw_pending_size -= PAGESIZE;
	}
	ASSERT(sw_pending_size >= 0);
	mutex_exit(&swapfs_lock);
	return (arg);
}

/*
 * Put an async request on the pending queue
 */
void
sw_putreq(struct async_reqs *arg)
{
	/* Hold onto it */
	VN_HOLD(arg->a_vp);

	mutex_enter(&swapfs_lock);
	arg->a_next = sw_pendlist;
	sw_pendlist = arg;
	sw_pending_size += PAGESIZE;
	mutex_exit(&swapfs_lock);
}

/*
 * Put an async request back on the pending queue
 */
void
sw_putbackreq(struct async_reqs *arg)
{
	mutex_enter(&swapfs_lock);
	arg->a_next = sw_pendlist;
	sw_pendlist = arg;
	sw_pending_size += PAGESIZE;
	mutex_exit(&swapfs_lock);
}

/*
 * Take an async request structure off the free list
 */
struct async_reqs *
sw_getfree()
{
	struct async_reqs *arg;

	mutex_enter(&swapfs_lock);
	arg = sw_freelist;
	if (arg) {
		sw_freelist = arg->a_next;
		arg->a_next = NULL;
	}
	mutex_exit(&swapfs_lock);
	return (arg);
}

/*
 * Put an async request structure on the free list
 */
void
sw_putfree(struct async_reqs *arg)
{
	/* Release our hold - should have locked the page by now */
	VN_RELE(arg->a_vp);

	mutex_enter(&swapfs_lock);
	arg->a_next = sw_freelist;
	sw_freelist = arg;
	mutex_exit(&swapfs_lock);
}

static pgcnt_t swapfs_pending_delete;

/*ARGSUSED*/
static void
swap_mem_config_post_add(
	void *arg,
	pgcnt_t delta_swaps)
{
	(void) swapfs_recalc(physmem - swapfs_pending_delete);
}

/*ARGSUSED*/
static int
swap_mem_config_pre_del(
	void *arg,
	pgcnt_t delta_swaps)
{
	pgcnt_t nv;

	nv = atomic_add_long_nv(&swapfs_pending_delete, (spgcnt_t)delta_swaps);
	if (!swapfs_recalc(physmem - nv)) {
		/*
		 * Tidy-up is done by the call to post_del which
		 * is always made.
		 */
		cmn_err(CE_NOTE, "Memory operation refused to ensure system "
		    "doesn't deadlock due to excessive consumption by swapfs.");
		return (EBUSY);
	}
	return (0);
}

/*ARGSUSED*/
static void
swap_mem_config_post_del(
	void *arg,
	pgcnt_t delta_swaps,
	int cancelled)
{
	pgcnt_t nv;

	nv = atomic_add_long_nv(&swapfs_pending_delete, -(spgcnt_t)delta_swaps);
	(void) swapfs_recalc(physmem - nv);
}

static kphysm_setup_vector_t swap_mem_config_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	swap_mem_config_post_add,
	swap_mem_config_pre_del,
	swap_mem_config_post_del,
};

static void
swap_init_mem_config(void)
{
	int ret;

	ret = kphysm_setup_func_register(&swap_mem_config_vec, (void *)NULL);
	ASSERT(ret == 0);
}
