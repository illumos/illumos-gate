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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/fs/hyprlofs_info.h>

#define	MODESHIFT	3

/* Initialize a hlnode and add it to file list under mount point. */
void
hyprlofs_node_init(hlfsmount_t *hm, hlnode_t *h, vattr_t *vap, cred_t *cr)
{
	vnode_t *vp;
	timestruc_t now;

	ASSERT(vap != NULL);

	rw_init(&h->hln_rwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&h->hln_tlock, NULL, MUTEX_DEFAULT, NULL);
	h->hln_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	h->hln_mask = 0;
	h->hln_type = vap->va_type;
	h->hln_nodeid = (ino64_t)(uint32_t)((uintptr_t)h >> 3);
	h->hln_nlink = 1;
	h->hln_size = 0;

	if (cr == NULL) {
		h->hln_uid = vap->va_uid;
		h->hln_gid = vap->va_gid;
	} else {
		h->hln_uid = crgetuid(cr);
		h->hln_gid = crgetgid(cr);
	}

	h->hln_fsid = hm->hlm_dev;
	h->hln_rdev = vap->va_rdev;
	h->hln_blksize = PAGESIZE;
	h->hln_nblocks = 0;
	gethrestime(&now);
	h->hln_atime = now;
	h->hln_mtime = now;
	h->hln_ctime = now;
	h->hln_seq = 0;
	h->hln_dir = NULL;

	h->hln_vnode = vn_alloc(KM_SLEEP);
	vp = HLNTOV(h);
	vn_setops(vp, hyprlofs_vnodeops);
	vp->v_vfsp = hm->hlm_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)h;
	mutex_enter(&hm->hlm_contents);
	/*
	 * Increment the pseudo generation number for this hlnode. Since
	 * hlnodes are allocated and freed, there really is no particular
	 * generation number for a new hlnode.  Just fake it by using a
	 * counter in each file system.
	 */
	h->hln_gen = hm->hlm_gen++;

	/*
	 * Add new hlnode to end of linked list of hlnodes for this hyprlofs
	 * Root dir is handled specially in hyprlofs_mount.
	 */
	if (hm->hlm_rootnode != (hlnode_t *)NULL) {
		h->hln_forw = NULL;
		h->hln_back = hm->hlm_rootnode->hln_back;
		h->hln_back->hln_forw = hm->hlm_rootnode->hln_back = h;
	}
	mutex_exit(&hm->hlm_contents);
	vn_exists(vp);
}

int
hyprlofs_taccess(void *vtp, int mode, cred_t *cr)
{
	hlnode_t *hp = vtp;
	int shift = 0;

	/* Check access based on owner, group and public perms in hlnode. */
	if (crgetuid(cr) != hp->hln_uid) {
		shift += MODESHIFT;
		if (groupmember(hp->hln_gid, cr) == 0)
			shift += MODESHIFT;
	}

	return (secpolicy_vnode_access2(cr, HLNTOV(hp), hp->hln_uid,
	    hp->hln_mode << shift, mode));
}

/*
 * Allocate zeroed memory if hyprlofs_maxkmem has not been exceeded or the
 * 'musthave' flag is set. 'musthave' allocations should always be subordinate
 * to normal allocations so that hyprlofs_maxkmem can't be exceeded by more
 * than a few KB.  E.g. when creating a new dir, the hlnode is a normal
 * allocation; if that succeeds, the dirents for "." and ".." are 'musthave'
 * allocations.
 */
void *
hyprlofs_memalloc(size_t size, int musthave)
{
	if (atomic_add_long_nv(&hyprlofs_kmemspace, size) < hyprlofs_maxkmem ||
	    musthave)
		return (kmem_zalloc(size, KM_SLEEP));

	atomic_add_long(&hyprlofs_kmemspace, -size);
	cmn_err(CE_WARN, "hyprlofs over memory limit");
	return (NULL);
}

void
hyprlofs_memfree(void *cp, size_t size)
{
	kmem_free(cp, size);
	atomic_add_long(&hyprlofs_kmemspace, -size);
}
