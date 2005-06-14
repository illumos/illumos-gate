/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <vm/hat.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/pvn.h>
#include <vm/page.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/fs/xmem.h>


extern void	*xpgget(struct xmount *);
extern void	xpgput(struct xmount *, void *);

#define	MODESHIFT	3

size_t		xmemfs_maxkmem = 32768;
size_t		xmemfs_kmemcnt;

int
xmem_xaccess(void *vxp, int mode, struct cred *cred)
{
	struct xmemnode *xp = vxp;
	int shift = 0;
	/*
	 * Check access based on owner, group and
	 * public permissions in xmemnode.
	 */
	if (crgetuid(cred) != xp->xn_uid) {
		shift += MODESHIFT;
		if (groupmember(xp->xn_gid, cred) == 0)
			shift += MODESHIFT;
	}

	mode &= ~(xp->xn_mode << shift);

	if (mode == 0)
		return (0);

	return (secpolicy_vnode_access(cred, XNTOV(xp), xp->xn_uid, mode));
}

/*
 * Decide whether it is okay to remove within a sticky directory.
 * Two conditions need to be met:  write access to the directory
 * is needed.  In sticky directories, write access is not sufficient;
 * you can remove entries from a directory only if you own the directory,
 * if you are privileged, if you own the entry or if they entry is
 * a plain file and you have write access to that file.
 * Function returns 0 if remove access is granted.
 */
int
xmem_sticky_remove_access(struct xmemnode *dir, struct xmemnode *entry,
	struct cred *cr)
{
	uid_t uid;

	if ((dir->xn_mode & S_ISVTX) &&
	    (uid = crgetuid(cr)) != dir->xn_uid &&
	    uid != entry->xn_uid &&
	    (entry->xn_type != VREG ||
		xmem_xaccess(entry, VWRITE, cr) != 0))
			return (secpolicy_vnode_remove(cr));
	return (0);
}

/*
 * Allocate zeroed memory if xmemfs_maxkmem has not been exceeded
 * or the 'musthave' flag is set.  'musthave' allocations should
 * always be subordinate to normal allocations so that xmemfs_maxkmem
 * can't be exceeded by more than a few KB.  Example: when creating
 * a new directory, the xmemnode is a normal allocation; if that
 * succeeds, the dirents for "." and ".." are 'musthave' allocations.
 */
void *
xmem_memalloc(size_t size, int musthave)
{
	void			*ptr = NULL;

	if (musthave) {
		atomic_add_long(&xmemfs_kmemcnt, size);
		ptr = kmem_zalloc(size, KM_SLEEP);
	} else if (xmemfs_kmemcnt + size < xmemfs_maxkmem) {
		/*
		 * kmemcnt may have increased since above check so a little
		 * more than xmemfs_maxkmem may be allocated.
		 */
		ptr = kmem_zalloc(size, KM_NOSLEEP);
		if (ptr)
			atomic_add_long(&xmemfs_kmemcnt, size);
	}
	return (ptr);
}

void
xmem_memfree(void *cp, size_t size)
{
	extern size_t		xmemfs_kmemcnt;

	kmem_free(cp, size);
	atomic_add_long(&xmemfs_kmemcnt, -size);
}

/* add to the number of pages we have created */

int
xmem_mem_add(struct xmount *xm, size_t size)
{
	mutex_enter(&xm->xm_contents);

	/* allocate the last available block */
	if ((xm->xm_mem + size) > xm->xm_max) {
		mutex_exit(&xm->xm_contents);
		return (1);
	}
	xm->xm_mem += size;
	mutex_exit(&xm->xm_contents);
	return (0);
}

/* sub to the number of pages we have created */

static void
xmem_mem_sub(struct xmount *xm, size_t size)
{
	mutex_enter(&xm->xm_contents);
	xm->xm_mem -= size;
	mutex_exit(&xm->xm_contents);
}

/*
 * xmem_acquire_pages: returns an array of size btop(xm_bsize) page pointers
 * or xm_bsize bytes.
 *
 * If large page, the array will contain 1024 entries (4MB) or 512 entries.
 *
 * If not large page, there is no array as a page_t * is returned.
 */

static page_t **
xmem_acquire_pages(struct xmount *xm, struct vnode *vp, offset_t off)
{
	page_t		**ppa, *pp, *pplist;
	uint_t		pindex;
	size_t		bsize;
	struct seg	tmpseg;

	bsize = xm->xm_bsize;

	if (xmem_mem_add(xm, 1))
		return (NULL);

	if (xm->xm_flags & XARGS_RESERVEMEM) {

		mutex_enter(&xm->xm_contents);
		ppa = xpgget(xm);
		mutex_exit(&xm->xm_contents);

		if (xm->xm_ppb == 1) {
			/* ppa is a direct page pointer */

			if (!page_hashin((page_t *)ppa, vp, off, NULL)) {
				panic("xmem_acquire_pages: hashin failed"
				    " %p %llx", (void *)vp, off);
			}
			pindex = xm->xm_ppb;	/* bypass for loop */
		} else {
			pindex = 0;
		}

		for (; pindex < xm->xm_ppb; pindex++, off += PAGESIZE) {
			pp = ppa[pindex];
			if (!page_hashin(pp, vp, off, NULL)) {
				panic("xmem_acquire_pages: hashin failed"
				    " %p %p %llx", (void *)pp, (void *)vp, off);
			}
		}
		return (ppa);
	}
	bzero(&tmpseg, sizeof (struct seg));
	tmpseg.s_as = &kas;

	if ((freemem - xm->xm_ppb) < xmemfs_minfree ||
		page_resv(xm->xm_ppb, KM_NOSLEEP) == 0) {

		cmn_err(CE_WARN, "%s: File system full, no memory",
				xm->xm_mntpath);
		return (NULL);
	}

	(void) page_create_wait(xm->xm_ppb, PG_WAIT);

	pplist = page_get_freelist(vp, off, &tmpseg,
	    (caddr_t)(uintptr_t)off, bsize, 0, NULL);
	if (pplist == NULL && xm->xm_ppb == 1) {
		pplist = page_get_cachelist(vp, off, &tmpseg,
		    (caddr_t)(uintptr_t)off, 0, NULL);
	}
	if (pplist == NULL) {
		page_create_putback(xm->xm_ppb);
		page_unresv(xm->xm_ppb);
		return (NULL);
	}
	if (PP_ISAGED(pplist) == 0) {
		ASSERT(xm->xm_ppb == 1);
		page_hashout(pplist, NULL);
	}

	if (xm->xm_ppb > 1)
		ppa = kmem_alloc(sizeof (*ppa) * xm->xm_ppb, KM_SLEEP);

	for (pindex = 0; pindex < xm->xm_ppb; pindex++, off += PAGESIZE) {
		pp = pplist;
		page_sub(&pplist, pp);
		ASSERT(PAGE_EXCL(pp));
		ASSERT(pp->p_vnode == NULL);
		ASSERT(!hat_page_is_mapped(pp));
		PP_CLRFREE(pp);
		PP_CLRAGED(pp);

		if (xm->xm_ppb == 1)
			ppa = (page_t **)pp;
		else
			ppa[pindex] = pp;

		if (!page_hashin(pp, vp, off, NULL)) {
			panic("xmem_acquire_pages: hashin failed"
			    " %p %p %llx", (void *)pp, (void *)vp, off);
		}
		page_downgrade(pp); 		/* XXX */
	}
	return (ppa);
}

static void
xmem_release_pages(struct xmount *xm, page_t **ppa)
{
	uint_t	pindex;
	page_t	*pp;

	xmem_mem_sub(xm, 1);

	if (xm->xm_flags & XARGS_RESERVEMEM) {

		/*
		 * if ppb == 1 and to lessen the load on kmem memory in
		 * having to allocate a million 4 byte pointers for a
		 * 4 GB file system, ppa is actually a page_t *
		 */

		if (xm->xm_ppb == 1) {
			page_hashout((page_t *)ppa, NULL);
			pindex = xm->xm_ppb;		/* bypass for loop */
		} else
			pindex = 0;

		for (; pindex < xm->xm_ppb; pindex++) {
			pp = ppa[pindex];
			page_hashout(pp, NULL);
		}
		mutex_enter(&xm->xm_contents);
		xpgput(xm, ppa);
		mutex_exit(&xm->xm_contents);

	} else {
		int	flag = B_INVAL;

		if (xm->xm_ppb == 1) {
			VN_DISPOSE((page_t *)ppa, flag, 0, kcred);
		} else {

			for (pindex = 0; pindex < xm->xm_ppb; pindex++)
				VN_DISPOSE(ppa[pindex], flag, 0, kcred);

			kmem_free(ppa, sizeof (*ppa) * xm->xm_ppb);
		}
		page_unresv(xm->xm_ppb);
	}
}

/*
 * Initialize a xmemnode and add it to file list under mount point.
 */
void
xmemnode_init(struct xmount *xm, struct xmemnode *xp,
		vattr_t *vap, cred_t *cred)
{
	struct vnode *vp;
	timestruc_t now;

	ASSERT(vap != NULL);
	ASSERT(cred != NULL);

	rw_init(&xp->xn_rwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&xp->xn_tlock, NULL, MUTEX_DEFAULT, NULL);
	xp->xn_mode = MAKEIMODE(vap->va_type, vap->va_mode);

	if (S_ISREG(xp->xn_mode))
		xp->xn_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);

	xp->xn_mask = 0;
	xp->xn_type = vap->va_type;
	xp->xn_nodeid = (ino64_t)(uint32_t)((uintptr_t)xp >> 3);
	xp->xn_nlink = 1;
	xp->xn_size = 0;
	xp->xn_uid = crgetuid(cred);
	xp->xn_gid = crgetgid(cred);

	xp->xn_fsid = xm->xm_dev;
	xp->xn_rdev = vap->va_rdev;
	xp->xn_blksize = PAGESIZE;
	xp->xn_nblocks = 0;
	gethrestime(&now);
	xp->xn_atime = now;
	xp->xn_mtime = now;
	xp->xn_ctime = now;
	xp->xn_seq = 0;
	xp->xn_dir = NULL;

	vp = XNTOV(xp);
	vn_reinit(vp);
	vn_setops(vp, xmem_vnodeops);
	vp->v_vfsp = xm->xm_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)xp;

	mutex_enter(&xm->xm_contents);
	/*
	 * Increment the pseudo generation number for this xmemnode.
	 * Since xmemnodes are allocated and freed, there really is no
	 * particular generation number for a new xmemnode.  Just fake it
	 * by using a counter in each file system.
	 */
	xp->xn_gen = xm->xm_gen++;

	/*
	 * Add new xmemnode to end of linked list of xmemnodes for this xmemfs
	 * Root directory is handled specially in xmem_mount.
	 */
	if (xm->xm_rootnode != (struct xmemnode *)NULL) {
		xp->xn_forw = NULL;
		xp->xn_back = xm->xm_rootnode->xn_back;
		xp->xn_back->xn_forw = xm->xm_rootnode->xn_back = xp;
	}
	mutex_exit(&xm->xm_contents);
}

/*
 *
 */
int
xmem_fillpages(struct xmemnode *xp, struct vnode *vp, offset_t off,
					offset_t len, int zerofill)
{
	uint_t		blockno, endblock;
	caddr_t		base;
	int		error = 0;
	struct xmount	*xm = (struct xmount *)VTOXM(vp);
	offset_t	poff;
	size_t		bsize = xm->xm_bsize;

	blockno = off >> xm->xm_bshift;
	poff = (offset_t)blockno << xm->xm_bshift;
	endblock = howmany(off + len, (offset_t)bsize);

	if (endblock > xp->xn_ppasz)
		return (EINVAL);

	/* Create missing pages if any */
	for (; blockno < endblock; ) {
		if (!xp->xn_ppa[blockno]) {
			xp->xn_ppa[blockno] = xmem_acquire_pages(xm, vp, poff);
			if (!xp->xn_ppa[blockno])
				return (ENOSPC);
			if (zerofill) {
				page_t	**ppp;
				if (xm->xm_ppb == 1)
					ppp = (page_t **)&xp->xn_ppa[blockno];
				else
					ppp = xp->xn_ppa[blockno];

				base = segxmem_getmap(xm->xm_map, vp, poff,
					bsize, ppp, S_WRITE);
				(void) kzero(base, bsize);
				segxmem_release(xm->xm_map, base, bsize);
			}
			xp->xn_nblocks++;
		}
		blockno++;
		poff += bsize;
	}
	return (error);
}

/*
 * xmemnode_trunc - set length of xmemnode and deal with resources
 */
int
xmemnode_trunc(struct xmount *xm, struct xmemnode *xp, u_offset_t newsize)
{
	u_offset_t oldsize = xp->xn_size;
	timestruc_t now;
	int error = 0;
	size_t zlen;
	ulong_t	newblocks, oldblocks;

	ASSERT(RW_WRITE_HELD(&xp->xn_rwlock));
	ASSERT(RW_WRITE_HELD(&xp->xn_contents));

	if (newsize == oldsize) {
		/* Required by POSIX */
		goto stamp_out;
	}

	switch (xp->xn_type) {
	case VREG:

		oldblocks = howmany(oldsize, xm->xm_bsize);
		newblocks = howmany(newsize, xm->xm_bsize);

		XMEMPRINTF(4, ("xmemnode_trunc: xp %p old %lx new %lx\n",
				xp, oldblocks, newblocks));
		/*
		 * xn_ppasz is the size of the ppa array which may not
		 * be fully populated if pages cannot be allocated.
		 */
		ASSERT(xp->xn_ppasz >= oldblocks);

		/* Growing the file */
		if (newblocks > oldblocks) {
		    if (xp->xn_ppasz < newblocks) {
			page_t ***ppa;
			ppa = kmem_zalloc(newblocks * sizeof (*ppa), KM_SLEEP);
			if (xp->xn_ppasz) {
				bcopy(xp->xn_ppa, ppa,
					newblocks * sizeof (*ppa));

				kmem_free(xp->xn_ppa,
					xp->xn_ppasz * sizeof (*ppa));
			}
			xp->xn_ppa = ppa;
			xp->xn_ppasz = newblocks;
		    }
		}

		/* Free pages if shrinking file over block boundary. */
		if (newblocks < oldblocks) {
			uint_t	next;
			page_t ***ppa = NULL;
			next = newblocks;
			if (next) {
				ppa = kmem_zalloc(next * sizeof (*ppa),
								KM_SLEEP);
				bcopy(xp->xn_ppa, ppa, next * sizeof (*ppa));
			}
			for (; next < oldblocks; next++) {
				if (!xp->xn_ppa[next])
					continue;
				xmem_release_pages(xm, xp->xn_ppa[next]);
				xp->xn_nblocks--;
			}
			kmem_free(xp->xn_ppa, xp->xn_ppasz * sizeof (*ppa));
			xp->xn_ppa = ppa;
			xp->xn_ppasz = newblocks;
		}

		/*
		 * Update the file size now to reflect the pages we just
		 * blew away as we're about to drop the
		 * contents lock to zero the partial page (which could
		 * re-enter xmemfs via getpage and try to reacquire the lock)
		 * Once we drop the lock, faulters can fill in holes in
		 * the file and if we haven't updated the size they
		 * may fill in holes that are beyond EOF, which will then
		 * never get cleared.
		 */
		xp->xn_size = newsize;


		if (newsize) {
			/* Zero new size of file to page boundary. */
			zlen = PAGESIZE - ((ulong_t)newsize & PAGEOFFSET);
			rw_exit(&xp->xn_contents);
			pvn_vpzero(XNTOV(xp), (u_offset_t)newsize, zlen);
			rw_enter(&xp->xn_contents, RW_WRITER);
		}

		break;

	case VLNK:
		/*
		 * Don't do anything here
		 * xmem_inactive frees the memory
		 */
		if (newsize != 0)
			error = EINVAL;
		goto out;
	case VDIR:
		/*
		 * Remove all the directory entries under this directory.
		 */
		if (newsize != 0) {
			error = EINVAL;
			goto out;
		}
		xdirtrunc(xp);
		ASSERT(xp->xn_nlink == 0);
		break;
	default:
		goto out;
	}

stamp_out:
	gethrestime(&now);
	xp->xn_mtime = now;
	xp->xn_ctime = now;
out:
	/*
	 * xmemnode_trunc() cannot fail when newsize == 0.
	 */
	ASSERT(error == 0 || newsize != 0);
	return (error);
}
