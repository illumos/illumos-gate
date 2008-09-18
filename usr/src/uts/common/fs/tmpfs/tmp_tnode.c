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
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <sys/fs/tmp.h>
#include <sys/fs/tmpnode.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/swap.h>
#include <sys/vtrace.h>

/*
 * Reserve swap space for the size of the file.
 * Called before growing a file (i.e. ftruncate, write)
 * Returns 0 on success.
 */
int
tmp_resv(
	struct tmount *tm,
	struct tmpnode *tp,
	size_t delta,		/* size needed */
	int pagecreate)		/* call anon_resv if set */
{
	pgcnt_t pages = btopr(delta);
	zone_t *zone;

	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));
	ASSERT(tp->tn_type == VREG);
	/*
	 * pagecreate is set only if we actually need to call anon_resv
	 * to reserve an additional page of anonymous memory.
	 * Since anon_resv always reserves a page at a time,
	 * it should only get called when we know we're growing the
	 * file into a new page or filling a hole.
	 *
	 * Deny if trying to reserve more than tmpfs can allocate
	 */
	zone = tm->tm_vfsp->vfs_zone;
	if (pagecreate && ((tm->tm_anonmem + pages > tm->tm_anonmax) ||
	    (!anon_checkspace(ptob(pages + tmpfs_minfree), zone)) ||
	    (anon_try_resv_zone(delta, zone) == 0))) {
		return (1);
	}

	/*
	 * update statistics
	 */
	if (pagecreate) {
		mutex_enter(&tm->tm_contents);
		tm->tm_anonmem += pages;
		mutex_exit(&tm->tm_contents);

		TRACE_2(TR_FAC_VM, TR_ANON_TMPFS, "anon tmpfs:%p %lu",
		    tp, delta);
	}

	return (0);
}

/*
 * tmp_unresv - called when truncating a file
 * Only called if we're freeing at least pagesize bytes
 * because anon_unresv does a btopr(delta)
 */
static void
tmp_unresv(
	struct tmount *tm,
	struct tmpnode *tp,
	size_t delta)
{
	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));
	ASSERT(tp->tn_type == VREG);

	anon_unresv_zone(delta, tm->tm_vfsp->vfs_zone);

	mutex_enter(&tm->tm_contents);
	tm->tm_anonmem -= btopr(delta);
	mutex_exit(&tm->tm_contents);

	TRACE_2(TR_FAC_VM, TR_ANON_TMPFS, "anon tmpfs:%p %lu", tp, delta);
}

#define	TMP_INIT_SZ	128

/*
 * Grow the anon pointer array to cover 'newsize' bytes plus slack.
 */
void
tmpnode_growmap(struct tmpnode *tp, ulong_t newsize)
{
	pgcnt_t np = btopr(newsize);

	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));
	ASSERT(RW_WRITE_HELD(&tp->tn_contents));
	ASSERT(tp->tn_type == VREG);

	if (tp->tn_asize >= np)
		return;

	if (newsize > MAXOFF_T)
		np = btopr((u_offset_t)MAXOFF_T);

	if (tp->tn_anon == NULL) {
		tp->tn_anon = anon_create(MAX(np, TMP_INIT_SZ), ANON_SLEEP);
		tp->tn_asize = tp->tn_anon->size;
		return;
	}

	tp->tn_asize = anon_grow(tp->tn_anon, NULL, tp->tn_asize,
	    np - tp->tn_asize, ANON_SLEEP);
	ASSERT(tp->tn_asize >= np);
}

/*
 * Initialize a tmpnode and add it to file list under mount point.
 */
void
tmpnode_init(struct tmount *tm, struct tmpnode *t, vattr_t *vap, cred_t *cred)
{
	struct vnode *vp;
	timestruc_t now;

	ASSERT(vap != NULL);

	rw_init(&t->tn_rwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&t->tn_tlock, NULL, MUTEX_DEFAULT, NULL);
	t->tn_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	t->tn_mask = 0;
	t->tn_type = vap->va_type;
	t->tn_nodeid = (ino64_t)(uint32_t)((uintptr_t)t >> 3);
	t->tn_nlink = 1;
	t->tn_size = 0;

	if (cred == NULL) {
		t->tn_uid = vap->va_uid;
		t->tn_gid = vap->va_gid;
	} else {
		t->tn_uid = crgetuid(cred);
		t->tn_gid = crgetgid(cred);
	}

	t->tn_fsid = tm->tm_dev;
	t->tn_rdev = vap->va_rdev;
	t->tn_blksize = PAGESIZE;
	t->tn_nblocks = 0;
	gethrestime(&now);
	t->tn_atime = now;
	t->tn_mtime = now;
	t->tn_ctime = now;
	t->tn_seq = 0;
	t->tn_dir = NULL;

	t->tn_vnode = vn_alloc(KM_SLEEP);
	vp = TNTOV(t);
	vn_setops(vp, tmp_vnodeops);
	vp->v_vfsp = tm->tm_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)t;
	mutex_enter(&tm->tm_contents);
	/*
	 * Increment the pseudo generation number for this tmpnode.
	 * Since tmpnodes are allocated and freed, there really is no
	 * particular generation number for a new tmpnode.  Just fake it
	 * by using a counter in each file system.
	 */
	t->tn_gen = tm->tm_gen++;

	/*
	 * Add new tmpnode to end of linked list of tmpnodes for this tmpfs
	 * Root directory is handled specially in tmp_mount.
	 */
	if (tm->tm_rootnode != (struct tmpnode *)NULL) {
		t->tn_forw = NULL;
		t->tn_back = tm->tm_rootnode->tn_back;
		t->tn_back->tn_forw = tm->tm_rootnode->tn_back = t;
	}
	mutex_exit(&tm->tm_contents);
	vn_exists(vp);
}

/*
 * tmpnode_trunc - set length of tmpnode and deal with resources
 */
int
tmpnode_trunc(
	struct tmount *tm,
	struct tmpnode *tp,
	ulong_t newsize)
{
	size_t oldsize = tp->tn_size;
	size_t delta;
	struct vnode *vp = TNTOV(tp);
	timestruc_t now;
	int error = 0;

	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));
	ASSERT(RW_WRITE_HELD(&tp->tn_contents));

	if (newsize == oldsize) {
		/* Required by POSIX */
		goto stamp_out;
	}

	switch (tp->tn_type) {
	case VREG:
		/* Growing the file */
		if (newsize > oldsize) {
			delta = P2ROUNDUP(newsize, PAGESIZE) -
			    P2ROUNDUP(oldsize, PAGESIZE);
			/*
			 * Grow the size of the anon array to the new size
			 * Reserve the space for the growth here.
			 * We do it this way for now because this is how
			 * tmpfs used to do it, and this way the reserved
			 * space is alway equal to the file size.
			 * Alternatively, we could wait to reserve space 'til
			 * someone tries to store into one of the newly
			 * trunc'ed up pages. This would give us behavior
			 * identical to ufs; i.e., you could fail a
			 * fault on storing into a holey region of a file
			 * if there is no space in the filesystem to fill
			 * the hole at that time.
			 */
			/*
			 * tmp_resv calls anon_resv only if we're extending
			 * the file into a new page
			 */
			if (tmp_resv(tm, tp, delta,
			    (btopr(newsize) != btopr(oldsize)))) {
				error = ENOSPC;
				goto out;
			}
			tmpnode_growmap(tp, newsize);
			tp->tn_size = newsize;
			break;
		}

		/* Free anon pages if shrinking file over page boundary. */
		if (btopr(newsize) != btopr(oldsize)) {
			pgcnt_t freed;
			delta = P2ROUNDUP(oldsize, PAGESIZE) -
			    P2ROUNDUP(newsize, PAGESIZE);
			freed = anon_pages(tp->tn_anon, btopr(newsize),
			    btopr(delta));
			tp->tn_nblocks -= freed;
			anon_free(tp->tn_anon, btopr(newsize), delta);
			tmp_unresv(tm, tp, delta);
		}

		/*
		 * Update the file size now to reflect the pages we just
		 * blew away as we're about to drop the
		 * contents lock to zero the partial page (which could
		 * re-enter tmpfs via getpage and try to reacquire the lock)
		 * Once we drop the lock, faulters can fill in holes in
		 * the file and if we haven't updated the size they
		 * may fill in holes that are beyond EOF, which will then
		 * never get cleared.
		 */
		tp->tn_size = newsize;

		/* Zero new size of file to page boundary. */
		if (anon_get_ptr(tp->tn_anon, btop(newsize)) != NULL) {
			size_t zlen;

			zlen = PAGESIZE - ((ulong_t)newsize & PAGEOFFSET);
			rw_exit(&tp->tn_contents);
			pvn_vpzero(TNTOV(tp), (u_offset_t)newsize, zlen);
			rw_enter(&tp->tn_contents, RW_WRITER);
		}

		if (newsize == 0) {
			/* Delete anon array for tmpnode */
			ASSERT(tp->tn_nblocks == 0);
			ASSERT(anon_get_ptr(tp->tn_anon, 0) == NULL);
			ASSERT(!vn_has_cached_data(vp));

			anon_release(tp->tn_anon, tp->tn_asize);
			tp->tn_anon = NULL;
			tp->tn_asize = 0;
		}
		break;
	case VLNK:
		/*
		 * Don't do anything here
		 * tmp_inactive frees the memory
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
		tdirtrunc(tp);
		ASSERT(tp->tn_nlink == 0);
		break;
	default:
		goto out;
	}

stamp_out:
	gethrestime(&now);
	tp->tn_mtime = now;
	tp->tn_ctime = now;
out:
	/*
	 * tmpnode_trunc() cannot fail when newsize == 0.
	 */
	ASSERT(error == 0 || newsize != 0);
	return (error);
}
