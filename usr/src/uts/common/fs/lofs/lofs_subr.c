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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * The idea behind composition-based stacked filesystems is to add a
 * vnode to the stack of vnodes for each mount. These vnodes have their
 * own set of mount options and filesystem-specific functions, so they
 * can modify data or operations before they are passed along. Such a
 * filesystem must maintain a mapping from the underlying vnodes to its
 * interposing vnodes.
 *
 * In lofs, this mapping is implemented by a hashtable. Each bucket
 * contains a count of the number of nodes currently contained, the
 * chain of vnodes, and a lock to protect the list of vnodes. The
 * hashtable dynamically grows if the number of vnodes in the table as a
 * whole exceeds the size of the table left-shifted by
 * lo_resize_threshold. In order to minimize lock contention, there is
 * no global lock protecting the hashtable, hence obtaining the
 * per-bucket locks consists of a dance to make sure we've actually
 * locked the correct bucket. Acquiring a bucket lock doesn't involve
 * locking the hashtable itself, so we refrain from freeing old
 * hashtables, and store them in a linked list of retired hashtables;
 * the list is freed when the filesystem is unmounted.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/t_lock.h>
#include <sys/debug.h>
#include <sys/atomic.h>

#include <sys/fs/lofs_node.h>
#include <sys/fs/lofs_info.h>
/*
 * Due to the hashing algorithm, the size of the hash table needs to be a
 * power of 2.
 */
#define	LOFS_DEFAULT_HTSIZE	(1 << 6)

#define	ltablehash(vp, tblsz)	((((intptr_t)(vp))>>10) & ((tblsz)-1))

/*
 * The following macros can only be safely used when the desired bucket
 * is already locked.
 */
/*
 * The lock in the hashtable associated with the given vnode.
 */
#define	TABLE_LOCK(vp, li)      \
	(&(li)->li_hashtable[ltablehash((vp), (li)->li_htsize)].lh_lock)

/*
 * The bucket in the hashtable that the given vnode hashes to.
 */
#define	TABLE_BUCKET(vp, li)    \
	((li)->li_hashtable[ltablehash((vp), (li)->li_htsize)].lh_chain)

/*
 * Number of elements currently in the bucket that the vnode hashes to.
 */
#define	TABLE_COUNT(vp, li)	\
	((li)->li_hashtable[ltablehash((vp), (li)->li_htsize)].lh_count)

/*
 * Grab/Drop the lock for the bucket this vnode hashes to.
 */
#define	TABLE_LOCK_ENTER(vp, li)	table_lock_enter(vp, li)
#define	TABLE_LOCK_EXIT(vp, li)		\
	mutex_exit(&(li)->li_hashtable[ltablehash((vp),	\
	    (li)->li_htsize)].lh_lock)

static lnode_t *lfind(struct vnode *, struct loinfo *);
static void lsave(lnode_t *, struct loinfo *);
static struct vfs *makelfsnode(struct vfs *, struct loinfo *);
static struct lfsnode *lfsfind(struct vfs *, struct loinfo *);

uint_t lo_resize_threshold = 1;
uint_t lo_resize_factor = 2;

static kmem_cache_t *lnode_cache;

/*
 * Since the hashtable itself isn't protected by a lock, obtaining a
 * per-bucket lock proceeds as follows:
 *
 * (a) li->li_htlock protects li->li_hashtable, li->li_htsize, and
 * li->li_retired.
 *
 * (b) Per-bucket locks (lh_lock) protect the contents of the bucket.
 *
 * (c) Locking order for resizing the hashtable is li_htlock then
 * lh_lock.
 *
 * To grab the bucket lock we:
 *
 * (1) Stash away the htsize and the pointer to the hashtable to make
 * sure neither change while we're using them.
 *
 * (2) lgrow() updates the pointer to the hashtable before it updates
 * the size: the worst case scenario is that we have the wrong size (but
 * the correct table), so we hash to the wrong bucket, grab the wrong
 * lock, and then realize that things have changed, rewind and start
 * again. If both the size and the table changed since we loaded them,
 * we'll realize that too and restart.
 *
 * (3) The protocol for growing the hashtable involves holding *all* the
 * locks in the table, hence the unlocking code (TABLE_LOCK_EXIT())
 * doesn't need to do any dances, since neither the table nor the size
 * can change while any bucket lock is held.
 *
 * (4) If the hashtable is growing (by thread t1) while another thread
 * (t2) is trying to grab a bucket lock, t2 might have a stale reference
 * to li->li_htsize:
 *
 * - t1 grabs all locks in lgrow()
 * 	- t2 loads li->li_htsize and li->li_hashtable
 * - t1 changes li->hashtable
 * 	- t2 loads from an offset in the "stale" hashtable and tries to grab
 * 	the relevant mutex.
 *
 * If t1 had free'd the stale hashtable, t2 would be in trouble. Hence,
 * stale hashtables are not freed but stored in a list of "retired"
 * hashtables, which is emptied when the filesystem is unmounted.
 */
static void
table_lock_enter(vnode_t *vp, struct loinfo *li)
{
	struct lobucket *chain;
	uint_t htsize;
	uint_t hash;

	for (;;) {
		htsize = li->li_htsize;
		membar_consumer();
		chain = (struct lobucket *)li->li_hashtable;
		hash = ltablehash(vp, htsize);
		mutex_enter(&chain[hash].lh_lock);
		if (li->li_hashtable == chain && li->li_htsize == htsize)
			break;
		mutex_exit(&chain[hash].lh_lock);
	}
}

void
lofs_subrinit(void)
{
	/*
	 * Initialize the cache.
	 */
	lnode_cache = kmem_cache_create("lnode_cache", sizeof (lnode_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
lofs_subrfini(void)
{
	kmem_cache_destroy(lnode_cache);
}

/*
 * Initialize a (struct loinfo), and initialize the hashtable to have
 * htsize buckets.
 */
void
lsetup(struct loinfo *li, uint_t htsize)
{
	li->li_refct = 0;
	li->li_lfs = NULL;
	if (htsize == 0)
		htsize = LOFS_DEFAULT_HTSIZE;
	li->li_htsize = htsize;
	li->li_hashtable = kmem_zalloc(htsize * sizeof (*li->li_hashtable),
	    KM_SLEEP);
	mutex_init(&li->li_lfslock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&li->li_htlock, NULL, MUTEX_DEFAULT, NULL);
	li->li_retired = NULL;
}

/*
 * Destroy a (struct loinfo)
 */
void
ldestroy(struct loinfo *li)
{
	uint_t i, htsize;
	struct lobucket *table;
	struct lo_retired_ht *lrhp, *trhp;

	mutex_destroy(&li->li_htlock);
	mutex_destroy(&li->li_lfslock);
	htsize = li->li_htsize;
	table = li->li_hashtable;
	for (i = 0; i < htsize; i++)
		mutex_destroy(&table[i].lh_lock);
	kmem_free(table, htsize * sizeof (*li->li_hashtable));

	/*
	 * Free the retired hashtables.
	 */
	lrhp = li->li_retired;
	while (lrhp != NULL) {
		trhp = lrhp;
		lrhp = lrhp->lrh_next;
		kmem_free(trhp->lrh_table,
		    trhp->lrh_size * sizeof (*li->li_hashtable));
		kmem_free(trhp, sizeof (*trhp));
	}
	li->li_retired = NULL;
}

/*
 * Return a looped back vnode for the given vnode.
 * If no lnode exists for this vnode create one and put it
 * in a table hashed by vnode.  If the lnode for
 * this vnode is already in the table return it (ref count is
 * incremented by lfind).  The lnode will be flushed from the
 * table when lo_inactive calls freelonode.  The creation of
 * a new lnode can be forced via the LOF_FORCE flag even if
 * the vnode exists in the table.  This is used in the creation
 * of a terminating lnode when looping is detected.  A unique
 * lnode is required for the correct evaluation of the current
 * working directory.
 * NOTE: vp is assumed to be a held vnode.
 */
struct vnode *
makelonode(struct vnode *vp, struct loinfo *li, int flag)
{
	lnode_t *lp, *tlp;
	struct vfs *vfsp;
	vnode_t *nvp;

	lp = NULL;
	TABLE_LOCK_ENTER(vp, li);
	if (flag != LOF_FORCE)
		lp = lfind(vp, li);
	if ((flag == LOF_FORCE) || (lp == NULL)) {
		/*
		 * Optimistically assume that we won't need to sleep.
		 */
		lp = kmem_cache_alloc(lnode_cache, KM_NOSLEEP);
		nvp = vn_alloc(KM_NOSLEEP);
		if (lp == NULL || nvp == NULL) {
			TABLE_LOCK_EXIT(vp, li);
			/* The lnode allocation may have succeeded, save it */
			tlp = lp;
			if (tlp == NULL) {
				tlp = kmem_cache_alloc(lnode_cache, KM_SLEEP);
			}
			if (nvp == NULL) {
				nvp = vn_alloc(KM_SLEEP);
			}
			lp = NULL;
			TABLE_LOCK_ENTER(vp, li);
			if (flag != LOF_FORCE)
				lp = lfind(vp, li);
			if (lp != NULL) {
				kmem_cache_free(lnode_cache, tlp);
				vn_free(nvp);
				VN_RELE(vp);
				goto found_lnode;
			}
			lp = tlp;
		}
		atomic_inc_32(&li->li_refct);
		vfsp = makelfsnode(vp->v_vfsp, li);
		lp->lo_vnode = nvp;
		VN_SET_VFS_TYPE_DEV(nvp, vfsp, vp->v_type, vp->v_rdev);
		nvp->v_flag |= (vp->v_flag & (VNOMOUNT|VNOMAP|VDIROPEN));
		vn_setops(nvp, lo_vnodeops);
		nvp->v_data = (caddr_t)lp;
		lp->lo_vp = vp;
		lp->lo_looping = 0;
		lsave(lp, li);
		vn_exists(vp);
	} else {
		VN_RELE(vp);
	}

found_lnode:
	TABLE_LOCK_EXIT(vp, li);
	return (ltov(lp));
}

/*
 * Get/Make vfs structure for given real vfs
 */
static struct vfs *
makelfsnode(struct vfs *vfsp, struct loinfo *li)
{
	struct lfsnode *lfs;
	struct lfsnode *tlfs;

	/*
	 * Don't grab any locks for the fast (common) case.
	 */
	if (vfsp == li->li_realvfs)
		return (li->li_mountvfs);
	ASSERT(li->li_refct > 0);
	mutex_enter(&li->li_lfslock);
	if ((lfs = lfsfind(vfsp, li)) == NULL) {
		mutex_exit(&li->li_lfslock);
		lfs = kmem_zalloc(sizeof (*lfs), KM_SLEEP);
		mutex_enter(&li->li_lfslock);
		if ((tlfs = lfsfind(vfsp, li)) != NULL) {
			kmem_free(lfs, sizeof (*lfs));
			lfs = tlfs;
			goto found_lfs;
		}
		lfs->lfs_realvfs = vfsp;

		/*
		 * Even though the lfsnode is strictly speaking a private
		 * implementation detail of lofs, it should behave as a regular
		 * vfs_t for the benefit of the rest of the kernel.
		 */
		VFS_INIT(&lfs->lfs_vfs, lo_vfsops, (caddr_t)li);
		lfs->lfs_vfs.vfs_fstype = li->li_mountvfs->vfs_fstype;
		lfs->lfs_vfs.vfs_flag =
		    ((vfsp->vfs_flag | li->li_mflag) & ~li->li_dflag) &
		    INHERIT_VFS_FLAG;
		lfs->lfs_vfs.vfs_bsize = vfsp->vfs_bsize;
		lfs->lfs_vfs.vfs_dev = vfsp->vfs_dev;
		lfs->lfs_vfs.vfs_fsid = vfsp->vfs_fsid;

		if (vfsp->vfs_mntpt != NULL) {
			lfs->lfs_vfs.vfs_mntpt = vfs_getmntpoint(vfsp);
			/* Leave a reference to the mountpoint */
		}

		(void) VFS_ROOT(vfsp, &lfs->lfs_realrootvp);

		/*
		 * We use 1 instead of 0 as the value to associate with
		 * an idle lfs_vfs.  This is to prevent VFS_RELE()
		 * trying to kmem_free() our lfs_t (which is the wrong
		 * size).
		 */
		VFS_HOLD(&lfs->lfs_vfs);
		lfs->lfs_next = li->li_lfs;
		li->li_lfs = lfs;
		vfs_propagate_features(vfsp, &lfs->lfs_vfs);
	}

found_lfs:
	VFS_HOLD(&lfs->lfs_vfs);
	mutex_exit(&li->li_lfslock);
	return (&lfs->lfs_vfs);
}

/*
 * Free lfs node since no longer in use
 */
static void
freelfsnode(struct lfsnode *lfs, struct loinfo *li)
{
	struct lfsnode *prev = NULL;
	struct lfsnode *this;

	ASSERT(MUTEX_HELD(&li->li_lfslock));
	ASSERT(li->li_refct > 0);
	for (this = li->li_lfs; this != NULL; this = this->lfs_next) {
		if (this == lfs) {
			ASSERT(lfs->lfs_vfs.vfs_count == 1);
			if (prev == NULL)
				li->li_lfs = lfs->lfs_next;
			else
				prev->lfs_next = lfs->lfs_next;
			if (lfs->lfs_realrootvp != NULL) {
				VN_RELE(lfs->lfs_realrootvp);
			}
			if (lfs->lfs_vfs.vfs_mntpt != NULL)
				refstr_rele(lfs->lfs_vfs.vfs_mntpt);
			if (lfs->lfs_vfs.vfs_implp != NULL) {
				ASSERT(lfs->lfs_vfs.vfs_femhead == NULL);
				ASSERT(lfs->lfs_vfs.vfs_vskap == NULL);
				ASSERT(lfs->lfs_vfs.vfs_fstypevsp == NULL);
				kmem_free(lfs->lfs_vfs.vfs_implp,
				    sizeof (vfs_impl_t));
			}
			sema_destroy(&lfs->lfs_vfs.vfs_reflock);
			kmem_free(lfs, sizeof (struct lfsnode));
			return;
		}
		prev = this;
	}
	panic("freelfsnode");
	/*NOTREACHED*/
}

/*
 * Find lfs given real vfs and mount instance(li)
 */
static struct lfsnode *
lfsfind(struct vfs *vfsp, struct loinfo *li)
{
	struct lfsnode *lfs;

	ASSERT(MUTEX_HELD(&li->li_lfslock));

	/*
	 * We need to handle the case where a UFS filesystem was forced
	 * unmounted and then a subsequent mount got the same vfs
	 * structure.  If the new mount lies in the lofs hierarchy, then
	 * this will confuse lofs, because the original vfsp (of the
	 * forced unmounted filesystem) is still around. We check for
	 * this condition here.
	 *
	 * If we find a cache vfsp hit, then we check to see if the
	 * cached filesystem was forced unmounted. Skip all such
	 * entries. This should be safe to do since no
	 * makelonode()->makelfsnode()->lfsfind() calls should be
	 * generated for such force-unmounted filesystems (because (ufs)
	 * lookup would've returned an error).
	 */
	for (lfs = li->li_lfs; lfs != NULL; lfs = lfs->lfs_next) {
		if (lfs->lfs_realvfs == vfsp) {
			struct vnode *realvp;

			realvp = lfs->lfs_realrootvp;
			if (realvp == NULL)
				continue;
			if (realvp->v_vfsp == NULL || realvp->v_type == VBAD)
				continue;
			return (lfs);
		}
	}
	return (NULL);
}

/*
 * Find real vfs given loopback vfs
 */
struct vfs *
lo_realvfs(struct vfs *vfsp, struct vnode **realrootvpp)
{
	struct loinfo *li = vtoli(vfsp);
	struct lfsnode *lfs;

	ASSERT(li->li_refct > 0);
	if (vfsp == li->li_mountvfs) {
		if (realrootvpp != NULL)
			*realrootvpp = vtol(li->li_rootvp)->lo_vp;
		return (li->li_realvfs);
	}
	mutex_enter(&li->li_lfslock);
	for (lfs = li->li_lfs; lfs != NULL; lfs = lfs->lfs_next) {
		if (vfsp == &lfs->lfs_vfs) {
			if (realrootvpp != NULL)
				*realrootvpp = lfs->lfs_realrootvp;
			mutex_exit(&li->li_lfslock);
			return (lfs->lfs_realvfs);
		}
	}
	panic("lo_realvfs");
	/*NOTREACHED*/
}

/*
 * Lnode lookup stuff.
 * These routines maintain a table of lnodes hashed by vp so
 * that the lnode for a vp can be found if it already exists.
 *
 * NB: A lofs shadow vnode causes exactly one VN_HOLD() on the
 * underlying vnode.
 */

/*
 * Retire old hashtables.
 */
static void
lretire(struct loinfo *li, struct lobucket *table, uint_t size)
{
	struct lo_retired_ht *lrhp;

	lrhp = kmem_alloc(sizeof (*lrhp), KM_SLEEP);
	lrhp->lrh_table = table;
	lrhp->lrh_size = size;

	mutex_enter(&li->li_htlock);
	lrhp->lrh_next = li->li_retired;
	li->li_retired = lrhp;
	mutex_exit(&li->li_htlock);
}

/*
 * Grow the hashtable.
 */
static void
lgrow(struct loinfo *li, uint_t newsize)
{
	uint_t oldsize;
	uint_t i;
	struct lobucket *oldtable, *newtable;

	/*
	 * It's OK to not have enough memory to resize the hashtable.
	 * We'll go down this path the next time we add something to the
	 * table, and retry the allocation then.
	 */
	if ((newtable = kmem_zalloc(newsize * sizeof (*li->li_hashtable),
	    KM_NOSLEEP)) == NULL)
		return;

	mutex_enter(&li->li_htlock);
	if (newsize <= li->li_htsize) {
		mutex_exit(&li->li_htlock);
		kmem_free(newtable, newsize * sizeof (*li->li_hashtable));
		return;
	}
	oldsize = li->li_htsize;
	oldtable = li->li_hashtable;

	/*
	 * Grab all locks so TABLE_LOCK_ENTER() calls block until the
	 * resize is complete.
	 */
	for (i = 0; i < oldsize; i++)
		mutex_enter(&oldtable[i].lh_lock);
	/*
	 * li->li_hashtable gets set before li->li_htsize, so in the
	 * time between the two assignments, callers of
	 * TABLE_LOCK_ENTER() cannot hash to a bucket beyond oldsize,
	 * hence we only need to grab the locks up to oldsize.
	 */
	for (i = 0; i < oldsize; i++)
		mutex_enter(&newtable[i].lh_lock);
	/*
	 * Rehash.
	 */
	for (i = 0; i < oldsize; i++) {
		lnode_t *tlp, *nlp;

		for (tlp = oldtable[i].lh_chain; tlp != NULL; tlp = nlp) {
			uint_t hash = ltablehash(tlp->lo_vp, newsize);

			nlp = tlp->lo_next;
			tlp->lo_next = newtable[hash].lh_chain;
			newtable[hash].lh_chain = tlp;
			newtable[hash].lh_count++;
		}
	}

	/*
	 * As soon as we store the new hashtable, future locking operations
	 * will use it.  Therefore, we must ensure that all the state we've
	 * just established reaches global visibility before the new hashtable
	 * does.
	 */
	membar_producer();
	li->li_hashtable = newtable;

	/*
	 * table_lock_enter() relies on the fact that li->li_hashtable
	 * is set to its new value before li->li_htsize.
	 */
	membar_producer();
	li->li_htsize = newsize;

	/*
	 * The new state is consistent now, so we can drop all the locks.
	 */
	for (i = 0; i < oldsize; i++) {
		mutex_exit(&newtable[i].lh_lock);
		mutex_exit(&oldtable[i].lh_lock);
	}
	mutex_exit(&li->li_htlock);

	lretire(li, oldtable, oldsize);
}

/*
 * Put a lnode in the table
 */
static void
lsave(lnode_t *lp, struct loinfo *li)
{
	ASSERT(lp->lo_vp);
	ASSERT(MUTEX_HELD(TABLE_LOCK(lp->lo_vp, li)));

#ifdef LODEBUG
	lo_dprint(4, "lsave lp %p hash %d\n",
	    lp, ltablehash(lp->lo_vp, li));
#endif

	TABLE_COUNT(lp->lo_vp, li)++;
	lp->lo_next = TABLE_BUCKET(lp->lo_vp, li);
	TABLE_BUCKET(lp->lo_vp, li) = lp;

	if (li->li_refct > (li->li_htsize << lo_resize_threshold)) {
		TABLE_LOCK_EXIT(lp->lo_vp, li);
		lgrow(li, li->li_htsize << lo_resize_factor);
		TABLE_LOCK_ENTER(lp->lo_vp, li);
	}
}

/*
 * Our version of vfs_rele() that stops at 1 instead of 0, and calls
 * freelfsnode() instead of kmem_free().
 */
static void
lfs_rele(struct lfsnode *lfs, struct loinfo *li)
{
	vfs_t *vfsp = &lfs->lfs_vfs;

	ASSERT(MUTEX_HELD(&li->li_lfslock));
	ASSERT(vfsp->vfs_count > 1);
	if (atomic_dec_32_nv(&vfsp->vfs_count) == 1)
		freelfsnode(lfs, li);
}

/*
 * Remove a lnode from the table
 */
void
freelonode(lnode_t *lp)
{
	lnode_t *lt;
	lnode_t *ltprev = NULL;
	struct lfsnode *lfs, *nextlfs;
	struct vfs *vfsp;
	struct vnode *vp = ltov(lp);
	struct vnode *realvp = realvp(vp);
	struct loinfo *li = vtoli(vp->v_vfsp);

#ifdef LODEBUG
	lo_dprint(4, "freelonode lp %p hash %d\n",
	    lp, ltablehash(lp->lo_vp, li));
#endif
	TABLE_LOCK_ENTER(lp->lo_vp, li);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		VN_RELE_LOCKED(vp);
		mutex_exit(&vp->v_lock);
		TABLE_LOCK_EXIT(lp->lo_vp, li);
		return;
	}
	mutex_exit(&vp->v_lock);

	for (lt = TABLE_BUCKET(lp->lo_vp, li); lt != NULL;
	    ltprev = lt, lt = lt->lo_next) {
		if (lt == lp) {
#ifdef LODEBUG
			lo_dprint(4, "freeing %p, vfsp %p\n",
			    vp, vp->v_vfsp);
#endif
			atomic_dec_32(&li->li_refct);
			vfsp = vp->v_vfsp;
			vn_invalid(vp);
			if (vfsp != li->li_mountvfs) {
				mutex_enter(&li->li_lfslock);
				/*
				 * Check for unused lfs
				 */
				lfs = li->li_lfs;
				while (lfs != NULL) {
					nextlfs = lfs->lfs_next;
					if (vfsp == &lfs->lfs_vfs) {
						lfs_rele(lfs, li);
						break;
					}
					if (lfs->lfs_vfs.vfs_count == 1) {
						/*
						 * Lfs is idle
						 */
						freelfsnode(lfs, li);
					}
					lfs = nextlfs;
				}
				mutex_exit(&li->li_lfslock);
			}
			if (ltprev == NULL) {
				TABLE_BUCKET(lt->lo_vp, li) = lt->lo_next;
			} else {
				ltprev->lo_next = lt->lo_next;
			}
			TABLE_COUNT(lt->lo_vp, li)--;
			TABLE_LOCK_EXIT(lt->lo_vp, li);
			kmem_cache_free(lnode_cache, lt);
			vn_free(vp);
			VN_RELE(realvp);
			return;
		}
	}
	panic("freelonode");
	/*NOTREACHED*/
}

/*
 * Lookup a lnode by vp
 */
static lnode_t *
lfind(struct vnode *vp, struct loinfo *li)
{
	lnode_t *lt;

	ASSERT(MUTEX_HELD(TABLE_LOCK(vp, li)));

	lt = TABLE_BUCKET(vp, li);
	while (lt != NULL) {
		if (lt->lo_vp == vp) {
			VN_HOLD(ltov(lt));
			return (lt);
		}
		lt = lt->lo_next;
	}
	return (NULL);
}

#ifdef	LODEBUG
static int lofsdebug;
#endif	/* LODEBUG */

/*
 * Utilities used by both client and server
 * Standard levels:
 * 0) no debugging
 * 1) hard failures
 * 2) soft failures
 * 3) current test software
 * 4) main procedure entry points
 * 5) main procedure exit points
 * 6) utility procedure entry points
 * 7) utility procedure exit points
 * 8) obscure procedure entry points
 * 9) obscure procedure exit points
 * 10) random stuff
 * 11) all <= 1
 * 12) all <= 2
 * 13) all <= 3
 * ...
 */

#ifdef LODEBUG
/*VARARGS2*/
lo_dprint(int level, char *str, int a1, int a2, int a3, int a4, int a5, int a6,
    int a7, int a8, int a9)
{

	if (lofsdebug == level || (lofsdebug > 10 && (lofsdebug - 10) >= level))
		printf(str, a1, a2, a3, a4, a5, a6, a7, a8, a9);
}
#endif
