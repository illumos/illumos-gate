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
 *
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Node hash implementation borrowed from NFS.
 * See: uts/common/fs/nfs/nfs_subr.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/bitmap.h>
#include <sys/dnlc.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#include <sys/utfconv.h>
#include <sys/smb_iconv.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_rq.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

/*
 * The hash queues for the access to active and cached smbnodes
 * are organized as doubly linked lists.  A reader/writer lock
 * for each hash bucket is used to control access and to synchronize
 * lookups, additions, and deletions from the hash queue.
 *
 * The smbnode freelist is organized as a doubly linked list with
 * a head pointer.  Additions and deletions are synchronized via
 * a single mutex.
 *
 * In order to add an smbnode to the free list, it must be hashed into
 * a hash queue and the exclusive lock to the hash queue be held.
 * If an smbnode is not hashed into a hash queue, then it is destroyed
 * because it represents no valuable information that can be reused
 * about the file.  The exclusive lock to the hash queue must be
 * held in order to prevent a lookup in the hash queue from finding
 * the smbnode and using it and assuming that the smbnode is not on the
 * freelist.  The lookup in the hash queue will have the hash queue
 * locked, either exclusive or shared.
 *
 * The vnode reference count for each smbnode is not allowed to drop
 * below 1.  This prevents external entities, such as the VM
 * subsystem, from acquiring references to vnodes already on the
 * freelist and then trying to place them back on the freelist
 * when their reference is released.  This means that the when an
 * smbnode is looked up in the hash queues, then either the smbnode
 * is removed from the freelist and that reference is tranfered to
 * the new reference or the vnode reference count must be incremented
 * accordingly.  The mutex for the freelist must be held in order to
 * accurately test to see if the smbnode is on the freelist or not.
 * The hash queue lock might be held shared and it is possible that
 * two different threads may race to remove the smbnode from the
 * freelist.  This race can be resolved by holding the mutex for the
 * freelist.  Please note that the mutex for the freelist does not
 * need to held if the smbnode is not on the freelist.  It can not be
 * placed on the freelist due to the requirement that the thread
 * putting the smbnode on the freelist must hold the exclusive lock
 * to the hash queue and the thread doing the lookup in the hash
 * queue is holding either a shared or exclusive lock to the hash
 * queue.
 *
 * The lock ordering is:
 *
 *	hash bucket lock -> vnode lock
 *	hash bucket lock -> freelist lock
 */
static rhashq_t *smbtable;

static kmutex_t smbfreelist_lock;
static smbnode_t *smbfreelist = NULL;
static ulong_t	smbnodenew = 0;
long	nsmbnode = 0;

static int smbtablesize;
static int smbtablemask;
static int smbhashlen = 4;

static struct kmem_cache *smbnode_cache;

/*
 * Mutex to protect the following variables:
 *	smbfs_major
 *	smbfs_minor
 */
kmutex_t smbfs_minor_lock;
int smbfs_major;
int smbfs_minor;

/*
 * Local functions.
 * Not static, to aid debugging.
 */
void smb_rmfree(smbnode_t *);
void smbinactive(smbnode_t *);
void smb_rmhash_locked(smbnode_t *);
void smb_destroy_node(smbnode_t *);
void smbfs_kmem_reclaim(void *cdrarg);

smbnode_t *smbhashfind(struct vfs *, const char *, int, rhashq_t *);
static vnode_t *make_smbnode(vfs_t *, char *, int, rhashq_t *, int *);


/*
 * Free the resources associated with an smbnode.
 * Note: This is different from smbfs_inactive
 *
 * NFS: nfs_subr.c:rinactive
 */
void
smbinactive(smbnode_t *np)
{

	if (np->n_rpath) {
		kmem_free(np->n_rpath, np->n_rplen + 1);
		np->n_rpath = NULL;
	}
}

/*
 * Return a vnode for the given CIFS directory and filename.
 * If no smbnode exists for this fhandle, create one and put it
 * into the hash queues.  If the smbnode for this fhandle
 * already exists, return it.
 *
 * Note: make_smbnode() may upgrade the hash bucket lock to exclusive.
 *
 * NFS: nfs_subr.c:makenfsnode
 */
vnode_t *
smbfs_make_node(
	vfs_t *vfsp,
	const char *dir,
	int dirlen,
	const char *name,
	int nmlen,
	char sep,
	struct smbfattr *fap)
{
	char *rpath;
	int rplen, idx;
	uint32_t hash;
	rhashq_t *rhtp;
	smbnode_t *np;
	vnode_t *vp;
#ifdef NOT_YET
	vattr_t va;
#endif
	int newnode;

	/*
	 * Build the full path name in allocated memory
	 * so we have it for lookup, etc.  Note the
	 * special case at the root (dir=="\\", dirlen==1)
	 * where this does not add a slash separator.
	 * To do that would make a double slash, which
	 * has special meaning in CIFS.
	 *
	 * ToDo:  Would prefer to allocate a remote path
	 * only when we will create a new node.
	 */
	if (dirlen <= 1 && sep == '\\')
		sep = '\0';	/* no slash */

	/* Compute the length of rpath and allocate. */
	rplen = dirlen;
	if (sep)
		rplen++;
	if (name)
		rplen += nmlen;

	rpath = kmem_alloc(rplen + 1, KM_SLEEP);

	/* Fill in rpath */
	bcopy(dir, rpath, dirlen);
	if (sep)
		rpath[dirlen++] = sep;
	if (name)
		bcopy(name, &rpath[dirlen], nmlen);
	rpath[rplen] = 0;

	hash = smbfs_hash(rpath, rplen);
	idx = hash & smbtablemask;
	rhtp = &smbtable[idx];
	rw_enter(&rhtp->r_lock, RW_READER);

	vp = make_smbnode(vfsp, rpath, rplen, rhtp, &newnode);
	np = VTOSMB(vp);
	np->n_ino = hash;	/* Equivalent to: smbfs_getino() */

	/*
	 * Note: make_smbnode keeps a reference to rpath in
	 * new nodes it creates, so only free when we found
	 * an existing node.
	 */
	if (!newnode) {
		kmem_free(rpath, rplen + 1);
		rpath = NULL;
	}

	if (fap == NULL) {
#ifdef NOT_YET
		if (newnode) {
			PURGE_ATTRCACHE(vp);
		}
#endif
		rw_exit(&rhtp->r_lock);
		return (vp);
	}

	/* Have SMB attributes. */
	vp->v_type = (fap->fa_attr & SMB_FA_DIR) ? VDIR : VREG;
	/* XXX: np->n_ino = fap->fa_ino; see above */
	np->r_size = fap->fa_size;
	/* XXX: np->r_attr = *fap here instead? */
	np->r_atime = fap->fa_atime;
	np->r_ctime = fap->fa_mtime;
	np->r_mtime = fap->fa_ctime;

#ifdef NOT_YET
	if (!newnode) {
		rw_exit(&rhtp->r_lock);
		(void) nfs_cache_fattr(vp, attr, &va, t, cr);
	} else {
		if (attr->na_type < NFNON || attr->na_type > NFSOC)
			vp->v_type = VBAD;
		else
			vp->v_type = n2v_type(attr);
		vp->v_rdev = makedevice(attr->rdev.specdata1,
		    attr->rdev.specdata2);
		nfs_attrcache(vp, attr, t);
		rw_exit(&rhtp->r_lock);
	}
#else
	rw_exit(&rhtp->r_lock);
#endif

	return (vp);
}

/*
 * NFS: nfs_subr.c:rtablehash
 * We use smbfs_hash().
 */

/*
 * Find or create an smbnode.
 * NFS: nfs_subr.c:make_rnode
 */
static vnode_t *
make_smbnode(
	vfs_t *vfsp,
	char *rpath,
	int rplen,
	rhashq_t *rhtp,
	int *newnode)
{
	smbnode_t *np;
	smbnode_t *tnp;
	vnode_t *vp;
	smbmntinfo_t *mi;

	ASSERT(RW_READ_HELD(&rhtp->r_lock));

	mi = VFTOSMI(vfsp);

start:
	np = smbhashfind(vfsp, rpath, rplen, rhtp);
	if (np != NULL) {
		vp = SMBTOV(np);
		*newnode = 0;
		return (vp);
	}

	/* Note: will retake this lock below. */
	rw_exit(&rhtp->r_lock);

	/*
	 * see if we can find something on the freelist
	 */
	mutex_enter(&smbfreelist_lock);
	if (smbfreelist != NULL && smbnodenew >= nsmbnode) {
		np = smbfreelist;
		smb_rmfree(np);
		mutex_exit(&smbfreelist_lock);

		vp = SMBTOV(np);

		if (np->r_flags & RHASHED) {
			rw_enter(&np->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				vp->v_count--;
				mutex_exit(&vp->v_lock);
				rw_exit(&np->r_hashq->r_lock);
				rw_enter(&rhtp->r_lock, RW_READER);
				goto start;
			}
			mutex_exit(&vp->v_lock);
			smb_rmhash_locked(np);
			rw_exit(&np->r_hashq->r_lock);
		}

		smbinactive(np);

		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			vp->v_count--;
			mutex_exit(&vp->v_lock);
			rw_enter(&rhtp->r_lock, RW_READER);
			goto start;
		}
		mutex_exit(&vp->v_lock);
		vn_invalid(vp);
		/*
		 * destroy old locks before bzero'ing and
		 * recreating the locks below.
		 */
		smbfs_rw_destroy(&np->r_rwlock);
		smbfs_rw_destroy(&np->r_lkserlock);
		mutex_destroy(&np->r_statelock);
		cv_destroy(&np->r_cv);
		/*
		 * Make sure that if smbnode is recycled then
		 * VFS count is decremented properly before
		 * reuse.
		 */
		VFS_RELE(vp->v_vfsp);
		vn_reinit(vp);
	} else {
		/*
		 * allocate and initialize a new smbnode
		 */
		vnode_t *new_vp;

		mutex_exit(&smbfreelist_lock);

		np = kmem_cache_alloc(smbnode_cache, KM_SLEEP);
		new_vp = vn_alloc(KM_SLEEP);

		atomic_add_long((ulong_t *)&smbnodenew, 1);
		vp = new_vp;
	}

	/* Initialize smbnode_t */
	bzero(np, sizeof (*np));

	smbfs_rw_init(&np->r_rwlock, NULL, RW_DEFAULT, NULL);
	smbfs_rw_init(&np->r_lkserlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&np->r_statelock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&np->r_cv, NULL, CV_DEFAULT, NULL);
	/* cv_init(&np->r_commit.c_cv, NULL, CV_DEFAULT, NULL); */

	np->r_vnode = vp;
	np->n_mount = mi;
	np->r_hashq = rhtp;
	np->n_direof = -1;
	np->n_fid = SMB_FID_UNUSED;
	np->n_uid = UID_NOBODY;
	np->n_gid = GID_NOBODY;
	/* XXX: make attributes stale? */

#if 0 /* XXX dircache */
	/*
	 * We don't know if it's a directory yet.
	 * Let the caller do this?  XXX
	 */
	avl_create(&np->r_dir, compar, sizeof (rddir_cache),
	    offsetof(rddir_cache, tree));
#endif

	/* Now fill in the vnode. */
	vn_setops(vp, smbfs_vnodeops);
	vp->v_data = (caddr_t)np;
	VFS_HOLD(vfsp);
	vp->v_vfsp = vfsp;
	vp->v_type = VNON;

	/*
	 * There is a race condition if someone else
	 * alloc's the smbnode while no locks are held, so we
	 * check again and recover if found.
	 */
	rw_enter(&rhtp->r_lock, RW_WRITER);
	tnp = smbhashfind(vfsp, rpath, rplen, rhtp);
	if (tnp != NULL) {
		vp = SMBTOV(tnp);
		*newnode = 0;
		rw_exit(&rhtp->r_lock);
		/* The node we were building goes on the free list. */
		smb_addfree(np);
		rw_enter(&rhtp->r_lock, RW_READER);
		return (vp);
	}

	/*
	 * Hash search identifies nodes by the full pathname,
	 * so store that before linking in the hash list.
	 * Note: caller allocates the rpath, and knows
	 * about this reference when *newnode is set.
	 */
	np->n_rpath = rpath;
	np->n_rplen = rplen;

	smb_addhash(np);
	*newnode = 1;
	return (vp);
}

/*
 * smb_addfree
 * Put a smbnode on the free list.
 *
 * Normally called by smbfs_inactive, but also
 * called in here during cleanup operations.
 *
 * Smbnodes which were allocated above and beyond the normal limit
 * are immediately freed.
 *
 * NFS: nfs_subr.c:rp_addfree
 */
void
smb_addfree(smbnode_t *np)
{
	vnode_t *vp;
	struct vfs *vfsp;

	vp = SMBTOV(np);
	ASSERT(vp->v_count >= 1);
	ASSERT(np->r_freef == NULL && np->r_freeb == NULL);

	/*
	 * If we have too many smbnodes allocated and there are no
	 * references to this smbnode, or if the smbnode is no longer
	 * accessible by it does not reside in the hash queues,
	 * or if an i/o error occurred while writing to the file,
	 * then just free it instead of putting it on the smbnode
	 * freelist.
	 */
	vfsp = vp->v_vfsp;
	if (((smbnodenew > nsmbnode || !(np->r_flags & RHASHED) ||
	    np->r_error || (vfsp->vfs_flag & VFS_UNMOUNTED)) &&
	    np->r_count == 0)) {
		if (np->r_flags & RHASHED) {
			rw_enter(&np->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				vp->v_count--;
				mutex_exit(&vp->v_lock);
				rw_exit(&np->r_hashq->r_lock);
				return;
				/*
				 * Will get another call later,
				 * via smbfs_inactive.
				 */
			}
			mutex_exit(&vp->v_lock);
			smb_rmhash_locked(np);
			rw_exit(&np->r_hashq->r_lock);
		}

		smbinactive(np);

		/*
		 * Recheck the vnode reference count.  We need to
		 * make sure that another reference has not been
		 * acquired while we were not holding v_lock.  The
		 * smbnode is not in the smbnode hash queues, so the
		 * only way for a reference to have been acquired
		 * is for a VOP_PUTPAGE because the smbnode was marked
		 * with RDIRTY or for a modified page.  This
		 * reference may have been acquired before our call
		 * to smbinactive.  The i/o may have been completed,
		 * thus allowing smbinactive to complete, but the
		 * reference to the vnode may not have been released
		 * yet.  In any case, the smbnode can not be destroyed
		 * until the other references to this vnode have been
		 * released.  The other references will take care of
		 * either destroying the smbnode or placing it on the
		 * smbnode freelist.  If there are no other references,
		 * then the smbnode may be safely destroyed.
		 */
		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			vp->v_count--;
			mutex_exit(&vp->v_lock);
			return;
		}
		mutex_exit(&vp->v_lock);

		smb_destroy_node(np);
		return;
	}
	/*
	 * Lock the hash queue and then recheck the reference count
	 * to ensure that no other threads have acquired a reference
	 * to indicate that the smbnode should not be placed on the
	 * freelist.  If another reference has been acquired, then
	 * just release this one and let the other thread complete
	 * the processing of adding this smbnode to the freelist.
	 */
	rw_enter(&np->r_hashq->r_lock, RW_WRITER);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		rw_exit(&np->r_hashq->r_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	/*
	 * If there is no cached data or metadata for this file, then
	 * put the smbnode on the front of the freelist so that it will
	 * be reused before other smbnodes which may have cached data or
	 * metadata associated with them.
	 */
	mutex_enter(&smbfreelist_lock);
	if (smbfreelist == NULL) {
		np->r_freef = np;
		np->r_freeb = np;
		smbfreelist = np;
	} else {
		np->r_freef = smbfreelist;
		np->r_freeb = smbfreelist->r_freeb;
		smbfreelist->r_freeb->r_freef = np;
		smbfreelist->r_freeb = np;
	}
	mutex_exit(&smbfreelist_lock);

	rw_exit(&np->r_hashq->r_lock);
}

/*
 * Remove an smbnode from the free list.
 *
 * The caller must be holding smbfreelist_lock and the smbnode
 * must be on the freelist.
 *
 * NFS: nfs_subr.c:rp_rmfree
 */
void
smb_rmfree(smbnode_t *np)
{

	ASSERT(MUTEX_HELD(&smbfreelist_lock));
	ASSERT(np->r_freef != NULL && np->r_freeb != NULL);

	if (np == smbfreelist) {
		smbfreelist = np->r_freef;
		if (np == smbfreelist)
			smbfreelist = NULL;
	}

	np->r_freeb->r_freef = np->r_freef;
	np->r_freef->r_freeb = np->r_freeb;

	np->r_freef = np->r_freeb = NULL;
}

/*
 * Put a smbnode in the hash table.
 *
 * The caller must be holding the exclusive hash queue lock.
 *
 * NFS: nfs_subr.c:rp_addhash
 */
void
smb_addhash(smbnode_t *np)
{

	ASSERT(RW_WRITE_HELD(&np->r_hashq->r_lock));
	ASSERT(!(np->r_flags & RHASHED));

	np->r_hashf = np->r_hashq->r_hashf;
	np->r_hashq->r_hashf = np;
	np->r_hashb = (smbnode_t *)np->r_hashq;
	np->r_hashf->r_hashb = np;

	mutex_enter(&np->r_statelock);
	np->r_flags |= RHASHED;
	mutex_exit(&np->r_statelock);
}

/*
 * Remove a smbnode from the hash table.
 *
 * The caller must be holding the hash queue lock.
 *
 * NFS: nfs_subr.c:rp_rmhash_locked
 */
void
smb_rmhash_locked(smbnode_t *np)
{

	ASSERT(RW_WRITE_HELD(&np->r_hashq->r_lock));
	ASSERT(np->r_flags & RHASHED);

	np->r_hashb->r_hashf = np->r_hashf;
	np->r_hashf->r_hashb = np->r_hashb;

	mutex_enter(&np->r_statelock);
	np->r_flags &= ~RHASHED;
	mutex_exit(&np->r_statelock);
}

/*
 * Remove a smbnode from the hash table.
 *
 * The caller must not be holding the hash queue lock.
 */
void
smb_rmhash(smbnode_t *np)
{

	rw_enter(&np->r_hashq->r_lock, RW_WRITER);
	smb_rmhash_locked(np);
	rw_exit(&np->r_hashq->r_lock);
}

/*
 * Lookup a smbnode by fhandle.
 *
 * The caller must be holding the hash queue lock, either shared or exclusive.
 * XXX: make static?
 *
 * NFS: nfs_subr.c:rfind
 */
smbnode_t *
smbhashfind(
	struct vfs *vfsp,
	const char *rpath,
	int rplen,
	rhashq_t *rhtp)
{
	smbnode_t *np;
	vnode_t *vp;

	ASSERT(RW_LOCK_HELD(&rhtp->r_lock));

	for (np = rhtp->r_hashf; np != (smbnode_t *)rhtp; np = np->r_hashf) {
		vp = SMBTOV(np);
		if (vp->v_vfsp == vfsp &&
		    np->n_rplen == rplen &&
		    bcmp(np->n_rpath, rpath, rplen) == 0) {
			/*
			 * remove smbnode from free list, if necessary.
			 */
			if (np->r_freef != NULL) {
				mutex_enter(&smbfreelist_lock);
				/*
				 * If the smbnode is on the freelist,
				 * then remove it and use that reference
				 * as the new reference.  Otherwise,
				 * need to increment the reference count.
				 */
				if (np->r_freef != NULL) {
					smb_rmfree(np);
					mutex_exit(&smbfreelist_lock);
				} else {
					mutex_exit(&smbfreelist_lock);
					VN_HOLD(vp);
				}
			} else
				VN_HOLD(vp);
			return (np);
		}
	}
	return (NULL);
}

#ifdef SMB_VNODE_DEBUG
int smb_check_table_debug = 1;
#else /* SMB_VNODE_DEBUG */
int smb_check_table_debug = 0;
#endif /* SMB_VNODE_DEBUG */


/*
 * Return 1 if there is a active vnode belonging to this vfs in the
 * smbtable cache.
 *
 * Several of these checks are done without holding the usual
 * locks.  This is safe because destroy_smbtable(), smb_addfree(),
 * etc. will redo the necessary checks before actually destroying
 * any smbnodes.
 *
 * NFS: nfs_subr.c:check_rtable
 *
 * Debugging changes here relative to NFS.
 * Relatively harmless, so left 'em in.
 */
int
smb_check_table(struct vfs *vfsp, smbnode_t *rtnp)
{
	smbnode_t *np;
	vnode_t *vp;
	int index;
	int busycnt = 0;

	for (index = 0; index < smbtablesize; index++) {
		rw_enter(&smbtable[index].r_lock, RW_READER);
		for (np = smbtable[index].r_hashf;
		    np != (smbnode_t *)(&smbtable[index]);
		    np = np->r_hashf) {
			if (np == rtnp)
				continue; /* skip the root */
			vp = SMBTOV(np);
			if (vp->v_vfsp != vfsp)
				continue; /* skip other mount */

			/* Now the 'busy' checks: */
			/* Not on the free list? */
			if (np->r_freef == NULL) {
				SMBVDEBUG("!r_freef: node=0x%p, v_path=%s\n",
				    (void *)np, vp->v_path);
				busycnt++;
			}

			/* Has dirty pages? */
			if (vn_has_cached_data(vp) &&
			    (np->r_flags & RDIRTY)) {
				SMBVDEBUG("is dirty: node=0x%p, v_path=%s\n",
				    (void *)np, vp->v_path);
				busycnt++;
			}

			/* Other refs? (not reflected in v_count) */
			if (np->r_count > 0) {
				SMBVDEBUG("+r_count: node=0x%p, v_path=%s\n",
				    (void *)np, vp->v_path);
				busycnt++;
			}

			if (busycnt && !smb_check_table_debug)
				break;

		}
		rw_exit(&smbtable[index].r_lock);
	}
	return (busycnt);
}

/*
 * Destroy inactive vnodes from the hash queues which belong to this
 * vfs.  It is essential that we destroy all inactive vnodes during a
 * forced unmount as well as during a normal unmount.
 *
 * NFS: nfs_subr.c:destroy_rtable
 */
void
smbfs_destroy_table(struct vfs *vfsp)
{
	int index;
	smbnode_t *np;
	smbnode_t *rlist;
	smbnode_t *r_hashf;
	vnode_t *vp;

	rlist = NULL;

	for (index = 0; index < smbtablesize; index++) {
		rw_enter(&smbtable[index].r_lock, RW_WRITER);
		for (np = smbtable[index].r_hashf;
		    np != (smbnode_t *)(&smbtable[index]);
		    np = r_hashf) {
			/* save the hash pointer before destroying */
			r_hashf = np->r_hashf;
			vp = SMBTOV(np);
			if (vp->v_vfsp == vfsp) {
				mutex_enter(&smbfreelist_lock);
				if (np->r_freef != NULL) {
					smb_rmfree(np);
					mutex_exit(&smbfreelist_lock);
					smb_rmhash_locked(np);
					np->r_hashf = rlist;
					rlist = np;
				} else
					mutex_exit(&smbfreelist_lock);
			}
		}
		rw_exit(&smbtable[index].r_lock);
	}

	for (np = rlist; np != NULL; np = rlist) {
		rlist = np->r_hashf;
		/*
		 * This call to smb_addfree will end up destroying the
		 * smbnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		smb_addfree(np);
	}

}

/*
 * This routine destroys all the resources associated with the smbnode
 * and then the smbnode itself.
 *
 * NFS: nfs_subr.c:destroy_rnode
 */
void
smb_destroy_node(smbnode_t *np)
{
	vnode_t *vp;
	vfs_t *vfsp;

	vp = SMBTOV(np);
	vfsp = vp->v_vfsp;

	ASSERT(vp->v_count == 1);
	ASSERT(np->r_count == 0);
	ASSERT(np->r_mapcnt == 0);
	ASSERT(!(np->r_flags & RHASHED));
	ASSERT(np->r_freef == NULL && np->r_freeb == NULL);
	atomic_add_long((ulong_t *)&smbnodenew, -1);
	vn_invalid(vp);
	vn_free(vp);
	kmem_cache_free(smbnode_cache, np);
	VFS_RELE(vfsp);
}

/* rflush? */
/* access cache */
/* client handles */

/*
 * initialize resources that are used by smbfs_subr.c
 * this is called from the _init() routine (by the way of smbfs_clntinit())
 *
 * allocate and initialze smbfs hash table
 * NFS: nfs_subr.c:nfs_subrinit
 */
int
smbfs_subrinit(void)
{
	int i;
	ulong_t nsmbnode_max;

	/*
	 * Allocate and initialize the smbnode hash queues
	 */
	if (nsmbnode <= 0)
		nsmbnode = ncsize; /* dnlc.h */
	nsmbnode_max = (ulong_t)((kmem_maxavail() >> 2) /
	    sizeof (struct smbnode));
	if (nsmbnode > nsmbnode_max || (nsmbnode == 0 && ncsize == 0)) {
		zcmn_err(GLOBAL_ZONEID, CE_NOTE,
		    "setting nsmbnode to max value of %ld", nsmbnode_max);
		nsmbnode = nsmbnode_max;
	}

	smbtablesize = 1 << highbit(nsmbnode / smbhashlen);
	smbtablemask = smbtablesize - 1;
	smbtable = kmem_alloc(smbtablesize * sizeof (*smbtable), KM_SLEEP);
	for (i = 0; i < smbtablesize; i++) {
		smbtable[i].r_hashf = (smbnode_t *)(&smbtable[i]);
		smbtable[i].r_hashb = (smbnode_t *)(&smbtable[i]);
		rw_init(&smbtable[i].r_lock, NULL, RW_DEFAULT, NULL);
	}
	smbnode_cache = kmem_cache_create("smbnode_cache", sizeof (smbnode_t),
	    0, NULL, NULL, smbfs_kmem_reclaim, NULL, NULL, 0);

	/*
	 * Initialize the various mutexes and reader/writer locks
	 */
	mutex_init(&smbfreelist_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&smbfs_minor_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Assign unique major number for all smbfs mounts
	 */
	if ((smbfs_major = getudev()) == -1) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "smbfs: init: can't get unique device number");
		smbfs_major = 0;
	}
	smbfs_minor = 0;

	return (0);
}

/*
 * free smbfs hash table, etc.
 * NFS: nfs_subr.c:nfs_subrfini
 */
void
smbfs_subrfini(void)
{
	int i;

	/*
	 * Deallocate the smbnode hash queues
	 */
	kmem_cache_destroy(smbnode_cache);

	for (i = 0; i < smbtablesize; i++)
		rw_destroy(&smbtable[i].r_lock);
	kmem_free(smbtable, smbtablesize * sizeof (*smbtable));

	/*
	 * Destroy the various mutexes and reader/writer locks
	 */
	mutex_destroy(&smbfreelist_lock);
	mutex_destroy(&smbfs_minor_lock);
}

/* rddir_cache ? */

/*
 * Support functions for smbfs_kmem_reclaim
 */

static int
smbfs_node_reclaim(void)
{
	int freed;
	smbnode_t *np;
	vnode_t *vp;

	freed = 0;
	mutex_enter(&smbfreelist_lock);
	while ((np = smbfreelist) != NULL) {
		smb_rmfree(np);
		mutex_exit(&smbfreelist_lock);
		if (np->r_flags & RHASHED) {
			vp = SMBTOV(np);
			rw_enter(&np->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				vp->v_count--;
				mutex_exit(&vp->v_lock);
				rw_exit(&np->r_hashq->r_lock);
				mutex_enter(&smbfreelist_lock);
				continue;
			}
			mutex_exit(&vp->v_lock);
			smb_rmhash_locked(np);
			rw_exit(&np->r_hashq->r_lock);
		}
		/*
		 * This call to smb_addfree will end up destroying the
		 * smbnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		smb_addfree(np);
		mutex_enter(&smbfreelist_lock);
	}
	mutex_exit(&smbfreelist_lock);
	return (freed);
}

/*
 * Called by kmem_cache_alloc ask us if we could
 * "Please give back some memory!"
 *
 * Todo: dump nodes from the free list?
 */
/*ARGSUSED*/
void
smbfs_kmem_reclaim(void *cdrarg)
{
	(void) smbfs_node_reclaim();
}

/* nfs failover stuff */
/* nfs_rw_xxx - see smbfs_rwlock.c */
