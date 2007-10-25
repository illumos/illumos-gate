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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/callb.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/fs/cachefs_fs.h>

extern time_t time;

/* forward references */
int cachefs_rl_entry_get(cachefscache_t *, uint_t, rl_entry_t **);
void cachefs_garbage_collect_queue(cachefscache_t *cachep);
static time_t cachefs_gc_front_atime(cachefscache_t *cachep);
static void cachefs_garbage_collect(cachefscache_t *cachep);
static void cachefs_packed_pending(cachefscache_t *cachep);


#define	RL_HEAD(cachep, type) \
	(&(cachep->c_rlinfo.rl_items[CACHEFS_RL_INDEX(type)]))

/*
 * This function moves an RL entry from wherever it currently is to
 * the back of the requested list.
 */
void
cachefs_rlent_moveto(cachefscache_t *cachep,
    enum cachefs_rl_type type, uint_t entno, size_t blks)
{
	mutex_enter(&cachep->c_contentslock);
	cachefs_cache_dirty(cachep, 0);
	cachefs_rlent_moveto_nolock(cachep, type, entno, blks);
	mutex_exit(&cachep->c_contentslock);
}

void
cachefs_rlent_moveto_nolock(cachefscache_t *cachep,
    enum cachefs_rl_type type, uint_t entno, size_t blks)
{
	rl_entry_t *rl_ent;
	uint_t prev, next;
	cachefs_rl_listhead_t *lhp;
	enum cachefs_rl_type otype;
	int error;

	ASSERT(entno != 0);
	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	ASSERT(MUTEX_HELD(&cachep->c_contentslock));
	ASSERT((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));

	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error)
		return;
	next = rl_ent->rl_fwd_idx;
	prev = rl_ent->rl_bkwd_idx;
	otype = rl_ent->rl_current;
	ASSERT((CACHEFS_RL_START <= otype) && (otype <= CACHEFS_RL_END));
	rl_ent->rl_current = CACHEFS_RL_NONE;

	if (type == CACHEFS_RL_PACKED_PENDING) {
		/* XXX sam: is this the right place to turn this on? */
		cachep->c_flags |= CACHE_PACKED_PENDING;
	}

	/* remove entry from its previous list */

	lhp = RL_HEAD(cachep, otype);
	if ((lhp->rli_back == 0) || (lhp->rli_front == 0))
		ASSERT((lhp->rli_back == 0) && (lhp->rli_front == 0));

	if (lhp->rli_back == entno)
		lhp->rli_back = next;
	if (lhp->rli_front == entno)
		lhp->rli_front = prev;
	if (prev != 0) {
		error = cachefs_rl_entry_get(cachep, prev, &rl_ent);
		if (error)
			return;
		rl_ent->rl_fwd_idx = next;
	}
	if (next != 0) {
		error = cachefs_rl_entry_get(cachep, next, &rl_ent);
		if (error)
			return;
		rl_ent->rl_bkwd_idx = prev;
	}
	lhp->rli_blkcnt -= blks;
	lhp->rli_itemcnt--;

	/* add entry to its new list */

	lhp = RL_HEAD(cachep, type);
	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error)
		return;
	rl_ent->rl_current = type;
	rl_ent->rl_bkwd_idx = 0;
	rl_ent->rl_fwd_idx = lhp->rli_back;

	if (lhp->rli_back != 0) {
		ASSERT(lhp->rli_front != 0);
		error = cachefs_rl_entry_get(cachep, lhp->rli_back, &rl_ent);
		if (error)
			return;
		rl_ent->rl_bkwd_idx = entno;
	} else {
		ASSERT(lhp->rli_front == 0);
		lhp->rli_front = entno;
	}
	lhp->rli_back = entno;
	lhp->rli_blkcnt += blks;
	lhp->rli_itemcnt++;
}

/*
 * This function verifies that an rl entry is of the `correct' type.
 * it's used for debugging (only?).
 */

/*ARGSUSED*/
void
cachefs_rlent_verify(cachefscache_t *cachep,
    enum cachefs_rl_type type, uint_t entno)
{
#ifdef CFSDEBUG
	rl_entry_t *rl_ent;
	int error;

	ASSERT((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));

	mutex_enter(&cachep->c_contentslock);

	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (!error && rl_ent->rl_current != type) {
#ifdef CFSRLDEBUG
		printf("cachefs_rldebug: type should be %x\n", type);
		cachefs_rl_debug_show(rl_ent);
		debug_enter("cachefs_rlent_verify");
#else /* CFSRLDEBUG */
		cmn_err(CE_WARN, "rl entry %x type = %x should be %x\n",
		    entno, rl_ent->rl_current, type);
#endif /* CFSRLDEBUG */
	}

	mutex_exit(&cachep->c_contentslock);
#endif /* CFSDEBUG */
}

/*
 * Returns the rl data of the front of the specified resource list.
 * Returns 0 for success, !0 if the list is empty.
 */
int
cachefs_rlent_data(cachefscache_t *cachep, rl_entry_t *valp, uint_t *entnop)
{
	uint_t entno;
	rl_entry_t *rl_ent;
	int error = 0;
	cachefs_rl_listhead_t *lhp;
	enum cachefs_rl_type type;

	ASSERT((cachep->c_flags & CACHE_NOCACHE) == 0);

	if (entnop == NULL)
		entnop = &entno;
	*entnop = 0;

	mutex_enter(&cachep->c_contentslock);

	type = valp->rl_current;
	ASSERT((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));
	lhp = RL_HEAD(cachep, type);
	entno = lhp->rli_front;

	if (*entnop == 0) {
		error = ENOENT;
	} else {
		error = cachefs_rl_entry_get(cachep, *entnop, &rl_ent);
		if (!error)
			*valp = *rl_ent;
	}
	mutex_exit(&cachep->c_contentslock);
	return (error);
}

/*
 * This function plucks a slot from the RL free list and creates an RL entry.
 */
int
cachefs_rl_alloc(struct cachefscache *cachep, rl_entry_t *valp, uint_t *entnop)
{
	int error = 0;
	uint_t entno;
	rl_entry_t *rl_ent;
	cachefs_rl_listhead_t *lhp;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	mutex_enter(&cachep->c_contentslock);

	cachefs_cache_dirty(cachep, 0);
	lhp = RL_HEAD(cachep, CACHEFS_RL_FREE);
	entno = lhp->rli_front;
	if (entno == 0) {
		if (cachep->c_rlinfo.rl_entries >=
			cachep->c_label.cl_maxinodes) {
			error = ENOMEM;
			goto out;
		}
		entno = ++(cachep->c_rlinfo.rl_entries);
		lhp->rli_itemcnt++;
		error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
		if (error)
			goto out;
		rl_ent->rl_current = CACHEFS_RL_NONE;
		rl_ent->rl_fwd_idx = 0;
		rl_ent->rl_bkwd_idx = 0;
	}

	cachefs_rlent_moveto_nolock(cachep, CACHEFS_RL_NONE, entno, 0);

	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error)
		goto out;
	rl_ent->rl_fsid = valp->rl_fsid;
	rl_ent->rl_fileno = valp->rl_fileno;
	rl_ent->rl_local = valp->rl_local;
	rl_ent->rl_attrc = valp->rl_attrc;
	rl_ent->rl_fsck = 0;
out:
	mutex_exit(&cachep->c_contentslock);
	if (error == 0)
		*entnop = entno;
	return (error);
}

/*
 * Call to change a local fileno in an rl entry to a normal fileno.
 */
void
cachefs_rl_changefileno(cachefscache_t *cachep, uint_t entno, ino64_t fileno)
{
	rl_entry_t *rl_ent;
	int error;

	mutex_enter(&cachep->c_contentslock);
	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (!error) {
		ASSERT(rl_ent->rl_local);
		rl_ent->rl_local = 0;
		rl_ent->rl_fileno = fileno;
	}
	mutex_exit(&cachep->c_contentslock);
}

/*
 * Moves the files on the modified list for this file system to
 * the modified fix list.
 */
void
cachefs_move_modified_to_mf(cachefscache_t *cachep, fscache_t *fscp)
{
	rl_entry_t *list_ent;
	uint_t curp, nextp;
	cachefs_rl_listhead_t *lhp;
	int error;

	ASSERT(MUTEX_HELD(&cachep->c_mflock));

	mutex_enter(&cachep->c_contentslock);

	lhp = RL_HEAD(cachep, CACHEFS_RL_MF);
	ASSERT(lhp->rli_front == 0);
	ASSERT(lhp->rli_back == 0);
	ASSERT(lhp->rli_itemcnt == 0);
	lhp->rli_blkcnt = 0;

	cachefs_cache_dirty(cachep, 0);

	/* walk the modified list */
	lhp = RL_HEAD(cachep, CACHEFS_RL_MODIFIED);
	for (curp = lhp->rli_front; curp != 0; curp = nextp) {
		/* get the next element */
		error = cachefs_rl_entry_get(cachep, curp, &list_ent);
		if (error) {
			mutex_exit(&cachep->c_contentslock);
			return;
		}
		nextp = list_ent->rl_bkwd_idx;

		/* skip if element is not in this file system */
		if (list_ent->rl_fsid != fscp->fs_cfsid)
			continue;

		/* move from modified list to mf list */
		cachefs_rlent_moveto_nolock(cachep, CACHEFS_RL_MF, curp, 0);
	}
	mutex_exit(&cachep->c_contentslock);
}

/*
 * Moves the contents of the active list to the rl list.
 * Leave modified files on the active list, so they are not
 * garbage collected.
 */
void
cachefs_rl_cleanup(cachefscache_t *cachep)
{
	cachefs_rl_listhead_t *lhp;
	rl_entry_t *rlp;
	uint_t entno, next;
	int error;

	ASSERT(MUTEX_HELD(&cachep->c_contentslock));

	/*
	 * if fsck ran, then both of these lists should be empty.  the
	 * only time this isn't the case is when we've done a cachefs
	 * boot with a clean cache.  then, the cache may have been
	 * clean, but files and attrfiles were left dangling.
	 *
	 * when this happens, we just fix the linked lists here.  this
	 * means that the attrcache header and cnode metadata might
	 * have incorrect information about which resource lists an
	 * entity is currently on.  so, we set CACHE_CHECK_RLTYPE,
	 * which says cache-wide to double-check and go with whatever
	 * is in the resource list at the time such an object is
	 * loaded into memory.
	 */

	lhp = RL_HEAD(cachep, CACHEFS_RL_ACTIVE);
	if (lhp->rli_itemcnt > 0) {
		cachep->c_flags |= CACHE_CHECK_RLTYPE;
		cachefs_cache_dirty(cachep, 0);
	}
	for (entno = lhp->rli_front; entno != 0; entno = next) {
		error = cachefs_rl_entry_get(cachep, entno, &rlp);
		if (error)
			return;
		next = rlp->rl_bkwd_idx;

		ASSERT(rlp->rl_current == CACHEFS_RL_ACTIVE);
		cachefs_rlent_moveto_nolock(cachep, CACHEFS_RL_GC, entno, 0);
	}

#if 0
	lhp = RL_HEAD(cachep, CACHEFS_RL_ATTRFILE);
	if (lhp->rli_itemcnt > 0) {
		cachep->c_flags |= CACHE_CHECK_RLTYPE;
		cachefs_cache_dirty(cachep, 0);
	}
	for (entno = lhp->rli_front; entno != 0; entno = next) {
		error = cachefs_rl_entry_get(cachep, entno, &rlp);
		if (error)
			return;
		next = rlp->rl_bkwd_idx;

		ASSERT(rlp->rl_current == CACHEFS_RL_ATTRFILE);
		cachefs_rlent_moveto_nolock(cachep, CACHEFS_RL_GC, entno, 0);
	}
#endif
}

int
cachefs_allocfile(cachefscache_t *cachep)
{
	int error = 0;
	int collect = 0;
	struct statvfs64 sb;
	fsfilcnt64_t used;

	(void) VFS_STATVFS(cachep->c_dirvp->v_vfsp, &sb);
	used = sb.f_files - sb.f_ffree;

	mutex_enter(&cachep->c_contentslock);

	/* if there are no more available inodes */
	if ((cachep->c_usage.cu_filesused >= cachep->c_label.cl_maxinodes) ||
	    ((cachep->c_usage.cu_filesused > cachep->c_label.cl_filemin) &&
	    (used > cachep->c_label.cl_filetresh))) {
		error = ENOSPC;
		if ((cachep->c_flags & CACHE_GARBAGE_COLLECT) == 0)
			collect = 1;
	}

	/* else if there are more available inodes */
	else {
		cachefs_cache_dirty(cachep, 0);
		cachep->c_usage.cu_filesused++;
		if (((cachep->c_flags & CACHE_GARBAGE_COLLECT) == 0) &&
		    (cachep->c_usage.cu_filesused >=
		    cachep->c_label.cl_filehiwat))
			collect = 1;
	}

	mutex_exit(&cachep->c_contentslock);

	if (collect)
		cachefs_garbage_collect_queue(cachep);

	return (error);
}

void
cachefs_freefile(cachefscache_t *cachep)
{
	mutex_enter(&cachep->c_contentslock);
	ASSERT(cachep->c_usage.cu_filesused > 0);
	cachefs_cache_dirty(cachep, 0);
	cachep->c_usage.cu_filesused--;
	mutex_exit(&cachep->c_contentslock);
}

/*ARGSUSED*/
int
cachefs_allocblocks(cachefscache_t *cachep, size_t nblks,
    enum cachefs_rl_type type)
{
	int error = 0;
	int collect = 0;
	struct statvfs64 sb;
	size_t used;
	size_t blocks;

	ASSERT(type != CACHEFS_RL_FREE);

	(void) VFS_STATVFS(cachep->c_dirvp->v_vfsp, &sb);
	used = ((sb.f_blocks - sb.f_bfree) * sb.f_frsize) / MAXBSIZE;

	mutex_enter(&cachep->c_contentslock);

	/* if there are no more available blocks */
	blocks = cachep->c_usage.cu_blksused + nblks;
	if ((blocks >= cachep->c_label.cl_maxblks) ||
	    ((blocks > cachep->c_label.cl_blockmin) &&
	    (used > cachep->c_label.cl_blocktresh))) {
		error = ENOSPC;
		if ((cachep->c_flags & CACHE_GARBAGE_COLLECT) == 0)
			collect = 1;
	}

	/* else if there are more available blocks */
	else {
		cachefs_cache_dirty(cachep, 0);
		cachep->c_usage.cu_blksused += (uint_t)nblks;
		ASSERT((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));
		RL_HEAD(cachep, type)->rli_blkcnt += nblks;

		if (((cachep->c_flags & CACHE_GARBAGE_COLLECT) == 0) &&
		    (cachep->c_usage.cu_blksused >=
		    cachep->c_label.cl_blkhiwat))
			collect = 1;
	}

	mutex_exit(&cachep->c_contentslock);

	if (collect)
		cachefs_garbage_collect_queue(cachep);

	return (error);
}

void
cachefs_freeblocks(cachefscache_t *cachep, size_t nblks,
		enum cachefs_rl_type type)
{
	mutex_enter(&cachep->c_contentslock);
	cachefs_cache_dirty(cachep, 0);
	cachep->c_usage.cu_blksused -= (uint_t)nblks;
	ASSERT(cachep->c_usage.cu_blksused >= 0);
	ASSERT((CACHEFS_RL_START <= type) && (type <= CACHEFS_RL_END));
	ASSERT(type != CACHEFS_RL_FREE);
	RL_HEAD(cachep, type)->rli_blkcnt -= nblks;
	mutex_exit(&cachep->c_contentslock);
}

int
cachefs_victim(cachefscache_t *cachep)
{
	uint_t entno;
	rl_entry_t *rl_ent;
	int error = 0;
	ino64_t fsid;
	cfs_cid_t cid;
	struct fscache *fscp;
	struct filegrp *fgp;
	struct cachefs_metadata md;
	struct cnode *cp;
	int isattrc;
	cachefs_rl_listhead_t *lhp;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	fscp = NULL;
	fgp = NULL;

	/* get the file and fsid of the first item on the rl list */
	/* XXX call rlent_data() instead */
	mutex_enter(&cachep->c_contentslock);
	lhp = RL_HEAD(cachep, CACHEFS_RL_GC);
	entno = lhp->rli_front;
	if (entno == 0) {
		mutex_exit(&cachep->c_contentslock);
		error = ENOSPC;
		goto out;
	}
	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error) {
		mutex_exit(&cachep->c_contentslock);
		goto out;
	}
	fsid = rl_ent->rl_fsid;
	cid.cid_fileno = rl_ent->rl_fileno;
	ASSERT(rl_ent->rl_local == 0);
	cid.cid_flags = 0;
	isattrc = rl_ent->rl_attrc;
	mutex_exit(&cachep->c_contentslock);

	/* get the file system cache object for this fsid */
	mutex_enter(&cachep->c_fslistlock);
	fscp = fscache_list_find(cachep, fsid);
	if (fscp == NULL) {
		fscp = fscache_create(cachep);
		error = fscache_activate(fscp, fsid, NULL, NULL, 0);
		if (error) {
			cmn_err(CE_WARN,
			    "cachefs: cache corruption, run fsck\n");
			fscache_destroy(fscp);
			fscp = NULL;
			mutex_exit(&cachep->c_fslistlock);
			error = 0;
			goto out;
		}
		fscache_list_add(cachep, fscp);
	}
	fscache_hold(fscp);
	mutex_exit(&cachep->c_fslistlock);

	/* get the file group object for this file */
	mutex_enter(&fscp->fs_fslock);
	fgp = filegrp_list_find(fscp, &cid);
	if (fgp == NULL) {
		fgp = filegrp_create(fscp, &cid);
		filegrp_list_add(fscp, fgp);
	}
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		if (isattrc == 0) {
			cmn_err(CE_WARN,
			    "cachefs: cache corruption, run fsck\n");
			delay(5*hz);
		}
		filegrp_list_remove(fscp, fgp);
		filegrp_destroy(fgp);
		error = 0;
		fgp = NULL;
		mutex_exit(&fscp->fs_fslock);
		goto out;
	}

	/* if we are victimizing an attrcache file */
	if (isattrc) {
		mutex_enter(&fgp->fg_mutex);
		/* if the filegrp is not writable */
		if ((fgp->fg_flags & CFS_FG_WRITE) == 0) {
			mutex_exit(&fgp->fg_mutex);
			error = EROFS;
			fgp = NULL;
			mutex_exit(&fscp->fs_fslock);
			goto out;
		}

		/* if the filegrp did not go active on us */
		if ((fgp->fg_count == 0) && (fgp->fg_header->ach_nffs == 0)) {
			mutex_exit(&fgp->fg_mutex);
			filegrp_list_remove(fscp, fgp);
			fgp->fg_header->ach_count = 0;
			filegrp_destroy(fgp);
		} else {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("c_victim: filegrp went active"
				    " %p %llu %d %d %lld\n",
				    (void *) fgp,
				    (u_longlong_t)fgp->fg_id.cid_fileno,
				    fgp->fg_header->ach_rlno,
				    fgp->fg_count, fgp->fg_header->ach_nffs);
#endif
			ASSERT(fgp->fg_header->ach_rl_current !=
			    CACHEFS_RL_GC);
			mutex_exit(&fgp->fg_mutex);
		}
		fgp = NULL;
		error = 0;
		mutex_exit(&fscp->fs_fslock);
		goto out;
	}
	ASSERT((fgp->fg_flags & CFS_FG_ALLOC_FILE) == 0);
	filegrp_hold(fgp);
	mutex_exit(&fscp->fs_fslock);

	/* grab the cnode list lock */
	mutex_enter(&fgp->fg_cnodelock);

	/* see if a cnode exists for this file */
	(void) cachefs_cnode_find(fgp, &cid, NULL, &cp, NULL, NULL);
	if (cp) {
		VN_HOLD(CTOV(cp));

		/* move file from rl to active list */
		cachefs_rlent_moveto(fscp->fs_cache,
		    CACHEFS_RL_ACTIVE, cp->c_metadata.md_rlno,
		    cp->c_metadata.md_frontblks);
		cp->c_metadata.md_rltype = CACHEFS_RL_ACTIVE;
		mutex_exit(&cp->c_statelock);
		mutex_exit(&fgp->fg_cnodelock);
		VN_RELE(CTOV(cp));
		error = 0;
		goto out;
	}

	/*
	 * The cnode does not exist and since we hold the hashlock
	 * it cannot be created until we are done.
	 */

	/* see if the item is no longer on the rl list, it could happen */
	mutex_enter(&cachep->c_contentslock);
	lhp = RL_HEAD(cachep, CACHEFS_RL_GC);
	entno = lhp->rli_front;
	if (entno == 0) {
		mutex_exit(&cachep->c_contentslock);
		mutex_exit(&fgp->fg_cnodelock);
		error = ENOSPC;
		goto out;
	}
	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error) {
		mutex_exit(&cachep->c_contentslock);
		mutex_exit(&fgp->fg_cnodelock);
		goto out;
	}
	if ((fsid != rl_ent->rl_fsid) ||
	    (cid.cid_fileno != rl_ent->rl_fileno)) {
		mutex_exit(&cachep->c_contentslock);
		mutex_exit(&fgp->fg_cnodelock);
		error = 0;
		goto out;
	}
	mutex_exit(&cachep->c_contentslock);

	/* Get the metadata from the attrcache file */
	ASSERT((fgp->fg_flags & CFS_FG_ALLOC_ATTR) == 0);
	error = filegrp_read_metadata(fgp, &cid, &md);
	ASSERT(error == 0);

	/* md.md_rltype may be incorrect, but we know file isn't active. */
	if (error) {
		/* XXX this should never happen, fix on panic */
		mutex_exit(&fgp->fg_cnodelock);
		error = 0;
		goto out;
	}

	/* destroy the frontfile */
	cachefs_removefrontfile(&md, &cid, fgp);

	/* remove the victim from the gc list */
	cachefs_rlent_moveto(fscp->fs_cache, CACHEFS_RL_FREE, entno, 0);

	/* destroy the metadata */
	(void) filegrp_destroy_metadata(fgp, &cid);

	mutex_exit(&fgp->fg_cnodelock);
	error = 0;
out:
	if (fgp) {
		filegrp_rele(fgp);
	}
	if (fscp) {
		fscache_rele(fscp);
	}
	return (error);
}

static void
cachefs_garbage_collect(cachefscache_t *cachep)
{
	fsfilcnt64_t filelowat, filelowatmax, maxfiles, threshfiles;
	fsblkcnt64_t blocklowat, blocklowatmax, maxblks, threshblks;
	int error;
	struct cache_usage *cup = &cachep->c_usage;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	mutex_enter(&cachep->c_contentslock);
	ASSERT(cachep->c_flags & CACHE_GARBAGE_COLLECT);
	filelowat = cachep->c_label.cl_filelowat;
	blocklowat = cachep->c_label.cl_blklowat;
	maxblks = cachep->c_label.cl_maxblks;
	maxfiles = cachep->c_label.cl_maxinodes;
	threshblks = cachep->c_label.cl_blocktresh;
	threshfiles = cachep->c_label.cl_filetresh;
	mutex_exit(&cachep->c_contentslock);

	cachep->c_gc_count++;
	cachep->c_gc_time = time;
	cachep->c_gc_before = cachefs_gc_front_atime(cachep);

	/*
	 * since we're here, we're running out of blocks or files.
	 * file and block lowat are what determine how low we garbage
	 * collect.  in order to do any good, we should drop below
	 * maxblocks, threshblocks, or the current blocks, whichever
	 * is smaller (same goes for files).  however, we won't go
	 * below an arbitrary (small) minimum for each.
	 */

	/* move down for maxfiles and maxblocks */
	if ((filelowatmax = (maxfiles * 7) / 10) < filelowat)
		filelowat = filelowatmax;
	if ((blocklowatmax = (maxblks * 7) / 10) < blocklowat)
		blocklowat = blocklowatmax;

	/* move down for threshfiles and threshblocks */
	if ((filelowatmax = (threshfiles * 7) / 10) < filelowat)
		filelowat = filelowatmax;
	if ((blocklowatmax = (threshblks * 7) / 10) < blocklowat)
		blocklowat = blocklowatmax;

	/* move down for current files and blocks */
	if ((filelowatmax = ((fsfilcnt64_t)cup->cu_filesused * 7) / 10) <
	    filelowat)
		filelowat = filelowatmax;
	if ((blocklowatmax = ((fsblkcnt64_t)cup->cu_blksused * 7) / 10) <
	    blocklowat)
		blocklowat = blocklowatmax;

	/* move up for an arbitrary minimum */
#define	MIN_BLKLO	640		/* 640*8192 == 5MB */
#define	MIN_FILELO	1000
	if (filelowat < MIN_FILELO)
		filelowat = MIN_FILELO;
	if (blocklowat < MIN_BLKLO)
		blocklowat = MIN_BLKLO;

	while (cup->cu_filesused > filelowat || cup->cu_blksused > blocklowat) {
		/* if the thread is to terminate */
		if (cachep->c_flags & CACHE_CACHEW_THREADEXIT)
			break;

		error = cachefs_victim(cachep);
		if (error)
			break;
	}

	cachep->c_gc_after = cachefs_gc_front_atime(cachep);
	CACHEFS_TIME_TO_CFS_TIME_COPY(cachep->c_gc_after,
			cachep->c_rlinfo.rl_gctime, error);
}

/*
 * traverse the packed pending list, repacking files when possible.
 */

static void
cachefs_packed_pending(cachefscache_t *cachep)
{
	rl_entry_t rl;
	int error = 0; /* not returned -- used as placeholder */
	fscache_t *fscp = NULL;
	cfs_cid_t cid;
	cnode_t *cp;
	uint_t entno;
	int count = 0;
	cachefs_rl_listhead_t *lhp;

	ASSERT(MUTEX_HELD(&cachep->c_contentslock));

	lhp = RL_HEAD(cachep, CACHEFS_RL_PACKED_PENDING);
	count = lhp->rli_itemcnt;

	mutex_exit(&cachep->c_contentslock);

	rl.rl_current = CACHEFS_RL_PACKED_PENDING;
	while (cachefs_rlent_data(cachep, &rl, &entno) == 0) {
		if (count-- <= 0) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs_ppending: count exceeded\n");
#endif /* CFSDEBUG */
			break;
		}
		if ((cachep->c_flags &
		    (CACHE_PACKED_PENDING | CACHE_CACHEW_THREADEXIT)) !=
		    CACHE_PACKED_PENDING) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs_ppending: early exit\n");
#endif /* CFSDEBUG */
			break;
		}
		if (rl.rl_current != CACHEFS_RL_PACKED_PENDING) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs_ppending: gone from list\n");
#endif /* CFSDEBUG */
			break;
		}

		/* if the fscp we have does not match */
		if ((fscp == NULL) || (fscp->fs_cfsid != rl.rl_fsid)) {
			if (fscp) {
				cachefs_cd_release(fscp);
				fscache_rele(fscp);
				fscp = NULL;
			}

			/* get the file system cache object for this fsid */
			mutex_enter(&cachep->c_fslistlock);
			fscp = fscache_list_find(cachep, rl.rl_fsid);
			if (fscp == NULL) {

				/*
				 * uh oh, the filesystem probably
				 * isn't mounted.  we `move' this
				 * entry onto the same list that it's
				 * on, which really just moves it to
				 * the back of the list.  we need not
				 * worry about an infinite loop, due
				 * to the counter.
				 */

				cachefs_rlent_moveto(cachep,
				    CACHEFS_RL_PACKED_PENDING, entno, 0);
#ifdef CFSDEBUG
				CFS_DEBUG(CFSDEBUG_RESOURCE)
					printf("cachefs_ppending: "
					    "fscp find failed\n");
#endif /* CFSDEBUG */
				continue;
			}
			fscache_hold(fscp);
			mutex_exit(&cachep->c_fslistlock);

			/* get access to the file system */
			error = cachefs_cd_access(fscp, 0, 0);
			if ((error) ||
			    (fscp->fs_cdconnected != CFS_CD_CONNECTED)) {
#ifdef CFSDEBUG
				CFS_DEBUG(CFSDEBUG_RESOURCE)
					printf("cachefs: "
					    "ppending: err %d con %d\n",
					    error, fscp->fs_cdconnected);
#endif /* CFSDEBUG */
				fscache_rele(fscp);
				fscp = NULL;
				break;
			}
		}

		/* get the cnode for the file */
		cid.cid_fileno = rl.rl_fileno;
		cid.cid_flags = rl.rl_local ? CFS_CID_LOCAL : 0;
		error = cachefs_cnode_make(&cid, fscp,
		    NULL, NULL, NULL, kcred, 0, &cp);
		if (error) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs: "
				    "ppending: could not find %llu\n",
				    (u_longlong_t)cid.cid_fileno);
			delay(5*hz);
#endif /* CFSDEBUG */
			break;
		}

		mutex_enter(&cp->c_statelock);
		if (cp->c_flags & CN_STALE) {
			/* back file went away behind our back */
			ASSERT(cp->c_metadata.md_rlno == 0);
			mutex_exit(&cp->c_statelock);

#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs: ppending: stale\n");
#endif /* CFSDEBUG */

			VN_RELE(CTOV(cp));
			continue;
		}
		mutex_exit(&cp->c_statelock);

		error = cachefs_pack_common(CTOV(cp),
		    (cp->c_cred) ? cp->c_cred : kcred);
		VN_RELE(CTOV(cp));

		if (error != 0) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_RESOURCE)
				printf("cachefs: "
				    "ppending: pack_common: error = %d\n",
				    error);
#endif /* CFSDEBUG */
			break;
		}
	}

	if (fscp != NULL) {
		cachefs_cd_release(fscp);
		fscache_rele(fscp);
	}

	mutex_enter(&cachep->c_contentslock);
	if (lhp->rli_itemcnt == 0)
		cachep->c_flags &= ~CACHE_PACKED_PENDING;
}

/* seconds; interval to do ppend list */
static time_t cachefs_ppend_time = 900;

/* main routine for the cachep worker thread */
void
cachefs_cachep_worker_thread(cachefscache_t *cachep)
{
	int error;
	struct flock64 fl;
	callb_cpr_t cprinfo;
	kmutex_t cpr_lock;


	/* lock the lock file for exclusive write access */
	fl.l_type = F_WRLCK;
	fl.l_whence = 0;
	fl.l_start = (offset_t)0;
	fl.l_len = (offset_t)1024;
	fl.l_sysid = 0;
	fl.l_pid = 0;
	error = VOP_FRLOCK(cachep->c_lockvp, F_SETLK, &fl, FWRITE,
		(offset_t)0, NULL, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN,
		    "cachefs: Can't lock Cache Lock File(r); Error %d\n",
		    error);
	}

	mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cprinfo, &cpr_lock, callb_generic_cpr, "cfs_gct");
	mutex_enter(&cpr_lock);
	mutex_enter(&cachep->c_contentslock);

	/* loop while the thread is allowed to run */
	while ((cachep->c_flags & CACHE_CACHEW_THREADEXIT) == 0) {
		clock_t wakeup;

		/* wait for a wakeup call */
		cachep->c_flags &= ~CACHE_GARBAGE_COLLECT;
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		mutex_exit(&cpr_lock);
		wakeup = (clock_t)(lbolt + (cachefs_ppend_time * hz));
		(void) cv_timedwait(&cachep->c_cwcv,
			&cachep->c_contentslock, wakeup);
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &cpr_lock);

		/* if the thread is to terminate */
		if (cachep->c_flags & CACHE_CACHEW_THREADEXIT)
			break;

		/* thread is running during nofill, but just to hold lock */
		if (cachep->c_flags & CACHE_NOFILL)
			continue;

		/* if garbage collection is to run */
		if (cachep->c_flags & CACHE_GARBAGE_COLLECT) {
			mutex_exit(&cachep->c_contentslock);
			cachefs_garbage_collect(cachep);

			/*
			 * Prevent garbage collection from running more
			 * than once every 30 seconds.  This addresses
			 * those cases which do not allow removing
			 * an item from the rl by keeping gc from
			 * being a spin loop.
			 */
			delay(30*hz); /* XXX sam: still do this? */
			mutex_enter(&cachep->c_contentslock);
		}

		if (cachep->c_flags & CACHE_PACKED_PENDING)
			cachefs_packed_pending(cachep);
		ASSERT(MUTEX_HELD(&cachep->c_contentslock));
	}

	cachep->c_flags &= ~CACHE_CACHEW_THREADRUN;
	cv_broadcast(&cachep->c_cwhaltcv);
	CALLB_CPR_EXIT(&cprinfo);
	mutex_exit(&cachep->c_contentslock);
	mutex_destroy(&cpr_lock);

	/* unlock the lock file */
	fl.l_type = F_UNLCK;
	fl.l_whence = 0;
	fl.l_start = (offset_t)0;
	fl.l_len = (offset_t)1024;
	fl.l_sysid = 0;
	fl.l_pid = 0;
	error = VOP_FRLOCK(cachep->c_lockvp, F_SETLK, &fl,
		FWRITE, (offset_t)0, NULL, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: Can't unlock lock file\n");
	}

	thread_exit();
	/*NOTREACHED*/
}

/* queues up a request to run the garbage collection */
void
cachefs_garbage_collect_queue(cachefscache_t *cachep)
{
	cachefs_rl_listhead_t *lhp;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	mutex_enter(&cachep->c_contentslock);

	/* quit if there is no garbage collection thread */
	if ((cachep->c_flags & CACHE_CACHEW_THREADRUN) == 0) {
		mutex_exit(&cachep->c_contentslock);
		return;
	}

	/* quit if garbage collection is already in progress */
	if (cachep->c_flags & CACHE_GARBAGE_COLLECT) {
		mutex_exit(&cachep->c_contentslock);
		return;
	}

	/* quit if there is no garbage to collect */
	lhp = RL_HEAD(cachep, CACHEFS_RL_GC);
	if (lhp->rli_front == 0) {
		mutex_exit(&cachep->c_contentslock);
		return;
	}

	/* indicate garbage collecting is in progress */
	cachep->c_flags |= CACHE_GARBAGE_COLLECT;

	/* wake up the garbage collection thread */
	cv_signal(&cachep->c_cwcv);

	mutex_exit(&cachep->c_contentslock);
}

#ifdef CFSRLDEBUG
time_t cachefs_dbvalid = 123; /* default to non-zero junk */
struct kmem_cache *cachefs_rl_debug_cache = NULL;
static int cachefs_rl_debug_maxcount = CACHEFS_RLDB_DEF_MAXCOUNT;
kmutex_t cachefs_rl_debug_mutex;
static int cachefs_rl_debug_inuse = 0;

void
cachefs_rl_debug_reclaim(void *cdrarg)
{
	extern cachefscache_t *cachefs_cachelist;
	cachefscache_t *cachep;
	int index;
	int error;

	for (cachep = cachefs_cachelist; cachep != NULL;
		cachep = cachep->c_next) {
		mutex_enter(&cachep->c_contentslock);

		for (index = 0;
		    index <= cachep->c_rlinfo.rl_entries;
		    index++) {
			rl_entry_t *rlent;

			error = cachefs_rl_entry_get(cachep, index, &rlent);
			if (error)
				break;
			cachefs_rl_debug_destroy(rlent);
		}

		mutex_exit(&cachep->c_contentslock);
	}
}

void
cachefs_rl_debug_save(rl_entry_t *rlent)
{
	rl_debug_t *rldb, *prev, *next;
	int count = 0;

	mutex_enter(&cachefs_rl_debug_mutex);
	if (cachefs_rl_debug_cache == NULL)
		cachefs_rl_debug_cache =
		    kmem_cache_create("cachefs_rl_debug",
			sizeof (rl_debug_t), 0,
			NULL, NULL, cachefs_rl_debug_reclaim, NULL, NULL, 0);

	rldb = kmem_cache_alloc(cachefs_rl_debug_cache, KM_SLEEP);
	++cachefs_rl_debug_inuse;

	rldb->db_hrtime = gethrtime();

	rldb->db_attrc = rlent->rl_attrc;
	rldb->db_fsck = rlent->rl_fsck;
	rldb->db_fsid = rlent->rl_fsid;
	rldb->db_fileno = rlent->rl_fileno;
	rldb->db_current = rlent->rl_current;

	rldb->db_stackheight = getpcstack(rldb->db_stack,
	    CACHEFS_RLDB_STACKSIZE);

	if (rlent->rl_dbvalid == cachefs_dbvalid) {
		rldb->db_next = rlent->rl_debug;
	} else {
		rldb->db_next = NULL;
		rlent->rl_dbvalid = cachefs_dbvalid;
	}
	rlent->rl_debug = rldb;

	prev = rldb;
	for (rldb = rldb->db_next; rldb != NULL; rldb = next) {
		next = rldb->db_next;
		if (++count >= cachefs_rl_debug_maxcount) {
			if (prev != NULL)
				prev->db_next = NULL;
			kmem_cache_free(cachefs_rl_debug_cache, rldb);
			--cachefs_rl_debug_inuse;
			prev = NULL;
		} else {
			prev = rldb;
		}
	}
	mutex_exit(&cachefs_rl_debug_mutex);
}

void
cachefs_rl_debug_show(rl_entry_t *rlent)
{
	rl_debug_t *rldb;
	hrtime_t now, elapse;
	timestruc_t tv;
	char *cname = NULL;
	int i;

	mutex_enter(&cachefs_rl_debug_mutex);
	if (rlent->rl_dbvalid != cachefs_dbvalid) {
		printf("cachefs_rldb: rl entry at %lx -- no info!\n",
		    (uintptr_t)rlent);
		mutex_exit(&cachefs_rl_debug_mutex);
		return;
	}

	now = gethrtime();
	hrt2ts(now, &tv);

	printf("===== cachefs_rldb start at %ld =====\n", tv.tv_sec);
	printf("-==== i am thread id %lx   ====-\n", (uintptr_t)curthread);

	for (rldb = rlent->rl_debug;
	    rldb != NULL;
	    rldb = rldb->db_next) {
		printf("----- cachefs_rldb record start -----\n");
		elapse = now - rldb->db_hrtime;
		hrt2ts(elapse, &tv);
		printf("cachefs_rldb: ago = %lds %ldus\n",
		    tv.tv_sec, tv.tv_nsec / 1000);

		printf("cachefs_rldb: rl_attrc = %d\n", rldb->db_attrc);
		printf("cachefs_rldb: rl_fsck = %d\n", rldb->db_fsck);
		printf("cachefs_rldb: rl_fsid = %u\n", rldb->db_fsid);
		printf("cachefs_rldb: rl_fileno = %lu\n", rldb->db_fileno);

		switch (rldb->db_current) {
		case CACHEFS_RL_NONE:
			cname = "CACHEFS_RL_NONE";
			break;
		case CACHEFS_RL_FREE:
			cname = "CACHEFS_RL_FREE";
			break;
		case CACHEFS_RL_GC:
			cname = "CACHEFS_RL_GC";
			break;
		case CACHEFS_RL_ACTIVE:
			cname = "CACHEFS_RL_ACTIVE";
			break;
		case CACHEFS_RL_ATTRFILE:
			cname = "CACHEFS_RL_ATTRFILE";
			break;
		case CACHEFS_RL_MODIFIED:
			cname = "CACHEFS_RL_MODIFIED";
			break;
		case CACHEFS_RL_PACKED:
			cname = "CACHEFS_RL_PACKED";
			break;
		case CACHEFS_RL_PACKED_PENDING:
			cname = "CACHEFS_RL_PACKED_PENDING";
			break;
		case CACHEFS_RL_MF:
			cname = "CACHEFS_MF_GC";
			break;
		}
		if (cname != NULL) {
			printf("cachefs_rldb: state = %s\n", cname);
		} else {
			printf("cachefs_rldb: undefined state %x\n",
			    rldb->db_current);
		}

		printf("cachefs_rldb: stack trace\n");
		for (i = 0; i < rldb->db_stackheight; i++) {
			char *sym;
			uint_t off;

			sym = kobj_getsymname(rldb->db_stack[i], &off);
			printf("cachefs_rldb:    %s+%lx\n",
			    sym ? sym : "?", off);
			delay(hz/4);
		}

		printf("----- cachefs_rldb record end -----\n");
	}

	mutex_exit(&cachefs_rl_debug_mutex);
}

void
cachefs_rl_debug_destroy(rl_entry_t *rlent)
{
	rl_debug_t *rldb, *next;

	mutex_enter(&cachefs_rl_debug_mutex);
	if (rlent->rl_dbvalid != cachefs_dbvalid) {
		rlent->rl_debug = NULL;
		mutex_exit(&cachefs_rl_debug_mutex);
		return;
	}

	for (rldb = rlent->rl_debug; rldb != NULL; rldb = next) {
		next = rldb->db_next;
		kmem_cache_free(cachefs_rl_debug_cache, rldb);
		--cachefs_rl_debug_inuse;
	}

	rlent->rl_debug = NULL;
	mutex_exit(&cachefs_rl_debug_mutex);
}
#endif /* CFSRLDEBUG */

int
cachefs_rl_entry_get(cachefscache_t *cachep, uint_t entno, rl_entry_t **ent)
{
	rl_entry_t *rl_ent;
	uint_t whichwindow, winoffset;
	int error = 0;

	ASSERT(MUTEX_HELD(&cachep->c_contentslock));
	ASSERT(entno <= cachep->c_label.cl_maxinodes); /* strictly less? */
#if 0
	ASSERT((cachep->c_flags & CACHE_NOFILL) == 0);
#endif

	whichwindow = entno / CACHEFS_RLPMBS;
	winoffset = entno % CACHEFS_RLPMBS;

	if ((cachep->c_rl_entries == NULL) ||
	    (cachep->c_rl_window != whichwindow)) {
		if (cachep->c_rl_entries != NULL) {
			error = vn_rdwr(UIO_WRITE, cachep->c_resfilevp,
			    (caddr_t)cachep->c_rl_entries, MAXBSIZE,
			    (offset_t)((cachep->c_rl_window + 1) * MAXBSIZE),
			    UIO_SYSSPACE, 0, RLIM_INFINITY, kcred, NULL);
			if (error)
				return (error);
		}
		else
			cachep->c_rl_entries = (rl_entry_t *)
			    cachefs_kmem_alloc(MAXBSIZE, KM_SLEEP);

		error = vn_rdwr(UIO_READ, cachep->c_resfilevp,
		    (caddr_t)cachep->c_rl_entries, MAXBSIZE,
		    (offset_t)((whichwindow + 1) * MAXBSIZE),
		    UIO_SYSSPACE, 0, RLIM_INFINITY, kcred, NULL);
		if (error) {
			cachefs_kmem_free(cachep->c_rl_entries, MAXBSIZE);
			cachep->c_rl_entries = NULL;
			return (error);
		}
		cachep->c_rl_window = whichwindow;
	}
	rl_ent = &cachep->c_rl_entries[winoffset];

	*ent = rl_ent;
#ifdef CFSRLDEBUG
	cachefs_rl_debug_save(rl_ent);
#endif /* CFSRLDEBUG */

	return (error);
}

static time_t
cachefs_gc_front_atime(cachefscache_t *cachep)
{
	char namebuf[CFS_FRONTFILE_NAME_SIZE];

	rl_entry_t rl, *rl_ent;
	uint_t entno, fgsize;
	cfs_cid_t dircid, cid;
	struct fscache *fscp;
	cachefs_rl_listhead_t *lhp;
	int error;

	struct vnode *dirvp, *filevp;
	struct vattr va;

	int reledir = 0;
	int gotfile = 0;
	time_t rc = (time_t)0;

	mutex_enter(&cachep->c_contentslock);
	lhp = RL_HEAD(cachep, CACHEFS_RL_GC);
	entno = lhp->rli_front;
	if (entno == 0) {
		mutex_exit(&cachep->c_contentslock);
		goto out;
	}

	error = cachefs_rl_entry_get(cachep, entno, &rl_ent);
	if (error) {
		mutex_exit(&cachep->c_contentslock);
		goto out;
	}
	rl = *rl_ent;
	mutex_exit(&cachep->c_contentslock);
	cid.cid_fileno = rl.rl_fileno;
	ASSERT(rl.rl_local == 0);
	cid.cid_flags = 0;
	dircid.cid_flags = 0;
	mutex_enter(&cachep->c_fslistlock);
	if ((fscp = fscache_list_find(cachep, rl.rl_fsid)) == NULL) {
		mutex_exit(&cachep->c_fslistlock);
		goto out;
	}

	if (rl.rl_attrc) {
		make_ascii_name(&cid, namebuf);
		dirvp = fscp->fs_fsattrdir;
	} else {
		dirvp = NULL;
		fgsize = fscp->fs_info.fi_fgsize;
		dircid.cid_fileno = ((cid.cid_fileno / fgsize) * fgsize);
		make_ascii_name(&dircid, namebuf);
		if (VOP_LOOKUP(fscp->fs_fscdirvp, namebuf,
		    &dirvp, (struct pathname *)NULL, 0,
		    (vnode_t *)NULL, kcred, NULL, NULL, NULL) == 0) {
			make_ascii_name(&cid, namebuf);
			reledir++;
		} else {
			mutex_exit(&cachep->c_fslistlock);
			goto out;
		}
	}
	if (dirvp && VOP_LOOKUP(dirvp, namebuf, &filevp,
	    (struct pathname *)NULL, 0,
	    (vnode_t *)NULL, kcred, NULL, NULL, NULL) == 0) {
		gotfile = 1;
	}
	if (reledir)
		VN_RELE(dirvp);
	mutex_exit(&cachep->c_fslistlock);

	if (gotfile) {
		va.va_mask = AT_ATIME;
		if (VOP_GETATTR(filevp, &va, 0, kcred, NULL) == 0)
			rc = va.va_atime.tv_sec;
		VN_RELE(filevp);
	}

out:
	return (rc);
}
