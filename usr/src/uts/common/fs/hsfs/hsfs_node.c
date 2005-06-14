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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Directory operations for High Sierra filesystem
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/dnlc.h>
#include <sys/cmn_err.h>
#include <sys/fbuf.h>
#include <sys/kmem.h>
#include <sys/policy.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/fs/hsfs_node.h>
#include <sys/fs/hsfs_impl.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <fs/fs_subr.h>

/*
 * This macro expects a name that ends in '.' and returns TRUE if the
 * name is not "." or ".."
 */
#define	CAN_TRUNCATE_DOT(name, namelen)	\
		(namelen > 1 && (namelen > 2 || name[0] != '.'))

enum dirblock_result { FOUND_ENTRY, WENT_PAST, HIT_END };

/*
 * These values determine whether we will try to read a file or dir;
 * they may be patched via /etc/system to allow users to read
 * record-oriented files.
 */
int ide_prohibited = IDE_PROHIBITED;
int hde_prohibited = HDE_PROHIBITED;

/*
 * This variable determines if the HSFS code will use the
 * directory name lookup cache. The default is for the cache to be used.
 */
static int hsfs_use_dnlc = 1;

/*
 * This variable determines whether strict ISO-9660 directory ordering
 * is to be assumed.  If false (which it is by default), then when
 * searching a directory of an ISO-9660 disk, we do not expect the
 * entries to be sorted (as the spec requires), and so cannot terminate
 * the search early.  Unfortunately, some vendors are producing
 * non-compliant disks.  This variable exists to revert to the old
 * behavior in case someone relies on this. This option is expected to be
 * removed at some point in the future.
 *
 * Use "set hsfs:strict_iso9660_ordering = 1" in /etc/system to override.
 */
static int strict_iso9660_ordering = 0;

static void hs_hsnode_cache_reclaim(void *unused);
static void hs_addfreeb(struct hsfs *fsp, struct hsnode *hp);
static int nmcmp(char *a, char *b, int len, int is_rrip);
static enum dirblock_result process_dirblock(struct fbuf *fbp, uint_t *offset,
	uint_t last_offset, char *nm, int nmlen, struct hsfs *fsp,
	struct hsnode *dhp, struct vnode *dvp, struct vnode **vpp,
	int *error, int is_rrip);
static int strip_trailing(struct hsfs *fsp, char *nm, int len);
static int uppercase_cp(char *from, char *to, int size);

/*
 * hs_access
 * Return 0 if the desired access may be granted.
 * Otherwise return error code.
 */
int
hs_access(struct vnode *vp, mode_t m, struct cred *cred)
{
	struct hsnode *hp;
	int	shift = 0;

	/*
	 * Write access cannot be granted for a read-only medium
	 */
	if ((m & VWRITE) && !IS_DEVVP(vp))
		return (EROFS);

	hp = VTOH(vp);

	/*
	 * XXX - For now, use volume protections.
	 *  Also, always grant EXEC access for directories
	 *  if READ access is granted.
	 */
	if ((vp->v_type == VDIR) && (m & VEXEC)) {
		m &= ~VEXEC;
		m |= VREAD;
	}

	if (crgetuid(cred) != hp->hs_dirent.uid) {
		shift += 3;
		if (!groupmember((uid_t)hp->hs_dirent.gid, cred))
			shift += 3;
	}
	m &= ~(hp->hs_dirent.mode << shift);
	if (m != 0)
		return (secpolicy_vnode_access(cred, vp, hp->hs_dirent.uid, m));
	return (0);
}

#if ((HS_HASHSIZE & (HS_HASHSIZE - 1)) == 0)
#define	HS_HASH(l)	((uint_t)(l) & (HS_HASHSIZE - 1))
#else
#define	HS_HASH(l)	((uint_t)(l) % HS_HASHSIZE)
#endif
#define	HS_HPASH(hp)	HS_HASH((hp)->hs_nodeid)

/*
 * The tunable nhsnode is now a threshold for a dynamically allocated
 * pool of hsnodes, not the size of a statically allocated table.
 * When the number of hsnodes for a particular file system exceeds
 * nhsnode, the allocate and free logic will try to reduce the number
 * of allocated nodes by returning unreferenced nodes to the kmem_cache
 * instead of putting them on the file system's private free list.
 */
int nhsnode = HS_HSNODESPACE / sizeof (struct hsnode);

struct kmem_cache *hsnode_cache;  /* free hsnode cache */

/*
 * Initialize the cache of free hsnodes.
 */
void
hs_init_hsnode_cache(void)
{
	/*
	 * A kmem_cache is used for the hsnodes
	 * No constructor because hsnodes are initialised by bzeroing.
	 */
	hsnode_cache = kmem_cache_create("hsfs_hsnode_cache",
	    sizeof (struct hsnode), 0, NULL,
	    NULL, hs_hsnode_cache_reclaim, NULL, NULL, 0);
}

/*
 * System is short on memory, free up as much as possible
 */
/*ARGSUSED*/
static void
hs_hsnode_cache_reclaim(void *unused)
{
	struct hsfs *fsp;
	struct hsnode *hp;

	/*
	 * For each vfs in the hs_mounttab list
	 */
	mutex_enter(&hs_mounttab_lock);
	for (fsp = hs_mounttab; fsp != NULL; fsp = fsp->hsfs_next) {
		/*
		 * Purge the dnlc of all hsfs entries
		 */
		(void) dnlc_purge_vfsp(fsp->hsfs_vfs, 0);

		/*
		 * For each entry in the free chain
		 */
		rw_enter(&fsp->hsfs_hash_lock, RW_WRITER);
		mutex_enter(&fsp->hsfs_free_lock);
		for (hp = fsp->hsfs_free_f; hp != NULL; hp = fsp->hsfs_free_f) {
			/*
			 * Remove from chain
			 */
			fsp->hsfs_free_f = hp->hs_freef;
			if (fsp->hsfs_free_f != NULL) {
				fsp->hsfs_free_f->hs_freeb = NULL;
			} else {
				fsp->hsfs_free_b = NULL;
			}
			/*
			 * Free the node. Force it to be fully freed
			 * by setting the 3rd arg (nopage) to 1.
			 */
			hs_freenode(HTOV(hp), fsp, 1);
		}
		mutex_exit(&fsp->hsfs_free_lock);
		rw_exit(&fsp->hsfs_hash_lock);
	}
	mutex_exit(&hs_mounttab_lock);
}

/*
 * Add an hsnode to the end of the free list.
 */
static void
hs_addfreeb(struct hsfs *fsp, struct hsnode *hp)
{
	struct hsnode *ep;

	vn_invalid(HTOV(hp));
	mutex_enter(&fsp->hsfs_free_lock);
	ep = fsp->hsfs_free_b;
	fsp->hsfs_free_b = hp;		/* hp is the last entry in free list */
	hp->hs_freef = NULL;
	hp->hs_freeb = ep;		/* point at previous last entry */
	if (ep == NULL)
		fsp->hsfs_free_f = hp;	/* hp is only entry in free list */
	else
		ep->hs_freef = hp;	/* point previous last entry at hp */

	mutex_exit(&fsp->hsfs_free_lock);
}

/*
 * Get an hsnode from the front of the free list.
 * Must be called with write hsfs_hash_lock held.
 */
static struct hsnode *
hs_getfree(struct hsfs *fsp)
{
	struct hsnode *hp, **tp;

	ASSERT(RW_WRITE_HELD(&fsp->hsfs_hash_lock));

	/*
	 * If the number of currently-allocated hsnodes is less than
	 * the hsnode count threshold (nhsnode), or if there are no
	 * nodes on the file system's local free list (which acts as a
	 * cache), call kmem_cache_alloc to get a new hsnode from
	 * kernel memory.
	 */
	mutex_enter(&fsp->hsfs_free_lock);
	if ((fsp->hsfs_nohsnode < nhsnode) || (fsp->hsfs_free_f == NULL)) {
		mutex_exit(&fsp->hsfs_free_lock);
		hp = kmem_cache_alloc(hsnode_cache, KM_SLEEP);
		fsp->hsfs_nohsnode++;
		bzero((caddr_t)hp, sizeof (*hp));
		hp->hs_vnode = vn_alloc(KM_SLEEP);
		return (hp);
	}
	hp = fsp->hsfs_free_f;
	/* hp cannot be NULL, since we already checked this above */
	fsp->hsfs_free_f = hp->hs_freef;
	if (fsp->hsfs_free_f != NULL)
		fsp->hsfs_free_f->hs_freeb = NULL;
	else
		fsp->hsfs_free_b = NULL;
	mutex_exit(&fsp->hsfs_free_lock);

	for (tp = &fsp->hsfs_hash[HS_HPASH(hp)]; *tp != NULL;
		tp = &(*tp)->hs_hash) {
		if (*tp == hp) {
			struct vnode *vp;

			vp = HTOV(hp);

			/*
			 * file is no longer referenced, destroy all old pages
			 */
			if (vn_has_cached_data(vp))
				/*
				 * pvn_vplist_dirty will abort all old pages
				 */
				(void) pvn_vplist_dirty(vp, (u_offset_t)0,
				hsfs_putapage, B_INVAL, (struct cred *)NULL);
			*tp = hp->hs_hash;
			break;
		}
	}
	if (hp->hs_dirent.sym_link != (char *)NULL) {
		kmem_free(hp->hs_dirent.sym_link,
			(size_t)(hp->hs_dirent.ext_size + 1));
	}

	mutex_destroy(&hp->hs_contents_lock);
	{
		vnode_t	*vp;

		vp = hp->hs_vnode;
		bzero((caddr_t)hp, sizeof (*hp));
		hp->hs_vnode = vp;
		vn_reinit(vp);
	}
	return (hp);
}

/*
 * Remove an hsnode from the free list.
 */
static void
hs_remfree(struct hsfs *fsp, struct hsnode *hp)
{
	mutex_enter(&fsp->hsfs_free_lock);
	if (hp->hs_freef != NULL)
		hp->hs_freef->hs_freeb = hp->hs_freeb;
	else
		fsp->hsfs_free_b = hp->hs_freeb;
	if (hp->hs_freeb != NULL)
		hp->hs_freeb->hs_freef = hp->hs_freef;
	else
		fsp->hsfs_free_f = hp->hs_freef;
	mutex_exit(&fsp->hsfs_free_lock);
}

/*
 * Look for hsnode in hash list.
 * Check equality of fsid and nodeid.
 * If found, reactivate it if inactive.
 * Must be entered with hsfs_hash_lock held.
 */
struct vnode *
hs_findhash(ino64_t nodeid, struct vfs *vfsp)
{
	struct hsnode *tp;
	struct hsfs *fsp;

	fsp = VFS_TO_HSFS(vfsp);

	ASSERT(RW_LOCK_HELD(&fsp->hsfs_hash_lock));

	for (tp = fsp->hsfs_hash[HS_HASH(nodeid)]; tp != NULL;
	    tp = tp->hs_hash) {
		if (tp->hs_nodeid == nodeid) {
			struct vnode *vp;

			mutex_enter(&tp->hs_contents_lock);
			vp = HTOV(tp);
			VN_HOLD(vp);
			if ((tp->hs_flags & HREF) == 0) {
				tp->hs_flags |= HREF;
				/*
				 * reactivating a free hsnode:
				 * remove from free list
				 */
				hs_remfree(fsp, tp);
			}
			mutex_exit(&tp->hs_contents_lock);
			return (vp);
		}
	}
	return (NULL);
}

static void
hs_addhash(struct hsfs *fsp, struct hsnode *hp)
{
	ulong_t hashno;

	ASSERT(RW_WRITE_HELD(&fsp->hsfs_hash_lock));

	hashno = HS_HPASH(hp);
	hp->hs_hash = fsp->hsfs_hash[hashno];
	fsp->hsfs_hash[hashno] = hp;
}

/*
 * Destroy all old pages and free the hsnodes
 * Return 1 if busy (a hsnode is still referenced).
 */
int
hs_synchash(struct vfs *vfsp)
{
	struct hsfs *fsp;
	int i;
	struct hsnode *hp, *nhp;
	int busy = 0;
	struct vnode *vp, *rvp;

	fsp = VFS_TO_HSFS(vfsp);
	rvp = fsp->hsfs_rootvp;
	/* make sure no one can come in */
	rw_enter(&fsp->hsfs_hash_lock, RW_WRITER);
	for (i = 0; i < HS_HASHSIZE; i++) {
		for (hp = fsp->hsfs_hash[i]; hp != NULL; hp = hp->hs_hash) {
			vp = HTOV(hp);
			if ((hp->hs_flags & HREF) && (vp != rvp ||
				(vp == rvp && vp->v_count > 1))) {
				busy = 1;
				continue;
			}
			if (vn_has_cached_data(vp))
				(void) pvn_vplist_dirty(vp, (u_offset_t)0,
				hsfs_putapage, B_INVAL, (struct cred *)NULL);
		}
	}
	if (busy) {
		rw_exit(&fsp->hsfs_hash_lock);
		return (1);
	}

	/* now free the hsnodes */
	for (i = 0; i < HS_HASHSIZE; i++) {
		for (hp = fsp->hsfs_hash[i]; hp != NULL; hp = nhp) {
			nhp = hp->hs_hash;
			/*
			 * We know there are no pages associated with
			 * all the hsnodes (they've all been released
			 * above). So remove from free list and
			 * free the entry with nopage set.
			 */
			vp = HTOV(hp);
			if (vp != rvp) {
				hs_remfree(fsp, hp);
				hs_freenode(vp, fsp, 1);
			}
		}
	}

	ASSERT(fsp->hsfs_nohsnode == 1);
	rw_exit(&fsp->hsfs_hash_lock);
	/* release the root hsnode, this should free the final hsnode */
	VN_RELE(rvp);

	return (0);
}

/*
 * hs_makenode
 *
 * Construct an hsnode.
 * Caller specifies the directory entry, the block number and offset
 * of the directory entry, and the vfs pointer.
 * note: off is the sector offset, not lbn offset
 * if NULL is returned implies file system hsnode table full
 */
struct vnode *
hs_makenode(
	struct hs_direntry *dp,
	uint_t lbn,
	uint_t off,
	struct vfs *vfsp)
{
	struct hsnode *hp;
	struct vnode *vp;
	struct hs_volume *hvp;
	struct vnode *newvp;
	struct hsfs *fsp;
	ino64_t nodeid;

	fsp = VFS_TO_HSFS(vfsp);

	/*
	 * Construct the nodeid: in the case of a directory
	 * entry, this should point to the canonical dirent, the "."
	 * directory entry for the directory.  This dirent is pointed
	 * to by all directory entries for that dir (including the ".")
	 * entry itself.
	 * In the case of a file, simply point to the dirent for that
	 * file (there are no hard links in Rock Ridge, so there's no
	 * need to determine what the canonical dirent is.
	 */
	if (dp->type == VDIR) {
		lbn = dp->ext_lbn;
		off = 0;
	}

	/*
	 * Normalize lbn and off before creating a nodeid
	 * and before storing them in a hs_node structure
	 */
	hvp = &fsp->hsfs_vol;
	lbn += off >> hvp->lbn_shift;
	off &= hvp->lbn_maxoffset;
	nodeid = (ino64_t)MAKE_NODEID(lbn, off, vfsp);

	/* look for hsnode in cache first */

	rw_enter(&fsp->hsfs_hash_lock, RW_READER);

	if ((vp = hs_findhash(nodeid, vfsp)) == NULL) {

		/*
		 * Not in cache.  However, someone else may have come
		 * to the same conclusion and just put one in.	Upgrade
		 * our lock to a write lock and look again.
		 */
		rw_exit(&fsp->hsfs_hash_lock);
		rw_enter(&fsp->hsfs_hash_lock, RW_WRITER);

		if ((vp = hs_findhash(nodeid, vfsp)) == NULL) {
			/*
			 * Now we are really sure that the hsnode is not
			 * in the cache.  Get one off freelist or else
			 * allocate one. Either way get a bzeroed hsnode.
			 */
			hp = hs_getfree(fsp);

			bcopy((caddr_t)dp, (caddr_t)&hp->hs_dirent,
				sizeof (*dp));
			/*
			 * We've just copied this pointer into hs_dirent,
			 * and don't want 2 references to same symlink.
			 */
			dp->sym_link = (char *)NULL;

			/*
			 * No need to hold any lock because hsnode is not
			 * yet in the hash chain.
			 */
			mutex_init(&hp->hs_contents_lock, NULL, MUTEX_DEFAULT,
			    NULL);
			hp->hs_dir_lbn = lbn;
			hp->hs_dir_off = off;
			hp->hs_nodeid = nodeid;
			hp->hs_seq = 0;
			hp->hs_flags = HREF;
			if (off > HS_SECTOR_SIZE)
				cmn_err(CE_WARN, "hs_makenode: bad offset");

			vp = HTOV(hp);
			vp->v_vfsp = vfsp;
			vp->v_type = dp->type;
			vp->v_rdev = dp->r_dev;
			vn_setops(vp, hsfs_vnodeops);
			vp->v_data = (caddr_t)hp;
			vn_exists(vp);
			/*
			 * if it's a device, call specvp
			 */
			if (IS_DEVVP(vp)) {
				rw_exit(&fsp->hsfs_hash_lock);
				newvp = specvp(vp, vp->v_rdev, vp->v_type,
						CRED());
				if (newvp == NULL)
				    cmn_err(CE_NOTE,
					"hs_makenode: specvp failed");
				VN_RELE(vp);
				return (newvp);
			}

			hs_addhash(fsp, hp);

		}
	}

	if (dp->sym_link != (char *)NULL) {
		kmem_free(dp->sym_link, (size_t)(dp->ext_size + 1));
		dp->sym_link = (char *)NULL;
	}

	rw_exit(&fsp->hsfs_hash_lock);
	return (vp);
}

/*
 * hs_freenode
 *
 * Deactivate an hsnode.
 * Leave it on the hash list but put it on the free list.
 * If the vnode does not have any pages, release the hsnode to the
 * kmem_cache using kmem_cache_free, else put in back of the free list.
 *
 * This function can be called with the hsfs_free_lock held, but only
 * when the code is guaranteed to go through the path where the
 * node is freed entirely, and not the path where the node could go back
 * on the free list (and where the free lock would need to be acquired).
 */
void
hs_freenode(vnode_t *vp, struct hsfs *fsp, int nopage)
{
	struct hsnode **tp;
	struct hsnode *hp = VTOH(vp);

	ASSERT(RW_LOCK_HELD(&fsp->hsfs_hash_lock));

	if (nopage || (fsp->hsfs_nohsnode >= nhsnode)) {
		/* remove this node from the hash list, if it's there */
		for (tp = &fsp->hsfs_hash[HS_HPASH(hp)]; *tp != NULL;
			tp = &(*tp)->hs_hash) {

			if (*tp == hp) {
				*tp = hp->hs_hash;
				break;
			}
		}

		if (hp->hs_dirent.sym_link != (char *)NULL) {
			kmem_free(hp->hs_dirent.sym_link,
				(size_t)(hp->hs_dirent.ext_size + 1));
			hp->hs_dirent.sym_link = NULL;
		}
		if (vn_has_cached_data(vp)) {
			/* clean all old pages */
			(void) pvn_vplist_dirty(vp, (u_offset_t)0,
			    hsfs_putapage, B_INVAL, (struct cred *)NULL);
			/* XXX - can we remove pages by fiat like this??? */
			vp->v_pages = NULL;
		}
		mutex_destroy(&hp->hs_contents_lock);
		vn_invalid(vp);
		vn_free(vp);
		kmem_cache_free(hsnode_cache, hp);
		fsp->hsfs_nohsnode--;
		return;
	}
	hs_addfreeb(fsp, hp); /* add to back of free list */
}

/*
 * hs_remakenode
 *
 * Reconstruct a vnode given the location of its directory entry.
 * Caller specifies the the block number and offset
 * of the directory entry, and the vfs pointer.
 * Returns an error code or 0.
 */
int
hs_remakenode(uint_t lbn, uint_t off, struct vfs *vfsp,
    struct vnode **vpp)
{
	struct buf *secbp;
	struct hsfs *fsp;
	uint_t secno;
	uchar_t *dirp;
	struct hs_direntry hd;
	int error;

	/* Convert to sector and offset */
	fsp = VFS_TO_HSFS(vfsp);
	if (off > HS_SECTOR_SIZE) {
		cmn_err(CE_WARN, "hs_remakenode: bad offset");
		error = EINVAL;
		goto end;
	}
	secno = LBN_TO_SEC(lbn, vfsp);
	secbp = bread(fsp->hsfs_devvp->v_rdev, secno * 4, HS_SECTOR_SIZE);

	error = geterror(secbp);
	if (error != 0) {
		cmn_err(CE_NOTE, "hs_remakenode: bread: error=(%d)", error);
		goto end;
	}

	dirp = (uchar_t *)secbp->b_un.b_addr;
	error = hs_parsedir(fsp, &dirp[off], &hd, (char *)NULL, (int *)NULL);
	if (!error) {
		*vpp = hs_makenode(&hd, lbn, off, vfsp);
		if (*vpp == NULL)
			error = ENFILE;
	}

end:
	brelse(secbp);
	return (error);
}


/*
 * hs_dirlook
 *
 * Look for a given name in a given directory.
 * If found, construct an hsnode for it.
 */
int
hs_dirlook(
	struct vnode	*dvp,
	char		*name,
	int		namlen,		/* length of 'name' */
	struct vnode	**vpp,
	struct cred	*cred)
{
	struct hsnode *dhp;
	struct hsfs	*fsp;
	int		error = 0;
	uint_t		offset;		/* real offset in directory */
	uint_t		last_offset;	/* last index into current dir block */
	char		*cmpname;	/* case-folded name */
	int		cmpname_size;	/* how much memory we allocate for it */
	int		cmpnamelen;
	int		adhoc_search;	/* did we start at begin of dir? */
	int		end;
	uint_t		hsoffset;
	struct fbuf	*fbp;
	int		bytes_wanted;
	int		dirsiz;
	int		is_rrip;

	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	if (error = hs_access(dvp, (mode_t)VEXEC, cred))
		return (error);

	if (hsfs_use_dnlc && (*vpp = dnlc_lookup(dvp, name)))
		return (0);

	dhp = VTOH(dvp);
	fsp = VFS_TO_HSFS(dvp->v_vfsp);

	cmpname_size = (int)(fsp->hsfs_namemax + 1);
	cmpname = kmem_alloc((size_t)cmpname_size, KM_SLEEP);

	is_rrip = IS_RRIP_IMPLEMENTED(fsp);

	if (namlen >= cmpname_size)
		namlen = cmpname_size - 1;
	/*
	 * For the purposes of comparing the name against dir entries,
	 * fold it to upper case.
	 */
	if (is_rrip) {
		(void) strcpy(cmpname, name);
		cmpnamelen = namlen;
	} else {
		/*
		 * If we don't consider a trailing dot as part of the filename,
		 * remove it from the specified name
		 */
		if ((fsp->hsfs_flags & HSFSMNT_NOTRAILDOT) &&
			name[namlen-1] == '.' &&
				CAN_TRUNCATE_DOT(name, namlen))
			name[--namlen] = '\0';
		cmpnamelen = hs_uppercase_copy(name, cmpname, namlen);
	}

	/* make sure dirent is filled up with all info */
	if (dhp->hs_dirent.ext_size == 0)
		hs_filldirent(dvp, &dhp->hs_dirent);

	/*
	 * No lock is needed - hs_offset is used as starting
	 * point for searching the directory.
	 */
	offset = dhp->hs_offset;
	hsoffset = offset;
	adhoc_search = (offset != 0);

	end = dhp->hs_dirent.ext_size;
	dirsiz = end;

tryagain:

	while (offset < end) {

		if ((offset & MAXBMASK) + MAXBSIZE > dirsiz)
			bytes_wanted = dirsiz - (offset & MAXBMASK);
		else
			bytes_wanted = MAXBSIZE;

		error = fbread(dvp, (offset_t)(offset & MAXBMASK),
			(unsigned int)bytes_wanted, S_READ, &fbp);
		if (error)
			goto done;

		last_offset = (offset & MAXBMASK) + fbp->fb_count - 1;

#define	rel_offset(offset) ((offset) & MAXBOFFSET)  /* index into cur blk */

		switch (process_dirblock(fbp, &offset,
					last_offset, cmpname,
					cmpnamelen, fsp, dhp, dvp,
					vpp, &error, is_rrip)) {
		case FOUND_ENTRY:
			/* found an entry, either correct or not */
			goto done;

		case WENT_PAST:
			/*
			 * If we get here we know we didn't find it on the
			 * first pass. If adhoc_search, then we started a
			 * bit into the dir, and need to wrap around and
			 * search the first entries.  If not, then we started
			 * at the beginning and didn't find it.
			 */
			if (adhoc_search) {
				offset = 0;
				end = hsoffset;
				adhoc_search = 0;
				goto tryagain;
			}
			error = ENOENT;
			goto done;

		case HIT_END:
			goto tryagain;
		}
	}
	/*
	 * End of all dir blocks, didn't find entry.
	 */
	if (adhoc_search) {
		offset = 0;
		end = hsoffset;
		adhoc_search = 0;
		goto tryagain;
	}
	error = ENOENT;
done:
	/*
	 * If we found the entry, add it to the DNLC
	 * If the entry is a device file (assuming we support Rock Ridge),
	 * we enter the device vnode to the cache since that is what
	 * is in *vpp.
	 * That is ok since the CD-ROM is read-only, so (dvp,name) will
	 * always point to the same device.
	 */
	if (hsfs_use_dnlc && !error)
		dnlc_enter(dvp, name, *vpp);

	kmem_free(cmpname, (size_t)cmpname_size);

	return (error);
}

/*
 * hs_parsedir
 *
 * Parse a Directory Record into an hs_direntry structure.
 * High Sierra and ISO directory are almost the same
 * except the flag and date
 */
int
hs_parsedir(
	struct hsfs		*fsp,
	uchar_t			*dirp,
	struct hs_direntry	*hdp,
	char			*dnp,
	int			*dnlen)
{
	char	*on_disk_name;
	int	on_disk_namelen;
	uchar_t	flags;
	int	namelen;
	int	error;
	int	name_change_flag = 0;	/* set if name was gotten in SUA */

	hdp->ext_lbn = HDE_EXT_LBN(dirp);
	hdp->ext_size = HDE_EXT_SIZE(dirp);
	hdp->xar_len = HDE_XAR_LEN(dirp);
	hdp->intlf_sz = HDE_INTRLV_SIZE(dirp);
	hdp->intlf_sk = HDE_INTRLV_SKIP(dirp);
	hdp->sym_link = (char *)NULL;

	if (fsp->hsfs_vol_type == HS_VOL_TYPE_HS) {
		flags = HDE_FLAGS(dirp);
		hs_parse_dirdate(HDE_cdate(dirp), &hdp->cdate);
		hs_parse_dirdate(HDE_cdate(dirp), &hdp->adate);
		hs_parse_dirdate(HDE_cdate(dirp), &hdp->mdate);
		if ((flags & hde_prohibited) == 0) {
			/*
			 * Skip files with the associated bit set.
			 */
			if (flags & HDE_ASSOCIATED)
				return (EAGAIN);
			hdp->type = VREG;
			hdp->mode = HFREG;
			hdp->nlink = 1;
		} else if ((flags & hde_prohibited) == HDE_DIRECTORY) {
			hdp->type = VDIR;
			hdp->mode = HFDIR;
			hdp->nlink = 2;
		} else {
			hs_log_bogus_disk_warning(fsp,
				HSFS_ERR_UNSUP_TYPE, flags);
			return (EINVAL);
		}
		hdp->uid = fsp -> hsfs_vol.vol_uid;
		hdp->gid = fsp -> hsfs_vol.vol_gid;
		hdp->mode = hdp-> mode | (fsp -> hsfs_vol.vol_prot & 0777);
	} else if (fsp->hsfs_vol_type == HS_VOL_TYPE_ISO) {
		flags = IDE_FLAGS(dirp);
		hs_parse_dirdate(IDE_cdate(dirp), &hdp->cdate);
		hs_parse_dirdate(IDE_cdate(dirp), &hdp->adate);
		hs_parse_dirdate(IDE_cdate(dirp), &hdp->mdate);

		if ((flags & ide_prohibited) == 0) {
			/*
			 * Skip files with the associated bit set.
			 */
			if (flags & IDE_ASSOCIATED)
				return (EAGAIN);
			hdp->type = VREG;
			hdp->mode = HFREG;
			hdp->nlink = 1;
		} else if ((flags & ide_prohibited) == IDE_DIRECTORY) {
			hdp->type = VDIR;
			hdp->mode = HFDIR;
			hdp->nlink = 2;
		} else {
			hs_log_bogus_disk_warning(fsp,
				HSFS_ERR_UNSUP_TYPE, flags);
			return (EINVAL);
		}
		hdp->uid = fsp -> hsfs_vol.vol_uid;
		hdp->gid = fsp -> hsfs_vol.vol_gid;
		hdp->mode = hdp-> mode | (fsp -> hsfs_vol.vol_prot & 0777);

		/*
		 * Having this all filled in, let's see if we have any
		 * SUA susp to look at.
		 */
		if (IS_SUSP_IMPLEMENTED(fsp)) {
			error = parse_sua((uchar_t *)dnp, dnlen,
					&name_change_flag, dirp, hdp, fsp,
					(uchar_t *)NULL, NULL);
			if (error) {
				if (hdp->sym_link) {
					kmem_free(hdp->sym_link,
						(size_t)(hdp->ext_size + 1));
					hdp->sym_link = (char *)NULL;
				}
				return (error);
			}
		}
	}
	hdp->xar_prot = (HDE_PROTECTION & flags) != 0;

#if dontskip
	if (hdp->xar_len > 0) {
		cmn_err(CE_NOTE, "hsfs: extended attributes not supported");
		return (EINVAL);
	}
#endif

	/* check interleaf size and skip factor */
	/* must both be zero or non-zero */
	if (hdp->intlf_sz + hdp->intlf_sk) {
		if ((hdp->intlf_sz == 0) || (hdp->intlf_sk == 0)) {
			cmn_err(CE_NOTE,
				"hsfs: interleaf size or skip factor error");
			return (EINVAL);
		}
		if (hdp->ext_size == 0) {
			cmn_err(CE_NOTE,
			    "hsfs: interleaving specified on zero length file");
			return (EINVAL);
		}
	}

	if (HDE_VOL_SET(dirp) != 1) {
		if (fsp->hsfs_vol.vol_set_size != 1 &&
		    fsp->hsfs_vol.vol_set_size != HDE_VOL_SET(dirp)) {
			cmn_err(CE_NOTE, "hsfs: multivolume file?");
			return (EINVAL);
		}
	}

	/*
	 * If the name changed, then the NM field for RRIP was hit and
	 * we should not copy the name again, just return.
	 */
	if (NAME_HAS_CHANGED(name_change_flag))
		return (0);

	/* return the pointer to the directory name and its length */
	on_disk_name = (char *)HDE_name(dirp);
	on_disk_namelen = (int)HDE_NAME_LEN(dirp);

	if (((int)(fsp->hsfs_namemax) > 0) &&
			(on_disk_namelen > (int)(fsp->hsfs_namemax))) {
		hs_log_bogus_disk_warning(fsp, HSFS_ERR_BAD_FILE_LEN, 0);
		on_disk_namelen = fsp->hsfs_namemax;
	}
	if (dnp != NULL) {
		namelen = hs_namecopy(on_disk_name, dnp, on_disk_namelen,
		    fsp->hsfs_flags);
		if ((fsp->hsfs_flags & HSFSMNT_NOTRAILDOT) &&
		    dnp[ namelen-1 ] == '.' && CAN_TRUNCATE_DOT(dnp, namelen))
			dnp[ --namelen ] = '\0';
	} else
		namelen = on_disk_namelen;
	if (dnlen != NULL)
		*dnlen = namelen;

	return (0);
}

/*
 * hs_namecopy
 *
 * Parse a file/directory name into UNIX form.
 * Delete trailing blanks, upper-to-lower case, add NULL terminator.
 * Returns the (possibly new) length.
 */
int
hs_namecopy(char *from, char *to, int size, ulong_t flags)
{
	uint_t i;
	uchar_t c;
	int lastspace;
	int maplc;

	/* special handling for '.' and '..' */
	if (size == 1) {
		if (*from == '\0') {
			*to++ = '.';
			*to = '\0';
			return (1);
		} else if (*from == '\1') {
			*to++ = '.';
			*to++ = '.';
			*to = '\0';
			return (2);
		}
	}

	maplc = (flags & HSFSMNT_NOMAPLCASE) == 0;
	for (i = 0, lastspace = -1; i < size; i++) {
		c = from[i];
		if (c == ';')
			break;
		if (c <= ' ') {
			if (lastspace == -1)
				lastspace = i;
		} else
			lastspace = -1;
		if (maplc && (c >= 'A') && (c <= 'Z'))
			c += 'a' - 'A';
		to[i] = c;
	}
	if (lastspace != -1)
		i = lastspace;
	to[i] = '\0';
	return (i);
}

/*
 * map a filename to upper case;
 * return 1 if found lowercase character
 */
static int
uppercase_cp(char *from, char *to, int size)
{
	uint_t i;
	uchar_t c;
	uchar_t had_lc = 0;

	for (i = 0; i < size; i++) {
		c = *from++;
		if ((c >= 'a') && (c <= 'z')) {
			c -= ('a' - 'A');
			had_lc = 1;
		}
		*to++ = c;
	}
	return (had_lc);
}

/*
 * hs_uppercase_copy
 *
 * Convert a UNIX-style name into its HSFS equivalent.
 * Map to upper case.
 * Returns the (possibly new) length.
 */
int
hs_uppercase_copy(char *from, char *to, int size)
{
	uint_t i;
	uchar_t c;

	/* special handling for '.' and '..' */

	if (size == 1 && *from == '.') {
		*to = '\0';
		return (1);
	} else if (size == 2 && *from == '.' && *(from+1) == '.') {
		*to = '\1';
		return (1);
	}

	for (i = 0; i < size; i++) {
		c = *from++;
		if ((c >= 'a') && (c <= 'z'))
			c = c - 'a' + 'A';
		*to++ = c;
	}
	return (size);
}

void
hs_filldirent(struct vnode *vp, struct hs_direntry *hdp)
{
	struct buf *secbp;
	uint_t	secno;
	offset_t secoff;
	struct hsfs *fsp;
	uchar_t *secp;
	int	error;

	if (vp->v_type != VDIR) {
		cmn_err(CE_WARN, "hsfs_filldirent: vp (0x%p) not a directory",
			(void *)vp);
		return;
	}

	fsp = VFS_TO_HSFS(vp ->v_vfsp);
	secno = LBN_TO_SEC(hdp->ext_lbn+hdp->xar_len, vp->v_vfsp);
	secoff = LBN_TO_BYTE(hdp->ext_lbn+hdp->xar_len, vp->v_vfsp) &
			MAXHSOFFSET;
	secbp = bread(fsp->hsfs_devvp->v_rdev, secno * 4, HS_SECTOR_SIZE);
	error = geterror(secbp);
	if (error != 0) {
		cmn_err(CE_NOTE, "hs_filldirent: bread: error=(%d)", error);
		goto end;
	}

	secp = (uchar_t *)secbp->b_un.b_addr;

	/* quick check */
	if (hdp->ext_lbn != HDE_EXT_LBN(&secp[secoff])) {
		cmn_err(CE_NOTE, "hsfs_filldirent: dirent not match");
		/* keep on going */
	}
	(void) hs_parsedir(fsp, &secp[secoff], hdp, (char *)NULL, (int *)NULL);

end:
	brelse(secbp);
}

/*
 * Look through a directory block for a matching entry.
 * Note: this routine does an fbrelse() on the buffer passed in.
 */
static enum dirblock_result
process_dirblock(
	struct fbuf	*fbp,		/* buffer containing dirblk */
	uint_t		*offset,	/* lower index */
	uint_t		last_offset,	/* upper index */
	char		*nm,		/* upcase nm to compare against */
	int		nmlen,		/* length of name */
	struct hsfs	*fsp,
	struct hsnode	*dhp,
	struct vnode	*dvp,
	struct vnode	**vpp,
	int		*error,		/* return value: errno */
	int		is_rrip)	/* 1 if rock ridge is implemented */
{
	uchar_t		*blkp = (uchar_t *)fbp->fb_addr; /* dir block */
	char		*dname;		/* name in directory entry */
	int		dnamelen;	/* length of name */
	struct hs_direntry hd;
	int		hdlen;
	uchar_t		*dirp;	/* the directory entry */
	int		res;
	int		parsedir_res;
	size_t		rrip_name_size;
	int		rr_namelen;
	char		*rrip_name_str = NULL;
	char		*rrip_tmp_name = NULL;
	enum dirblock_result err = 0;
	int 		did_fbrelse = 0;
	char		uppercase_name[ISO_FILE_NAMELEN];

	/* return after performing cleanup-on-exit */
#define	PD_return(retval)	{ err = retval; goto do_ret; }

	if (is_rrip) {
		rrip_name_size = RRIP_FILE_NAMELEN + 1;
		rrip_name_str = kmem_alloc(rrip_name_size, KM_SLEEP);
		rrip_tmp_name = kmem_alloc(rrip_name_size, KM_SLEEP);
		rrip_name_str[0] = '\0';
		rrip_tmp_name[0] = '\0';
	}

	while (*offset < last_offset) {

		/*
		 * Directory Entries cannot span sectors.
		 * Unused bytes at the end of each sector are zeroed.
		 * Therefore, detect this condition when the size
		 * field of the directory entry is zero.
		 */
		hdlen = (int)((uchar_t)
				HDE_DIR_LEN(&blkp[rel_offset(*offset)]));
		if (hdlen == 0) {
			/* advance to next sector boundary */
			*offset = (*offset & MAXHSMASK) + HS_SECTOR_SIZE;

			if (*offset > last_offset) {
				/* end of block */
				PD_return(HIT_END)
			} else
				continue;
		}

		/*
		 * Zero out the hd to read new directory
		 */
		bzero(&hd, sizeof (hd));

		/*
		 * Just ignore invalid directory entries.
		 * XXX - maybe hs_parsedir() will detect EXISTENCE bit
		 */
		dirp = &blkp[rel_offset(*offset)];
		dname = (char *)HDE_name(dirp);
		dnamelen = (int)((uchar_t)HDE_NAME_LEN(dirp));
		if (dnamelen > (int)(fsp->hsfs_namemax)) {
			hs_log_bogus_disk_warning(fsp,
				HSFS_ERR_BAD_FILE_LEN, 0);
			dnamelen = fsp->hsfs_namemax;
		}

		/*
		 * If the rock ridge is implemented, then we copy the name
		 * from the SUA area to rrip_name_str. If no Alternate
		 * name is found, then use the uppercase NM in the
		 * rrip_name_str char array.
		 */
		if (is_rrip) {

			rrip_name_str[0] = '\0';
			rr_namelen = rrip_namecopy(nm, &rrip_name_str[0],
			    &rrip_tmp_name[0], dirp, fsp, &hd);
			if (hd.sym_link) {
				kmem_free(hd.sym_link,
				    (size_t)(hd.ext_size+1));
				hd.sym_link = (char *)NULL;
			}

			if (rr_namelen != -1) {
				dname = (char *)&rrip_name_str[0];
				dnamelen = rr_namelen;
			}
		}

		if (!is_rrip || rr_namelen == -1) {
			/* use iso name instead */

			int i;
			/*
			 * make sure that we get rid of ';' in the dname of
			 * an iso direntry, as we should have no knowledge
			 * of file versions.
			 */

			for (i = dnamelen - 1;
			    (dname[i] != ';') && (i > 0);
			    i--)
				continue;

			if (dname[i] == ';')
				dnamelen = i;
			else
				dnamelen = strip_trailing(fsp, dname, dnamelen);

			if (uppercase_cp(dname, uppercase_name, dnamelen))
				hs_log_bogus_disk_warning(fsp,
					HSFS_ERR_LOWER_CASE_NM, 0);
			dname = uppercase_name;
			if (! is_rrip &&
				(fsp->hsfs_flags & HSFSMNT_NOTRAILDOT) &&
					dname[ dnamelen-1 ] == '.' &&
					CAN_TRUNCATE_DOT(dname, dnamelen))
				dname[ --dnamelen ] = '\0';
		}

		/*
		 * Quickly screen for a non-matching entry, but not for RRIP.
		 * This test doesn't work for lowercase vs. uppercase names.
		 */

		/* if we saw a lower case name we can't do this test either */
		if (strict_iso9660_ordering && !is_rrip &&
			!HSFS_HAVE_LOWER_CASE(fsp) && *nm < *dname) {
			RESTORE_NM(rrip_tmp_name, nm);
			PD_return(WENT_PAST)
		}

		if (*nm != *dname || nmlen != dnamelen) {
			/* look at next dir entry */
			RESTORE_NM(rrip_tmp_name, nm);
			*offset += hdlen;
			continue;
		}

		if ((res = nmcmp(dname, nm, nmlen, is_rrip)) == 0) {
			/* name matches */
			parsedir_res =
				hs_parsedir(fsp, dirp, &hd, (char *)NULL,
					    (int *)NULL);
			if (!parsedir_res) {
				uint_t lbn;	/* logical block number */

				lbn = dhp->hs_dirent.ext_lbn +
					dhp->hs_dirent.xar_len;
				/*
				 * Need to do an fbrelse() on the buffer,
				 * as hs_makenode() may try to acquire
				 * hs_hashlock, which may not be required
				 * while a page is locked.
				 */
				fbrelse(fbp, S_READ);
				did_fbrelse = 1;
				*vpp = hs_makenode(&hd, lbn,
						*offset, dvp->v_vfsp);
				if (*vpp == NULL) {
					*error = ENFILE;
					RESTORE_NM(rrip_tmp_name, nm);
					PD_return(FOUND_ENTRY)
				}

				dhp->hs_offset = *offset;
				RESTORE_NM(rrip_tmp_name, nm);
				PD_return(FOUND_ENTRY)
			} else if (parsedir_res != EAGAIN) {
				/* improper dir entry */
				*error = parsedir_res;
				RESTORE_NM(rrip_tmp_name, nm);
				PD_return(FOUND_ENTRY)
			}
		} else if (strict_iso9660_ordering && !is_rrip &&
			!HSFS_HAVE_LOWER_CASE(fsp) && res < 0) {
			/* name < dir entry */
			RESTORE_NM(rrip_tmp_name, nm);
			PD_return(WENT_PAST)
		}
		/*
		 * name > dir entry,
		 * look at next one.
		 */
		*offset += hdlen;
		RESTORE_NM(rrip_tmp_name, nm);
	}
	PD_return(HIT_END)

do_ret:
	if (rrip_name_str)
		kmem_free(rrip_name_str, rrip_name_size);
	if (rrip_tmp_name)
		kmem_free(rrip_tmp_name, rrip_name_size);
	if (! did_fbrelse)
		fbrelse(fbp, S_READ);
	return (err);
#undef PD_return
}


/*
 * Compare the names, returning < 0 if a < b,
 * 0 if a == b, and > 0 if a > b.
 */
static int
nmcmp(char *a, char *b, int len, int is_rrip)
{
	while (len--) {
		if (*a == *b) {
			b++; a++;
		} else {
			/* if file version, stop */
			if (! is_rrip && ((*a == ';') && (*b == '\0')))
				return (0);
			return ((uchar_t)*b - (uchar_t)*a);
		}
	}
	return (0);
}

/*
 * Strip trailing nulls or spaces from the name;
 * return adjusted length.  If we find such junk,
 * log a non-conformant disk message.
 */
static int
strip_trailing(struct hsfs *fsp, char *nm, int len)
{
	char *c;
	int trailing_junk = 0;

	for (c = nm + len - 1; c > nm; c--) {
		if (*c == ' ' || *c == '\0')
			trailing_junk = 1;
		else
			break;
	}

	if (trailing_junk)
		hs_log_bogus_disk_warning(fsp, HSFS_ERR_TRAILING_JUNK, 0);

	return ((int)(c - nm + 1));
}
