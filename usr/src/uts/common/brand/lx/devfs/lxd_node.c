/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/policy.h>
#include <sys/sdt.h>

#include "lxd.h"

#define	LXD_HASH_SIZE	8192		/* must be power of 2 */
#define	LXD_MUTEX_SIZE	64


#define	MODESHIFT	3

typedef enum lxd_nodehold {
	NOHOLD,
	HOLD
} lxd_nodehold_t;

/*
 * The following functions maintain the per-mount "front" files.
 */
static void
lxd_save_dirent(lxd_dirent_t *de)
{
	lxd_mnt_t	*lxdm = VTOLXDM(LDNTOV(de->lddir_parent));
	uint_t		hash;
	kmutex_t	*hmtx;

	LXD_NM_HASH(de->lddir_parent, de->lddir_name, hash);
	de->lddir_hash = hash;

	hmtx = &lxdm->lxdm_hash_mutex[hash];

	mutex_enter(hmtx);
	ASSERT(de->lddir_link == NULL);
	de->lddir_link = lxdm->lxdm_dent_htable[hash];
	lxdm->lxdm_dent_htable[hash] = de;
	mutex_exit(hmtx);

	atomic_inc_32(&lxdm->lxdm_dent_refcnt);
}

static void
lxd_rm_dirent(lxd_dirent_t *de)
{
	lxd_mnt_t	*lxdm = VTOLXDM(LDNTOV(de->lddir_parent));
	uint_t		hash;
	lxd_dirent_t	**prevpp;
	kmutex_t	*hmtx;

	hash = de->lddir_hash;
	hmtx = &lxdm->lxdm_hash_mutex[hash];

	mutex_enter(hmtx);
	prevpp = &lxdm->lxdm_dent_htable[hash];
	while (*prevpp != de)
		prevpp = &(*prevpp)->lddir_link;
	*prevpp = de->lddir_link;
	de->lddir_link = NULL;
	mutex_exit(hmtx);

	ASSERT(lxdm->lxdm_dent_refcnt > 0);
	atomic_dec_32(&lxdm->lxdm_dent_refcnt);
}

static lxd_dirent_t *
lxd_find_dirent(char *name, lxd_node_t *parent, lxd_nodehold_t do_hold,
    lxd_node_t **found)
{
	lxd_mnt_t	*lxdm = VTOLXDM(LDNTOV(parent));
	lxd_dirent_t	*de;
	uint_t		hash;
	kmutex_t	*hmtx;

	LXD_NM_HASH(parent, name, hash);
	hmtx = &lxdm->lxdm_hash_mutex[hash];

	mutex_enter(hmtx);
	de = lxdm->lxdm_dent_htable[hash];
	while (de) {
		if (de->lddir_hash == hash && de->lddir_parent == parent &&
		    strcmp(de->lddir_name, name) == 0) {
			lxd_node_t *ldn = de->lddir_node;

			if (do_hold == HOLD) {
				ASSERT(ldn != NULL);
				ldnode_hold(ldn);
			}
			if (found != NULL)
				*found = ldn;
			mutex_exit(hmtx);
			return (de);
		}

		de = de->lddir_link;
	}
	mutex_exit(hmtx);
	return (NULL);
}

int
lxd_naccess(void *vcp, int mode, cred_t *cr)
{
	lxd_node_t *ldn = vcp;
	int shift = 0;
	/*
	 * Check access based on owner, group and public perms in lxd_node.
	 */
	if (crgetuid(cr) != ldn->lxdn_uid) {
		shift += MODESHIFT;
		if (groupmember(ldn->lxdn_gid, cr) == 0)
			shift += MODESHIFT;
	}

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (secpolicy_vnode_access2(cr, LDNTOV(ldn),
		    ldn->lxdn_uid, ldn->lxdn_mode << shift, mode));

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	return (VOP_ACCESS(ldn->lxdn_real_vp, mode, 0, cr, NULL));
}

static lxd_node_t *
lxd_find_back(struct vnode *vp, uint_t hash, lxd_mnt_t *lxdm)
{
	lxd_node_t *l;

	ASSERT(MUTEX_HELD(&lxdm->lxdm_hash_mutex[hash]));

	for (l = lxdm->lxdm_back_htable[hash]; l != NULL; l = l->lxdn_hnxt) {
		if (l->lxdn_real_vp == vp) {
			ASSERT(l->lxdn_type == LXDNT_BACK);

			VN_HOLD(LDNTOV(l));
			return (l);
		}
	}
	return (NULL);
}

static void
lxd_save_back(lxd_node_t *l, uint_t hash, lxd_mnt_t *lxdm)
{
	ASSERT(l->lxdn_type == LXDNT_BACK);
	ASSERT(l->lxdn_real_vp != NULL);
	ASSERT(MUTEX_HELD(&lxdm->lxdm_hash_mutex[hash]));

	atomic_inc_32(&lxdm->lxdm_back_refcnt);

	l->lxdn_hnxt = lxdm->lxdm_back_htable[hash];
	lxdm->lxdm_back_htable[hash] = l;
}


struct vnode *
lxd_make_back_node(struct vnode *vp, lxd_mnt_t *lxdm)
{
	uint_t hash;
	kmutex_t *hmtx;
	lxd_node_t *l;

	hash = LXD_BACK_HASH(vp);	/* Note: hashing with realvp */
	hmtx = &lxdm->lxdm_hash_mutex[hash];
	mutex_enter(hmtx);

	l = lxd_find_back(vp, hash, lxdm);
	if (l == NULL) {
		vnode_t *nvp;

		l = kmem_zalloc(sizeof (lxd_node_t), KM_SLEEP);
		nvp = vn_alloc(KM_SLEEP);

		rw_init(&l->lxdn_rwlock, NULL, RW_DEFAULT, NULL);
		mutex_init(&l->lxdn_tlock, NULL, MUTEX_DEFAULT, NULL);

		l->lxdn_vnode = nvp;
		l->lxdn_type = LXDNT_BACK;
		l->lxdn_real_vp = vp;

		VN_SET_VFS_TYPE_DEV(nvp, lxdm->lxdm_vfsp, vp->v_type,
		    vp->v_rdev);
		nvp->v_flag |= (vp->v_flag & (VNOMOUNT|VNOMAP|VDIROPEN));
		vn_setops(nvp, lxd_vnodeops);
		nvp->v_data = (caddr_t)l;

		lxd_save_back(l, hash, lxdm);
		vn_exists(vp);
	} else {
		VN_RELE(vp);
	}

	mutex_exit(hmtx);
	return (LDNTOV(l));
}

void
lxd_free_back_node(lxd_node_t *lp)
{
	uint_t hash;
	kmutex_t *hmtx;
	lxd_node_t *l;
	lxd_node_t *lprev = NULL;
	vnode_t *vp = LDNTOV(lp);
	vnode_t *realvp = REALVP(vp);
	lxd_mnt_t *lxdm = VTOLXDM(vp);

	/* in lxd_make_back_node we call lxd_find_back with the realvp */
	hash = LXD_BACK_HASH(realvp);
	hmtx = &lxdm->lxdm_hash_mutex[hash];
	mutex_enter(hmtx);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		vp->v_count--;	/* release our hold from vn_rele */
		mutex_exit(&vp->v_lock);
		mutex_exit(hmtx);
		return;
	}
	mutex_exit(&vp->v_lock);

	for (l = lxdm->lxdm_back_htable[hash]; l != NULL;
	    lprev = l, l = l->lxdn_hnxt) {

		if (l != lp)
			continue;

		ASSERT(l->lxdn_type == LXDNT_BACK);
		ASSERT(lxdm->lxdm_back_refcnt > 0);

		atomic_dec_32(&lxdm->lxdm_back_refcnt);
		vn_invalid(vp);

		if (lprev == NULL) {
			lxdm->lxdm_back_htable[hash] = l->lxdn_hnxt;
		} else {
			lprev->lxdn_hnxt = l->lxdn_hnxt;
		}

		mutex_exit(hmtx);
		rw_destroy(&l->lxdn_rwlock);
		mutex_destroy(&l->lxdn_tlock);
		kmem_free(l, sizeof (lxd_node_t));
		vn_free(vp);
		VN_RELE(realvp);
		return;
	}

	panic("lxd_free_back_node");
	/*NOTREACHED*/
}
/*
 * Search directory 'parent' for entry 'name'.
 *
 * 0 is returned on success and *foundcp points
 * to the found lxd_node with its vnode held.
 */
int
lxd_dirlookup(lxd_node_t *parent, char *name, lxd_node_t **foundnp, cred_t *cr)
{
	int error;

	*foundnp = NULL;
	if (parent->lxdn_vnode->v_type != VDIR)
		return (ENOTDIR);

	if ((error = lxd_naccess(parent, VEXEC, cr)))
		return (error);

	if (*name == '\0') {
		ldnode_hold(parent);
		*foundnp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name
	 * We need the lock protecting the lxdn_dir list
	 * so that it doesn't change out from underneath us.
	 * lxd_find_dirent() will pass back the lxd_node
	 * with a hold on it.
	 */

	if (lxd_find_dirent(name, parent, HOLD, foundnp) != NULL) {
		ASSERT(*foundnp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Check if the source directory is in the path of the target directory.
 * The target directory is locked by the caller.
 */
static int
lxd_dircheckpath(lxd_node_t *fromnode, lxd_node_t *toparent, cred_t *cr)
{
	int error = 0;
	lxd_node_t *dir, *dotdot;

	ASSERT(RW_WRITE_HELD(&toparent->lxdn_rwlock));
	ASSERT(toparent->lxdn_vnode->v_type == VDIR);

	dotdot = toparent->lxdn_parent;
	if (dotdot == NULL)
		return (ENOENT);
	ldnode_hold(dotdot);

	if (dotdot == toparent) {
		/* root of fs.  search trivially satisfied. */
		ldnode_rele(dotdot);
		return (0);
	}

	for (;;) {
		/*
		 * Return error for cases like "mv c c/d",
		 * "mv c c/d/e" and so on.
		 */
		if (dotdot == fromnode) {
			ldnode_rele(dotdot);
			error = EINVAL;
			break;
		}

		dir = dotdot;
		dotdot = dir->lxdn_parent;
		if (dotdot == NULL) {
			ldnode_rele(dir);
			error = ENOENT;
			break;
		}
		ldnode_hold(dotdot);

		/*
		 * We're okay if we traverse the directory tree up to
		 * the root directory and don't run into the
		 * parent directory.
		 */
		if (dir == dotdot) {
			ldnode_rele(dir);
			ldnode_rele(dotdot);
			break;
		}
		ldnode_rele(dir);
	}

	return (error);
}

static int
lxd_dir_make_node(lxd_node_t *dir, lxd_mnt_t *lxdm, struct vattr *va,
    enum de_op op, lxd_node_t **newnode, struct cred *cred)
{
	lxd_node_t *ldn;

	ASSERT(va != NULL);

	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);

	ldn = kmem_zalloc(sizeof (lxd_node_t), KM_SLEEP);

	ldn->lxdn_type = LXDNT_FRONT;
	lxd_node_init(lxdm, ldn, NULL, va, cred);

	ldn->lxdn_vnode->v_rdev = ldn->lxdn_rdev = NODEV;
	ldn->lxdn_vnode->v_type = va->va_type;
	ldn->lxdn_uid = crgetuid(cred);
	ldn->lxdn_gid = crgetgid(cred);
	ldn->lxdn_nodeid = lxdm->lxdm_gen++;

	if (va->va_mask & AT_ATIME)
		ldn->lxdn_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		ldn->lxdn_mtime = va->va_mtime;

	if (op == DE_MKDIR) {
		lxd_dirinit(dir, ldn, cred);
	}

	*newnode = ldn;
	return (0);
}

static int
lxd_diraddentry(lxd_node_t *dir, lxd_node_t *ldn, char *name, enum de_op op)
{
	lxd_dirent_t	*dp, *pdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent directory wasn't removed from
	 * underneath the caller.
	 */
	if (dir->lxdn_dir == NULL)
		return (ENOENT);

	/* Check that everything is on the same filesystem. */
	if (ldn->lxdn_vnode->v_vfsp != dir->lxdn_vnode->v_vfsp)
		return (EXDEV);

	/* Allocate and initialize directory entry */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (lxd_dirent_t);
	dp = kmem_zalloc(alloc_size, KM_NOSLEEP | KM_NORMALPRI);
	if (dp == NULL)
		return (ENOSPC);

	ldn->lxdn_parent = dir;

	dir->lxdn_size += alloc_size;
	dir->lxdn_dirents++;
	dp->lddir_node = ldn;
	dp->lddir_parent = dir;

	/* The directory entry and its name were allocated sequentially. */
	dp->lddir_name = (char *)dp + sizeof (lxd_dirent_t);
	(void) strcpy(dp->lddir_name, name);

	lxd_save_dirent(dp);

	/*
	 * Some utilities expect the size of a directory to remain
	 * somewhat static.  For example, a routine which removes
	 * subdirectories between calls to readdir(); the size of the
	 * directory changes from underneath it and so the real
	 * directory offset in bytes is invalid.  To circumvent
	 * this problem, we initialize a directory entry with an
	 * phony offset, and use this offset to determine end of
	 * file in lxd_readdir.
	 */
	pdp = dir->lxdn_dir->lddir_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (pdp->lddir_next != NULL &&
	    (pdp->lddir_next->lddir_offset - pdp->lddir_offset) <= 1) {
		ASSERT(pdp->lddir_next != pdp);
		ASSERT(pdp->lddir_prev != pdp);
		ASSERT(pdp->lddir_next->lddir_offset > pdp->lddir_offset);
		pdp = pdp->lddir_next;
	}
	dp->lddir_offset = pdp->lddir_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which
	 * is necessarily the largest offset in this directory) is more
	 * than twice the number of dirents, that means the directory is
	 * 50% holes.  At this point we reset the slot pointer back to
	 * the beginning of the directory so we start using the holes.
	 * The idea is that if there are N dirents, there must also be
	 * N holes, so we can satisfy the next N creates by walking at
	 * most 2N entries; thus the average cost of a create is constant.
	 * Note that we use the first dirent's lddir_prev as the roving
	 * slot pointer; it's ugly, but it saves a word in every dirent.
	 */
	if (pdp->lddir_next == NULL &&
	    pdp->lddir_offset > 2 * dir->lxdn_dirents)
		dir->lxdn_dir->lddir_prev = dir->lxdn_dir->lddir_next;
	else
		dir->lxdn_dir->lddir_prev = dp;

	ASSERT(pdp->lddir_next != pdp);
	ASSERT(pdp->lddir_prev != pdp);

	dp->lddir_next = pdp->lddir_next;
	if (dp->lddir_next) {
		dp->lddir_next->lddir_prev = dp;
	}
	dp->lddir_prev = pdp;
	pdp->lddir_next = dp;

	ASSERT(dp->lddir_next != dp);
	ASSERT(dp->lddir_prev != dp);
	ASSERT(pdp->lddir_next != pdp);
	ASSERT(pdp->lddir_prev != pdp);

	gethrestime(&now);
	dir->lxdn_mtime = now;
	dir->lxdn_ctime = now;

	return (0);
}

/*
 * Enter a directory entry for 'name' into directory 'dir'
 *
 * Returns 0 on success.
 */
int
lxd_direnter(
	lxd_mnt_t	*lxdm,
	lxd_node_t	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	lxd_node_t	*fromparent,    /* original directory if rename */
	lxd_node_t	*ldn,		/* existing lxd_node, if rename */
	struct vattr	*va,
	lxd_node_t	**rnp,		/* return lxd_node, if create/mkdir */
	cred_t		*cr,
	caller_context_t *ctp)
{
	lxd_dirent_t *dirp;
	lxd_node_t *found = NULL;
	int error = 0;
	char *s;

	/* lxdn_rwlock is held to serialize direnter and dirdeletes */
	ASSERT(RW_WRITE_HELD(&dir->lxdn_rwlock));
	ASSERT(dir->lxdn_vnode->v_type == VDIR);

	/*
	 * Don't allow '/' characters in pathname component,
	 */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	if (name[0] == '\0')
		panic("lxd_direnter: NULL name");

	/*
	 * For rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.
	 */
	if (op == DE_RENAME) {
		mutex_enter(&ldn->lxdn_tlock);
		if (ldn->lxdn_nlink == 0) {
			mutex_exit(&ldn->lxdn_tlock);
			return (ENOENT);
		}

		if (ldn->lxdn_nlink == MAXLINK) {
			mutex_exit(&ldn->lxdn_tlock);
			return (EMLINK);
		}
		ldn->lxdn_nlink++;
		gethrestime(&ldn->lxdn_ctime);
		mutex_exit(&ldn->lxdn_tlock);
	}

	/*
	 * This might be a "dangling detached directory" (it could have been
	 * removed, but a reference to it kept in u_cwd). Don't bother
	 * searching it, and with any luck the user will get tired of dealing
	 * with us and cd to some absolute pathway (thus in ufs, too).
	 */
	if (dir->lxdn_nlink == 0) {
		error = ENOENT;
		goto out;
	}

	/*
	 * If this is a rename of a directory and the parent is different
	 * (".." must be changed), then the source directory must not be in the
	 * directory hierarchy above the target, as this would orphan
	 * everything below the source directory.
	 */
	if (op == DE_RENAME) {
		if (ldn == dir) {
			error = EINVAL;
			goto out;
		}
		if ((ldn->lxdn_vnode->v_type) == VDIR) {
			if ((fromparent != dir) &&
			    (error = lxd_dircheckpath(ldn, dir, cr)) != 0) {
				goto out;
			}
		}
	}

	/* Search for an existing entry. */
	dirp = lxd_find_dirent(name, dir, HOLD, &found);
	if (dirp != NULL) {
		ASSERT(found != NULL);
		switch (op) {
		case DE_CREATE:
		case DE_MKDIR:
			if (rnp != NULL) {
				*rnp = found;
				error = EEXIST;
			} else {
				ldnode_rele(found);
			}
			break;

		case DE_RENAME:
			/*
			 * Note that we only hit this path when we're renaming
			 * a symlink from one directory to another and there is
			 * a pre-existing symlink as the target. lxd_rename
			 * will unlink the src from the original directory but
			 * here we need to unlink the dest that we collided
			 * with, then create the new directory entry as we do
			 * below when there is no pre-existing symlink.
			 */
			if ((error = lxd_naccess(dir, VWRITE, cr)) != 0)
				goto out;

			ASSERT(found->lxdn_vnode->v_type == VLNK);
			/* dir rw lock is already held and asserted above */
			rw_enter(&found->lxdn_rwlock, RW_WRITER);
			error = lxd_dirdelete(dir, found, name, DR_RENAME, cr);
			rw_exit(&found->lxdn_rwlock);
			ldnode_rele(found);
			if (error != 0)
				goto out;

			error = lxd_diraddentry(dir, ldn, name, op);
			if (error == 0 && rnp != NULL)
				*rnp = ldn;
			break;
		}
	} else {

		/*
		 * The directory entry does not exist, but the node might if
		 * this is a rename. Check write permission in directory to
		 * see if entry can be created.
		 */
		if ((error = lxd_naccess(dir, VWRITE, cr)) != 0)
			goto out;
		if (op == DE_CREATE || op == DE_MKDIR) {
			/*
			 * Make new lxd_node and directory entry as required.
			 */
			error = lxd_dir_make_node(dir, lxdm, va, op, &ldn, cr);
			if (error)
				goto out;
		}

		error = lxd_diraddentry(dir, ldn, name, op);
		if (error != 0) {
			if (op == DE_CREATE || op == DE_MKDIR) {
				/*
				 * Unmake the inode we just made.
				 */
				rw_enter(&ldn->lxdn_rwlock, RW_WRITER);
				if ((ldn->lxdn_vnode->v_type) == VDIR) {
					ASSERT(dirp == NULL);
					/*
					 * cleanup allocs made by lxd_dirinit
					 */
					lxd_dirtrunc(ldn);
				}
				mutex_enter(&ldn->lxdn_tlock);
				ldn->lxdn_nlink = 0;
				gethrestime(&ldn->lxdn_ctime);
				mutex_exit(&ldn->lxdn_tlock);
				rw_exit(&ldn->lxdn_rwlock);
				ldnode_rele(ldn);
				ldn = NULL;
			}
		} else if (rnp != NULL) {
			*rnp = ldn;
		} else if (op == DE_CREATE || op == DE_MKDIR) {
			ldnode_rele(ldn);
		}
	}

out:
	if (error && op == DE_RENAME) {
		/* Undo bumped link count. */
		mutex_enter(&ldn->lxdn_tlock);
		ldn->lxdn_nlink--;
		gethrestime(&ldn->lxdn_ctime);
		mutex_exit(&ldn->lxdn_tlock);
	}
	return (error);
}

/*
 * Delete entry ldn of name "nm" from parent dir. This is used to both remove
 * a directory and to remove file nodes within the directory (by recursively
 * calling itself). It frees the dir entry space and decrements link count on
 * lxd_node(s).
 *
 * Return 0 on success.
 */
int
lxd_dirdelete(lxd_node_t *dir, lxd_node_t *ldn, char *nm, enum dr_op op,
    cred_t *cred)
{
	lxd_dirent_t *dirp;
	int error;
	size_t namelen;
	lxd_node_t *fndnp;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->lxdn_rwlock));
	ASSERT(RW_WRITE_HELD(&ldn->lxdn_rwlock));
	ASSERT(dir->lxdn_vnode->v_type == VDIR);

	if (nm[0] == '\0')
		panic("lxd_dirdelete: empty name for 0x%p", (void *)ldn);

	/*
	 * return error when removing . and ..
	 */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	if ((error = lxd_naccess(dir, VEXEC|VWRITE, cred)) != 0)
		return (error);

	if (dir->lxdn_dir == NULL)
		return (ENOENT);

	if (op == DR_RMDIR) {
		/*
		 * This is the top-level removal of a directory. Start by
		 * removing any file entries from the dir. We do this by
		 * recursively calling back into this function with a different
		 * op code. The caller of this function has already verified
		 * that it is safe to remove this directory.
		 */
		lxd_dirent_t *dirp;

		ASSERT(ldn->lxdn_vnode->v_type == VDIR);

		dirp = ldn->lxdn_dir;
		while (dirp) {
			lxd_node_t *dn;
			lxd_dirent_t *nextp;

			if (strcmp(dirp->lddir_name, ".") == 0 ||
			    strcmp(dirp->lddir_name, "..") == 0) {
				dirp = dirp->lddir_next;
				continue;
			}

			dn = dirp->lddir_node;
			nextp = dirp->lddir_next;

			ldnode_hold(dn);
			error = lxd_dirdelete(ldn, dn, dirp->lddir_name,
			    DR_REMOVE, cred);
			ldnode_rele(dn);

			dirp = nextp;
		}
	}

	dirp = lxd_find_dirent(nm, dir, NOHOLD, &fndnp);
	VERIFY(dirp != NULL);
	VERIFY(ldn == fndnp);

	lxd_rm_dirent(dirp);

	/* Take dirp out of the directory list. */
	ASSERT(dirp->lddir_next != dirp);
	ASSERT(dirp->lddir_prev != dirp);
	if (dirp->lddir_prev) {
		dirp->lddir_prev->lddir_next = dirp->lddir_next;
	}
	if (dirp->lddir_next) {
		dirp->lddir_next->lddir_prev = dirp->lddir_prev;
	}

	/*
	 * If the roving slot pointer happens to match dirp,
	 * point it at the previous dirent.
	 */
	if (dir->lxdn_dir->lddir_prev == dirp) {
		dir->lxdn_dir->lddir_prev = dirp->lddir_prev;
	}
	ASSERT(dirp->lddir_next != dirp);
	ASSERT(dirp->lddir_prev != dirp);

	/* dirp points to the correct directory entry */
	namelen = strlen(dirp->lddir_name) + 1;

	kmem_free(dirp, sizeof (lxd_dirent_t) + namelen);
	dir->lxdn_size -= (sizeof (lxd_dirent_t) + namelen);
	dir->lxdn_dirents--;

	gethrestime(&now);
	dir->lxdn_mtime = now;
	dir->lxdn_ctime = now;
	ldn->lxdn_ctime = now;

	ASSERT(ldn->lxdn_nlink > 0);
	mutex_enter(&ldn->lxdn_tlock);
	ldn->lxdn_nlink--;
	mutex_exit(&ldn->lxdn_tlock);
	if (op == DR_RMDIR && ldn->lxdn_vnode->v_type == VDIR) {
		lxd_dirtrunc(ldn);
		ASSERT(ldn->lxdn_nlink == 0);
	}
	return (0);
}

/*
 * Initialize a lxd_node and add it to file list under mount point.
 */
void
lxd_node_init(lxd_mnt_t *lxdm, lxd_node_t *ldn, vnode_t *realvp, vattr_t *vap,
    cred_t *cred)
{
	struct vnode *vp;
	timestruc_t now;

	ASSERT(vap != NULL);

	rw_init(&ldn->lxdn_rwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&ldn->lxdn_tlock, NULL, MUTEX_DEFAULT, NULL);
	ldn->lxdn_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	ldn->lxdn_mask = 0;
	ldn->lxdn_attr.va_type = vap->va_type;
	ldn->lxdn_nlink = 1;
	ldn->lxdn_size = 0;

	if (cred == NULL) {
		ldn->lxdn_uid = vap->va_uid;
		ldn->lxdn_gid = vap->va_gid;
	} else {
		ldn->lxdn_uid = crgetuid(cred);
		ldn->lxdn_gid = crgetgid(cred);
	}

	ldn->lxdn_fsid = lxdm->lxdm_dev;
	ldn->lxdn_rdev = vap->va_rdev;
	ldn->lxdn_blksize = PAGESIZE;
	ldn->lxdn_nblocks = 0;
	gethrestime(&now);
	ldn->lxdn_atime = now;
	ldn->lxdn_mtime = now;
	ldn->lxdn_ctime = now;
	ldn->lxdn_seq = 0;
	ldn->lxdn_dir = NULL;

	ldn->lxdn_real_vp = realvp;

	ldn->lxdn_vnode = vn_alloc(KM_SLEEP);
	vp = LDNTOV(ldn);
	vn_setops(vp, lxd_vnodeops);
	vp->v_vfsp = lxdm->lxdm_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)ldn;

	mutex_enter(&lxdm->lxdm_contents);
	ldn->lxdn_nodeid = lxdm->lxdm_gen++;

	/*
	 * Add new lxd_node to end of linked list of lxd_nodes for this
	 * lxdevfs. Root directory is handled specially in lxd_mount.
	 */
	if (lxdm->lxdm_rootnode != (lxd_node_t *)NULL) {
		ldn->lxdn_next = NULL;
		ldn->lxdn_prev = lxdm->lxdm_rootnode->lxdn_prev;
		ldn->lxdn_prev->lxdn_next = lxdm->lxdm_rootnode->lxdn_prev =
		    ldn;
	}
	mutex_exit(&lxdm->lxdm_contents);
	vn_exists(vp);
}

/*
 * lxd_dirinit is used internally to initialize a directory (dir)
 * with '.' and '..' entries without checking permissions and locking
 * It also creates the entries for the pseudo file nodes that reside in the
 * directory.
 */
void
lxd_dirinit(lxd_node_t *parent, lxd_node_t *dir, cred_t *cr)
{
	lxd_dirent_t *dot, *dotdot;
	timestruc_t now;
	lxd_mnt_t *lxdm = VTOLXDM(dir->lxdn_vnode);
	struct vattr nattr;

	ASSERT(RW_WRITE_HELD(&parent->lxdn_rwlock));
	ASSERT(dir->lxdn_vnode->v_type == VDIR);

	dir->lxdn_nodeid = lxdm->lxdm_gen++;

	/*
	 * Initialize the entries
	 */
	dot = kmem_zalloc(sizeof (lxd_dirent_t) + 2, KM_SLEEP);
	dot->lddir_node = dir;
	dot->lddir_offset = 0;
	dot->lddir_name = (char *)dot + sizeof (lxd_dirent_t);
	dot->lddir_name[0] = '.';
	dot->lddir_parent = dir;
	lxd_save_dirent(dot);

	dotdot = kmem_zalloc(sizeof (lxd_dirent_t) + 3, KM_SLEEP);
	dotdot->lddir_node = parent;
	dotdot->lddir_offset = 1;
	dotdot->lddir_name = (char *)dotdot + sizeof (lxd_dirent_t);
	dotdot->lddir_name[0] = '.';
	dotdot->lddir_name[1] = '.';
	dotdot->lddir_parent = dir;
	lxd_save_dirent(dotdot);

	/*
	 * Initialize directory entry list.
	 */
	dot->lddir_next = dotdot;
	dot->lddir_prev = dotdot; /* dot's lddir_prev holds roving slot ptr */
	dotdot->lddir_next = NULL;
	dotdot->lddir_prev = dot;

	gethrestime(&now);
	dir->lxdn_mtime = now;
	dir->lxdn_ctime = now;

	parent->lxdn_nlink++;
	parent->lxdn_ctime = now;

	dir->lxdn_dir = dot;
	dir->lxdn_size = 2 * sizeof (lxd_dirent_t) + 5;	/* dot and dotdot */
	dir->lxdn_dirents = 2;
	dir->lxdn_nlink = 2;
	dir->lxdn_parent = parent;

	bzero(&nattr, sizeof (struct vattr));
	nattr.va_mode = (mode_t)(0644);
	nattr.va_type = VREG;
	nattr.va_rdev = 0;
}

/*
 * lxd_dirtrunc is called to remove all directory entries under this directory.
 */
void
lxd_dirtrunc(lxd_node_t *dir)
{
	lxd_dirent_t *ldp;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->lxdn_rwlock));
	ASSERT(dir->lxdn_vnode->v_type == VDIR);

	for (ldp = dir->lxdn_dir; ldp; ldp = dir->lxdn_dir) {
		size_t namelen;
		lxd_node_t *ldn;

		ASSERT(ldp->lddir_next != ldp);
		ASSERT(ldp->lddir_prev != ldp);
		ASSERT(ldp->lddir_node);

		dir->lxdn_dir = ldp->lddir_next;
		namelen = strlen(ldp->lddir_name) + 1;

		/*
		 * Adjust the link counts to account for this directory entry
		 * removal. We do hold/rele operations to free up these nodes.
		 */
		ldn = ldp->lddir_node;

		ASSERT(ldn->lxdn_nlink > 0);
		mutex_enter(&ldn->lxdn_tlock);
		ldn->lxdn_nlink--;
		mutex_exit(&ldn->lxdn_tlock);

		lxd_rm_dirent(ldp);
		kmem_free(ldp, sizeof (lxd_dirent_t) + namelen);
		dir->lxdn_size -= (sizeof (lxd_dirent_t) + namelen);
		dir->lxdn_dirents--;
	}

	gethrestime(&now);
	dir->lxdn_mtime = now;
	dir->lxdn_ctime = now;

	ASSERT(dir->lxdn_dir == NULL);
	ASSERT(dir->lxdn_size == 0);
	ASSERT(dir->lxdn_dirents == 0);
}
