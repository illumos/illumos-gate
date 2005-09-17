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
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/fs/xmem.h>

static int xdircheckpath(struct xmemnode *, struct xmemnode *, struct cred *);
static int xdirrename(struct xmemnode *, struct xmemnode *, struct xmemnode *,
	char *, struct xmemnode *, struct xdirent *, struct cred *);
static void xdirfixdotdot(struct xmemnode *, struct xmemnode *,
	struct xmemnode *);
static int xdirmakexnode(struct xmemnode *, struct xmount *,
	struct vattr *, enum de_op, struct xmemnode **, struct cred *);
static int xdiraddentry(struct xmemnode *, struct xmemnode *, char *,
	enum de_op, struct xmemnode *);


#define	X_HASH_SIZE	8192		/* must be power of 2 */
#define	X_MUTEX_SIZE	64

static struct xdirent	*x_hashtable[X_HASH_SIZE];
static kmutex_t		 x_hashmutex[X_MUTEX_SIZE];

#define	X_HASH_INDEX(a)		((a) & (X_HASH_SIZE-1))
#define	X_MUTEX_INDEX(a)	((a) & (X_MUTEX_SIZE-1))

#define	XMEMFS_HASH(xp, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = ((uintptr_t)(xp)) >> 8;			\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
	}

void
xmemfs_hash_init(void)
{
	int	ix;

	for (ix = 0; ix < X_MUTEX_SIZE; ix++)
		mutex_init(&x_hashmutex[ix], NULL, MUTEX_DEFAULT, NULL);
}

/*
 * This routine is where the rubber meets the road for identities.
 */
static void
xmemfs_hash_in(struct xdirent *x)
{
	uint_t		hash;
	struct xdirent	**prevpp;
	kmutex_t	*t_hmtx;

	XMEMFS_HASH(x->xd_parent, x->xd_name, hash);
	x->xd_hash = hash;
	prevpp = &x_hashtable[X_HASH_INDEX(hash)];
	t_hmtx = &x_hashmutex[X_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	x->xd_link = *prevpp;
	*prevpp = x;
	mutex_exit(t_hmtx);
}

/*
 * Remove xdirent *t from the hash list.
 */
static void
xmemfs_hash_out(struct xdirent *x)
{
	uint_t		hash;
	struct xdirent	**prevpp;
	kmutex_t	*t_hmtx;

	hash = x->xd_hash;
	prevpp = &x_hashtable[X_HASH_INDEX(hash)];
	t_hmtx = &x_hashmutex[X_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	while (*prevpp != x)
		prevpp = &(*prevpp)->xd_link;
	*prevpp = x->xd_link;
	mutex_exit(t_hmtx);
}

static struct xdirent *
xmemfs_hash_lookup(char *name, struct xmemnode *parent, uint_t hold,
	struct xmemnode **found)
{
	struct xdirent	*l;
	uint_t		hash;
	kmutex_t	*t_hmtx;
	struct xmemnode	*xp;

	XMEMFS_HASH(parent, name, hash);
	t_hmtx = &x_hashmutex[X_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	l = x_hashtable[X_HASH_INDEX(hash)];
	while (l) {
		if ((l->xd_hash == hash) &&
		    (l->xd_parent == parent) &&
		    (strcmp(l->xd_name, name) == 0)) {
			/*
			 * We need to make sure that the xmemnode that
			 * we put a hold on is the same one that we pass back.
			 * Hence, temporary variable xp is necessary.
			 * The right way to fix this would be to add the t_hmtx
			 * lock acquisition to callers like tdirrename, so
			 * that this race condition doesn't occur.  But
			 * this "fix" is simpler, and less of a performance
			 * impact.
			 */
			xp = l->xd_xmemnode;
			if (hold) {
				ASSERT(xp);
				xmemnode_hold(xp);
			}
			if (found)
				*found = xp;
			mutex_exit(t_hmtx);
			return (l);
		} else {
			l = l->xd_link;
		}
	}
	mutex_exit(t_hmtx);
	return (NULL);
}

/*
 * Search directory 'parent' for entry 'name'.
 *
 * The calling thread can't hold the write version
 * of the rwlock for the directory being searched
 *
 * 0 is returned on success and *foundxp points
 * to the found xmemnode with its vnode held.
 */
int
xdirlookup(
	struct xmemnode *parent,
	char *name,
	struct xmemnode **foundxp,
	struct cred *cred)
{
	int error;

	*foundxp = NULL;
	if (parent->xn_type != VDIR)
		return (ENOTDIR);

	if ((error = xmem_xaccess(parent, VEXEC, cred)))
		return (error);

	if (*name == '\0') {
		xmemnode_hold(parent);
		*foundxp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name
	 * We need the lock protecting the xn_dir list
	 * so that it doesn't change out from underneath us.
	 * xmemfs_hash_lookup() will pass back the xmemnode
	 * with a hold on it.
	 */

	if (xmemfs_hash_lookup(name, parent, 1, foundxp) != NULL) {
		ASSERT(*foundxp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Enter a directory entry for 'name' and 'xp' into directory 'dir'
 *
 * Returns 0 on success.
 */
int
xdirenter(
	struct xmount	*xm,
	struct xmemnode	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	struct xmemnode	*fromparent,	/* source directory if rename */
	struct xmemnode	*xp,		/* source xmemnode, if link/rename */
	struct vattr	*va,
	struct xmemnode	**xpp,		/* return xmemnode, if create/mkdir */
	struct cred	*cred)
{
	struct xdirent *xdp;
	struct xmemnode *found = NULL;
	int error = 0;
	char *s;

	/*
	 * xn_rwlock is held to serialize direnter and dirdeletes
	 */
	ASSERT(RW_WRITE_HELD(&dir->xn_rwlock));
	ASSERT(dir->xn_type == VDIR);

	/*
	 * Don't allow '/' characters in pathname component
	 * (thus in ufs_direnter()).
	 */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	ASSERT(name[0] != '\0');

	/*
	 * For link and rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.
	 */
	if (op == DE_LINK || op == DE_RENAME) {
		mutex_enter(&xp->xn_tlock);
		if (xp->xn_nlink == 0) {
			mutex_exit(&xp->xn_tlock);
			return (ENOENT);
		}

		if (xp->xn_nlink == MAXLINK) {
			mutex_exit(&xp->xn_tlock);
			return (EMLINK);
		}
		xp->xn_nlink++;
		mutex_exit(&xp->xn_tlock);
		gethrestime(&xp->xn_ctime);
	}

	/*
	 * This might be a "dangling detached directory".
	 * it could have been removed, but a reference
	 * to it kept in u_cwd.  don't bother searching
	 * it, and with any luck the user will get tired
	 * of dealing with us and cd to some absolute
	 * pathway.  *sigh*, thus in ufs, too.
	 */
	if (dir->xn_nlink == 0) {
		error = ENOENT;
		goto out;
	}

	/*
	 * If this is a rename of a directory and the parent is
	 * different (".." must be changed), then the source
	 * directory must not be in the directory hierarchy
	 * above the target, as this would orphan everything
	 * below the source directory.
	 */
	if (op == DE_RENAME) {
		if (xp == dir) {
			error = EINVAL;
			goto out;
		}
		if (xp->xn_type == VDIR) {
			if ((fromparent != dir) &&
			    (error = xdircheckpath(xp, dir, cred))) {
				goto out;
			}
		}
	}

	/*
	 * Search for the entry.  Return "found" if it exists.
	 */
	xdp = xmemfs_hash_lookup(name, dir, 1, &found);

	if (xdp) {
		ASSERT(found);
		switch (op) {
		case DE_CREATE:
		case DE_MKDIR:
			if (xpp) {
				*xpp = found;
				error = EEXIST;
			} else {
				xmemnode_rele(found);
			}
			break;

		case DE_RENAME:
			error = xdirrename(fromparent, xp,
			    dir, name, found, xdp, cred);
			xmemnode_rele(found);
			break;

		case DE_LINK:
			/*
			 * Can't link to an existing file.
			 */
			error = EEXIST;
			xmemnode_rele(found);
			break;
		}
	} else {

		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (error = xmem_xaccess(dir, VWRITE, cred))
			goto out;
		if (op == DE_CREATE || op == DE_MKDIR) {
			/*
			 * Make new xmemnode and directory entry as required.
			 */
			error = xdirmakexnode(dir, xm, va, op, &xp, cred);
			if (error)
				goto out;
		}
		if (error = xdiraddentry(dir, xp, name, op, fromparent)) {
			if (op == DE_CREATE || op == DE_MKDIR) {
				/*
				 * Unmake the inode we just made.
				 */
				rw_enter(&xp->xn_rwlock, RW_WRITER);
				if ((xp->xn_type) == VDIR) {
					ASSERT(xdp == NULL);
					/*
					 * cleanup allocs made by xdirinit()
					 */
					xdirtrunc(xp);
				}
				mutex_enter(&xp->xn_tlock);
				xp->xn_nlink = 0;
				mutex_exit(&xp->xn_tlock);
				gethrestime(&xp->xn_ctime);
				rw_exit(&xp->xn_rwlock);
				xmemnode_rele(xp);
				xp = NULL;
			}
		} else if (xpp) {
			*xpp = xp;
		} else if (op == DE_CREATE || op == DE_MKDIR) {
			xmemnode_rele(xp);
		}
	}
out:
	if (error && (op == DE_LINK || op == DE_RENAME)) {
		/*
		 * Undo bumped link count.
		 */
		DECR_COUNT(&xp->xn_nlink, &xp->xn_tlock);
		gethrestime(&xp->xn_ctime);
	}
	return (error);
}

/*
 * Delete entry xp of name "nm" from dir.
 * Free dir entry space and decrement link count on xmemnode(s).
 *
 * Return 0 on success.
 */
int
xdirdelete(
	struct xmemnode *dir,
	struct xmemnode *xp,
	char *nm,
	enum dr_op op,
	struct cred *cred)
{
	register struct xdirent *tpdp;
	int error;
	size_t namelen;
	struct xmemnode *xptmp;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->xn_rwlock));
	ASSERT(RW_WRITE_HELD(&xp->xn_rwlock));
	ASSERT(dir->xn_type == VDIR);

	ASSERT(nm[0] != '\0');

	/*
	 * return error when removing . and ..
	 */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	if (error = xmem_xaccess(dir, VEXEC|VWRITE, cred))
		return (error);

	/*
	 * If the parent directory is "sticky", then the user must
	 * own the parent directory or the file in it, or else must
	 * have permission to write the file.  Otherwise it may not
	 * be deleted (except by privileged users).  Same as ufs_dirremove.
	 */
	if (error = xmem_sticky_remove_access(dir, xp, cred))
		return (error);

	if (dir->xn_dir == NULL)
		return (ENOENT);

	tpdp = xmemfs_hash_lookup(nm, dir, 0, &xptmp);
	if (tpdp == NULL) {
		/*
		 * If it is gone, some other thread got here first!
		 * Return error ENOENT.
		 */
		return (ENOENT);
	}

	/*
	 * If the xmemnode in the xdirent changed, we were probably
	 * the victim of a concurrent rename operation.  The original
	 * is gone, so return that status (same as UFS).
	 */
	if (xp != xptmp)
		return (ENOENT);

	xmemfs_hash_out(tpdp);

	/*
	 * Take tpdp out of the directory list.
	 */
	ASSERT(tpdp->xd_next != tpdp);
	ASSERT(tpdp->xd_prev != tpdp);
	if (tpdp->xd_prev) {
		tpdp->xd_prev->xd_next = tpdp->xd_next;
	}
	if (tpdp->xd_next) {
		tpdp->xd_next->xd_prev = tpdp->xd_prev;
	}

	/*
	 * If the roving slot pointer happens to match tpdp,
	 * point it at the previous dirent.
	 */
	if (dir->xn_dir->xd_prev == tpdp) {
		dir->xn_dir->xd_prev = tpdp->xd_prev;
	}
	ASSERT(tpdp->xd_next != tpdp);
	ASSERT(tpdp->xd_prev != tpdp);

	/*
	 * tpdp points to the correct directory entry
	 */
	namelen = strlen(tpdp->xd_name) + 1;

	xmem_memfree(tpdp, sizeof (struct xdirent) + namelen);
	dir->xn_size -= (sizeof (struct xdirent) + namelen);
	dir->xn_dirents--;

	gethrestime(&now);
	dir->xn_mtime = now;
	dir->xn_ctime = now;
	xp->xn_ctime = now;

	ASSERT(xp->xn_nlink > 0);
	DECR_COUNT(&xp->xn_nlink, &xp->xn_tlock);
	if (op == DR_RMDIR && xp->xn_type == VDIR) {
		xdirtrunc(xp);
		ASSERT(xp->xn_nlink == 0);
	}
	return (0);
}

/*
 * xdirinit is used internally to initialize a directory (dir)
 * with '.' and '..' entries without checking permissions and locking
 */
void
xdirinit(
	struct xmemnode *parent,	/* parent of directory to initialize */
	struct xmemnode *dir)		/* the new directory */
{
	struct xdirent *dot, *dotdot;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&parent->xn_rwlock));
	ASSERT(dir->xn_type == VDIR);

	dot = xmem_memalloc(sizeof (struct xdirent) + 2, 1);
	dotdot = xmem_memalloc(sizeof (struct xdirent) + 3, 1);

	/*
	 * Initialize the entries
	 */
	dot->xd_xmemnode = dir;
	dot->xd_offset = 0;
	dot->xd_name = (char *)dot + sizeof (struct xdirent);
	dot->xd_name[0] = '.';
	dot->xd_parent = dir;
	xmemfs_hash_in(dot);

	dotdot->xd_xmemnode = parent;
	dotdot->xd_offset = 1;
	dotdot->xd_name = (char *)dotdot + sizeof (struct xdirent);
	dotdot->xd_name[0] = '.';
	dotdot->xd_name[1] = '.';
	dotdot->xd_parent = dir;
	xmemfs_hash_in(dotdot);

	/*
	 * Initialize directory entry list.
	 */
	dot->xd_next = dotdot;
	dot->xd_prev = dotdot;	/* dot's xd_prev holds roving slot pointer */
	dotdot->xd_next = NULL;
	dotdot->xd_prev = dot;
	INCR_COUNT(&parent->xn_nlink, &parent->xn_tlock);

	dir->xn_dir = dot;
	dir->xn_size = 2 * sizeof (struct xdirent) + 5;	/* dot and dotdot */
	dir->xn_dirents = 2;
	dir->xn_nlink = 2;	/* one for daddy, and one just for being me */

	gethrestime(&now);
	dir->xn_mtime = now;
	dir->xn_ctime = now;
	parent->xn_ctime = now;
}

/*
 * xdirtrunc is called to remove all directory entries under this directory.
 * The files themselves are removed elsewhere.
 */
void
xdirtrunc(struct xmemnode *dir)
{
	register struct xdirent *xdp;
	size_t namelen;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->xn_rwlock));
	ASSERT(dir->xn_type == VDIR);

	for (xdp = dir->xn_dir; xdp; xdp = dir->xn_dir) {
		ASSERT(xdp->xd_next != xdp);
		ASSERT(xdp->xd_prev != xdp);
		ASSERT(xdp->xd_xmemnode);
		ASSERT(xdp->xd_xmemnode->xn_nlink > 0);

		dir->xn_dir = xdp->xd_next;
		namelen = strlen(xdp->xd_name) + 1;

		DECR_COUNT(&xdp->xd_xmemnode->xn_nlink,
		    &xdp->xd_xmemnode->xn_tlock);

		xmemfs_hash_out(xdp);

		xmem_memfree(xdp, sizeof (struct xdirent) + namelen);
		dir->xn_size -= (sizeof (struct xdirent) + namelen);
		dir->xn_dirents--;
	}

	gethrestime(&now);
	dir->xn_mtime = now;
	dir->xn_ctime = now;

	ASSERT(dir->xn_dir == NULL);
	ASSERT(dir->xn_size == 0);
	ASSERT(dir->xn_dirents == 0);
}

/*
 * Check if the source directory is in the path of the target directory.
 * The target directory is locked by the caller.
 */
static int
xdircheckpath(
	struct xmemnode *fromxp,
	struct xmemnode	*toparent,
	struct cred	*cred)
{
	int	error = 0;
	struct xmemnode *dir, *dotdot;
	struct xdirent *xdp;

	ASSERT(RW_WRITE_HELD(&toparent->xn_rwlock));

	xdp = xmemfs_hash_lookup("..", toparent, 1, &dotdot);
	if (xdp == NULL)
		return (ENOENT);

	ASSERT(dotdot);

	if (dotdot == toparent) {
		/* root of fs.  search trivially satisfied. */
		xmemnode_rele(dotdot);
		return (0);
	}
	for (;;) {
		/*
		 * Return error for cases like "mv c c/d",
		 * "mv c c/d/e" and so on.
		 */
		if (dotdot == fromxp) {
			xmemnode_rele(dotdot);
			error = EINVAL;
			break;
		}
		dir = dotdot;
		error = xdirlookup(dir, "..", &dotdot, cred);
		if (error) {
			xmemnode_rele(dir);
			break;
		}
		/*
		 * We're okay if we traverse the directory tree up to
		 * the root directory and don't run into the
		 * parent directory.
		 */
		if (dir == dotdot) {
			xmemnode_rele(dir);
			xmemnode_rele(dotdot);
			break;
		}
		xmemnode_rele(dir);
	}
	return (error);
}

static int
xdirrename(
	struct xmemnode *fromparent,	/* parent directory of source */
	struct xmemnode *fromxp,	/* source xmemnode */
	struct xmemnode *toparent,	/* parent directory of target */
	char *nm,			/* entry we are trying to change */
	struct xmemnode *to,		/* target xmemnode */
	struct xdirent *where,		/* target xmemnode directory entry */
	struct cred *cred)		/* credentials */
{
	int error = 0;
	int doingdirectory;
	timestruc_t now;

#if defined(lint)
	nm = nm;
#endif
	ASSERT(RW_WRITE_HELD(&toparent->xn_rwlock));

	rw_enter(&fromxp->xn_rwlock, RW_READER);
	rw_enter(&to->xn_rwlock, RW_READER);

	/*
	 * Check that everything is on the same filesystem.
	 */
	if (to->xn_vnode->v_vfsp != toparent->xn_vnode->v_vfsp ||
	    to->xn_vnode->v_vfsp != fromxp->xn_vnode->v_vfsp) {
		error = EXDEV;
		goto out;
	}

	/*
	 * Short circuit rename of something to itself.
	 */
	if (fromxp == to) {
		error = ESAME;		/* special KLUDGE error code */
		goto out;
	}

	/*
	 * Must have write permission to rewrite target entry.
	 */
	if (error = xmem_xaccess(fromparent, VWRITE, cred))
		goto out;

	/*
	 * If the parent directory is "sticky", then the user must own
	 * either the parent directory or the destination of the rename,
	 * or else must have permission to write the destination.
	 * Otherwise the destination may not be changed (except by the
	 * privileged users).  This implements append-only directories.
	 */
	if (error = xmem_sticky_remove_access(toparent, to, cred))
		goto out;

	/*
	 * Ensure source and target are compatible (both directories
	 * or both not directories).  If target is a directory it must
	 * be empty and have no links to it; in addition it must not
	 * be a mount point, and both the source and target must be
	 * writable.
	 */
	doingdirectory = (fromxp->xn_type == VDIR);
	if (to->xn_type == VDIR) {
		if (!doingdirectory) {
			error = EISDIR;
			goto out;
		}
		/*
		 * vn_vfswlock will prevent mounts from using the directory
		 * until we are done.
		 */
		if (vn_vfswlock(XNTOV(to))) {
			error = EBUSY;
			goto out;
		}
		if (vn_mountedvfs(XNTOV(to)) != NULL) {
			vn_vfsunlock(XNTOV(to));
			error = EBUSY;
			goto out;
		}

		mutex_enter(&to->xn_tlock);
		if (to->xn_dirents > 2 || to->xn_nlink > 2) {
			mutex_exit(&to->xn_tlock);
			vn_vfsunlock(XNTOV(to));
			error = EEXIST; /* SIGH should be ENOTEMPTY */
			/*
			 * Update atime because checking xn_dirents is
			 * logically equivalent to reading the directory
			 */
			gethrestime(&to->xn_atime);
			goto out;
		}
		mutex_exit(&to->xn_tlock);
	} else if (doingdirectory) {
		error = ENOTDIR;
		goto out;
	}

	where->xd_xmemnode = fromxp;
	gethrestime(&now);
	toparent->xn_mtime = now;
	toparent->xn_ctime = now;

	/*
	 * Upgrade to write lock on "to" (i.e., the target xmemnode).
	 */
	rw_exit(&to->xn_rwlock);
	rw_enter(&to->xn_rwlock, RW_WRITER);

	/*
	 * Decrement the link count of the target xmemnode.
	 */
	DECR_COUNT(&to->xn_nlink, &to->xn_tlock);
	to->xn_ctime = now;

	if (doingdirectory) {
		/*
		 * The entry for "to" no longer exists so release the vfslock.
		 */
		vn_vfsunlock(XNTOV(to));

		/*
		 * Decrement the target link count and delete all entires.
		 */
		xdirtrunc(to);
		ASSERT(to->xn_nlink == 0);

		/*
		 * Renaming a directory with the parent different
		 * requires that ".." be rewritten.  The window is
		 * still there for ".." to be inconsistent, but this
		 * is unavoidable, and a lot shorter than when it was
		 * done in a user process.
		 */
		if (fromparent != toparent)
			xdirfixdotdot(fromxp, fromparent, toparent);
	}
out:
	rw_exit(&to->xn_rwlock);
	rw_exit(&fromxp->xn_rwlock);
	return (error);
}

static void
xdirfixdotdot(
	struct xmemnode	*fromxp,	/* child directory */
	struct xmemnode	*fromparent,	/* old parent directory */
	struct xmemnode	*toparent)	/* new parent directory */
{
	struct xdirent	*dotdot;

	ASSERT(RW_LOCK_HELD(&toparent->xn_rwlock));

	/*
	 * Increment the link count in the new parent xmemnode
	 */
	INCR_COUNT(&toparent->xn_nlink, &toparent->xn_tlock);
	gethrestime(&toparent->xn_ctime);

	dotdot = xmemfs_hash_lookup("..", fromxp, 0, NULL);

	ASSERT(dotdot->xd_xmemnode == fromparent);
	dotdot->xd_xmemnode = toparent;

	/*
	 * Decrement the link count of the old parent xmemnode.
	 * If fromparent is NULL, then this is a new directory link;
	 * it has no parent, so we need not do anything.
	 */
	if (fromparent != NULL) {
		mutex_enter(&fromparent->xn_tlock);
		if (fromparent->xn_nlink != 0) {
			fromparent->xn_nlink--;
			gethrestime(&fromparent->xn_ctime);
		}
		mutex_exit(&fromparent->xn_tlock);
	}
}

static int
xdiraddentry(
	struct xmemnode	*dir,	/* target directory to make entry in */
	struct xmemnode	*xp,	/* new xmemnode */
	char		*name,
	enum de_op	op,
	struct xmemnode	*fromxp)
{
	struct xdirent *xdp, *tpdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent directory wasn't removed from
	 * underneath the caller.
	 */
	if (dir->xn_dir == NULL)
		return (ENOENT);

	/*
	 * Check that everything is on the same filesystem.
	 */
	if (xp->xn_vnode->v_vfsp != dir->xn_vnode->v_vfsp)
		return (EXDEV);

	/*
	 * Allocate and initialize directory entry
	 */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (struct xdirent);
	xdp = xmem_memalloc(alloc_size, 0);
	if (xdp == NULL)
		return (ENOSPC);

	if ((op == DE_RENAME) && (xp->xn_type == VDIR))
		xdirfixdotdot(xp, fromxp, dir);

	dir->xn_size += alloc_size;
	dir->xn_dirents++;
	xdp->xd_xmemnode = xp;
	xdp->xd_parent = dir;

	/*
	 * The directory entry and its name were allocated sequentially.
	 */
	xdp->xd_name = (char *)xdp + sizeof (struct xdirent);
	(void) strcpy(xdp->xd_name, name);

	xmemfs_hash_in(xdp);

	/*
	 * Some utilities expect the size of a directory to remain
	 * somewhat static.  For example, a routine which unlinks
	 * files between calls to readdir(); the size of the
	 * directory changes from underneath it and so the real
	 * directory offset in bytes is invalid.  To circumvent
	 * this problem, we initialize a directory entry with an
	 * phony offset, and use this offset to determine end of
	 * file in xmem_readdir.
	 */
	tpdp = dir->xn_dir->xd_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (tpdp->xd_next != NULL && (tpdp->xd_next->xd_offset -
	    tpdp->xd_offset) <= 1) {
		ASSERT(tpdp->xd_next != tpdp);
		ASSERT(tpdp->xd_prev != tpdp);
		ASSERT(tpdp->xd_next->xd_offset > tpdp->xd_offset);
		tpdp = tpdp->xd_next;
	}
	xdp->xd_offset = tpdp->xd_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which
	 * is necessarily the largest offset in this directory) is more
	 * than twice the number of dirents, that means the directory is
	 * 50% holes.  At this point we reset the slot pointer back to
	 * the beginning of the directory so we start using the holes.
	 * The idea is that if there are N dirents, there must also be
	 * N holes, so we can satisfy the next N creates by walking at
	 * most 2N entries; thus the average cost of a create is constant.
	 * Note that we use the first dirent's xd_prev as the roving
	 * slot pointer; it's ugly, but it saves a word in every dirent.
	 */
	if (tpdp->xd_next == NULL && tpdp->xd_offset > 2 * dir->xn_dirents)
		dir->xn_dir->xd_prev = dir->xn_dir->xd_next;
	else
		dir->xn_dir->xd_prev = xdp;

	ASSERT(tpdp->xd_next != tpdp);
	ASSERT(tpdp->xd_prev != tpdp);

	xdp->xd_next = tpdp->xd_next;
	if (xdp->xd_next) {
		xdp->xd_next->xd_prev = xdp;
	}
	xdp->xd_prev = tpdp;
	tpdp->xd_next = xdp;

	ASSERT(xdp->xd_next != xdp);
	ASSERT(xdp->xd_prev != xdp);
	ASSERT(tpdp->xd_next != tpdp);
	ASSERT(tpdp->xd_prev != tpdp);

	gethrestime(&now);
	dir->xn_mtime = now;
	dir->xn_ctime = now;

	return (0);
}

static int
xdirmakexnode(
	struct xmemnode *dir,
	struct xmount	*xm,
	struct vattr	*va,
	enum	de_op	op,
	struct xmemnode **newnode,
	struct cred	*cred)
{
	struct xmemnode *xp;
	enum vtype	type;

	ASSERT(va != NULL);
	ASSERT(op == DE_CREATE || op == DE_MKDIR);
	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);
	type = va->va_type;
	xp = xmem_memalloc(sizeof (struct xmemnode), 1);
	xp->xn_vnode = vn_alloc(KM_SLEEP);
	xmemnode_init(xm, xp, va, cred);
	if (type == VBLK || type == VCHR) {
		xp->xn_vnode->v_rdev = xp->xn_rdev = va->va_rdev;
	} else {
		xp->xn_vnode->v_rdev = xp->xn_rdev = NODEV;
	}
	xp->xn_vnode->v_type = type;
	xp->xn_uid = crgetuid(cred);

	/*
	 * To determine the group-id of the created file:
	 *   1) If the gid is set in the attribute list (non-Sun & pre-4.0
	 *	clients are not likely to set the gid), then use it if
	 *	the process is privileged, belongs to the target group,
	 *	or the group is the same as the parent directory.
	 *   2) If the filesystem was not mounted with the Old-BSD-compatible
	 *	GRPID option, and the directory's set-gid bit is clear,
	 *	then use the process's gid.
	 *   3) Otherwise, set the group-id to the gid of the parent directory.
	 */
	if ((va->va_mask & AT_GID) &&
	    ((va->va_gid == dir->xn_gid) || groupmember(va->va_gid, cred) ||
	    secpolicy_vnode_create_gid(cred) == 0)) {
		xp->xn_gid = va->va_gid;
	} else {
		if (dir->xn_mode & VSGID)
			xp->xn_gid = dir->xn_gid;
		else
			xp->xn_gid = crgetgid(cred);
	}
	/*
	 * If we're creating a directory, and the parent directory has the
	 * set-GID bit set, set it on the new directory.
	 * Otherwise, if the user is neither privileged nor a member of the
	 * file's new group, clear the file's set-GID bit.
	 */
	if (dir->xn_mode & VSGID && type == VDIR)
		xp->xn_mode |= VSGID;
	else if ((xp->xn_mode & VSGID) &&
		secpolicy_vnode_setids_setgids(cred, xp->xn_gid) != 0)
			xp->xn_mode &= ~VSGID;

	if (va->va_mask & AT_ATIME)
		xp->xn_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		xp->xn_mtime = va->va_mtime;

	if (op == DE_MKDIR)
		xdirinit(dir, xp);

	*newnode = xp;
	return (0);
}
