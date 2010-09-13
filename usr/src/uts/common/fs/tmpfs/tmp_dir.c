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
#include <sys/fs/tmpnode.h>
#include <sys/fs/tmp.h>
#include <sys/vtrace.h>

static int tdircheckpath(struct tmpnode *, struct tmpnode *, struct cred *);
static int tdirrename(struct tmpnode *, struct tmpnode *, struct tmpnode *,
	char *, struct tmpnode *, struct tdirent *, struct cred *);
static void tdirfixdotdot(struct tmpnode *, struct tmpnode *, struct tmpnode *);
static int tdirmaketnode(struct tmpnode *, struct tmount *, struct vattr *,
	enum de_op, struct tmpnode **, struct cred *);
static int tdiraddentry(struct tmpnode *, struct tmpnode *, char *,
	enum de_op, struct tmpnode *);


#define	T_HASH_SIZE	8192		/* must be power of 2 */
#define	T_MUTEX_SIZE	64

static struct tdirent	*t_hashtable[T_HASH_SIZE];
static kmutex_t		 t_hashmutex[T_MUTEX_SIZE];

#define	T_HASH_INDEX(a)		((a) & (T_HASH_SIZE-1))
#define	T_MUTEX_INDEX(a)	((a) & (T_MUTEX_SIZE-1))

#define	TMPFS_HASH(tp, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = (uint_t)(uintptr_t)(tp) >> 8;		\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
	}

void
tmpfs_hash_init(void)
{
	int	ix;

	for (ix = 0; ix < T_MUTEX_SIZE; ix++)
		mutex_init(&t_hashmutex[ix], NULL, MUTEX_DEFAULT, NULL);
}

/*
 * This routine is where the rubber meets the road for identities.
 */
static void
tmpfs_hash_in(struct tdirent *t)
{
	uint_t		hash;
	struct tdirent	**prevpp;
	kmutex_t	*t_hmtx;

	TMPFS_HASH(t->td_parent, t->td_name, hash);
	t->td_hash = hash;
	prevpp = &t_hashtable[T_HASH_INDEX(hash)];
	t_hmtx = &t_hashmutex[T_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	t->td_link = *prevpp;
	*prevpp = t;
	mutex_exit(t_hmtx);
}

/*
 * Remove tdirent *t from the hash list.
 */
static void
tmpfs_hash_out(struct tdirent *t)
{
	uint_t		hash;
	struct tdirent	**prevpp;
	kmutex_t	*t_hmtx;

	hash = t->td_hash;
	prevpp = &t_hashtable[T_HASH_INDEX(hash)];
	t_hmtx = &t_hashmutex[T_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	while (*prevpp != t)
		prevpp = &(*prevpp)->td_link;
	*prevpp = t->td_link;
	mutex_exit(t_hmtx);
}

/*
 * Currently called by tdirrename() only.
 * rename operation needs to be done with lock held, to ensure that
 * no other operations can access the tmpnode at the same instance.
 */
static void
tmpfs_hash_change(struct tdirent *tdp, struct tmpnode *fromtp)
{
	uint_t		hash;
	kmutex_t	*t_hmtx;

	hash = tdp->td_hash;
	t_hmtx = &t_hashmutex[T_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	tdp->td_tmpnode = fromtp;
	mutex_exit(t_hmtx);
}

static struct tdirent *
tmpfs_hash_lookup(char *name, struct tmpnode *parent, uint_t hold,
	struct tmpnode **found)
{
	struct tdirent	*l;
	uint_t		hash;
	kmutex_t	*t_hmtx;
	struct tmpnode	*tnp;

	TMPFS_HASH(parent, name, hash);
	t_hmtx = &t_hashmutex[T_MUTEX_INDEX(hash)];
	mutex_enter(t_hmtx);
	l = t_hashtable[T_HASH_INDEX(hash)];
	while (l) {
		if ((l->td_hash == hash) &&
		    (l->td_parent == parent) &&
		    (strcmp(l->td_name, name) == 0)) {
			/*
			 * We need to make sure that the tmpnode that
			 * we put a hold on is the same one that we pass back.
			 * Hence, temporary variable tnp is necessary.
			 */
			tnp = l->td_tmpnode;
			if (hold) {
				ASSERT(tnp);
				tmpnode_hold(tnp);
			}
			if (found)
				*found = tnp;
			mutex_exit(t_hmtx);
			return (l);
		} else {
			l = l->td_link;
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
 * 0 is returned on success and *foundtp points
 * to the found tmpnode with its vnode held.
 */
int
tdirlookup(
	struct tmpnode *parent,
	char *name,
	struct tmpnode **foundtp,
	struct cred *cred)
{
	int error;

	*foundtp = NULL;
	if (parent->tn_type != VDIR)
		return (ENOTDIR);

	if ((error = tmp_taccess(parent, VEXEC, cred)))
		return (error);

	if (*name == '\0') {
		tmpnode_hold(parent);
		*foundtp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name
	 * We need the lock protecting the tn_dir list
	 * so that it doesn't change out from underneath us.
	 * tmpfs_hash_lookup() will pass back the tmpnode
	 * with a hold on it.
	 */

	if (tmpfs_hash_lookup(name, parent, 1, foundtp) != NULL) {
		ASSERT(*foundtp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Enter a directory entry for 'name' and 'tp' into directory 'dir'
 *
 * Returns 0 on success.
 */
int
tdirenter(
	struct tmount	*tm,
	struct tmpnode	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	struct tmpnode	*fromparent,	/* source directory if rename */
	struct tmpnode	*tp,		/* source tmpnode, if link/rename */
	struct vattr	*va,
	struct tmpnode	**tpp,		/* return tmpnode, if create/mkdir */
	struct cred	*cred,
	caller_context_t *ctp)
{
	struct tdirent *tdp;
	struct tmpnode *found = NULL;
	int error = 0;
	char *s;

	/*
	 * tn_rwlock is held to serialize direnter and dirdeletes
	 */
	ASSERT(RW_WRITE_HELD(&dir->tn_rwlock));
	ASSERT(dir->tn_type == VDIR);

	/*
	 * Don't allow '/' characters in pathname component
	 * (thus in ufs_direnter()).
	 */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	if (name[0] == '\0')
		panic("tdirenter: NULL name");

	/*
	 * For link and rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.
	 */
	if (op == DE_LINK || op == DE_RENAME) {
		if (tp != dir)
			rw_enter(&tp->tn_rwlock, RW_WRITER);
		mutex_enter(&tp->tn_tlock);
		if (tp->tn_nlink == 0) {
			mutex_exit(&tp->tn_tlock);
			if (tp != dir)
				rw_exit(&tp->tn_rwlock);
			return (ENOENT);
		}

		if (tp->tn_nlink == MAXLINK) {
			mutex_exit(&tp->tn_tlock);
			if (tp != dir)
				rw_exit(&tp->tn_rwlock);
			return (EMLINK);
		}
		tp->tn_nlink++;
		gethrestime(&tp->tn_ctime);
		mutex_exit(&tp->tn_tlock);
		if (tp != dir)
			rw_exit(&tp->tn_rwlock);
	}

	/*
	 * This might be a "dangling detached directory".
	 * it could have been removed, but a reference
	 * to it kept in u_cwd.  don't bother searching
	 * it, and with any luck the user will get tired
	 * of dealing with us and cd to some absolute
	 * pathway.  *sigh*, thus in ufs, too.
	 */
	if (dir->tn_nlink == 0) {
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
		if (tp == dir) {
			error = EINVAL;
			goto out;
		}
		if (tp->tn_type == VDIR) {
			if ((fromparent != dir) &&
			    (error = tdircheckpath(tp, dir, cred))) {
				goto out;
			}
		}
	}

	/*
	 * Search for the entry.  Return "found" if it exists.
	 */
	tdp = tmpfs_hash_lookup(name, dir, 1, &found);

	if (tdp) {
		ASSERT(found);
		switch (op) {
		case DE_CREATE:
		case DE_MKDIR:
			if (tpp) {
				*tpp = found;
				error = EEXIST;
			} else {
				tmpnode_rele(found);
			}
			break;

		case DE_RENAME:
			error = tdirrename(fromparent, tp,
			    dir, name, found, tdp, cred);
			if (error == 0) {
				if (found != NULL) {
					vnevent_rename_dest(TNTOV(found),
					    TNTOV(dir), name, ctp);
				}
			}

			tmpnode_rele(found);
			break;

		case DE_LINK:
			/*
			 * Can't link to an existing file.
			 */
			error = EEXIST;
			tmpnode_rele(found);
			break;
		}
	} else {

		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (error = tmp_taccess(dir, VWRITE, cred))
			goto out;
		if (op == DE_CREATE || op == DE_MKDIR) {
			/*
			 * Make new tmpnode and directory entry as required.
			 */
			error = tdirmaketnode(dir, tm, va, op, &tp, cred);
			if (error)
				goto out;
		}
		if (error = tdiraddentry(dir, tp, name, op, fromparent)) {
			if (op == DE_CREATE || op == DE_MKDIR) {
				/*
				 * Unmake the inode we just made.
				 */
				rw_enter(&tp->tn_rwlock, RW_WRITER);
				if ((tp->tn_type) == VDIR) {
					ASSERT(tdp == NULL);
					/*
					 * cleanup allocs made by tdirinit()
					 */
					tdirtrunc(tp);
				}
				mutex_enter(&tp->tn_tlock);
				tp->tn_nlink = 0;
				mutex_exit(&tp->tn_tlock);
				gethrestime(&tp->tn_ctime);
				rw_exit(&tp->tn_rwlock);
				tmpnode_rele(tp);
				tp = NULL;
			}
		} else if (tpp) {
			*tpp = tp;
		} else if (op == DE_CREATE || op == DE_MKDIR) {
			tmpnode_rele(tp);
		}
	}

out:
	if (error && (op == DE_LINK || op == DE_RENAME)) {
		/*
		 * Undo bumped link count.
		 */
		DECR_COUNT(&tp->tn_nlink, &tp->tn_tlock);
		gethrestime(&tp->tn_ctime);
	}
	return (error);
}

/*
 * Delete entry tp of name "nm" from dir.
 * Free dir entry space and decrement link count on tmpnode(s).
 *
 * Return 0 on success.
 */
int
tdirdelete(
	struct tmpnode *dir,
	struct tmpnode *tp,
	char *nm,
	enum dr_op op,
	struct cred *cred)
{
	struct tdirent *tpdp;
	int error;
	size_t namelen;
	struct tmpnode *tnp;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->tn_rwlock));
	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));
	ASSERT(dir->tn_type == VDIR);

	if (nm[0] == '\0')
		panic("tdirdelete: NULL name for %p", (void *)tp);

	/*
	 * return error when removing . and ..
	 */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	if (error = tmp_taccess(dir, VEXEC|VWRITE, cred))
		return (error);

	/*
	 * If the parent directory is "sticky", then the user must
	 * own the parent directory or the file in it, or else must
	 * have permission to write the file.  Otherwise it may not
	 * be deleted (except by privileged users).
	 * Same as ufs_dirremove.
	 */
	if ((error = tmp_sticky_remove_access(dir, tp, cred)) != 0)
		return (error);

	if (dir->tn_dir == NULL)
		return (ENOENT);

	tpdp = tmpfs_hash_lookup(nm, dir, 0, &tnp);
	if (tpdp == NULL) {
		/*
		 * If it is gone, some other thread got here first!
		 * Return error ENOENT.
		 */
		return (ENOENT);
	}

	/*
	 * If the tmpnode in the tdirent changed, we were probably
	 * the victim of a concurrent rename operation.  The original
	 * is gone, so return that status (same as UFS).
	 */
	if (tp != tnp)
		return (ENOENT);

	tmpfs_hash_out(tpdp);

	/*
	 * Take tpdp out of the directory list.
	 */
	ASSERT(tpdp->td_next != tpdp);
	ASSERT(tpdp->td_prev != tpdp);
	if (tpdp->td_prev) {
		tpdp->td_prev->td_next = tpdp->td_next;
	}
	if (tpdp->td_next) {
		tpdp->td_next->td_prev = tpdp->td_prev;
	}

	/*
	 * If the roving slot pointer happens to match tpdp,
	 * point it at the previous dirent.
	 */
	if (dir->tn_dir->td_prev == tpdp) {
		dir->tn_dir->td_prev = tpdp->td_prev;
	}
	ASSERT(tpdp->td_next != tpdp);
	ASSERT(tpdp->td_prev != tpdp);

	/*
	 * tpdp points to the correct directory entry
	 */
	namelen = strlen(tpdp->td_name) + 1;

	tmp_memfree(tpdp, sizeof (struct tdirent) + namelen);
	dir->tn_size -= (sizeof (struct tdirent) + namelen);
	dir->tn_dirents--;

	gethrestime(&now);
	dir->tn_mtime = now;
	dir->tn_ctime = now;
	tp->tn_ctime = now;

	ASSERT(tp->tn_nlink > 0);
	DECR_COUNT(&tp->tn_nlink, &tp->tn_tlock);
	if (op == DR_RMDIR && tp->tn_type == VDIR) {
		tdirtrunc(tp);
		ASSERT(tp->tn_nlink == 0);
	}
	return (0);
}

/*
 * tdirinit is used internally to initialize a directory (dir)
 * with '.' and '..' entries without checking permissions and locking
 */
void
tdirinit(
	struct tmpnode *parent,		/* parent of directory to initialize */
	struct tmpnode *dir)		/* the new directory */
{
	struct tdirent *dot, *dotdot;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&parent->tn_rwlock));
	ASSERT(dir->tn_type == VDIR);

	dot = tmp_memalloc(sizeof (struct tdirent) + 2, TMP_MUSTHAVE);
	dotdot = tmp_memalloc(sizeof (struct tdirent) + 3, TMP_MUSTHAVE);

	/*
	 * Initialize the entries
	 */
	dot->td_tmpnode = dir;
	dot->td_offset = 0;
	dot->td_name = (char *)dot + sizeof (struct tdirent);
	dot->td_name[0] = '.';
	dot->td_parent = dir;
	tmpfs_hash_in(dot);

	dotdot->td_tmpnode = parent;
	dotdot->td_offset = 1;
	dotdot->td_name = (char *)dotdot + sizeof (struct tdirent);
	dotdot->td_name[0] = '.';
	dotdot->td_name[1] = '.';
	dotdot->td_parent = dir;
	tmpfs_hash_in(dotdot);

	/*
	 * Initialize directory entry list.
	 */
	dot->td_next = dotdot;
	dot->td_prev = dotdot;	/* dot's td_prev holds roving slot pointer */
	dotdot->td_next = NULL;
	dotdot->td_prev = dot;

	gethrestime(&now);
	dir->tn_mtime = now;
	dir->tn_ctime = now;

	/*
	 * Link counts are special for the hidden attribute directory.
	 * The only explicit reference in the name space is "." and
	 * the reference through ".." is not counted on the parent
	 * file. The attrdir is created as a side effect to lookup,
	 * so don't change the ctime of the parent.
	 * Since tdirinit is called with both dir and parent being the
	 * same for the root vnode, we need to increment this before we set
	 * tn_nlink = 2 below.
	 */
	if (!(dir->tn_vnode->v_flag & V_XATTRDIR)) {
		INCR_COUNT(&parent->tn_nlink, &parent->tn_tlock);
		parent->tn_ctime = now;
	}

	dir->tn_dir = dot;
	dir->tn_size = 2 * sizeof (struct tdirent) + 5;	/* dot and dotdot */
	dir->tn_dirents = 2;
	dir->tn_nlink = 2;
}


/*
 * tdirtrunc is called to remove all directory entries under this directory.
 */
void
tdirtrunc(struct tmpnode *dir)
{
	struct tdirent *tdp;
	struct tmpnode *tp;
	size_t namelen;
	timestruc_t now;
	int isvattrdir, isdotdot, skip_decr;

	ASSERT(RW_WRITE_HELD(&dir->tn_rwlock));
	ASSERT(dir->tn_type == VDIR);

	isvattrdir = (dir->tn_vnode->v_flag & V_XATTRDIR) ? 1 : 0;
	for (tdp = dir->tn_dir; tdp; tdp = dir->tn_dir) {
		ASSERT(tdp->td_next != tdp);
		ASSERT(tdp->td_prev != tdp);
		ASSERT(tdp->td_tmpnode);

		dir->tn_dir = tdp->td_next;
		namelen = strlen(tdp->td_name) + 1;

		/*
		 * Adjust the link counts to account for this directory
		 * entry removal. Hidden attribute directories may
		 * not be empty as they may be truncated as a side-
		 * effect of removing the parent. We do hold/rele
		 * operations to free up these tmpnodes.
		 *
		 * Skip the link count adjustment for parents of
		 * attribute directories as those link counts
		 * do not include the ".." reference in the hidden
		 * directories.
		 */
		tp = tdp->td_tmpnode;
		isdotdot = (strcmp("..", tdp->td_name) == 0);
		skip_decr = (isvattrdir && isdotdot);
		if (!skip_decr) {
			ASSERT(tp->tn_nlink > 0);
			DECR_COUNT(&tp->tn_nlink, &tp->tn_tlock);
		}

		tmpfs_hash_out(tdp);

		tmp_memfree(tdp, sizeof (struct tdirent) + namelen);
		dir->tn_size -= (sizeof (struct tdirent) + namelen);
		dir->tn_dirents--;
	}

	gethrestime(&now);
	dir->tn_mtime = now;
	dir->tn_ctime = now;

	ASSERT(dir->tn_dir == NULL);
	ASSERT(dir->tn_size == 0);
	ASSERT(dir->tn_dirents == 0);
}

/*
 * Check if the source directory is in the path of the target directory.
 * The target directory is locked by the caller.
 *
 * XXX - The source and target's should be different upon entry.
 */
static int
tdircheckpath(
	struct tmpnode *fromtp,
	struct tmpnode	*toparent,
	struct cred	*cred)
{
	int	error = 0;
	struct tmpnode *dir, *dotdot;
	struct tdirent *tdp;

	ASSERT(RW_WRITE_HELD(&toparent->tn_rwlock));

	tdp = tmpfs_hash_lookup("..", toparent, 1, &dotdot);
	if (tdp == NULL)
		return (ENOENT);

	ASSERT(dotdot);

	if (dotdot == toparent) {
		/* root of fs.  search trivially satisfied. */
		tmpnode_rele(dotdot);
		return (0);
	}
	for (;;) {
		/*
		 * Return error for cases like "mv c c/d",
		 * "mv c c/d/e" and so on.
		 */
		if (dotdot == fromtp) {
			tmpnode_rele(dotdot);
			error = EINVAL;
			break;
		}
		dir = dotdot;
		error = tdirlookup(dir, "..", &dotdot, cred);
		if (error) {
			tmpnode_rele(dir);
			break;
		}
		/*
		 * We're okay if we traverse the directory tree up to
		 * the root directory and don't run into the
		 * parent directory.
		 */
		if (dir == dotdot) {
			tmpnode_rele(dir);
			tmpnode_rele(dotdot);
			break;
		}
		tmpnode_rele(dir);
	}
	return (error);
}

static int
tdirrename(
	struct tmpnode *fromparent,	/* parent directory of source */
	struct tmpnode *fromtp,		/* source tmpnode */
	struct tmpnode *toparent,	/* parent directory of target */
	char *nm,			/* entry we are trying to change */
	struct tmpnode *to,		/* target tmpnode */
	struct tdirent *where,		/* target tmpnode directory entry */
	struct cred *cred)		/* credentials */
{
	int error = 0;
	int doingdirectory;
	timestruc_t now;

#if defined(lint)
	nm = nm;
#endif
	ASSERT(RW_WRITE_HELD(&toparent->tn_rwlock));

	/*
	 * Short circuit rename of something to itself.
	 */
	if (fromtp == to)
		return (ESAME);		/* special KLUDGE error code */

	rw_enter(&fromtp->tn_rwlock, RW_READER);
	rw_enter(&to->tn_rwlock, RW_READER);

	/*
	 * Check that everything is on the same filesystem.
	 */
	if (to->tn_vnode->v_vfsp != toparent->tn_vnode->v_vfsp ||
	    to->tn_vnode->v_vfsp != fromtp->tn_vnode->v_vfsp) {
		error = EXDEV;
		goto out;
	}

	/*
	 * Must have write permission to rewrite target entry.
	 * Check for stickyness.
	 */
	if ((error = tmp_taccess(toparent, VWRITE, cred)) != 0 ||
	    (error = tmp_sticky_remove_access(toparent, to, cred)) != 0)
		goto out;

	/*
	 * Ensure source and target are compatible (both directories
	 * or both not directories).  If target is a directory it must
	 * be empty and have no links to it; in addition it must not
	 * be a mount point, and both the source and target must be
	 * writable.
	 */
	doingdirectory = (fromtp->tn_type == VDIR);
	if (to->tn_type == VDIR) {
		if (!doingdirectory) {
			error = EISDIR;
			goto out;
		}
		/*
		 * vn_vfswlock will prevent mounts from using the directory
		 * until we are done.
		 */
		if (vn_vfswlock(TNTOV(to))) {
			error = EBUSY;
			goto out;
		}
		if (vn_mountedvfs(TNTOV(to)) != NULL) {
			vn_vfsunlock(TNTOV(to));
			error = EBUSY;
			goto out;
		}

		mutex_enter(&to->tn_tlock);
		if (to->tn_dirents > 2 || to->tn_nlink > 2) {
			mutex_exit(&to->tn_tlock);
			vn_vfsunlock(TNTOV(to));
			error = EEXIST; /* SIGH should be ENOTEMPTY */
			/*
			 * Update atime because checking tn_dirents is
			 * logically equivalent to reading the directory
			 */
			gethrestime(&to->tn_atime);
			goto out;
		}
		mutex_exit(&to->tn_tlock);
	} else if (doingdirectory) {
		error = ENOTDIR;
		goto out;
	}

	tmpfs_hash_change(where, fromtp);
	gethrestime(&now);
	toparent->tn_mtime = now;
	toparent->tn_ctime = now;

	/*
	 * Upgrade to write lock on "to" (i.e., the target tmpnode).
	 */
	rw_exit(&to->tn_rwlock);
	rw_enter(&to->tn_rwlock, RW_WRITER);

	/*
	 * Decrement the link count of the target tmpnode.
	 */
	DECR_COUNT(&to->tn_nlink, &to->tn_tlock);
	to->tn_ctime = now;

	if (doingdirectory) {
		/*
		 * The entry for "to" no longer exists so release the vfslock.
		 */
		vn_vfsunlock(TNTOV(to));

		/*
		 * Decrement the target link count and delete all entires.
		 */
		tdirtrunc(to);
		ASSERT(to->tn_nlink == 0);

		/*
		 * Renaming a directory with the parent different
		 * requires that ".." be rewritten.  The window is
		 * still there for ".." to be inconsistent, but this
		 * is unavoidable, and a lot shorter than when it was
		 * done in a user process.
		 */
		if (fromparent != toparent)
			tdirfixdotdot(fromtp, fromparent, toparent);
	}
out:
	rw_exit(&to->tn_rwlock);
	rw_exit(&fromtp->tn_rwlock);
	return (error);
}

static void
tdirfixdotdot(
	struct tmpnode	*fromtp,	/* child directory */
	struct tmpnode	*fromparent,	/* old parent directory */
	struct tmpnode	*toparent)	/* new parent directory */
{
	struct tdirent	*dotdot;

	ASSERT(RW_LOCK_HELD(&toparent->tn_rwlock));

	/*
	 * Increment the link count in the new parent tmpnode
	 */
	INCR_COUNT(&toparent->tn_nlink, &toparent->tn_tlock);
	gethrestime(&toparent->tn_ctime);

	dotdot = tmpfs_hash_lookup("..", fromtp, 0, NULL);

	ASSERT(dotdot->td_tmpnode == fromparent);
	dotdot->td_tmpnode = toparent;

	/*
	 * Decrement the link count of the old parent tmpnode.
	 * If fromparent is NULL, then this is a new directory link;
	 * it has no parent, so we need not do anything.
	 */
	if (fromparent != NULL) {
		mutex_enter(&fromparent->tn_tlock);
		if (fromparent->tn_nlink != 0) {
			fromparent->tn_nlink--;
			gethrestime(&fromparent->tn_ctime);
		}
		mutex_exit(&fromparent->tn_tlock);
	}
}

static int
tdiraddentry(
	struct tmpnode	*dir,	/* target directory to make entry in */
	struct tmpnode	*tp,	/* new tmpnode */
	char		*name,
	enum de_op	op,
	struct tmpnode	*fromtp)
{
	struct tdirent *tdp, *tpdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent directory wasn't removed from
	 * underneath the caller.
	 */
	if (dir->tn_dir == NULL)
		return (ENOENT);

	/*
	 * Check that everything is on the same filesystem.
	 */
	if (tp->tn_vnode->v_vfsp != dir->tn_vnode->v_vfsp)
		return (EXDEV);

	/*
	 * Allocate and initialize directory entry
	 */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (struct tdirent);
	tdp = tmp_memalloc(alloc_size, 0);
	if (tdp == NULL)
		return (ENOSPC);

	if ((op == DE_RENAME) && (tp->tn_type == VDIR))
		tdirfixdotdot(tp, fromtp, dir);

	dir->tn_size += alloc_size;
	dir->tn_dirents++;
	tdp->td_tmpnode = tp;
	tdp->td_parent = dir;

	/*
	 * The directory entry and its name were allocated sequentially.
	 */
	tdp->td_name = (char *)tdp + sizeof (struct tdirent);
	(void) strcpy(tdp->td_name, name);

	tmpfs_hash_in(tdp);

	/*
	 * Some utilities expect the size of a directory to remain
	 * somewhat static.  For example, a routine which unlinks
	 * files between calls to readdir(); the size of the
	 * directory changes from underneath it and so the real
	 * directory offset in bytes is invalid.  To circumvent
	 * this problem, we initialize a directory entry with an
	 * phony offset, and use this offset to determine end of
	 * file in tmp_readdir.
	 */
	tpdp = dir->tn_dir->td_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (tpdp->td_next != NULL && (tpdp->td_next->td_offset -
	    tpdp->td_offset) <= 1) {
		ASSERT(tpdp->td_next != tpdp);
		ASSERT(tpdp->td_prev != tpdp);
		ASSERT(tpdp->td_next->td_offset > tpdp->td_offset);
		tpdp = tpdp->td_next;
	}
	tdp->td_offset = tpdp->td_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which
	 * is necessarily the largest offset in this directory) is more
	 * than twice the number of dirents, that means the directory is
	 * 50% holes.  At this point we reset the slot pointer back to
	 * the beginning of the directory so we start using the holes.
	 * The idea is that if there are N dirents, there must also be
	 * N holes, so we can satisfy the next N creates by walking at
	 * most 2N entries; thus the average cost of a create is constant.
	 * Note that we use the first dirent's td_prev as the roving
	 * slot pointer; it's ugly, but it saves a word in every dirent.
	 */
	if (tpdp->td_next == NULL && tpdp->td_offset > 2 * dir->tn_dirents)
		dir->tn_dir->td_prev = dir->tn_dir->td_next;
	else
		dir->tn_dir->td_prev = tdp;

	ASSERT(tpdp->td_next != tpdp);
	ASSERT(tpdp->td_prev != tpdp);

	tdp->td_next = tpdp->td_next;
	if (tdp->td_next) {
		tdp->td_next->td_prev = tdp;
	}
	tdp->td_prev = tpdp;
	tpdp->td_next = tdp;

	ASSERT(tdp->td_next != tdp);
	ASSERT(tdp->td_prev != tdp);
	ASSERT(tpdp->td_next != tpdp);
	ASSERT(tpdp->td_prev != tpdp);

	gethrestime(&now);
	dir->tn_mtime = now;
	dir->tn_ctime = now;

	return (0);
}

static int
tdirmaketnode(
	struct tmpnode *dir,
	struct tmount	*tm,
	struct vattr	*va,
	enum	de_op	op,
	struct tmpnode **newnode,
	struct cred	*cred)
{
	struct tmpnode *tp;
	enum vtype	type;

	ASSERT(va != NULL);
	ASSERT(op == DE_CREATE || op == DE_MKDIR);
	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);
	type = va->va_type;
	tp = tmp_memalloc(sizeof (struct tmpnode), TMP_MUSTHAVE);
	tmpnode_init(tm, tp, va, cred);

	/* setup normal file/dir's extended attribute directory */
	if (dir->tn_flags & ISXATTR) {
		/* parent dir is , mark file as xattr */
		tp->tn_flags |= ISXATTR;
	}


	if (type == VBLK || type == VCHR) {
		tp->tn_vnode->v_rdev = tp->tn_rdev = va->va_rdev;
	} else {
		tp->tn_vnode->v_rdev = tp->tn_rdev = NODEV;
	}
	tp->tn_vnode->v_type = type;
	tp->tn_uid = crgetuid(cred);

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
	    ((va->va_gid == dir->tn_gid) || groupmember(va->va_gid, cred) ||
	    secpolicy_vnode_create_gid(cred) == 0)) {
		/*
		 * XXX - is this only the case when a 4.0 NFS client, or a
		 * client derived from that code, makes a call over the wire?
		 */
		tp->tn_gid = va->va_gid;
	} else {
		if (dir->tn_mode & VSGID)
			tp->tn_gid = dir->tn_gid;
		else
			tp->tn_gid = crgetgid(cred);
	}
	/*
	 * If we're creating a directory, and the parent directory has the
	 * set-GID bit set, set it on the new directory.
	 * Otherwise, if the user is neither privileged nor a member of the
	 * file's new group, clear the file's set-GID bit.
	 */
	if (dir->tn_mode & VSGID && type == VDIR)
		tp->tn_mode |= VSGID;
	else {
		if ((tp->tn_mode & VSGID) &&
		    secpolicy_vnode_setids_setgids(cred, tp->tn_gid) != 0)
			tp->tn_mode &= ~VSGID;
	}

	if (va->va_mask & AT_ATIME)
		tp->tn_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		tp->tn_mtime = va->va_mtime;

	if (op == DE_MKDIR)
		tdirinit(dir, tp);

	*newnode = tp;
	return (0);
}
