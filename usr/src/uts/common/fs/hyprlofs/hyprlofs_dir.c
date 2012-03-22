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
 * Copyright 2012, Joyent, Inc.  All rights reserved.
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
#include <sys/policy.h>
#include <sys/fs/hyprlofs_info.h>

static int hldir_make_hlnode(hlnode_t *, hlfsmount_t *, vattr_t *, enum de_op,
		vnode_t *, hlnode_t **, cred_t *);
static int hldiraddentry(hlnode_t *, hlnode_t *, char *);


#define	HL_HASH_SIZE	8192		/* must be power of 2 */
#define	HL_MUTEX_SIZE	64

static hldirent_t	*hl_hashtable[HL_HASH_SIZE];
static kmutex_t		 hl_hashmutex[HL_MUTEX_SIZE];

#define	HL_HASH_INDEX(a)	((a) & (HL_HASH_SIZE-1))
#define	HL_MUTEX_INDEX(a)	((a) & (HL_MUTEX_SIZE-1))

#define	HYPRLOFS_HASH(tp, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = (uint_t)(uintptr_t)(tp) >> 8;		\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
	}

void
hyprlofs_hash_init(void)
{
	int	ix;

	for (ix = 0; ix < HL_MUTEX_SIZE; ix++)
		mutex_init(&hl_hashmutex[ix], NULL, MUTEX_DEFAULT, NULL);
}

static void
hyprlofs_hash_in(hldirent_t *h)
{
	uint_t		hash;
	hldirent_t	**prevpp;
	kmutex_t	*hmtx;

	HYPRLOFS_HASH(h->hld_parent, h->hld_name, hash);
	h->hld_hash = hash;
	prevpp = &hl_hashtable[HL_HASH_INDEX(hash)];
	hmtx = &hl_hashmutex[HL_MUTEX_INDEX(hash)];
	mutex_enter(hmtx);
	h->hld_link = *prevpp;
	*prevpp = h;
	mutex_exit(hmtx);
}

/* Remove hldirent *h from the hash list. */
static void
hyprlofs_hash_out(hldirent_t *h)
{
	uint_t		hash;
	hldirent_t	**prevpp;
	kmutex_t	*hmtx;

	hash = h->hld_hash;
	prevpp = &hl_hashtable[HL_HASH_INDEX(hash)];
	hmtx = &hl_hashmutex[HL_MUTEX_INDEX(hash)];
	mutex_enter(hmtx);
	while (*prevpp != h)
		prevpp = &(*prevpp)->hld_link;
	*prevpp = h->hld_link;
	mutex_exit(hmtx);
}

static hldirent_t *
hyprlofs_hash_lookup(char *name, hlnode_t *parent, uint_t hold,
    hlnode_t **found)
{
	hldirent_t	*l;
	uint_t		hash;
	kmutex_t	*hmtx;
	hlnode_t	*hnp;

	HYPRLOFS_HASH(parent, name, hash);
	hmtx = &hl_hashmutex[HL_MUTEX_INDEX(hash)];
	mutex_enter(hmtx);
	l = hl_hashtable[HL_HASH_INDEX(hash)];
	while (l) {
		if (l->hld_hash == hash && l->hld_parent == parent &&
		    strcmp(l->hld_name, name) == 0) {
			/*
			 * Ensure that the hlnode that we put a hold on is the
			 * same one that we pass back. Thus the temp. var
			 * hnp is necessary.
			 */
			hnp = l->hld_hlnode;
			if (hold) {
				ASSERT(hnp);
				hlnode_hold(hnp);
			}
			if (found)
				*found = hnp;
			mutex_exit(hmtx);
			return (l);
		} else {
			l = l->hld_link;
		}
	}
	mutex_exit(hmtx);
	return (NULL);
}

/*
 * Search directory 'parent' for entry 'name'.
 *
 * The calling thread can't hold the write version of the rwlock for the
 * directory being searched
 *
 * On success *foundtp points to the found hlnode with its vnode held.
 */
int
hyprlofs_dirlookup(hlnode_t *parent, char *name, hlnode_t **foundtp, cred_t *cr)
{
	int error;

	*foundtp = NULL;
	if (parent->hln_type != VDIR)
		return (ENOTDIR);

	if ((error = hyprlofs_taccess(parent, VEXEC, cr)))
		return (error);

	if (*name == '\0') {
		hlnode_hold(parent);
		*foundtp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name. We need the lock
	 * protecting the hln_dir list so that it doesn't change out from
	 * underneath us. hyprlofs_hash_lookup() will pass back the hlnode
	 * with a hold on it.
	 */
	if (hyprlofs_hash_lookup(name, parent, 1, foundtp) != NULL) {
		ASSERT(*foundtp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Enter a directory entry (either a file or subdir, depending on op) for
 * 'name' and 'hp' into directory 'dir'
 */
int
hyprlofs_direnter(
	hlfsmount_t	*hm,
	hlnode_t	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	vnode_t		*realvp,	/* real vnode */
	vattr_t		*va,
	hlnode_t	**hpp,		/* return hlnode */
	cred_t		*cr)
{
	hldirent_t *hdp;
	hlnode_t *found = NULL;
	hlnode_t *hp;
	int error = 0;
	char *s;

	/* hln_rwlock is held to serialize direnter and dirdeletes */
	ASSERT(RW_WRITE_HELD(&dir->hln_rwlock));
	ASSERT(dir->hln_type == VDIR);

	/* Don't allow '/' characters in pathname component */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	if (name[0] == '\0')
		panic("hyprlofs_direnter: NULL name");

	/*
	 * This might be a "dangling detached directory". It could have been
	 * removed, but a reference to it kept in u_cwd. Don't bother searching
	 * it, and with any luck the user will get tired of dealing with us and
	 * cd to some absolute pathway. This is in ufs, too.
	 */
	if (dir->hln_nlink == 0) {
		return (ENOENT);
	}

	/* Search for the entry.  Return "found" if it exists. */
	hdp = hyprlofs_hash_lookup(name, dir, 1, &found);

	if (hdp) {
		ASSERT(found);
		switch (op) {
		case DE_CREATE:
		case DE_MKDIR:
			if (hpp) {
				*hpp = found;
				error = EEXIST;
			} else {
				hlnode_rele(found);
			}
			break;
		}
	} else {

		/*
		 * The entry does not exist. Check write perms in dir to see if
		 * entry can be created.
		 */
		if ((error = hyprlofs_taccess(dir, VWRITE, cr)))
			return (error);

		/* Make new hlnode and directory entry as required. */
		if ((error = hldir_make_hlnode(dir, hm, va, op, realvp, &hp,
		    cr)))
			return (error);

		if ((error = hldiraddentry(dir, hp, name))) {
			/* Unmake the inode we just made. */
			rw_enter(&hp->hln_rwlock, RW_WRITER);
			if ((hp->hln_type) == VDIR) {
				ASSERT(hdp == NULL);
				/* cleanup allocs made by hyprlofs_dirinit() */
				hyprlofs_dirtrunc(hp);
			}
			mutex_enter(&hp->hln_tlock);
			hp->hln_nlink = 0;
			mutex_exit(&hp->hln_tlock);
			gethrestime(&hp->hln_ctime);
			rw_exit(&hp->hln_rwlock);
			hlnode_rele(hp);
			hp = NULL;
		} else if (hpp) {
			*hpp = hp;
		} else {
			hlnode_rele(hp);
		}
	}

	return (error);
}

/*
 * Delete entry hp of name "nm" from dir. Free dir entry space and decrement
 * link count on hlnode(s).
 */
int
hyprlofs_dirdelete(hlnode_t *dir, hlnode_t *hp, char *nm, enum dr_op op,
    cred_t *cr)
{
	hldirent_t *hpdp;
	int error;
	size_t namelen;
	hlnode_t *hnp;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->hln_rwlock));
	ASSERT(RW_WRITE_HELD(&hp->hln_rwlock));
	ASSERT(dir->hln_type == VDIR);

	if (nm[0] == '\0')
		panic("hyprlofs_dirdelete: NULL name for %p", (void *)hp);

	/* return error if removing . or .. */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	if (error = hyprlofs_taccess(dir, VEXEC|VWRITE, cr))
		return (error);

	if (dir->hln_dir == NULL)
		return (ENOENT);

	hpdp = hyprlofs_hash_lookup(nm, dir, 0, &hnp);
	if (hpdp == NULL) {
		/*
		 * If it is gone, some other thread got here first!
		 * Return error ENOENT.
		 */
		return (ENOENT);
	}

	/*
	 * If the hlnode in the hldirent changed (shouldn't happen since we
	 * don't support rename) then original is gone, so return that status
	 * (same as UFS).
	 */
	if (hp != hnp)
		return (ENOENT);

	hyprlofs_hash_out(hpdp);

	/* Take hpdp out of the directory list. */
	ASSERT(hpdp->hld_next != hpdp);
	ASSERT(hpdp->hld_prev != hpdp);
	if (hpdp->hld_prev) {
		hpdp->hld_prev->hld_next = hpdp->hld_next;
	}
	if (hpdp->hld_next) {
		hpdp->hld_next->hld_prev = hpdp->hld_prev;
	}

	/*
	 * If the roving slot pointer happens to match hpdp, point it at the
	 * previous dirent.
	 */
	if (dir->hln_dir->hld_prev == hpdp) {
		dir->hln_dir->hld_prev = hpdp->hld_prev;
	}
	ASSERT(hpdp->hld_next != hpdp);
	ASSERT(hpdp->hld_prev != hpdp);

	/* hpdp points to the correct directory entry */
	namelen = strlen(hpdp->hld_name) + 1;

	hyprlofs_memfree(hpdp, sizeof (hldirent_t) + namelen);
	dir->hln_size -= (sizeof (hldirent_t) + namelen);
	dir->hln_dirents--;

	gethrestime(&now);
	dir->hln_mtime = now;
	dir->hln_ctime = now;
	hp->hln_ctime = now;

	ASSERT(hp->hln_nlink > 0);
	DECR_COUNT(&hp->hln_nlink, &hp->hln_tlock);
	if (op == DR_RMDIR && hp->hln_type == VDIR) {
		hyprlofs_dirtrunc(hp);
		ASSERT(hp->hln_nlink == 0);
	}
	return (0);
}

/*
 * hyprlofs_dirinit initializes a dir with '.' and '..' entries without
 * checking perms and locking
 */
void
hyprlofs_dirinit(
	hlnode_t *parent,	/* parent of directory to initialize */
	hlnode_t *dir)		/* the new directory */
{
	hldirent_t *dot, *dotdot;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&parent->hln_rwlock));
	ASSERT(dir->hln_type == VDIR);

	dot = hyprlofs_memalloc(sizeof (hldirent_t) + 2, HL_MUSTHAVE);
	dotdot = hyprlofs_memalloc(sizeof (hldirent_t) + 3, HL_MUSTHAVE);

	/* Initialize the entries */
	dot->hld_hlnode = dir;
	dot->hld_offset = 0;
	dot->hld_name = (char *)dot + sizeof (hldirent_t);
	dot->hld_name[0] = '.';
	dot->hld_parent = dir;
	hyprlofs_hash_in(dot);

	dotdot->hld_hlnode = parent;
	dotdot->hld_offset = 1;
	dotdot->hld_name = (char *)dotdot + sizeof (hldirent_t);
	dotdot->hld_name[0] = '.';
	dotdot->hld_name[1] = '.';
	dotdot->hld_parent = dir;
	hyprlofs_hash_in(dotdot);

	/* Initialize directory entry list. */
	dot->hld_next = dotdot;
	dot->hld_prev = dotdot;
	dotdot->hld_next = NULL;
	dotdot->hld_prev = dot;

	gethrestime(&now);
	dir->hln_mtime = now;
	dir->hln_ctime = now;

	/*
	 * Since hyprlofs_dirinit is called with both dir and parent being the
	 * same for the root vnode, we need to increment this before we set
	 * hln_nlink = 2 below.
	 */
	INCR_COUNT(&parent->hln_nlink, &parent->hln_tlock);
	parent->hln_ctime = now;

	dir->hln_dir = dot;
	dir->hln_size = 2 * sizeof (hldirent_t) + 5; /* dot and dotdot */
	dir->hln_dirents = 2;
	dir->hln_nlink = 2;
}


/*
 * hyprlofs_dirtrunc removes all dir entries under this dir.
 */
void
hyprlofs_dirtrunc(hlnode_t *dir)
{
	hldirent_t *hdp;
	hlnode_t *tp;
	size_t namelen;
	timestruc_t now;

	ASSERT(RW_WRITE_HELD(&dir->hln_rwlock));
	ASSERT(dir->hln_type == VDIR);

	if (dir->hln_looped)
		return;

	for (hdp = dir->hln_dir; hdp; hdp = dir->hln_dir) {
		ASSERT(hdp->hld_next != hdp);
		ASSERT(hdp->hld_prev != hdp);
		ASSERT(hdp->hld_hlnode);

		dir->hln_dir = hdp->hld_next;
		namelen = strlen(hdp->hld_name) + 1;

		/*
		 * Adjust the link counts to account for this dir entry removal.
		 */
		tp = hdp->hld_hlnode;

		ASSERT(tp->hln_nlink > 0);
		DECR_COUNT(&tp->hln_nlink, &tp->hln_tlock);

		hyprlofs_hash_out(hdp);

		hyprlofs_memfree(hdp, sizeof (hldirent_t) + namelen);
		dir->hln_size -= (sizeof (hldirent_t) + namelen);
		dir->hln_dirents--;
	}

	gethrestime(&now);
	dir->hln_mtime = now;
	dir->hln_ctime = now;

	ASSERT(dir->hln_dir == NULL);
	ASSERT(dir->hln_size == 0);
	ASSERT(dir->hln_dirents == 0);
}

static int
hldiraddentry(
    hlnode_t	*dir,	/* target directory to make entry in */
    hlnode_t	*hp,	/* new hlnode */
    char	*name)
{
	hldirent_t	*hdp, *hpdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent dir wasn't removed from underneath the caller.
	 */
	if (dir->hln_dir == NULL)
		return (ENOENT);

	/* Check that everything is on the same FS. */
	if (hp->hln_vnode->v_vfsp != dir->hln_vnode->v_vfsp)
		return (EXDEV);

	/* Alloc and init dir entry */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (hldirent_t);
	hdp = hyprlofs_memalloc(alloc_size, 0);
	if (hdp == NULL)
		return (ENOSPC);

	dir->hln_size += alloc_size;
	dir->hln_dirents++;
	hdp->hld_hlnode = hp;
	hdp->hld_parent = dir;

	/* The dir entry and its name were allocated sequentially. */
	hdp->hld_name = (char *)hdp + sizeof (hldirent_t);
	(void) strcpy(hdp->hld_name, name);

	hyprlofs_hash_in(hdp);

	/*
	 * Some utilities expect the size of a directory to remain fairly
	 * static.  For example, a routine which unlinks files between calls to
	 * readdir(); the size of the dir changes from underneath it and so the
	 * real dir offset in bytes is invalid.  To circumvent this problem, we
	 * initialize a dir entry with a phony offset, and use this offset to
	 * determine end of file in hyprlofs_readdir.
	 */
	hpdp = dir->hln_dir->hld_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (hpdp->hld_next != NULL && (hpdp->hld_next->hld_offset -
	    hpdp->hld_offset) <= 1) {
		ASSERT(hpdp->hld_next != hpdp);
		ASSERT(hpdp->hld_prev != hpdp);
		ASSERT(hpdp->hld_next->hld_offset > hpdp->hld_offset);
		hpdp = hpdp->hld_next;
	}
	hdp->hld_offset = hpdp->hld_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which is
	 * necessarily the largest offset in this dir) is more than twice the
	 * number of dirents, that means the dir is 50% holes.  At this point
	 * we reset the slot pointer back to the beginning of the dir so we
	 * start using the holes. The idea is that if there are N dirents,
	 * there must also be N holes, so we can satisfy the next N creates by
	 * walking at most 2N entries; thus the average cost of a create is
	 * constant. Note that we use the first dirent's hld_prev as the roving
	 * slot pointer. This saves a word in every dirent.
	 */
	if (hpdp->hld_next == NULL && hpdp->hld_offset > 2 * dir->hln_dirents)
		dir->hln_dir->hld_prev = dir->hln_dir->hld_next;
	else
		dir->hln_dir->hld_prev = hdp;

	ASSERT(hpdp->hld_next != hpdp);
	ASSERT(hpdp->hld_prev != hpdp);

	hdp->hld_next = hpdp->hld_next;
	if (hdp->hld_next) {
		hdp->hld_next->hld_prev = hdp;
	}
	hdp->hld_prev = hpdp;
	hpdp->hld_next = hdp;

	ASSERT(hdp->hld_next != hdp);
	ASSERT(hdp->hld_prev != hdp);
	ASSERT(hpdp->hld_next != hpdp);
	ASSERT(hpdp->hld_prev != hpdp);

	gethrestime(&now);
	dir->hln_mtime = now;
	dir->hln_ctime = now;

	return (0);
}

static int
hldir_make_hlnode(hlnode_t *dir, hlfsmount_t *hm, vattr_t *va, enum de_op op,
    vnode_t *realvp, hlnode_t **newnode, cred_t *cr)
{
	hlnode_t	*hp;
	enum vtype	type;

	ASSERT(va != NULL);
	ASSERT(op == DE_CREATE || op == DE_MKDIR);
	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);
	type = va->va_type;
	hp = hyprlofs_memalloc(sizeof (hlnode_t), HL_MUSTHAVE);
	hyprlofs_node_init(hm, hp, va, cr);

	hp->hln_vnode->v_rdev = hp->hln_rdev = NODEV;
	hp->hln_vnode->v_type = type;
	hp->hln_uid = crgetuid(cr);

	/*
	 * To determine the gid of the created file:
	 *   If the directory's set-gid bit is set, set the gid to the gid
	 *   of the parent dir, otherwise, use the process's gid.
	 */
	if (dir->hln_mode & VSGID)
		hp->hln_gid = dir->hln_gid;
	else
		hp->hln_gid = crgetgid(cr);

	/*
	 * If we're creating a dir and the parent dir has the set-GID bit set,
	 * set it on the new dir. Otherwise, if the user is neither privileged
	 * nor a member of the file's new group, clear the file's set-GID bit.
	 */
	if (dir->hln_mode & VSGID && type == VDIR)
		hp->hln_mode |= VSGID;
	else {
		if ((hp->hln_mode & VSGID) &&
		    secpolicy_vnode_setids_setgids(cr, hp->hln_gid) != 0)
			hp->hln_mode &= ~VSGID;
	}

	if (va->va_mask & AT_ATIME)
		hp->hln_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		hp->hln_mtime = va->va_mtime;

	if (op == DE_MKDIR) {
		hyprlofs_dirinit(dir, hp);
		hp->hln_looped = 0;
	} else {
		hp->hln_realvp = realvp;
		hp->hln_size = va->va_size;
		hp->hln_looped = 1;
	}

	*newnode = hp;
	return (0);
}
