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
 * Copyright 2016 Joyent, Inc.
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

#include "cgrps.h"

static int cgrp_dirmakecgnode(cgrp_node_t *, cgrp_mnt_t *, struct vattr *,
	enum de_op, cgrp_node_t **, struct cred *);
static int cgrp_diraddentry(cgrp_node_t *, cgrp_node_t *, char *);

static cgrp_subsys_dirent_t cgrp_generic_dir[] = {
	{ CG_PROCS,		"cgroup.procs" },
	{ CG_NOTIFY,		"notify_on_release" },
	{ CG_TASKS,		"tasks" }
};

typedef struct cgrp_ssde {
	cgrp_subsys_dirent_t	*cg_ssde_files;
	int			cg_ssde_nfiles;
} cgrp_ssde_t;

#define	CGDIRLISTSZ(l)		(sizeof (l) / sizeof ((l)[0]))

/*
 * Note, these entries must be in the same order as the cgrp_ssid_t entries.
 */
static cgrp_ssde_t cg_ssde_dir[] = {
	/* subsystems start at 1 */
	{NULL, 0},

	/* CG_SSID_GENERIC */
	{cgrp_generic_dir, CGDIRLISTSZ(cgrp_generic_dir)},
};


#define	CG_HASH_SIZE	8192		/* must be power of 2 */
#define	CG_MUTEX_SIZE	64

static cgrp_dirent_t	*cg_hashtable[CG_HASH_SIZE];
static kmutex_t		 cg_hashmutex[CG_MUTEX_SIZE];

#define	CG_HASH_INDEX(a)	((a) & (CG_HASH_SIZE-1))
#define	CG_MUTEX_INDEX(a)	((a) & (CG_MUTEX_SIZE-1))

#define	CG_HASH(cp, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = (uint_t)(uintptr_t)(cp) >> 8;		\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
	}

#define	MODESHIFT	3

typedef enum cgrp_nodehold {
	NOHOLD,
	HOLD
} cgrp_nodehold_t;

void
cgrp_hash_init(void)
{
	int i;

	for (i = 0; i < CG_MUTEX_SIZE; i++)
		mutex_init(&cg_hashmutex[i], NULL, MUTEX_DEFAULT, NULL);
}

static void
cgrp_hash_in(cgrp_dirent_t *c)
{
	uint_t		hash;
	cgrp_dirent_t	**prevpp;
	kmutex_t	*cg_hmtx;

	CG_HASH(c->cgd_parent, c->cgd_name, hash);
	c->cgd_hash = hash;
	prevpp = &cg_hashtable[CG_HASH_INDEX(hash)];
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	c->cgd_link = *prevpp;
	*prevpp = c;
	mutex_exit(cg_hmtx);
}

static void
cgrp_hash_out(cgrp_dirent_t *c)
{
	uint_t		hash;
	cgrp_dirent_t	**prevpp;
	kmutex_t	*cg_hmtx;

	hash = c->cgd_hash;
	prevpp = &cg_hashtable[CG_HASH_INDEX(hash)];
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	while (*prevpp != c)
		prevpp = &(*prevpp)->cgd_link;
	*prevpp = c->cgd_link;
	mutex_exit(cg_hmtx);
}

static cgrp_dirent_t *
cgrp_hash_lookup(char *name, cgrp_node_t *parent, cgrp_nodehold_t hold,
    cgrp_node_t **found)
{
	cgrp_dirent_t	*l;
	uint_t		hash;
	kmutex_t	*cg_hmtx;
	cgrp_node_t	*cnp;

	CG_HASH(parent, name, hash);
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	l = cg_hashtable[CG_HASH_INDEX(hash)];
	while (l) {
		if ((l->cgd_hash == hash) &&
		    (l->cgd_parent == parent) &&
		    (strcmp(l->cgd_name, name) == 0)) {
			/*
			 * We need to make sure that the cgrp_node that
			 * we put a hold on is the same one that we pass back.
			 * Hence, temporary variable cnp is necessary.
			 */
			cnp = l->cgd_cgrp_node;
			if (hold == HOLD) {
				ASSERT(cnp);
				cgnode_hold(cnp);
			}
			if (found)
				*found = cnp;
			mutex_exit(cg_hmtx);
			return (l);
		} else {
			l = l->cgd_link;
		}
	}
	mutex_exit(cg_hmtx);
	return (NULL);
}

/*
 * The following functions maintain the per-mount cgroup hash table.
 */
static void
cgrp_cg_hash_insert(cgrp_mnt_t *cgm, cgrp_node_t *cn)
{
	uint_t cgid;
	int hsh;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	cgid = cn->cgn_id;
	hsh = cgid % CGRP_HASH_SZ;

	cn->cgn_next = cgm->cg_grp_hash[hsh];
	cgm->cg_grp_hash[hsh] = cn;
}

static void
cgrp_cg_hash_remove(cgrp_mnt_t *cgm, cgrp_node_t *cn)
{
	uint_t cgid;
	int hsh;
	cgrp_node_t *np = NULL, *curp, *prevp = NULL;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	cgid = cn->cgn_id;
	hsh = cgid % CGRP_HASH_SZ;

	for (curp = cgm->cg_grp_hash[hsh]; curp != NULL;
	    curp = curp->cgn_next) {
		if (curp->cgn_id == cgid) {
			if (prevp == NULL) {
				cgm->cg_grp_hash[hsh] = curp->cgn_next;
			} else {
				prevp->cgn_next = curp->cgn_next;
			}
			np = curp;
			np->cgn_next = NULL;
			break;
		}

		prevp = curp;
	}

	ASSERT(np != NULL);
	ASSERT(np->cgn_task_cnt == 0);
}

/*
 * Count up the number of threads already running in the zone and initialize the
 * first cgroup's task counter.
 *
 * We have to look at all of the processes to find applicable ones.
 */
static void
cgrp_cg_hash_init(cgrp_node_t *cn)
{
	int i;
	int cnt = 0;
	zoneid_t zoneid = curproc->p_zone->zone_id;
	pid_t schedpid = curproc->p_zone->zone_zsched->p_pid;

	/* Scan all of the process entries */
	mutex_enter(&pidlock);
	for (i = 1; i < v.v_proc; i++) {
		proc_t *p;

		/*
		 * Skip indices for which there is no pid_entry, PIDs for
		 * which there is no corresponding process, system processes,
		 * a PID of 0, the pid for our zsched process,  anything the
		 * security policy doesn't allow us to look at, its not an
		 * lx-branded process and processes that are not in the zone.
		 */
		if ((p = pid_entry(i)) == NULL ||
		    p->p_stat == SIDL ||
		    (p->p_flag & SSYS) != 0 ||
		    p->p_pid == 0 ||
		    p->p_pid == schedpid ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0 ||
		    p->p_zone->zone_id != zoneid) {
			continue;
		}

		mutex_enter(&p->p_lock);
		if (p->p_brand != &lx_brand) {
			mutex_exit(&p->p_lock);
			continue;
		}
		cnt += p->p_lwpcnt;
		mutex_exit(&p->p_lock);
	}

	/*
	 * There should be at least the init process with 1 thread in the zone
	 */
	ASSERT(cnt > 0);
	cn->cgn_task_cnt = cnt;

	DTRACE_PROBE2(cgrp__grp__init, void *, cn, int, cnt);

	mutex_exit(&pidlock);
}

cgrp_node_t *
cgrp_cg_hash_lookup(cgrp_mnt_t *cgm, uint_t cgid)
{
	int hsh = cgid % CGRP_HASH_SZ;
	cgrp_node_t *curp;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	for (curp = cgm->cg_grp_hash[hsh]; curp != NULL;
	    curp = curp->cgn_next) {
		if (curp->cgn_id == cgid) {
			return (curp);
		}
	}

	return (NULL);
}

/*
 * Calculate an inode number
 *
 * This takes various bits of info and munges them to give the inode number for
 * a cgrp pseudo file node.
 */
ino_t
cgrp_inode(cgrp_nodetype_t type, unsigned int cgrpid)
{
	/*
	 * cgroup inode format:
	 * 00000000AABBBBBB
	 *
	 * AA		- node type (from subsystem list)
	 * BBBBBB	- id of the cgroup
	 */

	return ((ino_t)(type << 24) | (cgrpid & 0xffffff));
}

/*
 * Return the number of pseudo file entries in a cgroup directory for the
 * given subsystem.
 */
int
cgrp_num_pseudo_ents(cgrp_ssid_t ssid)
{
	cgrp_ssde_t *ssdp = &cg_ssde_dir[ssid];

	return (ssdp->cg_ssde_nfiles);
}

int
cgrp_taccess(void *vcp, int mode, cred_t *cred)
{
	cgrp_node_t *cn = vcp;
	int shift = 0;
	/*
	 * Check access based on owner, group and public perms in cgrp_node.
	 */
	if (crgetuid(cred) != cn->cgn_uid) {
		shift += MODESHIFT;
		if (groupmember(cn->cgn_gid, cred) == 0)
			shift += MODESHIFT;
	}

	return (secpolicy_vnode_access2(cred, CGNTOV(cn), cn->cgn_uid,
	    cn->cgn_mode << shift, mode));
}

/*
 * Search directory 'parent' for entry 'name'.
 *
 * 0 is returned on success and *foundcp points
 * to the found cgrp_node with its vnode held.
 */
int
cgrp_dirlookup(cgrp_node_t *parent, char *name, cgrp_node_t **foundcp,
    cred_t *cred)
{
	int error;

	ASSERT(MUTEX_HELD(&VTOCGM(parent->cgn_vnode)->cg_contents));
	*foundcp = NULL;
	if (parent->cgn_type != CG_CGROUP_DIR)
		return (ENOTDIR);

	if ((error = cgrp_taccess(parent, VEXEC, cred)))
		return (error);

	if (*name == '\0') {
		cgnode_hold(parent);
		*foundcp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name
	 * We need the lock protecting the cgn_dir list
	 * so that it doesn't change out from underneath us.
	 * cgrp_hash_lookup() will pass back the cgrp_node
	 * with a hold on it.
	 */

	if (cgrp_hash_lookup(name, parent, HOLD, foundcp) != NULL) {
		ASSERT(*foundcp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Enter a directory entry for 'name' and 'cp' into directory 'dir'
 *
 * Returns 0 on success.
 */
int
cgrp_direnter(
	cgrp_mnt_t	*cgm,
	cgrp_node_t	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	cgrp_node_t	*cn,		/* existing cgrp_node, if rename */
	struct vattr	*va,
	cgrp_node_t	**cnp,		/* return cgrp_node, if create/mkdir */
	cred_t		*cred)
{
	cgrp_dirent_t *cdp;
	cgrp_node_t *found = NULL;
	int error = 0;
	char *s;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	/*
	 * Don't allow '/' characters in pathname component,
	 */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	if (name[0] == '\0')
		panic("cgrp_direnter: NULL name");

	/*
	 * For rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.
	 * Remember that we can only rename within the same directory.
	 */
	if (op == DE_RENAME) {
		if (cn->cgn_nlink == 0) {
			return (ENOENT);
		}

		if (cn->cgn_nlink == MAXLINK) {
			return (EMLINK);
		}
		cn->cgn_nlink++;
		gethrestime(&cn->cgn_ctime);
	}

	/*
	 * This might be a "dangling detached directory".
	 * it could have been removed, but a reference
	 * to it kept in u_cwd.  don't bother searching
	 * it, and with any luck the user will get tired
	 * of dealing with us and cd to some absolute
	 * pathway.  *sigh*, thus in ufs, too.
	 */
	if (dir->cgn_nlink == 0) {
		error = ENOENT;
		goto out;
	}

	/*
	 * Search for the entry. In all cases it is an error if it exists.
	 */
	cdp = cgrp_hash_lookup(name, dir, HOLD, &found);

	if (cdp) {
		ASSERT(found != NULL);
		error = EEXIST;
		mutex_exit(&cgm->cg_contents);
		cgnode_rele(found);
		mutex_enter(&cgm->cg_contents);
	} else {

		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if ((error = cgrp_taccess(dir, VWRITE, cred)) != 0)
			goto out;
		if (op == DE_CREATE || op == DE_MKDIR) {
			/*
			 * Make new cgrp_node and directory entry as required.
			 */
			error = cgrp_dirmakecgnode(dir, cgm, va, op, &cn, cred);
			if (error)
				goto out;

			if (op == DE_MKDIR) {
				/*
				 * inherit notify_on_release value from parent
				 */
				cn->cgn_notify = dir->cgn_notify;
			}
		}

		error = cgrp_diraddentry(dir, cn, name);
		if (error != 0) {
			if (op == DE_CREATE || op == DE_MKDIR) {
				/*
				 * Unmake the inode we just made.
				 */
				if ((cn->cgn_type) == CG_CGROUP_DIR) {
					ASSERT(cdp == NULL);
					/*
					 * cleanup allocs made by cgrp_dirinit
					 */
					cgrp_dirtrunc(cn);
				}
				cn->cgn_nlink = 0;
				gethrestime(&cn->cgn_ctime);
				mutex_exit(&cgm->cg_contents);
				cgnode_rele(cn);
				mutex_enter(&cgm->cg_contents);
				cn = NULL;
			}
		} else if (cnp) {
			*cnp = cn;
		} else if (op == DE_CREATE || op == DE_MKDIR) {
			mutex_exit(&cgm->cg_contents);
			cgnode_rele(cn);
			mutex_enter(&cgm->cg_contents);
		}
	}

out:
	if (error && op == DE_RENAME) {
		/* Undo bumped link count. */
		cn->cgn_nlink--;
		gethrestime(&cn->cgn_ctime);
	}
	return (error);
}

/*
 * Delete entry cn of name "nm" from parent dir. This is used to both remove
 * a cgroup directory and to remove the pseudo file nodes within the cgroup
 * directory (by recursively calling itself). It frees the dir entry space
 * and decrements link count on cgrp_node(s).
 *
 * Return 0 on success.
 */
int
cgrp_dirdelete(cgrp_node_t *dir, cgrp_node_t *cn, char *nm, enum dr_op op,
    cred_t *cred)
{
	cgrp_mnt_t *cgm = VTOCGM(cn->cgn_vnode);
	cgrp_dirent_t *cndp;
	int error;
	size_t namelen;
	cgrp_node_t *cnnp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	if (nm[0] == '\0')
		panic("cgrp_dirdelete: empty name for 0x%p", (void *)cn);

	/*
	 * return error when removing . and ..
	 */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	if ((error = cgrp_taccess(dir, VEXEC|VWRITE, cred)) != 0)
		return (error);

	if (dir->cgn_dir == NULL)
		return (ENOENT);

	if (op == DR_RMDIR) {
		/*
		 * This is the top-level removal of a cgroup dir. Start by
		 * removing the fixed pseudo file entries from the dir. We do
		 * this by recursively calling back into this function with
		 * a different op code. The caller of this function has
		 * already verified that it is safe to remove this directory.
		 */
		cgrp_dirent_t *cdp;

		ASSERT(cn->cgn_type == CG_CGROUP_DIR);

		cdp = cn->cgn_dir;
		while (cdp) {
			cgrp_node_t *pseudo_node;
			cgrp_dirent_t *nextp;

			if (strcmp(cdp->cgd_name, ".") == 0 ||
			    strcmp(cdp->cgd_name, "..") == 0) {
				cdp = cdp->cgd_next;
				continue;
			}

			pseudo_node = cdp->cgd_cgrp_node;
			nextp = cdp->cgd_next;

			cgnode_hold(pseudo_node);
			error = cgrp_dirdelete(cn, pseudo_node,
			    cdp->cgd_name, DR_REMOVE, cred);
			mutex_exit(&cgm->cg_contents);
			cgnode_rele(pseudo_node);
			mutex_enter(&cgm->cg_contents);

			cdp = nextp;
		}

		cgrp_cg_hash_remove(cgm, cn);
	}

	cndp = cgrp_hash_lookup(nm, dir, NOHOLD, &cnnp);
	VERIFY(cndp != NULL);
	VERIFY(cn == cnnp);

	cgrp_hash_out(cndp);

	/* Take cndp out of the directory list. */
	ASSERT(cndp->cgd_next != cndp);
	ASSERT(cndp->cgd_prev != cndp);
	if (cndp->cgd_prev) {
		cndp->cgd_prev->cgd_next = cndp->cgd_next;
	}
	if (cndp->cgd_next) {
		cndp->cgd_next->cgd_prev = cndp->cgd_prev;
	}

	/*
	 * If the roving slot pointer happens to match cndp,
	 * point it at the previous dirent.
	 */
	if (dir->cgn_dir->cgd_prev == cndp) {
		dir->cgn_dir->cgd_prev = cndp->cgd_prev;
	}
	ASSERT(cndp->cgd_next != cndp);
	ASSERT(cndp->cgd_prev != cndp);

	/* cndp points to the correct directory entry */
	namelen = strlen(cndp->cgd_name) + 1;

	kmem_free(cndp, sizeof (cgrp_dirent_t) + namelen);
	dir->cgn_size -= (sizeof (cgrp_dirent_t) + namelen);
	dir->cgn_dirents--;

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;
	cn->cgn_ctime = now;

	ASSERT(cn->cgn_nlink > 0);
	cn->cgn_nlink--;
	if (op == DR_RMDIR && cn->cgn_type == CG_CGROUP_DIR) {
		cgrp_dirtrunc(cn);
		ASSERT(cn->cgn_nlink == 0);
	}
	return (0);
}

/*
 * Initialize a cgrp_node and add it to file list under mount point.
 */
void
cgrp_node_init(cgrp_mnt_t *cgm, cgrp_node_t *cn, vattr_t *vap, cred_t *cred)
{
	struct vnode *vp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(vap != NULL);

	cn->cgn_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	cn->cgn_mask = 0;
	cn->cgn_attr.va_type = vap->va_type;
	cn->cgn_nlink = 1;
	cn->cgn_size = 0;

	if (cred == NULL) {
		cn->cgn_uid = vap->va_uid;
		cn->cgn_gid = vap->va_gid;
	} else {
		cn->cgn_uid = crgetuid(cred);
		cn->cgn_gid = crgetgid(cred);
	}

	cn->cgn_fsid = cgm->cg_dev;
	cn->cgn_rdev = vap->va_rdev;
	cn->cgn_blksize = PAGESIZE;
	cn->cgn_nblocks = 0;
	gethrestime(&now);
	cn->cgn_atime = now;
	cn->cgn_mtime = now;
	cn->cgn_ctime = now;
	cn->cgn_seq = 0;
	cn->cgn_dir = NULL;

	cn->cgn_vnode = vn_alloc(KM_SLEEP);
	vp = CGNTOV(cn);
	vn_setops(vp, cgrp_vnodeops);
	vp->v_vfsp = cgm->cg_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)cn;

	cn->cgn_nodeid = cgm->cg_gen++;

	/*
	 * Add new cgrp_node to end of linked list of cgrp_nodes for this
	 * cgroup fs. Root directory is handled specially in cgrp_mount.
	 */
	if (cgm->cg_rootnode != (cgrp_node_t *)NULL) {
		cn->cgn_forw = NULL;
		cn->cgn_back = cgm->cg_rootnode->cgn_back;
		cn->cgn_back->cgn_forw = cgm->cg_rootnode->cgn_back = cn;
	}
	vn_exists(vp);
}

void
cgrp_addnode(cgrp_mnt_t *cgm, cgrp_node_t *dir, char *name,
    cgrp_nodetype_t type, struct vattr *nattr, cred_t *cr)
{
	cgrp_node_t *ncn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	VERIFY0(cgrp_direnter(cgm, dir, name, DE_CREATE, (cgrp_node_t *)NULL,
	    nattr, &ncn, cr));

	/*
	 * Fix the inode and assign the pseudo file type to be correct.
	 */
	ncn->cgn_nodeid = cgrp_inode(type, dir->cgn_nodeid);
	ncn->cgn_type = type;

	/*
	 * Since we're creating these entries here and not via the
	 * normal VOP_CREATE code path, we need to do the rele to drop
	 * our hold. This will leave the vnode v_count at 0 when we
	 * come out of cgrp_inactive but we won't reclaim the vnode
	 * there since the cgn_nlink value will still be 1.
	 */
	mutex_exit(&cgm->cg_contents);
	cgnode_rele(ncn);
	mutex_enter(&cgm->cg_contents);
}

/*
 * cgrp_dirinit is used internally to initialize a directory (dir)
 * with '.' and '..' entries without checking permissions and locking
 * It also creates the entries for the pseudo file nodes that reside in the
 * directory.
 */
void
cgrp_dirinit(cgrp_node_t *parent, cgrp_node_t *dir, cred_t *cr)
{
	cgrp_dirent_t *dot, *dotdot;
	timestruc_t now;
	cgrp_mnt_t *cgm = VTOCGM(dir->cgn_vnode);
	cgrp_ssde_t *ssdp;
	cgrp_subsys_dirent_t *pseudo_files;
	struct vattr nattr;
	int i;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	ASSERT(cgm->cg_ssid > 0 && cgm->cg_ssid < CG_SSID_NUM);
	ssdp = &cg_ssde_dir[cgm->cg_ssid];

	/*
	 * If this is the top-level cgroup created by the mount then we need to
	 * count up the number of procs and tasks already running in the zone.
	 */

	/*
	 * Set the cgroup ID for this cgrp_node by using a counter on each
	 * mount.
	 */
	dir->cgn_id = cgm->cg_grp_gen++;
	cgrp_cg_hash_insert(cgm, dir);
	/* Initialise the first cgroup if this is top-level group */
	if (parent == dir)
		cgrp_cg_hash_init(dir);

	/*
	 * Initialize the entries
	 */
	dot = kmem_zalloc(sizeof (cgrp_dirent_t) + 2, KM_SLEEP);
	dot->cgd_cgrp_node = dir;
	dot->cgd_offset = 0;
	dot->cgd_name = (char *)dot + sizeof (cgrp_dirent_t);
	dot->cgd_name[0] = '.';
	dot->cgd_parent = dir;
	cgrp_hash_in(dot);

	dotdot = kmem_zalloc(sizeof (cgrp_dirent_t) + 3, KM_SLEEP);
	dotdot->cgd_cgrp_node = parent;
	dotdot->cgd_offset = 1;
	dotdot->cgd_name = (char *)dotdot + sizeof (cgrp_dirent_t);
	dotdot->cgd_name[0] = '.';
	dotdot->cgd_name[1] = '.';
	dotdot->cgd_parent = dir;
	cgrp_hash_in(dotdot);

	/*
	 * Initialize directory entry list.
	 */
	dot->cgd_next = dotdot;
	dot->cgd_prev = dotdot;	/* dot's cgd_prev holds roving slot pointer */
	dotdot->cgd_next = NULL;
	dotdot->cgd_prev = dot;

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	parent->cgn_nlink++;
	parent->cgn_ctime = now;

	dir->cgn_dir = dot;
	dir->cgn_size = 2 * sizeof (cgrp_dirent_t) + 5;	/* dot and dotdot */
	dir->cgn_dirents = 2;
	dir->cgn_nlink = 2;

	bzero(&nattr, sizeof (struct vattr));
	nattr.va_mode = (mode_t)(0644);
	nattr.va_type = VREG;
	nattr.va_rdev = 0;

	/*
	 * If this is the top-level dir in the file system then it always
	 * has a release_agent pseudo file. Only the top-level dir has this
	 * file.
	 */
	if (parent == dir) {
		cgrp_addnode(cgm, dir, "release_agent", CG_REL_AGENT, &nattr,
		    cr);
	}

	pseudo_files = ssdp->cg_ssde_files;
	for (i = 0; i < ssdp->cg_ssde_nfiles; i++) {
		cgrp_addnode(cgm, dir, pseudo_files[i].cgrp_ssd_name,
		    pseudo_files[i].cgrp_ssd_type, &nattr, cr);
	}
}

/*
 * cgrp_dirtrunc is called to remove all directory entries under this directory.
 */
void
cgrp_dirtrunc(cgrp_node_t *dir)
{
	cgrp_dirent_t *cgdp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&VTOCGM(dir->cgn_vnode)->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	for (cgdp = dir->cgn_dir; cgdp; cgdp = dir->cgn_dir) {
		size_t namelen;
		cgrp_node_t *cn;

		ASSERT(cgdp->cgd_next != cgdp);
		ASSERT(cgdp->cgd_prev != cgdp);
		ASSERT(cgdp->cgd_cgrp_node);

		dir->cgn_dir = cgdp->cgd_next;
		namelen = strlen(cgdp->cgd_name) + 1;

		/*
		 * Adjust the link counts to account for this directory entry
		 * removal. We do hold/rele operations to free up these nodes.
		 */
		cn = cgdp->cgd_cgrp_node;
		ASSERT(cn->cgn_nlink > 0);
		cn->cgn_nlink--;

		cgrp_hash_out(cgdp);
		kmem_free(cgdp, sizeof (cgrp_dirent_t) + namelen);
		dir->cgn_size -= (sizeof (cgrp_dirent_t) + namelen);
		dir->cgn_dirents--;
	}

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	ASSERT(dir->cgn_dir == NULL);
	ASSERT(dir->cgn_size == 0);
	ASSERT(dir->cgn_dirents == 0);
}

static int
cgrp_diraddentry(cgrp_node_t *dir, cgrp_node_t *cn, char *name)
{
	cgrp_dirent_t *cdp, *cpdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent directory wasn't removed from
	 * underneath the caller.
	 */
	if (dir->cgn_dir == NULL)
		return (ENOENT);

	/* Check that everything is on the same filesystem. */
	if (cn->cgn_vnode->v_vfsp != dir->cgn_vnode->v_vfsp)
		return (EXDEV);

	/* Allocate and initialize directory entry */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (cgrp_dirent_t);
	cdp = kmem_zalloc(alloc_size, KM_NOSLEEP | KM_NORMALPRI);
	if (cdp == NULL)
		return (ENOSPC);

	cn->cgn_parent = dir;

	dir->cgn_size += alloc_size;
	dir->cgn_dirents++;
	cdp->cgd_cgrp_node = cn;
	cdp->cgd_parent = dir;

	/* The directory entry and its name were allocated sequentially. */
	cdp->cgd_name = (char *)cdp + sizeof (cgrp_dirent_t);
	(void) strcpy(cdp->cgd_name, name);

	cgrp_hash_in(cdp);

	/*
	 * Some utilities expect the size of a directory to remain
	 * somewhat static.  For example, a routine which removes
	 * subdirectories between calls to readdir(); the size of the
	 * directory changes from underneath it and so the real
	 * directory offset in bytes is invalid.  To circumvent
	 * this problem, we initialize a directory entry with an
	 * phony offset, and use this offset to determine end of
	 * file in cgrp_readdir.
	 */
	cpdp = dir->cgn_dir->cgd_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (cpdp->cgd_next != NULL && (cpdp->cgd_next->cgd_offset -
	    cpdp->cgd_offset) <= 1) {
		ASSERT(cpdp->cgd_next != cpdp);
		ASSERT(cpdp->cgd_prev != cpdp);
		ASSERT(cpdp->cgd_next->cgd_offset > cpdp->cgd_offset);
		cpdp = cpdp->cgd_next;
	}
	cdp->cgd_offset = cpdp->cgd_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which
	 * is necessarily the largest offset in this directory) is more
	 * than twice the number of dirents, that means the directory is
	 * 50% holes.  At this point we reset the slot pointer back to
	 * the beginning of the directory so we start using the holes.
	 * The idea is that if there are N dirents, there must also be
	 * N holes, so we can satisfy the next N creates by walking at
	 * most 2N entries; thus the average cost of a create is constant.
	 * Note that we use the first dirent's cgd_prev as the roving
	 * slot pointer; it's ugly, but it saves a word in every dirent.
	 */
	if (cpdp->cgd_next == NULL && cpdp->cgd_offset > 2 * dir->cgn_dirents)
		dir->cgn_dir->cgd_prev = dir->cgn_dir->cgd_next;
	else
		dir->cgn_dir->cgd_prev = cdp;

	ASSERT(cpdp->cgd_next != cpdp);
	ASSERT(cpdp->cgd_prev != cpdp);

	cdp->cgd_next = cpdp->cgd_next;
	if (cdp->cgd_next) {
		cdp->cgd_next->cgd_prev = cdp;
	}
	cdp->cgd_prev = cpdp;
	cpdp->cgd_next = cdp;

	ASSERT(cdp->cgd_next != cdp);
	ASSERT(cdp->cgd_prev != cdp);
	ASSERT(cpdp->cgd_next != cpdp);
	ASSERT(cpdp->cgd_prev != cpdp);

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	return (0);
}

static int
cgrp_dirmakecgnode(cgrp_node_t *dir, cgrp_mnt_t *cgm, struct vattr *va,
    enum de_op op, cgrp_node_t **newnode, struct cred *cred)
{
	cgrp_node_t *cn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(va != NULL);

	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);

	cn = kmem_zalloc(sizeof (cgrp_node_t), KM_SLEEP);
	cgrp_node_init(cgm, cn, va, cred);

	cn->cgn_vnode->v_rdev = cn->cgn_rdev = NODEV;
	cn->cgn_vnode->v_type = va->va_type;
	cn->cgn_uid = crgetuid(cred);
	cn->cgn_gid = crgetgid(cred);

	if (va->va_mask & AT_ATIME)
		cn->cgn_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		cn->cgn_mtime = va->va_mtime;

	if (op == DE_MKDIR) {
		cn->cgn_type = CG_CGROUP_DIR;
		cgrp_dirinit(dir, cn, cred);
	}

	*newnode = cn;
	return (0);
}
