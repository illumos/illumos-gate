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

/*
 * The cgroup file system implements a subset of the Linux cgroup functionality
 * for use by lx-branded zones. On Linux, cgroups are a generic process grouping
 * mechanism which is used to apply various behaviors to the processes within
 * the group, although it's primary purpose is for resource management.
 *
 * In Linux, the cgroup file system provides two pieces of functionality:
 * 1) A per-mount set of cgroups arranged in a tree, such that every task in
 *    the system is in one, and only one, of the cgroups in the tree.
 * 2) A set of subsystems; each subsystem has subsystem-specific state and
 *    behavior and is associated with a cgroup mount. This provides a way to
 *    apply arbitrary functionality (but generally resource management related)
 *    to the processes associated with the nodes in the tree at that mount
 *    point.
 *
 * For example, it is common to see cgroup trees (each is its own mount with a
 * different subsystem controller) for blkio, cpuset, memory, systemd (has no
 * controller), etc. Within each tree there is a top-level directory with at
 * least a cgroup.procs, notify_on_release, release_agent, and tasks file.
 * The cgroup.procs file lists the processes within that group and the tasks
 * file lists the threads in the group. There could be subdirectories, which
 * define new cgroups, that then contain a subset of the processes. Each
 * subdirectory also has, at a minimum, a cgroup.procs, notify_on_release, and
 * tasks file.
 *
 * Since we're using lx to run user-level code within zones, the majority (all?)
 * of the cgroup resource management functionality simply doesn't apply to us.
 * The primary need for cgroups is to support the init program 'systemd' as the
 * consumer. systemd only requires the process grouping hierarchy of cgroups,
 * although it can also use the resource management features if they are
 * available. Given this, our cgroup file system only implements the process
 * hierarchy and does not report that any resource management controllers are
 * available for separate mounts.
 *
 * In addition to the hierarchy, the other important component of cgroups that
 * is used by systemd is the 'release_agent'. This provides a mechanism to
 * run a command when a cgroup becomes empty (the last task in the group
 * leaves, either by exit or move, and there are no more sub-cgroups). The
 * 'release_agent' file only exists in the top-level cgroup of the mounted
 * file system and holds the path to a command to run. The 'notify_on_release'
 * file exists in each cgroup dir. If that file contains a '1' then the agent
 * is run when that group becomes empty. The agent is passed a path string of
 * the cgroup, relative to the file system mount point (e.g. a mount on
 * /sys/fs/cgroups/systemd with a sub-cgroup of /sys/fs/cgroups/systemd/foo/bar
 * gets the arg /foo/bar).
 *
 * Cgroup membership is implemented via hooks into the lx brand code. When
 * the cgroup file system loads it installs callbacks for:
 *    lx_cgrp_initlwp
 *    lx_cgrp_freelwp
 * and when it unloads it clears those hooks. The lx brand code calls those
 * hooks when a lwp starts and when it exits. Internally we use a
 * simple reference counter (cgn_task_cnt) on the cgroup node to track how many
 * threads are in the group, so we can tell when a group becomes empty.
 * To make this quick, a hash table (cg_grp_hash) is maintained on the
 * cgrp_mnt_t struct to allow quick lookups by cgroup ID. The hash table is
 * sized so that there should typically only be 0 or 1 cgroups per bucket.
 * We also keep a reference to the file system in the zone-specific brand data
 * (lxzd_cgroup) so that the lx brand code can pass in the correct vfs_t
 * when it runs the hook.
 *
 * Once a cgroup is about to become empty, the final process exiting the cgroup
 * will launch a new user-level process which execs the release agent. The new
 * process is created as a child of zsched (indicated by the -1 pid argument
 * to newproc) and is not associated with the exiting process in any way.
 *
 * This file system is similar to tmpfs in that directories only exist in
 * memory. Each subdirectory represents a different cgroup. Within the cgroup
 * there are pseudo files (see cg_ssde_dir) with well-defined names which
 * control the configuration and behavior of the cgroup (see cgrp_nodetype_t).
 * The primary files within every cgroup are named 'cgroup.procs',
 * 'notify_on_release', and 'tasks' (as well as 'release_agent' in the
 * top-level cgroup). The cgroup.procs and tasks files are used to control and
 * list which processes/threads belong to the cgroup. In the general case there
 * could be additional files in the cgroup, which defined additional behavior
 * (i.e. subsystem specific pseudo files), although none exist at this time.
 *
 * Each cgroup node has a unique ID (cgn_nodeid) within the mount. This ID is
 * used to correlate with the threads to determine cgroup membership. When
 * assigning a PID to a cgroup (via write) the code updates the br_cgroupid
 * member in the brand-specific lx_lwp_data structure to control which cgroup
 * the thread belongs to. Note that because the br_cgroupid lives in
 * lx_lwp_data, native processes will not appear in the cgroup hierarchy.
 *
 * An overview of the behavior for the various vnode operations is:
 * - no hardlinks or symlinks
 * - no file create (the subsystem-specific files are a fixed list of
 *   pseudo-files accessible within the directory)
 * - no file remove
 * - no file rename, but a directory (i.e. a cgroup) can be renamed within the
 *   containing directory, but not into a different directory
 * - can mkdir and rmdir to create/destroy cgroups
 * - cannot rmdir while it contains tasks or a subdir (i.e. a sub-cgroup)
 * - open, read/write, close on the subsytem-specific pseudo files is
 *   allowed, as this is the interface to configure and report on the cgroup.
 *   The pseudo file's mode controls write access and cannot be changed.
 *
 * The locking in this file system is simple since the file system is not
 * subjected to heavy I/O activity and all data is in-memory. There is a single
 * global mutex for each mount (cg_contents). This mutex is held for the life
 * of most vnode operations. The most active path is probably the LWP start and
 * exit hooks which increment/decrement the reference counter on the cgroup
 * node. The lock is important for this case since we don't want concurrent
 * activity (such as moving the process into another cgroup) while we're trying
 * to lookup the cgroup from the mount's hash table. We must be careful to
 * avoid a deadlock while reading or writing since that code can take pidlock
 * and p_lock, but the cgrp_lwp_fork_helper can also be called while one of
 * those is held. To prevent deadlock we always take cg_contents after pidlock
 * and p_lock.
 *
 * EXTENDING THE FILE SYSTEM
 *
 * When adding support for a new subsystem, be sure to also update the
 * lxpr_read_cgroups function in lx_procfs so that the subsystem is reported
 * by proc.
 *
 * Although we don't currently support any subsystem controllers, the design
 * allows for the file system to be extended to add controller emulation
 * if needed. New controller IDs (i.e. different subsystems) for a mount can
 * be defined in the cgrp_ssid_t enum (e.g. CG_SSID_CPUSET or CG_SSID_MEMORY)
 * and new node types for additional pseudo files in the tree can be defined in
 * the cgrp_nodetype_t enum (e.g. CG_CPUSET_CPUS or CG_MEMORY_USAGE_IN_BYTES).
 * The cg_ssde_dir array would need a new entry for the new subsystem to
 * control which nodes are visible in a directory for the new subsystem.
 *
 * New emulation would then need to be written to manage the behavior on the
 * new pseudo file(s) associated with new cgrp_nodetype_t types.
 *
 * Within lx procfs the lxpr_read_pid_cgroup() function would need to be
 * updated so that it reported the various subsystems used by the different
 * mounts.
 *
 * In addition, in order to support more than one cgroup mount we would need a
 * list of cgroup IDs associated with every thread, instead of just one ID
 * (br_cgroupid). The thread data would need to become a struct which held
 * both an ID and an indication as to which mounted cgroup file system instance
 * the ID was associated with. We would also need a list of cgroup mounts per
 * zone, instead the current single zone reference.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/mntent.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/vmparam.h>
#include <sys/corectl.h>
#include <sys/contract_impl.h>
#include <sys/pool.h>
#include <sys/stack.h>
#include <sys/rt.h>
#include <sys/fx.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

#include "cgrps.h"

/* Module level parameters */
static int	cgrp_fstype;
static dev_t	cgrp_dev;

#define	MAX_AGENT_EVENTS	32		/* max num queued events */

#define	UMNT_DELAY_TIME	drv_usectohz(50000)	/* 500th of a second */
#define	UMNT_RETRY_MAX	100			/* 100 times - 2 secs */

/*
 * cgrp_mountcount is used to prevent module unloads while there is still
 * state from a former mount hanging around. The filesystem module must not be
 * allowed to go away before the last VFS_FREEVFS() call has been made. Since
 * this is just an atomic counter, there's no need for locking.
 */
static uint32_t cgrp_mountcount;

/*
 * cgrp_minfree is the minimum amount of swap space that cgroups leaves for
 * the rest of the zone. In other words, if the amount of free swap space
 * in the zone drops below cgrp_minfree, cgroup anon allocations will fail.
 * This number is only likely to become factor when DRAM and swap have both
 * been capped low to allow for maximum tenancy.
 */
size_t cgrp_minfree = 0;

/*
 * CGMINFREE -- the value from which cgrp_minfree is derived -- should be
 * configured to a value that is roughly the smallest practical value for
 * memory + swap minus the largest reasonable size for cgroups in such
 * a configuration. As of this writing, the smallest practical memory + swap
 * configuration is 128MB, and it seems reasonable to allow cgroups to consume
 * no more than half of this, yielding a CGMINFREE of 64MB.
 */
#define	CGMINFREE	64 * 1024 * 1024	/* 64 Megabytes */

extern pgcnt_t swapfs_minfree;

/*
 * cgroup vfs operations.
 */
static int cgrp_init(int, char *);
static int cgrp_mount(struct vfs *, struct vnode *,
	struct mounta *, struct cred *);
static int cgrp_unmount(struct vfs *, int, struct cred *);
static int cgrp_root(struct vfs *, struct vnode **);
static int cgrp_statvfs(struct vfs *, struct statvfs64 *);
static void cgrp_freevfs(vfs_t *vfsp);

/* Forward declarations for hooks */
static void cgrp_lwp_fork_helper(vfs_t *, uint_t, id_t, pid_t);
static void cgrp_lwp_exit_helper(vfs_t *, uint_t, id_t, pid_t);

/*
 * Loadable module wrapper
 */
#include <sys/modctl.h>

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"lx_cgroup",
	cgrp_init,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "lx brand cgroups", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlfs, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	int error;

	if (cgrp_mountcount)
		return (EBUSY);

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	/* Disable hooks used by the lx brand module. */
	lx_cgrp_initlwp = NULL;
	lx_cgrp_freelwp = NULL;

	/*
	 * Tear down the operations vectors
	 */
	(void) vfs_freevfsops_by_type(cgrp_fstype);
	vn_freevnodeops(cgrp_vnodeops);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Initialize global locks, etc. Called when loading cgroup module.
 */
static int
cgrp_init(int fstype, char *name)
{
	static const fs_operation_def_t cgrp_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = cgrp_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = cgrp_unmount },
		VFSNAME_ROOT,		{ .vfs_root = cgrp_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = cgrp_statvfs },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = cgrp_freevfs },
		NULL,			NULL
	};
	extern const struct fs_operation_def cgrp_vnodeops_template[];
	int error;
	extern  void    cgrp_hash_init();
	major_t dev;

	cgrp_hash_init();
	cgrp_fstype = fstype;
	ASSERT(cgrp_fstype != 0);

	error = vfs_setfsops(fstype, cgrp_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "cgrp_init: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, cgrp_vnodeops_template, &cgrp_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "cgrp_init: bad vnode ops template");
		return (error);
	}

	/*
	 * cgrp_minfree doesn't need to be some function of configured
	 * swap space since it really is an absolute limit of swap space
	 * which still allows other processes to execute.
	 */
	if (cgrp_minfree == 0) {
		/* Set if not patched */
		cgrp_minfree = btopr(CGMINFREE);
	}

	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "cgrp_init: Can't get unique device number.");
		dev = 0;
	}

	/*
	 * Make the pseudo device
	 */
	cgrp_dev = makedevice(dev, 0);

	/* Install the hooks used by the lx brand module. */
	lx_cgrp_initlwp = cgrp_lwp_fork_helper;
	lx_cgrp_freelwp = cgrp_lwp_exit_helper;

	return (0);
}

static int
cgrp_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	cgrp_mnt_t *cgm = NULL;
	struct cgrp_node *cp;
	struct pathname dpn;
	int error;
	struct vattr rattr;
	cgrp_ssid_t ssid = CG_SSID_GENERIC;
	lx_zone_data_t *lxzdata;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * Since we depend on per-thread lx brand data, only allow mounting
	 * within lx zones.
	 */
	if (curproc->p_zone->zone_brand != &lx_brand)
		return (EINVAL);

	/*
	 * Ensure we don't allow overlaying mounts
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Having the resource be anything but "swap" doesn't make sense.
	 */
	vfs_setresource(vfsp, "swap", 0);

	/* cgroups don't support read-only mounts */
	if (vfs_optionisset(vfsp, MNTOPT_RO, NULL)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Here is where we could support subsystem-specific controller
	 * mounting. For example, if mounting a cgroup fs with the 'cpuset'
	 * option to specify that particular controller.
	 *
	 * char *argstr;
	 * if (vfs_optionisset(vfsp, "cpuset", &argstr)) {
	 *	if (ssid != CG_SSID_GENERIC) {
	 *		error = EINVAL;
	 *		goto out;
	 *	}
	 *	ssid = CG_SSID_CPUSET;
	 * }
	 */

	error = pn_get(uap->dir,
	    (uap->flags & MS_SYSSPACE) ? UIO_SYSSPACE : UIO_USERSPACE, &dpn);
	if (error != 0)
		goto out;

	/*
	 * We currently only support one mount per zone.
	 */
	lxzdata = ztolxzd(curproc->p_zone);
	mutex_enter(&lxzdata->lxzd_lock);
	if (lxzdata->lxzd_cgroup != NULL) {
		mutex_exit(&lxzdata->lxzd_lock);
		return (EINVAL);
	}

	cgm = kmem_zalloc(sizeof (*cgm), KM_SLEEP);

	/* Set but don't bother entering the mutex (not on mount list yet) */
	mutex_init(&cgm->cg_contents, NULL, MUTEX_DEFAULT, NULL);

	cgm->cg_vfsp = lxzdata->lxzd_cgroup = vfsp;
	mutex_exit(&lxzdata->lxzd_lock);

	cgm->cg_lxzdata = lxzdata;
	cgm->cg_ssid = ssid;

	vfsp->vfs_data = (caddr_t)cgm;
	vfsp->vfs_fstype = cgrp_fstype;
	vfsp->vfs_dev = cgrp_dev;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfs_make_fsid(&vfsp->vfs_fsid, cgrp_dev, cgrp_fstype);
	cgm->cg_mntpath = kmem_zalloc(dpn.pn_pathlen + 1, KM_SLEEP);
	(void) strcpy(cgm->cg_mntpath, dpn.pn_path);

	cgm->cg_grp_hash = kmem_zalloc(sizeof (cgrp_node_t *) * CGRP_HASH_SZ,
	    KM_SLEEP);

	/* allocate and initialize root cgrp_node structure */
	bzero(&rattr, sizeof (struct vattr));
	rattr.va_mode = (mode_t)(S_IFDIR | 0755);
	rattr.va_type = VDIR;
	rattr.va_rdev = 0;
	cp = kmem_zalloc(sizeof (struct cgrp_node), KM_SLEEP);

	mutex_enter(&cgm->cg_contents);
	cgrp_node_init(cgm, cp, &rattr, cr);

	CGNTOV(cp)->v_flag |= VROOT;

	/*
	 * initialize linked list of cgrp_nodes so that the back pointer of
	 * the root cgrp_node always points to the last one on the list
	 * and the forward pointer of the last node is null
	 */
	cp->cgn_back = cp;
	cp->cgn_forw = NULL;
	cp->cgn_nlink = 0;
	cgm->cg_rootnode = cp;

	cp->cgn_type = CG_CGROUP_DIR;
	cp->cgn_nodeid = cgrp_inode(ssid, cgm->cg_gen);
	cgrp_dirinit(cp, cp, cr);

	mutex_exit(&cgm->cg_contents);

	pn_free(&dpn);
	error = 0;
	atomic_inc_32(&cgrp_mountcount);

out:
	if (error == 0)
		vfs_set_feature(vfsp, VFSFT_SYSATTR_VIEWS);

	return (error);
}

static int
cgrp_unmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	cgrp_node_t *cgnp, *cancel;
	struct vnode	*vp;
	int error;
	uint_t cnt;
	int retry_cnt = 0;

	if ((error = secpolicy_fs_unmount(cr, vfsp)) != 0)
		return (error);

retry:
	mutex_enter(&cgm->cg_contents);

	/*
	 * In the normal unmount case, if there were no open files, only the
	 * root node would have a reference count. However, the user-level
	 * agent manager should have the root vnode open and be waiting in
	 * ioctl. We need to wake the manager and it may take some retries
	 * before it closes its file descriptor.
	 *
	 * With cg_contents held, nothing can be added or removed.
	 * There may be some dirty pages.  To prevent fsflush from
	 * disrupting the unmount, put a hold on each node while scanning.
	 * If we find a previously referenced node, undo the holds we have
	 * placed and fail EBUSY.
	 */
	cgnp = cgm->cg_rootnode;

	ASSERT(cgm->cg_lxzdata->lxzd_cgroup != NULL);

	vp = CGNTOV(cgnp);
	mutex_enter(&vp->v_lock);

	if (flag & MS_FORCE) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&cgm->cg_contents);
		return (EINVAL);
	}


	cnt = vp->v_count;
	if (cnt > 1) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&cgm->cg_contents);
		/* Likely because the user-level manager hasn't exited yet */
		if (retry_cnt++ < UMNT_RETRY_MAX) {
			delay(UMNT_DELAY_TIME);
			goto retry;
		}
		return (EBUSY);
	}

	mutex_exit(&vp->v_lock);

	/*
	 * Check for open files. An open file causes everything to unwind.
	 */
	for (cgnp = cgnp->cgn_forw; cgnp; cgnp = cgnp->cgn_forw) {
		vp = CGNTOV(cgnp);
		mutex_enter(&vp->v_lock);
		cnt = vp->v_count;
		if (cnt > 0) {
			/* An open file; unwind the holds we've been adding. */
			mutex_exit(&vp->v_lock);
			cancel = cgm->cg_rootnode->cgn_forw;
			while (cancel != cgnp) {
				vp = CGNTOV(cancel);
				ASSERT(vp->v_count > 0);
				VN_RELE(vp);
				cancel = cancel->cgn_forw;
			}
			mutex_exit(&cgm->cg_contents);
			return (EBUSY);
		} else {
			/* directly add a VN_HOLD since we have the lock */
			vp->v_count++;
			mutex_exit(&vp->v_lock);
		}
	}

	mutex_enter(&cgm->cg_lxzdata->lxzd_lock);
	cgm->cg_lxzdata->lxzd_cgroup = NULL;
	mutex_exit(&cgm->cg_lxzdata->lxzd_lock);
	kmem_free(cgm->cg_grp_hash, sizeof (cgrp_node_t *) * CGRP_HASH_SZ);

	/*
	 * We can drop the mutex now because
	 * no one can find this mount anymore
	 */
	vfsp->vfs_flag |= VFS_UNMOUNTED;
	mutex_exit(&cgm->cg_contents);

	return (0);
}

/*
 * Implementation of VFS_FREEVFS(). This is called by the vfs framework after
 * umount and the last VFS_RELE, to trigger the release of any resources still
 * associated with the given vfs_t. This is normally called immediately after
 * cgrp_umount.
 */
void
cgrp_freevfs(vfs_t *vfsp)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	cgrp_node_t *cn;
	struct vnode	*vp;

	/*
	 * Free all kmemalloc'd and anonalloc'd memory associated with
	 * this filesystem.  To do this, we go through the file list twice,
	 * once to remove all the directory entries, and then to remove
	 * all the pseudo files.
	 */

	/*
	 * Now that we are tearing ourselves down we need to remove the
	 * UNMOUNTED flag. If we don't, we'll later hit a VN_RELE when we remove
	 * files from the system causing us to have a negative value. Doing this
	 * seems a bit better than trying to set a flag on the tmount that says
	 * we're tearing down.
	 */
	vfsp->vfs_flag &= ~VFS_UNMOUNTED;

	/*
	 * Remove all directory entries
	 */
	for (cn = cgm->cg_rootnode; cn; cn = cn->cgn_forw) {
		mutex_enter(&cgm->cg_contents);
		if (cn->cgn_type == CG_CGROUP_DIR)
			cgrp_dirtrunc(cn);
		mutex_exit(&cgm->cg_contents);
	}

	ASSERT(cgm->cg_rootnode);

	/*
	 * All links are gone, v_count is keeping nodes in place.
	 * VN_RELE should make the node disappear, unless somebody
	 * is holding pages against it.  Nap and retry until it disappears.
	 *
	 * We re-acquire the lock to prevent others who have a HOLD on
	 * a cgrp_node via its pages or anon slots from blowing it away
	 * (in cgrp_inactive) while we're trying to get to it here. Once
	 * we have a HOLD on it we know it'll stick around.
	 *
	 */
	mutex_enter(&cgm->cg_contents);

	/* Remove all the files (except the rootnode) backwards. */
	while ((cn = cgm->cg_rootnode->cgn_back) != cgm->cg_rootnode) {
		mutex_exit(&cgm->cg_contents);
		/*
		 * All nodes will be released here. Note we handled the link
		 * count above.
		 */
		vp = CGNTOV(cn);
		VN_RELE(vp);
		mutex_enter(&cgm->cg_contents);
		/*
		 * It's still there after the RELE. Someone else like pageout
		 * has a hold on it so wait a bit and then try again - we know
		 * they'll give it up soon.
		 */
		if (cn == cgm->cg_rootnode->cgn_back) {
			VN_HOLD(vp);
			mutex_exit(&cgm->cg_contents);
			delay(hz / 4);
			mutex_enter(&cgm->cg_contents);
		}
	}
	mutex_exit(&cgm->cg_contents);

	VN_RELE(CGNTOV(cgm->cg_rootnode));

	ASSERT(cgm->cg_mntpath);

	kmem_free(cgm->cg_mntpath, strlen(cgm->cg_mntpath) + 1);

	mutex_destroy(&cgm->cg_contents);
	kmem_free(cgm, sizeof (cgrp_mnt_t));

	/* Allow _fini() to succeed now */
	atomic_dec_32(&cgrp_mountcount);
}

/*
 * return root cgnode for given vnode
 */
static int
cgrp_root(struct vfs *vfsp, struct vnode **vpp)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	cgrp_node_t *cp = cgm->cg_rootnode;
	struct vnode *vp;

	ASSERT(cp);

	vp = CGNTOV(cp);
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
cgrp_statvfs(struct vfs *vfsp, struct statvfs64 *sbp)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	ulong_t	blocks;
	dev32_t d32;
	zoneid_t eff_zid;
	struct zone *zp;

	zp = cgm->cg_vfsp->vfs_zone;

	if (zp == NULL)
		eff_zid = GLOBAL_ZONEUNIQID;
	else
		eff_zid = zp->zone_id;

	sbp->f_bsize = PAGESIZE;
	sbp->f_frsize = PAGESIZE;

	/*
	 * Find the amount of available physical and memory swap
	 */
	mutex_enter(&anoninfo_lock);
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);
	blocks = (ulong_t)CURRENT_TOTAL_AVAILABLE_SWAP;
	mutex_exit(&anoninfo_lock);

	if (blocks > cgrp_minfree)
		sbp->f_bfree = blocks - cgrp_minfree;
	else
		sbp->f_bfree = 0;

	sbp->f_bavail = sbp->f_bfree;

	/*
	 * Total number of blocks is just what's available
	 */
	sbp->f_blocks = (fsblkcnt64_t)(sbp->f_bfree);

	if (eff_zid != GLOBAL_ZONEUNIQID &&
	    zp->zone_max_swap_ctl != UINT64_MAX) {
		/*
		 * If the fs is used by a zone with a swap cap,
		 * then report the capped size.
		 */
		rctl_qty_t cap, used;
		pgcnt_t pgcap, pgused;

		mutex_enter(&zp->zone_mem_lock);
		cap = zp->zone_max_swap_ctl;
		used = zp->zone_max_swap;
		mutex_exit(&zp->zone_mem_lock);

		pgcap = btop(cap);
		pgused = btop(used);

		sbp->f_bfree = MIN(pgcap - pgused, sbp->f_bfree);
		sbp->f_bavail = sbp->f_bfree;
		sbp->f_blocks = MIN(pgcap, sbp->f_blocks);
	}

	/*
	 * The maximum number of files available is approximately the number
	 * of cgrp_nodes we can allocate from the remaining kernel memory
	 * available to cgroups.  This is fairly inaccurate since it doesn't
	 * take into account the names stored in the directory entries.
	 */
	sbp->f_ffree = sbp->f_files = ptob(availrmem) /
	    (sizeof (cgrp_node_t) + sizeof (cgrp_dirent_t));
	sbp->f_favail = (fsfilcnt64_t)(sbp->f_ffree);
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[cgrp_fstype].vsw_name);
	(void) strncpy(sbp->f_fstr, cgm->cg_mntpath, sizeof (sbp->f_fstr));
	/* ensure null termination */
	sbp->f_fstr[sizeof (sbp->f_fstr) - 1] = '\0';
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	return (0);
}

static int
cgrp_get_dirname(cgrp_node_t *cn, char *buf, int blen)
{
	cgrp_node_t *parent;
	cgrp_dirent_t *dp;

	buf[0] = '\0';

	parent = cn->cgn_parent;
	if (parent == NULL || parent == cn) {
		(void) strlcpy(buf, ".", blen);
		return (0);
	}

	/*
	 * Search the parent dir list to find this cn's name.
	 */
	for (dp = parent->cgn_dir; dp != NULL; dp = dp->cgd_next) {
		if (dp->cgd_cgrp_node->cgn_id == cn->cgn_id) {
			(void) strlcpy(buf, dp->cgd_name, blen);
			return (0);
		}
	}

	return (-1);
}

typedef struct cgrp_rra_arg {
	char *crraa_agent_path;
	char *crraa_event_path;
} cgrp_rra_arg_t;

static void
cgrp_run_rel_agent(void *a)
{
	cgrp_rra_arg_t *rarg = a;
	proc_t *p = ttoproc(curthread);
	zone_t *z = p->p_zone;
	struct core_globals *cg;
	int res;

	ASSERT(!INGLOBALZONE(curproc));

	/* The following block is derived from start_init_common */
	ASSERT_STACK_ALIGNED();

	p->p_cstime = p->p_stime = p->p_cutime = p->p_utime = 0;
	p->p_usrstack = (caddr_t)USRSTACK32;
	p->p_model = DATAMODEL_ILP32;
	p->p_stkprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_datprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_stk_ctl = INT32_MAX;

	p->p_as = as_alloc();
	p->p_as->a_proc = p;
	p->p_as->a_userlimit = (caddr_t)USERLIMIT32;
	(void) hat_setup(p->p_as->a_hat, HAT_INIT);

	VERIFY((cg = zone_getspecific(core_zone_key, z)) != NULL);

	corectl_path_hold(cg->core_default_path);
	corectl_content_hold(cg->core_default_content);

	curproc->p_corefile = cg->core_default_path;
	curproc->p_content = cg->core_default_content;

	init_mstate(curthread, LMS_SYSTEM);
	res = exec_init(rarg->crraa_agent_path, rarg->crraa_event_path);

	/* End of code derived from start_init_common */

	kmem_free(rarg->crraa_event_path, MAXPATHLEN);
	kmem_free(rarg->crraa_agent_path, CGRP_AGENT_LEN);
	kmem_free(rarg, sizeof (cgrp_rra_arg_t));

	/* The following is derived from zone_start_init - see comments there */
	if (res != 0 || zone_status_get(global_zone) >= ZONE_IS_SHUTTING_DOWN) {
		if (proc_exit(CLD_EXITED, res) != 0) {
			mutex_enter(&p->p_lock);
			ASSERT(p->p_flag & SEXITLWPS);
			lwp_exit();
		}
	} else {
		id_t cid = curthread->t_cid;

		mutex_enter(&class_lock);
		ASSERT(cid < loaded_classes);
		if (strcmp(sclass[cid].cl_name, "FX") == 0 &&
		    z->zone_fixed_hipri) {
			pcparms_t pcparms;

			pcparms.pc_cid = cid;
			((fxkparms_t *)pcparms.pc_clparms)->fx_upri = FXMAXUPRI;
			((fxkparms_t *)pcparms.pc_clparms)->fx_uprilim =
			    FXMAXUPRI;
			((fxkparms_t *)pcparms.pc_clparms)->fx_cflags =
			    FX_DOUPRILIM | FX_DOUPRI;

			mutex_enter(&pidlock);
			mutex_enter(&curproc->p_lock);
			(void) parmsset(&pcparms, curthread);
			mutex_exit(&curproc->p_lock);
			mutex_exit(&pidlock);
		} else if (strcmp(sclass[cid].cl_name, "RT") == 0) {
			curthread->t_pri = RTGPPRIO0;
		}
		mutex_exit(&class_lock);

		/* cause the process to return to userland. */
		lwp_rtt();
	}
}

/*
 * Launch the user-level release_agent manager. The event data is the
 * pathname (relative to the mount point of the file system) of the newly empty
 * cgroup.
 *
 * The cg_contents mutex is held on entry and dropped before returning.
 */
void
cgrp_rel_agent_event(cgrp_mnt_t *cgm, cgrp_node_t *cn)
{
	cgrp_node_t *parent;
	char nm[MAXNAMELEN];
	char *argstr, *oldstr, *tmp;
	id_t cid;
	int agent_err;
	proc_t *p = ttoproc(curthread);
	zone_t *z = p->p_zone;
	lx_lwp_data_t *plwpd = ttolxlwp(curthread);
	cgrp_rra_arg_t *rarg;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	/* Nothing to do if the agent is not set */
	if (cgm->cg_agent[0] == '\0') {
		mutex_exit(&cgm->cg_contents);
		return;
	}

	parent = cn->cgn_parent;
	/* Cannot remove the top-level cgroup (only via unmount) */
	if (parent == cn) {
		mutex_exit(&cgm->cg_contents);
		return;
	}

	argstr = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	oldstr = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	*argstr = '\0';

	/*
	 * Iterate up the directory tree to construct the agent argument string.
	 */
	do {
		cgrp_get_dirname(cn, nm, sizeof (nm));
		DTRACE_PROBE1(cgrp__dir__name, char *, nm);
		if (*argstr == '\0') {
			(void) snprintf(argstr, MAXPATHLEN, "/%s", nm);
		} else {
			tmp = oldstr;
			oldstr = argstr;
			argstr = tmp;
			(void) snprintf(argstr, MAXPATHLEN, "/%s%s", nm,
			    oldstr);
		}

		if (cn->cgn_parent == NULL)
			break;
		cn = cn->cgn_parent;
		parent = cn->cgn_parent;

		/*
		 * The arg path is relative to the mountpoint so we stop when
		 * we get to the top level.
		 */
		if (parent == NULL || parent == cn)
			break;
	} while (parent != cn);

	kmem_free(oldstr, MAXPATHLEN);

	rarg = kmem_alloc(sizeof (cgrp_rra_arg_t), KM_SLEEP);
	rarg->crraa_agent_path = kmem_alloc(sizeof (cgm->cg_agent), KM_SLEEP);
	(void) strlcpy(rarg->crraa_agent_path, cgm->cg_agent,
	    sizeof (cgm->cg_agent));
	rarg->crraa_event_path = argstr;

	DTRACE_PROBE2(cgrp__agent__event, cgrp_rra_arg_t *, rarg,
	    int, plwpd->br_cgroupid);

	/* The release agent process cannot belong to our cgroup */
	plwpd->br_cgroupid = 0;

	/*
	 * The cg_contents mutex cannot be held while taking the pool lock
	 * or calling newproc.
	 */
	mutex_exit(&cgm->cg_contents);

	if (z->zone_defaultcid > 0) {
		cid = z->zone_defaultcid;
	} else {
		pool_lock();
		cid = pool_get_class(z->zone_pool);
		pool_unlock();
	}
	if (cid == -1)
		cid = defaultcid;

	if ((agent_err = newproc(cgrp_run_rel_agent, (void *)rarg, cid,
	    minclsyspri - 1, NULL, -1)) != 0) {
		/* There's nothing we can do if creating the proc fails. */
		kmem_free(rarg->crraa_event_path, MAXPATHLEN);
		kmem_free(rarg->crraa_agent_path, sizeof (cgm->cg_agent));
		kmem_free(rarg, sizeof (cgrp_rra_arg_t));
	}
}

/*ARGSUSED*/
static void
cgrp_lwp_fork_helper(vfs_t *vfsp, uint_t cg_id, id_t tid, pid_t tpid)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	cgrp_node_t *cn;

	mutex_enter(&cgm->cg_contents);
	cn = cgrp_cg_hash_lookup(cgm, cg_id);
	ASSERT(cn != NULL);
	cn->cgn_task_cnt++;
	mutex_exit(&cgm->cg_contents);

	DTRACE_PROBE1(cgrp__lwp__fork, void *, cn);
}

/*ARGSUSED*/
static void
cgrp_lwp_exit_helper(vfs_t *vfsp, uint_t cg_id, id_t tid, pid_t tpid)
{
	cgrp_mnt_t *cgm = (cgrp_mnt_t *)VFSTOCGM(vfsp);
	cgrp_node_t *cn;

	mutex_enter(&cgm->cg_contents);
	cn = cgrp_cg_hash_lookup(cgm, cg_id);
	ASSERT(cn != NULL);
	if (cn->cgn_task_cnt == 0) {
		/* top-level cgroup cnt can be 0 during reboot */
		mutex_exit(&cgm->cg_contents);
		return;
	}
	cn->cgn_task_cnt--;
	DTRACE_PROBE1(cgrp__lwp__exit, void *, cn);

	if (cn->cgn_task_cnt == 0 && cn->cgn_dirents == N_DIRENTS(cgm) &&
	    cn->cgn_notify == 1) {
		cgrp_rel_agent_event(cgm, cn);
		ASSERT(MUTEX_NOT_HELD(&cgm->cg_contents));
	} else {
		mutex_exit(&cgm->cg_contents);
	}
}
