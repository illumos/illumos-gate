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
 * Copyright (c) 2015 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/systm.h>
#include <sys/id_space.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/policy.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include <sys/fs/bootfs_impl.h>

/*
 * While booting, additional types of modules and files can be passed in to the
 * loader. These include the familiar boot archive, as well as, a module hash
 * and additional modules that are interpreted as files. As part of the handoff
 * in early boot, information about these modules are saved as properties on the
 * root of the devinfo tree, similar to other boot-time properties.
 *
 * This file system provides a read-only view of those additional files. Due to
 * its limited scope, it has a slightly simpler construction than several other
 * file systems. When mounted, it looks for the corresponding properties and
 * creates bootfs_node_t's and vnodes for all of the corresponding files and
 * directories that exist along the way. At this time, there are currently a
 * rather small number of files passed in this way.
 *
 * This does lead to one behavior that folks used to other file systems might
 * find peculiar. Because we are not always actively creating and destroying the
 * required vnodes on demand, the count on the root vnode will not be going up
 * accordingly with the existence of other vnodes. This means that a bootfs file
 * system that is not in use will have all of its vnodes exist with a v_count of
 * one.
 */

major_t bootfs_major;
static int bootfs_fstype;
static id_space_t *bootfs_idspace;
static uint64_t bootfs_nactive;
static kmutex_t bootfs_lock;

static const char *bootfs_name = "bootfs";

static int
bootfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	int ret;
	bootfs_t *bfs;
	struct pathname dpn;
	dev_t fsdev;

	if ((ret = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (ret);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if (uap->flags & MS_REMOUNT)
		return (EBUSY);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * We indicate that the backing store is bootfs. We don't want to use
	 * swap, because folks might think that this is putting all the data
	 * into memory ala tmpfs. Rather these modules are always in memory and
	 * there's nothing to be done about that.
	 */
	vfs_setresource(vfsp, bootfs_name, 0);
	bfs = kmem_zalloc(sizeof (bootfs_t), KM_NOSLEEP | KM_NORMALPRI);
	if (bfs == NULL)
		return (ENOMEM);

	ret = pn_get(uap->dir,
	    (uap->flags & MS_SYSSPACE) ? UIO_SYSSPACE : UIO_USERSPACE, &dpn);
	if (ret != 0) {
		kmem_free(bfs, sizeof (bfs));
		return (ret);
	}

	bfs->bfs_minor = id_alloc(bootfs_idspace);
	bfs->bfs_kstat = kstat_create_zone("bootfs", bfs->bfs_minor, "bootfs",
	    "fs", KSTAT_TYPE_NAMED,
	    sizeof (bootfs_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID);
	if (bfs->bfs_kstat == NULL) {
		id_free(bootfs_idspace, bfs->bfs_minor);
		pn_free(&dpn);
		kmem_free(bfs, sizeof (bfs));
		return (ENOMEM);
	}
	bfs->bfs_kstat->ks_data = &bfs->bfs_stat;

	fsdev = makedevice(bootfs_major, bfs->bfs_minor);
	bfs->bfs_vfsp = vfsp;

	vfsp->vfs_data = (caddr_t)bfs;
	vfsp->vfs_fstype = bootfs_fstype;
	vfsp->vfs_dev = fsdev;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_RDONLY | VFS_NOSETUID | VFS_NOTRUNC |
	    VFS_UNLINKABLE;
	vfs_make_fsid(&vfsp->vfs_fsid, fsdev, bootfs_fstype);
	bfs->bfs_mntpath = kmem_alloc(dpn.pn_pathlen + 1, KM_SLEEP);
	bcopy(dpn.pn_path, bfs->bfs_mntpath, dpn.pn_pathlen);
	bfs->bfs_mntpath[dpn.pn_pathlen] = '\0';
	pn_free(&dpn);
	list_create(&bfs->bfs_nodes, sizeof (bootfs_node_t),
	    offsetof(bootfs_node_t, bvn_alink));

	kstat_named_init(&bfs->bfs_stat.bfss_nfiles, "nfiles",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&bfs->bfs_stat.bfss_ndirs, "ndirs",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&bfs->bfs_stat.bfss_nbytes, "nbytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&bfs->bfs_stat.bfss_ndups, "ndup",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&bfs->bfs_stat.bfss_ndiscards, "ndiscard",
	    KSTAT_DATA_UINT32);

	bootfs_construct(bfs);

	kstat_install(bfs->bfs_kstat);

	return (0);
}

static int
bootfs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	int ret;
	bootfs_t *bfs = vfsp->vfs_data;
	bootfs_node_t *bnp;

	if ((ret = secpolicy_fs_unmount(cr, vfsp)) != 0)
		return (ret);

	if (flag & MS_FORCE)
		return (ENOTSUP);

	for (bnp = list_head(&bfs->bfs_nodes); bnp != NULL;
	    bnp = list_next(&bfs->bfs_nodes, bnp)) {
		mutex_enter(&bnp->bvn_vnp->v_lock);
		if (bnp->bvn_vnp->v_count > 1) {
			mutex_exit(&bnp->bvn_vnp->v_lock);
			return (EBUSY);
		}
		mutex_exit(&bnp->bvn_vnp->v_lock);
	}

	kstat_delete(bfs->bfs_kstat);
	bootfs_destruct(bfs);
	list_destroy(&bfs->bfs_nodes);
	kmem_free(bfs->bfs_mntpath, strlen(bfs->bfs_mntpath) + 1);
	id_free(bootfs_idspace, bfs->bfs_minor);
	kmem_free(bfs, sizeof (bootfs_t));
	return (0);
}

static int
bootfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	bootfs_t *bfs;

	bfs = (bootfs_t *)vfsp->vfs_data;
	*vpp = bfs->bfs_rootvn->bvn_vnp;
	VN_HOLD(*vpp)

	return (0);
}

static int
bootfs_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	const bootfs_t *bfs = (bootfs_t *)vfsp;
	dev32_t d32;

	sbp->f_bsize = PAGESIZE;
	sbp->f_frsize = PAGESIZE;

	sbp->f_blocks = bfs->bfs_stat.bfss_nbytes.value.ui64 >> PAGESHIFT;
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;

	sbp->f_files = bfs->bfs_stat.bfss_nfiles.value.ui32 +
	    bfs->bfs_stat.bfss_ndirs.value.ui32;
	sbp->f_ffree = 0;
	sbp->f_favail = 0;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strlcpy(sbp->f_basetype, bootfs_name, FSTYPSZ);
	bzero(sbp->f_fstr, sizeof (sbp->f_fstr));

	return (0);
}

static const fs_operation_def_t bootfs_vfsops_tmpl[] = {
	VFSNAME_MOUNT,		{ .vfs_mount = bootfs_mount },
	VFSNAME_UNMOUNT,	{ .vfs_unmount = bootfs_unmount },
	VFSNAME_ROOT,		{ .vfs_root = bootfs_root },
	VFSNAME_STATVFS,	{ .vfs_statvfs = bootfs_statvfs },
	NULL,			NULL
};

static int
bootfs_init(int fstype, char *name)
{
	int ret;

	bootfs_fstype = fstype;
	ASSERT(bootfs_fstype != 0);

	ret = vfs_setfsops(fstype, bootfs_vfsops_tmpl, NULL);
	if (ret != 0)
		return (ret);

	ret = vn_make_ops(name, bootfs_vnodeops_template, &bootfs_vnodeops);
	if (ret != 0) {
		(void) vfs_freevfsops_by_type(bootfs_fstype);
		return (ret);
	}

	bootfs_major = getudev();
	if (bootfs_major == (major_t)-1) {
		cmn_err(CE_WARN, "bootfs_init: Can't get unique device number");
		bootfs_major = 0;
	}

	bootfs_nactive = 0;
	return (0);
}

static mntopts_t bootfs_mntopts = {
	0, NULL
};

static vfsdef_t bootfs_vfsdef = {
	VFSDEF_VERSION,
	"bootfs",
	bootfs_init,
	VSW_HASPROTO|VSW_STATS,
	&bootfs_mntopts
};

static struct modlfs bootfs_modlfs = {
	&mod_fsops, "boot-time modules file system", &bootfs_vfsdef
};

static struct modlinkage bootfs_modlinkage = {
	MODREV_1, &bootfs_modlfs, NULL
};

int
_init(void)
{
	bootfs_node_cache = kmem_cache_create("bootfs_node_cache",
	    sizeof (bootfs_node_t), 0, bootfs_node_constructor,
	    bootfs_node_destructor, NULL, NULL, NULL, 0);
	bootfs_idspace = id_space_create("bootfs_minors", 1, INT32_MAX);
	mutex_init(&bootfs_lock, NULL, MUTEX_DEFAULT, NULL);

	return (mod_install(&bootfs_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&bootfs_modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	mutex_enter(&bootfs_lock);
	if (bootfs_nactive > 0) {
		mutex_exit(&bootfs_lock);
		return (EBUSY);
	}
	mutex_exit(&bootfs_lock);

	err = mod_remove(&bootfs_modlinkage);
	if (err != 0)
		return (err);

	(void) vfs_freevfsops_by_type(bootfs_fstype);
	vn_freevnodeops(bootfs_vnodeops);
	id_space_destroy(bootfs_idspace);
	mutex_destroy(&bootfs_lock);
	kmem_cache_destroy(bootfs_node_cache);
	return (err);
}
