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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/tiuser.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/pathname.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <fs/fs_subr.h>
#include <sys/fs/autofs.h>
#include <sys/modctl.h>
#include <sys/mntent.h>
#include <sys/policy.h>
#include <sys/zone.h>

static int autofs_init(int, char *);

static major_t autofs_major;
static minor_t autofs_minor;

kmutex_t autofs_minor_lock;
zone_key_t autofs_key;

static mntopts_t auto_mntopts;

/*
 * The AUTOFS system call.
 */
static struct sysent autofssysent = {
	2,
	SE_32RVAL1 | SE_ARGC | SE_NOUNLOAD,
	autofssys
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"AUTOFS syscall",
	&autofssysent
};

#ifdef	_SYSCALL32_IMPL
static struct modlsys  modlsys32 = {
	&mod_syscallops32,
	"AUTOFS syscall (32-bit)",
	&autofssysent
};
#endif	/* _SYSCALL32_IMPL */

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"autofs",
	autofs_init,
	VSW_HASPROTO|VSW_CANRWRO|VSW_CANREMOUNT|VSW_STATS|VSW_ZMOUNT,
	&auto_mntopts
};

/*
 * Module linkage information for the kernel.
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for autofs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlfs,
	&modlsys,
#ifdef	_SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

/*
 * This is the module initialization routine.
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	/*
	 * Don't allow the autofs module to be unloaded for now.
	 */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int autofs_fstype;

/*
 * autofs VFS operations
 */
static int auto_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int auto_unmount(vfs_t *, int, cred_t *);
static int auto_root(vfs_t *, vnode_t **);
static int auto_statvfs(vfs_t *, struct statvfs64 *);

/*
 * Auto Mount options table
 */

static char *direct_cancel[] = { MNTOPT_INDIRECT, NULL };
static char *indirect_cancel[] = { MNTOPT_DIRECT, NULL };
static char *browse_cancel[] = { MNTOPT_NOBROWSE, NULL };
static char *nobrowse_cancel[] = { MNTOPT_BROWSE, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name		cancel options	default arg	flags
 */
	{ MNTOPT_DIRECT,	direct_cancel,	NULL,		0,
		NULL },
	{ MNTOPT_INDIRECT,	indirect_cancel, NULL,		0,
		NULL },
	{ MNTOPT_IGNORE,	NULL,		NULL,
		MO_DEFAULT|MO_TAG,	NULL },
	{ "nest",		NULL,		NULL,		MO_TAG,
		NULL },
	{ MNTOPT_BROWSE,	browse_cancel,	NULL,		MO_TAG,
		NULL },
	{ MNTOPT_NOBROWSE,	nobrowse_cancel, NULL,		MO_TAG,
		NULL },
	{ MNTOPT_RESTRICT,	NULL,		NULL,		MO_TAG,
		NULL },
};

static mntopts_t auto_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

/*ARGSUSED*/
static void
autofs_zone_destructor(zoneid_t zoneid, void *arg)
{
	struct autofs_globals *fngp = arg;
	vnode_t *vp;

	if (fngp == NULL)
		return;
	ASSERT(fngp->fng_fnnode_count == 1);
	ASSERT(fngp->fng_unmount_threads == 0);

	if (fngp->fng_autofs_daemon_dh != NULL)
		door_ki_rele(fngp->fng_autofs_daemon_dh);
	/*
	 * vn_alloc() initialized the rootnode with a count of 1; we need to
	 * make this 0 to placate auto_freefnnode().
	 */
	vp = fntovn(fngp->fng_rootfnnodep);
	ASSERT(vp->v_count == 1);
	vp->v_count--;
	auto_freefnnode(fngp->fng_rootfnnodep);
	mutex_destroy(&fngp->fng_unmount_threads_lock);
	kmem_free(fngp, sizeof (*fngp));
}

/*
 * rootfnnodep is allocated here.  Its sole purpose is to provide
 * read/write locking for top level fnnodes.  This object is
 * persistent and will not be deallocated until the zone is destroyed.
 *
 * The current zone is implied as the zone of interest, since we will be
 * calling zthread_create() which must be called from the correct zone.
 */
struct autofs_globals *
autofs_zone_init(void)
{
	char rootname[sizeof ("root_fnnode_zone_") + ZONEID_WIDTH];
	struct autofs_globals *fngp;
	zoneid_t zoneid = getzoneid();

	fngp = kmem_zalloc(sizeof (*fngp), KM_SLEEP);
	(void) snprintf(rootname, sizeof (rootname), "root_fnnode_zone_%d",
	    zoneid);
	fngp->fng_rootfnnodep = auto_makefnnode(VNON, NULL, rootname, CRED(),
	    fngp);
	/*
	 * Don't need to hold fng_rootfnnodep as it's never really used for
	 * anything.
	 */
	fngp->fng_fnnode_count = 1;
	fngp->fng_printed_not_running_msg = 0;
	fngp->fng_zoneid = zoneid;
	mutex_init(&fngp->fng_unmount_threads_lock, NULL, MUTEX_DEFAULT,
	    NULL);
	fngp->fng_unmount_threads = 0;

	mutex_init(&fngp->fng_autofs_daemon_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Start the unmounter thread for this zone.
	 */
	(void) zthread_create(NULL, 0, auto_do_unmount, fngp, 0, minclsyspri);
	return (fngp);
}

int
autofs_init(int fstype, char *name)
{
	static const fs_operation_def_t auto_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = auto_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = auto_unmount },
		VFSNAME_ROOT,		{ .vfs_root = auto_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = auto_statvfs },
		NULL,			NULL
	};
	int error;

	autofs_fstype = fstype;
	ASSERT(autofs_fstype != 0);
	/*
	 * Associate VFS ops vector with this fstype
	 */
	error = vfs_setfsops(fstype, auto_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "autofs_init: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, auto_vnodeops_template, &auto_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "autofs_init: bad vnode ops template");
		return (error);
	}

	mutex_init(&autofs_minor_lock, NULL, MUTEX_DEFAULT, NULL);
	/*
	 * Assign unique major number for all autofs mounts
	 */
	if ((autofs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN,
		    "autofs: autofs_init: can't get unique device number");
		mutex_destroy(&autofs_minor_lock);
		return (1);
	}

	/*
	 * We'd like to be able to provide a constructor here, but we can't
	 * since it wants to zthread_create(), something it can't do in a ZSD
	 * constructor.
	 */
	zone_key_create(&autofs_key, NULL, NULL, autofs_zone_destructor);

	return (0);
}

static char *restropts[] = {
	RESTRICTED_MNTOPTS
};

/*
 * This routine adds those options to the option string `buf' which are
 * forced by secpolicy_fs_mount.  If the automatic "security" options
 * are set, the option string gets them added if they aren't already
 * there.  We search the string with "strstr" and make sure that
 * the string we find is bracketed with <start|",">MNTOPT<","|"\0">
 *
 * This is one half of the option inheritence algorithm which
 * implements the "restrict" option.  The other half is implemented
 * in automountd; it takes its cue from the options we add here.
 */
static int
autofs_restrict_opts(struct vfs *vfsp, char *buf, size_t maxlen, size_t *curlen)
{
	int i;
	char *p;
	size_t len = *curlen - 1;

	/* Unrestricted */
	if (!vfs_optionisset(vfsp, restropts[0], NULL))
		return (0);

	for (i = 0; i < sizeof (restropts)/sizeof (restropts[0]); i++) {
		size_t olen = strlen(restropts[i]);

		/* Add "restrict" always and the others insofar set */
		if ((i == 0 || vfs_optionisset(vfsp, restropts[i], NULL)) &&
		    ((p = strstr(buf, restropts[i])) == NULL ||
		    !((p == buf || p[-1] == ',') &&
		    (p[olen] == '\0' || p[olen] == ',')))) {

			if (len + olen + 1 > maxlen)
				return (-1);

			if (*buf != '\0')
				buf[len++] = ',';
			(void) strcpy(&buf[len], restropts[i]);
			len += olen;
		}
	}
	*curlen = len + 1;
	return (0);
}

/* ARGSUSED */
static int
auto_mount(vfs_t *vfsp, vnode_t *vp, struct mounta *uap, cred_t *cr)
{
	int error;
	size_t len = 0;
	autofs_args args;
	fninfo_t *fnip = NULL;
	vnode_t *rootvp = NULL;
	fnnode_t *rootfnp = NULL;
	char *data = uap->dataptr;
	char datalen = uap->datalen;
	dev_t autofs_dev;
	char strbuff[MAXPATHLEN + 1];
	vnode_t *kkvp;
	struct autofs_globals *fngp;
	zone_t *zone = curproc->p_zone;

	AUTOFS_DPRINT((4, "auto_mount: vfs %p vp %p\n", (void *)vfsp,
	    (void *)vp));

	if ((error = secpolicy_fs_mount(cr, vp, vfsp)) != 0)
		return (EPERM);

	if (zone == global_zone) {
		zone_t *mntzone;

		mntzone = zone_find_by_path(refstr_value(vfsp->vfs_mntpt));
		ASSERT(mntzone != NULL);
		zone_rele(mntzone);
		if (mntzone != zone) {
			return (EBUSY);
		}
	}

	/*
	 * Stop the mount from going any further if the zone is going away.
	 */
	if (zone_status_get(zone) >= ZONE_IS_SHUTTING_DOWN)
		return (EBUSY);

	/*
	 * We need a lock to serialize this; minor_lock is as good as any.
	 */
	mutex_enter(&autofs_minor_lock);
	if ((fngp = zone_getspecific(autofs_key, zone)) == NULL) {
		fngp = autofs_zone_init();
		(void) zone_setspecific(autofs_key, zone, fngp);
	}
	mutex_exit(&autofs_minor_lock);
	ASSERT(fngp != NULL);

	/*
	 * Get arguments
	 */
	if (uap->flags & MS_SYSSPACE) {
		if (datalen != sizeof (args))
			return (EINVAL);
		error = kcopy(data, &args, sizeof (args));
	} else {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (datalen != sizeof (args))
				return (EINVAL);
			error = copyin(data, &args, sizeof (args));
		} else {
			struct autofs_args32 args32;

			if (datalen != sizeof (args32))
				return (EINVAL);
			error = copyin(data, &args32, sizeof (args32));

			args.addr.maxlen = args32.addr.maxlen;
			args.addr.len = args32.addr.len;
			args.addr.buf = (char *)(uintptr_t)args32.addr.buf;
			args.path = (char *)(uintptr_t)args32.path;
			args.opts = (char *)(uintptr_t)args32.opts;
			args.map = (char *)(uintptr_t)args32.map;
			args.subdir = (char *)(uintptr_t)args32.subdir;
			args.key = (char *)(uintptr_t)args32.key;
			args.mount_to = args32.mount_to;
			args.rpc_to = args32.rpc_to;
			args.direct = args32.direct;
		}
	}
	if (error)
		return (EFAULT);

	/*
	 * For a remount, only update mount information
	 * i.e. default mount options, map name, etc.
	 */
	if (uap->flags & MS_REMOUNT) {
		fnip = vfstofni(vfsp);
		if (fnip == NULL)
			return (EINVAL);

		if (args.direct == 1)
			fnip->fi_flags |= MF_DIRECT;
		else
			fnip->fi_flags &= ~MF_DIRECT;
		fnip->fi_mount_to = args.mount_to;
		fnip->fi_rpc_to = args.rpc_to;

		/*
		 * Get default options
		 */
		if (uap->flags & MS_SYSSPACE)
			error = copystr(args.opts, strbuff, sizeof (strbuff),
			    &len);
		else
			error = copyinstr(args.opts, strbuff, sizeof (strbuff),
			    &len);
		if (error)
			return (EFAULT);

		if (autofs_restrict_opts(vfsp, strbuff, sizeof (strbuff), &len)
		    != 0) {
			return (EFAULT);
		}

		kmem_free(fnip->fi_opts, fnip->fi_optslen);
		fnip->fi_opts = kmem_alloc(len, KM_SLEEP);
		fnip->fi_optslen = (int)len;
		bcopy(strbuff, fnip->fi_opts, len);

		/*
		 * Get context/map name
		 */
		if (uap->flags & MS_SYSSPACE)
			error = copystr(args.map, strbuff, sizeof (strbuff),
			    &len);
		else
			error = copyinstr(args.map, strbuff, sizeof (strbuff),
			    &len);
		if (error)
			return (EFAULT);

		kmem_free(fnip->fi_map, fnip->fi_maplen);
		fnip->fi_map = kmem_alloc(len, KM_SLEEP);
		fnip->fi_maplen = (int)len;
		bcopy(strbuff, fnip->fi_map, len);

		return (0);
	}

	/*
	 * Allocate fninfo struct and attach it to vfs
	 */
	fnip = kmem_zalloc(sizeof (*fnip), KM_SLEEP);
	fnip->fi_mountvfs = vfsp;

	fnip->fi_mount_to = args.mount_to;
	fnip->fi_rpc_to = args.rpc_to;
	fnip->fi_refcnt = 0;
	vfsp->vfs_bsize = AUTOFS_BLOCKSIZE;
	vfsp->vfs_fstype = autofs_fstype;

	/*
	 * Assign a unique device id to the mount
	 */
	mutex_enter(&autofs_minor_lock);
	do {
		autofs_minor = (autofs_minor + 1) & L_MAXMIN32;
		autofs_dev = makedevice(autofs_major, autofs_minor);
	} while (vfs_devismounted(autofs_dev));
	mutex_exit(&autofs_minor_lock);
	vfsp->vfs_dev = autofs_dev;
	vfs_make_fsid(&vfsp->vfs_fsid, autofs_dev, autofs_fstype);
	vfsp->vfs_data = (void *)fnip;
	vfsp->vfs_bcount = 0;

	/*
	 * Get daemon address
	 */
	fnip->fi_addr.len = args.addr.len;
	fnip->fi_addr.maxlen = fnip->fi_addr.len;
	fnip->fi_addr.buf = kmem_alloc(args.addr.len, KM_SLEEP);
	if (uap->flags & MS_SYSSPACE)
		error = kcopy(args.addr.buf, fnip->fi_addr.buf, args.addr.len);
	else
		error = copyin(args.addr.buf, fnip->fi_addr.buf, args.addr.len);
	if (error) {
		error = EFAULT;
		goto errout;
	}

	fnip->fi_zoneid = getzoneid();
	/*
	 * Get path for mountpoint
	 */
	if (uap->flags & MS_SYSSPACE)
		error = copystr(args.path, strbuff, sizeof (strbuff), &len);
	else
		error = copyinstr(args.path, strbuff, sizeof (strbuff), &len);
	if (error) {
		error = EFAULT;
		goto errout;
	}
	fnip->fi_path = kmem_alloc(len, KM_SLEEP);
	fnip->fi_pathlen = (int)len;
	bcopy(strbuff, fnip->fi_path, len);

	/*
	 * Get default options
	 */
	if (uap->flags & MS_SYSSPACE)
		error = copystr(args.opts, strbuff, sizeof (strbuff), &len);
	else
		error = copyinstr(args.opts, strbuff, sizeof (strbuff), &len);

	if (error != 0 ||
	    autofs_restrict_opts(vfsp, strbuff, sizeof (strbuff), &len) != 0) {
		error = EFAULT;
		goto errout;
	}
	fnip->fi_opts = kmem_alloc(len, KM_SLEEP);
	fnip->fi_optslen = (int)len;
	bcopy(strbuff, fnip->fi_opts, len);

	/*
	 * Get context/map name
	 */
	if (uap->flags & MS_SYSSPACE)
		error = copystr(args.map, strbuff, sizeof (strbuff), &len);
	else
		error = copyinstr(args.map, strbuff, sizeof (strbuff), &len);
	if (error) {
		error = EFAULT;
		goto errout;
	}
	fnip->fi_map = kmem_alloc(len, KM_SLEEP);
	fnip->fi_maplen = (int)len;
	bcopy(strbuff, fnip->fi_map, len);

	/*
	 * Get subdirectory within map
	 */
	if (uap->flags & MS_SYSSPACE)
		error = copystr(args.subdir, strbuff, sizeof (strbuff), &len);
	else
		error = copyinstr(args.subdir, strbuff, sizeof (strbuff), &len);
	if (error) {
		error = EFAULT;
		goto errout;
	}
	fnip->fi_subdir = kmem_alloc(len, KM_SLEEP);
	fnip->fi_subdirlen = (int)len;
	bcopy(strbuff, fnip->fi_subdir, len);

	/*
	 * Get the key
	 */
	if (uap->flags & MS_SYSSPACE)
		error = copystr(args.key, strbuff, sizeof (strbuff), &len);
	else
		error = copyinstr(args.key, strbuff, sizeof (strbuff), &len);
	if (error) {
		error = EFAULT;
		goto errout;
	}
	fnip->fi_key = kmem_alloc(len, KM_SLEEP);
	fnip->fi_keylen = (int)len;
	bcopy(strbuff, fnip->fi_key, len);

	/*
	 * Is this a direct mount?
	 */
	if (args.direct == 1)
		fnip->fi_flags |= MF_DIRECT;

	/*
	 * Setup netconfig.
	 * Can I pass in knconf as mount argument? what
	 * happens when the daemon gets restarted?
	 */
	if ((error = lookupname("/dev/ticotsord", UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &kkvp)) != 0) {
		cmn_err(CE_WARN, "autofs: lookupname: %d", error);
		goto errout;
	}

	fnip->fi_knconf.knc_rdev = kkvp->v_rdev;
	fnip->fi_knconf.knc_protofmly = NC_LOOPBACK;
	fnip->fi_knconf.knc_semantics = NC_TPI_COTS_ORD;
	VN_RELE(kkvp);

	/*
	 * Make the root vnode
	 */
	rootfnp = auto_makefnnode(VDIR, vfsp, fnip->fi_path, cr, fngp);
	if (rootfnp == NULL) {
		error = ENOMEM;
		goto errout;
	}
	rootvp = fntovn(rootfnp);

	rootvp->v_flag |= VROOT;
	rootfnp->fn_mode = AUTOFS_MODE;
	rootfnp->fn_parent = rootfnp;
	/* account for ".." entry */
	rootfnp->fn_linkcnt = rootfnp->fn_size = 1;
	fnip->fi_rootvp = rootvp;

	/*
	 * Add to list of top level AUTOFS' if it is being mounted by
	 * a user level process.
	 */
	if (!(uap->flags & MS_SYSSPACE)) {
		rw_enter(&fngp->fng_rootfnnodep->fn_rwlock, RW_WRITER);
		rootfnp->fn_parent = fngp->fng_rootfnnodep;
		rootfnp->fn_next = fngp->fng_rootfnnodep->fn_dirents;
		fngp->fng_rootfnnodep->fn_dirents = rootfnp;
		rw_exit(&fngp->fng_rootfnnodep->fn_rwlock);
	}

	AUTOFS_DPRINT((5, "auto_mount: vfs %p root %p fnip %p return %d\n",
	    (void *)vfsp, (void *)rootvp, (void *)fnip, error));

	return (0);

errout:
	ASSERT(fnip != NULL);
	ASSERT((uap->flags & MS_REMOUNT) == 0);

	if (fnip->fi_addr.buf != NULL)
		kmem_free(fnip->fi_addr.buf, fnip->fi_addr.len);
	if (fnip->fi_path != NULL)
		kmem_free(fnip->fi_path, fnip->fi_pathlen);
	if (fnip->fi_opts != NULL)
		kmem_free(fnip->fi_opts, fnip->fi_optslen);
	if (fnip->fi_map != NULL)
		kmem_free(fnip->fi_map, fnip->fi_maplen);
	if (fnip->fi_subdir != NULL)
		kmem_free(fnip->fi_subdir, fnip->fi_subdirlen);
	if (fnip->fi_key != NULL)
		kmem_free(fnip->fi_key, fnip->fi_keylen);
	kmem_free(fnip, sizeof (*fnip));

	AUTOFS_DPRINT((5, "auto_mount: vfs %p root %p fnip %p return %d\n",
	    (void *)vfsp, (void *)rootvp, (void *)fnip, error));

	return (error);
}

/* ARGSUSED */
static int
auto_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	fninfo_t *fnip;
	vnode_t *rvp;
	fnnode_t *rfnp, *fnp, *pfnp;
	fnnode_t *myrootfnnodep;

	fnip = vfstofni(vfsp);
	AUTOFS_DPRINT((4, "auto_unmount vfsp %p fnip %p\n", (void *)vfsp,
	    (void *)fnip));

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);
	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	ASSERT(vn_vfswlock_held(vfsp->vfs_vnodecovered));
	rvp = fnip->fi_rootvp;
	rfnp = vntofn(rvp);

	if (rvp->v_count > 1 || rfnp->fn_dirents != NULL)
		return (EBUSY);

	/*
	 * The root vnode is on the linked list of root fnnodes only if
	 * this was not a trigger node. Since we have no way of knowing,
	 * if we don't find it, then we assume it was a trigger node.
	 */
	myrootfnnodep = rfnp->fn_globals->fng_rootfnnodep;
	pfnp = NULL;
	rw_enter(&myrootfnnodep->fn_rwlock, RW_WRITER);
	fnp = myrootfnnodep->fn_dirents;
	while (fnp != NULL) {
		if (fnp == rfnp) {
			/*
			 * A check here is made to see if rvp is busy.  If
			 * so, return EBUSY.  Otherwise proceed with
			 * disconnecting it from the list.
			 */
			if (rvp->v_count > 1 || rfnp->fn_dirents != NULL) {
				rw_exit(&myrootfnnodep->fn_rwlock);
				return (EBUSY);
			}
			if (pfnp)
				pfnp->fn_next = fnp->fn_next;
			else
				myrootfnnodep->fn_dirents = fnp->fn_next;
			fnp->fn_next = NULL;
			break;
		}
		pfnp = fnp;
		fnp = fnp->fn_next;
	}
	rw_exit(&myrootfnnodep->fn_rwlock);

	ASSERT(rvp->v_count == 1);
	ASSERT(rfnp->fn_size == 1);
	ASSERT(rfnp->fn_linkcnt == 1);
	/*
	 * The following drops linkcnt to 0, therefore the disconnect is
	 * not attempted when auto_inactive() is called by
	 * vn_rele(). This is necessary because we have nothing to get
	 * disconnected from since we're the root of the filesystem. As a
	 * side effect the node is not freed, therefore I should free the
	 * node here.
	 *
	 * XXX - I really need to think of a better way of doing this.
	 */
	rfnp->fn_size--;
	rfnp->fn_linkcnt--;

	/*
	 * release of last reference causes node
	 * to be freed
	 */
	VN_RELE(rvp);
	rfnp->fn_parent = NULL;

	auto_freefnnode(rfnp);

	kmem_free(fnip->fi_addr.buf, fnip->fi_addr.len);
	kmem_free(fnip->fi_path, fnip->fi_pathlen);
	kmem_free(fnip->fi_map, fnip->fi_maplen);
	kmem_free(fnip->fi_subdir, fnip->fi_subdirlen);
	kmem_free(fnip->fi_key, fnip->fi_keylen);
	kmem_free(fnip->fi_opts, fnip->fi_optslen);
	kmem_free(fnip, sizeof (*fnip));
	AUTOFS_DPRINT((5, "auto_unmount: return=0\n"));

	return (0);
}


/*
 * find root of autofs
 */
static int
auto_root(vfs_t *vfsp, vnode_t **vpp)
{
	*vpp = (vnode_t *)vfstofni(vfsp)->fi_rootvp;
	VN_HOLD(*vpp);

	AUTOFS_DPRINT((5, "auto_root: vfs %p, *vpp %p\n", (void *)vfsp,
	    (void *)*vpp));
	return (0);
}

/*
 * Get file system statistics.
 */
static int
auto_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	dev32_t d32;

	AUTOFS_DPRINT((4, "auto_statvfs %p\n", (void *)vfsp));

	bzero(sbp, sizeof (*sbp));
	sbp->f_bsize	= vfsp->vfs_bsize;
	sbp->f_frsize	= sbp->f_bsize;
	sbp->f_blocks	= (fsblkcnt64_t)0;
	sbp->f_bfree	= (fsblkcnt64_t)0;
	sbp->f_bavail	= (fsblkcnt64_t)0;
	sbp->f_files	= (fsfilcnt64_t)0;
	sbp->f_ffree	= (fsfilcnt64_t)0;
	sbp->f_favail	= (fsfilcnt64_t)0;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid	= d32;
	(void) strcpy(sbp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN;
	(void) strcpy(sbp->f_fstr, MNTTYPE_AUTOFS);

	return (0);
}
