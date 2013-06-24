/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_vfsops.c,v 1.73.64.1 2005/05/27 02:35:28 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <fs/fs_subr.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/zone.h>
#include <sys/vfs_opreg.h>
#include <sys/mntent.h>
#include <sys/priv.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tndb.h>
#include <inet/ip.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

/*
 * Local functions definitions.
 */
int		smbfsinit(int fstyp, char *name);
void		smbfsfini();
static int	smbfs_mount_label_policy(vfs_t *, void *, int, cred_t *);

/*
 * SMBFS Mount options table for MS_OPTIONSTR
 * Note: These are not all the options.
 * Some options come in via MS_DATA.
 * Others are generic (see vfs.c)
 */
static char *intr_cancel[] = { MNTOPT_NOINTR, NULL };
static char *nointr_cancel[] = { MNTOPT_INTR, NULL };
static char *acl_cancel[] = { MNTOPT_NOACL, NULL };
static char *noacl_cancel[] = { MNTOPT_ACL, NULL };
static char *xattr_cancel[] = { MNTOPT_NOXATTR, NULL };
static char *noxattr_cancel[] = { MNTOPT_XATTR, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name		cancel option	default arg	flags
 *		ufs arg flag
 */
	{ MNTOPT_INTR,		intr_cancel,	NULL,	MO_DEFAULT, 0 },
	{ MNTOPT_NOINTR,	nointr_cancel,	NULL,	0,	0 },
	{ MNTOPT_ACL,		acl_cancel,	NULL,	MO_DEFAULT, 0 },
	{ MNTOPT_NOACL,		noacl_cancel,	NULL,	0,	0 },
	{ MNTOPT_XATTR,		xattr_cancel,	NULL,	MO_DEFAULT, 0 },
	{ MNTOPT_NOXATTR,	noxattr_cancel, NULL,	0,	0 }
};

static mntopts_t smbfs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

static const char fs_type_name[FSTYPSZ] = "smbfs";

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	(char *)fs_type_name,
	smbfsinit,		/* init routine */
	VSW_HASPROTO|VSW_NOTZONESAFE,	/* flags */
	&smbfs_mntopts			/* mount options table prototype */
};

static struct modlfs modlfs = {
	&mod_fsops,
	"SMBFS filesystem",
	&vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

/*
 * Mutex to protect the following variables:
 *	  smbfs_major
 *	  smbfs_minor
 */
extern	kmutex_t	smbfs_minor_lock;
extern	int		smbfs_major;
extern	int		smbfs_minor;

/*
 * Prevent unloads while we have mounts
 */
uint32_t	smbfs_mountcount;

/*
 * smbfs vfs operations.
 */
static int	smbfs_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int	smbfs_unmount(vfs_t *, int, cred_t *);
static int	smbfs_root(vfs_t *, vnode_t **);
static int	smbfs_statvfs(vfs_t *, statvfs64_t *);
static int	smbfs_sync(vfs_t *, short, cred_t *);
static void	smbfs_freevfs(vfs_t *);

/*
 * Module loading
 */

/*
 * This routine is invoked automatically when the kernel module
 * containing this routine is loaded.  This allows module specific
 * initialization to be done when the module is loaded.
 */
int
_init(void)
{
	int		error;

	/*
	 * Check compiled-in version of "nsmb"
	 * that we're linked with.  (paranoid)
	 */
	if (nsmb_version != NSMB_VERSION) {
		cmn_err(CE_WARN, "_init: nsmb version mismatch");
		return (ENOTTY);
	}

	smbfs_mountcount = 0;

	/*
	 * NFS calls these two in _clntinit
	 * Easier to follow this way.
	 */
	if ((error = smbfs_subrinit()) != 0) {
		cmn_err(CE_WARN, "_init: smbfs_subrinit failed");
		return (error);
	}

	if ((error = smbfs_vfsinit()) != 0) {
		cmn_err(CE_WARN, "_init: smbfs_vfsinit failed");
		smbfs_subrfini();
		return (error);
	}

	if ((error = smbfs_clntinit()) != 0) {
		cmn_err(CE_WARN, "_init: smbfs_clntinit failed");
		smbfs_vfsfini();
		smbfs_subrfini();
		return (error);
	}

	error = mod_install((struct modlinkage *)&modlinkage);
	return (error);
}

/*
 * Free kernel module resources that were allocated in _init
 * and remove the linkage information into the kernel
 */
int
_fini(void)
{
	int	error;

	/*
	 * If a forcedly unmounted instance is still hanging around,
	 * we cannot allow the module to be unloaded because that would
	 * cause panics once the VFS framework decides it's time to call
	 * into VFS_FREEVFS().
	 */
	if (smbfs_mountcount)
		return (EBUSY);

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	/*
	 * Free the allocated smbnodes, etc.
	 */
	smbfs_clntfini();

	/* NFS calls these two in _clntfini */
	smbfs_vfsfini();
	smbfs_subrfini();

	/*
	 * Free the ops vectors
	 */
	smbfsfini();
	return (0);
}

/*
 * Return information about the module
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info((struct modlinkage *)&modlinkage, modinfop));
}

/*
 * Initialize the vfs structure
 */

int smbfsfstyp;
vfsops_t *smbfs_vfsops = NULL;

static const fs_operation_def_t smbfs_vfsops_template[] = {
	{ VFSNAME_MOUNT, { .vfs_mount = smbfs_mount } },
	{ VFSNAME_UNMOUNT, { .vfs_unmount = smbfs_unmount } },
	{ VFSNAME_ROOT,	{ .vfs_root = smbfs_root } },
	{ VFSNAME_STATVFS, { .vfs_statvfs = smbfs_statvfs } },
	{ VFSNAME_SYNC,	{ .vfs_sync = smbfs_sync } },
	{ VFSNAME_VGET,	{ .error = fs_nosys } },
	{ VFSNAME_MOUNTROOT, { .error = fs_nosys } },
	{ VFSNAME_FREEVFS, { .vfs_freevfs = smbfs_freevfs } },
	{ NULL, NULL }
};

int
smbfsinit(int fstyp, char *name)
{
	int		error;

	error = vfs_setfsops(fstyp, smbfs_vfsops_template, &smbfs_vfsops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "smbfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, smbfs_vnodeops_template, &smbfs_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstyp);
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "smbfsinit: bad vnode ops template");
		return (error);
	}

	smbfsfstyp = fstyp;

	return (0);
}

void
smbfsfini()
{
	if (smbfs_vfsops) {
		(void) vfs_freevfsops_by_type(smbfsfstyp);
		smbfs_vfsops = NULL;
	}
	if (smbfs_vnodeops) {
		vn_freevnodeops(smbfs_vnodeops);
		smbfs_vnodeops = NULL;
	}
}

void
smbfs_free_smi(smbmntinfo_t *smi)
{
	if (smi == NULL)
		return;

	if (smi->smi_zone_ref.zref_zone != NULL)
		zone_rele_ref(&smi->smi_zone_ref, ZONE_REF_SMBFS);

	if (smi->smi_share != NULL)
		smb_share_rele(smi->smi_share);

	avl_destroy(&smi->smi_hash_avl);
	rw_destroy(&smi->smi_hash_lk);
	cv_destroy(&smi->smi_statvfs_cv);
	mutex_destroy(&smi->smi_lock);

	kmem_free(smi, sizeof (smbmntinfo_t));
}

/*
 * smbfs mount vfsop
 * Set up mount info record and attach it to vfs struct.
 */
static int
smbfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	char		*data = uap->dataptr;
	int		error;
	smbnode_t 	*rtnp = NULL;	/* root of this fs */
	smbmntinfo_t 	*smi = NULL;
	dev_t 		smbfs_dev;
	int 		version;
	int 		devfd;
	zone_t		*zone = curproc->p_zone;
	zone_t		*mntzone = NULL;
	smb_share_t 	*ssp = NULL;
	smb_cred_t 	scred;
	int		flags, sec;

	STRUCT_DECL(smbfs_args, args);		/* smbfs mount arguments */

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * get arguments
	 *
	 * uap->datalen might be different from sizeof (args)
	 * in a compatible situation.
	 */
	STRUCT_INIT(args, get_udatamodel());
	bzero(STRUCT_BUF(args), SIZEOF_STRUCT(smbfs_args, DATAMODEL_NATIVE));
	if (copyin(data, STRUCT_BUF(args), MIN(uap->datalen,
	    SIZEOF_STRUCT(smbfs_args, DATAMODEL_NATIVE))))
		return (EFAULT);

	/*
	 * Check mount program version
	 */
	version = STRUCT_FGET(args, version);
	if (version != SMBFS_VERSION) {
		cmn_err(CE_WARN, "mount version mismatch:"
		    " kernel=%d, mount=%d\n",
		    SMBFS_VERSION, version);
		return (EINVAL);
	}

	/*
	 * Deal with re-mount requests.
	 */
	if (uap->flags & MS_REMOUNT) {
		cmn_err(CE_WARN, "MS_REMOUNT not implemented");
		return (ENOTSUP);
	}

	/*
	 * Check for busy
	 */
	mutex_enter(&mvp->v_lock);
	if (!(uap->flags & MS_OVERLAY) &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Get the "share" from the netsmb driver (ssp).
	 * It is returned with a "ref" (hold) for us.
	 * Release this hold: at errout below, or in
	 * smbfs_freevfs().
	 */
	devfd = STRUCT_FGET(args, devfd);
	error = smb_dev2share(devfd, &ssp);
	if (error) {
		cmn_err(CE_WARN, "invalid device handle %d (%d)\n",
		    devfd, error);
		return (error);
	}

	/*
	 * Use "goto errout" from here on.
	 * See: ssp, smi, rtnp, mntzone
	 */

	/*
	 * Determine the zone we're being mounted into.
	 */
	zone_hold(mntzone = zone);		/* start with this assumption */
	if (getzoneid() == GLOBAL_ZONEID) {
		zone_rele(mntzone);
		mntzone = zone_find_by_path(refstr_value(vfsp->vfs_mntpt));
		ASSERT(mntzone != NULL);
		if (mntzone != zone) {
			error = EBUSY;
			goto errout;
		}
	}

	/*
	 * Stop the mount from going any further if the zone is going away.
	 */
	if (zone_status_get(mntzone) >= ZONE_IS_SHUTTING_DOWN) {
		error = EBUSY;
		goto errout;
	}

	/*
	 * On a Trusted Extensions client, we may have to force read-only
	 * for read-down mounts.
	 */
	if (is_system_labeled()) {
		void *addr;
		int ipvers = 0;
		struct smb_vc *vcp;

		vcp = SSTOVC(ssp);
		addr = smb_vc_getipaddr(vcp, &ipvers);
		error = smbfs_mount_label_policy(vfsp, addr, ipvers, cr);

		if (error > 0)
			goto errout;

		if (error == -1) {
			/* change mount to read-only to prevent write-down */
			vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
		}
	}

	/* Prevent unload. */
	atomic_inc_32(&smbfs_mountcount);

	/*
	 * Create a mount record and link it to the vfs struct.
	 * No more possiblities for errors from here on.
	 * Tear-down of this stuff is in smbfs_free_smi()
	 *
	 * Compare with NFS: nfsrootvp()
	 */
	smi = kmem_zalloc(sizeof (*smi), KM_SLEEP);

	mutex_init(&smi->smi_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&smi->smi_statvfs_cv, NULL, CV_DEFAULT, NULL);

	rw_init(&smi->smi_hash_lk, NULL, RW_DEFAULT, NULL);
	smbfs_init_hash_avl(&smi->smi_hash_avl);

	smi->smi_share = ssp;
	ssp = NULL;

	/*
	 * Convert the anonymous zone hold acquired via zone_hold() above
	 * into a zone reference.
	 */
	zone_init_ref(&smi->smi_zone_ref);
	zone_hold_ref(mntzone, &smi->smi_zone_ref, ZONE_REF_SMBFS);
	zone_rele(mntzone);
	mntzone = NULL;

	/*
	 * Initialize option defaults
	 */
	smi->smi_flags	= SMI_LLOCK;
	smi->smi_acregmin = SEC2HR(SMBFS_ACREGMIN);
	smi->smi_acregmax = SEC2HR(SMBFS_ACREGMAX);
	smi->smi_acdirmin = SEC2HR(SMBFS_ACDIRMIN);
	smi->smi_acdirmax = SEC2HR(SMBFS_ACDIRMAX);

	/*
	 * All "generic" mount options have already been
	 * handled in vfs.c:domount() - see mntopts stuff.
	 * Query generic options using vfs_optionisset().
	 */
	if (vfs_optionisset(vfsp, MNTOPT_INTR, NULL))
		smi->smi_flags |= SMI_INT;
	if (vfs_optionisset(vfsp, MNTOPT_ACL, NULL))
		smi->smi_flags |= SMI_ACL;

	/*
	 * Get the mount options that come in as smbfs_args,
	 * starting with args.flags (SMBFS_MF_xxx)
	 */
	flags = STRUCT_FGET(args, flags);
	smi->smi_uid 	= STRUCT_FGET(args, uid);
	smi->smi_gid 	= STRUCT_FGET(args, gid);
	smi->smi_fmode	= STRUCT_FGET(args, file_mode) & 0777;
	smi->smi_dmode	= STRUCT_FGET(args, dir_mode) & 0777;

	/*
	 * Hande the SMBFS_MF_xxx flags.
	 */
	if (flags & SMBFS_MF_NOAC)
		smi->smi_flags |= SMI_NOAC;
	if (flags & SMBFS_MF_ACREGMIN) {
		sec = STRUCT_FGET(args, acregmin);
		if (sec < 0 || sec > SMBFS_ACMINMAX)
			sec = SMBFS_ACMINMAX;
		smi->smi_acregmin = SEC2HR(sec);
	}
	if (flags & SMBFS_MF_ACREGMAX) {
		sec = STRUCT_FGET(args, acregmax);
		if (sec < 0 || sec > SMBFS_ACMAXMAX)
			sec = SMBFS_ACMAXMAX;
		smi->smi_acregmax = SEC2HR(sec);
	}
	if (flags & SMBFS_MF_ACDIRMIN) {
		sec = STRUCT_FGET(args, acdirmin);
		if (sec < 0 || sec > SMBFS_ACMINMAX)
			sec = SMBFS_ACMINMAX;
		smi->smi_acdirmin = SEC2HR(sec);
	}
	if (flags & SMBFS_MF_ACDIRMAX) {
		sec = STRUCT_FGET(args, acdirmax);
		if (sec < 0 || sec > SMBFS_ACMAXMAX)
			sec = SMBFS_ACMAXMAX;
		smi->smi_acdirmax = SEC2HR(sec);
	}

	/*
	 * Get attributes of the remote file system,
	 * i.e. ACL support, named streams, etc.
	 */
	smb_credinit(&scred, cr);
	error = smbfs_smb_qfsattr(smi->smi_share, &smi->smi_fsa, &scred);
	smb_credrele(&scred);
	if (error) {
		SMBVDEBUG("smbfs_smb_qfsattr error %d\n", error);
	}

	/*
	 * We enable XATTR by default (via smbfs_mntopts)
	 * but if the share does not support named streams,
	 * force the NOXATTR option (also clears XATTR).
	 * Caller will set or clear VFS_XATTR after this.
	 */
	if ((smi->smi_fsattr & FILE_NAMED_STREAMS) == 0)
		vfs_setmntopt(vfsp, MNTOPT_NOXATTR, NULL, 0);

	/*
	 * Ditto ACLs (disable if not supported on this share)
	 */
	if ((smi->smi_fsattr & FILE_PERSISTENT_ACLS) == 0) {
		vfs_setmntopt(vfsp, MNTOPT_NOACL, NULL, 0);
		smi->smi_flags &= ~SMI_ACL;
	}

	/*
	 * Assign a unique device id to the mount
	 */
	mutex_enter(&smbfs_minor_lock);
	do {
		smbfs_minor = (smbfs_minor + 1) & MAXMIN32;
		smbfs_dev = makedevice(smbfs_major, smbfs_minor);
	} while (vfs_devismounted(smbfs_dev));
	mutex_exit(&smbfs_minor_lock);

	vfsp->vfs_dev	= smbfs_dev;
	vfs_make_fsid(&vfsp->vfs_fsid, smbfs_dev, smbfsfstyp);
	vfsp->vfs_data	= (caddr_t)smi;
	vfsp->vfs_fstype = smbfsfstyp;
	vfsp->vfs_bsize = MAXBSIZE;
	vfsp->vfs_bcount = 0;

	smi->smi_vfsp	= vfsp;
	smbfs_zonelist_add(smi);	/* undo in smbfs_freevfs */

	/*
	 * Create the root vnode, which we need in unmount
	 * for the call to smbfs_check_table(), etc.
	 * Release this hold in smbfs_unmount.
	 */
	rtnp = smbfs_node_findcreate(smi, "\\", 1, NULL, 0, 0,
	    &smbfs_fattr0);
	ASSERT(rtnp != NULL);
	rtnp->r_vnode->v_type = VDIR;
	rtnp->r_vnode->v_flag |= VROOT;
	smi->smi_root = rtnp;

	/*
	 * NFS does other stuff here too:
	 *   async worker threads
	 *   init kstats
	 *
	 * End of code from NFS nfsrootvp()
	 */
	return (0);

errout:
	vfsp->vfs_data = NULL;
	if (smi != NULL)
		smbfs_free_smi(smi);

	if (mntzone != NULL)
		zone_rele(mntzone);

	if (ssp != NULL)
		smb_share_rele(ssp);

	return (error);
}

/*
 * vfs operations
 */
static int
smbfs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	smbmntinfo_t	*smi;
	smbnode_t	*rtnp;

	smi = VFTOSMI(vfsp);

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	if ((flag & MS_FORCE) == 0) {
		smbfs_rflush(vfsp, cr);

		/*
		 * If there are any active vnodes on this file system,
		 * (other than the root vnode) then the file system is
		 * busy and can't be umounted.
		 */
		if (smbfs_check_table(vfsp, smi->smi_root))
			return (EBUSY);

		/*
		 * We normally hold a ref to the root vnode, so
		 * check for references beyond the one we expect:
		 *   smbmntinfo_t -> smi_root
		 * Note that NFS does not hold the root vnode.
		 */
		if (smi->smi_root &&
		    smi->smi_root->r_vnode->v_count > 1)
			return (EBUSY);
	}

	/*
	 * common code for both forced and non-forced
	 *
	 * Setting VFS_UNMOUNTED prevents new operations.
	 * Operations already underway may continue,
	 * but not for long.
	 */
	vfsp->vfs_flag |= VFS_UNMOUNTED;

	/*
	 * Shutdown any outstanding I/O requests on this share,
	 * and force a tree disconnect.  The share object will
	 * continue to hang around until smb_share_rele().
	 * This should also cause most active nodes to be
	 * released as their operations fail with EIO.
	 */
	smb_share_kill(smi->smi_share);

	/*
	 * If we hold the root VP (and we normally do)
	 * then it's safe to release it now.
	 */
	if (smi->smi_root) {
		rtnp = smi->smi_root;
		smi->smi_root = NULL;
		VN_RELE(rtnp->r_vnode);	/* release root vnode */
	}

	/*
	 * Remove all nodes from the node hash tables.
	 * This (indirectly) calls: smbfs_addfree, smbinactive,
	 * which will try to flush dirty pages, etc. so
	 * don't destroy the underlying share just yet.
	 *
	 * Also, with a forced unmount, some nodes may
	 * remain active, and those will get cleaned up
	 * after their last vn_rele.
	 */
	smbfs_destroy_table(vfsp);

	/*
	 * Delete our kstats...
	 *
	 * Doing it here, rather than waiting until
	 * smbfs_freevfs so these are not visible
	 * after the unmount.
	 */
	if (smi->smi_io_kstats) {
		kstat_delete(smi->smi_io_kstats);
		smi->smi_io_kstats = NULL;
	}
	if (smi->smi_ro_kstats) {
		kstat_delete(smi->smi_ro_kstats);
		smi->smi_ro_kstats = NULL;
	}

	/*
	 * The rest happens in smbfs_freevfs()
	 */
	return (0);
}


/*
 * find root of smbfs
 */
static int
smbfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	smbmntinfo_t	*smi;
	vnode_t		*vp;

	smi = VFTOSMI(vfsp);

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	/*
	 * The root vp is created in mount and held
	 * until unmount, so this is paranoia.
	 */
	if (smi->smi_root == NULL)
		return (EIO);

	/* Just take a reference and return it. */
	vp = SMBTOV(smi->smi_root);
	VN_HOLD(vp);
	*vpp = vp;

	return (0);
}

/*
 * Get file system statistics.
 */
static int
smbfs_statvfs(vfs_t *vfsp, statvfs64_t *sbp)
{
	int		error;
	smbmntinfo_t	*smi = VFTOSMI(vfsp);
	smb_share_t	*ssp = smi->smi_share;
	statvfs64_t	stvfs;
	hrtime_t now;
	smb_cred_t	scred;

	if (curproc->p_zone != smi->smi_zone_ref.zref_zone)
		return (EPERM);

	if (smi->smi_flags & SMI_DEAD || vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	mutex_enter(&smi->smi_lock);

	/*
	 * Use cached result if still valid.
	 */
recheck:
	now = gethrtime();
	if (now < smi->smi_statfstime) {
		error = 0;
		goto cache_hit;
	}

	/*
	 * FS attributes are stale, so someone
	 * needs to do an OTW call to get them.
	 * Serialize here so only one thread
	 * does the OTW call.
	 */
	if (smi->smi_status & SM_STATUS_STATFS_BUSY) {
		smi->smi_status |= SM_STATUS_STATFS_WANT;
		if (!cv_wait_sig(&smi->smi_statvfs_cv, &smi->smi_lock)) {
			mutex_exit(&smi->smi_lock);
			return (EINTR);
		}
		/* Hope status is valid now. */
		goto recheck;
	}
	smi->smi_status |= SM_STATUS_STATFS_BUSY;
	mutex_exit(&smi->smi_lock);

	/*
	 * Do the OTW call.  Note: lock NOT held.
	 */
	smb_credinit(&scred, NULL);
	bzero(&stvfs, sizeof (stvfs));
	error = smbfs_smb_statfs(ssp, &stvfs, &scred);
	smb_credrele(&scred);
	if (error) {
		SMBVDEBUG("statfs error=%d\n", error);
	} else {

		/*
		 * Set a few things the OTW call didn't get.
		 */
		stvfs.f_frsize = stvfs.f_bsize;
		stvfs.f_favail = stvfs.f_ffree;
		stvfs.f_fsid = (unsigned long)vfsp->vfs_fsid.val[0];
		bcopy(fs_type_name, stvfs.f_basetype, FSTYPSZ);
		stvfs.f_flag	= vf_to_stf(vfsp->vfs_flag);
		stvfs.f_namemax	= smi->smi_fsa.fsa_maxname;

		/*
		 * Save the result, update lifetime
		 */
		now = gethrtime();
		smi->smi_statfstime = now +
		    (SM_MAX_STATFSTIME * (hrtime_t)NANOSEC);
		smi->smi_statvfsbuf = stvfs; /* struct assign! */
	}

	mutex_enter(&smi->smi_lock);
	if (smi->smi_status & SM_STATUS_STATFS_WANT)
		cv_broadcast(&smi->smi_statvfs_cv);
	smi->smi_status &= ~(SM_STATUS_STATFS_BUSY | SM_STATUS_STATFS_WANT);

	/*
	 * Copy the statvfs data to caller's buf.
	 * Note: struct assignment
	 */
cache_hit:
	if (error == 0)
		*sbp = smi->smi_statvfsbuf;
	mutex_exit(&smi->smi_lock);
	return (error);
}

static kmutex_t smbfs_syncbusy;

/*
 * Flush dirty smbfs files for file system vfsp.
 * If vfsp == NULL, all smbfs files are flushed.
 */
/*ARGSUSED*/
static int
smbfs_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	/*
	 * Cross-zone calls are OK here, since this translates to a
	 * VOP_PUTPAGE(B_ASYNC), which gets picked up by the right zone.
	 */
	if (!(flag & SYNC_ATTR) && mutex_tryenter(&smbfs_syncbusy) != 0) {
		smbfs_rflush(vfsp, cr);
		mutex_exit(&smbfs_syncbusy);
	}

	return (0);
}

/*
 * Initialization routine for VFS routines.  Should only be called once
 */
int
smbfs_vfsinit(void)
{
	mutex_init(&smbfs_syncbusy, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*
 * Shutdown routine for VFS routines.  Should only be called once
 */
void
smbfs_vfsfini(void)
{
	mutex_destroy(&smbfs_syncbusy);
}

void
smbfs_freevfs(vfs_t *vfsp)
{
	smbmntinfo_t    *smi;

	/* free up the resources */
	smi = VFTOSMI(vfsp);

	/*
	 * By this time we should have already deleted the
	 * smi kstats in the unmount code.  If they are still around
	 * something is wrong
	 */
	ASSERT(smi->smi_io_kstats == NULL);

	smbfs_zonelist_remove(smi);

	smbfs_free_smi(smi);

	/*
	 * Allow _fini() to succeed now, if so desired.
	 */
	atomic_dec_32(&smbfs_mountcount);
}

/*
 * smbfs_mount_label_policy:
 *	Determine whether the mount is allowed according to MAC check,
 *	by comparing (where appropriate) label of the remote server
 *	against the label of the zone being mounted into.
 *
 *	Returns:
 *		 0 :	access allowed
 *		-1 :	read-only access allowed (i.e., read-down)
 *		>0 :	error code, such as EACCES
 *
 * NB:
 * NFS supports Cipso labels by parsing the vfs_resource
 * to see what the Solaris server global zone has shared.
 * We can't support that for CIFS since resource names
 * contain share names, not paths.
 */
static int
smbfs_mount_label_policy(vfs_t *vfsp, void *ipaddr, int addr_type, cred_t *cr)
{
	bslabel_t	*server_sl, *mntlabel;
	zone_t		*mntzone = NULL;
	ts_label_t	*zlabel;
	tsol_tpc_t	*tp;
	ts_label_t	*tsl = NULL;
	int		retv;

	/*
	 * Get the zone's label.  Each zone on a labeled system has a label.
	 */
	mntzone = zone_find_by_any_path(refstr_value(vfsp->vfs_mntpt), B_FALSE);
	zlabel = mntzone->zone_slabel;
	ASSERT(zlabel != NULL);
	label_hold(zlabel);

	retv = EACCES;				/* assume the worst */

	/*
	 * Next, get the assigned label of the remote server.
	 */
	tp = find_tpc(ipaddr, addr_type, B_FALSE);
	if (tp == NULL)
		goto out;			/* error getting host entry */

	if (tp->tpc_tp.tp_doi != zlabel->tsl_doi)
		goto rel_tpc;			/* invalid domain */
	if ((tp->tpc_tp.host_type != UNLABELED))
		goto rel_tpc;			/* invalid hosttype */

	server_sl = &tp->tpc_tp.tp_def_label;
	mntlabel = label2bslabel(zlabel);

	/*
	 * Now compare labels to complete the MAC check.  If the labels
	 * are equal or if the requestor is in the global zone and has
	 * NET_MAC_AWARE, then allow read-write access.   (Except for
	 * mounts into the global zone itself; restrict these to
	 * read-only.)
	 *
	 * If the requestor is in some other zone, but his label
	 * dominates the server, then allow read-down.
	 *
	 * Otherwise, access is denied.
	 */
	if (blequal(mntlabel, server_sl) ||
	    (crgetzoneid(cr) == GLOBAL_ZONEID &&
	    getpflags(NET_MAC_AWARE, cr) != 0)) {
		if ((mntzone == global_zone) ||
		    !blequal(mntlabel, server_sl))
			retv = -1;		/* read-only */
		else
			retv = 0;		/* access OK */
	} else if (bldominates(mntlabel, server_sl)) {
		retv = -1;			/* read-only */
	} else {
		retv = EACCES;
	}

	if (tsl != NULL)
		label_rele(tsl);

rel_tpc:
	/*LINTED*/
	TPC_RELE(tp);
out:
	if (mntzone)
		zone_rele(mntzone);
	label_rele(zlabel);
	return (retv);
}
