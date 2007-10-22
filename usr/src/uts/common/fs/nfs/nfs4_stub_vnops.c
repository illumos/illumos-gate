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

/*
 * Support for ephemeral mounts, e.g. mirror-mounts. These mounts are
 * triggered from a "stub" rnode via a special set of vnodeops.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/cmn_err.h>
#include <sys/pathconf.h>
#include <sys/utsname.h>
#include <sys/dnlc.h>
#include <sys/acl.h>
#include <sys/systeminfo.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/list.h>
#include <sys/stat.h>
#include <sys/mntent.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>
#include <nfs/lm.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>
#include <vm/seg_vn.h>

#include <fs/fs_subr.h>

#include <sys/ddi.h>
#include <sys/int_fmtio.h>

#include <util/string.h>

/*
 * The automatic unmounter thread stuff!
 */
static int nfs4_trigger_thread_timer = 20;	/* in seconds */

/*
 * Just a default....
 */
static uint_t nfs4_trigger_mount_to = 240;

typedef struct nfs4_trigger_globals {
	kmutex_t		ntg_forest_lock;
	uint_t			ntg_mount_to;
	int			ntg_thread_started;
	nfs4_ephemeral_tree_t	*ntg_forest;
} nfs4_trigger_globals_t;

kmutex_t	nfs4_ephemeral_thread_lock;

zone_key_t	nfs4_ephemeral_key = ZONE_KEY_UNINITIALIZED;

static void	nfs4_ephemeral_start_harvester(nfs4_trigger_globals_t *);

/*
 * Used for ephemeral mounts; contains data either duplicated from
 * servinfo4_t, or hand-crafted, depending on type of ephemeral mount.
 *
 * It's intended that this structure is used solely for ephemeral
 * mount-type specific data, for passing this data to
 * nfs4_trigger_nargs_create().
 */
typedef struct ephemeral_servinfo {
	char			*esi_hostname;
	char			*esi_netname;
	char			*esi_path;
	int			esi_path_len;
	int			esi_mount_flags;
	struct netbuf		*esi_addr;
	struct netbuf		*esi_syncaddr;
	struct knetconfig	*esi_knconf;
} ephemeral_servinfo_t;

/*
 * Collect together the mount-type specific and generic data args.
 */
typedef struct domount_args {
	ephemeral_servinfo_t	*dma_esi;
	char			*dma_hostlist; /* comma-sep. for RO failover */
	struct nfs_args		*dma_nargs;
} domount_args_t;


/*
 * The vnode ops functions for a trigger stub vnode
 */
static int	nfs4_trigger_open(vnode_t **, int, cred_t *);
static int	nfs4_trigger_getattr(vnode_t *, struct vattr *, int, cred_t *);
static int	nfs4_trigger_setattr(vnode_t *, struct vattr *, int, cred_t *,
			caller_context_t *);
static int	nfs4_trigger_access(vnode_t *, int, int, cred_t *);
static int	nfs4_trigger_readlink(vnode_t *, struct uio *, cred_t *);
static int	nfs4_trigger_lookup(vnode_t *, char *, vnode_t **,
			struct pathname *, int, vnode_t *, cred_t *);
static int	nfs4_trigger_create(vnode_t *, char *, struct vattr *,
			enum vcexcl, int, vnode_t **, cred_t *, int);
static int	nfs4_trigger_remove(vnode_t *, char *, cred_t *);
static int	nfs4_trigger_link(vnode_t *, vnode_t *, char *, cred_t *);
static int	nfs4_trigger_rename(vnode_t *, char *, vnode_t *, char *,
			cred_t *);
static int	nfs4_trigger_mkdir(vnode_t *, char *, struct vattr *,
			vnode_t **, cred_t *);
static int	nfs4_trigger_rmdir(vnode_t *, char *, vnode_t *, cred_t *);
static int	nfs4_trigger_symlink(vnode_t *, char *, struct vattr *, char *,
			cred_t *);
static int	nfs4_trigger_cmp(vnode_t *, vnode_t *);

/*
 * Regular NFSv4 vnodeops that we need to reference directly
 */
extern int	nfs4_getattr(vnode_t *, struct vattr *, int, cred_t *);
extern void	nfs4_inactive(vnode_t *, cred_t *);
extern int	nfs4_rwlock(vnode_t *, int, caller_context_t *);
extern void	nfs4_rwunlock(vnode_t *, int, caller_context_t *);
extern int	nfs4_lookup(vnode_t *, char *, vnode_t **,
    struct pathname *, int, vnode_t *, cred_t *);
extern int	nfs4_pathconf(vnode_t *, int, ulong_t *, cred_t *);
extern int	nfs4_getsecattr(vnode_t *, vsecattr_t *, int, cred_t *);
extern int	nfs4_fid(vnode_t *, fid_t *);
extern int	nfs4_realvp(vnode_t *, vnode_t **);

static int	nfs4_trigger_mount(vnode_t *, vnode_t **);
static int	nfs4_trigger_domount(vnode_t *, domount_args_t *, vfs_t **,
    cred_t *);
static domount_args_t  *nfs4_trigger_domount_args_create(vnode_t *);
static void	nfs4_trigger_domount_args_destroy(domount_args_t *dma,
    vnode_t *vp);
static ephemeral_servinfo_t *nfs4_trigger_esi_create(vnode_t *, servinfo4_t *);
static void	nfs4_trigger_esi_destroy(ephemeral_servinfo_t *, vnode_t *);
static ephemeral_servinfo_t *nfs4_trigger_esi_create_mirrormount(vnode_t *,
    servinfo4_t *);
static struct nfs_args 	*nfs4_trigger_nargs_create(mntinfo4_t *, servinfo4_t *,
    ephemeral_servinfo_t *);
static void	nfs4_trigger_nargs_destroy(struct nfs_args *);
static char	*nfs4_trigger_create_mntopts(vfs_t *);
static void	nfs4_trigger_destroy_mntopts(char *);
static int 	nfs4_trigger_add_mntopt(char *, char *, vfs_t *);
static enum clnt_stat nfs4_trigger_ping_server(servinfo4_t *, int);

extern int	umount2_engine(vfs_t *, int, cred_t *, int);


vnodeops_t *nfs4_trigger_vnodeops;

/*
 * These are the vnodeops that we must define for stub vnodes.
 *
 *
 * Many of the VOPs defined for NFSv4 do not need to be defined here,
 * for various reasons. This will result in the VFS default function being
 * used:
 *
 * - These VOPs require a previous VOP_OPEN to have occurred. That will have
 *   lost the reference to the stub vnode, meaning these should not be called:
 *       close, read, write, ioctl, readdir, seek.
 *
 * - These VOPs are meaningless for vnodes without data pages. Since the
 *   stub vnode is of type VDIR, these should not be called:
 *       space, getpage, putpage, map, addmap, delmap, pageio, fsync.
 *
 * - These VOPs are otherwise not applicable, and should not be called:
 *       dump, setsecattr.
 *
 *
 * These VOPs we do not want to define, but nor do we want the VFS default
 * action. Instead, we specify the VFS error function, with fs_error(), but
 * note that fs_error() is not actually called. Instead it results in the
 * use of the error function defined for the particular VOP, in vn_ops_table[]:
 *
 * -   frlock, dispose, shrlock.
 *
 *
 * These VOPs we define to use the corresponding regular NFSv4 vnodeop.
 * NOTE: if any of these ops involve an OTW call with the stub FH, then
 * that call must be wrapped with save_mnt_secinfo()/check_mnt_secinfo()
 * to protect the security data in the servinfo4_t for the "parent"
 * filesystem that contains the stub.
 *
 * - These VOPs should not trigger a mount, so that "ls -l" does not:
 *       pathconf, getsecattr.
 *
 * - These VOPs would not make sense to trigger:
 *       inactive, rwlock, rwunlock, fid, realvp.
 */
const fs_operation_def_t nfs4_trigger_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = nfs4_trigger_open },
	VOPNAME_GETATTR,	{ .vop_getattr = nfs4_trigger_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = nfs4_trigger_setattr },
	VOPNAME_ACCESS,		{ .vop_access = nfs4_trigger_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = nfs4_trigger_lookup },
	VOPNAME_CREATE,		{ .vop_create = nfs4_trigger_create },
	VOPNAME_REMOVE,		{ .vop_remove = nfs4_trigger_remove },
	VOPNAME_LINK,		{ .vop_link = nfs4_trigger_link },
	VOPNAME_RENAME,		{ .vop_rename = nfs4_trigger_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = nfs4_trigger_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = nfs4_trigger_rmdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = nfs4_trigger_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = nfs4_trigger_readlink },
	VOPNAME_INACTIVE, 	{ .vop_inactive = nfs4_inactive },
	VOPNAME_FID,		{ .vop_fid = nfs4_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = nfs4_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = nfs4_rwunlock },
	VOPNAME_REALVP,		{ .vop_realvp = nfs4_realvp },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = nfs4_getsecattr },
	VOPNAME_PATHCONF,	{ .vop_pathconf = nfs4_pathconf },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL, NULL
};

/*
 * Trigger ops for stub vnodes; for mirror mounts, etc.
 *
 * The general idea is that a "triggering" op will first call
 * nfs4_trigger_mount(), which will find out whether a mount has already
 * been triggered.
 *
 * If it has, then nfs4_trigger_mount() sets newvp to the root vnode
 * of the covering vfs.
 *
 * If a mount has not yet been triggered, nfs4_trigger_mount() will do so,
 * and again set newvp, as above.
 *
 * The triggering op may then re-issue the VOP by calling it on newvp.
 *
 * Note that some ops may perform custom action, and may or may not need
 * to trigger a mount.
 *
 * Some ops need to call the regular NFSv4 vnodeop for a stub vnode. We
 * obviously can't do this with VOP_<whatever>, since it's a stub vnode
 * and that would just recurse. Instead, we call the v4 op directly,
 * by name.  This is OK, since we know that the vnode is for NFSv4,
 * otherwise it couldn't be a stub.
 *
 */

static int
nfs4_trigger_open(vnode_t **vpp, int flag, cred_t *cr)
{
	int error;
	vnode_t *newvp;

	error = nfs4_trigger_mount(*vpp, &newvp);
	if (error)
		return (error);

	/* Release the stub vnode, as we're losing the reference to it */
	VN_RELE(*vpp);

	/* Give the caller the root vnode of the newly-mounted fs */
	*vpp = newvp;

	/* return with VN_HELD(newvp) */
	return (VOP_OPEN(vpp, flag, cr));
}

/*
 * For the majority of cases, nfs4_trigger_getattr() will not trigger
 * a mount. However, if ATTR_TRIGGER is set, we are being informed
 * that we need to force the mount before we attempt to determine
 * the attributes. The intent is an atomic operation for security
 * testing.
 */
static int
nfs4_trigger_getattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr)
{
	int error;

	if (flags & ATTR_TRIGGER) {
		vnode_t	*newvp;

		error = nfs4_trigger_mount(vp, &newvp);
		if (error)
			return (error);

		error = VOP_GETATTR(newvp, vap, flags, cr);
		VN_RELE(newvp);
	} else {
		error = nfs4_getattr(vp, vap, flags, cr);
	}

	return (error);
}

static int
nfs4_trigger_setattr(vnode_t *vp, struct vattr *vap, int flags, cred_t *cr,
		caller_context_t *ct)
{
	int error;
	vnode_t *newvp;

	error = nfs4_trigger_mount(vp, &newvp);
	if (error)
		return (error);

	error = VOP_SETATTR(newvp, vap, flags, cr, ct);
	VN_RELE(newvp);

	return (error);
}

static int
nfs4_trigger_access(vnode_t *vp, int mode, int flags, cred_t *cr)
{
	int error;
	vnode_t *newvp;

	error = nfs4_trigger_mount(vp, &newvp);
	if (error)
		return (error);

	error = VOP_ACCESS(newvp, mode, flags, cr);
	VN_RELE(newvp);

	return (error);
}

static int
nfs4_trigger_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
	int flags, vnode_t *rdir, cred_t *cr)
{
	int error;
	vnode_t *newdvp;
	rnode4_t *drp = VTOR4(dvp);

	ASSERT(RP_ISSTUB(drp));

	/* for now, we only support mirror-mounts */
	ASSERT(RP_ISSTUB_MIRRORMOUNT(drp));

	/*
	 * It's not legal to lookup ".." for an fs root, so we mustn't pass
	 * that up. Instead, pass onto the regular op, regardless of whether
	 * we've triggered a mount.
	 */
	if (strcmp(nm, "..") == 0)
		return (nfs4_lookup(dvp, nm, vpp, pnp, flags, rdir, cr));

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_LOOKUP(newdvp, nm, vpp, pnp, flags, rdir, cr);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_create(vnode_t *dvp, char *nm, struct vattr *va,
		enum vcexcl exclusive, int mode, vnode_t **vpp, cred_t *cr,
		int flags)
{
	int error;
	vnode_t *newdvp;

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_CREATE(newdvp, nm, va, exclusive, mode, vpp, cr, flags);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_remove(vnode_t *dvp, char *nm, cred_t *cr)
{
	int error;
	vnode_t *newdvp;

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_REMOVE(newdvp, nm, cr);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_link(vnode_t *tdvp, vnode_t *svp, char *tnm, cred_t *cr)
{
	int error;
	vnode_t *newtdvp;

	error = nfs4_trigger_mount(tdvp, &newtdvp);
	if (error)
		return (error);

	/*
	 * We don't check whether svp is a stub. Let the NFSv4 code
	 * detect that error, and return accordingly.
	 */
	error = VOP_LINK(newtdvp, svp, tnm, cr);
	VN_RELE(newtdvp);

	return (error);
}

static int
nfs4_trigger_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
		cred_t *cr)
{
	int error;
	vnode_t *newsdvp;
	rnode4_t *tdrp = VTOR4(tdvp);

	/*
	 * We know that sdvp is a stub, otherwise we would not be here.
	 *
	 * If tdvp is also be a stub, there are two possibilities: it
	 * is either the same stub as sdvp [i.e. VN_CMP(sdvp, tdvp)]
	 * or it is a different stub [!VN_CMP(sdvp, tdvp)].
	 *
	 * In the former case, just trigger sdvp, and treat tdvp as
	 * though it were not a stub.
	 *
	 * In the latter case, it might be a different stub for the
	 * same server fs as sdvp, or for a different server fs.
	 * Regardless, from the client perspective this would still
	 * be a cross-filesystem rename, and should not be allowed,
	 * so return EXDEV, without triggering either mount.
	 */
	if (RP_ISSTUB(tdrp) && !VN_CMP(sdvp, tdvp))
		return (EXDEV);

	error = nfs4_trigger_mount(sdvp, &newsdvp);
	if (error)
		return (error);

	error = VOP_RENAME(newsdvp, snm, tdvp, tnm, cr);

	VN_RELE(newsdvp);

	return (error);
}

static int
nfs4_trigger_mkdir(vnode_t *dvp, char *nm, struct vattr *va, vnode_t **vpp,
		cred_t *cr)
{
	int error;
	vnode_t *newdvp;

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_MKDIR(newdvp, nm, va, vpp, cr);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, cred_t *cr)
{
	int error;
	vnode_t *newdvp;

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_RMDIR(newdvp, nm, cdir, cr);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_symlink(vnode_t *dvp, char *lnm, struct vattr *tva, char *tnm,
	cred_t *cr)
{
	int error;
	vnode_t *newdvp;

	error = nfs4_trigger_mount(dvp, &newdvp);
	if (error)
		return (error);

	error = VOP_SYMLINK(newdvp, lnm, tva, tnm, cr);
	VN_RELE(newdvp);

	return (error);
}

static int
nfs4_trigger_readlink(vnode_t *vp, struct uio *uiop, cred_t *cr)
{
	int error;
	vnode_t *newvp;

	error = nfs4_trigger_mount(vp, &newvp);
	if (error)
		return (error);

	error = VOP_READLINK(newvp, uiop, cr);
	VN_RELE(newvp);

	return (error);
}

/* end of trigger vnode ops */


/*
 * Mount upon a trigger vnode; for mirror-mounts, etc.
 *
 * The mount may have already occurred, via another thread. If not,
 * assemble the location information - which may require fetching - and
 * perform the mount.
 *
 * Sets newvp to be the root of the fs that is now covering vp. Note
 * that we return with VN_HELD(*newvp).
 *
 * The caller is responsible for passing the VOP onto the covering fs.
 */
static int
nfs4_trigger_mount(vnode_t *vp, vnode_t **newvpp)
{
	int			 error;
	vfs_t			*vfsp;
	rnode4_t		*rp = VTOR4(vp);
	mntinfo4_t		*mi = VTOMI4(vp);
	domount_args_t		*dma;

	nfs4_ephemeral_tree_t	*net;

	bool_t			must_unlock = FALSE;
	bool_t			is_building = FALSE;

	cred_t			*zcred;

	nfs4_trigger_globals_t	*ntg;

	zone_t			*zone = curproc->p_zone;

	ASSERT(RP_ISSTUB(rp));

	/* for now, we only support mirror-mounts */
	ASSERT(RP_ISSTUB_MIRRORMOUNT(rp));

	*newvpp = NULL;

	/*
	 * Has the mount already occurred?
	 */
	error = vn_vfsrlock_wait(vp);
	if (error)
		goto done;
	vfsp = vn_mountedvfs(vp);
	if (vfsp != NULL) {
		/* the mount has already occurred */
		error = VFS_ROOT(vfsp, newvpp);
		if (!error) {
			/* need to update the reference time  */
			mutex_enter(&mi->mi_lock);
			if (mi->mi_ephemeral)
				mi->mi_ephemeral->ne_ref_time =
				    gethrestime_sec();
			mutex_exit(&mi->mi_lock);
		}

		vn_vfsunlock(vp);
		goto done;
	}
	vn_vfsunlock(vp);

	ntg = zone_getspecific(nfs4_ephemeral_key, zone);
	ASSERT(ntg != NULL);

	mutex_enter(&mi->mi_lock);

	/*
	 * We need to lock down the ephemeral tree.
	 */
	if (mi->mi_ephemeral_tree == NULL) {
		net = kmem_zalloc(sizeof (*net), KM_SLEEP);
		mutex_init(&net->net_tree_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&net->net_cnt_lock, NULL, MUTEX_DEFAULT, NULL);
		net->net_refcnt = 1;
		net->net_status = NFS4_EPHEMERAL_TREE_BUILDING;
		is_building = TRUE;

		/*
		 * We need to add it to the zone specific list for
		 * automatic unmounting and harvesting of deadwood.
		 */
		mutex_enter(&ntg->ntg_forest_lock);
		if (ntg->ntg_forest != NULL)
			net->net_next = ntg->ntg_forest;
		ntg->ntg_forest = net;
		mutex_exit(&ntg->ntg_forest_lock);

		/*
		 * No lock order confusion with mi_lock because no
		 * other node could have grabbed net_tree_lock.
		 */
		mutex_enter(&net->net_tree_lock);
		mi->mi_ephemeral_tree = net;
		net->net_mount = mi;
		mutex_exit(&mi->mi_lock);
	} else {
		net = mi->mi_ephemeral_tree;
		mutex_exit(&mi->mi_lock);

		mutex_enter(&net->net_cnt_lock);
		net->net_refcnt++;
		mutex_exit(&net->net_cnt_lock);

		/*
		 * Note that we do not do any checks to
		 * see if the parent has been nuked.
		 * We count on the vfs layer having protected
		 * us from feet shooters.
		 */
		mutex_enter(&net->net_tree_lock);
	}

	mutex_enter(&net->net_cnt_lock);
	net->net_status |= NFS4_EPHEMERAL_TREE_MOUNTING;
	mutex_exit(&net->net_cnt_lock);

	must_unlock = TRUE;

	dma = nfs4_trigger_domount_args_create(vp);
	if (dma == NULL) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Need to be root for this call to make mount work.
	 * Note that since we define mirror mounts to work
	 * for any user, we allow the mount to proceed. And
	 * we realize that the server will perform security
	 * checks to make sure that the client is allowed
	 * access. Finally, once the mount takes place,
	 * directory permissions will ensure that the
	 * content is secure.
	 */
	zcred = zone_get_kcred(getzoneid());
	ASSERT(zcred != NULL);

	error = nfs4_trigger_domount(vp, dma, &vfsp, zcred);
	nfs4_trigger_domount_args_destroy(dma, vp);

	crfree(zcred);

	if (!error)
		error = VFS_ROOT(vfsp, newvpp);
done:
	if (must_unlock) {
		mutex_enter(&net->net_cnt_lock);
		net->net_status &= ~NFS4_EPHEMERAL_TREE_MOUNTING;
		if (is_building)
			net->net_status &= ~NFS4_EPHEMERAL_TREE_BUILDING;
		net->net_refcnt--;
		mutex_exit(&net->net_cnt_lock);

		mutex_exit(&net->net_tree_lock);
	}

	if (!error && (newvpp == NULL || *newvpp == NULL))
		error = ENOSYS;

	return (error);
}

/*
 * Collect together both the generic & mount-type specific args.
 */
static domount_args_t *
nfs4_trigger_domount_args_create(vnode_t *vp)
{
	int nointr;
	char *hostlist;
	servinfo4_t *svp;
	struct nfs_args *nargs, *nargs_head;
	enum clnt_stat status;
	ephemeral_servinfo_t *esi, *esi_first;
	domount_args_t *dma;
	mntinfo4_t *mi = VTOMI4(vp);

	nointr = !(mi->mi_flags & MI4_INT);
	hostlist = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	svp = mi->mi_curr_serv;
	/* check if the current server is responding */
	status = nfs4_trigger_ping_server(svp, nointr);
	if (status == RPC_SUCCESS) {
		esi_first = nfs4_trigger_esi_create(vp, svp);
		if (esi_first == NULL) {
			kmem_free(hostlist, MAXPATHLEN);
			return (NULL);
		}

		(void) strlcpy(hostlist, esi_first->esi_hostname, MAXPATHLEN);

		nargs_head = nfs4_trigger_nargs_create(mi, svp, esi_first);
	} else {
		/* current server did not respond */
		esi_first = NULL;
		nargs_head = NULL;
	}
	nargs = nargs_head;

	/*
	 * NFS RO failover.
	 *
	 * If we have multiple servinfo4 structures, linked via sv_next,
	 * we must create one nfs_args for each, linking the nfs_args via
	 * nfs_ext_u.nfs_extB.next.
	 *
	 * We need to build a corresponding esi for each, too, but that is
	 * used solely for building nfs_args, and may be immediately
	 * discarded, as domount() requires the info from just one esi,
	 * but all the nfs_args.
	 *
	 * Currently, the NFS mount code will hang if not all servers
	 * requested are available. To avoid that, we need to ping each
	 * server, here, and remove it from the list if it is not
	 * responding. This has the side-effect of that server then
	 * being permanently unavailable for this failover mount, even if
	 * it recovers. That's unfortunate, but the best we can do until
	 * the mount code path is fixed.
	 */

	/*
	 * If the current server was down, loop indefinitely until we find
	 * at least one responsive server.
	 */
	do {
		/* no locking needed for sv_next; it is only set at fs mount */
		for (svp = mi->mi_servers; svp != NULL; svp = svp->sv_next) {
			struct nfs_args *next;

			/*
			 * nargs_head: the head of the nfs_args list
			 * nargs: the current tail of the list
			 * next: the newly-created element to be added
			 */

			/*
			 * We've already tried the current server, above;
			 * if it was responding, we have already included it
			 * and it may now be ignored.
			 *
			 * Otherwise, try it again, since it may now have
			 * recovered.
			 */
			if (svp == mi->mi_curr_serv && esi_first != NULL)
				continue;

			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
			if (svp->sv_flags & SV4_NOTINUSE) {
				nfs_rw_exit(&svp->sv_lock);
				continue;
			}
			nfs_rw_exit(&svp->sv_lock);

			/* check if the server is responding */
			status = nfs4_trigger_ping_server(svp, nointr);
			/* if the server did not respond, ignore it */
			if (status != RPC_SUCCESS)
				continue;

			esi = nfs4_trigger_esi_create(vp, svp);
			if (esi == NULL)
				continue;

			/*
			 * If the original current server (mi_curr_serv)
			 * was down when when we first tried it,
			 * (i.e. esi_first == NULL),
			 * we select this new server (svp) to be the server
			 * that we will actually contact (esi_first).
			 *
			 * Note that it's possible that mi_curr_serv == svp,
			 * if that mi_curr_serv was down but has now recovered.
			 */
			next = nfs4_trigger_nargs_create(mi, svp, esi);
			if (esi_first == NULL) {
				ASSERT(nargs == NULL);
				ASSERT(nargs_head == NULL);
				nargs_head = next;
				esi_first = esi;
				(void) strlcpy(hostlist,
				    esi_first->esi_hostname, MAXPATHLEN);
			} else {
				ASSERT(nargs_head != NULL);
				nargs->nfs_ext_u.nfs_extB.next = next;
				(void) strlcat(hostlist, ",", MAXPATHLEN);
				(void) strlcat(hostlist, esi->esi_hostname,
				    MAXPATHLEN);
				/* esi was only needed for hostname & nargs */
				nfs4_trigger_esi_destroy(esi, vp);
			}

			nargs = next;
		}

		/* if we've had no response at all, wait a second */
		if (esi_first == NULL)
			delay(drv_usectohz(1000000));

	} while (esi_first == NULL);
	ASSERT(nargs_head != NULL);

	dma = kmem_zalloc(sizeof (domount_args_t), KM_SLEEP);
	dma->dma_esi = esi_first;
	dma->dma_hostlist = hostlist;
	dma->dma_nargs = nargs_head;

	return (dma);
}

static void
nfs4_trigger_domount_args_destroy(domount_args_t *dma, vnode_t *vp)
{
	if (dma != NULL) {
		if (dma->dma_esi != NULL && vp != NULL)
			nfs4_trigger_esi_destroy(dma->dma_esi, vp);

		if (dma->dma_hostlist != NULL)
			kmem_free(dma->dma_hostlist, MAXPATHLEN);

		if (dma->dma_nargs != NULL) {
			struct nfs_args *nargs = dma->dma_nargs;

			do {
				struct nfs_args *next =
				    nargs->nfs_ext_u.nfs_extB.next;

				nfs4_trigger_nargs_destroy(nargs);
				nargs = next;
			} while (nargs != NULL);
		}

		kmem_free(dma, sizeof (domount_args_t));
	}
}

/*
 * The ephemeral_servinfo_t struct contains basic information we will need to
 * perform the mount. Whilst the structure is generic across different
 * types of ephemeral mount, the way we gather its contents differs.
 */
static ephemeral_servinfo_t *
nfs4_trigger_esi_create(vnode_t *vp, servinfo4_t *svp)
{
	ephemeral_servinfo_t *esi;
	rnode4_t *rp = VTOR4(vp);

	ASSERT(RP_ISSTUB(rp));

	/* Call the ephemeral type-specific routine */
	if (RP_ISSTUB_MIRRORMOUNT(rp))
		esi = nfs4_trigger_esi_create_mirrormount(vp, svp);
	else
		esi = NULL;

	/* for now, we only support mirror-mounts */
	ASSERT(esi != NULL);

	return (esi);
}

static void
nfs4_trigger_esi_destroy(ephemeral_servinfo_t *esi, vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);

	ASSERT(RP_ISSTUB(rp));

	/* for now, we only support mirror-mounts */
	ASSERT(RP_ISSTUB_MIRRORMOUNT(rp));

	/* Currently, no need for an ephemeral type-specific routine */

	/*
	 * The contents of ephemeral_servinfo_t goes into nfs_args,
	 * and will be handled by nfs4_trigger_nargs_destroy().
	 * We need only free the structure itself.
	 */
	if (esi != NULL)
		kmem_free(esi, sizeof (ephemeral_servinfo_t));
}

/*
 * Some of this may turn out to be common with other ephemeral types,
 * in which case it should be moved to nfs4_trigger_esi_create(), or a
 * common function called.
 */
static ephemeral_servinfo_t *
nfs4_trigger_esi_create_mirrormount(vnode_t *vp, servinfo4_t *svp)
{
	char			*stubpath;
	struct knetconfig	*sikncp, *svkncp;
	struct netbuf		*bufp;
	ephemeral_servinfo_t	*esi;

	esi = kmem_zalloc(sizeof (ephemeral_servinfo_t), KM_SLEEP);

	/* initially set to be our type of ephemeral mount; may be added to */
	esi->esi_mount_flags = NFSMNT_MIRRORMOUNT;

	/*
	 * We're copying info from the stub rnode's servinfo4, but
	 * we must create new copies, not pointers, since this information
	 * is to be associated with the new mount, which will be
	 * unmounted (and its structures freed) separately
	 */

	/*
	 * Sizes passed to kmem_[z]alloc here must match those freed
	 * in nfs4_free_args()
	 */

	/*
	 * We hold sv_lock across kmem_zalloc() calls that may sleep, but this
	 * is difficult to avoid: as we need to read svp to calculate the
	 * sizes to be allocated.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);

	esi->esi_hostname = kmem_zalloc(strlen(svp->sv_hostname) + 1, KM_SLEEP);
	(void) strcat(esi->esi_hostname, svp->sv_hostname);

	esi->esi_addr = kmem_zalloc(sizeof (struct netbuf), KM_SLEEP);
	bufp = esi->esi_addr;
	bufp->len = svp->sv_addr.len;
	bufp->maxlen = svp->sv_addr.maxlen;
	bufp->buf = kmem_zalloc(bufp->len, KM_SLEEP);
	bcopy(svp->sv_addr.buf, bufp->buf, bufp->len);

	esi->esi_knconf = kmem_zalloc(sizeof (*esi->esi_knconf), KM_SLEEP);
	sikncp = esi->esi_knconf;
	svkncp = svp->sv_knconf;
	sikncp->knc_semantics = svkncp->knc_semantics;
	sikncp->knc_protofmly = (caddr_t)kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
	(void) strcat((char *)sikncp->knc_protofmly,
	    (char *)svkncp->knc_protofmly);
	sikncp->knc_proto = (caddr_t)kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
	(void) strcat((char *)sikncp->knc_proto, (char *)svkncp->knc_proto);
	sikncp->knc_rdev = svkncp->knc_rdev;

	/*
	 * Used when AUTH_DH is negotiated.
	 *
	 * This is ephemeral mount-type specific, since it contains the
	 * server's time-sync syncaddr.
	 */
	if (svp->sv_dhsec) {
		struct netbuf *bufp;
		sec_data_t *sdata;
		dh_k4_clntdata_t *data;

		sdata = svp->sv_dhsec;
		data = (dh_k4_clntdata_t *)sdata->data;
		ASSERT(sdata->rpcflavor == AUTH_DH);

		bufp = kmem_zalloc(sizeof (struct netbuf), KM_SLEEP);
		bufp->len = data->syncaddr.len;
		bufp->maxlen = data->syncaddr.maxlen;
		bufp->buf = kmem_zalloc(bufp->len, KM_SLEEP);
		bcopy(data->syncaddr.buf, bufp->buf, bufp->len);
		esi->esi_syncaddr = bufp;

		if (data->netname != NULL) {
			int nmlen = data->netnamelen;

			/*
			 * We need to copy from a dh_k4_clntdata_t
			 * netname/netnamelen pair to a NUL-terminated
			 * netname string suitable for putting in nfs_args,
			 * where the latter has no netnamelen field.
			 */
			esi->esi_netname = kmem_zalloc(nmlen + 1, KM_SLEEP);
			bcopy(data->netname, esi->esi_netname, nmlen);
		}
	} else {
		esi->esi_syncaddr = NULL;
		esi->esi_netname = NULL;
	}

	stubpath = fn_path(VTOSV(vp)->sv_name);
	/* step over initial '.', to avoid e.g. sv_path: "/tank./ws" */
	ASSERT(*stubpath == '.');
	stubpath += 1;

	/* for nfs_args->fh */
	esi->esi_path_len = strlen(svp->sv_path) + strlen(stubpath) + 1;
	esi->esi_path = kmem_zalloc(esi->esi_path_len, KM_SLEEP);
	(void) strcat(esi->esi_path, svp->sv_path);
	(void) strcat(esi->esi_path, stubpath);

	stubpath -= 1;
	/* stubpath allocated by fn_path() */
	kmem_free(stubpath, strlen(stubpath) + 1);

	nfs_rw_exit(&svp->sv_lock);

	return (esi);
}

/*
 * Assemble the args, and call the generic VFS mount function to
 * finally perform the ephemeral mount.
 */
static int
nfs4_trigger_domount(vnode_t *stubvp, domount_args_t *dma, vfs_t **vfsp,
    cred_t *cr)
{
	struct mounta	*uap;
	char		*mntpt, *orig_path, *path;
	const char	*orig_mntpt;
	int		retval;
	int		mntpt_len;
	int		spec_len;
	zone_t		*zone = curproc->p_zone;
	bool_t		has_leading_slash;

	vfs_t			*stubvfsp = stubvp->v_vfsp;
	ephemeral_servinfo_t	*esi = dma->dma_esi;
	struct nfs_args		*nargs = dma->dma_nargs;

	/* first, construct the mount point for the ephemeral mount */
	orig_path = path = fn_path(VTOSV(stubvp)->sv_name);
	orig_mntpt = (char *)refstr_value(stubvfsp->vfs_mntpt);

	if (*orig_path == '.')
		orig_path++;

	/*
	 * Get rid of zone's root path
	 */
	if (zone != global_zone) {
		/*
		 * -1 for trailing '/' and -1 for EOS.
		 */
		if (strncmp(zone->zone_rootpath, orig_mntpt,
		    zone->zone_rootpathlen - 1) == 0) {
			orig_mntpt += (zone->zone_rootpathlen - 2);
		}
	}

	mntpt_len = strlen(orig_mntpt) + strlen(orig_path);
	mntpt = kmem_zalloc(mntpt_len + 1, KM_SLEEP);
	(void) strcat(mntpt, orig_mntpt);
	(void) strcat(mntpt, orig_path);

	kmem_free(path, strlen(path) + 1);
	path = esi->esi_path;
	if (*path == '.')
		path++;
	if (path[0] == '/' && path[1] == '/')
		path++;
	has_leading_slash = (*path == '/');

	spec_len = strlen(dma->dma_hostlist);
	spec_len += strlen(path);

	/* We are going to have to add this in */
	if (!has_leading_slash)
		spec_len++;

	/* We need to get the ':' for dma_hostlist:esi_path */
	spec_len++;

	uap = kmem_zalloc(sizeof (struct mounta), KM_SLEEP);
	uap->spec = kmem_zalloc(spec_len + 1, KM_SLEEP);
	(void) snprintf(uap->spec, spec_len + 1, "%s:%s%s", dma->dma_hostlist,
	    has_leading_slash ? "" : "/", path);

	uap->dir = mntpt;

	uap->flags = MS_SYSSPACE | MS_DATA;
	/* fstype-independent mount options not covered elsewhere */
	/* copy parent's mount(1M) "-m" flag */
	if (stubvfsp->vfs_flag & VFS_NOMNTTAB)
		uap->flags |= MS_NOMNTTAB;

	uap->fstype = MNTTYPE_NFS4;
	uap->dataptr = (char *)nargs;
	/* not needed for MS_SYSSPACE */
	uap->datalen = 0;

	/* use optptr to pass in extra mount options */
	uap->flags |= MS_OPTIONSTR;
	uap->optptr = nfs4_trigger_create_mntopts(stubvfsp);
	if (uap->optptr == NULL) {
		retval = EINVAL;
		goto done;
	}
	/* domount() expects us to count the trailing NUL */
	uap->optlen = strlen(uap->optptr) + 1;

	retval = domount(NULL, uap, stubvp, cr, vfsp);
	if (retval == 0)
		VFS_RELE(*vfsp);
done:
	if (uap->optptr)
		nfs4_trigger_destroy_mntopts(uap->optptr);

	kmem_free(uap->spec, spec_len + 1);
	kmem_free(uap, sizeof (struct mounta));
	kmem_free(mntpt, mntpt_len + 1);

	return (retval);
}

/*
 * Build an nfs_args structure for passing to domount().
 *
 * Ephemeral mount-type specific data comes from the ephemeral_servinfo_t;
 * generic data - common to all ephemeral mount types - is read directly
 * from the parent mount's servinfo4_t and mntinfo4_t, via the stub vnode.
 */
static struct nfs_args *
nfs4_trigger_nargs_create(mntinfo4_t *mi, servinfo4_t *svp,
    ephemeral_servinfo_t *esi)
{
	sec_data_t *secdata;
	struct nfs_args *nargs;

	/* setup the nfs args */
	nargs = kmem_zalloc(sizeof (struct nfs_args), KM_SLEEP);

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);

	nargs->addr = esi->esi_addr;

	/* for AUTH_DH by negotiation */
	if (esi->esi_syncaddr || esi->esi_netname) {
		nargs->flags |= NFSMNT_SECURE;
		nargs->syncaddr = esi->esi_syncaddr;
		nargs->netname = esi->esi_netname;
	}

	nargs->flags |= NFSMNT_KNCONF;
	nargs->knconf = esi->esi_knconf;
	nargs->flags |= NFSMNT_HOSTNAME;
	nargs->hostname = esi->esi_hostname;
	nargs->fh = esi->esi_path;

	/* general mount settings, all copied from parent mount */
	mutex_enter(&mi->mi_lock);

	if (!(mi->mi_flags & MI4_HARD))
		nargs->flags |= NFSMNT_SOFT;

	nargs->flags |= NFSMNT_WSIZE | NFSMNT_RSIZE | NFSMNT_TIMEO |
	    NFSMNT_RETRANS;
	nargs->wsize = mi->mi_stsize;
	nargs->rsize = mi->mi_tsize;
	nargs->timeo = mi->mi_timeo;
	nargs->retrans = mi->mi_retrans;

	if (mi->mi_flags & MI4_INT)
		nargs->flags |= NFSMNT_INT;
	if (mi->mi_flags & MI4_NOAC)
		nargs->flags |= NFSMNT_NOAC;

	nargs->flags |= NFSMNT_ACREGMIN | NFSMNT_ACREGMAX | NFSMNT_ACDIRMIN |
	    NFSMNT_ACDIRMAX;
	nargs->acregmin = HR2SEC(mi->mi_acregmin);
	nargs->acregmax = HR2SEC(mi->mi_acregmax);
	nargs->acdirmin = HR2SEC(mi->mi_acdirmin);
	nargs->acdirmax = HR2SEC(mi->mi_acdirmax);

	if (mi->mi_flags & MI4_NOCTO)
		nargs->flags |= NFSMNT_NOCTO;
	if (mi->mi_flags & MI4_GRPID)
		nargs->flags |= NFSMNT_GRPID;
	if (mi->mi_flags & MI4_LLOCK)
		nargs->flags |= NFSMNT_LLOCK;
	if (mi->mi_flags & MI4_NOPRINT)
		nargs->flags |= NFSMNT_NOPRINT;
	if (mi->mi_flags & MI4_DIRECTIO)
		nargs->flags |= NFSMNT_DIRECTIO;
	if (mi->mi_flags & MI4_PUBLIC)
		nargs->flags |= NFSMNT_PUBLIC;

	mutex_exit(&mi->mi_lock);

	/* add any specific flags for this type of ephemeral mount */
	nargs->flags |= esi->esi_mount_flags;

	/*
	 * Security data & negotiation policy.
	 *
	 * We need to preserve the parent mount's preference for security
	 * negotiation, translating SV4_TRYSECDEFAULT -> NFSMNT_SECDEFAULT.
	 *
	 * If SV4_TRYSECDEFAULT is not set, that indicates that a specific
	 * security flavour was requested, with data in sv_secdata, and that
	 * no negotiation should occur. If this specified flavour fails, that's
	 * it. We will copy sv_secdata, and not set NFSMNT_SECDEFAULT.
	 *
	 * If SV4_TRYSECDEFAULT is set, then we start with a passed-in
	 * default flavour, in sv_secdata, but then negotiate a new flavour.
	 * Possible flavours are recorded in an array in sv_secinfo, with
	 * currently in-use flavour pointed to by sv_currsec.
	 *
	 * If sv_currsec is set, i.e. if negotiation has already occurred,
	 * we will copy sv_currsec. Otherwise, copy sv_secdata. Regardless,
	 * we will set NFSMNT_SECDEFAULT, to enable negotiation.
	 */
	if (svp->sv_flags & SV4_TRYSECDEFAULT) {
		/* enable negotiation for ephemeral mount */
		nargs->flags |= NFSMNT_SECDEFAULT;

		/*
		 * As a starting point for negotiation, copy parent
		 * mount's negotiated flavour (sv_currsec) if available,
		 * or its passed-in flavour (sv_secdata) if not.
		 */
		if (svp->sv_currsec != NULL)
			secdata = copy_sec_data(svp->sv_currsec);
		else if (svp->sv_secdata != NULL)
			secdata = copy_sec_data(svp->sv_secdata);
		else
			secdata = NULL;
	} else {
		/* do not enable negotiation; copy parent's passed-in flavour */
		if (svp->sv_secdata != NULL)
			secdata = copy_sec_data(svp->sv_secdata);
		else
			secdata = NULL;
	}

	nfs_rw_exit(&svp->sv_lock);

	nargs->flags |= NFSMNT_NEWARGS;
	nargs->nfs_args_ext = NFS_ARGS_EXTB;
	nargs->nfs_ext_u.nfs_extB.secdata = secdata;

	/* for NFS RO failover; caller will set if necessary */
	nargs->nfs_ext_u.nfs_extB.next = NULL;

	return (nargs);
}

static void
nfs4_trigger_nargs_destroy(struct nfs_args *nargs)
{
	/*
	 * Either the mount failed, in which case the data is not needed, or
	 * nfs4_mount() has either taken copies of what it needs or,
	 * where it has merely copied the ptr, it has set *our* ptr to NULL,
	 * whereby nfs4_free_args() will ignore it.
	 */
	nfs4_free_args(nargs);
	kmem_free(nargs, sizeof (struct nfs_args));
}

/*
 * When we finally get into the mounting, we need to add this
 * node to the ephemeral tree.
 *
 * This is called from nfs4_mount().
 */
void
nfs4_record_ephemeral_mount(mntinfo4_t *mi, vnode_t *mvp)
{
	mntinfo4_t		*mi_parent;
	nfs4_ephemeral_t	*eph;
	nfs4_ephemeral_tree_t	*net;

	nfs4_ephemeral_t	*prior;
	nfs4_ephemeral_t	*child;

	nfs4_ephemeral_t	*peer;

	nfs4_trigger_globals_t	*ntg;
	zone_t			*zone = curproc->p_zone;

	mi_parent = VTOMI4(mvp);

	/*
	 * Get this before grabbing anything else!
	 */
	ntg = zone_getspecific(nfs4_ephemeral_key, zone);
	if (!ntg->ntg_thread_started) {
		nfs4_ephemeral_start_harvester(ntg);
	}

	mutex_enter(&mi_parent->mi_lock);
	mutex_enter(&mi->mi_lock);

	/*
	 * We need to tack together the ephemeral mount
	 * with this new mntinfo.
	 */
	eph = kmem_zalloc(sizeof (*eph), KM_SLEEP);
	eph->ne_mount = mi;
	eph->ne_ref_time = gethrestime_sec();

	/*
	 * We need to tell the ephemeral mount when
	 * to time out.
	 */
	eph->ne_mount_to = ntg->ntg_mount_to;

	mi->mi_flags |= MI4_EPHEMERAL;
	mi->mi_ephemeral = eph;

	net = mi->mi_ephemeral_tree =
	    mi_parent->mi_ephemeral_tree;
	ASSERT(net != NULL);

	/*
	 * If the enclosing mntinfo4 is also ephemeral,
	 * then we need to point to its enclosing parent.
	 * Else the enclosing mntinfo4 is the enclosing parent.
	 *
	 * We also need to weave this ephemeral node
	 * into the tree.
	 */
	if (mi_parent->mi_flags & MI4_EPHEMERAL) {
		/*
		 * We need to decide if we are
		 * the root node of this branch
		 * or if we are a sibling of this
		 * branch.
		 */
		prior = mi_parent->mi_ephemeral;
		ASSERT(prior != NULL);
		if (prior->ne_child == NULL) {
			prior->ne_child = eph;
		} else {
			child = prior->ne_child;

			prior->ne_child = eph;
			eph->ne_peer = child;

			child->ne_prior = eph;
		}

		eph->ne_prior = prior;
	} else {
		/*
		 * The parent mntinfo4 is the non-ephemeral
		 * root of the ephemeral tree. We
		 * need to decide if we are the root
		 * node of that tree or if we are a
		 * sibling of the root node.
		 *
		 * We are the root if there is no
		 * other node.
		 */
		if (net->net_root == NULL) {
			net->net_root = eph;
		} else {
			eph->ne_peer = peer = net->net_root;
			ASSERT(peer != NULL);
			net->net_root = eph;

			peer->ne_prior = eph;
		}

		eph->ne_prior = NULL;
	}

	mutex_exit(&mi->mi_lock);
	mutex_exit(&mi_parent->mi_lock);
}

/*
 * Commit the changes to the ephemeral tree for removing this node.
 */
static void
nfs4_ephemeral_umount_cleanup(nfs4_ephemeral_t *eph)
{
	nfs4_ephemeral_t	*e = eph;
	nfs4_ephemeral_t	*peer;
	nfs4_ephemeral_t	*prior;

	peer = eph->ne_peer;
	prior = e->ne_prior;

	/*
	 * If this branch root was not the
	 * tree root, then we need to fix back pointers.
	 */
	if (prior) {
		if (prior->ne_child == e) {
			prior->ne_child = peer;
		} else {
			prior->ne_peer = peer;
		}

		if (peer)
			peer->ne_prior = prior;
	} else if (peer) {
		peer->ne_mount->mi_ephemeral_tree->net_root = peer;
		peer->ne_prior = NULL;
	} else {
		e->ne_mount->mi_ephemeral_tree->net_root = NULL;
	}
}

/*
 * We want to avoid recursion at all costs. So we need to
 * unroll the tree. We do this by a depth first traversal to
 * leaf nodes. We blast away the leaf and work our way back
 * up and down the tree.
 */
static int
nfs4_ephemeral_unmount_engine(nfs4_ephemeral_t *eph,
    int isTreeRoot, int flag, cred_t *cr)
{
	nfs4_ephemeral_t	*e = eph;
	nfs4_ephemeral_t	*prior;
	mntinfo4_t		*mi;
	vfs_t			*vfsp;
	int			error;

	/*
	 * We use the loop while unrolling the ephemeral tree.
	 */
	for (;;) {
		/*
		 * First we walk down the child.
		 */
		if (e->ne_child) {
			prior = e;
			e = e->ne_child;
			continue;
		}

		/*
		 * If we are the root of the branch we are removing,
		 * we end it here. But if the branch is the root of
		 * the tree, we have to forge on. We do not consider
		 * the peer list for the root because while it may
		 * be okay to remove, it is both extra work and a
		 * potential for a false-positive error to stall the
		 * unmount attempt.
		 */
		if (e == eph && isTreeRoot == FALSE)
			return (0);

		/*
		 * Next we walk down the peer list.
		 */
		if (e->ne_peer) {
			prior = e;
			e = e->ne_peer;
			continue;
		}

		/*
		 * We can only remove the node passed in by the
		 * caller if it is the root of the ephemeral tree.
		 * Otherwise, the caller will remove it.
		 */
		if (e == eph && isTreeRoot == FALSE)
			return (0);

		/*
		 * Okay, we have a leaf node, time
		 * to prune it!
		 *
		 * Note that prior can only be NULL if
		 * and only if it is the root of the
		 * ephemeral tree.
		 */
		prior = e->ne_prior;

		mi = e->ne_mount;
		mutex_enter(&mi->mi_lock);
		vfsp = mi->mi_vfsp;

		/*
		 * Cleared by umount2_engine.
		 */
		VFS_HOLD(vfsp);

		/*
		 * Inform nfs4_unmount to not recursively
		 * descend into this node's children when it
		 * gets processed.
		 */
		mi->mi_flags |= MI4_EPHEMERAL_RECURSED;
		mutex_exit(&mi->mi_lock);

		error = umount2_engine(vfsp, flag, cr, FALSE);
		if (error) {
			/*
			 * We need to reenable nfs4_unmount's ability
			 * to recursively descend on this node.
			 */
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI4_EPHEMERAL_RECURSED;
			mutex_exit(&mi->mi_lock);

			return (error);
		}

		/*
		 * If we are the current node, we do not want to
		 * touch anything else. At this point, the only
		 * way the current node can have survived to here
		 * is if it is the root of the ephemeral tree and
		 * we are unmounting the enclosing mntinfo4.
		 */
		if (e == eph) {
			ASSERT(prior == NULL);
			return (0);
		}

		/*
		 * Stitch up the prior node. Note that since
		 * we have handled the root of the tree, prior
		 * must be non-NULL.
		 */
		ASSERT(prior != NULL);
		if (prior->ne_child == e) {
			prior->ne_child = NULL;
		} else {
			ASSERT(prior->ne_peer == e);

			prior->ne_peer = NULL;
		}

		e = prior;
	}

	/* NOTREACHED */
}

/*
 * Common code to safely release net_cnt_lock and net_tree_lock
 */
void
nfs4_ephemeral_umount_unlock(bool_t *pmust_unlock,
    nfs4_ephemeral_tree_t **pnet)
{
	nfs4_ephemeral_tree_t	*net = *pnet;

	if (*pmust_unlock) {
		mutex_enter(&net->net_cnt_lock);
		net->net_refcnt--;
		net->net_status &= ~NFS4_EPHEMERAL_TREE_UMOUNTING;
		mutex_exit(&net->net_cnt_lock);

		mutex_exit(&net->net_tree_lock);

		*pmust_unlock = FALSE;
	}
}

/*
 * While we may have removed any child or sibling nodes of this
 * ephemeral node, we can not nuke it until we know that there
 * were no actived vnodes on it. This will do that final
 * work once we know it is not busy.
 */
void
nfs4_ephemeral_umount_activate(mntinfo4_t *mi, bool_t *pmust_unlock,
    nfs4_ephemeral_tree_t **pnet)
{
	/*
	 * Now we need to get rid of the ephemeral data if it exists.
	 */
	mutex_enter(&mi->mi_lock);
	if (mi->mi_ephemeral) {
		/*
		 * If we are the root node of an ephemeral branch
		 * which is being removed, then we need to fixup
		 * pointers into and out of the node.
		 */
		if (!(mi->mi_flags & MI4_EPHEMERAL_RECURSED))
			nfs4_ephemeral_umount_cleanup(mi->mi_ephemeral);

		ASSERT(mi->mi_ephemeral != NULL);

		kmem_free(mi->mi_ephemeral, sizeof (*mi->mi_ephemeral));
		mi->mi_ephemeral = NULL;
	}
	mutex_exit(&mi->mi_lock);

	nfs4_ephemeral_umount_unlock(pmust_unlock, pnet);
}

/*
 * Unmount an ephemeral node.
 */
int
nfs4_ephemeral_umount(mntinfo4_t *mi, int flag, cred_t *cr,
    bool_t *pmust_unlock, nfs4_ephemeral_tree_t **pnet)
{
	int			error = 0;
	nfs4_ephemeral_t	*eph;
	nfs4_ephemeral_tree_t	*net;
	int			is_derooting = FALSE;
	int			is_recursed = FALSE;
	int			was_locked = FALSE;

	/*
	 * The active vnodes on this file system may be ephemeral
	 * children. We need to check for and try to unmount them
	 * here. If any can not be unmounted, we are going
	 * to return EBUSY.
	 */
	mutex_enter(&mi->mi_lock);

	/*
	 * If an ephemeral tree, we need to check to see if
	 * the lock is already held. If it is, then we need
	 * to see if we are being called as a result of
	 * the recursive removal of some node of the tree or
	 * if we are another attempt to remove the tree.
	 *
	 * mi_flags & MI4_EPHEMERAL indicates an ephemeral
	 * node. mi_ephemeral being non-NULL also does this.
	 *
	 * mi_ephemeral_tree being non-NULL is sufficient
	 * to also indicate either it is an ephemeral node
	 * or the enclosing mntinfo4.
	 *
	 * Do we need MI4_EPHEMERAL? Yes, it is useful for
	 * when we delete the ephemeral node and need to
	 * differentiate from an ephemeral node and the
	 * enclosing root node.
	 */
	*pnet = net = mi->mi_ephemeral_tree;
	eph = mi->mi_ephemeral;
	if (net) {
		is_recursed = mi->mi_flags & MI4_EPHEMERAL_RECURSED;
		is_derooting = (eph == NULL);
		mutex_exit(&mi->mi_lock);

		/*
		 * If this is not recursion, then we need to
		 * grab a ref count.
		 *
		 * But wait, we also do not want to do that
		 * if a harvester thread has already grabbed
		 * the lock.
		 */
		if (!is_recursed) {
			mutex_enter(&net->net_cnt_lock);
			if (net->net_status &
			    NFS4_EPHEMERAL_TREE_LOCKED)
				was_locked = TRUE;
			else
				net->net_refcnt++;
			mutex_exit(&net->net_cnt_lock);
		}

		/*
		 * If we grab the lock, it means that no other
		 * operation is working on the tree. If we don't
		 * grab it, we need to decide if this is because
		 * we are a recursive call or a new operation.
		 *
		 * If we are a recursive call, we proceed without
		 * the lock.
		 *
		 * Else we have to wait until the lock becomes free.
		 */
		if (was_locked == FALSE &&
		    !mutex_tryenter(&net->net_tree_lock)) {
			if (!is_recursed) {
				mutex_enter(&net->net_cnt_lock);
				if (net->net_status &
				    (NFS4_EPHEMERAL_TREE_DEROOTING
				    | NFS4_EPHEMERAL_TREE_INVALID)) {
					net->net_refcnt--;
					mutex_exit(&net->net_cnt_lock);
					goto is_busy;
				}
				mutex_exit(&net->net_cnt_lock);

				/*
				 * We can't hold any other locks whilst
				 * we wait on this to free up.
				 */
				mutex_enter(&net->net_tree_lock);

				/*
				 * Note that while mi->mi_ephemeral
				 * may change and thus we have to
				 * update eph, it is the case that
				 * we have tied down net and
				 * do not care if mi->mi_ephemeral_tree
				 * has changed.
				 */
				mutex_enter(&mi->mi_lock);
				eph = mi->mi_ephemeral;
				mutex_exit(&mi->mi_lock);

				/*
				 * Okay, we need to see if either the
				 * tree got nuked or the current node
				 * got nuked. Both of which will cause
				 * an error.
				 *
				 * Note that a subsequent retry of the
				 * umount shall work.
				 */
				mutex_enter(&net->net_cnt_lock);
				if (net->net_status &
				    NFS4_EPHEMERAL_TREE_INVALID ||
				    (!is_derooting && eph == NULL)) {
					net->net_refcnt--;
					mutex_exit(&net->net_cnt_lock);
					mutex_exit(&net->net_tree_lock);
					goto is_busy;
				}
				mutex_exit(&net->net_cnt_lock);
				*pmust_unlock = TRUE;
			}
		} else if (was_locked == FALSE) {
			/*
			 * If we grab it right away, everything must
			 * be great!
			 */
			*pmust_unlock = TRUE;
		}

		/*
		 * Only once we have grabbed the lock can we mark what we
		 * are planning on doing to the ephemeral tree.
		 */
		if (*pmust_unlock) {
			mutex_enter(&net->net_cnt_lock);
			net->net_status |= NFS4_EPHEMERAL_TREE_UMOUNTING;

			/*
			 * Check to see if we are nuking the root.
			 */
			if (is_derooting)
				net->net_status |=
				    NFS4_EPHEMERAL_TREE_DEROOTING;
			mutex_exit(&net->net_cnt_lock);
		}

		if (!is_derooting) {
			/*
			 * Only work on children if the caller has not already
			 * done so.
			 */
			if (!is_recursed) {
				ASSERT(eph != NULL);

				error = nfs4_ephemeral_unmount_engine(eph,
				    FALSE, flag, cr);
				if (error)
					goto is_busy;
			}
		} else {
			eph = net->net_root;

			/*
			 * Only work if there is something there.
			 */
			if (eph) {
				error = nfs4_ephemeral_unmount_engine(eph, TRUE,
				    flag, cr);
				if (error) {
					mutex_enter(&net->net_cnt_lock);
					net->net_status &=
					    ~NFS4_EPHEMERAL_TREE_DEROOTING;
					mutex_exit(&net->net_cnt_lock);
					goto is_busy;
				}

				/*
				 * Nothing else which goes wrong will
				 * invalidate the blowing away of the
				 * ephmeral tree.
				 */
				net->net_root = NULL;
			}

			/*
			 * We have derooted and we have caused the tree to be
			 * invalid.
			 */
			mutex_enter(&net->net_cnt_lock);
			net->net_status &= ~NFS4_EPHEMERAL_TREE_DEROOTING;
			net->net_status |= NFS4_EPHEMERAL_TREE_INVALID;
			net->net_refcnt--;
			mutex_exit(&net->net_cnt_lock);

			/*
			 * At this point, the tree should no
			 * longer be associated with the
			 * mntinfo4. We need to pull it off
			 * there and let the harvester take
			 * care of it once the refcnt drops.
			 */
			mutex_enter(&mi->mi_lock);
			mi->mi_ephemeral_tree = NULL;
			mutex_exit(&mi->mi_lock);
		}
	} else {
		mutex_exit(&mi->mi_lock);
	}

	return (0);

is_busy:

	nfs4_ephemeral_umount_unlock(pmust_unlock, pnet);

	return (error);
}

/*
 * Do the umount and record any error in the parent.
 */
static void
nfs4_ephemeral_record_umount(vfs_t *vfsp, int flag,
    nfs4_ephemeral_t *e, nfs4_ephemeral_t *prior)
{
	int	error;

	error = umount2_engine(vfsp, flag, kcred, FALSE);
	if (error) {
		if (prior) {
			if (prior->ne_child == e)
				prior->ne_state |=
				    NFS4_EPHEMERAL_CHILD_ERROR;
			else
				prior->ne_state |=
				    NFS4_EPHEMERAL_PEER_ERROR;
		}
	}
}

/*
 * For each tree in the forest (where the forest is in
 * effect all of the ephemeral trees for this zone),
 * scan to see if a node can be unmounted. Note that
 * unlike nfs4_ephemeral_unmount_engine(), we do
 * not process the current node before children or
 * siblings. I.e., if a node can be unmounted, we
 * do not recursively check to see if the nodes
 * hanging off of it can also be unmounted.
 *
 * Instead, we delve down deep to try and remove the
 * children first. Then, because we share code with
 * nfs4_ephemeral_unmount_engine(), we will try
 * them again. This could be a performance issue in
 * the future.
 *
 * Also note that unlike nfs4_ephemeral_unmount_engine(),
 * we do not halt on an error. We will not remove the
 * current node, but we will keep on trying to remove
 * the others.
 *
 * force indicates that we want the unmount to occur
 * even if there is something blocking it.
 *
 * time_check indicates that we want to see if the
 * mount has expired past mount_to or not. Typically
 * we want to do this and only on a shutdown of the
 * zone would we want to ignore the check.
 */
static void
nfs4_ephemeral_harvest_forest(nfs4_trigger_globals_t *ntg,
    bool_t force, bool_t time_check)
{
	nfs4_ephemeral_tree_t	*net;
	nfs4_ephemeral_tree_t	*prev = NULL;
	nfs4_ephemeral_tree_t	*next;
	nfs4_ephemeral_t	*e;
	nfs4_ephemeral_t	*prior;
	time_t			now = gethrestime_sec();

	nfs4_ephemeral_tree_t	*harvest = NULL;

	int			flag;

	mntinfo4_t		*mi;
	vfs_t			*vfsp;

	if (force)
		flag = MS_FORCE;
	else
		flag = 0;

	mutex_enter(&ntg->ntg_forest_lock);
	for (net = ntg->ntg_forest; net != NULL; net = next) {
		next = net->net_next;

		mutex_enter(&net->net_cnt_lock);
		net->net_refcnt++;
		mutex_exit(&net->net_cnt_lock);

		mutex_enter(&net->net_tree_lock);

		/*
		 * Let the unmount code know that the
		 * tree is already locked!
		 */
		mutex_enter(&net->net_cnt_lock);
		net->net_status |= NFS4_EPHEMERAL_TREE_LOCKED;
		mutex_exit(&net->net_cnt_lock);

		/*
		 * If the intent is force all ephemeral nodes to
		 * be unmounted in this zone, we can short circuit a
		 * lot of tree traversal and simply zap the root node.
		 */
		if (force) {
			if (net->net_root) {
				mi = net->net_root->ne_mount;
				vfsp = mi->mi_vfsp;

				/*
				 * Cleared by umount2_engine.
				 */
				VFS_HOLD(vfsp);

				(void) umount2_engine(vfsp, flag,
				    kcred, FALSE);

				goto check_done;
			}
		}

		e = net->net_root;
		if (e)
			e->ne_state = NFS4_EPHEMERAL_VISIT_CHILD;

		while (e) {
			if (e->ne_state == NFS4_EPHEMERAL_VISIT_CHILD) {
				e->ne_state = NFS4_EPHEMERAL_VISIT_SIBLING;
				if (e->ne_child) {
					e = e->ne_child;
					e->ne_state =
					    NFS4_EPHEMERAL_VISIT_CHILD;
				}

				continue;
			} else if (e->ne_state ==
			    NFS4_EPHEMERAL_VISIT_SIBLING) {
				e->ne_state = NFS4_EPHEMERAL_PROCESS_ME;
				if (e->ne_peer) {
					e = e->ne_peer;
					e->ne_state =
					    NFS4_EPHEMERAL_VISIT_CHILD;
				}

				continue;
			} else if (e->ne_state ==
			    NFS4_EPHEMERAL_CHILD_ERROR) {
				prior = e->ne_prior;

				/*
				 * If a child reported an error, do
				 * not bother trying to unmount.
				 *
				 * If your prior node is a parent,
				 * pass the error up such that they
				 * also do not try to unmount.
				 *
				 * However, if your prior is a sibling,
				 * let them try to unmount if they can.
				 */
				if (prior) {
					if (prior->ne_child == e)
						prior->ne_state |=
						    NFS4_EPHEMERAL_CHILD_ERROR;
					else
						prior->ne_state |=
						    NFS4_EPHEMERAL_PEER_ERROR;
				}

				/*
				 * Clear the error and if needed, process peers.
				 *
				 * Once we mask out the error, we know whether
				 * or we have to process another node.
				 */
				e->ne_state &= ~NFS4_EPHEMERAL_CHILD_ERROR;
				if (e->ne_state == NFS4_EPHEMERAL_PROCESS_ME)
					e = prior;

				continue;
			} else if (e->ne_state ==
			    NFS4_EPHEMERAL_PEER_ERROR) {
				prior = e->ne_prior;

				if (prior) {
					if (prior->ne_child == e)
						prior->ne_state =
						    NFS4_EPHEMERAL_CHILD_ERROR;
					else
						prior->ne_state =
						    NFS4_EPHEMERAL_PEER_ERROR;
				}

				/*
				 * Clear the error from this node and do the
				 * correct processing.
				 */
				e->ne_state &= ~NFS4_EPHEMERAL_PEER_ERROR;
				continue;
			}

			prior = e->ne_prior;
			e->ne_state = NFS4_EPHEMERAL_OK;

			/*
			 * It must be the case that we need to process
			 * this node.
			 */
			if (!time_check ||
			    now - e->ne_ref_time > e->ne_mount_to) {
				mi = e->ne_mount;
				vfsp = mi->mi_vfsp;

				/*
				 * Cleared by umount2_engine.
				 */
				VFS_HOLD(vfsp);

				/*
				 * Note that we effectively work down to the
				 * leaf nodes first, try to unmount them,
				 * then work our way back up into the leaf
				 * nodes.
				 *
				 * Also note that we deal with a lot of
				 * complexity by sharing the work with
				 * the manual unmount code.
				 */
				nfs4_ephemeral_record_umount(vfsp, flag,
				    e, prior);
			}

			e = prior;
		}

check_done:

		/*
		 * Are we done with this tree?
		 */
		mutex_enter(&net->net_cnt_lock);
		if (net->net_refcnt == 1 &&
		    net->net_status & NFS4_EPHEMERAL_TREE_INVALID) {
			net->net_refcnt--;
			net->net_status &= ~NFS4_EPHEMERAL_TREE_LOCKED;
			mutex_exit(&net->net_cnt_lock);
			mutex_exit(&net->net_tree_lock);

			if (prev)
				prev->net_next = net->net_next;
			else
				ntg->ntg_forest = net->net_next;

			net->net_next = harvest;
			harvest = net;
			continue;
		}

		net->net_refcnt--;
		net->net_status &= ~NFS4_EPHEMERAL_TREE_LOCKED;
		mutex_exit(&net->net_cnt_lock);
		mutex_exit(&net->net_tree_lock);

		prev = net;
	}
	mutex_exit(&ntg->ntg_forest_lock);

	for (net = harvest; net != NULL; net = next) {
		next = net->net_next;

		mutex_destroy(&net->net_tree_lock);
		mutex_destroy(&net->net_cnt_lock);
		kmem_free(net, sizeof (*net));
	}
}

/*
 * This is the thread which decides when the harvesting
 * can proceed and when to kill it off for this zone.
 */
static void
nfs4_ephemeral_harvester(nfs4_trigger_globals_t *ntg)
{
	clock_t		timeleft;
	zone_t		*zone = curproc->p_zone;

	for (;;) {
		timeleft = zone_status_timedwait(zone, lbolt +
		    nfs4_trigger_thread_timer * hz, ZONE_IS_SHUTTING_DOWN);

		/*
		 * zone is exiting...
		 */
		if (timeleft != -1) {
			ASSERT(zone_status_get(zone) >= ZONE_IS_SHUTTING_DOWN);
			zthread_exit();
			/* NOTREACHED */
		}

		/*
		 * Only bother scanning if there is potential
		 * work to be done.
		 */
		if (ntg->ntg_forest == NULL)
			continue;

		/*
		 * Now scan the list and get rid of everything which
		 * is old.
		 */
		nfs4_ephemeral_harvest_forest(ntg, FALSE, TRUE);
	}

	/* NOTREACHED */
}

/*
 * The zone specific glue needed to start the unmount harvester.
 *
 * Note that we want to avoid holding the mutex as long as possible,
 * hence the multiple checks.
 *
 * The caller should avoid us getting down here in the first
 * place.
 */
static void
nfs4_ephemeral_start_harvester(nfs4_trigger_globals_t *ntg)
{
	/*
	 * It got started before we got here...
	 */
	if (ntg->ntg_thread_started)
		return;

	mutex_enter(&nfs4_ephemeral_thread_lock);

	if (ntg->ntg_thread_started) {
		mutex_exit(&nfs4_ephemeral_thread_lock);
		return;
	}

	/*
	 * Start the unmounter harvester thread for this zone.
	 */
	(void) zthread_create(NULL, 0, nfs4_ephemeral_harvester,
	    ntg, 0, minclsyspri);

	ntg->ntg_thread_started = TRUE;
	mutex_exit(&nfs4_ephemeral_thread_lock);
}

/*ARGSUSED*/
static void *
nfs4_ephemeral_zsd_create(zoneid_t zoneid)
{
	nfs4_trigger_globals_t	*ntg;

	ntg = kmem_zalloc(sizeof (*ntg), KM_SLEEP);
	ntg->ntg_thread_started = FALSE;

	/*
	 * This is the default....
	 */
	ntg->ntg_mount_to = nfs4_trigger_thread_timer;

	mutex_init(&ntg->ntg_forest_lock, NULL,
	    MUTEX_DEFAULT, NULL);

	return (ntg);
}

/*
 * Try a nice gentle walk down the forest and convince
 * all of the trees to gracefully give it up.
 */
/*ARGSUSED*/
static void
nfs4_ephemeral_zsd_shutdown(zoneid_t zoneid, void *arg)
{
	nfs4_trigger_globals_t	*ntg = arg;

	if (!ntg)
		return;

	nfs4_ephemeral_harvest_forest(ntg, FALSE, FALSE);
}

/*
 * Race along the forest and rip all of the trees out by
 * their rootballs!
 */
/*ARGSUSED*/
static void
nfs4_ephemeral_zsd_destroy(zoneid_t zoneid, void *arg)
{
	nfs4_trigger_globals_t	*ntg = arg;

	if (!ntg)
		return;

	nfs4_ephemeral_harvest_forest(ntg, TRUE, FALSE);

	mutex_destroy(&ntg->ntg_forest_lock);
	kmem_free(ntg, sizeof (*ntg));
}

/*
 * This is the zone independent cleanup needed for
 * emphemeral mount processing.
 */
void
nfs4_ephemeral_fini(void)
{
	(void) zone_key_delete(nfs4_ephemeral_key);
	mutex_destroy(&nfs4_ephemeral_thread_lock);
}

/*
 * This is the zone independent initialization needed for
 * emphemeral mount processing.
 */
void
nfs4_ephemeral_init(void)
{
	mutex_init(&nfs4_ephemeral_thread_lock, NULL, MUTEX_DEFAULT,
	    NULL);

	zone_key_create(&nfs4_ephemeral_key, nfs4_ephemeral_zsd_create,
	    nfs4_ephemeral_zsd_shutdown, nfs4_ephemeral_zsd_destroy);
}

/*
 * nfssys() calls this function to set the per-zone
 * value of mount_to to drive when an ephemeral mount is
 * timed out. Each mount will grab a copy of this value
 * when mounted.
 */
void
nfs4_ephemeral_set_mount_to(uint_t mount_to)
{
	nfs4_trigger_globals_t	*ntg;
	zone_t			*zone = curproc->p_zone;

	ntg = zone_getspecific(nfs4_ephemeral_key, zone);

	ntg->ntg_mount_to = mount_to;
}

/*
 * Walk the list of v4 mount options; if they are currently set in vfsp,
 * append them to a new comma-separated mount option string, and return it.
 *
 * Caller should free by calling nfs4_trigger_destroy_mntopts().
 */
static char *
nfs4_trigger_create_mntopts(vfs_t *vfsp)
{
	uint_t i;
	char *mntopts;
	struct vfssw *vswp;
	mntopts_t *optproto;

	mntopts = kmem_zalloc(MAX_MNTOPT_STR, KM_SLEEP);

	/* get the list of applicable mount options for v4; locks *vswp */
	vswp = vfs_getvfssw(MNTTYPE_NFS4);
	optproto = &vswp->vsw_optproto;

	for (i = 0; i < optproto->mo_count; i++) {
		struct mntopt *mop = &optproto->mo_list[i];

		if (mop->mo_flags & MO_EMPTY)
			continue;

		if (nfs4_trigger_add_mntopt(mntopts, mop->mo_name, vfsp)) {
			kmem_free(mntopts, MAX_MNTOPT_STR);
			vfs_unrefvfssw(vswp);
			return (NULL);
		}
	}

	vfs_unrefvfssw(vswp);

	/*
	 * MNTOPT_XATTR is not in the v4 mount opt proto list,
	 * and it may only be passed via MS_OPTIONSTR, so we
	 * must handle it here.
	 *
	 * Ideally, it would be in the list, but NFS does not specify its
	 * own opt proto list, it uses instead the default one. Since
	 * not all filesystems support extended attrs, it would not be
	 * appropriate to add it there.
	 */
	if (nfs4_trigger_add_mntopt(mntopts, MNTOPT_XATTR, vfsp) ||
	    nfs4_trigger_add_mntopt(mntopts, MNTOPT_NOXATTR, vfsp)) {
		kmem_free(mntopts, MAX_MNTOPT_STR);
		return (NULL);
	}

	return (mntopts);
}

static void
nfs4_trigger_destroy_mntopts(char *mntopts)
{
	if (mntopts)
		kmem_free(mntopts, MAX_MNTOPT_STR);
}

/*
 * Check a single mount option (optname). Add to mntopts if it is set in VFS.
 */
static int
nfs4_trigger_add_mntopt(char *mntopts, char *optname, vfs_t *vfsp)
{
	if (mntopts == NULL || optname == NULL || vfsp == NULL)
		return (EINVAL);

	if (vfs_optionisset(vfsp, optname, NULL)) {
		size_t mntoptslen = strlen(mntopts);
		size_t optnamelen = strlen(optname);

		/* +1 for ',', +1 for NUL */
		if (mntoptslen + optnamelen + 2 > MAX_MNTOPT_STR)
			return (EOVERFLOW);

		/* first or subsequent mount option? */
		if (*mntopts != '\0')
			(void) strcat(mntopts, ",");

		(void) strcat(mntopts, optname);
	}

	return (0);
}

static enum clnt_stat
nfs4_trigger_ping_server(servinfo4_t *svp, int nointr)
{
	int retries, error;
	uint_t max_msgsize;
	enum clnt_stat status;
	CLIENT *cl;
	struct timeval timeout;

	/* as per recov_newserver() */
	max_msgsize = 0;
	retries = 1;
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr, NFS_PROGRAM,
	    NFS_V4, max_msgsize, retries, CRED(), &cl);
	if (error)
		return (RPC_FAILED);

	if (nointr)
		cl->cl_nosignal = TRUE;
	status = CLNT_CALL(cl, RFS_NULL, xdr_void, NULL, xdr_void, NULL,
	    timeout);
	if (nointr)
		cl->cl_nosignal = FALSE;

	AUTH_DESTROY(cl->cl_auth);
	CLNT_DESTROY(cl);

	return (status);
}
