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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2013 Joyent, Inc. All rights reserved.
 */

/*
 *	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *		All rights reserved.
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/bootconf.h>
#include <fs/fs_subr.h>
#include <rpc/types.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode.h>
#include <nfs/mount.h>
#include <nfs/nfssys.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/zone.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/ddi.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/svc.h>

/*
 * The pseudo NFS filesystem to allow diskless booting to dynamically
 * mount either a NFS V2, NFS V3, or NFS V4 filesystem.  This only implements
 * the VFS_MOUNTROOT op and is only intended to be used by the
 * diskless booting code until the real root filesystem is mounted.
 * Nothing else should ever call this!
 *
 * The strategy is that if the initial rootfs type is set to "nfsdyn"
 * by loadrootmodules() this filesystem is called to mount the
 * root filesystem.  It first attempts to mount a V4 filesystem, and if that
 * fails due to an RPC version mismatch it tries V3 and finally V2.
 * Once the real mount succeeds the vfsops and rootfs name are changed
 * to reflect the real filesystem type.
 */
static int nfsdyninit(int, char *);
static int nfsdyn_mountroot(vfs_t *, whymountroot_t);

vfsops_t *nfsdyn_vfsops;

/*
 * The following data structures are used to configure the NFS
 * system call, the NFS Version 2 client VFS, and the NFS Version
 * 3 client VFS into the system.  The NFS Version 4 structures are defined in
 * nfs4_common.c
 */

/*
 * The NFS system call.
 */
static struct sysent nfssysent = {
	2,
	SE_32RVAL1 | SE_ARGC | SE_NOUNLOAD,
	nfssys
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"NFS syscall, client, and common",
	&nfssysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"NFS syscall, client, and common (32-bit)",
	&nfssysent
};
#endif /* _SYSCALL32_IMPL */

/*
 * The NFS Dynamic client VFS.
 */
static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"nfsdyn",
	nfsdyninit,
	0,
	NULL
};

static struct modlfs modlfs = {
	&mod_fsops,
	"network filesystem",
	&vfw
};

/*
 * The NFS Version 2 client VFS.
 */
static vfsdef_t vfw2 = {
	VFSDEF_VERSION,
	"nfs",
	nfsinit,
	VSW_CANREMOUNT|VSW_NOTZONESAFE|VSW_STATS,
	NULL
};

static struct modlfs modlfs2 = {
	&mod_fsops,
	"network filesystem version 2",
	&vfw2
};

/*
 * The NFS Version 3 client VFS.
 */
static vfsdef_t vfw3 = {
	VFSDEF_VERSION,
	"nfs3",
	nfs3init,
	VSW_CANREMOUNT|VSW_NOTZONESAFE|VSW_STATS,
	NULL
};

static struct modlfs modlfs3 = {
	&mod_fsops,
	"network filesystem version 3",
	&vfw3
};

extern struct modlfs modlfs4;

/*
 * We have too many linkage structures so we define our own XXX
 */
struct modlinkage_big {
	int		ml_rev;		/* rev of loadable modules system */
	void		*ml_linkage[7];	/* NULL terminated list of */
					/* linkage structures */
};

/*
 * All of the module configuration linkages required to configure
 * the system call and client VFS's into the system.
 */
static struct modlinkage_big modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	&modlfs,
	&modlfs2,
	&modlfs3,
	&modlfs4,
	NULL
};

/*
 * This routine is invoked automatically when the kernel module
 * containing this routine is loaded.  This allows module specific
 * initialization to be done when the module is loaded.
 */
int
_init(void)
{
	int status;

	if ((status = nfs_clntinit()) != 0) {
		cmn_err(CE_WARN, "_init: nfs_clntinit failed");
		return (status);
	}

	/*
	 * Create the version specific kstats.
	 *
	 * PSARC 2001/697 Contract Private Interface
	 * All nfs kstats are under SunMC contract
	 * Please refer to the PSARC listed above and contact
	 * SunMC before making any changes!
	 *
	 * Changes must be reviewed by Solaris File Sharing
	 * Changes must be communicated to contract-2001-697@sun.com
	 *
	 */

	zone_key_create(&nfsstat_zone_key, nfsstat_zone_init, NULL,
	    nfsstat_zone_fini);
	status = mod_install((struct modlinkage *)&modlinkage);

	if (status)  {
		(void) zone_key_delete(nfsstat_zone_key);

		/*
		 * Failed to install module, cleanup previous
		 * initialization work.
		 */
		nfs_clntfini();

		/*
		 * Clean up work performed indirectly by mod_installfs()
		 * as a result of our call to mod_install().
		 */
		nfs4fini();
		nfs3fini();
		nfsfini();
	}
	return (status);
}

int
_fini(void)
{
	/* Don't allow module to be unloaded */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info((struct modlinkage *)&modlinkage, modinfop));
}

/*
 * General utilities
 */

/*
 * Returns the preferred transfer size in bytes based on
 * what network interfaces are available.
 */
int
nfstsize(void)
{
	/*
	 * For the moment, just return NFS_MAXDATA until we can query the
	 * appropriate transport.
	 */
	return (NFS_MAXDATA);
}

/*
 * Returns the preferred transfer size in bytes based on
 * what network interfaces are available.
 */

/* this should reflect the largest transfer size possible */
static int nfs3_max_transfer_size = 1024 * 1024;

int
nfs3tsize(void)
{
	/*
	 * For the moment, just return nfs3_max_transfer_size until we
	 * can query the appropriate transport.
	 */
	return (nfs3_max_transfer_size);
}

static uint_t nfs3_max_transfer_size_clts = 32 * 1024;
static uint_t nfs3_max_transfer_size_cots = 1024 * 1024;
static uint_t nfs3_max_transfer_size_rdma = 1024 * 1024;

uint_t
nfs3_tsize(struct knetconfig *knp)
{

	if (knp->knc_semantics == NC_TPI_COTS_ORD ||
	    knp->knc_semantics == NC_TPI_COTS)
		return (nfs3_max_transfer_size_cots);
	if (knp->knc_semantics == NC_TPI_RDMA)
		return (nfs3_max_transfer_size_rdma);
	return (nfs3_max_transfer_size_clts);
}

uint_t
rfs3_tsize(struct svc_req *req)
{

	if (req->rq_xprt->xp_type == T_COTS_ORD ||
	    req->rq_xprt->xp_type == T_COTS)
		return (nfs3_max_transfer_size_cots);
	if (req->rq_xprt->xp_type == T_RDMA)
		return (nfs3_max_transfer_size_rdma);
	return (nfs3_max_transfer_size_clts);
}

/* ARGSUSED */
static int
nfsdyninit(int fstyp, char *name)
{
	static const fs_operation_def_t nfsdyn_vfsops_template[] = {
		VFSNAME_MOUNTROOT, { .vfs_mountroot = nfsdyn_mountroot },
		NULL, NULL
	};
	int error;

	error = vfs_setfsops(fstyp, nfsdyn_vfsops_template, &nfsdyn_vfsops);
	if (error != 0)
		return (error);

	return (0);
}

/* ARGSUSED */
static int
nfsdyn_mountroot(vfs_t *vfsp, whymountroot_t why)
{
	char root_hostname[SYS_NMLN+1];
	struct servinfo *svp;
	int error;
	int vfsflags;
	char *root_path;
	struct pathname pn;
	char *name;
	static char token[10];
	struct nfs_args args;		/* nfs mount arguments */

	bzero(&args, sizeof (args));

	/* do this BEFORE getfile which causes xid stamps to be initialized */
	clkset(-1L);		/* hack for now - until we get time svc? */

	if (why == ROOT_REMOUNT) {
		/*
		 * Shouldn't happen.
		 */
		panic("nfs3_mountroot: why == ROOT_REMOUNT\n");
	}

	if (why == ROOT_UNMOUNT) {
		/*
		 * Nothing to do for NFS.
		 */
		return (0);
	}

	/*
	 * why == ROOT_INIT
	 */

	name = token;
	*name = 0;
	getfsname("root", name, sizeof (token));

	pn_alloc(&pn);
	root_path = pn.pn_path;

	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	mutex_init(&svp->sv_lock, NULL, MUTEX_DEFAULT, NULL);
	svp->sv_knconf = kmem_zalloc(sizeof (*svp->sv_knconf), KM_SLEEP);
	svp->sv_knconf->knc_protofmly = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	svp->sv_knconf->knc_proto = kmem_alloc(KNC_STRSIZE, KM_SLEEP);

	/*
	 * First try version 4
	 */
	vfs_setops(vfsp, nfs4_vfsops);
	args.addr = &svp->sv_addr;
	args.fh = (char *)&svp->sv_fhandle;
	args.knconf = svp->sv_knconf;
	args.hostname = root_hostname;
	vfsflags = 0;

	if (error = mount_root(*name ? name : "root", root_path, NFS_V4,
	    &args, &vfsflags)) {
		if (error != EPROTONOSUPPORT) {
			nfs_cmn_err(error, CE_WARN,
			    "Unable to mount NFS root filesystem: %m");
			sv_free(svp);
			pn_free(&pn);
			vfs_setops(vfsp, nfsdyn_vfsops);
			return (error);
		}

		/*
		 * Then try version 3
		 */
		bzero(&args, sizeof (args));
		vfs_setops(vfsp, nfs3_vfsops);
		args.addr = &svp->sv_addr;
		args.fh = (char *)&svp->sv_fhandle;
		args.knconf = svp->sv_knconf;
		args.hostname = root_hostname;
		vfsflags = 0;

		if (error = mount_root(*name ? name : "root", root_path,
		    NFS_V3, &args, &vfsflags)) {
			if (error != EPROTONOSUPPORT) {
				nfs_cmn_err(error, CE_WARN,
				    "Unable to mount NFS root filesystem: %m");
				sv_free(svp);
				pn_free(&pn);
				vfs_setops(vfsp, nfsdyn_vfsops);
				return (error);
			}

			/*
			 * Finally, try version 2
			 */
			bzero(&args, sizeof (args));
			args.addr = &svp->sv_addr;
			args.fh = (char *)&svp->sv_fhandle.fh_buf;
			args.knconf = svp->sv_knconf;
			args.hostname = root_hostname;
			vfsflags = 0;

			vfs_setops(vfsp, nfs_vfsops);

			if (error = mount_root(*name ? name : "root",
			    root_path, NFS_VERSION, &args, &vfsflags)) {
				nfs_cmn_err(error, CE_WARN,
				    "Unable to mount NFS root filesystem: %m");
				sv_free(svp);
				pn_free(&pn);
				vfs_setops(vfsp, nfsdyn_vfsops);
				return (error);
			}
		}
	}

	sv_free(svp);
	pn_free(&pn);
	return (VFS_MOUNTROOT(vfsp, why));
}

int
nfs_setopts(vnode_t *vp, model_t model, struct nfs_args *buf)
{
	mntinfo_t *mi;			/* mount info, pointed at by vfs */
	STRUCT_HANDLE(nfs_args, args);
	int flags;

#ifdef lint
	model = model;
#endif

	STRUCT_SET_HANDLE(args, model, buf);

	flags = STRUCT_FGET(args, flags);

	/*
	 * Set option fields in mount info record
	 */
	mi = VTOMI(vp);

	if (flags & NFSMNT_NOAC) {
		mi->mi_flags |= MI_NOAC;
		PURGE_ATTRCACHE(vp);
	}
	if (flags & NFSMNT_NOCTO)
		mi->mi_flags |= MI_NOCTO;
	if (flags & NFSMNT_LLOCK)
		mi->mi_flags |= MI_LLOCK;
	if (flags & NFSMNT_GRPID)
		mi->mi_flags |= MI_GRPID;
	if (flags & NFSMNT_RETRANS) {
		if (STRUCT_FGET(args, retrans) < 0)
			return (EINVAL);
		mi->mi_retrans = STRUCT_FGET(args, retrans);
	}
	if (flags & NFSMNT_TIMEO) {
		if (STRUCT_FGET(args, timeo) <= 0)
			return (EINVAL);
		mi->mi_timeo = STRUCT_FGET(args, timeo);
		/*
		 * The following scales the standard deviation and
		 * and current retransmission timer to match the
		 * initial value for the timeout specified.
		 */
		mi->mi_timers[NFS_CALLTYPES].rt_deviate =
		    (mi->mi_timeo * hz * 2) / 5;
		mi->mi_timers[NFS_CALLTYPES].rt_rtxcur =
		    mi->mi_timeo * hz / 10;
	}
	if (flags & NFSMNT_RSIZE) {
		if (STRUCT_FGET(args, rsize) <= 0)
			return (EINVAL);
		mi->mi_tsize = MIN(mi->mi_tsize, STRUCT_FGET(args, rsize));
		mi->mi_curread = MIN(mi->mi_curread, mi->mi_tsize);
	}
	if (flags & NFSMNT_WSIZE) {
		if (STRUCT_FGET(args, wsize) <= 0)
			return (EINVAL);
		mi->mi_stsize = MIN(mi->mi_stsize, STRUCT_FGET(args, wsize));
		mi->mi_curwrite = MIN(mi->mi_curwrite, mi->mi_stsize);
	}
	if (flags & NFSMNT_ACREGMIN) {
		if (STRUCT_FGET(args, acregmin) < 0)
			mi->mi_acregmin = ACMINMAX;
		else
			mi->mi_acregmin = MIN(STRUCT_FGET(args, acregmin),
			    ACMINMAX);
		mi->mi_acregmin = SEC2HR(mi->mi_acregmin);
	}
	if (flags & NFSMNT_ACREGMAX) {
		if (STRUCT_FGET(args, acregmax) < 0)
			mi->mi_acregmax = ACMAXMAX;
		else
			mi->mi_acregmax = MIN(STRUCT_FGET(args, acregmax),
			    ACMAXMAX);
		mi->mi_acregmax = SEC2HR(mi->mi_acregmax);
	}
	if (flags & NFSMNT_ACDIRMIN) {
		if (STRUCT_FGET(args, acdirmin) < 0)
			mi->mi_acdirmin = ACMINMAX;
		else
			mi->mi_acdirmin = MIN(STRUCT_FGET(args, acdirmin),
			    ACMINMAX);
		mi->mi_acdirmin = SEC2HR(mi->mi_acdirmin);
	}
	if (flags & NFSMNT_ACDIRMAX) {
		if (STRUCT_FGET(args, acdirmax) < 0)
			mi->mi_acdirmax = ACMAXMAX;
		else
			mi->mi_acdirmax = MIN(STRUCT_FGET(args, acdirmax),
			    ACMAXMAX);
		mi->mi_acdirmax = SEC2HR(mi->mi_acdirmax);
	}

	if (flags & NFSMNT_LOOPBACK)
		mi->mi_flags |= MI_LOOPBACK;

	return (0);
}

/*
 * Set or Clear direct I/O flag
 * VOP_RWLOCK() is held for write access to prevent a race condition
 * which would occur if a process is in the middle of a write when
 * directio flag gets set. It is possible that all pages may not get flushed.
 */

/* ARGSUSED */
int
nfs_directio(vnode_t *vp, int cmd, cred_t *cr)
{
	int	error = 0;
	rnode_t	*rp;

	rp = VTOR(vp);

	if (cmd == DIRECTIO_ON) {

		if (rp->r_flags & RDIRECTIO)
			return (0);

		/*
		 * Flush the page cache.
		 */

		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);

		if (rp->r_flags & RDIRECTIO) {
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			return (0);
		}

		if (vn_has_cached_data(vp) &&
		    ((rp->r_flags & RDIRTY) || rp->r_awcount > 0)) {
			error = VOP_PUTPAGE(vp, (offset_t)0, (uint_t)0,
			    B_INVAL, cr, NULL);
			if (error) {
				if (error == ENOSPC || error == EDQUOT) {
					mutex_enter(&rp->r_statelock);
					if (!rp->r_error)
						rp->r_error = error;
					mutex_exit(&rp->r_statelock);
				}
				VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
				return (error);
			}
		}

		mutex_enter(&rp->r_statelock);
		rp->r_flags |= RDIRECTIO;
		mutex_exit(&rp->r_statelock);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		return (0);
	}

	if (cmd == DIRECTIO_OFF) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~RDIRECTIO;	/* disable direct mode */
		mutex_exit(&rp->r_statelock);
		return (0);
	}

	return (EINVAL);
}
