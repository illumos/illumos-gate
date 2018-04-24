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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>
#include <sys/acl.h>
#include <sys/flock.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/class.h>
#include <sys/socket.h>
#include <sys/netconfig.h>
#include <sys/mntent.h>
#include <sys/tsol/label.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode.h>
#include <nfs/mount.h>
#include <nfs/nfs_acl.h>

#include <fs/fs_subr.h>

/*
 * From rpcsec module (common/rpcsec).
 */
extern int sec_clnt_loadinfo(struct sec_data *, struct sec_data **, model_t);
extern void sec_clnt_freeinfo(struct sec_data *);

static int pathconf_copyin(struct nfs_args *, struct pathcnf *);
static int pathconf_get(struct mntinfo *, struct nfs_args *);
static void pathconf_rele(struct mntinfo *);

/*
 * The order and contents of this structure must be kept in sync with that of
 * rfsreqcnt_v2_tmpl in nfs_stats.c
 */
static char *rfsnames_v2[] = {
	"null", "getattr", "setattr", "unused", "lookup", "readlink", "read",
	"unused", "write", "create", "remove", "rename", "link", "symlink",
	"mkdir", "rmdir", "readdir", "fsstat"
};

/*
 * This table maps from NFS protocol number into call type.
 * Zero means a "Lookup" type call
 * One  means a "Read" type call
 * Two  means a "Write" type call
 * This is used to select a default time-out.
 */
static uchar_t call_type_v2[] = {
	0, 0, 1, 0, 0, 0, 1,
	0, 2, 2, 2, 2, 2, 2,
	2, 2, 1, 0
};

/*
 * Similar table, but to determine which timer to use
 * (only real reads and writes!)
 */
static uchar_t timer_type_v2[] = {
	0, 0, 0, 0, 0, 0, 1,
	0, 2, 0, 0, 0, 0, 0,
	0, 0, 1, 0
};

/*
 * This table maps from NFS protocol number into a call type
 * for the semisoft mount option.
 * Zero means do not repeat operation.
 * One  means repeat.
 */
static uchar_t ss_call_type_v2[] = {
	0, 0, 1, 0, 0, 0, 0,
	0, 1, 1, 1, 1, 1, 1,
	1, 1, 0, 0
};

/*
 * nfs vfs operations.
 */
static int	nfs_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int	nfs_unmount(vfs_t *, int, cred_t *);
static int	nfs_root(vfs_t *, vnode_t **);
static int	nfs_statvfs(vfs_t *, struct statvfs64 *);
static int	nfs_sync(vfs_t *, short, cred_t *);
static int	nfs_vget(vfs_t *, vnode_t **, fid_t *);
static int	nfs_mountroot(vfs_t *, whymountroot_t);
static void	nfs_freevfs(vfs_t *);

static int	nfsrootvp(vnode_t **, vfs_t *, struct servinfo *,
		    int, cred_t *, zone_t *);

/*
 * Initialize the vfs structure
 */

int nfsfstyp;
vfsops_t *nfs_vfsops;

/*
 * Debug variable to check for rdma based
 * transport startup and cleanup. Controlled
 * through /etc/system. Off by default.
 */
int rdma_debug = 0;

int
nfsinit(int fstyp, char *name)
{
	static const fs_operation_def_t nfs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = nfs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = nfs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = nfs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = nfs_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = nfs_sync },
		VFSNAME_VGET,		{ .vfs_vget = nfs_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = nfs_mountroot },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = nfs_freevfs },
		NULL,			NULL
	};
	int error;

	error = vfs_setfsops(fstyp, nfs_vfsops_template, &nfs_vfsops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, nfs_vnodeops_template, &nfs_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstyp);
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfsinit: bad vnode ops template");
		return (error);
	}


	nfsfstyp = fstyp;

	return (0);
}

void
nfsfini(void)
{
}

static void
nfs_free_args(struct nfs_args *nargs, nfs_fhandle *fh)
{

	if (fh)
		kmem_free(fh, sizeof (*fh));

	if (nargs->pathconf) {
		kmem_free(nargs->pathconf, sizeof (struct pathcnf));
		nargs->pathconf = NULL;
	}

	if (nargs->knconf) {
		if (nargs->knconf->knc_protofmly)
			kmem_free(nargs->knconf->knc_protofmly, KNC_STRSIZE);
		if (nargs->knconf->knc_proto)
			kmem_free(nargs->knconf->knc_proto, KNC_STRSIZE);
		kmem_free(nargs->knconf, sizeof (*nargs->knconf));
		nargs->knconf = NULL;
	}

	if (nargs->fh) {
		kmem_free(nargs->fh, strlen(nargs->fh) + 1);
		nargs->fh = NULL;
	}

	if (nargs->hostname) {
		kmem_free(nargs->hostname, strlen(nargs->hostname) + 1);
		nargs->hostname = NULL;
	}

	if (nargs->addr) {
		if (nargs->addr->buf) {
			ASSERT(nargs->addr->len);
			kmem_free(nargs->addr->buf, nargs->addr->len);
		}
		kmem_free(nargs->addr, sizeof (struct netbuf));
		nargs->addr = NULL;
	}

	if (nargs->syncaddr) {
		ASSERT(nargs->syncaddr->len);
		if (nargs->syncaddr->buf) {
			ASSERT(nargs->syncaddr->len);
			kmem_free(nargs->syncaddr->buf, nargs->syncaddr->len);
		}
		kmem_free(nargs->syncaddr, sizeof (struct netbuf));
		nargs->syncaddr = NULL;
	}

	if (nargs->netname) {
		kmem_free(nargs->netname, strlen(nargs->netname) + 1);
		nargs->netname = NULL;
	}

	if (nargs->nfs_ext_u.nfs_extA.secdata) {
		sec_clnt_freeinfo(nargs->nfs_ext_u.nfs_extA.secdata);
		nargs->nfs_ext_u.nfs_extA.secdata = NULL;
	}
}

static int
nfs_copyin(char *data, int datalen, struct nfs_args *nargs, nfs_fhandle *fh)
{

	int error;
	size_t nlen;			/* length of netname */
	size_t hlen;			/* length of hostname */
	char netname[MAXNETNAMELEN+1];	/* server's netname */
	struct netbuf addr;		/* server's address */
	struct netbuf syncaddr;		/* AUTH_DES time sync addr */
	struct knetconfig *knconf;	/* transport knetconfig structure */
	struct sec_data *secdata = NULL;	/* security data */
	STRUCT_DECL(nfs_args, args);		/* nfs mount arguments */
	STRUCT_DECL(knetconfig, knconf_tmp);
	STRUCT_DECL(netbuf, addr_tmp);
	int flags;
	struct pathcnf	*pc;		/* Pathconf */
	char *p, *pf;
	char *userbufptr;


	bzero(nargs, sizeof (*nargs));

	STRUCT_INIT(args, get_udatamodel());
	bzero(STRUCT_BUF(args), SIZEOF_STRUCT(nfs_args, DATAMODEL_NATIVE));
	if (copyin(data, STRUCT_BUF(args), MIN(datalen, STRUCT_SIZE(args))))
		return (EFAULT);

	nargs->wsize = STRUCT_FGET(args, wsize);
	nargs->rsize = STRUCT_FGET(args, rsize);
	nargs->timeo = STRUCT_FGET(args, timeo);
	nargs->retrans = STRUCT_FGET(args, retrans);
	nargs->acregmin = STRUCT_FGET(args, acregmin);
	nargs->acregmax = STRUCT_FGET(args, acregmax);
	nargs->acdirmin = STRUCT_FGET(args, acdirmin);
	nargs->acdirmax = STRUCT_FGET(args, acdirmax);

	flags = STRUCT_FGET(args, flags);
	nargs->flags = flags;


	addr.buf = NULL;
	syncaddr.buf = NULL;

	/*
	 * Allocate space for a knetconfig structure and
	 * its strings and copy in from user-land.
	 */
	knconf = kmem_zalloc(sizeof (*knconf), KM_SLEEP);
	STRUCT_INIT(knconf_tmp, get_udatamodel());
	if (copyin(STRUCT_FGETP(args, knconf), STRUCT_BUF(knconf_tmp),
	    STRUCT_SIZE(knconf_tmp))) {
		kmem_free(knconf, sizeof (*knconf));
		return (EFAULT);
	}

	knconf->knc_semantics = STRUCT_FGET(knconf_tmp, knc_semantics);
	knconf->knc_protofmly = STRUCT_FGETP(knconf_tmp, knc_protofmly);
	knconf->knc_proto = STRUCT_FGETP(knconf_tmp, knc_proto);
	if (get_udatamodel() != DATAMODEL_LP64) {
		knconf->knc_rdev = expldev(STRUCT_FGET(knconf_tmp, knc_rdev));
	} else {
		knconf->knc_rdev = STRUCT_FGET(knconf_tmp, knc_rdev);
	}

	pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	error = copyinstr(knconf->knc_protofmly, pf, KNC_STRSIZE, NULL);
	if (error) {
		kmem_free(pf, KNC_STRSIZE);
		kmem_free(p, KNC_STRSIZE);
		kmem_free(knconf, sizeof (*knconf));
		return (error);
	}

	error = copyinstr(knconf->knc_proto, p, KNC_STRSIZE, NULL);
	if (error) {
		kmem_free(pf, KNC_STRSIZE);
		kmem_free(p, KNC_STRSIZE);
		kmem_free(knconf, sizeof (*knconf));
		return (error);
	}


	knconf->knc_protofmly = pf;
	knconf->knc_proto = p;

	nargs->knconf = knconf;

	/* Copyin pathconf if there is one */
	if (STRUCT_FGETP(args, pathconf) != NULL) {
		pc = kmem_alloc(sizeof (*pc), KM_SLEEP);
		error = pathconf_copyin(STRUCT_BUF(args), pc);
		nargs->pathconf = pc;
		if (error)
			goto errout;
	}

	/*
	 * Get server address
	 */
	STRUCT_INIT(addr_tmp, get_udatamodel());
	if (copyin(STRUCT_FGETP(args, addr), STRUCT_BUF(addr_tmp),
	    STRUCT_SIZE(addr_tmp))) {
		error = EFAULT;
		goto errout;
	}
	nargs->addr = kmem_alloc(sizeof (struct netbuf), KM_SLEEP);
	userbufptr = STRUCT_FGETP(addr_tmp, buf);
	addr.len = STRUCT_FGET(addr_tmp, len);
	addr.buf = kmem_alloc(addr.len, KM_SLEEP);
	addr.maxlen = addr.len;
	if (copyin(userbufptr, addr.buf, addr.len)) {
		kmem_free(addr.buf, addr.len);
		error = EFAULT;
		goto errout;
	}
	bcopy(&addr, nargs->addr, sizeof (struct netbuf));

	/*
	 * Get the root fhandle
	 */

	if (copyin(STRUCT_FGETP(args, fh), &fh->fh_buf, NFS_FHSIZE)) {
		error = EFAULT;
		goto errout;
	}
	fh->fh_len = NFS_FHSIZE;

	/*
	 * Get server's hostname
	 */
	if (flags & NFSMNT_HOSTNAME) {
		error = copyinstr(STRUCT_FGETP(args, hostname), netname,
		    sizeof (netname), &hlen);
		if (error)
			goto errout;
		nargs->hostname = kmem_zalloc(hlen, KM_SLEEP);
		(void) strcpy(nargs->hostname, netname);

	} else {
		nargs->hostname = NULL;
	}


	/*
	 * If there are syncaddr and netname data, load them in. This is
	 * to support data needed for NFSV4 when AUTH_DH is the negotiated
	 * flavor via SECINFO. (instead of using MOUNT protocol in V3).
	 */
	netname[0] = '\0';
	if (flags & NFSMNT_SECURE) {
		if (STRUCT_FGETP(args, syncaddr) == NULL) {
			error = EINVAL;
			goto errout;
		}
		/* get syncaddr */
		STRUCT_INIT(addr_tmp, get_udatamodel());
		if (copyin(STRUCT_FGETP(args, syncaddr), STRUCT_BUF(addr_tmp),
		    STRUCT_SIZE(addr_tmp))) {
			error = EINVAL;
			goto errout;
		}
		userbufptr = STRUCT_FGETP(addr_tmp, buf);
		syncaddr.len = STRUCT_FGET(addr_tmp, len);
		syncaddr.buf = kmem_alloc(syncaddr.len, KM_SLEEP);
		syncaddr.maxlen = syncaddr.len;
		if (copyin(userbufptr, syncaddr.buf, syncaddr.len)) {
			kmem_free(syncaddr.buf, syncaddr.len);
			error = EFAULT;
			goto errout;
		}

		nargs->syncaddr = kmem_alloc(sizeof (struct netbuf), KM_SLEEP);
		bcopy(&syncaddr, nargs->syncaddr, sizeof (struct netbuf));

		ASSERT(STRUCT_FGETP(args, netname));
		if (copyinstr(STRUCT_FGETP(args, netname), netname,
		    sizeof (netname), &nlen)) {
			error = EFAULT;
			goto errout;
		}

		netname[nlen] = '\0';
		nargs->netname = kmem_zalloc(nlen, KM_SLEEP);
		(void) strcpy(nargs->netname, netname);
	}

	/*
	 * Get the extention data which has the security data structure.
	 * This includes data for AUTH_SYS as well.
	 */
	if (flags & NFSMNT_NEWARGS) {
		nargs->nfs_args_ext = STRUCT_FGET(args, nfs_args_ext);
		if (nargs->nfs_args_ext == NFS_ARGS_EXTA ||
		    nargs->nfs_args_ext == NFS_ARGS_EXTB) {
			/*
			 * Indicating the application is using the new
			 * sec_data structure to pass in the security
			 * data.
			 */
			if (STRUCT_FGETP(args,
			    nfs_ext_u.nfs_extA.secdata) != NULL) {
				error = sec_clnt_loadinfo(
				    (struct sec_data *)STRUCT_FGETP(args,
				    nfs_ext_u.nfs_extA.secdata), &secdata,
				    get_udatamodel());
			}
			nargs->nfs_ext_u.nfs_extA.secdata = secdata;
		}
	}

	if (error)
		goto errout;

	/*
	 * Failover support:
	 *
	 * We may have a linked list of nfs_args structures,
	 * which means the user is looking for failover.  If
	 * the mount is either not "read-only" or "soft",
	 * we want to bail out with EINVAL.
	 */
	if (nargs->nfs_args_ext == NFS_ARGS_EXTB)
		nargs->nfs_ext_u.nfs_extB.next =
		    STRUCT_FGETP(args, nfs_ext_u.nfs_extB.next);

errout:
	if (error)
		nfs_free_args(nargs, fh);

	return (error);
}


/*
 * nfs mount vfsop
 * Set up mount info record and attach it to vfs struct.
 */
static int
nfs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	char *data = uap->dataptr;
	int error;
	vnode_t *rtvp;			/* the server's root */
	mntinfo_t *mi;			/* mount info, pointed at by vfs */
	size_t nlen;			/* length of netname */
	struct knetconfig *knconf;	/* transport knetconfig structure */
	struct knetconfig *rdma_knconf;	/* rdma transport structure */
	rnode_t *rp;
	struct servinfo *svp;		/* nfs server info */
	struct servinfo *svp_tail = NULL; /* previous nfs server info */
	struct servinfo *svp_head;	/* first nfs server info */
	struct servinfo *svp_2ndlast;	/* 2nd last in the server info list */
	struct sec_data *secdata;	/* security data */
	struct nfs_args	*args = NULL;
	int flags, addr_type;
	zone_t *zone = nfs_zone();
	zone_t *mntzone = NULL;
	nfs_fhandle	*fhandle = NULL;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * get arguments
	 *
	 * nfs_args is now versioned and is extensible, so
	 * uap->datalen might be different from sizeof (args)
	 * in a compatible situation.
	 */
more:

	if (!(uap->flags & MS_SYSSPACE)) {
		if (args == NULL)
			args = kmem_alloc(sizeof (struct nfs_args), KM_SLEEP);
		else {
			nfs_free_args(args, fhandle);
			fhandle = NULL;
		}
		if (fhandle == NULL)
			fhandle = kmem_zalloc(sizeof (nfs_fhandle), KM_SLEEP);
		error = nfs_copyin(data, uap->datalen, args, fhandle);
		if (error)  {
			if (args)
				kmem_free(args, sizeof (*args));
			return (error);
		}
	} else {
		args = (struct nfs_args *)data;
		fhandle = (nfs_fhandle *)args->fh;
	}


	flags = args->flags;

	if (uap->flags & MS_REMOUNT) {
		size_t n;
		char name[FSTYPSZ];

		if (uap->flags & MS_SYSSPACE)
			error = copystr(uap->fstype, name, FSTYPSZ, &n);
		else
			error = copyinstr(uap->fstype, name, FSTYPSZ, &n);

		if (error) {
			if (error == ENAMETOOLONG)
				return (EINVAL);
			return (error);
		}


		/*
		 * This check is to ensure that the request is a
		 * genuine nfs remount request.
		 */

		if (strncmp(name, "nfs", 3) != 0)
			return (EINVAL);

		/*
		 * If the request changes the locking type, disallow the
		 * remount,
		 * because it's questionable whether we can transfer the
		 * locking state correctly.
		 *
		 * Remounts need to save the pathconf information.
		 * Part of the infamous static kludge.
		 */

		if ((mi = VFTOMI(vfsp)) != NULL) {
			uint_t new_mi_llock;
			uint_t old_mi_llock;

			new_mi_llock = (flags & NFSMNT_LLOCK) ? 1 : 0;
			old_mi_llock = (mi->mi_flags & MI_LLOCK) ? 1 : 0;
			if (old_mi_llock != new_mi_llock)
				return (EBUSY);
		}
		error = pathconf_get((struct mntinfo *)vfsp->vfs_data, args);

		if (!(uap->flags & MS_SYSSPACE)) {
			nfs_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
		}

		return (error);
	}

	mutex_enter(&mvp->v_lock);
	if (!(uap->flags & MS_OVERLAY) &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
		}
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/* make sure things are zeroed for errout: */
	rtvp = NULL;
	mi = NULL;
	secdata = NULL;

	/*
	 * A valid knetconfig structure is required.
	 */
	if (!(flags & NFSMNT_KNCONF)) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
		}
		return (EINVAL);
	}

	if ((strlen(args->knconf->knc_protofmly) >= KNC_STRSIZE) ||
	    (strlen(args->knconf->knc_proto) >= KNC_STRSIZE)) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
		}
		return (EINVAL);
	}


	/*
	 * Allocate a servinfo struct.
	 */
	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	mutex_init(&svp->sv_lock, NULL, MUTEX_DEFAULT, NULL);
	if (svp_tail) {
		svp_2ndlast = svp_tail;
		svp_tail->sv_next = svp;
	} else {
		svp_head = svp;
		svp_2ndlast = svp;
	}

	svp_tail = svp;

	/*
	 * Get knetconfig and server address
	 */
	svp->sv_knconf = args->knconf;
	args->knconf = NULL;

	if (args->addr == NULL || args->addr->buf == NULL) {
		error = EINVAL;
		goto errout;
	}

	svp->sv_addr.maxlen = args->addr->maxlen;
	svp->sv_addr.len = args->addr->len;
	svp->sv_addr.buf = args->addr->buf;
	args->addr->buf = NULL;

	/*
	 * Get the root fhandle
	 */
	ASSERT(fhandle);

	bcopy(&fhandle->fh_buf, &svp->sv_fhandle.fh_buf, fhandle->fh_len);
	svp->sv_fhandle.fh_len = fhandle->fh_len;

	/*
	 * Get server's hostname
	 */
	if (flags & NFSMNT_HOSTNAME) {
		if (args->hostname == NULL) {
			error = EINVAL;
			goto errout;
		}
		svp->sv_hostnamelen = strlen(args->hostname) + 1;
		svp->sv_hostname = args->hostname;
		args->hostname = NULL;
	} else {
		char *p = "unknown-host";
		svp->sv_hostnamelen = strlen(p) + 1;
		svp->sv_hostname = kmem_zalloc(svp->sv_hostnamelen, KM_SLEEP);
		(void) strcpy(svp->sv_hostname, p);
	}


	/*
	 * RDMA MOUNT SUPPORT FOR NFS v2:
	 * Establish, is it possible to use RDMA, if so overload the
	 * knconf with rdma specific knconf and free the orignal.
	 */
	if ((flags & NFSMNT_TRYRDMA) || (flags & NFSMNT_DORDMA)) {
		/*
		 * Determine the addr type for RDMA, IPv4 or v6.
		 */
		if (strcmp(svp->sv_knconf->knc_protofmly, NC_INET) == 0)
			addr_type = AF_INET;
		else if (strcmp(svp->sv_knconf->knc_protofmly, NC_INET6) == 0)
			addr_type = AF_INET6;

		if (rdma_reachable(addr_type, &svp->sv_addr,
		    &rdma_knconf) == 0) {
			/*
			 * If successful, hijack, the orignal knconf and
			 * replace with a new one, depending on the flags.
			 */
			svp->sv_origknconf = svp->sv_knconf;
			svp->sv_knconf = rdma_knconf;
			knconf = rdma_knconf;
		} else {
			if (flags & NFSMNT_TRYRDMA) {
#ifdef	DEBUG
				if (rdma_debug)
					zcmn_err(getzoneid(), CE_WARN,
					    "no RDMA onboard, revert\n");
#endif
			}

			if (flags & NFSMNT_DORDMA) {
				/*
				 * If proto=rdma is specified and no RDMA
				 * path to this server is avialable then
				 * ditch this server.
				 * This is not included in the mountable
				 * server list or the replica list.
				 * Check if more servers are specified;
				 * Failover case, otherwise bail out of mount.
				 */
				if (args->nfs_args_ext == NFS_ARGS_EXTB &&
				    args->nfs_ext_u.nfs_extB.next != NULL) {
					data = (char *)
					    args->nfs_ext_u.nfs_extB.next;
					if (uap->flags & MS_RDONLY &&
					    !(flags & NFSMNT_SOFT)) {
						if (svp_head->sv_next == NULL) {
							svp_tail = NULL;
							svp_2ndlast = NULL;
							sv_free(svp_head);
							goto more;
						} else {
							svp_tail = svp_2ndlast;
							svp_2ndlast->sv_next =
							    NULL;
							sv_free(svp);
							goto more;
						}
					}
				} else {
					/*
					 * This is the last server specified
					 * in the nfs_args list passed down
					 * and its not rdma capable.
					 */
					if (svp_head->sv_next == NULL) {
						/*
						 * Is this the only one
						 */
						error = EINVAL;
#ifdef	DEBUG
						if (rdma_debug)
							zcmn_err(getzoneid(),
							    CE_WARN,
							    "No RDMA srv");
#endif
						goto errout;
					} else {
						/*
						 * There is list, since some
						 * servers specified before
						 * this passed all requirements
						 */
						svp_tail = svp_2ndlast;
						svp_2ndlast->sv_next = NULL;
						sv_free(svp);
						goto proceed;
					}
				}
			}
		}
	}

	/*
	 * Get the extention data which has the new security data structure.
	 */
	if (flags & NFSMNT_NEWARGS) {
		switch (args->nfs_args_ext) {
		case NFS_ARGS_EXTA:
		case NFS_ARGS_EXTB:
			/*
			 * Indicating the application is using the new
			 * sec_data structure to pass in the security
			 * data.
			 */
			secdata = args->nfs_ext_u.nfs_extA.secdata;
			if (secdata == NULL) {
				error = EINVAL;
			} else {
				/*
				 * Need to validate the flavor here if
				 * sysspace, userspace was already
				 * validate from the nfs_copyin function.
				 */
				switch (secdata->rpcflavor) {
					case AUTH_NONE:
					case AUTH_UNIX:
					case AUTH_LOOPBACK:
					case AUTH_DES:
					case RPCSEC_GSS:
						break;
					default:
						error = EINVAL;
						goto errout;
				}
			}
			args->nfs_ext_u.nfs_extA.secdata = NULL;
			break;

		default:
			error = EINVAL;
			break;
		}
	} else if (flags & NFSMNT_SECURE) {
		/*
		 * Keep this for backward compatibility to support
		 * NFSMNT_SECURE/NFSMNT_RPCTIMESYNC flags.
		 */
		if (args->syncaddr == NULL || args->syncaddr->buf == NULL) {
			error = EINVAL;
			goto errout;
		}

		/*
		 * get time sync address.
		 */
		if (args->syncaddr == NULL) {
			error = EFAULT;
			goto errout;
		}

		/*
		 * Move security related data to the sec_data structure.
		 */
		{
			dh_k4_clntdata_t *data;
			char *pf, *p;

			secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
			if (flags & NFSMNT_RPCTIMESYNC)
				secdata->flags |= AUTH_F_RPCTIMESYNC;
			data = kmem_alloc(sizeof (*data), KM_SLEEP);
			bcopy(args->syncaddr, &data->syncaddr,
			    sizeof (*args->syncaddr));


			/*
			 * duplicate the knconf information for the
			 * new opaque data.
			 */
			data->knconf = kmem_alloc(sizeof (*knconf), KM_SLEEP);
			*data->knconf = *knconf;
			pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
			p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
			bcopy(knconf->knc_protofmly, pf, KNC_STRSIZE);
			bcopy(knconf->knc_proto, pf, KNC_STRSIZE);
			data->knconf->knc_protofmly = pf;
			data->knconf->knc_proto = p;

			/* move server netname to the sec_data structure */
			nlen = strlen(args->hostname) + 1;
			if (nlen != 0) {
				data->netname = kmem_alloc(nlen, KM_SLEEP);
				bcopy(args->hostname, data->netname, nlen);
				data->netnamelen = (int)nlen;
			}
			secdata->secmod = secdata->rpcflavor = AUTH_DES;
			secdata->data = (caddr_t)data;
		}
	} else {
		secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
		secdata->secmod = secdata->rpcflavor = AUTH_UNIX;
		secdata->data = NULL;
	}
	svp->sv_secdata = secdata;

	/*
	 * See bug 1180236.
	 * If mount secure failed, we will fall back to AUTH_NONE
	 * and try again.  nfs3rootvp() will turn this back off.
	 *
	 * The NFS Version 2 mount uses GETATTR and STATFS procedures.
	 * The server does not care if these procedures have the proper
	 * authentication flavor, so if mount retries using AUTH_NONE
	 * that does not require a credential setup for root then the
	 * automounter would work without requiring root to be
	 * keylogged into AUTH_DES.
	 */
	if (secdata->rpcflavor != AUTH_UNIX &&
	    secdata->rpcflavor != AUTH_LOOPBACK)
		secdata->flags |= AUTH_F_TRYNONE;

	/*
	 * Failover support:
	 *
	 * We may have a linked list of nfs_args structures,
	 * which means the user is looking for failover.  If
	 * the mount is either not "read-only" or "soft",
	 * we want to bail out with EINVAL.
	 */
	if (args->nfs_args_ext == NFS_ARGS_EXTB &&
	    args->nfs_ext_u.nfs_extB.next != NULL) {
		if (uap->flags & MS_RDONLY && !(flags & NFSMNT_SOFT)) {
			data = (char *)args->nfs_ext_u.nfs_extB.next;
			goto more;
		}
		error = EINVAL;
		goto errout;
	}

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

	if (is_system_labeled()) {
		error = nfs_mount_label_policy(vfsp, &svp->sv_addr,
		    svp->sv_knconf, cr);

		if (error > 0)
			goto errout;

		if (error == -1) {
			/* change mount to read-only to prevent write-down */
			vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
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
	 * Get root vnode.
	 */
proceed:
	error = nfsrootvp(&rtvp, vfsp, svp_head, flags, cr, mntzone);

	if (error)
		goto errout;

	/*
	 * Set option fields in the mount info record
	 */
	mi = VTOMI(rtvp);

	if (svp_head->sv_next)
		mi->mi_flags |= MI_LLOCK;

	error = nfs_setopts(rtvp, DATAMODEL_NATIVE, args);
	if (!error) {
		/* static pathconf kludge */
		error = pathconf_get(mi, args);
	}

errout:
	if (rtvp != NULL) {
		if (error) {
			rp = VTOR(rtvp);
			if (rp->r_flags & RHASHED)
				rp_rmhash(rp);
		}
		VN_RELE(rtvp);
	}

	if (error) {
		sv_free(svp_head);
		if (mi != NULL) {
			nfs_async_stop(vfsp);
			nfs_async_manager_stop(vfsp);
			if (mi->mi_io_kstats) {
				kstat_delete(mi->mi_io_kstats);
				mi->mi_io_kstats = NULL;
			}
			if (mi->mi_ro_kstats) {
				kstat_delete(mi->mi_ro_kstats);
				mi->mi_ro_kstats = NULL;
			}
			nfs_free_mi(mi);
		}
	}

	if (!(uap->flags & MS_SYSSPACE)) {
		nfs_free_args(args, fhandle);
		kmem_free(args, sizeof (*args));
	}

	if (mntzone != NULL)
		zone_rele(mntzone);

	return (error);
}

/*
 * The pathconf information is kept on a linked list of kmem_alloc'ed
 * structs. We search the list & add a new struct iff there is no other
 * struct with the same information.
 * See sys/pathconf.h for ``the rest of the story.''
 */
static struct pathcnf *allpc = NULL;

static int
pathconf_copyin(struct nfs_args *args, struct pathcnf *pc)
{
	STRUCT_DECL(pathcnf, pc_tmp);
	STRUCT_HANDLE(nfs_args, ap);
	int i;
	model_t	model;

	model = get_udatamodel();
	STRUCT_INIT(pc_tmp, model);
	STRUCT_SET_HANDLE(ap, model, args);

	if ((STRUCT_FGET(ap, flags) & NFSMNT_POSIX) &&
	    STRUCT_FGETP(ap, pathconf) != NULL) {
		if (copyin(STRUCT_FGETP(ap, pathconf), STRUCT_BUF(pc_tmp),
		    STRUCT_SIZE(pc_tmp)))
			return (EFAULT);
		if (_PC_ISSET(_PC_ERROR, STRUCT_FGET(pc_tmp, pc_mask)))
			return (EINVAL);

		pc->pc_link_max = STRUCT_FGET(pc_tmp, pc_link_max);
		pc->pc_max_canon = STRUCT_FGET(pc_tmp, pc_max_canon);
		pc->pc_max_input = STRUCT_FGET(pc_tmp, pc_max_input);
		pc->pc_name_max = STRUCT_FGET(pc_tmp, pc_name_max);
		pc->pc_path_max = STRUCT_FGET(pc_tmp, pc_path_max);
		pc->pc_pipe_buf = STRUCT_FGET(pc_tmp, pc_pipe_buf);
		pc->pc_vdisable = STRUCT_FGET(pc_tmp, pc_vdisable);
		pc->pc_xxx = STRUCT_FGET(pc_tmp, pc_xxx);
		for (i = 0; i < _PC_N; i++)
			pc->pc_mask[i] = STRUCT_FGET(pc_tmp, pc_mask[i]);
	}
	return (0);
}

static int
pathconf_get(struct mntinfo *mi, struct nfs_args *args)
{
	struct pathcnf *p, *pc;

	pc = args->pathconf;
	if (mi->mi_pathconf != NULL) {
		pathconf_rele(mi);
		mi->mi_pathconf = NULL;
	}

	if (args->flags & NFSMNT_POSIX && args->pathconf != NULL) {
		if (_PC_ISSET(_PC_ERROR, pc->pc_mask))
			return (EINVAL);

		for (p = allpc; p != NULL; p = p->pc_next) {
			if (PCCMP(p, pc) == 0)
				break;
		}
		if (p != NULL) {
			mi->mi_pathconf = p;
			p->pc_refcnt++;
		} else {
			p = kmem_alloc(sizeof (*p), KM_SLEEP);
			bcopy(pc, p, sizeof (struct pathcnf));
			p->pc_next = allpc;
			p->pc_refcnt = 1;
			allpc = mi->mi_pathconf = p;
		}
	}
	return (0);
}

/*
 * release the static pathconf information
 */
static void
pathconf_rele(struct mntinfo *mi)
{
	if (mi->mi_pathconf != NULL) {
		if (--mi->mi_pathconf->pc_refcnt == 0) {
			struct pathcnf *p;
			struct pathcnf *p2;

			p2 = p = allpc;
			while (p != NULL && p != mi->mi_pathconf) {
				p2 = p;
				p = p->pc_next;
			}
			if (p == NULL) {
				panic("mi->pathconf");
				/*NOTREACHED*/
			}
			if (p == allpc)
				allpc = p->pc_next;
			else
				p2->pc_next = p->pc_next;
			kmem_free(p, sizeof (*p));
			mi->mi_pathconf = NULL;
		}
	}
}

static int nfs_dynamic = 1;	/* global variable to enable dynamic retrans. */
static ushort_t nfs_max_threads = 8;	/* max number of active async threads */
static uint_t nfs_async_clusters = 1;	/* # of reqs from each async queue */
static uint_t nfs_cots_timeo = NFS_COTS_TIMEO;

static int
nfsrootvp(vnode_t **rtvpp, vfs_t *vfsp, struct servinfo *svp,
    int flags, cred_t *cr, zone_t *zone)
{
	vnode_t *rtvp;
	mntinfo_t *mi;
	dev_t nfs_dev;
	struct vattr va;
	int error;
	rnode_t *rp;
	int i;
	struct nfs_stats *nfsstatsp;
	cred_t *lcr = NULL, *tcr = cr;

	nfsstatsp = zone_getspecific(nfsstat_zone_key, nfs_zone());
	ASSERT(nfsstatsp != NULL);

	/*
	 * Create a mount record and link it to the vfs struct.
	 */
	mi = kmem_zalloc(sizeof (*mi), KM_SLEEP);
	mutex_init(&mi->mi_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&mi->mi_remap_lock, NULL, MUTEX_DEFAULT, NULL);
	mi->mi_flags = MI_ACL | MI_EXTATTR;
	if (!(flags & NFSMNT_SOFT))
		mi->mi_flags |= MI_HARD;
	if ((flags & NFSMNT_SEMISOFT))
		mi->mi_flags |= MI_SEMISOFT;
	if ((flags & NFSMNT_NOPRINT))
		mi->mi_flags |= MI_NOPRINT;
	if (flags & NFSMNT_INT)
		mi->mi_flags |= MI_INT;
	mi->mi_retrans = NFS_RETRIES;
	if (svp->sv_knconf->knc_semantics == NC_TPI_COTS_ORD ||
	    svp->sv_knconf->knc_semantics == NC_TPI_COTS)
		mi->mi_timeo = nfs_cots_timeo;
	else
		mi->mi_timeo = NFS_TIMEO;
	mi->mi_prog = NFS_PROGRAM;
	mi->mi_vers = NFS_VERSION;
	mi->mi_rfsnames = rfsnames_v2;
	mi->mi_reqs = nfsstatsp->nfs_stats_v2.rfsreqcnt_ptr;
	mi->mi_call_type = call_type_v2;
	mi->mi_ss_call_type = ss_call_type_v2;
	mi->mi_timer_type = timer_type_v2;
	mi->mi_aclnames = aclnames_v2;
	mi->mi_aclreqs = nfsstatsp->nfs_stats_v2.aclreqcnt_ptr;
	mi->mi_acl_call_type = acl_call_type_v2;
	mi->mi_acl_ss_call_type = acl_ss_call_type_v2;
	mi->mi_acl_timer_type = acl_timer_type_v2;
	cv_init(&mi->mi_failover_cv, NULL, CV_DEFAULT, NULL);
	mi->mi_servers = svp;
	mi->mi_curr_serv = svp;
	mi->mi_acregmin = SEC2HR(ACREGMIN);
	mi->mi_acregmax = SEC2HR(ACREGMAX);
	mi->mi_acdirmin = SEC2HR(ACDIRMIN);
	mi->mi_acdirmax = SEC2HR(ACDIRMAX);

	if (nfs_dynamic)
		mi->mi_flags |= MI_DYNAMIC;

	if (flags & NFSMNT_DIRECTIO)
		mi->mi_flags |= MI_DIRECTIO;

	mutex_init(&mi->mi_rnodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&mi->mi_rnodes, sizeof (rnode_t),
	    offsetof(rnode_t, r_mi_link));

	/*
	 * Make a vfs struct for nfs.  We do this here instead of below
	 * because rtvp needs a vfs before we can do a getattr on it.
	 *
	 * Assign a unique device id to the mount
	 */
	mutex_enter(&nfs_minor_lock);
	do {
		nfs_minor = (nfs_minor + 1) & MAXMIN32;
		nfs_dev = makedevice(nfs_major, nfs_minor);
	} while (vfs_devismounted(nfs_dev));
	mutex_exit(&nfs_minor_lock);

	vfsp->vfs_dev = nfs_dev;
	vfs_make_fsid(&vfsp->vfs_fsid, nfs_dev, nfsfstyp);
	vfsp->vfs_data = (caddr_t)mi;
	vfsp->vfs_fstype = nfsfstyp;
	vfsp->vfs_bsize = NFS_MAXDATA;

	/*
	 * Initialize fields used to support async putpage operations.
	 */
	for (i = 0; i < NFS_ASYNC_TYPES; i++)
		mi->mi_async_clusters[i] = nfs_async_clusters;
	mi->mi_async_init_clusters = nfs_async_clusters;
	mi->mi_async_curr[NFS_ASYNC_QUEUE] =
	    mi->mi_async_curr[NFS_ASYNC_PGOPS_QUEUE] = &mi->mi_async_reqs[0];
	mi->mi_max_threads = nfs_max_threads;
	mutex_init(&mi->mi_async_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mi->mi_async_reqs_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&mi->mi_async_work_cv[NFS_ASYNC_QUEUE], NULL, CV_DEFAULT, NULL);
	cv_init(&mi->mi_async_work_cv[NFS_ASYNC_PGOPS_QUEUE], NULL,
	    CV_DEFAULT, NULL);
	cv_init(&mi->mi_async_cv, NULL, CV_DEFAULT, NULL);

	mi->mi_vfsp = vfsp;
	mi->mi_zone = zone;
	zone_init_ref(&mi->mi_zone_ref);
	zone_hold_ref(zone, &mi->mi_zone_ref, ZONE_REF_NFS);
	nfs_mi_zonelist_add(mi);

	/*
	 * Make the root vnode, use it to get attributes,
	 * then remake it with the attributes.
	 */
	rtvp = makenfsnode((fhandle_t *)svp->sv_fhandle.fh_buf,
	    NULL, vfsp, gethrtime(), cr, NULL, NULL);

	va.va_mask = AT_ALL;

	/*
	 * If the uid is set then set the creds for secure mounts
	 * by proxy processes such as automountd.
	 */
	if (svp->sv_secdata->uid != 0 &&
	    svp->sv_secdata->rpcflavor == RPCSEC_GSS) {
		lcr = crdup(cr);
		(void) crsetugid(lcr, svp->sv_secdata->uid, crgetgid(cr));
		tcr = lcr;
	}

	error = nfsgetattr(rtvp, &va, tcr);
	if (error)
		goto bad;
	rtvp->v_type = va.va_type;

	/*
	 * Poll every server to get the filesystem stats; we're
	 * only interested in the server's transfer size, and we
	 * want the minimum.
	 *
	 * While we're looping, we'll turn off AUTH_F_TRYNONE,
	 * which is only for the mount operation.
	 */

	mi->mi_tsize = MIN(NFS_MAXDATA, nfstsize());
	mi->mi_stsize = MIN(NFS_MAXDATA, nfstsize());

	for (svp = mi->mi_servers; svp != NULL; svp = svp->sv_next) {
		struct nfsstatfs fs;
		int douprintf;

		douprintf = 1;
		mi->mi_curr_serv = svp;

		error = rfs2call(mi, RFS_STATFS, xdr_fhandle,
		    (caddr_t)svp->sv_fhandle.fh_buf, xdr_statfs, (caddr_t)&fs,
		    tcr, &douprintf, &fs.fs_status, 0, NULL);
		if (error)
			goto bad;
		mi->mi_stsize = MIN(mi->mi_stsize, fs.fs_tsize);
		svp->sv_secdata->flags &= ~AUTH_F_TRYNONE;
	}
	mi->mi_curr_serv = mi->mi_servers;
	mi->mi_curread = mi->mi_tsize;
	mi->mi_curwrite = mi->mi_stsize;

	/*
	 * Start the manager thread responsible for handling async worker
	 * threads.
	 */
	VFS_HOLD(vfsp);	/* add reference for thread */
	mi->mi_manager_thread = zthread_create(NULL, 0, nfs_async_manager,
	    vfsp, 0, minclsyspri);
	ASSERT(mi->mi_manager_thread != NULL);

	/*
	 * Initialize kstats
	 */
	nfs_mnt_kstat_init(vfsp);

	mi->mi_type = rtvp->v_type;

	*rtvpp = rtvp;
	if (lcr != NULL)
		crfree(lcr);

	return (0);
bad:
	/*
	 * An error occurred somewhere, need to clean up...
	 * We need to release our reference to the root vnode and
	 * destroy the mntinfo struct that we just created.
	 */
	if (lcr != NULL)
		crfree(lcr);
	rp = VTOR(rtvp);
	if (rp->r_flags & RHASHED)
		rp_rmhash(rp);
	VN_RELE(rtvp);
	nfs_async_stop(vfsp);
	nfs_async_manager_stop(vfsp);
	if (mi->mi_io_kstats) {
		kstat_delete(mi->mi_io_kstats);
		mi->mi_io_kstats = NULL;
	}
	if (mi->mi_ro_kstats) {
		kstat_delete(mi->mi_ro_kstats);
		mi->mi_ro_kstats = NULL;
	}
	nfs_free_mi(mi);
	*rtvpp = NULL;
	return (error);
}

/*
 * vfs operations
 */
static int
nfs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	mntinfo_t *mi;
	ushort_t omax;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	mi = VFTOMI(vfsp);
	if (flag & MS_FORCE) {

		vfsp->vfs_flag |= VFS_UNMOUNTED;

		/*
		 * We are about to stop the async manager.
		 * Let every one know not to schedule any
		 * more async requests.
		 */
		mutex_enter(&mi->mi_async_lock);
		mi->mi_max_threads = 0;
		NFS_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
		mutex_exit(&mi->mi_async_lock);

		/*
		 * We need to stop the manager thread explicitly; the worker
		 * threads can time out and exit on their own.
		 */
		nfs_async_manager_stop(vfsp);
		destroy_rtable(vfsp, cr);
		if (mi->mi_io_kstats) {
			kstat_delete(mi->mi_io_kstats);
			mi->mi_io_kstats = NULL;
		}
		if (mi->mi_ro_kstats) {
			kstat_delete(mi->mi_ro_kstats);
			mi->mi_ro_kstats = NULL;
		}
		return (0);
	}
	/*
	 * Wait until all asynchronous putpage operations on
	 * this file system are complete before flushing rnodes
	 * from the cache.
	 */
	omax = mi->mi_max_threads;
	if (nfs_async_stop_sig(vfsp)) {
		return (EINTR);
	}
	rflush(vfsp, cr);
	/*
	 * If there are any active vnodes on this file system,
	 * then the file system is busy and can't be umounted.
	 */
	if (check_rtable(vfsp)) {
		mutex_enter(&mi->mi_async_lock);
		mi->mi_max_threads = omax;
		mutex_exit(&mi->mi_async_lock);
		return (EBUSY);
	}
	/*
	 * The unmount can't fail from now on; stop the manager thread.
	 */
	nfs_async_manager_stop(vfsp);
	/*
	 * Destroy all rnodes belonging to this file system from the
	 * rnode hash queues and purge any resources allocated to
	 * them.
	 */
	destroy_rtable(vfsp, cr);
	if (mi->mi_io_kstats) {
		kstat_delete(mi->mi_io_kstats);
		mi->mi_io_kstats = NULL;
	}
	if (mi->mi_ro_kstats) {
		kstat_delete(mi->mi_ro_kstats);
		mi->mi_ro_kstats = NULL;
	}
	return (0);
}

/*
 * find root of nfs
 */
static int
nfs_root(vfs_t *vfsp, vnode_t **vpp)
{
	mntinfo_t *mi;
	vnode_t *vp;
	servinfo_t *svp;
	rnode_t *rp;
	int error = 0;

	mi = VFTOMI(vfsp);

	if (nfs_zone() != mi->mi_zone)
		return (EPERM);

	svp = mi->mi_curr_serv;
	if (svp && (svp->sv_flags & SV_ROOT_STALE)) {
		mutex_enter(&svp->sv_lock);
		svp->sv_flags &= ~SV_ROOT_STALE;
		mutex_exit(&svp->sv_lock);
		error = ENOENT;
	}

	vp = makenfsnode((fhandle_t *)mi->mi_curr_serv->sv_fhandle.fh_buf,
	    NULL, vfsp, gethrtime(), CRED(), NULL, NULL);

	/*
	 * if the SV_ROOT_STALE flag was reset above, reset the
	 * RSTALE flag if needed and return an error
	 */
	if (error == ENOENT) {
		rp = VTOR(vp);
		if (svp && rp->r_flags & RSTALE) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags &= ~RSTALE;
			mutex_exit(&rp->r_statelock);
		}
		VN_RELE(vp);
		return (error);
	}

	ASSERT(vp->v_type == VNON || vp->v_type == mi->mi_type);

	vp->v_type = mi->mi_type;

	*vpp = vp;

	return (0);
}

/*
 * Get file system statistics.
 */
static int
nfs_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	int error;
	mntinfo_t *mi;
	struct nfsstatfs fs;
	int douprintf;
	failinfo_t fi;
	vnode_t *vp;

	error = nfs_root(vfsp, &vp);
	if (error)
		return (error);

	mi = VFTOMI(vfsp);
	douprintf = 1;
	fi.vp = vp;
	fi.fhp = NULL;		/* no need to update, filehandle not copied */
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	error = rfs2call(mi, RFS_STATFS, xdr_fhandle, (caddr_t)VTOFH(vp),
	    xdr_statfs, (caddr_t)&fs, CRED(), &douprintf, &fs.fs_status, 0,
	    &fi);

	if (!error) {
		error = geterrno(fs.fs_status);
		if (!error) {
			mutex_enter(&mi->mi_lock);
			if (mi->mi_stsize) {
				mi->mi_stsize = MIN(mi->mi_stsize, fs.fs_tsize);
			} else {
				mi->mi_stsize = fs.fs_tsize;
				mi->mi_curwrite = mi->mi_stsize;
			}
			mutex_exit(&mi->mi_lock);
			sbp->f_bsize = fs.fs_bsize;
			sbp->f_frsize = fs.fs_bsize;
			sbp->f_blocks = (fsblkcnt64_t)fs.fs_blocks;
			sbp->f_bfree = (fsblkcnt64_t)fs.fs_bfree;
			/*
			 * Some servers may return negative available
			 * block counts.  They may do this because they
			 * calculate the number of available blocks by
			 * subtracting the number of used blocks from
			 * the total number of blocks modified by the
			 * minimum free value.  For example, if the
			 * minumum free percentage is 10 and the file
			 * system is greater than 90 percent full, then
			 * 90 percent of the total blocks minus the
			 * actual number of used blocks may be a
			 * negative number.
			 *
			 * In this case, we need to sign extend the
			 * negative number through the assignment from
			 * the 32 bit bavail count to the 64 bit bavail
			 * count.
			 *
			 * We need to be able to discern between there
			 * just being a lot of available blocks on the
			 * file system and the case described above.
			 * We are making the assumption that it does
			 * not make sense to have more available blocks
			 * than there are free blocks.  So, if there
			 * are, then we treat the number as if it were
			 * a negative number and arrange to have it
			 * sign extended when it is converted from 32
			 * bits to 64 bits.
			 */
			if (fs.fs_bavail <= fs.fs_bfree)
				sbp->f_bavail = (fsblkcnt64_t)fs.fs_bavail;
			else {
				sbp->f_bavail =
				    (fsblkcnt64_t)((long)fs.fs_bavail);
			}
			sbp->f_files = (fsfilcnt64_t)-1;
			sbp->f_ffree = (fsfilcnt64_t)-1;
			sbp->f_favail = (fsfilcnt64_t)-1;
			sbp->f_fsid = (unsigned long)vfsp->vfs_fsid.val[0];
			(void) strncpy(sbp->f_basetype,
			    vfssw[vfsp->vfs_fstype].vsw_name, FSTYPSZ);
			sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
			sbp->f_namemax = (uint32_t)-1;
		} else {
			PURGE_STALE_FH(error, vp, CRED());
		}
	}

	VN_RELE(vp);

	return (error);
}

static kmutex_t nfs_syncbusy;

/*
 * Flush dirty nfs files for file system vfsp.
 * If vfsp == NULL, all nfs files are flushed.
 */
/* ARGSUSED */
static int
nfs_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	/*
	 * Cross-zone calls are OK here, since this translates to a
	 * VOP_PUTPAGE(B_ASYNC), which gets picked up by the right zone.
	 */
	if (!(flag & SYNC_ATTR) && mutex_tryenter(&nfs_syncbusy) != 0) {
		rflush(vfsp, cr);
		mutex_exit(&nfs_syncbusy);
	}
	return (0);
}

/* ARGSUSED */
static int
nfs_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	int error;
	vnode_t *vp;
	struct vattr va;
	struct nfs_fid *nfsfidp = (struct nfs_fid *)fidp;
	zoneid_t zoneid = VFTOMI(vfsp)->mi_zone->zone_id;

	if (nfs_zone() != VFTOMI(vfsp)->mi_zone)
		return (EPERM);
	if (fidp->fid_len != (sizeof (*nfsfidp) - sizeof (short))) {
#ifdef DEBUG
		zcmn_err(zoneid, CE_WARN,
		    "nfs_vget: bad fid len, %d/%d", fidp->fid_len,
		    (int)(sizeof (*nfsfidp) - sizeof (short)));
#endif
		*vpp = NULL;
		return (ESTALE);
	}

	vp = makenfsnode((fhandle_t *)(nfsfidp->nf_data), NULL, vfsp,
	    gethrtime(), CRED(), NULL, NULL);

	if (VTOR(vp)->r_flags & RSTALE) {
		VN_RELE(vp);
		*vpp = NULL;
		return (ENOENT);
	}

	if (vp->v_type == VNON) {
		va.va_mask = AT_ALL;
		error = nfsgetattr(vp, &va, CRED());
		if (error) {
			VN_RELE(vp);
			*vpp = NULL;
			return (error);
		}
		vp->v_type = va.va_type;
	}

	*vpp = vp;

	return (0);
}

/* ARGSUSED */
static int
nfs_mountroot(vfs_t *vfsp, whymountroot_t why)
{
	vnode_t *rtvp;
	char root_hostname[SYS_NMLN+1];
	struct servinfo *svp;
	int error;
	int vfsflags;
	size_t size;
	char *root_path;
	struct pathname pn;
	char *name;
	cred_t *cr;
	struct nfs_args args;		/* nfs mount arguments */
	static char token[10];

	bzero(&args, sizeof (args));

	/* do this BEFORE getfile which causes xid stamps to be initialized */
	clkset(-1L);		/* hack for now - until we get time svc? */

	if (why == ROOT_REMOUNT) {
		/*
		 * Shouldn't happen.
		 */
		panic("nfs_mountroot: why == ROOT_REMOUNT");
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
	svp->sv_knconf = kmem_zalloc(sizeof (*svp->sv_knconf), KM_SLEEP);
	svp->sv_knconf->knc_protofmly = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	svp->sv_knconf->knc_proto = kmem_alloc(KNC_STRSIZE, KM_SLEEP);

	/*
	 * Get server address
	 * Get the root fhandle
	 * Get server's transport
	 * Get server's hostname
	 * Get options
	 */
	args.addr = &svp->sv_addr;
	args.fh = (char *)&svp->sv_fhandle.fh_buf;
	args.knconf = svp->sv_knconf;
	args.hostname = root_hostname;
	vfsflags = 0;
	if (error = mount_root(*name ? name : "root", root_path, NFS_VERSION,
	    &args, &vfsflags)) {
		nfs_cmn_err(error, CE_WARN,
		    "nfs_mountroot: mount_root failed: %m");
		sv_free(svp);
		pn_free(&pn);
		return (error);
	}
	svp->sv_fhandle.fh_len = NFS_FHSIZE;
	svp->sv_hostnamelen = (int)(strlen(root_hostname) + 1);
	svp->sv_hostname = kmem_alloc(svp->sv_hostnamelen, KM_SLEEP);
	(void) strcpy(svp->sv_hostname, root_hostname);

	/*
	 * Force root partition to always be mounted with AUTH_UNIX for now
	 */
	svp->sv_secdata = kmem_alloc(sizeof (*svp->sv_secdata), KM_SLEEP);
	svp->sv_secdata->secmod = AUTH_UNIX;
	svp->sv_secdata->rpcflavor = AUTH_UNIX;
	svp->sv_secdata->data = NULL;

	cr = crgetcred();
	rtvp = NULL;

	error = nfsrootvp(&rtvp, vfsp, svp, args.flags, cr, global_zone);

	crfree(cr);

	if (error) {
		pn_free(&pn);
		sv_free(svp);
		return (error);
	}

	error = nfs_setopts(rtvp, DATAMODEL_NATIVE, &args);
	if (error) {
		nfs_cmn_err(error, CE_WARN,
		    "nfs_mountroot: invalid root mount options");
		pn_free(&pn);
		goto errout;
	}

	(void) vfs_lock_wait(vfsp);
	vfs_add(NULL, vfsp, vfsflags);
	vfs_unlock(vfsp);

	size = strlen(svp->sv_hostname);
	(void) strcpy(rootfs.bo_name, svp->sv_hostname);
	rootfs.bo_name[size] = ':';
	(void) strcpy(&rootfs.bo_name[size + 1], root_path);

	pn_free(&pn);

errout:
	if (error) {
		sv_free(svp);
		nfs_async_stop(vfsp);
		nfs_async_manager_stop(vfsp);
	}

	if (rtvp != NULL)
		VN_RELE(rtvp);

	return (error);
}

/*
 * Initialization routine for VFS routines.  Should only be called once
 */
int
nfs_vfsinit(void)
{
	mutex_init(&nfs_syncbusy, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

void
nfs_vfsfini(void)
{
	mutex_destroy(&nfs_syncbusy);
}

void
nfs_freevfs(vfs_t *vfsp)
{
	mntinfo_t *mi;
	servinfo_t *svp;

	/* free up the resources */
	mi = VFTOMI(vfsp);
	pathconf_rele(mi);
	svp = mi->mi_servers;
	mi->mi_servers = mi->mi_curr_serv = NULL;
	sv_free(svp);

	/*
	 * By this time we should have already deleted the
	 * mi kstats in the unmount code. If they are still around
	 * somethings wrong
	 */
	ASSERT(mi->mi_io_kstats == NULL);
	nfs_free_mi(mi);
}
