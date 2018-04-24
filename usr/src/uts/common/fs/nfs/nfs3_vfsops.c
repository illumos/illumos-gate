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
 */

/*
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
#include <sys/tsol/tnet.h>

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

/*
 * The order and contents of this structure must be kept in sync with that of
 * rfsreqcnt_v3_tmpl in nfs_stats.c
 */
static char *rfsnames_v3[] = {
	"null", "getattr", "setattr", "lookup", "access", "readlink", "read",
	"write", "create", "mkdir", "symlink", "mknod", "remove", "rmdir",
	"rename", "link", "readdir", "readdirplus", "fsstat", "fsinfo",
	"pathconf", "commit"
};

/*
 * This table maps from NFS protocol number into call type.
 * Zero means a "Lookup" type call
 * One  means a "Read" type call
 * Two  means a "Write" type call
 * This is used to select a default time-out.
 */
static uchar_t call_type_v3[] = {
	0, 0, 1, 0, 0, 0, 1,
	2, 2, 2, 2, 2, 2, 2,
	2, 2, 1, 2, 0, 0, 0,
	2 };

/*
 * Similar table, but to determine which timer to use
 * (only real reads and writes!)
 */
static uchar_t timer_type_v3[] = {
	0, 0, 0, 0, 0, 0, 1,
	2, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 1, 0, 0, 0,
	0 };

/*
 * This table maps from NFS protocol number into a call type
 * for the semisoft mount option.
 * Zero means do not repeat operation.
 * One  means repeat.
 */
static uchar_t ss_call_type_v3[] = {
	0, 0, 1, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1,
	1, 1, 0, 0, 0, 0, 0,
	1 };

/*
 * nfs3 vfs operations.
 */
static int	nfs3_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int	nfs3_unmount(vfs_t *, int, cred_t *);
static int	nfs3_root(vfs_t *, vnode_t **);
static int	nfs3_statvfs(vfs_t *, struct statvfs64 *);
static int	nfs3_sync(vfs_t *, short, cred_t *);
static int	nfs3_vget(vfs_t *, vnode_t **, fid_t *);
static int	nfs3_mountroot(vfs_t *, whymountroot_t);
static void	nfs3_freevfs(vfs_t *);

static int	nfs3rootvp(vnode_t **, vfs_t *, struct servinfo *,
		    int, cred_t *, zone_t *);

/*
 * Initialize the vfs structure
 */

static int nfs3fstyp;
vfsops_t *nfs3_vfsops;

/*
 * Debug variable to check for rdma based
 * transport startup and cleanup. Controlled
 * through /etc/system. Off by default.
 */
extern int rdma_debug;

int
nfs3init(int fstyp, char *name)
{
	static const fs_operation_def_t nfs3_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = nfs3_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = nfs3_unmount },
		VFSNAME_ROOT,		{ .vfs_root = nfs3_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = nfs3_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = nfs3_sync },
		VFSNAME_VGET,		{ .vfs_vget = nfs3_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = nfs3_mountroot },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = nfs3_freevfs },
		NULL,			NULL
	};
	int error;

	error = vfs_setfsops(fstyp, nfs3_vfsops_template, &nfs3_vfsops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs3init: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, nfs3_vnodeops_template, &nfs3_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstyp);
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs3init: bad vnode ops template");
		return (error);
	}

	nfs3fstyp = fstyp;

	return (0);
}

void
nfs3fini(void)
{
}

static void
nfs3_free_args(struct nfs_args *nargs, nfs_fhandle *fh)
{

	if (fh)
		kmem_free(fh, sizeof (*fh));

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
nfs3_copyin(char *data, int datalen, struct nfs_args *nargs, nfs_fhandle *fh)
{

	int error;
	size_t nlen;			/* length of netname */
	size_t hlen;			/* length of hostname */
	char netname[MAXNETNAMELEN+1];  /* server's netname */
	struct netbuf addr;		/* server's address */
	struct netbuf syncaddr;		/* AUTH_DES time sync addr */
	struct knetconfig *knconf;	/* transport knetconfig structure */
	struct sec_data *secdata = NULL;	/* security data */
	STRUCT_DECL(nfs_args, args);    	/* nfs mount arguments */
	STRUCT_DECL(knetconfig, knconf_tmp);
	STRUCT_DECL(netbuf, addr_tmp);
	int flags;
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

	if (copyin(STRUCT_FGETP(args, fh), fh, sizeof (nfs_fhandle))) {
		error = EFAULT;
		goto errout;
	}


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
		nfs3_free_args(nargs, fh);

	return (error);
}


/*
 * nfs mount vfsop
 * Set up mount info record and attach it to vfs struct.
 */
static int
nfs3_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	struct nfs_args	*args = NULL;
	nfs_fhandle	*fhandle = NULL;
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
	struct servinfo *svp_2ndlast;	/* 2nd last in server info list */
	struct sec_data *secdata;	/* security data */
	int flags, addr_type;
	zone_t *zone = nfs_zone();
	zone_t *mntzone = NULL;


	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (EPERM);

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
			nfs3_free_args(args, fhandle);
			fhandle = NULL;
		}
		if (fhandle == NULL)
			fhandle = kmem_alloc(sizeof (nfs_fhandle), KM_SLEEP);
		error = nfs3_copyin(data, uap->datalen, args, fhandle);
		if (error) {
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
		size_t	n;
		char	name[FSTYPSZ];

		if (uap->flags & MS_SYSSPACE) {
			error = copystr(uap->fstype, name, FSTYPSZ, &n);
		} else {
			nfs3_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
			error = copyinstr(uap->fstype, name, FSTYPSZ, &n);
		}
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
		 */

		if ((mi = VFTOMI(vfsp)) != NULL) {
			uint_t new_mi_llock;
			uint_t old_mi_llock;

			new_mi_llock = (flags & NFSMNT_LLOCK) ? 1 : 0;
			old_mi_llock = (mi->mi_flags & MI_LLOCK) ? 1 : 0;
			if (old_mi_llock != new_mi_llock)
				return (EBUSY);
		}
		return (0);
	}

	mutex_enter(&mvp->v_lock);
	if (!(uap->flags & MS_OVERLAY) &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs3_free_args(args, fhandle);
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
			nfs3_free_args(args, fhandle);
			kmem_free(args, sizeof (*args));
		}
		return (EINVAL);
	}

	if ((strlen(args->knconf->knc_protofmly) >= KNC_STRSIZE) ||
	    (strlen(args->knconf->knc_proto) >= KNC_STRSIZE)) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs3_free_args(args, fhandle);
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
	 * Check the root fhandle length
	 */
	ASSERT(fhandle);
	if (fhandle->fh_len > NFS3_FHSIZE || fhandle->fh_len == 0) {
		error = EINVAL;
#ifdef DEBUG
		zcmn_err(getzoneid(), CE_WARN,
		    "nfs3_mount: got an invalid fhandle. fh_len = %d",
		    fhandle->fh_len);
		fhandle->fh_len = NFS_FHANDLE_LEN;
		nfs_printfhandle(fhandle);
#endif
		goto errout;
	}

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
	 * RDMA MOUNT SUPPORT FOR NFS v3:
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
			 * If successful, hijack the orignal knconf and
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
			if (args->nfs_ext_u.nfs_extA.secdata == NULL) {
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
					args->nfs_ext_u.nfs_extA.secdata = NULL;
					break;
				default:
					error = EINVAL;
					goto errout;
				}
			}
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

			nlen = strlen(args->hostname) + 1;
			/* move server netname to the sec_data structure */
			if (nlen != 0) {
				data->netname = kmem_alloc(nlen, KM_SLEEP);
				bcopy(args->hostname, data->netname, nlen);
				data->netnamelen = nlen;
			}
			secdata->secmod = secdata->rpcflavor = AUTH_DES;
			secdata->data = (caddr_t)data;
		}
	} else 	{
		secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
		secdata->secmod = secdata->rpcflavor = AUTH_UNIX;
		secdata->data = NULL;
	}

	svp->sv_secdata = secdata;
	if (error)
		goto errout;

	/*
	 * See bug 1180236.
	 * If mount secure failed, we will fall back to AUTH_NONE
	 * and try again.  nfs3rootvp() will turn this back off.
	 *
	 * The NFS Version 3 mount uses the FSINFO and GETATTR
	 * procedures.  The server should not care if these procedures
	 * have the proper security flavor, so if mount retries using
	 * AUTH_NONE that does not require a credential setup for root
	 * then the automounter would work without requiring root to be
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
	error = nfs3rootvp(&rtvp, vfsp, svp_head, flags, cr, mntzone);

	if (error)
		goto errout;

	/*
	 * Set option fields in the mount info record
	 */
	mi = VTOMI(rtvp);

	if (svp_head->sv_next)
		mi->mi_flags |= MI_LLOCK;

	error = nfs_setopts(rtvp, DATAMODEL_NATIVE, args);

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
		nfs3_free_args(args, fhandle);
		kmem_free(args, sizeof (*args));
	}

	if (mntzone != NULL)
		zone_rele(mntzone);

	return (error);
}

static int nfs3_dynamic = 0;	/* global variable to enable dynamic retrans. */
static ushort_t nfs3_max_threads = 8;	/* max number of active async threads */
uint_t nfs3_bsize = 32 * 1024;	/* client `block' size */
static uint_t nfs3_async_clusters = 1;	/* # of reqs from each async queue */
static uint_t nfs3_cots_timeo = NFS_COTS_TIMEO;

static int
nfs3rootvp(vnode_t **rtvpp, vfs_t *vfsp, struct servinfo *svp,
    int flags, cred_t *cr, zone_t *zone)
{
	vnode_t *rtvp;
	mntinfo_t *mi;
	dev_t nfs_dev;
	struct vattr va;
	struct FSINFO3args args;
	struct FSINFO3res res;
	int error;
	int douprintf;
	rnode_t *rp;
	int i;
	uint_t max_transfer_size;
	struct nfs_stats *nfsstatsp;
	cred_t *lcr = NULL, *tcr = cr;

	nfsstatsp = zone_getspecific(nfsstat_zone_key, nfs_zone());
	ASSERT(nfsstatsp != NULL);

	ASSERT(nfs_zone() == zone);
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
		mi->mi_timeo = nfs3_cots_timeo;
	else
		mi->mi_timeo = NFS_TIMEO;
	mi->mi_prog = NFS_PROGRAM;
	mi->mi_vers = NFS_V3;
	mi->mi_rfsnames = rfsnames_v3;
	mi->mi_reqs = nfsstatsp->nfs_stats_v3.rfsreqcnt_ptr;
	mi->mi_call_type = call_type_v3;
	mi->mi_ss_call_type = ss_call_type_v3;
	mi->mi_timer_type = timer_type_v3;
	mi->mi_aclnames = aclnames_v3;
	mi->mi_aclreqs = nfsstatsp->nfs_stats_v3.aclreqcnt_ptr;
	mi->mi_acl_call_type = acl_call_type_v3;
	mi->mi_acl_ss_call_type = acl_ss_call_type_v3;
	mi->mi_acl_timer_type = acl_timer_type_v3;
	cv_init(&mi->mi_failover_cv, NULL, CV_DEFAULT, NULL);
	mi->mi_servers = svp;
	mi->mi_curr_serv = svp;
	mi->mi_acregmin = SEC2HR(ACREGMIN);
	mi->mi_acregmax = SEC2HR(ACREGMAX);
	mi->mi_acdirmin = SEC2HR(ACDIRMIN);
	mi->mi_acdirmax = SEC2HR(ACDIRMAX);

	if (nfs3_dynamic)
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
	vfs_make_fsid(&vfsp->vfs_fsid, nfs_dev, nfs3fstyp);
	vfsp->vfs_data = (caddr_t)mi;
	vfsp->vfs_fstype = nfsfstyp;

	/*
	 * Verify that nfs3_bsize tuneable is set to an
	 * acceptable value.  It be a multiple of PAGESIZE or
	 * file corruption can occur.
	 */
	if (nfs3_bsize & PAGEOFFSET)
		nfs3_bsize &= PAGEMASK;
	if (nfs3_bsize < PAGESIZE)
		nfs3_bsize = PAGESIZE;
	vfsp->vfs_bsize = nfs3_bsize;

	/*
	 * Initialize fields used to support async putpage operations.
	 */
	for (i = 0; i < NFS_ASYNC_TYPES; i++)
		mi->mi_async_clusters[i] = nfs3_async_clusters;
	mi->mi_async_init_clusters = nfs3_async_clusters;
	mi->mi_async_curr[NFS_ASYNC_QUEUE] =
	    mi->mi_async_curr[NFS_ASYNC_PGOPS_QUEUE] = &mi->mi_async_reqs[0];
	mi->mi_max_threads = nfs3_max_threads;
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
	rtvp = makenfs3node((nfs_fh3 *)&svp->sv_fhandle,
	    NULL, vfsp, gethrtime(), cr, NULL, NULL);

	/*
	 * Make the FSINFO calls, primarily at this point to
	 * determine the transfer size.  For client failover,
	 * we'll want this to be the minimum bid from any
	 * server, so that we don't overrun stated limits.
	 *
	 * While we're looping, we'll turn off AUTH_F_TRYNONE,
	 * which is only for the mount operation.
	 */

	mi->mi_tsize = nfs3_tsize(svp->sv_knconf);
	mi->mi_stsize = mi->mi_tsize;

	mi->mi_curread = nfs3_bsize;
	mi->mi_curwrite = mi->mi_curread;

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

	for (svp = mi->mi_servers; svp != NULL; svp = svp->sv_next) {
		douprintf = 1;
		mi->mi_curr_serv = svp;
		max_transfer_size = nfs3_tsize(svp->sv_knconf);
		mi->mi_tsize = MIN(max_transfer_size, mi->mi_tsize);
		mi->mi_stsize = MIN(max_transfer_size, mi->mi_stsize);
		mi->mi_curread = MIN(max_transfer_size, mi->mi_curread);
		mi->mi_curwrite = MIN(max_transfer_size, mi->mi_curwrite);
		args.fsroot = *(nfs_fh3 *)&svp->sv_fhandle;

		error = rfs3call(mi, NFSPROC3_FSINFO,
		    xdr_nfs_fh3, (caddr_t)&args,
		    xdr_FSINFO3res, (caddr_t)&res, tcr,
		    &douprintf, &res.status, 0, NULL);
		if (error)
			goto bad;
		error = geterrno3(res.status);
		if (error)
			goto bad;

		/* get type of root node */
		if (res.resok.obj_attributes.attributes) {
			if (res.resok.obj_attributes.attr.type < NF3REG ||
			    res.resok.obj_attributes.attr.type > NF3FIFO) {
#ifdef DEBUG
				zcmn_err(getzoneid(), CE_WARN,
			    "NFS3 server %s returned a bad file type for root",
				    svp->sv_hostname);
#else
				zcmn_err(getzoneid(), CE_WARN,
			    "NFS server %s returned a bad file type for root",
				    svp->sv_hostname);
#endif
				error = EINVAL;
				goto bad;
			} else {
				if (rtvp->v_type != VNON && rtvp->v_type !=
				    nf3_to_vt[res.resok.obj_attributes.attr.
				    type]) {
#ifdef DEBUG
					zcmn_err(getzoneid(), CE_WARN,
		"NFS3 server %s returned a different file type for root",
					    svp->sv_hostname);
#else
					zcmn_err(getzoneid(), CE_WARN,
		"NFS server %s returned a different file type for root",
					    svp->sv_hostname);
#endif
					error = EINVAL;
					goto bad;
				}
				rtvp->v_type =
				    nf3_to_vt[res.resok.obj_attributes.attr.
				    type];
			}
		}

		if (res.resok.rtmax != 0) {
			mi->mi_tsize = MIN(res.resok.rtmax, mi->mi_tsize);
			if (res.resok.rtpref != 0) {
				mi->mi_curread = MIN(res.resok.rtpref,
				    mi->mi_curread);
			} else {
				mi->mi_curread = MIN(res.resok.rtmax,
				    mi->mi_curread);
			}
		} else if (res.resok.rtpref != 0) {
			mi->mi_tsize = MIN(res.resok.rtpref, mi->mi_tsize);
			mi->mi_curread = MIN(res.resok.rtpref, mi->mi_curread);
		} else {
#ifdef DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			    "NFS3 server %s returned 0 for read transfer sizes",
			    svp->sv_hostname);
#else
			zcmn_err(getzoneid(), CE_WARN,
			    "NFS server %s returned 0 for read transfer sizes",
			    svp->sv_hostname);
#endif
			error = EIO;
			goto bad;
		}
		if (res.resok.wtmax != 0) {
			mi->mi_stsize = MIN(res.resok.wtmax, mi->mi_stsize);
			if (res.resok.wtpref != 0) {
				mi->mi_curwrite = MIN(res.resok.wtpref,
				    mi->mi_curwrite);
			} else {
				mi->mi_curwrite = MIN(res.resok.wtmax,
				    mi->mi_curwrite);
			}
		} else if (res.resok.wtpref != 0) {
			mi->mi_stsize = MIN(res.resok.wtpref, mi->mi_stsize);
			mi->mi_curwrite = MIN(res.resok.wtpref,
			    mi->mi_curwrite);
		} else {
#ifdef DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			"NFS3 server %s returned 0 for write transfer sizes",
			    svp->sv_hostname);
#else
			zcmn_err(getzoneid(), CE_WARN,
			"NFS server %s returned 0 for write transfer sizes",
			    svp->sv_hostname);
#endif
			error = EIO;
			goto bad;
		}

		/*
		 * These signal the ability of the server to create
		 * hard links and symbolic links, so they really
		 * aren't relevant if there is more than one server.
		 * We'll set them here, though it probably looks odd.
		 */
		if (res.resok.properties & FSF3_LINK)
			mi->mi_flags |= MI_LINK;
		if (res.resok.properties & FSF3_SYMLINK)
			mi->mi_flags |= MI_SYMLINK;

		/* Pick up smallest non-zero maxfilesize value */
		if (res.resok.maxfilesize) {
			if (mi->mi_maxfilesize) {
				mi->mi_maxfilesize = MIN(mi->mi_maxfilesize,
				    res.resok.maxfilesize);
			} else
				mi->mi_maxfilesize = res.resok.maxfilesize;
		}

		/*
		 * AUTH_F_TRYNONE is only for the mount operation,
		 * so turn it back off.
		 */
		svp->sv_secdata->flags &= ~AUTH_F_TRYNONE;
	}
	mi->mi_curr_serv = mi->mi_servers;

	/*
	 * Start the thread responsible for handling async worker threads.
	 */
	VFS_HOLD(vfsp);	/* add reference for thread */
	mi->mi_manager_thread = zthread_create(NULL, 0, nfs_async_manager,
	    vfsp, 0, minclsyspri);
	ASSERT(mi->mi_manager_thread != NULL);

	/*
	 * Initialize kstats
	 */
	nfs_mnt_kstat_init(vfsp);

	/* If we didn't get a type, get one now */
	if (rtvp->v_type == VNON) {
		va.va_mask = AT_ALL;

		error = nfs3getattr(rtvp, &va, tcr);
		if (error)
			goto bad;
		rtvp->v_type = va.va_type;
	}

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
nfs3_unmount(vfs_t *vfsp, int flag, cred_t *cr)
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
		 * more async requests
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
	 * The unmount can't fail from now on; stop the worker thread manager.
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
nfs3_root(vfs_t *vfsp, vnode_t **vpp)
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

	vp = makenfs3node((nfs_fh3 *)&mi->mi_curr_serv->sv_fhandle,
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
nfs3_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	int error;
	struct mntinfo *mi;
	struct FSSTAT3args args;
	struct FSSTAT3res res;
	int douprintf;
	failinfo_t fi;
	vnode_t *vp;
	cred_t *cr;
	hrtime_t t;

	mi = VFTOMI(vfsp);
	if (nfs_zone() != mi->mi_zone)
		return (EPERM);
	error = nfs3_root(vfsp, &vp);
	if (error)
		return (error);

	cr = CRED();

	args.fsroot = *VTOFH3(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.fsroot;
	fi.copyproc = nfs3copyfh;
	fi.lookupproc = nfs3lookup;
	fi.xattrdirproc = acl_getxattrdir3;

	douprintf = 1;

	t = gethrtime();

	error = rfs3call(mi, NFSPROC3_FSSTAT,
	    xdr_nfs_fh3, (caddr_t)&args,
	    xdr_FSSTAT3res, (caddr_t)&res, cr,
	    &douprintf, &res.status, 0, &fi);

	if (error) {
		VN_RELE(vp);
		return (error);
	}

	error = geterrno3(res.status);
	if (!error) {
		nfs3_cache_post_op_attr(vp, &res.resok.obj_attributes, t, cr);
		sbp->f_bsize = MAXBSIZE;
		sbp->f_frsize = DEV_BSIZE;
		/*
		 * Allow -1 fields to pass through unconverted.  These
		 * indicate "don't know" fields.
		 */
		if (res.resok.tbytes == (size3)-1)
			sbp->f_blocks = (fsblkcnt64_t)res.resok.tbytes;
		else {
			sbp->f_blocks = (fsblkcnt64_t)
			    (res.resok.tbytes / DEV_BSIZE);
		}
		if (res.resok.fbytes == (size3)-1)
			sbp->f_bfree = (fsblkcnt64_t)res.resok.fbytes;
		else {
			sbp->f_bfree = (fsblkcnt64_t)
			    (res.resok.fbytes / DEV_BSIZE);
		}
		if (res.resok.abytes == (size3)-1)
			sbp->f_bavail = (fsblkcnt64_t)res.resok.abytes;
		else {
			sbp->f_bavail = (fsblkcnt64_t)
			    (res.resok.abytes / DEV_BSIZE);
		}
		sbp->f_files = (fsfilcnt64_t)res.resok.tfiles;
		sbp->f_ffree = (fsfilcnt64_t)res.resok.ffiles;
		sbp->f_favail = (fsfilcnt64_t)res.resok.afiles;
		sbp->f_fsid = (unsigned long)vfsp->vfs_fsid.val[0];
		(void) strncpy(sbp->f_basetype,
		    vfssw[vfsp->vfs_fstype].vsw_name, FSTYPSZ);
		sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
		sbp->f_namemax = (ulong_t)-1;
	} else {
		nfs3_cache_post_op_attr(vp, &res.resfail.obj_attributes, t, cr);
		PURGE_STALE_FH(error, vp, cr);
	}

	VN_RELE(vp);

	return (error);
}

static kmutex_t nfs3_syncbusy;

/*
 * Flush dirty nfs files for file system vfsp.
 * If vfsp == NULL, all nfs files are flushed.
 */
/* ARGSUSED */
static int
nfs3_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	/*
	 * Cross-zone calls are OK here, since this translates to a
	 * VOP_PUTPAGE(B_ASYNC), which gets picked up by the right zone.
	 */
	if (!(flag & SYNC_ATTR) && mutex_tryenter(&nfs3_syncbusy) != 0) {
		rflush(vfsp, cr);
		mutex_exit(&nfs3_syncbusy);
	}
	return (0);
}

/* ARGSUSED */
static int
nfs3_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	int error;
	nfs_fh3 fh;
	vnode_t *vp;
	struct vattr va;

	if (fidp->fid_len > NFS3_FHSIZE) {
		*vpp = NULL;
		return (ESTALE);
	}

	if (nfs_zone() != VFTOMI(vfsp)->mi_zone)
		return (EPERM);
	fh.fh3_length = fidp->fid_len;
	bcopy(fidp->fid_data, fh.fh3_u.data, fh.fh3_length);

	vp = makenfs3node(&fh, NULL, vfsp, gethrtime(), CRED(), NULL, NULL);

	if (VTOR(vp)->r_flags & RSTALE) {
		VN_RELE(vp);
		*vpp = NULL;
		return (ENOENT);
	}

	if (vp->v_type == VNON) {
		va.va_mask = AT_ALL;
		error = nfs3getattr(vp, &va, CRED());
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
nfs3_mountroot(vfs_t *vfsp, whymountroot_t why)
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
		panic("nfs3_mountroot: why == ROOT_REMOUNT");
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
	args.fh = (char *)&svp->sv_fhandle;
	args.knconf = svp->sv_knconf;
	args.hostname = root_hostname;
	vfsflags = 0;
	if (error = mount_root(*name ? name : "root", root_path, NFS_V3,
	    &args, &vfsflags)) {
		if (error == EPROTONOSUPPORT)
			nfs_cmn_err(error, CE_WARN, "nfs3_mountroot: "
			    "mount_root failed: server doesn't support NFS V3");
		else
			nfs_cmn_err(error, CE_WARN,
			    "nfs3_mountroot: mount_root failed: %m");
		sv_free(svp);
		pn_free(&pn);
		return (error);
	}
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

	error = nfs3rootvp(&rtvp, vfsp, svp, args.flags, cr, global_zone);

	crfree(cr);

	if (error) {
		pn_free(&pn);
		sv_free(svp);
		return (error);
	}

	error = nfs_setopts(rtvp, DATAMODEL_NATIVE, &args);
	if (error) {
		nfs_cmn_err(error, CE_WARN,
		    "nfs3_mountroot: invalid root mount options");
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
nfs3_vfsinit(void)
{
	mutex_init(&nfs3_syncbusy, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

void
nfs3_vfsfini(void)
{
	mutex_destroy(&nfs3_syncbusy);
}

void
nfs3_freevfs(vfs_t *vfsp)
{
	mntinfo_t *mi;
	servinfo_t *svp;

	/* free up the resources */
	mi = VFTOMI(vfsp);
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
