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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All Rights Reserved
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
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/bootconf.h>
#include <sys/modctl.h>
#include <sys/acl.h>
#include <sys/flock.h>
#include <sys/time.h>
#include <sys/disp.h>
#include <sys/policy.h>
#include <sys/socket.h>
#include <sys/netconfig.h>
#include <sys/dnlc.h>
#include <sys/list.h>
#include <sys/mntent.h>
#include <sys/tsol/label.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpcsec_gss.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/mount.h>
#include <nfs/nfs_acl.h>

#include <fs/fs_subr.h>

#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/fs/autofs.h>

#include <sys/sdt.h>


/*
 * Arguments passed to thread to free data structures from forced unmount.
 */

typedef struct {
	vfs_t	*fm_vfsp;
	int	fm_flag;
	cred_t	*fm_cr;
} freemountargs_t;

static void	async_free_mount(vfs_t *, int, cred_t *);
static void	nfs4_free_mount(vfs_t *, int, cred_t *);
static void	nfs4_free_mount_thread(freemountargs_t *);
static int nfs4_chkdup_servinfo4(servinfo4_t *, servinfo4_t *);

/*
 * From rpcsec module (common/rpcsec).
 */
extern int sec_clnt_loadinfo(struct sec_data *, struct sec_data **, model_t);
extern void sec_clnt_freeinfo(struct sec_data *);

/*
 * The order and contents of this structure must be kept in sync with that of
 * rfsreqcnt_v4_tmpl in nfs_stats.c
 */
static char *rfsnames_v4[] = {
	"null", "compound", "reserved",	"access", "close", "commit", "create",
	"delegpurge", "delegreturn", "getattr",	"getfh", "link", "lock",
	"lockt", "locku", "lookup", "lookupp", "nverify", "open", "openattr",
	"open_confirm",	"open_downgrade", "putfh", "putpubfh", "putrootfh",
	"read", "readdir", "readlink", "remove", "rename", "renew",
	"restorefh", "savefh", "secinfo", "setattr", "setclientid",
	"setclientid_confirm", "verify", "write"
};

/*
 * nfs4_max_mount_retry is the number of times the client will redrive
 * a mount compound before giving up and returning failure.  The intent
 * is to redrive mount compounds which fail NFS4ERR_STALE so that
 * if a component of the server path being mounted goes stale, it can
 * "recover" by redriving the mount compund (LOOKUP ops).  This recovery
 * code is needed outside of the recovery framework because mount is a
 * special case.  The client doesn't create vnodes/rnodes for components
 * of the server path being mounted.  The recovery code recovers real
 * client objects, not STALE FHs which map to components of the server
 * path being mounted.
 *
 * We could just fail the mount on the first time, but that would
 * instantly trigger failover (from nfs4_mount), and the client should
 * try to re-lookup the STALE FH before doing failover.  The easiest
 * way to "re-lookup" is to simply redrive the mount compound.
 */
static int nfs4_max_mount_retry = 2;

/*
 * nfs4 vfs operations.
 */
int		nfs4_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int	nfs4_unmount(vfs_t *, int, cred_t *);
static int	nfs4_root(vfs_t *, vnode_t **);
static int	nfs4_statvfs(vfs_t *, struct statvfs64 *);
static int	nfs4_sync(vfs_t *, short, cred_t *);
static int	nfs4_vget(vfs_t *, vnode_t **, fid_t *);
static int	nfs4_mountroot(vfs_t *, whymountroot_t);
static void	nfs4_freevfs(vfs_t *);

static int	nfs4rootvp(vnode_t **, vfs_t *, struct servinfo4 *,
		    int, cred_t *, zone_t *);

vfsops_t	*nfs4_vfsops;

int nfs4_vfsinit(void);
void nfs4_vfsfini(void);
static void nfs4setclientid_init(void);
static void nfs4setclientid_fini(void);
static void nfs4setclientid_otw(mntinfo4_t *, servinfo4_t *,  cred_t *,
		struct nfs4_server *, nfs4_error_t *, int *);
static void	destroy_nfs4_server(nfs4_server_t *);
static void	remove_mi(nfs4_server_t *, mntinfo4_t *);

extern void nfs4_ephemeral_init(void);
extern void nfs4_ephemeral_fini(void);

/* referral related routines */
static servinfo4_t *copy_svp(servinfo4_t *);
static void free_knconf_contents(struct knetconfig *k);
static char *extract_referral_point(const char *, int);
static void setup_newsvpath(servinfo4_t *, int);
static void update_servinfo4(servinfo4_t *, fs_location4 *,
		struct nfs_fsl_info *, char *, int);

/*
 * Initialize the vfs structure
 */

static int nfs4fstyp;


/*
 * Debug variable to check for rdma based
 * transport startup and cleanup. Controlled
 * through /etc/system. Off by default.
 */
extern int rdma_debug;

int
nfs4init(int fstyp, char *name)
{
	static const fs_operation_def_t nfs4_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = nfs4_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = nfs4_unmount },
		VFSNAME_ROOT,		{ .vfs_root = nfs4_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = nfs4_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = nfs4_sync },
		VFSNAME_VGET,		{ .vfs_vget = nfs4_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = nfs4_mountroot },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = nfs4_freevfs },
		NULL,			NULL
	};
	int error;

	nfs4_vfsops = NULL;
	nfs4_vnodeops = NULL;
	nfs4_trigger_vnodeops = NULL;

	error = vfs_setfsops(fstyp, nfs4_vfsops_template, &nfs4_vfsops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs4init: bad vfs ops template");
		goto out;
	}

	error = vn_make_ops(name, nfs4_vnodeops_template, &nfs4_vnodeops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs4init: bad vnode ops template");
		goto out;
	}

	error = vn_make_ops("nfs4_trigger", nfs4_trigger_vnodeops_template,
	    &nfs4_trigger_vnodeops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "nfs4init: bad trigger vnode ops template");
		goto out;
	}

	nfs4fstyp = fstyp;
	(void) nfs4_vfsinit();
	(void) nfs4_init_dot_entries();

out:
	if (error) {
		if (nfs4_trigger_vnodeops != NULL)
			vn_freevnodeops(nfs4_trigger_vnodeops);

		if (nfs4_vnodeops != NULL)
			vn_freevnodeops(nfs4_vnodeops);

		(void) vfs_freevfsops_by_type(fstyp);
	}

	return (error);
}

void
nfs4fini(void)
{
	(void) nfs4_destroy_dot_entries();
	nfs4_vfsfini();
}

/*
 * Create a new sec_data structure to store AUTH_DH related data:
 * netname, syncaddr, knetconfig. There is no AUTH_F_RPCTIMESYNC
 * flag set for NFS V4 since we are avoiding to contact the rpcbind
 * daemon and is using the IP time service (IPPORT_TIMESERVER).
 *
 * sec_data can be freed by sec_clnt_freeinfo().
 */
static struct sec_data *
create_authdh_data(char *netname, int nlen, struct netbuf *syncaddr,
		struct knetconfig *knconf) {
	struct sec_data *secdata;
	dh_k4_clntdata_t *data;
	char *pf, *p;

	if (syncaddr == NULL || syncaddr->buf == NULL || nlen == 0)
		return (NULL);

	secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
	secdata->flags = 0;

	data = kmem_alloc(sizeof (*data), KM_SLEEP);

	data->syncaddr.maxlen = syncaddr->maxlen;
	data->syncaddr.len = syncaddr->len;
	data->syncaddr.buf = (char *)kmem_alloc(syncaddr->len, KM_SLEEP);
	bcopy(syncaddr->buf, data->syncaddr.buf, syncaddr->len);

	/*
	 * duplicate the knconf information for the
	 * new opaque data.
	 */
	data->knconf = kmem_alloc(sizeof (*knconf), KM_SLEEP);
	*data->knconf = *knconf;
	pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	bcopy(knconf->knc_protofmly, pf, KNC_STRSIZE);
	bcopy(knconf->knc_proto, p, KNC_STRSIZE);
	data->knconf->knc_protofmly = pf;
	data->knconf->knc_proto = p;

	/* move server netname to the sec_data structure */
	data->netname = kmem_alloc(nlen, KM_SLEEP);
	bcopy(netname, data->netname, nlen);
	data->netnamelen = (int)nlen;

	secdata->secmod = AUTH_DH;
	secdata->rpcflavor = AUTH_DH;
	secdata->data = (caddr_t)data;

	return (secdata);
}

/*
 * Returns (deep) copy of sec_data_t. Allocates all memory required; caller
 * is responsible for freeing.
 */
sec_data_t *
copy_sec_data(sec_data_t *fsecdata) {
	sec_data_t *tsecdata;

	if (fsecdata == NULL)
		return (NULL);

	if (fsecdata->rpcflavor == AUTH_DH) {
		dh_k4_clntdata_t *fdata = (dh_k4_clntdata_t *)fsecdata->data;

		if (fdata == NULL)
			return (NULL);

		tsecdata = (sec_data_t *)create_authdh_data(fdata->netname,
		    fdata->netnamelen, &fdata->syncaddr, fdata->knconf);

		return (tsecdata);
	}

	tsecdata = kmem_zalloc(sizeof (sec_data_t), KM_SLEEP);

	tsecdata->secmod = fsecdata->secmod;
	tsecdata->rpcflavor = fsecdata->rpcflavor;
	tsecdata->flags = fsecdata->flags;
	tsecdata->uid = fsecdata->uid;

	if (fsecdata->rpcflavor == RPCSEC_GSS) {
		gss_clntdata_t *gcd = (gss_clntdata_t *)fsecdata->data;

		tsecdata->data = (caddr_t)copy_sec_data_gss(gcd);
	} else {
		tsecdata->data = NULL;
	}

	return (tsecdata);
}

gss_clntdata_t *
copy_sec_data_gss(gss_clntdata_t *fdata)
{
	gss_clntdata_t *tdata;

	if (fdata == NULL)
		return (NULL);

	tdata = kmem_zalloc(sizeof (gss_clntdata_t), KM_SLEEP);

	tdata->mechanism.length = fdata->mechanism.length;
	tdata->mechanism.elements = kmem_zalloc(fdata->mechanism.length,
	    KM_SLEEP);
	bcopy(fdata->mechanism.elements, tdata->mechanism.elements,
	    fdata->mechanism.length);

	tdata->service = fdata->service;

	(void) strcpy(tdata->uname, fdata->uname);
	(void) strcpy(tdata->inst, fdata->inst);
	(void) strcpy(tdata->realm, fdata->realm);

	tdata->qop = fdata->qop;

	return (tdata);
}

static int
nfs4_chkdup_servinfo4(servinfo4_t *svp_head, servinfo4_t *svp)
{
	servinfo4_t *si;

	/*
	 * Iterate over the servinfo4 list to make sure
	 * we do not have a duplicate. Skip any servinfo4
	 * that has been marked "NOT IN USE"
	 */
	for (si = svp_head; si; si = si->sv_next) {
		(void) nfs_rw_enter_sig(&si->sv_lock, RW_READER, 0);
		if (si->sv_flags & SV4_NOTINUSE) {
			nfs_rw_exit(&si->sv_lock);
			continue;
		}
		nfs_rw_exit(&si->sv_lock);
		if (si == svp)
			continue;
		if (si->sv_addr.len == svp->sv_addr.len &&
		    strcmp(si->sv_knconf->knc_protofmly,
		    svp->sv_knconf->knc_protofmly) == 0 &&
		    bcmp(si->sv_addr.buf, svp->sv_addr.buf,
		    si->sv_addr.len) == 0) {
			/* it's a duplicate */
			return (1);
		}
	}
	/* it's not a duplicate */
	return (0);
}

void
nfs4_free_args(struct nfs_args *nargs)
{
	if (nargs->knconf) {
		if (nargs->knconf->knc_protofmly)
			kmem_free(nargs->knconf->knc_protofmly,
			    KNC_STRSIZE);
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
		sec_clnt_freeinfo(
		    nargs->nfs_ext_u.nfs_extA.secdata);
		nargs->nfs_ext_u.nfs_extA.secdata = NULL;
	}
}


int
nfs4_copyin(char *data, int datalen, struct nfs_args *nargs)
{

	int error;
	size_t hlen;			/* length of hostname */
	size_t nlen;			/* length of netname */
	char netname[MAXNETNAMELEN+1];	/* server's netname */
	struct netbuf addr;		/* server's address */
	struct netbuf syncaddr;		/* AUTH_DES time sync addr */
	struct knetconfig *knconf;		/* transport structure */
	struct sec_data *secdata = NULL;	/* security data */
	STRUCT_DECL(nfs_args, args);		/* nfs mount arguments */
	STRUCT_DECL(knetconfig, knconf_tmp);
	STRUCT_DECL(netbuf, addr_tmp);
	int flags;
	char *p, *pf;
	struct pathname pn;
	char *userbufptr;


	bzero(nargs, sizeof (*nargs));

	STRUCT_INIT(args, get_udatamodel());
	bzero(STRUCT_BUF(args), SIZEOF_STRUCT(nfs_args, DATAMODEL_NATIVE));
	if (copyin(data, STRUCT_BUF(args), MIN(datalen,
	    STRUCT_SIZE(args))))
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

	nargs->addr = kmem_zalloc(sizeof (struct netbuf), KM_SLEEP);
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
	error = pn_get(STRUCT_FGETP(args, fh), UIO_USERSPACE, &pn);
	if (error)
		goto errout;

	/* Volatile fh: keep server paths, so use actual-size strings */
	nargs->fh = kmem_alloc(pn.pn_pathlen + 1, KM_SLEEP);
	bcopy(pn.pn_path, nargs->fh, pn.pn_pathlen);
	nargs->fh[pn.pn_pathlen] = '\0';
	pn_free(&pn);


	/*
	 * Get server's hostname
	 */
	if (flags & NFSMNT_HOSTNAME) {
		error = copyinstr(STRUCT_FGETP(args, hostname),
		    netname, sizeof (netname), &hlen);
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

		/* get server's netname */
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
				    nfs_ext_u.nfs_extA.secdata),
				    &secdata, get_udatamodel());
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
		nfs4_free_args(nargs);

	return (error);
}


/*
 * nfs mount vfsop
 * Set up mount info record and attach it to vfs struct.
 */
int
nfs4_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	char *data = uap->dataptr;
	int error;
	vnode_t *rtvp;			/* the server's root */
	mntinfo4_t *mi;			/* mount info, pointed at by vfs */
	struct knetconfig *rdma_knconf;	/* rdma transport structure */
	rnode4_t *rp;
	struct servinfo4 *svp;		/* nfs server info */
	struct servinfo4 *svp_tail = NULL; /* previous nfs server info */
	struct servinfo4 *svp_head;	/* first nfs server info */
	struct servinfo4 *svp_2ndlast;	/* 2nd last in server info list */
	struct sec_data *secdata;	/* security data */
	struct nfs_args *args = NULL;
	int flags, addr_type, removed;
	zone_t *zone = nfs_zone();
	nfs4_error_t n4e;
	zone_t *mntzone = NULL;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
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
			args = kmem_zalloc(sizeof (struct nfs_args), KM_SLEEP);
		else
			nfs4_free_args(args);
		error = nfs4_copyin(data, uap->datalen, args);
		if (error) {
			if (args) {
				kmem_free(args, sizeof (*args));
			}
			return (error);
		}
	} else {
		args = (struct nfs_args *)data;
	}

	flags = args->flags;

	/*
	 * If the request changes the locking type, disallow the remount,
	 * because it's questionable whether we can transfer the
	 * locking state correctly.
	 */
	if (uap->flags & MS_REMOUNT) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs4_free_args(args);
			kmem_free(args, sizeof (*args));
		}
		if ((mi = VFTOMI4(vfsp)) != NULL) {
			uint_t new_mi_llock;
			uint_t old_mi_llock;
			new_mi_llock = (flags & NFSMNT_LLOCK) ? 1 : 0;
			old_mi_llock = (mi->mi_flags & MI4_LLOCK) ? 1 : 0;
			if (old_mi_llock != new_mi_llock)
				return (EBUSY);
		}
		return (0);
	}

	/*
	 * For ephemeral mount trigger stub vnodes, we have two problems
	 * to solve: racing threads will likely fail the v_count check, and
	 * we want only one to proceed with the mount.
	 *
	 * For stubs, if the mount has already occurred (via a racing thread),
	 * just return success. If not, skip the v_count check and proceed.
	 * Note that we are already serialised at this point.
	 */
	mutex_enter(&mvp->v_lock);
	if (vn_matchops(mvp, nfs4_trigger_vnodeops)) {
		/* mntpt is a v4 stub vnode */
		ASSERT(RP_ISSTUB(VTOR4(mvp)));
		ASSERT(!(uap->flags & MS_OVERLAY));
		ASSERT(!(mvp->v_flag & VROOT));
		if (vn_mountedvfs(mvp) != NULL) {
			/* ephemeral mount has already occurred */
			ASSERT(uap->flags & MS_SYSSPACE);
			mutex_exit(&mvp->v_lock);
			return (0);
		}
	} else {
		/* mntpt is a non-v4 or v4 non-stub vnode */
		if (!(uap->flags & MS_OVERLAY) &&
		    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
			mutex_exit(&mvp->v_lock);
			if (!(uap->flags & MS_SYSSPACE)) {
				nfs4_free_args(args);
				kmem_free(args, sizeof (*args));
			}
			return (EBUSY);
		}
	}
	mutex_exit(&mvp->v_lock);

	/* make sure things are zeroed for errout: */
	rtvp = NULL;
	mi = NULL;
	secdata = NULL;

	/*
	 * A valid knetconfig structure is required.
	 */
	if (!(flags & NFSMNT_KNCONF) ||
	    args->knconf == NULL || args->knconf->knc_protofmly == NULL ||
	    args->knconf->knc_proto == NULL ||
	    (strcmp(args->knconf->knc_proto, NC_UDP) == 0)) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs4_free_args(args);
			kmem_free(args, sizeof (*args));
		}
		return (EINVAL);
	}

	if ((strlen(args->knconf->knc_protofmly) >= KNC_STRSIZE) ||
	    (strlen(args->knconf->knc_proto) >= KNC_STRSIZE)) {
		if (!(uap->flags & MS_SYSSPACE)) {
			nfs4_free_args(args);
			kmem_free(args, sizeof (*args));
		}
		return (EINVAL);
	}

	/*
	 * Allocate a servinfo4 struct.
	 */
	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	nfs_rw_init(&svp->sv_lock, NULL, RW_DEFAULT, NULL);
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

	/*
	 * Get server address
	 */
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
	if (args->fh == NULL || (strlen(args->fh) >= MAXPATHLEN)) {
		error = EINVAL;
		goto errout;
	}

	svp->sv_path = args->fh;
	svp->sv_pathlen = strlen(args->fh) + 1;
	args->fh = NULL;

	/*
	 * Get server's hostname
	 */
	if (flags & NFSMNT_HOSTNAME) {
		if (args->hostname == NULL || (strlen(args->hostname) >
		    MAXNETNAMELEN)) {
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
	 * RDMA MOUNT SUPPORT FOR NFS v4.
	 * Establish, is it possible to use RDMA, if so overload the
	 * knconf with rdma specific knconf and free the orignal knconf.
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
			 * replace with the new one, depending on the flags.
			 */
			svp->sv_origknconf = svp->sv_knconf;
			svp->sv_knconf = rdma_knconf;
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
							sv4_free(svp_head);
							goto more;
						} else {
							svp_tail = svp_2ndlast;
							svp_2ndlast->sv_next =
							    NULL;
							sv4_free(svp);
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
						sv4_free(svp);
						goto proceed;
					}
				}
			}
		}
	}

	/*
	 * If there are syncaddr and netname data, load them in. This is
	 * to support data needed for NFSV4 when AUTH_DH is the negotiated
	 * flavor via SECINFO. (instead of using MOUNT protocol in V3).
	 */
	if (args->flags & NFSMNT_SECURE) {
		svp->sv_dhsec = create_authdh_data(args->netname,
		    strlen(args->netname),
		    args->syncaddr, svp->sv_knconf);
	}

	/*
	 * Get the extention data which has the security data structure.
	 * This includes data for AUTH_SYS as well.
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
			} else if (uap->flags & MS_SYSSPACE) {
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
		 * NFSMNT_SECURE is deprecated but we keep it
		 * to support the rogue user-generated application
		 * that may use this undocumented interface to do
		 * AUTH_DH security, e.g. our own rexd.
		 *
		 * Also note that NFSMNT_SECURE is used for passing
		 * AUTH_DH info to be used in negotiation.
		 */
		secdata = create_authdh_data(args->netname,
		    strlen(args->netname), args->syncaddr, svp->sv_knconf);

	} else {
		secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
		secdata->secmod = secdata->rpcflavor = AUTH_SYS;
		secdata->data = NULL;
	}

	svp->sv_secdata = secdata;

	/*
	 * User does not explictly specify a flavor, and a user
	 * defined default flavor is passed down.
	 */
	if (flags & NFSMNT_SECDEFAULT) {
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
		svp->sv_flags |= SV4_TRYSECDEFAULT;
		nfs_rw_exit(&svp->sv_lock);
	}

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
	error = nfs4rootvp(&rtvp, vfsp, svp_head, flags, cr, mntzone);
	if (error) {
		/* if nfs4rootvp failed, it will free svp_head */
		svp_head = NULL;
		goto errout;
	}

	mi = VTOMI4(rtvp);

	/*
	 * Send client id to the server, if necessary
	 */
	nfs4_error_zinit(&n4e);
	nfs4setclientid(mi, cr, FALSE, &n4e);

	error = n4e.error;

	if (error)
		goto errout;

	/*
	 * Set option fields in the mount info record
	 */

	if (svp_head->sv_next) {
		mutex_enter(&mi->mi_lock);
		mi->mi_flags |= MI4_LLOCK;
		mutex_exit(&mi->mi_lock);
	}
	error = nfs4_setopts(rtvp, DATAMODEL_NATIVE, args);
	if (error)
		goto errout;

	/*
	 * Time to tie in the mirror mount info at last!
	 */
	if (flags & NFSMNT_EPHEMERAL)
		error = nfs4_record_ephemeral_mount(mi, mvp);

errout:
	if (error) {
		if (rtvp != NULL) {
			rp = VTOR4(rtvp);
			if (rp->r_flags & R4HASHED)
				rp4_rmhash(rp);
		}
		if (mi != NULL) {
			nfs4_async_stop(vfsp);
			nfs4_async_manager_stop(vfsp);
			nfs4_remove_mi_from_server(mi, NULL);
			if (rtvp != NULL)
				VN_RELE(rtvp);
			if (mntzone != NULL)
				zone_rele(mntzone);
			/* need to remove it from the zone */
			removed = nfs4_mi_zonelist_remove(mi);
			if (removed)
				zone_rele_ref(&mi->mi_zone_ref,
				    ZONE_REF_NFSV4);
			MI4_RELE(mi);
			if (!(uap->flags & MS_SYSSPACE) && args) {
				nfs4_free_args(args);
				kmem_free(args, sizeof (*args));
			}
			return (error);
		}
		if (svp_head)
			sv4_free(svp_head);
	}

	if (!(uap->flags & MS_SYSSPACE) && args) {
		nfs4_free_args(args);
		kmem_free(args, sizeof (*args));
	}
	if (rtvp != NULL)
		VN_RELE(rtvp);

	if (mntzone != NULL)
		zone_rele(mntzone);

	return (error);
}

#ifdef  DEBUG
#define	VERS_MSG	"NFS4 server "
#else
#define	VERS_MSG	"NFS server "
#endif

#define	READ_MSG        \
	VERS_MSG "%s returned 0 for read transfer size"
#define	WRITE_MSG       \
	VERS_MSG "%s returned 0 for write transfer size"
#define	SIZE_MSG        \
	VERS_MSG "%s returned 0 for maximum file size"

/*
 * Get the symbolic link text from the server for a given filehandle
 * of that symlink.
 *
 *      (get symlink text) PUTFH READLINK
 */
static int
getlinktext_otw(mntinfo4_t *mi, nfs_fh4 *fh, char **linktextp, cred_t *cr,
    int flags)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue;
	nfs_argop4 argop[2];
	nfs_resop4 *resop;
	READLINK4res *lr_res;
	uint_t len;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_sharedfh_t *sfh;
	nfs4_error_t e;
	int num_retry = nfs4_max_mount_retry;
	int recovery = !(flags & NFS4_GETFH_NEEDSOP);

	sfh = sfh4_get(fh, mi);
	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	nfs4_error_zinit(&e);

	args.array_len = 2;
	args.array = argop;
	args.ctag = TAG_GET_SYMLINK;

	if (! recovery) {
		e.error = nfs4_start_op(mi, NULL, NULL, &recov_state);
		if (e.error) {
			sfh4_rele(&sfh);
			return (e.error);
		}
	}

	/* 0. putfh symlink fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = sfh;

	/* 1. readlink */
	argop[1].argop = OP_READLINK;

	doqueue = 1;

	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);

	if (needrecov && !recovery && num_retry-- > 0) {

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "getlinktext_otw: initiating recovery\n"));

		if (nfs4_start_recovery(&e, mi, NULL, NULL, NULL, NULL,
		    OP_READLINK, NULL, NULL, NULL) == FALSE) {
			nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			goto recov_retry;
		}
	}

	/*
	 * If non-NFS4 pcol error and/or we weren't able to recover.
	 */
	if (e.error != 0) {
		if (! recovery)
			nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		sfh4_rele(&sfh);
		return (e.error);
	}

	if (res.status) {
		e.error = geterrno4(res.status);
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		if (! recovery)
			nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		sfh4_rele(&sfh);
		return (e.error);
	}

	/* res.status == NFS4_OK */
	ASSERT(res.status == NFS4_OK);

	resop = &res.array[1];  /* readlink res */
	lr_res = &resop->nfs_resop4_u.opreadlink;

	/* treat symlink name as data */
	*linktextp = utf8_to_str((utf8string *)&lr_res->link, &len, NULL);

	if (! recovery)
		nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
	sfh4_rele(&sfh);
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	return (0);
}

/*
 * Skip over consecutive slashes and "/./" in a pathname.
 */
void
pathname_skipslashdot(struct pathname *pnp)
{
	char *c1, *c2;

	while (pnp->pn_pathlen > 0 && *pnp->pn_path == '/') {

		c1 = pnp->pn_path + 1;
		c2 = pnp->pn_path + 2;

		if (*c1 == '.' && (*c2 == '/' || *c2 == '\0')) {
			pnp->pn_path = pnp->pn_path + 2; /* skip "/." */
			pnp->pn_pathlen = pnp->pn_pathlen - 2;
		} else {
			pnp->pn_path++;
			pnp->pn_pathlen--;
		}
	}
}

/*
 * Resolve a symbolic link path. The symlink is in the nth component of
 * svp->sv_path and has an nfs4 file handle "fh".
 * Upon return, the sv_path will point to the new path that has the nth
 * component resolved to its symlink text.
 */
int
resolve_sympath(mntinfo4_t *mi, servinfo4_t *svp, int nth, nfs_fh4 *fh,
    cred_t *cr, int flags)
{
	char *oldpath;
	char *symlink, *newpath;
	struct pathname oldpn, newpn;
	char component[MAXNAMELEN];
	int i, addlen, error = 0;
	int oldpathlen;

	/* Get the symbolic link text over the wire. */
	error = getlinktext_otw(mi, fh, &symlink, cr, flags);

	if (error || symlink == NULL || strlen(symlink) == 0)
		return (error);

	/*
	 * Compose the new pathname.
	 * Note:
	 *    - only the nth component is resolved for the pathname.
	 *    - pathname.pn_pathlen does not count the ending null byte.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	oldpath = svp->sv_path;
	oldpathlen = svp->sv_pathlen;
	if (error = pn_get(oldpath, UIO_SYSSPACE, &oldpn)) {
		nfs_rw_exit(&svp->sv_lock);
		kmem_free(symlink, strlen(symlink) + 1);
		return (error);
	}
	nfs_rw_exit(&svp->sv_lock);
	pn_alloc(&newpn);

	/*
	 * Skip over previous components from the oldpath so that the
	 * oldpn.pn_path will point to the symlink component. Skip
	 * leading slashes and "/./" (no OP_LOOKUP on ".") so that
	 * pn_getcompnent can get the component.
	 */
	for (i = 1; i < nth; i++) {
		pathname_skipslashdot(&oldpn);
		error = pn_getcomponent(&oldpn, component);
		if (error)
			goto out;
	}

	/*
	 * Copy the old path upto the component right before the symlink
	 * if the symlink is not an absolute path.
	 */
	if (symlink[0] != '/') {
		addlen = oldpn.pn_path - oldpn.pn_buf;
		bcopy(oldpn.pn_buf, newpn.pn_path, addlen);
		newpn.pn_pathlen += addlen;
		newpn.pn_path += addlen;
		newpn.pn_buf[newpn.pn_pathlen] = '/';
		newpn.pn_pathlen++;
		newpn.pn_path++;
	}

	/* copy the resolved symbolic link text */
	addlen = strlen(symlink);
	if (newpn.pn_pathlen + addlen >= newpn.pn_bufsize) {
		error = ENAMETOOLONG;
		goto out;
	}
	bcopy(symlink, newpn.pn_path, addlen);
	newpn.pn_pathlen += addlen;
	newpn.pn_path += addlen;

	/*
	 * Check if there is any remaining path after the symlink component.
	 * First, skip the symlink component.
	 */
	pathname_skipslashdot(&oldpn);
	if (error = pn_getcomponent(&oldpn, component))
		goto out;

	addlen = pn_pathleft(&oldpn); /* includes counting the slash */

	/*
	 * Copy the remaining path to the new pathname if there is any.
	 */
	if (addlen > 0) {
		if (newpn.pn_pathlen + addlen >= newpn.pn_bufsize) {
			error = ENAMETOOLONG;
			goto out;
		}
		bcopy(oldpn.pn_path, newpn.pn_path, addlen);
		newpn.pn_pathlen += addlen;
	}
	newpn.pn_buf[newpn.pn_pathlen] = '\0';

	/* get the newpath and store it in the servinfo4_t */
	newpath = kmem_alloc(newpn.pn_pathlen + 1, KM_SLEEP);
	bcopy(newpn.pn_buf, newpath, newpn.pn_pathlen);
	newpath[newpn.pn_pathlen] = '\0';

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	svp->sv_path = newpath;
	svp->sv_pathlen = strlen(newpath) + 1;
	nfs_rw_exit(&svp->sv_lock);

	kmem_free(oldpath, oldpathlen);
out:
	kmem_free(symlink, strlen(symlink) + 1);
	pn_free(&newpn);
	pn_free(&oldpn);

	return (error);
}

/*
 * This routine updates servinfo4 structure with the new referred server
 * info.
 * nfsfsloc has the location related information
 * fsp has the hostname and pathname info.
 * new path = pathname from referral + part of orig pathname(based on nth).
 */
static void
update_servinfo4(servinfo4_t *svp, fs_location4 *fsp,
    struct nfs_fsl_info *nfsfsloc, char *orig_path, int nth)
{
	struct knetconfig *knconf, *svknconf;
	struct netbuf *saddr;
	sec_data_t	*secdata;
	utf8string *host;
	int i = 0, num_slashes = 0;
	char *p, *spath, *op, *new_path;

	/* Update knconf */
	knconf = svp->sv_knconf;
	free_knconf_contents(knconf);
	bzero(knconf, sizeof (struct knetconfig));
	svknconf = nfsfsloc->knconf;
	knconf->knc_semantics = svknconf->knc_semantics;
	knconf->knc_protofmly = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
	knconf->knc_proto = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
	knconf->knc_rdev = svknconf->knc_rdev;
	bcopy(svknconf->knc_protofmly, knconf->knc_protofmly, KNC_STRSIZE);
	bcopy(svknconf->knc_proto, knconf->knc_proto, KNC_STRSIZE);

	/* Update server address */
	saddr = &svp->sv_addr;
	if (saddr->buf != NULL)
		kmem_free(saddr->buf, saddr->maxlen);
	saddr->buf  = kmem_alloc(nfsfsloc->addr->maxlen, KM_SLEEP);
	saddr->len = nfsfsloc->addr->len;
	saddr->maxlen = nfsfsloc->addr->maxlen;
	bcopy(nfsfsloc->addr->buf, saddr->buf, nfsfsloc->addr->len);

	/* Update server name */
	host = fsp->server_val;
	kmem_free(svp->sv_hostname, svp->sv_hostnamelen);
	svp->sv_hostname = kmem_zalloc(host->utf8string_len + 1, KM_SLEEP);
	bcopy(host->utf8string_val, svp->sv_hostname, host->utf8string_len);
	svp->sv_hostname[host->utf8string_len] = '\0';
	svp->sv_hostnamelen = host->utf8string_len + 1;

	/*
	 * Update server path.
	 * We need to setup proper path here.
	 * For ex., If we got a path name serv1:/rp/aaa/bbb
	 * where aaa is a referral and points to serv2:/rpool/aa
	 * we need to set the path to serv2:/rpool/aa/bbb
	 * The first part of this below code generates /rpool/aa
	 * and the second part appends /bbb to the server path.
	 */
	spath = p = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	*p++ = '/';
	for (i = 0; i < fsp->rootpath.pathname4_len; i++) {
		component4 *comp;

		comp = &fsp->rootpath.pathname4_val[i];
		/* If no space, null the string and bail */
		if ((p - spath) + comp->utf8string_len + 1 > MAXPATHLEN) {
			p = spath + MAXPATHLEN - 1;
			spath[0] = '\0';
			break;
		}
		bcopy(comp->utf8string_val, p, comp->utf8string_len);
		p += comp->utf8string_len;
		*p++ = '/';
	}
	if (fsp->rootpath.pathname4_len != 0)
		*(p - 1) = '\0';
	else
		*p = '\0';
	p = spath;

	new_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) strlcpy(new_path, p, MAXPATHLEN);
	kmem_free(p, MAXPATHLEN);
	i = strlen(new_path);

	for (op = orig_path; *op; op++) {
		if (*op == '/')
			num_slashes++;
		if (num_slashes == nth + 2) {
			while (*op != '\0') {
				new_path[i] = *op;
				i++;
				op++;
			}
			break;
		}
	}
	new_path[i] = '\0';

	kmem_free(svp->sv_path, svp->sv_pathlen);
	svp->sv_pathlen = strlen(new_path) + 1;
	svp->sv_path = kmem_alloc(svp->sv_pathlen, KM_SLEEP);
	bcopy(new_path, svp->sv_path, svp->sv_pathlen);
	kmem_free(new_path, MAXPATHLEN);

	/*
	 * All the security data is specific to old server.
	 * Clean it up except secdata which deals with mount options.
	 * We need to inherit that data. Copy secdata into our new servinfo4.
	 */
	if (svp->sv_dhsec) {
		sec_clnt_freeinfo(svp->sv_dhsec);
		svp->sv_dhsec = NULL;
	}
	if (svp->sv_save_secinfo &&
	    svp->sv_save_secinfo != svp->sv_secinfo) {
		secinfo_free(svp->sv_save_secinfo);
		svp->sv_save_secinfo = NULL;
	}
	if (svp->sv_secinfo) {
		secinfo_free(svp->sv_secinfo);
		svp->sv_secinfo = NULL;
	}
	svp->sv_currsec = NULL;

	secdata = kmem_alloc(sizeof (*secdata), KM_SLEEP);
	*secdata = *svp->sv_secdata;
	secdata->data = NULL;
	if (svp->sv_secdata) {
		sec_clnt_freeinfo(svp->sv_secdata);
		svp->sv_secdata = NULL;
	}
	svp->sv_secdata = secdata;
}

/*
 * Resolve a referral. The referral is in the n+1th component of
 * svp->sv_path and has a parent nfs4 file handle "fh".
 * Upon return, the sv_path will point to the new path that has referral
 * component resolved to its referred path and part of original path.
 * Hostname and other address information is also updated.
 */
int
resolve_referral(mntinfo4_t *mi, servinfo4_t *svp, cred_t *cr, int nth,
    nfs_fh4 *fh)
{
	nfs4_sharedfh_t	*sfh;
	struct nfs_fsl_info nfsfsloc;
	nfs4_ga_res_t garp;
	COMPOUND4res_clnt callres;
	fs_location4	*fsp;
	char *nm, *orig_path;
	int orig_pathlen = 0, ret = -1, index;

	if (svp->sv_pathlen <= 0)
		return (ret);

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	orig_pathlen = svp->sv_pathlen;
	orig_path = kmem_alloc(orig_pathlen, KM_SLEEP);
	bcopy(svp->sv_path, orig_path, orig_pathlen);
	nm = extract_referral_point(svp->sv_path, nth);
	setup_newsvpath(svp, nth);
	nfs_rw_exit(&svp->sv_lock);

	sfh = sfh4_get(fh, mi);
	index = nfs4_process_referral(mi, sfh, nm, cr,
	    &garp, &callres, &nfsfsloc);
	sfh4_rele(&sfh);
	kmem_free(nm, MAXPATHLEN);
	if (index < 0) {
		kmem_free(orig_path, orig_pathlen);
		return (index);
	}

	fsp =  &garp.n4g_ext_res->n4g_fslocations.locations_val[index];
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	update_servinfo4(svp, fsp, &nfsfsloc, orig_path, nth);
	nfs_rw_exit(&svp->sv_lock);

	mutex_enter(&mi->mi_lock);
	mi->mi_vfs_referral_loop_cnt++;
	mutex_exit(&mi->mi_lock);

	ret = 0;
bad:
	/* Free up XDR memory allocated in nfs4_process_referral() */
	xdr_free(xdr_nfs_fsl_info, (char *)&nfsfsloc);
	xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&callres);
	kmem_free(orig_path, orig_pathlen);

	return (ret);
}

/*
 * Get the root filehandle for the given filesystem and server, and update
 * svp.
 *
 * If NFS4_GETFH_NEEDSOP is set, then use nfs4_start_fop and nfs4_end_fop
 * to coordinate with recovery.  Otherwise, the caller is assumed to be
 * the recovery thread or have already done a start_fop.
 *
 * Errors are returned by the nfs4_error_t parameter.
 */
static void
nfs4getfh_otw(struct mntinfo4 *mi, servinfo4_t *svp, vtype_t *vtp,
    int flags, cred_t *cr, nfs4_error_t *ep)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue = 1;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	nfs4_ga_res_t *garp;
	int num_argops;
	lookup4_param_t lookuparg;
	nfs_fh4 *tmpfhp;
	nfs_fh4 *resfhp;
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	int llndx;
	int nthcomp;
	int recovery = !(flags & NFS4_GETFH_NEEDSOP);

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ASSERT(svp->sv_path != NULL);
	if (svp->sv_path[0] == '\0') {
		nfs_rw_exit(&svp->sv_lock);
		nfs4_error_init(ep, EINVAL);
		return;
	}
	nfs_rw_exit(&svp->sv_lock);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	if (mi->mi_vfs_referral_loop_cnt >= NFS4_REFERRAL_LOOP_MAX) {
		DTRACE_PROBE3(nfs4clnt__debug__referral__loop, mntinfo4 *,
		    mi, servinfo4_t *, svp, char *, "nfs4getfh_otw");
		nfs4_error_init(ep, EINVAL);
		return;
	}
	nfs4_error_zinit(ep);

	if (!recovery) {
		ep->error = nfs4_start_fop(mi, NULL, NULL, OH_MOUNT,
		    &recov_state, NULL);

		/*
		 * If recovery has been started and this request as
		 * initiated by a mount, then we must wait for recovery
		 * to finish before proceeding, otherwise, the error
		 * cleanup would remove data structures needed by the
		 * recovery thread.
		 */
		if (ep->error) {
			mutex_enter(&mi->mi_lock);
			if (mi->mi_flags & MI4_MOUNTING) {
				mi->mi_flags |= MI4_RECOV_FAIL;
				mi->mi_error = EIO;

				NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
				    "nfs4getfh_otw: waiting 4 recovery\n"));

				while (mi->mi_flags & MI4_RECOV_ACTIV)
					cv_wait(&mi->mi_failover_cv,
					    &mi->mi_lock);
			}
			mutex_exit(&mi->mi_lock);
			return;
		}

		/*
		 * If the client does not specify a specific flavor to use
		 * and has not gotten a secinfo list from the server yet,
		 * retrieve the secinfo list from the server and use a
		 * flavor from the list to mount.
		 *
		 * If fail to get the secinfo list from the server, then
		 * try the default flavor.
		 */
		if ((svp->sv_flags & SV4_TRYSECDEFAULT) &&
		    svp->sv_secinfo == NULL) {
			(void) nfs4_secinfo_path(mi, cr, FALSE);
		}
	}

	if (recovery)
		args.ctag = TAG_REMAP_MOUNT;
	else
		args.ctag = TAG_MOUNT;

	lookuparg.l4_getattrs = LKP4_ALL_ATTRIBUTES;
	lookuparg.argsp = &args;
	lookuparg.resp = &res;
	lookuparg.header_len = 2;	/* Putrootfh, getfh */
	lookuparg.trailer_len = 0;
	lookuparg.ga_bits = FATTR4_FSINFO_MASK;
	lookuparg.mi = mi;

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ASSERT(svp->sv_path != NULL);
	llndx = nfs4lookup_setup(svp->sv_path, &lookuparg, 0);
	nfs_rw_exit(&svp->sv_lock);

	argop = args.array;
	num_argops = args.array_len;

	/* choose public or root filehandle */
	if (flags & NFS4_GETFH_PUBLIC)
		argop[0].argop = OP_PUTPUBFH;
	else
		argop[0].argop = OP_PUTROOTFH;

	/* get fh */
	argop[1].argop = OP_GETFH;

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4getfh_otw: %s call, mi 0x%p",
	    needrecov ? "recov" : "first", (void *)mi));

	rfs4call(mi, &args, &res, cr, &doqueue, RFSCALL_SOFT, ep);

	needrecov = nfs4_needs_recovery(ep, FALSE, mi->mi_vfsp);

	if (needrecov) {
		bool_t abort;

		if (recovery) {
			nfs4args_lookup_free(argop, num_argops);
			kmem_free(argop,
			    lookuparg.arglen * sizeof (nfs_argop4));
			if (!ep->error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			return;
		}

		NFS4_DEBUG(nfs4_client_recov_debug,
		    (CE_NOTE, "nfs4getfh_otw: initiating recovery\n"));

		abort = nfs4_start_recovery(ep, mi, NULL,
		    NULL, NULL, NULL, OP_GETFH, NULL, NULL, NULL);
		if (!ep->error) {
			ep->error = geterrno4(res.status);
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		}
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state, needrecov);
		/* have another go? */
		if (abort == FALSE)
			goto recov_retry;
		return;
	}

	/*
	 * No recovery, but check if error is set.
	 */
	if (ep->error)  {
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		if (!recovery)
			nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state,
			    needrecov);
		return;
	}

is_link_err:

	/* for non-recovery errors */
	if (res.status && res.status != NFS4ERR_SYMLINK &&
	    res.status != NFS4ERR_MOVED) {
		if (!recovery) {
			nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state,
			    needrecov);
		}
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	/*
	 * If any intermediate component in the path is a symbolic link,
	 * resolve the symlink, then try mount again using the new path.
	 */
	if (res.status == NFS4ERR_SYMLINK || res.status == NFS4ERR_MOVED) {
		int where;

		/*
		 * Need to call nfs4_end_op before resolve_sympath to avoid
		 * potential nfs4_start_op deadlock.
		 */
		if (!recovery)
			nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state,
			    needrecov);

		/*
		 * This must be from OP_LOOKUP failure. The (cfh) for this
		 * OP_LOOKUP is a symlink node. Found out where the
		 * OP_GETFH is for the (cfh) that is a symlink node.
		 *
		 * Example:
		 * (mount) PUTROOTFH, GETFH, LOOKUP comp1, GETFH, GETATTR,
		 * LOOKUP comp2, GETFH, GETATTR, LOOKUP comp3, GETFH, GETATTR
		 *
		 * LOOKUP comp3 fails with SYMLINK because comp2 is a symlink.
		 * In this case, where = 7, nthcomp = 2.
		 */
		where = res.array_len - 2;
		ASSERT(where > 0);

		if (res.status == NFS4ERR_SYMLINK) {

			resop = &res.array[where - 1];
			ASSERT(resop->resop == OP_GETFH);
			tmpfhp = &resop->nfs_resop4_u.opgetfh.object;
			nthcomp = res.array_len/3 - 1;
			ep->error = resolve_sympath(mi, svp, nthcomp,
			    tmpfhp, cr, flags);

		} else if (res.status == NFS4ERR_MOVED) {

			resop = &res.array[where - 2];
			ASSERT(resop->resop == OP_GETFH);
			tmpfhp = &resop->nfs_resop4_u.opgetfh.object;
			nthcomp = res.array_len/3 - 1;
			ep->error = resolve_referral(mi, svp, cr, nthcomp,
			    tmpfhp);
		}

		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

		if (ep->error)
			return;

		goto recov_retry;
	}

	/* getfh */
	resop = &res.array[res.array_len - 2];
	ASSERT(resop->resop == OP_GETFH);
	resfhp = &resop->nfs_resop4_u.opgetfh.object;

	/* getattr fsinfo res */
	resop++;
	garp = &resop->nfs_resop4_u.opgetattr.ga_res;

	*vtp = garp->n4g_va.va_type;

	mi->mi_fh_expire_type = garp->n4g_ext_res->n4g_fet;

	mutex_enter(&mi->mi_lock);
	if (garp->n4g_ext_res->n4g_pc4.pc4_link_support)
		mi->mi_flags |= MI4_LINK;
	if (garp->n4g_ext_res->n4g_pc4.pc4_symlink_support)
		mi->mi_flags |= MI4_SYMLINK;
	if (garp->n4g_ext_res->n4g_suppattrs & FATTR4_ACL_MASK)
		mi->mi_flags |= MI4_ACL;
	mutex_exit(&mi->mi_lock);

	if (garp->n4g_ext_res->n4g_maxread == 0)
		mi->mi_tsize =
		    MIN(MAXBSIZE, mi->mi_tsize);
	else
		mi->mi_tsize =
		    MIN(garp->n4g_ext_res->n4g_maxread,
		    mi->mi_tsize);

	if (garp->n4g_ext_res->n4g_maxwrite == 0)
		mi->mi_stsize =
		    MIN(MAXBSIZE, mi->mi_stsize);
	else
		mi->mi_stsize =
		    MIN(garp->n4g_ext_res->n4g_maxwrite,
		    mi->mi_stsize);

	if (garp->n4g_ext_res->n4g_maxfilesize != 0)
		mi->mi_maxfilesize =
		    MIN(garp->n4g_ext_res->n4g_maxfilesize,
		    mi->mi_maxfilesize);

	/*
	 * If the final component is a a symbolic link, resolve the symlink,
	 * then try mount again using the new path.
	 *
	 * Assume no symbolic link for root filesysm "/".
	 */
	if (*vtp == VLNK) {
		/*
		 * nthcomp is the total result length minus
		 * the 1st 2 OPs (PUTROOTFH, GETFH),
		 * then divided by 3 (LOOKUP,GETFH,GETATTR)
		 *
		 * e.g. PUTROOTFH GETFH LOOKUP 1st-comp GETFH GETATTR
		 *	LOOKUP 2nd-comp GETFH GETATTR
		 *
		 *	(8 - 2)/3 = 2
		 */
		nthcomp = (res.array_len - 2)/3;

		/*
		 * Need to call nfs4_end_op before resolve_sympath to avoid
		 * potential nfs4_start_op deadlock. See RFE 4777612.
		 */
		if (!recovery)
			nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state,
			    needrecov);

		ep->error = resolve_sympath(mi, svp, nthcomp, resfhp, cr,
		    flags);

		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

		if (ep->error)
			return;

		goto recov_retry;
	}

	/*
	 * We need to figure out where in the compound the getfh
	 * for the parent directory is. If the object to be mounted is
	 * the root, then there is no lookup at all:
	 * PUTROOTFH, GETFH.
	 * If the object to be mounted is in the root, then the compound is:
	 * PUTROOTFH, GETFH, LOOKUP, GETFH, GETATTR.
	 * In either of these cases, the index of the GETFH is 1.
	 * If it is not at the root, then it's something like:
	 * PUTROOTFH, GETFH, LOOKUP, GETFH, GETATTR,
	 * LOOKUP, GETFH, GETATTR
	 * In this case, the index is llndx (last lookup index) - 2.
	 */
	if (llndx == -1 || llndx == 2)
		resop = &res.array[1];
	else {
		ASSERT(llndx > 2);
		resop = &res.array[llndx-2];
	}

	ASSERT(resop->resop == OP_GETFH);
	tmpfhp = &resop->nfs_resop4_u.opgetfh.object;

	/* save the filehandles for the replica */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	ASSERT(tmpfhp->nfs_fh4_len <= NFS4_FHSIZE);
	svp->sv_pfhandle.fh_len = tmpfhp->nfs_fh4_len;
	bcopy(tmpfhp->nfs_fh4_val, svp->sv_pfhandle.fh_buf,
	    tmpfhp->nfs_fh4_len);
	ASSERT(resfhp->nfs_fh4_len <= NFS4_FHSIZE);
	svp->sv_fhandle.fh_len = resfhp->nfs_fh4_len;
	bcopy(resfhp->nfs_fh4_val, svp->sv_fhandle.fh_buf, resfhp->nfs_fh4_len);

	/* initialize fsid and supp_attrs for server fs */
	svp->sv_fsid = garp->n4g_fsid;
	svp->sv_supp_attrs =
	    garp->n4g_ext_res->n4g_suppattrs | FATTR4_MANDATTR_MASK;

	nfs_rw_exit(&svp->sv_lock);
	nfs4args_lookup_free(argop, num_argops);
	kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	if (!recovery)
		nfs4_end_fop(mi, NULL, NULL, OH_MOUNT, &recov_state, needrecov);
}

/*
 * Save a copy of Servinfo4_t structure.
 * We might need when there is a failure in getting file handle
 * in case of a referral to replace servinfo4 struct and try again.
 */
static struct servinfo4 *
copy_svp(servinfo4_t *nsvp)
{
	servinfo4_t *svp = NULL;
	struct knetconfig *sknconf, *tknconf;
	struct netbuf *saddr, *taddr;

	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	nfs_rw_init(&svp->sv_lock, NULL, RW_DEFAULT, NULL);
	svp->sv_flags = nsvp->sv_flags;
	svp->sv_fsid = nsvp->sv_fsid;
	svp->sv_hostnamelen = nsvp->sv_hostnamelen;
	svp->sv_pathlen = nsvp->sv_pathlen;
	svp->sv_supp_attrs = nsvp->sv_supp_attrs;

	svp->sv_path = kmem_alloc(svp->sv_pathlen, KM_SLEEP);
	svp->sv_hostname = kmem_alloc(svp->sv_hostnamelen, KM_SLEEP);
	bcopy(nsvp->sv_hostname, svp->sv_hostname, svp->sv_hostnamelen);
	bcopy(nsvp->sv_path, svp->sv_path, svp->sv_pathlen);

	saddr = &nsvp->sv_addr;
	taddr = &svp->sv_addr;
	taddr->maxlen = saddr->maxlen;
	taddr->len = saddr->len;
	if (saddr->len > 0) {
		taddr->buf = kmem_zalloc(saddr->maxlen, KM_SLEEP);
		bcopy(saddr->buf, taddr->buf, saddr->len);
	}

	svp->sv_knconf = kmem_zalloc(sizeof (struct knetconfig), KM_SLEEP);
	sknconf = nsvp->sv_knconf;
	tknconf = svp->sv_knconf;
	tknconf->knc_semantics = sknconf->knc_semantics;
	tknconf->knc_rdev = sknconf->knc_rdev;
	if (sknconf->knc_proto != NULL) {
		tknconf->knc_proto = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
		bcopy(sknconf->knc_proto, (char *)tknconf->knc_proto,
		    KNC_STRSIZE);
	}
	if (sknconf->knc_protofmly != NULL) {
		tknconf->knc_protofmly = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
		bcopy(sknconf->knc_protofmly, (char *)tknconf->knc_protofmly,
		    KNC_STRSIZE);
	}

	if (nsvp->sv_origknconf != NULL) {
		svp->sv_origknconf = kmem_zalloc(sizeof (struct knetconfig),
		    KM_SLEEP);
		sknconf = nsvp->sv_origknconf;
		tknconf = svp->sv_origknconf;
		tknconf->knc_semantics = sknconf->knc_semantics;
		tknconf->knc_rdev = sknconf->knc_rdev;
		if (sknconf->knc_proto != NULL) {
			tknconf->knc_proto = kmem_zalloc(KNC_STRSIZE, KM_SLEEP);
			bcopy(sknconf->knc_proto, (char *)tknconf->knc_proto,
			    KNC_STRSIZE);
		}
		if (sknconf->knc_protofmly != NULL) {
			tknconf->knc_protofmly = kmem_zalloc(KNC_STRSIZE,
			    KM_SLEEP);
			bcopy(sknconf->knc_protofmly,
			    (char *)tknconf->knc_protofmly, KNC_STRSIZE);
		}
	}

	svp->sv_secdata = copy_sec_data(nsvp->sv_secdata);
	svp->sv_dhsec = copy_sec_data(svp->sv_dhsec);
	/*
	 * Rest of the security information is not copied as they are built
	 * with the information available from secdata and dhsec.
	 */
	svp->sv_next = NULL;

	return (svp);
}

servinfo4_t *
restore_svp(mntinfo4_t *mi, servinfo4_t *svp, servinfo4_t *origsvp)
{
	servinfo4_t *srvnext, *tmpsrv;

	if (strcmp(svp->sv_hostname, origsvp->sv_hostname) != 0) {
		/*
		 * Since the hostname changed, we must be dealing
		 * with a referral, and the lookup failed.  We will
		 * restore the whole servinfo4_t to what it was before.
		 */
		srvnext = svp->sv_next;
		svp->sv_next = NULL;
		tmpsrv = copy_svp(origsvp);
		sv4_free(svp);
		svp = tmpsrv;
		svp->sv_next = srvnext;
		mutex_enter(&mi->mi_lock);
		mi->mi_servers = svp;
		mi->mi_curr_serv = svp;
		mutex_exit(&mi->mi_lock);

	} else if (origsvp->sv_pathlen != svp->sv_pathlen) {

		/*
		 * For symlink case: restore original path because
		 * it might have contained symlinks that were
		 * expanded by nfsgetfh_otw before the failure occurred.
		 */
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		kmem_free(svp->sv_path, svp->sv_pathlen);
		svp->sv_path =
		    kmem_alloc(origsvp->sv_pathlen, KM_SLEEP);
		svp->sv_pathlen = origsvp->sv_pathlen;
		bcopy(origsvp->sv_path, svp->sv_path,
		    origsvp->sv_pathlen);
		nfs_rw_exit(&svp->sv_lock);
	}
	return (svp);
}

static ushort_t nfs4_max_threads = 8;	/* max number of active async threads */
uint_t nfs4_bsize = 32 * 1024;	/* client `block' size */
static uint_t nfs4_async_clusters = 1;	/* # of reqs from each async queue */
static uint_t nfs4_cots_timeo = NFS_COTS_TIMEO;

/*
 * Remap the root filehandle for the given filesystem.
 *
 * results returned via the nfs4_error_t parameter.
 */
void
nfs4_remap_root(mntinfo4_t *mi, nfs4_error_t *ep, int flags)
{
	struct servinfo4 *svp, *origsvp;
	vtype_t vtype;
	nfs_fh4 rootfh;
	int getfh_flags;
	int num_retry;

	mutex_enter(&mi->mi_lock);

remap_retry:
	svp = mi->mi_curr_serv;
	getfh_flags =
	    (flags & NFS4_REMAP_NEEDSOP) ? NFS4_GETFH_NEEDSOP : 0;
	getfh_flags |=
	    (mi->mi_flags & MI4_PUBLIC) ? NFS4_GETFH_PUBLIC : 0;
	mutex_exit(&mi->mi_lock);

	/*
	 * Just in case server path being mounted contains
	 * symlinks and fails w/STALE, save the initial sv_path
	 * so we can redrive the initial mount compound with the
	 * initial sv_path -- not a symlink-expanded version.
	 *
	 * This could only happen if a symlink was expanded
	 * and the expanded mount compound failed stale.  Because
	 * it could be the case that the symlink was removed at
	 * the server (and replaced with another symlink/dir,
	 * we need to use the initial sv_path when attempting
	 * to re-lookup everything and recover.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	origsvp = copy_svp(svp);
	nfs_rw_exit(&svp->sv_lock);

	num_retry = nfs4_max_mount_retry;

	do {
		/*
		 * Get the root fh from the server.  Retry nfs4_max_mount_retry
		 * (2) times if it fails with STALE since the recovery
		 * infrastructure doesn't do STALE recovery for components
		 * of the server path to the object being mounted.
		 */
		nfs4getfh_otw(mi, svp, &vtype, getfh_flags, CRED(), ep);

		if (ep->error == 0 && ep->stat == NFS4_OK)
			break;

		/*
		 * For some reason, the mount compound failed.  Before
		 * retrying, we need to restore original conditions.
		 */
		svp = restore_svp(mi, svp, origsvp);

	} while (num_retry-- > 0);

	sv4_free(origsvp);

	if (ep->error != 0 || ep->stat != 0) {
		return;
	}

	if (vtype != VNON && vtype != mi->mi_type) {
		/* shouldn't happen */
		zcmn_err(mi->mi_zone->zone_id, CE_WARN,
		    "nfs4_remap_root: server root vnode type (%d) doesn't "
		    "match mount info (%d)", vtype, mi->mi_type);
	}

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	rootfh.nfs_fh4_val = svp->sv_fhandle.fh_buf;
	rootfh.nfs_fh4_len = svp->sv_fhandle.fh_len;
	nfs_rw_exit(&svp->sv_lock);
	sfh4_update(mi->mi_rootfh, &rootfh);

	/*
	 * It's possible that recovery took place on the filesystem
	 * and the server has been updated between the time we did
	 * the nfs4getfh_otw and now. Re-drive the otw operation
	 * to make sure we have a good fh.
	 */
	mutex_enter(&mi->mi_lock);
	if (mi->mi_curr_serv != svp)
		goto remap_retry;

	mutex_exit(&mi->mi_lock);
}

static int
nfs4rootvp(vnode_t **rtvpp, vfs_t *vfsp, struct servinfo4 *svp_head,
    int flags, cred_t *cr, zone_t *zone)
{
	vnode_t *rtvp = NULL;
	mntinfo4_t *mi;
	dev_t nfs_dev;
	int error = 0;
	rnode4_t *rp;
	int i, len;
	struct vattr va;
	vtype_t vtype = VNON;
	vtype_t tmp_vtype = VNON;
	struct servinfo4 *firstsvp = NULL, *svp = svp_head;
	nfs4_oo_hash_bucket_t *bucketp;
	nfs_fh4 fh;
	char *droptext = "";
	struct nfs_stats *nfsstatsp;
	nfs4_fname_t *mfname;
	nfs4_error_t e;
	int num_retry, removed;
	cred_t *lcr = NULL, *tcr = cr;
	struct servinfo4 *origsvp;
	char *resource;

	nfsstatsp = zone_getspecific(nfsstat_zone_key, nfs_zone());
	ASSERT(nfsstatsp != NULL);

	ASSERT(nfs_zone() == zone);
	ASSERT(crgetref(cr));

	/*
	 * Create a mount record and link it to the vfs struct.
	 */
	mi = kmem_zalloc(sizeof (*mi), KM_SLEEP);
	mutex_init(&mi->mi_lock, NULL, MUTEX_DEFAULT, NULL);
	nfs_rw_init(&mi->mi_recovlock, NULL, RW_DEFAULT, NULL);
	nfs_rw_init(&mi->mi_rename_lock, NULL, RW_DEFAULT, NULL);
	nfs_rw_init(&mi->mi_fh_lock, NULL, RW_DEFAULT, NULL);

	if (!(flags & NFSMNT_SOFT))
		mi->mi_flags |= MI4_HARD;
	if ((flags & NFSMNT_NOPRINT))
		mi->mi_flags |= MI4_NOPRINT;
	if (flags & NFSMNT_INT)
		mi->mi_flags |= MI4_INT;
	if (flags & NFSMNT_PUBLIC)
		mi->mi_flags |= MI4_PUBLIC;
	if (flags & NFSMNT_MIRRORMOUNT)
		mi->mi_flags |= MI4_MIRRORMOUNT;
	if (flags & NFSMNT_REFERRAL)
		mi->mi_flags |= MI4_REFERRAL;
	mi->mi_retrans = NFS_RETRIES;
	if (svp->sv_knconf->knc_semantics == NC_TPI_COTS_ORD ||
	    svp->sv_knconf->knc_semantics == NC_TPI_COTS)
		mi->mi_timeo = nfs4_cots_timeo;
	else
		mi->mi_timeo = NFS_TIMEO;
	mi->mi_prog = NFS_PROGRAM;
	mi->mi_vers = NFS_V4;
	mi->mi_rfsnames = rfsnames_v4;
	mi->mi_reqs = nfsstatsp->nfs_stats_v4.rfsreqcnt_ptr;
	cv_init(&mi->mi_failover_cv, NULL, CV_DEFAULT, NULL);
	mi->mi_servers = svp;
	mi->mi_curr_serv = svp;
	mi->mi_acregmin = SEC2HR(ACREGMIN);
	mi->mi_acregmax = SEC2HR(ACREGMAX);
	mi->mi_acdirmin = SEC2HR(ACDIRMIN);
	mi->mi_acdirmax = SEC2HR(ACDIRMAX);
	mi->mi_fh_expire_type = FH4_PERSISTENT;
	mi->mi_clientid_next = NULL;
	mi->mi_clientid_prev = NULL;
	mi->mi_srv = NULL;
	mi->mi_grace_wait = 0;
	mi->mi_error = 0;
	mi->mi_srvsettime = 0;
	mi->mi_srvset_cnt = 0;

	mi->mi_count = 1;

	mi->mi_tsize = nfs4_tsize(svp->sv_knconf);
	mi->mi_stsize = mi->mi_tsize;

	if (flags & NFSMNT_DIRECTIO)
		mi->mi_flags |= MI4_DIRECTIO;

	mi->mi_flags |= MI4_MOUNTING;

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
	vfs_make_fsid(&vfsp->vfs_fsid, nfs_dev, nfs4fstyp);
	vfsp->vfs_data = (caddr_t)mi;
	vfsp->vfs_fstype = nfsfstyp;
	vfsp->vfs_bsize = nfs4_bsize;

	/*
	 * Initialize fields used to support async putpage operations.
	 */
	for (i = 0; i < NFS4_ASYNC_TYPES; i++)
		mi->mi_async_clusters[i] = nfs4_async_clusters;
	mi->mi_async_init_clusters = nfs4_async_clusters;
	mi->mi_async_curr[NFS4_ASYNC_QUEUE] =
	    mi->mi_async_curr[NFS4_ASYNC_PGOPS_QUEUE] = &mi->mi_async_reqs[0];
	mi->mi_max_threads = nfs4_max_threads;
	mutex_init(&mi->mi_async_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mi->mi_async_reqs_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&mi->mi_async_work_cv[NFS4_ASYNC_QUEUE], NULL, CV_DEFAULT,
	    NULL);
	cv_init(&mi->mi_async_work_cv[NFS4_ASYNC_PGOPS_QUEUE], NULL,
	    CV_DEFAULT, NULL);
	cv_init(&mi->mi_async_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&mi->mi_inact_req_cv, NULL, CV_DEFAULT, NULL);

	mi->mi_vfsp = vfsp;
	mi->mi_zone = zone;
	zone_init_ref(&mi->mi_zone_ref);
	zone_hold_ref(zone, &mi->mi_zone_ref, ZONE_REF_NFSV4);
	nfs4_mi_zonelist_add(mi);

	/*
	 * Initialize the <open owner/cred> hash table.
	 */
	for (i = 0; i < NFS4_NUM_OO_BUCKETS; i++) {
		bucketp = &(mi->mi_oo_list[i]);
		mutex_init(&bucketp->b_lock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&bucketp->b_oo_hash_list,
		    sizeof (nfs4_open_owner_t),
		    offsetof(nfs4_open_owner_t, oo_hash_node));
	}

	/*
	 * Initialize the freed open owner list.
	 */
	mi->mi_foo_num = 0;
	mi->mi_foo_max = NFS4_NUM_FREED_OPEN_OWNERS;
	list_create(&mi->mi_foo_list, sizeof (nfs4_open_owner_t),
	    offsetof(nfs4_open_owner_t, oo_foo_node));

	list_create(&mi->mi_lost_state, sizeof (nfs4_lost_rqst_t),
	    offsetof(nfs4_lost_rqst_t, lr_node));

	list_create(&mi->mi_bseqid_list, sizeof (nfs4_bseqid_entry_t),
	    offsetof(nfs4_bseqid_entry_t, bs_node));

	/*
	 * Initialize the msg buffer.
	 */
	list_create(&mi->mi_msg_list, sizeof (nfs4_debug_msg_t),
	    offsetof(nfs4_debug_msg_t, msg_node));
	mi->mi_msg_count = 0;
	mutex_init(&mi->mi_msg_list_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Initialize kstats
	 */
	nfs4_mnt_kstat_init(vfsp);

	/*
	 * Initialize the shared filehandle pool.
	 */
	sfh4_createtab(&mi->mi_filehandles);

	/*
	 * Save server path we're attempting to mount.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	origsvp = copy_svp(svp);
	nfs_rw_exit(&svp->sv_lock);

	/*
	 * Make the GETFH call to get root fh for each replica.
	 */
	if (svp_head->sv_next)
		droptext = ", dropping replica";

	/*
	 * If the uid is set then set the creds for secure mounts
	 * by proxy processes such as automountd.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	if (svp->sv_secdata->uid != 0 &&
	    svp->sv_secdata->rpcflavor == RPCSEC_GSS) {
		lcr = crdup(cr);
		(void) crsetugid(lcr, svp->sv_secdata->uid, crgetgid(cr));
		tcr = lcr;
	}
	nfs_rw_exit(&svp->sv_lock);
	for (svp = svp_head; svp; svp = svp->sv_next) {
		if (nfs4_chkdup_servinfo4(svp_head, svp)) {
			nfs_cmn_err(error, CE_WARN,
			    VERS_MSG "Host %s is a duplicate%s",
			    svp->sv_hostname, droptext);
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
			svp->sv_flags |= SV4_NOTINUSE;
			nfs_rw_exit(&svp->sv_lock);
			continue;
		}
		mi->mi_curr_serv = svp;

		/*
		 * Just in case server path being mounted contains
		 * symlinks and fails w/STALE, save the initial sv_path
		 * so we can redrive the initial mount compound with the
		 * initial sv_path -- not a symlink-expanded version.
		 *
		 * This could only happen if a symlink was expanded
		 * and the expanded mount compound failed stale.  Because
		 * it could be the case that the symlink was removed at
		 * the server (and replaced with another symlink/dir,
		 * we need to use the initial sv_path when attempting
		 * to re-lookup everything and recover.
		 *
		 * Other mount errors should evenutally be handled here also
		 * (NFS4ERR_DELAY, NFS4ERR_RESOURCE).  For now, all mount
		 * failures will result in mount being redriven a few times.
		 */
		num_retry = nfs4_max_mount_retry;
		do {
			nfs4getfh_otw(mi, svp, &tmp_vtype,
			    ((flags & NFSMNT_PUBLIC) ? NFS4_GETFH_PUBLIC : 0) |
			    NFS4_GETFH_NEEDSOP, tcr, &e);

			if (e.error == 0 && e.stat == NFS4_OK)
				break;

			/*
			 * For some reason, the mount compound failed.  Before
			 * retrying, we need to restore original conditions.
			 */
			svp = restore_svp(mi, svp, origsvp);
			svp_head = svp;

		} while (num_retry-- > 0);
		error = e.error ? e.error : geterrno4(e.stat);
		if (error) {
			nfs_cmn_err(error, CE_WARN,
			    VERS_MSG "initial call to %s failed%s: %m",
			    svp->sv_hostname, droptext);
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
			svp->sv_flags |= SV4_NOTINUSE;
			nfs_rw_exit(&svp->sv_lock);
			mi->mi_flags &= ~MI4_RECOV_FAIL;
			mi->mi_error = 0;
			continue;
		}

		if (tmp_vtype == VBAD) {
			zcmn_err(mi->mi_zone->zone_id, CE_WARN,
			    VERS_MSG "%s returned a bad file type for "
			    "root%s", svp->sv_hostname, droptext);
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
			svp->sv_flags |= SV4_NOTINUSE;
			nfs_rw_exit(&svp->sv_lock);
			continue;
		}

		if (vtype == VNON) {
			vtype = tmp_vtype;
		} else if (vtype != tmp_vtype) {
			zcmn_err(mi->mi_zone->zone_id, CE_WARN,
			    VERS_MSG "%s returned a different file type "
			    "for root%s", svp->sv_hostname, droptext);
			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
			svp->sv_flags |= SV4_NOTINUSE;
			nfs_rw_exit(&svp->sv_lock);
			continue;
		}
		if (firstsvp == NULL)
			firstsvp = svp;
	}

	if (firstsvp == NULL) {
		if (error == 0)
			error = ENOENT;
		goto bad;
	}

	mi->mi_curr_serv = svp = firstsvp;
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ASSERT((mi->mi_curr_serv->sv_flags & SV4_NOTINUSE) == 0);
	fh.nfs_fh4_len = svp->sv_fhandle.fh_len;
	fh.nfs_fh4_val = svp->sv_fhandle.fh_buf;
	mi->mi_rootfh = sfh4_get(&fh, mi);
	fh.nfs_fh4_len = svp->sv_pfhandle.fh_len;
	fh.nfs_fh4_val = svp->sv_pfhandle.fh_buf;
	mi->mi_srvparentfh = sfh4_get(&fh, mi);
	nfs_rw_exit(&svp->sv_lock);

	/*
	 * Get the fname for filesystem root.
	 */
	mi->mi_fname = fn_get(NULL, ".", mi->mi_rootfh);
	mfname = mi->mi_fname;
	fn_hold(mfname);

	/*
	 * Make the root vnode without attributes.
	 */
	rtvp = makenfs4node_by_fh(mi->mi_rootfh, NULL,
	    &mfname, NULL, mi, cr, gethrtime());
	rtvp->v_type = vtype;

	mi->mi_curread = mi->mi_tsize;
	mi->mi_curwrite = mi->mi_stsize;

	/*
	 * Start the manager thread responsible for handling async worker
	 * threads.
	 */
	MI4_HOLD(mi);
	VFS_HOLD(vfsp);	/* add reference for thread */
	mi->mi_manager_thread = zthread_create(NULL, 0, nfs4_async_manager,
	    vfsp, 0, minclsyspri);
	ASSERT(mi->mi_manager_thread != NULL);

	/*
	 * Create the thread that handles over-the-wire calls for
	 * VOP_INACTIVE.
	 * This needs to happen after the manager thread is created.
	 */
	MI4_HOLD(mi);
	mi->mi_inactive_thread = zthread_create(NULL, 0, nfs4_inactive_thread,
	    mi, 0, minclsyspri);
	ASSERT(mi->mi_inactive_thread != NULL);

	/* If we didn't get a type, get one now */
	if (rtvp->v_type == VNON) {
		va.va_mask = AT_TYPE;
		error = nfs4getattr(rtvp, &va, tcr);
		if (error)
			goto bad;
		rtvp->v_type = va.va_type;
	}

	mi->mi_type = rtvp->v_type;

	mutex_enter(&mi->mi_lock);
	mi->mi_flags &= ~MI4_MOUNTING;
	mutex_exit(&mi->mi_lock);

	/* Update VFS with new server and path info */
	if ((strcmp(svp->sv_hostname, origsvp->sv_hostname) != 0) ||
	    (strcmp(svp->sv_path, origsvp->sv_path) != 0)) {
		len = svp->sv_hostnamelen + svp->sv_pathlen;
		resource = kmem_zalloc(len, KM_SLEEP);
		(void) strcat(resource, svp->sv_hostname);
		(void) strcat(resource, ":");
		(void) strcat(resource, svp->sv_path);
		vfs_setresource(vfsp, resource, 0);
		kmem_free(resource, len);
	}

	sv4_free(origsvp);
	*rtvpp = rtvp;
	if (lcr != NULL)
		crfree(lcr);

	return (0);
bad:
	/*
	 * An error occurred somewhere, need to clean up...
	 */
	if (lcr != NULL)
		crfree(lcr);

	if (rtvp != NULL) {
		/*
		 * We need to release our reference to the root vnode and
		 * destroy the mntinfo4 struct that we just created.
		 */
		rp = VTOR4(rtvp);
		if (rp->r_flags & R4HASHED)
			rp4_rmhash(rp);
		VN_RELE(rtvp);
	}
	nfs4_async_stop(vfsp);
	nfs4_async_manager_stop(vfsp);
	removed = nfs4_mi_zonelist_remove(mi);
	if (removed)
		zone_rele_ref(&mi->mi_zone_ref, ZONE_REF_NFSV4);

	/*
	 * This releases the initial "hold" of the mi since it will never
	 * be referenced by the vfsp.  Also, when mount returns to vfs.c
	 * with an error, the vfsp will be destroyed, not rele'd.
	 */
	MI4_RELE(mi);

	if (origsvp != NULL)
		sv4_free(origsvp);

	*rtvpp = NULL;
	return (error);
}

/*
 * vfs operations
 */
static int
nfs4_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	mntinfo4_t		*mi;
	ushort_t		omax;
	int			removed;

	bool_t			must_unlock;

	nfs4_ephemeral_tree_t	*eph_tree;

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	mi = VFTOMI4(vfsp);

	if (flag & MS_FORCE) {
		vfsp->vfs_flag |= VFS_UNMOUNTED;
		if (nfs_zone() != mi->mi_zone) {
			/*
			 * If the request is coming from the wrong zone,
			 * we don't want to create any new threads, and
			 * performance is not a concern.  Do everything
			 * inline.
			 */
			NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
			    "nfs4_unmount x-zone forced unmount of vfs %p\n",
			    (void *)vfsp));
			nfs4_free_mount(vfsp, flag, cr);
		} else {
			/*
			 * Free data structures asynchronously, to avoid
			 * blocking the current thread (for performance
			 * reasons only).
			 */
			async_free_mount(vfsp, flag, cr);
		}

		return (0);
	}

	/*
	 * Wait until all asynchronous putpage operations on
	 * this file system are complete before flushing rnodes
	 * from the cache.
	 */
	omax = mi->mi_max_threads;
	if (nfs4_async_stop_sig(vfsp))
		return (EINTR);

	r4flush(vfsp, cr);

	/*
	 * About the only reason that this would fail would be
	 * that the harvester is already busy tearing down this
	 * node. So we fail back to the caller and let them try
	 * again when needed.
	 */
	if (nfs4_ephemeral_umount(mi, flag, cr,
	    &must_unlock, &eph_tree)) {
		ASSERT(must_unlock == FALSE);
		mutex_enter(&mi->mi_async_lock);
		mi->mi_max_threads = omax;
		mutex_exit(&mi->mi_async_lock);

		return (EBUSY);
	}

	/*
	 * If there are any active vnodes on this file system,
	 * then the file system is busy and can't be unmounted.
	 */
	if (check_rtable4(vfsp)) {
		nfs4_ephemeral_umount_unlock(&must_unlock, &eph_tree);

		mutex_enter(&mi->mi_async_lock);
		mi->mi_max_threads = omax;
		mutex_exit(&mi->mi_async_lock);

		return (EBUSY);
	}

	/*
	 * The unmount can't fail from now on, so record any
	 * ephemeral changes.
	 */
	nfs4_ephemeral_umount_activate(mi, &must_unlock, &eph_tree);

	/*
	 * There are no active files that could require over-the-wire
	 * calls to the server, so stop the async manager and the
	 * inactive thread.
	 */
	nfs4_async_manager_stop(vfsp);

	/*
	 * Destroy all rnodes belonging to this file system from the
	 * rnode hash queues and purge any resources allocated to
	 * them.
	 */
	destroy_rtable4(vfsp, cr);
	vfsp->vfs_flag |= VFS_UNMOUNTED;

	nfs4_remove_mi_from_server(mi, NULL);
	removed = nfs4_mi_zonelist_remove(mi);
	if (removed)
		zone_rele_ref(&mi->mi_zone_ref, ZONE_REF_NFSV4);

	return (0);
}

/*
 * find root of nfs
 */
static int
nfs4_root(vfs_t *vfsp, vnode_t **vpp)
{
	mntinfo4_t *mi;
	vnode_t *vp;
	nfs4_fname_t *mfname;
	servinfo4_t *svp;

	mi = VFTOMI4(vfsp);

	if (nfs_zone() != mi->mi_zone)
		return (EPERM);

	svp = mi->mi_curr_serv;
	if (svp) {
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		if (svp->sv_flags & SV4_ROOT_STALE) {
			nfs_rw_exit(&svp->sv_lock);

			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
			if (svp->sv_flags & SV4_ROOT_STALE) {
				svp->sv_flags &= ~SV4_ROOT_STALE;
				nfs_rw_exit(&svp->sv_lock);
				return (ENOENT);
			}
			nfs_rw_exit(&svp->sv_lock);
		} else
			nfs_rw_exit(&svp->sv_lock);
	}

	mfname = mi->mi_fname;
	fn_hold(mfname);
	vp = makenfs4node_by_fh(mi->mi_rootfh, NULL, &mfname, NULL,
	    VFTOMI4(vfsp), CRED(), gethrtime());

	if (VTOR4(vp)->r_flags & R4STALE) {
		VN_RELE(vp);
		return (ENOENT);
	}

	ASSERT(vp->v_type == VNON || vp->v_type == mi->mi_type);

	vp->v_type = mi->mi_type;

	*vpp = vp;

	return (0);
}

static int
nfs4_statfs_otw(vnode_t *vp, struct statvfs64 *sbp, cred_t *cr)
{
	int error;
	nfs4_ga_res_t gar;
	nfs4_ga_ext_res_t ger;

	gar.n4g_ext_res = &ger;

	if (error = nfs4_attr_otw(vp, TAG_FSINFO, &gar,
	    NFS4_STATFS_ATTR_MASK, cr))
		return (error);

	*sbp = gar.n4g_ext_res->n4g_sb;

	return (0);
}

/*
 * Get file system statistics.
 */
static int
nfs4_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	int error;
	vnode_t *vp;
	cred_t *cr;

	error = nfs4_root(vfsp, &vp);
	if (error)
		return (error);

	cr = CRED();

	error = nfs4_statfs_otw(vp, sbp, cr);
	if (!error) {
		(void) strncpy(sbp->f_basetype,
		    vfssw[vfsp->vfs_fstype].vsw_name, FSTYPSZ);
		sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	} else {
		nfs4_purge_stale_fh(error, vp, cr);
	}

	VN_RELE(vp);

	return (error);
}

static kmutex_t nfs4_syncbusy;

/*
 * Flush dirty nfs files for file system vfsp.
 * If vfsp == NULL, all nfs files are flushed.
 *
 * SYNC_CLOSE in flag is passed to us to
 * indicate that we are shutting down and or
 * rebooting.
 */
static int
nfs4_sync(vfs_t *vfsp, short flag, cred_t *cr)
{
	/*
	 * Cross-zone calls are OK here, since this translates to a
	 * VOP_PUTPAGE(B_ASYNC), which gets picked up by the right zone.
	 */
	if (!(flag & SYNC_ATTR) && mutex_tryenter(&nfs4_syncbusy) != 0) {
		r4flush(vfsp, cr);
		mutex_exit(&nfs4_syncbusy);
	}

	/*
	 * if SYNC_CLOSE is set then we know that
	 * the system is rebooting, mark the mntinfo
	 * for later examination.
	 */
	if (vfsp && (flag & SYNC_CLOSE)) {
		mntinfo4_t *mi;

		mi = VFTOMI4(vfsp);
		if (!(mi->mi_flags & MI4_SHUTDOWN)) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags |= MI4_SHUTDOWN;
			mutex_exit(&mi->mi_lock);
		}
	}
	return (0);
}

/*
 * vget is difficult, if not impossible, to support in v4 because we don't
 * know the parent directory or name, which makes it impossible to create a
 * useful shadow vnode.  And we need the shadow vnode for things like
 * OPEN.
 */

/* ARGSUSED */
/*
 * XXX Check nfs4_vget_pseudo() for dependency.
 */
static int
nfs4_vget(vfs_t *vfsp, vnode_t **vpp, fid_t *fidp)
{
	return (EREMOTE);
}

/*
 * nfs4_mountroot get called in the case where we are diskless booting.  All
 * we need from here is the ability to get the server info and from there we
 * can simply call nfs4_rootvp.
 */
/* ARGSUSED */
static int
nfs4_mountroot(vfs_t *vfsp, whymountroot_t why)
{
	vnode_t *rtvp;
	char root_hostname[SYS_NMLN+1];
	struct servinfo4 *svp;
	int error;
	int vfsflags;
	size_t size;
	char *root_path;
	struct pathname pn;
	char *name;
	cred_t *cr;
	mntinfo4_t *mi;
	struct nfs_args args;		/* nfs mount arguments */
	static char token[10];
	nfs4_error_t n4e;

	bzero(&args, sizeof (args));

	/* do this BEFORE getfile which causes xid stamps to be initialized */
	clkset(-1L);		/* hack for now - until we get time svc? */

	if (why == ROOT_REMOUNT) {
		/*
		 * Shouldn't happen.
		 */
		panic("nfs4_mountroot: why == ROOT_REMOUNT");
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
	(void) getfsname("root", name, sizeof (token));

	pn_alloc(&pn);
	root_path = pn.pn_path;

	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	nfs_rw_init(&svp->sv_lock, NULL, RW_DEFAULT, NULL);
	svp->sv_knconf = kmem_zalloc(sizeof (*svp->sv_knconf), KM_SLEEP);
	svp->sv_knconf->knc_protofmly = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
	svp->sv_knconf->knc_proto = kmem_alloc(KNC_STRSIZE, KM_SLEEP);

	/*
	 * Get server address
	 * Get the root path
	 * Get server's transport
	 * Get server's hostname
	 * Get options
	 */
	args.addr = &svp->sv_addr;
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	args.fh = (char *)&svp->sv_fhandle;
	args.knconf = svp->sv_knconf;
	args.hostname = root_hostname;
	vfsflags = 0;
	if (error = mount_root(*name ? name : "root", root_path, NFS_V4,
	    &args, &vfsflags)) {
		if (error == EPROTONOSUPPORT)
			nfs_cmn_err(error, CE_WARN, "nfs4_mountroot: "
			    "mount_root failed: server doesn't support NFS V4");
		else
			nfs_cmn_err(error, CE_WARN,
			    "nfs4_mountroot: mount_root failed: %m");
		nfs_rw_exit(&svp->sv_lock);
		sv4_free(svp);
		pn_free(&pn);
		return (error);
	}
	nfs_rw_exit(&svp->sv_lock);
	svp->sv_hostnamelen = (int)(strlen(root_hostname) + 1);
	svp->sv_hostname = kmem_alloc(svp->sv_hostnamelen, KM_SLEEP);
	(void) strcpy(svp->sv_hostname, root_hostname);

	svp->sv_pathlen = (int)(strlen(root_path) + 1);
	svp->sv_path = kmem_alloc(svp->sv_pathlen, KM_SLEEP);
	(void) strcpy(svp->sv_path, root_path);

	/*
	 * Force root partition to always be mounted with AUTH_UNIX for now
	 */
	svp->sv_secdata = kmem_alloc(sizeof (*svp->sv_secdata), KM_SLEEP);
	svp->sv_secdata->secmod = AUTH_UNIX;
	svp->sv_secdata->rpcflavor = AUTH_UNIX;
	svp->sv_secdata->data = NULL;

	cr = crgetcred();
	rtvp = NULL;

	error = nfs4rootvp(&rtvp, vfsp, svp, args.flags, cr, global_zone);

	if (error) {
		crfree(cr);
		pn_free(&pn);
		sv4_free(svp);
		return (error);
	}

	mi = VTOMI4(rtvp);

	/*
	 * Send client id to the server, if necessary
	 */
	nfs4_error_zinit(&n4e);
	nfs4setclientid(mi, cr, FALSE, &n4e);
	error = n4e.error;

	crfree(cr);

	if (error) {
		pn_free(&pn);
		goto errout;
	}

	error = nfs4_setopts(rtvp, DATAMODEL_NATIVE, &args);
	if (error) {
		nfs_cmn_err(error, CE_WARN,
		    "nfs4_mountroot: invalid root mount options");
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
		sv4_free(svp);
		nfs4_async_stop(vfsp);
		nfs4_async_manager_stop(vfsp);
	}

	if (rtvp != NULL)
		VN_RELE(rtvp);

	return (error);
}

/*
 * Initialization routine for VFS routines.  Should only be called once
 */
int
nfs4_vfsinit(void)
{
	mutex_init(&nfs4_syncbusy, NULL, MUTEX_DEFAULT, NULL);
	nfs4setclientid_init();
	nfs4_ephemeral_init();
	return (0);
}

void
nfs4_vfsfini(void)
{
	nfs4_ephemeral_fini();
	nfs4setclientid_fini();
	mutex_destroy(&nfs4_syncbusy);
}

void
nfs4_freevfs(vfs_t *vfsp)
{
	mntinfo4_t *mi;

	/* need to release the initial hold */
	mi = VFTOMI4(vfsp);

	/*
	 * At this point, we can no longer reference the vfs
	 * and need to inform other holders of the reference
	 * to the mntinfo4_t.
	 */
	mi->mi_vfsp = NULL;

	MI4_RELE(mi);
}

/*
 * Client side SETCLIENTID and SETCLIENTID_CONFIRM
 */
struct nfs4_server nfs4_server_lst =
	{ &nfs4_server_lst, &nfs4_server_lst };

kmutex_t nfs4_server_lst_lock;

static void
nfs4setclientid_init(void)
{
	mutex_init(&nfs4_server_lst_lock, NULL, MUTEX_DEFAULT, NULL);
}

static void
nfs4setclientid_fini(void)
{
	mutex_destroy(&nfs4_server_lst_lock);
}

int nfs4_retry_sclid_delay = NFS4_RETRY_SCLID_DELAY;
int nfs4_num_sclid_retries = NFS4_NUM_SCLID_RETRIES;

/*
 * Set the clientid for the server for "mi".  No-op if the clientid is
 * already set.
 *
 * The recovery boolean should be set to TRUE if this function was called
 * by the recovery code, and FALSE otherwise.  This is used to determine
 * if we need to call nfs4_start/end_op as well as grab the mi_recovlock
 * for adding a mntinfo4_t to a nfs4_server_t.
 *
 * Error is returned via 'n4ep'.  If there was a 'n4ep->stat' error, then
 * 'n4ep->error' is set to geterrno4(n4ep->stat).
 */
void
nfs4setclientid(mntinfo4_t *mi, cred_t *cr, bool_t recovery, nfs4_error_t *n4ep)
{
	struct nfs4_server *np;
	struct servinfo4 *svp = mi->mi_curr_serv;
	nfs4_recov_state_t recov_state;
	int num_retries = 0;
	bool_t retry;
	cred_t *lcr = NULL;
	int retry_inuse = 1; /* only retry once on NFS4ERR_CLID_INUSE */
	time_t lease_time = 0;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
	ASSERT(n4ep != NULL);

recov_retry:
	retry = FALSE;
	nfs4_error_zinit(n4ep);
	if (!recovery)
		(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);

	mutex_enter(&nfs4_server_lst_lock);
	np = servinfo4_to_nfs4_server(svp); /* This locks np if it is found */
	mutex_exit(&nfs4_server_lst_lock);
	if (!np) {
		struct nfs4_server *tnp;
		np = new_nfs4_server(svp, cr);
		mutex_enter(&np->s_lock);

		mutex_enter(&nfs4_server_lst_lock);
		tnp = servinfo4_to_nfs4_server(svp);
		if (tnp) {
			/*
			 * another thread snuck in and put server on list.
			 * since we aren't adding it to the nfs4_server_list
			 * we need to set the ref count to 0 and destroy it.
			 */
			np->s_refcnt = 0;
			destroy_nfs4_server(np);
			np = tnp;
		} else {
			/*
			 * do not give list a reference until everything
			 * succeeds
			 */
			insque(np, &nfs4_server_lst);
		}
		mutex_exit(&nfs4_server_lst_lock);
	}
	ASSERT(MUTEX_HELD(&np->s_lock));
	/*
	 * If we find the server already has N4S_CLIENTID_SET, then
	 * just return, we've already done SETCLIENTID to that server
	 */
	if (np->s_flags & N4S_CLIENTID_SET) {
		/* add mi to np's mntinfo4_list */
		nfs4_add_mi_to_server(np, mi);
		if (!recovery)
			nfs_rw_exit(&mi->mi_recovlock);
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		return;
	}
	mutex_exit(&np->s_lock);


	/*
	 * Drop the mi_recovlock since nfs4_start_op will
	 * acquire it again for us.
	 */
	if (!recovery) {
		nfs_rw_exit(&mi->mi_recovlock);

		n4ep->error = nfs4_start_op(mi, NULL, NULL, &recov_state);
		if (n4ep->error) {
			nfs4_server_rele(np);
			return;
		}
	}

	mutex_enter(&np->s_lock);
	while (np->s_flags & N4S_CLIENTID_PEND) {
		if (!cv_wait_sig(&np->s_clientid_pend, &np->s_lock)) {
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			if (!recovery)
				nfs4_end_op(mi, NULL, NULL, &recov_state,
				    recovery);
			n4ep->error = EINTR;
			return;
		}
	}

	if (np->s_flags & N4S_CLIENTID_SET) {
		/* XXX copied/pasted from above */
		/* add mi to np's mntinfo4_list */
		nfs4_add_mi_to_server(np, mi);
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		if (!recovery)
			nfs4_end_op(mi, NULL, NULL, &recov_state, recovery);
		return;
	}

	/*
	 * Reset the N4S_CB_PINGED flag. This is used to
	 * indicate if we have received a CB_NULL from the
	 * server. Also we reset the waiter flag.
	 */
	np->s_flags &= ~(N4S_CB_PINGED | N4S_CB_WAITER);
	/* any failure must now clear this flag */
	np->s_flags |= N4S_CLIENTID_PEND;
	mutex_exit(&np->s_lock);
	nfs4setclientid_otw(mi, svp, cr, np, n4ep, &retry_inuse);

	if (n4ep->error == EACCES) {
		/*
		 * If the uid is set then set the creds for secure mounts
		 * by proxy processes such as automountd.
		 */
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		if (svp->sv_secdata->uid != 0) {
			lcr = crdup(cr);
			(void) crsetugid(lcr, svp->sv_secdata->uid,
			    crgetgid(cr));
		}
		nfs_rw_exit(&svp->sv_lock);

		if (lcr != NULL) {
			mutex_enter(&np->s_lock);
			crfree(np->s_cred);
			np->s_cred = lcr;
			mutex_exit(&np->s_lock);
			nfs4setclientid_otw(mi, svp, lcr, np, n4ep,
			    &retry_inuse);
		}
	}
	mutex_enter(&np->s_lock);
	lease_time = np->s_lease_time;
	np->s_flags &= ~N4S_CLIENTID_PEND;
	mutex_exit(&np->s_lock);

	if (n4ep->error != 0 || n4ep->stat != NFS4_OK) {
		/*
		 * Start recovery if failover is a possibility.  If
		 * invoked by the recovery thread itself, then just
		 * return and let it handle the failover first.  NB:
		 * recovery is not allowed if the mount is in progress
		 * since the infrastructure is not sufficiently setup
		 * to allow it.  Just return the error (after suitable
		 * retries).
		 */
		if (FAILOVER_MOUNT4(mi) && nfs4_try_failover(n4ep)) {
			(void) nfs4_start_recovery(n4ep, mi, NULL,
			    NULL, NULL, NULL, OP_SETCLIENTID, NULL, NULL, NULL);
			/*
			 * Don't retry here, just return and let
			 * recovery take over.
			 */
			if (recovery)
				retry = FALSE;
		} else if (nfs4_rpc_retry_error(n4ep->error) ||
		    n4ep->stat == NFS4ERR_RESOURCE ||
		    n4ep->stat == NFS4ERR_STALE_CLIENTID) {

			retry = TRUE;
			/*
			 * Always retry if in recovery or once had
			 * contact with the server (but now it's
			 * overloaded).
			 */
			if (recovery == TRUE ||
			    n4ep->error == ETIMEDOUT ||
			    n4ep->error == ECONNRESET)
				num_retries = 0;
		} else if (retry_inuse && n4ep->error == 0 &&
		    n4ep->stat == NFS4ERR_CLID_INUSE) {
			retry = TRUE;
			num_retries = 0;
		}
	} else {
		/*
		 * Since everything succeeded give the list a reference count if
		 * it hasn't been given one by add_new_nfs4_server() or if this
		 * is not a recovery situation in which case it is already on
		 * the list.
		 */
		mutex_enter(&np->s_lock);
		if ((np->s_flags & N4S_INSERTED) == 0) {
			np->s_refcnt++;
			np->s_flags |= N4S_INSERTED;
		}
		mutex_exit(&np->s_lock);
	}

	if (!recovery)
		nfs4_end_op(mi, NULL, NULL, &recov_state, recovery);


	if (retry && num_retries++ < nfs4_num_sclid_retries) {
		if (retry_inuse) {
			delay(SEC_TO_TICK(lease_time + nfs4_retry_sclid_delay));
			retry_inuse = 0;
		} else
			delay(SEC_TO_TICK(nfs4_retry_sclid_delay));

		nfs4_server_rele(np);
		goto recov_retry;
	}


	if (n4ep->error == 0)
		n4ep->error = geterrno4(n4ep->stat);

	/* broadcast before release in case no other threads are waiting */
	cv_broadcast(&np->s_clientid_pend);
	nfs4_server_rele(np);
}

int nfs4setclientid_otw_debug = 0;

/*
 * This function handles the recovery of STALE_CLIENTID for SETCLIENTID_CONFRIM,
 * but nothing else; the calling function must be designed to handle those
 * other errors.
 */
static void
nfs4setclientid_otw(mntinfo4_t *mi, struct servinfo4 *svp,  cred_t *cr,
    struct nfs4_server *np, nfs4_error_t *ep, int *retry_inusep)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[3];
	SETCLIENTID4args *s_args;
	SETCLIENTID4resok *s_resok;
	int doqueue = 1;
	nfs4_ga_res_t *garp = NULL;
	timespec_t prop_time, after_time;
	verifier4 verf;
	clientid4 tmp_clientid;

	ASSERT(!MUTEX_HELD(&np->s_lock));

	args.ctag = TAG_SETCLIENTID;

	args.array = argop;
	args.array_len = 3;

	/* PUTROOTFH */
	argop[0].argop = OP_PUTROOTFH;

	/* GETATTR */
	argop[1].argop = OP_GETATTR;
	argop[1].nfs_argop4_u.opgetattr.attr_request = FATTR4_LEASE_TIME_MASK;
	argop[1].nfs_argop4_u.opgetattr.mi = mi;

	/* SETCLIENTID */
	argop[2].argop = OP_SETCLIENTID;

	s_args = &argop[2].nfs_argop4_u.opsetclientid;

	mutex_enter(&np->s_lock);

	s_args->client.verifier = np->clidtosend.verifier;
	s_args->client.id_len = np->clidtosend.id_len;
	ASSERT(s_args->client.id_len <= NFS4_OPAQUE_LIMIT);
	s_args->client.id_val = np->clidtosend.id_val;

	/*
	 * Callback needs to happen on non-RDMA transport
	 * Check if we have saved the original knetconfig
	 * if so, use that instead.
	 */
	if (svp->sv_origknconf != NULL)
		nfs4_cb_args(np, svp->sv_origknconf, s_args);
	else
		nfs4_cb_args(np, svp->sv_knconf, s_args);

	mutex_exit(&np->s_lock);

	rfs4call(mi, &args, &res, cr, &doqueue, 0, ep);

	if (ep->error)
		return;

	/* getattr lease_time res */
	if ((res.array_len >= 2) &&
	    (res.array[1].nfs_resop4_u.opgetattr.status == NFS4_OK)) {
		garp = &res.array[1].nfs_resop4_u.opgetattr.ga_res;

#ifndef _LP64
		/*
		 * The 32 bit client cannot handle a lease time greater than
		 * (INT32_MAX/1000000).  This is due to the use of the
		 * lease_time in calls to drv_usectohz() in
		 * nfs4_renew_lease_thread().  The problem is that
		 * drv_usectohz() takes a time_t (which is just a long = 4
		 * bytes) as its parameter.  The lease_time is multiplied by
		 * 1000000 to convert seconds to usecs for the parameter.  If
		 * a number bigger than (INT32_MAX/1000000) is used then we
		 * overflow on the 32bit client.
		 */
		if (garp->n4g_ext_res->n4g_leasetime > (INT32_MAX/1000000)) {
			garp->n4g_ext_res->n4g_leasetime = INT32_MAX/1000000;
		}
#endif

		mutex_enter(&np->s_lock);
		np->s_lease_time = garp->n4g_ext_res->n4g_leasetime;

		/*
		 * Keep track of the lease period for the mi's
		 * mi_msg_list.  We need an appropiate time
		 * bound to associate past facts with a current
		 * event.  The lease period is perfect for this.
		 */
		mutex_enter(&mi->mi_msg_list_lock);
		mi->mi_lease_period = np->s_lease_time;
		mutex_exit(&mi->mi_msg_list_lock);
		mutex_exit(&np->s_lock);
	}


	if (res.status == NFS4ERR_CLID_INUSE) {
		clientaddr4 *clid_inuse;

		if (!(*retry_inusep)) {
			clid_inuse = &res.array->nfs_resop4_u.
			    opsetclientid.SETCLIENTID4res_u.client_using;

			zcmn_err(mi->mi_zone->zone_id, CE_NOTE,
			    "NFS4 mount (SETCLIENTID failed)."
			    "  nfs4_client_id.id is in"
			    "use already by: r_netid<%s> r_addr<%s>",
			    clid_inuse->r_netid, clid_inuse->r_addr);
		}

		/*
		 * XXX - The client should be more robust in its
		 * handling of clientid in use errors (regen another
		 * clientid and try again?)
		 */
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	if (res.status) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	s_resok = &res.array[2].nfs_resop4_u.
	    opsetclientid.SETCLIENTID4res_u.resok4;

	tmp_clientid = s_resok->clientid;

	verf = s_resok->setclientid_confirm;

#ifdef	DEBUG
	if (nfs4setclientid_otw_debug) {
		union {
			clientid4	clientid;
			int		foo[2];
		} cid;

		cid.clientid = s_resok->clientid;

		zcmn_err(mi->mi_zone->zone_id, CE_NOTE,
		"nfs4setclientid_otw: OK, clientid = %x,%x, "
		"verifier = %" PRIx64 "\n", cid.foo[0], cid.foo[1], verf);
	}
#endif

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	/* Confirm the client id and get the lease_time attribute */

	args.ctag = TAG_SETCLIENTID_CF;

	args.array = argop;
	args.array_len = 1;

	argop[0].argop = OP_SETCLIENTID_CONFIRM;

	argop[0].nfs_argop4_u.opsetclientid_confirm.clientid = tmp_clientid;
	argop[0].nfs_argop4_u.opsetclientid_confirm.setclientid_confirm = verf;

	/* used to figure out RTT for np */
	gethrestime(&prop_time);

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "nfs4setlientid_otw: "
	    "start time: %ld sec %ld nsec", prop_time.tv_sec,
	    prop_time.tv_nsec));

	rfs4call(mi, &args, &res, cr, &doqueue, 0, ep);

	gethrestime(&after_time);
	mutex_enter(&np->s_lock);
	np->propagation_delay.tv_sec =
	    MAX(1, after_time.tv_sec - prop_time.tv_sec);
	mutex_exit(&np->s_lock);

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "nfs4setlcientid_otw: "
	    "finish time: %ld sec ", after_time.tv_sec));

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "nfs4setclientid_otw: "
	    "propagation delay set to %ld sec",
	    np->propagation_delay.tv_sec));

	if (ep->error)
		return;

	if (res.status == NFS4ERR_CLID_INUSE) {
		clientaddr4 *clid_inuse;

		if (!(*retry_inusep)) {
			clid_inuse = &res.array->nfs_resop4_u.
			    opsetclientid.SETCLIENTID4res_u.client_using;

			zcmn_err(mi->mi_zone->zone_id, CE_NOTE,
			    "SETCLIENTID_CONFIRM failed.  "
			    "nfs4_client_id.id is in use already by: "
			    "r_netid<%s> r_addr<%s>",
			    clid_inuse->r_netid, clid_inuse->r_addr);
		}

		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	if (res.status) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	mutex_enter(&np->s_lock);
	np->clientid = tmp_clientid;
	np->s_flags |= N4S_CLIENTID_SET;

	/* Add mi to np's mntinfo4 list */
	nfs4_add_mi_to_server(np, mi);

	if (np->lease_valid == NFS4_LEASE_NOT_STARTED) {
		/*
		 * Start lease management thread.
		 * Keep trying until we succeed.
		 */

		np->s_refcnt++;		/* pass reference to thread */
		(void) zthread_create(NULL, 0, nfs4_renew_lease_thread, np, 0,
		    minclsyspri);
	}
	mutex_exit(&np->s_lock);

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
}

/*
 * Add mi to sp's mntinfo4_list if it isn't already in the list.  Makes
 * mi's clientid the same as sp's.
 * Assumes sp is locked down.
 */
void
nfs4_add_mi_to_server(nfs4_server_t *sp, mntinfo4_t *mi)
{
	mntinfo4_t *tmi;
	int in_list = 0;

	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
	    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
	ASSERT(sp != &nfs4_server_lst);
	ASSERT(MUTEX_HELD(&sp->s_lock));

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_add_mi_to_server: add mi %p to sp %p",
	    (void*)mi, (void*)sp));

	for (tmi = sp->mntinfo4_list;
	    tmi != NULL;
	    tmi = tmi->mi_clientid_next) {
		if (tmi == mi) {
			NFS4_DEBUG(nfs4_client_lease_debug,
			    (CE_NOTE,
			    "nfs4_add_mi_to_server: mi in list"));
			in_list = 1;
		}
	}

	/*
	 * First put a hold on the mntinfo4's vfsp so that references via
	 * mntinfo4_list will be valid.
	 */
	if (!in_list)
		VFS_HOLD(mi->mi_vfsp);

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "nfs4_add_mi_to_server: "
	    "hold vfs %p for mi: %p", (void*)mi->mi_vfsp, (void*)mi));

	if (!in_list) {
		if (sp->mntinfo4_list)
			sp->mntinfo4_list->mi_clientid_prev = mi;
		mi->mi_clientid_next = sp->mntinfo4_list;
		mi->mi_srv = sp;
		sp->mntinfo4_list = mi;
		mi->mi_srvsettime = gethrestime_sec();
		mi->mi_srvset_cnt++;
	}

	/* set mi's clientid to that of sp's for later matching */
	mi->mi_clientid = sp->clientid;

	/*
	 * Update the clientid for any other mi's belonging to sp.  This
	 * must be done here while we hold sp->s_lock, so that
	 * find_nfs4_server() continues to work.
	 */

	for (tmi = sp->mntinfo4_list;
	    tmi != NULL;
	    tmi = tmi->mi_clientid_next) {
		if (tmi != mi) {
			tmi->mi_clientid = sp->clientid;
		}
	}
}

/*
 * Remove the mi from sp's mntinfo4_list and release its reference.
 * Exception: if mi still has open files, flag it for later removal (when
 * all the files are closed).
 *
 * If this is the last mntinfo4 in sp's list then tell the lease renewal
 * thread to exit.
 */
static void
nfs4_remove_mi_from_server_nolock(mntinfo4_t *mi, nfs4_server_t *sp)
{
	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_remove_mi_from_server_nolock: remove mi %p from sp %p",
	    (void*)mi, (void*)sp));

	ASSERT(sp != NULL);
	ASSERT(MUTEX_HELD(&sp->s_lock));
	ASSERT(mi->mi_open_files >= 0);

	/*
	 * First make sure this mntinfo4 can be taken off of the list,
	 * ie: it doesn't have any open files remaining.
	 */
	if (mi->mi_open_files > 0) {
		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_remove_mi_from_server_nolock: don't "
		    "remove mi since it still has files open"));

		mutex_enter(&mi->mi_lock);
		mi->mi_flags |= MI4_REMOVE_ON_LAST_CLOSE;
		mutex_exit(&mi->mi_lock);
		return;
	}

	VFS_HOLD(mi->mi_vfsp);
	remove_mi(sp, mi);
	VFS_RELE(mi->mi_vfsp);

	if (sp->mntinfo4_list == NULL) {
		/* last fs unmounted, kill the thread */
		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "remove_mi_from_nfs4_server_nolock: kill the thread"));
		nfs4_mark_srv_dead(sp);
	}
}

/*
 * Remove mi from sp's mntinfo4_list and release the vfs reference.
 */
static void
remove_mi(nfs4_server_t *sp, mntinfo4_t *mi)
{
	ASSERT(MUTEX_HELD(&sp->s_lock));

	/*
	 * We release a reference, and the caller must still have a
	 * reference.
	 */
	ASSERT(mi->mi_vfsp->vfs_count >= 2);

	if (mi->mi_clientid_prev) {
		mi->mi_clientid_prev->mi_clientid_next = mi->mi_clientid_next;
	} else {
		/* This is the first mi in sp's mntinfo4_list */
		/*
		 * Make sure the first mntinfo4 in the list is the actual
		 * mntinfo4 passed in.
		 */
		ASSERT(sp->mntinfo4_list == mi);

		sp->mntinfo4_list = mi->mi_clientid_next;
	}
	if (mi->mi_clientid_next)
		mi->mi_clientid_next->mi_clientid_prev = mi->mi_clientid_prev;

	/* Now mark the mntinfo4's links as being removed */
	mi->mi_clientid_prev = mi->mi_clientid_next = NULL;
	mi->mi_srv = NULL;
	mi->mi_srvset_cnt++;

	VFS_RELE(mi->mi_vfsp);
}

/*
 * Free all the entries in sp's mntinfo4_list.
 */
static void
remove_all_mi(nfs4_server_t *sp)
{
	mntinfo4_t *mi;

	ASSERT(MUTEX_HELD(&sp->s_lock));

	while (sp->mntinfo4_list != NULL) {
		mi = sp->mntinfo4_list;
		/*
		 * Grab a reference in case there is only one left (which
		 * remove_mi() frees).
		 */
		VFS_HOLD(mi->mi_vfsp);
		remove_mi(sp, mi);
		VFS_RELE(mi->mi_vfsp);
	}
}

/*
 * Remove the mi from sp's mntinfo4_list as above, and rele the vfs.
 *
 * This version can be called with a null nfs4_server_t arg,
 * and will either find the right one and handle locking, or
 * do nothing because the mi wasn't added to an sp's mntinfo4_list.
 */
void
nfs4_remove_mi_from_server(mntinfo4_t *mi, nfs4_server_t *esp)
{
	nfs4_server_t	*sp;

	if (esp) {
		nfs4_remove_mi_from_server_nolock(mi, esp);
		return;
	}

	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);
	if (sp = find_nfs4_server_all(mi, 1)) {
		nfs4_remove_mi_from_server_nolock(mi, sp);
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
	}
	nfs_rw_exit(&mi->mi_recovlock);
}

/*
 * Return TRUE if the given server has any non-unmounted filesystems.
 */

bool_t
nfs4_fs_active(nfs4_server_t *sp)
{
	mntinfo4_t *mi;

	ASSERT(MUTEX_HELD(&sp->s_lock));

	for (mi = sp->mntinfo4_list; mi != NULL; mi = mi->mi_clientid_next) {
		if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
			return (TRUE);
	}

	return (FALSE);
}

/*
 * Mark sp as finished and notify any waiters.
 */

void
nfs4_mark_srv_dead(nfs4_server_t *sp)
{
	ASSERT(MUTEX_HELD(&sp->s_lock));

	sp->s_thread_exit = NFS4_THREAD_EXIT;
	cv_broadcast(&sp->cv_thread_exit);
}

/*
 * Create a new nfs4_server_t structure.
 * Returns new node unlocked and not in list, but with a reference count of
 * 1.
 */
struct nfs4_server *
new_nfs4_server(struct servinfo4 *svp, cred_t *cr)
{
	struct nfs4_server *np;
	timespec_t tt;
	union {
		struct {
			uint32_t sec;
			uint32_t subsec;
		} un_curtime;
		verifier4	un_verifier;
	} nfs4clientid_verifier;
	/*
	 * We change this ID string carefully and with the Solaris
	 * NFS server behaviour in mind.  "+referrals" indicates
	 * a client that can handle an NFSv4 referral.
	 */
	char id_val[] = "Solaris: %s, NFSv4 kernel client +referrals";
	int len;

	np = kmem_zalloc(sizeof (struct nfs4_server), KM_SLEEP);
	np->saddr.len = svp->sv_addr.len;
	np->saddr.maxlen = svp->sv_addr.maxlen;
	np->saddr.buf = kmem_alloc(svp->sv_addr.maxlen, KM_SLEEP);
	bcopy(svp->sv_addr.buf, np->saddr.buf, svp->sv_addr.len);
	np->s_refcnt = 1;

	/*
	 * Build the nfs_client_id4 for this server mount.  Ensure
	 * the verifier is useful and that the identification is
	 * somehow based on the server's address for the case of
	 * multi-homed servers.
	 */
	nfs4clientid_verifier.un_verifier = 0;
	gethrestime(&tt);
	nfs4clientid_verifier.un_curtime.sec = (uint32_t)tt.tv_sec;
	nfs4clientid_verifier.un_curtime.subsec = (uint32_t)tt.tv_nsec;
	np->clidtosend.verifier = nfs4clientid_verifier.un_verifier;

	/*
	 * calculate the length of the opaque identifier.  Subtract 2
	 * for the "%s" and add the traditional +1 for null
	 * termination.
	 */
	len = strlen(id_val) - 2 + strlen(uts_nodename()) + 1;
	np->clidtosend.id_len = len + np->saddr.maxlen;

	np->clidtosend.id_val = kmem_alloc(np->clidtosend.id_len, KM_SLEEP);
	(void) sprintf(np->clidtosend.id_val, id_val, uts_nodename());
	bcopy(np->saddr.buf, &np->clidtosend.id_val[len], np->saddr.len);

	np->s_flags = 0;
	np->mntinfo4_list = NULL;
	/* save cred for issuing rfs4calls inside the renew thread */
	crhold(cr);
	np->s_cred = cr;
	cv_init(&np->cv_thread_exit, NULL, CV_DEFAULT, NULL);
	mutex_init(&np->s_lock, NULL, MUTEX_DEFAULT, NULL);
	nfs_rw_init(&np->s_recovlock, NULL, RW_DEFAULT, NULL);
	list_create(&np->s_deleg_list, sizeof (rnode4_t),
	    offsetof(rnode4_t, r_deleg_link));
	np->s_thread_exit = 0;
	np->state_ref_count = 0;
	np->lease_valid = NFS4_LEASE_NOT_STARTED;
	cv_init(&np->s_cv_otw_count, NULL, CV_DEFAULT, NULL);
	cv_init(&np->s_clientid_pend, NULL, CV_DEFAULT, NULL);
	np->s_otw_call_count = 0;
	cv_init(&np->wait_cb_null, NULL, CV_DEFAULT, NULL);
	np->zoneid = getzoneid();
	np->zone_globals = nfs4_get_callback_globals();
	ASSERT(np->zone_globals != NULL);
	return (np);
}

/*
 * Create a new nfs4_server_t structure and add it to the list.
 * Returns new node locked; reference must eventually be freed.
 */
static struct nfs4_server *
add_new_nfs4_server(struct servinfo4 *svp, cred_t *cr)
{
	nfs4_server_t *sp;

	ASSERT(MUTEX_HELD(&nfs4_server_lst_lock));
	sp = new_nfs4_server(svp, cr);
	mutex_enter(&sp->s_lock);
	insque(sp, &nfs4_server_lst);
	sp->s_refcnt++;			/* list gets a reference */
	sp->s_flags |= N4S_INSERTED;
	sp->clientid = 0;
	return (sp);
}

int nfs4_server_t_debug = 0;

#ifdef lint
extern void
dumpnfs4slist(char *, mntinfo4_t *, clientid4, servinfo4_t *);
#endif

#ifndef lint
#ifdef DEBUG
void
dumpnfs4slist(char *txt, mntinfo4_t *mi, clientid4 clientid, servinfo4_t *srv_p)
{
	int hash16(void *p, int len);
	nfs4_server_t *np;

	NFS4_DEBUG(nfs4_server_t_debug, (CE_NOTE,
	    "dumping nfs4_server_t list in %s", txt));
	NFS4_DEBUG(nfs4_server_t_debug, (CE_CONT,
	    "mi 0x%p, want clientid %llx, addr %d/%04X",
	    mi, (longlong_t)clientid, srv_p->sv_addr.len,
	    hash16((void *)srv_p->sv_addr.buf, srv_p->sv_addr.len)));
	for (np = nfs4_server_lst.forw; np != &nfs4_server_lst;
	    np = np->forw) {
		NFS4_DEBUG(nfs4_server_t_debug, (CE_CONT,
		    "node 0x%p,    clientid %llx, addr %d/%04X, cnt %d",
		    np, (longlong_t)np->clientid, np->saddr.len,
		    hash16((void *)np->saddr.buf, np->saddr.len),
		    np->state_ref_count));
		if (np->saddr.len == srv_p->sv_addr.len &&
		    bcmp(np->saddr.buf, srv_p->sv_addr.buf,
		    np->saddr.len) == 0)
			NFS4_DEBUG(nfs4_server_t_debug, (CE_CONT,
			    " - address matches"));
		if (np->clientid == clientid || np->clientid == 0)
			NFS4_DEBUG(nfs4_server_t_debug, (CE_CONT,
			    " - clientid matches"));
		if (np->s_thread_exit != NFS4_THREAD_EXIT)
			NFS4_DEBUG(nfs4_server_t_debug, (CE_CONT,
			    " - thread not exiting"));
	}
	delay(hz);
}
#endif
#endif


/*
 * Move a mntinfo4_t from one server list to another.
 * Locking of the two nfs4_server_t nodes will be done in list order.
 *
 * Returns NULL if the current nfs4_server_t for the filesystem could not
 * be found (e.g., due to forced unmount).  Otherwise returns a reference
 * to the new nfs4_server_t, which must eventually be freed.
 */
nfs4_server_t *
nfs4_move_mi(mntinfo4_t *mi, servinfo4_t *old, servinfo4_t *new)
{
	nfs4_server_t *p, *op = NULL, *np = NULL;
	int num_open;
	zoneid_t zoneid = nfs_zoneid();

	ASSERT(nfs_zone() == mi->mi_zone);

	mutex_enter(&nfs4_server_lst_lock);
#ifdef DEBUG
	if (nfs4_server_t_debug)
		dumpnfs4slist("nfs4_move_mi", mi, (clientid4)0, new);
#endif
	for (p = nfs4_server_lst.forw; p != &nfs4_server_lst; p = p->forw) {
		if (p->zoneid != zoneid)
			continue;
		if (p->saddr.len == old->sv_addr.len &&
		    bcmp(p->saddr.buf, old->sv_addr.buf, p->saddr.len) == 0 &&
		    p->s_thread_exit != NFS4_THREAD_EXIT) {
			op = p;
			mutex_enter(&op->s_lock);
			op->s_refcnt++;
		}
		if (p->saddr.len == new->sv_addr.len &&
		    bcmp(p->saddr.buf, new->sv_addr.buf, p->saddr.len) == 0 &&
		    p->s_thread_exit != NFS4_THREAD_EXIT) {
			np = p;
			mutex_enter(&np->s_lock);
		}
		if (op != NULL && np != NULL)
			break;
	}
	if (op == NULL) {
		/*
		 * Filesystem has been forcibly unmounted.  Bail out.
		 */
		if (np != NULL)
			mutex_exit(&np->s_lock);
		mutex_exit(&nfs4_server_lst_lock);
		return (NULL);
	}
	if (np != NULL) {
		np->s_refcnt++;
	} else {
#ifdef DEBUG
		NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
		    "nfs4_move_mi: no target nfs4_server, will create."));
#endif
		np = add_new_nfs4_server(new, kcred);
	}
	mutex_exit(&nfs4_server_lst_lock);

	NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
	    "nfs4_move_mi: for mi 0x%p, "
	    "old servinfo4 0x%p, new servinfo4 0x%p, "
	    "old nfs4_server 0x%p, new nfs4_server 0x%p, ",
	    (void*)mi, (void*)old, (void*)new,
	    (void*)op, (void*)np));
	ASSERT(op != NULL && np != NULL);

	/* discard any delegations */
	nfs4_deleg_discard(mi, op);

	num_open = mi->mi_open_files;
	mi->mi_open_files = 0;
	op->state_ref_count -= num_open;
	ASSERT(op->state_ref_count >= 0);
	np->state_ref_count += num_open;
	nfs4_remove_mi_from_server_nolock(mi, op);
	mi->mi_open_files = num_open;
	NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
	    "nfs4_move_mi: mi_open_files %d, op->cnt %d, np->cnt %d",
	    mi->mi_open_files, op->state_ref_count, np->state_ref_count));

	nfs4_add_mi_to_server(np, mi);

	mutex_exit(&op->s_lock);
	mutex_exit(&np->s_lock);
	nfs4_server_rele(op);

	return (np);
}

/*
 * Need to have the nfs4_server_lst_lock.
 * Search the nfs4_server list to find a match on this servinfo4
 * based on its address.
 *
 * Returns NULL if no match is found.  Otherwise returns a reference (which
 * must eventually be freed) to a locked nfs4_server.
 */
nfs4_server_t *
servinfo4_to_nfs4_server(servinfo4_t *srv_p)
{
	nfs4_server_t *np;
	zoneid_t zoneid = nfs_zoneid();

	ASSERT(MUTEX_HELD(&nfs4_server_lst_lock));
	for (np = nfs4_server_lst.forw; np != &nfs4_server_lst; np = np->forw) {
		if (np->zoneid == zoneid &&
		    np->saddr.len == srv_p->sv_addr.len &&
		    bcmp(np->saddr.buf, srv_p->sv_addr.buf,
		    np->saddr.len) == 0 &&
		    np->s_thread_exit != NFS4_THREAD_EXIT) {
			mutex_enter(&np->s_lock);
			np->s_refcnt++;
			return (np);
		}
	}
	return (NULL);
}

/*
 * Locks the nfs4_server down if it is found and returns a reference that
 * must eventually be freed.
 */
static nfs4_server_t *
lookup_nfs4_server(nfs4_server_t *sp, int any_state)
{
	nfs4_server_t *np;

	mutex_enter(&nfs4_server_lst_lock);
	for (np = nfs4_server_lst.forw; np != &nfs4_server_lst; np = np->forw) {
		mutex_enter(&np->s_lock);
		if (np == sp && np->s_refcnt > 0 &&
		    (np->s_thread_exit != NFS4_THREAD_EXIT || any_state)) {
			mutex_exit(&nfs4_server_lst_lock);
			np->s_refcnt++;
			return (np);
		}
		mutex_exit(&np->s_lock);
	}
	mutex_exit(&nfs4_server_lst_lock);

	return (NULL);
}

/*
 * The caller should be holding mi->mi_recovlock, and it should continue to
 * hold the lock until done with the returned nfs4_server_t.  Once
 * mi->mi_recovlock is released, there is no guarantee that the returned
 * mi->nfs4_server_t will continue to correspond to mi.
 */
nfs4_server_t *
find_nfs4_server(mntinfo4_t *mi)
{
	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
	    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

	return (lookup_nfs4_server(mi->mi_srv, 0));
}

/*
 * Same as above, but takes an "any_state" parameter which can be
 * set to 1 if the caller wishes to find nfs4_server_t's which
 * have been marked for termination by the exit of the renew
 * thread.  This should only be used by operations which are
 * cleaning up and will not cause an OTW op.
 */
nfs4_server_t *
find_nfs4_server_all(mntinfo4_t *mi, int any_state)
{
	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
	    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

	return (lookup_nfs4_server(mi->mi_srv, any_state));
}

/*
 * Lock sp, but only if it's still active (in the list and hasn't been
 * flagged as exiting) or 'any_state' is non-zero.
 * Returns TRUE if sp got locked and adds a reference to sp.
 */
bool_t
nfs4_server_vlock(nfs4_server_t *sp, int any_state)
{
	return (lookup_nfs4_server(sp, any_state) != NULL);
}

/*
 * Release the reference to sp and destroy it if that's the last one.
 */

void
nfs4_server_rele(nfs4_server_t *sp)
{
	mutex_enter(&sp->s_lock);
	ASSERT(sp->s_refcnt > 0);
	sp->s_refcnt--;
	if (sp->s_refcnt > 0) {
		mutex_exit(&sp->s_lock);
		return;
	}
	mutex_exit(&sp->s_lock);

	mutex_enter(&nfs4_server_lst_lock);
	mutex_enter(&sp->s_lock);
	if (sp->s_refcnt > 0) {
		mutex_exit(&sp->s_lock);
		mutex_exit(&nfs4_server_lst_lock);
		return;
	}
	remque(sp);
	sp->forw = sp->back = NULL;
	mutex_exit(&nfs4_server_lst_lock);
	destroy_nfs4_server(sp);
}

static void
destroy_nfs4_server(nfs4_server_t *sp)
{
	ASSERT(MUTEX_HELD(&sp->s_lock));
	ASSERT(sp->s_refcnt == 0);
	ASSERT(sp->s_otw_call_count == 0);

	remove_all_mi(sp);

	crfree(sp->s_cred);
	kmem_free(sp->saddr.buf, sp->saddr.maxlen);
	kmem_free(sp->clidtosend.id_val, sp->clidtosend.id_len);
	mutex_exit(&sp->s_lock);

	/* destroy the nfs4_server */
	nfs4callback_destroy(sp);
	list_destroy(&sp->s_deleg_list);
	mutex_destroy(&sp->s_lock);
	cv_destroy(&sp->cv_thread_exit);
	cv_destroy(&sp->s_cv_otw_count);
	cv_destroy(&sp->s_clientid_pend);
	cv_destroy(&sp->wait_cb_null);
	nfs_rw_destroy(&sp->s_recovlock);
	kmem_free(sp, sizeof (*sp));
}

/*
 * Fork off a thread to free the data structures for a mount.
 */

static void
async_free_mount(vfs_t *vfsp, int flag, cred_t *cr)
{
	freemountargs_t *args;
	args = kmem_alloc(sizeof (freemountargs_t), KM_SLEEP);
	args->fm_vfsp = vfsp;
	VFS_HOLD(vfsp);
	MI4_HOLD(VFTOMI4(vfsp));
	args->fm_flag = flag;
	args->fm_cr = cr;
	crhold(cr);
	(void) zthread_create(NULL, 0, nfs4_free_mount_thread, args, 0,
	    minclsyspri);
}

static void
nfs4_free_mount_thread(freemountargs_t *args)
{
	mntinfo4_t *mi;
	nfs4_free_mount(args->fm_vfsp, args->fm_flag, args->fm_cr);
	mi = VFTOMI4(args->fm_vfsp);
	crfree(args->fm_cr);
	VFS_RELE(args->fm_vfsp);
	MI4_RELE(mi);
	kmem_free(args, sizeof (freemountargs_t));
	zthread_exit();
	/* NOTREACHED */
}

/*
 * Thread to free the data structures for a given filesystem.
 */
static void
nfs4_free_mount(vfs_t *vfsp, int flag, cred_t *cr)
{
	mntinfo4_t		*mi = VFTOMI4(vfsp);
	nfs4_server_t		*sp;
	callb_cpr_t		cpr_info;
	kmutex_t		cpr_lock;
	boolean_t		async_thread;
	int			removed;

	bool_t			must_unlock;
	nfs4_ephemeral_tree_t	*eph_tree;

	/*
	 * We need to participate in the CPR framework if this is a kernel
	 * thread.
	 */
	async_thread = (curproc == nfs_zone()->zone_zsched);
	if (async_thread) {
		mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
		CALLB_CPR_INIT(&cpr_info, &cpr_lock, callb_generic_cpr,
		    "nfsv4AsyncUnmount");
	}

	/*
	 * We need to wait for all outstanding OTW calls
	 * and recovery to finish before we remove the mi
	 * from the nfs4_server_t, as current pending
	 * calls might still need this linkage (in order
	 * to find a nfs4_server_t from a mntinfo4_t).
	 */
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, FALSE);
	sp = find_nfs4_server(mi);
	nfs_rw_exit(&mi->mi_recovlock);

	if (sp) {
		while (sp->s_otw_call_count != 0) {
			if (async_thread) {
				mutex_enter(&cpr_lock);
				CALLB_CPR_SAFE_BEGIN(&cpr_info);
				mutex_exit(&cpr_lock);
			}
			cv_wait(&sp->s_cv_otw_count, &sp->s_lock);
			if (async_thread) {
				mutex_enter(&cpr_lock);
				CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
				mutex_exit(&cpr_lock);
			}
		}
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
		sp = NULL;
	}

	mutex_enter(&mi->mi_lock);
	while (mi->mi_in_recovery != 0) {
		if (async_thread) {
			mutex_enter(&cpr_lock);
			CALLB_CPR_SAFE_BEGIN(&cpr_info);
			mutex_exit(&cpr_lock);
		}
		cv_wait(&mi->mi_cv_in_recov, &mi->mi_lock);
		if (async_thread) {
			mutex_enter(&cpr_lock);
			CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
			mutex_exit(&cpr_lock);
		}
	}
	mutex_exit(&mi->mi_lock);

	/*
	 * If we got an error, then do not nuke the
	 * tree. Either the harvester is busy reclaiming
	 * this node or we ran into some busy condition.
	 *
	 * The harvester will eventually come along and cleanup.
	 * The only problem would be the root mount point.
	 *
	 * Since the busy node can occur for a variety
	 * of reasons and can result in an entry staying
	 * in df output but no longer accessible from the
	 * directory tree, we are okay.
	 */
	if (!nfs4_ephemeral_umount(mi, flag, cr,
	    &must_unlock, &eph_tree))
		nfs4_ephemeral_umount_activate(mi, &must_unlock,
		    &eph_tree);

	/*
	 * The original purge of the dnlc via 'dounmount'
	 * doesn't guarantee that another dnlc entry was not
	 * added while we waitied for all outstanding OTW
	 * and recovery calls to finish.  So re-purge the
	 * dnlc now.
	 */
	(void) dnlc_purge_vfsp(vfsp, 0);

	/*
	 * We need to explicitly stop the manager thread; the asyc worker
	 * threads can timeout and exit on their own.
	 */
	mutex_enter(&mi->mi_async_lock);
	mi->mi_max_threads = 0;
	NFS4_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
	mutex_exit(&mi->mi_async_lock);
	if (mi->mi_manager_thread)
		nfs4_async_manager_stop(vfsp);

	destroy_rtable4(vfsp, cr);

	nfs4_remove_mi_from_server(mi, NULL);

	if (async_thread) {
		mutex_enter(&cpr_lock);
		CALLB_CPR_EXIT(&cpr_info);	/* drops cpr_lock */
		mutex_destroy(&cpr_lock);
	}

	removed = nfs4_mi_zonelist_remove(mi);
	if (removed)
		zone_rele_ref(&mi->mi_zone_ref, ZONE_REF_NFSV4);
}

/* Referral related sub-routines */

/* Freeup knetconfig */
static void
free_knconf_contents(struct knetconfig *k)
{
	if (k == NULL)
		return;
	if (k->knc_protofmly)
		kmem_free(k->knc_protofmly, KNC_STRSIZE);
	if (k->knc_proto)
		kmem_free(k->knc_proto, KNC_STRSIZE);
}

/*
 * This updates newpath variable with exact name component from the
 * path which gave us a NFS4ERR_MOVED error.
 * If the path is /rp/aaa/bbb and nth value is 1, aaa is returned.
 */
static char *
extract_referral_point(const char *svp, int nth)
{
	int num_slashes = 0;
	const char *p;
	char *newpath = NULL;
	int i = 0;

	newpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	for (p = svp; *p; p++) {
		if (*p == '/')
			num_slashes++;
		if (num_slashes == nth + 1) {
			p++;
			while (*p != '/') {
				if (*p == '\0')
					break;
				newpath[i] = *p;
				i++;
				p++;
			}
			newpath[i++] = '\0';
			break;
		}
	}
	return (newpath);
}

/*
 * This sets up a new path in sv_path to do a lookup of the referral point.
 * If the path is /rp/aaa/bbb and the referral point is aaa,
 * this updates /rp/aaa. This path will be used to get referral
 * location.
 */
static void
setup_newsvpath(servinfo4_t *svp, int nth)
{
	int num_slashes = 0, pathlen, i = 0;
	char *newpath, *p;

	newpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	for (p = svp->sv_path; *p; p++) {
		newpath[i] =  *p;
		if (*p == '/')
			num_slashes++;
		if (num_slashes == nth + 1) {
			newpath[i] = '\0';
			pathlen = strlen(newpath) + 1;
			kmem_free(svp->sv_path, svp->sv_pathlen);
			svp->sv_path = kmem_alloc(pathlen, KM_SLEEP);
			svp->sv_pathlen = pathlen;
			bcopy(newpath, svp->sv_path, pathlen);
			break;
		}
		i++;
	}
	kmem_free(newpath, MAXPATHLEN);
}
