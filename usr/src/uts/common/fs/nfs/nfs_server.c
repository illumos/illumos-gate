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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 *	Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/siginfo.h>
#include <sys/tiuser.h>
#include <sys/statvfs.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/timod.h>
#include <sys/t_kuser.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/dirent.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/unistd.h>
#include <sys/vtrace.h>
#include <sys/mode.h>
#include <sys/acl.h>
#include <sys/sdt.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <rpc/rpc_rdma.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>
#include <nfs/nfs_log.h>
#include <nfs/nfs_cmd.h>
#include <nfs/lm.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfs4_drc.h>

#include <sys/modctl.h>
#include <sys/cladm.h>
#include <sys/clconf.h>

#include <sys/tsol/label.h>

#define	MAXHOST 32
const char *kinet_ntop6(uchar_t *, char *, size_t);

/*
 * Module linkage information.
 */

static struct modlmisc modlmisc = {
	&mod_miscops, "NFS server module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

kmem_cache_t *nfs_xuio_cache;
int nfs_loaned_buffers = 0;

int
_init(void)
{
	int status;

	if ((status = nfs_srvinit()) != 0) {
		cmn_err(CE_WARN, "_init: nfs_srvinit failed");
		return (status);
	}

	status = mod_install((struct modlinkage *)&modlinkage);
	if (status != 0) {
		/*
		 * Could not load module, cleanup previous
		 * initialization work.
		 */
		nfs_srvfini();

		return (status);
	}

	/*
	 * Initialise some placeholders for nfssys() calls. These have
	 * to be declared by the nfs module, since that handles nfssys()
	 * calls - also used by NFS clients - but are provided by this
	 * nfssrv module. These also then serve as confirmation to the
	 * relevant code in nfs that nfssrv has been loaded, as they're
	 * initially NULL.
	 */
	nfs_srv_quiesce_func = nfs_srv_quiesce_all;
	nfs_srv_dss_func = rfs4_dss_setpaths;

	/* setup DSS paths here; must be done before initial server startup */
	rfs4_dss_paths = rfs4_dss_oldpaths = NULL;

	/* initialize the copy reduction caches */

	nfs_xuio_cache = kmem_cache_create("nfs_xuio_cache",
	    sizeof (nfs_xuio_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	return (status);
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * PUBLICFH_CHECK() checks if the dispatch routine supports
 * RPC_PUBLICFH_OK, if the filesystem is exported public, and if the
 * incoming request is using the public filehandle. The check duplicates
 * the exportmatch() call done in checkexport(), and we should consider
 * modifying those routines to avoid the duplication. For now, we optimize
 * by calling exportmatch() only after checking that the dispatch routine
 * supports RPC_PUBLICFH_OK, and if the filesystem is explicitly exported
 * public (i.e., not the placeholder).
 */
#define	PUBLICFH_CHECK(disp, exi, fsid, xfid) \
		((disp->dis_flags & RPC_PUBLICFH_OK) && \
		((exi->exi_export.ex_flags & EX_PUBLIC) || \
		(exi == exi_public && exportmatch(exi_root, \
		fsid, xfid))))

static void	nfs_srv_shutdown_all(int);
static void	rfs4_server_start(int);
static void	nullfree(void);
static void	rfs_dispatch(struct svc_req *, SVCXPRT *);
static void	acl_dispatch(struct svc_req *, SVCXPRT *);
static void	common_dispatch(struct svc_req *, SVCXPRT *,
		rpcvers_t, rpcvers_t, char *,
		struct rpc_disptable *);
static void	hanfsv4_failover(void);
static	int	checkauth(struct exportinfo *, struct svc_req *, cred_t *, int,
		bool_t, bool_t *);
static char	*client_name(struct svc_req *req);
static char	*client_addr(struct svc_req *req, char *buf);
extern	int	sec_svc_getcred(struct svc_req *, cred_t *cr, char **, int *);
extern	bool_t	sec_svc_inrootlist(int, caddr_t, int, caddr_t *);

#define	NFSLOG_COPY_NETBUF(exi, xprt, nb)	{		\
	(nb)->maxlen = (xprt)->xp_rtaddr.maxlen;		\
	(nb)->len = (xprt)->xp_rtaddr.len;			\
	(nb)->buf = kmem_alloc((nb)->len, KM_SLEEP);		\
	bcopy((xprt)->xp_rtaddr.buf, (nb)->buf, (nb)->len);	\
	}

/*
 * Public Filehandle common nfs routines
 */
static int	MCLpath(char **);
static void	URLparse(char *);

/*
 * NFS callout table.
 * This table is used by svc_getreq() to dispatch a request with
 * a given prog/vers pair to an appropriate service provider
 * dispatch routine.
 *
 * NOTE: ordering is relied upon below when resetting the version min/max
 * for NFS_PROGRAM.  Careful, if this is ever changed.
 */
static SVC_CALLOUT __nfs_sc_clts[] = {
	{ NFS_PROGRAM,	   NFS_VERSMIN,	    NFS_VERSMAX,	rfs_dispatch },
	{ NFS_ACL_PROGRAM, NFS_ACL_VERSMIN, NFS_ACL_VERSMAX,	acl_dispatch }
};

static SVC_CALLOUT_TABLE nfs_sct_clts = {
	sizeof (__nfs_sc_clts) / sizeof (__nfs_sc_clts[0]), FALSE,
	__nfs_sc_clts
};

static SVC_CALLOUT __nfs_sc_cots[] = {
	{ NFS_PROGRAM,	   NFS_VERSMIN,	    NFS_VERSMAX,	rfs_dispatch },
	{ NFS_ACL_PROGRAM, NFS_ACL_VERSMIN, NFS_ACL_VERSMAX,	acl_dispatch }
};

static SVC_CALLOUT_TABLE nfs_sct_cots = {
	sizeof (__nfs_sc_cots) / sizeof (__nfs_sc_cots[0]), FALSE, __nfs_sc_cots
};

static SVC_CALLOUT __nfs_sc_rdma[] = {
	{ NFS_PROGRAM,	   NFS_VERSMIN,	    NFS_VERSMAX,	rfs_dispatch },
	{ NFS_ACL_PROGRAM, NFS_ACL_VERSMIN, NFS_ACL_VERSMAX,	acl_dispatch }
};

static SVC_CALLOUT_TABLE nfs_sct_rdma = {
	sizeof (__nfs_sc_rdma) / sizeof (__nfs_sc_rdma[0]), FALSE, __nfs_sc_rdma
};
rpcvers_t nfs_versmin = NFS_VERSMIN_DEFAULT;
rpcvers_t nfs_versmax = NFS_VERSMAX_DEFAULT;

/*
 * Used to track the state of the server so that initialization
 * can be done properly.
 */
typedef enum {
	NFS_SERVER_STOPPED,	/* server state destroyed */
	NFS_SERVER_STOPPING,	/* server state being destroyed */
	NFS_SERVER_RUNNING,
	NFS_SERVER_QUIESCED,	/* server state preserved */
	NFS_SERVER_OFFLINE	/* server pool offline */
} nfs_server_running_t;

static nfs_server_running_t nfs_server_upordown;
static kmutex_t nfs_server_upordown_lock;
static	kcondvar_t nfs_server_upordown_cv;

/*
 * DSS: distributed stable storage
 * lists of all DSS paths: current, and before last warmstart
 */
nvlist_t *rfs4_dss_paths, *rfs4_dss_oldpaths;

int rfs4_dispatch(struct rpcdisp *, struct svc_req *, SVCXPRT *, char *,
    size_t *);
bool_t rfs4_minorvers_mismatch(struct svc_req *, SVCXPRT *, void *);

/*
 * RDMA wait variables.
 */
static kcondvar_t rdma_wait_cv;
static kmutex_t rdma_wait_mutex;

/*
 * Will be called at the point the server pool is being unregistered
 * from the pool list. From that point onwards, the pool is waiting
 * to be drained and as such the server state is stale and pertains
 * to the old instantiation of the NFS server pool.
 */
void
nfs_srv_offline(void)
{
	mutex_enter(&nfs_server_upordown_lock);
	if (nfs_server_upordown == NFS_SERVER_RUNNING) {
		nfs_server_upordown = NFS_SERVER_OFFLINE;
	}
	mutex_exit(&nfs_server_upordown_lock);
}

/*
 * Will be called at the point the server pool is being destroyed so
 * all transports have been closed and no service threads are in
 * existence.
 *
 * If we quiesce the server, we're shutting it down without destroying the
 * server state. This allows it to warm start subsequently.
 */
void
nfs_srv_stop_all(void)
{
	int quiesce = 0;
	nfs_srv_shutdown_all(quiesce);
}

/*
 * This alternative shutdown routine can be requested via nfssys()
 */
void
nfs_srv_quiesce_all(void)
{
	int quiesce = 1;
	nfs_srv_shutdown_all(quiesce);
}

static void
nfs_srv_shutdown_all(int quiesce) {
	mutex_enter(&nfs_server_upordown_lock);
	if (quiesce) {
		if (nfs_server_upordown == NFS_SERVER_RUNNING ||
			nfs_server_upordown == NFS_SERVER_OFFLINE) {
			nfs_server_upordown = NFS_SERVER_QUIESCED;
			cv_signal(&nfs_server_upordown_cv);

			/* reset DSS state, for subsequent warm restart */
			rfs4_dss_numnewpaths = 0;
			rfs4_dss_newpaths = NULL;

			cmn_err(CE_NOTE, "nfs_server: server is now quiesced; "
			    "NFSv4 state has been preserved");
		}
	} else {
		if (nfs_server_upordown == NFS_SERVER_OFFLINE) {
			nfs_server_upordown = NFS_SERVER_STOPPING;
			mutex_exit(&nfs_server_upordown_lock);
			rfs4_state_fini();
			rfs4_fini_drc(nfs4_drc);
			mutex_enter(&nfs_server_upordown_lock);
			nfs_server_upordown = NFS_SERVER_STOPPED;
			cv_signal(&nfs_server_upordown_cv);
		}
	}
	mutex_exit(&nfs_server_upordown_lock);
}

static int
nfs_srv_set_sc_versions(struct file *fp, SVC_CALLOUT_TABLE **sctpp,
			rpcvers_t versmin, rpcvers_t versmax)
{
	struct strioctl strioc;
	struct T_info_ack tinfo;
	int		error, retval;

	/*
	 * Find out what type of transport this is.
	 */
	strioc.ic_cmd = TI_GETINFO;
	strioc.ic_timout = -1;
	strioc.ic_len = sizeof (tinfo);
	strioc.ic_dp = (char *)&tinfo;
	tinfo.PRIM_type = T_INFO_REQ;

	error = strioctl(fp->f_vnode, I_STR, (intptr_t)&strioc, 0, K_TO_K,
	    CRED(), &retval);
	if (error || retval)
		return (error);

	/*
	 * Based on our query of the transport type...
	 *
	 * Reset the min/max versions based on the caller's request
	 * NOTE: This assumes that NFS_PROGRAM is first in the array!!
	 * And the second entry is the NFS_ACL_PROGRAM.
	 */
	switch (tinfo.SERV_type) {
	case T_CLTS:
		if (versmax == NFS_V4)
			return (EINVAL);
		__nfs_sc_clts[0].sc_versmin = versmin;
		__nfs_sc_clts[0].sc_versmax = versmax;
		__nfs_sc_clts[1].sc_versmin = versmin;
		__nfs_sc_clts[1].sc_versmax = versmax;
		*sctpp = &nfs_sct_clts;
		break;
	case T_COTS:
	case T_COTS_ORD:
		__nfs_sc_cots[0].sc_versmin = versmin;
		__nfs_sc_cots[0].sc_versmax = versmax;
		/* For the NFS_ACL program, check the max version */
		if (versmax > NFS_ACL_VERSMAX)
			versmax = NFS_ACL_VERSMAX;
		__nfs_sc_cots[1].sc_versmin = versmin;
		__nfs_sc_cots[1].sc_versmax = versmax;
		*sctpp = &nfs_sct_cots;
		break;
	default:
		error = EINVAL;
	}

	return (error);
}

/*
 * NFS Server system call.
 * Does all of the work of running a NFS server.
 * uap->fd is the fd of an open transport provider
 */
int
nfs_svc(struct nfs_svc_args *arg, model_t model)
{
	file_t *fp;
	SVCMASTERXPRT *xprt;
	int error;
	int readsize;
	char buf[KNC_STRSIZE];
	size_t len;
	STRUCT_HANDLE(nfs_svc_args, uap);
	struct netbuf addrmask;
	SVC_CALLOUT_TABLE *sctp = NULL;

#ifdef lint
	model = model;		/* STRUCT macros don't always refer to it */
#endif

	STRUCT_SET_HANDLE(uap, model, arg);

	/* Check privileges in nfssys() */

	if ((fp = getf(STRUCT_FGET(uap, fd))) == NULL)
		return (EBADF);

	/*
	 * Set read buffer size to rsize
	 * and add room for RPC headers.
	 */
	readsize = nfs3tsize() + (RPC_MAXDATASIZE - NFS_MAXDATA);
	if (readsize < RPC_MAXDATASIZE)
		readsize = RPC_MAXDATASIZE;

	error = copyinstr((const char *)STRUCT_FGETP(uap, netid), buf,
	    KNC_STRSIZE, &len);
	if (error) {
		releasef(STRUCT_FGET(uap, fd));
		return (error);
	}

	addrmask.len = STRUCT_FGET(uap, addrmask.len);
	addrmask.maxlen = STRUCT_FGET(uap, addrmask.maxlen);
	addrmask.buf = kmem_alloc(addrmask.maxlen, KM_SLEEP);
	error = copyin(STRUCT_FGETP(uap, addrmask.buf), addrmask.buf,
	    addrmask.len);
	if (error) {
		releasef(STRUCT_FGET(uap, fd));
		kmem_free(addrmask.buf, addrmask.maxlen);
		return (error);
	}

	nfs_versmin = STRUCT_FGET(uap, versmin);
	nfs_versmax = STRUCT_FGET(uap, versmax);

	/* Double check the vers min/max ranges */
	if ((nfs_versmin > nfs_versmax) ||
	    (nfs_versmin < NFS_VERSMIN) ||
	    (nfs_versmax > NFS_VERSMAX)) {
		nfs_versmin = NFS_VERSMIN_DEFAULT;
		nfs_versmax = NFS_VERSMAX_DEFAULT;
	}

	if (error =
	    nfs_srv_set_sc_versions(fp, &sctp, nfs_versmin, nfs_versmax)) {
		releasef(STRUCT_FGET(uap, fd));
		kmem_free(addrmask.buf, addrmask.maxlen);
		return (error);
	}

	/* Initialize nfsv4 server */
	if (nfs_versmax == (rpcvers_t)NFS_V4)
		rfs4_server_start(STRUCT_FGET(uap, delegation));

	/* Create a transport handle. */
	error = svc_tli_kcreate(fp, readsize, buf, &addrmask, &xprt,
	    sctp, NULL, NFS_SVCPOOL_ID, TRUE);

	if (error)
		kmem_free(addrmask.buf, addrmask.maxlen);

	releasef(STRUCT_FGET(uap, fd));

	/* HA-NFSv4: save the cluster nodeid */
	if (cluster_bootflags & CLUSTER_BOOTED)
		lm_global_nlmid = clconf_get_nodeid();

	return (error);
}

static void
rfs4_server_start(int nfs4_srv_delegation)
{
	/*
	 * Determine if the server has previously been "started" and
	 * if not, do the per instance initialization
	 */
	mutex_enter(&nfs_server_upordown_lock);

	if (nfs_server_upordown != NFS_SERVER_RUNNING) {
		/* Do we need to stop and wait on the previous server? */
		while (nfs_server_upordown == NFS_SERVER_STOPPING ||
		    nfs_server_upordown == NFS_SERVER_OFFLINE)
			cv_wait(&nfs_server_upordown_cv,
			    &nfs_server_upordown_lock);

		if (nfs_server_upordown != NFS_SERVER_RUNNING) {
			(void) svc_pool_control(NFS_SVCPOOL_ID,
			    SVCPSET_UNREGISTER_PROC, (void *)&nfs_srv_offline);
			(void) svc_pool_control(NFS_SVCPOOL_ID,
			    SVCPSET_SHUTDOWN_PROC, (void *)&nfs_srv_stop_all);

			/* is this an nfsd warm start? */
			if (nfs_server_upordown == NFS_SERVER_QUIESCED) {
				cmn_err(CE_NOTE, "nfs_server: "
				    "server was previously quiesced; "
				    "existing NFSv4 state will be re-used");

				/*
				 * HA-NFSv4: this is also the signal
				 * that a Resource Group failover has
				 * occurred.
				 */
				if (cluster_bootflags & CLUSTER_BOOTED)
					hanfsv4_failover();
			} else {
				/* cold start */
				rfs4_state_init();
				nfs4_drc = rfs4_init_drc(nfs4_drc_max,
				    nfs4_drc_hash);
			}

			/*
			 * Check to see if delegation is to be
			 * enabled at the server
			 */
			if (nfs4_srv_delegation != FALSE)
				rfs4_set_deleg_policy(SRV_NORMAL_DELEGATE);

			nfs_server_upordown = NFS_SERVER_RUNNING;
		}
		cv_signal(&nfs_server_upordown_cv);
	}
	mutex_exit(&nfs_server_upordown_lock);
}

/*
 * If RDMA device available,
 * start RDMA listener.
 */
int
rdma_start(struct rdma_svc_args *rsa)
{
	int error;
	rdma_xprt_group_t started_rdma_xprts;
	rdma_stat stat;
	int svc_state = 0;

	/* Double check the vers min/max ranges */
	if ((rsa->nfs_versmin > rsa->nfs_versmax) ||
	    (rsa->nfs_versmin < NFS_VERSMIN) ||
	    (rsa->nfs_versmax > NFS_VERSMAX)) {
		rsa->nfs_versmin = NFS_VERSMIN_DEFAULT;
		rsa->nfs_versmax = NFS_VERSMAX_DEFAULT;
	}
	nfs_versmin = rsa->nfs_versmin;
	nfs_versmax = rsa->nfs_versmax;

	/* Set the versions in the callout table */
	__nfs_sc_rdma[0].sc_versmin = rsa->nfs_versmin;
	__nfs_sc_rdma[0].sc_versmax = rsa->nfs_versmax;
	/* For the NFS_ACL program, check the max version */
	__nfs_sc_rdma[1].sc_versmin = rsa->nfs_versmin;
	if (rsa->nfs_versmax > NFS_ACL_VERSMAX)
		__nfs_sc_rdma[1].sc_versmax = NFS_ACL_VERSMAX;
	else
		__nfs_sc_rdma[1].sc_versmax = rsa->nfs_versmax;

	/* Initialize nfsv4 server */
	if (rsa->nfs_versmax == (rpcvers_t)NFS_V4)
		rfs4_server_start(rsa->delegation);

	started_rdma_xprts.rtg_count = 0;
	started_rdma_xprts.rtg_listhead = NULL;
	started_rdma_xprts.rtg_poolid = rsa->poolid;

restart:
	error = svc_rdma_kcreate(rsa->netid, &nfs_sct_rdma, rsa->poolid,
	    &started_rdma_xprts);

	svc_state = !error;

	while (!error) {

		/*
		 * wait till either interrupted by a signal on
		 * nfs service stop/restart or signalled by a
		 * rdma plugin attach/detatch.
		 */

		stat = rdma_kwait();

		/*
		 * stop services if running -- either on a HCA detach event
		 * or if the nfs service is stopped/restarted.
		 */

		if ((stat == RDMA_HCA_DETACH || stat == RDMA_INTR) &&
		    svc_state) {
			rdma_stop(&started_rdma_xprts);
			svc_state = 0;
		}

		/*
		 * nfs service stop/restart, break out of the
		 * wait loop and return;
		 */
		if (stat == RDMA_INTR)
			return (0);

		/*
		 * restart stopped services on a HCA attach event
		 * (if not already running)
		 */

		if ((stat == RDMA_HCA_ATTACH) && (svc_state == 0))
			goto restart;

		/*
		 * loop until a nfs service stop/restart
		 */
	}

	return (error);
}

/* ARGSUSED */
void
rpc_null(caddr_t *argp, caddr_t *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
}

/* ARGSUSED */
void
rpc_null_v3(caddr_t *argp, caddr_t *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	DTRACE_NFSV3_3(op__null__start, struct svc_req *, req,
	    cred_t *, cr, vnode_t *, NULL);
	DTRACE_NFSV3_3(op__null__done, struct svc_req *, req,
	    cred_t *, cr, vnode_t *, NULL);
}

/* ARGSUSED */
static void
rfs_error(caddr_t *argp, caddr_t *resp, struct exportinfo *exi,
    struct svc_req *req, cred_t *cr, bool_t ro)
{
	/* return (EOPNOTSUPP); */
}

static void
nullfree(void)
{
}

static char *rfscallnames_v2[] = {
	"RFS2_NULL",
	"RFS2_GETATTR",
	"RFS2_SETATTR",
	"RFS2_ROOT",
	"RFS2_LOOKUP",
	"RFS2_READLINK",
	"RFS2_READ",
	"RFS2_WRITECACHE",
	"RFS2_WRITE",
	"RFS2_CREATE",
	"RFS2_REMOVE",
	"RFS2_RENAME",
	"RFS2_LINK",
	"RFS2_SYMLINK",
	"RFS2_MKDIR",
	"RFS2_RMDIR",
	"RFS2_READDIR",
	"RFS2_STATFS"
};

static struct rpcdisp rfsdisptab_v2[] = {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */
	{rpc_null,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* RFS_GETATTR = 1 */
	{rfs_getattr,
	    xdr_fhandle, xdr_fastfhandle, sizeof (fhandle_t),
	    xdr_attrstat, xdr_fastattrstat, sizeof (struct nfsattrstat),
	    nullfree, RPC_IDEMPOTENT|RPC_ALLOWANON|RPC_MAPRESP,
	    rfs_getattr_getfh},

	/* RFS_SETATTR = 2 */
	{rfs_setattr,
	    xdr_saargs, NULL_xdrproc_t, sizeof (struct nfssaargs),
	    xdr_attrstat, xdr_fastattrstat, sizeof (struct nfsattrstat),
	    nullfree, RPC_MAPRESP,
	    rfs_setattr_getfh},

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */
	{rfs_error,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* RFS_LOOKUP = 4 */
	{rfs_lookup,
	    xdr_diropargs, NULL_xdrproc_t, sizeof (struct nfsdiropargs),
	    xdr_diropres, xdr_fastdiropres, sizeof (struct nfsdiropres),
	    nullfree, RPC_IDEMPOTENT|RPC_MAPRESP|RPC_PUBLICFH_OK,
	    rfs_lookup_getfh},

	/* RFS_READLINK = 5 */
	{rfs_readlink,
	    xdr_fhandle, xdr_fastfhandle, sizeof (fhandle_t),
	    xdr_rdlnres, NULL_xdrproc_t, sizeof (struct nfsrdlnres),
	    rfs_rlfree, RPC_IDEMPOTENT,
	    rfs_readlink_getfh},

	/* RFS_READ = 6 */
	{rfs_read,
	    xdr_readargs, NULL_xdrproc_t, sizeof (struct nfsreadargs),
	    xdr_rdresult, NULL_xdrproc_t, sizeof (struct nfsrdresult),
	    rfs_rdfree, RPC_IDEMPOTENT,
	    rfs_read_getfh},

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */
	{rfs_error,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* RFS_WRITE = 8 */
	{rfs_write,
	    xdr_writeargs, NULL_xdrproc_t, sizeof (struct nfswriteargs),
	    xdr_attrstat, xdr_fastattrstat, sizeof (struct nfsattrstat),
	    nullfree, RPC_MAPRESP,
	    rfs_write_getfh},

	/* RFS_CREATE = 9 */
	{rfs_create,
	    xdr_creatargs, NULL_xdrproc_t, sizeof (struct nfscreatargs),
	    xdr_diropres, xdr_fastdiropres, sizeof (struct nfsdiropres),
	    nullfree, RPC_MAPRESP,
	    rfs_create_getfh},

	/* RFS_REMOVE = 10 */
	{rfs_remove,
	    xdr_diropargs, NULL_xdrproc_t, sizeof (struct nfsdiropargs),
#ifdef _LITTLE_ENDIAN
	    xdr_enum, xdr_fastenum, sizeof (enum nfsstat),
#else
	    xdr_enum, NULL_xdrproc_t, sizeof (enum nfsstat),
#endif
	    nullfree, RPC_MAPRESP,
	    rfs_remove_getfh},

	/* RFS_RENAME = 11 */
	{rfs_rename,
	    xdr_rnmargs, NULL_xdrproc_t, sizeof (struct nfsrnmargs),
#ifdef _LITTLE_ENDIAN
	    xdr_enum, xdr_fastenum, sizeof (enum nfsstat),
#else
	    xdr_enum, NULL_xdrproc_t, sizeof (enum nfsstat),
#endif
	    nullfree, RPC_MAPRESP,
	    rfs_rename_getfh},

	/* RFS_LINK = 12 */
	{rfs_link,
	    xdr_linkargs, NULL_xdrproc_t, sizeof (struct nfslinkargs),
#ifdef _LITTLE_ENDIAN
	    xdr_enum, xdr_fastenum, sizeof (enum nfsstat),
#else
	    xdr_enum, NULL_xdrproc_t, sizeof (enum nfsstat),
#endif
	    nullfree, RPC_MAPRESP,
	    rfs_link_getfh},

	/* RFS_SYMLINK = 13 */
	{rfs_symlink,
	    xdr_slargs, NULL_xdrproc_t, sizeof (struct nfsslargs),
#ifdef _LITTLE_ENDIAN
	    xdr_enum, xdr_fastenum, sizeof (enum nfsstat),
#else
	    xdr_enum, NULL_xdrproc_t, sizeof (enum nfsstat),
#endif
	    nullfree, RPC_MAPRESP,
	    rfs_symlink_getfh},

	/* RFS_MKDIR = 14 */
	{rfs_mkdir,
	    xdr_creatargs, NULL_xdrproc_t, sizeof (struct nfscreatargs),
	    xdr_diropres, xdr_fastdiropres, sizeof (struct nfsdiropres),
	    nullfree, RPC_MAPRESP,
	    rfs_mkdir_getfh},

	/* RFS_RMDIR = 15 */
	{rfs_rmdir,
	    xdr_diropargs, NULL_xdrproc_t, sizeof (struct nfsdiropargs),
#ifdef _LITTLE_ENDIAN
	    xdr_enum, xdr_fastenum, sizeof (enum nfsstat),
#else
	    xdr_enum, NULL_xdrproc_t, sizeof (enum nfsstat),
#endif
	    nullfree, RPC_MAPRESP,
	    rfs_rmdir_getfh},

	/* RFS_READDIR = 16 */
	{rfs_readdir,
	    xdr_rddirargs, NULL_xdrproc_t, sizeof (struct nfsrddirargs),
	    xdr_putrddirres, NULL_xdrproc_t, sizeof (struct nfsrddirres),
	    rfs_rddirfree, RPC_IDEMPOTENT,
	    rfs_readdir_getfh},

	/* RFS_STATFS = 17 */
	{rfs_statfs,
	    xdr_fhandle, xdr_fastfhandle, sizeof (fhandle_t),
	    xdr_statfs, xdr_faststatfs, sizeof (struct nfsstatfs),
	    nullfree, RPC_IDEMPOTENT|RPC_ALLOWANON|RPC_MAPRESP,
	    rfs_statfs_getfh},
};

static char *rfscallnames_v3[] = {
	"RFS3_NULL",
	"RFS3_GETATTR",
	"RFS3_SETATTR",
	"RFS3_LOOKUP",
	"RFS3_ACCESS",
	"RFS3_READLINK",
	"RFS3_READ",
	"RFS3_WRITE",
	"RFS3_CREATE",
	"RFS3_MKDIR",
	"RFS3_SYMLINK",
	"RFS3_MKNOD",
	"RFS3_REMOVE",
	"RFS3_RMDIR",
	"RFS3_RENAME",
	"RFS3_LINK",
	"RFS3_READDIR",
	"RFS3_READDIRPLUS",
	"RFS3_FSSTAT",
	"RFS3_FSINFO",
	"RFS3_PATHCONF",
	"RFS3_COMMIT"
};

static struct rpcdisp rfsdisptab_v3[] = {
	/*
	 * NFS VERSION 3
	 */

	/* RFS_NULL = 0 */
	{rpc_null_v3,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* RFS3_GETATTR = 1 */
	{rfs3_getattr,
	    xdr_nfs_fh3_server, NULL_xdrproc_t, sizeof (GETATTR3args),
	    xdr_GETATTR3res, NULL_xdrproc_t, sizeof (GETATTR3res),
	    nullfree, (RPC_IDEMPOTENT | RPC_ALLOWANON),
	    rfs3_getattr_getfh},

	/* RFS3_SETATTR = 2 */
	{rfs3_setattr,
	    xdr_SETATTR3args, NULL_xdrproc_t, sizeof (SETATTR3args),
	    xdr_SETATTR3res, NULL_xdrproc_t, sizeof (SETATTR3res),
	    nullfree, 0,
	    rfs3_setattr_getfh},

	/* RFS3_LOOKUP = 3 */
	{rfs3_lookup,
	    xdr_diropargs3, NULL_xdrproc_t, sizeof (LOOKUP3args),
	    xdr_LOOKUP3res, NULL_xdrproc_t, sizeof (LOOKUP3res),
	    nullfree, (RPC_IDEMPOTENT | RPC_PUBLICFH_OK),
	    rfs3_lookup_getfh},

	/* RFS3_ACCESS = 4 */
	{rfs3_access,
	    xdr_ACCESS3args, NULL_xdrproc_t, sizeof (ACCESS3args),
	    xdr_ACCESS3res, NULL_xdrproc_t, sizeof (ACCESS3res),
	    nullfree, RPC_IDEMPOTENT,
	    rfs3_access_getfh},

	/* RFS3_READLINK = 5 */
	{rfs3_readlink,
	    xdr_nfs_fh3_server, NULL_xdrproc_t, sizeof (READLINK3args),
	    xdr_READLINK3res, NULL_xdrproc_t, sizeof (READLINK3res),
	    rfs3_readlink_free, RPC_IDEMPOTENT,
	    rfs3_readlink_getfh},

	/* RFS3_READ = 6 */
	{rfs3_read,
	    xdr_READ3args, NULL_xdrproc_t, sizeof (READ3args),
	    xdr_READ3res, NULL_xdrproc_t, sizeof (READ3res),
	    rfs3_read_free, RPC_IDEMPOTENT,
	    rfs3_read_getfh},

	/* RFS3_WRITE = 7 */
	{rfs3_write,
	    xdr_WRITE3args, NULL_xdrproc_t, sizeof (WRITE3args),
	    xdr_WRITE3res, NULL_xdrproc_t, sizeof (WRITE3res),
	    nullfree, 0,
	    rfs3_write_getfh},

	/* RFS3_CREATE = 8 */
	{rfs3_create,
	    xdr_CREATE3args, NULL_xdrproc_t, sizeof (CREATE3args),
	    xdr_CREATE3res, NULL_xdrproc_t, sizeof (CREATE3res),
	    nullfree, 0,
	    rfs3_create_getfh},

	/* RFS3_MKDIR = 9 */
	{rfs3_mkdir,
	    xdr_MKDIR3args, NULL_xdrproc_t, sizeof (MKDIR3args),
	    xdr_MKDIR3res, NULL_xdrproc_t, sizeof (MKDIR3res),
	    nullfree, 0,
	    rfs3_mkdir_getfh},

	/* RFS3_SYMLINK = 10 */
	{rfs3_symlink,
	    xdr_SYMLINK3args, NULL_xdrproc_t, sizeof (SYMLINK3args),
	    xdr_SYMLINK3res, NULL_xdrproc_t, sizeof (SYMLINK3res),
	    nullfree, 0,
	    rfs3_symlink_getfh},

	/* RFS3_MKNOD = 11 */
	{rfs3_mknod,
	    xdr_MKNOD3args, NULL_xdrproc_t, sizeof (MKNOD3args),
	    xdr_MKNOD3res, NULL_xdrproc_t, sizeof (MKNOD3res),
	    nullfree, 0,
	    rfs3_mknod_getfh},

	/* RFS3_REMOVE = 12 */
	{rfs3_remove,
	    xdr_diropargs3, NULL_xdrproc_t, sizeof (REMOVE3args),
	    xdr_REMOVE3res, NULL_xdrproc_t, sizeof (REMOVE3res),
	    nullfree, 0,
	    rfs3_remove_getfh},

	/* RFS3_RMDIR = 13 */
	{rfs3_rmdir,
	    xdr_diropargs3, NULL_xdrproc_t, sizeof (RMDIR3args),
	    xdr_RMDIR3res, NULL_xdrproc_t, sizeof (RMDIR3res),
	    nullfree, 0,
	    rfs3_rmdir_getfh},

	/* RFS3_RENAME = 14 */
	{rfs3_rename,
	    xdr_RENAME3args, NULL_xdrproc_t, sizeof (RENAME3args),
	    xdr_RENAME3res, NULL_xdrproc_t, sizeof (RENAME3res),
	    nullfree, 0,
	    rfs3_rename_getfh},

	/* RFS3_LINK = 15 */
	{rfs3_link,
	    xdr_LINK3args, NULL_xdrproc_t, sizeof (LINK3args),
	    xdr_LINK3res, NULL_xdrproc_t, sizeof (LINK3res),
	    nullfree, 0,
	    rfs3_link_getfh},

	/* RFS3_READDIR = 16 */
	{rfs3_readdir,
	    xdr_READDIR3args, NULL_xdrproc_t, sizeof (READDIR3args),
	    xdr_READDIR3res, NULL_xdrproc_t, sizeof (READDIR3res),
	    rfs3_readdir_free, RPC_IDEMPOTENT,
	    rfs3_readdir_getfh},

	/* RFS3_READDIRPLUS = 17 */
	{rfs3_readdirplus,
	    xdr_READDIRPLUS3args, NULL_xdrproc_t, sizeof (READDIRPLUS3args),
	    xdr_READDIRPLUS3res, NULL_xdrproc_t, sizeof (READDIRPLUS3res),
	    rfs3_readdirplus_free, RPC_AVOIDWORK,
	    rfs3_readdirplus_getfh},

	/* RFS3_FSSTAT = 18 */
	{rfs3_fsstat,
	    xdr_nfs_fh3_server, NULL_xdrproc_t, sizeof (FSSTAT3args),
	    xdr_FSSTAT3res, NULL_xdrproc_t, sizeof (FSSTAT3res),
	    nullfree, RPC_IDEMPOTENT,
	    rfs3_fsstat_getfh},

	/* RFS3_FSINFO = 19 */
	{rfs3_fsinfo,
	    xdr_nfs_fh3_server, NULL_xdrproc_t, sizeof (FSINFO3args),
	    xdr_FSINFO3res, NULL_xdrproc_t, sizeof (FSINFO3res),
	    nullfree, RPC_IDEMPOTENT|RPC_ALLOWANON,
	    rfs3_fsinfo_getfh},

	/* RFS3_PATHCONF = 20 */
	{rfs3_pathconf,
	    xdr_nfs_fh3_server, NULL_xdrproc_t, sizeof (PATHCONF3args),
	    xdr_PATHCONF3res, NULL_xdrproc_t, sizeof (PATHCONF3res),
	    nullfree, RPC_IDEMPOTENT,
	    rfs3_pathconf_getfh},

	/* RFS3_COMMIT = 21 */
	{rfs3_commit,
	    xdr_COMMIT3args, NULL_xdrproc_t, sizeof (COMMIT3args),
	    xdr_COMMIT3res, NULL_xdrproc_t, sizeof (COMMIT3res),
	    nullfree, RPC_IDEMPOTENT,
	    rfs3_commit_getfh},
};

static char *rfscallnames_v4[] = {
	"RFS4_NULL",
	"RFS4_COMPOUND",
	"RFS4_NULL",
	"RFS4_NULL",
	"RFS4_NULL",
	"RFS4_NULL",
	"RFS4_NULL",
	"RFS4_NULL",
	"RFS4_CREATE"
};

static struct rpcdisp rfsdisptab_v4[] = {
	/*
	 * NFS VERSION 4
	 */

	/* RFS_NULL = 0 */
	{rpc_null,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT, 0},

	/* RFS4_compound = 1 */
	{rfs4_compound,
	    xdr_COMPOUND4args_srv, NULL_xdrproc_t, sizeof (COMPOUND4args),
	    xdr_COMPOUND4res_srv, NULL_xdrproc_t, sizeof (COMPOUND4res),
	    rfs4_compound_free, 0, 0},
};

union rfs_args {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */

	/* RFS_GETATTR = 1 */
	fhandle_t nfs2_getattr_args;

	/* RFS_SETATTR = 2 */
	struct nfssaargs nfs2_setattr_args;

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */

	/* RFS_LOOKUP = 4 */
	struct nfsdiropargs nfs2_lookup_args;

	/* RFS_READLINK = 5 */
	fhandle_t nfs2_readlink_args;

	/* RFS_READ = 6 */
	struct nfsreadargs nfs2_read_args;

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */

	/* RFS_WRITE = 8 */
	struct nfswriteargs nfs2_write_args;

	/* RFS_CREATE = 9 */
	struct nfscreatargs nfs2_create_args;

	/* RFS_REMOVE = 10 */
	struct nfsdiropargs nfs2_remove_args;

	/* RFS_RENAME = 11 */
	struct nfsrnmargs nfs2_rename_args;

	/* RFS_LINK = 12 */
	struct nfslinkargs nfs2_link_args;

	/* RFS_SYMLINK = 13 */
	struct nfsslargs nfs2_symlink_args;

	/* RFS_MKDIR = 14 */
	struct nfscreatargs nfs2_mkdir_args;

	/* RFS_RMDIR = 15 */
	struct nfsdiropargs nfs2_rmdir_args;

	/* RFS_READDIR = 16 */
	struct nfsrddirargs nfs2_readdir_args;

	/* RFS_STATFS = 17 */
	fhandle_t nfs2_statfs_args;

	/*
	 * NFS VERSION 3
	 */

	/* RFS_NULL = 0 */

	/* RFS3_GETATTR = 1 */
	GETATTR3args nfs3_getattr_args;

	/* RFS3_SETATTR = 2 */
	SETATTR3args nfs3_setattr_args;

	/* RFS3_LOOKUP = 3 */
	LOOKUP3args nfs3_lookup_args;

	/* RFS3_ACCESS = 4 */
	ACCESS3args nfs3_access_args;

	/* RFS3_READLINK = 5 */
	READLINK3args nfs3_readlink_args;

	/* RFS3_READ = 6 */
	READ3args nfs3_read_args;

	/* RFS3_WRITE = 7 */
	WRITE3args nfs3_write_args;

	/* RFS3_CREATE = 8 */
	CREATE3args nfs3_create_args;

	/* RFS3_MKDIR = 9 */
	MKDIR3args nfs3_mkdir_args;

	/* RFS3_SYMLINK = 10 */
	SYMLINK3args nfs3_symlink_args;

	/* RFS3_MKNOD = 11 */
	MKNOD3args nfs3_mknod_args;

	/* RFS3_REMOVE = 12 */
	REMOVE3args nfs3_remove_args;

	/* RFS3_RMDIR = 13 */
	RMDIR3args nfs3_rmdir_args;

	/* RFS3_RENAME = 14 */
	RENAME3args nfs3_rename_args;

	/* RFS3_LINK = 15 */
	LINK3args nfs3_link_args;

	/* RFS3_READDIR = 16 */
	READDIR3args nfs3_readdir_args;

	/* RFS3_READDIRPLUS = 17 */
	READDIRPLUS3args nfs3_readdirplus_args;

	/* RFS3_FSSTAT = 18 */
	FSSTAT3args nfs3_fsstat_args;

	/* RFS3_FSINFO = 19 */
	FSINFO3args nfs3_fsinfo_args;

	/* RFS3_PATHCONF = 20 */
	PATHCONF3args nfs3_pathconf_args;

	/* RFS3_COMMIT = 21 */
	COMMIT3args nfs3_commit_args;

	/*
	 * NFS VERSION 4
	 */

	/* RFS_NULL = 0 */

	/* COMPUND = 1 */
	COMPOUND4args nfs4_compound_args;
};

union rfs_res {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */

	/* RFS_GETATTR = 1 */
	struct nfsattrstat nfs2_getattr_res;

	/* RFS_SETATTR = 2 */
	struct nfsattrstat nfs2_setattr_res;

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */

	/* RFS_LOOKUP = 4 */
	struct nfsdiropres nfs2_lookup_res;

	/* RFS_READLINK = 5 */
	struct nfsrdlnres nfs2_readlink_res;

	/* RFS_READ = 6 */
	struct nfsrdresult nfs2_read_res;

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */

	/* RFS_WRITE = 8 */
	struct nfsattrstat nfs2_write_res;

	/* RFS_CREATE = 9 */
	struct nfsdiropres nfs2_create_res;

	/* RFS_REMOVE = 10 */
	enum nfsstat nfs2_remove_res;

	/* RFS_RENAME = 11 */
	enum nfsstat nfs2_rename_res;

	/* RFS_LINK = 12 */
	enum nfsstat nfs2_link_res;

	/* RFS_SYMLINK = 13 */
	enum nfsstat nfs2_symlink_res;

	/* RFS_MKDIR = 14 */
	struct nfsdiropres nfs2_mkdir_res;

	/* RFS_RMDIR = 15 */
	enum nfsstat nfs2_rmdir_res;

	/* RFS_READDIR = 16 */
	struct nfsrddirres nfs2_readdir_res;

	/* RFS_STATFS = 17 */
	struct nfsstatfs nfs2_statfs_res;

	/*
	 * NFS VERSION 3
	 */

	/* RFS_NULL = 0 */

	/* RFS3_GETATTR = 1 */
	GETATTR3res nfs3_getattr_res;

	/* RFS3_SETATTR = 2 */
	SETATTR3res nfs3_setattr_res;

	/* RFS3_LOOKUP = 3 */
	LOOKUP3res nfs3_lookup_res;

	/* RFS3_ACCESS = 4 */
	ACCESS3res nfs3_access_res;

	/* RFS3_READLINK = 5 */
	READLINK3res nfs3_readlink_res;

	/* RFS3_READ = 6 */
	READ3res nfs3_read_res;

	/* RFS3_WRITE = 7 */
	WRITE3res nfs3_write_res;

	/* RFS3_CREATE = 8 */
	CREATE3res nfs3_create_res;

	/* RFS3_MKDIR = 9 */
	MKDIR3res nfs3_mkdir_res;

	/* RFS3_SYMLINK = 10 */
	SYMLINK3res nfs3_symlink_res;

	/* RFS3_MKNOD = 11 */
	MKNOD3res nfs3_mknod_res;

	/* RFS3_REMOVE = 12 */
	REMOVE3res nfs3_remove_res;

	/* RFS3_RMDIR = 13 */
	RMDIR3res nfs3_rmdir_res;

	/* RFS3_RENAME = 14 */
	RENAME3res nfs3_rename_res;

	/* RFS3_LINK = 15 */
	LINK3res nfs3_link_res;

	/* RFS3_READDIR = 16 */
	READDIR3res nfs3_readdir_res;

	/* RFS3_READDIRPLUS = 17 */
	READDIRPLUS3res nfs3_readdirplus_res;

	/* RFS3_FSSTAT = 18 */
	FSSTAT3res nfs3_fsstat_res;

	/* RFS3_FSINFO = 19 */
	FSINFO3res nfs3_fsinfo_res;

	/* RFS3_PATHCONF = 20 */
	PATHCONF3res nfs3_pathconf_res;

	/* RFS3_COMMIT = 21 */
	COMMIT3res nfs3_commit_res;

	/*
	 * NFS VERSION 4
	 */

	/* RFS_NULL = 0 */

	/* RFS4_COMPOUND = 1 */
	COMPOUND4res nfs4_compound_res;

};

static struct rpc_disptable rfs_disptable[] = {
	{sizeof (rfsdisptab_v2) / sizeof (rfsdisptab_v2[0]),
	    rfscallnames_v2,
	    &rfsproccnt_v2_ptr, &rfsprocio_v2_ptr, rfsdisptab_v2},
	{sizeof (rfsdisptab_v3) / sizeof (rfsdisptab_v3[0]),
	    rfscallnames_v3,
	    &rfsproccnt_v3_ptr, &rfsprocio_v3_ptr, rfsdisptab_v3},
	{sizeof (rfsdisptab_v4) / sizeof (rfsdisptab_v4[0]),
	    rfscallnames_v4,
	    &rfsproccnt_v4_ptr, &rfsprocio_v4_ptr, rfsdisptab_v4},
};

/*
 * If nfs_portmon is set, then clients are required to use privileged
 * ports (ports < IPPORT_RESERVED) in order to get NFS services.
 *
 * N.B.: this attempt to carry forward the already ill-conceived notion
 * of privileged ports for TCP/UDP is really quite ineffectual.  Not only
 * is it transport-dependent, it's laughably easy to spoof.  If you're
 * really interested in security, you must start with secure RPC instead.
 */
static int nfs_portmon = 0;

#ifdef DEBUG
static int cred_hits = 0;
static int cred_misses = 0;
#endif


#ifdef DEBUG
/*
 * Debug code to allow disabling of rfs_dispatch() use of
 * fastxdrargs() and fastxdrres() calls for testing purposes.
 */
static int rfs_no_fast_xdrargs = 0;
static int rfs_no_fast_xdrres = 0;
#endif

union acl_args {
	/*
	 * ACL VERSION 2
	 */

	/* ACL2_NULL = 0 */

	/* ACL2_GETACL = 1 */
	GETACL2args acl2_getacl_args;

	/* ACL2_SETACL = 2 */
	SETACL2args acl2_setacl_args;

	/* ACL2_GETATTR = 3 */
	GETATTR2args acl2_getattr_args;

	/* ACL2_ACCESS = 4 */
	ACCESS2args acl2_access_args;

	/* ACL2_GETXATTRDIR = 5 */
	GETXATTRDIR2args acl2_getxattrdir_args;

	/*
	 * ACL VERSION 3
	 */

	/* ACL3_NULL = 0 */

	/* ACL3_GETACL = 1 */
	GETACL3args acl3_getacl_args;

	/* ACL3_SETACL = 2 */
	SETACL3args acl3_setacl;

	/* ACL3_GETXATTRDIR = 3 */
	GETXATTRDIR3args acl3_getxattrdir_args;

};

union acl_res {
	/*
	 * ACL VERSION 2
	 */

	/* ACL2_NULL = 0 */

	/* ACL2_GETACL = 1 */
	GETACL2res acl2_getacl_res;

	/* ACL2_SETACL = 2 */
	SETACL2res acl2_setacl_res;

	/* ACL2_GETATTR = 3 */
	GETATTR2res acl2_getattr_res;

	/* ACL2_ACCESS = 4 */
	ACCESS2res acl2_access_res;

	/* ACL2_GETXATTRDIR = 5 */
	GETXATTRDIR2args acl2_getxattrdir_res;

	/*
	 * ACL VERSION 3
	 */

	/* ACL3_NULL = 0 */

	/* ACL3_GETACL = 1 */
	GETACL3res acl3_getacl_res;

	/* ACL3_SETACL = 2 */
	SETACL3res acl3_setacl_res;

	/* ACL3_GETXATTRDIR = 3 */
	GETXATTRDIR3res acl3_getxattrdir_res;

};

static bool_t
auth_tooweak(struct svc_req *req, char *res)
{

	if (req->rq_vers == NFS_VERSION && req->rq_proc == RFS_LOOKUP) {
		struct nfsdiropres *dr = (struct nfsdiropres *)res;
		if ((enum wnfsstat)dr->dr_status == WNFSERR_CLNT_FLAVOR)
			return (TRUE);
	} else if (req->rq_vers == NFS_V3 && req->rq_proc == NFSPROC3_LOOKUP) {
		LOOKUP3res *resp = (LOOKUP3res *)res;
		if ((enum wnfsstat)resp->status == WNFSERR_CLNT_FLAVOR)
			return (TRUE);
	}
	return (FALSE);
}


static void
common_dispatch(struct svc_req *req, SVCXPRT *xprt, rpcvers_t min_vers,
		rpcvers_t max_vers, char *pgmname,
		struct rpc_disptable *disptable)
{
	int which;
	rpcvers_t vers;
	char *args;
	union {
			union rfs_args ra;
			union acl_args aa;
		} args_buf;
	char *res;
	union {
			union rfs_res rr;
			union acl_res ar;
		} res_buf;
	struct rpcdisp *disp = NULL;
	int dis_flags = 0;
	cred_t *cr;
	int error = 0;
	int anon_ok;
	struct exportinfo *exi = NULL;
	unsigned int nfslog_rec_id;
	int dupstat;
	struct dupreq *dr;
	int authres;
	bool_t publicfh_ok = FALSE;
	enum_t auth_flavor;
	bool_t dupcached = FALSE;
	struct netbuf	nb;
	bool_t logging_enabled = FALSE;
	struct exportinfo *nfslog_exi = NULL;
	char **procnames;
	char cbuf[INET6_ADDRSTRLEN];	/* to hold both IPv4 and IPv6 addr */
	bool_t ro = FALSE;
	kstat_t *ksp = NULL;
	kstat_t *exi_ksp = NULL;
	size_t pos;			/* request size */
	size_t rlen;			/* reply size */
	bool_t rsent = FALSE;		/* reply was sent successfully */

	vers = req->rq_vers;

	if (vers < min_vers || vers > max_vers) {
		svcerr_progvers(req->rq_xprt, min_vers, max_vers);
		error++;
		cmn_err(CE_NOTE, "%s: bad version number %u", pgmname, vers);
		goto done;
	}
	vers -= min_vers;

	which = req->rq_proc;
	if (which < 0 || which >= disptable[(int)vers].dis_nprocs) {
		svcerr_noproc(req->rq_xprt);
		error++;
		goto done;
	}

	(*(disptable[(int)vers].dis_proccntp))[which].value.ui64++;

	ksp = (*(disptable[(int)vers].dis_prociop))[which];
	if (ksp != NULL) {
		mutex_enter(ksp->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(ksp));
		mutex_exit(ksp->ks_lock);
	}
	pos = XDR_GETPOS(&xprt->xp_xdrin);

	disp = &disptable[(int)vers].dis_table[which];
	procnames = disptable[(int)vers].dis_procnames;

	auth_flavor = req->rq_cred.oa_flavor;

	/*
	 * Deserialize into the args struct.
	 */
	args = (char *)&args_buf;

#ifdef DEBUG
	if (rfs_no_fast_xdrargs || (auth_flavor == RPCSEC_GSS) ||
	    disp->dis_fastxdrargs == NULL_xdrproc_t ||
	    !SVC_GETARGS(xprt, disp->dis_fastxdrargs, (char *)&args))
#else
	if ((auth_flavor == RPCSEC_GSS) ||
	    disp->dis_fastxdrargs == NULL_xdrproc_t ||
	    !SVC_GETARGS(xprt, disp->dis_fastxdrargs, (char *)&args))
#endif
	{
		bzero(args, disp->dis_argsz);
		if (!SVC_GETARGS(xprt, disp->dis_xdrargs, args)) {
			error++;
			/*
			 * Check if we are outside our capabilities.
			 */
			if (rfs4_minorvers_mismatch(req, xprt, (void *)args))
				goto done;

			svcerr_decode(xprt);
			cmn_err(CE_NOTE,
			    "Failed to decode arguments for %s version %u "
			    "procedure %s client %s%s",
			    pgmname, vers + min_vers, procnames[which],
			    client_name(req), client_addr(req, cbuf));
			goto done;
		}
	}

	/*
	 * If Version 4 use that specific dispatch function.
	 */
	if (req->rq_vers == 4) {
		error += rfs4_dispatch(disp, req, xprt, args, &rlen);
		if (error == 0)
			rsent = TRUE;
		goto done;
	}

	dis_flags = disp->dis_flags;

	/*
	 * Find export information and check authentication,
	 * setting the credential if everything is ok.
	 */
	if (disp->dis_getfh != NULL) {
		void *fh;
		fsid_t *fsid;
		fid_t *fid, *xfid;
		fhandle_t *fh2;
		nfs_fh3 *fh3;

		fh = (*disp->dis_getfh)(args);
		switch (req->rq_vers) {
		case NFS_VERSION:
			fh2 = (fhandle_t *)fh;
			fsid = &fh2->fh_fsid;
			fid = (fid_t *)&fh2->fh_len;
			xfid = (fid_t *)&fh2->fh_xlen;
			break;
		case NFS_V3:
			fh3 = (nfs_fh3 *)fh;
			fsid = &fh3->fh3_fsid;
			fid = FH3TOFIDP(fh3);
			xfid = FH3TOXFIDP(fh3);
			break;
		}

		/*
		 * Fix for bug 1038302 - corbin
		 * There is a problem here if anonymous access is
		 * disallowed.  If the current request is part of the
		 * client's mount process for the requested filesystem,
		 * then it will carry root (uid 0) credentials on it, and
		 * will be denied by checkauth if that client does not
		 * have explicit root=0 permission.  This will cause the
		 * client's mount operation to fail.  As a work-around,
		 * we check here to see if the request is a getattr or
		 * statfs operation on the exported vnode itself, and
		 * pass a flag to checkauth with the result of this test.
		 *
		 * The filehandle refers to the mountpoint itself if
		 * the fh_data and fh_xdata portions of the filehandle
		 * are equal.
		 *
		 * Added anon_ok argument to checkauth().
		 */

		if ((dis_flags & RPC_ALLOWANON) && EQFID(fid, xfid))
			anon_ok = 1;
		else
			anon_ok = 0;

		cr = xprt->xp_cred;
		ASSERT(cr != NULL);
#ifdef DEBUG
		if (crgetref(cr) != 1) {
			crfree(cr);
			cr = crget();
			xprt->xp_cred = cr;
			cred_misses++;
		} else
			cred_hits++;
#else
		if (crgetref(cr) != 1) {
			crfree(cr);
			cr = crget();
			xprt->xp_cred = cr;
		}
#endif

		exi = checkexport(fsid, xfid);

		if (exi != NULL) {
			rw_enter(&exported_lock, RW_READER);

			switch (req->rq_vers) {
			case NFS_VERSION:
				exi_ksp = (disptable == rfs_disptable) ?
				    exi->exi_kstats->rfsprocio_v2_ptr[which] :
				    exi->exi_kstats->aclprocio_v2_ptr[which];
				break;
			case NFS_V3:
				exi_ksp = (disptable == rfs_disptable) ?
				    exi->exi_kstats->rfsprocio_v3_ptr[which] :
				    exi->exi_kstats->aclprocio_v3_ptr[which];
				break;
			default:
				ASSERT(0);
				break;
			}

			if (exi_ksp != NULL) {
				mutex_enter(exi_ksp->ks_lock);
				kstat_runq_enter(KSTAT_IO_PTR(exi_ksp));
				mutex_exit(exi_ksp->ks_lock);
			} else {
				rw_exit(&exported_lock);
			}

			publicfh_ok = PUBLICFH_CHECK(disp, exi, fsid, xfid);

			/*
			 * Don't allow non-V4 clients access
			 * to pseudo exports
			 */
			if (PSEUDO(exi)) {
				svcerr_weakauth(xprt);
				error++;
				goto done;
			}

			authres = checkauth(exi, req, cr, anon_ok, publicfh_ok,
			    &ro);
			/*
			 * authres >  0: authentication OK - proceed
			 * authres == 0: authentication weak - return error
			 * authres <  0: authentication timeout - drop
			 */
			if (authres <= 0) {
				if (authres == 0) {
					svcerr_weakauth(xprt);
					error++;
				}
				goto done;
			}
		}
	} else
		cr = NULL;

	if ((dis_flags & RPC_MAPRESP) && (auth_flavor != RPCSEC_GSS)) {
		res = (char *)SVC_GETRES(xprt, disp->dis_ressz);
		if (res == NULL)
			res = (char *)&res_buf;
	} else
		res = (char *)&res_buf;

	if (!(dis_flags & RPC_IDEMPOTENT)) {
		dupstat = SVC_DUP_EXT(xprt, req, res, disp->dis_ressz, &dr,
		    &dupcached);

		switch (dupstat) {
		case DUP_ERROR:
			svcerr_systemerr(xprt);
			error++;
			goto done;
			/* NOTREACHED */
		case DUP_INPROGRESS:
			if (res != (char *)&res_buf)
				SVC_FREERES(xprt);
			error++;
			goto done;
			/* NOTREACHED */
		case DUP_NEW:
		case DUP_DROP:
			curthread->t_flag |= T_DONTPEND;

			(*disp->dis_proc)(args, res, exi, req, cr, ro);

			curthread->t_flag &= ~T_DONTPEND;
			if (curthread->t_flag & T_WOULDBLOCK) {
				curthread->t_flag &= ~T_WOULDBLOCK;
				SVC_DUPDONE_EXT(xprt, dr, res, NULL,
				    disp->dis_ressz, DUP_DROP);
				if (res != (char *)&res_buf)
					SVC_FREERES(xprt);
				error++;
				goto done;
			}
			if (dis_flags & RPC_AVOIDWORK) {
				SVC_DUPDONE_EXT(xprt, dr, res, NULL,
				    disp->dis_ressz, DUP_DROP);
			} else {
				SVC_DUPDONE_EXT(xprt, dr, res,
				    disp->dis_resfree == nullfree ? NULL :
				    disp->dis_resfree,
				    disp->dis_ressz, DUP_DONE);
				dupcached = TRUE;
			}
			break;
		case DUP_DONE:
			break;
		}

	} else {
		curthread->t_flag |= T_DONTPEND;

		(*disp->dis_proc)(args, res, exi, req, cr, ro);

		curthread->t_flag &= ~T_DONTPEND;
		if (curthread->t_flag & T_WOULDBLOCK) {
			curthread->t_flag &= ~T_WOULDBLOCK;
			if (res != (char *)&res_buf)
				SVC_FREERES(xprt);
			error++;
			goto done;
		}
	}

	if (auth_tooweak(req, res)) {
		svcerr_weakauth(xprt);
		error++;
		goto done;
	}

	/*
	 * Check to see if logging has been enabled on the server.
	 * If so, then obtain the export info struct to be used for
	 * the later writing of the log record.  This is done for
	 * the case that a lookup is done across a non-logged public
	 * file system.
	 */
	if (nfslog_buffer_list != NULL) {
		nfslog_exi = nfslog_get_exi(exi, req, res, &nfslog_rec_id);
		/*
		 * Is logging enabled?
		 */
		logging_enabled = (nfslog_exi != NULL);

		/*
		 * Copy the netbuf for logging purposes, before it is
		 * freed by svc_sendreply().
		 */
		if (logging_enabled) {
			NFSLOG_COPY_NETBUF(nfslog_exi, xprt, &nb);
			/*
			 * If RPC_MAPRESP flag set (i.e. in V2 ops) the
			 * res gets copied directly into the mbuf and
			 * may be freed soon after the sendreply. So we
			 * must copy it here to a safe place...
			 */
			if (res != (char *)&res_buf) {
				bcopy(res, (char *)&res_buf, disp->dis_ressz);
			}
		}
	}

	/*
	 * Serialize and send results struct
	 */
#ifdef DEBUG
	if (rfs_no_fast_xdrres == 0 && res != (char *)&res_buf)
#else
	if (res != (char *)&res_buf)
#endif
	{
		if (!svc_sendreply(xprt, disp->dis_fastxdrres, res)) {
			cmn_err(CE_NOTE, "%s: bad sendreply", pgmname);
			svcerr_systemerr(xprt);
			error++;
		} else {
			rlen = xdr_sizeof(disp->dis_fastxdrres, res);
			rsent = TRUE;
		}
	} else {
		if (!svc_sendreply(xprt, disp->dis_xdrres, res)) {
			cmn_err(CE_NOTE, "%s: bad sendreply", pgmname);
			svcerr_systemerr(xprt);
			error++;
		} else {
			rlen = xdr_sizeof(disp->dis_xdrres, res);
			rsent = TRUE;
		}
	}

	/*
	 * Log if needed
	 */
	if (logging_enabled) {
		nfslog_write_record(nfslog_exi, req, args, (char *)&res_buf,
		    cr, &nb, nfslog_rec_id, NFSLOG_ONE_BUFFER);
		exi_rele(nfslog_exi);
		kmem_free((&nb)->buf, (&nb)->len);
	}

	/*
	 * Free results struct. With the addition of NFS V4 we can
	 * have non-idempotent procedures with functions.
	 */
	if (disp->dis_resfree != nullfree && dupcached == FALSE) {
		(*disp->dis_resfree)(res);
	}

done:
	if (ksp != NULL || exi_ksp != NULL) {
		pos = XDR_GETPOS(&xprt->xp_xdrin) - pos;
	}

	/*
	 * Free arguments struct
	 */
	if (disp) {
		if (!SVC_FREEARGS(xprt, disp->dis_xdrargs, args)) {
			cmn_err(CE_NOTE, "%s: bad freeargs", pgmname);
			error++;
		}
	} else {
		if (!SVC_FREEARGS(xprt, (xdrproc_t)0, (caddr_t)0)) {
			cmn_err(CE_NOTE, "%s: bad freeargs", pgmname);
			error++;
		}
	}

	if (exi_ksp != NULL) {
		mutex_enter(exi_ksp->ks_lock);
		KSTAT_IO_PTR(exi_ksp)->nwritten += pos;
		KSTAT_IO_PTR(exi_ksp)->writes++;
		if (rsent) {
			KSTAT_IO_PTR(exi_ksp)->nread += rlen;
			KSTAT_IO_PTR(exi_ksp)->reads++;
		}
		kstat_runq_exit(KSTAT_IO_PTR(exi_ksp));
		mutex_exit(exi_ksp->ks_lock);

		rw_exit(&exported_lock);
	}

	if (exi != NULL)
		exi_rele(exi);

	if (ksp != NULL) {
		mutex_enter(ksp->ks_lock);
		KSTAT_IO_PTR(ksp)->nwritten += pos;
		KSTAT_IO_PTR(ksp)->writes++;
		if (rsent) {
			KSTAT_IO_PTR(ksp)->nread += rlen;
			KSTAT_IO_PTR(ksp)->reads++;
		}
		kstat_runq_exit(KSTAT_IO_PTR(ksp));
		mutex_exit(ksp->ks_lock);
	}

	global_svstat_ptr[req->rq_vers][NFS_BADCALLS].value.ui64 += error;

	global_svstat_ptr[req->rq_vers][NFS_CALLS].value.ui64++;
}

static void
rfs_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	common_dispatch(req, xprt, NFS_VERSMIN, NFS_VERSMAX,
	    "NFS", rfs_disptable);
}

static char *aclcallnames_v2[] = {
	"ACL2_NULL",
	"ACL2_GETACL",
	"ACL2_SETACL",
	"ACL2_GETATTR",
	"ACL2_ACCESS",
	"ACL2_GETXATTRDIR"
};

static struct rpcdisp acldisptab_v2[] = {
	/*
	 * ACL VERSION 2
	 */

	/* ACL2_NULL = 0 */
	{rpc_null,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* ACL2_GETACL = 1 */
	{acl2_getacl,
	    xdr_GETACL2args, xdr_fastGETACL2args, sizeof (GETACL2args),
	    xdr_GETACL2res, NULL_xdrproc_t, sizeof (GETACL2res),
	    acl2_getacl_free, RPC_IDEMPOTENT,
	    acl2_getacl_getfh},

	/* ACL2_SETACL = 2 */
	{acl2_setacl,
	    xdr_SETACL2args, NULL_xdrproc_t, sizeof (SETACL2args),
#ifdef _LITTLE_ENDIAN
	    xdr_SETACL2res, xdr_fastSETACL2res, sizeof (SETACL2res),
#else
	    xdr_SETACL2res, NULL_xdrproc_t, sizeof (SETACL2res),
#endif
	    nullfree, RPC_MAPRESP,
	    acl2_setacl_getfh},

	/* ACL2_GETATTR = 3 */
	{acl2_getattr,
	    xdr_GETATTR2args, xdr_fastGETATTR2args, sizeof (GETATTR2args),
#ifdef _LITTLE_ENDIAN
	    xdr_GETATTR2res, xdr_fastGETATTR2res, sizeof (GETATTR2res),
#else
	    xdr_GETATTR2res, NULL_xdrproc_t, sizeof (GETATTR2res),
#endif
	    nullfree, RPC_IDEMPOTENT|RPC_ALLOWANON|RPC_MAPRESP,
	    acl2_getattr_getfh},

	/* ACL2_ACCESS = 4 */
	{acl2_access,
	    xdr_ACCESS2args, xdr_fastACCESS2args, sizeof (ACCESS2args),
#ifdef _LITTLE_ENDIAN
	    xdr_ACCESS2res, xdr_fastACCESS2res, sizeof (ACCESS2res),
#else
	    xdr_ACCESS2res, NULL_xdrproc_t, sizeof (ACCESS2res),
#endif
	    nullfree, RPC_IDEMPOTENT|RPC_MAPRESP,
	    acl2_access_getfh},

	/* ACL2_GETXATTRDIR = 5 */
	{acl2_getxattrdir,
	    xdr_GETXATTRDIR2args, NULL_xdrproc_t, sizeof (GETXATTRDIR2args),
	    xdr_GETXATTRDIR2res, NULL_xdrproc_t, sizeof (GETXATTRDIR2res),
	    nullfree, RPC_IDEMPOTENT,
	    acl2_getxattrdir_getfh},
};

static char *aclcallnames_v3[] = {
	"ACL3_NULL",
	"ACL3_GETACL",
	"ACL3_SETACL",
	"ACL3_GETXATTRDIR"
};

static struct rpcdisp acldisptab_v3[] = {
	/*
	 * ACL VERSION 3
	 */

	/* ACL3_NULL = 0 */
	{rpc_null,
	    xdr_void, NULL_xdrproc_t, 0,
	    xdr_void, NULL_xdrproc_t, 0,
	    nullfree, RPC_IDEMPOTENT,
	    0},

	/* ACL3_GETACL = 1 */
	{acl3_getacl,
	    xdr_GETACL3args, NULL_xdrproc_t, sizeof (GETACL3args),
	    xdr_GETACL3res, NULL_xdrproc_t, sizeof (GETACL3res),
	    acl3_getacl_free, RPC_IDEMPOTENT,
	    acl3_getacl_getfh},

	/* ACL3_SETACL = 2 */
	{acl3_setacl,
	    xdr_SETACL3args, NULL_xdrproc_t, sizeof (SETACL3args),
	    xdr_SETACL3res, NULL_xdrproc_t, sizeof (SETACL3res),
	    nullfree, 0,
	    acl3_setacl_getfh},

	/* ACL3_GETXATTRDIR = 3 */
	{acl3_getxattrdir,
	    xdr_GETXATTRDIR3args, NULL_xdrproc_t, sizeof (GETXATTRDIR3args),
	    xdr_GETXATTRDIR3res, NULL_xdrproc_t, sizeof (GETXATTRDIR3res),
	    nullfree, RPC_IDEMPOTENT,
	    acl3_getxattrdir_getfh},
};

static struct rpc_disptable acl_disptable[] = {
	{sizeof (acldisptab_v2) / sizeof (acldisptab_v2[0]),
		aclcallnames_v2,
		&aclproccnt_v2_ptr, &aclprocio_v2_ptr, acldisptab_v2},
	{sizeof (acldisptab_v3) / sizeof (acldisptab_v3[0]),
		aclcallnames_v3,
		&aclproccnt_v3_ptr, &aclprocio_v3_ptr, acldisptab_v3},
};

static void
acl_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	common_dispatch(req, xprt, NFS_ACL_VERSMIN, NFS_ACL_VERSMAX,
	    "ACL", acl_disptable);
}

int
checkwin(int flavor, int window, struct svc_req *req)
{
	struct authdes_cred *adc;

	switch (flavor) {
	case AUTH_DES:
		adc = (struct authdes_cred *)req->rq_clntcred;
		if (adc->adc_fullname.window > window)
			return (0);
		break;

	default:
		break;
	}
	return (1);
}


/*
 * checkauth() will check the access permission against the export
 * information.  Then map root uid/gid to appropriate uid/gid.
 *
 * This routine is used by NFS V3 and V2 code.
 */
static int
checkauth(struct exportinfo *exi, struct svc_req *req, cred_t *cr, int anon_ok,
    bool_t publicfh_ok, bool_t *ro)
{
	int i, nfsflavor, rpcflavor, stat, access;
	struct secinfo *secp;
	caddr_t principal;
	char buf[INET6_ADDRSTRLEN]; /* to hold both IPv4 and IPv6 addr */
	int anon_res = 0;

	uid_t uid;
	gid_t gid;
	uint_t ngids;
	gid_t *gids;

	/*
	 * Check for privileged port number
	 * N.B.:  this assumes that we know the format of a netbuf.
	 */
	if (nfs_portmon) {
		struct sockaddr *ca;
		ca = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;

		if (ca == NULL)
			return (0);

		if ((ca->sa_family == AF_INET &&
		    ntohs(((struct sockaddr_in *)ca)->sin_port) >=
		    IPPORT_RESERVED) ||
		    (ca->sa_family == AF_INET6 &&
		    ntohs(((struct sockaddr_in6 *)ca)->sin6_port) >=
		    IPPORT_RESERVED)) {
			cmn_err(CE_NOTE,
			    "nfs_server: client %s%ssent NFS request from "
			    "unprivileged port",
			    client_name(req), client_addr(req, buf));
			return (0);
		}
	}

	/*
	 *  return 1 on success or 0 on failure
	 */
	stat = sec_svc_getcred(req, cr, &principal, &nfsflavor);

	/*
	 * A failed AUTH_UNIX sec_svc_getcred() implies we couldn't set
	 * the credentials; below we map that to anonymous.
	 */
	if (!stat && nfsflavor != AUTH_UNIX) {
		cmn_err(CE_NOTE,
		    "nfs_server: couldn't get unix cred for %s",
		    client_name(req));
		return (0);
	}

	/*
	 * Short circuit checkauth() on operations that support the
	 * public filehandle, and if the request for that operation
	 * is using the public filehandle. Note that we must call
	 * sec_svc_getcred() first so that xp_cookie is set to the
	 * right value. Normally xp_cookie is just the RPC flavor
	 * of the the request, but in the case of RPCSEC_GSS it
	 * could be a pseudo flavor.
	 */
	if (publicfh_ok)
		return (1);

	rpcflavor = req->rq_cred.oa_flavor;
	/*
	 * Check if the auth flavor is valid for this export
	 */
	access = nfsauth_access(exi, req, cr, &uid, &gid, &ngids, &gids);
	if (access & NFSAUTH_DROP)
		return (-1);	/* drop the request */

	if (access & NFSAUTH_RO)
		*ro = TRUE;

	if (access & NFSAUTH_DENIED) {
		/*
		 * If anon_ok == 1 and we got NFSAUTH_DENIED, it was
		 * probably due to the flavor not matching during
		 * the mount attempt. So map the flavor to AUTH_NONE
		 * so that the credentials get mapped to the anonymous
		 * user.
		 */
		if (anon_ok == 1)
			rpcflavor = AUTH_NONE;
		else
			return (0);	/* deny access */

	} else if (access & NFSAUTH_MAPNONE) {
		/*
		 * Access was granted even though the flavor mismatched
		 * because AUTH_NONE was one of the exported flavors.
		 */
		rpcflavor = AUTH_NONE;

	} else if (access & NFSAUTH_WRONGSEC) {
		/*
		 * NFSAUTH_WRONGSEC is used for NFSv4. If we get here,
		 * it means a client ignored the list of allowed flavors
		 * returned via the MOUNT protocol. So we just disallow it!
		 */
		return (0);
	}

	if (rpcflavor != AUTH_SYS)
		kmem_free(gids, ngids * sizeof (gid_t));

	switch (rpcflavor) {
	case AUTH_NONE:
		anon_res = crsetugid(cr, exi->exi_export.ex_anon,
		    exi->exi_export.ex_anon);
		(void) crsetgroups(cr, 0, NULL);
		break;

	case AUTH_UNIX:
		if (!stat || crgetuid(cr) == 0 && !(access & NFSAUTH_UIDMAP)) {
			anon_res = crsetugid(cr, exi->exi_export.ex_anon,
			    exi->exi_export.ex_anon);
			(void) crsetgroups(cr, 0, NULL);
		} else if (crgetuid(cr) == 0 && access & NFSAUTH_ROOT) {
			/*
			 * It is root, so apply rootid to get real UID
			 * Find the secinfo structure.  We should be able
			 * to find it by the time we reach here.
			 * nfsauth_access() has done the checking.
			 */
			secp = NULL;
			for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
				struct secinfo *sptr;
				sptr = &exi->exi_export.ex_secinfo[i];
				if (sptr->s_secinfo.sc_nfsnum == nfsflavor) {
					secp = sptr;
					break;
				}
			}
			if (secp != NULL) {
				(void) crsetugid(cr, secp->s_rootid,
				    secp->s_rootid);
				(void) crsetgroups(cr, 0, NULL);
			}
		} else if (crgetuid(cr) != uid || crgetgid(cr) != gid) {
			if (crsetugid(cr, uid, gid) != 0)
				anon_res = crsetugid(cr,
				    exi->exi_export.ex_anon,
				    exi->exi_export.ex_anon);
			(void) crsetgroups(cr, 0, NULL);
		} else if (access & NFSAUTH_GROUPS) {
			(void) crsetgroups(cr, ngids, gids);
		}

		kmem_free(gids, ngids * sizeof (gid_t));

		break;

	case AUTH_DES:
	case RPCSEC_GSS:
		/*
		 *  Find the secinfo structure.  We should be able
		 *  to find it by the time we reach here.
		 *  nfsauth_access() has done the checking.
		 */
		secp = NULL;
		for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
			if (exi->exi_export.ex_secinfo[i].s_secinfo.sc_nfsnum ==
			    nfsflavor) {
				secp = &exi->exi_export.ex_secinfo[i];
				break;
			}
		}

		if (!secp) {
			cmn_err(CE_NOTE, "nfs_server: client %s%shad "
			    "no secinfo data for flavor %d",
			    client_name(req), client_addr(req, buf),
			    nfsflavor);
			return (0);
		}

		if (!checkwin(rpcflavor, secp->s_window, req)) {
			cmn_err(CE_NOTE,
			    "nfs_server: client %s%sused invalid "
			    "auth window value",
			    client_name(req), client_addr(req, buf));
			return (0);
		}

		/*
		 * Map root principals listed in the share's root= list to root,
		 * and map any others principals that were mapped to root by RPC
		 * to anon.
		 */
		if (principal && sec_svc_inrootlist(rpcflavor, principal,
		    secp->s_rootcnt, secp->s_rootnames)) {
			if (crgetuid(cr) == 0 && secp->s_rootid == 0)
				return (1);


			(void) crsetugid(cr, secp->s_rootid, secp->s_rootid);

			/*
			 * NOTE: If and when kernel-land privilege tracing is
			 * added this may have to be replaced with code that
			 * retrieves root's supplementary groups (e.g., using
			 * kgss_get_group_info().  In the meantime principals
			 * mapped to uid 0 get all privileges, so setting cr's
			 * supplementary groups for them does nothing.
			 */
			(void) crsetgroups(cr, 0, NULL);

			return (1);
		}

		/*
		 * Not a root princ, or not in root list, map UID 0/nobody to
		 * the anon ID for the share.  (RPC sets cr's UIDs and GIDs to
		 * UID_NOBODY and GID_NOBODY, respectively.)
		 */
		if (crgetuid(cr) != 0 &&
		    (crgetuid(cr) != UID_NOBODY || crgetgid(cr) != GID_NOBODY))
			return (1);

		anon_res = crsetugid(cr, exi->exi_export.ex_anon,
		    exi->exi_export.ex_anon);
		(void) crsetgroups(cr, 0, NULL);
		break;
	default:
		return (0);
	} /* switch on rpcflavor */

	/*
	 * Even if anon access is disallowed via ex_anon == -1, we allow
	 * this access if anon_ok is set.  So set creds to the default
	 * "nobody" id.
	 */
	if (anon_res != 0) {
		if (anon_ok == 0) {
			cmn_err(CE_NOTE,
			    "nfs_server: client %s%ssent wrong "
			    "authentication for %s",
			    client_name(req), client_addr(req, buf),
			    exi->exi_export.ex_path ?
			    exi->exi_export.ex_path : "?");
			return (0);
		}

		if (crsetugid(cr, UID_NOBODY, GID_NOBODY) != 0)
			return (0);
	}

	return (1);
}

/*
 * returns 0 on failure, -1 on a drop, -2 on wrong security flavor,
 * and 1 on success
 */
int
checkauth4(struct compound_state *cs, struct svc_req *req)
{
	int i, rpcflavor, access;
	struct secinfo *secp;
	char buf[MAXHOST + 1];
	int anon_res = 0, nfsflavor;
	struct exportinfo *exi;
	cred_t	*cr;
	caddr_t	principal;

	uid_t uid;
	gid_t gid;
	uint_t ngids;
	gid_t *gids;

	exi = cs->exi;
	cr = cs->cr;
	principal = cs->principal;
	nfsflavor = cs->nfsflavor;

	ASSERT(cr != NULL);

	rpcflavor = req->rq_cred.oa_flavor;
	cs->access &= ~CS_ACCESS_LIMITED;

	/*
	 * Check for privileged port number
	 * N.B.:  this assumes that we know the format of a netbuf.
	 */
	if (nfs_portmon) {
		struct sockaddr *ca;
		ca = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;

		if (ca == NULL)
			return (0);

		if ((ca->sa_family == AF_INET &&
		    ntohs(((struct sockaddr_in *)ca)->sin_port) >=
		    IPPORT_RESERVED) ||
		    (ca->sa_family == AF_INET6 &&
		    ntohs(((struct sockaddr_in6 *)ca)->sin6_port) >=
		    IPPORT_RESERVED)) {
			cmn_err(CE_NOTE,
			    "nfs_server: client %s%ssent NFSv4 request from "
			    "unprivileged port",
			    client_name(req), client_addr(req, buf));
			return (0);
		}
	}

	/*
	 * Check the access right per auth flavor on the vnode of
	 * this export for the given request.
	 */
	access = nfsauth4_access(cs->exi, cs->vp, req, cr, &uid, &gid, &ngids,
	    &gids);

	if (access & NFSAUTH_WRONGSEC)
		return (-2);	/* no access for this security flavor */

	if (access & NFSAUTH_DROP)
		return (-1);	/* drop the request */

	if (access & NFSAUTH_DENIED) {

		if (exi->exi_export.ex_seccnt > 0)
			return (0);	/* deny access */

	} else if (access & NFSAUTH_LIMITED) {

		cs->access |= CS_ACCESS_LIMITED;

	} else if (access & NFSAUTH_MAPNONE) {
		/*
		 * Access was granted even though the flavor mismatched
		 * because AUTH_NONE was one of the exported flavors.
		 */
		rpcflavor = AUTH_NONE;
	}

	/*
	 * XXX probably need to redo some of it for nfsv4?
	 * return 1 on success or 0 on failure
	 */

	if (rpcflavor != AUTH_SYS)
		kmem_free(gids, ngids * sizeof (gid_t));

	switch (rpcflavor) {
	case AUTH_NONE:
		anon_res = crsetugid(cr, exi->exi_export.ex_anon,
		    exi->exi_export.ex_anon);
		(void) crsetgroups(cr, 0, NULL);
		break;

	case AUTH_UNIX:
		if (crgetuid(cr) == 0 && !(access & NFSAUTH_UIDMAP)) {
			anon_res = crsetugid(cr, exi->exi_export.ex_anon,
			    exi->exi_export.ex_anon);
			(void) crsetgroups(cr, 0, NULL);
		} else if (crgetuid(cr) == 0 && access & NFSAUTH_ROOT) {
			/*
			 * It is root, so apply rootid to get real UID
			 * Find the secinfo structure.  We should be able
			 * to find it by the time we reach here.
			 * nfsauth_access() has done the checking.
			 */
			secp = NULL;
			for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
				struct secinfo *sptr;
				sptr = &exi->exi_export.ex_secinfo[i];
				if (sptr->s_secinfo.sc_nfsnum == nfsflavor) {
					secp = &exi->exi_export.ex_secinfo[i];
					break;
				}
			}
			if (secp != NULL) {
				(void) crsetugid(cr, secp->s_rootid,
				    secp->s_rootid);
				(void) crsetgroups(cr, 0, NULL);
			}
		} else if (crgetuid(cr) != uid || crgetgid(cr) != gid) {
			if (crsetugid(cr, uid, gid) != 0)
				anon_res = crsetugid(cr,
				    exi->exi_export.ex_anon,
				    exi->exi_export.ex_anon);
			(void) crsetgroups(cr, 0, NULL);
		} if (access & NFSAUTH_GROUPS) {
			(void) crsetgroups(cr, ngids, gids);
		}

		kmem_free(gids, ngids * sizeof (gid_t));

		break;

	default:
		/*
		 *  Find the secinfo structure.  We should be able
		 *  to find it by the time we reach here.
		 *  nfsauth_access() has done the checking.
		 */
		secp = NULL;
		for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
			if (exi->exi_export.ex_secinfo[i].s_secinfo.sc_nfsnum ==
			    nfsflavor) {
				secp = &exi->exi_export.ex_secinfo[i];
				break;
			}
		}

		if (!secp) {
			cmn_err(CE_NOTE, "nfs_server: client %s%shad "
			    "no secinfo data for flavor %d",
			    client_name(req), client_addr(req, buf),
			    nfsflavor);
			return (0);
		}

		if (!checkwin(rpcflavor, secp->s_window, req)) {
			cmn_err(CE_NOTE,
			    "nfs_server: client %s%sused invalid "
			    "auth window value",
			    client_name(req), client_addr(req, buf));
			return (0);
		}

		/*
		 * Map root principals listed in the share's root= list to root,
		 * and map any others principals that were mapped to root by RPC
		 * to anon. If not going to anon, set to rootid (root_mapping).
		 */
		if (principal && sec_svc_inrootlist(rpcflavor, principal,
		    secp->s_rootcnt, secp->s_rootnames)) {
			if (crgetuid(cr) == 0 && secp->s_rootid == 0)
				return (1);

			(void) crsetugid(cr, secp->s_rootid, secp->s_rootid);

			/*
			 * NOTE: If and when kernel-land privilege tracing is
			 * added this may have to be replaced with code that
			 * retrieves root's supplementary groups (e.g., using
			 * kgss_get_group_info().  In the meantime principals
			 * mapped to uid 0 get all privileges, so setting cr's
			 * supplementary groups for them does nothing.
			 */
			(void) crsetgroups(cr, 0, NULL);

			return (1);
		}

		/*
		 * Not a root princ, or not in root list, map UID 0/nobody to
		 * the anon ID for the share.  (RPC sets cr's UIDs and GIDs to
		 * UID_NOBODY and GID_NOBODY, respectively.)
		 */
		if (crgetuid(cr) != 0 &&
		    (crgetuid(cr) != UID_NOBODY || crgetgid(cr) != GID_NOBODY))
			return (1);

		anon_res = crsetugid(cr, exi->exi_export.ex_anon,
		    exi->exi_export.ex_anon);
		(void) crsetgroups(cr, 0, NULL);
		break;
	} /* switch on rpcflavor */

	/*
	 * Even if anon access is disallowed via ex_anon == -1, we allow
	 * this access if anon_ok is set.  So set creds to the default
	 * "nobody" id.
	 */

	if (anon_res != 0) {
		cmn_err(CE_NOTE,
		    "nfs_server: client %s%ssent wrong "
		    "authentication for %s",
		    client_name(req), client_addr(req, buf),
		    exi->exi_export.ex_path ?
		    exi->exi_export.ex_path : "?");
		return (0);
	}

	return (1);
}


static char *
client_name(struct svc_req *req)
{
	char *hostname = NULL;

	/*
	 * If it's a Unix cred then use the
	 * hostname from the credential.
	 */
	if (req->rq_cred.oa_flavor == AUTH_UNIX) {
		hostname = ((struct authunix_parms *)
		    req->rq_clntcred)->aup_machname;
	}
	if (hostname == NULL)
		hostname = "";

	return (hostname);
}

static char *
client_addr(struct svc_req *req, char *buf)
{
	struct sockaddr *ca;
	uchar_t *b;
	char *frontspace = "";

	/*
	 * We assume we are called in tandem with client_name and the
	 * format string looks like "...client %s%sblah blah..."
	 *
	 * If it's a Unix cred then client_name returned
	 * a host name, so we need insert a space between host name
	 * and IP address.
	 */
	if (req->rq_cred.oa_flavor == AUTH_UNIX)
		frontspace = " ";

	/*
	 * Convert the caller's IP address to a dotted string
	 */
	ca = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;

	if (ca->sa_family == AF_INET) {
		b = (uchar_t *)&((struct sockaddr_in *)ca)->sin_addr;
		(void) sprintf(buf, "%s(%d.%d.%d.%d) ", frontspace,
		    b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
	} else if (ca->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)ca;
		(void) kinet_ntop6((uchar_t *)&sin6->sin6_addr,
		    buf, INET6_ADDRSTRLEN);

	} else {

		/*
		 * No IP address to print. If there was a host name
		 * printed, then we print a space.
		 */
		(void) sprintf(buf, frontspace);
	}

	return (buf);
}

/*
 * NFS Server initialization routine.  This routine should only be called
 * once.  It performs the following tasks:
 *	- Call sub-initialization routines (localize access to variables)
 *	- Initialize all locks
 *	- initialize the version 3 write verifier
 */
int
nfs_srvinit(void)
{
	int error;

	error = nfs_exportinit();
	if (error != 0)
		return (error);
	error = rfs4_srvrinit();
	if (error != 0) {
		nfs_exportfini();
		return (error);
	}
	rfs_srvrinit();
	rfs3_srvrinit();
	nfsauth_init();

	/* Init the stuff to control start/stop */
	nfs_server_upordown = NFS_SERVER_STOPPED;
	mutex_init(&nfs_server_upordown_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&nfs_server_upordown_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&rdma_wait_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rdma_wait_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*
 * NFS Server finalization routine. This routine is called to cleanup the
 * initialization work previously performed if the NFS server module could
 * not be loaded correctly.
 */
void
nfs_srvfini(void)
{
	nfsauth_fini();
	rfs3_srvrfini();
	rfs_srvrfini();
	nfs_exportfini();

	mutex_destroy(&nfs_server_upordown_lock);
	cv_destroy(&nfs_server_upordown_cv);
	mutex_destroy(&rdma_wait_mutex);
	cv_destroy(&rdma_wait_cv);
}

/*
 * Set up an iovec array of up to cnt pointers.
 */

void
mblk_to_iov(mblk_t *m, int cnt, struct iovec *iovp)
{
	while (m != NULL && cnt-- > 0) {
		iovp->iov_base = (caddr_t)m->b_rptr;
		iovp->iov_len = (m->b_wptr - m->b_rptr);
		iovp++;
		m = m->b_cont;
	}
}

/*
 * Common code between NFS Version 2 and NFS Version 3 for the public
 * filehandle multicomponent lookups.
 */

/*
 * Public filehandle evaluation of a multi-component lookup, following
 * symbolic links, if necessary. This may result in a vnode in another
 * filesystem, which is OK as long as the other filesystem is exported.
 *
 * Note that the exi will be set either to NULL or a new reference to the
 * exportinfo struct that corresponds to the vnode of the multi-component path.
 * It is the callers responsibility to release this reference.
 */
int
rfs_publicfh_mclookup(char *p, vnode_t *dvp, cred_t *cr, vnode_t **vpp,
    struct exportinfo **exi, struct sec_ol *sec)
{
	int pathflag;
	vnode_t *mc_dvp = NULL;
	vnode_t *realvp;
	int error;

	*exi = NULL;

	/*
	 * check if the given path is a url or native path. Since p is
	 * modified by MCLpath(), it may be empty after returning from
	 * there, and should be checked.
	 */
	if ((pathflag = MCLpath(&p)) == -1)
		return (EIO);

	/*
	 * If pathflag is SECURITY_QUERY, turn the SEC_QUERY bit
	 * on in sec->sec_flags. This bit will later serve as an
	 * indication in makefh_ol() or makefh3_ol() to overload the
	 * filehandle to contain the sec modes used by the server for
	 * the path.
	 */
	if (pathflag == SECURITY_QUERY) {
		if ((sec->sec_index = (uint_t)(*p)) > 0) {
			sec->sec_flags |= SEC_QUERY;
			p++;
			if ((pathflag = MCLpath(&p)) == -1)
				return (EIO);
		} else {
			cmn_err(CE_NOTE,
			    "nfs_server: invalid security index %d, "
			    "violating WebNFS SNEGO protocol.", sec->sec_index);
			return (EIO);
		}
	}

	if (p[0] == '\0') {
		error = ENOENT;
		goto publicfh_done;
	}

	error = rfs_pathname(p, &mc_dvp, vpp, dvp, cr, pathflag);

	/*
	 * If name resolves to "/" we get EINVAL since we asked for
	 * the vnode of the directory that the file is in. Try again
	 * with NULL directory vnode.
	 */
	if (error == EINVAL) {
		error = rfs_pathname(p, NULL, vpp, dvp, cr, pathflag);
		if (!error) {
			ASSERT(*vpp != NULL);
			if ((*vpp)->v_type == VDIR) {
				VN_HOLD(*vpp);
				mc_dvp = *vpp;
			} else {
				/*
				 * This should not happen, the filesystem is
				 * in an inconsistent state. Fail the lookup
				 * at this point.
				 */
				VN_RELE(*vpp);
				error = EINVAL;
			}
		}
	}

	if (error)
		goto publicfh_done;

	if (*vpp == NULL) {
		error = ENOENT;
		goto publicfh_done;
	}

	ASSERT(mc_dvp != NULL);
	ASSERT(*vpp != NULL);

	if ((*vpp)->v_type == VDIR) {
		do {
			/*
			 * *vpp may be an AutoFS node, so we perform
			 * a VOP_ACCESS() to trigger the mount of the intended
			 * filesystem, so we can perform the lookup in the
			 * intended filesystem.
			 */
			(void) VOP_ACCESS(*vpp, 0, 0, cr, NULL);

			/*
			 * If vnode is covered, get the
			 * the topmost vnode.
			 */
			if (vn_mountedvfs(*vpp) != NULL) {
				error = traverse(vpp);
				if (error) {
					VN_RELE(*vpp);
					goto publicfh_done;
				}
			}

			if (VOP_REALVP(*vpp, &realvp, NULL) == 0 &&
			    realvp != *vpp) {
				/*
				 * If realvp is different from *vpp
				 * then release our reference on *vpp, so that
				 * the export access check be performed on the
				 * real filesystem instead.
				 */
				VN_HOLD(realvp);
				VN_RELE(*vpp);
				*vpp = realvp;
			} else {
				break;
			}
		/* LINTED */
		} while (TRUE);

		/*
		 * Let nfs_vptexi() figure what the real parent is.
		 */
		VN_RELE(mc_dvp);
		mc_dvp = NULL;

	} else {
		/*
		 * If vnode is covered, get the
		 * the topmost vnode.
		 */
		if (vn_mountedvfs(mc_dvp) != NULL) {
			error = traverse(&mc_dvp);
			if (error) {
				VN_RELE(*vpp);
				goto publicfh_done;
			}
		}

		if (VOP_REALVP(mc_dvp, &realvp, NULL) == 0 &&
		    realvp != mc_dvp) {
			/*
			 * *vpp is a file, obtain realvp of the parent
			 * directory vnode.
			 */
			VN_HOLD(realvp);
			VN_RELE(mc_dvp);
			mc_dvp = realvp;
		}
	}

	/*
	 * The pathname may take us from the public filesystem to another.
	 * If that's the case then just set the exportinfo to the new export
	 * and build filehandle for it. Thanks to per-access checking there's
	 * no security issues with doing this. If the client is not allowed
	 * access to this new export then it will get an access error when it
	 * tries to use the filehandle
	 */
	if (error = nfs_check_vpexi(mc_dvp, *vpp, kcred, exi)) {
		VN_RELE(*vpp);
		goto publicfh_done;
	}

	/*
	 * Not allowed access to pseudo exports.
	 */
	if (PSEUDO(*exi)) {
		error = ENOENT;
		VN_RELE(*vpp);
		goto publicfh_done;
	}

	/*
	 * Do a lookup for the index file. We know the index option doesn't
	 * allow paths through handling in the share command, so mc_dvp will
	 * be the parent for the index file vnode, if its present. Use
	 * temporary pointers to preserve and reuse the vnode pointers of the
	 * original directory in case there's no index file. Note that the
	 * index file is a native path, and should not be interpreted by
	 * the URL parser in rfs_pathname()
	 */
	if (((*exi)->exi_export.ex_flags & EX_INDEX) &&
	    ((*vpp)->v_type == VDIR) && (pathflag == URLPATH)) {
		vnode_t *tvp, *tmc_dvp;	/* temporary vnode pointers */

		tmc_dvp = mc_dvp;
		mc_dvp = tvp = *vpp;

		error = rfs_pathname((*exi)->exi_export.ex_index, NULL, vpp,
		    mc_dvp, cr, NATIVEPATH);

		if (error == ENOENT) {
			*vpp = tvp;
			mc_dvp = tmc_dvp;
			error = 0;
		} else {	/* ok or error other than ENOENT */
			if (tmc_dvp)
				VN_RELE(tmc_dvp);
			if (error)
				goto publicfh_done;

			/*
			 * Found a valid vp for index "filename". Sanity check
			 * for odd case where a directory is provided as index
			 * option argument and leads us to another filesystem
			 */

			/* Release the reference on the old exi value */
			ASSERT(*exi != NULL);
			exi_rele(*exi);

			if (error = nfs_check_vpexi(mc_dvp, *vpp, kcred, exi)) {
				VN_RELE(*vpp);
				goto publicfh_done;
			}
		}
	}

publicfh_done:
	if (mc_dvp)
		VN_RELE(mc_dvp);

	return (error);
}

/*
 * Evaluate a multi-component path
 */
int
rfs_pathname(
	char *path,			/* pathname to evaluate */
	vnode_t **dirvpp,		/* ret for ptr to parent dir vnode */
	vnode_t **compvpp,		/* ret for ptr to component vnode */
	vnode_t *startdvp,		/* starting vnode */
	cred_t *cr,			/* user's credential */
	int pathflag)			/* flag to identify path, e.g. URL */
{
	char namebuf[TYPICALMAXPATHLEN];
	struct pathname pn;
	int error;

	/*
	 * If pathname starts with '/', then set startdvp to root.
	 */
	if (*path == '/') {
		while (*path == '/')
			path++;

		startdvp = rootdir;
	}

	error = pn_get_buf(path, UIO_SYSSPACE, &pn, namebuf, sizeof (namebuf));
	if (error == 0) {
		/*
		 * Call the URL parser for URL paths to modify the original
		 * string to handle any '%' encoded characters that exist.
		 * Done here to avoid an extra bcopy in the lookup.
		 * We need to be careful about pathlen's. We know that
		 * rfs_pathname() is called with a non-empty path. However,
		 * it could be emptied due to the path simply being all /'s,
		 * which is valid to proceed with the lookup, or due to the
		 * URL parser finding an encoded null character at the
		 * beginning of path which should not proceed with the lookup.
		 */
		if (pn.pn_pathlen != 0 && pathflag == URLPATH) {
			URLparse(pn.pn_path);
			if ((pn.pn_pathlen = strlen(pn.pn_path)) == 0)
				return (ENOENT);
		}
		VN_HOLD(startdvp);
		error = lookuppnvp(&pn, NULL, NO_FOLLOW, dirvpp, compvpp,
		    rootdir, startdvp, cr);
	}
	if (error == ENAMETOOLONG) {
		/*
		 * This thread used a pathname > TYPICALMAXPATHLEN bytes long.
		 */
		if (error = pn_get(path, UIO_SYSSPACE, &pn))
			return (error);
		if (pn.pn_pathlen != 0 && pathflag == URLPATH) {
			URLparse(pn.pn_path);
			if ((pn.pn_pathlen = strlen(pn.pn_path)) == 0) {
				pn_free(&pn);
				return (ENOENT);
			}
		}
		VN_HOLD(startdvp);
		error = lookuppnvp(&pn, NULL, NO_FOLLOW, dirvpp, compvpp,
		    rootdir, startdvp, cr);
		pn_free(&pn);
	}

	return (error);
}

/*
 * Adapt the multicomponent lookup path depending on the pathtype
 */
static int
MCLpath(char **path)
{
	unsigned char c = (unsigned char)**path;

	/*
	 * If the MCL path is between 0x20 and 0x7E (graphic printable
	 * character of the US-ASCII coded character set), its a URL path,
	 * per RFC 1738.
	 */
	if (c >= 0x20 && c <= 0x7E)
		return (URLPATH);

	/*
	 * If the first octet of the MCL path is not an ASCII character
	 * then it must be interpreted as a tag value that describes the
	 * format of the remaining octets of the MCL path.
	 *
	 * If the first octet of the MCL path is 0x81 it is a query
	 * for the security info.
	 */
	switch (c) {
	case 0x80:	/* native path, i.e. MCL via mount protocol */
		(*path)++;
		return (NATIVEPATH);
	case 0x81:	/* security query */
		(*path)++;
		return (SECURITY_QUERY);
	default:
		return (-1);
	}
}

#define	fromhex(c)  ((c >= '0' && c <= '9') ? (c - '0') : \
			((c >= 'A' && c <= 'F') ? (c - 'A' + 10) :\
			((c >= 'a' && c <= 'f') ? (c - 'a' + 10) : 0)))

/*
 * The implementation of URLparse guarantees that the final string will
 * fit in the original one. Replaces '%' occurrences followed by 2 characters
 * with its corresponding hexadecimal character.
 */
static void
URLparse(char *str)
{
	char *p, *q;

	p = q = str;
	while (*p) {
		*q = *p;
		if (*p++ == '%') {
			if (*p) {
				*q = fromhex(*p) * 16;
				p++;
				if (*p) {
					*q += fromhex(*p);
					p++;
				}
			}
		}
		q++;
	}
	*q = '\0';
}


/*
 * Get the export information for the lookup vnode, and verify its
 * useable.
 */
int
nfs_check_vpexi(vnode_t *mc_dvp, vnode_t *vp, cred_t *cr,
    struct exportinfo **exi)
{
	int walk;
	int error = 0;

	*exi = nfs_vptoexi(mc_dvp, vp, cr, &walk, NULL, FALSE);
	if (*exi == NULL)
		error = EACCES;
	else {
		/*
		 * If nosub is set for this export then
		 * a lookup relative to the public fh
		 * must not terminate below the
		 * exported directory.
		 */
		if ((*exi)->exi_export.ex_flags & EX_NOSUB && walk > 0)
			error = EACCES;
	}

	return (error);
}

/*
 * Do the main work of handling HA-NFSv4 Resource Group failover on
 * Sun Cluster.
 * We need to detect whether any RG admin paths have been added or removed,
 * and adjust resources accordingly.
 * Currently we're using a very inefficient algorithm, ~ 2 * O(n**2). In
 * order to scale, the list and array of paths need to be held in more
 * suitable data structures.
 */
static void
hanfsv4_failover(void)
{
	int i, start_grace, numadded_paths = 0;
	char **added_paths = NULL;
	rfs4_dss_path_t *dss_path;

	/*
	 * Note: currently, rfs4_dss_pathlist cannot be NULL, since
	 * it will always include an entry for NFS4_DSS_VAR_DIR. If we
	 * make the latter dynamically specified too, the following will
	 * need to be adjusted.
	 */

	/*
	 * First, look for removed paths: RGs that have been failed-over
	 * away from this node.
	 * Walk the "currently-serving" rfs4_dss_pathlist and, for each
	 * path, check if it is on the "passed-in" rfs4_dss_newpaths array
	 * from nfsd. If not, that RG path has been removed.
	 *
	 * Note that nfsd has sorted rfs4_dss_newpaths for us, and removed
	 * any duplicates.
	 */
	dss_path = rfs4_dss_pathlist;
	do {
		int found = 0;
		char *path = dss_path->path;

		/* used only for non-HA so may not be removed */
		if (strcmp(path, NFS4_DSS_VAR_DIR) == 0) {
			dss_path = dss_path->next;
			continue;
		}

		for (i = 0; i < rfs4_dss_numnewpaths; i++) {
			int cmpret;
			char *newpath = rfs4_dss_newpaths[i];

			/*
			 * Since nfsd has sorted rfs4_dss_newpaths for us,
			 * once the return from strcmp is negative we know
			 * we've passed the point where "path" should be,
			 * and can stop searching: "path" has been removed.
			 */
			cmpret = strcmp(path, newpath);
			if (cmpret < 0)
				break;
			if (cmpret == 0) {
				found = 1;
				break;
			}
		}

		if (found == 0) {
			unsigned index = dss_path->index;
			rfs4_servinst_t *sip = dss_path->sip;
			rfs4_dss_path_t *path_next = dss_path->next;

			/*
			 * This path has been removed.
			 * We must clear out the servinst reference to
			 * it, since it's now owned by another
			 * node: we should not attempt to touch it.
			 */
			ASSERT(dss_path == sip->dss_paths[index]);
			sip->dss_paths[index] = NULL;

			/* remove from "currently-serving" list, and destroy */
			remque(dss_path);
			/* allow for NUL */
			kmem_free(dss_path->path, strlen(dss_path->path) + 1);
			kmem_free(dss_path, sizeof (rfs4_dss_path_t));

			dss_path = path_next;
		} else {
			/* path was found; not removed */
			dss_path = dss_path->next;
		}
	} while (dss_path != rfs4_dss_pathlist);

	/*
	 * Now, look for added paths: RGs that have been failed-over
	 * to this node.
	 * Walk the "passed-in" rfs4_dss_newpaths array from nfsd and,
	 * for each path, check if it is on the "currently-serving"
	 * rfs4_dss_pathlist. If not, that RG path has been added.
	 *
	 * Note: we don't do duplicate detection here; nfsd does that for us.
	 *
	 * Note: numadded_paths <= rfs4_dss_numnewpaths, which gives us
	 * an upper bound for the size needed for added_paths[numadded_paths].
	 */

	/* probably more space than we need, but guaranteed to be enough */
	if (rfs4_dss_numnewpaths > 0) {
		size_t sz = rfs4_dss_numnewpaths * sizeof (char *);
		added_paths = kmem_zalloc(sz, KM_SLEEP);
	}

	/* walk the "passed-in" rfs4_dss_newpaths array from nfsd */
	for (i = 0; i < rfs4_dss_numnewpaths; i++) {
		int found = 0;
		char *newpath = rfs4_dss_newpaths[i];

		dss_path = rfs4_dss_pathlist;
		do {
			char *path = dss_path->path;

			/* used only for non-HA */
			if (strcmp(path, NFS4_DSS_VAR_DIR) == 0) {
				dss_path = dss_path->next;
				continue;
			}

			if (strncmp(path, newpath, strlen(path)) == 0) {
				found = 1;
				break;
			}

			dss_path = dss_path->next;
		} while (dss_path != rfs4_dss_pathlist);

		if (found == 0) {
			added_paths[numadded_paths] = newpath;
			numadded_paths++;
		}
	}

	/* did we find any added paths? */
	if (numadded_paths > 0) {
		/* create a new server instance, and start its grace period */
		start_grace = 1;
		rfs4_servinst_create(start_grace, numadded_paths, added_paths);

		/* read in the stable storage state from these paths */
		rfs4_dss_readstate(numadded_paths, added_paths);

		/*
		 * Multiple failovers during a grace period will cause
		 * clients of the same resource group to be partitioned
		 * into different server instances, with different
		 * grace periods.  Since clients of the same resource
		 * group must be subject to the same grace period,
		 * we need to reset all currently active grace periods.
		 */
		rfs4_grace_reset_all();
	}

	if (rfs4_dss_numnewpaths > 0)
		kmem_free(added_paths, rfs4_dss_numnewpaths * sizeof (char *));
}

/*
 * Used by NFSv3 and NFSv4 server to query label of
 * a pathname component during lookup/access ops.
 */
ts_label_t *
nfs_getflabel(vnode_t *vp, struct exportinfo *exi)
{
	zone_t *zone;
	ts_label_t *zone_label;
	char *path;

	mutex_enter(&vp->v_lock);
	if (vp->v_path != NULL) {
		zone = zone_find_by_any_path(vp->v_path, B_FALSE);
		mutex_exit(&vp->v_lock);
	} else {
		/*
		 * v_path not cached. Fall back on pathname of exported
		 * file system as we rely on pathname from which we can
		 * derive a label. The exported file system portion of
		 * path is sufficient to obtain a label.
		 */
		path = exi->exi_export.ex_path;
		if (path == NULL) {
			mutex_exit(&vp->v_lock);
			return (NULL);
		}
		zone = zone_find_by_any_path(path, B_FALSE);
		mutex_exit(&vp->v_lock);
	}
	/*
	 * Caller has verified that the file is either
	 * exported or visible. So if the path falls in
	 * global zone, admin_low is returned; otherwise
	 * the zone's label is returned.
	 */
	zone_label = zone->zone_slabel;
	label_hold(zone_label);
	zone_rele(zone);
	return (zone_label);
}

/*
 * TX NFS routine used by NFSv3 and NFSv4 to do label check
 * on client label and server's file object lable.
 */
boolean_t
do_rfs_label_check(bslabel_t *clabel, vnode_t *vp, int flag,
    struct exportinfo *exi)
{
	bslabel_t *slabel;
	ts_label_t *tslabel;
	boolean_t result;

	if ((tslabel = nfs_getflabel(vp, exi)) == NULL) {
		return (B_FALSE);
	}
	slabel = label2bslabel(tslabel);
	DTRACE_PROBE4(tx__rfs__log__info__labelcheck, char *,
	    "comparing server's file label(1) with client label(2) (vp(3))",
	    bslabel_t *, slabel, bslabel_t *, clabel, vnode_t *, vp);

	if (flag == EQUALITY_CHECK)
		result = blequal(clabel, slabel);
	else
		result = bldominates(clabel, slabel);
	label_rele(tslabel);
	return (result);
}

/*
 * Callback function to return the loaned buffers.
 * Calls VOP_RETZCBUF() only after all uio_iov[]
 * buffers are returned. nu_ref maintains the count.
 */
void
rfs_free_xuio(void *free_arg)
{
	uint_t ref;
	nfs_xuio_t *nfsuiop = (nfs_xuio_t *)free_arg;

	ref = atomic_dec_uint_nv(&nfsuiop->nu_ref);

	/*
	 * Call VOP_RETZCBUF() only when all the iov buffers
	 * are sent OTW.
	 */
	if (ref != 0)
		return;

	if (((uio_t *)nfsuiop)->uio_extflg & UIO_XUIO) {
		(void) VOP_RETZCBUF(nfsuiop->nu_vp, (xuio_t *)free_arg, NULL,
		    NULL);
		VN_RELE(nfsuiop->nu_vp);
	}

	kmem_cache_free(nfs_xuio_cache, free_arg);
}

xuio_t *
rfs_setup_xuio(vnode_t *vp)
{
	nfs_xuio_t *nfsuiop;

	nfsuiop = kmem_cache_alloc(nfs_xuio_cache, KM_SLEEP);

	bzero(nfsuiop, sizeof (nfs_xuio_t));
	nfsuiop->nu_vp = vp;

	/*
	 * ref count set to 1. more may be added
	 * if multiple mblks refer to multiple iov's.
	 * This is done in uio_to_mblk().
	 */

	nfsuiop->nu_ref = 1;

	nfsuiop->nu_frtn.free_func = rfs_free_xuio;
	nfsuiop->nu_frtn.free_arg = (char *)nfsuiop;

	nfsuiop->nu_uio.xu_type = UIOTYPE_ZEROCOPY;

	return (&nfsuiop->nu_uio);
}

mblk_t *
uio_to_mblk(uio_t *uiop)
{
	struct iovec *iovp;
	int i;
	mblk_t *mp, *mp1;
	nfs_xuio_t *nfsuiop = (nfs_xuio_t *)uiop;

	if (uiop->uio_iovcnt == 0)
		return (NULL);

	iovp = uiop->uio_iov;
	mp = mp1 = esballoca((uchar_t *)iovp->iov_base, iovp->iov_len,
	    BPRI_MED, &nfsuiop->nu_frtn);
	ASSERT(mp != NULL);

	mp->b_wptr += iovp->iov_len;
	mp->b_datap->db_type = M_DATA;

	for (i = 1; i < uiop->uio_iovcnt; i++) {
		iovp = (uiop->uio_iov + i);

		mp1->b_cont = esballoca(
		    (uchar_t *)iovp->iov_base, iovp->iov_len, BPRI_MED,
		    &nfsuiop->nu_frtn);

		mp1 = mp1->b_cont;
		ASSERT(mp1 != NULL);
		mp1->b_wptr += iovp->iov_len;
		mp1->b_datap->db_type = M_DATA;
	}

	nfsuiop->nu_ref = uiop->uio_iovcnt;

	return (mp);
}

/*
 * Allocate memory to hold data for a read request of len bytes.
 *
 * We don't allocate buffers greater than kmem_max_cached in size to avoid
 * allocating memory from the kmem_oversized arena.  If we allocate oversized
 * buffers, we incur heavy cross-call activity when freeing these large buffers
 * in the TCP receive path. Note that we can't set b_wptr here since the
 * length of the data returned may differ from the length requested when
 * reading the end of a file; we set b_wptr in rfs_rndup_mblks() once the
 * length of the read is known.
 */
mblk_t *
rfs_read_alloc(uint_t len, struct iovec **iov, int *iovcnt)
{
	struct iovec *iovarr;
	mblk_t *mp, **mpp = &mp;
	size_t mpsize;
	uint_t remain = len;
	int i, err = 0;

	*iovcnt = howmany(len, kmem_max_cached);

	iovarr = kmem_alloc(*iovcnt * sizeof (struct iovec), KM_SLEEP);
	*iov = iovarr;

	for (i = 0; i < *iovcnt; remain -= mpsize, i++) {
		ASSERT(remain <= len);
		/*
		 * We roundup the size we allocate to a multiple of
		 * BYTES_PER_XDR_UNIT (4 bytes) so that the call to
		 * xdrmblk_putmblk() never fails.
		 */
		ASSERT(kmem_max_cached % BYTES_PER_XDR_UNIT == 0);
		mpsize = MIN(kmem_max_cached, remain);
		*mpp = allocb_wait(RNDUP(mpsize), BPRI_MED, STR_NOSIG, &err);
		ASSERT(*mpp != NULL);
		ASSERT(err == 0);

		iovarr[i].iov_base = (caddr_t)(*mpp)->b_rptr;
		iovarr[i].iov_len = mpsize;
		mpp = &(*mpp)->b_cont;
	}
	return (mp);
}

void
rfs_rndup_mblks(mblk_t *mp, uint_t len, int buf_loaned)
{
	int i;
	int alloc_err = 0;
	mblk_t *rmp;
	uint_t mpsize, remainder;

	remainder = P2NPHASE(len, BYTES_PER_XDR_UNIT);

	/*
	 * Non copy-reduction case.  This function assumes that blocks were
	 * allocated in multiples of BYTES_PER_XDR_UNIT bytes, which makes this
	 * padding safe without bounds checking.
	 */
	if (!buf_loaned) {
		/*
		 * Set the size of each mblk in the chain until we've consumed
		 * the specified length for all but the last one.
		 */
		while ((mpsize = MBLKSIZE(mp)) < len) {
			ASSERT(mpsize % BYTES_PER_XDR_UNIT == 0);
			mp->b_wptr += mpsize;
			len -= mpsize;
			mp = mp->b_cont;
			ASSERT(mp != NULL);
		}

		ASSERT(len + remainder <= mpsize);
		mp->b_wptr += len;
		for (i = 0; i < remainder; i++)
			*mp->b_wptr++ = '\0';
		return;
	}

	/*
	 * No remainder mblk required.
	 */
	if (remainder == 0)
		return;

	/*
	 * Get to the last mblk in the chain.
	 */
	while (mp->b_cont != NULL)
		mp = mp->b_cont;

	/*
	 * In case of copy-reduction mblks, the size of the mblks are fixed
	 * and are of the size of the loaned buffers.  Allocate a remainder
	 * mblk and chain it to the data buffers. This is sub-optimal, but not
	 * expected to happen commonly.
	 */
	rmp = allocb_wait(remainder, BPRI_MED, STR_NOSIG, &alloc_err);
	ASSERT(rmp != NULL);
	ASSERT(alloc_err == 0);

	for (i = 0; i < remainder; i++)
		*rmp->b_wptr++ = '\0';

	rmp->b_datap->db_type = M_DATA;
	mp->b_cont = rmp;
}
