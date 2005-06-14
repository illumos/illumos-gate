/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/types.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/siginfo.h>
#include <sys/proc.h>		/* for exit() declaration */
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <sys/thread.h>
#include <rpc/auth.h>
#include <rpc/rpcsys.h>
#include <rpc/svc.h>

/*
 * This is filled in with an appropriate address for the
 * function that will traverse the rfs4_client_t table
 * and mark any matching IP Address as "forced_expire".
 *
 * It is the server init() function that plops the
 * function pointer.
 */
void (*rfs4_client_clrst)(struct nfs4clrst_args *) = NULL;

/* This filled in by nfssrv:_init() */
void (*nfs_srv_quiesce_func)(void) = NULL;

/*
 * These will be reset by klmmod:lm_svc(), when lockd starts NLM service,
 * based on values read by lockd from /etc/default/nfs. Since nfssrv depends on
 * klmmod, the declarations need to be here (in nfs, on which both depend) so
 * that nfssrv can see the klmmod changes.
 * When the dependency of NFSv4 on NLM/lockd is removed, this will need to
 * be adjusted.
 */
#define	RFS4_LEASETIME 90			/* seconds */
time_t rfs4_lease_time = RFS4_LEASETIME;
time_t rfs4_grace_period = RFS4_LEASETIME;

int
nfssys(enum nfssys_op opcode, void *arg)
{
	int error = 0;

	if (!(opcode == NFS_REVAUTH || opcode == NFS4_SVC) &&
	    secpolicy_nfs(CRED()) != 0)
		return (set_errno(EPERM));

	switch (opcode) {
	case NFS4_CLR_STATE: { /* Clear NFS4 client state */
		struct nfs4clrst_args clr;
		STRUCT_DECL(nfs4clrst_args, u_clr);

		/*
		 * If the server is not loaded then no point in
		 * clearing nothing :-)
		 */
		if (rfs4_client_clrst == NULL) {
			break;
		}

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));

		STRUCT_INIT(u_clr, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(u_clr), STRUCT_SIZE(u_clr)))
			return (set_errno(EFAULT));

		clr.vers = STRUCT_FGET(u_clr, vers);

		if (clr.vers != NFS4_CLRST_VERSION)
			return (set_errno(EINVAL));

		clr.addr_type = STRUCT_FGET(u_clr, addr_type);
		clr.ap = STRUCT_FGETP(u_clr, ap);
		rfs4_client_clrst(&clr);
		break;
	}

	case SVCPOOL_CREATE: { /* setup an RPC server thread pool */
		struct svcpool_args p;

		if (copyin(arg, &p, sizeof (p)))
			return (set_errno(EFAULT));

		error = svc_pool_create(&p);
		break;
	}

	case SVCPOOL_WAIT: { /* wait in kernel for threads to be needed */
		int id;

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_wait(id);
		break;
	}

	case SVCPOOL_RUN: { /* give work to a runnable thread */
		int id;

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_do_run(id);
		break;
	}

	case RDMA_SVC_INIT: {
		struct rdma_svc_args rsa;
		char netstore[20] = "tcp";

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			STRUCT_DECL(rdma_svc_args, ursa);

			STRUCT_INIT(ursa, get_udatamodel());
			if (copyin(arg, STRUCT_BUF(ursa), STRUCT_SIZE(ursa)))
				return (set_errno(EFAULT));

			rsa.poolid = STRUCT_FGET(ursa, poolid);
			rsa.nfs_versmin = STRUCT_FGET(ursa, nfs_versmin);
			rsa.nfs_versmax = STRUCT_FGET(ursa, nfs_versmax);
			rsa.delegation = STRUCT_FGET(ursa, delegation);
		} else {
			if (copyin(arg, &rsa, sizeof (rsa)))
				return (set_errno(EFAULT));
		}
		rsa.netid = netstore;

		error = rdma_start(&rsa);
		break;
	}

	case NFS_SVC: { /* NFS server daemon */
		STRUCT_DECL(nfs_svc_args, nsa);

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		STRUCT_INIT(nsa, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(nsa), STRUCT_SIZE(nsa)))
			return (set_errno(EFAULT));

		error = nfs_svc(STRUCT_BUF(nsa), get_udatamodel());
		break;
	}

	/* Request that NFS server quiesce on next shutdown */
	case NFS_SVC_REQUEST_QUIESCE: {
		int id;

		/* check that nfssrv module is loaded */
		if (nfs_srv_quiesce_func == NULL)
			return (set_errno(ENOTSUP));

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_pool_control(id, SVCPSET_SHUTDOWN_PROC,
		    (void *)nfs_srv_quiesce_func);
		break;
	}

	case EXPORTFS: { /* export a file system */
		STRUCT_DECL(exportfs_args, ea);

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		STRUCT_INIT(ea, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(ea), STRUCT_SIZE(ea)))
			return (set_errno(EFAULT));

		error = exportfs(STRUCT_BUF(ea), get_udatamodel(), CRED());
		break;
	}

	case NFS_GETFH: { /* get a file handle */
		STRUCT_DECL(nfs_getfh_args, nga);

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		STRUCT_INIT(nga, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nga), STRUCT_SIZE(nga)))
			return (set_errno(EFAULT));

		error = nfs_getfh(STRUCT_BUF(nga), get_udatamodel(), CRED());
		break;
	}

	case NFS_REVAUTH: { /* revoke the cached credentials for the uid */
		STRUCT_DECL(nfs_revauth_args, nra);

		STRUCT_INIT(nra, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nra), STRUCT_SIZE(nra)))
			return (set_errno(EFAULT));

		/* This call performs its own privilege checking */
		error = sec_clnt_revoke(STRUCT_FGET(nra, authtype),
		    STRUCT_FGET(nra, uid), CRED(), NULL, get_udatamodel());
		break;
	}

	case LM_SVC: { /* LM server daemon */
		struct lm_svc_args lsa;

		if (get_udatamodel() != DATAMODEL_NATIVE) {
			STRUCT_DECL(lm_svc_args, ulsa);

			STRUCT_INIT(ulsa, get_udatamodel());
			if (copyin(arg, STRUCT_BUF(ulsa), STRUCT_SIZE(ulsa)))
				return (set_errno(EFAULT));

			lsa.version = STRUCT_FGET(ulsa, version);
			lsa.fd = STRUCT_FGET(ulsa, fd);
			lsa.n_fmly = STRUCT_FGET(ulsa, n_fmly);
			lsa.n_proto = STRUCT_FGET(ulsa, n_proto);
			lsa.n_rdev = expldev(STRUCT_FGET(ulsa, n_rdev));
			lsa.debug = STRUCT_FGET(ulsa, debug);
			lsa.timout = STRUCT_FGET(ulsa, timout);
			lsa.grace = STRUCT_FGET(ulsa, grace);
			lsa.retransmittimeout = STRUCT_FGET(ulsa,
			    retransmittimeout);
		} else {
			if (copyin(arg, &lsa, sizeof (lsa)))
				return (set_errno(EFAULT));
		}

		error = lm_svc(&lsa);
		break;
	}

	case KILL_LOCKMGR: {
		error = lm_shutdown();
		break;
	}

	case LOG_FLUSH:	{	/* Flush log buffer and possibly rename */
		STRUCT_DECL(nfsl_flush_args, nfa);

		STRUCT_INIT(nfa, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nfa), STRUCT_SIZE(nfa)))
			return (set_errno(EFAULT));

		error = nfsl_flush(STRUCT_BUF(nfa), get_udatamodel());
		break;
	}

	case NFS4_SVC: { /* NFS client callback daemon */

		STRUCT_DECL(nfs4_svc_args, nsa);

		STRUCT_INIT(nsa, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(nsa), STRUCT_SIZE(nsa)))
			return (set_errno(EFAULT));

		error = nfs4_svc(STRUCT_BUF(nsa), get_udatamodel());
		break;
	}

	case NFS_IDMAP: {
		struct nfsidmap_args idm;

		if (copyin(arg, &idm, sizeof (idm)))
			return (set_errno(EFAULT));

		nfs_idmap_args(&idm);
		error = 0;
		break;
	}

	default:
		error = EINVAL;
		break;
	}

	return ((error != 0) ? set_errno(error) : 0);
}
