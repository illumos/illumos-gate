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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "metad_local.h"
#include <metad.h>

#include <grp.h>
#include <pwd.h>
#include <synch.h>
#include <netdir.h>
#include <netdb.h>
#include <sdssc.h>

extern	void	nc_perror(const char *msg);

/*ARGSUSED*/
void
sigalarmhandler(int sig)
{
	md_exit(NULL, 0);
}


/*
 * check for trusted host and user
 */
static int
check_host(
	struct svc_req		*rqstp		/* RPC stuff */
)
{
	struct authsys_parms	*sys_credp;
	SVCXPRT			*transp = rqstp->rq_xprt;
	struct netconfig	*nconfp = NULL;
	struct nd_hostservlist	*hservlistp = NULL;
	int			i;
	int			rval = -1;
	char			*inplace = NULL;

	/* check for root */
	/*LINTED*/
	sys_credp = (struct authsys_parms *)rqstp->rq_clntcred;
	assert(sys_credp != NULL);
	if (sys_credp->aup_uid != 0)
		goto out;

	/* get hostnames */
	if (transp->xp_netid == NULL) {
		md_eprintf("transp->xp_netid == NULL\n");
		goto out;
	}
	if ((nconfp = getnetconfigent(transp->xp_netid)) == NULL) {
#ifdef	DEBUG
		nc_perror("getnetconfigent(transp->xp_netid)");
#endif
		goto out;
	}
	if ((__netdir_getbyaddr_nosrv(nconfp, &hservlistp, &transp->xp_rtaddr)
	    != 0) || (hservlistp == NULL)) {
#ifdef	DEBUG
		netdir_perror("netdir_getbyaddr(transp->xp_rtaddr)");
#endif
		goto out;
	}

	/* check hostnames */
	for (i = 0; (i < hservlistp->h_cnt); ++i) {
		struct nd_hostserv	*hservp = &hservlistp->h_hostservs[i];
		char			*hostname = hservp->h_host;

		inplace = strdup(hostname);

		/* localhost is OK */
		if (strcmp(hostname, mynode()) == 0) {
			rval = 0;
			goto out;
		}

		/* check for remote root access */
		if (ruserok(hostname, 1, "root", "root") == 0) {
			rval = 0;
			goto out;
		}

		sdssc_cm_nm2nid(inplace);
		if (strcmp(inplace, hostname)) {

			/*
			 * If the names are now different it indicates
			 * that hostname was converted to a nodeid. This
			 * will only occur if hostname is part of the same
			 * cluster that the current node is in.
			 * If the machine is not running in a cluster than
			 * sdssc_cm_nm2nid is a noop which leaves inplace
			 * alone.
			 */
			rval = 0;
			goto out;
		}
	}

	/* cleanup, return success */
out:
	if (inplace)
		free(inplace);
	if (hservlistp != NULL)
		netdir_free(hservlistp, ND_HOSTSERVLIST);
	if (nconfp != NULL)
		Free(nconfp);
	return (rval);
}

/*
 * check for user in local group 14
 */
static int
check_gid14(
	uid_t		uid
)
{
	struct passwd	*pwp;
	struct group	*grp;
	char		**namep;

	/* get user info, check default GID */
	if ((pwp = getpwuid(uid)) == NULL)
		return (-1);
	if (pwp->pw_gid == METAD_GID)
		return (0);

	/* check in group */
	if ((grp = getgrgid(METAD_GID)) == NULL)
		return (-1);
	for (namep = grp->gr_mem; ((*namep != NULL) && (**namep != '\0'));
	    ++namep) {
		if (strcmp(*namep, pwp->pw_name) == 0)
			return (0);
	}
	return (-1);
}

/*
 * check AUTH_SYS
 */
static int
check_sys(
	struct svc_req		*rqstp,		/* RPC stuff */
	int			amode,		/* R_OK | W_OK */
	md_error_t		*ep		/* returned status */
)
{
	static mutex_t		mx = DEFAULTMUTEX;
	struct authsys_parms	*sys_credp;

	/* for read, anything is OK */
	if (! (amode & W_OK))
		return (0);

	/* single thread (not really needed if daemon stays single threaded) */
	(void) mutex_lock(&mx);

	/* check for remote root or METAD_GID */
	/*LINTED*/
	sys_credp = (struct authsys_parms *)rqstp->rq_clntcred;
	if ((check_gid14(sys_credp->aup_uid) == 0) ||
	    (check_host(rqstp) == 0)) {
		(void) mutex_unlock(&mx);
		return (0);
	}

	/* return failure */
	(void) mutex_unlock(&mx);
	return (mdsyserror(ep, EACCES, "rpc.metad"));
}

/*
 * setup RPC service
 *
 * if can't authenticate return < 0
 * any other error return > 0
 */
int
svc_init(
	struct svc_req	*rqstp,	/* RPC stuff */
	int		amode,	/* R_OK | W_OK */
	md_error_t	*ep	/* returned status */
)
{
	SVCXPRT		*transp;

	if (sdssc_bind_library() == SDSSC_ERROR) {
		(void) mdsyserror(ep, EACCES, "can't bind to cluster library");
		return (1);
	}

	/*
	 * if we have no rpc service info, we must have been
	 * called recursively from within the daemon
	 */
	if (rqstp == NULL) {
		mdclrerror(ep);
		return (0);		/* OK */
	}

	/*
	 * initialize
	 */
	transp = rqstp->rq_xprt;
	assert(transp != NULL);
	*ep = mdnullerror;

	/*
	 * check credentials
	 */
	switch (rqstp->rq_cred.oa_flavor) {

	/* UNIX flavor */
	case AUTH_SYS:
	{
		if (check_sys(rqstp, amode, ep) != 0)
			return (1);	/* error */
		break;
	}

	/* can't authenticate anything else */
	default:
		svcerr_weakauth(transp);
		return (-1);		/* weak authentication */
	}

	/*
	 * (re)initialize
	 */
	if (md_init_daemon("rpc.metad", ep) != 0)
		return (1);		/* error */

	if (set_snarf(ep))
		return (1);

	sr_validate();

	/* success */
	return (0);
}

/*ARGSUSED*/
int
svc_fini(md_error_t *ep)
{
	return (0);
}

int
check_set_lock(
	int		amode,	/* R_OK | W_OK */
	md_setkey_t	*cl_sk,	/* clients idea of set locked */
	md_error_t	*ep	/* returned status */
)
{
	md_setkey_t	*svc_sk;

	if (cl_sk == NULL)
		return (0);

	svc_sk = svc_get_setkey(cl_sk->sk_setno);

	/* The set is not locked */
	if (svc_sk == NULL) {
		if ((amode & W_OK) == W_OK) {
			(void) mddserror(ep, MDE_DS_WRITEWITHSULK,
			    cl_sk->sk_setno, mynode(), NULL, cl_sk->sk_setname);
			return (1);
		}
		return (0);
	}

	/* The set is locked, do we have the key? */
	if (cl_sk->sk_key.tv_sec == svc_sk->sk_key.tv_sec &&
	    cl_sk->sk_key.tv_usec == svc_sk->sk_key.tv_usec)
		return (0);

	(void) mddserror(ep, MDE_DS_SETLOCKED, MD_SET_BAD, mynode(),
	    svc_sk->sk_host, svc_sk->sk_setname);

	return (1);
}
