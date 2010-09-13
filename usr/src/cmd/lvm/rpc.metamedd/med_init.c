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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "med_local.h"
#include <sdssc.h>

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <netdir.h>
#include <netdb.h>
#include <sys/resource.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/utsname.h>

extern	void	nc_perror(const char *msg);

/* daemon name */
static char	*medname = MED_SERVNAME;

/*
 * reset and exit daemon
 */
void
med_exit(
	int	eval
)
{
	med_err_t	status = med_null_err;

	if (med_db_finit(&status))
		medde_perror(&status, "med_db_finit");

	/* log exit */
	med_eprintf("exiting with %d\n", eval);

	/* exit with value */
	exit(eval);
}

/*
 * signal catchers
 */
static void
med_catcher(
	int	sig
)
{
	char	buf[128];
	char	*msg;

	/* log signal */
	if ((msg = strsignal(sig)) == NULL) {
		(void) sprintf(buf, "unknown signal %d", sig);
		msg = buf;
	}
	med_eprintf("%s\n", msg);

	/* let default handler do it's thing */
	(void) sigset(sig, SIG_DFL);
	if (kill(getpid(), sig) != 0) {
		med_perror("kill(getpid())");
		med_exit(-sig);
	}
}

/*
 * initialize daemon
 */
static int
med_setup(
	med_err_t	*medep
)
{
	/* catch common signals */
	if ((sigset(SIGHUP, med_catcher) == SIG_ERR) ||
	    (sigset(SIGINT, med_catcher) == SIG_ERR) ||
	    (sigset(SIGABRT, med_catcher) == SIG_ERR) ||
	    (sigset(SIGBUS, med_catcher) == SIG_ERR) ||
	    (sigset(SIGSEGV, med_catcher) == SIG_ERR) ||
	    (sigset(SIGPIPE, med_catcher) == SIG_ERR) ||
	    (sigset(SIGTERM, med_catcher) == SIG_ERR)) {
		return (med_error(medep, errno, "sigset"));
	}

	/* ignore SIGALRM (used in med_cv_timedwait) */
	if (sigset(SIGALRM, SIG_IGN) == SIG_ERR) {
		return (med_error(medep, errno, "sigset"));
	}

	/* return success */
	return (0);
}

/*
 * (re)initalize daemon
 */
static int
med_init_daemon(
	med_err_t	*medep
)
{
	static int	already = 0;

	/* setup */
	if (! already) {
		if (med_setup(medep) != 0)
			return (-1);
		openlog(medname, LOG_CONS, LOG_DAEMON);
		already = 1;
	}

	/* return success */
	return (0);
}

/*
 * get my nodename
 */
char *
mynode(void)
{
	static struct utsname	myuname;
	static int		done = 0;

	if (! done) {
		if (uname(&myuname) == -1) {
			med_perror("uname");
			assert(0);
		}
		done = 1;
	}
	return (myuname.nodename);
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
		med_eprintf("transp->xp_netid == NULL\n");
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

		/* localhost is OK */
		if (strcmp(hostname, mynode()) == 0) {
			rval = 0;
			goto out;
		}

		if (strcmp(hostname, "localhost") == 0) {
			rval = 0;
			goto out;
		}

		/* check for remote root access */
		if (ruserok(hostname, 1, "root", "root") == 0) {
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
	if (pwp->pw_gid == MED_GID)
		return (0);

	/* check in group */
	if ((grp = getgrgid(MED_GID)) == NULL)
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
	med_err_t		*medep		/* returned status */
)
{
#ifdef	_REENTRANT
	static mutex_t		mx = DEFAULTMUTEX;
#endif	/* _REENTRANT */
	struct authsys_parms	*sys_credp;

	/* for read, anything is OK */
	if (! (amode & W_OK))
		return (0);

#ifdef	_REENTRANT
	/* single thread (not really needed if daemon stays single threaded) */
	mutex_lock(&mx);
#endif	/* _REENTRANT */

	/* check for remote root or METAMED_GID */
	/*LINTED*/
	sys_credp = (struct authsys_parms *)rqstp->rq_clntcred;
	if ((check_gid14(sys_credp->aup_uid) == 0) ||
	    (check_host(rqstp) == 0)) {
#ifdef	_REENTRANT
		mutex_unlock(&mx);
#endif	/* _REENTRANT */
		return (0);
	}

	/* return failure */
#ifdef	_REENTRANT
	mutex_unlock(&mx);
#endif	/* _REENTRANT */
	return (med_error(medep, EACCES, medname));
}

/*
 * setup RPC service
 *
 * if can't authenticate return < 0
 * if any other error return > 0
 */
int
med_init(
	struct svc_req	*rqstp,		/* RPC stuff */
	int		amode,		/* R_OK | W_OK */
	med_err_t	*medep		/* returned status */
)
{
	SVCXPRT		*transp = rqstp->rq_xprt;

	/*
	 * initialize
	 */
	(void) memset(medep, 0, sizeof (*medep));

	if (sdssc_bind_library() == SDSSC_ERROR) {
		(void) med_error(medep, EACCES,
		    "can't bind to cluster library");
		return (1);
	}

	/*
	 * check credentials
	 */
	switch (rqstp->rq_cred.oa_flavor) {

	/* UNIX flavor */
	case AUTH_SYS:
	{
		if (check_sys(rqstp, amode, medep) != 0)
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
	if (med_init_daemon(medep) != 0)
		return (1);		/* error */

	/* return success */
	return (0);
}
