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

#include "mhd_local.h"

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio_ext.h>
#include <syslog.h>
#include <netdir.h>
#include <netdb.h>
#include <sys/resource.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/utsname.h>

extern	void	nc_perror(const char *msg);

/* daemon name */
static char	*myname = "rpc.metamhd";

/*
 * reset and exit daemon
 */
void
mhd_exit(
	int	eval
)
{
	/* log exit */
	mhd_eprintf("exiting with %d\n", eval);

	/* exit with value */
	exit(eval);
}

/*
 * signal catchers
 */
static void
mhd_catcher(
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
	mhd_eprintf("%s\n", msg);

	/* let default handler do it's thing */
	(void) sigset(sig, SIG_DFL);
	if (kill(getpid(), sig) != 0) {
		mhd_perror("kill(getpid())");
		mhd_exit(-sig);
	}
}

/*
 * initialize daemon
 */
static int
mhd_setup(
	mhd_error_t	*mhep
)
{
	struct rlimit	rlimit;
	pcinfo_t	pcinfo;
	pcparms_t	pcparms;
	rtparms_t	*rtparmsp = (rtparms_t *)pcparms.pc_clparms;

	/* catch common signals */
	if ((sigset(SIGHUP, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGINT, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGABRT, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGBUS, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGSEGV, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGPIPE, mhd_catcher) == SIG_ERR) ||
	    (sigset(SIGTERM, mhd_catcher) == SIG_ERR)) {
		return (mhd_error(mhep, errno, "sigset"));
	}

	/* ignore SIGHUP (used in mhd_cv_timedwait) */
	if (sigset(SIGALRM, SIG_IGN) == SIG_ERR) {
		return (mhd_error(mhep, errno, "sigset"));
	}

	/* increase number of file descriptors */
	(void) memset(&rlimit, 0, sizeof (rlimit));
	if (getrlimit(RLIMIT_NOFILE, &rlimit) != 0)
		return (mhd_error(mhep, errno, "getrlimit(RLIMIT_NOFILE)"));
	rlimit.rlim_cur = rlimit.rlim_max = 1024;
	if (setrlimit(RLIMIT_NOFILE, &rlimit) != 0)
		return (mhd_error(mhep, errno, "setrlimit(RLIMIT_NOFILE)"));
	(void) enable_extended_FILE_stdio(-1, -1);

	/* set default RT priority */
	(void) memset(&pcinfo, 0, sizeof (pcinfo));
	(void) strncpy(pcinfo.pc_clname, "RT", sizeof (pcinfo.pc_clname));
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) < 0)
		return (mhd_error(mhep, errno, "priocntl(PC_GETCID): \"RT\""));
	(void) memset(&pcparms, 0, sizeof (pcparms));
	pcparms.pc_cid = pcinfo.pc_cid;
	rtparmsp->rt_pri = RT_NOCHANGE;
	rtparmsp->rt_tqsecs = (ulong_t)RT_NOCHANGE;
	rtparmsp->rt_tqnsecs = RT_NOCHANGE;
	if (priocntl(P_PID, getpid(), PC_SETPARMS, (caddr_t)&pcparms) != 0)
		return (mhd_error(mhep, errno, "priocntl(PC_SETPARMS)"));

	/* return success */
	return (0);
}

/*
 * (re)initalize daemon
 */
static int
mhd_init_daemon(
	mhd_error_t	*mhep
)
{
	static int	already = 0;

	/* setup */
	if (! already) {
		if (mhd_setup(mhep) != 0)
			return (-1);
		openlog(myname, LOG_CONS, LOG_DAEMON);
		already = 1;
	}

	/* return success */
	return (0);
}

/*
 * get my nodename
 */
static char *
mynodename()
{
	static struct utsname	myuname;
	static int		done = 0;

	if (! done) {
		if (uname(&myuname) == -1) {
			mhd_perror("uname");
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

	/* check for root */
	/*LINTED*/
	sys_credp = (struct authsys_parms *)rqstp->rq_clntcred;
	assert(sys_credp != NULL);
	if (sys_credp->aup_uid != 0)
		goto out;

	/* get hostnames */
	if (transp->xp_netid == NULL) {
		mhd_eprintf("transp->xp_netid == NULL\n");
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

		/* localhost is OK */
		if (strcmp(hostname, mynodename()) == 0) {
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
	if (pwp->pw_gid == METAMHD_GID)
		return (0);

	/* check in group */
	if ((grp = getgrgid(METAMHD_GID)) == NULL)
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
	mhd_error_t		*mhep		/* returned status */
)
{
	static mutex_t		mx = DEFAULTMUTEX;
	struct authsys_parms	*sys_credp;

	/* for read, anything is OK */
	if (! (amode & W_OK))
		return (0);

	/* single thread (not really needed if daemon stays single threaded) */
	(void) mutex_lock(&mx);

	/* check for remote root or METAMHD_GID */
	/*LINTED*/
	sys_credp = (struct authsys_parms *)rqstp->rq_clntcred;
	if ((check_gid14(sys_credp->aup_uid) == 0) ||
	    (check_host(rqstp) == 0)) {
		(void) mutex_unlock(&mx);
		return (0);
	}

	/* return failure */
	(void) mutex_unlock(&mx);
	return (mhd_error(mhep, EACCES, myname));
}

/*
 * setup RPC service
 *
 * if can't authenticate return < 0
 * if any other error return > 0
 */
int
mhd_init(
	struct svc_req	*rqstp,		/* RPC stuff */
	int		amode,		/* R_OK | W_OK */
	mhd_error_t	*mhep		/* returned status */
)
{
	SVCXPRT		*transp = rqstp->rq_xprt;

	/*
	 * initialize
	 */
	(void) memset(mhep, 0, sizeof (*mhep));

	/*
	 * check credentials
	 */
	switch (rqstp->rq_cred.oa_flavor) {

	/* UNIX flavor */
	case AUTH_SYS:
	{
		if (check_sys(rqstp, amode, mhep) != 0)
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
	if (mhd_init_daemon(mhep) != 0)
		return (1);		/* error */

	/* return success */
	return (0);
}
