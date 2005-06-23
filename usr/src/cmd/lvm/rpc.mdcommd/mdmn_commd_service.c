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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdmn_commd.h>
#include <stdio.h>
#include <stdlib.h> /* getenv, exit */
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <syslog.h>
#include <meta.h>

#ifdef DEBUG
#define	RPC_SVC_FG
#endif

/*
 * This means we shutdown rpc.mdcommd at some time in the window
 * after 1201 seconds and before 2400 seconds of inactivity.
 */
#define	_RPCSVC_CLOSEDOWN 2400

#ifdef RPC_SVC_FG
static int _rpcpmstart;		/* Started by a port monitor ? */
#endif /* RPC_SVC_FG */
/* States a server can be in wrt request */

#define	_IDLE 0
#define	_SERVED 1

static int _rpcsvcstate = _IDLE;	/* Set when a request is serviced */
static int _rpcsvccount = 0;		/* Number of requests being serviced */

extern  md_mn_result_t	*mdmn_send_svc_1();
extern  int		*mdmn_work_svc_1();
extern  int		*mdmn_wakeup_initiator_svc_1();
extern  int		*mdmn_wakeup_master_svc_1();
extern  int		*mdmn_comm_lock_svc_1();
extern  int		*mdmn_comm_unlock_svc_1();
extern  int		*mdmn_comm_suspend_svc_1();
extern  int		*mdmn_comm_resume_svc_1();
extern  int		*mdmn_comm_reinit_set_svc_1();
extern  int		*mdmn_comm_msglock_svc_1();


static void
_msgout(msg)
	char *msg;
{
#ifdef RPC_SVC_FG
	if (_rpcpmstart)
		syslog(LOG_ERR, "%s", msg);
	else
		(void) fprintf(stderr, "%s\n", msg);
#else
	syslog(LOG_ERR, "%s", msg);
#endif
}

static void
closedown(void)
{
	if (_rpcsvcstate == _IDLE && _rpcsvccount == 0) {
		int size;
		int i, openfd = 0;

		size = svc_max_pollfd;
		for (i = 0; i < size && openfd < 2; i++)
			if (svc_pollfd[i].fd >= 0)
				openfd++;
		if (openfd <= 1)
			exit(0);
	} else
		_rpcsvcstate = _IDLE;

	(void) signal(SIGALRM, (void(*)()) closedown);
	(void) alarm(_RPCSVC_CLOSEDOWN/2);
}

static void
mdmn_commd_1(rqstp, transp)
	struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	union {
		md_mn_msg_t mdmn_send_1_arg;
		md_mn_msg_t mdmn_work_1_arg;
		md_mn_result_t mdmn_wakeup_1_arg;
		md_mn_msgclass_t mdmn_comm_lock_1_arg;
		md_mn_msgclass_t mdmn_comm_unlock_1_arg;
		uint_t mdmn_comm_reinit_1_arg;
	} argument;
	char *result;
	bool_t (*_xdr_argument)(), (*_xdr_result)();
	char *(*local)();
	int free_result = 0;


	_rpcsvccount++;
	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void,
			(char *)NULL);
		_rpcsvccount--;
		_rpcsvcstate = _SERVED;
		return;

	case mdmn_send:
		_xdr_argument = xdr_md_mn_msg_t;
		_xdr_result = xdr_md_mn_result_t;
		(void) memset((char *)&argument, 0, sizeof (argument));
		if (!svc_getargs(transp, _xdr_argument, (caddr_t)&argument)) {
			svcerr_decode(transp);
			_rpcsvccount--;
			_rpcsvcstate = _SERVED;
			return;
		}
		/*
		 * mdmn_send_1 will not always do a sendreply.
		 * it will register in a table and let the mdmn_wakeup1
		 * do the sendreply for that call.
		 * in order to register properly we need the transp handle
		 */
		(void) mdmn_send_svc_1((md_mn_msg_t *)&argument, rqstp);

		return; /* xdr_free is called by mdmn_wakeup_initiator_svc_1 */

	case mdmn_work:
		_xdr_argument = xdr_md_mn_msg_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_work_svc_1;
		free_result = 1;
		break;

	case mdmn_wakeup_master:
		_xdr_argument = xdr_md_mn_result_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_wakeup_master_svc_1;
		free_result = 1;
		break;

	case mdmn_wakeup_initiator:
		_xdr_argument = xdr_md_mn_result_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_wakeup_initiator_svc_1;
		free_result = 1;
		break;

	case mdmn_comm_lock:
		_xdr_argument = xdr_md_mn_set_and_class_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_lock_svc_1;
		break;

	case mdmn_comm_unlock:
		_xdr_argument = xdr_md_mn_set_and_class_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_unlock_svc_1;
		break;

	case mdmn_comm_suspend:
		_xdr_argument = xdr_md_mn_set_and_class_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_suspend_svc_1;
		break;

	case mdmn_comm_resume:
		_xdr_argument = xdr_md_mn_set_and_class_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_resume_svc_1;
		break;

	case mdmn_comm_reinit_set:
		_xdr_argument = xdr_u_int;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_reinit_set_svc_1;
		break;

	case mdmn_comm_msglock:
		_xdr_argument = xdr_md_mn_type_and_lock_t;
		_xdr_result = xdr_int;
		local = (char *(*)()) mdmn_comm_msglock_svc_1;
		break;

	default:
		svcerr_noproc(transp);
		_rpcsvccount--;
		_rpcsvcstate = _SERVED;
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, _xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		_rpcsvccount--;
		_rpcsvcstate = _SERVED;
		return;
	}
	result = (*local)(&argument, rqstp);
	if (_xdr_result && result != NULL &&
	    !svc_sendreply(transp, _xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, _xdr_argument, (caddr_t)&argument)) {
		_msgout(gettext("unable to free arguments"));
		exit(1);
	}

	if (free_result == 1) {
		free(result);
	}
	_rpcsvccount--;
	_rpcsvcstate = _SERVED;
}

/*
 * atexit handler to flag the lack of commd to the kernel so that we don't
 * panic due to RPC failures when the commd has been killed.
 */
static void
exit_commd()
{
	md_error_t	ep = mdnullerror;
	(void) metaioctl(MD_MN_SET_COMMD_RUNNING, 0, &ep, "rpc.mdcommd");
}

/* ARGSUSED */
int
main()
{
	pid_t pid;
	int i;
	md_error_t	ep = mdnullerror;

	(void) sigset(SIGPIPE, SIG_IGN);

	/*
	 * If stdin looks like a TLI endpoint, we assume
	 * that we were started by a port monitor. If
	 * t_getstate fails with TBADF, this is not a
	 * TLI endpoint.
	 */
	if (t_getstate(0) != -1 || t_errno != TBADF) {
		char *netid;
		struct netconfig *nconf = NULL;
		SVCXPRT *transp;
		int pmclose;

#ifdef RPC_SVC_FG
		_rpcpmstart = 1;
#endif /* RPC_SVC_FG */
		openlog("mdmn_commd", LOG_PID, LOG_DAEMON);

		if ((netid = getenv("NLSPROVIDER")) == NULL) {
		/* started from inetd */
			pmclose = 1;
		} else {
			if ((nconf = getnetconfigent(netid)) == NULL)
				_msgout(gettext("cannot get transport info"));

			pmclose = (t_getstate(0) != T_DATAXFER);
		}
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			_msgout(gettext("cannot create server handle"));
			exit(1);
		}
		if (nconf)
			freenetconfigent(nconf);
		if (!svc_reg(transp, MDMN_COMMD, ONE, mdmn_commd_1, 0)) {
			_msgout(gettext(
			    "unable to register (MDMN_COMMD, ONE)."));
			exit(1);
		}

		atexit(exit_commd);

		if (pmclose) {
			(void) signal(SIGALRM, (void(*)()) closedown);
			(void) alarm(_RPCSVC_CLOSEDOWN/2);
		}

		(void) metaioctl(MD_MN_SET_COMMD_RUNNING, (void *)1, &ep,
		    "rpc.mdcommd");
		svc_run();
		exit(1);
		/* NOTREACHED */
	}	else {
#ifndef RPC_SVC_FG
#pragma weak closefrom
		/* LINTED */
		extern void closefrom();
		int size;
		struct rlimit rl;
		pid = fork();
		if (pid < 0) {
			perror(gettext("cannot fork"));
			exit(1);
		}
		if (pid)
			exit(0);
		if (closefrom != NULL)
			closefrom(0);
		else {
			rl.rlim_max = 0;
			getrlimit(RLIMIT_NOFILE, &rl);
			if ((size = rl.rlim_max) == 0)
				exit(1);
			for (i = 0; i < size; i++)
				(void) close(i);
		}
		i = open("/dev/null", 2);
		(void) dup2(i, 1);
		(void) dup2(i, 2);
		setsid();
		openlog("mdmn_commd", LOG_PID, LOG_DAEMON);
#endif
	}
	if (!svc_create(mdmn_commd_1, MDMN_COMMD, ONE, "tcp")) {
		_msgout(gettext("unable to create (MDMN_COMMD, ONE) for tcp."));
		exit(1);
	}

	atexit(exit_commd);
	(void) metaioctl(MD_MN_SET_COMMD_RUNNING, (void *)1, &ep,
	    "rpc.mdcommd");

	svc_run();
	_msgout(gettext("svc_run returned"));
	return (1);
}
