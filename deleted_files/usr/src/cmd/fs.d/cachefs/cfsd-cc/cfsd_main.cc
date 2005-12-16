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
 * Copyright (c) 1994,1998-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

// -----------------------------------------------------------------
//
//			main.cc
//
// Main routines for cachefs daemon.

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <signal.h>
#include <sysent.h> /* getdtablesize, open */
#include <unistd.h> /* setsid */
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <libintl.h>
#include <locale.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <synch.h>
#include <mdbug-cc/mdbug.h>
#include <common/cachefsd.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"
#include "cfsd_all.h"
#include "cfsd_subr.h"

#define	RPCGEN_ACTION(X) X
#include "cachefsd_tbl.i"

#ifndef SIG_PF
#define	SIG_PF void(*)(int)
#endif

typedef bool_t (* LOCAL)(void *, void *, struct svc_req *);

// global definitions
cfsd_all all;

// forward references
void msgout(char *msgp);
void cachefsdprog_1(struct svc_req *rqstp, register SVCXPRT *transp);
void sigusr1_handler(int, siginfo_t *, void *);


// -----------------------------------------------------------------
//
//			main
//
// Description:
//	main routine for the chart daemon.
// Arguments:
//	argc
//	argv
// Returns:
//	Returns 0 for a normal exit, !0 if an error occurred.
// Preconditions:
//	precond(argv)

int
main(int argc, char **argv)
{
	dbug_enter("main");
	dbug_process("cfsadmin");

	/* verify root */
	if (getuid() != 0) {
		fprintf(stderr, "%s: must be run by root\n", argv[0]);
		return (1);
	}

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	int opt_fork = 0;
	int opt_mt = 0;
	char *opt_root = NULL;

	int c;
	const char *msgp;
	while ((c = getopt(argc, argv, "fmr:#:")) != EOF) {
		switch (c) {
		case 'f':
			opt_fork = 1;
			break;

		case 'm':
			opt_mt = 1;
			break;

		case 'r':
			opt_root = optarg;
			break;

		case '#':	/* dbug args */
			msgp = dbug_push(optarg);
			if (msgp) {
				printf("dbug_push failed \"%s\"\n", msgp);
				return (1);
			}
			break;

		default:
			printf("illegal switch\n");
			return (1);
		}
	}

	pid_t pid;
	int xx;
	char mname[FMNAMESZ + 1];

	// XXX need some way to prevent multiple daemons from running

	dbug_print("info", ("cachefsd started..."));

	if (opt_mt) {
		dbug_print("info", ("MT_AUTO mode set"));
		int mode = RPC_SVC_MT_AUTO;
		if (!rpc_control(RPC_SVC_MTMODE_SET, &mode)) {
			msgout("unable to set automatic MT mode.");
			return (1);
		}
	}

#if 0
	/* XXX change to sigation */
	(void) sigset(SIGPIPE, SIG_IGN);
	(void) sigset(SIGUSR1, sigusr1_handler);

#else
	/* ignore sigpipe */
	struct sigaction nact;
	nact.sa_handler = SIG_IGN;
	nact.sa_sigaction = NULL;
	sigemptyset(&nact.sa_mask);
	nact.sa_flags = 0;
	xx = sigaction(SIGPIPE, &nact, NULL);
	if (xx) {
		dbug_print("error", ("sigaction/SIGPIPE failed %d", errno));
	}

	/* catch sigusr1 signals, used to wake up threads */
	nact.sa_handler = NULL;
	nact.sa_sigaction = sigusr1_handler;
	sigemptyset(&nact.sa_mask);
	nact.sa_flags = SA_SIGINFO;
	xx = sigaction(SIGUSR1, &nact, NULL);
	if (xx) {
		dbug_print("error", ("sigaction failed %d", errno));
	}
#endif

	// do not set up rpc services if just taking care of root
	if (opt_root) {
		dbug_print("info", ("handling just root"));

		// make the fscache object
		cfsd_fscache *fscachep;
		fscachep = new cfsd_fscache("rootcache", opt_root, 1);

		// init the fscache object with mount information
		fscachep->fscache_lock();
		fscachep->fscache_refinc();
		fscachep->fscache_setup();
		fscachep->fscache_mounted(1);
		fscachep->fscache_unlock();

		if (fscachep->fscache_disconnectable() &&
		    fscachep->fscache_mounted()) {
			pid = fork();
			if (pid < 0) {
				perror("cannot fork");
				return (1);
			}
			if (pid)
				return (0);
			closefrom(0);
			xx = open("/dev/console", 2);
			(void) dup2(xx, 1);
			(void) dup2(xx, 2);
			setsid();

			fscachep->fscache_process();
		} else {
			// not disconnectable
			return (1);
		}
		return (0);
	}

	// if a port mapper started us
	else if (!ioctl(0, I_LOOK, mname) &&
		((strcmp(mname, "sockmod") == 0) ||
		(strcmp(mname, "timod") == 0))) {
		char *netid;
		struct netconfig *nconf = NULL;
		SVCXPRT *transp;
		int pmclose;

		dbug_print("info", ("started by portmapper"));

		if ((netid = getenv("NLSPROVIDER")) == NULL) {
		/* started from inetd */
			pmclose = 1;
		} else {
			if ((nconf = getnetconfigent(netid)) == NULL)
				msgout("cannot get transport info");

			pmclose = (t_getstate(0) != T_DATAXFER);
		}
		if (strcmp(mname, "sockmod") == 0) {
			if (ioctl(0, I_POP, 0) || ioctl(0, I_PUSH, "timod")) {
				msgout("could not get the right module");
				return (1);
			}
		}
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			msgout("cannot create server handle");
			return (1);
		}
		if (nconf)
			freenetconfigent(nconf);
		xx = svc_reg(transp, CACHEFSDPROG, CACHEFSDVERS,
			cachefsdprog_1, 0);
		if (!xx) {
			msgout("unable to reg (CACHEFSDPROG, CACHEFSDVERS).");
			return (1);
		}
		if (pmclose) {
#if 0
			(void) signal(SIGALRM, (SIG_PF) closedown);
			(void) alarm(_RPCSVC_CLOSEDOWN/2);
#endif
		}
	}

	// else if started by hand
	else {
		// if we should fork
		if (opt_fork) {
			dbug_print("info", ("forking"));
			pid = fork();
			if (pid < 0) {
				perror("cannot fork");
				return (1);
			}
			if (pid)
				return (0);
			closefrom(0);
			xx = open("/dev/console", 2);
			(void) dup2(xx, 1);
			(void) dup2(xx, 2);
			setsid();
		}

		xx = svc_create(cachefsdprog_1, CACHEFSDPROG, CACHEFSDVERS,
			"tcp");
#if 0
		xx = svc_create(cachefsdprog_1, CACHEFSDPROG, CACHEFSDVERS,
			"netpath");
#endif
		if (!xx) {
			msgout("unable to create (CACHEFSDPROG, CACHEFSDVERS)"
				" for netpath.");
			return (1);
		}
	}

	// find existing caches and mounted file systems
	subr_cache_setup(&all);

	// process requests
	svc_run();

	msgout("svc_run returned");
	return (1);
}


// -----------------------------------------------------------------
//
//			msgout
//
// Description:
//	Outputs an error message to stderr.
// Arguments:
//	msgp
// Returns:
// Preconditions:
//	precond(msgp)

void
msgout(char *msgp)
{
	dbug_enter("msgout");
	dbug_precond(msgp);

	(void) fprintf(stderr, "%s\n", msgp);
}

// -----------------------------------------------------------------
//
//			closedown
//
// Description:
// Arguments:
//	sig
// Returns:
// Preconditions:

// XXX bob: need to shut down daemon if no requests after 5 minutes
// and no chart mounts
#if 0
void
closedown(int sig)
{
	mutex_lock(&_svcstate_lock);
	if (_rpcsvcstate == _IDLE) {
		int size;
		int i, openfd;
		struct t_info tinfo;

		if (!t_getinfo(0, &tinfo) && (tinfo.servtype == T_CLTS))
			exit(0);
		size = svc_max_pollfd;
		for (i = 0, openfd = 0; i < size && openfd < 2; i++) {
			if (svc_pollfd[i].fd >= 0) {
				openfd++;
			}
		}
		if (openfd <= 1) {
			msgout("daemon exiting");
			exit(0);
		}
	}
	if (_rpcsvcstate == _SERVED)
		_rpcsvcstate = _IDLE;

	mutex_unlock(&_svcstate_lock);
	(void) signal(SIGALRM, (SIG_PF) closedown);
	(void) alarm(_RPCSVC_CLOSEDOWN/2);
}
#endif

// -----------------------------------------------------------------
//
//			cachefsdprog_1
//
// Description:
// Arguments:
//	rqstp
//	transp
// Returns:
// Preconditions:
//	precond(rqstp)
//	precond(transp)

void
cachefsdprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	dbug_enter("cachefsdprog_1");

	dbug_precond(rqstp);
	dbug_precond(transp);

	// make sure a valid command number
	int index = rqstp->rq_proc;
	if ((index < 0) || (cachefsdprog_1_nproc <= index)) {
		msgout("bad message");
		svcerr_noproc(transp);
		return;
	}

	// get command information
	struct rpcgen_table *rtp = &cachefsdprog_1_table[index];

	// get memory for the arguments
	void *argumentp = NULL;
	if (rtp->len_arg != 0) {
		argumentp = (void *)new char[rtp->len_arg];
		memset(argumentp, 0, rtp->len_arg);
	}

	// get memory for the results
	void *resultp = NULL;
	if (rtp->len_res != 0)
		resultp = (void *)new char[rtp->len_res];

	// get the arguments
	if (rtp->xdr_arg && argumentp) {
		if (!svc_getargs(transp, rtp->xdr_arg, (caddr_t)argumentp)) {
			svcerr_decode(transp);
			delete argumentp;
			delete resultp;
			return;
		}
	}

	// call the routine to process the command
	LOCAL local = (LOCAL)rtp->proc;
	int xx = (*local)(argumentp, resultp, rqstp);

	// if the command could not be processed
	if (xx == 0) {
		svcerr_systemerr(transp);
	}

	// else send the results back to the caller
	else {
		xx = svc_sendreply(transp, rtp->xdr_res, (caddr_t)resultp);
		if (!xx)
			svcerr_systemerr(transp);

		// free the results
		xx = cachefsdprog_1_freeresult(transp, rtp->xdr_res,
			(caddr_t)resultp);
		if (xx == 0)
			msgout("unable to free results");
	}

	// free the passed in arguments
	if (!svc_freeargs(transp, rtp->xdr_arg, (caddr_t)argumentp)) {
		msgout("unable to free arguments");
		abort();
	}

	delete argumentp;
	delete resultp;
}

//
//			sigusr1_handler
//
// Description:
//	Catches sigusr1 signal so threads wake up.
// Arguments:
// Returns:
// Preconditions:

void
sigusr1_handler(int, siginfo_t *, void *)
{
}
