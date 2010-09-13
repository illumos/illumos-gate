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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <stropts.h>
#include <sys/termios.h>
#include <syslog.h>
#include <rpcsvc/bootparam_prot.h>

#include "bootparam_private.h"

#define	_RPCSVC_CLOSEDOWN 120

int debug = 0;

static void bootparamprog_1(struct svc_req *, register SVCXPRT *);
static void closedown(int);

static int server_child = 0;	/* program was started by another server */
static int _rpcsvcdirty;	/* Still serving ? */

int
main(int argc, char *argv[])
{
	pid_t pid;
	int c;
	char *progname = argv[0];
	int connmaxrec = RPC_MAXDATASIZE;

	while ((c = getopt(argc, argv, "d")) != -1)
		switch ((char)c) {
		case 'd':
			debug++;
			break;
		default:
			(void) fprintf(stderr, "usage: %s [-d]\n", progname);
			exit(EXIT_FAILURE);
		}


	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		msgout("unable to set maximum RPC record size");
	}

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

		if ((netid = getenv("NLSPROVIDER")) == NULL) {
			if (debug)
				msgout("cannot get transport name");
		} else if ((nconf = getnetconfigent(netid)) == NULL) {
			if (debug)
				msgout("cannot get transport info");
		}
		pmclose = (t_getstate(0) != T_DATAXFER);
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			msgout("cannot create server handle");
			exit(EXIT_FAILURE);
		}
		if (nconf)
			freenetconfigent(nconf);
		if (!svc_reg(transp, BOOTPARAMPROG, BOOTPARAMVERS,
		    bootparamprog_1, 0)) {
			msgout("unable to register (BOOTPARAMPROG, "
			    "BOOTPARAMVERS).");
			exit(EXIT_FAILURE);
		}
		if (pmclose) {
			(void) signal(SIGALRM, closedown);
			(void) alarm(_RPCSVC_CLOSEDOWN);
		}

		svc_run();
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}

	/*
	 * run this process in the background only if it was started from
	 * a shell and the debug flag was not given.
	 */
	if (!server_child && !debug) {
		pid = fork();
		if (pid < 0) {
			perror("cannot fork");
			exit(EXIT_FAILURE);
		}
		if (pid)
			exit(EXIT_SUCCESS);

		closefrom(0);
		(void) setsid();
	}

	/*
	 * messges go to syslog if the program was started by
	 * another server, or if it was run from the command line without
	 * the debug flag.
	 */
	if (server_child || !debug)
		openlog("bootparam_prot", LOG_PID, LOG_DAEMON);

	if (debug) {
		if (debug == 1)
			msgout("in debug mode.");
		else
			msgout("in debug mode (level %d).", debug);
	}

	if (!svc_create(bootparamprog_1, BOOTPARAMPROG, BOOTPARAMVERS,
			"netpath")) {
		msgout("unable to create (BOOTPARAMPROG, BOOTPARAMVERS) "
		    "for netpath.");
		exit(EXIT_FAILURE);
	}

	svc_run();
	msgout("svc_run returned");
	return (EXIT_FAILURE);
}

static void
bootparamprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		bp_whoami_arg bootparamproc_whoami_1_arg;
		bp_getfile_arg bootparamproc_getfile_1_arg;
	} argument;
	char *result;
	bool_t (*xdr_argument)(), (*xdr_result)();
	char *(*local)();

	_rpcsvcdirty = 1;
	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void, (char *)NULL);
		_rpcsvcdirty = 0;
		return;

	case BOOTPARAMPROC_WHOAMI:
		xdr_argument = xdr_bp_whoami_arg;
		xdr_result = xdr_bp_whoami_res;
		local = (char *(*)()) bootparamproc_whoami_1;
		break;

	case BOOTPARAMPROC_GETFILE:
		xdr_argument = xdr_bp_getfile_arg;
		xdr_result = xdr_bp_getfile_res;
		local = (char *(*)()) bootparamproc_getfile_1;
		break;

	default:
		svcerr_noproc(transp);
		_rpcsvcdirty = 0;
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		_rpcsvcdirty = 0;
		return;
	}
	result = (*local)(&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		msgout("unable to free arguments");
		exit(EXIT_FAILURE);
	}
	_rpcsvcdirty = 0;
}

/*PRINTFLIKE1*/
void
msgout(char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	/*
	 * messges go to syslog if the program was started by
	 * another server, or if it was run from the command line without
	 * the debug flag.
	 */
	if (server_child || !debug)
		vsyslog(LOG_ERR, fmt, ap);
	else {
		(void) vfprintf(stderr, fmt, ap);
		(void) fputc('\n', stderr);
	}
	va_end(ap);
}

/* ARGSUSED */
static void
closedown(int sig)
{
	if (_rpcsvcdirty == 0) {
		int size;
		int i, openfd;
		struct t_info tinfo;

		if (!t_getinfo(0, &tinfo) && (tinfo.servtype == T_CLTS))
			exit(EXIT_SUCCESS);
		size = svc_max_pollfd;
		for (i = 0, openfd = 0; i < size && openfd < 2; i++)
			if (svc_pollfd[i].fd >= 0)
				openfd++;
		if (openfd <= 1)
			exit(EXIT_SUCCESS);
	}
	(void) alarm(_RPCSVC_CLOSEDOWN);
}
