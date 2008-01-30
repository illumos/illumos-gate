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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdarg.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <rpc/rpc.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>	/* 5.x includes stdarg.h, varargs.h */
#include <rpcsvc/yp_prot.h>
#include "prnt.h"

#define	YPDNSPROG	123456L /* default prognum: not used */
#define	YPDNSVERS	2L

extern void dispatch(struct svc_req *rqstp, SVCXPRT *transp);
extern void svc_run_as(void);

static struct timeval start_time; /* Time service started running.	*/
int verbose = 0;		/* Verbose mode, 0=off, 1=on		*/
int verbose_out = 0;		/* Verbose ouput, 0=log, 1=stdout	*/
static int background = TRUE;	/* Forground or bkgrd			*/
pid_t ppid = 0;			/* for terminating if nisd dies		*/
static long prognum = YPDNSPROG; /* for cleanup (may want transient)	*/
SVCXPRT *reply_xprt4;		/* used for sendreply (IPv4)		*/
struct netconfig *udp_nconf4;	/* used to set xprt caller in dispatch  */
SVCXPRT *reply_xprt6;		/* used for sendreply (IPv6)		*/
struct netconfig *udp_nconf6;	/* used to set xprt caller in dispatch  */

/*
 * The -v -V is used to distinguiish between verbose to stdout
 * versus verbose to syslog rather then the background flag
 * because this may be started  from a daemon (nisd). When started
 * from a daemon we can't use forground to print to stdout.
 */
static void usage()
{
	(void) fprintf(stderr,
	"usage: rpc.nisd_resolv [-v|-V] [-F[-C xx]] [-t xx] [-p yy]\n");
	(void) fprintf(stderr, "Options supported by this version :\n");
	(void) fprintf(stderr, "\tF - run in forground\n");
	(void) fprintf(stderr,
		"\tC fd - use fd for service xprt (from nisd)\n");
	(void) fprintf(stderr, "\tv - verbose syslog\n");
	(void) fprintf(stderr, "\tV - verbose stdout\n");
	(void) fprintf(stderr, "\tt xx - use transport xxx\n");
	(void) fprintf(stderr, "\tp yy - use transient program# yyy\n");
	(void) fprintf(stderr, "Use SIGUSR1 to toggle verbose mode.\n");
	exit(1);
}

void
prnt(int info_or_err, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (info_or_err == 1 /* error */) {
		if (verbose_out) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) vfprintf(stderr, format, ap);
		} else
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) vsyslog(LOG_ERR, format, ap);
	} else if (verbose) {
		if (verbose_out) {
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) vfprintf(stdout, format, ap);
		} else
			/* LINTED E_SEC_PRINTF_VAR_FMT */
			(void) vsyslog(LOG_INFO, format, ap);
	}

	va_end(ap);
}

void
cleanup(int sig)
{
	/* unreg prog */
	if (sig) prnt(P_INFO, "unregistering resolv server and exiting.\n");
	(void) rpcb_unset(prognum, YPDNSVERS, NULL);
	exit(0);
}

/* ARGSUSED */
static void
toggle_verbose(int sig)
{
	(void) signal(SIGUSR1, toggle_verbose);

	if (verbose) {
		prnt(P_INFO, "verbose turned off.\n");
		verbose = FALSE;
	} else {
		verbose = TRUE;
		prnt(P_INFO, "verbose turned on.\n");
	}
}

/*
 * Callback function passed to fdwalk() to close all files.
 */
static int
void_close(void *use_fdp, int fd)
{
	if (fd != *(int *)use_fdp)
		(void) close(fd);
	return (0);
}

int
main(int argc, char *argv[])
{
	int			use_fd = -2; /* not set */
	int			c;
	SVCXPRT 		*transp;
	char			*t_type = "ticots";
	struct netconfig	*nc;
	int			connmaxrec = RPC_MAXDATASIZE;

	/*
	 * Process the command line arguments
	 */
	opterr = 0;
	(void) chdir("/var/nis");
	while ((c = getopt(argc, argv, "vVFC:p:t:")) != -1) {
		switch (c) {
			case 'v' : /* syslog */
				verbose = TRUE;
				verbose_out = 0;
				break;
			case 'V' : /* stdout */
				verbose = TRUE;
				verbose_out = 1;
				break;
			case 'F' :
				background = FALSE;
				break;
			case 'C' :
				use_fd = atoi(optarg);
				break;
			case 't' :
				t_type = optarg;
				break;
			case 'p' :
				prognum = atol(optarg);
				break;
			case '?':
				usage();
		}
	}

	if (background)  {
		switch (fork()) {
		case -1:
			(void) fprintf(stderr,
				"Couldn't fork a process: exiting.\n");
			exit(1);
			/* NOTREACHED */
		case 0:
			break;
		default:
			exit(0);
		}

		closefrom(0);
		(void) open("/dev/null", O_RDONLY);
		(void) open("/dev/null", O_WRONLY);
		(void) dup(1);
	} else { /* foreground */
		/* pardon the mess: due to transient p# requirement */
		switch (use_fd) {
		case -2: /* -C not used: just close stdin */
			(void) close(0);
			break;
		case -1: /* close all (nisd non transient) */
			closefrom(0);
			break;
		default: /* use use_fd as svc fd; close others (nisd trans) */
			ppid = getppid();
			(void) fdwalk(void_close, &use_fd);
			break;
		}
	}

	if (!verbose_out)
		openlog("rpc.nisd_resolv", LOG_PID+LOG_NOWAIT, LOG_DAEMON);

	(void) signal(SIGUSR1, toggle_verbose);
	(void) signal(SIGINT, cleanup);
	(void) signal(SIGQUIT, cleanup);
	(void) signal(SIGTERM, cleanup);

	(void) gettimeofday(&start_time, 0);
	prnt(P_INFO, "Starting nisd resolv server: %s",
					ctime((time_t *)&start_time.tv_sec));

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		prnt(P_INFO, "unable to set maximum RPC record size\n");
	}

	/* no check for already running since using transient */

	if ((nc = getnetconfigent(t_type)) == NULL) {
		prnt(P_ERR, "cannot get %s netconf.\n", t_type);
		exit(1);
	}
	if (use_fd != -1 && use_fd != -2) {
		/* use passed in fd = use_fd */
		transp = svc_tli_create(use_fd, nc, NULL, YPMSGSZ, YPMSGSZ);
		if (transp == NULL) {
			prnt(P_ERR, "cannot create service xprt.\n");
			exit(1);
		}
		/* parent did rpcb_set(): just add to callout */
		if (!svc_reg(transp, prognum, YPDNSVERS, dispatch, NULL)) {
			prnt(P_ERR, "cannot register service xprt.\n");
			exit(1);
		}
	} else {
		(void) rpcb_unset(prognum, YPDNSVERS, NULL);
		if (!svc_tp_create(dispatch, prognum, YPDNSVERS, nc)) {
			prnt(P_ERR, "cannot create resolv service.\n");
			exit(1);
		}
	}
	freenetconfigent(nc);

	/* Need udp xprt for sendreply()s, but don't reg it. */
	udp_nconf4 = getnetconfigent("udp");
	udp_nconf6 = getnetconfigent("udp6");
	if (udp_nconf4 == 0 && udp_nconf6 == 0) {
		prnt(P_ERR, "cannot get udp/udp6 netconf.\n");
		exit(1);
	}

	if (udp_nconf4 != 0)
		reply_xprt4 = svc_tli_create(RPC_ANYFD, udp_nconf4, NULL,
						YPMSGSZ, YPMSGSZ);
	else
		reply_xprt4 = 0;


	if (udp_nconf6 != 0)
		reply_xprt6 = svc_tli_create(RPC_ANYFD, udp_nconf6, NULL,
						YPMSGSZ, YPMSGSZ);
	else
		reply_xprt6 = 0;

	if (reply_xprt4 == NULL && reply_xprt6 == NULL) {
		prnt(P_ERR, "cannot create udp/udp6 xprt.\n");
		exit(1);
	} else
		prnt(P_INFO, "created sendreply handle(s).\n");

	/* keep udp_nconf[46] which is used later to create nbuf from uaddr */

	prnt(P_INFO, "entering loop.\n");

	svc_run_as();

	return (0);
}
