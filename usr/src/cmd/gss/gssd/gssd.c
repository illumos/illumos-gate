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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Usermode daemon which assists the kernel when handling gssapi calls.
 * It is gssd that actually implements all gssapi calls.
 * Some calls, such as gss_sign, are implemented in the kernel on a per
 * mechanism basis.
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <sys/syslog.h>
#include <sys/termios.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <stdlib.h>
#include <stropts.h>
#include <fcntl.h>
#include <strings.h>
#include <signal.h>
#include <syslog.h>
#include "gssd.h"

int gssd_debug = 0;		/* enable debugging printfs */
extern void gsscred_set_options(void);

void gssprog_1();
void gssd_setup(char *);
static void usage(void);
static void daemonize_start();
static void daemonize_ready(unsigned char status);
extern int  svc_create_local_service();

/* following declarations needed in rpcgen-generated code */
int _rpcpmstart = 0;		/* Started by a port monitor ? */
int _rpcfdtype;			/* Whether Stream or Datagram ? */
int _rpcsvcdirty;		/* Still serving ? */
mutex_t _svcstate_lock = ERRORCHECKMUTEX;

static void
/* LINTED */
catch_hup(int sig_num)
{
	sigset_t mask_set;  /* used to set a signal masking set. */
	sigset_t old_set;   /* used to store the old mask set.   */

	/* re-set the signal handler again to catch_hup, for next time */
	(void) signal(SIGHUP, catch_hup);
	/* mask any further signals while we're inside the handler. */
	(void) sigfillset(&mask_set);
	(void) sigprocmask(SIG_SETMASK, &mask_set, &old_set);

	gsscred_set_options();

	/* let admin know the sighup was caught and conf file re-read */
	syslog(LOG_INFO,
	    "catch_hup: read gsscred.conf opts");
	if (gssd_debug)
		(void) fprintf(stderr, "catch_hup: read gsscred.conf opts");

	(void) sigprocmask(SIG_SETMASK, &old_set, NULL);
}


int
main(int argc, char **argv)
{
	register SVCXPRT *transp;
	int maxrecsz = RPC_MAXDATASIZE;
	extern int optind;
	int c;
	char mname[FMNAMESZ + 1];

	/* set locale and domain for internationalization */
	setlocale(LC_ALL, "");
	textdomain(TEXT_DOMAIN);

	/*
	 * Take special note that "getuid()" is called here.  This call is used
	 * rather than app_krb5_user_uid(), to ensure gssd(1M) is running as
	 * root.
	 */
#ifdef DEBUG
	(void) setuid(0);		/* DEBUG: set ruid to root */
#endif /* DEBUG */
	if (getuid()) {
		(void) fprintf(stderr,
		    gettext("[%s] must be run as root\n"), argv[0]);
#ifdef DEBUG
		(void) fprintf(stderr, gettext(" warning only\n"));
#else /* DEBUG */
		exit(1);
#endif /* DEBUG */
	}

	gssd_setup(argv[0]);

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c) {
		case 'd':
			/* turn on debugging */
			gssd_debug = 1;
			break;
		default:
			usage();
		}

	if (optind != argc) {
		usage();
	}

	gsscred_set_options();
	(void) signal(SIGHUP, catch_hup);

	/*
	 * Started by inetd if name of module just below stream
	 * head is either a sockmod or timod.
	 */
	if (!ioctl(0, I_LOOK, mname) && ((strcmp(mname, "sockmod") == 0) ||
	    (strcmp(mname, "timod") == 0))) {

		char *netid;
		struct netconfig *nconf;

		openlog("gssd", LOG_PID, LOG_DAEMON);

		if ((netid = getenv("NLSPROVIDER")) ==  NULL) {
			netid = "ticotsord";
		}

		if ((nconf = getnetconfigent(netid)) == NULL) {
			syslog(LOG_ERR, gettext("cannot get transport info"));
			exit(1);
		}

		if (strcmp(mname, "sockmod") == 0) {
			if (ioctl(0, I_POP, 0) || ioctl(0, I_PUSH, "timod")) {
				syslog(LOG_ERR,
				    gettext("could not get the "
				    "right module"));
				exit(1);
			}
		}
		if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrecsz)) {
			syslog(LOG_ERR,
			    gettext("unable to set RPC max record size"));
			exit(1);
		}
		/* XXX - is nconf even needed here? */
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			syslog(LOG_ERR, gettext("cannot create server handle"));
			exit(1);
		}

		/*
		 * We use a NULL nconf because GSSPROG has already been
		 * registered with rpcbind.
		 */
		if (!svc_reg(transp, GSSPROG, GSSVERS, gssprog_1, NULL)) {
			syslog(LOG_ERR,
			    gettext("unable to register "
			    "(GSSPROG, GSSVERS)"));
			exit(1);
		}

		if (nconf)
			freenetconfigent(nconf);
	} else {
		if (!gssd_debug)
			daemonize_start();

		openlog("gssd", LOG_PID, LOG_DAEMON);

		if (svc_create_local_service(gssprog_1, GSSPROG, GSSVERS,
		    "netpath", "gssd") == 0) {
			syslog(LOG_ERR, gettext("unable to create service"));
			exit(1);
		}

		/* service created, now the daemon parent can exit */
		daemonize_ready(0);
	}


	if (gssd_debug) {
		fprintf(stderr,
		    gettext("gssd start: \n"));
	}
	svc_run();
	abort();
	/*NOTREACHED*/
#ifdef	lint
	return (1);
#endif
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: gssd [-dg]\n"));
	exit(1);
}


/*
 * Fork, detach from tty, etc...
 */
static int write_pipe_fd = -1;
static
void
daemonize_start()
{
	int pipe_fds[2];
	unsigned char status = 1;

	closefrom(0);

	/* Open stdin/out/err, chdir, get a pipe */
	if (open("/dev/null", O_RDONLY) < 0 ||
	    open("/dev/null", O_WRONLY) < 0 || dup(1) < 0 ||
	    chdir("/") < 0 || pipe(pipe_fds) < 0)
		exit(1);

	/* For daemonize_ready() */
	write_pipe_fd = pipe_fds[1];

	switch (fork()) {
	case -1:
		exit(1);
		/* NOTREACHED */
	case 0:
		break;
	default:
		/* Wait for child to be ready befor exiting */
		(void) close(pipe_fds[1]);
		(void) signal(SIGPIPE, SIG_DFL);
		(void) read(pipe_fds[0], &status, sizeof (status));
		exit(status);
	}

	(void) close(pipe_fds[0]);
	(void) setsid();
}

static
void
daemonize_ready(unsigned char status)
{
	if (write_pipe_fd == -1)
		return;

	(void) write(write_pipe_fd, &status, sizeof (status));
	(void) close(write_pipe_fd);
	write_pipe_fd = -1;
}

/*ARGSUSED*/
int
gssprog_1_freeresult(SVCXPRT *transport, xdrproc_t xdr_res, caddr_t res)
{
	xdr_free(xdr_res, res);
	return (1);
}
