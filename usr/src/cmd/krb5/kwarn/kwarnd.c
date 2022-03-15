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
 * Usermode daemon which is responsible for sending kerberos credentials
 * expiration warnings to the user, syslog or snmp (eventually), depending
 * on how it is configured through /etc/krb5/warn.conf.
 * the code in this file was borrowed from gssd.c
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <sys/syslog.h>
#include <sys/termios.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <stdlib.h>
#include <stropts.h>
#include <fcntl.h>
#include <strings.h>
#include <syslog.h>
#include <thread.h>
#include <netdb.h>
#include <libgen.h>
#include "kwarnd.h"

#define	MAXTHREADS 64

int kwarnd_debug = 0;		/* enable debugging printfs */

extern void kwarnprog_1(struct svc_req *, register SVCXPRT *);
static void usage(void);
static void detachfromtty(void);
extern int svc_create_local_service(void (*) (),
					ulong_t, ulong_t, char *, char *);
extern void kwarnd_check_warning_list(void);
extern bool_t loadConfigFile(void);

/* following declarations needed in rpcgen-generated code */
int _rpcpmstart = 0;		/* Started by a port monitor ? */
int _rpcfdtype;			/* Whether Stream or Datagram ? */
int _rpcsvcdirty;		/* Still serving ? */
mutex_t _svcstate_lock = ERRORCHECKMUTEX;

char myhostname[MAXHOSTNAMELEN] = {0};
char progname[MAXNAMELEN] = {0};


int
main(int argc, char **argv)
{
	SVCXPRT *transp;
	extern int optind;
	int c;
	char mname[FMNAMESZ + 1];
	int rpc_svc_mode = RPC_SVC_MT_AUTO;

	/* set locale and domain for internationalization */
	setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	textdomain(TEXT_DOMAIN);

	(void) strlcpy(progname, basename(argv[0]), sizeof (progname));

	/*
	 * Take special note that "getuid()" is called here.  This call is used
	 * rather that app_krb5_user_uid(), to ensure ktkt_warnd(8) is running
	 * as root.
	 */
#ifdef DEBUG
	(void) setuid(0);		/* DEBUG: set ruid to root */
#endif /* DEBUG */
	if (getuid()) {
		(void) fprintf(stderr,
		    gettext("[%s] must be run as root\n"), argv[0]);
#ifdef DEBUG
		(void) fprintf(stderr, gettext(" warning only\n"));
#else /* !DEBUG */
		exit(1);
#endif /* DEBUG */
	}

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c) {
		case 'd':
			/* turn on debugging */
			kwarnd_debug = 1;
			break;
		default:
			usage();
		}

	if (optind != argc) {
		usage();
	}

	(void) gethostname(myhostname, sizeof (myhostname));

	/*
	 * Started by inetd if name of module just below stream
	 * head is either a sockmod or timod.
	 */
	if (!ioctl(0, I_LOOK, mname) && ((strcmp(mname, "sockmod") == 0) ||
	    (strcmp(mname, "timod") == 0))) {
		char *netid;
		struct netconfig *nconf;

		openlog("kwarnd", LOG_PID, LOG_DAEMON);

		if ((netid = getenv("NLSPROVIDER")) ==  NULL) {
			netid = "ticotsord";
		}

		if ((nconf = getnetconfigent(netid)) == NULL) {
			syslog(LOG_ERR, gettext("cannot get transport info"));
			exit(1);
		}

		if (strcmp(mname, "sockmod") == 0) {
			if (ioctl(0, I_POP, 0) || ioctl(0, I_PUSH, "timod")) {
				syslog(LOG_ERR, gettext("could not get the "
				    "right module"));
				exit(1);
			}
		}

		/* XXX - is nconf even needed here? */
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			syslog(LOG_ERR, gettext("cannot create server handle"));
			exit(1);
		}

		/*
		 * We use a NULL nconf because KWARNPROG has already been
		 * registered with rpcbind.
		 */
		if (!svc_reg(transp, KWARNPROG, KWARNVERS, kwarnprog_1, NULL)) {
			syslog(LOG_ERR, gettext("unable to register "
			    "(KWARNPROG, KWARNVERS)"));
			exit(1);
		}

		if (nconf)
			freenetconfigent(nconf);
	} else {

		if (!kwarnd_debug)
			detachfromtty();

		openlog("kwarnd", LOG_PID, LOG_DAEMON);

		if (svc_create_local_service(kwarnprog_1, KWARNPROG, KWARNVERS,
		    "netpath", "kwarnd") == 0) {
			syslog(LOG_ERR, gettext("unable to create service"));
			exit(1);
		}
	}


	if (kwarnd_debug) {
		fprintf(stderr,
		    gettext("kwarnd start: \n"));
	}

	(void) signal(SIGCHLD, SIG_IGN);

	if (thr_create(NULL, 0,
	    (void *(*)(void *))kwarnd_check_warning_list, NULL,
	    THR_DETACHED | THR_DAEMON | THR_NEW_LWP, NULL)) {
		syslog(LOG_ERR,
		    gettext("unable to create cache_cleanup thread"));
		exit(1);
	}

	if (!loadConfigFile()) {
		syslog(LOG_ERR, gettext("could not read config file\n"));
		exit(1);
	}

	if (!rpc_control(RPC_SVC_MTMODE_SET, &rpc_svc_mode)) {
		syslog(LOG_ERR, gettext("unable to set automatic MT mode"));
		exit(1);
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
	(void) fprintf(stderr, gettext("usage: %s [-d]\n"), progname);
	exit(1);
}


/*
 * detach from tty
 */
static void
detachfromtty(void)
{
	switch (fork()) {
	case -1:
		perror(gettext("kwarnd: can not fork"));
		exit(1);
		/*NOTREACHED*/
	case 0:
		break;
	default:
		exit(0);
	}

	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();
}

/*ARGSUSED*/
int
kwarnprog_1_freeresult(SVCXPRT *transport, xdrproc_t xdr_res, caddr_t res)
{
	xdr_free(xdr_res, res);
	return (1);
}
