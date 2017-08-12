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
 * Copyright 2017 Gary Mills
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * This contains the mainline code for the YP server.  Data
 * structures which are process-global are also in this module.
 */

/* this is so that ypserv will compile under 5.5 */
#define	_SVID_GETTOD
#include <sys/time.h>
extern int gettimeofday(struct timeval *);

#include "ypsym.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include "shim.h"
#include "yptol.h"
#include <syslog.h>

static char register_failed[] = "ypserv:  Unable to register service for ";
bool silent = TRUE;

/*
 * client_setup_failure will be TRUE, if setup of the
 * connection to rpc.nisd_resolv failed
 */
bool client_setup_failure = FALSE;

/* N2L options */
bool init_dit = FALSE;
bool init_containers = FALSE;
bool init_maps = FALSE;
char **ldapCLA = NULL;

/* For DNS forwarding command line option (-d) */
bool dnsforward = FALSE;
int resolv_pid = 0;
CLIENT *resolv_client = NULL;
char *resolv_tp = "ticots";

#ifdef MINUS_C_OPTION
/* For cluster support (-c) */
bool multiflag = FALSE;
#endif

static char logfile[] = "/var/yp/ypserv.log";
void logprintf(char *format, ...);

static void ypexit(void);
static void ypinit(int argc, char **argv);
static void ypdispatch(struct svc_req *rqstp, SVCXPRT *transp);
static void ypolddispatch(struct svc_req *rqstp, SVCXPRT *transp);
static void ypget_command_line_args(int argc, char **argv);
extern void setup_resolv(bool *fwding, int *child,
			CLIENT **client, char *tp_type, long prognum);
static void cleanup_resolv(int);

/*
 * This is the main line code for the yp server.
 */
int
main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr, "must be root to run %s\n", argv[0]);
		exit(1);
	}

	/* Set up shop */
	ypinit(argc, argv);

	/* If requested set up the N2L maps. May take a while */
	if (init_dit)
		if (FAILURE == dump_maps_to_dit(init_containers)) {
			fprintf(stderr, "Fatal error dumping maps to DIT."
			" See syslog and LDAP server logs for details.\n");
			exit(1);
		}

	if (init_maps)
		if (FAILURE == dump_dit_to_maps()) {
			fprintf(stderr, "Fatal error dumping DIT to maps."
			" See syslog and LDAP server logs for details.\n");
			exit(1);
		}

	/*
	 * If we were asked to init the maps now exit. User will then use
	 * ypstart to restart ypserv and all the other NIS daemons.
	 */
	if (init_dit || init_maps) {
		printf("Map setup complete. Please now restart NIS daemons "
			"with ypstart.\n");
		exit(0);
	}

	svc_run();

	/*
	 * This is stupid, but the compiler likes to warn us about the
	 * absence of returns from main()
	 */
	return (0);
}

typedef struct {
	char		*netid;
	int		fd;
	int		olddispatch;	/* Register on protocol version 1 ? */
	int		class;		/* Other services that must succeed */
	SVCXPRT		*xprt;
	int		ok;		/* Registered successfully ? */
} ypservice_t;

ypservice_t	service[] = {
	{ "udp", -1, 1, 4, 0, 0 },
	{ "tcp", -1, 1, 4, 0, 0 },
	{ "udp6", -1, 0, 6, 0, 0 },
	{ "tcp6", -1, 0, 6, 0, 0 }
};

#define	MAXSERVICES	(sizeof (service)/sizeof (service[0]))

int		service_classes[MAXSERVICES];

/*
 * Does startup processing for the yp server.
 */
static void
ypinit(int argc, char **argv)
{
	int pid;
	int stat;
	struct sigaction act;
	int ufd, tfd;
	SVCXPRT *utransp, *ttransp;
	struct netconfig *nconf;
	int connmaxrec = RPC_MAXDATASIZE;
	int i, j, services = 0;


	/*
	 * Init yptol flags. Will get redone by init_lock_system() but we need
	 * to know if we should parse yptol cmd line options.
	 */
	init_yptol_flag();

	ypget_command_line_args(argc, argv);

	if (silent) {
		pid = (int)fork();

		if (pid == -1) {
		    logprintf("ypserv:  ypinit fork failure.\n");
		    ypexit();
		}

		if (pid != 0) {
		    exit(0);
		}
	}

	if (!init_lock_system(FALSE)) {
		ypexit();
	}

	get_secure_nets(argv[0]);

	if (silent) {
		closelog();
		closefrom(3);
	}

	if (yptol_mode) {
		stat = parseConfig(ldapCLA, NTOL_MAP_FILE);
		if (stat == 1) {
			logprintf("NIS to LDAP mapping inactive.\n");
		} else if (stat != 0) {
			logprintf("Aborting after NIS to LDAP mapping "
							"error.\n");
			fflush(stderr);
			exit(-1);
		}
	}

	if (silent) {
		freopen("/dev/null", "r", stdin);
		if (access(logfile, _IOWRT)) {
		    freopen("/dev/null", "w", stdout);
		    freopen("/dev/null", "w", stderr);
		} else {
		    freopen(logfile, "a", stdout);
		    freopen(logfile, "a", stderr);
		}

		(void) open("/dev/tty", 2);

		setpgrp();
	}

#ifdef	SYSVCONFIG
	sigset(SIGHUP, (void (*)())sysvconfig);
#else
	sigset(SIGHUP, SIG_IGN);
#endif

	/*
	 * Setting disposition to SIG_IGN will not create zombies when child
	 * processes terminate.
	 */
	sigset(SIGCHLD, SIG_IGN);

	act.sa_handler = cleanup_resolv;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESETHAND;
	sigaction(SIGTERM, &act, (struct sigaction *)NULL);
	sigaction(SIGQUIT, &act, (struct sigaction *)NULL);
	sigaction(SIGABRT, &act, (struct sigaction *)NULL);
	sigaction(SIGBUS, &act, (struct sigaction *)NULL);
	sigaction(SIGSEGV, &act, (struct sigaction *)NULL);

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		logprintf("unable to set maximum RPC record size");
	}

	svc_unreg(YPPROG, YPVERS);
	svc_unreg(YPPROG, YPVERS_ORIG);

	for (i = 0; i < sizeof (service)/sizeof (ypservice_t); i++) {

		service_classes[i] = -1;

		if ((nconf = getnetconfigent(service[i].netid)) == NULL) {
			logprintf("getnetconfigent(\"%s\") failed\n",
					service[i].netid);
			continue;
		}

		if ((service[i].fd = t_open(nconf->nc_device, O_RDWR, NULL)) <
			0) {
			logprintf("t_open failed for %s\n", service[i].netid);
			freenetconfigent(nconf);
			continue;
		}

		if (netdir_options(nconf, ND_SET_RESERVEDPORT, service[i].fd,
			NULL) < 0) {
			logprintf("could not set reserved port for %s\n",
				service[i].netid);
			(void) close(service[i].fd);
			service[i].fd = -1;
			freenetconfigent(nconf);
			continue;
		}

		if ((service[i].xprt = svc_tli_create(service[i].fd, nconf,
			NULL, 0, 0)) == NULL) {
			logprintf("svc_tli_create failed for %s\n",
				service[i].netid);
			(void) close(service[i].fd);
			service[i].fd = -1;
			freenetconfigent(nconf);
			continue;
		}

		if (!svc_reg(service[i].xprt, YPPROG, YPVERS, ypdispatch,
			nconf)) {
			logprintf("%s %s\n", service[i].netid, register_failed);
			svc_destroy(service[i].xprt);
			service[i].xprt = 0;
			(void) close(service[i].fd);
			service[i].fd = -1;
			freenetconfigent(nconf);
			continue;
		}

		if (service[i].olddispatch && !svc_reg(service[i].xprt, YPPROG,
					YPVERS_ORIG, ypolddispatch, nconf)) {
			logprintf("old %s %s\n",
				service[i].netid, register_failed);
			/* Can only unregister prognum/versnum */
			svc_destroy(service[i].xprt);
			service[i].xprt = 0;
			(void) close(service[i].fd);
			service[i].fd = -1;
			freenetconfigent(nconf);
			continue;
		}

		services++;
		service[i].ok = 1;
		service_classes[i] = service[i].class;

		freenetconfigent(nconf);

	}

	/*
	 * Check if we managed to register enough services to continue.
	 * It's OK if we managed to register all IPv4 services but no
	 * IPv6, or the other way around, but not if we (say) registered
	 * IPv4 UDP but not TCP.
	 */
	if (services > 0) {
		for (j = 0; j < MAXSERVICES; j++) {
			if (service_classes[j] >= 0) {
				/*
				 * Must have all services of this class
				 * registered.
				 */
				for (i = 0; i < MAXSERVICES; i++) {
					if (service[i].ok == 0 &&
						service[i].class ==
						service_classes[j]) {
						logprintf(
			"unable to register all services for class %d\n",
							service[i].class);
						ypexit();
					}
				}
			}
		}
	} else {
		logprintf("unable to register any services\n");
		ypexit();
	}

	/* Now we setup circuit_n or yp_all() and yp_update() will not work */
	if (!svc_create(ypdispatch, YPPROG, YPVERS, "circuit_n")) {
		logprintf("circuit_n %s\n", register_failed);
		ypexit();
	}

	if (dnsforward) {
		setup_resolv(&dnsforward, &resolv_pid,
				&resolv_client, resolv_tp, 0);
		if (resolv_client == NULL)
			client_setup_failure = TRUE;
	}
}

void
cleanup_resolv(int sig)
{
	if (resolv_pid)
		kill(resolv_pid, sig);

	kill(getpid(), sig);
}

/*
 * This picks up any command line args passed from the process invocation.
 */
static void
ypget_command_line_args(int argc, char **argv)
{
	for (argv++; --argc; argv++) {

		if ((*argv)[0] == '-') {

			switch ((*argv)[1]) {
#ifdef	MINUS_C_OPTION
			case 'c':
				multiflag = TRUE;
				break;
#endif
			case 'd':
				if (access("/etc/resolv.conf", F_OK) == -1) {
					fprintf(stderr,
			"No /etc/resolv.conf file, -d option ignored\n");
				} else {
					dnsforward = TRUE;
				}
				break;
			case 'I':
				init_containers = TRUE;
				/* ... and also do -i stuff */
			case 'i':
				if (yptol_mode) {
					init_dit = TRUE;
				} else {
					fprintf(stderr, "-%c option is illegal "
					"if not in NIS to LDAP mode. Exiting\n",
						(*argv)[1]);
					fflush(stderr);
					exit(-1);
				}

				/* Handle -ir */
				if ('r' != (*argv)[2])
					break;

			case 'r':
				if (yptol_mode) {
					init_maps = TRUE;
				} else {
					fprintf(stderr, "-r option is illegal "
						"if not in NIS to LDAP mode. "
						"Exiting\n");
					fflush(stderr);
					exit(-1);
				}
				break;
			case 'v':
				silent = FALSE;
				break;
			}
		}
	}

	/* If setting up don't run silent or demonize */
	if (init_dit || init_maps)
		silent = FALSE;

}

/*
 * This dispatches to server action routines based on the input procedure
 * number.  ypdispatch is called from the RPC function svc_run.
 */
static void
ypdispatch(struct svc_req *rqstp, SVCXPRT *transp)
{
	sigset_t set, oset;


#ifdef	SYSVCONFIG
	/* prepare to answer questions about system v filesystem aliases */
	sysvconfig();
#endif

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &oset);

	switch (rqstp->rq_proc) {

	case YPPROC_NULL:

		if (!svc_sendreply(transp, xdr_void, 0))
			logprintf("ypserv:  Can't reply to rpc call.\n");
		break;

	case YPPROC_DOMAIN:
		ypdomain(transp, TRUE);
		break;

	case YPPROC_DOMAIN_NONACK:
		ypdomain(transp, FALSE);
		break;

	case YPPROC_MATCH:
		ypmatch(transp, rqstp);
		break;

	case YPPROC_FIRST:
		ypfirst(transp);
		break;

	case YPPROC_NEXT:
		ypnext(transp);
		break;

	case YPPROC_XFR:
		ypxfr(transp, YPPROC_XFR);
		break;

	case YPPROC_NEWXFR:
		ypxfr(transp, YPPROC_NEWXFR);
		break;

	case YPPROC_CLEAR:
		ypclr_current_map();

		if (!svc_sendreply(transp, xdr_void, 0))
			logprintf("ypserv:  Can't reply to rpc call.\n");
		break;

	case YPPROC_ALL:
		ypall(transp);
		break;

	case YPPROC_MASTER:
		ypmaster(transp);
		break;

	case YPPROC_ORDER:
		yporder(transp);
		break;

	case YPPROC_MAPLIST:
		ypmaplist(transp);
		break;

	default:
		svcerr_noproc(transp);
		break;

	}

	sigprocmask(SIG_SETMASK, &oset, (sigset_t *)NULL);

}

static void
ypolddispatch(struct svc_req *rqstp, SVCXPRT *transp)
{
	sigset_t set, oset;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &oset);

	switch (rqstp->rq_proc) {

	case YPOLDPROC_NULL:
		if (!svc_sendreply(transp, xdr_void, 0))
			logprintf("ypserv:  Can't replay to rpc call.\n");
		break;

	case YPOLDPROC_DOMAIN:
		ypdomain(transp, TRUE);
		break;

	case YPOLDPROC_DOMAIN_NONACK:
		ypdomain(transp, FALSE);
		break;

	case YPOLDPROC_MATCH:
		ypoldmatch(transp, rqstp);
		break;

	case YPOLDPROC_FIRST:
		ypoldfirst(transp);
		break;

	case YPOLDPROC_NEXT:
		ypoldnext(transp);
		break;

	case YPOLDPROC_POLL:
		ypoldpoll(transp);
		break;

	case YPOLDPROC_PUSH:
		ypoldpush(transp);
		break;

	case YPOLDPROC_PULL:
		ypoldpull(transp);
		break;

	case YPOLDPROC_GET:
		ypoldget(transp);

	default:
		svcerr_noproc(transp);
		break;
	}

	sigprocmask(SIG_SETMASK, &oset, (sigset_t *)NULL);
}

/*
 * This flushes output to stderr, then aborts the server process to leave a
 * core dump.
 */
static void
ypexit(void)
{
	fflush(stderr);
	abort();
}

/*
 * This constructs a logging record.
 */
void
logprintf(char *format, ...)
{
	va_list ap;
	struct timeval t;

	va_start(ap, format);

	if (silent) {
		gettimeofday(&t);
		fseek(stderr, 0, 2);
		fprintf(stderr, "%19.19s: ", ctime(&t.tv_sec));
	}

	vfprintf(stderr, format, ap);
	va_end(ap);
	fflush(stderr);
}
