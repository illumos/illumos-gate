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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/* LINTLIBRARY */
/* PROTOLIB1 */

/*
 * NLM server
 *
 * Most of this copied from ../nfsd/nfsd.c
 * and then s:NFS:NLM: applied, etc.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <tiuser.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <thread.h>
#include <sys/time.h>
#include <sys/file.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <signal.h>
#include <netconfig.h>
#include <netdir.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <poll.h>
#include <priv_utils.h>
#include <sys/tiuser.h>
#include <netinet/tcp.h>
#include <deflt.h>
#include <rpcsvc/daemon_utils.h>
#include <rpcsvc/nlm_prot.h>
#include <libintl.h>
#include <libscf.h>
#include <libshare.h>
#include "nfs_tbind.h"
#include "thrpool.h"
#include "smfcfg.h"

/* Option defaults.  See nfssys.h */
struct lm_svc_args lmargs = {
	.version = LM_SVC_CUR_VERS,
	/* fd, n_fmly, n_proto, n_rdev (below) */
	.debug = 0,
	.timout = 5 * 60,
	.grace = 60,
	.retransmittimeout = 15
};
int max_servers = 20;


#define	RET_OK		0	/* return code for no error */
#define	RET_ERR		33	/* return code for error(s) */

static	int	nlmsvc(int fd, struct netbuf addrmask,
			struct netconfig *nconf);
static int nlmsvcpool(int max_servers);
static	void	usage(void);

extern	int	_nfssys(int, void *);
static void sigterm_handler(void);
static void shutdown_lockd(void);

extern int	daemonize_init(void);
extern void	daemonize_fini(int fd);

static	char	*MyName;

/*
 * We want to bind to these TLI providers, and in this order,
 * because the kernel NLM needs the loopback first for its
 * initialization. (It uses it to talk to statd.)
 */
static  NETSELDECL(defaultproviders)[] = {
	"/dev/ticotsord",
	"/dev/tcp",
	"/dev/udp",
	"/dev/tcp6",
	"/dev/udp6",
	NULL
};

/*
 * The following are all globals used by routines in nfs_tbind.c.
 */
size_t	end_listen_fds;		/* used by conn_close_oldest() */
size_t	num_fds = 0;		/* used by multiple routines */
int	listen_backlog = 32;	/* used by bind_to_{provider,proto}() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = nlmsvc;
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */

int
main(int ac, char *av[])
{
	char *propname = NULL;
	char *dir = "/";
	char *provider = (char *)NULL;
	struct protob *protobp;
	NETSELPDECL(providerp);
	sigset_t sgset;
	int i, c, pid, ret, val;
	int pipe_fd = -1;
	struct sigaction act;

	MyName = *av;

	/*
	 * Initializations that require more privileges than we need to run.
	 */
	(void) _create_daemon_lock(LOCKD, DAEMON_UID, DAEMON_GID);
	svcsetprio();

	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS, NULL) == -1) {
		(void) fprintf(stderr, "%s should be run with"
		    " sufficient privileges\n", av[0]);
		exit(1);
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * Read in the values from SMF first before we check
	 * command line options so the options override SMF values.
	 */

	/* How long to keep idle connections. */
	propname = "conn_idle_timeout"; /* also -t */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			lmargs.timout = val;
	}

	/* Note: debug_level can only be set by args. */

	/* How long to wait for clients to re-establish locks. */
	propname = "grace_period"; /* also -g */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			lmargs.grace = val;
	}

	propname = "listen_backlog"; /* also -l */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			listen_backlog = val;
	}

	propname = "max_connections"; /* also -c */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			max_conns_allowed = val;
	}

	propname = "max_servers"; /* also argv[1] */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			max_servers = val;
	}

	propname = "retrans_timeout"; /* also -r */
	ret = nfs_smf_get_iprop(propname, &val,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, LOCKD);
	if (ret == SA_OK) {
		if (val <= 0)
			fprintf(stderr, gettext(
			    "Invalid %s from SMF"), propname);
		else
			lmargs.retransmittimeout = val;
	}


	while ((c = getopt(ac, av, "c:d:g:l:r:t:")) != EOF)
		switch (c) {
		case 'c': /* max_connections */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			max_conns_allowed = val;
			break;

		case 'd': /* debug */
			lmargs.debug = atoi(optarg);
			break;

		case 'g': /* grace_period */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			lmargs.grace = val;
			break;

		case 'l': /* listen_backlog */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			listen_backlog = val;
			break;

		case 'r': /* retrans_timeout */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			lmargs.retransmittimeout = val;
			break;

		case 't': /* conn_idle_timeout */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			lmargs.timout = val;
			break;

		badval:
			fprintf(stderr, gettext(
			    "Invalid -%c option value"), c);
			/* FALLTHROUGH */
		default:
			usage();
			/* NOTREACHED */
		}

	/*
	 * If there is exactly one more argument, it is the number of
	 * servers.
	 */
	if (optind < ac) {
		val = atoi(av[optind]);
		if (val <= 0) {
			fprintf(stderr, gettext(
			    "Invalid max_servers argument"));
			usage();
		}
		max_servers = val;
		optind++;
	}
	/*
	 * If there are two or more arguments, then this is a usage error.
	 */
	if (optind != ac)
		usage();

	if (lmargs.debug) {
		printf("%s: debug= %d, conn_idle_timout= %d,"
		    " grace_period= %d, listen_backlog= %d,"
		    " max_connections= %d, max_servers= %d,"
		    " retrans_timeout= %d\n",
		    MyName, lmargs.debug, lmargs.timout,
		    lmargs.grace, listen_backlog,
		    max_conns_allowed, max_servers,
		    lmargs.retransmittimeout);
	}

	/*
	 * Set current dir to server root
	 */
	if (chdir(dir) < 0) {
		(void) fprintf(stderr, "%s:  ", MyName);
		perror(dir);
		exit(1);
	}

	/* Daemonize, if not debug. */
	if (lmargs.debug == 0)
		pipe_fd = daemonize_init();

	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	pid = _enter_daemon_lock(LOCKD);
	switch (pid) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "error locking for %s: %s", LOCKD,
		    strerror(errno));
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	/*
	 * Block all signals till we spawn other
	 * threads.
	 */
	(void) sigfillset(&sgset);
	(void) thr_sigsetmask(SIG_BLOCK, &sgset, NULL);

	/* Unregister any previous versions. */
	for (i = NLM_VERS; i < NLM4_VERS; i++) {
		svc_unreg(NLM_PROG, i);
	}

	/*
	 * Set up kernel RPC thread pool for the NLM server.
	 */
	if (nlmsvcpool(max_servers)) {
		fprintf(stderr, "Can't set up kernel NLM service: %s. Exiting",
		    strerror(errno));
		exit(1);
	}

	/*
	 * Set up blocked thread to do LWP creation on behalf of the kernel.
	 */
	if (svcwait(NLM_SVCPOOL_ID)) {
		fprintf(stderr, "Can't set up NLM pool creator: %s. Exiting",
		    strerror(errno));
		exit(1);
	}

	/*
	 * Install atexit and sigterm handlers
	 */
	act.sa_handler = sigterm_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) atexit(shutdown_lockd);

	/*
	 * Now open up for signal delivery
	 */
	(void) thr_sigsetmask(SIG_UNBLOCK, &sgset, NULL);

	/*
	 * Build a protocol block list for registration.
	 */
	protobp = (struct protob *)malloc(sizeof (struct protob));
	protobp->serv = "NLM";
	protobp->versmin = NLM_VERS;
	protobp->versmax = NLM4_VERS;
	protobp->program = NLM_PROG;
	protobp->next = (struct protob *)NULL;

	for (providerp = defaultproviders;
	    *providerp != NULL; providerp++) {
		provider = *providerp;
		do_one(provider, NULL, protobp, nlmsvc);
	}

	free(protobp);

	if (num_fds == 0) {
		fprintf(stderr, "Could not start NLM service for any protocol."
		    " Exiting");
		exit(1);
	}

	end_listen_fds = num_fds;

	/*
	 * lockd is up and running as far as we are concerned.
	 */
	if (lmargs.debug == 0)
		daemonize_fini(pipe_fd);

	/*
	 * Get rid of unneeded privileges.
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	/*
	 * Poll for non-data control events on the transport descriptors.
	 */
	poll_for_action();

	/*
	 * If we get here, something failed in poll_for_action().
	 */
	return (1);
}

static int
nlmsvcpool(int maxservers)
{
	struct svcpool_args npa;

	npa.id = NLM_SVCPOOL_ID;
	npa.maxthreads = maxservers;
	npa.redline = 0;
	npa.qsize = 0;
	npa.timeout = 0;
	npa.stksize = 0;
	npa.max_same_xprt = 0;
	return (_nfssys(SVCPOOL_CREATE, &npa));
}

static int
ncfmly_to_lmfmly(const char *ncfmly)
{
	if (0 == strcmp(ncfmly, NC_INET))
		return (LM_INET);
	if (0 == strcmp(ncfmly, NC_INET6))
		return (LM_INET6);
	if (0 == strcmp(ncfmly, NC_LOOPBACK))
		return (LM_LOOPBACK);
	return (-1);
}

static int
nctype_to_lmprot(uint_t semantics)
{
	switch (semantics) {
	case NC_TPI_CLTS:
		return (LM_UDP);
	case NC_TPI_COTS_ORD:
		return (LM_TCP);
	}
	return (-1);
}

static dev_t
ncdev_to_rdev(const char *ncdev)
{
	struct stat st;

	if (stat(ncdev, &st) < 0)
		return (NODEV);
	return (st.st_rdev);
}

static void
sigterm_handler(void)
{
	/* to call atexit handler */
	exit(0);
}

static void
shutdown_lockd(void)
{
	(void) _nfssys(KILL_LOCKMGR, NULL);
}


/*
 * Establish NLM service thread.
 */
static int
nlmsvc(int fd, struct netbuf addrmask, struct netconfig *nconf)
{
	struct lm_svc_args lma;

	lma = lmargs; /* init by struct copy */

	/*
	 * The kernel code needs to reconstruct a complete
	 * knetconfig from n_fmly, n_proto.  We use these
	 * two fields to convey the family and semantics.
	 */
	lma.fd = fd;
	lma.n_fmly = ncfmly_to_lmfmly(nconf->nc_protofmly);
	lma.n_proto = nctype_to_lmprot(nconf->nc_semantics);
	lma.n_rdev = ncdev_to_rdev(nconf->nc_device);

	return (_nfssys(LM_SVC, &lma));
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: %s [options] [max_servers]\n"), MyName);
	(void) fprintf(stderr, gettext(
	    "options:  (see SMF property descriptions)\n"));
	/* Note: don't translate these */
	(void) fprintf(stderr, "\t-c max_connections\n");
	(void) fprintf(stderr, "\t-d debug_level\n");
	(void) fprintf(stderr, "\t-g grace_period\n");
	(void) fprintf(stderr, "\t-l listen_backlog\n");
	(void) fprintf(stderr, "\t-r retrans_timeout\n");
	(void) fprintf(stderr, "\t-t conn_idle_timeout\n");

	exit(1);
}
