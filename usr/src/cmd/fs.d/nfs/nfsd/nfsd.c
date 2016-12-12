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

/* NFS server */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <tiuser.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <thread.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/file.h>
#include <nfs/nfs.h>
#include <nfs/nfs_acl.h>
#include <nfs/nfssys.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <signal.h>
#include <netconfig.h>
#include <netdir.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <sys/wait.h>
#include <poll.h>
#include <priv_utils.h>
#include <sys/tiuser.h>
#include <netinet/tcp.h>
#include <deflt.h>
#include <rpcsvc/daemon_utils.h>
#include <rpcsvc/nfs4_prot.h>
#include <libnvpair.h>
#include <libscf.h>
#include <libshare.h>
#include "nfs_tbind.h"
#include "thrpool.h"
#include "smfcfg.h"

/* quiesce requests will be ignored if nfs_server_vers_max < QUIESCE_VERSMIN */
#define	QUIESCE_VERSMIN	4
/* DSS: distributed stable storage */
#define	DSS_VERSMIN	4

static	int	nfssvc(int, struct netbuf, struct netconfig *);
static	int	nfssvcpool(int maxservers);
static	int	dss_init(uint_t npaths, char **pathnames);
static	void	dss_mkleafdirs(uint_t npaths, char **pathnames);
static	void	dss_mkleafdir(char *dir, char *leaf, char *path);
static	void	usage(void);
int		qstrcmp(const void *s1, const void *s2);

extern	int	_nfssys(int, void *);

extern int	daemonize_init(void);
extern void	daemonize_fini(int fd);

/* signal handlers */
static void sigflush(int);
static void quiesce(int);

static	char	*MyName;
static	NETSELDECL(defaultproviders)[] = { "/dev/tcp6", "/dev/tcp", "/dev/udp",
					    "/dev/udp6", NULL };
/* static	NETSELDECL(defaultprotos)[] =	{ NC_UDP, NC_TCP, NULL }; */
/*
 * The following are all globals used by routines in nfs_tbind.c.
 */
size_t	end_listen_fds;		/* used by conn_close_oldest() */
size_t	num_fds = 0;		/* used by multiple routines */
int	listen_backlog = 32;	/* used by bind_to_{provider,proto}() */
int	num_servers;		/* used by cots_listen_event() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = nfssvc;
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */

/*
 * Keep track of min/max versions of NFS protocol to be started.
 * Start with the defaults (min == 2, max == 3).  We have the
 * capability of starting vers=4 but only if the user requests it.
 */
int	nfs_server_vers_min = NFS_VERSMIN_DEFAULT;
int	nfs_server_vers_max = NFS_VERSMAX_DEFAULT;

/*
 * Set the default for server delegation enablement and set per
 * /etc/default/nfs configuration (if present).
 */
int	nfs_server_delegation = NFS_SERVER_DELEGATION_DEFAULT;

int
main(int ac, char *av[])
{
	char *dir = "/";
	int allflag = 0;
	int df_allflag = 0;
	int opt_cnt = 0;
	int maxservers = 1024;	/* zero allows inifinte number of threads */
	int maxservers_set = 0;
	int logmaxservers = 0;
	int pid;
	int i;
	char *provider = (char *)NULL;
	char *df_provider = (char *)NULL;
	struct protob *protobp0, *protobp;
	NETSELDECL(proto) = NULL;
	NETSELDECL(df_proto) = NULL;
	NETSELPDECL(providerp);
	char *defval;
	boolean_t can_do_mlp;
	uint_t dss_npaths = 0;
	char **dss_pathnames = NULL;
	sigset_t sgset;
	char name[PATH_MAX], value[PATH_MAX];
	int ret, bufsz;

	int pipe_fd = -1;

	MyName = *av;

	/*
	 * Initializations that require more privileges than we need to run.
	 */
	(void) _create_daemon_lock(NFSD, DAEMON_UID, DAEMON_GID);
	svcsetprio();

	can_do_mlp = priv_ineffect(PRIV_NET_BINDMLP);
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS,
	    can_do_mlp ? PRIV_NET_BINDMLP : NULL, NULL) == -1) {
		(void) fprintf(stderr, "%s should be run with"
		    " sufficient privileges\n", av[0]);
		exit(1);
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * Read in the values from SMF first before we check
	 * command line options so the options override SMF values.
	 */
	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("max_connections", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		max_conns_allowed = strtol(value, (char **)NULL, 10);
		if (errno != 0)
			max_conns_allowed = -1;
	}

	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("listen_backlog", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		listen_backlog = strtol(value, (char **)NULL, 10);
		if (errno != 0) {
			listen_backlog = 32;
		}
	}

	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("protocol", value, DEFAULT_INSTANCE,
	    SCF_TYPE_ASTRING, NFSD, &bufsz);
	if ((ret == SA_OK) && strlen(value) > 0) {
		df_proto = strdup(value);
		opt_cnt++;
		if (strncasecmp("ALL", value, 3) == 0) {
			free(df_proto);
			df_proto = NULL;
			df_allflag = 1;
		}
	}

	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("device", value, DEFAULT_INSTANCE,
	    SCF_TYPE_ASTRING, NFSD, &bufsz);
	if ((ret == SA_OK) && strlen(value) > 0) {
		df_provider = strdup(value);
		opt_cnt++;
	}

	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("servers", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		maxservers = strtol(value, (char **)NULL, 10);
		if (errno != 0)
			maxservers = 1024;
		else
			maxservers_set = 1;
	}

	bufsz = 4;
	ret = nfs_smf_get_prop("server_versmin", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK)
		nfs_server_vers_min = strtol(value, (char **)NULL, 10);

	bufsz = 4;
	ret = nfs_smf_get_prop("server_versmax", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK)
		nfs_server_vers_max = strtol(value, (char **)NULL, 10);

	bufsz = PATH_MAX;
	ret = nfs_smf_get_prop("server_delegation", value, DEFAULT_INSTANCE,
	    SCF_TYPE_ASTRING, NFSD, &bufsz);
	if (ret == SA_OK)
		if (strncasecmp(value, "off", 3) == 0)
			nfs_server_delegation = FALSE;

	/*
	 * Conflict options error messages.
	 */
	if (opt_cnt > 1) {
		(void) fprintf(stderr, "\nConflicting options, only one of "
		    "the following options can be specified\n"
		    "in SMF:\n"
		    "\tprotocol=ALL\n"
		    "\tprotocol=protocol\n"
		    "\tdevice=devicename\n\n");
		usage();
	}
	opt_cnt = 0;

	while ((i = getopt(ac, av, "ac:p:s:t:l:")) != EOF) {
		switch (i) {
		case 'a':
			free(df_proto);
			df_proto = NULL;
			free(df_provider);
			df_provider = NULL;

			allflag = 1;
			opt_cnt++;
			break;

		case 'c':
			max_conns_allowed = atoi(optarg);
			break;

		case 'p':
			proto = optarg;
			df_allflag = 0;
			opt_cnt++;
			break;

		/*
		 * DSS: NFSv4 distributed stable storage.
		 *
		 * This is a Contracted Project Private interface, for
		 * the sole use of Sun Cluster HA-NFS. See PSARC/2006/313.
		 */
		case 's':
			if (strlen(optarg) < MAXPATHLEN) {
				/* first "-s" option encountered? */
				if (dss_pathnames == NULL) {
					/*
					 * Allocate maximum possible space
					 * required given cmdline arg count;
					 * "-s <path>" consumes two args.
					 */
					size_t sz = (ac / 2) * sizeof (char *);
					dss_pathnames = (char **)malloc(sz);
					if (dss_pathnames == NULL) {
						(void) fprintf(stderr, "%s: "
						    "dss paths malloc failed\n",
						    av[0]);
						exit(1);
					}
					(void) memset(dss_pathnames, 0, sz);
				}
				dss_pathnames[dss_npaths] = optarg;
				dss_npaths++;
			} else {
				(void) fprintf(stderr,
				    "%s: -s pathname too long.\n", av[0]);
			}
			break;

		case 't':
			provider = optarg;
			df_allflag = 0;
			opt_cnt++;
			break;

		case 'l':
			listen_backlog = atoi(optarg);
			break;

		case '?':
			usage();
			/* NOTREACHED */
		}
	}

	allflag = df_allflag;
	if (proto == NULL)
		proto = df_proto;
	if (provider == NULL)
		provider = df_provider;

	/*
	 * Conflict options error messages.
	 */
	if (opt_cnt > 1) {
		(void) fprintf(stderr, "\nConflicting options, only one of "
		    "the following options can be specified\n"
		    "on the command line:\n"
		    "\t-a\n"
		    "\t-p protocol\n"
		    "\t-t transport\n\n");
		usage();
	}

	if (proto != NULL &&
	    strncasecmp(proto, NC_UDP, strlen(NC_UDP)) == 0) {
		if (nfs_server_vers_max == NFS_V4) {
			if (nfs_server_vers_min == NFS_V4) {
				fprintf(stderr,
				    "NFS version 4 is not supported "
				    "with the UDP protocol.  Exiting\n");
				exit(3);
			} else {
				fprintf(stderr,
				    "NFS version 4 is not supported "
				    "with the UDP protocol.\n");
			}
		}
	}

	/*
	 * If there is exactly one more argument, it is the number of
	 * servers.
	 */
	if (optind == ac - 1) {
		maxservers = atoi(av[optind]);
		maxservers_set = 1;
	}
	/*
	 * If there are two or more arguments, then this is a usage error.
	 */
	else if (optind < ac - 1)
		usage();
	/*
	 * Check the ranges for min/max version specified
	 */
	else if ((nfs_server_vers_min > nfs_server_vers_max) ||
	    (nfs_server_vers_min < NFS_VERSMIN) ||
	    (nfs_server_vers_max > NFS_VERSMAX))
		usage();
	/*
	 * There are no additional arguments, and we haven't set maxservers
	 * explicitly via the config file, we use a default number of
	 * servers.  We will log this.
	 */
	else if (maxservers_set == 0)
		logmaxservers = 1;

	/*
	 * Basic Sanity checks on options
	 *
	 * max_conns_allowed must be positive, except for the special
	 * value of -1 which is used internally to mean unlimited, -1 isn't
	 * documented but we allow it anyway.
	 *
	 * maxservers must be positive
	 * listen_backlog must be positive or zero
	 */
	if (((max_conns_allowed != -1) && (max_conns_allowed <= 0)) ||
	    (listen_backlog < 0) || (maxservers <= 0)) {
		usage();
	}

	/*
	 * Set current dir to server root
	 */
	if (chdir(dir) < 0) {
		(void) fprintf(stderr, "%s:  ", MyName);
		perror(dir);
		exit(1);
	}

#ifndef DEBUG
	pipe_fd = daemonize_init();
#endif

	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	pid = _enter_daemon_lock(NFSD);
	switch (pid) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "error locking for %s: %s\n", NFSD,
		    strerror(errno));
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	/*
	 * If we've been given a list of paths to be used for distributed
	 * stable storage, and provided we're going to run a version
	 * that supports it, setup the DSS paths.
	 */
	if (dss_pathnames != NULL && nfs_server_vers_max >= DSS_VERSMIN) {
		if (dss_init(dss_npaths, dss_pathnames) != 0) {
			fprintf(stderr, "%s", "dss_init failed. Exiting.\n");
			exit(1);
		}
	}

	/*
	 * Block all signals till we spawn other
	 * threads.
	 */
	(void) sigfillset(&sgset);
	(void) thr_sigsetmask(SIG_BLOCK, &sgset, NULL);

	if (logmaxservers) {
		fprintf(stderr,
		    "Number of servers not specified. Using default of %d.\n",
		    maxservers);
	}

	/*
	 * Make sure to unregister any previous versions in case the
	 * user is reconfiguring the server in interesting ways.
	 */
	svc_unreg(NFS_PROGRAM, NFS_VERSION);
	svc_unreg(NFS_PROGRAM, NFS_V3);
	svc_unreg(NFS_PROGRAM, NFS_V4);
	svc_unreg(NFS_ACL_PROGRAM, NFS_ACL_V2);
	svc_unreg(NFS_ACL_PROGRAM, NFS_ACL_V3);

	/*
	 * Set up kernel RPC thread pool for the NFS server.
	 */
	if (nfssvcpool(maxservers)) {
		fprintf(stderr, "Can't set up kernel NFS service: %s. "
		    "Exiting.\n", strerror(errno));
		exit(1);
	}

	/*
	 * Set up blocked thread to do LWP creation on behalf of the kernel.
	 */
	if (svcwait(NFS_SVCPOOL_ID)) {
		fprintf(stderr, "Can't set up NFS pool creator: %s. Exiting.\n",
		    strerror(errno));
		exit(1);
	}

	/*
	 * RDMA start and stop thread.
	 * Per pool RDMA listener creation and
	 * destructor thread.
	 *
	 * start rdma services and block in the kernel.
	 * (only if proto or provider is not set to TCP or UDP)
	 */
	if ((proto == NULL) && (provider == NULL)) {
		if (svcrdma(NFS_SVCPOOL_ID, nfs_server_vers_min,
		    nfs_server_vers_max, nfs_server_delegation)) {
			fprintf(stderr,
			    "Can't set up RDMA creator thread : %s\n",
			    strerror(errno));
		}
	}

	/*
	 * Now open up for signal delivery
	 */

	(void) thr_sigsetmask(SIG_UNBLOCK, &sgset, NULL);
	sigset(SIGTERM, sigflush);
	sigset(SIGUSR1, quiesce);

	/*
	 * Build a protocol block list for registration.
	 */
	protobp0 = protobp = (struct protob *)malloc(sizeof (struct protob));
	protobp->serv = "NFS";
	protobp->versmin = nfs_server_vers_min;
	protobp->versmax = nfs_server_vers_max;
	protobp->program = NFS_PROGRAM;

	protobp->next = (struct protob *)malloc(sizeof (struct protob));
	protobp = protobp->next;
	protobp->serv = "NFS_ACL";		/* not used */
	protobp->versmin = nfs_server_vers_min;
	/* XXX - this needs work to get the version just right */
	protobp->versmax = (nfs_server_vers_max > NFS_ACL_V3) ?
	    NFS_ACL_V3 : nfs_server_vers_max;
	protobp->program = NFS_ACL_PROGRAM;
	protobp->next = (struct protob *)NULL;

	if (allflag) {
		if (do_all(protobp0, nfssvc) == -1) {
			fprintf(stderr, "setnetconfig failed : %s\n",
			    strerror(errno));
			exit(1);
		}
	} else if (proto) {
		/* there's more than one match for the same protocol */
		struct netconfig *nconf;
		NCONF_HANDLE *nc;
		bool_t	protoFound = FALSE;
		if ((nc = setnetconfig()) == (NCONF_HANDLE *) NULL) {
			fprintf(stderr, "setnetconfig failed : %s\n",
			    strerror(errno));
			goto done;
		}
		while (nconf = getnetconfig(nc)) {
			if (strcmp(nconf->nc_proto, proto) == 0) {
				protoFound = TRUE;
				do_one(nconf->nc_device, NULL,
				    protobp0, nfssvc);
			}
		}
		(void) endnetconfig(nc);
		if (protoFound == FALSE) {
			fprintf(stderr,
			    "couldn't find netconfig entry for protocol %s\n",
			    proto);
		}
	} else if (provider)
		do_one(provider, proto, protobp0, nfssvc);
	else {
		for (providerp = defaultproviders;
		    *providerp != NULL; providerp++) {
			provider = *providerp;
			do_one(provider, NULL, protobp0, nfssvc);
		}
	}
done:

	free(protobp);
	free(protobp0);

	if (num_fds == 0) {
		fprintf(stderr, "Could not start NFS service for any protocol."
		    " Exiting.\n");
		exit(1);
	}

	end_listen_fds = num_fds;

	/*
	 * nfsd is up and running as far as we are concerned.
	 */
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
nfssvcpool(int maxservers)
{
	struct svcpool_args npa;

	npa.id = NFS_SVCPOOL_ID;
	npa.maxthreads = maxservers;
	npa.redline = 0;
	npa.qsize = 0;
	npa.timeout = 0;
	npa.stksize = 0;
	npa.max_same_xprt = 0;
	return (_nfssys(SVCPOOL_CREATE, &npa));
}

/*
 * Establish NFS service thread.
 */
static int
nfssvc(int fd, struct netbuf addrmask, struct netconfig *nconf)
{
	struct nfs_svc_args nsa;

	nsa.fd = fd;
	nsa.netid = nconf->nc_netid;
	nsa.addrmask = addrmask;
	if (strncasecmp(nconf->nc_proto, NC_UDP, strlen(NC_UDP)) == 0) {
		nsa.versmax = (nfs_server_vers_max > NFS_V3) ?
		    NFS_V3 : nfs_server_vers_max;
		nsa.versmin = nfs_server_vers_min;
		/*
		 * If no version left, silently do nothing, previous
		 * checks will have assured at least TCP is available.
		 */
		if (nsa.versmin > nsa.versmax)
			return (0);
	} else {
		nsa.versmax = nfs_server_vers_max;
		nsa.versmin = nfs_server_vers_min;
	}
	nsa.delegation = nfs_server_delegation;
	return (_nfssys(NFS_SVC, &nsa));
}

static void
usage(void)
{
	(void) fprintf(stderr,
"usage: %s [ -a ] [ -c max_conns ] [ -p protocol ] [ -t transport ] ", MyName);
	(void) fprintf(stderr, "\n[ -l listen_backlog ] [ nservers ]\n");
	(void) fprintf(stderr,
"\twhere -a causes <nservers> to be started on each appropriate transport,\n");
	(void) fprintf(stderr,
"\tmax_conns is the maximum number of concurrent connections allowed,\n");
	(void) fprintf(stderr, "\t\tand max_conns must be a decimal number");
	(void) fprintf(stderr, "> zero,\n");
	(void) fprintf(stderr, "\tprotocol is a protocol identifier,\n");
	(void) fprintf(stderr,
	    "\ttransport is a transport provider name (i.e. device),\n");
	(void) fprintf(stderr,
	    "\tlisten_backlog is the TCP listen backlog,\n");
	(void) fprintf(stderr,
	    "\tand <nservers> must be a decimal number > zero.\n");
	exit(1);
}

/*
 * Issue nfssys system call to flush all logging buffers asynchronously.
 *
 * NOTICE: It is extremely important to flush NFS logging buffers when
 *	   nfsd exits. When the system is halted or rebooted nfslogd
 *	   may not have an opportunity to flush the buffers.
 */
static void
nfsl_flush()
{
	struct nfsl_flush_args nfa;

	memset((void *)&nfa, 0, sizeof (nfa));
	nfa.version = NFSL_FLUSH_ARGS_VERS;
	nfa.directive = NFSL_ALL;	/* flush all asynchronously */

	if (_nfssys(LOG_FLUSH, &nfa) < 0)
		syslog(LOG_ERR, "_nfssys(LOG_FLUSH) failed: %s\n",
		    strerror(errno));
}

/*
 * SIGTERM handler.
 * Flush logging buffers and exit.
 */
static void
sigflush(int sig)
{
	nfsl_flush();
	_exit(0);
}

/*
 * SIGUSR1 handler.
 *
 * Request that server quiesce, then (nfsd) exit. For subsequent warm start.
 *
 * This is a Contracted Project Private interface, for the sole use
 * of Sun Cluster HA-NFS. See PSARC/2004/497.
 *
 * Equivalent to SIGTERM handler if nfs_server_vers_max < QUIESCE_VERSMIN.
 */
static void
quiesce(int sig)
{
	int error;
	int id = NFS_SVCPOOL_ID;

	if (nfs_server_vers_max >= QUIESCE_VERSMIN) {
		/* Request server quiesce at next shutdown */
		error = _nfssys(NFS4_SVC_REQUEST_QUIESCE, &id);

		/*
		 * ENOENT is returned if there is no matching SVC pool
		 * for the id. Possibly because the pool is not yet setup.
		 * In this case, just exit as if no error. For all other errors,
		 * just return and allow caller to retry.
		 */
		if (error && errno != ENOENT) {
			syslog(LOG_ERR,
			    "_nfssys(NFS4_SVC_REQUEST_QUIESCE) failed: %s",
			    strerror(errno));
			return;
		}
	}

	/* Flush logging buffers */
	nfsl_flush();

	_exit(0);
}

/*
 * DSS: distributed stable storage.
 * Create leaf directories as required, keeping an eye on path
 * lengths. Calls exit(1) on failure.
 * The pathnames passed in must already exist, and must be writeable by nfsd.
 * Note: the leaf directories under NFS4_VAR_DIR are not created here;
 * they're created at pkg install.
 */
static void
dss_mkleafdirs(uint_t npaths, char **pathnames)
{
	int i;
	char *tmppath = NULL;

	/*
	 * Create the temporary storage used by dss_mkleafdir() here,
	 * rather than in that function, so that it only needs to be
	 * done once, rather than once for each call. Too big to put
	 * on the function's stack.
	 */
	tmppath = (char *)malloc(MAXPATHLEN);
	if (tmppath == NULL) {
		syslog(LOG_ERR, "tmppath malloc failed. Exiting");
		exit(1);
	}

	for (i = 0; i < npaths; i++) {
		char *p = pathnames[i];

		dss_mkleafdir(p, NFS4_DSS_STATE_LEAF, tmppath);
		dss_mkleafdir(p, NFS4_DSS_OLDSTATE_LEAF, tmppath);
	}

	free(tmppath);
}

/*
 * Create "leaf" in "dir" (which must already exist).
 * leaf: should start with a '/'
 */
static void
dss_mkleafdir(char *dir, char *leaf, char *tmppath)
{
	/* MAXPATHLEN includes the terminating NUL */
	if (strlen(dir) + strlen(leaf) > MAXPATHLEN - 1) {
		fprintf(stderr, "stable storage path too long: %s%s. "
		    "Exiting.\n", dir, leaf);
		exit(1);
	}

	(void) snprintf(tmppath, MAXPATHLEN, "%s/%s", dir, leaf);

	/* the directory may already exist: that's OK */
	if (mkdir(tmppath, NFS4_DSS_DIR_MODE) == -1 && errno != EEXIST) {
		fprintf(stderr, "error creating stable storage directory: "
		    "%s: %s. Exiting.\n", strerror(errno), tmppath);
		exit(1);
	}
}

/*
 * Create the storage dirs, and pass the path list to the kernel.
 * This requires the nfssrv module to be loaded; the _nfssys() syscall
 * will fail ENOTSUP if it is not.
 * Use libnvpair(3LIB) to pass the data to the kernel.
 */
static int
dss_init(uint_t npaths, char **pathnames)
{
	int i, j, nskipped, error;
	char *bufp;
	uint32_t bufsize;
	size_t buflen;
	nvlist_t *nvl;

	if (npaths > 1) {
		/*
		 * We need to remove duplicate paths; this might be user error
		 * in the general case, but HA-NFSv4 can also cause this.
		 * Sort the pathnames array, and NULL out duplicates,
		 * then write the non-NULL entries to a new array.
		 * Sorting will also allow the kernel to optimise its searches.
		 */

		qsort(pathnames, npaths, sizeof (char *), qstrcmp);

		/* now NULL out any duplicates */
		i = 0; j = 1; nskipped = 0;
		while (j < npaths) {
			if (strcmp(pathnames[i], pathnames[j]) == NULL) {
				pathnames[j] = NULL;
				j++;
				nskipped++;
				continue;
			}

			/* skip i over any of its NULLed duplicates */
			i = j++;
		}

		/* finally, write the non-NULL entries to a new array */
		if (nskipped > 0) {
			int nreal;
			size_t sz;
			char **tmp_pathnames;

			nreal = npaths - nskipped;

			sz = nreal * sizeof (char *);
			tmp_pathnames = (char **)malloc(sz);
			if (tmp_pathnames == NULL) {
				fprintf(stderr, "tmp_pathnames malloc "
				    "failed\n");
				exit(1);
			}

			for (i = 0, j = 0; i < npaths; i++)
				if (pathnames[i] != NULL)
					tmp_pathnames[j++] = pathnames[i];
			free(pathnames);
			pathnames = tmp_pathnames;
			npaths = nreal;
		}

	}

	/* Create directories to store the distributed state files */
	dss_mkleafdirs(npaths, pathnames);

	/* Create the name-value pair list */
	error = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (error) {
		fprintf(stderr, "nvlist_alloc failed: %s\n", strerror(errno));
		return (1);
	}

	/* Add the pathnames array as a single name-value pair */
	error = nvlist_add_string_array(nvl, NFS4_DSS_NVPAIR_NAME,
	    pathnames, npaths);
	if (error) {
		fprintf(stderr, "nvlist_add_string_array failed: %s\n",
		    strerror(errno));
		nvlist_free(nvl);
		return (1);
	}

	/*
	 * Pack list into contiguous memory, for passing to kernel.
	 * nvlist_pack() will allocate the memory for the buffer,
	 * which we should free() when no longer needed.
	 * NV_ENCODE_XDR for safety across ILP32/LP64 kernel boundary.
	 */
	bufp = NULL;
	error = nvlist_pack(nvl, &bufp, &buflen, NV_ENCODE_XDR, 0);
	if (error) {
		fprintf(stderr, "nvlist_pack failed: %s\n", strerror(errno));
		nvlist_free(nvl);
		return (1);
	}

	/* Now we have the packed buffer, we no longer need the list */
	nvlist_free(nvl);

	/*
	 * Let the kernel know in advance how big the buffer is.
	 * NOTE: we cannot just pass buflen, since size_t is a long, and
	 * thus a different size between ILP32 userland and LP64 kernel.
	 * Use an int for the transfer, since that should be big enough;
	 * this is a no-op at the moment, here, since nfsd is 32-bit, but
	 * that could change.
	 */
	bufsize = (uint32_t)buflen;
	error = _nfssys(NFS4_DSS_SETPATHS_SIZE, &bufsize);
	if (error) {
		fprintf(stderr,
		    "_nfssys(NFS4_DSS_SETPATHS_SIZE) failed: %s\n",
		    strerror(errno));
		free(bufp);
		return (1);
	}

	/* Pass the packed buffer to the kernel */
	error = _nfssys(NFS4_DSS_SETPATHS, bufp);
	if (error) {
		fprintf(stderr,
		    "_nfssys(NFS4_DSS_SETPATHS) failed: %s\n", strerror(errno));
		free(bufp);
		return (1);
	}

	/*
	 * The kernel has now unpacked the buffer and extracted the
	 * pathnames array, we no longer need the buffer.
	 */
	free(bufp);

	return (0);
}

/*
 * Quick sort string compare routine, for qsort.
 * Needed to make arg types correct.
 */
int
qstrcmp(const void *p1, const void *p2)
{
	char *s1 = *((char **)p1);
	char *s2 = *((char **)p2);

	return (strcmp(s1, s2));
}
