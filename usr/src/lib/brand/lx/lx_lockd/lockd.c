/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Joyent, Inc.
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
 * lx-brand NFS lockd (NLM) server.
 *
 * This code is derived from the native lockd. The original history starts
 * from:
 *    copied from usr/src/cmd/fs.d/nfs/nfsd/nfsd.c and then s:NFS:NLM: applied
 *
 * On Linux 'lockd' is implemented entirely inside the kernel, whereas our
 * native lockd support is a combination of user-level and kernel code.
 * Unfortunately, the native lockd is unable to run in lx for several reasons:
 * - tightly bound to SMF
 * - interacts with various native libnsl configuration files
 * - expects to register with a native rpcbind using /dev/ticlts
 * Thus, this code is derived from the native lockd, but modified to address
 * these issues and run inside an lx-branded zone. Because the Linux lockd
 * lives entirely in the kernel, our lockd must be started automatically if
 * it is needed. This is done by the NFS mount code when it determines that
 * a lockd is not already running. The kernel code ensures that there is only a
 * single instance of the lockd running, in the case that there is a race with
 * two NFS mounts occuring in parallel.
 *
 * lockd is required for both NFSv3 and v4 locking. Although v4 locking is
 * part of the v4 protocol, the kernel support to allow NFS locking is enabled
 * by the lockd when it starts. For v3, there must be a lockd registered with
 * rpcbind or the server side will fail the lock. This is because the server
 * side expects to make callbacks to the client. We must successfully register
 * with the Linux rpcbind, otherwise the NFS syscall to enable the kernel side
 * of locking will fail. For the v3 case, the user-level Linux mount helper cmd
 * already checks for the presence of rpcbind. It fails if rpcbind is not
 * running and the mount does not include the "nolock" option. For v4 the use
 * of rpcbind appears unnecessary, since locking is built-in to the protocol,
 * but it still required by our kernel NFS locking code.
 *
 * As with the native lockd, the kernel locking code makes upcalls to our lockd
 * over /dev/ticotsord, so that device must be present inside an lx zone.
 *
 * Because this process tries to mimic the Linux kernel lockd, there is no
 * stdin/out/err and we block all signals, unless we're running in debug mode.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include <rpcsvc/nlm_prot.h>
#include <ctype.h>
#include <strings.h>
#include <sys/varargs.h>
#include <rpcsvc/nlm_prot.h>
#include <rpc/pmap_prot.h>
#include "nfs_tbind.h"
#include "thrpool.h"

/* Option defaults.  See nfssys.h */
struct lm_svc_args lmargs = {
	.version = LM_SVC_CUR_VERS,
	/* fd, n_fmly, n_proto, n_rdev (below) */
	.n_v4_only = 0,
	.timout = 5 * 60,
	.grace = 90, /* How long to wait for clients to re-establish locks. */
	.retransmittimeout = 5
};
int max_servers = 256;

#define	RET_OK		0	/* return code for no error */
#define	RET_ERR		33	/* return code for error(s) */

#define	SYSLOG_BLEN	256

int nlmsvc(int fd, struct netbuf addrmask, struct netconfig *nconf);

static int nlmsvcpool(int max_servers);
static void usage(void);

static struct timeval tottimeout = { 60, 0 };
static struct timeval rpcbtime = { 15, 0 };
static const char nullstring[] = "\000";

boolean_t have_rpcbind = B_FALSE;

extern int _nfssys(int, void *);
extern void nlm_do_one(char *, int (*)(int, struct netbuf, struct netconfig *));
extern int nlm_bind_to_provider(char *, struct netbuf **, struct netconfig **);

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
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = nlmsvc;

boolean_t	debug = B_FALSE;

#define	LX_PMAP_VERS	4

/*
 * Set a mapping between program, version and address.
 * Calls the lx-zone's rpcbind service to do the mapping.
 */
boolean_t
lx_rpcb_set(const rpcvers_t version, const struct netconfig *nconf,
    const struct netbuf *address)
{
	CLIENT *client;
	bool_t rslt = FALSE;
	RPCB parms;
	char uidbuf[32];

	client = clnt_create_timed("localhost", PMAPPROG, LX_PMAP_VERS,
	    "datagram_v", &rpcbtime);
	if (client == NULL)
		return (B_FALSE);

	parms.r_addr = taddr2uaddr((struct netconfig *)nconf,
	    (struct netbuf *)address); /* convert to universal */
	if (!parms.r_addr) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		return (B_FALSE);
	}
	parms.r_prog = NLM_PROG;
	parms.r_vers = version;
	parms.r_netid = nconf->nc_netid;
	/*
	 * Though uid is not being used directly, we still send it for
	 * completeness.  For non-unix platforms, perhaps some other
	 * string or an empty string can be sent.
	 */
	(void) sprintf(uidbuf, "%d", (int)geteuid());
	parms.r_owner = uidbuf;

	CLNT_CALL(client, RPCBPROC_SET, (xdrproc_t)xdr_rpcb, (char *)&parms,
	    (xdrproc_t)xdr_bool, (char *)&rslt, tottimeout);

	CLNT_DESTROY(client);
	free(parms.r_addr);
	return (B_TRUE);
}

/*
 * Remove the mapping between program, version and netbuf address.
 * Calls the rpcbind service to do the un-mapping.
 */
void
lx_rpcb_unset(const rpcvers_t version, char *nc_netid)
{
	CLIENT *client;
	bool_t rslt;
	RPCB parms;
	char uidbuf[32];

	if (!have_rpcbind)
		return;

	client = clnt_create_timed("localhost", PMAPPROG, LX_PMAP_VERS,
	    "datagram_v", &rpcbtime);
	if (client == NULL)
		return;

	parms.r_prog = NLM_PROG;
	parms.r_vers = version;
	parms.r_netid = nc_netid;
	parms.r_addr = (char *)&nullstring[0];
	(void) sprintf(uidbuf, "%d", (int)geteuid());
	parms.r_owner = uidbuf;

	CLNT_CALL(client, RPCBPROC_UNSET, (xdrproc_t)xdr_rpcb, (char *)&parms,
	    (xdrproc_t)xdr_bool, (char *)&rslt, tottimeout);

	CLNT_DESTROY(client);
}

static void
lx_nlm_unreg(char *provider)
{
	struct netconfig *retnconf;
	int vers;

	if (nlm_bind_to_provider(provider, NULL, &retnconf) == -1)
		return;

	/* Unregister all versions of the program. */
	for (vers = NLM_VERS; vers <= NLM4_VERS; vers++) {
		lx_rpcb_unset(vers, retnconf->nc_netid);
	}
}

void
lx_syslog(char *fmt, ...)
{
	int fd, l;
	struct sockaddr_un snd_addr;
	char buf[SYSLOG_BLEN], fb[SYSLOG_BLEN], *bp, *fp, *ep;
	va_list ap;

	/* First we replace %m in fmt string with error string into fb. */
	ep = fb + sizeof (fb);
	fb[SYSLOG_BLEN - 1] = '\0';
	for (bp = fb, fp = fmt; bp < ep && (*bp = *fp) != '\0'; bp++, fp++) {
		if (*fp == '%' && *(fp + 1) == 'm') {
			(void) strlcpy(bp, strerror(errno), ep - bp);
			bp += strlen(bp);
			fp += 2;
		}
	}

	va_start(ap, fmt);
	(void) snprintf(buf, sizeof (buf), "  rpc.lockd[%d]: ", getpid());
	l = strlen(buf);
	bp = &buf[l];
	(void) vsnprintf(bp, sizeof (buf) - l, fb, ap);
	va_end(ap);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		return;

	bzero(&snd_addr, sizeof (snd_addr));
	strcpy(snd_addr.sun_path, "/dev/log");
	snd_addr.sun_family = AF_LOCAL;
	l = strlen(snd_addr.sun_path) + sizeof (snd_addr.sun_family);

	if (connect(fd, (struct sockaddr *)&snd_addr, l) == 0) {
		l = strlen(buf);
		(void) send(fd, buf, l, 0);
	}

	close(fd);
}

/* When debugging, ensure cleanup */
static void
sigint_handler(int signal __unused)
{
	NETSELPDECL(providerp);

	lx_syslog("Stopping");

	/* unregister from rpcbind */
	for (providerp = defaultproviders; *providerp != NULL; providerp++) {
		char *provider = *providerp;
		lx_nlm_unreg(provider);
	}
	(void) _nfssys(KILL_LOCKMGR, NULL);

	exit(0);
}

int
main(int ac, char *av[])
{
	NETSELPDECL(providerp);
	int i, c, val;

	if (geteuid() != 0) {
		exit(1);
	}

	/* Initializations that require more privileges than we need to run. */
	if (__init_daemon_priv(PU_RESETGROUPS | PU_CLEARLIMITSET, 1, 1,
	    PRIV_SYS_NFS, NULL) == -1) {
		exit(1);
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	while ((c = getopt(ac, av, "c:dg:l:t:")) != EOF)
		switch (c) {
		case 'c': /* max_connections */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			max_conns_allowed = val;
			break;

		case 'd': /* debug */
			debug = B_TRUE;
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

		case 't': /* retrans_timeout */
			if ((val = atoi(optarg)) <= 0)
				goto badval;
			lmargs.retransmittimeout = val;
			break;

		badval:
			if (debug) {
				fprintf(stderr, "Invalid -%c option value", c);
			}
			/* FALLTHROUGH */
		default:
			if (debug) {
				usage();
			}
			exit(1);
		}

	/* If there is one more argument, it is the number of servers. */
	if (optind < ac) {
		val = atoi(av[optind]);
		if (val <= 0) {
			if (debug) {
				fprintf(stderr, "Invalid max_servers argument");
				usage();
			}
			exit(1);
		}
		max_servers = val;
		optind++;
	}
	/* If there are two or more arguments, then this is a usage error. */
	if (optind != ac) {
		if (debug) {
			usage();
		}
		exit(1);
	}

	if (debug) {
		printf("lx_lockd: debug=%d, conn_idle_timout=%d, "
		    "grace_period=%d, listen_backlog=%d, "
		    "max_connections=%d, max_servers=%d, "
		    "retrans_timeout=%d\n",
		    debug, lmargs.timout, lmargs.grace, listen_backlog,
		    max_conns_allowed, max_servers, lmargs.retransmittimeout);
	}

	/* Set current dir to server root */
	if (chdir("/") < 0) {
		lx_syslog("chdir: %m");
		exit(1);
	}

	if (!debug) {
		/* Block all signals if not debugging. */
		sigset_t set;

		(void) sigfillset(&set);
		(void) sigprocmask(SIG_BLOCK, &set, NULL);
		(void) setsid();
	} else {
		struct sigaction act;

		act.sa_handler = sigint_handler;
		act.sa_flags = 0;
		(void) sigaction(SIGINT, &act, NULL);
	}

	lx_syslog("Starting");

	/* Unregister any previous versions. */
	for (i = NLM_VERS; i < NLM4_VERS; i++) {
		svc_unreg(NLM_PROG, i);
	}

	/* Set up kernel RPC thread pool for the NLM server. */
	if (nlmsvcpool(max_servers)) {
		lx_syslog("Can't set up kernel NLM service: %m. Exiting");
		exit(1);
	}

	/* Set up blocked thread to do LWP creation on behalf of the kernel. */
	if (svcwait(NLM_SVCPOOL_ID)) {
		lx_syslog("Can't set up NLM pool creator: %m. Exiting");
		exit(1);
	}

	for (providerp = defaultproviders; *providerp != NULL; providerp++) {
		char *provider = *providerp;
		nlm_do_one(provider, nlmsvc);
	}

	if (num_fds == 0) {
		lx_syslog("Could not start NLM service for any protocol. "
		    "Exiting");
		exit(1);
	}

	end_listen_fds = num_fds;

	/*
	 * lockd is up and running as far as we are concerned.
	 *
	 * Get rid of unneeded privileges.
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	/* Poll for non-data control events on the transport descriptors. */
	poll_for_action();

	/* If we get here, something failed in poll_for_action(). */
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

/*
 * Establish NLM service thread.
 */
int
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

	if (!have_rpcbind) {
		/*
		 * Inform the kernel NLM code to run without rpcbind and
		 * rpc.statd.
		 */
		lma.n_v4_only = -1;
	}

	return (_nfssys(LM_SVC, &lma));
}

static void
usage(void)
{
	(void) fprintf(stderr, "usage: lx_lockd [options] [max_servers]\n");
	(void) fprintf(stderr, "\t-c max_connections\n");
	(void) fprintf(stderr, "\t-d enable debugging\n");
	(void) fprintf(stderr, "\t-g grace_period\n");
	(void) fprintf(stderr, "\t-l listen_backlog\n");
	(void) fprintf(stderr, "\t-t retransmit_timeout\n");
}
