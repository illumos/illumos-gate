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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides the user level support for the NFSv4
 * callback program.  It is modeled after nfsd.  When a nfsv4
 * mount occurs, the mount command forks and the child runs
 * start_nfs4_callback.  If this is the first mount, then the
 * process will hang around listening for incoming connection
 * requests from the nfsv4 server.
 *
 * For connection-less protocols, the krpc is started immediately.
 * For connection oriented protocols, the kernel module is informed
 * of netid and universal address that it can give this
 * information to the server during setclientid.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <syslog.h>
#include <tiuser.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <thread.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <stdio.h>
#include <stdlib.h>
#include <netconfig.h>
#include <netdir.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <netinet/tcp.h>
#include "nfs_tbind.h"
#include "thrpool.h"
#include <rpcsvc/nfs4_prot.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <priv_utils.h>
#include <rpcsvc/daemon_utils.h>

static	int	nfs4svc(int, struct netbuf *, struct netconfig *, int,
		struct netbuf *);
extern	int	_nfssys(int, void *);

static	char	*MyName;

/*
 * The following are all globals used by routines in nfs_tbind.c.
 */
size_t	end_listen_fds;		/* used by conn_close_oldest() */
size_t	num_fds = 0;		/* used by multiple routines */
int	listen_backlog = 32;	/* used by bind_to_{provider,proto}() */
int	num_servers;		/* used by cots_listen_event() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = NULL;
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */

int
main(int argc, char *argv[])
{
	int pid;
	int i;
	struct protob *protobp;
	struct flock f;
	pid_t pi;
	struct svcpool_args cb_svcpool;

	MyName = "nfs4cbd";
	Mysvc4 = nfs4svc;

#ifndef	DEBUG
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
#endif

	/*
	 * create a child to continue our work
	 * Parent's exit will tell mount command we're ready to go
	 */
	if ((pi = fork()) > 0) {
		exit(0);
	}

	if (pi == -1) {
		(void) syslog(LOG_ERR,
			"Could not start NFS4_CALLBACK service");
		exit(1);
	}

	(void) _create_daemon_lock(NFS4CBD, DAEMON_UID, DAEMON_GID);

	svcsetprio();

	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS, (char *)NULL) == -1) {
		(void) fprintf(stderr, "%s must be run with sufficient"
			" privileges\n", argv[0]);
		exit(1);
	}
	/* Basic privileges we don't need, remove from E/P. */
	__fini_daemon_priv(PRIV_PROC_EXEC, PRIV_PROC_FORK, PRIV_FILE_LINK_ANY,
	    PRIV_PROC_SESSION, PRIV_PROC_INFO, (char *)NULL);

	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	pid = _enter_daemon_lock(NFS4CBD);
	switch (pid) {
	case 0:
		break;
	case -1:
		syslog(LOG_ERR, "error locking for %s: %s", NFS4CBD,
		    strerror(errno));
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	cb_svcpool.id = NFS_CB_SVCPOOL_ID;
	cb_svcpool.maxthreads = 0;
	cb_svcpool.redline = 0;
	cb_svcpool.qsize = 0;
	cb_svcpool.timeout = 0;
	cb_svcpool.stksize = 0;
	cb_svcpool.max_same_xprt = 0;

	/* create a SVC_POOL for the nfsv4 callback deamon */
	if (_nfssys(SVCPOOL_CREATE, &cb_svcpool)) {
		(void) syslog(LOG_ERR, "can't setup NFS_CB SVCPOOL: Exiting");
		exit(1);
	}

	/*
	 * Set up blocked thread to do LWP creation on behalf of the kernel.
	 */
	if (svcwait(NFS_CB_SVCPOOL_ID)) {
		(void) syslog(LOG_ERR,
		    "Can't set up NFS_CB LWP creator: Exiting");
		exit(1);
	}


	/*
	 * Build a protocol block list for registration.
	 */
	protobp = (struct protob *)malloc(sizeof (struct protob));
	protobp->serv = "NFS4_CALLBACK";
	protobp->versmin = NFS_CB;
	protobp->versmax = NFS_CB;
	protobp->program = NFS4_CALLBACK;
	protobp->next = NULL;

	if (do_all(protobp, NULL, 0) == -1) {
		exit(1);
	}

	free(protobp);

	if (num_fds == 0) {
		(void) syslog(LOG_ERR,
		"Could not start NFS4_CALLBACK service for any protocol");
		exit(1);
	}

	end_listen_fds = num_fds;
	/*
	 * Poll for non-data control events on the transport descriptors.
	 */
	poll_for_action();

	/*
	 * If we get here, something failed in poll_for_action().
	 */
	return (1);
}

char *
get_uaddr(int fd, struct netconfig *nconf, struct netbuf *nb)
{
	struct nfs_svc_args nsa;
	char *ua, *ua2, *mua = NULL;
	char me[MAXHOSTNAMELEN];
	struct nd_addrlist *nas;
	struct nd_hostserv hs;
	struct nd_mergearg ma;

	ua = taddr2uaddr(nconf, nb);

	if (ua == NULL) {
#ifdef	DEBUG
		fprintf(stderr, "taddr2uaddr failed for netid %s\n",
			nconf->nc_netid);
#endif
		return (NULL);
	}

	gethostname(me, MAXHOSTNAMELEN);

	hs.h_host = me;
	hs.h_serv = "nfs";
	if (netdir_getbyname(nconf, &hs, &nas)) {
#ifdef DEBUG
		netdir_perror("netdir_getbyname");
#endif
		return (NULL);
	}

	ua2 = taddr2uaddr(nconf, nas->n_addrs);

	if (ua2 == NULL) {
#ifdef	DEBUG
		fprintf(stderr, "taddr2uaddr failed for netid %s.\n",
			nconf->nc_netid);
#endif
		return (NULL);
	}

	ma.s_uaddr = ua;
	ma.c_uaddr = ua2;
	ma.m_uaddr = NULL;

	if (netdir_options(nconf, ND_MERGEADDR, 0, (char *)&ma)) {
#ifdef DEBUG
		netdir_perror("netdir_options");
#endif
		return (NULL);
	}

	mua = ma.m_uaddr;
	return (mua);
}

/*
 * Establish NFS4 callback service thread.
 */
static int
nfs4svc(int fd, struct netbuf *addrmask, struct netconfig *nconf,
	int cmd, struct netbuf *addr)
{
	struct nfs4_svc_args nsa;
	char *ua;
	int error;

	ua = get_uaddr(fd, nconf, addr);

	if (ua == NULL) {
		syslog(LOG_NOTICE, "nfsv4 cannot determine local hostname "
			"binding for transport %s - delegations will not be "
			"available on this transport\n", nconf->nc_netid);
		return (0);
	}

#ifdef	DEBUG
	if (cmd & NFS4_KRPC_START)
		fprintf(stderr, "nfs4cbd: starting callback rpc on %s %s\n",
			nconf->nc_netid, ua);
	else
		fprintf(stderr, "nfs4cbd: listening on %s %s\n",
			nconf->nc_netid, ua);
#endif

	nsa.fd = fd;
	nsa.cmd = cmd;
	nsa.netid = nconf->nc_netid;
	if (addrmask)
		nsa.addrmask = *addrmask;
	else
		bzero(&nsa.addrmask, sizeof (struct netbuf));
	nsa.addr = ua;
	nsa.protofmly = nconf->nc_protofmly;
	nsa.proto = nconf->nc_proto;
	if ((error = _nfssys(NFS4_SVC, &nsa)) != 0)
		syslog(LOG_ERR, "nfssys NFS4_SVC failed\n");

	return (error);
}
