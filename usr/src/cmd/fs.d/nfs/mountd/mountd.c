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
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <sys/stat.h>
#include <netconfig.h>
#include <netdir.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread.h>
#include <assert.h>
#include <priv_utils.h>
#include <nfs/auth.h>
#include <nfs/nfssys.h>
#include <nfs/nfs.h>
#include <nfs/nfs_sec.h>
#include <rpcsvc/daemon_utils.h>
#include <deflt.h>
#include "../../fslib.h"
#include <sharefs/share.h>
#include <sharefs/sharetab.h>
#include "../lib/sharetab.h"
#include "mountd.h"
#include <tsol/label.h>
#include <sys/tsol/label_macro.h>
#include <libtsnet.h>
#include <sys/sdt.h>
#include <libscf.h>
#include <limits.h>
#include <sys/nvpair.h>
#include <attr.h>
#include "smfcfg.h"
#include <pwd.h>
#include <grp.h>

extern int daemonize_init(void);
extern void daemonize_fini(int fd);

struct sh_list *share_list;

rwlock_t sharetab_lock;		/* lock to protect the cached sharetab */
static mutex_t mnttab_lock;	/* prevent concurrent mnttab readers */

static mutex_t logging_queue_lock;
static cond_t logging_queue_cv;

static share_t *find_lofsentry(char *, int *);
static int getclientsnames_lazy(char *, struct netbuf **,
	struct nd_hostservlist **);
static int getclientsnames(SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **);
static int getclientsflavors_old(share_t *, SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **, int *);
static int getclientsflavors_new(share_t *, SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **, int *);
static int check_client_old(share_t *, SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **, int, uid_t, gid_t, uid_t *, gid_t *);
static int check_client_new(share_t *, SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **, int, uid_t, gid_t, uid_t *, gid_t *);
static void mnt(struct svc_req *, SVCXPRT *);
static void mnt_pathconf(struct svc_req *);
static int mount(struct svc_req *r);
static void sh_free(struct sh_list *);
static void umount(struct svc_req *);
static void umountall(struct svc_req *);
static void sigexit(int);
static int newopts(char *);
static tsol_tpent_t *get_client_template(struct sockaddr *);

static int verbose;
static int rejecting;
static int mount_vers_min = MOUNTVERS;
static int mount_vers_max = MOUNTVERS3;

/* Needs to be accessed by nfscmd.c */
int  in_access_list(SVCXPRT *, struct netbuf **,
	struct nd_hostservlist **, char *);

extern void nfscmd_func(void *, char *, size_t, door_desc_t *, uint_t);

thread_t	nfsauth_thread;
thread_t	cmd_thread;
thread_t	logging_thread;

typedef struct logging_data {
	char			*ld_host;
	char			*ld_path;
	char			*ld_rpath;
	int			ld_status;
	char			*ld_netid;
	struct netbuf		*ld_nb;
	struct logging_data	*ld_next;
} logging_data;

static logging_data *logging_head = NULL;
static logging_data *logging_tail = NULL;

/* ARGSUSED */
static void *
nfsauth_svc(void *arg)
{
	int	doorfd = -1;
	uint_t	darg;
#ifdef DEBUG
	int	dfd;
#endif

	if ((doorfd = door_create(nfsauth_func, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, "Unable to create door: %m\n");
		exit(10);
	}

#ifdef DEBUG
	/*
	 * Create a file system path for the door
	 */
	if ((dfd = open(MOUNTD_DOOR, O_RDWR|O_CREAT|O_TRUNC,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1) {
		syslog(LOG_ERR, "Unable to open %s: %m\n", MOUNTD_DOOR);
		(void) close(doorfd);
		exit(11);
	}

	/*
	 * Clean up any stale namespace associations
	 */
	(void) fdetach(MOUNTD_DOOR);

	/*
	 * Register in namespace to pass to the kernel to door_ki_open
	 */
	if (fattach(doorfd, MOUNTD_DOOR) == -1) {
		syslog(LOG_ERR, "Unable to fattach door: %m\n");
		(void) close(dfd);
		(void) close(doorfd);
		exit(12);
	}
	(void) close(dfd);
#endif

	/*
	 * Must pass the doorfd down to the kernel.
	 */
	darg = doorfd;
	(void) _nfssys(MOUNTD_ARGS, &darg);

	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	for (;;)
		(void) pause();

	/*NOTREACHED*/
	syslog(LOG_ERR, gettext("Door server exited"));
	return (NULL);
}

/*
 * NFS command service thread code for setup and handling of the
 * nfs_cmd requests for character set conversion and other future
 * events.
 */

static void *
cmd_svc(void *arg)
{
	int	doorfd = -1;
	uint_t	darg;

	if ((doorfd = door_create(nfscmd_func, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, "Unable to create cmd door: %m\n");
		exit(10);
	}

	/*
	 * Must pass the doorfd down to the kernel.
	 */
	darg = doorfd;
	(void) _nfssys(NFSCMD_ARGS, &darg);

	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	for (;;)
		(void) pause();

	/*NOTREACHED*/
	syslog(LOG_ERR, gettext("Cmd door server exited"));
	return (NULL);
}

static void
free_logging_data(logging_data *lq)
{
	if (lq != NULL) {
		free(lq->ld_host);
		free(lq->ld_netid);

		if (lq->ld_nb != NULL) {
			free(lq->ld_nb->buf);
			free(lq->ld_nb);
		}

		free(lq->ld_path);
		free(lq->ld_rpath);

		free(lq);
	}
}

static logging_data *
remove_head_of_queue(void)
{
	logging_data    *lq;

	/*
	 * Pull it off the queue.
	 */
	lq = logging_head;
	if (lq) {
		logging_head = lq->ld_next;

		/*
		 * Drained it.
		 */
		if (logging_head == NULL) {
			logging_tail = NULL;
		}
	}

	return (lq);
}

static void
do_logging_queue(logging_data *lq)
{
	int		cleared = 0;
	char		*host;

	struct nd_hostservlist	*clnames;

	while (lq) {
		if (lq->ld_host == NULL) {
			DTRACE_PROBE(mountd, name_by_lazy);
			if (getclientsnames_lazy(lq->ld_netid,
			    &lq->ld_nb, &clnames) != 0)
				host = NULL;
			else
				host = clnames->h_hostservs[0].h_host;
		} else
			host = lq->ld_host;

		audit_mountd_mount(host, lq->ld_path, lq->ld_status); /* BSM */

		/* add entry to mount list */
		if (lq->ld_rpath)
			mntlist_new(host, lq->ld_rpath);

		if (lq->ld_host != host)
			netdir_free(clnames, ND_HOSTSERVLIST);

		free_logging_data(lq);
		cleared++;

		(void) mutex_lock(&logging_queue_lock);
		lq = remove_head_of_queue();
		(void) mutex_unlock(&logging_queue_lock);
	}

	DTRACE_PROBE1(mountd, logging_cleared, cleared);
}

static void *
logging_svc(void *arg)
{
	logging_data	*lq;

	for (;;) {
		(void) mutex_lock(&logging_queue_lock);
		while (logging_head == NULL) {
			(void) cond_wait(&logging_queue_cv,
			    &logging_queue_lock);
		}

		lq = remove_head_of_queue();
		(void) mutex_unlock(&logging_queue_lock);

		do_logging_queue(lq);
	}

	/*NOTREACHED*/
	syslog(LOG_ERR, gettext("Logging server exited"));
	return (NULL);
}

static int
convert_int(int *val, char *str)
{
	long lval;

	if (str == NULL || !isdigit(*str))
		return (-1);

	lval = strtol(str, &str, 10);
	if (*str != '\0' || lval > INT_MAX)
		return (-2);

	*val = (int)lval;
	return (0);
}

int
main(int argc, char *argv[])
{
	int	pid;
	int	c;
	int	rpc_svc_fdunlim = 1;
	int	rpc_svc_mode = RPC_SVC_MT_AUTO;
	int	maxrecsz = RPC_MAXDATASIZE;
	bool_t	exclbind = TRUE;
	bool_t	can_do_mlp;
	long	thr_flags = (THR_NEW_LWP|THR_DAEMON);
	char defval[4];
	int defvers, ret, bufsz;
	struct rlimit rl;
	int listen_backlog = 0;
	int max_threads = 0;
	int tmp;

	int	pipe_fd = -1;

	/*
	 * Mountd requires uid 0 for:
	 *	/etc/rmtab updates (we could chown it to daemon)
	 *	/etc/dfs/dfstab reading (it wants to lock out share which
	 *		doesn't do any locking before first truncate;
	 *		NFS share does; should use fcntl locking instead)
	 *	Needed privileges:
	 *		auditing
	 *		nfs syscall
	 *		file dac search (so it can stat all files)
	 *	Optional privileges:
	 *		MLP
	 */
	can_do_mlp = priv_ineffect(PRIV_NET_BINDMLP);
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET, -1, -1,
	    PRIV_SYS_NFS, PRIV_PROC_AUDIT, PRIV_FILE_DAC_SEARCH,
	    can_do_mlp ? PRIV_NET_BINDMLP : NULL, NULL) == -1) {
		(void) fprintf(stderr,
		    "%s: must be run with sufficient privileges\n",
		    argv[0]);
		exit(1);
	}

	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		syslog(LOG_ERR, "getrlimit failed");
	} else {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			syslog(LOG_ERR, "setrlimit failed");
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	ret = nfs_smf_get_iprop("mountd_max_threads", &max_threads,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, NFSD);
	if (ret != SA_OK) {
		syslog(LOG_ERR, "Reading of mountd_max_threads from SMF "
		    "failed, using default value");
	}

	while ((c = getopt(argc, argv, "vrm:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'r':
			rejecting = 1;
			break;
		case 'm':
			if (convert_int(&tmp, optarg) != 0 || tmp < 1) {
				(void) fprintf(stderr, "%s: invalid "
				    "max_threads option, using defaults\n",
				    argv[0]);
				break;
			}
			max_threads = tmp;
			break;
		default:
			fprintf(stderr, "usage: mountd [-v] [-r]\n");
			exit(1);
		}
	}

	/*
	 * Read in the NFS version values from config file.
	 */
	bufsz = 4;
	ret = nfs_smf_get_prop("server_versmin", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		defvers = strtol(defval, (char **)NULL, 10);
		if (errno == 0) {
			mount_vers_min = defvers;
			/*
			 * special because NFSv2 is
			 * supported by mount v1 & v2
			 */
			if (defvers == NFS_VERSION)
				mount_vers_min = MOUNTVERS;
		}
	}

	bufsz = 4;
	ret = nfs_smf_get_prop("server_versmax", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, NFSD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		defvers = strtol(defval, (char **)NULL, 10);
		if (errno == 0) {
			mount_vers_max = defvers;
		}
	}

	ret = nfs_smf_get_iprop("mountd_listen_backlog", &listen_backlog,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, NFSD);
	if (ret != SA_OK) {
		syslog(LOG_ERR, "Reading of mountd_listen_backlog from SMF "
		    "failed, using default value");
	}

	/*
	 * Sanity check versions,
	 * even though we may get versions > MOUNTVERS3, we still need
	 * to start nfsauth service, so continue on regardless of values.
	 */
	if (mount_vers_min > mount_vers_max) {
		fprintf(stderr, "server_versmin > server_versmax\n");
		mount_vers_max = mount_vers_min;
	}
	(void) setlocale(LC_ALL, "");
	(void) rwlock_init(&sharetab_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&mnttab_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&logging_queue_lock, USYNC_THREAD, NULL);
	(void) cond_init(&logging_queue_cv, USYNC_THREAD, NULL);

	netgroup_init();

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Don't drop core if the NFS module isn't loaded. */
	(void) signal(SIGSYS, SIG_IGN);

	pipe_fd = daemonize_init();

	/*
	 * If we coredump it'll be in /core
	 */
	if (chdir("/") < 0)
		fprintf(stderr, "chdir /: %s\n", strerror(errno));

	openlog("mountd", LOG_PID, LOG_DAEMON);

	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	pid = _enter_daemon_lock(MOUNTD);
	switch (pid) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "error locking for %s: %s\n", MOUNTD,
		    strerror(errno));
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	audit_mountd_setup();	/* BSM */

	/*
	 * Set number of file descriptors to unlimited
	 */
	if (!rpc_control(RPC_SVC_USE_POLLFD, &rpc_svc_fdunlim)) {
		syslog(LOG_INFO, "unable to set number of FDs to unlimited");
	}

	/*
	 * Tell RPC that we want automatic thread mode.
	 * A new thread will be spawned for each request.
	 */
	if (!rpc_control(RPC_SVC_MTMODE_SET, &rpc_svc_mode)) {
		fprintf(stderr, "unable to set automatic MT mode\n");
		exit(1);
	}

	/*
	 * Enable non-blocking mode and maximum record size checks for
	 * connection oriented transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrecsz)) {
		fprintf(stderr, "unable to set RPC max record size\n");
	}

	/*
	 * Prevent our non-priv udp and tcp ports bound w/wildcard addr
	 * from being hijacked by a bind to a more specific addr.
	 */
	if (!rpc_control(__RPC_SVC_EXCLBIND_SET, &exclbind)) {
		fprintf(stderr, "warning: unable to set udp/tcp EXCLBIND\n");
	}

	/*
	 * Set the maximum number of outstanding connection
	 * indications (listen backlog) to the value specified.
	 */
	if (listen_backlog > 0 && !rpc_control(__RPC_SVC_LSTNBKLOG_SET,
	    &listen_backlog)) {
		fprintf(stderr, "unable to set listen backlog\n");
		exit(1);
	}

	/*
	 * If max_threads was specified, then set the
	 * maximum number of threads to the value specified.
	 */
	if (max_threads > 0 && !rpc_control(RPC_SVC_THRMAX_SET, &max_threads)) {
		fprintf(stderr, "unable to set max_threads\n");
		exit(1);
	}

	/*
	 * Make sure to unregister any previous versions in case the
	 * user is reconfiguring the server in interesting ways.
	 */
	svc_unreg(MOUNTPROG, MOUNTVERS);
	svc_unreg(MOUNTPROG, MOUNTVERS_POSIX);
	svc_unreg(MOUNTPROG, MOUNTVERS3);

	/*
	 * Create the nfsauth thread with same signal disposition
	 * as the main thread. We need to create a separate thread
	 * since mountd() will be both an RPC server (for remote
	 * traffic) _and_ a doors server (for kernel upcalls).
	 */
	if (thr_create(NULL, 0, nfsauth_svc, 0, thr_flags, &nfsauth_thread)) {
		fprintf(stderr,
		    gettext("Failed to create NFSAUTH svc thread\n"));
		exit(2);
	}

	/*
	 * Create the cmd service thread with same signal disposition
	 * as the main thread. We need to create a separate thread
	 * since mountd() will be both an RPC server (for remote
	 * traffic) _and_ a doors server (for kernel upcalls).
	 */
	if (thr_create(NULL, 0, cmd_svc, 0, thr_flags, &cmd_thread)) {
		syslog(LOG_ERR, gettext("Failed to create CMD svc thread"));
		exit(2);
	}

	/*
	 * Create an additional thread to service the rmtab and
	 * audit_mountd_mount logging for mount requests. Use the same
	 * signal disposition as the main thread. We create
	 * a separate thread to allow the mount request threads to
	 * clear as soon as possible.
	 */
	if (thr_create(NULL, 0, logging_svc, 0, thr_flags, &logging_thread)) {
		syslog(LOG_ERR, gettext("Failed to create LOGGING svc thread"));
		exit(2);
	}

	/*
	 * Create datagram and connection oriented services
	 */
	if (mount_vers_max >= MOUNTVERS) {
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS, "datagram_v") == 0) {
			fprintf(stderr,
			    "couldn't register datagram_v MOUNTVERS\n");
			exit(1);
		}
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS, "circuit_v") == 0) {
			fprintf(stderr,
			    "couldn't register circuit_v MOUNTVERS\n");
			exit(1);
		}
	}

	if (mount_vers_max >= MOUNTVERS_POSIX) {
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS_POSIX,
		    "datagram_v") == 0) {
			fprintf(stderr,
			    "couldn't register datagram_v MOUNTVERS_POSIX\n");
			exit(1);
		}
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS_POSIX,
		    "circuit_v") == 0) {
			fprintf(stderr,
			    "couldn't register circuit_v MOUNTVERS_POSIX\n");
			exit(1);
		}
	}

	if (mount_vers_max >= MOUNTVERS3) {
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS3, "datagram_v") == 0) {
			fprintf(stderr,
			    "couldn't register datagram_v MOUNTVERS3\n");
			exit(1);
		}
		if (svc_create(mnt, MOUNTPROG, MOUNTVERS3, "circuit_v") == 0) {
			fprintf(stderr,
			    "couldn't register circuit_v MOUNTVERS3\n");
			exit(1);
		}
	}

	/*
	 * Start serving
	 */
	rmtab_load();

	daemonize_fini(pipe_fd);

	/* Get rid of the most dangerous basic privileges. */
	__fini_daemon_priv(PRIV_PROC_EXEC, PRIV_PROC_INFO, PRIV_PROC_SESSION,
	    (char *)NULL);

	svc_run();
	syslog(LOG_ERR, "Error: svc_run shouldn't have returned");
	abort();

	/* NOTREACHED */
	return (0);
}

/*
 * Server procedure switch routine
 */
void
mnt(struct svc_req *rqstp, SVCXPRT *transp)
{
	switch (rqstp->rq_proc) {
	case NULLPROC:
		errno = 0;
		if (!svc_sendreply(transp, xdr_void, (char *)0))
			log_cant_reply(transp);
		return;

	case MOUNTPROC_MNT:
		(void) mount(rqstp);
		return;

	case MOUNTPROC_DUMP:
		mntlist_send(transp);
		return;

	case MOUNTPROC_UMNT:
		umount(rqstp);
		return;

	case MOUNTPROC_UMNTALL:
		umountall(rqstp);
		return;

	case MOUNTPROC_EXPORT:
	case MOUNTPROC_EXPORTALL:
		export(rqstp);
		return;

	case MOUNTPROC_PATHCONF:
		if (rqstp->rq_vers == MOUNTVERS_POSIX)
			mnt_pathconf(rqstp);
		else
			svcerr_noproc(transp);
		return;

	default:
		svcerr_noproc(transp);
		return;
	}
}

/* Set up anonymous client */

struct nd_hostservlist *
anon_client(char *host)
{
	struct nd_hostservlist *anon_hsl;
	struct nd_hostserv *anon_hs;

	anon_hsl = malloc(sizeof (*anon_hsl));
	if (anon_hsl == NULL)
		return (NULL);

	anon_hs = malloc(sizeof (*anon_hs));
	if (anon_hs == NULL) {
		free(anon_hsl);
		return (NULL);
	}

	if (host == NULL)
		anon_hs->h_host = strdup("(anon)");
	else
		anon_hs->h_host = strdup(host);

	if (anon_hs->h_host == NULL) {
		free(anon_hs);
		free(anon_hsl);
		return (NULL);
	}
	anon_hs->h_serv = '\0';

	anon_hsl->h_cnt = 1;
	anon_hsl->h_hostservs = anon_hs;

	return (anon_hsl);
}

static int
getclientsnames_common(struct netconfig *nconf, struct netbuf **nbuf,
    struct nd_hostservlist **serv)
{
	char host[MAXIPADDRLEN];

	assert(*nbuf != NULL);

	/*
	 * Use the this API instead of the netdir_getbyaddr()
	 * to avoid service lookup.
	 */
	if (__netdir_getbyaddr_nosrv(nconf, serv, *nbuf) != 0) {
		if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
			struct sockaddr_in *sa;

			/* LINTED pointer alignment */
			sa = (struct sockaddr_in *)((*nbuf)->buf);
			(void) inet_ntoa_r(sa->sin_addr, host);
		} else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			struct sockaddr_in6 *sa;

			/* LINTED pointer alignment */
			sa = (struct sockaddr_in6 *)((*nbuf)->buf);
			(void) inet_ntop(AF_INET6, sa->sin6_addr.s6_addr,
			    host, INET6_ADDRSTRLEN);
		} else {
			syslog(LOG_ERR, gettext(
			    "Client's address is neither IPv4 nor IPv6"));
			return (EINVAL);
		}

		*serv = anon_client(host);
		if (*serv == NULL)
			return (ENOMEM);
	}

	assert(*serv != NULL);
	return (0);
}

/*
 * Get the client's hostname from the copy of the
 * relevant transport handle parts.
 * If the name is not available then return "(anon)".
 */
static int
getclientsnames_lazy(char *netid, struct netbuf **nbuf,
    struct nd_hostservlist **serv)
{
	struct netconfig *nconf;
	int	rc;

	nconf = getnetconfigent(netid);
	if (nconf == NULL) {
		syslog(LOG_ERR, "%s: getnetconfigent failed", netid);
		*serv = anon_client(NULL);
		if (*serv == NULL)
			return (ENOMEM);
		return (0);
	}

	rc = getclientsnames_common(nconf, nbuf, serv);
	freenetconfigent(nconf);
	return (rc);
}

/*
 * Get the client's hostname from the transport handle.
 * If the name is not available then return "(anon)".
 */
int
getclientsnames(SVCXPRT *transp, struct netbuf **nbuf,
    struct nd_hostservlist **serv)
{
	struct netconfig *nconf;
	int	rc;

	nconf = getnetconfigent(transp->xp_netid);
	if (nconf == NULL) {
		syslog(LOG_ERR, "%s: getnetconfigent failed",
		    transp->xp_netid);
		*serv = anon_client(NULL);
		if (*serv == NULL)
			return (ENOMEM);
		return (0);
	}

	*nbuf = svc_getrpccaller(transp);
	if (*nbuf == NULL) {
		freenetconfigent(nconf);
		*serv = anon_client(NULL);
		if (*serv == NULL)
			return (ENOMEM);
		return (0);
	}

	rc = getclientsnames_common(nconf, nbuf, serv);
	freenetconfigent(nconf);
	return (rc);
}

void
log_cant_reply(SVCXPRT *transp)
{
	int saverrno;
	struct nd_hostservlist *clnames = NULL;
	register char *host;
	struct netbuf *nb;

	saverrno = errno;	/* save error code */
	if (getclientsnames(transp, &nb, &clnames) != 0)
		return;
	host = clnames->h_hostservs->h_host;

	errno = saverrno;
	if (errno == 0)
		syslog(LOG_ERR, "couldn't send reply to %s", host);
	else
		syslog(LOG_ERR, "couldn't send reply to %s: %m", host);

	netdir_free(clnames, ND_HOSTSERVLIST);
}

/*
 * Answer pathconf questions for the mount point fs
 */
static void
mnt_pathconf(struct svc_req *rqstp)
{
	SVCXPRT *transp;
	struct pathcnf p;
	char *path, rpath[MAXPATHLEN];
	struct stat st;

	transp = rqstp->rq_xprt;
	path = NULL;
	(void) memset((caddr_t)&p, 0, sizeof (p));

	if (!svc_getargs(transp, xdr_dirpath, (caddr_t)&path)) {
		svcerr_decode(transp);
		return;
	}
	if (lstat(path, &st) < 0) {
		_PC_SET(_PC_ERROR, p.pc_mask);
		goto done;
	}
	/*
	 * Get a path without symbolic links.
	 */
	if (realpath(path, rpath) == NULL) {
		syslog(LOG_DEBUG,
		    "mount request: realpath failed on %s: %m",
		    path);
		_PC_SET(_PC_ERROR, p.pc_mask);
		goto done;
	}
	(void) memset((caddr_t)&p, 0, sizeof (p));
	/*
	 * can't ask about devices over NFS
	 */
	_PC_SET(_PC_MAX_CANON, p.pc_mask);
	_PC_SET(_PC_MAX_INPUT, p.pc_mask);
	_PC_SET(_PC_PIPE_BUF, p.pc_mask);
	_PC_SET(_PC_VDISABLE, p.pc_mask);

	errno = 0;
	p.pc_link_max = pathconf(rpath, _PC_LINK_MAX);
	if (errno)
		_PC_SET(_PC_LINK_MAX, p.pc_mask);
	p.pc_name_max = pathconf(rpath, _PC_NAME_MAX);
	if (errno)
		_PC_SET(_PC_NAME_MAX, p.pc_mask);
	p.pc_path_max = pathconf(rpath, _PC_PATH_MAX);
	if (errno)
		_PC_SET(_PC_PATH_MAX, p.pc_mask);
	if (pathconf(rpath, _PC_NO_TRUNC) == 1)
		_PC_SET(_PC_NO_TRUNC, p.pc_mask);
	if (pathconf(rpath, _PC_CHOWN_RESTRICTED) == 1)
		_PC_SET(_PC_CHOWN_RESTRICTED, p.pc_mask);

done:
	errno = 0;
	if (!svc_sendreply(transp, xdr_ppathcnf, (char *)&p))
		log_cant_reply(transp);
	if (path != NULL)
		svc_freeargs(transp, xdr_dirpath, (caddr_t)&path);
}

/*
 * If the rootmount (export) option is specified, the all mount requests for
 * subdirectories return EACCES.
 */
static int
checkrootmount(share_t *sh, char *rpath)
{
	char *val;

	if ((val = getshareopt(sh->sh_opts, SHOPT_NOSUB)) != NULL) {
		free(val);
		if (strcmp(sh->sh_path, rpath) != 0)
			return (0);
		else
			return (1);
	} else
		return (1);
}

#define	MAX_FLAVORS	128

/*
 * Return only EACCES if client does not have access
 *  to this directory.
 * "If the server exports only /a/b, an attempt to
 *  mount a/b/c will fail with ENOENT if the directory
 *  does not exist"... However, if the client
 *  does not have access to /a/b, an attacker can
 *  determine whether the directory exists.
 * This routine checks either existence of the file or
 * existence of the file name entry in the mount table.
 * If the file exists and there is no file name entry,
 * the error returned should be EACCES.
 * If the file does not exist, it must be determined
 * whether the client has access to a parent
 * directory.  If the client has access to a parent
 * directory, the error returned should be ENOENT,
 * otherwise EACCES.
 */
static int
mount_enoent_error(SVCXPRT *transp, char *path, char *rpath,
    struct nd_hostservlist **clnames, struct netbuf **nb, int *flavor_list)
{
	char *checkpath, *dp;
	share_t *sh = NULL;
	int realpath_error = ENOENT, reply_error = EACCES, lofs_tried = 0;
	int flavor_count;

	checkpath = strdup(path);
	if (checkpath == NULL) {
		syslog(LOG_ERR, "mount_enoent: no memory");
		return (EACCES);
	}

	/* CONSTCOND */
	while (1) {
		if (sh) {
			sharefree(sh);
			sh = NULL;
		}

		if ((sh = findentry(rpath)) == NULL &&
		    (sh = find_lofsentry(rpath, &lofs_tried)) == NULL) {
			/*
			 * There is no file name entry.
			 * If the file (with symbolic links resolved) exists,
			 * the error returned should be EACCES.
			 */
			if (realpath_error == 0)
				break;
		} else if (checkrootmount(sh, rpath) == 0) {
			/*
			 * This is a "nosub" only export, in which case,
			 * mounting subdirectories isn't allowed.
			 * If the file (with symbolic links resolved) exists,
			 * the error returned should be EACCES.
			 */
			if (realpath_error == 0)
				break;
		} else {
			/*
			 * Check permissions in mount table.
			 */
			if (newopts(sh->sh_opts))
				flavor_count = getclientsflavors_new(sh,
				    transp, nb, clnames, flavor_list);
			else
				flavor_count = getclientsflavors_old(sh,
				    transp, nb, clnames, flavor_list);
			if (flavor_count != 0) {
				/*
				 * Found entry in table and
				 * client has correct permissions.
				 */
				reply_error = ENOENT;
				break;
			}
		}

		/*
		 * Check all parent directories.
		 */
		dp = strrchr(checkpath, '/');
		if (dp == NULL)
			break;
		*dp = '\0';
		if (strlen(checkpath) == 0)
			break;
		/*
		 * Get the real path (no symbolic links in it)
		 */
		if (realpath(checkpath, rpath) == NULL) {
			if (errno != ENOENT)
				break;
		} else {
			realpath_error = 0;
		}
	}

	if (sh)
		sharefree(sh);
	free(checkpath);
	return (reply_error);
}

/*
 * We need to inform the caller whether or not we were
 * able to add a node to the queue. If we are not, then
 * it is up to the caller to go ahead and log the data.
 */
static int
enqueue_logging_data(char *host, SVCXPRT *transp, char *path,
    char *rpath, int status, int error)
{
	logging_data	*lq;
	struct netbuf	*nb;

	lq = (logging_data *)calloc(1, sizeof (logging_data));
	if (lq == NULL)
		goto cleanup;

	/*
	 * We might not yet have the host...
	 */
	if (host) {
		DTRACE_PROBE1(mountd, log_host, host);
		lq->ld_host = strdup(host);
		if (lq->ld_host == NULL)
			goto cleanup;
	} else {
		DTRACE_PROBE(mountd, log_no_host);

		lq->ld_netid = strdup(transp->xp_netid);
		if (lq->ld_netid == NULL)
			goto cleanup;

		lq->ld_nb = calloc(1, sizeof (struct netbuf));
		if (lq->ld_nb == NULL)
			goto cleanup;

		nb = svc_getrpccaller(transp);
		if (nb == NULL) {
			DTRACE_PROBE(mountd, e__nb__enqueue);
			goto cleanup;
		}

		DTRACE_PROBE(mountd, nb_set_enqueue);

		lq->ld_nb->maxlen = nb->maxlen;
		lq->ld_nb->len = nb->len;

		lq->ld_nb->buf = malloc(lq->ld_nb->len);
		if (lq->ld_nb->buf == NULL)
			goto cleanup;

		bcopy(nb->buf, lq->ld_nb->buf, lq->ld_nb->len);
	}

	lq->ld_path = strdup(path);
	if (lq->ld_path == NULL)
		goto cleanup;

	if (!error) {
		lq->ld_rpath = strdup(rpath);
		if (lq->ld_rpath == NULL)
			goto cleanup;
	}

	lq->ld_status = status;

	/*
	 * Add to the tail of the logging queue.
	 */
	(void) mutex_lock(&logging_queue_lock);
	if (logging_tail == NULL) {
		logging_tail = logging_head = lq;
	} else {
		logging_tail->ld_next = lq;
		logging_tail = lq;
	}
	(void) cond_signal(&logging_queue_cv);
	(void) mutex_unlock(&logging_queue_lock);

	return (TRUE);

cleanup:

	free_logging_data(lq);

	return (FALSE);
}

/*
 * Check mount requests, add to mounted list if ok
 */
static int
mount(struct svc_req *rqstp)
{
	SVCXPRT *transp;
	int version, vers;
	struct fhstatus fhs;
	struct mountres3 mountres3;
	char fh[FHSIZE3];
	int len = FHSIZE3;
	char *path, rpath[MAXPATHLEN];
	share_t *sh = NULL;
	struct nd_hostservlist *clnames = NULL;
	char *host = NULL;
	int error = 0, lofs_tried = 0, enqueued;
	int flavor_list[MAX_FLAVORS];
	int flavor_count;
	struct netbuf *nb = NULL;
	ucred_t	*uc = NULL;

	int audit_status;

	transp = rqstp->rq_xprt;
	version = rqstp->rq_vers;
	path = NULL;

	if (!svc_getargs(transp, xdr_dirpath, (caddr_t)&path)) {
		svcerr_decode(transp);
		return (EACCES);
	}

	/*
	 * Put off getting the name for the client until we
	 * need it. This is a performance gain. If we are logging,
	 * then we don't care about performance and might as well
	 * get the host name now in case we need to spit out an
	 * error message.
	 */
	if (verbose) {
		DTRACE_PROBE(mountd, name_by_verbose);
		if (getclientsnames(transp, &nb, &clnames) != 0) {
			/*
			 * We failed to get a name for the client, even
			 * 'anon', probably because we ran out of memory.
			 * In this situation it doesn't make sense to
			 * allow the mount to succeed.
			 */
			error = EACCES;
			goto reply;
		}
		host = clnames->h_hostservs[0].h_host;
	}

	/*
	 * If the version being used is less than the minimum version,
	 * the filehandle translation should not be provided to the
	 * client.
	 */
	if (rejecting || version < mount_vers_min) {
		if (verbose)
			syslog(LOG_NOTICE, "Rejected mount: %s for %s",
			    host, path);
		error = EACCES;
		goto reply;
	}

	/*
	 * Trusted Extension doesn't support nfsv2. nfsv2 client
	 * uses MOUNT protocol v1 and v2. To prevent circumventing
	 * TX label policy via using nfsv2 client, reject a mount
	 * request with version less than 3 and log an error.
	 */
	if (is_system_labeled()) {
		if (version < 3) {
			if (verbose)
				syslog(LOG_ERR,
				    "Rejected mount: TX doesn't support NFSv2");
			error = EACCES;
			goto reply;
		}
	}

	/*
	 * Get the real path (no symbolic links in it)
	 */
	if (realpath(path, rpath) == NULL) {
		error = errno;
		if (verbose)
			syslog(LOG_ERR,
			    "mount request: realpath: %s: %m", path);
		if (error == ENOENT)
			error = mount_enoent_error(transp, path, rpath,
			    &clnames, &nb, flavor_list);
		goto reply;
	}

	if ((sh = findentry(rpath)) == NULL &&
	    (sh = find_lofsentry(rpath, &lofs_tried)) == NULL) {
		error = EACCES;
		goto reply;
	}

	/*
	 * Check if this is a "nosub" only export, in which case, mounting
	 * subdirectories isn't allowed. Bug 1184573.
	 */
	if (checkrootmount(sh, rpath) == 0) {
		error = EACCES;
		goto reply;
	}

	if (newopts(sh->sh_opts))
		flavor_count = getclientsflavors_new(sh, transp, &nb, &clnames,
		    flavor_list);
	else
		flavor_count = getclientsflavors_old(sh, transp, &nb, &clnames,
		    flavor_list);

	if (clnames)
		host = clnames->h_hostservs[0].h_host;

	if (flavor_count == 0) {
		error = EACCES;
		goto reply;
	}

	/*
	 * Check MAC policy here. The server side policy should be
	 * consistent with client side mount policy, i.e.
	 * - we disallow an admin_low unlabeled client to mount
	 * - we disallow mount from a lower labeled client.
	 */
	if (is_system_labeled()) {
		m_label_t *clabel = NULL;
		m_label_t *slabel = NULL;
		m_label_t admin_low;

		if (svc_getcallerucred(rqstp->rq_xprt, &uc) != 0) {
			syslog(LOG_ERR,
			    "mount request: Failed to get caller's ucred : %m");
			error = EACCES;
			goto reply;
		}
		if ((clabel = ucred_getlabel(uc)) == NULL) {
			syslog(LOG_ERR,
			    "mount request: can't get client label from ucred");
			error = EACCES;
			goto reply;
		}

		bsllow(&admin_low);
		if (blequal(&admin_low, clabel)) {
			struct sockaddr *ca;
			tsol_tpent_t	*tp;

			ca = (struct sockaddr *)(void *)svc_getrpccaller(
			    rqstp->rq_xprt)->buf;
			if (ca == NULL) {
				error = EACCES;
				goto reply;
			}
			/*
			 * get trusted network template associated
			 * with the client.
			 */
			tp = get_client_template(ca);
			if (tp == NULL || tp->host_type != SUN_CIPSO) {
				if (tp != NULL)
					tsol_freetpent(tp);
				error = EACCES;
				goto reply;
			}
			tsol_freetpent(tp);
		} else {
			if ((slabel = m_label_alloc(MAC_LABEL)) == NULL) {
				error = EACCES;
				goto reply;
			}

			if (getlabel(rpath, slabel) != 0) {
				m_label_free(slabel);
				error = EACCES;
				goto reply;
			}

			if (!bldominates(clabel, slabel)) {
				m_label_free(slabel);
				error = EACCES;
				goto reply;
			}
			m_label_free(slabel);
		}
	}

	/*
	 * Now get the filehandle.
	 *
	 * NFS V2 clients get a 32 byte filehandle.
	 * NFS V3 clients get a 32 or 64 byte filehandle, depending on
	 * the embedded FIDs.
	 */
	vers = (version == MOUNTVERS3) ? NFS_V3 : NFS_VERSION;

	/* LINTED pointer alignment */
	while (nfs_getfh(rpath, vers, &len, fh) < 0) {
		if (errno == EINVAL &&
		    (sh = find_lofsentry(rpath, &lofs_tried)) != NULL) {
			errno = 0;
			continue;
		}
		error = errno == EINVAL ? EACCES : errno;
		syslog(LOG_DEBUG, "mount request: getfh failed on %s: %m",
		    path);
		break;
	}

	if (version == MOUNTVERS3) {
		mountres3.mountres3_u.mountinfo.fhandle.fhandle3_len = len;
		mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val = fh;
	} else {
		bcopy(fh, &fhs.fhstatus_u.fhs_fhandle, NFS_FHSIZE);
	}

reply:
	if (uc != NULL)
		ucred_free(uc);

	switch (version) {
	case MOUNTVERS:
	case MOUNTVERS_POSIX:
		if (error == EINVAL)
			fhs.fhs_status = NFSERR_ACCES;
		else if (error == EREMOTE)
			fhs.fhs_status = NFSERR_REMOTE;
		else
			fhs.fhs_status = error;

		if (!svc_sendreply(transp, xdr_fhstatus, (char *)&fhs))
			log_cant_reply(transp);

		audit_status = fhs.fhs_status;
		break;

	case MOUNTVERS3:
		if (!error) {
		mountres3.mountres3_u.mountinfo.auth_flavors.auth_flavors_val =
		    flavor_list;
		mountres3.mountres3_u.mountinfo.auth_flavors.auth_flavors_len =
		    flavor_count;

		} else if (error == ENAMETOOLONG)
			error = MNT3ERR_NAMETOOLONG;

		mountres3.fhs_status = error;
		if (!svc_sendreply(transp, xdr_mountres3, (char *)&mountres3))
			log_cant_reply(transp);

		audit_status = mountres3.fhs_status;
		break;
	}

	if (verbose)
		syslog(LOG_NOTICE, "MOUNT: %s %s %s",
		    (host == NULL) ? "unknown host" : host,
		    error ? "denied" : "mounted", path);

	/*
	 * If we can not create a queue entry, go ahead and do it
	 * in the context of this thread.
	 */
	enqueued = enqueue_logging_data(host, transp, path, rpath,
	    audit_status, error);
	if (enqueued == FALSE) {
		if (host == NULL) {
			DTRACE_PROBE(mountd, name_by_in_thread);
			if (getclientsnames(transp, &nb, &clnames) == 0)
				host = clnames->h_hostservs[0].h_host;
		}

		DTRACE_PROBE(mountd, logged_in_thread);
		audit_mountd_mount(host, path, audit_status); /* BSM */
		if (!error)
			mntlist_new(host, rpath); /* add entry to mount list */
	}

	if (path != NULL)
		svc_freeargs(transp, xdr_dirpath, (caddr_t)&path);

done:
	if (sh)
		sharefree(sh);
	netdir_free(clnames, ND_HOSTSERVLIST);

	return (error);
}

/*
 * Determine whether two paths are within the same file system.
 * Returns nonzero (true) if paths are the same, zero (false) if
 * they are different.  If an error occurs, return false.
 *
 * Use the actual FSID if it's available (via getattrat()); otherwise,
 * fall back on st_dev.
 *
 * With ZFS snapshots, st_dev differs from the regular file system
 * versus the snapshot.  But the fsid is the same throughout.  Thus
 * the fsid is a better test.
 */
static int
same_file_system(const char *path1, const char *path2)
{
	uint64_t fsid1, fsid2;
	struct stat64 st1, st2;
	nvlist_t *nvl1 = NULL;
	nvlist_t *nvl2 = NULL;

	if ((getattrat(AT_FDCWD, XATTR_VIEW_READONLY, path1, &nvl1) == 0) &&
	    (getattrat(AT_FDCWD, XATTR_VIEW_READONLY, path2, &nvl2) == 0) &&
	    (nvlist_lookup_uint64(nvl1, A_FSID, &fsid1) == 0) &&
	    (nvlist_lookup_uint64(nvl2, A_FSID, &fsid2) == 0)) {
		nvlist_free(nvl1);
		nvlist_free(nvl2);
		/*
		 * We have found fsid's for both paths.
		 */

		if (fsid1 == fsid2)
			return (B_TRUE);

		return (B_FALSE);
	}

	if (nvl1 != NULL)
		nvlist_free(nvl1);
	if (nvl2 != NULL)
		nvlist_free(nvl2);

	/*
	 * We were unable to find fsid's for at least one of the paths.
	 * fall back on st_dev.
	 */

	if (stat64(path1, &st1) < 0) {
		syslog(LOG_NOTICE, "%s: %m", path1);
		return (B_FALSE);
	}
	if (stat64(path2, &st2) < 0) {
		syslog(LOG_NOTICE, "%s: %m", path2);
		return (B_FALSE);
	}

	if (st1.st_dev == st2.st_dev)
		return (B_TRUE);

	return (B_FALSE);
}

share_t *
findentry(char *path)
{
	share_t *sh = NULL;
	struct sh_list *shp;
	register char *p1, *p2;

	check_sharetab();

	(void) rw_rdlock(&sharetab_lock);

	for (shp = share_list; shp; shp = shp->shl_next) {
		sh = shp->shl_sh;
		for (p1 = sh->sh_path, p2 = path; *p1 == *p2; p1++, p2++)
			if (*p1 == '\0')
				goto done;	/* exact match */

		/*
		 * Now compare the pathnames for three cases:
		 *
		 * Parent: /export/foo		(no trailing slash on parent)
		 * Child:  /export/foo/bar
		 *
		 * Parent: /export/foo/		(trailing slash on parent)
		 * Child:  /export/foo/bar
		 *
		 * Parent: /export/foo/		(no trailing slash on child)
		 * Child:  /export/foo
		 */
		if ((*p1 == '\0' && *p2 == '/') ||
		    (*p1 == '\0' && *(p1-1) == '/') ||
		    (*p2 == '\0' && *p1 == '/' && *(p1+1) == '\0')) {
			/*
			 * We have a subdirectory.  Test whether the
			 * subdirectory is in the same file system.
			 */
			if (same_file_system(path, sh->sh_path))
				goto done;
		}
	}
done:
	sh = shp ? sharedup(sh) : NULL;

	(void) rw_unlock(&sharetab_lock);

	return (sh);
}


static int
is_substring(char **mntp, char **path)
{
	char *p1 = *mntp, *p2 = *path;

	if (*p1 == '\0' && *p2 == '\0') /* exact match */
		return (1);
	else if (*p1 == '\0' && *p2 == '/')
		return (1);
	else if (*p1 == '\0' && *(p1-1) == '/') {
		*path = --p2; /* we need the slash in p2 */
		return (1);
	} else if (*p2 == '\0') {
		while (*p1 == '/')
			p1++;
		if (*p1 == '\0') /* exact match */
			return (1);
	}
	return (0);
}

/*
 * find_lofsentry() searches for the real path which this requested LOFS path
 * (rpath) shadows. If found, it will return the sharetab entry of
 * the real path that corresponds to the LOFS path.
 * We first search mnttab to see if the requested path is an automounted
 * path. If it is an automounted path, it will trigger the mount by stat()ing
 * the requested path. Note that it is important to check that this path is
 * actually an automounted path, otherwise we would stat() a path which may
 * turn out to be NFS and block indefinitely on a dead server. The automounter
 * times-out if the server is dead, so there's no risk of hanging this
 * thread waiting for stat().
 * After the mount has been triggered (if necessary), we look for a
 * mountpoint of type LOFS (by searching /etc/mnttab again) which
 * is a substring of the rpath. If found, we construct a new path by
 * concatenating the mnt_special and the remaining of rpath, call findentry()
 * to make sure the 'real path' is shared.
 */
static share_t *
find_lofsentry(char *rpath, int *done_flag)
{
	struct stat r_stbuf;
	mntlist_t *ml, *mntl, *mntpnt = NULL;
	share_t *retcode = NULL;
	char tmp_path[MAXPATHLEN];
	int mntpnt_len = 0, tmp;
	char *p1, *p2;

	if ((*done_flag)++)
		return (retcode);

	/*
	 * While fsgetmntlist() uses lockf() to
	 * lock the mnttab before reading it in,
	 * the lock ignores threads in the same process.
	 * Read in the mnttab with the protection of a mutex.
	 */
	(void) mutex_lock(&mnttab_lock);
	mntl = fsgetmntlist();
	(void) mutex_unlock(&mnttab_lock);

	/*
	 * Obtain the mountpoint for the requested path.
	 */
	for (ml = mntl; ml; ml = ml->mntl_next) {
		for (p1 = ml->mntl_mnt->mnt_mountp, p2 = rpath;
		    *p1 == *p2 && *p1; p1++, p2++)
			;
		if (is_substring(&p1, &p2) &&
		    (tmp = strlen(ml->mntl_mnt->mnt_mountp)) >= mntpnt_len) {
			mntpnt = ml;
			mntpnt_len = tmp;
		}
	}

	/*
	 * If the path needs to be autoFS mounted, trigger the mount by
	 * stat()ing it. This is determined by checking whether the
	 * mountpoint we just found is of type autofs.
	 */
	if (mntpnt != NULL &&
	    strcmp(mntpnt->mntl_mnt->mnt_fstype, "autofs") == 0) {
		/*
		 * The requested path is a substring of an autoFS filesystem.
		 * Trigger the mount.
		 */
		if (stat(rpath, &r_stbuf) < 0) {
			if (verbose)
				syslog(LOG_NOTICE, "%s: %m", rpath);
			goto done;
		}
		if ((r_stbuf.st_mode & S_IFMT) == S_IFDIR) {
			/*
			 * The requested path is a directory, stat(2) it
			 * again with a trailing '.' to force the autoFS
			 * module to trigger the mount of indirect
			 * automount entries, such as /net/jurassic/.
			 */
			if (strlen(rpath) + 2 > MAXPATHLEN) {
				if (verbose) {
					syslog(LOG_NOTICE,
					    "%s/.: exceeds MAXPATHLEN %d",
					    rpath, MAXPATHLEN);
				}
				goto done;
			}
			(void) strcpy(tmp_path, rpath);
			(void) strcat(tmp_path, "/.");

			if (stat(tmp_path, &r_stbuf) < 0) {
				if (verbose)
					syslog(LOG_NOTICE, "%s: %m", tmp_path);
				goto done;
			}
		}

		/*
		 * The mount has been triggered, re-read mnttab to pick up
		 * the changes made by autoFS.
		 */
		fsfreemntlist(mntl);
		(void) mutex_lock(&mnttab_lock);
		mntl = fsgetmntlist();
		(void) mutex_unlock(&mnttab_lock);
	}

	/*
	 * The autoFS mountpoint has been triggered if necessary,
	 * now search mnttab again to determine if the requested path
	 * is an LOFS mount of a shared path.
	 */
	mntpnt_len = 0;
	for (ml = mntl; ml; ml = ml->mntl_next) {
		if (strcmp(ml->mntl_mnt->mnt_fstype, "lofs"))
			continue;

		for (p1 = ml->mntl_mnt->mnt_mountp, p2 = rpath;
		    *p1 == *p2 && *p1; p1++, p2++)
			;

		if (is_substring(&p1, &p2) &&
		    ((tmp = strlen(ml->mntl_mnt->mnt_mountp)) >= mntpnt_len)) {
			mntpnt_len = tmp;

			if ((strlen(ml->mntl_mnt->mnt_special) + strlen(p2)) >
			    MAXPATHLEN) {
				if (verbose) {
					syslog(LOG_NOTICE, "%s%s: exceeds %d",
					    ml->mntl_mnt->mnt_special, p2,
					    MAXPATHLEN);
				}
				if (retcode)
					sharefree(retcode);
				retcode = NULL;
				goto done;
			}

			(void) strcpy(tmp_path, ml->mntl_mnt->mnt_special);
			(void) strcat(tmp_path, p2);
			if (retcode)
				sharefree(retcode);
			retcode = findentry(tmp_path);
		}
	}

	if (retcode) {
		assert(strlen(tmp_path) > 0);
		(void) strcpy(rpath, tmp_path);
	}

done:
	fsfreemntlist(mntl);
	return (retcode);
}

/*
 * Determine whether an access list grants rights to a particular host.
 * We match on aliases of the hostname as well as on the canonical name.
 * Names in the access list may be either hosts or netgroups;  they're
 * not distinguished syntactically.  We check for hosts first because
 * it's cheaper, then try netgroups.
 *
 * If pnb and pclnames are NULL, it means that we have to use transp
 * to resolve client IP address to hostname. If they aren't NULL
 * then transp argument won't be used and can be NULL.
 */
int
in_access_list(SVCXPRT *transp, struct netbuf **pnb,
    struct nd_hostservlist **pclnames,
    char *access_list)	/* N.B. we clobber this "input" parameter */
{
	char addr[INET_ADDRSTRLEN];
	char buff[256];
	int nentries = 0;
	char *cstr = access_list;
	char *gr = access_list;
	char *host;
	int off;
	int i;
	int response;
	int sbr = 0;
	struct nd_hostservlist *clnames;
	struct netent n, *np;

	/* If no access list - then it's unrestricted */
	if (access_list == NULL || *access_list == '\0')
		return (1);

	assert(transp != NULL || (*pnb != NULL && *pclnames != NULL));

	/* Get client address if it wasn't provided */
	if (*pnb == NULL)
		/* Don't grant access if client address isn't known */
		if ((*pnb = svc_getrpccaller(transp)) == NULL)
			return (0);

	/* Try to lookup client hostname if it wasn't provided */
	if (*pclnames == NULL)
		getclientsnames(transp, pnb, pclnames);
	clnames = *pclnames;

	for (;;) {
		if ((cstr = strpbrk(cstr, "[]:")) != NULL) {
			switch (*cstr) {
			case '[':
			case ']':
				sbr = !sbr;
				cstr++;
				continue;
			case ':':
				if (sbr) {
					cstr++;
					continue;
				}
				*cstr = '\0';
			}
		}

		/*
		 * If the list name has a '-' prepended then a match of
		 * the following name implies failure instead of success.
		 */
		if (*gr == '-') {
			response = 0;
			gr++;
		} else {
			response = 1;
		}

		/*
		 * First check if we have '@' entry, as it doesn't
		 * require client hostname.
		 */
		if (*gr == '@') {
			gr++;

			/* Netname support */
			if (!isdigit(*gr) && *gr != '[') {
				if ((np = getnetbyname_r(gr, &n, buff,
				    sizeof (buff))) != NULL &&
				    np->n_net != 0) {
					while ((np->n_net & 0xFF000000u) == 0)
						np->n_net <<= 8;
					np->n_net = htonl(np->n_net);
					if (inet_ntop(AF_INET, &np->n_net, addr,
					    INET_ADDRSTRLEN) == NULL)
						break;
					if (inet_matchaddr((*pnb)->buf, addr))
						return (response);
				}
			} else {
				if (inet_matchaddr((*pnb)->buf, gr))
					return (response);
			}

			if (cstr == NULL)
				break;

			gr = ++cstr;

			continue;
		}

		/*
		 * No other checks can be performed if client address
		 * can't be resolved.
		 */
		if (clnames == NULL) {
			if (cstr == NULL)
				break;

			gr = ++cstr;

			continue;
		}

		/* Otherwise loop through all client hostname aliases */
		for (i = 0; i < clnames->h_cnt; i++) {
			host = clnames->h_hostservs[i].h_host;

			/*
			 * If the list name begins with a dot then
			 * do a domain name suffix comparison.
			 * A single dot matches any name with no
			 * suffix.
			 */
			if (*gr == '.') {
				if (*(gr + 1) == '\0') {  /* single dot */
					if (strchr(host, '.') == NULL)
						return (response);
				} else {
					off = strlen(host) - strlen(gr);
					if (off > 0 &&
					    strcasecmp(host + off, gr) == 0) {
						return (response);
					}
				}
			} else {
				/* Just do a hostname match */
				if (strcasecmp(gr, host) == 0)
					return (response);
			}
		}

		nentries++;

		if (cstr == NULL)
			break;

		gr = ++cstr;
	}

	if (clnames == NULL)
		return (0);

	return (netgroup_check(clnames, access_list, nentries));
}


static char *optlist[] = {
#define	OPT_RO		0
	SHOPT_RO,
#define	OPT_RW		1
	SHOPT_RW,
#define	OPT_ROOT	2
	SHOPT_ROOT,
#define	OPT_SECURE	3
	SHOPT_SECURE,
#define	OPT_ANON	4
	SHOPT_ANON,
#define	OPT_WINDOW	5
	SHOPT_WINDOW,
#define	OPT_NOSUID	6
	SHOPT_NOSUID,
#define	OPT_ACLOK	7
	SHOPT_ACLOK,
#define	OPT_SEC		8
	SHOPT_SEC,
#define	OPT_NONE	9
	SHOPT_NONE,
#define	OPT_UIDMAP	10
	SHOPT_UIDMAP,
#define	OPT_GIDMAP	11
	SHOPT_GIDMAP,
	NULL
};

static int
map_flavor(char *str)
{
	seconfig_t sec;

	if (nfs_getseconfig_byname(str, &sec))
		return (-1);

	return (sec.sc_nfsnum);
}

/*
 * If the option string contains a "sec="
 * option, then use new option syntax.
 */
static int
newopts(char *opts)
{
	char *head, *p, *val;

	if (!opts || *opts == '\0')
		return (0);

	head = strdup(opts);
	if (head == NULL) {
		syslog(LOG_ERR, "opts: no memory");
		return (0);
	}

	p = head;
	while (*p) {
		if (getsubopt(&p, optlist, &val) == OPT_SEC) {
			free(head);
			return (1);
		}
	}

	free(head);
	return (0);
}

/*
 * Given an export and the clients hostname(s)
 * determine the security flavors that this
 * client is permitted to use.
 *
 * This routine is called only for "old" syntax, i.e.
 * only one security flavor is allowed.  So we need
 * to determine two things: the particular flavor,
 * and whether the client is allowed to use this
 * flavor, i.e. is in the access list.
 *
 * Note that if there is no access list, then the
 * default is that access is granted.
 */
static int
getclientsflavors_old(share_t *sh, SVCXPRT *transp, struct netbuf **nb,
    struct nd_hostservlist **clnames, int *flavors)
{
	char *opts, *p, *val;
	boolean_t ok = B_FALSE;
	int defaultaccess = 1;
	boolean_t reject = B_FALSE;

	opts = strdup(sh->sh_opts);
	if (opts == NULL) {
		syslog(LOG_ERR, "getclientsflavors: no memory");
		return (0);
	}

	flavors[0] = AUTH_SYS;
	p = opts;

	while (*p) {

		switch (getsubopt(&p, optlist, &val)) {
		case OPT_SECURE:
			flavors[0] = AUTH_DES;
			break;

		case OPT_RO:
		case OPT_RW:
			defaultaccess = 0;
			if (in_access_list(transp, nb, clnames, val))
				ok++;
			break;

		case OPT_NONE:
			defaultaccess = 0;
			if (in_access_list(transp, nb, clnames, val))
				reject = B_TRUE;
		}
	}

	free(opts);

	/* none takes precedence over everything else */
	if (reject)
		ok = B_TRUE;

	return (defaultaccess || ok);
}

/*
 * Given an export and the clients hostname(s)
 * determine the security flavors that this
 * client is permitted to use.
 *
 * This is somewhat more complicated than the "old"
 * routine because the options may contain multiple
 * security flavors (sec=) each with its own access
 * lists.  So a client could be granted access based
 * on a number of security flavors.  Note that the
 * type of access might not always be the same, the
 * client may get readonly access with one flavor
 * and readwrite with another, however the client
 * is not told this detail, it gets only the list
 * of flavors, and only if the client is using
 * version 3 of the mount protocol.
 */
static int
getclientsflavors_new(share_t *sh, SVCXPRT *transp, struct netbuf **nb,
    struct nd_hostservlist **clnames, int *flavors)
{
	char *opts, *p, *val;
	char *lasts;
	char *f;
	boolean_t access_ok;
	int count, c;
	boolean_t reject = B_FALSE;

	opts = strdup(sh->sh_opts);
	if (opts == NULL) {
		syslog(LOG_ERR, "getclientsflavors: no memory");
		return (0);
	}

	p = opts;
	count = c = 0;
	/* default access is rw */
	access_ok = B_TRUE;

	while (*p) {
		switch (getsubopt(&p, optlist, &val)) {
		case OPT_SEC:
			/*
			 * Before a new sec=xxx option, check if we need
			 * to move the c index back to the previous count.
			 */
			if (!access_ok) {
				c = count;
			}

			/* get all the sec=f1[:f2] flavors */
			while ((f = strtok_r(val, ":", &lasts))
			    != NULL) {
				flavors[c++] = map_flavor(f);
				val = NULL;
			}

			/* for a new sec=xxx option, default is rw access */
			access_ok = B_TRUE;
			break;

		case OPT_RO:
		case OPT_RW:
			if (in_access_list(transp, nb, clnames, val)) {
				count = c;
				access_ok = B_TRUE;
			} else {
				access_ok = B_FALSE;
			}
			break;

		case OPT_NONE:
			if (in_access_list(transp, nb, clnames, val))
				reject = B_TRUE; /* none overides rw/ro */
			break;
		}
	}

	if (reject)
		access_ok = B_FALSE;

	if (!access_ok)
		c = count;

	free(opts);

	return (c);
}

/*
 * This is a tricky piece of code that parses the
 * share options looking for a match on the auth
 * flavor that the client is using. If it finds
 * a match, then the client is given ro, rw, or
 * no access depending whether it is in the access
 * list.  There is a special case for "secure"
 * flavor.  Other flavors are values of the new "sec=" option.
 */
int
check_client(share_t *sh, struct netbuf *nb,
    struct nd_hostservlist *clnames, int flavor, uid_t clnt_uid, gid_t clnt_gid,
    uid_t *srv_uid, gid_t *srv_gid)
{
	if (newopts(sh->sh_opts))
		return (check_client_new(sh, NULL, &nb, &clnames, flavor,
		    clnt_uid, clnt_gid, srv_uid, srv_gid));
	else
		return (check_client_old(sh, NULL, &nb, &clnames, flavor,
		    clnt_uid, clnt_gid, srv_uid, srv_gid));
}

/*
 * is_a_number(number)
 *
 * is the string a number in one of the forms we want to use?
 */

static int
is_a_number(char *number)
{
	int ret = 1;
	int hex = 0;

	if (strncmp(number, "0x", 2) == 0) {
		number += 2;
		hex = 1;
	} else if (*number == '-') {
		number++; /* skip the minus */
	}
	while (ret == 1 && *number != '\0') {
		if (hex) {
			ret = isxdigit(*number++);
		} else {
			ret = isdigit(*number++);
		}
	}
	return (ret);
}

static boolean_t
get_uid(char *value, uid_t *uid)
{
	if (!is_a_number(value)) {
		struct passwd *pw;
		/*
		 * in this case it would have to be a
		 * user name
		 */
		pw = getpwnam(value);
		if (pw == NULL)
			return (B_FALSE);
		*uid = pw->pw_uid;
		endpwent();
	} else {
		uint64_t intval;
		intval = strtoull(value, NULL, 0);
		if (intval > UID_MAX && intval != -1)
			return (B_FALSE);
		*uid = (uid_t)intval;
	}

	return (B_TRUE);
}

static boolean_t
get_gid(char *value, gid_t *gid)
{
	if (!is_a_number(value)) {
		struct group *gr;
		/*
		 * in this case it would have to be a
		 * group name
		 */
		gr = getgrnam(value);
		if (gr == NULL)
			return (B_FALSE);
		*gid = gr->gr_gid;
		endgrent();
	} else {
		uint64_t intval;
		intval = strtoull(value, NULL, 0);
		if (intval > UID_MAX && intval != -1)
			return (B_FALSE);
		*gid = (gid_t)intval;
	}

	return (B_TRUE);
}

static int
check_client_old(share_t *sh, SVCXPRT *transp, struct netbuf **nb,
    struct nd_hostservlist **clnames, int flavor, uid_t clnt_uid,
    gid_t clnt_gid, uid_t *srv_uid, gid_t *srv_gid)
{
	char *opts, *p, *val;
	int match;	/* Set when a flavor is matched */
	int perm = 0;	/* Set when "ro", "rw" or "root" is matched */
	int list = 0;	/* Set when "ro", "rw" is found */
	int ro_val = 0;	/* Set if ro option is 'ro=' */
	int rw_val = 0;	/* Set if rw option is 'rw=' */

	boolean_t map_deny = B_FALSE;

	opts = strdup(sh->sh_opts);
	if (opts == NULL) {
		syslog(LOG_ERR, "check_client: no memory");
		return (0);
	}

	p = opts;
	match = AUTH_UNIX;

	while (*p) {
		switch (getsubopt(&p, optlist, &val)) {

		case OPT_SECURE:
			match = AUTH_DES;
			break;

		case OPT_RO:
			list++;
			if (val != NULL)
				ro_val++;
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_RO;
			break;

		case OPT_RW:
			list++;
			if (val != NULL)
				rw_val++;
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_RW;
			break;

		case OPT_ROOT:
			/*
			 * Check if the client is in
			 * the root list. Only valid
			 * for AUTH_SYS.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (val == NULL || *val == '\0')
				break;

			if (clnt_uid != 0)
				break;

			if (in_access_list(transp, nb, clnames, val)) {
				perm |= NFSAUTH_ROOT;
				perm |= NFSAUTH_UIDMAP | NFSAUTH_GIDMAP;
				map_deny = B_FALSE;
			}
			break;

		case OPT_NONE:
			/*
			 * Check if  the client should have no access
			 * to this share at all. This option behaves
			 * more like "root" than either "rw" or "ro".
			 */
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_DENIED;
			break;

		case OPT_UIDMAP: {
			char *c;
			char *n;

			/*
			 * The uidmap is supported for AUTH_SYS only.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (perm & NFSAUTH_UIDMAP || map_deny)
				break;

			for (c = val; c != NULL; c = n) {
				char *s;
				char *al;
				uid_t srv;

				n = strchr(c, '~');
				if (n != NULL)
					*n++ = '\0';

				s = strchr(c, ':');
				if (s != NULL) {
					*s++ = '\0';
					al = strchr(s, ':');
					if (al != NULL)
						*al++ = '\0';
				}

				if (s == NULL || al == NULL)
					continue;

				if (*c == '\0') {
					if (clnt_uid != (uid_t)-1)
						continue;
				} else if (strcmp(c, "*") != 0) {
					uid_t clnt;

					if (!get_uid(c, &clnt))
						continue;

					if (clnt_uid != clnt)
						continue;
				}

				if (*s == '\0')
					srv = UID_NOBODY;
				else if (!get_uid(s, &srv))
					continue;
				else if (srv == (uid_t)-1) {
					map_deny = B_TRUE;
					break;
				}

				if (in_access_list(transp, nb, clnames, al)) {
					*srv_uid = srv;
					perm |= NFSAUTH_UIDMAP;
					break;
				}
			}

			break;
		}

		case OPT_GIDMAP: {
			char *c;
			char *n;

			/*
			 * The gidmap is supported for AUTH_SYS only.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (perm & NFSAUTH_GIDMAP || map_deny)
				break;

			for (c = val; c != NULL; c = n) {
				char *s;
				char *al;
				gid_t srv;

				n = strchr(c, '~');
				if (n != NULL)
					*n++ = '\0';

				s = strchr(c, ':');
				if (s != NULL) {
					*s++ = '\0';
					al = strchr(s, ':');
					if (al != NULL)
						*al++ = '\0';
				}

				if (s == NULL || al == NULL)
					break;

				if (*c == '\0') {
					if (clnt_gid != (gid_t)-1)
						continue;
				} else if (strcmp(c, "*") != 0) {
					gid_t clnt;

					if (!get_gid(c, &clnt))
						continue;

					if (clnt_gid != clnt)
						continue;
				}

				if (*s == '\0')
					srv = UID_NOBODY;
				else if (!get_gid(s, &srv))
					continue;
				else if (srv == (gid_t)-1) {
					map_deny = B_TRUE;
					break;
				}

				if (in_access_list(transp, nb, clnames, al)) {
					*srv_gid = srv;
					perm |= NFSAUTH_GIDMAP;
					break;
				}
			}

			break;
		}

		default:
			break;
		}
	}

	free(opts);

	if (perm & NFSAUTH_ROOT) {
		*srv_uid = 0;
		*srv_gid = 0;
	}

	if (map_deny)
		perm |= NFSAUTH_DENIED;

	if (!(perm & NFSAUTH_UIDMAP))
		*srv_uid = clnt_uid;
	if (!(perm & NFSAUTH_GIDMAP))
		*srv_gid = clnt_gid;

	if (flavor != match || perm & NFSAUTH_DENIED)
		return (NFSAUTH_DENIED);

	if (list) {
		/*
		 * If the client doesn't match an "ro" or "rw"
		 * list then set no access.
		 */
		if ((perm & (NFSAUTH_RO | NFSAUTH_RW)) == 0)
			perm |= NFSAUTH_DENIED;
	} else {
		/*
		 * The client matched a flavor entry that
		 * has no explicit "rw" or "ro" determination.
		 * Default it to "rw".
		 */
		perm |= NFSAUTH_RW;
	}

	/*
	 * The client may show up in both ro= and rw=
	 * lists.  If so, then turn off the RO access
	 * bit leaving RW access.
	 */
	if (perm & NFSAUTH_RO && perm & NFSAUTH_RW) {
		/*
		 * Logically cover all permutations of rw=,ro=.
		 * In the case where, rw,ro=<host> we would like
		 * to remove RW access for the host.  In all other cases
		 * RW wins the precedence battle.
		 */
		if (!rw_val && ro_val) {
			perm &= ~(NFSAUTH_RW);
		} else {
			perm &= ~(NFSAUTH_RO);
		}
	}

	return (perm);
}

/*
 * Check if the client has access by using a flavor different from
 * the given "flavor". If "flavor" is not in the flavor list,
 * return TRUE to indicate that this "flavor" is a wrong sec.
 */
static bool_t
is_wrongsec(share_t *sh, SVCXPRT *transp, struct netbuf **nb,
	struct nd_hostservlist **clnames, int flavor)
{
	int flavor_list[MAX_FLAVORS];
	int flavor_count, i;

	/* get the flavor list that the client has access with */
	flavor_count = getclientsflavors_new(sh, transp, nb,
	    clnames, flavor_list);

	if (flavor_count == 0)
		return (FALSE);

	/*
	 * Check if the given "flavor" is in the flavor_list.
	 */
	for (i = 0; i < flavor_count; i++) {
		if (flavor == flavor_list[i])
			return (FALSE);
	}

	/*
	 * If "flavor" is not in the flavor_list, return TRUE to indicate
	 * that the client should have access by using a security flavor
	 * different from this "flavor".
	 */
	return (TRUE);
}

/*
 * Given an export and the client's hostname, we
 * check the security options to see whether the
 * client is allowed to use the given security flavor.
 *
 * The strategy is to proceed through the options looking
 * for a flavor match, then pay attention to the ro, rw,
 * and root options.
 *
 * Note that an entry may list several flavors in a
 * single entry, e.g.
 *
 *   sec=krb5,rw=clnt1:clnt2,ro,sec=sys,ro
 *
 */

static int
check_client_new(share_t *sh, SVCXPRT *transp, struct netbuf **nb,
    struct nd_hostservlist **clnames, int flavor, uid_t clnt_uid,
    gid_t clnt_gid, uid_t *srv_uid, gid_t *srv_gid)
{
	char *opts, *p, *val;
	char *lasts;
	char *f;
	int match = 0;	/* Set when a flavor is matched */
	int perm = 0;	/* Set when "ro", "rw" or "root" is matched */
	int list = 0;	/* Set when "ro", "rw" is found */
	int ro_val = 0;	/* Set if ro option is 'ro=' */
	int rw_val = 0;	/* Set if rw option is 'rw=' */

	boolean_t map_deny = B_FALSE;

	opts = strdup(sh->sh_opts);
	if (opts == NULL) {
		syslog(LOG_ERR, "check_client: no memory");
		return (0);
	}

	p = opts;

	while (*p) {
		switch (getsubopt(&p, optlist, &val)) {

		case OPT_SEC:
			if (match)
				goto done;

			while ((f = strtok_r(val, ":", &lasts))
			    != NULL) {
				if (flavor == map_flavor(f)) {
					match = 1;
					break;
				}
				val = NULL;
			}
			break;

		case OPT_RO:
			if (!match)
				break;

			list++;
			if (val != NULL)
				ro_val++;
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_RO;
			break;

		case OPT_RW:
			if (!match)
				break;

			list++;
			if (val != NULL)
				rw_val++;
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_RW;
			break;

		case OPT_ROOT:
			/*
			 * Check if the client is in
			 * the root list. Only valid
			 * for AUTH_SYS.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (!match)
				break;

			if (val == NULL || *val == '\0')
				break;

			if (clnt_uid != 0)
				break;

			if (in_access_list(transp, nb, clnames, val)) {
				perm |= NFSAUTH_ROOT;
				perm |= NFSAUTH_UIDMAP | NFSAUTH_GIDMAP;
				map_deny = B_FALSE;
			}
			break;

		case OPT_NONE:
			/*
			 * Check if  the client should have no access
			 * to this share at all. This option behaves
			 * more like "root" than either "rw" or "ro".
			 */
			if (in_access_list(transp, nb, clnames, val))
				perm |= NFSAUTH_DENIED;
			break;

		case OPT_UIDMAP: {
			char *c;
			char *n;

			/*
			 * The uidmap is supported for AUTH_SYS only.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (!match || perm & NFSAUTH_UIDMAP || map_deny)
				break;

			for (c = val; c != NULL; c = n) {
				char *s;
				char *al;
				uid_t srv;

				n = strchr(c, '~');
				if (n != NULL)
					*n++ = '\0';

				s = strchr(c, ':');
				if (s != NULL) {
					*s++ = '\0';
					al = strchr(s, ':');
					if (al != NULL)
						*al++ = '\0';
				}

				if (s == NULL || al == NULL)
					continue;

				if (*c == '\0') {
					if (clnt_uid != (uid_t)-1)
						continue;
				} else if (strcmp(c, "*") != 0) {
					uid_t clnt;

					if (!get_uid(c, &clnt))
						continue;

					if (clnt_uid != clnt)
						continue;
				}

				if (*s == '\0')
					srv = UID_NOBODY;
				else if (!get_uid(s, &srv))
					continue;
				else if (srv == (uid_t)-1) {
					map_deny = B_TRUE;
					break;
				}

				if (in_access_list(transp, nb, clnames, al)) {
					*srv_uid = srv;
					perm |= NFSAUTH_UIDMAP;
					break;
				}
			}

			break;
		}

		case OPT_GIDMAP: {
			char *c;
			char *n;

			/*
			 * The gidmap is supported for AUTH_SYS only.
			 */
			if (flavor != AUTH_SYS)
				break;

			if (!match || perm & NFSAUTH_GIDMAP || map_deny)
				break;

			for (c = val; c != NULL; c = n) {
				char *s;
				char *al;
				gid_t srv;

				n = strchr(c, '~');
				if (n != NULL)
					*n++ = '\0';

				s = strchr(c, ':');
				if (s != NULL) {
					*s++ = '\0';
					al = strchr(s, ':');
					if (al != NULL)
						*al++ = '\0';
				}

				if (s == NULL || al == NULL)
					break;

				if (*c == '\0') {
					if (clnt_gid != (gid_t)-1)
						continue;
				} else if (strcmp(c, "*") != 0) {
					gid_t clnt;

					if (!get_gid(c, &clnt))
						continue;

					if (clnt_gid != clnt)
						continue;
				}

				if (*s == '\0')
					srv = UID_NOBODY;
				else if (!get_gid(s, &srv))
					continue;
				else if (srv == (gid_t)-1) {
					map_deny = B_TRUE;
					break;
				}

				if (in_access_list(transp, nb, clnames, al)) {
					*srv_gid = srv;
					perm |= NFSAUTH_GIDMAP;
					break;
				}
			}

			break;
		}

		default:
			break;
		}
	}

done:
	if (perm & NFSAUTH_ROOT) {
		*srv_uid = 0;
		*srv_gid = 0;
	}

	if (map_deny)
		perm |= NFSAUTH_DENIED;

	if (!(perm & NFSAUTH_UIDMAP))
		*srv_uid = clnt_uid;
	if (!(perm & NFSAUTH_GIDMAP))
		*srv_gid = clnt_gid;

	/*
	 * If no match then set the perm accordingly
	 */
	if (!match || perm & NFSAUTH_DENIED) {
		free(opts);
		return (NFSAUTH_DENIED);
	}

	if (list) {
		/*
		 * If the client doesn't match an "ro" or "rw" list then
		 * check if it may have access by using a different flavor.
		 * If so, return NFSAUTH_WRONGSEC.
		 * If not, return NFSAUTH_DENIED.
		 */
		if ((perm & (NFSAUTH_RO | NFSAUTH_RW)) == 0) {
			if (is_wrongsec(sh, transp, nb, clnames, flavor))
				perm |= NFSAUTH_WRONGSEC;
			else
				perm |= NFSAUTH_DENIED;
		}
	} else {
		/*
		 * The client matched a flavor entry that
		 * has no explicit "rw" or "ro" determination.
		 * Make sure it defaults to "rw".
		 */
		perm |= NFSAUTH_RW;
	}

	/*
	 * The client may show up in both ro= and rw=
	 * lists.  If so, then turn off the RO access
	 * bit leaving RW access.
	 */
	if (perm & NFSAUTH_RO && perm & NFSAUTH_RW) {
		/*
		 * Logically cover all permutations of rw=,ro=.
		 * In the case where, rw,ro=<host> we would like
		 * to remove RW access for the host.  In all other cases
		 * RW wins the precedence battle.
		 */
		if (!rw_val && ro_val) {
			perm &= ~(NFSAUTH_RW);
		} else {
			perm &= ~(NFSAUTH_RO);
		}
	}

	free(opts);

	return (perm);
}

void
check_sharetab()
{
	FILE *f;
	struct stat st;
	static timestruc_t last_sharetab_time;
	timestruc_t prev_sharetab_time;
	share_t *sh;
	struct sh_list *shp, *shp_prev;
	int res, c = 0;

	/*
	 *  read in /etc/dfs/sharetab if it has changed
	 */
	if (stat(SHARETAB, &st) != 0) {
		syslog(LOG_ERR, "Cannot stat %s: %m", SHARETAB);
		return;
	}

	if (st.st_mtim.tv_sec == last_sharetab_time.tv_sec &&
	    st.st_mtim.tv_nsec == last_sharetab_time.tv_nsec) {
		/*
		 * No change.
		 */
		return;
	}

	/*
	 * Remember the mod time, then after getting the
	 * write lock check again.  If another thread
	 * already did the update, then there's no
	 * work to do.
	 */
	prev_sharetab_time = last_sharetab_time;

	(void) rw_wrlock(&sharetab_lock);

	if (prev_sharetab_time.tv_sec != last_sharetab_time.tv_sec ||
	    prev_sharetab_time.tv_nsec != last_sharetab_time.tv_nsec) {
		(void) rw_unlock(&sharetab_lock);
		return;
	}

	/*
	 * Note that since the sharetab is now in memory
	 * and a snapshot is taken, we no longer have to
	 * lock the file.
	 */
	f = fopen(SHARETAB, "r");
	if (f == NULL) {
		syslog(LOG_ERR, "Cannot open %s: %m", SHARETAB);
		(void) rw_unlock(&sharetab_lock);
		return;
	}

	/*
	 * Once we are sure /etc/dfs/sharetab has been
	 * modified, flush netgroup cache entries.
	 */
	netgrp_cache_flush();

	sh_free(share_list);			/* free old list */
	share_list = NULL;

	while ((res = getshare(f, &sh)) > 0) {
		c++;
		if (strcmp(sh->sh_fstype, "nfs") != 0)
			continue;

		shp = malloc(sizeof (*shp));
		if (shp == NULL)
			goto alloc_failed;
		if (share_list == NULL)
			share_list = shp;
		else
			/* LINTED not used before set */
			shp_prev->shl_next = shp;
		shp_prev = shp;
		shp->shl_next = NULL;
		shp->shl_sh = sharedup(sh);
		if (shp->shl_sh == NULL)
			goto alloc_failed;
	}

	if (res < 0)
		syslog(LOG_ERR, "%s: invalid at line %d\n",
		    SHARETAB, c + 1);

	if (stat(SHARETAB, &st) != 0) {
		syslog(LOG_ERR, "Cannot stat %s: %m", SHARETAB);
		(void) fclose(f);
		(void) rw_unlock(&sharetab_lock);
		return;
	}

	last_sharetab_time = st.st_mtim;
	(void) fclose(f);
	(void) rw_unlock(&sharetab_lock);

	return;

alloc_failed:

	syslog(LOG_ERR, "check_sharetab: no memory");
	sh_free(share_list);
	share_list = NULL;
	(void) fclose(f);
	(void) rw_unlock(&sharetab_lock);
}

static void
sh_free(struct sh_list *shp)
{
	register struct sh_list *next;

	while (shp) {
		sharefree(shp->shl_sh);
		next = shp->shl_next;
		free(shp);
		shp = next;
	}
}


/*
 * Remove an entry from mounted list
 */
static void
umount(struct svc_req *rqstp)
{
	char *host, *path, *remove_path;
	char rpath[MAXPATHLEN];
	struct nd_hostservlist *clnames = NULL;
	SVCXPRT *transp;
	struct netbuf *nb;

	transp = rqstp->rq_xprt;
	path = NULL;
	if (!svc_getargs(transp, xdr_dirpath, (caddr_t)&path)) {
		svcerr_decode(transp);
		return;
	}
	errno = 0;
	if (!svc_sendreply(transp, xdr_void, (char *)NULL))
		log_cant_reply(transp);

	if (getclientsnames(transp, &nb, &clnames) != 0) {
		/*
		 * Without the hostname we can't do audit or delete
		 * this host from the mount entries.
		 */
		svc_freeargs(transp, xdr_dirpath, (caddr_t)&path);
		return;
	}
	host = clnames->h_hostservs[0].h_host;

	if (verbose)
		syslog(LOG_NOTICE, "UNMOUNT: %s unmounted %s", host, path);

	audit_mountd_umount(host, path);

	remove_path = rpath;	/* assume we will use the cannonical path */
	if (realpath(path, rpath) == NULL) {
		if (verbose)
			syslog(LOG_WARNING, "UNMOUNT: realpath: %s: %m ", path);
		remove_path = path;	/* use path provided instead */
	}

	mntlist_delete(host, remove_path);	/* remove from mount list */

	svc_freeargs(transp, xdr_dirpath, (caddr_t)&path);
	netdir_free(clnames, ND_HOSTSERVLIST);
}

/*
 * Remove all entries for one machine from mounted list
 */
static void
umountall(struct svc_req *rqstp)
{
	struct nd_hostservlist *clnames = NULL;
	SVCXPRT *transp;
	char *host;
	struct netbuf *nb;

	transp = rqstp->rq_xprt;
	if (!svc_getargs(transp, xdr_void, NULL)) {
		svcerr_decode(transp);
		return;
	}
	/*
	 * We assume that this call is asynchronous and made via rpcbind
	 * callit routine.  Therefore return control immediately. The error
	 * causes rpcbind to remain silent, as opposed to every machine
	 * on the net blasting the requester with a response.
	 */
	svcerr_systemerr(transp);
	if (getclientsnames(transp, &nb, &clnames) != 0) {
		/* Can't do anything without the name of the client */
		return;
	}

	host = clnames->h_hostservs[0].h_host;

	/*
	 * Remove all hosts entries from mount list
	 */
	mntlist_delete_all(host);

	if (verbose)
		syslog(LOG_NOTICE, "UNMOUNTALL: from %s", host);

	netdir_free(clnames, ND_HOSTSERVLIST);
}

void *
exmalloc(size_t size)
{
	void *ret;

	if ((ret = malloc(size)) == NULL) {
		syslog(LOG_ERR, "Out of memory");
		exit(1);
	}
	return (ret);
}

static void
sigexit(int signum)
{

	if (signum == SIGHUP)
		_exit(0);
	_exit(1);
}

static tsol_tpent_t *
get_client_template(struct sockaddr *sock)
{
	in_addr_t	v4client;
	in6_addr_t	v6client;
	char		v4_addr[INET_ADDRSTRLEN];
	char		v6_addr[INET6_ADDRSTRLEN];
	tsol_rhent_t	*rh;
	tsol_tpent_t	*tp;

	switch (sock->sa_family) {
	case AF_INET:
		v4client = ((struct sockaddr_in *)(void *)sock)->
		    sin_addr.s_addr;
		if (inet_ntop(AF_INET, &v4client, v4_addr, INET_ADDRSTRLEN) ==
		    NULL)
			return (NULL);
		rh = tsol_getrhbyaddr(v4_addr, sizeof (v4_addr), AF_INET);
		if (rh == NULL)
			return (NULL);
		tp = tsol_gettpbyname(rh->rh_template);
		tsol_freerhent(rh);
		return (tp);
		break;
	case AF_INET6:
		v6client = ((struct sockaddr_in6 *)(void *)sock)->sin6_addr;
		if (inet_ntop(AF_INET6, &v6client, v6_addr, INET6_ADDRSTRLEN) ==
		    NULL)
			return (NULL);
		rh = tsol_getrhbyaddr(v6_addr, sizeof (v6_addr), AF_INET6);
		if (rh == NULL)
			return (NULL);
		tp = tsol_gettpbyname(rh->rh_template);
		tsol_freerhent(rh);
		return (tp);
		break;
	default:
		return (NULL);
	}
}
