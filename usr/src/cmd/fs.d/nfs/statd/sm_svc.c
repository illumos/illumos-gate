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
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <ftw.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <netconfig.h>
#include <netdir.h>
#include <unistd.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpc/svc.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sockio.h>
#include <dirent.h>
#include <errno.h>
#include <rpcsvc/sm_inter.h>
#include <rpcsvc/nsm_addr.h>
#include <thread.h>
#include <synch.h>
#include <net/if.h>
#include <limits.h>
#include <rpcsvc/daemon_utils.h>
#include <priv_utils.h>
#include "smfcfg.h"
#include "sm_statd.h"


#define	home0		"/var/statmon"
#define	current0	"/var/statmon/sm"
#define	backup0		"/var/statmon/sm.bak"
#define	state0		"/var/statmon/state"

#define	home1		"statmon"
#define	current1	"statmon/sm/"
#define	backup1		"statmon/sm.bak/"
#define	state1		"statmon/state"

extern int	daemonize_init(void);
extern void	daemonize_fini(int fd);

/*
 * User and group IDs to run as.  These are hardwired, rather than looked
 * up at runtime, because they are very unlikely to change and because they
 * provide some protection against bogus changes to the passwd and group
 * files.
 */
uid_t	daemon_uid = DAEMON_UID;
gid_t	daemon_gid = DAEMON_GID;

char STATE[MAXPATHLEN], CURRENT[MAXPATHLEN], BACKUP[MAXPATHLEN];
static char statd_home[MAXPATHLEN];

int debug;
int regfiles_only = 0;		/* 1 => use symlinks in statmon, 0 => don't */
int statd_port = 0;
char hostname[MAXHOSTNAMELEN];

/*
 * These variables will be used to store all the
 * alias names for the host, as well as the -a
 * command line hostnames.
 */
int host_name_count;
char **host_name; /* store -a opts */
int  addrix; /* # of -a entries */


/*
 * The following 2 variables are meaningful
 * only under a HA configuration.
 * The path_name array is dynamically allocated in main() during
 * command line argument processing for the -p options.
 */
char **path_name = NULL;  /* store -p opts */
int  pathix = 0;  /* # of -p entries */

/* Global variables.  Refer to sm_statd.h for description */
mutex_t crash_lock;
int die;
int in_crash;
mutex_t sm_trylock;
rwlock_t thr_rwlock;
cond_t retrywait;
mutex_t name_addrlock;

mutex_t merges_lock;
cond_t merges_cond;
boolean_t in_merges;

/* forward references */
static void set_statmon_owner(void);
static void copy_client_names(void);
static void one_statmon_owner(const char *);
static int nftw_owner(const char *, const struct stat *, int, struct FTW *);

/*
 * statd protocol
 * 	commands:
 * 		SM_STAT
 * 			returns stat_fail to caller
 * 		SM_MON
 * 			adds an entry to the monitor_q and the record_q.
 *			This message is sent by the server lockd to the server
 *			statd, to indicate that a new client is to be monitored.
 *			It is also sent by the server lockd to the client statd
 *			to indicate that a new server is to be monitored.
 * 		SM_UNMON
 * 			removes an entry from the monitor_q and the record_q
 * 		SM_UNMON_ALL
 * 			removes all entries from a particular host from the
 * 			monitor_q and the record_q.  Our statd has this
 * 			disabled.
 * 		SM_SIMU_CRASH
 * 			simulate a crash.  Removes everything from the
 * 			record_q and the recovery_q, then calls statd_init()
 * 			to restart things.  This message is sent by the server
 *			lockd to the server statd to have all clients notified
 *			that they should reclaim locks.
 * 		SM_NOTIFY
 *			Sent by statd on server to statd on client during
 *			crash recovery.  The client statd passes the info
 *			to its lockd so it can attempt to reclaim the locks
 *			held on the server.
 *
 * There are three main hash tables used to keep track of things.
 * 	mon_table
 * 		table that keeps track hosts statd must watch.  If one of
 * 		these hosts crashes, then any locks held by that host must
 * 		be released.
 * 	record_table
 * 		used to keep track of all the hostname files stored in
 * 		the directory /var/statmon/sm.  These are client hosts who
 *		are holding or have held a lock at some point.  Needed
 *		to determine if a file needs to be created for host in
 *		/var/statmon/sm.
 *	recov_q
 *		used to keep track hostnames during a recovery
 *
 * The entries are hashed based upon the name.
 *
 * There is a directory /var/statmon/sm which holds a file named
 * for each host that is holding (or has held) a lock.  This is
 * used during initialization on startup, or after a simulated
 * crash.
 */

static void
sm_prog_1(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		struct sm_name sm_stat_1_arg;
		struct mon sm_mon_1_arg;
		struct mon_id sm_unmon_1_arg;
		struct my_id sm_unmon_all_1_arg;
		struct stat_chge ntf_arg;
		struct reg1args reg1_arg;
	} argument;

	union {
		sm_stat_res stat_resp;
		sm_stat	mon_resp;
		struct reg1res reg1_resp;
	} result;

	bool_t (*xdr_argument)(), (*xdr_result)();
	char *(*local)();

	/*
	 * Dispatch according to which protocol is being used:
	 *	NSM_ADDR_PROGRAM is the private lockd address
	 *		registration protocol.
	 *	SM_PROG is the normal statd (NSM) protocol.
	 */
	if (rqstp->rq_prog == NSM_ADDR_PROGRAM) {
		switch (rqstp->rq_proc) {
		case NULLPROC:
			svc_sendreply(transp, xdr_void, (caddr_t)NULL);
			return;

		case NSMADDRPROC1_REG:
			xdr_argument = xdr_reg1args;
			xdr_result = xdr_reg1res;
			local = (char *(*)()) nsmaddrproc1_reg;
			break;

		case NSMADDRPROC1_UNREG: /* Not impl. */
		default:
			svcerr_noproc(transp);
			return;
		}
	} else {
		/* Must be SM_PROG */
		switch (rqstp->rq_proc) {
		case NULLPROC:
			svc_sendreply(transp, xdr_void, (caddr_t)NULL);
			return;

		case SM_STAT:
			xdr_argument = xdr_sm_name;
			xdr_result = xdr_sm_stat_res;
			local = (char *(*)()) sm_stat_svc;
			break;

		case SM_MON:
			xdr_argument = xdr_mon;
			xdr_result = xdr_sm_stat_res;
			local = (char *(*)()) sm_mon_svc;
			break;

		case SM_UNMON:
			xdr_argument = xdr_mon_id;
			xdr_result = xdr_sm_stat;
			local = (char *(*)()) sm_unmon_svc;
			break;

		case SM_UNMON_ALL:
			xdr_argument = xdr_my_id;
			xdr_result = xdr_sm_stat;
			local = (char *(*)()) sm_unmon_all_svc;
			break;

		case SM_SIMU_CRASH:
			xdr_argument = xdr_void;
			xdr_result = xdr_void;
			local = (char *(*)()) sm_simu_crash_svc;
			break;

		case SM_NOTIFY:
			xdr_argument = xdr_stat_chge;
			xdr_result = xdr_void;
			local = (char *(*)()) sm_notify_svc;
			break;

		default:
			svcerr_noproc(transp);
			return;
		}
	}

	(void) memset(&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}

	(void) memset(&result, 0, sizeof (result));
	(*local)(&argument, &result);
	if (!svc_sendreply(transp, xdr_result, (caddr_t)&result)) {
		svcerr_systemerr(transp);
	}

	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		syslog(LOG_ERR, "statd: unable to free arguments\n");
	}
}

/*
 * Remove all files under directory path_dir.
 */
static int
remove_dir(char *path_dir)
{
	DIR	*dp;
	struct dirent   *dirp;
	char tmp_path[MAXPATHLEN];

	if ((dp = opendir(path_dir)) == NULL) {
		if (debug)
			syslog(LOG_ERR,
			    "warning: open directory %s failed: %m\n",
			    path_dir);
		return (1);
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") != 0 &&
		    strcmp(dirp->d_name, "..") != 0) {
			if (strlen(path_dir) + strlen(dirp->d_name) +2 >
			    MAXPATHLEN) {

				syslog(LOG_ERR, "statd: remove dir %s/%s "
				    "failed.  Pathname too long.\n", path_dir,
				    dirp->d_name);

				continue;
			}
			(void) strcpy(tmp_path, path_dir);
			(void) strcat(tmp_path, "/");
			(void) strcat(tmp_path, dirp->d_name);
			delete_file(tmp_path);
		}
	}

	(void) closedir(dp);
	return (0);
}

/*
 * Copy all files from directory `from_dir' to directory `to_dir'.
 * Symlinks, if any, are preserved.
 */
void
copydir_from_to(char *from_dir, char *to_dir)
{
	int	n;
	DIR	*dp;
	struct dirent   *dirp;
	char rname[MAXNAMELEN + 1];
	char path[MAXPATHLEN+MAXNAMELEN+2];

	if ((dp = opendir(from_dir)) == NULL) {
		if (debug)
			syslog(LOG_ERR,
			    "warning: open directory %s failed: %m\n",
			    from_dir);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
			continue;
		}

		(void) strcpy(path, from_dir);
		(void) strcat(path, "/");
		(void) strcat(path, dirp->d_name);

		if (is_symlink(path)) {
			/*
			 * Follow the link to get the referenced file name
			 * and make a new link for that file in to_dir.
			 */
			n = readlink(path, rname, MAXNAMELEN);
			if (n <= 0) {
				if (debug >= 2) {
					(void) printf("copydir_from_to: can't "
					    "read link %s\n", path);
				}
				continue;
			}
			rname[n] = '\0';

			(void) create_symlink(to_dir, rname, dirp->d_name);
		} else {
			/*
			 * Simply copy regular files to to_dir.
			 */
			(void) strcpy(path, to_dir);
			(void) strcat(path, "/");
			(void) strcat(path, dirp->d_name);
			(void) create_file(path);
		}
	}

	(void) closedir(dp);
}

static int
init_hostname(void)
{
	struct lifnum lifn;
	int sock;

	if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "statd:init_hostname, socket: %m");
		return (-1);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;

	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syslog(LOG_ERR,
		"statd:init_hostname, get number of interfaces, error: %m");
		close(sock);
		return (-1);
	}

	host_name_count = lifn.lifn_count;

	host_name = malloc(host_name_count * sizeof (char *));
	if (host_name == NULL) {
		perror("statd -a can't get ip configuration\n");
		close(sock);
		return (-1);
	}
	close(sock);
	return (0);
}

static void
thr_statd_merges(void)
{
	/*
	 * Get other aliases from each interface.
	 */
	merge_hosts();

	/*
	 * Get all of the configured IP addresses.
	 */
	merge_ips();

	/*
	 * Notify the waiters.
	 */
	(void) mutex_lock(&merges_lock);
	in_merges = B_FALSE;
	(void) cond_broadcast(&merges_cond);
	(void) mutex_unlock(&merges_lock);
}

/*
 * This function is called for each configured network type to
 * bind and register our RPC service programs.
 *
 * On TCP or UDP, we may want to bind SM_PROG on a specific port
 * (when statd_port is specified) in which case we'll use the
 * variant of svc_tp_create() that lets us pass a bind address.
 */
static void
sm_svc_tp_create(struct netconfig *nconf)
{
	char port_str[8];
	struct nd_hostserv hs;
	struct nd_addrlist *al = NULL;
	SVCXPRT *xprt = NULL;

	/*
	 * If statd_port is set and this is an inet transport,
	 * bind this service on the specified port.  The TLI way
	 * to create such a bind address is netdir_getbyname()
	 * with the special "host" HOST_SELF_BIND.  This builds
	 * an all-zeros IP address with the specified port.
	 */
	if (statd_port != 0 &&
	    (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
	    strcmp(nconf->nc_protofmly, NC_INET6) == 0)) {
		int err;

		snprintf(port_str, sizeof (port_str), "%u",
		    (unsigned short)statd_port);

		hs.h_host = HOST_SELF_BIND;
		hs.h_serv = port_str;
		err = netdir_getbyname((struct netconfig *)nconf, &hs, &al);
		if (err == 0 && al != NULL) {
			xprt = svc_tp_create_addr(sm_prog_1, SM_PROG, SM_VERS,
			    nconf, al->n_addrs);
			netdir_free(al, ND_ADDRLIST);
		}
		if (xprt == NULL) {
			syslog(LOG_ERR, "statd: unable to create "
			    "(SM_PROG, SM_VERS) on transport %s (port %d)",
			    nconf->nc_netid, statd_port);
		}
		/* fall-back to default bind */
	}
	if (xprt == NULL) {
		/*
		 * Had statd_port=0, or non-inet transport,
		 * or the bind to a specific port failed.
		 * Do a default bind.
		 */
		xprt = svc_tp_create(sm_prog_1, SM_PROG, SM_VERS, nconf);
	}
	if (xprt == NULL) {
		syslog(LOG_ERR, "statd: unable to create "
		    "(SM_PROG, SM_VERS) for transport %s",
		    nconf->nc_netid);
		return;
	}

	/*
	 * Also register the NSM_ADDR program on this
	 * transport handle (same dispatch function).
	 */
	if (!svc_reg(xprt, NSM_ADDR_PROGRAM, NSM_ADDR_V1, sm_prog_1, nconf)) {
		syslog(LOG_ERR, "statd: failed to register "
		    "(NSM_ADDR_PROGRAM, NSM_ADDR_V1) for "
		    "netconfig %s", nconf->nc_netid);
	}
}

int
main(int argc, char *argv[])
{
	int c;
	int ppid;
	extern char *optarg;
	int choice = 0;
	struct rlimit rl;
	int mode;
	int sz;
	int pipe_fd = -1;
	int ret;
	int connmaxrec = RPC_MAXDATASIZE;
	struct netconfig *nconf;
	NCONF_HANDLE *nc;

	addrix = 0;
	pathix = 0;

	(void) gethostname(hostname, MAXHOSTNAMELEN);
	if (init_hostname() < 0)
		exit(1);

	ret = nfs_smf_get_iprop("statd_port", &statd_port,
	    DEFAULT_INSTANCE, SCF_TYPE_INTEGER, STATD);
	if (ret != SA_OK) {
		syslog(LOG_ERR, "Reading of statd_port from SMF "
		    "failed, using default value");
	}

	while ((c = getopt(argc, argv, "Dd:a:G:p:P:rU:")) != EOF)
		switch (c) {
		case 'd':
			(void) sscanf(optarg, "%d", &debug);
			break;
		case 'D':
			choice = 1;
			break;
		case 'a':
			if (addrix < host_name_count) {
				if (strcmp(hostname, optarg) != 0) {
					sz = strlen(optarg);
					if (sz < MAXHOSTNAMELEN) {
						host_name[addrix] =
						    (char *)xmalloc(sz+1);
						if (host_name[addrix] !=
						    NULL) {
						(void) sscanf(optarg, "%s",
						    host_name[addrix]);
							addrix++;
						}
					} else
					(void) fprintf(stderr,
				    "statd: -a name of host is too long.\n");
				}
			} else
				(void) fprintf(stderr,
				    "statd: -a exceeding maximum hostnames\n");
			break;
		case 'U':
			(void) sscanf(optarg, "%d", &daemon_uid);
			break;
		case 'G':
			(void) sscanf(optarg, "%d", &daemon_gid);
			break;
		case 'p':
			if (strlen(optarg) < MAXPATHLEN) {
				/* If the path_name array has not yet	   */
				/* been malloc'ed, do that.  The array	   */
				/* should be big enough to hold all of the */
				/* -p options we might have.  An upper	   */
				/* bound on the number of -p options is	   */
				/* argc/2, because each -p option consumes */
				/* two arguments.  Here the upper bound	   */
				/* is supposing that all the command line  */
				/* arguments are -p options, which would   */
				/* actually never be the case.		   */
				if (path_name == NULL) {
					size_t sz = (argc/2) * sizeof (char *);

					path_name = (char **)malloc(sz);
					if (path_name == NULL) {
						(void) fprintf(stderr,
						"statd: malloc failed\n");
						exit(1);
					}
					(void) memset(path_name, 0, sz);
				}
				path_name[pathix] = optarg;
				pathix++;
			} else {
				(void) fprintf(stderr,
				    "statd: -p pathname is too long.\n");
			}
			break;
		case 'P':
			(void) sscanf(optarg, "%d", &statd_port);
			if (statd_port < 1 || statd_port > UINT16_MAX) {
				(void) fprintf(stderr,
				    "statd: -P port invalid.\n");
				statd_port = 0;
			}
			break;
		case 'r':
			regfiles_only = 1;
			break;
		default:
			(void) fprintf(stderr,
			    "statd [-d level] [-D]\n");
			return (1);
		}

	if (choice == 0) {
		(void) strcpy(statd_home, home0);
		(void) strcpy(CURRENT, current0);
		(void) strcpy(BACKUP, backup0);
		(void) strcpy(STATE, state0);
	} else {
		(void) strcpy(statd_home, home1);
		(void) strcpy(CURRENT, current1);
		(void) strcpy(BACKUP, backup1);
		(void) strcpy(STATE, state1);
	}
	if (debug)
		(void) printf("debug is on, create entry: %s, %s, %s\n",
		    CURRENT, BACKUP, STATE);

	if (getrlimit(RLIMIT_NOFILE, &rl))
		(void) printf("statd: getrlimit failed. \n");

	/* Set maxfdlimit current soft limit */
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		syslog(LOG_ERR, "statd: unable to set RLIMIT_NOFILE to %d\n",
		    rl.rlim_cur);

	(void) enable_extended_FILE_stdio(-1, -1);

	if (!debug) {
		pipe_fd = daemonize_init();

		openlog("statd", LOG_PID, LOG_DAEMON);
	}

	(void) _create_daemon_lock(STATD, daemon_uid, daemon_gid);
	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	ppid = _enter_daemon_lock(STATD);
	switch (ppid) {
	case 0:
		break;
	case -1:
		syslog(LOG_ERR, "error locking for %s: %s", STATD,
		    strerror(errno));
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	mutex_init(&merges_lock, USYNC_THREAD, NULL);
	cond_init(&merges_cond, USYNC_THREAD, NULL);
	in_merges = B_TRUE;

	/*
	 * Create thr_statd_merges() thread to populate the host_name list
	 * asynchronously.
	 */
	if (thr_create(NULL, 0, (void *(*)(void *))thr_statd_merges, NULL,
	    THR_DETACHED, NULL) != 0) {
		syslog(LOG_ERR, "statd: unable to create thread for "
		    "thr_statd_merges().");
		exit(1);
	}

	/*
	 * Set to automatic mode such that threads are automatically
	 * created
	 */
	mode = RPC_SVC_MT_AUTO;
	if (!rpc_control(RPC_SVC_MTMODE_SET, &mode)) {
		syslog(LOG_ERR,
		    "statd:unable to set automatic MT mode.");
		exit(1);
	}

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		syslog(LOG_INFO, "unable to set maximum RPC record size");
	}

	/*
	 * Enumerate network transports and create service listeners
	 * as appropriate for each.
	 */
	if ((nc = setnetconfig()) == NULL) {
		syslog(LOG_ERR, "setnetconfig failed: %m");
		return (-1);
	}
	while ((nconf = getnetconfig(nc)) != NULL) {

		/*
		 * Skip things like tpi_raw, invisible...
		 */
		if ((nconf->nc_flag & NC_VISIBLE) == 0)
			continue;
		if (nconf->nc_semantics != NC_TPI_CLTS &&
		    nconf->nc_semantics != NC_TPI_COTS &&
		    nconf->nc_semantics != NC_TPI_COTS_ORD)
			continue;

		sm_svc_tp_create(nconf);
	}
	(void) endnetconfig(nc);

	/*
	 * Make sure /var/statmon and any alternate (-p) statmon
	 * directories exist and are owned by daemon.  Then change our uid
	 * to daemon.  The uid change is to prevent attacks against local
	 * daemons that trust any call from a local root process.
	 */

	set_statmon_owner();

	/*
	 *
	 * statd now runs as a daemon rather than root and can not
	 * dump core under / because of the permission. It is
	 * important that current working directory of statd be
	 * changed to writable directory /var/statmon so that it
	 * can dump the core upon the receipt of the signal.
	 * One still need to set allow_setid_core to non-zero in
	 * /etc/system to get the core dump.
	 *
	 */

	if (chdir(statd_home) < 0) {
		syslog(LOG_ERR, "can't chdir %s: %m", statd_home);
		exit(1);
	}

	copy_client_names();

	rwlock_init(&thr_rwlock, USYNC_THREAD, NULL);
	mutex_init(&crash_lock, USYNC_THREAD, NULL);
	mutex_init(&name_addrlock, USYNC_THREAD, NULL);
	cond_init(&retrywait, USYNC_THREAD, NULL);
	sm_inithash();
	die = 0;
	/*
	 * This variable is set to ensure that an sm_crash
	 * request will not be done at the same time
	 * when a statd_init is being done, since sm_crash
	 * can reset some variables that statd_init will be using.
	 */
	in_crash = 1;
	statd_init();

	/*
	 * statd is up and running as far as we are concerned.
	 */
	daemonize_fini(pipe_fd);

	if (debug)
		(void) printf("Starting svc_run\n");
	svc_run();
	syslog(LOG_ERR, "statd: svc_run returned\n");
	/* NOTREACHED */
	thr_exit((void *)1);
	return (0);

}

/*
 * Make sure the ownership of the statmon directories is correct, then
 * change our uid to match.  If the top-level directories (/var/statmon, -p
 * arguments) don't exist, they are created first.  The sm and sm.bak
 * directories are not created here, but if they already exist, they are
 * chowned to the correct uid, along with anything else in the
 * directories.
 */

static void
set_statmon_owner(void)
{
	int i;
	boolean_t can_do_mlp;

	/*
	 * Recursively chown/chgrp /var/statmon and the alternate paths,
	 * creating them if necessary.
	 */
	one_statmon_owner(statd_home);
	for (i = 0; i < pathix; i++) {
		char alt_path[MAXPATHLEN];

		snprintf(alt_path, MAXPATHLEN, "%s/statmon", path_name[i]);
		one_statmon_owner(alt_path);
	}

	can_do_mlp = priv_ineffect(PRIV_NET_BINDMLP);
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    daemon_uid, daemon_gid, can_do_mlp ? PRIV_NET_BINDMLP : NULL,
	    NULL) == -1) {
		syslog(LOG_ERR, "can't run unprivileged: %m");
		exit(1);
	}

	__fini_daemon_priv(PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, NULL);
}

/*
 * Copy client names from the alternate statmon directories into
 * /var/statmon.  The top-level (statmon) directories should already
 * exist, though the sm and sm.bak directories might not.
 */

static void
copy_client_names(void)
{
	int i;
	char buf[MAXPATHLEN+SM_MAXPATHLEN];

	/*
	 * Copy all clients from alternate paths to /var/statmon/sm
	 * Remove the files in alternate directory when copying is done.
	 */
	for (i = 0; i < pathix; i++) {
		/*
		 * If the alternate directories do not exist, create it.
		 * If they do exist, just do the copy.
		 */
		snprintf(buf, sizeof (buf), "%s/statmon/sm", path_name[i]);
		if ((mkdir(buf, SM_DIRECTORY_MODE)) == -1) {
			if (errno != EEXIST) {
				syslog(LOG_ERR,
				    "can't mkdir %s: %m\n", buf);
				continue;
			}
			copydir_from_to(buf, CURRENT);
			(void) remove_dir(buf);
		}

		(void) snprintf(buf, sizeof (buf), "%s/statmon/sm.bak",
		    path_name[i]);
		if ((mkdir(buf, SM_DIRECTORY_MODE)) == -1) {
			if (errno != EEXIST) {
				syslog(LOG_ERR,
				    "can't mkdir %s: %m\n", buf);
				continue;
			}
			copydir_from_to(buf, BACKUP);
			(void) remove_dir(buf);
		}
	}
}

/*
 * Create the given directory if it doesn't already exist.  Set the user
 * and group to daemon for the directory and anything under it.
 */

static void
one_statmon_owner(const char *dir)
{
	if ((mkdir(dir, SM_DIRECTORY_MODE)) == -1) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "can't mkdir %s: %m",
			    dir);
			return;
		}
	}

	if (debug)
		printf("Setting owner for %s\n", dir);

	if (nftw(dir, nftw_owner, MAX_FDS, FTW_PHYS) != 0) {
		syslog(LOG_WARNING, "error setting owner for %s: %m",
		    dir);
	}
}

/*
 * Set the user and group to daemon for the given file or directory.  If
 * it's a directory, also makes sure that it is mode 755.
 * Generates a syslog message but does not return an error if there were
 * problems.
 */

/*ARGSUSED3*/
static int
nftw_owner(const char *path, const struct stat *statp, int info,
    struct FTW *ftw)
{
	if (!(info == FTW_F || info == FTW_D))
		return (0);

	/*
	 * Some older systems might have mode 777 directories.  Fix that.
	 */

	if (info == FTW_D && (statp->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
		mode_t newmode = (statp->st_mode & ~(S_IWGRP | S_IWOTH)) &
		    S_IAMB;

		if (debug)
			printf("chmod %03o %s\n", newmode, path);
		if (chmod(path, newmode) < 0) {
			int error = errno;

			syslog(LOG_WARNING, "can't chmod %s to %03o: %m",
			    path, newmode);
			if (debug)
				printf("  FAILED: %s\n", strerror(error));
		}
	}

	/* If already owned by daemon, don't bother changing. */
	if (statp->st_uid == daemon_uid &&
	    statp->st_gid == daemon_gid)
		return (0);

	if (debug)
		printf("lchown %s daemon:daemon\n", path);
	if (lchown(path, daemon_uid, daemon_gid) < 0) {
		int error = errno;

		syslog(LOG_WARNING, "can't chown %s to daemon: %m",
		    path);
		if (debug)
			printf("  FAILED: %s\n", strerror(error));
	}

	return (0);
}
