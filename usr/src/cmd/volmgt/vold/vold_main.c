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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<syslog.h>
#include	<errno.h>
#include	<string.h>
#include	<rpc/rpc.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<sys/time.h>
#include	<sys/stat.h>
#include	<signal.h>
#include	<sys/signal.h>
#include	<rpcsvc/nfs_prot.h>
#include	<netinet/in.h>
#include	<sys/mnttab.h>
#include	<sys/mntent.h>
#include	<sys/mount.h>
#include	<sys/resource.h>
#include	<netdb.h>
#include	<sys/signal.h>
#include	<netdir.h>
#include	<locale.h>
#include	<ulimit.h>
#include	<ucontext.h>
#include	<pwd.h>
#include	<grp.h>
#include	<sys/systeminfo.h>
#include	<thread.h>
#include	<synch.h>
#include	<stropts.h>
#include	<zone.h>
#include	<libscf.h>
#include	"vold.h"


/* extern vars */
extern int 	trace;		/* nfs server trace enable */
extern int	vol_fd;

/* extern prototypes */
extern int	__rpc_negotiate_uid(int fd);


/* local prototypes */
static struct netconfig *trans_loopback(void);
static void		trans_netbuf(struct netconfig *, struct netbuf *);
static void		catch(void);
static void		catch_n_exit(int);
static void		catch_n_return(int);
void			reread_config(int);
static void		usage(void);
static void		vold_run(void);


/* global vars */
int 		verbose 	= DEFAULT_VERBOSE;
int 		debug_level 	= DEFAULT_DEBUG;
char		*vold_root 	= DEFAULT_VOLD_ROOT;
char		*vold_config 	= DEFAULT_VOLD_CONFIG;
char		*vold_devdir	= DEFAULT_VOLD_DEVDIR;
char		*volume_group	= DEFAULT_VOLUME_GROUP;
char		*nisplus_group	= DEFAULT_NISPLUS_GROUP;
int		never_writeback = 0;
uid_t		default_uid;
gid_t		default_gid;
char		self[MAXHOSTNAMELEN];
struct timeval	current_time;
rlim_t		original_nofile;
int		vold_running = 0;
cond_t		running_cv;
mutex_t		running_mutex;

/* local vars */
static int	vold_polltime = DEFAULT_POLLTIME;
static char	*prog_name;
static pid_t	mount_pid;
static int	mount_timeout 	= 30;
static int	reread_config_file = 0;
static int	event_notify_pipe[2];

#define	MAXPOLLFD	5

mutex_t	vold_main_mutex = DEFAULTMUTEX;

bool_t		mount_complete = FALSE;

extern int	umount_all(char *);

void
main(int argc, char **argv)
{
	extern void		nfs_program_2(struct svc_req *, SVCXPRT *);
	extern bool_t		vol_init(void);
	extern bool_t		config_read(void);
	extern int		sysevent_init(void);
	SVCXPRT			*xprt;
	struct netconfig	*nconf;
	struct nfs_args		args;
	struct knetconfig	knconf;
	struct stat		sb;
	int			c;
	int			set_my_log = 0;
	struct passwd		*pw;
	struct group		*gr;
	struct sigaction	act;
	int			rpc_fd;
	struct t_bind		*tbind;
	struct rlimit		rlim;
	char			*buf;
	struct vol_str		volstr;
	sec_data_t		secdata;
	char			mntopts[MAX_MNTOPT_STR];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    gettext("%s only runs in the global zone"), prog_name);
		_exit(SMF_EXIT_MON_OFFLINE);
	}

	/* argument processing */
	while ((c = getopt(argc, argv, "vtf:d:pl:L:g:no:G:P:")) != -1) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 't':
			trace++;
			break;
		case 'f':
			vold_config = (char *)optarg;
			break;
		case 'd':
			vold_root = (char *)optarg;
			break;
		case 'o':
			vold_devdir = (char *)optarg;
			break;
		case 'g':
			volume_group = (char *)optarg;
			break;
		case 'G':
			nisplus_group = (char *)optarg;
			break;
		case 'l':
			set_my_log = 1;
			setlog((char *)optarg);
			break;
		case 'L':
			debug_level = atoi((char *)optarg);
			break;
		case 'n':
			never_writeback = 1;
			break;
		case 'P':
			vold_polltime = atoi((char *)optarg) * 1000;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	if (set_my_log == 0)
		setlog(DEFAULT_VOLD_LOG);

	debug(5, "main: debug level %d (verbose = %d)\n",
	    debug_level, verbose);


	(void) gettimeofday(&current_time, NULL);

	openlog(prog_name, LOG_PID | LOG_NOWAIT | LOG_CONS, LOG_DAEMON);
	(void) umask(0);
	(void) setbuf(stdout, (char *)NULL);
	(void) sysinfo(SI_HOSTNAME, self, sizeof (self));

	/*
	 * XXLP: This really should be removed and work done to work out
	 * what privileges vold actually needs.  This could be problematic
	 * with vold because of the pluggable action system.  However this
	 * is done via rmmount in a child process so at least the main vold
	 * process can probably run with fewer privileges even if it needs
	 * a full inheritable set to pass on to rmmount.
	 */
	if (geteuid() != 0) {
		fatal(gettext("Must be root to execute vold\n"));
	}

	/*
	 * Increase file descriptor limit to the most it can possibly
	 * be.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		fatal("getrlimit for fd's failed; %m\n");
	}

	original_nofile = rlim.rlim_cur;
	rlim.rlim_cur = rlim.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		fatal("setrlimit for fd's failed; %m\n");
	}

	gr = getgrnam(DEFAULT_GROUP);
	if (gr == NULL) {
		fatal(gettext("Must have the \"%s\" group defined\n"),
		    DEFAULT_GROUP);
	}
	default_gid = gr->gr_gid;

	pw = getpwnam(DEFAULT_USER);
	if (pw == NULL) {
		fatal(gettext("Must have the \"%s\" user defined\n"),
			DEFAULT_USER);
	}
	default_uid = pw->pw_uid;

	(void) mutex_init(&running_mutex, USYNC_THREAD, 0);
	(void) cond_init(&running_cv, USYNC_THREAD, 0);

	if (vol_init() == FALSE) {
		fatal(gettext(
		    "vol_init failed (can't communicate with kernel)\n"));
		/*NOTREACHED*/
	}

	/* read in the config file */
	if (!config_read()) {
		fatal(gettext("vold can't start without a config file\n"));
	}

	nconf = trans_loopback();
	if (nconf == (struct netconfig *)NULL) {
		fatal(gettext("no tpi_clts loopback transport available\n"));
		/*NOTREACHED*/
	}
	if ((rpc_fd = t_open(nconf->nc_device, O_RDWR,
	    (struct t_info *)NULL)) < 0) {
		fatal(gettext("unable to t_open \"%s\"\n"), nconf->nc_device);
		/*NOTREACHED*/
	}

	/*
	 * Negotiate for returning the uid of the caller.
	 * This should be done before enabling the endpoint for
	 * service via t_bind() (called in svc_tli_create())
	 * so that requests to vold contain the uid.
	 */
	if (__rpc_negotiate_uid(rpc_fd) != 0) {
		(void) t_close(rpc_fd);
		fatal(gettext(
		"Couldn't negotiate for uid with loopback transport %s\n"),
			nconf->nc_netid);
		/* NOT REACHED */
	}

	/*LINTED alignment ok*/
	if ((tbind = (struct t_bind *)t_alloc(rpc_fd, T_BIND,
	    T_ALL)) == NULL) {
		fatal(gettext("unable to t_alloc\n"));
		/*NOTREACHED*/
	}
	tbind->qlen = 1;
	trans_netbuf(nconf, &tbind->addr);
	xprt = svc_tli_create(rpc_fd, nconf, tbind, 0, 0);
	if (xprt == (SVCXPRT *) NULL) {
		fatal(
		    gettext("svc_tli_create: Cannot create server handle\n"));
		/*NOTREACHED*/
	}
	if (!svc_reg(xprt, NFS_PROGRAM, NFS_VERSION, nfs_program_2,
		(struct netconfig *)0)) {
		fatal(gettext("Could not register RPC service\n"));
		/*NOTREACHED*/
	}

	if (tbind != NULL) {
		if (tbind->addr.buf != NULL)
			free(tbind->addr.buf);
		free(tbind);
	}

	/*
	 * create signal notify pipe.
	 */
	if (pipe(event_notify_pipe) < 0) {
		fatal(gettext("Could not create pipe\n"));
		/*NOTREACHED*/
	}
	(void) fcntl(event_notify_pipe[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(event_notify_pipe[1], F_SETFD, FD_CLOEXEC);
	(void) fcntl(event_notify_pipe[0], F_SETFL, O_WRONLY|O_NONBLOCK);

	/*
	 * ensure the root node is set up before using it
	 *
	 * XXX: the only case that this seems to apply to is the one where
	 * no floppy or CD-ROM (or otherwise normal device) is present,
	 * but the pcmem forcload=TRUE option has loaded the dev_pcmem
	 * DSO (see bug id# 1244293)
	 */
	if (root == NULL) {
		debug(5, "main: have to set up root vvnode myself!?\n");
		db_root();			/* funky but true */
	}

	/*
	 * unmount /vol if it was still mounted
	 */
	(void) umount_all(vold_root);

	/*
	 *  Fork vold
	 *  For debugging, the sense of this is backwards -- here we fork
	 *  the mount half rather than the work half (so we can use dbx
	 *  easily).
	 */
	mount_pid = fork();
	if (mount_pid == -1) {
		fatal(gettext("Cannot fork; %m\n"));
		/*NOTREACHED*/
	} else if (mount_pid == 0) {

		(void) memset(&args, 0, sizeof (args));
		(void) memset(&knconf, 0, sizeof (knconf));

		/* child */

		/*
		 * NFSMNT_NOAC flag needs to be turned off when NFS client
		 * side bugid 1110389 is fixed.
		 *
		 * NOTE: as of s494-ea, the NFSMNT_NOAC flag can NOT
		 *	be used, as it doesn't seem to be fully implemented.
		 *
		 * 10/14/94: symlinks seem to be hosed in 2.4 (NFS seems to
		 *	be caching READLINKs, so on goes NFSMNT_NOAC again
		 *	(see bug id# 1179769) -- also, 1110389 has long-since
		 *	been fixed.
		 */
		args.flags = NFSMNT_INT | NFSMNT_TIMEO | NFSMNT_RETRANS |
		    NFSMNT_HOSTNAME | NFSMNT_NOAC;
		args.addr = &xprt->xp_ltaddr;

		if (stat(nconf->nc_device, &sb) < 0) {
			fatal(gettext("Couldn't stat \"%s\"; %m\n"),
			    nconf->nc_device);
			/*NOTREACHED*/
		}
		knconf.knc_semantics = nconf->nc_semantics;
		knconf.knc_protofmly = nconf->nc_protofmly;
		knconf.knc_proto = nconf->nc_proto;
		knconf.knc_rdev = sb.st_rdev;
		args.flags |= NFSMNT_KNCONF;
		args.knconf = &knconf;

		args.timeo = (mount_timeout + 5) * 10;
		args.retrans = 5;
		args.hostname = strdup("for volume management (/vol)");
		args.netname = strdup("");

		ASSERT(root != NULL);
		args.fh = (caddr_t)&root->vn_fh;

		/*
		 * Check to see mount point is there...
		 */
		if (stat(vold_root, &sb) < 0) {
			if (errno == ENOENT) {
				info(gettext("%s did not exist: creating\n"),
				    vold_root);
				if (makepath(vold_root, 0755) < 0) {
					fatal(gettext(
					"can't make directory \"%s\"; %m\n"),
					    vold_root);
				}
			} else {
				fatal("can't stat \"%s\"; %m\n", vold_root);
				/*NOTREACHED*/
			}
		} else if (!(sb.st_mode & S_IFDIR)) {
			/* ...and that it's a directory. */
			fatal(gettext("\"%s\" is not a directory\n"),
			    vold_root);
			/*NOTREACHED*/
		}

		args.flags |= NFSMNT_NEWARGS;
		secdata.secmod = AUTH_LOOPBACK;
		secdata.rpcflavor = AUTH_LOOPBACK;
		secdata.flags = 0;
		secdata.data = NULL;

		args.nfs_args_ext = NFS_ARGS_EXTB;
		args.nfs_ext_u.nfs_extB.secdata = &secdata;
		args.nfs_ext_u.nfs_extB.next = NULL;

		/*
		 * it's not really mounted until /etc/mnttab says so
		 */
		c = strlen(self) + 64;
		buf = vold_malloc(c);
		(void) snprintf(buf, c, "%s:vold(pid%ld)", self, getppid());

		/*
		 * mount "/vol" -- this will block until our parent
		 * actually services this request
		 */
		(void) snprintf(mntopts, sizeof (mntopts),
			"%s,%s", MNTOPT_IGNORE, MNTOPT_NOQUOTA);
		if (mount(buf, vold_root, MS_DATA|MS_OPTIONSTR, MNTTYPE_NFS,
		    &args, sizeof (args), mntopts, MAX_MNTOPT_STR) < 0) {
			if (errno == EBUSY) {
				warning(gettext("vold restarted\n"));
			} else {
				warning(gettext("Can't mount \"%s\"; %m\n"),
				    vold_root);
			}
			exit(1);
			/*NOTREACHED*/
		}
		exit(0);
		/*NOTREACHED*/
	}

	/* parent */

	freenetconfigent(nconf);

	(void) setsid();

	/* set up our signal handlers */
	act.sa_handler = catch_n_return;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART|SA_SIGINFO;
	(void) sigaction(SIGCHLD, &act, NULL);

	act.sa_handler = catch;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART|SA_SIGINFO;
	(void) sigaction(SIGTERM, &act, NULL);

	/*
	 * The SIGHUP handler provides a mechanism
	 * for changing vold's map of the system's
	 * removable media devices when either vold's
	 * configuration file changes or the system's
	 * removable media device configuration changes.
	 *
	 * We also register with sysventd to receive notification
	 * of new devices being added.
	 */

	act.sa_handler = reread_config;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART|SA_SIGINFO;
	(void) sigaction(SIGHUP, &act, NULL);

	act.sa_handler = catch;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART|SA_SIGINFO;
	(void) sigaction(SIGINT, &act, NULL);

	act.sa_handler = catch_n_exit;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART|SA_SIGINFO;
	(void) sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = catch_n_return;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;	/* no restart!! */
	(void) sigaction(SIGUSR2, &act, NULL);

	/*
	 * tell vol driver about where our root is
	 */

	volstr.data = vold_root;
	volstr.data_len = strlen(vold_root);

	if (ioctl(vol_fd, VOLIOCDROOT, &volstr) != 0) {
		fatal(gettext("can't set vol root to \"%s\"; %m\n"),
		    vold_root);
		/*NOTREACHED*/
	}

	(void) sysevent_init();

	/* do the real work */
	vold_run();
	fatal(gettext("vold_run returned!\n"));
	/*NOTREACHED*/
}

/*
 * Get a netconfig entry for loopback transport
 */
static struct netconfig *
trans_loopback(void)
{
	struct netconfig	*nconf;
	NCONF_HANDLE		*nc;


	nc = setnetconfig();
	if (nc == NULL)
		return (NULL);

	while (nconf = getnetconfig(nc)) {
		if (nconf->nc_flag & NC_VISIBLE &&
		    nconf->nc_semantics == NC_TPI_CLTS &&
		    strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
			nconf = getnetconfigent(nconf->nc_netid);
			break;
		}
	}

	endnetconfig(nc);
	return (nconf);
}

static void
trans_netbuf(struct netconfig *nconf, struct netbuf *np)
{
	struct nd_hostserv	nd_hostserv;
	struct nd_addrlist	*nas;

	nd_hostserv.h_host = self;
	nd_hostserv.h_serv = DEFAULT_SERVICE;

	if (!netdir_getbyname(nconf, &nd_hostserv, &nas)) {
		np->len = nas->n_addrs->len;
		(void) memcpy(np->buf, nas->n_addrs->buf,
		    (int)nas->n_addrs->len);
		netdir_free((char *)nas, ND_ADDRLIST);
	} else {
		fatal(gettext("No service found for %s on transport %s\n"),
			DEFAULT_SERVICE, nconf->nc_netid);
		/*NOTREACHED*/
	}

}

static int
wait_mount(void)
{
	int	stat;
	bool_t	comp = FALSE;

	/*
	 * the child we forked to do the mount() may not be
	 * done yet, so wait until it is
	 */
	if (waitpid(mount_pid, &stat, WNOHANG) == mount_pid) {
		if (WIFEXITED(stat) && (WEXITSTATUS(stat) == 0)) {
			comp = TRUE;
		} else {
			fatal(gettext("mounting of \"%s\" failed\n"),
					    vold_root);
			/*NOTREACHED*/
		}
	}
	return (comp);
}

/*
 * main loop for the volume daemon.
 */

/*
 * egad... what a clever... well...
 * The problem is that it's impossible to write a fully MT program
 * at this time because several of the libraries that I depend on
 * (e.g. the rpc library) are not MT safe.  So, we suffer from a
 * very partial MT job.  The main significance here is that poll(2)
 * relies on SIGCHLD to kick us out of a system call.  It's much more
 * efficient (in terms of wall clock time) to do this than just
 * poll for some number of seconds.
 */

static void
vold_run(void)
{
	extern void	svc_getreq_common(const int);
	extern void	vol_readevents(void);
	extern int	vol_async(void);
	extern bool_t	config_read(void);
	int		n, i, fd;
	int		action_in_progress = 0;
	int		rpc_fd;
	size_t		npollfd = 0;
	struct	pollfd	poll_fds[MAXPOLLFD];

	for (i = 0; i < svc_max_pollfd; i++) {
		if (svc_pollfd[i].fd >= 0) {
			rpc_fd = i;
			break;
		}
	}

	info(gettext("vold: running\n"));

	/* let the threads GO */
	if (vold_running == 0) {
		(void) mutex_lock(&running_mutex);
		vold_running = 1;
		(void) cond_broadcast(&running_cv);
		(void) mutex_unlock(&running_mutex);
	}

	poll_fds[npollfd].fd = rpc_fd;
	poll_fds[npollfd].events = POLLIN|POLLRDNORM|POLLRDBAND;
	npollfd++;
	poll_fds[npollfd].fd = vol_fd;
	poll_fds[npollfd].events = POLLRDNORM;
	npollfd++;
	poll_fds[npollfd].fd = event_notify_pipe[1];
	poll_fds[npollfd].events = POLLIN;
	npollfd++;

	/* handle events forever */
	for (;;) {
		/* wait until something happens */
		debug(12, "vold_run: about to poll()\n");

		n = poll(poll_fds, npollfd, vold_polltime);

		debug(12, "vold_run: poll() returned %d (errno %d)\n",
			n, errno);

		/* update idea of the "now" */
		(void) gettimeofday(&current_time, NULL);

		/*
		 * We need to serialize:
		 * 1) svc_getreq_common	- it will touch devmap.
		 * 2) vol_readevents	- touch a lot of shared data.
		 * 3) vol_async		- dev_eject changes node data.
		 * 4) config_read	- anything should not be working.
		 */

		(void) mutex_lock(&vold_main_mutex);

		/*
		 * Is there work to do?
		 */
		if (n > 0) {
			/* there is work to do -- look at each possible fd */
			for (i = 0; n != 0 && i < npollfd; i++) {
				if (poll_fds[i].revents == 0)
					continue;

				fd = poll_fds[i].fd;
				if (fd == rpc_fd) {
					/* this is an NFS event */
					svc_getreq_common(rpc_fd);
				} else if (fd == vol_fd) {
					/* this is a volctl event */
					vol_readevents();
				} else if (fd == event_notify_pipe[1]) {
					/* this is a signal event */
					(void) ioctl(fd, I_FLUSH, FLUSHR);
				}
				n--;
			}
		} else if (n < 0) {
			/* poll() had an error */
			if (errno == EINTR) {
				debug(10, "vold_run: poll interrupted\n");
			} else {
				debug(10,
				    "vold_run: poll failed (errno %d)\n",
				    errno);
			}
			/* cleaup the signal notify pipe. */
			(void) ioctl(event_notify_pipe[1], I_FLUSH, FLUSHR);
		}

		if (mount_complete) {
			/*
			 * don't want to process async tasks (such as
			 * media insertion) until the NFS server is ready
			 * to handle request
			 */
			action_in_progress = vol_async();
		} else {
			if ((mount_complete = wait_mount()) == TRUE) {
				/*
				 * mount completed. we need to check pending
				 * event which was delivered while waiting
				 * for the child. Otherwise, events won't be
				 * processed until poll returns.
				 */
				action_in_progress = vol_async();
			}
		}

		/*
		 * should reconfig after vol_async() was called. Otherwise,
		 * new action may be invoked by vol_readevents, and may be
		 * running while reconfiguring.
		 */
		if (!action_in_progress && reread_config_file) {
			/*
			 * Either vold's configuration file
			 * has changed or the actual removable
			 * media device configuration has changed.
			 */
			reread_config_file = 0;
			(void) config_read();
		}

		(void) mutex_unlock(&vold_main_mutex);
	}
	/*NOTREACHED*/
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s\n"), prog_name);
	(void) fprintf(stderr,
	    gettext("\t[-v]\t\tverbose status information\n"));
	(void) fprintf(stderr,
	    gettext("\t[-t]\t\tunfs server trace information\n"));
	(void) fprintf(stderr,
	    gettext("\t[-f pathname]\talternate vold.conf file\n"));
	(void) fprintf(stderr,
	    gettext("\t[-d directory]\talternate /vol directory\n"));
	(void) fprintf(stderr,
	    gettext("\t[-l logfile]\tplace to put log messages\n"));
	(void) fprintf(stderr,
	    gettext("\t[-L loglevel]\tlevel of debug information\n"));
	(void) fprintf(stderr, "\n");
	exit(1);
}


void
catch(void)
{
	pid_t		parentpid = getpid();
	pid_t		childpid;
	int			err;

	childpid = fork1();
	if (childpid < 0) {
		warning(gettext("Can't fork; %m\n"));
	} else if (childpid == 0) {

		/* in child */

		if ((err = umount_all(vold_root)) != 0) {
			syslog(LOG_ERR, gettext("problem unmounting %s; %m\n"),
				vold_root);
		} else {
			debug(1, "Killing pid %d\n", parentpid);
			(void) kill(parentpid, SIGKILL);
		}
		exit(err);
	} else {

		/* in parent */

		debug(1, "catch(): pid %d created pid %d\n", getpid(),
			childpid);
		if (waitpid(childpid, NULL, 0) == childpid) {
			debug(10, "catch(): waitpid() succeeded for pid: %d\n",
				childpid);
		} else {
			debug(10, "waitpid, in catch() failed for pid: %d",
				childpid);
		}
	}
}


/*
 * Exit from the thread.
 */
/*ARGSUSED*/
static void
catch_n_exit(int sig)
{
	extern void	flushlog(void);
	extern void 	sysevent_fini(void);

	flushlog();
	if (thr_self() > 1) {
		debug(1, "thread %d exiting\n", thr_self());
		thr_exit(NULL);
	}

	(void) sysevent_fini();

	warning(gettext("volume management exiting\n"));
	exit(0);
}

/*
 * don't do anything but write one byte to pipe, so that poll()
 * never get stuck.
 */
/*ARGSUSED*/
void
catch_n_return(int sig)
{
	vold_run_run();
}

/*
 * Signal to reread the configuration file
 */
/*ARGSUSED*/
void
reread_config(int sig)
{
	reread_config_file = 1;
	vold_run_run();
}

void
vold_run_run(void)
{
	char c = 0;
	(void) write(event_notify_pipe[0], &c, 1);
}
