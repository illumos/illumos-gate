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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014 Gary Mills
 */

/*
 * Network SNDR/ncall-ip server - based on nfsd
 */
#include <sys/types.h>
#include <rpc/types.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netconfig.h>
#include <stropts.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdir.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>
#include <tiuser.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <syslog.h>
#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <libgen.h>
#include <deflt.h>
#include <sys/resource.h>

#include <sys/nsctl/nsctl.h>

#ifdef	__NCALL__

#include <sys/ncall/ncall.h>
#include <sys/ncall/ncall_ip.h>
#include <sys/nsctl/libncall.h>

#define	RDC_POOL_CREATE	NC_IOC_POOL_CREATE
#define	RDC_POOL_RUN	NC_IOC_POOL_RUN
#define	RDC_POOL_WAIT	NC_IOC_POOL_WAIT
#define	RDC_PROGRAM	NCALL_PROGRAM
#define	RDC_SERVICE	"ncall"
#undef RDC_SVCPOOL_ID	/* We are overloading this value */
#define	RDC_SVCPOOL_ID	NCALL_SVCPOOL_ID
#define	RDC_SVC_NAME	"NCALL"
#define	RDC_VERS_MIN	NCALL_VERS_MIN
#define	RDC_VERS_MAX	NCALL_VERS_MAX

#else	/* !__NCALL__ */

#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/librdc.h>

#define	RDC_SERVICE	"rdc"
#define	RDC_SVC_NAME	"RDC"

#endif	/* __NCALL__ */

#define	RDCADMIN	"/etc/default/sndr"

#include <nsctl.h>

struct conn_ind {
	struct conn_ind *conn_next;
	struct conn_ind *conn_prev;
	struct t_call   *conn_call;
};

struct conn_entry {
	bool_t			closing;
	struct netconfig	nc;
};

static char *progname;
static struct conn_entry *conn_polled;
static int num_conns;			/* Current number of connections */
static struct pollfd *poll_array;	/* array of poll descriptors for poll */
static size_t num_fds = 0;		/* number of transport fds opened */
static void poll_for_action();
static void remove_from_poll_list(int);
static int do_poll_cots_action(int, int);
static int do_poll_clts_action(int, int);
static void add_to_poll_list(int, struct netconfig *);
static int bind_to_provider(char *, char *, struct netbuf **,
    struct netconfig **);
static int set_addrmask(int, struct netconfig *, struct netbuf *);
static void conn_close_oldest(void);
static boolean_t conn_get(int, struct netconfig *, struct conn_ind **);
static void cots_listen_event(int, int);
static int discon_get(int, struct netconfig *, struct conn_ind **);
static int nofile_increase(int);
static int is_listen_fd_index(int);
#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)
static int sndrsvcpool(int);
static int svcwait(int id);
#endif


/*
 * RPC protocol block.  Useful for passing registration information.
 */
struct protob {
	char *serv;		/* ASCII service name, e.g. "RDC" */
	int versmin;		/* minimum version no. to be registered */
	int versmax;		/* maximum version no. to be registered */
	int program;		/* program no. to be registered */
	struct protob *next;	/* next entry on list */
};



static size_t end_listen_fds;
static int debugflg = 0;
static int max_conns_allowed = -1;
static int listen_backlog = 10;
static char *trans_provider = (char *)NULL;
static int rdcsvc(int, struct netbuf, struct netconfig *);

/* used by cots_listen_event() */
static int (*Mysvc)(int, struct netbuf, struct netconfig *) = rdcsvc;

/*
 * Determine valid semantics for rdc.
 */
#define	OK_TPI_TYPE(_nconf)	\
	(_nconf->nc_semantics == NC_TPI_CLTS || \
	_nconf->nc_semantics == NC_TPI_COTS || \
	_nconf->nc_semantics == NC_TPI_COTS_ORD)

#define	BE32_TO_U32(a)		\
	((((uint32_t)((uchar_t *)a)[0] & 0xFF) << (uint32_t)24) |\
	(((uint32_t)((uchar_t *)a)[1] & 0xFF) << (uint32_t)16) |\
	(((uint32_t)((uchar_t *)a)[2] & 0xFF) << (uint32_t)8)  |\
	((uint32_t)((uchar_t *)a)[3] & 0xFF))

#ifdef DEBUG
/*
 * Only support UDP in DEBUG mode for now
 */
static	char *defaultproviders[] = { "/dev/tcp", "/dev/tcp6", "/dev/udp",
		"/dev/udp6", NULL };
#else
static	char *defaultproviders[] = { "/dev/tcp6", "/dev/tcp", NULL };
#endif

/*
 * Number of elements to add to the poll array on each allocation.
 */
#define	POLL_ARRAY_INC_SIZE	64
#define	NOFILE_INC_SIZE		64

#ifdef	__NCALL__
const char *rdc_devr = "/dev/ncallip";
#else
const char *rdc_devr = "/dev/rdc";
#endif

static int rdc_fdr;
static int

open_rdc(void)
{
	int fd = open(rdc_devr, O_RDONLY);

	if (fd < 0)
		return (-1);

	return (rdc_fdr = fd);
}

static int
sndrsys(int type, void *arg)
{
	int ret = -1;
	if (!rdc_fdr && open_rdc() < 0) { /* open failed */
		syslog(LOG_ERR, "open_rdc() failed: %m\n");
	} else {
		if ((ret = ioctl(rdc_fdr, type, arg)) < 0) {
			syslog(LOG_ERR, "ioctl(rdc_ioctl) failed: %m\n");
		}
	}
	return (ret);
}

int
rdc_transport_open(struct netconfig *nconf)
{
	int fd;
	struct strioctl	strioc;

	if ((nconf == (struct netconfig *)NULL) ||
	    (nconf->nc_device == (char *)NULL)) {
		syslog(LOG_ERR, "No netconfig device");
		return (-1);
	}

	/*
	 * Open the transport device.
	 */
	fd = t_open(nconf->nc_device, O_RDWR, (struct t_info *)NULL);
	if (fd == -1)  {
		if (t_errno == TSYSERR && errno == EMFILE &&
		    (nofile_increase(0) == 0)) {
			/* Try again with a higher NOFILE limit. */
			fd = t_open(nconf->nc_device, O_RDWR, NULL);
		}
		if (fd == -1) {
			if (t_errno == TSYSERR) {
				syslog(LOG_ERR, "t_open failed: %m");
			} else {
				syslog(LOG_ERR, "t_open failed: %s",
				    t_errlist[t_errno]);
			}
			return (-1);
		}
	}

	/*
	 * Pop timod because the RPC module must be as close as possible
	 * to the transport.
	 */
	if (ioctl(fd, I_POP, 0) < 0) {
		syslog(LOG_ERR, "I_POP of timod failed: %m");
		if (t_close(fd) == -1) {
			if (t_errno == TSYSERR) {
				syslog(LOG_ERR, "t_close failed on %d: %m", fd);
			} else {
				syslog(LOG_ERR, "t_close failed on %d: %s",
				    fd, t_errlist[t_errno]);
			}
		}
		return (-1);
	}

	if (nconf->nc_semantics == NC_TPI_CLTS) {
		/*
		 * Push rpcmod to filter data traffic to KRPC.
		 */
		if (ioctl(fd, I_PUSH, "rpcmod") < 0) {
			syslog(LOG_ERR, "I_PUSH of rpcmod failed: %m");
			(void) t_close(fd);
			return (-1);
		}
	} else {
		if (ioctl(fd, I_PUSH, "rpcmod") < 0) {
			syslog(LOG_ERR, "I_PUSH of CONS rpcmod failed: %m");
			if (t_close(fd) == -1) {
				if (t_errno == TSYSERR) {
					syslog(LOG_ERR,
					    "t_close failed on %d: %m", fd);
				} else {
					syslog(LOG_ERR,
					    "t_close failed on %d: %s",
					    fd, t_errlist[t_errno]);
				}
			}
			return (-1);
		}

		strioc.ic_cmd = RPC_SERVER;
		strioc.ic_dp = (char *)0;
		strioc.ic_len = 0;
		strioc.ic_timout = -1;
		/* Tell CONS rpcmod to act like a server stream. */
		if (ioctl(fd, I_STR, &strioc) < 0) {
			syslog(LOG_ERR, "CONS rpcmod set-up ioctl failed: %m");
			if (t_close(fd) == -1) {
				if (t_errno == TSYSERR) {
					syslog(LOG_ERR,
					    "t_close failed on %d: %m", fd);
				} else {
					syslog(LOG_ERR,
					    "t_close failed on %d: %s",
					    fd, t_errlist[t_errno]);
				}
			}
			return (-1);
		}
	}

	/*
	 * Re-push timod so that we will still be doing TLI
	 * operations on the descriptor.
	 */
	if (ioctl(fd, I_PUSH, "timod") < 0) {
		syslog(LOG_ERR, "I_PUSH of timod failed: %m");
		if (t_close(fd) == -1) {
			if (t_errno == TSYSERR) {
				syslog(LOG_ERR, "t_close failed on %d: %m", fd);
			} else {
				syslog(LOG_ERR, "t_close failed on %d: %s",
				    fd, t_errlist[t_errno]);
			}
		}
		return (-1);
	}

	return (fd);
}


void
rdcd_log_tli_error(char *tli_name, int fd, struct netconfig *nconf)
{
	int error;

	/*
	 * Save the error code across syslog(), just in case syslog()
	 * gets its own error and, therefore, overwrites errno.
	 */
	error = errno;
	if (t_errno == TSYSERR) {
		syslog(LOG_ERR, "%s(file descriptor %d/transport %s) %m",
		    tli_name, fd, nconf->nc_proto);
	} else {
		syslog(LOG_ERR,
		    "%s(file descriptor %d/transport %s) TLI error %d",
		    tli_name, fd, nconf->nc_proto, t_errno);
	}
	errno = error;
}

/*
 * Called to set up service over a particular transport
 */
void
do_one(char *provider, char *proto, struct protob *protobp0,
	int (*svc)(int, struct netbuf, struct netconfig *))
{
	struct netbuf *retaddr;
	struct netconfig *retnconf;
	struct netbuf addrmask;
	int vers;
	int sock;

	if (provider) {
		sock = bind_to_provider(provider, protobp0->serv, &retaddr,
		    &retnconf);
	} else {
		(void) syslog(LOG_ERR,
	"Cannot establish %s service over %s: transport setup problem.",
		    protobp0->serv, provider ? provider : proto);
		return;
	}

	if (sock == -1) {
		if ((Is_ipv6present() &&
		    (strcmp(provider, "/dev/tcp6") == 0)) ||
		    (!Is_ipv6present() && (strcmp(provider, "/dev/tcp") == 0)))
			(void) syslog(LOG_ERR,
			    "Cannot establish %s service over %s: transport "
			    "setup problem.",
			    protobp0->serv, provider ? provider : proto);
		return;
	}

	if (set_addrmask(sock, retnconf, &addrmask) < 0) {
		(void) syslog(LOG_ERR,
		    "Cannot set address mask for %s", retnconf->nc_netid);
		return;
	}


	/*
	 * Register all versions of the programs in the protocol block list
	 */
	for (vers = protobp0->versmin; vers <= protobp0->versmax; vers++) {
		(void) rpcb_unset(protobp0->program, vers, retnconf);
		(void) rpcb_set(protobp0->program, vers, retnconf, retaddr);
	}

	if (retnconf->nc_semantics == NC_TPI_CLTS) {
		/* Don't drop core if supporting module(s) aren't loaded. */
		(void) signal(SIGSYS, SIG_IGN);

		/*
		 * svc() doesn't block, it returns success or failure.
		 */
		if ((*svc)(sock, addrmask, retnconf) < 0) {
			(void) syslog(LOG_ERR, "Cannot establish %s service "
			    "over <file desc. %d, protocol %s> : %m. Exiting",
			    protobp0->serv, sock, retnconf->nc_proto);
			exit(1);
		}
	}
	/*
	 * We successfully set up the server over this transport.
	 * Add this descriptor to the one being polled on.
	 */
	add_to_poll_list(sock, retnconf);
}

/*
 * Set up the SNDR/ncall-ip service over all the available transports.
 * Returns -1 for failure, 0 for success.
 */
int
do_all(struct protob *protobp,
	int (*svc)(int, struct netbuf, struct netconfig *))
{
	struct netconfig *nconf;
	NCONF_HANDLE *nc;

	if ((nc = setnetconfig()) == (NCONF_HANDLE *)NULL) {
		syslog(LOG_ERR, "setnetconfig failed: %m");
		return (-1);
	}
	while (nconf = getnetconfig(nc)) {
		if ((nconf->nc_flag & NC_VISIBLE) &&
		    strcmp(nconf->nc_protofmly, "loopback") != 0 &&
		    OK_TPI_TYPE(nconf))
			do_one(nconf->nc_device, nconf->nc_proto, protobp, svc);
	}
	(void) endnetconfig(nc);
	return (0);
}

/*
 * Read the /etc/default/sndr configuration file to determine if the
 * client has been configured for number of threads, backlog or transport
 * provider.
 */

static void
read_default(void)
{
	char *defval, *tmp_str;
	int errno;
	int tmp;

	/* Fail silently if error in opening the default rdc config file */
	if ((defopen(RDCADMIN)) == 0) {
		if ((defval = defread("SNDR_THREADS=")) != NULL) {
			errno = 0;
			tmp = strtol(defval, (char **)NULL, 10);
			if (errno == 0) {
				max_conns_allowed = tmp;
			}
		}
		if ((defval = defread("SNDR_LISTEN_BACKLOG=")) != NULL) {
			errno = 0;
			tmp = strtol(defval, (char **)NULL, 10);
			if (errno == 0) {
				listen_backlog = tmp;
			}
		}
		if ((defval = defread("SNDR_TRANSPORT=")) != NULL) {
			errno = 0;
			tmp_str = strdup(defval);
			if (errno == 0) {
				trans_provider = tmp_str;
			}
		}
		/* close defaults file */
		(void) defopen(NULL);
	}
}
#ifdef lint
int
sndrd_lintmain(int ac, char **av)
#else
int
main(int ac, char **av)
#endif
{
	const char *dir = "/";
	int allflag = 0;
	int pid;
	int i, rc;
	struct protob *protobp0, *protobp;
	char **providerp;
	char *required;
#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)
	int maxservers;
#endif

	(void) setlocale(LC_ALL, "");
#ifdef	__NCALL__
	(void) textdomain("ncall");
#else
	(void) textdomain("rdc");
#endif

	progname = basename(av[0]);

#ifdef	__NCALL__
	rc = ncall_check_release(&required);
#else
	rc = rdc_check_release(&required);
#endif
	if (rc < 0) {
		(void) fprintf(stderr,
		    gettext("%s: unable to determine the current "
		    "Solaris release: %s\n"), progname, strerror(errno));
		exit(1);
	} else if (rc == FALSE) {
		(void) fprintf(stderr,
		    gettext("%s: incorrect Solaris release (requires %s)\n"),
		    progname, required);
		exit(1);
	}

	openlog(progname, LOG_PID|LOG_CONS, LOG_DAEMON);
	read_default();

	/*
	 * Usage: <progname> [-c <number of threads>] [-t protocol] \
	 *		[-d] [-l <listen backlog>]
	 */
	while ((i = getopt(ac, av, "ac:t:dl:")) != EOF) {
		switch (i) {
			case 'a':
				allflag = 1;
				break;
			case 'c':
				max_conns_allowed = atoi(optarg);
				if (max_conns_allowed <= 0)
					max_conns_allowed = 16;
				break;

			case 'd':
				debugflg++;
				break;

			case 't':
				trans_provider = optarg;
				break;

			case 'l':
				listen_backlog = atoi(optarg);
				if (listen_backlog < 0)
					listen_backlog = 32;
				break;

			default:
				syslog(LOG_ERR,
				    "Usage: %s [-c <number of threads>] "
				    "[-d] [-t protocol] "
				    "[-l <listen backlog>]\n", progname);
				exit(1);
				break;
		}
	}

	if (chroot(dir) < 0) {
		syslog(LOG_ERR, "chroot failed: %m");
		exit(1);
	}

	if (chdir(dir) < 0) {
		syslog(LOG_ERR, "chdir failed: %m");
		exit(1);
	}

	if (!debugflg) {
		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "Fork failed\n");
			exit(1);
		}
		if (pid != 0)
			exit(0);

		/*
		 * Close existing file descriptors, open "/dev/null" as
		 * standard input, output, and error, and detach from
		 * controlling terminal.
		 */
#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)
		/* use closefrom(3C) from PSARC/2000/193 when possible */
		closefrom(0);
#else
		for (i = 0; i < _NFILE; i++)
			(void) close(i);
#endif
		(void) open("/dev/null", O_RDONLY);
		(void) open("/dev/null", O_WRONLY);
		(void) dup(1);
		(void) setsid();

		/*
		 * ignore all signals apart from SIGTERM.
		 */
		for (i = 1; i < _sys_nsig; i++)
			(void) sigset(i, SIG_IGN);

		(void) sigset(SIGTERM, SIG_DFL);
	}

#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)
	/*
	 * Set up kernel RPC thread pool for the SNDR/ncall-ip server.
	 */
	maxservers = (max_conns_allowed < 0 ? 16 : max_conns_allowed);
	if (sndrsvcpool(maxservers)) {
		(void) syslog(LOG_ERR,
		    "Can't set up kernel %s service: %m. Exiting", progname);
		exit(1);
	}

	/*
	 * Set up blocked thread to do LWP creation on behalf of the kernel.
	 */
	if (svcwait(RDC_SVCPOOL_ID)) {
		(void) syslog(LOG_ERR,
		    "Can't set up %s pool creator: %m, Exiting", progname);
		exit(1);
	}
#endif

	/*
	 * Build a protocol block list for registration.
	 */
	protobp0 = protobp = (struct protob *)malloc(sizeof (struct protob));
	protobp->serv = RDC_SVC_NAME;
	protobp->versmin = RDC_VERS_MIN;
	protobp->versmax = RDC_VERS_MAX;
	protobp->program = RDC_PROGRAM;
	protobp->next = (struct protob *)NULL;

	if (allflag) {
		if (do_all(protobp0, rdcsvc) == -1)
			exit(1);
	} else if (trans_provider)
		do_one(trans_provider, NULL, protobp0, rdcsvc);
	else {
		for (providerp = defaultproviders;
		    *providerp != NULL; providerp++) {
			trans_provider = *providerp;
			do_one(trans_provider, NULL, protobp0, rdcsvc);
		}
	}

done:
	free(protobp);

	end_listen_fds = num_fds;
	/*
	 * Poll for non-data control events on the transport descriptors.
	 */
	poll_for_action();

	syslog(LOG_ERR, "%s fatal server error\n", progname);

	return (-1);
}

static int
reuseaddr(int fd)
{
	struct t_optmgmt req, resp;
	struct opthdr *opt;
	char reqbuf[128];
	int *ip;

	/* LINTED pointer alignment */
	opt = (struct opthdr *)reqbuf;
	opt->level = SOL_SOCKET;
	opt->name = SO_REUSEADDR;
	opt->len = sizeof (int);

	/* LINTED pointer alignment */
	ip = (int *)&reqbuf[sizeof (struct opthdr)];
	*ip = 1;

	req.flags = T_NEGOTIATE;
	req.opt.len = sizeof (struct opthdr) + opt->len;
	req.opt.buf = (char *)opt;

	resp.flags = 0;
	resp.opt.buf = reqbuf;
	resp.opt.maxlen = sizeof (reqbuf);

	if (t_optmgmt(fd, &req, &resp) < 0 || resp.flags != T_SUCCESS) {
		if (t_errno == TSYSERR) {
			syslog(LOG_ERR, "reuseaddr() t_optmgmt failed: %m\n");
		} else {
			syslog(LOG_ERR, "reuseaddr() t_optmgmt failed: %s\n",
			    t_errlist[t_errno]);
		}
		return (-1);
	}
	return (0);
}

/*
 * poll on the open transport descriptors for events and errors.
 */
void
poll_for_action(void)
{
	int nfds;
	int i;

	/*
	 * Keep polling until all transports have been closed. When this
	 * happens, we return.
	 */
	while ((int)num_fds > 0) {
		nfds = poll(poll_array, num_fds, INFTIM);
		switch (nfds) {
		case 0:
			continue;

		case -1:
			/*
			 * Some errors from poll could be
			 * due to temporary conditions, and we try to
			 * be robust in the face of them. Other
			 * errors (should never happen in theory)
			 * are fatal (eg. EINVAL, EFAULT).
			 */
			switch (errno) {
			case EINTR:
				continue;

			case EAGAIN:
			case ENOMEM:
				(void) sleep(10);
				continue;

			default:
				(void) syslog(LOG_ERR,
				    "poll failed: %m. Exiting");
				exit(1);
			}
		default:
			break;
		}

		/*
		 * Go through the poll list looking for events.
		 */
		for (i = 0; i < num_fds && nfds > 0; i++) {
			if (poll_array[i].revents) {
				nfds--;
				/*
				 * We have a message, so try to read it.
				 * Record the error return in errno,
				 * so that syslog(LOG_ERR, "...%m")
				 * dumps the corresponding error string.
				 */
				if (conn_polled[i].nc.nc_semantics ==
				    NC_TPI_CLTS) {
					errno = do_poll_clts_action(
					    poll_array[i].fd, i);
				} else {
					errno = do_poll_cots_action(
					    poll_array[i].fd, i);
				}

				if (errno == 0)
					continue;
				/*
				 * Most returned error codes mean that there is
				 * fatal condition which we can only deal with
				 * by closing the transport.
				 */
				if (errno != EAGAIN && errno != ENOMEM) {
					(void) syslog(LOG_ERR,
					    "Error (%m) reading descriptor %d"
					    "/transport %s. Closing it.",
					    poll_array[i].fd,
					    conn_polled[i].nc.nc_proto);
					(void) t_close(poll_array[i].fd);
					remove_from_poll_list(poll_array[i].fd);
				} else if (errno == ENOMEM)
					(void) sleep(5);
			}
		}
	}

	(void) syslog(LOG_ERR,
	    "All transports have been closed with errors. Exiting.");
}

/*
 * Allocate poll/transport array entries for this descriptor.
 */
static void
add_to_poll_list(int fd, struct netconfig *nconf)
{
	static int poll_array_size = 0;

	/*
	 * If the arrays are full, allocate new ones.
	 */
	if (num_fds == poll_array_size) {
		struct pollfd *tpa;
		struct conn_entry *tnp;

		if (poll_array_size != 0) {
			tpa = poll_array;
			tnp = conn_polled;
		} else
			tpa = (struct pollfd *)0;

		poll_array_size += POLL_ARRAY_INC_SIZE;

		/*
		 * Allocate new arrays.
		 */
		poll_array = (struct pollfd *)
		    malloc(poll_array_size * sizeof (struct pollfd) + 256);
		conn_polled = (struct conn_entry *)
		    malloc(poll_array_size * sizeof (struct conn_entry) + 256);
		if (poll_array == (struct pollfd *)NULL ||
		    conn_polled == (struct conn_entry *)NULL) {
			syslog(LOG_ERR, "malloc failed for poll array");
			exit(1);
		}

		/*
		 * Copy the data of the old ones into new arrays, and
		 * free the old ones.
		 * num_fds is guaranteed to be less than
		 * poll_array_size, so this memcpy is safe.
		 */
		if (tpa) {
			(void) memcpy((void *)poll_array, (void *)tpa,
			    num_fds * sizeof (struct pollfd));
			(void) memcpy((void *)conn_polled, (void *)tnp,
			    num_fds * sizeof (struct conn_entry));
			free((void *)tpa);
			free((void *)tnp);
		}
	}

	/*
	 * Set the descriptor and event list. All possible events are
	 * polled for.
	 */
	poll_array[num_fds].fd = fd;
	poll_array[num_fds].events = POLLIN|POLLRDNORM|POLLRDBAND|POLLPRI;

	/*
	 * Copy the transport data over too.
	 */
	conn_polled[num_fds].nc = *nconf;	/* structure copy */
	conn_polled[num_fds].closing = 0;

	/*
	 * Set the descriptor to non-blocking. Avoids a race
	 * between data arriving on the stream and then having it
	 * flushed before we can read it.
	 */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		(void) syslog(LOG_ERR,
		    "fcntl(file desc. %d/transport %s, F_SETFL, "
		    "O_NONBLOCK): %m. Exiting",
		    num_fds, nconf->nc_proto);
		exit(1);
	}

	/*
	 * Count this descriptor.
	 */
	++num_fds;
}

static void
remove_from_poll_list(int fd)
{
	int i;
	int num_to_copy;

	for (i = 0; i < num_fds; i++) {
		if (poll_array[i].fd == fd) {
			--num_fds;
			num_to_copy = num_fds - i;
			(void) memcpy((void *)&poll_array[i],
			    (void *)&poll_array[i+1],
			    num_to_copy * sizeof (struct pollfd));
			(void) memset((void *)&poll_array[num_fds], 0,
			    sizeof (struct pollfd));
			(void) memcpy((void *)&conn_polled[i],
			    (void *)&conn_polled[i+1],
			    num_to_copy * sizeof (struct conn_entry));
			(void) memset((void *)&conn_polled[num_fds], 0,
			    sizeof (struct conn_entry));
			return;
		}
	}
	syslog(LOG_ERR, "attempt to remove nonexistent fd from poll list");

}

static void
conn_close_oldest(void)
{
	int fd;
	int i1;

	/*
	 * Find the oldest connection that is not already in the
	 * process of shutting down.
	 */
	for (i1 = end_listen_fds; /* no conditional expression */; i1++) {
		if (i1 >= num_fds)
			return;
		if (conn_polled[i1].closing == 0)
			break;
	}
#ifdef DEBUG
	(void) printf("too many connections (%d), releasing oldest (%d)\n",
	    num_conns, poll_array[i1].fd);
#else
	syslog(LOG_WARNING, "too many connections (%d), releasing oldest (%d)",
	    num_conns, poll_array[i1].fd);
#endif
	fd = poll_array[i1].fd;
	if (conn_polled[i1].nc.nc_semantics == NC_TPI_COTS) {
		/*
		 * For politeness, send a T_DISCON_REQ to the transport
		 * provider.  We close the stream anyway.
		 */
		(void) t_snddis(fd, (struct t_call *)0);
		num_conns--;
		remove_from_poll_list(fd);
		(void) t_close(fd);
	} else {
		/*
		 * For orderly release, we do not close the stream
		 * until the T_ORDREL_IND arrives to complete
		 * the handshake.
		 */
		if (t_sndrel(fd) == 0)
			conn_polled[i1].closing = 1;
	}
}

static boolean_t
conn_get(int fd, struct netconfig *nconf, struct conn_ind **connp)
{
	struct conn_ind	*conn;
	struct conn_ind	*next_conn;

	conn = (struct conn_ind *)malloc(sizeof (*conn));
	if (conn == NULL) {
		syslog(LOG_ERR, "malloc for listen indication failed");
		return (FALSE);
	}

	/* LINTED pointer alignment */
	conn->conn_call = (struct t_call *)t_alloc(fd, T_CALL, T_ALL);
	if (conn->conn_call == NULL) {
		free((char *)conn);
		rdcd_log_tli_error("t_alloc", fd, nconf);
		return (FALSE);
	}

	if (t_listen(fd, conn->conn_call) == -1) {
		rdcd_log_tli_error("t_listen", fd, nconf);
		(void) t_free((char *)conn->conn_call, T_CALL);
		free((char *)conn);
		return (FALSE);
	}

	if (conn->conn_call->udata.len > 0) {
		syslog(LOG_WARNING,
		    "rejecting inbound connection(%s) with %d bytes "
		    "of connect data",
		    nconf->nc_proto, conn->conn_call->udata.len);

		conn->conn_call->udata.len = 0;
		(void) t_snddis(fd, conn->conn_call);
		(void) t_free((char *)conn->conn_call, T_CALL);
		free((char *)conn);
		return (FALSE);
	}

	if ((next_conn = *connp) != NULL) {
		next_conn->conn_prev->conn_next = conn;
		conn->conn_next = next_conn;
		conn->conn_prev = next_conn->conn_prev;
		next_conn->conn_prev = conn;
	} else {
		conn->conn_next = conn;
		conn->conn_prev = conn;
		*connp = conn;
	}
	return (TRUE);
}

static int
discon_get(int fd, struct netconfig *nconf, struct conn_ind **connp)
{
	struct conn_ind	*conn;
	struct t_discon	discon;

	discon.udata.buf = (char *)0;
	discon.udata.maxlen = 0;
	if (t_rcvdis(fd, &discon) == -1) {
		rdcd_log_tli_error("t_rcvdis", fd, nconf);
		return (-1);
	}

	conn = *connp;
	if (conn == NULL)
		return (0);

	do {
		if (conn->conn_call->sequence == discon.sequence) {
			if (conn->conn_next == conn)
				*connp = (struct conn_ind *)0;
			else {
				if (conn == *connp) {
					*connp = conn->conn_next;
				}
				conn->conn_next->conn_prev = conn->conn_prev;
				conn->conn_prev->conn_next = conn->conn_next;
			}
			free((char *)conn);
			break;
		}
		conn = conn->conn_next;
	} while (conn != *connp);

	return (0);
}

static void
cots_listen_event(int fd, int conn_index)
{
	struct t_call *call;
	struct conn_ind	*conn;
	struct conn_ind	*conn_head;
	int event;
	struct netconfig *nconf = &conn_polled[conn_index].nc;
	int new_fd;
	struct netbuf addrmask;
	int ret = 0;

	conn_head = NULL;
	(void) conn_get(fd, nconf, &conn_head);

	while ((conn = conn_head) != NULL) {
		conn_head = conn->conn_next;
		if (conn_head == conn)
			conn_head = NULL;
		else {
			conn_head->conn_prev = conn->conn_prev;
			conn->conn_prev->conn_next = conn_head;
		}
		call = conn->conn_call;
		free(conn);

		/*
		 * If we have already accepted the maximum number of
		 * connections allowed on the command line, then drop
		 * the oldest connection (for any protocol) before
		 * accepting the new connection.  Unless explicitly
		 * set on the command line, max_conns_allowed is -1.
		 */
		if (max_conns_allowed != -1 && num_conns >= max_conns_allowed)
			conn_close_oldest();

		/*
		 * Create a new transport endpoint for the same proto as
		 * the listener.
		 */
		new_fd = rdc_transport_open(nconf);
		if (new_fd == -1) {
			call->udata.len = 0;
			(void) t_snddis(fd, call);
			(void) t_free((char *)call, T_CALL);
			syslog(LOG_ERR, "Cannot establish transport over %s",
			    nconf->nc_device);
			continue;
		}

		/* Bind to a generic address/port for the accepting stream. */
		if (t_bind(new_fd, NULL, NULL) == -1) {
			rdcd_log_tli_error("t_bind", new_fd, nconf);
			call->udata.len = 0;
			(void) t_snddis(fd, call);
			(void) t_free((char *)call, T_CALL);
			(void) t_close(new_fd);
			continue;
		}

		while (t_accept(fd, new_fd, call) == -1) {
			if (t_errno != TLOOK) {
				rdcd_log_tli_error("t_accept", fd, nconf);
				call->udata.len = 0;
				(void) t_snddis(fd, call);
				(void) t_free((char *)call, T_CALL);
				(void) t_close(new_fd);
				goto do_next_conn;
			}
			while (event = t_look(fd)) {
				switch (event) {
				case T_LISTEN:
					(void) conn_get(fd, nconf, &conn_head);
					continue;

				case T_DISCONNECT:
					(void) discon_get(fd, nconf,
					    &conn_head);
					continue;

				default:
					syslog(LOG_ERR,
					    "unexpected event 0x%x during "
					    "accept processing (%s)",
					    event, nconf->nc_proto);
					call->udata.len = 0;
					(void) t_snddis(fd, call);
					(void) t_free((char *)call, T_CALL);
					(void) t_close(new_fd);
					goto do_next_conn;
				}
			}
		}

		if (set_addrmask(new_fd, nconf, &addrmask) < 0) {
			(void) syslog(LOG_ERR, "Cannot set address mask for %s",
			    nconf->nc_netid);
			(void) t_snddis(new_fd, NULL);
			(void) t_free((char *)call, T_CALL);
			(void) t_close(new_fd);
			continue;
		}

		/* Tell kRPC about the new stream. */
		ret = (*Mysvc)(new_fd, addrmask, nconf);
		if (ret < 0) {
			syslog(LOG_ERR,
			    "unable to register with kernel rpc: %m");
			free(addrmask.buf);
			(void) t_snddis(new_fd, NULL);
			(void) t_free((char *)call, T_CALL);
			(void) t_close(new_fd);
			goto do_next_conn;
		}

		free(addrmask.buf);
		(void) t_free((char *)call, T_CALL);

		/*
		 * Poll on the new descriptor so that we get disconnect
		 * and orderly release indications.
		 */
		num_conns++;
		add_to_poll_list(new_fd, nconf);

		/* Reset nconf in case it has been moved. */
		nconf = &conn_polled[conn_index].nc;
do_next_conn:;
	}
}

static int
do_poll_cots_action(int fd, int conn_index)
{
	char buf[256];
	int event;
	int i1;
	int flags;
	struct conn_entry *connent = &conn_polled[conn_index];
	struct netconfig *nconf = &(connent->nc);
	const char *errorstr;

	while (event = t_look(fd)) {
		switch (event) {
		case T_LISTEN:
			cots_listen_event(fd, conn_index);
			break;

		case T_DATA:
			/*
			 * Receive a private notification from CONS rpcmod.
			 */
			i1 = t_rcv(fd, buf, sizeof (buf), &flags);
			if (i1 == -1) {
				syslog(LOG_ERR, "t_rcv failed");
				break;
			}
			if (i1 < sizeof (int))
				break;
			i1 = BE32_TO_U32(buf);
			if (i1 == 1 || i1 == 2) {
				/*
				 * This connection has been idle for too long,
				 * so release it as politely as we can.  If we
				 * have already initiated an orderly release
				 * and we get notified that the stream is
				 * still idle, pull the plug.  This prevents
				 * hung connections from continuing to consume
				 * resources.
				 */
				if (nconf->nc_semantics == NC_TPI_COTS ||
				    connent->closing != 0) {
					(void) t_snddis(fd, (struct t_call *)0);
					goto fdclose;
				}
				/*
				 * For NC_TPI_COTS_ORD, the stream is closed
				 * and removed from the poll list when the
				 * T_ORDREL is received from the provider.  We
				 * don't wait for it here because it may take
				 * a while for the transport to shut down.
				 */
				if (t_sndrel(fd) == -1) {
					syslog(LOG_ERR,
					"unable to send orderly release %m");
				}
				connent->closing = 1;
			} else
				syslog(LOG_ERR,
				    "unexpected event from CONS rpcmod %d", i1);
			break;

		case T_ORDREL:
			/* Perform an orderly release. */
			if (t_rcvrel(fd) == 0) {
				/* T_ORDREL on listen fd's should be ignored */
				if (!is_listen_fd_index(fd)) {
					(void) t_sndrel(fd);
					goto fdclose;
				}
				break;

			} else if (t_errno == TLOOK) {
				break;
			} else {
				rdcd_log_tli_error("t_rcvrel", fd, nconf);
				/*
				 * check to make sure we do not close
				 * listen fd
				 */
				if (!is_listen_fd_index(fd))
					break;
				else
					goto fdclose;
			}

		case T_DISCONNECT:
			if (t_rcvdis(fd, (struct t_discon *)NULL) == -1)
				rdcd_log_tli_error("t_rcvdis", fd, nconf);

			/*
			 * T_DISCONNECT on listen fd's should be ignored.
			 */
			if (!is_listen_fd_index(fd))
				break;
			else
				goto fdclose;

		default:
			if (t_errno == TSYSERR) {
				if ((errorstr = strerror(errno)) == NULL) {
					(void) snprintf(buf, sizeof (buf),
					    "Unknown error num %d", errno);
					errorstr = (const char *)buf;
				}
			} else if (event == -1)
				errorstr = t_strerror(t_errno);
			else
				errorstr = "";
#ifdef DEBUG
			syslog(LOG_ERR,
			    "unexpected TLI event (0x%x) on "
			    "connection-oriented transport(%s, %d):%s",
			    event, nconf->nc_proto, fd, errorstr);
#endif

fdclose:
			num_conns--;
			remove_from_poll_list(fd);
			(void) t_close(fd);
			return (0);
		}
	}

	return (0);
}


/*
 * Called to read and interpret the event on a connectionless descriptor.
 * Returns 0 if successful, or a UNIX error code if failure.
 */
static int
do_poll_clts_action(int fd, int conn_index)
{
	int error;
	int ret;
	int flags;
	struct netconfig *nconf = &conn_polled[conn_index].nc;
	static struct t_unitdata *unitdata = NULL;
	static struct t_uderr *uderr = NULL;
	static int oldfd = -1;
	struct nd_hostservlist *host = NULL;
	struct strbuf ctl[1], data[1];
	/*
	 * We just need to have some space to consume the
	 * message in the event we can't use the TLI interface to do the
	 * job.
	 *
	 * We flush the message using getmsg(). For the control part
	 * we allocate enough for any TPI header plus 32 bytes for address
	 * and options. For the data part, there is nothing magic about
	 * the size of the array, but 256 bytes is probably better than
	 * 1 byte, and we don't expect any data portion anyway.
	 *
	 * If the array sizes are too small, we handle this because getmsg()
	 * (called to consume the message) will return MOREDATA|MORECTL.
	 * Thus we just call getmsg() until it's read the message.
	 */
	char ctlbuf[sizeof (union T_primitives) + 32];
	char databuf[256];

	/*
	 * If this is the same descriptor as the last time
	 * do_poll_clts_action was called, we can save some
	 * de-allocation and allocation.
	 */
	if (oldfd != fd) {
		oldfd = fd;

		if (unitdata) {
			(void) t_free((char *)unitdata, T_UNITDATA);
			unitdata = NULL;
		}
		if (uderr) {
			(void) t_free((char *)uderr, T_UDERROR);
			uderr = NULL;
		}
	}

	/*
	 * Allocate a unitdata structure for receiving the event.
	 */
	if (unitdata == NULL) {
		/* LINTED pointer alignment */
		unitdata = (struct t_unitdata *)t_alloc(fd, T_UNITDATA, T_ALL);
		if (unitdata == NULL) {
			if (t_errno == TSYSERR) {
				/*
				 * Save the error code across
				 * syslog(), just in case
				 * syslog() gets its own error
				 * and therefore overwrites errno.
				 */
				error = errno;
				(void) syslog(LOG_ERR,
				    "t_alloc(file descriptor %d/transport %s, "
				    "T_UNITDATA) failed: %m",
				    fd, nconf->nc_proto);
				return (error);
			}
			(void) syslog(LOG_ERR, "t_alloc(file descriptor %d/"
			    "transport %s, T_UNITDATA) failed TLI error %d",
			    fd, nconf->nc_proto, t_errno);
			goto flush_it;
		}
	}

try_again:
	flags = 0;

	/*
	 * The idea is we wait for T_UNITDATA_IND's. Of course,
	 * we don't get any, because rpcmod filters them out.
	 * However, we need to call t_rcvudata() to let TLI
	 * tell us we have a T_UDERROR_IND.
	 *
	 * algorithm is:
	 * 	t_rcvudata(), expecting TLOOK.
	 * 	t_look(), expecting T_UDERR.
	 * 	t_rcvuderr(), expecting success (0).
	 * 	expand destination address into ASCII,
	 *	and dump it.
	 */

	ret = t_rcvudata(fd, unitdata, &flags);
	if (ret == 0 || t_errno == TBUFOVFLW) {
		(void) syslog(LOG_WARNING, "t_rcvudata(file descriptor %d/"
		    "transport %s) got unexpected data, %d bytes",
		    fd, nconf->nc_proto, unitdata->udata.len);

		/*
		 * Even though we don't expect any data, in case we do,
		 * keep reading until there is no more.
		 */
		if (flags & T_MORE)
			goto try_again;

		return (0);
	}

	switch (t_errno) {
	case TNODATA:
		return (0);
	case TSYSERR:
		/*
		 * System errors are returned to caller.
		 * Save the error code across
		 * syslog(), just in case
		 * syslog() gets its own error
		 * and therefore overwrites errno.
		 */
		error = errno;
		(void) syslog(LOG_ERR,
		    "t_rcvudata(file descriptor %d/transport %s) %m",
		    fd, nconf->nc_proto);
		return (error);
	case TLOOK:
		break;
	default:
		(void) syslog(LOG_ERR,
		    "t_rcvudata(file descriptor %d/transport %s) TLI error %d",
		    fd, nconf->nc_proto, t_errno);
		goto flush_it;
	}

	ret = t_look(fd);
	switch (ret) {
	case 0:
		return (0);
	case -1:
		/*
		 * System errors are returned to caller.
		 */
		if (t_errno == TSYSERR) {
			/*
			 * Save the error code across
			 * syslog(), just in case
			 * syslog() gets its own error
			 * and therefore overwrites errno.
			 */
			error = errno;
			(void) syslog(LOG_ERR,
			    "t_look(file descriptor %d/transport %s) %m",
			    fd, nconf->nc_proto);
			return (error);
		}
		(void) syslog(LOG_ERR,
		    "t_look(file descriptor %d/transport %s) TLI error %d",
		    fd, nconf->nc_proto, t_errno);
		goto flush_it;
	case T_UDERR:
		break;
	default:
		(void) syslog(LOG_WARNING, "t_look(file descriptor %d/"
		    "transport %s) returned %d not T_UDERR (%d)",
		    fd, nconf->nc_proto, ret, T_UDERR);
	}

	if (uderr == NULL) {
		/* LINTED pointer alignment */
		uderr = (struct t_uderr *)t_alloc(fd, T_UDERROR, T_ALL);
		if (uderr == NULL) {
			if (t_errno == TSYSERR) {
				/*
				 * Save the error code across
				 * syslog(), just in case
				 * syslog() gets its own error
				 * and therefore overwrites errno.
				 */
				error = errno;
				(void) syslog(LOG_ERR,
				    "t_alloc(file descriptor %d/transport %s, "
				    "T_UDERROR) failed: %m",
				    fd, nconf->nc_proto);
				return (error);
			}
			(void) syslog(LOG_ERR, "t_alloc(file descriptor %d/"
			    "transport %s, T_UDERROR) failed TLI error: %d",
			    fd, nconf->nc_proto, t_errno);
			goto flush_it;
		}
	}

	ret = t_rcvuderr(fd, uderr);
	if (ret == 0) {

		/*
		 * Save the datagram error in errno, so that the
		 * %m argument to syslog picks up the error string.
		 */
		errno = uderr->error;

		/*
		 * Log the datagram error, then log the host that
		 * probably triggerred. Cannot log both in the
		 * same transaction because of packet size limitations
		 * in /dev/log.
		 */
		(void) syslog((errno == ECONNREFUSED) ? LOG_DEBUG : LOG_WARNING,
		    "%s response over <file descriptor %d/transport %s> "
		    "generated error: %m",
		    progname, fd, nconf->nc_proto);

		/*
		 * Try to map the client's address back to a
		 * name.
		 */
		ret = netdir_getbyaddr(nconf, &host, &uderr->addr);
		if (ret != -1 && host && host->h_cnt > 0 &&
		    host->h_hostservs) {
		(void) syslog((errno == ECONNREFUSED) ? LOG_DEBUG : LOG_WARNING,
		    "Bad %s response was sent to client with "
		    "host name: %s; service port: %s",
		    progname, host->h_hostservs->h_host,
		    host->h_hostservs->h_serv);
		} else {
			int i, j;
			char *buf;
			char *hex = "0123456789abcdef";

			/*
			 * Mapping failed, print the whole thing
			 * in ASCII hex.
			 */
			buf = (char *)malloc(uderr->addr.len * 2 + 1);
			for (i = 0, j = 0; i < uderr->addr.len; i++, j += 2) {
				buf[j] = hex[((uderr->addr.buf[i]) >> 4) & 0xf];
				buf[j+1] = hex[uderr->addr.buf[i] & 0xf];
			}
			buf[j] = '\0';
			(void) syslog((errno == ECONNREFUSED) ?
			    LOG_DEBUG : LOG_WARNING,
			    "Bad %s response was sent to client with "
			    "transport address: 0x%s",
			    progname, buf);
			free((void *)buf);
		}

		if (ret == 0 && host != NULL)
			netdir_free((void *)host, ND_HOSTSERVLIST);
		return (0);
	}

	switch (t_errno) {
	case TNOUDERR:
		goto flush_it;
	case TSYSERR:
		/*
		 * System errors are returned to caller.
		 * Save the error code across
		 * syslog(), just in case
		 * syslog() gets its own error
		 * and therefore overwrites errno.
		 */
		error = errno;
		(void) syslog(LOG_ERR,
		    "t_rcvuderr(file descriptor %d/transport %s) %m",
		    fd, nconf->nc_proto);
		return (error);
	default:
		(void) syslog(LOG_ERR,
		    "t_rcvuderr(file descriptor %d/transport %s) TLI error %d",
		    fd, nconf->nc_proto, t_errno);
		goto flush_it;
	}

flush_it:
	/*
	 * If we get here, then we could not cope with whatever message
	 * we attempted to read, so flush it. If we did read a message,
	 * and one isn't present, that is all right, because fd is in
	 * nonblocking mode.
	 */
	(void) syslog(LOG_ERR,
	    "Flushing one input message from <file descriptor %d/transport %s>",
	    fd, nconf->nc_proto);

	/*
	 * Read and discard the message. Do this this until there is
	 * no more control/data in the message or until we get an error.
	 */
	do {
		ctl->maxlen = sizeof (ctlbuf);
		ctl->buf = ctlbuf;
		data->maxlen = sizeof (databuf);
		data->buf = databuf;
		flags = 0;
		ret = getmsg(fd, ctl, data, &flags);
		if (ret == -1)
			return (errno);
	} while (ret != 0);

	return (0);
}

/*
 * Establish service thread.
 */
static int
rdcsvc(int fd, struct netbuf addrmask, struct netconfig *nconf)
{
#ifdef	__NCALL__
	struct ncall_svc_args nsa;
#else	/* !__NCALL__ */
	struct rdc_svc_args nsa;
	_rdc_ioctl_t rdc_args = { 0, };
#endif	/* __NCALL__ */

	nsa.fd = fd;
	nsa.nthr = (max_conns_allowed < 0 ? 16 : max_conns_allowed);
	(void) strncpy(nsa.netid, nconf->nc_netid, sizeof (nsa.netid));
	nsa.addrmask.len = addrmask.len;
	nsa.addrmask.maxlen = addrmask.maxlen;
	nsa.addrmask.buf = addrmask.buf;

#ifdef	__NCALL__
	return (sndrsys(NC_IOC_SERVER, &nsa));
#else	/* !__NCALL__ */
	rdc_args.arg0 = (long)&nsa;
	return (sndrsys(RDC_ENABLE_SVR, &rdc_args));
#endif	/* __NCALL__ */
}



static int
nofile_increase(int limit)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
		syslog(LOG_ERR,
		    "nofile_increase() getrlimit of NOFILE failed: %m");
		return (-1);
	}

	if (limit > 0)
		rl.rlim_cur = limit;
	else
		rl.rlim_cur += NOFILE_INC_SIZE;

	if (rl.rlim_cur > rl.rlim_max && rl.rlim_max != RLIM_INFINITY)
		rl.rlim_max = rl.rlim_cur;

	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		syslog(LOG_ERR,
		    "nofile_increase() setrlimit of NOFILE to %d failed: %m",
		    rl.rlim_cur);
		return (-1);
	}

	return (0);
}

int
rdcd_bindit(struct netconfig *nconf, struct netbuf **addr,
    struct nd_hostserv *hs, int backlog)
{
	int fd;
	struct t_bind *ntb;
	struct t_bind tb;
	struct nd_addrlist *addrlist;
	struct t_optmgmt req, resp;
	struct opthdr *opt;
	char reqbuf[128];

	if ((fd = rdc_transport_open(nconf)) == -1) {
		syslog(LOG_ERR, "cannot establish transport service over %s",
		    nconf->nc_device);
		return (-1);
	}

	addrlist = (struct nd_addrlist *)NULL;
	if (netdir_getbyname(nconf, hs, &addrlist) != 0) {
		if (strncmp(nconf->nc_netid, "udp", 3) != 0) {
			syslog(LOG_ERR, "Cannot get address for transport "
			    "%s host %s service %s",
			    nconf->nc_netid, hs->h_host, hs->h_serv);
		}
		(void) t_close(fd);
		return (-1);
	}

	if (strcmp(nconf->nc_proto, "tcp") == 0) {
		/*
		 * If we're running over TCP, then set the
		 * SO_REUSEADDR option so that we can bind
		 * to our preferred address even if previously
		 * left connections exist in FIN_WAIT states.
		 * This is somewhat bogus, but otherwise you have
		 * to wait 2 minutes to restart after killing it.
		 */
		if (reuseaddr(fd) == -1) {
			syslog(LOG_WARNING,
			    "couldn't set SO_REUSEADDR option on transport");
		}
	}

	if (nconf->nc_semantics == NC_TPI_CLTS)
		tb.qlen = 0;
	else
		tb.qlen = backlog;

	/* LINTED pointer alignment */
	ntb = (struct t_bind *)t_alloc(fd, T_BIND, T_ALL);
	if (ntb == (struct t_bind *)NULL) {
		syslog(LOG_ERR, "t_alloc failed:  t_errno %d, %m", t_errno);
		(void) t_close(fd);
		netdir_free((void *)addrlist, ND_ADDRLIST);
		return (-1);
	}

	tb.addr = *(addrlist->n_addrs);		/* structure copy */

	if (t_bind(fd, &tb, ntb) == -1) {
		syslog(LOG_ERR, "t_bind failed:  t_errno %d, %m", t_errno);
		(void) t_free((char *)ntb, T_BIND);
		netdir_free((void *)addrlist, ND_ADDRLIST);
		(void) t_close(fd);
		return (-1);
	}

	/* make sure we bound to the right address */
	if (tb.addr.len != ntb->addr.len ||
	    memcmp(tb.addr.buf, ntb->addr.buf, tb.addr.len) != 0) {
		syslog(LOG_ERR, "t_bind to wrong address");
		(void) t_free((char *)ntb, T_BIND);
		netdir_free((void *)addrlist, ND_ADDRLIST);
		(void) t_close(fd);
		return (-1);
	}

	*addr = &ntb->addr;
	netdir_free((void *)addrlist, ND_ADDRLIST);

	if (strcmp(nconf->nc_proto, "tcp") == 0 ||
	    strcmp(nconf->nc_proto, "tcp6") == 0) {
		/*
		 * Disable the Nagle algorithm on TCP connections.
		 * Connections accepted from this listener will
		 * inherit the listener options.
		 */

		/* LINTED pointer alignment */
		opt = (struct opthdr *)reqbuf;
		opt->level = IPPROTO_TCP;
		opt->name = TCP_NODELAY;
		opt->len = sizeof (int);

		/* LINTED pointer alignment */
		*(int *)((char *)opt + sizeof (*opt)) = 1;

		req.flags = T_NEGOTIATE;
		req.opt.len = sizeof (*opt) + opt->len;
		req.opt.buf = (char *)opt;
		resp.flags = 0;
		resp.opt.buf = reqbuf;
		resp.opt.maxlen = sizeof (reqbuf);

		if (t_optmgmt(fd, &req, &resp) < 0 ||
		    resp.flags != T_SUCCESS) {
			syslog(LOG_ERR, "couldn't set NODELAY option for "
			    "proto %s: t_errno = %d, %m", nconf->nc_proto,
			    t_errno);
		}
	}

	return (fd);
}


/* ARGSUSED */
static int
bind_to_provider(char *provider, char *serv, struct netbuf **addr,
		struct netconfig **retnconf)
{
	struct netconfig *nconf;
	NCONF_HANDLE *nc;
	struct nd_hostserv hs;

	hs.h_host = HOST_SELF;
	hs.h_serv = RDC_SERVICE;	/* serv_name_to_port_name(serv); */

	if ((nc = setnetconfig()) == (NCONF_HANDLE *)NULL) {
		syslog(LOG_ERR, "setnetconfig failed: %m");
		return (-1);
	}
	while (nconf = getnetconfig(nc)) {
		if (OK_TPI_TYPE(nconf) &&
		    strcmp(nconf->nc_device, provider) == 0) {
			*retnconf = nconf;
			return (rdcd_bindit(nconf, addr, &hs, listen_backlog));
		}
	}
	(void) endnetconfig(nc);
	if ((Is_ipv6present() && (strcmp(provider, "/dev/tcp6") == 0)) ||
	    (!Is_ipv6present() && (strcmp(provider, "/dev/tcp") == 0)))
		syslog(LOG_ERR, "couldn't find netconfig entry for provider %s",
		    provider);
	return (-1);
}


/*
 * For listen fd's index is always less than end_listen_fds.
 * It's value is equal to the number of open file descriptors after the
 * last listen end point was opened but before any connection was accepted.
 */
static int
is_listen_fd_index(int index)
{
	return (index < end_listen_fds);
}


/*
 * Create an address mask appropriate for the transport.
 * The mask is used to obtain the host-specific part of
 * a network address when comparing addresses.
 * For an internet address the host-specific part is just
 * the 32 bit IP address and this part of the mask is set
 * to all-ones. The port number part of the mask is zeroes.
 */
static int
set_addrmask(int fd, struct netconfig *nconf, struct netbuf *mask)
{
	struct t_info info;

	/*
	 * Find the size of the address we need to mask.
	 */
	if (t_getinfo(fd, &info) < 0) {
		t_error("t_getinfo");
		return (-1);
	}
	mask->len = mask->maxlen = info.addr;
	if (info.addr <= 0) {
		syslog(LOG_ERR, "set_addrmask: address size: %ld", info.addr);
		return (-1);
	}

	mask->buf = (char *)malloc(mask->len);
	if (mask->buf == NULL) {
		syslog(LOG_ERR, "set_addrmask: no memory");
		return (-1);
	}
	(void) memset(mask->buf, 0, mask->len);	/* reset all mask bits */

	if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
		/*
		 * Set the mask so that the port is ignored.
		 */
		/* LINTED pointer alignment */
		((struct sockaddr_in *)mask->buf)->sin_addr.s_addr =
		    (in_addr_t)~0;
		/* LINTED pointer alignment */
		((struct sockaddr_in *)mask->buf)->sin_family = (sa_family_t)~0;
	}
#ifdef NC_INET6
	else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
		/* LINTED pointer alignment */
		(void) memset(&((struct sockaddr_in6 *)mask->buf)->sin6_addr,
		    (uchar_t)~0, sizeof (struct in6_addr));
		/* LINTED pointer alignment */
		((struct sockaddr_in6 *)mask->buf)->sin6_family =
		    (sa_family_t)~0;
	}
#endif
	else {
		/*
		 * Set all mask bits.
		 */
		(void) memset(mask->buf, (uchar_t)~0, mask->len);
	}
	return (0);
}

#if !defined(_SunOS_5_6) && !defined(_SunOS_5_7) && !defined(_SunOS_5_8)

static int
sndrsvcpool(int maxservers)
{
	struct svcpool_args npa;

	npa.id = RDC_SVCPOOL_ID;
	npa.maxthreads = maxservers;
	npa.redline = 0;
	npa.qsize = 0;
	npa.timeout = 0;
	npa.stksize = 0;
	npa.max_same_xprt = 0;
	return (sndrsys(RDC_POOL_CREATE, &npa));
}


/*
 * The following stolen from cmd/fs.d/nfs/lib/thrpool.c
 */

#include <thread.h>

/*
 * Thread to call into the kernel and do work on behalf of SNDR/ncall-ip.
 */
static void *
svcstart(void *arg)
{
	int id = (int)arg;
	int err;

	while ((err = sndrsys(RDC_POOL_RUN, &id)) != 0) {
		/*
		 * Interrupted by a signal while in the kernel.
		 * this process is still alive, try again.
		 */
		if (err == EINTR)
			continue;
		else
			break;
	}

	/*
	 * If we weren't interrupted by a signal, but did
	 * return from the kernel, this thread's work is done,
	 * and it should exit.
	 */
	thr_exit(NULL);
	return (NULL);
}

/*
 * User-space "creator" thread. This thread blocks in the kernel
 * until new worker threads need to be created for the service
 * pool. On return to userspace, if there is no error, create a
 * new thread for the service pool.
 */
static void *
svcblock(void *arg)
{
	int id = (int)arg;

	/* CONSTCOND */
	while (1) {
		thread_t tid;
		int err;

		/*
		 * Call into the kernel, and hang out there
		 * until a thread needs to be created.
		 */
		if (err = sndrsys(RDC_POOL_WAIT, &id)) {
			if (err == ECANCELED || err == EBUSY)
				/*
				 * If we get back ECANCELED, the service
				 * pool is exiting, and we may as well
				 * clean up this thread. If EBUSY is
				 * returned, there's already a thread
				 * looping on this pool, so we should
				 * give up.
				 */
				break;
			else
				continue;
		}

		(void) thr_create(NULL, NULL, svcstart, (void *)id,
		    THR_BOUND | THR_DETACHED, &tid);
	}

	thr_exit(NULL);
	return (NULL);
}

static int
svcwait(int id)
{
	thread_t tid;

	/*
	 * Create a bound thread to wait for kernel LWPs that
	 * need to be created.
	 */
	if (thr_create(NULL, NULL, svcblock, (void *)id,
	    THR_BOUND | THR_DETACHED, &tid))
		return (1);

	return (0);
}
#endif /* Solaris 9+ */
