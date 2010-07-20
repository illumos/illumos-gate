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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains the argument parsing routines of the dhcpd daemon.
 * It corresponds to the START state as spec'ed.
 */

/*
 * Multithreading Notes:
 * =====================
 *
 * For Enterprise DHCP scalability, libdhcpsvc has been made reentrant,
 * and the server has been organized with a worker thread per client.
 *
 * There is a thread per configured interface which reads requests,
 * determines if they are for this server, and appends them to the
 * interface's PKT list. This thread spawns worker threads as needed
 * to service incoming clients.
 *
 * The main thread creates a thread to handle signals. All subsequent threads
 * (and the main thread) mask out all signals.
 *
 * The signal thread will deal with the -t option. This is done by
 * waiting in sigtimedwait() for the timeout period, then spawning
 * a reinitialization thread.
 *
 * dhcp: each client worker thread moves through the multi-packet
 * state machine inline, performing icmp_echo_check() as needed.
 * We prevent multiple threads from registering the same address for ICMP
 * validation due to multiple DISCOVERS by reserving addresses in
 * select_offer() to ensure we don't offer IP addresses currently
 * undergoing ICMP validation.
 *
 * bootp: If automatic allocation is in effect,
 * bootp behaves in the same fashion as dhcp_offer.
 *
 * Summary:
 *
 *	Threads:
 *		1) Main thread: Handles startup and shutdown chores.
 *
 *		2) Signal thread: The main thread creates this thread, and
 *		   then masks out all signals. The signal thread waits on
 *		   sigwait(), and processes all signals. It notifies the
 *		   main thread of EINTR or ETERM via a global variable, which
 *		   the main thread checks upon the exit to cond_wait.
 *		   This thread is on it's own LWP, and is DETACHED | DAEMON.
 *		   The thread function is sig_handle().
 *
 *		3) Interface threads: Each interface structure has a thread
 *		   associated with it (created in open_interfaces) which is
 *		   responsible for polling the interface, validating bootp
 *		   packets received, and placing them on the client's
 *		   PKT_LIST. The thread function is monitor_interface().
 *		   When notified by the main thread via the thr_exit flag,
 *		   the thread prints interface statistics for the interface,
 *		   and then exits.
 *
 *		4) Client threads: Created as needed when the interface
 *		   thread processes each incoming packet. These threads are
 *		   created DETACHED and SUSPENDED by the interface thread,
 *		   which then  places each plp structure on the client's
 *		   PKT_LIST, then continues the thread. A client thread exits
 *		   when it has processed all incoming packets, and no
 *		   deferred client work is queued. See per_dnet.h for
 *		   more information on client locks.
 *
 *	Locks:
 *		1) if_head_mtx	-	Locks the global interface list.
 *
 *		2) ifp_mtx	-	Locks contents of the enclosed
 *					interface (IF) structure, including
 *					such things as thr_exit flag and
 *					statistics counters.
 *
 *		3) pkt_mtx	-	Locks PKT_LIST head list within the
 *					enclosed client (dsvc_clnt_t) struct.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/dhcp.h>
#include <synch.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <netdb.h>
#include <dhcp_svc_confkey.h>
#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"
#include <locale.h>
#include <mtmalloc.h>
#include <resolv.h>

extern int optind, opterr;
extern char *optarg;

typedef struct dhcp_cops {
	char		*cop_name;			/* opt name */
	boolean_t	cop_present;			/* opt present? */
	boolean_t	(*cop_vinit)(struct dhcp_cops *, const char *);
	union {
		char 		*ucop_str;
		boolean_t	ucop_bool;
		int		ucop_num;
	} dhcp_cops_un;
#define	cop_bool	dhcp_cops_un.ucop_bool	/* opt val: boolean_t */
#define	cop_num		dhcp_cops_un.ucop_num	/* opt val: int */
#define	cop_str		dhcp_cops_un.ucop_str	/* opt val: string */
} DHCP_COP;

static boolean_t bool_v(DHCP_COP *, const char *);
static boolean_t uchar_v(DHCP_COP *, const char *);
static boolean_t int_v(DHCP_COP *, const char *);
static boolean_t uint_v(DHCP_COP *, const char *);
static boolean_t str_v(DHCP_COP *, const char *);
static boolean_t bootp_v(DHCP_COP *, const char *);
static boolean_t logging_v(DHCP_COP *, const char *);
static boolean_t runmode_v(DHCP_COP *, const char *);
static int collect_options(int, char **);
static void usage(void);
static void local_closelog(void);
static void *sig_handle(void *);

#define	C_RUNMODE	0
#define	C_DEBUG		1
#define	C_VERBOSE	2
#define	C_HOPS		3
#define	C_LOGGING	4
#define	C_IF		5
#define	C_OFFER		6
#define	C_ICMP		7
#define	C_RESCAN	8
#define	C_BOOTP		9
#define	C_CLIENT	10
#define	C_THREADS	11
#define	C_MINLRU	12
#define	C_RELAY		13
#define	C_NSUPDATE	14
#define	C_CACHE		15

#define	C_DBGPORT	16
#define	C_RENOG		17
#define	C_OWNER		18
#ifdef	DEBUG
#define	C_DBGNET	19
#define	C_LAST		C_DBGNET
#else	/* DEBUG */
#define	C_LAST		C_OWNER
#endif	/* DEBUG */


static DHCP_COP options[C_LAST + 1] = {
/* name				Present?  Verify func   Value */
/* ====				========  ===========   ===== */
	/* Run mode / BOOTP relay agent selection option */
{ DSVC_CK_RUN_MODE,		B_FALSE,  runmode_v,	DSVC_CV_SERVER },
	/* Generic daemon options */
{ "DEBUG",			B_FALSE,  bool_v,	B_FALSE },
{ DSVC_CK_VERBOSE,		B_FALSE,  bool_v,	B_FALSE },
{ DSVC_CK_RELAY_HOPS,		B_FALSE,  uchar_v,	(char *)DSVC_CV_HOPS },
{ DSVC_CK_LOGGING_FACILITY,	B_FALSE,  logging_v,	0 },
{ DSVC_CK_INTERFACES,		B_FALSE,  str_v,	NULL },
	/* DHCP server run mode options */
{ DSVC_CK_OFFER_CACHE_TIMEOUT,	B_FALSE,  uint_v,   (char *)DSVC_CV_OFFER_TTL },
{ DSVC_CK_ICMP_VERIFY,		B_FALSE,  bool_v,	(char *)B_TRUE },
{ DSVC_CK_RESCAN_INTERVAL,	B_FALSE,  int_v,	0 },
{ DSVC_CK_BOOTP_COMPAT,		B_FALSE,  bootp_v,	NULL },
{ DSVC_CK_MAX_CLIENTS,		B_FALSE,  int_v,	(char *)0 },
{ DSVC_CK_MAX_THREADS,		B_FALSE,  int_v,	(char *)0 },
{ DSVC_CK_LEASE_MIN_LRU,	B_FALSE,  int_v,    (char *)DSVC_CV_MIN_LRU },
	/* BOOTP relay agent options */
{ DSVC_CK_RELAY_DESTINATIONS,	B_FALSE,  str_v,	NULL },
	/* Name service update timeout */
{ DSVC_CK_NSU_TIMEOUT,		B_FALSE,  uint_v,   (char *)DSVC_CV_NSU_TO },
{ DSVC_CK_CACHE_TIMEOUT,	B_FALSE,  int_v,   (char *)DSVC_CV_CACHE_TTL },
{ DSVC_CK_DBG_PORT_OFFSET,	B_FALSE,  int_v,	0 },
{ DSVC_CK_RENOG_INTERVAL,	B_FALSE,  uint_v,  (char *)DSVC_CV_RENOG_INT },
{ DSVC_CK_OWNER_IP,		B_FALSE,  str_v,	NULL },
#ifdef	DEBUG
{ DSVC_CK_DBG_MEMORY_NET,	B_FALSE,  str_v,	NULL }
#endif	/* DEBUG */
};

#define	DHCPCOP_NAME(x)		(options[x].cop_name)
#define	DHCPCOP_PRES(x)		(options[x].cop_present)
#define	DHCPCOP_VINIT(x, y)	(options[x].cop_vinit(&options[x], y))
#define	DHCPCOP_BOOL(x)		(options[x].cop_bool)
#define	DHCPCOP_NUM(x)		(options[x].cop_num)
#define	DHCPCOP_STR(x)		(options[x].cop_str)

int debug;
boolean_t verbose;
boolean_t noping;		/* Always ping before offer by default */
boolean_t no_dhcptab;		/* set if no dhcptab exists */
boolean_t server_mode;		/* set if running in server mode */
static boolean_t bootp_compat;	/* bootp compatibility */
boolean_t be_automatic;		/* set if bootp server should allocate IPs */
uchar_t max_hops;		/* max relay hops before discard */
int log_local;			/* syslog local facility number */
int icmp_tries = DHCP_ICMP_ATTEMPTS; /* Number of attempts @ icmp_timeout */
time_t off_secs;		/* def ttl of an offer */
time_t cache_secs;		/* def ttl of netmask and table caches */
time_t renog_secs;		/* def wait time for secondary server timeout */
time_t min_lru;			/* def minimum lru of a reclaimed lease */
time_t icmp_timeout = DHCP_ICMP_TIMEOUT; /* milliseconds to wait for response */
time_t nsutimeout_secs;		/* seconds to wait for a name service up date */
struct in_addr	server_ip;	/* IP address of server's primary interface */
struct in_addr	*owner_ip;	/* owner IP address list */
static dhcp_confopt_t *dsp;	/* Confopt for datastore access */
dsvc_datastore_t datastore;	/* Datastore for container access */
int max_threads;		/* maximum number of worker threads per net */
int max_clients;		/* maximum number of active clients per net */
ushort_t port_offset = 0;	/* offset to port for multiple server */
int net_thresh = DHCP_NET_THRESHOLD;	/* secs to keep pernet reference */
int clnt_thresh = DHCP_CLIENT_THRESHOLD; /* secs to keep client reference */
struct __res_state resolv_conf;	/* DNS resolver data, includes domain-name */
static int rescan_scale = DHCP_RESCAN_SCALE;	/* secs to scale */
#ifdef	DEBUG
char *dbg_net;			/* Simulated debug net (see misc.c) */
#endif	/* DEBUG */

static time_t rescan_interval;	/* dhcptab rescan interval */


/*
 * This global is set by the signal handler when the main thread (and thus
 * the daemon) should exit. We only use the mutex in this file, since we make
 * the main thread wait on it becoming true using a condition variable.
 */
boolean_t time_to_go = B_FALSE;
static mutex_t	ttg_mtx;
static cond_t ttg_cv;

/* local syslog facilities */
static int log_facilities[] = {
	LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4,
	LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7
};

time_t	reinit_time;			/* reinitialization time */
static thread_t init_thread;		/* reinitialization thread */

int
main(int argc, char *argv[])
{
	sigset_t	set;
	int		i, ns, err = 0;
	struct rlimit	rl;
	struct hostent	*hp;
	thread_t	sigthread;
	int		nss_lwp = 0;
	int32_t		ncpus;
	char		scratch[MAXHOSTNAMELEN + 1];
	char		ntoab[INET_ADDRSTRLEN];
	char		*ownerip_args, *sip, *lasts;
	int		np = 1;
	struct in_addr	*oip;

#ifdef	DEBUG
	mallocctl(MTDEBUGPATTERN, 1);
	mallocctl(MTINITBUFFER, 1);
#endif	/* DEBUG */

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEXT"
#endif	/* ! TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	if (geteuid() != (uid_t)0) {
		(void) fprintf(stderr, gettext("Must be 'root' to run %s.\n"),
		    DHCPD);
		return (EPERM);
	}

	if ((err = collect_options(argc, argv)) != 0) {
		if (errno == EAGAIN) {
			(void) fprintf(stderr, gettext("DHCP daemon config "
			    "file locked.\n"));
			err = EAGAIN;
		} else {
			usage();
			err = EINVAL;
		}
		return (err);
	}

	/* Deal with run mode generic options first */
	debug = DHCPCOP_BOOL(C_DEBUG);
	verbose = DHCPCOP_BOOL(C_VERBOSE);
	max_hops = DHCPCOP_NUM(C_HOPS);
	interfaces = DHCPCOP_STR(C_IF);
	bootp_compat = DHCPCOP_PRES(C_BOOTP); /* present then yes */
	max_clients = DHCPCOP_NUM(C_CLIENT);
	max_threads = DHCPCOP_NUM(C_THREADS);
	log_local = DHCPCOP_PRES(C_LOGGING) ?
	    log_facilities[DHCPCOP_NUM(C_LOGGING)] : -1;

	server_mode = (strcasecmp(DHCPCOP_STR(C_RUNMODE), DSVC_CV_SERVER) == 0);
	if (server_mode) {

		if (bootp_compat) {
			be_automatic = (strcasecmp(DHCPCOP_STR(C_BOOTP),
			    DSVC_CV_AUTOMATIC) == 0);
		}

		if (DHCPCOP_BOOL(C_ICMP) == B_FALSE) {
			(void) fprintf(stderr, gettext("\nWARNING: Disabling \
duplicate IP address detection!\n\n"));
			noping = B_TRUE;
		} else {
			noping = B_FALSE;
		}

		off_secs = DHCPCOP_NUM(C_OFFER);
		cache_secs = DHCPCOP_NUM(C_CACHE);
		renog_secs = DHCPCOP_NUM(C_RENOG);
		min_lru = DHCPCOP_NUM(C_MINLRU);
		port_offset = DHCPCOP_NUM(C_DBGPORT);	/* Private debug flag */
#ifdef	DEBUG
		dbg_net = DHCPCOP_STR(C_DBGNET);
#endif	/* DEBUG */
		nsutimeout_secs = DHCPCOP_PRES(C_NSUPDATE) ?
		    DHCPCOP_NUM(C_NSUPDATE) : DHCP_NO_NSU;

		if ((rescan_interval = DHCPCOP_NUM(C_RESCAN)) != 0) {
			rescan_interval *= rescan_scale;
		}

		/* Load current datastore, if any. */
		if (dsp == NULL)
			return (1);
		if ((i = confopt_to_datastore(dsp, &datastore)) !=
		    DSVC_SUCCESS) {
			(void) fprintf(stderr, gettext(
			    "WARNING: Invalid datastore: %s\n"),
			    dhcpsvc_errmsg(i));
			return (1);
		}
		free_dsvc_conf(dsp);

		ns = status_dd(&datastore);
		if (ns != DSVC_SUCCESS) {
			(void) fprintf(stderr, gettext(
			    "Datastore status error: %s\n"),
			    dhcpsvc_errmsg(ns));
			return (1);
		}
	} else {
		if (!DHCPCOP_PRES(C_RELAY)) {
			(void) fprintf(stderr, gettext("Missing BOOTP "
			    "relay destinations (%s)\n"),
			    DSVC_CK_RELAY_DESTINATIONS);
			return (1);
		}
		if ((err = relay_agent_init(DHCPCOP_STR(C_RELAY))) != 0)
			return (err);
	}

	if (!debug) {
		/* Daemon (background, detach from controlling tty). */
		switch (fork()) {
		case -1:
			(void) fprintf(stderr,
			    gettext("Daemon cannot fork(): %s\n"),
			    strerror(errno));
			return (errno);
		case 0:
			/* child */
			break;
		default:
			/* parent */
			return (0);
		}

		closefrom(0);	/* close all open files */
		errno = 0;	/* clean up benign bad file no error */
		(void) open("/dev/null", O_RDONLY, 0);
		(void) dup2(0, 1);
		(void) dup2(0, 2);

		/* Detach console */
		(void) setsid();

		(void) openlog(DHCPD, LOG_PID, LOG_DAEMON);
	}

	/* set NOFILE to unlimited */
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if ((err = setrlimit(RLIMIT_NOFILE, &rl)) < 0) {
		dhcpmsg(LOG_ERR, "Cannot set open file limit: %s\n",
		    strerror(errno));
		return (err);
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	if (verbose)
		dhcpmsg(LOG_INFO, "Daemon started.\n");

	/*
	 * Block all signals in main thread - threads created will also
	 * ignore signals.
	 */
	(void) sigfillset(&set);

	(void) sigdelset(&set, SIGABRT);	/* allow for user abort */

	(void) thr_sigsetmask(SIG_SETMASK, &set, NULL);

	/*
	 * Create signal handling thread.
	 * Due to threads library limitations, the main program
	 * thread currently cannot function as the signal thread, and
	 * must be a bound thread.
	 */
	if ((err = thr_create(NULL, 0, sig_handle, NULL, THR_NEW_LWP |
	    THR_DAEMON | THR_BOUND | THR_DETACHED, &sigthread)) != 0) {
		(void) fprintf(stderr,
		    gettext("Cannot start signal handling thread, error: %d\n"),
		    err);
		return (err);
	}
#ifdef	DEBUG
	(void) fprintf(stderr,
	    gettext("Started signal handling thread: %d\n"), sigthread);
#endif	/* DEBUG */

	/* Save away the IP address associated with our HOSTNAME. */

#ifdef	DEBUG
	/* Debugging: allow shared use of difficult to create databases. */
	if (getenv("DHCP_HOSTNAME") != NULL)
		(void) strcpy(scratch, getenv("DHCP_HOSTNAME"));
	else
#endif	/* DEBUG */
	(void) sysinfo(SI_HOSTNAME, scratch, MAXHOSTNAMELEN + 1);

	if ((hp = gethostbyname(scratch)) != NULL &&
	    hp->h_addrtype == AF_INET &&
	    hp->h_length == sizeof (struct in_addr)) {
		(void) memcpy((char *)&server_ip, hp->h_addr_list[0],
		    sizeof (server_ip));
		/*
		 * server_ip is supplemented by owner_ip list
		 * the first in the list of owner_ips always = server_ip
		 */
		owner_ip = smalloc((sizeof (struct in_addr)) * (np + 1));
		(void) memcpy(owner_ip, &server_ip, sizeof (server_ip));

		if (DHCPCOP_PRES(C_OWNER)) {
			ownerip_args = DHCPCOP_STR(C_OWNER);
			sip = strtok_r(ownerip_args, ",", &lasts);
			while (sip != NULL) {
				owner_ip = srealloc(owner_ip,
				    (sizeof (struct in_addr)) * (np + 2));
				oip = owner_ip + np;
				if (inet_pton(AF_INET, sip, oip) == 0 ||
				    oip->s_addr == INADDR_ANY) {
					dhcpmsg(LOG_ERR,
					    "Invalid OWNER IP address %s\n",
					    sip);
					sip = strtok_r(NULL, ",", &lasts);
					continue;
				}
				np++;
				sip = strtok_r(NULL, ",", &lasts);
			}
		}
		oip = owner_ip + np;
		oip->s_addr = INADDR_ANY;
	} else {
		dhcpmsg(LOG_ERR,
		    "Cannot determine server hostname/IP address.\n");
		local_closelog();
		return (1);
	}
	(void) memset(&resolv_conf, 0, sizeof (resolv_conf));
	if (res_ninit(&resolv_conf) == -1) {
		dhcpmsg(LOG_ERR, "Cannot acquire resolver configuration.\n");
	}
	i = 0;
	if (server_mode) {
		/*
		 * Calculate limits to maximum concurrency. Special values:
		 * If max_{threads,clients} == 0, calculate limits
		 * based on cpu and memory.
		 * Else if max_{threads,clients} is set to -1, run without
		 * concurrency limits.
		 * Else use supplied limits.
		 */
		if ((ncpus = sysconf(_SC_NPROCESSORS_CONF)) < 0)
			ncpus = 1;

		if (max_clients == 0)
			max_clients = DHCP_DEFAULT_CLIENTS * ncpus;

		/* Require a minimum number of client structs. */
		if (max_clients != -1 && max_clients < DHCP_MIN_CLIENTS) {
			max_clients = DHCP_MIN_CLIENTS;
			dhcpmsg(LOG_ERR, "Warning: adjusting MAX_CLIENTS"
			    " to minimum value %d\n", max_clients);
		}

		if (max_threads == 0)
			max_threads = max_clients/4;

		/*
		 * 4321342: Alloc additional lwps for unbound library threads.
		 * Remove this performance workaround when bug fixed.
		 */
		if (max_clients != 0)
			nss_lwp = max_clients/8;
		if (nss_lwp <= 0 || nss_lwp > DHCP_NSS_LWP)
			nss_lwp = DHCP_NSS_LWP;
		i = thr_setconcurrency(nss_lwp);
	}

	if (verbose) {
		if (i != 0)
			dhcpmsg(LOG_ERR, "Error setting concurrency %d: %s\n",
			    max_threads, strerror(i));
		dhcpmsg(LOG_INFO, "Daemon Version: %s\n", DAEMON_VERS);
		dhcpmsg(LOG_INFO, "Maximum relay hops: %d\n", max_hops);
		if (log_local > -1) {
			dhcpmsg(LOG_INFO,
			    "Transaction logging to %s enabled.\n",
			    debug ? "console" : "syslog");
		}
		if (server_mode) {
			dhcpmsg(LOG_INFO, "Run mode is: DHCP Server Mode.\n");
			dhcpmsg(LOG_INFO, "Datastore resource: %s\n",
			    datastore.d_resource ?
			    datastore.d_resource : "");
			dhcpmsg(LOG_INFO, "Location: %s\n",
			    datastore.d_location ?
			    datastore.d_location : "");
			dhcpmsg(LOG_INFO, "DHCP offer TTL: %ld\n", off_secs);
			if (bootp_compat)
				dhcpmsg(LOG_INFO,
				    "BOOTP compatibility enabled.\n");
			if (rescan_interval != 0) {
				dhcpmsg(LOG_INFO,
				    "Dhcptab rescan interval: %ld minutes.\n",
				    rescan_interval / rescan_scale);
			}
			dhcpmsg(LOG_INFO, "ICMP validation timeout: %ld "
			    "milliseconds, Attempts: %d.\n", icmp_timeout,
			    icmp_tries);
			if (nsutimeout_secs != DHCP_NO_NSU) {
				dhcpmsg(LOG_INFO, "Name service update "
				    "enabled, timeout: %ld seconds\n",
				    nsutimeout_secs);
			}
			for (oip = owner_ip; oip->s_addr != INADDR_ANY; oip++)
				dhcpmsg(LOG_INFO, "Owner IP address: %s\n",
				    inet_ntop(AF_INET, oip, ntoab,
				    sizeof (ntoab)));
			dhcpmsg(LOG_INFO, "Maximum concurrent clients: %d\n",
			    max_clients);
			dhcpmsg(LOG_INFO, "Maximum threads: %d\n", max_threads);
		} else
			dhcpmsg(LOG_INFO, "Run mode is: Relay Agent Mode.\n");
	}

	(void) mutex_init(&ttg_mtx, USYNC_THREAD, 0);
	(void) cond_init(&ttg_cv, USYNC_THREAD, 0);

	if (server_mode) {

		if (initntab() != 0) {
			dhcpmsg(LOG_ERR, "Cannot allocate per network hash "
			    "table.\n");
			local_closelog();
			(void) mutex_destroy(&ttg_mtx);
			(void) cond_destroy(&ttg_cv);
			res_ndestroy(&resolv_conf);
			return (1);
		}

		if (initmtab() != 0) {
			dhcpmsg(LOG_ERR, "Cannot allocate macro hash table.\n");
			local_closelog();
			(void) mutex_destroy(&ttg_mtx);
			(void) cond_destroy(&ttg_cv);
			res_ndestroy(&resolv_conf);
			return (1);
		}

		if ((err = checktab()) != 0 ||
		    (err = readtab(NEW_DHCPTAB)) != 0) {
			if (err == ENOENT) {
				no_dhcptab = B_TRUE;
			} else {
				dhcpmsg(LOG_ERR,
				    "Error reading macro table.\n");
				local_closelog();
				(void) mutex_destroy(&ttg_mtx);
				(void) cond_destroy(&ttg_cv);
				res_ndestroy(&resolv_conf);
				return (err);
			}
		} else
			no_dhcptab = B_FALSE;
	}

	if ((err = open_interfaces()) != 0) {
		local_closelog();
		(void) mutex_destroy(&ttg_mtx);
		(void) cond_destroy(&ttg_cv);
		res_ndestroy(&resolv_conf);
		return (err);
	}

	/*
	 * While forever, handle signals and dispatch them.
	 */
	while (!time_to_go) {
		(void) mutex_lock(&ttg_mtx);
		while (!time_to_go)
			(void) cond_wait(&ttg_cv, &ttg_mtx);
		(void) mutex_unlock(&ttg_mtx);
	}

	/* Daemon terminated. */
	if (server_mode) {
		resettab(B_TRUE);
		close_clnts();	/* reaps client threads */
	}

	close_interfaces();		/* reaps monitor threads */
	local_closelog();
	(void) fflush(NULL);
	(void) mutex_destroy(&ttg_mtx);
	(void) cond_destroy(&ttg_cv);
	res_ndestroy(&resolv_conf);
	return (err);
}

/*
 * Signal handler routine. All signals handled by calling thread.
 */
/* ARGSUSED */
static void *
sig_handle(void *arg)
{
	int		err;
	int		sig;
	sigset_t	set;
	char buf[SIG2STR_MAX];
	timespec_t	ts;
	siginfo_t	si;

	(void) sigfillset(&set);		/* catch all signals */

	ts.tv_sec = rescan_interval == 0 ? DEFAULT_LEASE : rescan_interval;
	ts.tv_nsec = 0L;

	/* wait for a signal */
	while (!time_to_go) {
		switch (sig = sigtimedwait(&set, &si, &ts)) {
		case -1:
			if (rescan_interval == 0 || errno != EAGAIN)
				break;
			/*FALLTHRU*/
		case SIGHUP:
			/*
			 * Create reinitialization thread.
			 */
			if (init_thread != NULL)
					break;

			if ((err = thr_create(NULL, 0, reinitialize,
			    &init_thread, THR_BOUND | THR_DETACHED,
			    &init_thread)) != 0) {
				(void) fprintf(stderr, gettext(
				    "Cannot start reinit thread, error: %d\n"),
				    err);
			}
			break;
		case SIGTERM:
			/* FALLTHRU */
		case SIGINT:
			(void) sig2str(sig, buf);
			dhcpmsg(LOG_NOTICE, "Signal: %s received...Exiting\n",
			    buf);
			time_to_go = B_TRUE;
			break;
		default:
			if (verbose) {
				(void) sig2str(sig, buf);
				dhcpmsg(LOG_INFO,
				    "Signal: %s received...Ignored\n",
				    buf);
			}
			break;
		}
		if (time_to_go) {
			(void) mutex_lock(&ttg_mtx);
			(void) cond_signal(&ttg_cv);
			(void) mutex_unlock(&ttg_mtx);
			break;
		}
	}
	return ((void *)sig);	/* NOTREACHED */
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "%s:\n\n\tCommon: [-d] [-v] [-i interface, ...] "
	    "[-h hops] [-l local_facility]\n\n\t"
	    "Server: [-n] [-t rescan_interval] [-o DHCP_offer_TTL]\n\t\t"
	    "[ -b automatic | manual]\n\n\t"
	    "Relay Agent: -r IP | hostname, ...\n"), DHCPD);
}

static void
local_closelog(void)
{
	dhcpmsg(LOG_INFO, "Daemon terminated.\n");
	if (!debug)
		closelog();
}

/*
 * Given a received BOOTP packet, generate an appropriately sized,
 * and generically initialized BOOTP packet.
 */
PKT *
gen_bootp_pkt(int size, PKT *srcpktp)
{
	PKT *pkt = (PKT *)smalloc(size);

	pkt->htype = srcpktp->htype;
	pkt->hlen = srcpktp->hlen;
	pkt->xid = srcpktp->xid;
	pkt->secs = srcpktp->secs;
	pkt->flags = srcpktp->flags;
	pkt->giaddr.s_addr = srcpktp->giaddr.s_addr;
	(void) memcpy(pkt->cookie, srcpktp->cookie, 4);
	(void) memcpy(pkt->chaddr, srcpktp->chaddr, srcpktp->hlen);

	return (pkt);
}

/*
 * Points field serves to identify those packets whose allocated size
 * and address is not represented by the address in pkt.
 */
void
free_plp(PKT_LIST *plp)
{
	char *tmpp;

#ifdef	DEBUG
	dhcpmsg(LOG_DEBUG,
"%04d: free_plp(0x%x)pkt(0x%x)len(%d)next(0x%x)prev(0x%x)\n",
	    thr_self(), plp, plp->pkt, plp->len,
	    plp->next, plp->prev);
#endif	/* DEBUG */
	if (plp->pkt) {
		if (plp->offset != 0)
			tmpp = (char *)((uint_t)plp->pkt - plp->offset);
		else
			tmpp = (char *)plp->pkt;
		free(tmpp);
	}
	free(plp);
	plp = NULL;
}

/*
 * Validate boolean is "B_TRUE" or "B_FALSE".
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
bool_v(DHCP_COP *dp, const char *option)
{
	boolean_t	i;

	assert(dp != NULL && option != NULL);

	if (strcasecmp(option, DSVC_CV_TRUE) == 0) {
		i = B_TRUE;
	} else if (strcasecmp(option, DSVC_CV_FALSE) == 0) {
		i = B_FALSE;
	} else {
		return (B_FALSE); /* huh? */
	}
	dp->cop_bool = i;
	return (B_TRUE);
}

/*
 * Validate uchar data.
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
uchar_v(DHCP_COP *dp, const char *option)
{
	if (dp == NULL || option == NULL || !isdigit(*option))
		return (B_FALSE);
	dp->cop_num = strtoul(option, 0L, 0L);
	if (dp->cop_num < 0 || dp->cop_num > 0xFF)
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * Validate integer data.
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
int_v(DHCP_COP *dp, const char *option)
{
	if (dp != NULL && option != NULL) {
		errno = 0;
		dp->cop_num = strtol(option, NULL, 0L);
		if (errno == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Validate unsigned integer data.
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
uint_v(DHCP_COP *dp, const char *option)
{
	if (dp != NULL && option != NULL) {
		errno = 0;
		dp->cop_num = strtoul(option, NULL, 0L);
		if (errno == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Check if value is a string.
 * Returns B_TRUE if successful, B_FALSE otherwise
 */
static boolean_t
str_v(DHCP_COP *dp, const char *option)
{
	if (dp == NULL || option == NULL ||
	    (dp->cop_str = strdup(option)) == NULL) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Validate bootp compatibility options. Must be "automatic" or
 * "manual".
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
bootp_v(DHCP_COP *dp, const char *option)
{
	if (dp == NULL || option == NULL)
		return (B_FALSE);

	if ((strcasecmp(option, DSVC_CV_AUTOMATIC) == 0 ||
	    strcasecmp(option, DSVC_CV_MANUAL) == 0) &&
	    (dp->cop_str = strdup(option)) != NULL) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Validate logging facility. Must be a number between 0 and 7 inclusive.
 * Returns B_TRUE if successful, B_FALSE otherwise.
 */
static boolean_t
logging_v(DHCP_COP *dp, const char *option)
{
	if (uint_v(dp, option) && dp->cop_num <= 7)
		return (B_TRUE);

	(void) fprintf(stderr, gettext("Syslog local facility must be in the "
	    "range of 0 through 7.\n"));
	return (B_FALSE);
}

/*
 * Validate run mode. Must be "server" or "relay".
 * Returns B_TRUE if successful, B_FALSE otherwise
 */
static boolean_t
runmode_v(DHCP_COP *dp, const char *option)
{
	if (dp == NULL || option == NULL)
		return (B_FALSE);
	if ((strcasecmp(option, DSVC_CV_SERVER) == 0 ||
	    strcasecmp(option, DSVC_CV_RELAY) == 0) &&
	    (dp->cop_str = strdup(option)) != NULL) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Initialize options table based upon config file settings or command
 * line flags. Handle all option inter-dependency checking here. No value
 * checking is done here.
 *
 * Returns 0 if successful, nonzero otherwise.
 */
static int
collect_options(int count, char **args)
{
	int			c, i, j;
	char			*mode;

	/* First, load the configuration options from the file, if present. */
	for (errno = 0, i = 0; i < DHCP_RDCOP_RETRIES &&
	    read_dsvc_conf(&dsp) < 0; i++) {
		(void) fprintf(stderr, gettext(
		    "WARNING: DHCP daemon config file: %s\n"),
		    strerror(errno));
		if (errno == EAGAIN) {
			/* file's busy, wait one second and try again */
			(void) sleep(1);
		} else
			break;
	}
	if (errno == EAGAIN)
		return (EAGAIN);

	/* set default RUN_MODE to server if it wasn't found in the file */
	if (query_dsvc_conf(dsp, DSVC_CK_RUN_MODE, &mode) < 0) {
		if (errno == ENOENT) {
			if (add_dsvc_conf(&dsp, DSVC_CK_RUN_MODE,
			    DSVC_CV_SERVER) != 0)
				return (errno);
		}
	} else
		free(mode);

	/*
	 * Second, pick up the user's preferences from the command line,
	 * which modify the config file settings.
	 */
	while ((c = getopt(count, args, "dnvh:o:r:b:i:t:l:")) != -1) {

		boolean_t	relay_mode = B_FALSE;
		char		*key = NULL, *value = NULL;

		switch (c) {
		case 'd':
			key = "DEBUG";
			value = DSVC_CV_TRUE;
			break;
		case 'n':
			key = DSVC_CK_ICMP_VERIFY;
			value = DSVC_CV_FALSE;
			break;
		case 'v':
			key = DSVC_CK_VERBOSE;
			value = DSVC_CV_TRUE;
			break;
		case 'r':
			key = DSVC_CK_RELAY_DESTINATIONS;
			value = optarg;
			relay_mode = B_TRUE;
			break;
		case 'b':
			key = DSVC_CK_BOOTP_COMPAT;
			value = optarg;
			break;
		case 'h':
			key = DSVC_CK_RELAY_HOPS;
			value = optarg;
			break;
		case 'i':
			key = DSVC_CK_INTERFACES;
			value = optarg;
			break;
		case 'o':
			key = DSVC_CK_OFFER_CACHE_TIMEOUT;
			value = optarg;
			break;
		case 't':
			key = DSVC_CK_RESCAN_INTERVAL;
			value = optarg;
			break;
		case 'l':
			key = DSVC_CK_LOGGING_FACILITY;
			value = optarg;
			break;
		default:
			(void) fprintf(stderr, gettext("Unknown option: %c\n"),
			    c);
			return (EINVAL);
		}

		/*
		 * Create parameters if they don't exist, or replace
		 * their value if they exist.
		 */
		if (replace_dsvc_conf(&dsp, key, value) < 0)
			return (errno);

		if (relay_mode) {
			if (replace_dsvc_conf(&dsp, DSVC_CK_RUN_MODE,
			    DSVC_CV_RELAY) < 0)
				return (errno);
		}
	}

	if (optind < count) {

		/* get all unused arguments */
		(void) fprintf(stderr, "%s: unexpected argument(s) \"",
		    args[0]);
		for (; optind < count; optind++) {
			if (args[optind][0] != '-')
				(void) fprintf(stderr, " %s", args[optind]);
			else
				break;
		}
		(void) fprintf(stderr, "\"; Aborting\n");
		return (EINVAL);
	}

	/* load options table, validating value portions of present as we go */
	for (i = 0; dsp != NULL && dsp[i].co_key != NULL; i++) {
		if (dsp[i].co_type != DHCP_KEY)
			continue;	/* comment */
		for (j = 0; j <= C_LAST; j++) {
			if (strcasecmp(DHCPCOP_NAME(j),
			    dsp[i].co_key) == 0) {
				DHCPCOP_PRES(j) = B_TRUE;
				if (DHCPCOP_VINIT(j, dsp[i].co_value))
					break;
				else {
					(void) fprintf(stderr, gettext(
					    "Invalid value for option: %s\n"),
					    DHCPCOP_NAME(j));
					return (EINVAL);
				}
			}
		}
	}

	return (0);
}

/*
 * monitor_client: worker thread from pool created for each network.
 * We loop through and process one packet. Relay agent tasks are handled by
 * the per-interface threads, thus we should only be dealing with bootp/dhcp
 * server bound packets here.
 *
 * The worker thread treats the client packet lists as
 * "stacks", or FIFO objects. We do this so that we get
 * the latest, equivalent request from the client before
 * responding, thus keeping the chance of responding to
 * moldy requests to an absolute minimum.
 *
 * Performance: a pool of threads are used, to avoid thread startup/teardown.
 * Per-interface threads keep track of clients who cannot be serviced
 * due to a lack of threads. After completing the current request, threads
 * look for other work to do, before suspending and waiting to be
 * continued when work is available.
 */
void *
monitor_client(void *arg)
{
	dsvc_thr_t	*thrp = (dsvc_thr_t *)arg;
	dsvc_clnt_t	*pcd;
	dsvc_dnet_t	*pnd;
	dsvc_pendclnt_t	*workp;
	IF		*ifp;
	PKT_LIST	*plp = NULL;
	int		nclients;
	boolean_t	delete;
	uint_t		flags = 0;

	/*
	 * Initialize variables.
	 *
	 * Due to a possible race between suspend and continue, we must
	 * provide a positive indication that the thread has continued to
	 * the per-interface thread.
	 */
	(void) mutex_lock(&thrp->thr_mtx);
	pcd = thrp->thr_pcd;
	thrp->thr_pcd = NULL;
	(void) mutex_unlock(&thrp->thr_mtx);

	ifp = pcd->ifp;
	pnd = pcd->pnd;

	/*
	 * The per-interface thread leaves the client struct open,
	 * so it cannot be garbage-collected in the interim.
	 * Keep track of when we must release client structs.
	 */
	(void) mutex_lock(&pnd->thr_mtx);
	nclients = pnd->nclients;
	(void) mutex_unlock(&pnd->thr_mtx);

	for (; (flags & DHCP_THR_EXITING) == 0; ) {
		if (pcd == NULL) {
			/*
			 * No work. Place thread struct on free list
			 * if it isn't already, and suspend
			 * until new work is available.
			 */
			(void) mutex_lock(&thrp->thr_mtx);
			if ((thrp->thr_flags & DHCP_THR_LIST) == 0) {
				thrp->thr_flags |= DHCP_THR_LIST;
				thrp->thr_pcd = NULL;
				thrp->thr_next = NULL;

				(void) mutex_lock(&pnd->thr_mtx);
				if (pnd->thrhead != NULL) {
					pnd->thrtail->thr_next = thrp;
				} else {
					pnd->thrhead = thrp;
				}
				pnd->thrtail = thrp;
				(void) mutex_unlock(&pnd->thr_mtx);
			}

			/* Wait for new work. */
			(void) cond_wait(&thrp->thr_cv,  &thrp->thr_mtx);

			/*
			 * Resume with new client if any.
			 */
			pcd = thrp->thr_pcd;
			thrp->thr_pcd = NULL;
			flags = thrp->thr_flags;
			(void) mutex_unlock(&thrp->thr_mtx);
			continue;
		}

		(void) mutex_lock(&pcd->pkt_mtx);
		/*
		 * Remove the first packet from the list
		 */
		plp = pcd->pkthead;
		if (plp != NULL) {

			detach_plp(pcd, plp);
			pcd->pending--;

			/*
			 * See if there's a later one
			 * exchanging this plp for that one.
			 */
			plp = refresh_pktlist(pcd, plp);
		}
		(void) mutex_unlock(&pcd->pkt_mtx);

		(void) mutex_lock(&pcd->pcd_mtx);
		if (plp == NULL || (pcd->flags & DHCP_PCD_CLOSING) != 0) {

			if (plp) {
				free_plp(plp); /* Free the packet. */
				plp = NULL;
			}

			/*
			 * No work remaining for this client. Release,
			 * and check for other deferred clients on the
			 * per net work list.
			 */
			pcd->flags &= ~DHCP_PCD_WORK;

			/*
			 * Housekeeping: delete pcd immediately if above
			 * threshold and no offer has been made, or offer
			 * has been completed. Only perform deletion if no
			 * other thread has.
			 */
			delete = B_FALSE;
			if (max_clients != -1 &&
			    (pcd->flags & DHCP_PCD_CLOSING) == 0) {
				if (nclients >=
				    max_clients - DHCP_MINFREE_CLIENTS &&
				    pcd->off_ip.s_addr == htonl(INADDR_ANY)) {

					/* Remove clients without offers. */
					pcd->flags |= DHCP_PCD_CLOSING;
					delete = B_TRUE;

				} else if (nclients > max_clients/2 &&
				    (pcd->state == ACK ||
				    (pcd->state == REQUEST &&
				    pcd->off_ip.s_addr == htonl(INADDR_ANY)))) {

					/* Remove completed clients. */
					pcd->flags |= DHCP_PCD_CLOSING;
					delete = B_TRUE;

				} else if (pcd->state == RELEASE ||
				    pcd->state == DECLINE) {

					/* Remove freed clients. */
					pcd->flags |= DHCP_PCD_CLOSING;
					delete = B_TRUE;
				}
			}
			pcd->clnt_thread = NULL;
			(void) mutex_unlock(&pcd->pcd_mtx);

			/* Close the client. */
			close_clnt(pcd, delete);
			pcd = NULL;

			/*
			 * Remove next deferred work from list.
			 */
			workp = NULL;
			(void) mutex_lock(&pnd->thr_mtx);
			nclients = pnd->nclients;
			workp = pnd->workhead;
			if (workp &&
			    (pnd->workhead = pnd->workhead->pnd_next) == NULL)
				pnd->worktail = NULL;
			(void) mutex_unlock(&pnd->thr_mtx);

			if (workp != NULL) {
				/* See if the deferred client still exists. */
				if (open_clnt(pnd, &pcd, workp->pnd_cid,
				    workp->pnd_cid_len, B_TRUE) != DSVC_SUCCESS)
					pcd = NULL;
				if (pcd == NULL) {
					free(workp);
					continue;
				}

				(void) mutex_lock(&pcd->pcd_mtx);
				/* Check if it needs a worker thread. */
				if (pcd->clnt_thread == NULL &&
				    (pcd->flags & DHCP_PCD_WORK) != 0 &&
				    (pcd->flags & DHCP_PCD_CLOSING) == 0) {
					/* Found a valid client. Restart. */
					pcd->clnt_thread = thrp;
					(void) mutex_unlock(&pcd->pcd_mtx);
					ifp = pcd->ifp;
					free(workp);
					continue;
				}
				(void) mutex_unlock(&pcd->pcd_mtx);
				close_clnt(pcd, B_FALSE);
				pcd = NULL;
				free(workp);
			}
			continue;
		}
		(void) mutex_unlock(&pcd->pcd_mtx);

		/*
		 * Based on the packet type, process accordingly.
		 */
		if (plp->pkt->op == BOOTREQUEST) {
			if (plp->opts[CD_DHCP_TYPE]) {
				/* DHCP packet */
				dhcp(pcd, plp);
			} else {
				/* BOOTP packet */
				if (!bootp_compat) {
					dhcpmsg(LOG_INFO, "BOOTP request "
					    "received on interface: %s "
					    "ignored.\n", ifp->nm);
				} else {
					bootp(pcd, plp);
				}
			}
		}
		if (plp != NULL) {
			free_plp(plp); /* Free the packet. */
			plp = NULL;
		}

		(void) mutex_lock(&ifp->ifp_mtx);
		ifp->processed++;
		(void) mutex_unlock(&ifp->ifp_mtx);
	}

	/* Free the packet. */
	if (plp != NULL)
		free_plp(plp);

	/* Release the client structure. */
	if (pcd != NULL) {
		(void) mutex_lock(&pcd->pcd_mtx);
		pcd->flags &= ~DHCP_PCD_WORK;
		pcd->clnt_thread = NULL;
		(void) mutex_unlock(&pcd->pcd_mtx);

		close_clnt(pcd, B_FALSE);
	}

	/* Release the thread reference in pernet structure. */
	if (pnd != NULL) {
		(void) mutex_lock(&pnd->thr_mtx);
		pnd->nthreads--;
		(void) cond_signal(&pnd->thr_cv);
		(void) mutex_unlock(&pnd->thr_mtx);
	}

	return (NULL);
}
