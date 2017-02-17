/*
 * main.c - Point-to-Point Protocol main module
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#define RCSID	"$Id: main.c,v 1.97 2000/04/24 02:54:16 masputra Exp $"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <netdb.h>
#include <pwd.h>
#include <setjmp.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "magic.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#ifdef INET6
#include "ipv6cp.h"
#endif
#include "upap.h"
#include "chap.h"
#include "ccp.h"
#include "pathnames.h"
#include "patchlevel.h"

#ifdef HAVE_MULTILINK
#include "tdb.h"
#endif

#ifdef CBCP_SUPPORT
#include "cbcp.h"
#endif

#ifdef IPX_CHANGE
#include "ipxcp.h"
#endif /* IPX_CHANGE */
#ifdef AT_CHANGE
#include "atcp.h"
#endif

#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

/* interface vars */
char ifname[32];		/* Interface name */
int ifunit = -1;		/* Interface unit number */

char *progname;			/* Name of this program */
char hostname[MAXHOSTNAMELEN+1]; /* Our hostname */
static char pidfilename[MAXPATHLEN]; /* name of pid file */
static char linkpidfile[MAXPATHLEN]; /* name of linkname pid file */
char ppp_devnam[MAXPATHLEN];	/* name of PPP tty (maybe ttypx) */
static uid_t uid;		/* Our real user-id */
static int conn_running;	/* we have a [dis]connector running */

int ttyfd;			/* Serial port file descriptor */
mode_t tty_mode = (mode_t)-1;	/* Original access permissions to tty */
int baud_rate;			/* Actual bits/second for serial device */
bool hungup;			/* terminal has been hung up */
bool privileged;		/* we're running as real uid root */
bool need_holdoff;		/* need holdoff period before restarting */
bool detached;			/* have detached from terminal */
struct stat devstat;		/* result of stat() on devnam */
bool prepass = 0;		/* doing prepass to find device name */
int devnam_fixed;		/* set while in options.ttyxx file */
volatile int status;		/* exit status for pppd */
int unsuccess;			/* # unsuccessful connection attempts */
int do_callback;		/* != 0 if we should do callback next */
int doing_callback;		/* != 0 if we are doing callback */
char *callback_script;		/* script for doing callback */
#ifdef HAVE_MULTILINK
TDB_CONTEXT *pppdb;		/* database for storing status etc. */
char db_key[32];
#endif

/*
 * For plug-in usage:
 *
 *	holdoff_hook - Can be used to change the demand-dial hold-off
 *		time dynamically.  This is normally set by the
 *		"holdoff" option, and is 30 seconds by default.
 *
 *	new_phase_hook - This is called for each change in the PPP
 *		phase (per RFC 1661).  This can be used to log
 *		progress.
 *
 *	check_options_hook - This is called before doing sys_init()
 *		and allows the plugin to verify the selected options.
 *
 *	updown_script_hook - This is called with the proposed
 *		command-line arguments for any of the
 *		/etc/ppp/{ip,ipv6,ipx,auth}-{up,down} scripts before
 *		fork/exec.  It can be used to add or change arguments.
 *
 *	device_pipe_hook - If this is set, then an extra fd (3) is
 *		passed to the connect/disconnect script.  This extra
 *		fd is the write side of a pipe, and the read side is
 *		passed to this routine.  This can be used to pass
 *		arbitrary data from the script back to pppd.
 */
int (*holdoff_hook) __P((void)) = NULL;
int (*new_phase_hook) __P((int new, int old)) = NULL;
int (*check_options_hook) __P((uid_t uid)) = NULL;
int (*updown_script_hook) __P((const char ***argsp)) = NULL;
void (*device_pipe_hook) __P((int pipefd)) = NULL;

static int fd_ppp = -1;		/* fd for talking PPP */
static int fd_loop;		/* fd for getting demand-dial packets */
static int pty_master;		/* fd for master side of pty */
int pty_slave = -1;		/* fd for slave side of pty */
static int real_ttyfd;		/* fd for actual serial port (not pty) */

int phase;			/* where the link is at */
int kill_link;
int open_ccp_flag;

static int waiting;		/* for input from peer or timer expiration */
static sigjmp_buf sigjmp;

char **script_env;		/* Env. variable values for scripts */
int s_env_nalloc;		/* # words avail at script_env */

u_char outpacket_buf[PPP_MRU+PPP_HDRLEN]; /* buffer for outgoing packet */
u_char inpacket_buf[PPP_MRU+PPP_HDRLEN]; /* buffer for incoming packet */
u_char nak_buffer[PPP_MRU];	/* where we construct a nak packet */

static int n_children;		/* # child processes still running */
static bool got_sigchld;	/* set if we have received a SIGCHLD */
static sigset_t main_sigmask;	/* signals blocked while dispatching */

static bool locked;		/* lock() has succeeded */
static bool privopen;		/* don't lock, open device as root */

char *no_ppp_msg = "Sorry - this system lacks PPP kernel support\n";

GIDSET_TYPE groups[NGROUPS_MAX];/* groups the user is in */
int ngroups;			/* How many groups valid in groups */

static struct timeval start_time; /* Time when link was started. */

struct pppd_stats link_stats;
int link_connect_time;
bool link_stats_valid;

static pid_t charshunt_pid;	/* Process ID for charshunt */

extern option_t general_options[];
extern option_t auth_options[];

/*
 * We maintain a list of child process pids and
 * functions to call when they exit.
 */
struct subprocess {
    pid_t	pid;
    char	*prog;
    void	(*done) __P((void *, int));
    void	*arg;
    struct subprocess *next;
};

static struct subprocess *children;

/* Prototypes for procedures local to this file. */

static void setup_signals __P((void));
static void create_pidfile __P((void));
static void create_linkpidfile __P((void));
static void cleanup __P((void));
static void close_tty __P((void));
static void get_input __P((void));
static void calltimeout __P((void));
static struct timeval *timeleft __P((struct timeval *));
static void kill_my_pg __P((int));
static void hup __P((int));
static void term __P((int));
static void chld __P((int));
static void toggle_debug __P((int));
static void open_ccp __P((int));
static void bad_signal __P((int));
static void holdoff_end __P((void *));
static int device_script __P((char *, int, int, int, char *));
static int reap_kids __P((int waitfor));
static void record_child __P((pid_t, char *, void (*) (void *, int), void *));
static int open_socket __P((char *));
static int start_charshunt __P((int, int));
static void charshunt_done __P((void *, int));
static void charshunt __P((int, int, char *));
static int record_write __P((FILE *, int code, u_char *buf, int nb,
    struct timeval *));
static void final_reap __P((void));

#ifdef HAVE_MULTILINK
static void update_db_entry __P((void));
static void add_db_key __P((const char *));
static void delete_db_key __P((const char *));
static void cleanup_db __P((void));
#endif

int main __P((int, char *[]));

#ifdef ultrix
#undef	O_NONBLOCK
#define	O_NONBLOCK	O_NDELAY
#endif

#ifdef ULTRIX
#define setlogmask(x)	0
#endif

/* Backward compatibility for Linux */
#ifndef RECMARK_TIMESTART
#define	RECMARK_STARTSEND	1
#define	RECMARK_STARTRECV	2
#define	RECMARK_ENDSEND		3
#define	RECMARK_ENDRECV		4
#define	RECMARK_TIMEDELTA32	5
#define	RECMARK_TIMEDELTA8	6
#define	RECMARK_TIMESTART	7
#endif

/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 * The last entry must be NULL.
 */
struct protent *protocols[] = {
    &lcp_protent,
    &pap_protent,
    &chap_protent,
#ifdef CBCP_SUPPORT
    &cbcp_protent,
#endif
    &ipcp_protent,
#ifdef INET6
    &ipv6cp_protent,
#endif
    &ccp_protent,
#ifdef IPX_CHANGE
    &ipxcp_protent,
#endif
#ifdef AT_CHANGE
    &atcp_protent,
#endif
    NULL
};

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int i, fdflags, t;
    char *p, *connector;
    struct passwd *pw;
    struct timeval timo;
    struct protent *protp;
    struct stat statbuf;
    char numbuf[16];

    ifname[0] = '\0';
    new_phase(PHASE_INITIALIZE);

    /*
     * Ensure that fds 0, 1, 2 are open, to /dev/null if nowhere else.
     * This way we can close 0, 1, 2 in detach() without clobbering
     * a fd that we are using.
     */
    if ((i = open(_PATH_DEVNULL, O_RDWR)) >= 0) {
	while (0 <= i && i <= 2)
	    i = dup(i);
	if (i >= 0)
	    (void) close(i);
    }

    script_env = NULL;

    /* Initialize syslog facilities */
    reopen_log();

    if (gethostname(hostname, MAXHOSTNAMELEN+1) < 0 ) {
	option_error("Couldn't get hostname: %m");
	exit(1);
    }
    hostname[MAXHOSTNAMELEN] = '\0';

    /* make sure we don't create world or group writable files. */
    (void) umask(umask(0777) | 022);

    uid = getuid();
    privileged = (uid == 0);
    (void) slprintf(numbuf, sizeof(numbuf), "%d", uid);
    script_setenv("ORIG_UID", numbuf, 0);

    ngroups = getgroups(NGROUPS_MAX, groups);

    /*
     * Initialize magic number generator now so that protocols may
     * use magic numbers in initialization.
     */
    magic_init();

    progname = *argv;
    prepass = 0;
    /*
     * Initialize to the standard option set, then parse, in order, the
     * system options file, the user's options file, the tty's options file,
     * and the command line arguments.  At last, install the options declared
     * by each protocol into the extra_option list.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i) {
        (*protp->init)(0);
	if (protp->options != NULL) {
	    add_options(protp->options);
	}
    }

    /*
     * Install "generic" options into the extra_options list.
     */
    add_options(auth_options);
    add_options(general_options);

    /* Install any system-specific options (or remove unusable ones) */
    sys_options();

    if (!options_from_file(_PATH_SYSOPTIONS, !privileged, 0, 1)
	|| !options_from_user())
	exit(EXIT_OPTION_ERROR);

    /* scan command line and options files to find device name */
    prepass = 1;
    (void) parse_args(argc-1, argv+1);
    prepass = 0;

    /*
     * Work out the device name, if it hasn't already been specified.
     */
    using_pty = notty || ptycommand != NULL || pty_socket != NULL;
    if (!using_pty && default_device && !direct_tty) {
	char *p;

	if (!isatty(0) || (p = ttyname(0)) == NULL) {
	    option_error("no device specified and stdin is not a tty");
	    exit(EXIT_OPTION_ERROR);
	}
	(void) strlcpy(devnam, p, sizeof(devnam));
	if (stat(devnam, &devstat) < 0)
	    fatal("Couldn't stat default device %s: %m", devnam);
    }

    /*
     * Parse the tty options file and the command line.
     * The per-tty options file should not change
     * ptycommand, pty_socket, notty or devnam.
     */
    devnam_fixed = 1;
    if (!using_pty && !direct_tty) {
	if (!options_for_tty())
	    exit(EXIT_OPTION_ERROR);
    }

    devnam_fixed = 0;
    if (!parse_args(argc-1, argv+1))
	exit(EXIT_OPTION_ERROR);

    /*
     * Check that we are running as root.
     */
    if (geteuid() != 0) {
	option_error("must be root to run %s, since it is not setuid-root",
		     argv[0]);
	exit(EXIT_NOT_ROOT);
    }

    if (!ppp_available()) {
	option_error(no_ppp_msg);
	exit(EXIT_NO_KERNEL_SUPPORT);
    }

    /*
     * Check that the options given are valid and consistent.
     */
    if (!sys_check_options())
	exit(EXIT_OPTION_ERROR);
    auth_check_options();
#ifdef HAVE_MULTILINK
    mp_check_options();
#endif
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
	if (protp->enabled_flag && protp->check_options != NULL)
	    (*protp->check_options)();
    if (demand && (connect_script == NULL)) {
	option_error("connect script is required for demand-dialling\n");
	exit(EXIT_OPTION_ERROR);
    }
    if (updetach && (nodetach || demand)) {
	option_error("updetach cannot be used with %s",
	    nodetach ? "nodetach" : "demand");
	exit(EXIT_OPTION_ERROR);
    }
    /* default holdoff to 0 if no connect script has been given */
    if ((connect_script == NULL) && !holdoff_specified)
	holdoff = 0;

    if (using_pty || direct_tty) {
	if (!default_device) {
	    option_error("%s option precludes specifying device name",
			 notty? "notty": "pty");
	    exit(EXIT_OPTION_ERROR);
	}
	if (ptycommand != NULL && (notty || direct_tty)) {
	    option_error("pty option is incompatible with notty option");
	    exit(EXIT_OPTION_ERROR);
	}
	if (pty_socket != NULL && (ptycommand != NULL || notty ||
	    direct_tty)) {
	    option_error("socket option is incompatible with pty and notty");
	    exit(EXIT_OPTION_ERROR);
	}
	default_device = notty || direct_tty;
	lockflag = 0;
	modem = 0;
	if (default_device && log_to_fd <= 1)
	    log_to_fd = -1;
    } else {
	/*
	 * If the user has specified a device which is the same as
	 * the one on stdin, pretend they didn't specify any.
	 * If the device is already open read/write on stdin,
	 * we assume we don't need to lock it, and we can open it as root.
	 */
	if (fstat(0, &statbuf) >= 0 && S_ISCHR(statbuf.st_mode)
	    && statbuf.st_rdev == devstat.st_rdev) {
	    default_device = 1;
	    fdflags = fcntl(0, F_GETFL);
	    if (fdflags != -1 && (fdflags & O_ACCMODE) == O_RDWR)
		privopen = 1;
	}
    }
    if (default_device)
	nodetach = 1;

    /*
     * Don't send log messages to the serial port, it tends to
     * confuse the peer. :-)
     */
    if (log_to_fd >= 0 && fstat(log_to_fd, &statbuf) >= 0
	&& S_ISCHR(statbuf.st_mode) && statbuf.st_rdev == devstat.st_rdev)
	log_to_fd = -1;
    early_log = 0;

    if (debug)
	(void) setlogmask(LOG_UPTO(LOG_DEBUG));

    /*
     * Initialize system-dependent stuff.
     */
    if (check_options_hook != NULL &&
	(*check_options_hook)(uid) == -1) {
	exit(EXIT_OPTION_ERROR);
    }
    sys_init(!devnam_info.priv && !privopen);

#ifdef HAVE_MULTILINK
    pppdb = tdb_open(_PATH_PPPDB, 0, 0, O_RDWR|O_CREAT, 0644);
    if (pppdb != NULL) {
	(void) slprintf(db_key, sizeof(db_key), "pppd%d", getpid());
	update_db_entry();
    } else {
	warn("Warning: couldn't open ppp database %s", _PATH_PPPDB);
	if (multilink) {
	    warn("Warning: disabling multilink");
	    multilink = 0;
	}
    }
#endif

    /*
     * Detach ourselves from the terminal, if required, and identify
     * who is running us.  Printing to stderr stops here unless
     * nodetach or updetach is set.
     */
    if (!nodetach && !updetach)
	detach();
    p = getlogin();
    if (p == NULL) {
	pw = getpwuid(uid);
	if (pw != NULL && pw->pw_name != NULL)
	    p = pw->pw_name;
	else
	    p = "(unknown)";
    }
    syslog(LOG_NOTICE, "pppd %s.%d%s started by %s, uid %d",
	   VERSION, PATCHLEVEL, IMPLEMENTATION, p, uid);
    script_setenv("PPPLOGNAME", p, 0);

    if (devnam[0] != '\0')
	script_setenv("DEVICE", devnam, 1);
    (void) slprintf(numbuf, sizeof(numbuf), "%d", getpid());
    script_setenv("PPPD_PID", numbuf, 1);

    setup_signals();

    waiting = 0;

    create_linkpidfile();

    /*
     * If we're doing dial-on-demand, set up the interface now.
     */
    if (demand) {
	/*
	 * Open the loopback channel and set it up to be the ppp interface.
	 */
#ifdef HAVE_MULTILINK
	(void) tdb_writelock(pppdb);
#endif
	set_ifunit(1);
	fd_loop = open_ppp_loopback();
#ifdef HAVE_MULTILINK
	(void) tdb_writeunlock(pppdb);
#endif

	/*
	 * Configure the interface and mark it up, etc.
	 */
	demand_conf();
    }

    new_phase(PHASE_INITIALIZED);
    do_callback = 0;
    for (;;) {

	need_holdoff = 1;
	ttyfd = -1;
	real_ttyfd = -1;
	status = EXIT_OK;
	++unsuccess;
	doing_callback = do_callback;
	do_callback = 0;

	if (demand && !doing_callback) {
	    /*
	     * Don't do anything until we see some activity.
	     */
	    kill_link = 0;
	    new_phase(PHASE_DORMANT);
	    demand_unblock();
	    add_fd(fd_loop);
	    for (;;) {
		if (sigsetjmp(sigjmp, 1) == 0) {
		    (void) sigprocmask(SIG_BLOCK, &main_sigmask, NULL);
		    if (kill_link || got_sigchld) {
			(void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
		    } else {
			waiting = 1;
			(void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
			wait_input(timeleft(&timo));
		    }
		}
		waiting = 0;
		calltimeout();
		if (kill_link) {
		    if (!persist)
			break;
		    kill_link = 0;
		}
		if (get_loop_output())
		    break;
		if (got_sigchld)
		    (void) reap_kids(0);
	    }
	    remove_fd(fd_loop);
	    if (kill_link && !persist)
		break;

	    /*
	     * Now we want to bring up the link.
	     */
	    demand_block();
	    info("Starting link");
	}

	new_phase(doing_callback ? PHASE_CALLINGBACK : PHASE_SERIALCONN);

	/*
	 * Get a pty master/slave pair if the pty, notty, socket,
	 * or record options were specified.
	 */
	(void) strlcpy(ppp_devnam, devnam, sizeof(ppp_devnam));
	pty_master = -1;
	pty_slave = -1;
	if (using_pty || record_file != NULL) {
	    if (!get_pty(&pty_master, &pty_slave, ppp_devnam, uid)) {
		error("Couldn't allocate pseudo-tty");
		status = EXIT_FATAL_ERROR;
		goto fail;
	    }
	    set_up_tty(pty_slave, 1);
	}

	/*
	 * Lock the device if we've been asked to.
	 */
	status = EXIT_LOCK_FAILED;
	if (lockflag && !privopen && !direct_tty) {
	    if (lock(devnam) < 0)
		goto fail;
	    locked = 1;
	}

	/*
	 * Open the serial device and set it up to be the ppp interface.
	 * First we open it in non-blocking mode so we can set the
	 * various termios flags appropriately.  If we aren't dialling
	 * out and we want to use the modem lines, we reopen it later
	 * in order to wait for the carrier detect signal from the modem.
	 */
	hungup = 0;
	kill_link = 0;
	connector = doing_callback? callback_script: connect_script;
	if (direct_tty) {
	    ttyfd = 0;
	} else if (devnam[0] != '\0') {
	    for (;;) {
		/* If the user specified the device name, become the
		   user before opening it. */
		int err;
		if (!devnam_info.priv && !privopen)
		    (void) seteuid(uid);
		if ((ttyfd = sys_extra_fd()) < 0)
		    ttyfd = open(devnam, O_NONBLOCK | O_RDWR);
		err = errno;
		if (!devnam_info.priv && !privopen)
		    (void) seteuid(0);
		if (ttyfd >= 0)
		    break;
		errno = err;
		if (err != EINTR) {
		    error("Failed to open %s: %m", devnam);
		    status = EXIT_OPEN_FAILED;
		}
		if (!persist || err != EINTR)
		    goto fail;
	    }
	    if ((fdflags = fcntl(ttyfd, F_GETFL)) == -1
		|| fcntl(ttyfd, F_SETFL, fdflags & ~O_NONBLOCK) < 0)
		warn("Couldn't reset non-blocking mode on device: %m");

	    /*
	     * Do the equivalent of `mesg n' to stop broadcast messages.
	     */
	    if (fstat(ttyfd, &statbuf) < 0
		|| fchmod(ttyfd, statbuf.st_mode & ~(S_IWGRP | S_IWOTH)) < 0) {
		warn("Couldn't restrict write permissions to %s: %m", devnam);
	    } else
		tty_mode = statbuf.st_mode;

	    /*
	     * Set line speed, flow control, etc.
	     * If we have a non-null connection or initializer script,
	     * on most systems we set CLOCAL for now so that we can talk
	     * to the modem before carrier comes up.  But this has the
	     * side effect that we might miss it if CD drops before we
	     * get to clear CLOCAL below.  On systems where we can talk
	     * successfully to the modem with CLOCAL clear and CD down,
	     * we could clear CLOCAL at this point.
	     */
	    set_up_tty(ttyfd, ((connector != NULL && connector[0] != '\0')
			       || initializer != NULL));
	    real_ttyfd = ttyfd;
	}

	/*
	 * If the pty, socket, notty and/or record option was specified,
	 * start up the character shunt now.
	 */
	status = EXIT_PTYCMD_FAILED;
	if (ptycommand != NULL) {
	    if (record_file != NULL) {
		int ipipe[2], opipe[2], ok;

		if (pipe(ipipe) < 0 || pipe(opipe) < 0)
		    fatal("Couldn't create pipes for record option: %m");
		dbglog("starting charshunt for pty option");
		ok = device_script(ptycommand, opipe[0], ipipe[1], 1,
		    "record") == 0 && start_charshunt(ipipe[0], opipe[1]);
		(void) close(ipipe[0]);
		(void) close(ipipe[1]);
		(void) close(opipe[0]);
		(void) close(opipe[1]);
		if (!ok)
		    goto fail;
	    } else {
		if (device_script(ptycommand, pty_master, pty_master, 1,
		    "pty") < 0)
		    goto fail;
		ttyfd = pty_slave;
		(void) close(pty_master);
		pty_master = -1;
	    }
	} else if (pty_socket != NULL) {
	    int fd = open_socket(pty_socket);
	    if (fd < 0)
		goto fail;
	    dbglog("starting charshunt for socket option");
	    if (!start_charshunt(fd, fd))
		goto fail;
	} else if (notty) {
	    dbglog("starting charshunt for notty option");
	    if (!start_charshunt(0, 1))
		goto fail;
	} else if (record_file != NULL) {
	    dbglog("starting charshunt for record option");
	    if (!start_charshunt(ttyfd, ttyfd))
		goto fail;
	}

	/* run connection script */
	if (((connector != NULL) && (connector[0] != '\0')) || initializer) {
	    if (real_ttyfd != -1) {
		/* XXX do this if doing_callback == CALLBACK_DIALIN? */
		if (!default_device && modem && !direct_tty) {
		    setdtr(real_ttyfd, 0);	/* in case modem is off hook */
		    (void) sleep(1);
		    setdtr(real_ttyfd, 1);
		}
	    }

	    if ((initializer != NULL) && (initializer[0] != '\0')) {
		if (device_script(initializer, ttyfd, ttyfd, 0, "init") < 0) {
		    error("Initializer script failed");
		    status = EXIT_INIT_FAILED;
		    goto fail;
		}
		if (kill_link)
		    goto disconnect;

		info("Serial port initialized.");
	    }

	    if ((connector != NULL) && (connector[0] != '\0')) {
		if (device_script(connector, ttyfd, ttyfd, 0, "connect") < 0) {
		    error("Connect script failed");
		    status = EXIT_CONNECT_FAILED;
		    goto fail;
		}
		if (kill_link)
		    goto disconnect;

		info("Serial connection established.");
	    }

	    /*
	     * Clear CLOCAL if modem option -- we now have carrier
	     * established, and we should respect loss of carrier.
	     */
	    if (real_ttyfd != -1)
		set_up_tty(real_ttyfd, 0);

	    if (doing_callback == CALLBACK_DIALIN)
		connector = NULL;
	}

	/* reopen tty if necessary to wait for carrier */
	if (connector == NULL && modem && devnam[0] != '\0' && !direct_tty) {
	    for (;;) {
		if ((i = open(devnam, O_RDWR)) >= 0)
		    break;
		if (errno != EINTR) {
		    error("Failed to reopen %s: %m", devnam);
		    status = EXIT_OPEN_FAILED;
		}
		if (!persist || errno != EINTR || hungup || kill_link)
		    goto fail;
	    }
	    (void) close(i);
	}

	(void) slprintf(numbuf, sizeof(numbuf), "%d", baud_rate);
	script_setenv("SPEED", numbuf, 0);

	/* run welcome script, if any */
	if ((welcomer != NULL) && (welcomer[0] != '\0')) {
	    if (device_script(welcomer, ttyfd, ttyfd, 0, "welcome") < 0)
		warn("Welcome script failed");
	}

	/* set up the serial device as a ppp interface */
#ifdef HAVE_MULTILINK
	(void) tdb_writelock(pppdb);
#endif
	fd_ppp = establish_ppp(ttyfd);
	if (fd_ppp < 0) {
#ifdef HAVE_MULTILINK
	    (void) tdb_writeunlock(pppdb);
#endif
	    status = EXIT_FATAL_ERROR;
	    goto disconnect;
	}

	if (!demand && ifunit >= 0)
	    set_ifunit(1);
#ifdef HAVE_MULTILINK
	(void) tdb_writeunlock(pppdb);
#endif

	/*
	 * Start opening the connection and wait for
	 * incoming events (reply, timeout, etc.).
	 */
	notice("Connect: %s <--> %s", ifname, ppp_devnam);
	(void) gettimeofday(&start_time, NULL);
	link_stats_valid = 0;
	script_unsetenv("CONNECT_TIME");
	script_unsetenv("BYTES_SENT");
	script_unsetenv("BYTES_RCVD");
	lcp_lowerup(0);

	/* Mostly for accounting purposes */
	new_phase(PHASE_CONNECTED);

	/*
	 * If we are initiating this connection, wait for a short
	 * time for something from the peer.  This can avoid bouncing
	 * our packets off its tty before it has set up the tty.
	 */
	add_fd(fd_ppp);
	if (connect_delay != 0 && (connector != NULL || ptycommand != NULL)) {
	    struct timeval t;
	    t.tv_sec = connect_delay / 1000;
	    t.tv_usec = connect_delay % 1000;
	    wait_input(&t);
	}

	lcp_open(0);		/* Start protocol */
	open_ccp_flag = 0;
	status = EXIT_NEGOTIATION_FAILED;
	new_phase(PHASE_ESTABLISH);
	while (phase != PHASE_DEAD) {
	    if (sigsetjmp(sigjmp, 1) == 0) {
		(void) sigprocmask(SIG_BLOCK, &main_sigmask, NULL);
		if (kill_link || open_ccp_flag || got_sigchld) {
		    (void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
		} else {
		    waiting = 1;
		    (void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
		    wait_input(timeleft(&timo));
		}
	    }
	    waiting = 0;
	    calltimeout();
	    get_input();
	    if (kill_link) {
		lcp_close(0, "User request");
		kill_link = 0;
	    }
	    if (open_ccp_flag) {
		if (phase == PHASE_NETWORK || phase == PHASE_RUNNING) {
		    /* Uncloak ourselves. */
		    ccp_fsm[0].flags &= ~OPT_SILENT;
		    (*ccp_protent.open)(0);
		}
		open_ccp_flag = 0;
	    }
	    if (got_sigchld)
		(void) reap_kids(0);	/* Don't leave dead kids lying around */
	}

	/*
	 * Print connect time and statistics.
	 */
	if (link_stats_valid) {
	    int t = (link_connect_time + 5) / 6;    /* 1/10ths of minutes */
	    info("Connect time %d.%d minutes.", t/10, t%10);
	    info("Sent %" PPP_COUNTER_F " bytes (%" PPP_COUNTER_F
		" packets), received %" PPP_COUNTER_F " bytes (%" PPP_COUNTER_F
		" packets).",
		 link_stats.bytes_out, link_stats.pkts_out,
		 link_stats.bytes_in, link_stats.pkts_in);
	}

	/*
	 * Delete pid file before disestablishing ppp.  Otherwise it
	 * can happen that another pppd gets the same unit and then
	 * we delete its pid file.
	 */
	if (!demand) {
	    if (pidfilename[0] != '\0'
		&& unlink(pidfilename) < 0 && errno != ENOENT)
		warn("unable to delete pid file %s: %m", pidfilename);
	    pidfilename[0] = '\0';
	}

	/*
	 * If we may want to bring the link up again, transfer
	 * the ppp unit back to the loopback.  Set the
	 * real serial device back to its normal mode of operation.
	 */
	remove_fd(fd_ppp);
	clean_check();
	if (demand)
	    restore_loop();
	disestablish_ppp(ttyfd);
	fd_ppp = -1;
	if (!hungup)
	    lcp_lowerdown(0);
	if (!demand)
	    script_unsetenv("IFNAME");

	/*
	 * Run disconnector script, if requested.
	 * XXX we may not be able to do this if the line has hung up!
	 */
    disconnect:
	if ((disconnect_script != NULL) && (disconnect_script[0] != '\0') &&
	    !hungup) {
	    new_phase(PHASE_DISCONNECT);
	    if (real_ttyfd >= 0)
		set_up_tty(real_ttyfd, 1);
	    if (device_script(disconnect_script, ttyfd, ttyfd, 0,
		"disconnect") < 0) {
		warn("disconnect script failed");
	    } else {
		info("Serial link disconnected.");
	    }
	}

    fail:
	if (pty_master >= 0)
	    (void) close(pty_master);
	if (pty_slave >= 0) {
	    (void) close(pty_slave);
	    pty_slave = -1;
	}
	if (real_ttyfd >= 0)
	    close_tty();
	if (locked) {
	    locked = 0;
	    unlock();
	}

	if (!demand) {
	    if (pidfilename[0] != '\0'
		&& unlink(pidfilename) < 0 && errno != ENOENT)
		warn("unable to delete pid file %s: %m", pidfilename);
	    pidfilename[0] = '\0';
	}

	if (!persist || (maxfail > 0 && unsuccess >= maxfail))
	    break;

	kill_link = 0;
	if (demand)
	    demand_discard();
	t = need_holdoff? holdoff: 0;
	if (holdoff_hook != NULL)
	    t = (*holdoff_hook)();
	if (t > 0) {
	    new_phase(PHASE_HOLDOFF);
	    TIMEOUT(holdoff_end, NULL, t);
	    do {
		if (sigsetjmp(sigjmp, 1) == 0) {
		    (void) sigprocmask(SIG_BLOCK, &main_sigmask, NULL);
		    if (kill_link || got_sigchld) {
			(void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
		    } else {
			waiting = 1;
			(void) sigprocmask(SIG_UNBLOCK, &main_sigmask, NULL);
			wait_input(timeleft(&timo));
		    }
		}
		waiting = 0;
		calltimeout();
		if (kill_link) {
		    kill_link = 0;
		    new_phase(PHASE_DORMANT); /* allow signal to end holdoff */
		}
		if (got_sigchld)
		    (void) reap_kids(0);
	    } while (phase == PHASE_HOLDOFF);
	    if (!persist)
		break;
	}
    }

    /* Wait for scripts to finish */
    final_reap();

    die(status);
    return (0);
}

/*
 * setup_signals - initialize signal handling.
 */
static void
setup_signals()
{
    struct sigaction sa;

    /*
     * Compute mask of all interesting signals and install signal handlers
     * for each.  Only one signal handler may be active at a time.  Therefore,
     * all other signals should be masked when any handler is executing.
     */
    (void) sigemptyset(&main_sigmask);
    (void) sigaddset(&main_sigmask, SIGHUP);
    (void) sigaddset(&main_sigmask, SIGINT);
    (void) sigaddset(&main_sigmask, SIGTERM);
    (void) sigaddset(&main_sigmask, SIGCHLD);
    (void) sigaddset(&main_sigmask, SIGUSR2);

#define SIGNAL(s, handler)	if (1) { \
	sa.sa_handler = handler; \
	if (sigaction(s, &sa, NULL) < 0) \
	    fatal("Couldn't establish signal handler (%d): %m", s); \
    } else ((void)0)

    sa.sa_mask = main_sigmask;
    sa.sa_flags = 0;
/*CONSTANTCONDITION*/ SIGNAL(SIGHUP, hup);		/* Hangup */
/*CONSTANTCONDITION*/ SIGNAL(SIGINT, term);		/* Interrupt */
/*CONSTANTCONDITION*/ SIGNAL(SIGTERM, term);		/* Terminate */
/*CONSTANTCONDITION*/ SIGNAL(SIGCHLD, chld);

/*CONSTANTCONDITION*/ SIGNAL(SIGUSR1, toggle_debug);	/* Toggle debug flag */
/*CONSTANTCONDITION*/ SIGNAL(SIGUSR2, open_ccp);	/* Reopen CCP */

    /*
     * Install a handler for other signals which would otherwise
     * cause pppd to exit without cleaning up.
     */
/*CONSTANTCONDITION*/ SIGNAL(SIGALRM, bad_signal);
/*CONSTANTCONDITION*/ SIGNAL(SIGQUIT, bad_signal);

/* Do not hook any of these signals on Solaris; allow core dump instead */
#ifndef SOL2
/*CONSTANTCONDITION*/ SIGNAL(SIGABRT, bad_signal);
/*CONSTANTCONDITION*/ SIGNAL(SIGFPE, bad_signal);
/*CONSTANTCONDITION*/ SIGNAL(SIGILL, bad_signal);
#ifndef DEBUG
/*CONSTANTCONDITION*/ SIGNAL(SIGSEGV, bad_signal);
#endif
#ifdef SIGBUS
/*CONSTANTCONDITION*/ SIGNAL(SIGBUS, bad_signal);
#endif
#ifdef SIGEMT
/*CONSTANTCONDITION*/ SIGNAL(SIGEMT, bad_signal);
#endif
#ifdef SIGPOLL
/*CONSTANTCONDITION*/ SIGNAL(SIGPOLL, bad_signal);
#endif
#ifdef SIGPROF
/*CONSTANTCONDITION*/ SIGNAL(SIGPROF, bad_signal);
#endif
#ifdef SIGSYS
/*CONSTANTCONDITION*/ SIGNAL(SIGSYS, bad_signal);
#endif
#ifdef SIGTRAP
/*CONSTANTCONDITION*/ SIGNAL(SIGTRAP, bad_signal);
#endif
#ifdef SIGVTALRM
/*CONSTANTCONDITION*/ SIGNAL(SIGVTALRM, bad_signal);
#endif
#ifdef SIGXCPU
/*CONSTANTCONDITION*/ SIGNAL(SIGXCPU, bad_signal);
#endif
#ifdef SIGXFSZ
/*CONSTANTCONDITION*/ SIGNAL(SIGXFSZ, bad_signal);
#endif
#endif

    /*
     * Apparently we can get a SIGPIPE when we call syslog, if
     * syslogd has died and been restarted.  Ignoring it seems
     * be sufficient.
     */
    (void) signal(SIGPIPE, SIG_IGN);
}

/*
 * set_ifunit - do things we need to do once we know which ppp
 * unit we are using.
 */
void
set_ifunit(iskey)
    int iskey;
{
    sys_ifname();
    info("Using interface %s", ifname);
    script_setenv("IFNAME", ifname, iskey);
    if (iskey) {
	create_pidfile();	/* write pid to file */
	create_linkpidfile();
    }
}

/*
 * detach - detach us from the controlling terminal.
 */
void
detach()
{
    pid_t pid;
    char numbuf[16];

    if (detached)
	return;
    if ((pid = fork()) == (pid_t)-1) {
	error("Couldn't detach (fork failed: %m)");
	die(1);			/* or just return? */
    }
    if (pid != (pid_t)0) {
	/* parent */
	if (locked)
	    (void) relock(pid);
	exit(0);		/* parent dies */
    }
    (void) setsid();
	/*
	 * Fork again to relinquish session leadership. This is needed
	 * to prevent the daemon from acquiring controlling terminal.
	 */
    if ((pid = fork()) == (pid_t)-1) {
	error("Couldn't detach (second fork failed: %m)");
	die(1);			/* or just return? */
    }
    if (pid != (pid_t)0) {
	/* parent */
	if (locked)
	    (void) relock(pid);
	exit(0);		/* parent dies */
    }
    (void) chdir("/");
    (void) close(0);
    (void) close(1);
    (void) close(2);
    detached = 1;
    if (!log_to_file && !log_to_specific_fd)
	log_to_fd = -1;
    /* update pid files if they have been written already */
    if (pidfilename[0] != '\0')
	create_pidfile();
    if (linkpidfile[0] != '\0')
	create_linkpidfile();
    (void) slprintf(numbuf, sizeof(numbuf), "%d", getpid());
    script_setenv("PPPD_PID", numbuf, 1);
}

/*
 * reopen_log - (re)open our connection to syslog.
 */
void
reopen_log()
{
#ifdef ULTRIX
    openlog("pppd", LOG_PID);
#else
    openlog("pppd", LOG_PID | LOG_NDELAY, LOG_PPP);
    (void) setlogmask(LOG_UPTO(LOG_INFO));
#endif
}

/*
 * Create a file containing our process ID.
 */
static void
create_pidfile()
{
    FILE *pidfile;

    (void) slprintf(pidfilename, sizeof(pidfilename), "%s%s.pid",
	     _PATH_VARRUN, ifname);
    if ((pidfile = fopen(pidfilename, "w")) != NULL) {
	(void) fprintf(pidfile, "%u\n", (unsigned)getpid());
	(void) fclose(pidfile);
    } else {
	error("Failed to create pid file %s: %m", pidfilename);
	pidfilename[0] = '\0';
    }
}

static void
create_linkpidfile()
{
    FILE *pidfile;

    if (linkname[0] == '\0')
	return;
    script_setenv("LINKNAME", linkname, 1);
    (void) slprintf(linkpidfile, sizeof(linkpidfile), "%sppp-%s.pid",
	     _PATH_VARRUN, linkname);
    if ((pidfile = fopen(linkpidfile, "w")) != NULL) {
	(void) fprintf(pidfile, "%u\n", (unsigned)getpid());
	if (ifname[0] != '\0')
	    (void) fprintf(pidfile, "%s\n", ifname);
	(void) fclose(pidfile);
    } else {
	error("Failed to create pid file %s: %m", linkpidfile);
	linkpidfile[0] = '\0';
    }
}

/*
 * holdoff_end - called via a timeout when the holdoff period ends.
 */
/*ARGSUSED*/
static void
holdoff_end(arg)
    void *arg;
{
    new_phase(PHASE_DORMANT);
}

/* List of protocol names, to make our messages a little more informative. */
struct protocol_list {
    u_short	proto;
    const char	*name;
} protocol_list[] = {
    { 0x21,	"IP" },
    { 0x23,	"OSI Network Layer" },
    { 0x25,	"Xerox NS IDP" },
    { 0x27,	"DECnet Phase IV" },
    { 0x29,	"Appletalk" },
    { 0x2b,	"Novell IPX" },
    { 0x2d,	"VJ compressed TCP/IP" },
    { 0x2f,	"VJ uncompressed TCP/IP" },
    { 0x31,	"Bridging PDU" },
    { 0x33,	"Stream Protocol ST-II" },
    { 0x35,	"Banyan Vines" },
    { 0x37,	"Old VJ compressed TCP/IP" },
    { 0x39,	"AppleTalk EDDP" },
    { 0x3b,	"AppleTalk SmartBuffered" },
    { 0x3d,	"Multilink" },
    { 0x3f,	"NetBIOS Frame" },
    { 0x41,	"Cisco LAN Extension" },
    { 0x43,	"Ascom Timeplex" },
    { 0x45,	"Fujitsu Link Backup and Load Balancing (LBLB)" },
    { 0x47,	"DCA Remote Lan" },
    { 0x49,	"Serial Data Transport Protocol (PPP-SDTP)" },
    { 0x4b,	"SNA over 802.2" },
    { 0x4d,	"SNA" },
    { 0x4f,	"IP6 Header Compression" },
    { 0x51,	"KNX Bridging" },
    { 0x53,	"Encrypted" },
    { 0x55,	"per-link encrypted" },
    { 0x57,	"IPv6" },
    { 0x59,	"PPP Muxing" },
    { 0x6f,	"Stampede Bridging" },
    { 0x73,	"MP+" },
    { 0xc1,	"STMF" },
    { 0xfb,	"per-link compressed" },
    { 0xfd,	"compressed datagram" },
    { 0x0201,	"802.1d Hello Packets" },
    { 0x0203,	"IBM Source Routing BPDU" },
    { 0x0205,	"DEC LANBridge100 Spanning Tree" },
    { 0x0207,	"Cisco Discovery Protocol" },
    { 0x0231,	"Luxcom" },
    { 0x0233,	"Sigma Network Systems" },
    { 0x0235,	"Apple Client Server Protocol" },
    { 0x0281,	"MPLS Unicast" },
    { 0x0283,	"MPLS Multicast" },
    { 0x0285,	"IEEE p1284.4" },
    { 0x0287,	"ETSI TETRA TNP1" },
    { 0x4021,	"Stacker LZS" },
    { 0x8021,	"Internet Protocol Control Protocol" },
    { 0x8023,	"OSI Network Layer Control Protocol" },
    { 0x8025,	"Xerox NS IDP Control Protocol" },
    { 0x8027,	"DECnet Phase IV Control Protocol" },
    { 0x8029,	"Appletalk Control Protocol" },
    { 0x802b,	"Novell IPX Control Protocol" },
    { 0x8031,	"Bridging Control Protocol" },
    { 0x8033,	"Stream Protocol Control Protocol" },
    { 0x8035,	"Banyan Vines Control Protocol" },
    { 0x803f,	"NetBIOS Frames Control Protocol" },
    { 0x8041,	"Cisco LAN Extension Control Protocol" },
    { 0x8043,	"Ascom Timeplex Control Protocol" },
    { 0x8045,	"Fujitsu LBLB Control Protocol" },
    { 0x8047,	"DCA Remote Lan Network Control Protocol (RLNCP)" },
    { 0x8049,	"Serial Data Control Protocol (PPP-SDCP)" },
    { 0x804b,	"SNA over 802.2 Control Protocol" },
    { 0x804d,	"SNA Control Protocol" },
    { 0x8051,	"KNX Bridging Control Protocol" },
    { 0x8053,	"Encryption Control Protocol" },
    { 0x8055,	"Per-link Encryption Control Protocol" },
    { 0x8057,	"IPv6 Control Protocol" },
    { 0x806f,	"Stampede Bridging Control Protocol" },
    { 0x80c1,	"STMF Control Protocol" },
    { 0x80fb,	"Per-link Compression Control Protocol" },
    { 0x80fd,	"Compression Control Protocol" },
    { 0x8207,	"Cisco Discovery Control Protocol" },
    { 0x8235,	"Apple Client Server Control Protocol" },
    { 0x8281,	"MPLS Control Protocol" },
    { 0x8287,	"ETSI TETRA TNP1 Control Protocol" },
    { 0xc021,	"Link Control Protocol" },
    { 0xc023,	"Password Authentication Protocol" },
    { 0xc025,	"Link Quality Report" },
    { 0xc027,	"Shiva Password Authentication Protocol" },
    { 0xc029,	"CallBack Control Protocol (CBCP)" },
    { 0xc02b,	"Bandwidth Allocation Control Protocol" },
    { 0xc02d,	"BAP" },
    { 0xc081,	"Container Control Protocol" },
    { 0xc223,	"Challenge Handshake Authentication Protocol" },
    { 0xc227,	"Extensible Authentication Protocol" },
    { 0xc281,	"Funk Proprietary Authentication Protocol" },
    { 0,	NULL },
};

/*
 * protocol_name - find a name for a PPP protocol.
 */
const char *
protocol_name(proto)
    int proto;
{
    struct protocol_list *lp;

    for (lp = protocol_list; lp->proto != 0; ++lp)
	if (proto == lp->proto)
	    return (lp->name);
    return (NULL);
}

static const char *phase_names[] = { PHASE__NAMES };

const char *
phase_name(pval)
    int pval;
{
    static char buf[32];

    if (pval < 0 || pval >= Dim(phase_names)) {
	(void) slprintf(buf, sizeof (buf), "unknown %d", pval);
	return ((const char *)buf);
    }
    return (phase_names[pval]);
}

/*
 * get_input - called when incoming data is available.
 */
static void
get_input()
{
    int len, i;
    u_char *p;
    u_short protocol;
    struct protent *protp;
    const char *pname;

    p = inpacket_buf;	/* point to beginning of packet buffer */

    len = read_packet(inpacket_buf);
    if (len < 0)
	return;

    if (len == 0) {
	notice("Modem hangup");
	hungup = 1;
	status = EXIT_HANGUP;
	lcp_lowerdown(0);	/* serial link is no longer available */
	link_terminated(0);
	return;
    }

    if (debug /*&& (debugflags & DBG_INPACKET)*/)
	dbglog("rcvd %P", p, len);

    if (len < PPP_HDRLEN) {
	dbglog("Discarded short packet (%d < %d)", len, PPP_HDRLEN);
	return;
    }

    p += 2;				/* Skip address and control */
    GETSHORT(protocol, p);
    len -= PPP_HDRLEN;

    pname = debug ? NULL : protocol_name(protocol);

    /*
     * Toss all non-LCP packets unless LCP is in Opened state and
     * discard non-authentication protocols if we're not yet
     * authenticated.
     */
    if ((protocol != PPP_LCP &&
	(phase < PHASE_AUTHENTICATE || phase > PHASE_RUNNING)) ||
	(phase <= PHASE_AUTHENTICATE &&
	    !(protocol == PPP_LCP || protocol == PPP_LQR ||
		protocol == PPP_PAP || protocol == PPP_CHAP))) {
	    if (pname == NULL)
		    dbglog("Discarded proto 0x%x in %s phase",
			protocol, phase_name(phase));
	    else
		    dbglog("Discarded %s (0x%x) in %s phase",
			pname, protocol, phase_name(phase));
	return;
    }

    /*
     * Upcall the proper protocol input routine.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i) {
	if (protp->protocol == protocol && protp->enabled_flag) {
	    (*protp->input)(0, p, len);
	    return;
	}
        if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag
	    && protp->datainput != NULL) {
	    (*protp->datainput)(0, p, len);
	    return;
	}
    }

    if (debug) {
	if (pname != NULL)
	    warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
	else
	    warn("Unsupported protocol 0x%x received", protocol);
    }
    lcp_sprotrej(0, p - PPP_HDRLEN, len + PPP_HDRLEN);
}

/*
 * new_phase - signal the start of a new phase of pppd's operation.
 */
void
new_phase(p)
    int p;
{
    if (new_phase_hook != NULL)
	(*new_phase_hook)(p, phase);
    phase = p;
}

/*
 * die - clean up state and exit with the specified status.
 */
void
die(status)
    int status;
{
    cleanup();
    if (phase != PHASE_EXIT) {
	syslog(LOG_INFO, "Exit.");
	new_phase(PHASE_EXIT);
    }
    exit(status);
}

/*
 * cleanup - restore anything which needs to be restored before we exit
 */
static void
cleanup()
{
    sys_cleanup();  /* XXX: Need to check if this is okay after close_tty */

    if (fd_ppp >= 0) {
	fd_ppp = -1;
	disestablish_ppp(ttyfd);
    }
    if (real_ttyfd >= 0)
	close_tty();

    if (pidfilename[0] != '\0' && unlink(pidfilename) < 0 && errno != ENOENT)
	warn("unable to delete pid file %s: %m", pidfilename);
    pidfilename[0] = '\0';
    if (linkpidfile[0] != '\0' && unlink(linkpidfile) < 0 && errno != ENOENT)
	warn("unable to delete pid file %s: %m", linkpidfile);
    linkpidfile[0] = '\0';

    if (locked) {
	locked = 0;
	unlock();
    }

#ifdef HAVE_MULTILINK
    if (pppdb != NULL) {
	cleanup_db();
	pppdb = NULL;
    }
#endif
}

/*
 * close_tty - restore the terminal device and close it.
 */
static void
close_tty()
{
    int fd = real_ttyfd;

    real_ttyfd = -1;

    /* drop dtr to hang up */
    if (!default_device && modem) {
	setdtr(fd, 0);
	/*
	 * This sleep is in case the serial port has CLOCAL set by default,
	 * and consequently will reassert DTR when we close the device.
	 */
	(void) sleep(1);
    }

    restore_tty(fd);

    if (tty_mode != (mode_t) -1) {
	if (fchmod(fd, tty_mode) != 0) {
	    /* XXX if devnam is a symlink, this will change the link */
	    if (chmod(devnam, tty_mode) != 0) {
		error("Unable to chmod file %s: %m", devnam);
	    }
	}
    }

    (void) close(fd);
}

/*
 * update_link_stats - get stats at link termination.
 */
void
update_link_stats(u)
    int u;
{
    struct timeval now;
    char numbuf[32];

    if (gettimeofday(&now, NULL) >= 0) {
	link_connect_time = now.tv_sec - start_time.tv_sec;
	(void) slprintf(numbuf, sizeof(numbuf), "%d", link_connect_time);
	script_setenv("CONNECT_TIME", numbuf, 0);
    } else {
	link_connect_time = 0;
    }

    if (get_ppp_stats(u, &link_stats)) {
	(void) slprintf(numbuf, sizeof(numbuf), "%" PPP_COUNTER_F,
	    link_stats.bytes_out);
	script_setenv("BYTES_SENT", numbuf, 0);
	(void) slprintf(numbuf, sizeof(numbuf), "%" PPP_COUNTER_F,
	    link_stats.bytes_in);
	script_setenv("BYTES_RCVD", numbuf, 0);
	(void) slprintf(numbuf, sizeof(numbuf), "%" PPP_COUNTER_F,
	    link_stats.pkts_in);
	script_setenv("PKTS_RCVD", numbuf, 0);
	(void) slprintf(numbuf, sizeof(numbuf), "%" PPP_COUNTER_F,
	    link_stats.pkts_out);
	script_setenv("PKTS_SENT", numbuf, 0);
	link_stats_valid = 1;
    }
}


struct	callout {
    struct timeval	c_time;		/* time at which to call routine */
    void		*c_arg;		/* argument to routine */
    void		(*c_func) __P((void *)); /* routine */
    struct		callout *c_next;
};

static struct callout *callout = NULL;	/* Callout list */
static struct timeval timenow;		/* Current time */

/*
 * timeout - Schedule a timeout.
 *
 * Note that this timeout takes the number of seconds, NOT hz (as in
 * the kernel).
 */
void
timeout(func, arg, time)
    void (*func) __P((void *));
    void *arg;
    int time;
{
    struct callout *newp, *p, **pp;

    MAINDEBUG(("Timeout %p:%p in %d seconds.", func, arg, time));

    /*
     * Allocate timeout.
     */
    if ((newp = (struct callout *) malloc(sizeof(struct callout))) == NULL)
	novm("callout structure for timeout.");
    newp->c_arg = arg;
    newp->c_func = func;
    (void) gettimeofday(&timenow, NULL);
    newp->c_time.tv_sec = timenow.tv_sec + time;
    newp->c_time.tv_usec = timenow.tv_usec;

    /*
     * Find correct place and link it in.
     */
    for (pp = &callout; (p = *pp) != NULL; pp = &p->c_next)
	if (newp->c_time.tv_sec < p->c_time.tv_sec
	    || (newp->c_time.tv_sec == p->c_time.tv_sec
		&& newp->c_time.tv_usec < p->c_time.tv_usec))
	    break;
    newp->c_next = p;
    *pp = newp;
}


/*
 * untimeout - Unschedule a timeout.
 */
void
untimeout(func, arg)
    void (*func) __P((void *));
    void *arg;
{
    struct callout **copp, *freep;

    MAINDEBUG(("Untimeout %p:%p.", func, arg));

    /*
     * Find first matching timeout and remove it from the list.
     */
    for (copp = &callout; (freep = *copp) != NULL; copp = &freep->c_next)
	if (freep->c_func == func && freep->c_arg == arg) {
	    *copp = freep->c_next;
	    free((char *) freep);
	    break;
	}
}


/*
 * calltimeout - Call any timeout routines which are now due.
 */
static void
calltimeout()
{
    struct callout *p;

    while (callout != NULL) {
	p = callout;

	if (gettimeofday(&timenow, NULL) < 0)
	    fatal("Failed to get time of day: %m");
	if (!(p->c_time.tv_sec < timenow.tv_sec
	      || (p->c_time.tv_sec == timenow.tv_sec
		  && p->c_time.tv_usec <= timenow.tv_usec)))
	    break;		/* no, it's not time yet */

	callout = p->c_next;
	(*p->c_func)(p->c_arg);

	free((char *) p);
    }
}


/*
 * timeleft - return the length of time until the next timeout is due.
 */
static struct timeval *
timeleft(tvp)
    struct timeval *tvp;
{
    if (callout == NULL)
	return (NULL);

    (void) gettimeofday(&timenow, NULL);
    tvp->tv_sec = callout->c_time.tv_sec - timenow.tv_sec;
    tvp->tv_usec = callout->c_time.tv_usec - timenow.tv_usec;
    if (tvp->tv_usec < 0) {
	tvp->tv_usec += 1000000;
	tvp->tv_sec -= 1;
    }
    if (tvp->tv_sec < 0)
	tvp->tv_sec = tvp->tv_usec = 0;

    return (tvp);
}


/*
 * kill_my_pg - send a signal to our process group, and ignore it ourselves.
 */
static void
kill_my_pg(sig)
    int sig;
{
    struct sigaction act, oldact;
    sigset_t mask;

    BZERO(&act, sizeof (act));
    act.sa_handler = SIG_IGN;
    (void) sigemptyset(&mask);
    (void) sigaddset(&mask, sig);
    /*
     * Ignore signal 'sig' temporarily, before finally re-activating the
     * original handler.  We need to do it in the following sequence, since
     * otherwise the signal handler for 'sig' will be called forever.
     */
    if (sigaction(sig, &act, &oldact) < 0) {
	fatal("kill_my_pg: couldn't establish signal handler (%d): %m", sig);
    }
    (void) sigprocmask(SIG_UNBLOCK, &mask, NULL);
    /*
     * Send signal 'sig' to all processes whose process group ID is equal
     * to the process group ID of the sender.
     */
    (void) kill(0, sig);
    if (sigaction(sig, &oldact, NULL) < 0) {
	fatal("kill_my_pg: couldn't establish signal handler (%d): %m", sig);
    }
}


/*
 * hup - Catch SIGHUP signal.
 *
 * Indicates that the physical layer has been disconnected.
 * We don't rely on this indication; if the user has sent this
 * signal, we just take the link down.
 */
static void
hup(sig)
    int sig;
{
    info("Hangup (SIGHUP)");
    kill_link = 1;
    if (status != EXIT_HANGUP)
	status = EXIT_USER_REQUEST;
    if (conn_running > 0)
	/* Send the signal to the [dis]connector process(es) also */
	kill_my_pg(sig);
    if (charshunt_pid)
	(void) kill(charshunt_pid, sig);
    if (waiting)
	siglongjmp(sigjmp, 1);
}


/*
 * term - Catch SIGTERM signal and SIGINT signal (^C/del).
 *
 * Indicates that we should initiate a graceful disconnect and exit.
 */
/*ARGSUSED*/
static void
term(sig)
    int sig;
{
    info("Terminating on signal %d.", sig);
    persist = 0;		/* don't try to restart */
    kill_link = 1;
    status = EXIT_USER_REQUEST;
    if (conn_running > 0)
	/* Send the signal to the [dis]connector process(es) also */
	kill_my_pg(sig);
    if (charshunt_pid)
	(void) kill(charshunt_pid, sig);
    if (waiting)
	siglongjmp(sigjmp, 1);
}


/*
 * chld - Catch SIGCHLD signal.
 * Sets a flag so we will call reap_kids in the mainline.
 */
/*ARGSUSED*/
static void
chld(sig)
    int sig;
{
    got_sigchld = 1;
    if (waiting)
	siglongjmp(sigjmp, 1);
}

/*
 * toggle_debug - Catch SIGUSR1 signal.
 *
 * Toggle debug flag.
 */
/*ARGSUSED*/
static void
toggle_debug(sig)
    int sig;
{
    if (debug) {
	print_ncpstate(0, NULL);
	dbglog("debug logging disabled");
	(void) setlogmask(LOG_UPTO(LOG_WARNING));
	debug = 0;
    } else {
	(void) setlogmask(LOG_UPTO(LOG_DEBUG));
	dbglog("debug logging enabled");
	print_ncpstate(0, NULL);
	debug = 1;
    }
}


/*
 * open_ccp - Catch SIGUSR2 signal.
 *
 * Try to (re)negotiate compression.
 */
/*ARGSUSED*/
static void
open_ccp(sig)
    int sig;
{
    open_ccp_flag = 1;
    if (waiting)
	siglongjmp(sigjmp, 1);
}


/*
 * bad_signal - We've caught a fatal signal.  Clean up state and exit.
 */
static void
bad_signal(sig)
    int sig;
{
    static int crashed = 0;

    if (crashed)
	_exit(127);
    crashed = 1;
    error("Fatal signal %d", sig);
    if (conn_running > 0)
	kill_my_pg(SIGTERM);
    if (charshunt_pid)
	(void) kill(charshunt_pid, SIGTERM);
    die(127);
}


/*
 * device_script - run a program to talk to the serial device
 * (e.g. to run the connector or disconnector script).
 */
static int
device_script(program, in, out, dont_wait, optname)
    char *program;
    int in, out;
    int dont_wait;
    char *optname;
{
    pid_t pid;
    int status = -1;
    int errfd;
    int envpipe[2];

    envpipe[0] = envpipe[1] = -1;
    if (!dont_wait && device_pipe_hook != NULL && pipe(envpipe) == -1) {
	error("Cannot create pipe for child: %m");
	return (-1);
    }

    ++conn_running;
    pid = fork();

    if (pid == (pid_t)-1) {
	--conn_running;
	error("Failed to create child process: %m");
	return (-1);
    }

    if (pid == (pid_t)0) {
	sys_close();
	closelog();
	if (envpipe[0] >= 0) {
	    if (envpipe[1] <= 2)
		envpipe[1] = dup(envpipe[1]);
	    (void) close(envpipe[0]);
	}
	if (in == 2) {
	    /* aargh!!! */
	    int newin = dup(in);
	    if (in == out)
		out = newin;
	    in = newin;
	} else if (out == 2) {
	    out = dup(out);
	}
	if (log_to_fd >= 0) {
	    if (log_to_fd != 2) {
		if (dup2(log_to_fd, 2) < 0)
		    error("dup2(log_to_fd, STDERR) failed: %m");
	    }
	} else {
	    (void) close(2);
	    errfd = open(_PATH_CONNERRS, O_WRONLY | O_APPEND | O_CREAT, 0600);
	    if (errfd >= 0 && errfd != 2) {
		if (dup2(errfd, 2) < 0)
		    error("dup2(errfd, STDERR) failed: %m");
		(void) close(errfd);
	    }
	}
	if (in != 0) {
	    if (out == 0)
		out = dup(out);
	    if (dup2(in, 0) < 0)
		error("dup2(in, STDIN) failed: %m");
	}
	if (out != 1) {
	    if (dup2(out, 1) < 0)
		error("dup2(out, STDOUT) failed: %m");
	}
	if (envpipe[0] >= 0 && dup2(envpipe[1], 3) < 0)
	    error("dup2(pipe, pipeout) failed: %m");
	if (real_ttyfd > 2)
	    (void) close(real_ttyfd);
	if (pty_master > 2)
	    (void) close(pty_master);
	if (pty_slave > 2) {
	    (void) close(pty_slave);
	    pty_slave = -1;
	}
	(void) setuid(uid);
	if (getuid() != uid) {
	    error("setuid failed");
	    exit(1);
	}
	(void) setgid(getgid());
	if (script_env != NULL) {
	    while (*script_env != NULL) {
		if (putenv(*script_env) == -1)
		    warn("unable to set %s for %s: %m", *script_env, program);
		script_env++;
	    }
	}
	(void) execl("/bin/sh", "sh", "-c", program, (char *)0);
	error("could not exec /bin/sh: %m");
	exit(99);
	/* NOTREACHED */
    }

    if (debug)
	dbglog("%s option: '%s' started (pid %d)", optname, program, pid);
    if (dont_wait) {
	record_child(pid, program, NULL, NULL);
	status = 0;
    } else {
	if (envpipe[0] >= 0) {
	    (void) close(envpipe[1]);
	    (*device_pipe_hook)(envpipe[0]);
	}
	while (waitpid(pid, &status, 0) < 0) {
	    if (errno == EINTR)
		continue;
	    fatal("error waiting for (dis)connection process: %m");
	}
	if (envpipe[0] >= 0)
	    (void) close(envpipe[0]);
	--conn_running;
    }

    return (status == 0 ? 0 : -1);
}


/*
 * run-program - execute a program with given arguments,
 * but don't wait for it.
 * If the program can't be executed, logs an error unless
 * must_exist is 0 and the program file doesn't exist.
 * Returns -1 if it couldn't fork, 0 if the file doesn't exist
 * or isn't an executable plain file, or the process ID of the child.
 * If done != NULL, (*done)(arg, int) will be called later (within
 * reap_kids) if this routine returns value > 0.
 */
pid_t
run_program(prog, args, must_exist, done, arg)
    char *prog;
    char **args;
    int must_exist;
    void (*done) __P((void *arg, int status));
    void *arg;
{
    pid_t pid;
    struct stat sbuf;
    int retv;

    /*
     * First check if the file exists and is executable.
     * We don't use access() because that would use the
     * real user-id, which might not be root, and the script
     * might be accessible only to root.
     */
    errno = EINVAL;
    if (stat(prog, &sbuf) < 0 || !S_ISREG(sbuf.st_mode)
	|| (sbuf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) == 0) {
	if (must_exist || errno != ENOENT)
	    warn("Can't execute %s: %m", prog);
	return (0);
    }

    if (updown_script_hook != NULL) {
	retv = (*updown_script_hook)((const char ***)&args);
	if (retv == -1) {
	    return (-1);
	}
    }

    pid = fork();
    if (pid == (pid_t)-1) {
	error("Failed to create child process for %s: %m", prog);
	return (-1);
    }
    if (pid == (pid_t)0) {
	int new_fd;

	/* Leave the current location */
	(void) setsid();	/* No controlling tty. */
	(void) umask (S_IRWXG|S_IRWXO);
	(void) chdir ("/");	/* no current directory. */
	(void) setuid(0);	/* set real UID = root */
	(void) setgid(getegid());

	/* Ensure that nothing of our device environment is inherited. */
	sys_close();
	closelog();
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) close(ttyfd);  /* tty interface to the ppp device */
	if (real_ttyfd >= 0)
	    (void) close(real_ttyfd);

        /* Don't pass handles to the PPP device, even by accident. */
	new_fd = open (_PATH_DEVNULL, O_RDWR);
	if (new_fd >= 0) {
	    if (new_fd != 0) {
	        if (dup2(new_fd, 0) < 0) /* stdin <- /dev/null */
		    error("dup2(/dev/null, STDIN) failed: %m");
		(void) close(new_fd);
	    }
	    if (dup2(0, 1) < 0) /* stdout -> /dev/null */
		error("dup2(/dev/null, STDOUT) failed: %m");
	    if (dup2(0, 2) < 0) /* stderr -> /dev/null */
		error("dup2(/dev/null, STDERR) failed: %m");
	}

#ifdef BSD
	/* Force the priority back to zero if pppd is running higher. */
	if (setpriority (PRIO_PROCESS, 0, 0) < 0)
	    warn("can't reset priority to 0: %m");
#endif

	/* SysV recommends a second fork at this point. */

	/* run the program */
	(void) execve(prog, args, script_env);
	if (must_exist || errno != ENOENT) {
	    /* have to reopen the log, there's nowhere else
	       for the message to go. */
	    reopen_log();
	    syslog(LOG_ERR, "Can't execute %s: %m", prog);
	    closelog();
	}
	_exit(-1);
    }

    if (debug)
	dbglog("Script %s started (pid %d)", prog, pid);
    record_child(pid, prog, done, arg);

    return (pid);
}


/*
 * record_child - add a child process to the list for reap_kids
 * to use.
 */
static void
record_child(pid, prog, done, arg)
    pid_t pid;
    char *prog;
    void (*done) __P((void *, int));
    void *arg;
{
    struct subprocess *chp;

    ++n_children;

    chp = (struct subprocess *) malloc(sizeof(struct subprocess));
    if (chp == NULL) {
	warn("losing track of %s process", prog);
    } else {
	chp->pid = pid;
	chp->prog = prog;
	chp->done = done;
	chp->arg = arg;
	chp->next = children;
	children = chp;
    }
}


/*
 * reap_kids - get status from any dead child processes,
 * and log a message for abnormal terminations.
 */
static int
reap_kids(waitfor)
    int waitfor;
{
    pid_t pid;
    int status, i;
    struct subprocess *chp, **prevp;

    got_sigchld = 0;
    if (n_children == 0)
	return (0);

    /*CONSTANTCONDITION*/
    while (1) {
	pid = waitpid(-1, &status, (waitfor ? 0 : WNOHANG));
	if (pid == 0) {
	    break;	/* return 0 */
	} else if (pid == -1) {
	    if (errno == EINTR)
		continue;
	    if (errno != ECHILD)
		error("Error waiting for child process: %m");
	    return (-1);
	} else {
	    for (prevp = &children; (chp = *prevp) != NULL;
		prevp = &chp->next) {
		if (chp->pid == pid) {
		    --n_children;
		    *prevp = chp->next;
		    break;
		}
	    }
	    if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
		i = WIFSIGNALED(status) ? WTERMSIG(status) : WSTOPSIG(status);
		warn("Child process %s (pid %d) %s with signal %d (%s)",
		    (chp != NULL ? chp->prog : "??"), pid,
		    (WIFSIGNALED(status) ? "terminated" : "stopped"),
		    i, signal_name(i));
	    } else if (debug) {
		dbglog("Child process %s finished (pid %d), status = %d",
		       (chp != NULL ? chp->prog: "??"), pid,
		    WEXITSTATUS(status));
	    }
	    if ((chp != NULL) && (chp->done != NULL))
		(*chp->done)(chp->arg, status);
	    if (chp != NULL)
		free(chp);
	}
    }
    return (0);
}

/*
 * infanticide - timeout while waiting for child process.
 */
/*ARGSUSED*/
static void
infanticide(sig)
    int sig;
{
    struct subprocess *chp;
    static int runcount = 0;

    if (runcount < 2) {
	for (chp = children; chp != NULL; chp = chp->next)
	    (void) kill(chp->pid, runcount == 0 ? SIGTERM : SIGKILL);
    } else {
	kill_my_pg(SIGTERM);
	/* Quit and hope for the best. */
	n_children = 0;
    }
    runcount++;
}

/*
 * Perform final wait before exiting.
 */
static void
final_reap()
{
    struct sigaction sa;
    struct subprocess *chp;

    if (n_children > 0 && debug) {
	dbglog("Waiting for %d child processes...", n_children);
	for (chp = children; chp != NULL; chp = chp->next)
	    dbglog("  pid %d: %s", chp->pid, chp->prog);
    }
    BZERO(&sa, sizeof (sa));
/*CONSTANTCONDITION*/ SIGNAL(SIGALRM, infanticide);
    while (n_children > 0) {
	(void) alarm(7);
	if (reap_kids(1) < 0)
	    break;
    }
    (void) alarm(0);
}

/*
 * novm - log an error message saying we ran out of memory, and die.
 */
void
novm(msg)
    char *msg;
{
    fatal("Virtual memory exhausted allocating %s\n", msg);
}

/*
 * script_setenv - set an environment variable value to be used
 * for scripts that we run (e.g. ip-up, auth-up, etc.)
 */
void
script_setenv(var, value, iskey)
    const char *var;
    const char *value;
    int iskey;
{
    size_t varl = strlen(var);
    size_t vl = varl + strlen(value) + 2;
    int i;
    char *p, *newstring;

    /*
     * XXX: Can we assert that a tdb write lock is held here ?  It appears that
     *	    Linux's use of tdb is not safe.
     */
    newstring = (char *) malloc(vl+1);
    if (newstring == NULL) {
	novm("script environment string");
	return;
    }
    *newstring++ = iskey;
    (void) slprintf(newstring, vl, "%s=%s", var, value);

    /* check if this variable is already set */
    if (script_env != NULL) {
	for (i = 0; (p = script_env[i]) != NULL; ++i) {
	    if (strncmp(p, var, varl) == 0 && p[varl] == '=') {
#ifdef HAVE_MULTILINK
		if (p[-1] != '\0' && pppdb != NULL)
		    delete_db_key(p);
#endif
		free(p-1);
		script_env[i] = newstring;
#ifdef HAVE_MULTILINK
		if (iskey && pppdb != NULL)
		    add_db_key(newstring);
		update_db_entry();
#endif
		return;
	    }
	}
    } else {
	/* no space allocated for script env. ptrs. yet */
	i = 0;
	script_env = (char **) malloc(16 * sizeof(char *));
	if (script_env == NULL) {
	    novm("script environment variable.");
	    return;
	}
	s_env_nalloc = 16;
    }

    /* reallocate script_env with more space if needed */
    if (i + 1 >= s_env_nalloc) {
	int new_n = i + 17;
	char **newenv = (char **) realloc((void *)script_env,
					  new_n * sizeof(char *));
	if (newenv == NULL) {
	    novm("expanded script environment variable.");
	    return;
	}
	script_env = newenv;
	s_env_nalloc = new_n;
    }

    script_env[i] = newstring;
    script_env[i+1] = NULL;

#ifdef HAVE_MULTILINK
    if (pppdb != NULL) {
	if (iskey)
	    add_db_key(newstring);
	update_db_entry();
    }
#endif
}

/*
 * script_unsetenv - remove a variable from the environment
 * for scripts.
 */
void
script_unsetenv(var)
    const char *var;
{
    int vl = strlen(var);
    int i;
    char *p;

    /*
     * XXX: Can we assert that a tdb write lock is held here ?  It appears that
     *	    Linux's use of tdb is not safe.
     */
    if (script_env == NULL)
	return;
    for (i = 0; (p = script_env[i]) != NULL; ++i) {
	if (strncmp(p, var, vl) == 0 && p[vl] == '=') {
#ifdef HAVE_MULTILINK
	    if (p[-1] != '\0' && pppdb != NULL)
		delete_db_key(p);
#endif
	    free(p-1);
	    while ((script_env[i] = script_env[i+1]) != NULL)
		++i;
	    break;
	}
    }
#ifdef HAVE_MULTILINK
    if ((pppdb != NULL) && (p != NULL))
	update_db_entry();
#endif
}

/*
 * script_getenv - find a variable in the script environment.
 */
const char *
script_getenv(var)
    const char *var;
{
    int vl = strlen(var);
    int i;
    char *p;

    if (script_env == NULL)
	return (NULL);
    for (i = 0; (p = script_env[i]) != NULL; ++i) {
	if (strncmp(p, var, vl) == 0 && p[vl] == '=')
	    return ((const char *)p+vl+1);
    }
    return (NULL);
}

#ifdef HAVE_MULTILINK
/*
 * update_db_entry - update our entry in the database.
 */
static void
update_db_entry()
{
    TDB_DATA key, dbuf;
    int vlen, i;
    char *p, *q, *vbuf;

    if (script_env == NULL)
	return;
    /*
     * vlen needs to be initialized as 1, or otherwise, the last string
     * is truncated by slprintf.
     */
    vlen = 1;
    for (i = 0; (p = script_env[i]) != NULL; ++i)
	vlen += strlen(p) + 1;
    vbuf = malloc(vlen);
    if (vbuf == NULL)
	novm("database entry");
    q = vbuf;
    for (i = 0; (p = script_env[i]) != NULL; ++i)
	q += slprintf(q, vbuf + vlen - q, "%s;", p);

    key.dptr = db_key;
    key.dsize = strlen(db_key);
    dbuf.dptr = vbuf;
    dbuf.dsize = vlen;
    if (tdb_store(pppdb, key, dbuf, TDB_REPLACE))
	error("tdb_store failed: %s", tdb_error(pppdb));
}

/*
 * add_db_key - add a key that we can use to look up our database entry.
 */
static void
add_db_key(str)
    const char *str;
{
    TDB_DATA key, dbuf;

    key.dptr = (char *) str;
    key.dsize = strlen(str);
    dbuf.dptr = db_key;
    dbuf.dsize = strlen(db_key);
    if (tdb_store(pppdb, key, dbuf, TDB_REPLACE))
	error("tdb_store key failed: %s", tdb_error(pppdb));
}

/*
 * delete_db_key - delete a key for looking up our database entry.
 */
static void
delete_db_key(str)
    const char *str;
{
    TDB_DATA key;

    key.dptr = (char *) str;
    key.dsize = strlen(str);
    (void) tdb_delete(pppdb, key);
}

/*
 * cleanup_db - delete all the entries we put in the database.
 */
static void
cleanup_db()
{
    TDB_DATA key;
    int i;
    char *p;

    key.dptr = db_key;
    key.dsize = strlen(db_key);
    (void) tdb_delete(pppdb, key);
    for (i = 0; (p = script_env[i]) != NULL; ++i)
	if (p[-1] != '\0')
	    delete_db_key(p);
}
#endif /* HAVE_MULTILINK */

/*
 * open_socket - establish a stream socket connection to the nominated
 * host and port.
 * XXX: Need IPv6 support for those systems that support it (use getaddrinfo),
 *	but requires portability changes.
 */
static int
open_socket(dest)
    char *dest;
{
    char *sep, *endp = NULL;
    int sock;
    int port = -1;
    u_int32_t host;
    struct hostent *hent = NULL;
    struct sockaddr_in sad;
    struct servent *se;

    /* parse host:port and resolve host to an IP address */
    sep = strchr(dest, ':');
    if (sep != NULL) {
	se = getservbyname((const char *)sep+1, "tcp");
	if (se != NULL) {
	    port = ntohs(se->s_port);
	} else {
	    port = strtol(sep+1, &endp, 10);
	    if (endp == sep+1 || *endp != '\0') {
		error("Can't parse host:port for socket destination");
		return (-1);
	    }
	}
    }
    if (port < 0 || port > 65535 || sep == dest) {
	error("Can't parse host:port for socket destination");
	return (-1);
    }
    *sep = '\0';
    host = inet_addr(dest);
    if (host == (u_int32_t) -1) {
	hent = gethostbyname(dest);
	if (hent == NULL) {
	    error("%s: unknown host in socket option", dest);
	    *sep = ':';
	    return (-1);
	}
	BCOPY(hent->h_addr_list[0], &host, sizeof(host));
	hent->h_addr_list++;
    }
    *sep = ':';

    for (;;) {
	/* get a socket and connect it to the other end */
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
	    error("Can't create socket: %m");
	    return (-1);
	}
	BZERO(&sad, sizeof(sad));
	sad.sin_family = AF_INET;
	sad.sin_port = htons(port);
	sad.sin_addr.s_addr = host;
	if (connect(sock, (struct sockaddr *)&sad, sizeof(sad)) >= 0) {
	    break;  /* return sock file descriptor */
	}
	if ((hent != NULL) && (hent->h_addr_list != NULL)) {
	    BCOPY(hent->h_addr_list[0], &host, sizeof(host));
	    hent->h_addr_list++;
	    (void) close(sock);
	    continue;
	}
	error("Can't connect to %s: %m", dest);
	(void) close(sock);
	return (-1);
    }
    return (sock);
}

/*
 * print_ncpstate - prints out current NCP state.
 *
 * We're normally called from SIGUSR1 here, but this is safe because
 * these signals are blocked unless we're idle waiting for events.
 * There's no need to otherwise lock the data structures referenced.
 */
void
print_ncpstate(unit, strptr)
    int unit;
    FILE *strptr;
{
    struct protent *protp;
    int i;

    (void) flprintf(strptr, "In %s phase\n", phase_name(phase));
    for (i = 0; (protp = protocols[i]) != NULL; ++i) {
	if (protp->print_stat != NULL)
	    (*protp->print_stat)(unit, strptr);
    }
    sys_print_state(strptr);
}

/*
 * start_charshunt - create a child process to run the character shunt.
 */
static int
start_charshunt(ifd, ofd)
    int ifd, ofd;
{
    pid_t cpid;

    cpid = fork();
    if (cpid == (pid_t)-1) {
	error("Can't fork process for character shunt: %m");
	return (0);
    }
    if (cpid == (pid_t)0) {
	/* child */
	(void) close(pty_slave);
	pty_slave = -1;
	(void) setgid(getgid());
	(void) setuid(uid);
	if (getuid() != uid)
	    fatal("setuid failed");
	if (!nodetach)
	    log_to_fd = -1;
	charshunt(ifd, ofd, record_file);
	exit(0);
    }
    charshunt_pid = cpid;
    (void) close(pty_master);
    pty_master = -1;
    ttyfd = pty_slave;
    record_child(cpid, "pppd (charshunt)", charshunt_done, NULL);
    return (1);
}

/*ARGSUSED*/
static void
charshunt_done(arg, status)
    void *arg;
    int status;
{
    charshunt_pid = (pid_t)0;
}

static void
reportme(int signo)
{
    dbglog("charshunt taking signal %d", signo);
    exit(1);
}

/*
 * charshunt - the character shunt, which passes characters between
 * the pty master side and the serial port (or stdin/stdout).
 * This runs as the user (not as root).
 * (We assume ofd >= ifd which is true the way this gets called. :-).
 */
static void
charshunt(ifd, ofd, record_file)
    int ifd, ofd;
    char *record_file;
{
    int n, nfds;
    fd_set ready, writey;
    u_char *ibufp, *obufp;
    int nibuf, nobuf;
    int flags;
    struct timeval lasttime;
    FILE *recordf = NULL;
    int ilevel, olevel, max_level;
    struct timeval levelt, tout, *top;

    /*
     * Reset signal handlers.
     */
    (void) signal(SIGHUP, SIG_IGN);		/* Hangup */
    (void) signal(SIGINT, reportme);		/* Interrupt */
    (void) signal(SIGTERM, reportme);		/* Terminate */
    (void) signal(SIGCHLD, reportme);
    (void) signal(SIGUSR1, reportme);
    (void) signal(SIGUSR2, reportme);
    (void) signal(SIGABRT, reportme);
    (void) signal(SIGALRM, reportme);
    (void) signal(SIGFPE, reportme);
    (void) signal(SIGILL, reportme);
    (void) signal(SIGPIPE, reportme);
    (void) signal(SIGQUIT, reportme);
#ifndef DEBUG
    (void) signal(SIGSEGV, reportme);
#endif
#ifdef SIGBUS
    (void) signal(SIGBUS, reportme);
#endif
#ifdef SIGEMT
    (void) signal(SIGEMT, reportme);
#endif
#ifdef SIGPOLL
    (void) signal(SIGPOLL, reportme);
#endif
#ifdef SIGPROF
    (void) signal(SIGPROF, reportme);
#endif
#ifdef SIGSYS
    (void) signal(SIGSYS, reportme);
#endif
#ifdef SIGTRAP
    (void) signal(SIGTRAP, reportme);
#endif
#ifdef SIGVTALRM
    (void) signal(SIGVTALRM, reportme);
#endif
#ifdef SIGXCPU
    (void) signal(SIGXCPU, reportme);
#endif
#ifdef SIGXFSZ
    (void) signal(SIGXFSZ, reportme);
#endif

    /*
     * Open the record file if required.
     */
    if (record_file != NULL) {
	recordf = fopen(record_file, "a");
	if (recordf == NULL)
	    error("Couldn't create record file %s: %m", record_file);
    }

    /* set all the fds to non-blocking mode */
    flags = fcntl(pty_master, F_GETFL);
    if (flags == -1
	|| fcntl(pty_master, F_SETFL, flags | O_NONBLOCK) == -1)
	warn("couldn't set pty master to nonblock: %m");
    flags = fcntl(ifd, F_GETFL);
    if (flags == -1
	|| fcntl(ifd, F_SETFL, flags | O_NONBLOCK) == -1)
	warn("couldn't set %s to nonblock: %m", (ifd==0? "stdin": "tty"));
    if (ofd != ifd) {
	flags = fcntl(ofd, F_GETFL);
	if (flags == -1
	    || fcntl(ofd, F_SETFL, flags | O_NONBLOCK) == -1)
	    warn("couldn't set stdout to nonblock: %m");
    }

    nibuf = nobuf = 0;
    ibufp = obufp = NULL;

    ilevel = olevel = 0;
    (void) gettimeofday(&levelt, NULL);
    if (max_data_rate) {
	max_level = max_data_rate / 10;
	if (max_level < MAXLEVELMINSIZE)
	    max_level = MAXLEVELMINSIZE;
    } else
	max_level = sizeof(inpacket_buf) + 1;

    nfds = (ofd > pty_master? ofd: pty_master) + 1;
    if (recordf != NULL) {
	(void) gettimeofday(&lasttime, NULL);
	(void) putc(RECMARK_TIMESTART, recordf);	/* put start marker */
	(void) putc(lasttime.tv_sec >> 24, recordf);
	(void) putc(lasttime.tv_sec >> 16, recordf);
	(void) putc(lasttime.tv_sec >> 8, recordf);
	(void) putc(lasttime.tv_sec, recordf);
	lasttime.tv_usec = 0;
    }

    while (nibuf != 0 || nobuf != 0 || ofd >= 0 || pty_master >= 0) {
	top = 0;
	tout.tv_sec = 0;
	tout.tv_usec = 10000;
	FD_ZERO(&ready);
	FD_ZERO(&writey);
	if (nibuf != 0) {
	    if (ilevel >= max_level)
		top = &tout;
	    else if (pty_master >= 0)
		FD_SET(pty_master, &writey);
	} else if (ifd >= 0)
	    FD_SET(ifd, &ready);
	if (nobuf != 0) {
	    if (olevel >= max_level)
		top = &tout;
	    else if (ofd >= 0)
		FD_SET(ofd, &writey);
	} else {
	    /* Don't read from pty if it's gone or it has closed. */
	    if (pty_master >= 0 && ofd >= 0)
		FD_SET(pty_master, &ready);
	}
	if (select(nfds, &ready, &writey, NULL, top) < 0) {
	    if (errno != EINTR)
		fatal("select");
	    continue;
	}
	if (max_data_rate) {
	    double dt;
	    int nbt;
	    struct timeval now;

	    (void) gettimeofday(&now, NULL);
	    dt = (now.tv_sec - levelt.tv_sec
		  + (now.tv_usec - levelt.tv_usec) / 1e6);
	    nbt = (int)(dt * max_data_rate);
	    ilevel = (nbt < 0 || nbt > ilevel)? 0: ilevel - nbt;
	    olevel = (nbt < 0 || nbt > olevel)? 0: olevel - nbt;
	    levelt = now;
	} else
	    ilevel = olevel = 0;
	if (FD_ISSET(ifd, &ready)) {
	    ibufp = inpacket_buf;
	    nibuf = read(ifd, ibufp, sizeof(inpacket_buf));
	    if (nibuf < 0 && errno == EIO)
		nibuf = 0;
	    if (nibuf < 0 || pty_master == -1) {
		if (errno != EINTR && errno != EAGAIN) {
		    error("Error reading standard input: %m");
		    break;
		}
		nibuf = 0;
	    } else if (nibuf == 0) {
		/* end of file from stdin */
		(void) close(pty_master);
		pty_master = -1;
		(void) close(ifd);
		ifd = -1;
		if (recordf)
		    if (!record_write(recordf, RECMARK_ENDRECV, NULL, 0,
			&lasttime))
			recordf = NULL;
	    } else {
		FD_SET(pty_master, &writey);
		if (recordf)
		    if (!record_write(recordf, RECMARK_STARTRECV, ibufp, nibuf,
			&lasttime))
			recordf = NULL;
	    }
	}
	if (ofd >= 0 && pty_master >= 0 && FD_ISSET(pty_master, &ready)) {
	    obufp = outpacket_buf;
	    nobuf = read(pty_master, obufp, sizeof(outpacket_buf));
	    if (nobuf < 0 && errno == EIO)
		nobuf = 0;
	    if (nobuf < 0 || ofd == -1) {
		if (!(errno == EINTR || errno == EAGAIN)) {
		    error("Error reading pseudo-tty master: %m");
		    break;
		}
		nobuf = 0;
	    } else if (nobuf == 0) {
		/* end of file from the pty - slave side has closed */
		nibuf = 0;
		(void) close(ofd);
		ofd = -1;
		if (recordf)
		    if (!record_write(recordf, RECMARK_ENDSEND, NULL, 0,
			&lasttime))
			recordf = NULL;
	    } else {
		FD_SET(ofd, &writey);
		if (recordf)
		    if (!record_write(recordf, RECMARK_STARTSEND, obufp, nobuf,
			&lasttime))
			recordf = NULL;
	    }
	}
	if (ofd == -1)
	    nobuf = 0;
	else if (FD_ISSET(ofd, &writey)) {
	    n = nobuf;
	    if (olevel + n > max_level)
		n = max_level - olevel;
	    n = write(ofd, obufp, n);
	    if (n < 0) {
		if (errno == EIO) {
		    (void) close(ofd);
		    ofd = -1;
		    nobuf = 0;
		} else if (errno != EAGAIN && errno != EINTR) {
		    error("Error writing standard output: %m");
		    break;
		}
	    } else {
		obufp += n;
		nobuf -= n;
		olevel += n;
	    }
	}
	if (pty_master == -1)
	    nibuf = 0;
	else if (FD_ISSET(pty_master, &writey)) {
	    n = nibuf;
	    if (ilevel + n > max_level)
		n = max_level - ilevel;
	    n = write(pty_master, ibufp, n);
	    if (n < 0) {
		if (errno == EAGAIN || errno == EINTR)
		    continue;
		if (errno != EIO) {
		    error("Error writing pseudo-tty master: %m");
		    break;
		}
		(void) close(pty_master);
		pty_master = -1;
		nibuf = 0;
	    } else {
		ibufp += n;
		nibuf -= n;
		ilevel += n;
	    }
	}
    }
    exit(0);
}

static int
record_write(f, code, buf, nb, tp)
    FILE *f;
    int code;
    u_char *buf;
    int nb;
    struct timeval *tp;
{
    struct timeval now;
    int diff;

    (void) gettimeofday(&now, NULL);
    now.tv_usec /= 100000;	/* actually 1/10 s, not usec now */
    diff = (now.tv_sec - tp->tv_sec) * 10 + (now.tv_usec - tp->tv_usec);
    if (diff > 0) {
	if (diff > 255) {
	    (void) putc(RECMARK_TIMEDELTA32, f);
	    (void) putc(diff >> 24, f);
	    (void) putc(diff >> 16, f);
	    (void) putc(diff >> 8, f);
	    (void) putc(diff, f);
	} else {
	    (void) putc(RECMARK_TIMEDELTA8, f);
	    (void) putc(diff, f);
	}
	*tp = now;
    }
    (void) putc(code, f);
    if (buf != NULL) {
	(void) putc(nb >> 8, f);
	(void) putc(nb, f);
	(void) fwrite(buf, nb, 1, f);
    }
    (void) fflush(f);
    if (ferror(f)) {
	error("Error writing record file: %m");
	return (0);
    }
    return (1);
}
