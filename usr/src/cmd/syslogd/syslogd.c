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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2013 Gary Mills
 */

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	All Rights Reserved
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 *  syslogd -- log system messages
 *
 * This program implements a system log. It takes a series of lines.
 * Each line may have a priority, signified as "<n>" as
 * the first characters of the line.  If this is
 * not present, a default priority is used.
 *
 * To kill syslogd, send a signal 15 (terminate).  A signal 1 (hup) will
 * cause it to reconfigure.
 *
 * Defined Constants:
 *
 * MAXLINE -- the maximimum line length that can be handled.
 * DEFUPRI -- the default priority for user messages.
 * DEFSPRI -- the default priority for kernel messages.
 *
 */

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <libscf.h>
#include <netconfig.h>
#include <netdir.h>
#include <pwd.h>
#include <sys/socket.h>
#include <tiuser.h>
#include <utmpx.h>
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <stropts.h>
#include <assert.h>
#include <sys/statvfs.h>

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/syslog.h>
#include <sys/strlog.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <door.h>

#include <wchar.h>
#include <locale.h>
#include <stdarg.h>

#include "dataq.h"
#include "conf.h"
#include "syslogd.h"

#define	DOORFILE		"/var/run/syslog_door"
#define	RELATIVE_DOORFILE	"../var/run/syslog_door"
#define	OLD_DOORFILE		"/etc/.syslog_door"

#define	PIDFILE			"/var/run/syslog.pid"
#define	RELATIVE_PIDFILE	"../var/run/syslog.pid"
#define	OLD_PIDFILE		"/etc/syslog.pid"

static char		*LogName = "/dev/log";
static char		*ConfFile = "/etc/syslog.conf";
static char		ctty[] = "/dev/console";
static char		sysmsg[] = "/dev/sysmsg";
static int		DoorFd = -1;
static int		DoorCreated = 0;
static int		PidfileCreated = 0;
static char		*DoorFileName = DOORFILE;
static char		*PidFileName = PIDFILE;

/*
 * configuration file directives
 */

static struct code	PriNames[] = {
	"panic",	LOG_EMERG,
	"emerg",	LOG_EMERG,
	"alert",	LOG_ALERT,
	"crit",		LOG_CRIT,
	"err",		LOG_ERR,
	"error",	LOG_ERR,
	"warn",		LOG_WARNING,
	"warning",	LOG_WARNING,
	"notice",	LOG_NOTICE,
	"info",		LOG_INFO,
	"debug",	LOG_DEBUG,
	"none",		NOPRI,
	NULL,		-1
};

static struct code	FacNames[] = {
	"kern",		LOG_KERN,
	"user",		LOG_USER,
	"mail",		LOG_MAIL,
	"daemon",	LOG_DAEMON,
	"auth",		LOG_AUTH,
	"security",	LOG_AUTH,
	"mark",		LOG_MARK,
	"syslog",	LOG_SYSLOG,
	"lpr",		LOG_LPR,
	"news",		LOG_NEWS,
	"uucp",		LOG_UUCP,
	"altcron",	LOG_ALTCRON,
	"authpriv",	LOG_AUTHPRIV,
	"ftp",		LOG_FTP,
	"ntp",		LOG_NTP,
	"audit",	LOG_AUDIT,
	"console",	LOG_CONSOLE,
	"cron",		LOG_CRON,
	"local0",	LOG_LOCAL0,
	"local1",	LOG_LOCAL1,
	"local2",	LOG_LOCAL2,
	"local3",	LOG_LOCAL3,
	"local4",	LOG_LOCAL4,
	"local5",	LOG_LOCAL5,
	"local6",	LOG_LOCAL6,
	"local7",	LOG_LOCAL7,
	NULL,		-1
};

static char		*TypeNames[7] = {
	"UNUSED",	"FILE",		"TTY",		"CONSOLE",
	"FORW",		"USERS",	"WALL"
};

/*
 * we allocate our own thread stacks so we can create them
 * without the MAP_NORESERVE option. We need to be sure
 * we have stack space even if the machine runs out of swap
 */

#define	DEFAULT_STACKSIZE (100 * 1024)  /* 100 k stack */
#define	DEFAULT_REDZONESIZE (8 * 1024)	/* 8k redzone */

static pthread_mutex_t wmp = PTHREAD_MUTEX_INITIALIZER;	/* wallmsg lock */

static pthread_mutex_t cft = PTHREAD_MUTEX_INITIALIZER;
static int conf_threads = 0;

static pthread_mutex_t hup_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hup_done = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t logerror_lock = PTHREAD_MUTEX_INITIALIZER;

#define	HUP_ACCEPTABLE		0x0000	/* can start SIGHUP process */
#define	HUP_INPROGRESS		0x0001	/* SIGHUP process in progress */
#define	HUP_COMPLETED		0x0002	/* SIGHUP process completed */
#define	HUP_SUSP_LOGMSG_REQD	0x1000	/* request to suspend */
#define	HUP_LOGMSG_SUSPENDED	0x2000	/* logmsg is suspended */
static int hup_state = HUP_ACCEPTABLE;

static size_t stacksize;		/* thread stack size */
static size_t redzonesize;		/* thread stack redzone size */
static char *stack_ptr;			/* ptr to allocated stacks */
static char *cstack_ptr;		/* ptr to conf_thr stacks */

static time_t start_time;

static pthread_t sys_thread;		/* queues messages from us */
static pthread_t net_thread;		/* queues messages from the net */
static pthread_t log_thread;		/* message processing thread */
static pthread_t hnl_thread;		/* hostname lookup thread */

static dataq_t inputq;			/* the input queue */
static dataq_t tmpq;			/* temporary queue for err msg */
static dataq_t hnlq;			/* hostname lookup queue */

static struct filed fallback[2];
static struct filed *Files;
static int nlogs;
static int Debug;			/* debug flag */
static host_list_t LocalHostName;	/* our hostname */
static host_list_t NullHostName;	/* in case of lookup failure */
static int debuglev = 1;		/* debug print level */
static int interrorlog;			/* internal error logging */

static int MarkInterval = 20;		/* interval between marks (mins) */
static int Marking = 0;			/* non-zero if marking some file */
static int Ninputs = 0;			/* number of network inputs */
static int curalarm = 0;		/* current timeout value (secs) */
static int sys_msg_count = 0;		/* total msgs rcvd from local log */
static int sys_init_msg_count = 0;	/* initially received */
static int net_msg_count = 0;		/* total msgs rcvd from net */

static struct pollfd Pfd;		/* Pollfd for local the log device */
static struct pollfd *Nfd;		/* Array of pollfds for udp ports */
static struct netconfig *Ncf;
static struct netbuf **Myaddrs;
static struct t_unitdata **Udp;
static struct t_uderr **Errp;
static int turnoff = 0;
static int shutting_down;

/* for managing door server threads */
static pthread_mutex_t door_server_cnt_lock = PTHREAD_MUTEX_INITIALIZER;
static uint_t door_server_cnt = 0;
static pthread_attr_t door_thr_attr;

static struct hostname_cache **hnc_cache;
static pthread_mutex_t hnc_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t hnc_size = DEF_HNC_SIZE;
static unsigned int hnc_ttl = DEF_HNC_TTL;

#define	DPRINT0(d, m)		if ((Debug) && debuglev >= (d)) \
				(void) fprintf(stderr, m)
#define	DPRINT1(d, m, a)	if ((Debug) && debuglev >= (d)) \
				(void) fprintf(stderr, m, a)
#define	DPRINT2(d, m, a, b)	if ((Debug) && debuglev >= (d)) \
				(void) fprintf(stderr, m, a, b)
#define	DPRINT3(d, m, a, b, c)	if ((Debug) && debuglev >= (d)) \
				(void) fprintf(stderr, m, a, b, c)
#define	DPRINT4(d, m, a, b, c, e)	if ((Debug) && debuglev >= (d)) \
				(void) fprintf(stderr, m, a, b, c, e)
#define	MALLOC_FAIL(x)	\
		logerror("malloc failed: " x)
#define	MALLOC_FAIL_EXIT	\
		logerror("malloc failed - fatal"); \
		exit(1)


#define	MAILCMD "mailx -s \"syslogd shut down\" root"

/*
 * Number of seconds to wait before giving up on threads that won't
 * shutdown: (that's right, 10 minutes!)
 */
#define	LOOP_MAX	(10 * 60)

/*
 * Interval(sec) to check the status of output queue while processing
 * HUP signal.
 */
#define	LOOP_INTERVAL	(15)

int
main(int argc, char **argv)
{
	int i;
	char *pstr;
	int sig, fd;
	int tflag = 0, Tflag = 0;
	sigset_t sigs, allsigs;
	struct rlimit rlim;
	char *debugstr;
	int mcount = 0;
	struct sigaction act;
	pthread_t mythreadno = 0;
	char cbuf [30];
	struct stat sb;

#ifdef DEBUG
#define	DEBUGDIR "/var/tmp"
	if (chdir(DEBUGDIR))
		DPRINT2(1, "main(%u): Unable to cd to %s\n", mythreadno,
		    DEBUGDIR);
#endif /* DEBUG */

	(void) setlocale(LC_ALL, "");

	if ((debugstr = getenv("SYSLOGD_DEBUG")) != NULL)
		if ((debuglev = atoi(debugstr)) == 0)
			debuglev = 1;

#if ! defined(TEXT_DOMAIN)	/* should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) time(&start_time);

	if (lstat("/var/run", &sb) != 0 || !(S_ISDIR(sb.st_mode))) {
		DoorFileName = OLD_DOORFILE;
		PidFileName  = OLD_PIDFILE;
	}

	properties();

	while ((i = getopt(argc, argv, "df:p:m:tT")) != EOF) {
		switch (i) {
		case 'f':		/* configuration file */
			ConfFile = optarg;
			break;

		case 'd':		/* debug */
			Debug++;
			break;

		case 'p':		/* path */
			LogName = optarg;
			break;

		case 'm':		/* mark interval */
			for (pstr = optarg; *pstr; pstr++) {
				if (! (isdigit(*pstr))) {
					(void) fprintf(stderr,
					    "Illegal interval\n");
					usage();
				}
			}
			MarkInterval = atoi(optarg);
			if (MarkInterval < 1 || MarkInterval > INT_MAX) {
				(void) fprintf(stderr,
				    "Interval must be between 1 and %d\n",
				    INT_MAX);
				usage();
			}
			break;
		case 't':		/* turn off remote reception */
			tflag++;
			turnoff++;
			break;
		case 'T':		/* turn on remote reception */
			Tflag++;
			turnoff = 0;
			break;
		default:
			usage();
		}
	}

	if (optind < argc)
		usage();

	if (tflag && Tflag) {
		(void) fprintf(stderr, "specify only one of -t and -T\n");
		usage();
	}

	/*
	 * close all fd's except 0-2
	 */

	closefrom(3);

	if (!Debug) {
		if (fork())
			return (0);
		(void) close(0);
		(void) open("/", 0);
		(void) dup2(0, 1);
		(void) dup2(0, 2);
		untty();
	}

	if (Debug) {
		mythreadno = pthread_self();
	}

	/*
	 * DO NOT call logerror() until tmpq is initialized.
	 */
	disable_errorlog();

	/*
	 * ensure that file descriptor limit is "high enough"
	 */
	(void) getrlimit(RLIMIT_NOFILE, &rlim);
	if (rlim.rlim_cur < rlim.rlim_max)
		rlim.rlim_cur = rlim.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
		logerror("Unable to increase file descriptor limit.");
	(void) enable_extended_FILE_stdio(-1, -1);

	/* block all signals from all threads initially */
	(void) sigfillset(&allsigs);
	(void) pthread_sigmask(SIG_BLOCK, &allsigs, NULL);

	DPRINT2(1, "main(%u): Started at time %s", mythreadno,
	    ctime_r(&start_time, cbuf));

	init();			/* read configuration, start threads */

	DPRINT1(1, "main(%u): off & running....\n", mythreadno);

	/* now set up to catch signals we care about */

	(void) sigemptyset(&sigs);
	(void) sigaddset(&sigs, SIGHUP);	/* reconfigure */
	(void) sigaddset(&sigs, SIGALRM);	/* mark & flush timer */
	(void) sigaddset(&sigs, SIGTERM);	/* exit */
	(void) sigaddset(&sigs, SIGINT);	/* exit if debugging */
	(void) sigaddset(&sigs, SIGQUIT);	/* exit if debugging */
	(void) sigaddset(&sigs, SIGPIPE);	/* catch & discard */
	(void) sigaddset(&sigs, SIGUSR1);	/* dump debug stats */

	/*
	 * We must set up to catch these signals, even though sigwait
	 * will get them before the isr does.  Setting SA_SIGINFO ensures
	 * that signals will be enqueued.
	 */

	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signull;

	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGALRM, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGQUIT, &act, NULL);
	(void) sigaction(SIGPIPE, &act, NULL);
	(void) sigaction(SIGUSR1, &act, NULL);

	/* we now turn into the signal handling thread */

	DPRINT1(2, "main(%u): now handling signals\n", mythreadno);
	for (;;) {
		(void) sigwait(&sigs, &sig);
		DPRINT2(2, "main(%u): received signal %d\n", mythreadno, sig);
		switch (sig) {
		case SIGALRM:
			DPRINT1(1, "main(%u): Got SIGALRM\n",
			    mythreadno);
			flushmsg(NOCOPY);
			if (Marking && (++mcount % MARKCOUNT == 0)) {
				if (logmymsg(LOG_INFO, "-- MARK --",
				    ADDDATE|MARK|NOCOPY, 0) == -1) {
					MALLOC_FAIL(
					    "dropping MARK message");
				}

				mcount = 0;
			}
			curalarm = MarkInterval * 60 / MARKCOUNT;
			(void) alarm((unsigned)curalarm);
			DPRINT2(2, "main(%u): Next alarm in %d "
			    "seconds\n", mythreadno, curalarm);
			break;
		case SIGHUP:
			DPRINT1(1, "main(%u): got SIGHUP - "
			    "reconfiguring\n", mythreadno);

			reconfigure();

			DPRINT1(1, "main(%u): done processing SIGHUP\n",
			    mythreadno);
			break;
		case SIGQUIT:
		case SIGINT:
			if (!Debug) {
				/* allow these signals if debugging */
				break;
			}
			/* FALLTHROUGH */
		case SIGTERM:
			DPRINT2(1, "main(%u): going down on signal %d\n",
			    mythreadno, sig);
			(void) alarm(0);
			flushmsg(0);
			errno = 0;
			t_errno = 0;
			logerror("going down on signal %d", sig);
			disable_errorlog();	/* force msg to console */
			(void) shutdown_msg();	/* stop threads */
			shutdown_input();
			close_door();
			delete_doorfiles();
			return (0);
		case SIGUSR1:			/* secret debug dump mode */
			/* if in debug mode, use stdout */

			if (Debug) {
				dumpstats(STDOUT_FILENO);
				break;
			}
			/* otherwise dump to a debug file */
			if ((fd = open(DEBUGFILE,
			    (O_WRONLY|O_CREAT|O_TRUNC|O_EXCL),
			    0644)) < 0)
				break;
			dumpstats(fd);
			(void) close(fd);
			break;
		default:
			DPRINT2(2, "main(%u): unexpected signal %d\n",
			    mythreadno, sig);
			break;
		}
	}
}

/*
 * Attempts to open the local log device
 * and return a file descriptor.
 */
static int
openklog(char *name, int mode)
{
	int fd;
	struct strioctl str;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if ((fd = open(name, mode)) < 0) {
		logerror("cannot open %s", name);
		DPRINT3(1, "openklog(%u): cannot create %s (%d)\n",
		    mythreadno, name, errno);
		return (-1);
	}
	str.ic_cmd = I_CONSLOG;
	str.ic_timout = 0;
	str.ic_len = 0;
	str.ic_dp = NULL;
	if (ioctl(fd, I_STR, &str) < 0) {
		logerror("cannot register to log console messages");
		DPRINT2(1, "openklog(%u): cannot register to log "
		    "console messages (%d)\n", mythreadno, errno);
		return (-1);
	}
	return (fd);
}


/*
 * Open the log device, and pull up all pending messages.
 */
static void
prepare_sys_poll()
{
	int nfds, funix;

	if ((funix = openklog(LogName, O_RDONLY)) < 0) {
		logerror("can't open kernel log device - fatal");
		exit(1);
	}

	Pfd.fd = funix;
	Pfd.events = POLLIN;

	for (;;) {
		nfds = poll(&Pfd, 1, 0);
		if (nfds <= 0) {
			if (sys_init_msg_count > 0)
				flushmsg(SYNC_FILE);
			break;
		}

		if (Pfd.revents & POLLIN) {
			getkmsg(0);
		} else if (Pfd.revents & (POLLNVAL|POLLHUP|POLLERR)) {
			logerror("kernel log driver poll error");
			break;
		}
	}

}

/*
 * this thread listens to the local stream log driver for log messages
 * generated by this host, formats them, and queues them to the logger
 * thread.
 */
/*ARGSUSED*/
static void *
sys_poll(void *ap)
{
	int nfds;
	static int klogerrs = 0;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(1, "sys_poll(%u): sys_thread started\n", mythreadno);

	/*
	 * Process messages, blocking on poll because timeout is set
	 * to INFTIM.  When poll returns with a message, call getkmsg
	 * to pull up one message from the log driver and enqueue it
	 * with the sync flag set.
	 */

	sys_init_msg_count = 0;

	for (;;) {
		errno = 0;
		t_errno = 0;

		nfds = poll(&Pfd, 1, INFTIM);

		if (nfds == 0)
			continue;

		if (nfds < 0) {
			if (errno != EINTR)
				logerror("poll");
			continue;
		}
		if (Pfd.revents & POLLIN) {
			getkmsg(INFTIM);
		} else {
			if (shutting_down) {
				pthread_exit(0);
			}
			if (Pfd.revents & (POLLNVAL|POLLHUP|POLLERR)) {
				logerror("kernel log driver poll error");
				(void) close(Pfd.fd);
				Pfd.fd = -1;
			}
		}

		while (Pfd.fd == -1 && klogerrs++ < 10) {
			Pfd.fd = openklog(LogName, O_RDONLY);
		}
		if (klogerrs >= 10) {
			logerror("can't reopen kernel log device - fatal");
			exit(1);
		}
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * Pull up one message from log driver.
 */
static void
getkmsg(int timeout)
{
	int flags = 0, i;
	char *lastline;
	struct strbuf ctl, dat;
	struct log_ctl hdr;
	char buf[MAXLINE+1];
	size_t buflen;
	size_t len;
	char tmpbuf[MAXLINE+1];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	dat.maxlen = MAXLINE;
	dat.buf = buf;
	ctl.maxlen = sizeof (struct log_ctl);
	ctl.buf = (caddr_t)&hdr;

	while ((i = getmsg(Pfd.fd, &ctl, &dat, &flags)) == MOREDATA) {
		lastline = &dat.buf[dat.len];
		*lastline = '\0';

		DPRINT2(5, "getkmsg:(%u): getmsg: dat.len = %d\n",
		    mythreadno, dat.len);
		buflen = strlen(buf);
		len = findnl_bkwd(buf, buflen);

		(void) memcpy(tmpbuf, buf, len);
		tmpbuf[len] = '\0';

		/*
		 * Format sys will enqueue the log message.
		 * Set the sync flag if timeout != 0, which
		 * means that we're done handling all the
		 * initial messages ready during startup.
		 */
		if (timeout == 0) {
			formatsys(&hdr, tmpbuf, 0);
			sys_init_msg_count++;
		} else {
			formatsys(&hdr, tmpbuf, 1);
		}
		sys_msg_count++;

		if (len != buflen) {
			/* If anything remains in buf */
			size_t remlen;

			if (buf[len] == '\n') {
				/* skip newline */
				len++;
			}

			/*
			 *  Move the remaining bytes to
			 * the beginnning of buf.
			 */

			remlen = buflen - len;
			(void) memcpy(buf, &buf[len], remlen);
			dat.maxlen = MAXLINE - remlen;
			dat.buf = &buf[remlen];
		} else {
			dat.maxlen = MAXLINE;
			dat.buf = buf;
		}
	}

	if (i == 0 && dat.len > 0) {
		dat.buf[dat.len] = '\0';
		/*
		 * Format sys will enqueue the log message.
		 * Set the sync flag if timeout != 0, which
		 * means that we're done handling all the
		 * initial messages ready during startup.
		 */
		DPRINT2(5, "getkmsg(%u): getmsg: dat.maxlen = %d\n",
		    mythreadno, dat.maxlen);
		DPRINT2(5, "getkmsg(%u): getmsg: dat.len = %d\n",
		    mythreadno, dat.len);
		DPRINT2(5, "getkmsg(%u): getmsg: strlen(dat.buf) = %d\n",
		    mythreadno, strlen(dat.buf));
		DPRINT2(5, "getkmsg(%u): getmsg: dat.buf = \"%s\"\n",
		    mythreadno, dat.buf);
		DPRINT2(5, "getkmsg(%u): buf len = %d\n",
		    mythreadno, strlen(buf));
		if (timeout == 0) {
			formatsys(&hdr, buf, 0);
			sys_init_msg_count++;
		} else {
			formatsys(&hdr, buf, 1);
		}
		sys_msg_count++;
	} else if (i < 0 && errno != EINTR) {
		if (!shutting_down) {
			logerror("kernel log driver read error");
		}
		(void) close(Pfd.fd);
		Pfd.fd = -1;
	}
}

/*
 * this thread polls all the network interfaces for syslog messages
 * forwarded to us, tags them with the hostname they are received
 * from, and queues them to the logger thread.
 */
/*ARGSUSED*/
static void *
net_poll(void *ap)
{
	int nfds, i;
	int flags = 0;
	struct t_unitdata *udp;
	struct t_uderr *errp;
	char buf[MAXLINE+1];
	char *uap;
	log_message_t *mp;
	host_info_t *hinfo;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(1, "net_poll(%u): net_thread started\n", mythreadno);

	for (;;) {
		errno = 0;
		t_errno = 0;
		nfds = poll(Nfd, Ninputs, -1);
		if (nfds == 0)
			continue;

		if (nfds < 0) {
			if (errno != EINTR)
				logerror("poll");
			continue;
		}
		for (i = 0; nfds > 0 && i < Ninputs; i++) {
			if ((Nfd[i].revents & POLLIN) == 0) {
				if (shutting_down) {
					pthread_exit(0);
				}
				if (Nfd[i].revents &
				    (POLLNVAL|POLLHUP|POLLERR)) {
					logerror("POLLNVAL|POLLHUP|POLLERR");
					(void) t_close(Nfd[i].fd);
					Nfd[i].fd = -1;
					nfds--;
				}
				continue;
			}

			udp = Udp[i];
			udp->udata.buf = buf;
			udp->udata.maxlen = MAXLINE;
			udp->udata.len = 0;
			flags = 0;
			if (t_rcvudata(Nfd[i].fd, udp, &flags) < 0) {
				errp = Errp[i];
				if (t_errno == TLOOK) {
					if (t_rcvuderr(Nfd[i].fd, errp) < 0) {
						if (!shutting_down) {
							logerror("t_rcvuderr");
						}
						(void) t_close(Nfd[i].fd);
						Nfd[i].fd = -1;
					}
				} else {
					if (!shutting_down) {
						logerror("t_rcvudata");
					}
					(void) t_close(Nfd[i].fd);
					Nfd[i].fd = -1;
				}
				nfds--;
				if (shutting_down) {
					pthread_exit(0);
				}
				continue;
			}
			nfds--;

			if (udp->udata.len == 0) {
				if (Debug) {
					uap = NULL;
					if (udp->addr.len > 0) {
						uap = taddr2uaddr(&Ncf[i],
						    &udp->addr);
					}
					DPRINT2(1, "net_poll(%u):"
					    " received empty packet"
					    " from %s\n", mythreadno,
					    uap ? uap : "<unknown>");
					if (uap)
						free(uap);
				}
				continue;	/* No data */
			}
			if (udp->addr.len == 0) {
				/*
				 * The previous message was larger than
				 * MAXLINE, and T_MORE should have been set.
				 * Further data needs to be discarded as
				 * we've already received MAXLINE.
				 */
				DPRINT1(1, "net_poll(%u): discarding packet "
				    "exceeds max line size\n", mythreadno);
				continue;
			}

			net_msg_count++;

			if ((mp = new_msg()) == NULL) {
				MALLOC_FAIL("dropping message from "
				    "remote");
				continue;
			}

			buf[udp->udata.len] = '\0';
			formatnet(&udp->udata, mp);

			if (Debug) {
				uap = taddr2uaddr(&Ncf[i], &udp->addr);
				DPRINT2(1, "net_poll(%u): received message"
				    " from %s\n", mythreadno,
				    uap ? uap : "<unknown>");
				free(uap);
			}
			if ((hinfo = malloc(sizeof (*hinfo))) == NULL ||
			    (hinfo->addr.buf =
			    malloc(udp->addr.len)) == NULL) {
				MALLOC_FAIL("dropping message from "
				    "remote");
				if (hinfo) {
					free(hinfo);
				}
				free_msg(mp);
				continue;
			}

			hinfo->ncp = &Ncf[i];
			hinfo->addr.len = udp->addr.len;
			(void) memcpy(hinfo->addr.buf, udp->addr.buf,
			    udp->addr.len);
			mp->ptr = hinfo;
			if (dataq_enqueue(&hnlq, (void *)mp) == -1) {
				MALLOC_FAIL("dropping message from "
				    "remote");
				free_msg(mp);
				free(hinfo->addr.buf);
				free(hinfo);
				continue;
			}
			DPRINT3(5, "net_poll(%u): enqueued msg %p "
			    "on queue %p\n", mythreadno, (void *)mp,
			    (void *)&hnlq);
		}
	}
	/*NOTREACHED*/
	return (NULL);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: syslogd [-d] [-t|-T] [-mmarkinterval] [-ppath]"
	    " [-fconffile]\n");
	exit(1);
}

static void
untty(void)
{
	if (!Debug)
		(void) setsid();
}

/*
 * generate a log message internally. The original version of syslogd
 * simply called logmsg directly, but because everything is now based
 * on message passing, we need an internal way to generate and queue
 * log messages from within syslogd itself.
 */
static int
logmymsg(int pri, char *msg, int flags, int pending)
{
	log_message_t *mp;
	pthread_t mythreadno;
	dataq_t *qptr;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if ((mp = new_msg()) == NULL) {
		return (-1);
	}

	mp->pri = pri;
	mp->hlp = &LocalHostName;
	(void) strlcpy(mp->msg, msg, MAXLINE+1);
	mp->flags = flags;
	(void) time(&mp->ts);

	qptr = pending ? &tmpq : &inputq;
	if (dataq_enqueue(qptr, (void *)mp) == -1) {
		free_msg(mp);
		return (-1);
	}

	DPRINT3(5, "logmymsg(%u): enqueued msg %p on queue %p\n",
	    mythreadno, (void *)mp, (void *)qptr);
	DPRINT2(5, "logmymsg(%u): Message content: %s\n", mythreadno, msg);
	return (0);
}

/*
 * Generate an internal shutdown message
 */
static int
shutdown_msg(void)
{
	pthread_t mythreadno;
	log_message_t *mp;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if ((mp = new_msg()) == NULL) {
		return (-1);
	}

	mp->flags = SHUTDOWN;
	mp->hlp = &LocalHostName;

	if (dataq_enqueue(&inputq, (void *)mp) == -1) {
		free_msg(mp);
		return (-1);
	}

	DPRINT3(5, "shutdown_msg(%u): enqueued msg %p on queue %p\n",
	    mythreadno, (void *)mp, (void *)&inputq);
	return (0);
}

/*
 * Generate an internal flush message
 */
static void
flushmsg(int flags)
{
	log_message_t *mp;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if ((mp = new_msg()) == NULL) {
		MALLOC_FAIL("dropping flush msg");
		return;
	}

	mp->flags = FLUSHMSG | flags;
	mp->hlp = &LocalHostName;

	if (dataq_enqueue(&inputq, (void *)mp) == -1) {
		free_msg(mp);
		MALLOC_FAIL("dropping flush msg");
		return;
	}

	DPRINT4(5, "flush_msg(%u): enqueued msg %p on queue %p, flags "
	    "0x%x\n", mythreadno, (void *)mp, (void *)&inputq, flags);
}

/*
 * Do some processing on messages received from the net
 */
static void
formatnet(struct netbuf *nbp, log_message_t *mp)
{
	char *p;
	int pri;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT2(5, "formatnet(%u): called for msg %p\n", mythreadno,
	    (void *)mp);

	mp->flags = NETWORK;
	(void) time(&mp->ts);

	/* test for special codes */
	pri = DEFUPRI;
	p = nbp->buf;
	DPRINT2(9, "formatnet(%u): Message content:\n>%s<\n", mythreadno,
	    p);
	if (*p == '<' && isdigit(*(p+1))) {
		pri = 0;
		while (isdigit(*++p))
			pri = 10 * pri + (*p - '0');
		if (*p == '>')
			++p;
		if (pri <= 0 || pri >= (LOG_NFACILITIES << 3))
			pri = DEFUPRI;
	}

	mp->pri = pri;
	(void) strlcpy(mp->msg, p, MAXLINE+1);
}

/*
 * Do some processing on messages generated by this host
 * and then enqueue the log message.
 */
static void
formatsys(struct log_ctl *lp, char *msg, int sync)
{
	char *p, *q;
	char line[MAXLINE + 1];
	size_t msglen;
	log_message_t	*mp;
	char cbuf[30];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT3(3, "formatsys(%u): log_ctl.mid = %d, log_ctl.sid = %d\n",
	    mythreadno, lp->mid, lp->sid);
	DPRINT2(9, "formatsys(%u): Message Content:\n>%s<\n", mythreadno,
	    msg);

	/* msglen includes the null termination */
	msglen = strlen(msg) + 1;

	for (p = msg; *p != '\0'; ) {
		size_t linelen;
		size_t len;

		/*
		 * Allocate a log_message_t structure.
		 * We should do it here since a single message (msg)
		 * could be composed of many lines.
		 */
		if ((mp = new_msg()) == NULL) {
			MALLOC_FAIL("dropping message");
			/*
			 * Should bail out from the loop.
			 */
			break;
		}

		mp->flags &= ~NETWORK;
		mp->hlp = &LocalHostName;
		mp->ts = lp->ttime;
		if (lp->flags & SL_LOGONLY)
			mp->flags |= IGN_CONS;
		if (lp->flags & SL_CONSONLY)
			mp->flags |= IGN_FILE;

		/* extract facility */
		if ((lp->pri & LOG_FACMASK) == LOG_KERN) {
			(void) sprintf(line, "%.15s ",
			    ctime_r(&mp->ts, cbuf) + 4);
		} else {
			(void) sprintf(line, "");
		}

		linelen = strlen(line);
		q = line + linelen;

		DPRINT2(5, "formatsys(%u): msglen = %d\n", mythreadno, msglen);
		len = copynl_frwd(q, MAXLINE + 1 - linelen, p, msglen);
		DPRINT2(5, "formatsys(%u): len (copynl_frwd) = %d\n",
		    mythreadno, len);

		p += len;
		msglen -= len;

		if (*p == '\n') {
			/* skip newline */
			p++;
		}

		if (sync && ((lp->pri & LOG_FACMASK) == LOG_KERN))
			mp->flags |= SYNC_FILE;	/* fsync file after write */

		if (len != 0) {
			(void) strlcpy(mp->msg, line, MAXLINE+1);
			mp->pri = lp->pri;

			if (dataq_enqueue(&inputq, (void *)mp) == -1) {
				free_msg(mp);
				MALLOC_FAIL("dropping message");
				break;
			}

			DPRINT3(5, "formatsys(%u): sys_thread enqueued msg "
			    "%p on queue %p\n", mythreadno, (void *)mp,
			    (void *)&inputq);
		} else
			free_msg(mp);
	}
}

/*
 * Log a message to the appropriate log files, users, etc. based on
 * the priority.
 */
/*ARGSUSED*/
static void *
logmsg(void *ap)
{
	struct filed *f;
	int fac, prilev, flags, refcnt;
	int fake_shutdown, skip_shutdown;
	log_message_t *mp, *save_mp;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(1, "logmsg(%u): msg dispatcher started\n", mythreadno);

	fake_shutdown = skip_shutdown = 0;
	save_mp = NULL;
	for (;;) {
		if (save_mp) {
			/*
			 * If we have set aside a message in order to fake a
			 * SHUTDOWN, use that message before picking from the
			 * queue again.
			 */
			mp = save_mp;
			save_mp = NULL;
		} else {
			(void) dataq_dequeue(&inputq, (void **)&mp, 0);
		}
		DPRINT3(5, "logmsg(%u): msg dispatcher dequeued %p from "
		    "queue %p\n", mythreadno, (void *)mp,
		    (void *)&inputq);

		/*
		 * In most cases, if the message traffic is low, logmsg() wakes
		 * up when it receives the SHUTDOWN msg, and will sleep until
		 * HUP process is complete.  However, if the inputq is too
		 * long, logmsg() may not receive SHUTDOWN before reconfigure()
		 * releases the logger fds, filed and logit threads.  That, in
		 * turn, will cause logmsg to refer to invalid fileds.
		 *
		 * logmsg() needs to respond to the SHUTDOWN message within
		 * LOOP_INTERVAL seconds when reconfigure() enqueues it. It
		 * does so in most cases.  When it does not respond in time,
		 * logmsg() needs to be in suspended state immediately, since
		 * filed may have been invalidated. reconfigure() will set the
		 * HUP_SUSP_LOGMSG_REQD bit in hup_state and wait another
		 * LOOP_INTERVAL seconds before proceeding.
		 *
		 * When HUP_SUSP_LOGMSG_REQD is set, we will create a fake
		 * SHUTDOWN message, and dispatch it to the various logit
		 * threads, and logmsg() itself will suspend.  In order to
		 * ignore the real SHUTDOWN which will arrive later, we keep a
		 * counter (skip_shutdown) and decrement it when the SHUTDOWN
		 * message arrives.
		 */
		if ((hup_state & HUP_SUSP_LOGMSG_REQD) &&
		    (mp->flags & SHUTDOWN) == 0) {
			DPRINT1(3, "logmsg(%u): suspend request\n",
			    mythreadno);

			save_mp = mp;

			/* create a fake SHUTDOWN msg */
			if ((mp = new_msg()) == NULL) {
				MALLOC_FAIL("dropping message");
				if (mp->flags & SHUTDOWN) {
					(void) logerror_to_console(1,
					    "unable to shutdown "
					    "logger thread");
				}
				continue;
			}
			mp->flags = SHUTDOWN;
			mp->hlp = &LocalHostName;
			fake_shutdown = 1;
			skip_shutdown++;
			DPRINT2(3, "logmsg(%u): pending SHUTDOWN %d\n",
			    mythreadno, skip_shutdown);
		}

		/*
		 * is it a shutdown or flush message ?
		 */
		if ((mp->flags & SHUTDOWN) || (mp->flags & FLUSHMSG)) {
			(void) pthread_mutex_lock(&mp->msg_mutex);

			if ((mp->flags & SHUTDOWN) &&
			    !fake_shutdown && skip_shutdown > 0) {
				skip_shutdown--;
				(void) pthread_mutex_unlock(&mp->msg_mutex);
				free_msg(mp);
				DPRINT2(3, "logmsg(%u): released late "
				    "arrived SHUTDOWN. pending %d\n",
				    mythreadno, skip_shutdown);
				continue;
			}

			for (f = Files; f < &Files[nlogs]; f++) {
				(void) pthread_mutex_lock(&f->filed_mutex);

				if (f->f_type == F_UNUSED) {
					(void) pthread_mutex_unlock(
					    &f->filed_mutex);
					continue;
				}

				f->f_queue_count++;
				mp->refcnt++;

				if (dataq_enqueue(&f->f_queue,
				    (void *)mp) == -1) {
					f->f_queue_count--;
					mp->refcnt--;
					(void) pthread_mutex_unlock(
					    &f->filed_mutex);
					MALLOC_FAIL("dropping message");

					if (mp->flags & SHUTDOWN) {
						(void) logerror_to_console(1,
						    "unable to shutdown "
						    "logger thread");
					}

					continue;
				}
				DPRINT3(5, "logmsg(%u): enqueued msg %p "
				    "on queue %p\n", mythreadno,
				    (void *)mp, (void *)&f->f_queue);
				(void) pthread_mutex_unlock(&f->filed_mutex);
			}

			/*
			 * flags value needs to be saved because mp may
			 * have been freed before SHUTDOWN test below.
			 */
			flags = mp->flags;
			refcnt = mp->refcnt;

			(void) pthread_mutex_unlock(&mp->msg_mutex);
			if (refcnt == 0)
				free_msg(mp);

			if (flags & SHUTDOWN) {
				(void) pthread_mutex_lock(&hup_lock);
				while (hup_state != HUP_COMPLETED) {
					hup_state |= HUP_LOGMSG_SUSPENDED;
					(void) pthread_cond_wait(&hup_done,
					    &hup_lock);
					hup_state &= ~HUP_LOGMSG_SUSPENDED;
				}
				hup_state = HUP_ACCEPTABLE;
				(void) pthread_mutex_unlock(&hup_lock);
				fake_shutdown = 0;
			}
			continue;
		}

		/*
		 * Check to see if msg looks non-standard.
		 */
		if ((int)strlen(mp->msg) < 16 || mp->msg[3] != ' ' ||
		    mp->msg[6] != ' ' || mp->msg[9] != ':' ||
		    mp->msg[12] != ':' || mp->msg[15] != ' ')
			mp->flags |= ADDDATE;

		/* extract facility and priority level */
		fac = (mp->pri & LOG_FACMASK) >> 3;
		if (mp->flags & MARK)
			fac = LOG_NFACILITIES;
		prilev = mp->pri & LOG_PRIMASK;

		DPRINT3(3, "logmsg(%u): fac = %d, pri = %d\n",
		    mythreadno, fac, prilev);

		/*
		 * Because different devices log at different speeds,
		 * it's important to hold the mutex for the current
		 * message until it's been enqueued to all log files,
		 * so the reference count is accurate before any
		 * of the log threads can decrement it.
		 */
		(void) pthread_mutex_lock(&mp->msg_mutex);

		for (f = Files; f < &Files[nlogs]; f++) {
			/* skip messages that are incorrect priority */
			if (f->f_pmask[fac] < (unsigned)prilev ||
			    f->f_pmask[fac] == NOPRI)
				continue;
			if (f->f_queue_count > Q_HIGHWATER_MARK) {
				DPRINT4(5, "logmsg(%u): Dropping message "
				    "%p on file %p, count = %d\n",
				    mythreadno, (void *)mp, (void *)f,
				    f->f_queue_count);
				continue;
			}

			/*
			 * Need to grab filed_mutex before testing the f_type.
			 * Otherwise logit() may set F_UNUSED after the test
			 * below, and start pulling out the pending messages.
			 */

			(void) pthread_mutex_lock(&f->filed_mutex);

			if (f->f_type == F_UNUSED ||
			    (f->f_type == F_FILE && (mp->flags & IGN_FILE)) ||
			    (f->f_type == F_CONSOLE &&
			    (mp->flags & IGN_CONS))) {
				(void) pthread_mutex_unlock(&f->filed_mutex);
				continue;
			}

			f->f_queue_count++;
			mp->refcnt++;

			if (dataq_enqueue(&f->f_queue, (void *)mp) == -1) {
				f->f_queue_count--;
				mp->refcnt--;
				(void) pthread_mutex_unlock(&f->filed_mutex);
				MALLOC_FAIL("dropping message");
				continue;
			}

			DPRINT3(5, "logmsg(%u): enqueued msg %p on queue "
			    "%p\n", mythreadno, (void *)mp,
			    (void *)&f->f_queue);
			(void) pthread_mutex_unlock(&f->filed_mutex);
		}
		refcnt = mp->refcnt;
		(void) pthread_mutex_unlock(&mp->msg_mutex);
		if (refcnt == 0)
			free_msg(mp);
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * function to actually write the log message to the selected file.
 * each file has a logger thread that runs this routine. The function
 * is called with a pointer to its file structure.
 */
static void *
logit(void *ap)
{
	struct filed *f = ap;
	log_message_t *mp;
	int forwardingloop = 0;
	const char *errmsg = "logit(%u): %s to %s forwarding loop detected\n";
	int i, currofst, prevofst, refcnt;
	host_list_t *hlp;

	assert(f != NULL);

	DPRINT4(5, "logit(%u): logger started for \"%s\" (queue %p, filed "
	    "%p)\n", f->f_thread, f->f_un.f_fname, (void *)&f->f_queue,
	    (void *)f);

	while (f->f_type != F_UNUSED) {
		(void) dataq_dequeue(&f->f_queue, (void **)&mp, 0);
		DPRINT3(5, "logit(%u): logger dequeued msg %p from queue "
		    "%p\n", f->f_thread, (void *)mp, (void *)&f->f_queue);
		(void) pthread_mutex_lock(&f->filed_mutex);
		assert(f->f_queue_count > 0);
		f->f_queue_count--;
		(void) pthread_mutex_unlock(&f->filed_mutex);
		assert(mp->refcnt > 0);

		/*
		 * is it a shutdown message ?
		 */
		if (mp->flags & SHUTDOWN) {
			(void) pthread_mutex_lock(&mp->msg_mutex);
			refcnt = --mp->refcnt;
			(void) pthread_mutex_unlock(&mp->msg_mutex);
			if (refcnt == 0)
				free_msg(mp);
			break;
		}

		/*
		 * Is it a logsync message?
		 */
		if ((mp->flags & (FLUSHMSG | LOGSYNC)) ==
		    (FLUSHMSG | LOGSYNC)) {
			if (f->f_type != F_FILE)
				goto out;	/* nothing to do */
			(void) close(f->f_file);
			f->f_file = open64(f->f_un.f_fname,
			    O_WRONLY|O_APPEND|O_NOCTTY);
			if (f->f_file < 0) {
				f->f_type = F_UNUSED;
				logerror(f->f_un.f_fname);
				f->f_stat.errs++;
			}
			goto out;
		}

		/*
		 * If the message flags include both flush and sync,
		 * then just sync the file out to disk if appropriate.
		 */
		if ((mp->flags & (FLUSHMSG | SYNC_FILE)) ==
		    (FLUSHMSG | SYNC_FILE)) {
			if (f->f_type == F_FILE) {
				DPRINT2(5, "logit(%u): got FLUSH|SYNC "
				    "for filed %p\n", f->f_thread,
				    (void *)f);
				(void) fsync(f->f_file);
			}
			goto out;
		}

		/*
		 * Otherwise if it's a standard flush message, write
		 * out any saved messages to the file.
		 */
		if ((mp->flags & FLUSHMSG) && (f->f_prevcount > 0)) {
			set_flush_msg(f);
			writemsg(SAVED, f);
			goto out;
		}

		(void) strlcpy(f->f_current.msg, mp->msg, MAXLINE+1);
		(void) strlcpy(f->f_current.host, mp->hlp->hl_hosts[0],
		    SYS_NMLN);
		f->f_current.pri = mp->pri;
		f->f_current.flags = mp->flags;
		f->f_current.time = mp->ts;
		f->f_msgflag &= ~CURRENT_VALID;
		hlp = mp->hlp;

		prevofst = (f->f_prevmsg.flags & ADDDATE) ? 0 : 16;
		currofst = (f->f_current.flags & ADDDATE) ? 0 : 16;

		if (f->f_type == F_FORW) {
			/*
			 * Should not forward MARK messages, as they are
			 * not defined outside of the current system.
			 */

			if (mp->flags & MARK) {
				DPRINT1(1, "logit(%u): cannot forward "
				    "Mark\n", f->f_thread);
				goto out;
			}

			/*
			 * can not forward message if we do
			 * not have a host to forward to
			 */
			if (hlp == (host_list_t *)NULL)
				goto out;
			/*
			 * a forwarding loop is created on machines
			 * with multiple interfaces because the
			 * network address of the sender is different
			 * to the receiver even though it is the
			 * same machine. Instead, if the
			 * hostname the source and target are
			 * the same the message if thrown away
			 */
			forwardingloop = 0;
			for (i = 0; i < hlp->hl_cnt; i++) {
				if (strcmp(hlp->hl_hosts[i],
				    f->f_un.f_forw.f_hname) == 0) {
					DPRINT3(1, errmsg, f->f_thread,
					    f->f_un.f_forw.f_hname,
					    hlp->hl_hosts[i]);
					forwardingloop = 1;
					break;
				}
			}

			if (forwardingloop == 1) {
				f->f_stat.cantfwd++;
				goto out;
			}
		}

		f->f_msgflag |= CURRENT_VALID;

		/* check for dup message */
		if (f->f_type != F_FORW &&
		    (f->f_msgflag & OLD_VALID) &&
		    prevofst == currofst &&
		    (strcmp(f->f_prevmsg.msg + prevofst,
		    f->f_current.msg + currofst) == 0) &&
		    (strcmp(f->f_prevmsg.host,
		    f->f_current.host) == 0)) {
			/* a dup */
			DPRINT2(2, "logit(%u): msg is dup - %p\n",
			    f->f_thread, (void *)mp);
			if (currofst == 16) {
				(void) strncpy(f->f_prevmsg.msg,
				    f->f_current.msg, 15); /* update time */
			}
			f->f_prevcount++;
			f->f_stat.dups++;
			f->f_stat.total++;
			f->f_msgflag &= ~CURRENT_VALID;
		} else {
			/* new: mark or prior dups exist */
			if (f->f_current.flags & MARK || f->f_prevcount > 0) {
				if (f->f_prevcount > 0 && f->f_type != F_FORW) {
					set_flush_msg(f);
					if (f->f_msgflag & OLD_VALID) {
						writemsg(SAVED, f);
					}
				}
				if (f->f_msgflag & CURRENT_VALID)
					writemsg(CURRENT, f);
				if (!(mp->flags & NOCOPY))
					copy_msg(f);
				if (f->f_current.flags & MARK) {
					DPRINT2(2, "logit(%u): msg is "
					    "mark - %p)\n", f->f_thread,
					    (void *)mp);
					f->f_msgflag &= ~OLD_VALID;
				} else {
					DPRINT2(2, "logit(%u): saving "
					    "message - %p\n", f->f_thread,
					    (void *)mp);
				}
				f->f_stat.total++;
			} else { /* new message */
				DPRINT2(2, "logit(%u): msg is new "
				    "- %p\n", f->f_thread, (void *)mp);
				writemsg(CURRENT, f);
				if (!(mp->flags & NOCOPY))
					copy_msg(f);
				f->f_stat.total++;
			}
		}
		/*
		 * if message refcnt goes to zero after we decrement
		 * it here, we are the last consumer of the message,
		 * and we should free it.  We need to hold the lock
		 * between decrementing the count and checking for
		 * zero so another thread doesn't beat us to it.
		 */
out:
		(void) pthread_mutex_lock(&mp->msg_mutex);
		refcnt = --mp->refcnt;
		(void) pthread_mutex_unlock(&mp->msg_mutex);
		if (refcnt == 0)
			free_msg(mp);
	}
	/* register our exit */

	/*
	 * Pull out all pending messages, if they exist.
	 */

	(void) pthread_mutex_lock(&f->filed_mutex);

	while (f->f_queue_count > 0) {
		(void) dataq_dequeue(&f->f_queue, (void **)&mp, 0);
		DPRINT3(5, "logit(%u): logger dequeued msg %p from queue "
		    "%p\n",
		    f->f_thread, (void *)mp, (void *)&f->f_queue);
		(void) pthread_mutex_lock(&mp->msg_mutex);
		refcnt = --mp->refcnt;
		(void) pthread_mutex_unlock(&mp->msg_mutex);
		if (refcnt == 0)
			free_msg(mp);
		f->f_queue_count--;
	}

	(void) pthread_mutex_unlock(&f->filed_mutex);

	if (f->f_type != F_USERS && f->f_type != F_WALL &&
	    f->f_type != F_UNUSED) {
		if (f->f_type == F_FORW)
			(void) t_close(f->f_file);
		else
			(void) close(f->f_file);
	}

	/*
	 * Since f_type may have been changed before this point, we need
	 * to test orig_type.
	 */
	if (f->f_orig_type == F_FORW) {
		free(f->f_un.f_forw.f_addr.buf);
	}

	f->f_type = F_UNUSED;
	(void) pthread_mutex_lock(&cft);
	--conf_threads;
	(void) pthread_mutex_unlock(&cft);
	DPRINT1(5, "logit(%u): logging thread exited\n", f->f_thread);
	return (NULL);
}

/*
 * change the previous message to a flush message, stating how
 * many repeats occurred since the last flush
 */
static void
set_flush_msg(struct filed *f)
{
	char tbuf[10];
	int prevofst = (f->f_prevmsg.flags & ADDDATE) ? 0 : 16;

	if (f->f_prevcount == 1)
		(void) strncpy(tbuf, "time", sizeof (tbuf));
	else
		(void) strncpy(tbuf, "times", sizeof (tbuf));

	(void) snprintf(f->f_prevmsg.msg+prevofst,
	    sizeof (f->f_prevmsg.msg) - prevofst,
	    "last message repeated %d %s", f->f_prevcount, tbuf);
	f->f_prevcount = 0;
	f->f_msgflag |= OLD_VALID;
}


/*
 * the actual writing of the message is broken into a separate function
 * because each file has a current and saved message associated with
 * it (for duplicate message detection). It is necessary to be able
 * to write either the saved message or the current message.
 */
static void
writemsg(int selection, struct filed *f)
{
	char *cp, *p;
	int pri;
	int flags;
	int l;
	time_t ts;
	struct t_unitdata ud;
	char *eomp, *eomp2, *from, *text, *msg;
	char line[MAXLINE*2];
	char head[MAXLINE+1];
	char tmpbuf[MAXLINE+1];
	char cbuf[30];
	char *filtered;
	char *msgid_start, *msgid_end;
	pthread_t mythreadno;
	size_t	hlen, filter_len;

	if (Debug) {
		mythreadno = pthread_self();
	}

	switch (selection) {
	default:
	case CURRENT:		/* print current message */
		msg = f->f_current.msg;
		from = f->f_current.host;
		pri = f->f_current.pri;
		flags = f->f_current.flags;
		ts = f->f_current.time;
		f->f_msgflag &= ~CURRENT_VALID;
		break;
	case SAVED:		/* print saved message */
		msg = f->f_prevmsg.msg;
		from = f->f_prevmsg.host;
		pri = f->f_prevmsg.pri;
		flags = f->f_prevmsg.flags;
		ts = f->f_prevmsg.time;
		f->f_msgflag &= ~OLD_VALID;
		break;
	}

	if (msg[0] == '\0')
		return;

	cp = line;

	if (flags & ADDDATE)
		(void) strncpy(cp, ctime_r(&ts, cbuf) + 4, 15);
	else
		(void) strncpy(cp, msg, 15);

	line[15] = '\0';
	(void) strcat(cp, " ");
	(void) strcat(cp, from);
	(void) strcat(cp, " ");
	text = cp + strlen(cp);

	if (flags & ADDDATE)
		(void) strcat(cp, msg);
	else
		(void) strcat(cp, msg+16);
	DPRINT2(5, "writemsg(%u): text = \"%s\"\n", mythreadno, text);

	errno = 0;
	t_errno = 0;
	switch (f->f_type) {
	case F_UNUSED:
		DPRINT1(1, "writemsg(%u): UNUSED\n", mythreadno);
		break;
	case F_FORW:
		DPRINT4(1, "writemsg(%u): Logging msg '%s' to %s %s\n",
		    mythreadno, msg, TypeNames[f->f_type],
		    f->f_un.f_forw.f_hname);

		hlen = snprintf(head, sizeof (head),
		    "<%d>%.15s ", pri, cp);

		DPRINT2(5, "writemsg(%u): head = \"%s\"\n", mythreadno, head);
		DPRINT2(5, "writemsg(%u): hlen = %d\n", mythreadno, hlen);

		l = strlen(text);
		p = text;

		DPRINT2(5, "writemsg(%u): text = \"%s\"\n", mythreadno, text);
		DPRINT2(5, "writemsg(%u): strlen(text) = %d\n", mythreadno, l);

		(void) strncpy(tmpbuf, head, hlen);

		while (l > 0) {
			size_t	len;

			len = copy_frwd(tmpbuf + hlen, sizeof (tmpbuf) - hlen,
			    p, l);

			DPRINT2(5, "writemsg(%u): tmpbuf = \"%s\"\n",
			    mythreadno, tmpbuf);
			DPRINT2(5, "writemsg(%u): len = %d\n", mythreadno,
			    len);
			DPRINT2(5, "writemsg(%u): strlen(tmpbuf) = %d\n",
			    mythreadno, strlen(tmpbuf));

			ud.opt.buf = NULL;
			ud.opt.len = 0;
			ud.udata.buf = tmpbuf;
			ud.udata.len = len + hlen;
			ud.addr.maxlen = f->f_un.f_forw.f_addr.maxlen;
			ud.addr.buf = f->f_un.f_forw.f_addr.buf;
			ud.addr.len = f->f_un.f_forw.f_addr.len;
			if (t_sndudata(f->f_file, &ud) < 0) {
				if ((hup_state & HUP_INPROGRESS) &&
				    f->f_type == F_UNUSED) {
					break;
				}
				(void) t_close(f->f_file);
				f->f_type = F_UNUSED;
				logerror("t_sndudata");

				/*
				 * Since it has already failed, it's not worth
				 * continuing output from the middle of
				 * message string.
				 */
				break;
			}
			p += len;
			l -= len;
		}
		break;
	case F_CONSOLE:
	case F_TTY:
	case F_FILE:
	case F_USERS:
	case F_WALL:
		DPRINT4(1, "writemsg(%u): Logging msg '%s' to %s %s\n",
		    mythreadno, msg, TypeNames[f->f_type],
		    ((f->f_type == F_USERS) || (f->f_type == F_WALL)) ?
		    "" : f->f_un.f_fname);
		/*
		 * filter the string in preparation for writing it
		 * save the original for possible forwarding.
		 * In case every byte in cp is a control character,
		 * allocates large enough buffer for filtered.
		 */

		filter_len = strlen(cp) * 4 + 1;
		filtered = (char *)malloc(filter_len);
		if (!filtered) {
			MALLOC_FAIL("dropping message");
			/* seems we can just return */
			return;
		}
		DPRINT3(5, "writemsg(%u): "
		    "filtered allocated (%p: %d bytes)\n",
		    mythreadno, (void *)filtered, filter_len);
		/* -3 : we may add "\r\n" to ecomp(filtered) later */
		filter_string(cp, filtered, filter_len - 3);

		DPRINT2(5, "writemsg(%u): strlen(filtered) = %d\n",
		    mythreadno, strlen(filtered));
		/*
		 * If we're writing to the console, strip out the message ID
		 * to reduce visual clutter.
		 */
		if ((msgid_start = strstr(filtered, "[ID ")) != NULL &&
		    (msgid_end = strstr(msgid_start, "] ")) != NULL &&
		    f->f_type == F_CONSOLE)
			(void) strcpy(msgid_start, msgid_end + 2);

		eomp = filtered + strlen(filtered);

		if ((f->f_type == F_USERS) || (f->f_type == F_WALL)) {
			/* CSTYLED */
			(void) strcat(eomp, "\r\n"); /*lint !e669*/
			/*
			 * Since wallmsg messes with utmpx we need
			 * to guarantee single threadedness...
			 */
			(void) pthread_mutex_lock(&wmp);
			wallmsg(f, from, filtered);
			(void) pthread_mutex_unlock(&wmp);

			/*
			 * The contents of filtered have been copied
			 * out to the struct walldev. We should free it here.
			 */

			free(filtered);

			/* exiting the switch */
			break;
		} else if (f->f_type != F_FILE) {
			/* CSTYLED */
			(void) strncpy(eomp, "\r\n", 3); /*lint !e669*/
		} else {
			if ((eomp2 = strchr(filtered, '\r')) != NULL) {
				(void) strncpy(eomp2, "\n", 2);
			} else {
				/* CSTYLED */
				(void) strncpy(eomp, "\n", 2); /*lint !e669*/
			}
		}
		if (write(f->f_file, filtered, strlen(filtered)) < 0) {
			int e = errno;

			if ((hup_state & HUP_INPROGRESS) &&
			    f->f_type == F_UNUSED) {
				free(filtered);
				break;
			}
			(void) close(f->f_file);
			/*
			 * Check for EBADF on TTY's due
			 * to vhangup() XXX
			 */
			if (e == EBADF && f->f_type != F_FILE) {
				f->f_file = open(f->f_un.f_fname,
				    O_WRONLY|O_APPEND|O_NOCTTY);
				if (f->f_file < 0) {
					f->f_type = F_UNUSED;
					logerror(f->f_un.f_fname);
					f->f_stat.errs++;
				}
				untty();
			} else {
				f->f_type = F_UNUSED;
				f->f_stat.errs++;
				errno = e;
				logerror(f->f_un.f_fname);
			}
		} else if (flags & SYNC_FILE)
			if (((pri & LOG_FACMASK) >> 3) == LOG_KERN)
				(void) fsync(f->f_file);

		DPRINT2(5, "writemsg(%u): freeing filtered (%p)\n",
		    mythreadno, (void *)filtered);

		free(filtered);
		break;
	}
}

/*
 *  WALLMSG -- Write a message to the world at large
 *
 *	Write the specified message to either the entire
 *	world, or a list of approved users.
 */
static void
wallmsg(struct filed *f, char *from, char *msg)
{
	int i;
	size_t	len, clen;
	char *buf = NULL;
	struct utmpx *utxp;
	time_t now;
	char line[512], dev[100];
	char cp[MAXLINE+1];
	struct stat statbuf;
	walldev_t *w;
	char cbuf[30];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (access(UTMPX_FILE, R_OK) != 0 || stat(UTMPX_FILE, &statbuf) != 0) {
		logerror(UTMPX_FILE);
		return;
	} else if (statbuf.st_uid != 0 || (statbuf.st_mode & 07777) != 0644) {
		(void) snprintf(line, sizeof (line), "%s %s", UTMPX_FILE,
		    "not owned by root or not mode 644.\n"
		    "This file must be owned by root "
		    "and not writable by\n"
		    "anyone other than root.  This alert is being "
		    "dropped because of\n"
		    "this problem.");
		logerror(line);
		return;
	}

	if (f->f_type == F_WALL) {
		(void) time(&now);
		len = snprintf(line, sizeof (line),
		    "\r\n\7Message from syslogd@%s "
		    "at %.24s ...\r\n", from, ctime_r(&now, cbuf));
		len += strlen(msg + 16);
		buf = (char *)malloc(len + 1);
		if (!buf) {
			MALLOC_FAIL("dropping message");
			return;
		}
		DPRINT3(5, "wallmsg(%u): buf allocated (%p: %d bytes)\n",
		    mythreadno, (void *)buf, len + 1);
		(void) strcpy(buf, line);
		(void) strcat(buf, msg + 16);
		clen = copy_frwd(cp, sizeof (cp), buf, len);
		DPRINT2(5, "wallmsg(%u): clen = %d\n",
		    mythreadno, clen);
		DPRINT2(5, "wallmsg(%u): freeing buf (%p)\n",
		    mythreadno, (void *)buf);
		free(buf);
	} else {
		clen = copy_frwd(cp, sizeof (cp), msg, strlen(msg));
		DPRINT2(5, "wallmsg(%u): clen = %d\n",
		    mythreadno, clen);
	}
	/* scan the user login file */
	setutxent();
	while ((utxp = getutxent()) != NULL) {
		/* is this slot used? */
		if (utxp->ut_name[0] == '\0' ||
		    utxp->ut_line[0] == '\0' ||
		    utxp->ut_type != USER_PROCESS)
			continue;
		/* should we send the message to this user? */
		if (f->f_type == F_USERS) {
			for (i = 0; i < MAXUNAMES; i++) {
				if (!f->f_un.f_uname[i][0]) {
					i = MAXUNAMES;
					break;
				}
				if (strncmp(f->f_un.f_uname[i],
				    utxp->ut_name, UNAMESZ) == 0)
					break;
			}
			if (i >= MAXUNAMES)
				continue;
		}

		/* compute the device name */
		if (utxp->ut_line[0] == '/') {
			(void) strncpy(dev, utxp->ut_line, UDEVSZ);
		} else {
			(void) strcpy(dev, "/dev/");
			(void) strncat(dev, utxp->ut_line, UDEVSZ);
		}
		DPRINT2(1, "wallmsg(%u): write to '%s'\n", mythreadno,
		    dev);

		if ((w = malloc(sizeof (walldev_t))) != NULL) {
			int rc;
			(void) pthread_attr_init(&w->thread_attr);
			(void) pthread_attr_setdetachstate(&w->thread_attr,
			    PTHREAD_CREATE_DETACHED);
			(void) strncpy(w->dev, dev, PATH_MAX);
			(void) strncpy(w->msg, cp, MAXLINE+1);
			(void) strncpy(w->ut_name, utxp->ut_name,
			    sizeof (w->ut_name));

			if ((rc = pthread_create(&w->thread, &w->thread_attr,
			    writetodev, (void *) w)) != 0) {
				DPRINT2(5, "wallmsg(%u): wallmsg thread "
				    "create failed rc = %d\n",
				    mythreadno, rc);
				free(w);
				break;
			}
		} else {
			MALLOC_FAIL("dropping message to user");
		}
	}
	/* close the user login file */
	endutxent();
}

/*
 * Each time we need to write to a tty device (a potentially expensive
 * or long-running operation) this routine gets called as a new
 * detached, unbound thread. This allows writes to many devices
 * to proceed nearly in parallel, without having to resort to
 * asynchronous I/O or forking.
 */
static void *
writetodev(void *ap)
{
	walldev_t *w = ap;
	int ttyf;
	int len;
	struct stat statb;
	struct passwd pw, *pwp;
	char pwbuf[MAXLINE];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(1, "writetodev(%u): Device writer thread started\n",
	    mythreadno);

	len = strlen(w->msg);

	ttyf = open(w->dev, O_WRONLY|O_NOCTTY|O_NDELAY);
	if (ttyf >= 0) {
		if (fstat(ttyf, &statb) != 0) {
			DPRINT2(1, "writetodev(%u): Can't stat '%s'\n",
			    mythreadno, w->dev);
			errno = 0;
			logerror("Can't stat '%s'", w->dev);
		} else if (!(statb.st_mode & S_IWRITE)) {
			DPRINT2(1, "writetodev(%u): Can't write to "
			    "'%s'\n", mythreadno, w->dev);
		} else if (!isatty(ttyf)) {
			DPRINT2(1, "writetodev(%u): '%s' not a tty\n",
			    mythreadno, w->dev);
			/*
			 * We might hit dtremote here. Don't generate
			 * error message.
			 */
		} else if (getpwuid_r(statb.st_uid, &pw, pwbuf,
		    sizeof (pwbuf), &pwp) != 0) {
			DPRINT2(1, "writetodev(%u): Can't determine owner "
			    "of '%s'\n", mythreadno, w->dev);
			errno = 0;
			logerror("Can't determine owner of '%s'", w->dev);
		} else if (strncmp(pw.pw_name, w->ut_name, UNAMESZ) != 0) {
			DPRINT2(1, "writetodev(%u): Bad terminal owner '%s'"
			    "\n", mythreadno, w->dev);
			errno = 0;
			logerror("%s %s owns '%s' %s %.*s",
			    "Bad terminal owner;", pw.pw_name, w->dev,
			    "but utmpx says", UNAMESZ, w->ut_name);
		} else if (write(ttyf, w->msg, len) != len) {
			DPRINT2(1, "writetodev(%u): Write failed to "
			    "'%s'\n", mythreadno, w->dev);
			errno = 0;
			logerror("Write failed to '%s'", w->dev);
		}

		DPRINT2(1, "writetodev(%u): write to '%s' succeeded\n",
		    mythreadno, w->dev);

		(void) close(ttyf);
	} else {
		DPRINT2(1, "writetodev(%u): Can't open '%s'\n",
		    mythreadno, w->dev);
	}

	(void) pthread_attr_destroy(&w->thread_attr);
	free(w);

	DPRINT1(1, "writetodev(%u): Device writer thread exiting\n",
	    mythreadno);

	pthread_exit(0);
	return (NULL);
	/*NOTREACHED*/
}

/*
 * Return a printable representation of a host address. If unable to
 * look up hostname, format the numeric address for display instead.
 *
 * First calls hnc_lookup to see if there is valid cache entry for
 * given network address. If it failed, cvthname looks up hostname,
 * and push the results into the hostname cache.
 */
static host_list_t *
cvthname(struct netbuf *nbp, struct netconfig *ncp, char *failsafe_addr)
{
	int i;
	host_list_t *h;
	struct nd_hostservlist *hsp;
	struct nd_hostserv *hspp;
	pthread_t mythreadno;
	int hindex;
	char *uap;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (Debug)
		uap = taddr2uaddr(ncp, nbp);

	DPRINT2(2, "cvthname(%u): looking up hostname for %s\n",
	    mythreadno, uap ? uap : "<unknown>");

	if ((h = hnc_lookup(nbp, ncp, &hindex)) != NULL) {
		DPRINT4(2, "cvthname(%u): Cache found %p for %s (%s)\n",
		    mythreadno, (void *)h, uap ? uap : "<unknown>",
		    h->hl_hosts[0]);
		return (h);
	}
	DPRINT2(2, "cvthname(%u): No cache found for %s\n",
	    mythreadno, uap ? uap : "<unknown>");

	if (Debug)
		free(uap);

	if (ncp->nc_semantics != NC_TPI_CLTS) {
		return (NULL);
	}

	/* memory allocation failure here is fatal */
	if ((h = malloc(sizeof (host_list_t))) == NULL) {
		MALLOC_FAIL("host name conversion");
		return (NULL);
	}

	if (netdir_getbyaddr(ncp, &hsp, nbp) == 0) {
		if (hsp->h_cnt <= 0) {
out:			netdir_free((void *)hsp, ND_HOSTSERVLIST);
			free(h);
			return (NULL);
		}

		hspp = hsp->h_hostservs;
		h->hl_cnt = hsp->h_cnt;
		h->hl_hosts = (char **)malloc(sizeof (char *) * (h->hl_cnt));
		if (h->hl_hosts == NULL) {
			MALLOC_FAIL("host name conversion");
			goto out;
		}

		DPRINT2(2, "cvthname(%u): Found %d hostnames\n",
		    mythreadno, h->hl_cnt);
		for (i = 0; i < h->hl_cnt; i++) {
			h->hl_hosts[i] = (char *)
			    malloc(sizeof (char) * (strlen(hspp->h_host) + 1));
			if (h->hl_hosts[i] == NULL) {
				int j;
				for (j = 0; j < i; j++) {
					free(h->hl_hosts[j]);
				}
				free(h->hl_hosts);
				MALLOC_FAIL("host name conversion");
				goto out;
			}
			(void) strcpy(h->hl_hosts[i], hspp->h_host);
			hspp++;
		}
		netdir_free((void *)hsp, ND_HOSTSERVLIST);
	} else { /* unknown address */
		h->hl_cnt = 1;
		h->hl_hosts = (char **)malloc(sizeof (char *));
		if (h->hl_hosts == NULL) {
			free(h);
			MALLOC_FAIL("host name conversion");
			return (NULL);
		}
		h->hl_hosts[0] = (char *)malloc(strlen(failsafe_addr) + 3);
		if (h->hl_hosts[0] == NULL) {
			free(h->hl_hosts);
			free(h);
			MALLOC_FAIL("host name conversion");
			return (NULL);
		}
		/*LINTED*/
		(void) sprintf(h->hl_hosts[0], "[%s]", failsafe_addr);
		DPRINT2(1, "cvthname(%u): Hostname lookup failed "
		    "- using address %s instead\n",
		    mythreadno, h->hl_hosts[0]);
	}

	h->hl_refcnt = 1;
	if (pthread_mutex_init(&h->hl_mutex, NULL) != 0) {
		logerror("pthread_mutex_init failed");
		/* This host_list won't be shared by the cache. */
		return (h);
	}
	hnc_register(nbp, ncp, h, hindex);
	DPRINT3(2, "cvthname(%u): returning %p for %s\n",
	    mythreadno, (void *)h, h->hl_hosts[0]);
	return (h);
}

/*
 * Print syslogd errors some place. Need to be careful here, because
 * this routine is called at times when we're not initialized and
 * ready to log messages...in this case, fall back to using the console.
 */
void
logerror(const char *type, ...)
{
	char buf[MAXLINE+1];
	pthread_t mythreadno;
	int flag;
	va_list ap;

	if (Debug) {
		mythreadno = pthread_self();
	}

	va_start(ap, type);
	logerror_format(type, buf, ap);
	va_end(ap);
	DPRINT2(1, "logerror(%u): %s\n", mythreadno, buf);

	(void) pthread_mutex_lock(&logerror_lock);
	if (!interrorlog) {
		flag = 0;
		if (logerror_to_console(1, buf) == 0) {
			/* has written to the console */
			flag = IGN_CONS;
		}
		(void) logmymsg(LOG_SYSLOG|LOG_ERR, buf, ADDDATE|flag, 1);
	} else {
		if (logmymsg(LOG_SYSLOG|LOG_ERR, buf, ADDDATE, 0) == -1) {
			(void) logerror_to_console(1, buf);
		}
	}
	(void) pthread_mutex_unlock(&logerror_lock);

	errno = 0;
	t_errno = 0;
}

static void
logerror_format(const char *type, char *buf, va_list ap)
{
	char tmpbuf[MAXLINE + 1];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	(void) vsnprintf(tmpbuf, MAXLINE, type, ap);

	if (t_errno == 0 || t_errno == TSYSERR) {
		char *errstr;

		if (errno == 0) {
			(void) snprintf(buf, MAXLINE, "syslogd: %.*s",
			    MAXLINE, tmpbuf);
		} else if ((errstr = strerror(errno)) == (char *)NULL) {
			(void) snprintf(buf, MAXLINE, "syslogd: %s: error"
			    " %d", tmpbuf, errno);
		} else {
			(void) snprintf(buf, MAXLINE, "syslogd: %s: %s",
			    tmpbuf, errstr);
		}
	} else {
		if (t_errno > t_nerr) {
			(void) snprintf(buf, MAXLINE, "syslogd: %s:"
			    " t_error %d", tmpbuf, t_errno);
		} else {
			(void) snprintf(buf, MAXLINE, "syslogd: %s: %s",
			    tmpbuf, t_errlist[t_errno]);
		}
	}

	DPRINT2(5, "logerror_format(%u): out %s\n", mythreadno, buf);
}

static int
logerror_to_console(int nonblock, const char *buf)
{
	int cfd, modes;
	pthread_t mythreadno;
	int ret = 0, len;
	char tmpbuf[MAXLINE + 1];

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT2(1, "logerror_to_console(%u): %s\n", mythreadno, buf);

	/*
	 * must use open here instead of fopen, because
	 * we need the O_NOCTTY behavior - otherwise we
	 * could hang the console at boot time
	 */

	modes = (nonblock) ?
	    O_WRONLY|O_APPEND|O_NOCTTY|O_NONBLOCK :
	    O_WRONLY|O_APPEND|O_NOCTTY;

	if (((cfd = open(sysmsg, modes)) >= 0) ||
	    ((cfd = open(ctty, modes)) >= 0)) {
		(void) snprintf(tmpbuf, MAXLINE, "%s\n", buf);
		len = strlen(tmpbuf);
		if (write(cfd, tmpbuf, len) != len) {
			ret = 1;
		}
		(void) close(cfd);
	} else {
		ret = 1;

		/* punt */
		DPRINT1(1, "logerror_console(%u): can't open console\n",
		    mythreadno);
	}
	return (ret);
}

/*
 * copy current message to saved message in filed structure.
 */
static void
copy_msg(struct filed *f)
{
	(void) strlcpy(f->f_prevmsg.msg, f->f_current.msg, MAXLINE+1);
	(void) strlcpy(f->f_prevmsg.host, f->f_current.host, SYS_NMLN);
	f->f_prevmsg.pri = f->f_current.pri;
	f->f_prevmsg.flags = f->f_current.flags;
	f->f_prevmsg.time = f->f_current.time;
	f->f_msgflag |= OLD_VALID;
}


/*
 * function to free a host_list_t struct that was allocated
 * out of cvthname(). There is a special case where we don't
 * free the hostname list in LocalHostName, because that's
 * our own addresses, and we just want to have to look it
 * up once and save it.  Also don't free it if it's
 * NullHostName, because that's a special one we use if
 * name service lookup fails.
 *
 * By having hostname cache, now host_list_t will be shared
 * by messages and hostname cache. hl_refcnt is used for
 * the purpose.
 */
static void
freehl(host_list_t *h)
{
	int i, refcnt;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT2(2, "freehl(%u): releasing %p\n", mythreadno, (void *)h);

	if (h == NULL || h == &LocalHostName || h == &NullHostName) {
		return;
	}

	(void) pthread_mutex_lock(&h->hl_mutex);
	refcnt = --h->hl_refcnt;
	(void) pthread_mutex_unlock(&h->hl_mutex);

	if (refcnt != 0) {
		DPRINT3(5, "freehl(%u): %p has reference %d\n",
		    mythreadno, (void *)h, refcnt);
		return;
	}

	(void) pthread_mutex_destroy(&h->hl_mutex);

	DPRINT2(5, "freehl(%u): freeing %p\n", mythreadno, (void *)h);

	for (i = 0; i < h->hl_cnt; i++) {
		free(h->hl_hosts[i]);
	}

	free(h->hl_hosts);
	free(h);
}

/*
 * Create the door file and the pid file in /var/run.  If the filesystem
 * containing /etc is writable, create symlinks /etc/.syslog_door and
 * /etc/syslog.pid to them.  On systems that do not support /var/run, create
 * /etc/.syslog_door and /etc/syslog.pid directly.
 *
 * Note: it is not considered fatal to fail to create the pid file or its
 * symlink.  Attempts to use them in the usual way will fail, of course, but
 * syslogd will function nicely without it (not so for the door file).
 */

static void
open_door(void)
{
	struct stat buf;
	door_info_t info;
	char line[MAXLINE+1];
	pthread_t mythreadno;
	int err;

	if (Debug) {
		mythreadno = pthread_self();
	}

	/*
	 * first see if another syslogd is running by trying
	 * a door call - if it succeeds, there is already
	 * a syslogd process active
	 */

	if (!DoorCreated) {
		int door;

		if ((door = open(DoorFileName, O_RDONLY)) >= 0) {
			DPRINT2(5, "open_door(%u): %s opened "
			    "successfully\n", mythreadno, DoorFileName);

			if (door_info(door, &info) >= 0) {
				DPRINT2(5, "open_door(%u): "
				    "door_info:info.di_target = %ld\n",
				    mythreadno, info.di_target);

				if (info.di_target > 0) {
					(void) sprintf(line, "syslogd pid %ld"
					    " already running. Cannot "
					    "start another syslogd pid %ld",
					    info.di_target, getpid());
					DPRINT2(5, "open_door(%u): error: "
					    "%s\n", mythreadno, line);
					errno = 0;
					logerror(line);
					exit(1);
				}
			}

			(void) close(door);
		} else {
			if (lstat(DoorFileName, &buf) < 0) {
				err = errno;

				DPRINT3(5, "open_door(%u): lstat() of %s "
				    "failed, errno=%d\n",
				    mythreadno, DoorFileName, err);

				if ((door = creat(DoorFileName, 0644)) < 0) {
					err = errno;
					(void) snprintf(line, sizeof (line),
					    "creat() of %s failed - fatal",
					    DoorFileName);
					DPRINT3(1, "open_door(%u): error: %s, "
					    "errno=%d\n", mythreadno, line,
					    err);
					errno = err;
					logerror(line);
					delete_doorfiles();
					exit(1);
				}

				(void) fchmod(door,
				    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

				DPRINT2(5, "open_door(%u): creat() of %s "
				    "succeeded\n", mythreadno,
				    DoorFileName);

				(void) close(door);
			}
		}

		if (strcmp(DoorFileName, DOORFILE) == 0) {
			if (lstat(OLD_DOORFILE, &buf) == 0) {
				DPRINT2(5, "open_door(%u): lstat() of %s "
				    "succeeded\n", mythreadno,
				    OLD_DOORFILE);

				if (S_ISDIR(buf.st_mode)) {
					(void) snprintf(line, sizeof (line),
					    "%s is a directory - fatal",
					    OLD_DOORFILE);
					DPRINT2(1, "open_door(%u): error: "
					    "%s\n", mythreadno, line);
					errno = 0;
					logerror(line);
					delete_doorfiles();
					exit(1);
				}

				DPRINT2(5, "open_door(%u): %s is not a "
				    "directory\n",
				    mythreadno, OLD_DOORFILE);

				if (unlink(OLD_DOORFILE) < 0) {
					err = errno;
					(void) snprintf(line, sizeof (line),
					    "unlink() of %s failed",
					    OLD_DOORFILE);
					DPRINT2(5, "open_door(%u): %s\n",
					    mythreadno, line);

					if (err != EROFS) {
						DPRINT3(1, "open_door(%u): "
						    "error: %s, "
						    "errno=%d\n",
						    mythreadno, line, err);
						(void) strcat(line, " - fatal");
						errno = err;
						logerror(line);
						delete_doorfiles();
						exit(1);
					}

					DPRINT1(5, "open_door(%u): unlink "
					    "failure OK on RO file "
					    "system\n", mythreadno);
				}
			} else {
				DPRINT2(5, "open_door(%u): file %s doesn't "
				    "exist\n", mythreadno, OLD_DOORFILE);
			}

			if (symlink(RELATIVE_DOORFILE, OLD_DOORFILE) < 0) {
				err = errno;
				(void) snprintf(line, sizeof (line),
				    "symlink %s -> %s failed", OLD_DOORFILE,
				    RELATIVE_DOORFILE);
				DPRINT2(5, "open_door(%u): %s\n", mythreadno,
				    line);

				if (err != EROFS) {
					DPRINT3(1, "open_door(%u): error: %s, "
					    "errno=%d\n", mythreadno, line,
					    err);
					errno = err;
					(void) strcat(line, " - fatal");
					logerror(line);
					delete_doorfiles();
					exit(1);
				}

				DPRINT1(5, "open_door(%u): symlink failure OK "
				    "on RO file system\n", mythreadno);
			} else {
				DPRINT3(5, "open_door(%u): symlink %s -> %s "
				    "succeeded\n", mythreadno,
				    OLD_DOORFILE, RELATIVE_DOORFILE);
			}
		}

		if ((DoorFd = door_create(server, 0,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
			err = errno;
			(void) sprintf(line, "door_create() failed - fatal");
			DPRINT3(1, "open_door(%u): error: %s, errno=%d\n",
			    mythreadno, line, err);
			errno = err;
			logerror(line);
			delete_doorfiles();
			exit(1);
		}
		(void) door_setparam(DoorFd, DOOR_PARAM_DATA_MAX, 0);
		DPRINT2(5, "open_door(%u): door_create() succeeded, "
		    "DoorFd=%d\n", mythreadno, DoorFd);

		DoorCreated = 1;
	}

	(void) fdetach(DoorFileName);	/* just in case... */

	(void) door_server_create(door_server_pool);

	if (fattach(DoorFd, DoorFileName) < 0) {
		err = errno;
		(void) snprintf(line, sizeof (line), "fattach() of fd"
		    " %d to %s failed - fatal", DoorFd, DoorFileName);
		DPRINT3(1, "open_door(%u): error: %s, errno=%d\n", mythreadno,
		    line, err);
		errno = err;
		logerror(line);
		delete_doorfiles();
		exit(1);
	}

	DPRINT2(5, "open_door(%u): attached server() to %s\n", mythreadno,
	    DoorFileName);

	/*
	 * create pidfile anyway, so those using it to control
	 * syslogd (with kill `cat /etc/syslog.pid` perhaps)
	 * don't get broken.
	 */

	if (!PidfileCreated) {
		int pidfd;

		PidfileCreated = 1;

		if ((pidfd = open(PidFileName, O_RDWR|O_CREAT|O_TRUNC, 0644))
		    < 0) {
			err = errno;
			(void) snprintf(line, sizeof (line),
			    "open() of %s failed", PidFileName);
			DPRINT3(1, "open_door(%u): warning: %s, errno=%d\n",
			    mythreadno, line, err);
			errno = err;
			logerror(line);
			return;
		}

		(void) fchmod(pidfd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		(void) sprintf(line, "%ld\n", getpid());

		if (write(pidfd, line, strlen(line)) < 0) {
			err = errno;
			(void) snprintf(line, sizeof (line),
			    "write to %s on fd %d failed", PidFileName, pidfd);
			DPRINT3(1, "open_door(%u): warning: %s, errno=%d\n",
			    mythreadno, line, err);
			errno = err;
			logerror(line);
			return;
		}

		(void) close(pidfd);

		DPRINT2(5, "open_door(%u): %s created\n",
		    mythreadno, PidFileName);

		if (strcmp(PidFileName, PIDFILE) == 0) {
			if (lstat(OLD_PIDFILE, &buf) == 0) {
				DPRINT2(5, "open_door(%u): lstat() of %s "
				    "succeded\n", mythreadno, OLD_PIDFILE);

				if (S_ISDIR(buf.st_mode)) {
					(void) snprintf(line, sizeof (line),
					    "file %s is a directory",
					    OLD_PIDFILE);
					DPRINT2(1, "open_door(%u): warning: "
					    "%s\n", mythreadno, line);
					errno = 0;
					logerror(line);
					return;
				}

				if (unlink(OLD_PIDFILE) < 0) {
					err = errno;
					(void) snprintf(line, sizeof (line),
					    "unlink() of %s failed",
					    OLD_PIDFILE);
					DPRINT2(5, "open_door(%u): %s\n",
					    mythreadno, line);

					if (err != EROFS) {
						DPRINT3(1, "open_door (%u): "
						    "warning: %s, "
						    "errno=%d\n",
						    mythreadno, line, err);
						errno = err;
						logerror(line);
						return;
					}

					DPRINT1(5, "open_door(%u): unlink "
					    "failure OK on RO file "
					    "system\n", mythreadno);
				}
			} else {
				DPRINT2(5, "open_door(%u): file %s doesn't "
				    "exist\n", mythreadno, OLD_PIDFILE);
			}

			if (symlink(RELATIVE_PIDFILE, OLD_PIDFILE) < 0) {
				err = errno;
				(void) snprintf(line, sizeof (line),
				    "symlink %s -> %s failed", OLD_PIDFILE,
				    RELATIVE_PIDFILE);
				DPRINT2(5, "open_door(%u): %s\n", mythreadno,
				    line);

				if (err != EROFS) {
					DPRINT3(1, "open_door(%u): warning: "
					    "%s, errno=%d\n", mythreadno,
					    line, err);
					errno = err;
					logerror(line);
					return;
				}

				DPRINT1(5, "open_door(%u): symlink failure OK "
				    "on RO file system\n", mythreadno);
				return;
			}

			DPRINT3(5, "open_door(%u): symlink %s -> %s "
			    "succeeded\n", mythreadno, OLD_PIDFILE,
			    RELATIVE_PIDFILE);
		}
	}
}

/*
 * the 'server' function that we export via the door. It does
 * nothing but return.
 */
/*ARGSUSED*/
static void
server(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n)
{
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */
}

/*ARGSUSED*/
static void *
create_door_thr(void *arg)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);

	/*
	 * If there is an error in door_return(), it will return here and
	 * the thread will exit. Hence we need to decrement door_server_cnt.
	 */
	(void) pthread_mutex_lock(&door_server_cnt_lock);
	door_server_cnt--;
	(void) pthread_mutex_unlock(&door_server_cnt_lock);
	return (NULL);
}

/*
 * Max number of door server threads for syslogd. Since door is used
 * to check the health of syslogd, we don't need large number of
 * server threads.
 */
#define	MAX_DOOR_SERVER_THR	3

/*
 * Manage door server thread pool.
 */
/*ARGSUSED*/
static void
door_server_pool(door_info_t *dip)
{
	(void) pthread_mutex_lock(&door_server_cnt_lock);
	if (door_server_cnt <= MAX_DOOR_SERVER_THR &&
	    pthread_create(NULL, &door_thr_attr, create_door_thr, NULL) == 0) {
		door_server_cnt++;
		(void) pthread_mutex_unlock(&door_server_cnt_lock);
		return;
	}

	(void) pthread_mutex_unlock(&door_server_cnt_lock);
}

/*
 * checkm4 - used to verify that the external utilities that
 * syslogd depends on are where we expect them to be.
 * Returns 0 if all utilities are found, > 0 if any are missing.
 * Also logs errors so user knows what's missing
 */
static int
checkm4(void)
{
	int notfound = 0;
	int saverrno;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (access("/usr/ccs/bin/m4", X_OK) < 0) {
		saverrno = errno;
		logerror("/usr/ccs/bin/m4");
		DPRINT2(1, "checkm4(%u): /usr/ccs/bin/m4 - access "
		    "returned %d\n", mythreadno, saverrno);
		notfound++;
	}

	return (notfound);
}

/*
 *  INIT -- Initialize syslogd from configuration table, start up
 *  input and logger threads. This routine is called only once.
 */
static void
init(void)
{
	struct utsname *up;
	pthread_attr_t sys_attr, net_attr, log_attr, hnl_attr;
	int nthread;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(2, "init(%u): initializing\n", mythreadno);

	/* hand-craft a host_list_t entry for our local host name */
	if ((up = malloc(sizeof (struct utsname))) == NULL) {
		MALLOC_FAIL_EXIT;
	}
	(void) uname(up);
	LocalHostName.hl_cnt = 1;
	if ((LocalHostName.hl_hosts = malloc(sizeof (char *))) == NULL) {
		MALLOC_FAIL_EXIT;
	}
	if ((LocalHostName.hl_hosts[0] = strdup(up->nodename)) == NULL) {
		free(LocalHostName.hl_hosts);
		MALLOC_FAIL_EXIT;
	}
	free(up);
	/* also hand craft one for use if name resolution fails */
	NullHostName.hl_cnt = 1;
	if ((NullHostName.hl_hosts = malloc(sizeof (char *))) == NULL) {
		MALLOC_FAIL_EXIT;
	}
	if ((NullHostName.hl_hosts[0] = strdup("name lookup failed")) == NULL) {
		MALLOC_FAIL_EXIT;
	}

	hnc_init(0);

	/*
	 * Note that getnets will allocate network resources, but won't be
	 * binding UDP port. This is because, there could be a race
	 * condition between door. If we bind here, one syslogd could grab
	 * UDP port first, but later another syslogd could take over without
	 * getting UDP port but grab the door file. The 2nd syslogd could
	 * continue to run without listening network.
	 * bindnet() will be called after door was successfully opened.
	 */
	getnets();

	/*
	 * Start up configured theads
	 */
	conf_init();

	/*
	 * allocate thread stacks for the persistant threads
	 */
	nthread = (turnoff == 0) ? 4 : 2;

	if ((stack_ptr = alloc_stacks(nthread)) == NULL) {
		logerror("alloc_stacks failed - fatal");
		exit(1);
	}

	if (Debug) {
		dumpstats(STDOUT_FILENO);
	}

	(void) dataq_init(&inputq);	/* init the input queue */

	if (pthread_attr_init(&sys_attr) != 0 ||
	    pthread_attr_init(&log_attr) != 0 ||
	    pthread_attr_init(&net_attr) != 0 ||
	    pthread_attr_init(&hnl_attr) != 0 ||
	    pthread_attr_init(&door_thr_attr) != 0) {
		logerror("pthread_attr_init failed - fatal");
		exit(1);
	}

	(void) pthread_attr_setscope(&sys_attr, PTHREAD_SCOPE_PROCESS);
	(void) pthread_attr_setscope(&log_attr, PTHREAD_SCOPE_PROCESS);
	(void) pthread_attr_setscope(&net_attr, PTHREAD_SCOPE_PROCESS);
	(void) pthread_attr_setscope(&hnl_attr, PTHREAD_SCOPE_PROCESS);
	(void) pthread_attr_setscope(&door_thr_attr, PTHREAD_SCOPE_SYSTEM);
	(void) pthread_attr_setdetachstate(&door_thr_attr,
	    PTHREAD_CREATE_DETACHED);

	/* 1: logmsg thread */
	(void) pthread_attr_setstacksize(&log_attr, stacksize);
	(void) pthread_attr_setstackaddr(&log_attr, stack_ptr);
	stack_ptr += stacksize + redzonesize;
	if (pthread_create(&log_thread, &log_attr, logmsg, NULL) != 0) {
		logerror("pthread_create failed - fatal");
		exit(1);
	}

	/*
	 * open the log device, and pull up all pending message
	 * from the log driver.
	 */
	prepare_sys_poll();

	/*
	 * Now we can deliver the pending internal error messages.
	 */
	enable_errorlog();

	/* 2: sys_poll thread */
	(void) pthread_attr_setstacksize(&sys_attr, stacksize);
	(void) pthread_attr_setstackaddr(&sys_attr, stack_ptr);
	stack_ptr += stacksize + redzonesize;
	if (pthread_create(&sys_thread, &sys_attr, sys_poll, NULL) != 0) {
		logerror("pthread_create failed - fatal");
		exit(1);
	}

	/*
	 * We've started the sys_poll() and logmsg() threads.  Now we are ready
	 * to open the door.  This cannot happen before spawning sys_poll(),
	 * because after opening the door, syslog() will no longer take care of
	 * LOG_CONS.  Therefor, we should pull up all pending log messages and
	 * activate sys_poll() before opening the door, so that log driver
	 * won't drop messages.
	 */
	open_door();

	DPRINT1(1, "init(%u): accepting messages from local system\n",
	    mythreadno);

	if (turnoff == 0) {
		/* init the hostname lookup queue */
		(void) dataq_init(&hnlq);

		/* 3: hostname lookup thread */
		(void) pthread_attr_setstacksize(&hnl_attr, stacksize);
		(void) pthread_attr_setstackaddr(&hnl_attr, stack_ptr);
		stack_ptr += stacksize + redzonesize;
		if (pthread_create(&hnl_thread, &hnl_attr,
		    hostname_lookup, NULL) != 0) {
			logerror("pthread_create failed - fatal");
			exit(1);
		}

		/* 4: net_poll thread */
		(void) pthread_attr_setstacksize(&net_attr, stacksize);
		(void) pthread_attr_setstackaddr(&net_attr, stack_ptr);
		stack_ptr += stacksize + redzonesize;

		/* grab UDP port */
		bindnet();

		if (pthread_create(&net_thread, &net_attr, net_poll,
		    NULL) != 0) {
			logerror("pthread_create failed - fatal");
			exit(1);
		}
		DPRINT1(1, "init(%u): accepting messages from remote\n",
		    mythreadno);
	}

	(void) pthread_attr_destroy(&sys_attr);
	(void) pthread_attr_destroy(&net_attr);
	(void) pthread_attr_destroy(&log_attr);
	(void) pthread_attr_destroy(&hnl_attr);

	curalarm = MarkInterval * 60 / MARKCOUNT;
	(void) alarm((unsigned)curalarm);
	DPRINT2(2, "init(%u): Next alarm in %d seconds\n",
	    mythreadno, curalarm);
	DPRINT1(1, "init(%u): syslogd: started\n", mythreadno);
}

/*
 * will print a bunch of debugging stats on 'fd'
 */
static void
dumpstats(int fd)
{
	FILE *out;
	struct filed *f;
	int i;
	char users[1024];
	char cbuf[30];
	char *dashes = "------------------------";
	static int conversion_printed;

	if ((out = fdopen(fd, "w+")) == NULL)
		return;

	(void) fprintf(out, "\nSyslogd started: %s",
	    ctime_r(&start_time, cbuf));
	(void) fprintf(out, "Input message count: system %d, network %d\n",
	    sys_msg_count, net_msg_count);
	(void) fprintf(out, "# Outputs: %d\n\n", nlogs);

	(void) fprintf(out, "%s priority = [file, facility] %s\n\n",
	    dashes, dashes);

	for (i = 0; i < LOG_NFACILITIES + 1; i++) {
		(void) fprintf(out, "%d ", i / 10);
	}
	(void) fprintf(out, "\n");
	for (i = 0; i < LOG_NFACILITIES + 1; i++) {
		(void) fprintf(out, "%d ", i % 10);
	}
	(void) fprintf(out, "\n");
	for (i = 0; i < LOG_NFACILITIES + 1; i++) {
		(void) fprintf(out, "--");
	}
	(void) fprintf(out, "\n");

	for (f = Files; f < &Files[nlogs]; f++) {
		for (i = 0; i < LOG_NFACILITIES + 1; i++) {
			if (f->f_pmask[i] == NOPRI)
				(void) fprintf(out, "X ");
			else
				(void) fprintf(out, "%d ",
				    f->f_pmask[i]);
		}
		(void) fprintf(out, "%s: ", TypeNames[f->f_type]);
		switch (f->f_type) {
		case F_FILE:
		case F_TTY:
		case F_CONSOLE:
			(void) fprintf(out, "%s", f->f_un.f_fname);
			break;
		case F_FORW:
			(void) fprintf(out, "%s", f->f_un.f_forw.f_hname);
			break;
		case F_USERS:
			for (i = 0; i < MAXUNAMES &&
			    *f->f_un.f_uname[i]; i++) {
				if (!i)
					(void) fprintf(out, "%s",
					    f->f_un.f_uname[i]);
				else
					(void) fprintf(out, ", %s",
					    f->f_un.f_uname[i]);
			}
			break;
		}
		(void) fprintf(out, "\n");
	}

	if (!conversion_printed) {
		(void) fprintf(out, "\nFacilities:\n");

		for (i = 0; FacNames[i].c_val != -1; i++) {
			(void) fprintf(out, "  [%02d] %s: %3d\n", i,
			    FacNames[i].c_name, FacNames[i].c_val);
		}

		(void) fprintf(out, "\nPriorities:\n");

		for (i = 0; PriNames[i].c_val != -1; i++) {
			(void) fprintf(out, "  [%02d] %s: %3d\n", i,
			    PriNames[i].c_name, PriNames[i].c_val);
		}

		conversion_printed = 1;
	}

	(void) fprintf(out, "\n\n\n\t\tPer File Statistics\n");
	(void) fprintf(out, "%-24s\tTot\tDups\tNofwd\tErrs\n", "File");
	(void) fprintf(out, "%-24s\t---\t----\t-----\t----\n", "----");
	for (f = Files; f < &Files[nlogs]; f++) {
		switch (f->f_type) {
		case F_FILE:
		case F_TTY:
		case F_CONSOLE:
			(void) fprintf(out, "%-24s", f->f_un.f_fname);
			break;
		case F_WALL:
			(void) fprintf(out, "%-24s", TypeNames[f->f_type]);
			break;
		case F_FORW:
			(void) fprintf(out, "%-24s", f->f_un.f_forw.f_hname);
			break;
		case F_USERS:
			for (i = 0; i < MAXUNAMES &&
			    *f->f_un.f_uname[i]; i++) {
				if (!i)
					(void) strcpy(users,
					    f->f_un.f_uname[i]);
				else {
					(void) strcat(users, ",");
					(void) strcat(users,
					    f->f_un.f_uname[i]);
				}
			}
			(void) fprintf(out, "%-24s", users);
			break;
		}
		(void) fprintf(out, "\t%d\t%d\t%d\t%d\n",
		    f->f_stat.total, f->f_stat.dups,
		    f->f_stat.cantfwd, f->f_stat.errs);
	}
	(void) fprintf(out, "\n\n");
	if (Debug && fd == 1)
		return;
	(void) fclose(out);
}

/*
 * conf_init - This routine is code seperated from the
 * init routine in order to be re-callable when we get
 * a SIGHUP signal.
 */
static void
conf_init(void)
{
	char *p;
	int i;
	struct filed *f;
	char *m4argv[4];
	int m4argc = 0;
	conf_t cf;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(2, "conf_init(%u): starting logger threads\n",
	    mythreadno);

	m4argv[m4argc++] = "m4";

	if (amiloghost() == 1) {
		DPRINT1(1, "conf_init(%u): I am loghost\n", mythreadno);
		m4argv[m4argc++] = "-DLOGHOST=1";
	}

	m4argv[m4argc++] = ConfFile;
	m4argv[m4argc] = NULL;

	/*
	 * Make sure the configuration file and m4 exist, and then parse
	 * the configuration file with m4.  If any of these fail, resort
	 * to our hardcoded fallback configuration.
	 */

	if (access(ConfFile, R_OK) == -1) {
		DPRINT2(1, "conf_init(%u): %s does not exist\n", mythreadno,
		    ConfFile);
		logerror("can't open configuration file");
		/* CSTYLED */
		Files = (struct filed *) &fallback; /*lint !e545 */
		cfline("*.ERR\t/dev/sysmsg", 0, &Files[0]);
		cfline("*.PANIC\t*", 0, &Files[1]);
		nlogs = 2;
		goto nofile;
	}

	if (checkm4() != 0 || conf_open(&cf, "/usr/ccs/bin/m4", m4argv) == -1) {
		DPRINT2(1, "conf_init(%u): cannot open %s\n", mythreadno,
		    ConfFile);
		/* CSTYLED */
		Files = (struct filed *) &fallback; /*lint !e545 */
		cfline("*.ERR\t/dev/sysmsg", 0, &Files[0]);
		cfline("*.PANIC\t*", 0, &Files[1]);
		nlogs = 2;
		goto nofile;
	}

	/* Count the number of lines which are not blanks or comments */
	nlogs = 0;
	while ((p = conf_read(&cf)) != NULL) {
		if (p[0] != '\0' && p[0] != '#')
			nlogs++;
	}

	Files = (struct filed *)malloc(sizeof (struct filed) * nlogs);

	if (!Files) {
		DPRINT1(1, "conf_init(%u): malloc failed - can't "
		    "allocate 'Files' array\n", mythreadno);
		MALLOC_FAIL("loading minimum configuration");
		/* CSTYLED */
		Files = (struct filed *) &fallback; /*lint !e545 */
		cfline("*.ERR\t/dev/sysmsg", 0, &Files[0]);
		cfline("*.PANIC\t*", 0, &Files[1]);
		nlogs = 2;
		conf_close(&cf);
		goto nofile;
	}

	/*
	 *  Foreach line in the conf table, open that file.
	 */
	conf_rewind(&cf);
	f = Files;
	i = 0;
	while (((p = conf_read(&cf)) != NULL) && (f < &Files[nlogs])) {
		i++;
		/* check for end-of-section */
		if (p[0] == '\0' || p[0] == '#')
			continue;

		cfline(p, i, f);
		if (f->f_type == F_UNUSED)
			nlogs--;
		else
			f++;
	}

	conf_close(&cf);

	/*
	 * See if marks are to be written to any files.  If so, set up a
	 * timeout for marks.
	 */
nofile:
	Marking = 0;

	/*
	 * allocate thread stacks - one for each logger thread.
	 */
	if ((cstack_ptr = alloc_stacks(nlogs)) == NULL) {
		logerror("alloc_stacks failed - fatal");
		exit(1);
	}

	/* And now one thread for each configured file */
	for (f = Files; f < &Files[nlogs]; f++) {
		if (filed_init(f) != 0) {
			logerror("pthread_create failed - fatal");
			exit(1);
		}

		(void) pthread_mutex_lock(&cft);
		++conf_threads;
		(void) pthread_mutex_unlock(&cft);

		if (f->f_type != F_UNUSED &&
		    f->f_pmask[LOG_NFACILITIES] != NOPRI)
			Marking = 1;
	}
}

/*
 * filed init - initialize fields in a file descriptor struct
 * this is called before multiple threads are running, so no mutex
 * needs to be held at this time.
 */
static int
filed_init(struct filed *f)
{
	pthread_attr_t stack_attr;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (pthread_mutex_init(&f->filed_mutex, NULL) != 0) {
		logerror("pthread_mutex_init failed");
		return (-1);
	}

	DPRINT2(5, "filed_init(%u): dataq_init for queue %p\n",
	    mythreadno, (void *)&f->f_queue);
	(void) dataq_init(&f->f_queue);

	if (pthread_attr_init(&stack_attr) != 0) {
		logerror("pthread_attr_init failed");
		return (-1);
	}

	(void) pthread_attr_setstacksize(&stack_attr, stacksize);
	(void) pthread_attr_setstackaddr(&stack_attr, cstack_ptr);
	cstack_ptr += stacksize + redzonesize;

	f->f_msgflag = 0;
	f->f_prevmsg.msg[0] = '\0';
	f->f_prevmsg.flags = 0;
	f->f_prevmsg.pri = 0;
	f->f_prevmsg.host[0] = '\0';

	f->f_current.msg[0] = '\0';
	f->f_current.flags = 0;
	f->f_current.pri = 0;
	f->f_current.host[0] = '\0';

	f->f_prevcount = 0;

	f->f_stat.flag = 0;
	f->f_stat.total = 0;
	f->f_stat.dups = 0;
	f->f_stat.cantfwd = 0;
	f->f_stat.errs = 0;

	if (pthread_create(&f->f_thread, NULL, logit, (void *)f) != 0) {
		logerror("pthread_create failed");
		(void) pthread_attr_destroy(&stack_attr);
		return (-1);
	}

	(void) pthread_attr_destroy(&stack_attr);
	return (0);
}


/*
 * Crack a configuration file line
 */
static void
cfline(char *line, int lineno, struct filed *f)
{
	char *p;
	char *q;
	int i;
	char *bp;
	int pri;
	char buf[MAXLINE];
	char ebuf[SYS_NMLN+1+40];
	mode_t fmode, omode = O_WRONLY|O_APPEND|O_NOCTTY;
	struct stat64 sbuf;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT2(1, "cfline(%u): (%s)\n", mythreadno, line);

	errno = 0;	/* keep errno related stuff out of logerror messages */

	/* clear out file entry */
	bzero((char *)f, sizeof (*f));
	for (i = 0; i <= LOG_NFACILITIES; i++)
		f->f_pmask[i] = NOPRI;

	/* scan through the list of selectors */
	for (p = line; *p && *p != '\t'; ) {

		/* find the end of this facility name list */
		for (q = p; *q && *q != '\t' && *q++ != '.'; )
			continue;

		/* collect priority name */
		for (bp = buf; *q && !strchr("\t,;", *q); )
			*bp++ = *q++;
		*bp = '\0';

		/* skip cruft */
		while (strchr(", ;", *q))
			q++;

		/* decode priority name */
		pri = decode(buf, PriNames);
		if (pri < 0) {
			logerror("line %d: unknown priority name \"%s\"",
			    lineno, buf);
			return;
		}

		/* scan facilities */
		while (*p && !strchr("\t.;", *p)) {
			for (bp = buf; *p && !strchr("\t,;.", *p); )
				*bp++ = *p++;
			*bp = '\0';
			if (*buf == '*')
				for (i = 0; i < LOG_NFACILITIES; i++)
					f->f_pmask[i] = (uchar_t)pri;
			else {
				i = decode(buf, FacNames);
				if (i < 0) {
					logerror("line %d: unknown facility"
					    " name \"%s\"", lineno, buf);
					return;
				}
				f->f_pmask[i >> 3] = (uchar_t)pri;
			}
			while (*p == ',' || *p == ' ')
				p++;
		}

		p = q;
	}

	/* skip to action part */
	while (*p == '\t' || *p == ' ')
		p++;

	switch (*p) {
	case '\0':
		errno = 0;
		logerror("line %d: no action part", lineno);
		break;

	case '@':
		(void) strlcpy(f->f_un.f_forw.f_hname, ++p, SYS_NMLN);
		if (logforward(f, ebuf, sizeof (ebuf)) != 0) {
			logerror("line %d: %s", lineno, ebuf);
			break;
		}
		f->f_type = F_FORW;
		break;

	case '/':
		(void) strlcpy(f->f_un.f_fname, p, MAXPATHLEN);
		if (stat64(p, &sbuf) < 0) {
			logerror(p);
			break;
		}
		/*
		 * don't block trying to open a pipe
		 * with no reader on the other end
		 */
		fmode = 0; 	/* reset each pass */
		if (S_ISFIFO(sbuf.st_mode))
			fmode = O_NONBLOCK;

		f->f_file = open64(p, omode|fmode);
		if (f->f_file < 0) {
			if (fmode && errno == ENXIO) {
				errno = 0;
				logerror("%s - no reader", p);
			} else
				logerror(p);
			break;
		}

		/*
		 * Fifos are initially opened NONBLOCK
		 * to insure we don't hang, but once
		 * we are open, we need to change the
		 * behavior back to blocking, otherwise
		 * we may get write errors, and the log
		 * will get closed down the line.
		 */
		if (S_ISFIFO(sbuf.st_mode))
			(void) fcntl(f->f_file, F_SETFL, omode);

		if (isatty(f->f_file)) {
			f->f_type = F_TTY;
			untty();
		} else
			f->f_type = F_FILE;

		if ((strcmp(p, ctty) == 0) || (strcmp(p, sysmsg) == 0))
			f->f_type = F_CONSOLE;
		break;

	case '*':
		f->f_type = F_WALL;
		break;

	default:
		for (i = 0; i < MAXUNAMES && *p; i++) {
			for (q = p; *q && *q != ','; )
				q++;
			(void) strlcpy(f->f_un.f_uname[i], p, UNAMESZ);
			if ((q - p) > UNAMESZ)
				f->f_un.f_uname[i][UNAMESZ] = '\0';
			else
				f->f_un.f_uname[i][q - p] = '\0';
			while (*q == ',' || *q == ' ')
				q++;
			p = q;
		}
		f->f_type = F_USERS;
		break;
	}
	f->f_orig_type = f->f_type;
}


/*
 *  Decode a symbolic name to a numeric value
 */
static int
decode(char *name, struct code *codetab)
{
	struct code *c;
	char *p;
	char buf[40];

	if (isdigit(*name))
		return (atoi(name));

	(void) strncpy(buf, name, sizeof (buf) - 1);
	for (p = buf; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);
	for (c = codetab; c->c_name; c++)
		if (!(strcmp(buf, c->c_name)))
			return (c->c_val);

	return (-1);
}

static int
ismyaddr(struct netbuf *nbp)
{
	int i;

	if (nbp == NULL)
		return (0);

	for (i = 1; i < Ninputs; i++) {
		if (same_addr(nbp, Myaddrs[i]))
			return (1);
	}
	return (0);
}

static void
getnets(void)
{
	struct nd_hostserv hs;
	struct netconfig *ncp;
	struct nd_addrlist *nap;
	struct netbuf *nbp;
	int i, inputs;
	void *handle;
	char *uap;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (turnoff) {
		DPRINT1(1, "getnets(%u): network is being turned off\n",
		    mythreadno);
		return;
	}

	hs.h_host = HOST_SELF;
	hs.h_serv = "syslog";

	if ((handle = setnetconfig()) == NULL) {
		return;
	}

	while ((ncp = getnetconfig(handle)) != NULL) {
		if (ncp->nc_semantics != NC_TPI_CLTS) {
			continue;
		}

		if (netdir_getbyname(ncp, &hs, &nap) != 0) {
			continue;
		}

		if (nap == NULL || nap->n_cnt <= 0) {
			DPRINT1(1, "getnets(%u): found no address\n",
			    mythreadno);
			netdir_free((void *)nap, ND_ADDRLIST);
			continue;
		}

		if (Debug) {
			DPRINT2(1, "getnets(%u): found %d addresses",
			    mythreadno, nap->n_cnt);
			DPRINT0(1, ", they are: ");
			nbp = nap->n_addrs;

			for (i = 0; i < nap->n_cnt; i++) {
				if ((uap = taddr2uaddr(ncp, nbp)) != NULL) {
					DPRINT1(1, "%s ", uap);
					free(uap);
				}
				nbp++;
			}

			DPRINT0(1, "\n");
		}

		inputs = Ninputs + nap->n_cnt;

		Nfd = realloc(Nfd, inputs * sizeof (struct pollfd));
		Ncf = realloc(Ncf, inputs * sizeof (struct netconfig));
		Myaddrs = realloc(Myaddrs, inputs * sizeof (struct netbuf *));
		Udp = realloc(Udp, inputs * sizeof (struct t_unitdata *));
		Errp = realloc(Errp, inputs * sizeof (struct t_uderr *));

		/*
		 * all malloc failures here are fatal
		 */
		if (Nfd == NULL || Ncf == NULL || Myaddrs == NULL ||
		    Udp == NULL || Errp == NULL) {
			MALLOC_FAIL_EXIT;
		}

		nbp = nap->n_addrs;

		for (i = 0; i < nap->n_cnt; i++, nbp++) {
			char ebuf[128];

			if (addnet(ncp, nbp) == 0) {
				/* no error */
				continue;
			}

			(void) strcpy(ebuf, "Unable to configure syslog port");

			if ((uap = taddr2uaddr(ncp, nbp)) != NULL) {
				size_t l = strlen(ebuf);
				(void) snprintf(ebuf + l, sizeof (ebuf) - l,
				    " for %s", uap);
			}

			DPRINT2(1, "getnets(%u): %s",
			    mythreadno, ebuf);

			if (uap) {
				free(uap);
			}

			logerror(ebuf);
			/*
			 * Here maybe syslogd can quit. However, syslogd
			 * has been ignoring this error and keep running.
			 * So we won't break it.
			 */
		}

		netdir_free((void *)nap, ND_ADDRLIST);
	}

	(void) endnetconfig(handle);
}

/*
 * Open the network device, and allocate necessary resources.
 * Myaddrs will also be filled, so that we can call ismyaddr() before
 * being bound to the network.
 */
static int
addnet(struct netconfig *ncp, struct netbuf *nbp)
{
	int fd;
	struct netbuf *bp;

	fd = t_open(ncp->nc_device, O_RDWR, NULL);

	if (fd < 0) {
		return (1);
	}

	(void) memcpy(&Ncf[Ninputs], ncp, sizeof (struct netconfig));

	/*LINTED*/
	Udp[Ninputs] = (struct t_unitdata *)t_alloc(fd, T_UNITDATA, T_ADDR);

	if (Udp[Ninputs] == NULL) {
		(void) t_close(fd);
		return (1);
	}

	/*LINTED*/
	Errp[Ninputs] = (struct t_uderr *)t_alloc(fd, T_UDERROR, T_ADDR);

	if (Errp[Ninputs] == NULL) {
		(void) t_close(fd);
		(void) t_free((char *)Udp[Ninputs], T_UNITDATA);
		return (1);
	}

	if ((bp = malloc(sizeof (struct netbuf))) == NULL ||
	    (bp->buf = malloc(nbp->len)) == NULL) {
		MALLOC_FAIL("allocating address buffer");
		(void) t_close(fd);
		(void) t_free((char *)Udp[Ninputs], T_UNITDATA);
		(void) t_free((char *)Errp[Ninputs], T_UDERROR);

		if (bp) {
			free(bp);
		}

		return (1);
	}

	bp->len = nbp->len;
	(void) memcpy(bp->buf, nbp->buf, nbp->len);
	Myaddrs[Ninputs] = bp;

	Nfd[Ninputs].fd = fd;
	Nfd[Ninputs].events = POLLIN;
	Ninputs++;
	return (0);
}

/*
 * Allocate UDP buffer to minimize packet loss.
 */
static void
set_udp_buffer(int fd)
{
	struct t_optmgmt req, resp;
	struct opthdr *opt;
	size_t optsize, bsize = 256 * 1024;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	optsize = sizeof (struct opthdr) + sizeof (int);
	if ((opt = malloc(optsize)) == NULL) {
		MALLOC_FAIL("will have no udp buffer");
		return;
	}
	opt->level = SOL_SOCKET;
	opt->name = SO_RCVBUF;
	opt->len = sizeof (int);
	*(int *)(opt + 1) = bsize;

	req.flags = T_NEGOTIATE;
	req.opt.len = optsize;
	req.opt.buf = (char *)opt;

	resp.flags = 0;
	resp.opt.maxlen = optsize;
	resp.opt.buf = (char *)opt;

	while (t_optmgmt(fd, &req, &resp) == -1 || resp.flags != T_SUCCESS) {
		if (t_errno != TSYSERR || errno != ENOBUFS) {
			bsize = 0;
			break;
		}
		bsize >>= 1;
		if (bsize < 8192) {
			break;
		}
		*(int *)(opt + 1) = bsize;
	}
	if (bsize == 0) {
		logerror("failed to allocate UDP buffer");
	}
	DPRINT3(1, "set_udp_buffer(%u): allocate %d for fd %d\n",
	    mythreadno, bsize, fd);
	free(opt);
}

/*
 * Attach the network, and allocate UDP buffer for the interface.
 */
static void
bindnet(void)
{
	struct t_bind bind, *bound;
	int cnt, i;
	char *uap;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	cnt = 0;

	while (cnt < Ninputs) {
		char ebuf[128];

		/*LINTED*/
		bound  = (struct t_bind *)t_alloc(Nfd[cnt].fd, T_BIND, T_ADDR);
		bind.addr = *Myaddrs[cnt];
		bind.qlen = 0;

		if (t_bind(Nfd[cnt].fd, &bind, bound) == 0) {
			if (same_addr(&bind.addr, &bound->addr)) {
				(void) t_free((char *)bound, T_BIND);
				set_udp_buffer(Nfd[cnt].fd);
				cnt++;
				continue;
			}
		}

		/* failed to bind port */
		(void) t_free((char *)bound, T_BIND);

		(void) strcpy(ebuf, "Unable to bind syslog port");

		uap = taddr2uaddr(&Ncf[cnt], Myaddrs[cnt]);
		if (uap) {
			i = strlen(ebuf);
			(void) snprintf(ebuf + i, sizeof (ebuf) - i,
			    " for %s", uap);
		}

		DPRINT2(1, "bindnet(%u): failed to bind port (%s)\n",
		    mythreadno, uap ? uap : "<unknown>");

		if (uap) {
			free(uap);
		}

		errno = 0;
		logerror(ebuf);

		(void) t_close(Nfd[cnt].fd);
		free(Myaddrs[cnt]->buf);
		free(Myaddrs[cnt]);
		(void) t_free((char *)Udp[cnt], T_UNITDATA);
		(void) t_free((char *)Errp[cnt], T_UDERROR);

		for (i = cnt; i < (Ninputs-1); i++) {
			Nfd[i] = Nfd[i + 1];
			Ncf[i] = Ncf[i + 1];
			Myaddrs[i] = Myaddrs[i + 1];
			Udp[i] = Udp[i + 1];
			Errp[i] = Errp[i + 1];
		}

		Ninputs--;
	}
}

static int
logforward(struct filed *f, char *ebuf, size_t elen)
{
	struct nd_hostserv hs;
	struct netbuf *nbp;
	struct netconfig *ncp;
	struct nd_addrlist *nap;
	void *handle;
	char *hp;

	hp = f->f_un.f_forw.f_hname;
	hs.h_host = hp;
	hs.h_serv = "syslog";

	if ((handle = setnetconfig()) == NULL) {
		(void) strlcpy(ebuf,
		    "unable to rewind the netconfig database", elen);
		errno = 0;
		return (-1);
	}
	nap = (struct nd_addrlist *)NULL;
	while ((ncp = getnetconfig(handle)) != NULL) {
		if (ncp->nc_semantics == NC_TPI_CLTS) {
			if (netdir_getbyname(ncp, &hs, &nap) == 0) {
				if (!nap)
					continue;
				nbp = nap->n_addrs;
				break;
			}
		}
	}
	if (ncp == NULL) {
		(void) endnetconfig(handle);
		(void) snprintf(ebuf, elen,
		    "WARNING: %s could not be resolved", hp);
		errno = 0;
		return (-1);
	}
	if (nap == (struct nd_addrlist *)NULL) {
		(void) endnetconfig(handle);
		(void) snprintf(ebuf, elen, "unknown host %s", hp);
		errno = 0;
		return (-1);
	}
	/* CSTYLED */
	if (ismyaddr(nbp)) { /*lint !e644 */
		netdir_free((void *)nap, ND_ADDRLIST);
		(void) endnetconfig(handle);
		(void) snprintf(ebuf, elen,
		    "host %s is this host - logging loop", hp);
		errno = 0;
		return (-1);
	}
	f->f_un.f_forw.f_addr.buf = malloc(nbp->len);
	if (f->f_un.f_forw.f_addr.buf == NULL) {
		netdir_free((void *)nap, ND_ADDRLIST);
		(void) endnetconfig(handle);
		(void) strlcpy(ebuf, "malloc failed", elen);
		return (-1);
	}
	bcopy(nbp->buf, f->f_un.f_forw.f_addr.buf, nbp->len);
	f->f_un.f_forw.f_addr.len = nbp->len;
	f->f_file = t_open(ncp->nc_device, O_RDWR, NULL);
	if (f->f_file < 0) {
		netdir_free((void *)nap, ND_ADDRLIST);
		(void) endnetconfig(handle);
		free(f->f_un.f_forw.f_addr.buf);
		(void) strlcpy(ebuf, "t_open", elen);
		return (-1);
	}
	netdir_free((void *)nap, ND_ADDRLIST);
	(void) endnetconfig(handle);
	if (t_bind(f->f_file, NULL, NULL) < 0) {
		(void) strlcpy(ebuf, "t_bind", elen);
		free(f->f_un.f_forw.f_addr.buf);
		(void) t_close(f->f_file);
		return (-1);
	}
	return (0);
}

static int
amiloghost(void)
{
	struct nd_hostserv hs;
	struct netconfig *ncp;
	struct nd_addrlist *nap;
	struct netbuf *nbp;
	int i, fd;
	void *handle;
	char *uap;
	struct t_bind bind, *bound;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	/*
	 * we need to know if we are running on the loghost. This is
	 * checked by binding to the address associated with "loghost"
	 * and "syslogd" service over the connectionless transport
	 */
	hs.h_host = "loghost";
	hs.h_serv = "syslog";

	if ((handle = setnetconfig()) == NULL) {
		return (0);
	}

	while ((ncp = getnetconfig(handle)) != NULL) {
		if (ncp->nc_semantics != NC_TPI_CLTS) {
			continue;
		}

		if (netdir_getbyname(ncp, &hs, &nap) != 0) {
			continue;
		}

		if (nap == NULL) {
			continue;
		}

		nbp = nap->n_addrs;

		for (i = 0; i < nap->n_cnt; i++) {
			if ((uap = taddr2uaddr(ncp, nbp)) != (char *)NULL) {
				DPRINT2(1, "amiloghost(%u): testing %s\n",
				    mythreadno, uap);
			}

			free(uap);

			fd = t_open(ncp->nc_device, O_RDWR, NULL);

			if (fd < 0) {
				netdir_free((void *)nap, ND_ADDRLIST);
				(void) endnetconfig(handle);
				return (0);
			}

			/*LINTED*/
			bound = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
			bind.addr = *nbp;
			bind.qlen = 0;

			if (t_bind(fd, &bind, bound) == 0) {
				(void) t_close(fd);
				(void) t_free((char *)bound, T_BIND);
				netdir_free((void *)nap, ND_ADDRLIST);
				(void) endnetconfig(handle);
				return (1);
			} else {
				(void) t_close(fd);
				(void) t_free((char *)bound, T_BIND);
			}

			nbp++;
		}

		netdir_free((void *)nap, ND_ADDRLIST);
	}

	(void) endnetconfig(handle);
	return (0);
}

int
same_addr(struct netbuf *na, struct netbuf *nb)
{
	char *a, *b;
	size_t n;

	assert(na->buf != NULL && nb->buf != NULL);

	if (na->len != nb->len) {
		return (0);
	}

	a = na->buf;
	b = nb->buf;
	n = nb->len;

	while (n-- > 0) {
		if (*a++ != *b++) {
			return (0);
		}
	}

	return (1);
}

/*
 * allocates a new message structure, initializes it
 * and returns a pointer to it
 */
static log_message_t *
new_msg(void)
{
	log_message_t *lm;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if ((lm = malloc(sizeof (log_message_t))) == NULL)
		return ((log_message_t *)NULL);

	if (pthread_mutex_init(&lm->msg_mutex, NULL) != 0)
		return ((log_message_t *)NULL);
	lm->refcnt = 0;
	lm->pri = 0;
	lm->flags = 0;
	lm->hlp = NULL;
	lm->msg[0] = '\0';
	lm->ptr = NULL;

	DPRINT2(3, "new_msg(%u): creating msg %p\n", mythreadno, (void *)lm);
	return (lm);
}

/*
 * frees a message structure - should only be called if
 * the refcount is 0
 */
static void
free_msg(log_message_t *lm)
{
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	assert(lm != NULL && lm->refcnt == 0);
	if (lm->hlp != NULL)
		freehl(lm->hlp);
	DPRINT2(3, "free_msg(%u): freeing msg %p\n", mythreadno, (void *)lm);
	free(lm);
}

/*
 *  Make sure that the message makes sense in the current locale, and
 *  does not contain stray control characters.
 */
static void
filter_string(char *mbstr, char *filtered, size_t max)
{
	size_t	cs = 0;
	size_t	mb_cur_max;
	unsigned char	*p = (unsigned char *)mbstr;
	pthread_t mythreadno = 0;

	if (Debug) {
		mythreadno = pthread_self();
	}

	assert(mbstr != NULL && filtered != NULL);

	/*
	 * Since the access to MB_CUR_MAX is expensive (because
	 * MB_CUR_MAX lives in a global area), it should be
	 * restrained for the better performance.
	 */
	mb_cur_max = (size_t)MB_CUR_MAX;
	if (mb_cur_max > 1) {
		/* multibyte locale */
		int	mlen;
		wchar_t	wc;

		while (*p != '\0') {
			if ((mlen = mbtowc(&wc, (char *)p,
			    mb_cur_max)) == -1) {
				/*
				 * Invalid byte sequence found.
				 *
				 * try to print one byte
				 * in ASCII format.
				 */
				DPRINT2(9, "filter_string(%u): Invalid "
				    "MB sequence: %ld\n", mythreadno,
				    wc);

				if (!putctrlc(*p++, &filtered, &cs, max)) {
					/* not enough buffer */
					goto end;
				} else {
					continue;
				}
			} else {
				/*
				 * Since *p is not a null byte here,
				 * mbtowc should have never returned 0.
				 *
				 * A valid wide character found.
				 */

				if (wc != L'\t' && iswcntrl(wc)) {
					/*
					 * non-tab, non-newline, and
					 * control character found.
					 *
					 * try to print this wide character
					 * in ASCII-format.
					 */
					char	*q = filtered;

					DPRINT2(9, "filter_string(%u): MB"
					    " control character: %ld\n",
					    mythreadno, wc);

					while (mlen--) {
						if (!putctrlc(*p++, &filtered,
						    &cs, max)) {
							/*
							 * not enough buffer in
							 * filtered
							 *
							 * cancel already
							 * stored bytes in
							 * filtered for this
							 * wide character.
							 */
							filtered = q;
							goto end;
						}
					}
					continue;
				} else {
					/*
					 * tab, newline, or non-control
					 * character found.
					 */
					if (cs + mlen < max) {
						/* enough buffer */
						cs += mlen;
						while (mlen--) {
							*filtered++ = *p++;
						}
						continue;
					} else {
						/* not enough buffer */
						goto end;
					}
				}
			}
		}
	} else {
		/* singlebyte locale */

		while (*p != '\0') {
			if (*p != '\t' && iscntrl(*p)) {
				/*
				 * non-tab, non-newline,
				 * and control character found.
				 *
				 * try to print this singlebyte character
				 * in ASCII format.
				 */
				DPRINT2(9, "filter_string(%u): control "
				    "character: %d\n", mythreadno, *p);

				if (!putctrlc(*p++, &filtered, &cs, max)) {
					/* not enough buffer */
					goto end;
				} else {
					continue;
				}
			} else if (*p != '\t' && !isprint(*p)) {
				/*
				 * non-tab and non printable character found
				 * this check is required for the C locale
				 */
				DPRINT2(9, "filter_string(%u): non-printable "
				    "character: %d\n", mythreadno, *p);
				if (!putctrlc(*p++, &filtered, &cs, max)) {
					/* not enough buffer */
					goto end;
				} else {
					continue;
				}
			} else {
				/*
				 * tab, newline, non-control character, or
				 * printable found.
				 */
				if (cs + 1 < max) {
					*filtered++ = *p++;
					cs++;
					continue;
				} else {
					/* not enough buffer */
					goto end;
				}
			}
		}
	}

end:
	*filtered = '\0';

	if (cs >= 2 &&
	    filtered[-2] == '\\' && filtered[-1] == 'n') {
		filtered[-2] = '\0';
	}
}

static char *
alloc_stacks(int numstacks)
{
	size_t pagesize, mapsize;
	char *stack_top;
	char *addr;
	int i;

	pagesize = (size_t)sysconf(_SC_PAGESIZE);
	/*
	 * stacksize and redzonesize are global so threads
	 * can be created elsewhere and refer to the sizes
	 */
	stacksize = (size_t)roundup(sysconf(_SC_THREAD_STACK_MIN) +
	    DEFAULT_STACKSIZE, pagesize);
	redzonesize = (size_t)roundup(DEFAULT_REDZONESIZE, pagesize);

	/*
	 * allocate an additional "redzonesize" chunk in addition
	 * to what we require, so we can create a redzone at the
	 * bottom of the last stack as well.
	 */
	mapsize = redzonesize + numstacks * (stacksize + redzonesize);
	stack_top = mmap(NULL, mapsize, PROT_READ|PROT_WRITE,
	    MAP_PRIVATE|MAP_ANON, -1, 0);
	if (stack_top == MAP_FAILED)
		return (NULL);

	addr = stack_top;
	/*
	 * this loop is intentionally <= instead of <, so we can
	 * protect the redzone at the bottom of the last stack
	 */
	for (i = 0; i <= numstacks; i++) {
		(void) mprotect(addr, redzonesize, PROT_NONE);
		addr += stacksize + redzonesize;
	}
	return ((char *)(stack_top + redzonesize));
}

static void
dealloc_stacks(int numstacks)
{
	size_t pagesize, mapsize;

	pagesize = (size_t)sysconf(_SC_PAGESIZE);

	stacksize = (size_t)roundup(sysconf(_SC_THREAD_STACK_MIN) +
	    DEFAULT_STACKSIZE, pagesize);

	redzonesize = (size_t)roundup(DEFAULT_REDZONESIZE, pagesize);

	mapsize = redzonesize + numstacks * (stacksize + redzonesize);
	(void) munmap(cstack_ptr - mapsize, mapsize);
}

static void
filed_destroy(struct filed *f)
{
	(void) dataq_destroy(&f->f_queue);
	(void) pthread_mutex_destroy(&f->filed_mutex);
}

static void
close_door(void)
{
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	(void) fdetach(DoorFileName);

	DPRINT2(5, "close_door(%u): detached server() from %s\n",
	    mythreadno, DoorFileName);
}

static void
delete_doorfiles(void)
{
	pthread_t mythreadno;
	struct stat sb;
	int err;
	char line[MAXLINE+1];

	if (Debug) {
		mythreadno = pthread_self();
	}


	if (lstat(DoorFileName, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
		if (unlink(DoorFileName) < 0) {
			err = errno;
			(void) snprintf(line, sizeof (line),
			    "unlink() of %s failed - fatal", DoorFileName);
			errno = err;
			logerror(line);
			DPRINT3(1, "delete_doorfiles(%u): error: %s, "
			    "errno=%d\n", mythreadno, line, err);
			exit(1);
		}

		DPRINT2(5, "delete_doorfiles(%u): deleted %s\n",
		    mythreadno, DoorFileName);
	}

	if (strcmp(DoorFileName, DOORFILE) == 0) {
		if (lstat(OLD_DOORFILE, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
			if (unlink(OLD_DOORFILE) < 0) {
				err = errno;
				(void) snprintf(line, sizeof (line),
				    "unlink() of %s failed", OLD_DOORFILE);
				DPRINT2(5, "delete_doorfiles(%u): %s\n",
				    mythreadno, line);

				if (err != EROFS) {
					errno = err;
					(void) strlcat(line, " - fatal",
					    sizeof (line));
					logerror(line);
					DPRINT3(1, "delete_doorfiles(%u): "
					    "error: %s, errno=%d\n",
					    mythreadno, line, err);
					exit(1);
				}

				DPRINT1(5, "delete_doorfiles(%u): unlink() "
				    "failure OK on RO file system\n",
				    mythreadno);
			}

			DPRINT2(5, "delete_doorfiles(%u): deleted %s\n",
			    mythreadno, OLD_DOORFILE);
		}
	}

	if (lstat(PidFileName, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
		if (unlink(PidFileName) < 0) {
			err = errno;
			(void) snprintf(line, sizeof (line),
			    "unlink() of %s failed - fatal", PidFileName);
			errno = err;
			logerror(line);
			DPRINT3(1, "delete_doorfiles(%u): error: %s, "
			    "errno=%d\n", mythreadno, line, err);
			exit(1);
		}

		DPRINT2(5, "delete_doorfiles(%u): deleted %s\n", mythreadno,
		    PidFileName);
	}

	if (strcmp(PidFileName, PIDFILE) == 0) {
		if (lstat(OLD_PIDFILE, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
			if (unlink(OLD_PIDFILE) < 0) {
				err = errno;
				(void) snprintf(line, sizeof (line),
				    "unlink() of %s failed", OLD_PIDFILE);
				DPRINT2(5, "delete_doorfiles(%u): %s, \n",
				    mythreadno, line);

				if (err != EROFS) {
					errno = err;
					(void) strlcat(line, " - fatal",
					    sizeof (line));
					logerror(line);
					DPRINT3(1, "delete_doorfiles(%u): "
					    "error: %s, errno=%d\n",
					    mythreadno, line, err);
					exit(1);
				}

				DPRINT1(5, "delete_doorfiles(%u): unlink "
				    "failure OK on RO file system\n",
				    mythreadno);
			}

			DPRINT2(5, "delete_doorfiles(%u): deleted %s\n",
			    mythreadno, OLD_PIDFILE);
		}
	}

	if (DoorFd != -1) {
		(void) door_revoke(DoorFd);
	}

	DPRINT2(1, "delete_doorfiles(%u): revoked door: DoorFd=%d\n",
	    mythreadno, DoorFd);
}


/*ARGSUSED*/
static void
signull(int sig, siginfo_t *sip, void *utp)
{
	DPRINT1(1, "signull(%u): THIS CALL SHOULD NEVER HAPPEN\n",
	    pthread_self());
	/*
	 * Do nothing, as this is a place-holder used in conjunction with
	 * sigaction()/sigwait() to ensure that the proper disposition is
	 * given to the signals we handle in main().
	 */
}

/*
 * putctrlc returns zero, if failed due to not enough buffer.
 * Otherwise, putctrlc returns non-zero.
 *
 * c:     a byte to print in ASCII format
 * **buf: a pointer to the pointer to the output buffer.
 * *cl:   current length of characters in the output buffer
 * max:   maximum length of the buffer
 */

static int
putctrlc(int c, char **buf, size_t *cl, size_t max)
{
	char	*p = *buf;

	if (c == '\n') {
		if (*cl + 2 < max) {
			*p++ = '\\';
			*p++ = 'n';
			*cl += 2;
			*buf = p;
			return (2);
		} else {
			return (0);
		}
	} else if (c < 0200) {
		/* ascii control character */
		if (*cl + 2 < max) {
			*p++ = '^';
			*p++ = c ^ 0100;
			*cl += 2;
			*buf = p;
			return (2);
		} else {
			return (0);
		}
	} else {
		if (*cl + 4 < max) {
			*p++ = '\\';
			*p++ = ((c >> 6) & 07) + '0';
			*p++ = ((c >> 3) & 07) + '0';
			*p++ = (c & 07) + '0';
			*cl += 4;
			*buf = p;
			return (4);
		} else {
			return (0);
		}
	}
}

/*
 * findnl_bkwd:
 *	Scans each character in buf until it finds the last newline in buf,
 *	or the scanned character becomes the last COMPLETE character in buf.
 *	Returns the number of scanned bytes.
 *
 *	buf - pointer to a buffer containing the message string
 *	len - the length of the buffer
 */
size_t
findnl_bkwd(const char *buf, const size_t len)
{
	const char *p;
	size_t	mb_cur_max;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (len == 0) {
		return (0);
	}

	mb_cur_max = MB_CUR_MAX;

	if (mb_cur_max == 1) {
		/* single-byte locale */
		for (p = buf + len - 1; p != buf; p--) {
			if (*p == '\n') {
				return ((size_t)(p - buf));
			}
		}
		return ((size_t)len);
	} else {
		/* multi-byte locale */
		int mlen;
		const char *nl;
		size_t	rem;

		p = buf;
		nl = NULL;
		for (rem = len; rem >= mb_cur_max; ) {
			mlen = mblen(p, mb_cur_max);
			if (mlen == -1) {
				/*
				 * Invalid character found.
				 */
				DPRINT1(9, "findnl_bkwd(%u): Invalid MB "
				    "sequence\n", mythreadno);
				/*
				 * handle as a single byte character.
				 */
				p++;
				rem--;
			} else {
				/*
				 * It's guaranteed that *p points to
				 * the 1st byte of a multibyte character.
				 */
				if (*p == '\n') {
					nl = p;
				}
				p += mlen;
				rem -= mlen;
			}
		}
		if (nl) {
			return ((size_t)(nl - buf));
		}
		/*
		 * no newline nor null byte found.
		 * Also it's guaranteed that *p points to
		 * the 1st byte of a (multibyte) character
		 * at this point.
		 */
		return (len - rem);
	}
}

/*
 * copynl_frwd:
 *	Scans each character in buf and copies the scanned character to obuf
 *	until it finds a null byte or a newline, or
 *	the number of the remaining bytes in obuf gets to exceed obuflen
 *	if copying the scanned character to obuf.
 *	Returns the number of scanned bytes.
 *
 *	obuf - buffer to be copied the scanned character
 *	obuflen - the size of obuf
 *	buf - pointer to a buffer containing the message string
 *	len - the length of the buffer
 */
size_t
copynl_frwd(char *obuf, const size_t obuflen,
	    const char *buf, const size_t len)
{
	const char *p;
	char	*q = obuf;
	size_t	olen = 0;
	size_t	mb_cur_max;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (len == 0) {
		return (0);
	}

	mb_cur_max = MB_CUR_MAX;

	if (mb_cur_max == 1) {
		/* single-byte locale */
		for (p = buf; *p; ) {
			if (obuflen > olen + 1) {
				if (*p != '\n') {
					*q++ = *p++;
					olen++;
				} else {
					*q = '\0';
					return ((size_t)(p - buf));
				}
			} else {
				*q = '\0';
				return ((size_t)(p - buf));
			}
		}
		*q = '\0';
		return ((size_t)(p - buf));
	} else {
		/* multi-byte locale */
		int mlen;

		for (p = buf; *p; ) {
			mlen = mblen(p, mb_cur_max);
			if (mlen == -1) {
				/*
				 * Invalid character found.
				 */
				DPRINT1(9, "copynl_frwd(%u): Invalid MB "
				    "sequence\n", mythreadno);
				/*
				 * handle as a single byte character.
				 */
				if (obuflen > olen + 1) {
					*q++ = *p++;
					olen++;
				} else {
					*q = '\0';
					return ((size_t)(p - buf));
				}
			} else {
				/*
				 * It's guaranteed that *p points to
				 * the 1st byte of a multibyte character.
				 */
				if (*p == '\n') {
					*q = '\0';
					return ((size_t)(p - buf));
				}
				if (obuflen > olen + mlen) {
					int	n;
					for (n = 0; n < mlen; n++) {
						*q++ = *p++;
					}
					olen += mlen;
				} else {
					*q = '\0';
					return ((size_t)(p - buf));
				}
			}
		}
		/*
		 * no newline nor null byte found.
		 * Also it's guaranteed that *p points to
		 * the 1st byte of a (multibyte) character
		 * at this point.
		 */
		*q = '\0';
		return ((size_t)(p - buf));
	}
}

/*
 * copy_frwd:
 *	Scans each character in buf and copies the scanned character to obuf
 *	until the number of the remaining bytes in obuf gets to exceed obuflen
 *	if copying the scanned character to obuf.
 *	Returns the number of scanned (copied) bytes.
 *
 *	obuf - buffer to be copied the scanned character
 *	obuflen - the size of obuf
 *	buf - pointer to a buffer containing the message string
 *	len - the length of the buffer
 */
size_t
copy_frwd(char *obuf, const size_t obuflen,
	const char *buf, const size_t len)
{
	const char *p;
	char	*q = obuf;
	size_t	olen = 0;
	size_t	mb_cur_max;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (len == 0) {
		return (0);
	}

	mb_cur_max = MB_CUR_MAX;

	if (mb_cur_max == 1) {
		/* single-byte locale */
		if (obuflen > len) {
			(void) memcpy(obuf, buf, len);
			obuf[len] = '\0';
			return ((size_t)len);
		} else {
			(void) memcpy(obuf, buf, obuflen - 1);
			obuf[obuflen - 1] = '\0';
			return (obuflen - 1);
		}
	} else {
		/* multi-byte locale */
		int mlen;

		for (p = buf; *p; ) {
			mlen = mblen(p, mb_cur_max);
			if (mlen == -1) {
				/*
				 * Invalid character found.
				 */
				DPRINT1(9, "copy_frwd(%u): Invalid MB "
				    "sequence\n", mythreadno);
				/*
				 * handle as a single byte character.
				 */
				if (obuflen > olen + 1) {
					*q++ = *p++;
					olen++;
				} else {
					*q = '\0';
					return ((size_t)(p - buf));
				}
			} else {
				if (obuflen > olen + mlen) {
					int	n;
					for (n = 0; n < mlen; n++) {
						*q++ = *p++;
					}
					olen += mlen;
				} else {
					*q = '\0';
					return ((size_t)(p - buf));
				}
			}
		}
		*q = '\0';
		return ((size_t)(p - buf));
	}
}

/*
 * properties:
 *	Get properties from SMF framework.
 */
static void
properties(void)
{
	scf_simple_prop_t *prop;
	uint8_t *bool;

	if ((prop = scf_simple_prop_get(NULL, NULL, "config",
	    "log_from_remote")) != NULL) {
		if ((bool = scf_simple_prop_next_boolean(prop)) != NULL) {
			if (*bool == 0)
				turnoff = 1; /* log_from_remote = false */
			else
				turnoff = 0; /* log_from_remote = true */
		}
		scf_simple_prop_free(prop);
		DPRINT1(1, "properties: setting turnoff to %s\n",
		    turnoff ? "true" : "false");
	}
}

/*
 * close all the input devices.
 */
static void
shutdown_input(void)
{
	int cnt;

	shutting_down = 1;

	for (cnt = 0; cnt < Ninputs; cnt++) {
		(void) t_close(Nfd[cnt].fd);
	}

	(void) close(Pfd.fd);
}

/*
 * This is for the one thread that dedicates to resolve the
 * hostname. This will get the messages from net_poll() through
 * hnlq, and resolve the hostname, and push the messages back
 * into the inputq.
 */
/*ARGSUSED*/
static void *
hostname_lookup(void *ap)
{
	char *uap;
	log_message_t *mp;
	host_info_t *hip;
	char failsafe_addr[SYS_NMLN + 1];
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT1(1, "hostname_lookup(%u): hostname_lookup started\n",
	    mythreadno);

	for (;;) {
		(void) dataq_dequeue(&hnlq, (void **)&mp, 0);

		DPRINT3(5, "hostname_lookup(%u): dequeued msg %p"
		    " from queue %p\n", mythreadno, (void *)mp,
		    (void *)&hnlq);

		hip = (host_info_t *)mp->ptr;
		if ((uap = taddr2uaddr(hip->ncp, &hip->addr)) != NULL) {
			(void) strlcpy(failsafe_addr, uap, SYS_NMLN);
			free(uap);
		} else {
			(void) strlcpy(failsafe_addr, "<unknown>", SYS_NMLN);
		}

		mp->hlp = cvthname(&hip->addr, hip->ncp, failsafe_addr);

		if (mp->hlp == NULL) {
			mp->hlp = &NullHostName;
		}

		free(hip->addr.buf);
		free(hip);
		mp->ptr = NULL;

		if (dataq_enqueue(&inputq, (void *)mp) == -1) {
			MALLOC_FAIL("dropping message from remote");
			free_msg(mp);
			continue;
		}

		DPRINT3(5, "hostname_lookup(%u): enqueued msg %p on queue "
		    "%p\n", mythreadno, (void *)mp, (void *)&inputq);
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Does all HUP(re-configuration) process.
 */
static void
reconfigure()
{
	int cnt, loop, drops;
	int really_stuck;
	int console_stuck = 0;
	struct filed *f;
	char buf[LINE_MAX];
	struct utsname up;
	char cbuf[30];
	time_t tim;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	/* If we get here then we must need to regen */
	flushmsg(0);

	if (logmymsg(LOG_SYSLOG|LOG_INFO, "syslogd: configuration restart",
	    ADDDATE, 0) == -1) {
		MALLOC_FAIL("dropping message");
	}

	/*
	 * make sure the logmsg thread is not in the waiting state.
	 * Otherwise, changing hup_state will prevent the logmsg thread
	 * getting out from the waiting loop.
	 */

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: awaiting logmsg()"
		    " moving to the safe place\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	for (loop = 0; loop < LOOP_MAX; loop++) {
		/* we don't need the mutex to read */
		if (hup_state == HUP_ACCEPTABLE)
			break;
		(void) sleep(1);
	}
	if (hup_state != HUP_ACCEPTABLE) {
		goto thread_stuck;
	}

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: logmsg() will accept HUP\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	/*
	 * Prevent logging until we are truly done processing the HUP
	 */
	(void) pthread_mutex_lock(&hup_lock);
	hup_state = HUP_INPROGRESS;
	(void) pthread_mutex_unlock(&hup_lock);

	/*
	 * We will be going into a critical state. Any error message
	 * from syslogd needs to be dumped to the console by default
	 * immediately. Also, those error messages are quened in a temporary
	 * queue to be able to post into the regular stream later.
	 */
	disable_errorlog();

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: sending SHUTDOWN\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	/* stop configured threads */
	if (shutdown_msg() == -1) {
		/*
		 * No memory, message will be dumped to the console.
		 */
		MALLOC_FAIL("unable to restart syslogd");
		goto out;
	}

	/* make sure logmsg() is in suspended state */
	for (loop = 0; loop < LOOP_INTERVAL; loop++) {
		if (hup_state & HUP_LOGMSG_SUSPENDED)
			break;
		(void) sleep(1);
	}

	if ((hup_state & HUP_LOGMSG_SUSPENDED) == 0) {
		if (Debug) {
			tim = time(NULL);
			DPRINT2(3, "reconfigure(%u): %.15s: logmsg() does not "
			    "stop. enforcing\n",
			    mythreadno, ctime_r(&tim, cbuf)+4);
		}

		/* probably we have too long input queue, or really stuck */
		(void) pthread_mutex_lock(&hup_lock);
		hup_state |= HUP_SUSP_LOGMSG_REQD;
		(void) pthread_mutex_unlock(&hup_lock);

		for (loop = 0; loop < LOOP_MAX; loop++) {
			if (hup_state & HUP_LOGMSG_SUSPENDED)
				break;
			(void) sleep(1);
		}
		if ((hup_state & HUP_LOGMSG_SUSPENDED) == 0) {
			if (Debug) {
				tim = time(NULL);
				DPRINT2(3, "reconfigure(%u): %.15s: logmsg()"
				    " does not stop. give up\n",
				    mythreadno, ctime_r(&tim, cbuf)+4);
			}
			logerror("could not suspend logmsg - fatal");
			goto thread_stuck;
		}
	}

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: logmsg() suspended\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	/*
	 * Will wait for LOOP_MAX secs with watching queue lengths for the
	 * each logger threads. If they have backlogs, and no change in the
	 * length of queue found in 30 seconds, those will be counted as
	 * "really stuck".
	 * If all running logger threads become "really stuck" state, there
	 * should be no worth waiting for them to quit.
	 * In that case, we will go ahead and close out file descriptors to
	 * have them pull out from hanging system call, and give them a last
	 * chance(LOOP_INTERVAL sec) to quit.
	 */

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: awaiting logit() to be"
		    " shutdown\n", mythreadno, ctime_r(&tim, cbuf)+4);
	}

	cnt = 0;
	really_stuck = 0;
	while (cnt < (LOOP_MAX/LOOP_INTERVAL) &&
	    conf_threads > really_stuck) {

		/* save initial queue count */
		for (f = Files; f < &Files[nlogs]; f++) {
			f->f_prev_queue_count = (f->f_type == F_UNUSED) ?
			    -1 : f->f_queue_count;
		}

		for (loop = 0; loop < LOOP_INTERVAL; loop++) {
			if (conf_threads == 0)
				break;
			(void) sleep(1);
		}

		if (conf_threads == 0)
			break;

		if (Debug) {
			tim = time(NULL);
			DPRINT3(3, "reconfigure(%u): %.15s: "
			    "%d threads are still alive.\n",
			    mythreadno, ctime_r(&tim, cbuf)+4,
			    conf_threads);
		}

		really_stuck = 0;
		for (f = Files; f < &Files[nlogs]; f++) {
			if (f->f_type == F_UNUSED) {
				f->f_prev_queue_count = -1;
				continue;
			}
			if (f->f_prev_queue_count == f->f_queue_count) {
				really_stuck++;
				f->f_prev_queue_count = 1;
				DPRINT2(3, "reconfigure(%u): "
				    "tid=%d is really stuck.\n",
				    mythreadno, f->f_thread);
			} else {
				f->f_prev_queue_count = 0;
				DPRINT2(3, "reconfigure(%u): "
				    "tid=%d is still active.\n",
				    mythreadno, f->f_thread);
			}
		}
		/*
		 * Here we have one of following values in the
		 * f_prev_queue_count:
		 *  0: logger thread is still actively working.
		 *  1: logger thread is really stuck.
		 * -1: logger thread has already died.
		 */

		cnt++;
	}

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s:"
		    " complete awaiting logit()\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
		DPRINT3(3, "reconfigure(%u): %d threads alive."
		    " %d threads stuck\n",
		    mythreadno, conf_threads, really_stuck);
	}

	/*
	 * Still running? If so, mark it as UNUSED, and close
	 * the fd so that logger threads can bail out from the loop.
	 */
	drops = 0;
	if (conf_threads) {
		for (f = Files; f < &Files[nlogs]; f++) {
			if (f->f_type == F_CONSOLE &&
			    f->f_prev_queue_count == 1) {
				/* console is really stuck */
				console_stuck = 1;
			}
			if (f->f_type == F_USERS || f->f_type == F_WALL ||
			    f->f_type == F_UNUSED)
				continue;
			cnt = f->f_queue_count;
			drops += (cnt > 0) ? cnt - 1: 0;
			f->f_type = F_UNUSED;

			if (f->f_orig_type == F_FORW)
				(void) t_close(f->f_file);
			else
				(void) close(f->f_file);
		}

		if (Debug) {
			tim = time(NULL);
			DPRINT1(3, "reconfigure(%u): terminating logit()\n",
			    mythreadno);
		}

		/* last chance to exit */
		for (loop = 0; loop < LOOP_MAX; loop++) {
			if (conf_threads == 0)
				break;
			(void) sleep(1);
		}

		if (Debug) {
			tim = time(NULL);
			DPRINT3(3, "reconfigure(%u): %.15s: %d alive\n",
			    mythreadno, ctime_r(&tim, cbuf)+4,
			    conf_threads);
		}
	}

	if (conf_threads == 0 && drops) {
		errno = 0;
		logerror("Could not completely output pending messages"
		    " while preparing re-configuration");
		logerror("discarded %d messages and restart configuration.",
		    drops);
		if (Debug) {
			tim = time(NULL);
			DPRINT3(3, "reconfigure(%u): %.15s: "
			    "discarded %d messages\n",
			    mythreadno, ctime_r(&tim, cbuf)+4, drops);
		}
	}

	/*
	 * If all threads still haven't exited
	 * something is stuck or hosed. We just
	 * have no option but to exit.
	 */
	if (conf_threads) {
thread_stuck:
		if (Debug) {
			tim = time(NULL);
			DPRINT2(3, "reconfigure(%u): %.15s: really stuck\n",
			    mythreadno, ctime_r(&tim, cbuf)+4);
		}

		shutdown_input();
		delete_doorfiles();
		(void) uname(&up);

		(void) snprintf(buf, sizeof (buf),
		    "syslogd(%s): some logger thread(s) "
		    "are stuck%s; syslogd is shutting down.",
		    up.nodename,
		    console_stuck ? " (including the console)" : "");

		if (console_stuck) {
			FILE *m = popen(MAILCMD, "w");

			if (m != NULL) {
				(void) fprintf(m, "%s\n", buf);
				(void) pclose(m);
			}
		}

		disable_errorlog();
		logerror(buf);
		exit(1);
	}

	/* Free up some resources */
	if (Files != (struct filed *)&fallback) {
		for (f = Files; f < &Files[nlogs]; f++) {
			(void) pthread_join(f->f_thread, NULL);
			filed_destroy(f);
		}
		free(Files);
	}

	dealloc_stacks(nlogs);

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: cleanup complete\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	hnc_init(1);	/* purge hostname cache */
	conf_init();	/* start reconfigure */

out:;
	/* Now should be ready to dispatch error messages from syslogd. */
	enable_errorlog();

	/* Wake up the log thread */

	if (Debug) {
		tim = time(NULL);
		DPRINT2(3, "reconfigure(%u): %.15s: resuming logmsg()\n",
		    mythreadno, ctime_r(&tim, cbuf)+4);
	}

	(void) pthread_mutex_lock(&hup_lock);
	hup_state = HUP_COMPLETED;
	(void) pthread_cond_signal(&hup_done);
	(void) pthread_mutex_unlock(&hup_lock);
}

/*
 * The following function implements simple hostname cache mechanism.
 * Host name cache is implemented through hash table bucket chaining method.
 * Collisions are handled by bucket chaining.
 *
 * hnc_init():
 * 	allocate and initialize the cache. If reinit is set,
 *	invalidate all cache entries.
 * hnc_look():
 *	It hashes the ipaddress gets the index and walks thru the
 *	single linked list. if cached entry was found, it will
 *	put in the head of the list, and return.While going through
 *	the entries, an entry which has already expired will be invalidated.
 * hnc_register():
 *	Hashes the ipaddress finds the index and puts current entry to the list.
 * hnc_unreg():
 *	invalidate the cachep.
 */

static void
hnc_init(int reinit)
{
	struct hostname_cache **hpp;
	pthread_t mythreadno;
	int i;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (reinit) {
		(void) pthread_mutex_lock(&hnc_mutex);

		for (i = 0; i < hnc_size; i++) {
			for (hpp = &hnc_cache[i]; *hpp != NULL; ) {
				hnc_unreg(hpp);
			}
		}

		(void) pthread_mutex_unlock(&hnc_mutex);
		DPRINT1(2, "hnc_init(%u): hostname cache re-configured\n",
		    mythreadno);
	} else {

		hnc_cache = calloc(hnc_size, sizeof (struct hostname_cache *));

		if (hnc_cache == NULL) {
			MALLOC_FAIL("hostname cache");
			logerror("hostname cache disabled");
			return;
		}

		DPRINT3(1, "hnc_init(%u): hostname cache configured %d entry"
		    " ttl:%d\n", mythreadno, hnc_size, hnc_ttl);
	}
}

static host_list_t *
hnc_lookup(struct netbuf *nbp, struct netconfig *ncp, int *hindex)
{
	struct hostname_cache **hpp, *hp;
	time_t now;
	pthread_t mythreadno;
	int index;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (hnc_cache == NULL) {
		return (NULL);
	}

	(void) pthread_mutex_lock(&hnc_mutex);
	now = time(0);

	*hindex = index = addr_hash(nbp);

	for (hpp = &hnc_cache[index]; (hp = *hpp) != NULL; ) {
		DPRINT4(10, "hnc_lookup(%u): check %p on %p for %s\n",
		    mythreadno, (void *)hp->h, (void *)hp,
		    hp->h->hl_hosts[0]);

		if (hp->expire < now) {
			DPRINT2(9, "hnc_lookup(%u): purge %p\n",
			    mythreadno, (void *)hp);
			hnc_unreg(hpp);
			continue;
		}

		if (ncp == hp->ncp && same_addr(&hp->addr, nbp)) {
			/*
			 * found!
			 * Put the entry at the top.
			 */

			if (hp != hnc_cache[index]) {
				/* unlink from active list */
				*hpp = (*hpp)->next;
				/* push it onto the top */
				hp->next = hnc_cache[index];
				hnc_cache[index] = hp;
			}

			(void) pthread_mutex_lock(&hp->h->hl_mutex);
			hp->h->hl_refcnt++;
			(void) pthread_mutex_unlock(&hp->h->hl_mutex);

			DPRINT4(9, "hnc_lookup(%u): found %p on %p for %s\n",
			    mythreadno, (void *)hp->h, (void *)hp,
			    hp->h->hl_hosts[0]);

			(void) pthread_mutex_unlock(&hnc_mutex);
			return (hp->h);
		}

		hpp = &hp->next;
	}

	(void) pthread_mutex_unlock(&hnc_mutex);
	return (NULL);
}

static void
hnc_register(struct netbuf *nbp, struct netconfig *ncp,
		    host_list_t *h, int hindex)
{
	struct hostname_cache **hpp, **tailp, *hp, *entry;
	void *addrbuf;
	time_t now;
	pthread_t mythreadno;
	int i;

	if (Debug) {
		mythreadno = pthread_self();
	}

	if (hnc_cache == NULL) {
		return;
	}

	if ((addrbuf = malloc(nbp->len)) == NULL) {
		MALLOC_FAIL("pushing hostname cache");
		return;
	}

	if ((entry = malloc(sizeof (struct hostname_cache))) == NULL) {
		MALLOC_FAIL("pushing hostname entry");
		free(addrbuf);
		return;
	}

	(void) pthread_mutex_lock(&hnc_mutex);

	i = 0;

	now = time(0);
	/*
	 * first go through active list, and discard the
	 * caches which has been invalid. Count number of
	 * non-expired buckets.
	 */

	for (hpp = &hnc_cache[hindex]; (hp = *hpp) != NULL; ) {
		tailp = hpp;

		if (hp->expire < now) {
			DPRINT2(9, "hnc_register(%u): discard %p\n",
			    mythreadno, (void *)hp);
			hnc_unreg(hpp);
		} else {
			i++;
			hpp = &hp->next;
		}
	}

	/*
	 * If max limit of chained hash buckets has been used up
	 * delete the least active element in the chain.
	 */
	if (i == MAX_BUCKETS) {
		hnc_unreg(tailp);
	}

	(void) memcpy(addrbuf, nbp->buf, nbp->len);
	entry->addr.len = nbp->len;
	entry->addr.buf = addrbuf;
	entry->ncp = ncp;
	entry->h = h;
	entry->expire = time(NULL) + hnc_ttl;

	/* insert it at the top */
	entry->next = hnc_cache[hindex];
	hnc_cache[hindex] = entry;

	/*
	 * As far as cache is valid, corresponding host_list must
	 * also be valid. Increments the refcnt to avoid freeing
	 * host_list.
	 */
	h->hl_refcnt++;
	DPRINT4(9, "hnc_register(%u): reg %p onto %p for %s\n",
	    mythreadno, (void *)entry->h, (void *)entry, entry->h->hl_hosts[0]);
	(void) pthread_mutex_unlock(&hnc_mutex);
}

static void
hnc_unreg(struct hostname_cache **hpp)
{
	struct hostname_cache *hp = *hpp;
	pthread_t mythreadno;

	if (Debug) {
		mythreadno = pthread_self();
	}

	DPRINT4(9, "hnc_unreg(%u): unreg %p on %p for %s\n",
	    mythreadno, (void *)hp->h, (void *)hp, hp->h->hl_hosts[0]);
	free(hp->addr.buf);
	freehl(hp->h);

	/* unlink from active list */
	*hpp = (*hpp)->next;

	free(hp);
}

/*
 * Once this is called, error messages through logerror() will go to
 * the console immediately. Also, messages are queued into the tmpq
 * to be able to later put them into inputq.
 */
static void
disable_errorlog()
{
	(void) dataq_init(&tmpq);

	(void) pthread_mutex_lock(&logerror_lock);
	interrorlog = 0;
	(void) pthread_mutex_unlock(&logerror_lock);
}

/*
 * Turn internal error messages to regular input stream.
 * All pending messages are pulled and pushed into the regular
 * input queue.
 */
static void
enable_errorlog()
{
	log_message_t *mp;

	(void) pthread_mutex_lock(&logerror_lock);
	interrorlog = 1;
	(void) pthread_mutex_unlock(&logerror_lock);

	/*
	 * push all the pending messages into inputq.
	 */
	while (dataq_dequeue(&tmpq, (void **)&mp, 1) == 0) {
		(void) dataq_enqueue(&inputq, mp);
	}
	(void) dataq_destroy(&tmpq);
}

/*
 * Generate a hash value of the given address and derive
 * an index into the hnc_cache hashtable.
 * The hashing method is similar to what Java does for strings.
 */
static int
addr_hash(struct netbuf *nbp)
{
	char *uap;
	int i;
	unsigned long hcode = 0;

	uap = nbp->buf;

	if (uap == NULL) {
		return (0);
	}

	/*
	 * Compute a hashcode of the address string
	 */
	for (i = 0; i < nbp->len; i++)
		hcode = (31 * hcode) + uap[i];

	/*
	 * Scramble the hashcode for better distribution
	 */
	hcode += ~(hcode << 9);
	hcode ^=  (hcode >> 14);
	hcode +=  (hcode << 4);
	hcode ^=  (hcode >> 10);

	return ((int)(hcode % hnc_size));
}
