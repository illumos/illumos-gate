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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <utmpx.h>
#include <pwd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/mount.h>
#include <rpcsvc/rwall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <locale.h>
#include <sys/syslog.h>
#include <zone.h>
#include <signal.h>

/*
 *	/usr/etc/shutdown when [messages]
 *
 *	allow super users to tell users and remind users
 *	of iminent shutdown of unix
 *	and shut it down automatically
 *	and even reboot or halt the machine if they desire
 */

#define	EPATH	"PATH=/usr/ucb:/usr/bin:/usr/sbin:"
#define	REBOOT	"/usr/sbin/reboot"
#define	HALT	"/usr/sbin/halt"
#define	MAXINTS 20
#define	HOURS	*3600
#define	MINUTES	*60
#define	SECONDS
#define	NLOG		600		/* no of bytes possible for message */
#define	NOLOGTIME	5 MINUTES
#define	IGNOREUSER	"sleeper"

struct hostlist {
    char *host;
    struct hostlist *nxt;
} *hostlist;

char	hostname[MAXHOSTNAMELEN];
char	mbuf[BUFSIZ];

extern	char *malloc();

extern	char *ctime();
extern	struct tm *localtime();

extern	char *strcpy();
extern	char *strncat();
extern	off_t lseek();

struct	utmpx *utmpx;

int	sint;
int	stogo;
char	tpath[] =	"/dev/";
int	nlflag = 1;		/* nolog yet to be done */
int	killflg = 1;
int	doreboot = 0;
int	halt = 0;
int	fast = 0;
char	*nosync = NULL;
char	nosyncflag[] = "-n";
char	term[sizeof tpath + sizeof (utmpx->ut_line)];
char	tbuf[BUFSIZ];
char    nolog1[] = "\n\nNO LOGINS: System going down at %5.5s\n\n";
char	mesg[NLOG+1];
#ifdef	DEBUG
char	fastboot[] = "fastboot";
#else
char	fastboot[] = "/fastboot";
#endif
char    nologin[] = "/etc/nologin";
time_t	nowtime;
jmp_buf	alarmbuf;

struct interval {
	int stogo;
	int sint;
} interval[] = {
	4 HOURS,	1 HOURS,
	2 HOURS,	30 MINUTES,
	1 HOURS,	15 MINUTES,
	30 MINUTES,	10 MINUTES,
	15 MINUTES,	5 MINUTES,
	10 MINUTES,	5 MINUTES,
	5 MINUTES,	3 MINUTES,
	2 MINUTES,	1 MINUTES,
	1 MINUTES,	30 SECONDS,
	0 SECONDS,	0 SECONDS
};

char	*msg1 = "shutdown: '%c' - unknown flag\n";
char	*msg2 = "Usage: shutdown [ -krhfn ] shutdowntime [ message ]\n";
char	*msg3 = "Usage: shutdown [ -krhfn ] shutdowntime [ message ]";
char	*msg4 = "Usage: shutdown [ -krhfn ] shutdowntime [ message ]\n";
char	*msg5 = "Usage: shutdown [ -krhfn ] shutdowntime [ message ]";
char	*msg6 = "\n\007\007System shutdown time has arrived\007\007\n";
char	*msg7 = "but you'll have to do it yourself\n";
char	*msg8 = "but you'll have to do it yourself";
char	*msg9 = "-l (without fsck's)\n";
char	*msg10 = "-l %s\n";
char	*msg11 = " (without fsck's)\n";
char	*msg12 = "That must be tomorrow\nCan't you wait till then?\n";
char	*msg13 = "That must be tomorrow";
char	*msg14 = "Can't you wait till then?";
char	*msg15 = "\007\007\t*** %sSystem shutdown message from %s@%s ***\r\n\n";
char	*msg16 = "System going down at %5.5s\r\n";
char	*msg17 = "System going down in %d minute%s\r\n";
char	*msg18 = "System going down in %d second%s\r\n";
char	*msg19 = "System going down IMMEDIATELY\r\n";
char	*msg20 = "Can't get PID for init\n";

char *shutter, *getlogin();

static void timeout(void);
static void gethostlist(void);
static void finish(char *, char *, int);
static void nolog(time_t);
static void rprintf(char *, char *);
static void rwarn(char *, time_t, time_t, char *, int);
static void doitfast(void);
static void warn(FILE *, time_t, time_t, char *, int);
static time_t getsdt(char *);

pid_t
get_initpid(void)
{
	pid_t init_pid;

	if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
	    sizeof (init_pid)) != sizeof (init_pid)) {
		(void) fprintf(stderr, gettext(msg20));
		exit(1);
	}
	return (init_pid);
}

int
main(int argc, char **argv)
{
	int i;
	char *f;
	char *ts;
	time_t sdt;
	int h, m;
	int first;
	void finish_sig();
	FILE *termf;
	struct passwd *pw, *getpwuid();
	extern char *strcat();
	extern uid_t geteuid();
	struct hostlist *hl;
	char *shutdown_program;
	char *shutdown_action;
	int fd;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	audit_shutdown_setup(argc, argv);

	shutter = getlogin();
	if (shutter == 0 && (pw = getpwuid(getuid())))
		shutter = pw->pw_name;
	if (shutter == 0)
		shutter = "???";
	(void) gethostname(hostname, sizeof (hostname));
	openlog("shutdown", 0, LOG_AUTH);
	argc--, argv++;
	while (argc > 0 && (f = argv[0], *f++ == '-')) {
		while (i = *f++) {
			switch (i) {
				case 'k':
					killflg = 0;
					continue;
				case 'n':
					nosync = nosyncflag;
					continue;
				case 'f':
					fast = 1;
					continue;
				case 'r':
					doreboot = 1;
					continue;
				case 'h':
					halt = 1;
					continue;
				default:
					(void) fprintf(stderr, gettext(msg1),
									i);
					(void) fprintf(stderr, gettext(msg2));
					finish(gettext(msg3), "", 1);
			}
		}
		argc--, argv++;
	}
	if (argc < 1) {
		(void) fprintf(stderr, gettext(msg4));
		finish(gettext(msg5), "", 1);
	}
	if (doreboot && halt) {
		(void) fprintf(stderr,
		    gettext("shutdown: Incompatible switches '-r' & '-h'\n"));
		finish(gettext("shutdown: Incompatible switches '-r' & '-h'"),
		    "", 1);
	}
	if (fast && (nosync == nosyncflag)) {
		(void) fprintf(stderr,
		    gettext("shutdown: Incompatible switches '-f' & '-n'\n"));
		finish(gettext("shutdown: Incompatible switches '-f' & '-n'"),
		    "", 1);
	}
	if (geteuid()) {
		(void) fprintf(stderr, gettext("shutdown: NOT super-user\n"));
		finish(gettext("shutdown: NOT super-user"), "", 1);
	}
	gethostlist();
	nowtime = time((time_t *)NULL);
	sdt = getsdt(argv[0]);
	argc--, argv++;
	mesg[0] = '\0';
	i = 0;
	while (argc-- > 0) {
		if (i + strlen(*argv) > NLOG)
			break;	/* no more room for the message */
		i += strlen(*argv) + 1;
		(void) strcat(mesg, *argv++);
		(void) strcat(mesg, " ");
	}
	if (i != 0)
		mesg[i - 1] = '\0';	/* remove trailing blank */
	m = ((stogo = sdt - nowtime) + 30)/60;
	h = m/60;
	m %= 60;
	ts = ctime(&sdt);
	(void) printf(gettext("Shutdown at %5.5s (in "), ts+11);
	if (h > 0)
		(void) printf("%d hour%s ", h, h != 1 ? "s" : "");
	(void) printf("%d minute%s) ", m, m != 1 ? "s" : "");
#ifndef DEBUG
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
#endif
	(void) signal(SIGTTOU, SIG_IGN);
	(void) signal(SIGINT, finish_sig);
	(void) signal(SIGALRM, (void(*)())timeout);
	(void) setpriority(PRIO_PROCESS, 0, PRIO_MIN);
	(void) fflush(stdout);
#ifndef DEBUG
	if (i = fork()) {
		(void) printf(gettext("[pid %d]\n"), i);
		exit(0);
	}
#else
	(void) putc('\n', stdout);
#endif
	sint = 1 HOURS;
	f = "";
	first = 1;
	if (doreboot) {
		shutdown_program = REBOOT;
		shutdown_action = "reboot";
	} else if (halt) {
		shutdown_program = HALT;
		shutdown_action = "halt";
	} else {
		shutdown_program = NULL;
		shutdown_action = "shutdown";
	}
	for (;;) {
		for (i = 0; stogo <= interval[i].stogo && interval[i].sint; i++)
			sint = interval[i].sint;
		if (stogo > 0 && (stogo-sint) < interval[i].stogo)
			sint = stogo - interval[i].stogo;
		if (stogo <= NOLOGTIME && nlflag) {
			nlflag = 0;
			nolog(sdt);
		}
		if (sint >= stogo || sint == 0)
			f = "FINAL ";
		nowtime = time((time_t *)NULL);

		setutxent();

		while ((utmpx = getutxent()) != NULL) {
		    if (utmpx->ut_name[0] &&
			strncmp(utmpx->ut_name, IGNOREUSER,
			    sizeof (utmpx->ut_name))) {
			/*
			 * don't write to pty's unless they're rlogin sessions
			 */
			if (utmpx->ut_type != USER_PROCESS &&
			    utmpx->ut_user[0] != '\0')
				continue;

			if (setjmp(alarmbuf))
				continue;
			(void) strcpy(term, tpath);
			(void) strncat(term, utmpx->ut_line,
			    sizeof (utmpx->ut_line));
			(void) alarm(5);

			/* check if device is really a tty */
			if ((fd = open(term, O_WRONLY|O_NOCTTY)) == -1) {
				fprintf(stderr, gettext("Cannot open %s.\n"),
				    term);
				(void) alarm(0);
				continue;
			} else {
			    if (!isatty(fd)) {
				fprintf(stderr,
				    gettext("%.*s in utmpx is not a tty\n"),
				    sizeof (utmpx->ut_line), utmpx->ut_line);
				syslog(LOG_CRIT, "%.*s in utmpx is not "
				    "a tty\n", sizeof (utmpx->ut_line),
				    utmpx->ut_line);
				close(fd);
				(void) alarm(0);
				continue;
			    }
			}
			close(fd);
#ifdef DEBUG
			if ((termf = stdout) != NULL)
#else
			if ((termf = fopen(term, "w")) != NULL)
#endif
			{
				(void) alarm(0);
				setbuf(termf, tbuf);
				(void) fprintf(termf, "\n\r\n");
				warn(termf, sdt, nowtime, f, first);
				(void) alarm(5);
#ifdef DEBUG
				(void) fflush(termf);
#else
				(void) fclose(termf);
#endif
				(void) alarm(0);
			}
		    }
		}  /* while */

		endutxent();

		for (hl = hostlist; hl != NULL; hl = hl->nxt)
			rwarn(hl->host, sdt, nowtime, f, first);
		if (stogo <= 0) {
			(void) printf(gettext(msg6));
			if (*mesg)
				syslog(LOG_CRIT, "%s by %s: %s",
				    shutdown_action, shutter, mesg);
			else
				syslog(LOG_CRIT, "%s by %s",
				    shutdown_action, shutter);
			sleep(2);
			(void) unlink(nologin);
			if (!killflg) {
				(void) printf(gettext(msg7));
				finish(gettext(msg8), "", 0);
			}
			if (fast)
				doitfast();
#ifndef DEBUG
			(void) putenv(EPATH);
			if (shutdown_program != NULL) {
				audit_shutdown_success();
				execlp(shutdown_program, shutdown_program,
				    "-l", nosync, (char *)0);
			} else {
				if (geteuid() == 0) {
					audit_shutdown_success();
					sleep(5);
				}
				if (getzoneid() == GLOBAL_ZONEID) {
					(void) system(
					    "/sbin/bootadm -a update_all");
				}

				(void) kill(get_initpid(), SIGINT); /* sync */
				(void) kill(get_initpid(), SIGINT); /* sync */
				sleep(20);
			}
#else
			if (shutdown_program) {
				(void) printf("%s ", shutdown_program);
				if (fast)
					(void) printf(gettext(msg9));
				else if (nosync != NULL)
					(void) printf(gettext(msg10), nosync);
				else
					(void) printf(gettext("-l\n"));
			} else {
				(void) printf("/sbin/bootadm -a update_all");
				(void) printf("kill -INT 1");
				if (fast)
					(void) printf(gettext(msg11));
				else
					(void) printf("\n");
			}
#endif
			finish("", "", 0);
		}
		stogo = sdt - time((time_t *)NULL);
		if (stogo > 0 && sint > 0)
			sleep((unsigned)(sint < stogo ? sint : stogo));
		stogo -= sint;
		first = 0;
	}
	/* NOTREACHED */
}

static time_t
getsdt(char *s)
{
	time_t t, t1, tim;
	char c;
	struct tm *lt;
	int c_count;

	if (strcmp(s, "now") == 0)
		return (nowtime);
	if (*s == '+') {
		++s;
		t = 0;
		for (c_count = 1; ; c_count++) {
			c = *s++;
			if (!isdigit(c)) {
					if (c_count == 1) {
							goto badform;
					} else {
							break;
					}
			}
			t = t * 10 + c - '0';
		}
		if (t <= 0)
			t = 5;
		t *= 60;
		tim = time((time_t *)NULL) + t;
		return (tim);
	}
	t = 0;
	while (strlen(s) > 2 && isdigit(*s))
		t = t * 10 + *s++ - '0';
	if (*s == ':')
		s++;
	if (t > 23)
		goto badform;
	tim = t*60;
	t = 0;
	while (isdigit(*s))
		t = t * 10 + *s++ - '0';
	if (t > 59)
		goto badform;
	tim += t;
	tim *= 60;
	t1 = time((time_t *)NULL);
	lt = localtime(&t1);
	t = lt->tm_sec + lt->tm_min*60 + lt->tm_hour*3600;
	if (tim < t || tim >= (24*3600)) {
		/* before now or after midnight */
		(void) printf(gettext(msg12));
		finish(gettext(msg13), gettext(msg14), 0);
	}
	return (t1 + tim - t);
badform:
	(void) printf(gettext("Bad time format\n"));
	finish(gettext("Bad time format"), "", 0);
	return (0);
	/* NOTREACHED */
}

static void
warn(FILE *termf, time_t sdt, time_t now, char *type, int first)
{
	char *ts;
	time_t delay = sdt - now;

	if (delay > 8)
		while (delay % 5)
			delay++;

	(void) fprintf(termf, gettext(msg15), type, shutter, hostname);

	ts = ctime(&sdt);
	if (delay > 10 MINUTES)
		(void) fprintf(termf, gettext(msg16), ts+11);
	else if (delay > 95 SECONDS) {
		(void) fprintf(termf, gettext(msg17), (delay+30)/60,
						(delay+30)/60 != 1 ? "s" : "");
	} else if (delay > 0) {
		(void) fprintf(termf, gettext(msg18), delay,
							delay != 1 ? "s" : "");
	} else
		(void) fprintf(termf, gettext(msg19));

	if (first || sdt - now > 1 MINUTES) {
		if (*mesg)
			(void) fprintf(termf, "\t...%s\r\n", mesg);
	}
}

static void
doitfast(void)
{
	FILE *fastd;

	if ((fastd = fopen(fastboot, "w")) != NULL) {
		(void) putc('\n', fastd);
		(void) fclose(fastd);
	}
}

static void
rwarn(char *host, time_t sdt, time_t now, char *type, int first)
{
	char *ts;
	time_t delay = sdt - now;
	char *bufp;

	if (delay > 8)
		while (delay % 5)
			delay++;

	(void) sprintf(mbuf,
	    "\007\007\t*** %sShutdown message for %s from %s@%s ***\r\n\n",
		type, hostname, shutter, hostname);
	ts = ctime(&sdt);
	bufp = mbuf + strlen(mbuf);
	if (delay > 10 MINUTES) {
		(void) sprintf(bufp, "%s going down at %5.5s\r\n", hostname,
		    ts+11);
	} else if (delay > 95 SECONDS) {
		(void) sprintf(bufp, "%s going down in %d minute%s\r\n",
		    hostname, (delay+30)/60, (delay+30)/60 != 1 ? "s" : "");
	} else if (delay > 0) {
		(void) sprintf(bufp, "%s going down in %d second%s\r\n",
		    hostname, delay, delay != 1 ? "s" : "");
	} else {
		(void) sprintf(bufp, "%s going down IMMEDIATELY\r\n",
		    hostname);
	}
	bufp = mbuf + strlen(mbuf);
	if (first || sdt - now > 1 MINUTES) {
		if (*mesg)
			(void) sprintf(bufp, "\t...%s\r\n", mesg);
	}
	rprintf(host, mbuf);
}

static void
rprintf(char *host, char *bufp)
{
	int err;

#ifdef DEBUG
	(void) fprintf(stderr, gettext("about to call %s\n"), host);
#endif
	if (err = callrpcfast(host, (rpcprog_t)WALLPROG, (rpcvers_t)WALLVERS,
	    (rpcproc_t)WALLPROC_WALL, xdr_dirpath, (char *)&bufp, xdr_void,
	    (char *)NULL)) {
#ifdef DEBUG
		(void) fprintf(stderr, gettext("couldn't make rpc call: "));
		clnt_perrno(err);
		(void) fprintf(stderr, "\n");
#endif
	    }
}

static void
nolog(time_t sdt)
{
	FILE *nologf;

	(void) unlink(nologin);			/* in case linked to std file */
	if ((nologf = fopen(nologin, "w")) != NULL) {
		(void) fprintf(nologf, nolog1, (ctime(&sdt)) + 11);
		if (*mesg)
			(void) fprintf(nologf, "\t%s\n", mesg);
		(void) fclose(nologf);
	}
}

void
finish_sig(void)
{
	finish("SIGINT", "", 1);
}

static void
finish(char *s1, char *s2, int exitcode)
{
	(void) signal(SIGINT, SIG_IGN);
	exit(exitcode);
}

static void
timeout(void)
{
	(void) signal(SIGALRM, (void(*)())timeout);
	longjmp(alarmbuf, 1);
}

static void
gethostlist(void)
{
	int s;
	struct mountbody *ml;
	struct hostlist *hl;
	struct sockaddr_in addr;
	CLIENT *cl;
	static struct timeval TIMEOUT = { 25, 0 };

	/*
	 * check for portmapper
	 */
	get_myaddress(&addr);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return;
	if (connect(s, (struct sockaddr *)&addr, sizeof (addr)) < 0)
		return;
	(void) close(s);

	/*
	 * First try tcp, then drop back to udp if
	 * tcp is unavailable (an old version of mountd perhaps)
	 * Using tcp is preferred because it can handle
	 * arbitrarily long export lists.
	 */
	cl = clnt_create(hostname, (ulong_t)MOUNTPROG, (ulong_t)MOUNTVERS,
	    "tcp");
	if (cl == NULL) {
		cl = clnt_create(hostname, (ulong_t)MOUNTPROG,
		    (ulong_t)MOUNTVERS, "udp");
		if (cl == NULL) {
			if (rpc_createerr.cf_stat != RPC_PROGNOTREGISTERED) {
				clnt_pcreateerror("shutdown warning");
			}
			return;
		}
	}

	ml = NULL;
	if (clnt_call(cl, MOUNTPROC_DUMP,
	    xdr_void, 0, xdr_mountlist, (char *)&ml, TIMEOUT) != RPC_SUCCESS) {
		clnt_perror(cl, "shutdown warning");
		return;
	}
	for (; ml != NULL; ml = ml->ml_next) {
		for (hl = hostlist; hl != NULL; hl = hl->nxt)
			if (strcmp(ml->ml_hostname, hl->host) == 0)
				goto again;
		hl = (struct hostlist *)malloc(sizeof (struct hostlist));
		hl->host = ml->ml_hostname;
		hl->nxt = hostlist;
		hostlist = hl;
	    again:;
	}
}

/*
 * Don't want to wait for usual portmapper timeout you get with
 * callrpc or clnt_call, so use rmtcall instead.  Use timeout
 * of 8 secs, based on the per try timeout of 3 secs for rmtcall
 */
int
callrpcfast(char *host, rpcprog_t prognum, rpcprog_t versnum,
    rpcprog_t procnum, xdrproc_t inproc, xdrproc_t outproc,
    char *in, char *out)
{
	struct sockaddr_in server_addr;
	struct hostent *hp;
	struct timeval rpctimeout;
	rpcport_t port;

	if ((hp = gethostbyname(host)) == NULL)
		return ((int)RPC_UNKNOWNHOST);
	bcopy(hp->h_addr, (char *)&server_addr.sin_addr, hp->h_length);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port =  0;
	rpctimeout.tv_sec = 8;
	rpctimeout.tv_usec = 0;
	return ((int)pmap_rmtcall(&server_addr, prognum, versnum, procnum,
	    inproc, in, outproc, out, rpctimeout, &port));
}
