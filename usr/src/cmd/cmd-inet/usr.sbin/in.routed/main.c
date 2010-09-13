/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/main.c,v 1.14 2000/08/11 08:24:38 sheldonh Exp $
 * char copyright[] = "@(#) Copyright (c) 1983, 1988, 1993\n"
 * " The Regents of the University of California.  All rights reserved.\n";
 */

#include "defs.h"
#include "pathnames.h"
#include <signal.h>
#include <fcntl.h>
#include <sys/file.h>
#include <userdefs.h>
#include <sys/stat.h>

#define	IN_ROUTED_VERSION	"2.22"

int		stopint;
boolean_t	supplier;	/* supply or broadcast updates */
boolean_t	supplier_set;
/* -S option. _B_TRUE=treat all RIP speakers as default routers. */
boolean_t	save_space = _B_FALSE;

static boolean_t default_gateway;	/* _B_TRUE=advertise default */
static boolean_t background = _B_TRUE;
boolean_t	ridhosts;	/* _B_TRUE=reduce host routes */
boolean_t	mhome;		/* _B_TRUE=want multi-homed host route */
boolean_t	advertise_mhome;  /* _B_TRUE=must continue advertising it */
boolean_t	auth_ok = _B_TRUE; /* _B_TRUE=ignore auth if we don't care */
boolean_t	no_install;	/* _B_TRUE=don't install in kernel */

struct timeval epoch;		/* when started */
struct timeval clk;
static struct timeval prev_clk;
static int usec_fudge;
struct timeval now;		/* current idea of time */
/* If a route's rts_time is <= to now_stale, the route is stale. */
time_t	now_stale;
/* If a route's rts_time is <= to now_expire, the route is expired */
time_t	now_expire;
/* If a route's rts_time is <= to now_garbage, the route needs to be deleted */
time_t	now_garbage;

static struct timeval next_bcast;	/* next general broadcast */
struct timeval no_flash = {		/* inhibit flash update */
	EPOCH+SUPPLY_INTERVAL, 0
};

/* When now reaches this time, it's time to call sync_kern() */
static struct timeval sync_kern_timer;

static fd_set	fdbits;
static int	sock_max;
int		rip_sock = -1;	/* RIP socket */
boolean_t	rip_enabled;
static boolean_t	openlog_done;

/*
 * The interface to which rip_sock is currently pointing for
 * output.
 */
struct interface *rip_sock_interface;

int	rt_sock;			/* routing socket */


static  int open_rip_sock();
static void timevalsub(struct timeval *, struct timeval *, struct timeval *);
static void	sigalrm(int);
static void	sigterm(int);

int
main(int argc, char *argv[])
{
	int n, off;
	char *p, *q;
	const char *cp;
	struct timeval select_timeout, result;
	fd_set ibits;
	in_addr_t p_net, p_mask;
	struct parm parm;
	char *tracename = NULL;
	boolean_t vflag = _B_FALSE;
	boolean_t version = _B_FALSE;
	int sigerr = 0;
	FILE *pidfp;
	mode_t pidmode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); /* 0644 */

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)   /* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEXT"
#endif	/* ! TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Some shells are badly broken and send SIGHUP to backgrounded
	 * processes.
	 */
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		sigerr = errno;

	ftrace = stdout;

	if (gettimeofday(&clk, 0) == -1) {
		logbad(_B_FALSE, "gettimeofday: %s", rip_strerror(errno));
	}
	prev_clk = clk;
	epoch = clk;
	epoch.tv_sec -= EPOCH;
	now.tv_sec = EPOCH;
	now_stale = EPOCH - STALE_TIME;
	now_expire = EPOCH - EXPIRE_TIME;
	now_garbage = EPOCH - GARBAGE_TIME;
	select_timeout.tv_sec = 0;

	while ((n = getopt(argc, argv, "sSqdghmpAztVvnT:F:P:")) != -1) {
		switch (n) {
		case 'A':
			/*
			 * Ignore authentication if we do not care.
			 * Crazy as it is, that is what RFC 2453 requires.
			 */
			auth_ok = _B_FALSE;
			break;

		case 't':
			if (new_tracelevel < 2)
				new_tracelevel = 2;
			background = _B_FALSE;
			break;

		case 'd':	/* put in.routed in foreground */
			background = _B_FALSE;
			break;

		case 'F':		/* minimal routes for SLIP */
			n = FAKE_METRIC;
			p = strchr(optarg, ',');
			if (p != NULL) {
				n = (int)strtoul(p+1, &q, 0);
				if (*q == '\0' && p+1 != q &&
				    n <= HOPCNT_INFINITY-1 && n >= 1)
					*p = '\0';
			}
			if (!getnet(optarg, &p_net, &p_mask)) {
				if (p != NULL)
					*p = ',';
				msglog(gettext("bad network; \"-F %s\""),
				    optarg);
				break;
			}
			(void) memset(&parm, 0, sizeof (parm));
			parm.parm_net = p_net;
			parm.parm_mask = p_mask;
			parm.parm_d_metric = n;
			cp = insert_parm(&parm);
			if (cp != NULL)
				msglog(gettext("bad -F: %s"), cp);
			break;

		case 'g':
			(void) memset(&parm, 0, sizeof (parm));
			parm.parm_d_metric = 1;
			cp = insert_parm(&parm);
			if (cp != NULL)
				msglog(gettext("bad -g: %s"), cp);
			else
				default_gateway = _B_TRUE;
			break;

		case 'h':		/* suppress extra host routes */
			ridhosts = _B_TRUE;
			break;

		case 'm':		/* advertise host route */
			mhome = _B_TRUE;	/* on multi-homed hosts */
			break;

		case 'n':	/* No-install mode */
			no_install = _B_TRUE;
			break;

		case 'P':
			/* handle arbitrary parameters. */
			q = strdup(optarg);
			if (q == NULL)
				logbad(_B_FALSE, "strdup: %s",
				    rip_strerror(errno));
			cp = parse_parms(q, _B_FALSE);
			if (cp != NULL)
				msglog(gettext("%1$s in \"-P %2$s\""), cp,
				    optarg);
			free(q);
			break;

		case 'q':
			supplier = _B_FALSE;
			supplier_set = _B_TRUE;
			break;

		case 's':
			supplier = _B_TRUE;
			supplier_set = _B_TRUE;
			break;

		case 'S':	/* save-space option */
			save_space = _B_TRUE;
			break;

		case 'T':
			tracename = optarg;
			break;

		case 'V':
			/* display version */
			version = _B_TRUE;
			msglog(gettext("version " IN_ROUTED_VERSION));
			break;

		case 'v':
			/* display route changes to supplied logfile */
			new_tracelevel = 1;
			vflag = _B_TRUE;
			break;

		case 'z':	/* increase debug-level */
			new_tracelevel++;
			break;

		default:
			goto usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (tracename == NULL && argc >= 1) {
		tracename = *argv++;
		argc--;
	}
	if (tracename != NULL && tracename[0] == '\0')
		goto usage;
	if (vflag && tracename == NULL)
		goto usage;
	if (argc != 0) {
usage:
		(void) fprintf(stderr, gettext(
		    "usage: in.routed [-AdghmnqsStVvz] "
		    "[-T <tracefile>]\n"));
		(void) fprintf(stderr,
		    gettext("\t[-F <net>[/<mask>][,<metric>]] [-P <parms>]\n"));
		logbad(_B_FALSE, gettext("excess arguments"));
	}
	if (geteuid() != 0) {
		/*
		 * Regular users are allowed to run in.routed for the
		 * sole purpose of obtaining the version number.  In
		 * that case, exit(EXIT_SUCCESS) without complaining.
		 */
		if (version)
			exit(EXIT_SUCCESS);
		logbad(_B_FALSE, gettext("requires UID 0"));
	}

	if (default_gateway) {
		if (supplier_set && !supplier) {
			msglog(gettext("-g and -q are incompatible"));
		} else {
			supplier = _B_TRUE;
			supplier_set = _B_TRUE;
		}
	}

	if (signal(SIGALRM, sigalrm) == SIG_ERR)
		sigerr = errno;
	/* SIGHUP fatal during debugging */
	if (!background)
		if (signal(SIGHUP, sigterm) == SIG_ERR)
			sigerr = errno;
	if (signal(SIGTERM, sigterm) == SIG_ERR)
		sigerr = errno;
	if (signal(SIGINT, sigterm) == SIG_ERR)
		sigerr = errno;
	if (signal(SIGUSR1, sigtrace_more) == SIG_ERR)
		sigerr = errno;
	if (signal(SIGUSR2, sigtrace_less) == SIG_ERR)
		sigerr = errno;
	if (signal(SIGHUP, sigtrace_dump) == SIG_ERR)
		sigerr = errno;

	if (sigerr)
		msglog("signal: %s", rip_strerror(sigerr));

	/* get into the background */
	if (background && daemon(0, 0) < 0)
		BADERR(_B_FALSE, "daemon()");

	/* Store our process id, blow away any existing file if it exists. */
	if ((pidfp = fopen(PATH_PID, "w")) == NULL) {
		(void) fprintf(stderr,
		    gettext("in.routed: unable to open " PATH_PID ": %s\n"),
		    strerror(errno));
	} else {
		(void) fprintf(pidfp, "%ld\n", getpid());
		(void) fclose(pidfp);
		(void) chmod(PATH_PID, pidmode);
	}

	srandom((int)(clk.tv_sec ^ clk.tv_usec ^ getpid()));

	/* allocate the interface tables */
	iftbl_alloc();

	/* prepare socket connected to the kernel. */
	rt_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (rt_sock < 0)
		BADERR(_B_TRUE, "rt_sock = socket()");
	if (fcntl(rt_sock, F_SETFL, O_NONBLOCK) == -1)
		logbad(_B_TRUE, "fcntl(rt_sock) O_NONBLOCK: %s",
		    rip_strerror(errno));
	off = 0;
	if (setsockopt(rt_sock, SOL_SOCKET, SO_USELOOPBACK,
	    &off, sizeof (off)) < 0)
		LOGERR("setsockopt(SO_USELOOPBACK,0)");

	fix_select();


	if (tracename != NULL) {
		(void) strlcpy(inittracename, tracename,
		    sizeof (inittracename));
		set_tracefile(inittracename, "%s", -1);
	} else {
		tracelevel_msg("%s", -1);   /* turn on tracing to stdio */
	}

	bufinit();

	/* initialize radix tree */
	rtinit();

	/*
	 * Pick a random part of the second for our output to minimize
	 * collisions.
	 *
	 * Start broadcasting after hearing from other routers, and
	 * at a random time so a bunch of systems do not get synchronized
	 * after a power failure.
	 *
	 * Since now is the number of seconds since epoch (this is initially
	 * EPOCH seconds), these times are really relative to now.
	 */
	intvl_random(&next_bcast, EPOCH+MIN_WAITTIME, EPOCH+SUPPLY_INTERVAL);
	age_timer.tv_usec = next_bcast.tv_usec;
	age_timer.tv_sec = EPOCH+MIN_WAITTIME;
	rdisc_timer = next_bcast;
	ifscan_timer.tv_usec = next_bcast.tv_usec;

	/*
	 * Open the global rip socket.  From now on, this socket can be
	 * assumed to be open.  It will remain open until in.routed
	 * exits.
	 */
	rip_sock = open_rip_sock();

	/*
	 * Collect an initial view of the world by checking the interface
	 * configuration and the kludge file.
	 *
	 * gwkludge() could call addroutefordefault(), resulting in a call to
	 * iflookup, and thus ifscan() to find the physical interfaces.
	 * ifscan() will attempt to use the rip_sock in order to join
	 * mcast groups, so gwkludge *must* be called after opening
	 * the rip_sock.
	 */
	gwkludge();

	ifscan();

	/* Ask for routes */
	rip_query();
	rdisc_sol();

	/* Now turn off stdio if not tracing */
	if (new_tracelevel == 0)
		trace_close(background);

	/* Loop until a fatal error occurs, listening and broadcasting. */
	for (;;) {
		prev_clk = clk;
		if (gettimeofday(&clk, 0) == -1) {
			logbad(_B_FALSE, "gettimeofday: %s",
			    rip_strerror(errno));
		}
		if (prev_clk.tv_sec == clk.tv_sec &&
		    prev_clk.tv_usec == clk.tv_usec+usec_fudge) {
			/*
			 * Much of `in.routed` depends on time always advancing.
			 * On systems that do not guarantee that gettimeofday()
			 * produces unique timestamps even if called within
			 * a single tick, use trickery like that in classic
			 * BSD kernels.
			 */
			clk.tv_usec += ++usec_fudge;

		} else {
			time_t dt;

			usec_fudge = 0;

			timevalsub(&result, &clk, &prev_clk);
			if (result.tv_sec < 0 || result.tv_sec >
			    select_timeout.tv_sec + 5) {
				/*
				 * Deal with time changes before other
				 * housekeeping to keep everything straight.
				 */
				dt = result.tv_sec;
				if (dt > 0)
					dt -= select_timeout.tv_sec;
				trace_act("time changed by %d sec", (int)dt);
				epoch.tv_sec += dt;
			}
		}
		timevalsub(&now, &clk, &epoch);
		now_stale = now.tv_sec - STALE_TIME;
		now_expire = now.tv_sec - EXPIRE_TIME;
		now_garbage = now.tv_sec - GARBAGE_TIME;

		/* deal with signals that should affect tracing */
		set_tracelevel();

		if (stopint != 0) {
			trace_off("exiting with signal %d", stopint);
			break;
		}

		/* look for new or dead interfaces */
		timevalsub(&select_timeout, &ifscan_timer, &now);
		if (select_timeout.tv_sec <= 0) {
			select_timeout.tv_sec = 0;
			ifscan();
			rip_query();
			continue;
		}

		/*
		 * Check the kernel table occassionally for mysteriously
		 * evaporated routes
		 */
		timevalsub(&result, &sync_kern_timer, &now);
		if (result.tv_sec <= 0) {
			sync_kern();
			sync_kern_timer.tv_sec = (now.tv_sec
			    + CHECK_QUIET_INTERVAL);
			continue;
		}
		if (timercmp(&result, &select_timeout, < /* */))
			select_timeout = result;

		/* If it is time, then broadcast our routes. */
		if (should_supply(NULL) || advertise_mhome) {
			timevalsub(&result, &next_bcast, &now);
			if (result.tv_sec <= 0) {
				/*
				 * Synchronize the aging and broadcast
				 * timers to minimize awakenings
				 */
				age(0);
				age_peer_info();

				rip_bcast(0);

				/*
				 * It is desirable to send routing updates
				 * regularly.  So schedule the next update
				 * 30 seconds after the previous one was
				 * scheduled, instead of 30 seconds after
				 * the previous update was finished.
				 * Even if we just started after discovering
				 * a 2nd interface or were otherwise delayed,
				 * pick a 30-second aniversary of the
				 * original broadcast time.
				 */
				n = 1 + (0-result.tv_sec)/SUPPLY_INTERVAL;
				next_bcast.tv_sec += n*SUPPLY_INTERVAL;

				continue;
			}

			if (timercmp(&result, &select_timeout, < /* */))
				select_timeout = result;
		}

		/*
		 * If we need a flash update, either do it now or
		 * set the delay to end when it is time.
		 *
		 * If we are within MIN_WAITTIME seconds of a full update,
		 * do not bother.
		 */
		if (need_flash && should_supply(NULL) &&
		    no_flash.tv_sec+MIN_WAITTIME < next_bcast.tv_sec) {
			/* accurate to the millisecond */
			if (!timercmp(&no_flash, &now, > /* */))
				rip_bcast(1);
			timevalsub(&result, &no_flash, &now);
			if (timercmp(&result, &select_timeout, < /* */))
				select_timeout = result;
		}

		/* trigger the main aging timer. */
		timevalsub(&result, &age_timer, &now);
		if (result.tv_sec <= 0) {
			age(0);
			continue;
		}
		if (timercmp(&result, &select_timeout, < /* */))
			select_timeout = result;

		/* update the kernel routing table */
		timevalsub(&result, &need_kern, &now);
		if (result.tv_sec <= 0) {
			age(0);
			continue;
		}
		if (timercmp(&result, &select_timeout, < /* */))
			select_timeout = result;

		/*
		 * take care of router discovery.  We compare timeval
		 * structures here to have millisecond granularity.
		 */
		if (!timercmp(&rdisc_timer, &now, > /* */)) {
			rdisc_age(0);
			continue;
		}
		timevalsub(&result, &rdisc_timer, &now);
		if (timercmp(&result, &select_timeout, < /* */))
			select_timeout = result;

		/*
		 * Well-known bit of select(3c) silliness inherited
		 * from BSD: anything over 100 million seconds is
		 * considered an "error."  Reset that to zero.
		 */
		if (select_timeout.tv_sec > 100000000)
			select_timeout.tv_sec = 0;

		/* wait for input or a timer to expire. */
		trace_flush();
		ibits = fdbits;
		n = select(sock_max, &ibits, 0, 0, &select_timeout);
		if (n <= 0) {
			if (n < 0 && errno != EINTR && errno != EAGAIN)
				BADERR(_B_TRUE, "select");
			continue;
		}

		if (FD_ISSET(rt_sock, &ibits)) {
			read_rt();
			n--;
		}
		if (rdisc_sock >= 0 && FD_ISSET(rdisc_sock, &ibits)) {
			read_d();
			n--;
		}
		if (rdisc_mib_sock >= 0 && FD_ISSET(rdisc_mib_sock, &ibits)) {
			process_d_mib_sock();
			n--;
		}
		if (rip_sock >= 0 && FD_ISSET(rip_sock, &ibits)) {
			if (read_rip() == -1) {
				rip_enabled = _B_FALSE;
				trace_off("main rip socket failed");
				(void) close(rip_sock);
				rip_sock = -1;
				fix_select();
				break;
			}
			n--;
		}
	}
	rip_bcast(0);
	rdisc_adv(_B_FALSE);
	(void) unlink(PATH_PID);
	return (stopint | 128);
}


static void
sigalrm(int sig)
{
	/*
	 * Historically, SIGALRM would cause the daemon to check for
	 * new and broken interfaces.
	 */
	ifscan_timer.tv_sec = now.tv_sec;
	trace_act("SIGALRM");
	if (signal(sig, sigalrm) == SIG_ERR)
		msglog("signal: %s", rip_strerror(errno));
}


/* watch for fatal signals */
static void
sigterm(int sig)
{
	stopint = sig;
	if (signal(sig, SIG_DFL) == SIG_ERR)	/* catch it only once */
		msglog("signal: %s", rip_strerror(errno));
}


void
fix_select(void)
{
	(void) FD_ZERO(&fdbits);
	sock_max = 0;

	FD_SET(rt_sock, &fdbits);
	if (sock_max <= rt_sock)
		sock_max = rt_sock+1;
	if (rip_sock >= 0) {
		FD_SET(rip_sock, &fdbits);
		if (sock_max <= rip_sock)
			sock_max = rip_sock+1;
	}
	if (rdisc_sock >= 0) {
		FD_SET(rdisc_sock, &fdbits);
		if (sock_max <= rdisc_sock)
			sock_max = rdisc_sock+1;
		FD_SET(rdisc_mib_sock, &fdbits);
		if (sock_max <= rdisc_mib_sock)
			sock_max = rdisc_mib_sock+1;
	}
}


void
fix_sock(int sock,
    const char *name)
{
	int on;
#define	MIN_SOCKBUF (4*1024)
	static int rbuf;

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
		logbad(_B_TRUE, "fcntl(%s) O_NONBLOCK: %s", name,
		    rip_strerror(errno));
	on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof (on)) < 0)
		msglog("setsockopt(%s,SO_BROADCAST): %s",
		    name, rip_strerror(errno));

	if (rbuf >= MIN_SOCKBUF) {
		if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		    &rbuf, sizeof (rbuf)) < 0)
			msglog("setsockopt(%s,SO_RCVBUF=%d): %s",
			    name, rbuf, rip_strerror(errno));
	} else {
		for (rbuf = 60*1024; ; rbuf -= 4096) {
			if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			    &rbuf, sizeof (rbuf)) == 0) {
				trace_act("RCVBUF=%d", rbuf);
				break;
			}
			if (rbuf < MIN_SOCKBUF) {
				msglog("setsockopt(%s,SO_RCVBUF = %d): %s",
				    name, rbuf, rip_strerror(errno));
				break;
			}
		}
	}
}


/*
 * Open and return the global rip socket.  It is guaranteed to return
 * a good file descriptor.
 */
static int
open_rip_sock()
{
	struct sockaddr_in sin;
	unsigned char ttl;
	int s;
	int on = 1;


	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		BADERR(_B_TRUE, "rip_sock = socket()");

	(void) memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(RIP_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		BADERR(_B_FALSE, "bind(rip_sock)");
	}
	fix_sock(s, "rip_sock");

	ttl = 1;
	if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
	    &ttl, sizeof (ttl)) < 0)
		DBGERR(_B_TRUE, "rip_sock setsockopt(IP_MULTICAST_TTL)");

	if (setsockopt(s, IPPROTO_IP, IP_RECVIF, &on, sizeof (on)))
		BADERR(_B_FALSE, "setsockopt(IP_RECVIF)");

	return (s);
}


/*
 * Disable RIP.  Note that we don't close the global rip socket since
 * it is used even when RIP is disabled to receive and answer certain
 * queries.
 */
void
rip_off(void)
{
	struct ip_mreq m;
	struct interface *ifp;
	char addrstr[INET_ADDRSTRLEN];

	if (rip_enabled && !mhome) {
		trace_act("turn off RIP");

		/*
		 * Unsubscribe from the 224.0.0.9  RIP multicast
		 * group address
		 */
		for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
			if ((ifp->int_if_flags & IFF_MULTICAST) &&
			    !IS_IFF_QUIET(ifp->int_if_flags) &&
			    !IS_RIP_IN_OFF(ifp->int_state) &&
			    !(ifp->int_state & IS_DUP)) {
				m.imr_multiaddr.s_addr =
				    htonl(INADDR_RIP_GROUP);
				m.imr_interface.s_addr =
				    (ifp->int_if_flags & IFF_POINTOPOINT) ?
				    ifp->int_dstaddr : ifp->int_addr;
				(void) strlcpy(addrstr,
				    inet_ntoa(m.imr_multiaddr),
				    sizeof (addrstr));
				if (setsockopt(rip_sock, IPPROTO_IP,
				    IP_DROP_MEMBERSHIP, &m,
				    sizeof (m)) < 0 &&
				    errno != EADDRNOTAVAIL && errno != ENOENT)
					writelog(LOG_WARNING,
					    "%s: setsockopt(IP_DROP_MEMBERSHIP "
					    "%s, %s): %s", ifp->int_name,
					    addrstr, inet_ntoa(m.imr_interface),
					    rip_strerror(errno));
			}
		}
		rip_enabled = _B_FALSE;

		age(0);
	}
}


/* turn on RIP multicast input via an interface */
void
rip_mcast_on(struct interface *ifp)
{
	struct ip_mreq m;

	if (!IS_RIP_IN_OFF(ifp->int_state) &&
	    (ifp->int_if_flags & IFF_MULTICAST) &&
	    !IS_IFF_QUIET(ifp->int_if_flags) &&
	    !(ifp->int_state & IS_DUP)) {
		m.imr_multiaddr.s_addr = htonl(INADDR_RIP_GROUP);
		m.imr_interface.s_addr = (ifp->int_if_flags & IFF_POINTOPOINT) ?
		    ifp->int_dstaddr : ifp->int_addr;
		if ((setsockopt(rip_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    &m, sizeof (m)) < 0) && !(ifp->int_state & IS_BROKE))
			writelog(LOG_WARNING,
			    "Could not join 224.0.0.9 on interface %s: %s",
			    ifp->int_name, rip_strerror(errno));
	}
}

/* turn off RIP multicast input via an interface */
void
rip_mcast_off(struct interface *ifp)
{
	struct ip_mreq m;

	if ((ifp->int_if_flags & IFF_MULTICAST) &&
	    !IS_IFF_QUIET(ifp->int_if_flags) && rip_enabled) {
		m.imr_multiaddr.s_addr = htonl(INADDR_RIP_GROUP);
		m.imr_interface.s_addr = (ifp->int_if_flags & IFF_POINTOPOINT) ?
		    ifp->int_dstaddr : ifp->int_addr;
		if ((setsockopt(rip_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		    &m, sizeof (m)) < 0) && errno != EADDRNOTAVAIL &&
		    errno != ENOENT)
			writelog(LOG_WARNING,
			    "setsockopt(IP_DROP_MEMBERSHIP RIP) for %s: %s",
			    ifp->int_name, rip_strerror(errno));
	}
}

/* enable RIP */
void
rip_on(struct interface *ifp)
{
	/*
	 * If RIP is already enabled, only start receiving
	 * multicasts for this interface.
	 */
	if (rip_enabled) {
		if (ifp != NULL)
			rip_mcast_on(ifp);
		return;
	}

	/*
	 * If RIP is disabled and it makes sense to enable it, then enable
	 * it on all of the interfaces.  It makes sense if either router
	 * discovery is off, or if router discovery is on and at most one
	 * interface is doing RIP.
	 */
	if (rip_interfaces > 0 && (!rdisc_ok || rip_interfaces > 1)) {
		trace_act("turn on RIP");

		rip_enabled = _B_TRUE;
		rip_sock_interface = NULL;

		/* Do not advertise anything until we have heard something */
		if (next_bcast.tv_sec < now.tv_sec+MIN_WAITTIME)
			next_bcast.tv_sec = now.tv_sec+MIN_WAITTIME;

		for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
			ifp->int_query_time = NEVER;
			rip_mcast_on(ifp);
		}
		ifscan_timer.tv_sec = now.tv_sec;
	}

	fix_select();
}


/* die if malloc(3) fails */
void *
rtmalloc(size_t size,
    const char *msg)
{
	void *p = malloc(size);
	if (p == NULL)
		logbad(_B_TRUE, "malloc(%lu) failed in %s: %s", (ulong_t)size,
		    msg, rip_strerror(errno));
	return (p);
}


/* get a random instant in an interval */
void
intvl_random(struct timeval *tp,	/* put value here */
    ulong_t lo,			/* value is after this second */
    ulong_t hi)			/* and before this */
{
	tp->tv_sec = (time_t)(hi == lo ? lo : (lo + random() % ((hi - lo))));
	tp->tv_usec = random() % 1000000;
}


void
timevaladd(struct timeval *t1,
    struct timeval *t2)
{

	t1->tv_sec += t2->tv_sec;
	if ((t1->tv_usec += t2->tv_usec) >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}


/* t1 = t2 - t3 */
static void
timevalsub(struct timeval *t1,
    struct timeval *t2,
    struct timeval *t3)
{
	t1->tv_sec = t2->tv_sec - t3->tv_sec;
	if ((t1->tv_usec = t2->tv_usec - t3->tv_usec) < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
}

static void
do_openlog(void)
{
	openlog_done = _B_TRUE;
	openlog("in.routed", LOG_PID | LOG_ODELAY, LOG_DAEMON);
}

/* put a LOG_ERR message into the system log */
void
msglog(const char *p, ...)
{
	va_list args;

	trace_flush();

	if (!openlog_done)
		do_openlog();
	va_start(args, p);
	vsyslog(LOG_ERR, p, args);

	if (ftrace != 0) {
		if (ftrace == stdout)
			(void) fputs("in.routed: ", ftrace);
		(void) vfprintf(ftrace, p, args);
		(void) fputc('\n', ftrace);
	}
}


/*
 * Put a message about a bad system into the system log if
 * we have not complained about it recently.
 *
 * It is desirable to complain about all bad systems, but not too often.
 * In the worst case, it is not practical to keep track of all bad systems.
 * For example, there can be many systems with the wrong password.
 */
void
msglim(struct msg_limit *lim, in_addr_t addr, const char *p, ...)
{
	va_list args;
	int i;
	struct msg_sub *ms1, *ms;
	const char *p1;

	va_start(args, p);

	/*
	 * look for the oldest slot in the table
	 * or the slot for the bad router.
	 */
	ms = ms1 = lim->subs;
	for (i = MSG_SUBJECT_N; ; i--, ms1++) {
		if (i == 0) {
			/* Reuse a slot at most once every 10 minutes. */
			if (lim->reuse > now.tv_sec) {
				ms = NULL;
			} else {
				lim->reuse = now.tv_sec + 10*60;
			}
			break;
		}
		if (ms->addr == addr) {
			/*
			 * Repeat a complaint about a given system at
			 * most once an hour.
			 */
			if (ms->until > now.tv_sec)
				ms = NULL;
			break;
		}
		if (ms->until < ms1->until)
			ms = ms1;
	}
	if (ms != NULL) {
		ms->addr = addr;
		ms->until = now.tv_sec + 60*60;	/* 60 minutes */

		if (!openlog_done)
			do_openlog();
		trace_flush();
		for (p1 = p; *p1 == ' '; p1++)
			continue;
		vsyslog(LOG_ERR, p1, args);
	}

	/* always display the message if tracing */
	if (ftrace != 0) {
		(void) vfprintf(ftrace, p, args);
		(void) fputc('\n', ftrace);
	}
}


void
logbad(boolean_t dump, const char *p, ...)
{
	va_list args;

	trace_flush();

	if (!openlog_done)
		do_openlog();
	va_start(args, p);
	vsyslog(LOG_ERR, p, args);

	(void) fputs(gettext("in.routed: "), stderr);
	(void) vfprintf(stderr, p, args);
	(void) fputs(gettext("; giving up\n"), stderr);
	(void) fflush(stderr);

	if (dump)
		abort();
	exit(EXIT_FAILURE);
}

/* put a message into the system log */
void
writelog(int level, const char *p, ...)
{
	va_list args;

	trace_flush();

	if (!openlog_done)
		do_openlog();
	va_start(args, p);
	vsyslog(level, p, args);

	if (ftrace != 0) {
		if (ftrace == stdout)
			(void) fputs("in.routed: ", ftrace);
		(void) vfprintf(ftrace, p, args);
		(void) fputc('\n', ftrace);
	}
}
