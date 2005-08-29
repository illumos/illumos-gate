/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ntpdate - set the time of day by polling one or more NTP servers
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifndef SYS_WINNT
#include <netdb.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#endif /* SYS_WINNT */

#ifdef SYS_VXWORKS
#include "ioLib.h"
#include "sockLib.h"
#include "timers.h"
/* select wants a zero structure ... */
struct timeval tv0 = {0,0};
#endif


#if defined(SYS_HPUX)
#include <utmp.h>
#endif

#include "ntp_fp.h"
#include "ntp.h"
#include "ntp_io.h"
#include "ntp_unixtime.h"
#include "ntpdate.h"
#include "ntp_string.h"
#include "ntp_syslog.h"
#include "ntp_select.h"
#include "ntp_stdlib.h"

#ifdef SYS_WINNT
#define TARGET_RESOLUTION 1  /* Try for 1-millisecond accuracy
				on Windows NT timers. */
#endif /* SYS_WINNT */

/*
 * Scheduling priority we run at
 */
#ifndef SYS_VXWORKS
#define	NTPDATE_PRIO	(-12)
#else
#define	NTPDATE_PRIO	(100)
#endif

#if defined(HAVE_TIMER_SETTIME) || defined (HAVE_TIMER_CREATE)
/* POSIX TIMERS - vxWorks doesn't have itimer - casey */
static timer_t ntpdate_timerid;
#endif

/*
 * Compatibility stuff for Version 2
 */
#define NTP_MAXSKW	0x28f	/* 0.01 sec in fp format */
#define NTP_MINDIST	0x51f	/* 0.02 sec in fp format */
#define PEER_MAXDISP	(64*FP_SECOND)	/* maximum dispersion (fp 64) */
#define NTP_INFIN	15	/* max stratum, infinity a la Bellman-Ford */
#define NTP_MAXWGT	(8*FP_SECOND)	/* maximum select weight 8 seconds */
#define NTP_MAXLIST	5	/* maximum select list size */
#define PEER_SHIFT	8	/* 8 suitable for crystal time base */

/*
 * Debugging flag
 */
int debug = 0;

/*
 * File descriptor masks etc. for call to select
 */
int fd;
#ifdef HAVE_POLL_H
struct pollfd fdmask;
#else
fd_set fdmask;
#endif

/*
 * Initializing flag.  All async routines watch this and only do their
 * thing when it is clear.
 */
int initializing = 1;

/*
 * Alarm flag.	Set when an alarm occurs
 */
volatile int alarm_flag = 0;

/*
 * Simple query flag.
 */
int simple_query = 0;

/*
 * Unpriviledged port flag.
 */
int unpriv_port = 0;

/*
 * Time to spend measuring drift rate
 */
int rate = 0;

/*
 * Program name.
 */
char *progname;

/*
 * Systemwide parameters and flags
 */
int sys_samples = DEFSAMPLES;	/* number of samples/server */
u_long sys_timeout = DEFTIMEOUT; /* timeout time, in TIMER_HZ units */
struct server **sys_servers;	/* the server list */
int sys_numservers = 0;		/* number of servers to poll */
int sys_maxservers = 0;		/* max number of servers to deal with */
int sys_authenticate = 0;	/* true when authenticating */
u_int32 sys_authkey = 0;	/* set to authentication key in use */
u_long sys_authdelay = 0;	/* authentication delay */
int sys_version = NTP_VERSION;	/* version to poll with */

/*
 * The current internal time
 */
u_long current_time = 0;

/*
 * Counter for keeping track of completed servers
 */
int complete_servers = 0;

/*
 * File of encryption keys
 */

#ifndef KEYFILE
# ifndef SYS_WINNT
#  ifdef SYS_SOLARIS
#define	KEYFILE		"/etc/inet/ntp.keys"
#  else
#define	KEYFILE		"/etc/ntp.keys"
#  endif
# else
#define	KEYFILE		"%windir%\\ntp.keys"
# endif /* SYS_WINNT */
#endif /* KEYFILE */

#ifndef SYS_WINNT
const char *key_file = KEYFILE;
#else
char key_file_storage[MAX_PATH+1], *key_file ;
#endif	 /* SYS_WINNT */

/*
 * Miscellaneous flags
 */
extern	int syslogit;
int verbose = 0;
int always_step = 0;
int never_step = 0;

#ifndef SYS_WINNT
extern int errno;
#endif /* SYS_WINNT */

/*
 * Wait option used when ntpdate is to wait until clock synch.
 */
int wait_secs = 0;

#define WAIT_INITSEC	30	/* Initial seconds to wait */
#define WAIT_MAXSEC	300	/* Max seconds to wait before trying again */

/*
 * Multicast option used to auto synch in a NTP Multicast environment.
 */
char *mc_message = "";

#define MC_NONE		0
#define MC_ENABLED	1
#define MC_BROADCAST	2
#define MC_SENDTO	3
#define MC_JOIN		4
#define MC_LISTEN	5
#define MC_TIMEOUT	6

int multicast = MC_NONE;

u_long wait_time = 0;

static	void	transmit	P((struct server *));
static	void	receive		P((struct recvbuf *));
static	void	server_data	P((struct server *, s_fp, l_fp *, u_fp));
static	void	clock_filter	P((struct server *));
static	struct server *clock_select P((void));
static	int	clock_adjust	P((void));
static	void	addserver	P((char *));
static	struct server *findserver P((struct sockaddr_in *));
static	void	timer		P((void));
static	void	init_alarm	P((void));
#ifndef SYS_WINNT
static	RETSIGTYPE alarming	P((int));
#else
void  PASCAL alarming P((UINT, UINT,DWORD, DWORD, DWORD));
#endif /* SYS_WINNT */
static	void	init_io		P((void));
static	struct recvbuf *getrecvbufs P((void));
static	void	freerecvbuf	P((struct recvbuf *));
static	void	sendpkt		P((struct sockaddr_in *, struct pkt *, int));
static	void	input_handler	P((void));
static	void	re_init_servers	P((void));

static	int	l_adj_systime	P((l_fp *));
static	int	l_step_systime	P((l_fp *));

static	int	getnetnum	P((char *, u_int32 *));
static	void	printserver	P((struct server *, FILE *));
static	void	collect		P((void));

#ifdef SYS_WINNT
int on = 1;
WORD wVersionRequested;
WSADATA wsaData;
#endif /* SYS_WINNT */

#ifdef NO_MAIN_ALLOWED
void ntpdatemain P((int, char *[]));

void
CALL(ntpdate,"ntpdate",ntpdatemain);

void clear_globals()
{
  extern int ntp_optind;

  /*
   * Debugging flag
   */
  debug = 0;

  ntp_optind = 0;
  /*
   * Initializing flag.  All async routines watch this and only do their
   * thing when it is clear.
   */
  initializing = 1;

  /*
   * Alarm flag.  Set when an alarm occurs
   */
  alarm_flag = 0;

  /*
   * Simple query flag.
   */
  simple_query = 0;

  /*
   * Unpriviledged port flag.
   */
  unpriv_port = 0;

  /*
   * Time to spend measuring drift rate
   */
  rate = 0;
  /*
   * Systemwide parameters and flags
   */
  sys_numservers = 0;     /* number of servers to poll */
  sys_maxservers = 0;     /* max number of servers to deal with */
  sys_authenticate = 0;   /* true when authenticating */
  sys_authkey = 0;     /* set to authentication key in use */
  sys_authdelay = 0;   /* authentication delay */
  sys_version = NTP_VERSION;  /* version to poll with */

  /*
   * The current internal time
   */
  current_time = 0;

  /*
   * Counter for keeping track of completed servers
   */
  complete_servers = 0;
  verbose = 0;
  always_step = 0;
  never_step = 0;
}
#else
int main P((int, char *[]));
#endif

/*
 * Main program.  Initialize us and loop waiting for I/O and/or
 * timer expiries.
 */
#ifndef NO_MAIN_ALLOWED
int main
#else
void ntpdatemain
#endif /* NO_MAIN_ALLOWED */
(argc, argv)
     int argc;
     char *argv[];
{
  l_fp tmp;
  int errflg;
  int c;
  int cur_time, end_time;
  extern char *ntp_optarg;
  extern int ntp_optind;
  extern char *Version;
#ifdef SYS_WINNT
  HANDLE process_handle;

  wVersionRequested = MAKEWORD(1,1);
  if (WSAStartup(wVersionRequested, &wsaData)) {
    msyslog(LOG_ERR, "No useable winsock.dll: %m");
    exit(1);
  }

  key_file = key_file_storage;

  if (!ExpandEnvironmentStrings(KEYFILE, key_file, MAX_PATH))
    {
      msyslog(LOG_ERR, "ExpandEnvironmentStrings(KEYFILE) failed: %m\n");
    }
#endif /* SYS_WINNT */

#ifdef NO_MAIN_ALLOWED
  clear_globals();
#endif
  errflg = 0;
  progname = argv[0];
  syslogit = 0;

  /*
   * Decode argument list
   */
  while ((c = ntp_getopt(argc, argv, "a:bBde:k:mo:p:qr:st:uvw")) != -1)
    switch (c)
      {
      case 'a':
	c = atoi(ntp_optarg);
	sys_authenticate = 1;
	sys_authkey = c;
	break;
      case 'b':
	always_step++;
	never_step = 0;
	break;
      case 'B':
	never_step++;
	always_step = 0;
	break;
      case 'd':
	++debug;
	break;
      case 'e':
	if (!atolfp(ntp_optarg, &tmp)
	    || tmp.l_ui != 0) {
	  (void) fprintf(stderr,
			 "%s: encryption delay %s is unlikely\n",
			 progname, ntp_optarg);
	  errflg++;
	} else {
	  sys_authdelay = tmp.l_uf;
	}
	break;
      case 'k':
	key_file = ntp_optarg;
	break;
      case 'm':
	multicast = MC_ENABLED;
	break;
      case 'o':
	sys_version = atoi(ntp_optarg);
	break;
      case 'p':
	c = atoi(ntp_optarg);
	if (c <= 0 || c > NTP_SHIFT) {
	  (void) fprintf(stderr,
			 "%s: number of samples (%d) is invalid\n",
			 progname, c);
	  errflg++;
	} else {
	  sys_samples = c;
	}
	break;
      case 'q':
	simple_query = 1;
	break;
      case 'r':
	c = atoi(ntp_optarg);
	if (c <= 0 || c > (60 * 60)) {
	  (void) fprintf(stderr,
			 "%s: rate (%d) is invalid: 0 - %d\n",
			 progname, c, (60 * 60));
	  errflg++;
	} else {
	  rate = c;
	}
	break;
      case 's':
	syslogit = 1;
	break;
      case 't':
	if (!atolfp(ntp_optarg, &tmp)) {
	  (void) fprintf(stderr,
			 "%s: timeout %s is undecodeable\n",
			 progname, ntp_optarg);
	  errflg++;
	} else {
	  sys_timeout = ((LFPTOFP(&tmp) * TIMER_HZ)
			 + 0x8000) >> 16;
	  if (sys_timeout == 0)
	    sys_timeout = 1;
	}
	break;
      case 'v':
	verbose = 1;
	break;
      case 'u':
	unpriv_port = 1;
	break;
      case 'w':
	wait_secs = WAIT_INITSEC;
	break;
      case '?':
	++errflg;
	break;
      default:
	break;
      }
	
  if (multicast)
    sys_maxservers = 255;
  else
    sys_maxservers = argc - ntp_optind;

  if (errflg || sys_maxservers == 0) {
    (void) fprintf(stderr,
		   "usage: %s [-bBdqsv] [-a key#] [-e delay] [-k file] [-p samples] [-o version#] [-r rate] [-t timeo] server ...\n",
		   progname);
    exit(2);
  }

  sys_servers = (struct server **)
    emalloc(sys_maxservers * sizeof(struct server *));

  if (debug || simple_query) {
#ifdef HAVE_SETVBUF
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, BUFSIZ);
#else
    setlinebuf(stdout);
#endif
  }

  /*
   * Logging.  Open the syslog if we have to
   */
  if (syslogit) {
#if !defined (SYS_WINNT) && !defined (SYS_VXWORKS)
#ifndef	LOG_DAEMON
    openlog("ntpdate", LOG_PID);
#else

#ifndef	LOG_NTP
#define	LOG_NTP	LOG_DAEMON
#endif
    openlog("ntpdate", LOG_PID | LOG_NDELAY, LOG_NTP);
    if (debug)
      setlogmask(LOG_UPTO(LOG_DEBUG));
    else
      setlogmask(LOG_UPTO(LOG_INFO));
#endif	/* LOG_DAEMON */
#endif	/* SYS_WINNT */
  }

  if (debug || verbose)
    msyslog(LOG_NOTICE, "%s", Version);

  /*
   * Add servers we are going to be polling
   */
  for ( ; ntp_optind < argc; ntp_optind++)
    addserver(argv[ntp_optind]);

  if (sys_numservers == 0) {
    msyslog(LOG_ERR, "no servers can be used, exiting");
    exit(1);
  }

  if (multicast && sys_numservers > 1) {
    msyslog(LOG_ERR, "only 1 multicast addr can be used, exiting");
    exit(1);
  }

  /*
   * Initialize the time of day routines and the I/O subsystem
   */
  if (sys_authenticate) {
    init_auth();
    if (!authreadkeys(key_file)) {
      msyslog(LOG_ERR, "no key file, exitting");
      exit(1);
    }
    if (!authhavekey(sys_authkey)) {
      char buf[10];
      
      (void) sprintf(buf, "%lu", (unsigned long)sys_authkey);
      msyslog(LOG_ERR, "authentication key %s unknown", buf);
      exit(1);
    }
  }
  init_io();
  init_alarm();

  /*
   * Set the priority.
   */
#ifdef SYS_VXWORKS
  taskPrioritySet( taskIdSelf(), NTPDATE_PRIO);
#endif
#if defined(HAVE_ATT_NICE)
  nice (NTPDATE_PRIO);
#endif
#if defined(HAVE_BSD_NICE)
  (void) setpriority(PRIO_PROCESS, 0, NTPDATE_PRIO);
#endif
#ifdef SYS_WINNT
  process_handle = GetCurrentProcess();
  if (!SetPriorityClass(process_handle, (DWORD) REALTIME_PRIORITY_CLASS)) {
    msyslog(LOG_ERR, "SetPriorityClass failed: %m");
  }
#endif /* SYS_WINNT */

  initializing = 0;

  for (;;) {
    collect();
    /*
     * We've collect()ed all the data we want, so try to adjust the clock.
     */
    errflg = clock_adjust();
    if (errflg && multicast) {
      /*
       * Either no server answered our multicast broadcast request or none was
       * suitable, so last we try to join the multicast group with incremental
       * ttl's until either we receive a broadcast from a server we can use or
       * we have reached a max ttl and give up.
       */
      int ttl;
      struct ip_mreq mreq;

      msyslog(LOG_NOTICE, "no server suitable for synchronization found yet");

      sys_servers[0]->event_time = 0;

      mreq.imr_multiaddr.s_addr = htonl(INADDR_NTP);
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      for (ttl = 1; ttl <= 32; ttl <<= 1) {
	u_char n;

	msyslog(LOG_NOTICE,
		"trying ttl %d for multicast server synchronization", ttl);

	multicast = MC_JOIN;
	setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq,
		   sizeof(mreq));
	n = ttl;
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&n, sizeof(n));
	multicast = MC_LISTEN;
	wait_time = current_time + (60 * TIMER_HZ);
	collect();
	multicast = MC_TIMEOUT;
	setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq,
		   sizeof(mreq));
	if (ttl << 1 == 32)
	  mc_message = "";
	if (! (errflg = clock_adjust()))
	  break;

	msyslog(LOG_NOTICE,
		"no multicast server suitable for synchronization found");

      }
    }
    if (! errflg)
      break;
    if (! wait_secs)
      break;
    /*
     * Wait option specified, so we keep trying until we synch up but first we
     * go to sleep awhile before trying again. Use a an exponential backed off
     * value.
     */
    syslog(LOG_NOTICE, "waiting %d seconds before trying again", wait_secs);

    cur_time = time(NULL);
    end_time = cur_time + wait_secs;
    while ((cur_time = time(NULL)) < end_time)
      (void)poll(NULL, 0, (end_time - cur_time)  * 1000);

    if ((wait_secs <<= 1) > WAIT_MAXSEC)
      wait_secs = WAIT_MAXSEC;

    re_init_servers();
  }
  /*
   * That's all folks ... Just exit() with the clock_adjust() ret value.
   */
  if (errflg)
    msyslog(LOG_ERR, "no server suitable for synchronization found");
  exit(errflg);
}

void
collect() {
  int was_alarmed;
  struct recvbuf *rbuflist;
  struct recvbuf *rbuf;

  was_alarmed = 0;
  rbuflist = (struct recvbuf *)0;
  while (complete_servers < sys_numservers || wait_time > current_time) {
#ifdef HAVE_POLL_H
    struct pollfd rdfdes;
#else
    fd_set rdfdes;
#endif
    int nfound;

    if (alarm_flag) {		/* alarmed? */
      was_alarmed = 1;
      alarm_flag = 0;
    }
    rbuflist = getrecvbufs();	/* get received buffers */

    if (!was_alarmed && rbuflist == (struct recvbuf *)0) {
      /*
       * Nothing to do.	 Wait for something.
       */
      struct timeval timeout;

      timeout.tv_sec = 60;	/* Give up after 60 seconds */
      timeout.tv_usec = 0;
      rdfdes = fdmask;
#ifndef SYS_VXWORKS
#ifdef HAVE_POLL_H
      nfound = poll(&rdfdes, 1, timeout.tv_sec * 1000);
#else
      nfound = select(fd+1, &rdfdes, (fd_set *)0,
		      (fd_set *)0, &timeout);
#endif
#else
      nfound = select(fd+1, &rdfdes, (fd_set *)0,
		      (fd_set *)0, &tv0);
#endif
      if (nfound > 0)
	input_handler();
      else if (
#ifndef SYS_WINNT
	       nfound == -1
#else
	       nfound == SOCKET_ERROR
#endif /* SYS_WINNT */
	       ) {
#ifndef SYS_WINNT
	if (errno != EINTR)
#endif
#ifdef HAVE_POLL_H
	  msyslog(LOG_ERR, "poll() error: %m");
#else
	  msyslog(LOG_ERR, "select() error: %m");
#endif
      } else {
#ifndef SYS_VXWORKS
#ifdef HAVE_POLL_H
	msyslog(LOG_DEBUG, "poll(): nfound = %d, error: %m", nfound);
#else
	msyslog(LOG_DEBUG, "select(): nfound = %d, error: %m", nfound);
#endif
#endif
      }
      if (alarm_flag) {		/* alarmed? */
	was_alarmed = 1;
	alarm_flag = 0;
      }
      rbuflist = getrecvbufs();	/* get received buffers */
    }

    /*
     * Out here, signals are unblocked.	 Call receive
     * procedure for each incoming packet.
     */
    while (rbuflist != (struct recvbuf *)0) {
      rbuf = rbuflist;
      rbuflist = rbuf->next;
      receive(rbuf);
      freerecvbuf(rbuf);
    }

    /*
     * Call timer to process any timeouts
     */
    if (was_alarmed) {
      if (multicast == MC_BROADCAST) {
	/*
	 * First alarm after a sendto() to the multicast addr, so from now on
	 * only deal with those servers we've heard from (if any).
	 */
	multicast = MC_SENDTO;
      }
      timer();
      was_alarmed = 0;
    }

    /*
     * Go around again
     */
  }

  /*
   * When we get here we've completed the polling of all servers.
   * Adjust the clock, then exit.
   */
#ifdef SYS_WINNT
  WSACleanup();
#endif

#ifdef SYS_VXWORKS    
  close (fd);
  timer_delete(ntpdate_timerid);
  clock_adjust();
#else
# ifndef SYS_SOLARIS
  exit(clock_adjust());
# endif
#endif /* SYS_VXWORKS */
}


/*
 * transmit - transmit a packet to the given server, or mark it completed.
 *	      This is called by the timeout routine and by the receive
 *	      procedure.
 */
static void
transmit(server)
     register struct server *server;
{
  struct pkt xpkt;

  if (debug)
    printf("transmit(%s)\n", ntoa(&server->srcadr));

  if (server->filter_nextpt < server->xmtcnt) {
    l_fp ts;
    /*
     * Last message to this server timed out.  Shift
     * zeros into the filter.
     */
    L_CLR(&ts);
    server_data(server, 0, &ts, 0);
  }

  if ((int)server->filter_nextpt >= sys_samples) {
    /*
     * Got all the data we need.  Mark this guy
     * completed and return.
     */
    server->event_time = 0;
    complete_servers++;
    return;
  }

  /*
   * If we're here, send another message to the server.	 Fill in
   * the packet and let 'er rip.
   */
  xpkt.li_vn_mode = PKT_LI_VN_MODE(LEAP_NOTINSYNC,
				   sys_version, MODE_CLIENT);
  xpkt.stratum = STRATUM_TO_PKT(STRATUM_UNSPEC);
  xpkt.ppoll = NTP_MINPOLL;
  xpkt.precision = NTPDATE_PRECISION;
  xpkt.rootdelay = htonl(NTPDATE_DISTANCE);
  xpkt.rootdispersion = htonl(NTPDATE_DISP);
  xpkt.refid = htonl(NTPDATE_REFID);
  L_CLR(&xpkt.reftime);
  L_CLR(&xpkt.org);
  L_CLR(&xpkt.rec);

  /*
   * Determine whether to authenticate or not.	If so,
   * fill in the extended part of the packet and do it.
   * If not, just timestamp it and send it away.
   */
  if (sys_authenticate) {
    int len;

    xpkt.keyid = htonl(sys_authkey);
    auth1crypt(sys_authkey, (u_int32 *)&xpkt, LEN_PKT_NOMAC);
    get_systime(&server->xmt);
    L_ADDUF(&server->xmt, sys_authdelay);
    HTONL_FP(&server->xmt, &xpkt.xmt);
    len = auth2crypt(sys_authkey, (u_int32 *)&xpkt, LEN_PKT_NOMAC);
    sendpkt(&(server->srcadr), &xpkt, LEN_PKT_NOMAC + len);

    if (debug > 1)
      printf("transmit auth to %s\n",
	     ntoa(&(server->srcadr)));
  } else {
    get_systime(&(server->xmt));
    HTONL_FP(&server->xmt, &xpkt.xmt);
    sendpkt(&(server->srcadr), &xpkt, LEN_PKT_NOMAC);

    if (debug > 1)
      printf("transmit to %s\n", ntoa(&(server->srcadr)));
  }

  /*
   * Update the server timeout and transmit count
   */
  server->event_time = current_time + sys_timeout;
  server->xmtcnt++;
}


/*
 * receive - receive and process an incoming frame
 */
static void
receive(rbufp)
     struct recvbuf *rbufp;
{
  register struct pkt *rpkt;
  register struct server *server;
  register s_fp di;
  l_fp t10, t23, tmp;
  l_fp org;
  l_fp rec;
  l_fp ci;
  int has_mac;
  int is_authentic;

  if (debug)
    printf("receive(%s)\n", ntoa(&rbufp->srcadr));
  /*
   * Check to see if the packet basically looks like something
   * intended for us.
   */
  if (rbufp->recv_length == LEN_PKT_NOMAC)
    has_mac = 0;
  else if (rbufp->recv_length >= LEN_PKT_NOMAC)
    has_mac = 1;
  else {
    if (debug)
      printf("receive: packet length %d\n",
	     rbufp->recv_length);
    return;			/* funny length packet */
  }

  rpkt = &(rbufp->recv_pkt);
  if (PKT_VERSION(rpkt->li_vn_mode) < NTP_OLDVERSION ||
      PKT_VERSION(rpkt->li_vn_mode) > NTP_VERSION) {
    return;
  }

  if ((PKT_MODE(rpkt->li_vn_mode) != MODE_SERVER
       && PKT_MODE(rpkt->li_vn_mode) != MODE_PASSIVE
       && (!multicast || PKT_MODE(rpkt->li_vn_mode) != MODE_BROADCAST))
      || rpkt->stratum > NTP_MAXSTRATUM) {
    if (debug)
      printf("receive: mode %d stratum %d\n",
	     PKT_MODE(rpkt->li_vn_mode), rpkt->stratum);
    return;
  }
	
  /*
   * So far, so good.  See if this is from a server we know.
   */
  server = findserver(&(rbufp->srcadr));
  if (server == NULL) {
    if (debug)
      printf("receive: server not found\n");
    return;
  }

  /*
   * Decode the org timestamp and make sure we're getting a response
   * to our last request.
   */
  NTOHL_FP(&rpkt->org, &org);
  if (!L_ISEQU(&org, &server->xmt)) {
    if (debug)
      printf("receive: pkt.org and peer.xmt differ\n");
    return;
  }
	
  /*
   * Check out the authenticity if we're doing that.
   */
  if (!sys_authenticate)
    is_authentic = 1;
  else {
    is_authentic = 0;

    if (debug > 3)
      printf("receive: rpkt keyid=%ld sys_authkey=%ld decrypt=%ld\n",
	     (long int)ntohl(rpkt->keyid), (long int)sys_authkey, 
	     (long int)authdecrypt(sys_authkey, (u_int32 *)rpkt,
				   LEN_PKT_NOMAC));

    if (has_mac && ntohl(rpkt->keyid) == sys_authkey &&
	authdecrypt(sys_authkey, (u_int32 *)rpkt, LEN_PKT_NOMAC))
      is_authentic = 1;
    if (debug)
      printf("receive: authentication %s\n",
	     is_authentic ? "passed" : "failed");
  }
  server->trust <<= 1;
  if (!is_authentic)
    server->trust |= 1;
	
  /*
   * Looks good.  Record info from the packet.
   */
  server->leap = PKT_LEAP(rpkt->li_vn_mode);
  server->stratum = PKT_TO_STRATUM(rpkt->stratum);
  server->precision = rpkt->precision;
  server->rootdelay = ntohl(rpkt->rootdelay);
  server->rootdispersion = ntohl(rpkt->rootdispersion);
  server->refid = rpkt->refid;
  NTOHL_FP(&rpkt->reftime, &server->reftime);
  NTOHL_FP(&rpkt->rec, &rec);
  NTOHL_FP(&rpkt->xmt, &server->org);

  /*
   * Make sure the server is at least somewhat sane.  If not, try
   * again.
   */
  if (L_ISZERO(&rec) || !L_ISHIS(&server->org, &rec)) {
    transmit(server);
    return;
  }

  /*
   * Calculate the round trip delay (di) and the clock offset (ci).
   * We use the equations (reordered from those in the spec):
   *
   * d = (t2 - t3) - (t1 - t0)
   * c = ((t2 - t3) + (t1 - t0)) / 2
   */
  t10 = server->org;		/* pkt.xmt == t1 */
  L_SUB(&t10, &rbufp->recv_time);	/* recv_time == t0*/

  t23 = rec;			/* pkt.rec == t2 */
  L_SUB(&t23, &org);		/* pkt->org == t3 */

  /* now have (t2 - t3) and (t0 - t1).	Calculate (ci) and (di) */
/* 
 * Calculate (ci) = ((t1 - t0)/2)+((t2-t3)/2)
 * By pushing the division to earlier in the calculation
 * we prevent overflow in large offsets.
 */
  ci = t10;
  L_RSHIFT(&ci);
  tmp = t23;
  L_RSHIFT(&tmp);
  L_ADD(&ci, &tmp);

  /*
   * Calculate di in t23 in full precision, then truncate
   * to an s_fp.
   */
  L_SUB(&t23, &t10);
  di = LFPTOFP(&t23);

  if (debug > 3)
    printf("offset: %s, delay %s\n", lfptoa(&ci, 6), fptoa(di, 5));

  di += (FP_SECOND >> (-(int)NTPDATE_PRECISION))
    + (FP_SECOND >> (-(int)server->precision)) + NTP_MAXSKW;

  if (di <= 0) {		/* value still too raunchy to use? */
    L_CLR(&ci);
    di = 0;
  } else {
    di = max(di, NTP_MINDIST);
  }

  /*
   * Shift this data in, then transmit again.
   */
  server_data(server, (u_fp) di, &ci, 0);
  transmit(server);
}


/*
 * server_data - add a sample to the server's filter registers
 */
static void
server_data(server, d, c, e)
     register struct server *server;
     s_fp d;
     l_fp *c;
     u_fp e;
{
  register int i;

  i = server->filter_nextpt;
  if (i < NTP_SHIFT) {
    server->filter_delay[i] = d;
    server->filter_offset[i] = *c;
    server->filter_soffset[i] = LFPTOFP(c);
    server->filter_error[i] = e;
    server->filter_nextpt = i + 1;
  }
}


/*
 * clock_filter - determine a server's delay, dispersion and offset
 */
static void
clock_filter(server)
     register struct server *server;
{
  register int i, j;
  int ord[NTP_SHIFT];

  /*
   * Sort indices into increasing delay order
   */
  for (i = 0; i < sys_samples; i++)
    ord[i] = i;
	
  for (i = 0; i < (sys_samples-1); i++) {
    for (j = i+1; j < sys_samples; j++) {
      if (server->filter_delay[ord[j]] == 0)
	continue;
      if (server->filter_delay[ord[i]] == 0
	  || (server->filter_delay[ord[i]]
	      > server->filter_delay[ord[j]])) {
	register int tmp;

	tmp = ord[i];
	ord[i] = ord[j];
	ord[j] = tmp;
      }
    }
  }

  /*
   * Now compute the dispersion, and assign values to delay and
   * offset.  If there are no samples in the register, delay and
   * offset go to zero and dispersion is set to the maximum.
   */
  if (server->filter_delay[ord[0]] == 0) {
    server->delay = 0;
    L_CLR(&server->offset);
    server->soffset = 0;
    server->dispersion = PEER_MAXDISP;
  } else {
    register s_fp d;

    server->delay = server->filter_delay[ord[0]];
    server->offset = server->filter_offset[ord[0]];
    server->soffset = LFPTOFP(&server->offset);
    server->dispersion = 0;
    for (i = 1; i < sys_samples; i++) {
      if (server->filter_delay[ord[i]] == 0)
	d = PEER_MAXDISP;
      else {
	d = server->filter_soffset[ord[i]]
	  - server->filter_soffset[ord[0]];
	if (d < 0)
	  d = -d;
	if (d > PEER_MAXDISP)
	  d = PEER_MAXDISP;
      }
      /*
       * XXX This *knows* PEER_FILTER is 1/2
       */
      server->dispersion += (u_fp)(d) >> i;
    }
  }
  /*
   * We're done
   */
}


/*
 * clock_select - select the pick-of-the-litter clock from the samples
 *		  we've got.
 */
static struct server *
clock_select()
{
  register struct server *server;
  register int i;
  register int nlist;
  register s_fp d;
  register int j;
  register int n;
  s_fp local_threshold;
  struct server *server_list[NTP_MAXCLOCK];
  u_fp server_badness[NTP_MAXCLOCK];
  struct server *sys_server;

  /*
   * This first chunk of code is supposed to go through all
   * servers we know about to find the NTP_MAXLIST servers which
   * are most likely to succeed.  We run through the list
   * doing the sanity checks and trying to insert anyone who
   * looks okay.  We are at all times aware that we should
   * only keep samples from the top two strata and we only need
   * NTP_MAXLIST of them.
   */
  nlist = 0;	/* none yet */
  for (n = 0; n < sys_numservers; n++) {
    server = sys_servers[n];
    if (server->delay == 0)
      continue;	/* no data */
    if (server->stratum > NTP_INFIN)
      continue;	/* stratum no good */
    if (server->delay > NTP_MAXWGT) {
      continue;	/* too far away */
    }
    if (server->leap == LEAP_NOTINSYNC)
      continue;	/* he's in trouble */
    if (!L_ISHIS(&server->org, &server->reftime)) {
      continue;	/* very broken host */
    }
    if ((server->org.l_ui - server->reftime.l_ui)
	>= NTP_MAXAGE) {
      continue;	/* too long without sync */
    }
    if (server->trust != 0) {
      continue;
    }

    /*
     * This one seems sane.  Find where he belongs
     * on the list.
     */
    d = server->dispersion + server->dispersion;
    for (i = 0; i < nlist; i++)
      if (server->stratum <= server_list[i]->stratum)
	break;
    for ( ; i < nlist; i++) {
      if (server->stratum < server_list[i]->stratum)
	break;
      if (d < (s_fp) server_badness[i])
	break;
    }

    /*
     * If i points past the end of the list, this
     * guy is a loser, else stick him in.
     */
    if (i >= NTP_MAXLIST)
      continue;
    for (j = nlist; j > i; j--)
      if (j < NTP_MAXLIST) {
	server_list[j] = server_list[j-1];
	server_badness[j]
	  = server_badness[j-1];
      }

    server_list[i] = server;
    server_badness[i] = d;
    if (nlist < NTP_MAXLIST)
      nlist++;
  }

  /*
   * Got the five-or-less best.	 Cut the list where the number of
   * strata exceeds two.
   */
  j = 0;
  for (i = 1; i < nlist; i++)
    if (server_list[i]->stratum > server_list[i-1]->stratum)
      if (++j == 2) {
	nlist = i;
	break;
      }

  /*
   * Whew!  What we should have by now is 0 to 5 candidates for
   * the job of syncing us.  If we have none, we're out of luck.
   * If we have one, he's a winner.  If we have more, do falseticker
   * detection.
   */

  if (nlist == 0)
    sys_server = 0;
  else if (nlist == 1) {
    sys_server = server_list[0];
  } else {
    /*
     * Re-sort by stratum, bdelay estimate quality and
     * server.delay.
     */
    for (i = 0; i < nlist-1; i++)
      for (j = i+1; j < nlist; j++) {
	if (server_list[i]->stratum
	    < server_list[j]->stratum)
	  break;	/* already sorted by stratum */
	if (server_list[i]->delay
	    < server_list[j]->delay)
	  continue;
	server = server_list[i];
	server_list[i] = server_list[j];
	server_list[j] = server;
      }
		
    /*
     * Calculate the fixed part of the dispersion limit
     */
    local_threshold = (FP_SECOND >> (-(int)NTPDATE_PRECISION))
      + NTP_MAXSKW;

    /*
     * Now drop samples until we're down to one.
     */
    while (nlist > 1) {
      for (n = 0; n < nlist; n++) {
	server_badness[n] = 0;
	for (j = 0; j < nlist; j++) {
	  if (j == n)	/* with self? */
	    continue;
	  d = server_list[j]->soffset
	    - server_list[n]->soffset;
	  if (d < 0)	/* absolute value */
	    d = -d;
	  /*
	   * XXX This code *knows* that
	   * NTP_SELECT is 3/4
	   */
	  for (i = 0; i < j; i++)
	    d = (d>>1) + (d>>2);
	  server_badness[n] += d;
	}
      }

      /*
       * We now have an array of nlist badness
       * coefficients.	Find the badest.  Find
       * the minimum precision while we're at
       * it.
       */
      i = 0;
      n = server_list[0]->precision;;
      for (j = 1; j < nlist; j++) {
	if (server_badness[j] >= server_badness[i])
	  i = j;
	if (n > server_list[j]->precision)
	  n = server_list[j]->precision;
      }
			
      /*
       * i is the index of the server with the worst
       * dispersion.  If his dispersion is less than
       * the threshold, stop now, else delete him and
       * continue around again.
       */
      if ( (s_fp) server_badness[i] < (local_threshold
				       + (FP_SECOND >> (-n))))
	break;
      for (j = i + 1; j < nlist; j++)
	server_list[j-1] = server_list[j];
      nlist--;
    }

    /*
     * What remains is a list of less than 5 servers.  Take
     * the best.
     */
    sys_server = server_list[0];
  }

  /*
   * That's it.	 Return our server.
   */
  return sys_server;
}


/*
 * clock_adjust - process what we've received, and adjust the time
 *		 if we got anything decent.
 */
static int
clock_adjust()
{
  register int i;
  register struct server *server;
  s_fp absoffset;
  int dostep;

  for (i = 0; i < sys_numservers; i++)
    clock_filter(sys_servers[i]);
  server = clock_select();

  if (debug || simple_query) {
    for (i = 0; i < sys_numservers; i++)
      printserver(sys_servers[i], stdout);
  }

  if (server == 0) {
    return(1);
  }

  if (always_step) {
    dostep = 1;
  } else if (never_step) {
    dostep = 0;
  } else {
    dostep = ((server->soffset >= NTPDATE_THRESHOLD) ||
	(server->soffset <= -NTPDATE_THRESHOLD));
  }

  if (dostep) {
    if (simple_query || l_step_systime(&server->offset)) {
      msyslog(LOG_NOTICE, "step time server %s offset %s sec",
	      ntoa(&server->srcadr),
	      lfptoa(&server->offset, 6));
    }
  } else {
#ifndef SYS_WINNT
    if (simple_query || l_adj_systime(&server->offset)) {
      msyslog(LOG_NOTICE, "adjust time server %s offset %s sec",
	      ntoa(&server->srcadr),
	      lfptoa(&server->offset, 6));
    }
#else
    /* The NT SetSystemTimeAdjustment() call achieves slewing by 
     * changing the clock frequency. This means that we cannot specify
     * it to slew the clock by a definite amount and then stop like
     * the Unix adjtime() routine. We can technically adjust the clock
     * frequency, have ntpdate sleep for a while, and then wake 
     * up and reset the clock frequency, but this might cause some
     * grief if the user attempts to run xntpd immediately after
     * ntpdate and the socket is in use.
     */
    printf("\nThe -b option is required by ntpdate on Windows NT platforms\n");
    exit(1);
#endif /* SYS_WINNT */
  }
  return(0);
}


/* XXX ELIMINATE: merge BIG slew into adj_systime in lib/systime.c */
/*
 * addserver - determine a server's address and allocate a new structure
 *	       for it.
 */
static void
addserver(serv)
     char *serv;
{
  register struct server *server;
  u_int32 netnum;
  static int toomany = 0;

  if (sys_numservers >= sys_maxservers) {
    if (!toomany) {
      /*
       * This is actually a `can't happen' now.	 Leave
       * the error message in anyway, though
       */
      toomany = 1;
      msyslog(LOG_ERR,
	      "too many servers (> %d) specified, remainder not used",
	      sys_maxservers);
    }
    return;
  }

  if (!getnetnum(serv, &netnum)) {
    msyslog(LOG_ERR, "can't find host %s\n", serv);
    return;
  }

  server = (struct server *)emalloc(sizeof(struct server));
  memset((char *)server, 0, sizeof(struct server));

  server->srcadr.sin_family = AF_INET;
  server->srcadr.sin_addr.s_addr = netnum;
  server->srcadr.sin_port = htons(NTP_PORT);

  sys_servers[sys_numservers++] = server;
  server->event_time = sys_numservers;
}


/*
 * findserver - find a server in the list given its address
 */
static struct server *
findserver(addr)
     struct sockaddr_in *addr;
{
  register int i;
  register u_int32 netnum;

  if (htons(addr->sin_port) != NTP_PORT)
    return 0;
  netnum = addr->sin_addr.s_addr;

  for (i = 0; i < sys_numservers; i++) {
    if (netnum == sys_servers[i]->srcadr.sin_addr.s_addr)
      return sys_servers[i];
  }
  if (multicast == MC_ENABLED) {
    /*
     * First transmit was done to the muticast addr, so set
     * multicast state and mark the multicast addr as complete
     * so no additional transmit will be done to it.
     */
    multicast = MC_BROADCAST;
    sys_servers[0]->event_time = 0;
    complete_servers++;
  }
  if ((multicast == MC_BROADCAST || multicast == MC_LISTEN)
     && sys_numservers < sys_maxservers) {
    /*
     * We're awaiting replys to our sendto the multicast addr, so
     * just add this addr to the server list as if it was speced.
     */
    struct server *server;

    server = (struct server *)emalloc(sizeof(struct server));
    memset((char *)server, 0, sizeof(struct server));

    server->srcadr.sin_family = AF_INET;
    server->srcadr.sin_addr.s_addr = netnum;
    server->srcadr.sin_port = htons(NTP_PORT);

    sys_servers[sys_numservers++] = server;
    server->event_time = sys_numservers;
    return server;
  }
  return 0;
}


/*
 * timer - process a timer interrupt
 */
static void
timer()
{
  register int i;

  /*
   * Bump the current idea of the time
   */
  current_time++;

  if (debug) {
    static int ix = 0;
    char twirl[] = {'|', '/', '-', '\\', '|', '/', '-', '\\'};

    fprintf(stderr, "%c\b", twirl[ix]);
    if (++ix == sizeof (twirl))
      ix = 0;
  }

  /*
   * Search through the server list looking for guys
   * who's event timers have expired.  Give these to
   * the transmit routine.
   */
  for (i = 0; i < sys_numservers; i++) {
    if (sys_servers[i]->event_time != 0
	&& sys_servers[i]->event_time <= current_time)
      transmit(sys_servers[i]);
  }
}

/*
 * Need to initialize these counters so after a timeout a new set of requests
 * (ie: packets) will be transmitted to the servers.
 */
static void
re_init_servers()
{
  int i;

  for (i = 0; i < sys_numservers; i++) {
    sys_servers[i]->filter_nextpt = 0;
    sys_servers[i]->xmtcnt = 0;
    sys_servers[i]->event_time = current_time + sys_timeout;
  }
  complete_servers = 0;
}

/*
 * init_alarm - set up the timer interrupt
 */
static void
init_alarm()
{
#ifndef SYS_WINNT
#ifndef HAVE_TIMER_SETTIME
  struct itimerval itimer;
#else
  struct itimerspec ntpdate_itimer;
#endif
#else
  TIMECAPS tc;
  HANDLE hToken;
  TOKEN_PRIVILEGES tkp;
  UINT wTimerRes, wTimerID;
  DWORD dwUser = 0;
#endif /* SYS_WINNT */

  alarm_flag = 0;

#ifndef SYS_WINNT
#if defined(HAVE_TIMER_CREATE) && defined(HAVE_TIMER_SETTIME)
  alarm_flag = 0;
  /* this code was put in as setitimer() is non existant this us the 
   * POSIX "equivalents" setup - casey
   */
  /* ntpdate_timerid is global - so we can kill timer later */
  if (timer_create (CLOCK_REALTIME, NULL, &ntpdate_timerid) ==
#ifdef SYS_VXWORKS
      ERROR
#else
      -1
#endif
      )
    {
      fprintf (stderr, "init_alarm(): timer_create (...) FAILED\n");
      return;
    }

  /*  TIMER_HZ = (5)
   * Set up the alarm interrupt.  The first comes 1/(2*TIMER_HZ)
   * seconds from now and they continue on every 1/TIMER_HZ seconds.
   */
  (void) signal_no_reset(SIGALRM, alarming);
  ntpdate_itimer.it_interval.tv_sec = ntpdate_itimer.it_value.tv_sec = 0;
  ntpdate_itimer.it_interval.tv_nsec = 1000000000/TIMER_HZ;
  ntpdate_itimer.it_value.tv_nsec = 1000000000/(TIMER_HZ<<1);
  timer_settime(ntpdate_timerid, 0 /* !TIMER_ABSTIME */, &ntpdate_itimer, NULL);
#else
  /*
   * Set up the alarm interrupt.  The first comes 1/(2*TIMER_HZ)
   * seconds from now and they continue on every 1/TIMER_HZ seconds.
   */
  (void) signal_no_reset(SIGALRM, alarming);
  itimer.it_interval.tv_sec = itimer.it_value.tv_sec = 0;
  itimer.it_interval.tv_usec = 1000000/TIMER_HZ;
  itimer.it_value.tv_usec = 1000000/(TIMER_HZ<<1);
  setitimer(ITIMER_REAL, &itimer, (struct itimerval *)0);
#endif
#else	/* SYS_WINNT */
  _tzset();

  /* 
   * Get previleges needed for fiddling with the clock
   */

  /* get the current process token handle */
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    msyslog(LOG_ERR, "OpenProcessToken failed: %m");
    exit(1);
  }
  /* get the LUID for system-time privilege. */
  LookupPrivilegeValue(NULL, SE_SYSTEMTIME_NAME, &tkp.Privileges[0].Luid);
  tkp.PrivilegeCount = 1;  /* one privilege to set */
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  /* get set-time privilege for this process. */
  AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,(PTOKEN_PRIVILEGES) NULL, 0);
  /* cannot test return value of AdjustTokenPrivileges. */
  if (GetLastError() != ERROR_SUCCESS)
    msyslog(LOG_ERR, "AdjustTokenPrivileges failed: %m");

  /* 
   * Set up timer interrupts for every 2**EVENT_TIMEOUT seconds
   * Under Win/NT, expiry of timer interval leads to invocation
   * of a callback function (on a different thread) rather than
   * generating an alarm signal
   */

  /* determine max and min resolution supported */
  if(timeGetDevCaps(&tc, sizeof(TIMECAPS)) != TIMERR_NOERROR) {
    msyslog(LOG_ERR, "timeGetDevCaps failed: %m");
    exit(1);
  }
  wTimerRes = min(max(tc.wPeriodMin, TARGET_RESOLUTION), tc.wPeriodMax);
  /* establish the minimum timer resolution that we'll use */
  timeBeginPeriod(wTimerRes);

  /* start the timer event */
  wTimerID = timeSetEvent(
			  (UINT) (1000/TIMER_HZ),    /* Delay */
			  wTimerRes,		     /* Resolution */
			  (LPTIMECALLBACK) alarming, /* Callback function */
			  (DWORD) dwUser,	     /* User data */
			  TIME_PERIODIC);	     /* Event type (periodic) */
  if (wTimerID == 0) {
    msyslog(LOG_ERR, "timeSetEvent failed: %m");
    exit(1);
  }
#endif /* SYS_WINNT */
}


#ifndef SYS_WINNT
/*
 * alarming - record the occurance of an alarm interrupt
 */
static RETSIGTYPE
alarming(sig)
     int sig;
{
  alarm_flag++;
}
#else /* SYS_WINNT */
/*
 * alarming for WinNT - invoke the timer() routine
 */
void PASCAL alarming (UINT wTimerID, UINT msg,
		      DWORD dwUser, DWORD dw1, DWORD dw2)
{
  extern int debug;
  static int initializing2 = 1;
  extern int fd;
  HANDLE TimerThreadHandle;
  static DWORD threadID;
#ifdef DEBUG
  SYSTEMTIME st;
#endif

  if (initializing2) {
    TimerThreadHandle = GetCurrentThread();
    if (!SetThreadPriority(TimerThreadHandle, (DWORD) THREAD_PRIORITY_HIGHEST))
      msyslog(LOG_ERR, "SetThreadPriority: %m");
    threadID = GetCurrentThreadId();
    initializing2 = 0;
  }

#ifdef DEBUG
  if (debug > 3) {
    GetSystemTime(&st);
    printf("thread %u (timer callback): time %02u:%02u:%02u:%03u\n",
	   threadID, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fflush(stdout);
  }
#endif

  timer();

  UNREFERENCED_PARAMETER(dw1);
  UNREFERENCED_PARAMETER(dw2);
  UNREFERENCED_PARAMETER(dwUser);
  UNREFERENCED_PARAMETER(msg);
  UNREFERENCED_PARAMETER(wTimerID);
}
#endif /* SYS_WINNT */


/*
 * We do asynchronous input using the SIGIO facility.  A number of
 * recvbuf buffers are preallocated for input.	In the signal
 * handler we poll to see if the socket is ready and read the
 * packets from it into the recvbuf's along with a time stamp and
 * an indication of the source host and the interface it was received
 * through.  This allows us to get as accurate receive time stamps
 * as possible independent of other processing going on.
 *
 * We allocate a number of recvbufs equal to the number of servers
 * plus 2.  This should be plenty.
 */

/*
 * recvbuf lists
 */
struct recvbuf *freelist;	/* free buffers */
struct recvbuf *fulllist;	/* buffers with data */

int full_recvbufs;		/* number of full ones */
int free_recvbufs;


/*
 * init_io - initialize I/O data and open socket
 */
static void
init_io()
{
  register int i;
  register struct recvbuf *rb;

  /*
   * Init buffer free list and stat counters
   */
  rb = (struct recvbuf *)
    emalloc((sys_numservers + 2) * sizeof(struct recvbuf));
  freelist = 0;
  for (i = sys_numservers + 2; i > 0; i--) {
    rb->next = freelist;
    freelist = rb;
    rb++;
  }

  fulllist = 0;
  full_recvbufs = 0;
  free_recvbufs = sys_numservers + 2;

  /*
   * Open the socket
   */

  /* create a datagram (UDP) socket */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    msyslog(LOG_ERR, "socket() failed: %m");
    exit(1);
    /*NOTREACHED*/
  }

  /*
   * bind the socket to the NTP port
   */
  if (/*!debug &&*/ !simple_query && !unpriv_port) {
    struct sockaddr_in addr;

    memset((char *)&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NTP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
#ifndef SYS_WINNT
      if (errno == EADDRINUSE)
#else
	if (WSAGetLastError() == WSAEADDRINUSE)
#endif /* SYS_WINNT */
	  msyslog(LOG_ERR,
		  "the NTP socket is in use, exiting");
	else
	  msyslog(LOG_ERR, "bind() fails: %m");
      exit(1);
    }
  }

#ifdef HAVE_POLL_H
  fdmask.fd = fd;
  fdmask.events = POLLIN;
#else
  FD_ZERO(&fdmask);
  FD_SET(fd, &fdmask);
#endif

  /*
   * set non-blocking,
   */
#ifndef SYS_WINNT
#ifdef SYS_VXWORKS
  {
    int on = TRUE;

    if (ioctl(fd,FIONBIO, &on) == ERROR) {
      msyslog(LOG_ERR, "ioctl(FIONBIO) fails: %m");
      exit(1);
    }
  }
#else
#if defined(O_NONBLOCK)
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    msyslog(LOG_ERR, "fcntl(FNDELAY|FASYNC) fails: %m");
    exit(1);
    /*NOTREACHED*/
  }
#else /* O_NONBLOCK */
#if defined(FNDELAY)
  if (fcntl(fd, F_SETFL, FNDELAY) < 0) {
    msyslog(LOG_ERR, "fcntl(FNDELAY|FASYNC) fails: %m");
    exit(1);
    /*NOTREACHED*/
  }
#else /* FNDELAY */
# include "Bletch: Need non blocking I/O"
#endif /* FNDELAY */
#endif /* SYS_VXWORKS */
#endif /* O_NONBLOCK */
#else /* SYS_WINNT */
  if (ioctlsocket(fd, FIONBIO, (u_long *) &on) == SOCKET_ERROR) {
    msyslog(LOG_ERR, "ioctlsocket(FIONBIO) fails: %m");
    exit(1);
  }
#endif /* SYS_WINNT */
}


/* XXX ELIMINATE getrecvbufs (almost) identical to ntpdate.c, ntptrace.c, ntp_io.c */
/*
 * getrecvbufs - get receive buffers which have data in them
 *
 * ***N.B. must be called with SIGIO blocked***
 */
static struct recvbuf *
getrecvbufs()
{
  struct recvbuf *rb;

  if (full_recvbufs == 0) {
    return (struct recvbuf *)0;	/* nothing has arrived */
  }
	
  /*
   * Get the fulllist chain and mark it empty
   */
  rb = fulllist;
  fulllist = 0;
  full_recvbufs = 0;

  /*
   * Return the chain
   */
  return rb;
}


/* XXX ELIMINATE freerecvbuf (almost) identical to ntpdate.c, ntptrace.c, ntp_io.c */
/*
 * freerecvbuf - make a single recvbuf available for reuse
 */
static void
freerecvbuf(rb)
     struct recvbuf *rb;
{

  rb->next = freelist;
  freelist = rb;
  free_recvbufs++;
}


/*
 * sendpkt - send a packet to the specified destination
 */
static void
sendpkt(dest, pkt, len)
     struct sockaddr_in *dest;
     struct pkt *pkt;
     int len;
{
  int cc;

#ifdef SYS_WINNT
  DWORD err;
#endif /* SYS_WINNT */

  cc = sendto(fd, (char *)pkt, len, 0, (struct sockaddr *)dest,
	      sizeof(struct sockaddr_in));
#ifndef SYS_WINNT
  if (cc == -1) {
    if (errno != EWOULDBLOCK && errno != ENOBUFS)
      msyslog(LOG_ERR, "sendto(%s): %m", ntoa(dest));
  }
#else
  if (cc == SOCKET_ERROR) {
    err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAENOBUFS)
      msyslog(LOG_ERR, "sendto(%s): %m", ntoa(dest));
  }
#endif /* SYS_WINNT */
}


/*
 * input_handler - receive packets asynchronously
 */
static void
input_handler()
{
  register int n;
  register struct recvbuf *rb;
  struct timeval tvzero;
  socklen_t fromlen;
  l_fp ts;
#ifdef HAVE_POLL_H
  struct pollfd fds;
#else
  fd_set fds;
#endif

  /*
   * Do a poll to see if we have data
   */
  for (;;) {
    fds = fdmask;
    tvzero.tv_sec = tvzero.tv_usec = 0;
#ifdef HAVE_POLL_H
    n = poll(&fds, 1, tvzero.tv_sec * 1000);
#else
    n = select(fd+1, &fds, (fd_set *)0, (fd_set *)0, &tvzero);
#endif

    /*
     * If nothing to do, just return.  If an error occurred,
     * complain and return.  If we've got some, freeze a
     * timestamp.
     */
    if (n == 0)
      return;
    else if (n == -1) {
      if (errno != EINTR)
#ifdef HAVE_POLL_H
	msyslog(LOG_ERR, "poll() error: %m");
#else
	msyslog(LOG_ERR, "select() error: %m");
#endif
      return;
    }
    get_systime(&ts);

    /*
     * Get a buffer and read the frame.	 If we
     * haven't got a buffer, or this is received
     * on the wild card socket, just dump the packet.
     */
    if (initializing || free_recvbufs == 0) {
      char buf[100];

    if (debug)
      printf("input_handler: ignore packet (%d).\n", free_recvbufs);

#ifndef SYS_WINNT
      (void) read(fd, buf, sizeof buf);
#else
      /* NT's _read does not operate on nonblocking sockets
       * either recvfrom or ReadFile() has to be used here.
       * ReadFile is used in [xntpd]ntp_intres() and xntpdc,
       * just to be different use recvfrom() here
       */
      recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)0, NULL);
#endif /* SYS_WINNT */
      continue;
    }

    rb = freelist;
    freelist = rb->next;
    free_recvbufs--;

    fromlen = (socklen_t) sizeof(struct sockaddr_in);
    rb->recv_length = recvfrom(fd, (char *)&rb->recv_pkt,
			       sizeof(rb->recv_pkt), 0,
			       (struct sockaddr *)&rb->srcadr, &fromlen);
    if (rb->recv_length == -1) {
      rb->next = freelist;
      freelist = rb;
      free_recvbufs++;
      continue;
    }

    /*
     * Got one.	 Mark how and when it got here,
     * put it on the full list.
     */
    rb->recv_time = ts;
    rb->next = fulllist;
    fulllist = rb;
    full_recvbufs++;
  }
}


#ifndef SYS_WINNT
/*
 * adj_systime - do a big long slew of the system time
 */
static int
l_adj_systime(ts)
     l_fp *ts;
{
  struct timeval adjtv, oadjtv;
  int isneg = 0;
  l_fp offset;
#ifndef STEP_SLEW
  l_fp overshoot;
#endif

  /*
   * Take the absolute value of the offset
   */
  offset = *ts;
  if (L_ISNEG(&offset)) {
    isneg = 1;
    L_NEG(&offset);
  }

#ifndef STEP_SLEW
  /*
   * Calculate the overshoot.  XXX N.B. This code *knows*
   * ADJ_OVERSHOOT is 1/2.
   */
  overshoot = offset;
  L_RSHIFTU(&overshoot);
  if (overshoot.l_ui != 0 || (overshoot.l_uf > ADJ_MAXOVERSHOOT)) {
    overshoot.l_ui = 0;
    overshoot.l_uf = ADJ_MAXOVERSHOOT;
  }
  L_ADD(&offset, &overshoot);
#endif
  TSTOTV(&offset, &adjtv);

  if (isneg) {
    adjtv.tv_sec = -adjtv.tv_sec;
    adjtv.tv_usec = -adjtv.tv_usec;
  }

  if (adjtv.tv_usec != 0 && !debug) {
    if (adjtime(&adjtv, &oadjtv) < 0) {
      msyslog(LOG_ERR, "Can't adjust the time of day: %m");
      return 0;
    }
  }
  return 1;
}
#endif /* SYS_WINNT */


/*
 * This fuction is not the same as lib/systime step_systime!!!
 */
static int
l_step_systime(ts)
     l_fp *ts;
{
#ifdef SLEWALWAYS 
#ifdef STEP_SLEW
  l_fp ftmp;
  int isneg;
  int n;
  
  if (debug) return 1;
  /*
   * Take the absolute value of the offset
   */
  ftmp = *ts;
  if (L_ISNEG(&ftmp)) {
    L_NEG(&ftmp);
    isneg = 1;
  } else
    isneg = 0;

  if (ftmp.l_ui >= 3) {		/* Step it and slew - we might win */
    n = step_systime_real(ts);
    if (!n)
      return n;
    if (isneg) 
      ts->l_ui = ~0;
    else
      ts->l_ui = ~0;
  }
  /*
   * Just add adjustment into the current offset.  The update
   * routine will take care of bringing the system clock into
   * line.
   */
#endif
  if (debug)
    return 1;
#ifdef FORCE_NTPDATE_STEP
  return step_systime_real(ts);
#else
  l_adj_systime(ts);
  return 1;
#endif
#else /* SLEWALWAYS  */
  if (debug)
    return 1;
  return step_systime_real(ts);
#endif	/* SLEWALWAYS */
}

/*
 * getnetnum - given a host name, return its net number
 */
static int
getnetnum(host, num)
     char *host;
     u_int32 *num;
{
  struct hostent *hp;

  if (decodenetnum(host, num)) {
    return 1;
  } else if ((hp = gethostbyname(host)) != 0) {
    memmove((char *)num, hp->h_addr, sizeof(u_int32));
    return (1);
  }
  return (0);
}

/* XXX ELIMINATE printserver similar in ntptrace.c, ntpdate.c */
/*
 * printserver - print detail information for a server
 */
static void
printserver(pp, fp)
     register struct server *pp;
     FILE *fp;
{
  register int i;
  char junk[5];
  char *str;

  if (!debug) {
    (void) fprintf(fp, "server %s, stratum %d, offset %s, delay %s\n",
		   ntoa(&pp->srcadr), pp->stratum,
		   lfptoa(&pp->offset, 6), fptoa(pp->delay, 5));
    return;
  }

  (void) fprintf(fp, "server %s, port %d\n",
		 ntoa(&pp->srcadr), ntohs(pp->srcadr.sin_port));

  (void) fprintf(fp, "stratum %d, precision %d, leap %c%c, trust %03o\n",
		 pp->stratum, pp->precision,
		 pp->leap & 0x2 ? '1' : '0',
		 pp->leap & 0x1 ? '1' : '0',
		 pp->trust);
	
  if (pp->stratum == 1) {
    junk[4] = 0;
    memmove(junk, (char *)&pp->refid, 4);
    str = junk;
  } else {
    str = numtoa(pp->refid);
  }
  (void) fprintf(fp,
		 "refid [%s], delay %s, dispersion %s\n",
		 str, fptoa(pp->delay, 5),
		 ufptoa(pp->dispersion, 5));
  
  (void) fprintf(fp, "transmitted %d, in filter %d\n",
		 pp->xmtcnt, pp->filter_nextpt);

  (void) fprintf(fp, "reference time:	   %s\n",
		 prettydate(&pp->reftime));
  (void) fprintf(fp, "originate timestamp: %s\n",
		 prettydate(&pp->org));
  (void) fprintf(fp, "transmit timestamp:  %s\n",
		 prettydate(&pp->xmt));
	
  (void) fprintf(fp, "filter delay: ");
  for (i = 0; i < NTP_SHIFT; i++) {
    (void) fprintf(fp, " %-8.8s", fptoa(pp->filter_delay[i], 5));
    if (i == (NTP_SHIFT>>1)-1)
      (void) fprintf(fp, "\n		  ");
  }
  (void) fprintf(fp, "\n");
  
  (void) fprintf(fp, "filter offset:");
  for (i = 0; i < PEER_SHIFT; i++) {
    (void) fprintf(fp, " %-8.8s", lfptoa(&pp->filter_offset[i], 6));
    if (i == (PEER_SHIFT>>1)-1)
      (void) fprintf(fp, "\n		  ");
  }
  (void) fprintf(fp, "\n");
  
  (void) fprintf(fp, "delay %s, dispersion %s\n",
		 fptoa(pp->delay, 5), ufptoa(pp->dispersion, 5));
  
  (void) fprintf(fp, "offset %s\n\n",
		 lfptoa(&pp->offset, 6));
}

#if !defined(HAVE_VSPRINTF)
/*
 * This nugget for pre-tahoe 4.3bsd systems
 */
#if !defined(__STDC__) || !__STDC__
#define const
#endif

int
vsprintf(str, fmt, ap)
     char *str;
     const char *fmt;
     va_list ap;
{
  FILE f;
  int len;

  f._flag = _IOWRT+_IOSTRG;
  f._ptr = str;
  f._cnt = 32767;
  len = _doprnt(fmt, ap, &f);
  *f._ptr = 0;
  return (len);
}
#endif

#if 0
/* override function in library since SA_RESTART makes ALL syscalls restart */
#ifdef SA_RESTART
void
signal_no_reset(sig, func)
     int sig;
     void (*func)();
{
  int n;
  struct sigaction vec;

  vec.sa_handler = func;
  sigemptyset(&vec.sa_mask);
  vec.sa_flags = 0;

  while (1)
    {
      n = sigaction(sig, &vec, NULL);
      if (n == -1 && errno == EINTR)
	continue;
      break;
    }
  if (n == -1)
    {
      perror("sigaction");
      exit(1);
    }
}
#endif
#endif
