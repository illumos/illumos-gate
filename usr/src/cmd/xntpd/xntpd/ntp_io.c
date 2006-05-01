/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * xntp_io.c - input/output routines for xntpd.  The socket-opening code
 *	       was shamelessly stolen from ntpd.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef SYS_SOLARIS
# define	FD_SETSIZE	65536
#include <stdio_ext.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H	/* UXPV: SIOC* #defines (Frank Vance <fvance@waii.com>) */
# include <sys/sockio.h>
#endif

#if	_BSDI_VERSION >= 199510
# include <ifaddrs.h>
#endif
#include "ntpd.h"
#include "ntp_select.h"
#include "ntp_io.h"
#include "ntp_refclock.h"
#include "ntp_if.h"
#include "ntp_stdlib.h"

#if defined (SYS_SOLARIS)
# include <sys/resource.h>
# define HAVE_RLIMIT
#endif

#if defined (SIOCGIFNUM) && defined (SYS_SOLARIS)
# include <assert.h>
#endif

#if defined(VMS)		/* most likely UCX-specific */

#include <UCX$INETDEF.H>

/* "un*x"-compatible names for some items in UCX$INETDEF.H */
#define ifreq		IFREQDEF
#define ifr_name	IFR$T_NAME
#define ifr_addr        IFR$R_DUMMY.IFR$T_ADDR
#define ifr_broadaddr   IFR$R_DUMMY.IFR$T_BROADADDR
#define ifr_flags       IFR$R_DUMMY.IFR$R_DUMMY_1_OVRL.IFR$W_FLAGS
#define IFF_UP		IFR$M_IFF_UP
#define IFF_BROADCAST	IFR$M_IFF_BROADCAST
#define IFF_LOOPBACK	IFR$M_IFF_LOOPBACK

/* structure used in SIOCGIFCONF request (after [KSR] OSF/1) */
struct ifconf {
  int ifc_len;			/* size of buffer */
  union {
    caddr_t ifcu_buf;
    struct ifreq *ifcu_req;
  } ifc_ifcu;
};
#define ifc_buf ifc_ifcu.ifcu_buf	/* buffer address */
#define ifc_req ifc_ifcu.ifcu_req	/* array of structures returned */

#endif /* VMS */

#if defined(USE_TTY_SIGPOLL) || defined(USE_UDP_SIGPOLL)
# if defined(SYS_AIX) && defined(_IO) /* XXX Identify AIX some other way */
#  undef _IO
# endif
# include <stropts.h>
#endif

/*
 * We do asynchronous input using the SIGIO facility.  A number of
 * recvbuf buffers are preallocated for input.  In the signal
 * handler we poll to see which sockets are ready and read the
 * packets from them into the recvbuf's along with a time stamp and
 * an indication of the source host and the interface it was received
 * through.  This allows us to get as accurate receive time stamps
 * as possible independent of other processing going on.
 *
 * We watch the number of recvbufs available to the signal handler
 * and allocate more when this number drops below the low water
 * mark.  If the signal handler should run out of buffers in the
 * interim it will drop incoming frames, the idea being that it is
 * better to drop a packet than to be inaccurate.
 */

/*
 * Block the interrupt, for critical sections.
 */
#if defined(HAVE_SIGNALED_IO)
static int sigio_block_count = 0;
# define BLOCKIO()   ((void) block_sigio())
# define UNBLOCKIO() ((void) unblock_sigio())
#else
# define BLOCKIO()
# define UNBLOCKIO()
#endif

/*
 * recvbuf memory management
 */
#define	RECV_INIT	10	/* 10 buffers initially */
#define	RECV_LOWAT	3	/* when we're down to three buffers get more */
#define	RECV_INC	5	/* get 5 more at a time */
#define	RECV_TOOMANY	30	/* this is way too many buffers */

/*
 * Memory allocation
 */
volatile u_long full_recvbufs;		/* number of recvbufs on fulllist */
volatile u_long free_recvbufs;		/* number of recvbufs on freelist */

static	struct recvbuf *volatile freelist;	/* free buffers */
static	struct recvbuf *volatile fulllist;	/* lifo buffers with data */
static	struct recvbuf *volatile beginlist;	/* fifo buffers with data */

u_long total_recvbufs;		/* total recvbufs currently in use */
u_long lowater_additions;	/* number of times we have added memory */

static	struct recvbuf initial_bufs[RECV_INIT];	/* initial allocation */


/*
 * Other statistics of possible interest
 */
volatile u_long packets_dropped;	/* total number of packets dropped on reception */
volatile u_long packets_ignored;	/* packets received on wild card interface */
volatile u_long packets_received;	/* total number of packets received */
u_long packets_sent;	/* total number of packets sent */
u_long packets_notsent;	/* total number of packets which couldn't be sent */

volatile u_long handler_calls;	/* number of calls to interrupt handler */
volatile u_long handler_pkts;	/* number of pkts received by handler */
u_long io_timereset;	/* time counters were reset */

/*
 * Interface stuff
 */
#define	MAXINTERFACES	192		/* much better for big gateways with IP/X.25 and more ... */
struct interface *any_interface;	/* pointer to default interface */
struct interface *loopback_interface;	/* point to loopback interface */
#define	DYN_IFLIST \
	(defined (SIOCGIFNUM) && !defined (STREAMS_TLI))
#if DYN_IFLIST && defined (DEBUG)
#define	DYN_IFL_ASSERT(WHAT)	assert(WHAT)
#else
#define	DYN_IFL_ASSERT(IGNORED)
#endif

#if DYN_IFLIST
static	struct interface *inter_list;
static	int ninter_alloc = 0;		/* # of if slots allocated */
#else
static	struct interface inter_list[MAXINTERFACES];
#endif
static	int ninterfaces;

#ifdef REFCLOCK
/*
 * Refclock stuff.  We keep a chain of structures with data concerning
 * the guys we are doing I/O for.
 */
static	struct refclockio *refio;
#endif /* REFCLOCK */

/*
 * File descriptor masks etc. for call to select
 */
fd_set activefds;
int maxactivefd;

/*
 * Imported from ntp_timer.c
 */
extern u_long current_time;

#ifndef SYS_WINNT
extern int errno;
#endif /* SYS_WINNT */
extern int debug;

static	int	create_sockets	P((u_int));
static	int	open_socket	P((struct sockaddr_in *, int, int));
static	void	close_socket	P((int));
static	void	close_file		P((int));
static	char *	fdbits		P((int, fd_set *));
#ifdef HAVE_SIGNALED_IO
static  int	init_clock_sig	P((struct refclockio *));
static  void	init_socket_sig P((int));
static  RETSIGTYPE sigio_handler P((int));
static  void	block_sigio	P((void));
static  void	unblock_sigio	P((void));
static  void	set_signal	P((void));
#endif /* HAVE_SIGNALED_IO */
#ifndef STREAMS_TLI
# ifndef SYS_WINNT
extern	char	*inet_ntoa	P((struct in_addr));
# endif /* SYS_WINNT */
#endif /* STREAMS_TLI */

#ifdef HAVE_RLIMIT
/*
 * Raise the fd limit to its maximum
 */
static void
max_fdlimit()
{
  struct rlimit r;

  r.rlim_cur = r.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_NOFILE, &r) == -1) {
    msyslog(LOG_ERR, "setrlimit(RLIMIT_NOFILE): %m");
    return;
  }
#ifdef SYS_SOLARIS
 enable_extended_FILE_stdio(-1, -1);
#endif
}
#endif

/*
 * init_io - initialize I/O data structures and call socket creation routine
 */
void
init_io()
{
  register int i;

#ifdef SYS_WINNT
  WORD wVersionRequested;
  WSADATA wsaData;
#endif /* SYS_WINNT */

  /*
   * Init buffer free list and stat counters
   */
  freelist = 0;
  for (i = 0; i < RECV_INIT; i++)
    {
      initial_bufs[i].next = (struct recvbuf *) freelist;
      freelist = &initial_bufs[i];
    }

  fulllist = 0;
  free_recvbufs = total_recvbufs = RECV_INIT;
  full_recvbufs = lowater_additions = 0;
  packets_dropped = packets_received = 0;
  packets_ignored = 0;
  packets_sent = packets_notsent = 0;
  handler_calls = handler_pkts = 0;
  io_timereset = 0;
  loopback_interface = 0;

#ifdef REFCLOCK
  refio = 0;
#endif

#if defined(HAVE_SIGNALED_IO)
  (void) set_signal();
#endif

#ifdef SYS_WINNT
  wVersionRequested = MAKEWORD(1,1);
  if (WSAStartup(wVersionRequested, &wsaData))
    {
      msyslog(LOG_ERR, "No useable winsock.dll: %m");
      exit(1);
    }
#endif /* SYS_WINNT */

#ifdef HAVE_RLIMIT
  /* Up the soft file descriptor limit to the system maximum */
  max_fdlimit();
#endif

  /*
   * Create the sockets
   */
  block_io_and_alarm();
  (void) create_sockets(htons(NTP_PORT));
  unblock_io_and_alarm();

#ifdef DEBUG
  if (debug)
    printf("init_io: maxactivefd %d\n", maxactivefd);
#endif
}

/*
 * create_sockets - create a socket for each interface plus a default
 *		    socket for when we don't know where to send
 */
static int
create_sockets(port)
     u_int port;
{
#if	_BSDI_VERSION >= 199510
  int i, j;
  struct ifaddrs *ifaddrs, *ifap;
  struct sockaddr_in resmask;
#if     _BSDI_VERSION < 199701 
  struct ifaddrs *lp;
  int num_if;
#endif
#else	/* _BSDI_VERSION >= 199510 */
# ifdef STREAMS_TLI
  struct strioctl	ioc;
# endif /* STREAMS_TLI */
# if DYN_IFLIST
  char	*buf;
  int	ifnum;
# else
  char	buf[MAXINTERFACES*sizeof(struct ifreq)];
# endif
  struct	ifconf	ifc;
  struct	ifreq	ifreq, *ifr;
  int n, i, j, vs, size;
  struct sockaddr_in resmask;
#endif	/* _BSDI_VERSION >= 199510 */

#ifdef DEBUG
  if (debug)
    printf("create_sockets(%d)\n", ntohs( (u_short) port));
#endif

  if ((vs = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    msyslog(LOG_ERR, "socket(AF_INET, SOCK_DGRAM): %m");
    exit(1);
  }

#if DYN_IFLIST
  if (ioctl(vs, SIOCGIFNUM, &ifnum) < 0 || ifnum <= 0) {
    msyslog(LOG_ERR, "get number of interfaces: %m");
    exit(1);
  }
  /*
   * One entry is later added to the table for each mcast net, and there
   * is a catch-all entry in inter_list[0].  So add a few extra entries
   * up front.  In the general case (one mcast net) later extension of
   * the table won't be necessary.
   */
  ninter_alloc = ifnum + 8;
#ifdef DEBUG
  if (debug > 2)
    printf("alloc inter_list[%d], %d bytes\n", ninter_alloc,
	sizeof (*inter_list) * ninter_alloc);
#endif
  if ((inter_list = malloc(sizeof (*inter_list) * ninter_alloc)) == NULL) {
    msyslog(LOG_ERR, "can't alloc interface table");
    exit (1);
  }
  memset(inter_list, 0, sizeof (*inter_list) * ninter_alloc);
#endif

  /*
   * create pseudo-interface with wildcard address
   */
  inter_list[0].sin.sin_family = AF_INET;
  inter_list[0].sin.sin_port = port;
  inter_list[0].sin.sin_addr.s_addr = htonl(INADDR_ANY);
  (void) strncpy(inter_list[0].name, "wildcard",
		 sizeof(inter_list[0].name));
  inter_list[0].mask.sin_addr.s_addr = htonl(~(u_int32)0);
  inter_list[0].received = 0;
  inter_list[0].sent = 0;
  inter_list[0].notsent = 0;
  inter_list[0].flags = INT_BROADCAST;
#if	_BSDI_VERSION >= 199510
#if     _BSDI_VERSION >= 199701 
   if (getifaddrs(&ifaddrs) < 0)
     {
       msyslog(LOG_ERR, "getifaddrs: %m");
       exit(1);
     }
   i = 1;
   for (ifap = ifaddrs; ifap != NULL; ifap = ifap->ifa_next)
#else
  if (getifaddrs(&ifaddrs, &num_if) < 0)
    {
      msyslog(LOG_ERR, "create_sockets: getifaddrs() failed: %m");
      exit(1);
    }

  i = 1;

  for (ifap = ifaddrs, lp = ifap + num_if; ifap < lp; ifap++)
#endif
    {
      struct sockaddr_in *sin;

      if (!ifap->ifa_addr)
	continue;
		
      if (ifap->ifa_addr->sa_family != AF_INET)
	continue;

      if ((ifap->ifa_flags & IFF_UP) == 0)
	continue;

      inter_list[i].flags = 0;
      if (ifap->ifa_flags & IFF_BROADCAST)
	inter_list[i].flags |= INT_BROADCAST;

      (void)strcpy(inter_list[i].name, ifap->ifa_name);

      sin = (struct sockaddr_in *)ifap->ifa_addr;
      inter_list[i].sin = *sin;
      inter_list[i].sin.sin_port = port;

      if (ifap->ifa_flags & IFF_LOOPBACK)
	{
	  inter_list[i].flags = INT_LOOPBACK;
	  if (loopback_interface == NULL
	      || ntohl(sin->sin_addr.s_addr) != 0x7f000001)
	    loopback_interface = &inter_list[i];
	}

      if (inter_list[i].flags & INT_BROADCAST)
	{
	  sin = (struct sockaddr_in *)ifap->ifa_broadaddr;
	  inter_list[i].bcast = *sin;
	  inter_list[i].bcast.sin_port = port;
	}

      if (ifap->ifa_flags & (IFF_LOOPBACK|IFF_POINTOPOINT))
	{
	  inter_list[i].mask.sin_addr.s_addr = 0xffffffff;
	}
      else
	{
	  sin = (struct sockaddr_in *)ifap->ifa_netmask;
	  inter_list[i].mask = *sin;
	}
      inter_list[i].mask.sin_family = AF_INET;
      inter_list[i].mask.sin_len = sizeof *sin;

      /*
       * look for an already existing source interface address.  If
       * the machine has multiple point to point interfaces, then
       * the local address may appear more than once.
       */
      for (j=0; j < i; j++)
	if (inter_list[j].sin.sin_addr.s_addr ==
	    inter_list[i].sin.sin_addr.s_addr)
	  {
	    if (inter_list[j].flags & INT_LOOPBACK)
	      inter_list[j] = inter_list[i];
	    break;
	  }
      if (j == i)
	i++;
    }
  free(ifaddrs);
#else	/* _BSDI_VERSION >= 199510 */

  i = 1;

  ifc.ifc_len = sizeof(buf);
# ifdef STREAMS_TLI
  ioc.ic_cmd = SIOCGIFCONF;
  ioc.ic_timout = 0;
  ioc.ic_dp = (caddr_t)buf;
  ioc.ic_len = sizeof(buf);
  if(ioctl(vs, I_STR, &ioc) < 0 ||
     ioc.ic_len < sizeof(struct ifreq))
    {
      msyslog(LOG_ERR, "create_sockets: ioctl(I_STR:SIOCGIFCONF) failed: %m - exiting");
      exit(1);
    }
#  ifdef SIZE_RETURNED_IN_BUFFER
  ifc.ifc_len = ioc.ic_len - sizeof(int);
  ifc.ifc_buf = buf + sizeof(int);
#  else /* not SIZE_RETURNED_IN_BUFFER */
  ifc.ifc_len = ioc.ic_len;
  ifc.ifc_buf = buf;
#  endif /* not SIZE_RETURNED_IN_BUFFER */

# else /* not STREAMS_TLI */
#  if DYN_IFLIST
  ifc.ifc_len = ifnum * sizeof (struct ifreq);
  if ((ifc.ifc_buf = malloc(ifc.ifc_len)) == NULL) {
    msyslog(LOG_ERR, "malloc ifreq buffer: %m");
    exit(1);
  }
#  else /* ! DYN_IFLIST */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
#  endif /* DYN_IFLIST */
#  ifndef SYS_WINNT
  if (ioctl(vs, SIOCGIFCONF, (char *)&ifc) < 0)
#  else
  if (get_winnt_interfaces(&ifc) < 0)
#  endif /* SYS_WINNT */
    {
      msyslog(LOG_ERR, "create_sockets: ioctl(SIOCGIFCONF) failed: %m - exiting");
      exit(1);
    }

# endif /* not STREAMS_TLI */

  for(n = ifc.ifc_len, ifr = ifc.ifc_req; n > 0;
      ifr = (struct ifreq *)((char *)ifr + size))
    {
      size = sizeof(*ifr);

# ifdef HAVE_SA_LEN_IN_STRUCT_SOCKADDR
      if (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_addr))
	size += ifr->ifr_addr.sa_len - sizeof(struct sockaddr);
# endif
      n -= size;
      if
# ifdef VMS /* VMS+UCX */
	  (((struct sockaddr *)&(ifr->ifr_addr))->sa_family != AF_INET)
# else
	  (ifr->ifr_addr.sa_family != AF_INET)
# endif /* VMS+UCX */
	  continue;
      ifreq = *ifr;
# ifndef SYS_WINNT /* no interface flags on NT */
#  ifdef STREAMS_TLI
      ioc.ic_cmd = SIOCGIFFLAGS;
      ioc.ic_timout = 0;
      ioc.ic_dp = (caddr_t)&ifreq;
      ioc.ic_len = sizeof(struct ifreq);
      if(ioctl(vs, I_STR, &ioc))
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(I_STR:SIOCGIFFLAGS) failed: %m");
	  continue;
	}
#  else /* not STREAMS_TLI */
      if (ioctl(vs, SIOCGIFFLAGS, (char *)&ifreq) < 0)
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(SIOCGIFFLAGS) failed: %m");
	  continue;
	}
#  endif /* not STREAMS_TLI */
      if ((ifreq.ifr_flags & IFF_UP) == 0)
	continue;
      inter_list[i].flags = 0;
      if (ifreq.ifr_flags & IFF_BROADCAST)
	inter_list[i].flags |= INT_BROADCAST;
# endif /* not SYS_WINNT */
# if !defined(SUN_3_3_STINKS)
      if (
#  if defined(IFF_LOCAL_LOOPBACK) /* defined(SYS_HPUX) && (SYS_HPUX < 8) */
	  (ifreq.ifr_flags & IFF_LOCAL_LOOPBACK)
#  elif defined(IFF_LOOPBACK)
	  (ifreq.ifr_flags & IFF_LOOPBACK)
#  else /* not IFF_LOCAL_LOOPBACK and not IFF_LOOPBACK */
	/* test against 127.0.0.1 (yuck!!) */
	  (inter_list[i].sin.sin_addr.s_addr == inet_addr("127.0.0.1"))
#  endif /* not IFF_LOCAL_LOOPBACK and not IFF_LOOPBACK */
	  )
	{
#  ifndef SYS_WINNT
	  inter_list[i].flags |= INT_LOOPBACK;
#  endif /* not SYS_WINNT */
	  if (loopback_interface == 0)
	    {
	      loopback_interface = &inter_list[i];
	    }
	}
# endif /* not SUN_3_3_STINKS */

#if 0
# ifndef SYS_WINNT
#  ifdef STREAMS_TLI
      ioc.ic_cmd = SIOCGIFADDR;
      ioc.ic_timout = 0;
      ioc.ic_dp = (caddr_t)&ifreq;
      ioc.ic_len = sizeof(struct ifreq);
      if (ioctl(vs, I_STR, &ioc))
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(I_STR:SIOCGIFADDR) failed: %m");
	  continue;
	}
#  else /* not STREAMS_TLI */
      if (ioctl(vs, SIOCGIFADDR, (char *)&ifreq) < 0)
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(SIOCGIFADDR) failed: %m");
	  continue;
	}
#  endif /* not STREAMS_TLI */
# endif /* not SYS_WINNT */
#endif /* 0 */

      (void)strncpy(inter_list[i].name, ifreq.ifr_name,
		    sizeof(inter_list[i].name));
      inter_list[i].sin = *(struct sockaddr_in *)&ifr->ifr_addr;
      inter_list[i].sin.sin_family = AF_INET;
      inter_list[i].sin.sin_port = port;

# if defined(SUN_3_3_STINKS)
      /*
       * Oh, barf!  I'm too disgusted to even explain this
       */
      if (SRCADR(&inter_list[i].sin) == 0x7f000001)
	{
	  inter_list[i].flags |= INT_LOOPBACK;
	  if (loopback_interface == 0)
	    loopback_interface = &inter_list[i];
	}
# endif /* SUN_3_3_STINKS */
# ifndef SYS_WINNT /* no interface flags on NT */
      if (inter_list[i].flags & INT_BROADCAST)
	{
#  ifdef STREAMS_TLI
	  ioc.ic_cmd = SIOCGIFBRDADDR;
	  ioc.ic_timout = 0;
	  ioc.ic_dp = (caddr_t)&ifreq;
	  ioc.ic_len = sizeof(struct ifreq);
	  if(ioctl(vs, I_STR, &ioc))
	    {
	      msyslog(LOG_ERR, "create_sockets: ioctl(I_STR:SIOCGIFBRDADDR) failed: %m");
	      exit(1);
	    }
#  else /* not STREAMS_TLI */
	  if (ioctl(vs, SIOCGIFBRDADDR, (char *)&ifreq) < 0)
	    {
	      msyslog(LOG_ERR, "create_sockets: ioctl(SIOCGIFBRDADDR) failed: %m");
	      exit(1);
	    }
#  endif /* not STREAMS_TLI */

#  ifndef ifr_broadaddr
	  inter_list[i].bcast =
	    *(struct sockaddr_in *)&ifreq.ifr_addr;
#  else
	  inter_list[i].bcast =
	    *(struct sockaddr_in *)&ifreq.ifr_broadaddr;
#  endif /* ifr_broadaddr */
	  inter_list[i].bcast.sin_family = AF_INET;
	  inter_list[i].bcast.sin_port = port;
	}

#  ifdef STREAMS_TLI
      ioc.ic_cmd = SIOCGIFNETMASK;
      ioc.ic_timout = 0;
      ioc.ic_dp = (caddr_t)&ifreq;
      ioc.ic_len = sizeof(struct ifreq);
      if(ioctl(vs, I_STR, &ioc))
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(I_STR:SIOCGIFNETMASK) failed: %m");
	  exit(1);
	}
#  else /* not STREAMS_TLI */
      if (ioctl(vs, SIOCGIFNETMASK, (char *)&ifreq) < 0)
	{
	  msyslog(LOG_ERR, "create_sockets: ioctl(SIOCGIFNETMASK) failed: %m");
	  exit(1);
	}
#  endif /* not STREAMS_TLI */
# endif /* not SYS_WINNT */
      inter_list[i].mask = *(struct sockaddr_in *)&ifreq.ifr_addr;

      /*
       * look for an already existing source interface address.  If
       * the machine has multiple point to point interfaces, then
       * the local address may appear more than once.
       */
      for (j=0; j < i; j++)
	if (inter_list[j].sin.sin_addr.s_addr ==
	    inter_list[i].sin.sin_addr.s_addr)
	  {
	    break;
	  }
      if (j == i)
	i++;
    }
  closesocket(vs);
#endif  /* _BSDI_VERSION >= 199510 */
  ninterfaces = i;
  DYN_IFL_ASSERT(ninterfaces <= ifnum + 1);
  maxactivefd = 0;
  FD_ZERO(&activefds);
			
  for (i = 0; i < ninterfaces; i++)
    {
      inter_list[i].fd =
	open_socket(&inter_list[i].sin,
		    inter_list[i].flags & INT_BROADCAST, 0);
    }

  /*
   * Now that we have opened all the sockets, turn off the reuse flag for
   * security.
   */
  for (i = 0; i < ninterfaces; i++)
    {
      int off = 0;

      if (setsockopt(inter_list[i].fd, SOL_SOCKET, SO_REUSEADDR,
		     (char *)&off, sizeof(off)))
	{
	  msyslog(LOG_ERR, "create_sockets: setsockopt(SO_REUSEADDR,off) failed: %m");
	}
    }

#if defined(MCAST)
  /*
   * enable possible multicast reception on the broadcast socket
   */
  inter_list[0].bcast.sin_addr.s_addr = htonl(INADDR_ANY);
  inter_list[0].bcast.sin_family = AF_INET;
  inter_list[0].bcast.sin_port = port;
#endif /* MCAST */

  /*
   * Blacklist all bound interface addresses
   */
  resmask.sin_addr.s_addr = ~ (u_int32)0;
  for (i = 1; i < ninterfaces; i++)
    hack_restrict(RESTRICT_FLAGS, &inter_list[i].sin, &resmask,
	     RESM_NTPONLY|RESM_INTERFACE, RES_IGNORE);

  any_interface = &inter_list[0];
#ifdef DEBUG
  if (debug > 2)
    {
      printf("create_sockets: ninterfaces=%d\n", ninterfaces);
      for (i = 0; i < ninterfaces; i++)
	{
	  printf("interface %d:  fd=%d,  bfd=%d,  name=%.8s,  flags=0x%x\n",
		 i,
		 inter_list[i].fd,
		 inter_list[i].bfd,
		 inter_list[i].name,
		 inter_list[i].flags);
	  /* Leave these as three printf calls. */
	  printf("              sin=%s",
		 inet_ntoa((inter_list[i].sin.sin_addr)));
	  if(inter_list[i].flags & INT_BROADCAST)
	    printf("  bcast=%s,",
		   inet_ntoa((inter_list[i].bcast.sin_addr)));
	  printf("  mask=%s\n",
		 inet_ntoa((inter_list[i].mask.sin_addr)));
	}
    }
#endif
#if DYN_IFLIST
  free(ifc.ifc_buf);
#endif
  return ninterfaces;
}


/*
 * io_setbclient - open the broadcast client sockets
 */
void
io_setbclient()
{
  int i;

  for (i = 1; i < ninterfaces; i++)
    {
      if (!(inter_list[i].flags & INT_BROADCAST))
	continue;
      if (inter_list[i].flags & INT_BCASTOPEN)
	continue;
#ifdef	SYS_SOLARIS
      inter_list[i].bcast.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
#ifdef OPEN_BCAST_SOCKET /* Was: !SYS_DOMAINOS && !SYS_LINUX */
      inter_list[i].bfd = open_socket(&inter_list[i].bcast, 0, 1);
      inter_list[i].flags |= INT_BCASTOPEN;
#endif
    }
}

/* Make sure there is at least N+1  elements in if list */
static void
extend_iflist(int n)
{
#if DYN_IFLIST
  if (n >= ninter_alloc) {
    int old_n = ninter_alloc;

    /*
     * Only called to add a few extra entries, so keep
     * the extensions fairly small.
     */
    ninter_alloc = n + 32;
# ifdef DEBUG
    if (debug > 2)
      printf("realloc inter_list[%d], %d bytes\n",
		ninter_alloc, sizeof (*inter_list) * ninter_alloc);
# endif
    inter_list = realloc(inter_list, ninter_alloc * sizeof (*inter_list));
    if (inter_list == NULL) {
      msyslog(LOG_ERR, "cannot extend interface table");
      exit (1);
    }
    /* Zero the part added */
    memset(inter_list + old_n, 0, sizeof (*inter_list) *
	(ninter_alloc - old_n));
  }
#endif /* DYN_IFLIST */
}

/*
 * io_multicast_add() - add multicast group address
 */
void
io_multicast_add(addr)
     u_int32 addr;
{
#ifdef MCAST
  struct ip_mreq mreq;
  int i = ninterfaces;	/* Use the next interface */
  u_int32 haddr = ntohl(addr);
  struct in_addr iaddr;
  int s;
  struct sockaddr_in *sinp;

  iaddr.s_addr = addr;

  if (!IN_CLASSD(haddr))
    {
      msyslog(LOG_ERR,
	     "cannot add multicast address %s as it is not class D",
	     inet_ntoa(iaddr));
      return;
    }

  DYN_IFL_ASSERT(inter_list != NULL);
  for (i = 0; i < ninterfaces; i++)
    {
      /* Already have this address */
      if (inter_list[i].sin.sin_addr.s_addr == addr) return;
      /* found a free slot */
      if (inter_list[i].sin.sin_addr.s_addr == 0 &&
	  inter_list[i].fd <= 0 && inter_list[i].bfd <= 0 &&
	  inter_list[i].flags == 0) break;
    }

  extend_iflist(i);

  sinp = &(inter_list[i].sin);

  memset((char *)&mreq, 0, sizeof(mreq));
  memset((char *)&inter_list[i], 0, sizeof inter_list[0]);
  sinp->sin_family = AF_INET;
  sinp->sin_addr = iaddr;
  sinp->sin_port = htons(123);

  s = open_socket(sinp, 0, 1);
  /* Try opening a socket for the specified class D address */
  /* This works under SunOS 4.x, but not OSF1 .. :-( */
  if (s < 0)
    {
      memset((char *)&inter_list[i], 0, sizeof inter_list[0]);
      i = 0;
      /* HACK ! -- stuff in an address */
      inter_list[i].bcast.sin_addr.s_addr = addr;
      msyslog(LOG_ERR, "...multicast address %s using wildcard socket",
	     inet_ntoa(iaddr));
    }
  else
    {
      inter_list[i].fd = s;
      inter_list[i].bfd = -1;
      (void) strncpy(inter_list[i].name, "multicast",
		     sizeof(inter_list[i].name));
      inter_list[i].mask.sin_addr.s_addr = htonl(~(u_int32)0);
    }

  /*
   * enable reception of multicast packets
   */
  mreq.imr_multiaddr = iaddr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(inter_list[i].fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		 (char *)&mreq, sizeof(mreq)) == -1)
    msyslog(LOG_ERR,
	   "setsockopt IP_ADD_MEMBERSHIP fails: %m for %x / %x (%s)",
	   mreq.imr_multiaddr, mreq.imr_interface.s_addr,
	   inet_ntoa(iaddr));
  inter_list[i].flags |= INT_MULTICAST;
  if (i >= ninterfaces) ninterfaces = i+1;	
#else /* MCAST */
  struct in_addr iaddr;

  iaddr.s_addr = addr;
  msyslog(LOG_ERR, "cannot add multicast address %s as no MCAST support",
	 inet_ntoa(iaddr));
#endif /* MCAST */
}

/*
 * io_unsetbclient - close the broadcast client sockets
 */
void
io_unsetbclient()
{
  int i;

  DYN_IFL_ASSERT(inter_list != NULL);
  for (i = 1; i < ninterfaces; i++)
    {
      if (!(inter_list[i].flags & INT_BCASTOPEN))
	continue;
      close_socket(inter_list[i].bfd);
      inter_list[i].bfd = -1;
      inter_list[i].flags &= ~INT_BCASTOPEN;
    }
}


/*
 * io_multicast_del() - delete multicast group address
 */
void
io_multicast_del(addr)
     u_int32 addr;
{
#ifdef MCAST
  int i;
  struct ip_mreq mreq;
  struct sockaddr_in sinaddr;

  DYN_IFL_ASSERT(inter_list != NULL);
  if (!IN_CLASSD(addr))
    {
      sinaddr.sin_addr.s_addr = addr;
      msyslog(LOG_ERR,
	     "invalid multicast address %s", ntoa(&sinaddr));
      return;
    }

  /*
   * Disable reception of multicast packets
   */
  mreq.imr_multiaddr.s_addr = addr;
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  for (i = 0; i < ninterfaces; i++)
    {
      if (!(inter_list[i].flags & INT_MULTICAST))
	continue;
      if (!(inter_list[i].fd < 0))
	continue;
      if (addr != inter_list[i].sin.sin_addr.s_addr)
	continue;
      if (i != 0)
	{
	  /* we have an explicit fd, so we can close it */
	  close_socket(inter_list[i].fd);
	  memset((char *)&inter_list[i], 0, sizeof inter_list[0]);
	  inter_list[i].fd = -1;
	  inter_list[i].bfd = -1;
	}
      else
	{
	  /* We are sharing "any address" port :-(  Don't close it! */
	  if (setsockopt(inter_list[i].fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
			 (char *)&mreq, sizeof(mreq)) == -1)
	    msyslog(LOG_ERR, "setsockopt IP_DROP_MEMBERSHIP fails: %m");
	  /* This is **WRONG** -- there may be others ! */
	  /* There should be a count of users ... */
	  inter_list[i].flags &= ~INT_MULTICAST;
	}
    }
#else /* not MCAST */
  msyslog(LOG_ERR, "this function requires multicast kernel");
#endif /* not MCAST */
}


/*
 * open_socket - open a socket, returning the file descriptor
 */
static int
open_socket(addr, flags, turn_off_reuse)
     struct sockaddr_in *addr;
     int flags;
     int turn_off_reuse;
{
  int fd;
  int on = 1, off = 0;

  /* create a datagram (UDP) socket */
  if (  (fd = socket(AF_INET, SOCK_DGRAM, 0)) 
#ifndef SYS_WINNT
		< 0
#else
		== INVALID_SOCKET
#endif /* SYS_WINNT */
	 )
    {
      msyslog(LOG_ERR, "socket(AF_INET, SOCK_DGRAM, 0) failed: %m");
      exit(1);
      /*NOTREACHED*/
    }

  /* set SO_REUSEADDR since we will be binding the same port
     number on each interface */
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		 (char *)&on, sizeof(on)))
    {
      msyslog(LOG_ERR, "setsockopt SO_REUSEADDR on fails: %m");
    }

  /*
   * bind the local address.
   */
  if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
      char buff[160];
      sprintf(buff,
	      "bind() fd %d, family %d, port %d, addr %08lx, in_classd=%d flags=%d fails: %%m",
	      fd, addr->sin_family, (int)ntohs(addr->sin_port),
	      (u_long)ntohl(addr->sin_addr.s_addr),
	      IN_CLASSD(ntohl(addr->sin_addr.s_addr)), flags);
      msyslog(LOG_ERR, buff);
      closesocket(fd);

      /*
       * soft fail if opening a class D address
       */
      if (IN_CLASSD(ntohl(addr->sin_addr.s_addr)))
	return -1;
      exit(1);
    }
#ifdef DEBUG
  if (debug)
    printf("bind() fd %d, family %d, port %d, addr %08lx, flags=%d\n",
	   fd,
	   addr->sin_family,
	   (int)ntohs(addr->sin_port),
	   (u_long)ntohl(addr->sin_addr.s_addr),
	   flags);
#endif
  if (fd > maxactivefd)
    maxactivefd = fd;
  FD_SET(fd, &activefds);

  /*
   * set non-blocking,
   */

#ifdef USE_FIONBIO
/* in vxWorks we use FIONBIO, but the others are defined for old systems, so
 * all hell breaks loose if we leave them defined 
 */
#undef O_NONBLOCK
#undef FNDELAY
#undef O_NDELAY
#endif

#if defined(O_NONBLOCK) /* POSIX */
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
    {
      msyslog(LOG_ERR, "fcntl(O_NONBLOCK) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#elif defined(FNDELAY)
  if (fcntl(fd, F_SETFL, FNDELAY) < 0)
    {
      msyslog(LOG_ERR, "fcntl(FNDELAY) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#elif defined(O_NDELAY) /* generally the same as FNDELAY */
  if (fcntl(fd, F_SETFL, O_NDELAY) < 0)
    {
      msyslog(LOG_ERR, "fcntl(O_NDELAY) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#elif defined(FIONBIO)
# if defined(VMS)
  if (ioctl(fd,FIONBIO,&1) < 0)
# elif defined(SYS_WINNT)
  if (ioctlsocket(fd,FIONBIO,(u_long *) &on) == SOCKET_ERROR)
# else
  if (ioctl(fd,FIONBIO,&on) < 0)
# endif
    {
      msyslog(LOG_ERR, "ioctl(FIONBIO) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#elif defined(FIOSNBIO)
  if (ioctl(fd,FIOSNBIO,&on) < 0)
    {
      msyslog(LOG_ERR, "ioctl(FIOSNBIO) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#else
#   include "Bletch: Need non blocking I/O!"
#endif

#ifdef HAVE_SIGNALED_IO
  init_socket_sig(fd);
#endif /* not HAVE_SIGNALED_IO */

  /*
   *  Turn off the SO_REUSEADDR socket option.  It apparently
   *  causes heartburn on systems with multicast IP installed.
   *  On normal systems it only gets looked at when the address
   *  is being bound anyway..
   */
  if (turn_off_reuse)
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (char *)&off, sizeof(off)))
      {
	msyslog(LOG_ERR, "setsockopt SO_REUSEADDR off fails: %m");
      }

#ifdef SO_BROADCAST
  /* if this interface can support broadcast, set SO_BROADCAST */
  if (flags & INT_BROADCAST)
    {
      if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
		     (char *)&on, sizeof(on)))
	{
	  msyslog(LOG_ERR, "setsockopt(SO_BROADCAST): %m");
	}
    }
#endif /* SO_BROADCAST */

#if !defined(SYS_WINNT) && !defined(VMS)
# ifdef DEBUG
  if (debug > 1)
    printf("flags for fd %d: 0%o\n", fd,
	   fcntl(fd, F_GETFL, 0));
# endif
#endif /* SYS_WINNT || VMS */

  return fd;
}


/*
 * close_socket - close a socket and remove from the activefd list
 */
static void
close_socket(fd)
     int fd;
{
  int i, newmax;

  (void) closesocket(fd);
  FD_CLR( (u_int) fd, &activefds);

  if (fd >= maxactivefd)
    {
      newmax = 0;
      for (i = 0; i < maxactivefd; i++)
	if (FD_ISSET(i, &activefds))
	  newmax = i;
      maxactivefd = newmax;
    }
}


/*
 * close_file - close a file and remove from the activefd list
 * added 1/31/1997 Greg Schueman for Windows NT portability
 */
static void
close_file(fd)
     int fd;
{
  int i, newmax;

  (void) close(fd);
  FD_CLR( (u_int) fd, &activefds);

  if (fd >= maxactivefd)
    {
      newmax = 0;
      for (i = 0; i < maxactivefd; i++)
	if (FD_ISSET(i, &activefds))
	  newmax = i;
      maxactivefd = newmax;
    }
}




/*
 * findbcastinter - find broadcast interface corresponding to address
 */
struct interface *
findbcastinter(addr)
     struct sockaddr_in *addr;
{
#ifdef SIOCGIFCONF
  register int i;
  register u_int32 netnum;

  DYN_IFL_ASSERT(inter_list != NULL);
  netnum = NSRCADR(addr);
  for (i = 1; i < ninterfaces; i++)
    {
      if (!(inter_list[i].flags & INT_BROADCAST))
	continue;
      if (NSRCADR(&inter_list[i].bcast) == netnum)
	return &inter_list[i];
      if ((NSRCADR(&inter_list[i].sin) & NSRCADR(&inter_list[i].mask))
	  == (netnum & NSRCADR(&inter_list[i].mask)))
	return &inter_list[i];
    }
#endif /* SIOCGIFCONF */
  return any_interface;
}


/* XXX ELIMINATE getrecvbufs (almost) identical to ntpdate.c, ntptrace.c, ntp_io.c */
/*
 * getrecvbufs - get receive buffers which have data in them
 *
 * ***N.B. must be called with SIGIO blocked***
 */
struct recvbuf *
getrecvbufs()
{
  struct recvbuf *rb;
  static struct timeval timelogged = {0, 0};
  struct timeval timenow;

#ifdef DEBUG
  if (debug > 4)
    printf("getrecvbufs: %ld handler interrupts, %ld frames\n",
	   handler_calls, handler_pkts);
#endif

  if (full_recvbufs == 0)
    {
#ifdef DEBUG
      if (debug > 4)
	printf("getrecvbufs called, no action here\n");
#endif
      return (struct recvbuf *)0;	/* nothing has arrived */
    }
	
  /*
   * Get the fulllist chain and mark it empty
   */
#ifdef DEBUG
  if (debug > 4)
    printf("getrecvbufs returning %ld buffers\n", full_recvbufs);
#endif
  rb = (struct recvbuf *) beginlist;
  fulllist = 0;
  full_recvbufs = 0;

  /*
   * Check to see if we're below the low water mark.
   */
  if (free_recvbufs <= RECV_LOWAT)
    {
      register struct recvbuf *buf;
      register int i;

      if (total_recvbufs >= RECV_TOOMANY)
	{
	  (void) gettimeofday(&timenow, NULL);
	  if (timenow.tv_sec > (timelogged.tv_sec + RECVBUF_LOG_INTERVAL))
	    {
	      msyslog(LOG_ERR, "NTP daemon is receiving more broadcast or"
		" multicast packets than expected: is network OK?");
	      (void) gettimeofday(&timelogged, NULL);
	    }
	}
      else
	{
	  buf = (struct recvbuf *)
	    emalloc(RECV_INC*sizeof(struct recvbuf));
	  for (i = 0; i < RECV_INC; i++)
	    {
	      buf->next = (struct recvbuf *) freelist;
	      freelist = buf;
	      buf++;
	    }

	  free_recvbufs += RECV_INC;
	  total_recvbufs += RECV_INC;
	  lowater_additions++;
	}
    }

  /*
   * Return the chain
   */
  return rb;
}


/* XXX ELIMINATE freerecvbuf (almost) identical to ntpdate.c, ntptrace.c, ntp_io.c */
/*
 * freerecvbuf - make a single recvbuf available for reuse
 */
void
freerecvbuf(rb)
     struct recvbuf *rb;
{
  BLOCKIO();
  rb->next = (struct recvbuf *) freelist;
  freelist = rb;
  free_recvbufs++;
  UNBLOCKIO();
}


/* XXX ELIMINATE sendpkt similar in ntpq.c, ntpdc.c, ntp_io.c, ntptrace.c */
/*
 * sendpkt - send a packet to the specified destination. Maintain a
 * send error cache so that only the first consecutive error for a
 * destination is logged.
 */
void
sendpkt(dest, inter, ttl, pkt, len)
     struct sockaddr_in *dest;
     struct interface *inter;
     int ttl;
     struct pkt *pkt;
     int len;
{
  int cc, slot;
#ifdef SYS_WINNT
  DWORD err;
#endif /* SYS_WINNT */

  /*
   * Send error cache. Empty slots have port == 0
   * Set ERRORCACHESIZE to 0 to disable
   */
  struct cache {
    u_short	port;
    struct	in_addr addr;
  };

#ifndef ERRORCACHESIZE
#define ERRORCACHESIZE 8
#endif
#if ERRORCACHESIZE > 0
  static struct cache badaddrs[ERRORCACHESIZE];
#else
#define badaddrs ((struct cache *)0)		/* Only used in empty loops! */
#endif

#ifdef DEBUG
  if (debug)
    printf("%ssendpkt(fd=%d %s, %s, ttl=%d, %d)\n",
	   (ttl >= 0) ? "\tMCAST\t*****" : "",
	   inter->fd, ntoa(dest),
	   ntoa(&inter->sin), ttl, len);
#endif

#ifdef MCAST
  /* for the moment we use the bcast option to set multicast ttl */
  if (ttl >= 0 && ttl != inter->last_ttl)
    {
      char mttl = ttl;

      /* set the multicast ttl for outgoing packets */
      if (setsockopt(inter->fd, IPPROTO_IP, IP_MULTICAST_TTL,
		     &mttl, sizeof(mttl)) == -1)
	{
	  msyslog(LOG_ERR, "setsockopt IP_MULTICAST_TTL fails: %m");
	}
      else inter->last_ttl = ttl;
    }
#endif /* MCAST */

  for (slot = ERRORCACHESIZE; --slot >= 0; )
    if (badaddrs[slot].port == dest->sin_port &&
	badaddrs[slot].addr.s_addr == dest->sin_addr.s_addr)
      break;

  cc = sendto(inter->fd, (char *)pkt, len, 0, (struct sockaddr *)dest,
	      sizeof(struct sockaddr_in));
  if (cc == -1)
    {
      inter->notsent++;
      packets_notsent++;
#ifndef SYS_WINNT
      if (errno != EWOULDBLOCK && errno != ENOBUFS && slot < 0)
#else
      err = WSAGetLastError();
      if (err != WSAEWOULDBLOCK && err != WSAENOBUFS && slot < 0)
#endif /* SYS_WINNT */
	{
	  /*
	   * Remember this, if there's an empty slot
	   */
	  for (slot = ERRORCACHESIZE; --slot >= 0; )
	    if (badaddrs[slot].port == 0)
	      {
		badaddrs[slot].port = dest->sin_port;
		badaddrs[slot].addr = dest->sin_addr;
		break;
	      }
	  msyslog(LOG_ERR, "sendto(%s): %m", ntoa(dest));
	}
    }
  else
    {
      inter->sent++;
      packets_sent++;
      /*
       * He's not bad any more
       */
      if (slot >= 0)
	{
	  msyslog(LOG_INFO, "Connection re-established to %s", ntoa(dest));
	  badaddrs[slot].port = 0;
	}
    }
}

/*
 * fdbits - generate ascii representation of fd_set (FAU debug support)
 * HFDF format - highest fd first.
 */
static char *
fdbits(count, set)
      int count;
      fd_set *set;
{
  static char *buffer = NULL;
  static int buflen = 0;
  char *buf;

  if (count + 1 >= buflen) {
    buflen = count + 2;

    if ((buffer = realloc(buffer, buflen)) == NULL) {
      msyslog(LOG_ERR, "can't alloc fdbits debug data");
      exit (1);
    }
  }

  buf = buffer;
  while (count >= 0)
    {
      *buf++ = FD_ISSET(count, set) ? '#' : '-';
      count--;
    }
  *buf = '\0';

  return buffer;
}


/*
 * input_handler - receive packets asynchronously
 */
void
input_handler(cts)
     l_fp *cts;
{
  register int i, n;
  register struct recvbuf *rb;
  register int doing;
  register int fd;
  struct timeval tvzero;
  socklen_t fromlen;
  l_fp ts;			/* Timestamp at BOselect() gob */
  l_fp ts_e;			/* Timestamp at EOselect() gob */
  fd_set fds;
  int select_count = 0;
#if 0
  int first = 1;
#endif
  static int handler_count = 0;

  ++handler_count;
  if (handler_count != 1)
    msyslog(LOG_ERR, "input_handler: handler_count is %d!", handler_count);
  handler_calls++;
  ts = *cts;

  for (;;)
    {
      /*
       * Do a poll to see who has data
       */

      fds = activefds;
      tvzero.tv_sec = tvzero.tv_usec = 0;
      
      /*
       * If we have something to do, freeze a timestamp.
       * See below for the other cases (nothing (left) to do or error)
       */
      while (0 < (n = select(maxactivefd+1, &fds, (fd_set *)0, (fd_set *)0, &tvzero)))
	{
#if 0
	  if (!first) get_systime(&ts);
	  first = 0;
#endif
	  ++select_count;
#if 1
	  ++handler_pkts;
#else
	  handler_pkts += n;
#endif

	  DYN_IFL_ASSERT(inter_list != NULL);
#ifdef REFCLOCK
	  /*
	   * Check out the reference clocks first, if any
	   */
	  if (refio != 0)
	    {
	      register struct refclockio *rp;

	      for (rp = refio; rp != 0 && n > 0; rp = rp->next)
		{
		  fd = rp->fd;
		  if (FD_ISSET(fd, &fds))
		    {
		      n--;
		      if (free_recvbufs == 0)
			{
			  char buf[RX_BUFF_SIZE];

#ifndef SYS_WINNT
			  (void) read(fd, buf, sizeof buf);
#else
			  (void) ReadFile((HANDLE)fd, buf, (DWORD)sizeof buf, NULL, NULL);
#endif /* SYS_WINNT */
			  packets_dropped++;
#if 1
			  goto select_again;
#else
			  continue;
#endif
			}

		      rb = (struct recvbuf *) freelist;
		      freelist = rb->next;
		      free_recvbufs--;

		      i = (rp->datalen == 0
			   || rp->datalen > sizeof(rb->recv_space))
			? sizeof(rb->recv_space) : rp->datalen;
#ifndef SYS_WINNT				
		      rb->recv_length =
			read(fd, (char *)&rb->recv_space, i)
#else  /* SYS_WINNT */
			ReadFile((HANDLE)fd, (char *)&rb->recv_space, (DWORD)i,
				 (LPDWORD)&(rb->recv_length), NULL)
#endif /* SYS_WINNT */
			;

		      if (rb->recv_length == -1)
			{
			  msyslog(LOG_ERR, "clock read fd %d: %m", fd);
			  rb->next = (struct recvbuf *) freelist;
			  freelist = rb;
			  free_recvbufs++;
#if 1
			  goto select_again;
#else
			  continue;
#endif
			}
	
		      /*
		       * Got one.  Mark how and when it got here,
		       * put it on the full list and do bookkeeping.
		       */
		      rb->recv_srcclock = rp->srcclock;
		      rb->dstadr = 0;
		      rb->fd = fd;
		      rb->recv_time = ts;
		      rb->receiver = rp->clock_recv;

		      if (fulllist == 0)
			{
			  beginlist = rb;
			  rb->next = 0;
			}
		      else
			{
			  rb->next = fulllist->next;
			  fulllist->next = rb;
			}
		      fulllist = rb;
		      full_recvbufs++;

		      rp->recvcount++;
		      packets_received++;
		    }
		}
	    }
#endif /* REFCLOCK */

	  /*
	   * Loop through the interfaces looking for data to read.
	   */
	  for (i = ninterfaces - 1; (i >= 0) && (n > 0); i--)
	    {
	      for (doing = 0; (doing < 2) && (n > 0); doing++)
		{
		  if (doing == 0)
		    {
		      fd = inter_list[i].fd;
		    }
		  else
		    {
		      if (!(inter_list[i].flags & INT_BCASTOPEN))
			break;
		      fd = inter_list[i].bfd;
		    }
		  if (fd < 0) continue;
		  if (FD_ISSET(fd, &fds))
		    {
		      n--;

		      /*
		       * Get a buffer and read the frame.  If we
		       * haven't got a buffer, or this is received
		       * on the wild card socket, just dump the
		       * packet.
		       */
		      if (
#ifndef SYS_WINNT
			  (!(free_recvbufs && (i == 0) &&
			     (inter_list[i].flags & INT_MULTICAST)))
#else
			  /* For Win/NT we are creating just one socket,
			   * i is 0, and INT_MULTICAST flag is not set.
			   */
			  (!free_recvbufs)
#endif /* SYS_WINNT */
			  )
			{
			  if (
#ifdef UDP_WILDCARD_DELIVERY
			      /*
			       * these guys manage to put properly addressed
			       * packets into the wildcard queue
			       */
			      (free_recvbufs == 0)
#else
			      ((i == 0) || (free_recvbufs == 0))
#endif
			      )
			    {
			      char buf[RX_BUFF_SIZE];
			      struct sockaddr from;

			      fromlen = sizeof from;
			      (void) recvfrom(fd, buf,
					      sizeof(buf), 0,
					      &from, &fromlen);
#ifdef DEBUG
			      if (debug)
				printf("%s on %d(%lu) fd=%d from %s\n",
				       (i) ? "drop" : "ignore",
				       i, free_recvbufs, fd,
				       inet_ntoa(((struct sockaddr_in *) &from)->sin_addr));
#endif
			      if (i == 0)
				packets_ignored++;
			      else
				packets_dropped++;
#if 1
			      goto select_again;
#else
			      continue;
#endif
			    }
			}

		      rb = (struct recvbuf *) freelist;

		      fromlen = sizeof(struct sockaddr_in);
		      rb->recv_length = recvfrom(fd,
						 (char *)&rb->recv_space,
						 sizeof(rb->recv_space), 0,
						 (struct sockaddr *)&rb->recv_srcadr,
						 &fromlen);
		      if (rb->recv_length > 0)
		        {
		          freelist = rb->next;
		          free_recvbufs--;
		        }
		      else if (rb->recv_length == 0
#ifdef EWOULDBLOCK
			       || errno==EWOULDBLOCK
#endif
#ifdef EAGAIN
			       || errno==EAGAIN
#endif
		              )
		        continue;
		      else
		        {
			  msyslog(LOG_ERR, "recvfrom() fd=%d: %m", fd);
#ifdef DEBUG
			  if (debug)
			    printf("input_handler: fd=%d dropped (bad recvfrom): %s\n",
				fd, strerror(errno));
#endif
			  continue;
			}
#ifdef DEBUG
		      if (debug)
			printf("input_handler: fd=%d length %d from %08lx %s\n",
			       fd, rb->recv_length,
			       (u_long)ntohl(rb->recv_srcadr.sin_addr.s_addr) &
			       0x00000000ffffffff,
			       inet_ntoa(rb->recv_srcadr.sin_addr));
#endif
		      
		      /*
		       * Got one.  Mark how and when it got here,
		       * put it on the full list and do bookkeeping.
		       */
		      rb->dstadr = &inter_list[i];
		      rb->fd = fd;
		      rb->recv_time = ts;
		      rb->receiver = receive;

		      if (fulllist == 0)
			{
			  beginlist = rb;
			  rb->next = 0;
			}
		      else
			{
			  rb->next = fulllist->next;
			  fulllist->next = rb;
			}
		      fulllist = rb;
		      full_recvbufs++;
	
		      inter_list[i].received++;
		      packets_received++;
		      goto select_again;
		    }
		  /* Check more interfaces */
		}
	    }
	select_again:;
	  /*
	   * Done everything from that select.  Poll again.
	   */
	}

      /*
       * If nothing more to do, try again.
       * If nothing to do, just return.
       * If an error occurred, complain and return.
       */
      if (n == 0)
	{
	  if (select_count == 0) /* We really had nothing to do */
	    {
	      if (debug)
		msyslog(LOG_DEBUG, "input_handler: select() returned 0");
	      --handler_count;
	      return;
	    }
	  /* We've done our work */
	  get_systime(&ts_e);
	  /*
	   * (ts_e - ts) is the amount of time we spent processing
	   * this gob of file descriptors.  Log it.
	   */
	  L_SUB(&ts_e, &ts);
	  if (debug > 3)
	    msyslog(LOG_INFO, "input_handler: Processed a gob of fd's in %s msec", lfptoms(&ts_e, 6));

#if 0
	  /*
	   * We'll re-start the for(;;) loop now.
	   * Use the ending timestamp as the received timestamp
	   */
	  ts = ts_e;
#else
	  /* No, for now just bail. */
	  --handler_count;
	  return;
#endif
	}
      else if (n == -1)
	{
#ifndef SYS_WINNT
	  int err = errno;
#else
	  DWORD err = WSAGetLastError();
#endif /* SYS_WINNT */

	  /*
	   * extended FAU debugging output
	   */
	  msyslog(LOG_ERR, "select(%d, %s, 0L, 0L, &0.000000) error: %m",
		 maxactivefd+1, fdbits(maxactivefd, &activefds));
	  if (
#ifndef SYS_WINNT
	      (err == EBADF)
#else
	      (err == WSAEBADF)
#endif /* SYS_WINNT */
	     )
	    {
	      int i, b;

	      fds = activefds;
	      for (i = 0; i <= maxactivefd; i++)
		if (
#ifndef SYS_WINNT
		    (FD_ISSET(i, &fds) && (read(i, &b, 0) == -1))
#else
		    (FD_ISSET(i, &fds) && (!ReadFile((HANDLE)i, &b, 0, NULL, NULL)))
#endif /* SYS_WINNT */
		    )
		  msyslog(LOG_ERR, "Bad file descriptor %d", i);
	    }
	  --handler_count;
	  return;
	}
    }
#ifndef SYS_SOLARIS
  msyslog(LOG_ERR, "input_handler: fell out of infinite for(;;) loop!");
  --handler_count;
  return;
#endif
}

/*
 * findinterface - utility used by other modules to find an interface
 *		   given an address.
 */
struct interface *
findinterface(addr)
     struct sockaddr_in *addr;
{
  register int i;
  register u_int32 saddr;

  DYN_IFL_ASSERT(inter_list != NULL);
  /*
   * Just match the address portion.
   */
  saddr = addr->sin_addr.s_addr;
  for (i = 0; i < ninterfaces; i++)
    {
      if (inter_list[i].sin.sin_addr.s_addr == saddr)
	return &inter_list[i];
    }
  return (struct interface *)0;
}


/*
 * io_clr_stats - clear I/O module statistics
 */
void
io_clr_stats()
{
  packets_dropped = 0;
  packets_ignored = 0;
  packets_received = 0;
  packets_sent = 0;
  packets_notsent = 0;

  handler_calls = 0;
  handler_pkts = 0;
  io_timereset = current_time;
}


#ifdef REFCLOCK
/*
 * This is a hack so that I don't have to fool with these ioctls in the
 * pps driver ... we are already non-blocking and turn on SIGIO thru
 * another mechanisim
 */
int
io_addclock_simple(rio)
     struct refclockio *rio;
{
  BLOCKIO();
  /*
   * Stuff the I/O structure in the list and mark the descriptor
   * in use.  There is a harmless (I hope) race condition here.
   */
  rio->next = refio;
  refio = rio;
  
  if (rio->fd > maxactivefd)
    maxactivefd = rio->fd;
  FD_SET(rio->fd, &activefds);
  UNBLOCKIO();
  return 1;
}

/*
 * io_addclock - add a reference clock to the list and arrange that we
 *               get SIGIO interrupts from it.
 */
int
io_addclock(rio)
     struct refclockio *rio;
{
  BLOCKIO();
  /*
   * Stuff the I/O structure in the list and mark the descriptor
   * in use.  There is a harmless (I hope) race condition here.
   */
  rio->next = refio;
  refio = rio;
  
# ifdef HAVE_SIGNALED_IO
  if (init_clock_sig(rio))
    { 
      refio = rio->next;
      UNBLOCKIO();
      return 0;
    }
# endif

  if (rio->fd > maxactivefd)
    maxactivefd = rio->fd;
  FD_SET(rio->fd, &activefds);

  UNBLOCKIO();
  return 1;
}

/*
 * io_closeclock - close the clock in the I/O structure given
 */
void
io_closeclock(rio)
     struct refclockio *rio;
{
  /*
   * Remove structure from the list
   */
  if (refio == rio)
    {
      refio = rio->next;
    }
  else
    {
      register struct refclockio *rp;

      for (rp = refio; rp != 0; rp = rp->next)
	if (rp->next == rio)
	  {
	    rp->next = rio->next;
	    break;
	  }
      
      if (rp == 0)
	{
	  /*
	   * Internal error.  Report it.
	   */
	  msyslog(LOG_ERR,
		 "internal error: refclockio structure not found");
	  return;
	}
    }
  
  /*
   * Close the descriptor.
   */
  close_file(rio->fd);
}
#endif	/* REFCLOCK */

/*
 * SIGPOLL and SIGIO ROUTINES.
 */
#ifdef HAVE_SIGNALED_IO
/*
 * Some systems (MOST) define SIGPOLL == SIGIO, others SIGIO == SIGPOLL, and
 * a few have separate SIGIO and SIGPOLL signals.  This code checks for the
 * SIGIO == SIGPOLL case at compile time.
 * Do not defined USE_SIGPOLL or USE_SIGIO.
 * these are interal only to ntp_io.c!
 */
# if defined(USE_SIGPOLL)
#  undef USE_SIGPOLL
# endif
# if defined(USE_SIGIO)
#  undef USE_SIGIO
# endif

# if defined(USE_TTY_SIGPOLL) || defined(USE_UDP_SIGPOLL)
#  define USE_SIGPOLL
# endif

# if !defined(USE_TTY_SIGPOLL) || !defined(USE_UDP_SIGPOLL)
#  define USE_SIGIO
# endif

# if defined(USE_SIGIO) && defined(USE_SIGPOLL)
#  if SIGIO == SIGPOLL
#   define USE_SIGIO
#   undef USE_SIGPOLL
#  endif /* SIGIO == SIGPOLL */
# endif /* USE_SIGIO && USE_SIGIO */


/*
 * TTY initialization routines.
 */
static int
init_clock_sig(rio)
     struct refclockio *rio;
# ifdef USE_TTY_SIGPOLL
{
  /* DO NOT ATTEMPT TO MAKE CLOCK-FD A CTTY: not portable, unreliable */
  if (ioctl(rio->fd, I_SETSIG, S_INPUT) < 0)
    {
      msyslog(LOG_ERR,
	     "init_clock_sig: ioctl(I_SETSIG, S_INPUT) failed: %m");
      return 1;
    }
  return 0;
}
# else
/*
 * Special cases first!
 */
/* Was: defined(SYS_HPUX) */
#  if defined(FIOSSAIOOWN) && defined(FIOSNBIO) && defined(FIOSSAIOSTAT)
#define CLOCK_DONE
{
  int pgrp, on = 1;
	
  /* DO NOT ATTEMPT TO MAKE CLOCK-FD A CTTY: not portable, unreliable */
  pgrp = getpid();
  if (ioctl(rio->fd, FIOSSAIOOWN, (char *)&pgrp) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOSSAIOOWN) fails for clock I/O: %m");
      exit(1);
      /*NOTREACHED*/
    }

  /*
   * set non-blocking, async I/O on the descriptor
   */
  if (ioctl(rio->fd, FIOSNBIO, (char *)&on) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOSNBIO) fails for clock I/O: %m");
      exit(1);
      /*NOTREACHED*/
    }

  if (ioctl(rio->fd, FIOSSAIOSTAT, (char *)&on) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOSSAIOSTAT) fails for clock I/O: %m");
      exit(1);
      /*NOTREACHED*/
    }
  return 0;	
}
#  endif /* SYS_HPUX: FIOSSAIOOWN && FIOSNBIO && FIOSSAIOSTAT */
/* Was: defined(SYS_AIX) && !defined(_BSD) */
#  if !defined(_BSD) && defined(_AIX) && defined(FIOASYNC) && defined(FIOSETOWN)
/*
 * SYSV compatibility mode under AIX.
 */
#define CLOCK_DONE
{
  int pgrp, on = 1;

  /* DO NOT ATTEMPT TO MAKE CLOCK-FD A CTTY: not portable, unreliable */
  if (ioctl(rio->fd, FIOASYNC, (char *)&on) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOASYNC) fails for clock I/O: %m");
      return 1;
    }
  pgrp = -getpid();
  if (ioctl(rio->fd, FIOSETOWN, (char*)&pgrp) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOSETOWN) fails for clock I/O: %m");
      return 1;
    }

  if (fcntl(rio->fd, F_SETFL, FNDELAY|FASYNC) < 0)
    {
      msyslog(LOG_ERR, "fcntl(FNDELAY|FASYNC) fails for clock I/O: %m");
      return 1;
    }
  return 0;
}
#  endif /* AIX && !BSD: !_BSD && FIOASYNC && FIOSETOWN */
#  ifndef  CLOCK_DONE
{
  /* DO NOT ATTEMPT TO MAKE CLOCK-FD A CTTY: not portable, unreliable */
#   if defined(TIOCSCTTY) && defined(USE_FSETOWNCTTY)
  /*
   * there are, however, always exceptions to the rules
   * one is, that OSF accepts SETOWN on TTY fd's only, iff they are
   * CTTYs. SunOS and HPUX do not semm to have this restriction.
   * another question is: how can you do multiple SIGIO from several
   * ttys (as they all should be CTTYs), wondering...
   *
   * kd 95-07-16
   */
  if (ioctl(rio->fd, TIOCSCTTY, 0) == -1)
    {
      msyslog(LOG_ERR, "ioctl(TIOCSCTTY, 0) fails for clock I/O: %m");
      return 1;
    }
#   endif /* TIOCSCTTY && USE_FSETOWNCTTY */

  if (fcntl(rio->fd, F_SETOWN, getpid()) == -1)
    {
      msyslog(LOG_ERR, "fcntl(F_SETOWN) fails for clock I/O: %m");
      return 1;
    }

  if (fcntl(rio->fd, F_SETFL, FNDELAY|FASYNC) < 0)
    {
      msyslog(LOG_ERR,
	     "fcntl(FNDELAY|FASYNC) fails for clock I/O: %m");
      return 1;
    }
  return 0;	
}
#  endif /* CLOCK_DONE */
# endif /* !USE_TTY_SIGPOLL  */



static void
init_socket_sig(fd)
     int fd;
# ifdef USE_UDP_SIGPOLL
{
  if (ioctl(fd, I_SETSIG, S_INPUT) < 0)
    {
      msyslog(LOG_ERR,
	     "init_socket_sig: ioctl(I_SETSIG, S_INPUT) failed: %m");
      exit(1);
    }
}
# else /* USE_UDP_SIGPOLL */
{
  int pgrp;
# ifdef FIOASYNC
  int on = 1;
# endif

#  if defined(FIOASYNC)
  if (ioctl(fd, FIOASYNC, (char *)&on) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOASYNC) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#  elif defined(FASYNC)
  {
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
      {
        msyslog(LOG_ERR, "fcntl(F_GETFL) fails: %m");
        exit(1);
        /*NOTREACHED*/
      }
    if (fcntl(fd, F_SETFL, flags|FASYNC) < 0)
      {
        msyslog(LOG_ERR, "fcntl(...|FASYNC) fails: %m");
        exit(1);
        /*NOTREACHED*/
      }
   }
#  else
#   include "Bletch: Need asynchronous I/O!"
#  endif

#  ifdef UDP_BACKWARDS_SETOWN
  pgrp = -getpid();
#  else
  pgrp = getpid();
#  endif

#  if defined(SIOCSPGRP)
  if (ioctl(fd, SIOCSPGRP, (char *)&pgrp) == -1)
    {
      msyslog(LOG_ERR, "ioctl(SIOCSPGRP) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#  elif defined(FIOSETOWN)
  if (ioctl(fd, FIOSETOWN, (char*)&pgrp) == -1)
    {
      msyslog(LOG_ERR, "ioctl(FIOSETOWN) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#  elif defined(F_SETOWN)
  if (fcntl(fd, F_SETOWN, pgrp) == -1)
    {
      msyslog(LOG_ERR, "fcntl(F_SETOWN) fails: %m");
      exit(1);
      /*NOTREACHED*/
    }
#  else
#   include "Bletch: Need to set process(group) to receive SIG(IO|POLL)"
#  endif
}
# endif /* USE_UDP_SIGPOLL */


static RETSIGTYPE
sigio_handler(sig)
     int sig;
{
  int saved_errno = errno;
  l_fp ts;

  get_systime(&ts);
  (void)input_handler(&ts);
  errno = saved_errno;
}

/*
 * Signal support routines.
 */
# ifdef HAVE_SIGACTION
static void
set_signal()
{
#  ifdef USE_SIGIO
  (void) signal_no_reset(SIGIO, sigio_handler);
# endif
#  ifdef USE_SIGPOLL
  (void) signal_no_reset(SIGPOLL, sigio_handler);
# endif
}

void
block_io_and_alarm()
{
  sigset_t set;

  if (sigemptyset(&set))
    msyslog(LOG_ERR, "block_io_and_alarm: sigemptyset() failed: %m");
#  if defined(USE_SIGIO)
  if (sigaddset(&set, SIGIO))
    msyslog(LOG_ERR, "block_io_and_alarm: sigaddset(SIGIO) failed: %m");
#  endif
#  if defined(USE_SIGPOLL)
  if (sigaddset(&set, SIGPOLL))
    msyslog(LOG_ERR, "block_io_and_alarm: sigaddset(SIGPOLL) failed: %m");
#  endif
  if (sigaddset(&set, SIGALRM))
    msyslog(LOG_ERR, "block_io_and_alarm: sigaddset(SIGALRM) failed: %m");

  if (sigprocmask(SIG_BLOCK, &set, NULL))
    msyslog(LOG_ERR, "block_io_and_alarm: sigprocmask() failed: %m");
}

static void
block_sigio()
{
  sigset_t set;

  ++sigio_block_count;
  if (sigio_block_count > 1)
    msyslog(LOG_INFO, "block_sigio: sigio_block_count > 1");
  if (sigio_block_count < 1)
    msyslog(LOG_INFO, "block_sigio: sigio_block_count < 1");

  if (sigemptyset(&set))
    msyslog(LOG_ERR, "block_sigio: sigemptyset() failed: %m");
#  if defined(USE_SIGIO)
  if (sigaddset(&set, SIGIO))
    msyslog(LOG_ERR, "block_sigio: sigaddset(SIGIO) failed: %m");
#  endif
#  if defined(USE_SIGPOLL)
  if (sigaddset(&set, SIGPOLL))
    msyslog(LOG_ERR, "block_sigio: sigaddset(SIGPOLL) failed: %m");
#  endif

  if (sigprocmask(SIG_BLOCK, &set, NULL))
    msyslog(LOG_ERR, "block_sigio: sigprocmask() failed: %m");
}

void
unblock_io_and_alarm()
{
  sigset_t unset;

  if (sigemptyset(&unset))
    msyslog(LOG_ERR, "unblock_io_and_alarm: sigemptyset() failed: %m");

#  if defined(USE_SIGIO)
  if (sigaddset(&unset, SIGIO))
    msyslog(LOG_ERR, "unblock_io_and_alarm: sigaddset(SIGIO) failed: %m");
#  endif
#  if defined(USE_SIGPOLL)
  if (sigaddset(&unset, SIGPOLL))
    msyslog(LOG_ERR, "unblock_io_and_alarm: sigaddset(SIGPOLL) failed: %m");
#  endif
  if (sigaddset(&unset, SIGALRM))
    msyslog(LOG_ERR, "unblock_io_and_alarm: sigaddset(SIGALRM) failed: %m");

  if (sigprocmask(SIG_UNBLOCK, &unset, NULL))
    msyslog(LOG_ERR, "unblock_io_and_alarm: sigprocmask() failed: %m");
}

static
void
unblock_sigio()
{
  sigset_t unset;

  --sigio_block_count;
  if (sigio_block_count > 0)
    msyslog(LOG_INFO, "unblock_sigio: sigio_block_count > 0");
  if (sigio_block_count < 0)
    msyslog(LOG_INFO, "unblock_sigio: sigio_block_count < 0");

  if (sigemptyset(&unset))
    msyslog(LOG_ERR, "unblock_sigio: sigemptyset() failed: %m");

#  if defined(USE_SIGIO)
  if (sigaddset(&unset, SIGIO))
    msyslog(LOG_ERR, "unblock_sigio: sigaddset(SIGIO) failed: %m");
#  endif
#  if defined(USE_SIGPOLL)
  if (sigaddset(&unset, SIGPOLL))
    msyslog(LOG_ERR, "unblock_sigio: sigaddset(SIGPOLL) failed: %m");
#  endif

  if (sigprocmask(SIG_UNBLOCK, &unset, NULL))
    msyslog(LOG_ERR, "unblock_sigio: sigprocmask() failed: %m");
}

void
wait_for_signal()
{
  sigset_t old;
  
  if (sigprocmask(SIG_UNBLOCK, NULL, &old))
    msyslog(LOG_ERR, "wait_for_signal: sigprocmask() failed: %m");
  
#  if defined(USE_SIGIO)
  if (sigdelset(&old, SIGIO))
    msyslog(LOG_ERR, "wait_for_signal: sigdelset(SIGIO) failed: %m");
#  endif
#  if defined(USE_SIGPOLL)
  if (sigdelset(&old, SIGPOLL))
    msyslog(LOG_ERR, "wait_for_signal: sigdelset(SIGPOLL) failed: %m");
#  endif
  if (sigdelset(&old, SIGALRM))
    msyslog(LOG_ERR, "wait_for_signal: sigdelset(SIGALRM) failed: %m");
  
  if (sigsuspend(&old) && (errno != EINTR))
    msyslog(LOG_ERR, "wait_for_signal: sigsuspend() failed: %m");
}

# else /* !HAVE_SIGACTION */
/*
 * Must be an old bsd system.
 * We assume there is no SIGPOLL.
 */

void
block_io_and_alarm()
{
  int mask;
  
  mask = sigmask(SIGIO) | sigmask(SIGALRM);
  if (sigblock(mask))
    msyslog(LOG_ERR, "block_io_and_alarm: sigblock() failed: %m");
}

static void
block_sigio()
{
  int mask;

  ++sigio_block_count;
  if (sigio_block_count > 1)
    msyslog(LOG_INFO, "block_sigio: sigio_block_count > 1");
  if (sigio_block_count < 1)
    msyslog(LOG_INFO, "block_sigio: sigio_block_count < 1");

  mask = sigmask(SIGIO);
  if (sigblock(mask))
    msyslog(LOG_ERR, "block_sigio: sigblock() failed: %m");
}

static void
set_signal()
{
  (void) signal_no_reset(SIGIO, sigio_handler);
}

void
unblock_io_and_alarm()
{
  int mask, omask;
  
  mask = sigmask(SIGIO) | sigmask(SIGALRM);
  omask = sigblock(0);
  omask &= ~mask;
  (void) sigsetmask(omask);
}

static void
unblock_sigio()
{
  int mask, omask;

  --sigio_block_count;
  if (sigio_block_count > 0)
    msyslog(LOG_INFO, "unblock_sigio: sigio_block_count > 0");
  if (sigio_block_count < 0)
    msyslog(LOG_INFO, "unblock_sigio: sigio_block_count < 0");
  mask = sigmask(SIGIO);
  omask = sigblock(0);
  omask &= ~mask;
  (void) sigsetmask(omask);
}

void
wait_for_signal()
{
  int mask, omask;
  
  mask = sigmask(SIGIO) | sigmask(SIGALRM);
  omask = sigblock(0);
  omask &= ~mask;
  if (sigpause(omask) && (errno != EINTR))
    msyslog(LOG_ERR, "wait_for_signal: sigspause() failed: %m");
}
# endif /* HAVE_SIGACTION */
#endif /* HAVE_SIGNALED_IO */

void
kill_asyncio()
{
  int i;
  
  BLOCKIO();

#ifdef	N_FD_RESERVE
  for (i = N_FD_RESERVE; i <= maxactivefd; i++)
    (void)close_socket(i);
#else
  for (i = 4; i <= maxactivefd; i++)
    (void)close_socket(i);
#endif
}

#ifdef SYS_WINNT
/* ------------------------------------------------------------------------------------------------------------------ */
/* modified with suggestions from Kevin Dunlap so we only pick out netcards bound to tcpip */

int
get_winnt_interfaces(ifc)
     struct ifconf *ifc;
{
  char *ifc_buffer = ifc->ifc_buf;

  struct ifreq *ifr;
  int maxsize = sizeof(ifc_buffer);
  HKEY hk, hksub;                      /* registry key handle */
  BOOL bSuccess;
  char newkey[200];

  char servicename[50];
  DWORD sizeofservicename = 50;
  int Done = 0;
        
  /*
   * these need to be big as they are multi_sz in type and hold all
   * ip addresses and subnet mask for a given interface
   */
  char IpAddresses[10000];
  char *ipptr = IpAddresses;
  DWORD sizeofipaddresses = 10000;
  char SubNetMasks[10000];
  char *subptr = SubNetMasks;
  DWORD sizeofsubnetmasks = 10000;
  char bindservicenames[1000];
  DWORD sizeofbindnames = 1000;
  
  char oneIpAddress[16];
  char oneSubNetMask[16];
  int count = 0;
  char *onenetcard;
  
  /* now get all the netcard values which are bound to tcpip */ 
  
  strcpy(newkey,"SYSTEM\\Currentcontrolset\\Services\\");
  strcat(newkey,"tcpip\\linkage");
  
  bSuccess = RegOpenKey(HKEY_LOCAL_MACHINE,newkey,&hk);
  if(bSuccess != ERROR_SUCCESS)
    {
      msyslog(LOG_ERR, "failed to Open TCP/IP Linkage Registry key: %m");
#ifdef DEBUG
      if (debug)
	printf("Cannot get TCP/IP Linkage from registery.\n");
#endif
      return -1;
    }

  /* now get the bind value */
  sizeofbindnames = 1000;
  bSuccess = RegQueryValueEx(hk,     /* subkey handle         */
			     "Bind", /* value name            */
			     NULL,   /* must be zero          */
			     NULL,   /* value type          not required  */
			     (LPBYTE) &bindservicenames,        /* address of value data */
			     &sizeofbindnames);                 /* length of value data  */
  if(bSuccess != ERROR_SUCCESS)
    {
      msyslog(LOG_ERR, "Error in RegQueryValueEx fetching Bind Service names parameter: %m");
      RegCloseKey(hk);
      return -1;
    }

  /* now loop through and get all the values which are bound to tcpip */ 
  /* we can also close the key here as we have the values now */
  RegCloseKey(hk);
  onenetcard = bindservicenames;
  while(1)
    {
      onenetcard = onenetcard + 8;
      if  ((onenetcard < (bindservicenames + sizeofbindnames)) &&
	   (sscanf(onenetcard,"%s",servicename) != EOF))
	{
	  onenetcard+= strlen(servicename) + 1;
	}
      else { /* no more */
	break;
      }

      /*
       * skip services that are NDISWAN... since these are temporary
       * interfaces like ras and if we bind to these we would have to
       * check if the socket is still ok everytime before using it as
       * when the link goes down and comes back up the socket is no
       * longer any good... and the server eventually crashes if we
       * don't check this.. and to check it entails a lot of overhead...
       * shouldn't be a problem with machines with only a RAS
       * interface anyway as we can bind to the loopback or 0.0.0.0
       */
      
      if ((strlen(servicename) >= 7) && (strncmp(strupr(servicename),"NDISWAN",7) == 0))
	{
	  /* skip it */
#ifdef DEBUG
	  if (debug)
	    printf("Skippping temporary interface [%s]\n",servicename);
#endif
	}
      else {
	/* if opening this key fails we can assume it is not a network card ie digiboard and go on.. */
	/* ok now that we have the service name parameter close the key and go get the ipaddress and subnet mask */
	
	strcpy(newkey,"SYSTEM\\Currentcontrolset\\Services\\");
	strcat(newkey,servicename);
	strcat(newkey,"\\parameters\\tcpip");
	
	bSuccess = RegOpenKey(HKEY_LOCAL_MACHINE,newkey,&hksub);
	if(bSuccess != ERROR_SUCCESS)
	  {
#ifdef DEBUG
	    if (debug)
	      printf("Skipping interface [%s] ... It is not a network card.\n",servicename);
#endif
	  }
	else
	  { /* ok it is a network card */            
	    /* ok now get the ipaddress and subnetmask */
	    sizeofipaddresses = 10000;
	    bSuccess =
	      RegQueryValueEx(hksub,       /* subkey handle         */
			      "IpAddress", /* value name            */
			      NULL,        /* must be zero          */
			      NULL,        /* value type      not required  */
			      (LPBYTE)&IpAddresses, /* address of value data */
			      &sizeofipaddresses);  /* length of value data  */
	    if(bSuccess != ERROR_SUCCESS)
	      {
		msyslog(LOG_ERR, "Error in RegQueryValueEx fetching IpAddress parameter: %m");
		RegCloseKey(hksub);
		return -1;
	      }
	    /* ok now get the ipaddress and subnetmask */
	    sizeofsubnetmasks = 10000;
	    bSuccess =
	      RegQueryValueEx(hksub,        /* subkey handle         */
			      "SubNetMask", /* value name            */
			      NULL,         /* must be zero          */
			      NULL,         /* value type     not required  */
			      (LPBYTE)&SubNetMasks, /* address of value data */
			      &sizeofsubnetmasks);  /* length of value data  */
	  if(bSuccess != ERROR_SUCCESS)
	    {
	      msyslog(LOG_ERR, "Error in RegQueryValueEx fetching SubNetMask parameter: %m");
	      RegCloseKey(hksub);
	      return -1;
	    }
	  
	  RegCloseKey(hksub);
	  /* ok now that we have some addresses and subnet masks go through each one and add to our structure... */
	  /* multi_sz strings are terminated by two \0 in a row */

	  ipptr = IpAddresses;
	  subptr = SubNetMasks;
	  Done = 0;
	  while (!Done)
	    {
	      ifr = (struct ifreq *)ifc_buffer;
	      if (sscanf(ipptr,"%s",oneIpAddress) != EOF)
		ipptr+= strlen(oneIpAddress) + 1; /* add one for terminator \0 */
	      else Done = 1;
	      
	      if (sscanf(subptr,"%s",oneSubNetMask) != EOF)
		subptr += strlen(oneSubNetMask) + 1;
	      else Done = 1;
	      
	      /* now add to interface structure */
	      if (!Done)                  
		{
		  ifr->ifr_addr.sa_family = AF_INET;
		  ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr = inet_addr(oneIpAddress);
		  strcpy(ifr->ifr_mask,oneSubNetMask);
		  
		  if (strlen(servicename) > 15)
		    strncpy(ifr->ifr_name,servicename,15);
		  else strcpy(ifr->ifr_name,servicename);
		  
		  /* now increment pointer */
		  ifc_buffer += sizeof (ifr->ifr_name) + sizeof(ifr->ifr_addr) + sizeof(ifr->ifr_mask);
		  ++count;
		  if (((char *)ipptr == '\0') || ((char *)subptr == '\0')) 
		    Done = 1;
		}
	    }
	} /* it is a network card */
      } /* it is/not a temporary ndiswan name */ 
    } /* end of loop  */
  
  /* now reset the length */
  ifc->ifc_len = count * (sizeof(ifr->ifr_name) + sizeof(ifr->ifr_addr) + sizeof(ifr->ifr_mask));
  return 0;
}

#endif /* SYS_WINNT */
