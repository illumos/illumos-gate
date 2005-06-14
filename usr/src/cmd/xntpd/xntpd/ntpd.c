/*
 * Copyright (c) 1996-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	HAVE_POSIX_MMAN
/*
 * ntpd.c - main program for the fixed point NTP daemon
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <stdio.h>
#include <errno.h>
#ifndef SYS_WINNT
# if !defined(VMS)	/*wjm*/
#  include <sys/param.h>
# endif /* VMS */
# include <sys/signal.h>
# ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
# endif /* HAVE_SYS_IOCTL_H */
# include <sys/time.h>
# if !defined(VMS)	/*wjm*/
#  include <sys/resource.h>
# endif /* VMS */
#else
# include <signal.h>
# include <process.h>
# include <io.h>
# include "../libntp/log.h"
#endif /* SYS_WINNT */
#if defined(HAVE_RTPRIO)
# ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
# endif
# ifdef HAVE_SYS_LOCK_H
#  include <sys/lock.h>
# endif
# include <sys/rtprio.h>
#else
# ifdef HAVE_PLOCK
#  ifdef HAVE_SYS_LOCK_H
#   include <sys/lock.h>
#  endif
# endif
#endif
#if defined(HAVE_SCHED_SETSCHEDULER)
# include <sched.h>
#endif
#if defined(HAVE_SYS_MMAN_H)
# include <sys/mman.h>
#endif

#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif

#ifdef SYS_DOMAINOS
# include <apollo/base.h>
#endif /* SYS_DOMAINOS */

#include "ntpd.h"
#include "ntp_select.h"
#include "ntp_io.h"
#include "ntp_stdlib.h"

#if 0				/* HMS: I don't think we need this. 961223 */
#ifdef LOCK_PROCESS
# ifdef SYS_SOLARIS
#  include <sys/mman.h>
# else
#  include <sys/lock.h>
# endif
#endif
#endif

/*
 * Signals we catch for debugging.  If not debugging we ignore them.
 */
#define	MOREDEBUGSIG	SIGUSR1
#define	LESSDEBUGSIG	SIGUSR2

/*
 * Signals which terminate us gracefully.
 */
#ifndef SYS_WINNT
# define	SIGDIE1		SIGHUP
# define	SIGDIE3		SIGQUIT
#endif /* SYS_WINNT */
#define	SIGDIE2		SIGINT
#define	SIGDIE4		SIGTERM

#ifdef SYS_WINNT
/* handles for various threads, process, and objects */
extern HANDLE hServDoneEvent;
HANDLE 	process_handle = NULL, WorkerThreadHandle = NULL,
  ResolverThreadHandle = NULL, TimerThreadHandle = NULL,
  hMutex = NULL;
/* variables used to inform the Service Control Manager of our current state */
SERVICE_STATUS ssStatus;
SERVICE_STATUS_HANDLE   sshStatusHandle;
int was_stopped = 0;
char szMsgPath[255];
#endif /* SYS_WINNT */

/*
 * Scheduling priority we run at
 */
#define	NTPD_PRIO	(-12)

/*
 * Debugging flag
 */
volatile int debug;

/*
 * -x and -g flags
*/
extern int allow_set_backward;
int correct_any;
/*
 * Initializing flag.  All async routines watch this and only do their
 * thing when it is clear.
 */
int initializing;

/*
 * Version declaration
 */
extern char *Version;

/* Added mutex to prevent race condition among threads under Windows NT */
#ifdef SYS_WINNT
HANDLE m_hListMutex;
#endif /* SYS_WINNT */

/*
 * Alarm flag.  Imported from timer module
 */
extern int alarm_flag;

int was_alarmed;

#ifdef DECL_SYSCALL
/*
 * We put this here, since the argument profile is syscall-specific
 */
extern int syscall	P((int, struct timeval *, struct timeval *));
#endif /* DECL_SYSCALL */

#ifdef SYS_WINNT
extern void worker_thread(void *);
#endif /* SYS_WINNT */
	
#ifdef	SIGDIE2
static	RETSIGTYPE	finish		P((int));
#endif	/* SIGDIE2 */

#ifdef	DEBUG
static	RETSIGTYPE	moredebug	P((int));
static	RETSIGTYPE	lessdebug	P((int));
#else /* not DEBUG */
static	RETSIGTYPE	no_debug	P((int));
#endif	/* not DEBUG */

#ifdef NO_MAIN_ALLOWED
void xntpdmain P((int, char *[]));
CALL(xntpd,"xntpd",xntpdmain);
#else
int main P((int, char *[]));
#endif

/*
 * Main program.  Initialize us, disconnect us from the tty if necessary,
 * and loop waiting for I/O and/or timer expiries.
 */
#ifndef NO_MAIN_ALLOWED
int main
#else
void xntpdmain
#endif
(argc, argv)
     int argc;
     char *argv[];
{
#ifndef SYS_WINNT
  char *cp;
  struct recvbuf *rbuflist;
  struct recvbuf *rbuf;
# if defined (SYS_SOLARIS)
#  define N_FD_RESERVE	16
  int fdsave[N_FD_RESERVE], f;
# endif
#endif

  initializing = 1;		/* mark that we are initializing */
  debug = 0;			/* no debugging by default */

#ifdef HAVE_UMASK     
  /* vxWorks does not have umask */
  {
    int uv;

    uv = umask(0);
    if(uv)
      (void) umask(uv);
    else
      (void) umask(022);
  }
#endif

#ifdef HAVE_GETUID
  {
    uid_t uid;

    uid = getuid();
    if (uid)
      {
	msyslog(LOG_ERR, "xntpd: must be run as root, not uid %d", uid);
	exit(1);
      }
  }
#endif

#ifdef SYS_WINNT
  /* Set the Event-ID message-file name. */
  if (!GetModuleFileName(NULL, szMsgPath, sizeof(szMsgPath))) {
    msyslog(LOG_ERR, "GetModuleFileName(PGM_EXE_FILE) failed: %m\n");
    exit(1);
  }
  addSourceToRegistry("NTP", szMsgPath);
#endif

  getstartup(argc, argv);	/* startup configuration, may set debug */

#if !defined(VMS)
# ifndef NODETACH
  /*
   * Detach us from the terminal.  May need an #ifndef GIZMO.
   */
#  ifdef DEBUG
  if (!debug)
    {
#  endif /* DEBUG */
#  ifndef SYS_WINNT
#   ifdef HAVE_DAEMON
      daemon(0, 0);
#   else /* not HAVE_DAEMON */
      if (fork())
	exit(0);

      {
#if defined(SYS_SOLARIS)
	closefrom(0);
#else /* SYS_SOLARIS */
	u_long s;
	int max_fd;
#if defined(HAVE_SYSCONF) && defined(_SC_OPEN_MAX)
	max_fd = sysconf(_SC_OPEN_MAX);
#else /* HAVE_SYSCONF && _SC_OPEN_MAX */
	max_fd = getdtablesize();
#endif /* HAVE_SYSCONF && _SC_OPEN_MAX */
	for (s = 0; s < max_fd; s++)
	  (void) close(s);
#endif /* SYS_SOLARIS */

	(void) open("/", 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
#ifdef SYS_DOMAINOS
	{
	  uid_$t puid;
	  status_$t st;

	  proc2_$who_am_i(&puid);
	  proc2_$make_server(&puid, &st);
	}
#endif /* SYS_DOMAINOS */
#if defined(HAVE_SETPGID) || defined(HAVE_SETSID)
# ifdef HAVE_SETSID
	if (setsid() == (pid_t)-1)
	  msyslog(LOG_ERR, "xntpd: setsid(): %m");
# else
	if (setpgid(0, 0) == -1)
	  msyslog(LOG_ERR, "xntpd: setpgid(): %m");
# endif
#else /* HAVE_SETPGID || HAVE_SETSID */
	{
	  int fid;

	  fid = open("/dev/tty", 2);
	  if (fid >= 0)
	    {
	      (void) ioctl(fid, (u_long) TIOCNOTTY, (char *) 0);
	      (void) close(fid);
	    }
# ifdef HAVE_SETPGRP_O
	  (void) setpgrp();
# else /* HAVE_SETPGRP_0 */
	  (void) setpgrp(0, getpid());
# endif /* HAVE_SETPGRP_0 */
	}
#endif /* HAVE_SETPGID || HAVE_SETSID */
      }
#endif /* not HAVE_DAEMON */
#else /* SYS_WINNT */

      {
	SERVICE_TABLE_ENTRY dispatchTable[] = {
	  { TEXT("NetworkTimeProtocol"), (LPSERVICE_MAIN_FUNCTION)service_main },
	  { NULL, NULL }
	};

      /* daemonize */
      if (!StartServiceCtrlDispatcher(dispatchTable))
	{
	  if (!was_stopped)
	    {
	      msyslog(LOG_ERR, "StartServiceCtrlDispatcher: %m");
	      ExitProcess(2);
	    }
	  else
	    {
	      NLOG(NLOG_SYSINFO) /* conditional if clause for conditional syslog */
		msyslog(LOG_INFO, "StartServiceCtrlDispatcher: service stopped");
	      ExitProcess(0);
	    }
	}
      }
#endif /* SYS_WINNT */
#ifdef	DEBUG
    }
#endif /* DEBUG */
#endif /* NODETACH */
#if defined(SYS_WINNT) && !defined(NODETACH)
#if defined(DEBUG)
  else
    service_main(argc, argv);
#endif
} /* end main */

/*
 * If this runs as a service under NT, the main thread will block at
 * StartServiceCtrlDispatcher() and another thread will be started by the
 * Service Control Dispatcher which will begin execution at the routine
 * specified in that call (viz. service_main) 
 */
void
service_main(argc, argv)
     DWORD argc;
     LPTSTR *argv;
{
  char *cp;
  DWORD dwWait;

  if(!debug)
    {
      /* register our service control handler */
      if (!(sshStatusHandle = RegisterServiceCtrlHandler( TEXT("NetworkTimeProtocol"),
							  (LPHANDLER_FUNCTION)service_ctrl)))
	{
	  msyslog(LOG_ERR, "RegisterServiceCtrlHandler failed: %m");
	  return;
	}

      /* report pending status to Service Control Manager */
      ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
      ssStatus.dwCurrentState = SERVICE_START_PENDING;
      ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
      ssStatus.dwWin32ExitCode = NO_ERROR;
      ssStatus.dwServiceSpecificExitCode = 0;
      ssStatus.dwCheckPoint = 1;
      ssStatus.dwWaitHint = 5000;
      if (!SetServiceStatus(sshStatusHandle, &ssStatus))
	{
	  msyslog(LOG_ERR, "SetServiceStatus: %m");
	  ssStatus.dwCurrentState = SERVICE_STOPPED;
	  SetServiceStatus(sshStatusHandle, &ssStatus);
	  return;
	}

    /*
     * create an event object that the control handler function
     * will signal when it receives the "stop" control code
     */
    if (!(hServDoneEvent = CreateEvent(
				       NULL,    /* no security attributes */
				       TRUE,    /* manual reset event */
				       FALSE,   /* not-signalled */
				       NULL)))  /* no name */
      {
	msyslog(LOG_ERR, "CreateEvent failed: %m");
	ssStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(sshStatusHandle, &ssStatus);
	return;
      }
    }  /* debug */
#endif /* defined(SYS_WINNT) && !defined(NODETACH) */
#endif /* VMS */

  /*
   * Logging.  This may actually work on the gizmo board.  Find a name
   * to log with by using the basename of argv[0]
   */
  cp = strrchr(argv[0], '/');
  if (cp == 0)
    cp = argv[0];
  else
    cp++;

  debug = 0; /* will be immediately re-initialized 8-( */
  getstartup(argc, argv);	/* startup configuration, catch logfile this time */

#if !defined(SYS_WINNT) && !defined(VMS)

# ifndef LOG_DAEMON
  openlog(cp, LOG_PID);
# else /* LOG_DAEMON */

#  ifndef LOG_NTP
#   define	LOG_NTP	LOG_DAEMON
#  endif
  openlog(cp, LOG_PID | LOG_NDELAY, LOG_NTP);
#  ifdef DEBUG
  if (debug)
    setlogmask(LOG_UPTO(LOG_DEBUG));
  else
#  endif /* DEBUG */
    setlogmask(LOG_UPTO(LOG_DEBUG)); /* @@@ was INFO */
# endif	/* LOG_DAEMON */

#endif  /* !SYS_WINNT && !VMS */

  NLOG(NLOG_SYSINFO) /* conditional if clause for conditional syslog */
    msyslog(LOG_NOTICE, "%s", Version);

#ifdef SYS_WINNT
  /* GMS 1/18/1997
   * TODO: lock the process in memory using SetProcessWorkingSetSize() and VirtualLock() functions 
   *
    process_handle = GetCurrentProcess();
	if (SetProcessWorkingSetSize(process_handle, 2097152 , 4194304 ) == TRUE) { 
		if (VirtualLock(0 , 4194304) == FALSE)
			msyslog(LOG_ERR, "VirtualLock() failed: %m");
	} else {
		msyslog(LOG_ERR, "SetProcessWorkingSetSize() failed: %m");
	}
	*/
#endif /* SYS_WINNT */

#if defined(HAVE_MLOCKALL) && defined(MCL_CURRENT) && defined(MCL_FUTURE)
  /*
   * lock the process into memory
   */
  if (mlockall(MCL_CURRENT|MCL_FUTURE) < 0)
    msyslog(LOG_ERR, "mlockall(): %m");
#else /* not (HAVE_MLOCKALL && MCL_CURRENT && MCL_FUTURE) */
# ifdef HAVE_PLOCK
#  ifdef PROCLOCK
  /*
   * lock the process into memory
   */
  if (plock(PROCLOCK) < 0)
    msyslog(LOG_ERR, "plock(PROCLOCK): %m");
#  else /* not PROCLOCK */
#   ifdef TXTLOCK
  /*
   * Lock text into ram
   */
  if (plock(TXTLOCK) < 0)
    msyslog(LOG_ERR, "plock(TXTLOCK) error: %m");
#   else /* not TXTLOCK */
  msyslog(LOG_ERR, "plock() - don't know what to lock!");
#   endif /* not TXTLOCK */
#  endif /* not PROCLOCK */
# endif /* HAVE_PLOCK */
#endif /* not (HAVE_MLOCKALL && MCL_CURRENT && MCL_FUTURE) */

  /*
   * Set the priority.
   */
#ifdef SYS_WINNT
  process_handle = GetCurrentProcess();
  if (!SetPriorityClass(process_handle, (DWORD) REALTIME_PRIORITY_CLASS))
    {
      msyslog(LOG_ERR, "SetPriorityClass: %m");
    }

  /* Added mutex to prevent race condition among threads under Windows NT */
  if ((m_hListMutex = CreateMutex(NULL,FALSE,NULL)) == NULL)
    msyslog(LOG_ERR, "CreateMutex: %m");
#else  /* not SYS_WINNT */
# if defined(HAVE_SCHED_SETSCHEDULER)
  {
    struct sched_param sched;
    sched.sched_priority = sched_get_priority_min(SCHED_FIFO);
    if ( sched_setscheduler(0, SCHED_FIFO, &sched) == -1 )
    {
      msyslog(LOG_ERR, "sched_setscheduler(): %m");
    }
  }
# else /* not HAVE_SCHED_SETSCHEDULER */
#  if defined(HAVE_RTPRIO)
#   ifdef RTP_SET
  {
    struct rtprio srtp;

    srtp.type = RTP_PRIO_REALTIME;	/* was: RTP_PRIO_NORMAL */
    srtp.prio = 0;		/* 0 (hi) -> RTP_PRIO_MAX (31,lo) */

    if (rtprio(RTP_SET, getpid(), &srtp) < 0)
      msyslog(LOG_ERR, "rtprio() error: %m");
  }
#   else /* not RTP_SET */
  if (rtprio(0, 120) < 0)
    msyslog(LOG_ERR, "rtprio() error: %m");
#   endif /* not RTP_SET */
#  else  /* not HAVE_RTPRIO */
#   if defined(NTPD_PRIO) && NTPD_PRIO != 0
#    ifdef HAVE_ATT_NICE
  nice (NTPD_PRIO);
#    endif /* HAVE_ATT_NICE */
#    ifdef HAVE_BSD_NICE
  (void) setpriority(PRIO_PROCESS, 0, NTPD_PRIO);
#    endif /* HAVE_BSD_NICE */
#   endif /* NTPD_PRIO && NTPD_PRIO != 0 */
#  endif /* not HAVE_RTPRIO */
# endif /* not HAVE_SCHED_SETSCHEDULER */
#endif /* not SYS_WINNT */

  /*
   * Set up signals we pay attention to locally.
   */
# ifdef SIGDIE1
  (void) signal_no_reset(SIGDIE1, finish);
# endif	/* SIGDIE1 */
# ifdef SIGDIE2
  (void) signal_no_reset(SIGDIE2, finish);
# endif	/* SIGDIE2 */
# ifdef SIGDIE3
  (void) signal_no_reset(SIGDIE3, finish);
# endif	/* SIGDIE3 */
# ifdef SIGDIE4
  (void) signal_no_reset(SIGDIE4, finish);
# endif	/* SIGDIE4 */

#ifdef SIGBUS
  (void) signal_no_reset(SIGBUS, finish);
#endif /* SIGBUS */

#if !defined(SYS_WINNT) && !defined(VMS)
# ifdef DEBUG
  (void) signal_no_reset(MOREDEBUGSIG, moredebug);
  (void) signal_no_reset(LESSDEBUGSIG, lessdebug);
# else
  (void) signal_no_reset(MOREDEBUGSIG, no_debug);
  (void) signal_no_reset(LESSDEBUGSIG, no_debug);
# endif /* DEBUG */
#endif /* !SYS_WINNT && !VMS */

  /*
   * Set up signals we should never pay attention to.
   */
#ifdef SIGPIPE
  (void) signal_no_reset(SIGPIPE, SIG_IGN);
#endif	/* SIGPIPE */

#ifdef N_FD_RESERVE
  /*
   * Reserve 16 low-order file descriptors for later use with stdio.
   */
# ifdef DEBUG
  if (debug > 2)
    printf("fdsave: ");
# endif
  for (f = 0; f < N_FD_RESERVE - 1; f++) {
    fdsave[f] = open("/dev/null", O_RDONLY);
# ifdef DEBUG
    if (debug > 2)
      printf("%d ", fdsave[f]);
# endif
  }
# ifdef DEBUG
  if (debug > 2)
    printf("\n");
# endif
#endif /* N_FD_RESERVE */

  /*
   * Call the init_ routines to initialize the data structures.
   * Note that init_systime() may run a protocol to get a crude
   * estimate of the time as an NTP client when running on the
   * gizmo board.  It is important that this be run before
   * init_subs() since the latter uses the time of day to seed
   * the random number generator.  That is not the only
   * dependency between these, either, be real careful about
   * reordering.
   */
  init_auth();
  init_util();
  init_restrict();
  init_mon();
  init_systime();
  init_timer();
  init_lib();
  init_random();
  init_request();
  init_control();
  init_leap();
  init_peer();
#ifdef REFCLOCK
  init_refclock();
#endif
  init_proto();
  init_io();
  init_loopfilter();

  mon_start(MON_ON);		/* monitor on by default now      */
				/* turn off in config if unwanted */

#ifdef N_FD_RESERVE
  /* Free up low-order file descriptors for use with stdio */
# ifdef DEBUG
  if (debug > 2)
    printf("fdsave: closing ");
# endif
  for (f = 0; f < N_FD_RESERVE - 1; f++) {
# ifdef DEBUG
    if (debug > 2)
      printf("%d ", fdsave[f]);
# endif
    close(fdsave[f]);
  }
# ifdef DEBUG
  if (debug > 2)
    printf("\n");
# endif
#endif /* N_FD_RESERVE */

  /*
   * Get configuration.  This (including argument list parsing) is
   * done in a separate module since this will definitely be different
   * for the gizmo board.
   */
  getconfig(argc, argv);
  initializing = 0;

#if defined(SYS_WINNT) && !defined(NODETACH)
# if defined(DEBUG)
  if(!debug)
    {
# endif

      /* 
       * the service_main() thread will have to wait for requests to
       * start/stop/pause/continue from the services icon in the Control
       * Panel or from any WIN32 application start a new thread to perform
       * all the work of the NTP service 
       */
      if (!(WorkerThreadHandle = (HANDLE)_beginthread(
						      worker_thread,
						      0,      /* stack size		*/
						      NULL))) /* argument to thread	*/
	{
	  msyslog(LOG_ERR, "_beginthread: %m");
	  if (hServDoneEvent != NULL)
	    CloseHandle(hServDoneEvent);
	  if (ResolverThreadHandle != NULL)
	    CloseHandle(ResolverThreadHandle);
	  ssStatus.dwCurrentState = SERVICE_STOPPED;
	  SetServiceStatus(sshStatusHandle, &ssStatus);
	  return;
	}

      /* report to the service control manager that the service is running */
      ssStatus.dwCurrentState = SERVICE_RUNNING;
      ssStatus.dwWin32ExitCode = NO_ERROR;
      if (!SetServiceStatus(sshStatusHandle, &ssStatus))
	{
	  msyslog(LOG_ERR, "SetServiceStatus: %m");
	  if (hServDoneEvent != NULL)
	    CloseHandle(hServDoneEvent);
	  if (ResolverThreadHandle != NULL)
	    CloseHandle(ResolverThreadHandle);
	  ssStatus.dwCurrentState = SERVICE_STOPPED;
	  SetServiceStatus(sshStatusHandle, &ssStatus);
	  return;
	}

      /* wait indefinitely until hServDoneEvent is signaled */
      dwWait = WaitForSingleObject(hServDoneEvent,INFINITE);
      if (hServDoneEvent != NULL)
	CloseHandle(hServDoneEvent);
      if (ResolverThreadHandle != NULL)
	CloseHandle(ResolverThreadHandle);
      if (WorkerThreadHandle != NULL)
	CloseHandle(WorkerThreadHandle);
      if (TimerThreadHandle != NULL)
	CloseHandle(TimerThreadHandle);
      /* restore the clock frequency back to its original value */
      if (!SetSystemTimeAdjustment((DWORD)0, TRUE))
	msyslog(LOG_ERR, "Failed to reset clock frequency, SetSystemTimeAdjustment(): %m");
      ssStatus.dwCurrentState = SERVICE_STOPPED;
      SetServiceStatus(sshStatusHandle, &ssStatus);
      return;
# if defined(DEBUG)
    }
  else 
    worker_thread( (void *) 0 );
# endif
} /* end service_main() */


/*
 * worker_thread - perform all remaining functions after initialization and and becoming a service
 */
void
worker_thread(notUsed)
     void *notUsed;
{
  struct recvbuf *rbuflist;
  struct recvbuf *rbuf;

#endif /* defined(SYS_WINNT) && !defined(NODETACH) */

  /*
   * Report that we're up to any trappers
   */
  report_event(EVNT_SYSRESTART, (struct peer *)0);

  /*
   * Use select() on all on all input fd's for unlimited
   * time.  select() will terminate on SIGALARM or on the
   * reception of input.  Using select() means we can't do
   * robust signal handling and we get a potential race
   * between checking for alarms and doing the select().
   * Mostly harmless, I think.
   */
  /*
   * Under NT, a timer periodically invokes a callback function
   * on a different thread. This callback function has no way
   * of interrupting a winsock "select" call on a different
   * thread. A mutex is used to synchronize access to clock
   * related variables between the two threads (one blocking
   * on a select or processing the received packets and the
   * other that calls the timer callback function, timer(),
   * every second). Due to this change, timer() routine can
   * be invoked between  processing two or more received
   * packets, or even during processing a single received
   * packet before entering the clock_update routine (if
   * needed). The potential race condition is also avoided.
   */
  /* On VMS, I suspect that select() can't be interrupted
   * by a "signal" either, so I take the easy way out and 
   * have select() time out after one second. 
   * System clock updates really aren't time-critical, 
   * and - lacking a hardware reference clock - I have 
   * yet to learn about anything else that is.
   */
  was_alarmed = 0;
  rbuflist = (struct recvbuf *)0;
  for (;;)
    {
#ifndef HAVE_SIGNALED_IO
      extern fd_set activefds;
      extern int maxactivefd;

      fd_set rdfdes;
      int nfound;
#else
      block_io_and_alarm();
#endif

      rbuflist = getrecvbufs();	/* get received buffers */
      if (alarm_flag)		/* alarmed? */
	{
	  was_alarmed = 1;
	  alarm_flag = 0;
	}

      if (!was_alarmed && rbuflist == (struct recvbuf *)0)
	{
	  /*
	   * Nothing to do.  Wait for something.
	   */
#ifndef HAVE_SIGNALED_IO
	  rdfdes = activefds;
#if defined(VMS) || defined(SYS_VXWORKS) 
	  /* make select() wake up after one second */
	  {
	    struct timeval t1;

	    t1.tv_sec = 1; t1.tv_usec = 0;
	    nfound = select(maxactivefd+1, &rdfdes, (fd_set *)0,
			    (fd_set *)0, &t1);
	  }
#else
	  nfound = select(maxactivefd+1, &rdfdes, (fd_set *)0,
			  (fd_set *)0, (struct timeval *)0);
#endif /* VMS */
	  if (nfound > 0)
	    {
	      l_fp ts;

	      get_systime(&ts);
          
	      (void)input_handler(&ts);
	    }
	  else if (
#ifndef SYS_WINNT
		   (nfound == -1 && errno != EINTR)
#else /* SYS_WINNT */
		   (nfound == SOCKET_ERROR && WSAGetLastError() != WSAEINTR)
#endif /* SYS_WINNT */
		   )
	    msyslog(LOG_DEBUG, "select(): error: %m");
	  else if (debug > 1)
	    msyslog(LOG_DEBUG, "select(): nfound=%d, error: %m", nfound);

#else /* HAVE_SIGNALED_IO */
	  wait_for_signal();
#endif /* HAVE_SIGNALED_IO */

	  if (alarm_flag)		/* alarmed? */
	    {
	      was_alarmed = 1;
	      alarm_flag = 0;
	    }
	  rbuflist = getrecvbufs();  /* get received buffers */
	}
#ifdef HAVE_SIGNALED_IO
      unblock_io_and_alarm();
#endif /* HAVE_SIGNALED_IO */

      /*
       * Out here, signals are unblocked.  Call timer routine
       * to process expiry.
       */
#ifndef SYS_WINNT
      /*
       * under WinNT, the timer() routine is directly called
       * by the timer callback function (alarming)
       * was_alarmed should have never been set, but don't
       * want to risk timer() being accidently called here
       */
      if (was_alarmed)
	{
	  timer();
	  was_alarmed = 0;
	}
#endif /* SYS_WINNT */

      /*
       * Call the data procedure to handle each received
       * packet.
       */
      while (rbuflist != (struct recvbuf *)0)
	{
	  rbuf = rbuflist;
	  rbuflist = rbuf->next;
	  (rbuf->receiver)(rbuf);
	  freerecvbuf(rbuf);
	}
      /*
       * Go around again
       */
    }
}


#ifdef SIGDIE2
/*
 * finish - exit gracefully
 */
static RETSIGTYPE
finish(sig)
     int sig;
{

  msyslog(LOG_NOTICE, "xntpd exiting on signal %d", sig);

#ifdef SYS_WINNT
  /*
   * with any exit(0)'s in the worker_thread, the service_main()
   * thread needs to be informed to quit also
   */
  SetEvent(hServDoneEvent);
#endif /* SYS_WINNT */

  switch (sig)
    {
#ifdef SIGBUS
    case SIGBUS:
        printf("\nfinish(SIGBUS)\n");
	exit(0);
#endif
    case 0:			/* Should never happen... */
      return;
    default:
      exit(0);
    }
}
#endif	/* SIGDIE2 */


#ifdef DEBUG
/*
 * moredebug - increase debugging verbosity
 */
static RETSIGTYPE
moredebug(sig)
     int sig;
{
  int saved_errno = errno;

  if (debug < 255)
    {
      debug++;
      msyslog(LOG_DEBUG, "debug raised to %d", debug);
    }
  errno = saved_errno;
}

/*
 * lessdebug - decrease debugging verbosity
 */
static RETSIGTYPE
lessdebug(sig)
     int sig;
{
  int saved_errno = errno;

  if (debug > 0)
    {
      debug--;
      msyslog(LOG_DEBUG, "debug lowered to %d", debug);
    }
  errno = saved_errno;
}
#else /* not DEBUG */
/*
 * no_debug - We don't do the debug here.
 */
static RETSIGTYPE
no_debug(sig)
     int sig;
{
  int saved_errno = errno;

  msyslog(LOG_DEBUG, "xntpd not compiled for debugging (signal %d)", sig);
  errno = saved_errno;
}
#endif	/* not DEBUG */

#ifdef SYS_WINNT
/* service_ctrl - control handler for NTP service
 * signals the service_main routine of start/stop requests
 * from the control panel or other applications making
 * win32API calls
 */
void
service_ctrl(dwCtrlCode)
     DWORD dwCtrlCode;
{
  DWORD  dwState = SERVICE_RUNNING;

  /* Handle the requested control code */
  switch(dwCtrlCode)
    {
    case SERVICE_CONTROL_PAUSE:
      /* see no reason to support this */
      break;

    case SERVICE_CONTROL_CONTINUE:
      /* see no reason to support this */
      break;

    case SERVICE_CONTROL_STOP:
      dwState = SERVICE_STOP_PENDING;
      /*
       * Report the status, specifying the checkpoint and waithint,
       *  before setting the termination event.
       */
      ssStatus.dwCurrentState = dwState;
      ssStatus.dwWin32ExitCode = NO_ERROR;
      ssStatus.dwWaitHint = 3000;
      if (!SetServiceStatus(sshStatusHandle, &ssStatus))
	{
	  msyslog(LOG_ERR, "SetServiceStatus: %m");
	}
      was_stopped = 1;
      SetEvent(hServDoneEvent);
      return;

    case SERVICE_CONTROL_INTERROGATE:
      /* Update the service status */
      break;

    default:
      /* invalid control code */
      break;

    }

  ssStatus.dwCurrentState = dwState;
  ssStatus.dwWin32ExitCode = NO_ERROR;
  if (!SetServiceStatus(sshStatusHandle, &ssStatus))
    {
      msyslog(LOG_ERR, "SetServiceStatus: %m");
    }
}
#endif /* SYS_WINNT */
