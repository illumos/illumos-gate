/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#include "ntp_syslog.h"
#include "ntp_stdlib.h"

#ifdef HAVE_SIGACTION
#include <errno.h>

extern int errno;

void
signal_no_reset(sig, func)
     int sig;
     void (*func) P((int));
{
  int n;
  struct sigaction vec;

  vec.sa_handler = func;
  sigemptyset(&vec.sa_mask);
#if 0
#ifdef SA_RESTART
  vec.sa_flags = SA_RESTART;
#else
  vec.sa_flags = 0;
#endif
#else
  vec.sa_flags = 0;
#endif

  while (1)
    {
      struct sigaction ovec;
      
      n = sigaction(sig, &vec, &ovec);
      if (n == -1 && errno == EINTR) continue;
      if (ovec.sa_flags)
	msyslog(LOG_DEBUG, "signal_no_reset: signal %d had flags %x",
		sig, ovec.sa_flags);
      break;
    }
  if (n == -1) {
    perror("sigaction");
    exit(1);
  }
}

#elif  HAVE_SIGVEC

void
signal_no_reset(sig, func)
     int sig;
     RETSIGTYPE (*func) P((int));
{
  struct sigvec sv;
  int n;

  bzero((char *) &sv, sizeof(sv));
  sv.sv_handler = func;
  n = sigvec(sig, &sv, (struct sigvec *)NULL);
  if (n == -1) {
    perror("sigvec");
    exit(1);
  }
}

#elif  HAVE_SIGSET

void
signal_no_reset(sig, func)
     int sig;
     RETSIGTYPE (*func) P((int));
{
  int n;

  n = sigset(sig, func);
  if (n == -1) {
    perror("sigset");
    exit(1);
  }
}

#else 

/* Beware!  This implementation resets the signal to SIG_DFL */
void
signal_no_reset(sig, func)
     int sig;
     RETSIGTYPE (*func) P((int));
{
  int n;

  n = signal(sig, func);
  if (n == -1) {
    perror("signal");
    exit(1);
  }
}

#endif
