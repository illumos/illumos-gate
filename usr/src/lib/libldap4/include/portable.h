/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _PORTABLE_H
#define _PORTABLE_H

/*
 * portable.h for LDAP -- this is where we define common stuff to make
 * life easier on various Unix systems.
 *
 * Unless you are porting LDAP to a new platform, you should not need to
 * edit this file.
 */


#ifndef SYSV
#if defined( hpux ) || defined( sunos5 ) || defined ( sgi ) || defined( SVR4 )
#define SYSV
#endif
#endif


/*
 * under System V, use sysconf() instead of getdtablesize
 */
#if !defined( USE_SYSCONF ) && defined( SYSV )
#define USE_SYSCONF
#endif


/*
 * under System V, daemons should use setsid() instead of detaching from their
 * tty themselves
 */
#if !defined( USE_SETSID ) && defined( SYSV )
#define USE_SETSID
#endif


/*
 * System V has socket options in filio.h
 */
#if !defined( NEED_FILIO ) && defined( SYSV ) && !defined( hpux )
#define NEED_FILIO
#endif

/*
 * use lockf() under System V
 */
#if !defined( USE_LOCKF ) && ( defined( SYSV ) || defined( aix ))
#define USE_LOCKF
#endif

/*
 * on many systems, we should use waitpid() instead of waitN()
 */
#if !defined( USE_WAITPID ) && ( defined( SYSV ) || defined( sunos4 ) || defined( ultrix ) || defined( aix ))
#define USE_WAITPID
#endif


/*
 * define the wait status argument type
 */
#if ( defined( SunOS ) && SunOS < 40 ) || defined( nextstep )
#define WAITSTATUSTYPE	union wait
#else
#define WAITSTATUSTYPE	int
#endif

/*
 * define the flags for wait
 */
#ifdef sunos5
#define WAIT_FLAGS	( WNOHANG | WUNTRACED | WCONTINUED )
#else
#define WAIT_FLAGS	( WNOHANG | WUNTRACED )
#endif


/*
 * defined the options for openlog (syslog)
 */
#ifdef ultrix
#define OPENLOG_OPTIONS		LOG_PID
#else
#define OPENLOG_OPTIONS		( LOG_PID | LOG_NOWAIT )
#endif


/*
 * some systems don't have the BSD re_comp and re_exec routines
 */
#ifndef NEED_BSDREGEX
#if defined( SYSV ) || defined( VMS ) || defined( netbsd ) || defined( freebsd ) || defined( linux )
#define NEED_BSDREGEX
#endif
#endif

/*
 * many systems do not have the setpwfile() library routine... we just
 * enable use for those systems we know have it.
 */
#ifndef HAVE_SETPWFILE
#if defined( sunos4 ) || defined( ultrix ) || defined( __osf__ )
#define HAVE_SETPWFILE
#endif
#endif

/*
 * Are sys_errlist and sys_nerr declared in stdio.h?
 */
#ifndef SYSERRLIST_IN_STDIO
#if defined( freebsd ) 
#define SYSERRLIST_IN_STDIO
#endif
#endif

/*
 * for select()
 */
#if !defined(FD_SET) && !defined(WINSOCK)
#define NFDBITS         32
#define FD_SETSIZE      32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif /* FD_SET */

#if defined( hpux ) && defined( __STDC__ )
/*
 * Under HP/UX, select seems to want (int *) instead of fd_set.  Non-ANSI
 * compilers don't like recursive macros, so ignore the problem if __STDC__
 * is not defined.
 */
#define select(a,b,c,d,e) select(a, (int *)b, (int *)c, (int *)d, e)
#endif /* hpux && __STDC__ */


/*
 * for signal() -- what do signal handling functions return?
 */
#ifndef SIG_FN
#ifdef sunos5
#   define SIG_FN void          /* signal-catching functions return void */
#else /* sunos5 */
# ifdef BSD
#  if (BSD >= 199006) || defined(NeXT) || defined(__osf__) || defined(sun) || defined(ultrix) || defined(apollo) || defined(POSIX_SIGNALS)
#   define SIG_FN void          /* signal-catching functions return void */
#  else
#   define SIG_FN int           /* signal-catching functions return int */
#  endif
# else /* BSD */
#  define SIG_FN void           /* signal-catching functions return void */
# endif /* BSD */
#endif /* sunos5 */
#endif /* SIG_FN */

/*
 * call signal or sigset (signal does not block the signal while
 * in the handler on sys v and sigset does not exist on bsd)
 */
#ifdef SYSV
#define SIGNAL sigset
#else
#define SIGNAL signal
#endif

/*
 * toupper and tolower macros are different under bsd and sys v
 */
#if defined( SYSV ) && !defined( hpux )
#define TOUPPER(c)	(isascii(c) && islower(c) ? _toupper(c) : c)
#define TOLOWER(c)	(isascii(c) && isupper(c) ? _tolower(c) : c)
#else
#define TOUPPER(c)	(isascii(c) && islower(c) ? toupper(c) : c)
#define TOLOWER(c)	(isascii(c) && isupper(c) ? tolower(c) : c)
#endif

/*
 * put a cover on the tty-related ioctl calls we need to use
 */
#if defined( NeXT ) || (defined(SunOS) && SunOS < 40)
#define TERMIO_TYPE struct sgttyb
#define TERMFLAG_TYPE int
#define GETATTR( fd, tiop )	ioctl((fd), TIOCGETP, (caddr_t)(tiop))
#define SETATTR( fd, tiop )	ioctl((fd), TIOCSETP, (caddr_t)(tiop))
#define GETFLAGS( tio )		(tio).sg_flags
#define SETFLAGS( tio, flags )	(tio).sg_flags = (flags)
#else
#define USE_TERMIOS
#define TERMIO_TYPE struct termios
#define TERMFLAG_TYPE tcflag_t
#define GETATTR( fd, tiop )	tcgetattr((fd), (tiop))
#define SETATTR( fd, tiop )	tcsetattr((fd), TCSANOW /* 0 */, (tiop))
#define GETFLAGS( tio )		(tio).c_lflag
#define SETFLAGS( tio, flags )	(tio).c_lflag = (flags)
#endif


#if defined( ultrix ) || defined( nextstep )
extern char *strdup();
#endif /* ultrix || nextstep */

#endif /* _PORTABLE_H */
