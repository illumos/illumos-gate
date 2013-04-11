/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNW_PORT_AFTER_H
#define	_SUNW_PORT_AFTER_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * rename setnetgrent and endnetgrent which were formerly in a separate irs
 * shared library.  These functions should come from libc.so
 */
#define	setnetgrent res_setnetgrent
#ifdef SETNETGRENT_ARGS
void setnetgrent(SETNETGRENT_ARGS);
#else
void setnetgrent(const char *netgroup);
#endif

#define	endnetgrent res_endnetgrent
void endnetgrent(void);


/*
 * include ports for the public header files. ISC's versions are quite different
 * from those currently in OpenSolaris.
 */

#ifdef _RESOLV_H_
#include <port_resolv.h>
#endif /* _RESOLV_H_ */

#ifdef _NETDB_H
#include <port_netdb.h>
#endif /* _NETDB_H */

#ifdef _ARPA_INET_H
#include <arpa/port_inet.h>
#endif /* _ARPA_INET_H */

#ifdef _ARPA_NAMESER_H
#include <arpa/port_nameser.h>
#endif /* _ARPA_NAMESER_H */


#ifdef _ARPA_NAMESER_COMPAT_H
/* no changes */
#endif /* _ARPA_NAMESER_COMPAT_H */

/* version-specific defines */
#include <os_version.h>

/*
 * Prior to 2.6, Solaris needs a prototype for gethostname().
 */
#if (OS_MAJOR == 5 && OS_MINOR < 6)
extern int gethostname(char *, size_t);
#endif
/*
 * gethostid() was not available until 2.5
 * setsockopt(SO_REUSEADDR) fails on unix domain sockets before 2.5
 * use ioctl(FIONBIO) rather than fcntl() calls to set/clear non-blocking i/o.
 */
#if (OS_MAJOR == 5 && OS_MINOR < 5)
#define	GET_HOST_ID_MISSING
#define	NO_UNIX_REUSEADDR
#define	USE_FIONBIO_IOCTL
#endif

#if (OS_MAJOR == 5 && OS_MINOR < 11)
#define	NEED_STRSEP
extern char *strsep(char **, const char *);
#endif


/*
 * Solaris 2.5 and later have getrlimit(), setrlimit() and getrusage().
 */
#if (OS_MAJOR > 5 || (OS_MAJOR == 5 && OS_MINOR >= 5))
#include <sys/resource.h>
#define	HAVE_GETRUSAGE
#define	RLIMIT_TYPE rlim_t
#define	RLIMIT_FILE_INFINITY
#endif

/* the default syslog facility of named/lwresd. */
#ifndef ISC_FACILITY
#define	ISC_FACILITY LOG_DAEMON
#endif


/*
 * Solaris 8 has if_nametoindex().
 */
#if (OS_MAJOR > 5 || (OS_MAJOR == 5 && OS_MINOR >= 8))
#define	USE_IFNAMELINKID
#endif

#undef ALIGN
#if (OS_MAJOR == 5 && OS_MINOR > 8)
#define	ALIGN(x) (((uintptr_t)(x) + (sizeof (char *) - 1UL)) & \
		~(sizeof (char *) - 1UL))
#else
#define	ALIGN(x) (((unsigned long)(x) + (sizeof (char *) - 1UL)) & \
		~(sizeof (char *) - 1UL))
#endif

#if (OS_MAJOR == 5 && OS_MINOR < 5)
#ifndef USE_FIONBIO_IOCTL
#define	USE_FIONBIO_IOCTL 1
#endif
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _SUNW_PORT_AFTER_H */
