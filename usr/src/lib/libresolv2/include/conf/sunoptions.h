/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNOPTIONS_H
#define	_SUNOPTIONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The following options are PP flags available in the reference implementation
 * but do not get compiled due to the elimination of the options.h file
 * This section selectively reintroduces them
 */

#define	HAVE_GETRUSAGE

/*
 * The following options are PP flags introduced as part of the Sun/Solaris
 * port.
 */

/* We may have to pull this out */
#define	SUNW_LIBNSL	/* conflicts for inet_addr, inet_ntoa */

/* Additions for Solaris 2 */
#define	SUNW_NSSEARCH	/* fix nslookup domain search */
#define	SUNW_AVOIDOVERFLOW	/* Avoid buffer overflows */
#define	SUNW_INITCHKIF	/* Check if any non-loopback interface is up */
#define	SUNW_DOMAINFROMNIS	/* Default domain name from NIS/NIS+ */
#define	USELOOPBACK	/* Resolver library defaults to 127.0.0.1 */
#define	SUNW_CONFCHECK	/* Abort quickly if no /etc/resolv.conf or local */
			/* named */
#define	SUNW_AREWEINNAMED	/* Override _confcheck if proc is in.named */
#define	SUNW_OPENFDOFFSET	/* Open non-stdio fd:s with offset */
#define	SUNW_POLL	/* Use poll(2) instead of select(3) */
#define	SUNW_HOSTS_FALLBACK	/* Configurable /etc/hosts fallback */
#define	SUNW_LISTEN_BACKLOG	/* Configurable listen(3N) backlog (named) */
#define	SUNW_REJECT_BOGUS_H_LENGTH	/* (libresolv) */
#define	SUNW_HNOK_UNDERSCORE	/* Allow underscore in hostnames (libresolv) */
#define	SUNW_MT_RESOLVER	/* MT hot extensions (libresolv) */
#define	SUNW_QSTREAM_CLEANUP	/* Avoid using free()d struct qstreams */
#define	SUNW_SETHERRNO		/* ISC does not set h_errno in gethostbyname */
#define	SUNW_OVERRIDE_RETRY	/* Allow NS switch to override res->retry */
#define	SUNW_CLOSEFROM		/* closefrom(3C) per PSARC 2000/193 */
#define	SUNW_AVOIDSTDIO_FDLIMIT	/* Avoid 256 file descriptor limit in stdio */
#define	SUNW_LIBMD5	/* Use md5(3EXT) instead of internal implementation */

/* If compiling an MT warm libresolv, we also need reentrancy */
#if	defined(SUNW_MT_RESOLVER) && !defined(_REENTRANT)
#define	_REENTRANT
#endif

/* SUNW_AREWEINNAMED and SUNW_CONFCHECCK are mutually inclusive */
#if	defined(SUNW_AREWEINNAMED) && !defined(SUNW_CONFCHECK)
#define	SUNW_CONFCHECK
#endif

/* End additions for Solaris 2 */

#endif /* _SUNOPTIONS_H */
