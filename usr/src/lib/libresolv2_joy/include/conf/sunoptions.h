/*
 * Copyright 2009 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNOPTIONS_H
#define	_SUNOPTIONS_H

#define	USELOOPBACK	/* Resolver library defaults to 127.0.0.1 */

/* Additions for Solaris 2 */

#define	SUNW_INITCHKIF		/* Check if any non-loopback interface is up */
#define	SUNW_CONFCHECK		/* Abort quickly if no /etc/resolv.conf or */
				/* local named */
#define	SUNW_HOSTS_FALLBACK	/* Configurable /etc/hosts fallback */
#define	SUNW_HNOK_UNDERSCORE	/* Allow underscore in hostnames (libresolv) */
#define	SUNW_MT_RESOLVER	/* MT hot extensions (libresolv) */
#define	SUNW_SETHERRNO		/* ISC does not set h_errno in gethostbyname */
#define	SUNW_OVERRIDE_RETRY	/* Allow NS switch to override res->retry */
#define	SUNW_LIBMD5	/* Use md5(3EXT) instead of internal implementation */

/* If compiling an MT warm libresolv, we also need reentrancy */
#if	defined(SUNW_MT_RESOLVER) && !defined(_REENTRANT)
#define	_REENTRANT
#endif

/* End additions for Solaris 2 */

#endif /* _SUNOPTIONS_H */
