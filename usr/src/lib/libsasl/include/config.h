/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/types.h>

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef mode_t */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Set to the database name you want SASL to use for
 * username->secret lookups */
/* #undef SASL_DB_PATH */

/* what db package are we using? */
/* #undef SASL_GDBM */
/* #undef SASL_NDBM */
/* #undef SASL_BERKELEYDB */

/* which mechs can we link staticly? */
/* #undef STATIC_ANONYMOUS */
/* #undef STATIC_CRAMMD5 */
/* #undef STATIC_DIGESTMD5 */
/* #undef STATIC_GSSAPIV2 */
/* #undef STATIC_KERBEROS4 */
/* #undef STATIC_LOGIN */
/* #undef STATIC_MYSQL */
/* #undef STATIC_NTLM */
/* #undef STATIC_OTP */
/* #undef STATIC_PLAIN */
/* #undef STATIC_SASLDB */
/* #undef STATIC_SRP */

/* This is where plugins will live at runtime */
#ifdef _LP64
#if defined(__sparcv9)
#define PLUGINDIR "/usr/lib/sasl/sparcv9"
#elif defined(__amd64)
#define PLUGINDIR "/usr/lib/sasl/amd64"
#else
#error Unsupported 64-bit architecture!
#endif
#else 
#define PLUGINDIR "/usr/lib/sasl"
#endif

#define SASL_CONFDIR "/etc/sasl"

/* should we use the internal rc4 library? */
/* This may be defined in digestmd5 makefile */
/* #undef WITH_RC4 */

/* do we have des available? */
/* This may be defined in digestmd5 makefile */
/* #undef WITH_DES */
/* #undef WITH_SSL_DES */

/* what about OpenSSL? */
/* #undef HAVE_OPENSSL */

/* should we support srp_setpass */
/* #undef DO_SRP_SETPASS */

/* do we have OPIE for server-side OTP support? */
/* #undef HAVE_OPIE */

/* Do we have kerberos for plaintext password checking? */
/* #undef HAVE_KRB */

/* do we have PAM for plaintext password checking? */
#define HAVE_PAM 1

/* do we have getsubopt()? */
#define HAVE_GETSUBOPT 1

/* Does your system have the snprintf() call? */
#define HAVE_SNPRINTF 1

/* Does your system have the vsnprintf() call? */
#define HAVE_VSNPRINTF 1

/* should we include support for the pwcheck daemon? */
/* #undef HAVE_PWCHECK */

/* where do we look for the pwcheck daemon? */
/* #undef PWCHECKDIR */

/* should we include support for the saslauth daemon? */
/* #undef HAVE_SASLAUTHD */

/* where does saslauthd look for the communication socket? */
/* #undef PATH_SASLAUTHD_RUNDIR */

/* do we want alwaystrue (discouraged)? */
/* #undef HAVE_ALWAYSTRUE */

/* are we linking against DMALLOC? */
/* #undef WITH_DMALLOC */

/* should we support sasl_checkapop */
#define DO_SASL_CHECKAPOP 1

/* do we pay attention to IP addresses in the kerberos 4 tickets? */
/* #undef KRB4_IGNORE_IP_ADDRESS */

/* do we have a preferred mechanism, or should we just pick the highest ssf? */
/* #undef PREFER_MECH */

/* Do we need a leading _ for dlsym? */
/* #undef DLSYM_NEEDS_UNDERSCORE */

/* Does libtool support shared libs on this system? */
#define HAVE_DLFCN_H 1
#define DO_DLOPEN 1

/* Should we try to dlopen stuff when we are staticly compiled? */
/* #undef TRY_DLOPEN_WHEN_STATIC */

/* define if your system has getaddrinfo() */
#define HAVE_GETADDRINFO 1
#define HAVE_INET_ATON 1

/* define if your system has getnameinfo() */
#define HAVE_GETNAMEINFO 1

/* define if your system has struct sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define if you have ss_family in struct sockaddr_storage. */
#define HAVE_SS_FAMILY 1

/* do we have socklen_t? */
#define HAVE_SOCKLEN_T 1

/* #undef HAVE_SOCKADDR_SA_LEN */

/* do we use doors for IPC? */
/* #undef USE_DOORS */

/* Define if you have the dn_expand function.  */
#define HAVE_DN_EXPAND 1

/* Define if you have the dns_lookup function.  */
/* #undef HAVE_DNS_LOOKUP */

/* Define if you have the getdomainname function.  */
/* #undef HAVE_GETDOMAINNAME */

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getpwnam function.  */
#define HAVE_GETPWNAM 1

/* Define if you have the getspnam function.  */
#define HAVE_GETSPNAM 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the gsskrb5_register_acceptor_identity function.  */
/* #undef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY */

/* Define if you have the jrand48 function.  */
#define HAVE_JRAND48 1

/* Define if you have the krb_get_err_text function.  */
/* #undef HAVE_KRB_GET_ERR_TEXT */

/* Define if you have the memcpy function.  */
#define HAVE_MEMCPY 1

/* Define if you have the mkdir function.  */
#define HAVE_MKDIR 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strchr function.  */
#define HAVE_STRCHR 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strspn function.  */
#define HAVE_STRSPN 1

/* Define if you have the strstr function.  */
#define HAVE_STRSTR 1

/* Define if you have the strtol function.  */
#define HAVE_STRTOL 1

/* Define if you have the syslog function.  */
#define HAVE_SYSLOG 1

/* Define if you have the <dirent.h> header file.  */
#define HAVE_DIRENT_H 1

/* Define if you have the <dlfcn.h> header file.  */
#define HAVE_DLFCN_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <inttypes.h> header file.  */
#define HAVE_INTTYPES_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <ndir.h> header file.  */
/* #undef HAVE_NDIR_H */

/* Define if you have the <paths.h> header file.  */
/* #undef HAVE_PATHS_H */

/* Define if you have the <stdarg.h> header file.  */
#define HAVE_STDARG_H 1

/* Define if you have the <strings.h> header file.  */
#define HAVE_STRINGS_H 1

/* Define if you have the <sys/dir.h> header file.  */
/* #undef HAVE_SYS_DIR_H */

/* Define if you have the <sys/file.h> header file.  */
#define HAVE_SYS_FILE_H 1

/* Define if you have the <sys/ndir.h> header file.  */
/* #undef HAVE_SYS_NDIR_H */

/* Define if you have the <sys/param.h> header file.  */
#define HAVE_SYS_PARAM_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/uio.h> header file.  */
#define HAVE_SYS_UIO_H 1

/* Define if you have the <sysexits.h> header file.  */
#define HAVE_SYSEXITS_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the <varargs.h> header file.  */
#define HAVE_VARARGS_H 1

/* Define if you have the db library (-ldb).  */
/* #undef HAVE_LIBDB */

/* Define if you have the resolv library (-lresolv).  */
#define HAVE_LIBRESOLV 1

/* Name of package */
/* #define PACKAGE "cyrus-sasl" */

/* Version number of package */
/* #undef VERSION */

/* define if your compiler has __attribute__ */
/* #undef HAVE___ATTRIBUTE__ */

/* Define if you have the gssapi.h header file */
/* #undef HAVE_GSSAPI_H */

/* Define if your GSSAPI implimentation defines GSS_C_NT_HOSTBASED_SERVICE */
#define HAVE_GSS_C_NT_HOSTBASED_SERVICE 


/* Create a struct iovec if we need one */
#if !defined(_WIN32) && !defined(HAVE_SYS_UIO_H)
/* (win32 is handled in sasl.h) */
struct iovec {
    char *iov_base;
    long iov_len;
};
#else
#include <sys/uio.h>
#endif

/* location of the random number generator */
#ifndef DEV_RANDOM
#define DEV_RANDOM "/dev/urandom"
#endif
#define _DEV_URANDOM "/dev/urandom"

/* if we've got krb_get_err_txt, we might as well use it;
   especially since krb_err_txt isn't in some newer distributions
   (MIT Kerb for Mac 4 being a notable example). If we don't have
   it, we fall back to the krb_err_txt array */
#ifdef HAVE_KRB_GET_ERR_TEXT
#define get_krb_err_txt krb_get_err_text
#else
#define get_krb_err_txt(X) (krb_err_txt[(X)])
#endif

/* Make Solaris happy... */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

/* Make Linux happy... */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef HAVE___ATTRIBUTE__
/* Can't use attributes... */
#define __attribute__(foo)
#endif

#define SASL_PATH_ENV_VAR "SASL_PATH"

#include <stdlib.h>
#include <sys/socket.h>
#ifndef WIN32
# include <netdb.h>
# ifdef HAVE_SYS_PARAM_H
#  include <sys/param.h>
# endif
#else /* WIN32 */
# include <winsock.h>
#endif /* WIN32 */

#include <string.h>

#include <netinet/in.h>

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
#define	_SS_MAXSIZE	128	/* Implementation specific max size */
#define	_SS_PADSIZE	(_SS_MAXSIZE - sizeof (struct sockaddr))

struct sockaddr_storage {
	struct	sockaddr ss_sa;
	char		__ss_pad2[_SS_PADSIZE];
};
# define ss_family ss_sa.sa_family
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define	AF_INET6	AF_MAX
#endif

#ifndef HAVE_GETADDRINFO
#define	getaddrinfo	sasl_getaddrinfo
#define	freeaddrinfo	sasl_freeaddrinfo
#define	getnameinfo	sasl_getnameinfo
#define	gai_strerror	sasl_gai_strerror
#include "gai.h"
#endif

/* Defined in RFC 1035. max strlen is only 253 due to length bytes. */
#ifndef MAXHOSTNAMELEN
#define        MAXHOSTNAMELEN  255
#endif

#ifndef HAVE_SYSEXITS_H
#include "exits.h"
#else
#include "sysexits.h"
#endif

#ifndef	NI_WITHSCOPEID
#define	NI_WITHSCOPEID	0
#endif

/* Get the correct time.h */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <libintl.h>
/*
 * We use gettext() so that xgettext will build msg database. libsasl and
 * plugins will actually use dgettext in the appropriate subroutine -
 * depending on SASL_CB_LANGUAGE or the specified language.
 */
#define gettext(x) (x)

#define USE_PTHREADS 1
#include <pthread.h>
#define	DEFINE_STATIC_MUTEX(x) \
	static pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER

#define	LOCK_MUTEX(x)	pthread_mutex_lock(x)
#define	UNLOCK_MUTEX(x)	pthread_mutex_unlock(x)

#define	DO_DLOPEN 1
#define	TRY_DLOPEN_WHEN_STATIC 1
#define	HAVE_DLFCN_H 1

/* HAVE_GSS_C_NT_USER_NAME is not needed for Solaris 10 since libgss has been
 * updated.
 */	
#undef HAVE_GSS_C_NT_USER_NAME

#define	HAVE_RPC_GSS_MECH_TO_OID 1

#define	_SUN_SDK_ 1

#define _INTEGRATED_SOLARIS_ 1
#define _HAVE_LIB_MD5 1

#include "md5global.h"
#include "md5_private.h"

#endif /* CONFIG_H */
