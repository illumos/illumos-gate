/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* autoconf.h.  Generated automatically by configure.  */
/* autoconf.h.in.  Generated automatically from configure.in by autoheader.  */
/* Edited to remove KRB4 compatible and SIZEOF_LONG
 */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef gid_t */

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef uid_t */

#define ANSI_STDIO 1
#define HAS_SETVBUF 1
#define HAVE_STDLIB_H 1
#define HAVE_STRDUP 1
#define HAVE_LABS 1
#define HAS_VOID_TYPE 1

/* #undef KRB5_NO_PROTOTYPES */
#define KRB5_PROVIDE_PROTOTYPES 1
/* #undef KRB5_NO_NESTED_PROTOTYPES */
/* #undef NO_STDLIB_H */

/* #undef NO_YYLINENO */
#define POSIX_FILE_LOCKS 1
#define POSIX_SIGTYPE 1
#define POSIX_TERMIOS 1
#define POSIX_TYPES 1
#define USE_DIRENT_H 1

/* Define if dlopen should be used */
#define USE_DLOPEN 1

#define HAVE_STRING_H 1
#define WAIT_USES_INT 1
#define krb5_sigtype void
#define HAVE_UNISTD_H 1
#define KRB5_USE_INET 1
#define KRB5_USE_INET6 1

/* Solaris Kerberos  - 163 Resync */
#define LIBDIR "/usr/lib"

/* Type of getpeername second argument. */
#define GETPEERNAME_ARG2_TYPE GETSOCKNAME_ARG2_TYPE

/* Type of getpeername second argument. */
#define GETPEERNAME_ARG3_TYPE GETSOCKNAME_ARG3_TYPE

/* Type of pointer target for argument 2 to getsockname */
#define GETSOCKNAME_ARG2_TYPE struct sockaddr

/* Type of pointer target for argument 3 to getsockname */
#define GETSOCKNAME_ARG3_TYPE socklen_t

#define	HAVE_GETEUID	1

/* Define if you have the getaddrinfo function */
#define HAVE_GETADDRINFO 1

/* Define if gethostbyname_r exists and its return type is known */
#define HAVE_GETHOSTBYNAME_R 1

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define if getservbyname_r exists and its return type is known */
#define HAVE_GETSERVBYNAME_R 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <lber.h> header file. */
#define HAVE_LBER_H 1

/* Define to 1 if you have the `ldap_explode_dn' function. */
#define HAVE_LDAP_EXPLODE_DN 1

/* Define to 1 if you have the <ldap.h> header file. */
#define HAVE_LDAP_H 1

/* Define to 1 if you have the `ldap_url_parse_nodn' function. */
#define HAVE_LDAP_URL_PARSE_NODN 1

#define HAVE_STDARG_H 1
/* #undef HAVE_VARARGS_H */

/* Define if MIT Project Athena default configuration should be used */
/* #undef KRB5_ATHENA_COMPAT */

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* Define if you have the <dbm.h> header file.  */
/* #undef HAVE_DBM_H */

/* Define if you have the <macsock.h> header file.  */
/* #undef HAVE_MACSOCK_H */

/* Define if you have the <ndbm.h> header file.  */
#define HAVE_NDBM_H 1

/* Define if you have the <stddef.h> header file.  */
#define HAVE_STDDEF_H 1

/* Define if you have the <sys/file.h> header file.  */
#define HAVE_SYS_FILE_H 1

/* Define if you have the <sys/param.h> header file.  */
#define HAVE_SYS_PARAM_H 1

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define if you have the <xom.h> header file.  */
/* #undef HAVE_XOM_H */

/* Define if you have the dbm library (-ldbm).  */
/* #undef HAVE_LIBDBM */

/* Define if you have the ndbm library (-lndbm).  */
/* #undef HAVE_LIBNDBM */

/* Define if you have the nsl library (-lnsl).  */
#define HAVE_LIBNSL 1

/* Define if you have the socket library (-lsocket).  */
#define HAVE_LIBSOCKET 1

/* Define if you have <sys/filio.h> */
#define HAVE_SYS_FILIO_H 1

/* Define if you have socklen_t */
#define HAVE_SOCKLEN_T 1

/* Define if you have sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* SUNW14resync start */

/* Define if thread support enabled */
#define ENABLE_THREADS 1

/* Define if #pragma weak references work */
#define HAVE_PRAGMA_WEAK_REF 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the `pthread_mutexattr_setrobust_np' function. */
#define HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP 1

/* Define if pthread_mutexattr_setrobust_np is provided in the thread library.
   */
#define HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP_IN_THREAD_LIB 1

/* Define to 1 if you have the `pthread_mutex_lock' function. */
#define HAVE_PTHREAD_MUTEX_LOCK 1

/* Define to 1 if you have the `pthread_once' function. */
#define HAVE_PTHREAD_ONCE 1

/* Define to 1 if you have the `pthread_rwlock_init' function. */
#define HAVE_PTHREAD_RWLOCK_INIT 1

/* Define if pthread_rwlock_init is provided in the thread library. */
#define HAVE_PTHREAD_RWLOCK_INIT_IN_THREAD_LIB 1


/* XXX */
/* Define to the necessary symbol if this constant uses a non-standard name on
   your system. */
#undef PTHREAD_CREATE_JOINABLE

/* Define if link-time options for library finalization will be used */
#undef USE_LINKER_FINI_OPTION

/* Define if link-time options for library initialization will be used */
#undef USE_LINKER_INIT_OPTION

/* from MIT 1.4 configure CC=.../cc */
#define HAVE_PRAGMA_WEAK_REF 1
#define DELAY_INITIALIZER 1
#define USE_LINKER_INIT_OPTION 1
#define USE_LINKER_FINI_OPTION 1

#define USE_BUNDLE_ERROR_STRINGS 1
#ifndef KRB5_PRIVATE
#define KRB5_PRIVATE 1
#endif
/* SUNW14resync end */
