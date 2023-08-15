/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/* config.h.  Generated from config.h.in by configure.  */
/* #undef _SOCKADDR_LEN */
#define HAVE_FCNTL_H 1
/* #undef HAVE_PATHS_H */
#define HAVE_INTTYPES_H 1
#define HAVE_STROPTS_H 1
/* #undef HAVE_SYS_TIMERS_H */
#define HAVE_SYS_SELECT_H 1
#define HAVE_MEMORY_H 1
/* #undef SYS_CDEFS_H */
#define _POSIX_PTHREAD_SEMANTICS 1
#define POSIX_GETPWUID_R 1
#define POSIX_GETPWNAM_R 1
#define POSIX_GETGRGID_R 1
#define POSIX_GETGRNAM_R 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMCHR 1
/* #undef SPRINTF_CHAR */
/* #undef VSPRINTF_CHAR */
#define USE_SYSERROR_LIST 1
/* #undef NEED_STRTOUL */
/* #undef NEED_SUN4PROTOS */
/* #undef REENABLE_SEND */

#define NEED_SETGROUPENT 1
#define NEED_GETGROUPLIST 1

/* define if prototype for getgrnam_r() is required */
/* #undef NEED_GETGRNAM_R  */
/* #undef NEED_GETGRGID_R  */
/* #undef NEED_GETGRENT_R  */
#define NEED_SETGRENT_R 1
#define NEED_ENDGRENT_R 1

#define NEED_INNETGR_R 1
/* #undef NEED_SETNETGRENT_R */
#define NEED_ENDNETGRENT_R 1

/* #undef NEED_GETPWNAM_R */
/* #undef NEED_GETPWUID_R */
#define NEED_SETPWENT_R 1
#define NEED_SETPASSENT_R 1
#define NEED_SETPWENT_R 1
/* #undef NEED_GETPWENT_R */
#define NEED_ENDPWENT_R 1

#define NEED_SETPASSENT 1

/* #undef HAS_PW_CLASS */

/* #undef ssize_t */
/* #undef uintptr_t */

/* Shut up warnings about sputaux in stdio.h on BSD/OS pre-4.1 */
/* #undef SHUTUP_SPUTAUX */
#ifdef SHUTUP_SPUTAUX
struct __sFILE;
extern __inline int __sputaux(int _c, struct __sFILE *_p);
#endif
#define BROKEN_IN6ADDR_INIT_MACROS 1
#define HAVE_STRLCAT 1
/* Shut up warnings about missing braces */
/* #undef SHUTUP_MUTEX_INITIALIZER */
#ifdef SHUTUP_MUTEX_INITIALIZER
#define LIBBIND_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }
#else
#define LIBBIND_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif

