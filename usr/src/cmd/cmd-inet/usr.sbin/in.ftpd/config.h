/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* src/config.h.  Generated automatically by configure.  */
/****************************************************************************  
 
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.org/license.html.
 
  $Id: config.h.in,v 1.31 2000/07/01 18:04:21 wuftpd Exp $
 
****************************************************************************/

#define SOLARIS_2
#define SVR4
#define HAVE_STATVFS
#define NO_UTMP
#define HAVE_FGETPWENT
#define HAVE_MKSTEMP
#define HAVE_SYS_SENDFILE_H

/*
 * Configuration file for autoconf - will be modified by configure
 */

#define HAVE_FCNTL_H 1
#define HAVE_DIRENT_H 1
#define HAVE_REGEX_H 1
#define TIME_WITH_SYS_TIME 1
/* #undef HAVE_SYS_TIME_H */
/* #undef HAVE_TIME_H */
/* #undef HAVE_MNTENT_H */
#define HAVE_SYS_MNTENT_H 1
#define HAVE_SYS_MNTTAB_H 1
/* #undef HAVE_NDIR_H */
#define HAVE_STRING_H 1
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_SYS_NDIR_H */
/* #undef HAVE_SYS_QUOTA_H */
#define HAVE_SYS_FS_UFS_QUOTA_H 1
/* #undef HAVE_UFS_QUOTA_H */
/* #undef HAVE_JFS_QUOTA_H */
/* #undef HAVE_UFS_UFS_QUOTA_H */
/* #undef HAVE_LINUX_QUOTA_H */
#define HAVE_STDLIB_H 1
#define HAVE_UNISTD_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_GLOB_H 1
#define HAVE_GRP_H 1
#define HAVE_SHADOW_H 1
/* #undef HAVE_VMSDIR_H */

/* #undef QUOTA_INODE */
#define QUOTA_DEVICE
#define QSORT_IS_VOID 1

#define HAVE_SIGPROCMASK 1
#define HAVE_VSNPRINTF 1
/* #undef HAVE_DIRFD */
/* #undef HAVE_FLOCK */
#define HAVE_FTW 1
#define HAVE_GETCWD 1
#define HAVE_GETDTABLESIZE 1
#define HAVE_GETRLIMIT 1
/* #undef HAVE_PSTAT */
#define HAVE_LSTAT 1
#define HAVE_VPRINTF 1
#define HAVE_SNPRINTF 1
#define HAVE_REGEX 1
#define HAVE_REGEXEC 1
#define HAVE_SETSID 1
#define HAVE_MEMMOVE 1
#define HAVE_STRTOUL 1
/* #undef HAVE_SIGLIST */
#define FACILITY LOG_DAEMON

#define HAVE_LIMITS_H 1
#define HAVE_VALUES_H 1
/* #undef HAVE_BSD_BSD_H */
#define HAVE_SYS_PARAM_H 1
/* #undef NEED_LIMITS_H */
/* #undef NEED_VALUES_H */
/* #undef NEED_BSD_BSD_H */
#define NEED_SYS_PARAM_H 1
#if defined(HAVE_SYS_PARAM_H) && defined(NEED_SYS_PARAM_H)
#include <sys/param.h>
#endif
#if defined(HAVE_VALUES_H) && defined(NEED_VALUES_H)
#include <values.h>
#endif
#if defined(HAVE_LIMITS_H) && defined(NEED_LIMITS_H)
#include <limits.h>
#endif
#if defined(HAVE_BSD_BSD_H) && defined(NEED_BSD_BSD_H)
#include <bsd/bsd.h>
#endif
/* #undef NBBY */

#define SIGNAL_TYPE void
#define HAVE_SETUID 1
#define HAVE_SETEUID 1
/* #undef HAVE_SETREUID */
/* #undef HAVE_SETRESUID */
#define HAVE_SETEGID 1
/* #undef HAVE_SETREGID */
/* #undef HAVE_SETRESGID */
#define HAVE_ST_BLKSIZE 1
#define HAVE_SYSCONF 1
#define HAVE_SYS_SYSTEMINFO_H 1
/* #undef HAVE_PATHS_H */
#define HAVE_SYSLOG_H 1
#define HAVE_SYS_SYSLOG_H 1
#define HAVE_FCHDIR 1
/* #undef HAVE_QUOTACTL */
#define HAS_OLDSTYLE_GETMNTENT
/* #undef HAS_PW_EXPIRE */
#define SHADOW_PASSWORD 1
#define AUTOCONF 1
#if _FILE_OFFSET_BITS == 64
#define L_FORMAT "lld"
#else
#define L_FORMAT "ld"
#endif
#define T_FORMAT "ld"
#define PW_UID_FORMAT "ld"
#define GR_GID_FORMAT "ld"

/* #undef HAVE_UT_UT_HOST */
#define HAVE_UT_UT_EXIT_E_TERMINATION 1

/* Here instead of everywhere: */
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Newer systems will have seteuid/setegid */
/* Older systems may have the BSD setreuid/setregid */
/* HP/UX has setresuid/setresgid */
/* Some SCO systems appearently have none of this.
   so if HAVE_SETUID is not defined we'll presume it's
   all needed since we're compiling support/sco.c */

#ifdef HAVE_SETUID

#ifndef HAVE_SETEUID
#ifdef HAVE_SETREUID
#define seteuid(euid) setreuid(-1,(euid))
#else
#ifdef HAVE_SETRESUID
#define seteuid(euid) setresuid(-1,(euid),-1)
#else
#error No seteuid() functions.
#endif
#endif
#endif

#ifndef HAVE_SETEGID
#ifdef HAVE_SETREGID
#define setegid(egid) setregid(-1,(egid))
#else
#ifdef HAVE_SETRESGID
#define setegid(egid) setresgid(-1,(egid),-1)
#else
#error No setegid() functions.
#endif
#endif
#endif

#endif /* HAVE_SETUID */

#ifndef HAVE_FCHDIR
#define HAS_NO_FCHDIR 1
#endif
#ifndef HAVE_QUOTACTL
#define HAS_NO_QUOTACTL
#endif
#ifdef HAVE_SYS_SYSTEMINFO_H
#define HAVE_SYSINFO 1
#endif
#ifndef HAVE_SETSID
#define NO_SETSID 1
#endif

#ifndef HAVE_MEMMOVE
#define memmove(a,b,c) bcopy(b,a,c)
#endif
#ifndef HAVE_STRTOUL
#define strtoul(a,b,c) (unsigned long)strtol(a,b,c)
#endif

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif

#define USE_PAM 1

/*
 * Socket macros which help with socket structure manipulation in a mixed
 * IPv4 / IPv6 environment.
 */
#ifdef INET6
#define HAVE_SIN6_SCOPE_ID
#ifdef HAVE__SS_FAMILY
#define ss_family __ss_family
#endif
#define SOCKSTORAGE sockaddr_storage
#define SOCK_FAMILY(ss) ((ss).ss_family)
#define SOCK_PORT(ss) ((ss).ss_family == AF_INET6 ? \
		     ((struct sockaddr_in6 *)&(ss))->sin6_port : \
		     ((struct sockaddr_in *)&(ss))->sin_port)
#define SOCK_LEN(ss) ((ss).ss_family == AF_INET6 ? \
		    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))
#define SOCK_ADDR(ss) ((ss).ss_family == AF_INET6 ? \
		     (void *)&((struct sockaddr_in6 *)&(ss))->sin6_addr : \
		     (void *)&((struct sockaddr_in *)&(ss))->sin_addr)
#define SET_SOCK_FAMILY(ss, family) (SOCK_FAMILY(ss) = (family))
#define SET_SOCK_PORT(ss, port) \
		((ss).ss_family == AF_INET6 ? \
		 (((struct sockaddr_in6 *)&(ss))->sin6_port = (port)) : \
		 (((struct sockaddr_in *)&(ss))->sin_port = (port)))
#define SET_SOCK_ADDR4(ss, addr) ((void)(sock_set_inaddr(&(ss), (addr))))
#define SET_SOCK_ADDR_ANY(ss) \
		((void)((ss).ss_family == AF_INET6 ? \
		 (void)(((struct sockaddr_in6 *)&(ss))->sin6_addr = \
			in6addr_any) : \
		 (void)(((struct sockaddr_in *)&(ss))->sin_addr.s_addr = \
			htonl(INADDR_ANY))))
#define SET_SOCK_SCOPE(dst, src) sock_set_scope(&(dst), &(src))
#else
#define SOCKSTORAGE sockaddr_in
#define SOCK_FAMILY(sin) ((sin).sin_family)
#define SOCK_PORT(sin) ((sin).sin_port)
#define SOCK_LEN(sin) (sizeof(sin))
#define SOCK_ADDR(sin) ((void *)&(sin).sin_addr)
#define SET_SOCK_FAMILY(sin, family) (SOCK_FAMILY(sin) = (family))
#define SET_SOCK_PORT(sin, port) ((sin).sin_port = (port))
#define SET_SOCK_ADDR4(sin, addr) ((sin).sin_addr = (addr))
#define SET_SOCK_ADDR_ANY(sin) ((sin).sin_addr.s_addr = htonl(INADDR_ANY))
#endif /* INET6 */

#define delay_signaling()
#define enable_signaling()

#include "wu_config.h"
