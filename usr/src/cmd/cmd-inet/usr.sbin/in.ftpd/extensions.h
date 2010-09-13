/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
   
  $Id: extensions.h,v 1.12 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
#define LOG_IN  0
#define C_WD    1
#define BANNER  2

#ifndef ALIGN
#define ALIGN(x)        ((x) + (sizeof(long) - (x) % sizeof(long)))
#endif

#define O_COMPRESS              (1 << 0)	/* file was compressed */
#define O_UNCOMPRESS            (1 << 1)	/* file was uncompressed */
#define O_TAR                   (1 << 2)	/* file was tar'ed */

#define MAXARGS         50
#define MAXKWLEN        20

struct aclmember {
    struct aclmember *next;
    char keyword[MAXKWLEN];
    char *arg[MAXARGS];
};

#define ARG0    entry->arg[0]
#define ARG1    entry->arg[1]
#define ARG2    entry->arg[2]
#define ARG3    entry->arg[3]
#define ARG4    entry->arg[4]
#define ARG5    entry->arg[5]
#define ARG6    entry->arg[6]
#define ARG7    entry->arg[7]
#define ARG8    entry->arg[8]
#define ARG9    entry->arg[9]
#define ARG     entry->arg

/* Header at start of PID file */
struct pidfile_header {
    int     count;
    time_t  last_checked;
};

/* File transfer logging (xferlog) */
#include <sys/param.h>

#define MAXXFERSTRLEN	(MAXPATHLEN + 1024)
#define MAXSPACTCHARS	4

struct xferstat {
    char    *filename;
    char    access_mode;
    char    completion;
    char    transfer_direction;
    char    transfer_type;
    char    special_action[MAXSPACTCHARS];
    int     auth;
    int     transfer_time;
    off_t   filesize;
    off_t   restart_offset;
    off_t   transfer_bytes;
};
extern int xferdone;
extern char xferlog_format[];
extern struct xferstat xfervalues;

/* Type values for the various passive modes supported by the server */
#define TYPE_PASV	0
#ifdef INET6
#define TYPE_EPSV	1
#define TYPE_LPSV	2
#endif

#ifdef QUOTA
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef IRIX
#define QUOTA_BLOCKS
#define QUOTA_DEVICE
#include <mntent.h>
#include <sys/quota.h>
#endif

#ifdef SOLARIS_2
#define QUOTA_BLOCKS
#define QUOTA_DEVICE
#define HAS_OLDSTYLE_GETMNTENT
#define HAS_NO_QUOTACTL
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/fs/ufs_quota.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#ifdef SUNOS
#define QUOTA_BLOCKS
#define QUOTA_DEVICE
#include <mntent.h>
#include <ufs/quota.h>
#endif

#ifdef AIX
#include <jfs/quota.h>
#endif

#ifdef DIGITAL
#include <ufs/quota.h>
#endif

#ifdef BSDI
#include <ufs/ufs/quota.h>
#endif

#ifdef LINUX
#define QUOTA_DEVICE
#include <mntent.h>
#include <asm/types.h>
#ifdef HAVE_SYS_QUOTA_H
#include <sys/quota.h>
#else
#include <linux/quota.h>
#endif
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_QUOTA_H		/* This is defined only in the autoconf'ed build */
#include <sys/quota.h>
#endif
#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif

#endif /* QUOTA */
