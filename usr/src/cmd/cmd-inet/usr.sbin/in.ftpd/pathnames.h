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
   
  $Id: pathnames.h.in,v 1.5 2000/07/01 18:04:21 wuftpd Exp $  
   
****************************************************************************/

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifdef SOLARIS_2
#define UTMP_DIR        "/var/adm"
#define WTMP_DIR        "/var/adm"
#define LASTLOG_DIR     "/var/adm"
#else
#define UTMP_DIR        "/etc"
#define WTMP_DIR        "/usr/adm"
#define LASTLOG_DIR     "/usr/adm"
#endif

#define _PATH_EXECPATH  "/bin/ftp-exec"

#ifdef VIRTUAL
/*
   ** Virtual hosting requires to support many different types of customer.
   ** needs. There must be complete support for the various ftpd system files
   ** and their functionality.
   **
   ** Supported on an individual virtual host basis:
   ** ----------------------------------------------
   **  _PATH_FTPACCESS
   **  _PATH_FTPUSERS
   **  _PATH_PRIVATE
   **  _PATH_FTPHOSTS
   **  _PATH_CVT
   **
   ** Set in a site's ftpaccess file
   **  _PATH_XFERLOG
   **
   ** Supported on a site-wide basis:
   ** --------------------------------
   **  _PATH_FTPSERVERS
   **  _PATH_EXECPATH
   **  _PATH_PIDNAMES
   **  _PATH_UTMP
   **  _PATH_WTMP
   **  _PATH_LASTLOG
   **  _PATH_BSHELL
   **  _PATH_DEVNULL
   **
   ** Following are possibly overridden by VIRTUAL Hosting Configuation
   ** Edit accordingly.
 */
#endif

#undef _PATH_FTPUSERS
#undef _PATH_FTPACCESS
#undef _PATH_CVT
#undef _PATH_PRIVATE

#define _PATH_FTPUSERS  "/etc/ftpd/ftpusers"
#define _PATH_FTPACCESS "/etc/ftpd/ftpaccess"
#define _PATH_CVT       "/etc/ftpd/ftpconversions"
#define _PATH_PRIVATE   "/etc/ftpd/ftpgroups"

#ifdef VIRTUAL
#undef _PATH_FTPSERVERS
#define _PATH_FTPSERVERS "/etc/ftpd/ftpservers"
#endif

#ifdef  HOST_ACCESS
#undef _PATH_FTPHOSTS
#define _PATH_FTPHOSTS  "/etc/ftpd/ftphosts"
#endif

/* _PATH_FTPD_PIDFILE is only used if DAEMON is defined */

#define _PATH_PIDNAMES  "/var/run/ftp.pids-%s"
#define _PATH_FTPD_PID  "/var/run/ftpd.pid"
#define _PATH_XFERLOG   "/var/log/xferlog"

#ifndef _PATH_UTMP
#ifdef UTMP_FILE
#define _PATH_UTMP UTMP_FILE
#endif
#endif

#ifndef _PATH_WTMP
#ifdef WTMP_FILE
#define _PATH_WTMP WTMP_FILE
#endif
#endif

#if defined(sun) && defined(SOLARIS_2)
#ifndef _PATH_UTMP
#define _PATH_UTMP      UTMP_DIR"/utmp"
#endif
#ifndef _PATH_WTMP
#define _PATH_WTMP      WTMP_DIR"/wtmp"
#endif
#ifndef _PATH_LASTLOG
#define _PATH_LASTLOG   LASTLOG_DIR"/lastlog"
#endif
#else
#ifndef _PATH_UTMP
#define _PATH_UTMP      "/etc/utmp"
#endif
#ifndef _PATH_WTMP
#define _PATH_WTMP      "/usr/adm/wtmp"
#endif
#ifndef _PATH_LASTLOG
#define _PATH_LASTLOG   "/usr/adm/lastlog"
#endif
#endif

#ifndef _PATH_BSHELL
#define _PATH_BSHELL    "/bin/sh"
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL   "/dev/null"
#endif

#ifndef _PATHS_DEFINED_
extern char _path_ftpaccess[];
extern char _path_ftpusers[];
extern char _path_ftphosts[];
extern char _path_private[];
extern char _path_cvt[];
#endif
