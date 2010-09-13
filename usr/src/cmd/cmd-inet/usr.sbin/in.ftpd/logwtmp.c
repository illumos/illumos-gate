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
  
  $Id: logwtmp.c,v 1.16 2000/07/01 18:17:39 wuftpd Exp $ 
  
****************************************************************************/
#include "config.h"

#include <sys/types.h>
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
#include <sys/stat.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include <utmp.h>
#ifdef SVR4
#ifndef NO_UTMPX
#include <utmpx.h>
#ifndef _SCO_DS
#include <sac.h>
#endif
#endif
#endif
#ifdef BSD
#include <strings.h>
#else
#include <string.h>
#endif
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "pathnames.h"
#include "proto.h"

#ifndef NO_UTMP
static int fd = -1;
#endif
#if defined(SVR4) && !defined(NO_UTMPX)
static int fdx = -1;
#endif

/* Modified version of logwtmp that holds wtmp file open after first call,
 * for use with ftp (which may chroot after login, but before logout). */

void wu_logwtmp(char *line, char *name, char *host, int login)
{
    struct stat buf;
#ifndef NO_UTMP
    struct utmp ut;
#endif

#if defined(SVR4) && !defined(NO_UTMPX)
    /*
     * Date: Tue, 09 Mar 1999 14:59:42 -0600
     * From: Chad Price <cprice@molbio.unmc.edu>
     * To: wu-ftpd@wugate.wustl.edu
     * Subject: Re: Problem w/ Solaris /var/adm/wtmpx and /usr/bin/last(1)
     * 
     * I've been running Sol 2.4 since it came out, and the 'last' command
     * has never worked correctly, for ftpd or logins either one.  wtmpx
     * often fails to close out sessions when the user logs out.  As a
     * result, I only use last to see who logged in, not who/when the
     * logout occurred.
     * 
     * When I first installed it, it was even worse, and they immediately
     * told me to patch the system.  This fixed it to semi-compus mentis,
     * but not to working order.  So I guess my conclusion is: ignore the
     * wtmpx / last log stuff on Solaris 2.4 (and other releases of Solaris
     * too from what I see in the comments), it's broken and always has
     * been.  I do of course stand ready to be corrected (in this case,
     * pointed to a patch which really does fix it.)
     *
     */
    struct utmpx utx;

    if (fdx < 0 && (fdx = open(WTMPX_FILE, O_WRONLY | O_APPEND, 0)) < 0) {
	syslog(LOG_ERR, "wtmpx %s %m", WTMPX_FILE);
	return;
    }

    if (fstat(fdx, &buf) == 0) {
	memset((void *) &utx, '\0', sizeof(utx));
	(void) strncpy(utx.ut_user, name, sizeof(utx.ut_user));
	(void) strncpy(utx.ut_host, host, sizeof(utx.ut_host));
	(void) strncpy(utx.ut_id, "ftp", sizeof(utx.ut_id));
	(void) strncpy(utx.ut_line, line, sizeof(utx.ut_line));
	utx.ut_syslen = strlen(utx.ut_host) + 1;
	utx.ut_pid = getpid();
	(void) time(&utx.ut_tv.tv_sec);
	if (login /* name && *name */ ) {
	    utx.ut_type = USER_PROCESS;
	}
	else {
	    utx.ut_type = DEAD_PROCESS;
	}
	utx.ut_exit.e_termination = 0;
	utx.ut_exit.e_exit = 0;
	if (write(fdx, (char *) &utx, sizeof(struct utmpx)) !=
	    sizeof(struct utmpx))
	          (void) ftruncate(fdx, buf.st_size);
    }
#endif /* defined(SVR4) && !defined(NO_UTMPX) */

#ifndef NO_UTMP
#ifdef __FreeBSD__
    if (strlen(host) > UT_HOSTSIZE) {
	if ((host = inet_htop(host)) == NULL)
	    host = "invalid hostname";
    }
#endif

    if (fd < 0 && (fd = open(_PATH_WTMP, O_WRONLY | O_APPEND, 0)) < 0) {
	syslog(LOG_ERR, "wtmp %s %m", _PATH_WTMP);
	return;
    }
    if (fstat(fd, &buf) == 0) {
#ifdef UTMAXTYPE
	memset((void *) &ut, 0, sizeof(ut));
#ifdef LINUX
	(void) strncpy(ut.ut_id, "", sizeof(ut.ut_id));
#else
	(void) strncpy(ut.ut_id, "ftp", sizeof(ut.ut_id));
#endif
	(void) strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	ut.ut_pid = getpid();
	if (login /* name && *name */ ) {
	    (void) strncpy(ut.ut_user, name, sizeof(ut.ut_user));
	    ut.ut_type = USER_PROCESS;
	}
	else
	    ut.ut_type = DEAD_PROCESS;
#if defined(HAVE_UT_UT_EXIT_E_TERMINATION) || (!defined(AUTOCONF) && !defined(LINUX))
	ut.ut_exit.e_termination = 0;
	ut.ut_exit.e_exit = 0;
#endif
#else
	(void) strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	if (login) {
	    (void) strncpy(ut.ut_name, name, sizeof(ut.ut_name));
	}
	else {
	    (void) strncpy(ut.ut_name, "", sizeof(ut.ut_name));
	}
#endif /* UTMAXTYPE */
#ifdef HAVE_UT_UT_HOST		/* does have host in utmp */
	if (login) {
	    (void) strncpy(ut.ut_host, host, sizeof(ut.ut_host));
	}
	else {
	    (void) strncpy(ut.ut_host, "", sizeof(ut.ut_host));
	}
#endif
	(void) time(&ut.ut_time);
	if (write(fd, (char *) &ut, sizeof(struct utmp)) !=
	    sizeof(struct utmp))
	         (void) ftruncate(fd, buf.st_size);
    }
#endif /* NO_UTMP */
}
