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
   
  $Id: paths.c,v 1.7 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
/*
 * paths.c - setting up the correct pathing to support files/directories
 *
 * INITAL AUTHOR - Kent Landfield  <kent@landfield.com>
 */
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>

#include "pathnames.h"
#include "proto.h"

#ifdef  VIRTUAL

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int virtual_mode = 0;
int virtual_ftpaccess = 0;

extern int debug;
extern char virtual_hostname[];
extern char virtual_address[];

#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/*
   ** Pathing storage
 */

#define _PATHS_DEFINED_ 1
char _path_ftpaccess[MAXPATHLEN];
char _path_ftpusers[MAXPATHLEN];
char _path_ftphosts[MAXPATHLEN];
char _path_private[MAXPATHLEN];
char _path_cvt[MAXPATHLEN];

extern char logfile[];
extern char hostname[];

void setup_paths(void);

/* 
   ** Virtual hosting has to support many different types of needs. There
   ** must be complete support for the various ftpd system files and their
   ** functionality. 
   **
   ** Full support on a virtual host basis:
   ** -------------------------------------
   **  _PATH_FTPACCESS  
   **  _PATH_FTPUSERS   
   **  _PATH_PRIVATE    
   **  _PATH_FTPHOSTS   
   **  _PATH_CVT        
   **
   ** Set in a site's ftpaccess file
   **  _PATH_XFERLOG   
   **
   ** Supported on a site basis:
   ** --------------------------
   **  _PATH_FTPSERVERS 
   **  _PATH_EXECPATH   
   **  _PATH_PIDNAMES  
   **  _PATH_UTMP     
   **  _PATH_WTMP    
   **  _PATH_LASTLOG  
   **  _PATH_BSHELL   
   **  _PATH_DEVNULL  
 */

/* ------------------------------------------------------------------------ */
/* FUNCTION  : setup_paths                                                  */
/* PURPOSE   : Determine appropriate paths to various configuration files.  */
/* ARGUMENTS : None                                                         */
/* RETURNS   : None                                                         */
/* ------------------------------------------------------------------------ */

void setup_paths(void)
{
#ifdef VIRTUAL
    char *sp;
    char configdir[MAXPATHLEN];
    char filepath[MAXPATHLEN];
#ifdef INET6
    char hostaddress[INET6_ADDRSTRLEN];
#else
    char hostaddress[32];
#endif
    FILE *svrfp;
    struct stat st;
#if defined(UNIXWARE) || defined(AIX)
    size_t virtual_len;
#else
    int virtual_len;
#endif
    struct SOCKSTORAGE virtual_addr;
#endif

    (void) strlcpy(_path_ftpaccess, _PATH_FTPACCESS, sizeof(_path_ftpaccess));
    (void) strlcpy(_path_ftpusers, _PATH_FTPUSERS, sizeof(_path_ftpusers));
    (void) strlcpy(_path_private, _PATH_PRIVATE, sizeof(_path_private));
    (void) strlcpy(_path_cvt, _PATH_CVT, sizeof(_path_cvt));
    (void) strlcpy(logfile, _PATH_XFERLOG, MAXPATHLEN);
    (void) strlcpy(_path_ftphosts, _PATH_FTPHOSTS, sizeof(_path_ftphosts));

#ifdef VIRTUAL
    /*
       ** Open PATH_FTPSERVERS config file.  If the file does not 
       ** exist then revert to using the standard _PATH_* path defines.
     */

    if ((svrfp = fopen(_PATH_FTPSERVERS, "r")) != NULL) {
	/*
	   ** OK.  The ftpservers file exists and is open.
	   ** 
	   ** Format of the file is:
	   **    ipaddr/hostname   directory-containing-configuration-files
	   **
	   **    208.196.145.10   /etc/ftpd/ftpaccess.somedomain/
	   **    208.196.145.200  /etc/ftpd/ftpaccess.someotherdomain/
	   **    some.domain      INTERNAL
	   ** 
	   ** Parse the file and try to match the IP address to one found 
	   ** in the file.  If a match is found then return the path to
	   ** the specified directory that contains the configuration files
	   ** for that specific domain.  If a match is not found, or an invalid
	   ** directory path is encountered like above, return standard paths.
	   **
	   ** As usual, comments and blanklines are ignored.
	 */

	/* get our address */

	virtual_len = sizeof(virtual_addr);
	if (getsockname(0, (struct sockaddr *) &virtual_addr, &virtual_len) == 0) {
	    while (read_servers_line(svrfp, hostaddress, sizeof(hostaddress),
		   configdir, sizeof(configdir)) == 1) {
		if (!strcmp(hostaddress, inet_stop(&virtual_addr))) {
		    if (debug)
			syslog(LOG_DEBUG, "VirtualFTP Connect to: %s", hostaddress);
		    (void) strlcpy(virtual_address, hostaddress,
				   MAXHOSTNAMELEN);
		    if (hostname != NULL) {
			/* reset hostname to this virtual name */
			wu_gethostbyaddr(&virtual_addr, hostname, MAXHOSTNAMELEN);
			(void) strlcpy(virtual_hostname, hostname,
				       MAXHOSTNAMELEN);
		    }

		    /* get rid of trailing slash */
		    sp = configdir + (strlen(configdir) - 1);
		    if (*sp == '/')
			*sp = '\0';

		    /* 
		       ** check to see that a valid directory value was
		       ** supplied and not something such as "INTERNAL"
		     */

		    if ((stat(configdir, &st) == 0) &&
			((st.st_mode & S_IFMT) == S_IFDIR)) {

			(void) snprintf(filepath, sizeof(filepath),
					"%s/ftpaccess", configdir);
			if (access(filepath, R_OK) == 0) {
			    (void) strlcpy(_path_ftpaccess, filepath,
					   sizeof(_path_ftpaccess));
			    virtual_mode = 1;
			    virtual_ftpaccess = 1;
			}

			(void) snprintf(filepath, sizeof(filepath),
					"%s/ftpusers", configdir);
			if (access(filepath, R_OK) == 0)
			    (void) strlcpy(_path_ftpusers, filepath,
					   sizeof(_path_ftpusers));

			(void) snprintf(filepath, sizeof(filepath),
					"%s/ftpgroups", configdir);
			if (access(filepath, R_OK) == 0)
			    (void) strlcpy(_path_private, filepath,
					   sizeof(_path_private));

			(void) snprintf(filepath, sizeof(filepath),
					"%s/ftphosts", configdir);
			if (access(filepath, R_OK) == 0)
			    (void) strlcpy(_path_ftphosts, filepath,
					   sizeof(_path_ftphosts));

			(void) snprintf(filepath, sizeof(filepath),
					"%s/ftpconversions", configdir);
			if (access(filepath, R_OK) == 0)
			    (void) strlcpy(_path_cvt, filepath,
					   sizeof(_path_cvt));
		    }
		    (void) fclose(svrfp);
		    return;
		}
	    }
	}
	(void) fclose(svrfp);
    }
#endif /* VIRTUAL */

    return;
}
