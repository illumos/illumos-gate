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
   
  $Id: hostacc.h,v 1.9 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
/*
 *  hostacc.h  -   Header file used in the implementation of
 *                 host access for the WU-FTPD FTP daemon
 *
 * INITIAL AUTHOR - Bart Muijzer    <bartm@cv.ruu.nl>
 */

#ifdef  HOST_ACCESS

#include <stdio.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "pathnames.h"		/* From the ftpd sources    */

/*
 * Host Access types, as stored in the ha_type field, 
 * and some other constants. All of this is tunable as
 * long as you don't depend on the values.
 */

#define ALLOW   1
#define DENY    2

#define MAXLEN  1024		/* Maximum length of one line in config file */
#define MAXHST  12		/* Max. number of hosts allowed on one line  */

/* ------------------------------------------------------------------------- */

/*
 * Structure holding all host-access information 
 */

typedef struct {
    short ha_type;		/* ALLOW | DENY             */
    char *ha_login;		/* Loginname to investigate */
    char *ha_hosts[MAXHST];	/* Array of hostnames       */
} hacc_t;

/* ------------------------------------------------------------------------ */

static int sethacc(void);
static int endhacc(void);
static hacc_t *gethacc(void);
static void fatalmsg(char *pcMsg);
static char *strnsav(char *pcStr, int iLen);

#endif /* HOST_ACCESS */
