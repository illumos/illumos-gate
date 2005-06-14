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
   
  $Id: timeout.c,v 1.5 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
#include "config.h"
#include "proto.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "extensions.h"

unsigned int timeout_idle = 900;	/* Command idle: 15 minutes */
unsigned int timeout_maxidle = 7200;	/* Command idle (MAX): 2 hours */
unsigned int timeout_data = 1200;	/* Data idle: 20 minutes */
unsigned int timeout_rfc931 = 10;	/* RFC931 session, total: 10 seconds */
unsigned int timeout_accept = 120;	/* Accepting data connection: 2 minutes */
unsigned int timeout_connect = 120;	/* Establishing data connection: 2 minutes */

void load_timeouts(void)
{
    struct aclmember *entry = NULL;
    while (getaclentry("timeout", &entry)) {
	if ((ARG0 != NULL) && (ARG1 != NULL)) {
	    unsigned long value = strtoul(ARG1, NULL, 0);
	    if (strcasecmp(ARG0, "rfc931") == 0)
		timeout_rfc931 = value;
	    else if (value > 0)
		if (strcasecmp(ARG0, "idle") == 0) {
		    timeout_idle = value;
		    if (timeout_maxidle < timeout_idle)
			timeout_maxidle = timeout_idle;
		}
		else if (strcasecmp(ARG0, "maxidle") == 0) {
		    timeout_maxidle = value;
		    if (timeout_idle > timeout_maxidle)
			timeout_idle = timeout_maxidle;
		}
		else if (strcasecmp(ARG0, "data") == 0)
		    timeout_data = value;
		else if (strcasecmp(ARG0, "accept") == 0)
		    timeout_accept = value;
		else if (strcasecmp(ARG0, "connect") == 0)
		    timeout_connect = value;
	}
    }
}
