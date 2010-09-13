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
 
  $Id: authenticate.c,v 1.9 2000/07/01 18:17:38 wuftpd Exp $
 
****************************************************************************/
#include "config.h"
#include <stdio.h>
#include <string.h>
#include "authuser.h"
#include "authenticate.h"
#include "proto.h"

#define AUTHNAMESIZE 100

char authuser[AUTHNAMESIZE];
int authenticated;

extern int disable_rfc931;
extern unsigned int timeout_rfc931;

/*
 * Ideally more authentication schemes would be called from here, with the
 * strongest called first.  One possible double-check would be to verify that
 * the results of all authentication calls (returning identical data!) are
 * checked against each other.
 */
int wu_authenticate(void)
{
    char *user;
#if USE_A_RFC931
    unsigned long in;
    unsigned short local, remote;
#endif /* USE_A_RFC931 */

    authenticated = 0;		/* this is a bitmask, one bit per method */

    user = "*";

#if USE_A_RFC931
    if (disable_rfc931 || (timeout_rfc931 == 0))
	user = "*";
    else if (auth_fd(0, &in, &local, &remote) == -1)
	user = "?";		/* getpeername/getsockname failure */
    else {
	if (!(user = auth_tcpuser(in, local, remote)))
	    user = "*";		/* remote host doesn't support RFC 931 */
	else
	    authenticated |= A_RFC931;
    }
#endif /* USE_A_RFC931 */

    strncpy(authuser, user, sizeof(authuser));
    authuser[AUTHNAMESIZE - 1] = '\0';
    return (0);
}
