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
 
  $Id: authuser.h,v 1.4 2000/07/01 18:36:28 wuftpd Exp $
 
****************************************************************************/
#ifndef AUTHUSER_H
#define AUTHUSER_H

extern unsigned short auth_tcpport;

extern char *auth_xline(register char *user, register int fd, register long unsigned int *in);

extern int auth_fd(register int fd, register long unsigned int *in, register short unsigned int *local, register short unsigned int *remote);

extern char *auth_tcpuser(register long unsigned int in, register short unsigned int local, register short unsigned int remote);
#endif
