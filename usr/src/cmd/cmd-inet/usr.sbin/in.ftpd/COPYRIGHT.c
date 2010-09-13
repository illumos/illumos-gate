/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
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

  $Id: COPYRIGHT.c,v 1.7 2000/07/01 18:46:31 wuftpd Exp $
 
****************************************************************************/

#include <stdio.h>

void print_copyright(void);
extern char version[];

char *Copyright = "\n\
  Copyright (c) 1999,2000 WU-FTPD Development Group.\n\
  All rights reserved.\n\
\n\
  Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.\n\
  Use is subject to license terms.\n\
\n\
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994\n\
    The Regents of the University of California.\n\
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.\n\
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.\n\
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.\n\
  Portions Copyright (c) 1998 Sendmail, Inc.\n\
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.\n\
  Portions Copyright (c) 1997 by Stan Barber.\n\
  Portions Copyright (c) 1997 by Kent Landfield.\n\
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997\n\
    Free Software Foundation, Inc.  \n\
\n\
  Use and distribution of this software and its source code are governed \n\
  by the terms and conditions of the WU-FTPD Software License (\"LICENSE\").\n\
\n\
  If you did not receive a copy of the license, it may be obtained online\n\
  at http://www.wu-ftpd.org/license.html.\n";

void print_copyright(void)
{
    printf("%s\n", Copyright);
    printf("%s\n", version);
}
