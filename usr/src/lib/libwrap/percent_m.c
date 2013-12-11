/*
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
 /*
  * Replace %m by system error message.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) percent_m.c 1.1 94/12/28 17:42:37";
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

extern int errno;

#include "mystdarg.h"

char   *percent_m(obuf, ibuf)
char   *obuf;
char   *ibuf;
{
    char   *bp = obuf;
    char   *cp = ibuf;

    while (*bp = *cp)
	if (*cp == '%' && cp[1] == 'm') {
	    strcpy(bp, strerror(errno));
	    bp += strlen(bp);
	    cp += 2;
	} else {
	    bp++, cp++;
	}
    return (obuf);
}
