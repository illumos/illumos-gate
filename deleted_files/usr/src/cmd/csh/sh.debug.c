/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"


#ifdef TRACE
#include <stdio.h>
FILE *trace;
/*
 * Trace routines
 */
#define TRACEFILE "/tmp/trace.XXXXXX"

/*
 * Initialie trace file.
 * Called from main.
 */
void
trace_init(void)
{
	extern char *mktemp();
	char name[128];
	char *p;

	strcpy(name, TRACEFILE);
	p = mktemp(name);
	trace = fopen(p, "w");
}

/*
 * write message to trace file
 */
/*VARARGS1*/
void
tprintf(fmt,a,b,c,d,e,f,g,h,i,j)
     char *fmt;
{
	if (trace) {
		fprintf(trace, fmt, a,b,c,d,e,f,g,h,i,j);
		fflush(trace);
	}
}
#endif
