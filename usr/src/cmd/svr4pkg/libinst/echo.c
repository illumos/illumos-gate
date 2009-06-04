/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



/*
 * System includes
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <zone.h>

/*
 * consolidation pkg command library includes
 */

#include "pkglib.h"

/*
 * internal global variables
 */

static boolean_t	debugFlag = B_FALSE;	/* debug messages enabled? */
static boolean_t	echoFlag = B_TRUE;	/* interactive msgs enabled? */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	echo
 * Synopsis:	Output an interactive message if interaction is enabled
 * Description:	Main method for outputting an interactive message; call to
 *		output interactive message if interation has not been disabled
 *		by a previous call to echoSetFlag(0).
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 */

/*PRINTFLIKE1*/
void
echo(char *fmt, ...)
{
	va_list ap;

	/* output message if echoing is enabled */

	if (echoFlag == B_TRUE) {
		va_start(ap, fmt);

		(void) vfprintf(stderr, fmt, ap);

		va_end(ap);

		(void) putc('\n', stderr);
	}
}

/*
 * Name:	echoDebug
 * Synopsis:	Output a debugging message if debugging is enabled
 * Description:	Main method for outputting a debugging message; call to
 *		output debugging message if debugging has been enabled
 *		by a previous call to echoDebugSetFlag(1).
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 * NOTE:	format of message will be:
 *			# [ aaa bbb ccc ] message
 *		where:	aaa - process i.d.
 *			bbb - zone i.d.
 *			ccc - name of program
 * 		for example:
 *			# [ 25685   0 pkgadd     ] unable to get package list
 */

/*PRINTFLIKE1*/
void
echoDebug(char *a_fmt, ...)
{
	va_list ap;

	/* output debugging message if debugging is enabled */

	if (debugFlag == B_TRUE) {
		char	*p = get_prog_name();

		(void) fprintf(stderr, "# [%6d %3d", getpid(), getzoneid());

		if ((p != (char *)NULL) && (*p != '\0')) {
			fprintf(stderr, " %-11s", p);
		}

		(void) fprintf(stderr, "] ");

		va_start(ap, a_fmt);

		(void) vfprintf(stderr, a_fmt, ap);

		va_end(ap);

		(void) putc('\n', stderr);
	}
}

/*
 * get the "interactive message enabled" flag
 */

boolean_t
echoGetFlag(void) {
	return (echoFlag);
}

/*
 * set the "interactive message enabled" flag
 */

boolean_t
echoSetFlag(boolean_t a_echoFlag)
{
	boolean_t	oldvalue;

	oldvalue = echoFlag;
	echoFlag = a_echoFlag;
	return (oldvalue);
}

/*
 * get the "debugging message enabled" flag
 */

boolean_t
echoDebugGetFlag(void) {
	return (debugFlag);
}

/*
 * set the "debugging message enabled" flag
 */

boolean_t
echoDebugSetFlag(boolean_t a_debugFlag)
{
	boolean_t	oldvalue;

	oldvalue = debugFlag;
	debugFlag = a_debugFlag;
	return (oldvalue);
}
