/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

#define MSYNC	'\020'
/* maximum likely message - make sure you don't get run away input */
#define MAXIMSG	256

/*
 * read message routine used before a
 * protocol is agreed upon.
 *	msg	-> address of input buffer
 *	fn	-> input file descriptor 
 * returns:
 *	EOF	-> no more messages
 *	0	-> message returned
 */
int
imsg(msg, fn)
char *msg;
int fn;
{
	char c;
	int i;
	short fndsync;
	char *bmsg;

	fndsync = 0;
	bmsg = msg;
	CDEBUG(7, "imsg %s>", "");
	while ((i = (*Read)(fn, msg, sizeof(char))) == sizeof(char)) {
		*msg &= 0177;
		c = *msg;
		CDEBUG(7, "%s", c < 040 ? "^" : "");
		CDEBUG(7, "%c", c < 040 ? c | 0100 : c);
		if (c == MSYNC) { /* look for sync character */
			msg = bmsg;
			fndsync = 1;
			continue;
		}
		if (!fndsync)
			continue;

		if (c == '\0' || c == '\n') {
			*msg = '\0';
			return(0);
		}
		else
			msg++;

		if (msg - bmsg > MAXIMSG)	/* unlikely */
			return(FAIL);
	}
	/* have not found sync or end of message */
	if (i < 0) {
		CDEBUG(7, "\nimsg read error: %s\n", strerror(errno));
	}
	*msg = '\0';
	return(EOF);
}

/*
 * initial write message routine -
 * used before a protocol is agreed upon.
 *	type	-> message type
 *	msg	-> message body address
 *	fn	-> file descriptor
 * return: 
 *	Must always return 0 - wmesg (WMESG) looks for zero
 */
int
omsg(type, msg, fn)
char *msg;
char type;
int fn;
{
	char buf[BUFSIZ];

	(void) sprintf(buf, "%c%c%s", MSYNC, type, msg);
	DEBUG( 7, "omsg \"%s\"\n", &buf[1] );
	(*Write)(fn, buf, strlen(buf) + 1);
	return(0);
}

/*
 * null turnoff routine to be used for errors
 * during protocol selection.
 */
int
turnoff(void)
{
	return(0);
}
