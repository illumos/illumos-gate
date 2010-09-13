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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <thread.h>
#undef t_errno

/*
 * transport errno
 */

int t_errno = 0;

/*
 * TLI Interface exposes "t_nerr" and "t_errlist" which is a poor
 * choice. XTI fixes that and only documents t_error() and t_strerror()
 * as interface. We leave these variables here alone here. We create
 * replica of these as a subset for use by XTI in t_strerror(). The
 * first part of the replica is same as here.
 * The rest of the errors are defined only in XTI.
 */
int t_nerr = 19;

/*
 * transport interface error list
 */

char *t_errlist[] = {
	"No Error",					/*  0 */
	"Incorrect address format",			/*  1 */
	"Incorrect options format",			/*  2 */
	"Illegal permissions",				/*  3 */
	"Illegal file descriptor",			/*  4 */
	"Couldn't allocate address",			/*  5 */
	"Routine will place interface out of state",    /*  6 */
	"Illegal called/calling sequence number",	/*  7 */
	"System error",					/*  8 */
	"An event requires attention",			/*  9 */
	"Illegal amount of data",			/* 10 */
	"Buffer not large enough",			/* 11 */
	"Can't send message - (blocked)",		/* 12 */
	"No message currently available",		/* 13 */
	"Disconnect message not found",			/* 14 */
	"Unitdata error message not found",		/* 15 */
	"Incorrect flags specified",			/* 16 */
	"Orderly release message not found",		/* 17 */
	"Primitive not supported by provider",		/* 18 */
	"State is in process of changing",		/* 19 */
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	""
	/*
	 *	N.B.:  t_errlist must not expand beyond this point or binary
	 *	compatibility will be broken.  When necessary to accomodate
	 *	more error strings, they may only be added to the list printed
	 *	by t_strerror(), q.v..  Currently, t_strerror() conserves space
	 *	by pointing into t_errlist[].  To expand beyond 57 errors, it
	 *	will be necessary to change t_strerror() to use a different
	 *	array.
	 */
};


int *
__t_errno(void)
{
	static pthread_key_t t_errno_key = PTHREAD_ONCE_KEY_NP;
	int *ret;

	if (thr_main())
		return (&t_errno);
	ret = thr_get_storage(&t_errno_key, sizeof (int), free);
	/* if thr_get_storage fails we return the address of t_errno */
	return (ret ? ret : &t_errno);
}
