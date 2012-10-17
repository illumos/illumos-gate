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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012 Gary Mills
 */

#include "mt.h"
#include <xti.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* ARGSUSED1 */
int
_tx_error(const char *s, int api_semantics)
{
	const char *c;
	int errnum = errno;	/* In case a system call fails. */

	c = t_strerror(t_errno);
	if (s != NULL && *s != '\0') {
		(void) write(2, s, strlen(s));
		(void) write(2, ": ", 2);
	}
	(void) write(2, c, strlen(c));
	if (t_errno == TSYSERR) {
		c = strerror(errnum);
		(void) write(2, ": ", 2);
		(void) write(2, c, strlen(c));
	}
	(void) write(2, "\n", 1);
	return (0);
}
