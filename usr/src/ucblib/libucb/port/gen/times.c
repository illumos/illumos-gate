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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/times.h>
#include "libc.h"

/*
 * Backwards compatible times.
 * BSD times() returns 0 if successful, vs sys5's times()
 * whih returns the elapsed real times in ticks.
 */

/*
 * This is defined in sys/_times.s
 * This extern cannot be in libc.h due to name conflict with synonyms.h
 */
extern int _times(struct tms *);

clock_t
times(struct tms *tmsp)
{
	int	error;

	errno = 0;
	if (!tmsp) {
		errno = EFAULT;
		return (-1);
	}

	error = _times(tmsp);
	return (error == -1 ? error : 0);
}
