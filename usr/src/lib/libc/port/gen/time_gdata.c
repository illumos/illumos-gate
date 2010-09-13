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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _altzone = altzone
#pragma weak _daylight = daylight
#pragma weak _timezone = timezone
#pragma weak _tzname = tzname

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <time.h>
#include <synch.h>

long int	timezone = 0;	/* XPG4 version 2 */
long int	altzone = 0;	/* follow suit */
int 		daylight = 0;
extern const char _tz_gmt[];
extern const char _tz_spaces[];
char 		*tzname[2] = {(char *)_tz_gmt, (char *)_tz_spaces};

mutex_t _time_lock = DEFAULTMUTEX;
