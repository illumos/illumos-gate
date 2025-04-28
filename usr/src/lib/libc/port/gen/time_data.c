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
/*	  All Rights Reserved	*/

#include	"lint.h"
#include	<time.h>
#include	<tzfile.h>
/*
 * This file contains constant data used by the functions in localtime.c.
 * The data is in a separate file to get around a limitation in the current
 * compiler; when a file is compiled with -KPIC, it doesn't have enough
 * information to know that it can put const arrays in rodata.  The amount
 * of data has an impact on dynamic shared library performance
 */

const int	__mon_lengths[2][MONSPERYEAR] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

const int	__year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};

const int __yday_to_month[12] = {0, 31, 59, 90, 120, 151, 181, 212,
					243, 273, 304, 334};
const int __lyday_to_month[12] = {0, 31, 60, 91, 121, 152, 182, 213,
					244, 274, 305, 335};
