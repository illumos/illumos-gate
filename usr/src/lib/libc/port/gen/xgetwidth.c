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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * _Xgetwidth calls _getwidth to get the values of environment variables
 * CSWIDTH, SCRWIDTH and PCWIDTH, and checks the values to fit C process
 * environment. This function is called only once in a program.
 */

/* #include "shlib.h" */
#include "lint.h"
#include <sys/types.h>
#include <euc.h>
#include <getwidth.h>
extern int _cswidth[];

void
_xgetwidth(void)
{
	eucwidth_t	_eucwidth;

	*_cswidth = 1; /* set to 1 when called */
	getwidth(&_eucwidth);

	if (_eucwidth._eucw1 <= 4)
		_cswidth[1] = _eucwidth._eucw1;
	if (_eucwidth._eucw2 <= 4)
		_cswidth[2] = _eucwidth._eucw2;
	if (_eucwidth._eucw3 <= 4)
		_cswidth[3] = _eucwidth._eucw3;
}
