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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "wish.h"
#include "token.h"

int
stubs(void)
{
	return (0);
}

int
(*ignoresigs())()
{
	return (NULL);
}

int
restoresigs()
{
	return (0);
}

int
osystem(void)
{
#ifdef _DEBUG
	_debug(stderr, "SYSTEM NOT IMPLEMENTED\n");
#endif
	return (0);
}

int
prompt(void)
{
#ifdef _DEBUG
	_debug(stderr, "PROMPT NOT WORKING\n");
#endif
	return (0);
}

int
suspend(void)
{
#ifdef _DEBUG
	_debug(stderr, "SUSPEND NOT IMPLEMENTED\n");
#endif
	return (0);
}

int
change_owns(void)
{
#ifdef _DEBUG
	_debug(stderr, "CHANGE_OWNS STUBBED OUT\n");
#endif
	return (0);
}

int
edit(void)
{
#ifdef _DEBUG
	_debug(stderr, "EDIT STUBBED OUT\n");
#endif
	return (0);
}
