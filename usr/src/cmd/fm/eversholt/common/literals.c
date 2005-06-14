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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * literals.c -- literals initialization module
 *
 * this file intializes all the literals so they are stored in the
 * string table.  instead of using:
 * 	stable("fault")
 * other modules can use:
 * 	L_fault
 * and avoid repeated calls to stable().
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "out.h"
#include "stable.h"
#define	L_DECL(s) const char *L_##s
#include "literals.h"

void
literals_init()
{

/*
 * this turns the statements like:
 *	extern const char *L_something;
 * in literals.h into initialization statements like:
 *	L_something = stable("something");
 *
 */
#undef	_ESC_COMMON_LITERALS_H
#undef	L_DECL
#define	L_DECL(s) L_##s = stable(#s)

#include "literals.h"

}

void
literals_fini(void)
{
}
