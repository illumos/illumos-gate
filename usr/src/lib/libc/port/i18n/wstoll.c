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

#pragma weak _wstoll = wstoll
#pragma weak _watoll = watoll

#include "lint.h"
#include <wchar.h>
#include <widec.h>

#undef watoll

/*
 * watoll() is defined as a macro in <widec.h> from 4/94.
 * It was a real function in libc in the earlier releases.
 * For binary comapatibility of the apps that were compiled
 * with earlier releases of Solaris 2.x which had watoll,
 * we provide watoll() as a function here as well.
 * PSARC opinion: PSARC/1993/121, approved on 3/11/93
 */
long long
watoll(const wchar_t *p)
{
	return (wcstoll(p, NULL, 10));
}

long long
wstoll(const wchar_t *str, wchar_t **ptr, int base)
{
	return (wcstoll(str, ptr, base));
}
