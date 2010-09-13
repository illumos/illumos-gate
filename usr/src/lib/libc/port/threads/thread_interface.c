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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "thr_uberdata.h"

extern	int	_ti_bind_guard();
extern	int	_ti_bind_clear();
extern	int	_ti_thr_self();
extern	int	_ti_critical();

/*
 * This is the array of interface functions passed to
 * the dynamic linker via _ld_libc() (see libc_init()).
 */
const Lc_interface rtld_funcs[] = {
	{CI_VERSION,	(int(*)())CI_V_CURRENT},
	{CI_BIND_GUARD,	(int(*)())_ti_bind_guard},
	{CI_BIND_CLEAR,	(int(*)())_ti_bind_clear},
	{CI_THR_SELF,	(int(*)())_ti_thr_self},
	{CI_CRITICAL,	(int(*)())_ti_critical},
	{CI_NULL,	(int(*)())NULL}
};
