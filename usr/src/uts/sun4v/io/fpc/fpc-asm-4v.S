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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Assembly language support for sun4v px driver
 */

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include <sys/hypervisor_api.h>
#include "fpc-impl-4v.h"

/*LINTLIBRARY*/

	/*
	 * fpc_get_fire_perfreg(devhandle_t dev_hdl, int regid, uint64_t *data)
	 */
	ENTRY(fpc_get_fire_perfreg)
	mov	FIRE_GET_PERFREG, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(fpc_get_fire_perfreg)

	/*
	 * fpc_set_fire_perfreg(devhandle_t dev_hdl, int regid, uint64_t data)
	 */
	ENTRY(fpc_set_fire_perfreg)
	mov	FIRE_SET_PERFREG, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(fpc_set_fire_perfreg)


