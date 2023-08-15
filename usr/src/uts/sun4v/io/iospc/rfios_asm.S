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

/*
 * Assembly language support for the iospc IO performance counter driver.
 */

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include "rfios_acc.h"

/*LINTLIBRARY*/

	ENTRY(rfiospc_get_perfreg)
	mov	RFIOS_GET_PERFREG, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(rfiospc_get_perfreg)

	ENTRY(rfiospc_set_perfreg)
	mov	RFIOS_SET_PERFREG, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(rfiospc_set_perfreg)

