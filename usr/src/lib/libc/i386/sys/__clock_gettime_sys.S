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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

	.file	"__clock_gettime_sys.s"

#include <sys/asm_linkage.h>
#include <sys/time_impl.h>
#include "SYS.h"

/*
 * int
 * __sys_clock_gettime(clockid_t clock_id, timespec_t *tp)
 */

	ENTRY(__clock_gettime_sys)
	movl	4(%esp), %eax
	cmpl	$__CLOCK_REALTIME0, %eax	/* if (clock_id) */
	je	2f				/* equal to __CLOCK_REALTIME0 */
	cmpl	$CLOCK_REALTIME, %eax		/* or if (clock_id) */
	jne	1f				/* equal to CLOCK_REALTIME */
2:
	SYSFASTTRAP(GETHRESTIME)
	movl	8(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	RETC
1:
	SYSTRAP_RVAL1(clock_gettime)
	SYSCERROR
	RETC
	SET_SIZE(__clock_gettime_sys)
