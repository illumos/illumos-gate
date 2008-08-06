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
 */

	.file	"gethrtime.s"

#include "SYS.h"

/*
 * hrtime_t gethrtime(void)
 *
 * Returns the current hi-res real time.
 */

	ENTRY(gethrtime)
	SYSFASTTRAP(GETHRTIME)
#if defined(__sparcv9)
	/*
	 * Note that the fast trap actually assumes V8 parameter passing
	 * conventions, so we have to reassemble a 64-bit value here.
	 */
	sllx	%o0, 32, %o0
	or	%o1, %o0, %o0
#endif
	RET
	SET_SIZE(gethrtime)

/*
 * hrtime_t gethrvtime(void)
 *
 * Returns the current hi-res LWP virtual time.
 */

	ENTRY(gethrvtime)
	SYSFASTTRAP(GETHRVTIME)
#if defined(__sparcv9)
	/*
	 * Note that the fast trap actually assumes V8 parameter passing
	 * conventions, so we have to reassemble a 64-bit value here.
	 */
	sllx	%o0, 32, %o0
	or	%o1, %o0, %o0
#endif
	RET
	SET_SIZE(gethrvtime)
