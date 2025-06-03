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

	.file	"__gethrtime_sys.s"

#include "SYS.h"

/*
 * hrtime_t __gethrtime_sys(void)
 *
 * Returns the current hi-res real time (via fasttrap).
 *
 * This is intended as a fallback options for cases where hrtime calculation
 * via the comm page is not possible.
 */
	ENTRY(__gethrtime_sys)
	SYSFASTTRAP(GETHRTIME)
	RET
	SET_SIZE(__gethrtime_sys)
