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

	.file	"_lgrp_home_fast.s"

/*
 * C library -- gethomelgroup
 * lgrpid_t gethomelgroup()
 * lgrp_id_t _lgrp_home_fast()
 */

#include "SYS.h"

	ANSI_PRAGMA_WEAK(gethomelgroup,function)

/*
 * lgrp_id_t _lgrp_home_fast(void)
 * lgrpid_t gethomelgroup(void)
 *
 * Returns the home lgroup id for caller using fast trap
 * XXX gethomelgroup() being replaced by lgrp_home() XXX
 */

	ENTRY2(_lgrp_home_fast,gethomelgroup)
	SYSFASTTRAP(GETLGRP)		/* share fast trap with getcpuid */
	RET2				/* return rval2 */
	SET_SIZE(_lgrp_home_fast)
	SET_SIZE(gethomelgroup)
