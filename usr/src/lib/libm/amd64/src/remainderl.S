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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

        .file "remainderl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(remainderl,function)

	ENTRY(remainderl)
	fldt	24(%rsp)		/ load arg y
	fldt	8(%rsp)			/ load arg x
.rem_loop:
	fprem1				/ partial remainder
	fstsw	%ax			/ store status word
	andw	$0x400,%ax		/ check whether reduction complete
	jne	.rem_loop		/ while reduction incomplete, do fprem1
	fstp	%st(1)
	ret
	.align	16
	SET_SIZE(remainderl)
