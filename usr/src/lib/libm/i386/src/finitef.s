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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

        .file "finitef.s"

#include "libm.h"

	ENTRY(finitef)
        movl    4(%esp),%eax		/ eax <-- x
        notl	%eax			/ not(bexp) = 0 iff bexp = all 1's
        andl    $0x7f800000,%eax	/ ZF <-- 1      iff not(bexp) = 0
        jz	.done			/ no jump if arg. is finite
        movl	$1,%eax			/ %ax was 0; ansi needs %eax = 1
.done:
        ret
	.align	4
	SET_SIZE(finitef)
