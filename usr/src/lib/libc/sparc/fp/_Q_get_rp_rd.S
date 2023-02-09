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

	.file	"_Q_get_rp_rd.s"

#include <sys/asm_linkage.h>

	ENTRY(_QgetRD)
	add     %sp,-SA(MINFRAME),%sp
        st      %fsr,[%sp+ARGPUSH]
        ld      [%sp+ARGPUSH],%o0	! o0 = fsr
        srl     %o0,30,%o0              ! return round control value
        retl
	add     %sp,SA(MINFRAME),%sp

	SET_SIZE(_QgetRD)
