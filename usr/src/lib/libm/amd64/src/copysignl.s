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

	.file	"copysignl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(copysignl,function)
#include "libm_synonyms.h"

	ENTRY(copysignl)
	movl	16(%rsp),%eax
	movl	32(%rsp),%ecx
	andl	$0x7fff,%eax
	andl	$0x8000,%ecx
	orl	%ecx,%eax
	movl	%eax,16(%rsp)
	fldt	8(%rsp)
	ret
	.align	16
	SET_SIZE(copysignl)
