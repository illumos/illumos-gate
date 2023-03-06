/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1993-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "assym.h"
#include <sys/machparam.h>

	!
	! this little hack generates a .note section where we tell
	! the booter what alignment we want
	!
	.section	".note"
	.align		4
	.word		.name_end - .name_begin
	.word		.desc_end - .desc_begin
	.word		ELF_NOTE_PAGESIZE_HINT
.name_begin:
	.asciz		ELF_NOTE_SOLARIS
.name_end:
	.align		4
	!
	! The pagesize is the descriptor.
	!
.desc_begin:
	.word		MMU_PAGESIZE4M
.desc_end:
	.align		4

