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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/elf_notes.h>

#include "assym.h"

/*
 * Tell the booter that we'd like to load unix on a large page.
 */
	.section        .note
	.align          4
	.4byte           .name1_end - .name1_begin
	.4byte           .desc1_end - .desc1_begin
	.4byte		ELF_NOTE_PAGESIZE_HINT
.name1_begin:
	.string         ELF_NOTE_SOLARIS
.name1_end:
	.align          4
.desc1_begin:
	.4byte		FOUR_MEG
.desc1_end:
	.align		4
