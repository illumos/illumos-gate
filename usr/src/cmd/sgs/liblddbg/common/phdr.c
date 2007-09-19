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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sgs.h>
#include	<_debug.h>
#include	<conv.h>
#include	<msg.h>

void
Elf_phdr(Lm_list *lml, Half mach, Phdr *phdr)
{
	Conv_inv_buf_t		inv_buf;
	Conv_phdr_flags_buf_t	phdr_flags_buf;

	dbg_print(lml, MSG_ORIG(MSG_PHD_VADDR), EC_ADDR(phdr->p_vaddr),
	    conv_phdr_flags(phdr->p_flags, 0, &phdr_flags_buf));
	dbg_print(lml, MSG_ORIG(MSG_PHD_PADDR), EC_ADDR(phdr->p_paddr),
	    conv_phdr_type(mach, phdr->p_type, 0, &inv_buf));
	dbg_print(lml, MSG_ORIG(MSG_PHD_FILESZ), EC_XWORD(phdr->p_filesz),
	    EC_XWORD(phdr->p_memsz));
	dbg_print(lml, MSG_ORIG(MSG_PHD_OFFSET), EC_OFF(phdr->p_offset),
	    EC_XWORD(phdr->p_align));
}
