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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routine for relocation types.
 */
#include	<stdio.h>
#include	<sys/elf_amd64.h>
#include	"_conv.h"
#include	"relocate_amd64_msg.h"

/*
 * Intel386 specific relocations.
 */
static const Msg rels[] = {
	MSG_R_AMD64_NONE,
	MSG_R_AMD64_64,
	MSG_R_AMD64_PC32,
	MSG_R_AMD64_GOT32,
	MSG_R_AMD64_PLT32,
	MSG_R_AMD64_COPY,
	MSG_R_AMD64_GLOB_DATA,
	MSG_R_AMD64_JUMP_SLOT,
	MSG_R_AMD64_RELATIVE,
	MSG_R_AMD64_GOTPCREL,
	MSG_R_AMD64_32,
	MSG_R_AMD64_32S,
	MSG_R_AMD64_16,
	MSG_R_AMD64_PC16,
	MSG_R_AMD64_8,
	MSG_R_AMD64_PC8,
	MSG_R_AMD64_DTPMOD64,
	MSG_R_AMD64_DTPOFF64,
	MSG_R_AMD64_TPOFF64,
	MSG_R_AMD64_TLSGD,
	MSG_R_AMD64_TLSLD,
	MSG_R_AMD64_DTPOFF32,
	MSG_R_AMD64_GOTTPOFF,
	MSG_R_AMD64_TPOFF32,
	MSG_R_AMD64_PC64,
	MSG_R_AMD64_GOTOFF64,
	MSG_R_AMD64_GOTPC32
};

const char *
conv_reloc_amd64_type_str(uint_t rel)
{
	static char	string[STRSIZE] = { '\0' };

	/*
	 * In order to assure that all values included in
	 * sys/elf_x86_64.h::R_AMD64_* are included in libconv/elfdump for
	 * decoding - we have the below #define trap.  Each time the rels[]
	 * table is updated, make sure the following entry is updated.
	 */

#if	(R_AMD64_NUM != (R_AMD64_GOTPC32 + 1))
#error	"R_AMD64_NUM has grown"
#endif

	if (rel >= R_AMD64_NUM)
		return (conv_invalid_str(string, STRSIZE, (Lword)rel, 0));
	else
		return (MSG_ORIG(rels[rel]));
}
