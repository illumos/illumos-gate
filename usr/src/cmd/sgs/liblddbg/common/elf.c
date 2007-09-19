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
Elf_ehdr(Lm_list *lml, Ehdr *ehdr, Shdr *shdr0)
{
	Conv_inv_buf_t		inv_buf1, inv_buf2;
	Conv_ehdr_flags_buf_t	flags_buf;
	Conv_sec_flags_buf_t	sec_flags_buf;
	Byte			*byte =	&(ehdr->e_ident[0]);
	const char		*flgs;
	int			xshdr = 0;

	dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(lml, MSG_INTL(MSG_ELF_HEADER));

	dbg_print(lml, MSG_ORIG(MSG_ELF_MAGIC), byte[EI_MAG0],
	    (byte[EI_MAG1] ? byte[EI_MAG1] : '0'),
	    (byte[EI_MAG2] ? byte[EI_MAG2] : '0'),
	    (byte[EI_MAG3] ? byte[EI_MAG3] : '0'));
	dbg_print(lml, MSG_ORIG(MSG_ELF_CLASS),
	    conv_ehdr_class(ehdr->e_ident[EI_CLASS], 0, &inv_buf1),
	    conv_ehdr_data(ehdr->e_ident[EI_DATA], 0, &inv_buf2));
	dbg_print(lml, MSG_ORIG(MSG_ELF_MACHINE),
	    conv_ehdr_mach(ehdr->e_machine, 0, &inv_buf1),
	    conv_ehdr_vers(ehdr->e_version, 0, &inv_buf2));
	dbg_print(lml, MSG_ORIG(MSG_ELF_TYPE),
	    conv_ehdr_type(ehdr->e_type, 0, &inv_buf1));

	/*
	 * Line up the flags differently depending on whether we received a
	 * numeric (e.g. "0x200") or text representation (e.g.
	 * "[ EF_SPARC_SUN_US1 ]").
	 */
	flgs = conv_ehdr_flags(ehdr->e_machine, ehdr->e_flags, 0, &flags_buf);
	if (flgs[0] == '[')
		dbg_print(lml, MSG_ORIG(MSG_ELF_FLAGS_FMT), flgs);
	else
		dbg_print(lml, MSG_ORIG(MSG_ELF_FLAGS), flgs);

	/*
	 * The e_shnum, e_shstrndx and e_phnum entries may have a different
	 * meaning if extended sections exist.
	 */
	if (ehdr->e_shstrndx == SHN_XINDEX) {
		dbg_print(lml, MSG_ORIG(MSG_ELFX_ESIZE),
		    EC_ADDR(ehdr->e_entry), ehdr->e_ehsize);
		xshdr++;
	} else
		dbg_print(lml, MSG_ORIG(MSG_ELF_ESIZE), EC_ADDR(ehdr->e_entry),
		    ehdr->e_ehsize, ehdr->e_shstrndx);

	if (ehdr->e_shnum == 0) {
		dbg_print(lml, MSG_ORIG(MSG_ELFX_SHOFF), EC_OFF(ehdr->e_shoff),
		    ehdr->e_shentsize);
		xshdr++;
	} else
		dbg_print(lml, MSG_ORIG(MSG_ELF_SHOFF), EC_OFF(ehdr->e_shoff),
		    ehdr->e_shentsize, ehdr->e_shnum);

	if (ehdr->e_phnum == PN_XNUM) {
		dbg_print(lml, MSG_ORIG(MSG_ELFX_PHOFF), EC_OFF(ehdr->e_phoff),
		    ehdr->e_phentsize);
		xshdr++;
	} else
		dbg_print(lml, MSG_ORIG(MSG_ELF_PHOFF), EC_OFF(ehdr->e_phoff),
		    ehdr->e_phentsize, ehdr->e_phnum);

	if ((xshdr == 0) || (shdr0 == NULL))
		return;

	/*
	 * If we have Extended ELF headers - print shdr[0].
	 */
	dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_TITLE));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_ADDR), EC_ADDR(shdr0->sh_addr),
	    conv_sec_flags(shdr0->sh_flags, 0, &sec_flags_buf));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_SIZE), EC_XWORD(shdr0->sh_size),
	    conv_sec_type(ehdr->e_machine, shdr0->sh_type, 0, &inv_buf1));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_OFFSET), EC_OFF(shdr0->sh_offset),
	    EC_XWORD(shdr0->sh_entsize));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_LINK), EC_WORD(shdr0->sh_link),
	    EC_WORD(shdr0->sh_info));
	dbg_print(lml, MSG_ORIG(MSG_SHD0_ALIGN), EC_XWORD(shdr0->sh_addralign));
}
