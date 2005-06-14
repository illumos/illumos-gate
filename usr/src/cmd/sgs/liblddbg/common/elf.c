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
 *	Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"


static void
Elf_elf_data(const char *str1, Addr addr, Elf_Data *data, const char *file,
    const char *str2)
{
	dbg_print(MSG_INTL(MSG_ELF_ENTRY), str1, EC_ADDR(addr),
	    conv_d_type_str(data->d_type), EC_XWORD(data->d_size),
	    EC_OFF(data->d_off), EC_XWORD(data->d_align), file, str2);
}

void
Gelf_elf_data_title()
{
	dbg_print(MSG_INTL(MSG_ELF_TITLE));
}

void
_Dbg_elf_data_in(Os_desc *osp, Is_desc *isp)
{
	Shdr		*shdr = osp->os_shdr;
	Elf_Data	*data = isp->is_indata;
	const char	*file, *str;
	Addr		addr;

	if (isp->is_flags & FLG_IS_DISCARD) {
		str = MSG_INTL(MSG_ELF_IGNSCN);
		addr = 0;
	} else {
		str = MSG_ORIG(MSG_STR_EMPTY);
		addr = (Addr)(shdr->sh_addr + data->d_off);
	}

	if (isp->is_file && isp->is_file->ifl_name)
		file = isp->is_file->ifl_name;
	else
		file = MSG_ORIG(MSG_STR_EMPTY);

	Elf_elf_data(MSG_INTL(MSG_STR_IN), addr, data, file, str);
}

void
_Dbg_elf_data_out(Os_desc *osp)
{
	Shdr		*shdr = osp->os_shdr;
	Elf_Data	*data = osp->os_outdata;

	Elf_elf_data(MSG_INTL(MSG_STR_OUT), shdr->sh_addr,
	    data, MSG_ORIG(MSG_STR_EMPTY), MSG_ORIG(MSG_STR_EMPTY));
}

void
Gelf_elf_header(GElf_Ehdr *ehdr, GElf_Shdr *shdr0)
{
	Byte		*byte =	&(ehdr->e_ident[0]);
	const char	*flgs;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_ELF_HEADER));

	dbg_print(MSG_ORIG(MSG_ELF_MAGIC), byte[EI_MAG0],
	    (byte[EI_MAG1] ? byte[EI_MAG1] : '0'),
	    (byte[EI_MAG2] ? byte[EI_MAG2] : '0'),
	    (byte[EI_MAG3] ? byte[EI_MAG3] : '0'));
	dbg_print(MSG_ORIG(MSG_ELF_CLASS),
	    conv_eclass_str(ehdr->e_ident[EI_CLASS]),
	    conv_edata_str(ehdr->e_ident[EI_DATA]));
	dbg_print(MSG_ORIG(MSG_ELF_MACHINE),
	    conv_emach_str(ehdr->e_machine), conv_ever_str(ehdr->e_version));
	dbg_print(MSG_ORIG(MSG_ELF_TYPE), conv_etype_str(ehdr->e_type));

	/*
	 * Line up the flags differently depending on wether we
	 * received a numeric (e.g. "0x200") or text represent-
	 * ation (e.g. "[ EF_SPARC_SUN_US1 ]").
	 */
	flgs = conv_eflags_str(ehdr->e_machine, ehdr->e_flags);
	if (flgs[0] == '[')
		dbg_print(MSG_ORIG(MSG_ELF_FLAGS_FMT), flgs);
	else
		dbg_print(MSG_ORIG(MSG_ELF_FLAGS), flgs);

	if ((ehdr->e_shnum == 0) && (ehdr->e_shstrndx == SHN_XINDEX))
		dbg_print(MSG_ORIG(MSG_ELFX_ESIZE), EC_ADDR(ehdr->e_entry),
		    ehdr->e_ehsize);
	else
		dbg_print(MSG_ORIG(MSG_ELF_ESIZE), EC_ADDR(ehdr->e_entry),
		    ehdr->e_ehsize, ehdr->e_shstrndx);

	if ((ehdr->e_shnum == 0) && shdr0 && (shdr0->sh_size != 0))
		dbg_print(MSG_ORIG(MSG_ELFX_SHOFF), EC_OFF(ehdr->e_shoff),
		    ehdr->e_shentsize);
	else
		dbg_print(MSG_ORIG(MSG_ELF_SHOFF), EC_OFF(ehdr->e_shoff),
		    ehdr->e_shentsize, ehdr->e_shnum);

	dbg_print(MSG_ORIG(MSG_ELF_PHOFF), EC_OFF(ehdr->e_phoff),
	    ehdr->e_phentsize, ehdr->e_phnum);

	if ((ehdr->e_shnum != 0) || (shdr0 == NULL) ||
	    (shdr0->sh_size == 0))
		return;

	/*
	 * If we have Extended ELF headers - print shdr0
	 */
	dbg_print(MSG_ORIG(MSG_SHD0_TITLE));
	dbg_print(MSG_ORIG(MSG_SHD_ADDR), EC_ADDR(shdr0->sh_addr),
	    /* LINTED */
	    conv_secflg_str(ehdr->e_machine, shdr0->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD0_SIZE), EC_XWORD(shdr0->sh_size),
		conv_sectyp_str(ehdr->e_machine, shdr0->sh_type));
	dbg_print(MSG_ORIG(MSG_SHD_OFFSET), EC_OFF(shdr0->sh_offset),
	    EC_XWORD(shdr0->sh_entsize));
	if (ehdr->e_shstrndx == SHN_XINDEX)
		dbg_print(MSG_ORIG(MSG_SHD0_LINK), EC_WORD(shdr0->sh_link),
		    /* LINTED */
		    conv_secinfo_str(shdr0->sh_info, shdr0->sh_flags));
	else
		dbg_print(MSG_ORIG(MSG_SHD_LINK), EC_WORD(shdr0->sh_link),
		    /* LINTED */
		    conv_secinfo_str(shdr0->sh_info, shdr0->sh_flags));
	dbg_print(MSG_ORIG(MSG_SHD_ALIGN), EC_XWORD(shdr0->sh_addralign));
}
