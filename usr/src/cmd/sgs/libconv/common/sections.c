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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routines for section attributes.
 */
#include	<string.h>
#include	<sys/param.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<_conv.h>
#include	<sections_msg.h>

static const Msg secs[SHT_NUM] = {
	MSG_SHT_NULL,		MSG_SHT_PROGBITS,	MSG_SHT_SYMTAB,
	MSG_SHT_STRTAB,		MSG_SHT_RELA,		MSG_SHT_HASH,
	MSG_SHT_DYNAMIC,	MSG_SHT_NOTE,		MSG_SHT_NOBITS,
	MSG_SHT_REL,		MSG_SHT_SHLIB,		MSG_SHT_DYNSYM,
	MSG_SHT_UNKNOWN12,	MSG_SHT_UNKNOWN13,	MSG_SHT_INIT_ARRAY,
	MSG_SHT_FINI_ARRAY,	MSG_SHT_PREINIT_ARRAY,	MSG_SHT_GROUP,
	MSG_SHT_SYMTAB_SHNDX
};
#if	(SHT_NUM != (SHT_SYMTAB_SHNDX + 1))
#error	"SHT_NUM has grown"
#endif

static const Msg usecs[SHT_HISUNW - SHT_LOSUNW + 1] = {
	MSG_SHT_SUNW_dof,	MSG_SHT_SUNW_cap,	MSG_SHT_SUNW_SIGNATURE,
	MSG_SHT_SUNW_ANNOTATE,	MSG_SHT_SUNW_DEBUGSTR,	MSG_SHT_SUNW_DEBUG,
	MSG_SHT_SUNW_move,	MSG_SHT_SUNW_COMDAT,	MSG_SHT_SUNW_syminfo,
	MSG_SHT_SUNW_verdef,	MSG_SHT_SUNW_verneed,	MSG_SHT_SUNW_versym
};
#if	(SHT_LOSUNW != SHT_SUNW_dof)
#error	"SHT_LOSUNW has moved"
#endif

const char *
conv_sec_type(Half mach, Word sec)
{
	static char	string[CONV_INV_STRSIZE];

	if (sec < SHT_NUM)
		return (MSG_ORIG(secs[sec]));
	else if ((sec >= SHT_LOSUNW) && (sec <= SHT_HISUNW))
		return (MSG_ORIG(usecs[sec - SHT_LOSUNW]));
	else if ((sec >= SHT_LOPROC) && (sec <= SHT_HIPROC)) {
		if ((sec == SHT_SPARC_GOTDATA) && ((mach == EM_SPARC) ||
		    (mach == EM_SPARC32PLUS) || (mach == EM_SPARCV9)))
			return (MSG_ORIG(MSG_SHT_SPARC_GOTDATA));
		else if ((sec == SHT_AMD64_UNWIND) && (mach == EM_AMD64))
			return (MSG_ORIG(MSG_SHT_AMD64_UNWIND));
		else
			return (conv_invalid_val(string, CONV_INV_STRSIZE,
			    sec, 0));
	} else
		return (conv_invalid_val(string, CONV_INV_STRSIZE, sec, 0));
}

#define	FLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_SHF_WRITE_SIZE + \
		MSG_SHF_ALLOC_SIZE + \
		MSG_SHF_EXECINSTR_SIZE + \
		MSG_SHF_MERGE_SIZE + \
		MSG_SHF_STRINGS_SIZE + \
		MSG_SHF_INFO_LINK_SIZE + \
		MSG_SHF_LINK_ORDER_SIZE + \
		MSG_SHF_OS_NONCONFORMING_SIZE + \
		MSG_SHF_GROUP_SIZE + \
		MSG_SHF_TLS_SIZE + \
		MSG_SHF_EXCLUDE_SIZE + \
		MSG_SHF_ORDERED_SIZE + \
		MSG_SHF_AMD64_LARGE_SIZE + \
		CONV_INV_STRSIZE + MSG_GBL_CSQBRKT_SIZE

const char *
conv_sec_flags(Xword flags)
{
	static	char	string[FLAGSZ];
	static Val_desc vda[] = {
		{ SHF_WRITE,		MSG_ORIG(MSG_SHF_WRITE) },
		{ SHF_ALLOC,		MSG_ORIG(MSG_SHF_ALLOC) },
		{ SHF_EXECINSTR,	MSG_ORIG(MSG_SHF_EXECINSTR) },
		{ SHF_MERGE,		MSG_ORIG(MSG_SHF_MERGE) },
		{ SHF_STRINGS,		MSG_ORIG(MSG_SHF_STRINGS) },
		{ SHF_INFO_LINK,	MSG_ORIG(MSG_SHF_INFO_LINK) },
		{ SHF_LINK_ORDER,	MSG_ORIG(MSG_SHF_LINK_ORDER) },
		{ SHF_OS_NONCONFORMING,	MSG_ORIG(MSG_SHF_OS_NONCONFORMING) },
		{ SHF_GROUP,		MSG_ORIG(MSG_SHF_GROUP) },
		{ SHF_TLS,		MSG_ORIG(MSG_SHF_TLS) },
		{ SHF_EXCLUDE,		MSG_ORIG(MSG_SHF_EXCLUDE) },
		{ SHF_ORDERED,		MSG_ORIG(MSG_SHF_ORDERED) },
		{ SHF_AMD64_LARGE,	MSG_ORIG(MSG_SHF_AMD64_LARGE) },
		{ 0,			0 }
	};

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	(void) strlcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT), FLAGSZ);
	if (conv_expn_field(string, FLAGSZ, vda, flags, flags, 0, 0))
		(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT), FLAGSZ);

	return ((const char *)string);
}

const char *
conv_sec_info(Word info, Xword flags)
{
	static	char	string[CONV_INV_STRSIZE];

	if (flags & SHF_ORDERED) {
		if (info == SHN_BEFORE)
			return (MSG_ORIG(MSG_SHN_BEFORE));
		else if (info == SHN_AFTER)
			return (MSG_ORIG(MSG_SHN_AFTER));
	}
	(void) conv_invalid_val(string, CONV_INV_STRSIZE, info, 1);
	return ((const char *)string);
}
