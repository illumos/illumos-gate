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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
/* ARGSUSED 1 */
conv_sectyp_str(ushort_t mach, uint_t sec)
{
	static char	string[STRSIZE] = { '\0' };

	if (sec < SHT_NUM)
		return (MSG_ORIG(secs[sec]));
	else if ((sec >= SHT_LOSUNW) && (sec <= SHT_HISUNW))
		return (MSG_ORIG(usecs[sec - SHT_LOSUNW]));
	else if ((sec >= SHT_LOPROC) && (sec <= SHT_HIPROC)) {
		if ((sec == (uint_t)SHT_SPARC_GOTDATA) &&
		    ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
		    (mach == EM_SPARCV9)))
			return (MSG_ORIG(MSG_SHT_SPARC_GOTDATA));
		else if ((sec == (uint_t)SHT_AMD64_UNWIND) &&
		    (mach == EM_AMD64))
			return (MSG_ORIG(MSG_SHT_AMD64_UNWIND));
		else
			return (conv_invalid_str(string, STRSIZE, sec, 0));
	} else
		return (conv_invalid_str(string, STRSIZE, sec, 0));
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
		MSG_GBL_CSQBRKT_SIZE

const char *
/* ARGSUSED 1 */
conv_secflg_str(ushort_t mach, uint_t flags)
{
	static	char	string[FLAGSZ] = { '\0' };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	else {
		uint_t	flags_handled = 0;

		(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));
		if (flags & SHF_WRITE) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_WRITE));
			flags_handled |= SHF_WRITE;
		}
		if (flags & SHF_ALLOC) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_ALLOC));
			flags_handled |= SHF_ALLOC;
		}
		if (flags & SHF_EXECINSTR) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_EXECINSTR));
			flags_handled |= SHF_EXECINSTR;
		}
		if (flags & SHF_MERGE) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_MERGE));
			flags_handled |= SHF_MERGE;
		}
		if (flags & SHF_STRINGS) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_STRINGS));
			flags_handled |= SHF_STRINGS;
		}
		if (flags & SHF_INFO_LINK) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_INFO_LINK));
			flags_handled |= SHF_INFO_LINK;
		}
		if (flags & SHF_LINK_ORDER) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_LINK_ORDER));
			flags_handled |= SHF_LINK_ORDER;
		}
		if (flags & SHF_OS_NONCONFORMING) {
			(void) strcat(string,
				MSG_ORIG(MSG_SHF_OS_NONCONFORMING));
			flags_handled |= SHF_OS_NONCONFORMING;
		}
		if (flags & SHF_GROUP) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_GROUP));
			flags_handled |= SHF_GROUP;
		}
		if (flags & SHF_TLS) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_TLS));
			flags_handled |= SHF_TLS;
		}
		if (flags & SHF_EXCLUDE) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_EXCLUDE));
			flags_handled |= SHF_EXCLUDE;
		}
		if (flags & SHF_ORDERED) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_ORDERED));
			flags_handled |= SHF_ORDERED;
		}
		if (flags & SHF_AMD64_LARGE) {
			(void) strcat(string, MSG_ORIG(MSG_SHF_AMD64_LARGE));
			flags_handled |= SHF_AMD64_LARGE;
		}

		/*
		 * Are there any flags that haven't been handled.
		 */
		if ((flags & flags_handled) != flags) {
			char	*str;
			size_t	len;

			len = strlen(string);
			str = string + len;
			(void) conv_invalid_str(str, FLAGSZ - len,
			    (flags & (~flags_handled)), 0);
		}
		(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

		return ((const char *)string);
	}
}

/*
 * Need to be able to hold a 32bit signed integer.
 */
#define	INFOSZ	128

const char *
conv_secinfo_str(uint_t info, uint_t flags)
{
	static	char	string[INFOSZ] = { '\0' };

	if (flags & SHF_ORDERED) {
		if (info == SHN_BEFORE)
			return (MSG_ORIG(MSG_SHN_BEFORE));
		else if (info == SHN_AFTER)
			return (MSG_ORIG(MSG_SHN_AFTER));
	}
	(void) conv_invalid_str(string, INFOSZ, info, 1);
	return ((const char *)string);
}
