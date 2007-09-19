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

/*
 * String conversion routines for section attributes.
 */
#include	<string.h>
#include	<sys/param.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<_conv.h>
#include	<sections_msg.h>



/* Instantiate a local copy of conv_map2str() from _conv.h */
DEFINE_conv_map2str



static const Msg secs[SHT_NUM] = {
	MSG_SHT_NULL,		MSG_SHT_PROGBITS,	MSG_SHT_SYMTAB,
	MSG_SHT_STRTAB,		MSG_SHT_RELA,		MSG_SHT_HASH,
	MSG_SHT_DYNAMIC,	MSG_SHT_NOTE,		MSG_SHT_NOBITS,
	MSG_SHT_REL,		MSG_SHT_SHLIB,		MSG_SHT_DYNSYM,
	MSG_SHT_UNKNOWN12,	MSG_SHT_UNKNOWN13,	MSG_SHT_INIT_ARRAY,
	MSG_SHT_FINI_ARRAY,	MSG_SHT_PREINIT_ARRAY,	MSG_SHT_GROUP,
	MSG_SHT_SYMTAB_SHNDX
};
static const Msg secs_alt[SHT_NUM] = {
	MSG_SHT_NULL_ALT,	MSG_SHT_PROGBITS_ALT,	MSG_SHT_SYMTAB_ALT,
	MSG_SHT_STRTAB_ALT,	MSG_SHT_RELA_ALT,	MSG_SHT_HASH_ALT,
	MSG_SHT_DYNAMIC_ALT,	MSG_SHT_NOTE_ALT,	MSG_SHT_NOBITS_ALT,
	MSG_SHT_REL_ALT,	MSG_SHT_SHLIB_ALT,	MSG_SHT_DYNSYM_ALT,
	MSG_SHT_UNKNOWN12,	MSG_SHT_UNKNOWN13,	MSG_SHT_INIT_ARRAY_ALT,
	MSG_SHT_FINI_ARRAY_ALT,	MSG_SHT_PREINIT_ARRAY_ALT, MSG_SHT_GROUP_ALT,
	MSG_SHT_SYMTAB_SHNDX_ALT
};
#if	(SHT_NUM != (SHT_SYMTAB_SHNDX + 1))
#error	"SHT_NUM has grown"
#endif

static const Msg usecs[SHT_HISUNW - SHT_LOSUNW + 1] = {
	MSG_SHT_SUNW_symsort,		MSG_SHT_SUNW_tlssort,
	MSG_SHT_SUNW_LDYNSYM,		MSG_SHT_SUNW_dof,
	MSG_SHT_SUNW_cap,		MSG_SHT_SUNW_SIGNATURE,
	MSG_SHT_SUNW_ANNOTATE,		MSG_SHT_SUNW_DEBUGSTR,
	MSG_SHT_SUNW_DEBUG,		MSG_SHT_SUNW_move,
	MSG_SHT_SUNW_COMDAT,		MSG_SHT_SUNW_syminfo,
	MSG_SHT_SUNW_verdef,		MSG_SHT_SUNW_verneed,
	MSG_SHT_SUNW_versym
};
static const Msg usecs_alt[SHT_HISUNW - SHT_LOSUNW + 1] = {
	MSG_SHT_SUNW_symsort_ALT,	MSG_SHT_SUNW_tlssort_ALT,
	MSG_SHT_SUNW_LDYNSYM_ALT,	MSG_SHT_SUNW_dof_ALT,
	MSG_SHT_SUNW_cap_ALT,		MSG_SHT_SUNW_SIGNATURE_ALT,
	MSG_SHT_SUNW_ANNOTATE_ALT,	MSG_SHT_SUNW_DEBUGSTR_ALT,
	MSG_SHT_SUNW_DEBUG_ALT,		MSG_SHT_SUNW_move_ALT,
	MSG_SHT_SUNW_COMDAT_ALT,	MSG_SHT_SUNW_syminfo_ALT,
	MSG_SHT_SUNW_verdef_ALT,	MSG_SHT_SUNW_verneed_ALT,
	MSG_SHT_SUNW_versym_ALT
};
#if	(SHT_LOSUNW != SHT_SUNW_symsort)
#error	"SHT_LOSUNW has moved"
#endif


const char *
conv_sec_type(Half mach, Word sec, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	if (sec < SHT_NUM) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			return (conv_map2str(inv_buf, sec, fmt_flags,
			    ARRAY_NELTS(secs_alt), secs_alt));
		default:
			return (conv_map2str(inv_buf, sec, fmt_flags,
			    ARRAY_NELTS(secs), secs));
		}
	} else if ((sec >= SHT_LOSUNW) && (sec <= SHT_HISUNW)) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			return (conv_map2str(inv_buf, sec - SHT_LOSUNW,
			    fmt_flags, ARRAY_NELTS(usecs_alt), usecs_alt));
		default:
			return (conv_map2str(inv_buf, sec - SHT_LOSUNW,
			    fmt_flags, ARRAY_NELTS(usecs), usecs));
		}
	} else if ((sec >= SHT_LOPROC) && (sec <= SHT_HIPROC)) {
		switch (mach) {
		case EM_SPARC:
		case EM_SPARC32PLUS:
		case EM_SPARCV9:
			if (sec != SHT_SPARC_GOTDATA)
				break;
			switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
			case CONV_FMT_ALT_DUMP:
			case CONV_FMT_ALT_FILE:
				return (MSG_ORIG(MSG_SHT_SPARC_GOTDATA_ALT));
			}
			return (MSG_ORIG(MSG_SHT_SPARC_GOTDATA));
		case EM_AMD64:
			if (sec != SHT_AMD64_UNWIND)
				break;
			switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
			case CONV_FMT_ALT_DUMP:
			case CONV_FMT_ALT_FILE:
				return (MSG_ORIG(MSG_SHT_AMD64_UNWIND_ALT));
			}
			return (MSG_ORIG(MSG_SHT_AMD64_UNWIND));
		}
	}

	/* If we get here, it's an unknown type */
	return (conv_invalid_val(inv_buf, sec, fmt_flags));
}

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_SHF_WRITE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_ALLOC_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_EXECINSTR_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_MERGE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_STRINGS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_INFO_LINK_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_LINK_ORDER_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_OS_NONCONFORMING_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_GROUP_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_TLS_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_EXCLUDE_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_ORDERED_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		MSG_SHF_AMD64_LARGE_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_sec_flags_buf_t is large enough:
 *
 * FLAGSZ is the real minimum size of the buffer required by conv_sec_flags().
 * However, Conv_sec_flags_buf_t uses CONV_SEC_FLAGS_BUFSIZE to set the
 * buffer size. We do things this way because the definition of FLAGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if CONV_SEC_FLAGS_BUFSIZE < FLAGSZ
#error "CONV_SEC_FLAGS_BUFSIZE is not large enough"
#endif

const char *
conv_sec_flags(Xword flags, Conv_fmt_flags_t fmt_flags,
    Conv_sec_flags_buf_t *sec_flags_buf)
{
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
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (sec_flags_buf->buf), vda };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));

	conv_arg.buf = sec_flags_buf->buf;
	conv_arg.oflags = conv_arg.rflags = flags;
	(void) conv_expn_field(&conv_arg, fmt_flags);

	return ((const char *)sec_flags_buf->buf);
}

const char *
conv_sec_linkinfo(Word info, Xword flags, Conv_inv_buf_t *inv_buf)
{
	if (flags & ALL_SHF_ORDER) {
		if (info == SHN_BEFORE)
			return (MSG_ORIG(MSG_SHN_BEFORE));
		else if (info == SHN_AFTER)
			return (MSG_ORIG(MSG_SHN_AFTER));
	}

	(void) conv_invalid_val(inv_buf, info, CONV_FMT_DECIMAL);
	return ((const char *)inv_buf->buf);
}
