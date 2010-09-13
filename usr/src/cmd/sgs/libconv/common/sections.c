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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * String conversion routines for section attributes.
 */
#include	<string.h>
#include	<sys/param.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	<_conv.h>
#include	<sections_msg.h>


static const conv_ds_t **
sec_type_strings(conv_iter_osabi_t osabi, Half mach, Conv_fmt_flags_t fmt_flags)
{
	/*
	 * This routine can return an array with 1 generic array, up to
	 * three osabi arrays, two machine arrays, plus the NULL termination.
	 */
#define	MAX_RET	7

	static const Msg secs_def[SHT_NUM] = {
		MSG_SHT_NULL,			MSG_SHT_PROGBITS,
		MSG_SHT_SYMTAB,			MSG_SHT_STRTAB,
		MSG_SHT_RELA,			MSG_SHT_HASH,
		MSG_SHT_DYNAMIC,		MSG_SHT_NOTE,
		MSG_SHT_NOBITS,			MSG_SHT_REL,
		MSG_SHT_SHLIB,			MSG_SHT_DYNSYM,
		MSG_SHT_UNKNOWN12,		MSG_SHT_UNKNOWN13,
		MSG_SHT_INIT_ARRAY,		MSG_SHT_FINI_ARRAY,
		MSG_SHT_PREINIT_ARRAY,		MSG_SHT_GROUP,
		MSG_SHT_SYMTAB_SHNDX
	};
	static const Msg secs_dmp[SHT_NUM] = {
		MSG_SHT_NULL_DMP,		MSG_SHT_PROGBITS_DMP,
		MSG_SHT_SYMTAB_DMP,		MSG_SHT_STRTAB_DMP,
		MSG_SHT_RELA_DMP,		MSG_SHT_HASH_DMP,
		MSG_SHT_DYNAMIC_DMP,		MSG_SHT_NOTE_DMP,
		MSG_SHT_NOBITS_DMP,		MSG_SHT_REL_DMP,
		MSG_SHT_SHLIB_DMP,		MSG_SHT_DYNSYM_DMP,
		MSG_SHT_UNKNOWN12_DMP,		MSG_SHT_UNKNOWN13_DMP,
		MSG_SHT_INIT_ARRAY_DMP,		MSG_SHT_FINI_ARRAY_DMP,
		MSG_SHT_PREINIT_ARRAY_DMP,	MSG_SHT_GROUP_DMP,
		MSG_SHT_SYMTAB_SHNDX_DMP
	};
	static const Msg secs_cf[SHT_NUM] = {
		MSG_SHT_NULL_CF,		MSG_SHT_PROGBITS_CF,
		MSG_SHT_SYMTAB_CF,		MSG_SHT_STRTAB_CF,
		MSG_SHT_RELA_CF,		MSG_SHT_HASH_CF,
		MSG_SHT_DYNAMIC_CF,		MSG_SHT_NOTE_CF,
		MSG_SHT_NOBITS_CF,		MSG_SHT_REL_CF,
		MSG_SHT_SHLIB_CF,		MSG_SHT_DYNSYM_CF,
		MSG_SHT_UNKNOWN12_CF,		MSG_SHT_UNKNOWN13_CF,
		MSG_SHT_INIT_ARRAY_CF,		MSG_SHT_FINI_ARRAY_CF,
		MSG_SHT_PREINIT_ARRAY_CF,	MSG_SHT_GROUP_CF,
		MSG_SHT_SYMTAB_SHNDX_CF
	};
	static const Msg secs_nf[SHT_NUM] = {
		MSG_SHT_NULL_NF,		MSG_SHT_PROGBITS_NF,
		MSG_SHT_SYMTAB_NF,		MSG_SHT_STRTAB_NF,
		MSG_SHT_RELA_NF,		MSG_SHT_HASH_NF,
		MSG_SHT_DYNAMIC_NF,		MSG_SHT_NOTE_NF,
		MSG_SHT_NOBITS_NF,		MSG_SHT_REL_NF,
		MSG_SHT_SHLIB_NF,		MSG_SHT_DYNSYM_NF,
		MSG_SHT_UNKNOWN12_NF,		MSG_SHT_UNKNOWN13_NF,
		MSG_SHT_INIT_ARRAY_NF,		MSG_SHT_FINI_ARRAY_NF,
		MSG_SHT_PREINIT_ARRAY_NF,	MSG_SHT_GROUP_NF,
		MSG_SHT_SYMTAB_SHNDX_NF
	};
#if	(SHT_NUM != (SHT_SYMTAB_SHNDX + 1))
#error	"SHT_NUM has grown"
#endif
	static const conv_ds_msg_t ds_secs_def = {
	    CONV_DS_MSG_INIT(SHT_NULL, secs_def) };
	static const conv_ds_msg_t ds_secs_dmp = {
	    CONV_DS_MSG_INIT(SHT_NULL, secs_dmp) };
	static const conv_ds_msg_t ds_secs_cf = {
	    CONV_DS_MSG_INIT(SHT_NULL, secs_cf) };
	static const conv_ds_msg_t ds_secs_nf = {
	    CONV_DS_MSG_INIT(SHT_NULL, secs_nf) };


	static const Msg usecs_def[SHT_HISUNW - SHT_LOSUNW + 1] = {
		MSG_SHT_SUNW_CAPCHAIN,		MSG_SHT_SUNW_CAPINFO,
		MSG_SHT_SUNW_SYMSORT,		MSG_SHT_SUNW_TLSSORT,
		MSG_SHT_SUNW_LDYNSYM,		MSG_SHT_SUNW_DOF,
		MSG_SHT_SUNW_CAP,		MSG_SHT_SUNW_SIGNATURE,
		MSG_SHT_SUNW_ANNOTATE,		MSG_SHT_SUNW_DEBUGSTR,
		MSG_SHT_SUNW_DEBUG,		MSG_SHT_SUNW_MOVE,
		MSG_SHT_SUNW_COMDAT,		MSG_SHT_SUNW_SYMINFO,
		MSG_SHT_SUNW_VERDEF,		MSG_SHT_SUNW_VERNEED,
		MSG_SHT_SUNW_VERSYM
	};
	static const Msg usecs_dmp[SHT_HISUNW - SHT_LOSUNW + 1] = {
		MSG_SHT_SUNW_CAPCHAIN_DMP,	MSG_SHT_SUNW_CAPINFO_DMP,
		MSG_SHT_SUNW_SYMSORT_DMP,	MSG_SHT_SUNW_TLSSORT_DMP,
		MSG_SHT_SUNW_LDYNSYM_DMP,	MSG_SHT_SUNW_DOF_DMP,
		MSG_SHT_SUNW_CAP_DMP,		MSG_SHT_SUNW_SIGNATURE_DMP,
		MSG_SHT_SUNW_ANNOTATE_DMP,	MSG_SHT_SUNW_DEBUGSTR_DMP,
		MSG_SHT_SUNW_DEBUG_DMP,		MSG_SHT_SUNW_MOVE_DMP,
		MSG_SHT_SUNW_COMDAT_DMP,	MSG_SHT_SUNW_SYMINFO_DMP,
		MSG_SHT_SUNW_VERDEF_DMP,	MSG_SHT_SUNW_VERNEED_DMP,
		MSG_SHT_SUNW_VERSYM_DMP
	};
	static const Msg usecs_cf[SHT_HISUNW - SHT_LOSUNW + 1] = {
		MSG_SHT_SUNW_CAPCHAIN_CF,	MSG_SHT_SUNW_CAPINFO_CF,
		MSG_SHT_SUNW_SYMSORT_CF,	MSG_SHT_SUNW_TLSSORT_CF,
		MSG_SHT_SUNW_LDYNSYM_CF,	MSG_SHT_SUNW_DOF_CF,
		MSG_SHT_SUNW_CAP_CF,		MSG_SHT_SUNW_SIGNATURE_CF,
		MSG_SHT_SUNW_ANNOTATE_CF,	MSG_SHT_SUNW_DEBUGSTR_CF,
		MSG_SHT_SUNW_DEBUG_CF,		MSG_SHT_SUNW_MOVE_CF,
		MSG_SHT_SUNW_COMDAT_CF,		MSG_SHT_SUNW_SYMINFO_CF,
		MSG_SHT_SUNW_VERDEF_CF,		MSG_SHT_SUNW_VERNEED_CF,
		MSG_SHT_SUNW_VERSYM_CF
	};
	static const Msg usecs_nf[SHT_HISUNW - SHT_LOSUNW + 1] = {
		MSG_SHT_SUNW_CAPCHAIN_NF,	MSG_SHT_SUNW_CAPINFO_NF,
		MSG_SHT_SUNW_SYMSORT_NF,	MSG_SHT_SUNW_TLSSORT_NF,
		MSG_SHT_SUNW_LDYNSYM_NF,	MSG_SHT_SUNW_DOF_NF,
		MSG_SHT_SUNW_CAP_NF,		MSG_SHT_SUNW_SIGNATURE_NF,
		MSG_SHT_SUNW_ANNOTATE_NF,	MSG_SHT_SUNW_DEBUGSTR_NF,
		MSG_SHT_SUNW_DEBUG_NF,		MSG_SHT_SUNW_MOVE_NF,
		MSG_SHT_SUNW_COMDAT_NF,		MSG_SHT_SUNW_SYMINFO_NF,
		MSG_SHT_SUNW_VERDEF_NF,		MSG_SHT_SUNW_VERNEED_NF,
		MSG_SHT_SUNW_VERSYM_NF
	};
#if	(SHT_LOSUNW != SHT_SUNW_capchain)
#error	"SHT_LOSUNW has moved"
#endif
	static const conv_ds_msg_t ds_usecs_def = {
	    CONV_DS_MSG_INIT(SHT_SUNW_capchain, usecs_def) };
	static const conv_ds_msg_t ds_usecs_dmp = {
	    CONV_DS_MSG_INIT(SHT_SUNW_capchain, usecs_dmp) };
	static const conv_ds_msg_t ds_usecs_cf = {
	    CONV_DS_MSG_INIT(SHT_SUNW_capchain, usecs_cf) };
	static const conv_ds_msg_t ds_usecs_nf = {
	    CONV_DS_MSG_INIT(SHT_SUNW_capchain, usecs_nf) };


	/* The Linux osabi range has two separate sequences */
	static const Msg usecs_gnu1_def[] = {
		MSG_SHT_GNU_ATTRIBUTES,		MSG_SHT_GNU_HASH,
		MSG_SHT_GNU_LIBLIST,		MSG_SHT_CHECKSUM,
	};
	static const Msg usecs_gnu1_dmp[] = {
		MSG_SHT_GNU_ATTRIBUTES_DMP,	MSG_SHT_GNU_HASH_DMP,
		MSG_SHT_GNU_LIBLIST_DMP,	MSG_SHT_CHECKSUM_DMP,
	};
	static const Msg usecs_gnu1_cf[] = {
		MSG_SHT_GNU_ATTRIBUTES_CF,	MSG_SHT_GNU_HASH_CF,
		MSG_SHT_GNU_LIBLIST_CF,	MSG_SHT_CHECKSUM_CF,
	};
	static const Msg usecs_gnu1_nf[] = {
		MSG_SHT_GNU_ATTRIBUTES_NF,	MSG_SHT_GNU_HASH_NF,
		MSG_SHT_GNU_LIBLIST_NF,	MSG_SHT_CHECKSUM_NF,
	};
	static const conv_ds_msg_t ds_usecs_gnu1_def = {
	    CONV_DS_MSG_INIT(SHT_GNU_ATTRIBUTES, usecs_gnu1_def) };
	static const conv_ds_msg_t ds_usecs_gnu1_dmp = {
	    CONV_DS_MSG_INIT(SHT_GNU_ATTRIBUTES, usecs_gnu1_dmp) };
	static const conv_ds_msg_t ds_usecs_gnu1_cf = {
	    CONV_DS_MSG_INIT(SHT_GNU_ATTRIBUTES, usecs_gnu1_cf) };
	static const conv_ds_msg_t ds_usecs_gnu1_nf = {
	    CONV_DS_MSG_INIT(SHT_GNU_ATTRIBUTES, usecs_gnu1_nf) };


	static const Msg usecs_gnu2_def[] = {
		MSG_SHT_GNU_VERDEF,		MSG_SHT_GNU_VERNEED,
		MSG_SHT_GNU_VERSYM
	};
	static const Msg usecs_gnu2_dmp[] = {
		MSG_SHT_GNU_VERDEF_DMP,		MSG_SHT_GNU_VERNEED_DMP,
		MSG_SHT_GNU_VERSYM_DMP
	};
	static const Msg usecs_gnu2_cf[] = {
		MSG_SHT_GNU_VERDEF_CF,		MSG_SHT_GNU_VERNEED_CF,
		MSG_SHT_GNU_VERSYM_CF
	};
	static const Msg usecs_gnu2_nf[] = {
		MSG_SHT_GNU_VERDEF_NF,		MSG_SHT_GNU_VERNEED_NF,
		MSG_SHT_GNU_VERSYM_NF
	};
	static const conv_ds_msg_t ds_usecs_gnu2_def = {
	    CONV_DS_MSG_INIT(SHT_GNU_verdef, usecs_gnu2_def) };
	static const conv_ds_msg_t ds_usecs_gnu2_dmp = {
	    CONV_DS_MSG_INIT(SHT_GNU_verdef, usecs_gnu2_dmp) };
	static const conv_ds_msg_t ds_usecs_gnu2_cf = {
	    CONV_DS_MSG_INIT(SHT_GNU_verdef, usecs_gnu2_cf) };
	static const conv_ds_msg_t ds_usecs_gnu2_nf = {
	    CONV_DS_MSG_INIT(SHT_GNU_verdef, usecs_gnu2_nf) };


	/* sparc processor range */
	static const Msg sparc_def[] = { MSG_SHT_SPARC_GOTDATA };
	static const Msg sparc_dmp[] = { MSG_SHT_SPARC_GOTDATA_DMP };
	static const Msg sparc_cf[] = { MSG_SHT_SPARC_GOTDATA_CF };
	static const Msg sparc_nf[] = { MSG_SHT_SPARC_GOTDATA_NF };
	static const conv_ds_msg_t ds_sparc_def = {
	    CONV_DS_MSG_INIT(SHT_SPARC_GOTDATA, sparc_def) };
	static const conv_ds_msg_t ds_sparc_dmp = {
	    CONV_DS_MSG_INIT(SHT_SPARC_GOTDATA, sparc_dmp) };
	static const conv_ds_msg_t ds_sparc_cf = {
	    CONV_DS_MSG_INIT(SHT_SPARC_GOTDATA, sparc_cf) };
	static const conv_ds_msg_t ds_sparc_nf = {
	    CONV_DS_MSG_INIT(SHT_SPARC_GOTDATA, sparc_nf) };

	/* amd64 processor range */
	static const Msg amd64_def[] = { MSG_SHT_AMD64_UNWIND };
	static const Msg amd64_dmp[] = { MSG_SHT_AMD64_UNWIND_DMP };
	static const Msg amd64_cf[] = { MSG_SHT_AMD64_UNWIND_CF };
	static const Msg amd64_nf[] = { MSG_SHT_AMD64_UNWIND_NF };
	static const conv_ds_msg_t ds_amd64_def = {
	    CONV_DS_MSG_INIT(SHT_AMD64_UNWIND, amd64_def) };
	static const conv_ds_msg_t ds_amd64_dmp = {
	    CONV_DS_MSG_INIT(SHT_AMD64_UNWIND, amd64_dmp) };
	static const conv_ds_msg_t ds_amd64_cf = {
	    CONV_DS_MSG_INIT(SHT_AMD64_UNWIND, amd64_cf) };
	static const conv_ds_msg_t ds_amd64_nf = {
	    CONV_DS_MSG_INIT(SHT_AMD64_UNWIND, amd64_nf) };


	static const conv_ds_t	*retarr[MAX_RET];
	int			retndx = 0;

	/* Select the strings to use, based on string style and OSABI */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		retarr[retndx++] = CONV_DS_ADDR(ds_secs_dmp);
		break;
	case CONV_FMT_ALT_CF:
		retarr[retndx++] = CONV_DS_ADDR(ds_secs_cf);
		break;
	case CONV_FMT_ALT_NF:
		retarr[retndx++] = CONV_DS_ADDR(ds_secs_nf);
		break;
	default:
		retarr[retndx++] = CONV_DS_ADDR(ds_secs_def);
		break;
	}

	if ((osabi == ELFOSABI_NONE) || (osabi == ELFOSABI_SOLARIS) ||
	    (osabi == CONV_OSABI_ALL)) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_dmp);
			break;
		case CONV_FMT_ALT_CF:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_cf);
			break;
		case CONV_FMT_ALT_NF:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_nf);
			break;
		default:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_def);
			break;
		}
	}

	if ((osabi == ELFOSABI_LINUX) || (osabi == CONV_OSABI_ALL)) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu1_dmp);
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu2_dmp);
			break;
		case CONV_FMT_ALT_CF:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu1_cf);
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu2_cf);
			break;
		case CONV_FMT_ALT_NF:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu1_nf);
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu2_nf);
			break;
		default:
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu1_def);
			retarr[retndx++] = CONV_DS_ADDR(ds_usecs_gnu2_def);
			break;
		}
	}

	if ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9) || (mach == CONV_MACH_ALL)) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_dmp);
			break;
		case CONV_FMT_ALT_CF:
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_cf);
			break;
		case CONV_FMT_ALT_NF:
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_nf);
			break;
		default:
			retarr[retndx++] = CONV_DS_ADDR(ds_sparc_def);
			break;
		}
	}

	if ((mach == EM_AMD64) || (mach == CONV_MACH_ALL)) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
			retarr[retndx++] = CONV_DS_ADDR(ds_amd64_dmp);
			break;
		case CONV_FMT_ALT_CF:
			retarr[retndx++] = CONV_DS_ADDR(ds_amd64_cf);
			break;
		case CONV_FMT_ALT_NF:
			retarr[retndx++] = CONV_DS_ADDR(ds_amd64_nf);
			break;
		default:
			retarr[retndx++] = CONV_DS_ADDR(ds_amd64_def);
			break;
		}
	}

	retarr[retndx++] = NULL;
	assert(retndx <= MAX_RET);
	return (retarr);

#undef MAX_RET
}

const char *
conv_sec_type(uchar_t osabi, Half mach, Word sec, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(osabi, mach, sec,
	    sec_type_strings(osabi, mach, fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_sec_type(conv_iter_osabi_t osabi, Half mach,
    Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(osabi, mach,
	    sec_type_strings(osabi, mach, fmt_flags), func, uvalue));
}


/*
 * Special iteration routine that returns strings for all symbol table
 * sections.
 */
conv_iter_ret_t
conv_iter_sec_symtab(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	static const Val_desc2 symtab_cf[] = {
		{ SHT_SYMTAB,	0, 0,	MSG_SHT_SYMTAB_CF },
		{ SHT_DYNSYM,	0, 0,	MSG_SHT_DYNSYM_CF },
		{ SHT_SUNW_LDYNSYM, ELFOSABI_SOLARIS, 0,
					MSG_SHT_SUNW_LDYNSYM_CF },

		{ 0 }
	};
	static const Val_desc2 symtab_nf[] = {
		{ SHT_SYMTAB,	0, 0,	MSG_SHT_SYMTAB_NF },
		{ SHT_DYNSYM,	0, 0,	MSG_SHT_DYNSYM_NF },
		{ SHT_SUNW_LDYNSYM, ELFOSABI_SOLARIS, 0,
					MSG_SHT_SUNW_LDYNSYM_NF },

		{ 0 }
	};

	const Val_desc2 *vdp;

	vdp = (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
	    symtab_nf : symtab_cf;

	return (conv_iter_vd2(osabi, EM_NONE, vdp, func, uvalue));
}


const Val_desc2 *
conv_sec_flags_strings(Conv_fmt_flags_t fmt_flags)
{
#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_SHF_WRITE_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_ALLOC_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_EXECINSTR_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_MERGE_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_STRINGS_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_INFO_LINK_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_LINK_ORDER_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_OS_NONCONFORMING_CF_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_GROUP_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_TLS_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_EXCLUDE_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_ORDERED_CF_SIZE		+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	MSG_SHF_AMD64_LARGE_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE + \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_sec_flags_buf_t is large enough:
	 *
	 * FLAGSZ is the real minimum size of the buffer required by
	 * conv_sec_flags(). However, Conv_sec_flags_buf_t uses
	 * CONV_SEC_FLAGS_BUFSIZE to set the buffer size. We do things this
	 * way because the definition of FLAGSZ uses information that is not
	 * available in the environment of other programs that include the
	 * conv.h header file.
	 */
#if (CONV_SEC_FLAGS_BUFSIZE != FLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE FLAGSZ
#include "report_bufsize.h"
#error "CONV_SEC_FLAGS_BUFSIZE does not match FLAGSZ"
#endif

#define	ALL	ELFOSABI_NONE, EM_NONE
#define	SOL	ELFOSABI_SOLARIS, EM_NONE
#define	AMD	ELFOSABI_NONE, EM_AMD64

	static const Val_desc2 vda_cf[] = {
		{ SHF_WRITE,		ALL,	MSG_SHF_WRITE_CF },
		{ SHF_ALLOC,		ALL,	MSG_SHF_ALLOC_CF },
		{ SHF_EXECINSTR,	ALL,	MSG_SHF_EXECINSTR_CF },
		{ SHF_MERGE,		ALL,	MSG_SHF_MERGE_CF },
		{ SHF_STRINGS,		ALL,	MSG_SHF_STRINGS_CF },
		{ SHF_INFO_LINK,	ALL,	MSG_SHF_INFO_LINK_CF },
		{ SHF_LINK_ORDER,	ALL,	MSG_SHF_LINK_ORDER_CF },
		{ SHF_OS_NONCONFORMING,	ALL,	MSG_SHF_OS_NONCONFORMING_CF },
		{ SHF_GROUP,		ALL,	MSG_SHF_GROUP_CF },
		{ SHF_TLS,		ALL,	MSG_SHF_TLS_CF },
		{ SHF_EXCLUDE,		SOL,	MSG_SHF_EXCLUDE_CF },
		{ SHF_ORDERED,		SOL,	MSG_SHF_ORDERED_CF },
		{ SHF_AMD64_LARGE,	AMD,	MSG_SHF_AMD64_LARGE_CF },
		{ 0,			0 }
	};
	static const Val_desc2 vda_nf[] = {
		{ SHF_WRITE,		ALL,	MSG_SHF_WRITE_NF },
		{ SHF_ALLOC,		ALL,	MSG_SHF_ALLOC_NF },
		{ SHF_EXECINSTR,	ALL,	MSG_SHF_EXECINSTR_NF },
		{ SHF_MERGE,		ALL,	MSG_SHF_MERGE_NF },
		{ SHF_STRINGS,		ALL,	MSG_SHF_STRINGS_NF },
		{ SHF_INFO_LINK,	ALL,	MSG_SHF_INFO_LINK_NF },
		{ SHF_LINK_ORDER,	ALL,	MSG_SHF_LINK_ORDER_NF },
		{ SHF_OS_NONCONFORMING,	ALL,	MSG_SHF_OS_NONCONFORMING_NF },
		{ SHF_GROUP,		ALL,	MSG_SHF_GROUP_NF },
		{ SHF_TLS,		ALL,	MSG_SHF_TLS_NF },
		{ SHF_EXCLUDE,		SOL,	MSG_SHF_EXCLUDE_NF },
		{ SHF_ORDERED,		SOL,	MSG_SHF_ORDERED_NF },
		{ SHF_AMD64_LARGE,	AMD,	MSG_SHF_AMD64_LARGE_NF },
		{ 0,			0 }
	};

	return ((CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
	    vda_nf : vda_cf);

#undef ALL
#undef SOL
#undef AMD
}

conv_iter_ret_t
conv_iter_sec_flags(conv_iter_osabi_t osabi, Half mach,
    Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func, void *uvalue)
{
	static const Msg amd64_alias_cf[] = { MSG_SHF_X86_64_LARGE_CF };
	static const conv_ds_msg_t ds_msg_amd64_alias_cf = {
	    CONV_DS_MSG_INIT(SHF_X86_64_LARGE, amd64_alias_cf) };
	static const conv_ds_t	*ds_amd64_alias_cf[] = {
	    CONV_DS_ADDR(ds_msg_amd64_alias_cf), NULL };

	static const Msg amd64_alias_nf[] = { MSG_SHF_X86_64_LARGE_NF };
	static const conv_ds_msg_t ds_msg_amd64_alias_nf = {
	    CONV_DS_MSG_INIT(SHF_X86_64_LARGE, amd64_alias_nf) };
	static const conv_ds_t	*ds_amd64_alias_nf[] = {
	    CONV_DS_ADDR(ds_msg_amd64_alias_nf), NULL };


	if (conv_iter_vd2(osabi, mach, conv_sec_flags_strings(fmt_flags),
	    func, uvalue) == CONV_ITER_DONE)
		return (CONV_ITER_DONE);

	/* SHF_AMD64_LARGE is also known as SHF_X86_64_LARGE */
	if (mach == EM_AMD64) {
		const conv_ds_t **ds;

		ds = (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
		    ds_amd64_alias_nf : ds_amd64_alias_cf;

		return (conv_iter_ds(ELFOSABI_NONE, mach, ds, func, uvalue));
	}

	return (CONV_ITER_CONT);
}
