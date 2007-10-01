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
 * String conversion routines for ELF header attributes.
 */
#include	<stdio.h>
#include	<string.h>
#include	"_conv.h"
#include	"elf_msg.h"
#include	<sys/elf_SPARC.h>



/* Instantiate a local copy of conv_map2str() from _conv.h */
DEFINE_conv_map2str



const char *
conv_ehdr_class(uchar_t class, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	classes[] = {
		MSG_ELFCLASSNONE, MSG_ELFCLASS32, MSG_ELFCLASS64
	};
	static const Msg	classes_alt[] = {
		MSG_ELFCLASSNONE_ALT, MSG_ELFCLASS32_ALT, MSG_ELFCLASS64_ALT
	};

	/* Use alternative strings? */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (conv_map2str(inv_buf, class, fmt_flags,
		    ARRAY_NELTS(classes_alt), classes_alt));
	}

	/* Use default strings */
	return (conv_map2str(inv_buf, class, fmt_flags,
	    ARRAY_NELTS(classes), classes));
}

const char *
conv_ehdr_data(uchar_t data, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	datas[] = {
		MSG_ELFDATANONE, MSG_ELFDATA2LSB, MSG_ELFDATA2MSB
	};
	static const Msg	datas_dump[] = {
		MSG_ELFDATANONE_ALT, MSG_ELFDATA2LSB_ALT1, MSG_ELFDATA2MSB_ALT1
	};
	static const Msg	datas_file[] = {
		MSG_ELFDATANONE_ALT, MSG_ELFDATA2LSB_ALT2, MSG_ELFDATA2MSB_ALT2
	};

	/* Use alternative strings? */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (conv_map2str(inv_buf, data, fmt_flags,
		    ARRAY_NELTS(datas_dump), datas_dump));
	case CONV_FMT_ALT_FILE:
		return (conv_map2str(inv_buf, data, fmt_flags,
		    ARRAY_NELTS(datas_file), datas_file));
	}

	/* Use default strings */
	return (conv_map2str(inv_buf, data, fmt_flags,
	    ARRAY_NELTS(datas), datas));
}

static const Msg machines[EM_NUM] = {
	MSG_EM_NONE,		MSG_EM_M32,		MSG_EM_SPARC,
	MSG_EM_386,		MSG_EM_68K,		MSG_EM_88K,
	MSG_EM_486,		MSG_EM_860,		MSG_EM_MIPS,
	MSG_EM_S370,		MSG_EM_MIPS_RS3_LE,	MSG_EM_RS6000,
	MSG_EM_UNKNOWN12,	MSG_EM_UNKNOWN13,	MSG_EM_UNKNOWN14,
	MSG_EM_PA_RISC,		MSG_EM_nCUBE,		MSG_EM_VPP500,
	MSG_EM_SPARC32PLUS,	MSG_EM_960,		MSG_EM_PPC,
	MSG_EM_PPC64,		MSG_EM_S390,		MSG_EM_UNKNOWN23,
	MSG_EM_UNKNOWN24,	MSG_EM_UNKNOWN25,	MSG_EM_UNKNOWN26,
	MSG_EM_UNKNOWN27,	MSG_EM_UNKNOWN28,	MSG_EM_UNKNOWN29,
	MSG_EM_UNKNOWN30,	MSG_EM_UNKNOWN31,	MSG_EM_UNKNOWN32,
	MSG_EM_UNKNOWN33,	MSG_EM_UNKNOWN34,	MSG_EM_UNKNOWN35,
	MSG_EM_V800,		MSG_EM_FR20,		MSG_EM_RH32,
	MSG_EM_RCE,		MSG_EM_ARM,		MSG_EM_ALPHA,
	MSG_EM_SH,		MSG_EM_SPARCV9,		MSG_EM_TRICORE,
	MSG_EM_ARC,		MSG_EM_H8_300,		MSG_EM_H8_300H,
	MSG_EM_H8S,		MSG_EM_H8_500,		MSG_EM_IA_64,
	MSG_EM_MIPS_X,		MSG_EM_COLDFIRE,	MSG_EM_68HC12,
	MSG_EM_MMA,		MSG_EM_PCP,		MSG_EM_NCPU,
	MSG_EM_NDR1,		MSG_EM_STARCORE,	MSG_EM_ME16,
	MSG_EM_ST100,		MSG_EM_TINYJ,		MSG_EM_AMD64,
	MSG_EM_PDSP,		MSG_EM_UNKNOWN64,	MSG_EM_UNKNOWN65,
	MSG_EM_FX66,		MSG_EM_ST9PLUS,		MSG_EM_ST7,
	MSG_EM_68HC16,		MSG_EM_68HC11,		MSG_EM_68HC08,
	MSG_EM_68HC05,		MSG_EM_SVX,		MSG_EM_ST19,
	MSG_EM_VAX,		MSG_EM_CRIS,		MSG_EM_JAVELIN,
	MSG_EM_FIREPATH,	MSG_EM_ZSP,		MSG_EM_MMIX,
	MSG_EM_HUANY,		MSG_EM_PRISM,		MSG_EM_AVR,
	MSG_EM_FR30,		MSG_EM_D10V,		MSG_EM_D30V,
	MSG_EM_V850,		MSG_EM_M32R,		MSG_EM_MN10300,
	MSG_EM_MN10200,		MSG_EM_PJ,		MSG_EM_OPENRISC,
	MSG_EM_ARC_A5,		MSG_EM_XTENSA
};
static const Msg machines_alt[EM_NUM] = {
	MSG_EM_NONE_ALT,	MSG_EM_M32_ALT,		MSG_EM_SPARC_ALT,
	MSG_EM_386_ALT,		MSG_EM_68K_ALT,		MSG_EM_88K_ALT,
	MSG_EM_486_ALT,		MSG_EM_860_ALT,		MSG_EM_MIPS_ALT,
	MSG_EM_S370,		MSG_EM_MIPS_RS3_LE_ALT,	MSG_EM_RS6000_ALT,
	MSG_EM_UNKNOWN12,	MSG_EM_UNKNOWN13,	MSG_EM_UNKNOWN14,
	MSG_EM_PA_RISC_ALT,	MSG_EM_nCUBE_ALT,	MSG_EM_VPP500_ALT,
	MSG_EM_SPARC32PLUS_ALT,	MSG_EM_960,		MSG_EM_PPC_ALT,
	MSG_EM_PPC64_ALT,	MSG_EM_S390,		MSG_EM_UNKNOWN23,
	MSG_EM_UNKNOWN24,	MSG_EM_UNKNOWN25,	MSG_EM_UNKNOWN26,
	MSG_EM_UNKNOWN27,	MSG_EM_UNKNOWN28,	MSG_EM_UNKNOWN29,
	MSG_EM_UNKNOWN30,	MSG_EM_UNKNOWN31,	MSG_EM_UNKNOWN32,
	MSG_EM_UNKNOWN33,	MSG_EM_UNKNOWN34,	MSG_EM_UNKNOWN35,
	MSG_EM_V800,		MSG_EM_FR20,		MSG_EM_RH32,
	MSG_EM_RCE,		MSG_EM_ARM_ALT,		MSG_EM_ALPHA_ALT,
	MSG_EM_SH,		MSG_EM_SPARCV9_ALT,	MSG_EM_TRICORE,
	MSG_EM_ARC,		MSG_EM_H8_300,		MSG_EM_H8_300H,
	MSG_EM_H8S,		MSG_EM_H8_500,		MSG_EM_IA_64_ALT,
	MSG_EM_MIPS_X,		MSG_EM_COLDFIRE,	MSG_EM_68HC12,
	MSG_EM_MMA,		MSG_EM_PCP,		MSG_EM_NCPU,
	MSG_EM_NDR1,		MSG_EM_STARCORE,	MSG_EM_ME16,
	MSG_EM_ST100,		MSG_EM_TINYJ,		MSG_EM_AMD64_ALT,
	MSG_EM_PDSP,		MSG_EM_UNKNOWN64,	MSG_EM_UNKNOWN65,
	MSG_EM_FX66,		MSG_EM_ST9PLUS,		MSG_EM_ST7,
	MSG_EM_68HC16,		MSG_EM_68HC11,		MSG_EM_68HC08,
	MSG_EM_68HC05,		MSG_EM_SVX,		MSG_EM_ST19,
	MSG_EM_VAX_ALT,		MSG_EM_CRIS,		MSG_EM_JAVELIN,
	MSG_EM_FIREPATH,	MSG_EM_ZSP,		MSG_EM_MMIX,
	MSG_EM_HUANY,		MSG_EM_PRISM,		MSG_EM_AVR,
	MSG_EM_FR30,		MSG_EM_D10V,		MSG_EM_D30V,
	MSG_EM_V850,		MSG_EM_M32R,		MSG_EM_MN10300,
	MSG_EM_MN10200,		MSG_EM_PJ,		MSG_EM_OPENRISC,
	MSG_EM_ARC_A5,		MSG_EM_XTENSA
};
#if	(EM_NUM != (EM_XTENSA + 1))
#error	"EM_NUM has grown"
#endif

const char *
conv_ehdr_mach(Half machine, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	/* Use alternative strings? */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (conv_map2str(inv_buf, machine, fmt_flags,
		    ARRAY_NELTS(machines_alt), machines_alt));
	}

	/* Use default strings */
	return (conv_map2str(inv_buf, machine, fmt_flags,
	    ARRAY_NELTS(machines), machines));
}


const char *
conv_ehdr_type(Half etype, Conv_fmt_flags_t fmt_flags, Conv_inv_buf_t *inv_buf)
{
	static const Msg	etypes[] = {
		MSG_ET_NONE,		MSG_ET_REL,		MSG_ET_EXEC,
		MSG_ET_DYN,		MSG_ET_CORE
	};
	static const Msg	etypes_alt[] = {
		MSG_ET_NONE_ALT,	MSG_ET_REL_ALT,		MSG_ET_EXEC_ALT,
		MSG_ET_DYN_ALT,		MSG_ET_CORE_ALT
	};

	if (etype == ET_SUNWPSEUDO) {
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
		case CONV_FMT_ALT_FILE:
			return (MSG_ORIG(MSG_ET_SUNWPSEUDO_ALT));
		default:
			return (MSG_ORIG(MSG_ET_SUNWPSEUDO));
		}
	}

	/* Use alternative strings? */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (conv_map2str(inv_buf, etype, fmt_flags,
		    ARRAY_NELTS(etypes_alt), etypes_alt));
	}

	/* Use default strings */
	return (conv_map2str(inv_buf, etype, fmt_flags,
	    ARRAY_NELTS(etypes), etypes));

}

const char *
conv_ehdr_vers(Word version, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	versions[] = {
		MSG_EV_NONE,		MSG_EV_CURRENT
	};
	static const Msg	versions_alt[] = {
		MSG_EV_NONE_ALT,	MSG_EV_CURRENT_ALT
	};

	/* Use alternative strings? */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (conv_map2str(inv_buf, version, fmt_flags,
		    ARRAY_NELTS(versions_alt), versions_alt));
	}

	/* Use default strings */
	return (conv_map2str(inv_buf, version, fmt_flags,
	    ARRAY_NELTS(versions), versions));
}

#define	EFLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_EF_SPARCV9_TSO_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
		MSG_EF_SPARC_SUN_US1_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
		MSG_EF_SPARC_HAL_R1_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
		MSG_EF_SPARC_SUN_US3_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

/*
 * Ensure that Conv_ehdr_flags_buf_t is large enough:
 *
 * EFLAGSZ is the real minimum size of the buffer required by conv_ehdr_flags().
 * However, Conv_ehdr_flags_buf_t uses CONV_EHDR_FLAG_BUFSIZE to set the
 * buffer size. We do things this way because the definition of EFLAGSZ uses
 * information that is not available in the environment of other programs
 * that include the conv.h header file.
 */
#if (CONV_EHDR_FLAGS_BUFSIZE != EFLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE EFLAGSZ
#include "report_bufsize.h"
#error "CONV_EHDR_FLAGS_BUFSIZE does not match EFLAGSZ"
#endif

/*
 * Make a string representation of the e_flags field.
 */
const char *
conv_ehdr_flags(Half mach, Word flags, Conv_fmt_flags_t fmt_flags,
    Conv_ehdr_flags_buf_t *flags_buf)
{
	static Val_desc vda[] = {
		{ EF_SPARC_32PLUS,	MSG_ORIG(MSG_EF_SPARC_32PLUS) },
		{ EF_SPARC_SUN_US1,	MSG_ORIG(MSG_EF_SPARC_SUN_US1) },
		{ EF_SPARC_HAL_R1,	MSG_ORIG(MSG_EF_SPARC_HAL_R1) },
		{ EF_SPARC_SUN_US3,	MSG_ORIG(MSG_EF_SPARC_SUN_US3) },
		{ 0,			0 }
	};
	static const Msg mm_flags[] = {
		MSG_EF_SPARCV9_TSO,	MSG_EF_SPARCV9_PSO,
		MSG_EF_SPARCV9_RMO
	};
	static const char *leading_str_arr[2];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (flags_buf->buf), vda, leading_str_arr };

	const char **lstr = leading_str_arr;

	conv_arg.buf = flags_buf->buf;

	/*
	 * Non-SPARC architectures presently provide no known flags.
	 */
	if ((mach == EM_SPARCV9) || (((mach == EM_SPARC) ||
	    (mach == EM_SPARC32PLUS)) && flags)) {
		/*
		 * Valid vendor extension bits for SPARCV9.  These must be
		 * updated along with elf_SPARC.h.
		 */

		conv_arg.oflags = conv_arg.rflags = flags;
		if ((mach == EM_SPARCV9) && (flags <= EF_SPARCV9_RMO)) {
			*lstr++ = MSG_ORIG(mm_flags[flags & EF_SPARCV9_MM]);
			conv_arg.rflags &= ~EF_SPARCV9_MM;
		}
		*lstr = NULL;

		(void) conv_expn_field(&conv_arg, fmt_flags);

		return (conv_arg.buf);
	}

	return (conv_invalid_val(&flags_buf->inv_buf, flags, CONV_FMT_DECIMAL));
}

/*
 * Make a string representation of the e_ident[EI_OSABI] field.
 */
const char *
conv_ehdr_osabi(uchar_t osabi, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	osabi_arr[] = {
		MSG_OSABI_NONE,		MSG_OSABI_HPUX,
		MSG_OSABI_NETBSD,	MSG_OSABI_LINUX,
		MSG_OSABI_UNKNOWN4,	MSG_OSABI_UNKNOWN5,
		MSG_OSABI_SOLARIS,	MSG_OSABI_AIX,
		MSG_OSABI_IRIX,		MSG_OSABI_FREEBSD,
		MSG_OSABI_TRU64,	MSG_OSABI_MODESTO,
		MSG_OSABI_OPENBSD,	MSG_OSABI_OPENVMS,
		MSG_OSABI_NSK,		MSG_OSABI_AROS
	};
	static const Msg	osabi_arr_alt[] = {
		MSG_OSABI_NONE_ALT,	MSG_OSABI_HPUX_ALT,
		MSG_OSABI_NETBSD_ALT,	MSG_OSABI_LINUX_ALT,
		MSG_OSABI_UNKNOWN4,	MSG_OSABI_UNKNOWN5,
		MSG_OSABI_SOLARIS_ALT,	MSG_OSABI_AIX_ALT,
		MSG_OSABI_IRIX_ALT,	MSG_OSABI_FREEBSD_ALT,
		MSG_OSABI_TRU64_ALT,	MSG_OSABI_MODESTO_ALT,
		MSG_OSABI_OPENBSD_ALT,	MSG_OSABI_OPENVMS_ALT,
		MSG_OSABI_NSK_ALT,	MSG_OSABI_AROS_ALT
	};

	const char *str;

	switch (osabi) {
	case ELFOSABI_ARM:
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
		case CONV_FMT_ALT_FILE:
			str = MSG_ORIG(MSG_OSABI_ARM_ALT);
			break;
		default:
			str = MSG_ORIG(MSG_OSABI_ARM);
		}
		break;

	case ELFOSABI_STANDALONE:
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
		case CONV_FMT_ALT_FILE:
			str = MSG_ORIG(MSG_OSABI_STANDALONE_ALT);
			break;
		default:
			str = MSG_ORIG(MSG_OSABI_STANDALONE);
		}
		break;

	default:
		switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
		case CONV_FMT_ALT_DUMP:
		case CONV_FMT_ALT_FILE:
			str = conv_map2str(inv_buf, osabi, fmt_flags,
			    ARRAY_NELTS(osabi_arr_alt), osabi_arr_alt);
			break;
		default:
			str = conv_map2str(inv_buf, osabi, fmt_flags,
			    ARRAY_NELTS(osabi_arr), osabi_arr);
		}
		break;
	}

	return (str);
}

/*
 * A generic means of returning additional information for a rejected file in
 * terms of a string.
 */
const char *
conv_reject_desc(Rej_desc * rej, Conv_reject_desc_buf_t *reject_desc_buf)
{
	ushort_t	type = rej->rej_type;
	uint_t		info = rej->rej_info;

	if (type == SGS_REJ_MACH)
		/* LINTED */
		return (conv_ehdr_mach((Half)info, 0,
		    &reject_desc_buf->inv_buf));
	else if (type == SGS_REJ_CLASS)
		/* LINTED */
		return (conv_ehdr_class((uchar_t)info, 0,
		    &reject_desc_buf->inv_buf));
	else if (type == SGS_REJ_DATA)
		/* LINTED */
		return (conv_ehdr_data((uchar_t)info, 0,
		    &reject_desc_buf->inv_buf));
	else if (type == SGS_REJ_TYPE)
		/* LINTED */
		return (conv_ehdr_type((Half)info, 0,
		    &reject_desc_buf->inv_buf));
	else if ((type == SGS_REJ_BADFLAG) || (type == SGS_REJ_MISFLAG) ||
	    (type == SGS_REJ_HAL) || (type == SGS_REJ_US3))
		/*
		 * Only called from ld.so.1, thus M_MACH is hardcoded.
		 */
		return (conv_ehdr_flags(M_MACH, (Word)info, 0,
		    &reject_desc_buf->flags_buf));
	else if (type == SGS_REJ_UNKFILE)
		return ((const char *)0);
	else if ((type == SGS_REJ_STR) || (type == SGS_REJ_HWCAP_1)) {
		if (rej->rej_str)
			return ((const char *)rej->rej_str);
		else
			return (MSG_ORIG(MSG_STR_EMPTY));
	} else
		return (conv_invalid_val(&reject_desc_buf->inv_buf, info,
		    CONV_FMT_DECIMAL));
}
