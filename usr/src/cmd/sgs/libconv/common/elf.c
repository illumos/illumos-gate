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
conv_ehdr_class(uchar_t class, int fmt_flags)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	classes[] = {
		MSG_ELFCLASSNONE, MSG_ELFCLASS32, MSG_ELFCLASS64
	};
	static const Msg	classes_alt[] = {
		MSG_ELFCLASSNONE_ALT, MSG_ELFCLASS32_ALT, MSG_ELFCLASS64_ALT
	};

	return (conv_map2str(string, sizeof (string), class, fmt_flags,
		ARRAY_NELTS(classes), classes, classes_alt, classes_alt));
}

const char *
conv_ehdr_data(uchar_t data, int fmt_flags)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	datas[] = {
		MSG_ELFDATANONE, MSG_ELFDATA2LSB, MSG_ELFDATA2MSB
	};
	static const Msg	datas_dump[] = {
		MSG_ELFDATANONE_ALT, MSG_ELFDATA2LSB_ALT1, MSG_ELFDATA2MSB_ALT1
	};
	static const Msg	datas_file[] = {
		MSG_ELFDATANONE_ALT, MSG_ELFDATA2LSB_ALT2, MSG_ELFDATA2MSB_ALT2
	};

	return (conv_map2str(string, sizeof (string), data, fmt_flags,
		ARRAY_NELTS(datas), datas, datas_dump, datas_file));
}

static const Msg machines[EM_NUM] = {
	MSG_EM_NONE,		MSG_EM_M32,		MSG_EM_SPARC,
	MSG_EM_386,		MSG_EM_68K,		MSG_EM_88K,
	MSG_EM_486,		MSG_EM_860,		MSG_EM_MIPS,
	MSG_EM_UNKNOWN9,	MSG_EM_MIPS_RS3_LE,	MSG_EM_RS6000,
	MSG_EM_UNKNOWN12,	MSG_EM_UNKNOWN13,	MSG_EM_UNKNOWN14,
	MSG_EM_PA_RISC,		MSG_EM_nCUBE,		MSG_EM_VPP500,
	MSG_EM_SPARC32PLUS,	MSG_EM_UNKNOWN19,	MSG_EM_PPC,
	MSG_EM_PPC64,		MSG_EM_UNKNOWN22,	MSG_EM_UNKNOWN23,
	MSG_EM_UNKNOWN24,	MSG_EM_UNKNOWN25,	MSG_EM_UNKNOWN26,
	MSG_EM_UNKNOWN27,	MSG_EM_UNKNOWN28,	MSG_EM_UNKNOWN29,
	MSG_EM_UNKNOWN30,	MSG_EM_UNKNOWN31,	MSG_EM_UNKNOWN32,
	MSG_EM_UNKNOWN33,	MSG_EM_UNKNOWN34,	MSG_EM_UNKNOWN35,
	MSG_EM_Y800,		MSG_EM_FR20,		MSG_EM_RH32,
	MSG_EM_RCE,		MSG_EM_ARM,		MSG_EM_ALPHA,
	MSG_EM_SH,		MSG_EM_SPARCV9,		MSG_EM_TRICORE,
	MSG_EM_ARC,		MSG_EM_H8_300,		MSG_EM_H8_300H,
	MSG_EM_H8S,		MSG_EM_H8_500,		MSG_EM_IA_64,
	MSG_EM_MIPS_X,		MSG_EM_COLDFIRE,	MSG_EM_68HC12,
	MSG_EM_MMA,		MSG_EM_PCP,		MSG_EM_NCPU,
	MSG_EM_NDR1,		MSG_EM_STARCORE,	MSG_EM_ME16,
	MSG_EM_ST100,		MSG_EM_TINYJ,		MSG_EM_AMD64,
	MSG_EM_UNKNOWN63,	MSG_EM_UNKNOWN64,	MSG_EM_UNKNOWN65,
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
	MSG_EM_UNKNOWN9,	MSG_EM_MIPS_RS3_LE_ALT,	MSG_EM_RS6000_ALT,
	MSG_EM_UNKNOWN12,	MSG_EM_UNKNOWN13,	MSG_EM_UNKNOWN14,
	MSG_EM_PA_RISC_ALT,	MSG_EM_nCUBE_ALT,	MSG_EM_VPP500_ALT,
	MSG_EM_SPARC32PLUS_ALT,	MSG_EM_UNKNOWN19,	MSG_EM_PPC_ALT,
	MSG_EM_PPC64_ALT,	MSG_EM_UNKNOWN22,	MSG_EM_UNKNOWN23,
	MSG_EM_UNKNOWN24,	MSG_EM_UNKNOWN25,	MSG_EM_UNKNOWN26,
	MSG_EM_UNKNOWN27,	MSG_EM_UNKNOWN28,	MSG_EM_UNKNOWN29,
	MSG_EM_UNKNOWN30,	MSG_EM_UNKNOWN31,	MSG_EM_UNKNOWN32,
	MSG_EM_UNKNOWN33,	MSG_EM_UNKNOWN34,	MSG_EM_UNKNOWN35,
	MSG_EM_Y800,		MSG_EM_FR20,		MSG_EM_RH32,
	MSG_EM_RCE,		MSG_EM_ARM_ALT,		MSG_EM_ALPHA_ALT,
	MSG_EM_SH,		MSG_EM_SPARCV9_ALT,	MSG_EM_TRICORE,
	MSG_EM_ARC,		MSG_EM_H8_300,		MSG_EM_H8_300H,
	MSG_EM_H8S,		MSG_EM_H8_500,		MSG_EM_IA_64_ALT,
	MSG_EM_MIPS_X,		MSG_EM_COLDFIRE,	MSG_EM_68HC12,
	MSG_EM_MMA,		MSG_EM_PCP,		MSG_EM_NCPU,
	MSG_EM_NDR1,		MSG_EM_STARCORE,	MSG_EM_ME16,
	MSG_EM_ST100,		MSG_EM_TINYJ,		MSG_EM_AMD64_ALT,
	MSG_EM_UNKNOWN63,	MSG_EM_UNKNOWN64,	MSG_EM_UNKNOWN65,
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
conv_ehdr_mach(Half machine, int fmt_flags)
{
	static char	string[CONV_INV_STRSIZE];

	return (conv_map2str(string, sizeof (string), machine, fmt_flags,
		ARRAY_NELTS(machines), machines, machines_alt, machines_alt));
}


const char *
conv_ehdr_type(Half etype, int fmt_flags)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	etypes[] = {
		MSG_ET_NONE,		MSG_ET_REL,		MSG_ET_EXEC,
		MSG_ET_DYN,		MSG_ET_CORE
	};
	static const Msg	etypes_alt[] = {
		MSG_ET_NONE_ALT,	MSG_ET_REL_ALT,		MSG_ET_EXEC_ALT,
		MSG_ET_DYN_ALT,		MSG_ET_CORE_ALT
	};

	if (etype == ET_SUNWPSEUDO) {
		return ((fmt_flags & CONV_FMTALTMASK)
			? MSG_ORIG(MSG_ET_SUNWPSEUDO_ALT)
			: MSG_ORIG(MSG_ET_SUNWPSEUDO));
	}

	return (conv_map2str(string, sizeof (string), etype, fmt_flags,
		ARRAY_NELTS(etypes), etypes, etypes_alt, etypes_alt));

}

const char *
conv_ehdr_vers(Word version, int fmt_flags)
{
	static char		string[CONV_INV_STRSIZE];
	static const Msg	versions[] = {
		MSG_EV_NONE,		MSG_EV_CURRENT
	};
	static const Msg	versions_alt[] = {
		MSG_EV_NONE_ALT,	MSG_EV_CURRENT_ALT
	};

	return (conv_map2str(string, sizeof (string), version, fmt_flags,
		ARRAY_NELTS(versions), versions, versions_alt, versions_alt));
}

#define	EFLAGSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_EF_SPARCV9_TSO_SIZE + \
		MSG_EF_SPARC_SUN_US1_SIZE + \
		MSG_EF_SPARC_HAL_R1_SIZE + \
		MSG_EF_SPARC_SUN_US3_SIZE + \
		CONV_INV_STRSIZE + MSG_GBL_CSQBRKT_SIZE

/*
 * Make a string representation of the e_flags field.
 */
const char *
conv_ehdr_flags(Half mach, Word flags)
{
	static char	string[EFLAGSZ];
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
	Word		_flags = flags;

	/*
	 * Non-SPARC architectures presently provide no known flags.
	 */
	if ((mach == EM_SPARCV9) || (((mach == EM_SPARC) ||
	    (mach == EM_SPARC32PLUS)) && flags)) {
		/*
		 * Valid vendor extension bits for SPARCV9.  These must be
		 * updated along with elf_SPARC.h.
		 */
		(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));

		if ((mach == EM_SPARCV9) && (flags <= EF_SPARCV9_RMO)) {
		    if (strlcat(string,
			MSG_ORIG(mm_flags[flags & EF_SPARCV9_MM]),
			EFLAGSZ) >= EFLAGSZ)
			    return (conv_invalid_val(string, EFLAGSZ,
				flags, 0));
		    _flags &= ~EF_SPARCV9_MM;
		}

		if (conv_expn_field(string, EFLAGSZ, vda, flags, _flags, 0, 0))
			(void) strlcat(string, MSG_ORIG(MSG_GBL_CSQBRKT),
			    EFLAGSZ);

		return (string);
	}
	return (conv_invalid_val(string, EFLAGSZ, flags, CONV_FMT_DECIMAL));
}

/*
 * A generic means of returning additional information for a rejected file in
 * terms of a string.
 */
const char *
conv_reject_desc(Rej_desc * rej)
{
	static char	string[CONV_INV_STRSIZE];

	ushort_t	type = rej->rej_type;
	uint_t		info = rej->rej_info;

	if (type == SGS_REJ_MACH)
		/* LINTED */
		return (conv_ehdr_mach((Half)info, 0));
	else if (type == SGS_REJ_CLASS)
		/* LINTED */
		return (conv_ehdr_class((uchar_t)info, 0));
	else if (type == SGS_REJ_DATA)
		/* LINTED */
		return (conv_ehdr_data((uchar_t)info, 0));
	else if (type == SGS_REJ_TYPE)
		/* LINTED */
		return (conv_ehdr_type((Half)info, 0));
	else if ((type == SGS_REJ_BADFLAG) || (type == SGS_REJ_MISFLAG) ||
	    (type == SGS_REJ_HAL) || (type == SGS_REJ_US3))
		/*
		 * Only called from ld.so.1, thus M_MACH is hardcoded.
		 */
		return (conv_ehdr_flags(M_MACH, (Word)info));
	else if (type == SGS_REJ_UNKFILE)
		return ((const char *)0);
	else if ((type == SGS_REJ_STR) || (type == SGS_REJ_HWCAP_1)) {
		if (rej->rej_str)
			return ((const char *)rej->rej_str);
		else
			return (MSG_ORIG(MSG_STR_EMPTY));
	} else
		return (conv_invalid_val(string, CONV_INV_STRSIZE, info,
		    CONV_FMT_DECIMAL));
}
