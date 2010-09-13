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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * String conversion routines for ELF header attributes.
 */
#include	<stdio.h>
#include	<string.h>
#include	"_conv.h"
#include	"elf_msg.h"
#include	<sys/elf_SPARC.h>



static const conv_ds_t **
ehdr_class_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	class_cf[] = {
		MSG_ELFCLASSNONE_CF, MSG_ELFCLASS32_CF, MSG_ELFCLASS64_CF
	};
	static const Msg	class_nf[] = {
		MSG_ELFCLASSNONE_NF, MSG_ELFCLASS32_NF, MSG_ELFCLASS64_NF
	};
	static const Msg	class_dump[] = {
		MSG_ELFCLASSNONE_DMP, MSG_ELFCLASS32_DMP, MSG_ELFCLASS64_DMP
	};

	static const conv_ds_msg_t ds_classes_cf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, class_cf) };
	static const conv_ds_msg_t ds_classes_nf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, class_nf) };
	static const conv_ds_msg_t ds_classes_dump = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, class_dump) };

	static const conv_ds_t *ds_cf[] = { CONV_DS_ADDR(ds_classes_cf), NULL };
	static const conv_ds_t *ds_nf[] = { CONV_DS_ADDR(ds_classes_nf), NULL };
	static const conv_ds_t *ds_dump[] = {
	    CONV_DS_ADDR(ds_classes_dump), NULL };

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (ds_dump);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);
}

const char *
conv_ehdr_class(uchar_t class, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, class,
	    ehdr_class_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_class(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    ehdr_class_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
ehdr_data_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	data_cf[] = {
		MSG_ELFDATANONE_CF, MSG_ELFDATA2LSB_CF, MSG_ELFDATA2MSB_CF
	};
	static const Msg	data_nf[] = {
		MSG_ELFDATANONE_NF, MSG_ELFDATA2LSB_NF, MSG_ELFDATA2MSB_NF
	};
	static const Msg	data_dump[] = {
		MSG_ELFDATANONE_DMP, MSG_ELFDATA2LSB_DMP, MSG_ELFDATA2MSB_DMP
	};
	static const Msg	data_file[] = {
		MSG_ELFDATANONE_DMP, MSG_ELFDATA2LSB_FIL, MSG_ELFDATA2MSB_FIL
	};


	static const conv_ds_msg_t ds_data_cf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, data_cf) };
	static const conv_ds_msg_t ds_data_nf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, data_nf) };
	static const conv_ds_msg_t ds_data_dump = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, data_dump) };
	static const conv_ds_msg_t ds_data_file = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, data_file) };

	static const conv_ds_t *ds_cf[] = { CONV_DS_ADDR(ds_data_cf), NULL };
	static const conv_ds_t *ds_nf[] = { CONV_DS_ADDR(ds_data_nf), NULL };
	static const conv_ds_t *ds_dump[] = { CONV_DS_ADDR(ds_data_dump),
	    NULL };
	static const conv_ds_t *ds_file[] = { CONV_DS_ADDR(ds_data_file),
	    NULL };

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (ds_dump);
	case CONV_FMT_ALT_FILE:
		return (ds_file);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);
}

const char *
conv_ehdr_data(uchar_t data, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, data,
	    ehdr_data_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_data(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    ehdr_data_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
ehdr_mach_strings(Conv_fmt_flags_t fmt_flags)
{

	static const Msg mach_0_11_cf[] = {
		MSG_EM_NONE_CF,		MSG_EM_M32_CF,
		MSG_EM_SPARC_CF,	MSG_EM_386_CF,
		MSG_EM_68K_CF,		MSG_EM_88K_CF,
		MSG_EM_486_CF,		MSG_EM_860_CF,
		MSG_EM_MIPS_CF,		MSG_EM_S370_CF,
		MSG_EM_MIPS_RS3_LE_CF,	MSG_EM_RS6000_CF
	};
	static const Msg mach_0_11_nf[] = {
		MSG_EM_NONE_NF,		MSG_EM_M32_NF,
		MSG_EM_SPARC_NF,	MSG_EM_386_NF,
		MSG_EM_68K_NF,		MSG_EM_88K_NF,
		MSG_EM_486_NF,		MSG_EM_860_NF,
		MSG_EM_MIPS_NF,		MSG_EM_S370_NF,
		MSG_EM_MIPS_RS3_LE_NF,	MSG_EM_RS6000_NF
	};
	static const Msg mach_0_11_dmp[] = {
		MSG_EM_NONE_DMP,	MSG_EM_M32_DMP,
		MSG_EM_SPARC_DMP,	MSG_EM_386_DMP,
		MSG_EM_68K_DMP,		MSG_EM_88K_DMP,
		MSG_EM_486_DMP,		MSG_EM_860_DMP,
		MSG_EM_MIPS_DMP,	MSG_EM_S370_CF,
		MSG_EM_MIPS_RS3_LE_DMP,	MSG_EM_RS6000_DMP
	};
	static const conv_ds_msg_t ds_mach_0_11_cf = {
	    CONV_DS_MSG_INIT(EM_NONE, mach_0_11_cf) };
	static const conv_ds_msg_t ds_mach_0_11_nf = {
	    CONV_DS_MSG_INIT(EM_NONE, mach_0_11_nf) };
	static const conv_ds_msg_t ds_mach_0_11_dmp = {
	    CONV_DS_MSG_INIT(EM_NONE, mach_0_11_dmp) };


	static const Msg mach_15_22_cf[] = {
		MSG_EM_PA_RISC_CF,	MSG_EM_NCUBE_CF,
		MSG_EM_VPP500_CF,	MSG_EM_SPARC32PLUS_CF,
		MSG_EM_960_CF,		MSG_EM_PPC_CF,
		MSG_EM_PPC64_CF,	MSG_EM_S390_CF
	};
	static const Msg mach_15_22_nf[] = {
		MSG_EM_PA_RISC_NF,	MSG_EM_NCUBE_NF,
		MSG_EM_VPP500_NF,	MSG_EM_SPARC32PLUS_NF,
		MSG_EM_960_NF,		MSG_EM_PPC_NF,
		MSG_EM_PPC64_NF,	MSG_EM_S390_NF
	};
	static const Msg mach_15_22_dmp[] = {
		MSG_EM_PA_RISC_DMP,	MSG_EM_NCUBE_DMP,
		MSG_EM_VPP500_DMP,	MSG_EM_SPARC32PLUS_DMP,
		MSG_EM_960_CF,		MSG_EM_PPC_DMP,
		MSG_EM_PPC64_DMP,	MSG_EM_S390_CF
	};
	static const conv_ds_msg_t ds_mach_15_22_cf = {
	    CONV_DS_MSG_INIT(EM_PA_RISC, mach_15_22_cf) };
	static const conv_ds_msg_t ds_mach_15_22_nf = {
	    CONV_DS_MSG_INIT(EM_PA_RISC, mach_15_22_nf) };
	static const conv_ds_msg_t ds_mach_15_22_dmp = {
	    CONV_DS_MSG_INIT(EM_PA_RISC, mach_15_22_dmp) };


	static const Msg mach_36_63_cf[] = {
		MSG_EM_V800_CF,		MSG_EM_FR20_CF,
		MSG_EM_RH32_CF,		MSG_EM_RCE_CF,
		MSG_EM_ARM_CF,		MSG_EM_ALPHA_CF,
		MSG_EM_SH_CF,		MSG_EM_SPARCV9_CF,
		MSG_EM_TRICORE_CF,	MSG_EM_ARC_CF,
		MSG_EM_H8_300_CF,	MSG_EM_H8_300H_CF,
		MSG_EM_H8S_CF,		MSG_EM_H8_500_CF,
		MSG_EM_IA_64_CF,	MSG_EM_MIPS_X_CF,
		MSG_EM_COLDFIRE_CF,	MSG_EM_68HC12_CF,
		MSG_EM_MMA_CF,		MSG_EM_PCP_CF,
		MSG_EM_NCPU_CF,		MSG_EM_NDR1_CF,
		MSG_EM_STARCORE_CF,	MSG_EM_ME16_CF,
		MSG_EM_ST100_CF,	MSG_EM_TINYJ_CF,
		MSG_EM_AMD64_CF,	MSG_EM_PDSP_CF
	};
	static const Msg mach_36_63_nf[] = {
		MSG_EM_V800_NF,		MSG_EM_FR20_NF,
		MSG_EM_RH32_NF,		MSG_EM_RCE_NF,
		MSG_EM_ARM_NF,		MSG_EM_ALPHA_NF,
		MSG_EM_SH_NF,		MSG_EM_SPARCV9_NF,
		MSG_EM_TRICORE_NF,	MSG_EM_ARC_NF,
		MSG_EM_H8_300_NF,	MSG_EM_H8_300H_NF,
		MSG_EM_H8S_NF,		MSG_EM_H8_500_NF,
		MSG_EM_IA_64_NF,	MSG_EM_MIPS_X_NF,
		MSG_EM_COLDFIRE_NF,	MSG_EM_68HC12_NF,
		MSG_EM_MMA_NF,		MSG_EM_PCP_NF,
		MSG_EM_NCPU_NF,		MSG_EM_NDR1_NF,
		MSG_EM_STARCORE_NF,	MSG_EM_ME16_NF,
		MSG_EM_ST100_NF,	MSG_EM_TINYJ_NF,
		MSG_EM_AMD64_NF,	MSG_EM_PDSP_NF
	};
	static const Msg mach_36_63_dmp[] = {
		MSG_EM_V800_CF,		MSG_EM_FR20_CF,
		MSG_EM_RH32_CF,		MSG_EM_RCE_CF,
		MSG_EM_ARM_DMP,		MSG_EM_ALPHA_DMP,
		MSG_EM_SH_CF,		MSG_EM_SPARCV9_DMP,
		MSG_EM_TRICORE_CF,	MSG_EM_ARC_CF,
		MSG_EM_H8_300_CF,	MSG_EM_H8_300H_CF,
		MSG_EM_H8S_CF,		MSG_EM_H8_500_CF,
		MSG_EM_IA_64_DMP,	MSG_EM_MIPS_X_CF,
		MSG_EM_COLDFIRE_CF,	MSG_EM_68HC12_CF,
		MSG_EM_MMA_CF,		MSG_EM_PCP_CF,
		MSG_EM_NCPU_CF,		MSG_EM_NDR1_CF,
		MSG_EM_STARCORE_CF,	MSG_EM_ME16_CF,
		MSG_EM_ST100_CF,	MSG_EM_TINYJ_CF,
		MSG_EM_AMD64_DMP,	MSG_EM_PDSP_CF
	};
	static const conv_ds_msg_t ds_mach_36_63_cf = {
	    CONV_DS_MSG_INIT(EM_V800, mach_36_63_cf) };
	static const conv_ds_msg_t ds_mach_36_63_nf = {
	    CONV_DS_MSG_INIT(EM_V800, mach_36_63_nf) };
	static const conv_ds_msg_t ds_mach_36_63_dmp = {
	    CONV_DS_MSG_INIT(EM_V800, mach_36_63_dmp) };


	static const Msg mach_66_94_cf[] = {
		MSG_EM_FX66_CF,		MSG_EM_ST9PLUS_CF,
		MSG_EM_ST7_CF,		MSG_EM_68HC16_CF,
		MSG_EM_68HC11_CF,	MSG_EM_68HC08_CF,
		MSG_EM_68HC05_CF,	MSG_EM_SVX_CF,
		MSG_EM_ST19_CF,		MSG_EM_VAX_CF,
		MSG_EM_CRIS_CF,		MSG_EM_JAVELIN_CF,
		MSG_EM_FIREPATH_CF,	MSG_EM_ZSP_CF,
		MSG_EM_MMIX_CF,		MSG_EM_HUANY_CF,
		MSG_EM_PRISM_CF,	MSG_EM_AVR_CF,
		MSG_EM_FR30_CF,		MSG_EM_D10V_CF,
		MSG_EM_D30V_CF,		MSG_EM_V850_CF,
		MSG_EM_M32R_CF,		MSG_EM_MN10300_CF,
		MSG_EM_MN10200_CF,	MSG_EM_PJ_CF,
		MSG_EM_OPENRISC_CF,	MSG_EM_ARC_A5_CF,
		MSG_EM_XTENSA_CF
	};
	static const Msg mach_66_94_nf[] = {
		MSG_EM_FX66_NF,		MSG_EM_ST9PLUS_NF,
		MSG_EM_ST7_NF,		MSG_EM_68HC16_NF,
		MSG_EM_68HC11_NF,	MSG_EM_68HC08_NF,
		MSG_EM_68HC05_NF,	MSG_EM_SVX_NF,
		MSG_EM_ST19_NF,		MSG_EM_VAX_NF,
		MSG_EM_CRIS_NF,		MSG_EM_JAVELIN_NF,
		MSG_EM_FIREPATH_NF,	MSG_EM_ZSP_NF,
		MSG_EM_MMIX_NF,		MSG_EM_HUANY_NF,
		MSG_EM_PRISM_NF,	MSG_EM_AVR_NF,
		MSG_EM_FR30_NF,		MSG_EM_D10V_NF,
		MSG_EM_D30V_NF,		MSG_EM_V850_NF,
		MSG_EM_M32R_NF,		MSG_EM_MN10300_NF,
		MSG_EM_MN10200_NF,	MSG_EM_PJ_NF,
		MSG_EM_OPENRISC_NF,	MSG_EM_ARC_A5_NF,
		MSG_EM_XTENSA_NF
	};
	static const Msg mach_66_94_dmp[] = {
		MSG_EM_FX66_CF,		MSG_EM_ST9PLUS_CF,
		MSG_EM_ST7_CF,		MSG_EM_68HC16_CF,
		MSG_EM_68HC11_CF,	MSG_EM_68HC08_CF,
		MSG_EM_68HC05_CF,	MSG_EM_SVX_CF,
		MSG_EM_ST19_CF,		MSG_EM_VAX_DMP,
		MSG_EM_CRIS_CF,		MSG_EM_JAVELIN_CF,
		MSG_EM_FIREPATH_CF,	MSG_EM_ZSP_CF,
		MSG_EM_MMIX_CF,		MSG_EM_HUANY_CF,
		MSG_EM_PRISM_CF,	MSG_EM_AVR_CF,
		MSG_EM_FR30_CF,		MSG_EM_D10V_CF,
		MSG_EM_D30V_CF,		MSG_EM_V850_CF,
		MSG_EM_M32R_CF,		MSG_EM_MN10300_CF,
		MSG_EM_MN10200_CF,	MSG_EM_PJ_CF,
		MSG_EM_OPENRISC_CF,	MSG_EM_ARC_A5_CF,
		MSG_EM_XTENSA_CF
	};
#if	(EM_NUM != (EM_XTENSA + 1))
#error	"EM_NUM has grown"
#endif
	static const conv_ds_msg_t ds_mach_66_94_cf = {
	    CONV_DS_MSG_INIT(EM_FX66, mach_66_94_cf) };
	static const conv_ds_msg_t ds_mach_66_94_nf = {
	    CONV_DS_MSG_INIT(EM_FX66, mach_66_94_nf) };
	static const conv_ds_msg_t ds_mach_66_94_dmp = {
	    CONV_DS_MSG_INIT(EM_FX66, mach_66_94_dmp) };


	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_mach_0_11_cf), CONV_DS_ADDR(ds_mach_15_22_cf),
		CONV_DS_ADDR(ds_mach_36_63_cf), CONV_DS_ADDR(ds_mach_66_94_cf),
		NULL
	};
	static const const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_mach_0_11_nf), CONV_DS_ADDR(ds_mach_15_22_nf),
		CONV_DS_ADDR(ds_mach_36_63_nf), CONV_DS_ADDR(ds_mach_66_94_nf),
		NULL
	};
	static const const conv_ds_t	*ds_dmp[] = {
		CONV_DS_ADDR(ds_mach_0_11_dmp), CONV_DS_ADDR(ds_mach_15_22_dmp),
		CONV_DS_ADDR(ds_mach_36_63_dmp),
		CONV_DS_ADDR(ds_mach_66_94_dmp), NULL
	};


	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
	case CONV_FMT_ALT_FILE:
		return (ds_dmp);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);
}

const char *
conv_ehdr_mach(Half machine, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, machine,
	    ehdr_mach_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_mach(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	static const Val_desc extra_dmp_nf[] = {
		{ EM_M32,		MSG_EM_M32_DMP},
		{ EM_386,		MSG_EM_386_DMP },
		{ EM_68K,		MSG_EM_68K_DMP },
		{ EM_88K,		MSG_EM_88K_DMP },
		{ EM_486,		MSG_EM_486_DMP },
		{ EM_860,		MSG_EM_860_DMP },
		{ EM_MIPS,		MSG_EM_MIPS_DMP },
		{ EM_MIPS_RS3_LE,	MSG_EM_MIPS_RS3_LE_DMP },
		{ EM_PPC,		MSG_EM_PPC_DMP },
		{ EM_PPC64,		MSG_EM_PPC64_DMP },

		{ 0 }
	};

	if (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    ehdr_mach_strings(fmt_flags), func, uvalue) == CONV_ITER_DONE)
		return (CONV_ITER_DONE);

	/*
	 * For the NF style, we also supply a few of the traditional
	 * dump versions for iteration, but not for display.
	 */
	if (CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF)
		return (conv_iter_vd(extra_dmp_nf, func, uvalue));

	return (CONV_ITER_CONT);
}



static const conv_ds_t **
ehdr_eident_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	eident_cf[] = {
		MSG_EI_MAG0_CF,		MSG_EI_MAG1_CF,
		MSG_EI_MAG2_CF,		MSG_EI_MAG3_CF,
		MSG_EI_CLASS_CF,	MSG_EI_DATA_CF,
		MSG_EI_VERSION_CF,	MSG_EI_OSABI_CF,
		MSG_EI_ABIVERSION_CF
	};
	static const Msg	eident_nf[] = {
		MSG_EI_MAG0_NF,		MSG_EI_MAG1_NF,
		MSG_EI_MAG2_NF,		MSG_EI_MAG3_NF,
		MSG_EI_CLASS_NF,	MSG_EI_DATA_NF,
		MSG_EI_VERSION_NF,	MSG_EI_OSABI_NF,
		MSG_EI_ABIVERSION_NF
	};
#if EI_PAD != (EI_ABIVERSION + 1)
error "EI_PAD has grown. Update etypes[]"
#endif
	static const conv_ds_msg_t ds_eident_cf = {
		CONV_DS_MSG_INIT(EI_MAG0, eident_cf) };
	static const conv_ds_msg_t ds_eident_nf = {
		CONV_DS_MSG_INIT(EI_MAG0, eident_nf) };

	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_eident_cf), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_eident_nf), NULL };

	/* Select the strings to use */
	return ((CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_CF) ?
	    ds_cf : ds_nf);
}

conv_iter_ret_t
conv_iter_ehdr_eident(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    ehdr_eident_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
ehdr_type_strings(Conv_fmt_flags_t fmt_flags)
{
#define	SOL	ELFOSABI_SOLARIS, EM_NONE

	static const Msg	type_cf[] = {
		MSG_ET_NONE_CF,		MSG_ET_REL_CF,		MSG_ET_EXEC_CF,
		MSG_ET_DYN_CF,		MSG_ET_CORE_CF
	};
	static const Msg	type_nf[] = {
		MSG_ET_NONE_NF,		MSG_ET_REL_NF,		MSG_ET_EXEC_NF,
		MSG_ET_DYN_NF,		MSG_ET_CORE_NF
	};
	static const Msg	type_dmp[] = {
		MSG_ET_NONE_DMP,	MSG_ET_REL_DMP,		MSG_ET_EXEC_DMP,
		MSG_ET_DYN_DMP,		MSG_ET_CORE_DMP
	};
#if ET_NUM != (ET_CORE + 1)
error "ET_NUM has grown. Update types[]"
#endif
	static const conv_ds_msg_t ds_type_cf = {
		CONV_DS_MSG_INIT(ET_NONE, type_cf) };
	static const conv_ds_msg_t ds_type_nf = {
		CONV_DS_MSG_INIT(ET_NONE, type_nf) };
	static const conv_ds_msg_t ds_type_dmp = {
		CONV_DS_MSG_INIT(ET_NONE, type_dmp) };

	static const Val_desc2 type_osabi_cf[] = {
		{ ET_SUNWPSEUDO,	SOL,	MSG_ET_SUNWPSEUDO_CF },
		{ 0 }
	};
	static const Val_desc2 type_osabi_nf[] = {
		{ ET_SUNWPSEUDO,	SOL,	MSG_ET_SUNWPSEUDO_NF },
		{ 0 }
	};
	static const Val_desc2 type_osabi_dmp[] = {
		{ ET_SUNWPSEUDO,	SOL,	MSG_ET_SUNWPSEUDO_DMP },
		{ 0 }
	};
#if ET_LOSUNW != ET_SUNWPSEUDO
error "ET_LOSUNW has grown. Update type_osabi[]"
#endif
	static const conv_ds_vd2_t ds_type_osabi_cf = {
	    CONV_DS_VD2, ET_LOOS, ET_HIOS, type_osabi_cf };
	static const conv_ds_vd2_t ds_type_osabi_nf = {
	    CONV_DS_VD2, ET_LOOS, ET_HIOS, type_osabi_nf };
	static const conv_ds_vd2_t ds_type_osabi_dmp = {
	    CONV_DS_VD2, ET_LOOS, ET_HIOS, type_osabi_dmp };


	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_type_cf), CONV_DS_ADDR(ds_type_osabi_cf),
		NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_type_nf), CONV_DS_ADDR(ds_type_osabi_nf),
		NULL };
	static const conv_ds_t	*ds_dmp[] = {
		CONV_DS_ADDR(ds_type_dmp), CONV_DS_ADDR(ds_type_osabi_dmp),
		NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (ds_dmp);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);

#undef SOL
}

const char *
conv_ehdr_type(uchar_t osabi, Half etype, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(osabi, EM_NONE, etype,
	    ehdr_type_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_type(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(osabi, EM_NONE,
	    ehdr_type_strings(fmt_flags), func, uvalue));
}

static const conv_ds_t **
ehdr_vers_strings(Conv_fmt_flags_t fmt_flags)
{
	static const Msg	versions_cf[] = {
		MSG_EV_NONE_CF,		MSG_EV_CURRENT_CF
	};
	static const Msg	versions_nf[] = {
		MSG_EV_NONE_NF,		MSG_EV_CURRENT_NF
	};
	static const Msg	versions_dmp[] = {
		MSG_EV_NONE_DMP,	MSG_EV_CURRENT_DMP
	};
#if EV_NUM != 2
error "EV_NUM has grown. Update versions[]"
#endif
	static const conv_ds_msg_t ds_versions_cf = {
		CONV_DS_MSG_INIT(EV_NONE, versions_cf) };
	static const conv_ds_msg_t ds_versions_nf = {
		CONV_DS_MSG_INIT(EV_NONE, versions_nf) };
	static const conv_ds_msg_t ds_versions_dmp = {
		CONV_DS_MSG_INIT(EV_NONE, versions_dmp) };

	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_versions_cf), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_versions_nf), NULL };
	static const conv_ds_t	*ds_dmp[] = {
		CONV_DS_ADDR(ds_versions_dmp), NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (ds_dmp);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);
}

const char *
conv_ehdr_vers(Word version, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, version,
	    ehdr_vers_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_vers(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    ehdr_vers_strings(fmt_flags), func, uvalue));
}

static void
conv_ehdr_sparc_flags_strings(Conv_fmt_flags_t fmt_flags,
    const conv_ds_msg_t **mm_msg, const Val_desc **flag_desc)
{
#define	EFLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
	MSG_EF_SPARCV9_TSO_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
	MSG_EF_SPARC_SUN_US1_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
	MSG_EF_SPARC_HAL_R1_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
	MSG_EF_SPARC_SUN_US3_CF_SIZE	+ CONV_EXPN_FIELD_DEF_SEP_SIZE +  \
	CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

	/*
	 * Ensure that Conv_ehdr_flags_buf_t is large enough:
	 *
	 * EFLAGSZ is the real minimum size of the buffer required by
	 * conv_ehdr_flags(). However, Conv_ehdr_flags_buf_t uses
	 * CONV_EHDR_FLAG_BUFSIZE to set the buffer size. We do things
	 * this way because the definition of EFLAGSZ uses information
	 * that is not available in the environment of other programs
	 * that include the conv.h header file.
	 */
#if (CONV_EHDR_FLAGS_BUFSIZE != EFLAGSZ) && !defined(__lint)
#define	REPORT_BUFSIZE EFLAGSZ
#include "report_bufsize.h"
#error "CONV_EHDR_FLAGS_BUFSIZE does not match EFLAGSZ"
#endif

	static const Msg mm_flags_cf[] = {
		MSG_EF_SPARCV9_TSO_CF,	MSG_EF_SPARCV9_PSO_CF,
		MSG_EF_SPARCV9_RMO_CF
	};
	static const Msg mm_flags_nf[] = {
		MSG_EF_SPARCV9_TSO_NF,	MSG_EF_SPARCV9_PSO_NF,
		MSG_EF_SPARCV9_RMO_NF
	};
	static const conv_ds_msg_t ds_mm_flags_cf = {
		CONV_DS_MSG_INIT(EF_SPARCV9_TSO, mm_flags_cf) };
	static const conv_ds_msg_t ds_mm_flags_nf = {
		CONV_DS_MSG_INIT(EF_SPARCV9_TSO, mm_flags_nf) };


	static const Val_desc vda_cf[] = {
		{ EF_SPARC_32PLUS,	MSG_EF_SPARC_32PLUS_CF },
		{ EF_SPARC_SUN_US1,	MSG_EF_SPARC_SUN_US1_CF },
		{ EF_SPARC_HAL_R1,	MSG_EF_SPARC_HAL_R1_CF },
		{ EF_SPARC_SUN_US3,	MSG_EF_SPARC_SUN_US3_CF },
		{ 0 }
	};
	static const Val_desc vda_nf[] = {
		{ EF_SPARC_32PLUS,	MSG_EF_SPARC_32PLUS_NF },
		{ EF_SPARC_SUN_US1,	MSG_EF_SPARC_SUN_US1_NF },
		{ EF_SPARC_HAL_R1,	MSG_EF_SPARC_HAL_R1_NF },
		{ EF_SPARC_SUN_US3,	MSG_EF_SPARC_SUN_US3_NF },
		{ 0 }
	};

	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	default:
		*mm_msg = &ds_mm_flags_cf;
		*flag_desc = vda_cf;
		break;
	case CONV_FMT_ALT_NF:
		*mm_msg = &ds_mm_flags_nf;
		*flag_desc = vda_nf;
		break;
	}
}

/*
 * Make a string representation of the e_flags field.
 */
const char *
conv_ehdr_flags(Half mach, Word flags, Conv_fmt_flags_t fmt_flags,
    Conv_ehdr_flags_buf_t *flags_buf)
{
	static const char *leading_str_arr[2];
	static CONV_EXPN_FIELD_ARG conv_arg = {
	    NULL, sizeof (flags_buf->buf), leading_str_arr };

	const char **lstr;
	const conv_ds_msg_t	*mm_msg;
	const Val_desc		*vdp;
	Word			mm;

	/*
	 * Non-SPARC architectures presently provide no known flags.
	 */
	if ((mach != EM_SPARCV9) && (((mach != EM_SPARC) &&
	    (mach != EM_SPARC32PLUS)) || (flags == 0)))
		return (conv_invalid_val(&flags_buf->inv_buf, flags,
		    CONV_FMT_DECIMAL));

	conv_arg.buf = flags_buf->buf;
	conv_ehdr_sparc_flags_strings(fmt_flags, &mm_msg, &vdp);
	conv_arg.oflags = conv_arg.rflags = flags;

	mm = flags & EF_SPARCV9_MM;
	lstr = leading_str_arr;
	if ((mach == EM_SPARCV9) && (mm <= mm_msg->ds_topval)) {
		*lstr++ = MSG_ORIG(mm_msg->ds_msg[mm]);
		conv_arg.rflags &= ~EF_SPARCV9_MM;
	}
	*lstr = NULL;

	(void) conv_expn_field(&conv_arg, vdp, fmt_flags);

	return (conv_arg.buf);
}

conv_iter_ret_t
conv_iter_ehdr_flags(Half mach, Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{

	if ((mach == EM_SPARCV9) || (mach == EM_SPARC) ||
	    (mach == EM_SPARC32PLUS) || (mach == CONV_MACH_ALL)) {
		const conv_ds_msg_t	*ds_msg_mm;
		const Val_desc		*vdp;

		conv_ehdr_sparc_flags_strings(fmt_flags, &ds_msg_mm, &vdp);

		if (mach == EM_SPARCV9) {
			const conv_ds_t *ds[2];

			ds[0] = CONV_DS_ADDR(ds_msg_mm);
			ds[1] = NULL;

			if (conv_iter_ds(ELFOSABI_NONE, mach, ds,
			    func, uvalue) == CONV_ITER_DONE)
				return (CONV_ITER_DONE);
		}

		return (conv_iter_vd(vdp, func, uvalue));
	}

	return (CONV_ITER_CONT);
}

static const conv_ds_t **
ehdr_osabi_strings(Conv_fmt_flags_t fmt_flags)
{

	static const Msg osabi_0_3_cf[] = {
		MSG_OSABI_NONE_CF,	MSG_OSABI_HPUX_CF,
		MSG_OSABI_NETBSD_CF,	MSG_OSABI_LINUX_CF
	};
	static const Msg osabi_0_3_nf[] = {
		MSG_OSABI_NONE_NF,	MSG_OSABI_HPUX_NF,
		MSG_OSABI_NETBSD_NF,	MSG_OSABI_LINUX_NF
	};
	static const Msg osabi_0_3_dmp[] = {
		MSG_OSABI_NONE_DMP,	MSG_OSABI_HPUX_DMP,
		MSG_OSABI_NETBSD_DMP,	MSG_OSABI_LINUX_DMP
	};
	static const conv_ds_msg_t ds_osabi_0_3_cf = {
	    CONV_DS_MSG_INIT(ELFOSABI_NONE, osabi_0_3_cf) };
	static const conv_ds_msg_t ds_osabi_0_3_nf = {
	    CONV_DS_MSG_INIT(ELFOSABI_NONE, osabi_0_3_nf) };
	static const conv_ds_msg_t ds_osabi_0_3_dmp = {
	    CONV_DS_MSG_INIT(ELFOSABI_NONE, osabi_0_3_dmp) };


	static const Msg osabi_6_15_cf[] = {
		MSG_OSABI_SOLARIS_CF,	MSG_OSABI_AIX_CF,
		MSG_OSABI_IRIX_CF,	MSG_OSABI_FREEBSD_CF,
		MSG_OSABI_TRU64_CF,	MSG_OSABI_MODESTO_CF,
		MSG_OSABI_OPENBSD_CF,	MSG_OSABI_OPENVMS_CF,
		MSG_OSABI_NSK_CF,	MSG_OSABI_AROS_CF
	};
	static const Msg osabi_6_15_nf[] = {
		MSG_OSABI_SOLARIS_NF,	MSG_OSABI_AIX_NF,
		MSG_OSABI_IRIX_NF,	MSG_OSABI_FREEBSD_NF,
		MSG_OSABI_TRU64_NF,	MSG_OSABI_MODESTO_NF,
		MSG_OSABI_OPENBSD_NF,	MSG_OSABI_OPENVMS_NF,
		MSG_OSABI_NSK_NF,	MSG_OSABI_AROS_NF
	};
	static const Msg osabi_6_15_dmp[] = {
		MSG_OSABI_SOLARIS_DMP,	MSG_OSABI_AIX_DMP,
		MSG_OSABI_IRIX_DMP,	MSG_OSABI_FREEBSD_DMP,
		MSG_OSABI_TRU64_DMP,	MSG_OSABI_MODESTO_DMP,
		MSG_OSABI_OPENBSD_DMP,	MSG_OSABI_OPENVMS_DMP,
		MSG_OSABI_NSK_DMP,	MSG_OSABI_AROS_DMP
	};
	static const conv_ds_msg_t ds_osabi_6_15_cf = {
	    CONV_DS_MSG_INIT(ELFOSABI_SOLARIS, osabi_6_15_cf) };
	static const conv_ds_msg_t ds_osabi_6_15_nf = {
	    CONV_DS_MSG_INIT(ELFOSABI_SOLARIS, osabi_6_15_nf) };
	static const conv_ds_msg_t ds_osabi_6_15_dmp = {
	    CONV_DS_MSG_INIT(ELFOSABI_SOLARIS, osabi_6_15_dmp) };


	static const Val_desc osabi_misc_cf[] = {
		{ ELFOSABI_ARM,			MSG_OSABI_ARM_CF },
		{ ELFOSABI_STANDALONE,		MSG_OSABI_STANDALONE_CF },
		{ 0 }
	};
	static const Val_desc osabi_misc_nf[] = {
		{ ELFOSABI_ARM,			MSG_OSABI_ARM_NF },
		{ ELFOSABI_STANDALONE,		MSG_OSABI_STANDALONE_NF },
		{ 0 }
	};
	static const Val_desc osabi_misc_dmp[] = {
		{ ELFOSABI_ARM,			MSG_OSABI_ARM_DMP },
		{ ELFOSABI_STANDALONE,		MSG_OSABI_STANDALONE_DMP },
		{ 0 }
	};
	static const conv_ds_vd_t ds_osabi_misc_cf = {
	    CONV_DS_VD, ELFOSABI_ARM, ELFOSABI_STANDALONE, osabi_misc_cf };
	static const conv_ds_vd_t ds_osabi_misc_nf = {
	    CONV_DS_VD, ELFOSABI_ARM, ELFOSABI_STANDALONE, osabi_misc_nf };
	static const conv_ds_vd_t ds_osabi_misc_dmp = {
	    CONV_DS_VD, ELFOSABI_ARM, ELFOSABI_STANDALONE, osabi_misc_dmp };

	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_osabi_0_3_cf), CONV_DS_ADDR(ds_osabi_6_15_cf),
		CONV_DS_ADDR(ds_osabi_misc_cf), NULL };
	static const const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_osabi_0_3_nf), CONV_DS_ADDR(ds_osabi_6_15_nf),
		CONV_DS_ADDR(ds_osabi_misc_nf), NULL };
	static const const conv_ds_t	*ds_dmp[] = {
		CONV_DS_ADDR(ds_osabi_0_3_dmp), CONV_DS_ADDR(ds_osabi_6_15_dmp),
		CONV_DS_ADDR(ds_osabi_misc_dmp), NULL };

	/* Select the strings to use */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_DUMP:
		return (ds_dmp);
	case CONV_FMT_ALT_NF:
		return (ds_nf);
	}

	return (ds_cf);
}

/*
 * Make a string representation of the e_ident[EI_OSABI] field.
 */
const char *
conv_ehdr_osabi(uchar_t osabi, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, osabi,
	    ehdr_osabi_strings(fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_osabi(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	if (conv_iter_ds(ELFOSABI_NONE, EM_NONE, ehdr_osabi_strings(fmt_flags),
	    func, uvalue) == CONV_ITER_DONE)
		return (CONV_ITER_DONE);

	/*
	 * ELFOSABI_NONE might have been better named ELFOSABI_SYSV. For the
	 * CF and NF sytles, we supply that name for 0 in addition to NONE.
	 */
	switch (CONV_TYPE_FMT_ALT(fmt_flags)) {
	case CONV_FMT_ALT_CF:
		return ((* func)(MSG_ORIG(MSG_OSABI_SYSV_CF),
		    ELFOSABI_NONE, uvalue));
	case CONV_FMT_ALT_NF:
		return ((* func)(MSG_ORIG(MSG_OSABI_SYSV_NF),
		    ELFOSABI_NONE, uvalue));
	}

		return (CONV_ITER_CONT);
}

static const conv_ds_t **
ehdr_abivers_strings(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags)
{
	static const Msg	abiversions_cf[] = {
		MSG_EAV_SUNW_NONE_CF,	MSG_EAV_SUNW_CURRENT_CF
	};
	static const Msg	abiversions_nf[] = {
		MSG_EAV_SUNW_NONE_NF,	MSG_EAV_SUNW_CURRENT_NF
	};
#if EAV_SUNW_NUM != 2
error "EAV_SUNW_NUM has grown. Update abiversions[]"
#endif
	static const conv_ds_msg_t ds_abiversions_cf = {
		CONV_DS_MSG_INIT(EV_NONE, abiversions_cf) };
	static const conv_ds_msg_t ds_abiversions_nf = {
		CONV_DS_MSG_INIT(EV_NONE, abiversions_nf) };

	/* Build NULL terminated return arrays for each string style */
	static const const conv_ds_t	*ds_cf[] = {
		CONV_DS_ADDR(ds_abiversions_cf), NULL };
	static const conv_ds_t	*ds_nf[] = {
		CONV_DS_ADDR(ds_abiversions_nf), NULL };

	/* For non-Solaris OSABI, we don't have symbolic names */
	static const conv_ds_t	*ds_none[] = { NULL };


	/*
	 * Select the strings to use. This is a rare case where
	 * we don't treat ELFOSABI_NONE and ELFOSABI_SOLARIS
	 * as the same thing. We should never create a Solaris
	 * object tagged as ELFOSABI_NONE for which the abiversion
	 * is non-zero.
	 */
	if ((osabi == ELFOSABI_SOLARIS) || (osabi == CONV_OSABI_ALL))
		return ((CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
		    ds_nf : ds_cf);

	return (ds_none);
}

const char *
conv_ehdr_abivers(uchar_t osabi, Word version, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	return (conv_map_ds(osabi, EM_NONE, version,
	    ehdr_abivers_strings(osabi, fmt_flags), fmt_flags, inv_buf));
}

conv_iter_ret_t
conv_iter_ehdr_abivers(conv_iter_osabi_t osabi, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	return (conv_iter_ds(osabi, EM_NONE,
	    ehdr_abivers_strings(osabi, fmt_flags), func, uvalue));
}

/*
 * A generic means of returning additional information for a rejected file in
 * terms of a string. ELFOSABI_SOLARIS is assummed.
 */
const char *
conv_reject_desc(Rej_desc * rej, Conv_reject_desc_buf_t *reject_desc_buf,
    Half mach)
{
	ushort_t	type = rej->rej_type;
	uint_t		info = rej->rej_info;

	switch (type) {
	case SGS_REJ_MACH:
		return (conv_ehdr_mach((Half)info, 0,
		    &reject_desc_buf->inv_buf));
	case SGS_REJ_CLASS:
		return (conv_ehdr_class((uchar_t)info, 0,
		    &reject_desc_buf->inv_buf));
	case SGS_REJ_DATA:
		return (conv_ehdr_data((uchar_t)info, 0,
		    &reject_desc_buf->inv_buf));
	case SGS_REJ_TYPE:
		return (conv_ehdr_type(ELFOSABI_SOLARIS, (Half)info, 0,
		    &reject_desc_buf->inv_buf));
	case SGS_REJ_BADFLAG:
	case SGS_REJ_MISFLAG:
	case SGS_REJ_HAL:
	case SGS_REJ_US3:
		return (conv_ehdr_flags(mach, (Word)info, 0,
		    &reject_desc_buf->flags_buf));
	case SGS_REJ_UNKFILE:
	case SGS_REJ_ARCHIVE:
		return (NULL);
	case SGS_REJ_STR:
	case SGS_REJ_HWCAP_1:
	case SGS_REJ_SFCAP_1:
	case SGS_REJ_HWCAP_2:
	case SGS_REJ_MACHCAP:
	case SGS_REJ_PLATCAP:
		if (rej->rej_str)
			return ((const char *)rej->rej_str);
		else
			return (MSG_ORIG(MSG_STR_EMPTY));
	default:
		return (conv_invalid_val(&reject_desc_buf->inv_buf, info,
		    CONV_FMT_DECIMAL));
	}
}
