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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<strings.h>
#include	<dwarf.h>
#include	"_conv.h"
#include	<dwarf_msg.h>

/*
 * This code is primarily of interest to elfdump. Separating it from dwarf_ehe
 * allows other tools to use dwarf_ehe without also pulling this in.
 */

/*
 * Translate DW_CFA_ codes, used to identify Call Frame Instructions.
 */
const char *
conv_dwarf_cfa(uchar_t op, Conv_fmt_flags_t fmt_flags, Conv_inv_buf_t *inv_buf)
{
	static const Msg	cfa[] = {
		MSG_DW_CFA_NOP,			MSG_DW_CFA_SET_LOC,
		MSG_DW_CFA_ADVANCE_LOC_1,	MSG_DW_CFA_ADVANCE_LOC_2,
		MSG_DW_CFA_ADVANCE_LOC_4,	MSG_DW_CFA_OFFSET_EXTENDED,
		MSG_DW_CFA_RESTORE_EXTENDED,	MSG_DW_CFA_UNDEFINED,
		MSG_DW_CFA_SAME_VALUE,		MSG_DW_CFA_REGISTER,
		MSG_DW_CFA_REMEMBER_STATE,	MSG_DW_CFA_RESTORE_STATE,
		MSG_DW_CFA_DEF_CFA,		MSG_DW_CFA_DEF_CFA_REGISTER,
		MSG_DW_CFA_DEF_CFA_OFFSET,	MSG_DW_CFA_DEF_CFA_EXPRESSION,
		MSG_DW_CFA_EXPRESSION,		MSG_DW_CFA_OFFSET_EXTENDED_SF,
		MSG_DW_CFA_DEF_CFA_SF,		MSG_DW_CFA_DEF_CFA_OFFSET_SF,
		MSG_DW_CFA_VAL_OFFSET,		MSG_DW_CFA_VAL_OFFSET_SF,
		MSG_DW_CFA_VAL_EXPRESSION
	};
	static const Msg	cfa_mips[] = {	MSG_DW_CFA_MIPS_ADV_LOC8 };
	static const Msg	cfa_gnu[] = {
		MSG_DW_CFA_GNU_WINDOW_SAVE,	MSG_DW_CFA_GNU_ARGS_SIZE,
		MSG_DW_CFA_GNU_NEGATIVE_OFF_X
	};
	static const conv_ds_msg_t ds_msg_cfa = {
	    CONV_DS_MSG_INIT(0, cfa) };
	static const conv_ds_msg_t ds_msg_cfa_mips = {
	    CONV_DS_MSG_INIT(0x1d, cfa_mips) };
	static const conv_ds_msg_t ds_msg_cfa_gnu = {
	    CONV_DS_MSG_INIT(0x2d, cfa_gnu) };
	static const conv_ds_t	*ds_cfa[] = { CONV_DS_ADDR(ds_msg_cfa),
	    CONV_DS_ADDR(ds_msg_cfa_mips), CONV_DS_ADDR(ds_msg_cfa_gnu), NULL };


	/*
	 * DWARF CFA opcodes are bytes. The top 2 bits are a primary
	 * opcode, and if zero, the lower 6 bits specify a sub-opcode
	 */
	switch (op >> 6) {
	case 0x1:
		return (MSG_ORIG(MSG_DW_CFA_ADVANCE_LOC));
	case 0x2:
		return (MSG_ORIG(MSG_DW_CFA_OFFSET));
	case 0x3:
		return (MSG_ORIG(MSG_DW_CFA_RESTORE));
	}

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, op, ds_cfa,
	    fmt_flags, inv_buf));
}

/*
 * Translate DWARF register numbers to hardware specific names
 *
 * If good_name is non-NULL, conv_dwarf_regname() will set the variable to
 * True(1) if the returned string is considered to be a good name to
 * display, and False(0) otherwise. To be considered "good":
 *
 *    -	The name must be a well known mnemonic for a register
 *	from the machine type in question.
 *
 *    -	The name must be different than the DWARF name for
 *	the same register.
 *
 * The returned string is usable, regardless of the value returned in
 * *good_name.
 */
const char *
conv_dwarf_regname(Half mach, Word regno, Conv_fmt_flags_t fmt_flags,
    int *good_name, Conv_inv_buf_t *inv_buf)
{
	static const Msg	reg_amd64[67] = {
		MSG_REG_RAX,		MSG_REG_RDX,
		MSG_REG_RCX,		MSG_REG_RBX,
		MSG_REG_RSI,		MSG_REG_RDI,
		MSG_REG_RBP,		MSG_REG_RSP,
		MSG_REG_R8,		MSG_REG_R9,
		MSG_REG_R10,		MSG_REG_R11,
		MSG_REG_R12,		MSG_REG_R13,
		MSG_REG_R14,		MSG_REG_R15,
		MSG_REG_RA,		MSG_REG_PERXMM0,
		MSG_REG_PERXMM1,	MSG_REG_PERXMM2,
		MSG_REG_PERXMM3,	MSG_REG_PERXMM4,
		MSG_REG_PERXMM5,	MSG_REG_PERXMM6,
		MSG_REG_PERXMM7,	MSG_REG_PERXMM8,
		MSG_REG_PERXMM9,	MSG_REG_PERXMM10,
		MSG_REG_PERXMM11,	MSG_REG_PERXMM12,
		MSG_REG_PERXMM13,	MSG_REG_PERXMM14,
		MSG_REG_PERXMM15,	MSG_REG_PERST0,
		MSG_REG_PERST1,		MSG_REG_PERST2,
		MSG_REG_PERST3,		MSG_REG_PERST4,
		MSG_REG_PERST5,		MSG_REG_PERST6,
		MSG_REG_PERST7,		MSG_REG_PERMM0,
		MSG_REG_PERMM1,		MSG_REG_PERMM2,
		MSG_REG_PERMM3,		MSG_REG_PERMM4,
		MSG_REG_PERMM5,		MSG_REG_PERMM6,
		MSG_REG_PERMM7,		MSG_REG_PERRFLAGS,
		MSG_REG_PERES,		MSG_REG_PERCS,
		MSG_REG_PERSS,		MSG_REG_PERDS,
		MSG_REG_PERFS,		MSG_REG_PERGS,
		MSG_REG_RESERVED,	MSG_REG_RESERVED,
		MSG_REG_PERFSDOTBASE,	MSG_REG_PERGSDOTBASE,
		MSG_REG_RESERVED,	MSG_REG_RESERVED,
		MSG_REG_PERTR,		MSG_REG_PERLDTR,
		MSG_REG_PERMXCSR,	MSG_REG_PERFCW,
		MSG_REG_PERFSW
	};
	static const conv_ds_msg_t ds_msg_reg_amd64 = {
	    CONV_DS_MSG_INIT(0, reg_amd64) };
	static const conv_ds_t	*ds_reg_amd64[] = {
	    CONV_DS_ADDR(ds_msg_reg_amd64), NULL };

	static const Msg	reg_i386[8] = {
		MSG_REG_EAX,		MSG_REG_ECX,
		MSG_REG_EDX,		MSG_REG_EBX,
		MSG_REG_UESP,		MSG_REG_EBP,
		MSG_REG_ESI,		MSG_REG_EDI
	};
	static const conv_ds_msg_t ds_msg_reg_i386 = {
	    CONV_DS_MSG_INIT(0, reg_i386) };
	static const conv_ds_t	*ds_reg_i386[] = {
	    CONV_DS_ADDR(ds_msg_reg_i386), NULL };

	static const Msg	reg_sparc[64] = {
		MSG_REG_G0,		MSG_REG_G1,
		MSG_REG_G2,		MSG_REG_G3,
		MSG_REG_G4,		MSG_REG_G5,
		MSG_REG_G6,		MSG_REG_G7,
		MSG_REG_O0,		MSG_REG_O1,
		MSG_REG_O2,		MSG_REG_O3,
		MSG_REG_O4,		MSG_REG_O5,
		MSG_REG_O6,		MSG_REG_O7,
		MSG_REG_L0,		MSG_REG_L1,
		MSG_REG_L2,		MSG_REG_L3,
		MSG_REG_L4,		MSG_REG_L5,
		MSG_REG_L6,		MSG_REG_L7,
		MSG_REG_I0,		MSG_REG_I1,
		MSG_REG_I2,		MSG_REG_I3,
		MSG_REG_I4,		MSG_REG_I5,
		MSG_REG_I6,		MSG_REG_I7,
		MSG_REG_F0,		MSG_REG_F1,
		MSG_REG_F2,		MSG_REG_F3,
		MSG_REG_F4,		MSG_REG_F5,
		MSG_REG_F6,		MSG_REG_F7,
		MSG_REG_F8,		MSG_REG_F9,
		MSG_REG_F10,		MSG_REG_F11,
		MSG_REG_F12,		MSG_REG_F13,
		MSG_REG_F14,		MSG_REG_F15,
		MSG_REG_F16,		MSG_REG_F17,
		MSG_REG_F18,		MSG_REG_F19,
		MSG_REG_F20,		MSG_REG_F21,
		MSG_REG_F22,		MSG_REG_F23,
		MSG_REG_F24,		MSG_REG_F25,
		MSG_REG_F26,		MSG_REG_F27,
		MSG_REG_F28,		MSG_REG_F29,
		MSG_REG_F30,		MSG_REG_F31
	};
	static const conv_ds_msg_t ds_msg_reg_sparc = {
	    CONV_DS_MSG_INIT(0, reg_sparc) };
	static const conv_ds_t	*ds_reg_sparc[] = {
	    CONV_DS_ADDR(ds_msg_reg_sparc), NULL };

	switch (mach) {
	case EM_AMD64:
		/*
		 * amd64 has several in-bounds names we'd rather not
		 * use. R8-R15 have the same name as their DWARF counterparts.
		 * 56-57, and 60-61 are reserved, and don't have a good name.
		 */
		if (good_name)
			*good_name = ((regno < 8) || (regno > 15)) &&
			    (regno != 56) && (regno != 57) &&
			    (regno != 60) && (regno != 61) &&
			    (regno < ARRAY_NELTS(reg_amd64));
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, regno,
		    ds_reg_amd64, fmt_flags, inv_buf));

	case EM_386:
	case EM_486:
		if (good_name)
			*good_name = (regno < ARRAY_NELTS(reg_i386));
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, regno,
		    ds_reg_i386, fmt_flags, inv_buf));

	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		if (good_name)
			*good_name = (regno < ARRAY_NELTS(reg_sparc));
		return (conv_map_ds(ELFOSABI_NONE, EM_NONE, regno,
		    ds_reg_sparc, fmt_flags, inv_buf));
	}

	if (good_name)
		*good_name = 0;
	return (conv_invalid_val(inv_buf, regno, 0));
}
