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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
*/

/* Init operation types and structures */
enum {
	OP_RD = 0x1,	/* read a single register */
	OP_WR,		/* write a single register */
	OP_SW,		/* copy a string to the device */
	OP_ZR,		/* clear memory */
	OP_ZP,		/* unzip then copy with DMAE */
	OP_WR_64,	/* write 64 bit pattern */
	OP_WB,		/* copy a string using DMAE */
#ifndef FW_ZIP_SUPPORT /* ! BNX2X_UPSTREAM */
	OP_FW,		/* copy an array from fw data (only used with unzipped FW) */
#endif
	OP_WB_ZR,	/* Clear a string using DMAE or indirect-wr */
	OP_IF_MODE_OR,  /* Skip the following ops if all init modes don't match */
	OP_IF_MODE_AND, /* Skip the following ops if any init modes don't match */
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	OP_IF_PHASE,
	OP_RT,
	OP_DELAY,
	OP_VERIFY,
#endif
	OP_MAX
};

enum {
	STAGE_START,
	STAGE_END,
};

/* Returns the index of start or end of a specific block stage in ops array*/
#define BLOCK_OPS_IDX(block, stage, end) \
	(2*(((block)*NUM_OF_INIT_PHASES) + (stage)) + (end))


/* structs for the various opcodes */
struct raw_op {
	u32 op:8;
	u32 offset:24;
	u32 raw_data;
};

struct op_read {
	u32 op:8;
	u32 offset:24;
	u32 val;
};

struct op_write {
	u32 op:8;
	u32 offset:24;
	u32 val;
};

struct op_arr_write {
	u32 op:8;
	u32 offset:24;
#ifdef __BIG_ENDIAN
	u16 data_len;
	u16 data_off;
#else /* __LITTLE_ENDIAN */
	u16 data_off;
	u16 data_len;
#endif
};

struct op_zero {
	u32 op:8;
	u32 offset:24;
	u32 len;
};

struct op_if_mode {
	u32 op:8;
	u32 cmd_offset:24;
	u32 mode_bit_map;
};

#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
struct op_if_phase {
	u32 op:8;
	u32 cmd_offset:24;
	u32 phase_bit_map;
};

struct op_delay {
	u32 op:8;
	u32 reserved:24;
	u32 delay;
};
#endif

union init_op {
	struct op_read		read;
	struct op_write		write;
	struct op_arr_write	arr_wr;
	struct op_zero		zero;
	struct raw_op		raw;
	struct op_if_mode	if_mode;
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	struct op_if_phase	if_phase;
	struct op_delay		delay;
#endif
};


/* Init Phases */
enum {
	PHASE_COMMON,
	PHASE_PORT0,
	PHASE_PORT1,
	PHASE_PF0,
	PHASE_PF1,
	PHASE_PF2,
	PHASE_PF3,
	PHASE_PF4,
	PHASE_PF5,
	PHASE_PF6,
	PHASE_PF7,
	NUM_OF_INIT_PHASES
};

/* Init Modes */
enum {
	MODE_ASIC                      = 0x00000001,
	MODE_FPGA                      = 0x00000002,
	MODE_EMUL                      = 0x00000004,
	MODE_E2                        = 0x00000008,
	MODE_E3                        = 0x00000010,
	MODE_PORT2                     = 0x00000020,
	MODE_PORT4                     = 0x00000040,
	MODE_SF                        = 0x00000080,
	MODE_MF                        = 0x00000100,
	MODE_MF_SD                     = 0x00000200,
	MODE_MF_SI                     = 0x00000400,
	MODE_MF_AFEX                   = 0x00000800,
	MODE_E3_A0                     = 0x00001000,
	MODE_E3_B0                     = 0x00002000,
	MODE_COS3                      = 0x00004000,
	MODE_COS6                      = 0x00008000,
	MODE_LITTLE_ENDIAN             = 0x00010000,
	MODE_BIG_ENDIAN                = 0x00020000,
};

/* Init Blocks */
enum {
	BLOCK_ATC,
	BLOCK_BRB1,
	BLOCK_CCM,
	BLOCK_CDU,
	BLOCK_CFC,
	BLOCK_CSDM,
	BLOCK_CSEM,
	BLOCK_DBG,
	BLOCK_DMAE,
	BLOCK_DORQ,
	BLOCK_HC,
	BLOCK_IGU,
	BLOCK_MISC,
	BLOCK_NIG,
	BLOCK_PBF,
	BLOCK_PGLUE_B,
	BLOCK_PRS,
	BLOCK_PXP2,
	BLOCK_PXP,
	BLOCK_QM,
	BLOCK_SRC,
	BLOCK_TCM,
	BLOCK_TM,
	BLOCK_TSDM,
	BLOCK_TSEM,
	BLOCK_UCM,
	BLOCK_UPB,
	BLOCK_USDM,
	BLOCK_USEM,
	BLOCK_XCM,
	BLOCK_XPB,
	BLOCK_XSDM,
	BLOCK_XSEM,
	BLOCK_MISC_AEU,
	NUM_OF_INIT_BLOCKS
};

