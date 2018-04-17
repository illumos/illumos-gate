/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __ECORE_HSI_TOOLS__
#define __ECORE_HSI_TOOLS__ 

/**********************************/
/* Tools HSI constants and macros */
/**********************************/

/* Width of GRC address in bits (addresses are specified in dwords) */
#define GRC_ADDR_BITS			23
#define MAX_GRC_ADDR			((1 << GRC_ADDR_BITS) - 1)

/* indicates an init that should be applied to any phase ID */
#define ANY_PHASE_ID			0xffff

/* init pattern size in bytes */
#define INIT_PATTERN_SIZE_BITS	4
#define MAX_INIT_PATTERN_SIZE	(1 << INIT_PATTERN_SIZE_BITS)

/* Max size in dwords of a zipped array */
#define MAX_ZIPPED_SIZE			8192

/* Global PXP window */
#define NUM_OF_PXP_WIN			19
#define PXP_WIN_DWORD_SIZE_BITS	10
#define PXP_WIN_DWORD_SIZE		(1 << PXP_WIN_DWORD_SIZE_BITS)
#define PXP_WIN_BYTE_SIZE_BITS	(PXP_WIN_DWORD_SIZE_BITS + 2)
#define PXP_WIN_BYTE_SIZE		(PXP_WIN_DWORD_SIZE * 4)


/*
 * Binary buffer header
 */
struct bin_buffer_hdr
{
	__le32 offset /* buffer offset in bytes from the beginning of the binary file */;
	__le32 length /* buffer length in bytes */;
};


/*
 * binary buffer types
 */
enum bin_buffer_type
{
	BIN_BUF_FW_VER_INFO /* fw_ver_info struct */,
	BIN_BUF_INIT_CMD /* init commands */,
	BIN_BUF_INIT_VAL /* init data */,
	BIN_BUF_INIT_MODE_TREE /* init modes tree */,
	BIN_BUF_IRO /* internal RAM offsets array */,
	MAX_BIN_BUFFER_TYPE
};


/*
 * init array header: raw
 */
struct init_array_raw_hdr
{
	__le32 data;
#define INIT_ARRAY_RAW_HDR_TYPE_MASK    0xF /* Init array type, from init_array_types enum */
#define INIT_ARRAY_RAW_HDR_TYPE_SHIFT   0
#define INIT_ARRAY_RAW_HDR_PARAMS_MASK  0xFFFFFFF /* init array params */
#define INIT_ARRAY_RAW_HDR_PARAMS_SHIFT 4
};


/*
 * init array header: standard
 */
struct init_array_standard_hdr
{
	__le32 data;
#define INIT_ARRAY_STANDARD_HDR_TYPE_MASK  0xF /* Init array type, from init_array_types enum */
#define INIT_ARRAY_STANDARD_HDR_TYPE_SHIFT 0
#define INIT_ARRAY_STANDARD_HDR_SIZE_MASK  0xFFFFFFF /* Init array size (in dwords) */
#define INIT_ARRAY_STANDARD_HDR_SIZE_SHIFT 4
};


/*
 * init array header: zipped
 */
struct init_array_zipped_hdr
{
	__le32 data;
#define INIT_ARRAY_ZIPPED_HDR_TYPE_MASK         0xF /* Init array type, from init_array_types enum */
#define INIT_ARRAY_ZIPPED_HDR_TYPE_SHIFT        0
#define INIT_ARRAY_ZIPPED_HDR_ZIPPED_SIZE_MASK  0xFFFFFFF /* Init array zipped size (in bytes) */
#define INIT_ARRAY_ZIPPED_HDR_ZIPPED_SIZE_SHIFT 4
};


/*
 * init array header: pattern
 */
struct init_array_pattern_hdr
{
	__le32 data;
#define INIT_ARRAY_PATTERN_HDR_TYPE_MASK          0xF /* Init array type, from init_array_types enum */
#define INIT_ARRAY_PATTERN_HDR_TYPE_SHIFT         0
#define INIT_ARRAY_PATTERN_HDR_PATTERN_SIZE_MASK  0xF /* pattern size in dword */
#define INIT_ARRAY_PATTERN_HDR_PATTERN_SIZE_SHIFT 4
#define INIT_ARRAY_PATTERN_HDR_REPETITIONS_MASK   0xFFFFFF /* pattern repetitions */
#define INIT_ARRAY_PATTERN_HDR_REPETITIONS_SHIFT  8
};


/*
 * init array header union
 */
union init_array_hdr
{
	struct init_array_raw_hdr raw /* raw init array header */;
	struct init_array_standard_hdr standard /* standard init array header */;
	struct init_array_zipped_hdr zipped /* zipped init array header */;
	struct init_array_pattern_hdr pattern /* pattern init array header */;
};


/*
 * init array types
 */
enum init_array_types
{
	INIT_ARR_STANDARD /* standard init array */,
	INIT_ARR_ZIPPED /* zipped init array */,
	INIT_ARR_PATTERN /* a repeated pattern */,
	MAX_INIT_ARRAY_TYPES
};


/*
 * init operation: callback
 */
struct init_callback_op
{
	__le32 op_data;
#define INIT_CALLBACK_OP_OP_MASK        0xF /* Init operation, from init_op_types enum */
#define INIT_CALLBACK_OP_OP_SHIFT       0
#define INIT_CALLBACK_OP_RESERVED_MASK  0xFFFFFFF
#define INIT_CALLBACK_OP_RESERVED_SHIFT 4
	__le16 callback_id /* Callback ID */;
	__le16 block_id /* Blocks ID */;
};


/*
 * init operation: delay
 */
struct init_delay_op
{
	__le32 op_data;
#define INIT_DELAY_OP_OP_MASK        0xF /* Init operation, from init_op_types enum */
#define INIT_DELAY_OP_OP_SHIFT       0
#define INIT_DELAY_OP_RESERVED_MASK  0xFFFFFFF
#define INIT_DELAY_OP_RESERVED_SHIFT 4
	__le32 delay /* delay in us */;
};


/*
 * init operation: if_mode
 */
struct init_if_mode_op
{
	__le32 op_data;
#define INIT_IF_MODE_OP_OP_MASK          0xF /* Init operation, from init_op_types enum */
#define INIT_IF_MODE_OP_OP_SHIFT         0
#define INIT_IF_MODE_OP_RESERVED1_MASK   0xFFF
#define INIT_IF_MODE_OP_RESERVED1_SHIFT  4
#define INIT_IF_MODE_OP_CMD_OFFSET_MASK  0xFFFF /* Commands to skip if the modes dont match */
#define INIT_IF_MODE_OP_CMD_OFFSET_SHIFT 16
	__le16 reserved2;
	__le16 modes_buf_offset /* offset (in bytes) in modes expression buffer */;
};


/*
 * init operation: if_phase
 */
struct init_if_phase_op
{
	__le32 op_data;
#define INIT_IF_PHASE_OP_OP_MASK           0xF /* Init operation, from init_op_types enum */
#define INIT_IF_PHASE_OP_OP_SHIFT          0
#define INIT_IF_PHASE_OP_DMAE_ENABLE_MASK  0x1 /* Indicates if DMAE is enabled in this phase */
#define INIT_IF_PHASE_OP_DMAE_ENABLE_SHIFT 4
#define INIT_IF_PHASE_OP_RESERVED1_MASK    0x7FF
#define INIT_IF_PHASE_OP_RESERVED1_SHIFT   5
#define INIT_IF_PHASE_OP_CMD_OFFSET_MASK   0xFFFF /* Commands to skip if the phases dont match */
#define INIT_IF_PHASE_OP_CMD_OFFSET_SHIFT  16
	__le32 phase_data;
#define INIT_IF_PHASE_OP_PHASE_MASK        0xFF /* Init phase */
#define INIT_IF_PHASE_OP_PHASE_SHIFT       0
#define INIT_IF_PHASE_OP_RESERVED2_MASK    0xFF
#define INIT_IF_PHASE_OP_RESERVED2_SHIFT   8
#define INIT_IF_PHASE_OP_PHASE_ID_MASK     0xFFFF /* Init phase ID */
#define INIT_IF_PHASE_OP_PHASE_ID_SHIFT    16
};


/*
 * init mode operators
 */
enum init_mode_ops
{
	INIT_MODE_OP_NOT /* init mode not operator */,
	INIT_MODE_OP_OR /* init mode or operator */,
	INIT_MODE_OP_AND /* init mode and operator */,
	MAX_INIT_MODE_OPS
};


/*
 * init operation: raw
 */
struct init_raw_op
{
	__le32 op_data;
#define INIT_RAW_OP_OP_MASK      0xF /* Init operation, from init_op_types enum */
#define INIT_RAW_OP_OP_SHIFT     0
#define INIT_RAW_OP_PARAM1_MASK  0xFFFFFFF /* init param 1 */
#define INIT_RAW_OP_PARAM1_SHIFT 4
	__le32 param2 /* Init param 2 */;
};


/*
 * init array params
 */
struct init_op_array_params
{
	__le16 size /* array size in dwords */;
	__le16 offset /* array start offset in dwords */;
};


/*
 * Write init operation arguments
 */
union init_write_args
{
	__le32 inline_val /* value to write, used when init source is INIT_SRC_INLINE */;
	__le32 zeros_count /* number of zeros to write, used when init source is INIT_SRC_ZEROS */;
	__le32 array_offset /* array offset to write, used when init source is INIT_SRC_ARRAY */;
	struct init_op_array_params runtime /* runtime array params to write, used when init source is INIT_SRC_RUNTIME */;
};


/*
 * init operation: write
 */
struct init_write_op
{
	__le32 data;
#define INIT_WRITE_OP_OP_MASK        0xF /* init operation, from init_op_types enum */
#define INIT_WRITE_OP_OP_SHIFT       0
#define INIT_WRITE_OP_SOURCE_MASK    0x7 /* init source type, taken from init_source_types enum */
#define INIT_WRITE_OP_SOURCE_SHIFT   4
#define INIT_WRITE_OP_RESERVED_MASK  0x1
#define INIT_WRITE_OP_RESERVED_SHIFT 7
#define INIT_WRITE_OP_WIDE_BUS_MASK  0x1 /* indicates if the register is wide-bus */
#define INIT_WRITE_OP_WIDE_BUS_SHIFT 8
#define INIT_WRITE_OP_ADDRESS_MASK   0x7FFFFF /* internal (absolute) GRC address, in dwords */
#define INIT_WRITE_OP_ADDRESS_SHIFT  9
	union init_write_args args /* Write init operation arguments */;
};


/*
 * init operation: read
 */
struct init_read_op
{
	__le32 op_data;
#define INIT_READ_OP_OP_MASK         0xF /* init operation, from init_op_types enum */
#define INIT_READ_OP_OP_SHIFT        0
#define INIT_READ_OP_POLL_TYPE_MASK  0xF /* polling type, from init_poll_types enum */
#define INIT_READ_OP_POLL_TYPE_SHIFT 4
#define INIT_READ_OP_RESERVED_MASK   0x1
#define INIT_READ_OP_RESERVED_SHIFT  8
#define INIT_READ_OP_ADDRESS_MASK    0x7FFFFF /* internal (absolute) GRC address, in dwords */
#define INIT_READ_OP_ADDRESS_SHIFT   9
	__le32 expected_val /* expected polling value, used only when polling is done */;
};


/*
 * Init operations union
 */
union init_op
{
	struct init_raw_op raw /* raw init operation */;
	struct init_write_op write /* write init operation */;
	struct init_read_op read /* read init operation */;
	struct init_if_mode_op if_mode /* if_mode init operation */;
	struct init_if_phase_op if_phase /* if_phase init operation */;
	struct init_callback_op callback /* callback init operation */;
	struct init_delay_op delay /* delay init operation */;
};


/*
 * Init command operation types
 */
enum init_op_types
{
	INIT_OP_READ /* GRC read init command */,
	INIT_OP_WRITE /* GRC write init command */,
	INIT_OP_IF_MODE /* Skip init commands if the init modes expression doesnt match */,
	INIT_OP_IF_PHASE /* Skip init commands if the init phase doesnt match */,
	INIT_OP_DELAY /* delay init command */,
	INIT_OP_CALLBACK /* callback init command */,
	MAX_INIT_OP_TYPES
};


/*
 * init polling types
 */
enum init_poll_types
{
	INIT_POLL_NONE /* No polling */,
	INIT_POLL_EQ /* init value is included in the init command */,
	INIT_POLL_OR /* init value is all zeros */,
	INIT_POLL_AND /* init value is an array of values */,
	MAX_INIT_POLL_TYPES
};


/*
 * init source types
 */
enum init_source_types
{
	INIT_SRC_INLINE /* init value is included in the init command */,
	INIT_SRC_ZEROS /* init value is all zeros */,
	INIT_SRC_ARRAY /* init value is an array of values */,
	INIT_SRC_RUNTIME /* init value is provided during runtime */,
	MAX_INIT_SOURCE_TYPES
};


struct fw_ver_num
{
	u8 major /* Firmware major version number */;
	u8 minor /* Firmware minor version number */;
	u8 rev /* Firmware revision version number */;
	u8 eng /* Firmware engineering version number (for bootleg verisons) */;
};


struct fw_ver_params
{
	u8 image_id /* Firmware image ID */;
	u8 storm_id /* Storm ID */;
	u8 chip_ver /* Chip version number */;
	u8 reserved;
};


struct fw_ver_info
{
	__le16 tools_ver /* Tools version number */;
	__le16 reserved;
	struct fw_ver_num num;
	struct fw_ver_params params;
	__le32 timestamp /* FW Timestamp in unix time  (sec. since 1970) */;
};


enum init_modes
{
	MODE_BB_A0,
	MODE_BB_B0,
	MODE_K2,
	MODE_ASIC,
	MODE_EMUL_REDUCED,
	MODE_EMUL_FULL,
	MODE_FPGA,
	MODE_CHIPSIM,
	MODE_SF,
	MODE_MF_SD,
	MODE_MF_SI,
	MODE_PORTS_PER_ENG_1,
	MODE_PORTS_PER_ENG_2,
	MODE_PORTS_PER_ENG_4,
	MODE_100G,
	MODE_EAGLE_ENG1_WORKAROUND,
	MAX_INIT_MODES
};


enum init_phases
{
	PHASE_ENGINE,
	PHASE_PORT,
	PHASE_PF,
	PHASE_VF,
	PHASE_QM_PF,
	MAX_INIT_PHASES
};


#endif /* __ECORE_HSI_TOOLS__ */
