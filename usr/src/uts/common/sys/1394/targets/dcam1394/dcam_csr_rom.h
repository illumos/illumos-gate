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

#ifndef _SYS_1394_TARGETS_DCAM1394_CSRROM_H
#define	_SYS_1394_TARGETS_DCAM1394_CSRROM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* make routines for accessing/extracting info from CSR/Config ROM (sec 3.4) */

#define	FW_DCAM_CSR_BASE_FW_BUS_ADDR		0xFFFFF000

#define	FW_DCAM_STATE_CLEAR_CORE_CSR_OFFS		0x0
#define	FW_DCAM_STATE_SET_CORE_CSR_OFFS			0x4
#define	FW_DCAM_NODE_IDS_CORE_CSR_OFFS			0x8
#define	FW_DCAM_RESET_START_CORE_CSR_OFFS		0xC
#define	FW_DCAM_SPLIT_TIMEOUT_HI_CORE_CSR_OFFS		0x18
#define	FW_DCAM_SPLIT_TIMEOUT_LO_CORE_CSR_OFFS		0x1C

#define	FW_DCAM_CYCLE_TIME_SERIAL_BUS_DEP_CSR_OFFS	0x200
#define	FW_DCAM_BUSY_TIMEOUT_SERIAL_BUS_DEP_CSR_OFFS	0x210

#define	FW_DCAM_CONFIG_ROM_BASE_FW_BUS_ADDR		0xFFFFF000

/*
 * CRC_LENGTH [8..15]		in 0x400
 * ROM_CRC_VALUE [16..31]	in 0x400
 * MAX_REC [16..?]		in 0x408
 * NODE_VENDOR_ID [0..23]	in 0x40C
 * CHIP_ID_HI [24..31]		in 0x40C
 * CHIP_ID_LO [0..31]		in 0x410
 */
#define	FW_DCAM_BUS_INFO_BLOCK_BASE_REG_OFFS		0x400


/*
 * CRC [16..31]				in 0x414
 * MODULE_VENDOR_ID [8..31]		in 0x418
 * INDIRECT_OFFSET [8..31]		in 0x420
 * UNIT_DIRECTORY_OFFSET [8..31]	in 0x424
 */
#define	FW_DCAM_ROOT_DIRECTORY_BASE_REG_OFFS		0x414

/*
 * CRC [16..31] in 0x0
 * NODE_VENDOR_ID [0..23] in 0x4
 * CHIP_ID_HI [24..31] in 0x4
 * CHIP_ID_LO [0..31] in 0x8
 */
#define	FW_DCAM_NODE_ID_LEAF_BASE_OFFS			0x0


/*
 * CRC [16..31]			in 0x0
 * UNIT_SPEC_ID [8..31]		in 0x4, FW_DCAM_SPEC_104 = 0xA02D
 * UNIT_SW_VERSION [8..31]	in 0x8
 * UNIT_DEPENDENT_DIRECTORY_OFFS_VAL [8..31] in 0xC
 */
#define	FW_DCAM_UNIT_DIRECTORY_BASE_OFFS		0x0


/*
 * UNIT_DEP_INFO_LENGTH [0..15] in 0x0
 * CRC [16..31] in 0x0
 *
 * COMMAND_REGS_BASE [8..31] in 0x4, the quadlet offs from base addr of
 * initial register space of the base addr of the command registers
 * defined in section 1 of this standard
 *
 * VENDOR_NAME_LEAF [8..31] in 0x8, specifies the number of quadlets
 * from the addr of the vendor_name_leaf entry to the address of the
 * vendor_name leaf containing an ascii representation of the vendor
 * name of this node
 *
 * MODEL_NAME_LEAF [8..31] in 0xC, specifies the number of quadlet from
 * the addr of the model_name_leaf entry to the address of the
 * model_name leaf containing an ascii representation of the model name
 * of this node
 */
#define	FW_DCAM_UNIT_DEPENDENT_DIRECTORY_BASE_OFFS	0x0


/*
 * LEAF_LENGTH [0..15]	in 0x0
 * CRC [16..31]		in 0x0
 * CHAR_0 [0..7]	in 0xC
 */
#define	FW_DCAM_NAME_LEAF_BASE_OFFS			0x0

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_CSRROM_H */
