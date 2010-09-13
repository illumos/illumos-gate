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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_SCSI_GENERIC_SFF_FRAMES_H
#define	_SYS_SCSI_GENERIC_SFF_FRAMES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>

/*
 * The definitions of SMP frame formats defined by SFF-8485.
 * These are NOT compatible with the generic SAS-1 and/or SAS-2 SMP frame
 * formats, but the function numbers and result codes are defined by SAS-2.
 */

#pragma	pack(1)

typedef struct sff_request_frame {
	uint8_t srf_frame_type;
	uint8_t srf_function;
	uint8_t srf_data[1];
} sff_request_frame_t;

typedef struct sff_response_frame {
	uint8_t srf_frame_type;
	uint8_t srf_function;
	uint8_t srf_result;
	uint8_t _reserved1;
	uint8_t srf_data[1];
} sff_response_frame_t;

/*
 * SFF-8485 8.4.1 GPIO register overview
 */
typedef enum sff_gpio_reg_type {
	SFF_GPIO_CFG = 0x00,
	SFF_GPIO_RX = 0x01,
	SFF_GPIO_RX_GP = 0x02,
	SFF_GPIO_TX = 0x03,
	SFF_GPIO_TX_GP = 0x04
} sff_gpio_reg_type_t;

/*
 * SFF-8485 8.4.2.1 GPIO configuration registers overview
 */
typedef enum sff_gpio_cfg_reg_index {
	SFF_GPIO_CFG_0 = 0x00,
	SFF_GPIO_CFG_1 = 0x01
} sff_gpio_cfg_reg_index_t;

/*
 * SFF-8485 8.4.2.2 GPIO_CFG[0] register
 */
typedef struct sff_gpio_cfg_reg_0 {
	uint8_t _reserved1;
	DECL_BITFIELD2(
	    sgcr0_version	:4,
	    _reserved2		:4);
	DECL_BITFIELD3(
	    sgcr0_gp_register_count	:4,
	    sgcr0_cfg_register_count	:3,
	    sgcr0_gpio_enable		:1);
	uint8_t sgcr0_supported_drive_count;
} sff_gpio_cfg_reg_0_t;

/*
 * SFF-8485 8.4.2.3 GPIO_CFG[1] register
 */
typedef struct sff_gpio_cfg_reg_1 {
	uint8_t _reserved1;
	DECL_BITFIELD2(
	    sgcr1_blink_gen_rate_a	:4,
	    sgcr1_blink_gen_rate_b	:4);
	DECL_BITFIELD2(
	    sgcr1_max_activity_on	:4,
	    sgcr1_force_activity_off	:4);
	DECL_BITFIELD2(
	    sgcr1_stretch_activity_on	:4,
	    sgcr1_stretch_activity_off	:4);
} sff_gpio_cfg_reg_1_t;

/*
 * SFF-8485 8.4.3 GPIO receive registers
 */
typedef struct sff_gpio_rx_reg {
	DECL_BITFIELD2(
	    sgrr_drive_3_gpio_input	:3,
	    _reserved1			:5);
	DECL_BITFIELD2(
	    sgrr_drive_2_gpio_input	:3,
	    _reserved1			:5);
	DECL_BITFIELD2(
	    sgrr_drive_1_gpio_input	:3,
	    _reserved1			:5);
	DECL_BITFIELD2(
	    sgrr_drive_0_gpio_input	:3,
	    _reserved1			:5);
} sff_gpio_rx_reg_t;

/*
 * SFF-8485 8.4.4 GPIO transmit registers
 */
typedef enum sff_drive_error {
	SFF_DRIVE_ERR_DISABLE = 0x0,
	SFF_DRIVE_ERR_ENABLE = 0x1,
	SFF_DRIVE_ERR_BLINK_A_1_0 = 0x2,
	SFF_DRIVE_ERR_BLINK_A_0_1 = 0x3,
	SFF_DRIVE_ERR_ENABLE_4 = 0x4,
	SFF_DRIVE_ERR_ENABLE_5 = 0x5,
	SFF_DRIVE_ERR_BLINK_B_1_0 = 0x6,
	SFF_DRIVE_ERR_BLINK_B_0_1 = 0x7
} sff_drive_error_t;

typedef enum sff_drive_locate {
	SFF_DRIVE_LOC_DISABLE = 0x0,
	SFF_DRIVE_LOC_ENABLE = 0x1,
	SFF_DRIVE_BLINK_A_1_0 = 0x2,
	SFF_DRIVE_BLINK_A_0_1 = 0x3
} sff_drive_locate_t;

typedef enum sff_drive_activity {
	SFF_DRIVE_ACT_DISABLE = 0x0,
	SFF_DRIVE_ACT_ENABLE = 0x1,
	SFF_DRIVE_ACT_BLINK_A_1_0 = 0x2,
	SFF_DRIVE_ACT_BLINK_A_0_1 = 0x3,
	SFF_DRIVE_ACT_ENABLE_END = 0x4,
	SFF_DRIVE_ACT_ENABLE_START = 0x5,
	SFF_DRIVE_ACT_BLINK_B_1_0 = 0x6,
	SFF_DRIVE_ACT_BLINK_B_0_1 = 0x7
} sff_drive_activity_t;

typedef struct sff_gpio_tx_reg {
	DECL_BITFIELD3(
	    sgtr_drive_3_error		:3,	/* sff_drive_error_t */
	    sgtr_drive_3_locate		:2,	/* sff_drive_locate_t */
	    sgtr_drive_3_activity	:3);	/* sff_drive_activity_t */
	DECL_BITFIELD3(
	    sgtr_drive_2_error		:3,	/* sff_drive_error_t */
	    sgtr_drive_2_locate		:2,	/* sff_drive_locate_t */
	    sgtr_drive_2_activity	:3);	/* sff_drive_activity_t */
	DECL_BITFIELD3(
	    sgtr_drive_1_error		:3,	/* sff_drive_error_t */
	    sgtr_drive_1_locate		:2,	/* sff_drive_locate_t */
	    sgtr_drive_1_activity	:3);	/* sff_drive_activity_t */
	DECL_BITFIELD3(
	    sgtr_drive_0_error		:3,	/* sff_drive_error_t */
	    sgtr_drive_0_locate		:2,	/* sff_drive_locate_t */
	    sgtr_drive_0_activity	:3);	/* sff_drive_activity_t */
} sff_gpio_tx_reg_t;

/*
 * SFF-8485 8.4.5.1 GPIO general purpose receive registers overview
 */
typedef enum sff_gpio_rx_gp_reg_index {
	SFF_GPIO_REG_RX_GP_CFG = 0x00,
	SFF_GPIO_REG_RX_GP_1 = 0x01	/* ... */
} sff_gpio_rx_gp_reg_index_t;

/*
 * SFF-8485 8.4.5.2 GPIO_RX_GP_CFG register
 */
typedef struct sff_gpio_rx_gp_cfg_reg {
	uint8_t _reserved1[2];
	uint8_t sgrgcr_count;
	uint8_t _reserved2;
} sff_gpio_rx_gp_cfg_reg_t;

/*
 * SFF-8485 8.4.5.3 GPIO_RX_GP[1..n] register
 */
typedef uint8_t sff_gpio_rx_gp_reg_t[4];	/* little-endian */

/*
 * SFF-8485 8.4.6.1 GPIO general purpose transmit registers overview
 */
typedef enum sff_gpio_tx_gp_reg_index {
	SFF_GPIO_REG_TX_GP_CFG = 0x00,
	SFF_GPIO_REG_TX_GP_1 = 0x01	/* ... */
} sff_gpio_tx_gp_reg_index_t;

/*
 * SFF-8485 8.4.6.2 GPIO_TX_GP_CFG register
 */
typedef struct sff_gpio_tx_cfg_reg {
	uint8_t _reserved1[2];
	uint8_t sgtcr_count;
	DECL_BITFIELD5(
	    sgtcr_sload_0	:1,
	    sgtcr_sload_1	:1,
	    sgtcr_sload_2	:1,
	    sgtcr_sload_3	:1,
	    _reserved2		:4);
} sff_gpio_tx_cfg_reg_t;

/*
 * SFF-8485 8.4.6.3 GPIO_TX_GP[1..n] registers
 */
typedef uint8_t sff_gpio_tx_gp_reg_t[4];	/* little-endian */

/*
 * SFF-8485 8.2.2 READ GPIO REGISTER request
 */
typedef struct sff_read_gpio_req {
	uint8_t srgr_register_type;
	uint8_t srgr_register_index;
	uint8_t srgr_register_count;
	uint8_t _reserved1[3];
} sff_read_gpio_req_t;

typedef uint8_t sff_gpio_reg_t[4];

/*
 * SFF-8485 8.2.2 READ GPIO REGISTER response
 */
typedef struct sff_read_gpio_resp {
	sff_gpio_reg_t srgr_regs[1];
} smp_response_frame_t;

/*
 * SFF-8485 8.2.3 WRITE GPIO REGISTER request (no additional response)
 */
typedef struct sff_write_gpio_req {
	uint8_t swgr_register_type;
	uint8_t swgr_register_index;
	uint8_t swgr_register_count;
	uint8_t _reserved1[3];
	sff_gpio_reg_t swgr_regs[1];
} sff_write_gpio_req_t;

#pragma	pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_GENERIC_SFF_FRAMES_H */
