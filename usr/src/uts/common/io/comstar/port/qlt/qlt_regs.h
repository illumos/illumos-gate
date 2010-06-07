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
 * Copyright 2009 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_QLT_REGS_H
#define	_QLT_REGS_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Register offsets
 */
#define	REG_FLASH_ADDR		0x00
#define	REG_FLASH_DATA		0x04
#define	REG_CTRL_STATUS		0x08
#define	REG_INTR_CTRL		0x0C
#define	REG_INTR_STATUS		0x10
#define	REG_REQ_IN_PTR		0x1C
#define	REG_REQ_OUT_PTR		0x20
#define	REG_RESP_IN_PTR		0x24
#define	REG_RESP_OUT_PTR	0x28
#define	REG_PREQ_IN_PTR		0x2C
#define	REG_PREQ_OUT_PTR	0x30
#define	REG_ATIO_IN_PTR		0x3C
#define	REG_ATIO_OUT_PTR	0x40
#define	REG_RISC_STATUS		0x44
#define	REG_HCCR		0x48
#define	REG_GPIO_DATA		0x4C
#define	REG_GPIO_ENABLE		0x50
#define	REG_IOBUS_BASE_ADDR	0x54
#define	REG_HOST_SEMA		0x58
#define	REG_MBOX0		0x80

#define	REG_MBOX(n)		(REG_MBOX0 + (n << 1))

#define	MAX_MBOXES		32

/*
 * Ctrl Status register definitions
 */
#define	FLASH_ERROR		BIT_18
#define	DMA_ACTIVE_STATUS	BIT_17
#define	DMA_SHUTDOWN_CTRL	BIT_16
#define	FUNCTION_NUMBER		BIT_15
/*
 * #define	81XX_FUNCTION_NUMBER	BIT_15 | BIT_14 | BIT_13 | BIT_12
 */
#define	PCI_X_BUS_MODE		(BIT_8 | BIT_9 | BIT_10 | BIT_11)
#define	PCI_X_XFER_CTRL		(BIT_4 | BIT_5)
#define	PCI_64_BIT_SLOT		BIT_2
#define	FLASH_WRITE_ENABLE	BIT_1
#define	CHIP_SOFT_RESET		BIT_0

/*
 * INTR_CTRL register
 */
#define	ENABLE_RISC_INTR	BIT_3

/*
 * INTR_STATUS register
 */
#define	RISC_PCI_INTR_REQUEST	BIT_3

/*
 * RISC_STATUS register
 */
#define	FW_INTR_INFO_MASK		(BIT_15 | BIT_14 | BIT_13 | BIT_12 | \
					BIT_11 | BIT_10 | BIT_9 | BIT_8 | \
					BIT_7 | BIT_6 | BIT_5 | BIT_4 | \
					BIT_3 | BIT_2 | BIT_1)
#define	FW_INTR_INFO_SHIFT		18

#define	FW_INTR_INFO(status)		(status & (FW_INTR_INFO_MASK << \
					    FW_INTR_INFO_SHIFT))
#define	RISC_HOST_INTR_REQUEST		BIT_15
#define	RISC_PAUSED			BIT_8

#define	FW_INTR_STATUS_MASK		(BIT_7 | BIT_6 | BIT_5 | BIT_4 | \
					BIT_3 | BIT_2 | BIT_1 | BIT_0)

#define	ROM_MBX_CMD_SUCCESSFUL		0x01
#define	ROM_MBX_CMD_NOT_SUCCESSFUL	0x02
#define	MBX_CMD_SUCCESSFUL		0x10
#define	MBX_CMD_NOT_SUCCESSFUL		0x11
#define	ASYNC_EVENT			0x12
#define	RESP_Q_UPDATE			0x13
#define	ATIO_Q_UPDATE			0x1c
#define	RESP_ATIO_Q_UPDATE		0x1d

/*
 * Mailbox command completion status.
 */
#define	QLT_MBX_CMD_SUCCESS		0x4000

/*
 * HCCR commands
 */
#define	NOP				0x00
#define	SET_RISC_RESET			0x01
#define	CLEAR_RISC_RESET		0x02
#define	SET_RISC_PAUSE			0x03
#define	CLEAR_RISC_PAUSE		0x04
#define	SET_HOST_TO_RISC_INTR		0x05
#define	CLEAR_HOST_TO_RISC_INTR		0x06
#define	CLEAR_RISC_TO_PCI_INTR		0x0A

#define	HCCR_CMD_SHIFT			28
#define	HCCR_CMD(cmd)			((uint32_t)cmd << HCCR_CMD_SHIFT)

#define	MBC_STOP_FIRMWARE		0x14

/*
 * Flash/NVRAM definitions
 */
#define	FLASH_DATA_FLAG			BIT_31
#define	FLASH_CONF_ADDR			0x7FFD0000
#define	FLASH_DATA_ADDR			0x7FF00000
#define	FLASH_DATA_ADDR_81XX		0x7F8D0000
#define	NVRAM_CONF_ADDR			0x7FFF0000
#define	NVRAM_DATA_ADDR			0x7FFE0000

#define	NVRAM_FUNC0_ADDR		(NVRAM_DATA_ADDR + 0x80)
#define	NVRAM_FUNC1_ADDR		(NVRAM_DATA_ADDR + 0x180)

#define	QLT25_NVRAM_FUNC0_ADDR		(FLASH_DATA_ADDR + 0x48080)
#define	QLT25_NVRAM_FUNC1_ADDR		(FLASH_DATA_ADDR + 0x48180)

#define	QLT81_NVRAM_FUNC0_ADDR		(FLASH_DATA_ADDR_81XX + 0x80)
#define	QLT81_NVRAM_FUNC1_ADDR		(FLASH_DATA_ADDR_81XX + 0x180)

typedef struct qlt_nvram {
	/* NVRAM header. */
	uint8_t id[4];
	uint8_t nvram_version[2];
	uint8_t reserved_0[2];

	/* Firmware Initialization Control Block. */
	uint8_t version[2];
	uint8_t reserved_1[2];
	uint8_t max_frame_length[2];
	uint8_t execution_throttle[2];
	uint8_t exchange_count[2];
	uint8_t hard_address[2];
	uint8_t port_name[8];
	uint8_t node_name[8];
	uint8_t login_retry_count[2];
	uint8_t link_down_on_nos[2];
	uint8_t interrupt_delay_timer[2];
	uint8_t login_timeout[2];

	/*
	 * BIT 0  = Hard Assigned Loop ID
	 * BIT 1  = Enable Fairness
	 * BIT 2  = Enable Full-Duplex
	 * BIT 3  = Reserved
	 * BIT 4  = Target Mode Enable
	 * BIT 5  = Initiator Mode Disable
	 * BIT 6  = Reserved
	 * BIT 7  = Reserved
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Disable Initial LIP
	 * BIT 10 = Descending Loop ID Search
	 * BIT 11 = Previous Assigned Loop ID
	 * BIT 12 = Reserved
	 * BIT 13 = Full Login after LIP
	 * BIT 14 = Node Name Option
	 * BIT 15-31 = Reserved
	 */
	uint8_t firmware_options_1[4];

	/*
	 * BIT 0  = Operation Mode bit 0
	 * BIT 1  = Operation Mode bit 1
	 * BIT 2  = Operation Mode bit 2
	 * BIT 3  = Operation Mode bit 3
	 * BIT 4  = Connection Options bit 0
	 * BIT 5  = Connection Options bit 1
	 * BIT 6  = Connection Options bit 2
	 * BIT 7  = Enable Non part on LIHA failure
	 *
	 * BIT 8  = Enable Class 2
	 * BIT 9  = Enable ACK0
	 * BIT 10 = Reserved
	 * BIT 11 = Enable FC-SP Security
	 * BIT 12 = FC Tape Enable
	 * BIT 13-31 = Reserved
	 */
	uint8_t firmware_options_2[4];

	/*
	 * BIT 0  = Reserved
	 * BIT 1  = Soft ID only
	 * BIT 2  = Reserved
	 * BIT 3  = Reserved
	 * BIT 4  = FCP RSP Payload bit 0
	 * BIT 5  = FCP RSP Payload bit 1
	 * BIT 6  = Enable Rec Out-of-Order data frame handling
	 * BIT 7  = Disable Automatic PLOGI on Local Loop
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Enable Out-of-Order FCP_XFER_RDY relative
	 *	    offset handling
	 * BIT 10 = Reserved
	 * BIT 11 = Reserved
	 * BIT 12 = Reserved
	 * BIT 13 = Data Rate bit 0
	 * BIT 14 = Data Rate bit 1
	 * BIT 15 = Data Rate bit 2
	 * BIT 16 = 75-ohm Termination Select
	 * BIT 17-31 = Reserved
	 */
	uint8_t firmware_options_3[4];

	/*
	 * Serial Link Control (offset 56)
	 * BIT 0  = control enable
	 * BIT 1-15 = Reserved
	 */
	uint8_t swing_opt[2];

	/*
	 * Serial Link Control 1G (offset 58)
	 * BIT 0-7   = Reserved
	 *
	 * BIT 8-10  = output swing
	 * BIT 11-13 = output emphasis
	 * BIT 14-15 = Reserved
	 */
	uint8_t swing_1g[2];

	/*
	 * Serial Link Control 2G (offset 60)
	 * BIT 0-7   = Reserved
	 *
	 * BIT 8-10  = output swing
	 * BIT 11-13 = output emphasis
	 * BIT 14-15 = Reserved
	 */
	uint8_t swing_2g[2];

	/*
	 * Serial Link Control 4G (offset 62)
	 * BIT 0-7   = Reserved
	 *
	 * BIT 8-10  = output swing
	 * BIT 11-13 = output emphasis
	 * BIT 14-15 = Reserved
	 */
	uint8_t swing_4g[2];

	/* Offset 64. */
	uint8_t reserved_2[32];

	/* Offset 96. */
	uint8_t reserved_3[32];

	/* PCIe table entries. */
	uint8_t reserved_4[32];

	/* Offset 160. */
	uint8_t reserved_5[32];

	/* Offset 192. */
	uint8_t reserved_6[32];

	/* Offset 224. */
	uint8_t reserved_7[32];

	/*
	 * BIT 0  = Enable spinup delay
	 * BIT 1  = Disable BIOS
	 * BIT 2  = Enable Memory Map BIOS
	 * BIT 3  = Enable Selectable Boot
	 * BIT 4  = Disable RISC code load
	 * BIT 5  = Disable serdes
	 * BIT 6  = Enable opt boot mode
	 * BIT 7  = Enable int mode BIOS
	 *
	 * BIT 8  =
	 * BIT 9  =
	 * BIT 10 = Enable lip full login
	 * BIT 11 = Enable target reset
	 * BIT 12 =
	 * BIT 13 = Default Node Name Option
	 * BIT 14 = Default valid
	 * BIT 15 = Enable alternate WWN
	 *
	 * BIT 16-31 =
	 */
	uint8_t host_p[4];

	uint8_t alternate_port_name[8];
	uint8_t alternate_node_name[8];

	uint8_t boot_port_name[8];
	uint8_t boot_lun_number[2];
	uint8_t reserved_8[2];

	uint8_t alt1_boot_port_name[8];
	uint8_t alt1_boot_lun_number[2];
	uint8_t reserved_9[2];

	uint8_t alt2_boot_port_name[8];
	uint8_t alt2_boot_lun_number[2];
	uint8_t reserved_10[2];

	uint8_t alt3_boot_port_name[8];
	uint8_t alt3_boot_lun_number[2];
	uint8_t reserved_11[2];

	/*
	 * BIT 0 = Selective Login
	 * BIT 1 = Alt-Boot Enable
	 * BIT 2 = Reserved
	 * BIT 3 = Enable Boot Order List
	 * BIT 4 = Reserved
	 * BIT 5 = Enable Selective LUN
	 * BIT 6 = Reserved
	 * BIT 7-31 =
	 */
	uint8_t efi_parameters[4];

	uint8_t reset_delay;
	uint8_t reserved_12;
	uint8_t reserved_13[2];

	uint8_t boot_id_number[2];
	uint8_t reserved_14[2];

	uint8_t max_luns_per_target[2];
	uint8_t reserved_15[2];

	uint8_t port_down_retry_count[2];
	uint8_t link_down_timeout[2];

	/*
	 * FCode parameters word (offset 344)
	 *
	 * BIT 0 = Enable BIOS pathname
	 * BIT 1 = fcode qlc
	 * BIT 2 = fcode host
	 * BIT 3-7 =
	 */
	uint8_t	fcode_p0;
	uint8_t reserved_16[7];

	/* Offset 352. */
	uint8_t prev_drv_ver_major;
	uint8_t prev_drv_ver_submajob;
	uint8_t prev_drv_ver_minor;
	uint8_t prev_drv_ver_subminor;

	uint8_t prev_bios_ver_major[2];
	uint8_t prev_bios_ver_minor[2];

	uint8_t prev_efi_ver_major[2];
	uint8_t prev_efi_ver_minor[2];

	uint8_t prev_fw_ver_major[2];
	uint8_t prev_fw_ver_minor;
	uint8_t prev_fw_ver_subminor;

	uint8_t reserved_17[16];

	/* Offset 384. */
	uint8_t	def_port_name[8];
	uint8_t def_node_name[8];

	uint8_t reserved_18[16];

	/* Offset 416. */
	uint8_t reserved_19[32];

	/* Offset 448. */
	uint8_t reserved_20[28];

	/* Offset 476. */
	uint8_t	fw_table_offset[2];
	uint8_t fw_table_sig[2];

	/* Offset 480. */
	uint8_t model_name[8];

	/* Offset 488. */
	uint8_t power_table[16];

	uint8_t subsystem_vendor_id[2];
	uint8_t subsystem_device_id[2];

	uint8_t checksum[4];
} qlt_nvram_t;

/* ISP81xx Extended Initialisation Control Block */
typedef struct qlt_ext_icb_81xx {

	uint8_t version[2];
	uint8_t fcf_vlan_match;
	uint8_t reserved_6[3];
	uint8_t fcf_vlan_id[2];
	uint8_t fcf_fabric_name[8];
	uint8_t reserved_7[14];
	uint8_t spma_proposed_mac_address[6];
	uint8_t reserved_8[28];

} qlt_ext_icb_81xx_t;

typedef struct qlt_nvram_81xx {
	/* NVRAM header. */
	uint8_t id[4];
	uint8_t nvram_version[2];
	uint8_t reserved_0[2];

	/* Firmware Initialization Control Block. */
	uint8_t version[2];
	uint8_t reserved_1[2];
	uint8_t max_frame_length[2];
	uint8_t execution_throttle[2];
	uint8_t exchange_count[2];
	uint8_t reserved_2[2];
	uint8_t port_name[8];
	uint8_t node_name[8];
	uint8_t login_retry_count[2];
	uint8_t reserved_3[2];
	uint8_t interrupt_delay_timer[2];
	uint8_t login_timeout[2];

	/*
	 * BIT 0  = Hard Assigned Loop ID
	 * BIT 1  = Enable Fairness
	 * BIT 2  = Enable Full-Duplex
	 * BIT 3  = Reserved
	 * BIT 4  = Target Mode Enable
	 * BIT 5  = Initiator Mode Disable
	 * BIT 6  = Reserved
	 * BIT 7  = Reserved
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Reserved
	 * BIT 10 = Reserved
	 * BIT 11 = Reserved
	 * BIT 12 = Reserved
	 * BIT 13 = Reserved
	 * BIT 14 = Node Name Option
	 * BIT 15-31 = Reserved
	 */
	uint8_t firmware_options_1[4];

	/*
	 * BIT 0  = Operation Mode bit 0
	 * BIT 1  = Operation Mode bit 1
	 * BIT 2  = Operation Mode bit 2
	 * BIT 3  = Operation Mode bit 3
	 * BIT 4  = Reserved
	 * BIT 5  = Reserved
	 * BIT 6  = Reserved
	 * BIT 7  = Reserved
	 *
	 * BIT 8  = Enable Class 2
	 * BIT 9  = Enable ACK0
	 * BIT 10 = Reserved
	 * BIT 11 = Enable FC-SP Security
	 * BIT 12 = FC Tape Enable
	 * BIT 13 = Reserved
	 * BIT 14 = Target PRLI Control
	 * BIT 15-31 = Reserved
	 */
	uint8_t firmware_options_2[4];

	/*
	 * BIT 0  = Reserved
	 * BIT 1  = Soft ID only
	 * BIT 2  = Reserved
	 * BIT 3  = Reserved
	 * BIT 4  = FCP RSP Payload bit 0
	 * BIT 5  = FCP RSP Payload bit 1
	 * BIT 6  = Enable Rec Out-of-Order data frame handling
	 * BIT 7  = Reserved
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Enable Out-of-Order FCP_XFER_RDY relative
	 *	    offset handling
	 * BIT 10 = Reserved
	 * BIT 11 = Reserved
	 * BIT 12 = Reserved
	 * BIT 13 = Reserved
	 * BIT 14 = Reserved
	 * BIT 15 = Reserved
	 * BIT 16 = Reserved
	 * BIT 17 = Enable Multiple FCFs
	 * BIT 18-20 = MAC Addressing Mode
	 * BIT 21-25 = Ethernet Data Rate
	 * BIT 26 = Enable Ethernet Header Receive ATIO_Q
	 * BIT 27 = Enable Ethernet Header Receive RSP_Q
	 * BIT 28-29 = SPMA Selection
	 * BIT 30-31 = Reserved
	 */
	uint8_t firmware_options_3[4];

	/* Offset 56 (38h). */
	uint8_t reserved_4[8];

	/* Offset 64 (40h). */
	uint8_t enode_mac[6];

	/* Offset 70 (46h). */
	uint8_t reserved_5[26];

	/* Offset 96 (60h). */
	uint8_t oem_specific;
	uint8_t reserved_6[15];

	/* Offset 112 (70h). */
	uint8_t reserved_7[16];

	/* Offset 128 (80h). */
	qlt_ext_icb_81xx_t   ext_blk;

	/* Offset 192. */
	uint8_t reserved_8[32];

	/* Offset 224. */
	uint8_t reserved_9[32];

	uint8_t host_p[4];

	uint8_t alternate_port_name[8];
	uint8_t alternate_name_name[8];

	uint8_t boot_port_name[8];
	uint8_t boot_lun_number[2];
	uint8_t reserved_10[2];

	uint8_t alt1_boot_port_name[8];
	uint8_t alt1_boot_lun_number[2];
	uint8_t reserved_11[2];

	uint8_t alt2_boot_port_name[8];
	uint8_t alt2_boot_lun_number[2];
	uint8_t reserved_12[2];

	uint8_t alt3_boot_port_name[8];
	uint8_t alt3_boot_lun_number[2];
	uint8_t reserved_13[2];

	/*
	 * BIT 0 = Selective Login
	 * BIT 1 = Alt-Boot Enable
	 * BIT 2 = Reserved
	 * BIT 3 = Enable Boot Order List
	 * BIT 4 = Reserved
	 * BIT 5 = Enable Selective LUN
	 * BIT 6 = Reserved
	 * BIT 7-31 =
	 */
	uint8_t efi_parameters[4];

	uint8_t reset_delay;
	uint8_t reserved_14;
	uint8_t reserved_15[2];

	uint8_t boot_id_number[2];
	uint8_t reserved_16[2];

	uint8_t max_luns_per_target[2];
	uint8_t reserved_17[2];

	uint8_t port_down_retry_count[2];
	uint8_t link_down_timeout[2];

	/*
	 * FCode parameters word (offset 344)
	 *
	 * BIT 0 = Enable BIOS pathname
	 * BIT 1 = fcode qlc
	 * BIT 2 = fcode host
	 * BIT 3-7 =
	 */
	uint8_t	fcode_parameter[2];
	uint8_t reserved_18[6];

	/* Offset 352. */
	uint8_t reserved_19[4];
	uint8_t reserved_20[10];
	uint8_t reserved_21[2];
	uint8_t reserved_22[16];

	/* Offset 384. */
	uint8_t	reserved_23[16];
	uint8_t reserved_24[16];

	/* Offset 416. */
	uint8_t reserved_25[64];

	/* Offset 480. */
	uint8_t model_name[16];

	/* Offset 496. */
	uint8_t feature_mask_l[2];
	uint8_t feature_mask_h[2];
	uint8_t reserved_26[4];

	uint8_t subsystem_vendor_id[2];
	uint8_t subsystem_device_id[2];

	uint8_t checksum[4];

} qlt_nvram_81xx_t;

#ifdef	__cplusplus
}
#endif

#endif /* _QLT_REGS_H */
