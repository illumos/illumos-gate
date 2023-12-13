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
 * Copyright 2009-2015 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, 2015, Oracle and/or its affiliates. All rights reserved.
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
#define	H2RISC_INTR		BIT_6
#define	RISC_RESET		BIT_5
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
 * Firmware state codes from get firmware state mailbox command
 */
#define	FSTATE_CONFIG_WAIT	0
#define	FSTATE_WAIT_AL_PA	1
#define	FSTATE_WAIT_LOGIN	2
#define	FSTATE_READY		3
#define	FSTATE_LOSS_SYNC	4
#define	FSTATE_ERROR		5
#define	FSTATE_NON_PART		7

#define	FSTATE_MPI_NIC_ERROR    0x10


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

/*
 * ISP8100/83xx Multi-Queue MBAR definitions
 */
#define	MQBAR_REQ_IN			0x0
#define	MQBAR_REQ_OUT			0x4
#define	MQBAR_RESP_IN			0x8
#define	MQBAR_RESP_OUT			0xc

#define	MQBAR_ATIO_IN			0x10
#define	MQBAR_ATIO_OUT			0x14

/* 83xx uses 32 bytes per queue pair */
#define	MQBAR_REG_SIZE			0x20
#define	MQBAR_REG_OFFSET		4096

#define	MQ_MAX_QUEUES			8


/*
 * Flash/NVRAM definitions
 */
#define	FLASH_DATA_FLAG			BIT_31

#define	FLASH_CONF_ADDR			0x7FFD0000

#define	FLASH_DATA_ADDR			0x7FF00000

#define	FLASH_2400_DATA_ADDR		0x7FF00000
#define	FLASH_2500_DATA_ADDR		0x7FF00000
#define	FLASH_2700_DATA_ADDR		0x7F800000
#define	FLASH_8100_DATA_ADDR		0x7F800000
#define	FLASH_8200_DATA_ADDR		0
#define	FLASH_8300_DATA_ADDR		0x7F800000

#define	FLASH_DATA_ADDR_81XX		0x7F8D0000
					/* 0x7F80000 + 0xD0000 */
#define	FLASH_DATA_ADDR_83XX		0x7FA70000
					/* 0x7F80000 + 0x270000 */

#define	NVRAM_CONF_ADDR			0x7FFF0000
#define	NVRAM_DATA_ADDR			0x7FFE0000

#define	NVRAM_2400_FUNC0_ADDR		0x80
#define	NVRAM_2400_FUNC1_ADDR		0x180

#define	NVRAM_2500_FUNC0_ADDR		0x48080
#define	NVRAM_2500_FUNC1_ADDR		0x48180

#define	NVRAM_2700_FUNC0_ADDR		0x270080
#define	NVRAM_2700_FUNC1_ADDR		0x270180
#define	NVRAM_2700_FUNC2_ADDR		0x270280
#define	NVRAM_2700_FUNC3_ADDR		0x270380

#define	NVRAM_8100_FUNC0_ADDR		0xD0080
#define	NVRAM_8100_FUNC1_ADDR		0xD0180

#define	NVRAM_8300_FC_FUNC0_ADDR	0x270080
#define	NVRAM_8300_FC_FUNC1_ADDR	0x270180

#define	NVRAM_8300_FCOE_FUNC0_ADDR	0x274080
#define	NVRAM_8300_FCOE_FUNC1_ADDR	0x274180

#define	NVRAM_FUNC0_ADDR		(NVRAM_DATA_ADDR + 0x80)
#define	NVRAM_FUNC1_ADDR		(NVRAM_DATA_ADDR + 0x180)

#define	QLT25_NVRAM_FUNC0_ADDR		(FLASH_DATA_ADDR + 0x48080)
#define	QLT25_NVRAM_FUNC1_ADDR		(FLASH_DATA_ADDR + 0x48180)

#define	QLT27_NVRAM_FUNC0_ADDR		(FLASH_2700_DATA_ADDR + 0x270080)
#define	QLT27_NVRAM_FUNC1_ADDR		(FLASH_2700_DATA_ADDR + 0x270180)
#define	QLT27_NVRAM_FUNC2_ADDR		(FLASH_2700_DATA_ADDR + 0x270280)
#define	QLT27_NVRAM_FUNC3_ADDR		(FLASH_2700_DATA_ADDR + 0x270380)

#define	QLT81_NVRAM_FUNC0_ADDR		(FLASH_DATA_ADDR_81XX + 0x80)
#define	QLT81_NVRAM_FUNC1_ADDR		(FLASH_DATA_ADDR_81XX + 0x180)

#define	QLT83FC_NVRAM_FUNC0_ADDR	(FLASH_DATA_ADDR_83XX + 0x80)
#define	QLT83FC_NVRAM_FUNC1_ADDR	(FLASH_DATA_ADDR_83XX + 0x180)

#define	QLT83FCOE_NVRAM_FUNC0_ADDR	(FLASH_DATA_ADDR_83XX + 0x4080)
#define	QLT83FCOE_NVRAM_FUNC1_ADDR	(FLASH_DATA_ADDR_83XX + 0x4180)

#define	VPD_2400_FUNC0_ADDR		0
#define	VPD_2400_FUNC1_ADDR		0x100

#define	VPD_2500_FUNC0_ADDR		0x48000
#define	VPD_2500_FUNC1_ADDR		0x48100

#define	VPD_2700_FUNC0_ADDR		0x270000
#define	VPD_2700_FUNC1_ADDR		0x270100
#define	VPD_2700_FUNC2_ADDR		0x270200
#define	VPD_2700_FUNC3_ADDR		0x270300

#define	VPD_8100_FUNC0_ADDR		0xD0000
#define	VPD_8100_FUNC1_ADDR		0xD0400

#define	VPD_8021_FUNC0_ADDR		0xFA300
#define	VPD_8021_FUNC1_ADDR		0xFA300

#define	VPD_8300_FC_FUNC0_ADDR		0x270000
#define	VPD_8300_FC_FUNC1_ADDR		0x270100

#define	VPD_8300_FCOE_FUNC0_ADDR	0x274000
#define	VPD_8300_FCOE_FUNC1_ADDR	0x274100
#define	VPD_SIZE			0x80

#define	QLT24_VPD_FUNC0_ADDR		(NVRAM_DATA_ADDR + 0x0)
#define	QLT24_VPD_FUNC1_ADDR		(NVRAM_DATA_ADDR + 0x100)

#define	QLT25_VPD_FUNC0_ADDR		(FLASH_DATA_ADDR + 0x48000)
#define	QLT25_VPD_FUNC1_ADDR		(FLASH_DATA_ADDR + 0x48100)

#define	QLT27_VPD_FUNC0_ADDR		(FLASH_2700_DATA_ADDR + 0x270000)
#define	QLT27_VPD_FUNC1_ADDR		(FLASH_2700_DATA_ADDR + 0x270100)
#define	QLT27_VPD_FUNC2_ADDR		(FLASH_2700_DATA_ADDR + 0x270200)
#define	QLT27_VPD_FUNC3_ADDR		(FLASH_2700_DATA_ADDR + 0x270300)

#define	QLT81_VPD_FUNC0_ADDR		(FLASH_8100_DATA_ADDR + 0xD0000)
#define	QLT81_VPD_FUNC1_ADDR		(FLASH_8100_DATA_ADDR + 0xD0400)

#define	QLT83FC_VPD_FUNC0_ADDR		(FLASH_8300_DATA_ADDR + 0x270000)
#define	QLT83FC_VPD_FUNC1_ADDR		(FLASH_8300_DATA_ADDR + 0x270100)

#define	QLT83FCOE_VPD_FUNC0_ADDR	(FLASH_8300_DATA_ADDR + 0x274000)
#define	QLT83FCOE_VPD_FUNC1_ADDR	(FLASH_8300_DATA_ADDR + 0x274100)

#define	FLASH_2400_FIRMWARE_ADDR	0x20000
#define	FLASH_2400_FIRMWARE_SIZE	0x10000

#define	FLASH_2500_FIRMWARE_ADDR	0x20000
#define	FLASH_2500_FIRMWARE_SIZE	0x10000

#define	FLASH_8100_FIRMWARE_ADDR	0xA0000
#define	FLASH_8100_FIRMWARE_SIZE	0x20000

#define	FLASH_8300_BFE_ADDR		0x200000 /* BIOS/FCode/EFI */
#define	FLASH_8300_BFE_SIZE		0x80000

#define	FLASH_8300_FC_FIRMWARE_ADDR	0x240000
#define	FLASH_8300_FCOE_FIRMWARE_ADDR	0x220000
#define	FLASH_8300_FIRMWARE_SIZE	0x20000

#define	FLASH_8300_FIRMWARE_IMAGE_ADDR	0x40000
#define	FLASH_8300_FIRMWARE_IMAGE_SIZE	0x80000

#define	FLASH_8200_BOOTLOADER_ADDR	0x4000
#define	FLASH_8200_BOOTLOADER_SIZE	0x8000

#define	FLASH_8300_BOOTLOADER_ADDR	0x4000
#define	FLASH_8300_BOOTLOADER_SIZE	0x8000

#define	FLASH_2400_DESCRIPTOR_TABLE	0
#define	FLASH_2500_DESCRIPTOR_TABLE	0x50000
#define	FLASH_8100_DESCRIPTOR_TABLE	0xD8000
#define	FLASH_8200_DESCRIPTOR_TABLE	0
#define	FLASH_8300_DESCRIPTOR_TABLE	0xFC000

#define	FLASH_2400_LAYOUT_TABLE		0x11400
#define	FLASH_2500_LAYOUT_TABLE		0x50400
#define	FLASH_8100_LAYOUT_TABLE		0xD8400
#define	FLASH_8200_LAYOUT_TABLE		0xFC400
#define	FLASH_8300_LAYOUT_TABLE		0xFC400

#define	FLASH_2400_BOOT_CODE_ADDR	0
#define	FLASH_2500_BOOT_CODE_ADDR	0
#define	FLASH_2700_BOOT_CODE_ADDR	0x200000
#define	FLASH_8100_BOOT_CODE_ADDR	0x80000
#define	FLASH_8300_BOOT_CODE_ADDR	0x200000

#define	VPD_TAG_END			0x78
#define	VPD_TAG_CHKSUM			"RV"
#define	VPD_TAG_SN			"SN"
#define	VPD_TAG_PN			"PN"
#define	VPD_TAG_PRODID			"\x82"
#define	VPD_TAG_LRT			0x90
#define	VPD_TAG_LRTC			0x91

typedef struct qlt_rom_header {
	uint8_t		signature[2];
	uint8_t		reserved[0x16];
	uint8_t		dataoffset[2];
	uint8_t		pad[6];
} qlt_rom_header_t;

typedef struct qlt_rom_data {
	uint8_t		signature[4];
	uint8_t		vid[2];
	uint8_t		did[2];
	uint8_t		reserved0[2];
	uint8_t		pcidatalen[2];
	uint8_t		pcidatarev;
	uint8_t		classcode[3];
	uint8_t		imagelength[2];	/* In sectors */
	uint8_t		revisionlevel[2];
	uint8_t		codetype;
	uint8_t		indicator;
	uint8_t		reserved1[2];
	uint8_t		pad[8];
} qlt_rom_data_t;

typedef struct qlt_rom_image {
	qlt_rom_header_t	header;
	qlt_rom_data_t		data;
	uint32_t		cksum;
} qlt_rom_image_t;

#define	PCI_HEADER0		0x55
#define	PCI_HEADER1		0xAA
#define	PCI_DATASIG		"PCIR"
#define	PCI_SECTOR_SIZE		0x200
#define	PCI_CODE_X86PC		0
#define	PCI_CODE_FCODE		1
#define	PCI_CODE_HPPA		2
#define	PCI_CODE_EFI		3
#define	PCI_CODE_FW		0xfe
#define	PCI_IND_LAST_IMAGE	0x80
#define	SBUS_CODE_FCODE		0xf1

/*
 * Firmware Dump structure definition
 */
#define	QL_2200_FW_DUMP_SIZE	0x68000		/* bytes */
#define	QL_2300_FW_DUMP_SIZE	0xE2000		/* bytes */
#define	QL_6322_FW_DUMP_SIZE	0xE2000		/* bytes */
#define	QL_24XX_FW_DUMP_SIZE	0x0330000	/* bytes */
#define	QL_25XX_FW_DUMP_SIZE	0x0330000	/* bytes */

#define	QL_24XX_VPD_SIZE	0x200		/* bytes */
#define	QL_24XX_SFP_SIZE	0x200		/* bytes */

#define	LNF_NVRAM_DATA		BIT_0
#define	LNF_VPD_DATA		BIT_1
#define	LNF_BFE_DATA		BIT_2

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

/*
 * firmware dump Entry Types
 */
#define	DT_NOP		 0
#define	DT_THDR		99
#define	DT_TEND		255
#define	DT_RIOB1	256
#define	DT_WIOB1	257
#define	DT_RIOB2	258
#define	DT_WIOB2	259
#define	DT_RPCI		260
#define	DT_WPCI		261
#define	DT_RRAM		262
#define	DT_GQUE		263
#define	DT_GFCE		264
#define	DT_PRISC	265
#define	DT_RRISC	266
#define	DT_DINT		267
#define	DT_GHBD		268
#define	DT_SCRA		269
#define	DT_RRREG	270
#define	DT_WRREG	271
#define	DT_RRRAM	272
#define	DT_RPCIC	273
#define	DT_GQUES	274
#define	DT_WDMP		275

/*
 * firmware dump Template Header (Entry Type 99)
 */
typedef struct qlt_dt_hdr {
	uint32_t	type;
	uint32_t	first_entry_offset;
	uint32_t	size_of_template;
	uint32_t	rsv;
	uint32_t	num_of_entries;
	uint32_t	version;
	uint32_t	driver_timestamp;
	uint32_t	checksum;
	uint32_t	rsv_1;
	uint32_t	driver_info[3];
	uint32_t	saved_state_area[16];
	uint32_t	rsv_2[8];
	uint32_t	ver_attr[5];
} qlt_dt_hdr_t;

/*
 * firmware dump Common Entry Header
 */
typedef struct qlt_dt_entry_hdr {
	uint32_t	type;
	uint32_t	size;
	uint32_t	rsv;
#ifdef _BIG_ENDIAN
	uint8_t		driver_flags;
	uint8_t		rsv_2;
	uint8_t		rsv_1;
	uint8_t		capture_flags;
#else
	uint8_t		capture_flags;
	uint8_t		rsv_1;
	uint8_t		rsv_2;
	uint8_t		driver_flags;
#endif
} qlt_dt_entry_hdr_t;

/*
 * Capture Flags
 */
#define	PF_ONLY_FLAG	BIT_0	/* Physical Function Only */
#define	PF_VF_FLAG	BIT_1	/* Physical and Virtual Functions */

/*
 * Driver Flags
 */
#define	SKIPPED_FLAG	BIT_7	/* driver skipped this entry  */

/*
 * firmware dump Entry Including Header
 */
typedef struct qlt_dt_entry {
	qlt_dt_entry_hdr_t	h;
	uint32_t		data[1];
} qlt_dt_entry_t;

/*
 * firmware dump Template image
 */
typedef struct qlt_dmp_template {
	uint32_t	rsv[2];
	uint32_t	len;
	uint32_t	major_ver;
	uint32_t	minor_ver;
	uint32_t	subminor_ver;
	uint32_t	attribute;
	qlt_dt_hdr_t	hdr;
	qlt_dt_entry_t	entries[1];
} qlt_dmp_template_t;

typedef struct qlt_dt_riob1 {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
#ifdef _BIG_ENDIAN
	uint8_t			pci_offset;
	uint8_t			reg_count_h;
	uint8_t			reg_count_l;
	uint8_t			reg_size;
#else
	uint8_t			reg_size;
	uint8_t			reg_count_l;
	uint8_t			reg_count_h;
	uint8_t			pci_offset;
#endif
} qlt_dt_riob1_t;

typedef struct qlt_dt_wiob1 {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
	uint32_t		data;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[3];
	uint8_t			pci_offset;
#else
	uint8_t			pci_offset;
	uint8_t			rsv[3];
#endif
} qlt_dt_wiob1_t;

typedef struct qlt_dt_riob2 {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
#ifdef _BIG_ENDIAN
	uint8_t			pci_offset;
	uint8_t			reg_count_h;
	uint8_t			reg_count_l;
	uint8_t			reg_size;
	uint8_t			rsv[3];
	uint8_t			bank_sel_offset;
#else
	uint8_t			reg_size;
	uint8_t			reg_count_l;
	uint8_t			reg_count_h;
	uint8_t			pci_offset;
	uint8_t			bank_sel_offset;
	uint8_t			rsv[3];
#endif
	uint32_t		reg_bank;
} qlt_dt_riob2_t;

typedef struct qlt_dt_wiob2 {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[2];
	uint8_t			data_h;
	uint8_t			data_l;
	uint8_t			bank_sel_offset;
	uint8_t			pci_offset;
	uint8_t			rsv1[2];
#else
	uint8_t			data_l;
	uint8_t			data_h;
	uint8_t			rsv[2];
	uint8_t			rsv1[2];
	uint8_t			pci_offset;
	uint8_t			bank_sel_offset;
#endif
	uint32_t		reg_bank;
} qlt_dt_wiob2_t;

typedef struct qlt_dt_rpci {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
} qlt_dt_rpci_t;

typedef struct qlt_dt_wpci {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
	uint32_t		data;
} qlt_dt_wpci_t, qlt_dt_wrreg_t;

typedef struct qlt_dt_rram {
	qlt_dt_entry_hdr_t	h;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[3];
	uint8_t			ram_area;
#else
	uint8_t			ram_area;
	uint8_t			rsv[3];
#endif
	uint32_t		start_addr;
	uint32_t		end_addr;
} qlt_dt_rram_t;

typedef struct qlt_dt_gque {
	qlt_dt_entry_hdr_t	h;
	uint32_t		num_queues;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[3];
	uint8_t			queue_type;
#else
	uint8_t			queue_type;
	uint8_t			rsv[3];
#endif
} qlt_dt_gque_t, qlt_dt_gques_t;

typedef struct qlt_dt_gfce {
	qlt_dt_entry_hdr_t	h;
	uint32_t		fce_trace_size;
	uint32_t		write_pointer[2];
	uint32_t		base_pointer[2];
	uint32_t		fce_enable_mb0;
	uint32_t		fce_enable_mb2;
	uint32_t		fce_enable_mb3;
	uint32_t		fce_enable_mb4;
	uint32_t		fce_enable_mb5;
	uint32_t		fce_enable_mb6;
} qlt_dt_gfce_t;

typedef struct qlt_dt_prisc {
	qlt_dt_entry_hdr_t	h;
} qlt_dt_prisc_t, qlt_dt_rrisc_t;

typedef struct qlt_dt_dint {
	qlt_dt_entry_hdr_t	h;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[3];
	uint8_t			pci_offset;
#else
	uint8_t			pci_offset;
	uint8_t			rsv[3];
#endif
	uint32_t		data;
} qlt_dt_dint_t;

typedef struct qlt_dt_ghbd {
	qlt_dt_entry_hdr_t	h;
#ifdef _BIG_ENDIAN
	uint8_t			rsv[3];
	uint8_t			host_buf_type;
#else
	uint8_t			host_buf_type;
	uint8_t			rsv[3];
#endif
	uint32_t		buf_size;
	uint32_t		start_addr;
} qlt_dt_ghbd_t;

typedef struct qlt_dt_scra {
	qlt_dt_entry_hdr_t	h;
	uint32_t		scratch_size;
} qlt_dt_scra_t;

typedef struct qlt_dt_rrreg {
	qlt_dt_entry_hdr_t	h;
	uint32_t		addr;
	uint32_t		count;
} qlt_dt_rrreg_t, qlt_dt_rrram_t, qlt_dt_rpcic_t;

typedef struct qlt_dt_wdmp {
	qlt_dt_entry_hdr_t	h;
	uint32_t		length;
	uint32_t		data[1];
} qlt_dt_wdmp_t;

#ifdef	__cplusplus
}
#endif

#endif /* _QLT_REGS_H */
