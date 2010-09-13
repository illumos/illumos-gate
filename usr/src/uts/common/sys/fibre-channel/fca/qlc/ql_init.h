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

/* Copyright 2009 QLogic Corporation */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_QL_INIT_H
#define	_QL_INIT_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2009 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ISP2200 NVRAM structure definition.
 * Little endian except where noted.
 */
typedef struct nvram {
	/*
	 * NVRAM header
	 */
	uint8_t	 id[4];
	uint8_t	 nvram_version;
	uint8_t	 reserved_0;

	/*
	 * NVRAM RISC parameter block
	 */
	uint8_t	 parameter_block_version;
	uint8_t	 reserved_1;

	/*
	 * LSB BIT 0  = enable_hard_loop_id
	 * LSB BIT 1  = enable_fairness
	 * LSB BIT 2  = enable_full_duplex
	 * LSB BIT 3  = enable_fast_posting
	 * LSB BIT 4  = enable_target_mode
	 * LSB BIT 5  = disable_initiator_mode
	 * LSB BIT 6  = enable_adisc
	 * LSB BIT 7  = enable_target_inquiry_data
	 *
	 * MSB BIT 0  = enable_port_update_ae
	 * MSB BIT 1  = disable_initial_lip
	 * MSB BIT 2  = enable_decending_soft_assign
	 * MSB BIT 3  = previous_assigned_addressing
	 * MSB BIT 4  = enable_stop_q_on_full
	 * MSB BIT 5  = enable_full_login_on_lip
	 * MSB BIT 6  = enable_node_name
	 * MSB BIT 7  = extended_control_block
	 */
	uint8_t	 firmware_options[2];

	uint8_t	 max_frame_length[2];
	uint8_t	 max_iocb_allocation[2];
	uint8_t	 execution_throttle[2];
	uint8_t	 login_retry_count;
	uint8_t	 retry_delay;			/* unused */
	uint8_t	 port_name[8];			/* Big endian. */
	uint8_t	 hard_address[2];
	uint8_t	 inquiry;
	uint8_t	 login_timeout;
	uint8_t	 node_name[8];			/* Big endian. */

	/*
	 * LSB BIT 0 = Timer operation mode bit 0
	 * LSB BIT 1 = Timer operation mode bit 1
	 * LSB BIT 2 = Timer operation mode bit 2
	 * LSB BIT 3 = Timer operation mode bit 3
	 * LSB BIT 4 = P2P Connection option bit 0
	 * LSB BIT 5 = P2P Connection option bit 1
	 * LSB BIT 6 = P2P Connection option bit 2
	 * LSB BIT 7 = Enable Non part on LIHA failure
	 *
	 * MSB BIT 0 = Enable class 2
	 * MSB BIT 1 = Enable ACK0
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 = FC Tape Enable
	 * MSB BIT 5 = Enable FC Confirm
	 * MSB BIT 6 = Enable command queuing in target mode
	 * MSB BIT 7 = No Logo On Link Down
	 */
	uint8_t	 add_fw_opt[2];
	uint8_t	 response_accumulation_timer;
	uint8_t	 interrupt_delay_timer;

	/*
	 * LSB BIT 0 = Enable Read xfr_rdy
	 * LSB BIT 1 = Soft ID only
	 * LSB BIT 2 =
	 * LSB BIT 3 =
	 * LSB BIT 4 = FCP RSP Payload [0]
	 * LSB BIT 5 = FCP RSP Payload [1] / Sbus enable - 2200
	 * LSB BIT 6 =
	 * LSB BIT 7 =
	 *
	 * MSB BIT 0 = Sbus enable - 2300
	 * MSB BIT 1 =
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 =
	 * MSB BIT 5 = Enable 50 ohm termination
	 * MSB BIT 6 = Data Rate (2300 only)
	 * MSB BIT 7 = Data Rate (2300 only)
	 */
	uint8_t	 special_options[2];

	/* Reserved for expanded RISC parameter block */
	uint8_t reserved_4[26];

	/*
	 * NVRAM host parameter block
	 *
	 * LSB BIT 0 = unused
	 * LSB BIT 1 = disable_bios
	 * LSB BIT 2 = disable_luns
	 * LSB BIT 3 = enable_selectable_boot
	 * LSB BIT 4 = disable_risc_code_load
	 * LSB BIT 5 = set_cache_line_size_1
	 * LSB BIT 6 = pci_parity_disable
	 * LSB BIT 7 = enable_extended_logging
	 *
	 * MSB BIT 0 = enable_64bit_addressing
	 * MSB BIT 1 = enable_lip_reset
	 * MSB BIT 2 = enable_lip_full_login
	 * MSB BIT 3 = enable_target_reset
	 * MSB BIT 4 = enable_database_storage
	 * MSB BIT 5 = unused
	 * MSB BIT 6 = unused
	 * MSB BIT 7 = unused
	 */
	uint8_t	 host_p[2];

	uint8_t	 boot_node_name[8];
	uint8_t	 boot_lun_number;
	uint8_t	 reset_delay;
	uint8_t	 port_down_retry_count;
	uint8_t	 reserved_5;

	uint8_t  maximum_luns_per_target[2];

	uint8_t reserved_6[14];

	/* Offset 100 */
	uint8_t reverved_7[12];

	/* offset 112 */
	uint8_t adapInfo[16];	/* Sun OEM HBA's 23xx only */

	uint8_t reserved_8[22];

	/* Offset 150 */
	uint8_t reserved_9[50];

	/* Offset 200 */
	uint8_t reserved_10[32];

	/*
	 * NVRAM Adapter Features offset 232-239
	 *
	 * LSB BIT 0 = External GBIC
	 * LSB BIT 1 = Risc RAM parity
	 * LSB BIT 2 = Buffer Plus Module
	 * LSB BIT 3 = Multi Chip Adapter
	 * LSB BIT 4 =
	 * LSB BIT 5 =
	 * LSB BIT 6 =
	 * LSB BIT 7 =
	 *
	 * MSB BIT 0 =
	 * MSB BIT 1 =
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 =
	 * MSB BIT 5 =
	 * MSB BIT 6 =
	 * MSB BIT 7 =
	 */
	uint8_t adapter_features[2];
	uint8_t reserved_11[6];

	/*
	 * Resrved for use with ISP2300 - offset 240
	 */
	uint8_t reserved_12[4];

	/* Subsystem ID must be at offset 244 */
	uint8_t subsystem_vendor_id[2];

	uint8_t reserved_13[2];

	/* Subsystem device ID must be at offset 248 */
	uint8_t subsystem_device_id[2];

	/* Subsystem vendor ID for ISP2200 */
	uint8_t subsystem_vendor_id_2200[2];

	/* Subsystem device ID for ISP2200 */
	uint8_t subsystem_device_id_2200[2];

	uint8_t	 reserved_14;
	uint8_t	 checksum;
} nvram_t;

/*
 * NVRAM structure definition.
 */
typedef struct nvram_24xx {
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
	 * BIT 15 = Reserved
	 *
	 * BIT 16-31 = Reserved
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
	 * BIT 10 = Enable Virtual Fabric
	 * BIT 11 = Enable FC-SP Security
	 * BIT 12 = FC Tape Enable
	 * BIT 13 = Reserved
	 * BIT 14 = Target PRLI Control
	 * BIT 15 = Reserved
	 *
	 * BIT 16  = Enable Emulated MSIX
	 * BIT 17  = Reserved
	 * BIT 18  = Enable Alternate Device Number
	 * BIT 19  = Enable Alternate Bus Number
	 * BIT 20  = Enable Translated Address
	 * BIT 21  = Enable VM Security
	 * BIT 22  = Enable Interrupt Handshake
	 * BIT 23  = Enable Multiple Queue
	 *
	 * BIT 24  = IOCB Security
	 * BIT 25  = qos
	 * BIT 26-31 = Reserved
	 */
	uint8_t firmware_options_2[4];

	/*
	 * BIT 0  = Reserved
	 * BIT 1  = Soft ID only
	 * BIT 2  = Reserved
	 * BIT 3  = disable split completion timeout
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
	 *
	 * BIT 16 = 75-ohm Termination Select
	 * BIT 17 = Enable Multiple FCFs
	 * BIT 18 = MAC Addressing Mode
	 * BIT 19 = MAC Addressing Mode
	 * BIT 20 = MAC Addressing Mode
	 * BIT 21 = Ethernet Data Rate
	 * BIT 22 = Ethernet Data Rate
	 * BIT 23 = Ethernet Data Rate
	 *
	 * BIT 24 = Ethernet Data Rate
	 * BIT 25 = Ethernet Data Rate
	 * BIT 26 = Enable Ethernet Header ATIO Queue
	 * BIT 27 = Enable Ethernet Header Response Queue
	 * BIT 28 = SPMA Selection
	 * BIT 29 = SPMA Selection
	 * BIT 30 = Reserved
	 * BIT 31 = Reserved
	 */
	uint8_t firmware_options_3[4];

	union {
		struct {
			/*
			 * Offset 56 (38h)
			 * Serial Link Control
			 * BIT 0 = control enable
			 * BIT 1-15 = Reserved
			 */
			uint8_t swing_opt[2];
			/*
			 * Offset 58 (3Ah)
			 * Serial Link Control 1G
			 * BIT 0-7   = Reserved
			 *
			 * BIT 8-10  = output swing
			 * BIT 11-13 = output emphasis
			 * BIT 14-15 = Reserved
			 */
			uint8_t swing_1g[2];
			/*
			 * Offset 60 (3Ch)
			 * Serial Link Control 2G
			 * BIT 0-7   = Reserved
			 *
			 * BIT 8-10  = output swing
			 * BIT 11-13 = output emphasis
			 * BIT 14-15 = Reserved
			 */
			uint8_t swing_2g[2];
			/*
			 * Offset 62 (3Eh)
			 * Serial Link Control 4G
			 * BIT 0-7   = Reserved
			 *
			 * BIT 8-10  = output swing
			 * BIT 11-13 = output emphasis
			 * BIT 14-15 = Reserved
			 */
			uint8_t swing_4g[2];

			/* Offset 64 (40h). */
			uint8_t reserved[32];
		} isp2400;
		struct {
			/*
			 * Offset 56 (38h)
			 * Serial Link Control
			 * BIT 0  = Reserved
			 * BIT 1  = 25xx TX control enable
			 * BIT 2  = 25xx RX control enable (lmtg)
			 * BIT 3  = 25xx RX control enable (linear)
			 * BIT 4  = embedded HBA
			 * BIT 5  = unused
			 * BIT 6  = 25xx E7 Addr27 Preset
			 * BIT 7  = 25xx E6 Addr0 Ch0 enable
			 *
			 * BIT 8-15 = 25xx E6 Addr0 Ch0
			 *
			 * BIT 16-31 = Reserved
			 */
			uint8_t swing_opt[4];

			/*
			 * Offset 60 (3Ch)
			 * Serial Link TX Parameters
			 * BIT 0 = TX Amplitude
			 * BIT 1 = TX Amplitude
			 * BIT 2 = TX Amplitude
			 * BIT 3 = TX Amplitude
			 * BIT 4 = TX Amplitude
			 * BIT 5 = TX iPost
			 * BIT 6 = TX iPost
			 * BIT 7 = TX iPost
			 *
			 * BIT 8 = TX iPost
			 * BIT 9 = TX iPre
			 * BIT 10 = TX iPre
			 * BIT 11 = TX iPre
			 * BIT 12 = TX iPre
			 * BIT 13 = TX iMain
			 * BIT 14 = TX iMain
			 * BIT 15 = TX iMain
			 *
			 * BIT 16 = TX iMain
			 * BIT 17 = TX iMain
			 * BIT 18-23 = Reserved
			 *
			 * BIT 24-31 = Reserved
			 */
			uint8_t tx_8g[4];
			/* Offset 64 (40h) */
			uint8_t tx_4g[4];
			/* Offset 68 (44h) */
			uint8_t tx_2g[4];

			/*
			 * Offset 72 (48h)
			 * Serial Link RX Parameters
			 * BIT 0 = RX Z1Cnt
			 * BIT 1 = RX Z1Cnt
			 * BIT 2 = RX Z1Cnt
			 * BIT 3 = RX Z1Cnt
			 * BIT 4 = RX G1Cnt
			 * BIT 5 = RX ZCnt
			 * BIT 6 = RX ZCnt
			 * BIT 7 = RX ZCnt
			 *
			 * BIT 8 = RX ZCnt
			 * BIT 9 = RX ZCnt
			 * BIT 10 = RX TLTH
			 * BIT 11 = RX TLTH
			 * BIT 12 = RX TLTH
			 * BIT 13 = RX TLTH
			 * BIT 14 = RX TLTH
			 * BIT 15 = RX TLTH
			 *
			 * BIT 16 = RX DFELTH
			 * BIT 17 = RX DFELTH
			 * BIT 18 = RX DFELTH
			 * BIT 19 = RX DFELTH
			 * BIT 20 = RX DFELTH
			 * BIT 21 = RX DFELTH
			 * BIT 22-23 = Reserved
			 *
			 * BIT 24-31 = Reserved
			 */
			uint8_t rx_limit_8g[4];
			/* Offset 76 (4Ch) */
			uint8_t rx_limit_4g[4];
			/* Offset 80 (50h) */
			uint8_t rx_limit_2g[4];
			/* Offset 84 (54h) */
			uint8_t rx_linear_8g[4];
			/* Offset 88 (58h) */
			uint8_t rx_linear_4g[4];
			/* Offset 92 (5Ch) */
			uint8_t rx_linear_2g[4];
		} isp2500;
		struct {
			/* Offset 56 (38h) */
			uint8_t reserved[8];

			/* Offset 64 (40h). */
			uint8_t e_node_mac_addr[6];

			/* Offset 70 (46h). */
			uint8_t reserved2[26];
		} isp8001;
	} fw;

	/*
	 * Offset 96 (60h)
	 * BIT 0   = initiator op
	 * BIT 1   = target op
	 * BIT 2   = VI op
	 * BIT 3-7 = Reserved
	 */
	uint8_t oem_specific;
	uint8_t reserved_4[15];

	/* Offset 112 (70h). */
	uint8_t reserved_5[16];

	/*
	 * Offset 128 (80h).
	 * PCIe table entries.
	 * Firmware Extended Initialization Control Block.
	 */
	ql_ext_icb_8100_t	ext_blk;

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
	 * BIT 8  = EV control enable
	 * BIT 9  = Enable lip reset
	 * BIT 10 = Enable lip full login
	 * BIT 11 = Enable target reset
	 * BIT 12 = Stop firmware
	 * BIT 13 = Default Node Name Option
	 * BIT 14 = Default WWPN valid
	 * BIT 15 = Enable alternate WWN
	 *
	 * CLP BIOS flags
	 *
	 * BIT 16 = clp lun string
	 * BIT 17 = clp target string
	 * BIT 18 = clp bios enable string
	 * BIT 19 = clp serdes_string
	 * BIT 20 = clp wwpn string
	 * BIT 21 = clp wwnn string
	 * BIT 22 = win reserverd 0
	 * BIT 23 = win reserverd 1
	 *
	 * BIT 24 = keep wwpn
	 * BIT 25 = temp wwpn
	 * BIT 26 = win reserverd 2
	 * BIT 27 = win reserverd 3
	 * BIT 28 = clear WBT in flash (win driver)
	 * BIT 29 = write WBT in flash (win driver)
	 * BIT 30 = load fw from flash (win driver)
	 * BIT 31 = enable alternate WWN (win driver)
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
	 * BIT 3 = fcode sunid
	 * BIT 4-7 =
	 */
	uint8_t	fcode_p0;
	uint8_t reserved_16[7];

	/*
	 * Offset 352 (160h).
	 * uint8_t prev_drv_ver_major;
	 * uint8_t prev_drv_ver_submajob;
	 * uint8_t prev_drv_ver_minor;
	 * uint8_t prev_drv_ver_subminor;
	 * uint8_t prev_bios_ver_major[2];
	 * uint8_t prev_bios_ver_minor[2];
	 * uint8_t prev_efi_ver_major[2];
	 * uint8_t prev_efi_ver_minor[2];
	 * uint8_t prev_fw_ver_major[2];
	 * uint8_t prev_fw_ver_minor;
	 * uint8_t prev_fw_ver_subminor;
	 * uint8_t reserved[16];
	 */
	uint8_t mac_address[6];
	uint8_t clp_flag[2];
	uint8_t reserved_18[24];

	/* Offset 384 (180h). */
	uint8_t	def_port_name[8];
	uint8_t def_node_name[8];
	uint8_t clp_flag1[2];
	uint8_t clp_flag2[2];

	/* Offset 404 (194h). */
	uint8_t default_firmware_options[2];

	/* Offset 406 (196h). */
	uint8_t enhanced_features[2];
	uint8_t serdes_index[2];
	uint8_t reserved_19[6];

	/* Offset 416 (1A0h). */
	uint8_t alt4_boot_port_name[8];
	uint8_t alt4_boot_lun_number[2];
	uint8_t reserved_20[2];

	/* Offset 428 (1ACh). */
	uint8_t alt5_boot_port_name[8];
	uint8_t alt5_boot_lun_number[2];
	uint8_t reserved_21[2];

	/* Offset 440 (1B8h). */
	uint8_t alt6_boot_port_name[8];
	uint8_t alt6_boot_lun_number[2];
	uint8_t reserved_22[2];

	/* Offset 452 (1C4h). */
	uint8_t alt7_boot_port_name[8];
	uint8_t alt7_boot_lun_number[2];
	uint8_t reserved_23[2];

	/* Offset 464 (1D0h). */
	uint8_t reserved_24[12];

	/* Offset 476 (1DCh). */
	uint8_t	fw_table_offset[2];
	uint8_t fw_table_sig[2];

	/* Offset 480 (1E0h). */
	int8_t  model_name[4];
	int8_t  model_name1[12]; /* 24xx power_table[8]. */

	/* Offset 496 (1F0h). */
	uint8_t feature_mask_l[2];
	uint8_t feature_mask_h[2];
	uint8_t reserved_25[4];

	/* Offset 504 (1F8h). */
	uint8_t subsystem_vendor_id[2];
	uint8_t subsystem_device_id[2];

	uint8_t checksum[4];
} nvram_24xx_t;

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

/*
 * firmware dump struct for 2300 is a superset of firmware dump struct
 * for 2200. Fields which are 2300 only or are enhanced for 2300 are
 * marked below.
 */
typedef struct ql_fw_dump {
	uint16_t pbiu_reg[8];
	uint16_t risc_host_reg[8];	/* 2300 only. */
	uint16_t mailbox_reg[16];	/* 2200 only needs 8 */
	uint16_t resp_dma_reg[32];	/* 2300 only. */
	uint16_t dma_reg[48];
	uint16_t risc_hdw_reg[16];
	uint16_t risc_gp0_reg[16];
	uint16_t risc_gp1_reg[16];
	uint16_t risc_gp2_reg[16];
	uint16_t risc_gp3_reg[16];
	uint16_t risc_gp4_reg[16];
	uint16_t risc_gp5_reg[16];
	uint16_t risc_gp6_reg[16];
	uint16_t risc_gp7_reg[16];
	uint16_t frame_buf_hdw_reg[64];	/* 2200 has only 16 */
	uint16_t fpm_b0_reg[64];
	uint16_t fpm_b1_reg[64];
	uint16_t risc_ram[0xf800];	/* 2200 needs only 0xf000 */
	uint16_t stack_ram[0x800];	/* 2300 only */
	uint16_t data_ram[0xf800];	/* 2300 only */
	uint32_t req_q[REQUEST_QUEUE_SIZE / 4];
	uint32_t rsp_q[RESPONSE_QUEUE_SIZE / 4];
} ql_fw_dump_t;

typedef struct ql_24xx_fw_dump {
	uint32_t hccr;
	uint32_t host_reg[32];
	uint16_t mailbox_reg[32];
	uint32_t xseq_gp_reg[128];
	uint32_t xseq_0_reg[16];
	uint32_t xseq_1_reg[16];
	uint32_t rseq_gp_reg[128];
	uint32_t rseq_0_reg[16];
	uint32_t rseq_1_reg[16];
	uint32_t rseq_2_reg[16];
	uint32_t cmd_dma_reg[16];
	uint32_t req0_dma_reg[15];
	uint32_t resp0_dma_reg[15];
	uint32_t req1_dma_reg[15];
	uint32_t xmt0_dma_reg[32];
	uint32_t xmt1_dma_reg[32];
	uint32_t xmt2_dma_reg[32];
	uint32_t xmt3_dma_reg[32];
	uint32_t xmt4_dma_reg[32];
	uint32_t xmt_data_dma_reg[16];
	uint32_t rcvt0_data_dma_reg[32];
	uint32_t rcvt1_data_dma_reg[32];
	uint32_t risc_gp_reg[128];
	uint32_t shadow_reg[7];
	uint32_t lmc_reg[112];
	uint32_t fpm_hdw_reg[192];
	uint32_t fb_hdw_reg[176];
	uint32_t code_ram[0x2000];
	uint32_t req_q[REQUEST_QUEUE_SIZE / 4];
	uint32_t rsp_q[RESPONSE_QUEUE_SIZE / 4];
	uint32_t ext_trace_buf[FWEXTSIZE / 4];
	uint32_t fce_trace_buf[FWFCESIZE / 4];
	uint32_t ext_mem[1];
} ql_24xx_fw_dump_t;

typedef struct ql_25xx_fw_dump {
	uint32_t r2h_status;
	uint32_t hostrisc_reg[32];
	uint32_t pcie_reg[4];
	uint32_t host_reg[32];
	uint16_t mailbox_reg[32];
	uint32_t xseq_gp_reg[128];
	uint32_t xseq_0_reg[48];
	uint32_t xseq_1_reg[16];
	uint32_t rseq_gp_reg[128];
	uint32_t rseq_0_reg[32];
	uint32_t rseq_1_reg[16];
	uint32_t rseq_2_reg[16];
	uint32_t aseq_gp_reg[128];
	uint32_t aseq_0_reg[32];
	uint32_t aseq_1_reg[16];
	uint32_t aseq_2_reg[16];
	uint32_t cmd_dma_reg[16];
	uint32_t req0_dma_reg[15];
	uint32_t resp0_dma_reg[15];
	uint32_t req1_dma_reg[15];
	uint32_t xmt0_dma_reg[32];
	uint32_t xmt1_dma_reg[32];
	uint32_t xmt2_dma_reg[32];
	uint32_t xmt3_dma_reg[32];
	uint32_t xmt4_dma_reg[32];
	uint32_t xmt_data_dma_reg[16];
	uint32_t rcvt0_data_dma_reg[32];
	uint32_t rcvt1_data_dma_reg[32];
	uint32_t risc_gp_reg[128];
	uint32_t shadow_reg[11];
	uint32_t risc_io;
	uint32_t lmc_reg[128];
	uint32_t fpm_hdw_reg[192];
	uint32_t fb_hdw_reg[192];
	uint32_t code_ram[0x2000];
	uint32_t req_q[REQUEST_QUEUE_SIZE / 4];
	uint32_t rsp_q[RESPONSE_QUEUE_SIZE / 4];
	uint32_t ext_trace_buf[FWEXTSIZE / 4];
	uint32_t fce_trace_buf[FWFCESIZE / 4];
	uint32_t ext_mem[1];
} ql_25xx_fw_dump_t;

typedef struct ql_81xx_fw_dump {
	uint32_t r2h_status;
	uint32_t hostrisc_reg[32];
	uint32_t pcie_reg[4];
	uint32_t host_reg[32];
	uint16_t mailbox_reg[32];
	uint32_t xseq_gp_reg[128];
	uint32_t xseq_0_reg[48];
	uint32_t xseq_1_reg[16];
	uint32_t rseq_gp_reg[128];
	uint32_t rseq_0_reg[32];
	uint32_t rseq_1_reg[16];
	uint32_t rseq_2_reg[16];
	uint32_t aseq_gp_reg[128];
	uint32_t aseq_0_reg[32];
	uint32_t aseq_1_reg[16];
	uint32_t aseq_2_reg[16];
	uint32_t cmd_dma_reg[16];
	uint32_t req0_dma_reg[15];
	uint32_t resp0_dma_reg[15];
	uint32_t req1_dma_reg[15];
	uint32_t xmt0_dma_reg[32];
	uint32_t xmt1_dma_reg[32];
	uint32_t xmt2_dma_reg[32];
	uint32_t xmt3_dma_reg[32];
	uint32_t xmt4_dma_reg[32];
	uint32_t xmt_data_dma_reg[16];
	uint32_t rcvt0_data_dma_reg[32];
	uint32_t rcvt1_data_dma_reg[32];
	uint32_t risc_gp_reg[128];
	uint32_t shadow_reg[11];
	uint32_t risc_io;
	uint32_t lmc_reg[128];
	uint32_t fpm_hdw_reg[224];
	uint32_t fb_hdw_reg[208];
	uint32_t code_ram[0x2000];
	uint32_t req_q[REQUEST_QUEUE_SIZE / 4];
	uint32_t rsp_q[RESPONSE_QUEUE_SIZE / 4];
	uint32_t ext_trace_buf[FWEXTSIZE / 4];
	uint32_t fce_trace_buf[FWFCESIZE / 4];
	uint32_t ext_mem[1];
} ql_81xx_fw_dump_t;

#ifdef _KERNEL

/*
 * ql_lock_nvram() flags
 */
#define	LNF_NVRAM_DATA	BIT_0		/* get nvram */
#define	LNF_VPD_DATA	BIT_1		/* get vpd data (24xx only) */

/*
 *  ISP product identification definitions in mailboxes after reset.
 */
#define	PROD_ID_1	0x4953
#define	PROD_ID_2	0x0000
#define	PROD_ID_2a	0x5020
#define	PROD_ID_3	0x2020

/*
 * NVRAM Command values.
 */
#define	NV_START_BIT	BIT_2
#define	NV_WRITE_OP	(BIT_26+BIT_24)
#define	NV_READ_OP	(BIT_26+BIT_25)
#define	NV_ERASE_OP	(BIT_26+BIT_25+BIT_24)
#define	NV_MASK_OP	(BIT_26+BIT_25+BIT_24)
#define	NV_DELAY_COUNT	10

/*
 * Deivce ID list definitions.
 */
struct ql_dev_id {
	uint8_t		al_pa;
	uint8_t		area;
	uint8_t		domain;
	uint8_t		loop_id;
};

struct ql_ex_dev_id {
	uint8_t		al_pa;
	uint8_t		area;
	uint8_t		domain;
	uint8_t		reserved;
	uint8_t		loop_id_l;
	uint8_t		loop_id_h;
};

struct ql_24_dev_id {
	uint8_t		al_pa;
	uint8_t		area;
	uint8_t		domain;
	uint8_t		reserved;
	uint8_t		n_port_hdl_l;
	uint8_t		n_port_hdl_h;
	uint8_t		reserved_1[2];
};

typedef union ql_dev_id_list {
	struct ql_dev_id	d;
	struct ql_ex_dev_id	d_ex;
	struct ql_24_dev_id	d_24;
} ql_dev_id_list_t;

/* Define maximum number of device list entries.. */
#define	DEVICE_LIST_ENTRIES	MAX_24_FIBRE_DEVICES

/*
 * Global Data in ql_init.c source file.
 */

/*
 * Global Function Prototypes in ql_init.c source file.
 */
int ql_initialize_adapter(ql_adapter_state_t *);
int ql_pci_sbus_config(ql_adapter_state_t *);
int ql_nvram_config(ql_adapter_state_t *);
uint16_t ql_get_nvram_word(ql_adapter_state_t *, uint32_t);
void ql_nv_write(ql_adapter_state_t *, uint16_t);
void ql_nv_delay(void);
int ql_lock_nvram(ql_adapter_state_t *, uint32_t *, uint32_t);
void ql_release_nvram(ql_adapter_state_t *);
void ql_common_properties(ql_adapter_state_t *);
uint32_t ql_get_prop(ql_adapter_state_t *, char *);
int ql_load_isp_firmware(ql_adapter_state_t *);
int ql_start_firmware(ql_adapter_state_t *);
int ql_set_cache_line(ql_adapter_state_t *);
int ql_init_rings(ql_adapter_state_t *);
int ql_fw_ready(ql_adapter_state_t *, uint8_t);
void ql_dev_list(ql_adapter_state_t *, ql_dev_id_list_t *, uint32_t,
    port_id_t *, uint16_t *);
void ql_reset_chip(ql_adapter_state_t *);
void ql_reset_24xx_chip(ql_adapter_state_t *);
int ql_abort_isp(ql_adapter_state_t *);
int ql_vport_control(ql_adapter_state_t *, uint8_t);
int ql_vport_modify(ql_adapter_state_t *, uint8_t, uint8_t);
int ql_vport_enable(ql_adapter_state_t *);
ql_adapter_state_t *ql_vport_create(ql_adapter_state_t *, uint8_t);
void ql_vport_destroy(ql_adapter_state_t *);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _QL_INIT_H */
