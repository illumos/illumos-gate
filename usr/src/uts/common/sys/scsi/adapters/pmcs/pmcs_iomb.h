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
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * PMC 8x6G IOMB Definitions
 */
#ifndef	_PMCS_IOMB_H
#define	_PMCS_IOMB_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * An IOMB (IO Message Buffer) is the principle means of communication
 * between the PMC and the HOST. The host places IOMBs on the Inbound
 * Queues (IQ) which are in HOST memory and updates a producer index
 * within the PMC. The PMC pulls the IOMB off the IQ and updates a
 * consumer index in HOST memory. If appropriate, when the PMC is
 * done with the action requested by the IOMB, the PMC writes a
 * reply IOMB to host memory and updates its producer index and
 * interrupts the HOST.
 */
/*
 * The first word of all IOMBs is always laid out thusly:
 *
 * |Byte 3       |Byte 2       |Byte 1      |Byte 0   |
 * +-------------+-------------+----------------------+
 * |V Resvd    BC|Resvd  OBID  |CAT   |  OPCODE       |
 * +--------------------------------------------------+
 *
 * V == Valid
 * BC = Buffer Count
 * OBID = Outbound Queue ID
 * CAT = Category
 * OPCODE = Well, uh, OPCODE.
 */

#define	PMCS_IOMB_VALID		(1U << 31)
#define	PMCS_IOMB_HIPRI		(1U << 30)
#define	PMCS_IOMB_BC_SHIFT	(24)
#define	PMCS_IOMB_BC_MASK	(0xf << PMCS_IOMB_BC_SHIFT)
#define	PMCS_IOMB_OBID_SHIFT	(16)
#define	PMCS_IOMB_OBID_MASK	(0xf << PMCS_IOMB_OBID_SHIFT)
#define	PMCS_IOMB_CAT_SHIFT	(12)
#define	PMCS_IOMB_CAT_MASK	(0xf << PMCS_IOMB_CAT_SHIFT)
#define	PMCS_IOMB_OPCODE_MASK	(0xfff)


#define	PMCS_IOMB_CAT_NET	0
#define	PMCS_IOMB_CAT_FC	1
#define	PMCS_IOMB_CAT_SAS	2
#define	PMCS_IOMB_CAT_SCSI	3

/*
 * Shorthand
 */
#define	PMCS_IOMB_IN_SAS(q, opcode)					\
	(PMCS_IOMB_VALID | (1 << PMCS_IOMB_BC_SHIFT)		|	\
	(PMCS_IOMB_CAT_SAS << PMCS_IOMB_CAT_SHIFT)		|	\
	((q << PMCS_IOMB_OBID_SHIFT) & PMCS_IOMB_OBID_MASK)	|	\
	(opcode & PMCS_IOMB_OPCODE_MASK))

/*
 * PMC IOMB Inbound Queue Opcodes
 */
#define	PMCIN_ECHO							0x01
#define	PMCIN_GET_INFO							0x02
#define	PMCIN_GET_VPD							0x03
#define	PMCIN_PHY_START							0x04
#define	PMCIN_PHY_STOP							0x05
#define	PMCIN_SSP_INI_IO_START						0x06
#define	PMCIN_SSP_INI_TM_START						0x07
#define	PMCIN_SSP_INI_EXT_IO_START					0x08
#define	PMCIN_DEVICE_HANDLE_ACCEPT					0x09
#define	PMCIN_SSP_TGT_IO_START						0x0A
#define	PMCIN_SSP_TGT_RESPONSE_START					0x0B
#define	PMCIN_SSP_INI_EDC_EXT_IO_START					0x0C
#define	PMCIN_SSP_INI_EDC_EXT_IO_START1					0x0D
#define	PMCIN_SSP_TGT_EDC_IO_START					0x0E
#define	PMCIN_SSP_ABORT							0x0F
#define	PMCIN_DEREGISTER_DEVICE_HANDLE					0x10
#define	PMCIN_GET_DEVICE_HANDLE						0x11
#define	PMCIN_SMP_REQUEST						0x12
#define	PMCIN_SMP_RESPONSE						0x13
#define	PMCIN_SMP_ABORT							0x14
#define	PMCIN_ASSISTED_DISCOVERY					0x15
#define	PMCIN_REGISTER_DEVICE						0x16
#define	PMCIN_SATA_HOST_IO_START					0x17
#define	PMCIN_SATA_ABORT						0x18
#define	PMCIN_LOCAL_PHY_CONTROL						0x19
#define	PMCIN_GET_DEVICE_INFO						0x1A
#define	PMCIN_TWI							0x1B
#define	PMCIN_FW_FLASH_UPDATE						0x20
#define	PMCIN_SET_VPD							0x21
#define	PMCIN_GPIO							0x22
#define	PMCIN_SAS_DIAG_MODE_START_END					0x23
#define	PMCIN_SAS_DIAG_EXECUTE						0x24
#define	PMCIN_SAS_HW_EVENT_ACK						0x25
#define	PMCIN_GET_TIME_STAMP						0x26
#define	PMCIN_PORT_CONTROL						0x27
#define	PMCIN_GET_NVMD_DATA						0x28
#define	PMCIN_SET_NVMD_DATA						0x29
#define	PMCIN_SET_DEVICE_STATE						0x2A
#define	PMCIN_GET_DEVICE_STATE						0x2B

/*
 * General Inbound Queue related parameters (DWORD 4)
 */
#define	PMCIN_MESSAGE_REPORT		(1 << 2)
#define	PMCIN_DS_ABORT_TASK		(1 << 3)
#define	PMCIN_DS_IN_RECOVERY		(1 << 4)
#define	PMCIN_DATADIR_NONE		(0x00 << 8)
#define	PMCIN_DATADIR_2_INI		(0x01 << 8)
#define	PMCIN_DATADIR_2_DEV		(0x02 << 8)


/*
 * SATA Host IO Start ATA Protocol Types
 * (placed into DWORD 4)
 */

#define	SATA_PROTOCOL_SRST_ASSERT	(0x01 << 10)
#define	SATA_PROTOCOL_SRT_DEASSERT	(0x02 << 10)
#define	SATA_PROTOCOL_EXECDEVDIAG	(0x03 << 10)
#define	SATA_PROTOCOL_NONDATA		(0x04 << 10)
#define	SATA_PROTOCOL_PIO		(0x05 << 10)
#define	SATA_PROTOCOL_DMA		(0x06 << 10)
#define	SATA_PROTOCOL_FPDMA		(0x07 << 10)

/*
 * SAS Host IO Start TLR definitions
 * (placed into DWORD 4)
 */
#define	SAS_TLR_ALL	0	/* SAS 1.1 and SAS 2.0 per device mode page */
#define	SAS_TLR_ON	1	/* unconditionally on */
#define	SAS_TLR_OFF	2	/* unconditionally off */
#define	SAS_TLR_SAS2	3	/* SAS 2.0 per device mode page */

/*
 * IOP SMP Request Information
 */
#define	SMP_INDIRECT_RESPONSE		0x01
#define	SMP_INDIRECT_REQUEST		0x02
#define	SMP_PHY_OVERRIDE		0x04
#define	SMP_REQUEST_LENGTH_SHIFT	16

/*
 * PHY Start related definitions
 */
#define	PHY_LINK_1_5			0x01
#define	PHY_LINK_3			0x02
#define	PHY_LINK_6			0x04
#define	PHY_LINK_ALL			(PHY_LINK_1_5 | PHY_LINK_3 | PHY_LINK_6)
#define	PHY_LINK_SHIFT			8

#define	PHY_LM_SAS			1
#define	PHY_LM_SATA			2
#define	PHY_LM_AUTO			3
#define	PHY_MODE_SHIFT			12

#define	PHY_SPINUP_HOLD			(1 << 14)

/*
 * LOCAL PHY CONTROL related definitions
 */

/*
 * Device Registration related definitions
 */
#define	PMCS_DEVREG_LINK_RATE_SHIFT	24
#define	PMCS_DEVREG_TYPE_SATA		0
#define	PMCS_DEVREG_TYPE_SAS		(1 << 28)
#define	PMCS_DEVREG_TYPE_SATA_DIRECT	(1 << 29)

#define	PMCS_PHYID_SHIFT		4	/* level 0 registration only */
#define	PMCS_DEVREG_TLR			0x1	/* Transport Layer Retry */

#define	PMCS_DEVREG_IT_NEXUS_TIMEOUT	2000U

#define	PMCS_DEVREG_HA			0x2	/* Host Assigned upper 16 */
						/* bits for device ID. */
/*
 * These are used for getting/setting data in the NVRAM (SEEPROM, VPD, etc.)
 */

typedef struct pmcs_get_nvmd_cmd_s {
	uint32_t		header;		/* DWORD 0 */
	uint32_t		htag;		/* DWORD 1 */
	uint8_t			tdas_nvmd;	/* DWORD 2 */
	uint8_t			tbn_tdps;
	uint8_t			tda;
	uint8_t			ip;
	uint8_t			doa[3];		/* DWORD 3 Data Offset Addr */
	uint8_t			d_len;		/* Direct Pld Data Len */
	uint32_t		rsvd[8];	/* DWORDS 4-11 */
	uint32_t		ipbal;		/* 12 - Ind Pld buf addr low */
	uint32_t		ipbah;		/* 13 - Ind Pld buf addr high */
	uint32_t		ipdl;		/* 14 - Ind Pld data length */
	uint32_t		rsvd3;
} pmcs_get_nvmd_cmd_t;

typedef struct pmcs_set_nvmd_cmd_s {
	uint32_t		header;		/* DWORD 0 */
	uint32_t		htag;		/* DWORD 1 */
	uint8_t			tdas_nvmd;	/* DWORD 2 */
	uint8_t			tbn_tdps;
	uint8_t			tda;
	uint8_t			ip;
	uint8_t			doa[3];		/* DWORD 3 Data Offset Addr */
	uint8_t			d_len;		/* Direct Pld Data Len */
	uint32_t		signature;	/* DWORD 4 */
	uint32_t		rsvd[7];	/* DWORDS 5-11 */
	uint32_t		ipbal;		/* 12 - Ind Pld buf addr low */
	uint32_t		ipbah;		/* 13 - Ind Pld buf addr high */
	uint32_t		ipdl;		/* 14 - Ind Pld data length */
	uint32_t		rsvd2;
} pmcs_set_nvmd_cmd_t;

#define	PMCIN_NVMD_DIRECT_PLD		0x00
#define	PMCIN_NVMD_INDIRECT_PLD		0x80

/* TWI bus number is upper 4 bits of tbn_tdps */
#define	PMCIN_NVMD_TBN(x)		(x << 4)

/* TWI Device Page Size bits (lower 4 bits of tbn_tdps */
#define	PMCIN_NVMD_TDPS_1		0	/* 1 byte */
#define	PMCIN_NVMD_TDPS_8		1	/* 8 bytes */
#define	PMCIN_NVMD_TDPS_16		2	/* 16 bytes */
#define	PMCIN_NVMD_TDPS_32		3	/* 32 bytes */

/* TWI Device Address Size (upper 4 bits of tdas_nvmd) */
#define	PMCIN_NVMD_TDAS_1		(0 << 4)	/* 1 byte */
#define	PMCIN_NVMD_TDAS_2		(1 << 4)	/* 2 bytes */

/*
 * TWI Device Address
 * The address used to access TWI device for the 2Kb SEEPROM device is
 * arranged as follows:
 *	Bits 7-4 are fixed (0xA)
 *	Bits 3-1 are page numbers for each 256 byte page
 *	Bit 0: Set to "1" to read, "0" to write
 * Bit 0 is set/reset by the firmware based on whether the command is a
 * SET or a GET.
 */
#define	PMCIN_TDA_BASE			0xA0
#define	PMCIN_TDA_PAGE(x)		(PMCIN_TDA_BASE | (x << 1))

/* NVM Device bits (lower 4 bits of tdas_nvmd) */
#define	PMCIN_NVMD_TWI			0	/* TWI Device */
#define	PMCIN_NVMD_SEEPROM		1	/* SEEPROM Device */
#define	PMCIN_NVMD_VPD			4	/* VPD Flash Memory */
#define	PMCIN_NVMD_AAP1			5	/* AAP1 Register Dump */
#define	PMCIN_NVMD_IOP			6	/* IOP Register Dump */

#define	PMCS_SEEPROM_PAGE_SIZE		256

/*
 * Minimum and maximum sizes of SPCBoot image
 */
#define	PMCS_SPCBOOT_MIN_SIZE		64
#define	PMCS_SPCBOOT_MAX_SIZE		512

#define	PMCS_SEEPROM_SIGNATURE		0xFEDCBA98

/*
 * Register dump information
 *
 * There are two 16KB regions for register dump information
 */

#define	PMCS_REGISTER_DUMP_FLASH_SIZE	(1024 * 16)
#define	PMCS_REGISTER_DUMP_BLOCK_SIZE	4096	/* Must be read 4K at a time */
#define	PMCS_FLASH_CHUNK_SIZE		4096	/* Must be read 4K at a time */
#define	PMCS_REG_DUMP_SIZE		(1024 * 1024 * 12)
#define	PMCS_NVMD_EVENT_LOG_OFFSET	0x10000
#define	PMCS_IQP_TRACE_BUFFER_SIZE	(1024 * 512)

/*
 * The list of items we can retrieve via the GET_NVMD_DATA command
 */

typedef enum {
	PMCS_NVMD_VPD = 0,
	PMCS_NVMD_REG_DUMP,
	PMCS_NVMD_EVENT_LOG,
	PMCS_NVMD_SPCBOOT
} pmcs_nvmd_type_t;

/*
 * Command types, descriptors and offsets for SAS_DIAG_EXECUTE.
 */
#define	PMCS_DIAG_CMD_DESC_SHIFT	8
#define	PMCS_DIAG_CMD_SHIFT		13
#define	PMCS_DIAG_REPORT_GET		0x04	/* Get counters */
#define	PMCS_ERR_CNT_RESET		0x05	/* Clear counters */
#define	PMCS_DISPARITY_ERR_CNT		0x02	/* Disparity error count */
#define	PMCS_LOST_DWORD_SYNC_CNT	0x05	/* Lost DWord sync count */
#define	PMCS_INVALID_DWORD_CNT		0x06	/* Invalid DWord count */
#define	PMCS_RESET_FAILED_CNT		0x0C	/* PHY reset failed count */

/*
 * VPD data layout
 */

#define	PMCS_EEPROM_INT_VERSION	1	/* supported version for Thebe INT */
#define	PMCS_EEPROM_EXT_VERSION	2	/* supported version for Thebe EXT */
#define	PMCS_VPD_DATA_PAGE	2	/* VPD starts at offset 512 */
#define	PMCS_VPD_RO_BYTE	0x90	/* Start of "read-only" data */
#define	PMCS_VPD_START		0x82	/* VPD start byte */
#define	PMCS_VPD_END		0x78	/* VPD end byte */

#define	PMCS_EEPROM_INT_SSID_BYTE1	0x02	/* Byte 1 of Thebe INT SSID */
#define	PMCS_EEPROM_INT_SSID_BYTE2	0x02	/* Byte 2 of Thebe INT SSID */
#define	PMCS_EEPROM_EXT_SSID_BYTE1	0x00	/* Byte 1 of Thebe EXT SSID */
#define	PMCS_EEPROM_EXT_SSID_BYTE2	0x22	/* Byte 2 of Thebe EXT SSID */

/*
 * This structure defines the "header" for the VPD data.  Everything
 * following this structure is self-defining.  The consumer just needs
 * to allocate a buffer large enough for vpd_length + 3 bytes of data.
 */

typedef struct {
	uint8_t		eeprom_version;
	uint8_t		vpd_length[2];	/* # bytes that follow, little-endian */
	uint8_t		hba_sas_wwid[8];
	uint8_t		subsys_pid[2];
	uint8_t		subsys_vid[2];
	uint8_t		vpd_start_byte;	/* 0x82 */
	uint8_t		strid_length[2]; /* little-endian */
	/* strid_length bytes follow */
} pmcs_vpd_header_t;

typedef struct {
	char		keyword[2];
	uint8_t		value_length;
	char		value[1];	/* Length is actually value_length */
} pmcs_vpd_kv_t;

/*
 * From here on out are definitions related to Outbound Queues
 * (completions of Inbound Queue requests and async events)
 */

/*
 * PMC IOMB Outbound Queue Opcodes
 */
#define	PMCOUT_ECHO							0x01
#define	PMCOUT_GET_INFO							0x02
#define	PMCOUT_GET_VPD							0x03
#define	PMCOUT_SAS_HW_EVENT						0x04
#define	PMCOUT_SSP_COMPLETION						0x05
#define	PMCOUT_SMP_COMPLETION						0x06
#define	PMCOUT_LOCAL_PHY_CONTROL					0x07
#define	PMCOUT_SAS_ASSISTED_DISCOVERY_EVENT				0x08
#define	PMCOUT_SATA_ASSISTED_DISCOVERY_EVENT				0x09
#define	PMCOUT_DEVICE_REGISTRATION					0x0A
#define	PMCOUT_DEREGISTER_DEVICE_HANDLE					0x0B
#define	PMCOUT_GET_DEVICE_HANDLE					0x0C
#define	PMCOUT_SATA_COMPLETION						0x0D
#define	PMCOUT_SATA_EVENT						0x0E
#define	PMCOUT_SSP_EVENT						0x0F
#define	PMCOUT_DEVICE_HANDLE_ARRIVED					0x10
#define	PMCOUT_SSP_REQUEST_RECEIVED					0x12
#define	PMCOUT_DEVICE_INFO						0x13
#define	PMCOUT_FW_FLASH_UPDATE						0x14
#define	PMCOUT_SET_VPD							0x15
#define	PMCOUT_GPIO							0x16
#define	PMCOUT_GPIO_EVENT						0x17
#define	PMCOUT_GENERAL_EVENT						0x18
#define	PMCOUT_TWI							0x19
#define	PMCOUT_SSP_ABORT						0x1A
#define	PMCOUT_SATA_ABORT						0x1B
#define	PMCOUT_SAS_DIAG_MODE_START_END					0x1C
#define	PMCOUT_SAS_DIAG_EXECUTE						0x1D
#define	PMCOUT_GET_TIME_STAMP						0x1E
#define	PMCOUT_SAS_HW_EVENT_ACK_ACK					0x1F
#define	PMCOUT_PORT_CONTROL						0x20
#define	PMCOUT_SKIP_ENTRIES						0x21
#define	PMCOUT_SMP_ABORT						0x22
#define	PMCOUT_GET_NVMD_DATA						0x23
#define	PMCOUT_SET_NVMD_DATA						0x24
#define	PMCOUT_DEVICE_HANDLE_REMOVED					0x25
#define	PMCOUT_SET_DEVICE_STATE						0x26
#define	PMCOUT_GET_DEVICE_STATE						0x27
#define	PMCOUT_SET_DEVICE_INFO						0x28

/*
 * General Outbound Status Definitions
 */
#define	PMCOUT_STATUS_OK						0x00
#define	PMCOUT_STATUS_ABORTED						0x01
#define	PMCOUT_STATUS_OVERFLOW						0x02
#define	PMCOUT_STATUS_UNDERFLOW						0x03
#define	PMCOUT_STATUS_FAILED						0x04
#define	PMCOUT_STATUS_ABORT_RESET					0x05
#define	PMCOUT_STATUS_IO_NOT_VALID					0x06
#define	PMCOUT_STATUS_NO_DEVICE						0x07
#define	PMCOUT_STATUS_ILLEGAL_PARAMETER					0x08
#define	PMCOUT_STATUS_LINK_FAILURE					0x09
#define	PMCOUT_STATUS_PROG_ERROR					0x0A
#define	PMCOUT_STATUS_EDC_IN_ERROR					0x0B
#define	PMCOUT_STATUS_EDC_OUT_ERROR					0x0C
#define	PMCOUT_STATUS_ERROR_HW_TIMEOUT					0x0D
#define	PMCOUT_STATUS_XFER_ERR_BREAK					0x0E
#define	PMCOUT_STATUS_XFER_ERR_PHY_NOT_READY				0x0F
#define	PMCOUT_STATUS_OPEN_CNX_PROTOCOL_NOT_SUPPORTED			0x10
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_ZONE_VIOLATION			0x11
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_BREAK				0x12
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_IT_NEXUS_LOSS			0x13
#define	PMCOUT_STATUS_OPENCNX_ERROR_BAD_DESTINATION			0x14
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED	0x15
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_STP_RESOURCES_BUSY			0x16
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_WRONG_DESTINATION			0x17
#define	PMCOUT_STATUS_OPEN_CNX_ERROR_UNKNOWN_ERROR			0x18
#define	PMCOUT_STATUS_IO_XFER_ERROR_NAK_RECEIVED			0x19
#define	PMCOUT_STATUS_XFER_ERROR_ACK_NAK_TIMEOUT			0x1A
#define	PMCOUT_STATUS_XFER_ERROR_PEER_ABORTED				0x1B
#define	PMCOUT_STATUS_XFER_ERROR_RX_FRAME				0x1C
#define	PMCOUT_STATUS_IO_XFER_ERROR_DMA					0x1D
#define	PMCOUT_STATUS_XFER_ERROR_CREDIT_TIMEOUT				0x1E
#define	PMCOUT_STATUS_XFER_ERROR_SATA_LINK_TIMEOUT			0x1F
#define	PMCOUT_STATUS_XFER_ERROR_SATA					0x20
#define	PMCOUT_STATUS_XFER_ERROR_REJECTED_NCQ_MODE			0x21
#define	PMCOUT_STATUS_XFER_ERROR_ABORTED_DUE_TO_SRST			0x22
#define	PMCOUT_STATUS_XFER_ERROR_ABORTED_NCQ_MODE			0x23
#define	PMCOUT_STATUS_IO_XFER_OPEN_RETRY_TIMEOUT			0x24
#define	PMCOUT_STATUS_SMP_RESP_CONNECTION_ERROR				0x25
#define	PMCOUT_STATUS_XFER_ERROR_UNEXPECTED_PHASE			0x26
#define	PMCOUT_STATUS_XFER_ERROR_RDY_OVERRUN				0x27
#define	PMCOUT_STATUS_XFER_ERROR_RDY_NOT_EXPECTED			0x28
/* 0x29 */
/* 0x2A */
/* 0x2B */
/* 0x2C */
/* 0x2D */
/* 0x2E */
/* 0x2F */
#define	PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_ACK_NAK_TIMEOUT		0x30
#define	PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_BREAK_BEFORE_ACK_NACK	0x31
#define	PMCOUT_STATUS_XFER_ERROR_CMD_ISSUE_PHY_DOWN_BEFORE_ACK_NAK	0x32
/* 0x33 */
#define	PMCOUT_STATUS_XFER_ERROR_OFFSET_MISMATCH			0x34
#define	PMCOUT_STATUS_XFER_ERROR_ZERO_DATA_LEN				0x35
#define	PMCOUT_STATUS_XFER_CMD_FRAME_ISSUED				0x36
#define	PMCOUT_STATUS_ERROR_INTERNAL_SMP_RESOURCE			0x37
#define	PMCOUT_STATUS_IO_PORT_IN_RESET					0x38
#define	PMCOUT_STATUS_IO_DS_NON_OPERATIONAL				0x39
#define	PMCOUT_STATUS_IO_DS_IN_RECOVERY					0x3A
#define	PMCOUT_STATUS_IO_TM_TAG_NOT_FOUND				0x3B
#define	PMCOUT_STATUS_IO_SSP_EXT_IU_ZERO_LEN_ERROR			0x3D
#define	PMCOUT_STATUS_IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY		0x3F
#define	PMCOUT_STATUS_IO_ABORT_IN_PROGRESS				0x40

/*
 * IOMB formats
 *
 * NOTE: All IOMBs are little-endian with exceptions to certain parts of
 * some IOMBs.  For example, the SSP_RESPONSE_IU in the SSP_COMPLETION
 * outbound IOMB is big-endian (SAS).
 */

/* Common IOMB header */

typedef struct pmcs_iomb_header {
	uint8_t		opcode_lo;
	DECL_BITFIELD2(opcode_hi: 4,
	    cat			: 4);
	DECL_BITFIELD2(obid	: 6,
	    rsvd1		: 2);
	DECL_BITFIELD4(buf_count: 5,
	    rsvd2		: 1,
	    h_bit		: 1,
	    v_bit		: 1);
} pmcs_iomb_header_t;

/* PMCOUT_SSP_COMPLETION */

typedef struct pmcout_ssp_comp {
	pmcs_iomb_header_t	header;
	uint32_t		htag;
	uint32_t		status;
	uint32_t		param;
	uint16_t		ssp_tag;
	DECL_BITFIELD3(resc_v	: 1,
	    resc_pad	: 2,
	    rsvd1	: 5);
	uint8_t			rsvd2;
	/* SSP_RESPONSE_IU (if it exists) */
	/* Residual count (if resc_v is set) */
} pmcout_ssp_comp_t;


/*
 * Device State definitions
 */
#define	PMCS_DEVICE_STATE_NOT_AVAILABLE		0x0	/* Unconfigured tgt */
#define	PMCS_DEVICE_STATE_OPERATIONAL		0x1
#define	PMCS_DEVICE_STATE_PORT_IN_RESET		0x2
#define	PMCS_DEVICE_STATE_IN_RECOVERY		0x3
#define	PMCS_DEVICE_STATE_IN_ERROR		0x4
#define	PMCS_DEVICE_STATE_NON_OPERATIONAL	0x7

/*
 * Reset Types
 */
#define	PMCS_SSP_LINK_RESET		0x1
#define	PMCS_SSP_HARD_RESET		0x2
#define	PMCS_SMP_HARD_RESET		0x3

/*
 * PHYOP for LOCAL_PHY_CONTROL Command
 */
#define	PMCS_PHYOP_LINK_RESET		0x01
#define	PMCS_PHYOP_HARD_RESET		0x02

/*
 * Specialized status values
 */
/* PHY Stop Status Results */
#define	IOP_PHY_STOP_OK		0x0
#define	IOP_PHY_STOP_INVALID	0x1
#define	IOP_PHY_STOP_ERROR	0x3
#define	IOP_PHY_STOP_ALREADY	0x4

/* PHY Start Status Results */
#define	IOP_PHY_START_OK	0
#define	IOP_PHY_START_INVALID	1
#define	IOP_PHY_START_ALREADY	2
#define	IOP_PHY_START_ERROR	3

/* SET/GET_NVMD status results */
#define	PMCS_NVMD_STAT_SUCCESS			0x0000
#define	PMCS_NVMD_STAT_PLD_NVMD_COMB_ERR	0x0001
#define	PMCS_NVMD_STAT_PLD_LEN_ERR		0x0002
#define	PMCS_NVMD_STAT_TWI_DEV_NACK		0x2001
#define	PMCS_NVMD_STAT_TWI_DEV_LOST_ARB		0x2002
#define	PMCS_NVMD_STAT_TWI_TIMEOUT		0x2021
#define	PMCS_NVMD_STAT_TWI_BUS_NACK		0x2081
#define	PMCS_NVMD_STAT_TWI_DEV_ARB_FAIL		0x2082
#define	PMCS_NVMD_STAT_TWI_BUS_SER_TIMEO	0x20FF
#define	PMCS_NVMD_STAT_PART_NOT_IN_FLASH	0x9001
#define	PMCS_NVMD_STAT_LEN_TOO_LARGE		0x9002
#define	PMCS_NVMD_STAT_FLASH_PRGRM_FAIL		0x9003
#define	PMCS_NVMD_STAT_DEVID_MATCH_FAIL		0x9004
#define	PMCS_NVMD_STAT_VENDID_MATCH_FAIL	0x9005
#define	PMCS_NVMD_STAT_SEC_ERASE_TIMEO		0x9006
#define	PMCS_NVMD_STAT_SEC_ERASE_CWE		0x9007
#define	PMCS_NVMD_STAT_FLASH_DEV_BUSY		0x9008
#define	PMCS_NVMD_STAT_FLASH_DEV_NOT_SUP	0x9009
#define	PMCS_NVMD_STAT_FLASH_NO_CFI		0x900A
#define	PMCS_NVMD_STAT_ERASE_BLOCKS		0x900B
#define	PMCS_NVMD_STAT_PART_READ_ONLY		0x900C
#define	PMCS_NVMD_STAT_PART_INV_MAP_TYPE	0x900D
#define	PMCS_NVMD_STAT_PART_INIT_STR_DIS	0x900E

/*
 * General Event Status Codes
 */
#define	INBOUND_IOMB_V_BIT_NOT_SET		0x1
#define	INBOUND_IOMB_OPC_NOT_SUPPORTED		0x2

/* Device Register Status Results */
#define	PMCS_DEVREG_OK				0x0
#define	PMCS_DEVREG_DEVICE_ALREADY_REGISTERED	0x2
#define	PMCS_DEVREG_PHY_ALREADY_REGISTERED	0x4

/*
 * Flash Update responses
 */
#define	FLASH_UPDATE_COMPLETE_PENDING_REBOOT	0x0
#define	FLASH_UPDATE_IN_PROGRESS		0x1
#define	FLASH_UPDATE_HDR_ERR			0x2
#define	FLASH_UPDATE_OFFSET_ERR			0x3
#define	FLASH_UPDATE_UPDATE_CRC_ERR		0x4
#define	FLASH_UPDATE_LENGTH_ERR			0x5
#define	FLASH_UPDATE_HW_ERR			0x6
#define	FLASH_UPDATE_DNLD_NOT_SUPPORTED		0x10
#define	FLASH_UPDATE_DISABLED			0x11

/*
 * IOP SAS HW Event Related definitions
 */

#define	IOP_EVENT_LINK_RATE(x)		((x >> 28) & 0xf)
#define	IOP_EVENT_STATUS(x) 		((x >> 24) & 0xf)
#define	IOP_EVENT_EVENT(x)		((x >> 8) & 0xffff)
#define	IOP_EVENT_PHYNUM(x)		((x >> 4) & 0xf)
#define	IOP_EVENT_PORTID(x)		((x) & 0xf)


#define	IOP_EVENT_PHY_STOP_STATUS		0x03
#define	IOP_EVENT_SAS_PHY_UP			0x04
#define	IOP_EVENT_SATA_PHY_UP			0x05
#define	IOP_EVENT_SATA_SPINUP_HOLD		0x06
#define	IOP_EVENT_PHY_DOWN			0x07
#define	IOP_EVENT_PORT_INVALID			0x08	/* < fw 1.6 */
#define	IOP_EVENT_BROADCAST_CHANGE		0x09
#define	IOP_EVENT_BROADCAST_SES			0x0B
#define	IOP_EVENT_PHY_ERR_INBOUND_CRC		0x0C
#define	IOP_EVENT_HARD_RESET_RECEIVED		0x0D
#define	IOP_EVENT_EVENT_ID_FRAME_TIMO		0x0F
#define	IOP_EVENT_BROADCAST_EXP			0x10
#define	IOP_EVENT_PHY_START_STATUS		0x11
#define	IOP_EVENT_PHY_ERR_INVALID_DWORD		0x12
#define	IOP_EVENT_PHY_ERR_DISPARITY_ERROR	0x13
#define	IOP_EVENT_PHY_ERR_CODE_VIOLATION	0x14
#define	IOP_EVENT_PHY_ERR_LOSS_OF_DWORD_SYN	0x15
#define	IOP_EVENT_PHY_ERR_PHY_RESET_FAILD	0x16
#define	IOP_EVENT_PORT_RECOVERY_TIMER_TMO	0x17
#define	IOP_EVENT_PORT_RECOVER			0x18
#define	IOP_EVENT_PORT_RESET_TIMER_TMO		0x19
#define	IOP_EVENT_PORT_RESET_COMPLETE		0x20
#define	IOP_EVENT_BROADCAST_ASYNC_EVENT		0x21
#define	IOP_EVENT_IT_NEXUS_LOSS			0x22


#define	IOP_EVENT_PORT_STATE(x)		((x) & 0xf)
#define	IOP_EVENT_NPIP(x)		(((x) >> 4) & 0xf)

#define	IOP_EVENT_PS_NIL		0x0	/* PORT_ID not valid yet */
#define	IOP_EVENT_PS_VALID		0x1	/* PORT_ID now valid */
#define	IOP_EVENT_PS_LOSTCOMM		0x2	/* Link temporarily down */
#define	IOP_EVENT_PS_IN_RESET		0x4	/* Port in reset */
#define	IOP_EVENT_PS_INVALID		0x8	/* PORT_ID now dead */

/*
 * HW Event Acknowledge Response Values
 */
#define	SAS_HW_EVENT_ACK_OK		0x0
#define	SAS_HW_EVENT_ACK_INVALID_SEA	0x1
#define	SAS_HW_EVENT_ACK_INVALID_PHY	0x2
#define	SAS_HW_EVENT_ACK_INVALID_PORT	0x4
#define	SAS_HW_EVENT_ACK_INVALID_PARAM	0x8

/*
 * IOMB Queue definitions and Macros
 */

#define	ADDQI(ix, n, qd)	((ix + n) & (qd - 1))
#define	INCQI(ix, qd)		ix = ADDQI(ix, 1, qd)
#define	QI2O(ix, n, qd)		(ADDQI(ix, n, qd) * PMCS_QENTRY_SIZE)

/*
 * Inbound Queue Producer Indices live inside the PMC card.
 *
 * Inbound Queue Consumer indices live in host memory. We use the Consumer
 * Index to return a pointer to an Inbound Queue entry. We then can fill
 * it with an IOMB. We then update the the Producer index which kicks
 * card to read the IOMB we just wrote.
 *
 * There is one mutex for each inbound queue that is held from the time
 * we get an entry until we increment the producer index, or released
 * manually if we don't actually send the message.
 */

/*
 * NB: the appropriate iqp_lock must be held
 */
#define	GET_IQ_ENTRY(hwp, qnum)	\
	((ADDQI(hwp->shadow_iqpi[qnum], 1, hwp->ioq_depth) == \
	pmcs_rd_iqci(hwp, qnum)) ? NULL : \
	&hwp->iqp[qnum][hwp->shadow_iqpi[qnum] * (PMCS_QENTRY_SIZE >> 2)])

/*
 * NB: This releases the lock on the Inbound Queue that GET_IO_IQ_ENTRY
 * acquired below.
 */
#ifdef	DEBUG
#define	INC_IQ_ENTRY(hwp, qnum)						\
{									\
	uint32_t htag;							\
	ASSERT(mutex_owned(&(hwp)->iqp_lock[qnum]));			\
	htag = hwp->iqp[qnum][(hwp->shadow_iqpi[qnum] *			\
	    (PMCS_QENTRY_SIZE >> 2)) + 1];				\
	mutex_enter(&(hwp)->dbglock);					\
	pmcs_iqp_trace(hwp, qnum);					\
	mutex_exit(&(hwp)->dbglock);					\
	INCQI(hwp->shadow_iqpi[qnum], hwp->ioq_depth);			\
	if (ddi_dma_sync(hwp->cip_handles, 0, 0,			\
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {			\
		pmcs_prt(hwp, PMCS_PRT_DEBUG, NULL, NULL, "Condition "	\
		    "failed at %s():%d", __func__, __LINE__);		\
	}								\
	hwp->ftime[hwp->fti] = gethrtime();				\
	pmcs_wr_iqpi(hwp, qnum, hwp->shadow_iqpi[qnum]);		\
	mutex_exit(&(hwp)->iqp_lock[qnum]);				\
	mutex_enter(&(hwp)->dbglock);					\
	hwp->ftag_lines[hwp->fti] = __LINE__;				\
	hwp->ftags[hwp->fti++] = htag;					\
	mutex_exit(&(hwp)->dbglock);					\
}
#else
#define	INC_IQ_ENTRY(hwp, qnum)						\
	INCQI(hwp->shadow_iqpi[qnum], hwp->ioq_depth);			\
	if (ddi_dma_sync(hwp->cip_handles, 0, 0,			\
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {			\
		pmcs_prt(hwp, PMCS_PRT_DEBUG, NULL, NULL, "Condition "	\
		    "failed at %s():%d", __func__, __LINE__);		\
	}								\
	pmcs_wr_iqpi(hwp, qnum, hwp->shadow_iqpi[qnum]);		\
	mutex_exit(&(hwp)->iqp_lock[qnum])
#endif


/*
 * NB: sucessfull acquisition of an IO Inbound Queue
 * entry leaves the lock on that Inbound Queue held.
 */
#define	GET_IO_IQ_ENTRY(pwp, msg, did, iq)				\
	iq = did & PMCS_IO_IQ_MASK;					\
	mutex_enter(&(pwp)->iqp_lock[iq]);				\
	msg = GET_IQ_ENTRY(pwp, iq);					\
	if (msg == NULL) {						\
		mutex_exit(&(pwp)->iqp_lock[iq]);			\
		for (iq = 0; iq <= PMCS_NON_HIPRI_QUEUES; iq++) {	\
			mutex_enter(&(pwp)->iqp_lock[iq]);		\
			msg = GET_IQ_ENTRY(pwp, iq);			\
			if (msg) {					\
				break;					\
			}						\
			mutex_exit(&(pwp->iqp_lock[iq]));		\
		}							\
	}

/*
 * Outbound Queue Macros
 *
 * Outbound Queue Consumer indices live inside the card.
 *
 * Outbound Queue Producer indices live in host memory. When the card
 * wants to send an IOMB, it uses the producer index to find the spot
 * to write the IOMB. After it's done it updates the producer index
 * and interrupts the host. The host reads the producer index (from
 * host memory) and reads IOMBs up to but not including that index.
 * It writes that index back to the consumer index on the card,
 * signifying that it has read up to that which the card has sent.
 */
#define	GET_OQ_ENTRY(hwp, qn, ix, o) \
	&hwp->oqp[qn][QI2O(ix, o, hwp->ioq_depth) >> 2]

#define	STEP_OQ_ENTRY(hwp, qn, ix, n)	ix = ADDQI(ix, n, hwp->ioq_depth)

#define	SYNC_OQ_ENTRY(hwp, qn, ci, pi) 		\
	pmcs_wr_oqci(hwp, qn, ci);		\
	(hwp)->oqci[qn] = ci;			\
	(hwp)->oqpi[qn] = pi

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_IOMB_H */
