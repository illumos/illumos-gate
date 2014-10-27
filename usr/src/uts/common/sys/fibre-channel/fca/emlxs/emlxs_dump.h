/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_DUMP_H
#define	_EMLXS_DUMP_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct emlxs_file
{
	uint8_t *buffer;
	uint8_t *ptr;
	uint32_t size;

} emlxs_file_t;

typedef struct dump_temp_event
{
	struct emlxs_hba *hba;
	uint32_t type;
	uint32_t temp;

} dump_temp_event_t;

#define	EMLXS_TXT_FILE_SIZE	(1024*1024)
#define	EMLXS_DMP_FILE_SIZE	((8*1024*1024)+0x100)
/* #define	EMLXS_DMP_FILE_SIZE	(4*1024*1024) */
#define	EMLXS_CEE_FILE_SIZE	(1024*1024)

/* Maximum BC for DUMP w/o MBX Extension */
#define	DUMP_BC_MAX		(0x18 * 4)

/* Conditional Compile Symbols */

#define	CC_DUMP_FW_BUG_1	1	/* 1 = workaround for FW Bug */
#define	CC_DUMP_ENABLE_PAD	1	/* 1 = enable DMP File Padding */

/* The following define controls whether the Dump Routines, */
/* in the Port Memory Dump, */
/* use all (potentially up to 3) Dump Tables, or only Dump Table #1. */
/* This is a diagnostic feature only, and is not compiled in releases. */
/* If enabled, this feature provides a way to test all the FW Dump Tables, */
/* a debugging courtesy to the FW group. */

/* 1 = all Dump Tables; 0 = Table 1 Only */
#define	CC_DUMP_USE_ALL_TABLES	1

/* Dump Type: loaded into gDumpType; controls */
/* operation of many dump functions */
#define	DUMP_TYPE_USER		0	/* User-Initiated Dump */
#define	DUMP_TYPE_DRIVER	1	/* Normal Driver-Initiated Dump */
#define	DUMP_TYPE_TEMP		2	/* Driver-Initiated Temp Event Dump */

/* Dump Temperature  tempType Event codes (from DFC) */
#define	TEMP_TYPE_CRITICAL	1
#define	TEMP_TYPE_THRESHOLD	2
#define	TEMP_TYPE_NORMAL	3

/* Misc Defines */

#define	DUMP_SEMAPHORE_RETRY	200	/* times to retry acquiring sema */

#define	DUMP_RETENTION_CNT_DEF	10	/* files to retain before purging */
#define	DUMP_RETENTION_CNT_MAX	500	/* (Linux KW ID 122) */

#define	DUMP_TXT_FILE		0
#define	DUMP_DMP_FILE		1
#define	DUMP_CEE_FILE		2

/* Driver Name Strings */
#define	DUMP_DRV_UNK		"Unknown"
#define	DUMP_DRV_LEADVILLE	"Solaris " DRIVER_NAME

/* SIDs (Dump File Segment Identifiers) */

/* SID Control Bits */
#define	SID_MULT_ELEM		0x20	/* indicates structures, not bytes */

/* This set of SIDs is defined in "LightPulse Dump Facility Design Guide" */
#define	SID_NULL		0x00	/* Null SID */
#define	SID_ID01		0x01	/* Dump Table Identification */
#define	SID_ID02		0x02	/* Dump Table Identification */
#define	SID_ID03		0x03	/* Dump Table Identification */
#define	SID_TERM		0x04	/* Dump Table Termination */
#define	SID_SLIM		0x05	/* SLIM */
#define	SID_05			0x06	/* reserved */
#define	SID_PCI_CONFIG		0x07	/* PCI Cfg Registers (Direct) */
#define	SID_SLI_REGS		0x08	/* SLI Registers (Direct) */
#define	SID_29			0x29	/* reserved */
#define	SID_PCI_CONFIG_I	0x47	/* PCI Cfg Registers (Indirect) */
#define	SID_SLI_I		0x48	/* SLI Registers (Indirect) */
#define	SID_DUMP_ID_LE		0x80	/* Dump Id, Little-endian system. */
#define	SID_DUMP_ID_BE		0x81	/* Dump Id, Big-endian system. */
#define	SID_DUMP_TERM		0x82	/* Dump Termination. Last byte */
#define	SID_LEGEND		0x83	/* Legend */
#define	SID_PCB			0x84	/* PCB */
#define	SID_MBX			0x86	/* Mailbox */
#define	SID_HOST_PTRS		0x87	/* Host Put/Get Pointer Array */
#define	SID_PORT_PTRS		0x88	/* Port Get/Put Pointer Array */
#define	SID_RINGS		0xA9	/* Command/Response Rings */
#define	SID_PCB_A		0xC4	/* PCB */
#define	SID_MBX_A		0xC6	/* Mailbox */
#define	SID_HOST_PTRS_A		0xC7	/* Host Put/Get Pointer Array */
#define	SID_PORT_PTRS_A		0xC8	/* Port Get/Put Pointer Array */
#define	SID_BUFFER_LISTS	0xCA	/* Buffer Lists */
#define	SID_RINGS_A		0xE9	/* Command/Response Rings */
#define	SID_BUFFER_LISTS_A	0xEA	/* Buffer Lists */

/* This set of SIDs is defined in "HBAnyware v2.3 */
/* Dump Feature Design Specification" */

#define	SID_HBA_MEM_DUMP	0x11	/* HBA Memory Dump */
#define	SID_REV_INFO		0x90	/* Revision Information */
#define	SID_HBA_INFO		0x91	/* HBA Information */
#define	SID_DP_TABLE		0x92	/* Driver Parm Table */
#define	SID_DP_UNIX		0x93	/* Driver Parm, config (Unix) */
#define	SID_DP_WINDOWS		0x94	/* Driver Parm, Reg Entries (Win) */
#define	SID_INTERNAL_MP		0x95	/* Driver-specific Intrnl, Miniport */
#define	SID_INTERNAL_SP		0x96	/* Driver-specific Intrnl, Storport */
#define	SID_INTERNAL_SOL	0x97	/* Driver-specific Intrnl, Solaris */
#define	SID_INTERNAL_L7X	0x98	/* Driver-specific Intrnl, Lnx 7x */
#define	SID_INTERNAL_L8X	0x99	/* Driver-specific Intrnl, Lnx 8x */
#define	SID_CONFIG_REGION	0x9A	/* Config Region Data */
#define	SID_NON_VOLATILE_LOG	0x9B	/* NV Log (Enterprise only) */

/* Legend Strings */

#define	LEGEND_CONFIG_REGION		"Config Region Data"
#define	LEGEND_HBA_MEM_DUMP		"HBA Memory Dump"
#define	LEGEND_REV_INFO			"Revision Information"
#define	LEGEND_HBA_INFO			"HBA Information"
#define	LEGEND_DP_TABLE			"Driver Parameters: Table"
#define	LEGEND_DP_UNIX		"Driver Parameters: Config File Entries"
#define	LEGEND_DP_WINDOWS	"Driver Parameters: Registry Entries"
#define	LEGEND_INTERNAL_MP	"Driver-specific Internal Structures, Miniport"
#define	LEGEND_INTERNAL_SP	"Driver-specific Internal Structures, Storport"
#define	LEGEND_INTERNAL_SOL	"Driver-specific Internal Structures, Solaris"
#define	LEGEND_INTERNAL_L7X	"Driver-specific Internal Structures, Linux 7x"
#define	LEGEND_INTERNAL_L8X	"Driver-specific Internal Structures, Linux 8x"
#define	LEGEND_SLI_STRUCTURES		"SLI Interface Structures"
#define	LEGEND_MENLO_LOG_CONFIG		"Converged Enhanced Ethernet (CEE) Log"
#define	LEGEND_MENLO_LOG_PANIC_REGS	"\n\nPanic Log Registers\n"
#define	LEGEND_MENLO_LOG_PANIC_LOGS	"\n\nPanic Log Entries\n"
#define	LEGEND_NON_VOLATILE_LOG		"Non-Volatile Log Data"

/* Sub-Legends associated with SID_HBA_MEM_DUMP // HBA Memory Dump */
#define	LEGEND_HBA_MEM_DUMP_TABLE	"Dump Table"
#define	LEGEND_HBA_MEM_DUMP_REGION	"Dump Region"

/* Sub-Legends associated with SID_REV_INFO // Revision Information */
#define	LEGEND_REV_OS_VERSION		"OS Version"
#define	LEGEND_REV_DRV_VERSION		"Driver Version"
#define	LEGEND_REV_UTIL_VERSION		"HBAnyware Version"
#define	LEGEND_REV_DFCLIB_VERSION	"DFC Lib Version"

/* Sub-Legends associated with SID_HBA_INFO // Adapter Information */
#define	LEGEND_HBA_MODEL		"Adapter Model"
#define	LEGEND_HBA_WWN			"Adapter WWN"
#define	LEGEND_HBA_SN			"Adapter Serial Number"
#define	LEGEND_HBA_FW_VERSION		"Firmware Version"
#define	LEGEND_HBA_FW_OPVERSION		"Operational FW Version"
#define	LEGEND_HBA_FW_SLI1VERSION	"SLI-1 FW Version"
#define	LEGEND_HBA_FW_SLI2VERSION	"SLI-2 FW Version"
#define	LEGEND_HBA_FW_SLI3VERSION	"SLI-3 FW Version"
#define	LEGEND_HBA_FW_KERNELVERSION	"Kernel FW Version"
#define	LEGEND_HBA_BB_STATE		"Boot Bios State"
#define	LEGEND_HBA_BB_VERSION		"Boot Bios Version"
#define	LEGEND_HBA_LMSD_A0		"Link Module Serial Data: Page A0"
#define	LEGEND_HBA_LMSD_A2		"Link Module Serial Data: Page A2"

/* Sub-Legends associated with SID_CONFIG_REGION // Configuration Region */
#define	LEGEND_CONFIG_REGION_0	"Config Region 0: Non-volatile Params"
#define	LEGEND_CONFIG_REGION_1	"Config Region 1: reserved"
#define	LEGEND_CONFIG_REGION_2	"Config Region 2: reserved"
#define	LEGEND_CONFIG_REGION_3	"Config Region 3: reserved"
#define	LEGEND_CONFIG_REGION_4	"Config Region 4: Wake-up Params"
#define	LEGEND_CONFIG_REGION_5	"Config Region 5: PCI Config, Default"
#define	LEGEND_CONFIG_REGION_6	"Config Region 6: PCI Config, Alternate 1"
#define	LEGEND_CONFIG_REGION_7	"Config Region 7: PCI Config, Alternate 2"
#define	LEGEND_CONFIG_REGION_8	"Config Region 8: Boot Params, x86, Basic"
#define	LEGEND_CONFIG_REGION_9	"Config Region 9: Boot Params, x86, Extended"
#define	LEGEND_CONFIG_REGION_10	"Config Region 10: Boot Params, EFI"
#define	LEGEND_CONFIG_REGION_11	"Config Region 11: reserved"
#define	LEGEND_CONFIG_REGION_12	"Config Region 12: reserved"
#define	LEGEND_CONFIG_REGION_13	"Config Region 13: reserved"
#define	LEGEND_CONFIG_REGION_14	"Config Region 14: VPD"
#define	LEGEND_CONFIG_REGION_15	"Config Region 15: Diagnostic Trace"
#define	LEGEND_CONFIG_REGION_16	"Config Region 16: reserved"
#define	LEGEND_CONFIG_REGION_17	\
	"Config Region 17: Physical Environment NV Params"
#define	LEGEND_CONFIG_REGION_18	"Config Region 18: reserved"
#define	LEGEND_CONFIG_REGION_19	"Config Region 19: reserved"
#define	LEGEND_CONFIG_REGION_20	"Config Region 20: reserved"
#define	LEGEND_CONFIG_REGION_21	"Config Region 21: Saved Wakeup Params"
#define	LEGEND_CONFIG_REGION_22	"Config Region 22: reserved"
#define	LEGEND_CONFIG_REGION_23	"Config Region 23: reserved"
#define	LEGEND_CONFIG_REGION_24	"Config Region 24: reserved"
#define	LEGEND_CONFIG_REGION_25	"Config Region 25: reserved"
#define	LEGEND_CONFIG_REGION_26	"Config Region 26: reserved"
#define	LEGEND_CONFIG_REGION_27	"Config Region 27: reserved"
#define	LEGEND_CONFIG_REGION_28	"Config Region 28: reserved"
#define	LEGEND_CONFIG_REGION_29	"Config Region 29: reserved"
#define	LEGEND_CONFIG_REGION_30	"Config Region 30: reserved"
#define	LEGEND_CONFIG_REGION_31	"Config Region 31: reserved"
#define	LEGEND_CONFIG_REGION_32	"Config Region 32: IEEE Address"

/* Additional Sub-Legends for Region 4 */
#define	LEGEND_CR4_INITIAL_LOAD		"Initial Load"
#define	LEGEND_CR4_FLAGS		"Flags       "
#define	LEGEND_CR4_BOOT_BIOS_ID		"Boot Bios ID"
#define	LEGEND_CR4_SLI1_ID		"SLI-1 ID    "
#define	LEGEND_CR4_SLI2_ID		"SLI-2 ID    "
#define	LEGEND_CR4_SLI3_ID		"SLI-3 ID    "
#define	LEGEND_CR4_SLI4_ID		"SLI-4 ID    "
#define	LEGEND_CR4_EROM_ID		"E-Rom ID    "

/* Sub-Legends associated with SLI Interface Structures */
#define	LEGEND_SLI_REGS		"SLI Registers"
#define	LEGEND_SLIM		"SLIM"
#define	LEGEND_PCB		"PCB"
#define	LEGEND_MBX		"Mailbox"
#define	LEGEND_HOST_PTRS	"Host Pointers"
#define	LEGEND_PORT_PTRS	"Port Pointers"
#define	LEGEND_RINGS		"Cmd/Rsp Rings"
#define	LEGEND_DRIVER_SPEC	"Driver-Specific Internal Structures"

/* Misc Legend Data */
#define	LEGEND_NULL	""
#define	LEGEND_NV_LOG_DRIVER_NOT_SUPPORTED \
	"NV Log not supported by the driver"
#define	LEGEND_NV_LOG_STATUS_ERROR \
	"Error in getting NV Log status"
#define	LEGEND_NV_LOG_ERROR \
	"Error in getting NV Log"

#define	NV_LOG_NOT_INCLUDED_IN_DMP \
	"Non-Volatile Log Dump is not included in the DMP file"
#define	NV_LOG_INCLUDED_IN_DMP \
	"Non-Volatile Log Dump is included in the DMP file"

#define	NV_LOG_NOT_INCLUDED_IN_FAT \
	"Non-Volatile Log Dump is not included in the FAT file"
#define	NV_LOG_INCLUDED_IN_FAT \
	"Non-Volatile Log Dump is included in the FAT file"

/* Dump Regions Definitions */
#define	DR_SLI_REGS	0x0000
#define	DR_SLIM		0x0001
#define	DR_PCB		0x0002
#define	DR_MBX		0x0003
#define	DR_HOST_PTRS	0x0004
#define	DR_PORT_PTRS	0x0005
#define	DR_RINGS	0x0006
#define	DR_INTERNAL	0x0007

/* DFC_GetDriverDumpRegions Status */
#define	GDDR_ST_SUCCESS		0
#define	GDDR_ST_ERROR		1	/* General Error */
#define	GDDR_ST_BAD_ID		2	/* Bad Region Identifier */
#define	GDDR_ST_BUF_OVERFLOW	3	/* Buffer Overflow */
#define	GDDR_ST_ID_NA		4	/* Region Identifier Not Applicable */

/* Max size supported by dump Config Region routines */
#define	DUMP_MAX_CONFIG_REGION_LENGTH   1000


/* This is a simplified form of the wakeup params structure, */
/* w/o all the bit fields, */
/* for ease of displaying in the Dump File. */
typedef struct _DUMP_WAKE_UP_PARAMS
{
	uint32_t InitialId[2];
	uint32_t Flags;
	uint32_t BootBiosId[2];
	uint32_t Sli1Id[2];
	uint32_t Sli2Id[2];
	uint32_t Sli3Id[2];
	uint32_t Sli4Id[2];
	uint32_t EromId[2];
} DUMP_WAKE_UP_PARAMS;


typedef struct _DUMP_TABLE_ENTRY_PORT_STRUCT
{
	union
	{
		uint32_t w[2];
		struct
		{
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t count:16;	/* structure repeat count */
			uint32_t length:8;	/* structure length */
			uint32_t sid:8;	/* SID */
#else
			uint32_t sid:8;	/* SID */
			uint32_t length:8;	/* structure length */
			uint32_t count:16;	/* structure repeat count */
#endif
			uint32_t addr;	/* address */
		} s;

	} un;

} DUMP_TABLE_ENTRY_PORT_STRUCT;


/* This is a simplified form of the Dump Table Entry structures. */
typedef struct _DUMP_TABLE_ENTRY_PORT_BLK
{
	union
	{
		uint32_t w[2];
		struct
		{

#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t bc:24;	/* byte count */
			uint32_t sid:8;	/* SID */
#else
			uint32_t sid:8;	/* SID */
			uint32_t bc:24;	/* byte count */
#endif
			uint32_t addr;	/* address */
		} s;

	} un;

} DUMP_TABLE_ENTRY_PORT_BLK;


typedef struct _DUMP_TABLE_ENTRY
{
	union
	{
		DUMP_TABLE_ENTRY_PORT_BLK PortBlock;
		DUMP_TABLE_ENTRY_PORT_STRUCT PortStruct;

	} un;

} DUMP_TABLE_ENTRY;

/* VPD Data Defines */

#define	VPD_TAG_82  0x82	/* start of VPD Data: Device Name */
#define	VPD_TAG_90  0x90	/* start of Read-Only Area */
#define	VPD_TAG_FF  0x0F	/* end tag */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_DUMP_H */
