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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This header file defines the interfaces available from the SMBIOS access
 * library, libsmbios, and an equivalent kernel module.  This API can be used
 * to access DMTF SMBIOS data from a device, file, or raw memory buffer.
 *
 * This is NOT a Public interface, and should be considered Unstable, as it is
 * subject to change without notice as the DMTF SMBIOS specification evolves.
 * Therefore, be aware that any program linked with this API in this
 * instance of illumos is almost guaranteed to break in the next release.
 */

#ifndef	_SYS_SMBIOS_H
#define	_SYS_SMBIOS_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum smbios_entry_point_type {
	SMBIOS_ENTRY_POINT_21,
	SMBIOS_ENTRY_POINT_30
} smbios_entry_point_t;

/*
 * SMBIOS Structure Table Entry Point.  See DSP0134 5.2.1 for more information.
 * The structure table entry point is located by searching for the anchor.
 */
#pragma pack(1)

typedef struct smbios_21_entry {
	char smbe_eanchor[4];		/* anchor tag (SMB_ENTRY_EANCHOR) */
	uint8_t smbe_ecksum;		/* checksum of entry point structure */
	uint8_t smbe_elen;		/* length in bytes of entry point */
	uint8_t smbe_major;		/* major version of the SMBIOS spec */
	uint8_t smbe_minor;		/* minor version of the SMBIOS spec */
	uint16_t smbe_maxssize;		/* maximum size in bytes of a struct */
	uint8_t smbe_revision;		/* entry point structure revision */
	uint8_t smbe_format[5];		/* entry point revision-specific data */
	char smbe_ianchor[5];		/* intermed. tag (SMB_ENTRY_IANCHOR) */
	uint8_t smbe_icksum;		/* intermed. checksum */
	uint16_t smbe_stlen;		/* length in bytes of structure table */
	uint32_t smbe_staddr;		/* physical addr of structure table */
	uint16_t smbe_stnum;		/* number of structure table entries */
	uint8_t smbe_bcdrev;		/* BCD value representing DMI version */
} smbios_21_entry_t;

/*
 * The 64-bit SMBIOS 3.0 Entry Point.  See DSP0134 5.2.2 for more information.
 * The structure table entry point is located by searching for the anchor.
 */

typedef struct smbios_30_entry {
	char smbe_eanchor[5];		/* anchor tag (SMB3_ENTRY_EANCHOR) */
	uint8_t smbe_ecksum;		/* checksum of entry point structure */
	uint8_t smbe_elen;		/* length in bytes of entry point */
	uint8_t smbe_major;		/* major version of the SMBIOS spec */
	uint8_t smbe_minor;		/* minor version of the SMBIOS spec */
	uint8_t smbe_docrev;		/* specification docrev */
	uint8_t smbe_revision;		/* entry point structure revision */
	uint8_t smbe_reserved;
	uint32_t smbe_stlen;		/* length in bytes of structure table */
	uint64_t smbe_staddr;		/* physical addr of structure table */
} smbios_30_entry_t;

typedef union {
	smbios_21_entry_t ep21;
	smbios_30_entry_t ep30;
} smbios_entry_t;

#pragma pack()

#define	SMB_ENTRY_EANCHOR	"_SM_"	/* structure table entry point anchor */
#define	SMB_ENTRY_EANCHORLEN	4	/* length of entry point anchor */
#define	SMB3_ENTRY_EANCHOR	"_SM3_"	/* structure table entry point anchor */
#define	SMB3_ENTRY_EANCHORLEN	5	/* length of entry point anchor */
#define	SMB_ENTRY_IANCHOR	"_DMI_"	/* intermediate anchor string */
#define	SMB_ENTRY_IANCHORLEN	5	/* length of intermediate anchor */
#define	SMB_ENTRY_MAXLEN	255	/* maximum length of entry point */

/*
 * Structure type codes.  The comments next to each type include an (R) note to
 * indicate a structure that is required as of SMBIOS v2.8 and an (O) note to
 * indicate a structure that is obsolete as of SMBIOS v2.8.
 */
#define	SMB_TYPE_BIOS		0	/* BIOS information (R) */
#define	SMB_TYPE_SYSTEM		1	/* system information (R) */
#define	SMB_TYPE_BASEBOARD	2	/* base board */
#define	SMB_TYPE_CHASSIS	3	/* system enclosure or chassis (R) */
#define	SMB_TYPE_PROCESSOR	4	/* processor (R) */
#define	SMB_TYPE_MEMCTL		5	/* memory controller (O) */
#define	SMB_TYPE_MEMMOD		6	/* memory module (O) */
#define	SMB_TYPE_CACHE		7	/* processor cache (R) */
#define	SMB_TYPE_PORT		8	/* port connector */
#define	SMB_TYPE_SLOT		9	/* upgradeable system slot (R) */
#define	SMB_TYPE_OBDEVS		10	/* on-board devices (O) */
#define	SMB_TYPE_OEMSTR		11	/* OEM string table */
#define	SMB_TYPE_SYSCONFSTR	12	/* system configuration string table */
#define	SMB_TYPE_LANG		13	/* BIOS language information */
#define	SMB_TYPE_GROUP		14	/* group associations */
#define	SMB_TYPE_EVENTLOG	15	/* system event log */
#define	SMB_TYPE_MEMARRAY	16	/* physical memory array (R) */
#define	SMB_TYPE_MEMDEVICE	17	/* memory device (R) */
#define	SMB_TYPE_MEMERR32	18	/* 32-bit memory error information */
#define	SMB_TYPE_MEMARRAYMAP	19	/* memory array mapped address (R) */
#define	SMB_TYPE_MEMDEVICEMAP	20	/* memory device mapped address */
#define	SMB_TYPE_POINTDEV	21	/* built-in pointing device */
#define	SMB_TYPE_BATTERY	22	/* portable battery */
#define	SMB_TYPE_RESET		23	/* system reset settings */
#define	SMB_TYPE_SECURITY	24	/* hardware security settings */
#define	SMB_TYPE_POWERCTL	25	/* system power controls */
#define	SMB_TYPE_VPROBE		26	/* voltage probe */
#define	SMB_TYPE_COOLDEV	27	/* cooling device */
#define	SMB_TYPE_TPROBE		28	/* temperature probe */
#define	SMB_TYPE_IPROBE		29	/* current probe */
#define	SMB_TYPE_OOBRA		30	/* out-of-band remote access facility */
#define	SMB_TYPE_BIS		31	/* boot integrity services */
#define	SMB_TYPE_BOOT		32	/* system boot status (R) */
#define	SMB_TYPE_MEMERR64	33	/* 64-bit memory error information */
#define	SMB_TYPE_MGMTDEV	34	/* management device */
#define	SMB_TYPE_MGMTDEVCP	35	/* management device component */
#define	SMB_TYPE_MGMTDEVDATA	36	/* management device threshold data */
#define	SMB_TYPE_MEMCHAN	37	/* memory channel */
#define	SMB_TYPE_IPMIDEV	38	/* IPMI device information */
#define	SMB_TYPE_POWERSUP	39	/* system power supply */
#define	SMB_TYPE_ADDINFO	40	/* additional information */
#define	SMB_TYPE_OBDEVEXT	41	/* on-board device extended info */
#define	SMB_TYPE_MCHI		42	/* mgmt controller host interface */
#define	SMB_TYPE_TPM		43	/* TPM device */
#define	SMB_TYPE_INACTIVE	126	/* inactive table entry */
#define	SMB_TYPE_EOT		127	/* end of table */

#define	SMB_TYPE_OEM_LO		128	/* start of OEM-specific type range */
#define	SUN_OEM_EXT_PROCESSOR	132	/* processor extended info */
#define	SUN_OEM_EXT_PORT	136	/* port exteded info */
#define	SUN_OEM_PCIEXRC		138	/* PCIE RootComplex/RootPort info */
#define	SUN_OEM_EXT_MEMARRAY	144	/* phys memory array extended info */
#define	SUN_OEM_EXT_MEMDEVICE	145	/* memory device extended info */
#define	SMB_TYPE_OEM_HI		256	/* end of OEM-specific type range */

/*
 * OEM string indicating "Platform Resource Management Specification"
 * compliance.
 */
#define	SMB_PRMS1	"SUNW-PRMS-1"

/*
 * Some default values set by BIOS vendor
 */
#define	SMB_DEFAULT1	"To Be Filled By O.E.M."
#define	SMB_DEFAULT2	"Not Available"

/*
 * SMBIOS Common Information.  These structures do not correspond to anything
 * in the SMBIOS specification, but allow library clients to more easily read
 * information that is frequently encoded into the various SMBIOS structures.
 */
typedef struct smbios_info {
	const char *smbi_manufacturer;	/* manufacturer */
	const char *smbi_product;	/* product name */
	const char *smbi_version;	/* version */
	const char *smbi_serial;	/* serial number */
	const char *smbi_asset;		/* asset tag */
	const char *smbi_location;	/* location tag */
	const char *smbi_part;		/* part number */
} smbios_info_t;

typedef struct smbios_version {
	uint8_t smbv_major;		/* version major number */
	uint8_t smbv_minor;		/* version minor number */
} smbios_version_t;

#define	SMB_CONT_BYTE	1		/* contained elements are byte size */
#define	SMB_CONT_WORD	2		/* contained elements are word size */
#define	SMB_CONT_MAX	255		/* maximum contained objects */

/*
 * SMBIOS Bios Information.  See DSP0134 Section 7.1 for more information.
 * smbb_romsize is converted from the implementation format into bytes. Note, if
 * we do not have an extended BIOS ROM size, it is filled in with the default
 * BIOS ROM size.
 */
typedef struct smbios_bios {
	const char *smbb_vendor;	/* bios vendor string */
	const char *smbb_version;	/* bios version string */
	const char *smbb_reldate;	/* bios release date */
	uint32_t smbb_segment;		/* bios address segment location */
	uint32_t smbb_romsize;		/* bios rom size in bytes */
	uint32_t smbb_runsize;		/* bios image size in bytes */
	uint64_t smbb_cflags;		/* bios characteristics */
	const uint8_t *smbb_xcflags;	/* bios characteristics extensions */
	size_t smbb_nxcflags;		/* number of smbb_xcflags[] bytes */
	smbios_version_t smbb_biosv;	/* bios version */
	smbios_version_t smbb_ecfwv;	/* bios embedded ctrl f/w version */
	uint64_t smbb_extromsize;	/* Extended bios ROM Size */
} smbios_bios_t;

#define	SMB_BIOSFL_RSV0		0x00000001	/* reserved bit zero */
#define	SMB_BIOSFL_RSV1		0x00000002	/* reserved bit one */
#define	SMB_BIOSFL_UNKNOWN	0x00000004	/* unknown */
#define	SMB_BIOSFL_BCNOTSUP	0x00000008	/* BIOS chars not supported */
#define	SMB_BIOSFL_ISA		0x00000010	/* ISA is supported */
#define	SMB_BIOSFL_MCA		0x00000020	/* MCA is supported */
#define	SMB_BIOSFL_EISA		0x00000040	/* EISA is supported */
#define	SMB_BIOSFL_PCI		0x00000080	/* PCI is supported */
#define	SMB_BIOSFL_PCMCIA	0x00000100	/* PCMCIA is supported */
#define	SMB_BIOSFL_PLUGNPLAY	0x00000200	/* Plug and Play is supported */
#define	SMB_BIOSFL_APM		0x00000400	/* APM is supported */
#define	SMB_BIOSFL_FLASH	0x00000800	/* BIOS is Flash Upgradeable */
#define	SMB_BIOSFL_SHADOW	0x00001000	/* BIOS shadowing is allowed */
#define	SMB_BIOSFL_VLVESA	0x00002000	/* VL-VESA is supported */
#define	SMB_BIOSFL_ESCD		0x00004000	/* ESCD support is available */
#define	SMB_BIOSFL_CDBOOT	0x00008000	/* Boot from CD is supported */
#define	SMB_BIOSFL_SELBOOT	0x00010000	/* Selectable Boot supported */
#define	SMB_BIOSFL_ROMSOCK	0x00020000	/* BIOS ROM is socketed */
#define	SMB_BIOSFL_PCMBOOT	0x00040000	/* Boot from PCMCIA supported */
#define	SMB_BIOSFL_EDD		0x00080000	/* EDD Spec is supported */
#define	SMB_BIOSFL_NEC9800	0x00100000	/* int 0x13 NEC 9800 floppy */
#define	SMB_BIOSFL_TOSHIBA	0x00200000	/* int 0x13 Toshiba floppy */
#define	SMB_BIOSFL_525_360K	0x00400000	/* int 0x13 5.25" 360K floppy */
#define	SMB_BIOSFL_525_12M	0x00800000	/* int 0x13 5.25" 1.2M floppy */
#define	SMB_BIOSFL_35_720K	0x01000000	/* int 0x13 3.5" 720K floppy */
#define	SMB_BIOSFL_35_288M	0x02000000	/* int 0x13 3.5" 2.88M floppy */
#define	SMB_BIOSFL_I5_PRINT	0x04000000	/* int 0x5 print screen svcs */
#define	SMB_BIOSFL_I9_KBD	0x08000000	/* int 0x9 8042 keyboard svcs */
#define	SMB_BIOSFL_I14_SER	0x10000000	/* int 0x14 serial svcs */
#define	SMB_BIOSFL_I17_PRINTER	0x20000000	/* int 0x17 printer svcs */
#define	SMB_BIOSFL_I10_CGA	0x40000000	/* int 0x10 CGA svcs */
#define	SMB_BIOSFL_NEC_PC98	0x80000000	/* NEC PC-98 */

/*
 * These values are used to allow consumers to have raw access to the extended
 * characteristic flags. We explicitly don't include the extended BIOS
 * information from section 3.1 as part of this as it has its own member.
 */
#define	SMB_BIOSXB_1		0	/* bios extension byte 1 (7.1.2.1) */
#define	SMB_BIOSXB_2		1	/* bios extension byte 2 (7.1.2.2) */
#define	SMB_BIOSXB_BIOS_MAJ	2	/* bios major version */
#define	SMB_BIOSXB_BIOS_MIN	3	/* bios minor version */
#define	SMB_BIOSXB_ECFW_MAJ	4	/* extended ctlr f/w major version */
#define	SMB_BIOSXB_ECFW_MIN	5	/* extended ctlr f/w minor version */

#define	SMB_BIOSXB1_ACPI	0x01	/* ACPI is supported */
#define	SMB_BIOSXB1_USBL	0x02	/* USB legacy is supported */
#define	SMB_BIOSXB1_AGP		0x04	/* AGP is supported */
#define	SMB_BIOSXB1_I20		0x08	/* I2O boot is supported */
#define	SMB_BIOSXB1_LS120	0x10	/* LS-120 boot is supported */
#define	SMB_BIOSXB1_ATZIP	0x20	/* ATAPI ZIP drive boot is supported */
#define	SMB_BIOSXB1_1394	0x40	/* 1394 boot is supported */
#define	SMB_BIOSXB1_SMBAT	0x80	/* Smart Battery is supported */

#define	SMB_BIOSXB2_BBOOT	0x01	/* BIOS Boot Specification supported */
#define	SMB_BIOSXB2_FKNETSVC	0x02	/* F-key Network Svc boot supported */
#define	SMB_BIOSXB2_ETCDIST	0x04	/* Enable Targeted Content Distrib. */
#define	SMB_BIOSXB2_UEFI	0x08	/* UEFI Specification supported */
#define	SMB_BIOSXB2_VM		0x10	/* SMBIOS table describes a VM */

/*
 * SMBIOS System Information.  See DSP0134 Section 7.2 for more information.
 * The current set of smbs_wakeup values is defined after the structure.
 */
typedef struct smbios_system {
	const uint8_t *smbs_uuid;	/* UUID byte array */
	uint8_t smbs_uuidlen;		/* UUID byte array length */
	uint8_t smbs_wakeup;		/* wake-up event */
	const char *smbs_sku;		/* SKU number */
	const char *smbs_family;	/* family */
} smbios_system_t;

#define	SMB_WAKEUP_RSV0		0x00	/* reserved */
#define	SMB_WAKEUP_OTHER	0x01	/* other */
#define	SMB_WAKEUP_UNKNOWN	0x02	/* unknown */
#define	SMB_WAKEUP_APM		0x03	/* APM timer */
#define	SMB_WAKEUP_MODEM	0x04	/* modem ring */
#define	SMB_WAKEUP_LAN		0x05	/* LAN remote */
#define	SMB_WAKEUP_SWITCH	0x06	/* power switch */
#define	SMB_WAKEUP_PCIPME	0x07	/* PCI PME# */
#define	SMB_WAKEUP_AC		0x08	/* AC power restored */

/*
 * SMBIOS Base Board description.  See DSP0134 Section 7.3 for more
 * information.  smbb_flags and smbb_type definitions are below.
 */
typedef struct smbios_bboard {
	id_t smbb_chassis;		/* chassis containing this board */
	uint8_t smbb_flags;		/* flags (see below) */
	uint8_t smbb_type;		/* board type (see below) */
	uint8_t smbb_contn;		/* number of contained object hdls */
} smbios_bboard_t;

#define	SMB_BBFL_MOTHERBOARD	0x01	/* board is a motherboard */
#define	SMB_BBFL_NEEDAUX	0x02	/* auxiliary card or daughter req'd */
#define	SMB_BBFL_REMOVABLE	0x04	/* board is removable */
#define	SMB_BBFL_REPLACABLE	0x08	/* board is field-replacable */
#define	SMB_BBFL_HOTSWAP	0x10	/* board is hot-swappable */

#define	SMB_BBT_UNKNOWN		0x1	/* unknown */
#define	SMB_BBT_OTHER		0x2	/* other */
#define	SMB_BBT_SBLADE		0x3	/* server blade */
#define	SMB_BBT_CSWITCH		0x4	/* connectivity switch */
#define	SMB_BBT_SMM		0x5	/* system management module */
#define	SMB_BBT_PROC		0x6	/* processor module */
#define	SMB_BBT_IO		0x7	/* i/o module */
#define	SMB_BBT_MEM		0x8	/* memory module */
#define	SMB_BBT_DAUGHTER	0x9	/* daughterboard */
#define	SMB_BBT_MOTHER		0xA	/* motherboard */
#define	SMB_BBT_PROCMEM		0xB	/* processor/memory module */
#define	SMB_BBT_PROCIO		0xC	/* processor/i/o module */
#define	SMB_BBT_INTER		0xD	/* interconnect board */

/*
 * SMBIOS Chassis description.  See DSP0134 Section 7.4 for more information.
 * We move the lock bit of the type field into smbc_lock for easier processing.
 */
typedef struct smbios_chassis {
	uint32_t smbc_oemdata;		/* OEM-specific data */
	uint8_t smbc_lock;		/* lock present? */
	uint8_t smbc_type;		/* type */
	uint8_t smbc_bustate;		/* boot-up state */
	uint8_t smbc_psstate;		/* power supply state */
	uint8_t smbc_thstate;		/* thermal state */
	uint8_t smbc_security;		/* security status */
	uint8_t smbc_uheight;		/* enclosure height in U's */
	uint8_t smbc_cords;		/* number of power cords */
	uint8_t smbc_elems;		/* number of element records (n) */
	uint8_t smbc_elemlen;		/* length of contained element (m) */
	char smbc_sku[256];		/* SKU number (as a string) */
} smbios_chassis_t;

#define	SMB_CHT_OTHER		0x01	/* other */
#define	SMB_CHT_UNKNOWN		0x02	/* unknown */
#define	SMB_CHT_DESKTOP		0x03	/* desktop */
#define	SMB_CHT_LPDESKTOP	0x04	/* low-profile desktop */
#define	SMB_CHT_PIZZA		0x05	/* pizza box */
#define	SMB_CHT_MINITOWER	0x06	/* mini-tower */
#define	SMB_CHT_TOWER		0x07	/* tower */
#define	SMB_CHT_PORTABLE	0x08	/* portable */
#define	SMB_CHT_LAPTOP		0x09	/* laptop */
#define	SMB_CHT_NOTEBOOK	0x0A	/* notebook */
#define	SMB_CHT_HANDHELD	0x0B	/* hand-held */
#define	SMB_CHT_DOCK		0x0C	/* docking station */
#define	SMB_CHT_ALLIN1		0x0D	/* all-in-one */
#define	SMB_CHT_SUBNOTE		0x0E	/* sub-notebook */
#define	SMB_CHT_SPACESAVE	0x0F	/* space-saving */
#define	SMB_CHT_LUNCHBOX	0x10	/* lunchbox */
#define	SMB_CHT_MAIN		0x11	/* main server chassis */
#define	SMB_CHT_EXPANSION	0x12	/* expansion chassis */
#define	SMB_CHT_SUB		0x13	/* sub-chassis */
#define	SMB_CHT_BUS		0x14	/* bus expansion chassis */
#define	SMB_CHT_PERIPHERAL	0x15	/* peripheral chassis */
#define	SMB_CHT_RAID		0x16	/* raid chassis */
#define	SMB_CHT_RACK		0x17	/* rack mount chassis */
#define	SMB_CHT_SEALED		0x18	/* sealed case pc */
#define	SMB_CHT_MULTI		0x19	/* multi-system chassis */
#define	SMB_CHT_CPCI		0x1A	/* compact PCI */
#define	SMB_CHT_ATCA		0x1B	/* advanced TCA */
#define	SMB_CHT_BLADE		0x1C	/* blade */
#define	SMB_CHT_BLADEENC	0x1D	/* blade enclosure */
#define	SMB_CHT_TABLET		0x1E	/* tablet */
#define	SMB_CHT_CONVERTIBLE	0x1F	/* convertible */
#define	SMB_CHT_DETACHABLE	0x20	/* detachable */
#define	SMB_CHT_IOTGW		0x21	/* IoT Gateway */
#define	SMB_CHT_EMBEDPC		0x22	/* Embedded PC */
#define	SMB_CHT_MINIPC		0x23	/* Mini PC */
#define	SMB_CHT_STICKPC		0x24	/* Stick PC */

#define	SMB_CHST_OTHER		0x01	/* other */
#define	SMB_CHST_UNKNOWN	0x02	/* unknown */
#define	SMB_CHST_SAFE		0x03	/* safe */
#define	SMB_CHST_WARNING	0x04	/* warning */
#define	SMB_CHST_CRITICAL	0x05	/* critical */
#define	SMB_CHST_NONREC		0x06	/* non-recoverable */

#define	SMB_CHSC_OTHER		0x01	/* other */
#define	SMB_CHSC_UNKNOWN	0x02	/* unknown */
#define	SMB_CHSC_NONE		0x03	/* none */
#define	SMB_CHSC_EILOCK		0x04	/* external interface locked out */
#define	SMB_CHSC_EIENAB		0x05	/* external interface enabled */

/*
 * SMBIOS Processor description.  See DSP0134 Section 7.5 for more details.
 * If the L1, L2, or L3 cache handle is -1, the cache information is unknown.
 * If the handle refers to something of size 0, that type of cache is absent.
 *
 * NOTE: Although SMBIOS exports a 64-bit CPUID result, this value should not
 * be used for any purpose other than BIOS debugging.  illumos itself computes
 * its own CPUID value and applies knowledge of additional errata and processor
 * specific CPUID variations, so this value should not be used for anything.
 */
typedef struct smbios_processor {
	uint64_t smbp_cpuid;		/* processor cpuid information */
	uint32_t smbp_family;		/* processor family */
	uint8_t smbp_type;		/* processor type (SMB_PRT_*) */
	uint8_t smbp_voltage;		/* voltage (SMB_PRV_*) */
	uint8_t smbp_status;		/* status (SMB_PRS_*) */
	uint8_t smbp_upgrade;		/* upgrade (SMB_PRU_*) */
	uint32_t smbp_clkspeed;		/* external clock speed in MHz */
	uint32_t smbp_maxspeed;		/* maximum speed in MHz */
	uint32_t smbp_curspeed;		/* current speed in MHz */
	id_t smbp_l1cache;		/* L1 cache handle */
	id_t smbp_l2cache;		/* L2 cache handle */
	id_t smbp_l3cache;		/* L3 cache handle */
	uint32_t smbp_corecount;
		/* number of cores per processor socket */
	uint32_t smbp_coresenabled;
		/* number of enabled cores per processor socket */
	uint32_t smbp_threadcount;
		/* number of threads per processor socket */
	uint16_t smbp_cflags;
		/* processor characteristics (SMB_PRC_*) */
	uint16_t smbp_family2;		/* processor family 2 */
	uint16_t smbp_corecount2;	/* core count 2 */
	uint16_t smbp_coresenabled2;	/* cores enabled 2 */
	uint16_t smbp_threadcount2;	/* thread count 2 */
} smbios_processor_t;

#define	SMB_PRT_OTHER		0x01	/* other */
#define	SMB_PRT_UNKNOWN		0x02	/* unknown */
#define	SMB_PRT_CENTRAL		0x03	/* central processor */
#define	SMB_PRT_MATH		0x04	/* math processor */
#define	SMB_PRT_DSP		0x05	/* DSP processor */
#define	SMB_PRT_VIDEO		0x06	/* video processor */

#define	SMB_PRV_LEGACY(v)	(!((v) & 0x80))	/* legacy voltage mode */
#define	SMB_PRV_FIXED(v)	((v) & 0x80)	/* fixed voltage mode */

#define	SMB_PRV_5V		0x01	/* 5V is supported */
#define	SMB_PRV_33V		0x02	/* 3.3V is supported */
#define	SMB_PRV_29V		0x04	/* 2.9V is supported */

#define	SMB_PRV_VOLTAGE(v)	((v) & 0x7f)

#define	SMB_PRSTATUS_PRESENT(s)	((s) & 0x40)	/* socket is populated */
#define	SMB_PRSTATUS_STATUS(s)	((s) & 0x07)	/* status (see below) */

#define	SMB_PRS_UNKNOWN		0x0	/* unknown */
#define	SMB_PRS_ENABLED		0x1	/* enabled */
#define	SMB_PRS_BDISABLED	0x2	/* disabled in bios user setup */
#define	SMB_PRS_PDISABLED	0x3	/* disabled in bios from post error */
#define	SMB_PRS_IDLE		0x4	/* waiting to be enabled */
#define	SMB_PRS_OTHER		0x7	/* other */

#define	SMB_PRU_OTHER		0x01	/* other */
#define	SMB_PRU_UNKNOWN		0x02	/* unknown */
#define	SMB_PRU_DAUGHTER	0x03	/* daughter board */
#define	SMB_PRU_ZIF		0x04	/* ZIF socket */
#define	SMB_PRU_PIGGY		0x05	/* replaceable piggy back */
#define	SMB_PRU_NONE		0x06	/* none */
#define	SMB_PRU_LIF		0x07	/* LIF socket */
#define	SMB_PRU_SLOT1		0x08	/* slot 1 */
#define	SMB_PRU_SLOT2		0x09	/* slot 2 */
#define	SMB_PRU_370PIN		0x0A	/* 370-pin socket */
#define	SMB_PRU_SLOTA		0x0B	/* slot A */
#define	SMB_PRU_SLOTM		0x0C	/* slot M */
#define	SMB_PRU_423		0x0D	/* socket 423 */
#define	SMB_PRU_A		0x0E	/* socket A (socket 462) */
#define	SMB_PRU_478		0x0F	/* socket 478 */
#define	SMB_PRU_754		0x10	/* socket 754 */
#define	SMB_PRU_940		0x11	/* socket 940 */
#define	SMB_PRU_939		0x12	/* socket 939 */
#define	SMB_PRU_MPGA604		0x13	/* mPGA604 */
#define	SMB_PRU_LGA771		0x14	/* LGA771 */
#define	SMB_PRU_LGA775		0x15	/* LGA775 */
#define	SMB_PRU_S1		0x16	/* socket S1 */
#define	SMB_PRU_AM2		0x17	/* socket AM2 */
#define	SMB_PRU_F		0x18	/* socket F */
#define	SMB_PRU_LGA1366		0x19	/* LGA1366 */
#define	SMB_PRU_G34		0x1A	/* socket G34 */
#define	SMB_PRU_AM3		0x1B	/* socket AM3 */
#define	SMB_PRU_C32		0x1C	/* socket C32 */
#define	SMB_PRU_LGA1156		0x1D	/* LGA1156 */
#define	SMB_PRU_LGA1567		0x1E	/* LGA1567 */
#define	SMB_PRU_PGA988A		0x1F	/* PGA988A */
#define	SMB_PRU_BGA1288		0x20	/* BGA1288 */
#define	SMB_PRU_RPGA988B	0x21	/* rPGA988B */
#define	SMB_PRU_BGA1023		0x22	/* BGA1023 */
#define	SMB_PRU_BGA1224		0x23	/* BGA1224 */
#define	SMB_PRU_LGA1155		0x24	/* LGA1155 */
#define	SMB_PRU_LGA1356		0x25	/* LGA1356 */
#define	SMB_PRU_LGA2011		0x26	/* LGA2011 */
#define	SMB_PRU_FS1		0x27	/* socket FS1 */
#define	SMB_PRU_FS2		0x28	/* socket FS2 */
#define	SMB_PRU_FM1		0x29	/* socket FM1 */
#define	SMB_PRU_FM2		0x2A	/* socket FM2 */
#define	SMB_PRU_LGA20113	0x2B	/* LGA2011-3 */
#define	SMB_PRU_LGA13563	0x2C	/* LGA1356-3 */
#define	SMB_PRU_LGA1150		0x2D	/* LGA1150 */
#define	SMB_PRU_BGA1168		0x2E	/* BGA1168 */
#define	SMB_PRU_BGA1234		0x2F	/* BGA1234 */
#define	SMB_PRU_BGA1364		0x30	/* BGA1364 */
#define	SMB_PRU_AM4		0x31	/* socket AM4 */
#define	SMB_PRU_LGA1151		0x32	/* LGA1151 */
#define	SMB_PRU_BGA1356		0x33	/* BGA1356 */
#define	SMB_PRU_BGA1440		0x34	/* BGA1440 */
#define	SMB_PRU_BGA1515		0x35	/* BGA1515 */
#define	SMB_PRU_LGA36471	0x36	/* LGA3647-1 */
#define	SMB_PRU_SP3		0x37	/* socket SP3 */
#define	SMB_PRU_SP3r2		0x38	/* socket SP3r2 */

#define	SMB_PRC_RESERVED	0x0001	/* reserved */
#define	SMB_PRC_UNKNOWN		0x0002	/* unknown */
#define	SMB_PRC_64BIT		0x0004	/* 64-bit capable */
#define	SMB_PRC_MC		0x0008	/* multi-core */
#define	SMB_PRC_HT		0x0010	/* hardware thread */
#define	SMB_PRC_NX		0x0020	/* execution protection */
#define	SMB_PRC_VT		0x0040	/* enhanced virtualization */
#define	SMB_PRC_PM		0x0080	/* power/performance control */

#define	SMB_PRF_OTHER		0x01	/* other */
#define	SMB_PRF_UNKNOWN		0x02	/* unknown */
#define	SMB_PRF_8086		0x03	/* 8086 */
#define	SMB_PRF_80286		0x04	/* 80286 */
#define	SMB_PRF_I386		0x05	/* Intel 386 */
#define	SMB_PRF_I486		0x06	/* Intel 486 */
#define	SMB_PRF_8087		0x07	/* 8087 */
#define	SMB_PRF_80287		0x08	/* 80287 */
#define	SMB_PRF_80387		0x09	/* 80387 */
#define	SMB_PRF_80487		0x0A	/* 80487 */
#define	SMB_PRF_PENTIUM		0x0B	/* Pentium Family */
#define	SMB_PRF_PENTIUMPRO	0x0C	/* Pentium Pro */
#define	SMB_PRF_PENTIUMII	0x0D	/* Pentium II */
#define	SMB_PRF_PENTIUM_MMX	0x0E	/* Pentium w/ MMX */
#define	SMB_PRF_CELERON		0x0F	/* Celeron */
#define	SMB_PRF_PENTIUMII_XEON	0x10	/* Pentium II Xeon */
#define	SMB_PRF_PENTIUMIII	0x11	/* Pentium III */
#define	SMB_PRF_M1		0x12	/* M1 */
#define	SMB_PRF_M2		0x13	/* M2 */
#define	SMB_PRF_CELERON_M	0x14	/* Celeron M */
#define	SMB_PRF_PENTIUMIV_HT	0x15	/* Pentium 4 HT */
#define	SMB_PRF_DURON		0x18	/* AMD Duron */
#define	SMB_PRF_K5		0x19	/* K5 */
#define	SMB_PRF_K6		0x1A	/* K6 */
#define	SMB_PRF_K6_2		0x1B	/* K6-2 */
#define	SMB_PRF_K6_3		0x1C	/* K6-3 */
#define	SMB_PRF_ATHLON		0x1D	/* Athlon */
#define	SMB_PRF_2900		0x1E	/* AMD 2900 */
#define	SMB_PRF_K6_2PLUS	0x1F	/* K6-2+ */
#define	SMB_PRF_PPC		0x20	/* PowerPC */
#define	SMB_PRF_PPC_601		0x21	/* PowerPC 601 */
#define	SMB_PRF_PPC_603		0x22	/* PowerPC 603 */
#define	SMB_PRF_PPC_603PLUS	0x23	/* PowerPC 603+ */
#define	SMB_PRF_PPC_604		0x24	/* PowerPC 604 */
#define	SMB_PRF_PPC_620		0x25	/* PowerPC 620 */
#define	SMB_PRF_PPC_704		0x26	/* PowerPC x704 */
#define	SMB_PRF_PPC_750		0x27	/* PowerPC 750 */
#define	SMB_PRF_CORE_DUO	0x28	/* Core Duo */
#define	SMB_PRF_CORE_DUO_M	0x29	/* Core Duo mobile */
#define	SMB_PRF_CORE_SOLO_M	0x2A	/* Core Solo mobile */
#define	SMB_PRF_ATOM		0x2B	/* Intel Atom */
#define	SMB_PRF_CORE_M		0x2C	/* Intel Core M */
#define	SMB_PRF_CORE_M3		0x2D	/* Intel Core m3 */
#define	SMB_PRF_CORE_M5		0x2E	/* Intel Core m5 */
#define	SMB_PRF_CORE_M7		0x2F	/* Intel Core m7 */
#define	SMB_PRF_ALPHA		0x30	/* Alpha */
#define	SMB_PRF_ALPHA_21064	0x31	/* Alpha 21064 */
#define	SMB_PRF_ALPHA_21066	0x32	/* Alpha 21066 */
#define	SMB_PRF_ALPHA_21164	0x33	/* Alpha 21164 */
#define	SMB_PRF_ALPHA_21164PC	0x34	/* Alpha 21164PC */
#define	SMB_PRF_ALPHA_21164A	0x35	/* Alpha 21164a */
#define	SMB_PRF_ALPHA_21264	0x36	/* Alpha 21264 */
#define	SMB_PRF_ALPHA_21364	0x37	/* Alpha 21364 */
#define	SMB_PRF_TURION2U_2C_MM	0x38
			/* AMD Turion II Ultra Dual-Core Mobile M */
#define	SMB_PRF_TURION2_2C_MM	0x39	/* AMD Turion II Dual-Core Mobile M */
#define	SMB_PRF_ATHLON2_2C_M	0x3A	/* AMD Athlon II Dual-Core M */
#define	SMB_PRF_OPTERON_6100	0x3B	/* AMD Opteron 6100 series */
#define	SMB_PRF_OPTERON_4100	0x3C	/* AMD Opteron 4100 series */
#define	SMB_PRF_OPTERON_6200	0x3D	/* AMD Opteron 6200 series */
#define	SMB_PRF_OPTERON_4200	0x3E	/* AMD Opteron 4200 series */
#define	SMB_PRF_AMD_FX		0x3F	/* AMD FX series */
#define	SMB_PRF_MIPS		0x40	/* MIPS */
#define	SMB_PRF_MIPS_R4000	0x41	/* MIPS R4000 */
#define	SMB_PRF_MIPS_R4200	0x42	/* MIPS R4200 */
#define	SMB_PRF_MIPS_R4400	0x43	/* MIPS R4400 */
#define	SMB_PRF_MIPS_R4600	0x44	/* MIPS R4600 */
#define	SMB_PRF_MIPS_R10000	0x45	/* MIPS R10000 */
#define	SMB_PRF_AMD_C		0x46	/* AMD C-series */
#define	SMB_PRF_AMD_E		0x47	/* AMD E-series */
#define	SMB_PRF_AMD_A		0x48	/* AMD A-series */
#define	SMB_PRF_AMD_G		0x49	/* AMD G-series */
#define	SMB_PRF_AMD_Z		0x4A	/* AMD Z-series */
#define	SMB_PRF_AMD_R		0x4B	/* AMD R-series */
#define	SMB_PRF_OPTERON_4300	0x4C	/* AMD Opteron 4300 series */
#define	SMB_PRF_OPTERON_6300	0x4D	/* AMD Opteron 6300 series */
#define	SMB_PRF_OPTERON_3300	0x4E	/* AMD Opteron 3300 series */
#define	SMB_PRF_AMD_FIREPRO	0x4F	/* AMD FirePro series */
#define	SMB_PRF_SPARC		0x50	/* SPARC */
#define	SMB_PRF_SUPERSPARC	0x51	/* SuperSPARC */
#define	SMB_PRF_MICROSPARCII	0x52	/* microSPARC II */
#define	SMB_PRF_MICROSPARCIIep	0x53	/* microSPARC IIep */
#define	SMB_PRF_ULTRASPARC	0x54	/* UltraSPARC */
#define	SMB_PRF_USII		0x55	/* UltraSPARC II */
#define	SMB_PRF_USIIi		0x56	/* UltraSPARC IIi */
#define	SMB_PRF_USIII		0x57	/* UltraSPARC III */
#define	SMB_PRF_USIIIi		0x58	/* UltraSPARC IIIi */
#define	SMB_PRF_68040		0x60	/* 68040 */
#define	SMB_PRF_68XXX		0x61	/* 68XXX */
#define	SMB_PRF_68000		0x62	/* 68000 */
#define	SMB_PRF_68010		0x63	/* 68010 */
#define	SMB_PRF_68020		0x64	/* 68020 */
#define	SMB_PRF_68030		0x65	/* 68030 */
#define	SMB_PRF_ATHLON_X4	0x66	/* AMD Athlon X4 Quad-Core */
#define	SMB_PRF_OPTERON_X1K	0x67	/* AMD Opteron X1000 */
#define	SMB_PRF_OPTERON_X2K	0x68	/* AMD Opteron X2000 APU */
#define	SMB_PRF_OPTERON_A	0x69	/* AMD Opteron A Series */
#define	SMB_PRF_OPTERON_X3K	0x6A	/* AMD Opteron X3000 APU */
#define	SMB_PRF_ZEN		0x6B	/* AMD Zen Processor Family */
#define	SMB_PRF_HOBBIT		0x70	/* Hobbit */
#define	SMB_PRF_TM5000		0x78	/* Crusoe TM5000 */
#define	SMB_PRF_TM3000		0x79	/* Crusoe TM3000 */
#define	SMB_PRF_TM8000		0x7A	/* Efficeon TM8000 */
#define	SMB_PRF_WEITEK		0x80	/* Weitek */
#define	SMB_PRF_ITANIC		0x82	/* Itanium */
#define	SMB_PRF_ATHLON64	0x83	/* Athlon64 */
#define	SMB_PRF_OPTERON		0x84	/* Opteron */
#define	SMB_PRF_SEMPRON		0x85    /* Sempron */
#define	SMB_PRF_TURION64_M	0x86	/* Turion 64 Mobile */
#define	SMB_PRF_OPTERON_2C	0x87	/* AMD Opteron Dual-Core */
#define	SMB_PRF_ATHLON64_X2_2C	0x88	/* AMD Athlon 64 X2 Dual-Core */
#define	SMB_PRF_TURION64_X2_M	0x89	/* AMD Turion 64 X2 Mobile */
#define	SMB_PRF_OPTERON_4C	0x8A	/* AMD Opteron Quad-Core */
#define	SMB_PRF_OPTERON_3G	0x8B	/* AMD Opteron 3rd Generation */
#define	SMB_PRF_PHENOM_FX_4C	0x8C	/* AMD Phenom FX Quad-Core */
#define	SMB_PRF_PHENOM_X4_4C	0x8D	/* AMD Phenom X4 Quad-Core */
#define	SMB_PRF_PHENOM_X2_2C	0x8E	/* AMD Phenom X2 Dual-Core */
#define	SMB_PRF_ATHLON_X2_2C	0x8F	/* AMD Athlon X2 Dual-Core */
#define	SMB_PRF_PA		0x90	/* PA-RISC */
#define	SMB_PRF_PA8500		0x91	/* PA-RISC 8500 */
#define	SMB_PRF_PA8000		0x92	/* PA-RISC 8000 */
#define	SMB_PRF_PA7300LC	0x93	/* PA-RISC 7300LC */
#define	SMB_PRF_PA7200		0x94	/* PA-RISC 7200 */
#define	SMB_PRF_PA7100LC	0x95	/* PA-RISC 7100LC */
#define	SMB_PRF_PA7100		0x96	/* PA-RISC 7100 */
#define	SMB_PRF_V30		0xA0	/* V30 */
#define	SMB_PRF_XEON_4C_3200	0xA1	/* Xeon Quad Core 3200 */
#define	SMB_PRF_XEON_2C_3000	0xA2	/* Xeon Dual Core 3000 */
#define	SMB_PRF_XEON_4C_5300	0xA3	/* Xeon Quad Core 5300 */
#define	SMB_PRF_XEON_2C_5100	0xA4	/* Xeon Dual Core 5100 */
#define	SMB_PRF_XEON_2C_5000	0xA5	/* Xeon Dual Core 5000 */
#define	SMB_PRF_XEON_2C_LV	0xA6	/* Xeon Dual Core LV */
#define	SMB_PRF_XEON_2C_ULV	0xA7	/* Xeon Dual Core ULV */
#define	SMB_PRF_XEON_2C_7100	0xA8	/* Xeon Dual Core 7100 */
#define	SMB_PRF_XEON_4C_5400	0xA9	/* Xeon Quad Core 5400 */
#define	SMB_PRF_XEON_4C		0xAA	/* Xeon Quad Core */
#define	SMB_PRF_XEON_2C_5200	0xAB	/* Xeon Dual Core 5200 */
#define	SMB_PRF_XEON_2C_7200	0xAC	/* Xeon Dual Core 7200 */
#define	SMB_PRF_XEON_4C_7300	0xAD	/* Xeon Quad Core 7300 */
#define	SMB_PRF_XEON_4C_7400	0xAE	/* Xeon Quad Core 7400 */
#define	SMB_PRF_XEON_XC_7400	0xAF	/* Xeon Multi Core 7400 */
#define	SMB_PRF_PENTIUMIII_XEON	0xB0	/* Pentium III Xeon */
#define	SMB_PRF_PENTIUMIII_SS	0xB1	/* Pentium III with SpeedStep */
#define	SMB_PRF_P4		0xB2	/* Pentium 4 */
#define	SMB_PRF_XEON		0xB3	/* Intel Xeon */
#define	SMB_PRF_AS400		0xB4	/* AS400 */
#define	SMB_PRF_XEON_MP		0xB5	/* Intel Xeon MP */
#define	SMB_PRF_ATHLON_XP	0xB6	/* AMD Athlon XP */
#define	SMB_PRF_ATHLON_MP	0xB7	/* AMD Athlon MP */
#define	SMB_PRF_ITANIC2		0xB8	/* Itanium 2 */
#define	SMB_PRF_PENTIUM_M	0xB9	/* Pentium M */
#define	SMB_PRF_CELERON_D	0xBA	/* Celeron D */
#define	SMB_PRF_PENTIUM_D	0xBB	/* Pentium D */
#define	SMB_PRF_PENTIUM_EE	0xBC	/* Pentium Extreme Edition */
#define	SMB_PRF_CORE_SOLO	0xBD	/* Intel Core Solo */
#define	SMB_PRF_CORE2_DUO	0xBF	/* Intel Core 2 Duo */
#define	SMB_PRF_CORE2_SOLO	0xC0	/* Intel Core 2 Solo */
#define	SMB_PRF_CORE2_EX	0xC1	/* Intel Core 2 Extreme */
#define	SMB_PRF_CORE2_QUAD	0xC2	/* Intel Core 2 Quad */
#define	SMB_PRF_CORE2_EX_M	0xC3	/* Intel Core 2 Extreme mobile */
#define	SMB_PRF_CORE2_DUO_M	0xC4	/* Intel Core 2 Duo mobile */
#define	SMB_PRF_CORE2_SOLO_M	0xC5	/* Intel Core 2 Solo mobile */
#define	SMB_PRF_CORE_I7		0xC6	/* Intel Core i7 */
#define	SMB_PRF_CELERON_2C	0xC7	/* Celeron Dual-Core */
#define	SMB_PRF_IBM390		0xC8	/* IBM 390 */
#define	SMB_PRF_G4		0xC9	/* G4 */
#define	SMB_PRF_G5		0xCA	/* G5 */
#define	SMB_PRF_ESA390		0xCB	/* ESA390 */
#define	SMB_PRF_ZARCH		0xCC	/* z/Architecture */
#define	SMB_PRF_CORE_I5		0xCD	/* Intel Core i5 */
#define	SMB_PRF_CORE_I3		0xCE	/* Intel Core i3 */
#define	SMB_PRF_C7M		0xD2	/* VIA C7-M */
#define	SMB_PRF_C7D		0xD3	/* VIA C7-D */
#define	SMB_PRF_C7		0xD4	/* VIA C7 */
#define	SMB_PRF_EDEN		0xD5	/* VIA Eden */
#define	SMB_PRF_XEON_XC		0xD6	/* Intel Xeon Multi-Core */
#define	SMB_PRF_XEON_2C_3XXX	0xD7	/* Intel Xeon Dual-Core 3xxx */
#define	SMB_PRF_XEON_4C_3XXX	0xD8	/* Intel Xeon Quad-Core 3xxx */
#define	SMB_PRF_VIA_NANO	0xD9	/* VIA Nano */
#define	SMB_PRF_XEON_2C_5XXX	0xDA	/* Intel Xeon Dual-Core 5xxx */
#define	SMB_PRF_XEON_4C_5XXX	0xDB	/* Intel Xeon Quad-Core 5xxx */
#define	SMB_PRF_XEON_2C_7XXX	0xDD	/* Intel Xeon Dual-Core 7xxx */
#define	SMB_PRF_XEON_4C_7XXX	0xDE	/* Intel Xeon Quad-Core 7xxx */
#define	SMB_PRF_XEON_XC_7XXX	0xDF	/* Intel Xeon Multi-Core 7xxx */
#define	SMB_PRF_XEON_XC_3400	0xE0	/* Intel Xeon Multi-Core 3400 */
#define	SMB_PRF_OPTERON_3000	0xE4	/* AMD Opteron 3000 */
#define	SMB_PRF_SEMPRON_II	0xE5	/* AMD Sempron II */
#define	SMB_PRF_OPTERON_4C_EM	0xE6	/* AMD Opteron Quad-Core embedded */
#define	SMB_PRF_PHENOM_3C	0xE7	/* AMD Phenom Triple-Core */
#define	SMB_PRF_TURIONU_2C_M	0xE8	/* AMD Turion Ultra Dual-Core mobile */
#define	SMB_PRF_TURION_2C_M	0xE9	/* AMD Turion Dual-Core mobile */
#define	SMB_PRF_ATHLON_2C	0xEA	/* AMD Athlon Dual-Core */
#define	SMB_PRF_SEMPRON_SI	0xEB	/* AMD Sempron SI */
#define	SMB_PRF_PHENOM_II	0xEC	/* AMD Phenom II */
#define	SMB_PRF_ATHLON_II	0xED	/* AMD Athlon II */
#define	SMB_PRF_OPTERON_6C	0xEE	/* AMD Opteron Six-Core */
#define	SMB_PRF_SEMPRON_M	0xEF	/* AMD Sempron M */
#define	SMB_PRF_I860		0xFA	/* i860 */
#define	SMB_PRF_I960		0xFB	/* i960 */
#define	SMB_PRF_ARMv7		0x100	/* ARMv7 */
#define	SMB_PRF_ARMv8		0x101	/* ARMv8 */
#define	SMB_PRF_SH3		0x104	/* SH-3 */
#define	SMB_PRF_SH4		0x105	/* SH-4 */
#define	SMB_PRF_ARM		0x118	/* ARM */
#define	SMB_PRF_SARM		0x119	/* StrongARM */
#define	SMB_PRF_6X86		0x12C	/* 6x86 */
#define	SMB_PRF_MEDIAGX		0x12D	/* MediaGX */
#define	SMB_PRF_MII		0x12E	/* MII */
#define	SMB_PRF_WINCHIP		0x140	/* WinChip */
#define	SMB_PRF_DSP		0x15E	/* DSP */
#define	SMB_PRF_VIDEO		0x1F4	/* Video Processor */

/*
 * SMBIOS Cache Information.  See DSP0134 Section 7.8 for more information.
 * If smba_size is zero, this indicates the specified cache is not present.
 *
 * SMBIOS 3.1 added extended cache sizes. Unfortunately, we had already baked in
 * the uint32_t sizes, so we added extended uint64_t's that correspond to the
 * new fields. To make life easier for consumers, we always make sure that the
 * _maxsize2 and _size2 members are filled in with the old value if no other
 * value is present.
 */
typedef struct smbios_cache {
	uint32_t smba_maxsize;		/* maximum installed size in bytes */
	uint32_t smba_size;		/* installed size in bytes */
	uint16_t smba_stype;		/* supported SRAM types (SMB_CAT_*) */
	uint16_t smba_ctype;		/* current SRAM type (SMB_CAT_*) */
	uint8_t smba_speed;		/* speed in nanoseconds */
	uint8_t smba_etype;		/* error correction type (SMB_CAE_*) */
	uint8_t smba_ltype;		/* logical cache type (SMB_CAG_*) */
	uint8_t smba_assoc;		/* associativity (SMB_CAA_*) */
	uint8_t smba_level;		/* cache level */
	uint8_t smba_mode;		/* cache mode (SMB_CAM_*) */
	uint8_t smba_location;		/* cache location (SMB_CAL_*) */
	uint8_t smba_flags;		/* cache flags (SMB_CAF_*) */
	uint64_t smba_maxsize2;		/* maximum installed size in bytes */
	uint64_t smba_size2;		/* installed size in bytes */
} smbios_cache_t;

#define	SMB_CAT_OTHER		0x0001		/* other */
#define	SMB_CAT_UNKNOWN		0x0002		/* unknown */
#define	SMB_CAT_NONBURST	0x0004		/* non-burst */
#define	SMB_CAT_BURST		0x0008		/* burst */
#define	SMB_CAT_PBURST		0x0010		/* pipeline burst */
#define	SMB_CAT_SYNC		0x0020		/* synchronous */
#define	SMB_CAT_ASYNC		0x0040		/* asynchronous */

#define	SMB_CAE_OTHER		0x01		/* other */
#define	SMB_CAE_UNKNOWN		0x02		/* unknown */
#define	SMB_CAE_NONE		0x03		/* none */
#define	SMB_CAE_PARITY		0x04		/* parity */
#define	SMB_CAE_SBECC		0x05		/* single-bit ECC */
#define	SMB_CAE_MBECC		0x06		/* multi-bit ECC */

#define	SMB_CAG_OTHER		0x01		/* other */
#define	SMB_CAG_UNKNOWN		0x02		/* unknown */
#define	SMB_CAG_INSTR		0x03		/* instruction */
#define	SMB_CAG_DATA		0x04		/* data */
#define	SMB_CAG_UNIFIED		0x05		/* unified */

#define	SMB_CAA_OTHER		0x01		/* other */
#define	SMB_CAA_UNKNOWN		0x02		/* unknown */
#define	SMB_CAA_DIRECT		0x03		/* direct mapped */
#define	SMB_CAA_2WAY		0x04		/* 2-way set associative */
#define	SMB_CAA_4WAY		0x05		/* 4-way set associative */
#define	SMB_CAA_FULL		0x06		/* fully associative */
#define	SMB_CAA_8WAY		0x07		/* 8-way set associative */
#define	SMB_CAA_16WAY		0x08		/* 16-way set associative */
#define	SMB_CAA_12WAY		0x09		/* 12-way set associative */
#define	SMB_CAA_24WAY		0x0A		/* 24-way set associative */
#define	SMB_CAA_32WAY		0x0B		/* 32-way set associative */
#define	SMB_CAA_48WAY		0x0C		/* 48-way set associative */
#define	SMB_CAA_64WAY		0x0D		/* 64-way set associative */
#define	SMB_CAA_20WAY		0x0E		/* 20-way set associative */

#define	SMB_CAM_WT		0x00		/* write-through */
#define	SMB_CAM_WB		0x01		/* write-back */
#define	SMB_CAM_VARY		0x02		/* varies by address */
#define	SMB_CAM_UNKNOWN		0x03		/* unknown */

#define	SMB_CAL_INTERNAL	0x00		/* internal */
#define	SMB_CAL_EXTERNAL	0x01		/* external */
#define	SMB_CAL_RESERVED	0x02		/* reserved */
#define	SMB_CAL_UNKNOWN		0x03		/* unknown */

#define	SMB_CAF_ENABLED		0x01		/* enabled at boot time */
#define	SMB_CAF_SOCKETED	0x02		/* cache is socketed */

/*
 * SMBIOS Port Information.  See DSP0134 Section 7.9 for more information.
 * The internal reference designator string is also mapped to the location.
 */
typedef struct smbios_port {
	const char *smbo_iref;	/* internal reference designator */
	const char *smbo_eref;	/* external reference designator */
	uint8_t smbo_itype;	/* internal connector type (SMB_POC_*) */
	uint8_t smbo_etype;	/* external connector type (SMB_POC_*) */
	uint8_t smbo_ptype;	/* port type (SMB_POT_*) */
	uint8_t smbo_pad;	/* padding */
} smbios_port_t;

#define	SMB_POC_NONE		0x00		/* none */
#define	SMB_POC_CENT		0x01		/* Centronics */
#define	SMB_POC_MINICENT	0x02		/* Mini-Centronics */
#define	SMB_POC_PROPRIETARY	0x03		/* proprietary */
#define	SMB_POC_DB25M		0x04		/* DB-25 pin male */
#define	SMB_POC_DB25F		0x05		/* DB-25 pin female */
#define	SMB_POC_DB15M		0x06		/* DB-15 pin male */
#define	SMB_POC_DB15F		0x07		/* DB-15 pin female */
#define	SMB_POC_DB9M		0x08		/* DB-9 pin male */
#define	SMB_POC_DB9F		0x09		/* DB-9 pin female */
#define	SMB_POC_RJ11		0x0A		/* RJ-11 */
#define	SMB_POC_RJ45		0x0B		/* RJ-45 */
#define	SMB_POC_MINISCSI	0x0C		/* 50-pin MiniSCSI */
#define	SMB_POC_MINIDIN		0x0D		/* Mini-DIN */
#define	SMB_POC_MICRODIN	0x0E		/* Micro-DIN */
#define	SMB_POC_PS2		0x0F		/* PS/2 */
#define	SMB_POC_IR		0x10		/* Infrared */
#define	SMB_POC_HPHIL		0x11		/* HP-HIL */
#define	SMB_POC_USB		0x12		/* USB */
#define	SMB_POC_SSA		0x13		/* SSA SCSI */
#define	SMB_POC_DIN8M		0x14		/* Circular DIN-8 male */
#define	SMB_POC_DIN8F		0x15		/* Circular DIN-8 female */
#define	SMB_POC_OBIDE		0x16		/* on-board IDE */
#define	SMB_POC_OBFLOPPY	0x17		/* on-board floppy */
#define	SMB_POC_DI9		0x18		/* 9p dual inline (p10 cut) */
#define	SMB_POC_DI25		0x19		/* 25p dual inline (p26 cut) */
#define	SMB_POC_DI50		0x1A		/* 50p dual inline */
#define	SMB_POC_DI68		0x1B		/* 68p dual inline */
#define	SMB_POC_CDROM		0x1C		/* on-board sound from CDROM */
#define	SMB_POC_MINI14		0x1D		/* Mini-Centronics Type 14 */
#define	SMB_POC_MINI26		0x1E		/* Mini-Centronics Type 26 */
#define	SMB_POC_MINIJACK	0x1F		/* Mini-jack (headphones) */
#define	SMB_POC_BNC		0x20		/* BNC */
#define	SMB_POC_1394		0x21		/* 1394 */
#define	SMB_POC_SATA		0x22		/* SAS/SATA plug receptacle */
#define	SMB_POC_PC98		0xA0		/* PC-98 */
#define	SMB_POC_PC98HR		0xA1		/* PC-98Hireso */
#define	SMB_POC_PCH98		0xA2		/* PC-H98 */
#define	SMB_POC_PC98NOTE	0xA3		/* PC-98Note */
#define	SMB_POC_PC98FULL	0xA4		/* PC-98Full */
#define	SMB_POC_OTHER		0xFF		/* other */

#define	SMB_POT_NONE		0x00		/* none */
#define	SMB_POT_PP_XTAT		0x01		/* Parallel Port XT/AT compat */
#define	SMB_POT_PP_PS2		0x02		/* Parallel Port PS/2 */
#define	SMB_POT_PP_ECP		0x03		/* Parallel Port ECP */
#define	SMB_POT_PP_EPP		0x04		/* Parallel Port EPP */
#define	SMB_POT_PP_ECPEPP	0x05		/* Parallel Port ECP/EPP */
#define	SMB_POT_SP_XTAT		0x06		/* Serial Port XT/AT compat */
#define	SMB_POT_SP_16450	0x07		/* Serial Port 16450 compat */
#define	SMB_POT_SP_16550	0x08		/* Serial Port 16550 compat */
#define	SMB_POT_SP_16550A	0x09		/* Serial Port 16550A compat */
#define	SMB_POT_SCSI		0x0A		/* SCSI port */
#define	SMB_POT_MIDI		0x0B		/* MIDI port */
#define	SMB_POT_JOYSTICK	0x0C		/* Joystick port */
#define	SMB_POT_KEYBOARD	0x0D		/* Keyboard port */
#define	SMB_POT_MOUSE		0x0E		/* Mouse port */
#define	SMB_POT_SSA		0x0F		/* SSA SCSI */
#define	SMB_POT_USB		0x10		/* USB */
#define	SMB_POT_FIREWIRE	0x11		/* FireWrite (IEEE P1394) */
#define	SMB_POT_PCMII		0x12		/* PCMCIA Type II */
#define	SMB_POT_PCMIIa		0x13		/* PCMCIA Type II (alternate) */
#define	SMB_POT_PCMIII		0x14		/* PCMCIA Type III */
#define	SMB_POT_CARDBUS		0x15		/* Cardbus */
#define	SMB_POT_ACCESS		0x16		/* Access Bus Port */
#define	SMB_POT_SCSI2		0x17		/* SCSI II */
#define	SMB_POT_SCSIW		0x18		/* SCSI Wide */
#define	SMB_POT_PC98		0x19		/* PC-98 */
#define	SMB_POT_PC98HR		0x1A		/* PC-98Hireso */
#define	SMB_POT_PCH98		0x1B		/* PC-H98 */
#define	SMB_POT_VIDEO		0x1C		/* Video port */
#define	SMB_POT_AUDIO		0x1D		/* Audio port */
#define	SMB_POT_MODEM		0x1E		/* Modem port */
#define	SMB_POT_NETWORK		0x1F		/* Network port */
#define	SMB_POT_SATA		0x20		/* SATA */
#define	SMB_POT_SAS		0x21		/* SAS */
#define	SMB_POT_8251		0xA0		/* 8251 compatible */
#define	SMB_POT_8251F		0xA1		/* 8251 FIFO compatible */
#define	SMB_POT_OTHER		0xFF		/* other */

/*
 * SMBIOS Slot Information.  See DSP0134 Section 7.10 for more information.
 * See DSP0134 7.10.5 for how to interpret the value of smbl_id.
 */
typedef struct smbios_slot {
	const char *smbl_name;		/* reference designation */
	uint8_t smbl_type;		/* slot type */
	uint8_t smbl_width;		/* slot data bus width */
	uint8_t smbl_usage;		/* current usage */
	uint8_t smbl_length;		/* slot length */
	uint16_t smbl_id;		/* slot ID */
	uint8_t smbl_ch1;		/* slot characteristics 1 */
	uint8_t smbl_ch2;		/* slot characteristics 2 */
	uint16_t smbl_sg;		/* segment group number */
	uint8_t smbl_bus;		/* bus number */
	uint8_t smbl_df;		/* device/function number */
} smbios_slot_t;

#define	SMB_SLT_OTHER		0x01	/* other */
#define	SMB_SLT_UNKNOWN		0x02	/* unknown */
#define	SMB_SLT_ISA		0x03	/* ISA */
#define	SMB_SLT_MCA		0x04	/* MCA */
#define	SMB_SLT_EISA		0x05	/* EISA */
#define	SMB_SLT_PCI		0x06	/* PCI */
#define	SMB_SLT_PCMCIA		0x07	/* PCMCIA */
#define	SMB_SLT_VLVESA		0x08	/* VL-VESA */
#define	SMB_SLT_PROPRIETARY	0x09	/* proprietary */
#define	SMB_SLT_PROC		0x0A	/* processor card slot */
#define	SMB_SLT_MEM		0x0B	/* proprietary memory card slot */
#define	SMB_SLT_IOR		0x0C	/* I/O riser card slot */
#define	SMB_SLT_NUBUS		0x0D	/* NuBus */
#define	SMB_SLT_PCI66		0x0E	/* PCI (66MHz capable) */
#define	SMB_SLT_AGP		0x0F	/* AGP */
#define	SMB_SLT_AGP2X		0x10	/* AGP 2X */
#define	SMB_SLT_AGP4X		0x11	/* AGP 4X */
#define	SMB_SLT_PCIX		0x12	/* PCI-X */
#define	SMB_SLT_AGP8X		0x13	/* AGP 8X */
#define	SMB_SLT_M2_1DP		0x14	/* M.2 Socket 1-DP (Mechanical Key A) */
#define	SMB_SLT_M2_1SD		0x15	/* M.2 Socket 1-SD (Mechanical Key E) */
#define	SMB_SLT_M2_2		0x16	/* M.2 Socket 2 (Mechanical Key B) */
#define	SMB_SLT_M2_3		0x17	/* M.2 Socket 3 (Mechanical Key M) */
#define	SMB_SLT_MXM_I		0x18	/* MXM Type I */
#define	SMB_SLT_MXM_II		0x19	/* MXM Type II */
#define	SMB_SLT_MXM_III		0x1A	/* MXM Type III (standard connector) */
#define	SMB_SLT_MXM_III_HE	0x1B	/* MXM Type III (HE connector) */
#define	SMB_SLT_MXM_V		0x1C	/* MXM Type IV */
#define	SMB_SLT_MXM3_A		0x1D	/* MXM 3.0 Type A */
#define	SMB_SLT_MXM3_B		0x1E	/* MXM 3.0 Type B */
#define	SMB_SLT_PCIEG2_SFF	0x1F	/* PCI Express Gen 2 SFF-8639 */
#define	SMB_SLT_PCIEG3_SFF	0x20	/* PCI Express Gen 3 SFF-8639 */
/*
 * These lines must be on one line for the string generating code.
 */
/* BEGIN CSTYLED */
#define	SMB_SLT_PCIE_M52_WBSKO	0x21	/* PCI Express Mini 52-pin with bottom-side keep-outs */
#define	SMB_SLT_PCIE_M52_WOBSKO	0x22	/* PCI Express Mini 52-pin without bottom-side keep-outs */
/* END CSTYLED */
#define	SMB_SLT_PCIE_M76	0x23	/* PCI Express Mini 72-pin */
#define	SMB_SLT_PC98_C20	0xA0	/* PC-98/C20 */
#define	SMB_SLT_PC98_C24	0xA1	/* PC-98/C24 */
#define	SMB_SLT_PC98_E		0xA2	/* PC-98/E */
#define	SMB_SLT_PC98_LB		0xA3	/* PC-98/Local Bus */
#define	SMB_SLT_PC98_C		0xA4	/* PC-98/Card */
#define	SMB_SLT_PCIE		0xA5	/* PCI Express */
#define	SMB_SLT_PCIE1		0xA6	/* PCI Express x1 */
#define	SMB_SLT_PCIE2		0xA7	/* PCI Express x2 */
#define	SMB_SLT_PCIE4		0xA8	/* PCI Express x4 */
#define	SMB_SLT_PCIE8		0xA9	/* PCI Express x8 */
#define	SMB_SLT_PCIE16		0xAA	/* PCI Express x16 */
#define	SMB_SLT_PCIE2G		0xAB	/* PCI Exp. Gen 2 */
#define	SMB_SLT_PCIE2G1		0xAC	/* PCI Exp. Gen 2 x1 */
#define	SMB_SLT_PCIE2G2		0xAD	/* PCI Exp. Gen 2 x2 */
#define	SMB_SLT_PCIE2G4		0xAE	/* PCI Exp. Gen 2 x4 */
#define	SMB_SLT_PCIE2G8		0xAF	/* PCI Exp. Gen 2 x8 */
#define	SMB_SLT_PCIE2G16	0xB0	/* PCI Exp. Gen 2 x16 */
#define	SMB_SLT_PCIE3G		0xB1	/* PCI Exp. Gen 3 */
#define	SMB_SLT_PCIE3G1		0xB2	/* PCI Exp. Gen 3 x1 */
#define	SMB_SLT_PCIE3G2		0xB3	/* PCI Exp. Gen 3 x2 */
#define	SMB_SLT_PCIE3G4		0xB4	/* PCI Exp. Gen 3 x4 */
#define	SMB_SLT_PCIE3G8		0xB5	/* PCI Exp. Gen 3 x8 */
#define	SMB_SLT_PCIE3G16	0xB6	/* PCI Exp. Gen 3 x16 */

#define	SMB_SLW_OTHER		0x01	/* other */
#define	SMB_SLW_UNKNOWN		0x02	/* unknown */
#define	SMB_SLW_8		0x03	/* 8 bit */
#define	SMB_SLW_16		0x04	/* 16 bit */
#define	SMB_SLW_32		0x05	/* 32 bit */
#define	SMB_SLW_64		0x06	/* 64 bit */
#define	SMB_SLW_128		0x07	/* 128 bit */
#define	SMB_SLW_1X		0x08	/* 1x or x1 */
#define	SMB_SLW_2X		0x09	/* 2x or x2 */
#define	SMB_SLW_4X		0x0A	/* 4x or x4 */
#define	SMB_SLW_8X		0x0B	/* 8x or x8 */
#define	SMB_SLW_12X		0x0C	/* 12x or x12 */
#define	SMB_SLW_16X		0x0D	/* 16x or x16 */
#define	SMB_SLW_32X		0x0E	/* 32x or x32 */

#define	SMB_SLU_OTHER		0x01	/* other */
#define	SMB_SLU_UNKNOWN		0x02	/* unknown */
#define	SMB_SLU_AVAIL		0x03	/* available */
#define	SMB_SLU_INUSE		0x04	/* in use */

#define	SMB_SLL_OTHER		0x01	/* other */
#define	SMB_SLL_UNKNOWN		0x02	/* unknown */
#define	SMB_SLL_SHORT		0x03	/* short length */
#define	SMB_SLL_LONG		0x04	/* long length */

#define	SMB_SLCH1_UNKNOWN	0x01	/* characteristics unknown */
#define	SMB_SLCH1_5V		0x02	/* provides 5.0V */
#define	SMB_SLCH1_33V		0x04	/* provides 3.3V */
#define	SMB_SLCH1_SHARED	0x08	/* opening shared with other slot */
#define	SMB_SLCH1_PC16		0x10	/* slot supports PC Card-16 */
#define	SMB_SLCH1_PCCB		0x20	/* slot supports CardBus */
#define	SMB_SLCH1_PCZV		0x40	/* slot supports Zoom Video */
#define	SMB_SLCH1_PCMRR		0x80	/* slot supports Modem Ring Resume */

#define	SMB_SLCH2_PME		0x01	/* slot supports PME# signal */
#define	SMB_SLCH2_HOTPLUG	0x02	/* slot supports hot-plug devices */
#define	SMB_SLCH2_SMBUS		0x04	/* slot supports SMBus signal */

/*
 * SMBIOS On-Board Device Information.  See DSP0134 Section 7.11 for more
 * information.  Any number of on-board device sections may be present, each
 * containing one or more records.  The smbios_info_obdevs() function permits
 * the caller to retrieve one or more of the records from a given section.
 */
typedef struct smbios_obdev {
	const char *smbd_name;		/* description string for this device */
	uint8_t smbd_type;		/* type code (SMB_OBT_*) */
	uint8_t smbd_enabled;		/* boolean (device is enabled) */
} smbios_obdev_t;

#define	SMB_OBT_OTHER		0x01	/* other */
#define	SMB_OBT_UNKNOWN		0x02	/* unknown */
#define	SMB_OBT_VIDEO		0x03	/* video */
#define	SMB_OBT_SCSI		0x04	/* scsi */
#define	SMB_OBT_ETHERNET	0x05	/* ethernet */
#define	SMB_OBT_TOKEN		0x06	/* token ring */
#define	SMB_OBT_SOUND		0x07	/* sound */
#define	SMB_OBT_PATA		0x08	/* pata */
#define	SMB_OBT_SATA		0x09	/* sata */
#define	SMB_OBT_SAS		0x0A	/* sas */

/*
 * SMBIOS BIOS Language Information.  See DSP0134 Section 7.14 for more
 * information.  The smbios_info_strtab() function can be applied using a
 * count of smbla_num to retrieve the other possible language settings.
 */
typedef struct smbios_lang {
	const char *smbla_cur;		/* current language setting */
	uint_t smbla_fmt;		/* language name format (see below) */
	uint_t smbla_num;		/* number of installed languages */
} smbios_lang_t;

#define	SMB_LFMT_LONG	0		/* <ISO639>|<ISO3166>|Encoding Method */
#define	SMB_LFMT_SHORT	1		/* <ISO930><ISO3166> */

/*
 * SMBIOS System Event Log Information.  See DSP0134 Section 7.16 for more
 * information.  Accessing the event log itself requires additional interfaces.
 */
typedef struct smbios_evtype {
	uint8_t smbevt_ltype;		/* log type */
	uint8_t smbevt_dtype;		/* variable data format type */
} smbios_evtype_t;

typedef struct smbios_evlog {
	size_t smbev_size;		/* size in bytes of log area */
	size_t smbev_hdr;		/* offset or index of header */
	size_t smbev_data;		/* offset or index of data */
	uint8_t smbev_method;		/* data access method (see below) */
	uint8_t smbev_flags;		/* flags (see below) */
	uint8_t smbev_format;		/* log header format (see below) */
	uint8_t smbev_pad;		/* padding */
	uint32_t smbev_token;		/* data update change token */
	union {
		struct {
			uint16_t evi_iaddr; /* index address */
			uint16_t evi_daddr; /* data address */
		} eva_io;		/* i/o address for SMB_EVM_XxY */
		uint32_t eva_addr;	/* address for SMB_EVM_MEM32 */
		uint16_t eva_gpnv;	/* handle for SMB_EVM_GPNV */
	} smbev_addr;
	uint32_t smbev_typec;		/* number of type descriptors */
	const smbios_evtype_t *smbev_typev; /* type descriptor array */
} smbios_evlog_t;

#define	SMB_EVM_1x1i_1x1d	0	/* I/O: 1 1b idx port, 1 1b data port */
#define	SMB_EVM_2x1i_1x1d	1	/* I/O: 2 1b idx port, 1 1b data port */
#define	SMB_EVM_1x2i_1x1d	2	/* I/O: 1 2b idx port, 1 1b data port */
#define	SMB_EVM_MEM32		3	/* Memory-Mapped 32-bit Physical Addr */
#define	SMB_EVM_GPNV		4	/* GP Non-Volatile API Access */

#define	SMB_EVFL_VALID		0x1	/* log area valid */
#define	SMB_EVFL_FULL		0x2	/* log area full */

#define	SMB_EVHF_NONE		0	/* no log headers used */
#define	SMB_EVHF_F1		1	/* DMTF log header type 1 */

/*
 * SMBIOS Physical Memory Array Information.  See DSP0134 Section 7.17 for
 * more information.  This describes a collection of physical memory devices.
 */
typedef struct smbios_memarray {
	uint8_t smbma_location;		/* physical device location */
	uint8_t smbma_use;		/* physical device functional purpose */
	uint8_t smbma_ecc;		/* error detect/correct mechanism */
	uint8_t smbma_pad0;		/* padding */
	uint32_t smbma_pad1;		/* padding */
	uint32_t smbma_ndevs;		/* number of slots or sockets */
	id_t smbma_err;			/* handle of error (if any) */
	uint64_t smbma_size;		/* maximum capacity in bytes */
} smbios_memarray_t;

#define	SMB_MAL_OTHER		0x01	/* other */
#define	SMB_MAL_UNKNOWN		0x02	/* unknown */
#define	SMB_MAL_SYSMB		0x03	/* system board or motherboard */
#define	SMB_MAL_ISA		0x04	/* ISA add-on card */
#define	SMB_MAL_EISA		0x05	/* EISA add-on card */
#define	SMB_MAL_PCI		0x06	/* PCI add-on card */
#define	SMB_MAL_MCA		0x07	/* MCA add-on card */
#define	SMB_MAL_PCMCIA		0x08	/* PCMCIA add-on card */
#define	SMB_MAL_PROP		0x09	/* proprietary add-on card */
#define	SMB_MAL_NUBUS		0x0A	/* NuBus */
#define	SMB_MAL_PC98C20		0xA0	/* PC-98/C20 add-on card */
#define	SMB_MAL_PC98C24		0xA1	/* PC-98/C24 add-on card */
#define	SMB_MAL_PC98E		0xA2	/* PC-98/E add-on card */
#define	SMB_MAL_PC98LB		0xA3	/* PC-98/Local bus add-on card */

#define	SMB_MAU_OTHER		0x01	/* other */
#define	SMB_MAU_UNKNOWN		0x02	/* unknown */
#define	SMB_MAU_SYSTEM		0x03	/* system memory */
#define	SMB_MAU_VIDEO		0x04	/* video memory */
#define	SMB_MAU_FLASH		0x05	/* flash memory */
#define	SMB_MAU_NVRAM		0x06	/* non-volatile RAM */
#define	SMB_MAU_CACHE		0x07	/* cache memory */

#define	SMB_MAE_OTHER		0x01	/* other */
#define	SMB_MAE_UNKNOWN		0x02	/* unknown */
#define	SMB_MAE_NONE		0x03	/* none */
#define	SMB_MAE_PARITY		0x04	/* parity */
#define	SMB_MAE_SECC		0x05	/* single-bit ECC */
#define	SMB_MAE_MECC		0x06	/* multi-bit ECC */
#define	SMB_MAE_CRC		0x07	/* CRC */

/*
 * SMBIOS Memory Device Information.  See DSP0134 Section 7.18 for more
 * information.  One or more of these structures are associated with each
 * smbios_memarray_t.  A structure is present even for unpopulated sockets.
 * Unknown values are set to -1.  A smbmd_size of 0 indicates unpopulated.
 * WARNING: Some BIOSes appear to export the *maximum* size of the device
 * that can appear in the corresponding socket as opposed to the current one.
 */
typedef struct smbios_memdevice {
	id_t smbmd_array;		/* handle of physical memory array */
	id_t smbmd_error;		/* handle of memory error data */
	uint32_t smbmd_twidth;		/* total width in bits including ecc */
	uint32_t smbmd_dwidth;		/* data width in bits */
	uint64_t smbmd_size;		/* size in bytes (see note above) */
	uint8_t smbmd_form;		/* form factor */
	uint8_t smbmd_set;		/* set (0x00=none, 0xFF=unknown) */
	uint8_t smbmd_type;		/* memory type */
	uint8_t smbmd_pad;		/* padding */
	uint32_t smbmd_flags;		/* flags (see below) */
	uint32_t smbmd_speed;		/* speed in MT/s */
	const char *smbmd_dloc;		/* physical device locator string */
	const char *smbmd_bloc;		/* physical bank locator string */
	uint8_t smbmd_rank;		/* rank */
	uint16_t smbmd_clkspeed;	/* configured clock speed */
	uint16_t smbmd_minvolt;		/* minimum voltage */
	uint16_t smbmd_maxvolt;		/* maximum voltage */
	uint16_t smbmd_confvolt;	/* configured voltage */
} smbios_memdevice_t;

#define	SMB_MDFF_OTHER		0x01	/* other */
#define	SMB_MDFF_UNKNOWN	0x02	/* unknown */
#define	SMB_MDFF_SIMM		0x03	/* SIMM */
#define	SMB_MDFF_SIP		0x04	/* SIP */
#define	SMB_MDFF_CHIP		0x05	/* chip */
#define	SMB_MDFF_DIP		0x06	/* DIP */
#define	SMB_MDFF_ZIP		0x07	/* ZIP */
#define	SMB_MDFF_PROP		0x08	/* proprietary card */
#define	SMB_MDFF_DIMM		0x09	/* DIMM */
#define	SMB_MDFF_TSOP		0x0A	/* TSOP */
#define	SMB_MDFF_CHIPROW	0x0B	/* row of chips */
#define	SMB_MDFF_RIMM		0x0C	/* RIMM */
#define	SMB_MDFF_SODIMM		0x0D	/* SODIMM */
#define	SMB_MDFF_SRIMM		0x0E	/* SRIMM */
#define	SMB_MDFF_FBDIMM		0x0F	/* FBDIMM */

#define	SMB_MDT_OTHER		0x01	/* other */
#define	SMB_MDT_UNKNOWN		0x02	/* unknown */
#define	SMB_MDT_DRAM		0x03	/* DRAM */
#define	SMB_MDT_EDRAM		0x04	/* EDRAM */
#define	SMB_MDT_VRAM		0x05	/* VRAM */
#define	SMB_MDT_SRAM		0x06	/* SRAM */
#define	SMB_MDT_RAM		0x07	/* RAM */
#define	SMB_MDT_ROM		0x08	/* ROM */
#define	SMB_MDT_FLASH		0x09	/* FLASH */
#define	SMB_MDT_EEPROM		0x0A	/* EEPROM */
#define	SMB_MDT_FEPROM		0x0B	/* FEPROM */
#define	SMB_MDT_EPROM		0x0C	/* EPROM */
#define	SMB_MDT_CDRAM		0x0D	/* CDRAM */
#define	SMB_MDT_3DRAM		0x0E	/* 3DRAM */
#define	SMB_MDT_SDRAM		0x0F	/* SDRAM */
#define	SMB_MDT_SGRAM		0x10	/* SGRAM */
#define	SMB_MDT_RDRAM		0x11	/* RDRAM */
#define	SMB_MDT_DDR		0x12	/* DDR */
#define	SMB_MDT_DDR2		0x13	/* DDR2 */
#define	SMB_MDT_DDR2FBDIMM	0x14	/* DDR2 FBDIMM */
#define	SMB_MDT_DDR3		0x18	/* DDR3 */
#define	SMB_MDT_FBD2		0x19	/* FBD2 */
#define	SMB_MDT_DDR4		0x1A	/* DDR4 */
#define	SMB_MDT_LPDDR		0x1B	/* LPDDR */
#define	SMB_MDT_LPDDR2		0x1C	/* LPDDR2 */
#define	SMB_MDT_LPDDR3		0x1D	/* LPDDR3 */
#define	SMB_MDT_LPDDR4		0x1E	/* LPDDR4 */

#define	SMB_MDF_OTHER		0x0002	/* other */
#define	SMB_MDF_UNKNOWN		0x0004	/* unknown */
#define	SMB_MDF_FASTPG		0x0008	/* fast-paged */
#define	SMB_MDF_STATIC		0x0010	/* static column */
#define	SMB_MDF_PSTATIC		0x0020	/* pseudo-static */
#define	SMB_MDF_RAMBUS		0x0040	/* RAMBUS */
#define	SMB_MDF_SYNC		0x0080	/* synchronous */
#define	SMB_MDF_CMOS		0x0100	/* CMOS */
#define	SMB_MDF_EDO		0x0200	/* EDO */
#define	SMB_MDF_WDRAM		0x0400	/* Window DRAM */
#define	SMB_MDF_CDRAM		0x0800	/* Cache DRAM */
#define	SMB_MDF_NV		0x1000	/* non-volatile */
#define	SMB_MDF_REG		0x2000	/* Registered (Buffered) */
#define	SMB_MDF_UNREG		0x4000	/* Unregistered (Unbuffered) */
#define	SMB_MDF_LRDIMM		0x8000	/* LRDIMM */

#define	SMB_MDR_SINGLE		0x01	/* single */
#define	SMB_MDR_DUAL		0x02	/* dual */
#define	SMB_MDR_QUAD		0x04	/* quad */
#define	SMB_MDR_OCTAL		0x08	/* octal */

/*
 * SMBIOS Memory Array Mapped Address.  See DSP0134 Section 7.20 for more
 * information.  We convert start/end addresses into addr/size for convenience.
 */
typedef struct smbios_memarrmap {
	id_t smbmam_array;		/* physical memory array handle */
	uint32_t smbmam_width;		/* number of devices that form a row */
	uint64_t smbmam_addr;		/* physical address of mapping */
	uint64_t smbmam_size;		/* size in bytes of address range */
} smbios_memarrmap_t;

/*
 * SMBIOS Memory Device Mapped Address.  See DSP0134 Section 7.21 for more
 * information.  We convert start/end addresses into addr/size for convenience.
 */
typedef struct smbios_memdevmap {
	id_t smbmdm_device;		/* memory device handle */
	id_t smbmdm_arrmap;		/* memory array mapped address handle */
	uint64_t smbmdm_addr;		/* physical address of mapping */
	uint64_t smbmdm_size;		/* size in bytes of address range */
	uint8_t smbmdm_rpos;		/* partition row position */
	uint8_t smbmdm_ipos;		/* interleave position */
	uint8_t smbmdm_idepth;		/* interleave data depth */
} smbios_memdevmap_t;

/*
 * SMBIOS Hardware Security Settings.  See DSP0134 Section 7.25 for more
 * information.  Only one such record will be present in the SMBIOS.
 */
typedef struct smbios_hwsec {
	uint8_t smbh_pwr_ps;		/* power-on password status */
	uint8_t smbh_kbd_ps;		/* keyboard password status */
	uint8_t smbh_adm_ps;		/* administrator password status */
	uint8_t smbh_pan_ps;		/* front panel reset status */
} smbios_hwsec_t;

#define	SMB_HWSEC_PS_DISABLED	0x00	/* password disabled */
#define	SMB_HWSEC_PS_ENABLED	0x01	/* password enabled */
#define	SMB_HWSEC_PS_NOTIMPL	0x02	/* password not implemented */
#define	SMB_HWSEC_PS_UNKNOWN	0x03	/* password status unknown */

/*
 * SMBIOS System Boot Information.  See DSP0134 Section 7.33 for more
 * information.  The contents of the data varies by type and is undocumented
 * from the perspective of DSP0134 -- it seems to be left as vendor-specific.
 * The (D) annotation next to SMB_BOOT_* below indicates possible data payload.
 */
typedef struct smbios_boot {
	uint8_t smbt_status;		/* boot status code (see below) */
	const void *smbt_data;		/* data buffer specific to status */
	size_t smbt_size;		/* size of smbt_data buffer in bytes */
} smbios_boot_t;

#define	SMB_BOOT_NORMAL		0	/* no errors detected */
#define	SMB_BOOT_NOMEDIA	1	/* no bootable media */
#define	SMB_BOOT_OSFAIL		2	/* normal o/s failed to load */
#define	SMB_BOOT_FWHWFAIL	3	/* firmware-detected hardware failure */
#define	SMB_BOOT_OSHWFAIL	4	/* o/s-detected hardware failure */
#define	SMB_BOOT_USERREQ	5	/* user-requested boot (keystroke) */
#define	SMB_BOOT_SECURITY	6	/* system security violation */
#define	SMB_BOOT_PREVREQ	7	/* previously requested image (D) */
#define	SMB_BOOT_WATCHDOG	8	/* watchdog initiated reboot */
#define	SMB_BOOT_RESV_LO	9	/* low end of reserved range */
#define	SMB_BOOT_RESV_HI	127	/* high end of reserved range */
#define	SMB_BOOT_OEM_LO		128	/* low end of OEM-specific range */
#define	SMB_BOOT_OEM_HI		191	/* high end of OEM-specific range */
#define	SMB_BOOT_PROD_LO	192	/* low end of product-specific range */
#define	SMB_BOOT_PROD_HI	255	/* high end of product-specific range */

/*
 * SMBIOS IPMI Device Information.  See DSP0134 Section 7.39 and also
 * Appendix C1 of the IPMI specification for more information on this record.
 */
typedef struct smbios_ipmi {
	uint_t smbip_type;		/* BMC interface type */
	smbios_version_t smbip_vers;	/* BMC's IPMI specification version */
	uint32_t smbip_i2c;		/* BMC I2C bus slave address */
	uint32_t smbip_bus;		/* bus ID of NV storage device, or -1 */
	uint64_t smbip_addr;		/* BMC base address */
	uint32_t smbip_flags;		/* flags (see below) */
	uint16_t smbip_intr;		/* interrupt number (or zero if none) */
	uint16_t smbip_regspacing;	/* i/o space register spacing (bytes) */
} smbios_ipmi_t;

#define	SMB_IPMI_T_UNKNOWN	0x00	/* unknown */
#define	SMB_IPMI_T_KCS		0x01	/* KCS: Keyboard Controller Style */
#define	SMB_IPMI_T_SMIC		0x02	/* SMIC: Server Mgmt Interface Chip */
#define	SMB_IPMI_T_BT		0x03	/* BT: Block Transfer */
#define	SMB_IPMI_T_SSIF		0x04	/* SSIF: SMBus System Interface */

#define	SMB_IPMI_F_IOADDR	0x01	/* base address is in i/o space */
#define	SMB_IPMI_F_INTRSPEC	0x02	/* intr information is specified */
#define	SMB_IPMI_F_INTRHIGH	0x04	/* intr active high (else low) */
#define	SMB_IPMI_F_INTREDGE	0x08	/* intr is edge triggered (else lvl) */

/*
 * SMBIOS Onboard Devices Extended Information.  See DSP0134 Section 7.42
 * for more information.
 */
typedef struct smbios_obdev_ext {
	const char *smboe_name;		/* reference designation */
	uint8_t smboe_dtype;		/* device type */
	uint8_t smboe_dti;		/* device type instance */
	uint16_t smboe_sg;		/* segment group number */
	uint8_t smboe_bus;		/* bus number */
	uint8_t smboe_df;		/* device/function number */
} smbios_obdev_ext_t;


/*
 * SMBIOS OEM-specific (Type 132) Processor Extended Information.
 */
typedef struct smbios_processor_ext {
	uint16_t smbpe_processor;	/* extending processor handle */
	uint8_t smbpe_fru;		/* FRU indicaor */
	uint8_t smbpe_n;		/* number of APIC IDs */
	uint16_t *smbpe_apicid;		/* strand Inital APIC IDs */
} smbios_processor_ext_t;

/*
 * SMBIOS OEM-specific (Type 136) Port Extended Information.
 */
typedef struct smbios_port_ext {
	uint16_t smbporte_chassis;	/* chassis handle */
	uint16_t smbporte_port;		/* port connector handle */
	uint8_t smbporte_dtype;		/* device type */
	uint16_t smbporte_devhdl;	/* device handle */
	uint8_t smbporte_phy;		/* PHY number */
} smbios_port_ext_t;

/*
 * SMBIOS OEM-specific (Type 138) PCI-Express RC/RP Information.
 */
typedef struct smbios_pciexrc {
	uint16_t smbpcie_bb;		/* base board handle */
	uint16_t smbpcie_bdf;		/* Bus/Dev/Funct (PCI) */
} smbios_pciexrc_t;

/*
 * SMBIOS OEM-specific (Type 144) Memory Array Extended Information.
 */
typedef struct smbios_memarray_ext {
	uint16_t smbmae_ma;		/* memory array handle */
	uint16_t smbmae_comp;		/* component parent handle */
	uint16_t smbmae_bdf;		/* Bus/Dev/Funct (PCI) */
} smbios_memarray_ext_t;

/*
 * SMBIOS OEM-specific (Type 145) Memory Device Extended Information.
 */
typedef struct smbios_memdevice_ext {
	uint16_t smbmdeve_md;		/* memory device handle */
	uint8_t smbmdeve_drch;		/* DRAM channel */
	uint8_t smbmdeve_ncs;		/* number of chip selects */
	uint8_t *smbmdeve_cs;		/* array of chip select numbers */
} smbios_memdevice_ext_t;

/*
 * SMBIOS Interfaces.  An SMBIOS image can be opened by either providing a file
 * pathname, device pathname, file descriptor, or raw memory buffer.  Once an
 * image is opened the functions below can be used to iterate over the various
 * structures and convert the underlying data representation into the simpler
 * data structures described earlier in this header file.  The SMB_VERSION
 * constant specified when opening an image indicates the version of the ABI
 * the caller expects and the DMTF SMBIOS version the client can understand.
 * The library will then map older or newer data structures to that as needed.
 */

#define	SMB_VERSION_23	0x0203		/* SMBIOS encoding for DMTF spec 2.3 */
#define	SMB_VERSION_24	0x0204		/* SMBIOS encoding for DMTF spec 2.4 */
#define	SMB_VERSION_25	0x0205		/* SMBIOS encoding for DMTF spec 2.5 */
#define	SMB_VERSION_26	0x0206		/* SMBIOS encoding for DMTF spec 2.6 */
#define	SMB_VERSION_27	0x0207		/* SMBIOS encoding for DMTF spec 2.7 */
#define	SMB_VERSION_28	0x0208		/* SMBIOS encoding for DMTF spec 2.8 */
#define	SMB_VERSION_30	0x0300		/* SMBIOS encoding for DMTF spec 3.0 */
#define	SMB_VERSION_31	0x0301		/* SMBIOS encoding for DMTF spec 3.1 */
#define	SMB_VERSION	SMB_VERSION_31	/* SMBIOS latest version definitions */

#define	SMB_O_NOCKSUM	0x1		/* do not verify header checksums */
#define	SMB_O_NOVERS	0x2		/* do not verify header versions */
#define	SMB_O_ZIDS	0x4		/* strip out identification numbers */
#define	SMB_O_MASK	0x7		/* mask of valid smbios_*open flags */

#define	SMB_ID_NOTSUP	0xFFFE		/* structure is not supported by BIOS */
#define	SMB_ID_NONE	0xFFFF		/* structure is a null reference */

#define	SMB_ERR		(-1)		/* id_t value indicating error */

typedef struct smbios_hdl smbios_hdl_t;

typedef struct smbios_struct {
	id_t smbstr_id;			/* structure ID handle */
	uint_t smbstr_type;		/* structure type */
	const void *smbstr_data;	/* structure data */
	size_t smbstr_size;		/* structure size */
} smbios_struct_t;

typedef int smbios_struct_f(smbios_hdl_t *,
    const smbios_struct_t *, void *);

extern smbios_hdl_t *smbios_open(const char *, int, int, int *);
extern smbios_hdl_t *smbios_fdopen(int, int, int, int *);
extern smbios_hdl_t *smbios_bufopen(const smbios_entry_t *,
    const void *, size_t, int, int, int *);

extern const void *smbios_buf(smbios_hdl_t *);
extern size_t smbios_buflen(smbios_hdl_t *);

extern void smbios_checksum(smbios_hdl_t *, smbios_entry_t *);
extern int smbios_write(smbios_hdl_t *, int);
extern void smbios_close(smbios_hdl_t *);

extern boolean_t smbios_truncated(smbios_hdl_t *);
extern int smbios_errno(smbios_hdl_t *);
extern const char *smbios_errmsg(int);

extern int smbios_lookup_id(smbios_hdl_t *, id_t, smbios_struct_t *);
extern int smbios_lookup_type(smbios_hdl_t *, uint_t, smbios_struct_t *);
extern int smbios_iter(smbios_hdl_t *, smbios_struct_f *, void *);

extern smbios_entry_point_t smbios_info_smbios(smbios_hdl_t *,
    smbios_entry_t *);
extern void smbios_info_smbios_version(smbios_hdl_t *, smbios_version_t *);
extern int smbios_info_common(smbios_hdl_t *, id_t, smbios_info_t *);
extern int smbios_info_contains(smbios_hdl_t *, id_t, uint_t, id_t *);
extern id_t smbios_info_bios(smbios_hdl_t *, smbios_bios_t *);
extern id_t smbios_info_system(smbios_hdl_t *, smbios_system_t *);
extern int smbios_info_bboard(smbios_hdl_t *, id_t, smbios_bboard_t *);
extern int smbios_info_chassis(smbios_hdl_t *, id_t, smbios_chassis_t *);
extern int smbios_info_processor(smbios_hdl_t *, id_t, smbios_processor_t *);
extern int smbios_info_extprocessor(smbios_hdl_t *, id_t,
    smbios_processor_ext_t *);
extern int smbios_info_cache(smbios_hdl_t *, id_t, smbios_cache_t *);
extern int smbios_info_port(smbios_hdl_t *, id_t, smbios_port_t *);
extern int smbios_info_extport(smbios_hdl_t *, id_t, smbios_port_ext_t *);
extern int smbios_info_slot(smbios_hdl_t *, id_t, smbios_slot_t *);
extern int smbios_info_obdevs(smbios_hdl_t *, id_t, int, smbios_obdev_t *);
extern int smbios_info_obdevs_ext(smbios_hdl_t *, id_t, smbios_obdev_ext_t *);
extern int smbios_info_strtab(smbios_hdl_t *, id_t, int, const char *[]);
extern id_t smbios_info_lang(smbios_hdl_t *, smbios_lang_t *);
extern id_t smbios_info_eventlog(smbios_hdl_t *, smbios_evlog_t *);
extern int smbios_info_memarray(smbios_hdl_t *, id_t, smbios_memarray_t *);
extern int smbios_info_extmemarray(smbios_hdl_t *, id_t,
    smbios_memarray_ext_t *);
extern int smbios_info_memarrmap(smbios_hdl_t *, id_t, smbios_memarrmap_t *);
extern int smbios_info_memdevice(smbios_hdl_t *, id_t, smbios_memdevice_t *);
extern int smbios_info_extmemdevice(smbios_hdl_t *, id_t,
    smbios_memdevice_ext_t *);
extern int smbios_info_memdevmap(smbios_hdl_t *, id_t, smbios_memdevmap_t *);
extern id_t smbios_info_hwsec(smbios_hdl_t *, smbios_hwsec_t *);
extern id_t smbios_info_boot(smbios_hdl_t *, smbios_boot_t *);
extern id_t smbios_info_ipmi(smbios_hdl_t *, smbios_ipmi_t *);
extern int smbios_info_pciexrc(smbios_hdl_t *, id_t, smbios_pciexrc_t *);

extern const char *smbios_psn(smbios_hdl_t *);
extern const char *smbios_csn(smbios_hdl_t *);

#ifndef _KERNEL
/*
 * The smbios_*_desc() and smbios_*_name() interfaces can be used for utilities
 * such as smbios(1M) that wish to decode SMBIOS fields for humans.  The _desc
 * functions return the comment string next to the #defines listed above, and
 * the _name functions return the appropriate #define identifier itself.
 */
extern const char *smbios_bboard_flag_desc(uint_t);
extern const char *smbios_bboard_flag_name(uint_t);
extern const char *smbios_bboard_type_desc(uint_t);

extern const char *smbios_bios_flag_desc(uint64_t);
extern const char *smbios_bios_flag_name(uint64_t);

extern const char *smbios_bios_xb1_desc(uint_t);
extern const char *smbios_bios_xb1_name(uint_t);
extern const char *smbios_bios_xb2_desc(uint_t);
extern const char *smbios_bios_xb2_name(uint_t);

extern const char *smbios_boot_desc(uint_t);

extern const char *smbios_cache_assoc_desc(uint_t);
extern const char *smbios_cache_ctype_desc(uint_t);
extern const char *smbios_cache_ctype_name(uint_t);
extern const char *smbios_cache_ecc_desc(uint_t);
extern const char *smbios_cache_flag_desc(uint_t);
extern const char *smbios_cache_flag_name(uint_t);
extern const char *smbios_cache_loc_desc(uint_t);
extern const char *smbios_cache_logical_desc(uint_t);
extern const char *smbios_cache_mode_desc(uint_t);

extern const char *smbios_chassis_state_desc(uint_t);
extern const char *smbios_chassis_type_desc(uint_t);

extern const char *smbios_evlog_flag_desc(uint_t);
extern const char *smbios_evlog_flag_name(uint_t);
extern const char *smbios_evlog_format_desc(uint_t);
extern const char *smbios_evlog_method_desc(uint_t);

extern const char *smbios_ipmi_flag_name(uint_t);
extern const char *smbios_ipmi_flag_desc(uint_t);
extern const char *smbios_ipmi_type_desc(uint_t);

extern const char *smbios_hwsec_desc(uint_t);

extern const char *smbios_memarray_loc_desc(uint_t);
extern const char *smbios_memarray_use_desc(uint_t);
extern const char *smbios_memarray_ecc_desc(uint_t);

extern const char *smbios_memdevice_form_desc(uint_t);
extern const char *smbios_memdevice_type_desc(uint_t);
extern const char *smbios_memdevice_flag_name(uint_t);
extern const char *smbios_memdevice_flag_desc(uint_t);
extern const char *smbios_memdevice_rank_desc(uint_t);

extern const char *smbios_onboard_type_desc(uint_t);

extern const char *smbios_port_conn_desc(uint_t);
extern const char *smbios_port_type_desc(uint_t);

extern const char *smbios_processor_family_desc(uint_t);
extern const char *smbios_processor_status_desc(uint_t);
extern const char *smbios_processor_type_desc(uint_t);
extern const char *smbios_processor_upgrade_desc(uint_t);
extern const char *smbios_processor_core_flag_name(uint_t);
extern const char *smbios_processor_core_flag_desc(uint_t);

extern const char *smbios_slot_type_desc(uint_t);
extern const char *smbios_slot_width_desc(uint_t);
extern const char *smbios_slot_usage_desc(uint_t);
extern const char *smbios_slot_length_desc(uint_t);
extern const char *smbios_slot_ch1_desc(uint_t);
extern const char *smbios_slot_ch1_name(uint_t);
extern const char *smbios_slot_ch2_desc(uint_t);
extern const char *smbios_slot_ch2_name(uint_t);

extern const char *smbios_type_desc(uint_t);
extern const char *smbios_type_name(uint_t);

extern const char *smbios_system_wakeup_desc(uint_t);
#endif /* !_KERNEL */

#ifdef _KERNEL
/*
 * For SMBIOS clients within the kernel itself, ksmbios is used to refer to
 * the kernel's current snapshot of the SMBIOS, if one exists, and the
 * ksmbios_flags tunable is the set of flags for use with smbios_open().
 */
extern smbios_hdl_t *ksmbios;
extern int ksmbios_flags;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMBIOS_H */
