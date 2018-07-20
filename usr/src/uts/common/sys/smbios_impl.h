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
 * Copyright 2015 OmniTI Computer Consulting, Inc.  All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This header file defines the implementation structures for the SMBIOS access
 * library, libsmbios, and an equivalent kernel module.  Clients should use
 * the <smbios.h> or <sys/smbios.h> header files to access DMTF SMBIOS
 * information, NOT these underlying implementation structures from the spec.
 * In short, do not user this header file or these routines for any purpose.
 */

#ifndef	_SYS_SMBIOS_IMPL_H
#define	_SYS_SMBIOS_IMPL_H

#include <sys/smbios.h>
#include <sys/sysmacros.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#include <stddef.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions required to interpret the BIOS type information.
 */
#define	SMB_BIOSXB_EXTROM	6

#define	SMB_BIOS_EXTROM_VALUE_MASK(x)	((x) & 0x3fff)
#define	SMB_BIOS_EXTROM_SHIFT_MASK(x)	(((x) & 0xc000) >> 14)

#pragma pack(1)

typedef struct smb_header {
	uint8_t smbh_type;		/* structure type (SMB_TYPE_* value) */
	uint8_t smbh_len;		/* length in bytes of formatted area */
	uint16_t smbh_hdl;		/* structure handle */
} smb_header_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_BIOS.
 */
typedef struct smb_bios {
	smb_header_t smbbi_hdr;		/* structure header */
	uint8_t smbbi_vendor;		/* bios vendor string */
	uint8_t smbbi_version;		/* bios version string */
	uint16_t smbbi_segment;		/* segment location of bios address */
	uint8_t smbbi_reldate;		/* bios release date */
	uint8_t smbbi_romsize;		/* bios rom size (64k * (n + 1)) */
	uint64_t smbbi_cflags;		/* bios characteristics */
	uint8_t smbbi_xcflags[1];	/* bios characteristics extensions */
} smb_bios_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_SYSTEM.
 */
typedef struct smb_system {
	smb_header_t smbsi_hdr;		/* structure header */
	uint8_t smbsi_manufacturer;	/* manufacturer */
	uint8_t smbsi_product;		/* product name */
	uint8_t smbsi_version;		/* version */
	uint8_t smbsi_serial;		/* serial number */
	uint8_t smbsi_uuid[16];		/* UUID */
	uint8_t smbsi_wakeup;		/* wake-up type */
	uint8_t smbsi_sku;		/* SKU number */
	uint8_t smbsi_family;		/* family */
} smb_system_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_BASEBOARD.
 */
typedef struct smb_bboard {
	smb_header_t smbbb_hdr;		/* structure header */
	uint8_t smbbb_manufacturer;	/* manufacturer */
	uint8_t smbbb_product;		/* product name */
	uint8_t smbbb_version;		/* version */
	uint8_t smbbb_serial;		/* serial number */
	uint8_t smbbb_asset;		/* asset tag */
	uint8_t smbbb_flags;		/* feature flags */
	uint8_t smbbb_location;		/* location in chassis */
	uint16_t smbbb_chassis;		/* chassis handle */
	uint8_t smbbb_type;		/* board type */
	uint8_t smbbb_cn;		/* number of contained handles */
	uint16_t smbbb_cv[1];		/* array of contained handles */
} smb_bboard_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_CHASSIS.
 */
typedef struct smb_chassis {
	smb_header_t smbch_hdr;		/* structure header */
	uint8_t smbch_manufacturer;	/* manufacturer */
	uint8_t smbch_type;		/* type */
	uint8_t smbch_version;		/* version */
	uint8_t smbch_serial;		/* serial number */
	uint8_t smbch_asset;		/* asset tag */
	uint8_t smbch_bustate;		/* boot-up state */
	uint8_t smbch_psstate;		/* power supply state */
	uint8_t smbch_thstate;		/* thermal state */
	uint8_t smbch_security;		/* security state */
	uint32_t smbch_oemdata;		/* OEM-specific data */
	uint8_t smbch_uheight;		/* enclosure height */
	uint8_t smbch_cords;		/* number of power cords */
	uint8_t smbch_cn;		/* number of contained records */
	uint8_t smbch_cm;		/* size of contained records */
	uint8_t smbch_cv[1];		/* array of contained records */
} smb_chassis_t;

/* WARNING: the argument is evaluated three times! */
#define	SMB_CH_SKU(smbcp) ((char *) \
	(smbcp)->smbch_cv + ((smbcp)->smbch_cn * (smbcp)->smbch_cm))
#define	SMB_CHT_LOCK	0x80		/* lock bit within smbch_type */

/*
 * SMBIOS implementation structure for SMB_TYPE_PROCESSOR.
 */
typedef struct smb_processor {
	smb_header_t smbpr_hdr;		/* structure header */
	uint8_t smbpr_socket;		/* socket designation */
	uint8_t smbpr_type;		/* processor type (see <smbios.h>) */
	uint8_t smbpr_family;		/* processor family (see <smbios.h>) */
	uint8_t smbpr_manufacturer;	/* manufacturer */
	uint64_t smbpr_cpuid;		/* processor cpuid information */
	uint8_t smbpr_version;		/* version */
	uint8_t smbpr_voltage;		/* voltage */
	uint16_t smbpr_clkspeed;	/* external clock speed in MHz */
	uint16_t smbpr_maxspeed;	/* maximum speed in MHz */
	uint16_t smbpr_curspeed;	/* current speed in MHz */
	uint8_t smbpr_status;		/* status (see <smbios.h>) */
	uint8_t smbpr_upgrade;		/* upgrade */
	uint16_t smbpr_l1cache;		/* L1 cache handle (if any) */
	uint16_t smbpr_l2cache;		/* L2 cache handle (if any) */
	uint16_t smbpr_l3cache;		/* L3 cache handle (if any) */
	uint8_t smbpr_serial;		/* serial number */
	uint8_t smbpr_asset;		/* asset tag */
	uint8_t smbpr_part;		/* part number */
	uint8_t smbpr_corecount;	/* number of cores per socket */
	uint8_t smbpr_coresenabled;	/* number of enabled cores per socket */
	uint8_t smbpr_threadcount;	/* number of threads per socket */
	uint16_t smbpr_cflags;	/* cpu characteristics (see <smbios.h>) */
	uint16_t smbpr_family2;		/* processor family2 (see <smbios.h>) */
	uint16_t smbpr_corecount2;	/* second number of cores per socket */
	uint16_t smbpr_coresenabled2;	/* second number of enabled cores */
	uint16_t smbpr_threadcount2;	/* second number of enabled threads */
} smb_processor_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_CACHE.
 */
typedef struct smb_cache {
	smb_header_t smbca_hdr;		/* structure header */
	uint8_t smbca_socket;		/* socket designation */
	uint16_t smbca_config;		/* cache configuration */
	uint16_t smbca_maxsize;		/* maximum installed size */
	uint16_t smbca_size;		/* installed size */
	uint16_t smbca_stype;		/* supported SRAM type */
	uint16_t smbca_ctype;		/* current SRAM type */
	uint8_t smbca_speed;		/* speed in nanoseconds */
	uint8_t smbca_etype;		/* error correction type */
	uint8_t smbca_ltype;		/* logical cache type */
	uint8_t smbca_assoc;		/* associativity */
	uint32_t smbca_maxsize2;	/* maximum installed size 2 */
	uint32_t smbca_size2;		/* installed size 2 */
} smb_cache_t;

/*
 * Convert encoded cache size to bytes: DSP0134 Section 7.8 explains the
 * encoding.  The highest bit is 0 for 1k units, 1 for 64k units, and this
 * macro decodes the value into bytes for exporting to our clients.
 */
#define	SMB_CACHE_SIZE(s)	(((s) & 0x8000) ? \
	((uint32_t)((s) & 0x7FFF) * 64 * 1024) : ((uint32_t)(s) * 1024))

#define	SMB_CACHE_EXT_SIZE(s)	(((s) & 0x80000000U) ? 	\
	((uint64_t)((s) & 0x7FFFFFFFULL) * 64ULL * 1024ULL) : 	\
	((uint64_t)(s) * 1024ULL))

#define	SMB_CACHE_CFG_MODE(c)		(((c) >> 8) & 3)
#define	SMB_CACHE_CFG_ENABLED(c)	(((c) >> 7) & 1)
#define	SMB_CACHE_CFG_LOCATION(c)	(((c) >> 5) & 3)
#define	SMB_CACHE_CFG_SOCKETED(c)	(((c) >> 3) & 1)
#define	SMB_CACHE_CFG_LEVEL(c)		(((c) & 7) + 1)

/*
 * SMBIOS implementation structure for SMB_TYPE_PORT.
 */
typedef struct smb_port {
	smb_header_t smbpo_hdr;		/* structure header */
	uint8_t smbpo_iref;		/* internal reference designator */
	uint8_t smbpo_itype;		/* internal connector type */
	uint8_t smbpo_eref;		/* external reference designator */
	uint8_t smbpo_etype;		/* external connector type */
	uint8_t smbpo_ptype;		/* port type */
} smb_port_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_SLOT.
 */
typedef struct smb_slot {
	smb_header_t smbsl_hdr;		/* structure header */
	uint8_t smbsl_name;		/* reference designation */
	uint8_t smbsl_type;		/* slot type */
	uint8_t smbsl_width;		/* slot data bus width */
	uint8_t smbsl_usage;		/* current usage */
	uint8_t smbsl_length;		/* slot length */
	uint16_t smbsl_id;		/* slot ID */
	uint8_t smbsl_ch1;		/* slot characteristics 1 */
	uint8_t smbsl_ch2;		/* slot characteristics 2 */
	uint16_t smbsl_sg;		/* segment group number */
	uint8_t smbsl_bus;		/* bus number */
	uint8_t smbsl_df;		/* device/function number */
} smb_slot_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_OBDEVS.
 */
typedef struct smb_obdev {
	uint8_t smbob_type;		/* encoded type and enable bit */
	uint8_t smbob_name;		/* description string */
} smb_obdev_t;

#define	SMB_OBT_ENABLED		0x80	/* enable bit within smbob_type */

/*
 * SMBIOS implementation structure for SMB_TYPE_OEMSTR, SMB_TYPE_SYSCONFSTR,
 * and SMB_TYPE_LANG.
 */
typedef struct smb_strtab {
	smb_header_t smbtb_hdr;		/* structure header */
	uint8_t smbtb_count;		/* number of strings */
} smb_strtab_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_LANG.
 */
typedef struct smb_lang {
	smb_header_t smblang_hdr;	/* structure header */
	uint8_t smblang_num;		/* number of installed languages */
	uint8_t smblang_flags;		/* flags */
	uint8_t smblang_resv[15];	/* reserved for future use */
	uint8_t smblang_cur;		/* current language string */
} smb_lang_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_EVENTLOG.
 */
typedef struct smb_sel {
	smb_header_t smbsel_hdr;	/* structure header */
	uint16_t smbsel_len;		/* log area length */
	uint16_t smbsel_hdroff;		/* header offset */
	uint16_t smbsel_dataoff;	/* data offset */
	uint8_t smbsel_method;		/* access method */
	uint8_t smbsel_status;		/* status flags */
	uint32_t smbsel_token;		/* change token */
	uint32_t smbsel_addr;		/* access method address */
	uint8_t smbsel_format;		/* header format */
	uint8_t smbsel_typec;		/* number of type descriptors */
	uint8_t smbsel_typesz;		/* size of each type descriptor */
	uint8_t smbsel_typev[1];	/* array of type descriptors */
} smb_sel_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_MEMARRAY.
 */
typedef struct smb_memarray {
	smb_header_t smbmarr_hdr;	/* structure header */
	uint8_t smbmarr_loc;		/* location */
	uint8_t smbmarr_use;		/* use */
	uint8_t smbmarr_ecc;		/* error detect/correct mechanism */
	uint32_t smbmarr_cap;		/* maximum capacity */
	uint16_t smbmarr_err;		/* error handle */
	uint16_t smbmarr_ndevs;		/* number of slots or sockets */
	uint64_t smbmarr_extcap;	/* extended maximum capacity */
} smb_memarray_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_MEMARRAYMAP.
 */
typedef struct smb_memarrmap {
	smb_header_t smbamap_hdr;	/* structure header */
	uint32_t smbamap_start;		/* starting address in kilobytes */
	uint32_t smbamap_end;		/* ending address in kilobytes */
	uint16_t smbamap_array;		/* physical memory array handle */
	uint8_t smbamap_width;		/* partition width */
	uint64_t smbamap_extstart;	/* extended starting address in bytes */
	uint64_t smbamap_extend;	/* extended ending address in bytes */
} smb_memarrmap_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_MEMDEVICE.
 */
typedef struct smb_memdevice {
	smb_header_t smbmdev_hdr;	/* structure header */
	uint16_t smbmdev_array;		/* array handle */
	uint16_t smbmdev_error;		/* error handle */
	uint16_t smbmdev_twidth;	/* total width */
	uint16_t smbmdev_dwidth;	/* data width */
	uint16_t smbmdev_size;		/* size in either K or MB */
	uint8_t smbmdev_form;		/* form factor */
	uint8_t smbmdev_set;		/* device set */
	uint8_t smbmdev_dloc;		/* device locator */
	uint8_t smbmdev_bloc;		/* bank locator */
	uint8_t smbmdev_type;		/* memory type */
	uint16_t smbmdev_flags;		/* detail flags */
	uint16_t smbmdev_speed;		/* speed in MT/s */
	uint8_t smbmdev_manufacturer;	/* manufacturer */
	uint8_t smbmdev_serial;		/* serial number */
	uint8_t smbmdev_asset;		/* asset tag */
	uint8_t smbmdev_part;		/* part number */
	uint8_t smbmdev_attrs;		/* attributes */
	uint32_t smbmdev_extsize;	/* extended size */
	uint16_t smbmdev_clkspeed;	/* configured clock speed */
	uint16_t smbmdev_minvolt;	/* minimum voltage */
	uint16_t smbmdev_maxvolt;	/* maximum voltage */
	uint16_t smbmdev_confvolt;	/* configured voltage */
} smb_memdevice_t;

#define	SMB_MDS_KBYTES		0x8000	/* size in specified in kilobytes */

/*
 * SMBIOS implementation structure for SMB_TYPE_MEMDEVICEMAP.
 */
typedef struct smb_memdevmap {
	smb_header_t smbdmap_hdr;	/* structure header */
	uint32_t smbdmap_start;		/* starting address in kilobytes */
	uint32_t smbdmap_end;		/* ending address in kilobytes */
	uint16_t smbdmap_device;	/* memory device handle */
	uint16_t smbdmap_array;		/* memory array mapped address handle */
	uint8_t smbdmap_rpos;		/* row position */
	uint8_t smbdmap_ipos;		/* interleave position */
	uint8_t smbdmap_idepth;		/* interleave depth */
	uint64_t smbdmap_extstart;	/* extended starting address */
	uint64_t smbdmap_extend;	/* extended ending address */
} smb_memdevmap_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_BATTERY.
 */
typedef struct smb_battery {
	smb_header_t smbbat_hdr;	/* structure header */
	uint8_t smbbat_loc;		/* location */
	uint8_t smbbat_manufacturer;	/* manufacturer */
	uint8_t smbbat_date;		/* manufacture date */
	uint8_t smbbat_serial;		/* serial number */
	uint8_t smbbat_devname;		/* device name */
	uint8_t smbbat_chem;		/* device chemistry */
	uint16_t smbbat_cap;		/* design capacity in mW hours */
	uint16_t smbbat_volt;		/* design voltage in mV */
	uint8_t smbbat_version;		/* SBDS version string */
	uint8_t smbbat_err;		/* error percentage */
	uint16_t smbbat_ssn;		/* SBDS serial number */
	uint16_t smbbat_sdate;		/* SBDS manufacture date */
	uint8_t smbbat_schem;		/* SBDS chemistry string */
	uint8_t smbbat_mult;		/* design capacity multiplier */
	uint32_t smbbat_oemdata;	/* OEM-specific data */
} smb_battery_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_SECURITY.
 */
typedef struct smb_hwsec {
	smb_header_t smbhs_hdr;		/* structure header */
	uint8_t smbhs_settings;		/* settings byte */
} smb_hwsec_t;

#define	SMB_HWS_PWR_PS(x)	(((x) & 0xC0) >> 6)
#define	SMB_HWS_KBD_PS(x)	(((x) & 0x30) >> 4)
#define	SMB_HWS_ADM_PS(x)	(((x) & 0x0C) >> 2)
#define	SMB_HWS_PAN_PS(x)	(((x) & 0x03) >> 0)

/*
 * SMBIOS implementation structure for SMB_TYPE_VPROBE.
 */
typedef struct smb_vprobe {
	smb_header_t smbvpr_hdr;	/* structure header */
	uint8_t smbvpr_descr;		/* description string */
	uint8_t smbvpr_locstat;		/* location and status */
	uint16_t smbvpr_maxval;		/* maximum voltage */
	uint16_t smbvpr_minval;		/* minimum voltage */
	uint16_t smbvpr_resolution;	/* probe resolution */
	uint16_t smbvpr_tolerance;	/* probe tolerance */
	uint16_t smbvpr_accuracy;	/* probe accuracy */
	uint32_t smbvpr_oem;		/* vendor-specific data */
	uint16_t smbvpr_nominal;	/* nominal value */
} smb_vprobe_t;

#define	SMB_VPROBE_MINLEN		0x14
#define	SMB_VPROBE_NOMINAL_MINLEN	0x16

#define	SMB_VPROBE_LOCATION(x)	((x) & 0x1f)
#define	SMB_VPROBE_STATUS(x)	(((x) >> 5) & 0x7)

/*
 * SMBIOS implementation structure for SMB_TYPE_COOLDEV.
 */
typedef struct smb_cooldev {
	smb_header_t smbcdev_hdr;	/* structure header */
	uint16_t smbcdev_tprobe;	/* temperature probe */
	uint8_t smbcdev_typstat;	/* type and status */
	uint8_t smbcdev_group;		/* group identifier */
	uint32_t smbcdev_oem;		/* vendor-specific data */
	uint16_t smbcdev_nominal;	/* nominal value */
	uint8_t smbcdev_descr;		/* description string */
} smb_cooldev_t;

#define	SMB_COOLDEV_MINLEN		0x0c
#define	SMB_COOLDEV_NOMINAL_MINLEN	0x0e
#define	SMB_COOLDEV_DESCR_MINLEN	0x0f

#define	SMB_COOLDEV_TYPE(x)	((x) & 0x1f)
#define	SMB_COOLDEV_STATUS(x)	(((x) >> 5) & 0x7)

/*
 * SMBIOS implementation structure for SMB_TYPE_TPROBE.
 */
typedef struct smb_tprobe {
	smb_header_t smbtpr_hdr;	/* structure header */
	uint8_t smbtpr_descr;		/* description string */
	uint8_t smbtpr_locstat;		/* location and status */
	uint16_t smbtpr_maxval;		/* maximum temperature */
	uint16_t smbtpr_minval;		/* minimum temperature */
	uint16_t smbtpr_resolution;	/* probe resolution */
	uint16_t smbtpr_tolerance;	/* probe tolerance */
	uint16_t smbtpr_accuracy;	/* probe accuracy */
	uint32_t smbtpr_oem;		/* vendor-specific data */
	uint16_t smbtpr_nominal;	/* nominal value */
} smb_tprobe_t;

#define	SMB_TPROBE_MINLEN		0x14
#define	SMB_TPROBE_NOMINAL_MINLEN	0x16

#define	SMB_TPROBE_LOCATION(x)	((x) & 0x1f)
#define	SMB_TPROBE_STATUS(x)	(((x) >> 5) & 0x7)

/*
 * SMBIOS implementation structure for SMB_TYPE_IPROBE.
 */
typedef struct smb_iprobe {
	smb_header_t smbipr_hdr;	/* structure header */
	uint8_t smbipr_descr;		/* description string */
	uint8_t smbipr_locstat;		/* location and status */
	uint16_t smbipr_maxval;		/* maximum current */
	uint16_t smbipr_minval;		/* minimum current */
	uint16_t smbipr_resolution;	/* probe resolution */
	uint16_t smbipr_tolerance;	/* probe tolerance */
	uint16_t smbipr_accuracy;	/* probe accuracy */
	uint32_t smbipr_oem;		/* vendor-specific data */
	uint16_t smbipr_nominal;	/* nominal value */
} smb_iprobe_t;

#define	SMB_IPROBE_MINLEN		0x14
#define	SMB_IPROBE_NOMINAL_MINLEN	0x16

#define	SMB_IPROBE_LOCATION(x)	((x) & 0x1f)
#define	SMB_IPROBE_STATUS(x)	(((x) >> 5) & 0x7)

/*
 * SMBIOS implementation structure for SMB_TYPE_BOOT.
 */
typedef struct smb_boot {
	smb_header_t smbbo_hdr;		/* structure header */
	uint8_t smbbo_pad[6];		/* reserved for future use */
	uint8_t smbbo_status[1];	/* variable-length status buffer */
} smb_boot_t;

/*
 * SMBIOS implementation structure for SMB_TYPE_IPMIDEV.
 */
typedef struct smb_ipmi {
	smb_header_t smbipm_hdr;	/* structure header */
	uint8_t smbipm_type;		/* interface type */
	uint8_t smbipm_spec;		/* specification revision */
	uint8_t smbipm_i2c;		/* i2C slave address */
	uint8_t smbipm_bus;		/* NV storage device bus ID */
	uint64_t smbipm_addr;		/* base address */
	uint8_t smbipm_info;		/* base address modifier/intr info */
	uint8_t smbipm_intr;		/* interrupt number */
} smb_ipmi_t;

#define	SMB_IPM_SPEC_MAJOR(x)	(((x) & 0xF0) >> 4)
#define	SMB_IPM_SPEC_MINOR(x)	((x) & 0x0F)

#define	SMB_IPM_ADDR_IO		1ULL

#define	SMB_IPM_INFO_REGS(x)	(((x) & 0xC0) >> 6)
#define	SMB_IPM_INFO_LSB(x)	(((x) & 0x10) >> 4)
#define	SMB_IPM_INFO_ISPEC(x)	(((x) & 0x08) >> 3)
#define	SMB_IPM_INFO_IPOL(x)	(((x) & 0x02) >> 1)
#define	SMB_IPM_INFO_IMODE(x)	(((x) & 0x01) >> 0)

#define	SMB_IPM_REGS_1B		0
#define	SMB_IPM_REGS_4B		1
#define	SMB_IPM_REGS_16B	2

#define	SMB_IPM_IPOL_LO		0
#define	SMB_IPM_IPOL_HI		1

#define	SMB_IPM_IMODE_EDGE	0
#define	SMB_IPM_IMODE_LEVEL	1

/*
 * SMBIOS implementation structure for SMB_TYPE_POWERSUP.
 */
typedef struct smb_powersup {
	smb_header_t smbpsup_hdr;	/* structure header */
	uint8_t smbpsup_group;		/* group id */
	uint8_t smbpsup_loc;		/* location tag */
	uint8_t smbpsup_devname;	/* device name */
	uint8_t smbpsup_manufacturer;	/* manufacturer */
	uint8_t smbpsup_serial;		/* serial number */
	uint8_t smbpsup_asset;		/* asset tag */
	uint8_t smbpsup_part;		/* part number */
	uint8_t smbpsup_rev;		/* revision string */
	uint16_t smbpsup_max;		/* max output in milliwatts */
	uint16_t smbpsup_char;		/* characteristics */
	uint16_t smbpsup_vprobe;	/* voltage probe handle */
	uint16_t smbpsup_cooldev;	/* cooling device handle */
	uint16_t smbpsup_iprobe;	/* current probe handle */
} smb_powersup_t;

#define	SMB_PSU_CHARS_ISHOT(x)		((x) & 0x01)
#define	SMB_PSU_CHARS_ISPRES(x)		((x) & 0x02)
#define	SMB_PSU_CHARS_ISUNPLUG(x)	((x) & 0x04)
#define	SMB_PSU_CHARS_IVRS(x)		(((x) >> 3) & 0xf)
#define	SMB_PSU_CHARS_STATUS(x)		(((x) >> 7) & 0x7)
#define	SMB_PSU_CHARS_TYPE(x)		(((x) >> 10) & 0xf)

/*
 * SMBIOS implementation structure for SMB_TYPE_OBDEVEXT.
 */
typedef struct smb_obdev_ext {
	smb_header_t smbobe_hdr;	/* structure header */
	uint8_t smbobe_name;		/* reference designation */
	uint8_t smbobe_dtype;		/* device type */
	uint8_t smbobe_dti;		/* device type instance */
	uint16_t smbobe_sg;		/* segment group number */
	uint8_t smbobe_bus;		/* bus number */
	uint8_t smbobe_df;		/* device/function number */
} smb_obdev_ext_t;

/*
 * SMBIOS implementation structure for SUN_OEM_EXT_PROCESSOR.
 */
typedef struct smb_processor_ext {
	smb_header_t smbpre_hdr;	/* structure header */
	uint16_t smbpre_processor;	/* processor handle */
	uint8_t smbpre_fru;		/* FRU indicator */
	uint8_t smbpre_n;		/* number of APIC IDs */
	uint16_t smbpre_apicid[1];	/* strand initial apic id */
} smb_processor_ext_t;

/*
 * SMBIOS implementation structure for SUN_OEM_EXT_PORT.
 */
typedef struct smb_port_ext {
	smb_header_t smbpoe_hdr;	/* structure header */
	uint16_t smbpoe_chassis;	/* chassis handle */
	uint16_t smbpoe_port;		/* port connector handle */
	uint8_t smbpoe_dtype;		/* device type */
	uint16_t smbpoe_devhdl;		/* device handle */
	uint8_t smbpoe_phy;		/* PHY number */
} smb_port_ext_t;

/*
 * SMBIOS implementation structure for SUN_OEM_PCIEXRC.
 */
typedef struct smb_pciexrc {
	smb_header_t smbpciexrc_hdr;	/* structure header */
	uint16_t smbpciexrc_bboard;	/* base board handle */
	uint16_t smbpciexrc_bdf;	/* PCI Bus/Dev/Func */
} smb_pciexrc_t;

/*
 * SMBIOS implementation structure for SUN_OEM_EXT_MEMARRAY.
 */
typedef struct smb_memarray_ext {
	smb_header_t smbmarre_hdr;	/* structure header */
	uint16_t smbmarre_ma;		/* memory array handle */
	uint16_t smbmarre_component;	/* component parent handle */
	uint16_t smbmarre_bdf;		/* PCI bus/dev/funct */
} smb_memarray_ext_t;

/*
 * SMBIOS implementation structure for SUN_OEM_EXT_MEMDEVICE.
 */
typedef struct smb_memdevice_ext {
	smb_header_t smbmdeve_hdr;	/* structure header */
	uint16_t smbmdeve_mdev;		/* memory device handle */
	uint8_t smbmdeve_dchan;		/* DRAM channel */
	uint8_t smbmdeve_ncs;		/* number of chip select */
	uint8_t smbmdeve_cs[1];		/* chip selects */
} smb_memdevice_ext_t;

#pragma pack()

typedef struct smb_struct {
	const smb_header_t *smbst_hdr;	/* address of raw structure data */
	const uchar_t *smbst_str;	/* address of string data (if any) */
	const uchar_t *smbst_end;	/* address of 0x0000 ending tag */
	struct smb_struct *smbst_next; 	/* next structure in hash chain */
	uint16_t *smbst_strtab;		/* string index -> offset table */
	uint_t smbst_strtablen;		/* length of smbst_strtab */
} smb_struct_t;

struct smbios_hdl {
	smbios_entry_point_t sh_ent_type; /* structure table entry point type */
	smbios_entry_t sh_ent;		/* structure table entry point */
	uint_t sh_ent_stnum;		/* number of structure table entries */
	const void *sh_buf;		/* structure table buffer */
	size_t sh_buflen;		/* size of structure table buffer */
	smb_struct_t *sh_structs;	/* array of structure descriptors */
	uint_t sh_nstructs;		/* number of active structures */
	smb_struct_t **sh_hash;		/* hash bucket array for descriptors */
	uint_t sh_hashlen;		/* hash bucket array length */
	int sh_err;			/* error code for smbios_errno() */
	int sh_libvers;			/* library client abi version */
	int sh_smbvers;			/* derived underlying format version */
	uint_t sh_flags;		/* miscellaneous flags (see below) */
};

#define	SMB_FL_DEBUG	0x1		/* print debug messages for this hdl */
#define	SMB_FL_BUFALLOC	0x2		/* sh_buf was allocated by library */
#define	SMB_FL_TRUNC	0x4		/* smbios table is truncated */

#define	SMB_BIOS_DEVICE		"/dev/xsvc"	/* device w/ BIOS physmem */
#define	SMB_SMBIOS_DEVICE	"/dev/smbios"	/* device w/ SMBIOS image */

#define	SMB_RANGE_START	0xF0000		/* start of physical address range */
#define	SMB_RANGE_LIMIT	0xFFFFF		/* limit of physical address range */
#define	SMB_SCAN_STEP	16		/* stepping by paragraph */

#define	SMB_MAJMIN(M, m)	((((M) & 0xFF) << 8) | ((m) & 0xFF))
#define	SMB_MAJOR(v)		(((v) & 0xFF00) >> 8)
#define	SMB_MINOR(v)		(((v) & 0x00FF))

#define	ESMB_BASE	1000		/* base value for libsmbios errnos */

enum {
	ESMB_NOTFOUND = ESMB_BASE,	/* SMBIOS table not found on system */
	ESMB_MAPDEV,			/* failed to map SMBIOS table */
	ESMB_NOENT,			/* failed to locate structure */
	ESMB_NOMEM,			/* failed to allocate memory */
	ESMB_NOHDR,			/* failed to read SMBIOS header */
	ESMB_NOSTAB,			/* failed to read SMBIOS struct table */
	ESMB_NOINFO,			/* no common info for structure */
	ESMB_SHORT,			/* buffer length doesn't match header */
	ESMB_CORRUPT,			/* buffer struct or len is corrupt */
	ESMB_VERSION,			/* version not supported by library */
	ESMB_NOTSUP,			/* feature not supported by provider */
	ESMB_HEADER,			/* SMBIOS header corrupt or invalid */
	ESMB_OLD,			/* SMBIOS version is too old for us */
	ESMB_NEW,			/* SMBIOS version is too new for us */
	ESMB_CKSUM,			/* SMBIOS header checksum mismatch */
	ESMB_INVAL,			/* invalid function call argument */
	ESMB_TYPE,			/* structure type mismatch */
	ESMB_UNKNOWN			/* unknown error (maximum value tag) */
};

extern const smb_struct_t *smb_lookup_type(smbios_hdl_t *, uint_t);
extern const smb_struct_t *smb_lookup_id(smbios_hdl_t *, uint_t);
extern const char *smb_strptr(const smb_struct_t *, uint_t);
extern int smb_gteq(smbios_hdl_t *, int);
extern int smb_libgteq(smbios_hdl_t *, int);

extern int smb_set_errno(smbios_hdl_t *, int);
extern smbios_hdl_t *smb_open_error(smbios_hdl_t *, int *, int);
extern const char *smb_strerror(int);

extern void *smb_alloc(size_t);
extern void *smb_zalloc(size_t);
extern void smb_free(void *, size_t);

extern void smb_dprintf(smbios_hdl_t *, const char *, ...);

extern int _smb_debug;

/*
 * The following series of structures represent the base versions of public
 * structures that are used inside by the smbios routines. This allows the
 * common code to properly know how much it should or should not bzero and how
 * to handle additions to the spec. Types should only be added here if we need
 * to extend the public structures in sys/smbios.h due to a change in the spec.
 *
 * Types here have the name smb_base_%s which corresponds to smbios_%s.
 */
typedef struct smb_base_chassis {
	uint32_t smbbc_oemdata;		/* OEM-specific data */
	uint8_t smbbc_lock;		/* lock present? */
	uint8_t smbbc_type;		/* type */
	uint8_t smbbc_bustate;		/* boot-up state */
	uint8_t smbbc_psstate;		/* power supply state */
	uint8_t smbbc_thstate;		/* thermal state */
	uint8_t smbbc_security;		/* security status */
	uint8_t smbbc_uheight;		/* enclosure height in U's */
	uint8_t smbbc_cords;		/* number of power cords */
	uint8_t smbbc_elems;		/* number of element records (n) */
	uint8_t smbbc_elemlen;		/* length of contained element (m) */
} smb_base_chassis_t;

typedef struct smb_base_processor {
	uint64_t smbbp_cpuid;		/* processor cpuid information */
	uint32_t smbbp_family;		/* processor family */
	uint8_t smbbp_type;		/* processor type (SMB_PRT_*) */
	uint8_t smbbp_voltage;		/* voltage (SMB_PRV_*) */
	uint8_t smbbp_status;		/* status (SMB_PRS_*) */
	uint8_t smbbp_upgrade;		/* upgrade (SMB_PRU_*) */
	uint32_t smbbp_clkspeed;	/* external clock speed in MHz */
	uint32_t smbbp_maxspeed;	/* maximum speed in MHz */
	uint32_t smbbp_curspeed;	/* current speed in MHz */
	id_t smbbp_l1cache;		/* L1 cache handle */
	id_t smbbp_l2cache;		/* L2 cache handle */
	id_t smbbp_l3cache;		/* L3 cache handle */
} smb_base_processor_t;

typedef struct smb_base_memdevice {
	id_t smbbmd_array;		/* handle of physical memory array */
	id_t smbbmd_error;		/* handle of memory error data */
	uint32_t smbbmd_twidth;		/* total width in bits including ecc */
	uint32_t smbbmd_dwidth;		/* data width in bits */
	uint64_t smbbmd_size;		/* size in bytes (see note above) */
	uint8_t smbbmd_form;		/* form factor */
	uint8_t smbbmd_set;		/* set (0x00=none, 0xFF=unknown) */
	uint8_t smbbmd_type;		/* memory type */
	uint8_t smbbmd_pad;		/* padding */
	uint32_t smbbmd_flags;		/* flags (see below) */
	uint32_t smbbmd_speed;		/* speed in MHz */
	const char *smbbmd_dloc;	/* physical device locator string */
	const char *smbbmd_bloc;	/* physical bank locator string */
	uint8_t smbbmd_rank;		/* rank */
} smb_base_memdevice_t;

typedef struct smb_base_bios {
	const char *smbbb_vendor;	/* bios vendor string */
	const char *smbbb_version;	/* bios version string */
	const char *smbbb_reldate;	/* bios release date */
	uint32_t smbbb_segment;		/* bios address segment location */
	uint32_t smbbb_romsize;		/* bios rom size in bytes */
	uint32_t smbbb_runsize;		/* bios image size in bytes */
	uint64_t smbbb_cflags;		/* bios characteristics */
	const uint8_t *smbbb_xcflags;	/* bios characteristics extensions */
	size_t smbbb_nxcflags;		/* number of smbb_xcflags[] bytes */
	smbios_version_t smbbb_biosv;	/* bios version */
	smbios_version_t smbbb_ecfwv;	/* bios embedded ctrl f/w version */
} smb_base_bios_t;

typedef struct smb_base_cache {
	uint32_t smbba_maxsize;		/* maximum installed size in bytes */
	uint32_t smbba_size;		/* installed size in bytes */
	uint16_t smbba_stype;		/* supported SRAM types (SMB_CAT_*) */
	uint16_t smbba_ctype;		/* current SRAM type (SMB_CAT_*) */
	uint8_t smbba_speed;		/* speed in nanoseconds */
	uint8_t smbba_etype;		/* error correction type (SMB_CAE_*) */
	uint8_t smbba_ltype;		/* logical cache type (SMB_CAG_*) */
	uint8_t smbba_assoc;		/* associativity (SMB_CAA_*) */
	uint8_t smbba_level;		/* cache level */
	uint8_t smbba_mode;		/* cache mode (SMB_CAM_*) */
	uint8_t smbba_location;		/* cache location (SMB_CAL_*) */
	uint8_t smbba_flags;		/* cache flags (SMB_CAF_*) */
} smb_base_cache_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMBIOS_IMPL_H */
