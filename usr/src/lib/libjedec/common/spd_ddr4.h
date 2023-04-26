/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SPD_DDR4_H
#define	_SPD_DDR4_H

/*
 * Definitions for use in DDR4 Serial Presence Detect decoding based on JEDEC
 * Standard 21-C Annex L: Serial Presence Detect (SPD) for DDR4 SDRAM Modules
 * Release 6.
 *
 * DDR4 modules are organized into a few main regions:
 *
 *   o Base Configuration and DRAM parameters (bytes 0x00-0x7f)
 *   o Standard Module Parameters (bytes 0x80-0xbf) these vary on whether
 *     something is considered an RDIMM, UDIMM, LRDIMM, etc.
 *   o Hybrid Module Parameters (bytes 0xc0-0xff)
 *   o Hybrid Module Extended Parameters (bytes 0x100-0x13f).
 *   o Manufacturing Information (bytes 0x140-0x17f)
 *   o End User Programmable data (0x180-0x1ff).
 *
 * This does not currently provide definitions for DDR4 NVDIMMs.
 */

#include <sys/bitext.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S8.1.1 Number of Bytes Used / Number of Bytes in SPD Device.
 */
#define	SPD_DDR4_NBYTES	0x000
#define	SPD_DDR4_NBYTES_USED(r)		bitx8(r, 3, 0)
#define	SPD_DDR4_NBYTES_USED_UNDEF	0
#define	SPD_DDR4_NBYTES_USED_128	1
#define	SPD_DDR4_NBYTES_USED_256	2
#define	SPD_DDR4_NBYTES_USED_384	3
#define	SPD_DDR4_NBYTES_USED_512	4
#define	SPD_DDR4_NBYTES_TOTAL(r)	bitx8(r, 6, 4)
#define	SPD_DDR4_NBYTES_TOTAL_UNDEF	0
#define	SPD_DDR4_NBYTES_TOTAL_256	1
#define	SPD_DDR4_NBYTES_TOTAL_512	2

/*
 * S8.1.2: SPD Revision. The SPD revision is split into two 4-bit fields. There
 * is an encoding level and an additions level. This can be somewhat thought of
 * like a major and minor version. The upper 4-bit encoding level tells us
 * whether or not we can parse it. The additions level just says what's been
 * added, but it doesn't reset across major versions.
 *
 * Currently all DDR4 devices are at encoding revision 1. The additions level
 * varies based on the type of DDR4 device (RDIMM, UDIMM, etc.).
 */
#define	SPD_DDR4_SPD_REV	0x001
#define	SPD_DDR4_SPD_REV_ENC(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_SPD_REV_ADD(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_SPD_REV_V1	1

/*
 * S8.1.3: Key Byte / DRAM Device Type. This field identifies the type of DDR
 * device and is actually consistent across all SPD versions. Known values are
 * in the spd_dram_type_t enumeration.
 */
#define	SPD_DDR4_DRAM_TYPE	0x002

/*
 * S8.1.4: Key Byte / Module type. This is used to describe what kind of DDR
 * module it is, which tell us what the module-specific section contents are.
 * These bits, unlike the one above are device specific.
 */
#define	SPD_DDR4_MOD_TYPE	0x003
#define	SPD_DDR4_MOD_TYPE_ISHYBRID(r)	bitx8(r, 7, 7)
#define	SPD_DDR4_MOD_TYPE_HYBRID(r)	bitx8(r, 6, 4)
#define	SPD_DDR4_MOD_TYPE_HYBRID_NONE		0
#define	SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_NF	1
#define	SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_P	2
#define	SPD_DDR4_MOD_TYPE_HYBRID_NVDIMM_H	3
#define	SPD_DDR4_MOD_TYPE_TYPE(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_MOD_TYPE_TYPE_EXT		0
#define	SPD_DDR4_MOD_TYPE_TYPE_RDIMM		1
#define	SPD_DDR4_MOD_TYPE_TYPE_UDIMM		2
#define	SPD_DDR4_MOD_TYPE_TYPE_SODIMM		3
#define	SPD_DDR4_MOD_TYPE_TYPE_LRDIMM		4
#define	SPD_DDR4_MOD_TYPE_TYPE_MINI_RDIMM	5
#define	SPD_DDR4_MOD_TYPE_TYPE_MINI_UDIMM	6
#define	SPD_DDR4_MOD_TYPE_TYPE_72b_SORDIMM	8
#define	SPD_DDR4_MOD_TYPE_TYPE_72b_SOUDIMM	9
#define	SPD_DDR4_MOD_TYPE_TYPE_16b_SODIMM	12
#define	SPD_DDR4_MOD_TYPE_TYPE_32b_SODIMM	13

/*
 * S8.1.5 SDRAM Density and Banks.
 */
#define	SPD_DDR4_DENSITY	0x004
#define	SPD_DDR4_DENSITY_NBG_BITS(r)	bitx8(r, 7, 6)
#define	SPD_DDR4_DENSITY_NBG_BITS_MAX	2
#define	SPD_DDR4_DENSITY_NBA_BITS(r)	bitx8(r, 5, 4)
#define	SPD_DDR4_DENSITY_NBA_BITS_BASE	2
#define	SPD_DDR4_DENSITY_NBA_BITS_MAX	3
#define	SPD_DDR4_DENSITY_DENSITY(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_DENSITY_DENSITY_256Mb	0
#define	SPD_DDR4_DENSITY_DENSITY_512Mb	1
#define	SPD_DDR4_DENSITY_DENSITY_1Gb	2
#define	SPD_DDR4_DENSITY_DENSITY_2Gb	3
#define	SPD_DDR4_DENSITY_DENSITY_4Gb	4
#define	SPD_DDR4_DENSITY_DENSITY_8Gb	5
#define	SPD_DDR4_DENSITY_DENSITY_16Gb	6
#define	SPD_DDR4_DENSITY_DENSITY_32Gb	7
#define	SPD_DDR4_DENSITY_DENSITY_12Gb	8
#define	SPD_DDR4_DENSITY_DENSITY_24Gb	9

/*
 * S8.1.6 SDRAM Addressing.
 */
#define	SPD_DDR4_ADDR	0x005
#define	SPD_DDR4_ADDR_NROWS(r)	bitx8(r, 5, 3)
#define	SPD_DDR4_ADDR_NROWS_BASE	12
#define	SPD_DDR4_ADDR_NROWS_MAX		18
#define	SPD_DDR4_ADDR_NCOLS(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_ADDR_NCOLS_BASE	9
#define	SPD_DDR4_ADDR_NCOLS_MAX		12

/*
 * S8.1.7 Primary SDRAM Package Type
 * S8.1.11 Secondary SDRAM Package Type
 *
 * This contains information about the package types that are present. The
 * secondary is only used when asymmetrical SDRAM types are present. These are
 * generally the same bits and meanings, with the one exception that the bits
 * 3:2 must be 0 in the primary. As such, we try to reuse definitions. In the
 * ratio macros, the 1S and 2S refer to the fact that they are 1 and 2 module
 * densities smaller.
 */
#define	SPD_DDR4_PRI_PKG	0x006
#define	SPD_DDR4_SEC_PKG	0x00a
#define	SPD_DDR4_PKG_TYPE(r)	bitx8(r, 7, 7)
#define	SPD_DDR4_PKG_TYPE_MONO	0
#define	SPD_DDR4_PKG_TYPE_NOT	1
#define	SPD_DDR4_PKG_DIE_CNT(r)	bitx8(r, 6, 4)
#define	SPD_DDR4_PKG_DIE_CNT_BASE	1
#define	SPD_DDR4_SEC_PKG_RATIO(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_SEC_PKG_RATIO_EQ	0
#define	SPD_DDR4_SEC_PKG_RATIO_1S	1
#define	SPD_DDR4_SEC_PKG_RATIO_2S	2
#define	SPD_DDR4_PKG_SIG_LOAD(r)	bitx8(r, 1, 0)
#define	SPD_DDR4_PKG_SIG_LOAD_UNSPEC	0
#define	SPD_DDR4_PKG_SIG_LOAD_MULTI	1
#define	SPD_DDR4_PKG_SIG_LOAD_SINGLE	2

/*
 * S8.1.8 SDRAM Optional Features.
 */
#define	SPD_DDR4_OPT_FEAT	0x007
#define	SPD_DDR4_OPT_FEAT_MAW(r)	bitx8(r, 5, 4)
#define	SPD_DDR4_OPT_FEAT_MAW_8192X	0
#define	SPD_DDR4_OPT_FEAT_MAW_4096X	1
#define	SPD_DDR4_OPT_FEAT_MAW_2048X	2
#define	SPD_DDR4_OPT_FEAT_MAC(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_OPT_FEAT_MAC_UNTESTED	0
#define	SPD_DDR4_OPT_FEAT_MAC_700K	1
#define	SPD_DDR4_OPT_FEAT_MAC_600K	2
#define	SPD_DDR4_OPT_FEAT_MAC_500K	3
#define	SPD_DDR4_OPT_FEAT_MAC_400K	4
#define	SPD_DDR4_OPT_FEAT_MAC_300K	5
#define	SPD_DDR4_OPT_FEAT_MAC_200K	6
#define	SPD_DDR4_OPT_FEAT_MAC_UNLIMITED	8

/*
 * S8.1.9 SDRAM Thermal and Refresh Options. This in theory is supposed to have
 * additional information from a data sheet; however, this field is noted as
 * reserved as zero. Therefore we entirely ignore this byte.
 */

/*
 * S8.1.10 Other SDRAM Optional Features. These are even more that aren't in the
 * first set of optional features.
 */
#define	SPD_DDR4_OPT_FEAT2	0x009
#define	SPD_DDR4_OPT_FEAT2_PPR(r)	bitx8(r, 7, 6)
#define	SPD_DDR4_OPT_FEAT2_PPR_NOTSUP	0
#define	SPD_DDR4_OPT_FEAT2_PPR_1RPBG	1
#define	SPD_DDR4_OPT_FEAT2_SOFT_PPR(r)	bitx8(r, 5, 5)
#define	SPD_DDR4_OPT_FEAT2_MBIST_PPR(r)	bitx8(r, 4, 4)

/*
 * S8.1.12 Module Nominal Voltage, VDD.
 */
#define	SPD_DDR4_VOLT	0x00b
#define	SPD_DDR4_VOLT_V1P2_ENDUR(r)	bitx8(r, 1, 1)
#define	SPD_DDR4_VOLT_V1P2_OPER(r)	bitx8(r, 0, 0)

/*
 * S8.1.13 Module Organization
 */
#define	SPD_DDR4_MOD_ORG	0x00c
#define	SPD_DDR4_MOD_ORG_RANK_MIX(r)	bitx8(r, 6, 6)
#define	SPD_DDR4_MOD_ORG_RANK_MIX_SYM	0
#define	SPD_DDR4_MOD_ORG_RANK_MIX_ASYM	1
#define	SPD_DDR4_MOD_ORG_NPKG_RANK(r)	bitx8(r, 5, 3)
#define	SPD_DDR4_MOD_ORG_NPKG_RANK_BASE	1
#define	SPD_DDR4_MOD_ORG_WIDTH(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_MOD_ORG_WIDTH_4b	0
#define	SPD_DDR4_MOD_ORG_WIDTH_8b	1
#define	SPD_DDR4_MOD_ORG_WIDTH_16b	2
#define	SPD_DDR4_MOD_ORG_WIDTH_32b	3

/*
 * S8.1.14 Module Memory Bus Width. The extensions here are generally used for
 * ECC.
 */
#define	SPD_DDR4_MOD_BUS_WIDTH	0x00d
#define	SPD_DDR4_MOD_BUS_WIDTH_EXT(r)	bitx8(r, 4, 3)
#define	SPD_DDR4_MOD_BUS_WIDTH_EXT_NONE	0
#define	SPD_DDR4_MOD_BUS_WIDTH_EXT_8b	1
#define	SPD_DDR4_MOD_BUS_WIDTH_PRI(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_MOD_BUS_WIDTH_PRI_8b	0
#define	SPD_DDR4_MOD_BUS_WIDTH_PRI_16b	1
#define	SPD_DDR4_MOD_BUS_WIDTH_PRI_32b	2
#define	SPD_DDR4_MOD_BUS_WIDTH_PRI_64b	3

/*
 * S8.1.15 Module Thermal Sensor.
 */
#define	SPD_DDR4_MOD_THERM	0x00e
#define	SPD_DDR4_MOD_THERM_PRES(r)	bitx8(r, 7, 7)

/*
 * S8.1.16 Extended Module Type. This contains a 4-bit extended module type;
 * however, none are defined for DDR4. We do not bother with a definition for
 * it. S8.1.17 Byte 16 is just reserved as must be zero.
 */

/*
 * S8.1.18 Timebases. These values are used throughout all other calculations to
 * describe various values that are present throughout many of the subsequent
 * bytes. There are two defined entities: the Median Time Base (MTB) and the
 * Fine Time Base (FTB). There is only one MTB and FTB defined for DDR4. These
 * are 125ps and 1ps respectively.
 *
 * Many of the timing values are split into two registers. One which contains a
 * value in MTB and one which has an adjustment in FTB. This is used when there
 * would otherwise be a fractional value that could not be rounded up to an even
 * number of MTB. We represent the FTB values by appending '_FINE' to them.
 */
#define	SPD_DDR4_TIMEBASE	0x011
#define	SPD_DDR4_TIMEBASE_MTB(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_TIMEBASE_MTB_125ps	0
#define	SPD_DDR4_TIMEBASE_FTB(r)	bitx8(r, 1, 0)
#define	SPD_DDR4_TIMEBASE_FTB_1ps	0
#define	SPD_DDR4_MTB_PS		125
#define	SPD_DDR4_FTB_PS		1

/*
 * S8.1.19 SDRAM Minimum Cycle Time t~ckavg~min.
 * S8.1.52 Fine Offset for ^
 * S8.1.20 SDRAM Maximum Cycle Time t~ckavg~max.
 * S8.1.51 Fine Offset for ^
 */
#define	SPD_DDR4_TCKAVG_MIN		0x012
#define	SPD_DDR4_TCKAVG_MIN_FINE	0x07d
#define	SPD_DDR4_TCKAVG_MAX		0x013
#define	SPD_DDR4_TCKAVG_MAX_FINE	0x07c

/*
 * S8.1.21 CAS Latencies. There are four bytes that are used to get at this and
 * show what is supported. These either start at CL7 or CL23 depending on the
 * top bit of the last CAS byte.
 */
#define	SPD_DDR4_CAS_SUP0	0x014
#define	SPD_DDR4_CAS_SUP1	0x015
#define	SPD_DDR4_CAS_SUP2	0x016
#define	SPD_DDR4_CAS_SUP3	0x017
#define	SPD_DDR4_CAS_SUP3_RANGE(r)	bitx8(r, 7, 7)
#define	SPD_DDR4_CAS_SUP3_RANGE_7	0
#define	SPD_DDR4_CAS_SUP3_RANGE_23	1

/*
 * S8.1.22 Minimum CAS Latency Time t~AA~min. This uses the MTB.
 * S8.1.50 Fine Offset for ^
 */
#define	SPD_DDR4_TAA_MIN	0x018
#define	SPD_DDR4_TAA_MIN_FINE	0x07b

/*
 * S8.1.23 Minimum RAS to CAS Delay Time t~RCD~min.
 * S8.1.49 Fine Offset for ^
 */
#define	SPD_DDR4_TRCD_MIN	0x019
#define	SPD_DDR4_TRCD_MIN_FINE	0x07a

/*
 * S8.1.24 Minimum Row Precharge Delay Time t~RP~min.
 * S8.1.48 Fine Offset for ^
 */
#define	SPD_DDR4_TRP_MIN	0x01a
#define	SPD_DDR4_TRP_MIN_FINE	0x079

/*
 * S8.1.25 Upper Nibbles for t~RAS~min and t~RC~min. These are bits 11:9 of
 * these values. The lower byte is in subsequent values.
 * S8.1.26 Minimum Active to Precharge Delay Time t~RAS~min.
 * S8.1.27 Minimum Active to Active/Refresh Delay Time t~RC~min.
 * S8.1.47 Fine Offset for ^
 */
#define	SPD_DDR4_RAS_RC_UPPER	0x01b
#define	SPD_DDR4_RAS_RC_UPPER_RC(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_RAS_RC_UPPER_RAS(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_TRAS_MIN	0x01c
#define	SPD_DDR4_TRC_MIN	0x01d
#define	SPD_DDR4_TRC_MIN_FINE	0x078

/*
 * S8.1.28: Minimum Refresh Recovery Delay Time t~RFC1~min.
 * S8.1.29: Minimum Refresh Recovery Delay Time t~RFC2~min.
 * S8.1.30: Minimum Refresh Recovery Delay Time t~RFC4~min.
 *
 * These are all different minimum refresh times. They are all two byte values
 * in units of MTB.
 */
#define	SPD_DDR4_TRFC1_MIN_LSB	0x01e
#define	SPD_DDR4_TRFC1_MIN_MSB	0x01f
#define	SPD_DDR4_TRFC2_MIN_LSB	0x020
#define	SPD_DDR4_TRFC2_MIN_MSB	0x021
#define	SPD_DDR4_TRFC4_MIN_LSB	0x022
#define	SPD_DDR4_TRFC4_MIN_MSB	0x023

/*
 * S8.1.31 Upper nibble for t~FAW~
 * S8.1.32 Minimum Four Activate Window Delay t~FAW~min.
 *
 * This is another 12-bit MTB-unit field.
 */
#define	SPD_DDR4_TFAW_UPPER	0x024
#define	SPD_DDR4_TFAW_UPPER_FAW(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_TFAW		0x025

/*
 * S8.1.33 Minimum Activate to Activate Delay Time t~RRD_S~min, different bank
 * group.
 * S8.1.46 Fine Offset for ^
 *
 * S8.1.34 Minimum Activate to Activate Delay Time t~RRD_L~min, same bank group.
 * S8.1.45 Fine Offset for ^
 *
 * S8.1.35 Minimum CAS to CAS Delay Time t~CCD_L~min, same bank group.
 * S8.1.44 Fine Offset for ^
 * group.
 */
#define	SPD_DDR4_TRRDS_MIN	0x026
#define	SPD_DDR4_TRRDS_MIN_FINE	0x077
#define	SPD_DDR4_TRRDL_MIN	0x027
#define	SPD_DDR4_TRRDL_MIN_FINE	0x076
#define	SPD_DDR4_TCCDL_MIN	0x028
#define	SPD_DDR4_TCCDL_MIN_FINE	0x075

/*
 * S8.1.36 Upper Nibble for t~WR~min.
 * S8.1.37 Minimum Write Recovery Time t~WR~min.
 */
#define	SPD_DDR4_TWR_MIN_UPPER	0x029
#define	SPD_DDR4_TWR_MIN_UPPER_TWR(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_TWR_MIN	0x02a

/*
 * S 8.1.38 Upper Nibbles for t~WTR~min
 * S8.1.39 Minimum Write to Read Time t~WTR_S~min, different bank group.
 * S8.1.40 Minimum Write to Read Time t~WTR_L~min, same bank group.
 *
 * Note, the referenced version of the spec has a typo here and refers to this
 * as byte 0x29, but that already exists with a different meaning.
 */
#define	SPD_DDR4_TWRT_UPPER	0x02b
#define	SPD_DDR4_TWRT_UPPER_TWRL(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_TWRT_UPPER_TWRS(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_TWTRS_MIN	0x02c
#define	SPD_DDR4_TWTRL_MIN	0x02d

/*
 * Bytes 0x2e to 0x3b are all reserved.
 */

/*
 * S8.1.42 Connector to SDRAM bit mapping. Each of the bytes defines a different
 * set of pins here. These all have a fairly standard set of transformations
 * that can be applied. These include a package rank map which only has a single
 * identity transformation applied and a separate nibble map encoding.
 */
#define	SPD_DDR4_MAP_DQ0	0x03c
#define	SPD_DDR4_MAP_DQ4	0x03d
#define	SPD_DDR4_MAP_DQ8	0x03e
#define	SPD_DDR4_MAP_DQ12	0x03f
#define	SPD_DDR4_MAP_DQ16	0x040
#define	SPD_DDR4_MAP_DQ20	0x041
#define	SPD_DDR4_MAP_DQ24	0x042
#define	SPD_DDR4_MAP_DQ28	0x043
#define	SPD_DDR4_MAP_CB0	0x044
#define	SPD_DDR4_MAP_CB4	0x045
#define	SPD_DDR4_MAP_DQ32	0x046
#define	SPD_DDR4_MAP_DQ36	0x047
#define	SPD_DDR4_MAP_DQ40	0x048
#define	SPD_DDR4_MAP_DQ44	0x049
#define	SPD_DDR4_MAP_DQ48	0x04a
#define	SPD_DDR4_MAP_DQ52	0x04b
#define	SPD_DDR4_MAP_DQ56	0x04c
#define	SPD_DDR4_MAP_DQ60	0x04d
#define	SPD_DDR4_MAP_PKG(r)	bitx8(r, 7, 6)
#define	SPD_DDR4_MAP_PKG_FLIP	0
#define	SPD_DDR4_MAP_NIBBLE(r)	bitx8(r, 5, 5)
#define	SPD_DDR4_MAP_IDX(r)	bitx8(r, 4, 0)
#define	SPD_DDR4_MAP_IDX_UNSPEC	0

/*
 * Bytes 0x4e-0x74 are reserved. Bytes 75-7D are fine offsets that are laid out
 * with their base counterparts.
 */

/*
 * S8.1.53 CRC For Base Configuration Section. This is a CRC that covers bytes
 * 0x00 to 0x7D using a specific CRC16.
 */
#define	SPD_DDR4_CRC_LSB	0x07e
#define	SPD_DDR4_CRC_MSB	0x07f

/*
 * We jump ahead to another common region which contains the common
 * manufacturing information which is shared across all module types.
 */

/*
 * S8.5.1 Module Manufacturer ID Code. This is a two byte JEP-108 style MFG ID.
 * S8.5.7 DRAM Manufacturer ID code.
 */
#define	SPD_DDR4_MOD_MFG_ID0	0x140
#define	SPD_DDR4_MOD_MFG_ID1	0x141
#define	SPD_DDR4_DRAM_MFG_ID0	0x15e
#define	SPD_DDR4_DRAM_MFG_ID1	0x15f

/*
 * S8.5.2 Module Manufacturing Location. This byte is manufacturer specific.
 */
#define	SPD_DDR4_MOD_MFG_LOC	0x142

/*
 * S8.5.3 module Manufacturing Date. Encoded as two BCD bytes for the year and
 * week.
 */
#define	SPD_DDR4_MOD_MFG_YEAR	0x143
#define	SPD_DDR4_MOD_MFG_WEEK	0x144

/*
 * S8.5.4 Module Serial Number.
 * S8.5.5 Module Part Number
 * S8.5.6 Module Revision Code
 */
#define	SPD_DDR4_MOD_SN		0x145
#define	SPD_DDR4_MOD_SN_LEN	4
#define	SPD_DDR4_MOD_PN		0x149
#define	SPD_DDR4_MOD_PN_LEN	20
#define	SPD_DDR4_MOD_REV	0x15d

/*
 * S8.5.8 DRAM Stepping
 */
#define	SPD_DDR4_DRAM_STEP	0x160

/*
 * Bytes 0x161-0x17d are left for Manufacturer specific data while bytes
 * 0x17e-0x17f are reserved.
 */

/*
 * The next region of bytes in the range 0x80-0xbf. We have specific definitions
 * for RDIMMs, LRDIMMs, and UDIMMs. While these often are very similar, they are
 * subtlety different.
 */

/*
 * S9.2.1 RDIMM: Raw Card Extension, Module Nominal Height. Bits 7-5 here have a
 * raw card revision. The revision extension, bits 7:5, are only valid when the
 * value of the normal reference card used in byte 0x82 is set to 0b11 (3).
 */
#define	SPD_DDR4_RDIMM_HEIGHT	0x080
#define	SPD_DDR4_RDIMM_HEIGHT_REV(r)	bitx8(r, 7, 5)
#define	SPD_DDR4_RDIMM_HEIGHT_MM(r)	bitx8(r, 4, 0)
#define	SPD_DDR4_RDIMM_HEIGHT_LT15MM	0
#define	SPD_DDR4_RDIMM_HEIGHT_BASE	15

/*
 * S9.2.2 RDIMM: Module Maximum Thickness. These measure thicknesses in mm, with
 * zero value meaning less than or equal to 1mm.
 */
#define	SPD_DDR4_RDIMM_THICK	0x081
#define	SPD_DDR4_RDIMM_THICK_BACK(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_RDIMM_THICK_FRONT(r)	bitx8(r, 3, 0)
#define	SPD_DDR4_RDIMM_THICK_BASE	1

/*
 * S9.2.3 RDIMM: Reference Raw Card Used. Bit 7 is used as basically another bit
 * for bits 4-0. We do not define each meaning of these bit combinations in this
 * header, that is left for tables in the library. When bits 6:5 are 0b11 (3)
 * then we must add in the reference card value in byte 0x80 to bits 6:5.
 */
#define	SPD_DDR4_RDIMM_REF	0x082
#define	SPD_DDR4_RDIMM_REF_EXT(r)	bitx8(r, 7, 7)
#define	SPD_DDR4_RDIMM_REF_REV(r)	bitx8(r, 6, 5)
#define	SPD_DDR4_RDIMM_REV_USE_HEIGHT	3
#define	SPD_DDR4_RDIMM_REF_CARD(r)	bitx8(r, 4, 0)

/*
 * S9.2.4 RDIMM: DIMM Attributes.
 */
#define	SPD_DDR4_RDIMM_ATTR	0x083
#define	SPD_DDR4_RDIMM_ATTR_TYPE(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_RDIMM_ATTR_TYPE_RCD01	0
#define	SPD_DDR4_RDIMM_ATTR_TYPE_RCD02	1
#define	SPD_DDR4_RDIMM_ATTR_NROWS(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_RDIMM_ATTR_NREGS(r)	bitx8(r, 1, 0)

/*
 * S9.2.5 RDIMM: Thermal Heat Spreader Solution
 */
#define	SPD_DDR4_RDIMM_THERM	0x084
#define	SPD_DDR4_RDIMM_THERM_IMPL(r)	bitx8(r, 7, 7)

/*
 * S9.2.6 RDIMM: Register Manufacturer JEDEC ID. This contains the JEDEC ID for
 * the manufacturer encoded as the number of continuation bytes and then the
 * actual code. This works with libjedec_vendor_string.
 */
#define	SPD_DDR4_RDIMM_REG_MFG_ID0	0x085
#define	SPD_DDR4_RDIMM_REG_MFG_ID1	0x086

/*
 * S9.2.7 RDIMM: Register Revision Number. This value is just a straight up hex
 * encoded value. It's a bit arbitrary. For example, they say 0x31 can be rev
 * 3.1, while 0x01 is just revision 1, and 0xB1 is revision B1.
 */
#define	SPD_DDR4_RDIMM_REV	0x087
#define	SPD_DDR4_RDIMM_REV_UNDEF	0xff

/*
 * S9.2.8 RDIMM: Address Mapping from Register to DRAM. This covers how the
 * register maps ranks 1 and 3 between the register and the actual modules.
 * Ranks 0/2 are always standard.
 */
#define	SPD_DDR4_RDIMM_MAP	0x88
#define	SPD_DDR4_RDIMM_MAP_R1(r)	bitx8(r, 0, 0)
#define	SPD_DDR4_RDIMM_MAP_R1_STD	0
#define	SPD_DDR4_RDIMM_MAP_R1_MIRROR	1

/*
 * S9.2.9 RDIMM: Register Output Drive Strength for Control and Command/Address
 * S9.2.10 RDIMM: Register Output Drive Strength for Clock
 */
#define	SPD_DDR4_RDIMM_ODS0	0x89
#define	SPD_DDR4_RDIMM_ODS0_CS(r)	bitx8(r, 7, 6)
#define	SPD_DDR4_RDIMM_ODS0_CA(r)	bitx8(r, 5, 4)
#define	SPD_DDR4_RDIMM_ODS0_ODT(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_RDIMM_ODS0_CKE(r)	bitx8(r, 1, 0)
#define	SPD_DDR4_RDIMM_ODS0_LIGHT	0
#define	SPD_DDR4_RDIMM_ODS0_MODERATE	1
#define	SPD_DDR4_RDIMM_ODS0_STRONG	2
#define	SPD_DDR4_RDIMM_ODS0_VERY_STRONG	3
#define	SPD_DDR4_RDIMM_ODS1	0x8a
#define	SPD_DDR4_RDIMM_ODS1_SLEW_SUP(r)	bitx8(r, 6, 6)
#define	SPD_DDR4_RDIMM_ODS1_Y1(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_RDIMM_ODS1_Y0(r)	bitx8(r, 1, 0)

/*
 * S9.2.12 CRC for SPD Block 1.
 */
#define	SPD_DDR4_BLK1_CRC_START	0x80
#define	SPD_DDR4_BLK1_CRC_LSB	0xfe
#define	SPD_DDR4_BLK1_CRC_MSB	0xff

/*
 * S9.1.1 UDIMM: Raw Card Extension, Module Nominal Height.
 * S9.1.2 UDIMM: Module Maximum Thickness.
 * S9.1.3 UDIMM: Reference Raw Card Used.
 *
 * These definitions are the same as for RDIMMs.
 */
#define	SPD_DDR4_UDIMM_HEIGHT	0x080
#define	SPD_DDR4_UDIMM_THICK	0x081
#define	SPD_DDR4_UDIMM_REF	0x082

/*
 * S9.1.4 UDIMM: Address Mapping from Edge Connector to DRAM. This is similar to
 * SPD_DDR4_RDIMM_MAP; however it doesn't take into account the register.
 */
#define	SPD_DDR4_UDIMM_MAP	0x83

/*
 * Everything else in UDIMMs is reserved, aside from the CRC, which is the same
 * as RDIMMs.
 */

/*
 * S9.3.1 LRDIMM: Raw Card Extension, Module Nominal Height
 * S9.3.2 LRDIMM: Module Maximum Thickness
 * S9.3.3 LRDIMM: Reference Raw Card Used
 *
 * These are the same as the corresponding UDIMM / RDIMM values.
 */
#define	SPD_DDR4_LRDIMM_HEIGHT	0x080
#define	SPD_DDR4_LRDIMM_THICK	0x081
#define	SPD_DDR4_LRDIMM_REF	0x082

/*
 * S9.3.4 LRDIMM: DIMM Attributes.
 */
#define	SPD_DDR4_LRDIMM_ATTR	0x083
#define	SPD_DDR4_LRDIMM_ATTR_TYPE(r)	bitx8(r, 7, 4)
#define	SPD_DDR4_LRDIMM_ATTR_TYPE_RCD01_DB01	0
#define	SPD_DDR4_LRDIMM_ATTR_TYPE_RCD02_DB02	1
#define	SPD_DDR4_LRDIMM_ATTR_NROWS(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_LRDIMM_ATTR_NREGS(r)	bitx8(r, 1, 0)

/*
 * S9.3.5 LRDIMM: Thermal Heat Spreader. See RDIMM version.
 */
#define	SPD_DDR4_LRDIMM_THERM	0x084

/*
 * S9.3.6 LRDIMM: Register and Data Buffer Manufacturer. See RDIMM version.
 */
#define	SPD_DDR4_LRDIMM_REG_MFG_ID0	0x085
#define	SPD_DDR4_LRDIMM_REG_MFG_ID1	0x086

/*
 * S9.3.7 LRDIMM: Register Revision Number. See RDIMM for more info.
 */
#define	SPD_DDR4_LRDIMM_REV	0x087

/*
 * S9.3.8 LRDIMM: Address Mapping from Register to DRAM. See RDIMM.
 */
#define	SPD_DDR4_LRDIMM_MAP	0x88

/*
 * S9.3.9 LRDIMM: Register Output Drive Strength for Control and
 * Command/Address.
 * S9.3.10: LRDIMM: Register Output Drive Strength for Clock and Data Buffer
 * Control.
 * See RDIMM for valid drive strength values and ODS0.
 */
#define	SPD_DDR4_LRDIMM_ODS0	0x89
#define	SPD_DDR4_LRDIMM_ODS1	0x8a
#define	SPD_DDR4_LRDIMM_ODS1_OSRC_SUP(r)	bitx8(r, 6, 6)
#define	SPD_DDR4_LRDIMM_ODS1_BCK(r)	bitx8(r, 5, 5)
#define	SPD_DDR4_LRDIMM_ODS1_BCOM(r)	bitx8(r, 4, 4)
#define	SPD_DDR4_LRDIMM_ODS1_MODERATE	0
#define	SPD_DDR4_LRDIMM_ODS1_STRONG	1
/*
 * The above two bit ranges use a single bit drive strength while the following
 * two use the same two-bit version as RDIMMs.
 */
#define	SPD_DDR4_RDIMM_ODS1_Y1(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_RDIMM_ODS1_Y0(r)	bitx8(r, 1, 0)

/*
 * S9.3.7 LRDIMM: Data Buffer Revision Number.
 */
#define	SPD_DDR4_LRDIMM_DB_REV	0x08b

/*
 * S9.3.12 LRDIMM: DRAM VrefDQ for Package Rank 0
 * S9.3.13 LRDIMM: DRAM VrefDQ for Package Rank 1
 * S9.3.14 LRDIMM: DRAM VrefDQ for Package Rank 2
 * S9.3.15 LRDIMM: DRAM VrefDQ for Package Rank 3
 *
 * These are all encoded with a value from MR6 in JESD79-4 apparently.
 */
#define	SPD_DDR4_LRDIMM_VREFDQ0	0x08c
#define	SPD_DDR4_LRDIMM_VREFDQ1	0x08d
#define	SPD_DDR4_LRDIMM_VREFDQ2	0x08e
#define	SPD_DDR4_LRDIMM_VREFDQ3	0x08f
#define	SPD_DDR4_LRDIMM_VREFDQ_V(r)	bitx8(r, 5, 0)

/*
 * S9.3.16 LRDIMM: Data Buffer VrefDQ for DRAM Interface. The entire byte is
 * used to match the encoding from the DDR4DB01 spec.
 */
#define	SPD_DDR4_LRDIMM_VREFDQ_DB	0x090

/*
 * S9.3.17 LRDIMM: Data Buffer MDQ Drive Strength and RTT for data rate <= 1866
 * S9.3.18 LRDIMM: Data Buffer MDQ Drive Strength and RTT for 1866 < data rate
 * <= 2400
 * S9.3.19 LRDIMM: Data Buffer MDQ Drive Strength and RTT for 2400 < data rate
 * <= 3200
 *
 * These three registers all share the same bit values and register extraction.
 */
#define	SPD_DDR4_LRDIMM_MDQ_1866	0x091
#define	SPD_DDR4_LRDIMM_MDQ_2400	0x092
#define	SPD_DDR4_LRDIMM_MDQ_3200	0x093
#define	SPD_DDR4_LRDIMM_MDQ_DS(r)	bitx8(r, 6, 4)
#define	SPD_DDR4_LRDIMM_MDQ_DS_40R	0
#define	SPD_DDR4_LRDIMM_MDQ_DS_34R	1
#define	SPD_DDR4_LRDIMM_MDQ_DS_48R	2
#define	SPD_DDR4_LRDIMM_MDQ_DS_60R	5
#define	SPD_DDR4_LRDIMM_MDQ_RTT(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_LRDIMM_MDQ_RTT_DIS	0
#define	SPD_DDR4_LRDIMM_MDQ_RTT_60R	1
#define	SPD_DDR4_LRDIMM_MDQ_RTT_120R	2
#define	SPD_DDR4_LRDIMM_MDQ_RTT_40R	3
#define	SPD_DDR4_LRDIMM_MDQ_RTT_240R	4
#define	SPD_DDR4_LRDIMM_MDQ_RTT_48R	5
#define	SPD_DDR4_LRDIMM_MDQ_RTT_80R	6
#define	SPD_DDR4_LRDIMM_MDQ_RTT_34R	7

/*
 * S9.3.20: LRDIMM: DRAM Drive Strength. One byte covers all data rates, which
 * share the same resistance values.
 */
#define	SPD_DDR4_LRDIMM_DRAM_DS	0x094
#define	SPD_DDR4_LRDIMM_DRAM_DS_3200(r)	bitx8(r, 5, 4)
#define	SPD_DDR4_LRDIMM_DRAM_DS_2400(r)	bitx8(r, 3, 2)
#define	SPD_DDR4_LRDIMM_DRAM_DS_1866(r)	bitx8(r, 1, 0)
#define	SPD_DDR4_LRDIMM_DRAM_DS_34R	0
#define	SPD_DDR4_LRDIMM_DRAM_DS_48R	1

/*
 * S9.3.21 LRDIMM: DRAM ODT (RTT_WR and RTT_NOM) for data rate <= 1866
 * S9.3.22 LRDIMM: DRAM ODT (RTT_WR and RTT_NOM) for 1866 < data rate <= 2400
 * S9.3.23 LRDIMM: DRAM ODT (RTT_WR and RTT_NOM) for 2400 < data rate <= 3200
 */
#define	SPD_DDR4_LRDIMM_ODT_1866	0x095
#define	SPD_DDR4_LRDIMM_ODT_2400	0x096
#define	SPD_DDR4_LRDIMM_ODT_3200	0x097
#define	SPD_DDR4_LRDIMM_ODT_WR(r)	bitx8(r, 5, 3)
#define	SPD_DDR4_LRDIMM_ODT_WR_DYN_OFF	0
#define	SPD_DDR4_LRDIMM_ODT_WR_120R	1
#define	SPD_DDR4_LRDIMM_ODT_WR_240R	2
#define	SPD_DDR4_LRDIMM_ODT_WR_HIZ	3
#define	SPD_DDR4_LRDIMM_ODT_WR_80R	4
#define	SPD_DDR4_LRDIMM_ODT_NOM(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_LRDIMM_ODT_NOM_DIS	0
#define	SPD_DDR4_LRDIMM_ODT_NOM_60R	1
#define	SPD_DDR4_LRDIMM_ODT_NOM_120R	2
#define	SPD_DDR4_LRDIMM_ODT_NOM_40R	3
#define	SPD_DDR4_LRDIMM_ODT_NOM_240R	4
#define	SPD_DDR4_LRDIMM_ODT_NOM_48R	5
#define	SPD_DDR4_LRDIMM_ODT_NOM_80R	6
#define	SPD_DDR4_LRDIMM_ODT_NOM_34R	7

/*
 * S9.3.24 LRDIMM: DRAM ODT (RTT_PARK) for data rate <= 1866
 * S9.3.25 LRDIMM: DRAM ODT (RTT_PARK) for 1866 < data rate <= 2400
 * S9.3.26 LRDIMM: DRAM ODT (RTT_PARK) for 2400 < data rate <= 3200
 */
#define	SPD_DDR4_LRDIMM_PARK_1866	0x098
#define	SPD_DDR4_LRDIMM_PARK_2400	0x099
#define	SPD_DDR4_LRDIMM_PARK_3200	0x09a
#define	SPD_DDR4_LRDIMM_PARK_R23(r)	bitx8(r, 5, 3)
#define	SPD_DDR4_LRDIMM_PARK_R01(r)	bitx8(r, 2, 0)
#define	SPD_DDR4_LRDIMM_PARK_DIS	0
#define	SPD_DDR4_LRDIMM_PARK_60R	1
#define	SPD_DDR4_LRDIMM_PARK_120R	2
#define	SPD_DDR4_LRDIMM_PARK_40R	3
#define	SPD_DDR4_LRDIMM_PARK_240R	4
#define	SPD_DDR4_LRDIMM_PARK_48R	5
#define	SPD_DDR4_LRDIMM_PARK_80R	6
#define	SPD_DDR4_LRDIMM_PARK_34R	7

/*
 * S9.3.27: Data Buffer VrefDQ for DRAM Interface Range.
 */
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG	0x09b
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG_DB(r)	bitx8(r, 4, 4)
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG_R3(r)	bitx8(r, 3, 3)
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG_R2(r)	bitx8(r, 2, 2)
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG_R1(r)	bitx8(r, 1, 1)
#define	SPD_DDR4_LRDIMM_VREFDQ_RNG_R0(r)	bitx8(r, 0, 0)
#define	SPD_DDR4_LRDIMM_VERFDQ_RNG_1	0
#define	SPD_DDR4_LRDIMM_VERFDQ_RNG_2	1

/*
 * S9.3.28: Data Buffer DQ Decision Feedback Equalization
 */
#define	SPD_DDR4_LRDIMM_EQ	0x09c
#define	SPD_DDR4_LRDIMM_EQ_DFE_SUP(r)	bitx8(r, 1, 1)
#define	SPD_DDR4_LRDIMM_EQ_GA_SUP(r)	bitx8(r, 0, 0)

#ifdef __cplusplus
}
#endif

#endif /* _SPD_DDR4_H */
