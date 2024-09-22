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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SPD_LP4_H
#define	_SPD_LP4_H

/*
 * Definitions for use in LPDDR3, LPDDR4, and LPDDR4x Serial Presence Decoding
 * based on JEDEC Standard 21-C Section Title: Annex M: Serial Presence Detect
 * (SPD) for LPDDR3 and LPDDR4 SDRAM Modules Release 2. While this covers
 * multiple revisions, we'll generally refer to this collectively as LPDDR4.
 *
 * LPDDR4 modules are organized into a few regions that are generally similar to
 * DDR4, though the contents vary:
 *
 *   o Base Configuration and DRAM parameters (bytes 0x00-0x7f)
 *   o Standard Module Parameters (bytes 0x80-0xff) these vary on whether
 *     something is an LP-DIMM or soldered down.
 *   o Hybrid Module Extended Parameters (bytes 0x100-0x13f).
 *   o Manufacturing Information (bytes 0x140-0x17f)
 *   o End User Programmable data (0x180-0x1ff).
 */

#include <sys/bitext.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S3.1.1 Number of Bytes Used / Number of Bytes in SPD Device.
 */
#define	SPD_LP4_NBYTES	0x000
#define	SPD_LP4_NBYTES_TOTAL(r)		bitx8(r, 6, 4)
#define	SPD_LP4_NBYTES_TOTAL_UNDEF	0
#define	SPD_LP4_NBYTES_TOTAL_256	1
#define	SPD_LP4_NBYTES_TOTAL_512	2
#define	SPD_LP4_NBYTES_USED(r)		bitx8(r, 3, 0)
#define	SPD_LP4_NBYTES_USED_UNDEF	0
#define	SPD_LP4_NBYTES_USED_128		1
#define	SPD_LP4_NBYTES_USED_256		2
#define	SPD_LP4_NBYTES_USED_384		3
#define	SPD_LP4_NBYTES_USED_512		4


/*
 * S3.1.2 SPD Revision. This is the same as described in SPD_DDR4_SPD_REV as
 * defined in spd_ddr4.h.
 */
#define	SPD_LP4_SPD_REV	0x001
#define	SPD_LP4_SPD_REV_ENC(r)	bitx8(r, 7, 4)
#define	SPD_LP4_SPD_REV_ADD(r)	bitx8(r, 3, 0)
#define	SPD_LP4_SPD_REV_V1	1

/*
 * Key Byte / DRAM Device Type. This field identifies the type of DDR device and
 * is actually consistent across all SPD versions. Known values are in the
 * spd_dram_type_t enumeration.
 */
#define	SPD_LP4_DRAM_TYPE	0x002

/*
 * S3.1.4: Key Byte / Module type. This is used to describe what kind of DDR
 * module it is, which tell us what the module-specific section contents are.
 * These bits, unlike the one above are device specific.
 */
#define	SPD_LP4_MOD_TYPE	0x003
#define	SPD_LP4_MOD_TYPE_ISHYBRID(r)	bitx8(r, 7, 7)
#define	SPD_LP4_MOD_TYPE_HYBRID(r)	bitx8(r, 6, 4)
#define	SPD_LP4_MOD_TYPE_HYBRID_NONE	0
#define	SPD_LP4_MOD_TYPE_TYPE(r)	bitx8(r, 3, 0)
#define	SPD_LP4_MOD_TYPE_TYPE_EXT	0
#define	SPD_LP4_MOD_TYPE_TYPE_LPDIMM	0x7
#define	SPD_LP4_MOD_TYPE_TYPE_SOLDER	0xe

/*
 * S3.1.5 SDRAM Density and Banks.
 */
#define	SPD_LP4_DENSITY	0x004
#define	SPD_LP4_DENSITY_NBG_BITS(r)	bitx8(r, 7, 6)
#define	SPD_LP4_DENSITY_NBG_BITS_MAX	2
#define	SPD_LP4_DENSITY_NBA_BITS(r)	bitx8(r, 5, 4)
#define	SPD_LP4_DENSITY_NBA_BITS_BASE	2
#define	SPD_LP4_DENSITY_NBA_BITS_MAX	3
#define	SPD_LP4_DENSITY_DENSITY(r)	bitx8(r, 3, 0)
#define	SPD_LP4_DENSITY_DENSITY_1Gb	2
#define	SPD_LP4_DENSITY_DENSITY_2Gb	3
#define	SPD_LP4_DENSITY_DENSITY_4Gb	4
#define	SPD_LP4_DENSITY_DENSITY_8Gb	5
#define	SPD_LP4_DENSITY_DENSITY_16Gb	6
#define	SPD_LP4_DENSITY_DENSITY_32Gb	7
#define	SPD_LP4_DENSITY_DENSITY_12Gb	8
#define	SPD_LP4_DENSITY_DENSITY_24Gb	9
#define	SPD_LP4_DENSITY_DENSITY_3Gb	10
#define	SPD_LP4_DENSITY_DENSITY_6Gb	11
#define	SPD_LP4_DENSITY_DENSITY_18Gb	12

/*
 * S3.1.6 SDRAM Addressing.
 */
#define	SPD_LP4_ADDR	0x005
#define	SPD_LP4_ADDR_NROWS(r)	bitx8(r, 5, 3)
#define	SPD_LP4_ADDR_NROWS_BASE		12
#define	SPD_LP4_ADDR_NROWS_MAX		18
#define	SPD_LP4_ADDR_NCOLS(r)	bitx8(r, 2, 0)
#define	SPD_LP4_ADDR_NCOLS_BASE		9
#define	SPD_LP4_ADDR_NCOLS_MAX		12

/*
 * S3.1.7 SDRAM Package Type
 */
#define	SPD_LP4_PKG	0x006
#define	SPD_LP4_PKG_TYPE(r)	bitx8(r, 7, 7)
#define	SPD_LP4_PKG_TYPE_MONO	0
#define	SPD_LP4_PKG_TYPE_NOT	1
#define	SPD_LP4_PKG_DIE_CNT(r)	bitx8(r, 6, 4)
#define	SPD_LP4_PKG_DIE_CNT_BASE	1
#define	SPD_LP4_PKG_NCHAN(r)	bitx8(r, 3, 2)
#define	SPD_LP4_PKG_NCHAN_MAX		4
#define	SPD_LP4_PKG_SL(r)	bitx8(r, 1, 0)
#define	SPD_LP4_PKG_SL_M1	1
#define	SPD_LP4_PKG_SL_M2	3

/*
 * S3.1.8 SDRAM Optional Features.
 */
#define	SPD_LP4_OPT_FEAT	0x007
#define	SPD_LP4_OPT_FEAT_MAW(r)	bitx8(r, 5, 4)
#define	SPD_LP4_OPT_FEAT_MAW_8192X	0
#define	SPD_LP4_OPT_FEAT_MAW_4096X	1
#define	SPD_LP4_OPT_FEAT_MAW_2048X	2
#define	SPD_LP4_OPT_FEAT_MAC(r)	bitx8(r, 3, 0)
#define	SPD_LP4_OPT_FEAT_MAC_UNTESTED	0
#define	SPD_LP4_OPT_FEAT_MAC_700K	1
#define	SPD_LP4_OPT_FEAT_MAC_600K	2
#define	SPD_LP4_OPT_FEAT_MAC_500K	3
#define	SPD_LP4_OPT_FEAT_MAC_400K	4
#define	SPD_LP4_OPT_FEAT_MAC_300K	5
#define	SPD_LP4_OPT_FEAT_MAC_200K	6
#define	SPD_LP4_OPT_FEAT_MAC_UNLIMITED	8

/*
 * S3.1.10 Other SDRAM Optional Features. These are even more that aren't in the
 * first set of optional features.
 */
#define	SPD_LP4_OPT_FEAT2	0x009
#define	SPD_LP4_OPT_FEAT2_PPR(r)	bitx8(r, 7, 6)
#define	SPD_LP4_OPT_FEAT2_PPR_NOTSUP	0
#define	SPD_LP4_OPT_FEAT2_PPR_1RPBG	1
#define	SPD_LP4_OPT_FEAT2_SOFT_PPR(r)	bitx8(r, 5, 5)

/*
 * S3.1.13 Module Organization
 */
#define	SPD_LP4_MOD_ORG	0x00c
#define	SPD_LP4_MOD_ORG_IDENT(r)	bitx8(r, 6, 6)
#define	SPD_LP4_MOD_ORG_IDENT_STD	0
#define	SPD_LP4_MOD_ORG_IDENT_BYTE	1
#define	SPD_LP4_MOD_ORG_RANK_MIX(r)	bitx8(r, 6, 6)
#define	SPD_LP4_MOD_ORG_RANK_MIX_SYM	0
#define	SPD_LP4_MOD_ORG_RANK_MIX_ASYM	1
#define	SPD_LP4_MOD_ORG_NPKG_RANK(r)	bitx8(r, 5, 3)
#define	SPD_LP4_MOD_ORG_NPKG_RANK_BASE	1
#define	SPD_LP4_MOD_ORG_NPKG_RANK_MAX	4
#define	SPD_LP4_MOD_ORG_WIDTH(r)	bitx8(r, 2, 0)
#define	SPD_LP4_MOD_ORG_WIDTH_BASE	2
#define	SPD_LP4_MOD_ORG_WIDTH_MAX	32

/*
 * S3.1.14 Memory Bus Width.
 */
#define	SPD_LP4_BUS_WIDTH	0x00d
#define	SPD_LP4_BUS_WIDTH_NCHAN(r)	bitx8(r, 7, 5)
#define	SPD_LP4_BUS_WIDTH_NCHAN_1ch	0
#define	SPD_LP4_BUS_WIDTH_NCHAN_2ch	1
#define	SPD_LP4_BUS_WIDTH_NCHAN_3ch	2
#define	SPD_LP4_BUS_WIDTH_NCHAN_4ch	3
#define	SPD_LP4_BUS_WIDTH_NCHAN_8ch	4
#define	SPD_LP4_BUS_WIDTH_EXT(r)	bitx8(r, 4, 3)
#define	SPD_LP4_BUS_WIDTH_EXT_NONE	0
#define	SPD_LP4_BUS_WIDTH_PRI(r)	bitx8(r, 2, 0)
#define	SPD_LP4_BUS_WIDTH_PRI_BASE	3
#define	SPD_LP4_BUS_WIDTH_PRI_MAX	64

/*
 * S8.1.15 Module Thermal Sensor.
 */
#define	SPD_LP4_MOD_THERM	0x00e
#define	SPD_LP4_MOD_THERM_PRES(r)	bitx8(r, 7, 7)

/*
 * S3.1.17 Signal Loading
 *
 * The values of the signal loading are dependent on the value found in the
 * SPD_LP4_PKG (byte 6) register, The interpretation varies based on the value
 * of SPD_LP4_PKG_SL(). However, the only defined signal loading matrix is
 * matrix 1.
 */
#define	SPD_LP4_SIGLOAD	0x010
#define	SPD_LP4_SIGLOAD1_DSM_LOAD(r)	bitx8(r, 7, 6)
#define	SPD_LP4_SIGLOAD1_DSM_LOAD_MAX	4
#define	SPD_LP4_SIGLOAD1_CAC_LOAD(r)	bitx8(r, 5, 3)
#define	SPD_LP4_SIGLOAD1_CAC_LOAD_MAX	8
#define	SPD_LP4_SIGLOAD1_CS_LOAD(r)	bitx8(r, 2, 0)
#define	SPD_LP4_SIGLOAD1_CS_LOAD_MAX	8

/*
 * Timebases
 *
 * Like with DDR4, there are strictly speaking timebase values encoded in the
 * registers that describe how to calculate other values. These are broken into
 * the Medium and Fine timebases respectively which as of v1.0 have fixed
 * values of 125ps and 1ps respectively. See the DDR4 version for more
 * information.
 */
#define	SPD_LP4_TIMEBASE	0x011
#define	SPD_LP4_TIMEBASE_MTB(r)		bitx8(r, 3, 2)
#define	SPD_LP4_TIMEBASE_MTB_125ps	0
#define	SPD_LP4_TIMEBASE_FTB(r)		bitx8(r, 1, 0)
#define	SPD_LP4_TIMEBASE_FTB_1ps	0
#define	SPD_LP4_MTB_PS		125
#define	SPD_LP4_FTB_PS		1

/*
 * S3.1.19 SDRAM Minimum Cycle Time t~ckavg~min.
 * S3.1.37 Fine Offset for ^
 * S3.1.20 SDRAM Maximum Cycle Time t~ckavg~max.
 * S3.1.36 Fine Offset for ^
 */
#define	SPD_LP4_TCKAVG_MIN		0x012
#define	SPD_LP4_TCKAVG_MIN_FINE		0x07d
#define	SPD_LP4_TCKAVG_MAX		0x013
#define	SPD_LP4_TCKAVG_MAX_FINE		0x07c

/*
 * S3.1.21 CAS Latencies. These are four bytes that are used to get at what
 * speeds are supported. These always start at CL3, but the mapping of bits to
 * CL values is not uniform.
 */
#define	SPD_LP4_CAS_SUP0	0x014
#define	SPD_LP4_CAS_SUP1	0x015
#define	SPD_LP4_CAS_SUP2	0x016
#define	SPD_LP4_CAS_SUP3	0x017

/*
 * S3.1.22 Minimum CAS Latency Time t~AA~min. This uses the MTB.
 * S3.1.35 Fine Offset for ^
 */
#define	SPD_LP4_TAA_MIN		0x018
#define	SPD_LP4_TAA_MIN_FINE	0x07b

/*
 * S3.1.23 Read and Write Latency Set Options
 */
#define	SPD_LP4_RWLAT		0x019
#define	SPD_LP4_RWLAT_WRITE(r)	bitx8(r, 3, 2)
#define	SPD_LP4_RWLAT_WRITE_A	0
#define	SPD_LP4_RWLAT_WRITE_B	1
#define	SPD_LP4_RWLAT_READ(r)	bitx8(r, 1, 0)
#define	SPD_LP4_RWLAT_DBIRD_DIS	0
#define	SPD_LP4_RWLAT_DBIRD_EN	1

/*
 * S3.1.24 Minimum RAS to CAS Delay Time t~RCD~min.
 * S3.1.34 Fine Offset for ^
 */
#define	SPD_LP4_TRCD_MIN	0x01a
#define	SPD_LP4_TRCD_MIN_FINE	0x07a

/*
 * S3.1.25 All Banks Minimum Row Precharge Delay Time t~RPab~min.
 * S3.1.33 Fine Offset for ^
 */
#define	SPD_LP4_TRPAB_MIN	0x01b
#define	SPD_LP4_TRPAB_MIN_FINE	0x079

/*
 * S3.1.26 Per Bank Minimum Row Precharge Delay Time t~RPpb~min.
 * S3.1.32 Fine Offset for ^
 */
#define	SPD_LP4_TRPPB_MIN	0x01c
#define	SPD_LP4_TRPPB_MIN_FINE	0x078

/*
 * S3.1.27 All Banks Minimum Refresh Recovery Delay Time t~RFCab~min. This is a
 * 16-bit quantity that is split between a lower and upper value. Both registers
 * are in terms of the medium time base.
 */
#define	SPD_LP4_TRFCAB_MIN_LO	0x1d
#define	SPD_LP4_TRFCAB_MIN_HI	0x1e

/*
 * S3.1.28 Per Bank Minimum Refresh Recovery Delay Time t~RFCpb~min. This is a
 * 16-bit quantity that is split between a lower and upper value. Both registers
 * are in terms of the medium time base.
 */
#define	SPD_LP4_TRFCPB_MIN_LO	0x1f
#define	SPD_LP4_TRFCPB_MIN_HI	0x20

/*
 * S3.1.30 Connector to SDRAM bit mapping. Each of the bytes defines a different
 * set of pins here. These all have a fairly standard set of transformations
 * that can be applied. These include a package rank map which only has a single
 * identity transformation applied and a separate nibble map encoding.
 */
#define	SPD_LP4_MAP_DQ0		0x03c
#define	SPD_LP4_MAP_DQ4		0x03d
#define	SPD_LP4_MAP_DQ8		0x03e
#define	SPD_LP4_MAP_DQ12	0x03f
#define	SPD_LP4_MAP_DQ16	0x040
#define	SPD_LP4_MAP_DQ20	0x041
#define	SPD_LP4_MAP_DQ24	0x042
#define	SPD_LP4_MAP_DQ28	0x043
#define	SPD_LP4_MAP_CB0		0x044
#define	SPD_LP4_MAP_CB4		0x045
#define	SPD_LP4_MAP_DQ32	0x046
#define	SPD_LP4_MAP_DQ36	0x047
#define	SPD_LP4_MAP_DQ40	0x048
#define	SPD_LP4_MAP_DQ44	0x049
#define	SPD_LP4_MAP_DQ48	0x04a
#define	SPD_LP4_MAP_DQ52	0x04b
#define	SPD_LP4_MAP_DQ56	0x04c
#define	SPD_LP4_MAP_DQ60	0x04d
#define	SPD_LP4_MAP_PKG(r)	bitx8(r, 7, 6)
#define	SPD_LP4_MAP_PKG_FLIP	0
#define	SPD_LP4_MAP_NIBBLE(r)	bitx8(r, 5, 5)
#define	SPD_LP4_MAP_IDX(r)	bitx8(r, 4, 0)
#define	SPD_LP4_MAP_IDX_UNSPEC	0

/*
 * S3.1.38 CRC For Base Configuration Section. This is a CRC that covers bytes
 * 0x00 to 0x7D using a specific CRC16.
 */
#define	SPD_LP4_CRC_LSB	0x07e
#define	SPD_LP4_CRC_MSB	0x07f

/*
 * The manufacturing information section is identical to DDR4.
 */

/*
 * LPDDR3/4 only define an annex for the LP-DIMM form factor.
 */

/*
 * S4.1.1 LP-DIMM: Raw Card Extension, Module Nominal Height. Bits 7-5 here have
 * a raw card revision. The revision extension, bits 7:5, are only valid when
 * the value of the normal reference card used in byte 0x82 is set to 0b11 (3).
 */
#define	SPD_LP4_LPDIMM_HEIGHT	0x080
#define	SPD_LP4_LPDIMM_HEIGHT_REV(r)	bitx8(r, 7, 5)
#define	SPD_LP4_LPDIMM_HEIGHT_MM(r)	bitx8(r, 4, 0)
#define	SPD_LP4_LPDIMM_HEIGHT_LT15MM	0
#define	SPD_LP4_LPDIMM_HEIGHT_BASE	15

/*
 * S4.1.2 LP-DIMM: Module Maximum Thickness. These measure thicknesses in mm,
 * with zero value meaning less than or equal to 1mm.
 */
#define	SPD_LP4_LPDIMM_THICK	0x081
#define	SPD_LP4_LPDIMM_THICK_BACK(r)	bitx8(r, 7, 4)
#define	SPD_LP4_LPDIMM_THICK_FRONT(r)	bitx8(r, 3, 0)
#define	SPD_LP4_LPDIMM_THICK_BASE	1

/*
 * S4.1.3 LP-DIMM: Reference Raw Card Used. Bit 7 is used as basically another
 * bit for bits 4-0. We do not define each meaning of these bit combinations in
 * this header, that is left for tables in the library. When bits 6:5 are 0b11
 * (3) then we must add in the reference card value in byte 0x80 to bits 6:5.
 */
#define	SPD_LP4_LPDIMM_REF	0x082
#define	SPD_LP4_LPDIMM_REF_EXT(r)	bitx8(r, 7, 7)
#define	SPD_LP4_LPDIMM_REF_REV(r)	bitx8(r, 6, 5)
#define	SPD_LP4_LPDIMM_REV_USE_HEIGHT	3
#define	SPD_LP4_LPDIMM_REF_CARD(r)	bitx8(r, 4, 0)

/*
 * S4.1.5 LP-DIMM: CRC. Like DDR4, this is the CRC for the upper page. However,
 * it is only defined on a per-Annex basis.
 */
#define	SPD_LP4_BLK1_CRC_START	0x80
#define	SPD_LP4_BLK1_CRC_LSB	0xfe
#define	SPD_LP4_BLK1_CRC_MSB	0xff

#ifdef __cplusplus
}
#endif

#endif /* _SPD_LP4_H */
