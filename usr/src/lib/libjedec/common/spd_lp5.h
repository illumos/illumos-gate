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

#ifndef _SPD_LP5_H
#define	_SPD_LP5_H

/*
 * Definitions for use in LPDDR5/LPDDR5X Serial Presence Detect decoding based
 * on JEDEC standard JESD406-5 LPDDR5/5X Serial Presence Detect (SPD) Contents.
 * Release 1.0. This does not cover DDR5. That is covered in spd_ddr5.h.
 *
 * LPDDR5/X modules are organized into a few main regions which is identical to
 * DDR5; however, the contents vary:
 *
 *   o Base Configuration, DRAM, and Module Parameters (0x00-0x7f)
 *   o Common Module Parameters (0xc0, 0xef)
 *   o Standard Module Parameters (0xf0-0x1bf) which vary on the specific DIMM
 *     type.
 *   o A CRC check for the first 510 bytes (0x1fe-0x1ff)
 *   o Manufacturing Information (0x200-0x27f)
 *   o Optional end-user programmable regions (0x280-0x3ff)
 *
 * This covers all LPDDR5/X variants other than NVDIMMs.
 */

#include <sys/bitext.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Number of Bytes in SPD Device and Beta Level
 */
#define	SPD_LP5_NBYTES	0x00
#define	SPD_LP5_NBYTES_BETAHI(r)	bitx8(r, 7, 7)
#define	SPD_LP5_NBYTES_TOTAL(r)		bitx8(r, 6, 4)
#define	SPD_LP5_NBYTES_TOTAL_UNDEF	0
#define	SPD_LP5_NBYTES_TOTAL_256	1
#define	SPD_LP5_NBYTES_TOTAL_512	2
#define	SPD_LP5_NBYTES_TOTAL_1024	3
#define	SPD_LP5_NBYTES_TOTAL_2048	4
#define	SPD_LP5_NBYTES_BETA(r)		bitx8(r, 3, 0)

/*
 * SPD Revision for Base Configuration Parameters. This is the same as described
 * in SPD_DDR4_SPD_REV as defined in spd_ddr4.h.
 */
#define	SPD_LP5_SPD_REV	0x001
#define	SPD_LP5_SPD_REV_ENC(r)	bitx8(r, 7, 4)
#define	SPD_LP5_SPD_REV_ADD(r)	bitx8(r, 3, 0)
#define	SPD_LP5_SPD_REV_V1	1

/*
 * Key Byte / DRAM Device Type. This field identifies the type of DDR device and
 * is actually consistent across all SPD versions. Known values are in the
 * spd_dram_type_t enumeration.
 */
#define	SPD_LP5_DRAM_TYPE	0x002

/*
 * Key Byte / Module Type
 */
#define	SPD_LP5_MOD_TYPE	0x003
#define	SPD_LP5_MOD_TYPE_ISHYBRID(r)	bitx8(r, 7, 7)
#define	SPD_LP5_MOD_TYPE_HYBRID(r)	bitx8(r, 6, 4)
#define	SPD_LP5_MOD_TYPE_HYBRID_NONE		0
#define	SPD_LP5_MOD_TYPE_HYBRID_NVDIMM_N	1
#define	SPD_LP5_MOD_TYPE_HYBRID_NVDIMM_P	2
#define	SPD_LP5_MOD_TYPE_TYPE(r)	bitx8(r, 3, 0)
#define	SPD_LP5_MOD_TYPE_TYPE_RDIMM	1
#define	SPD_LP5_MOD_TYPE_TYPE_UDIMM	2
#define	SPD_LP5_MOD_TYPE_TYPE_SODIMM	3
#define	SPD_LP5_MOD_TYPE_TYPE_LRDIMM	4
#define	SPD_LP5_MOD_TYPE_TYPE_CUDIMM	5
#define	SPD_LP5_MOD_TYPE_TYPE_CSODIMM	6
#define	SPD_LP5_MOD_TYPE_TYPE_MRDIMM	7
#define	SPD_LP5_MOD_TYPE_TYPE_CAMM2	8
#define	SPD_LP5_MOD_TYPE_TYPE_DDIMM	10
#define	SPD_LP5_MOD_TYPE_TYPE_SOLDER	11

/*
 * SDRAM Density and Banks
 */
#define	SPD_LP5_DENSITY		0x004
#define	SPD_LP5_DENSITY_NBG_BITS(r)	bitx8(r, 7, 6)
#define	SPD_LP5_DENSITY_NBG_BITS_MAX	2
#define	SPD_LP5_DENSITY_NBA_BITS(r)	bitx8(r, 5, 4)
#define	SPD_LP5_DENSITY_NBA_BITS_BASE	2
#define	SPD_LP5_DENSITY_NBA_BITS_MAX	4
#define	SPD_LP5_DENSITY_DENSITY(r)	bitx8(r, 3, 0)
#define	SPD_LP5_DENSITY_DENSITY_1Gb	2
#define	SPD_LP5_DENSITY_DENSITY_2Gb	3
#define	SPD_LP5_DENSITY_DENSITY_4Gb	4
#define	SPD_LP5_DENSITY_DENSITY_8Gb	5
#define	SPD_LP5_DENSITY_DENSITY_16Gb	6
#define	SPD_LP5_DENSITY_DENSITY_32Gb	7
#define	SPD_LP5_DENSITY_DENSITY_12Gb	8
#define	SPD_LP5_DENSITY_DENSITY_24Gb	9
#define	SPD_LP5_DENSITY_DENSITY_3Gb	10
#define	SPD_LP5_DENSITY_DENSITY_6Gb	11

/*
 * SDRAM Addressing
 *
 * While the number of banks and bank groups is described above, the values for
 * the number of columns is combined with the number of bank group and bank
 * address bits.
 */
#define	SPD_LP5_ADDRESS		0x005
#define	SPD_LP5_ADDRESS_NROWS(x)	bitx8(x, 5, 3)
#define	SPD_LP5_ADDRESS_NROW_BASE	12
#define	SPD_LP5_ADDRESS_NROW_MAX	18
#define	SPD_LP5_ADDRESS_BCOL(x)		bitx8(x, 2, 0)
#define	SPD_LP5_ADDRESS_BCOL_3BA6C	0
#define	SPD_LP5_ADDRESS_BCOL_4BA6C	1

/*
 * SDRAM Package Type
 */
#define	SPD_LP5_PKG		0x006
#define	SPD_LP5_PKG_TYPE(r)	bitx8(r, 7, 7)
#define	SPD_LP5_PKG_TYPE_MONO	0
#define	SPD_LP5_PKG_TYPE_NOT	1
#define	SPD_LP5_PKG_DIE_CNT(r)	bitx8(r, 6, 4)
#define	SPD_LP5_DIE_CNT_1	0
#define	SPD_LP5_DIE_CNT_2	1
#define	SPD_LP5_DIE_CNT_3	2
#define	SPD_LP5_DIE_CNT_4	3
#define	SPD_LP5_DIE_CNT_5	4
#define	SPD_LP5_DIE_CNT_6	5
#define	SPD_LP5_DIE_CNT_16	6
#define	SPD_LP5_DIE_CNT_8	7
#define	SPD_LP5_PKG_DQSDW(r)	bitx8(r, 3, 1)
#define	SPD_LP5_PKG_DQSDW_1	0
#define	SPD_LP5_PKG_DQSDW_16	1
#define	SPD_LP5_PKG_DQSDW_2	2
#define	SPD_LP5_PKG_DQSDW_4	4
#define	SPD_LP5_PKG_DQSDW_8	8
#define	SPD_LP5_PKG_SLIDX(r)		bitx8(r, 1, 0)
#define	SPD_LP5_PKG_SLIDX_UNSPEC	0
#define	SPD_LP5_PKG_SLIDX_B16SLM1	1

/*
 * Optional Features
 */
#define	SPD_LP5_OPT_FEAT	0x009
#define	SPD_LP5_OPT_FEAT_PPR(r)		bitx8(r, 7, 6)
#define	SPD_LP5_OPT_FEAT_PPR_NOTSUP	0
#define	SPD_LP5_OPT_FEAT_PPR_SUP	1
#define	SPD_LP5_OPT_FEAT_SOFT_PPR(r)	bitx8(r, 5, 5)

/*
 * Module Organization
 */
#define	SPD_LP5_MOD_ORG		0x00c
#define	SPD_LP5_MOD_ORG_IDENT(r)	bitx8(r, 6, 6)
#define	SPD_LP5_MOD_ORG_IDENT_STD	0
#define	SPD_LP5_MOD_ORG_IDENT_BYTE	1
#define	SPD_LP5_MOD_ORG_RANK(r)		bitx8(r, 5, 3)
#define	SPD_LP5_MOD_ORG_RANK_BASE	1
#define	SPD_LP5_MOD_ORG_RANK_MAX	4
#define	SPD_LP5_MOD_ORG_WIDTH(r)	bitx8(r, 2, 0)
#define	SPD_LP5_MOD_ORG_WIDTH_BASE	2
#define	SPD_LP5_MOD_ORG_WIDTH_MAX	32

/*
 * System Sub-Channel Bus Width
 */
#define	SPD_LP5_WIDTH	0x00d
#define	SPD_LP5_WIDTH_SUBCHAN(r)	bitx8(r, 2, 0)
#define	SP5_LP5_WIDTH_SUBCHAN_16b	1
#define	SP5_LP5_WIDTH_SUBCHAN_32b	2

/*
 * Signal Loading
 *
 * The values of the signal loading are dependent on the value found in the
 * SPD_LP5_PKG (byte 6) register, The interpretation varies based on the value
 * of SPD_LP5_PKG_SLIDX().
 */
#define	SPD_LP5_SIGLOAD	0x010
#define	SPD_LP5_SIGLOAD1_DSM_LOAD(r)	bitx8(r, 7, 6)
#define	SPD_LP5_SIGLOAD1_DSM_LOAD_MAX	4
#define	SPD_LP5_SIGLOAD1_CAC_LOAD(r)	bitx8(r, 5, 3)
#define	SPD_LP5_SIGLOAD1_CAC_LOAD_MAX	8
#define	SPD_LP5_SIGLOAD1_CS_LOAD(r)	bitx8(r, 2, 0)
#define	SPD_LP5_SIGLOAD1_CS_LOAD_MAX	8

/*
 * Timebases
 *
 * Like with DDR4, there are strictly speaking timebase values encoded in the
 * registers that describe how to calculate other values. These are broken into
 * the Medium and Fine timebases respectively which as of v1.0 have fixed
 * values of 125ps and 1ps respectively. See the DDR4 version for more
 * information.
 */
#define	SPD_LP5_TIMEBASE	0x011
#define	SPD_LP5_TIMEBASE_MTB(r)		bitx8(r, 3, 2)
#define	SPD_LP5_TIMEBASE_MTB_125ps	0
#define	SPD_LP5_TIMEBASE_FTB(r)		bitx8(r, 1, 0)
#define	SPD_LP5_TIMEBASE_FTB_1ps	0
#define	SPD_LP5_MTB_PS		125
#define	SPD_LP5_FTB_PS		1

/*
 * SDRAM Minimum Cycle Time t~ckavg~min.
 * Fine Offset for ^
 * SDRAM Maximum Cycle Time t~ckavg~max.
 * Fine Offset for ^
 */
#define	SPD_LP5_TCKAVG_MIN		0x012
#define	SPD_LP5_TCKAVG_MIN_FINE		0x07d
#define	SPD_LP5_TCKAVG_MAX		0x013
#define	SPD_LP5_TCKAVG_MAX_FINE		0x07c

/*
 * Minimum CAS Latency Time t~AA~min. This uses the MTB.
 * Fine Offset for ^
 */
#define	SPD_LP5_TAA_MIN		0x018
#define	SPD_LP5_TAA_MIN_FINE	0x07b

/*
 * Minimum RAS to CAS Delay Time t~RCD~min.
 * Fine Offset for ^
 */
#define	SPD_LP5_TRCD_MIN	0x01a
#define	SPD_LP5_TRCD_MIN_FINE	0x07a

/*
 * All Banks Minimum Row Precharge Delay Time t~RPab~min.
 * Fine Offset for ^
 */
#define	SPD_LP5_TRPAB_MIN	0x01b
#define	SPD_LP5_TRPAB_MIN_FINE	0x079

/*
 * Per Bank Minimum Row Precharge Delay Time t~RPpb~min.
 * Fine Offset for ^
 */
#define	SPD_LP5_TRPPB_MIN	0x01c
#define	SPD_LP5_TRPPB_MIN_FINE	0x078

/*
 * All Banks Minimum Refresh Recovery Delay Time t~RFCab~min. This is a 16-bit
 * quantity that is split between a lower and upper value. Both registers are in
 * terms of the medium time base.
 */
#define	SPD_LP5_TRFCAB_MIN_LO	0x1d
#define	SPD_LP5_TRFCAB_MIN_HI	0x1e

/*
 * Per Bank Minimum Refresh Recovery Delay Time t~RFCpb~min. This is a 16-bit
 * quantity that is split between a lower and upper value. Both registers are in
 * terms of the medium time base.
 */
#define	SPD_LP5_TRFCPB_MIN_LO	0x1f
#define	SPD_LP5_TRFCPB_MIN_HI	0x20

/*
 * DDR5 and LPDDR5/x share the common definitions for the module and
 * manufacturer's information. The module-type specific overlays such as
 * soldered down and CAMM2 are shared between all of them and are currently
 * defined in the spd_ddr5.h header.
 */

#ifdef __cplusplus
}
#endif

#endif /* _SPD_LP5_H */
