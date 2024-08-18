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

#ifndef _SPD_DDR3_H
#define	_SPD_DDR3_H

/*
 * Definitions for use in DDR3 Serial Presence Decoding
 * based on JEDEC Standard 21-C Section Annex K: Serial Presence Detect
 * (SPD) for DDR3 SDRAM Modules Release 6.
 *
 * DDR3 modules are organized in a 256 byte memory map:
 *
 *   o Base Configuration and DRAM parameters (bytes 0x00-0x3b)
 *   o Standard Module Parameters (bytes 0x40-0x74) these vary on whether
 *     something is considered an RDIMM, UDIMM, etc.
 *   o Manufacturing Information (bytes 0x75-0xaf)
 *   o End User Programmable data (0xb0-0xff).
 */

#include <sys/bitext.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Number of Bytes Used / Number of Bytes in SPD Device / CRC Coverage
 */
#define	SPD_DDR3_NBYTES		0x00
#define	SPD_DDR3_NBYTES_CRC(r)		bitx8(r, 7, 7)
#define	SPD_DDR3_NBYTES_CRC_125		0
#define	SPD_DDR3_NBYTES_CRC_116		1
#define	SPD_DDR3_NBYTES_TOTAL(r)	bitx8(r, 6, 4)
#define	SPD_DDR3_NBYTES_TOTAL_UNDEF	0
#define	SPD_DDR3_NBYTES_TOTAL_256	1
#define	SPD_DDR3_NBYTES_USED(r)		bitx8(r, 3, 0)
#define	SPD_DDR3_NBYTES_USED_UNDEF	0
#define	SPD_DDR3_NBYTES_USED_128	1
#define	SPD_DDR3_NBYTES_USED_176	2
#define	SPD_DDR3_NBYTES_USED_256	3

/*
 * SPD Revision. This is the same as described in SPD_DDR4_SPD_REV as
 * defined in spd_ddr4.h.
 */
#define	SPD_DDR3_SPD_REV	0x01
#define	SPD_DDR3_SPD_REV_ENC(r)	bitx8(r, 7, 4)
#define	SPD_DDR3_SPD_REV_ADD(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_SPD_REV_V1	1

/*
 * Key Byte / DRAM Device Type. This field identifies the type of DDR device and
 * is actually consistent across all SPD versions. Known values are in the
 * spd_dram_type_t enumeration.
 */
#define	SPD_DDR3_DRAM_TYPE	0x02

/*
 * Key Byte / Module Type. This is used to describe what kind of DDR module it
 * is, which tells us what the module-specific section contents are. These bits,
 * unlike the one above are device specific.
 */
#define	SPD_DDR3_MOD_TYPE	0x03
#define	SPD_DDR3_MOD_TYPE_TYPE(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_MOD_TYPE_TYPE_UNDEF		0
#define	SPD_DDR3_MOD_TYPE_TYPE_RDIMM		1
#define	SPD_DDR3_MOD_TYPE_TYPE_UDIMM		2
#define	SPD_DDR3_MOD_TYPE_TYPE_SODIMM		3
#define	SPD_DDR3_MOD_TYPE_TYPE_MICRO_DIMM	4
#define	SPD_DDR3_MOD_TYPE_TYPE_MINI_RDIMM	5
#define	SPD_DDR3_MOD_TYPE_TYPE_MINI_UDIMM	6
#define	SPD_DDR3_MOD_TYPE_TYPE_MINI_CDIMM	7
#define	SPD_DDR3_MOD_TYPE_TYPE_72b_SORDIMM	8
#define	SPD_DDR3_MOD_TYPE_TYPE_72b_SOUDIMM	9
#define	SPD_DDR3_MOD_TYPE_TYPE_72b_SOCDIMM	10
#define	SPD_DDR3_MOD_TYPE_TYPE_LRDIMM		11
#define	SPD_DDR3_MOD_TYPE_TYPE_16b_SODIMM	12
#define	SPD_DDR3_MOD_TYPE_TYPE_32b_SODIMM	13

/*
 * SDRAM Density and Banks
 */
#define	SPD_DDR3_DENSITY	0x04
#define	SPD_DDR3_DENSITY_NBA_BITS(r)	bitx8(r, 6, 4)
#define	SPD_DDR3_DENSITY_NBA_BITS_BASE	3
#define	SPD_DDR3_DENSITY_NBA_BITS_MAX	6
#define	SPD_DDR3_DENSITY_DENSITY(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_DENSITY_DENSITY_256Mb	0
#define	SPD_DDR3_DENSITY_DENSITY_512Mb	1
#define	SPD_DDR3_DENSITY_DENSITY_1Gb	2
#define	SPD_DDR3_DENSITY_DENSITY_2Gb	3
#define	SPD_DDR3_DENSITY_DENSITY_4Gb	4
#define	SPD_DDR3_DENSITY_DENSITY_8Gb	5
#define	SPD_DDR3_DENSITY_DENSITY_16Gb	6
#define	SPD_DDR3_DENSITY_DENSITY_32Gb	7
#define	SPD_DDR3_DENSITY_DENSITY_12Gb	8
#define	SPD_DDR3_DENSITY_DENSITY_24Gb	9

/*
 * SDRAM Addressing.
 */
#define	SPD_DDR3_ADDR		0x05
#define	SPD_DDR3_ADDR_NROWS(r)		bitx8(r, 5, 3)
#define	SPD_DDR3_ADDR_NROWS_BASE	12
#define	SPD_DDR3_ADDR_NROWS_MAX		16
#define	SPD_DDR3_ADDR_NCOLS(r)		bitx8(r, 2, 0)
#define	SPD_DDR3_ADDR_NCOLS_BASE	9
#define	SPD_DDR3_ADDR_NCOLS_MAX		12

/*
 * Module Nominal Voltage, VDD
 */
#define	SPD_DDR3_VOLT		0x06
#define	SPD_DDR3_VOLT_V1P25_OPER(r)	bitx8(r, 2, 2)
#define	SPD_DDR3_VOLT_V1P35_OPER(r)	bitx8(r, 1, 1)
#define	SPD_DDR3_VOLT_V1P5_OPER(r)	bitx8(r, 0, 0)

/*
 * Module Organization
 */
#define	SPD_DDR3_MOD_ORG	0x07
#define	SPD_DDR3_MOD_ORG_NRANKS(r)	bitx(r, 5, 3)
#define	SPD_DDR3_MOD_ORG_NRANKS_1	0
#define	SPD_DDR3_MOD_ORG_NRANKS_2	1
#define	SPD_DDR3_MOD_ORG_NRANKS_3	2
#define	SPD_DDR3_MOD_ORG_NRANKS_4	3
#define	SPD_DDR3_MOD_ORG_NRANKS_8	4
#define	SPD_DDR4_MOD_ORG_WIDTH(r)	bitx8(r, 2, 0)
#define	SPD_DDR3_MOD_ORG_WIDTH_BASE	2
#define	SPD_DDR3_MOD_ORG_WIDTH_MAX	32

/*
 * Module Memory Bus Width
 */
#define	SPD_DDR3_BUS_WIDTH	0x08
#define	SPD_DDR3_BUS_WIDTH_EXT(r)	bitx8(r, 4, 3)
#define	SPD_DDR3_BUS_WIDTH_EXT_NONE	0
#define	SPD_DDR3_BUS_WIDTH_EXT_8b	1
#define	SPD_DDR3_BUS_WIDTH_PRI(r)	bitx8(r, 2, 0)
#define	SPD_DDR3_BUS_WIDTH_PRI_BASE	3
#define	SPD_DDR3_BUS_WIDTH_PRI_MAX	64

/*
 * Fine Timebase (FTB) Dividend / Divisor. While LPDDR3+ and DDR4+ use fixed
 * timebases, DDR3 does not and the fine time base is defined as a divisor and
 * dividend.
 */
#define	SPD_DDR3_FTB		0x09
#define	SPD_DDR3_FTB_DIVIDEND(r)	bitx8(r, 7, 4)
#define	SPD_DDR3_FTB_DIVISOR(r)		bitx8(r, 3, 0)
#define	SPD_DDR3_FTB_PS		1

/*
 * Medium Timebase (MTB) Dividend and Divisor. Like the FTB, this is split into
 * two different values. DDR3 only defines a single valid MTB value, a dividend
 * of 1 and a divisor of 8 meaning that the MTB is 125 ps.
 */
#define	SPD_DDR3_MTB_DIVIDEND	0x0a
#define	SPD_DDR3_MTB_DIVISOR	0x0b
#define	SPD_DDR3_MTB_PS		125
#define	SPD_DDR3_MTB_125PS_DIVIDEND	1
#define	SPD_DDR3_MTB_125PS_DIVISOR	8

/*
 * SDRAM Minimum Cycle Time t~CK~min. This is only in units of MTB.
 * Fine offset for ^
 */
#define	SPD_DDR3_TCK_MIN	0x0c
#define	SPD_DDR3_TCK_MIN_FINE	0x22

/*
 * Supported CAS Latencies. There are two bytes that are used to get at what
 * speeds are supported. This starts at CL4 and goes up by 1 each time.
 */
#define	SPD_DDR3_CAS_SUP0	0x0e
#define	SPD_DDR3_CAS_SUP1	0x0f
#define	SPD_DDR3_CAS_BASE	0x04

/*
 * Minimum CAS Latency Time t~AA~min.
 * Fine Offset for ^
 */
#define	SPD_DDR3_TAA_MIN	0x10
#define	SPD_DDR3_TAA_MIN_FINE	0x23

/*
 * Minimum Write Recovery Time t~WR~min.
 */
#define	SPD_DDR3_TWR_MIN	0x11

/*
 * Minimum RAS to CAS Delay Time t~RCD~min.
 * Fine Offset for ^
 */
#define	SPD_DDR3_TRCD_MIN	0x12
#define	SPD_DDR3_TRCD_MIN_FINE	0x24

/*
 * Minimum Row Active to Row Active Delay Time t~RRD~min
 */
#define	SPD_DDR3_TRRD_MIN	0x13

/*
 * Minimum Row Precharge Delay Time t~RP~min.
 * Fine Offset for ^
 */
#define	SPD_DDR3_TRP_MIN	0x14
#define	SPD_DDR3_TRP_MIN_FINE	0x25

/*
 * Upper Nibbles for t~RAS~min and t~RC~min. These are bits 11:9 of
 * these values. The lower byte is in subsequent values.
 * Minimum Active to Precharge Delay Time t~RAS~min.
 * Minimum Active to Active/Refresh Delay Time t~RC~min.
 * Fine Offset for ^
 */
#define	SPD_DDR3_RAS_RC_UPPER	0x15
#define	SPD_DDR3_RAS_RC_UPPER_RC(r)	bitx8(r, 7, 4)
#define	SPD_DDR3_RAS_RC_UPPER_RAS(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_TRAS_MIN	0x16
#define	SPD_DDR3_TRC_MIN	0x17
#define	SPD_DDR3_TRC_MIN_FINE	0x26

/*
 * Minimum Refresh Recovery Delay Time t~RFC~min. This value is split into two
 * bytes of MTB.
 */
#define	SPD_DDR3_TRFC_MIN_LSB	0x18
#define	SPD_DDR3_TRFC_MIN_MSB	0x19

/*
 * Minimum Internal Write to Read Command Delay t~WTR~min.
 */
#define	SPD_DDR3_TWTR_MIN	0x1a

/*
 * Minimum Internal Read to Precharge Command Delay Time t~RTP~min.
 */
#define	SPD_DDR3_TRTP_MIN	0x1b

/*
 * Upper Nibble for t~FAW~
 * Minimum Four Activate Window Delay Time t~FAW~min
 */
#define	SPD_DDR3_TFAW_NIB	0x1c
#define	SPD_DDR3_TFAB_NIB_UPPER_TFAW(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_TFAW_LSB	0x1d

/*
 * SDRAM Optional Features
 */
#define	SPD_DDR3_OPT_FEAT	0x1e
#define	SPD_DDR3_OPT_FEAT_DLLO(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_OPT_FEAT_RZQ7(r)	bitx8(r, 1, 1)
#define	SPD_DDR3_OPT_FEAT_RZQ6(r)	bitx8(r, 0, 0)

/*
 * SDRAM Thermal and Refresh Options
 */
#define	SPD_DDR3_REFRESH		0x1f
#define	SPD_DDR3_REFRESH_PASR_SUP(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_REFRESH_ODTS_SUP(r)	bitx8(r, 3, 3)
#define	SPD_DDR3_REFRESH_ASR_SUP(r)	bitx8(r, 2, 2)
#define	SPD_DDR3_REFRESH_ETR_REF(r)	bitx8(r, 1, 1)
#define	SPD_DDR3_REFRESH_ETR_REF_2X	0
#define	SPD_DDR3_REFRESH_ETR_REF_1X	1
#define	SPD_DDR3_REFRESH_ETR_TEMP(r)	bitx8(r, 0, 0)
#define	SPD_DDR3_REFRESH_ETR_TEMP_85C	0
#define	SPD_DDR3_REFRESH_ETR_TEMP_95C	1

/*
 * Module Thermal Sensor. If present, this complies with TSE2002. The remaining
 * bits here are used for thermal sensor accuracy and all values are undefined.
 */
#define	SPD_DDR3_MOD_THERM	0x20
#define	SPD_DDR3_MOD_THERM_PRES(r)	bitx8(r, 7, 7)

/*
 * SDRAM Device Type
 */
#define	SPD_DDR3_TYPE		0x21
#define	SPD_DDR3_PKG_TYPE(r)		bitx8(r, 7, 7)
#define	SPD_DDR3_PKG_TYPE_MONO		0
#define	SPD_DDR3_PKG_TYPE_NOT		1
#define	SPD_DDR3_PKG_DIE_CNT(r)		bitx8(r, 6, 4)
#define	SPD_DDR3_PKG_DIE_CNT_MIN	1
#define	SPD_DDR3_PKG_DIE_CNT_MAX	8
#define	SPD_DDR3_PKG_SIG_LOAD(r)	bitx8(r, 1, 0)
#define	SPD_DDR3_PKG_SIG_LOAD_UNSPEC	0
#define	SPD_DDR3_PKG_SIG_LOAD_MULTI	1
#define	SPD_DDR3_PKG_SIG_LOAD_SINGLE	2

/*
 * SDRAM Maximum Active Count
 */
#define	SPD_DDR3_MAC		0x29
#define	SPD_DDR3_MAC_MAW(r)		bitx8(r, 5, 4)
#define	SPD_DDR3_MAC_MAW_8192X		0
#define	SPD_DDR3_MAC_MAW_4096X		1
#define	SPD_DDR3_MAC_MAW_2048X		2
#define	SPD_DDR3_MAC_MAC(r)		bitx8(r, 3, 0)
#define	SPD_DDR3_MAC_MAC_UNTESTED	0
#define	SPD_DDR3_MAC_MAC_700K		1
#define	SPD_DDR3_MAC_MAC_600K		2
#define	SPD_DDR3_MAC_MAC_500K		3
#define	SPD_DDR3_MAC_MAC_400K		4
#define	SPD_DDR3_MAC_MAC_300K		5
#define	SPD_DDR3_MAC_MAC_200K		6
#define	SPD_DDR3_MAC_MAC_UNLIMITED	8

/*
 * Module Specific Bytes. There are four annexes defined: UDIMMs, RDIMMs,
 * CDIMMs, and LRDIMMS.
 */

/*
 * Annex K.1 Module Specific Bytes for Unbuffered Memory Module Types.
 */

/*
 * UDIMM: Raw Card Extension, Module Nominal Height. Bits 7-5 here have a raw
 * card revision. The revision extension, bits 7:5, are only valid when the
 * value of the normal reference card used in byte 0x3e is set to 0b11 (3).
 */
#define	SPD_DDR3_UDIMM_HEIGHT	0x3c
#define	SPD_DDR3_UDIMM_HEIGHT_REV(r)	bitx8(r, 7, 5)
#define	SPD_DDR3_UDIMM_HEIGHT_MM(r)	bitx8(r, 4, 0)
#define	SPD_DDR3_UDIMM_HEIGHT_LT15MM	0
#define	SPD_DDR3_UDIMM_HEIGHT_BASE	15

/*
 * UDIMM: Module Maximum Thickness. These measure thicknesses in mm,
 * with zero value meaning less than or equal to 1mm.
 */
#define	SPD_DDR3_UDIMM_THICK	0x3d
#define	SPD_DDR3_UDIMM_THICK_BACK(r)	bitx8(r, 7, 4)
#define	SPD_DDR3_UDIMM_THICK_FRONT(r)	bitx8(r, 3, 0)
#define	SPD_DDR3_UDIMM_THICK_BASE	1

/*
 * UDIMM: Reference Raw Card Used. Bit 7 is used as basically another
 * bit for bits 4-0. We do not define each meaning of these bit combinations in
 * this header, that is left for tables in the library. When bits 6:5 are 0b11
 * (3) then we must add in the reference card value in byte 0x80 to bits 6:5.
 */
#define	SPD_DDR3_UDIMM_REF	0x3e
#define	SPD_DDR3_UDIMM_REF_EXT(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_UDIMM_REF_REV(r)	bitx8(r, 6, 5)
#define	SPD_DDR3_UDIMM_REV_USE_HEIGHT	3
#define	SPD_DDR3_UDIMM_REF_CARD(r)	bitx8(r, 4, 0)

/*
 * UDIMM: Address Mapping from Edge Connector to DRAM.
 */
#define	SPD_DDR3_UDIMM_MAP	0x3f
#define	SPD_DDR3_UDIMM_MAP_R1(r)	bitx8(r, 0, 0)
#define	SPD_DDR3_UDIMM_MAP_R1_STD	0
#define	SPD_DDR3_UDIMM_MAP_R1_MIRROR	1

/*
 * Annex K.2 Module Specific bytes for Registered Memory Module Types.
 */

/*
 * RDIMM: Raw Card Extension, Module Nominal Height
 * RDIMM: Module Maximum Thickness
 * RDIMM: Reference Raw Card Used
 *
 * These have the same definitions as the DDR3 UDIMM.
 */
#define	SPD_DDR3_RDIMM_HEIGHT	0x3c
#define	SPD_DDR3_RDIMM_THICK	0x3d
#define	SPD_DDR3_RDIMM_REF	0x3e

/*
 * RDIMM: DIMM Module Attributes
 */
#define	SPD_DDR3_RDIMM_ATTR	0x3f
#define	SPD_DDR3_RDIMM_ATTR_NROWS(r)	bitx8(r, 3, 2)
#define	SPD_DDR3_RDIMM_ATTR_NREGS(r)	bitx8(r, 1, 0)

/*
 * RDIMM: Thermal Heat Spreader Solution.
 */
#define	SPD_DDR3_RDIMM_THERM	0x40
#define	SPD_DDR3_RDIMM_THERM_IMPL(r)	bitx8(r, 7, 7)

/*
 * RDIMM: Register Manufacturer JEDEC ID. This contains the JEDEC ID for the
 * manufacturer encoded as the number of continuation bytes and then the actual
 * code. This works with libjedec_vendor_string.
 */
#define	SPD_DDR3_RDIMM_REG_MFG_ID0	0x41
#define	SPD_DDR3_RDIMM_REG_MFG_ID1	0x42

/*
 * RDIMM: Register Revision Number. This value is just a straight up hex encoded
 * value. It's a bit arbitrary. For example, they say 0x31 can be rev 3.1, while
 * 0x01 is just revision 1, and 0xB1 is revision B1.
 */
#define	SPD_DDR3_RDIMM_REV	0x43
#define	SPD_DDR3_RDIMM_REV_UNDEF	0xff

/*
 * RDIMM: Register Type
 */
#define	SPD_DDR3_RDIMM_RTYPE	0x44
#define	SPD_DDR3_RDIMM_RTYPE_TYPE(r)	bitx8(r, 2, 0)
#define	SPD_DDR3_RDIMM_RTYPE_TYPE_SSTE32882	0

/*
 * Byte 69 (0x45) is reserved for future use.
 */

/*
 * RDIMM: SSTE32882: RC3 / RC2 - Drive Strength, Command/Address. The lower
 * nibble is reserved.
 */
#define	SPD_DDR3_RDIMM_CADS	0x46
#define	SPD_DDR3_RDIMM_CADS_CAA(r)	bitx8(r, 5, 4)
#define	SPD_DDR3_RDIMM_DS_LIGHT		0
#define	SPD_DDR3_RDIMM_DS_MODERATE	1
#define	SPD_DDR3_RDIMM_DS_STRONG	2
#define	SPD_DDR3_RDIMM_DS_VERY_STRONG	3	/* LRDIMMs only */
#define	SPD_DDR3_RDIMM_CADS_CAB(r)	bitx8(r, 7, 6)

/*
 * RDIMM: SSTE32882: RC5 / RC4 - Drive Strength, Control and Clock
 */
#define	SPD_DDR3_RDIMM_CCDS	0x47
#define	SPD_DDR3_RDIMM_CCDS_CLK0(r)	bitx8(r, 7, 6)
#define	SPD_DDR3_RDIMM_CCDS_CLK1(r)	bitx8(r, 5, 4)
#define	SPD_DDR3_RDIMM_CCDS_CTLB(r)	bitx8(r, 3, 2)
#define	SPD_DDR3_RDIMM_CCDS_CTLA(r)	bitx8(r, 1, 0)

/*
 * Bytes 72-76 have definitions but must be written as zero and are all
 * reserved. As such we don't define any of them. The rest of the section is
 * fully reserved.
 */

/*
 * Annex K.3: Module Specific Bytes for Clocked Memory Module Types
 *
 * CDIMM: Raw Card Extension, Module Nominal Height
 * CDIMM: Module Maximum Thickness
 * CDIMM: Reference Raw Card Used
 *
 * These have the same definitions as the DDR3 UDIMM.
 */
#define	SPD_DDR3_CDIMM_HEIGHT	0x3c
#define	SPD_DDR3_CDIMM_THICK	0x3d
#define	SPD_DDR3_CDIMM_REF	0x3e

/*
 * Annex K.4: Module Specific Bytes for Load Reduced Memory Module Types
 */

/*
 * LRDIMM: Raw Card Extension, Module Nominal Height
 * LRDIMM: Module Maximum Thickness
 * LRDIMM: Reference Raw Card Used
 *
 * These have the same definitions as the DDR3 UDIMM.
 */
#define	SPD_DDR3_LRDIMM_HEIGHT	0x3c
#define	SPD_DDR3_LRDIMM_THICK	0x3d
#define	SPD_DDR3_LRDIMM_REF	0x3e

/*
 * LRDIMM: Module Attributes
 */
#define	SPD_DDR3_LRDIMM_ATTR	0x3f
#define	SPD_DDR3_LRDIMM_ATTR_HS(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_LRDIMM_ATTR_RN(r)	bitx8(r, 5, 5)
#define	SPD_DDR3_LRDIMM_ATTR_RN_CONTIG	0
#define	SPD_DDR3_LRDIMM_ATTR_RN_EVEN	1
#define	SPD_DDR3_LRDIMM_ATTR_ORIENT(r)	bitx8(r, 4, 4)
#define	SPD_DDR3_LRDIMM_ATTR_ORIENT_VERT	0
#define	SPD_DDR3_LRDIMM_ATTR_ORIENT_HORIZ	1
#define	SPD_DDR3_LRDIMM_ATTR_NROWS(r)	bitx8(r, 3, 2)
#define	SPD_DDR3_LRDIMM_ATTR_MIR(r)	bitx8(r, 1, 0)
#define	SPD_DDR3_LRDIMM_ATTR_MIR_ALL_NONE	0
#define	SPD_DDR3_LRDIMM_ATTR_MIR_ODD_ARE	1

/*
 * LRDIMM: Memory Buffer Revision Number
 * LRDIMM: Memory Buffer Manufacturer ID Code
 */
#define	SPD_DDR3_LRDIMM_MB_REV	0x40
#define	SPD_DDR3_LRDIMM_MB_MFG_ID0	0x41
#define	SPD_DDR3_LRDIMM_MB_MFG_ID1	0x42

/*
 * LRDIMM: F0RC3 / F0RC2 - Timing Control & Drive Strength, Address/Command &
 * QxCS_n
 *
 * Drive strength values and encodings are shared with RDIMMs.
 */
#define	SPD_DDR3_LRDIMM_TCDS	0x43
#define	SPD_DDR3_LRDIMM_TCDS_QxCS(r)	bitx8(r, 7, 6)
#define	SPD_DDR3_LRDIMM_TCDS_AC(r)	bitx8(r, 5, 4)
#define	SPD_DDR3_LRDIMM_TCDS_SWAP(r)	bitx8(r, 1, 1)
#define	SPD_DDR3_LRDIMM_TCDS_SWAP_NONE	0
#define	SPD_DDR3_LRDIMM_TCDS_SWAP_R15	1
#define	SPD_DDR3_LRDIMM_TCDS_ACPL(r)	bitx8(r, 0, 0)
#define	SPD_DDR3_LRDIMM_TCDS_ACPL_STD		0
#define	SPD_DDR3_LRDIMM_TCDS_ACPL_F1RC12	1

/*
 * LRDIMM: F0RC5 / F0RC4 - Drive Strength, QxODT & QxCKE and Clock
 */
#define	SPD_DDR3_LRDIMM_CKDS	0x44
#define	SPD_DDR3_LRDIMM_CKDS_Y0Y2(r)	bitx8(r, 7, 6)
#define	SPD_DDR3_LRDIMM_CKDS_Y1Y3(r)	bitx8(r, 5, 4)
#define	SPD_DDR3_LRDIMM_CKDS_CKE(r)	bitx8(r, 3, 2)
#define	SPD_DDR3_LRDIMM_CKDS_ODT(r)	bitx8(r, 1, 0)

/*
 * LRDIMM: F1RC11 / F1RC8 - Extended Delay for Clocks, QxCS_n and QxODT & QxCKE
 *
 * Delay measures are defined in terms of 1/128 clock cycles.
 */
#define	SPD_DDR3_LRDIMM_EXTD	0x45
#define	SPD_DDR3_LRDIMM_EXTD_CKE(r)	bitx8(r, 7, 6)
#define	SPD_DDR3_LRDIMM_EXTD_ODT(r)	bitx8(r, 5, 4)
#define	SPD_DDR3_LRDIMM_EXTD_CS(r)	bitx8(r, 3, 2)
#define	SPD_DDR3_LRDIMM_EXTD_Y(r)	bitx8(r, 1, 0)

/*
 * LRDIMM: F1RC13 / F1RC12 - Additive Delay for QxCS and QxCA
 *
 * Values are shared between this and the next registers. The Y value delay
 * controls are bit 0 in SPD_DDR3_LRDIMM_TCDS_ACPL.
 */
#define	SPD_DDR3_LRDIMM_ADDD_CSY	0x46
#define	SPD_DDR3_LRDIMM_ADDD_CSY_CS_EN(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_LRDIMM_ADDD_CSY_CS(r)		bitx8(r, 6, 4)
#define	SPD_DDR3_LRDIMM_ADDD_CSY_Y(r)		bitx8(r, 2, 0)
#define	SPD_DDR3_LRDIMM_ADD_BASE		8

/*
 * LRDIMM: F1RC15 / F1RC14 - Additive Delay for QxODT and QxCKE
 */
#define	SPD_DDR3_LRDIMM_ADDD_ODT	0x47
#define	SPD_DDR3_LRDIMM_ADDD_ODT_CKE_EN(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_LRDIMM_ADDD_ODT_CKE(r)		bitx8(r, 6, 4)
#define	SPD_DDR3_LRDIMM_ADDD_ODT_ODT_EN(r)	bitx8(r, 3, 3)
#define	SPD_DDR3_LRDIMM_ADDD_ODT_ODT(r)		bitx8(r, 2, 0)

/*
 * This constant represents the gap between a register and its corresponding
 * speed variants. This section of LRDIMM data has a version for 800, 133, and
 * 1866 which are all 6 registers apart.
 */
#define	SPD_DDR3_LRDIMM_STRIDE	6

/*
 * LRDIMM: F3RC9 / F3RC8 - DRAM Interface MDQ Termination and Drive Strength
 * <= 1066
 * LRDIMM: F3RC9 / F3RC8 - DRAM Interface MDQ Termination and Drive Strength
 * >= 1333 <= 1600
 * LRDIMM: F3RC9 / F3RC8 - DRAM Interface MDQ Termination and Drive Strength
 * >= 1866 <= 2133
 */
#define	SPD_DDR3_LRDIMM_MDQ_800		0x48
#define	SPD_DDR3_LRDIMM_MDQ_1333	0x4e
#define	SPD_DDR3_LRDIMM_MDQ_1866	0x54
#define	SPD_DDR3_LRDIMM_MDQ_DS(r)	bitx8(r, 6, 4)
#define	SPD_DDR3_LRDIMM_MDQ_DS_40R	0
#define	SPD_DDR3_LRDIMM_MDQ_DS_34R	1
#define	SPD_DDR3_LRDIMM_MDQ_DS_48R	2
#define	SPD_DDR3_LRDIMM_MDQ_DS_27R	3
#define	SPD_DDR3_LRDIMM_MDQ_DS_20R	4
#define	SPD_DDR3_LRDIMM_MDQ_ODT(r)	bitx8(r, 2, 0)
#define	SPD_DDR3_LRDIMM_MDQ_ODT_DIS	0
#define	SPD_DDR3_LRDIMM_MDQ_ODT_60R	1
#define	SPD_DDR3_LRDIMM_MDQ_ODT_120R	2
#define	SPD_DDR3_LRDIMM_MDQ_ODT_40R	3
#define	SPD_DDR3_LRDIMM_MDQ_ODT_30R	5
#define	SPD_DDR3_LRDIMM_MDQ_ODT_240R	6
#define	SPD_DDR3_LRDIMM_MDQ_ODT_80R	7

/*
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 0/1 R/W QxODT Control <= 1066
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 2/3 R/W QxODT Control <= 1066
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 4/5 R/W QxODT Control <= 1066
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 6/7 R/W QxODT Control <= 1066
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 0/1 R/W QxODT Control >= 1333 <= 1600
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 2/3 R/W QxODT Control >= 1333 <= 1600
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 4/5 R/W QxODT Control >= 1333 <= 1600
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 6/7 R/W QxODT Control >= 1333 <= 1600
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 0/1 R/W QxODT Control >= 1866 <= 2133
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 2/3 R/W QxODT Control >= 1866 <= 2133
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 4/5 R/W QxODT Control >= 1866 <= 2133
 * LRDIMM: F[3,4]RC11 / F[3,4]RC10 - Rank 6/7 R/W QxODT Control >= 1866 <= 2133
 *
 * These registers all have the same layout, just different targeted ranks.
 */
#define	SPD_DDR3_LRDIMM_ODT_R0_800	0x49
#define	SPD_DDR3_LRDIMM_ODT_R2_800	0x4a
#define	SPD_DDR3_LRDIMM_ODT_R4_800	0x4b
#define	SPD_DDR3_LRDIMM_ODT_R6_800	0x4c
#define	SPD_DDR3_LRDIMM_ODT_R0_1333	0x4f
#define	SPD_DDR3_LRDIMM_ODT_R2_1333	0x50
#define	SPD_DDR3_LRDIMM_ODT_R4_1333	0x51
#define	SPD_DDR3_LRDIMM_ODT_R6_1333	0x52
#define	SPD_DDR3_LRDIMM_ODT_R0_1866	0x55
#define	SPD_DDR3_LRDIMM_ODT_R2_1866	0x56
#define	SPD_DDR3_LRDIMM_ODT_R4_1866	0x57
#define	SPD_DDR3_LRDIMM_ODT_R6_1866	0x58
#define	SPD_DDR3_LRDIMM_ODT_R1_ODT1_WR(r)	bitx8(r, 7, 7)
#define	SPD_DDR3_LRDIMM_ODT_R1_ODT0_WR(r)	bitx8(r, 6, 6)
#define	SPD_DDR3_LRDIMM_ODT_R0_ODT1_WR(r)	bitx8(r, 5, 5)
#define	SPD_DDR3_LRDIMM_ODT_R0_ODT0_WR(r)	bitx8(r, 4, 4)
#define	SPD_DDR3_LRDIMM_ODT_R1_ODT1_RD(r)	bitx8(r, 3, 3)
#define	SPD_DDR3_LRDIMM_ODT_R1_ODT0_RD(r)	bitx8(r, 2, 2)
#define	SPD_DDR3_LRDIMM_ODT_R0_ODT1_RD(r)	bitx8(r, 1, 1)
#define	SPD_DDR3_LRDIMM_ODT_R0_ODT0_RD(r)	bitx8(r, 0, 0)

/*
 * LRDIMM: MR1,2 <= 1066
 * LRDIMM: MR1,2 >= 1333 <= 1600
 * LRDIMM: MR1,2 >= 1866 <= 2133
 */
#define	SPD_DDR3_LRDIMM_RTT_800		0x4d
#define	SPD_DDR3_LRDIMM_RTT_1333	0x53
#define	SPD_DDR3_LRDIMM_RTT_1866	0x59
#define	SPD_DDR3_LRDIMM_RTT_WR(r)	bitx8(r, 7, 6)
#define	SPD_DDR3_LRDIMM_RTT_WR_DIS	0
#define	SPD_DDR3_LRDIMM_RTT_WR_60R	1
#define	SPD_DDR3_LRDIMM_RTT_WR_120R	2
#define	SPD_DDR3_LRDIMM_RTT_NOM(r)	bitx8(r, 4, 2)
#define	SPD_DDR3_LRDIMM_RTT_NOM_DIS	0
#define	SPD_DDR3_LRDIMM_RTT_NOM_60R	1
#define	SPD_DDR3_LRDIMM_RTT_NOM_120R	2
#define	SPD_DDR3_LRDIMM_RTT_NOM_40R	3
#define	SPD_DDR3_LRDIMM_RTT_NOM_20R	4
#define	SPD_DDR3_LRDIMM_RTT_NOM_30R	5
#define	SPD_DDR3_LRDIMM_RTT_IMP(r)	bitx8(r, 1, 0)
#define	SPD_DDR3_LRDIMM_RTT_IMP_40R	0
#define	SPD_DDR3_LRDIMM_RTT_IMP_34R	1

/*
 * LRDIMM: Minimum Module Delay Time for 1.5V
 * LRDIMM: Maximum Module Delay Time for 1.5V
 * LRDIMM: Minimum Module Delay Time for 1.35V
 * LRDIMM: Maximum Module Delay Time for 1.35V
 * LRDIMM: Minimum Module Delay Time for 1.25V
 * LRDIMM: Maximum Module Delay Time for 1.25V
 */
#define	SPD_DDR3_LRDIMM_MIN_DELAY_1V5	0x5a
#define	SPD_DDR3_LRDIMM_MAX_DELAY_1V5	0x5b
#define	SPD_DDR3_LRDIMM_MIN_DELAY_1V35	0x5c
#define	SPD_DDR3_LRDIMM_MAX_DELAY_1V35	0x5d
#define	SPD_DDR3_LRDIMM_MIN_DELAY_1V25	0x5e
#define	SPD_DDR3_LRDIMM_MAX_DELAY_1V25	0x5f

/*
 * LRDIMM: Memory Buffer Personality Bytes
 */
#define	SPD_DDR3_LRDIMM_PERS	0x66
#define	SPD_DDR3_LRDIMM_PERS_NBYTES	15


/*
 * S2.3 Unique Module ID Bytes. This is a two byte JEP-108 style ID.
 */
#define	SPD_DDR3_MFG_MOD_ID0	0x75
#define	SPD_DDR3_MFG_MOD_ID1	0x76

/*
 * Module Manufacturing Location
 */
#define	SPD_DDR3_MFG_LOC	0x77

/*
 * Module Manufacturing Date. Encoded as two BCD bytes for the year and week.
 */
#define	SPD_DDR3_MFG_YEAR	0x78
#define	SPD_DDR3_MFG_WEEK	0x79

/*
 * Module Serial Number
 */
#define	SPD_DDR3_MOD_SN		0x7a
#define	SPD_DDR3_MOD_SN_LEN	4

/*
 * SPD Cyclical Redundancy Code (CRC)
 */
#define	SPD_DDR3_CRC_LSB	0x7e
#define	SPD_DDR3_CRC_MSB	0x7f

/*
 * Module Part Number
 */
#define	SPD_DDR3_MOD_PN		0x80
#define	SPD_DDR3_MOD_PN_LEN	18

/*
 * Module Revision Code
 */
#define	SPD_DDR3_MOD_REV	0x92
#define	SPD_DDR3_MOD_REV_LEN	2

/*
 * DRAM Manufacturer ID Code. This is a two byte JEP-108 style ID.
 */
#define	SPD_DDR3_MFG_DRAM_ID0	0x94
#define	SPD_DDR3_MFG_DRAM_ID1	0x95

/*
 * The remaining portions of this are defined for the manufacturer's and end
 * user's use.
 */

#ifdef __cplusplus
}
#endif

#endif /* _SPD_DDR3_H */
