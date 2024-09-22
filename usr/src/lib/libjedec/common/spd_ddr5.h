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

#ifndef _SPD_DDR5_H
#define	_SPD_DDR5_H

/*
 * Definitions for use in DDR5 Serial Presence Detect decoding based on JEDEC
 * Standard JESD400-5A.01 DDR5 Serial Presence Detect (SPD) Contents. Release
 * 1.2. This does not cover LPDDR5. While the two are similar, there are enough
 * differences that we maintain LPDDR5 in its own header (spd_lp5.h).
 *
 * DDR5 modules are organized into a few main regions:
 *
 *   o Base Configuration and DRAM parameters (0x00-0x7f)
 *   o Common Module Parameters (0xc0-0xef)
 *   o Standard Module Parameters (0xf0-0x1bf) which vary on whether something
 *     is an RDIMM, UDIMM, etc.
 *   o A CRC check for the first 510 bytes (0x1fe-0x1ff)
 *   o Manufacturing Information (0x200-0x27f)
 *   o Optional end-user programmable regions (0x280-0x3ff)
 *
 * This covers all DDR5 variants other than NVDIMMs.
 */

#include <sys/bitext.h>
#include "spd_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * S8.1.1 Number of Bytes in SPD Device and Beta Level
 */
#define	SPD_DDR5_NBYTES	0x000
#define	SPD_DDR5_NBYTES_BETAHI(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_NBYTES_TOTAL(r)	bitx8(r, 6, 4)
#define	SPD_DDR5_NBYTES_TOTAL_UNDEF	0
#define	SPD_DDR5_NBYTES_TOTAL_256	1
#define	SPD_DDR5_NBYTES_TOTAL_512	2
#define	SPD_DDR5_NBYTES_TOTAL_1024	3
#define	SPD_DDR5_NBYTES_TOTAL_2048	4
#define	SPD_DDR5_NBYTES_BETA(r)		bitx8(r, 3, 0)

/*
 * S8.1.2 SPD Revision for Base Configuration Parameters. This is the same as
 * described in SPD_DDR4_SPD_REV as defined in spd_ddr4.h.
 */
#define	SPD_DDR5_SPD_REV	0x001
#define	SPD_DDR5_SPD_REV_ENC(r)	bitx8(r, 7, 4)
#define	SPD_DDR5_SPD_REV_ADD(r)	bitx8(r, 3, 0)
#define	SPD_DDR5_SPD_REV_V1	1

/*
 * S8.1.3: Key Byte / DRAM Device Type. This field identifies the type of DDR
 * device and is actually consistent across all SPD versions. Known values are
 * in the spd_dram_type_t enumeration.
 */
#define	SPD_DDR5_DRAM_TYPE	0x002

/*
 * S8.1.4 Key Byte / Module Type
 */
#define	SPD_DDR5_MOD_TYPE	0x003
#define	SPD_DDR5_MOD_TYPE_ISHYBRID(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_MOD_TYPE_HYBRID(r)	bitx8(r, 6, 4)
#define	SPD_DDR5_MOD_TYPE_HYBRID_NONE		0
#define	SPD_DDR5_MOD_TYPE_HYBRID_NVDIMM_N	1
#define	SPD_DDR5_MOD_TYPE_HYBRID_NVDIMM_P	2
#define	SPD_DDR5_MOD_TYPE_TYPE(r)	bitx8(r, 3, 0)
#define	SPD_DDR5_MOD_TYPE_TYPE_RDIMM	1
#define	SPD_DDR5_MOD_TYPE_TYPE_UDIMM	2
#define	SPD_DDR5_MOD_TYPE_TYPE_SODIMM	3
#define	SPD_DDR5_MOD_TYPE_TYPE_LRDIMM	4
#define	SPD_DDR5_MOD_TYPE_TYPE_CUDIMM	5
#define	SPD_DDR5_MOD_TYPE_TYPE_CSODIMM	6
#define	SPD_DDR5_MOD_TYPE_TYPE_MRDIMM	7
#define	SPD_DDR5_MOD_TYPE_TYPE_CAMM2	8
#define	SPD_DDR5_MOD_TYPE_TYPE_DDIMM	10
#define	SPD_DDR5_MOD_TYPE_TYPE_SOLDER	11

/*
 * S8.1.5 First SDRAM Density and Package
 * S8.1.9 Second SDRAM Density and Package
 */
#define	SPD_DDR5_DENPKG1	0x004
#define	SPD_DDR5_DENPKG2	0x008
#define	SPD_DDR5_DENPKG_DPP(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_DENPKG_DPP_MONO	0
#define	SPD_DDR5_DENPKG_DPP_DDP		1
#define	SPD_DDR5_DENPKG_DPP_2H3DS	2
#define	SPD_DDR5_DENPKG_DPP_4H3DS	3
#define	SPD_DDR5_DENPKG_DPP_8H3DS	4
#define	SPD_DDR5_DENPKG_DPP_16H3DS	5
#define	SPD_DDR5_DENPKG_DPD(r)	bitx8(r, 4, 0)
#define	SPD_DDR5_DENPKG_DPD_4Gb		1
#define	SPD_DDR5_DENPKG_DPD_8Gb		2
#define	SPD_DDR5_DENPKG_DPD_12Gb	3
#define	SPD_DDR5_DENPKG_DPD_16Gb	4
#define	SPD_DDR5_DENPKG_DPD_24Gb	5
#define	SPD_DDR5_DENPKG_DPD_32Gb	6
#define	SPD_DDR5_DENPKG_DPD_48Gb	7
#define	SPD_DDR5_DENPKG_DPD_64Gb	8

/*
 * S8.1.6 First SDRAM Addressing
 * S8.1.10 Second SDRAM Addressing
 */
#define	SPD_DDR5_ADDR1	0x005
#define	SPD_DDR5_ADDR2	0x009
#define	SPD_DDR5_ADDR_NCOLS(r)		bitx8(r, 7, 5)
#define	SPD_DDR5_ADDR_NCOLS_BASE	10
#define	SPD_DDR5_ADDR_NCOLS_MAX		11
#define	SPD_DDR5_ADDR_NROWS(r)		bitx8(r, 4, 0)
#define	SPD_DDR5_ADDR_NROWS_BASE	16
#define	SPD_DDR5_ADDR_NROWS_MAX		18

/*
 * S8.1.7 First SDRAM I/O Width
 * S8.1.11 Second SDRAM I/O Width
 */
#define	SPD_DDR5_WIDTH1	0x006
#define	SPD_DDR5_WIDTH2	0x00a
#define	SPD_DDR5_WIDTH_WIDTH(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_WIDTH_X4	0
#define	SPD_DDR5_WIDTH_X8	1
#define	SPD_DDR5_WIDTH_X16	2
#define	SPD_DDR5_WIDTH_X32	3

/*
 * S8.1.8 First SDRAM Bank Groups and Banks per Bank Group
 * S8.1.8 Second SDRAM Bank Groups and Banks per Bank Group
 *
 * Both values here are in the number of bits that correspond to bank groups and
 * banks per group. In other words, the total number is 1 << value.
 */
#define	SPD_DDR5_BANKS1	0x007
#define	SPD_DDR5_BANKS2	0x00b
#define	SPD_DDR5_BANKS_NBG_BITS(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_BANKS_NBG_BITS_MAX	3
#define	SPD_DDR5_BANKS_NBA_BITS(r)	bitx8(r, 2, 0)
#define	SPD_DDR5_BANKS_NBA_BITS_MAX	2

/*
 * S8.1.13 SDRAM BL32 and Post Package Repair
 */
#define	SPD_DDR5_PPR	0x00c
#define	SPD_DDR5_PPR_GRAN(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_PPR_GRAN_BGRP	0
#define	SPD_DDR5_PPR_GRAN_BANK	1
#define	SPD_DDR5_PPR_LOCK_SUP(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_PPR_BL32_SUP(r)	bitx8(r, 4, 4)
#define	SPD_DDR5_PPR_MPPR_SUP(r)	bitx8(r, 1, 1)

/*
 * S8.1.14 SDRAM Duty Cycle Adjustor and Partial Array Self Refresh
 */
#define	SPD_DDR5_SDA	0x00d
#define	SPD_DDR5_SPD_DCA_PASR(r)	bitx8(r, 4, 4)
#define	SPD_DDR5_SPD_DCA_TYPE(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_SPD_DCA_TYPE_UNSUP	0
#define	SPD_DDR5_SPD_DCA_TYPE_1_2P	1
#define	SPD_DDR5_SPD_DCA_TYPE_4P	2

/*
 * S8.1.15 SDRAM Fault Handling and Temperature Sense
 */
#define	SPD_DDR5_FLT	0x00e
#define	SPD_DDR5_FLT_WIDE_TS(r)		bitx8(r, 3, 3)
#define	SPD_DDR5_FLT_WBSUPR_SUP(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_FLT_WBSUPR_SEL(r)	bitx8(r, 1, 1)
#define	SPD_DDR5_FLT_WBSUPR_SEL_MR9	0
#define	SPD_DDR5_FLT_WBSUPR_SEL_MR15	1
#define	SPD_DDR5_FLT_BFLT(r)		bitx8(r, 0, 0)

/*
 * S8.1.17 SDRAM Nominal Voltage, VDD
 * S8.1.18 SDRAM Nominal Voltage, VDDQ
 * S8.1.19 SDRAM Nominal Voltage, VDP
 *
 * These three share the same breakdown between nominal, operable, and endurant
 * voltages. However, the actual values that they support are different.
 */
#define	SPD_DDR5_DRAM_VDD	0x010
#define	SPD_DDR5_DRAM_VDDQ	0x011
#define	SPD_DDR5_DRAM_VPP	0x012
#define	SPD_DDR5_DRAM_VOLT_NOM(r)	bitx8(r, 7, 4)
#define	SPD_DDR5_DRAM_VOLT_OPER(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_DRAM_VOLT_END(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_DRAM_VDD_V1P1		0
#define	SPD_DDR5_DRAM_VDQ_V1P1		0
#define	SPD_DDR5_DRAM_VPP_V1P8		0

/*
 * S8.1.20 SDRAM Timing
 */
#define	SPD_DDR5_TIME	0x013
#define	SPD_DDR5_TIME_STD(r)	bitx8(r, 0, 0)
#define	SPD_DDR5_TIME_STD_STD	0
#define	SPD_DDR5_TIME_STD_NON	1

/*
 * Timing based parameters. DDR5 uses two timebase values, either 1ps or 1ns.
 * This is different from DDR4 which had the MTB and FTB. For each parameter we
 * note whether it is in picoseconds or nanosecond units.
 */

/*
 * S8.1.21 SDRAM Minimum Cycle Time t~CKAVG~min (ps)
 * S8.1.22 SDRAM Maximum Cycle Time t~CKAVG~max (ps)
 */
#define	SPD_DDR5_TCKAVG_MIN_LSB	0x014
#define	SPD_DDR5_TCKAVG_MIN_MSB	0x015
#define	SPD_DDR5_TCKAVG_MAX_LSB	0x016
#define	SPD_DDR5_TCKAVG_MAX_MSB	0x017

/*
 * S8.1.23 CAS Latencies. These are 5 bytes which indicate which set o CAS
 * latencies are supported. The LSB of the SPD_DDR5_CAS_SUP0 corresponds to
 * CL20. Each subsequent bit is an additional 2 CL. So bit 4 is CL28. Byte 2 bit
 * 6 is CL64.
 */
#define	SPD_DDR5_CAS_SUP0	0x018
#define	SPD_DDR5_CAS_SUP1	0x019
#define	SPD_DDR5_CAS_SUP2	0x01a
#define	SPD_DDR5_CAS_SUP3	0x01b
#define	SPD_DDR5_CAS_SUP4	0x01c

/*
 * S8.1.25 SDRAM Read Command to First Data (t~AA~) (ps)
 * S8.1.26 SDRAM Activate to Read or Write Command Delay (t~RCD~) (ps)
 * S8.1.27 SDRAM Row Precharge Time (t~RP~) (ps)
 * S8.1.28 SDRAM Activate to Precharge Command Period (t~RAS~) (ps)
 * S8.1.29 SDRAM Activate to to Activate or Refresh Command Period (t~RC~) (ps)
 * S8.1.30 SDRAM Write Recovery Time (t~WR~) (ps)
 * S8.1.31 SDRAM Normal Refresh Recovery Time (t~RFC1,tRFC1_slr~) (ns)
 * S8.1.32 SDRAM Fine Granularity Refresh Recovery Time (t~RFC2,tRFC2_slr~) (ns)
 * S8.1.33 SDRAM Same Bank Refresh Recovery Time (t~RFCsb,tRFCsb_slr~) (ns)
 * S8.1.34 SDRAM Normal Refresh Recovery Time, 3DS Different Logical Rank
 * (t~RFC1_dlr~) (ns)
 * S8.1.35 SDRAM Fine Granularity Recovery Time, 3DS Different Logical Rank
 * (t~RFC2_dlr~) (ns)
 * S8.1.36 SDRAM Fine Granularity Recovery Time, 3DS Different Logical Rank
 * (t~RFCsb_dlr~) (ns)
 */
#define	SPD_DDR5_TAA_LSB	0x01e
#define	SPD_DDR5_TAA_MSB	0x01f
#define	SPD_DDR5_TRCD_LSB	0x020
#define	SPD_DDR5_TRCD_MSB	0x021
#define	SPD_DDR5_TRP_LSB	0x022
#define	SPD_DDR5_TRP_MSB	0x023
#define	SPD_DDR5_TRAS_LSB	0x024
#define	SPD_DDR5_TRAS_MSB	0x025
#define	SPD_DDR5_TRC_LSB	0x026
#define	SPD_DDR5_TRC_MSB	0x027
#define	SPD_DDR5_TWR_LSB	0x028
#define	SPD_DDR5_TWR_MSB	0x029
#define	SPD_DDR5_TRFC1_LSB	0x02a
#define	SPD_DDR5_TRFC1_MSB	0x02b
#define	SPD_DDR5_TRFC2_LSB	0x02c
#define	SPD_DDR5_TRFC2_MSB	0x02d
#define	SPD_DDR5_TRFCSB_LSB	0x02e
#define	SPD_DDR5_TRFCSB_MSB	0x02f
#define	SPD_DDR5_3DS_TRFC1_LSB	0x030
#define	SPD_DDR5_3DS_TRFC1_MSB	0x031
#define	SPD_DDR5_3DS_TRFC2_LSB	0x032
#define	SPD_DDR5_3DS_TRFC2_MSB	0x033
#define	SPD_DDR5_3DS_TRFCSB_LSB	0x034
#define	SPD_DDR5_3DS_TRFCSB_MSB	0x035

/*
 * S8.1.37 SDRAM Refresh Management First SDRAM
 * S8.1.38 SDRAM Refresh Management Second SDRAM
 *
 * Refresh Management spans two bytes.
 */
#define	SPD_DDR5_RFM0_SDRAM0	0x036
#define	SPD_DDR5_RFM0_SDRAM1	0x038
#define	SPD_DDR5_RFM0_RAAMMT_NORM(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_RFM0_RAAMMT_NORM_MIN	3
#define	SPD_DDR5_RFM0_RAAMMT_NORM_MAX	6
#define	SPD_DDR5_RFM0_RAAMMT_NORM_MULT	1
#define	SPD_DDR5_RFM0_RAAMMT_FGR(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_RFM0_RAAMMT_FGR_MIN	6
#define	SPD_DDR5_RFM0_RAAMMT_FGR_MAX	12
#define	SPD_DDR5_RFM0_RAAMMT_FGR_MULT	2
#define	SPD_DDR5_RFM0_RAAIMT_NORM(r)	bitx8(r, 4, 1)
#define	SPD_DDR5_RFM0_RAAIMT_NORM_MIN	32
#define	SPD_DDR5_RFM0_RAAIMT_NORM_MAX	80
#define	SPD_DDR5_RFM0_RAAIMT_NORM_MULT	8
#define	SPD_DDR5_RFM0_RAAIMT_FGR(r)	bitx8(r, 4, 1)
#define	SPD_DDR5_RFM0_RAAIMT_FGR_MIN	16
#define	SPD_DDR5_RFM0_RAAIMT_FGR_MAX	40
#define	SPD_DDR5_RFM0_RAAIMT_FGR_MULT	4
#define	SPD_DDR5_RFM0_RFM_REQ(r)	bitx8(r, 0, 0)
#define	SPD_DDR5_RFM1_SDRAM0	0x037
#define	SPD_DDR5_RFM1_SDRAM1	0x039
#define	SPD_DDR5_RFM1_CTR(r)	bitx8(r, 7, 6)
#define	SPD_DDR5_RFM1_CTR_1X	0
#define	SPD_DDR5_RFM1_CTR_2X	1
#define	SPD_DDR5_RFM1_BRC_SUP(r)bitx8(r, 3, 3)
#define	SPD_DDR5_RFM1_BRC_SUP_234	0
#define	SPD_DDR5_RFM1_BRC_SUP_2		1
#define	SPD_DDR5_RFM1_BRC_CFG(r)	bitx8(r, 2, 1)
#define	SPD_DDR5_RFM1_BRC_CFG_BASE	2
#define	SPD_DDR5_RFM1_BRC_CFG_MAX	4
#define	SPD_DDR5_RFM1_DRFM_SUP(r)	bitx8(r, 0, 0)

/*
 * S8.1.39 SDRAM Adaptive Refresh Management. This is broken down so that there
 * are three levels, A, B, and C. There are then two bytes per level. And there
 * is one entry for the first DRAM and one for the second. With the exception of
 * bit 0 of the low byte, which indicates whether or not this is supported,
 * these two byte ranges all match the prior two bytes.
 */
#define	SPD_DDR5_ARFM0_A_SDRAM0		0x03a
#define	SPD_DDR5_ARFM1_A_SDRAM0		0x03b
#define	SPD_DDR5_ARFM0_A_SDRAM1		0x03c
#define	SPD_DDR5_ARFM1_A_SDRAM1		0x03d
#define	SPD_DDR5_ARFM0_B_SDRAM0		0x03e
#define	SPD_DDR5_ARFM1_B_SDRAM0		0x03f
#define	SPD_DDR5_ARFM0_B_SDRAM1		0x040
#define	SPD_DDR5_ARFM1_B_SDRAM1		0x041
#define	SPD_DDR5_ARFM0_C_SDRAM0		0x042
#define	SPD_DDR5_ARFM1_C_SDRAM0		0x043
#define	SPD_DDR5_ARFM0_C_SDRAM1		0x044
#define	SPD_DDR5_ARFM1_C_SDRAM1		0x045
#define	SPD_DDR5_ARFM_SUP(r)	bitx8(r, 0, 0)

/*
 * S8.1.40 SDRAM Activate to Activate Command Delay for Same Bank Group
 * (t~RRD_L~)
 * S8.1.41 SDRAM Read to Read Command Delay for Same Bank Group (t~CDD_L~)
 * S8.1.42 SDRAM Write to Write Command Delay for Same Bank Group (t~CDD_L_WR~)
 * S8.1.43 SDRAM Write to Write Command Delay for Same Bank Group, Second Write
 * not RMW (t~CDD_L_WR2~)
 * S8.1.44 SDRAM Four Activate Window (t~FAW~)
 * S8.1.45 SDRAM Write to Read Command Delay for Same Bank Group (t~CCD_L_WTR~)
 * S8.1.46 SDRAM Write to Read Command Delay for Different Bank Group
 * (t~CCD_S_WTR~)
 * S8.1.47 SDRAM Read to Precharge Command Delay (t~RTP~,t~RTP_slr~)
 * S8.1.48 (v1.2) SDRAM Read to Read Command Delay for Different Bank in Same
 * Bank Group (t~CCD_M~)
 * S8.1.49 (v1.2) SDRAM Write to Write Command Delay for Different Bank in Same
 * Bank Group (t~CCD_M_WR~)
 * S8.1.50 (v1.2) SDRAM Write to Read Command Delay for Different Bank in Same
 * Bank Group (t~CCD_M_WTR~)
 *
 * These timing registers all consist of three bytes. The first two bytes are
 * the LSB / MSB of the value in ps. The third bird defines the number of clock
 * cycles required.
 */
#define	SPD_DDR5_TRRD_L_LSB	0x046
#define	SPD_DDR5_TRRD_L_MSB	0x047
#define	SPD_DDR5_TRRD_L_NCK	0x048
#define	SPD_DDR5_TCCD_L_LSB	0x049
#define	SPD_DDR5_TCCD_L_MSB	0x04a
#define	SPD_DDR5_TCCD_L_NCK	0x04b
#define	SPD_DDR5_TCCD_L_WR_LSB	0x04c
#define	SPD_DDR5_TCCD_L_WR_MSB	0x04d
#define	SPD_DDR5_TCCD_L_WR_NCK	0x04e
#define	SPD_DDR5_TCCD_L_WR2_LSB	0x04f
#define	SPD_DDR5_TCCD_L_WR2_MSB	0x050
#define	SPD_DDR5_TCCD_L_WR2_NCK	0x051
#define	SPD_DDR5_TFAW_LSB	0x052
#define	SPD_DDR5_TFAW_MSB	0x053
#define	SPD_DDR5_TFAW_NCK	0x054
#define	SPD_DDR5_TCCD_L_WTR_LSB	0x055
#define	SPD_DDR5_TCCD_L_WTR_MSB	0x056
#define	SPD_DDR5_TCCD_L_WTR_NCK	0x057
#define	SPD_DDR5_TCCD_S_WTR_LSB	0x058
#define	SPD_DDR5_TCCD_S_WTR_MSB	0x059
#define	SPD_DDR5_TCCD_S_WTR_NCK	0x05a
#define	SPD_DDR5_TRTP_LSB	0x05b
#define	SPD_DDR5_TRTP_MSB	0x05c
#define	SPD_DDR5_TRTP_NCK	0x05d
#define	SPD_DDR5_TCCD_M_LSB	0x05e
#define	SPD_DDR5_TCCD_M_MSB	0x05f
#define	SPD_DDR5_TCCD_M_NCK	0x060
#define	SPD_DDR5_TCCD_M_WR_LSB	0x061
#define	SPD_DDR5_TCCD_M_WR_MSB	0x062
#define	SPD_DDR5_TCCD_M_WR_NCK	0x063
#define	SPD_DDR5_TCCD_M_WTR_LSB	0x064
#define	SPD_DDR5_TCCD_M_WTR_MSB	0x065
#define	SPD_DDR5_TCCD_M_WTR_NCK	0x066

/*
 * The remaining bytes in this section are currently reserved. Next, we begin
 * Annex A.0 which has common bytes that are shared between all module types.
 */

/*
 * S11.1 Common: SPD Revision for Module Information. This is the equivalent of
 * SPD_DDR5_SPD_REV, but covers all of the module-specific information, which
 * includes both the common area and type-specific areas.
 */
#define	SPD_DDR5_COM_REV	0x0c0

/*
 * S11.2 Common: Hashing Sequence. This defines a possible hashing sequence that
 * may be applied to a certificate related to device authentication per
 * JEDS316-5.
 */
#define	SPD_DDR5_COM_HASH	0x0c1
#define	SPD_DDR5_COM_HASH_HASH(r)	bitx8(r, 2, 0)
#define	SPD_DDR5_COM_HASH_NONE		0
#define	SPD_DDR5_COM_HASH_ALG1		1

/*
 * S11.3 Common: Module Device Information. This contains a series of four
 * registers for each of five possible items: the SPD, three PMICs (power
 * management integrated circuit), and a temperature sensor. Before leveraging
 * the MFG ID, one must consult the Device Type register to see if it is
 * present. We start with generic definitions for each register type. Specifics
 * to a register such as type values will follow. The revision is a BCD revision
 * register. See DDR4 discussion.
 */
#define	SPD_DDR5_COM_INFO_PRES(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_COM_INFO_TYPE(r)	bitx8(r, 3, 0)

#define	SPD_DDR5_COM_MFG_ID0_SPD	0x0c2
#define	SPD_DDR5_COM_MFG_ID1_SPD	0x0c3
#define	SPD_DDR5_COM_INFO_SPD		0x0c4
#define	SPD_DDR5_COM_INFO_TYPE_SPD5118	0
#define	SPD_DDR5_COM_INFO_TYPE_ESPD5216	1
#define	SPD_DDR5_COM_REV_SPD		0x0c5

#define	SPD_DDR5_COM_MFG_ID0_PMIC0	0x0c6
#define	SPD_DDR5_COM_MFG_ID1_PMIC0	0x0c7
#define	SPD_DDR5_COM_INFO_PMIC0		0x0c8
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5000	0
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5010	1
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5100	2
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5020	3
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5120	4
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5200	5
#define	SPD_DDR5_COM_INFO_TYPE_PMIC5030	6
#define	SPD_DDR5_COM_REV_PMIC0		0x0c9

#define	SPD_DDR5_COM_MFG_ID0_PMIC1	0x0ca
#define	SPD_DDR5_COM_MFG_ID1_PMIC1	0x0cb
#define	SPD_DDR5_COM_INFO_PMIC1		0x0cc
#define	SPD_DDR5_COM_REV_PMIC1		0x0cd

#define	SPD_DDR5_COM_MFG_ID0_PMIC2	0x0ce
#define	SPD_DDR5_COM_MFG_ID1_PMIC2	0x0cf
#define	SPD_DDR5_COM_INFO_PMIC2		0x0d0
#define	SPD_DDR5_COM_REV_PMIC2		0x0d1

#define	SPD_DDR5_COM_MFG_ID0_TS		0x0d2
#define	SPD_DDR5_COM_MFG_ID1_TS		0x0d3
#define	SPD_DDR5_COM_INFO_TS		0x0d4
#define	SPD_DDR5_COM_INFO_TS1_PRES(r)	bitx8(r, 6, 6)
#define	SPD_DDR5_COM_INFO_TYPE_TS5111	0
#define	SPD_DDR5_COM_INFO_TYPE_TS5110	1
#define	SPD_DDR5_COM_INFO_TYPE_TS5211	2
#define	SPD_DDR5_COM_INFO_TYPE_TS5210	3
#define	SPD_DDR5_COM_REV_TS		0x0d5

/*
 * S11.5 Common: Module Nominal Height
 */
#define	SPD_DDR5_COM_HEIGHT	0x0e6
#define	SPD_DDR5_COM_HEIGHT_MM(r)	bitx8(r, 4, 0)
#define	SPD_DDR5_COM_HEIGHT_BASE	15

/*
 * S11.6 Common: Module Maximum Thickness
 */
#define	SPD_DDR5_COM_THICK	0x0e7
#define	SPD_DDR5_COM_THICK_BACK(r)	bitx8(r, 7, 4)
#define	SPD_DDR5_COM_THICK_FRONT(r)	bitx8(r, 3, 0)
#define	SPD_DDR5_COM_THICK_BASE		1

/*
 * S11.7 Common: Reference Raw Card Used
 */
#define	SPD_DDR5_COM_REF	0x0e8
#define	SPD_DDR5_COM_REF_REV(r)		bitx8(r, 7, 5)
#define	SPD_DDR5_COM_REF_REV_MAX	6
#define	SPD_DDR5_COM_REF_CARD(r)	bitx8(r, 4, 0)

/*
 * S11.8 Common: DIMM Attributes
 */
#define	SPD_DDR5_COM_ATTR	0x0e9
#define	SPD_DDR5_COM_ATTR_OTR(r)	bitx8(r, 7, 4)
#define	SPD_DDR5_COM_ATTR_OTR_A1T	0
#define	SPD_DDR5_COM_ATTR_OTR_A2T	1
#define	SPD_DDR5_COM_ATTR_OTR_A3T	2
#define	SPD_DDR5_COM_ATTR_OTR_IT	3
#define	SPD_DDR5_COM_ATTR_OTR_ST	4
#define	SPD_DDR5_COM_ATTR_OTR_ET	5
#define	SPD_DDR5_COM_ATTR_OTR_RT	6
#define	SPD_DDR5_COM_ATTR_OTR_NT	7
#define	SPD_DDR5_COM_ATTR_OTR_XT	8
#define	SPD_DDR5_COM_ATTR_SPREAD(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_COM_ATTR_NROWS(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_COM_ATTR_NROWS_UNDEF	0
#define	SPD_DDR5_COM_ATTR_NROWS_1	1
#define	SPD_DDR5_COM_ATTR_NROWS_2	2

/*
 * S11.9 Common: Module Organization
 */
#define	SPD_DDR5_COM_ORG	0x0ea
#define	SPD_DDR5_COM_ORG_MIX(r)		bitx8(r, 6, 6)
#define	SPD_DDR5_COM_ORG_MIX_SYM	0
#define	SPD_DDR5_COM_ORG_MIX_ASYM	1
#define	SPD_DDR5_COM_ORG_NRANK(r)	bitx8(r, 5, 3)
#define	SPD_DDR5_COM_ORG_NRANK_BASE	1

/*
 * S11.10 Common: Memory Channel Bus Width. Unlike DDR4, these widths are in
 * terms of sub-channels.
 */
#define	SPD_DDR5_COM_BUS_WIDTH	0x0eb
#define	SPD_DDR5_COM_BUS_WIDTH_NSC(r)	bitx8(r, 7, 5)
#define	SPD_DDR5_COM_BUS_WIDTH_NSC_MAX	8
#define	SPD_DDR5_COM_BUS_WIDTH_EXT(r)	bitx8(r, 4, 3)
#define	SPD_DDR5_COM_BUS_WIDTH_EXT_NONE	0
#define	SPD_DDR5_COM_BUS_WIDTH_EXT_4b	1
#define	SPD_DDR5_COM_BUS_WIDTH_EXT_8b	2
#define	SPD_DDR5_COM_BUS_WIDTH_PRI(r)	bitx8(r, 2, 0)
#define	SPD_DDR5_COM_BUS_WIDTH_PRI_8b	0
#define	SPD_DDR5_COM_BUS_WIDTH_PRI_16b	1
#define	SPD_DDR5_COM_BUS_WIDTH_PRI_32b	2
#define	SPD_DDR5_COM_BUS_WIDTH_PRI_64b	3

/*
 * After this point, all remaining bytes are reserved and Annex specific
 * information follows. Annex A.1 Module Specific Bytes for Solder Down is
 * skipped because there are no bytes defined. The revisions for these all
 * follow the common revision found at SPD_DDR5_COM_REV.
 */

/*
 * Annex A.2 Module Specific Bytes for Buffered Memory Module Types.  S13.1
 * UDIMM: Module Specific Device Information. This follows the same pattern as
 * the other device specific manufacturing information with a series of four
 * bytes. See the discussion of S11.3. Revision 1.0 only defined the CLK
 * information. Revision 1.1 added several additional pieces of data.
 */
#define	SPD_DDR5_UDIMM_MFG_ID0_CLK	0x0f0
#define	SPD_DDR5_UDIMM_MFG_ID1_CLK	0x0f1
#define	SPD_DDR5_UDIMM_INFO_CLK		0x0f2
#define	SPD_DDR5_UDIMM_INFO_TYPE_DDR5CK01	0
#define	SPD_DDR5_UDIMM_REV_CLK		0x0f3

/*
 * S13.2 UDIMM v1.1: CKD-RW00 CKD Configuration
 */
#define	SPD_DDR5_UDIMM_CKD_CFG		0x0f4
#define	SPD_DDR5_UDIMM_CKD_CFG_CHBQCK1(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_UDIMM_CKD_CFG_CHBQCK0(r)	bitx8(r, 6, 6)
#define	SPD_DDR5_UDIMM_CKD_CFG_CHAQCK1(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_UDIMM_CKD_CFG_CHAQCK0(r)	bitx8(r, 4, 4)

/*
 * S13.3 UDIMM v1.1: CKD-RW02 QCK Driver Characteristics
 */
#define	SPD_DDR5_UDIMM_CKD_DRV		0x0f5
#define	SPD_DDR5_UDIMM_CKD_DRV_CHBQCK1_DRIVE(r)	bitx8(r, 7, 6)
#define	SPD_DDR5_UDIMM_CKD_DRV_CHBQCK0_DRIVE(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_UDIMM_CKD_DRV_CHAQCK1_DRIVE(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_UDIMM_CKD_DRV_CHAQCK0_DRIVE(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_UDIMM_CKD_DRV_LIGHT	0
#define	SPD_DDR5_UDIMM_CKD_DRV_MODERATE	1
#define	SPD_DDR5_UDIMM_CKD_DRV_STRONG	2
#define	SPD_DDR5_UDIMM_CKD_DRV_WEAK	3

/*
 * S13.4 UDIMM v1.1: CKD-RW03 QCK Output Differential Slew Rate
 */
#define	SPD_DDR5_UDIMM_CKD_SLEW		0x0f6
#define	SPD_DDR5_UDIMM_CKD_SLEW_CHBQCK_SLEW(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_UDIMM_CKD_SLEW_CHAQCK_SLEW(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_UDIMM_CKD_SLEW_SLEW_MODERATE	0
#define	SPD_DDR5_UDIMM_CKD_SLEW_SLEW_FAST	1

/*
 * Annex A.3: Module Specific Bytes for Registered (RDIMM) and Load Reduced
 * (LRDIMM) Memory Module Types.
 */

/*
 * S14.2 RDIMM: Module Specific Device Information. This covers the RCD and DB
 * components. Only LRDIMMs will have the DB present and it will be left as zero
 * for RDIMMs.
 */
#define	SPD_DDR5_RDIMM_MFG_ID0_RCD	0x0f0
#define	SPD_DDR5_RDIMM_MFG_ID1_RCD	0x0f1
#define	SPD_DDR5_RDIMM_INFO_RCD		0x0f2
#define	SPD_DDR5_RDIMM_INFO_TYPE_RCD01	0
#define	SPD_DDR5_RDIMM_INFO_TYPE_RCD02	1
#define	SPD_DDR5_RDIMM_INFO_TYPE_RCD03	2
#define	SPD_DDR5_RDIMM_INFO_TYPE_RCD04	3
#define	SPD_DDR5_RDIMM_INFO_TYPE_RCD05	4
#define	SPD_DDR5_RDIMM_REV_RCD		0x0f3

#define	SPD_DDR5_RDIMM_MFG_ID0_DB	0x0f4
#define	SPD_DDR5_RDIMM_MFG_ID1_DB	0x0f5
#define	SPD_DDR5_RDIMM_INFO_DB		0x0f6
#define	SPD_DDR5_RDIMM_INFO_TYPE_DB01	0
#define	SPD_DDR5_RDIMM_INFO_TYPE_DB02	1
#define	SPD_DDR5_RDIMM_REV_DB		0x0f7

/*
 * S14.3 RDIMM: RCD-RW08 Clock Driver Enable
 */
#define	SPD_DDR5_RDIMM_CLKEN	0x0f8
#define	SPD_DDR5_RDIMM_CLKEN_BCK(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_RDIMM_CLKEN_QDCK(r)	bitx8(r, 3, 3)
#define	SPD_DDR5_RDIMM_CLKEN_QCCK(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_RDIMM_CLKEN_QBCK(r)	bitx8(r, 1, 1)
#define	SPD_DDR5_RDIMM_CLKEN_QACK(r)	bitx8(r, 0, 0)

/*
 * S14.4 RDIMM: RCD-RW09 Output Address and Control Enable
 */
#define	SPD_DDR5_RDIMM_RW09	0x0f9
#define	SPD_DDR5_RDIMM_RW09_QBCS(r)	bitx8(r, 6, 6)
#define	SPD_DDR5_RDIMM_RW09_QACS(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_RDIMM_RW09_QXCA13(r)	bitx8(r, 4, 4)
#define	SPD_DDR5_RDIMM_RW09_BCS(r)	bitx8(r, 3, 3)
#define	SPD_DDR5_RDIMM_RW09_DCS(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_RDIMM_RW09_QBCA(r)	bitx8(r, 1, 1)
#define	SPD_DDR5_RDIMM_RW09_QACA(r)	bitx8(r, 0, 0)

/*
 * S14.5 RDIMM: RCD-RW0A QCK Driver Characteristics
 * S14.7 RDIMM: RCD-RW0C QxCA and QxCS_n Driver Characteristics
 * S14.8 LRDIMM: RCD-RW0D Data Buffer Interface Driver Characteristics
 *
 * RDIMM 1.0 phrased these in terms of resistance values; however, RDIMM 1.1
 * changed them into relative terms used elsewhere like light, moderate, and
 * strong.
 */
#define	SPD_DDR5_RDIMM_QCK_DRV	0x0fa
#define	SPD_DDR5_RDIMM_QCK_DRV_QDCK(r)	bitx8(r, 7, 6)
#define	SPD_DDR5_RDIMM_QCK_DRV_QCCK(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_RDIMM_QCK_DRV_QBCK(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_RDIMM_QCK_DRV_QACK(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_RDIMM_DRV_LIGHT	0
#define	SPD_DDR5_RDIMM_DRV_MODERATE	1
#define	SPD_DDR5_RDIMM_DRV_STRONG	2

#define	SPD_DDR5_RDIMM_QCA_DRV	0x0fc
#define	SPD_DDR5_RDIMM_QCA_DRV_CS(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_RDIMM_QCA_DRV_CA(r)	bitx8(r, 1, 0)

#define	SPD_DDR5_LRDIMM_DB_DRV	0x0fd
#define	SPD_DDR5_LRDIMM_DB_DRV_BCK(r)	bitx8(r, 4, 3)
#define	SPD_DDR5_LRDIMM_DB_DRV_BCOM(r)	bitx8(r, 1, 0)

/*
 * S14.9 RDIMM: RCD-RW0E QCK, QCA, and QCS Output Slew Rate
 * S14.10 LRDIMM: RCD-RW0F BCK, BCOM, and BCS Output Slew Rate
 *
 * These all use the same rough definitions for slew rates, i.e. slow, moderate,
 * and fast; however, they all have different voltage ranges.
 */
#define	SPD_DDR5_RDIMM_QXX_SLEW	0x0fe
#define	SPD_DDR5_RDIMM_QXX_SLEW_QCS(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_RDIMM_SLEW_MODERTE	0
#define	SPD_DDR5_RDIMM_SLEW_FAST	1
#define	SPD_DDR5_RDIMM_SLEW_SLOW	2
#define	SPD_DDR5_RDIMM_QXX_SLEW_QCA(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_RDIMM_QXX_SLEW_QCK(r)	bitx8(r, 1, 0)

#define	SPD_DDR5_LRDIMM_BXX_SLEW	0x0ff
#define	SPD_DDR5_LRDIMM_BXX_SLEW_BCK(r)		bitx8(r, 3, 2)
#define	SPD_DDR5_LRDIMM_BXX_SLEW_BCOM(r)	bitx8(r, 1, 0)

/*
 * S14.11 DB-RW86 DQS RTT Park Termination
 */
#define	SPD_DDR5_LRDIMM_PARK	0x100
#define	SPD_DDR5_LRDIMM_PARK_TERM(r)	bitx8(r, 2, 0)
#define	SPD_DDR5_LDRIMM_PARK_OFF	0
#define	SPD_DDR5_LDRIMM_PARK_240R	1
#define	SPD_DDR5_LDRIMM_PARK_120R	2
#define	SPD_DDR5_LDRIMM_PARK_80R	3
#define	SPD_DDR5_LDRIMM_PARK_60R	4
#define	SPD_DDR5_LDRIMM_PARK_48R	5
#define	SPD_DDR5_LDRIMM_PARK_40R	6
#define	SPD_DDR5_LDRIMM_PARK_34R	7

/*
 * Annex A.4: Module Specific Bytes for Multiplexed Rank (MRDIMM) Memory Module
 * Types. Revision 1.0 only defined the type information. Revision 1.1 added
 * several additional bytes of data that start after the MDB information.
 */
#define	SPD_DDR5_MRDIMM_MFG_ID0_MRCD	0x0f0
#define	SPD_DDR5_MRDIMM_MFG_ID1_MRCD	0x0f1
#define	SPD_DDR5_MRDIMM_INFO_MRCD	0x0f2
#define	SPD_DDR5_MRDIMM_INFO_TYPE_MRCD01	0
#define	SPD_DDR5_MRDIMM_INFO_TYPE_MRCD02	1
#define	SPD_DDR5_MRDIMM_REV_MRCD	0x0f3

#define	SPD_DDR5_MRDIMM_MFG_ID0_MDB	0x0f4
#define	SPD_DDR5_MRDIMM_MFG_ID1_MDB	0x0f5
#define	SPD_DDR5_MRDIMM_INFO_MDB	0x0f6
#define	SPD_DDR5_MRDIMM_INFO_TYPE_MDB01	0
#define	SPD_DDR5_MRDIMM_INFO_TYPE_MDB02	1
#define	SPD_DDR5_MRDIMM_REV_MDB		0x0f7

/*
 * S15.3 MRDIMM v1.1: MRCD-RW08 Clock Driver Enable
 */
#define	SPD_DDR5_MRDIMM_CDEN	0x0f8
#define	SPD_DDR5_MRDIMM_CDEN_BCK(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_MRDIMM_CDEN_QDCK(r)	bitx8(r, 3, 3)
#define	SPD_DDR5_MRDIMM_CDEN_QCCK(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_MRDIMM_CDEN_QBCK(r)	bitx8(r, 1, 2)
#define	SPD_DDR5_MRDIMM_CDEN_QACK(r)	bitx8(r, 0, 0)

/*
 * S15.3 MRDIMM v1.1: MRCD-RW09 Output Address and Control Enable
 */
#define	SPD_DDR5_MRDIMM_OACEN	0x0f9
#define	SPD_DDR5_MRDIMM_CDEN_DCS1(r)	bitx8(r, 7, 7)
#define	SPD_DDR5_MRDIMM_CDEN_QBCS(r)	bitx8(r, 6, 6)
#define	SPD_DDR5_MRDIMM_CDEN_QACS(r)	bitx8(r, 5, 5)
#define	SPD_DDR5_MRDIMM_CDEN_QCA13(r)	bitx8(r, 4, 4)
#define	SPD_DDR5_MRDIMM_CDEN_BCS(r)	bitx8(r, 3, 3)
#define	SPD_DDR5_MRDIMM_CDEN_QxCS1(r)	bitx8(r, 2, 2)
#define	SPD_DDR5_MRDIMM_CDEN_QBCA(r)	bitx8(r, 1, 1)
#define	SPD_DDR5_MRDIMM_CDEN_QACA(r)	bitx8(r, 0, 0)

/*
 * S15.4 MRDIMM v1.1: MRCD-RW0A QCK Driver Characteristics
 * S15.6 MRDIMM v1.1: MRCD-RW0C QxCA and QxCS_n Driver Characteristics
 * S15.7 MRDIMM v1.1: MRCD-RW0D Data Buffer Interface Driver Characteristics
 *
 * Similar to the RDIMM 1.1 version of these. These are all described in terms
 * of relative rates.
 */
#define	SPD_DDR5_MRDIMM_QCK_DRV	0x0fa
#define	SPD_DDR5_MRDIMM_QCK_DRV_QDCK(r)	bitx8(r, 7, 6)
#define	SPD_DDR5_MRDIMM_QCK_DRV_QCCK(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_MRDIMM_QCK_DRV_QBCK(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_MRDIMM_QCK_DRV_QACK(r)	bitx8(r, 1, 0)
#define	SPD_DDR5_MRDIMM_DRV_LIGHT	0
#define	SPD_DDR5_MRDIMM_DRV_MODERATE	1
#define	SPD_DDR5_MRDIMM_DRV_STRONG	2

#define	SPD_DDR5_MRDIMM_QCA_DRV	0x0fc
#define	SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT(r)	bitx8(r, 7, 6)
#define	SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_NORM	0
#define	SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_DIS	1
#define	SPD_DDR5_MRDIMM_QCA_DRV_QCS1_OUT_LOW	2
#define	SPD_DDR5_MRDIMM_QCA_DRV_CS(r)		bitx8(r, 5, 4)
#define	SPD_DDR5_MRDIMM_QCA_DRV_CA(r)		bitx8(r, 1, 0)

#define	SPD_DDR5_MRDIMM_DB_DRV	0x0fd
#define	SPD_DDR5_MRDIMM_DB_DRV_BCK(r)	bitx8(r, 4, 3)
#define	SPD_DDR5_MRDIMM_DB_DRV_BCOM(r)	bitx8(r, 1, 0)

/*
 * S15.8 MRDIMM v1.1: MRCD-RW0E QCK, QCA, and QCS Output Slew Rate
 * S15.9 MRDIMM v1.1: MRCD-RW0F BCK, BCOM, and BCS Output Slew Rate
 *
 * Similar to the [LR]DIMM version. These use the same definitions for slew
 * rates.
 */
#define	SPD_DDR5_MRDIMM_QXX_SLEW	0x0fe
#define	SPD_DDR5_MRDIMM_QXX_SLEW_QCS(r)	bitx8(r, 5, 4)
#define	SPD_DDR5_MRDIMM_SLEW_MODERTE	0
#define	SPD_DDR5_MRDIMM_SLEW_FAST	1
#define	SPD_DDR5_MRDIMM_SLEW_SLOW	2
#define	SPD_DDR5_MRDIMM_QXX_SLEW_QCA(r)	bitx8(r, 3, 2)
#define	SPD_DDR5_MRDIMM_QXX_SLEW_QCK(r)	bitx8(r, 1, 0)

#define	SPD_DDR5_MRDIMM_BXX_SLEW	0x0ff
#define	SPD_DDR5_MRDIMM_BXX_SLEW_BCK(r)		bitx8(r, 3, 2)
#define	SPD_DDR5_MRDIMM_BXX_SLEW_BCOM(r)	bitx8(r, 1, 0)

/*
 * S15.10 MRDIMM v1.1: MDB-PG[C]RWE0 Duty Cycle Adjuster Configuration
 */
#define	SPD_DDR5_MRDIMM_DCA_CFG		0x100
#define	SPD_DDR5_MRDIMM_DCA_CFG_CFG(r)	bitx8(r, 0, 0)

/*
 * S15.11 MRDIMM v1.1: MDB-PG[70]RWE1 DRAM Interface Receiver Type
 */
#define	SPD_DDR5_MRDIMM_IRXTYPE		0x101
#define	SPD_DDR5_MRDIMM_IRXTYPE_TYPE(r)	bitx8(r, 0, 0)
#define	SPD_DDR5_MRDIMM_IRXTYPE_TYPE_UNMATCHED	0
#define	SPD_DDR5_MRDIMM_IRXTYPE_TYPE_MATCHED	1

/*
 * Annex A.5: Module Specific Bytes for Differential Memory Module Types. Like
 * UDIMMs and MRDIMMs, there is only a single section for Module Specific
 * Device Information.
 */
#define	SPD_DDR5_DDIMM_MFG_ID0_DMB	0x0f0
#define	SPD_DDR5_DDIMM_MFG_ID1_DMB	0x0f1
#define	SPD_DDR5_DDIMM_INFO_DMB		0x0f2
#define	SPD_DDR5_DDIMM_INFO_TYPE_DMB501	0
#define	SPD_DDR5_DDIMM_REV_DMB		0x0f3

/*
 * Annex A.8: Module Specific Bytes for Compression Attached Memory Module Types
 * (CAMM2).
 */
#define	SPD_DDR5_CAMM2_MFG_ID0_CKD0	0x0f0
#define	SPD_DDR5_CAMM2_MFG_ID1_CKD0	0x0f1
#define	SPD_DDR5_CAMM2_INFO_CKD0	0x0f2
#define	SPD_DDR5_CAMM2_INFO_TYPE_CKD01	0
#define	SPD_DDR5_CAMM2_INFO_REV_CKD0	0x0f3
#define	SPD_DDR5_CAMM2_MFG_ID0_CKD1	0x0f4
#define	SPD_DDR5_CAMM2_MFG_ID1_CKD1	0x0f5
#define	SPD_DDR5_CAMM2_INFO_CKD1	0x0f6
#define	SPD_DDR5_CAMM2_INFO_REV_CKD1	0x0f7

/*
 * S7.4 CRC. DDR5 modules have a single CRC calculation that covers bytes 0-509.
 * Thus it covers everything prior to the manufacturing information.
 */
#define	SPD_DDR5_CRC_LSB		0x1fe
#define	SPD_DDR5_CRC_MSB		0x1ff

/*
 * Manufacturing Information.
 */

/*
 * S20.1 Module Manufacturer ID Code
 * S20.7 DRAM Manufacturer ID Code
 */
#define	SPD_DDR5_MOD_MFG_ID0	0x200
#define	SPD_DDR5_MOD_MFG_ID1	0x201
#define	SPD_DDR5_DRAM_MFG_ID0	0x228
#define	SPD_DDR5_DRAM_MFG_ID1	0x229

/*
 * S20.2 Module Manufacturing Location. This byte is manufacturer specific.
 */
#define	SPD_DDR5_MOD_MFG_LOC	0x202

/*
 * S20.3 module Manufacturing Date. Encoded as two BCD bytes for the year and
 * week.
 */
#define	SPD_DDR5_MOD_MFG_YEAR	0x203
#define	SPD_DDR5_MOD_MFG_WEEK	0x204

/*
 * S20.4 Module Serial Number.
 * S20.5 Module Part Number
 * S20.6 Module Revision Code
 */
#define	SPD_DDR5_MOD_SN		0x205
#define	SPD_DDR5_MOD_SN_LEN	4
#define	SPD_DDR5_MOD_PN		0x209
#define	SPD_DDR5_MOD_PN_LEN	30
#define	SPD_DDR5_MOD_REV	0x227

/*
 * S20.8 DRAM Stepping
 */
#define	SPD_DDR5_DRAM_STEP	0x22a

/*
 * Bytes 0x22b-0x27f are left for manufacturer specific data.
 */

#ifdef __cplusplus
}
#endif

#endif /* _SPD_DDR5_H */
