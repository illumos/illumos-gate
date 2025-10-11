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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _PCHSMBUS_H
#define	_PCHSMBUS_H

/*
 * Intel ICH/PCH SMBus Controller Definitions
 *
 * The ICH/PCH Controller is a device that always shows up in PCI configuration
 * space. It has a few registers in configuration space and then has a primary
 * BAR. That BAR is either I/O space or memory space depending on the
 * generation. The original version of this in the ICH used I/O space. By the
 * time of the PCH-era devices, this BAR shows up in memory space. Regardless of
 * the source, the register definitions have generally stayed the same, with
 * newer devices adding additional registers. We will denote in comments when
 * certain registers and fields were added.
 *
 * A few notes and conventions:
 *
 *  - All registers are generally 8-bit registers unless explicitly noted
 *    otherwise.
 *  - Registers in configuration space use the _PCI_ where as registers in the
 *    bar use _BAR_ to indicate where they are found.
 */

#include <sys/bitext.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Host Configuration -- HCFG (config space).
 */
#define	PCH_R_PCIE_HCFG		0x40
/*
 * Disable writes to SPD related data. This bit locks. It was added in PCH 7
 * generation. It was reserved prior to this, so we can just read the reserved 0
 * bit and interpret it as needed.
 */
#define	PCH_R_HCFG_GET_SPDWD(r)		bitx8(r, 4, 4)
/*
 * Subsystem reset added in ICH8.
 */
#define	PCH_R_HCFG_GET_SSRESET(r)	bitx32(r, 3, 3)
#define	PCH_R_HCFG_SET_SSRESET(r, v)	bitset8(r, 3, 3, v)
#define	PCH_R_HCFG_SET_I2CEN(r, v)	bitset8(r, 2, 2, v)
#define	PCH_R_HCFG_I2CEN_I2C		1
#define	PCH_R_HCFG_I2CEN_SMBUS		0
#define	PCH_R_HCFG_GET_SMI_EN(r)	bitx8(r, 1, 1)
#define	PCH_R_HCFG_SET_EN(r, v)		bitset8(r, 0, 0, v)

/*
 * Host Timing -- HTIM (config). 32-bits.
 *
 * Starting in the 100 series chipset Intel started mentioning the presence of
 * the host timing register in PCI configuration space. Whether this is
 * documented or not seems to vary. We mention this here, but our ability to
 * confirm its register layout and presence across generations is rather
 * limited. What knowledge we do have comes from the Ice Lake-D documentation
 * and is also present in the C600 docs. It seems like in practice this may be
 * there but documentation is sparse. These fields depend on the PHY clock.
 */
#define	PCH_R_PCIE_HTIM		0x64
/*
 * 0x0: -7 clocks
 * 0x8: 0 clocks
 * 0xff: 247 clocks
 */
#define	PCH_R_HTIM_SET_THIGH(r, v)	bitset32(r, 31, 24, v)
#define	PCH_R_HTIM_SET_TLOW(r, v)	bitset32(r, 23, 16, v)
/*
 * Signed 4-bit two's complement. 0xf is -7, 0x7 is +7
 */
#define	PCH_R_HTIM_SET_THDSTA(r, v)	bitset32(r, 15, 12, v)
#define	PCH_R_HTIM_SET_TSUSTA(r, v)	bitset32(r, 11, 8, v)
#define	PCH_R_HTIM_SET_TBUF(r, v)	bitset32(r, 7, 4, v)
#define	PCH_R_HTIM_SET_TSUSTO(r, v)	bitset32(r, 3, 0, v)

/*
 * Host Status -- HSTS (HST_STA)
 */
#define	PCH_R_BAR_HSTS		0x00
typedef enum {
	/*
	 * Byte done status (BDS). Indicates that a byte has been transmitted or
	 * received when the 32-byte buffer is not being used.
	 */
	PCH_HSTS_BYTE_DONE	= 1 << 7,
	/*
	 * In use status (IUS). This indicates that the device is currently in
	 * use.  This is basically set whenever a read occurs and is meant to
	 * allow for software synchronization.
	 */
	PCH_HSTS_IN_USE		= 1 << 6,
	/*
	 * SMBus Alert status. Indicates that an SMBus Alert has been generated.
	 */
	PCH_HSTS_SMBUS_ALERT	= 1 << 5,
	/*
	 * Fail. This is set when a failed bus transaction occurs due to the
	 * kill bit being set. That is, software caused this.
	 */
	PCH_HSTS_FAIL		 = 1 << 4,
	/*
	 * Bus error (BERR). This is set when a transaction collision occurs.
	 */
	PCH_HSTS_BUS_ERR	= 1 << 3,
	/*
	 * Device Error (DERR). This is in a number of different cases by
	 * hardware that may be host initiated such as illegal commands, device
	 * time outs, CRC errors, or more.
	 */
	PCH_HSTS_DEV_ERR	= 1 << 2,
	/*
	 * Interrupt (INTR). This indicates that the interrupt occurred because
	 * the last command was successful.
	 */
	PCH_HSTS_INTR		= 1 << 1,
	/*
	 * Host Busy (HBSY) Indicates that the device is busy running a command.
	 * When this is set only the block data is supposed to be accessed.
	 */
	PCH_HSTS_BUSY		= 1 << 0
} pch_smbus_sts_t;

/*
 * Macros for combinations of host status pieces that we care about. The first
 * of these is the collection of errors. The second of these is the set of
 * statuses we want to clear before a transaction and the second the ones after.
 * The primary distinction here is that we don't want to clear the in use flag
 * until we're done with an operation. While we don't actually support alerts,
 * we make it part of the default clear set. Finally, the host busy flag is
 * never part of these as we never want to manually clear the flag.
 */
#define	PCH_HSTS_ERRORS		(PCH_HSTS_FAIL | PCH_HSTS_BUS_ERR | \
    PCH_HSTS_DEV_ERR)
#define	PCH_HSTS_CLEAR_PRE	(PCH_HSTS_ERRORS | PCH_HSTS_INTR | \
    PCH_HSTS_BYTE_DONE | PCH_HSTS_SMBUS_ALERT)
#define	PCH_HSTS_CLEAR_POST	(PCH_HSTS_CLEAR_PRE | PCH_HSTS_IN_USE)

/*
 * Host Control -- HCTL (HST_CNT)
 */
#define	PCH_R_BAR_HCTL		0x02
/*
 * PEC Controls were added in ICH3+.
 */
#define	PCH_R_HCTL_SET_PEC(r, v)	bitset8(r, 7, 7, v)
#define	PCH_R_HCTL_SET_START(r, v)	bitset8(r, 6, 6, v)
#define	PCH_R_HCTL_SET_LAST(r, v)	bitset8(r, 5, 5, v)
#define	PCH_R_HCTL_SET_CMD(r, v)	bitset8(r, 4, 2, v)
#define	PCH_R_HCTL_SET_KILL(r, v)	bitset8(r, 1, 1, v)
#define	PCH_R_HCTL_SET_INT_EN(r, v)	bitset8(r, 0, 0, v)

/*
 * Host Command -- HCMD (HST_CMD).
 *
 * This contains the 8-bit SMBus command field.
 */
#define	PCH_R_BAR_HCMD		0x03

/*
 * Target Address -- TSA (XMIT_SLVA)
 *
 * This sets the 7-bit address and the read/write bit.
 */
#define	PCH_R_BAR_TSA		0x04
#define	PCH_R_TSA_SET_ADDR(r, v)	bitset8(r, 7, 1, v)
#define	PCH_R_TSA_SET_RW(r, v)		bitset8(r, 0, 0, v)
#define	PCH_R_TSA_RW_WRITE	0
#define	PCH_R_TSA_RW_READ	1

/*
 * Host Data 0 -- HD0 (HST_D0)
 * Host Data 1 -- HD0 (HST_D1)
 *
 * These two bytes represent data sent or received in the SMBus commands. When
 * using the block transfer, data 0 is the actual byte count that should be
 * transferred.
 */
#define	PCH_R_BAR_HD0		0x05
#define	PCH_R_BAR_HD1		0x06

/*
 * Host Block Data -- HBD (BLOCK_DB).
 *
 * This register is used as either a FIFO or a single byte buffer depending on
 * whether or not the corresponding feature is enabled in the AUXC register. The
 * ability to treat this as a FIFO was added in ICH4.
 */
#define	PCH_R_BAR_HBD		0x07

/*
 * Packet Error Check Data -- PEC. ICH3+
 */
#define	PCH_R_BAR_PEC		0x08

/*
 * Receive Target Address -- RSA (RCV_SLVA). ICH2+
 */
#define	PCH_R_BAR_RSA		0x09
#define	PCH_R_RSA_SET_ADDR(r, v)	bitset8(r, 6, 0, v)

/*
 * Target Data Register -- SD (SLV_DATA). ICH2+, 16-bits wide.
 *
 * This is a two byte register that contains the data that was received. The low
 * bits correspond to message byte 0. The high bits, byte 1.
 */
#define	PCH_R_BAR_SD		0x0a

/*
 * Auxiliary Status -- AUXS (AUX_STS). ICH4+
 *
 * When the ME is present and there are SMLink connections, some of these bits
 * are read-only bits that describe whether they are enabled or present.
 * However, the exact mapping here is unclear and as we cannot interact with
 * them, left out.
 */
#define	PCH_R_BAR_AUXS		0x0c
#define	PCH_R_AUXS_GET_CRCE(r)		bitx8(r, 0, 0)
#define	PCH_R_AUXS_SET_CRCE(r, v)	bitx8(r, 0, 0, v)

/*
 * Auxiliary Control -- AUXC (AUX_CTL). ICH4+
 *
 * This register enables a number of additional features in the controller.
 */
#define	PCH_R_BAR_AUXC		0x0d
#define	PCH_R_AUXC_SET_E32B(r, v)	bitset8(r, 1, 1, v)
#define	PCH_R_AUXC_SET_AAC(r, v)	bitset8(r, 0, 0, v)

/*
 * SMLink Pin Control -- SMLC. ICH2+
 *
 * The SMLink is a controller that is nominally owned by the ME on several
 * platforms.
 */
#define	PCH_R_BAR_SMLC		0x0e
#define	PCH_R_SMLC_SET_CLK_OVR(r)	bitset8(r, 2, 2, v)
#define	PCH_R_SMLC_CLK_LOW	0
#define	PCH_R_SMLC_CLK_DEF	1
#define	PCH_R_SMLC_GET_DATA(r)	bitx8(r, 1, 1, v)
#define	PCH_R_SMLC_GET_BCLK(r)	bitx8(r, 0, 0, v)

/*
 * SMBus Pin Control -- SMBC. ICH2+
 *
 * This provides the current status of the bus pins and provides an override for
 * the clock to force it low.
 */
#define	PCH_R_BAR_SMBC		0x0f
#define	PCH_R_SMBC_SET_CLK_OVR(r, v)	bitset8(r, 2, 2, v)
#define	PCH_R_SMBC_CLK_LOW	0
#define	PCH_R_SMBC_CLK_DEF	1
#define	PCH_R_SMBC_GET_DATA(r)		bitx8(r, 1, 1, v)
#define	PCH_R_SMBC_GET_BCLK(r)		bitx8(r, 0, 0, v)

/*
 * Target Status Register -- SSTS (SLV_STS). ICH3+
 */
#define	PCH_R_BAR_SSTS		0x10
#define	PCH_R_SSTS_GET_HNS(r)	bitx8(r, 0, 0)
#define	PCH_R_SSTS_SET_HNS(r)	bitx8(r, 0, 0, 1)

/*
 * Target Command Register -- SCMD (SLV_CMD). ICH3+
 */
#define	PCH_R_BAR_SCMD		0x11
#define	PCH_R_SCMD_GET_SMB_D(r)		bitx8(r, 2, 2)
#define	PCH_R_SCMD_SET_SMB_D(r, v)	bitset8(r, 2, 2, v)
#define	PCH_R_SCMD_GET_HNW(r)		bitx8(r, 1, 1)
#define	PCH_R_SCMD_SET_HNW(r, v)	bitset8(r, 1, 1, v)
#define	PCH_R_SCMD_GET_HNI(r)		bitx8(r, 0, 0)
#define	PCH_R_SCMD_SET_HNI(r, v)	bitset8(r, 0, 0, v)

/*
 * Notify Device Address -- NDA. ICH3+
 */
#define	PCH_R_BAR_NDA		0x14
#define	PCH_R_NDA_SET_ADDR(r, v)	bitset8(r, 7, 1, v)

/*
 * Notify Data Low Byte -- NDLB. ICH3+
 * Notify Data High Byte -- NDHB. ICH3+
 *
 * These registers contain the notification data when the notification status is
 * set. The entire register is used for the byte.
 */
#define	PCH_R_BAR_NDLB		0x16
#define	PCH_R_BAR_NDHB		0x17

/*
 * Command Operation Codes. These values must match the expectations of the Host
 * Control register's command field. These do not have read versus write
 * distinctions (other than i2c reads). Read versus write otherwise comes from
 * the direction used.
 */
typedef enum {
	PCH_SMBUS_CMD_QUICK		= 0,
	PCH_SMBUS_CMD_BYTE		= 1,
	PCH_SMBUS_CMD_BYTE_DATA		= 2,
	PCH_SMBUS_CMD_WORD_DATA		= 3,
	PCH_SMBUS_CMD_PROC_CALL		= 4,
	PCH_SMBUS_CMD_BLOCK		= 5,
	/*
	 * According to various datasheets, this command was added even in the
	 * original ICH. Other drivers claim that this was only supported
	 * started in ICH5+. In practice, we don't support anything without the
	 * extended buffer support and we are unlikely to find a 64-bit system
	 * with this old a chipset (but if we do, we can address it then).
	 */
	PCH_SMBUS_CMD_I2C_READ		= 6,
	/*
	 * This feature was specifically listed starting in ICH5+.
	 */
	PCH_SMBUS_CMD_BLOCK_PROC	= 7
} pch_smbus_cmd_t;

/*
 * These are a series of features that different devices can support that our
 * per-device detection leverages to know what to use or not. Just because a
 * feature is listed here doesn't mean the driver will take advantage or work on
 * hardware without it. We have left out timing control due to its limited
 * documentation.
 */
typedef enum {
	/*
	 * Indicates that the controller supports acting as a target and that it
	 * supports notification features. The first is ICH2+. The second is
	 * ICH3+.
	 */
	PCH_SMBUS_FEAT_TARG		= 1 << 0,
	PCH_SMBUS_FEAT_TARG_NOTIFY	= 1 << 1,
	/*
	 * This indicates support for calculating the PEC and checking it in
	 * software. Generally speaking this is ICH3+.
	 */
	PCH_SMBUS_FEAT_SW_PEC		= 1 << 2,
	/*
	 * This indicates support for hardware PEC features. Generally speaking
	 * this is ICH4+.
	 */
	PCH_SMBUS_FEAT_HW_PEC		= 1 << 3,
	/*
	 * This indicates that the hardware supports the 32 byte block buffer
	 * features. This generally was added in ICH4+.
	 */
	PCH_SMBUS_FEAT_32B_BUF		= 1 << 4,
	/*
	 * This indicates that the hardware supports the block procedure call
	 * function. This is ICH5+.
	 */
	PCH_SMBUS_FEAT_BLOCK_PROC	= 1 << 5,
	/*
	 * Indicates support for the subsystem reset. This is ICH8+.
	 */
	PCH_SMBUS_FEAT_RESET		= 1 << 6,
} pch_smbus_feat_t;

#define	PCH_SMBUS_FEAT_ALL_ICH2		PCH_SMBUS_FEAT_TARG
#define	PCH_SMBUS_FEAT_ALL_ICH3		(PCH_SMBUS_FEAT_ALL_ICH2 | \
    PCH_SMBUS_FEAT_TARG_NOTIFY | PCH_SMBUS_FEAT_SW_PEC)
#define	PCH_SMBUS_FEAT_ALL_ICH4		(PCH_SMBUS_FEAT_ALL_ICH3 | \
    PCH_SMBUS_FEAT_HW_PEC | PCH_SMBUS_FEAT_32B_BUF)
#define	PCH_SMBUS_FEAT_ALL_ICH5		(PCH_SMBUS_FEAT_ALL_ICH4 | \
    PCH_SMBUS_FEAT_BLOCK_PROC)
#define	PCH_SMBUS_FEAT_ALL_ICH8		(PCH_SMBUS_FEAT_ALL_ICH5 | \
    PCH_SMBUS_FEAT_RESET)

/*
 * The following are various PCI IDs for devices that we've sourced from Intel
 * datasheets.
 */
#define	PCH_SMBUS_VID_INTEL	0x8086
#define	PCH_SMBUS_ICH0_82801AA	0x2413
#define	PCH_SMBUS_ICH0_82901AB	0x2423
#define	PCH_SMBUS_ICH2_82801BA	0x2443
#define	PCH_SMBUS_ICH3_82801CA	0x2483
#define	PCH_SMBUS_ICH4_82801DB	0x24c3
#define	PCH_SMBUS_ICH5_82801Ex	0x24d3
#define	PCH_SMBUS_6300ESB	0x25a4
#define	PCH_SMBUS_ICH6		0x266a
#define	PCH_SMBUS_631xESB	0x269b /* Also 632xESB */
#define	PCH_SMBUS_ICH7		0x27da
#define	PCH_SMBUS_ICH8		0x283e
#define	PCH_SMBUS_ICH9		0x2930
#define	PCH_SMBUS_ICH10_USER	0x3a30
#define	PCH_SMBUS_ICH10_CORP	0x3a60
#define	PCH_SMBUS_PCH5		0x3b30	/* Also 3400 */
#define	PCH_SMBUS_PCH6		0x1cc2	/* Also C200 */
#define	PCH_SMBUS_C600		0x1d22	/* Also X79 */
#define	PCH_SMBUS_C600_SMB0	0x1d70
#define	PCH_SMBUS_C600_SMB1	0x1d71	/* C606/C608 */
#define	PCH_SMBUS_C600_SMB2	0x1d72	/* C608 */
#define	PCH_SMBUS_DH89xxCC	0x2330
#define	PCH_SMBUS_DH89xxCL	0x23b0
#define	PCH_SMBUS_PCH7		0x1e22	/* Also C216 */
#define	PCH_SMBUS_PCH8		0x8cc2	/* Also C220 */
/*
 * This device ID has seen a bunch of use. It was originally the 4th Gen Core
 * series low power ID. The 300 series on package low power also used it. It has
 * also been used by some of the Braswell N/J 3xxx Atoms.
 */
#define	PCH_SMBUS_PCH8_LP	0x9c22
#define	PCH_SMBUS_C610		0x8d22	/* Also X99 */
/* Owned by the ME, but may be released to us */
#define	PCH_SMBUS_C610_MS0	0x8d7d
#define	PCH_SMBUS_C610_MS1	0x8d7e
#define	PCH_SMBUS_C610_MS2	0x8d7f
#define	PCH_SMBUS_PCH9		0x8ca2
#define	PCH_SMBUS_PCH9_LP	0x9ca2	/* 5th Gen Mobile */
#define	PCH_SMBUS_BAYTRAIL	0x0f12	/* E3800 and Z3700 Atom */
#define	PCH_SMBUS_100		0xa123	/* Also C230 */
#define	PCH_SMBUS_DENVERTON	0x19df	/* Atom C3000 */
#define	PCH_SMBUS_C740		0x1bc9
#define	PCH_SMBUS_APOLLO	0x5ad4	/* Atom E3900, Silver Celeron */
#define	PCH_SMBUS_C620		0xa1a3
#define	PCH_SMBUS_C620_SUPER	0xa223
#define	PCH_SMBUS_200		0xa2a3	/* Also X299/Z370 */
#define	PCH_SMBUS_GEMINI	0x31d4
#define	PCH_SMBUS_300		0xa323	/* Also C240 */
/* Ice Lake Variants */
#define	PCH_SMBUS_ICE_LAKE_D	0x18df
#define	PCH_SMBUS_495_PKG	0x34a3
/* Comet Lake */
#define	PCH_SMBUS_400_PKG	0x02a3
#define	PCH_SMBUS_400		0x06a3
/* Elkhart Lake aka Atom x6000E */
#define	PCH_SMBUS_ELKHART	0x4b23
/* Tiger Lake */
#define	PCH_SMBUS_500		0x43a3
#define	PCH_SMBUS_500_PKG	0xa0a3
#define	PCH_SMBUS_JASPER	0x4da3	/* Pentium/Celeron Silver (Atom) */
/* Adler Lake */
#define	PCH_SMBUS_600		0x7aa3	/* Also 700 series */
#define	PCH_SMBUS_600_PKG	0x51a3	/* Also 700 On-Package */
/* Meteor Lake */
#define	PCH_SMBUS_800		0x7f23
#define	PCH_SMBUS_METEOR_PS	0x7e22	/* Also -H/-E */
/* Arrow Lake */
#define	PCH_SMBUS_ULTRA_200	0x7722
/* Panther Lake */
#define	PCH_SMBUS_PANTHER_H	0xe322
#define	PCH_SMBUS_PANTHER_P	0xe422

#ifdef __cplusplus
}
#endif

#endif /* _PCHSMBUS_H */
