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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

#ifndef _BGE_HW_H
#define	_BGE_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>


/*
 * First section:
 *	Identification of the various Broadcom chips
 *
 * Note: the various ID values are *not* all unique ;-(
 *
 * Note: the presence of an ID here does *not* imply that the chip is
 * supported.  At this time, only the 5703C, 5704C, and 5704S devices
 * used on the motherboards of certain Sun products are supported.
 *
 * Note: the revision-id values in the PCI revision ID register are
 * *NOT* guaranteed correct.  Use the chip ID from the MHCR instead.
 */

#define	VENDOR_ID_BROADCOM		0x14e4
#define	VENDOR_ID_SUN			0x108e

#define	DEVICE_ID_5700			0x1644
#define	DEVICE_ID_5700x			0x0003
#define	DEVICE_ID_5701			0x1645
#define	DEVICE_ID_5702			0x16a6
#define	DEVICE_ID_5702fe		0x164d
#define	DEVICE_ID_5703C			0x16a7
#define	DEVICE_ID_5703S			0x1647
#define	DEVICE_ID_5703			0x16c7
#define	DEVICE_ID_5704C			0x1648
#define	DEVICE_ID_5704S			0x16a8
#define	DEVICE_ID_5704			0x1649
#define	DEVICE_ID_5705C			0x1653
#define	DEVICE_ID_5705_2		0x1654
#define	DEVICE_ID_5717			0x1655
#define	DEVICE_ID_5717_C0		0x1665
#define	DEVICE_ID_5718			0x1656
#define	DEVICE_ID_5719			0x1657
#define	DEVICE_ID_5720			0x165f
#define	DEVICE_ID_5724			0x165c
#define	DEVICE_ID_5725			0x1643
#define	DEVICE_ID_5727			0x16f3
#define	DEVICE_ID_5705M			0x165d
#define	DEVICE_ID_5705MA3		0x165e
#define	DEVICE_ID_5705F			0x166e
#define	DEVICE_ID_5780			0x166a
#define	DEVICE_ID_5782			0x1696
#define	DEVICE_ID_5785			0x1699
#define	DEVICE_ID_5787			0x169b
#define	DEVICE_ID_5787M			0x1693
#define	DEVICE_ID_5788			0x169c
#define	DEVICE_ID_5789			0x169d
#define	DEVICE_ID_5751			0x1677
#define	DEVICE_ID_5751M			0x167d
#define	DEVICE_ID_5752			0x1600
#define	DEVICE_ID_5752M			0x1601
#define	DEVICE_ID_5753			0x16fd
#define	DEVICE_ID_5754			0x167a
#define	DEVICE_ID_5755			0x167b
#define	DEVICE_ID_5755M			0x1673
#define	DEVICE_ID_5756M			0x1674
#define	DEVICE_ID_5721			0x1659
#define	DEVICE_ID_5722			0x165a
#define	DEVICE_ID_5723			0x165b
#define	DEVICE_ID_5714C			0x1668
#define	DEVICE_ID_5714S			0x1669
#define	DEVICE_ID_5715C			0x1678
#define	DEVICE_ID_5715S			0x1679
#define	DEVICE_ID_5761E			0x1680
#define	DEVICE_ID_5761			0x1681
#define	DEVICE_ID_5764			0x1684
#define	DEVICE_ID_5906			0x1712
#define	DEVICE_ID_5906M			0x1713
#define	DEVICE_ID_57780			0x1692

#define	REVISION_ID_5700_B0		0x10
#define	REVISION_ID_5700_B2		0x12
#define	REVISION_ID_5700_B3		0x13
#define	REVISION_ID_5700_C0		0x20
#define	REVISION_ID_5700_C1		0x21
#define	REVISION_ID_5700_C2		0x22

#define	REVISION_ID_5701_A0		0x08
#define	REVISION_ID_5701_A2		0x12
#define	REVISION_ID_5701_A3		0x15

#define	REVISION_ID_5702_A0		0x00

#define	REVISION_ID_5703_A0		0x00
#define	REVISION_ID_5703_A1		0x01
#define	REVISION_ID_5703_A2		0x02

#define	REVISION_ID_5704_A0		0x00
#define	REVISION_ID_5704_A1		0x01
#define	REVISION_ID_5704_A2		0x02
#define	REVISION_ID_5704_A3		0x03
#define	REVISION_ID_5704_B0		0x10

#define	REVISION_ID_5705_A0		0x00
#define	REVISION_ID_5705_A1		0x01
#define	REVISION_ID_5705_A2		0x02
#define	REVISION_ID_5705_A3		0x03

#define	REVISION_ID_5721_A0		0x00
#define	REVISION_ID_5721_A1		0x01

#define	REVISION_ID_5751_A0		0x00
#define	REVISION_ID_5751_A1		0x01

#define	REVISION_ID_5714_A0		0x00
#define	REVISION_ID_5714_A1		0x01
#define	REVISION_ID_5714_A2		0xA2
#define	REVISION_ID_5714_A3		0xA3

#define	REVISION_ID_5715_A0		0x00
#define	REVISION_ID_5715_A1		0x01
#define	REVISION_ID_5715_A2		0xA2

#define	REVISION_ID_5715S_A0		0x00
#define	REVISION_ID_5715S_A1		0x01

#define	REVISION_ID_5754_A0		0x00
#define	REVISION_ID_5754_A1		0x01

#define	DEVICE_5704_SERIES_CHIPSETS(bgep)\
		((bgep->chipid.device == DEVICE_ID_5700) ||\
		(bgep->chipid.device == DEVICE_ID_5701) ||\
		(bgep->chipid.device == DEVICE_ID_5702) ||\
		(bgep->chipid.device == DEVICE_ID_5702fe)||\
		(bgep->chipid.device == DEVICE_ID_5703C) ||\
		(bgep->chipid.device == DEVICE_ID_5703S) ||\
		(bgep->chipid.device == DEVICE_ID_5703) ||\
		(bgep->chipid.device == DEVICE_ID_5704C) ||\
		(bgep->chipid.device == DEVICE_ID_5704S) ||\
		(bgep->chipid.device == DEVICE_ID_5704))

#define	DEVICE_5702_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5702) ||\
		(bgep->chipid.device == DEVICE_ID_5702fe))

#define	DEVICE_5705_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5705C) ||\
		(bgep->chipid.device == DEVICE_ID_5705M) ||\
		(bgep->chipid.device == DEVICE_ID_5705MA3) ||\
		(bgep->chipid.device == DEVICE_ID_5705F) ||\
		(bgep->chipid.device == DEVICE_ID_5780) ||\
		(bgep->chipid.device == DEVICE_ID_5782) ||\
		(bgep->chipid.device == DEVICE_ID_5788) ||\
		(bgep->chipid.device == DEVICE_ID_5705_2) ||\
		(bgep->chipid.device == DEVICE_ID_5754) ||\
		(bgep->chipid.device == DEVICE_ID_5755) ||\
		(bgep->chipid.device == DEVICE_ID_5756M) ||\
		(bgep->chipid.device == DEVICE_ID_5753))

#define	DEVICE_5721_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5721) ||\
		(bgep->chipid.device == DEVICE_ID_5751) ||\
		(bgep->chipid.device == DEVICE_ID_5751M) ||\
		(bgep->chipid.device == DEVICE_ID_5752) ||\
		(bgep->chipid.device == DEVICE_ID_5752M) ||\
		(bgep->chipid.device == DEVICE_ID_5789))

#define	DEVICE_5717_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5717) ||\
		(bgep->chipid.device == DEVICE_ID_5718) ||\
		(bgep->chipid.device == DEVICE_ID_5719) ||\
		(bgep->chipid.device == DEVICE_ID_5720) ||\
		(bgep->chipid.device == DEVICE_ID_5724))

#define	DEVICE_5725_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5725) ||\
		(bgep->chipid.device == DEVICE_ID_5727))

#define	DEVICE_5723_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5723) ||\
		(bgep->chipid.device == DEVICE_ID_5761) ||\
		(bgep->chipid.device == DEVICE_ID_5761E) ||\
		(bgep->chipid.device == DEVICE_ID_5764) ||\
		(bgep->chipid.device == DEVICE_ID_5785) ||\
		(bgep->chipid.device == DEVICE_ID_57780))

#define	DEVICE_5714_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5714C) ||\
		(bgep->chipid.device == DEVICE_ID_5714S) ||\
		(bgep->chipid.device == DEVICE_ID_5715C) ||\
		(bgep->chipid.device == DEVICE_ID_5715S))

#define	DEVICE_5906_SERIES_CHIPSETS(bgep) \
		((bgep->chipid.device == DEVICE_ID_5906) ||\
		(bgep->chipid.device == DEVICE_ID_5906M))

/*
 * Second section:
 *	Offsets of important registers & definitions for bits therein
 */

/*
 * PCI-X registers & bits
 */
#define	PCIX_CONF_COMM			0x42
#define	PCIX_COMM_RELAXED		0x0002

/*
 * Miscellaneous Host Control Register, in PCI config space
 */
#define	PCI_CONF_BGE_MHCR		0x68
#define	MHCR_CHIP_REV_MASK		0xffff0000
#define	MHCR_ENABLE_TAGGED_STATUS_MODE	0x00000200
#define	MHCR_MASK_INTERRUPT_MODE	0x00000100
#define	MHCR_ENABLE_INDIRECT_ACCESS	0x00000080
#define	MHCR_ENABLE_REGISTER_WORD_SWAP	0x00000040
#define	MHCR_ENABLE_CLOCK_CONTROL_WRITE	0x00000020
#define	MHCR_ENABLE_PCI_STATE_RW	0x00000010
#define	MHCR_ENABLE_ENDIAN_WORD_SWAP	0x00000008
#define	MHCR_ENABLE_ENDIAN_BYTE_SWAP	0x00000004
#define	MHCR_MASK_PCI_INT_OUTPUT	0x00000002
#define	MHCR_CLEAR_INTERRUPT_INTA	0x00000001
#define	MHCR_BOUNDARY_CHECK		0x00002000
#define	MHCR_TLP_MINOR_ERR_TOLERANCE	0x00008000

#define	MHCR_CHIP_REV_5700_B0		0x71000000
#define	MHCR_CHIP_REV_5700_B2		0x71020000
#define	MHCR_CHIP_REV_5700_B3		0x71030000
#define	MHCR_CHIP_REV_5700_C0		0x72000000
#define	MHCR_CHIP_REV_5700_C1		0x72010000
#define	MHCR_CHIP_REV_5700_C2		0x72020000

#define	MHCR_CHIP_REV_5701_A0		0x00000000
#define	MHCR_CHIP_REV_5701_A2		0x00020000
#define	MHCR_CHIP_REV_5701_A3		0x00030000
#define	MHCR_CHIP_REV_5701_A5		0x01050000

#define	MHCR_CHIP_REV_5702_A0		0x10000000
#define	MHCR_CHIP_REV_5702_A1		0x10010000
#define	MHCR_CHIP_REV_5702_A2		0x10020000

#define	MHCR_CHIP_REV_5703_A0		0x10000000
#define	MHCR_CHIP_REV_5703_A1		0x10010000
#define	MHCR_CHIP_REV_5703_A2		0x10020000
#define	MHCR_CHIP_REV_5703_B0		0x11000000
#define	MHCR_CHIP_REV_5703_B1		0x11010000

#define	MHCR_CHIP_REV_5704_A0		0x20000000
#define	MHCR_CHIP_REV_5704_A1		0x20010000
#define	MHCR_CHIP_REV_5704_A2		0x20020000
#define	MHCR_CHIP_REV_5704_A3		0x20030000
#define	MHCR_CHIP_REV_5704_B0		0x21000000

#define	MHCR_CHIP_REV_5705_A0		0x30000000
#define	MHCR_CHIP_REV_5705_A1		0x30010000
#define	MHCR_CHIP_REV_5705_A2		0x30020000
#define	MHCR_CHIP_REV_5705_A3		0x30030000
#define	MHCR_CHIP_REV_5705_A5		0x30050000

#define	MHCR_CHIP_REV_5782_A0		0x30030000
#define	MHCR_CHIP_REV_5782_A1		0x30030088

#define	MHCR_CHIP_REV_5788_A1		0x30050000

#define	MHCR_CHIP_REV_5751_A0		0x40000000
#define	MHCR_CHIP_REV_5751_A1		0x40010000

#define	MHCR_CHIP_REV_5721_A0		0x41000000
#define	MHCR_CHIP_REV_5721_A1		0x41010000

#define	MHCR_CHIP_REV_5714_A0		0x50000000
#define	MHCR_CHIP_REV_5714_A1		0x90010000

#define	MHCR_CHIP_REV_5715_A0		0x50000000
#define	MHCR_CHIP_REV_5715_A1		0x90010000

#define	MHCR_CHIP_REV_5715S_A0		0x50000000
#define	MHCR_CHIP_REV_5715S_A1		0x90010000

#define	MHCR_CHIP_REV_5754_A0		0xb0000000
#define	MHCR_CHIP_REV_5754_A1		0xb0010000

#define	MHCR_CHIP_REV_5787_A0		0xb0000000
#define	MHCR_CHIP_REV_5787_A1		0xb0010000
#define	MHCR_CHIP_REV_5787_A2		0xb0020000

#define	MHCR_CHIP_REV_5755_A0		0xa0000000
#define	MHCR_CHIP_REV_5755_A1		0xa0010000

#define	MHCR_CHIP_REV_5906_A0		0xc0000000
#define	MHCR_CHIP_REV_5906_A1		0xc0010000
#define	MHCR_CHIP_REV_5906_A2		0xc0020000

#define	CHIP_ASIC_REV_USE_PROD_ID_REG	0xf0000000
#define	MHCR_CHIP_ASIC_REV(bgep) ((bgep)->chipid.asic_rev & 0xf0000000)
#define	CHIP_ASIC_REV_PROD_ID(bgep) ((bgep)->chipid.asic_rev_prod_id)
#define	CHIP_ASIC_REV(bgep) ((bgep)->chipid.asic_rev_prod_id >> 12)

#define	MHCR_CHIP_ASIC_REV_5700		(0x7 << 28)
#define	MHCR_CHIP_ASIC_REV_5701		(0x0 << 28)
#define	MHCR_CHIP_ASIC_REV_5703		(0x1 << 28)
#define	MHCR_CHIP_ASIC_REV_5704		(0x2 << 28)
#define	MHCR_CHIP_ASIC_REV_5705		(0x3 << 28)
#define	MHCR_CHIP_ASIC_REV_5721_5751	(0x4 << 28)
#define	MHCR_CHIP_ASIC_REV_5714 	(0x5 << 28)
#define	MHCR_CHIP_ASIC_REV_5752		(0x6 << 28)
#define	MHCR_CHIP_ASIC_REV_5754		(0xb << 28)
#define	MHCR_CHIP_ASIC_REV_5787		((uint32_t)0xb << 28)
#define	MHCR_CHIP_ASIC_REV_5755		((uint32_t)0xa << 28)
#define	MHCR_CHIP_ASIC_REV_5715 	((uint32_t)0x9 << 28)
#define	MHCR_CHIP_ASIC_REV_5906		((uint32_t)0xc << 28)
/* (0xf << 28) touches all 5717 and 5725 series as well (OK) */
#define	MHCR_CHIP_ASIC_REV_5723		((uint32_t)0xf << 28)

#define	CHIP_ASIC_REV_5723		0x5784
#define	CHIP_ASIC_REV_5761		0x5761
#define	CHIP_ASIC_REV_5785		0x5785
#define	CHIP_ASIC_REV_57780		0x57780

#define	CHIP_ASIC_REV_5717		0x5717
#define	CHIP_ASIC_REV_5719		0x5719
#define	CHIP_ASIC_REV_5720		0x5720
#define	CHIP_ASIC_REV_5762		0x5762 /* 5725/5727 */

#define	CHIP_ASIC_REV_PROD_ID_REG	0x000000bc
#define	CHIP_ASIC_REV_PROD_ID_GEN2_REG	0x000000f4

#define	CHIP_ASIC_REV_5717_B0		0x05717100
#define	CHIP_ASIC_REV_5717_C0		0x05717200
#define	CHIP_ASIC_REV_5718_B0		0x05717100
#define	CHIP_ASIC_REV_5719_A0		0x05719000
#define	CHIP_ASIC_REV_5719_A1		0x05719001
#define	CHIP_ASIC_REV_5720_A0		0x05720000
#define	CHIP_ASIC_REV_5725_A0		0x05762000
#define	CHIP_ASIC_REV_5727_B0		0x05762100

/*
 * PCI DMA read/write Control Register, in PCI config space
 *
 * Note that several fields previously defined here have been deleted
 * as they are not implemented in the 5703/4.
 *
 * Note: the value of this register is critical.  It is possible to
 * cause various unpleasant effects (DTOs, transaction deadlock, etc)
 * by programming the wrong value.  The value #defined below has been
 * tested and shown to avoid all known problems.  If it is to be changed,
 * correct operation must be reverified on all supported platforms.
 *
 * In particular, we set both watermark fields to 2xCacheLineSize (128)
 * bytes and DMA_MIN_BEATS to 0 in order to avoid unfortunate interactions
 * with Tomatillo's internal pipelines, that otherwise result in stalls,
 * repeated retries, and DTOs.
 */
#define	PCI_CONF_BGE_PDRWCR		0x6c
#define	PDRWCR_RWCMD_MASK		0xFF000000
#define	PDRWCR_PCIX32_BUGFIX_MASK	0x00800000
#define	PDRWCR_WRITE_WATERMARK_MASK	0x00380000
#define	PDRWCR_READ_WATERMARK_MASK	0x00070000
#define	PDRWCR_CONCURRENCY_MASK		0x0000c000
#define	PDRWCR_5704_FLOP_ON_RETRY	0x00008000
#define	PDRWCR_ONE_DMA_AT_ONCE		0x00004000
#define	PDRWCR_MIN_BEAT_MASK		0x000000ff

/*
 * These are the actual values to be put into the fields shown above
 */
#define	PDRWCR_RWCMDS			0x76000000	/* MW and MR	*/
#define	PDRWCR_DMA_WRITE_WATERMARK	0x00180000	/* 011 => 128	*/
#define	PDRWCR_DMA_READ_WATERMARK	0x00030000	/* 011 => 128	*/
#define	PDRWCR_MIN_BEATS		0x00000000

#define	PDRWCR_VAR_DEFAULT		0x761b0000
#define	PDRWCR_VAR_5721			0x76180000
#define	PDRWCR_VAR_5714			0x76148000	/* OR of above	*/
#define	PDRWCR_VAR_5715			0x76144000	/* OR of above	*/
#define	PDRWCR_VAR_5717			0x00380000

/*
 * PCI State Register, in PCI config space
 *
 * Note: this register is read-only unless the ENABLE_PCI_STATE_WRITE bit
 * is set in the MHCR, EXCEPT for the RETRY_SAME_DMA bit which is always RW
 */
#define	PCI_CONF_BGE_PCISTATE		0x70
#define	PCISTATE_ALLOW_APE_CTLSPC_WR	0x00010000
#define	PCISTATE_ALLOW_APE_SHMEM_WR	0x00020000
#define	PCISTATE_ALLOW_APE_PSPACE_WR	0x00040000
#define	PCISTATE_RETRY_SAME_DMA		0x00002000
#define	PCISTATE_FLAT_VIEW		0x00000100
#define	PCISTATE_EXT_ROM_RETRY		0x00000040
#define	PCISTATE_EXT_ROM_ENABLE		0x00000020
#define	PCISTATE_BUS_IS_32_BIT		0x00000010
#define	PCISTATE_BUS_IS_FAST		0x00000008
#define	PCISTATE_BUS_IS_PCI		0x00000004
#define	PCISTATE_INTA_STATE		0x00000002
#define	PCISTATE_FORCE_RESET		0x00000001

/*
 * PCI Clock Control Register, in PCI config space
 */
#define	PCI_CONF_BGE_CLKCTL		0x74
#define	CLKCTL_PCIE_PLP_DISABLE		0x80000000
#define	CLKCTL_PCIE_DLP_DISABLE		0x40000000
#define	CLKCTL_PCIE_TLP_DISABLE		0x20000000
#define	CLKCTL_PCI_READ_TOO_LONG_FIX	0x04000000
#define	CLKCTL_PCI_WRITE_TOO_LONG_FIX	0x02000000
#define	CLKCTL_PCIE_A0_FIX		0x00101000

/*
 * Dual MAC Control Register, in PCI config space
 */
#define	PCI_CONF_BGE_DUAL_MAC_CONTROL	0xB8
#define	DUALMAC_CHANNEL_CONTROL_MASK	0x00000003	/* RW	*/
#define	DUALMAC_CHANNEL_ID_MASK		0x00000004	/* RO	*/

/*
 * Register Indirect Access Address Register, 0x78 in PCI config
 * space.  Once this is set, accesses to the Register Indirect
 * Access Data Register (0x80) refer to the register whose address
 * is given by *this* register.  This allows access to all the
 * operating registers, while using only config space accesses.
 *
 * Note that the address written to the RIIAR should lie in one
 * of the following ranges:
 *	0x00000000 <= address < 0x00008000 (regular registers)
 *	0x00030000 <= address < 0x00034000 (RxRISC scratchpad)
 *	0x00034000 <= address < 0x00038000 (TxRISC scratchpad)
 *	0x00038000 <= address < 0x00038800 (RxRISC ROM)
 */
#define	PCI_CONF_BGE_RIAAR		0x78
#define	PCI_CONF_BGE_RIADR		0x80

#define	RIAAR_REGISTER_MIN		0x00000000
#define	RIAAR_REGISTER_MAX		0x00008000
#define	RIAAR_RX_SCRATCH_MIN		0x00030000
#define	RIAAR_RX_SCRATCH_MAX		0x00034000
#define	RIAAR_TX_SCRATCH_MIN		0x00034000
#define	RIAAR_TX_SCRATCH_MAX		0x00038000
#define	RIAAR_RXROM_MIN			0x00038000
#define	RIAAR_RXROM_MAX			0x00038800

/*
 * Memory Window Base Address Register, 0x7c in PCI config space
 * Once this is set, accesses to the Memory Window Data Access Register
 * (0x84) refer to the word of NIC-local memory whose address is given
 * by this register.  When used in this way, the whole of the address
 * written to this register is significant.
 *
 * This register also provides the 32K-aligned base address for a 32K
 * region of NIC-local memory that the host can directly address in
 * the upper 32K of the 64K of PCI memory space allocated to the chip.
 * In this case, the bottom 15 bits of the register are ignored.
 *
 * Note that the address written to the MWBAR should lie in the range
 * 0x00000000 <= address < 0x00020000.  The rest of the range up to 1M
 * (i.e. 0x00200000 <= address < 0x01000000) would be valid if external
 * memory were present, but it's only supported on the 5700, not the
 * 5701/5703/5704.
 */
#define	PCI_CONF_BGE_MWBAR		0x7c
#define	PCI_CONF_BGE_MWDAR		0x84
#define	MWBAR_GRANULARITY		0x00008000	/* 32k	*/
#define	MWBAR_GRANULE_MASK		(MWBAR_GRANULARITY-1)
#define	MWBAR_ONCHIP_MAX		0x00020000	/* 128k */

/*
 * The PCI express device control register and device status register
 * which are only applicable on BCM5751 and BCM5721.
 */
#define	PCI_CONF_DEV_CTRL		0xd8
#define	PCI_CONF_DEV_CTRL_5723		0xd4
#define	PCI_CONF_DEV_CTRL_5717		0xb4
#define	READ_REQ_SIZE_MASK		0x7000
#define	READ_REQ_SIZE_MAX		0x5000
#define	READ_REQ_SIZE_2K 		0x4000
#define	DEV_CTRL_NO_SNOOP		0x0800
#define	DEV_CTRL_RELAXED		0x0010

#define	PCI_CONF_DEV_STUS		0xda
#define	PCI_CONF_DEV_STUS_5723		0xd6
#define	DEVICE_ERROR_STUS		0xf

#define	NIC_MEM_WINDOW_OFFSET		0x00008000	/* 32k	*/

/*
 * Where to find things in NIC-local (on-chip) memory
 */
#define	NIC_MEM_SEND_RINGS		0x0100
#define	NIC_MEM_SEND_RING(ring)		(0x0100+16*(ring))
#define	NIC_MEM_RECV_RINGS		0x0200
#define	NIC_MEM_RECV_RING(ring)		(0x0200+16*(ring))
#define	NIC_MEM_STATISTICS		0x0300
#define	NIC_MEM_STATISTICS_SIZE		0x0800
#define	NIC_MEM_STATUS_BLOCK		0x0b00
#define	NIC_MEM_STATUS_SIZE		0x0050
#define	NIC_MEM_GENCOMM			0x0b50


/*
 * Note: the (non-bogus) values below are appropriate for systems
 * without external memory.  They would be different on a 5700 with
 * external memory.
 *
 * Note: The higher send ring addresses and the mini ring shadow
 * buffer address are dummies - systems without external memory
 * are limited to 4 send rings and no mini receive ring.
 */
#define	NIC_MEM_SHADOW_DMA		0x2000
#define	NIC_MEM_SHADOW_SEND_1_4		0x4000
#define	NIC_MEM_SHADOW_SEND_5_6		0x6000		/* bogus	*/
#define	NIC_MEM_SHADOW_SEND_7_8		0x7000		/* bogus	*/
#define	NIC_MEM_SHADOW_SEND_9_16	0x8000		/* bogus	*/
#define	NIC_MEM_SHADOW_BUFF_STD		0x6000
#define	NIC_MEM_SHADOW_BUFF_STD_5717	0x40000
#define	NIC_MEM_SHADOW_BUFF_JUMBO	0x7000
#define	NIC_MEM_SHADOW_BUFF_MINI	0x8000		/* bogus	*/
#define	NIC_MEM_SHADOW_SEND_RING(ring, nslots)	(0x4000 + 4*(ring)*(nslots))

/*
 * Put this in the GENCOMM port to tell the firmware not to run PXE
 */
#define	T3_MAGIC_NUMBER			0x4b657654u

/*
 * The remaining registers appear in the low 32K of regular
 * PCI Memory Address Space
 */

/*
 * All the state machine control registers below have at least a
 * <RESET> bit and an <ENABLE> bit as defined below.  Some also
 * have an <ATTN_ENABLE> bit.
 */
#define	STATE_MACHINE_ATTN_ENABLE_BIT	0x00000004
#define	STATE_MACHINE_ENABLE_BIT	0x00000002
#define	STATE_MACHINE_RESET_BIT		0x00000001

#define	TRANSMIT_MAC_MODE_REG		0x045c
#define	SEND_DATA_INITIATOR_MODE_REG	0x0c00
#define	SEND_DATA_COMPLETION_MODE_REG	0x1000
#define	SEND_BD_SELECTOR_MODE_REG	0x1400
#define	SEND_BD_INITIATOR_MODE_REG	0x1800
#define	SEND_BD_COMPLETION_MODE_REG	0x1c00

#define	RECEIVE_MAC_MODE_REG		0x0468
#define	RCV_LIST_PLACEMENT_MODE_REG	0x2000
#define	RCV_DATA_BD_INITIATOR_MODE_REG	0x2400
#define	RCV_DATA_COMPLETION_MODE_REG	0x2800
#define	RCV_BD_INITIATOR_MODE_REG	0x2c00
#define	RCV_BD_COMPLETION_MODE_REG	0x3000
#define	RCV_LIST_SELECTOR_MODE_REG	0x3400

#define	MBUF_CLUSTER_FREE_MODE_REG	0x3800
#define	HOST_COALESCE_MODE_REG		0x3c00
#define	MEMORY_ARBITER_MODE_REG		0x4000
#define	BUFFER_MANAGER_MODE_REG		0x4400
#define	BUFFER_MANAGER_MODE_NO_TX_UNDERRUN	0x80000000
#define	BUFFER_MANAGER_MODE_MBLOW_ATTN_ENABLE	0x00000010
#define	READ_DMA_MODE_REG		0x4800
#define	WRITE_DMA_MODE_REG		0x4c00
#define	DMA_COMPLETION_MODE_REG		0x6400
#define	FAST_BOOT_PC			0x6894

#define	RDMA_RSRV_CTRL_REG		0x4900
#define	RDMA_RSRV_CTRL_REG2		0x4890
#define	RDMA_RSRV_CTRL_FIFO_OFLW_FIX	0x00000004
#define	RDMA_RSRV_CTRL_FIFO_LWM_1_5K	0x00000c00
#define	RDMA_RSRV_CTRL_FIFO_LWM_MASK	0x00000ff0
#define	RDMA_RSRV_CTRL_FIFO_HWM_1_5K	0x000c0000
#define	RDMA_RSRV_CTRL_FIFO_HWM_MASK	0x000ff000
#define	RDMA_RSRV_CTRL_TXMRGN_320B	0x28000000
#define	RDMA_RSRV_CTRL_TXMRGN_MASK	0xffe00000

#define	RDMA_CORR_CTRL_REG		0x4910
#define	RDMA_CORR_CTRL_REG2		0x48a0
#define	RDMA_CORR_CTRL_BLEN_BD_4K	0x00030000
#define	RDMA_CORR_CTRL_BLEN_LSO_4K	0x000c0000
#define	RDMA_CORR_CTRL_TX_LENGTH_WA	0x02000000

#define	BGE_NUM_RDMA_CHANNELS		4
#define	BGE_RDMA_LENGTH			0x4be0

/*
 * Other bits in some of the above state machine control registers
 */

/*
 * Transmit MAC Mode Register
 * (TRANSMIT_MAC_MODE_REG, 0x045c)
 */
#define	TRANSMIT_MODE_MBUF_LOCKUP_FIX	0x00000100
#define	TRANSMIT_MODE_LONG_PAUSE	0x00000040
#define	TRANSMIT_MODE_BIG_BACKOFF	0x00000020
#define	TRANSMIT_MODE_FLOW_CONTROL	0x00000010

/*
 * Receive MAC Mode Register
 * (RECEIVE_MAC_MODE_REG, 0x0468)
 */
#define	RECEIVE_MODE_KEEP_VLAN_TAG	0x00000400
#define	RECEIVE_MODE_NO_CRC_CHECK	0x00000200
#define	RECEIVE_MODE_PROMISCUOUS	0x00000100
#define	RECEIVE_MODE_LENGTH_CHECK	0x00000080
#define	RECEIVE_MODE_ACCEPT_RUNTS	0x00000040
#define	RECEIVE_MODE_ACCEPT_OVERSIZE	0x00000020
#define	RECEIVE_MODE_KEEP_PAUSE		0x00000010
#define	RECEIVE_MODE_FLOW_CONTROL	0x00000004

/*
 * Receive BD Initiator Mode Register
 * (RCV_BD_INITIATOR_MODE_REG, 0x2c00)
 *
 * Each of these bits controls whether ATTN is asserted
 * on a particular condition
 */
#define	RCV_BD_DISABLED_RING_ATTN	0x00000004

/*
 * Receive Data & Receive BD Initiator Mode Register
 * (RCV_DATA_BD_INITIATOR_MODE_REG, 0x2400)
 *
 * Each of these bits controls whether ATTN is asserted
 * on a particular condition
 */
#define	RCV_DATA_BD_ILL_RING_ATTN	0x00000010
#define	RCV_DATA_BD_FRAME_SIZE_ATTN	0x00000008
#define	RCV_DATA_BD_NEED_JUMBO_ATTN	0x00000004

#define	RCV_DATA_BD_ALL_ATTN_BITS	0x0000001c

/*
 * Host Coalescing Mode Control Register
 * (HOST_COALESCE_MODE_REG, 0x3c00)
 */
#define	COALESCE_64_BYTE_RINGS		12
#define	COALESCE_NO_INT_ON_COAL_FORCE	0x00001000
#define	COALESCE_NO_INT_ON_DMAD_FORCE	0x00000800
#define	COALESCE_CLR_TICKS_TX		0x00000400
#define	COALESCE_CLR_TICKS_RX		0x00000200
#define	COALESCE_32_BYTE_STATUS		0x00000100
#define	COALESCE_64_BYTE_STATUS		0x00000080
#define	COALESCE_NOW			0x00000008

/*
 * Memory Arbiter Mode Register
 * (MEMORY_ARBITER_MODE_REG, 0x4000)
 */
#define	MEMORY_ARBITER_ENABLE		0x00000002

/*
 * Buffer Manager Mode Register
 * (BUFFER_MANAGER_MODE_REG, 0x4400)
 *
 * In addition to the usual error-attn common to most state machines
 * this register has a separate bit for attn on running-low-on-mbufs
 */
#define	BUFF_MGR_TEST_MODE		0x00000008
#define	BUFF_MGR_MBUF_LOW_ATTN_ENABLE	0x00000010

#define	BUFF_MGR_ALL_ATTN_BITS		0x00000014

/*
 * Read and Write DMA Mode Registers (READ_DMA_MODE_REG,
 * 0x4800 and WRITE_DMA_MODE_REG, 0x4c00)
 *
 * These registers each contain a 2-bit priority field, which controls
 * the relative priority of that type of DMA (read vs. write vs. MSI),
 * and a set of bits that control whether ATTN is asserted on each
 * particular condition
 */
#define	DMA_PRIORITY_MASK		0xc0000000
#define	DMA_PRIORITY_SHIFT		30
#define	ALL_DMA_ATTN_BITS		0x000003fc

/*
 * BCM5755, 5755M, 5906, 5906M only
 * 1 - Enable Fix. Device will send out the status block before
 *     the interrupt message
 * 0 - Disable fix. Device will send out the interrupt message
 *     before the status block
 */
#define	DMA_STATUS_TAG_FIX_CQ12384	0x20000000

/*
 * End of state machine control register definitions
 */


/*
 * High priority mailbox registers.
 * Mailbox Registers (8 bytes each, but high half unused)
 */
#define	INTERRUPT_MBOX_0_REG		0x0200
#define	INTERRUPT_MBOX_1_REG		0x0208
#define	INTERRUPT_MBOX_2_REG		0x0210
#define	INTERRUPT_MBOX_3_REG		0x0218
#define	INTERRUPT_MBOX_REG(n)		(0x0200+8*(n))

/*
 * Low priority mailbox registers, for BCM5906, BCM5906M.
 */
#define	INTERRUPT_LP_MBOX_0_REG		0x5800

/*
 * Ring Producer/Consumer Index (Mailbox) Registers
 */
#define	RECV_STD_PROD_INDEX_REG		0x0268
#define	RECV_JUMBO_PROD_INDEX_REG	0x0270
#define	RECV_MINI_PROD_INDEX_REG	0x0278
#define	RECV_RING_CONS_INDEX_REGS	0x0280
#define	SEND_RING_HOST_PROD_INDEX_REGS	0x0300
#define	SEND_RING_NIC_PROD_INDEX_REGS	0x0380

#define	RECV_RING_CONS_INDEX_REG(ring)	(0x0280+8*(ring))
#define	SEND_RING_HOST_INDEX_REG(ring)	(0x0300+8*(ring))
#define	SEND_RING_NIC_INDEX_REG(ring)	(0x0380+8*(ring))

/*
 * Ethernet MAC Mode Register
 */
#define	ETHERNET_MAC_MODE_REG		0x0400
#define	ETHERNET_MODE_APE_TX_EN		0x10000000
#define	ETHERNET_MODE_APE_RX_EN		0x08000000
#define	ETHERNET_MODE_ENABLE_FHDE	0x00800000
#define	ETHERNET_MODE_ENABLE_RDE	0x00400000
#define	ETHERNET_MODE_ENABLE_TDE	0x00200000
#define	ETHERNET_MODE_ENABLE_MIP	0x00100000
#define	ETHERNET_MODE_ENABLE_ACPI	0x00080000
#define	ETHERNET_MODE_ENABLE_MAGIC_PKT	0x00040000
#define	ETHERNET_MODE_SEND_CFGS		0x00020000
#define	ETHERNET_MODE_FLUSH_TX_STATS	0x00010000
#define	ETHERNET_MODE_CLEAR_TX_STATS	0x00008000
#define	ETHERNET_MODE_ENABLE_TX_STATS	0x00004000
#define	ETHERNET_MODE_FLUSH_RX_STATS	0x00002000
#define	ETHERNET_MODE_CLEAR_RX_STATS	0x00001000
#define	ETHERNET_MODE_ENABLE_RX_STATS	0x00000800
#define	ETHERNET_MODE_LINK_POLARITY	0x00000400
#define	ETHERNET_MODE_MAX_DEFER		0x00000200
#define	ETHERNET_MODE_ENABLE_TX_BURST	0x00000100
#define	ETHERNET_MODE_TAGGED_MODE	0x00000080
#define	ETHERNET_MODE_MAC_LOOPBACK	0x00000010
#define	ETHERNET_MODE_PORTMODE_MASK	0x0000000c
#define	ETHERNET_MODE_PORTMODE_TBI	0x0000000c
#define	ETHERNET_MODE_PORTMODE_GMII	0x00000008
#define	ETHERNET_MODE_PORTMODE_MII	0x00000004
#define	ETHERNET_MODE_PORTMODE_NONE	0x00000000
#define	ETHERNET_MODE_HALF_DUPLEX	0x00000002
#define	ETHERNET_MODE_GLOBAL_RESET	0x00000001

/*
 * Ethernet MAC Status & Event Registers
 */
#define	ETHERNET_MAC_STATUS_REG		0x0404
#define	ETHERNET_STATUS_MI_INT		0x00800000
#define	ETHERNET_STATUS_MI_COMPLETE	0x00400000
#define	ETHERNET_STATUS_LINK_CHANGED	0x00001000
#define	ETHERNET_STATUS_PCS_ERROR	0x00000400
#define	ETHERNET_STATUS_SYNC_CHANGED	0x00000010
#define	ETHERNET_STATUS_CFG_CHANGED	0x00000008
#define	ETHERNET_STATUS_RECEIVING_CFG	0x00000004
#define	ETHERNET_STATUS_SIGNAL_DETECT	0x00000002
#define	ETHERNET_STATUS_PCS_SYNCHED	0x00000001

#define	ETHERNET_MAC_EVENT_ENABLE_REG	0x0408
#define	ETHERNET_EVENT_MI_INT		0x00800000
#define	ETHERNET_EVENT_LINK_INT		0x00001000
#define	ETHERNET_STATUS_PCS_ERROR_INT	0x00000400

/*
 * Ethernet MAC LED Control Register
 *
 * NOTE: PHY mode 1 *MUST* be selected; this is the hardware default and
 * the external LED driver circuitry is wired up to assume that this mode
 * will always be selected.  Software must not change it!
 */
#define	ETHERNET_MAC_LED_CONTROL_REG	0x040c
#define	LED_CONTROL_OVERRIDE_BLINK	0x80000000
#define	LED_CONTROL_BLINK_PERIOD_MASK	0x7ff80000
#define	LED_CONTROL_LED_MODE_MASK	0x00001800
#define	LED_CONTROL_LED_MODE_5700	0x00000000
#define	LED_CONTROL_LED_MODE_PHY_1	0x00000800	/* mandatory	*/
#define	LED_CONTROL_LED_MODE_PHY_2	0x00001000
#define	LED_CONTROL_LED_MODE_RESERVED	0x00001800
#define	LED_CONTROL_TRAFFIC_LED_STATUS	0x00000400
#define	LED_CONTROL_10MBPS_LED_STATUS	0x00000200
#define	LED_CONTROL_100MBPS_LED_STATUS	0x00000100
#define	LED_CONTROL_1000MBPS_LED_STATUS	0x00000080
#define	LED_CONTROL_BLINK_TRAFFIC	0x00000040
#define	LED_CONTROL_TRAFFIC_LED		0x00000020
#define	LED_CONTROL_OVERRIDE_TRAFFIC	0x00000010
#define	LED_CONTROL_10MBPS_LED		0x00000008
#define	LED_CONTROL_100MBPS_LED		0x00000004
#define	LED_CONTROL_1000MBPS_LED	0x00000002
#define	LED_CONTROL_OVERRIDE_LINK	0x00000001
#define	LED_CONTROL_DEFAULT		0x02000800

/*
 * MAC Address registers
 *
 * These four eight-byte registers each hold one unicast address
 * (six bytes), right justified & zero-filled on the left.
 * They will normally all be set to the same value, as a station
 * usually only has one h/w address.  The value in register 0 is
 * used for pause packets; any of the four can be specified for
 * substitution into other transmitted packets if required.
 */
#define	MAC_ADDRESS_0_REG		0x0410
#define	MAC_ADDRESS_1_REG		0x0418
#define	MAC_ADDRESS_2_REG		0x0420
#define	MAC_ADDRESS_3_REG		0x0428

#define	MAC_ADDRESS_REG(n)		(0x0410+8*(n))
#define	MAC_ADDRESS_REGS_MAX		4

/*
 * More MAC Registers ...
 */
#define	MAC_TX_RANDOM_BACKOFF_REG	0x0438
#define	MAC_RX_MTU_SIZE_REG		0x043c
#define	MAC_RX_MTU_DEFAULT		0x000005f2	/* 1522	*/
#define	MAC_TX_LENGTHS_REG		0x0464
#define	MAC_TX_LENGTHS_DEFAULT		0x00002620

/*
 * MII access registers
 */
#define	MI_COMMS_REG			0x044c
#define	MI_COMMS_START			0x20000000
#define	MI_COMMS_READ_FAILED		0x10000000
#define	MI_COMMS_COMMAND_MASK		0x0c000000
#define	MI_COMMS_COMMAND_READ		0x08000000
#define	MI_COMMS_COMMAND_WRITE		0x04000000
#define	MI_COMMS_ADDRESS_MASK		0x03e00000
#define	MI_COMMS_ADDRESS_SHIFT		21
#define	MI_COMMS_REGISTER_MASK		0x001f0000
#define	MI_COMMS_REGISTER_SHIFT		16
#define	MI_COMMS_DATA_MASK		0x0000ffff
#define	MI_COMMS_DATA_SHIFT		0

#define	MI_STATUS_REG			0x0450
#define	MI_STATUS_10MBPS		0x00000002
#define	MI_STATUS_LINK			0x00000001

#define	MI_MODE_REG			0x0454
#define	MI_MODE_CLOCK_MASK		0x001f0000
#define	MI_MODE_AUTOPOLL		0x00000010
#define	MI_MODE_POLL_SHORT_PREAMBLE	0x00000002
#define	MI_MODE_DEFAULT			0x000c0000

#define	MI_AUTOPOLL_STATUS_REG		0x0458
#define	MI_AUTOPOLL_ERROR		0x00000001

#define	TRANSMIT_MAC_STATUS_REG		0x0460
#define	TRANSMIT_STATUS_ODI_OVERRUN	0x00000020
#define	TRANSMIT_STATUS_ODI_UNDERRUN	0x00000010
#define	TRANSMIT_STATUS_LINK_UP		0x00000008
#define	TRANSMIT_STATUS_SENT_XON	0x00000004
#define	TRANSMIT_STATUS_SENT_XOFF	0x00000002
#define	TRANSMIT_STATUS_RCVD_XOFF	0x00000001

#define	RECEIVE_MAC_STATUS_REG		0x046c
#define	RECEIVE_STATUS_RCVD_XON		0x00000004
#define	RECEIVE_STATUS_RCVD_XOFF	0x00000002
#define	RECEIVE_STATUS_SENT_XOFF	0x00000001

/*
 * These four-byte registers constitute a hash table for deciding
 * whether to accept incoming multicast packets.  The bits are
 * numbered in big-endian fashion, from hash 0 => the MSB of
 * register 0 to hash 127 => the LSB of the highest-numbered
 * register.
 *
 * NOTE: the 5704 can use a 256-bit table (registers 0-7) if
 * enabled by setting the appropriate bit in the Rx MAC mode
 * register.  Otherwise, and on all earlier chips, the table
 * is only 128 bits (registers 0-3).
 */
#define	MAC_HASH_0_REG			0x0470
#define	MAC_HASH_1_REG			0x0474
#define	MAC_HASH_2_REG			0x0478
#define	MAC_HASH_3_REG			0x047c
#define	MAC_HASH_4_REG			0x????
#define	MAC_HASH_5_REG			0x????
#define	MAC_HASH_6_REG			0x????
#define	MAC_HASH_7_REG			0x????
#define	MAC_HASH_REG(n)			(0x470+4*(n))

/*
 * Receive Rules Registers: 16 pairs of control+mask/value pairs
 */
#define	RCV_RULES_CONTROL_0_REG		0x0480
#define	RCV_RULES_MASK_0_REG		0x0484
#define	RCV_RULES_CONTROL_15_REG	0x04f8
#define	RCV_RULES_MASK_15_REG		0x04fc
#define	RCV_RULES_CONFIG_REG		0x0500
#define	RCV_RULES_CONFIG_DEFAULT	0x00000008

#define	RECV_RULES_NUM_MAX		16
#define	RECV_RULE_CONTROL_REG(rule)	(RCV_RULES_CONTROL_0_REG+8*(rule))
#define	RECV_RULE_MASK_REG(rule)	(RCV_RULES_MASK_0_REG+8*(rule))

#define	RECV_RULE_CTL_ENABLE		0x80000000
#define	RECV_RULE_CTL_AND		0x40000000
#define	RECV_RULE_CTL_P1		0x20000000
#define	RECV_RULE_CTL_P2		0x10000000
#define	RECV_RULE_CTL_P3		0x08000000
#define	RECV_RULE_CTL_MASK		0x04000000
#define	RECV_RULE_CTL_DISCARD		0x02000000
#define	RECV_RULE_CTL_MAP		0x01000000
#define	RECV_RULE_CTL_RESV_BITS		0x00fc0000
#define	RECV_RULE_CTL_OP		0x00030000
#define	RECV_RULE_CTL_OP_EQ		0x00000000
#define	RECV_RULE_CTL_OP_NEQ		0x00010000
#define	RECV_RULE_CTL_OP_GREAT		0x00020000
#define	RECV_RULE_CTL_OP_LESS		0x00030000
#define	RECV_RULE_CTL_HEADER		0x0000e000
#define	RECV_RULE_CTL_HEADER_FRAME	0x00000000
#define	RECV_RULE_CTL_HEADER_IP		0x00002000
#define	RECV_RULE_CTL_HEADER_TCP	0x00004000
#define	RECV_RULE_CTL_HEADER_UDP	0x00006000
#define	RECV_RULE_CTL_HEADER_DATA	0x00008000
#define	RECV_RULE_CTL_CLASS_BITS	0x00001f00
#define	RECV_RULE_CTL_CLASS(ring)	(((ring) << 8) & \
					    RECV_RULE_CTL_CLASS_BITS)
#define	RECV_RULE_CTL_OFFSET		0x000000ff

/*
 * Receive Rules definition
 */
#define	ETHERHEADER_DEST_OFFSET		0x00
#define	IPHEADER_PROTO_OFFSET		0x08
#define	IPHEADER_SIP_OFFSET		0x0c
#define	IPHEADER_DIP_OFFSET		0x10
#define	TCPHEADER_SPORT_OFFSET		0x00
#define	TCPHEADER_DPORT_OFFSET		0x02
#define	UDPHEADER_SPORT_OFFSET		0x00
#define	UDPHEADER_DPORT_OFFSET		0x02

#define	RULE_MATCH(ring)	(RECV_RULE_CTL_ENABLE | RECV_RULE_CTL_OP_EQ | \
				    RECV_RULE_CTL_CLASS((ring)))

#define	RULE_MATCH_MASK(ring)	(RULE_MATCH(ring) | RECV_RULE_CTL_MASK)

#define	RULE_DEST_MAC_1(ring)	(RULE_MATCH(ring) | \
				    RECV_RULE_CTL_HEADER_FRAME | \
				    ETHERHEADER_DEST_OFFSET)

#define	RULE_DEST_MAC_2(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_FRAME | \
				    ETHERHEADER_DEST_OFFSET + 4)

#define	RULE_LOCAL_IP(ring)	(RULE_MATCH(ring) | RECV_RULE_CTL_HEADER_IP | \
				    IPHEADER_DIP_OFFSET)

#define	RULE_REMOTE_IP(ring)	(RULE_MATCH(ring) | RECV_RULE_CTL_HEADER_IP | \
				    IPHEADER_SIP_OFFSET)

#define	RULE_IP_PROTO(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_IP | \
				    IPHEADER_PROTO_OFFSET)

#define	RULE_TCP_SPORT(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_TCP | \
				    TCPHEADER_SPORT_OFFSET)

#define	RULE_TCP_DPORT(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_TCP | \
				    TCPHEADER_DPORT_OFFSET)

#define	RULE_UDP_SPORT(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_UDP | \
				    UDPHEADER_SPORT_OFFSET)

#define	RULE_UDP_DPORT(ring)	(RULE_MATCH_MASK(ring) | \
				    RECV_RULE_CTL_HEADER_UDP | \
				    UDPHEADER_DPORT_OFFSET)

/*
 * 1000BaseX low-level access registers
 */
#define	MAC_GIGABIT_PCS_TEST_REG	0x0440
#define	MAC_GIGABIT_PCS_TEST_ENABLE	0x00100000
#define	MAC_GIGABIT_PCS_TEST_PATTERN	0x000fffff
#define	TX_1000BASEX_AUTONEG_REG	0x0444
#define	RX_1000BASEX_AUTONEG_REG	0x0448

/*
 * Autoneg code bits for the 1000BASE-X AUTONEG registers
 */
#define	AUTONEG_CODE_PAUSE		0x00008000
#define	AUTONEG_CODE_HALF_DUPLEX	0x00004000
#define	AUTONEG_CODE_FULL_DUPLEX	0x00002000
#define	AUTONEG_CODE_NEXT_PAGE		0x00000080
#define	AUTONEG_CODE_ACKNOWLEDGE	0x00000040
#define	AUTONEG_CODE_FAULT_MASK		0x00000030
#define	AUTONEG_CODE_FAULT_ANEG_ERR	0x00000030
#define	AUTONEG_CODE_FAULT_LINK_FAIL	0x00000020
#define	AUTONEG_CODE_FAULT_OFFLINE	0x00000010
#define	AUTONEG_CODE_ASYM_PAUSE		0x00000001

/*
 * SerDes Registers (5703S/5704S only)
 */
#define	SERDES_CONTROL_REG		0x0590
#define	SERDES_CONTROL_TBI_LOOPBACK	0x00020000
#define	SERDES_CONTROL_COMMA_DETECT	0x00010000
#define	SERDES_CONTROL_TX_DISABLE	0x00004000
#define	SERDES_STATUS_REG		0x0594
#define	SERDES_STATUS_COMMA_DETECTED	0x00000100
#define	SERDES_STATUS_RXSTAT		0x000000ff

/* 5780/5714 only */
#define SERDES_RX_CONTROL		0x000005b0
#define SERDES_RX_CONTROL_SIG_DETECT	0x00000400

/*
 * SGMII Status Register (5717/18/19/20 only)
 */
#define	SGMII_STATUS_REG	0x5B4
#define	MEDIA_SELECTION_MODE	0x00000100

/*
 * Statistic Registers (5705/5788/5721/5751/5752/5714/5715 only)
 */
#define	STAT_IFHCOUT_OCTETS_REG		0x0800
#define	STAT_ETHER_COLLIS_REG		0x0808
#define	STAT_OUTXON_SENT_REG		0x080c
#define	STAT_OUTXOFF_SENT_REG		0x0810
#define	STAT_DOT3_INTMACTX_ERR_REG		0x0818
#define	STAT_DOT3_SCOLLI_FRAME_REG		0x081c
#define	STAT_DOT3_MCOLLI_FRAME_REG		0x0820
#define	STAT_DOT3_DEFERED_TX_REG		0x0824
#define	STAT_DOT3_EXCE_COLLI_REG		0x082c
#define	STAT_DOT3_LATE_COLLI_REG		0x0830
#define	STAT_IFHCOUT_UPKGS_REG		0x086c
#define	STAT_IFHCOUT_MPKGS_REG		0x0870
#define	STAT_IFHCOUT_BPKGS_REG		0x0874

#define	STAT_IFHCIN_OCTETS_REG		0x0880
#define	STAT_ETHER_FRAGMENT_REG		0x0888
#define	STAT_IFHCIN_UPKGS_REG		0x088c
#define	STAT_IFHCIN_MPKGS_REG		0x0890
#define	STAT_IFHCIN_BPKGS_REG		0x0894

#define	STAT_DOT3_FCS_ERR_REG		0x0898
#define	STAT_DOT3_ALIGN_ERR_REG		0x089c
#define	STAT_XON_PAUSE_RX_REG		0x08a0
#define	STAT_XOFF_PAUSE_RX_REG		0x08a4
#define	STAT_MAC_CTRL_RX_REG		0x08a8
#define	STAT_XOFF_STATE_ENTER_REG		0x08ac
#define	STAT_DOT3_FRAME_TOOLONG_REG		0x08b0
#define	STAT_ETHER_JABBERS_REG		0x08b4
#define	STAT_ETHER_UNDERSIZE_REG		0x08b8
#define	SIZE_OF_STATISTIC_REG		0x1B
/*
 * Send Data Initiator Registers
 */
#define	SEND_INIT_STATS_CONTROL_REG	0x0c08
#define	SEND_INIT_STATS_ZERO		0x00000010
#define	SEND_INIT_STATS_FLUSH		0x00000008
#define	SEND_INIT_STATS_CLEAR		0x00000004
#define	SEND_INIT_STATS_FASTER		0x00000002
#define	SEND_INIT_STATS_ENABLE		0x00000001

#define	SEND_INIT_STATS_ENABLE_MASK_REG	0x0c0c

/*
 * Send Buffer Descriptor Selector Control Registers
 */
#define	SEND_BD_SELECTOR_STATUS_REG	0x1404
#define	SEND_BD_SELECTOR_HWDIAG_REG	0x1408
#define	SEND_BD_SELECTOR_INDEX_REG(n)	(0x1440+4*(n))

/*
 * Receive List Placement Registers
 */
#define	RCV_LP_CONFIG_REG		0x2010
#define	RCV_LP_CONFIG_DEFAULT		0x00000009
#define	RCV_LP_CONFIG(rings)		(((rings) << 3) | 0x1)

#define	RCV_LP_STATS_CONTROL_REG	0x2014
#define	RCV_LP_STATS_ZERO		0x00000010
#define	RCV_LP_STATS_FLUSH		0x00000008
#define	RCV_LP_STATS_CLEAR		0x00000004
#define	RCV_LP_STATS_FASTER		0x00000002
#define	RCV_LP_STATS_ENABLE		0x00000001

#define	RCV_LP_STATS_ENABLE_MASK_REG	0x2018
#define	RCV_LP_STATS_DISABLE_MACTQ	0x040000

/*
 * Receive Data & BD Initiator Registers
 */
#define	RCV_INITIATOR_STATUS_REG	0x2404

/*
 * Receive Buffer Descriptor Ring Control Block Registers
 * NB: sixteen bytes (128 bits) each
 */
#define	JUMBO_RCV_BD_RING_RCB_REG	0x2440
#define	STD_RCV_BD_RING_RCB_REG		0x2450
#define	MINI_RCV_BD_RING_RCB_REG	0x2460

/*
 * Receive Buffer Descriptor Ring Replenish Threshold Registers
 */
#define	MINI_RCV_BD_REPLENISH_REG	0x2c14
#define	MINI_RCV_BD_REPLENISH_DEFAULT	0x00000080	/* 128	*/
#define	STD_RCV_BD_REPLENISH_REG	0x2c18
#define	STD_RCV_BD_REPLENISH_DEFAULT	0x00000002	/* 2	*/
#define	JUMBO_RCV_BD_REPLENISH_REG	0x2c1c
#define	JUMBO_RCV_BD_REPLENISH_DEFAULT	0x00000020	/* 32	*/

/*
 * CPMU registers (5717/18/19/20 only)
 */
#define	CPMU_CLCK_ORIDE_REG		0x3624
#define	CPMU_CLCK_ORIDE_MAC_ORIDE_EN	0x80000000
#define	CPMU_STATUS_REG			0x362c
#define	CPMU_STATUS_FUNC_NUM		0x20000000
#define	CPMU_STATUS_FUNC_NUM_SHIFT	29
#define	CPMU_STATUS_FUNC_NUM_5719 	0xc0000000
#define	CPMU_STATUS_FUNC_NUM_5719_SHIFT	30

/*
 * EEE registers (5718/19/20 only)
 */
#define	EEE_MODE_REG			0x36b0
#define	EEE_MODE_APE_TX_DET_EN		0x00000004
#define	EEE_MODE_ERLY_L1_XIT_DET	0x00000008
#define	EEE_MODE_SND_IDX_DET_EN		0x00000040
#define	EEE_MODE_LPI_ENABLE		0x00000080
#define	EEE_MODE_LPI_IN_TX		0x00000100
#define	EEE_MODE_LPI_IN_RX		0x00000200
#define	EEE_MODE_EEE_ENABLE		0x00100000

#define	EEE_DEBOUNCE_T1_CONTROL_REG	0x36b4
#define	EEE_DEBOUNCE_T1_PCIEXIT_2047US	0x07ff0000
#define	EEE_DEBOUNCE_T1_LNKIDLE_2047US	0x000007ff

#define	EEE_DEBOUNCE_T2_CONTROL_REG	0x36b8
#define	EEE_DEBOUNCE_T2_APE_TX_2047US	0x07ff0000
#define	EEE_DEBOUNCE_T2_TXIDXEQ_2047US	0x000007ff

#define	EEE_LINK_IDLE_CONTROL_REG	0x36bc
#define	EEE_LINK_IDLE_PCIE_NL0		0x01000000
#define	EEE_LINK_IDLE_UART_IDL		0x00000004
#define	EEE_LINK_IDLE_APE_TX_MT		0x00000002

#define	EEE_CONTROL_REG			0x36d0
#define	EEE_CONTROL_EXIT_16_5_US	0x0000019d
#define	EEE_CONTROL_EXIT_36_US		0x00000384
#define	EEE_CONTROL_EXIT_20_1_US	0x000001f8

/* Clause 45 expansion registers */
#define	EEE_CL45_D7_RESULT_STAT			0x803e
#define	EEE_CL45_D7_RESULT_STAT_LP_100TX	0x0002
#define	EEE_CL45_D7_RESULT_STAT_LP_1000T	0x0004

#define MDIO_MMD_AN			0x0007
#define MDIO_AN_EEE_ADV			0x003c

/*
 * Host Coalescing Engine Control Registers
 */
#define	RCV_COALESCE_TICKS_REG		0x3c08
#define	RCV_COALESCE_TICKS_DEFAULT	0x00000096	/* 150	*/
#define	SEND_COALESCE_TICKS_REG		0x3c0c
#define	SEND_COALESCE_TICKS_DEFAULT	0x00000096	/* 150	*/
#define	RCV_COALESCE_MAX_BD_REG		0x3c10
#define	RCV_COALESCE_MAX_BD_DEFAULT	0x0000000a	/* 10	*/
#define	SEND_COALESCE_MAX_BD_REG	0x3c14
#define	SEND_COALESCE_MAX_BD_DEFAULT	0x0000000a	/* 10	*/
#define	RCV_COALESCE_INT_TICKS_REG	0x3c18
#define	RCV_COALESCE_INT_TICKS_DEFAULT	0x00000000	/* 0	*/
#define	SEND_COALESCE_INT_TICKS_REG	0x3c1c
#define	SEND_COALESCE_INT_TICKS_DEFAULT	0x00000000	/* 0	*/
#define	RCV_COALESCE_INT_BD_REG		0x3c20
#define	RCV_COALESCE_INT_BD_DEFAULT	0x00000000	/* 0	*/
#define	SEND_COALESCE_INT_BD_REG	0x3c24
#define	SEND_COALESCE_INT_BD_DEFAULT	0x00000000	/* 0	*/
#define	STATISTICS_TICKS_REG		0x3c28
#define	STATISTICS_TICKS_DEFAULT	0x000f4240	/* 1000000 */
#define	STATISTICS_HOST_ADDR_REG	0x3c30
#define	STATUS_BLOCK_HOST_ADDR_REG	0x3c38
#define	STATISTICS_BASE_ADDR_REG	0x3c40
#define	STATUS_BLOCK_BASE_ADDR_REG	0x3c44
#define	FLOW_ATTN_REG			0x3c48

#define	NIC_JUMBO_RECV_INDEX_REG	0x3c50
#define	NIC_STD_RECV_INDEX_REG		0x3c54
#define	NIC_MINI_RECV_INDEX_REG		0x3c58
#define	NIC_DIAG_RETURN_INDEX_REG(n)	(0x3c80+4*(n))
#define	NIC_DIAG_SEND_INDEX_REG(n)	(0x3cc0+4*(n))

/*
 * Mbuf Pool Initialisation & Watermark Registers
 *
 * There are some conflicts in the PRM; compare the recommendations
 * on pp. 115, 236, and 339.  The values here were recommended by
 * dkim@broadcom.com (and the PRM should be corrected soon ;-)
 */
#define	BUFFER_MANAGER_STATUS_REG	0x4404
#define	MBUF_POOL_BASE_REG		0x4408
#define	MBUF_POOL_BASE_DEFAULT		0x00008000
#define	MBUF_POOL_BASE_5721		0x00010000
#define	MBUF_POOL_BASE_5704		0x00010000
#define	MBUF_POOL_BASE_5705		0x00010000
#define	MBUF_POOL_LENGTH_REG		0x440c
#define	MBUF_POOL_LENGTH_DEFAULT	0x00018000
#define	MBUF_POOL_LENGTH_5704		0x00010000
#define	MBUF_POOL_LENGTH_5705		0x00008000
#define	MBUF_POOL_LENGTH_5721		0x00008000
#define	RDMA_MBUF_LOWAT_REG		0x4410
#define	RDMA_MBUF_LOWAT_DEFAULT		0x00000050
#define	RDMA_MBUF_LOWAT_5705		0x00000000
#define	RDMA_MBUF_LOWAT_5906		0x00000000
#define	RDMA_MBUF_LOWAT_JUMBO		0x00000130
#define	RDMA_MBUF_LOWAT_5714_JUMBO	0x00000000
#define	MAC_RX_MBUF_LOWAT_REG		0x4414
#define	MAC_RX_MBUF_LOWAT_DEFAULT	0x00000020
#define	MAC_RX_MBUF_LOWAT_5705		0x00000010
#define	MAC_RX_MBUF_LOWAT_5906		0x00000004
#define	MAC_RX_MBUF_LOWAT_5717		0x0000002a
#define	MAC_RX_MBUF_LOWAT_JUMBO		0x00000098
#define	MAC_RX_MBUF_LOWAT_5714_JUMBO	0x0000004b
#define	MBUF_HIWAT_REG			0x4418
#define	MBUF_HIWAT_DEFAULT		0x00000060
#define	MBUF_HIWAT_5705			0x00000060
#define	MBUF_HIWAT_5906			0x00000010
#define	MBUF_HIWAT_5717			0x000000a0
#define	MBUF_HIWAT_JUMBO		0x0000017c
#define	MBUF_HIWAT_5714_JUMBO		0x00000096

/*
 * DMA Descriptor Pool Initialisation & Watermark Registers
 */
#define	DMAD_POOL_BASE_REG		0x442c
#define	DMAD_POOL_BASE_DEFAULT		0x00002000
#define	DMAD_POOL_LENGTH_REG		0x4430
#define	DMAD_POOL_LENGTH_DEFAULT	0x00002000
#define	DMAD_POOL_LOWAT_REG		0x4434
#define	DMAD_POOL_LOWAT_DEFAULT		0x00000005	/* 5	*/
#define	DMAD_POOL_HIWAT_REG		0x4438
#define	DMAD_POOL_HIWAT_DEFAULT		0x0000000a	/* 10	*/

/*
 * More threshold/watermark registers ...
 */
#define	RECV_FLOW_THRESHOLD_REG		0x4458
#define	LOWAT_MAX_RECV_FRAMES_REG	0x0504
#define	LOWAT_MAX_RECV_FRAMES_DEFAULT	0x00000002

/*
 * Read/Write DMA Status Registers
 */
#define	READ_DMA_STATUS_REG		0x4804
#define	WRITE_DMA_STATUS_REG		0x4c04

/*
 * RX/TX RISC Registers
 */
#define	RX_RISC_MODE_REG		0x5000
#define	RX_RISC_STATE_REG		0x5004
#define	RX_RISC_PC_REG			0x501c
#define	TX_RISC_MODE_REG		0x5400
#define	TX_RISC_STATE_REG		0x5404
#define	TX_RISC_PC_REG			0x541c

/*
 * V? RISC Registerss
 */
#define	VCPU_STATUS_REG			0x5100
#define	VCPU_INIT_DONE			0x04000000
#define	VCPU_DRV_RESET			0x08000000

#define	VCPU_EXT_CTL			0x6890
#define	VCPU_EXT_CTL_HALF		0x00400000

#define	FTQ_RESET_REG			0x5c00

#define	MSI_MODE_REG			0x6000
#define	MSI_PRI_HIGHEST			0xc0000000
#define	MSI_MSI_ENABLE			0x00000002
#define	MSI_ERROR_ATTENTION		0x0000001c

#define	MSI_STATUS_REG			0x6004

#define	MODE_CONTROL_REG		0x6800
#define	MODE_ROUTE_MCAST_TO_RX_RISC	0x40000000
#define	MODE_4X_NIC_SEND_RINGS		0x20000000
#define	MODE_INT_ON_FLOW_ATTN		0x10000000
#define	MODE_INT_ON_DMA_ATTN		0x08000000
#define	MODE_INT_ON_MAC_ATTN		0x04000000
#define	MODE_INT_ON_RXRISC_ATTN		0x02000000
#define	MODE_INT_ON_TXRISC_ATTN		0x01000000
#define	MODE_RECV_NO_PSEUDO_HDR_CSUM	0x00800000
#define	MODE_SEND_NO_PSEUDO_HDR_CSUM	0x00100000
#define	MODE_HOST_SEND_BDS		0x00020000
#define	MODE_HOST_STACK_UP		0x00010000
#define	MODE_FORCE_32_BIT_PCI		0x00008000
#define	MODE_NO_INT_ON_RECV		0x00004000
#define	MODE_NO_INT_ON_SEND		0x00002000
#define	MODE_ALLOW_BAD_FRAMES		0x00000800
#define	MODE_NO_CRC			0x00000400
#define	MODE_NO_FRAME_CRACKING		0x00000200
#define	MODE_WORD_SWAP_FRAME		0x00000020
#define	MODE_BYTE_SWAP_FRAME		0x00000010
#define	MODE_WORD_SWAP_NONFRAME		0x00000004
#define	MODE_BYTE_SWAP_NONFRAME		0x00000002
#define	MODE_UPDATE_ON_COAL_ONLY	0x00000001

/*
 * Miscellaneous Configuration Register
 *
 * This contains various bits relating to power control (which differ
 * among different members of the chip family), but the important bits
 * for our purposes are the RESET bit and the Timer Prescaler field.
 *
 * The RESET bit in this register serves to reset the whole chip, even
 * including the PCI interface(!)  Once it's set, the chip will not
 * respond to ANY accesses -- not even CONFIG space -- until the reset
 * completes internally.  According to the PRM, this should take less
 * than 100us.  Any access during this period will get a bus error.
 *
 * The Timer Prescaler field must be programmed so that the timer period
 * is as near as possible to 1us.  The value in this field should be
 * the Core Clock frequency in MHz minus 1.  From my reading of the PRM,
 * the Core Clock should always be 66MHz (independently of the bus speed,
 * at least for PCI rather than PCI-X), so this register must be set to
 * the value 0x82 ((66-1) << 1).
 */
#define	CORE_CLOCK_MHZ			66
#define	MISC_CONFIG_REG			0x6804
#define	MISC_CONFIG_GRC_RESET_DISABLE   0x20000000
#define	MISC_CONFIG_GPHY_POWERDOWN_OVERRIDE 0x04000000
#define	MISC_CONFIG_POWERDOWN		0x00100000
#define	MISC_CONFIG_POWER_STATE		0x00060000
#define	MISC_CONFIG_PRESCALE_MASK	0x000000fe
#define	MISC_CONFIG_RESET_BIT		0x00000001
#define	MISC_CONFIG_DEFAULT		(((CORE_CLOCK_MHZ)-1) << 1)
#define	MISC_CONFIG_EPHY_IDDQ		0x00200000

/*
 * Miscellaneous Local Control Register (MLCR)
 */
#define	MISC_LOCAL_CONTROL_REG		0x6808

#define	MLCR_PCI_CTRL_SELECT		0x10000000
#define	MLCR_LEGACY_PCI_MODE		0x08000000
#define	MLCR_AUTO_SEEPROM_ACCESS	0x01000000
#define	MLCR_SSRAM_CYCLE_DESELECT	0x00800000
#define	MLCR_SSRAM_TYPE			0x00400000
#define	MLCR_BANK_SELECT		0x00200000

#define	MLCR_SRAM_SIZE_16M		0x00180000
#define	MLCR_SRAM_SIZE_8M		0x00140000
#define	MLCR_SRAM_SIZE_4M		0x00100000
#define	MLCR_SRAM_SIZE_2M		0x000c0000
#define	MLCR_SRAM_SIZE_1M		0x00080000
#define	MLCR_SRAM_SIZE_512K		0x00040000
#define	MLCR_SRAM_SIZE_256K		0x00000000
#define	MLCR_SRAM_SIZE_MASK		0x001c0000

#define	MLCR_ENABLE_EXTERNAL_MEMORY	0x00020000
#define	MLCR_MISC_PINS_OUTPUT_2		0x00010000

#define	MLCR_MISC_PINS_OUTPUT_1		0x00008000
#define	MLCR_MISC_PINS_OUTPUT_0		0x00004000
#define	MLCR_MISC_PINS_OUTPUT_ENABLE_2	0x00002000
#define	MLCR_MISC_PINS_OUTPUT_ENABLE_1	0x00001000

#define	MLCR_MISC_PINS_OUTPUT_ENABLE_0	0x00000800
#define	MLCR_MISC_PINS_INPUT_2		0x00000400	/* R/O	*/
#define	MLCR_MISC_PINS_INPUT_1		0x00000200	/* R/O	*/
#define	MLCR_MISC_PINS_INPUT_0		0x00000100	/* R/O	*/

#define	MLCR_GPIO_OUTPUT3		0x00000080
#define	MLCR_GPIO_OE3			0x00000040
#define	MLCR_USE_EXT_SIG_DETECT		0x00000020	/* 5714/5780 only */
#define	MLCR_GPIO_INPUT3		0x00000020
#define	MLCR_GPIO_UART_SEL		0x00000010	/* 5755 only */
#define	MLCR_USE_SIG_DETECT		0x00000010	/* 5714/5780 only */

#define	MLCR_INT_ON_ATTN		0x00000008	/* R/W	*/
#define	MLCR_SET_INT			0x00000004	/* W/O	*/
#define	MLCR_CLR_INT			0x00000002	/* W/O	*/
#define	MLCR_INTA_STATE			0x00000001	/* R/O	*/

/*
 * This value defines all GPIO bits as INPUTS, but sets their default
 * values as outputs to HIGH, on the assumption that external circuits
 * (if any) will probably be active-LOW with passive pullups.
 *
 * The Claymore blade uses GPIO1 to control writing to the SEEPROM in
 * just this fashion.  It has to be set as an OUTPUT and driven LOW to
 * enable writing.  Otherwise, the SEEPROM is protected.
 */
#define	MLCR_DEFAULT			(MLCR_AUTO_SEEPROM_ACCESS | \
					 MLCR_MISC_PINS_OUTPUT_2  | \
					 MLCR_MISC_PINS_OUTPUT_1  | \
					 MLCR_MISC_PINS_OUTPUT_0)

#define	MLCR_DEFAULT_5714		(MLCR_PCI_CTRL_SELECT     | \
					 MLCR_LEGACY_PCI_MODE     | \
					 MLCR_AUTO_SEEPROM_ACCESS | \
					 MLCR_MISC_PINS_OUTPUT_2  | \
					 MLCR_MISC_PINS_OUTPUT_1  | \
					 MLCR_MISC_PINS_OUTPUT_0  | \
					 MLCR_USE_SIG_DETECT)

#define	MLCR_DEFAULT_5717		(MLCR_AUTO_SEEPROM_ACCESS)

/*
 * Serial EEPROM Data/Address Registers (auto-access mode)
 */
#define	SERIAL_EEPROM_DATA_REG		0x683c
#define	SERIAL_EEPROM_ADDRESS_REG	0x6838
#define	SEEPROM_ACCESS_READ		0x80000000
#define	SEEPROM_ACCESS_WRITE		0x00000000
#define	SEEPROM_ACCESS_COMPLETE		0x40000000
#define	SEEPROM_ACCESS_RESET		0x20000000
#define	SEEPROM_ACCESS_DEVID_MASK	0x1c000000
#define	SEEPROM_ACCESS_START		0x02000000
#define	SEEPROM_ACCESS_HALFCLOCK_MASK	0x01ff0000
#define	SEEPROM_ACCESS_ADDRESS_MASK	0x0000fffc

#define	SEEPROM_ACCESS_DEVID_SHIFT	26		/* bits	*/
#define	SEEPROM_ACCESS_HALFCLOCK_SHIFT	16		/* bits */
#define	SEEPROM_ACCESS_ADDRESS_SIZE	16		/* bits	*/

#define	SEEPROM_ACCESS_HALFCLOCK_340KHZ	0x0060		/* 340kHz */
#define	SEEPROM_ACCESS_INIT		0x20600000	/* reset+clock	*/

/*
 * "Linearised" address mask, treating multiple devices as consecutive
 */
#define	SEEPROM_DEV_AND_ADDR_MASK	0x0007fffc	/* 8x64k devices */

/*
 * Non-Volatile Memory Interface Registers
 * Note: on chips that support the flash interface (5702+), flash is the
 * default and the legacy seeprom interface must be explicitly enabled
 * if required. On older chips (5700/01), SEEPROM is the default (and
 * only) non-volatile memory available, and these registers don't exist!
 */
#define	NVM_FLASH_CMD_REG		0x7000
#define	NVM_FLASH_CMD_LAST		0x00000100
#define	NVM_FLASH_CMD_FIRST		0x00000080
#define	NVM_FLASH_CMD_RD		0x00000000
#define	NVM_FLASH_CMD_WR		0x00000020
#define	NVM_FLASH_CMD_DOIT		0x00000010
#define	NVM_FLASH_CMD_DONE		0x00000008

#define	NVM_FLASH_WRITE_REG		0x7008
#define	NVM_FLASH_READ_REG		0x7010

#define	NVM_FLASH_ADDR_REG		0x700c
#define	NVM_FLASH_ADDR_MASK		0x00fffffc

#define	NVM_CONFIG1_REG			0x7014
#define	NVM_CFG1_LEGACY_SEEPROM_MODE	0x80000000
#define	NVM_CFG1_SEE_CLK_DIV_MASK	0x003ff800
#define	NVM_CFG1_SPI_CLK_DIV_MASK	0x00000780
#define	NVM_CFG1_BUFFERED_MODE		0x00000002
#define	NVM_CFG1_FLASH_MODE		0x00000001

#define	NVM_SW_ARBITRATION_REG		0x7020
#define	NVM_READ_REQ3			0x00008000
#define	NVM_READ_REQ2			0x00004000
#define	NVM_READ_REQ1			0x00002000
#define	NVM_READ_REQ0			0x00001000
#define	NVM_WON_REQ3			0x00000800
#define	NVM_WON_REQ2			0x00000400
#define	NVM_WON_REQ1			0x00000200
#define	NVM_WON_REQ0			0x00000100
#define	NVM_RESET_REQ3			0x00000080
#define	NVM_RESET_REQ2			0x00000040
#define	NVM_RESET_REQ1			0x00000020
#define	NVM_RESET_REQ0			0x00000010
#define	NVM_SET_REQ3			0x00000008
#define	NVM_SET_REQ2			0x00000004
#define	NVM_SET_REQ1			0x00000002
#define	NVM_SET_REQ0			0x00000001

#define	EEPROM_MAGIC			0x669955aa
#define	EEPROM_MAGIC_FW			0xa5000000
#define	EEPROM_MAGIC_FW_MSK		0xff000000
#define	EEPROM_SB_FORMAT_MASK		0x00e00000
#define	EEPROM_SB_FORMAT_1		0x00200000
#define	EEPROM_SB_REVISION_MASK		0x001f0000
#define	EEPROM_SB_REVISION_0		0x00000000
#define	EEPROM_SB_REVISION_2		0x00020000
#define	EEPROM_SB_REVISION_3		0x00030000
#define	EEPROM_SB_REVISION_4		0x00040000
#define	EEPROM_SB_REVISION_5		0x00050000
#define	EEPROM_SB_REVISION_6		0x00060000
#define	EEPROM_MAGIC_HW			0xabcd
#define	EEPROM_MAGIC_HW_MSK		0xffff

#define	NVM_DIR_START		0x18
#define	NVM_DIR_END		0x78
#define	NVM_DIRENT_SIZE		0xc
#define	NVM_DIRTYPE_SHIFT	24
#define	NVM_DIRTYPE_LENMSK	0x003fffff
#define	NVM_DIRTYPE_ASFINI	1
#define	NVM_DIRTYPE_EXTVPD	20
#define	NVM_PTREV_BCVER		0x94
#define	NVM_BCVER_MAJMSK	0x0000ff00
#define	NVM_BCVER_MAJSFT	8
#define	NVM_BCVER_MINMSK	0x000000ff

/*
 * NVM access register
 * Applicable to BCM5721,BCM5751,BCM5752,BCM5714
 * and BCM5715 only.
 */
#define	NVM_ACCESS_REG			0x7024
#define	NVM_WRITE_ENABLE		0x00000002
#define	NVM_ACCESS_ENABLE		0x00000001

/*
 * TLP Control Register
 * Applicable to BCM5721 and BCM5751 only
 */
#define	TLP_CONTROL_REG			0x7c00
#define	TLP_DATA_FIFO_PROTECT		0x02000000

/*
 * PHY Test Control Register
 * Applicable to BCM5721 and BCM5751 only
 */
#define	PHY_TEST_CTRL_REG		0x7e2c
#define	PHY_PCIE_SCRAM_MODE		0x20
#define	PHY_PCIE_LTASS_MODE		0x40

/*
 * The internal firmware expects a certain layout of the non-volatile
 * memory (if fitted), and will check for it during startup, and use the
 * contents to initialise various internal parameters if it looks good.
 *
 * The offsets and field definitions below refer to where to find some
 * important values, and how to interpret them ...
 */
#define	NVMEM_DATA_MAC_ADDRESS		0x007c		/* 8 bytes	*/
#define	NVMEM_DATA_MAC_ADDRESS_5906	0x0010		/* 8 bytes	*/

/*
 * Vendor-specific MII registers
 */

#define	MII_MMD_CTRL			0x0d /* MMD Access Control register */
#define	MII_MMD_CTRL_DATA_NOINC		0x4000
#define	MII_MMD_ADDRESS_DATA		0x0e /* MMD Address Data register */

#define	MII_RXR_COUNTERS		0x14 /* Local/Remote Rx Counts */
#define	MII_DSP_RW_PORT			0x15 /* DSP read/write port */
#define	MII_DSP_CONTROL			0x16 /* DSP control register */
#define	MII_DSP_ADDRESS			0x17 /* DSP address register */

#define	MII_DSP_TAP26			0x001a
#define	MII_DSP_TAP26_ALNOKO		0x0001
#define	MII_DSP_TAP26_RMRXSTO		0x0002
#define	MII_DSP_TAP26_OPCSINPT		0x0004

#define	MII_DSP_CH34TP2			0x4022
#define	MII_DSP_CH34TP2_HIBW01		0x017b

#define	MII_EXT_CONTROL			MII_VENDOR(0)
#define	MII_EXT_STATUS			MII_VENDOR(1)
#define	MII_RCV_ERR_COUNT		MII_VENDOR(2)
#define	MII_FALSE_CARR_COUNT		MII_VENDOR(3)
#define	MII_RCV_NOT_OK_COUNT		MII_VENDOR(4)
#define	MII_AUX_CONTROL			MII_VENDOR(8)
#define	MII_AUX_STATUS			MII_VENDOR(9)
#define	MII_INTR_STATUS			MII_VENDOR(10)
#define	MII_INTR_MASK			MII_VENDOR(11)
#define	MII_HCD_STATUS			MII_VENDOR(13)

#define	MII_MAXREG			MII_VENDOR(15)	/* 31, 0x1f	*/

/*
 * Bits in the MII_EXT_CONTROL register
 */
#define	MII_EXT_CTRL_INTERFACE_TBI	0x8000
#define	MII_EXT_CTRL_DISABLE_AUTO_MDIX	0x4000
#define	MII_EXT_CTRL_DISABLE_TRANSMIT	0x2000
#define	MII_EXT_CTRL_DISABLE_INTERRUPT	0x1000
#define	MII_EXT_CTRL_FORCE_INTERRUPT	0x0800
#define	MII_EXT_CTRL_BYPASS_4B5B	0x0400
#define	MII_EXT_CTRL_BYPASS_SCRAMBLER	0x0200
#define	MII_EXT_CTRL_BYPASS_MLT3	0x0100
#define	MII_EXT_CTRL_BYPASS_RX_ALIGN	0x0080
#define	MII_EXT_CTRL_RESET_SCRAMBLER	0x0040
#define	MII_EXT_CTRL_LED_TRAFFIC_MODE	0x0020
#define	MII_EXT_CTRL_FORCE_LEDS_ON	0x0010
#define	MII_EXT_CTRL_FORCE_LEDS_OFF	0x0008
#define	MII_EXT_CTRL_EXTEND_TX_IPG	0x0004
#define	MII_EXT_CTRL_3LINK_LED_MODE	0x0002
#define	MII_EXT_CTRL_FIFO_ELASTICITY	0x0001

/*
 * Bits in the MII_EXT_STATUS register
 */
#define	MII_EXT_STAT_S3MII_FIFO_ERROR	0x8000
#define	MII_EXT_STAT_WIRESPEED_DOWNGRADE 0x4000
#define	MII_EXT_STAT_MDIX_STATE		0x2000
#define	MII_EXT_STAT_INTERRUPT_STATUS	0x1000
#define	MII_EXT_STAT_REMOTE_RCVR_STATUS	0x0800
#define	MII_EXT_STAT_LOCAL_RDVR_STATUS	0x0400
#define	MII_EXT_STAT_DESCRAMBLER_LOCKED	0x0200
#define	MII_EXT_STAT_LINK_STATUS	0x0100
#define	MII_EXT_STAT_CRC_ERROR		0x0080
#define	MII_EXT_STAT_CARR_EXT_ERROR	0x0040
#define	MII_EXT_STAT_BAD_SSD_ERROR	0x0020
#define	MII_EXT_STAT_BAD_ESD_ERROR	0x0010
#define	MII_EXT_STAT_RECEIVE_ERROR	0x0008
#define	MII_EXT_STAT_TRANSMIT_ERROR	0x0004
#define	MII_EXT_STAT_LOCK_ERROR		0x0002
#define	MII_EXT_STAT_MLT3_CODE_ERROR	0x0001

/*
 * The AUX CONTROL register is seriously weird!
 *
 * It hides (up to) eight 'shadow' registers.  When writing, which one
 * of them is written is determined by the low-order bits of the data
 * written(!), but when reading, which one is read is determined by the
 * value previously written to (part of) one of the shadow registers!!!
 */

/*
 * Shadow register numbers
 */
#define	MII_AUX_CTRL_NORMAL		0
#define	MII_AUX_CTRL_10BASE_T		1
#define	MII_AUX_CTRL_POWER		2
#define	MII_AUX_CTRL_TEST_1		4
#define	MII_AUX_CTRL_MISC		7

/*
 * Selected bits in some of the shadow registers ...
 */
#define	MII_AUX_CTRL_NORM_EXT_LOOPBACK	0x8000
#define	MII_AUX_CTRL_NORM_LONG_PKTS	0x4000
#define	MII_AUX_CTRL_NORM_EDGE_CTRL	0x3000
#define	MII_AUX_CTRL_NORM_TX_MODE	0x0400
#define	MII_AUX_CTRL_NORM_CABLE_TEST	0x0008

#define	MII_AUX_CTRL_TEST_TX_HALF	0x0008

#define	MII_AUX_CTRL_MISC_WRITE_ENABLE	0x8000
#define	MII_AUX_CTRL_MISC_WIRE_SPEED	0x0010

#define	MII_AUX_CTRL_TX_6DB		0x0400
#define	MII_AUX_CTRL_SMDSP_ENA		0x0800

/*
 * Write this value to the AUX control register
 * to select which shadow register will be read
 */
#define	MII_AUX_CTRL_SHADOW_READ(x)	(((x) << 12) | MII_AUX_CTRL_MISC)

/*
 * Bits in the MII_AUX_STATUS register
 */
#define	MII_AUX_STATUS_MODE_MASK	0x0700
#define	MII_AUX_STATUS_MODE_1000_F	0x0700
#define	MII_AUX_STATUS_MODE_1000_H	0x0600
#define	MII_AUX_STATUS_MODE_100_F	0x0500
#define	MII_AUX_STATUS_MODE_100_4	0x0400
#define	MII_AUX_STATUS_MODE_100_H	0x0300
#define	MII_AUX_STATUS_MODE_10_F	0x0200
#define	MII_AUX_STATUS_MODE_10_H	0x0100
#define	MII_AUX_STATUS_MODE_NONE	0x0000
#define	MII_AUX_STATUS_MODE_SHIFT	8

#define	MII_AUX_STATUS_PAR_FAULT	0x0080
#define	MII_AUX_STATUS_REM_FAULT	0x0040
#define	MII_AUX_STATUS_LP_ANEG_ABLE	0x0010
#define	MII_AUX_STATUS_LP_NP_ABLE	0x0008

#define	MII_AUX_STATUS_LINKUP		0x0004
#define	MII_AUX_STATUS_RX_PAUSE		0x0002
#define	MII_AUX_STATUS_TX_PAUSE		0x0001

#define	MII_AUX_STATUS_SPEED_IND_5906	0x0008
#define	MII_AUX_STATUS_NEG_ENABLED_5906		0x0002
#define	MII_AUX_STATUS_DUPLEX_IND_5906		0x0001

/*
 * Bits in the MII_INTR_STATUS and MII_INTR_MASK registers
 */
#define	MII_INTR_RMT_RX_STATUS_CHANGE	0x0020
#define	MII_INTR_LCL_RX_STATUS_CHANGE	0x0010
#define	MII_INTR_LINK_DUPLEX_CHANGE	0x0008
#define	MII_INTR_LINK_SPEED_CHANGE	0x0004
#define	MII_INTR_LINK_STATUS_CHANGE	0x0002


/*
 * Third section:
 * 	Hardware-defined data structures
 *
 * Note that the chip is naturally BIG-endian, so, for a big-endian
 * host, the structures defined below match those described in the PRM.
 * For little-endian hosts, some structures have to be swapped around.
 */

#if	!defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
#error	Host endianness not defined
#endif

/*
 * Architectural constants: absolute maximum numbers of each type of ring
 */
#ifdef BGE_EXT_MEM
#define	BGE_SEND_RINGS_MAX		16	/* only with ext mem	*/
#else
#define	BGE_SEND_RINGS_MAX		4
#endif
#define	BGE_SEND_RINGS_MAX_5705		1
#define	BGE_RECV_RINGS_MAX		16
#define	BGE_RECV_RINGS_MAX_5705		1
#define	BGE_BUFF_RINGS_MAX		3	/* jumbo/std/mini (mini	*/
						/* only with ext mem)	*/

#define	BGE_SEND_SLOTS_MAX		512
#define	BGE_STD_SLOTS_MAX		512
#define	BGE_JUMBO_SLOTS_MAX		256
#define	BGE_MINI_SLOTS_MAX		1024
#define	BGE_RECV_SLOTS_MAX		2048
#define	BGE_RECV_SLOTS_5705		512
#define	BGE_RECV_SLOTS_5782		512
#define	BGE_RECV_SLOTS_5721		512

/*
 * Hardware-defined Ring Control Block
 */
typedef struct {
	uint64_t	host_ring_addr;
#ifdef	_BIG_ENDIAN
	uint16_t	max_len;
	uint16_t	flags;
	uint32_t	nic_ring_addr;
#else
	uint32_t	nic_ring_addr;
	uint16_t	flags;
	uint16_t	max_len;
#endif	/* _BIG_ENDIAN */
} bge_rcb_t;

#define	RCB_FLAG_USE_EXT_RCV_BD		0x0001
#define	RCB_FLAG_RING_DISABLED		0x0002

/*
 * Hardware-defined Send Buffer Descriptor
 */
typedef struct {
	uint64_t	host_buf_addr;
#ifdef	_BIG_ENDIAN
	uint16_t	len;
	uint16_t	flags;
	uint16_t	reserved;
	uint16_t	vlan_tci;
#else
	uint16_t	vlan_tci;
	uint16_t	reserved;
	uint16_t	flags;
	uint16_t	len;
#endif	/* _BIG_ENDIAN */
} bge_sbd_t;

#define	SBD_FLAG_TCP_UDP_CKSUM		0x0001
#define	SBD_FLAG_IP_CKSUM		0x0002
#define	SBD_FLAG_PACKET_END		0x0004
#define	SBD_FLAG_IP_FRAG		0x0008
#define	SBD_FLAG_JMB_PKT		0x0008
#define	SBD_FLAG_IP_FRAG_END		0x0010

#define	SBD_FLAG_VLAN_TAG		0x0040
#define	SBD_FLAG_COAL_NOW		0x0080
#define	SBD_FLAG_CPU_PRE_DMA		0x0100
#define	SBD_FLAG_CPU_POST_DMA		0x0200

#define	SBD_FLAG_INSERT_SRC_ADDR	0x1000
#define	SBD_FLAG_CHOOSE_SRC_ADDR	0x6000
#define	SBD_FLAG_DONT_GEN_CRC		0x8000

/*
 * Hardware-defined Receive Buffer Descriptor
 */
typedef struct {
	uint64_t	host_buf_addr;
#ifdef	_BIG_ENDIAN
	uint16_t	index;
	uint16_t	len;
	uint16_t	type;
	uint16_t	flags;
	uint16_t	ip_cksum;
	uint16_t	tcp_udp_cksum;
	uint16_t	error_flag;
	uint16_t	vlan_tci;
	uint32_t	reserved;
	uint32_t	opaque;
#else
	uint16_t	flags;
	uint16_t	type;
	uint16_t	len;
	uint16_t	index;
	uint16_t	vlan_tci;
	uint16_t	error_flag;
	uint16_t	tcp_udp_cksum;
	uint16_t	ip_cksum;
	uint32_t	opaque;
	uint32_t	reserved;
#endif	/* _BIG_ENDIAN */
} bge_rbd_t;

#define	RBD_FLAG_STD_RING		0x0000
#define	RBD_FLAG_PACKET_END		0x0004

#define	RBD_FLAG_JUMBO_RING		0x0020
#define	RBD_FLAG_VLAN_TAG		0x0040

#define	RBD_FLAG_FRAME_HAS_ERROR	0x0400
#define	RBD_FLAG_MINI_RING		0x0800
#define	RBD_FLAG_IP_CHECKSUM		0x1000
#define	RBD_FLAG_TCP_UDP_CHECKSUM	0x2000
#define	RBD_FLAG_TCP_UDP_IS_TCP		0x4000

#define	RBD_FLAG_DEFAULT		0x0000

#define	RBD_ERROR_BAD_CRC		0x00010000
#define	RBD_ERROR_COLL_DETECT		0x00020000
#define	RBD_ERROR_LINK_LOST		0x00040000
#define	RBD_ERROR_PHY_DECODE_ERR	0x00080000
#define	RBD_ERROR_ODD_NIBBLE_RX_MII	0x00100000
#define	RBD_ERROR_MAC_ABORT		0x00200000
#define	RBD_ERROR_LEN_LESS_64		0x00400000
#define	RBD_ERROR_TRUNC_NO_RES		0x00800000
#define	RBD_ERROR_GIANT_PKT_RCVD	0x01000000

/*
 * Hardware-defined Status Block,Size of status block
 * is actually 0x50 bytes.Use 0x80 bytes for cache line
 * alignment.For BCM5705/5788/5721/5751/5752/5714
 * and 5715,there is only 1 recv and send ring index,but
 * driver defined 16 indexs here,please pay attention only
 * one ring is enabled in these chipsets.
 */
typedef struct {
	uint64_t	flags_n_tag;
	uint16_t	buff_cons_index[4];
	struct {
#ifdef	_BIG_ENDIAN
		uint16_t	send_cons_index;
		uint16_t	recv_prod_index;
#else
		uint16_t	recv_prod_index;
		uint16_t	send_cons_index;
#endif	/* _BIG_ENDIAN */
	} index[16];
} bge_status_t;

/*
 * Hardware-defined Receive BD Rule
 */
typedef struct {
	uint32_t	control;
	uint32_t	mask_value;
} bge_recv_rule_t;

/*
 * This describes which sub-rule slots are used by a particular rule.
 */
typedef struct {
	int		start;
	int		count;
} bge_rule_info_t;

/*
 * Indexes into the <buff_cons_index> array
 */
#ifdef	_BIG_ENDIAN
#define	STATUS_STD_BUFF_CONS_INDEX	0
#define	STATUS_JUMBO_BUFF_CONS_INDEX	1
#define	STATUS_MINI_BUFF_CONS_INDEX	3
#define	SEND_INDEX_P(bsp, ring)	(&(bsp)->index[(ring)^0].send_cons_index)
#define	RECV_INDEX_P(bsp, ring)	(&(bsp)->index[(ring)^0].recv_prod_index)
#else
#define	STATUS_STD_BUFF_CONS_INDEX	3
#define	STATUS_JUMBO_BUFF_CONS_INDEX	2
#define	STATUS_MINI_BUFF_CONS_INDEX	0
#define	SEND_INDEX_P(bsp, ring)	(&(bsp)->index[(ring)^1].send_cons_index)
#define	RECV_INDEX_P(bsp, ring)	(&(bsp)->index[(ring)^1].recv_prod_index)
#endif	/* _BIG_ENDIAN */

/*
 * Bits in the <flags_n_tag> word
 */
#define	STATUS_FLAG_UPDATED		0x0000000100000000ull
#define	STATUS_FLAG_LINK_CHANGED	0x0000000200000000ull
#define	STATUS_FLAG_ERROR		0x0000000400000000ull
#define	STATUS_TAG_MASK			0x00000000000000FFull

/*
 * The tag from the status block is fed back to Interrupt Mailbox 0
 * (INTERRUPT_MBOX_0_REG, 0x0200) after servicing an interrupt.  This
 * lets the chip know what updates have been processed, so it can
 * reassert its interrupt if more updates have occurred since.
 *
 * These macros extract the tag from the <flags_n_tag> word, shift
 * it to the proper position in the Mailbox register, and provide
 * the complete values to write to INTERRUPT_MBOX_0_REG to disable
 * or enable interrupts
 */
#define	STATUS_TAG(fnt)			((fnt) & STATUS_TAG_MASK)
#define	INTERRUPT_TAG(fnt)		(STATUS_TAG(fnt) << 24)
#define	INTERRUPT_MBOX_DISABLE(fnt)	(INTERRUPT_TAG(fnt) | 1)
#define	INTERRUPT_MBOX_ENABLE(fnt)	(INTERRUPT_TAG(fnt) | 0)

/*
 * Hardware-defined Statistics Block Offsets
 *
 * These are given in the manual as addresses in NIC memory, starting
 * from the NIC statistics area base address of 0x300; but here we
 * convert them into indexes into an array of (uint64_t)s, so we can
 * use them directly for accessing the copy of the statistics block
 * that the chip DMAs into main memory ...
 */

#define	KS_BASE				0x300
#define	KS_ADDR(x)			(((x)-KS_BASE)/sizeof (uint64_t))

typedef enum {
	KS_ifHCInOctets = KS_ADDR(0x400),
	KS_etherStatsFragments = KS_ADDR(0x410),
	KS_ifHCInUcastPkts,
	KS_ifHCInMulticastPkts,
	KS_ifHCInBroadcastPkts,
	KS_dot3StatsFCSErrors,
	KS_dot3StatsAlignmentErrors,
	KS_xonPauseFramesReceived,
	KS_xoffPauseFramesReceived,
	KS_macControlFramesReceived,
	KS_xoffStateEntered,
	KS_dot3StatsFrameTooLongs,
	KS_etherStatsJabbers,
	KS_etherStatsUndersizePkts,
	KS_inRangeLengthError,
	KS_outRangeLengthError,
	KS_etherStatsPkts64Octets,
	KS_etherStatsPkts65to127Octets,
	KS_etherStatsPkts128to255Octets,
	KS_etherStatsPkts256to511Octets,
	KS_etherStatsPkts512to1023Octets,
	KS_etherStatsPkts1024to1518Octets,
	KS_etherStatsPkts1519to2047Octets,
	KS_etherStatsPkts2048to4095Octets,
	KS_etherStatsPkts4096to8191Octets,
	KS_etherStatsPkts8192to9022Octets,

	KS_ifHCOutOctets = KS_ADDR(0x600),
	KS_etherStatsCollisions = KS_ADDR(0x610),
	KS_outXonSent,
	KS_outXoffSent,
	KS_flowControlDone,
	KS_dot3StatsInternalMacTransmitErrors,
	KS_dot3StatsSingleCollisionFrames,
	KS_dot3StatsMultipleCollisionFrames,
	KS_dot3StatsDeferredTransmissions,
	KS_dot3StatsExcessiveCollisions = KS_ADDR(0x658),
	KS_dot3StatsLateCollisions,
	KS_dot3Collided2Times,
	KS_dot3Collided3Times,
	KS_dot3Collided4Times,
	KS_dot3Collided5Times,
	KS_dot3Collided6Times,
	KS_dot3Collided7Times,
	KS_dot3Collided8Times,
	KS_dot3Collided9Times,
	KS_dot3Collided10Times,
	KS_dot3Collided11Times,
	KS_dot3Collided12Times,
	KS_dot3Collided13Times,
	KS_dot3Collided14Times,
	KS_dot3Collided15Times,
	KS_ifHCOutUcastPkts,
	KS_ifHCOutMulticastPkts,
	KS_ifHCOutBroadcastPkts,
	KS_dot3StatsCarrierSenseErrors,
	KS_ifOutDiscards,
	KS_ifOutErrors,

	KS_COSIfHCInPkts_1 = KS_ADDR(0x800),		/* [16]	*/
	KS_COSIfHCInPkts_2,
	KS_COSIfHCInPkts_3,
	KS_COSIfHCInPkts_4,
	KS_COSIfHCInPkts_5,
	KS_COSIfHCInPkts_6,
	KS_COSIfHCInPkts_7,
	KS_COSIfHCInPkts_8,
	KS_COSIfHCInPkts_9,
	KS_COSIfHCInPkts_10,
	KS_COSIfHCInPkts_11,
	KS_COSIfHCInPkts_12,
	KS_COSIfHCInPkts_13,
	KS_COSIfHCInPkts_14,
	KS_COSIfHCInPkts_15,
	KS_COSIfHCInPkts_16,
	KS_COSFramesDroppedDueToFilters,
	KS_nicDmaWriteQueueFull,
	KS_nicDmaWriteHighPriQueueFull,
	KS_nicNoMoreRxBDs,
	KS_ifInDiscards,
	KS_ifInErrors,
	KS_nicRecvThresholdHit,

	KS_COSIfHCOutPkts_1 = KS_ADDR(0x900),		/* [16]	*/
	KS_COSIfHCOutPkts_2,
	KS_COSIfHCOutPkts_3,
	KS_COSIfHCOutPkts_4,
	KS_COSIfHCOutPkts_5,
	KS_COSIfHCOutPkts_6,
	KS_COSIfHCOutPkts_7,
	KS_COSIfHCOutPkts_8,
	KS_COSIfHCOutPkts_9,
	KS_COSIfHCOutPkts_10,
	KS_COSIfHCOutPkts_11,
	KS_COSIfHCOutPkts_12,
	KS_COSIfHCOutPkts_13,
	KS_COSIfHCOutPkts_14,
	KS_COSIfHCOutPkts_15,
	KS_COSIfHCOutPkts_16,
	KS_nicDmaReadQueueFull,
	KS_nicDmaReadHighPriQueueFull,
	KS_nicSendDataCompQueueFull,
	KS_nicRingSetSendProdIndex,
	KS_nicRingStatusUpdate,
	KS_nicInterrupts,
	KS_nicAvoidedInterrupts,
	KS_nicSendThresholdHit,

	KS_STATS_SIZE = KS_ADDR(0xb00)
} bge_stats_offset_t;

/*
 * Hardware-defined Statistics Block
 *
 * Another view of the statistic block, as a array and a structure ...
 */

typedef union {
	uint64_t		a[KS_STATS_SIZE];
	struct {
		uint64_t	spare1[(0x400-0x300)/sizeof (uint64_t)];

		uint64_t	ifHCInOctets;		/* 0x0400	*/
		uint64_t	spare2[1];
		uint64_t	etherStatsFragments;
		uint64_t	ifHCInUcastPkts;
		uint64_t	ifHCInMulticastPkts;
		uint64_t	ifHCInBroadcastPkts;
		uint64_t	dot3StatsFCSErrors;
		uint64_t	dot3StatsAlignmentErrors;
		uint64_t	xonPauseFramesReceived;
		uint64_t	xoffPauseFramesReceived;
		uint64_t	macControlFramesReceived;
		uint64_t	xoffStateEntered;
		uint64_t	dot3StatsFrameTooLongs;
		uint64_t	etherStatsJabbers;
		uint64_t	etherStatsUndersizePkts;
		uint64_t	inRangeLengthError;
		uint64_t	outRangeLengthError;
		uint64_t	etherStatsPkts64Octets;
		uint64_t	etherStatsPkts65to127Octets;
		uint64_t	etherStatsPkts128to255Octets;
		uint64_t	etherStatsPkts256to511Octets;
		uint64_t	etherStatsPkts512to1023Octets;
		uint64_t	etherStatsPkts1024to1518Octets;
		uint64_t	etherStatsPkts1519to2047Octets;
		uint64_t	etherStatsPkts2048to4095Octets;
		uint64_t	etherStatsPkts4096to8191Octets;
		uint64_t	etherStatsPkts8192to9022Octets;
		uint64_t	spare3[(0x600-0x4d8)/sizeof (uint64_t)];

		uint64_t	ifHCOutOctets;		/* 0x0600	*/
		uint64_t	spare4[1];
		uint64_t	etherStatsCollisions;
		uint64_t	outXonSent;
		uint64_t	outXoffSent;
		uint64_t	flowControlDone;
		uint64_t	dot3StatsInternalMacTransmitErrors;
		uint64_t	dot3StatsSingleCollisionFrames;
		uint64_t	dot3StatsMultipleCollisionFrames;
		uint64_t	dot3StatsDeferredTransmissions;
		uint64_t	spare5[1];
		uint64_t	dot3StatsExcessiveCollisions;
		uint64_t	dot3StatsLateCollisions;
		uint64_t	dot3Collided2Times;
		uint64_t	dot3Collided3Times;
		uint64_t	dot3Collided4Times;
		uint64_t	dot3Collided5Times;
		uint64_t	dot3Collided6Times;
		uint64_t	dot3Collided7Times;
		uint64_t	dot3Collided8Times;
		uint64_t	dot3Collided9Times;
		uint64_t	dot3Collided10Times;
		uint64_t	dot3Collided11Times;
		uint64_t	dot3Collided12Times;
		uint64_t	dot3Collided13Times;
		uint64_t	dot3Collided14Times;
		uint64_t	dot3Collided15Times;
		uint64_t	ifHCOutUcastPkts;
		uint64_t	ifHCOutMulticastPkts;
		uint64_t	ifHCOutBroadcastPkts;
		uint64_t	dot3StatsCarrierSenseErrors;
		uint64_t	ifOutDiscards;
		uint64_t	ifOutErrors;
		uint64_t	spare6[(0x800-0x708)/sizeof (uint64_t)];

		uint64_t	COSIfHCInPkts[16];	/* 0x0800	*/
		uint64_t	COSFramesDroppedDueToFilters;
		uint64_t	nicDmaWriteQueueFull;
		uint64_t	nicDmaWriteHighPriQueueFull;
		uint64_t	nicNoMoreRxBDs;
		uint64_t	ifInDiscards;
		uint64_t	ifInErrors;
		uint64_t	nicRecvThresholdHit;
		uint64_t	spare7[(0x900-0x8b8)/sizeof (uint64_t)];

		uint64_t	COSIfHCOutPkts[16];	/* 0x0900	*/
		uint64_t	nicDmaReadQueueFull;
		uint64_t	nicDmaReadHighPriQueueFull;
		uint64_t	nicSendDataCompQueueFull;
		uint64_t	nicRingSetSendProdIndex;
		uint64_t	nicRingStatusUpdate;
		uint64_t	nicInterrupts;
		uint64_t	nicAvoidedInterrupts;
		uint64_t	nicSendThresholdHit;
		uint64_t	spare8[(0xb00-0x9c0)/sizeof (uint64_t)];
	} s;
} bge_statistics_t;

#define	KS_STAT_REG_SIZE	(0x1B)
#define	KS_STAT_REG_BASE	(0x800)

typedef struct {
	uint32_t	ifHCOutOctets;
	uint32_t	etherStatsCollisions;
	uint32_t	outXonSent;
	uint32_t	outXoffSent;
	uint32_t	dot3StatsInternalMacTransmitErrors;
	uint32_t	dot3StatsSingleCollisionFrames;
	uint32_t	dot3StatsMultipleCollisionFrames;
	uint32_t	dot3StatsDeferredTransmissions;
	uint32_t	dot3StatsExcessiveCollisions;
	uint32_t	dot3StatsLateCollisions;
	uint32_t	ifHCOutUcastPkts;
	uint32_t	ifHCOutMulticastPkts;
	uint32_t	ifHCOutBroadcastPkts;
	uint32_t	ifHCInOctets;
	uint32_t	etherStatsFragments;
	uint32_t	ifHCInUcastPkts;
	uint32_t	ifHCInMulticastPkts;
	uint32_t	ifHCInBroadcastPkts;
	uint32_t	dot3StatsFCSErrors;
	uint32_t	dot3StatsAlignmentErrors;
	uint32_t	xonPauseFramesReceived;
	uint32_t	xoffPauseFramesReceived;
	uint32_t	macControlFramesReceived;
	uint32_t	xoffStateEntered;
	uint32_t	dot3StatsFrameTooLongs;
	uint32_t	etherStatsJabbers;
	uint32_t	etherStatsUndersizePkts;
} bge_statistics_reg_t;


#ifdef BGE_IPMI_ASF

/*
 * Device internal memory entries
 */

#define	BGE_FIRMWARE_MAILBOX				0x0b50
#define	BGE_MAGIC_NUM_FIRMWARE_INIT_DONE		0x4b657654
#define	BGE_MAGIC_NUM_DISABLE_DMAW_ON_LINK_CHANGE	0x4861764b


#define	BGE_NIC_DATA_SIG_ADDR			0x0b54
#define	BGE_NIC_DATA_SIG			0x4b657654


#define	BGE_NIC_DATA_NIC_CFG_ADDR		0x0b58

#define	BGE_NIC_CFG_LED_MODE_TRIPLE_SPEED	0x000004
#define	BGE_NIC_CFG_LED_MODE_LINK_SPEED		0x000008
#define	BGE_NIC_CFG_LED_MODE_OPEN_DRAIN		0x000004
#define	BGE_NIC_CFG_LED_MODE_OUTPUT		0x000008
#define	BGE_NIC_CFG_LED_MODE_MASK		0x00000c

#define	BGE_NIC_CFG_PHY_TYPE_UNKNOWN		0x000000
#define	BGE_NIC_CFG_PHY_TYPE_COPPER		0x000010
#define	BGE_NIC_CFG_PHY_TYPE_FIBER		0x000020
#define	BGE_NIC_CFG_PHY_TYPE_MASK		0x000030

#define	BGE_NIC_CFG_ENABLE_WOL			0x000040
#define	BGE_NIC_CFG_ENABLE_ASF			0x000080
#define	BGE_NIC_CFG_EEPROM_WP			0x000100
#define	BGE_NIC_CFG_POWER_SAVING		0x000200
#define	BGE_NIC_CFG_SWAP_PORT			0x000800
#define	BGE_NIC_CFG_MINI_PCI			0x001000
#define	BGE_NIC_CFG_FIBER_WOL_CAPABLE		0x004000
#define	BGE_NIC_CFG_5753_12x12			0x100000


#define	BGE_NIC_DATA_FIRMWARE_VERSION		0x0b5c


#define	BGE_NIC_DATA_PHY_ID_ADDR		0x0b74
#define	BGE_NIC_PHY_ID1_MASK			0xffff0000
#define	BGE_NIC_PHY_ID2_MASK			0x0000ffff


#define	BGE_CMD_MAILBOX				0x0b78
#define	BGE_CMD_NICDRV_ALIVE			0x00000001
#define	BGE_CMD_NICDRV_PAUSE_FW			0x00000002
#define	BGE_CMD_NICDRV_IPV4ADDR_CHANGE		0x00000003
#define	BGE_CMD_NICDRV_IPV6ADDR_CHANGE		0x00000004


#define	BGE_CMD_LENGTH_MAILBOX			0x0b7c
#define	BGE_CMD_DATA_MAILBOX			0x0b80
#define	BGE_ASF_FW_STATUS_MAILBOX		0x0c00

#define	BGE_DRV_STATE_MAILBOX			0x0c04
#define	BGE_DRV_STATE_START			0x00000001
#define	BGE_DRV_STATE_START_DONE		0x80000001
#define	BGE_DRV_STATE_UNLOAD			0x00000002
#define	BGE_DRV_STATE_UNLOAD_DONE		0x80000002
#define	BGE_DRV_STATE_WOL			0x00000003
#define	BGE_DRV_STATE_SUSPEND			0x00000004


#define	BGE_FW_LAST_RESET_TYPE_MAILBOX		0x0c08
#define	BGE_FW_LAST_RESET_TYPE_WARM		0x0001
#define	BGE_FW_LAST_RESET_TYPE_COLD		0x0002


#define	BGE_MAC_ADDR_HIGH_MAILBOX		0x0c14
#define	BGE_MAC_ADDR_LOW_MAILBOX		0x0c18


/*
 * RX-RISC event register
 */
#define	RX_RISC_EVENT_REG			0x6810
#define	RRER_ASF_EVENT				0x4000

#endif /* BGE_IPMI_ASF */

/* APE registers.  Accessible through BAR1 */
#define	BGE_APE_GPIO_MSG		0x0008
#define	BGE_APE_GPIO_MSG_SHIFT		4
#define	BGE_APE_EVENT			0x000c
#define	 APE_EVENT_1			 0x00000001
#define	BGE_APE_LOCK_REQ		0x002c
#define	 APE_LOCK_REQ_DRIVER		 0x00001000
#define	BGE_APE_LOCK_GRANT		0x004c
#define	 APE_LOCK_GRANT_DRIVER		 0x00001000
#define	BGE_APE_STICKY_TMR		0x00b0

/* APE shared memory.  Accessible through BAR1 */
#define	BGE_APE_SHMEM_BASE		0x4000
#define	BGE_APE_SEG_SIG			0x4000
#define	 APE_SEG_SIG_MAGIC		 0x41504521
#define	BGE_APE_FW_STATUS		0x400c
#define	 APE_FW_STATUS_READY		 0x00000100
#define	BGE_APE_FW_FEATURES		0x4010
#define	 BGE_APE_FW_FEATURE_NCSI	 0x00000002
#define	BGE_APE_FW_VERSION		0x4018
#define	 APE_FW_VERSION_MAJMSK		 0xff000000
#define	 APE_FW_VERSION_MAJSFT		 24
#define	 APE_FW_VERSION_MINMSK		 0x00ff0000
#define	 APE_FW_VERSION_MINSFT		 16
#define	 APE_FW_VERSION_REVMSK		 0x0000ff00
#define	 APE_FW_VERSION_REVSFT		 8
#define	 APE_FW_VERSION_BLDMSK		 0x000000ff
#define	BGE_APE_SEG_MSG_BUF_OFF		0x401c
#define	BGE_APE_SEG_MSG_BUF_LEN		0x4020
#define	BGE_APE_HOST_SEG_SIG		0x4200
#define	 APE_HOST_SEG_SIG_MAGIC		 0x484f5354
#define	BGE_APE_HOST_SEG_LEN		0x4204
#define	 APE_HOST_SEG_LEN_MAGIC		 0x00000020
#define	BGE_APE_HOST_INIT_COUNT		0x4208
#define	BGE_APE_HOST_DRIVER_ID		0x420c
#define	 APE_HOST_DRIVER_ID_SOLARIS	0xf4000000
#define	 APE_HOST_DRIVER_ID_MAGIC(maj, min) \
	(APE_HOST_DRIVER_ID_SOLARIS | (maj & 0xff) << 16 | (min & 0xff) << 8)
#define	BGE_APE_HOST_BEHAVIOR		0x4210
#define	 APE_HOST_BEHAV_NO_PHYLOCK	 0x00000001
#define	BGE_APE_HOST_HEARTBEAT_INT_MS	0x4214
#define	 APE_HOST_HEARTBEAT_INT_DISABLE	 0
#define	 APE_HOST_HEARTBEAT_INT_5SEC	 5000
#define	BGE_APE_HOST_HEARTBEAT_COUNT	0x4218
#define	BGE_APE_HOST_DRVR_STATE		0x421c
#define	BGE_APE_HOST_DRVR_STATE_START	 0x00000001
#define	BGE_APE_HOST_DRVR_STATE_UNLOAD	 0x00000002
#define	BGE_APE_HOST_DRVR_STATE_WOL	 0x00000003
#define	BGE_APE_HOST_WOL_SPEED		0x4224
#define	BGE_APE_HOST_WOL_SPEED_AUTO	 0x00008000

#define	BGE_APE_EVENT_STATUS		0x4300

#define	 APE_EVENT_STATUS_DRIVER_EVNT	 0x00000010
#define	 APE_EVENT_STATUS_STATE_CHNGE	 0x00000500
#define	 APE_EVENT_STATUS_SCRTCHPD_READ	 0x00001600
#define	 APE_EVENT_STATUS_SCRTCHPD_WRITE 0x00001700
#define	 APE_EVENT_STATUS_STATE_START	 0x00010000
#define	 APE_EVENT_STATUS_STATE_UNLOAD	 0x00020000
#define	 APE_EVENT_STATUS_STATE_WOL	 0x00030000
#define	 APE_EVENT_STATUS_STATE_SUSPEND	 0x00040000
#define	 APE_EVENT_STATUS_EVENT_PENDING	 0x80000000

#define	BGE_APE_PER_LOCK_REQ		0x8400
#define	 APE_LOCK_PER_REQ_DRIVER	 0x00001000
#define	BGE_APE_PER_LOCK_GRANT		0x8420
#define	 APE_PER_LOCK_GRANT_DRIVER	 0x00001000

/* APE convenience enumerations. */
#define	BGE_APE_LOCK_PHY0		0
#define	BGE_APE_LOCK_GRC		1
#define	BGE_APE_LOCK_PHY1		2
#define	BGE_APE_LOCK_PHY2		3
#define	BGE_APE_LOCK_MEM		4
#define	BGE_APE_LOCK_PHY3		5
#define	BGE_APE_LOCK_GPIO		7

#ifdef __cplusplus
}
#endif

#endif	/* _BGE_HW_H */
