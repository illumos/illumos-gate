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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SDCARD_SDHOST_H
#define	_SYS_SDCARD_SDHOST_H

/*
 * The entire contents of this file are private the SD Host driver
 * implementation.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sdcard/sda.h>
#include <sys/pci.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	BIT(x)	(1 << (x))

/*
 * SD Host Spec says that a controller can support up to 6 different
 * slots, each with its own register set.
 */
#define	SDHOST_MAXSLOTS	6

/*
 * SD Host specific PCI configuration register.
 */
#define	SLOTINFO		0x40
#define	SLOTINFO_NSLOT_SHFT	4
#define	SLOTINFO_NSLOT_MSK	(0x3 << SLOTINFO_NSLOT_SHFT)
#define	SLOTINFO_BAR_SHFT	0
#define	SLOTINFO_BAR_MSK	(0x3 << SLOTINFO_BAR_SHFT)

#define	SLOTINFO_NSLOT(x)		\
	((((x) & SLOTINFO_NSLOT_MSK) >> SLOTINFO_NSLOT_SHFT) + 1)

#define	SLOTINFO_BAR(x)		\
	(((x) & SLOTINFO_BAR_MSK) >> SLOTINFO_BAR_SHFT)

/*
 * Slot-specific CSRs
 */
#define	REG_SDMA_ADDR			0x0000	/* 32 bits */
#define	REG_BLKSZ			0x0004	/* 16 bits */
#define	REG_BLOCK_COUNT			0x0006	/* 16 bits */
#define	REG_ARGUMENT			0x0008	/* 32 bits */
#define	REG_XFR_MODE			0x000C	/* 16 bits */
#define	REG_COMMAND			0x000E	/* 16 bits */
#define	REG_RESP1			0x0010	/* 32 bits */
#define	REG_RESP2			0x0014	/* 32 bits */
#define	REG_RESP3			0x0018	/* 32 bits */
#define	REG_RESP4			0x001C	/* 32 bits */
#define	REG_DATA			0x0020	/* 32 bits */
#define	REG_PRS				0x0024	/* 32 bits */
#define	REG_HOST_CONTROL		0x0028	/* 8 bits */
#define	REG_POWER_CONTROL		0x0029	/* 8 bits */
#define	REG_BLOCK_GAP_CONTROL		0x002A	/* 8 bits */
#define	REG_WAKEUP_CONTROL		0x002B	/* 8 bits */
#define	REG_CLOCK_CONTROL		0x002C	/* 16 bits */
#define	REG_TIMEOUT_CONTROL		0x002E	/* 8 bits */
#define	REG_SOFT_RESET			0x002F	/* 8 bits */
#define	REG_INT_STAT			0x0030	/* 16 bits */
#define	REG_ERR_STAT			0x0032	/* 16 bits */
#define	REG_INT_EN			0x0034	/* 16 bits */
#define	REG_ERR_EN			0x0036	/* 16 bits */
#define	REG_INT_MASK			0x0038	/* 16 bits */
#define	REG_ERR_MASK			0x003A	/* 16 bits */
#define	REG_ACMD12_ERROR		0x003C	/* 16 bits */
#define	REG_CAPAB			0x0040	/* 64 bits */
#define	REG_MAX_CURRENT			0x0048	/* 64 bits */
#define	REG_SLOT_INT_STAT		0x00FC	/* 16 bits */
#define	REG_VERSION			0x00FE	/* 16 bits */
#define	REG_ERR_FORCE			0x0052	/* 16 bits */
#define	REG_ACMD12_ERROR_FORCE		0x0050	/* 16 bits */
#define	REG_ADMA_ERROR			0x0054	/* 8 bits */
#define	REG_ADMA_ADDR			0x0058	/* 64 bits */

/* REG_BLKSZ bits */
#define	BLKSZ_XFR_BLK_SIZE_MASK		(0x0fff)
#define	BLKSZ_BOUNDARY_4K		(0 << 12)
#define	BLKSZ_BOUNDARY_8K		(1 << 12)
#define	BLKSZ_BOUNDARY_16K		(2 << 12)
#define	BLKSZ_BOUNDARY_32K		(3 << 12)
#define	BLKSZ_BOUNDARY_64K		(4 << 12)
#define	BLKSZ_BOUNDARY_128K		(5 << 12)
#define	BLKSZ_BOUNDARY_256K		(6 << 12)
#define	BLKSZ_BOUNDARY_512K		(7 << 12)
#define	BLKSZ_BOUNDARY_MASK		(0x7 << 12)

/* REG_XFR_MODE bits */
#define	XFR_MODE_DMA_EN			BIT(0)
#define	XFR_MODE_COUNT			BIT(1)
#define	XFR_MODE_AUTO_CMD12		BIT(2)
#define	XFR_MODE_READ			BIT(4)	/* 1 = read, 0 = write */
#define	XFR_MODE_MULTI			BIT(5)	/* 1 = multi, 0 = single */

/* REG_COMMAND bits */
#define	COMMAND_CRC_CHECK_EN		BIT(3)
#define	COMMAND_INDEX_CHECK_EN		BIT(4)
#define	COMMAND_DATA_PRESENT		BIT(5)
#define	COMMAND_TYPE
#define	COMMAND_TYPE_NORM		(0 << 6)
#define	COMMAND_TYPE_SUSPEND		(1 << 6)
#define	COMMAND_TYPE_RESUME		(2 << 6)
#define	COMMAND_TYPE_ABORT		(3 << 6)
#define	COMMAND_TYPE_MASK		(0x3 << 6)
#define	COMMAND_RESP_NONE		0
#define	COMMAND_RESP_136		1	/* R2 */
#define	COMMAND_RESP_48			2	/* R1, R3, R6, R7 */
#define	COMMAND_RESP_48_BUSY		3	/* R1b */

/* REG_PRS bits */
#define	PRS_CMD_INHIBIT			BIT(0)
#define	PRS_DAT_INHIBIT			BIT(1)
#define	PRS_DAT_ACTIVE			BIT(2)
#define	PRS_WRITE_ACTIVE		BIT(8)
#define	PRS_READ_ACTIVE			BIT(9)
#define	PRS_BUF_WR_EN			BIT(10)
#define	PRS_BUF_RD_EN			BIT(11)
#define	PRS_CARD_INSERTED		BIT(16)
#define	PRS_CARD_STABLE			BIT(17)
#define	PRS_CARD_DETECT			BIT(18)
#define	PRS_WRITE_ENABLE		BIT(19)
#define	PRS_DAT0_SIG			BIT(20)
#define	PRS_DAT1_SIG			BIT(21)
#define	PRS_DAT2_SIG			BIT(22)
#define	PRS_DAT3_SIG			BIT(23)

#define	PRS_INHIBIT    \
	(PRS_CMD_INHIBIT | PRS_DAT_INHIBIT)
#define	PRS_DAT_SIG	\
	(PRS_DAT0_SIG | PRS_DAT1_SIG | PRS_DAT2_SIG | PRS_DAT3_SIG)

/* REG_HOST_CONTROL bits */
#define	HOST_CONTROL_LED_ON		BIT(0)
#define	HOST_CONTROL_DATA_WIDTH		BIT(1)
#define	HOST_CONTROL_HIGH_SPEED_EN	BIT(2)
#define	HOST_CONTROL_DMA_SDMA		(0 << 3)
#define	HOST_CONTROL_DMA_ADMA32		(2 << 3)
#define	HOST_CONTROL_DMA_ADMA64		(3 << 3)
#define	HOST_CONTROL_DMA_MASK		(0x3 << 3)
#define	HOST_CONTROL_CARD_DETECT_TEST	BIT(6)
#define	HOST_CONTROL_CARD_DETECT_SEL	BIT(7)

/* REG_POWER_CONTROL bits */
#define	POWER_CONTROL_BUS_POWER		BIT(0)
#define	POWER_CONTROL_33V		(7 << 1)
#define	POWER_CONTROL_30V		(6 << 1)
#define	POWER_CONTROL_18V		(5 << 1)

/* REG_BLOCK_GAP_CONTROL bits */
#define	BLOCK_GAP_CONTROL_STOP		BIT(0)
#define	BLOCK_GAP_CONTROL_CONTINUE	BIT(1)
#define	BLOCK_GAP_CONTROL_READ_WAIT	BIT(2)
#define	BLOCK_GAP_CONTROL_INTERRUPT	BIT(3)

/* REG_WAKEUP_CONTROL bits */
#define	WAKEUP_CONTROL_INTERRUPT	BIT(0)
#define	WAKEUP_CONTROL_INSERT		BIT(1)
#define	WAKEUP_CONTROL_REMOVE		BIT(2)

/* REG_CLOCK_CONTROL bits */
#define	CLOCK_CONTROL_INT_CLOCK_EN	BIT(0)
#define	CLOCK_CONTROL_INT_CLOCK_STABLE	BIT(1)
#define	CLOCK_CONTROL_SD_CLOCK_EN	BIT(2)
#define	CLOCK_CONTROL_FREQ_MASK		(0xff << 8)
#define	CLOCK_CONTROL_FREQ_SHIFT	8

/* REG_TIMEOUT_CONTROL bits */
#define	TIMEOUT_TIMECLK_2_27		(0xe)
/* not listing them all here... but it goes on */
#define	TIMEOUT_TIMECLK_2_13		(0x0)

/* REG_SOFT_RESET bits */
#define	SOFT_RESET_ALL			BIT(0)
#define	SOFT_RESET_CMD			BIT(1)
#define	SOFT_RESET_DAT			BIT(2)

/* REG_INT_{STAT,EN,MASK} bits */
#define	INT_CMD				BIT(0)
#define	INT_XFR				BIT(1)
#define	INT_BG				BIT(2)
#define	INT_DMA				BIT(3)
#define	INT_WR				BIT(4)
#define	INT_RD				BIT(5)
#define	INT_INS				BIT(6)
#define	INT_REM				BIT(7)
#define	INT_CARD			BIT(8)
#define	INT_ERR				BIT(15)

#define	INT_PIO		(INT_RD | INT_WR)
#define	INT_HOTPLUG	(INT_INS | INT_REM)

#define	INT_MASK	(INT_XFR | INT_DMA | INT_PIO | INT_HOTPLUG)
#define	INT_ENAB	(INT_MASK | INT_CMD)

/* REG_ERR_{STAT,EN,MASK} bits */
#define	ERR_VENDOR			(0xf << 12)
#define	ERR_ADMA			BIT(9)
#define	ERR_ACMD12			BIT(8)
#define	ERR_CURRENT			BIT(7)
#define	ERR_DAT_END			BIT(6)
#define	ERR_DAT_CRC			BIT(5)
#define	ERR_DAT_TMO			BIT(4)
#define	ERR_CMD_IDX			BIT(3)
#define	ERR_CMD_END			BIT(2)
#define	ERR_CMD_CRC			BIT(1)
#define	ERR_CMD_TMO			BIT(0)

#define	ERR_CMD		(ERR_CMD_IDX | ERR_CMD_END | ERR_CMD_CRC | ERR_CMD_TMO)
#define	ERR_CMD_CFL	(ERR_CMD_CRC | ERR_CMD_TMO)

#define	ERR_DAT		(ERR_DAT_END | ERR_DAT_CRC | ERR_DAT_TMO)

#define	ERR_MASK	(ERR_ACMD12 | ERR_DAT)
#define	ERR_ENAB	(ERR_MASK | ERR_CMD)

/* REG_ACMD12_ERROR bits */
#define	ACMD12_ERROR_NOT_EXECUTED	BIT(0)
#define	ACMD12_ERROR_TIMEOUT		BIT(1)
#define	ACMD12_ERROR_CRC		BIT(2)
#define	ACMD12_ERROR_END_BIT		BIT(3)
#define	ACMD12_ERROR_INDEX		BIT(4)
#define	ACMD12_ERROR_NOT_ISSUED		BIT(7)

/* REG_CAPAB bits */
#define	CAPAB_TIMEOUT_FREQ_SHIFT	0
#define	CAPAB_TIMEOUT_FREQ_MASK		(0x3f << 0)
#define	CAPAB_TIMEOUT_UNITS		BIT(7)		/* 1 == MHz, 0 = kHz */
#define	CAPAB_BASE_FREQ_SHIFT		8
#define	CAPAB_BASE_FREQ_MASK		(0x3f << 8)
#define	CAPAB_MAXBLK_512		(0 << 16)
#define	CAPAB_MAXBLK_1K			(1 << 16)
#define	CAPAB_MAXBLK_2K			(2 << 16)
#define	CAPAB_MAXBLK_MASK		(0x3 << 16)
#define	CAPAB_ADMA2			BIT(19)
#define	CAPAB_ADMA1			BIT(20)
#define	CAPAB_HIGH_SPEED		BIT(21)
#define	CAPAB_SDMA			BIT(22)
#define	CAPAB_SUSPEND			BIT(23)
#define	CAPAB_33V			BIT(24)
#define	CAPAB_30V			BIT(25)
#define	CAPAB_18V			BIT(26)
#define	CAPAB_VOLTS			(CAPAB_33V | CAPAB_30V | CAPAB_18V)
#define	CAPAB_64BIT			BIT(28)

/* REG_MAX_CURRENT bits */
#define	MAX_CURRENT_33V_SHIFT		0
#define	MAX_CURRENT_33V_MASK		(0xff << 0)
#define	MAX_CURRENT_30V_SHIFT		8
#define	MAX_CURRENT_30V_MASK		(0xff << 8)
#define	MAX_CURRENT_18V_SHIFT		16
#define	MAX_CURRENT_18V_MASK		(0xff << 16)

/* REG_VERSION bits */
#define	VERSION_VENDOR_SHIFT		8
#define	VERSION_VENDOR_MASK		(0xff << 8)
#define	VERSION_SDHOST_MASK		0xff
#define	VERSION_SDHOST_1		0
#define	VERSION_SDHOST_2		1

/* REG_ADMA_ERROR bits */
#define	ADMA_ERROR_STATE_ST_STOP	0
#define	ADMA_ERROR_STATE_ST_FDS		1
#define	ADMA_ERROR_STATE_ST_TFR		3
#define	ADMA_ERROR_STATE_MASK		0x3
#define	ADMA_ERROR_LEN_MISMATCH		BIT(2)

/*
 * Properties.
 */
#define	SDHOST_PROP_ENABLE_MSI		"enable-msi"
#define	SDHOST_PROP_ENABLE_MSIX		"enable-msix"
#define	SDHOST_PROP_FORCE_PIO		"force-pio"
#define	SDHOST_PROP_FORCE_DMA		"force-dma"

#endif	/* _SYS_SDCARD_SDHOST_H */
