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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/pci.h>

#include "ata_blacklist.h"

pcibl_t	ata_pciide_blacklist[] = {
	/*
	 * The Nat SEMI PC87415 doesn't handle data and status byte
	 * synchornization correctly if an I/O error occurs that
	 * stops the request before the last sector.  I think it can
	 * cause lockups. See section 7.4.5.3 of the PC87415 spec.
	 * It's also rumored to be a "single fifo" type chip that can't
	 * DMA on both channels correctly.
	 */
	{ 0x100b, 0xffff, 0x2, 0xffff, ATA_BL_BOGUS},

	/*
	 * The CMD chip 0x646 does not support the use of interrupt bit
	 * in the busmaster ide status register when PIO is used.
	 * DMA is explicitly disabled for this legacy chip
	 */
	{ 0x1095, 0xffff, 0x0646, 0xffff, ATA_BL_BMSTATREG_PIO_BROKEN |
							ATA_BL_NODMA},

	/*
	 * Ditto for Serverworks CSB5, CSB6 and BCM5785[HT1000] chips,
	 * but we can handle DMA.  Also, when emulating OSB4 mode,
	 * the simplex bit lies!
	 */
	{ 0x1166, 0xffff, 0x0212, 0xffff, ATA_BL_BMSTATREG_PIO_BROKEN|
							ATA_BL_NO_SIMPLEX},
	{ 0x1166, 0xffff, 0x0213, 0xffff, ATA_BL_BMSTATREG_PIO_BROKEN},
	{ 0x1166, 0xffff, 0x0214, 0xffff, ATA_BL_BMSTATREG_PIO_BROKEN},

	/*
	 * The  chip 0x24b,which is Broadcom HT1000 SATA controller
	 * working in legacy IDE mode, does not support ATAPI DMA
	 */
	{ 0x1166, 0xffff, 0x024b, 0xffff, ATA_BL_ATAPI_NODMA},

	/*
	 * On Intel ICH5/ICH5R (SATA controller), the simplex bit lies
	 */
	{ 0x8086, 0xffff, 0x24d1, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x24df, 0xffff, ATA_BL_NO_SIMPLEX},

	/*
	 * On Intel ICH6/ICH6R/ICH6-M (IDE and SATA controllers), the
	 * simplex bit lies
	 */
	{ 0x8086, 0xffff, 0x266f, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2651, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2652, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2653, 0xffff, ATA_BL_NO_SIMPLEX},

	/*
	 * On Intel ICH7 (IDE and SATA(Non-AHCI/Non-RAID, desktop and
	 * mobile)), the simplex bit lies
	 */
	{ 0x8086, 0xffff, 0x27df, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x27c0, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x27c4, 0xffff, ATA_BL_NO_SIMPLEX},

	/*
	 * On Intel ICH8 (IDE and SATA(Non-AHCI/Non-RAID, desktop and
	 * mobile)), the simplex bit lies
	 */
	{ 0x8086, 0xffff, 0x2820, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2825, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2828, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2850, 0xffff, ATA_BL_NO_SIMPLEX},

	/*
	 * On Intel ICH9 SATA(Non-AHCI/Non-RAID), the simplex bit lies
	 */
	{ 0x8086, 0xffff, 0x2920, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2921, 0xffff, ATA_BL_NO_SIMPLEX},
	{ 0x8086, 0xffff, 0x2926, 0xffff, ATA_BL_NO_SIMPLEX},

	/*
	 * The ITE 8211F requires some special initialization to get DMA
	 * working that does not fit into the current ata driver model.
	 * This makes it work in PIO mode.
	 */
	{ 0x1283, 0xffff, 0x8211, 0xffff, ATA_BL_NODMA},

	{ 0, 0, 0, 0, 0 }
};

/*
 * add drives that have DMA or other problems to this list
 */

atabl_t	ata_drive_blacklist[] = {
	{ "NEC CD-ROM DRIVE:260",	ATA_BL_1SECTOR },
	{ "NEC CD-ROM DRIVE:272",	ATA_BL_1SECTOR },
	{ "NEC CD-ROM DRIVE:273",	ATA_BL_1SECTOR },

	{ /* Mitsumi */ "FX001DE",	ATA_BL_1SECTOR },

	{ "fubar",
		(ATA_BL_NODMA |
		ATA_BL_1SECTOR |
		ATA_BL_NORVRT |
		ATA_BL_BOGUS |
		ATA_BL_BMSTATREG_PIO_BROKEN)
	},

	/* Known drives that have DMA problems */
	{ "SAMSUNG CD-ROM SN-124",	ATA_BL_NODMA },
	{ "SAMSUNG CDRW/DVD SM-352F",	ATA_BL_NODMA },

	NULL
};
