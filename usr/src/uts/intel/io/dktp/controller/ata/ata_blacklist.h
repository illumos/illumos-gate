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

#ifndef _ATA_BLACKLIST_H
#define	_ATA_BLACKLIST_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is the PCI-IDE chip blacklist
 */
typedef struct {
	uint_t	b_vendorid;
	uint_t	b_vmask;
	uint_t	b_deviceid;
	uint_t	b_dmask;
	uint_t	b_flags;
} pcibl_t;

extern	pcibl_t	ata_pciide_blacklist[];

/*
 * This is the drive blacklist
 */
typedef	struct {
	char	*b_model;
	char    *b_fw;
	uint_t	 b_flags;
} atabl_t;

extern	atabl_t	ata_drive_blacklist[];

/*
 * use the same flags for both lists
 */
#define	ATA_BL_BOGUS	0x1	/* only use in compatibility mode */
#define	ATA_BL_NODMA	0x2	/* don't use DMA on this one */
#define	ATA_BL_1SECTOR	0x4	/* limit PIO transfers to 1 sector */
#define	ATA_BL_BMSTATREG_PIO_BROKEN	0x8

				/*
				 * do not use bus master ide status register
				 * if not doing dma, or if it does not work
				 * properly when doing DMA (for example, on
				 * some lx50's!)
				 */


#define	ATA_BL_NORVRT	0x10
				/*
				 * Don't enable revert to power-on
				 * defaults before rebooting
				 */

#define	ATA_BL_NO_SIMPLEX	0x20
				/*
				 * Ignore simplex bit on this device
				 * if set
				 */
#define	ATA_BL_ATAPI_NODMA	0x40
				/*
				 * Disable DMA for ATAPI devices because
				 * controller has trouble supporting it
				 */

#define	ATA_BL_LBA48	0x80
				/*
				 * the drive's ATA version is less than 6,
				 * but it support the LBA48 mode.
				 */

#ifdef	__cplusplus
}
#endif

#endif /* _ATA_BLACKLIST_H */
