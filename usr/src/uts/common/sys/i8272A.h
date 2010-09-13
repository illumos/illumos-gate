/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_I8272A_H
#define	_SYS_I8272A_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * i/o port numbers
 */
#define	FCR_BASE	0x3f0	/* default i/o base address */

#define	FCR_SRA		0x000	/* only 82077AA (not AT mode) or SMC */
#define	FCR_SRB		0x001	/* only 82077AA (not AT mode) or SMC */
#define	FCR_DOR		0x002
#define	FCR_MSR		0x004
#define	FCR_DSR		0x004	/* only enhanced controllers */
#define	FCR_DATA	0x005
#define	FCR_DIR		0x007
#define	FCR_CCR		0x007	/* 82077AA term; == DSR on PC/AT */

/*  SRA : values for Configuration Select Register for SMC FDC37C66xGT */
#define	FSA_ENA5	0x55	/*  enable config mode, issue twice */
#define	FSA_ENA6	0x44	/*  enable config mode, issue twice */
#define	FSA_DISB	0xAA	/*  disable config mode */
#define	FSA_CR5		0x05	/*  select config register 5 */

/*  SRB : Configuration Data Register for SMC FDC37C66xGT */
#define	FSB_DSDEF	0xE7	/*  bit mask for density select in reg 5 */
#define	FSB_DSLO	0x10	/*  density select = LOW (300 rpm) */
#define	FSB_DSHI	0x18	/*  density select = HIGH (360 rpm) */

/*  DOR : Digital Output Register */
#define	FD_DMTREN	0xF0
#define	FD_D3MTR	0x80
#define	FD_D2MTR	0x40
#define	FD_DBMTR	0x20
#define	FD_DAMTR	0x10
#define	FD_ENABLE	0x08	/* DMA gate */
#define	FD_RSETZ	0x04
#define	FD_DRSEL	0x03
#define	FD_DBSEL	0x01
#define	FD_DASEL	0x00

#define	ENAB_MCA_INT	0x00


/* MSR - Main Status Register */
#define	MS_RQM		0x80	/* request for master - chip needs attention */
#define	MS_DIO		0x40	/* data in/out, 1 = remove bytes from fifo */
#define	MS_NDM		0x20	/* non-dma mode - 1 during execution phase */
#define	MS_CB		0x10	/* controller busy, command in progress */
#define	MS_D3B		0x08	/* drive 3 busy */
#define	MS_D2B		0x04	/* drive 2 busy */
#define	MS_DBB		0x02	/* drive B busy */
#define	MS_DAB		0x01	/* drive A busy */

#define	FDC_RQM_RETRY	300


/*  DIR : Digital Input Register */
#define	FDI_DKCHG	0x80	/* this is inverted in Model 30 mode */
#define	FDI_DMAGAT	0x08	/* Model 30: DMA gate */
#define	FDI_NOPREC	0x04	/* Model 30 only */
#define	FDI_DRATE	0x03	/* Model 30: selected datarate mask */


/*  DSR : Datarate Select Register on 82072 and 82077AA */
#define	FSR_SWR		0x80	/* software reset */
#define	FSR_PD		0x40	/* power down */
#define	FSR_PRECP	0x1C	/* precomp mask */
#define	FSR_DRATE	0x3	/* datarate select mask */


/*  CCR : Configuration Control Register, aka Datarate Select Register */
#define	FCC_NOPREC	0x4	/* Model 30 only */
#define	FCC_DRATE	0x3	/* datarate select mask */


/*
 * Floppy controller command opcodes
 */
#define	FO_MODE		0x01	/* National PC8477 types only */
#define	FO_RDTRK	0x02
#define	FO_SPEC		0x03
#define	FO_SDRV		0x04	/* read status register 3 */
#define	FO_WRDAT	0x05
#define	FO_RDDAT	0x06
#define	FO_RECAL	0x07
#define	FO_SINT		0x08
#define	FO_WRDEL	0x09
#define	FO_RDID		0x0A
#define	FO_RDDEL	0x0C
#define	FO_FRMT		0x0D
#define	FO_SEEK		0x0F
#define	FO_VRSN		0x10	/* get version */
#define	FO_PERP		0x12	/* perpendicular mode */
#define	FO_CNFG		0x13	/* configure */
#define	FO_NSC		0x18	/* identify National chip */

				/* option bits */
#define	FO_MT		0x80	/* multi-track operation */
#define	FO_MFM		0x40	/* double & high density disks */
#define	FO_FM		0x00	/* single density disks */
#define	FO_SK		0x20	/* skip deleted adr mark */


#define	S0_ICMASK	0xC0	/* status register 0 */
#define	S0_XRDY		0xC0
#define	S0_IVCMD	0x80
#define	S0_ABTERM	0x40
#define	S0_SEKEND	0x20
#define	S0_ECHK		0x10
#define	S0_NOTRDY	0x08

#define	S1_EOCYL	0x80	/* status register 1 */
#define	S1_CRCER	0x20
#define	S1_OVRUN	0x10
#define	S1_NODATA	0x04
#define	S1_MADMK	0x01

#define	S3_FAULT	0x80	/* status register 3 */
#define	S3_WPROT	0x40
#define	S3_DRRDY	0x20
#define	S3_TRK0		0x10
#define	S3_2SIDE	0x08
#define	S3_HEAD		0x04
#define	S3_UNIT		0x03


/*
 * controller chip values
 */
#define	i8272A		0x8272
#define	uPD72064	0x72064		/* NEC */
/* enhanced floppy controllers */
#define	i82077		0x82077
#define	PC87322		0x87322		/* National Semiconducter */
#define	FDC37C665	0x37c665	/* SMC */
#define	FDC37C666	0x37c666	/* SMC */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_I8272A_H */
