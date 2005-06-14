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
 * Copyright (c) 1989-1998,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FDREG_H
#define	_SYS_FDREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Floppy Controller Registers
 */
#ifndef	_ASM
union fdcreg {
	volatile struct {
		uchar_t	fdc_control;
		uchar_t	fdc_fifo;
	} fdc_82072_reg;

	volatile struct fdc_82077_reg {
		uchar_t	fdc_filler1[2];
		uchar_t	fdc_dor;	/* Digital Output Register */
		uchar_t	fdc_filler2;
		uchar_t	fdc_control;	/* DSR on write, MSR on read */
#define			fdc_msr	fdc_control
#define			fdc_dsr	fdc_control
		uchar_t	fdc_fifo;
		uchar_t	fdc_filler3;
		uchar_t	fdc_dir;	/* Digital Input Register */
#define			fdc_ccr	fdc_dir
	} fdc_82077_reg;
};
#endif	/* !_ASM */

/* DSR - data rate select register */
#define	SWR		0x80	/* software reset */
#define	PD		0x40	/* power down */
#define	EPL		0x20	/* enable phase lock loop */
#define	PRECOMPMSK	0x1c	/* precomp mask */
#define	DRSELMSK	0x3	/* data rate select mask */

/* MSR - main status register */
#define	RQM 0x80	/* request for master - chip needs attention */
#define	DIO 0x40	/* data in/out - 1 = remove bytes from fifo */
#define	NDM 0x20	/* non-dma mode - 1 during execution phase */
#define	CB  0x10	/* controller busy - command in progress */

/* command types */
#define	GPLN 0x1b	/* gap length for read/write command */
#define	GPLF 0x54	/* gap length for format command */
#define	FDATA 0xe5	/* fill data fields during format */

/* commands */

/* 0x00-0x01 not defined */
#define	RDTRK		0x02
#define	SPECIFY		0x03
#define	SNSDSTAT	0x04
#define	WRTCMD		0x05
#define	RDCMD		0x06
#define	RECALIBRATE	0x07
#define	SNSISTAT	0x08	/* Sense Interrupt Status */
#define	WRTDEL		0x09	/* Write Deleted Data Sector */
#define	RDID		0x0A	/* Read Identifier */
#define	MTONOFF		0x0B	/* motor on/off */
#define	RDDEL		0x0C	/* Read Deleted Data Sector */
#define	FMTTRK		0x0D	/* Format Track */
#define	DUMPREG		0x0E	/* Dump Registers */
#define	SEEK		0x0F	/* Seek */
/* 0x10-0x12 not defined */
#define	CONFIGURE	0x13
/* 0x14-0x1F not defined */

/* Modifier bits for the command byte */
#define	MT		0x80
#define	MFM		0x40
#define	SK		0x20
#define	MOT		0x80
#define	IPS		0x80	/* Used for South Bridge superI/O */


#define	SSSDTL		0xff	/* special sector size */

#define	NCBRW		0x09	/* number cmd bytes for read/write cmds */
#define	NRBRW		0x07	/* number result bytes for read/write cmds */

/* results */
/* status reg0 */
#define	IC_SR0		0xc0	/* interrupt code */
#define	SE_SR0		0x20	/* seek end */
#define	EC_SR0		0x10	/* equipment check */
#define	NR_SR0		0x08	/* not ready */
#define	H_SR0		0x04	/* head address */
#define	DS_SR0		0x03	/* drive select */

/* status reg1 */
#define	EN_SR1		0x80	/* end of cylinder */
#define	DE_SR1		0x20	/* data error */
#define	OR_SR1		0x10	/* overrun/underrun */
#define	ND_SR1		0x04	/* no data */
#define	NW_SR1		0x02	/* not writable */
#define	MA_SR1		0x01	/* missing address mark */
#define	TO_SR1		0x08	/* Timeout */

/* status reg3 */
#define	WP_SR3		0x40	/* write protected */
#define	T0_SR3		0x10	/* track zero */

/* DOR - Digital Output register - 82077 only */
#define	EJECT   	0x80	/* eject diskette - was in Auxio */
#define	EJECT_DMA	0x20	/* eject diskette - on DMA platform */
#define	MOTEN(unit) 	(unit ? 0x30 : 0x10) 	/* motor enable bit */
#define	DMAGATE 	0x8	/* must be high to enable interrupts */
#define	RESET   	0x4	/* reset bit */
#define	DRVSEL		0x1 	/* drive select */

/* DIR - Digital Input register - 82077 only */
#define	DSKCHG  0x80		/* diskette was changed - was in Auxio */

#define	DRV_MASK	0x03	/* drive mask for the second command byte */

#ifndef	_ASM
#define	Moton_delay	(drv_usectohz(750000))		/* motor on delay */
							/* 0.75 seconds */
#define	Motoff_delay	(6 * drv_usectohz(1000000))	/* motor off delay */
							/* 6 seconds */

/* Macros to set and retrieve data from the controller registers */
#define	Msr(fdc)	ddi_get8(fdc->c_handlep_cont, \
					((uint8_t *)fdc->c_control))
#define	Dsr(fdc, val)   ddi_put8(fdc->c_handlep_cont, \
					((uint8_t *)fdc->c_control),\
					((uint8_t)val))
#define	Dir(fdc)	ddi_get8(fdc->c_handlep_cont, \
					((uint8_t *)fdc->c_dir))
#define	Fifo(fdc)	ddi_get8(fdc->c_handlep_cont, \
					((uint8_t *)fdc->c_fifo))
#define	Set_Fifo(fdc, val) ddi_put8(fdc->c_handlep_cont, \
					((uint8_t *)fdc->c_fifo), \
					((uint8_t)val))
#define	Dor(fdc)	ddi_get8(fdc->c_handlep_cont, ((uint8_t *)fdc->c_dor))
#define	Set_dor(fdc, val, flag) \
	{ if (flag) \
		ddi_put8(fdc->c_handlep_cont, ((uint8_t *)fdc->c_dor), \
			((uint8_t)(Dor(fdc) | (val)))); \
	    else \
		ddi_put8(fdc->c_handlep_cont, ((uint8_t *)fdc->c_dor), \
			((uint8_t)(Dor(fdc) & ~(val)))); }
#endif	/* !_ASM */

/*
 * Auxio Registers
 */

/*
 * Definitions and structures for the floppy Auxiliary Input/Output register
 * for the muchio, slavio, and cheerio I/O subsystem chips
 *
 * In general, muchio is found on sun4c, slavio is found on sun4m and sun4u
 * with Sbus.  Cheerio is found on sun4u with a PCI bus.
 *
 *
 *
 *			07   06   05   04   03   02   01   00
 *	muchio		1    1    DEN  CHG  SEL  TC   EJCT LED
 *	slavio   	1    1    DEN  0    IMUX 0    TC   LED
 *
 * The auxio register is designed poorly from a software perspective.
 *  a) it supports other functions as well as floppy
 *  b) TC is at a different bit position for muchio versus sun4m
 *
 * The cheerio auxio register is only for the floppy and it is a 32 bit
 * register.  It does not contain a TC because the cheerio supports
 * floppy DMA.  Please note that on the slavio auxio, the Digital
 * Output register of the floppy controller contains a Density Select bit.
 * On the cheerio, this bit is muxed with another
 * signal.  So, the cheerio auxio register contains a density select bit.
 *
 *    cheerio auxio bit name	bit#
 *    ------------------------------
 *    Floppy density sense    	0
 *    Floppy desnity select     1
 *    Unused			31:1
 *
 */

/*
 * muchio/slavio: Bits of the auxio register
 *	- when writing to the auxio register, the bits represented by
 *	  AUX_MBO and AUX_MBO4M must be one
 */

#define	AUX_MBO		0xF0		/* Must be written with ones */
#define	AUX_MBO4M	0xC0		/* Must be written with ones */

#define	AUX_TC4M	0x02	/* 4m Floppy termnal count */
				/* 1 = transfer over */
#define	AUX_TC		0x04	/* 4c Floppy terminal count */
				/* 1 = transfer over */
#define	AUX_DENSITY	0x20	/* Floppy density (input value) */
				/* 1 = high, 0 = low */


/*
 * muchio additional floppy auxio bits
 * slavio uses internal dor for these bits
 */

#define	AUX_DISKCHG	0x10		/* Floppy diskette change (input) */
					/* 1 = new diskette inserted */
#define	AUX_DRVSELECT	0x08		/* Floppy drive select (output) */
					/* 1 = selected, 0 = deselected */
#define	AUX_EJECT	0x02		/* Floppy eject (output,NON inverted) */
					/* 0 = eject the diskette */
/*
 * cheerio additional floppy auxio bits
 */

#define	AUX_MEDIUM_DENSITY	0x0	/* Use medium density */
#define	AUX_HIGH_DENSITY	0x2

/*
 * macros to set the Cheerio auxio registers.
 */

#define	Set_auxio(fdc, val)	ddi_put32(fdc->c_handlep_aux, \
				((uint32_t *)fdc->c_auxio_reg), \
				    ((uint32_t)(val)))

#define	Get_auxio(fdc)		ddi_get32(fdc->c_handlep_aux, \
				((uint32_t *)fdc->c_auxio_reg))

/*
 * DMA registers (sun4u only)
 */
#ifndef _ASM
struct	cheerio_dma_reg {
	uint_t fdc_dcsr;		/* Data Control Status Register */
	uint_t fdc_dacr;		/* DMA Address Count Registers */
	uint_t fdc_dbcr;		/* DMA Byte Count Register */
};

#define	ISA_REG_LEN	0x500	/* South Bridge dma regs span */
				/* complete 0x500 isa registers. */

struct sb_dma_reg {
	uchar_t sb_dma_regs[ISA_REG_LEN];
};
struct fdc_dma_reg {
	uchar_t fdc_dma_regs[ISA_REG_LEN]; /* registers from isa config space */
};


#endif /* !_ASM */



/*
 * DMA Control and Status Register(DCSR) definitions.  See Cheerio spec
 * for more details
 */
#define	DCSR_INT_PEND 	0x00000001	/* 1= floppy interrupts */
#define	DCSR_ERR_PEND 	0x00000002	/* 1= host bus error detected */
#define	DCSR_INT_EN 	0x00000010	/* 1= enable floppy interrupts */
#define	DCSR_RESET  	0x00000080	/* 1= resets the DCSR */
#define	DCSR_WRITE  	0x00000100  	/* DMA direction; 1 = memory */
#define	DCSR_EN_DMA  	0x00000200  	/* 1= enable DMA */
#define	DCSR_CYC_PEND	0x00000400	/* 1 = DMA pending */
#define	DCSR_EN_CNT 	0x00002000	/* 1= enables byte counter */
#define	DCSR_TC		0x00004000  	/* 1= Terminal Count occurred */
#define	DCSR_CSR_DRAIN 	0x00000000 	/* 1= disable draining */
#define	DCSR_BURST_0    0x00080000 	/* Burst Size bit 0 */
#define	DCSR_BURST_1    0x00040000 	/* Burst Size bit 1 */
#define	DCSR_DIAG	0x00000000 	/* 1= diag enable */
#define	DCSR_TCI_DIS 	0x00800000	/* 1= TC won't cause interrupt */
#define	DCSR_INIT_BITS  DCSR_INT_EN | DCSR_EN_CNT | DCSR_CSR_DRAIN  \
			| fd_burstsize \
			| DCSR_TCI_DIS | DCSR_EN_DMA

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FDREG_H */
