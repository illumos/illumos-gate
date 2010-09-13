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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DMA_I8237A_H
#define	_SYS_DMA_I8237A_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	All Rights Reserved	*/

#define	D37A_MAX_CHAN   8
#define	D37A_DFR_ALIGN  0xf
#define	D37A_MIN_CHAN   0x0

/*
 * Defines for PC AT DMA controllers.
 */

/*
 * The PC/AT has two Intel 8237A-5 DMA controllers that provide 8 channels
 */
#define	DMA_0WCNT	0x01	/* Channel  word count */
#define	DMA_1WCNT	0x03	/* Channel  word count */
#define	DMA_2WCNT	0x05	/* Channel  word count */
#define	DMA_3WCNT	0x07	/* Channel  word count */
#define	DMA_4WCNT	0xC2	/* (RESERVED) Channel  word count */
#define	DMA_5WCNT	0xC6	/* Channel  word count */
#define	DMA_6WCNT	0xCA	/* Channel  word count */
#define	DMA_7WCNT	0xCE	/* Channel  word count */

#define	DMA_0ADR	0x00	/* Channel  address register */
#define	DMA_1ADR	0x02	/* Channel  address register */
#define	DMA_2ADR	0x04	/* Channel  address register */
#define	DMA_3ADR	0x06	/* Channel  address register */
#define	DMA_4ADR	0xC0	/* (RESERVED) Channel  address register */
#define	DMA_5ADR	0xC4	/* Channel  address register */
#define	DMA_6ADR	0xC8	/* Channel  address register */
#define	DMA_7ADR	0xCC	/* Channel  address register */

/*
 * The Intel DMA controllers are augmented with 8-bit page registers
 * for each channel, allowing access to a 16MB address space.
 */
#define	DMA_0PAGE	0x87	/* Channel 0 address extension reg */
#define	DMA_1PAGE	0x83	/* Channel 1 address extension reg */
#define	DMA_2PAGE	0x81	/* Channel 2 address extension reg */
#define	DMA_3PAGE	0x82	/* Channel 3 address extension reg */
#define	DMA_4PAGE	0	/* dummy address for dma chan. 4 page reg. */
#define	DMA_5PAGE	0x8B	/* Channel 5 address extension reg */
#define	DMA_6PAGE	0x89	/* Channel 6 address extension reg */
#define	DMA_7PAGE	0x8A	/* Channel 7 address extension reg */

/*
 * The EISA has an 8-bit high-page register for each channel
 * for access to a 32-bit address space.
 */
#define	DMA_0HPG	0x487   /* port address for dma channel 0 */
				/* high page reg */
#define	DMA_1HPG	0x483   /* port address for dma channel 1 */
				/* high page reg */
#define	DMA_2HPG	0x481   /* port address for dma channel 2 */
				/* high page reg */
#define	DMA_3HPG	0x482   /* port address for dma channel 3 */
				/* high page reg */
#define	DMA_4HPG	0	/* dummy address for dma channel 4 */
				/* high page reg */
#define	DMA_5HPG	0x48B   /* port address for dma channel 5 */
				/* high page reg */
#define	DMA_6HPG	0x489   /* port address for dma channel 6 */
				/* high page reg */
#define	DMA_7HPG	0x48A   /* port address for dma channel 7 */
				/* high page reg */

/*
 * The EISA has an 8-bit high-count register for each channel
 * for xfer sizes up to 16MB.
 */
#define	DMA_0XCNT	0x401   /* chan. 0 base and current count high */
#define	DMA_1XCNT	0x403   /* chan. 1 base and current count high */
#define	DMA_2XCNT	0x405   /* chan. 2 base and current count high */
#define	DMA_3XCNT	0x407   /* chan. 3 base and current count high */
#define	DMA_4XCNT	0	/* dummy chan. 4 base and current count high */
#define	DMA_5XCNT	0x4C6   /* chan. 5 base and current count high */
#define	DMA_6XCNT	0x4CA   /* chan. 6 base and current count high */
#define	DMA_7XCNT	0x4CE   /* chan. 7 base and current count high */

/*
 * I/O port addresses for controller 1
 */
#define	DMAC1_CMD	0x08	/* Command reg */
#define	DMAC1_REQ	0x09	/* request reg */
#define	DMAC1_STAT	0x08	/* Status reg */
#define	DMAC1_MASK	0x0A	/* Mask set/reset register */
#define	DMAC1_MODE	0x0B	/* Mode reg */
#define	DMAC1_CLFF	0x0C	/* Clear byte pointer first/last flip-flop */
#define	DMA1RTRWMC	0x0D	/* read temp reg/write master clear */
#define	DMA1CMR		0x0E	/* clear mask register */
#define	DMAC1_ALLMASK	0x0F	/* Mask all registers */
#define	DMAC1_SCM	0x40A   /* set chain mode */
#define	DMAC1_EWM	0x40B	/* extended write mode */

/*
 * I/O port addresses for controller 2
 */
#define	DMAC2_CMD	0xD0	/* Command reg */
#define	DMAC2_STAT	0xD0	/* Status reg */
#define	DMAC2_REQ	0xD2	/* request reg */
#define	DMAC2_MASK	0xD4	/* Mask set/reset register */
#define	DMAC2_MODE	0xD6	/* Mode reg */
#define	DMAC2_CLFF	0xD8	/* Clear byte pointer first/last flip-flop */
#define	DMA2RTRWMC	0xDA	/* read temp reg/write master clear */
#define	DMA2CMR		0xDC	/* clear mask register */
#define	DMAC2_ALLMASK	0xDE	/* Mask all registers */
#define	DMAC2_SCM	0x4D4   /* set chain mode */
#define	DMAC2_EWM	0x4D6   /* extended write mode */

/*
 * Write-only Command register definitions.
 */
#define	DMACMD_MEM_TO_MEM	0x01	/* memory-to-memory copy (1=enable) */
#define	DMACMD_CHAN_HOLD	0x02	/* Channel 0 address hold (1=enable) */
#define	DMACMD_CTLR_ENABLE	0x04	/* Controller disable (0=enabled) */
#define	DMACMD_TIMING		0x08	/* normal/compressed timing (0=nrml) */
#define	DMACMD_FIX_PRIO		0x10	/* fixed/rotating priority (0=fixed) */
#define	DMACMD_WRT_SELECT	0x20	/* late/ext write selection (1=ext) */
#define	DMACMD_DREQ_LEVEL	0x40	/* DREQ sense active (0=actv. high) */
#define	DMACMD_DACK_LEVEL	0x80	/* DACK sense active (0=actv. low) */

/*
 * Initialization value for DMA controller.
 */
#define	DMA_CTLR_INIT	~(DMACMD_MEM_TO_MEM | DMACMD_CHAN_HOLD | \
			DMACMD_CTLR_ENABLE | DMACMD_TIMING | \
			DMACMD_FIX_PRIO	| DMACMD_WRT_SELECT | \
			DMACMD_DREQ_LEVEL | DMACMD_DACK_LEVEL)

/*
 * Write-only Mode register.  There is actually a 6-bit Mode register
 * associated with each channel.  These are written one at a time, with
 * the channel number indicated by the low-order 2 bits.
 */

#define	DMAMODE_CHAN	0x03	/* Mask for the "channel select" bits. */
				/* These indicate channel 0-3 */
#define	DMAMODE_VERF	0x00	/* Verify Transfer */
#define	DMAMODE_READ	0x04	/* Read Transfer */
#define	DMAMODE_WRITE   0x08	/* Write Transfer */
				/* Note: Above settings for bits 2-3 are */
				/* "don't care" if bits 6-7 indicate */
				/* cascade mode */
#define	DMAMODE_AUTO	0x10	/* enable Autoinitialization on completion */
#define	DMAMODE_DECR	0x20	/* Address Decrement.  If 0, address incr */
#define	DMAMODE_DEMAND  0x00	/* Select Demand mode */
				/* Each DREQ causes transfers at full speed */
				/* until DREQ goes inactive (after which it */
				/* can be resumed) or either terminal-count */
				/* happens or EOP is asserted */
#define	DMAMODE_SINGLE  0x40	/* Select Single mode */
				/* Each DREQ causes a single byte/word xfer */
#define	DMAMODE_BLOCK   0x80	/* Select Block mode */
				/* Each DREQ causes transfers at full speed */
				/* until terminal count or EOP */
#define	DMAMODE_CASC	0xC0	/* Select Cascade mode.  On the PC-AT, this */
				/* should be set for DMA 2 channel 0 ONLY */


#define	EISA_DMAIS	0x40a   /* interrupt status register */

#define	DMA_MSK		0x0A	/* Mask, enable disk, disable others */
#define	DMA_CLEAR	0x1A	/* Master clear */
#define	IOCR		0x56	/* IO controller */

/*
 * DMA Channels. d_chan field of dmareq.
 */

/* 8 bit channels */
#define	DMAE_CH0	0	/* Channel 0 */
#define	DMAE_CH1	1	/* Channel 1 */
#define	DMAE_CH2	2	/* Channel 2 */
#define	DMAE_CH3	3	/* Channel 3 */
#define	DMAE_CH4	4	/* Channel 4 */
/* 16 bit channels */
#define	DMAE_CH5	5	/* Channel 5 */
#define	DMAE_CH6	6	/* Channel 6 */
#define	DMAE_CH7	7	/* Channel 7 */

/*
 * DMA Masks.
 */
#define	DMA_SETMSK	4	/* Set mask bit */
#define	DMA_CLRMSK	0	/* Clear mask bit */

/* dma_alloc modes */
#define	DMA_BLOCK	0	/* blocking task time allocation */
#define	DMA_NBLOCK	1	/* non-blocking task time allocation */

#define	EISA_DMA_8	0	/* 8-bit data path */
#define	EISA_DMA_16	1<<2	/* 16-bit data path, word count */
#define	EISA_DMA_32	2<<2	/* 32-bit data path */
#define	EISA_DMA_16B	3<<2	/* 16-bit data path, byte count */

#define	EISA_ENCM	4	/* enable chaining mode */
#define	EISA_CMOK	8	/* chaining mode completed (OK) */


/*
 * Channel Address Array - makes life much easier
 */
struct d37A_chan_reg_addr {
	uchar_t	addr_reg;	/* address register */
	uchar_t	cnt_reg;	/* count register */
	uchar_t	page_reg;	/* page register */
	uchar_t	ff_reg;		/* first-last flipflop */
	uchar_t	cmd_reg;	/* command register */
	uchar_t	mode_reg;	/* mode register */
	uchar_t	mask_reg;	/* mask register */
	uchar_t	stat_reg;	/* status register */
	uchar_t	reqt_reg;	/* request register */
	ushort_t hpage_reg;	/* high page register */
	ushort_t hcnt_reg;	/* high count register */
	ushort_t emode_reg;	/* extended mode register */
	ushort_t scm_reg;	/* set chaining mode register */
};

/*
 * macro to initialize array of d37A_chan_reg_addr structures
 */
#define	D37A_BASE_REGS_VALUES \
	{DMA_0ADR, DMA_0WCNT, DMA_0PAGE, DMAC1_CLFF, \
	    DMAC1_CMD, DMAC1_MODE, DMAC1_MASK, DMAC1_STAT, DMAC1_REQ, \
	    DMA_0HPG, DMA_0XCNT, DMAC1_EWM, DMAC1_SCM}, \
	{DMA_1ADR, DMA_1WCNT, DMA_1PAGE, DMAC1_CLFF, \
	    DMAC1_CMD, DMAC1_MODE, DMAC1_MASK, DMAC1_STAT, DMAC1_REQ, \
	    DMA_1HPG, DMA_1XCNT, DMAC1_EWM, DMAC1_SCM}, \
	{DMA_2ADR, DMA_2WCNT, DMA_2PAGE, DMAC1_CLFF, \
	    DMAC1_CMD, DMAC1_MODE, DMAC1_MASK, DMAC1_STAT, DMAC1_REQ, \
	    DMA_2HPG, DMA_2XCNT, DMAC1_EWM, DMAC1_SCM}, \
	{DMA_3ADR, DMA_3WCNT, DMA_3PAGE, DMAC1_CLFF, \
	    DMAC1_CMD, DMAC1_MODE, DMAC1_MASK, DMAC1_STAT, DMAC1_REQ, \
	    DMA_3HPG, DMA_3XCNT, DMAC1_EWM, DMAC1_SCM}, \
	{DMA_4ADR, DMA_4WCNT, DMA_4PAGE, DMAC2_CLFF, \
	    DMAC2_CMD, DMAC2_MODE, DMAC2_MASK, DMAC2_STAT, DMAC2_REQ, \
	    DMA_4HPG, DMA_4XCNT, DMAC2_EWM, DMAC2_SCM}, \
	{DMA_5ADR, DMA_5WCNT, DMA_5PAGE, DMAC2_CLFF, \
	    DMAC2_CMD, DMAC2_MODE, DMAC2_MASK, DMAC2_STAT, DMAC2_REQ, \
	    DMA_5HPG, DMA_5XCNT, DMAC2_EWM, DMAC2_SCM}, \
	{DMA_6ADR, DMA_6WCNT, DMA_6PAGE, DMAC2_CLFF, \
	    DMAC2_CMD, DMAC2_MODE, DMAC2_MASK, DMAC2_STAT, DMAC2_REQ, \
	    DMA_6HPG, DMA_6XCNT, DMAC2_EWM, DMAC2_SCM}, \
	{DMA_7ADR, DMA_7WCNT, DMA_7PAGE, DMAC2_CLFF, \
	    DMAC2_CMD, DMAC2_MODE, DMAC2_MASK, DMAC2_STAT, DMAC2_REQ, \
	    DMA_7HPG, DMA_7XCNT, DMAC2_EWM, DMAC2_SCM}

extern int d37A_init(dev_info_t *);
extern void d37A_dma_disable(int);
extern void d37A_dma_enable(int);
extern void d37A_dma_swstart(int);
extern void d37A_dma_stop(int);
extern void d37A_get_chan_stat(int, ulong_t *, int *);
extern int d37A_dma_valid(int);
extern void d37A_dma_release(int);

/* The following 3 routines are intel specific : man page ddi_dmae_req(9S) */
#if defined(__i386) || defined(__amd64)
extern uchar_t d37A_get_best_mode(struct ddi_dmae_req *);
extern int d37A_prog_chan(struct ddi_dmae_req *, ddi_dma_cookie_t *, int);
extern int d37A_dma_swsetup(struct ddi_dmae_req *, ddi_dma_cookie_t *, int);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DMA_I8237A_H */
