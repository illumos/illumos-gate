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
 * Copyright (c) 1990,1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_BPP_REG_H
#define	_SYS_BPP_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Header file describing the hardware for the
 *	bidirectional parallel port
 *	driver (bpp) for the Zebra SBus card.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*	Structure definitions and locals #defines below */

struct bpp_regs	{			/* bpp register	definitions 	*/
	uint_t	dma_csr;		/* dma control and status register  */
	uint_t	dma_addr;		/* Address register.		*/
	uint_t	dma_bcnt;		/* Byte count register		*/
	uint_t	unused;			/* to fill the hole		*/

	ushort_t hw_config;		/* Hardware configuration reg	*/
	ushort_t op_config;		/* Operation config register	*/

	uchar_t	data;			/* parallel port data		*/
	uchar_t	trans_cntl;		/* transfer control register	*/
	uchar_t	out_pins;		/* output pins register		*/
	uchar_t	in_pins;		/* input pins register		*/
	ushort_t int_cntl;		/* interrupt control register	*/
					/* Blame Ira for this misplaced short */

};

/* #defines for bits in the dma_csr register */
#define	BPP_INT_PEND		0x00000001 /* pp dma or control intr pending */
#define	BPP_ERR_PEND		0x00000002 /* SBus error pending	*/
#define	BPP_DRAINING		0x0000000c /* cache is draining	*/
#define	BPP_INT_EN		0x00000010 /* Enable interrupts	*/
#define	BPP_FLUSH		0x00000020 /* Flush the cache	*/
#define	BPP_SLAVE_ERR		0x00000040 /* Slave cycle size error */
#define	BPP_RESET_BPP		0x00000080 /* Hardware reset parallel port */
#define	BPP_READ		0x00000100 /* DMA transfer direction */
#define	BPP_ENABLE_DMA		0x00000200 /* Enable dma transfers	*/
#define	BPP_ENABLE_BCNT		0x00002000 /* Enable byte counter in dma */
#define	BPP_TERMINAL_CNT	0x00004000 /* Terminal count flag	*/
#define	BPP_BURST_SIZES_MASK	0x000c0000 /* SBus burst sizes flags	*/
#define	BPP_TC_INTR_DISABLE	0x00800000 /* DISABLE terminal count intr  */
#define	BPP_EN_CHAIN_DMA	0x01000000 /* Enable chained dma */
#define	BPP_DMA_ON		0x02000000 /* DMA is on	*/
#define	BPP_ADDR_VALID		0x04000000 /* addr and bcnt are valid */
#define	BPP_NEXT_VALID		0x08000000 /* next addr and bcnt valid */
#define	BPP_DEVICE_ID_MASK	0xf0000000 /* device id field */

/* #defines for the dma_csr register */
#define	BPP_BURST_4WORD		0x00000000	/* 4 word read, 4 word write */
#define	BPP_BURST_16BYTE	BPP_BURST_4WORD	/* 4 words = 16 bytes	*/
#define	BPP_BURST_DEFAULT	BPP_BURST_4WORD
#define	BPP_BURST_8WORD		0x00040000	/* 8 word read, 8 word write */
#define	BPP_BURST_32BYTE	BPP_BURST_8WORD	/* 8 words = 32 bytes	*/
#define	BPP_BURST_1WORD		0x00080000	/* no-burst read and write */
#define	BPP_BURST_4BYTE		BPP_BURST_1WORD	/* 1 word = 4 bytes	*/
#define	BPP_BURST_NOBURST	BPP_BURST_1WORD
#define	BPP_HIOD_DEVID		0x40000000	/* HIOD BPP (zebra) 	*/
#define	BPP_DMA2P_DEVID		0xa0000000	/* DMA2P BPP (campus2) 	*/

/* #defines for the dma_addr register */
#define	BPP_MAX_DMA		0x01000000	/* 16 MB DMA boundary	*/

/* #defines for the hw_config register */
#define	BPP_DSS_MASK		0x007f	/* 7-bit DSS value mask		*/
#define	BPP_DSS_SIZE		0x007f	/* 7-bit DSS size mask		*/
#define	BPP_DSW_MASK		0x7f00	/* 7-bit DSW value mask		*/
#define	BPP_DSW_SIZE		0x007f	/* 7-bit DSW size mask		*/
#define	BPP_CNTR_TEST		0x8000	/* Allow reading buried counters */
#define	BPP_SEVEN_BITS		0x007f	/* mask for allowable DSS, DSW values */

/* #defines for the op_config register */
	/* WARNING - the EN_VERSATEC bit will disallow lpvi operation	*/
#define	BPP_EN_VERSATEC		0x0001	/* Enable versatec operation	*/
#define	BPP_VERSATEC_INTERLOCK	0x0002	/* Versatec connector absent	*/
#define	BPP_IDLE		0x0008	/* data transfer idle		*/
#define	BPP_SRST		0x0080	/* reset state machines		*/
#define	BPP_ACK_OP		0x0100	/* Acknowledge handshake op	*/
#define	BPP_BUSY_OP		0x0200	/* Busy handshake op		*/
#define	BPP_EN_DIAG		0x0400	/* Enable diagnostic mode	*/
#define	BPP_ACK_BIDIR		0x0800	/* Acknowledge is bidirectional	*/
#define	BPP_BUSY_BIDIR		0x1000	/* Busy is bidirectional	*/
#define	BPP_DS_BIDIR		0x2000	/* Data Strobe is bidirectional	*/
#define	BPP_DMA_DATA		0x4000	/* Data value in DMA mem clear	*/
#define	BPP_EN_MEM_CLR		0x8000	/* Enable DMA memory clear op	*/

/* #defines for the trans_cntl register */
#define	BPP_DS_PIN		0x01	/* Data strobe pin		*/
#define	BPP_ACK_PIN		0x02	/* Acknowledge pin		*/
#define	BPP_BUSY_PIN		0x04	/* Busy pin (active low)	*/
#define	BPP_DIRECTION		0x08	/* Direction cntl (0 = write)	*/

/*
 * the out_pins register takes the same #defines as the
 * output_reg_pins field of the bpp_pins structure, defined in bpp_io.h.
 * The #defines are included here for reference only.
 *
 * BPP_SLCTIN_PIN	0x01	 Select in pin
 * BPP_AFX_PIN		0x02	 Auto feed pin
 * BPP_INIT_PIN		0x04	 Initialize pin
 * BPP_V1_PIN		0x08	 Versatec pin 1
 * BPP_V2_PIN		0x10	 Versatec pin 2
 * BPP_V3_PIN		0x20	 Versatec pin 3
 */

/*
 * the in_pins register takes the same #defines as the
 * input_reg_pins field of the bpp_pins structure, defined in bpp_io.h.
 * The #defines are included here for reference only.
 *
 * BPP_ERR_PIN		0x01	 Error pin
 * BPP_SLCT_PIN		0x02	 Select pin
 * BPP_PE_PIN		0x04	 Paper empty pin
 */

/* #defines for the int_cntl register */
#define	BPP_ERR_IRQ_EN		0x0001	/* ERR interrupt enable		*/
#define	BPP_ERR_IRP		0x0002	/* ERR intr polarity: 1=rising edge */
#define	BPP_SLCT_IRQ_EN		0x0004	/* SLCT interrupt enable	*/
#define	BPP_SLCT_IRP		0x0008	/* SLCT intr polarity: 1=rising edge */
#define	BPP_PE_IRQ_EN		0x0010	/* PE interrupt enable		*/
#define	BPP_PE_IRP		0x0020	/* PE intr polarity: 1=rising edge */
#define	BPP_BUSY_IRQ_EN		0x0040	/* BUSY interrupt enable	*/
#define	BPP_BUSY_IRP		0x0080	/* BUSY intr polarity: 1=rising edge */
#define	BPP_ACK_IRQ_EN		0x0100	/* ACK+ interrupt enable	*/
#define	BPP_DS_IRQ_EN		0x0200	/* DIR+ interrupt enable	*/
#define	BPP_ERR_IRQ		0x0400	/* ERR interrupt pending	*/
#define	BPP_SLCT_IRQ		0x0800	/* SLCT interrupt pending	*/
#define	BPP_PE_IRQ		0x1000	/* PE interrupt pending		*/
#define	BPP_BUSY_IRQ		0x2000	/* BUSY interrupt pending	*/
#define	BPP_ACK_IRQ		0x4000	/* ACK interrupt pending	*/
#define	BPP_DS_IRQ		0x8000	/* DS interrupt pending		*/
#define	BPP_ALL_IRQS	(BPP_ERR_IRQ | BPP_SLCT_IRQ | BPP_PE_IRQ | \
			BPP_BUSY_IRQ | BPP_ACK_IRQ | BPP_DS_IRQ)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BPP_REG_H */
