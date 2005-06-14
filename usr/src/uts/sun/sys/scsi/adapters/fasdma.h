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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_ADAPTERS_FASDMA_H
#define	_SYS_SCSI_ADAPTERS_FASDMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SCSI	Channel	Engine (fas SCSI DVMA) definitions
 */
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * for historical reasons, we call the scsi channel engine
 * dma for now
 */
struct dma {
	uint32_t dma_csr;		/* control/status register */
	uint32_t dma_addr;		/* dma address register	*/
	uint32_t dma_count;		/* count register */
	uint32_t dma_test;		/* test csr register */
};


/*
 * dma_csr bits
 */
#define	DMA_INTPEND	0x0001	/* (R) interrupt pending from fas or dma */
#define	DMA_ERRPEND	0x0002	/* (R) error pending from dma */
#define	DMA_DRAINING	0x0004	/* (R) if set, buffers aredraining to mem */
#define	DMA_INTEN	0x0010	/* (RW)	enable interrupts */
#define	DMA_RESET	0x0080	/* (RW)	invalidates the	buffers, resets	CE */
#define	DMA_WRITE	0x0100	/* (RW)	write to memory	*/
#define	DMA_ENDVMA	0x0200	/* (RW)	enable dvma */
#define	DMA_REQPEND	0x0400	/* (R) do not assert reset when	set! */
#define	DMA_DMAREV	0x7800	/* (R) dma revision */
#define	DMA_WIDE_EN	0x8000	/* (RW)	enable wide SBus DVMA mode */
#define	DMA_DSBL_DRAIN  0x00020000	/* (RW)	disable	draining on slave */
					/*	accesses */
#define	DMA_BURSTS  	0x000c0000	/* (RW)	burst sizes */
#define	DMA_TWO_CYCLE	0x00200000	/* (RW)	2 cycle	dma access to 366 */
#define	DMA_DSBL_PARITY	0x02000000	/* (RW)	disables checking for parity */
#define	DMA_PAUSE_FAS	0x04000000	/* (RW)	pause  fas */
#define	DMA_RESET_FAS	0x08000000	/* (RW)	hardware reset to fas */
#define	DMA_DEV_ID	0xf0000000	/* (R)	Device ID (0xb)	*/

#define	DMA_INT_MASK  (DMA_INTPEND | DMA_ERRPEND)

#define	DMA_BITS	\
"\20\34RST\33PSE\31DSBLPAR\26TWOCYC\24BRST1\23BST0\
\22DSBLEDRN\20WIDE\13REQPEND\12ENBLE\11WR\10RST\05INTEN\
\03DRNING\02ERRPEND\01INTPND"

#define	DMAREV(dmap)	(((dmap->dma_csr) & DMA_DMAREV) >> 11)

/*
 * burst sizes for dma
 */
#define	DMA_BURST16	0x00000000
#define	DMA_BURST32	0x00040000
#define	DMA_BURST64	0x000c0000
#define	DMA_CE_ID	0xb0000000	/* SCSI	CE device ID */

/*
 * burst sizes for dma attr
 */
#define	BURST1		0x01
#define	BURST2		0x02
#define	BURST4		0x04
#define	BURST8		0x08
#define	BURST16		0x10
#define	BURST32		0x20
#define	BURST64		0x40
#define	BURSTSIZE_MASK	0x7f
#define	DEFAULT_BURSTSIZE \
		BURST64|BURST32|BURST16|BURST8|BURST4|BURST2|BURST1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_FASDMA_H */
