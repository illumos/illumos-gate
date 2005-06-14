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
 * Copyright (c) 1988-1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DMAGA_H
#define	_SYS_DMAGA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * New SUN DMA gate array definitions, revisions 1 and 2.
 *
 * Generally, this dma engine is owned exclusively by a SCSI host
 * adapter chip (ESP or ESP-2). Strictly speaking, a lance chip
 * (AMD 7990 Local Area Ethernet Chip) is hung off of it as well,
 * but there is very little we can do to the gate array to affect
 * the lance.
 *
 * NOTE: On SS1 with DMA rev 1 it is essential that prior to accessing
 *	 the D-channel (esp) registers, the dma is disabled. If not
 *	 a watchdog reset or data access may follow
 */


struct dmaga {
	uint32_t dmaga_csr;	/* control/status register */
	/*
	 * Dma Address Register
	 *
	 * For DMA Rev1, strictly speaking, the msb is an 8 bit
	 * register and the 24 lsbs are a counter. This asssumes
	 * that no transfer will cross a 16mb boundary. This
	 * restriction does not apply for anything but DMA rev1.
	 */
	uint32_t dmaga_addr;
	uint32_t dmaga_count;	/* count register. Only the 24 lsbs matter */
	uint32_t dmaga_diag;	/* undefined - unused */
};

#define	SET_DMAESC_COUNT(dmar, val) (dmar)->dmaga_count = val

/* bits in the dma gate array status register */
#define	DMAGA_INTPEND	0x0001	/* (r)	Interrupt pending. */
				/* 	Clear when device drops INT. */
				/*	ESC: only ESP interrupt pending. */

#define	DMAGA_ERRPEND	0x0002	/* (r) error pending on memory exception */

/*
 * The following two defines apply only to rev1 (DMA) gate arrays
 */
#define	DMAGA_PACKCNT	0x000C	/* (r) number of bytes in pack register */
#define	DMAGA_NPACKED(x)	(((x)->dmaga_csr & DMAGA_PACKCNT) >> 2)

/*
 * The following define applies only to rev2 (DMA+), rev3 (DMA2),
 * and ESC gate arrays.
 */

#define	DMAGA_DRAINING	0x000C

#define	DMAGA_INTEN	0x0010	/* (r/w)	Interrupt enable. */
				/*	Sad but true: you have to turn this */
				/*	on to get any interrupts from the */
				/*	ESP SCSI chip..... */

#define	DMAGA_FLUSH	0x0020	/* (w) 1 == clears PACKCNT, ERRPEND and TC */

/*
 * The following define applies only to rev1 (DMA) gate arrays
 */
#define	DMAGA_DRAIN	0x0040	/* (r/w) 1 == pushes PACKCNT bytes to memory */
/*
 * The following define applies only to rev2 (DMA+), rev3 (DMA2),
 * and ESC gate arrays.
 */
#define	DMAGA_SLVERR	0x0040	/* (r) Set on slave size error. Reset on */
				/* csr read.  */

#define	DMAGA_RESET	0x0080	/* (r/w) 1 == reset dma gate array */
				/*	May or may not reset attached */
				/*	devices (e.g. ESP chip). */

#define	DMAGA_WRITE	0x0100	/* (r/w) DVMA direction */
				/*	1 == TO MEMORY */
				/*	0 == FROM MEMORY */

#define	DMAGA_ENDVMA	0x0200	/* (r/w) 1 == dmaga responds to dma requests */

/*
 * The following define applies only to rev1 (DMA) and ESC gate arrays
 */
#define	DMAGA_REQPEND	0x0400	/* (r) 1 == dma gate array active */
				/*	NO reset and flush allowed */

/*
 * The following defines thru DMAESC_EN_ADD apply only to ESC gate arrays
 */
#define	DMAESC_BSIZE	0x0800	/* (r/w) maximum burst size */
				/*	1 = 16 bytes */
				/*	0 = 32 bytes */
#define	DMAESC_SETBURST16(d)	(d)->dmaga_csr |= DMAESC_BSIZE
#define	DMAESC_SETBURST32(d)	(d)->dmaga_csr &= ~DMAESC_BSIZE

#define	DMAESC_TCZERO	0x1000	/* (r) set when transfer count becomes 0 */

#define	DMAESC_EN_TCI	0x2000	/* (r/w) enable interrupt generation on */
				/*	  expiration of count */

#define	DMAESC_INTPEND	0x4000	/* (r) interrupt summary - 3 sources: */
				/*	1) DMAESC_SCSI_INT - ESP interrupt */
				/*	2) DMAESC_TCZERO - transfer count 0 */
				/*	3) DMAESC_PERR -  parity error */

#define	DMAESC_PEN	0x8000	/* (r/w) sbus parity enable */

#define	DMAESC_PERR	0x00010000	/* (r) sbus parity error */

#define	DMAESC_DRAIN	0x00020000	/* (w) write 1 to drain data in */
					/*	buffer. */
					/*	ignored if DMAESC_EN_AD set */

#define	DMAESC_EN_ADD	0x00040000	/* (r/w) enable auto-drain */
					/* Note: overlap with DMA2 define */
					/* below. */

/*
 * The following two defines apply only to rev1 (DMA) gate arrays
 */
#define	DMAGA_BYTEADR	0x1800	/* (r) next byte to be accessed */
#define	DMAGA_NEXTBYTE(x)	(((x)->dmaga_csr & DMAGA_BYTEADR) >> 11)

#define	DMAGA_ENATC	0x2000	/* (r/w) enable byte counter */

/*
 * The following two defines apply only to rev1 (DMA) and rev 2 (DMA+)
 * gate arrays
 */
#define	DMAGA_TC	0x4000	/* (r) terminal count reached */

#define	DMAGA_ILACC	0x8000	/* 'new' ethernet chip enabled- modifies */
				/* lance DMA read cycle. This is not */
				/* currently implemented and is not available */
				/* for DMA2 or ESC. */

/*
 * The following define is available only for rev3 (DMA2) gate arrays
 *
 * Do not set NOBURST and BURST64 at the same time (this is reserved
 * and will have undefined effects). Instead, clear the BURSTMASK
 * field and set what you want.
 */

#define	DMAGA_BURSTMASK	0x000C0000	/* Burst size field. */
#define	DMAGA_BURST16	0x00000000	/* 16 Byte bursts (default). */
					/* Comaptible with DMA+.  */
#define	DMAGA_NOBURST	0x00080000	/* No bursts. */
#define	DMAGA_BURST32	0x00040000	/* 32 Byte bursts. */

#define	DMA2_SETNOBURST(d)	\
	(d)->dmaga_csr &= ~DMAGA_BURSTMASK, (d)->dmaga_csr |= DMAGA_NOBURST
#define	DMA2_SETBURST16(d)	(d)->dmaga_csr &= ~DMAGA_BURSTMASK
#define	DMA2_SETBURST32(d)	\
	(d)->dmaga_csr &= ~DMAGA_BURSTMASK, (d)->dmaga_csr |= DMAGA_BURST32

/*
 * The following defines up through the DMAGA_DEVID are valid only for
 * rev2 (DMA+) gate arrays.
 */


#define	DMAGA_ALE	0x00100000	/* (r/w) defines pin 27 as ALE */
					/* (address latch enable) or AS* */
					/* (address strobe). 1 = ALE, */
					/* 0 = AS* (defaults to 0). This */
					/* for different types of lance */
					/* dma handshaking. This is not */
					/* currently implemented and is */
					/* not available on DMA2 or ESC. */

#define	DMAGA_LERR	0x00200000	/* (r) Set when a memory error occurs */
					/* on a transfer to/from LANCE. */
					/* Clears on a slave write to LANCE. */
					/* This is not currently used by any */
					/* standard s/w, and is not */
					/* implemented on DMA2 or ESC. */

#define	DMAGA_TURBO	0x00400000	/* (r/w) turns on 'faster' mode for */
					/* use with the 53C90A scsi chip.  */

#define	DMAGA_NOTCINT	0x00800000	/* (r/w) Disable TC (terminal count) */
					/* interrupts (if set). Defaults to */
					/* 0. Note that in order to get TC */
					/* ints you have to enable the byte */
					/* counter by setting DMAGA_ENATC. */
					/* If you enable the byte counter, */
					/* but also set this bit, you can get */
					/* dma transfer limited by a byte */
					/* counter w/o dealing with */
					/* interrupts. */

/*
 * The following defines are valid only for rev3 (DMA2) gate arrays.
 */

#define	DMAGA_TWO_CYCLE 0x00200000


/*
 * The next three defines are for the 'Next-address' autoload mechanism
 *
 * This mechanism is a somewhat complicated mechanism for pipelining DMA
 * transfers. In the rev2 (DMA+) gate array, there are next_address and
 * next_bytecnt registers that hide at the same address as the address
 * and byte_count registers.
 *
 * The best way to describe how this works is to paraphrase from the S4-DMA+
 * chip document (prelim, 7/12/89):
 *
 *
 * If The DMAGA_ENANXT bit in dmaga_ csr is set, then a write to the
 * dmaga_addr register will will write to the NEXT_ADDR register instead.
 * If the DMAGA_ENANXT bit is set when the byte counter (dmaga_count)
 * expires, and the NEXT_ADDR regsiter has been written to since the last
 * time the byte counter expired, then the contents of the NEXT_ADDR
 * register are copied to the dmaga_addr register. If DMAGA_ENANXT is set
 * when the byte counter (dmaga_count) expires, but the NEXT_ADDR register
 * has not been written to since the last time the byte counter expired,
 * then DMA activity is stopped and DMA request from the ESP will be
 * ignored until NEXT_ADDR is written to, or DMAGA_ENANXT is cleared.
 * (Also, the DMAGA_DMAON bit will read as 0 while DMA is stopped because
 * of this). When DMA is re-enabled by writing to the NEXT_ADDR register,
 * the contents of the NEXT_ADDR register are copied to the dmaga_addr
 * register before DMA activity actually begins.
 *
 * ...
 *
 * If the DMAGA_ENANXT bit in dmaga_csr is set, then a write to dmaga_count
 * will write to the NEXT_BCNT register instead. If the NEXT_ADDR register
 * is being copied into dmaga_addr, and DMAGA_ENANXT is set, then the
 * NEXT_BCNT register will be copied into dmaga_count at the same time.
 *
 * (whew!)
 */

#define	DMAGA_ENANXT	0x01000000	/* (r/w) Enable 'next-address' */
					/* autoload mechanism (see above). */

#define	DMAGA_DMAON	0x02000000	/* (r) reads as 1 when: */
					/*  (DMAGA_ALOAD || DMAGA_NALOAD) && */
					/*	DMAGA_ENDVMA && */
					/*	!(DMAGA_ERRPEND) */

#define	DMAGA_ALOAD	0x04000000	/* (r) Address Loaded (see above). */

#define	DMAGA_NALOAD	0x08000000	/* (r) Next Address loaded */
					/* (see above). */

/*
 * burstsizes
 */
#define	BURST1		0x01
#define	BURST2		0x02
#define	BURST4		0x04
#define	BURST8		0x08
#define	BURST16		0x10
#define	BURST32		0x20
#define	BURST64		0x40
#define	BURSTSIZE_MASK	0x7f
#define	DEFAULT_BURSTSIZE	BURST16|BURST8|BURST4|BURST2|BURST1


/*
 * Gate Array id bits:
 */

#define	DMAGA_DEVID	0xF0000000	/* (r) Device ID */
#define	DMAGA_REV(x)	(((x)->dmaga_csr & DMAGA_DEVID) >> 28)

#define	DMA_REV1	0x8	/* DMA gate array */
#define	DMA_REV2	0x9	/* DMA+ gate array */
#define	ESC1_REV1	0x4	/* ESC gate array */
#define	DMA_REV3	0xA	/* DMA2 gate array */


/*
 * Compound conditions for interrupt and error checking.
 */

#define	DMAGA_CHK_MASK	(DMAGA_INTPEND | DMAGA_ERRPEND | DMAGA_REQPEND)
#define	DMAGA_INT_MASK	(DMAGA_INTPEND | DMAGA_ERRPEND)

/*
 * %b formatted error strings
 */

#define	DMAGA_BITS	\
"\20\20ILACC\17TC\13RQPND\12EN\11IN\10RST\7DRAIN\6FLSH\5INTEN\2ERRPEND\1INTPND"

#ifdef	_KERNEL

extern struct dmaga *dma_alloc(dev_info_t *cdev);
extern void dma_free(struct dmaga *regs);
extern int dma_affinity(dev_info_t *dma, dev_info_t *cdev);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMAGA_H */
