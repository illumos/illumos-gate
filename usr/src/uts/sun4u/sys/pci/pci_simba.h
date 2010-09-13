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
 * Copyright (c) 1994-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PCI_SIMBA_H
#define	_SYS_PCI_SIMBA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This files contains info specific to Simba (pci to pci bridge)
 * The rest of info common to simba and DecNet are in "pci.h"
 */

/*
 * Simba configuration space registers.
 */
#define	PCI_BCNF_SECSTATUS		0x1e	/* secondary status */

/*
 * Simba device specific registers.
 */
#define	PCI_BCNF_MATER_RETRY_LIMIT	0xc0	/* primary master retry limit */
#define	PCI_BCNF_DMA_AFSR		0xc8	/* dma afsr */
#define	PCI_BCNF_DMA_AFAR		0xd0	/* dma afar */
#define	PCI_BCNF_PIOTGT_RTY_LIMIT	0xd8	/* pio target retry limit */
#define	PCI_BCNF_PIOTGT_LATE_TIMER	0xd9	/* pio target retry limit */
#define	PCI_BCNF_DMATGT_RTY_LIMIT	0xda	/* dma target retry limit */
#define	PCI_BCNF_DMATGT_LATE_TIMER	0xdb	/* dma target retry limit */
#define	PCI_BCNF_TGT_RETRY_LIMIT	0xdc	/* primary master retry limit */
#define	PCI_BCNF_SECBRIDGE_CTL		0xdd	/* secondary bridge control */
#define	PCI_BCNF_ADDR_MAP		0xdf	/* address map */

/*
 * Psycho compatible registers.
 */
#define	PCI_BCNF_CTL_STAT		0xe0	/* control-status */
#define	PCI_BCNF_PIO_AFSR		0xe8	/* pio afsr */
#define	PCI_BCNF_PIO_AFAR		0xf0	/* pio afar */

/*
 * Simba device specific registers.
 */
#define	PCI_BCNF_DIAGNOSTICS		0xf8	/* diagnostics */


/*
 * primary/secondary timer reg mask(addrs = 0x0d/0x1b).
 */
#define	PCI_LATENCY_TMR_LO		0x7	/* read only part, 0x0 */
#define	PCI_LATENCY_TMR_HI		0xf8	/* programable part */

/*
 * PCI secondary status register bits.
 * All bit definitions are the same as primary status register,
 * but the meaning of bit 14 relates to secondary bus.
 */


/*
 * Secondary control bit defines(addrs = 0xdd).
 */
#define	PCI_SEC_CNTL_PIO_PREF		0x1	/* prefetch dma reads as pio */
#define	PCI_SEC_CNTL_CONVT_MRM		0x2	/* convert mem multiple read */

/*
 * Psycho ctrl/status reg bit defines(addrs = 0xe0).
 */
#define	PCI_PSYCHO_SLOT_ENAM_MASK	0xf	/* slot arbiter enable mask */
#define	PCI_PSYCHO_SEC_ERRINIT_ENAB	0x100	/* 1=forward SERR to primary */
#define	PCI_PSYCHO_WAKEUP_ENAB		0x200   /* not used, reads as 0 */
#define	PCI_PSYCHO_SBH_INT_ENAB		0x400   /* not used, reads as 0 */
#define	PCI_PSYCHO_SLOT_PRIORITY	0xf0000 /* slot arb priority mask */
#define	PCI_PSYCHO_CPU_PRIORITY		0x100000 /* pio arb priority (simba) */
#define	PCI_PSYCHO_PBUS_PARK_ENAB	0x200000 /* pci bus parking enable */
#define	PCI_PSYCHO_INTER_ARB_ENAB	0x100000000 /* enable internal arb */
#define	PCI_PSYCHO_PCI_SPEED		0x200000000 /* not used, reads as 0 */
#define	PCI_PSYCHO_PCI_SYS_ERROR	0x800000000 /* set, if err on 2ndary */
#define	PCI_PSYCHO_PCI_SBH_ERROR	0x1000000000 /* not used, reads as 0 */

/*
 * Psycho AFSR reg bit defines(addrs = 0xe8).
 */
#define	PCI_PSYCHO_ERR_NUM		0xff		/* error index number */
#define	PCI_PSYCHO_MID_MASK		(0x1f<<25)	/* mid mask, reads 0 */
#define	PCI_PSYCHO_BLK			(1<<31)		/* block, reads 0 */
#define	PCI_PSYCHO_BYTE_MASK		(0xffff<<32)	/* byte mask, reads 0 */
#define	PCI_PSYCHO_SEC_APERR		(1<<54)    	/* 2ndary adr par err */
#define	PCI_PSYCHO_PRI_APERR		(1<<55)		/* pri addr par err */
#define	PCI_PSYCHO_SEC_PERR		(1<<56)		/* 2nd data par err */
#define	PCI_PSYCHO_SEC_RTRY_ERR		(1<<57)		/* 2nd retry err */
#define	PCI_PSYCHO_SEC_TA_ERR		(1<<58)		/* 2nd tgt abort err */
#define	PCI_PSYCHO_SEC_MA_ERR		(1<<59)		/* 2nd mstr abort err */
#define	PCI_PSYCHO_PRI_PERR		(1<<60)		/* pri data par error */
#define	PCI_PSYCHO_PRI_RTRY_ERR		(1<<61)		/* pri retry error */
#define	PCI_PSYCHO_PRI_TA_ERR		(1<<62)		/* mstr tgt abort err */
#define	PCI_PSYCHO_PRI_MA_ERR		(1<<63)		/* mstr mstr abrt err */


/*
 * notice: In Simba, AFAR will log statring address of transaction with error
 *		The byte offset will be logged in [7:0] of AFSR.
 */

/*
 * Diagnostics reg bit defines(size=d word)(addrs = 0xf8).
 */
#define	PCI_DIAG_IDMA_WDATA_PAR		0x1	/* invert dma wr data parity */
#define	PCI_DIAG_IDMA_RDATA_PAR		0x2	/* invert dma rd data parity */
#define	PCI_DIAG_IDMA_ADDR_PAR		0x4	/* invert dma addr parity */
#define	PCI_DIAG_IPIO_WDATA_PAR		0x10	/* invert pio wr data parity */
#define	PCI_DIAG_IPIO_RDATA_PAR		0x20	/* invert pio rd data parity */
#define	PCI_DIAG_IPIO_ADDR_PAR		0x40	/* invert pio addr parity */

/*
 * usefull defines.
 */
#define	PCI_UNLIMITED_RETRY		0x0	/* unlimitted retry */
#define	PCI_UNLIMITED_LATENCY		0x0	/* unlimitted latency */

/*
 * vendor & device id for simba.
 */
#define	PCI_SIMBA_VENID		0x108e  /* vendor id for simba */
#define	PCI_SIMBA_DEVID		0x5000  /* device id for simba */

/*
 * programming interface for simba.
 */
#define	PCI_SIMBA_PRI			0x0	/*  prog interface for simba */

/*
 * master/secondary latency timer value.
 */
#define	PCI_LATENCY_TIMER_VAL		0x28	/* timer value for simba */

/*
 * primary bus number for simba.
 */
#define	PCI_BCNF_PRIBUS_NUM		0x0	/* primary bus # for simba */

/*
 * secondary bus number for simba.
 */
#define	PCI_BCNF_SECBUS_NUM_ONE		0x1	/* secondary bus number one */
#define	PCI_BCNF_SECBUS_NUM_TWO		0x2	/* secondary bus number two */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_SIMBA_H */
