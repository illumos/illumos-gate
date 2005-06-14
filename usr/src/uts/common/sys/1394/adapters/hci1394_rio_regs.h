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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_RIO_REGS_H
#define	_SYS_1394_ADAPTERS_HCI1394_RIO_REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_rio_regs.h
 *    Sun Microsystems RIO chipset
 *    See the RIO specification (r1.0), section 5.9, for a description
 *    of the vendor specific registers.
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * RIO's vendor specific register mapping information.  What register set it
 * uses and the offset/size of the register set.
 */
#define	RIOREG_REG_BASE		0x2
#define	RIOREG_OFFSET		0x0
#define	RIOREG_LENGTH		0x800

/*
 * For RIO pass 1, we will setup the GUID in as part of the vendor specific
 * init. This is to support the RIO PPX card (since it does not have firmware
 * to setup the GUID.
 */
#define	RIOREG_GUID_MASK		0x000000FFFFFFFFFF
#define	RIOREG_GUID_SUN_MICROSYSTEMS	0x0800200000000000
#define	RIOREG_SUNW_RIO_PASS1		0x01080020

/*
 * RIO vendor specific registers.  These are the offsets of the registers. They
 * should be used as paramteres to hci1394_vendor_reg_write() and
 * hci1394_vendor_reg_read().
 */
#define	RIOREG_INTR_EVENT	0x00
#define	RIOREG_INTR_MASK	0x04
#define	RIOREG_DMA_BURST_SIZE	0x08
#define	RIOREG_XMIT_CONTROL	0x0C
#define	RIOREG_HOST_CONTROL	0x10
#define	RIOREG_STATS_RETRIES	0x14
#define	RIOREG_STATS_ERRORS	0x18
#define	RIOREG_STATS_PHYSICAL	0x1C

/* RIO interrupt event & mask bit offsets */
#define	RIOREG_INTR_STATS1	0x001
#define	RIOREG_INTR_STATS2	0x002
#define	RIOREG_INTR_STATS3	0x004
#define	RIOREG_INTR_STATS4	0x008
#define	RIOREG_INTR_STATS5	0x010
#define	RIOREG_INTR_STATS6	0x020
#define	RIOREG_INTR_STATS7	0x040
#define	RIOREG_INTR_STATS8	0x080
#define	RIOREG_INTR_LINKON	0x100

/* dma_burst_size (field defs) */
#define	RIOREG_INF_BURST_SHIFT	0
#define	RIOREG_DBURST_SHIFT	1
#define	RIOREG_RXBURST_SHIFT	26
#define	RIOREG_TXBURST_SHIFT	28
#define	RIOREG_PFBURST_SHIFT	30
#define	RIOREG_INF_BURST_MASK	(1 << RIOREG_INF_BURST_SHIFT)
#define	RIOREG_DBURST_MASK	(1 << RIOREG_DBURST_SHIFT)
#define	RIOREG_RXBURST_MASK	(3 << RIOREG_RXBURST_SHIFT)
#define	RIOREG_TXBURST_MASK	(3 << RIOREG_TXBURST_SHIFT)
#define	RIOREG_PFBURST_MASK	(3 << RIOREG_PFBURST_SHIFT)

/* dma_burst_size (values) */
#define	RIOREG_BURST_32		0 /* 32 bytes or less */
#define	RIOREG_BURST_64		1 /* 64 bytes or less */
#define	RIOREG_BURST_128	2 /* 128 bytes or less */
#define	RIOREG_BURST_256	3 /* 256 bytes or less */

/* xmit ctrl (field defs) */
#define	RIOREG_XMIT_BND1_SHIFT	0
#define	RIOREG_XMIT_BND2_SHIFT	8
#define	RIOREG_XMIT_BND1_MASK	(0xFF << RIOREG_XMIT_BND1_SHIFT)
#define	RIOREG_XMIT_BND2_MASK	(0xFF << RIOREG_XMIT_BND2_SHIFT)

/* host control (field defs) */
#define	RIOREG_HOST_ATREQ	0x00000001
#define	RIOREG_HOST_ATRESP	0x00000002
#define	RIOREG_HOST_IT1		0x00000004
#define	RIOREG_HOST_IT2		0x00000008
#define	RIOREG_HOST_IT3		0x00000010
#define	RIOREG_HOST_IT4		0x00000020
#define	RIOREG_HOST_ARREQ	0x00000040
#define	RIOREG_HOST_ARRESP	0x00000080
#define	RIOREG_HOST_IR1		0x00000100
#define	RIOREG_HOST_IR2		0x00000200
#define	RIOREG_HOST_IR3		0x00000400
#define	RIOREG_HOST_IR4		0x00000800
#define	RIOREG_HOST_BWCAT	0x02000000
#define	RIOREG_HOST_BRCAT	0x04000000
#define	RIOREG_HOST_ISOCTL	0xC0000000

/* Allow Descriptor pre-fetching */
#define	RIOREG_HOST_CONTROL_SETTING	\
	(RIOREG_HOST_ATREQ | RIOREG_HOST_ATRESP | RIOREG_HOST_IT1 | \
	RIOREG_HOST_IT2 | RIOREG_HOST_IT3 | RIOREG_HOST_IT4 | \
	RIOREG_HOST_ARREQ | RIOREG_HOST_ARRESP | RIOREG_HOST_IR1 | \
	RIOREG_HOST_IR2 | RIOREG_HOST_IR3 | RIOREG_HOST_IR4)

/* stats_retries (field defs) */
#define	RIOREG_RET_PHYS		0xFF000000
#define	RIOREG_RET_ATS		0x0000FF00
#define	RIOREG_RET_ATQ		0x000000FF

/* stats_errors (field defs) */
#define	RIOREG_ERR_EACKR	0x000000FF
#define	RIOREG_ERR_EACKX	0x0000FF00
#define	RIOREG_ERR_BUS		0x0FFF0000

/* stats_phys (field defs) */
#define	RIOREG_PHYS_WRQ		0x000000FF
#define	RIOREG_PHYS_RDQ		0x00FF0000


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_1394_ADAPTERS_HCI1394_RIO_REGS_H */
