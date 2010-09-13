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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DB21554_CSR_H
#define	_SYS_DB21554_CSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* CSR Register Offset  definitions */
#define	DB_CSR_DS_CONF_ADDR		0x000	/* DownStream config addres */
#define	DB_CSR_DS_CONF_DATA		0x004	/* downstream config data */
#define	DB_CSR_US_CONF_ADDR		0x008	/* UpStream config address */
#define	DB_CSR_US_CONF_DATA		0x00C	/* UpStream config data */
#define	DB_CSR_CONF_OWN			0x010   /* config own bits - word reg */
#define	DB_CSR8_DS_CONF_OWN		0x010   /* config own bits - byte reg */
#define	DB_CSR8_US_CONF_OWN		0x011   /* config own bits - byte reg */
#define	DB_CSR_CONF_CSR			0x012   /* config ctrl/status - word */
#define	DB_CSR8_DS_CONF_CSR		0x012   /* DS config csr - byte */
#define	DB_CSR8_US_CONF_CSR		0x013   /* US config csr - byte */
#define	DB_CSR_DS_IO_ADDR		0x014	/* DS io address */
#define	DB_CSR_DS_IO_DATA		0x018	/* DS io data */
#define	DB_CSR_US_IO_ADDR		0x01C	/* US io address */
#define	DB_CSR_US_IO_DATA		0x020	/* US io data */
#define	DB_CSR_IO_OWN			0x024	/* IO Own bits - word reg */
#define	DB_CSR8_DS_IO_OWN		0x024	/* DS IO Own bits - byte reg */
#define	DB_CSR8_US_IO_OWN		0x025	/* DS IO Own bits - byte reg */
#define	DB_CSR_IO_CSR			0x026	/* IO csr  - word reg */
#define	DB_CSR8_DS_IO_CSR		0x026	/* DS IO csr - byte reg */
#define	DB_CSR8_US_IO_CSR		0x027	/* US IO csr - byte reg */
#define	DB_CSR_LUT_OFFSET		0x028	/* Lookup Table offset */
#define	DB_CSR_LUT_DATA			0x02C	/* LookUp Table Data */

#define	DB_CSR_I2O_OB_PL_STATUS		0x030	/* I2O outbound postlist stat */
#define	DB_CSR_I2O_OB_PL_INTR_MASK	0x034	/* I2O outbound postlistImask */
#define	DB_CSR_I2O_IB_PL_STATUS		0x038	/* I2O inbound postlist stat */
#define	DB_CSR_I2O_IB_PL_INTR_MASK	0x03C	/* I2O inbound postlist Imask */

#define	DB_CSR_CHIP_STATUS_CSR		0x082	/* chip status CSR */
#define	DB_CSR_CHIP_SET_IRQ_MASK	0x084	/* chip set IRQ mask */
#define	DB_CSR_CHIP_CLR_IRQ_MASK	0x086	/* chip clear IRQ mask */
#define	DB_CSR_US_PAGEBOUND_IRQ0	0x088	/* US page boundary IRQ 0 */
#define	DB_CSR_US_PAGEBOUND_IRQ1	0x08C	/* US page boundary IRQ 1 */
#define	DB_CSR_US_PAGEBOUND_IRQ_MASK0	0x090	/* US page boundary IRQ mask0 */
#define	DB_CSR_US_PAGEBOUND_IRQ_MASK1	0x094	/* US page boundary IRQ mask1 */
#define	DB_CSR_PRIM_CLR_IRQ		0x098	/* Primary Clear IRQ */
#define	DB_CSR_SEC_CLR_IRQ		0x09A	/* Secondary Clear IRQ */
#define	DB_CSR_PRIM_SET_IRQ		0x09C	/* Primary Set IRQ */
#define	DB_CSR_SEC_SET_IRQ		0x09E	/* Secondary Set IRQ */
#define	DB_CSR_PRIM_CLR_IRQ_MASK	0x0A0	/* Primary Clear IRQ Mask */
#define	DB_CSR_SEC_CLR_IRQ_MASK		0x0A2	/* Secondary Clear IRQ Mask */
#define	DB_CSR_PRIM_SET_IRQ_MASK	0x0A4	/* Primary Set IRQ Mask */
#define	DB_CSR_SEC_SET_IRQ_MASK		0x0A6	/* Secondary Set IRQ Mask */
#define	DB_CSR_SCRATCHPAD_0		0x0A8	/* Scratchpad 0 */
#define	DB_CSR_SCRATCHPAD_1		0x0AC	/* Scratchpad 1 */
#define	DB_CSR_SCRATCHPAD_2		0x0B0	/* Scratchpad 2 */
#define	DB_CSR_SCRATCHPAD_3		0x0B4	/* Scratchpad 3 */
#define	DB_CSR_SCRATCHPAD_4		0x0B8	/* Scratchpad 4 */
#define	DB_CSR_SCRATCHPAD_5		0x0BC	/* Scratchpad 5 */
#define	DB_CSR_SCRATCHPAD_6		0x0C0	/* Scratchpad 6 */
#define	DB_CSR_SCRATCHPAD_7		0x0C4	/* Scratchpad 7 */
#define	DB_CSR_ROM_SETUP		0x0C8	/* ROM setup register */
#define	DB_CSR_ROM_DATA			0x0CA	/* ROM Data register */
#define	DB_CSR_ROM_ADDR			0x0CC	/* ROM Address register */
#define	DB_CSR_ROM_CTRL			0x0CF	/* ROM control */
#define	DB_CSR_US_MEM2_LUT		0x100	/* US Memory 2 Lookup Table */

/* Configuration Own Bits register definition */
#define	DS_IO_OWN			0x0001
#define	US_IO_OWN			0x0100
/* the following is a 8bit register bit definitions for IO own */
#define	DS8_IO_OWN			0x01
#define	US8_IO_OWN			0x01

/* IO control status register bits: Register offset 0x26-27 */
#define	IO_DS_OWN_STAT 0x0001  /* downstream config own status */
#define	IO_DS_ENABLE   0x0002  /* enable downstream config cycles */
#define	IO_US_OWN_STAT 0x0100  /* upstream config own status */
#define	IO_US_ENABLE   0x0200  /* enable upstream config cycles */

typedef volatile struct us_mem2_tbl {
	uchar_t		unimpl[256];		/* currently unimplemented */
} us_mem2_tbl_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DB21554_CSR_H */
