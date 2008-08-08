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

#ifndef	_SYS_SDCARD_WBSD_H
#define	_SYS_SDCARD_WBSD_H

/*
 * Private header for the Winbond W83L519D series SD controller.
 */

/*
 * Direct access registers.
 */
#define	REG_CMDR	0x00	/* command register */
#define	REG_DFR		0x01	/* data fifo register */
#define	REG_EIR		0x02	/* enable interrupt register */
#define	REG_ISR		0x03	/* interrupt status register */
#define	REG_FSR		0x04	/* fifo status register */
#define	REG_IDXR	0x05	/* index register */
#define	REG_DATAR	0x06	/* data register */
#define	REG_CSR		0x07	/* card status register */

/*
 * Direct access register values.
 */

/*
 * Note that some sources appear to have mixed up the busy and prog
 * bits.  At least on a Tadpole SPARCLE the bits seem to work as
 * defined here, although note that on SPARC hardware there does not
 * appear to be any kind of DMA support for ebus (ISA).
 */
#define	EIR_CARD	0x40	/* card interrupt */
#define	EIR_FIFO	0x20	/* FIFO threshold reached */
#define	EIR_CRC_ERR	0x10	/* CRC error? */
#define	EIR_TIMEOUT	0x08	/* timeout on CMD or DAT */
#define	EIR_BUSY_END	0x04	/* programming complete */
#define	EIR_PROG_END	0x02	/* busy bit has cleared */
#define	EIR_TC		0x01	/* DMA transfer complete */
#define	EIR_TYPICAL	(EIR_CARD | EIR_CRC_ERR | EIR_TIMEOUT)
#define	EIR_WRITE	(EIR_TYPICAL | EIR_FIFO | EIR_PROG_END)
#define	EIR_READ	(EIR_TYPICAL | EIR_FIFO)
#define	EIR_STOP	(EIR_TYPICAL | EIR_BUSY_END)

#define	ISR_CARD	0x40	/* card interrupt */
#define	ISR_FIFO	0x20	/* FIFO threshold reached */
#define	ISR_CRC_ERR	0x10	/* CRC7 error */
#define	ISR_TIMEOUT	0x08	/* timeout on CMD or DAT */
#define	ISR_BUSY_END	0x04	/* programming complete */
#define	ISR_PROG_END	0x02	/* busy bit has cleared */
#define	ISR_TC		0x01	/* DMA transfer complete */
#define	ISR_WANTED	(ISR_CARD | ISR_FIFO | ISR_CRC_ERR | ISR_TIMEOUT | \
			ISR_BUSY_END | ISR_PROG_END)

#define	FSR_FULL_THRE	0x10
#define	FSR_EMPTY_THRE	0x20
#define	FSR_FULL	0x40
#define	FSR_EMPTY	0x80
#define	FSR_PTR_MASK	0x0F

#define	CSR_PRESENT	0x01
#define	CSR_WPROTECT	0x04
#define	CSR_POWER_N	0x10
#define	CSR_MSLED	0x20

/*
 * Index offsets for indirect registers.
 */
#define	IDX_CLOCK	0x01	/* clock select */
#define	IDX_BLKSZMSB	0x02	/* data width, block size MSB */
#define	IDX_TAAC	0x03	/* TAAC timing spec */
#define	IDX_NSAC	0x04	/* NSAC timing spec */
#define	IDX_BLKSZLSB	0x05	/* block size LSB */
#define	IDX_RESET	0x06	/* reset */
#define	IDX_DMA		0x07	/* DMA setting */
#define	IDX_THRESH	0x08	/* FIFO threshold control */
#define	IDX_PID_1	0x0E	/* product id */
#define	IDX_PID_2	0x0F	/* product id */
#define	IDX_STATUS	0x10	/* chip status */
#define	IDX_CMD		0x11	/* first command index */
#define	IDX_RESP_TYPE	0x1E
#define	IDX_RESP_0	0x1F
#define	IDX_RESP_1	0x20
#define	IDX_RESP_2	0x21
#define	IDX_RESP_3	0x22
#define	IDX_RESP_4	0x13
#define	IDX_RESP_5	0x24
#define	IDX_RESP_6	0x25
#define	IDX_RESP_7	0x26
#define	IDX_RESP_8	0x27
#define	IDX_RESP_9	0x28
#define	IDX_RESP_10	0x29
#define	IDX_RESP_11	0x2A
#define	IDX_RESP_12	0x2B
#define	IDX_RESP_13	0x2C
#define	IDX_RESP_14	0x2D
#define	IDX_RESP_15	0x2E
#define	IDX_RESP_16	0x2F
#define	IDX_CRCSTAT	0x30

#define	IDX_CLOCK_375K		0	/* clock/128 */
#define	IDX_CLOCK_12M		1	/* clock/4 */
#define	IDX_CLOCK_16M		2	/* clock/3 */
#define	IDX_CLOCK_24M		3	/* clock/2 */

#define	IDX_RESET_DAT3_H	0x08
#define	IDX_RESET_FIFO		0x04
#define	IDX_RESET_SOFT		0x02
#define	IDX_RESET_AUTO_INC	0x01	/* not really a reset bit */

#define	IDX_DMA_EN		0x02
#define	IDX_DMA_SINGLE		0x01

#define	IDX_STATUS_READ		0x80	/* block write in progress */
#define	IDX_STATUS_WRITE	0x40	/* block read in progress */
#define	IDX_STATUS_BUSY		0x20	/* e.g. R1b or R5b */
#define	IDX_STATUS_DAT		0xE0	/* stats using DAT line */
#define	IDX_STATUS_TRAFFIC	0x04	/* cmd line busy */
#define	IDX_STATUS_CMD		0x02
#define	IDX_STATUS_RESP		0x01

#define	IDX_RESP_TYPE_LONG	0x01	/* the chip figures these out, btw */
#define	IDX_RESP_TYPE_SHORT	0x00

#define	IDX_CRC_MASK		0x1F
#define	IDX_CRC_OK		0x05

#define	IDX_THRESH_MASK		0x0F	/* threshold value (may not work) */
#define	IDX_THRESH_FULL		0x10	/* enable threshold full */
#define	IDX_THRESH_EMPTY	0x20	/* enable threshold empty */

#endif	/* _SYS_SDCARD_WBSD_H */
