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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BOOT_SERIAL_H
#define	_BOOT_SERIAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- ports on 16550 serial chips ---- */
#define	DAT	0	/* ... data */
#define	ICR	1	/* ... intr control reg */
#define	ISR	2	/* ... intr status reg */
#define	LCR	3	/* ... line control reg */
#define	MCR	4	/* ... modem control reg */
#define	LSR	5	/* ... line status reg */
#define	MSR	6	/* ... modem status reg */
#define	DLL	0	/* ... data latch low (used for baud rate) */
#define	DLH	1	/* ... data latch high (ditto) */
#define	FIFOR	ISR	/* ... fifo write reg */

/* ---- LSR bits ---- */
#define	RCA		0x01	/* ... receive char avail */
#define	XHRE		0x20	/* ... xmit hold buffer empty */

/* ---- Modem bits ---- */
#define	DTR		0x01
#define	RTS		0x02
#define	OUT2		0x08

#define	FIFO_ON		0x01
#define	FIFO_OFF	0x00
#define	FIFORXFLSH	0x02
#define	FIFOTXFLSH	0x04
#define	FIFODMA		0x08

/* ---- LCR bits ---- */
#define	STOP1		00
#define	STOP2   	0x04
#define	BITS5		0x00	/* 5 bits per char */
#define	BITS6		0x01	/* 6 bits per char */
#define	BITS7		0x02	/* 7 bits per char */
#define	BITS8		0x03	/* 8 bits per char */

/* baud rate definitions */
#define	DLAB		0x80	/* divisor latch access bit */
#define	ASY110		1047	/* 110 baud rate for serial console */
#define	ASY150		768	/* 150 baud rate for serial console */
#define	ASY300		384	/* 300 baud rate for serial console */
#define	ASY600		192	/* 600 baud rate for serial console */
#define	ASY1200		96	/* 1200 baud rate for serial console */
#define	ASY2400		48	/* 2400 baud rate for serial console */
#define	ASY4800		24	/* 4800 baud rate for serial console */
#define	ASY9600		12	/* 9600 baud rate for serial console */
#define	ASY19200	6	/* 19200 baud rate for serial console */
#define	ASY38400	3	/* 38400 baud rate for serial console */
#define	ASY57600	2	/* 57600 baud rate for serial console */
#define	ASY115200	1	/* 115200 baud rate for serial console */


/*
 *  Defines for the serial port
 */

#define	SERIAL_FIFO_FLUSH	16	/* maximum number of chars to flush */

/* ---- Bit 11 defines direct serial port ---- */
#define	SDIRECT		0x1000

/* ---- Bits 9-10 define flow control ---- */
#define	SSOFT		0x800
#define	SHARD		0x400

/* ---- Bits 5-8 define baud rate ---- */
#define	S110		0x00
#define	S150		0x20
#define	S300		0x40
#define	S600		0x60
#define	S1200		0x80
#define	S2400		0xa0
#define	S4800		0xc0
#define	S9600		0xe0
#define	S19200		0x100
#define	S38400		0x120
#define	S57600		0x140
#define	S76800		0x160
#define	S115200		0x180
#define	S153600		0x1a0
#define	S230400		0x1c0
#define	S307200		0x1e0
#define	S460800		0x200

/* ---- Bits 3 & 4 are parity ---- */
#define	PARITY_NONE	0x10
#define	PARITY_ODD	0x08
#define	PARITY_EVEN	0x18

/* ---- Bit 2 is stop bit ---- */
#define	STOP_1		0x00
#define	STOP_2		0x04

/* ---- Bits 0 & 1 are data bits ---- */
#define	DATA_8		0x03
#define	DATA_7		0x02
#define	DATA_6		0x01
#define	DATA_5		0x00

/* ---- Line Status ---- */
#define	SERIAL_TIMEOUT	0x80
#define	SERIAL_XMITSHFT	0x40
#define	SERIAL_XMITHOLD	0x20
#define	SERIAL_BREAK	0x10
#define	SERIAL_FRAME	0x08
#define	SERIAL_PARITY	0x04
#define	SERIAL_OVERRUN	0x02
#define	SERIAL_DATA	0x01


#ifdef __cplusplus
}
#endif

#endif	/* _BOOT_SERIAL_H */
