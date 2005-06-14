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
 * Copyright (c) 1997, Sun Microsystems, Inc.  All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* ---- ports on 16550 serial chips ---- */
#define DAT	0	/* ... data */
#define ICR	1	/* ... intr control reg */
#define ISR	2	/* ... intr status reg */
#define LCR	3	/* ... line control reg */
#define MCR	4	/* ... modem control reg */
#define LSR	5	/* ... line status reg */
#define MSR	6	/* ... modem status reg */
#define DLL	0	/* ... data latch low (used for baud rate) */
#define DLH	1	/* ... data latch high (ditto) */
#define FIFOR	ISR	/* ... fifo write reg */

/* ---- convenant macros ---- */
/* this macro uses the _chario_io_p structure */
#define INB(a, off) \
	(inb((a) + off))
#define OUTB(a, off, val) \
	(outb((a)+(off), (char)(val)))

/* ---- LSR bits ---- */
#define RCA		0x01	/* ... receive char avail */
#define XHRE		0x20	/* ... xmit hold buffer empty */

/* ---- Modem bits ---- */
#define DTR		0x01
#define RTS		0x02
#define OUT2		0x08

#define FIFO_ON		0x01
#define FIFO_OFF	0x00
#define FIFORXFLSH	0x02
#define FIFOTXFLSH	0x04
#define FIFODMA		0x08

/* ---- LCR bits ---- */
#define STOP1		00
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
