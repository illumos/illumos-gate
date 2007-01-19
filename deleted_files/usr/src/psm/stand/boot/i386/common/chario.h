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
 * Copyright (c) 1995-1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CHARIO_H
#define	_CHARIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  This file contains all character i/o related structures
 *  and defines.
 *
 *  Project: Devconf
 *  Author : Rick McNeal
 *  Date   : 2-Nov-1994
 */
struct _char_io_ {
	struct _char_io_	*next;		/* next i/o member */
	char	*name;				/* Name for stats */
	int	in, out, errs;			/* Simple stats */
	int	flags;				/* control bits */
	int	vals;				/* state bits */
	int	addr;				/* physical address */
	char	*cookie;			/* for driver use */
	char	(*getc)(struct _char_io_ *);	/* returns character */
	void	(*putc)(struct _char_io_ *, char); /* outputs one character */
	int	(*avail)(struct _char_io_ *);	/* returns 1 if char avail */
	void	(*clear)(struct _char_io_ *);	/* clear screen */
	void	(*set)(struct _char_io_ *, int, int); /* set cursor pos. */
};
typedef struct _char_io_ _char_io_t, *_char_io_p;

int serial_port_enabled(int port);

#define	CHARIO_IGNORE_ALL	0x0001	/* don't output to this dev */
#define	CHARIO_DISABLED		0x0002	/* error occured and ports not used */
#define	CHARIO_OUT_ENABLE	0x0004	/* Device does output */
#define	CHARIO_IN_ENABLE	0x0008	/* Device does input */
#define	CHARIO_IGNORE_CD	0x0010	/* Device shouldn't wait for CD */
#define	CHARIO_RTS_DTR_OFF	0x0020	/* Device shouldn't set rts/dtr */
#define	CHARIO_INIT		0x0040	/* Device should be (re)initialized */

/*
 * Use this macro when debugging the output side of your driver. This
 * will prevent any printf's from your driver causing an infinite loop
 */
#define	PRINT(p, x) \
{ p->flags |= CHARIO_IGNORE_ALL; printf x; p->flags &= ~CHARIO_IGNORE_ALL; }

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

/*
 *  Bit style flag operations for 32bit ints only
 */
#define	BCLR(x)		x &= ~(1 << y)
#define	BSET(x, y) 	x |= (1 << y)
#define	BISSET(x, y)	x & (1 << y)

#ifdef	__cplusplus
}
#endif

#endif /* _CHARIO_H */
