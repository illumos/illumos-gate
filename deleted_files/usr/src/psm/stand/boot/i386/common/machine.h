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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyrighted as an unpublished work.
 * (c) Copyright INTERACTIVE Systems Corporation 1986, 1988, 1990
 * All rights reserved.
 */

#ifndef	_MACHINE_H
#define	_MACHINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct machconfig {
	char		*sigaddr;	/* Machine signature location 	*/
	unsigned char	siglen;		/* Signature length 		*/
	unsigned char	sigid[10];	/* Signature to match 		*/
	unsigned char	old_mt;		/* OLD Machine type 		*/
	unsigned char	machine;	/* Machine type 		*/
	ulong_t		m_flag;		/* status flag			*/
	int		(*m_entry)();	/* machine entry point		*/
};

#define	M_FLG_SRGE	1	/* sig scattered in a range of memory	*/

#define	M_ID_AT386	0
#define	M_ID_MC386	1
#define	M_ID_EISA	2

#define	SYS_MODEL() 	*(char *)0xFFFFE
#define	MODEL_AT	(uchar_t)0xFC
#define	MODEL_MC	(uchar_t)0xF8
#define	USER_START	0x100000

#define	NPTEPERPT	1024
typedef struct ptbl {
	int page[NPTEPERPT];
} ptbl_t;

/* combine later with ../../../uts/i86/sys/pte.h */
#define	PG_P 0x1  	/* page is present */
#define	PG_RW 0x2  	/* page is read/write */
#define	PG_SIZE 0x80	/* page is 4MB */
#define	PG_GLOBAL 0x100	/* page is persistent */

/*
 * keyboard controller I/O port addresses
 */

#define	KB_OUT	0x60		/* output buffer R/O */
#define	KB_IDAT	0x60		/* input buffer data write W/O */
#define	KB_STAT	0x64		/* keyboard controller status R/O */
#define	KB_ICMD	0x64		/* input buffer command write W/O */

/*
 * keyboard controller commands and flags
 */
#define	KB_INBF		0x02	/* input buffer full flag */
#define	KB_OUTBF	0x01	/* output buffer full flag */
#define	KB_GATE20	0x02	/* set this bit to allow addresses > 1Mb */
#define	KB_ROP		0xD0	/* read output port command */
#define	KB_WOP		0xD1	/* write output port command */
#define	KB_RCB		0x20	/* read command byte command */
#define	KB_WCB		0x60	/* write command byte command */
#define	KB_ENAB		0xae	/* enable keyboard interface */
#define	KB_DISAB	0x10	/* disable keyboard */
#define	KB_EOBFI	0x01	/* enable interrupt on output buffer full */
#define	KB_ACK		0xFA	/* Acknowledgement byte from keyboard */
#define	KB_RESETCPU	0xFE	/* command to reset AT386 cpu */
#define	KB_READID	0xF2	/* command to read keyboard id */
#define	KB_RESEND	0xFE	/* response from keyboard to resend data */
#define	KB_ERROR	0xFF	/* response from keyboard to resend data */
#define	KB_RESET	0xFF	/* command to reset keyboard */
/*
 * command to to enable keyboard
 * this is different from KB_ENAB above in
 * that KB_ENAB is a command to the 8042 to
 * enable the keyboard interface, not the
 * keyboard itself
 */
#define	KB_ENABLE	0xF4

/* move later into immu.h */
#ifndef	PTSIZE
#define	PTSIZE 4096
#endif

#define	ptround(p)	((int *)(((int)p + PTSIZE-1) & ~(PTSIZE-1)))
#define	FOURMEG  4194304
#define	FOURMB_PTE (PG_P | PG_RW | PG_SIZE)

#ifdef	__cplusplus
}
#endif

#endif	/* _MACHINE_H */
