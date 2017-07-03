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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _DIAL_H
#define	_DIAL_H

#ifndef IUCLC
#include <sys/termio.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/* uucico routines need these */
#define	DIAL

/* The following are no longer used by dial() and may be out of date.	*/
/* They are included here only to maintain source compatibility.	*/
#define	STANDALONE
#define	DEVDIR	"/dev/"				/* device path		*/
#define	LOCK	"/usr/spool/uucp/LCK.."		/* lock file semaphore	*/
#define	DVC_LEN	80	/* max NO of chars in TTY-device path name	*/
/* End of unused definitions						*/

		/* error mnemonics */

#define	TRUE	1
#define	FALSE	0
#define	INTRPT	(-1)	/* interrupt occured */
#define	D_HUNG	(-2)	/* dialer hung (no return from write) */
#define	NO_ANS	(-3)	/* no answer (caller script failed) */
#define	ILL_BD	(-4)	/* illegal baud-rate */
#define	A_PROB	(-5)	/* acu problem (open() failure) */
#define	L_PROB	(-6)	/* line problem (open() failure) */
#define	NO_Ldv	(-7)	/* can't open Devices file */
#define	DV_NT_A	(-8)	/* requested device not available */
#define	DV_NT_K	(-9)	/* requested device not known */
#define	NO_BD_A	(-10)	/* no device available at requested baud */
#define	NO_BD_K	(-11)	/* no device known at requested baud */
#define	DV_NT_E (-12)	/* requested speed does not match */
#define	BAD_SYS (-13)	/* system not in Systems file */

typedef struct {
	struct termio *attr;	/* ptr to termio attribute struct */
	int	baud;		/* unused */
	int	speed;		/* 212A modem: low=300, high=1200 */
	char	*line;		/* device name for out-going line */
	char	*telno;		/* ptr to tel-no/system name string */
	int	modem;		/* unused */
	char	*device;	/* unused */
	int	dev_len;	/* unused */
} CALL;

extern int dial(CALL);
extern void undial(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _DIAL_H */
