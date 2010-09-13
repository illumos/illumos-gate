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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_TERMIO_H
#define	_SYS_TERMIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.11 */

#include <sys/termios.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* all the ioctl codes and flags are now in termios.h */

/*
 * Ioctl control packet
 */
struct termio {
	unsigned short	c_iflag;	/* input modes */
	unsigned short	c_oflag;	/* output modes */
	unsigned short	c_cflag;	/* control modes */
	unsigned short	c_lflag;	/* line discipline modes */
	char	c_line;		/* line discipline */
	unsigned char	c_cc[_NCC];	/* control chars */
};

#define	IOCTYPE	0xff00


/*
 * structure of ioctl arg for LDGETT and LDSETT
 */
struct	termcb	{
	char	st_flgs;	/* term flags */
	char	st_termt;	/* term type */
	char	st_crow;	/* gtty only - current row */
	char	st_ccol;	/* gtty only - current col */
	char	st_vrow;	/* variable row */
	char	st_lrow;	/* last row */
};

#ifndef u3b15
#define	SSPEED	7	/* default speed: 300 baud */
#else
#define	SSPEED	9	/* default speed: 1200 baud */
#endif

#ifdef u3b15
#define	TTYTYPE (_TIOC|8)
#endif
#define	TCDSET	(_TIOC|32)

/*
 * Terminal types
 */
#define	TERM_NONE	0	/* tty */
#define	TERM_TEC	1	/* TEC Scope */
#define	TERM_V61	2	/* DEC VT61 */
#define	TERM_V10	3	/* DEC VT100 */
#define	TERM_TEX	4	/* Tektronix 4023 */
#define	TERM_D40	5	/* TTY Mod 40/1 */
#define	TERM_H45	6	/* Hewlitt-Packard 45 */
#define	TERM_D42	7	/* TTY Mod 40/2B */

/*
 * Terminal flags
 */
#define	TM_NONE		0000	/* use default flags */
#define	TM_SNL		0001	/* special newline flag */
#define	TM_ANL		0002	/* auto newline on column 80 */
#define	TM_LCF		0004	/* last col of last row special */
#define	TM_CECHO	0010	/* echo terminal cursor control */
#define	TM_CINVIS	0020	/* do not send esc seq to user */
#define	TM_SET		0200	/* must be on to set/res flags */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TERMIO_H */
