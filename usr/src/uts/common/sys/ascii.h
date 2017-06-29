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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_ASCII_H
#define	_SYS_ASCII_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	A_NUL	0
#define	A_SOH	1
#define	A_STX	2
#define	A_ETX	3
#define	A_EOT	4
#define	A_ENQ	5
#define	A_ACK	6
#define	A_BEL	7
#define	A_BS	8
#define	A_HT	9
#define	A_NL	10
#define	A_LF	10
#define	A_VT	11
#define	A_FF	12
#define	A_NP	12
#define	A_CR	13
#define	A_SO	14
#define	A_SI	15
#define	A_DLE	16
#define	A_DC1	17
#define	A_DC2	18
#define	A_DC3	19
#define	A_DC4	20
#define	A_NAK	21
#define	A_SYN	22
#define	A_ETB	23
#define	A_CAN	24
#define	A_EM	25
#define	A_SUB	26
#define	A_ESC	27
#define	A_FS	28
#define	A_GS	29
#define	A_RS	30
#define	A_US	31
#define	A_DEL	127
#define	A_CSI	0x9b

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ASCII_H */
