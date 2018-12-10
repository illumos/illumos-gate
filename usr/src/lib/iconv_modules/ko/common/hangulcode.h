/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */



#ifndef _HANGULCODE_H_
#define	_HANGULCODE_H_


typedef struct _kcode_table {
	unsigned short	code;
	unsigned long	utf8;
} kcode_table;

/* Cho Sung Count - 1 and Joong Sung Count - 1 */
#define	CI_CNT			18
#define V_CNT			20

/* 0xa1 + 0xff - 0xfe */
#define SKIP			0xA2

#ifndef BYTE_MASK
#define	BYTE_MASK		0xFF
#endif	/* BYTE_MASK */

#define BIT_MASK		0x01

/* FAILED == non-identical character. */
#define FAILED			0
#define ILLEGAL_SEQ		1
#define HANGUL			2
#define HANJA_OR_SYMBOL		3

#define CHOSUNG(code)		((unsigned short)((code) & 0x7c00) >> 10)
#define JOONGSUNG(code)		((unsigned short)((code) & 0x03e0) >> 5)
#define JONGSUNG(code)		((code) & 0x001f)

#define MAGIC_NUMBER		0x2165

#define CVC_FILL		100

#define	ESC			0x1B
#define SI			0x0F
#define SO			0x0E

#define MAX_E2U_NUM		5873
#define MAX_J922U_NUM		5873
#define MAX_U2E_NUM		8223
#define MAX_U2ISO2022_NUM	8223
#define MAX_U2J92_NUM		8223

#define	NON_IDENTICAL		'?'

#define	UTF8_NON_ID_CHAR1		0xEF
#define	UTF8_NON_ID_CHAR2		0xBF
#define	UTF8_NON_ID_CHAR3		0xBD

#endif	/* _HANGULCODE_H_ */
