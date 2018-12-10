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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Definition for hangul character macro added */

#define	_K1	01		/* First byte of Completion code */
#define _K2	02		/* Second byte of Completion code */

/* #define	_HA	04*/		/* Hangul alphabet */

#define _GR	04 		/* First byte of Non-Hangeul/Hanja Characters */
#define _HN	010		/* First byte of Hangeul Characters */
#define _HJ	020		/* First byte of Hanja Characters */
#define _HU	040 		/* First byte of User-Definable Characters */
#define _HR	0100		/* Fisrt byte of Reserved for Future Assignment */

static char	_hctype_[] = { 0,

/*	0/4		1/5		2/6		3/7	*/

/*00*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*10*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*20*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*30*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*40*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*50*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*60*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*70*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*80*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*90*/	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
	0,		0,		0,		0,
/*A0*/	0,		_K2|_K1|_GR,	_K2|_K1|_GR,	_K2|_K1|_GR,
	_K2|_K1|_GR,	_K2|_K1|_GR,	_K2|_K1|_GR,	_K2|_K1|_HR,
	_K2|_K1|_HR,	_K2|_K1|_HR,	_K2|_K1|_HR,	_K2|_K1|_HR,
	_K2|_K1|_HR,	_K2|_K1|_HR,	_K2|_K1|_HR,	_K2|_K1|_HR,
/*B0*/	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
/*C0*/	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,	_K2|_K1|_HN,
	_K2|_K1|_HN,	_K2|_K1|_HU,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
/*D0*/	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
/*E0*/	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
/*F0*/	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HJ,
	_K2|_K1|_HJ,	_K2|_K1|_HJ,	_K2|_K1|_HU,	0,
};


#define	iskorea1(c)	((_hctype_+1)[(unsigned char)(c)]&_K1)
#define	iskorea2(c)	((_hctype_+1)[(unsigned char)(c)]&_K2)

#define ishangraph(c)	((_hctype_+1)[(unsigned char)(c)]&_GR)
#define	ishangul(c)	((_hctype_+1)[(unsigned char)(c)]&_HN)
#define ishanja(c)	((_hctype_+1)[(unsigned char)(c)]&_HJ)
#define ishanusr(c)	((_hctype_+1)[(unsigned char)(c)]&_HU)
#define ishreserve(c)	((_hctype_+1)[(unsigned char)(c)]&_HR)
/*
#define ishanalpha(c)	((_hctype_+1)[(unsigned char)(c)]&_HA)
*/
#define KCT_ASCII	0x00
#define KCT_KOREA1	0x01
#define KCT_KOREA2	0x02
#define KCT_HANGUL1	0x04
#define KCT_HANGUL2	0x08
#define KCT_HANJA1	0x10
#define KCT_HANJA2	0x20
#define KCT_ILLGL	0x40
