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
 * Copyright (c) 1991, Sun Microsystems, Inc.
 * Copyright (c) 1991, Nihon Sun Microsystems K.K.
 */

#define GET(c)		((c) = *ip, ip++, ileft--)
#define PUT(c)		(*op = (c), op++, oleft--)
#define UNGET()		(ip--, ileft++)

#define ERR_RETURN	(-1)		/* result code on error */

/* is a valid character for ascii? */
#define ISASC(c)		(((c) >= 0x00) && ((c) <= 0x7f))

/* is a valid character for codeset 1? */
#define ISCS1(c)		(((c) >= 0xa1) && ((c) <= 0xfe))

/* is a valid character for codeset 2? */
#define ISCS2(c)		(((c) >= 0xa1) && ((c) <= 0xdf))

/* is a valid character for codeset 3? */
#define ISCS3(c)		(((c) >= 0xa1) && ((c) <= 0xfe))

/* is a valid hankaku_katakana for SJIS? */
#define ISSJKANA(c)		(((c) >= 0xa1) && ((c) <= 0xdf))

/* is a valid character for the first byte of SJIS kanji? */
#define ISSJKANJI1(c)	((((c) >= 0x81) && ((c) <= 0x9f)) ||\
						 (((c) >= 0xe0) && ((c) <= 0xef)))

/* is a valid character for the second byte of SJIS kanji? */
#define ISSJKANJI2(c)	((((c) >= 0x40) && ((c) <= 0x7e)) ||\
						 (((c) >= 0x80) && ((c) <= 0xfc)))

#define CS_0			0		/* codeset 0 */
#define CS_1			1		/* codeset 1 */
#define CS_2			2		/* codeset 2 */
#define CS_3			3		/* codeset 3 */

#define ST_INIT			0		/* init */
#define ST_INCS1		1		/* in codeset 1 */
#define ST_INCS2		2		/* in codeset 2 */
#define ST_INCS3		3		/* in codeset 3 */
#define ST_ESC			4		/* in ESC */
#define ST_MBTOG0_1		5		/* in the designation of MB to G0 - 1 */
#define ST_MBTOG0_2		6		/* in the designation of MB to G0 - 2 */
#define ST_SBTOG0		7		/* in the designation of SB to G0 */

/*
 * CODE SET 0
 * ESC ( B   			: To ASCII
 * ESC ( J				: To JIS X 0201 - 1976 ROMAN
 * ESC ( @				: TO ISO 646 IRV
 *
 * CODE SET 1
 * ESC & @ ESC $ ( B	: To JIS X 0208 - 1990		: Not implemented
 * ESC $ ( B			: To JIS X 0208 - 1983/1990
 * ESC $ ( @			: To JIS X 0208 - 1978
 * ESC $ B				: To JIS X 0208 - 1983/1990
 * ESC $ @				: To JIS X 0208 - 1978
 * ESC & @ ESC $ B		: To JIS X 0208 - 1983/1990	: Not implemented
 *
 * CODE SET 2
 * SO  					: G1 -> G
 * SI  					: G0 -> G
 * ESC ( I				: To JIS X 0201 - 1976 Katakana
 *
 * CODE SET 3
 * ESC $ ( D			: To JIS X 0212 - 1990
 * ESC $ D				: To JIS X 0212 - 1990
 *
 */

#define ESC					0x1b		/* Escape : 1/12 */
#define SO					0x0e		/* Shift Out : 0/14 */
#define SI					0x0f		/* SHift In  : 0/15 */

#define SBTOG0_1			0x28		/* ( : 2/8 */
#define F_ASCII				0x42		/* B : 4/2 */
#define F_X0201_RM			0x4a		/* J : 4/10 */
#define F_ISO646			0x40		/* @ : 4/0 */
#define F_X0201_KN			0x49		/* I : 4/9 */

#define MBTOG0_1			0x24		/* $ : 2/4 */
#define MBTOG0_2			0x28		/* ( : 2/8 */
#define F_X0208_83_90		0x42		/* B : 4/2 */
#define F_X0208_78			0x40		/* @ : 4/0 */
#define F_X0212_90			0x44		/* D : 4/4 */

#define	CMASK				0x7f
#define	CMSB				0x80

/* the byte length of ESC sequences */
#define SEQ_SBTOG0			3			/* ESC + ( + F */
#define SEQ_MBTOG0			4			/* ESC + $ + ( + F */
#define SEQ_MBTOG0_O		3			/* ESC + $ + F */

/* the byte length of SO/SI */
#define SEQ_SOSI			1			/* SO or SI */

/* the byte length of SS2/SS3 */
#define SEQ_SS				1			/* SS2 or SS3 */

/* the byte length of JIS characters */
#define JISW0				1			/* ASCII */
#define JISW1				2			/* Kanji */
#define JISW2				1			/* Hankaku Katakana */
#define JISW3				2			/* Hojo Kanji */

/* the byte length of EUC characters */
#define EUCW0				1			/* ASCII */
#define EUCW1				2			/* Kanji */
#define EUCW2				1			/* Hankaku Katakana */
#define EUCW3				2			/* Hojo Kanji */
#define SS2W				1			/* SS2 */
#define SS3W				1			/* SS3 */

/* the byte length of SJIS characters */
#define SJISW0				1			/* ASCII */
#define SJISW1				2			/* Kanji */
#define SJISW2				1			/* Hankaku Katakana */

#define EBCDIC0				1
#define EBCDIC1				2
#define EBCDIC2				1
#define EBCDIC3				2

/* the byte length of unknown characters */
#define UNKNOWNW			1
