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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Came from en_US.UTF-8 locale's width definition at 6/24/1999.
 *
 * Epoch:	Based on Unicode 2.0 / ISO/IEC 10646-1:1993 plus
 *		AM2 (UTF-8) and DAM5 (Hangul) as of 6/1996.
 *
 * 2/28/1998:	Added missed Tibetan block (U+0F00 ~ U+0FBF),
 *		Added OBJECT REPLACEMENT CHARACTERS (U+FFFC) and
 *		EURO SIGN (U+20AC) for Unicode 2.1.
 * 8/3/1999:	Added Unicode 3.0 Beta characters.
 * 11/19/2001:	Added Unicode 3.1 character width definition from
 *		Solaris Unicode locale common method shared object for
 *		Plane 0 and 1. All other characters at Plane 2, 14, 15,
 *		and 16 will be taken care of by using if expressions at
 *		the ldterm_utf8_width().
 * 2/26/2004:	Added 1,016 new characters of Unicode 3.2 at BMP, corrected
 *		U+0B83 as specified at the Unicode 3.2 Errata, and added
 *		986 new characters of Unicode 4.0. (For the Unicode 4.0,
 *		452 and 534 new characters have been added at BMP and Plane 01,
 *		respectively. 240 new characters for the Plane 0E are
 *		being taken care of at the ldterm_utf8_width().)
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/termio.h>
#include <sys/stream.h>
#include <sys/euc.h>
#include <sys/eucioctl.h>
#include <sys/ldterm.h>

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Private use area characters' width. We set it to two since PU will be
 * used mostly by Asian locales.
 */
#ifndef	PU
#define	PU			2
#endif	/* PU */

/* Not-yet-assigned/some control/invalid characters will have width of 1. */
#ifndef	IL
#define	IL			1
#endif	/* IL */

/*
 * Following table contains width information for Unicode.
 *
 * There are only three different kind of width: zero, one, or two.
 * The fourth possible value was -1 but changed to 1; the value means not yet
 * assigned, some control, or, invalid Unicode character, i.e., U+FFFE and
 * U+FFFF.
 */
/* BEGIN CSTYLED */
const ldterm_unicode_data_cell_t ldterm_ucode[2][16384] = {
	{
/*		0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
/*		---------------------------------------------- */
/* U+0000 */	0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+000F */
/* U+0010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+001F */
/* U+0020 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+002F */
/* U+0030 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+003F */
/* U+0040 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+004F */
/* U+0050 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+005F */
/* U+0060 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+006F */
/* U+0070 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+007F */
/* U+0080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+008F */
/* U+0090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+009F */
/* U+00A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00AF */
/* U+00B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00BF */
/* U+00C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00CF */
/* U+00D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00DF */
/* U+00E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00EF */
/* U+00F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+00FF */
/* U+0100 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+010F */
/* U+0110 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+011F */
/* U+0120 */	1, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+012F */
/* U+0130 */	1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+013F */
/* U+0140 */	2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1,    /* U+014F */
/* U+0150 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+015F */
/* U+0160 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+016F */
/* U+0170 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+017F */
/* U+0180 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+018F */
/* U+0190 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+019F */
/* U+01A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+01AF */
/* U+01B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+01BF */
/* U+01C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1,    /* U+01CF */
/* U+01D0 */	2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 1, 1,    /* U+01DF */
/* U+01E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+01EF */
/* U+01F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+01FF */
/* U+0200 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+020F */
/* U+0210 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+021F */
/* U+0220 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+022F */
/* U+0230 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+023F */
/* U+0240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+024F */
/* U+0250 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+025F */
/* U+0260 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+026F */
/* U+0270 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+027F */
/* U+0280 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+028F */
/* U+0290 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+029F */
/* U+02A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+02AF */
/* U+02B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+02BF */
/* U+02C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1,    /* U+02CF */
/* U+02D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 1, 2, 1, 1, 1,    /* U+02DF */
/* U+02E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+02EF */
/* U+02F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+02FF */
/* U+0300 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+030F */
/* U+0310 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+031F */
/* U+0320 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+032F */
/* U+0330 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+033F */
/* U+0340 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+034F */
/* U+0350 */	0, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,IL,0, 0, 0,    /* U+035F */
/* U+0360 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+036F */
/* U+0370 */	IL,IL,IL,IL,1, 1, IL,IL,IL,IL,1, IL,IL,IL,1, IL,   /* U+037F */
/* U+0380 */	IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, 1,    /* U+038F */
/* U+0390 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+039F */
/* U+03A0 */	1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+03AF */
/* U+03B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+03BF */
/* U+03C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+03CF */
/* U+03D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+03DF */
/* U+03E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+03EF */
/* U+03F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+03FF */
/* U+0400 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+040F */
/* U+0410 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+041F */
/* U+0420 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+042F */
/* U+0430 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+043F */
/* U+0440 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+044F */
/* U+0450 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+045F */
/* U+0460 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+046F */
/* U+0470 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+047F */
/* U+0480 */	1, 1, 1, 0, 0, 0, 0, IL,0, 0, 1, 1, 1, 1, 1, 1,    /* U+048F */
/* U+0490 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+049F */
/* U+04A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+04AF */
/* U+04B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+04BF */
/* U+04C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+04CF */
/* U+04D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+04DF */
/* U+04E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+04EF */
/* U+04F0 */	1, 1, 1, 1, 1, 1, IL,IL,1, 1, IL,IL,IL,IL,IL,IL,   /* U+04FF */
/* U+0500 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+050F */
/* U+0510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+051F */
/* U+0520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+052F */
/* U+0530 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+053F */
/* U+0540 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+054F */
/* U+0550 */	1, 1, 1, 1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, 1,    /* U+055F */
/* U+0560 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+056F */
/* U+0570 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+057F */
/* U+0580 */	1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, IL,IL,IL,IL,IL,   /* U+058F */
/* U+0590 */	IL,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+059F */
/* U+05A0 */	0, 0, IL,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+05AF */
/* U+05B0 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,0, 0, 0, 1, 0,    /* U+05BF */
/* U+05C0 */	1, 0, 0, 1, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+05CF */
/* U+05D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+05DF */
/* U+05E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+05EF */
/* U+05F0 */	1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+05FF */
/* U+0600 */	0, 0, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,1, 1, 1, 1,    /* U+060F */
/* U+0610 */	0, 0, 0, 0, 0, 0, IL,IL,IL,IL,IL,1, IL,IL,IL,1,    /* U+061F */
/* U+0620 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+062F */
/* U+0630 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+063F */
/* U+0640 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,    /* U+064F */
/* U+0650 */	0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,IL,IL,IL,   /* U+065F */
/* U+0660 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+066F */
/* U+0670 */	0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+067F */
/* U+0680 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+068F */
/* U+0690 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+069F */
/* U+06A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+06AF */
/* U+06B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+06BF */
/* U+06C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+06CF */
/* U+06D0 */	1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+06DF */
/* U+06E0 */	0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1,    /* U+06EF */
/* U+06F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+06FF */
/* U+0700 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,0,    /* U+070F */
/* U+0710 */	1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+071F */
/* U+0720 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+072F */
/* U+0730 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+073F */
/* U+0740 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,1, 1, 1,    /* U+074F */
/* U+0750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+075F */
/* U+0760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+076F */
/* U+0770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+077F */
/* U+0780 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+078F */
/* U+0790 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+079F */
/* U+07A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+07AF */
/* U+07B0 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+07BF */
/* U+07C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+07CF */
/* U+07D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+07DF */
/* U+07E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+07EF */
/* U+07F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+07FF */
/* U+0800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+080F */
/* U+0810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+081F */
/* U+0820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+082F */
/* U+0830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+083F */
/* U+0840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+084F */
/* U+0850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+085F */
/* U+0860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+086F */
/* U+0870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+087F */
/* U+0880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+088F */
/* U+0890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+089F */
/* U+08A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08AF */
/* U+08B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08BF */
/* U+08C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08CF */
/* U+08D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08DF */
/* U+08E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08EF */
/* U+08F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+08FF */
/* U+0900 */	IL,0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+090F */
/* U+0910 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+091F */
/* U+0920 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+092F */
/* U+0930 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,0, 1, 0, 0,    /* U+093F */
/* U+0940 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,   /* U+094F */
/* U+0950 */	1, 0, 0, 0, 0, IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+095F */
/* U+0960 */	1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+096F */
/* U+0970 */	1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+097F */
/* U+0980 */	IL,0, 0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, IL,IL,1,    /* U+098F */
/* U+0990 */	1, IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+099F */
/* U+09A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+09AF */
/* U+09B0 */	1, IL,1, IL,IL,IL,1, 1, 1, 1, IL,IL,0, 1, 0, 0,    /* U+09BF */
/* U+09C0 */	0, 0, 0, 0, 0, IL,IL,0, 0, IL,IL,0, 0, 0, IL,IL,   /* U+09CF */
/* U+09D0 */	IL,IL,IL,IL,IL,IL,IL,0, IL,IL,IL,IL,1, 1, IL,1,    /* U+09DF */
/* U+09E0 */	1, 1, 0, 0, IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+09EF */
/* U+09F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+09FF */
/* U+0A00 */	IL,0, 0, 0, IL,1, 1, 1, 1, 1, 1, IL,IL,IL,IL,1,    /* U+0A0F */
/* U+0A10 */	1, IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0A1F */
/* U+0A20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0A2F */
/* U+0A30 */	1, IL,1, 1, IL,1, 1, IL,1, 1, IL,IL,0, IL,0, 0,    /* U+0A3F */
/* U+0A40 */	0, 0, 0, IL,IL,IL,IL,0, 0, IL,IL,0, 0, 0, IL,IL,   /* U+0A4F */
/* U+0A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,1, 1, 1, 1, IL,1, IL,   /* U+0A5F */
/* U+0A60 */	IL,IL,IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0A6F */
/* U+0A70 */	0, 0, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0A7F */
/* U+0A80 */	IL,0, 0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1,    /* U+0A8F */
/* U+0A90 */	1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0A9F */
/* U+0AA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0AAF */
/* U+0AB0 */	1, IL,1, 1, IL,1, 1, 1, 1, 1, IL,IL,0, 1, 0, 0,    /* U+0ABF */
/* U+0AC0 */	0, 0, 0, 0, 0, 0, IL,0, 0, 0, IL,0, 0, 0, IL,IL,   /* U+0ACF */
/* U+0AD0 */	1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0ADF */
/* U+0AE0 */	1, 1, 0, 0, IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0AEF */
/* U+0AF0 */	IL,1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0AFF */
/* U+0B00 */	IL,0, 0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, IL,IL,1,    /* U+0B0F */
/* U+0B10 */	1, IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0B1F */
/* U+0B20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0B2F */
/* U+0B30 */	1, IL,1, 1, IL,1, 1, 1, 1, 1, IL,IL,0, 1, 0, 0,    /* U+0B3F */
/* U+0B40 */	0, 0, 0, 0, IL,IL,IL,0, 0, IL,IL,0, 0, 0, IL,IL,   /* U+0B4F */
/* U+0B50 */	IL,IL,IL,IL,IL,IL,0, 0, IL,IL,IL,IL,1, 1, IL,1,    /* U+0B5F */
/* U+0B60 */	1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0B6F */
/* U+0B70 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0B7F */
/* U+0B80 */	IL,IL,0, 1, IL,1, 1, 1, 1, 1, 1, IL,IL,IL,1, 1,    /* U+0B8F */
/* U+0B90 */	1, IL,1, 1, 1, 1, IL,IL,IL,1, 1, IL,1, IL,1, 1,    /* U+0B9F */
/* U+0BA0 */	IL,IL,IL,1, 1, IL,IL,IL,1, 1, 1, IL,IL,IL,1, 1,    /* U+0BAF */
/* U+0BB0 */	1, 1, 1, 1, 1, 1, IL,1, 1, 1, IL,IL,IL,IL,0, 0,    /* U+0BBF */
/* U+0BC0 */	0, 0, 0, IL,IL,IL,0, 0, 0, IL,0, 0, 0, 0, IL,IL,   /* U+0BCF */
/* U+0BD0 */	IL,IL,IL,IL,IL,IL,IL,0, IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0BDF */
/* U+0BE0 */	IL,IL,IL,IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0BEF */
/* U+0BF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+0BFF */
/* U+0C00 */	IL,0, 0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,    /* U+0C0F */
/* U+0C10 */	1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0C1F */
/* U+0C20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0C2F */
/* U+0C30 */	1, 1, 1, 1, IL,1, 1, 1, 1, 1, IL,IL,IL,IL,0, 0,    /* U+0C3F */
/* U+0C40 */	0, 0, 0, 0, 0, IL,0, 0, 0, IL,0, 0, 0, 0, IL,IL,   /* U+0C4F */
/* U+0C50 */	IL,IL,IL,IL,IL,0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0C5F */
/* U+0C60 */	1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0C6F */
/* U+0C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0C7F */
/* U+0C80 */	IL,IL,0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,    /* U+0C8F */
/* U+0C90 */	1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0C9F */
/* U+0CA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0CAF */
/* U+0CB0 */	1, 1, 1, 1, IL,1, 1, 1, 1, 1, IL,IL,0, 1, 0, 0,    /* U+0CBF */
/* U+0CC0 */	0, 0, 0, 0, 0, IL,0, 0, 0, IL,0, 0, 0, 0, IL,IL,   /* U+0CCF */
/* U+0CD0 */	IL,IL,IL,IL,IL,0, 0, IL,IL,IL,IL,IL,IL,IL,1, IL,   /* U+0CDF */
/* U+0CE0 */	1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0CEF */
/* U+0CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0CFF */
/* U+0D00 */	IL,IL,0, 0, IL,1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,    /* U+0D0F */
/* U+0D10 */	1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0D1F */
/* U+0D20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1,    /* U+0D2F */
/* U+0D30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,0, 0,    /* U+0D3F */
/* U+0D40 */	0, 0, 0, 0, IL,IL,0, 0, 0, IL,0, 0, 0, 0, IL,IL,   /* U+0D4F */
/* U+0D50 */	IL,IL,IL,IL,IL,IL,IL,0, IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0D5F */
/* U+0D60 */	1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0D6F */
/* U+0D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0D7F */
/* U+0D80 */	IL,IL,1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0D8F */
/* U+0D90 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,1, 1, 1, 1, 1, 1,    /* U+0D9F */
/* U+0DA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0DAF */
/* U+0DB0 */	1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, IL,IL,   /* U+0DBF */
/* U+0DC0 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,1, IL,IL,IL,IL,1,    /* U+0DCF */
/* U+0DD0 */	1, 1, 1, 1, 1, IL,1, IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+0DDF */
/* U+0DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0DEF */
/* U+0DF0 */	IL,IL,1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0DFF */
/* U+0E00 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0E0F */
/* U+0E10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0E1F */
/* U+0E20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0E2F */
/* U+0E30 */	1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,1,    /* U+0E3F */
/* U+0E40 */	1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,    /* U+0E4F */
/* U+0E50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+0E5F */
/* U+0E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0E6F */
/* U+0E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0E7F */
/* U+0E80 */	IL,1, 1, IL,1, IL,IL,1, 1, IL,1, IL,IL,1, IL,IL,   /* U+0E8F */
/* U+0E90 */	IL,IL,IL,IL,1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1,    /* U+0E9F */
/* U+0EA0 */	IL,1, 1, 1, IL,1, IL,1, IL,IL,1, 1, IL,1, 1, 1,    /* U+0EAF */
/* U+0EB0 */	1, 0, 1, 1, 0, 0, 0, 0, 0, 0, IL,0, 0, 1, IL,IL,   /* U+0EBF */
/* U+0EC0 */	1, 1, 1, 1, 1, IL,1, IL,0, 0, 0, 0, 0, 0, IL,IL,   /* U+0ECF */
/* U+0ED0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,1, 1, IL,IL,   /* U+0EDF */
/* U+0EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0EEF */
/* U+0EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0EFF */
/* U+0F00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0F0F */
/* U+0F10 */	1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1,    /* U+0F1F */
/* U+0F20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0F2F */
/* U+0F30 */	1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,    /* U+0F3F */
/* U+0F40 */	1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1,    /* U+0F4F */
/* U+0F50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0F5F */
/* U+0F60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+0F6F */
/* U+0F70 */	IL,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,    /* U+0F7F */
/* U+0F80 */	0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,   /* U+0F8F */
/* U+0F90 */	0, 0, 0, 0, 0, 0, 0, 0, IL,0, 0, 0, 0, 0, 0, 0,    /* U+0F9F */
/* U+0FA0 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+0FAF */
/* U+0FB0 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,1, 1,    /* U+0FBF */
/* U+0FC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+0FCF */
/* U+0FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0FDF */
/* U+0FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0FEF */
/* U+0FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+0FFF */
/* U+1000 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+100F */
/* U+1010 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+101F */
/* U+1020 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+102F */
/* U+1030 */	1, 1, 1, IL,IL,IL,0, 0, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+103F */
/* U+1040 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+104F */
/* U+1050 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+105F */
/* U+1060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+106F */
/* U+1070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+107F */
/* U+1080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+108F */
/* U+1090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+109F */
/* U+10A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+10AF */
/* U+10B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+10BF */
/* U+10C0 */	1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+10CF */
/* U+10D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+10DF */
/* U+10E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+10EF */
/* U+10F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,1, IL,IL,IL,IL,   /* U+10FF */
/* U+1100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+110F */
/* U+1110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+111F */
/* U+1120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+112F */
/* U+1130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+113F */
/* U+1140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+114F */
/* U+1150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,2,    /* U+115F */
/* U+1160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+116F */
/* U+1170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+117F */
/* U+1180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+118F */
/* U+1190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+119F */
/* U+11A0 */	2, 2, 2, IL,IL,IL,IL,IL,2, 2, 2, 2, 2, 2, 2, 2,    /* U+11AF */
/* U+11B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+11BF */
/* U+11C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+11CF */
/* U+11D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+11DF */
/* U+11E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+11EF */
/* U+11F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,   /* U+11FF */
/* U+1200 */	1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+120F */
/* U+1210 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+121F */
/* U+1220 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+122F */
/* U+1230 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+123F */
/* U+1240 */	1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, 1, 1, 1, IL,IL,   /* U+124F */
/* U+1250 */	1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, 1, 1, 1, IL,IL,   /* U+125F */
/* U+1260 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+126F */
/* U+1270 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+127F */
/* U+1280 */	1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, 1, 1, 1, IL,IL,   /* U+128F */
/* U+1290 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+129F */
/* U+12A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+12AF */
/* U+12B0 */	1, IL,1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, 1, IL,   /* U+12BF */
/* U+12C0 */	1, IL,1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, 1, IL,   /* U+12CF */
/* U+12D0 */	1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+12DF */
/* U+12E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+12EF */
/* U+12F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+12FF */
/* U+1300 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+130F */
/* U+1310 */	1, IL,1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, 1, IL,   /* U+131F */
/* U+1320 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+132F */
/* U+1330 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+133F */
/* U+1340 */	1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+134F */
/* U+1350 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+135F */
/* U+1360 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+136F */
/* U+1370 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,   /* U+137F */
/* U+1380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+138F */
/* U+1390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+139F */
/* U+13A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+13AF */
/* U+13B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+13BF */
/* U+13C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+13CF */
/* U+13D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+13DF */
/* U+13E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+13EF */
/* U+13F0 */	1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+13FF */
/* U+1400 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+140F */
/* U+1410 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+141F */
/* U+1420 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+142F */
/* U+1430 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+143F */
/* U+1440 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+144F */
/* U+1450 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+145F */
/* U+1460 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+146F */
/* U+1470 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+147F */
/* U+1480 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+148F */
/* U+1490 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+149F */
/* U+14A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14AF */
/* U+14B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14BF */
/* U+14C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14CF */
/* U+14D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14DF */
/* U+14E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14EF */
/* U+14F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+14FF */
/* U+1500 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+150F */
/* U+1510 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+151F */
/* U+1520 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+152F */
/* U+1530 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+153F */
/* U+1540 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+154F */
/* U+1550 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+155F */
/* U+1560 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+156F */
/* U+1570 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+157F */
/* U+1580 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+158F */
/* U+1590 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+159F */
/* U+15A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15AF */
/* U+15B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15BF */
/* U+15C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15CF */
/* U+15D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15DF */
/* U+15E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15EF */
/* U+15F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+15FF */
/* U+1600 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+160F */
/* U+1610 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+161F */
/* U+1620 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+162F */
/* U+1630 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+163F */
/* U+1640 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+164F */
/* U+1650 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+165F */
/* U+1660 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+166F */
/* U+1670 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+167F */
/* U+1680 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+168F */
/* U+1690 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,   /* U+169F */
/* U+16A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+16AF */
/* U+16B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+16BF */
/* U+16C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+16CF */
/* U+16D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+16DF */
/* U+16E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+16EF */
/* U+16F0 */	1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+16FF */
/* U+1700 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,    /* U+170F */
/* U+1710 */	1, 1, 0, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+171F */
/* U+1720 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+172F */
/* U+1730 */	1, 1, 0, 0, 0, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+173F */
/* U+1740 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+174F */
/* U+1750 */	1, 1, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+175F */
/* U+1760 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,    /* U+176F */
/* U+1770 */	1, IL,0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+177F */
/* U+1780 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+178F */
/* U+1790 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+179F */
/* U+17A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+17AF */
/* U+17B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+17BF */
/* U+17C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+17CF */
/* U+17D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, IL,IL,   /* U+17DF */
/* U+17E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+17EF */
/* U+17F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+17FF */
/* U+1800 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, IL,   /* U+180F */
/* U+1810 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+181F */
/* U+1820 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+182F */
/* U+1830 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+183F */
/* U+1840 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+184F */
/* U+1850 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+185F */
/* U+1860 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+186F */
/* U+1870 */	1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,   /* U+187F */
/* U+1880 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+188F */
/* U+1890 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+189F */
/* U+18A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+18AF */
/* U+18B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+18BF */
/* U+18C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+18CF */
/* U+18D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+18DF */
/* U+18E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+18EF */
/* U+18F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+18FF */
/* U+1900 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+190F */
/* U+1910 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,   /* U+191F */
/* U+1920 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,   /* U+192F */
/* U+1930 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,   /* U+193F */
/* U+1940 */	1, IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+194F */
/* U+1950 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+195F */
/* U+1960 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,   /* U+196F */
/* U+1970 */	1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+197F */
/* U+1980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+198F */
/* U+1990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+199F */
/* U+19A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+19AF */
/* U+19B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+19BF */
/* U+19C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+19CF */
/* U+19D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+19DF */
/* U+19E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+19EF */
/* U+19F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+19FF */
/* U+1A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A0F */
/* U+1A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A1F */
/* U+1A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A2F */
/* U+1A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A3F */
/* U+1A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A4F */
/* U+1A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A5F */
/* U+1A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A6F */
/* U+1A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A7F */
/* U+1A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A8F */
/* U+1A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1A9F */
/* U+1AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1AAF */
/* U+1AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1ABF */
/* U+1AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1ACF */
/* U+1AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1ADF */
/* U+1AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1AEF */
/* U+1AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1AFF */
/* U+1B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B0F */
/* U+1B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B1F */
/* U+1B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B2F */
/* U+1B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B3F */
/* U+1B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B4F */
/* U+1B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B5F */
/* U+1B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B6F */
/* U+1B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B7F */
/* U+1B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B8F */
/* U+1B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1B9F */
/* U+1BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BAF */
/* U+1BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BBF */
/* U+1BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BCF */
/* U+1BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BDF */
/* U+1BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BEF */
/* U+1BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1BFF */
/* U+1C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C0F */
/* U+1C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C1F */
/* U+1C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C2F */
/* U+1C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C3F */
/* U+1C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C4F */
/* U+1C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C5F */
/* U+1C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C6F */
/* U+1C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C7F */
/* U+1C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C8F */
/* U+1C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1C9F */
/* U+1CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CAF */
/* U+1CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CBF */
/* U+1CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CCF */
/* U+1CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CDF */
/* U+1CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CEF */
/* U+1CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1CFF */
/* U+1D00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D0F */
/* U+1D10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D1F */
/* U+1D20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D2F */
/* U+1D30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D3F */
/* U+1D40 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D4F */
/* U+1D50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1D5F */
/* U+1D60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+1D6F */
/* U+1D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1D7F */
/* U+1D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1D8F */
/* U+1D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1D9F */
/* U+1DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DAF */
/* U+1DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DBF */
/* U+1DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DCF */
/* U+1DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DDF */
/* U+1DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DEF */
/* U+1DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+1DFF */
/* U+1E00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E0F */
/* U+1E10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E1F */
/* U+1E20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E2F */
/* U+1E30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E3F */
/* U+1E40 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E4F */
/* U+1E50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E5F */
/* U+1E60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E6F */
/* U+1E70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E7F */
/* U+1E80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1E8F */
/* U+1E90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+1E9F */
/* U+1EA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1EAF */
/* U+1EB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1EBF */
/* U+1EC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1ECF */
/* U+1ED0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1EDF */
/* U+1EE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1EEF */
/* U+1EF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,   /* U+1EFF */
/* U+1F00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F0F */
/* U+1F10 */	1, 1, 1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, IL,IL,   /* U+1F1F */
/* U+1F20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F2F */
/* U+1F30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F3F */
/* U+1F40 */	1, 1, 1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, IL,IL,   /* U+1F4F */
/* U+1F50 */	1, 1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, IL,1, IL,1,    /* U+1F5F */
/* U+1F60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F6F */
/* U+1F70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,   /* U+1F7F */
/* U+1F80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F8F */
/* U+1F90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1F9F */
/* U+1FA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1FAF */
/* U+1FB0 */	1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1FBF */
/* U+1FC0 */	1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1FCF */
/* U+1FD0 */	1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1, IL,1, 1, 1,    /* U+1FDF */
/* U+1FE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+1FEF */
/* U+1FF0 */	IL,IL,1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+1FFF */
/* U+2000 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, IL,IL,IL,IL,   /* U+200F */
/* U+2010 */	2, 1, 1, 2, 2, 1, 2, 1, 2, 2, 1, 1, 2, 2, 1, 1,    /* U+201F */
/* U+2020 */	2, 2, 2, 1, 1, 2, 2, 1, 0, 0, IL,IL,IL,IL,IL,1,    /* U+202F */
/* U+2030 */	2, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1,    /* U+203F */
/* U+2040 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+204F */
/* U+2050 */	1, 1, 1, 1, 1, IL,IL,1, IL,IL,IL,IL,IL,IL,IL,1,    /* U+205F */
/* U+2060 */	0, 0, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+206F */
/* U+2070 */	1, 1, IL,IL,2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2,    /* U+207F */
/* U+2080 */	1, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+208F */
/* U+2090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+209F */
/* U+20A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+20AF */
/* U+20B0 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+20BF */
/* U+20C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+20CF */
/* U+20D0 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+20DF */
/* U+20E0 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, IL,IL,IL,IL,IL,   /* U+20EF */
/* U+20F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+20FF */
/* U+2100 */	1, 1, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1,    /* U+210F */
/* U+2110 */	1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+211F */
/* U+2120 */	1, 2, 2, 1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1,    /* U+212F */
/* U+2130 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1,    /* U+213F */
/* U+2140 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+214F */
/* U+2150 */	IL,IL,IL,2, 2, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 1,    /* U+215F */
/* U+2160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,    /* U+216F */
/* U+2170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,    /* U+217F */
/* U+2180 */	1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+218F */
/* U+2190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,    /* U+219F */
/* U+21A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21AF */
/* U+21B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21BF */
/* U+21C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21CF */
/* U+21D0 */	1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21DF */
/* U+21E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21EF */
/* U+21F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+21FF */
/* U+2200 */	2, 1, 2, 2, 1, 1, 1, 2, 2, 1, 1, 2, 1, 1, 1, 2,    /* U+220F */
/* U+2210 */	1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 2, 2, 2,    /* U+221F */
/* U+2220 */	2, 1, 1, 2, 1, 2, 1, 2, 2, 2, 2, 2, 2, 1, 2, 1,    /* U+222F */
/* U+2230 */	1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1,    /* U+223F */
/* U+2240 */	1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1,    /* U+224F */
/* U+2250 */	1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+225F */
/* U+2260 */	2, 2, 1, 1, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 2, 2,    /* U+226F */
/* U+2270 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+227F */
/* U+2280 */	1, 1, 2, 2, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+228F */
/* U+2290 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1,    /* U+229F */
/* U+22A0 */	1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+22AF */
/* U+22B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2,    /* U+22BF */
/* U+22C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+22CF */
/* U+22D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+22DF */
/* U+22E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+22EF */
/* U+22F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+22FF */
/* U+2300 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+230F */
/* U+2310 */	1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+231F */
/* U+2320 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+232F */
/* U+2330 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+233F */
/* U+2340 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+234F */
/* U+2350 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+235F */
/* U+2360 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+236F */
/* U+2370 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+237F */
/* U+2380 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+238F */
/* U+2390 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+239F */
/* U+23A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+23AF */
/* U+23B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+23BF */
/* U+23C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+23CF */
/* U+23D0 */	1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+23DF */
/* U+23E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+23EF */
/* U+23F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+23FF */
/* U+2400 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+240F */
/* U+2410 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+241F */
/* U+2420 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+242F */
/* U+2430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+243F */
/* U+2440 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,   /* U+244F */
/* U+2450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+245F */
/* U+2460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+246F */
/* U+2470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+247F */
/* U+2480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+248F */
/* U+2490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+249F */
/* U+24A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24AF */
/* U+24B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24BF */
/* U+24C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24CF */
/* U+24D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24DF */
/* U+24E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24EF */
/* U+24F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+24FF */
/* U+2500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+250F */
/* U+2510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+251F */
/* U+2520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+252F */
/* U+2530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+253F */
/* U+2540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+254F */
/* U+2550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+255F */
/* U+2560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+256F */
/* U+2570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+257F */
/* U+2580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+258F */
/* U+2590 */	2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+259F */
/* U+25A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+25AF */
/* U+25B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+25BF */
/* U+25C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+25CF */
/* U+25D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+25DF */
/* U+25E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+25EF */
/* U+25F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+25FF */
/* U+2600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+260F */
/* U+2610 */	2, 2, 2, 2, 2, 2, 2, 2, IL,1, 2, 2, 2, 2, 2, 2,    /* U+261F */
/* U+2620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+262F */
/* U+2630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+263F */
/* U+2640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+264F */
/* U+2650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+265F */
/* U+2660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+266F */
/* U+2670 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,   /* U+267F */
/* U+2680 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+268F */
/* U+2690 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+269F */
/* U+26A0 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26AF */
/* U+26B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26BF */
/* U+26C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26CF */
/* U+26D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26DF */
/* U+26E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26EF */
/* U+26F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+26FF */
/* U+2700 */	IL,1, 1, 1, 1, IL,1, 1, 1, 1, IL,IL,1, 1, 1, 1,    /* U+270F */
/* U+2710 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+271F */
/* U+2720 */	1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1,    /* U+272F */
/* U+2730 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+273F */
/* U+2740 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, IL,1,    /* U+274F */
/* U+2750 */	1, 1, 1, IL,IL,IL,1, IL,1, 1, 1, 1, 1, 1, 1, IL,   /* U+275F */
/* U+2760 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+276F */
/* U+2770 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+277F */
/* U+2780 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+278F */
/* U+2790 */	1, 1, 1, 1, 1, IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1,    /* U+279F */
/* U+27A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+27AF */
/* U+27B0 */	IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+27BF */
/* U+27C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+27CF */
/* U+27D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+27DF */
/* U+27E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,   /* U+27EF */
/* U+27F0 */	1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+27FF */
/* U+2800 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+280F */
/* U+2810 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+281F */
/* U+2820 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+282F */
/* U+2830 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+283F */
/* U+2840 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+284F */
/* U+2850 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+285F */
/* U+2860 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+286F */
/* U+2870 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+287F */
/* U+2880 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+288F */
/* U+2890 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+289F */
/* U+28A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28AF */
/* U+28B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28BF */
/* U+28C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28CF */
/* U+28D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28DF */
/* U+28E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28EF */
/* U+28F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+28FF */
/* U+2900 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+290F */
/* U+2910 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+291F */
/* U+2920 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+292F */
/* U+2930 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+293F */
/* U+2940 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+294F */
/* U+2950 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+295F */
/* U+2960 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+296F */
/* U+2970 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+297F */
/* U+2980 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+298F */
/* U+2990 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+299F */
/* U+29A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29AF */
/* U+29B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29BF */
/* U+29C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29CF */
/* U+29D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29DF */
/* U+29E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29EF */
/* U+29F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+29FF */
/* U+2A00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A0F */
/* U+2A10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A1F */
/* U+2A20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A2F */
/* U+2A30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A3F */
/* U+2A40 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A4F */
/* U+2A50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A5F */
/* U+2A60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A6F */
/* U+2A70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A7F */
/* U+2A80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A8F */
/* U+2A90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2A9F */
/* U+2AA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2AAF */
/* U+2AB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2ABF */
/* U+2AC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2ACF */
/* U+2AD0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2ADF */
/* U+2AE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2AEF */
/* U+2AF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+2AFF */
/* U+2B00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,   /* U+2B0F */
/* U+2B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B1F */
/* U+2B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B2F */
/* U+2B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B3F */
/* U+2B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B4F */
/* U+2B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B5F */
/* U+2B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B6F */
/* U+2B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B7F */
/* U+2B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B8F */
/* U+2B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2B9F */
/* U+2BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BAF */
/* U+2BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BBF */
/* U+2BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BCF */
/* U+2BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BDF */
/* U+2BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BEF */
/* U+2BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2BFF */
/* U+2C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C0F */
/* U+2C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C1F */
/* U+2C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C2F */
/* U+2C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C3F */
/* U+2C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C4F */
/* U+2C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C5F */
/* U+2C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C6F */
/* U+2C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C7F */
/* U+2C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C8F */
/* U+2C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2C9F */
/* U+2CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CAF */
/* U+2CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CBF */
/* U+2CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CCF */
/* U+2CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CDF */
/* U+2CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CEF */
/* U+2CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2CFF */
/* U+2D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D0F */
/* U+2D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D1F */
/* U+2D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D2F */
/* U+2D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D3F */
/* U+2D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D4F */
/* U+2D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D5F */
/* U+2D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D6F */
/* U+2D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D7F */
/* U+2D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D8F */
/* U+2D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2D9F */
/* U+2DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DAF */
/* U+2DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DBF */
/* U+2DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DCF */
/* U+2DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DDF */
/* U+2DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DEF */
/* U+2DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2DFF */
/* U+2E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E0F */
/* U+2E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E1F */
/* U+2E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E2F */
/* U+2E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E3F */
/* U+2E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E4F */
/* U+2E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E5F */
/* U+2E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E6F */
/* U+2E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2E7F */
/* U+2E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2E8F */
/* U+2E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,2, 2, 2, 2, 2,    /* U+2E9F */
/* U+2EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2EAF */
/* U+2EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2EBF */
/* U+2EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2ECF */
/* U+2ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2EDF */
/* U+2EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2EEF */
/* U+2EF0 */	2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2EFF */
/* U+2F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F0F */
/* U+2F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F1F */
/* U+2F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F2F */
/* U+2F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F3F */
/* U+2F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F4F */
/* U+2F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F5F */
/* U+2F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F6F */
/* U+2F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F7F */
/* U+2F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F8F */
/* U+2F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2F9F */
/* U+2FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2FAF */
/* U+2FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2FBF */
/* U+2FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+2FCF */
/* U+2FD0 */	2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2FDF */
/* U+2FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+2FEF */
/* U+2FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,   /* U+2FFF */
/* U+3000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+300F */
/* U+3010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+301F */
/* U+3020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0,    /* U+302F */
/* U+3030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1,    /* U+303F */
/* U+3040 */	IL,2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+304F */
/* U+3050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+305F */
/* U+3060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+306F */
/* U+3070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+307F */
/* U+3080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+308F */
/* U+3090 */	2, 2, 2, 2, 2, 2, 2, IL,IL,0, 0, 2, 2, 2, 2, 2,    /* U+309F */
/* U+30A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30AF */
/* U+30B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30BF */
/* U+30C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30CF */
/* U+30D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30DF */
/* U+30E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30EF */
/* U+30F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+30FF */
/* U+3100 */	IL,IL,IL,IL,IL,2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+310F */
/* U+3110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+311F */
/* U+3120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,   /* U+312F */
/* U+3130 */	IL,2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+313F */
/* U+3140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+314F */
/* U+3150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+315F */
/* U+3160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+316F */
/* U+3170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+317F */
/* U+3180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,   /* U+318F */
/* U+3190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+319F */
/* U+31A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+31AF */
/* U+31B0 */	2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,   /* U+31BF */
/* U+31C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+31CF */
/* U+31D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+31DF */
/* U+31E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+31EF */
/* U+31F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+31FF */
/* U+3200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+320F */
/* U+3210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,   /* U+321F */
/* U+3220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+322F */
/* U+3230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+323F */
/* U+3240 */	2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+324F */
/* U+3250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+325F */
/* U+3260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+326F */
/* U+3270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,2,    /* U+327F */
/* U+3280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+328F */
/* U+3290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+329F */
/* U+32A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+32AF */
/* U+32B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+32BF */
/* U+32C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+32CF */
/* U+32D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+32DF */
/* U+32E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+32EF */
/* U+32F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,   /* U+32FF */
/* U+3300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+330F */
/* U+3310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+331F */
/* U+3320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+332F */
/* U+3330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+333F */
/* U+3340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+334F */
/* U+3350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+335F */
/* U+3360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+336F */
/* U+3370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+337F */
/* U+3380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+338F */
/* U+3390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+339F */
/* U+33A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33AF */
/* U+33B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33BF */
/* U+33C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33CF */
/* U+33D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33DF */
/* U+33E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33EF */
/* U+33F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+33FF */
/* U+3400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+340F */
/* U+3410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+341F */
/* U+3420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+342F */
/* U+3430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+343F */
/* U+3440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+344F */
/* U+3450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+345F */
/* U+3460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+346F */
/* U+3470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+347F */
/* U+3480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+348F */
/* U+3490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+349F */
/* U+34A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34AF */
/* U+34B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34BF */
/* U+34C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34CF */
/* U+34D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34DF */
/* U+34E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34EF */
/* U+34F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+34FF */
/* U+3500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+350F */
/* U+3510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+351F */
/* U+3520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+352F */
/* U+3530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+353F */
/* U+3540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+354F */
/* U+3550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+355F */
/* U+3560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+356F */
/* U+3570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+357F */
/* U+3580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+358F */
/* U+3590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+359F */
/* U+35A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35AF */
/* U+35B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35BF */
/* U+35C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35CF */
/* U+35D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35DF */
/* U+35E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35EF */
/* U+35F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+35FF */
/* U+3600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+360F */
/* U+3610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+361F */
/* U+3620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+362F */
/* U+3630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+363F */
/* U+3640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+364F */
/* U+3650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+365F */
/* U+3660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+366F */
/* U+3670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+367F */
/* U+3680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+368F */
/* U+3690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+369F */
/* U+36A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36AF */
/* U+36B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36BF */
/* U+36C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36CF */
/* U+36D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36DF */
/* U+36E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36EF */
/* U+36F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+36FF */
/* U+3700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+370F */
/* U+3710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+371F */
/* U+3720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+372F */
/* U+3730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+373F */
/* U+3740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+374F */
/* U+3750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+375F */
/* U+3760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+376F */
/* U+3770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+377F */
/* U+3780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+378F */
/* U+3790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+379F */
/* U+37A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37AF */
/* U+37B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37BF */
/* U+37C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37CF */
/* U+37D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37DF */
/* U+37E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37EF */
/* U+37F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+37FF */
/* U+3800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+380F */
/* U+3810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+381F */
/* U+3820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+382F */
/* U+3830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+383F */
/* U+3840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+384F */
/* U+3850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+385F */
/* U+3860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+386F */
/* U+3870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+387F */
/* U+3880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+388F */
/* U+3890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+389F */
/* U+38A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38AF */
/* U+38B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38BF */
/* U+38C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38CF */
/* U+38D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38DF */
/* U+38E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38EF */
/* U+38F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+38FF */
/* U+3900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+390F */
/* U+3910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+391F */
/* U+3920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+392F */
/* U+3930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+393F */
/* U+3940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+394F */
/* U+3950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+395F */
/* U+3960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+396F */
/* U+3970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+397F */
/* U+3980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+398F */
/* U+3990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+399F */
/* U+39A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39AF */
/* U+39B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39BF */
/* U+39C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39CF */
/* U+39D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39DF */
/* U+39E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39EF */
/* U+39F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+39FF */
/* U+3A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A0F */
/* U+3A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A1F */
/* U+3A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A2F */
/* U+3A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A3F */
/* U+3A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A4F */
/* U+3A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A5F */
/* U+3A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A6F */
/* U+3A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A7F */
/* U+3A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A8F */
/* U+3A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3A9F */
/* U+3AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3AAF */
/* U+3AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3ABF */
/* U+3AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3ACF */
/* U+3AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3ADF */
/* U+3AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3AEF */
/* U+3AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3AFF */
/* U+3B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B0F */
/* U+3B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B1F */
/* U+3B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B2F */
/* U+3B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B3F */
/* U+3B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B4F */
/* U+3B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B5F */
/* U+3B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B6F */
/* U+3B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B7F */
/* U+3B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B8F */
/* U+3B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3B9F */
/* U+3BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BAF */
/* U+3BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BBF */
/* U+3BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BCF */
/* U+3BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BDF */
/* U+3BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BEF */
/* U+3BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3BFF */
/* U+3C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C0F */
/* U+3C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C1F */
/* U+3C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C2F */
/* U+3C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C3F */
/* U+3C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C4F */
/* U+3C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C5F */
/* U+3C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C6F */
/* U+3C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C7F */
/* U+3C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C8F */
/* U+3C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3C9F */
/* U+3CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CAF */
/* U+3CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CBF */
/* U+3CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CCF */
/* U+3CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CDF */
/* U+3CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CEF */
/* U+3CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3CFF */
/* U+3D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D0F */
/* U+3D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D1F */
/* U+3D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D2F */
/* U+3D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D3F */
/* U+3D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D4F */
/* U+3D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D5F */
/* U+3D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D6F */
/* U+3D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D7F */
/* U+3D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D8F */
/* U+3D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3D9F */
/* U+3DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DAF */
/* U+3DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DBF */
/* U+3DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DCF */
/* U+3DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DDF */
/* U+3DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DEF */
/* U+3DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3DFF */
/* U+3E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E0F */
/* U+3E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E1F */
/* U+3E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E2F */
/* U+3E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E3F */
/* U+3E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E4F */
/* U+3E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E5F */
/* U+3E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E6F */
/* U+3E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E7F */
/* U+3E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E8F */
/* U+3E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3E9F */
/* U+3EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3EAF */
/* U+3EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3EBF */
/* U+3EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3ECF */
/* U+3ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3EDF */
/* U+3EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3EEF */
/* U+3EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3EFF */
/* U+3F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F0F */
/* U+3F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F1F */
/* U+3F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F2F */
/* U+3F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F3F */
/* U+3F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F4F */
/* U+3F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F5F */
/* U+3F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F6F */
/* U+3F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F7F */
/* U+3F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F8F */
/* U+3F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3F9F */
/* U+3FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FAF */
/* U+3FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FBF */
/* U+3FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FCF */
/* U+3FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FDF */
/* U+3FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FEF */
/* U+3FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+3FFF */
/* U+4000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+400F */
/* U+4010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+401F */
/* U+4020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+402F */
/* U+4030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+403F */
/* U+4040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+404F */
/* U+4050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+405F */
/* U+4060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+406F */
/* U+4070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+407F */
/* U+4080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+408F */
/* U+4090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+409F */
/* U+40A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40AF */
/* U+40B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40BF */
/* U+40C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40CF */
/* U+40D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40DF */
/* U+40E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40EF */
/* U+40F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+40FF */
/* U+4100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+410F */
/* U+4110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+411F */
/* U+4120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+412F */
/* U+4130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+413F */
/* U+4140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+414F */
/* U+4150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+415F */
/* U+4160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+416F */
/* U+4170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+417F */
/* U+4180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+418F */
/* U+4190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+419F */
/* U+41A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41AF */
/* U+41B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41BF */
/* U+41C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41CF */
/* U+41D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41DF */
/* U+41E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41EF */
/* U+41F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+41FF */
/* U+4200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+420F */
/* U+4210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+421F */
/* U+4220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+422F */
/* U+4230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+423F */
/* U+4240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+424F */
/* U+4250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+425F */
/* U+4260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+426F */
/* U+4270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+427F */
/* U+4280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+428F */
/* U+4290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+429F */
/* U+42A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42AF */
/* U+42B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42BF */
/* U+42C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42CF */
/* U+42D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42DF */
/* U+42E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42EF */
/* U+42F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+42FF */
/* U+4300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+430F */
/* U+4310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+431F */
/* U+4320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+432F */
/* U+4330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+433F */
/* U+4340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+434F */
/* U+4350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+435F */
/* U+4360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+436F */
/* U+4370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+437F */
/* U+4380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+438F */
/* U+4390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+439F */
/* U+43A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43AF */
/* U+43B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43BF */
/* U+43C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43CF */
/* U+43D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43DF */
/* U+43E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43EF */
/* U+43F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+43FF */
/* U+4400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+440F */
/* U+4410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+441F */
/* U+4420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+442F */
/* U+4430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+443F */
/* U+4440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+444F */
/* U+4450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+445F */
/* U+4460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+446F */
/* U+4470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+447F */
/* U+4480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+448F */
/* U+4490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+449F */
/* U+44A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44AF */
/* U+44B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44BF */
/* U+44C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44CF */
/* U+44D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44DF */
/* U+44E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44EF */
/* U+44F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+44FF */
/* U+4500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+450F */
/* U+4510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+451F */
/* U+4520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+452F */
/* U+4530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+453F */
/* U+4540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+454F */
/* U+4550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+455F */
/* U+4560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+456F */
/* U+4570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+457F */
/* U+4580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+458F */
/* U+4590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+459F */
/* U+45A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45AF */
/* U+45B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45BF */
/* U+45C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45CF */
/* U+45D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45DF */
/* U+45E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45EF */
/* U+45F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+45FF */
/* U+4600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+460F */
/* U+4610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+461F */
/* U+4620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+462F */
/* U+4630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+463F */
/* U+4640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+464F */
/* U+4650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+465F */
/* U+4660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+466F */
/* U+4670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+467F */
/* U+4680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+468F */
/* U+4690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+469F */
/* U+46A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46AF */
/* U+46B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46BF */
/* U+46C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46CF */
/* U+46D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46DF */
/* U+46E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46EF */
/* U+46F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+46FF */
/* U+4700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+470F */
/* U+4710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+471F */
/* U+4720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+472F */
/* U+4730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+473F */
/* U+4740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+474F */
/* U+4750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+475F */
/* U+4760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+476F */
/* U+4770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+477F */
/* U+4780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+478F */
/* U+4790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+479F */
/* U+47A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47AF */
/* U+47B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47BF */
/* U+47C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47CF */
/* U+47D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47DF */
/* U+47E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47EF */
/* U+47F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+47FF */
/* U+4800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+480F */
/* U+4810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+481F */
/* U+4820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+482F */
/* U+4830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+483F */
/* U+4840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+484F */
/* U+4850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+485F */
/* U+4860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+486F */
/* U+4870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+487F */
/* U+4880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+488F */
/* U+4890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+489F */
/* U+48A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48AF */
/* U+48B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48BF */
/* U+48C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48CF */
/* U+48D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48DF */
/* U+48E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48EF */
/* U+48F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+48FF */
/* U+4900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+490F */
/* U+4910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+491F */
/* U+4920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+492F */
/* U+4930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+493F */
/* U+4940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+494F */
/* U+4950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+495F */
/* U+4960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+496F */
/* U+4970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+497F */
/* U+4980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+498F */
/* U+4990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+499F */
/* U+49A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49AF */
/* U+49B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49BF */
/* U+49C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49CF */
/* U+49D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49DF */
/* U+49E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49EF */
/* U+49F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+49FF */
/* U+4A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A0F */
/* U+4A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A1F */
/* U+4A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A2F */
/* U+4A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A3F */
/* U+4A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A4F */
/* U+4A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A5F */
/* U+4A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A6F */
/* U+4A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A7F */
/* U+4A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A8F */
/* U+4A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4A9F */
/* U+4AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4AAF */
/* U+4AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4ABF */
/* U+4AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4ACF */
/* U+4AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4ADF */
/* U+4AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4AEF */
/* U+4AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4AFF */
/* U+4B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B0F */
/* U+4B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B1F */
/* U+4B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B2F */
/* U+4B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B3F */
/* U+4B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B4F */
/* U+4B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B5F */
/* U+4B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B6F */
/* U+4B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B7F */
/* U+4B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B8F */
/* U+4B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4B9F */
/* U+4BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BAF */
/* U+4BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BBF */
/* U+4BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BCF */
/* U+4BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BDF */
/* U+4BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BEF */
/* U+4BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4BFF */
/* U+4C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C0F */
/* U+4C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C1F */
/* U+4C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C2F */
/* U+4C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C3F */
/* U+4C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C4F */
/* U+4C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C5F */
/* U+4C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C6F */
/* U+4C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C7F */
/* U+4C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C8F */
/* U+4C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4C9F */
/* U+4CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CAF */
/* U+4CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CBF */
/* U+4CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CCF */
/* U+4CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CDF */
/* U+4CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CEF */
/* U+4CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4CFF */
/* U+4D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D0F */
/* U+4D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D1F */
/* U+4D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D2F */
/* U+4D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D3F */
/* U+4D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D4F */
/* U+4D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D5F */
/* U+4D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D6F */
/* U+4D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D7F */
/* U+4D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D8F */
/* U+4D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4D9F */
/* U+4DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4DAF */
/* U+4DB0 */	2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+4DBF */
/* U+4DC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+4DCF */
/* U+4DD0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+4DDF */
/* U+4DE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+4DEF */
/* U+4DF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+4DFF */
/* U+4E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E0F */
/* U+4E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E1F */
/* U+4E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E2F */
/* U+4E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E3F */
/* U+4E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E4F */
/* U+4E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E5F */
/* U+4E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E6F */
/* U+4E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E7F */
/* U+4E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E8F */
/* U+4E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4E9F */
/* U+4EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4EAF */
/* U+4EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4EBF */
/* U+4EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4ECF */
/* U+4ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4EDF */
/* U+4EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4EEF */
/* U+4EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4EFF */
/* U+4F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F0F */
/* U+4F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F1F */
/* U+4F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F2F */
/* U+4F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F3F */
/* U+4F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F4F */
/* U+4F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F5F */
/* U+4F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F6F */
/* U+4F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F7F */
/* U+4F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F8F */
/* U+4F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4F9F */
/* U+4FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FAF */
/* U+4FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FBF */
/* U+4FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FCF */
/* U+4FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FDF */
/* U+4FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FEF */
/* U+4FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+4FFF */
/* U+5000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+500F */
/* U+5010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+501F */
/* U+5020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+502F */
/* U+5030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+503F */
/* U+5040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+504F */
/* U+5050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+505F */
/* U+5060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+506F */
/* U+5070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+507F */
/* U+5080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+508F */
/* U+5090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+509F */
/* U+50A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50AF */
/* U+50B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50BF */
/* U+50C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50CF */
/* U+50D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50DF */
/* U+50E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50EF */
/* U+50F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+50FF */
/* U+5100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+510F */
/* U+5110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+511F */
/* U+5120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+512F */
/* U+5130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+513F */
/* U+5140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+514F */
/* U+5150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+515F */
/* U+5160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+516F */
/* U+5170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+517F */
/* U+5180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+518F */
/* U+5190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+519F */
/* U+51A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51AF */
/* U+51B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51BF */
/* U+51C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51CF */
/* U+51D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51DF */
/* U+51E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51EF */
/* U+51F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+51FF */
/* U+5200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+520F */
/* U+5210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+521F */
/* U+5220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+522F */
/* U+5230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+523F */
/* U+5240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+524F */
/* U+5250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+525F */
/* U+5260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+526F */
/* U+5270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+527F */
/* U+5280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+528F */
/* U+5290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+529F */
/* U+52A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52AF */
/* U+52B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52BF */
/* U+52C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52CF */
/* U+52D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52DF */
/* U+52E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52EF */
/* U+52F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+52FF */
/* U+5300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+530F */
/* U+5310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+531F */
/* U+5320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+532F */
/* U+5330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+533F */
/* U+5340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+534F */
/* U+5350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+535F */
/* U+5360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+536F */
/* U+5370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+537F */
/* U+5380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+538F */
/* U+5390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+539F */
/* U+53A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53AF */
/* U+53B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53BF */
/* U+53C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53CF */
/* U+53D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53DF */
/* U+53E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53EF */
/* U+53F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+53FF */
/* U+5400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+540F */
/* U+5410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+541F */
/* U+5420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+542F */
/* U+5430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+543F */
/* U+5440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+544F */
/* U+5450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+545F */
/* U+5460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+546F */
/* U+5470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+547F */
/* U+5480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+548F */
/* U+5490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+549F */
/* U+54A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54AF */
/* U+54B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54BF */
/* U+54C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54CF */
/* U+54D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54DF */
/* U+54E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54EF */
/* U+54F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+54FF */
/* U+5500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+550F */
/* U+5510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+551F */
/* U+5520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+552F */
/* U+5530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+553F */
/* U+5540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+554F */
/* U+5550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+555F */
/* U+5560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+556F */
/* U+5570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+557F */
/* U+5580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+558F */
/* U+5590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+559F */
/* U+55A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55AF */
/* U+55B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55BF */
/* U+55C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55CF */
/* U+55D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55DF */
/* U+55E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55EF */
/* U+55F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+55FF */
/* U+5600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+560F */
/* U+5610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+561F */
/* U+5620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+562F */
/* U+5630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+563F */
/* U+5640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+564F */
/* U+5650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+565F */
/* U+5660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+566F */
/* U+5670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+567F */
/* U+5680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+568F */
/* U+5690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+569F */
/* U+56A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56AF */
/* U+56B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56BF */
/* U+56C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56CF */
/* U+56D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56DF */
/* U+56E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56EF */
/* U+56F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+56FF */
/* U+5700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+570F */
/* U+5710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+571F */
/* U+5720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+572F */
/* U+5730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+573F */
/* U+5740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+574F */
/* U+5750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+575F */
/* U+5760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+576F */
/* U+5770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+577F */
/* U+5780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+578F */
/* U+5790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+579F */
/* U+57A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57AF */
/* U+57B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57BF */
/* U+57C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57CF */
/* U+57D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57DF */
/* U+57E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57EF */
/* U+57F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+57FF */
/* U+5800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+580F */
/* U+5810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+581F */
/* U+5820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+582F */
/* U+5830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+583F */
/* U+5840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+584F */
/* U+5850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+585F */
/* U+5860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+586F */
/* U+5870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+587F */
/* U+5880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+588F */
/* U+5890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+589F */
/* U+58A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58AF */
/* U+58B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58BF */
/* U+58C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58CF */
/* U+58D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58DF */
/* U+58E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58EF */
/* U+58F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+58FF */
/* U+5900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+590F */
/* U+5910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+591F */
/* U+5920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+592F */
/* U+5930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+593F */
/* U+5940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+594F */
/* U+5950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+595F */
/* U+5960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+596F */
/* U+5970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+597F */
/* U+5980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+598F */
/* U+5990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+599F */
/* U+59A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59AF */
/* U+59B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59BF */
/* U+59C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59CF */
/* U+59D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59DF */
/* U+59E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59EF */
/* U+59F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+59FF */
/* U+5A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A0F */
/* U+5A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A1F */
/* U+5A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A2F */
/* U+5A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A3F */
/* U+5A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A4F */
/* U+5A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A5F */
/* U+5A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A6F */
/* U+5A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A7F */
/* U+5A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A8F */
/* U+5A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5A9F */
/* U+5AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5AAF */
/* U+5AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5ABF */
/* U+5AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5ACF */
/* U+5AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5ADF */
/* U+5AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5AEF */
/* U+5AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5AFF */
/* U+5B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B0F */
/* U+5B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B1F */
/* U+5B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B2F */
/* U+5B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B3F */
/* U+5B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B4F */
/* U+5B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B5F */
/* U+5B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B6F */
/* U+5B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B7F */
/* U+5B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B8F */
/* U+5B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5B9F */
/* U+5BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BAF */
/* U+5BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BBF */
/* U+5BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BCF */
/* U+5BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BDF */
/* U+5BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BEF */
/* U+5BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5BFF */
/* U+5C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C0F */
/* U+5C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C1F */
/* U+5C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C2F */
/* U+5C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C3F */
/* U+5C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C4F */
/* U+5C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C5F */
/* U+5C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C6F */
/* U+5C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C7F */
/* U+5C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C8F */
/* U+5C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5C9F */
/* U+5CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CAF */
/* U+5CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CBF */
/* U+5CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CCF */
/* U+5CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CDF */
/* U+5CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CEF */
/* U+5CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5CFF */
/* U+5D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D0F */
/* U+5D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D1F */
/* U+5D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D2F */
/* U+5D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D3F */
/* U+5D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D4F */
/* U+5D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D5F */
/* U+5D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D6F */
/* U+5D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D7F */
/* U+5D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D8F */
/* U+5D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5D9F */
/* U+5DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DAF */
/* U+5DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DBF */
/* U+5DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DCF */
/* U+5DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DDF */
/* U+5DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DEF */
/* U+5DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5DFF */
/* U+5E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E0F */
/* U+5E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E1F */
/* U+5E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E2F */
/* U+5E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E3F */
/* U+5E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E4F */
/* U+5E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E5F */
/* U+5E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E6F */
/* U+5E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E7F */
/* U+5E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E8F */
/* U+5E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5E9F */
/* U+5EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5EAF */
/* U+5EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5EBF */
/* U+5EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5ECF */
/* U+5ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5EDF */
/* U+5EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5EEF */
/* U+5EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5EFF */
/* U+5F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F0F */
/* U+5F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F1F */
/* U+5F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F2F */
/* U+5F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F3F */
/* U+5F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F4F */
/* U+5F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F5F */
/* U+5F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F6F */
/* U+5F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F7F */
/* U+5F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F8F */
/* U+5F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5F9F */
/* U+5FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FAF */
/* U+5FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FBF */
/* U+5FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FCF */
/* U+5FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FDF */
/* U+5FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FEF */
/* U+5FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+5FFF */
/* U+6000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+600F */
/* U+6010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+601F */
/* U+6020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+602F */
/* U+6030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+603F */
/* U+6040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+604F */
/* U+6050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+605F */
/* U+6060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+606F */
/* U+6070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+607F */
/* U+6080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+608F */
/* U+6090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+609F */
/* U+60A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60AF */
/* U+60B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60BF */
/* U+60C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60CF */
/* U+60D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60DF */
/* U+60E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60EF */
/* U+60F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+60FF */
/* U+6100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+610F */
/* U+6110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+611F */
/* U+6120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+612F */
/* U+6130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+613F */
/* U+6140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+614F */
/* U+6150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+615F */
/* U+6160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+616F */
/* U+6170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+617F */
/* U+6180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+618F */
/* U+6190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+619F */
/* U+61A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61AF */
/* U+61B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61BF */
/* U+61C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61CF */
/* U+61D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61DF */
/* U+61E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61EF */
/* U+61F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+61FF */
/* U+6200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+620F */
/* U+6210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+621F */
/* U+6220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+622F */
/* U+6230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+623F */
/* U+6240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+624F */
/* U+6250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+625F */
/* U+6260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+626F */
/* U+6270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+627F */
/* U+6280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+628F */
/* U+6290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+629F */
/* U+62A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62AF */
/* U+62B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62BF */
/* U+62C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62CF */
/* U+62D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62DF */
/* U+62E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62EF */
/* U+62F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+62FF */
/* U+6300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+630F */
/* U+6310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+631F */
/* U+6320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+632F */
/* U+6330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+633F */
/* U+6340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+634F */
/* U+6350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+635F */
/* U+6360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+636F */
/* U+6370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+637F */
/* U+6380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+638F */
/* U+6390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+639F */
/* U+63A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63AF */
/* U+63B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63BF */
/* U+63C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63CF */
/* U+63D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63DF */
/* U+63E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63EF */
/* U+63F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+63FF */
/* U+6400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+640F */
/* U+6410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+641F */
/* U+6420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+642F */
/* U+6430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+643F */
/* U+6440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+644F */
/* U+6450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+645F */
/* U+6460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+646F */
/* U+6470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+647F */
/* U+6480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+648F */
/* U+6490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+649F */
/* U+64A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64AF */
/* U+64B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64BF */
/* U+64C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64CF */
/* U+64D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64DF */
/* U+64E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64EF */
/* U+64F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+64FF */
/* U+6500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+650F */
/* U+6510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+651F */
/* U+6520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+652F */
/* U+6530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+653F */
/* U+6540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+654F */
/* U+6550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+655F */
/* U+6560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+656F */
/* U+6570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+657F */
/* U+6580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+658F */
/* U+6590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+659F */
/* U+65A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65AF */
/* U+65B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65BF */
/* U+65C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65CF */
/* U+65D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65DF */
/* U+65E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65EF */
/* U+65F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+65FF */
/* U+6600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+660F */
/* U+6610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+661F */
/* U+6620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+662F */
/* U+6630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+663F */
/* U+6640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+664F */
/* U+6650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+665F */
/* U+6660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+666F */
/* U+6670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+667F */
/* U+6680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+668F */
/* U+6690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+669F */
/* U+66A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66AF */
/* U+66B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66BF */
/* U+66C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66CF */
/* U+66D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66DF */
/* U+66E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66EF */
/* U+66F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+66FF */
/* U+6700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+670F */
/* U+6710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+671F */
/* U+6720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+672F */
/* U+6730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+673F */
/* U+6740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+674F */
/* U+6750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+675F */
/* U+6760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+676F */
/* U+6770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+677F */
/* U+6780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+678F */
/* U+6790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+679F */
/* U+67A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67AF */
/* U+67B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67BF */
/* U+67C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67CF */
/* U+67D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67DF */
/* U+67E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67EF */
/* U+67F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+67FF */
/* U+6800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+680F */
/* U+6810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+681F */
/* U+6820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+682F */
/* U+6830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+683F */
/* U+6840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+684F */
/* U+6850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+685F */
/* U+6860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+686F */
/* U+6870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+687F */
/* U+6880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+688F */
/* U+6890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+689F */
/* U+68A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68AF */
/* U+68B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68BF */
/* U+68C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68CF */
/* U+68D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68DF */
/* U+68E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68EF */
/* U+68F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+68FF */
/* U+6900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+690F */
/* U+6910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+691F */
/* U+6920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+692F */
/* U+6930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+693F */
/* U+6940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+694F */
/* U+6950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+695F */
/* U+6960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+696F */
/* U+6970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+697F */
/* U+6980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+698F */
/* U+6990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+699F */
/* U+69A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69AF */
/* U+69B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69BF */
/* U+69C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69CF */
/* U+69D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69DF */
/* U+69E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69EF */
/* U+69F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+69FF */
/* U+6A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A0F */
/* U+6A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A1F */
/* U+6A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A2F */
/* U+6A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A3F */
/* U+6A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A4F */
/* U+6A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A5F */
/* U+6A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A6F */
/* U+6A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A7F */
/* U+6A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A8F */
/* U+6A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6A9F */
/* U+6AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6AAF */
/* U+6AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6ABF */
/* U+6AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6ACF */
/* U+6AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6ADF */
/* U+6AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6AEF */
/* U+6AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6AFF */
/* U+6B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B0F */
/* U+6B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B1F */
/* U+6B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B2F */
/* U+6B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B3F */
/* U+6B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B4F */
/* U+6B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B5F */
/* U+6B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B6F */
/* U+6B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B7F */
/* U+6B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B8F */
/* U+6B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6B9F */
/* U+6BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BAF */
/* U+6BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BBF */
/* U+6BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BCF */
/* U+6BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BDF */
/* U+6BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BEF */
/* U+6BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6BFF */
/* U+6C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C0F */
/* U+6C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C1F */
/* U+6C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C2F */
/* U+6C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C3F */
/* U+6C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C4F */
/* U+6C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C5F */
/* U+6C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C6F */
/* U+6C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C7F */
/* U+6C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C8F */
/* U+6C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6C9F */
/* U+6CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CAF */
/* U+6CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CBF */
/* U+6CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CCF */
/* U+6CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CDF */
/* U+6CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CEF */
/* U+6CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6CFF */
/* U+6D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D0F */
/* U+6D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D1F */
/* U+6D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D2F */
/* U+6D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D3F */
/* U+6D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D4F */
/* U+6D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D5F */
/* U+6D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D6F */
/* U+6D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D7F */
/* U+6D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D8F */
/* U+6D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6D9F */
/* U+6DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DAF */
/* U+6DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DBF */
/* U+6DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DCF */
/* U+6DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DDF */
/* U+6DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DEF */
/* U+6DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6DFF */
/* U+6E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E0F */
/* U+6E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E1F */
/* U+6E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E2F */
/* U+6E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E3F */
/* U+6E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E4F */
/* U+6E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E5F */
/* U+6E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E6F */
/* U+6E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E7F */
/* U+6E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E8F */
/* U+6E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6E9F */
/* U+6EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6EAF */
/* U+6EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6EBF */
/* U+6EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6ECF */
/* U+6ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6EDF */
/* U+6EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6EEF */
/* U+6EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6EFF */
/* U+6F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F0F */
/* U+6F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F1F */
/* U+6F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F2F */
/* U+6F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F3F */
/* U+6F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F4F */
/* U+6F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F5F */
/* U+6F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F6F */
/* U+6F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F7F */
/* U+6F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F8F */
/* U+6F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6F9F */
/* U+6FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FAF */
/* U+6FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FBF */
/* U+6FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FCF */
/* U+6FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FDF */
/* U+6FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FEF */
/* U+6FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+6FFF */
/* U+7000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+700F */
/* U+7010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+701F */
/* U+7020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+702F */
/* U+7030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+703F */
/* U+7040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+704F */
/* U+7050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+705F */
/* U+7060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+706F */
/* U+7070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+707F */
/* U+7080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+708F */
/* U+7090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+709F */
/* U+70A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70AF */
/* U+70B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70BF */
/* U+70C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70CF */
/* U+70D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70DF */
/* U+70E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70EF */
/* U+70F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+70FF */
/* U+7100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+710F */
/* U+7110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+711F */
/* U+7120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+712F */
/* U+7130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+713F */
/* U+7140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+714F */
/* U+7150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+715F */
/* U+7160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+716F */
/* U+7170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+717F */
/* U+7180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+718F */
/* U+7190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+719F */
/* U+71A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71AF */
/* U+71B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71BF */
/* U+71C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71CF */
/* U+71D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71DF */
/* U+71E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71EF */
/* U+71F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+71FF */
/* U+7200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+720F */
/* U+7210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+721F */
/* U+7220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+722F */
/* U+7230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+723F */
/* U+7240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+724F */
/* U+7250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+725F */
/* U+7260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+726F */
/* U+7270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+727F */
/* U+7280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+728F */
/* U+7290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+729F */
/* U+72A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72AF */
/* U+72B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72BF */
/* U+72C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72CF */
/* U+72D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72DF */
/* U+72E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72EF */
/* U+72F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+72FF */
/* U+7300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+730F */
/* U+7310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+731F */
/* U+7320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+732F */
/* U+7330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+733F */
/* U+7340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+734F */
/* U+7350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+735F */
/* U+7360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+736F */
/* U+7370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+737F */
/* U+7380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+738F */
/* U+7390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+739F */
/* U+73A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73AF */
/* U+73B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73BF */
/* U+73C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73CF */
/* U+73D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73DF */
/* U+73E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73EF */
/* U+73F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+73FF */
/* U+7400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+740F */
/* U+7410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+741F */
/* U+7420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+742F */
/* U+7430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+743F */
/* U+7440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+744F */
/* U+7450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+745F */
/* U+7460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+746F */
/* U+7470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+747F */
/* U+7480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+748F */
/* U+7490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+749F */
/* U+74A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74AF */
/* U+74B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74BF */
/* U+74C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74CF */
/* U+74D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74DF */
/* U+74E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74EF */
/* U+74F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+74FF */
/* U+7500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+750F */
/* U+7510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+751F */
/* U+7520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+752F */
/* U+7530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+753F */
/* U+7540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+754F */
/* U+7550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+755F */
/* U+7560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+756F */
/* U+7570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+757F */
/* U+7580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+758F */
/* U+7590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+759F */
/* U+75A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75AF */
/* U+75B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75BF */
/* U+75C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75CF */
/* U+75D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75DF */
/* U+75E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75EF */
/* U+75F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+75FF */
/* U+7600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+760F */
/* U+7610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+761F */
/* U+7620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+762F */
/* U+7630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+763F */
/* U+7640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+764F */
/* U+7650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+765F */
/* U+7660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+766F */
/* U+7670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+767F */
/* U+7680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+768F */
/* U+7690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+769F */
/* U+76A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76AF */
/* U+76B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76BF */
/* U+76C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76CF */
/* U+76D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76DF */
/* U+76E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76EF */
/* U+76F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+76FF */
/* U+7700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+770F */
/* U+7710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+771F */
/* U+7720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+772F */
/* U+7730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+773F */
/* U+7740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+774F */
/* U+7750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+775F */
/* U+7760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+776F */
/* U+7770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+777F */
/* U+7780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+778F */
/* U+7790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+779F */
/* U+77A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77AF */
/* U+77B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77BF */
/* U+77C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77CF */
/* U+77D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77DF */
/* U+77E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77EF */
/* U+77F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+77FF */
/* U+7800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+780F */
/* U+7810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+781F */
/* U+7820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+782F */
/* U+7830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+783F */
/* U+7840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+784F */
/* U+7850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+785F */
/* U+7860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+786F */
/* U+7870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+787F */
/* U+7880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+788F */
/* U+7890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+789F */
/* U+78A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78AF */
/* U+78B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78BF */
/* U+78C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78CF */
/* U+78D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78DF */
/* U+78E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78EF */
/* U+78F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+78FF */
/* U+7900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+790F */
/* U+7910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+791F */
/* U+7920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+792F */
/* U+7930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+793F */
/* U+7940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+794F */
/* U+7950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+795F */
/* U+7960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+796F */
/* U+7970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+797F */
/* U+7980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+798F */
/* U+7990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+799F */
/* U+79A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79AF */
/* U+79B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79BF */
/* U+79C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79CF */
/* U+79D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79DF */
/* U+79E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79EF */
/* U+79F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+79FF */
/* U+7A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A0F */
/* U+7A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A1F */
/* U+7A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A2F */
/* U+7A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A3F */
/* U+7A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A4F */
/* U+7A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A5F */
/* U+7A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A6F */
/* U+7A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A7F */
/* U+7A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A8F */
/* U+7A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7A9F */
/* U+7AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7AAF */
/* U+7AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7ABF */
/* U+7AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7ACF */
/* U+7AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7ADF */
/* U+7AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7AEF */
/* U+7AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7AFF */
/* U+7B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B0F */
/* U+7B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B1F */
/* U+7B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B2F */
/* U+7B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B3F */
/* U+7B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B4F */
/* U+7B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B5F */
/* U+7B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B6F */
/* U+7B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B7F */
/* U+7B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B8F */
/* U+7B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7B9F */
/* U+7BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BAF */
/* U+7BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BBF */
/* U+7BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BCF */
/* U+7BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BDF */
/* U+7BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BEF */
/* U+7BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7BFF */
/* U+7C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C0F */
/* U+7C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C1F */
/* U+7C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C2F */
/* U+7C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C3F */
/* U+7C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C4F */
/* U+7C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C5F */
/* U+7C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C6F */
/* U+7C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C7F */
/* U+7C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C8F */
/* U+7C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7C9F */
/* U+7CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CAF */
/* U+7CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CBF */
/* U+7CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CCF */
/* U+7CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CDF */
/* U+7CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CEF */
/* U+7CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7CFF */
/* U+7D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D0F */
/* U+7D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D1F */
/* U+7D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D2F */
/* U+7D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D3F */
/* U+7D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D4F */
/* U+7D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D5F */
/* U+7D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D6F */
/* U+7D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D7F */
/* U+7D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D8F */
/* U+7D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7D9F */
/* U+7DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DAF */
/* U+7DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DBF */
/* U+7DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DCF */
/* U+7DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DDF */
/* U+7DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DEF */
/* U+7DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7DFF */
/* U+7E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E0F */
/* U+7E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E1F */
/* U+7E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E2F */
/* U+7E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E3F */
/* U+7E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E4F */
/* U+7E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E5F */
/* U+7E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E6F */
/* U+7E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E7F */
/* U+7E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E8F */
/* U+7E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7E9F */
/* U+7EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7EAF */
/* U+7EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7EBF */
/* U+7EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7ECF */
/* U+7ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7EDF */
/* U+7EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7EEF */
/* U+7EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7EFF */
/* U+7F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F0F */
/* U+7F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F1F */
/* U+7F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F2F */
/* U+7F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F3F */
/* U+7F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F4F */
/* U+7F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F5F */
/* U+7F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F6F */
/* U+7F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F7F */
/* U+7F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F8F */
/* U+7F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7F9F */
/* U+7FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FAF */
/* U+7FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FBF */
/* U+7FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FCF */
/* U+7FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FDF */
/* U+7FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FEF */
/* U+7FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+7FFF */
/* U+8000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+800F */
/* U+8010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+801F */
/* U+8020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+802F */
/* U+8030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+803F */
/* U+8040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+804F */
/* U+8050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+805F */
/* U+8060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+806F */
/* U+8070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+807F */
/* U+8080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+808F */
/* U+8090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+809F */
/* U+80A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80AF */
/* U+80B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80BF */
/* U+80C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80CF */
/* U+80D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80DF */
/* U+80E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80EF */
/* U+80F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+80FF */
/* U+8100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+810F */
/* U+8110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+811F */
/* U+8120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+812F */
/* U+8130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+813F */
/* U+8140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+814F */
/* U+8150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+815F */
/* U+8160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+816F */
/* U+8170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+817F */
/* U+8180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+818F */
/* U+8190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+819F */
/* U+81A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81AF */
/* U+81B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81BF */
/* U+81C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81CF */
/* U+81D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81DF */
/* U+81E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81EF */
/* U+81F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+81FF */
/* U+8200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+820F */
/* U+8210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+821F */
/* U+8220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+822F */
/* U+8230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+823F */
/* U+8240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+824F */
/* U+8250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+825F */
/* U+8260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+826F */
/* U+8270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+827F */
/* U+8280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+828F */
/* U+8290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+829F */
/* U+82A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82AF */
/* U+82B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82BF */
/* U+82C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82CF */
/* U+82D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82DF */
/* U+82E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82EF */
/* U+82F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+82FF */
/* U+8300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+830F */
/* U+8310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+831F */
/* U+8320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+832F */
/* U+8330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+833F */
/* U+8340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+834F */
/* U+8350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+835F */
/* U+8360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+836F */
/* U+8370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+837F */
/* U+8380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+838F */
/* U+8390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+839F */
/* U+83A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83AF */
/* U+83B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83BF */
/* U+83C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83CF */
/* U+83D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83DF */
/* U+83E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83EF */
/* U+83F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+83FF */
/* U+8400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+840F */
/* U+8410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+841F */
/* U+8420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+842F */
/* U+8430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+843F */
/* U+8440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+844F */
/* U+8450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+845F */
/* U+8460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+846F */
/* U+8470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+847F */
/* U+8480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+848F */
/* U+8490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+849F */
/* U+84A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84AF */
/* U+84B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84BF */
/* U+84C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84CF */
/* U+84D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84DF */
/* U+84E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84EF */
/* U+84F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+84FF */
/* U+8500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+850F */
/* U+8510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+851F */
/* U+8520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+852F */
/* U+8530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+853F */
/* U+8540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+854F */
/* U+8550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+855F */
/* U+8560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+856F */
/* U+8570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+857F */
/* U+8580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+858F */
/* U+8590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+859F */
/* U+85A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85AF */
/* U+85B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85BF */
/* U+85C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85CF */
/* U+85D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85DF */
/* U+85E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85EF */
/* U+85F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+85FF */
/* U+8600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+860F */
/* U+8610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+861F */
/* U+8620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+862F */
/* U+8630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+863F */
/* U+8640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+864F */
/* U+8650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+865F */
/* U+8660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+866F */
/* U+8670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+867F */
/* U+8680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+868F */
/* U+8690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+869F */
/* U+86A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86AF */
/* U+86B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86BF */
/* U+86C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86CF */
/* U+86D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86DF */
/* U+86E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86EF */
/* U+86F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+86FF */
/* U+8700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+870F */
/* U+8710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+871F */
/* U+8720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+872F */
/* U+8730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+873F */
/* U+8740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+874F */
/* U+8750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+875F */
/* U+8760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+876F */
/* U+8770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+877F */
/* U+8780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+878F */
/* U+8790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+879F */
/* U+87A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87AF */
/* U+87B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87BF */
/* U+87C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87CF */
/* U+87D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87DF */
/* U+87E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87EF */
/* U+87F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+87FF */
/* U+8800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+880F */
/* U+8810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+881F */
/* U+8820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+882F */
/* U+8830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+883F */
/* U+8840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+884F */
/* U+8850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+885F */
/* U+8860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+886F */
/* U+8870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+887F */
/* U+8880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+888F */
/* U+8890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+889F */
/* U+88A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88AF */
/* U+88B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88BF */
/* U+88C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88CF */
/* U+88D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88DF */
/* U+88E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88EF */
/* U+88F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+88FF */
/* U+8900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+890F */
/* U+8910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+891F */
/* U+8920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+892F */
/* U+8930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+893F */
/* U+8940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+894F */
/* U+8950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+895F */
/* U+8960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+896F */
/* U+8970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+897F */
/* U+8980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+898F */
/* U+8990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+899F */
/* U+89A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89AF */
/* U+89B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89BF */
/* U+89C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89CF */
/* U+89D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89DF */
/* U+89E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89EF */
/* U+89F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+89FF */
/* U+8A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A0F */
/* U+8A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A1F */
/* U+8A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A2F */
/* U+8A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A3F */
/* U+8A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A4F */
/* U+8A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A5F */
/* U+8A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A6F */
/* U+8A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A7F */
/* U+8A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A8F */
/* U+8A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8A9F */
/* U+8AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8AAF */
/* U+8AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8ABF */
/* U+8AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8ACF */
/* U+8AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8ADF */
/* U+8AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8AEF */
/* U+8AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8AFF */
/* U+8B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B0F */
/* U+8B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B1F */
/* U+8B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B2F */
/* U+8B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B3F */
/* U+8B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B4F */
/* U+8B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B5F */
/* U+8B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B6F */
/* U+8B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B7F */
/* U+8B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B8F */
/* U+8B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8B9F */
/* U+8BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BAF */
/* U+8BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BBF */
/* U+8BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BCF */
/* U+8BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BDF */
/* U+8BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BEF */
/* U+8BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8BFF */
/* U+8C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C0F */
/* U+8C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C1F */
/* U+8C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C2F */
/* U+8C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C3F */
/* U+8C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C4F */
/* U+8C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C5F */
/* U+8C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C6F */
/* U+8C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C7F */
/* U+8C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C8F */
/* U+8C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8C9F */
/* U+8CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CAF */
/* U+8CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CBF */
/* U+8CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CCF */
/* U+8CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CDF */
/* U+8CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CEF */
/* U+8CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8CFF */
/* U+8D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D0F */
/* U+8D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D1F */
/* U+8D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D2F */
/* U+8D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D3F */
/* U+8D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D4F */
/* U+8D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D5F */
/* U+8D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D6F */
/* U+8D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D7F */
/* U+8D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D8F */
/* U+8D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8D9F */
/* U+8DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DAF */
/* U+8DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DBF */
/* U+8DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DCF */
/* U+8DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DDF */
/* U+8DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DEF */
/* U+8DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8DFF */
/* U+8E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E0F */
/* U+8E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E1F */
/* U+8E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E2F */
/* U+8E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E3F */
/* U+8E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E4F */
/* U+8E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E5F */
/* U+8E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E6F */
/* U+8E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E7F */
/* U+8E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E8F */
/* U+8E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8E9F */
/* U+8EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8EAF */
/* U+8EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8EBF */
/* U+8EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8ECF */
/* U+8ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8EDF */
/* U+8EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8EEF */
/* U+8EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8EFF */
/* U+8F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F0F */
/* U+8F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F1F */
/* U+8F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F2F */
/* U+8F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F3F */
/* U+8F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F4F */
/* U+8F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F5F */
/* U+8F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F6F */
/* U+8F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F7F */
/* U+8F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F8F */
/* U+8F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8F9F */
/* U+8FA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FAF */
/* U+8FB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FBF */
/* U+8FC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FCF */
/* U+8FD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FDF */
/* U+8FE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FEF */
/* U+8FF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+8FFF */
/* U+9000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+900F */
/* U+9010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+901F */
/* U+9020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+902F */
/* U+9030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+903F */
/* U+9040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+904F */
/* U+9050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+905F */
/* U+9060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+906F */
/* U+9070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+907F */
/* U+9080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+908F */
/* U+9090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+909F */
/* U+90A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90AF */
/* U+90B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90BF */
/* U+90C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90CF */
/* U+90D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90DF */
/* U+90E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90EF */
/* U+90F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+90FF */
/* U+9100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+910F */
/* U+9110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+911F */
/* U+9120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+912F */
/* U+9130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+913F */
/* U+9140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+914F */
/* U+9150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+915F */
/* U+9160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+916F */
/* U+9170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+917F */
/* U+9180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+918F */
/* U+9190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+919F */
/* U+91A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91AF */
/* U+91B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91BF */
/* U+91C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91CF */
/* U+91D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91DF */
/* U+91E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91EF */
/* U+91F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+91FF */
/* U+9200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+920F */
/* U+9210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+921F */
/* U+9220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+922F */
/* U+9230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+923F */
/* U+9240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+924F */
/* U+9250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+925F */
/* U+9260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+926F */
/* U+9270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+927F */
/* U+9280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+928F */
/* U+9290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+929F */
/* U+92A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92AF */
/* U+92B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92BF */
/* U+92C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92CF */
/* U+92D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92DF */
/* U+92E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92EF */
/* U+92F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+92FF */
/* U+9300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+930F */
/* U+9310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+931F */
/* U+9320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+932F */
/* U+9330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+933F */
/* U+9340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+934F */
/* U+9350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+935F */
/* U+9360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+936F */
/* U+9370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+937F */
/* U+9380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+938F */
/* U+9390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+939F */
/* U+93A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93AF */
/* U+93B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93BF */
/* U+93C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93CF */
/* U+93D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93DF */
/* U+93E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93EF */
/* U+93F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+93FF */
/* U+9400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+940F */
/* U+9410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+941F */
/* U+9420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+942F */
/* U+9430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+943F */
/* U+9440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+944F */
/* U+9450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+945F */
/* U+9460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+946F */
/* U+9470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+947F */
/* U+9480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+948F */
/* U+9490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+949F */
/* U+94A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94AF */
/* U+94B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94BF */
/* U+94C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94CF */
/* U+94D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94DF */
/* U+94E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94EF */
/* U+94F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+94FF */
/* U+9500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+950F */
/* U+9510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+951F */
/* U+9520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+952F */
/* U+9530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+953F */
/* U+9540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+954F */
/* U+9550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+955F */
/* U+9560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+956F */
/* U+9570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+957F */
/* U+9580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+958F */
/* U+9590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+959F */
/* U+95A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95AF */
/* U+95B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95BF */
/* U+95C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95CF */
/* U+95D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95DF */
/* U+95E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95EF */
/* U+95F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+95FF */
/* U+9600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+960F */
/* U+9610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+961F */
/* U+9620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+962F */
/* U+9630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+963F */
/* U+9640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+964F */
/* U+9650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+965F */
/* U+9660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+966F */
/* U+9670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+967F */
/* U+9680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+968F */
/* U+9690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+969F */
/* U+96A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96AF */
/* U+96B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96BF */
/* U+96C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96CF */
/* U+96D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96DF */
/* U+96E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96EF */
/* U+96F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+96FF */
/* U+9700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+970F */
/* U+9710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+971F */
/* U+9720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+972F */
/* U+9730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+973F */
/* U+9740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+974F */
/* U+9750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+975F */
/* U+9760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+976F */
/* U+9770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+977F */
/* U+9780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+978F */
/* U+9790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+979F */
/* U+97A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97AF */
/* U+97B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97BF */
/* U+97C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97CF */
/* U+97D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97DF */
/* U+97E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97EF */
/* U+97F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+97FF */
/* U+9800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+980F */
/* U+9810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+981F */
/* U+9820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+982F */
/* U+9830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+983F */
/* U+9840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+984F */
/* U+9850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+985F */
/* U+9860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+986F */
/* U+9870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+987F */
/* U+9880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+988F */
/* U+9890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+989F */
/* U+98A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98AF */
/* U+98B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98BF */
/* U+98C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98CF */
/* U+98D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98DF */
/* U+98E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98EF */
/* U+98F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+98FF */
/* U+9900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+990F */
/* U+9910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+991F */
/* U+9920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+992F */
/* U+9930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+993F */
/* U+9940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+994F */
/* U+9950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+995F */
/* U+9960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+996F */
/* U+9970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+997F */
/* U+9980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+998F */
/* U+9990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+999F */
/* U+99A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99AF */
/* U+99B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99BF */
/* U+99C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99CF */
/* U+99D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99DF */
/* U+99E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99EF */
/* U+99F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+99FF */
/* U+9A00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A0F */
/* U+9A10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A1F */
/* U+9A20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A2F */
/* U+9A30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A3F */
/* U+9A40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A4F */
/* U+9A50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A5F */
/* U+9A60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A6F */
/* U+9A70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A7F */
/* U+9A80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A8F */
/* U+9A90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9A9F */
/* U+9AA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9AAF */
/* U+9AB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9ABF */
/* U+9AC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9ACF */
/* U+9AD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9ADF */
/* U+9AE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9AEF */
/* U+9AF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9AFF */
/* U+9B00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B0F */
/* U+9B10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B1F */
/* U+9B20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B2F */
/* U+9B30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B3F */
/* U+9B40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B4F */
/* U+9B50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B5F */
/* U+9B60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B6F */
/* U+9B70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B7F */
/* U+9B80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B8F */
/* U+9B90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9B9F */
/* U+9BA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BAF */
/* U+9BB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BBF */
/* U+9BC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BCF */
/* U+9BD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BDF */
/* U+9BE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BEF */
/* U+9BF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9BFF */
/* U+9C00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C0F */
/* U+9C10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C1F */
/* U+9C20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C2F */
/* U+9C30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C3F */
/* U+9C40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C4F */
/* U+9C50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C5F */
/* U+9C60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C6F */
/* U+9C70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C7F */
/* U+9C80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C8F */
/* U+9C90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9C9F */
/* U+9CA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CAF */
/* U+9CB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CBF */
/* U+9CC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CCF */
/* U+9CD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CDF */
/* U+9CE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CEF */
/* U+9CF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9CFF */
/* U+9D00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D0F */
/* U+9D10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D1F */
/* U+9D20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D2F */
/* U+9D30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D3F */
/* U+9D40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D4F */
/* U+9D50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D5F */
/* U+9D60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D6F */
/* U+9D70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D7F */
/* U+9D80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D8F */
/* U+9D90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9D9F */
/* U+9DA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DAF */
/* U+9DB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DBF */
/* U+9DC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DCF */
/* U+9DD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DDF */
/* U+9DE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DEF */
/* U+9DF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9DFF */
/* U+9E00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E0F */
/* U+9E10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E1F */
/* U+9E20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E2F */
/* U+9E30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E3F */
/* U+9E40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E4F */
/* U+9E50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E5F */
/* U+9E60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E6F */
/* U+9E70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E7F */
/* U+9E80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E8F */
/* U+9E90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9E9F */
/* U+9EA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9EAF */
/* U+9EB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9EBF */
/* U+9EC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9ECF */
/* U+9ED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9EDF */
/* U+9EE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9EEF */
/* U+9EF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9EFF */
/* U+9F00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F0F */
/* U+9F10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F1F */
/* U+9F20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F2F */
/* U+9F30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F3F */
/* U+9F40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F4F */
/* U+9F50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F5F */
/* U+9F60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F6F */
/* U+9F70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F7F */
/* U+9F80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F8F */
/* U+9F90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+9F9F */
/* U+9FA0 */	2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FAF */
/* U+9FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FBF */
/* U+9FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FCF */
/* U+9FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FDF */
/* U+9FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FEF */
/* U+9FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+9FFF */
/* U+A000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A00F */
/* U+A010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A01F */
/* U+A020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A02F */
/* U+A030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A03F */
/* U+A040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A04F */
/* U+A050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A05F */
/* U+A060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A06F */
/* U+A070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A07F */
/* U+A080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A08F */
/* U+A090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A09F */
/* U+A0A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0AF */
/* U+A0B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0BF */
/* U+A0C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0CF */
/* U+A0D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0DF */
/* U+A0E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0EF */
/* U+A0F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A0FF */
/* U+A100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A10F */
/* U+A110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A11F */
/* U+A120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A12F */
/* U+A130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A13F */
/* U+A140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A14F */
/* U+A150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A15F */
/* U+A160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A16F */
/* U+A170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A17F */
/* U+A180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A18F */
/* U+A190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A19F */
/* U+A1A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1AF */
/* U+A1B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1BF */
/* U+A1C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1CF */
/* U+A1D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1DF */
/* U+A1E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1EF */
/* U+A1F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A1FF */
/* U+A200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A20F */
/* U+A210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A21F */
/* U+A220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A22F */
/* U+A230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A23F */
/* U+A240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A24F */
/* U+A250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A25F */
/* U+A260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A26F */
/* U+A270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A27F */
/* U+A280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A28F */
/* U+A290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A29F */
/* U+A2A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2AF */
/* U+A2B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2BF */
/* U+A2C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2CF */
/* U+A2D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2DF */
/* U+A2E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2EF */
/* U+A2F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A2FF */
/* U+A300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A30F */
/* U+A310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A31F */
/* U+A320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A32F */
/* U+A330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A33F */
/* U+A340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A34F */
/* U+A350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A35F */
/* U+A360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A36F */
/* U+A370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A37F */
/* U+A380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A38F */
/* U+A390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A39F */
/* U+A3A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3AF */
/* U+A3B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3BF */
/* U+A3C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3CF */
/* U+A3D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3DF */
/* U+A3E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3EF */
/* U+A3F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A3FF */
/* U+A400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A40F */
/* U+A410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A41F */
/* U+A420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A42F */
/* U+A430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A43F */
/* U+A440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A44F */
/* U+A450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A45F */
/* U+A460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A46F */
/* U+A470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A47F */
/* U+A480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,   /* U+A48F */
/* U+A490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A49F */
/* U+A4A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A4AF */
/* U+A4B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+A4BF */
/* U+A4C0 */	2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A4CF */
/* U+A4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A4DF */
/* U+A4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A4EF */
/* U+A4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A4FF */
/* U+A500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A50F */
/* U+A510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A51F */
/* U+A520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A52F */
/* U+A530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A53F */
/* U+A540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A54F */
/* U+A550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A55F */
/* U+A560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A56F */
/* U+A570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A57F */
/* U+A580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A58F */
/* U+A590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A59F */
/* U+A5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5AF */
/* U+A5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5BF */
/* U+A5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5CF */
/* U+A5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5DF */
/* U+A5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5EF */
/* U+A5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A5FF */
/* U+A600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A60F */
/* U+A610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A61F */
/* U+A620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A62F */
/* U+A630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A63F */
/* U+A640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A64F */
/* U+A650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A65F */
/* U+A660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A66F */
/* U+A670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A67F */
/* U+A680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A68F */
/* U+A690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A69F */
/* U+A6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6AF */
/* U+A6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6BF */
/* U+A6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6CF */
/* U+A6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6DF */
/* U+A6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6EF */
/* U+A6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A6FF */
/* U+A700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A70F */
/* U+A710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A71F */
/* U+A720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A72F */
/* U+A730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A73F */
/* U+A740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A74F */
/* U+A750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A75F */
/* U+A760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A76F */
/* U+A770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A77F */
/* U+A780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A78F */
/* U+A790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A79F */
/* U+A7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7AF */
/* U+A7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7BF */
/* U+A7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7CF */
/* U+A7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7DF */
/* U+A7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7EF */
/* U+A7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A7FF */
/* U+A800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A80F */
/* U+A810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A81F */
/* U+A820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A82F */
/* U+A830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A83F */
/* U+A840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A84F */
/* U+A850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A85F */
/* U+A860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A86F */
/* U+A870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A87F */
/* U+A880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A88F */
/* U+A890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A89F */
/* U+A8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8AF */
/* U+A8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8BF */
/* U+A8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8CF */
/* U+A8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8DF */
/* U+A8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8EF */
/* U+A8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A8FF */
/* U+A900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A90F */
/* U+A910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A91F */
/* U+A920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A92F */
/* U+A930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A93F */
/* U+A940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A94F */
/* U+A950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A95F */
/* U+A960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A96F */
/* U+A970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A97F */
/* U+A980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A98F */
/* U+A990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A99F */
/* U+A9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9AF */
/* U+A9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9BF */
/* U+A9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9CF */
/* U+A9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9DF */
/* U+A9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9EF */
/* U+A9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+A9FF */
/* U+AA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA0F */
/* U+AA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA1F */
/* U+AA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA2F */
/* U+AA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA3F */
/* U+AA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA4F */
/* U+AA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA5F */
/* U+AA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA6F */
/* U+AA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA7F */
/* U+AA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA8F */
/* U+AA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AA9F */
/* U+AAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AAAF */
/* U+AAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AABF */
/* U+AAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AACF */
/* U+AAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AADF */
/* U+AAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AAEF */
/* U+AAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AAFF */
/* U+AB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB0F */
/* U+AB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB1F */
/* U+AB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB2F */
/* U+AB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB3F */
/* U+AB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB4F */
/* U+AB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB5F */
/* U+AB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB6F */
/* U+AB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB7F */
/* U+AB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB8F */
/* U+AB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+AB9F */
/* U+ABA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABAF */
/* U+ABB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABBF */
/* U+ABC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABCF */
/* U+ABD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABDF */
/* U+ABE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABEF */
/* U+ABF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+ABFF */
/* U+AC00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC0F */
/* U+AC10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC1F */
/* U+AC20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC2F */
/* U+AC30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC3F */
/* U+AC40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC4F */
/* U+AC50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC5F */
/* U+AC60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC6F */
/* U+AC70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC7F */
/* U+AC80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC8F */
/* U+AC90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AC9F */
/* U+ACA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACAF */
/* U+ACB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACBF */
/* U+ACC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACCF */
/* U+ACD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACDF */
/* U+ACE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACEF */
/* U+ACF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ACFF */
/* U+AD00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD0F */
/* U+AD10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD1F */
/* U+AD20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD2F */
/* U+AD30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD3F */
/* U+AD40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD4F */
/* U+AD50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD5F */
/* U+AD60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD6F */
/* U+AD70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD7F */
/* U+AD80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD8F */
/* U+AD90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AD9F */
/* U+ADA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADAF */
/* U+ADB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADBF */
/* U+ADC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADCF */
/* U+ADD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADDF */
/* U+ADE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADEF */
/* U+ADF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+ADFF */
/* U+AE00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE0F */
/* U+AE10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE1F */
/* U+AE20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE2F */
/* U+AE30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE3F */
/* U+AE40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE4F */
/* U+AE50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE5F */
/* U+AE60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE6F */
/* U+AE70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE7F */
/* U+AE80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE8F */
/* U+AE90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AE9F */
/* U+AEA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AEAF */
/* U+AEB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AEBF */
/* U+AEC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AECF */
/* U+AED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AEDF */
/* U+AEE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AEEF */
/* U+AEF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AEFF */
/* U+AF00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF0F */
/* U+AF10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF1F */
/* U+AF20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF2F */
/* U+AF30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF3F */
/* U+AF40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF4F */
/* U+AF50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF5F */
/* U+AF60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF6F */
/* U+AF70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF7F */
/* U+AF80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF8F */
/* U+AF90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AF9F */
/* U+AFA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFAF */
/* U+AFB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFBF */
/* U+AFC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFCF */
/* U+AFD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFDF */
/* U+AFE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFEF */
/* U+AFF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+AFFF */
/* U+B000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B00F */
/* U+B010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B01F */
/* U+B020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B02F */
/* U+B030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B03F */
/* U+B040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B04F */
/* U+B050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B05F */
/* U+B060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B06F */
/* U+B070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B07F */
/* U+B080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B08F */
/* U+B090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B09F */
/* U+B0A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0AF */
/* U+B0B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0BF */
/* U+B0C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0CF */
/* U+B0D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0DF */
/* U+B0E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0EF */
/* U+B0F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B0FF */
/* U+B100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B10F */
/* U+B110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B11F */
/* U+B120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B12F */
/* U+B130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B13F */
/* U+B140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B14F */
/* U+B150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B15F */
/* U+B160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B16F */
/* U+B170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B17F */
/* U+B180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B18F */
/* U+B190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B19F */
/* U+B1A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1AF */
/* U+B1B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1BF */
/* U+B1C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1CF */
/* U+B1D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1DF */
/* U+B1E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1EF */
/* U+B1F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B1FF */
/* U+B200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B20F */
/* U+B210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B21F */
/* U+B220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B22F */
/* U+B230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B23F */
/* U+B240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B24F */
/* U+B250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B25F */
/* U+B260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B26F */
/* U+B270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B27F */
/* U+B280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B28F */
/* U+B290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B29F */
/* U+B2A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2AF */
/* U+B2B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2BF */
/* U+B2C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2CF */
/* U+B2D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2DF */
/* U+B2E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2EF */
/* U+B2F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B2FF */
/* U+B300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B30F */
/* U+B310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B31F */
/* U+B320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B32F */
/* U+B330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B33F */
/* U+B340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B34F */
/* U+B350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B35F */
/* U+B360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B36F */
/* U+B370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B37F */
/* U+B380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B38F */
/* U+B390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B39F */
/* U+B3A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3AF */
/* U+B3B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3BF */
/* U+B3C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3CF */
/* U+B3D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3DF */
/* U+B3E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3EF */
/* U+B3F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B3FF */
/* U+B400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B40F */
/* U+B410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B41F */
/* U+B420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B42F */
/* U+B430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B43F */
/* U+B440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B44F */
/* U+B450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B45F */
/* U+B460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B46F */
/* U+B470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B47F */
/* U+B480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B48F */
/* U+B490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B49F */
/* U+B4A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4AF */
/* U+B4B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4BF */
/* U+B4C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4CF */
/* U+B4D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4DF */
/* U+B4E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4EF */
/* U+B4F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B4FF */
/* U+B500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B50F */
/* U+B510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B51F */
/* U+B520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B52F */
/* U+B530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B53F */
/* U+B540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B54F */
/* U+B550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B55F */
/* U+B560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B56F */
/* U+B570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B57F */
/* U+B580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B58F */
/* U+B590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B59F */
/* U+B5A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5AF */
/* U+B5B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5BF */
/* U+B5C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5CF */
/* U+B5D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5DF */
/* U+B5E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5EF */
/* U+B5F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B5FF */
/* U+B600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B60F */
/* U+B610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B61F */
/* U+B620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B62F */
/* U+B630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B63F */
/* U+B640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B64F */
/* U+B650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B65F */
/* U+B660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B66F */
/* U+B670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B67F */
/* U+B680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B68F */
/* U+B690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B69F */
/* U+B6A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6AF */
/* U+B6B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6BF */
/* U+B6C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6CF */
/* U+B6D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6DF */
/* U+B6E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6EF */
/* U+B6F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B6FF */
/* U+B700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B70F */
/* U+B710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B71F */
/* U+B720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B72F */
/* U+B730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B73F */
/* U+B740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B74F */
/* U+B750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B75F */
/* U+B760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B76F */
/* U+B770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B77F */
/* U+B780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B78F */
/* U+B790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B79F */
/* U+B7A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7AF */
/* U+B7B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7BF */
/* U+B7C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7CF */
/* U+B7D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7DF */
/* U+B7E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7EF */
/* U+B7F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B7FF */
/* U+B800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B80F */
/* U+B810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B81F */
/* U+B820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B82F */
/* U+B830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B83F */
/* U+B840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B84F */
/* U+B850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B85F */
/* U+B860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B86F */
/* U+B870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B87F */
/* U+B880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B88F */
/* U+B890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B89F */
/* U+B8A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8AF */
/* U+B8B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8BF */
/* U+B8C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8CF */
/* U+B8D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8DF */
/* U+B8E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8EF */
/* U+B8F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B8FF */
/* U+B900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B90F */
/* U+B910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B91F */
/* U+B920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B92F */
/* U+B930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B93F */
/* U+B940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B94F */
/* U+B950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B95F */
/* U+B960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B96F */
/* U+B970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B97F */
/* U+B980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B98F */
/* U+B990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B99F */
/* U+B9A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9AF */
/* U+B9B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9BF */
/* U+B9C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9CF */
/* U+B9D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9DF */
/* U+B9E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9EF */
/* U+B9F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+B9FF */
/* U+BA00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA0F */
/* U+BA10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA1F */
/* U+BA20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA2F */
/* U+BA30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA3F */
/* U+BA40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA4F */
/* U+BA50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA5F */
/* U+BA60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA6F */
/* U+BA70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA7F */
/* U+BA80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA8F */
/* U+BA90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BA9F */
/* U+BAA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BAAF */
/* U+BAB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BABF */
/* U+BAC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BACF */
/* U+BAD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BADF */
/* U+BAE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BAEF */
/* U+BAF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BAFF */
/* U+BB00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB0F */
/* U+BB10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB1F */
/* U+BB20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB2F */
/* U+BB30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB3F */
/* U+BB40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB4F */
/* U+BB50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB5F */
/* U+BB60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB6F */
/* U+BB70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB7F */
/* U+BB80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB8F */
/* U+BB90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BB9F */
/* U+BBA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBAF */
/* U+BBB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBBF */
/* U+BBC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBCF */
/* U+BBD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBDF */
/* U+BBE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBEF */
/* U+BBF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BBFF */
/* U+BC00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC0F */
/* U+BC10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC1F */
/* U+BC20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC2F */
/* U+BC30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC3F */
/* U+BC40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC4F */
/* U+BC50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC5F */
/* U+BC60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC6F */
/* U+BC70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC7F */
/* U+BC80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC8F */
/* U+BC90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BC9F */
/* U+BCA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCAF */
/* U+BCB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCBF */
/* U+BCC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCCF */
/* U+BCD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCDF */
/* U+BCE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCEF */
/* U+BCF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BCFF */
/* U+BD00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD0F */
/* U+BD10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD1F */
/* U+BD20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD2F */
/* U+BD30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD3F */
/* U+BD40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD4F */
/* U+BD50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD5F */
/* U+BD60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD6F */
/* U+BD70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD7F */
/* U+BD80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD8F */
/* U+BD90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BD9F */
/* U+BDA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDAF */
/* U+BDB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDBF */
/* U+BDC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDCF */
/* U+BDD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDDF */
/* U+BDE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDEF */
/* U+BDF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BDFF */
/* U+BE00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE0F */
/* U+BE10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE1F */
/* U+BE20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE2F */
/* U+BE30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE3F */
/* U+BE40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE4F */
/* U+BE50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE5F */
/* U+BE60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE6F */
/* U+BE70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE7F */
/* U+BE80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE8F */
/* U+BE90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BE9F */
/* U+BEA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BEAF */
/* U+BEB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BEBF */
/* U+BEC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BECF */
/* U+BED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BEDF */
/* U+BEE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BEEF */
/* U+BEF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BEFF */
/* U+BF00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF0F */
/* U+BF10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF1F */
/* U+BF20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF2F */
/* U+BF30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF3F */
/* U+BF40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF4F */
/* U+BF50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF5F */
/* U+BF60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF6F */
/* U+BF70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF7F */
/* U+BF80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF8F */
/* U+BF90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BF9F */
/* U+BFA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFAF */
/* U+BFB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFBF */
/* U+BFC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFCF */
/* U+BFD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFDF */
/* U+BFE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFEF */
/* U+BFF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+BFFF */
/* U+C000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C00F */
/* U+C010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C01F */
/* U+C020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C02F */
/* U+C030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C03F */
/* U+C040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C04F */
/* U+C050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C05F */
/* U+C060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C06F */
/* U+C070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C07F */
/* U+C080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C08F */
/* U+C090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C09F */
/* U+C0A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0AF */
/* U+C0B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0BF */
/* U+C0C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0CF */
/* U+C0D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0DF */
/* U+C0E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0EF */
/* U+C0F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C0FF */
/* U+C100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C10F */
/* U+C110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C11F */
/* U+C120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C12F */
/* U+C130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C13F */
/* U+C140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C14F */
/* U+C150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C15F */
/* U+C160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C16F */
/* U+C170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C17F */
/* U+C180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C18F */
/* U+C190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C19F */
/* U+C1A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1AF */
/* U+C1B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1BF */
/* U+C1C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1CF */
/* U+C1D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1DF */
/* U+C1E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1EF */
/* U+C1F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C1FF */
/* U+C200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C20F */
/* U+C210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C21F */
/* U+C220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C22F */
/* U+C230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C23F */
/* U+C240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C24F */
/* U+C250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C25F */
/* U+C260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C26F */
/* U+C270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C27F */
/* U+C280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C28F */
/* U+C290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C29F */
/* U+C2A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2AF */
/* U+C2B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2BF */
/* U+C2C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2CF */
/* U+C2D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2DF */
/* U+C2E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2EF */
/* U+C2F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C2FF */
/* U+C300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C30F */
/* U+C310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C31F */
/* U+C320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C32F */
/* U+C330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C33F */
/* U+C340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C34F */
/* U+C350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C35F */
/* U+C360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C36F */
/* U+C370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C37F */
/* U+C380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C38F */
/* U+C390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C39F */
/* U+C3A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3AF */
/* U+C3B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3BF */
/* U+C3C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3CF */
/* U+C3D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3DF */
/* U+C3E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3EF */
/* U+C3F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C3FF */
/* U+C400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C40F */
/* U+C410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C41F */
/* U+C420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C42F */
/* U+C430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C43F */
/* U+C440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C44F */
/* U+C450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C45F */
/* U+C460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C46F */
/* U+C470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C47F */
/* U+C480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C48F */
/* U+C490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C49F */
/* U+C4A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4AF */
/* U+C4B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4BF */
/* U+C4C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4CF */
/* U+C4D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4DF */
/* U+C4E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4EF */
/* U+C4F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C4FF */
/* U+C500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C50F */
/* U+C510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C51F */
/* U+C520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C52F */
/* U+C530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C53F */
/* U+C540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C54F */
/* U+C550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C55F */
/* U+C560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C56F */
/* U+C570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C57F */
/* U+C580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C58F */
/* U+C590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C59F */
/* U+C5A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5AF */
/* U+C5B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5BF */
/* U+C5C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5CF */
/* U+C5D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5DF */
/* U+C5E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5EF */
/* U+C5F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C5FF */
/* U+C600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C60F */
/* U+C610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C61F */
/* U+C620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C62F */
/* U+C630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C63F */
/* U+C640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C64F */
/* U+C650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C65F */
/* U+C660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C66F */
/* U+C670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C67F */
/* U+C680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C68F */
/* U+C690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C69F */
/* U+C6A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6AF */
/* U+C6B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6BF */
/* U+C6C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6CF */
/* U+C6D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6DF */
/* U+C6E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6EF */
/* U+C6F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C6FF */
/* U+C700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C70F */
/* U+C710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C71F */
/* U+C720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C72F */
/* U+C730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C73F */
/* U+C740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C74F */
/* U+C750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C75F */
/* U+C760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C76F */
/* U+C770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C77F */
/* U+C780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C78F */
/* U+C790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C79F */
/* U+C7A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7AF */
/* U+C7B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7BF */
/* U+C7C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7CF */
/* U+C7D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7DF */
/* U+C7E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7EF */
/* U+C7F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C7FF */
/* U+C800 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C80F */
/* U+C810 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C81F */
/* U+C820 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C82F */
/* U+C830 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C83F */
/* U+C840 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C84F */
/* U+C850 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C85F */
/* U+C860 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C86F */
/* U+C870 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C87F */
/* U+C880 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C88F */
/* U+C890 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C89F */
/* U+C8A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8AF */
/* U+C8B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8BF */
/* U+C8C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8CF */
/* U+C8D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8DF */
/* U+C8E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8EF */
/* U+C8F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C8FF */
/* U+C900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C90F */
/* U+C910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C91F */
/* U+C920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C92F */
/* U+C930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C93F */
/* U+C940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C94F */
/* U+C950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C95F */
/* U+C960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C96F */
/* U+C970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C97F */
/* U+C980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C98F */
/* U+C990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C99F */
/* U+C9A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9AF */
/* U+C9B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9BF */
/* U+C9C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9CF */
/* U+C9D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9DF */
/* U+C9E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9EF */
/* U+C9F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+C9FF */
/* U+CA00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA0F */
/* U+CA10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA1F */
/* U+CA20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA2F */
/* U+CA30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA3F */
/* U+CA40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA4F */
/* U+CA50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA5F */
/* U+CA60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA6F */
/* U+CA70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA7F */
/* U+CA80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA8F */
/* U+CA90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CA9F */
/* U+CAA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CAAF */
/* U+CAB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CABF */
/* U+CAC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CACF */
/* U+CAD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CADF */
/* U+CAE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CAEF */
/* U+CAF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CAFF */
/* U+CB00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB0F */
/* U+CB10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB1F */
/* U+CB20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB2F */
/* U+CB30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB3F */
/* U+CB40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB4F */
/* U+CB50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB5F */
/* U+CB60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB6F */
/* U+CB70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB7F */
/* U+CB80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB8F */
/* U+CB90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CB9F */
/* U+CBA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBAF */
/* U+CBB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBBF */
/* U+CBC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBCF */
/* U+CBD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBDF */
/* U+CBE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBEF */
/* U+CBF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CBFF */
/* U+CC00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC0F */
/* U+CC10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC1F */
/* U+CC20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC2F */
/* U+CC30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC3F */
/* U+CC40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC4F */
/* U+CC50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC5F */
/* U+CC60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC6F */
/* U+CC70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC7F */
/* U+CC80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC8F */
/* U+CC90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CC9F */
/* U+CCA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCAF */
/* U+CCB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCBF */
/* U+CCC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCCF */
/* U+CCD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCDF */
/* U+CCE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCEF */
/* U+CCF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CCFF */
/* U+CD00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD0F */
/* U+CD10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD1F */
/* U+CD20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD2F */
/* U+CD30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD3F */
/* U+CD40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD4F */
/* U+CD50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD5F */
/* U+CD60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD6F */
/* U+CD70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD7F */
/* U+CD80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD8F */
/* U+CD90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CD9F */
/* U+CDA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDAF */
/* U+CDB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDBF */
/* U+CDC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDCF */
/* U+CDD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDDF */
/* U+CDE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDEF */
/* U+CDF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CDFF */
/* U+CE00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE0F */
/* U+CE10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE1F */
/* U+CE20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE2F */
/* U+CE30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE3F */
/* U+CE40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE4F */
/* U+CE50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE5F */
/* U+CE60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE6F */
/* U+CE70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE7F */
/* U+CE80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE8F */
/* U+CE90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CE9F */
/* U+CEA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CEAF */
/* U+CEB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CEBF */
/* U+CEC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CECF */
/* U+CED0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CEDF */
/* U+CEE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CEEF */
/* U+CEF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CEFF */
/* U+CF00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF0F */
/* U+CF10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF1F */
/* U+CF20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF2F */
/* U+CF30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF3F */
/* U+CF40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF4F */
/* U+CF50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF5F */
/* U+CF60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF6F */
/* U+CF70 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF7F */
/* U+CF80 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF8F */
/* U+CF90 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CF9F */
/* U+CFA0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFAF */
/* U+CFB0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFBF */
/* U+CFC0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFCF */
/* U+CFD0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFDF */
/* U+CFE0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFEF */
/* U+CFF0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+CFFF */
/* U+D000 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D00F */
/* U+D010 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D01F */
/* U+D020 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D02F */
/* U+D030 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D03F */
/* U+D040 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D04F */
/* U+D050 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D05F */
/* U+D060 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D06F */
/* U+D070 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D07F */
/* U+D080 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D08F */
/* U+D090 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D09F */
/* U+D0A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0AF */
/* U+D0B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0BF */
/* U+D0C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0CF */
/* U+D0D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0DF */
/* U+D0E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0EF */
/* U+D0F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D0FF */
/* U+D100 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D10F */
/* U+D110 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D11F */
/* U+D120 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D12F */
/* U+D130 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D13F */
/* U+D140 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D14F */
/* U+D150 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D15F */
/* U+D160 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D16F */
/* U+D170 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D17F */
/* U+D180 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D18F */
/* U+D190 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D19F */
/* U+D1A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1AF */
/* U+D1B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1BF */
/* U+D1C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1CF */
/* U+D1D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1DF */
/* U+D1E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1EF */
/* U+D1F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D1FF */
/* U+D200 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D20F */
/* U+D210 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D21F */
/* U+D220 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D22F */
/* U+D230 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D23F */
/* U+D240 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D24F */
/* U+D250 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D25F */
/* U+D260 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D26F */
/* U+D270 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D27F */
/* U+D280 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D28F */
/* U+D290 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D29F */
/* U+D2A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2AF */
/* U+D2B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2BF */
/* U+D2C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2CF */
/* U+D2D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2DF */
/* U+D2E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2EF */
/* U+D2F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D2FF */
/* U+D300 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D30F */
/* U+D310 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D31F */
/* U+D320 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D32F */
/* U+D330 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D33F */
/* U+D340 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D34F */
/* U+D350 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D35F */
/* U+D360 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D36F */
/* U+D370 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D37F */
/* U+D380 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D38F */
/* U+D390 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D39F */
/* U+D3A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3AF */
/* U+D3B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3BF */
/* U+D3C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3CF */
/* U+D3D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3DF */
/* U+D3E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3EF */
/* U+D3F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D3FF */
/* U+D400 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D40F */
/* U+D410 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D41F */
/* U+D420 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D42F */
/* U+D430 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D43F */
/* U+D440 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D44F */
/* U+D450 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D45F */
/* U+D460 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D46F */
/* U+D470 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D47F */
/* U+D480 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D48F */
/* U+D490 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D49F */
/* U+D4A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4AF */
/* U+D4B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4BF */
/* U+D4C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4CF */
/* U+D4D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4DF */
/* U+D4E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4EF */
/* U+D4F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D4FF */
/* U+D500 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D50F */
/* U+D510 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D51F */
/* U+D520 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D52F */
/* U+D530 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D53F */
/* U+D540 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D54F */
/* U+D550 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D55F */
/* U+D560 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D56F */
/* U+D570 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D57F */
/* U+D580 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D58F */
/* U+D590 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D59F */
/* U+D5A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5AF */
/* U+D5B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5BF */
/* U+D5C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5CF */
/* U+D5D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5DF */
/* U+D5E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5EF */
/* U+D5F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D5FF */
/* U+D600 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D60F */
/* U+D610 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D61F */
/* U+D620 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D62F */
/* U+D630 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D63F */
/* U+D640 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D64F */
/* U+D650 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D65F */
/* U+D660 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D66F */
/* U+D670 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D67F */
/* U+D680 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D68F */
/* U+D690 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D69F */
/* U+D6A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6AF */
/* U+D6B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6BF */
/* U+D6C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6CF */
/* U+D6D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6DF */
/* U+D6E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6EF */
/* U+D6F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D6FF */
/* U+D700 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D70F */
/* U+D710 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D71F */
/* U+D720 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D72F */
/* U+D730 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D73F */
/* U+D740 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D74F */
/* U+D750 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D75F */
/* U+D760 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D76F */
/* U+D770 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D77F */
/* U+D780 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D78F */
/* U+D790 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+D79F */
/* U+D7A0 */	2, 2, 2, 2, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7AF */
/* U+D7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7BF */
/* U+D7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7CF */
/* U+D7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7DF */
/* U+D7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7EF */
/* U+D7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D7FF */
/* U+D800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D80F */
/* U+D810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D81F */
/* U+D820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D82F */
/* U+D830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D83F */
/* U+D840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D84F */
/* U+D850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D85F */
/* U+D860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D86F */
/* U+D870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D87F */
/* U+D880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D88F */
/* U+D890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D89F */
/* U+D8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8AF */
/* U+D8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8BF */
/* U+D8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8CF */
/* U+D8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8DF */
/* U+D8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8EF */
/* U+D8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D8FF */
/* U+D900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D90F */
/* U+D910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D91F */
/* U+D920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D92F */
/* U+D930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D93F */
/* U+D940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D94F */
/* U+D950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D95F */
/* U+D960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D96F */
/* U+D970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D97F */
/* U+D980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D98F */
/* U+D990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D99F */
/* U+D9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9AF */
/* U+D9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9BF */
/* U+D9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9CF */
/* U+D9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9DF */
/* U+D9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9EF */
/* U+D9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+D9FF */
/* U+DA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA0F */
/* U+DA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA1F */
/* U+DA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA2F */
/* U+DA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA3F */
/* U+DA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA4F */
/* U+DA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA5F */
/* U+DA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA6F */
/* U+DA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA7F */
/* U+DA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA8F */
/* U+DA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DA9F */
/* U+DAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DAAF */
/* U+DAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DABF */
/* U+DAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DACF */
/* U+DAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DADF */
/* U+DAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DAEF */
/* U+DAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DAFF */
/* U+DB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB0F */
/* U+DB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB1F */
/* U+DB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB2F */
/* U+DB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB3F */
/* U+DB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB4F */
/* U+DB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB5F */
/* U+DB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB6F */
/* U+DB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB7F */
/* U+DB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB8F */
/* U+DB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DB9F */
/* U+DBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBAF */
/* U+DBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBBF */
/* U+DBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBCF */
/* U+DBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBDF */
/* U+DBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBEF */
/* U+DBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DBFF */
/* U+DC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC0F */
/* U+DC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC1F */
/* U+DC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC2F */
/* U+DC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC3F */
/* U+DC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC4F */
/* U+DC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC5F */
/* U+DC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC6F */
/* U+DC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC7F */
/* U+DC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC8F */
/* U+DC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DC9F */
/* U+DCA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCAF */
/* U+DCB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCBF */
/* U+DCC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCCF */
/* U+DCD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCDF */
/* U+DCE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCEF */
/* U+DCF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DCFF */
/* U+DD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD0F */
/* U+DD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD1F */
/* U+DD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD2F */
/* U+DD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD3F */
/* U+DD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD4F */
/* U+DD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD5F */
/* U+DD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD6F */
/* U+DD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD7F */
/* U+DD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD8F */
/* U+DD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DD9F */
/* U+DDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDAF */
/* U+DDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDBF */
/* U+DDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDCF */
/* U+DDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDDF */
/* U+DDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDEF */
/* U+DDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DDFF */
/* U+DE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE0F */
/* U+DE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE1F */
/* U+DE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE2F */
/* U+DE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE3F */
/* U+DE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE4F */
/* U+DE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE5F */
/* U+DE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE6F */
/* U+DE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE7F */
/* U+DE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE8F */
/* U+DE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DE9F */
/* U+DEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DEAF */
/* U+DEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DEBF */
/* U+DEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DECF */
/* U+DED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DEDF */
/* U+DEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DEEF */
/* U+DEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DEFF */
/* U+DF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF0F */
/* U+DF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF1F */
/* U+DF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF2F */
/* U+DF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF3F */
/* U+DF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF4F */
/* U+DF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF5F */
/* U+DF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF6F */
/* U+DF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF7F */
/* U+DF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF8F */
/* U+DF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DF9F */
/* U+DFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFAF */
/* U+DFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFBF */
/* U+DFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFCF */
/* U+DFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFDF */
/* U+DFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFEF */
/* U+DFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+DFFF */
/* U+E000 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E00F */
/* U+E010 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E01F */
/* U+E020 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E02F */
/* U+E030 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E03F */
/* U+E040 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E04F */
/* U+E050 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E05F */
/* U+E060 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E06F */
/* U+E070 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E07F */
/* U+E080 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E08F */
/* U+E090 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E09F */
/* U+E0A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0AF */
/* U+E0B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0BF */
/* U+E0C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0CF */
/* U+E0D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0DF */
/* U+E0E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0EF */
/* U+E0F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E0FF */
/* U+E100 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E10F */
/* U+E110 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E11F */
/* U+E120 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E12F */
/* U+E130 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E13F */
/* U+E140 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E14F */
/* U+E150 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E15F */
/* U+E160 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E16F */
/* U+E170 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E17F */
/* U+E180 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E18F */
/* U+E190 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E19F */
/* U+E1A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1AF */
/* U+E1B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1BF */
/* U+E1C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1CF */
/* U+E1D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1DF */
/* U+E1E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1EF */
/* U+E1F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E1FF */
/* U+E200 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E20F */
/* U+E210 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E21F */
/* U+E220 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E22F */
/* U+E230 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E23F */
/* U+E240 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E24F */
/* U+E250 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E25F */
/* U+E260 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E26F */
/* U+E270 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E27F */
/* U+E280 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E28F */
/* U+E290 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E29F */
/* U+E2A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2AF */
/* U+E2B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2BF */
/* U+E2C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2CF */
/* U+E2D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2DF */
/* U+E2E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2EF */
/* U+E2F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E2FF */
/* U+E300 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E30F */
/* U+E310 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E31F */
/* U+E320 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E32F */
/* U+E330 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E33F */
/* U+E340 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E34F */
/* U+E350 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E35F */
/* U+E360 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E36F */
/* U+E370 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E37F */
/* U+E380 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E38F */
/* U+E390 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E39F */
/* U+E3A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3AF */
/* U+E3B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3BF */
/* U+E3C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3CF */
/* U+E3D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3DF */
/* U+E3E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3EF */
/* U+E3F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E3FF */
/* U+E400 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E40F */
/* U+E410 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E41F */
/* U+E420 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E42F */
/* U+E430 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E43F */
/* U+E440 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E44F */
/* U+E450 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E45F */
/* U+E460 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E46F */
/* U+E470 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E47F */
/* U+E480 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E48F */
/* U+E490 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E49F */
/* U+E4A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4AF */
/* U+E4B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4BF */
/* U+E4C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4CF */
/* U+E4D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4DF */
/* U+E4E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4EF */
/* U+E4F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E4FF */
/* U+E500 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E50F */
/* U+E510 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E51F */
/* U+E520 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E52F */
/* U+E530 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E53F */
/* U+E540 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E54F */
/* U+E550 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E55F */
/* U+E560 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E56F */
/* U+E570 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E57F */
/* U+E580 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E58F */
/* U+E590 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E59F */
/* U+E5A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5AF */
/* U+E5B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5BF */
/* U+E5C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5CF */
/* U+E5D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5DF */
/* U+E5E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5EF */
/* U+E5F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E5FF */
/* U+E600 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E60F */
/* U+E610 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E61F */
/* U+E620 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E62F */
/* U+E630 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E63F */
/* U+E640 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E64F */
/* U+E650 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E65F */
/* U+E660 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E66F */
/* U+E670 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E67F */
/* U+E680 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E68F */
/* U+E690 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E69F */
/* U+E6A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6AF */
/* U+E6B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6BF */
/* U+E6C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6CF */
/* U+E6D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6DF */
/* U+E6E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6EF */
/* U+E6F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E6FF */
/* U+E700 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E70F */
/* U+E710 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E71F */
/* U+E720 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E72F */
/* U+E730 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E73F */
/* U+E740 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E74F */
/* U+E750 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E75F */
/* U+E760 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E76F */
/* U+E770 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E77F */
/* U+E780 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E78F */
/* U+E790 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E79F */
/* U+E7A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7AF */
/* U+E7B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7BF */
/* U+E7C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7CF */
/* U+E7D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7DF */
/* U+E7E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7EF */
/* U+E7F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E7FF */
/* U+E800 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E80F */
/* U+E810 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E81F */
/* U+E820 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E82F */
/* U+E830 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E83F */
/* U+E840 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E84F */
/* U+E850 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E85F */
/* U+E860 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E86F */
/* U+E870 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E87F */
/* U+E880 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E88F */
/* U+E890 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E89F */
/* U+E8A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8AF */
/* U+E8B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8BF */
/* U+E8C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8CF */
/* U+E8D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8DF */
/* U+E8E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8EF */
/* U+E8F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E8FF */
/* U+E900 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E90F */
/* U+E910 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E91F */
/* U+E920 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E92F */
/* U+E930 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E93F */
/* U+E940 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E94F */
/* U+E950 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E95F */
/* U+E960 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E96F */
/* U+E970 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E97F */
/* U+E980 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E98F */
/* U+E990 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E99F */
/* U+E9A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9AF */
/* U+E9B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9BF */
/* U+E9C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9CF */
/* U+E9D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9DF */
/* U+E9E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9EF */
/* U+E9F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+E9FF */
/* U+EA00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA0F */
/* U+EA10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA1F */
/* U+EA20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA2F */
/* U+EA30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA3F */
/* U+EA40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA4F */
/* U+EA50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA5F */
/* U+EA60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA6F */
/* U+EA70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA7F */
/* U+EA80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA8F */
/* U+EA90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EA9F */
/* U+EAA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EAAF */
/* U+EAB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EABF */
/* U+EAC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EACF */
/* U+EAD0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EADF */
/* U+EAE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EAEF */
/* U+EAF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EAFF */
/* U+EB00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB0F */
/* U+EB10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB1F */
/* U+EB20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB2F */
/* U+EB30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB3F */
/* U+EB40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB4F */
/* U+EB50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB5F */
/* U+EB60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB6F */
/* U+EB70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB7F */
/* U+EB80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB8F */
/* U+EB90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EB9F */
/* U+EBA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBAF */
/* U+EBB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBBF */
/* U+EBC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBCF */
/* U+EBD0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBDF */
/* U+EBE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBEF */
/* U+EBF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EBFF */
/* U+EC00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC0F */
/* U+EC10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC1F */
/* U+EC20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC2F */
/* U+EC30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC3F */
/* U+EC40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC4F */
/* U+EC50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC5F */
/* U+EC60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC6F */
/* U+EC70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC7F */
/* U+EC80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC8F */
/* U+EC90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EC9F */
/* U+ECA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECAF */
/* U+ECB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECBF */
/* U+ECC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECCF */
/* U+ECD0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECDF */
/* U+ECE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECEF */
/* U+ECF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ECFF */
/* U+ED00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED0F */
/* U+ED10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED1F */
/* U+ED20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED2F */
/* U+ED30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED3F */
/* U+ED40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED4F */
/* U+ED50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED5F */
/* U+ED60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED6F */
/* U+ED70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED7F */
/* U+ED80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED8F */
/* U+ED90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+ED9F */
/* U+EDA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDAF */
/* U+EDB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDBF */
/* U+EDC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDCF */
/* U+EDD0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDDF */
/* U+EDE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDEF */
/* U+EDF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EDFF */
/* U+EE00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE0F */
/* U+EE10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE1F */
/* U+EE20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE2F */
/* U+EE30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE3F */
/* U+EE40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE4F */
/* U+EE50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE5F */
/* U+EE60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE6F */
/* U+EE70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE7F */
/* U+EE80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE8F */
/* U+EE90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EE9F */
/* U+EEA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EEAF */
/* U+EEB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EEBF */
/* U+EEC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EECF */
/* U+EED0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EEDF */
/* U+EEE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EEEF */
/* U+EEF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EEFF */
/* U+EF00 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF0F */
/* U+EF10 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF1F */
/* U+EF20 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF2F */
/* U+EF30 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF3F */
/* U+EF40 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF4F */
/* U+EF50 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF5F */
/* U+EF60 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF6F */
/* U+EF70 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF7F */
/* U+EF80 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF8F */
/* U+EF90 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EF9F */
/* U+EFA0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFAF */
/* U+EFB0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFBF */
/* U+EFC0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFCF */
/* U+EFD0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFDF */
/* U+EFE0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFEF */
/* U+EFF0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+EFFF */
/* U+F000 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F00F */
/* U+F010 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F01F */
/* U+F020 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F02F */
/* U+F030 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F03F */
/* U+F040 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F04F */
/* U+F050 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F05F */
/* U+F060 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F06F */
/* U+F070 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F07F */
/* U+F080 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F08F */
/* U+F090 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F09F */
/* U+F0A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0AF */
/* U+F0B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0BF */
/* U+F0C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0CF */
/* U+F0D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0DF */
/* U+F0E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0EF */
/* U+F0F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F0FF */
/* U+F100 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F10F */
/* U+F110 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F11F */
/* U+F120 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F12F */
/* U+F130 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F13F */
/* U+F140 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F14F */
/* U+F150 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F15F */
/* U+F160 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F16F */
/* U+F170 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F17F */
/* U+F180 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F18F */
/* U+F190 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F19F */
/* U+F1A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1AF */
/* U+F1B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1BF */
/* U+F1C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1CF */
/* U+F1D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1DF */
/* U+F1E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1EF */
/* U+F1F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F1FF */
/* U+F200 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F20F */
/* U+F210 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F21F */
/* U+F220 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F22F */
/* U+F230 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F23F */
/* U+F240 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F24F */
/* U+F250 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F25F */
/* U+F260 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F26F */
/* U+F270 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F27F */
/* U+F280 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F28F */
/* U+F290 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F29F */
/* U+F2A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2AF */
/* U+F2B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2BF */
/* U+F2C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2CF */
/* U+F2D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2DF */
/* U+F2E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2EF */
/* U+F2F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F2FF */
/* U+F300 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F30F */
/* U+F310 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F31F */
/* U+F320 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F32F */
/* U+F330 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F33F */
/* U+F340 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F34F */
/* U+F350 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F35F */
/* U+F360 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F36F */
/* U+F370 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F37F */
/* U+F380 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F38F */
/* U+F390 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F39F */
/* U+F3A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3AF */
/* U+F3B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3BF */
/* U+F3C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3CF */
/* U+F3D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3DF */
/* U+F3E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3EF */
/* U+F3F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F3FF */
/* U+F400 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F40F */
/* U+F410 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F41F */
/* U+F420 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F42F */
/* U+F430 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F43F */
/* U+F440 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F44F */
/* U+F450 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F45F */
/* U+F460 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F46F */
/* U+F470 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F47F */
/* U+F480 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F48F */
/* U+F490 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F49F */
/* U+F4A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4AF */
/* U+F4B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4BF */
/* U+F4C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4CF */
/* U+F4D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4DF */
/* U+F4E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4EF */
/* U+F4F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F4FF */
/* U+F500 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F50F */
/* U+F510 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F51F */
/* U+F520 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F52F */
/* U+F530 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F53F */
/* U+F540 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F54F */
/* U+F550 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F55F */
/* U+F560 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F56F */
/* U+F570 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F57F */
/* U+F580 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F58F */
/* U+F590 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F59F */
/* U+F5A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5AF */
/* U+F5B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5BF */
/* U+F5C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5CF */
/* U+F5D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5DF */
/* U+F5E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5EF */
/* U+F5F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F5FF */
/* U+F600 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F60F */
/* U+F610 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F61F */
/* U+F620 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F62F */
/* U+F630 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F63F */
/* U+F640 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F64F */
/* U+F650 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F65F */
/* U+F660 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F66F */
/* U+F670 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F67F */
/* U+F680 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F68F */
/* U+F690 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F69F */
/* U+F6A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6AF */
/* U+F6B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6BF */
/* U+F6C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6CF */
/* U+F6D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6DF */
/* U+F6E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6EF */
/* U+F6F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F6FF */
/* U+F700 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F70F */
/* U+F710 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F71F */
/* U+F720 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F72F */
/* U+F730 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F73F */
/* U+F740 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F74F */
/* U+F750 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F75F */
/* U+F760 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F76F */
/* U+F770 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F77F */
/* U+F780 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F78F */
/* U+F790 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F79F */
/* U+F7A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7AF */
/* U+F7B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7BF */
/* U+F7C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7CF */
/* U+F7D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7DF */
/* U+F7E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7EF */
/* U+F7F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F7FF */
/* U+F800 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F80F */
/* U+F810 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F81F */
/* U+F820 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F82F */
/* U+F830 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F83F */
/* U+F840 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F84F */
/* U+F850 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F85F */
/* U+F860 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F86F */
/* U+F870 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F87F */
/* U+F880 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F88F */
/* U+F890 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F89F */
/* U+F8A0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8AF */
/* U+F8B0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8BF */
/* U+F8C0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8CF */
/* U+F8D0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8DF */
/* U+F8E0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8EF */
/* U+F8F0 */	PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,PU,   /* U+F8FF */
/* U+F900 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F90F */
/* U+F910 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F91F */
/* U+F920 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F92F */
/* U+F930 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F93F */
/* U+F940 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F94F */
/* U+F950 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F95F */
/* U+F960 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F96F */
/* U+F970 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F97F */
/* U+F980 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F98F */
/* U+F990 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F99F */
/* U+F9A0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9AF */
/* U+F9B0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9BF */
/* U+F9C0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9CF */
/* U+F9D0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9DF */
/* U+F9E0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9EF */
/* U+F9F0 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+F9FF */
/* U+FA00 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FA0F */
/* U+FA10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FA1F */
/* U+FA20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,   /* U+FA2F */
/* U+FA30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FA3F */
/* U+FA40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FA4F */
/* U+FA50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FA5F */
/* U+FA60 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, IL,IL,IL,IL,IL,   /* U+FA6F */
/* U+FA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FA7F */
/* U+FA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FA8F */
/* U+FA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FA9F */
/* U+FAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FAAF */
/* U+FAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FABF */
/* U+FAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FACF */
/* U+FAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FADF */
/* U+FAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FAEF */
/* U+FAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FAFF */
/* U+FB00 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FB0F */
/* U+FB10 */	IL,IL,IL,1, 1, 1, 1, 1, IL,IL,IL,IL,IL,1, 0, 1,    /* U+FB1F */
/* U+FB20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB2F */
/* U+FB30 */	1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, IL,1, IL,   /* U+FB3F */
/* U+FB40 */	1, 1, IL,1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB4F */
/* U+FB50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB5F */
/* U+FB60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB6F */
/* U+FB70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB7F */
/* U+FB80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB8F */
/* U+FB90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FB9F */
/* U+FBA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FBAF */
/* U+FBB0 */	1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FBBF */
/* U+FBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FBCF */
/* U+FBD0 */	IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FBDF */
/* U+FBE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FBEF */
/* U+FBF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FBFF */
/* U+FC00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC0F */
/* U+FC10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC1F */
/* U+FC20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC2F */
/* U+FC30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC3F */
/* U+FC40 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC4F */
/* U+FC50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC5F */
/* U+FC60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC6F */
/* U+FC70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC7F */
/* U+FC80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC8F */
/* U+FC90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FC9F */
/* U+FCA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCAF */
/* U+FCB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCBF */
/* U+FCC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCCF */
/* U+FCD0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCDF */
/* U+FCE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCEF */
/* U+FCF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FCFF */
/* U+FD00 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD0F */
/* U+FD10 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD1F */
/* U+FD20 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD2F */
/* U+FD30 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD3F */
/* U+FD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FD4F */
/* U+FD50 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD5F */
/* U+FD60 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD6F */
/* U+FD70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD7F */
/* U+FD80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD8F */
/* U+FD90 */	IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FD9F */
/* U+FDA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FDAF */
/* U+FDB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FDBF */
/* U+FDC0 */	1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FDCF */
/* U+FDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FDDF */
/* U+FDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FDEF */
/* U+FDF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,   /* U+FDFF */
/* U+FE00 */	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    /* U+FE0F */
/* U+FE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FE1F */
/* U+FE20 */	0, 0, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,   /* U+FE2F */
/* U+FE30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FE3F */
/* U+FE40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FE4F */
/* U+FE50 */	2, 2, 2, IL,2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FE5F */
/* U+FE60 */	2, 2, 2, 2, 2, 2, 2, IL,2, 2, 2, 2, IL,IL,IL,IL,   /* U+FE6F */
/* U+FE70 */	1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FE7F */
/* U+FE80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FE8F */
/* U+FE90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FE9F */
/* U+FEA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FEAF */
/* U+FEB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FEBF */
/* U+FEC0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FECF */
/* U+FED0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FEDF */
/* U+FEE0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FEEF */
/* U+FEF0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,   /* U+FEFF */
/* U+FF00 */	IL,2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF0F */
/* U+FF10 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF1F */
/* U+FF20 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF2F */
/* U+FF30 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF3F */
/* U+FF40 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF4F */
/* U+FF50 */	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,    /* U+FF5F */
/* U+FF60 */	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FF6F */
/* U+FF70 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FF7F */
/* U+FF80 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FF8F */
/* U+FF90 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FF9F */
/* U+FFA0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,    /* U+FFAF */
/* U+FFB0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,   /* U+FFBF */
/* U+FFC0 */	IL,IL,1, 1, 1, 1, 1, 1, IL,IL,1, 1, 1, 1, 1, 1,    /* U+FFCF */
/* U+FFD0 */	IL,IL,1, 1, 1, 1, 1, 1, IL,IL,1, 1, 1, IL,IL,IL,   /* U+FFDF */
/* U+FFE0 */	2, 2, 2, 2, 2, 2, 2, IL,1, 1, 1, 1, 1, 1, 1, IL,   /* U+FFEF */
/* U+FFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,0, 0, 0, 1, 1, IL,IL    /* U+FFFF */
	},
	{
/*		0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
/*		---------------------------------------------- */
/* U+10000 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1,   /* U+1000F */
/* U+10010 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1001F */
/* U+10020 */	1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1,   /* U+1002F */
/* U+10030 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, IL,1,   /* U+1003F */
/* U+10040 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,  /* U+1004F */
/* U+10050 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,  /* U+1005F */
/* U+10060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1006F */
/* U+10070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1007F */
/* U+10080 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1008F */
/* U+10090 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1009F */
/* U+100A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+100AF */
/* U+100B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+100BF */
/* U+100C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+100CF */
/* U+100D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+100DF */
/* U+100E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+100EF */
/* U+100F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,  /* U+100FF */
/* U+10100 */	1, 1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1010F */
/* U+10110 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1011F */
/* U+10120 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1012F */
/* U+10130 */	1, 1, 1, 1, IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1013F */
/* U+10140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1014F */
/* U+10150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1015F */
/* U+10160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1016F */
/* U+10170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1017F */
/* U+10180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1018F */
/* U+10190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1019F */
/* U+101A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101AF */
/* U+101B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101BF */
/* U+101C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101CF */
/* U+101D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101DF */
/* U+101E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101EF */
/* U+101F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+101FF */
/* U+10200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1020F */
/* U+10210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1021F */
/* U+10220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1022F */
/* U+10230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1023F */
/* U+10240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1024F */
/* U+10250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1025F */
/* U+10260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1026F */
/* U+10270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1027F */
/* U+10280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1028F */
/* U+10290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1029F */
/* U+102A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102AF */
/* U+102B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102BF */
/* U+102C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102CF */
/* U+102D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102DF */
/* U+102E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102EF */
/* U+102F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+102FF */
/* U+10300 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1030F */
/* U+10310 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,  /* U+1031F */
/* U+10320 */	1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1032F */
/* U+10330 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1033F */
/* U+10340 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,  /* U+1034F */
/* U+10350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1035F */
/* U+10360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1036F */
/* U+10370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1037F */
/* U+10380 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1038F */
/* U+10390 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1,   /* U+1039F */
/* U+103A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103AF */
/* U+103B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103BF */
/* U+103C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103CF */
/* U+103D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103DF */
/* U+103E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103EF */
/* U+103F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+103FF */
/* U+10400 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1040F */
/* U+10410 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1041F */
/* U+10420 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1042F */
/* U+10430 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1043F */
/* U+10440 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1044F */
/* U+10450 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1045F */
/* U+10460 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1046F */
/* U+10470 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1047F */
/* U+10480 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1048F */
/* U+10490 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,  /* U+1049F */
/* U+104A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,  /* U+104AF */
/* U+104B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+104BF */
/* U+104C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+104CF */
/* U+104D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+104DF */
/* U+104E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+104EF */
/* U+104F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+104FF */
/* U+10500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1050F */
/* U+10510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1051F */
/* U+10520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1052F */
/* U+10530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1053F */
/* U+10540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1054F */
/* U+10550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1055F */
/* U+10560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1056F */
/* U+10570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1057F */
/* U+10580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1058F */
/* U+10590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1059F */
/* U+105A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105AF */
/* U+105B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105BF */
/* U+105C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105CF */
/* U+105D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105DF */
/* U+105E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105EF */
/* U+105F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+105FF */
/* U+10600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1060F */
/* U+10610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1061F */
/* U+10620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1062F */
/* U+10630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1063F */
/* U+10640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1064F */
/* U+10650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1065F */
/* U+10660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1066F */
/* U+10670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1067F */
/* U+10680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1068F */
/* U+10690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1069F */
/* U+106A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106AF */
/* U+106B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106BF */
/* U+106C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106CF */
/* U+106D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106DF */
/* U+106E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106EF */
/* U+106F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+106FF */
/* U+10700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1070F */
/* U+10710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1071F */
/* U+10720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1072F */
/* U+10730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1073F */
/* U+10740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1074F */
/* U+10750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1075F */
/* U+10760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1076F */
/* U+10770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1077F */
/* U+10780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1078F */
/* U+10790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1079F */
/* U+107A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107AF */
/* U+107B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107BF */
/* U+107C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107CF */
/* U+107D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107DF */
/* U+107E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107EF */
/* U+107F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+107FF */
/* U+10800 */	1, 1, 1, 1, 1, 1, IL,IL,1, IL,1, 1, 1, 1, 1, 1,   /* U+1080F */
/* U+10810 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1081F */
/* U+10820 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1082F */
/* U+10830 */	1, 1, 1, 1, 1, 1, IL,1, 1, IL,IL,IL,1, IL,IL,1,   /* U+1083F */
/* U+10840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1084F */
/* U+10850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1085F */
/* U+10860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1086F */
/* U+10870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1087F */
/* U+10880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1088F */
/* U+10890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1089F */
/* U+108A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108AF */
/* U+108B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108BF */
/* U+108C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108CF */
/* U+108D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108DF */
/* U+108E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108EF */
/* U+108F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+108FF */
/* U+10900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1090F */
/* U+10910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1091F */
/* U+10920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1092F */
/* U+10930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1093F */
/* U+10940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1094F */
/* U+10950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1095F */
/* U+10960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1096F */
/* U+10970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1097F */
/* U+10980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1098F */
/* U+10990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1099F */
/* U+109A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109AF */
/* U+109B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109BF */
/* U+109C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109CF */
/* U+109D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109DF */
/* U+109E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109EF */
/* U+109F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+109FF */
/* U+10A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A0F */
/* U+10A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A1F */
/* U+10A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A2F */
/* U+10A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A3F */
/* U+10A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A4F */
/* U+10A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A5F */
/* U+10A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A6F */
/* U+10A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A7F */
/* U+10A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A8F */
/* U+10A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10A9F */
/* U+10AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10AAF */
/* U+10AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10ABF */
/* U+10AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10ACF */
/* U+10AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10ADF */
/* U+10AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10AEF */
/* U+10AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10AFF */
/* U+10B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B0F */
/* U+10B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B1F */
/* U+10B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B2F */
/* U+10B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B3F */
/* U+10B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B4F */
/* U+10B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B5F */
/* U+10B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B6F */
/* U+10B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B7F */
/* U+10B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B8F */
/* U+10B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10B9F */
/* U+10BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BAF */
/* U+10BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BBF */
/* U+10BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BCF */
/* U+10BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BDF */
/* U+10BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BEF */
/* U+10BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10BFF */
/* U+10C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C0F */
/* U+10C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C1F */
/* U+10C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C2F */
/* U+10C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C3F */
/* U+10C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C4F */
/* U+10C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C5F */
/* U+10C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C6F */
/* U+10C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C7F */
/* U+10C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C8F */
/* U+10C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10C9F */
/* U+10CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CAF */
/* U+10CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CBF */
/* U+10CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CCF */
/* U+10CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CDF */
/* U+10CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CEF */
/* U+10CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10CFF */
/* U+10D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D0F */
/* U+10D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D1F */
/* U+10D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D2F */
/* U+10D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D3F */
/* U+10D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D4F */
/* U+10D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D5F */
/* U+10D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D6F */
/* U+10D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D7F */
/* U+10D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D8F */
/* U+10D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10D9F */
/* U+10DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DAF */
/* U+10DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DBF */
/* U+10DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DCF */
/* U+10DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DDF */
/* U+10DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DEF */
/* U+10DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10DFF */
/* U+10E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E0F */
/* U+10E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E1F */
/* U+10E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E2F */
/* U+10E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E3F */
/* U+10E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E4F */
/* U+10E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E5F */
/* U+10E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E6F */
/* U+10E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E7F */
/* U+10E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E8F */
/* U+10E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10E9F */
/* U+10EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10EAF */
/* U+10EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10EBF */
/* U+10EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10ECF */
/* U+10ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10EDF */
/* U+10EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10EEF */
/* U+10EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10EFF */
/* U+10F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F0F */
/* U+10F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F1F */
/* U+10F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F2F */
/* U+10F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F3F */
/* U+10F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F4F */
/* U+10F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F5F */
/* U+10F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F6F */
/* U+10F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F7F */
/* U+10F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F8F */
/* U+10F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10F9F */
/* U+10FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FAF */
/* U+10FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FBF */
/* U+10FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FCF */
/* U+10FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FDF */
/* U+10FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FEF */
/* U+10FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+10FFF */
/* U+11000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1100F */
/* U+11010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1101F */
/* U+11020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1102F */
/* U+11030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1103F */
/* U+11040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1104F */
/* U+11050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1105F */
/* U+11060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1106F */
/* U+11070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1107F */
/* U+11080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1108F */
/* U+11090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1109F */
/* U+110A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110AF */
/* U+110B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110BF */
/* U+110C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110CF */
/* U+110D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110DF */
/* U+110E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110EF */
/* U+110F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+110FF */
/* U+11100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1110F */
/* U+11110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1111F */
/* U+11120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1112F */
/* U+11130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1113F */
/* U+11140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1114F */
/* U+11150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1115F */
/* U+11160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1116F */
/* U+11170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1117F */
/* U+11180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1118F */
/* U+11190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1119F */
/* U+111A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111AF */
/* U+111B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111BF */
/* U+111C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111CF */
/* U+111D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111DF */
/* U+111E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111EF */
/* U+111F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+111FF */
/* U+11200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1120F */
/* U+11210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1121F */
/* U+11220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1122F */
/* U+11230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1123F */
/* U+11240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1124F */
/* U+11250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1125F */
/* U+11260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1126F */
/* U+11270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1127F */
/* U+11280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1128F */
/* U+11290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1129F */
/* U+112A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112AF */
/* U+112B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112BF */
/* U+112C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112CF */
/* U+112D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112DF */
/* U+112E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112EF */
/* U+112F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+112FF */
/* U+11300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1130F */
/* U+11310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1131F */
/* U+11320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1132F */
/* U+11330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1133F */
/* U+11340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1134F */
/* U+11350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1135F */
/* U+11360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1136F */
/* U+11370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1137F */
/* U+11380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1138F */
/* U+11390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1139F */
/* U+113A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113AF */
/* U+113B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113BF */
/* U+113C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113CF */
/* U+113D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113DF */
/* U+113E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113EF */
/* U+113F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+113FF */
/* U+11400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1140F */
/* U+11410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1141F */
/* U+11420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1142F */
/* U+11430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1143F */
/* U+11440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1144F */
/* U+11450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1145F */
/* U+11460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1146F */
/* U+11470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1147F */
/* U+11480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1148F */
/* U+11490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1149F */
/* U+114A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114AF */
/* U+114B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114BF */
/* U+114C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114CF */
/* U+114D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114DF */
/* U+114E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114EF */
/* U+114F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+114FF */
/* U+11500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1150F */
/* U+11510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1151F */
/* U+11520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1152F */
/* U+11530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1153F */
/* U+11540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1154F */
/* U+11550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1155F */
/* U+11560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1156F */
/* U+11570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1157F */
/* U+11580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1158F */
/* U+11590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1159F */
/* U+115A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115AF */
/* U+115B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115BF */
/* U+115C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115CF */
/* U+115D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115DF */
/* U+115E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115EF */
/* U+115F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+115FF */
/* U+11600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1160F */
/* U+11610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1161F */
/* U+11620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1162F */
/* U+11630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1163F */
/* U+11640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1164F */
/* U+11650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1165F */
/* U+11660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1166F */
/* U+11670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1167F */
/* U+11680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1168F */
/* U+11690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1169F */
/* U+116A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116AF */
/* U+116B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116BF */
/* U+116C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116CF */
/* U+116D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116DF */
/* U+116E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116EF */
/* U+116F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+116FF */
/* U+11700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1170F */
/* U+11710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1171F */
/* U+11720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1172F */
/* U+11730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1173F */
/* U+11740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1174F */
/* U+11750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1175F */
/* U+11760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1176F */
/* U+11770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1177F */
/* U+11780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1178F */
/* U+11790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1179F */
/* U+117A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117AF */
/* U+117B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117BF */
/* U+117C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117CF */
/* U+117D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117DF */
/* U+117E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117EF */
/* U+117F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+117FF */
/* U+11800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1180F */
/* U+11810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1181F */
/* U+11820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1182F */
/* U+11830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1183F */
/* U+11840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1184F */
/* U+11850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1185F */
/* U+11860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1186F */
/* U+11870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1187F */
/* U+11880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1188F */
/* U+11890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1189F */
/* U+118A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118AF */
/* U+118B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118BF */
/* U+118C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118CF */
/* U+118D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118DF */
/* U+118E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118EF */
/* U+118F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+118FF */
/* U+11900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1190F */
/* U+11910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1191F */
/* U+11920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1192F */
/* U+11930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1193F */
/* U+11940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1194F */
/* U+11950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1195F */
/* U+11960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1196F */
/* U+11970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1197F */
/* U+11980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1198F */
/* U+11990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1199F */
/* U+119A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119AF */
/* U+119B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119BF */
/* U+119C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119CF */
/* U+119D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119DF */
/* U+119E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119EF */
/* U+119F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+119FF */
/* U+11A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A0F */
/* U+11A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A1F */
/* U+11A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A2F */
/* U+11A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A3F */
/* U+11A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A4F */
/* U+11A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A5F */
/* U+11A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A6F */
/* U+11A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A7F */
/* U+11A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A8F */
/* U+11A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11A9F */
/* U+11AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11AAF */
/* U+11AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11ABF */
/* U+11AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11ACF */
/* U+11AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11ADF */
/* U+11AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11AEF */
/* U+11AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11AFF */
/* U+11B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B0F */
/* U+11B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B1F */
/* U+11B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B2F */
/* U+11B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B3F */
/* U+11B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B4F */
/* U+11B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B5F */
/* U+11B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B6F */
/* U+11B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B7F */
/* U+11B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B8F */
/* U+11B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11B9F */
/* U+11BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BAF */
/* U+11BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BBF */
/* U+11BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BCF */
/* U+11BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BDF */
/* U+11BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BEF */
/* U+11BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11BFF */
/* U+11C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C0F */
/* U+11C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C1F */
/* U+11C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C2F */
/* U+11C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C3F */
/* U+11C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C4F */
/* U+11C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C5F */
/* U+11C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C6F */
/* U+11C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C7F */
/* U+11C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C8F */
/* U+11C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11C9F */
/* U+11CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CAF */
/* U+11CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CBF */
/* U+11CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CCF */
/* U+11CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CDF */
/* U+11CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CEF */
/* U+11CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11CFF */
/* U+11D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D0F */
/* U+11D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D1F */
/* U+11D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D2F */
/* U+11D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D3F */
/* U+11D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D4F */
/* U+11D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D5F */
/* U+11D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D6F */
/* U+11D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D7F */
/* U+11D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D8F */
/* U+11D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11D9F */
/* U+11DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DAF */
/* U+11DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DBF */
/* U+11DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DCF */
/* U+11DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DDF */
/* U+11DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DEF */
/* U+11DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11DFF */
/* U+11E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E0F */
/* U+11E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E1F */
/* U+11E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E2F */
/* U+11E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E3F */
/* U+11E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E4F */
/* U+11E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E5F */
/* U+11E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E6F */
/* U+11E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E7F */
/* U+11E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E8F */
/* U+11E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11E9F */
/* U+11EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11EAF */
/* U+11EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11EBF */
/* U+11EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11ECF */
/* U+11ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11EDF */
/* U+11EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11EEF */
/* U+11EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11EFF */
/* U+11F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F0F */
/* U+11F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F1F */
/* U+11F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F2F */
/* U+11F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F3F */
/* U+11F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F4F */
/* U+11F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F5F */
/* U+11F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F6F */
/* U+11F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F7F */
/* U+11F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F8F */
/* U+11F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11F9F */
/* U+11FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FAF */
/* U+11FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FBF */
/* U+11FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FCF */
/* U+11FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FDF */
/* U+11FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FEF */
/* U+11FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+11FFF */
/* U+12000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1200F */
/* U+12010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1201F */
/* U+12020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1202F */
/* U+12030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1203F */
/* U+12040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1204F */
/* U+12050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1205F */
/* U+12060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1206F */
/* U+12070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1207F */
/* U+12080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1208F */
/* U+12090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1209F */
/* U+120A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120AF */
/* U+120B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120BF */
/* U+120C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120CF */
/* U+120D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120DF */
/* U+120E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120EF */
/* U+120F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+120FF */
/* U+12100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1210F */
/* U+12110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1211F */
/* U+12120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1212F */
/* U+12130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1213F */
/* U+12140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1214F */
/* U+12150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1215F */
/* U+12160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1216F */
/* U+12170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1217F */
/* U+12180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1218F */
/* U+12190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1219F */
/* U+121A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121AF */
/* U+121B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121BF */
/* U+121C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121CF */
/* U+121D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121DF */
/* U+121E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121EF */
/* U+121F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+121FF */
/* U+12200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1220F */
/* U+12210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1221F */
/* U+12220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1222F */
/* U+12230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1223F */
/* U+12240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1224F */
/* U+12250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1225F */
/* U+12260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1226F */
/* U+12270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1227F */
/* U+12280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1228F */
/* U+12290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1229F */
/* U+122A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122AF */
/* U+122B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122BF */
/* U+122C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122CF */
/* U+122D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122DF */
/* U+122E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122EF */
/* U+122F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+122FF */
/* U+12300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1230F */
/* U+12310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1231F */
/* U+12320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1232F */
/* U+12330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1233F */
/* U+12340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1234F */
/* U+12350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1235F */
/* U+12360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1236F */
/* U+12370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1237F */
/* U+12380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1238F */
/* U+12390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1239F */
/* U+123A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123AF */
/* U+123B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123BF */
/* U+123C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123CF */
/* U+123D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123DF */
/* U+123E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123EF */
/* U+123F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+123FF */
/* U+12400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1240F */
/* U+12410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1241F */
/* U+12420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1242F */
/* U+12430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1243F */
/* U+12440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1244F */
/* U+12450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1245F */
/* U+12460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1246F */
/* U+12470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1247F */
/* U+12480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1248F */
/* U+12490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1249F */
/* U+124A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124AF */
/* U+124B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124BF */
/* U+124C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124CF */
/* U+124D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124DF */
/* U+124E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124EF */
/* U+124F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+124FF */
/* U+12500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1250F */
/* U+12510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1251F */
/* U+12520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1252F */
/* U+12530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1253F */
/* U+12540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1254F */
/* U+12550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1255F */
/* U+12560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1256F */
/* U+12570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1257F */
/* U+12580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1258F */
/* U+12590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1259F */
/* U+125A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125AF */
/* U+125B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125BF */
/* U+125C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125CF */
/* U+125D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125DF */
/* U+125E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125EF */
/* U+125F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+125FF */
/* U+12600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1260F */
/* U+12610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1261F */
/* U+12620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1262F */
/* U+12630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1263F */
/* U+12640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1264F */
/* U+12650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1265F */
/* U+12660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1266F */
/* U+12670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1267F */
/* U+12680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1268F */
/* U+12690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1269F */
/* U+126A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126AF */
/* U+126B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126BF */
/* U+126C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126CF */
/* U+126D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126DF */
/* U+126E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126EF */
/* U+126F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+126FF */
/* U+12700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1270F */
/* U+12710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1271F */
/* U+12720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1272F */
/* U+12730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1273F */
/* U+12740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1274F */
/* U+12750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1275F */
/* U+12760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1276F */
/* U+12770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1277F */
/* U+12780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1278F */
/* U+12790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1279F */
/* U+127A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127AF */
/* U+127B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127BF */
/* U+127C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127CF */
/* U+127D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127DF */
/* U+127E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127EF */
/* U+127F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+127FF */
/* U+12800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1280F */
/* U+12810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1281F */
/* U+12820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1282F */
/* U+12830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1283F */
/* U+12840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1284F */
/* U+12850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1285F */
/* U+12860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1286F */
/* U+12870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1287F */
/* U+12880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1288F */
/* U+12890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1289F */
/* U+128A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128AF */
/* U+128B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128BF */
/* U+128C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128CF */
/* U+128D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128DF */
/* U+128E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128EF */
/* U+128F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+128FF */
/* U+12900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1290F */
/* U+12910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1291F */
/* U+12920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1292F */
/* U+12930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1293F */
/* U+12940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1294F */
/* U+12950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1295F */
/* U+12960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1296F */
/* U+12970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1297F */
/* U+12980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1298F */
/* U+12990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1299F */
/* U+129A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129AF */
/* U+129B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129BF */
/* U+129C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129CF */
/* U+129D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129DF */
/* U+129E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129EF */
/* U+129F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+129FF */
/* U+12A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A0F */
/* U+12A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A1F */
/* U+12A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A2F */
/* U+12A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A3F */
/* U+12A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A4F */
/* U+12A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A5F */
/* U+12A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A6F */
/* U+12A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A7F */
/* U+12A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A8F */
/* U+12A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12A9F */
/* U+12AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12AAF */
/* U+12AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12ABF */
/* U+12AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12ACF */
/* U+12AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12ADF */
/* U+12AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12AEF */
/* U+12AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12AFF */
/* U+12B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B0F */
/* U+12B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B1F */
/* U+12B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B2F */
/* U+12B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B3F */
/* U+12B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B4F */
/* U+12B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B5F */
/* U+12B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B6F */
/* U+12B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B7F */
/* U+12B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B8F */
/* U+12B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12B9F */
/* U+12BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BAF */
/* U+12BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BBF */
/* U+12BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BCF */
/* U+12BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BDF */
/* U+12BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BEF */
/* U+12BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12BFF */
/* U+12C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C0F */
/* U+12C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C1F */
/* U+12C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C2F */
/* U+12C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C3F */
/* U+12C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C4F */
/* U+12C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C5F */
/* U+12C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C6F */
/* U+12C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C7F */
/* U+12C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C8F */
/* U+12C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12C9F */
/* U+12CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CAF */
/* U+12CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CBF */
/* U+12CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CCF */
/* U+12CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CDF */
/* U+12CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CEF */
/* U+12CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12CFF */
/* U+12D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D0F */
/* U+12D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D1F */
/* U+12D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D2F */
/* U+12D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D3F */
/* U+12D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D4F */
/* U+12D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D5F */
/* U+12D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D6F */
/* U+12D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D7F */
/* U+12D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D8F */
/* U+12D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12D9F */
/* U+12DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DAF */
/* U+12DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DBF */
/* U+12DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DCF */
/* U+12DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DDF */
/* U+12DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DEF */
/* U+12DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12DFF */
/* U+12E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E0F */
/* U+12E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E1F */
/* U+12E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E2F */
/* U+12E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E3F */
/* U+12E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E4F */
/* U+12E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E5F */
/* U+12E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E6F */
/* U+12E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E7F */
/* U+12E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E8F */
/* U+12E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12E9F */
/* U+12EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12EAF */
/* U+12EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12EBF */
/* U+12EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12ECF */
/* U+12ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12EDF */
/* U+12EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12EEF */
/* U+12EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12EFF */
/* U+12F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F0F */
/* U+12F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F1F */
/* U+12F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F2F */
/* U+12F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F3F */
/* U+12F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F4F */
/* U+12F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F5F */
/* U+12F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F6F */
/* U+12F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F7F */
/* U+12F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F8F */
/* U+12F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12F9F */
/* U+12FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FAF */
/* U+12FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FBF */
/* U+12FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FCF */
/* U+12FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FDF */
/* U+12FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FEF */
/* U+12FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+12FFF */
/* U+13000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1300F */
/* U+13010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1301F */
/* U+13020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1302F */
/* U+13030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1303F */
/* U+13040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1304F */
/* U+13050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1305F */
/* U+13060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1306F */
/* U+13070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1307F */
/* U+13080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1308F */
/* U+13090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1309F */
/* U+130A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130AF */
/* U+130B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130BF */
/* U+130C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130CF */
/* U+130D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130DF */
/* U+130E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130EF */
/* U+130F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+130FF */
/* U+13100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1310F */
/* U+13110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1311F */
/* U+13120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1312F */
/* U+13130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1313F */
/* U+13140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1314F */
/* U+13150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1315F */
/* U+13160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1316F */
/* U+13170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1317F */
/* U+13180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1318F */
/* U+13190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1319F */
/* U+131A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131AF */
/* U+131B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131BF */
/* U+131C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131CF */
/* U+131D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131DF */
/* U+131E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131EF */
/* U+131F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+131FF */
/* U+13200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1320F */
/* U+13210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1321F */
/* U+13220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1322F */
/* U+13230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1323F */
/* U+13240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1324F */
/* U+13250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1325F */
/* U+13260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1326F */
/* U+13270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1327F */
/* U+13280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1328F */
/* U+13290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1329F */
/* U+132A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132AF */
/* U+132B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132BF */
/* U+132C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132CF */
/* U+132D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132DF */
/* U+132E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132EF */
/* U+132F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+132FF */
/* U+13300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1330F */
/* U+13310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1331F */
/* U+13320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1332F */
/* U+13330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1333F */
/* U+13340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1334F */
/* U+13350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1335F */
/* U+13360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1336F */
/* U+13370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1337F */
/* U+13380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1338F */
/* U+13390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1339F */
/* U+133A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133AF */
/* U+133B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133BF */
/* U+133C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133CF */
/* U+133D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133DF */
/* U+133E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133EF */
/* U+133F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+133FF */
/* U+13400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1340F */
/* U+13410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1341F */
/* U+13420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1342F */
/* U+13430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1343F */
/* U+13440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1344F */
/* U+13450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1345F */
/* U+13460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1346F */
/* U+13470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1347F */
/* U+13480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1348F */
/* U+13490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1349F */
/* U+134A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134AF */
/* U+134B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134BF */
/* U+134C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134CF */
/* U+134D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134DF */
/* U+134E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134EF */
/* U+134F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+134FF */
/* U+13500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1350F */
/* U+13510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1351F */
/* U+13520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1352F */
/* U+13530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1353F */
/* U+13540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1354F */
/* U+13550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1355F */
/* U+13560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1356F */
/* U+13570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1357F */
/* U+13580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1358F */
/* U+13590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1359F */
/* U+135A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135AF */
/* U+135B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135BF */
/* U+135C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135CF */
/* U+135D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135DF */
/* U+135E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135EF */
/* U+135F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+135FF */
/* U+13600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1360F */
/* U+13610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1361F */
/* U+13620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1362F */
/* U+13630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1363F */
/* U+13640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1364F */
/* U+13650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1365F */
/* U+13660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1366F */
/* U+13670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1367F */
/* U+13680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1368F */
/* U+13690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1369F */
/* U+136A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136AF */
/* U+136B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136BF */
/* U+136C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136CF */
/* U+136D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136DF */
/* U+136E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136EF */
/* U+136F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+136FF */
/* U+13700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1370F */
/* U+13710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1371F */
/* U+13720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1372F */
/* U+13730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1373F */
/* U+13740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1374F */
/* U+13750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1375F */
/* U+13760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1376F */
/* U+13770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1377F */
/* U+13780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1378F */
/* U+13790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1379F */
/* U+137A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137AF */
/* U+137B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137BF */
/* U+137C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137CF */
/* U+137D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137DF */
/* U+137E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137EF */
/* U+137F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+137FF */
/* U+13800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1380F */
/* U+13810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1381F */
/* U+13820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1382F */
/* U+13830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1383F */
/* U+13840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1384F */
/* U+13850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1385F */
/* U+13860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1386F */
/* U+13870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1387F */
/* U+13880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1388F */
/* U+13890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1389F */
/* U+138A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138AF */
/* U+138B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138BF */
/* U+138C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138CF */
/* U+138D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138DF */
/* U+138E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138EF */
/* U+138F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+138FF */
/* U+13900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1390F */
/* U+13910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1391F */
/* U+13920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1392F */
/* U+13930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1393F */
/* U+13940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1394F */
/* U+13950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1395F */
/* U+13960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1396F */
/* U+13970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1397F */
/* U+13980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1398F */
/* U+13990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1399F */
/* U+139A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139AF */
/* U+139B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139BF */
/* U+139C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139CF */
/* U+139D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139DF */
/* U+139E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139EF */
/* U+139F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+139FF */
/* U+13A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A0F */
/* U+13A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A1F */
/* U+13A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A2F */
/* U+13A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A3F */
/* U+13A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A4F */
/* U+13A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A5F */
/* U+13A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A6F */
/* U+13A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A7F */
/* U+13A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A8F */
/* U+13A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13A9F */
/* U+13AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13AAF */
/* U+13AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13ABF */
/* U+13AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13ACF */
/* U+13AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13ADF */
/* U+13AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13AEF */
/* U+13AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13AFF */
/* U+13B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B0F */
/* U+13B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B1F */
/* U+13B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B2F */
/* U+13B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B3F */
/* U+13B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B4F */
/* U+13B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B5F */
/* U+13B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B6F */
/* U+13B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B7F */
/* U+13B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B8F */
/* U+13B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13B9F */
/* U+13BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BAF */
/* U+13BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BBF */
/* U+13BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BCF */
/* U+13BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BDF */
/* U+13BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BEF */
/* U+13BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13BFF */
/* U+13C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C0F */
/* U+13C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C1F */
/* U+13C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C2F */
/* U+13C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C3F */
/* U+13C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C4F */
/* U+13C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C5F */
/* U+13C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C6F */
/* U+13C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C7F */
/* U+13C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C8F */
/* U+13C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13C9F */
/* U+13CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CAF */
/* U+13CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CBF */
/* U+13CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CCF */
/* U+13CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CDF */
/* U+13CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CEF */
/* U+13CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13CFF */
/* U+13D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D0F */
/* U+13D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D1F */
/* U+13D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D2F */
/* U+13D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D3F */
/* U+13D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D4F */
/* U+13D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D5F */
/* U+13D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D6F */
/* U+13D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D7F */
/* U+13D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D8F */
/* U+13D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13D9F */
/* U+13DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DAF */
/* U+13DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DBF */
/* U+13DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DCF */
/* U+13DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DDF */
/* U+13DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DEF */
/* U+13DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13DFF */
/* U+13E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E0F */
/* U+13E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E1F */
/* U+13E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E2F */
/* U+13E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E3F */
/* U+13E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E4F */
/* U+13E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E5F */
/* U+13E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E6F */
/* U+13E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E7F */
/* U+13E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E8F */
/* U+13E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13E9F */
/* U+13EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13EAF */
/* U+13EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13EBF */
/* U+13EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13ECF */
/* U+13ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13EDF */
/* U+13EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13EEF */
/* U+13EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13EFF */
/* U+13F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F0F */
/* U+13F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F1F */
/* U+13F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F2F */
/* U+13F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F3F */
/* U+13F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F4F */
/* U+13F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F5F */
/* U+13F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F6F */
/* U+13F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F7F */
/* U+13F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F8F */
/* U+13F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13F9F */
/* U+13FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FAF */
/* U+13FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FBF */
/* U+13FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FCF */
/* U+13FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FDF */
/* U+13FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FEF */
/* U+13FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+13FFF */
/* U+14000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1400F */
/* U+14010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1401F */
/* U+14020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1402F */
/* U+14030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1403F */
/* U+14040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1404F */
/* U+14050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1405F */
/* U+14060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1406F */
/* U+14070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1407F */
/* U+14080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1408F */
/* U+14090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1409F */
/* U+140A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140AF */
/* U+140B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140BF */
/* U+140C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140CF */
/* U+140D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140DF */
/* U+140E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140EF */
/* U+140F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+140FF */
/* U+14100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1410F */
/* U+14110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1411F */
/* U+14120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1412F */
/* U+14130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1413F */
/* U+14140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1414F */
/* U+14150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1415F */
/* U+14160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1416F */
/* U+14170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1417F */
/* U+14180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1418F */
/* U+14190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1419F */
/* U+141A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141AF */
/* U+141B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141BF */
/* U+141C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141CF */
/* U+141D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141DF */
/* U+141E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141EF */
/* U+141F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+141FF */
/* U+14200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1420F */
/* U+14210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1421F */
/* U+14220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1422F */
/* U+14230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1423F */
/* U+14240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1424F */
/* U+14250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1425F */
/* U+14260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1426F */
/* U+14270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1427F */
/* U+14280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1428F */
/* U+14290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1429F */
/* U+142A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142AF */
/* U+142B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142BF */
/* U+142C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142CF */
/* U+142D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142DF */
/* U+142E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142EF */
/* U+142F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+142FF */
/* U+14300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1430F */
/* U+14310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1431F */
/* U+14320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1432F */
/* U+14330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1433F */
/* U+14340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1434F */
/* U+14350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1435F */
/* U+14360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1436F */
/* U+14370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1437F */
/* U+14380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1438F */
/* U+14390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1439F */
/* U+143A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143AF */
/* U+143B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143BF */
/* U+143C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143CF */
/* U+143D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143DF */
/* U+143E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143EF */
/* U+143F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+143FF */
/* U+14400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1440F */
/* U+14410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1441F */
/* U+14420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1442F */
/* U+14430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1443F */
/* U+14440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1444F */
/* U+14450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1445F */
/* U+14460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1446F */
/* U+14470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1447F */
/* U+14480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1448F */
/* U+14490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1449F */
/* U+144A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144AF */
/* U+144B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144BF */
/* U+144C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144CF */
/* U+144D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144DF */
/* U+144E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144EF */
/* U+144F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+144FF */
/* U+14500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1450F */
/* U+14510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1451F */
/* U+14520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1452F */
/* U+14530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1453F */
/* U+14540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1454F */
/* U+14550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1455F */
/* U+14560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1456F */
/* U+14570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1457F */
/* U+14580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1458F */
/* U+14590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1459F */
/* U+145A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145AF */
/* U+145B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145BF */
/* U+145C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145CF */
/* U+145D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145DF */
/* U+145E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145EF */
/* U+145F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+145FF */
/* U+14600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1460F */
/* U+14610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1461F */
/* U+14620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1462F */
/* U+14630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1463F */
/* U+14640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1464F */
/* U+14650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1465F */
/* U+14660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1466F */
/* U+14670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1467F */
/* U+14680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1468F */
/* U+14690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1469F */
/* U+146A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146AF */
/* U+146B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146BF */
/* U+146C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146CF */
/* U+146D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146DF */
/* U+146E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146EF */
/* U+146F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+146FF */
/* U+14700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1470F */
/* U+14710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1471F */
/* U+14720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1472F */
/* U+14730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1473F */
/* U+14740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1474F */
/* U+14750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1475F */
/* U+14760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1476F */
/* U+14770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1477F */
/* U+14780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1478F */
/* U+14790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1479F */
/* U+147A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147AF */
/* U+147B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147BF */
/* U+147C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147CF */
/* U+147D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147DF */
/* U+147E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147EF */
/* U+147F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+147FF */
/* U+14800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1480F */
/* U+14810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1481F */
/* U+14820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1482F */
/* U+14830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1483F */
/* U+14840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1484F */
/* U+14850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1485F */
/* U+14860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1486F */
/* U+14870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1487F */
/* U+14880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1488F */
/* U+14890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1489F */
/* U+148A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148AF */
/* U+148B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148BF */
/* U+148C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148CF */
/* U+148D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148DF */
/* U+148E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148EF */
/* U+148F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+148FF */
/* U+14900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1490F */
/* U+14910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1491F */
/* U+14920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1492F */
/* U+14930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1493F */
/* U+14940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1494F */
/* U+14950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1495F */
/* U+14960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1496F */
/* U+14970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1497F */
/* U+14980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1498F */
/* U+14990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1499F */
/* U+149A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149AF */
/* U+149B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149BF */
/* U+149C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149CF */
/* U+149D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149DF */
/* U+149E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149EF */
/* U+149F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+149FF */
/* U+14A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A0F */
/* U+14A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A1F */
/* U+14A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A2F */
/* U+14A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A3F */
/* U+14A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A4F */
/* U+14A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A5F */
/* U+14A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A6F */
/* U+14A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A7F */
/* U+14A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A8F */
/* U+14A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14A9F */
/* U+14AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14AAF */
/* U+14AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14ABF */
/* U+14AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14ACF */
/* U+14AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14ADF */
/* U+14AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14AEF */
/* U+14AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14AFF */
/* U+14B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B0F */
/* U+14B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B1F */
/* U+14B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B2F */
/* U+14B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B3F */
/* U+14B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B4F */
/* U+14B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B5F */
/* U+14B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B6F */
/* U+14B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B7F */
/* U+14B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B8F */
/* U+14B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14B9F */
/* U+14BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BAF */
/* U+14BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BBF */
/* U+14BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BCF */
/* U+14BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BDF */
/* U+14BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BEF */
/* U+14BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14BFF */
/* U+14C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C0F */
/* U+14C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C1F */
/* U+14C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C2F */
/* U+14C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C3F */
/* U+14C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C4F */
/* U+14C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C5F */
/* U+14C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C6F */
/* U+14C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C7F */
/* U+14C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C8F */
/* U+14C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14C9F */
/* U+14CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CAF */
/* U+14CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CBF */
/* U+14CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CCF */
/* U+14CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CDF */
/* U+14CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CEF */
/* U+14CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14CFF */
/* U+14D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D0F */
/* U+14D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D1F */
/* U+14D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D2F */
/* U+14D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D3F */
/* U+14D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D4F */
/* U+14D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D5F */
/* U+14D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D6F */
/* U+14D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D7F */
/* U+14D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D8F */
/* U+14D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14D9F */
/* U+14DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DAF */
/* U+14DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DBF */
/* U+14DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DCF */
/* U+14DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DDF */
/* U+14DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DEF */
/* U+14DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14DFF */
/* U+14E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E0F */
/* U+14E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E1F */
/* U+14E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E2F */
/* U+14E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E3F */
/* U+14E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E4F */
/* U+14E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E5F */
/* U+14E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E6F */
/* U+14E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E7F */
/* U+14E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E8F */
/* U+14E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14E9F */
/* U+14EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14EAF */
/* U+14EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14EBF */
/* U+14EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14ECF */
/* U+14ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14EDF */
/* U+14EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14EEF */
/* U+14EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14EFF */
/* U+14F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F0F */
/* U+14F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F1F */
/* U+14F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F2F */
/* U+14F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F3F */
/* U+14F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F4F */
/* U+14F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F5F */
/* U+14F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F6F */
/* U+14F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F7F */
/* U+14F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F8F */
/* U+14F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14F9F */
/* U+14FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FAF */
/* U+14FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FBF */
/* U+14FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FCF */
/* U+14FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FDF */
/* U+14FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FEF */
/* U+14FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+14FFF */
/* U+15000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1500F */
/* U+15010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1501F */
/* U+15020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1502F */
/* U+15030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1503F */
/* U+15040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1504F */
/* U+15050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1505F */
/* U+15060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1506F */
/* U+15070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1507F */
/* U+15080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1508F */
/* U+15090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1509F */
/* U+150A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150AF */
/* U+150B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150BF */
/* U+150C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150CF */
/* U+150D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150DF */
/* U+150E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150EF */
/* U+150F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+150FF */
/* U+15100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1510F */
/* U+15110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1511F */
/* U+15120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1512F */
/* U+15130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1513F */
/* U+15140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1514F */
/* U+15150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1515F */
/* U+15160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1516F */
/* U+15170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1517F */
/* U+15180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1518F */
/* U+15190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1519F */
/* U+151A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151AF */
/* U+151B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151BF */
/* U+151C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151CF */
/* U+151D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151DF */
/* U+151E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151EF */
/* U+151F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+151FF */
/* U+15200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1520F */
/* U+15210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1521F */
/* U+15220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1522F */
/* U+15230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1523F */
/* U+15240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1524F */
/* U+15250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1525F */
/* U+15260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1526F */
/* U+15270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1527F */
/* U+15280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1528F */
/* U+15290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1529F */
/* U+152A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152AF */
/* U+152B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152BF */
/* U+152C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152CF */
/* U+152D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152DF */
/* U+152E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152EF */
/* U+152F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+152FF */
/* U+15300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1530F */
/* U+15310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1531F */
/* U+15320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1532F */
/* U+15330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1533F */
/* U+15340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1534F */
/* U+15350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1535F */
/* U+15360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1536F */
/* U+15370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1537F */
/* U+15380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1538F */
/* U+15390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1539F */
/* U+153A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153AF */
/* U+153B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153BF */
/* U+153C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153CF */
/* U+153D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153DF */
/* U+153E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153EF */
/* U+153F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+153FF */
/* U+15400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1540F */
/* U+15410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1541F */
/* U+15420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1542F */
/* U+15430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1543F */
/* U+15440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1544F */
/* U+15450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1545F */
/* U+15460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1546F */
/* U+15470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1547F */
/* U+15480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1548F */
/* U+15490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1549F */
/* U+154A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154AF */
/* U+154B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154BF */
/* U+154C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154CF */
/* U+154D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154DF */
/* U+154E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154EF */
/* U+154F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+154FF */
/* U+15500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1550F */
/* U+15510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1551F */
/* U+15520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1552F */
/* U+15530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1553F */
/* U+15540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1554F */
/* U+15550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1555F */
/* U+15560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1556F */
/* U+15570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1557F */
/* U+15580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1558F */
/* U+15590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1559F */
/* U+155A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155AF */
/* U+155B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155BF */
/* U+155C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155CF */
/* U+155D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155DF */
/* U+155E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155EF */
/* U+155F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+155FF */
/* U+15600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1560F */
/* U+15610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1561F */
/* U+15620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1562F */
/* U+15630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1563F */
/* U+15640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1564F */
/* U+15650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1565F */
/* U+15660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1566F */
/* U+15670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1567F */
/* U+15680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1568F */
/* U+15690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1569F */
/* U+156A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156AF */
/* U+156B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156BF */
/* U+156C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156CF */
/* U+156D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156DF */
/* U+156E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156EF */
/* U+156F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+156FF */
/* U+15700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1570F */
/* U+15710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1571F */
/* U+15720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1572F */
/* U+15730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1573F */
/* U+15740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1574F */
/* U+15750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1575F */
/* U+15760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1576F */
/* U+15770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1577F */
/* U+15780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1578F */
/* U+15790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1579F */
/* U+157A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157AF */
/* U+157B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157BF */
/* U+157C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157CF */
/* U+157D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157DF */
/* U+157E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157EF */
/* U+157F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+157FF */
/* U+15800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1580F */
/* U+15810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1581F */
/* U+15820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1582F */
/* U+15830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1583F */
/* U+15840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1584F */
/* U+15850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1585F */
/* U+15860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1586F */
/* U+15870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1587F */
/* U+15880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1588F */
/* U+15890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1589F */
/* U+158A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158AF */
/* U+158B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158BF */
/* U+158C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158CF */
/* U+158D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158DF */
/* U+158E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158EF */
/* U+158F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+158FF */
/* U+15900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1590F */
/* U+15910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1591F */
/* U+15920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1592F */
/* U+15930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1593F */
/* U+15940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1594F */
/* U+15950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1595F */
/* U+15960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1596F */
/* U+15970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1597F */
/* U+15980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1598F */
/* U+15990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1599F */
/* U+159A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159AF */
/* U+159B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159BF */
/* U+159C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159CF */
/* U+159D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159DF */
/* U+159E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159EF */
/* U+159F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+159FF */
/* U+15A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A0F */
/* U+15A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A1F */
/* U+15A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A2F */
/* U+15A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A3F */
/* U+15A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A4F */
/* U+15A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A5F */
/* U+15A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A6F */
/* U+15A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A7F */
/* U+15A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A8F */
/* U+15A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15A9F */
/* U+15AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15AAF */
/* U+15AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15ABF */
/* U+15AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15ACF */
/* U+15AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15ADF */
/* U+15AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15AEF */
/* U+15AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15AFF */
/* U+15B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B0F */
/* U+15B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B1F */
/* U+15B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B2F */
/* U+15B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B3F */
/* U+15B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B4F */
/* U+15B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B5F */
/* U+15B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B6F */
/* U+15B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B7F */
/* U+15B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B8F */
/* U+15B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15B9F */
/* U+15BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BAF */
/* U+15BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BBF */
/* U+15BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BCF */
/* U+15BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BDF */
/* U+15BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BEF */
/* U+15BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15BFF */
/* U+15C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C0F */
/* U+15C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C1F */
/* U+15C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C2F */
/* U+15C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C3F */
/* U+15C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C4F */
/* U+15C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C5F */
/* U+15C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C6F */
/* U+15C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C7F */
/* U+15C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C8F */
/* U+15C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15C9F */
/* U+15CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CAF */
/* U+15CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CBF */
/* U+15CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CCF */
/* U+15CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CDF */
/* U+15CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CEF */
/* U+15CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15CFF */
/* U+15D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D0F */
/* U+15D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D1F */
/* U+15D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D2F */
/* U+15D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D3F */
/* U+15D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D4F */
/* U+15D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D5F */
/* U+15D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D6F */
/* U+15D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D7F */
/* U+15D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D8F */
/* U+15D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15D9F */
/* U+15DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DAF */
/* U+15DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DBF */
/* U+15DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DCF */
/* U+15DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DDF */
/* U+15DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DEF */
/* U+15DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15DFF */
/* U+15E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E0F */
/* U+15E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E1F */
/* U+15E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E2F */
/* U+15E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E3F */
/* U+15E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E4F */
/* U+15E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E5F */
/* U+15E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E6F */
/* U+15E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E7F */
/* U+15E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E8F */
/* U+15E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15E9F */
/* U+15EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15EAF */
/* U+15EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15EBF */
/* U+15EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15ECF */
/* U+15ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15EDF */
/* U+15EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15EEF */
/* U+15EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15EFF */
/* U+15F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F0F */
/* U+15F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F1F */
/* U+15F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F2F */
/* U+15F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F3F */
/* U+15F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F4F */
/* U+15F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F5F */
/* U+15F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F6F */
/* U+15F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F7F */
/* U+15F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F8F */
/* U+15F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15F9F */
/* U+15FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FAF */
/* U+15FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FBF */
/* U+15FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FCF */
/* U+15FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FDF */
/* U+15FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FEF */
/* U+15FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+15FFF */
/* U+16000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1600F */
/* U+16010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1601F */
/* U+16020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1602F */
/* U+16030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1603F */
/* U+16040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1604F */
/* U+16050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1605F */
/* U+16060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1606F */
/* U+16070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1607F */
/* U+16080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1608F */
/* U+16090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1609F */
/* U+160A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160AF */
/* U+160B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160BF */
/* U+160C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160CF */
/* U+160D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160DF */
/* U+160E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160EF */
/* U+160F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+160FF */
/* U+16100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1610F */
/* U+16110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1611F */
/* U+16120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1612F */
/* U+16130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1613F */
/* U+16140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1614F */
/* U+16150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1615F */
/* U+16160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1616F */
/* U+16170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1617F */
/* U+16180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1618F */
/* U+16190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1619F */
/* U+161A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161AF */
/* U+161B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161BF */
/* U+161C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161CF */
/* U+161D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161DF */
/* U+161E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161EF */
/* U+161F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+161FF */
/* U+16200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1620F */
/* U+16210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1621F */
/* U+16220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1622F */
/* U+16230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1623F */
/* U+16240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1624F */
/* U+16250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1625F */
/* U+16260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1626F */
/* U+16270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1627F */
/* U+16280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1628F */
/* U+16290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1629F */
/* U+162A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162AF */
/* U+162B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162BF */
/* U+162C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162CF */
/* U+162D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162DF */
/* U+162E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162EF */
/* U+162F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+162FF */
/* U+16300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1630F */
/* U+16310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1631F */
/* U+16320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1632F */
/* U+16330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1633F */
/* U+16340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1634F */
/* U+16350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1635F */
/* U+16360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1636F */
/* U+16370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1637F */
/* U+16380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1638F */
/* U+16390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1639F */
/* U+163A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163AF */
/* U+163B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163BF */
/* U+163C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163CF */
/* U+163D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163DF */
/* U+163E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163EF */
/* U+163F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+163FF */
/* U+16400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1640F */
/* U+16410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1641F */
/* U+16420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1642F */
/* U+16430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1643F */
/* U+16440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1644F */
/* U+16450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1645F */
/* U+16460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1646F */
/* U+16470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1647F */
/* U+16480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1648F */
/* U+16490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1649F */
/* U+164A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164AF */
/* U+164B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164BF */
/* U+164C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164CF */
/* U+164D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164DF */
/* U+164E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164EF */
/* U+164F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+164FF */
/* U+16500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1650F */
/* U+16510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1651F */
/* U+16520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1652F */
/* U+16530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1653F */
/* U+16540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1654F */
/* U+16550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1655F */
/* U+16560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1656F */
/* U+16570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1657F */
/* U+16580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1658F */
/* U+16590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1659F */
/* U+165A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165AF */
/* U+165B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165BF */
/* U+165C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165CF */
/* U+165D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165DF */
/* U+165E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165EF */
/* U+165F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+165FF */
/* U+16600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1660F */
/* U+16610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1661F */
/* U+16620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1662F */
/* U+16630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1663F */
/* U+16640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1664F */
/* U+16650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1665F */
/* U+16660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1666F */
/* U+16670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1667F */
/* U+16680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1668F */
/* U+16690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1669F */
/* U+166A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166AF */
/* U+166B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166BF */
/* U+166C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166CF */
/* U+166D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166DF */
/* U+166E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166EF */
/* U+166F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+166FF */
/* U+16700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1670F */
/* U+16710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1671F */
/* U+16720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1672F */
/* U+16730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1673F */
/* U+16740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1674F */
/* U+16750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1675F */
/* U+16760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1676F */
/* U+16770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1677F */
/* U+16780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1678F */
/* U+16790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1679F */
/* U+167A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167AF */
/* U+167B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167BF */
/* U+167C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167CF */
/* U+167D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167DF */
/* U+167E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167EF */
/* U+167F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+167FF */
/* U+16800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1680F */
/* U+16810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1681F */
/* U+16820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1682F */
/* U+16830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1683F */
/* U+16840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1684F */
/* U+16850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1685F */
/* U+16860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1686F */
/* U+16870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1687F */
/* U+16880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1688F */
/* U+16890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1689F */
/* U+168A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168AF */
/* U+168B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168BF */
/* U+168C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168CF */
/* U+168D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168DF */
/* U+168E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168EF */
/* U+168F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+168FF */
/* U+16900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1690F */
/* U+16910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1691F */
/* U+16920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1692F */
/* U+16930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1693F */
/* U+16940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1694F */
/* U+16950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1695F */
/* U+16960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1696F */
/* U+16970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1697F */
/* U+16980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1698F */
/* U+16990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1699F */
/* U+169A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169AF */
/* U+169B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169BF */
/* U+169C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169CF */
/* U+169D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169DF */
/* U+169E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169EF */
/* U+169F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+169FF */
/* U+16A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A0F */
/* U+16A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A1F */
/* U+16A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A2F */
/* U+16A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A3F */
/* U+16A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A4F */
/* U+16A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A5F */
/* U+16A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A6F */
/* U+16A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A7F */
/* U+16A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A8F */
/* U+16A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16A9F */
/* U+16AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16AAF */
/* U+16AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16ABF */
/* U+16AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16ACF */
/* U+16AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16ADF */
/* U+16AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16AEF */
/* U+16AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16AFF */
/* U+16B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B0F */
/* U+16B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B1F */
/* U+16B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B2F */
/* U+16B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B3F */
/* U+16B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B4F */
/* U+16B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B5F */
/* U+16B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B6F */
/* U+16B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B7F */
/* U+16B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B8F */
/* U+16B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16B9F */
/* U+16BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BAF */
/* U+16BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BBF */
/* U+16BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BCF */
/* U+16BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BDF */
/* U+16BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BEF */
/* U+16BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16BFF */
/* U+16C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C0F */
/* U+16C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C1F */
/* U+16C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C2F */
/* U+16C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C3F */
/* U+16C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C4F */
/* U+16C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C5F */
/* U+16C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C6F */
/* U+16C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C7F */
/* U+16C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C8F */
/* U+16C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16C9F */
/* U+16CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CAF */
/* U+16CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CBF */
/* U+16CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CCF */
/* U+16CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CDF */
/* U+16CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CEF */
/* U+16CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16CFF */
/* U+16D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D0F */
/* U+16D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D1F */
/* U+16D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D2F */
/* U+16D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D3F */
/* U+16D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D4F */
/* U+16D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D5F */
/* U+16D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D6F */
/* U+16D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D7F */
/* U+16D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D8F */
/* U+16D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16D9F */
/* U+16DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DAF */
/* U+16DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DBF */
/* U+16DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DCF */
/* U+16DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DDF */
/* U+16DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DEF */
/* U+16DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16DFF */
/* U+16E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E0F */
/* U+16E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E1F */
/* U+16E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E2F */
/* U+16E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E3F */
/* U+16E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E4F */
/* U+16E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E5F */
/* U+16E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E6F */
/* U+16E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E7F */
/* U+16E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E8F */
/* U+16E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16E9F */
/* U+16EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16EAF */
/* U+16EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16EBF */
/* U+16EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16ECF */
/* U+16ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16EDF */
/* U+16EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16EEF */
/* U+16EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16EFF */
/* U+16F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F0F */
/* U+16F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F1F */
/* U+16F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F2F */
/* U+16F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F3F */
/* U+16F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F4F */
/* U+16F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F5F */
/* U+16F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F6F */
/* U+16F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F7F */
/* U+16F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F8F */
/* U+16F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16F9F */
/* U+16FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FAF */
/* U+16FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FBF */
/* U+16FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FCF */
/* U+16FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FDF */
/* U+16FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FEF */
/* U+16FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+16FFF */
/* U+17000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1700F */
/* U+17010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1701F */
/* U+17020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1702F */
/* U+17030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1703F */
/* U+17040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1704F */
/* U+17050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1705F */
/* U+17060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1706F */
/* U+17070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1707F */
/* U+17080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1708F */
/* U+17090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1709F */
/* U+170A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170AF */
/* U+170B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170BF */
/* U+170C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170CF */
/* U+170D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170DF */
/* U+170E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170EF */
/* U+170F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+170FF */
/* U+17100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1710F */
/* U+17110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1711F */
/* U+17120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1712F */
/* U+17130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1713F */
/* U+17140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1714F */
/* U+17150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1715F */
/* U+17160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1716F */
/* U+17170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1717F */
/* U+17180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1718F */
/* U+17190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1719F */
/* U+171A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171AF */
/* U+171B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171BF */
/* U+171C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171CF */
/* U+171D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171DF */
/* U+171E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171EF */
/* U+171F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+171FF */
/* U+17200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1720F */
/* U+17210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1721F */
/* U+17220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1722F */
/* U+17230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1723F */
/* U+17240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1724F */
/* U+17250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1725F */
/* U+17260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1726F */
/* U+17270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1727F */
/* U+17280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1728F */
/* U+17290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1729F */
/* U+172A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172AF */
/* U+172B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172BF */
/* U+172C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172CF */
/* U+172D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172DF */
/* U+172E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172EF */
/* U+172F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+172FF */
/* U+17300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1730F */
/* U+17310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1731F */
/* U+17320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1732F */
/* U+17330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1733F */
/* U+17340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1734F */
/* U+17350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1735F */
/* U+17360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1736F */
/* U+17370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1737F */
/* U+17380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1738F */
/* U+17390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1739F */
/* U+173A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173AF */
/* U+173B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173BF */
/* U+173C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173CF */
/* U+173D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173DF */
/* U+173E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173EF */
/* U+173F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+173FF */
/* U+17400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1740F */
/* U+17410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1741F */
/* U+17420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1742F */
/* U+17430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1743F */
/* U+17440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1744F */
/* U+17450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1745F */
/* U+17460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1746F */
/* U+17470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1747F */
/* U+17480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1748F */
/* U+17490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1749F */
/* U+174A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174AF */
/* U+174B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174BF */
/* U+174C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174CF */
/* U+174D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174DF */
/* U+174E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174EF */
/* U+174F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+174FF */
/* U+17500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1750F */
/* U+17510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1751F */
/* U+17520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1752F */
/* U+17530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1753F */
/* U+17540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1754F */
/* U+17550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1755F */
/* U+17560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1756F */
/* U+17570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1757F */
/* U+17580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1758F */
/* U+17590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1759F */
/* U+175A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175AF */
/* U+175B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175BF */
/* U+175C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175CF */
/* U+175D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175DF */
/* U+175E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175EF */
/* U+175F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+175FF */
/* U+17600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1760F */
/* U+17610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1761F */
/* U+17620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1762F */
/* U+17630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1763F */
/* U+17640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1764F */
/* U+17650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1765F */
/* U+17660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1766F */
/* U+17670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1767F */
/* U+17680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1768F */
/* U+17690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1769F */
/* U+176A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176AF */
/* U+176B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176BF */
/* U+176C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176CF */
/* U+176D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176DF */
/* U+176E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176EF */
/* U+176F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+176FF */
/* U+17700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1770F */
/* U+17710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1771F */
/* U+17720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1772F */
/* U+17730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1773F */
/* U+17740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1774F */
/* U+17750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1775F */
/* U+17760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1776F */
/* U+17770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1777F */
/* U+17780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1778F */
/* U+17790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1779F */
/* U+177A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177AF */
/* U+177B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177BF */
/* U+177C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177CF */
/* U+177D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177DF */
/* U+177E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177EF */
/* U+177F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+177FF */
/* U+17800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1780F */
/* U+17810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1781F */
/* U+17820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1782F */
/* U+17830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1783F */
/* U+17840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1784F */
/* U+17850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1785F */
/* U+17860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1786F */
/* U+17870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1787F */
/* U+17880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1788F */
/* U+17890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1789F */
/* U+178A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178AF */
/* U+178B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178BF */
/* U+178C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178CF */
/* U+178D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178DF */
/* U+178E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178EF */
/* U+178F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+178FF */
/* U+17900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1790F */
/* U+17910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1791F */
/* U+17920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1792F */
/* U+17930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1793F */
/* U+17940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1794F */
/* U+17950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1795F */
/* U+17960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1796F */
/* U+17970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1797F */
/* U+17980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1798F */
/* U+17990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1799F */
/* U+179A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179AF */
/* U+179B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179BF */
/* U+179C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179CF */
/* U+179D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179DF */
/* U+179E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179EF */
/* U+179F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+179FF */
/* U+17A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A0F */
/* U+17A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A1F */
/* U+17A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A2F */
/* U+17A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A3F */
/* U+17A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A4F */
/* U+17A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A5F */
/* U+17A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A6F */
/* U+17A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A7F */
/* U+17A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A8F */
/* U+17A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17A9F */
/* U+17AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17AAF */
/* U+17AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17ABF */
/* U+17AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17ACF */
/* U+17AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17ADF */
/* U+17AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17AEF */
/* U+17AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17AFF */
/* U+17B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B0F */
/* U+17B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B1F */
/* U+17B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B2F */
/* U+17B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B3F */
/* U+17B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B4F */
/* U+17B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B5F */
/* U+17B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B6F */
/* U+17B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B7F */
/* U+17B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B8F */
/* U+17B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17B9F */
/* U+17BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BAF */
/* U+17BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BBF */
/* U+17BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BCF */
/* U+17BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BDF */
/* U+17BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BEF */
/* U+17BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17BFF */
/* U+17C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C0F */
/* U+17C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C1F */
/* U+17C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C2F */
/* U+17C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C3F */
/* U+17C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C4F */
/* U+17C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C5F */
/* U+17C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C6F */
/* U+17C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C7F */
/* U+17C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C8F */
/* U+17C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17C9F */
/* U+17CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CAF */
/* U+17CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CBF */
/* U+17CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CCF */
/* U+17CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CDF */
/* U+17CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CEF */
/* U+17CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17CFF */
/* U+17D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D0F */
/* U+17D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D1F */
/* U+17D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D2F */
/* U+17D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D3F */
/* U+17D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D4F */
/* U+17D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D5F */
/* U+17D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D6F */
/* U+17D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D7F */
/* U+17D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D8F */
/* U+17D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17D9F */
/* U+17DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DAF */
/* U+17DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DBF */
/* U+17DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DCF */
/* U+17DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DDF */
/* U+17DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DEF */
/* U+17DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17DFF */
/* U+17E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E0F */
/* U+17E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E1F */
/* U+17E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E2F */
/* U+17E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E3F */
/* U+17E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E4F */
/* U+17E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E5F */
/* U+17E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E6F */
/* U+17E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E7F */
/* U+17E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E8F */
/* U+17E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17E9F */
/* U+17EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17EAF */
/* U+17EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17EBF */
/* U+17EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17ECF */
/* U+17ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17EDF */
/* U+17EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17EEF */
/* U+17EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17EFF */
/* U+17F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F0F */
/* U+17F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F1F */
/* U+17F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F2F */
/* U+17F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F3F */
/* U+17F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F4F */
/* U+17F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F5F */
/* U+17F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F6F */
/* U+17F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F7F */
/* U+17F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F8F */
/* U+17F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17F9F */
/* U+17FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FAF */
/* U+17FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FBF */
/* U+17FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FCF */
/* U+17FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FDF */
/* U+17FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FEF */
/* U+17FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+17FFF */
/* U+18000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1800F */
/* U+18010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1801F */
/* U+18020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1802F */
/* U+18030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1803F */
/* U+18040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1804F */
/* U+18050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1805F */
/* U+18060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1806F */
/* U+18070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1807F */
/* U+18080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1808F */
/* U+18090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1809F */
/* U+180A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180AF */
/* U+180B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180BF */
/* U+180C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180CF */
/* U+180D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180DF */
/* U+180E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180EF */
/* U+180F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+180FF */
/* U+18100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1810F */
/* U+18110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1811F */
/* U+18120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1812F */
/* U+18130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1813F */
/* U+18140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1814F */
/* U+18150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1815F */
/* U+18160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1816F */
/* U+18170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1817F */
/* U+18180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1818F */
/* U+18190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1819F */
/* U+181A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181AF */
/* U+181B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181BF */
/* U+181C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181CF */
/* U+181D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181DF */
/* U+181E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181EF */
/* U+181F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+181FF */
/* U+18200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1820F */
/* U+18210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1821F */
/* U+18220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1822F */
/* U+18230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1823F */
/* U+18240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1824F */
/* U+18250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1825F */
/* U+18260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1826F */
/* U+18270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1827F */
/* U+18280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1828F */
/* U+18290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1829F */
/* U+182A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182AF */
/* U+182B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182BF */
/* U+182C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182CF */
/* U+182D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182DF */
/* U+182E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182EF */
/* U+182F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+182FF */
/* U+18300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1830F */
/* U+18310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1831F */
/* U+18320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1832F */
/* U+18330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1833F */
/* U+18340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1834F */
/* U+18350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1835F */
/* U+18360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1836F */
/* U+18370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1837F */
/* U+18380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1838F */
/* U+18390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1839F */
/* U+183A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183AF */
/* U+183B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183BF */
/* U+183C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183CF */
/* U+183D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183DF */
/* U+183E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183EF */
/* U+183F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+183FF */
/* U+18400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1840F */
/* U+18410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1841F */
/* U+18420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1842F */
/* U+18430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1843F */
/* U+18440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1844F */
/* U+18450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1845F */
/* U+18460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1846F */
/* U+18470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1847F */
/* U+18480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1848F */
/* U+18490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1849F */
/* U+184A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184AF */
/* U+184B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184BF */
/* U+184C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184CF */
/* U+184D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184DF */
/* U+184E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184EF */
/* U+184F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+184FF */
/* U+18500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1850F */
/* U+18510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1851F */
/* U+18520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1852F */
/* U+18530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1853F */
/* U+18540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1854F */
/* U+18550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1855F */
/* U+18560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1856F */
/* U+18570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1857F */
/* U+18580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1858F */
/* U+18590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1859F */
/* U+185A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185AF */
/* U+185B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185BF */
/* U+185C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185CF */
/* U+185D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185DF */
/* U+185E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185EF */
/* U+185F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+185FF */
/* U+18600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1860F */
/* U+18610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1861F */
/* U+18620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1862F */
/* U+18630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1863F */
/* U+18640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1864F */
/* U+18650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1865F */
/* U+18660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1866F */
/* U+18670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1867F */
/* U+18680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1868F */
/* U+18690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1869F */
/* U+186A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186AF */
/* U+186B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186BF */
/* U+186C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186CF */
/* U+186D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186DF */
/* U+186E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186EF */
/* U+186F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+186FF */
/* U+18700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1870F */
/* U+18710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1871F */
/* U+18720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1872F */
/* U+18730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1873F */
/* U+18740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1874F */
/* U+18750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1875F */
/* U+18760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1876F */
/* U+18770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1877F */
/* U+18780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1878F */
/* U+18790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1879F */
/* U+187A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187AF */
/* U+187B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187BF */
/* U+187C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187CF */
/* U+187D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187DF */
/* U+187E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187EF */
/* U+187F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+187FF */
/* U+18800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1880F */
/* U+18810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1881F */
/* U+18820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1882F */
/* U+18830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1883F */
/* U+18840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1884F */
/* U+18850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1885F */
/* U+18860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1886F */
/* U+18870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1887F */
/* U+18880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1888F */
/* U+18890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1889F */
/* U+188A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188AF */
/* U+188B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188BF */
/* U+188C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188CF */
/* U+188D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188DF */
/* U+188E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188EF */
/* U+188F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+188FF */
/* U+18900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1890F */
/* U+18910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1891F */
/* U+18920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1892F */
/* U+18930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1893F */
/* U+18940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1894F */
/* U+18950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1895F */
/* U+18960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1896F */
/* U+18970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1897F */
/* U+18980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1898F */
/* U+18990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1899F */
/* U+189A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189AF */
/* U+189B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189BF */
/* U+189C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189CF */
/* U+189D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189DF */
/* U+189E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189EF */
/* U+189F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+189FF */
/* U+18A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A0F */
/* U+18A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A1F */
/* U+18A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A2F */
/* U+18A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A3F */
/* U+18A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A4F */
/* U+18A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A5F */
/* U+18A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A6F */
/* U+18A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A7F */
/* U+18A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A8F */
/* U+18A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18A9F */
/* U+18AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18AAF */
/* U+18AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18ABF */
/* U+18AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18ACF */
/* U+18AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18ADF */
/* U+18AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18AEF */
/* U+18AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18AFF */
/* U+18B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B0F */
/* U+18B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B1F */
/* U+18B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B2F */
/* U+18B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B3F */
/* U+18B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B4F */
/* U+18B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B5F */
/* U+18B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B6F */
/* U+18B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B7F */
/* U+18B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B8F */
/* U+18B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18B9F */
/* U+18BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BAF */
/* U+18BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BBF */
/* U+18BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BCF */
/* U+18BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BDF */
/* U+18BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BEF */
/* U+18BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18BFF */
/* U+18C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C0F */
/* U+18C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C1F */
/* U+18C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C2F */
/* U+18C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C3F */
/* U+18C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C4F */
/* U+18C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C5F */
/* U+18C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C6F */
/* U+18C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C7F */
/* U+18C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C8F */
/* U+18C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18C9F */
/* U+18CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CAF */
/* U+18CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CBF */
/* U+18CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CCF */
/* U+18CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CDF */
/* U+18CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CEF */
/* U+18CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18CFF */
/* U+18D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D0F */
/* U+18D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D1F */
/* U+18D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D2F */
/* U+18D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D3F */
/* U+18D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D4F */
/* U+18D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D5F */
/* U+18D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D6F */
/* U+18D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D7F */
/* U+18D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D8F */
/* U+18D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18D9F */
/* U+18DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DAF */
/* U+18DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DBF */
/* U+18DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DCF */
/* U+18DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DDF */
/* U+18DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DEF */
/* U+18DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18DFF */
/* U+18E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E0F */
/* U+18E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E1F */
/* U+18E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E2F */
/* U+18E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E3F */
/* U+18E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E4F */
/* U+18E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E5F */
/* U+18E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E6F */
/* U+18E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E7F */
/* U+18E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E8F */
/* U+18E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18E9F */
/* U+18EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18EAF */
/* U+18EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18EBF */
/* U+18EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18ECF */
/* U+18ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18EDF */
/* U+18EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18EEF */
/* U+18EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18EFF */
/* U+18F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F0F */
/* U+18F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F1F */
/* U+18F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F2F */
/* U+18F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F3F */
/* U+18F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F4F */
/* U+18F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F5F */
/* U+18F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F6F */
/* U+18F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F7F */
/* U+18F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F8F */
/* U+18F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18F9F */
/* U+18FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FAF */
/* U+18FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FBF */
/* U+18FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FCF */
/* U+18FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FDF */
/* U+18FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FEF */
/* U+18FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+18FFF */
/* U+19000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1900F */
/* U+19010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1901F */
/* U+19020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1902F */
/* U+19030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1903F */
/* U+19040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1904F */
/* U+19050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1905F */
/* U+19060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1906F */
/* U+19070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1907F */
/* U+19080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1908F */
/* U+19090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1909F */
/* U+190A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190AF */
/* U+190B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190BF */
/* U+190C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190CF */
/* U+190D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190DF */
/* U+190E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190EF */
/* U+190F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+190FF */
/* U+19100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1910F */
/* U+19110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1911F */
/* U+19120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1912F */
/* U+19130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1913F */
/* U+19140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1914F */
/* U+19150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1915F */
/* U+19160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1916F */
/* U+19170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1917F */
/* U+19180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1918F */
/* U+19190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1919F */
/* U+191A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191AF */
/* U+191B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191BF */
/* U+191C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191CF */
/* U+191D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191DF */
/* U+191E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191EF */
/* U+191F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+191FF */
/* U+19200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1920F */
/* U+19210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1921F */
/* U+19220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1922F */
/* U+19230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1923F */
/* U+19240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1924F */
/* U+19250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1925F */
/* U+19260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1926F */
/* U+19270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1927F */
/* U+19280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1928F */
/* U+19290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1929F */
/* U+192A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192AF */
/* U+192B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192BF */
/* U+192C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192CF */
/* U+192D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192DF */
/* U+192E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192EF */
/* U+192F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+192FF */
/* U+19300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1930F */
/* U+19310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1931F */
/* U+19320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1932F */
/* U+19330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1933F */
/* U+19340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1934F */
/* U+19350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1935F */
/* U+19360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1936F */
/* U+19370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1937F */
/* U+19380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1938F */
/* U+19390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1939F */
/* U+193A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193AF */
/* U+193B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193BF */
/* U+193C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193CF */
/* U+193D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193DF */
/* U+193E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193EF */
/* U+193F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+193FF */
/* U+19400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1940F */
/* U+19410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1941F */
/* U+19420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1942F */
/* U+19430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1943F */
/* U+19440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1944F */
/* U+19450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1945F */
/* U+19460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1946F */
/* U+19470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1947F */
/* U+19480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1948F */
/* U+19490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1949F */
/* U+194A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194AF */
/* U+194B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194BF */
/* U+194C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194CF */
/* U+194D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194DF */
/* U+194E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194EF */
/* U+194F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+194FF */
/* U+19500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1950F */
/* U+19510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1951F */
/* U+19520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1952F */
/* U+19530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1953F */
/* U+19540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1954F */
/* U+19550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1955F */
/* U+19560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1956F */
/* U+19570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1957F */
/* U+19580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1958F */
/* U+19590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1959F */
/* U+195A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195AF */
/* U+195B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195BF */
/* U+195C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195CF */
/* U+195D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195DF */
/* U+195E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195EF */
/* U+195F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+195FF */
/* U+19600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1960F */
/* U+19610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1961F */
/* U+19620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1962F */
/* U+19630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1963F */
/* U+19640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1964F */
/* U+19650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1965F */
/* U+19660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1966F */
/* U+19670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1967F */
/* U+19680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1968F */
/* U+19690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1969F */
/* U+196A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196AF */
/* U+196B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196BF */
/* U+196C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196CF */
/* U+196D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196DF */
/* U+196E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196EF */
/* U+196F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+196FF */
/* U+19700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1970F */
/* U+19710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1971F */
/* U+19720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1972F */
/* U+19730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1973F */
/* U+19740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1974F */
/* U+19750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1975F */
/* U+19760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1976F */
/* U+19770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1977F */
/* U+19780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1978F */
/* U+19790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1979F */
/* U+197A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197AF */
/* U+197B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197BF */
/* U+197C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197CF */
/* U+197D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197DF */
/* U+197E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197EF */
/* U+197F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+197FF */
/* U+19800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1980F */
/* U+19810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1981F */
/* U+19820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1982F */
/* U+19830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1983F */
/* U+19840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1984F */
/* U+19850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1985F */
/* U+19860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1986F */
/* U+19870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1987F */
/* U+19880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1988F */
/* U+19890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1989F */
/* U+198A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198AF */
/* U+198B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198BF */
/* U+198C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198CF */
/* U+198D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198DF */
/* U+198E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198EF */
/* U+198F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+198FF */
/* U+19900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1990F */
/* U+19910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1991F */
/* U+19920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1992F */
/* U+19930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1993F */
/* U+19940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1994F */
/* U+19950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1995F */
/* U+19960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1996F */
/* U+19970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1997F */
/* U+19980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1998F */
/* U+19990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1999F */
/* U+199A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199AF */
/* U+199B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199BF */
/* U+199C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199CF */
/* U+199D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199DF */
/* U+199E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199EF */
/* U+199F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+199FF */
/* U+19A00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A0F */
/* U+19A10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A1F */
/* U+19A20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A2F */
/* U+19A30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A3F */
/* U+19A40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A4F */
/* U+19A50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A5F */
/* U+19A60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A6F */
/* U+19A70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A7F */
/* U+19A80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A8F */
/* U+19A90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19A9F */
/* U+19AA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19AAF */
/* U+19AB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19ABF */
/* U+19AC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19ACF */
/* U+19AD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19ADF */
/* U+19AE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19AEF */
/* U+19AF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19AFF */
/* U+19B00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B0F */
/* U+19B10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B1F */
/* U+19B20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B2F */
/* U+19B30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B3F */
/* U+19B40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B4F */
/* U+19B50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B5F */
/* U+19B60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B6F */
/* U+19B70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B7F */
/* U+19B80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B8F */
/* U+19B90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19B9F */
/* U+19BA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BAF */
/* U+19BB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BBF */
/* U+19BC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BCF */
/* U+19BD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BDF */
/* U+19BE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BEF */
/* U+19BF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19BFF */
/* U+19C00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C0F */
/* U+19C10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C1F */
/* U+19C20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C2F */
/* U+19C30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C3F */
/* U+19C40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C4F */
/* U+19C50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C5F */
/* U+19C60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C6F */
/* U+19C70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C7F */
/* U+19C80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C8F */
/* U+19C90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19C9F */
/* U+19CA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CAF */
/* U+19CB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CBF */
/* U+19CC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CCF */
/* U+19CD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CDF */
/* U+19CE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CEF */
/* U+19CF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19CFF */
/* U+19D00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D0F */
/* U+19D10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D1F */
/* U+19D20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D2F */
/* U+19D30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D3F */
/* U+19D40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D4F */
/* U+19D50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D5F */
/* U+19D60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D6F */
/* U+19D70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D7F */
/* U+19D80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D8F */
/* U+19D90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19D9F */
/* U+19DA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DAF */
/* U+19DB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DBF */
/* U+19DC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DCF */
/* U+19DD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DDF */
/* U+19DE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DEF */
/* U+19DF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19DFF */
/* U+19E00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E0F */
/* U+19E10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E1F */
/* U+19E20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E2F */
/* U+19E30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E3F */
/* U+19E40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E4F */
/* U+19E50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E5F */
/* U+19E60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E6F */
/* U+19E70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E7F */
/* U+19E80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E8F */
/* U+19E90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19E9F */
/* U+19EA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19EAF */
/* U+19EB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19EBF */
/* U+19EC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19ECF */
/* U+19ED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19EDF */
/* U+19EE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19EEF */
/* U+19EF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19EFF */
/* U+19F00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F0F */
/* U+19F10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F1F */
/* U+19F20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F2F */
/* U+19F30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F3F */
/* U+19F40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F4F */
/* U+19F50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F5F */
/* U+19F60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F6F */
/* U+19F70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F7F */
/* U+19F80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F8F */
/* U+19F90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19F9F */
/* U+19FA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FAF */
/* U+19FB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FBF */
/* U+19FC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FCF */
/* U+19FD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FDF */
/* U+19FE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FEF */
/* U+19FF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+19FFF */
/* U+1A000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A00F */
/* U+1A010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A01F */
/* U+1A020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A02F */
/* U+1A030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A03F */
/* U+1A040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A04F */
/* U+1A050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A05F */
/* U+1A060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A06F */
/* U+1A070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A07F */
/* U+1A080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A08F */
/* U+1A090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A09F */
/* U+1A0A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0AF */
/* U+1A0B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0BF */
/* U+1A0C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0CF */
/* U+1A0D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0DF */
/* U+1A0E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0EF */
/* U+1A0F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A0FF */
/* U+1A100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A10F */
/* U+1A110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A11F */
/* U+1A120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A12F */
/* U+1A130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A13F */
/* U+1A140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A14F */
/* U+1A150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A15F */
/* U+1A160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A16F */
/* U+1A170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A17F */
/* U+1A180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A18F */
/* U+1A190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A19F */
/* U+1A1A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1AF */
/* U+1A1B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1BF */
/* U+1A1C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1CF */
/* U+1A1D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1DF */
/* U+1A1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1EF */
/* U+1A1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A1FF */
/* U+1A200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A20F */
/* U+1A210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A21F */
/* U+1A220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A22F */
/* U+1A230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A23F */
/* U+1A240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A24F */
/* U+1A250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A25F */
/* U+1A260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A26F */
/* U+1A270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A27F */
/* U+1A280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A28F */
/* U+1A290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A29F */
/* U+1A2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2AF */
/* U+1A2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2BF */
/* U+1A2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2CF */
/* U+1A2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2DF */
/* U+1A2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2EF */
/* U+1A2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A2FF */
/* U+1A300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A30F */
/* U+1A310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A31F */
/* U+1A320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A32F */
/* U+1A330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A33F */
/* U+1A340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A34F */
/* U+1A350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A35F */
/* U+1A360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A36F */
/* U+1A370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A37F */
/* U+1A380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A38F */
/* U+1A390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A39F */
/* U+1A3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3AF */
/* U+1A3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3BF */
/* U+1A3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3CF */
/* U+1A3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3DF */
/* U+1A3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3EF */
/* U+1A3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A3FF */
/* U+1A400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A40F */
/* U+1A410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A41F */
/* U+1A420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A42F */
/* U+1A430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A43F */
/* U+1A440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A44F */
/* U+1A450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A45F */
/* U+1A460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A46F */
/* U+1A470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A47F */
/* U+1A480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A48F */
/* U+1A490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A49F */
/* U+1A4A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4AF */
/* U+1A4B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4BF */
/* U+1A4C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4CF */
/* U+1A4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4DF */
/* U+1A4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4EF */
/* U+1A4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A4FF */
/* U+1A500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A50F */
/* U+1A510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A51F */
/* U+1A520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A52F */
/* U+1A530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A53F */
/* U+1A540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A54F */
/* U+1A550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A55F */
/* U+1A560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A56F */
/* U+1A570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A57F */
/* U+1A580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A58F */
/* U+1A590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A59F */
/* U+1A5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5AF */
/* U+1A5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5BF */
/* U+1A5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5CF */
/* U+1A5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5DF */
/* U+1A5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5EF */
/* U+1A5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A5FF */
/* U+1A600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A60F */
/* U+1A610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A61F */
/* U+1A620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A62F */
/* U+1A630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A63F */
/* U+1A640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A64F */
/* U+1A650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A65F */
/* U+1A660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A66F */
/* U+1A670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A67F */
/* U+1A680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A68F */
/* U+1A690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A69F */
/* U+1A6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6AF */
/* U+1A6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6BF */
/* U+1A6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6CF */
/* U+1A6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6DF */
/* U+1A6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6EF */
/* U+1A6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A6FF */
/* U+1A700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A70F */
/* U+1A710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A71F */
/* U+1A720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A72F */
/* U+1A730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A73F */
/* U+1A740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A74F */
/* U+1A750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A75F */
/* U+1A760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A76F */
/* U+1A770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A77F */
/* U+1A780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A78F */
/* U+1A790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A79F */
/* U+1A7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7AF */
/* U+1A7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7BF */
/* U+1A7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7CF */
/* U+1A7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7DF */
/* U+1A7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7EF */
/* U+1A7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A7FF */
/* U+1A800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A80F */
/* U+1A810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A81F */
/* U+1A820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A82F */
/* U+1A830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A83F */
/* U+1A840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A84F */
/* U+1A850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A85F */
/* U+1A860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A86F */
/* U+1A870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A87F */
/* U+1A880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A88F */
/* U+1A890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A89F */
/* U+1A8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8AF */
/* U+1A8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8BF */
/* U+1A8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8CF */
/* U+1A8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8DF */
/* U+1A8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8EF */
/* U+1A8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A8FF */
/* U+1A900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A90F */
/* U+1A910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A91F */
/* U+1A920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A92F */
/* U+1A930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A93F */
/* U+1A940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A94F */
/* U+1A950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A95F */
/* U+1A960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A96F */
/* U+1A970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A97F */
/* U+1A980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A98F */
/* U+1A990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A99F */
/* U+1A9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9AF */
/* U+1A9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9BF */
/* U+1A9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9CF */
/* U+1A9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9DF */
/* U+1A9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9EF */
/* U+1A9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1A9FF */
/* U+1AA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA0F */
/* U+1AA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA1F */
/* U+1AA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA2F */
/* U+1AA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA3F */
/* U+1AA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA4F */
/* U+1AA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA5F */
/* U+1AA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA6F */
/* U+1AA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA7F */
/* U+1AA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA8F */
/* U+1AA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AA9F */
/* U+1AAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AAAF */
/* U+1AAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AABF */
/* U+1AAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AACF */
/* U+1AAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AADF */
/* U+1AAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AAEF */
/* U+1AAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AAFF */
/* U+1AB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB0F */
/* U+1AB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB1F */
/* U+1AB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB2F */
/* U+1AB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB3F */
/* U+1AB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB4F */
/* U+1AB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB5F */
/* U+1AB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB6F */
/* U+1AB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB7F */
/* U+1AB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB8F */
/* U+1AB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AB9F */
/* U+1ABA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABAF */
/* U+1ABB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABBF */
/* U+1ABC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABCF */
/* U+1ABD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABDF */
/* U+1ABE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABEF */
/* U+1ABF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ABFF */
/* U+1AC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC0F */
/* U+1AC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC1F */
/* U+1AC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC2F */
/* U+1AC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC3F */
/* U+1AC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC4F */
/* U+1AC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC5F */
/* U+1AC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC6F */
/* U+1AC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC7F */
/* U+1AC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC8F */
/* U+1AC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AC9F */
/* U+1ACA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACAF */
/* U+1ACB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACBF */
/* U+1ACC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACCF */
/* U+1ACD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACDF */
/* U+1ACE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACEF */
/* U+1ACF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ACFF */
/* U+1AD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD0F */
/* U+1AD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD1F */
/* U+1AD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD2F */
/* U+1AD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD3F */
/* U+1AD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD4F */
/* U+1AD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD5F */
/* U+1AD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD6F */
/* U+1AD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD7F */
/* U+1AD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD8F */
/* U+1AD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AD9F */
/* U+1ADA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADAF */
/* U+1ADB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADBF */
/* U+1ADC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADCF */
/* U+1ADD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADDF */
/* U+1ADE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADEF */
/* U+1ADF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ADFF */
/* U+1AE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE0F */
/* U+1AE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE1F */
/* U+1AE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE2F */
/* U+1AE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE3F */
/* U+1AE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE4F */
/* U+1AE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE5F */
/* U+1AE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE6F */
/* U+1AE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE7F */
/* U+1AE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE8F */
/* U+1AE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AE9F */
/* U+1AEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AEAF */
/* U+1AEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AEBF */
/* U+1AEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AECF */
/* U+1AED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AEDF */
/* U+1AEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AEEF */
/* U+1AEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AEFF */
/* U+1AF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF0F */
/* U+1AF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF1F */
/* U+1AF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF2F */
/* U+1AF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF3F */
/* U+1AF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF4F */
/* U+1AF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF5F */
/* U+1AF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF6F */
/* U+1AF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF7F */
/* U+1AF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF8F */
/* U+1AF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AF9F */
/* U+1AFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFAF */
/* U+1AFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFBF */
/* U+1AFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFCF */
/* U+1AFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFDF */
/* U+1AFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFEF */
/* U+1AFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1AFFF */
/* U+1B000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B00F */
/* U+1B010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B01F */
/* U+1B020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B02F */
/* U+1B030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B03F */
/* U+1B040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B04F */
/* U+1B050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B05F */
/* U+1B060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B06F */
/* U+1B070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B07F */
/* U+1B080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B08F */
/* U+1B090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B09F */
/* U+1B0A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0AF */
/* U+1B0B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0BF */
/* U+1B0C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0CF */
/* U+1B0D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0DF */
/* U+1B0E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0EF */
/* U+1B0F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B0FF */
/* U+1B100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B10F */
/* U+1B110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B11F */
/* U+1B120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B12F */
/* U+1B130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B13F */
/* U+1B140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B14F */
/* U+1B150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B15F */
/* U+1B160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B16F */
/* U+1B170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B17F */
/* U+1B180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B18F */
/* U+1B190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B19F */
/* U+1B1A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1AF */
/* U+1B1B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1BF */
/* U+1B1C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1CF */
/* U+1B1D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1DF */
/* U+1B1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1EF */
/* U+1B1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B1FF */
/* U+1B200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B20F */
/* U+1B210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B21F */
/* U+1B220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B22F */
/* U+1B230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B23F */
/* U+1B240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B24F */
/* U+1B250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B25F */
/* U+1B260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B26F */
/* U+1B270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B27F */
/* U+1B280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B28F */
/* U+1B290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B29F */
/* U+1B2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2AF */
/* U+1B2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2BF */
/* U+1B2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2CF */
/* U+1B2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2DF */
/* U+1B2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2EF */
/* U+1B2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B2FF */
/* U+1B300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B30F */
/* U+1B310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B31F */
/* U+1B320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B32F */
/* U+1B330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B33F */
/* U+1B340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B34F */
/* U+1B350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B35F */
/* U+1B360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B36F */
/* U+1B370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B37F */
/* U+1B380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B38F */
/* U+1B390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B39F */
/* U+1B3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3AF */
/* U+1B3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3BF */
/* U+1B3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3CF */
/* U+1B3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3DF */
/* U+1B3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3EF */
/* U+1B3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B3FF */
/* U+1B400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B40F */
/* U+1B410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B41F */
/* U+1B420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B42F */
/* U+1B430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B43F */
/* U+1B440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B44F */
/* U+1B450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B45F */
/* U+1B460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B46F */
/* U+1B470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B47F */
/* U+1B480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B48F */
/* U+1B490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B49F */
/* U+1B4A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4AF */
/* U+1B4B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4BF */
/* U+1B4C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4CF */
/* U+1B4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4DF */
/* U+1B4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4EF */
/* U+1B4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B4FF */
/* U+1B500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B50F */
/* U+1B510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B51F */
/* U+1B520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B52F */
/* U+1B530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B53F */
/* U+1B540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B54F */
/* U+1B550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B55F */
/* U+1B560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B56F */
/* U+1B570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B57F */
/* U+1B580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B58F */
/* U+1B590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B59F */
/* U+1B5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5AF */
/* U+1B5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5BF */
/* U+1B5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5CF */
/* U+1B5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5DF */
/* U+1B5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5EF */
/* U+1B5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B5FF */
/* U+1B600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B60F */
/* U+1B610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B61F */
/* U+1B620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B62F */
/* U+1B630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B63F */
/* U+1B640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B64F */
/* U+1B650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B65F */
/* U+1B660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B66F */
/* U+1B670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B67F */
/* U+1B680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B68F */
/* U+1B690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B69F */
/* U+1B6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6AF */
/* U+1B6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6BF */
/* U+1B6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6CF */
/* U+1B6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6DF */
/* U+1B6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6EF */
/* U+1B6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B6FF */
/* U+1B700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B70F */
/* U+1B710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B71F */
/* U+1B720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B72F */
/* U+1B730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B73F */
/* U+1B740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B74F */
/* U+1B750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B75F */
/* U+1B760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B76F */
/* U+1B770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B77F */
/* U+1B780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B78F */
/* U+1B790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B79F */
/* U+1B7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7AF */
/* U+1B7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7BF */
/* U+1B7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7CF */
/* U+1B7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7DF */
/* U+1B7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7EF */
/* U+1B7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B7FF */
/* U+1B800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B80F */
/* U+1B810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B81F */
/* U+1B820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B82F */
/* U+1B830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B83F */
/* U+1B840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B84F */
/* U+1B850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B85F */
/* U+1B860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B86F */
/* U+1B870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B87F */
/* U+1B880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B88F */
/* U+1B890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B89F */
/* U+1B8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8AF */
/* U+1B8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8BF */
/* U+1B8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8CF */
/* U+1B8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8DF */
/* U+1B8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8EF */
/* U+1B8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B8FF */
/* U+1B900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B90F */
/* U+1B910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B91F */
/* U+1B920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B92F */
/* U+1B930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B93F */
/* U+1B940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B94F */
/* U+1B950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B95F */
/* U+1B960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B96F */
/* U+1B970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B97F */
/* U+1B980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B98F */
/* U+1B990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B99F */
/* U+1B9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9AF */
/* U+1B9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9BF */
/* U+1B9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9CF */
/* U+1B9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9DF */
/* U+1B9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9EF */
/* U+1B9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1B9FF */
/* U+1BA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA0F */
/* U+1BA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA1F */
/* U+1BA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA2F */
/* U+1BA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA3F */
/* U+1BA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA4F */
/* U+1BA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA5F */
/* U+1BA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA6F */
/* U+1BA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA7F */
/* U+1BA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA8F */
/* U+1BA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BA9F */
/* U+1BAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BAAF */
/* U+1BAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BABF */
/* U+1BAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BACF */
/* U+1BAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BADF */
/* U+1BAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BAEF */
/* U+1BAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BAFF */
/* U+1BB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB0F */
/* U+1BB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB1F */
/* U+1BB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB2F */
/* U+1BB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB3F */
/* U+1BB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB4F */
/* U+1BB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB5F */
/* U+1BB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB6F */
/* U+1BB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB7F */
/* U+1BB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB8F */
/* U+1BB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BB9F */
/* U+1BBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBAF */
/* U+1BBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBBF */
/* U+1BBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBCF */
/* U+1BBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBDF */
/* U+1BBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBEF */
/* U+1BBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BBFF */
/* U+1BC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC0F */
/* U+1BC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC1F */
/* U+1BC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC2F */
/* U+1BC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC3F */
/* U+1BC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC4F */
/* U+1BC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC5F */
/* U+1BC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC6F */
/* U+1BC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC7F */
/* U+1BC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC8F */
/* U+1BC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BC9F */
/* U+1BCA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCAF */
/* U+1BCB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCBF */
/* U+1BCC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCCF */
/* U+1BCD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCDF */
/* U+1BCE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCEF */
/* U+1BCF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BCFF */
/* U+1BD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD0F */
/* U+1BD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD1F */
/* U+1BD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD2F */
/* U+1BD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD3F */
/* U+1BD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD4F */
/* U+1BD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD5F */
/* U+1BD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD6F */
/* U+1BD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD7F */
/* U+1BD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD8F */
/* U+1BD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BD9F */
/* U+1BDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDAF */
/* U+1BDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDBF */
/* U+1BDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDCF */
/* U+1BDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDDF */
/* U+1BDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDEF */
/* U+1BDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BDFF */
/* U+1BE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE0F */
/* U+1BE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE1F */
/* U+1BE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE2F */
/* U+1BE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE3F */
/* U+1BE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE4F */
/* U+1BE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE5F */
/* U+1BE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE6F */
/* U+1BE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE7F */
/* U+1BE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE8F */
/* U+1BE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BE9F */
/* U+1BEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BEAF */
/* U+1BEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BEBF */
/* U+1BEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BECF */
/* U+1BED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BEDF */
/* U+1BEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BEEF */
/* U+1BEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BEFF */
/* U+1BF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF0F */
/* U+1BF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF1F */
/* U+1BF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF2F */
/* U+1BF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF3F */
/* U+1BF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF4F */
/* U+1BF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF5F */
/* U+1BF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF6F */
/* U+1BF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF7F */
/* U+1BF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF8F */
/* U+1BF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BF9F */
/* U+1BFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFAF */
/* U+1BFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFBF */
/* U+1BFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFCF */
/* U+1BFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFDF */
/* U+1BFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFEF */
/* U+1BFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1BFFF */
/* U+1C000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C00F */
/* U+1C010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C01F */
/* U+1C020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C02F */
/* U+1C030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C03F */
/* U+1C040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C04F */
/* U+1C050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C05F */
/* U+1C060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C06F */
/* U+1C070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C07F */
/* U+1C080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C08F */
/* U+1C090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C09F */
/* U+1C0A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0AF */
/* U+1C0B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0BF */
/* U+1C0C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0CF */
/* U+1C0D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0DF */
/* U+1C0E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0EF */
/* U+1C0F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C0FF */
/* U+1C100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C10F */
/* U+1C110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C11F */
/* U+1C120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C12F */
/* U+1C130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C13F */
/* U+1C140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C14F */
/* U+1C150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C15F */
/* U+1C160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C16F */
/* U+1C170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C17F */
/* U+1C180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C18F */
/* U+1C190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C19F */
/* U+1C1A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1AF */
/* U+1C1B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1BF */
/* U+1C1C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1CF */
/* U+1C1D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1DF */
/* U+1C1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1EF */
/* U+1C1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C1FF */
/* U+1C200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C20F */
/* U+1C210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C21F */
/* U+1C220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C22F */
/* U+1C230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C23F */
/* U+1C240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C24F */
/* U+1C250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C25F */
/* U+1C260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C26F */
/* U+1C270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C27F */
/* U+1C280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C28F */
/* U+1C290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C29F */
/* U+1C2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2AF */
/* U+1C2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2BF */
/* U+1C2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2CF */
/* U+1C2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2DF */
/* U+1C2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2EF */
/* U+1C2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C2FF */
/* U+1C300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C30F */
/* U+1C310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C31F */
/* U+1C320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C32F */
/* U+1C330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C33F */
/* U+1C340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C34F */
/* U+1C350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C35F */
/* U+1C360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C36F */
/* U+1C370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C37F */
/* U+1C380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C38F */
/* U+1C390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C39F */
/* U+1C3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3AF */
/* U+1C3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3BF */
/* U+1C3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3CF */
/* U+1C3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3DF */
/* U+1C3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3EF */
/* U+1C3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C3FF */
/* U+1C400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C40F */
/* U+1C410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C41F */
/* U+1C420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C42F */
/* U+1C430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C43F */
/* U+1C440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C44F */
/* U+1C450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C45F */
/* U+1C460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C46F */
/* U+1C470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C47F */
/* U+1C480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C48F */
/* U+1C490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C49F */
/* U+1C4A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4AF */
/* U+1C4B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4BF */
/* U+1C4C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4CF */
/* U+1C4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4DF */
/* U+1C4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4EF */
/* U+1C4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C4FF */
/* U+1C500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C50F */
/* U+1C510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C51F */
/* U+1C520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C52F */
/* U+1C530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C53F */
/* U+1C540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C54F */
/* U+1C550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C55F */
/* U+1C560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C56F */
/* U+1C570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C57F */
/* U+1C580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C58F */
/* U+1C590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C59F */
/* U+1C5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5AF */
/* U+1C5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5BF */
/* U+1C5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5CF */
/* U+1C5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5DF */
/* U+1C5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5EF */
/* U+1C5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C5FF */
/* U+1C600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C60F */
/* U+1C610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C61F */
/* U+1C620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C62F */
/* U+1C630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C63F */
/* U+1C640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C64F */
/* U+1C650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C65F */
/* U+1C660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C66F */
/* U+1C670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C67F */
/* U+1C680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C68F */
/* U+1C690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C69F */
/* U+1C6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6AF */
/* U+1C6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6BF */
/* U+1C6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6CF */
/* U+1C6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6DF */
/* U+1C6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6EF */
/* U+1C6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C6FF */
/* U+1C700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C70F */
/* U+1C710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C71F */
/* U+1C720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C72F */
/* U+1C730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C73F */
/* U+1C740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C74F */
/* U+1C750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C75F */
/* U+1C760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C76F */
/* U+1C770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C77F */
/* U+1C780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C78F */
/* U+1C790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C79F */
/* U+1C7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7AF */
/* U+1C7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7BF */
/* U+1C7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7CF */
/* U+1C7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7DF */
/* U+1C7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7EF */
/* U+1C7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C7FF */
/* U+1C800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C80F */
/* U+1C810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C81F */
/* U+1C820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C82F */
/* U+1C830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C83F */
/* U+1C840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C84F */
/* U+1C850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C85F */
/* U+1C860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C86F */
/* U+1C870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C87F */
/* U+1C880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C88F */
/* U+1C890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C89F */
/* U+1C8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8AF */
/* U+1C8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8BF */
/* U+1C8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8CF */
/* U+1C8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8DF */
/* U+1C8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8EF */
/* U+1C8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C8FF */
/* U+1C900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C90F */
/* U+1C910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C91F */
/* U+1C920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C92F */
/* U+1C930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C93F */
/* U+1C940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C94F */
/* U+1C950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C95F */
/* U+1C960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C96F */
/* U+1C970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C97F */
/* U+1C980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C98F */
/* U+1C990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C99F */
/* U+1C9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9AF */
/* U+1C9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9BF */
/* U+1C9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9CF */
/* U+1C9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9DF */
/* U+1C9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9EF */
/* U+1C9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1C9FF */
/* U+1CA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA0F */
/* U+1CA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA1F */
/* U+1CA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA2F */
/* U+1CA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA3F */
/* U+1CA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA4F */
/* U+1CA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA5F */
/* U+1CA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA6F */
/* U+1CA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA7F */
/* U+1CA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA8F */
/* U+1CA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CA9F */
/* U+1CAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CAAF */
/* U+1CAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CABF */
/* U+1CAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CACF */
/* U+1CAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CADF */
/* U+1CAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CAEF */
/* U+1CAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CAFF */
/* U+1CB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB0F */
/* U+1CB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB1F */
/* U+1CB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB2F */
/* U+1CB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB3F */
/* U+1CB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB4F */
/* U+1CB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB5F */
/* U+1CB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB6F */
/* U+1CB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB7F */
/* U+1CB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB8F */
/* U+1CB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CB9F */
/* U+1CBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBAF */
/* U+1CBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBBF */
/* U+1CBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBCF */
/* U+1CBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBDF */
/* U+1CBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBEF */
/* U+1CBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CBFF */
/* U+1CC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC0F */
/* U+1CC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC1F */
/* U+1CC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC2F */
/* U+1CC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC3F */
/* U+1CC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC4F */
/* U+1CC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC5F */
/* U+1CC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC6F */
/* U+1CC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC7F */
/* U+1CC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC8F */
/* U+1CC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CC9F */
/* U+1CCA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCAF */
/* U+1CCB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCBF */
/* U+1CCC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCCF */
/* U+1CCD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCDF */
/* U+1CCE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCEF */
/* U+1CCF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CCFF */
/* U+1CD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD0F */
/* U+1CD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD1F */
/* U+1CD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD2F */
/* U+1CD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD3F */
/* U+1CD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD4F */
/* U+1CD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD5F */
/* U+1CD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD6F */
/* U+1CD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD7F */
/* U+1CD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD8F */
/* U+1CD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CD9F */
/* U+1CDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDAF */
/* U+1CDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDBF */
/* U+1CDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDCF */
/* U+1CDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDDF */
/* U+1CDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDEF */
/* U+1CDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CDFF */
/* U+1CE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE0F */
/* U+1CE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE1F */
/* U+1CE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE2F */
/* U+1CE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE3F */
/* U+1CE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE4F */
/* U+1CE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE5F */
/* U+1CE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE6F */
/* U+1CE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE7F */
/* U+1CE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE8F */
/* U+1CE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CE9F */
/* U+1CEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CEAF */
/* U+1CEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CEBF */
/* U+1CEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CECF */
/* U+1CED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CEDF */
/* U+1CEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CEEF */
/* U+1CEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CEFF */
/* U+1CF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF0F */
/* U+1CF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF1F */
/* U+1CF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF2F */
/* U+1CF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF3F */
/* U+1CF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF4F */
/* U+1CF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF5F */
/* U+1CF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF6F */
/* U+1CF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF7F */
/* U+1CF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF8F */
/* U+1CF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CF9F */
/* U+1CFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFAF */
/* U+1CFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFBF */
/* U+1CFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFCF */
/* U+1CFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFDF */
/* U+1CFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFEF */
/* U+1CFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1CFFF */
/* U+1D000 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D00F */
/* U+1D010 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D01F */
/* U+1D020 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D02F */
/* U+1D030 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D03F */
/* U+1D040 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D04F */
/* U+1D050 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D05F */
/* U+1D060 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D06F */
/* U+1D070 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D07F */
/* U+1D080 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D08F */
/* U+1D090 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D09F */
/* U+1D0A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D0AF */
/* U+1D0B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D0BF */
/* U+1D0C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D0CF */
/* U+1D0D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D0DF */
/* U+1D0E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D0EF */
/* U+1D0F0 */	1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D0FF */
/* U+1D100 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D10F */
/* U+1D110 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D11F */
/* U+1D120 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,1, 1, 1, 1, 1, 1,   /* U+1D12F */
/* U+1D130 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D13F */
/* U+1D140 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D14F */
/* U+1D150 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D15F */
/* U+1D160 */	1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0,   /* U+1D16F */
/* U+1D170 */	0, 0, 0, IL,IL,IL,IL,IL,IL,IL,IL,0, 0, 0, 0, 0,   /* U+1D17F */
/* U+1D180 */	0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,   /* U+1D18F */
/* U+1D190 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D19F */
/* U+1D1A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,   /* U+1D1AF */
/* U+1D1B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D1BF */
/* U+1D1C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D1CF */
/* U+1D1D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,  /* U+1D1DF */
/* U+1D1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D1EF */
/* U+1D1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D1FF */
/* U+1D200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D20F */
/* U+1D210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D21F */
/* U+1D220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D22F */
/* U+1D230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D23F */
/* U+1D240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D24F */
/* U+1D250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D25F */
/* U+1D260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D26F */
/* U+1D270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D27F */
/* U+1D280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D28F */
/* U+1D290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D29F */
/* U+1D2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2AF */
/* U+1D2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2BF */
/* U+1D2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2CF */
/* U+1D2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2DF */
/* U+1D2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2EF */
/* U+1D2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D2FF */
/* U+1D300 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D30F */
/* U+1D310 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D31F */
/* U+1D320 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D32F */
/* U+1D330 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D33F */
/* U+1D340 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D34F */
/* U+1D350 */	1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D35F */
/* U+1D360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D36F */
/* U+1D370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D37F */
/* U+1D380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D38F */
/* U+1D390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D39F */
/* U+1D3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3AF */
/* U+1D3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3BF */
/* U+1D3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3CF */
/* U+1D3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3DF */
/* U+1D3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3EF */
/* U+1D3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D3FF */
/* U+1D400 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D40F */
/* U+1D410 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D41F */
/* U+1D420 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D42F */
/* U+1D430 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D43F */
/* U+1D440 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D44F */
/* U+1D450 */	1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D45F */
/* U+1D460 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D46F */
/* U+1D470 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D47F */
/* U+1D480 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D48F */
/* U+1D490 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1,   /* U+1D49F */
/* U+1D4A0 */	IL,IL,1, IL,IL,1, 1, IL,IL,1, 1, 1, 1, IL,1, 1,   /* U+1D4AF */
/* U+1D4B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, IL,1, 1, 1,   /* U+1D4BF */
/* U+1D4C0 */	1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D4CF */
/* U+1D4D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D4DF */
/* U+1D4E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D4EF */
/* U+1D4F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D4FF */
/* U+1D500 */	1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, IL,IL,1, 1, 1,   /* U+1D50F */
/* U+1D510 */	1, 1, 1, 1, 1, IL,1, 1, 1, 1, 1, 1, 1, IL,1, 1,   /* U+1D51F */
/* U+1D520 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D52F */
/* U+1D530 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,1, 1, 1, 1, IL,  /* U+1D53F */
/* U+1D540 */	1, 1, 1, 1, 1, IL,1, IL,IL,IL,1, 1, 1, 1, 1, 1,   /* U+1D54F */
/* U+1D550 */	1, IL,1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D55F */
/* U+1D560 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D56F */
/* U+1D570 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D57F */
/* U+1D580 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D58F */
/* U+1D590 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D59F */
/* U+1D5A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5AF */
/* U+1D5B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5BF */
/* U+1D5C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5CF */
/* U+1D5D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5DF */
/* U+1D5E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5EF */
/* U+1D5F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D5FF */
/* U+1D600 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D60F */
/* U+1D610 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D61F */
/* U+1D620 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D62F */
/* U+1D630 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D63F */
/* U+1D640 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D64F */
/* U+1D650 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D65F */
/* U+1D660 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D66F */
/* U+1D670 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D67F */
/* U+1D680 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D68F */
/* U+1D690 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D69F */
/* U+1D6A0 */	1, 1, 1, 1, IL,IL,IL,IL,1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6AF */
/* U+1D6B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6BF */
/* U+1D6C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6CF */
/* U+1D6D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6DF */
/* U+1D6E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6EF */
/* U+1D6F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D6FF */
/* U+1D700 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D70F */
/* U+1D710 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D71F */
/* U+1D720 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D72F */
/* U+1D730 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D73F */
/* U+1D740 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D74F */
/* U+1D750 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D75F */
/* U+1D760 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D76F */
/* U+1D770 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D77F */
/* U+1D780 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D78F */
/* U+1D790 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D79F */
/* U+1D7A0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D7AF */
/* U+1D7B0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D7BF */
/* U+1D7C0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, IL,IL,IL,IL,1, 1,   /* U+1D7CF */
/* U+1D7D0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D7DF */
/* U+1D7E0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D7EF */
/* U+1D7F0 */	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,   /* U+1D7FF */
/* U+1D800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D80F */
/* U+1D810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D81F */
/* U+1D820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D82F */
/* U+1D830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D83F */
/* U+1D840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D84F */
/* U+1D850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D85F */
/* U+1D860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D86F */
/* U+1D870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D87F */
/* U+1D880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D88F */
/* U+1D890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D89F */
/* U+1D8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8AF */
/* U+1D8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8BF */
/* U+1D8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8CF */
/* U+1D8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8DF */
/* U+1D8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8EF */
/* U+1D8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D8FF */
/* U+1D900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D90F */
/* U+1D910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D91F */
/* U+1D920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D92F */
/* U+1D930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D93F */
/* U+1D940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D94F */
/* U+1D950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D95F */
/* U+1D960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D96F */
/* U+1D970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D97F */
/* U+1D980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D98F */
/* U+1D990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D99F */
/* U+1D9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9AF */
/* U+1D9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9BF */
/* U+1D9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9CF */
/* U+1D9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9DF */
/* U+1D9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9EF */
/* U+1D9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1D9FF */
/* U+1DA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA0F */
/* U+1DA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA1F */
/* U+1DA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA2F */
/* U+1DA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA3F */
/* U+1DA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA4F */
/* U+1DA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA5F */
/* U+1DA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA6F */
/* U+1DA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA7F */
/* U+1DA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA8F */
/* U+1DA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DA9F */
/* U+1DAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DAAF */
/* U+1DAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DABF */
/* U+1DAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DACF */
/* U+1DAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DADF */
/* U+1DAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DAEF */
/* U+1DAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DAFF */
/* U+1DB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB0F */
/* U+1DB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB1F */
/* U+1DB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB2F */
/* U+1DB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB3F */
/* U+1DB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB4F */
/* U+1DB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB5F */
/* U+1DB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB6F */
/* U+1DB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB7F */
/* U+1DB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB8F */
/* U+1DB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DB9F */
/* U+1DBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBAF */
/* U+1DBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBBF */
/* U+1DBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBCF */
/* U+1DBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBDF */
/* U+1DBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBEF */
/* U+1DBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DBFF */
/* U+1DC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC0F */
/* U+1DC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC1F */
/* U+1DC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC2F */
/* U+1DC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC3F */
/* U+1DC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC4F */
/* U+1DC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC5F */
/* U+1DC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC6F */
/* U+1DC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC7F */
/* U+1DC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC8F */
/* U+1DC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DC9F */
/* U+1DCA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCAF */
/* U+1DCB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCBF */
/* U+1DCC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCCF */
/* U+1DCD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCDF */
/* U+1DCE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCEF */
/* U+1DCF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DCFF */
/* U+1DD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD0F */
/* U+1DD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD1F */
/* U+1DD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD2F */
/* U+1DD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD3F */
/* U+1DD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD4F */
/* U+1DD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD5F */
/* U+1DD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD6F */
/* U+1DD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD7F */
/* U+1DD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD8F */
/* U+1DD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DD9F */
/* U+1DDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDAF */
/* U+1DDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDBF */
/* U+1DDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDCF */
/* U+1DDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDDF */
/* U+1DDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDEF */
/* U+1DDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DDFF */
/* U+1DE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE0F */
/* U+1DE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE1F */
/* U+1DE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE2F */
/* U+1DE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE3F */
/* U+1DE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE4F */
/* U+1DE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE5F */
/* U+1DE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE6F */
/* U+1DE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE7F */
/* U+1DE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE8F */
/* U+1DE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DE9F */
/* U+1DEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DEAF */
/* U+1DEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DEBF */
/* U+1DEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DECF */
/* U+1DED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DEDF */
/* U+1DEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DEEF */
/* U+1DEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DEFF */
/* U+1DF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF0F */
/* U+1DF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF1F */
/* U+1DF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF2F */
/* U+1DF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF3F */
/* U+1DF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF4F */
/* U+1DF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF5F */
/* U+1DF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF6F */
/* U+1DF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF7F */
/* U+1DF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF8F */
/* U+1DF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DF9F */
/* U+1DFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFAF */
/* U+1DFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFBF */
/* U+1DFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFCF */
/* U+1DFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFDF */
/* U+1DFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFEF */
/* U+1DFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1DFFF */
/* U+1E000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E00F */
/* U+1E010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E01F */
/* U+1E020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E02F */
/* U+1E030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E03F */
/* U+1E040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E04F */
/* U+1E050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E05F */
/* U+1E060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E06F */
/* U+1E070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E07F */
/* U+1E080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E08F */
/* U+1E090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E09F */
/* U+1E0A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0AF */
/* U+1E0B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0BF */
/* U+1E0C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0CF */
/* U+1E0D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0DF */
/* U+1E0E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0EF */
/* U+1E0F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E0FF */
/* U+1E100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E10F */
/* U+1E110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E11F */
/* U+1E120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E12F */
/* U+1E130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E13F */
/* U+1E140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E14F */
/* U+1E150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E15F */
/* U+1E160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E16F */
/* U+1E170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E17F */
/* U+1E180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E18F */
/* U+1E190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E19F */
/* U+1E1A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1AF */
/* U+1E1B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1BF */
/* U+1E1C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1CF */
/* U+1E1D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1DF */
/* U+1E1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1EF */
/* U+1E1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E1FF */
/* U+1E200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E20F */
/* U+1E210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E21F */
/* U+1E220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E22F */
/* U+1E230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E23F */
/* U+1E240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E24F */
/* U+1E250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E25F */
/* U+1E260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E26F */
/* U+1E270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E27F */
/* U+1E280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E28F */
/* U+1E290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E29F */
/* U+1E2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2AF */
/* U+1E2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2BF */
/* U+1E2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2CF */
/* U+1E2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2DF */
/* U+1E2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2EF */
/* U+1E2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E2FF */
/* U+1E300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E30F */
/* U+1E310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E31F */
/* U+1E320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E32F */
/* U+1E330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E33F */
/* U+1E340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E34F */
/* U+1E350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E35F */
/* U+1E360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E36F */
/* U+1E370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E37F */
/* U+1E380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E38F */
/* U+1E390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E39F */
/* U+1E3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3AF */
/* U+1E3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3BF */
/* U+1E3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3CF */
/* U+1E3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3DF */
/* U+1E3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3EF */
/* U+1E3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E3FF */
/* U+1E400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E40F */
/* U+1E410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E41F */
/* U+1E420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E42F */
/* U+1E430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E43F */
/* U+1E440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E44F */
/* U+1E450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E45F */
/* U+1E460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E46F */
/* U+1E470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E47F */
/* U+1E480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E48F */
/* U+1E490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E49F */
/* U+1E4A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4AF */
/* U+1E4B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4BF */
/* U+1E4C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4CF */
/* U+1E4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4DF */
/* U+1E4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4EF */
/* U+1E4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E4FF */
/* U+1E500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E50F */
/* U+1E510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E51F */
/* U+1E520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E52F */
/* U+1E530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E53F */
/* U+1E540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E54F */
/* U+1E550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E55F */
/* U+1E560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E56F */
/* U+1E570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E57F */
/* U+1E580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E58F */
/* U+1E590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E59F */
/* U+1E5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5AF */
/* U+1E5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5BF */
/* U+1E5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5CF */
/* U+1E5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5DF */
/* U+1E5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5EF */
/* U+1E5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E5FF */
/* U+1E600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E60F */
/* U+1E610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E61F */
/* U+1E620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E62F */
/* U+1E630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E63F */
/* U+1E640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E64F */
/* U+1E650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E65F */
/* U+1E660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E66F */
/* U+1E670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E67F */
/* U+1E680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E68F */
/* U+1E690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E69F */
/* U+1E6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6AF */
/* U+1E6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6BF */
/* U+1E6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6CF */
/* U+1E6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6DF */
/* U+1E6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6EF */
/* U+1E6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E6FF */
/* U+1E700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E70F */
/* U+1E710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E71F */
/* U+1E720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E72F */
/* U+1E730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E73F */
/* U+1E740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E74F */
/* U+1E750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E75F */
/* U+1E760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E76F */
/* U+1E770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E77F */
/* U+1E780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E78F */
/* U+1E790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E79F */
/* U+1E7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7AF */
/* U+1E7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7BF */
/* U+1E7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7CF */
/* U+1E7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7DF */
/* U+1E7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7EF */
/* U+1E7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E7FF */
/* U+1E800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E80F */
/* U+1E810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E81F */
/* U+1E820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E82F */
/* U+1E830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E83F */
/* U+1E840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E84F */
/* U+1E850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E85F */
/* U+1E860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E86F */
/* U+1E870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E87F */
/* U+1E880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E88F */
/* U+1E890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E89F */
/* U+1E8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8AF */
/* U+1E8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8BF */
/* U+1E8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8CF */
/* U+1E8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8DF */
/* U+1E8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8EF */
/* U+1E8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E8FF */
/* U+1E900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E90F */
/* U+1E910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E91F */
/* U+1E920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E92F */
/* U+1E930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E93F */
/* U+1E940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E94F */
/* U+1E950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E95F */
/* U+1E960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E96F */
/* U+1E970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E97F */
/* U+1E980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E98F */
/* U+1E990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E99F */
/* U+1E9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9AF */
/* U+1E9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9BF */
/* U+1E9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9CF */
/* U+1E9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9DF */
/* U+1E9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9EF */
/* U+1E9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1E9FF */
/* U+1EA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA0F */
/* U+1EA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA1F */
/* U+1EA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA2F */
/* U+1EA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA3F */
/* U+1EA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA4F */
/* U+1EA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA5F */
/* U+1EA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA6F */
/* U+1EA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA7F */
/* U+1EA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA8F */
/* U+1EA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EA9F */
/* U+1EAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EAAF */
/* U+1EAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EABF */
/* U+1EAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EACF */
/* U+1EAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EADF */
/* U+1EAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EAEF */
/* U+1EAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EAFF */
/* U+1EB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB0F */
/* U+1EB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB1F */
/* U+1EB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB2F */
/* U+1EB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB3F */
/* U+1EB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB4F */
/* U+1EB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB5F */
/* U+1EB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB6F */
/* U+1EB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB7F */
/* U+1EB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB8F */
/* U+1EB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EB9F */
/* U+1EBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBAF */
/* U+1EBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBBF */
/* U+1EBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBCF */
/* U+1EBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBDF */
/* U+1EBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBEF */
/* U+1EBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EBFF */
/* U+1EC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC0F */
/* U+1EC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC1F */
/* U+1EC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC2F */
/* U+1EC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC3F */
/* U+1EC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC4F */
/* U+1EC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC5F */
/* U+1EC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC6F */
/* U+1EC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC7F */
/* U+1EC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC8F */
/* U+1EC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EC9F */
/* U+1ECA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECAF */
/* U+1ECB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECBF */
/* U+1ECC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECCF */
/* U+1ECD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECDF */
/* U+1ECE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECEF */
/* U+1ECF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ECFF */
/* U+1ED00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED0F */
/* U+1ED10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED1F */
/* U+1ED20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED2F */
/* U+1ED30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED3F */
/* U+1ED40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED4F */
/* U+1ED50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED5F */
/* U+1ED60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED6F */
/* U+1ED70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED7F */
/* U+1ED80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED8F */
/* U+1ED90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1ED9F */
/* U+1EDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDAF */
/* U+1EDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDBF */
/* U+1EDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDCF */
/* U+1EDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDDF */
/* U+1EDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDEF */
/* U+1EDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EDFF */
/* U+1EE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE0F */
/* U+1EE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE1F */
/* U+1EE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE2F */
/* U+1EE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE3F */
/* U+1EE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE4F */
/* U+1EE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE5F */
/* U+1EE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE6F */
/* U+1EE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE7F */
/* U+1EE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE8F */
/* U+1EE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EE9F */
/* U+1EEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EEAF */
/* U+1EEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EEBF */
/* U+1EEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EECF */
/* U+1EED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EEDF */
/* U+1EEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EEEF */
/* U+1EEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EEFF */
/* U+1EF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF0F */
/* U+1EF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF1F */
/* U+1EF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF2F */
/* U+1EF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF3F */
/* U+1EF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF4F */
/* U+1EF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF5F */
/* U+1EF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF6F */
/* U+1EF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF7F */
/* U+1EF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF8F */
/* U+1EF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EF9F */
/* U+1EFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFAF */
/* U+1EFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFBF */
/* U+1EFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFCF */
/* U+1EFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFDF */
/* U+1EFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFEF */
/* U+1EFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1EFFF */
/* U+1F000 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F00F */
/* U+1F010 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F01F */
/* U+1F020 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F02F */
/* U+1F030 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F03F */
/* U+1F040 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F04F */
/* U+1F050 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F05F */
/* U+1F060 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F06F */
/* U+1F070 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F07F */
/* U+1F080 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F08F */
/* U+1F090 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F09F */
/* U+1F0A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0AF */
/* U+1F0B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0BF */
/* U+1F0C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0CF */
/* U+1F0D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0DF */
/* U+1F0E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0EF */
/* U+1F0F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F0FF */
/* U+1F100 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F10F */
/* U+1F110 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F11F */
/* U+1F120 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F12F */
/* U+1F130 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F13F */
/* U+1F140 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F14F */
/* U+1F150 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F15F */
/* U+1F160 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F16F */
/* U+1F170 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F17F */
/* U+1F180 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F18F */
/* U+1F190 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F19F */
/* U+1F1A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1AF */
/* U+1F1B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1BF */
/* U+1F1C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1CF */
/* U+1F1D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1DF */
/* U+1F1E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1EF */
/* U+1F1F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F1FF */
/* U+1F200 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F20F */
/* U+1F210 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F21F */
/* U+1F220 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F22F */
/* U+1F230 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F23F */
/* U+1F240 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F24F */
/* U+1F250 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F25F */
/* U+1F260 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F26F */
/* U+1F270 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F27F */
/* U+1F280 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F28F */
/* U+1F290 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F29F */
/* U+1F2A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2AF */
/* U+1F2B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2BF */
/* U+1F2C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2CF */
/* U+1F2D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2DF */
/* U+1F2E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2EF */
/* U+1F2F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F2FF */
/* U+1F300 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F30F */
/* U+1F310 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F31F */
/* U+1F320 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F32F */
/* U+1F330 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F33F */
/* U+1F340 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F34F */
/* U+1F350 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F35F */
/* U+1F360 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F36F */
/* U+1F370 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F37F */
/* U+1F380 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F38F */
/* U+1F390 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F39F */
/* U+1F3A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3AF */
/* U+1F3B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3BF */
/* U+1F3C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3CF */
/* U+1F3D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3DF */
/* U+1F3E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3EF */
/* U+1F3F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F3FF */
/* U+1F400 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F40F */
/* U+1F410 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F41F */
/* U+1F420 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F42F */
/* U+1F430 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F43F */
/* U+1F440 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F44F */
/* U+1F450 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F45F */
/* U+1F460 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F46F */
/* U+1F470 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F47F */
/* U+1F480 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F48F */
/* U+1F490 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F49F */
/* U+1F4A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4AF */
/* U+1F4B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4BF */
/* U+1F4C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4CF */
/* U+1F4D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4DF */
/* U+1F4E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4EF */
/* U+1F4F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F4FF */
/* U+1F500 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F50F */
/* U+1F510 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F51F */
/* U+1F520 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F52F */
/* U+1F530 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F53F */
/* U+1F540 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F54F */
/* U+1F550 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F55F */
/* U+1F560 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F56F */
/* U+1F570 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F57F */
/* U+1F580 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F58F */
/* U+1F590 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F59F */
/* U+1F5A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5AF */
/* U+1F5B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5BF */
/* U+1F5C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5CF */
/* U+1F5D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5DF */
/* U+1F5E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5EF */
/* U+1F5F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F5FF */
/* U+1F600 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F60F */
/* U+1F610 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F61F */
/* U+1F620 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F62F */
/* U+1F630 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F63F */
/* U+1F640 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F64F */
/* U+1F650 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F65F */
/* U+1F660 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F66F */
/* U+1F670 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F67F */
/* U+1F680 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F68F */
/* U+1F690 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F69F */
/* U+1F6A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6AF */
/* U+1F6B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6BF */
/* U+1F6C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6CF */
/* U+1F6D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6DF */
/* U+1F6E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6EF */
/* U+1F6F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F6FF */
/* U+1F700 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F70F */
/* U+1F710 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F71F */
/* U+1F720 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F72F */
/* U+1F730 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F73F */
/* U+1F740 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F74F */
/* U+1F750 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F75F */
/* U+1F760 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F76F */
/* U+1F770 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F77F */
/* U+1F780 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F78F */
/* U+1F790 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F79F */
/* U+1F7A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7AF */
/* U+1F7B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7BF */
/* U+1F7C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7CF */
/* U+1F7D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7DF */
/* U+1F7E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7EF */
/* U+1F7F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F7FF */
/* U+1F800 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F80F */
/* U+1F810 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F81F */
/* U+1F820 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F82F */
/* U+1F830 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F83F */
/* U+1F840 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F84F */
/* U+1F850 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F85F */
/* U+1F860 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F86F */
/* U+1F870 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F87F */
/* U+1F880 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F88F */
/* U+1F890 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F89F */
/* U+1F8A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8AF */
/* U+1F8B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8BF */
/* U+1F8C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8CF */
/* U+1F8D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8DF */
/* U+1F8E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8EF */
/* U+1F8F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F8FF */
/* U+1F900 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F90F */
/* U+1F910 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F91F */
/* U+1F920 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F92F */
/* U+1F930 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F93F */
/* U+1F940 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F94F */
/* U+1F950 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F95F */
/* U+1F960 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F96F */
/* U+1F970 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F97F */
/* U+1F980 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F98F */
/* U+1F990 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F99F */
/* U+1F9A0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9AF */
/* U+1F9B0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9BF */
/* U+1F9C0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9CF */
/* U+1F9D0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9DF */
/* U+1F9E0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9EF */
/* U+1F9F0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1F9FF */
/* U+1FA00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA0F */
/* U+1FA10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA1F */
/* U+1FA20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA2F */
/* U+1FA30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA3F */
/* U+1FA40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA4F */
/* U+1FA50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA5F */
/* U+1FA60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA6F */
/* U+1FA70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA7F */
/* U+1FA80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA8F */
/* U+1FA90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FA9F */
/* U+1FAA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FAAF */
/* U+1FAB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FABF */
/* U+1FAC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FACF */
/* U+1FAD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FADF */
/* U+1FAE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FAEF */
/* U+1FAF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FAFF */
/* U+1FB00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB0F */
/* U+1FB10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB1F */
/* U+1FB20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB2F */
/* U+1FB30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB3F */
/* U+1FB40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB4F */
/* U+1FB50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB5F */
/* U+1FB60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB6F */
/* U+1FB70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB7F */
/* U+1FB80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB8F */
/* U+1FB90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FB9F */
/* U+1FBA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBAF */
/* U+1FBB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBBF */
/* U+1FBC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBCF */
/* U+1FBD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBDF */
/* U+1FBE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBEF */
/* U+1FBF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FBFF */
/* U+1FC00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC0F */
/* U+1FC10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC1F */
/* U+1FC20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC2F */
/* U+1FC30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC3F */
/* U+1FC40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC4F */
/* U+1FC50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC5F */
/* U+1FC60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC6F */
/* U+1FC70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC7F */
/* U+1FC80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC8F */
/* U+1FC90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FC9F */
/* U+1FCA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCAF */
/* U+1FCB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCBF */
/* U+1FCC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCCF */
/* U+1FCD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCDF */
/* U+1FCE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCEF */
/* U+1FCF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FCFF */
/* U+1FD00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD0F */
/* U+1FD10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD1F */
/* U+1FD20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD2F */
/* U+1FD30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD3F */
/* U+1FD40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD4F */
/* U+1FD50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD5F */
/* U+1FD60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD6F */
/* U+1FD70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD7F */
/* U+1FD80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD8F */
/* U+1FD90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FD9F */
/* U+1FDA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDAF */
/* U+1FDB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDBF */
/* U+1FDC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDCF */
/* U+1FDD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDDF */
/* U+1FDE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDEF */
/* U+1FDF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FDFF */
/* U+1FE00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE0F */
/* U+1FE10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE1F */
/* U+1FE20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE2F */
/* U+1FE30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE3F */
/* U+1FE40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE4F */
/* U+1FE50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE5F */
/* U+1FE60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE6F */
/* U+1FE70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE7F */
/* U+1FE80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE8F */
/* U+1FE90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FE9F */
/* U+1FEA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FEAF */
/* U+1FEB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FEBF */
/* U+1FEC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FECF */
/* U+1FED0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FEDF */
/* U+1FEE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FEEF */
/* U+1FEF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FEFF */
/* U+1FF00 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF0F */
/* U+1FF10 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF1F */
/* U+1FF20 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF2F */
/* U+1FF30 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF3F */
/* U+1FF40 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF4F */
/* U+1FF50 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF5F */
/* U+1FF60 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF6F */
/* U+1FF70 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF7F */
/* U+1FF80 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF8F */
/* U+1FF90 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FF9F */
/* U+1FFA0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FFAF */
/* U+1FFB0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FFBF */
/* U+1FFC0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FFCF */
/* U+1FFD0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FFDF */
/* U+1FFE0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,  /* U+1FFEF */
/* U+1FFF0 */	IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL,IL   /* U+1FFFF */
	}
};
/* END CSTYLED */
