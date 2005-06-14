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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GNU_PRIME_H
#define	_GNU_PRIME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

static const unsigned int	prime[] = {
	2,	3,	5,	7,	11,	/* 0 - 4 */
	13,	17,	19,	23,	29,	/* 5 - 9 */
	31,	37,	41,	43,	47,	/* 10 - 14 */
	53,	59,	61,	67,	71,	/* 15 - 19 */
	73,	79,	83,	89,	97,	/* 20 - 24 */
	101,	103,	107,	109,	113,	/* 25 - 29 */
	127,	131,	137,	139,	149,	/* 30 - 34 */
	151,	157,	163,	167,	173,	/* 35 - 39 */
	179,	181,	191,	193,	197,	/* 40 - 44 */
	199,	211,	223,	227,	229,	/* 45 - 49 */
	233,	239,	241,	251,	257,	/* 50 - 54 */
	263,	269,	271,	277,	281,	/* 55 - 59 */
	283,	293,	307,	311,	313,	/* 60 - 64 */
	317,	331,	337,	347,	349,	/* 65 - 69 */
	353,	359,	367,	373,	379,	/* 70 - 74 */
	383,	389,	397,	401,	409,	/* 75 - 79 */
	419,	421,	431,	433,	439,	/* 80 - 84 */
	443,	449,	457,	461,	463,	/* 85 - 89 */
	467,	479,	487,	491,	499,	/* 90 - 94 */
	503,	509,	521,	523,	541,	/* 95 - 99 */
	547,	557,	563,	569,	571,	/* 100 - 104 */
	577,	587,	593,	599,	601,	/* 105 - 109 */
	607,	613,	617,	619,	631,	/* 110 - 114 */
	641,	643,	647,	653,	659,	/* 115 - 119 */
	661,	673,	677,	683,	691,	/* 120 - 124 */
	701,	709,	719,	727,	733,	/* 125 - 129 */
	739,	743,	751,	757,	761,	/* 130 - 134 */
	769,	773,	787,	797,	809,	/* 135 - 139 */
	811,	821,	823,	827,	829,	/* 140 - 144 */
	839,	853,	857,	859,	863,	/* 145 - 149 */
	877,	881,	883,	887,	907,	/* 150 - 154 */
	911,	919,	929,	937,	941,	/* 155 - 159 */
	947,	953,	967,	971,	977,	/* 160 - 164 */
	983,	991,	997,	1009,	1013,	/* 165 - 169 */
	1019,	1021,	1031,	1033,	1039,	/* 170 - 174 */
	1049,	1051,	1061,	1063,	1069,	/* 175 - 179 */
	1087,	1091,	1093,	1097,	1103	/* 180 - 184 */
};

static const int	index[] = {
	1,	/*    0:   3 */
	24,	/*  100:  97 */
	45,	/*  200: 199 */
	61,	/*  300: 293 */
	77,	/*  400: 397 */
	94,	/*  500: 499 */
	108,	/*  600: 599 */
	124,	/*  700: 691 */
	138,	/*  800: 797 */
	153,	/*  900: 887 */
	167	/* 1000: 997 */
};

#define	MAX_INDEX_INDEX	10
#define	MAX_PRIME_INDEX	184
#define	START_SEARCH_INDEX	10	/* 31:  31 * 31 = 961 */

#ifdef	__cplusplus
}
#endif

#endif /* _GNU_PRIME_H */
