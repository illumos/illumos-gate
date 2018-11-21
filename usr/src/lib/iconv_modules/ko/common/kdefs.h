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

#define GI_UG		0x41	/* gi-ug 		'A' */
#define D_GI_UG		0x42	/* double gi-ug		'B' */
#define NI_UN		0x44	/* ni-un		'D' */
#define DI_GUD		0x47	/* di-gud		'G' */
#define D_DI_GUD	0x48	/* double di-gud	'H' */
#define RI_UL		0x49	/* ri-ul		'I' */
#define MI_UM		0x51	/* mi-um		'Q' */
#define BI_UB		0x52	/* bi-ub		'R' */
#define D_BI_UB		0x53	/* double bi-ub		'S' */
#define SI_OD		0x55	/* si-od		'U' */
#define D_SI_OD		0x56	/* double si-od		'V' */
#define YI_UNG		0x57	/* yi-ung		'W' */
#define JI_UD		0x58	/* ji-ud		'X' */
#define D_JI_UD		0x59	/* double ji-ud		'Y' */
#define CHI_UD		0x5a	/* chi-ud		'Z' */
#define KI_UK		0x5b	/* ki-uk		'[' */
#define TI_GUT		0x5c	/* ti-gut		'\' */
#define PI_UP		0x5d	/* pi-up		']' */
#define HI_UD		0x5e	/* hi-ud		'^' */
#define A		0x62	/* a			'b' */
#define AE		0x63	/* ae			'c' */
#define IA		0x64	/* ia			'd' */
#define IYAI		0x65	/* iyai			'e' */
#define E		0x66	/* e			'f' */
#define EA		0x67	/* ea			'g' */
#define IE		0x6a	/* ie			'j' */
#define YEA		0x6b	/* yea			'k' */
#define O		0x6c	/* o			'l' */
#define YO		0x72	/* yo			'r' */
#define U		0x73	/* u			's' */
#define YU		0x77	/* yu			'g' */
#define EU		0x7a	/* eu			'z' */
#define I		0x7c	/* i			'|' */

#define	GIUG_SIOD	0x43 	/* gi-ug and si-od	'C' */
#define	NIUN_JIUD	0x45 	/* ni-un and ji-ud	'E' */
#define	NIUN_HIUD	0x46 	/* ni-un and hi-ud	'F' */
#define	RIUL_GIUG	0x4a 	/* ri_ul and gi_ug	'J' */
#define	RIUL_MIUM	0x4b 	/* ri_ul and mi_um	'K' */
#define	RIUL_BIUB	0x4c 	/* ri_ul and bi_ub	'L' */
#define	RIUL_SIOD	0x4d 	/* ri_ul and si_od	'M' */
#define	RIUL_TIGUT	0x4e 	/* ri_ul and ti_gut	'N' */
#define	RIUL_PIUP	0x4f 	/* ri_ul and pi_up	'O' */
#define	RIUL_HIUD	0x50 	/* ri_ul and hi_ud	'P' */
#define	BIUB_SIOD	0x54 	/* bi_ub and si_od	'T' */

#define	O_A		0x6d 	/* o and a		'm' */
#define	O_AE		0x6e 	/* o and ae		'n' */
#define	O_I		0x6f 	/* o and i		'o' */
#define	U_E		0x74 	/* u and e		't' */
#define	U_EA		0x75 	/* u and ea		'u' */
#define	U_I		0x76 	/* u and i		'v' */
#define	EU_I		0x7b 	/* eu and i		'{' */

#define ishaninit(c)	(c>=0xa4a1&&c<=0xa4be)	/* S000 */
#define ishanmid(c)	(c>=0xa4bf&&c<=0xa4d3)

#define INITIAL_SOUND(c)	((KCHAR)(c & 0x7c00) >> 10)
#define MIDDLE_SOUND(c)		((KCHAR)(c & 0x03e0) >> 5)
#define FINAL_SOUND(c)		(c & 0x001f)

#define BEG_OF_CONSO		0x40	/* S000 */
#define BEG_OF_VOW		0x60

#define BYTE_MASK		0xff
#define	BIT_MASK		0x01
#define	MSB_MASK		0x8000
#define K_ILLEGAL			0xffff

typedef unsigned short          KCHAR;
