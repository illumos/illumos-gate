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



#ifndef	_KTABLE_H_
#define	_KTABLE_H_


#include <widec.h>

/*  7 bit Sound ---> 5 bit Combination Code		*/
/*	: give 5 bit combination code to each sound	*/

extern short X32_19[];	/* INITIAL SOUND	*/
extern short X32_21[];	/* MIDDLE SOUND		*/
extern short X32_28[];	/* FINAL SOUND		*/


/*  5 bit Combination Code ---> 7 bit code 	*/
/*	: give 7 bit Code to each Sound		*/

extern short Y19_32[];	/* INITIAL SOUND	*/
extern short Y21_32[];	/* MIDDLE SOUND		*/
extern short Y28_32[];	/* FINAL SOUND		*/


/*
 * Bit map of all possible Hangul Character compositions.
 * 	first  sound = 19 consonants;
 *	middle sound = 21 vowels;
 *	final  sound = 28 consonants;
 * For each array element of first_sound and middle_sound, there is bit map
 * of 28 final_sound in 32bits according to ***KSC 5601***.
 */
extern long cmp_bitmap[19][21];

/*
 * Each cmp_srctbl[i][j] has 2-byte compeletion code
 * where i is initial_sound and j is middle_sound.
 * So, cmp_srctbl[i][0] is the code for some initial_sound and
 * the first of middle_sound(always 'a').
 */
extern unsigned short cmp_srchtbl[19][21];


#endif	/* _KTABLE_H_ */
