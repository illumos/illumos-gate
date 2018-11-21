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

/*
 * $Id: pack_to_comp.c,v 1.15 1997/10/31 16:17:04 binz Exp $ SMI
 */

/* Based on Korean Standard Code    87-3 */

/*
 * convert 2 byte combination code into
 * 	   2 byte completion code
 */

#include 	<stdio.h>
#include	"kdefs.h"
#include	"ktable.h"

#define		SKIP	0xa1 + 0xff - 0xfe

#ifdef	__STDC__
	KCHAR packtocomp(KCHAR comb2)
#else
	KCHAR packtocomp(comb2)
	KCHAR comb2;
#endif
{
	KCHAR	comp2 ;
	short 	Ci_val;    /* initial sound */
	short	V_val ;    /* middle  sound */
	short	Cf_val;    /* final   sound */
	short	mask ;

	int	disp, k;

	long	Cfbit ;

#if defined(i386) || defined(__ppc)
	comb2 = ((comb2 & 0xff00) >> 8) | ((comb2 & 0x00ff) << 8);
#endif

	/* Find index value of	initial sound	*/
	/*			middle  sound	*/
	/*			final   sound	*/
	/*	from combination code for table	*/

	Ci_val = INITIAL_SOUND((unsigned int)comb2) - 0x0a;
	V_val  = MIDDLE_SOUND((unsigned int)comb2) - (MIDDLE_SOUND((unsigned int)comb2)/4 + 2);
	Cf_val = FINAL_SOUND(comb2);

	/*
	 * Special case code check
	 */
	if ( V_val < 0 )	/* just initial sound */
#if defined(i386) || defined(__ppc)
	{
		comp2 = 0xa4a0 + Y19_32[INITIAL_SOUND((unsigned int)comb2)
			- 0x09];
		return(((comp2 & 0x00ff) << 8)|((comp2 & 0xff00) >> 8));
	}
#else
		return(0xa4a0 + Y19_32[INITIAL_SOUND((unsigned int)comb2)
			- 0x09]);
#endif

	if (Ci_val < 0 )	/* just middle  sound */
        {
		if (Cf_val <= 1)
#if defined(i386) || defined(__ppc)
		{
			comp2 = 0xa4bf + MIDDLE_SOUND((unsigned int)comb2)
				- MIDDLE_SOUND((unsigned int)comb2)/4 - 2;
			return(((comp2 & 0x00ff) << 8)|((comp2 & 0xff00) >> 8));
		}
#else
			return(0xa4bf + MIDDLE_SOUND((unsigned int)comb2)
				- MIDDLE_SOUND((unsigned int)comb2)/4 - 2);
#endif
		return(K_ILLEGAL);
	}

	/*
	 * Existence check
	 */

	Cfbit = cmp_bitmap[Ci_val][V_val] ;
	for (disp = 0, k = 0; k < Cf_val; k++)
		{
			if (Cfbit & BIT_MASK)
				disp++ ;
			Cfbit >>= 1    ;
		}

	if (!(Cfbit & BIT_MASK))	/* check Ci-val'th bit */
		return(K_ILLEGAL) ;		/* non-existence       */

	/* Find 2 byte completion code	*/

	comp2 = cmp_srchtbl[Ci_val][V_val] + disp ;
	mask  = cmp_srchtbl[Ci_val][V_val] & 0xff ;

	if ((mask + disp) > 0xfe)
		comp2 += SKIP ;
#if defined(i386) || defined(__ppc)
	return(((comp2 & 0x00ff) << 8)|((comp2 & 0xff00) >> 8));
#else
	return(comp2);
#endif
}

#ifdef TESTP
main()	/* This main portion is just for test */
{
	unsigned int comb2, comp2;
	for(;;) {
	scanf("%x",&comb2);
	comp2 = packtocomp(comb2);
	printf("/n completion code = 0x%x\n", comp2);
	}
}
#endif
