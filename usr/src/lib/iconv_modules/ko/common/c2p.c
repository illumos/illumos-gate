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
/* $Id: c2p.c,v 1.12 1997/10/31 16:16:56 binz Exp $ SMI: ALE */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  Convert 2 byte completion  code to
 *	    2 byte combination code
 *  1) find the sequential No. of initial and middle sounds.
 *  2) decide the displacement of final sound from the starting point.
 *  3) combine each sounds into combination code.
 */

#include 	<stdio.h>
#include	"kdefs.h"
#include	"ktable.h"

#define		SKIP	0xa1 + 0xff - 0xfe

#define 	CI_CNT  19 - 1
#define		V_CNT	21 - 1

/* KS C 5601-1986 */
KCHAR c2p(comp2)
KCHAR comp2;
{

	KCHAR	comb2;
	short 	Ci_val;		/* initial sound */
	short	V_val ;		/* middle  sound */
	short	Cf_val;		/* final   sound */
	short	mask  ;
	short 	high = CI_CNT ;
	short	low  = 0      ;

	int	disp,cnt;

	long	Cfbit ;

/*
 * Find initial sound (Ci_val) and
 *	middle  sound (V_val )
 * which make the starting point for 'comp2'.
 */

	for (;;) {
		Ci_val = (low + high) / 2 ;
		if (low >= high)
			break ;
		if (comp2 < cmp_srchtbl[Ci_val][0])
			high = Ci_val - 1 ;
		else if (comp2 < cmp_srchtbl[Ci_val+1][0])
			break ;
		     else low = Ci_val + 1 ;
	}

	V_val = 1;
	while(1) {
		if (comp2 < cmp_srchtbl[Ci_val][V_val]) {
			while(cmp_srchtbl[Ci_val][--V_val] == 0)
				;
			break;
		}else if (V_val == V_CNT)
			break ;
		V_val++;
	}

	/* Find displacement (temporary final sound value) */

	disp  = comp2 - cmp_srchtbl[Ci_val][V_val] ;
	mask  = cmp_srchtbl[Ci_val][V_val] & BYTE_MASK  ;

	if ((mask + disp) > 0xfe)
		disp -= SKIP ;

	/* Find the value of final sound */

	Cfbit = cmp_bitmap[Ci_val][V_val] ;
	for (cnt = -1 , Cf_val = -1; cnt < disp; Cf_val++)
		{
			if (Cfbit & BIT_MASK)
				cnt++ ;
			Cfbit >>= 1   ;
		}

	/* make 2 byte combination code	*/

	comb2  = (unsigned int) (Ci_val + 0x0a) ;
	comb2  = (comb2 << 5) | (V_val + (V_val + 1)/3 + 2) ;
	comb2  = (comb2 << 5) | Cf_val ;

	return(comb2 | 0x8000) ;
}

/* KS C 5601-1992 */
KCHAR c2j(comp2)
KCHAR comp2;
{

	KCHAR	comb2;
	short 	Ci_val;		/* initial sound */
	short	V_val ;		/* middle  sound */
	short	Cf_val;		/* final   sound */
	short	mask  ;
	short 	high = CI_CNT ;
	short	low  = 0      ;

	int	disp,cnt;

	long	Cfbit ;

/*
 * Find initial sound (Ci_val) and
 *	middle  sound (V_val )
 * which make the starting point for 'comp2'.
 */

	for (;;) {
		Ci_val = (low + high) / 2 ;
		if (low >= high)
			break ;
		if (comp2 < cmp_srchtbl[Ci_val][0])
			high = Ci_val - 1 ;
		else if (comp2 < cmp_srchtbl[Ci_val+1][0])
			break ;
		     else low = Ci_val + 1 ;
	}

	V_val = 1;
	while(1) {
		if (comp2 < cmp_srchtbl[Ci_val][V_val]) {
			while(cmp_srchtbl[Ci_val][--V_val] == 0)
				;
			break;
		}else if (V_val == V_CNT)
			break ;
		V_val++;
	}

	/* Find displacement (temporary final sound value) */

	disp  = comp2 - cmp_srchtbl[Ci_val][V_val] ;
	mask  = cmp_srchtbl[Ci_val][V_val] & BYTE_MASK  ;

	if ((mask + disp) > 0xfe)
		disp -= SKIP ;

	/* Find the value of final sound */

	Cfbit = cmp_bitmap[Ci_val][V_val] ;
	for (cnt = -1 , Cf_val = -1; cnt < disp; Cf_val++)
		{
			if (Cfbit & BIT_MASK)
				cnt++ ;
			Cfbit >>= 1   ;
		}

	/* make 2 byte combination code	*/

	comb2 = (unsigned int) (Ci_val + 2);
	comb2 = (comb2 << 5) | (V_val + (V_val + 1) / 6 * 2 + 3);
	comb2 = (comb2 << 5) | (Cf_val + (Cf_val) / 18);


	return(comb2 | 0x8000) ;
}

#ifdef TESTPRINT
main()
{
	unsigned short comp2, comb2;
	int i,j;

	printf("\ncompletion code       combination code\n");
	for (i=0xb0;i<=0xc8;i++) {
		for (j=0xa1;j<=0xfe;j++) {
			comp2 = i<<8|j;
			comb2 = comptopack(comp2);
			printf("    %4x                        %4x\n", comp2,comb2);
		}
	}
}
#endif
