/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */


#include "gigi.h"

linemod( line )
char	*line;
{
	/*
	 * Note that the bit patterns could be compacted using the
	 *  repeat field conventions.  They aren't for clarity.
	 *  Examples of almost identical packed patterns are in the
	 *  comments.
	 *  If linemod is changed really often, a ~15% savings
	 *  could be achieved.
	 */
	if ( *(line) == 's' ) {
		if ( *(++line) == 'o' ) {
			/*
			 * solid mode 1
			 */
			printf( "W(P1)" );
			return;
		}
		else if ( *(line) == 'h' ) {
			/*
			 * shortdashed mode 4
			 *  printf( "W(P000111)" );
			 */
			printf( "W(P00011100)" );
			return;
		}
	}
	else if ( *(line) == 'd' ) {
		if ( *(++line) == 'o' && *(++line) == 't' ) {
			if ( *(++line) == 't' ) {
				/*
				 * dotted mode 2
				 *  printf( "W(P00001)" );
				 */
				printf( "W(P10000000)" );
				return;
			}
			else if ( *(line) == 'd' ) {
				/*
				 * dotdashed mode 3
				 *  printf( "W(P0110010)" );
				 */
				printf( "W(P10001100)" );
				return;
			}
		}
	}
	else if ( *(line) == 'l' ) {
		/*
		 * longdashed mode 5
		 *  printf( "W(P11100)" );
		 */
		printf( "W(P11111100)" );
		return;
	}
	printf( "W(P1)" );			/* default to solid */
	return;
}
