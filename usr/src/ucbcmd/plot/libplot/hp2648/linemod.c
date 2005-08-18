/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "hp2648.h"

void
linemod(char *line)
{
	putchar('Z'); 
	handshake();
	putchar(ESC); 
	putchar(GRAPHIC);
	putchar(MODE);
	if ( *(line) == 's' ) {
		if ( *(++line) == 'o' ) {
			/*
			 * solid mode 1
			 */
			putchar( '1' );
			putchar( 'b' );
			goto done;
		}
		else if ( *(line) == 'h' ) {
			/*
			 * shortdashed mode 4
			 */
			putchar( '6' );
			putchar( 'b' );
			goto done;
		}
	}
	else if ( *(line) == 'd' ) {
		if ( *(++line) == 'o' && *(++line) == 't' ) {
			if ( *(++line) == 't' ) {
				/*
				 * dotted mode 2
				 */
				putchar( '7' );
				putchar( 'b' );
				goto done;
			}
			else if ( *(line) == 'd' ) {
				/*
				 * dotdashed mode 3
				 */
				putchar( '8' );
				putchar( 'b' );
				goto done;
			}
		}
	}
	else if ( *(line) == 'l' ) {
		/*
		 * longdashed mode 5
		 */
		putchar( '5' );
		putchar( 'b' );
		goto done;
	}
	putchar( '1' );				/* default to solid */
	putchar( 'b' );				/* default to solid */
done:
	putchar( 'Z' );
	handshake();
	putchar(ESC); 
	putchar(GRAPHIC);
	putchar(PLOT);
	putchar(BINARY);
	buffcount = 4;
	return;
}
