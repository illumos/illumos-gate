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

#include "hp7221.h"

void
putMBP(int x, int y)
{
    int		chr;

    chr = ( x >> 10 ) & 017;
    chr|= 0140;
    putchar( chr );
    chr = ( x >> 4 ) & 077;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    chr = ( y >> 12 ) & 03;
    chr|= ( x << 2  ) & 071;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    chr = ( y >> 6 ) & 077;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    chr = ( y ) & 077;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    return;
}

void
putMBN(int i)
{
    int		chr;

    chr = ( i>>12 ) & 07;
    chr|= 0140;
    putchar( chr );
    chr = ( i>>6 ) & 077;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    chr = i & 077;
    if ( chr < 32 ) {
	chr += 64;
    }
    putchar( chr );
    return;
}

void
putSBN(int i)
{
    i &= 077;
    if ( i < 32 ) {
	i += 64;
    }
    putchar( i );
    return;
}
