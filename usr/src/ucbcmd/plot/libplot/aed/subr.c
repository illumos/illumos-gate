/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "aed.h"

/*
 * The following table is used to convert numbers to hex.  We cannot use
 * standard C library conversion because it generates lower case letters
 * which are bad news to the AED512.
 */

static char hex[] = "0123456789ABCDEF";

/*---------------------------------------------------------
 *	This is a local routine that converts an integer to a string
 *	of hexadecimal characters.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	The string contains the value of the low-order nchars 4-bit chunks
 *	of val, as represented in hexadecimal.  String is zero-filled.
 *
 *	Parameters
 *		val	- Integer value to be converted.
 * 		string	- Pointer to area for converted result.
 *		nchars	- Number of characters to be converted.
 *---------------------------------------------------------
 */
void
chex(int val, char *string, int nchars)
{
    string = &(string[nchars]);
    *string = '\0';
    for (; nchars>0 ; nchars--)
    {
	*(--string) = hex[val & 017];
	val >>= 4;
    }
}

/*---------------------------------------------------------
 *	This local routine outputs an x-y coordinate pair in the standard
 *	format required by the AED display.
 *
 *	Results:	None.
 *	
 *	Side Effects:
 *	Characters are output to the AED512 in the standard way required
 *	for values indicated by "xy20" in the user manual.
 *
 *	Errors:		None.
 *
 *	Parameters:
 *		x, y	- The coordinates to be output.  Note:  these
 *			are world coordinates, not screen ones.  We
 *			scale in this routine.
 *---------------------------------------------------------
 */
void
outxy20(int x, int y)
{
    char s1[4], s2[4], s3[4];
    x = ((x - xbot) * scale)>>12;
    y = ((y - ybot) * scale)>>12;
    chex(((y>>8)&03) | ((x>>6)&014), s1, 1);
    chex(x&0377, s2, 2);
    chex(y&0377, s3, 2);
    fprintf(stdout, "%s%s%s", s1, s2, s3);
}

/*---------------------------------------------------------
 *	This routine sets the display's current color.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	The current color in the display is set to pcolor, if it
 *	isn't that already.
 *
 *	Parameter:
 *		pcolor	- Pointer to a string giving the desired color
 *			in hexadecimal
 *---------------------------------------------------------
 */
void
setcolor(char *pcolor)
{
    static char curcolor[] = "xx";
    if ((pcolor[0] != curcolor[0]) || (pcolor[1] != curcolor[1]))
    {
	curcolor[0] = pcolor[0];
	curcolor[1] = pcolor[1];
	putc('L', stdout);
	fputs(curcolor, stdout);
    }
}
