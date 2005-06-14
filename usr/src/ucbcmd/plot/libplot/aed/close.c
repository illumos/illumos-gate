/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */


#include "aed.h"

/*---------------------------------------------------------
 *	Closepl does whatever is necessary to reset the characteristics
 *	of the AED512 after the program is finished.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	The graphics display modes are reset.
 *---------------------------------------------------------
 */
closepl()
{
    fputs("Q00204\6", stdout);
    (void) fflush(stdout);
    (void) stty(fileno(stdout), &sgttyb);
}
