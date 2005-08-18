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

#include <signal.h>
#include "dumb.h"

void
closepl(void)
{
	int i, j;

	for(j=0; j<LINES; j++){
		for(i=0; i<COLS; i++){
			printf("%c", screenmat[i][j]);
		}
		printf("\n");
	}
	signal(SIGINT, SIG_IGN);
	exit(0);
}
