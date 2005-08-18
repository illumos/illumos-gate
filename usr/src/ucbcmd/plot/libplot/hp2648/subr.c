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

#include <sgtty.h>
#include "hp2648.h"

void
handshake(void)
{
	int i;
	char ch;

	if( shakehands != TRUE )
		return;
	ch = ' ';
	putchar(ENQ);
	fflush(stdout);
	while(1){
		i = read(fildes, &ch, 1);
		if(i < 0)
			continue;
		if(ch == ACK)
			break;
		putchar('Z');
		fflush(stdout);
		stty(fildes, &sarg);
		exit(0);
	}
}

void
buffready(int n)
{
	buffcount = buffcount + n;
	if(buffcount >= 80){
		handshake();
		putchar(ESC); 
		putchar(GRAPHIC);
		putchar(PLOT);
		putchar(BINARY);
		buffcount = n+4;
	}
}

void
itoa(int num, char *byte1, char *byte2)
{
	*byte1 = (num & 037) | 040;
	*byte2 = ((num>>5) & 037) | 040;
}
