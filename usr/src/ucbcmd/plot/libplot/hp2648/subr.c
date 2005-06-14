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


#include <sgtty.h>
#include "hp2648.h"

handshake()
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

buffready(n)
int n;
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

itoa(num,byte1,byte2)
int num;
char *byte1,*byte2;
{
	*byte1 = (num & 037) | 040;
	*byte2 = ((num>>5) & 037) | 040;
}
