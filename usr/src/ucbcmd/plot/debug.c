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

#include <stdio.h>

float deltx;
float delty;

static void	fplt(FILE *);
static int	getsi(FILE *);
static void	getstr(char *, FILE *);

int
main(int argc, char **argv)
{
	int std=1;
	FILE *fin;

	while(argc-- > 1) {
		if(*argv[1] == '-')
			switch(argv[1][1]) {
				case 'l':
					deltx = atoi(&argv[1][2]) - 1;
					break;
				case 'w':
					delty = atoi(&argv[1][2]) - 1;
					break;
				}

		else {
			std = 0;
			if ((fin = fopen(argv[1], "r")) == NULL) {
				fprintf(stderr, "can't open %s\n", argv[1]);
				exit(1);
				}
			fplt(fin);
			}
		argv++;
		}
	if (std)
		fplt( stdin );
	return (0);
}


static void
fplt(FILE *fin)
{
	int c;
	char s[256];
	int xi,yi,x0,y0,x1,y1,r/*,dx,n,i*/;

	printf("openpl\n");
	while((c=getc(fin)) != EOF){
		switch(c){
		case 'm':
			xi = getsi(fin);
			yi = getsi(fin);
			printf("move %d %d\n", xi, yi);
			break;
		case 'l':
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			printf("line %d %d   %d %d\n", x0, y0, x1, y1);
			break;
		case 't':
			getstr(s,fin);
			printf("label %s\n", s);
			break;
		case 'e':
			printf("erase\n");
			break;
		case 'p':
			xi = getsi(fin);
			yi = getsi(fin);
			printf("point %d %d\n", xi, yi);
			break;
		case 'n':
			xi = getsi(fin);
			yi = getsi(fin);
			printf("continue %d %d\n", xi, yi);
			break;
		case 's':
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			printf("space %d %d   %d %d\n", x0, y0, x1, y1);
			break;
		case 'a':
			xi = getsi(fin);
			yi = getsi(fin);
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			printf("arc\n");
			break;
		case 'c':
			xi = getsi(fin);
			yi = getsi(fin);
			r = getsi(fin);
			printf("circle\n");
			break;
		case 'f':
			getstr(s,fin);
			printf("linemod %s\n", s);
			break;
		default:
			fprintf(stderr, "Unknown command %c (%o)\n", c, c);
			break;
			}
		}
	printf("closepl\n");
}

/* get an integer stored in 2 ascii bytes. */
static int
getsi(FILE *fin)
{
	short a, b;
	if((b = getc(fin)) == EOF)
		return(EOF);
	if((a = getc(fin)) == EOF)
		return(EOF);
	a = a<<8;
	return(a|b);
}

static void
getstr(char *s, FILE *fin)
{
	for( ; *s = getc(fin); s++)
		if(*s == '\n')
			break;
	*s = '\0';
}
