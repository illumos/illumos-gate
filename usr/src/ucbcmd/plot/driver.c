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
int PlotRes;

static void fplt(FILE *);
static int getsi(FILE *);
static void getstr(char *, FILE *);

int
main(int argc, char *argv[])
{
	int std = 1;
	char *progname;
	FILE *fin;

	progname = argv[0];
	for (argc--, argv++; argc > 0; argc--, argv++) {
		if (argv[0][0] == '-') {
			switch (argv[0][1]) {
			case 'l':
				deltx = atoi(&argv[0][2]) - 1;
				break;
			case 'w':
				delty = atoi(&argv[0][2]) - 1;
				break;
			case 'r':
				PlotRes = atoi(&argv[0][2]);
				break;
			}
			continue;
		}
		std = 0;
		fin = fopen(argv[0], "r");
		if (fin == NULL) {
			fprintf(stderr, "%s: can't open %s\n", progname,
			    argv[0]);
			exit(1);
		}
		fplt(fin);
		fclose(fin);
	}
	if (std)
		fplt(stdin);
	return (0);
}

static void
fplt(FILE *fin)
{
	int c;
	char s[256];
	int xi,yi,x0,y0,x1,y1,r,dx,n,i;
	int pat[256];

	openpl();
	while((c = getc(fin)) != EOF) {
		switch(c) {
		case 'm':
			xi = getsi(fin);
			yi = getsi(fin);
			move(xi,yi);
			break;
		case 'l':
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			line(x0,y0,x1,y1);
			break;
		case 't':
			getstr(s,fin);
			label(s);
			break;
		case 'e':
			erase();
			break;
		case 'p':
			xi = getsi(fin);
			yi = getsi(fin);
			point(xi,yi);
			break;
		case 'n':
			xi = getsi(fin);
			yi = getsi(fin);
			cont(xi,yi);
			break;
		case 's':
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			space(x0,y0,x1,y1);
			break;
		case 'a':
			xi = getsi(fin);
			yi = getsi(fin);
			x0 = getsi(fin);
			y0 = getsi(fin);
			x1 = getsi(fin);
			y1 = getsi(fin);
			arc(xi,yi,x0,y0,x1,y1);
			break;
		case 'c':
			xi = getsi(fin);
			yi = getsi(fin);
			r = getsi(fin);
			circle(xi,yi,r);
			break;
		case 'f':
			getstr(s,fin);
			linemod(s);
			break;
		case 'd':
			xi = getsi(fin);
			yi = getsi(fin);
			dx = getsi(fin);
			n = getsi(fin);
			for(i=0; i<n; i++)
				pat[i] = getsi(fin);
			dot(xi,yi,dx,n,pat);
			break;
		}
	}
	closepl();
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
