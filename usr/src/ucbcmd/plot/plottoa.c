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

/*
 * Convert the standard plot input into a readable form for debugging.
 */

#include <stdio.h>

float deltx;
float delty;

static void	arc(int, int, int, int, int, int);
static void	circle(int, int, int);
static void	closepl(void);
static void	cont(int, int);
static void	dot(int, int, int, int, char *);
static void	erase(void);
static void	fplt(FILE *);
static int	getsi(FILE *);
static void	getstr(char *, FILE *);
static void	label(char *);
static void	line(int, int, int, int);
static void	linemod(char *);
static void	move(int, int);
static void	openpl(void);
static void	point(int, int);
static void	space(int, int, int, int);

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
			fclose(fin);
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
	int xi,yi,x0,y0,x1,y1,r,dx,n,i;
	int pat[256];

	openpl();
	while((c = getc(fin)) != EOF){
		switch(c){
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
			for(i=0; i<n; i++)pat[i] = getsi(fin);
			dot(xi, yi, dx, n, (char *)pat);
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

/* Print out the arguments to plot routines. */

static void
space(int x0, int y0, int x1, int y1)
{
	printf( "s %d %d %d %d\n", x0, y0, x1, y1 );
}

static void
openpl(void)
{
}

static void
closepl(void)
{
}

static void
erase(void)
{
	printf( "e\n" );
}

static void
move(int xi, int yi)
{
	printf( "m %d %d\n", xi, yi );
}

static void
cont(int xi, int yi)
{
	printf( "n %d %d\n", xi, yi );
}

static void
line(int x0, int y0, int x1, int y1)
{
	printf( "l %d %d %d %d\n", x0, y0, x1, y1 );
}

static void
point(int xi, int yi)
{
	printf( "p %d %d\n", xi, yi );
}

static void
label(char *s)
{
	printf( "t%s\n\n", s );
}


static void
arc(int xcent, int ycent, int xbeg, int ybeg, int xend, int yend)
{
	printf( "a %d %d %d %d %d %d\n", xcent, ycent, xbeg, ybeg, xend, yend );
}

static void
circle(int xc, int yc, int r)
{
	printf( "c %d %d %d\n", xc, yc, r );
}

static void
linemod(char *line)
{
	printf( "f%s\n\n", line );
}

/* don't know what this should do */
static void
dot(int xi, int yi, int dx, int n, char *pat)
{
	printf("d %d %d %d %d %s\n\n", xi, yi, dx, n, pat);
}
