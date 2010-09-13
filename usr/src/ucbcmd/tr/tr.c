/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

/* tr - transliterate data stream */
int	dflag	= 0;
int	sflag	= 0;
int	cflag = 0;
int	save	= 0;
char	code[256];
char	squeez[256];
char	vect[256];
struct string { int last, max; char *p; } string1, string2;

int
main(int argc, char **argv)
{
	int i;
	int j;
	int c, d;
	char *compl;
	int lastd;

	string1.last = string2.last = 0;
	string1.max = string2.max = 0;
	string1.p = string2.p = "";

	if(--argc>0) {
		argv++;
		if(*argv[0]=='-'&&argv[0][1]!=0) {
			while(*++argv[0])
				switch(*argv[0]) {
				case 'c':
					cflag++;
					continue;
				case 'd':
					dflag++;
					continue;
				case 's':
					sflag++;
					continue;
				}
			argc--;
			argv++;
		}
	}
	if(argc>0) string1.p = argv[0];
	if(argc>1) string2.p = argv[1];
	for(i=0; i<256; i++)
		code[i] = vect[i] = 0;
	if(cflag) {
		while(c = next(&string1))
			vect[c&0377] = 1;
		j = 0;
		for(i=1; i<256; i++)
			if(vect[i]==0) vect[j++] = i;
		vect[j] = 0;
		compl = vect;
	}
	for(i=0; i<256; i++)
		squeez[i] = 0;
	lastd = 0;
	for(;;){
		if(cflag) c = *compl++;
		else c = next(&string1);
		if(c==0) break;
		d = next(&string2);
		if(d==0) d = lastd;
		else lastd = d;
		squeez[d&0377] = 1;
		code[c&0377] = dflag?1:d;
	}
	while(d = next(&string2))
		squeez[d&0377] = 1;
	squeez[0] = 1;
	for(i=0;i<256;i++) {
		if(code[i]==0) code[i] = i;
		else if(dflag) code[i] = 0;
	}

	clearerr(stdout);
	while((c=getc(stdin)) != EOF ) {
		if(c == 0) continue;
		if(c = code[c&0377]&0377)
			if(!sflag || c!=save || !squeez[c&0377]) {
				(void)putchar(save = c);
				if(ferror(stdout))
					exit(1);
			}
	}
	return (0);
}

int
next(struct string *s)
{

again:
	if(s->max) {
		if(s->last++ < s->max)
			return(s->last);
		s->max = s->last = 0;
	}
	if(s->last && *s->p=='-') {
		(void)nextc(s);
		s->max = nextc(s);
		if(s->max==0) {
			s->p--;
			return('-');
		}
		if(s->max < s->last)  {
			s->last = s->max-1;
			return('-');
		}
		goto again;
	}
	return(s->last = nextc(s));
}

int
nextc(struct string *s)
{
	int c, i, n;

	c = *s->p++;
	if(c=='\\') {
		i = n = 0;
		while(i<3 && (c = *s->p)>='0' && c<='7') {
			n = n*8 + c - '0';
			i++;
			s->p++;
		}
		if(i>0) c = n;
		else c = *s->p++;
	}
	if(c==0) *--s->p = 0;
	return(c&0377);
}
