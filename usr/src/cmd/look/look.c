/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

FILE *dfile;
char *filenam  = "/usr/share/lib/dict/words";

int fold;
int dict;
int tab;
#define WORDSIZE 257
char entry[WORDSIZE];
char word[WORDSIZE];
char key[WORDSIZE];

int	compare(char *, char *);
void	canon(char *, char *);
int	getword(char *);

int
main(int argc, char **argv)
{
	int c;
	long top,bot,mid;
	char *wstring, *ptr;

	while(argc>=2 && *argv[1]=='-') {
		for(;;) {
			switch(*++argv[1]) {
			case 'd':
				dict++;
				continue;
			case 'f':
				fold++;
				continue;
			case 't':
				tab = argv[1][1];
				if(tab)
					++argv[1];
				continue;
			case 0:
				break;
			default:
				continue;
			}
			break;
		}
		argc --;
		argv++;
	}
	if(argc<=1)
		return (1);
	if(argc==2) {
		fold++;
		dict++;
	} else
		filenam = argv[2];
	dfile = fopen(filenam,"r");
	if(dfile==NULL) {
		fprintf(stderr,"look: can't open %s\n",filenam);
		exit(2);
	}
	wstring = strdup(argv[1]);
	if (tab != 0) {
		if ((ptr = strchr(wstring, tab)) != NULL) {
			*++ptr = '\0';
		}
	}
	canon(wstring,key);
	bot = 0;
	fseek(dfile,0L,2);
	top = ftell(dfile);
	for(;;) {
		mid = (top+bot)/2;
		fseek(dfile,mid,0);
		do {
			c = getc(dfile);
			mid++;
		} while(c!=EOF && c!='\n');
		if(!getword(entry))
			break;
		canon(entry,word);
		switch(compare(key,word)) {
		case -2:
		case -1:
		case 0:
			if(top<=mid)
				break;
			top = mid;
			continue;
		case 1:
		case 2:
			bot = mid;
			continue;
		}
		break;
	}
	fseek(dfile,bot,0);
	while(ftell(dfile)<top) {
		if(!getword(entry))
			return (0);
		canon(entry,word);
		switch(compare(key,word)) {
		case -2:
			return (0);
		case -1:
		case 0:
			puts(entry);
			break;
		case 1:
		case 2:
			continue;
		}
		break;
	}
	while(getword(entry)) {
		canon(entry,word);
		switch(compare(key,word)) {
		case -1:
		case 0:
			puts(entry);
			continue;
		}
		break;
	}
	return (0);
}

int
compare(char *s, char *t)
{
	for(;*s==*t;s++,t++)
		if(*s==0)
			return(0);
	return(*s==0? -1:
		*t==0? 1:
		*s<*t? -2:
		2);
}

int
getword(char *w)
{
	int c;
	int avail = WORDSIZE - 1;

	while(avail--) {
		c = getc(dfile);
		if(c==EOF)
			return(0);
		if(c=='\n')
			break;
		*w++ = c;
	}
	while (c != '\n')
		c = getc(dfile);
	*w = 0;
	return(1);
}

void
canon(char *old, char *new)
{
	int c;
	int avail = WORDSIZE - 1;

	for(;;) {
		*new = c = *old++;
		if(c==0) {
			*new = 0;
			break;
		}
		if(dict) {
			if(!isalnum(c))
				continue;
		}
		if(fold) {
			if(isupper(c))
				*new += 'a' - 'A';
		}
		new++;
		avail--;
		if (avail <= 0) {
			*new = 0;
			break;
		}
	}
}
