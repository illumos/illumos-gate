/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include "sed.h"

#define	NWFILES		11	/* 10 plus one for standard output */
FILE	*fin;
FILE    *fcode[NWFILES];
char    *lastre;
char    sseof;
union reptr     *ptrend;
int     eflag;
extern	int	nbra;
char    linebuf[LBSIZE+1];
int     gflag;
int     nlno;
char    *fname[NWFILES];
int     nfiles;
union reptr ptrspace[PTRSIZE];
union reptr *rep;
char    *cp;
char    respace[RESIZE];
struct label ltab[LABSIZE];
struct label    *lab;
struct label    *labend;
int     depth;
int     eargc;
char    **eargv;
union reptr     **cmpend[DEPTH];

#define CCEOF	22

struct label    *labtab = ltab;

char	ETMES[]		= "Extra text at end of command: %s";
char	SMMES[]		= "Space missing before filename: %s";
char    TMMES[]		= "Too much command text: %s";
char    LTL[]  		= "Label too long: %s";
char    AD0MES[]	= "No addresses allowed: %s";
char    AD1MES[]	= "Only one address allowed: %s";
char	TOOBIG[]	= "Suffix too large - 512 max: %s";

extern int sed;	  /* IMPORTANT flag !!! */
extern char *comple();

static void dechain(void);
static void fcomp(void);

int
main(int argc, char *argv[])
{
	int flag_found = 0;

	sed = 1;
	eargc = argc;
	eargv = argv;

	aptr = abuf;
	lab = labtab + 1;       /* 0 reserved for end-pointer */
	rep = ptrspace;
	rep->r1.ad1 = respace;
	lcomend = &genbuf[71];
	ptrend = &ptrspace[PTRSIZE];
	labend = &labtab[LABSIZE];
	lnum = 0;
	pending = 0;
	depth = 0;
	spend = linebuf;
	hspend = holdsp;	/* Avoid "bus error" under "H" cmd. */
	fcode[0] = stdout;
	fname[0] = "";
	nfiles = 1;

	if(eargc == 1)
		exit(0);


	setlocale(LC_ALL, "");		/* get locale environment */

	while (--eargc > 0 && (++eargv)[0][0] == '-')
		switch (eargv[0][1]) {

		case 'n':
			nflag++;
			continue;

		case 'f':
			flag_found = 1;
			if(eargc-- <= 0)	exit(2);

			if((fin = fopen(*++eargv, "r")) == NULL) {
				(void) fprintf(stderr, "sed: ");
				perror(*eargv);
				exit(2);
			}

			fcomp();
			(void) fclose(fin);
			continue;

		case 'e':
			flag_found = 1;
			eflag++;
			fcomp();
			eflag = 0;
			continue;

		case 'g':
			gflag++;
			continue;

		default:
			(void) fprintf(stderr, "sed: Unknown flag: %c\n", eargv[0][1]);
			exit(2);
		}


	if(rep == ptrspace && !flag_found) {
		eargv--;
		eargc++;
		eflag++;
		fcomp();
		eargv++;
		eargc--;
		eflag = 0;
	}

	if(depth)
		comperr("Too many {'s");

	labtab->address = rep;

	dechain();

	if(eargc <= 0)
		execute((char *)NULL);
	else while(--eargc >= 0) {
		execute(*eargv++);
	}
	(void) fclose(stdout);
	return (0);
}

static void
fcomp(void)
{

	char   *p, *op, *tp;
	char    *address();
	union reptr     *pt, *pt1;
	int     i, ii;
	struct label    *lpt;
	char fnamebuf[MAXPATHLEN];

	op = lastre;

	if(rline(linebuf, &linebuf[LBSIZE+1]) < 0)  return;
	if(*linebuf == '#') {
		if(linebuf[1] == 'n')
			nflag = 1;
	}
	else {
		cp = linebuf;
		goto comploop;
	}

	for(;;) {
		if(rline(linebuf, &linebuf[LBSIZE+1]) < 0)  break;

		cp = linebuf;

comploop:
/*		(void) fprintf(stderr, "cp: %s\n", cp); DEBUG */
		while(*cp == ' ' || *cp == '\t')	cp++;
		if(*cp == '\0' || *cp == '#')	 continue;
		if(*cp == ';') {
			cp++;
			goto comploop;
		}

		p = address(rep->r1.ad1);

		if(p == rep->r1.ad1) {
			if(op)
				rep->r1.ad1 = op;
			else
				comperr("First RE may not be null: %s");
		} else if(p == 0) {
			p = rep->r1.ad1;
			rep->r1.ad1 = 0;
		} else {
			op = rep->r1.ad1;
			if(*cp == ',' || *cp == ';') {
				cp++;
				rep->r1.ad2 = p;
				p = address(rep->r1.ad2);
				if(p == 0)
					comperr("Illegal line number: %s");
				if(p == rep->r1.ad2)
					rep->r1.ad2 = op;
				else
					op = rep->r1.ad2;

			} else
				rep->r1.ad2 = 0;
		}

		if(p > &respace[RESIZE-1])
			comperr(TMMES);

		while(*cp == ' ' || *cp == '\t')	cp++;

swit:
		switch(*cp++) {

			default:
				comperr("Unrecognized command: %s");

			case '!':
				rep->r1.negfl = 1;
				goto swit;

			case '{':
				rep->r1.command = BCOM;
				rep->r1.negfl = !(rep->r1.negfl);
				cmpend[depth++] = &rep->r2.lb1;
				if(++rep >= ptrend)
					comperr("Too many commands: %s");
				rep->r1.ad1 = p;
				if(*cp == '\0') continue;

				goto comploop;

			case '}':
				if(rep->r1.ad1)
					comperr(AD0MES);

				if(--depth < 0)
					comperr("Too many }'s");
				*cmpend[depth] = rep;

				rep->r1.ad1 = p;
				continue;

			case '=':
				rep->r1.command = EQCOM;
				if(rep->r1.ad2)
					comperr(AD1MES);
				break;

			case ':':
				if(rep->r1.ad1)
					comperr(AD0MES);

				while(*cp++ == ' ');
				cp--;


				tp = lab->asc;
				while((*tp++ = *cp++))
					if(tp >= &(lab->asc[9]))
						comperr(LTL);
				*--tp = '\0';

				if(lpt = search(lab)) {
					if(lpt->address)
						comperr("Duplicate labels: %s");
				} else {
					lab->chain = 0;
					lpt = lab;
					if(++lab >= labend)
						comperr("Too many labels: %s");
				}
				lpt->address = rep;
				rep->r1.ad1 = p;

				continue;

			case 'a':
				rep->r1.command = ACOM;
				if(rep->r1.ad2)
					comperr(AD1MES);
				if(*cp == '\\') cp++;
				if(*cp++ != '\n')
					comperr(ETMES);
				rep->r1.re1 = p;
				if ((p = text(rep->r1.re1, &respace[RESIZE-1])) == NULL)
					comperr(TMMES);
				break;
			case 'c':
				rep->r1.command = CCOM;
				if(*cp == '\\') cp++;
				if(*cp++ != ('\n'))
					comperr(ETMES);
				rep->r1.re1 = p;
				if ((p = text(rep->r1.re1, &respace[RESIZE-1])) == NULL)
					comperr(TMMES);
				break;
			case 'i':
				rep->r1.command = ICOM;
				if(rep->r1.ad2)
					comperr(AD1MES);
				if(*cp == '\\') cp++;
				if(*cp++ != ('\n'))
					comperr(ETMES);
				rep->r1.re1 = p;
				if ((p = text(rep->r1.re1, &respace[RESIZE-1])) == NULL)
					comperr(TMMES);
				break;

			case 'g':
				rep->r1.command = GCOM;
				break;

			case 'G':
				rep->r1.command = CGCOM;
				break;

			case 'h':
				rep->r1.command = HCOM;
				break;

			case 'H':
				rep->r1.command = CHCOM;
				break;

			case 't':
				rep->r1.command = TCOM;
				goto jtcommon;

			case 'b':
				rep->r1.command = BCOM;
jtcommon:
				while(*cp++ == ' ');
				cp--;

				if(*cp == '\0') {
					if(pt = labtab->chain) {
						while(pt1 = pt->r2.lb1)
							pt = pt1;
						pt->r2.lb1 = rep;
					} else
						labtab->chain = rep;
					break;
				}
				tp = lab->asc;
				while((*tp++ = *cp++))
					if(tp >= &(lab->asc[9]))
						comperr(LTL);
				cp--;
				*--tp = '\0';

				if(lpt = search(lab)) {
					if(lpt->address) {
						rep->r2.lb1 = lpt->address;
					} else {
						pt = lpt->chain;
						while(pt1 = pt->r2.lb1)
							pt = pt1;
						pt->r2.lb1 = rep;
					}
				} else {
					lab->chain = rep;
					lab->address = 0;
					if(++lab >= labend)
						comperr("Too many labels: %s");
				}
				break;

			case 'n':
				rep->r1.command = NCOM;
				break;

			case 'N':
				rep->r1.command = CNCOM;
				break;

			case 'p':
				rep->r1.command = PCOM;
				break;

			case 'P':
				rep->r1.command = CPCOM;
				break;

			case 'r':
				rep->r1.command = RCOM;
				if(rep->r1.ad2)
					comperr(AD1MES);
				if(*cp++ != ' ')
					comperr(SMMES);
				rep->r1.re1 = p;
				if ((p = text(rep->r1.re1, &respace[RESIZE-1])) == NULL)
					comperr(TMMES);
				break;

			case 'd':
				rep->r1.command = DCOM;
				break;

			case 'D':
				rep->r1.command = CDCOM;
				rep->r2.lb1 = ptrspace;
				break;

			case 'q':
				rep->r1.command = QCOM;
				if(rep->r1.ad2)
					comperr(AD1MES);
				break;

			case 'l':
				rep->r1.command = LCOM;
				break;

			case 's':
				rep->r1.command = SCOM;
				sseof = *cp++;
				rep->r1.re1 = p;
				p = comple((char *) 0, rep->r1.re1, &respace[RESIZE-1], sseof);
				if(p == rep->r1.re1) {
					if(op)
						rep->r1.re1 = op;
					else
						comperr("First RE may not be null: %s");
				} else
					op = rep->r1.re1;
				rep->r1.rhs = p;

				p = compsub(rep->r1.rhs);

				if(*cp == 'g') {
					cp++;
					rep->r1.gfl = 999;
				} else if(gflag)
					rep->r1.gfl = 999;

				if(*cp >= '1' && *cp <= '9')
					{i = *cp - '0';
					cp++;
					while(1)
						{ii = *cp;
						if(ii < '0' || ii > '9') break;
						i = i*10 + ii - '0';
						if(i > 512)
							comperr(TOOBIG);
						cp++;
						}
					rep->r1.gfl = i;
					}

				if(*cp == 'p') {
					cp++;
					rep->r1.pfl = 1;
				}

				if(*cp == 'P') {
					cp++;
					rep->r1.pfl = 2;
				}

				if(*cp == 'w') {
					cp++;
					if(*cp++ !=  ' ')
						comperr(SMMES);
					if (text(fnamebuf, &fnamebuf[MAXPATHLEN]) == NULL)
						comperr("File name too long: %s");
					for(i = nfiles - 1; i >= 0; i--)
						if(strcmp(fnamebuf,fname[i]) == 0) {
							rep->r1.fcode = fcode[i];
							goto done;
						}
					if(nfiles >= NWFILES)
						comperr("Too many files in w commands: %s");

					i = strlen(fnamebuf) + 1;
					if ((fname[nfiles] = malloc((unsigned)i)) == NULL) {
						(void) fprintf(stderr, "sed: Out of memory\n");
						exit(2);
					}
					(void) strcpy(fname[nfiles], fnamebuf);
					if((rep->r1.fcode = fopen(fname[nfiles], "w")) == NULL) {
						(void) fprintf(stderr, "sed: Cannot open ");
						perror(fname[nfiles]);
						exit(2);
					}
					fcode[nfiles++] = rep->r1.fcode;
				}
				break;

			case 'w':
				rep->r1.command = WCOM;
				if(*cp++ != ' ')
					comperr(SMMES);
				if (text(fnamebuf, &fnamebuf[MAXPATHLEN]) == NULL)
					comperr("File name too long: %s");
				for(i = nfiles - 1; i >= 0; i--)
					if(strcmp(fnamebuf, fname[i]) == 0) {
						rep->r1.fcode = fcode[i];
						goto done;
					}
				if(nfiles >= NWFILES)
					comperr("Too many files in w commands: %s");

				i = strlen(fnamebuf) + 1;
				if ((fname[nfiles] = malloc((unsigned)i)) == NULL) {
					(void) fprintf(stderr, "sed: Out of memory\n");
					exit(2);
				}
				(void) strcpy(fname[nfiles], fnamebuf);
				if((rep->r1.fcode = fopen(fname[nfiles], "w")) == NULL) {
					(void) fprintf(stderr, "sed: Cannot create ");
					perror(fname[nfiles]);
					exit(2);
				}
				fcode[nfiles++] = rep->r1.fcode;
				break;

			case 'x':
				rep->r1.command = XCOM;
				break;

			case 'y':
				rep->r1.command = YCOM;
				sseof = *cp++;
				rep->r1.re1 = p;
				p = ycomp(rep->r1.re1);
				break;

		}
done:
		if(++rep >= ptrend)
			comperr("Too many commands, last: %s");

		rep->r1.ad1 = p;

		if(*cp++ != '\0') {
			if(cp[-1] == ';')
				goto comploop;
			comperr(ETMES);
		}
	}
	rep->r1.command = 0;
	lastre = op;
}

char    *compsub(rhsbuf)
char    *rhsbuf;
{
	char   *p, *q;

	p = rhsbuf;
	q = cp;
	for(;;) {
		if(p > &respace[RESIZE-1])
			comperr(TMMES);
		if((*p = *q++) == '\\') {
			p++;
			if(p > &respace[RESIZE-1])
				comperr(TMMES);
			*p = *q++;
			if(*p > nbra + '0' && *p <= '9')
				comperr("``\\digit'' out of range: %s");
			p++;
			continue;
		}
		if(*p == sseof) {
			*p++ = '\0';
			cp = q;
			return(p);
		}
  		if(*p++ == '\0')
			comperr("Ending delimiter missing on substitution: %s");

	}
}

int
rline(lbuf, lbend)
char    *lbuf;
char	*lbend;
{
	char   *p, *q;
	int	t;
	static char     *saveq;

	p = lbuf;

	if(eflag) {
		if(eflag > 0) {
			eflag = -1;
			if(--eargc <= 0)
				exit(2);
			q = *++eargv;
			while((t = *q++) != '\0') {
				if(t == '\n') {
					saveq = q;
					goto out1;
				}
				if (p < lbend)
					*p++ = t;
				if(t == '\\') {
					if((t = *q++) == '\0') {
						saveq = 0;
						return(-1);
					}
					if (p < lbend)
						*p++ = t;
				}
			}
			saveq = 0;

		out1:
			if (p == lbend)
				comperr("Command line too long");
			*p = '\0';
			return(1);
		}
		if((q = saveq) == 0)    return(-1);

		while((t = *q++) != '\0') {
			if(t == '\n') {
				saveq = q;
				goto out2;
			}
			if(p < lbend)
				*p++ = t;
			if(t == '\\') {
				if((t = *q++) == '\0') {
					saveq = 0;
					return(-1);
				}
				if (p < lbend)
					*p++ = t;
			}
		}
		saveq = 0;

	out2:
		if (p == lbend)
			comperr("Command line too long");
		*p = '\0';
		return(1);
	}

	while((t = getc(fin)) != EOF) {
		if(t == '\n') {
			if (p == lbend)
				comperr("Command line too long");
			*p = '\0';
			return(1);
		}
		if (p < lbend)
			*p++ = t;
		if(t == '\\') {
			if((t = getc(fin)) == EOF)
				break;
			if(p < lbend)
				*p++ = t;
		}
	}
	if(ferror(fin)) {
		perror("sed: Error reading pattern file");
		exit(2);
	}
	return(-1);
}

char    *address(expbuf)
char    *expbuf;
{
	char   *rcp;
	long long	lno;

	if(*cp == '$') {
		if (expbuf > &respace[RESIZE-2])
			comperr(TMMES);
		cp++;
		*expbuf++ = CEND;
		*expbuf++ = CCEOF;
		return(expbuf);
	}
	if (*cp == '/' || *cp == '\\' ) {
		if ( *cp == '\\' )
			cp++;
		sseof = *cp++;
		return(comple((char *) 0, expbuf, &respace[RESIZE-1], sseof));
	}

	rcp = cp;
	lno = 0;

	while(*rcp >= '0' && *rcp <= '9')
		lno = lno*10 + *rcp++ - '0';

	if(rcp > cp) {
		if (expbuf > &respace[RESIZE-3])
			comperr(TMMES);
		*expbuf++ = CLNUM;
		*expbuf++ = nlno;
		tlno[nlno++] = lno;
		if(nlno >= NLINES)
			comperr("Too many line numbers: %s");
		*expbuf++ = CCEOF;
		cp = rcp;
		return(expbuf);
	}
	return(0);
}

char    *text(textbuf, tbend)
char    *textbuf;
char	*tbend;
{
	char   *p, *q;

	p = textbuf;
	q = cp;
#ifndef S5EMUL
	/*
	 * Strip off indentation from text to be inserted.
	 */
	while(*q == '\t' || *q == ' ')	q++;
#endif
	for(;;) {

		if(p > tbend)
			return(NULL);	/* overflowed the buffer */
		if((*p = *q++) == '\\')
			*p = *q++;
		if(*p == '\0') {
			cp = --q;
			return(++p);
		}
#ifndef S5EMUL
		/*
		 * Strip off indentation from text to be inserted.
		 */
		if(*p == '\n') {
			while(*q == '\t' || *q == ' ')	q++;
		}
#endif
		p++;
	}
}


struct label    *search(ptr)
struct label    *ptr;
{
	struct label    *rp;

	rp = labtab;
	while(rp < ptr) {
		if(strcmp(rp->asc, ptr->asc) == 0)
			return(rp);
		rp++;
	}

	return(0);
}


static void
dechain(void)
{
	struct label    *lptr;
	union reptr     *rptr, *trptr;

	for(lptr = labtab; lptr < lab; lptr++) {

		if(lptr->address == 0) {
			(void) fprintf(stderr, "sed: Undefined label: %s\n", lptr->asc);
			exit(2);
		}

		if(lptr->chain) {
			rptr = lptr->chain;
			while(trptr = rptr->r2.lb1) {
				rptr->r2.lb1 = lptr->address;
				rptr = trptr;
			}
			rptr->r2.lb1 = lptr->address;
		}
	}
}

char *ycomp(expbuf)
char    *expbuf;
{
	char	c;
	char *ep, *tsp;
	int i;
	char    *sp;

	ep = expbuf;
	if(ep + 0377 > &respace[RESIZE-1])
		comperr(TMMES);
	sp = cp;
	for(tsp = cp; (c = *tsp) != sseof; tsp++) {
		if(c == '\\')
			tsp++;
		if(c == '\0' || c == '\n')
			comperr("Ending delimiter missing on string: %s");
	}
	tsp++;

	while((c = *sp++) != sseof) {
		c &= 0377;
		if(c == '\\' && *sp == 'n') {
			sp++;
			c = '\n';
		}
		if((ep[c] = *tsp++) == '\\' && *tsp == 'n') {
			ep[c] = '\n';
			tsp++;
		}
		if(ep[c] == sseof || ep[c] == '\0')
			comperr("Transform strings not the same size: %s");
	}
	if(*tsp != sseof) {
		if(*tsp == '\0')
			comperr("Ending delimiter missing on string: %s");
		else 
			comperr("Transform strings not the same size: %s");
	}
	cp = ++tsp;

	for(i = 0; i < 0400; i++)
		if(ep[i] == 0)
			ep[i] = i;

	return(ep + 0400);
}

void
comperr(char *msg)
{
	(void) fprintf(stderr, "sed: ");
	(void) fprintf(stderr, msg, linebuf);
	(void) putc('\n', stderr);
	exit(2);
}
