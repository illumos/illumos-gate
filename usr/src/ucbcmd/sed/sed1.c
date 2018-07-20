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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sed.h"
#include <regexp.h>

union reptr     *abuf[ABUFSIZE+1];
union reptr **aptr;
char    ibuf[BUFSIZ];
char    *cbp;
char    *ebp;
char    genbuf[LBSIZE+1];
char	*lcomend;
int     dolflag;
int     sflag;
int     jflag;
int     delflag;
long long lnum;
char    holdsp[LBSIZE+1];
char    *spend;
char    *hspend;
int     nflag;
long long tlno[NLINES];
int     f;
char	*ifname;
int	numpass;
union reptr     *pending;
char	*trans[040]  = {
	"\\01",
	"\\02",
	"\\03",
	"\\04",
	"\\05",
	"\\06",
	"\\07",
	"-<",
	"->",
	"\n",
	"\\13",
	"\\14",
	"\\15",
	"\\16",
	"\\17",
	"\\20",
	"\\21",
	"\\22",
	"\\23",
	"\\24",
	"\\25",
	"\\26",
	"\\27",
	"\\30",
	"\\31",
	"\\32",
	"\\33",
	"\\34",
	"\\35",
	"\\36",
	"\\37"
};
char	rub[] = {"\\177"};

extern char TMMES[];

static int match(char *expbuf, int gf);
static int substitute(union reptr *ipc);
static void dosub(char *rhsbuf, int n);
static void command(union reptr *ipc);
static void arout(void);

void
execute(char *file)
{
	char *p1, *p2;
	union reptr	*ipc;
	int	c;
	char	*execp;

	if (file) {
		if ((f = open(file, 0)) < 0) {
			(void) fprintf(stderr, "sed: ");
			perror(file);
		}
		ifname = file;
	} else {
		f = 0;
		ifname = "standard input";
	}

	ebp = ibuf;
	cbp = ibuf;

	if(pending) {
		ipc = pending;
		pending = 0;
		goto yes;
	}

	for(;;) {
		if((execp = gline(linebuf)) == 0) {
			(void) close(f);
			return;
		}
		spend = execp;

		for(ipc = ptrspace; ipc->r1.command; ) {

			p1 = ipc->r1.ad1;
			p2 = ipc->r1.ad2;

			if(p1) {

				if(ipc->r1.inar) {
					if(*p2 == CEND) {
						p1 = 0;
					} else if(*p2 == CLNUM) {
						c = (unsigned char)p2[1];
						if(lnum > tlno[c]) {
							ipc->r1.inar = 0;
							if(ipc->r1.negfl)
								goto yes;
							ipc++;
							continue;
						}
						if(lnum == tlno[c]) {
							ipc->r1.inar = 0;
						}
					} else if(match(p2, 0)) {
						ipc->r1.inar = 0;
					}
				} else if(*p1 == CEND) {
					if(!dolflag) {
						if(ipc->r1.negfl)
							goto yes;
						ipc++;
						continue;
					}

				} else if(*p1 == CLNUM) {
					c = (unsigned char)p1[1];
					if(lnum != tlno[c]) {
						if(ipc->r1.negfl)
							goto yes;
						ipc++;
						continue;
					}
					if(p2)
						ipc->r1.inar = 1;
				} else if(match(p1, 0)) {
					if(p2)
						ipc->r1.inar = 1;
				} else {
					if(ipc->r1.negfl)
						goto yes;
					ipc++;
					continue;
				}
			}

			if(ipc->r1.negfl) {
				ipc++;
				continue;
			}
	yes:
			command(ipc);

			if(delflag)
				break;

			if(jflag) {
				jflag = 0;
				if((ipc = ipc->r2.lb1) == 0) {
					ipc = ptrspace;
					break;
				}
			} else
				ipc++;

		}
		if(!nflag && !delflag) {
			for(p1 = linebuf; p1 < spend; p1++)
				(void) putc(*p1, stdout);
			(void) putc('\n', stdout);
		}

		if(aptr > abuf) {
			arout();
		}

		delflag = 0;

	}
}

static int
match(char *expbuf, int gf)
{
	char   *p1;

	if(gf) {
		if(*expbuf)	return(0);
		locs = p1 = loc2;
	} else {
		p1 = linebuf;
		locs = 0;
	}

	circf = *expbuf++;
	return(step(p1, expbuf));
}

static int
substitute(union reptr *ipc)
{
	if(match(ipc->r1.re1, 0) == 0)	return(0);

	numpass = 0;
	sflag = 0;		/* Flags if any substitution was made */
	dosub(ipc->r1.rhs, ipc->r1.gfl);

	if(ipc->r1.gfl) {
		while(*loc2) {
			if(match(ipc->r1.re1, 1) == 0) break;
			dosub(ipc->r1.rhs, ipc->r1.gfl);
		}
	}
	return(sflag);
}

static void
dosub(char *rhsbuf, int n)
{
	char *lp, *sp, *rp;
	int c;

	if(n > 0 && n < 999)
		{numpass++;
		if(n != numpass) return;
		}
	sflag = 1;
	lp = linebuf;
	sp = genbuf;
	rp = rhsbuf;
	while (lp < loc1)
		*sp++ = *lp++;
	while(c = *rp++) {
		if (c == '&')
			sp = place(sp, loc1, loc2);
		else if (c == '\\') {
			c = *rp++;
			if (c >= '1' && c < NBRA+'1')
				sp = place(sp, braslist[c-'1'], braelist[c-'1']);
			else
				*sp++ = c;
  		} else
			*sp++ = c;
		if (sp == &genbuf[LBSIZE+1]) {
			(void) fprintf(stderr, "Output line too long.\n");
			*--sp = '\0';
			goto out;
		}
	}
	lp = loc2;
	loc2 = sp - genbuf + linebuf;
	while(*sp++ = *lp++)
		if (sp == &genbuf[LBSIZE+1]) {
			(void) fprintf(stderr, "Output line too long.\n");
			*--sp = '\0';
			break;
		}
out:
	lp = linebuf;
	sp = genbuf;
	while (*lp++ = *sp++);
	spend = lp-1;
}

char	*place(asp, al1, al2)
char	*asp, *al1, *al2;
{
	char *sp, *l1, *l2;

	sp = asp;
	l1 = al1;
	l2 = al2;
	while (l1 < l2) {
		*sp++ = *l1++;
		if (sp == &genbuf[LBSIZE+1])
			break;
	}
	return(sp);
}

static void
command(union reptr *ipc)
{
	int	i;
	char   *p1, *p2, *p3;
	char	*execp;


	switch(ipc->r1.command) {

		case ACOM:
			if(aptr >= &abuf[ABUFSIZE]) {
				(void) fprintf(stderr, "Too many appends or reads after line %lld\n",
					lnum);
			} else {
				*aptr++ = ipc;
				*aptr = 0;
			}
			break;

		case CCOM:
			delflag = 1;
			if(!ipc->r1.inar || dolflag) {
				for(p1 = ipc->r1.re1; *p1; )
					(void) putc(*p1++, stdout);
				(void) putc('\n', stdout);
			}
			break;
		case DCOM:
			delflag++;
			break;
		case CDCOM:
			p1 = p2 = linebuf;

			while(*p1 != '\n') {
				if(*p1++ == 0) {
					delflag++;
					return;
				}
			}

			p1++;
			while(*p2++ = *p1++);
			spend = p2-1;
			jflag++;
			break;

		case EQCOM:
			(void) fprintf(stdout, "%lld\n", lnum);
			break;

		case GCOM:
			p1 = linebuf;
			p2 = holdsp;
			while(*p1++ = *p2++);
			spend = p1-1;
			break;

		case CGCOM:
			*spend++ = '\n';
			p1 = spend;
			p2 = holdsp;
			do {
				if (p1 == &linebuf[LBSIZE+1]) {
					(void) fprintf(stderr, "Output line too long.\n");
					*--p1 = '\0';
				}
			} while(*p1++ = *p2++);
			spend = p1-1;
			break;

		case HCOM:
			p1 = holdsp;
			p2 = linebuf;
			while(*p1++ = *p2++);
			hspend = p1-1;
			break;

		case CHCOM:
			*hspend++ = '\n';
			p1 = hspend;
			p2 = linebuf;
			do {
				if (p1 == &holdsp[LBSIZE+1]) {
					(void) fprintf(stderr, "Hold space overflowed.\n");
					*--p1 = '\0';
				}
			} while(*p1++ = *p2++);
			hspend = p1-1;
			break;

		case ICOM:
			for(p1 = ipc->r1.re1; *p1; )
				(void) putc(*p1++, stdout);
			(void) putc('\n', stdout);
			break;

		case BCOM:
			jflag = 1;
			break;


		case LCOM:
			p1 = linebuf;
			p2 = genbuf;
			genbuf[72] = 0;
			while(*p1)
				if((unsigned char)*p1 >= 040) {
					if(*p1 == 0177) {
						p3 = rub;
						while(*p2++ = *p3++)
							if(p2 >= lcomend) {
								*p2 = '\\';
								(void) fprintf(stdout, "%s\n", genbuf);
								p2 = genbuf;
							}
						p2--;
						p1++;
						continue;
					}
					if(!isprint(*p1 & 0377)) {
						*p2++ = '\\';
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
						*p2++ = (*p1 >> 6) + '0';
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
						*p2++ = ((*p1 >> 3) & 07) + '0';
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
						*p2++ = (*p1++ & 07) + '0';
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
					} else {
						*p2++ = *p1++;
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
					}
				} else {
					p3 = trans[(unsigned char)*p1-1];
					while(*p2++ = *p3++)
						if(p2 >= lcomend) {
							*p2 = '\\';
							(void) fprintf(stdout, "%s\n", genbuf);
							p2 = genbuf;
						}
					p2--;
					p1++;
				}
			*p2 = 0;
			(void) fprintf(stdout, "%s\n", genbuf);
			break;

		case NCOM:
			if(!nflag) {
				for(p1 = linebuf; p1 < spend; p1++)
					(void) putc(*p1, stdout);
				(void) putc('\n', stdout);
			}

			if(aptr > abuf)
				arout();
			if((execp = gline(linebuf)) == 0) {
				pending = ipc;
				delflag = 1;
				break;
			}
			spend = execp;

			break;
		case CNCOM:
			if(aptr > abuf)
				arout();
			*spend++ = '\n';
			if((execp = gline(spend)) == 0) {
				pending = ipc;
				delflag = 1;
				break;
			}
			spend = execp;
			break;

		case PCOM:
			for(p1 = linebuf; p1 < spend; p1++)
				(void) putc(*p1, stdout);
			(void) putc('\n', stdout);
			break;
		case CPCOM:
	cpcom:
			for(p1 = linebuf; *p1 != '\n' && *p1 != '\0'; )
				(void) putc(*p1++, stdout);
			(void) putc('\n', stdout);
			break;

		case QCOM:
			if(!nflag) {
				for(p1 = linebuf; p1 < spend; p1++)
					(void) putc(*p1, stdout);
				(void) putc('\n', stdout);
			}
			if(aptr > abuf) arout();
			(void) fclose(stdout);
			exit(0);
		case RCOM:
			if(aptr >= &abuf[ABUFSIZE]) {
				(void) fprintf(stderr, "Too many appends or reads after line %lld\n",
					lnum);
			} else {
				*aptr++ = ipc;
				*aptr = 0;
			}
			break;

		case SCOM:
			i = substitute(ipc);
			if(ipc->r1.pfl && nflag && i)
				if(ipc->r1.pfl == 1) {
					for(p1 = linebuf; p1 < spend; p1++)
						(void) putc(*p1, stdout);
					(void) putc('\n', stdout);
				}
				else
					goto cpcom;
			if(i && ipc->r1.fcode)
				goto wcom;
			break;

		case TCOM:
			if(sflag == 0)  break;
			sflag = 0;
			jflag = 1;
			break;

		wcom:
		case WCOM:
			(void) fprintf(ipc->r1.fcode, "%s\n", linebuf);
			(void) fflush(ipc->r1.fcode);
			break;
		case XCOM:
			p1 = linebuf;
			p2 = genbuf;
			while(*p2++ = *p1++);
			p1 = holdsp;
			p2 = linebuf;
			while(*p2++ = *p1++);
			spend = p2 - 1;
			p1 = genbuf;
			p2 = holdsp;
			while(*p2++ = *p1++);
			hspend = p2 - 1;
			break;

		case YCOM: 
			p1 = linebuf;
			p2 = ipc->r1.re1;
			while(*p1 = p2[(unsigned char)*p1])	p1++;
			break;
	}

}

char	*gline(addr)
char	*addr;
{
	char   *p1, *p2;
	int	c;
	sflag = 0;
	p1 = addr;
	p2 = cbp;
	for (;;) {
		if (p2 >= ebp) {
			if(f < 0 || (c = read(f, ibuf, BUFSIZ)) == 0) {
				return(0);
			}
			if(c < 0) {
				(void) fprintf(stderr, "sed: error reading ");
				perror(ifname);
				exit(2);
			}
			p2 = ibuf;
			ebp = ibuf+c;
		}
		if ((c = *p2++) == '\n') {
			if(p2 >=  ebp) {
				if(f < 0 || (c = read(f, ibuf, BUFSIZ)) == 0) {
					if(f >= 0) {
						(void) close(f);
						f = -1;
					}
					if(eargc == 0)
							dolflag = 1;
				}
				if(c < 0) {
					(void) fprintf(stderr, "sed: error reading ");
					perror(ifname);
					exit(2);
				}

				p2 = ibuf;
				ebp = ibuf + c;
			}
			break;
		}
		if(c)
		if(p1 < &linebuf[LBSIZE])
			*p1++ = c;
	}
	lnum++;
	*p1 = 0;
	cbp = p2;

	return(p1);
}

char *comple(x1, ep, x3, x4)
char *x1, *x3;
char x4;
char *ep;
{
	char *p;

	p = compile(x1, ep + 1, x3, x4);
	if(p == ep + 1)
		return(ep);
	*ep = circf;
	return(p);
}

void
regerr(int err)
{
	switch(err) {

	case 11:
		comperr("Range endpoint too large: %s");
		break;

	case 16:
		comperr("Bad number: %s");
		break;

	case 25:
		comperr("``\\digit'' out of range: %s");
		break;

	case 36:
		comperr("Illegal or missing delimiter: %s");
		break;

	case 41:
		comperr("No remembered search string: %s");
		break;

	case 42:
		comperr("\\( \\) imbalance: %s");
		break;

	case 43:
		comperr("Too many \\(: %s");
		break;

	case 44:
		comperr("More than 2 numbers given in \\{ \\}: %s");
		break;

	case 45:
		comperr("} expected after \\: %s");
		break;

	case 46:
		comperr("First number exceeds second in \\{ \\}: %s");
		break;

	case 49:
		comperr("[ ] imbalance: %s");
		break;

	case 50:
		comperr(TMMES);
		break;

	default:
		(void) fprintf(stderr, "Unknown regexp error code %d: %s\n",
		    err, linebuf);
		exit(2);
		break;
	}
}

static void
arout(void)
{
	char   *p1;
	FILE	*fi;
	char	c;
	int	t;

	aptr = abuf - 1;
	while(*++aptr) {
		if((*aptr)->r1.command == ACOM) {
			for(p1 = (*aptr)->r1.re1; *p1; )
				(void) putc(*p1++, stdout);
			(void) putc('\n', stdout);
		} else {
			if((fi = fopen((*aptr)->r1.re1, "r")) == NULL)
				continue;
			while((t = getc(fi)) != EOF) {
				c = t;
				(void) putc(c, stdout);
			}
			(void) fclose(fi);
		}
	}
	aptr = abuf;
	*aptr = 0;
}
