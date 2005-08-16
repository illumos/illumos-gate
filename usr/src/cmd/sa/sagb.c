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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "saghdr.h"
#include <strings.h>
#include <stdlib.h>

void
combine(struct p *p, int pn)
{
	int	a, b, c;
	int	i;
	int	qi = 0;
	float	vala, valb;
	struct	array	*ara, *arb, *arc;
	struct	array	*popar();

	ara = p->c[pn].dptr;
	arb = p->c[pn+1].dptr;
	arc = popar();
	if (DEBUG) {
		fprintf(stderr,
		    "combine p->c[%d].name:%s  &  p->c[%d].name:%s\n",
		    pn, p->c[pn].name, pn+1, p->c[pn+1].name);
		fprintf(stderr, "  alias ara->hname:%s    arb->hname:%s\n",
		    ara->hname, arb->hname);
	}

	for (a = b = c = 0; a < NPTS && b < NPTS && c < NPTS; ) {
		if ((ara->ent[a].hr == 0) || (arb->ent[b].hr == 0)) {
			/*   End of file   */
			arc->ent[c].hr = 0;
			break;
		}

		if ((ara->ent[0].hr < 0) || (arb->ent[0].hr < 0)) {
			/*   One or both is a constant   */
			if ((ara->ent[a].val <= -1000) ||
			    (arb->ent[b].val <= -1000))
				arc->ent[c].val = -1000;
			else
				switch (p->c[pn].op) {
				case '+':
					arc->ent[c].val =
					    ara->ent[a].val + arb->ent[b].val;
					break;
				case '-':
					arc->ent[c].val =
					    ara->ent[a].val - arb->ent[b].val;
					break;
				case '*':
					arc->ent[c].val =
					    ara->ent[a].val * arb->ent[b].val;
					break;
				case '/':
					if (arb->ent[b].val != 0)
						arc->ent[c].val =
						    ara->ent[a].val /
						    arb->ent[b].val;
					else
						arc->ent[c].val = 0;
					break;
				default:
					break;
				}

			if (ara->ent[0].hr >= 0) {
				/*   a is variable   */
				strcpy(arc->ent[c].tm, ara->ent[a].tm);
				strcpy(arc->ent[c].qfld, ara->ent[a].qfld);
				arc->ent[c].hr = ara->ent[a].hr;
				a++;
			} else if (arb->ent[0].hr >= 0) {
				/*   b is variable   */
				strcpy(arc->ent[c].tm, arb->ent[b].tm);
				strcpy(arc->ent[c].qfld, arb->ent[b].qfld);
				arc->ent[c].hr = arb->ent[b].hr;
				b++;
			} else {
				/*   Both are constant   */
				strcpy(arc->ent[c].tm, ara->ent[a].tm);
				strcpy(arc->ent[c].qfld, ara->ent[a].qfld);
				arc->ent[c].hr = ara->ent[a].hr;
				a++;
				b++;
			}
			c++;
			continue;
		}

		if (ara->ent[a].hr < arb->ent[b].hr) {
			/*   b missing   */
			arc->ent[c].hr = ara->ent[a].hr;
			strcpy(arc->ent[c].tm, ara->ent[a].tm);
			strcpy(arc->ent[c].qfld, ara->ent[a].qfld);
			vala = ara->ent[a].val;
			valb = 0.;
			a++;
		} else if (ara->ent[a].hr > arb->ent[b].hr) {
			/*   a missing   */
			arc->ent[c].hr = arb->ent[b].hr;
			strcpy(arc->ent[c].tm, arb->ent[b].tm);
			strcpy(arc->ent[c].qfld, arb->ent[b].qfld);
			valb = arb->ent[b].val;
			vala = 0.;
			b++;
		} else {
			/*   a & b hrs equal   */
			arc->ent[c].hr = ara->ent[a].hr;
			strcpy(arc->ent[c].tm, ara->ent[a].tm);
			vala = ara->ent[a].val;
			valb = arb->ent[b].val;
			/*
			 * Test which index can be incremented without
			 * incurring a change in ..hr
			 */
			if ((ara->ent[a+1].hr == ara->ent[a].hr) &&
			    (arb->ent[b+1].hr != arb->ent[b].hr)) {
				/*  a free, b constrained  */
				strcpy(arc->ent[c].qfld, ara->ent[a].qfld);
				qi = 0;
				a++;
			} else if ((ara->ent[a+1].hr != ara->ent[a].hr) &&
			    (arb->ent[b+1].hr == arb->ent[b].hr)) {
				/*   a constrained, b free  */
				strcpy(arc->ent[c].qfld, arb->ent[b].qfld);
				qi = 1;
				b++;
			} else {
				/*   Both free or both constrained   */
				if (qi == 1)
					strcpy(arc->ent[c].qfld,
					    arb->ent[b].qfld);
				else
					strcpy(arc->ent[c].qfld,
					    ara->ent[a].qfld);
				a++;
				b++;
			}
		}
		if ((vala <= -1000) || (valb <= -1000))
			arc->ent[c].val = -1000;
		else
			switch (p->c[pn].op) {
			case '+':
				arc->ent[c].val = vala + valb;
				break;
			case '-':
				arc->ent[c].val = vala - valb;
				break;
			case '*':
				arc->ent[c].val = vala * valb;
				break;
			case '/':
				if (valb != 0)
					arc->ent[c].val = vala / valb;
				else
					arc->ent[c].val = 0;
				break;
			default:
				break;
			}
		c++;
	}

	sprintf(arc->hname, "%s %c %s", ara->hname, p->c[pn].op, arb->hname);
	if (DEBUG) {
		printar(ara);
		printar(arb);
		printar(arc);
	}
	pushar(ara);
	pushar(arb);
	p->c[pn].op = p->c[pn+1].op;
	p->c[pn].dptr = arc;
	for (i = pn + 1; i < 4; i++) {
		strcpy(p->c[i].name, p->c[i+1].name);
		p->c[i].op = p->c[i+1].op;
		p->c[i].dptr = p->c[i+1].dptr;
	}
}



/*
 * Extracts data from sarc[] array and puts into array entries.  Hunts for name
 * string among column headers in sarc, and copies following data items from
 * corresponding field up to next "Average" line.  Special treatment when name
 * string contains an integer or "time".
 */
int
getdata(char *name, struct array *array)
{
	extern	char	fld[NFLD][FLDCH];
	extern	FILE	*sard;
	extern	long	sardoff;
	int	fnum;
	char	nm[18], ql[8];
	int	nparts;
	int	i, j;
	int	timeflg;
	int	hr, min, sec;
	int	nmloc;
	float	hour;
	char	*tok;

	if (DEBUG)
		fprintf(stderr, "getdata-> name:%s\n", name);

	/*  name contains a constant  */
	if (sscanf(name, "%f", &array->ent[0].val) == 1) {
		/*  no sar data is required  */
		strcpy(array->ent[0].tm, "***");
		strcpy(array->hname, name);
		array->ent[0].hr = -1;
		array->ent[0].qfld[0] = '\0';
		array->ent[1].hr = 0;
		return (0);
	}

	if (strmatch("time", name) >= 0) {
		/* Pick up time values from 1st sar group - %usr */
		if (DEBUG)
			fprintf(stderr, "name matches time\n");
		strcpy(nm, "%usr");
		strcpy(ql, "");
		nparts = 1;
		timeflg = 1;
	} else {
		nparts = 0;
		timeflg = 0;
		if ((tok = strtok(name, "[]")) != NULL) {
			nparts = 1;
			strcpy(nm, tok);
		}
		if ((tok = strtok(0, "[]")) != NULL) {
			nparts++;
			strcpy(ql, tok);
		} else
			strcpy(ql, "");
	}

	/* fprintf(stderr, "nparts:%d  nm:%s  ql:%s\n",  nparts, nm, ql); */

	fseek(sard, sardoff, 0);		/*  seek to line 2 of sard  */
	while ((fnum = getfld()) != EOF) {
		for (i = 0; i < fnum; i++)
			if (strmatch(nm, fld[i]) >= 0) {
				if (timeflg == 1) {
					nmloc = 0;
					strcpy(array->hname, "time");
				} else {
					nmloc = i;
					if (nparts < 2)
						strcpy(array->hname, fld[i]);
					else
						sprintf(array->hname, "%s[%s]",
						    fld[i], ql);
				}
				goto readin;
			}
	}
	fprintf(stderr, "\"%s\" data not found\n", nm);
	return (-1);

readin:
	for (i = 0; i < NPTS; ) {
		if (((fnum = getfld()) == EOF) || (strmatch(":", fld[0]) < 0)) {
			array->ent[i].hr = 0;
			return (0);
		}
		if (DEBUG > 1) {
			for (j = 0; j < fnum; j++)
				fprintf(stderr, "  %s", fld[j]);
			fputc('\n', stderr);
		}
		sscanf(fld[0], "%d:%d:%d", &hr, &min, &sec);
		hour = (float)hr + (float)min/60 + (float)sec/3600;
		if (timeflg == 1) {
			strcpy(array->ent[i].tm, fld[0]);
			array->ent[i].hr = hour;
			array->ent[i].val = hour;
			strcpy(array->ent[i].qfld, "");
			i++;
			continue;
		}
		if (strmatch("unix", fld[1]) >= 0) {
			strcpy(array->ent[i].tm, fld[0]);
			array->ent[i].hr = hour;
			array->ent[i].val = -1000.;
			strcpy(array->ent[i].qfld, "");
			i++;
			continue;
		}
		if ((nparts > 1) && (strmatch(ql, fld[1]) < 0))
			continue;

		strcpy(array->ent[i].tm, fld[0]);
		array->ent[i].hr = hour;
		array->ent[i].val = atof(fld[nmloc]);
		strcpy(array->ent[i].qfld, fld[1]);

		if (DEBUG > 1)
			fprintf(stderr, "    .val:%.3f\n", array->ent[i].val);
		i++;
	}
	return (0);
}



/*
 * Scans characters pointed to by cp; puts non-blank strings into
 * fld[NFLD][FLDCH] up to first newline or EOF.
 *
 * Returns number of fld's filled (or EOF), with cp updated to next readable
 * char.
 */
int
getfld()
{
	extern	char	fld[NFLD][FLDCH];
	extern	FILE	*sard;
	int	fnum = 0, i = 0;
	int	c;

	while ((c = getc(sard)) != EOF)
		switch ((char)c) {
		case ' ':
			fld[fnum][i] = '\0';
			i = 0;
			if (++fnum >= 9)
				return (fnum);
			break;
		case '\n':
			fld[fnum][i] = '\0';
			return (++fnum);
			break;
		default:
			fld[fnum][i++] = c;
			break;
		}

	fld[fnum][i] = '\0';
	if ((i == 0) && (fnum == 0))
		return (EOF);
	else
		return (++fnum);
}


static	struct	array	stack[10];
static	struct	array	*sp[] = {
	&stack[0],
	&stack[1],
	&stack[2],
	&stack[3],
	&stack[4],
	&stack[5],
	&stack[6],
	&stack[7],
	&stack[8],
	&stack[9]};
static	int	spn = 10;



struct array *
popar()
{
	if (spn > 0)
		return (sp[--spn]);
	else
	{
		fprintf(stderr, "Stack empty\n");
		exit(1);
	}
}


int
pushar(struct array *par)
{
	if (spn < 10) {
		sp[spn++] = par;
		return (1);
	} else {
		fprintf(stderr, "Stack full\n");
		return (0);
	}
}



/*
 *	Strips leading and trailing blanks from string
 *	by moving string pointer to first non-blank character,
 *	and replacing trailing blanks with '\0'.
 *	Returns number of remaining characters.
 */
int
stribl(char *s)
{
	char	*a, *b;

	a = b = s;
	while (*b == ' ')
		b++;
	while ((*a++ = *b++) != '\0')
		;
	a--;
	while (a-- > s)
		if (*a != ' ')
			break;
		else
			*a = '\0';
	return (int)(a-s+1);
}



/*
 *	strmatch looks for an occurrence of string pat
 *	inside string targ.  It returns the number of
 *	the first starting character position (zero is valid),
 *	or -1 for no match.
 */
int
strmatch(char *pat, char *targ)
{
	int i, c, ifirst;

	for (ifirst = 0; ; ifirst++) {
		i = 0;
		do {
			if (pat[i] == '\0')
				return (ifirst);
			if (targ[ifirst + i] == '\0')
				return (-1);
			c = i++;
		} while (pat[c] == targ[ifirst + c]);
	}
}



float
yrange(float ff)
{
	static float ylimit[] = {1.0, 1.5, 2.5, 5.0, 10.0};
	float	div = 1;
	int	i = 0;
	if (ff <= 0.)
		return (0);
	while (ff/div > 10.)
		div *= 10.;
	while (ff/div < 1.)
		div /= 10.;
	while ((ff/div) > ylimit[i])
		i++;
	return (ylimit[i] * div);
}
