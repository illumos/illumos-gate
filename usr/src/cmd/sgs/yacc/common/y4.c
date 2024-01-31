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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#include "dextern.h"
#define	NOMORE -1000

static void gin(int);
static void stin(int);
static void osummary(void);
static void aoutput(void);
static void arout(wchar_t *, int *, int);
static int nxti(void);
static int gtnm(void);

static int *ggreed;
static int *pgo;
static int *yypgo;

static int maxspr = 0;  /* maximum spread of any entry */
static int maxoff = 0;  /* maximum offset into an array */
int *optimmem;
static int *maxa;

static int nxdb = 0;
static int adb = 0;

void
callopt(void)
{
	int i, *p, j, k, *q;

	ggreed = (int *) malloc(sizeof (int) * size);
	pgo = (int *) malloc(sizeof (int) * size);
	yypgo = &nontrst[0].tvalue;

	/* read the arrays from tempfile and set parameters */

	if ((finput = fopen(TEMPNAME, "r")) == NULL)
/*
 * TRANSLATION_NOTE  -- This is a message from yacc.
 *	This message is passed to error() function.
 *	tempfile can be translated as temporary file.
 */
		error(gettext(
		    "optimizer cannot open tempfile"));

	optimmem = tracemem;
	pgo[0] = 0;
	temp1[0] = 0;
	nstate = 0;
	nnonter = 0;
	for (;;) {
		switch (gtnm()) {

		case L'\n':
			temp1[++nstate] = (--optimmem) - tracemem;
			/* FALLTHRU */

		case L',':
			continue;

		case L'$':
			break;

		default:
			error("bad tempfile");
		}
		break;
	}

	temp1[nstate] = yypgo[0] = (--optimmem) - tracemem;

	for (;;) {
		switch (gtnm()) {

		case L'\n':
			yypgo[++nnonter] = optimmem-tracemem;
			/* FALLTHRU */
		case L',':
			continue;

		case EOF:
			break;

		default:
/*
 * TRANSLATION_NOTE  -- This is a message from yacc.
 *	This message is passed to error() function.
 *	tempfile can be translated as 'temporary file'.
 */
			error(gettext(
			"bad tempfile"));
		}
		break;
	}

	yypgo[nnonter--] = (--optimmem) - tracemem;

	for (i = 0; i < nstate; ++i) {
		k = 32000000;
		j = 0;
		q = tracemem + temp1[i+1];
		for (p = tracemem + temp1[i]; p < q; p += 2) {
			if (*p > j)
				j = *p;
			if (*p < k)
				k = *p;
		}
		if (k <= j) {
			/*
			 * nontrivial situation
			 * temporarily, kill this for compatibility
			 */
			/* j -= k;  j is now the range */
			if (k > maxoff)
				maxoff = k;
		}
		tystate[i] = (temp1[i+1] - temp1[i]) + 2*j;
		if (j > maxspr)
			maxspr = j;
	}

	/* initialize ggreed table */
	for (i = 1; i <= nnonter; ++i) {
		ggreed[i] = 1;
		j = 0;
		/* minimum entry index is always 0 */
		q = tracemem + yypgo[i+1] -1;
		for (p = tracemem + yypgo[i]; p < q; p += 2) {
			ggreed[i] += 2;
			if (*p > j)
				j = *p;
		}
		ggreed[i] = ggreed[i] + 2*j;
		if (j > maxoff)
			maxoff = j;
	}

	/* now, prepare to put the shift actions into the amem array */
	for (i = 0; i < new_actsize; ++i)
		amem[i] = 0;
	maxa = amem;

	for (i = 0; i < nstate; ++i) {
		if (tystate[i] == 0 && adb > 1)
			(void) fprintf(ftable, "State %d: null\n", i);
		indgo[i] = YYFLAG1;
	}

	while ((i = nxti()) != NOMORE) {
		if (i >= 0)
			stin(i);
		else
			gin(-i);
	}

	if (adb > 2) { /* print a array */
		for (p = amem; p <= maxa; p += 10) {
			(void) fprintf(ftable, "%4" PRIdPTR "  ", p-amem);
			for (i = 0; i < 10; ++i)
				(void) fprintf(ftable, "%4d  ", p[i]);
			(void) fprintf(ftable, "\n");
		}
	}
	/* write out the output appropriate to the language */
	aoutput();
	osummary();
	ZAPFILE(TEMPNAME);
}

static void
gin(int i)
{
	int *r, *s, *q1, *q2;
	int *p;

	/* enter gotos on nonterminal i into array amem */
	ggreed[i] = 0;

	q2 = tracemem + yypgo[i+1] - 1;
	q1 = tracemem + yypgo[i];

	/* now, find a place for it */

	/* for( p=amem; p < &amem[new_actsize]; ++p ){ */
	p = amem;
	for (;;) {
		while (p >= &amem[new_actsize])
			exp_act(&p);
		if (*p)
			goto nextgp;
		for (r = q1; r < q2; r += 2) {
			s = p + *r + 1;
			/*
			 * Check if action table needs to
			 * be expanded or not. If so,
			 * expand it.
			 */
			while (s >= &amem[new_actsize]) {
				exp_act(&p);
				s = p + *r + 1;
			}
			if (*s)
				goto nextgp;
			if (s > maxa) {
				while ((maxa = s) >= &amem[new_actsize])
					/* error( "amem array overflow" ); */
					exp_act(&p);
			}
		}
		/* we have found a spot */
		*p = *q2;
		if (p > maxa) {
			while ((maxa = p) >= &amem[new_actsize])
				/* error("amem array overflow"); */
				exp_act(&p);
		}
		for (r = q1; r < q2; r += 2) {
			s = p + *r + 1;
			/*
			 * Check if action table needs to
			 * be expanded or not. If so,
			 * expand it.
			 */
			while (s >= &amem[new_actsize]) {
				exp_act(&p);
				s = p + *r + 1;
			}
			*s = r[1];
		}

		pgo[i] = p - amem;
		if (adb > 1)
			(void) fprintf(ftable,
			    "Nonterminal %d, entry at %d\n", i, pgo[i]);
		goto nextgi;

		nextgp:
			++p;
	}
	/* error( "cannot place goto %d\n", i ); */
	nextgi:;
}

static void
stin(int i)
{
	int *r, n, nn, flag, j, *q1, *q2;
	int *s;

	tystate[i] = 0;

	/* Enter state i into the amem array */

	q2 = tracemem + temp1[i + 1];
	q1 = tracemem + temp1[i];
	/* Find an acceptable place */

	nn = -maxoff;
	more:
	for (n = nn; n < new_actsize; ++n) {
		flag = 0;
		for (r = q1; r < q2; r += 2) {
			s = *r + n + amem;
			if (s < amem)
				goto nextn;
			/*
			 * Check if action table needs to
			 * be expanded or not. If so,
			 * expand it.
			 */
			while (s >= &amem[new_actsize]) {
				exp_act((int **)NULL);
				s = *r + n + amem;
			}
			if (*s == 0)
				++flag;
			else if (*s != r[1])
				goto nextn;
		}

		/*
		 * check that the position equals another
		 * only if the states are identical
		 */
		for (j = 0; j < nstate; ++j) {
			if (indgo[j] == n) {
				if (flag)
					/*
					 * we have some disagreement.
					 */
					goto nextn;
				if (temp1[j+1] + temp1[i] ==
				    temp1[j] + temp1[i+1]) {
					/* states are equal */
					indgo[i] = n;
					if (adb > 1)
						(void) fprintf(ftable,
						    "State %d: entry at"
						    " %d equals state %d\n",
						    i, n, j);
					return;
				}
				goto nextn;  /* we have some disagreement */
			}
		}

		for (r = q1; r < q2; r += 2) {
			while ((s = *r + n + amem) >= &amem[new_actsize]) {
				/*
				 * error( "out of space");
				 */
				exp_act((int **)NULL);
			}
			if (s > maxa)
				maxa = s;
			if (*s != 0 && *s != r[1])
/*
 * TRANSLATION_NOTE  -- This is a message from yacc.
 *	This message is passed to error() function.
 *	Leave this untrasnlated. Yacc internal error.
 */
				error(gettext(
				    "clobber of amem array, pos'n %d, by %d"),
				    s-amem, r[1]);
			*s = r[1];
		}
		indgo[i] = n;
		if (adb > 1)
			(void) fprintf(ftable,
			    "State %d: entry at %d\n", i, indgo[i]);
		return;
		nextn:;
	}

	/* error( "Error; failure to place state %d\n", i ); */
	exp_act((int **)NULL);
	nn = new_actsize - ACTSIZE;
	goto more;
	/* NOTREACHED */
}

static int
nxti(void)
{
	/* finds the next i */
	int i, max, maxi;
	max = 0;

	for (i = 1; i <= nnonter; ++i)
		if (ggreed[i] >= max) {
		max = ggreed[i];
		maxi = -i;
		}

	for (i = 0; i < nstate; ++i)
		if (tystate[i] >= max) {
			max = tystate[i];
			maxi = i;
		}
	if (nxdb)
		(void) fprintf(ftable, "nxti = %d, max = %d\n", maxi, max);
	if (max == 0)
		return (NOMORE);
	else
		return (maxi);
}

static void
osummary(void)
{
	/* write summary */
	int i, *p;

	if (foutput == NULL)
		return;
	i = 0;
	for (p = maxa; p >= amem; --p) {
		if (*p == 0)
			++i;
	}

	(void) fprintf(foutput,
	    "Optimizer space used: input %" PRIdPTR
	    "/%d, output %" PRIdPTR "/%d\n",
	    optimmem-tracemem + 1, new_memsize, maxa-amem + 1, new_actsize);
	(void) fprintf(foutput,
	    "%" PRIdPTR " table entries, %d zero\n", (maxa-amem) + 1, i);
	(void) fprintf(foutput,
	    "maximum spread: %d, maximum offset: %d\n", maxspr, maxoff);

}

static void
aoutput(void)
{
	/* this version is for C */
	/* write out the optimized parser */

	(void) fprintf(ftable, "# define YYLAST %" PRIdPTR "\n", maxa-amem + 1);
	arout(L"yyact", amem, (maxa - amem) + 1);
	arout(L"yypact", indgo, nstate);
	arout(L"yypgo", pgo, nnonter + 1);
}

static void
arout(wchar_t *s, int *v, int n)
{
	int i;

	(void) fprintf(ftable, "static YYCONST yytabelem %ws[]={\n", s);
	for (i = 0; i < n; ) {
		if (i % 10 == 0)
			(void) fprintf(ftable, "\n");
		(void) fprintf(ftable, "%6d", v[i]);
		if (++i == n)
			(void) fprintf(ftable, " };\n");
		else
			(void) fprintf(ftable, ",");
	}
}

static int
gtnm(void)
{
	int s, val, c;

	/* read and convert an integer from the standard input */
	/* return the terminating character */
	/* blanks, tabs, and newlines are ignored */

	s = 1;
	val = 0;

	while ((c = getwc(finput)) != EOF) {
		if (iswdigit(c))
			val = val * 10 + c - L'0';
		else if (c == L'-')
			s = -1;
		else
			break;
	}
	*optimmem++ = s*val;
	if (optimmem >= &tracemem[new_memsize])
		exp_mem(0);
	return (c);
}

void
exp_act(int **ptr)
{
	static int *actbase;
	int i;
	new_actsize += ACTSIZE;

	actbase = amem;
	amem = (int *) realloc((char *)amem, sizeof (int) * new_actsize);
	if (amem == NULL)
/*
 * TRANSLATION_NOTE  -- This is a message from yacc.
 *	This message is passed to error() function.
 *
 *	You may just translate this as:
 *	'Could not allocate internally used memory.'
 */
		error(gettext(
		"couldn't expand action table"));

	for (i = new_actsize-ACTSIZE; i < new_actsize; ++i)
		amem[i] = 0;
	if (ptr != NULL)
		*ptr = *ptr - actbase + amem;
	if (memp >= amem)
		memp = memp - actbase + amem;
	if (maxa >= amem)
		maxa = maxa - actbase + amem;
}
