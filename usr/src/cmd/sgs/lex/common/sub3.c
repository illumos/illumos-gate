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

/*
 * sub3.c ... ALE enhancement.
 * Since a typical Asian language has a huge character set, it is not
 * ideal to index an array by a character code itself, which requires
 * as large as 2**16 entries per array.
 * To get arround this problem, we identify a set of characters that
 * causes the same transition on all states and call it character group.
 * Every character in a same character group has a unique number called
 * character group id.  A function yycgid(c) maps the character c (in process
 * code) to the id.  This mapping is determined by analyzing all regular
 * expressions in the lex program.
 *
 */
#include	<stdlib.h>
#include	<widec.h>
#include	<search.h>
#include	"ldefs.h"

/*
 * "lchar" stands for linearized character.  It is a variant of
 * process code.  AT&T's 16-bit process code has a drawback in which
 * for three three process code C, D and E where C <= D <= E,
 * codeset(C)==codeset(E) does not mean codeset(D)==codeset(C).
 * In other words, four codesets alternates as the magnitude
 * of character increases.
 * The lchar representation holds this property:
 *   If three lchar C', D' and E' have the relationship C' < D' <  E' and
 *   codeset(C') == codeset(E') then D' is guaranteed to belong to
 *   the same codeset as C' and E'.
 * lchar is implemented as 32 bit entities and the function linearize()
 * that maps a wchar_t to lchar is defined below.  There is no
 * reverse function for it though.
 * The 32-bit process code by AT&T, used only for Taiwanese version at the
 * time of wrting, has no such problem and we use it as it is.
 */

lchar	yycgidtbl[MAXNCG] = {
	0,		/* For ease of computation of the id. */
	'\n',		/* Newline is always special because '.' exclude it. */
	0x000000ff,	/* The upper limit of codeset 0. */
	0x20ffffff,	/* The upper limit of codeset 2. */
	0x40ffffff	/* The upper limit of codeset 3. */
/*	0x60ffffff	   The upper limit of codeset 1. */
	/* Above assumes the number of significant bits of wchar_t is <= 24. */
};
int	ncgidtbl = 5; /* # elements in yycgidtbl. */
int	ncg; /* Should set to ncgidtbl*2; this is the largest value yycgid() */
		/* returns plus 1. */

static void setsymbol(int i);

/*
 * For given 16-bit wchar_t (See NOTE), lchar is computed as illustrated below:
 *
 *	wc: axxxxxxbyyyyyyy
 *
 * returns: 0ab0000000000000axxxxxxxbyyyyyyy
 *
 * linearize() doesn't do any if compiled with 32-bit wchar_t, use of
 * which is flagged with LONG_WCHAR_T macro.
 * NOTE:
 * The implementation is highly depends on the process code representation.
 * This function should be modified when 32-bit process code is used.
 * There is no need to keep 'a' and 'b' bits in the lower half of lchar.
 * You can actually omit these and squeeze the xxxxxx part one bit right.
 * We don't do that here just in sake of speed.
 */
lchar
linearize(wchar_t wc)
{
#ifdef LONG_WCHAR_T
	return ((lchar)wc); /* Don't do anything. */
#else

	lchar	prefix;
	switch (wc&0x8080) {
	case 0x0000: prefix = 0x00000000; break;
	case 0x0080: prefix = 0x20000000; break;
	case 0x8000: prefix = 0x40000000; break;
	case 0x8080: prefix = 0x60000000; break;
	}
	return (prefix|wc);
#endif
}

/* compare liniear characters pointed to by pc1 and pc2 */
int
cmplc(const void *arg1, const void *arg2)
{
	lchar *pc1 = (lchar *)arg1;
	lchar *pc2 = (lchar *)arg2;

	if (*pc1 > *pc2)
		return (1);
	else if (*pc1 == *pc2)
		return (0);
	else
		return (-1);
}

void
remch(wchar_t c)
{
	lchar	lc = linearize(c);
	size_t	local_ncgidtbl;

	/*
	 * User-friendliness consideration:
	 * Make sure no EUC chars are used in reg. exp.
	 */
	if (!handleeuc) {
		if (!isascii(c))
			if (iswprint(c))
				warning(
"Non-ASCII character '%wc' in pattern; use -w or -e lex option.", c);
			else warning(
"Non-ASCII character of value %#x in pattern; use -w or -e lex option.", c);
		/* In any case, we don't need to construct ncgidtbl[]. */
		return;
	}

	/*
	 * lsearch wants ncgidtbl to be size_t, but it is int. Hence,
	 * the use of local_ncgidtbl to satisfy the calling interface.
	 */
	local_ncgidtbl = ncgidtbl;
	(void) lsearch(&lc, yycgidtbl,
	    &local_ncgidtbl, sizeof (lchar), cmplc);
	ncgidtbl = (int)local_ncgidtbl;
}

void
sortcgidtbl(void)
{
	if (!handleeuc)
		return;
	qsort(yycgidtbl, ncgidtbl, sizeof (lchar), cmplc);
}

/*
 * int yycgid(wchar_t c)
 *	Takes c and returns its character group id, determind by the
 *	following algorithm.  The program also uses the binary search
 *	algorithm, generalized from Knuth (6.2.1) Algorithm B.
 *
 *	This function computes the "character group id" based on
 *	a table yycgidtbl of which each lchar entry is pre-sorted
 *	in ascending sequence  The number of valid entries is given
 *	by YYNCGIDTBL.  There is no duplicate entries in yycgidtbl.
 *		const int YYNCGIDTBL;
 *		lchar	yycgidtbl[YYNCGIDTBL];
 *
 *	yycgidtbl[0] is guaranteed to have zero.
 *
 *	For given c, yycgid(c) returns:
 *		2*i	iff yycgidtbl[i] == lc
 *		2*i+1	iff yycgidtbl[i] < lc < yycgidtbl[i+1]
 *		YYNCGIDTBL*2-1
 *			iff yycgidtbl[YYNCGIDTBL-1] < lc
 *	where lc=linearize(c).
 *
 *	Some interesting properties.:
 *	1.  For any c, 0 <= yycgid(c) <= 2*YYNCGIDTBL-1
 *	2.  yycgid(c) == 0  iff  c == 0.
 *	3.  For any wchar_t c and d, if linearize(c) < linearize(d) then
 *	    yycgid(c) <= yycgid(d).
 *	4.  For any wchar_t c and d, if yycgid(c) < yycgid(d) then
 *	    linearize(c) < linearize(d).
 */
#define	YYNCGIDTBL ncgidtbl

int
yycgid(wchar_t c)
{
	int first = 0;
	int last = YYNCGIDTBL - 1;
	lchar lc;

	/*
	 * In ASCII compat. mode, each character forms a "group" and the
	 * group-id is itself...
	 */
	if (!handleeuc)
		return (c);

	lc = linearize(c);

	/* An exceptional case: yycgidtbl[YYNCGIDTBL-1] < lc */
	if (yycgidtbl[YYNCGIDTBL - 1] < lc)
		return (YYNCGIDTBL*2 - 1);

	while (last >= 0) {
		int i = (first+last)/2;
		if (lc == yycgidtbl[i])
			return (2*i);	/* lc exactly matches an element. */
		else if (yycgidtbl[i] < lc) {
			if (lc < yycgidtbl[i+1]) {
				/* lc is in between two elements */
				return (2*i+1);
			}
			else
				first = i + 1;
		} else
			last = i - 1;
	}
	error(
	"system error in yycgid():binary search failed for c=0x%04x\n", c);
	return (0);
}

/*
 * repbycgid --- replaces each character in the parsing tree by its
 * character group id.   This, however, should be called even in
 * the ASCII compat. mode to process DOT nodes and to call cclinter()
 * for the DOT and CCL nodes.
 */
void
repbycgid(void)
{
	int i, c;

	for (i = 0; i < tptr; ++i) {
		c = name[i];
		if (!ISOPERATOR(c)) {
		/* If not an operator, it must be a char.  */
			name[i] = yycgid((wchar_t)c); /* So replace it. */
#ifdef DEBUG
			if (debug) {
				printf("name[%d]:'%c'->%d;\n", i, c, name[i]);
			}
#endif
		} else if (c == RSTR) {
			c = right[i];
			right[i] = yycgid((wchar_t)c);
#ifdef DEBUG
			if (debug) {
				printf(
				    "name[%d].right:'%c'->%d;\n",
				    i, c, right[i]);
			}
#endif
		} else if ((c == RCCL) || (c == RNCCL)) {
			CHR cc, *s;
			int j;
			CHR ccltoken[CCLSIZE];
			CHR *ccp;
			int m;
			/*
			 * This node represetns a character class RE [ccccc]
			 * s points to the string of characters that forms
			 * the class and/or a special prefix notation
			 * <RANGE>XY which corresponds to the RE X-Y,
			 * characters in the range of X and Y.  Here,
			 * X <= Y is guranteed.
			 * We transform these characters into a string
			 * of sorted character group ids.
			 *
			 * There is another mechanism of packing tables
			 * that is inherited from the ASCII lex.  Call of
			 * cclinter() is required for this packing.
			 * This used to be done as yylex() reads the lex
			 * rules but we have to do this here because the
			 * transition table is made to work on the char-group
			 * ids and the mapping cannot be determined until
			 * the entire file is read.
			 */
#ifdef DEBUG
			if (debug) {
				printf("name[%d]:R[N]CCL of \"", i);
				strpt(left[i]);
				printf(" -> {");
			}
#endif
			/* Prepare symbol[] for cclinter(). */
			for (j = 0; j < ncg; ++j)
				symbol[j] = FALSE;

			s = (CHR *) left[i];
			while (cc = *s++) {
				if (cc == RANGE) {
					int	low, high, i;
					/*
					 * Special form: <RANGE>XY
					 * This means the range X-Y.
					 * We mark all symbols[]
					 * elements for yycgid(X) thru
					 * yycgid(Y), inclusively.
					 */
					low = yycgid(*s++);
					high = yycgid(*s++);
					for (i = low; i <= high; ++i)
						setsymbol(i);
				} else {
					setsymbol(yycgid(cc));
				}
			}

			/* Now make a transformed string of cgids. */
			s = ccptr;
			m = 0;
			for (j = 0; j < ncg; ++j)
				if (symbol[j]) {
					ccltoken[m++] = (CHR)j;
#ifdef DEBUG
					if (debug) printf("%d, ", j);
#endif
				}

#ifdef DEBUG
			if (debug) printf("}\n");
#endif
			ccltoken[m] = 0;
			ccp = ccl;
			while (ccp < ccptr && scomp(ccltoken, ccp) != 0)
				ccp++;
			if (ccp < ccptr) {  /* character class found in ccl */
				left[i] = (int)ccp;
			} else { /* not in ccl, add it */
				left[i] = (int)ccptr;
				scopy(ccltoken, ccptr);
				ccptr += slength(ccltoken) + 1;
				if (ccptr > ccl + CCLSIZE)
					error(
					"Too many large character classes");
			}
			cclinter(c == RCCL);
		} else if (c == DOT) {
			if (psave == 0) { /* First DOT node. */
				int j, nlid;
				/*
				 * Make symbol[k]=TRUE for all k
				 *  except k == yycgid('\n').
				 */
				nlid = yycgid('\n');
				psave = ccptr;
				for (j = 1; j < ncg; ++j) {
					if (j == nlid) {
						symbol[j] = FALSE;
					} else {
						symbol[j] = TRUE;
						*ccptr++ = (CHR) j;
					}
				}
				*ccptr++ = 0;
				if (ccptr > ccl + CCLSIZE)
					error(
					"Too many large character classes");
			}
			/* Mimic mn1(RCCL,psave)... */
			name[i] = RCCL;
			left[i] = (int)psave;
			cclinter(1);
		}
	}
#ifdef DEBUG
	if (debug) {
		printf("treedump after repbycgid().\n");
		treedump();
	}
#endif
}

static void
setsymbol(int i)
{
	if (i > sizeof (symbol))
		error("setsymbol: (SYSERR) %d out of range", i);
	symbol[i] = TRUE;
}
