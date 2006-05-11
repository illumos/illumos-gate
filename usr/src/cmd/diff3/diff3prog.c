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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#include <errno.h>
#

/*
 * diff3 - 3-way differential file comparison
 */

/*
 * diff3 [-ex3EX] d13 d23 f1 f2 f3 [m1 m3]
 *
 * d13 = diff report on f1 vs f3
 * d23 = diff report on f2 vs f3
 * f1, f2, f3 the 3 files
 * if changes in f1 overlap with changes in f3, m1 and m3 are used
 * to mark the overlaps; otherwise, the file names f1 and f3 are used
 * (only for options E and X).
 */

struct  range {int from, to; };
	/*
	 * from is first in range of changed lines
	 * to is last+1
	 * from = to = line after point of insertion
	 * for added lines
	 */
struct diff {struct range old, new; };

#define	NC 4096
/*
 * de is used to gather editing scripts,
 * that are later spewed out in reverse order.
 * its first element must be all zero
 * the "new" component of de contains line positions
 * or byte positions depending on when you look(!?)
 */
static struct diff d13[NC];
static struct diff d23[NC];

/*
 * array overlap indicates which sections in de correspond to
 * lines that are different in all three files.
 */

static struct diff de[NC];
static char overlap[NC];
static int  overlapcnt = 0;

static char line[LINE_MAX+1];
static FILE *fp[3];
/*
 *	the number of the last-read line in each file
 *	is kept in cline[0-2]
 */
static int cline[3];
/*
 *	the latest known correspondence between line
 *	numbers of the 3 files is stored in last[1-3]
 */
static int last[4];
static int eflag;
static int oflag;	/* indicates whether to mark overlaps (-E or -X) */
static int debug  = 0;
/* markers for -E and -X: */
static char f1mark[8+MAXPATHLEN], f3mark[8+MAXPATHLEN];
		/* Need space for "<<<<<<< " or ">>>>>>> " plus filename   */
static int save_err;	/* saves errno */

static int readin(char *name, struct diff *dd);
static int number(char **lc);
static int digit(int c);
static int getchange(FILE *b);
static int getline(FILE *b);
static void merge(int m1, int m2);
static void separate(char *s);
static void change(int i, struct range *rold, int dup);
static void prange(struct range *rold);
static void keep(int i, struct range *rnew);
static int skip(int i, int from, char *pr);
static int duplicate(struct range *r1, struct range *r2);
static void repos(int nchar);
static void trouble();
static int edit(struct diff *diff, int dup, int j);
static void edscript(int n);
static void usage();

int
main(int argc, char **argv)
{
	int i, m, n;
	eflag  = 0;
	oflag  = 0;
	if ((argc > 1) && (*argv[1] == '-')) {
		switch (argv[1][1]) {
		case 'e':
			eflag = 3;
			break;
		case '3':
			eflag = 2;
			break;
		case 'x':
			eflag = 1;
			break;
		case 'E':
			eflag = 3;
			oflag = 1;
			break;
		case 'X':
			oflag = eflag = 1;
			break;
		default:
			usage();
			break;
		}
		argv++;
		argc--;
	}
	if (argc < 6)
		usage();
	if (oflag) {
		(void) snprintf(f1mark, sizeof (f1mark), "<<<<<<< %s",
						argc >= 7 ? argv[6] : argv[3]);
		(void) snprintf(f3mark, sizeof (f3mark), ">>>>>>> %s",
						argc >= 8 ? argv[7] : argv[5]);
	}

	m = readin(argv[1], d13);
	n = readin(argv[2], d23);
	for (i = 0; i <= 2; i++)
		if ((fp[i] = fopen(argv[i+3], "r")) == NULL) {
			save_err = errno;
			(void) fprintf(stderr, "diff3: can't open %s: ",
				argv[i+3]);
			errno = save_err;
			perror("");
			exit(1);
		}
	merge(m, n);
	return (0);
}

/*
 * pick up the line numbers of all changes from
 * one change file
 * (this puts the numbers in a vector, which is not
 * strictly necessary, since the vector is processed
 * in one sequential pass. The vector could be optimized
 * out of existence)
 */

static int
readin(char *name, struct diff *dd)
{
	int i;
	int a, b, c, d;
	char kind;
	char *p;
	if ((fp[0] = fopen(name, "r")) == NULL) {
		save_err = errno;
		(void) fprintf(stderr, "diff3: can't open %s: ", name);
		errno = save_err;
		perror("");
		exit(1);
	}
	for (i = 0; getchange(fp[0]); i++) {
		if (i >= NC) {
			(void) fprintf(stderr, "diff3: too many changes\n");
			exit(0);
		}
		p = line;
		a = b = number(&p);
		if (*p == ',') {
			p++;
			b = number(&p);
		}
		kind = *p++;
		c = d = number(&p);
		if (*p == ',') {
			p++;
			d = number(&p);
		}
		if (kind == 'a')
			a++;
		if (kind == 'd')
			c++;
		b++;
		d++;
		dd[i].old.from = a;
		dd[i].old.to = b;
		dd[i].new.from = c;
		dd[i].new.to = d;
	}
	dd[i].old.from = dd[i-1].old.to;
	dd[i].new.from = dd[i-1].new.to;
	(void) fclose(fp[0]);
	return (i);
}

static int
number(char **lc)
{
	int nn;
	nn = 0;
	while (digit(**lc))
		nn = nn*10 + *(*lc)++ - '0';
	return (nn);
}

static int
digit(int c)
{
	return (c >= '0' && c <= '9');
}

static int
getchange(FILE *b)
{
	while (getline(b))
		if (digit(line[0]))
			return (1);
	return (0);
}

static int
getline(FILE *b)
{
	int i, c;
	for (i = 0; i < sizeof (line)-1; i++) {
		c = getc(b);
		if (c == EOF) {
			line[i] = 0;
			return (i);
		}
		line[i] = c;
		if (c == '\n') {
			line[++i] = 0;
			return (i);
		}
	}
	return (0);
}

static void
merge(int m1, int m2)
{
	struct diff *d1, *d2, *d3;
	int dup;
	int j;
	int t1, t2;
	d1 = d13;
	d2 = d23;
	j = 0;
	for (; (t1 = d1 < d13+m1) | (t2 = d2 < d23+m2); ) {
		if (debug) {
			(void) printf("%d,%d=%d,%d %d,%d=%d,%d\n",
			d1->old.from, d1->old.to,
			d1->new.from, d1->new.to,
			d2->old.from, d2->old.to,
			d2->new.from, d2->new.to);
		}

		/* first file is different from others */
		if (!t2 || t1 && d1->new.to < d2->new.from) {
			/* stuff peculiar to 1st file */
			if (eflag == 0) {
				separate("1");
				change(1, &d1->old, 0);
				keep(2, &d1->new);
				change(3, &d1->new, 0);
			}
			d1++;
			continue;
		}

		/* second file is different from others */
		if (!t1 || t2 && d2->new.to < d1->new.from) {
			if (eflag == 0) {
				separate("2");
				keep(1, &d2->new);
				change(2, &d2->old, 0);
				change(3, &d2->new, 0);
			}
			d2++;
			continue;
		}
		/*
		 * merge overlapping changes in first file
		 * this happens after extension see below
		 */
		if (d1+1 < d13+m1 && d1->new.to >= d1[1].new.from) {
			d1[1].old.from = d1->old.from;
			d1[1].new.from = d1->new.from;
			d1++;
			continue;
		}

		/* merge overlapping changes in second */
		if (d2+1 < d23+m2 && d2->new.to >= d2[1].new.from) {
			d2[1].old.from = d2->old.from;
			d2[1].new.from = d2->new.from;
			d2++;
			continue;
		}

		/* stuff peculiar to third file or different in all */
		if (d1->new.from == d2->new.from && d1->new.to == d2->new.to) {
			dup = duplicate(&d1->old, &d2->old);
			/*
			 * dup = 0 means all files differ
			 * dup = 1 meands files 1&2 identical
			 */
			if (eflag == 0) {
				separate(dup?"3":"");
				change(1, &d1->old, dup);
				change(2, &d2->old, 0);
				d3 = d1->old.to > d1->old.from ? d1 : d2;
				change(3, &d3->new, 0);
			} else
				j = edit(d1, dup, j);
			d1++;
			d2++;
			continue;
		}
		/*
		 * overlapping changes from file1 & 2
		 * extend changes appropriately to
		 * make them coincide
		 */
		if (d1->new.from < d2->new.from) {
			d2->old.from -= d2->new.from-d1->new.from;
			d2->new.from = d1->new.from;
		} else if (d2->new.from < d1->new.from) {
			d1->old.from -= d1->new.from-d2->new.from;
			d1->new.from = d2->new.from;
		}

		if (d1->new.to > d2->new.to) {
			d2->old.to += d1->new.to - d2->new.to;
			d2->new.to = d1->new.to;
		} else if (d2->new.to > d1->new.to) {
			d1->old.to += d2->new.to - d1->new.to;
			d1->new.to = d2->new.to;
		}
	}
	if (eflag) {
		edscript(j);
		if (j)
			(void) printf("w\nq\n");
	}
}

static void
separate(char *s)
{
	(void) printf("====%s\n", s);
}

/*
 * the range of ines rold.from thru rold.to in file i
 * is to be changed. it is to be printed only if
 * it does not duplicate something to be printed later
 */
static void
change(int i, struct range *rold, int dup)
{
	(void) printf("%d:", i);
	last[i] = rold->to;
	prange(rold);
	if (dup)
		return;
	if (debug)
		return;
	i--;
	(void) skip(i, rold->from, (char *)0);
	(void) skip(i, rold->to, "  ");
}

/*
 * print the range of line numbers, rold.from  thru rold.to
 * as n1, n2 or n1
 */
static void
prange(struct range *rold)
{
	if (rold->to <= rold->from)
		(void) printf("%da\n", rold->from-1);
	else {
		(void) printf("%d", rold->from);
		if (rold->to > rold->from+1)
			(void) printf(",%d", rold->to-1);
		(void) printf("c\n");
	}
}

/*
 * no difference was reported by diff between file 1(or 2)
 * and file 3, and an artificial dummy difference (trange)
 * must be ginned up to correspond to the change reported
 * in the other file
 */
static void
keep(int i, struct range *rnew)
{
	int delta;
	struct range trange;
	delta = last[3] - last[i];
	trange.from = rnew->from - delta;
	trange.to = rnew->to - delta;
	change(i, &trange, 1);
}

/*
 * skip to just befor line number from in file i
 * if "pr" is nonzero, print all skipped stuff
 * with string pr as a prefix
 */
static int
skip(int i, int from, char *pr)
{
	int j, n;
	for (n = 0; cline[i] < from-1; n += j) {
		if ((j = getline(fp[i])) == 0)
			trouble();
		if (pr)
			(void) printf("%s%s", pr, line);
		cline[i]++;
	}
	return (n);
}

/*
 * return 1 or 0 according as the old range
 * (in file 1) contains exactly the same data
 * as the new range (in file 2)
 */
static int
duplicate(struct range *r1, struct range *r2)
{
	int c, d;
	int nchar;
	int nline;
	if (r1->to-r1->from != r2->to-r2->from)
		return (0);
	(void) skip(0, r1->from, (char *)0);
	(void) skip(1, r2->from, (char *)0);
	nchar = 0;
	for (nline = 0; nline < r1->to-r1->from; nline++) {
		do {
			c = getc(fp[0]);
			d = getc(fp[1]);
			if (c == -1 || d == -1)
				trouble();
			nchar++;
			if (c != d) {
				repos(nchar);
				return (0);
			}
		} while (c != '\n');
	}
	repos(nchar);
	return (1);
}

static void
repos(int nchar)
{
	int i;
	for (i = 0; i < 2; i++)
		(void) fseek(fp[i], (long)-nchar, 1);
}

static void
trouble()
{
	(void) fprintf(stderr, "diff3: logic error\n");
	abort();
}

/*
 * collect an editing script for later regurgitation
 */
static int
edit(struct diff *diff, int dup, int j)
{
	if (((dup+1)&eflag) == 0)
		return (j);
	j++;
	overlap[j] = !dup;
	if (!dup) overlapcnt++;
	de[j].old.from = diff->old.from;
	de[j].old.to = diff->old.to;
	de[j].new.from = de[j-1].new.to + skip(2, diff->new.from, (char *)0);
	de[j].new.to = de[j].new.from + skip(2, diff->new.to, (char *)0);
	return (j);
}

/*		regurgitate */
static void
edscript(int n)
{
	int j, k;
	char	 block[BUFSIZ];

	for (n = n; n > 0; n--) {
		if (!oflag || !overlap[n])
			prange(&de[n].old);
		else
			(void) printf("%da\n=======\n", de[n].old.to -1);
		(void) fseek(fp[2], (long)de[n].new.from, 0);
		for (k = de[n].new.to-de[n].new.from; k > 0; k -= j) {
			j = k > BUFSIZ?BUFSIZ:k;
			if (fread(block, 1, j, fp[2]) != j)
				trouble();
			(void) fwrite(block, 1, j, stdout);
		}
		if (!oflag || !overlap[n])
			(void) printf(".\n");
		else {
			(void) printf("%s\n.\n", f3mark);
			(void) printf("%da\n%s\n.\n", de[n].old.from-1, f1mark);
		}
	}
}

static void
usage()
{
	(void) fprintf(stderr,
	    "\tusage: diff3prog [-ex3EX] d13 d23 f1 f2 f3 [m1 m2]\n");
	exit(1);
}
