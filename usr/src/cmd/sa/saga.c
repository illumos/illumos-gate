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
#include <limits.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char	fld[NFLD][10];
char	cmd[300];
long	sardoff;
FILE	*sard;

static void printar(struct array *ptr);
static void parse(struct p *p);
static void plot(struct p[], int, char *, char *, char *, char *);
static void scale(struct p[], int, char *, char *, char *, char *);

int
main(int argc, char *argv[])
{
	extern	char	cmd[];
	extern	char	fld[NFLD][FLDCH];
	char	sarg[10];
	char	earg[10];
	char	iarg[10];
	char	farg[PATH_MAX + 4];
	char	yarg[200];
	char	xarg[100];
	char	Targ[10];
	char	title[60];
	int	nplot, nchar;
	int	n, i;
	char	xlab_s[10], xlab_e[10];

	struct	p	p[6];

	char	sardfile[20];
	int	c;
	char	temp[80];
	char	*strcpy();

	*Targ = '\0';

	strcpy(sarg, "-s 08:00");
	strcpy(earg, "-e 18:00");
	strcpy(iarg, "");
	strcpy(farg, "");
#ifndef u370
	strcpy(
	    yarg, "%usr 0 100; %usr + %sys 0 100; %usr + %sys + %wio 0 100");
#else
	strcpy(yarg,
	    "%usr 0 100; %usr + %usup 0 100; %usr + %usup + %tss 0 100");
#endif
	strcpy(xarg, "time");

	while ((c = getopt(argc, argv, "s:e:i:f:y:x:T:")) != EOF)
		switch (c) {
		case 's':
			strcpy(sarg, "-s ");
			if (strlcat(sarg, optarg, sizeof (sarg)) >=
			    sizeof (sarg)) {
				fprintf(stderr,
				    "-s argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'e':
			strcpy(earg, "-e ");
			if (strlcat(earg, optarg, sizeof (earg)) >=
			    sizeof (earg)) {
				fprintf(stderr,
				    "-e argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'i':
			strcpy(iarg, "-i ");
			if (strlcat(iarg, optarg, sizeof (iarg)) >=
			    sizeof (iarg)) {
				fprintf(stderr,
				    "-i argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'f':
			strcpy(farg, "-f ");
			if (strlcat(farg, optarg, sizeof (farg)) >=
			    sizeof (farg)) {
				fprintf(stderr,
				    "-f argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'y':
			if (strlcat(yarg, optarg, sizeof (yarg)) >=
			    sizeof (yarg)) {
				fprintf(stderr,
				    "-y argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'x':
			if (strlcat(xarg, optarg, sizeof (xarg)) >=
			    sizeof (xarg)) {
				fprintf(stderr,
				    "-x argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case 'T':
			strcpy(Targ, "-T");
			if (strlcat(Targ, optarg, sizeof (Targ)) >=
			    sizeof (Targ)) {
				fprintf(stderr,
				    "-T argument too long: %s\n", optarg);
				exit(1);
			}
			break;
		case '?':
			fprintf(stderr,
			    "Usage: sag -s hh:mm -e hh:mm -i "
			    "sec -f safile -T term\n");
			fprintf(stderr,
			    "\t -x \"spec\" -y \"spec[;spec]...\"\n");
			fprintf(stderr,
			    "\twhere spec is name[ op name]...[lo hi]\n");
			fprintf(stderr,
			    "\tand name is a hdrstr that may include "
			    "[devstr]\n");
			exit(2);
		}
	for (; optind < argc; optind++)
		fprintf(stderr, "\"%s\" ignored\n", argv[optind]);
	/*
	 * Test xarg, break yarg into ";" separated graph commands
	 */

	*temp = '\0';
	*(p[0].spec) = '\0';
	sscanf(xarg, "%[^;];%s", p[0].spec, temp);
	if (stribl(temp) > 0) {
		fprintf(stderr,
		    "More than one x-axis spec not allowed:\n%s\n", xarg);
		exit(2);
	}
	for (nplot = nchar = 0, i = 1; i < 6; ) {
		*temp = '\0';
		*(p[i].spec) = '\0';
		n = sscanf(yarg+nchar, "%[^;]%s", p[i].spec, temp);
		nchar += strlen(p[i].spec) + 1;
		if (stribl(p[i].spec) > 0) {
			nplot++;
			i++;
		}
		if (n < 2)
			break;
	}
	if (DEBUG) {
		fprintf(stderr, "nplot:%d\n", nplot);
		for (i = 0; i < 6; i++)
			fprintf(stderr, "p[%d].spec:%s\n", i, p[i].spec);
	}
	/*
	 *	Parse each spec
	 */
	for (i = 0; i <= nplot; i++)
		parse(&p[i]);

	/*
	 *	Run sar, with output to sardfile.
	 */
	sprintf(sardfile, "/tmp/sard%ld", getpid());
	sprintf(cmd, "sar -ubdycwaqmvpr %s %s %s %s | sed "
	    "-e '/:/h' "
	    "-e '/:/s/ .*//' "
	    "-e '/:/x' "
	    "-e '/^	/G' "
	    "-e '/^	/s/\\(.*\\)\\n\\(.*\\)/\\2\\1/' "
	    "-e '/proc-sz/,$s/\\/ */\\//g' "
	    "-e '/proc-sz/,$s/\\/[^	 ]*//g' "
	    "-e 's/	/ /g' "
	    "-e 's/  */ /g' "
	    "-e '/^ /s///' "
	    "-e '/^$/d' "
	    "> %s",
	    sarg, earg, iarg, farg, sardfile);
	system(cmd);

	sard = fopen(sardfile, "r");
	if ((n = getfld()) == EOF) {
		fprintf(stderr, "No sar data!\n");
		exit(2);
	}
	sardoff = ftell(sard);
	for (i = 0; i < n; i++) {
		strcat(title, fld[i]);
		strcat(title, " ");
	}

	for (i = 0; i <= nplot; i++)
		if (reduce(&p[i]) < 0) {
			fprintf(stderr, "Can't reduce %s\n", p[i].spec);
			exit(2);
		}
		else
			if (DEBUG > 1)  printar(p[i].c[0].dptr);

	fclose(sard);

	scale(p, nplot, sarg, earg, xlab_s, xlab_e);

	plot(p, nplot, xlab_s, xlab_e, title, Targ);
	unlink(sardfile);
	exit(0);
}

static void
printar(struct array *ptr)
{
	int	i;

	fprintf(stderr, "hname:%s\n", ptr->hname);
	for (i = 0; i < NPTS; i++) {
		if (ptr->ent[i].hr == 0)
			break;
		fprintf(stderr, "tm:%s   hr:%f   val:%f   qfld:%s\n",
			ptr->ent[i].tm,
			ptr->ent[i].hr,
			ptr->ent[i].val,
			ptr->ent[i].qfld);
	}
}

/*
 *	Parses command string for one graph parameter
 *	found in p->spec, placing field names in p->c[j].name,
 *	operators in p->c[j].op, and ranges in p->mn, p->mx, p->min, and p->max
 */
static void
parse(struct p *p)
{
	int	n, j;
	char	f[11][18];
	char	*strcpy();

	n = sscanf(p->spec,
		"%s %s %s %s %s %s %s %s %s %s %s ",
		f[0], f[1], f[2], f[3], f[4], f[5],
		f[6], f[7], f[8], f[9], f[10]);
	if (n % 2 == 0)
		fprintf(stderr, "Can't parse:%s:\nNeed odd # of arg's\n",
		    p->spec);
	for (j = 0; j < n; j += 2) {
		strcpy(p->c[j/2].name, f[j]);
		p->c[j/2].dptr = NULL;
		if (j == n-1) {
			p->c[j/2].op = '\0';
			break;
		} else if ((strcmp(f[j+1], "+") == 0) ||
		    (strcmp(f[j+1], "-") == 0) ||
		    (strcmp(f[j+1], "*") == 0) ||
		    (strcmp(f[j+1], "/") == 0))
			p->c[j/2].op = f[j+1][0];
		else {
			p->c[j/2].op = '\0';
			strcpy(p->mn, f[j+1]);
			strcpy(p->mx, f[j+2]);
			p->min = (float)atoi(p->mn);
			p->max = (float)atoi(p->mx);
			break;
		}
	}
	if (DEBUG) {
		for (n = 0; n <= j/2; n++)
			fprintf(stderr, "\"%s\" %c ",
			    p->c[n].name, p->c[n].op);
		fprintf(stderr, ", limits: %f %f\n", p->min, p->max);
	}
}

static void
plot(struct p p[], int nplot, char *xlab_s, char *xlab_e, char *title,
    char *Targ)
{
	extern	char	cmd[];
	FILE	*pipe, *popen();
	static	char	pchar[] = {'+', '-', '=', '#', 'o', 'x'};
	char	plotfile[20];
	int	i;
	int	a, b;
	struct	array	*ara, *arb;

	sprintf(plotfile, "/tmp/sag%ld", getpid());

	/*	Construct graph commands for left edge labels		*/

	sprintf(cmd, "graph -x 0 1 -y 0 1 -r 0 -h .8 -u .2 -g 0 -b > %s",
		plotfile);
	fflush(stdout);
	if (pipe = popen(cmd, "w")) {
		for (i = 1; i <= nplot; i++)
		fprintf(pipe, "%.3f %.3f \"%c%3.0f\"\n",
			0., (1-.02*(float)(i-1)), pchar[i-1], p[i].max);
		for (i = 1; i <= nplot; i++)
		fprintf(pipe, "%.3f %.3f \"%c%3.0f\"\n",
			0., (0+.02*(float)(i-1)), pchar[i-1], p[i].min);
		pclose(pipe);
	}

	/*	Construct graph commands for bottom labels and title	*/

	sprintf(cmd, "graph -x 0 1 -y 0 1 -r .1 -h .8 -u 0 -g 0 -b -s >> %s",
		plotfile);
	fflush(stdout);
	if (pipe = popen(cmd, "w")) {
		fprintf(pipe, "%.3f %.3f \"%s\"\n%.3f %.3f \"%s\"\n",
			0., .22, xlab_s,
			1., .22, xlab_e);
		for (i = 1; i <= nplot; i++)
			fprintf(pipe, "%.3f %.3f \"%c  %s\"\n",
				.05, (.18 -.18*(float)(i-1)/5),
				pchar[i-1], p[i].c[0].dptr->hname);
		fprintf(pipe, "%.3f %.3f \"vs %s\"\n",
			.05, (.18 -.18*(float)nplot/5), p[0].c[0].dptr->hname);
		fprintf(pipe, "%.3f %.3f \"%s\"\n",
			.5 - (float)strlen(title)/(5.75*10.*2.), .22, title);
		pclose(pipe);
	}

	/*	Form grid	*/

	sprintf(cmd,
	    "graph -x %.3f %.3f -y 0 1 -r .1 -h .8 -u .2 -g 1 -s >> %s",
	    p[0].min, p[0].max, plotfile);
	fflush(stdout);
	if (pipe = popen(cmd, "w"))
		pclose(pipe);

	/*	Construct graph commands for plotting, nplot cases	*/

	for (i = 1; i <= nplot; i++) {
		if (p[i].mode == 0)
		sprintf(cmd, "graph -x %.3f %.3f -y %.3f %.3f -r "
		    ".1 -h .8 -u .2 -g 0 -s -m %d -c \"%c\" >> %s",
			p[0].min, p[0].max, p[i].min, p[i].max,
			(strmatch("time", p[0].spec) >= 0 ? 1 : 0),
			pchar[i-1], plotfile);
		else
		sprintf(cmd, "graph -x %.3f %.3f -y %.3f %.3f -r "
		    ".1 -h .8 -u .2 -g 0 -s -m 0 >> %s",
			p[0].min, p[0].max, p[i].min, p[i].max,
			plotfile);
		fflush(stdout);
		if (pipe = popen(cmd, "w")) {
			ara = p[0].c[0].dptr;
			arb = p[i].c[0].dptr;
			for (a = b = 0; a < NPTS && b < NPTS; ) {
				if ((ara->ent[a].hr == 0) ||
				    (arb->ent[b].hr == 0))
					break;
				if (ara->ent[a].hr < arb->ent[b].hr) {
					/*   b data missing   */
					fprintf(pipe, "%.3f %.3f\n",
						ara->ent[a].val, -100.);
					a++;
				} else if (ara->ent[a].hr > arb->ent[b].hr) {
					/*   error - a missing   */
					fprintf(pipe, "%.3 %.3f\n",
						ara->ent[a].val, -100.);
					b++;
				} else {	/*   a & b hr agree  */
					if (p[i].mode == 0)
						fprintf(pipe, "%.3f %.3f\n",
						    ara->ent[a].val,
						    arb->ent[b].val);
					else
						fprintf(pipe,
						    "%.3f %.3f \"%c\"\n",
						    ara->ent[a].val,
						    arb->ent[b].val,
						    arb->ent[b].qfld[
						    strlen(
						    arb->ent[b].qfld) - 1]);
			/*
			 *	Test which index can be incremented without
			 *	incurring a change in ..hr
			 */
					if ((ara->ent[a+1].hr ==
					    ara->ent[a].hr) &&
					    (arb->ent[b+1].hr !=
					    arb->ent[b].hr))
						/* a free, b constrained  */
						a++;
					else if ((ara->ent[a+1].hr !=
					    ara->ent[a].hr) &&
					    (arb->ent[b+1].hr ==
					    arb->ent[b].hr))
						/* a constrained, b free  */
						b++;
					else {
						/* Both free or constrained */
						a++;
						b++;
					}
				}
			}
			pclose(pipe);
		}
	}
	sprintf(cmd, "tplot %s < %s", Targ, plotfile);
	fflush(stdout);
	system(cmd);
	sprintf(cmd, "rm %s", plotfile);
	fflush(stdout);
	system(cmd);
}

int
reduce(struct p *pr)
{
	int	i, j;
	struct	array	*popar();

	for (i = 0; i < 4; ) {
		if (DEBUG) {
			fprintf(stderr, "reduce pr->spec:%s\n", pr->spec);
			fprintf(stderr, "pr->c[%d].op:%c\n", i, pr->c[i].op);
		}
		switch (pr->c[i].op) {
		case '+':
		case '-':
			for (j = i; j < i+2; j++)
				if (pr->c[j].dptr == NULL)
					if (getdata(pr->c[j].name,
					    pr->c[j].dptr = popar()) < 0)
						return (-1);
			combine(pr, i);
			break;
		case '\0':
			if (pr->c[i].dptr == NULL)
				if (getdata(pr->c[i].name,
				    pr->c[i].dptr = popar()) < 0)
					return (-1);
			if (i == 0)
				return (0);
			else
				goto muldiv;
			break;
		default:
			i++;
			break;
		}
	}

	muldiv:
	while (pr->c[0].op != '\0') {
		if (DEBUG)
			fprintf(stderr, "pr->c[\"0\"].op:%c\n", pr->c[0].op);
		for (j = 0; j < 2; j++)
			if (pr->c[j].dptr == NULL)
				if (getdata(pr->c[j].name,
				    pr->c[j].dptr = popar()) < 0)
					return (-1);
		combine(pr, 0);
	}
	return (0);
}

static void
scale(struct p p[], int nplot, char *sarg, char *earg, char *xlab_s,
    char *xlab_e)
{
	/*
	 *	Scans each data set to find and label those that contain
	 *	multiple entries.  Also truncates data values to fit within
	 *	given plotting limits, or if unspecified, finds max value
	 *	over all such data sets and sets their limits.
	 *	If p[0] contains "time" values, its limits are taken from
	 *	the -s and -e args.
	 */

	float	yrange();
	char	*strcpy();
	int	i = 0;
	int	j;
	struct	array	*ara;
	float	maxd = -1000;
	float	hrb;
	float	hr, min;

	if (strmatch("time", p[0].spec) >= 0) {
		sscanf(sarg, "-s %s", xlab_s);
		hr = min = 0;
		sscanf(sarg, "-s %f:%f", &hr, &min);
		p[0].min = hr + min/60;
		sscanf(earg, "-e %s", xlab_e);
		hr = min = 0;
		sscanf(earg, "-e %f:%f", &hr, &min);
		p[0].max = hr + min/60;
		p[0].mode = 0;
		i = 1;
	}
	for (; i <= nplot; i++) {
		p[i].mode = 0;
		hrb = 0;
		ara = p[i].c[0].dptr;

		for (j = 0; j < NPTS; j++) {
			if (ara->ent[j].hr == 0)
				break;
			if (p[i].max > 0) {
				ara->ent[j].val = (ara->ent[j].val >
				    p[i].max) ? p[i].max : ara->ent[j].val;
				if (ara->ent[j].val > -1000.)
					ara->ent[j].val =
					    (ara->ent[j].val < p[i].min) ?
					    p[i].min : ara->ent[j].val;
			}
			else
				maxd = (ara->ent[j].val > maxd) ?
					ara->ent[j].val : maxd;
			if (ara->ent[j].hr == hrb)
				p[i].mode = 1;
			hrb = ara->ent[j].hr;
		}

		if (i == 0) {
			if (p[0].max == 0) {
				p[0].min = 0;
				p[0].max = yrange(maxd);
				maxd = -1000;
			}
			sprintf(xlab_s, "%1.1f", p[0].min);
			sprintf(xlab_e, "%1.1f", p[0].max);
		}
	}

	/*
	 * Now that data range has been found, set limits of unspecified
	 * cases
	 */
	for (i = 1; i <= nplot; i++)
		if (p[i].max == 0) {
			p[i].max = yrange(maxd);
			p[i].min = 0;
			if (p[i].max == 0)
				p[i].max = 1.;
		}
}
