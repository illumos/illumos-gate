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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
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

/* Note added 9/25/83
	Setting the parameter biggestfont in the DESC file
	to be at least as big as the number of characters
	in the largest font for a particular device
	eliminates the "font X too big for position Y"
	message from troff.
	Thanks to Dave Stephens, WECo.
*/
/*
  makedev:
	read text info about a particular device
	(e.g., cat, 202, aps5) from file, convert
	it into internal (binary) form suitable for
	fast reading by troff initialization (ptinit()).

	Usage:

	makedev DESC [ F ... ]
		uses DESC to create a description file
		using the information therein.
		It creates the file DESC.out.

	makedev F ...
		makes the font tables for fonts F only,
		creates files F.out.

	DESC.out contains:
	dev structure with fundamental sizes
	list of sizes (nsizes+1) terminated by 0, as short's
	indices of char names (nchtab * sizeof(short))
	char names as hy\0em\0... (lchname)
	nfonts occurrences of
		widths (nwidth)
		kerning (nwidth) [ascender+descender only so far]
		codes (nwidth) to drive actual typesetter
		fitab (nchtab+128-32)
	each of these is an array of char.

	dev.filesize contains the number of bytes
	in the file, excluding the dev part itself.

	F.out contains the font header, width, kern, codes, and fitab.
	Width, kern and codes are parallel arrays.
	(Which suggests that they ought to be together?)
	Later, we might allow for codes which are actually
	sequences of formatting info so characters can be drawn.
*/

#include	"stdio.h"
#include	"dev.h"

#define	BYTEMASK	0377
#define	skipline(f)	while(getc(f) != '\n')

struct	dev	dev;
struct	Font	font;

#define	NSIZE	100	/* maximum number of sizes */
short	size[NSIZE];
#define	NCH	256	/* max number of characters with funny names */
char	chname[5*NCH];	/* character names, including \0 for each */
short	chtab[NCH];	/* index of character in chname */

#define	NFITAB	(NCH + 128-32)	/* includes ascii chars, but not non-graphics */
char	fitab[NFITAB];	/* font index table: position of char i on this font. */
			/* zero if not there */

#define	FSIZE	256	/* size of a physical font (e.g., 102 for cat) */
char	width[FSIZE];	/* width table for a physical font */
char	kern[FSIZE];	/* ascender+descender info */
char	code[FSIZE];	/* actual device codes for a physical font */

#define	NFONT	60	/* max number of default fonts */
char	fname[NFONT][10];	/* temp space to hold default font names */

int	fflag	= 0;	/* on if font table to be written */
int	fdout;	/* output file descriptor */
char	*fout	= "DESC.out";

int main(int argc, char *argv[])
{
	FILE *fin;
	char cmd[100], *p;
	int i, totfont, v;

    if (argc < 2) {
        fprintf(stderr, "Usage:  makedev [DESC] [fonts]\n");
        exit(1);
    }

	if ((fin = fopen("DESC", "r")) == NULL) {
		fprintf(stderr, "makedev: can't open %s\n", argv[1]);
		exit(1);
	}
	while (fscanf(fin, "%s", cmd) != EOF) {
		if (cmd[0] == '#')	/* comment */
			skipline(fin);
		else if (strcmp(cmd, "res") == 0) {
			fscanf(fin, "%hd", &dev.res);
		} else if (strcmp(cmd, "hor") == 0) {
			fscanf(fin, "%hd", &dev.hor);
		} else if (strcmp(cmd, "vert") == 0) {
			fscanf(fin, "%hd", &dev.vert);
		} else if (strcmp(cmd, "unitwidth") == 0) {
			fscanf(fin, "%hd", &dev.unitwidth);
		} else if (strcmp(cmd, "sizescale") == 0) {
			fscanf(fin, "%hd", &dev.sizescale);
		} else if (strcmp(cmd, "paperwidth") == 0) {
			fscanf(fin, "%hd", &dev.paperwidth);
		} else if (strcmp(cmd, "paperlength") == 0) {
			fscanf(fin, "%hd", &dev.paperlength);
		} else if (strcmp(cmd, "biggestfont") == 0) {
			fscanf(fin, "%hd", &dev.biggestfont);
		} else if (strcmp(cmd, "spare2") == 0) {
			fscanf(fin, "%hd", &dev.spare2);
		} else if (strcmp(cmd, "sizes") == 0) {
			dev.nsizes = 0;
			while (fscanf(fin, "%d", &v) != EOF && v != 0)
				size[dev.nsizes++] = v;
			size[dev.nsizes] = 0;	/* need an extra 0 at the end */
		} else if (strcmp(cmd, "fonts") == 0) {
			fscanf(fin, "%hd", &dev.nfonts);
			for (i = 0; i < dev.nfonts; i++)
				fscanf(fin, "%s", fname[i]);
		} else if (strcmp(cmd, "charset") == 0) {
			p = chname;
			dev.nchtab = 0;
			while (fscanf(fin, "%s", p) != EOF) {
				chtab[dev.nchtab++] = p - chname;
				while (*p++)	/* skip to end of name */
					;
			}
			dev.lchname = p - chname;
			chtab[dev.nchtab++] = 0;	/* terminate properly */
		} else
			fprintf(stderr, "makedev: unknown command %s\n", cmd);
	}
	if (argc > 0 && strcmp(argv[1], "DESC") == 0) {
		fdout = creat(fout, 0666);
		if (fdout < 0) {
			fprintf(stderr, "makedev: can't open %s\n", fout);
			exit(1);
		}
		write(fdout, &dev, sizeof(struct dev));
		write(fdout, size, (dev.nsizes+1) * sizeof(size[0]));	/* we need a 0 on the end */
		write(fdout, chtab, dev.nchtab * sizeof(chtab[0]));
		write(fdout, chname, dev.lchname);
		totfont = 0;
		for (i = 0; i < dev.nfonts; i++) {
			totfont += dofont(fname[i]);
			write(fdout, &font, sizeof(struct Font));
			write(fdout, width, font.nwfont & BYTEMASK);
			write(fdout, kern, font.nwfont & BYTEMASK);
			write(fdout, code, font.nwfont & BYTEMASK);
			write(fdout, fitab, dev.nchtab+128-32);
		}
		lseek(fdout, 0L, 0);	/* back to beginning to install proper size */
		dev.filesize =		/* excluding dev struct itself */
			(dev.nsizes+1) * sizeof(size[0])
			+ dev.nchtab * sizeof(chtab[0])
			+ dev.lchname * sizeof(char)
			+ totfont * sizeof(char);
		write(fdout, &dev, sizeof(struct dev));
		close(fdout);
		argc--;
		argv++;
	}
	for (i = 1; i < argc; i++)
		dofont(argv[i]);
	exit(0);

	return (0);
}

int
dofont(name)	/* create fitab and width tab for font */
char *name;
{
	FILE *fin;
	int fdout;
	int i, nw, spacewidth, n, v;
	char buf[100], ch[10], s1[10], s2[10], s3[10], cmd[30];

	if ((fin = fopen(name, "r")) == NULL) {
		fprintf(stderr, "makedev: can't open font %s\n", name);
		exit(2);
	}
	sprintf(cmd, "%s.out", name);
	fdout = creat(cmd, 0666);
	for (i = 0; i < NFITAB; i++)
		fitab[i] = 0;
	for (i = 0; i < FSIZE; i++)
		width[i] = kern[i] = code[i] = 0;
	font.specfont = font.ligfont = spacewidth = 0;
	while (fscanf(fin, "%s", cmd) != EOF) {
		if (cmd[0] == '#')
			skipline(fin);
		else if (strcmp(cmd, "name") == 0)
			fscanf(fin, "%s", font.namefont);
		else if (strcmp(cmd, "internalname") == 0)
			fscanf(fin, "%s", font.intname);
		else if (strcmp(cmd, "special") == 0)
			font.specfont = 1;
		else if (strcmp(cmd, "spare1") == 0)
			fscanf(fin, "%1s", &font.spare1);
		else if (strcmp(cmd, "ligatures") == 0) {
			font.ligfont = getlig(fin);
		} else if (strcmp(cmd, "spacewidth") == 0) {
			fscanf(fin, "%d", &spacewidth);
			width[0] = spacewidth;	/* width of space on this font */
		} else if (strcmp(cmd, "charset") == 0) {
			skipline(fin);
			nw = 0;
			/* widths are origin 1 so fitab==0 can mean "not there" */
			while (fgets(buf, 100, fin) != NULL) {
				sscanf(buf, "%s %s %s %s", ch, s1, s2, s3);
				if (s1[0] != '"') {	/* it's a genuine new character */
					nw++;
					width[nw] = atoi(s1);
					kern[nw] = atoi(s2);
					/* temporarily, pick up one byte as code */
					if (s3[0] == '0')
						sscanf(s3, "%o", &i);
					else
						sscanf(s3, "%d", &i);
					code[nw] = i;
				}
				/*
				 * otherwise it's a synonym for previous character,
				 * so leave previous values intact
				*/
				if (strlen(ch) == 1)	/* it's ascii */
					fitab[ch[0] - 32] = nw;	/* fitab origin omits non-graphics */
				else {		/* it has a funny name */
					for (i = 0; i < dev.nchtab; i++)
						if (strcmp(&chname[chtab[i]], ch) == 0) {
							fitab[i + 128-32] = nw;	/* starts after the ascii */
							break;
						}
					if (i >= dev.nchtab)
						fprintf(stderr, "makedev: font %s: %s not in charset\n", name, ch);
				}
			}
			nw++;
			if (dev.biggestfont >= nw)
				n = dev.biggestfont;
			else {
				if (dev.biggestfont > 0)
					fprintf(stderr, "font %s too big\n", name);
				n = nw;
			}
			font.nwfont = n;
		}
	}
	if (spacewidth == 0)
		width[0] = dev.res * dev.unitwidth / 72 / 3;
	fclose(fin);

	write(fdout, &font, sizeof(struct Font));
	write(fdout, width, font.nwfont & BYTEMASK);
	write(fdout, kern, font.nwfont & BYTEMASK);
	write(fdout, code, font.nwfont & BYTEMASK);
	write(fdout, fitab, dev.nchtab+128-32);
	close(fdout);
	v = sizeof(struct Font) + 3 * n + dev.nchtab + 128-32;
	fprintf(stderr, "%3s: %3d chars, width %3d, size %3d\n",
		font.namefont, nw, width[0], v);
	return v;
}

int
getlig(fin)	/* pick up ligature list */
	FILE *fin;
{
	int lig;
	char temp[100];

	lig = 0;
	while (fscanf(fin, "%s", temp) != EOF && strcmp(temp, "0") != 0) {
		if (strcmp(temp, "fi") == 0)
			lig |= LFI;
		else if (strcmp(temp, "fl") == 0)
			lig |= LFL;
		else if (strcmp(temp, "ff") == 0)
			lig |= LFF;
		else if (strcmp(temp, "ffi") == 0)
			lig |= LFFI;
		else if (strcmp(temp, "ffl") == 0)
			lig |= LFFL;
		else
			fprintf(stderr, "illegal ligature %s\n", temp);
	}
	skipline(fin);
	return lig;
}
