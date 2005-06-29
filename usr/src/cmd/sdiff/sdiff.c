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

	/*
	 *	sdiff [-l] [-s] [-w #] [-o output] file1 file2
	 *	does side by side diff listing
	 *	-l leftside only for identical lines
	 *	-s silent; only print differences
	 *	-w # width of output
	 *	-o output  interactive creation of new output commands:
	 *		s	silent; do not print identical lines
	 *		v	turn off silent
	 *		l	copy left side to output
	 *		r	copy right side to output
	 *		e l	call ed with left side
	 *		e r	call ed with right side
	 *		e b	call ed with cat of left and right
	 *		e	call ed with empty file
	 *		q	exit from program
	 *
	 *	functions:
	 *	cmd	decode diff commands
	 *	put1	output left side
	 *	put2	output right side
	 *	putmid	output gutter
	 *	putline	output n chars to indicated file
	 *	getlen	calculate length of strings with tabs
	 *	cmdin	read and process interactive cmds
	 *	cpp	copy from file to file
	 *	edit	call ed with file
	 */

#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <limits.h>
#include <string.h>
#include <wchar.h>

#define	LMAX	BUFSIZ
#define	BMAX	BUFSIZ
#define	STDOUT	1
#define	WGUTTER	6
#define	WLEN	(WGUTTER * 2 + WGUTTER + 2)
#define	PROMPT	'%'

static const char	twoblanks[3] = "  ";

static const char	*DIFF	= "diff -b ";
static char	diffcmd[BMAX];
static char	inbuf[10];

static int	llen = 130;	/* Default maximum line length written out */
static int	hlen;		/* Half line length with space for gutter */
static int	len1;		/* Calculated length of left side */
static int	nchars;		/* Number of characters in left side - */
					/* used for tab expansion */
static char	change = ' ';
static int	leftonly = 0;	/* if set print left side only for */
					/* identical lines */
static int	silent = 0;	/* if set do not print identical lines */
static int	midflg = 0;	/* set after middle was output */
static int	rcode = 0;	/* return code */


static char	*file1;
static FILE	*fdes1;

static char	*file2;
static FILE	*fdes2;

static FILE	*diffdes;

static int oflag;
static char	*ofile;
static FILE	*odes;

static char	*ltemp;
static FILE	*left;

static char	*rtemp;
static FILE	*right;

static FILE *tempdes;
static char *temp;

/* decoded diff cmd- left side from to; right side from, to */

static int from1, to1, from2, to2;

static int num1, num2;		/* line count for left side file and right */
static int tempfd = -1;

static char	*filename(char *, char *);
static char	*fgetline(FILE *);
static int	put1(void);
static int	put2(void);
static void	putline(FILE *, char *, int);
static int	cmd(char *);
static int	getlen(int, char *);
static void	putmid(int);
static void	error(char *, char *);
static void	onintr(void);
static void	sremove(void);
static void	cmdin(void);
static void	cpp(char *, FILE *, FILE *);
static void	edit(char *);

int
main(int argc, char **argv)
{
	int	com;
	int	n1, n2, n;
	char	*bp;
	int	lfd = -1;
	int	rfd = -1;

	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		(void) signal((int)SIGHUP, (void (*)(int))onintr);
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		(void) signal((int)SIGINT, (void (*)(int))onintr);
	if (signal(SIGPIPE, SIG_IGN) != SIG_IGN)
		(void) signal((int)SIGPIPE, (void (*)(int))onintr);
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		(void) signal((int)SIGTERM, (void (*)(int))onintr);

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while (--argc > 1 && **++argv == '-') {
		switch (*++*argv) {

		case 'w':
			/* -w# instead of -w # */
			if (*++*argv)
				llen = atoi(*argv);
			else {
				argc--;
				llen = atoi(*++argv);
			}
			if (llen < WLEN)
				error(gettext("Wrong line length %s"), *argv);
			if (llen > LMAX)
				llen = LMAX;
			break;

		case 'l':
			leftonly++;
			break;

		case 's':
			silent++;
			break;
		case 'o':
			oflag++;
			argc--;
			ofile = *++argv;
			break;
		default:
			error(gettext("Illegal argument: %s"), *argv);
		}
	}
	if (argc != 2) {
		(void) fprintf(stderr, gettext(
		"Usage: sdiff [-l] [-s] [-o output] [-w #] file1 file2\n"));
		return (2);
	}

	file1 = *argv++;
	file2 = *argv;
	file1 = filename(file1, file2);
	file2 = filename(file2, file1);
	hlen = (llen - WGUTTER +1)/2;

	if ((fdes1 = fopen(file1, "r")) == NULL)
		error(gettext("Cannot open: %s"), file1);

	if ((fdes2 = fopen(file2, "r")) == NULL)
		error(gettext("Cannot open: %s"), file2);

	if (oflag) {
		if (tempfd == -1) {
			temp = strdup("/tmp/sdiffXXXXXX");
			tempfd = mkstemp(temp);
			if (tempfd == -1) {
				error(gettext(
					"Cannot open/create temp %s"), temp);
				free(temp);
				temp = 0;
			}
		}
		ltemp = strdup("/tmp/sdifflXXXXXX");
		if ((lfd = mkstemp(ltemp)) == -1 ||
			(left = fdopen(lfd, "w")) == NULL)
				error(gettext(
					"Cannot open/create temp %s"),
					ltemp);
		rtemp = strdup("/tmp/sdiffrXXXXXX");
		if ((rfd = mkstemp(rtemp)) == -1 ||
			(right = fdopen(rfd, "w")) == NULL)
				error(gettext(
					"Cannot open/create temp file %s"),
					rtemp);
		if ((odes = fopen(ofile, "w")) == NULL)
			error(gettext("Cannot open output %s"), ofile);
	}
	/* Call DIFF command */
	(void) strcpy(diffcmd, DIFF);
	(void) strcat(diffcmd, file1);
	(void) strcat(diffcmd, " ");
	(void) strcat(diffcmd, file2);
	diffdes = popen(diffcmd, "r");

	num1 = num2 = 0;

	/*
	 * Read in diff output and decode commands
	 * "change" is used to determine character to put in gutter
	 *  num1 and num2 counts the number of lines in file1 and 2
	 */

	n = 0;
	while ((bp = fgetline(diffdes)) != NULL) {
		change = ' ';
		com = cmd(bp);

	/*
	 * handles all diff output that is not cmd
	 * lines starting with <, >, ., ---
	 */
		if (com == 0)
			continue;

	/* Catch up to from1 and from2 */
		rcode = 1;
		n1 = from1 - num1;
		n2 = from2 - num2;
		n = n1 > n2 ? n2 : n1;
		if (com == 'c' && n > 0)
			n--;
		if (silent)
			(void) fputs(bp, stdout);
		while (n-- > 0) {
			(void) put1();
			(void) put2();
			if (!silent)
				(void) putc('\n', stdout);
			midflg = 0;
		}

	/* Process diff cmd */
		switch (com) {

		case 'a':
			change = '>';
			while (num2 < to2) {
				(void) put2();
				(void) putc('\n', stdout);
				midflg = 0;
			}
			break;

		case 'd':
			change = '<';
			while (num1 < to1) {
				(void) put1();
				(void) putc('\n', stdout);
				midflg = 0;
			}
			break;

		case 'c':
			n1 = to1 - from1;
			n2 = to2 - from2;
			n = n1 > n2 ? n2 : n1;
			change = '|';
			do {
				(void) put1();
				(void) put2();
				(void) putc('\n', stdout);
				midflg = 0;
			} while (n--);

			change = '<';
			while (num1 < to1) {
				(void) put1();
				(void) putc('\n', stdout);
				midflg = 0;
			}

			change = '>';
			while (num2 < to2) {
				(void) put2();
				(void) putc('\n', stdout);
				midflg = 0;
			}
			break;

		default:
			(void) fprintf(stderr, gettext(
				"%c: cmd not found\n"), cmd);
			break;
		}

		if (oflag == 1 && com != 0) {
			cmdin();
			if ((left = fopen(ltemp, "w")) == NULL)
				error(gettext(
					"main: Cannot open temp %s"), ltemp);
			if ((right = fopen(rtemp, "w")) == NULL)
				error(gettext(
					"main: Cannot open temp %s"), rtemp);
		}
	}
	/* put out remainder of input files */

	while (put1()) {
		(void) put2();
		if (!silent)
			(void) putc('\n', stdout);
		midflg = 0;
	}
	if (odes)
		(void) fclose(odes);
	sremove();
	return (rcode);
}

static int
put1(void)
{
	/* len1 = length of left side */
	/* nchars = num of chars including tabs */

	char	*bp;


	if ((bp = fgetline(fdes1)) != NULL) {
		len1 = getlen(0, bp);
		if ((!silent || change != ' ') && len1 != 0)
			putline(stdout, bp, nchars);

		if (oflag) {
		/*
		 * put left side either to output file
		 * if identical to right
		 * or left temp file if not
		 */

			if (change == ' ')
				putline(odes, bp, strlen(bp));
			else
				putline(left, bp, strlen(bp));
		}
		if (change != ' ')
			putmid(1);
		num1++;
		return (1);
	} else
		return (0);
}

static int
put2(void)
{
	char	*bp;

	if ((bp = fgetline(fdes2)) != NULL) {
		(void) getlen((hlen + WGUTTER) % 8, bp);

		/*
		 * if the left and right are different they are always
		 * printed.
		 * If the left and right are identical
		 * right is only printed if leftonly is not specified
		 * or silent mode is not specified
		 * or the right contains other than white space (len1 !=0)
		 */
		if (change != ' ') {

		/*
		 * put right side to right temp file only
		 * because left side was written to output for
		 * identical lines
		 */

			if (oflag)
				putline(right, bp, strlen(bp));

			if (midflg == 0)
				putmid(1);
			putline(stdout, bp, nchars);
		} else
			if (!silent && !leftonly && len1 != 0) {
				if (midflg == 0)
					putmid(1);
				putline(stdout, bp, nchars);
			}
		num2++;
		len1 = 0;
		return (1);
	} else {
		len1 = 0;
		return (0);
	}
}

static void
putline(FILE *file, char *start, int num)
{
	char	*cp, *end;
	int	i, len, d_col;
	wchar_t	wc;

	cp = start;
	end = cp + num;
	while (cp < end) {
		if (isascii(*cp)) {
			(void) putc(*cp++, file);
			continue;
		}

		if ((len = end - cp) > MB_LEN_MAX)
			len = MB_LEN_MAX;

		if ((len = mbtowc(&wc, cp, len)) <= 0) {
			(void) putc(*cp++, file);
			continue;
		}

		if ((d_col = wcwidth(wc)) <= 0)
			d_col = len;

		if ((cp + d_col) > end)
			return;

		for (i = 0; i < len; i++)
			(void) putc(*cp++, file);
	}
}

static int
cmd(char *start)
{
	unsigned char	*cp;
	char	*cps;
	int	com;

	if (*start == '>' || *start == '<' || *start == '-' || *start == '.')
		return (0);

	cp = (unsigned char *)start;
	cps = start;
	while (isdigit(*cp))
		cp++;
	from1 = atoi(cps);
	to1 = from1;
	if (*cp == ',') {
		cp++;
		cps = (char *)cp;
		while (isdigit(*cp))
			cp++;
		to1 = atoi(cps);
	}

	com = *cp++;
	cps = (char *)cp;

	while (isdigit(*cp))
		cp++;
	from2 = atoi(cps);
	to2 = from2;
	if (*cp == ',') {
		cp++;
		cps = (char *)cp;
		while (isdigit(*cp))
			cp++;
		to2 = atoi(cps);
	}
	return (com);
}

static int
getlen(int startpos, char *buffer)
{
	/*
	 * get the length of the string in buffer
	 *  expand tabs to next multiple of 8
	 */
	unsigned char	*cp;
	int	slen, tlen, len, d_col;
	int	notspace;
	wchar_t	wc;

	nchars = 0;
	notspace = 0;
	tlen = startpos;
	for (cp = (unsigned char *)buffer; (*cp != '\n') && (*cp); cp++) {
		if (*cp == '\t') {
			slen = tlen;
			tlen += 8 - (tlen % 8);
			if (tlen >= hlen) {
				tlen = slen;
				break;
			}
			nchars++;
			continue;
		}

		if (isascii(*cp)) {
			slen = tlen;
			tlen++;
			if (tlen >= hlen) {
				tlen = slen;
				break;
			}
			if (!isspace(*cp))
				notspace = 1;
			nchars++;
			continue;
		}

		if ((len = mbtowc(&wc, (char *)cp, MB_LEN_MAX)) <= 0) {
			slen = tlen;
			tlen++;
			if (tlen >= hlen) {
				tlen = slen;
				break;
			}
			notspace = 1;
			nchars++;
			continue;
		}

		if ((d_col = wcwidth(wc)) <= 0)
			d_col = len;

		slen = tlen;
		tlen += d_col;
		if (tlen > hlen) {
			tlen = slen;
			break;
		}
		notspace = 1;
		cp += len - 1;
		nchars += len;
	}
	return (notspace ? tlen : 0);
}

static void
putmid(int bflag)
{
	int	i;

	/*
	 * len1 set by getlen to the possibly truncated
	 *  length of left side
	 *  hlen is length of half line
	 */

	midflg = 1;
	if (bflag) {
		for (i = 0; i < hlen - len1; i++)
			(void) putc(' ', stdout);
	}
	(void) fputs(twoblanks, stdout);
	(void) putc((int)change, stdout);
	(void) fputs(twoblanks, stdout);
}

static void
error(char *s1, char *s2)
{
	(void) fprintf(stderr, "sdiff: ");
	(void) fprintf(stderr, s1, s2);
	(void) putc('\n', stderr);
	sremove();
	exit(2);
}

static void
onintr(void)
{
	sremove();
	exit(rcode);
}

static void
sremove(void)
{
	if (ltemp) {
		(void) unlink(ltemp);
		free(ltemp);
	}
	if (rtemp) {
		(void) unlink(rtemp);
		free(rtemp);
	}
	if (temp) {
		(void) unlink(temp);
		free(temp);
	}
}

static void
cmdin(void)
{
	char	*cp, *ename;
	int	notacc;

	(void) fclose(left);
	(void) fclose(right);
	notacc = 1;
	while (notacc) {
		(void) putc(PROMPT, stdout);
		if ((cp = fgets(inbuf, 10, stdin)) == NULL) {
			(void) putc('\n', stdout);
			break;
		}
		switch (*cp) {

		case 's':
			silent = 1;
			break;

		case 'v':
			silent = 0;
			break;

		case 'q':
			sremove();
			exit(rcode);
			/* NOTREACHED */
			break;

		case 'l':
			cpp(ltemp, left, odes);
			notacc = 0;
			break;

		case 'r':
			cpp(rtemp, right, odes);
			notacc = 0;
			break;

		case 'e':
			while (*++cp == ' ')
				;
			switch (*cp) {
			case 'l':
			case '<':
				notacc = 0;
				ename = ltemp;
				edit(ename);
				break;

			case 'r':
			case '>':
				notacc = 0;
				ename = rtemp;
				edit(ename);
				break;

			case 'b':
			case '|':
				if ((tempdes = fopen(temp, "w")) == NULL)
					error(gettext(
						"Cannot open temp file %s"),
						temp);
				cpp(ltemp, left, tempdes);
				cpp(rtemp, right, tempdes);
				(void) fclose(tempdes);
				notacc = 0;
				ename = temp;
				edit(ename);
				break;

			case '\n':
				if ((tempdes = fopen(temp, "w")) == NULL)
					error(gettext(
						"Cannot open temp file %s"),
						temp);
				(void) fclose(tempdes);
				notacc = 0;
				ename = temp;
				edit(ename);
				break;
			default:
				(void) fprintf(stderr, gettext(
					"Illegal command %s reenter\n"),
					cp);
				break;
			}
			if (notacc == 0)
				cpp(ename, tempdes, odes);
			break;

		default:
			(void) fprintf(stderr, gettext(
				"Illegal command reenter\n"));
			break;
		}
	}
}

static void
cpp(char *from, FILE *fromdes, FILE *todes)
{
	char	tempbuf[BMAX + 1];

	if ((fromdes = fopen(from, "r")) == NULL)
		error(gettext(
			"cpp: Cannot open %s"), from);
	while ((fgets(tempbuf, BMAX, fromdes) != NULL))
		(void) fputs(tempbuf, todes);
	(void) fclose(fromdes);
}

static void
edit(char *file)
{
	int	i;
	pid_t	pid;
	void (*oldintr)(int);

	switch (pid = fork()) {
	case (pid_t)-1:
		error(gettext("Cannot fork"), NULL);
		/* NOTREACHED */
		break;
	case (pid_t)0:
		(void) execl("/usr/bin/ed", "ed", file, NULL);
	}

	oldintr = signal(SIGINT, SIG_IGN);	/* ignore interrupts in ed */
	while (pid != wait(&i))
		;
	/* restore previous interrupt proc */
	(void) signal(SIGINT, oldintr);
}

static char *
filename(char *pa1, char *pa2)
{
	int	c;
	char 	*a1, *b1, *a2;
	struct stat	stbuf;
	a1 = pa1;
	a2 = pa2;
	if (stat(a1, &stbuf) != -1 && ((stbuf.st_mode&S_IFMT) == S_IFDIR)) {
		b1 = pa1 = (char *)malloc(strlen(a1) + strlen(a2) + 2);
		while (*b1++ = *a1++);
		b1[-1] = '/';
		a1 = b1;
		while (*a1++ = *a2++)
			if (*a2 && *a2 != '/' && a2[-1] == '/')
				a1 = b1;
	} else if (a1[0] == '-' && a1[1] == 0 && temp == 0) {
		if (fstat(fileno(stdin), &stbuf) == -1)
			error(gettext("Cannot process stdin"), NULL);
		pa1 = temp = strdup("/tmp/sdiffXXXXXX");
		if ((tempfd = mkstemp(temp)) == -1 ||
			(tempdes = fdopen(tempfd, "w")) == NULL)
				error(gettext("Cannot open/create temp %s"),
					temp);
		while ((c = getc(stdin)) != EOF)
			(void) putc(c, tempdes);
		(void) fclose(tempdes);
	}
	return (pa1);
}

/*
 * like fgets, but reads upto and including a newline,
 * the data is stored in a reusable dynamic buffer that grows to fit
 * the largest line in the file, the buffer is NULL terminated
 * returns a pointer to the dynamic buffer.
 */
static char *
fgetline(FILE *fp)
{
	static char	*bp = NULL;
	static int	blen = 0;
	int	sl;

	if (bp == NULL) {
		/* allocate it for the first time */
		bp = (char *)malloc(BUFSIZ);
		if (bp == NULL)
			error(gettext("fgetline: malloc failed"), NULL);
		blen = BUFSIZ;
	}

	/* check for error or nothing read */
	if (fgets(bp, blen, fp) == NULL)
		return (NULL);

	if (feof(fp))
		return (bp);

	while ((sl = strlen(bp)) == blen-1 && *(bp+blen-2) != '\n') {
		/* still more data, grow the buffer */
		blen *= 2;
		bp = (char *)realloc(bp, blen);
		if (bp == NULL)
			error(gettext("fgetline: realloc failed"), NULL);
		/* continue reading and add to end of buffer */
		(void) fgets(bp+sl, blen-sl, fp);
	}
	return (bp);
}
