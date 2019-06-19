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

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

#include <stdio.h>
#include <stdarg.h>
#include "ldefs.h"
#include <limits.h>

/*
 * return next line of input, throw away trailing '\n'
 * and also throw away trailing blanks (spaces and tabs)
 * returns 0 if eof is had immediately
 */

CHR *
getl(CHR *p)
{
	int c;
	CHR *s, *t, *u;
	int blank = 0;

	t = s = p;
	while (((c = gch()) != 0) && c != '\n') {
		if (t >= &p[BUF_SIZ])
			error("definitions too long");
		if (c == ' ' || c == '\t') {
			if (!blank) {
				blank = 1;
				u = t;
			}
		} else
			blank = 0;

		*t++ = c;
	}
	if (blank)
		*u = 0;
	else
		*t = 0;

	if (c == 0 && s == t)
		return ((CHR *) 0);
	prev = '\n';
	pres = '\n';
	return (s);
}

int
space(int ch)
{
	switch (ch) {
		case ' ':
		case '\t':
		case '\n':
			return (1);
	}
	return (0);
}

int
digit(int c)
{
	return (c >= '0' && c <= '9');
}

void
error(char *s, ...)
{
	va_list ap;

	/* if(!eof) */
	if (!yyline) {
		(void) fprintf(errorf, "Command line: ");
	} else {
		(void) fprintf(errorf,
		    !no_input ? "" : "\"%s\":", sargv[optind]);
		(void) fprintf(errorf, "line %d: ", yyline);
	}
	(void) fprintf(errorf, "Error: ");
	va_start(ap, s);
	(void) vfprintf(errorf, s, ap);
	va_end(ap);
	(void) putc('\n', errorf);
	if (fatal)
		error_tail();
}

void
error_tail(void)
{
#ifdef DEBUG
	if (debug && sect != ENDSECTION) {
		sect1dump();
		sect2dump();
	}
#endif

	if (report == 1)
		statistics();
	exit(1);
	/* NOTREACHED */
}

void
warning(char *s, ...)
{
	va_list ap;

	if (!eof)
		if (!yyline)
			(void) fprintf(errorf, "Command line: ");
		else {
			(void) fprintf(errorf,
			    !no_input ? "" : "\"%s\":", sargv[optind]);
			(void) fprintf(errorf,
			    "line %d: ", yyline);
		}
	(void) fprintf(errorf, "Warning: ");
	va_start(ap, s);
	(void) vfprintf(errorf, s, ap);
	va_end(ap);
	(void) putc('\n', errorf);
	(void) fflush(errorf);
	if (fout)
		(void) fflush(fout);
	(void) fflush(stdout);
}

/*
 * This function is apparently unused, but lint flags the fact
 * that it does not have the same signature as the libc function
 * of the same name. So, take it out of view for lint.
 */
#if !defined(__lint)
int
index(int a, CHR *s)
{
	int k;
	for (k = 0; s[k]; k++)
		if (s[k] == a)
			return (k);
	return (-1);
}
#endif

int
alpha(int c)
{
	return ('a' <= c && c <= 'z' ||
	    'A' <= c && c <= 'Z');
}

int
printable(int c)
{
	return (c > 040 && c < 0177);
}

void
lgate(void)
{
	char fname[20];

	if (lgatflg)
		return;
	lgatflg = 1;
	if (fout == NULL) {
		(void) sprintf(fname, "lex.yy.%c", ratfor ? 'r' : 'c');
		fout = fopen(fname, "w");
	}
	if (fout == NULL)
		error("Can't open %s", fname);
	if (ratfor)
		(void) fprintf(fout, "#\n");
	phead1();
}

/*
 * scopy(ptr to str, ptr to str) - copy first arg str to second
 * returns ptr to second arg
 */
void
scopy(CHR *s, CHR *t)
{
	CHR *i;
	i = t;
	while (*i++ = *s++)
		;
}

/*
 * convert string t, return integer value
 */
int
siconv(CHR *t)
{
	int i, sw;
	CHR *s;
	s = t;
	while (space(*s))
		s++;
	if (!digit(*s) && *s != '-')
		error("missing translation value");
	sw = 0;
	if (*s == '-') {
		sw = 1;
		s++;
	}
	if (!digit(*s))
		error("incomplete translation format");
	i = 0;
	while ('0' <= *s && *s <= '9')
		i = i * 10 + (*(s++)-'0');
	return (sw ? -i : i);
}

/*
 * slength(ptr to str) - return integer length of string arg
 * excludes '\0' terminator
 */
int
slength(CHR *s)
{
	int n;
	CHR *t;
	t = s;
	for (n = 0; *t++; n++)
		;
	return (n);
}

/*
 * scomp(x,y) - return -1 if x < y,
 *		0 if x == y,
 *		return 1 if x > y, all lexicographically
 */
int
scomp(CHR *x, CHR *y)
{
	CHR *a, *d;
	a = (CHR *) x;
	d = (CHR *) y;
	while (*a || *d) {
		if (*a > *d)
			return (1);
		if (*a < *d)
			return (-1);
		a++;
		d++;
	}
	return (0);
}

int
ctrans(CHR **ss)
{
	int c, k;
	if ((c = **ss) != '\\')
		return (c);
	switch (c = *++*ss) {
	case 'a':
		c = '\a';
		warning("\\a is ANSI C \"alert\" character");
		break;
	case 'v': c = '\v'; break;
	case 'n': c = '\n'; break;
	case 't': c = '\t'; break;
	case 'r': c = '\r'; break;
	case 'b': c = '\b'; break;
	case 'f': c = 014; break;		/* form feed for ascii */
	case '\\': c = '\\'; break;
	case 'x': {
		int dd;
		warning("\\x is ANSI C hex escape");
		if (digit((dd = *++*ss)) ||
		    ('a' <= dd && dd <= 'f') ||
		    ('A' <= dd && dd <= 'F')) {
			c = 0;
			while (digit(dd) ||
			    ('A' <= dd && dd <= 'F') ||
			    ('a' <= dd && dd <= 'f')) {
				if (digit(dd))
					c = c*16 + dd - '0';
				else if (dd >= 'a')
					c = c*16 + 10 + dd - 'a';
				else
					c = c*16 + 10 + dd - 'A';
				dd = *++*ss;
			}
		} else
			c = 'x';
		break;
		}
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
		c -= '0';
		while ((k = *(*ss+1)) >= '0' && k <= '7') {
			c = c*8 + k - '0';
			(*ss)++;
		}
		break;
	}
	return (c);
}

void
cclinter(int sw)
{
	/* sw = 1 ==> ccl */
	int i, j, k;
	int m;
	if (!sw) { /* is NCCL */
		for (i = 1; i < ncg; i++)
			symbol[i] ^= 1;	/* reverse value */
	}
	for (i = 1; i < ncg; i++)
		if (symbol[i])
			break;
	if (i >= ncg)
		return;
	i = cindex[i];
	/* see if ccl is already in our table */
	j = 0;
	if (i) {
		for (j = 1; j < ncg; j++) {
			if ((symbol[j] && cindex[j] != i) ||
			    (!symbol[j] && cindex[j] == i))
				break;
		}
	}
	if (j >= ncg)
		return;		/* already in */
	m = 0;
	k = 0;
	for (i = 1; i < ncg; i++) {
		if (symbol[i]) {
			if (!cindex[i]) {
				cindex[i] = ccount;
				symbol[i] = 0;
				m = 1;
			} else
				k = 1;
		}
	}
	/* m == 1 implies last value of ccount has been used */
	if (m)
		ccount++;
	if (k == 0)
		return;	/* is now in as ccount wholly */
	/* intersection must be computed */
	for (i = 1; i < ncg; i++) {
		if (symbol[i]) {
			m = 0;
			j = cindex[i];	/* will be non-zero */
			for (k = 1; k < ncg; k++) {
				if (cindex[k] == j) {
					if (symbol[k])
						symbol[k] = 0;
					else {
						cindex[k] = ccount;
						m = 1;
					}
				}
			}
			if (m)
				ccount++;
		}
	}
}

int
usescape(int c)
{
	char d;
	switch (c) {
	case 'a':
		c = '\a';
		warning("\\a is ANSI C \"alert\" character"); break;
	case 'v': c = '\v'; break;
	case 'n': c = '\n'; break;
	case 'r': c = '\r'; break;
	case 't': c = '\t'; break;
	case 'b': c = '\b'; break;
	case 'f': c = 014; break;		/* form feed for ascii */
	case 'x': {
		int dd;
		if (digit((dd = gch())) ||
		    ('A' <= dd && dd <= 'F') ||
		    ('a' <= dd && dd <= 'f')) {
			c = 0;
			while (digit(dd) ||
			    ('A' <= dd && dd <= 'F') ||
			    ('a' <= dd && dd <= 'f')) {
				if (digit(dd))
					c = c*16 + dd - '0';
				else if (dd >= 'a')
					c = c*16 + 10 + dd - 'a';
				else
					c = c*16 + 10 + dd - 'A';
				if (!digit(peek) &&
				    !('A' <= peek && peek <= 'F') &&
				    !('a' <= peek && peek <= 'f'))
					break;
				dd = gch();
			}

		} else
			c = 'x';
		break;
	}
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
		c -= '0';
		while ('0' <= (d = gch()) && d <= '7') {
			c = c * 8 + (d-'0');
			if (!('0' <= peek && peek <= '7')) break;
			}

		break;
	}

	if (handleeuc && !isascii(c)) {
		char tmpchar = c & 0x00ff;
		(void) mbtowc((wchar_t *)&c, &tmpchar, sizeof (tmpchar));
	}
	return (c);
}

int
lookup(CHR *s, CHR **t)
{
	int i;
	i = 0;
	while (*t) {
		if (scomp(s, *t) == 0)
			return (i);
		i++;
		t++;
	}
	return (-1);
}

void
cpycom(CHR *p)
{
	static CHR *t;
	static int c;
	t = p;

	if (sargv[optind] == NULL)
		(void) fprintf(fout, "\n# line %d\n", yyline);
	else
		(void) fprintf(fout,
		    "\n# line %d \"%s\"\n", yyline, sargv[optind]);

	(void) putc(*t++, fout);
	(void) putc(*t++, fout);
	while (*t) {
		while (*t == '*') {
			(void) putc(*t++, fout);
			if (*t == '/')
				goto backcall;
		}
		/*
		 * FIX BUG #1058428, not parsing comments correctly
		 * that span more than one line
		 */
		if (*t != 0)
			(void) putc(*t++, fout);
	}
	(void) putc('\n', fout);
	while (c = gch()) {
		while (c == '*') {
			(void) putc((char)c, fout);
			if ((c = gch()) == '/') {
				while ((c = gch()) == ' ' || c == '\t')
					;
				if (!space(c))
					error("unacceptable statement");
				prev = '\n';
				goto backcall;
			}
		}
		(void) putc((char)c, fout);
	}
	error("unexpected EOF inside comment");
backcall:
	(void) putc('/', fout);
	(void) putc('\n', fout);
}

/*
 * copy C action to the next ; or closing
 */
int
cpyact(void)
{
	int brac, c, mth;
	static int sw, savline;

	brac = 0;
	sw = TRUE;
	savline = yyline;

	if (sargv[optind] == NULL)
		(void) fprintf(fout, "\n# line %d\n", yyline);
	else
		(void) fprintf(fout,
		    "\n# line %d \"%s\"\n", yyline, sargv[optind]);

	while (!eof) {
		c = gch();
	swt:
		switch (c) {
		case '|':
			if (brac == 0 && sw == TRUE) {
				if (peek == '|')
					(void) gch(); /* eat up an extra '|' */
				return (0);
			}
			break;
		case ';':
			if (brac == 0) {
				(void) putwc(c, fout);
				(void) putc('\n', fout);
				return (1);
			}
			break;
		case '{':
			brac++;
			savline = yyline;
			break;
		case '}':
			brac--;
			if (brac == 0) {
				(void) putwc(c, fout);
				(void) putc('\n', fout);
				return (1);
			}
			break;
		case '/':
			(void) putwc(c, fout);
			c = gch();
			if (c != '*')
				goto swt;
			(void) putwc(c, fout);
			savline = yyline;
			while (c = gch()) {
				while (c == '*') {
					(void) putwc(c, fout);
					if ((c = gch()) == '/') {
						(void) putc('/', fout);
						while ((c = gch()) == ' ' ||
						    c == '\t' || c == '\n')
							(void) putwc(c, fout);
						goto swt;
					}
				}
				(void) putc((char)c, fout);
			}
			yyline = savline;
			error("EOF inside comment");
			/* NOTREACHED */
			break;
		case '\'': /* character constant */
		case '"': /* character string */
			mth = c;
			(void) putwc(c, fout);
			while (c = gch()) {
				if (c == '\\') {
					(void) putwc(c, fout);
					c = gch();
				}
				else
					if (c == mth)
						goto loop;
				(void) putwc(c, fout);
				if (c == '\n') {
					yyline--;
					error(
"Non-terminated string or character constant");
				}
			}
			error("EOF in string or character constant");
			/* NOTREACHED */
			break;
		case '\0':
			yyline = savline;
			error("Action does not terminate");
			/* NOTREACHED */
			break;
		default:
			break; /* usual character */
		}
	loop:
		if (c != ' ' && c != '\t' && c != '\n')
			sw = FALSE;
		(void) putwc(c, fout);
		if (peek == '\n' && !brac && copy_line) {
			(void) putc('\n', fout);
			return (1);
		}
	}
	error("Premature EOF");
	return (0);
}

int
gch(void)
{
	int c;
	prev = pres;
	c = pres = peek;
	peek = pushptr > pushc ? *--pushptr : getwc(fin);
	while (peek == EOF) {
		if (no_input) {
			if (!yyline)
				error("Cannot read from -- %s",
				    sargv[optind]);
			if (optind < sargc-1) {
				yyline = 0;
				if (fin != stdin)
					(void) fclose(fin);
				fin = fopen(sargv[++optind], "r");
				if (fin == NULL)
					error("Cannot open file -- %s",
					    sargv[optind]);
				peek = getwc(fin);
			} else
				break;
		} else {
			if (fin != stdin)
				(void) fclose(fin);
			if (!yyline)
				error("Cannot read from -- standard input");
			else
				break;
		}
	}
	if (c == EOF) {
		eof = TRUE;
		return (0);
	}
	if (c == '\n')
		yyline++;
	return (c);
}

int
mn2(int a, int d, int c)
{
	if (tptr >= treesize) {
		tptr++;
		error("Parse tree too big %s",
		    (treesize == TREESIZE ? "\nTry using %e num" : ""));
	}
	if (d >= treesize) {
		error("Parse error");
	}
	name[tptr] = a;
	left[tptr] = d;
	right[tptr] = c;
	parent[tptr] = 0;
	nullstr[tptr] = 0;
	switch (a) {
	case RSTR:
		parent[d] = tptr;
		break;
	case BAR:
	case RNEWE:
		if (nullstr[d] || nullstr[c])
			nullstr[tptr] = TRUE;
		parent[d] = parent[c] = tptr;
		break;
	case RCAT:
	case DIV:
		if (nullstr[d] && nullstr[c])
			nullstr[tptr] = TRUE;
		parent[d] = parent[c] = tptr;
		break;
	/* XCU4: add RXSCON */
	case RXSCON:
	case RSCON:
		parent[d] = tptr;
		nullstr[tptr] = nullstr[d];
		break;
#ifdef DEBUG
	default:
		warning("bad switch mn2 %d %d", a, d);
		break;
#endif
	}
	return (tptr++);
}

int
mn1(int a, int d)
{
	if (tptr >= treesize) {
		tptr++;
		error("Parse tree too big %s",
		    (treesize == TREESIZE ? "\nTry using %e num" : ""));
	}
	name[tptr] = a;
	left[tptr] = d;
	parent[tptr] = 0;
	nullstr[tptr] = 0;
	switch (a) {
	case RCCL:
	case RNCCL:
		if (slength((CHR *)d) == 0)
			nullstr[tptr] = TRUE;
		break;
	case STAR:
	case QUEST:
		nullstr[tptr] = TRUE;
		parent[d] = tptr;
		break;
	case PLUS:
	case CARAT:
		nullstr[tptr] = nullstr[d];
		parent[d] = tptr;
		break;
	case S2FINAL:
		nullstr[tptr] = TRUE;
		break;
#ifdef DEBUG
	case FINAL:
	case S1FINAL:
		break;
	default:
		warning("bad switch mn1 %d %d", a, d);
		break;
#endif
	}
	return (tptr++);
}

int
mn0(int a)
{
	if (tptr >= treesize) {
		tptr++;
		error("Parse tree too big %s",
		    (treesize == TREESIZE ? "\nTry using %e num" : ""));
	}

	name[tptr] = a;
	parent[tptr] = 0;
	nullstr[tptr] = 0;
	if (ISOPERATOR(a)) {
		switch (a) {
		case DOT: break;
		case RNULLS: nullstr[tptr] = TRUE; break;
#ifdef DEBUG
		default:
			warning("bad switch mn0 %d", a);
			break;
#endif
		}
	}
	return (tptr++);
}

void
munput(int t, CHR *p)
{
	int i, j;
	if (t == 'c') {
		*pushptr++ = peek;
		peek = *p;
	} else if (t == 's') {
		*pushptr++ = peek;
		peek = p[0];
		i = slength(p);
		for (j = i - 1; j >= 1; j--)
			*pushptr++ = p[j];
	}
	if (pushptr >= pushc + TOKENSIZE)
		error("Too many characters pushed");
}

int
dupl(int n)
{
	/* duplicate the subtree whose root is n, return ptr to it */
	int i;
	i = name[n];
	if (!ISOPERATOR(i))
		return (mn0(i));
	switch (i) {
	case DOT:
	case RNULLS:
		return (mn0(i));
	case RCCL: case RNCCL: case FINAL: case S1FINAL: case S2FINAL:
		return (mn1(i, left[n]));
	case STAR: case QUEST: case PLUS: case CARAT:
		return (mn1(i, dupl(left[n])));

	/* XCU4: add RXSCON */
	case RSTR: case RSCON: case RXSCON:
		return (mn2(i, dupl(left[n]), right[n]));
	case BAR: case RNEWE: case RCAT: case DIV:
		return (mn2(i, dupl(left[n]), dupl(right[n])));
	}
	return (0);
}

#ifdef DEBUG
void
allprint(CHR c)
{
	switch (c) {
	case 014:
		(void) printf("\\f");
		charc++;
		break;
	case '\n':
		(void) printf("\\n");
		charc++;
		break;
	case '\t':
		(void) printf("\\t");
		charc++;
		break;
	case '\b':
		(void) printf("\\b");
		charc++;
		break;
	case ' ':
		(void) printf("\\_");
		break;
	default:
		if (!iswprint(c)) {
			printf("\\x%-2x", c); /* up to fashion. */
			charc += 3;
		} else
			(void) putwc(c, stdout);
		break;
	}
	charc++;
}

void
strpt(CHR *s)
{
	charc = 0;
	while (*s) {
		allprint(*s++);
		if (charc > LINESIZE) {
			charc = 0;
			(void) printf("\n\t");
		}
	}
}

void
sect1dump(void)
{
	int i;
	(void) printf("Sect 1:\n");
	if (def[0]) {
		(void) printf("str	trans\n");
		i = -1;
		while (def[++i])
			(void) printf("%ws\t%ws\n", def[i], subs[i]);
	}
	if (sname[0]) {
		(void) printf("start names\n");
		i = -1;
		while (sname[++i])
			(void) printf("%ws\n", sname[i]);
	}
	if (chset == TRUE) {
		(void) printf("char set changed\n");
		for (i = 1; i < NCH; i++) {
			if (i != ctable[i]) {
				allprint(i);
				(void) putchar(' ');
				iswprint(ctable[i]) ?
				    (void) putwc(ctable[i], stdout) :
				    (void) printf("%d", ctable[i]);
				(void) putchar('\n');
			}
		}
	}
}

void
sect2dump(void)
{
	(void) printf("Sect 2:\n");
	treedump();
}

void
treedump(void)
{
	int t;
	CHR *p;
	(void) printf("treedump %d nodes:\n", tptr);
	for (t = 0; t < tptr; t++) {
		(void) printf("%4d ", t);
		parent[t] ? (void) printf("p=%4d", parent[t]) :
		    (void) printf("      ");
		(void) printf("  ");
		if (!ISOPERATOR(name[t])) {
			allprint(name[t]);
		} else
			switch (name[t]) {
			case RSTR:
				(void) printf("%d ", left[t]);
				allprint(right[t]);
				break;
			case RCCL:
				(void) printf("ccl ");
				strpt(left[t]);
				break;
			case RNCCL:
				(void) printf("nccl ");
				strpt(left[t]);
				break;
			case DIV:
				(void) printf("/ %d %d", left[t], right[t]);
				break;
			case BAR:
				(void) printf("| %d %d", left[t], right[t]);
				break;
			case RCAT:
				(void) printf("cat %d %d", left[t], right[t]);
				break;
			case PLUS:
				(void) printf("+ %d", left[t]);
				break;
			case STAR:
				(void) printf("* %d", left[t]);
				break;
			case CARAT:
				(void) printf("^ %d", left[t]);
				break;
			case QUEST:
				(void) printf("? %d", left[t]);
				break;
			case RNULLS:
				(void) printf("nullstring");
				break;
			case FINAL:
				(void) printf("final %d", left[t]);
				break;
			case S1FINAL:
				(void) printf("s1final %d", left[t]);
				break;
			case S2FINAL:
				(void) printf("s2final %d", left[t]);
				break;
			case RNEWE:
				(void) printf("new %d %d", left[t], right[t]);
				break;

			/* XCU4: add RXSCON */
			case RXSCON:
				p = (CHR *)right[t];
				(void) printf("exstart %s", sname[*p++-1]);
				while (*p)
					(void) printf(", %ws", sname[*p++-1]);
				(void) printf(" %d", left[t]);
				break;
			case RSCON:
				p = (CHR *)right[t];
				(void) printf("start %s", sname[*p++-1]);
				while (*p)
					(void) printf(", %ws", sname[*p++-1]);
				(void) printf(" %d", left[t]);
				break;
			case DOT:
				printf("dot");
				break;
			default:
				(void) printf(
				"unknown %d %d %d", name[t], left[t], right[t]);
				break;
			}
		if (nullstr[t])
			(void) printf("\t(null poss.)");
		(void) putchar('\n');
	}
}
#endif
