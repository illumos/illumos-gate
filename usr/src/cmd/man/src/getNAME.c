/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Copyright 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Get name sections from manual pages.
 *	-t	for building toc
 *	-i	for building intro entries
 *	other	apropos database
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <wchar.h>
#include <errno.h>
#include <sys/param.h>

#define	PLEN	3	/* prefix length "man" */

static char path[MAXPATHLEN+1];
static int tocrc;
static int intro;
static char *progname;

static void trimln(char *);
static void roff_trim(char *cp);
static void doname(char *);
static void section(char *, char *);
static void split(char *, char *);
static void dorefname(char *);
static void troffpage(char *);
static void sgmlpage(char *);

/*
 * Test to see if this is an SGML manpage or a regular manpage
 * Unless the first line begins with <!DOCTYPE, we assume it isn't.
 */
static int
issgml(FILE *fp)
{
	static const char magic[] = "<!DOCTYPE";
	char buf[sizeof (magic)];
	size_t n = sizeof (magic) - 1;

	if (read(fileno(fp), buf, n) != n ||
	    lseek(fileno(fp), 0, SEEK_SET) != 0)
		return (0);
	return (strncmp(magic, buf, n) == 0);
}

int
main(int argc, char *argv[])
{
	int c;

	(void) setlocale(LC_ALL, "");

	progname = argv[0];

	while ((c = getopt(argc, argv, "it")) != EOF)
		switch (c) {
		case 't':
			tocrc++;
			break;
		case 'i':
			intro++;
			break;
		case '?':
		default:
			(void) fprintf(stderr,
			    "usage: %s [-i][-t] files..\n", progname);
			exit(1);
		}

	if (getcwd(path, sizeof (path)) == NULL) {
		(void) fprintf(stderr, "%s: getcwd: %s\n", progname, path);
		exit(1);
	}

	for (; optind < argc; optind++) {
		char *name = argv[optind];

		if (freopen(name, "r", stdin) == 0) {
			(void) fprintf(stderr,
			    "%s: %s: %s\n", progname, name, strerror(errno));
			continue;
		}

		/*
		 * Most of the info we care about is in the first kbyte
		 */
		(void) setvbuf(stdin, NULL, _IOFBF, 1024);

		if (issgml(stdin))
			sgmlpage(name);
		else
			troffpage(name);
	}

	return (0);
}

/*
 * Parse a troff-format manpage
 */
static void
troffpage(char *name)
{
	char headbuf[BUFSIZ];
	char linbuf[BUFSIZ];
	char *strptr;
	int i = 0;

	for (;;) {
		if (fgets(headbuf, sizeof (headbuf), stdin) == NULL)
			return;
		if (headbuf[0] != '.')
			continue;
		if (headbuf[1] == 'T' && headbuf[2] == 'H')
			break;
		if (headbuf[1] == 't' && headbuf[2] == 'h')
			break;
	}
	for (;;) {
		if (fgets(linbuf, sizeof (linbuf), stdin) == NULL)
			return;
		if (linbuf[0] != '.')
			continue;
		if (linbuf[1] == 'S' && linbuf[2] == 'H')
			break;
		if (linbuf[1] == 's' && linbuf[2] == 'h')
			break;
	}
	trimln(headbuf);
	if (tocrc)
		doname(name);
	if (!intro)
		section(name, headbuf);
	for (;;) {
		if (fgets(linbuf, sizeof (linbuf), stdin) == NULL)
			break;
		if (linbuf[0] == '.') {
			if (linbuf[1] == 'S' && linbuf[2] == 'H')
				break;
			if (linbuf[1] == 's' && linbuf[2] == 'h')
				break;
			if (linbuf[1] == '\\' && linbuf[2] == '"')
				continue;
		}
		trimln(linbuf);
		roff_trim(linbuf);
		if (intro) {
			split(linbuf, name);
			continue;
		}
		if (i != 0)
			(void) printf(" ");
		i++;
		(void) printf("%s", linbuf);
	}
	(void) printf("\n");
}


/*
 * Substitute section defined in page with new section spec
 * of the form xx/yy where xx is the section suffix of the
 * directory and yy is the filename extension (unless xx
 * and yy are equal, in which case xx is the section).
 * Pages should be placed in their proper directory with the
 * proper name to simplify things.
 *
 * For example take the following names:
 *    man1/ar.1v	(1/1V)
 *    man1/find.1	(1)
 *    man1/loco		(1/)
 *
 */
static void
section(char *name, char *buf)
{
	char scratch[MAXPATHLEN+1];
	char *p = buf;
	char *dir, *fname;
	char *dp, *np;
	int i;
	int plen = PLEN;

	/*
	 * split dirname and filename
	 */
	(void) strcpy(scratch, name);
	if ((fname = strrchr(scratch, '/')) == NULL) {
		fname = name;
		dir = path;
	} else {
		dir = scratch;
		*fname = 0;
		fname++;
	}
	dp = strrchr(dir, '/');

	if (*(dp+1) == 's')
		plen = PLEN + 1;

	if (dp != NULL) {
		dp = dp+plen+1;
	} else {
		dp = dir+plen;
	}
	np = strrchr(fname, '.');
	if (np != NULL) {
		++np;
	} else {
		np = "";
	}
	for (i = 0; i < 2; i++) {
		while (*p && *p != ' ' && *p != '\t')
			p++;
		if (!*p)
			break;
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		if (!*p)
			break;
	}
	*p++ = 0;
	(void) printf("%s", buf);
	if (strcmp(np, dp) == 0)
		(void) printf("%s", dp);
	else
		(void) printf("%s/%s", dp, np);
	while (*p && *p != ' ' && *p != '\t')
		p++;
	(void) printf("%s\t", p);
}

static void
trimln(char *cp)
{
	while (*cp)
		cp++;
	if (*--cp == '\n')
		*cp = 0;
}

static void
roff_trim(char *cp)
{
	if (*cp == '.') {
		while ((*cp != ' ') && (*cp != '\0')) {
			strcpy(cp, cp+1);
		}
		strcpy(cp, cp+1);
	}
	while (*cp) {
		if (strncmp(cp, "\\f", 2) == 0) {
			if ((*(cp+2) >= 48) && (*(cp+2) <= 57)) {
				strcpy(cp, cp+3);
			}
			if (*(cp+2) == '(') {
				strcpy(cp, cp+5);
			}
		}
		cp++;
	}
}

static void
doname(char *name)
{
	char *dp = name, *ep;

again:
	while (*dp && *dp != '.')
		(void) putchar(*dp++);
	if (*dp)
		for (ep = dp+1; *ep; ep++)
			if (*ep == '.') {
				(void) putchar(*dp++);
				goto again;
			}
	(void) putchar('(');
	if (*dp)
		dp++;
	while (*dp)
		(void) putchar(*dp++);
	(void) putchar(')');
	(void) putchar(' ');
}

static void
split(char *line, char *name)
{
	char *cp, *dp;
	char *sp, *sep;

	cp = strchr(line, '-');
	if (cp == 0)
		return;
	sp = cp + 1;
	for (--cp; *cp == ' ' || *cp == '\t' || *cp == '\\'; cp--)
		;
	*++cp = '\0';
	while (*sp && (*sp == ' ' || *sp == '\t'))
		sp++;
	for (sep = "", dp = line; dp && *dp; dp = cp, sep = "\n") {
		cp = strchr(dp, ',');
		if (cp) {
			char *tp;

			for (tp = cp - 1; *tp == ' ' || *tp == '\t'; tp--)
				;
			*++tp = '\0';
			for (++cp; *cp == ' ' || *cp == '\t'; cp++)
				;
		}
		(void) printf("%s%s\t", sep, dp);
		dorefname(name);
		(void) printf("\t%s", sp);
	}
}

static void
dorefname(char *name)
{
	char *dp = name, *ep;

again:
	while (*dp && *dp != '.')
		(void) putchar(*dp++);
	if (*dp)
		for (ep = dp+1; *ep; ep++)
			if (*ep == '.') {
				(void) putchar(*dp++);
				goto again;
			}
	(void) putchar('.');
	if (*dp)
		dp++;
	while (*dp)
		(void) putchar(*dp++);
}

/*
 * The rest of the routines in the file form a simplistic parser
 * for SGML manpages.  We assume the input is syntactically correct
 * SGML, and that the fields occur in the input file in order.
 */

/*
 * Some utilities for constructing arbitrary length wide character strings
 */

typedef struct {
	wchar_t *str;
	size_t size;
	long index;
} string_t;

#define	DEF_STR_SIZE	16
#define	DEF_STR_GROWTH	16

static void
outofspace(char *where)
{
	(void) fprintf(stderr, "%s: '%s' - out of memory\n", progname, where);
	exit(1);
}

static string_t *
newstring(size_t initial)
{
	string_t *s = malloc(sizeof (*s));

	if (s == NULL)
		outofspace("new s");

	initial *= sizeof (wchar_t);
	if (initial < DEF_STR_SIZE)
		initial = DEF_STR_SIZE;

	s->str = malloc(initial);
	if (s->str == NULL)
		outofspace("new str");

	s->size = initial;
	s->index = 0;
	*s->str = L'\0';
	return (s);
}

static void
delstring(string_t **s)
{
	free((*s)->str);
	(*s)->str = NULL;
	free(*s);
	*s = NULL;
}

static wchar_t *
getwstring(string_t *s)
{
	static const wchar_t wnull = L'\0';

	if (s)
		return (s->str);
	return ((wchar_t *)&wnull);
}

static char *
getcstring(string_t *s)
{
	size_t len = (wcslen(s->str) + 1) * MB_CUR_MAX;
	char *cstr = malloc(len);
	char *p = cstr;
	wchar_t *wp = s->str;

	if (p == NULL)
		outofspace("getc");
	while (*wp)
		p += wctomb(p, *wp++);
	*p = '\0';
	return (cstr);
}

static void
appendwstring(string_t *s, const wchar_t *str)
{
	size_t len = wcslen(str) + 1;

	s->size += sizeof (wchar_t) * len;
	s->str = realloc(s->str, s->size);
	if (s->str == NULL)
		outofspace("appendw");
	(void) wcscat(s->str, str);
	s->index = wcslen(s->str) + 1;
}

static void
putwstring(string_t *s, wchar_t wc)
{
	if ((s->index + 1) * sizeof (wchar_t) >= s->size) {
		s->size += DEF_STR_GROWTH;
		s->str = realloc(s->str, s->size);
		if (s->str == NULL)
			outofspace("put");
	}
	s->str[s->index++] = wc;
}

/*
 * Find the closing > of an SGML comment block
 * (allowing for multibyte, embedded, comments)
 */
static void
eatcomments(void)
{
	int pending = 1;

	while (pending)
		switch (getwchar()) {
		default:
			break;
		case L'<':
			pending++;
			break;
		case L'>':
			pending--;
			break;
		case WEOF:
			return;
		}
}

/*
 * Find the next token on stdin.
 * Handles nested comment strings, and removes any trailing newlines
 * from the stream after the closing '>'.
 */
static int
find_token(char *tokbuf, size_t tokbuflen)
{
	int c;
	wint_t wc;
	char *tokp;

top:
	while ((wc = getwchar()) != WEOF)
		if (wc == L'<')
			break;

	if (wc == WEOF && errno == EILSEQ)
		return (0);

	switch (c = getchar()) {
	case EOF:
		return (0);
	default:
		(void) ungetc(c, stdin);
		break;
	case '!':
		eatcomments();
		goto top;
	}

	tokp = tokbuf;

	while ((c = getchar()) != EOF) {
		if (c == '>') {
			while ((c = getchar()) != EOF)
				if (c != '\n') {
					(void) ungetc(c, stdin);
					break;
				}
			*tokp = '\0';
			return (1);
		}
		if (tokp - tokbuf < tokbuflen)
			*tokp++ = (char)c;
	}

	return (0);
}

/*
 * This structure is filled out during the parsing of each page we encounter
 */
typedef struct {
	char *name;
	string_t *title;
	string_t *volnum;
	string_t *date;
	string_t *names;
	string_t *purpose;
} manpage_t;

static void
warning(manpage_t *m, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: %s - ", progname, m->name);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * Fetch a string from stdin, terminated by the endtoken.
 * These strings may be localized, so do this with wide characters.
 * Hack: skip over (completely ignore) all other tokens
 * Hack: map all &blort; constructs to spaces.
 */
static string_t *
filestring(manpage_t *m, size_t initial, char *endtoken)
{
	char tokbuf[BUFSIZ * MB_LEN_MAX];
	string_t *s = newstring(initial);
	wint_t wc;

	while ((wc = getwchar()) != WEOF)
		switch (wc) {
		case L'\n':
			if ((wc = getwchar()) != WEOF)
				(void) ungetwc(wc, stdin);
			if (wc != L'<')
				putwstring(s, L' ');
			break;
		case L'<':
			(void) ungetwc(wc, stdin);
			if (!find_token(tokbuf, sizeof (tokbuf)) ||
			    strcasecmp(endtoken, tokbuf) == 0)
				goto done;
			break;
		case L'&':
			while ((wc = getwchar()) != WEOF)
				if (wc == L';')
					break;
			wc = L' ';
			/* FALLTHROUGH */
		default:
			putwstring(s, wc);
			break;
		}

	if (errno == EILSEQ)
		warning(m, "%s while parsing %s\n", strerror(errno), endtoken);
done:
	putwstring(s, L'\0');
	return (s);
}

/*
 * <refentrytitle> TITLE </refentrytitle>
 */
static int
refentrytitle(manpage_t *m)
{
	if (m->title != NULL)
		warning(m, "repeated refentrytitle\n");
	m->title = filestring(m, 8, "/refentrytitle");
	return (1);
}

/*
 * <manvolnum> MANVOLNUM </manvolnum>
 */
static int
manvolnum(manpage_t *m)
{
	if (m->volnum != NULL)
		warning(m, "repeated manvolnum\n");
	m->volnum = filestring(m, 3, "/manvolnum");
	return (1);
}

/*
 * <refmiscinfo class="date"> DATE </refmiscinfo>
 */
static int
refmiscinfo_date(manpage_t *m)
{
	if (m->date != NULL)
		warning(m, "repeated date\n");
	m->date = filestring(m, 11, "/refmiscinfo");
	return (1);
}

/*
 * .. </refmeta>
 */
static int
print_refmeta(manpage_t *m)
{
	char headbuf[BUFSIZ];

	(void) snprintf(headbuf, sizeof (headbuf), ".TH %ws %ws \"%ws\"",
	    getwstring(m->title), getwstring(m->volnum), getwstring(m->date));

	trimln(headbuf);
	if (tocrc)
		doname(m->name);
	if (!intro)
		section(m->name, headbuf);

	if (m->title)
		delstring(&m->title);
	if (m->volnum)
		delstring(&m->volnum);
	if (m->date)
		delstring(&m->date);

	return (1);
}

static int
appendname(manpage_t *m, char *term)
{
	string_t *r = filestring(m, 0, term);

	if (m->names) {
		appendwstring(m->names, L", ");
		appendwstring(m->names, getwstring(r));
		delstring(&r);
	} else
		m->names = r;
	return (1);
}

/*
 * <refdescriptor> REFDESCRIPTOR </refdescriptor>
 */
static int
refdescriptor(manpage_t *m)
{
	return (appendname(m, "/refdescriptor"));
}

/*
 * <refname> REFNAME </refname>
 */
static int
refname(manpage_t *m)
{
	return (appendname(m, "/refname"));
}

/*
 * <refpurpose> PURPOSE </refpurpose>
 */
static int
refpurpose(manpage_t *m)
{
	if (m->purpose != NULL)
		warning(m, "repeated refpurpose\n");
	m->purpose = filestring(m, 0, "/refpurpose");
	return (1);
}

/*
 * .. </refnamediv> - this is our chance to bail out.
 */
static int
terminate(manpage_t *m)
{
	if (m->names) {
		appendwstring(m->names, L" \\- ");
		appendwstring(m->names, getwstring(m->purpose));
		if (intro) {
			char *buf = getcstring(m->names);
			split(buf, m->name);
			free(buf);
		} else
			(void) printf("%ws", getwstring(m->names));
	}

	if (m->names)
		delstring(&m->names);
	if (m->purpose)
		delstring(&m->purpose);

	(void) printf("\n");
	return (0);
}


/*
 * Basic control structure of the SGML "parser".
 * It's very simplistic - when named tags are encountered in the
 * input stream, control is transferred to the corresponding routine.
 * No checking is done for correct pairing of tags.  A few other hacks
 * are sneaked into the lexical routines above.
 * Output is generated after seeing the /refmeta and /refnamediv
 * closing tags.
 */
static const struct {
	char *name;
	int (*action)(manpage_t *);
} acts[] = {
	{ "refentrytitle",		refentrytitle },
	{ "manvolnum",			manvolnum },
	{ "refmiscinfo class=\"date\"",	refmiscinfo_date },
	{ "/refmeta",			print_refmeta },
	{ "refdescriptor",		refdescriptor },
	{ "refname",			refname },
	{ "refpurpose",			refpurpose },
	{ "/refnamediv",		terminate },
	{ 0 }
};

static void
sgmlpage(char *name)
{
	int rc = 1, a;
	char tokbuf[BUFSIZ];
	manpage_t manpage, *m = &manpage;

	(void) memset(m, 0, sizeof (*m));
	m->name = name;

	do {
		if (!find_token(tokbuf, sizeof (tokbuf)))
			break;
		for (a = 0; acts[a].name; a++) {
			if (strcasecmp(acts[a].name, tokbuf) != 0)
				continue;
			rc = acts[a].action(m);
			break;
		}
	} while (rc);
}
