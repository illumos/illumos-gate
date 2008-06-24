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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<limits.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	"m4.h"

#define	arg(n)	(c < (n) ? nullstr: ap[n])
static void mkpid(char *);
static void def(wchar_t **, int, int);
static void dump(wchar_t *, wchar_t *);
static void incl(wchar_t **, int, int);
static int leftmatch(wchar_t *, wchar_t *);

static void
dochcom(wchar_t **ap, int c)
{
	wchar_t	*l = arg(1);
	wchar_t	*r = arg(2);

	if (wcslen(l) > MAXSYM || wcslen(r) > MAXSYM)
		error2(gettext(
		"comment marker longer than %d chars"), MAXSYM);
	(void) wcscpy(lcom, l);
	(void) wcscpy(rcom, *r ? r : L"\n");
}

static void
docq(wchar_t **ap, int c)
{
	wchar_t	*l = arg(1);
	wchar_t	*r = arg(2);

	if (wcslen(l) > MAXSYM || wcslen(r) > MAXSYM)
		error2(gettext(
		"quote marker longer than %d chars"), MAXSYM);

	if (c <= 1 && !*l) {
		l = L"`";
		r = L"'";
	} else if (c == 1) {
		r = l;
	}

	(void) wcscpy(lquote, l);
	(void) wcscpy(rquote, r);
}

static void
dodecr(wchar_t **ap, int c)
{
	pbnum(ctol(arg(1))-1);
}

void
dodef(wchar_t **ap, int c)
{
	def(ap, c, NOPUSH);
}

static void
def(wchar_t **ap, int c, int mode)
{
	wchar_t	*s;

	if (c < 1)
		return;

	s = ap[1];
	if (is_alpha(*s) || *s == '_') {
		s++;
		while (is_alnum(*s) || *s == '_')
			s++;
	}
	if (*s || s == ap[1])
		error(gettext("bad macro name"));

	if ((ap[2] != NULL) && (wcscmp(ap[1], ap[2]) == 0))
		error(gettext("macro defined as itself"));

	install(ap[1], arg(2), mode);
}

static void
dodefn(wchar_t **ap, int c)
{
	wchar_t *d;

	while (c > 0)
		if ((d = lookup(ap[c--])->def) != NULL) {
			putbak(*rquote);
			while (*d)
				putbak(*d++);
			putbak(*lquote);
		}
}

static void
dodiv(wchar_t **ap, int c)
{
	int f;

	f = wstoi(arg(1));
	if (f >= 10 || f < 0) {
		cf = NULL;
		ofx = f;
		return;
	}
	tempfile[7] = 'a'+f;
	if (ofile[f] || (ofile[f] = xfopen(tempfile, "w"))) {
		ofx = f;
		cf = ofile[f];
	}
}

/* ARGSUSED */
static void
dodivnum(wchar_t **ap, int c)
{
	pbnum((long)ofx);
}

/* ARGSUSED */
static void
dodnl(wchar_t **ap, int c)
{
	wchar_t t;

	while ((t = getchr()) != '\n' && t != WEOF)
		;
}

static void
dodump(wchar_t **ap, int c)
{
	struct nlist *np;
	int	i;

	if (c > 0)
		while (c--) {
			if ((np = lookup(*++ap))->name != NULL)
				dump(np->name, np->def);
		}
	else
		for (i = 0; i < hshsize; i++)
			for (np = hshtab[i]; np != NULL; np = np->next)
				dump(np->name, np->def);
}

/*ARGSUSED*/
static void
dump(wchar_t *name, wchar_t *defnn)
{
	wchar_t	*s = defnn;

#if !defined(__lint)	/* lint doesn't grok "%ws" */
	(void) fprintf(stderr, "%ws:\t", name);
#endif

	while (*s++)
		;
	--s;

	while (s > defnn) {
		--s;
		if (is_builtin(*s)) {
#if !defined(__lint)	/* lint doesn't grok "%ws" */
			(void) fprintf(stderr, "<%ws>",
			    barray[builtin_idx(*s)].bname);
		} else {
#endif
			(void) fputwc(*s, stderr);
		}
	}
	(void) fputc('\n', stderr);
}

/*ARGSUSED*/
static void
doerrp(wchar_t **ap, int c)
{
#if !defined(__lint)	/* lint doesn't grok "%ws" */
	if (c > 0)
		(void) fprintf(stderr, "%ws", ap[1]);
#endif
}

long	evalval;	/* return value from yacc stuff */
wchar_t	*pe;	/* used by grammar */

static void
doeval(wchar_t **ap, int c)
{
	int base = wstoi(arg(2));
	int pad = wstoi(arg(3));
	extern	int yyparse(void);

	evalval = 0;
	if (c > 0) {
		pe = ap[1];
		if (yyparse() != 0)
			error(gettext(
			"invalid expression"));
	}
	pbnbr(evalval, base > 0 ? base:10, pad > 0 ? pad : 1);
}

/*
 * doexit
 *
 * Process m4exit macro.
 */
static void
doexit(wchar_t **ap, int c)
{
	delexit(wstoi(arg(1)), 1);
}

static void
doif(wchar_t **ap, int c)
{
	if (c < 3)
		return;
	while (c >= 3) {
		if (wcscmp(ap[1], ap[2]) == 0) {
			pbstr(ap[3]);
			return;
		}
		c -= 3;
		ap += 3;
	}
	if (c > 0)
		pbstr(ap[1]);
}

static void
doifdef(wchar_t **ap, int c)
{
	if (c < 2)
		return;

	while (c >= 2) {
		if (lookup(ap[1])->name != NULL) {
			pbstr(ap[2]);
			return;
		}
		c -= 2;
		ap += 2;
	}

	if (c > 0)
		pbstr(ap[1]);
}

static void
doincl(wchar_t **ap, int c)
{
	incl(ap, c, 1);
}

static void
incl(wchar_t **ap, int c, int noisy)
{
	if (c > 0 && wcslen(ap[1]) > 0) {
		if (ifx >= 9)
			error(gettext(
			"input file nesting too deep (9)"));
		if ((ifile[++ifx] = fopen(wstr2str(ap[1], 0), "r")) == NULL) {
			--ifx;
			if (noisy)
				error(gettext(
				"can't open file"));
		} else {
			ipstk[ifx] = ipflr = ip;
			setfname(wstr2str(ap[1], 0));
		}
	}
}

static void
doincr(wchar_t **ap, int c)
{
	pbnum(ctol(arg(1))+1);
}

static void
doindex(wchar_t **ap, int c)
{
	wchar_t	*subj = arg(1);
	wchar_t	*obj  = arg(2);
	int	i;

	for (i = 0; *subj; ++i)
		if (leftmatch(subj++, obj)) {
			pbnum((long)i);
			return;
		}

	pbnum((long)-1);
}

static int
leftmatch(wchar_t *str, wchar_t *substr)
{
	while (*substr)
		if (*str++ != *substr++)
			return (0);

	return (1);
}

static void
dolen(wchar_t **ap, int c)
{
	pbnum((long)wcslen(arg(1)));
}

static void
domake(wchar_t **ap, int c)
{
	char *path;

	if (c > 0) {
		path = wstr2str(ap[1], 1);
		mkpid(path);
		pbstr(str2wstr(path, 0));
		free(path);
	}
}

static void
dopopdef(wchar_t **ap, int c)
{
	int	i;

	for (i = 1; i <= c; ++i)
		(void) undef(ap[i]);
}

static void
dopushdef(wchar_t **ap, int c)
{
	def(ap, c, PUSH);
}

static void
doshift(wchar_t **ap, int c)
{
	if (c <= 1)
		return;

	for (;;) {
		pbstr(rquote);
		pbstr(ap[c--]);
		pbstr(lquote);

		if (c <= 1)
			break;

		pbstr(L",");
	}
}

static void
dosincl(wchar_t **ap, int c)
{
	incl(ap, c, 0);
}

static void
dosubstr(wchar_t **ap, int c)
{
	wchar_t	*str;
	int	inlen, outlen;
	int	offset, ix;

	inlen = wcslen(str = arg(1));
	offset = wstoi(arg(2));

	if (offset < 0 || offset >= inlen)
		return;

	outlen = c >= 3 ? wstoi(ap[3]) : inlen;
	ix = min(offset+outlen, inlen);

	while (ix > offset)
		putbak(str[--ix]);
}

static void
dosyscmd(wchar_t **ap, int c)
{
	sysrval = 0;
	if (c > 0) {
		(void) fflush(stdout);
		sysrval = system(wstr2str(ap[1], 0));
	}
}

/* ARGSUSED */
static void
dosysval(wchar_t **ap, int c)
{
	pbnum((long)(sysrval < 0 ? sysrval :
	    (sysrval >> 8) & ((1 << 8) - 1)) |
	    ((sysrval & ((1 << 8) - 1)) << 8));
}

static void
dotransl(wchar_t **ap, int c)
{
	wchar_t	*sink, *fr, *sto;
	wchar_t	*source, *to;

	if (c < 1)
		return;

	sink = ap[1];
	fr = arg(2);
	sto = arg(3);

	for (source = ap[1]; *source; source++) {
		wchar_t	*i;
		to = sto;
		for (i = fr; *i; ++i) {
			if (*source == *i)
				break;
			if (*to)
				++to;
		}
		if (*i) {
			if (*to)
				*sink++ = *to;
		} else
			*sink++ = *source;
	}
	*sink = EOS;
	pbstr(ap[1]);
}

static void
dotroff(wchar_t **ap, int c)
{
	struct nlist	*np;

	trace = 0;

	while (c > 0)
		if ((np = lookup(ap[c--]))->name)
			np->tflag = 0;
}

static void
dotron(wchar_t **ap, int c)
{
	struct nlist	*np;

	trace = !*arg(1);

	while (c > 0)
		if ((np = lookup(ap[c--]))->name)
			np->tflag = 1;
}

void
doundef(wchar_t **ap, int c)
{
	int	i;

	for (i = 1; i <= c; ++i)
		while (undef(ap[i]))
			;
}

int
undef(wchar_t *nam)
{
	struct	nlist *np, *tnp;

	if ((np = lookup(nam))->name == NULL)
		return (0);
	tnp = hshtab[hshval];	/* lookup sets hshval */
	if (tnp == np)	/* it's in first place */
		hshtab[hshval] = tnp->next;
	else {
		while (tnp->next != np)
			tnp = tnp->next;

		tnp->next = np->next;
	}
	free(np->name);
	free(np->def);
	free(np);
	return (1);
}

static void
doundiv(wchar_t **ap, int c)
{
	int i;

	if (c <= 0)
		for (i = 1; i < 10; i++)
			undiv(i, OK);
	else
		while (--c >= 0)
			undiv(wstoi(*++ap), OK);
}

/*
 * dowrap
 *
 * Process m4wrap macro.
 */
static void
dowrap(wchar_t **ap, int c)
{
	wchar_t	*a = arg(1);
	struct Wrap *wrapentry;		/* entry for list of "m4wrap" strings */

	wrapentry = xmalloc(sizeof (struct Wrap));
	/* store m4wrap string */
	wrapentry->wrapstr = wstrdup(a);
	/* add this entry to the front of the list of Wrap entries */
	wrapentry->nxt = wrapstart;
	wrapstart = wrapentry;
}

static void
mkpid(char *as)
{
	char *s = as;
	char *l;
	char *first_X;
	unsigned xcnt = 0;
	char my_pid[32];
	int pid_len;
	int i = 0;

	/*
	 * Count number of X.
	 */
	l = &s[strlen(s)-1];
	while (l != as) {
		if (*l == 'X') {
			first_X = l;
			l--;
			xcnt++;
		} else if (xcnt == 0)
			l--;
		else {
			break;
		}
	}

	/*
	 *	1) If there is no X in the passed string,
	 *		then it just return the passed string.
	 *	2) If the length of the continuous right most X's of
	 *	   the string is shorter than the length of pid,
	 *		then right most X's will be substitued with
	 *		upper digits of pid.
	 *	3) If the length of the continuous right most X's of
	 *	   the string is equat to the length of pid,
	 *		then X's will be replaced with pid.
	 *	4) If the lenght of the continuous right most X's of
	 *	   the string is longer than the length of pid,
	 *		then X's will have leading 0 followed by
	 *		pid.
	 */

	/*
	 * If there were no X, don't do anything.
	 */
	if (xcnt == 0)
		return;

	/*
	 * Get pid
	 */
	(void) snprintf(my_pid, sizeof (my_pid), "%d", (int)getpid());
	pid_len = strlen(my_pid);

	if (pid_len > xcnt)
		my_pid[xcnt] = 0;
	else if (pid_len < xcnt) {
		while (xcnt != pid_len) {
			*first_X++ = '0';
			xcnt--;
		}
	}

	/*
	 * Copy pid
	 */
	while (i != xcnt)
		*first_X++ = my_pid[i++];
}

struct bs	barray[] = {
	dochcom,	L"changecom",
	docq,		L"changequote",
	dodecr,		L"decr",
	dodef,		L"define",
	dodefn,		L"defn",
	dodiv,		L"divert",
	dodivnum,	L"divnum",
	dodnl,		L"dnl",
	dodump,		L"dumpdef",
	doerrp,		L"errprint",
	doeval,		L"eval",
	doexit,		L"m4exit",
	doif,		L"ifelse",
	doifdef,	L"ifdef",
	doincl,		L"include",
	doincr,		L"incr",
	doindex,	L"index",
	dolen,		L"len",
	domake,		L"maketemp",
	dopopdef,	L"popdef",
	dopushdef,	L"pushdef",
	doshift,	L"shift",
	dosincl,	L"sinclude",
	dosubstr,	L"substr",
	dosyscmd,	L"syscmd",
	dosysval,	L"sysval",
	dotransl,	L"translit",
	dotroff,	L"traceoff",
	dotron,		L"traceon",
	doundef,	L"undefine",
	doundiv,	L"undivert",
	dowrap,		L"m4wrap",
	0,		0
};
