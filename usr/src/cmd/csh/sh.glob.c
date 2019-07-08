/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "sh.h"
#include "sh.tconst.h"
#include <dirent.h>
#include <strings.h>
#ifdef MBCHAR
#include <widec.h>	/* wcsetno() */
#include <fnmatch.h>	/* fnmatch() */
#endif /* MBCHAR */

/*
 * C Shell
 */

int	globcnt;

tchar	*gpath, *gpathp, *lastgpathp;
int	globbed;
bool	noglob;
bool	nonomatch;
tchar	*entp;
tchar	**sortbas;
int	sortscmp(tchar **, tchar **);
void	ginit(tchar **);
void	collect(tchar *);
void	acollect(tchar *);
void	expand(tchar *);
void	matchdir_(tchar *);
void	Gcat(tchar *, tchar *);
void	addpath(tchar);
void	tglob(tchar **);
tchar	**dobackp(tchar *, bool);
void	backeval(tchar *, bool);
void	psave(tchar);
void	pword(void);

extern	DIR *opendir_(tchar *);

#define	sort()	qsort((char *)sortbas, &gargv[gargc] - sortbas, \
			sizeof (*sortbas), (int (*)(const void *, \
			const void *)) sortscmp), sortbas = &gargv[gargc]


tchar **
glob(tchar **v)
{
	tchar agpath[BUFSIZ];
	tchar *agargv[GAVSIZ];

	gpath = agpath; gpathp = gpath; *gpathp = 0;
	lastgpathp = &gpath[BUFSIZ - 2];
	ginit(agargv); globcnt = 0;
#ifdef TRACE
	tprintf("TRACE- glob()\n");
#endif
#ifdef GDEBUG
	printf("glob entered: "); blkpr(v); printf("\n");
#endif
	noglob = adrof(S_noglob /* "noglob" */) != 0;
	nonomatch = adrof(S_nonomatch /* "nonomatch" */) != 0;
	globcnt = noglob | nonomatch;
	while (*v)
		collect(*v++);
#ifdef GDEBUG
	printf("glob done, globcnt=%d, gflag=%d: ", globcnt, gflag);
	blkpr(gargv); printf("\n");
#endif
	if (globcnt == 0 && (gflag&1)) {
		blkfree(gargv), gargv = 0;
		return (0);
	} else
		return (gargv = copyblk(gargv));
}

void
ginit(tchar **agargv)
{

	agargv[0] = 0; gargv = agargv; sortbas = agargv; gargc = 0;
	gnleft = NCARGS - 4;
}

void
collect(tchar *as)
{
	int i;

#ifdef TRACE
	tprintf("TRACE- collect()\n");
#endif
	if (any('`', as)) {
#ifdef GDEBUG
		printf("doing backp of %t\n", as);
#endif
		(void) dobackp(as, 0);
#ifdef GDEBUG
		printf("backp done, acollect'ing\n");
#endif
		/*
		 * dobackp has the side effect of messing with
		 * gflag, since it does more globbing, so check
		 * if the results is still globbable
		 */
		tglob(pargv);

		for (i = 0; i < pargc; i++)
			if (noglob) {
				Gcat(pargv[i], S_ /* "" */);
				sortbas = &gargv[gargc];
			} else
				acollect(pargv[i]);
		if (pargv)
			blkfree(pargv), pargv = 0;
#ifdef GDEBUG
		printf("acollect done\n");
#endif
	} else if (noglob || eq(as, S_LBRA /* "{" */) ||
	    eq(as, S_BRABRA /* "{}" */)) {
		Gcat(as, S_ /* "" */);
		sort();
	} else
		acollect(as);
}

void
acollect(tchar *as)
{
	long ogargc = gargc;

#ifdef TRACE
	tprintf("TRACE- acollect()\n");
#endif
	gpathp = gpath; *gpathp = 0; globbed = 0;
	expand(as);
	if (gargc == ogargc) {
		if (nonomatch) {
			Gcat(as, S_ /* "" */);
			sort();
		}
	} else
		sort();
}

/*
 * String compare for qsort.  Also used by filec code in sh.file.c.
 */
int
sortscmp(tchar **a1, tchar **a2)
{

	return (strcoll_(*a1, *a2));
}

void
expand(tchar *as)
{
	tchar *cs;
	tchar *sgpathp, *oldcs;
	struct stat stb;

#ifdef TRACE
	tprintf("TRACE- expand()\n");
#endif
	sgpathp = gpathp;
	cs = as;
	if (*cs == '~' && gpathp == gpath) {
		addpath('~');
		for (cs++; alnum(*cs) || *cs == '-'; )
			addpath(*cs++);
		if (!*cs || *cs == '/') {
			if (gpathp != gpath + 1) {
				*gpathp = 0;
				if (gethdir(gpath + 1))
					/*
					 * modified from %s to %t
					 */
					error("Unknown user: %t", gpath + 1);
				(void) strcpy_(gpath, gpath + 1);
			} else
				(void) strcpy_(gpath,
				    value(S_home /* "home" */));
			gpathp = strend(gpath);
		}
	}
	while (!isglob(*cs)) {
		if (*cs == 0) {
			if (!globbed)
				Gcat(gpath, S_ /* "" */);
			else if (lstat_(gpath, &stb) >= 0) {
				Gcat(gpath, S_ /* "" */);
				globcnt++;
			}
			goto endit;
		}
		addpath(*cs++);
	}
	oldcs = cs;
	while (cs > as && *cs != '/')
		cs--, gpathp--;
	if (*cs == '/')
		cs++, gpathp++;
	*gpathp = 0;
	if (*oldcs == '{') {
		(void) execbrc(cs, NOSTR);
		return;
	}
	matchdir_(cs);
endit:
	gpathp = sgpathp;
	*gpathp = 0;
}

void
matchdir_(tchar *pattern)
{
	struct stat stb;
	struct dirent *dp;
	DIR *dirp;
	tchar curdir_[MAXNAMLEN+1];
	int slproc = 0;

#ifdef TRACE
	tprintf("TRACE- matchdir()\n");
#endif
	/*
	 * BSD's opendir would open "." if argument is NULL, but not S5
	 */

	if (*gpath == '\0')
		dirp = opendir_(S_DOT /* "." */);
	else
		dirp = opendir_(gpath);
	if (dirp == NULL) {
		if (globbed)
			return;
		goto patherr2;
	}
	if (fstat(dirp->dd_fd, &stb) < 0)
		goto patherr1;
	if (!isdir(stb)) {
		errno = ENOTDIR;
		goto patherr1;
	}
	while ((dp = readdir(dirp)) != NULL) {

		if (dp->d_ino == 0)
			continue;
		strtots(curdir_, dp->d_name);
		slproc = 0;
		if (match(curdir_, pattern, &slproc)) {
			Gcat(gpath, curdir_);
			globcnt++;
		}
	}
	unsetfd(dirp->dd_fd);
	closedir_(dirp);
	return;

patherr1:
	unsetfd(dirp->dd_fd);
	closedir_(dirp);
patherr2:
	Perror(gpath);
}

int
execbrc(tchar *p, tchar *s)
{
	tchar restbuf[BUFSIZ + 2];
	tchar *pe, *pm, *pl;
	int brclev = 0;
	tchar *lm, savec, *sgpathp;
	int slproc = 0;

#ifdef TRACE
	tprintf("TRACE- execbrc()\n");
#endif
	for (lm = restbuf; *p != '{'; *lm++ = *p++)
		continue;
	for (pe = ++p; *pe; pe++)
	switch (*pe) {

	case '{':
		brclev++;
		continue;

	case '}':
		if (brclev == 0)
			goto pend;
		brclev--;
		continue;

	case '[':
		for (pe++; *pe && *pe != ']'; pe++)
			continue;
		if (!*pe)
			error("Missing ]");
		continue;
	}
pend:
	if (brclev || !*pe)
		error("Missing }");
	for (pl = pm = p; pm <= pe; pm++)
	switch (*pm & (QUOTE|TRIM)) {

	case '{':
		brclev++;
		continue;

	case '}':
		if (brclev) {
			brclev--;
			continue;
		}
		goto doit;

	case ',':
		if (brclev)
			continue;
doit:
		savec = *pm;
		*pm = 0;
		(void) strcpy_(lm, pl);
		(void) strcat_(restbuf, pe + 1);
		*pm = savec;
		if (s == 0) {
			sgpathp = gpathp;
			expand(restbuf);
			gpathp = sgpathp;
			*gpathp = 0;
		} else if (amatch(s, restbuf, &slproc))
			return (1);
		sort();
		pl = pm + 1;
		continue;

	case '[':
		for (pm++; *pm && *pm != ']'; pm++)
			continue;
		if (!*pm)
			error("Missing ]");
		continue;
	}
	return (0);
}

int
match(tchar *s, tchar *p, int *slproc)
{
	int c;
	tchar *sentp;
	tchar sglobbed = globbed;

#ifdef TRACE
	tprintf("TRACE- match()\n");
#endif
	if (*s == '.' && *p != '.')
		return (0);
	sentp = entp;
	entp = s;
	c = amatch(s, p, slproc);
	entp = sentp;
	globbed = sglobbed;
	return (c);
}

int
amatch(tchar *s, tchar *p, int *slproc)
{
	int scc;
	int ok, lc;
	tchar *sgpathp;
	struct stat stb;
	int c, cc;

#ifdef TRACE
	tprintf("TRACE- amatch()\n");
#endif
	globbed = 1;
	for (;;) {
		scc = *s++ & TRIM;
		switch (c = *p++) {

		case '{':
			return (execbrc(p - 1, s - 1));

		case '[':
			ok = 0;
			lc = TRIM;
			while (cc = *p++) {
				if (cc == ']') {
					if (ok)
						break;
					return (0);
				}
				if (cc == '-') {
#ifdef MBCHAR
					wchar_t rc = *p++;
					if (rc == ']') {
						p--;
						continue;
					}
					/*
					 * Both ends of the char range
					 * must belong to the same codeset.
					 */
					if (sh_bracket_exp(scc, lc, rc))
						ok++;
#else /* !MBCHAR */
					if (lc <= scc && scc <= (int)*p++)
						ok++;
#endif /* !MBCHAR */
				} else
					if (scc == (lc = cc))
						ok++;
			}
			if (cc == 0)
				error("Missing ]");
			continue;

		case '*':
			if (!*p)
				return (1);
			if (*p == '/') {
				p++;
				goto slash;
			} else if (*p == '*') {
				s--;
				continue;
			}

			for (s--; *s; s++)
				if (amatch(s, p, slproc))
					return (1);

			return (0);

		case 0:
			return (scc == 0);

		default:
			if ((c & TRIM) != scc)
				return (0);
			continue;

		case '?':
			if (scc == 0)
				return (0);
			continue;

		case '/':
			if (scc)
				return (0);
slash:
			if (*slproc)	/* Need to expand "/" only once */
				return (0);
			else
				*slproc = 1;

			s = entp;
			sgpathp = gpathp;
			while (*s)
				addpath(*s++);
			addpath('/');
			if (stat_(gpath, &stb) == 0 && isdir(stb))
				if (*p == 0) {
					Gcat(gpath, S_ /* "" */);
					globcnt++;
				} else
					expand(p);
			gpathp = sgpathp;
			*gpathp = 0;
			return (0);
		}
	}
}

int
Gmatch(tchar *s, tchar *p)
{
	int scc;
	int ok, lc;
	int c, cc;

#ifdef TRACE
	tprintf("TRACE- Gmatch()\n");
#endif
	for (;;) {
		scc = *s++ & TRIM;
		switch (c = *p++) {

		case '[':
			ok = 0;
			lc = TRIM;
			while (cc = *p++) {
				if (cc == ']') {
					if (ok)
						break;
					return (0);
				}
				if (cc == '-') {
#ifdef MBCHAR
					wchar_t rc = *p++;
					/*
					 * Both ends of the char range
					 * must belong to the same codeset...
					 */
					if (sh_bracket_exp(scc, lc, rc))
						ok++;
#else /* !MBCHAR */
					if (lc <= scc && scc <= (int)*p++)
						ok++;
#endif /* !MBCHAR */
				} else
					if (scc == (lc = cc))
						ok++;
			}
			if (cc == 0)
				bferr("Missing ]");
			continue;

		case '*':
			if (!*p)
				return (1);
			for (s--; *s; s++)
				if (Gmatch(s, p))
					return (1);
			return (0);

		case 0:
			return (scc == 0);

		default:
			if ((c & TRIM) != scc)
				return (0);
			continue;

		case '?':
			if (scc == 0)
				return (0);
			continue;

		}
	}
}

void
Gcat(tchar *s1, tchar *s2)
{
	tchar *p, *q;
	int n;

#ifdef TRACE
	tprintf("TRACE- Gcat()\n");
#endif
	for (p = s1; *p++; )
		;
	for (q = s2; *q++; )
		;
	gnleft -= (n = (p - s1) + (q - s2) - 1);
	if (gnleft <= 0 || ++gargc >= GAVSIZ)
		error("Arguments too long");
	gargv[gargc] = 0;
	p = gargv[gargc - 1] = (tchar *) xalloc((unsigned)n*sizeof (tchar));

	for (q = s1; *p++ = *q++; )
		;
	for (p--, q = s2; *p++ = *q++; )
		;
}

void
addpath(tchar c)
{

#ifdef TRACE
	tprintf("TRACE- addpath()\n");
#endif
	if (gpathp >= lastgpathp)
		error("Pathname too long");
	*gpathp++ = c & TRIM;
	*gpathp = 0;
}

void
rscan(tchar **t, int (*f)(int))
{
	tchar *p;

#ifdef TRACE
	tprintf("TRACE- rscan()\n");
#endif
	while (p = *t++)
		while (*p)
			(*f)(*p++);
}

void
trim(tchar **t)
{
	tchar *p;

#ifdef TRACE
	tprintf("TRACE- trim()\n");
#endif
	while (p = *t++)
		while (*p)
			*p++ &= TRIM;
}

void
tglob(tchar **t)
{
	tchar *p, c;

#ifdef TRACE
	tprintf("TRACE- tglob()\n");
#endif
	while (p = *t++) {
		if (*p == '~')
			gflag |= 2;
		else if (*p == '{' && (p[1] == '\0' ||
		    p[1] == '}' && p[2] == '\0'))
			continue;
		while (c = *p++)
			if (isglob(c))
				gflag |= c == '{' ? 2 : 1;
	}
}

tchar *
globone(tchar *str)
{
	tchar *gv[2];
	tchar **gvp;
	tchar *cp;

#ifdef TRACE
	tprintf("TRACE- globone()\n");
#endif
	gv[0] = str;
	gv[1] = 0;
	gflag = 0;
	tglob(gv);
	if (gflag) {
		gvp = glob(gv);
		if (gvp == 0) {
			setname(str);
			bferr("No match");
		}
		cp = *gvp++;
		if (cp == 0)
			cp = S_ /* "" */;
		else if (*gvp) {
			setname(str);
			bferr("Ambiguous");
		} else
			cp = strip(cp);
#if 0
		if (cp == 0 || *gvp) {
			setname(str);
			bferr(cp ? "Ambiguous" : "No output");
		}
#endif
		xfree((char *)gargv); gargv = 0;
	} else {
		trim(gv);
		cp = savestr(gv[0]);
	}
	return (cp);
}

/*
 * Command substitute cp.  If literal, then this is
 * a substitution from a << redirection, and so we should
 * not crunch blanks and tabs, separating words only at newlines.
 */
tchar **
dobackp(tchar *cp, bool literal)
{
	tchar *lp, *rp;
	tchar *ep;
	tchar word[BUFSIZ];
	tchar *apargv[GAVSIZ + 2];

#ifdef TRACE
	tprintf("TRACE- dobackp()\n");
#endif
	if (pargv) {
		blkfree(pargv);
	}
	pargv = apargv;
	pargv[0] = NOSTR;
	pargcp = pargs = word;
	pargc = 0;
	pnleft = BUFSIZ - 4;
	for (;;) {
		for (lp = cp; *lp != '`'; lp++) {
			if (*lp == 0) {
				if (pargcp != pargs)
					pword();
#ifdef GDEBUG
				printf("leaving dobackp\n");
#endif
				return (pargv = copyblk(pargv));
			}
			psave(*lp);
		}
		lp++;
		for (rp = lp; *rp && *rp != '`'; rp++)
			if (*rp == '\\') {
				rp++;
				if (!*rp)
					goto oops;
			}
		if (!*rp)
oops:
			error("Unmatched `");
		ep = savestr(lp);
		ep[rp - lp] = 0;
		backeval(ep, literal);
#ifdef GDEBUG
		printf("back from backeval\n");
#endif
		cp = rp + 1;
	}
}

void
backeval(tchar *cp, bool literal)
{
	int pvec[2];
	int quoted = (literal || (cp[0] & QUOTE)) ? QUOTE : 0;
	tchar ibuf[BUFSIZ + MB_LEN_MAX]; /* read_ can return extra bytes */
	int icnt = 0, c;
	tchar *ip;
	bool hadnl = 0;
	tchar *fakecom[2];
	struct command faket;

#ifdef TRACE
	tprintf("TRACE- backeval()\n");
#endif
	faket.t_dtyp = TCOM;
	faket.t_dflg = 0;
	faket.t_dlef = 0;
	faket.t_drit = 0;
	faket.t_dspr = 0;
	faket.t_dcom = fakecom;
	fakecom[0] = S_QPPPQ; /* "` ... `" */;
	fakecom[1] = 0;
	/*
	 * We do the psave job to temporarily change the current job
	 * so that the following fork is considered a separate job.
	 * This is so that when backquotes are used in a
	 * builtin function that calls glob the "current job" is not corrupted.
	 * We only need one level of pushed jobs as long as we are sure to
	 * fork here.
	 */
	psavejob();
	/*
	 * It would be nicer if we could integrate this redirection more
	 * with the routines in sh.sem.c by doing a fake execute on a builtin
	 * function that was piped out.
	 */
	mypipe(pvec);
	if (pfork(&faket, -1) == 0) {
		struct wordent paraml;
		struct command *t;
		tchar oHIST;

		new_process();
		(void) close(pvec[0]);
		unsetfd(pvec[0]);
		(void) dmove(pvec[1], 1);
		(void) dmove(SHDIAG, 2);
		reinitdesc(0, NULL);
		arginp = cp;
		while (*cp)
			*cp++ &= TRIM;
		/*
		 *	disable history subsitution in sub-shell
		 *  of `` evaluation prevents possible
		 *  infinite recursion of `` evaluation
		 */
		oHIST = HIST;
		HIST = 0;
		(void) lex(&paraml);
		HIST = oHIST;
		if (err)
			error("%s", gettext(err));
		alias(&paraml);
		t = syntax(paraml.next, &paraml, 0);
		if (err)
			error("%s", gettext(err));
		if (t)
			t->t_dflg |= FPAR;
		(void) signal(SIGTSTP, SIG_IGN);
		(void) signal(SIGTTIN, SIG_IGN);
		(void) signal(SIGTTOU, SIG_IGN);
		execute(t, -1);
		exitstat();
	}
	xfree(cp);
	(void) close(pvec[1]);
	unsetfd(pvec[1]);
	do {
		int cnt = 0;
		for (;;) {
			if (icnt == 0) {
				ip = ibuf;
				icnt = read_(pvec[0], ip, BUFSIZ);
				if (icnt <= 0) {
					c = -1;
					break;
				}
			}
			if (hadnl)
				break;
			--icnt;
			c = (*ip++ & TRIM);
			if (c == 0)
				break;
			if (c == '\n') {
				/*
				 * Continue around the loop one
				 * more time, so that we can eat
				 * the last newline without terminating
				 * this word.
				 */
				hadnl = 1;
				continue;
			}
			if (!quoted && issp(c))
				break;
			cnt++;
			psave(c | quoted);
		}
		/*
		 * Unless at end-of-file, we will form a new word
		 * here if there were characters in the word, or in
		 * any case when we take text literally.  If
		 * we didn't make empty words here when literal was
		 * set then we would lose blank lines.
		 */
		if (c != -1 && (cnt || literal)) {
			if (pargc == GAVSIZ)
				break;
			pword();
		}
		hadnl = 0;
	} while (c >= 0);
#ifdef GDEBUG
	printf("done in backeval, pvec: %d %d\n", pvec[0], pvec[1]);
	printf("also c = %c <%o>\n", (tchar) c, (tchar) c);
#endif
	(void) close(pvec[0]);
	unsetfd(pvec[0]);
	pwait();
	prestjob();
}

void
psave(tchar c)
{
#ifdef TRACE
	tprintf("TRACE- psave()\n");
#endif

	if (--pnleft <= 0)
		error("Word too long");
	*pargcp++ = c;
}

void
pword(void)
{
#ifdef TRACE
	tprintf("TRACE- pword()\n");
#endif

	psave(0);
	if (pargc == GAVSIZ)
		error("Too many words from ``");
	pargv[pargc++] = savestr(pargs);
	pargv[pargc] = NOSTR;
#ifdef GDEBUG
	printf("got word %t\n", pargv[pargc-1]);
#endif
	pargcp = pargs;
	pnleft = BUFSIZ - 4;
}



/*
 * returns pathname of the form dir/file;
 *  dir is a null-terminated string;
 */
char *
makename(char *dir, char *file)
{
	/*
	 *  Maximum length of a
	 *  file/dir name in ls-command;
	 *  dfile is static as this is returned
	 *  by makename();
	 */
	static char dfile[MAXNAMLEN];

	char *dp, *fp;

	dp = dfile;
	fp = dir;
	while (*fp)
		*dp++ = *fp++;
	if (dp > dfile && *(dp - 1) != '/')
		*dp++ = '/';
	fp = file;
	while (*fp)
		*dp++ = *fp++;
	*dp = '\0';
	/*
	 * dfile points to the absolute pathname. We are
	 * only interested in the last component.
	 */
	return (rindex(dfile, '/') + 1);
}

int
sh_bracket_exp(tchar t_ch, tchar t_fch, tchar t_lch)
{
	char	t_char[MB_LEN_MAX + 1];
	char	t_patan[MB_LEN_MAX * 2 + 8];
	char	*p;
	int	i;

	if ((t_ch == t_fch) || (t_ch == t_lch))
		return (1);

	p = t_patan;
	if ((i = wctomb(t_char, (wchar_t)t_ch)) <= 0)
		return (0);
	t_char[i] = 0;

	*p++ = '[';
	if ((i = wctomb(p, (wchar_t)t_fch)) <= 0)
		return (0);
	p += i;
	*p++ = '-';
	if ((i = wctomb(p, (wchar_t)t_lch)) <= 0)
		return (0);
	p += i;
	*p++ = ']';
	*p = 0;

	if (fnmatch(t_patan, t_char, FNM_NOESCAPE))
		return (0);
	return (1);
}
