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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2011 Gary Mills
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include	<signal.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	"m4.h"

#if defined(__lint)
extern int yydebug;
#endif

#define	match(c, s)	(c == *s && (!s[1] || inpmatch(s+1)))

static char	tmp_name[] = "/tmp/m4aXXXXX";
static wchar_t	prev_char;
static int mb_cur_max;

static void getflags(int *, char ***, int *);
static void initalloc(void);
static void expand(wchar_t **, int);
static void lnsync(FILE *);
static void fpath(FILE *);
static void puttok(wchar_t *);
static void error3(void);
static wchar_t itochr(int);
/*LINTED: E_STATIC_UNUSED*/
static wchar_t *chkbltin(wchar_t *);
static wchar_t *inpmatch(wchar_t *);
static void chkspace(char **, int *, char ***);
static void catchsig(int);
static FILE *m4open(char ***, char *, int *);
static void showwrap(void);
static void sputchr(wchar_t, FILE *);
static void putchr(wchar_t);
static void *xcalloc(size_t, size_t);
static wint_t myfgetwc(FILE *, int);
static wint_t myfputwc(wchar_t, FILE *);
static int myfeof(int);

int
main(int argc, char **argv)
{
	wchar_t t;
	int i, opt_end = 0;
	int sigs[] = {SIGHUP, SIGINT, SIGPIPE, 0};

#if defined(__lint)
	yydebug = 0;
#endif

	for (i = 0; sigs[i]; ++i) {
		if (signal(sigs[i], SIG_IGN) != SIG_IGN)
			(void) signal(sigs[i], catchsig);
	}
	tempfile = mktemp(tmp_name);
	(void) close(creat(tempfile, 0));

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((mb_cur_max = MB_CUR_MAX) > 1)
		wide = 1;

	procnam = argv[0];
	getflags(&argc, &argv, &opt_end);
	initalloc();

	setfname("-");
	if (argc > 1) {
		--argc;
		++argv;
		if (strcmp(argv[0], "-")) {
			ifile[ifx] = m4open(&argv, "r", &argc);
			setfname(argv[0]);
		}
	}

	for (;;) {
		token[0] = t = getchr();
		token[1] = EOS;

		if (t == WEOF) {
			if (ifx > 0) {
				(void) fclose(ifile[ifx]);
				ipflr = ipstk[--ifx];
				continue;
			}

			getflags(&argc, &argv, &opt_end);

			if (argc <= 1)
				/*
				 * If dowrap() has been called, the m4wrap
				 * macro has been processed, and a linked
				 * list of m4wrap strings has been created.
				 * The list starts at wrapstart.
				 */
				if (wrapstart) {
					/*
					 * Now that EOF has been processed,
					 * display the m4wrap strings.
					 */
					showwrap();
					continue;
				} else
					break;
			--argc;
			++argv;

			if (ifile[ifx] != stdin)
				(void) fclose(ifile[ifx]);

			if (strcmp(argv[0], "-"))
				ifile[ifx] = m4open(&argv, "r", &argc);
			else
				ifile[ifx] = stdin;

			setfname(argv[0]);
			continue;
		}

		if (is_alpha(t) || t == '_') {
			wchar_t	*tp = token+1;
			int tlim = toksize;
			struct nlist	*macadd;  /* temp variable */

			while ((*tp = getchr()) != WEOF &&
			    (is_alnum(*tp) || *tp == '_')) {
				tp++;
				if (--tlim <= 0)
					error2(gettext(
					    "more than %d chars in word"),
					    toksize);
			}
			putbak(*tp);
			*tp = EOS;

			macadd = lookup(token);
			*Ap = (wchar_t *)macadd;
			if (macadd->def) {
				if ((wchar_t *)(++Ap) >= astklm) {
					--Ap;
					error2(gettext(
					    "more than %d items on "
					    "argument stack"),
					    stksize);
				}

				if (Cp++ == NULL)
					Cp = callst;

				Cp->argp = Ap;
				*Ap++ = op;
				puttok(token);
				stkchr(EOS);
				t = getchr();
				putbak(t);

				if (t != '(')
					pbstr(L"()");
				else	/* try to fix arg count */
					*Ap++ = op;

				Cp->plev = 0;
			} else {
				puttok(token);
			}
		} else if (match(t, lquote)) {
			int	qlev = 1;

			for (;;) {
				token[0] = t = getchr();
				token[1] = EOS;

				if (match(t, rquote)) {
					if (--qlev > 0)
						puttok(token);
					else
						break;
				} else if (match(t, lquote)) {
					++qlev;
					puttok(token);
				} else {
					if (t == WEOF)
						error(gettext(
						"EOF in quote"));
					putchr(t);
				}
			}
		} else if (match(t, lcom) &&
		    ((lcom[0] != L'#' || lcom[1] != L'\0') ||
		    prev_char != '$')) {

			/*
			 * Don't expand commented macro (between lcom and
			 * rcom).
			 * What we know so far is that we have found the
			 * left comment char (lcom).
			 * Make sure we haven't found '#' (lcom) immediately
			 * preceded by '$' because we want to expand "$#".
			 */

			puttok(token);
			for (;;) {
				token[0] = t = getchr();
				token[1] = EOS;
				if (match(t, rcom)) {
					puttok(token);
					break;
				} else {
					if (t == WEOF)
						error(gettext(
						"EOF in comment"));
					putchr(t);
				}
			}
		} else if (Cp == NULL) {
			putchr(t);
		} else if (t == '(') {
			if (Cp->plev)
				stkchr(t);
			else {
				/* skip white before arg */
				while ((t = getchr()) != WEOF && is_space(t))
					;

				putbak(t);
			}

			++Cp->plev;
		} else if (t == ')') {
			--Cp->plev;

			if (Cp->plev == 0) {
				stkchr(EOS);
				expand(Cp->argp, Ap-Cp->argp-1);
				op = *Cp->argp;
				Ap = Cp->argp-1;

				if (--Cp < callst)
					Cp = NULL;
			} else
				stkchr(t);
		} else if (t == ',' && Cp->plev <= 1) {
			stkchr(EOS);
			*Ap = op;

			if ((wchar_t *)(++Ap) >= astklm) {
				--Ap;
				error2(gettext(
				    "more than %d items on argument stack"),
				    stksize);
			}

			while ((t = getchr()) != WEOF && is_space(t))
				;

			putbak(t);
		} else {
			stkchr(t);
		}
	}

	if (Cp != NULL)
		error(gettext(
		"EOF in argument list"));

	delexit(exitstat, 1);
	return (0);
}

static wchar_t *
inpmatch(wchar_t *s)
{
	wchar_t	*tp = token+1;

	while (*s) {
		*tp = getchr();

		if (*tp++ != *s++) {
			*tp = EOS;
			pbstr(token+1);
			return (0);
		}
	}

	*tp = EOS;
	return (token);
}

static void
getflags(int *xargc, char ***xargv, int *option_end)
{
	char	*arg;
	char *t;
	wchar_t *s[3];

	while (*xargc > 1) {
		arg = (*xargv)[1]; /* point arg to current argument */

		/*
		 * This argument is not an option if it equals "-" or if
		 * "--" has already been parsed.
		 */
		if (arg[0] != '-' || arg[1] == EOS || *option_end)
			break;
		if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
			*option_end = 1;
		} else {
			switch (arg[1]) {
			case 'B':
				chkspace(&arg, xargc, xargv);
				bufsize = atoi(&arg[2]);
				if (bufsize <= 0) {
					bufsize = DEF_BUFSIZE;
				}
				break;
			case 'D':
				initalloc();
				chkspace(&arg, xargc, xargv);
				for (t = &arg[2]; *t; t++) {
					if (*t == '=') {
						*t++ = EOS;
						break;
					}
				}
				s[1] = str2wstr(&arg[2], 1);
				s[2] = str2wstr(t, 1);
				dodef(&s[0], 2);
				free(s[1]);
				free(s[2]);
				break;
			case 'H':
				chkspace(&arg, xargc, xargv);
				hshsize = atoi(&arg[2]);
				if (hshsize <= 0) {
					hshsize = DEF_HSHSIZE;
				}
				break;
			case 'S':
				chkspace(&arg, xargc, xargv);
				stksize = atoi(&arg[2]);
				if (stksize <= 0) {
					stksize = DEF_STKSIZE;
				}
				break;
			case 'T':
				chkspace(&arg, xargc, xargv);
				toksize = atoi(&arg[2]);
				if (toksize <= 0) {
					toksize = DEF_TOKSIZE;
				}
				break;
			case 'U':
				initalloc();
				chkspace(&arg, xargc, xargv);
				s[1] = str2wstr(&arg[2], 1);
				doundef(&s[0], 1);
				free(s[1]);
				break;
			case 'e':
				setbuf(stdout, NULL);
				(void) signal(SIGINT, SIG_IGN);
				break;
			case 's':
				/* turn on line sync */
				sflag = 1;
				break;
			default:
				(void) fprintf(stderr,
				    gettext("%s: bad option: %s\n"),
				    procnam, arg);
				delexit(NOT_OK, 0);
			}
		} /* end else not "--" */

		(*xargv)++;
		--(*xargc);
	} /* end while options to process */
}

/*
 * Function: chkspace
 *
 * If there is a space between the option and its argument,
 * adjust argptr so that &arg[2] will point to beginning of the option argument.
 * This will ensure that processing in getflags() will work, because &arg[2]
 * will point to the beginning of the option argument whether or not we have
 * a space between the option and its argument.  If there is a space between
 * the option and its argument, also adjust xargv and xargc because we are
 * processing the next argument.
 */
static void
chkspace(char **argptr, int *xargc, char ***xargv)
{
	if ((*argptr)[2] == EOS) {
		/* there is a space between the option and its argument */
		(*xargv)++; /* look at the next argument */
		--(*xargc);
		/*
		 * Adjust argptr if the option is followed by an
		 * option argument.
		 */
		if (*xargc > 1) {
			*argptr = (*xargv)[1];
			/* point &arg[2] to beginning of option argument */
			*argptr -= 2;
		}
	}
}

static void
initalloc(void)
{
	static int done = 0;
	int	t;

	if (done++)
		return;

	hshtab = xcalloc(hshsize, sizeof (struct nlist *));
	callst = xcalloc(stksize/3+1, sizeof (struct call));
	Ap = argstk = xcalloc(stksize+3, sizeof (wchar_t *));
	ipstk[0] = ipflr = ip = ibuf = xcalloc(bufsize+1, sizeof (wchar_t));
	op = obuf = xcalloc(bufsize+1, sizeof (wchar_t));
	token = xcalloc(toksize+1, sizeof (wchar_t));

	astklm = (wchar_t *)(&argstk[stksize]);
	ibuflm = &ibuf[bufsize];
	obuflm = &obuf[bufsize];
	toklm = &token[toksize];

	for (t = 0; barray[t].bname; ++t) {
		wchar_t	p[2] = {0, EOS};

		p[0] = builtin(t);
		install(barray[t].bname, p, NOPUSH);
	}
	install(L"unix", nullstr, NOPUSH);
}

void
install(wchar_t *nam, wchar_t *val, int mode)
{
	struct nlist *np;
	wchar_t	*cp;
	int		l;

	if (mode == PUSH)
		(void) lookup(nam);	/* lookup sets hshval */
	else
		while (undef(nam))	/* undef calls lookup */
			;

	np = xcalloc(1, sizeof (*np));
	np->name = wstrdup(nam);
	np->next = hshtab[hshval];
	hshtab[hshval] = np;

	cp = xcalloc((l = wcslen(val))+1, sizeof (*val));
	np->def = cp;
	cp = &cp[l];

	while (*val)
		*--cp = *val++;
}

struct nlist *
lookup(wchar_t *str)
{
	wchar_t	*s1;
	struct nlist	*np;
	static struct nlist	nodef;

	s1 = str;

	for (hshval = 0; *s1; )
		hshval += *s1++;

	hshval %= hshsize;

	for (np = hshtab[hshval]; np != NULL; np = np->next) {
		if (*str == *np->name && wcscmp(str, np->name) == 0)
			return (np);
	}
	return (&nodef);
}

static void
expand(wchar_t **a1, int c)
{
	wchar_t	*dp;
	struct nlist	*sp;

	sp = (struct nlist *)a1[-1];

	if (sp->tflag || trace) {
#if !defined(__lint)	/* lint doesn't grok "%ws" */
		int	i;

		(void) fprintf(stderr,
		    "Trace(%d): %ws", Cp-callst, a1[0]);
#endif

		if (c > 0) {
#if !defined(__lint)	/* lint doesn't grok "%ws" */
			(void) fprintf(stderr, "(%ws", chkbltin(a1[1]));
			for (i = 2; i <= c; ++i)
				(void) fprintf(stderr, ",%ws", chkbltin(a1[i]));
#endif
			(void) fprintf(stderr, ")");
		}
		(void) fprintf(stderr, "\n");
	}

	dp = sp->def;

	for (; *dp; ++dp) {
		if (is_builtin(*dp)) {
			(*barray[builtin_idx(*dp)].bfunc)(a1, c);
		} else if (dp[1] == '$') {
			if (is_digit(*dp)) {
				int	n;
				if ((n = *dp-'0') <= c)
					pbstr(a1[n]);
				++dp;
			} else if (*dp == '#') {
				pbnum((long)c);
				++dp;
			} else if (*dp == '*' || *dp == '@') {
				int i = c;
				wchar_t **a = a1;

				if (i > 0)
					for (;;) {
						if (*dp == '@')
							pbstr(rquote);

						pbstr(a[i--]);

						if (*dp == '@')
							pbstr(lquote);

						if (i <= 0)
							break;

						pbstr(L",");
					}
				++dp;
			} else
				putbak(*dp);
		} else
			putbak(*dp);
	}
}

void
setfname(char *s)
{
	if (fname[ifx])
		free(fname[ifx]);
	if ((fname[ifx] = strdup(s)) == NULL)
		error(gettext("out of storage"));
	fline[ifx] = 1;
	nflag = 1;
	lnsync(stdout);
}

static void
lnsync(FILE *iop)
{
	static int cline = 0;
	static int cfile = 0;

	if (!sflag || iop != stdout)
		return;

	if (nflag || ifx != cfile) {
		nflag = 0;
		cfile = ifx;
		(void) fprintf(iop, "#line %d \"", cline = fline[ifx]);
		fpath(iop);
		(void) fprintf(iop, "\"\n");
	} else if (++cline != fline[ifx])
		(void) fprintf(iop, "#line %d\n", cline = fline[ifx]);
}

static void
fpath(FILE *iop)
{
	int	i;

	if (fname[0] == NULL)
		return;

	(void) fprintf(iop, "%s", fname[0]);

	for (i = 1; i <= ifx; ++i)
		(void) fprintf(iop, ":%s", fname[i]);
}

/* ARGSUSED */
static void
catchsig(int i)
{
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
	delexit(NOT_OK, 0);
}

void
delexit(int code, int flushio)
{
	int i;

	cf = stdout;

/*
 *	if (ofx != 0) {
 *		ofx = 0;
 *		code = NOT_OK;
 *	}
 */
	ofx = 0;	/* ensure that everything comes out */
	for (i = 1; i < 10; i++)
		undiv(i, code);

	tempfile[7] = 'a';
	(void) unlink(tempfile);

	/* flush standard I/O buffers, ie: call exit() not _exit() */
	if (flushio)
		exit(code);

	_exit(code);
}

static void
puttok(wchar_t *tp)
{
	if (Cp) {
		while (*tp)
			stkchr(*tp++);
	} else if (cf) {
		while (*tp) {
			sputchr(*tp++, cf);
		}
	}
}

void
pbstr(wchar_t *str)
{
	wchar_t *p;

	for (p = str + wcslen(str); --p >= str; )
		putbak(*p);
}

void
undiv(int i, int code)
{
	FILE *fp;
	wint_t c;

	if (i < 1 || i > 9 || i == ofx || !ofile[i])
		return;

	(void) fclose(ofile[i]);
	tempfile[7] = 'a'+i;

	if (code == OK && cf) {
		fp = xfopen(tempfile, "r");

		if (wide) {
			while ((c = myfgetwc(fp, -1)) != WEOF)
				sputchr((wchar_t)c, cf);
		} else {
			while ((c = (wint_t)getc(fp)) != WEOF)
				sputchr((wchar_t)c, cf);
		}

		(void) fclose(fp);
	}

	(void) unlink(tempfile);
	ofile[i] = NULL;
}

void
pbnum(long num)
{
	pbnbr(num, 10, 1);
}

void
pbnbr(long nbr, int base, int len)
{
	int	neg = 0;

	if (base <= 0)
		return;

	if (nbr < 0)
		neg = 1;
	else
		nbr = -nbr;

	while (nbr < 0) {
		int	i;
		if (base > 1) {
			i = nbr%base;
			nbr /= base;
#if (-3 % 2) != -1
			while (i > 0) {
				i -= base;
				++nbr;
			}
#endif
			i = -i;
		} else {
			i = 1;
			++nbr;
		}
		putbak(itochr(i));
		--len;
	}

	while (--len >= 0)
		putbak('0');

	if (neg)
		putbak('-');
}

static wchar_t
itochr(int i)
{
	if (i > 9)
		return ((wchar_t)(i-10+'A'));
	else
		return ((wchar_t)(i+'0'));
}

long
ctol(wchar_t *str)
{
	int sign;
	long num;

	while (is_space(*str))
		++str;
	num = 0;
	if (*str == '-') {
		sign = -1;
		++str;
	} else
		sign = 1;
	while (is_digit(*str))
		num = num*10 + *str++ - '0';
	return (sign * num);
}

int
min(int a, int b)
{
	if (a > b)
		return (b);
	return (a);
}

FILE *
xfopen(char *name, char *mode)
{
	FILE	*fp;

	if ((fp = fopen(name, mode)) == NULL)
		errorf(gettext("cannot open file: %s"),
		    strerror(errno));

	return (fp);
}

/*
 * m4open
 *
 * Continue processing files when unable to open the given file argument.
 */
FILE *
m4open(char ***argvec, char *mode, int *argcnt)
{
	FILE	*fp;
	char *arg;

	while (*argcnt > 0) {
		arg = (*argvec)[0]; /* point arg to current file name */
		if (arg[0] == '-' && arg[1] == EOS)
			return (stdin);
		else {
			if ((fp = fopen(arg, mode)) == NULL) {
				(void) fprintf(stderr, gettext(
				"m4: cannot open %s: "), arg);
				perror("");
				if (*argcnt == 1) {
					/* last arg therefore exit */
					error3();
				} else {
					exitstat = 1;
					(*argvec)++; /* try next arg */
					(*argcnt)--;
				}
			} else
				break;
		}
	}
	return (fp);
}

void *
xmalloc(size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL)
		error(gettext("out of storage"));
	return (ptr);
}

static void *
xcalloc(size_t nbr, size_t size)
{
	void	*ptr;

	ptr = xmalloc(nbr * size);
	(void) memset(ptr, '\0', nbr * size);
	return (ptr);
}

/* Typical format: "cannot open file: %s" */
/* PRINTFLIKE1 */
void
errorf(char *str, char *serr)
{
	char buf[500];

	(void) snprintf(buf, sizeof (buf), str, serr);
	error(buf);
}

/* PRINTFLIKE1 */
void
error2(char *str, int num)
{
	char buf[500];

	(void) snprintf(buf, sizeof (buf), str, num);
	error(buf);
}

void
error(char *str)
{
	(void) fprintf(stderr, "\n%s:", procnam);
	fpath(stderr);
	(void) fprintf(stderr, ":%d %s\n", fline[ifx], str);
	error3();
}

static void
error3()
{
	if (Cp) {
		struct call	*mptr;

		/* fix limit */
		*op = EOS;
		(Cp+1)->argp = Ap+1;

		for (mptr = callst; mptr <= Cp; ++mptr) {
			wchar_t	**aptr, **lim;

			aptr = mptr->argp;
			lim = (mptr+1)->argp-1;
			if (mptr == callst)
				(void) fputws(*aptr, stderr);
			++aptr;
			(void) fputs("(", stderr);
			if (aptr < lim)
				for (;;) {
					(void) fputws(*aptr++, stderr);
					if (aptr >= lim)
						break;
					(void) fputs(",", stderr);
				}
		}
		while (--mptr >= callst)
			(void) fputs(")", stderr);

		(void) fputs("\n", stderr);
	}
	delexit(NOT_OK, 1);
}

static wchar_t *
chkbltin(wchar_t *s)
{
	static wchar_t buf[24];

	if (is_builtin(*s)) {
		(void) swprintf(buf, sizeof (buf)/sizeof (wchar_t), L"<%ls>",
		    barray[builtin_idx(*s)].bname);
		return (buf);
	}
	return (s);
}

wchar_t
getchr()
{
	static wchar_t C;

	prev_char = C;
	if (ip > ipflr)
		return (*--ip);
	if (wide) {
		C = (wchar_t)(myfeof(ifx) ? WEOF : myfgetwc(NULL, ifx));
	} else {
		C = (wchar_t)(feof(ifile[ifx]) ?
		    WEOF : (wint_t)getc(ifile[ifx]));
	}
	if (C == '\n')
		fline[ifx]++;
	return (C);
}

/*
 * showwrap
 *
 * Loop through the list of m4wrap strings.  Call pbstr() so that the
 * string will be displayed, then delete the list entry and free the memory
 * allocated for it.
 */
static void
showwrap()
{
	struct Wrap *prev;

	while (wrapstart) {
		pbstr(wrapstart->wrapstr);
		free(wrapstart->wrapstr);
		prev = wrapstart;
		wrapstart = wrapstart->nxt;
		free(prev);
	}
}

static void
sputchr(wchar_t c, FILE *f)
{
	wint_t ret;

	if (is_builtin(c))
		return;
	if (wide)
		ret = myfputwc(c, f);
	else
		ret = (wint_t)putc((int)c, f);
	if (ret == WEOF)
		error(gettext("output error"));
	if (ret == '\n')
		lnsync(f);
}

static void
putchr(wchar_t c)
{
	wint_t ret;

	if (Cp)
		stkchr(c);
	else if (cf) {
		if (sflag)
			sputchr(c, cf);
		else {
			if (is_builtin(c))
				return;
			if (wide)
				ret = myfputwc(c, cf);
			else
				ret = (wint_t)putc((int)c, cf);
			if (ret == WEOF) {
				error(gettext("output error"));
			}
		}
	}
}

wchar_t *
wstrdup(wchar_t *p)
{
	size_t len = wcslen(p);
	wchar_t *ret;

	ret = xmalloc((len + 1) * sizeof (wchar_t));
	(void) wcscpy(ret, p);
	return (ret);
}

int
wstoi(wchar_t *p)
{
	return ((int)wcstol(p, NULL, 10));
}

char *
wstr2str(wchar_t *from, int alloc)
{
	static char *retbuf;
	static size_t bsiz;
	char *p, *ret;

	if (alloc) {
		ret = p = xmalloc(wcslen(from) * mb_cur_max + 1);
	} else {
		while (bsiz < (wcslen(from) * mb_cur_max + 1)) {
			if ((p = realloc(retbuf, bsiz + 256)) == NULL)
				error(gettext("out of storage"));
			bsiz += 256;
			retbuf = p;
		}
		ret = p = retbuf;
	}

	if (wide) {
		while (*from) {
			int len;

			if (*from & INVALID_CHAR) {
				*p = (char)(*from & ~INVALID_CHAR);
				len = 1;
			} else {
				if ((len = wctomb(p, *from)) == -1) {
					*p = (char)*from;
					len = 1;
				}
			}
			p += len;
			from++;
		}
	} else {
		while (*from)
			*p++ = (char)*from++;
	}
	*p = '\0';

	return (ret);
}

wchar_t *
str2wstr(char *from, int alloc)
{
	static wchar_t *retbuf;
	static size_t bsiz;
	wchar_t *p, *ret;

	if (alloc) {
		ret = p = xmalloc((strlen(from) + 1) * sizeof (wchar_t));
	} else {
		while (bsiz < (strlen(from) + 1)) {
			if ((p = realloc(retbuf,
			    (bsiz + 256) * sizeof (wchar_t))) == NULL) {
				error(gettext("out of storage"));
			}
			bsiz += 256;
			retbuf = p;
		}
		ret = p = retbuf;
	}

	if (wide) {
		while (*from) {
			int len;
			wchar_t wc;

			if ((len = mbtowc(&wc, from, mb_cur_max)) <= 0) {
				wc = *from | INVALID_CHAR;
				len = 1;
			}
			*p++ = wc;
			from += len;
		}
	} else {
		while (*from)
			*p++ = (unsigned char) *from++;
	}
	*p = 0;

	return (ret);
}

static wint_t
myfgetwc(FILE *fp, int idx)
{
	int i, c, len, nb;
	wchar_t wc;
	unsigned char *buf;

	if (fp == NULL)
		fp = ifile[idx];
	else
		idx = 10; /* extra slot */
	buf = ibuffer[idx].buffer;
	nb = ibuffer[idx].nbytes;
	len = 0;
	for (i = 1; i <= mb_cur_max; i++) {
		if (nb < i) {
			c = getc(fp);
			if (c == EOF) {
				if (nb == 0)
					return (WEOF);
				else
					break;
			}
			buf[nb++] = (unsigned char)c;
		}
		if ((len = mbtowc(&wc, (char *)buf, i)) >= 0)
			break;
	}
	if (len <= 0) {
		wc = buf[0] | INVALID_CHAR;
		len = 1;
	}
	nb -= len;
	if (nb > 0) {
		for (i = 0; i < nb; i++)
			buf[i] = buf[i + len];
	}
	ibuffer[idx].nbytes = nb;
	return (wc);
}

static wint_t
myfputwc(wchar_t wc, FILE *fp)
{
	if (wc & INVALID_CHAR) {
		wc &= ~INVALID_CHAR;
		return (fputc((int)wc, fp));
	}
	return (fputwc(wc, fp));
}

static int
myfeof(int idx)
{
	return (ibuffer[idx].nbytes == 0 && feof(ifile[idx]));
}
