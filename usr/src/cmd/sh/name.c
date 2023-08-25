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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * UNIX shell
 */

#include	"defs.h"
#include	<stropts.h>

extern BOOL	chkid();
extern unsigned char	*simple();
extern int	mailchk;

static void	setname(unsigned char *, int);
static void	set_builtins_path();
static int	patheq();
static void	namwalk(struct namnod *);
static void	dolocale();

struct namnod ps2nod =
{
	(struct namnod *)NIL,
	&acctnod,
	(unsigned char *)ps2name
};
struct namnod cdpnod =
{
	(struct namnod *)NIL,
	(struct namnod *)NIL,
	(unsigned char *)cdpname
};
struct namnod pathnod =
{
	&mailpnod,
	(struct namnod *)NIL,
	(unsigned char *)pathname
};
struct namnod ifsnod =
{
	&homenod,
	&mailnod,
	(unsigned char *)ifsname
};
struct namnod ps1nod =
{
	&pathnod,
	&ps2nod,
	(unsigned char *)ps1name
};
struct namnod homenod =
{
	&cdpnod,
	(struct namnod *)NIL,
	(unsigned char *)homename
};
struct namnod mailnod =
{
	(struct namnod *)NIL,
	(struct namnod *)NIL,
	(unsigned char *)mailname
};
struct namnod mchknod =
{
	&ifsnod,
	&ps1nod,
	(unsigned char *)mchkname
};
struct namnod acctnod =
{
	(struct namnod *)NIL,
	(struct namnod *)NIL,
	(unsigned char *)acctname
};
struct namnod mailpnod =
{
	(struct namnod *)NIL,
	(struct namnod *)NIL,
	(unsigned char *)mailpname
};


struct namnod *namep = &mchknod;

/* ========	variable and string handling	======== */

int
syslook(unsigned char *w, struct sysnod syswds[], int n)
{
	int	low;
	int	high;
	int	mid;
	int	cond;

	if (w == 0 || *w == 0)
		return(0);

	low = 0;
	high = n - 1;

	while (low <= high)
	{
		mid = (low + high) / 2;

		if ((cond = cf(w, syswds[mid].sysnam)) < 0)
			high = mid - 1;
		else if (cond > 0)
			low = mid + 1;
		else
			return(syswds[mid].sysval);
	}
	return(0);
}

void
setlist(struct argnod *arg, int xp)
{
	if (flags & exportflg)
		xp |= N_EXPORT;

	while (arg)
	{
		unsigned char *s = mactrim(arg->argval);
		setname(s, xp);
		arg = arg->argnxt;
		if (flags & execpr)
		{
			prs(s);
			if (arg)
				blank();
			else
				newline();
		}
	}
}

static void
setname(unsigned char *argi, int xp)	/* does parameter assignments */
{
	unsigned char *argscan = argi;
	struct namnod *n;

	if (letter(*argscan))
	{
		while (alphanum(*argscan))
			argscan++;

		if (*argscan == '=')
		{
			*argscan = 0;	/* make name a cohesive string */

			n = lookup(argi);
			*argscan++ = '=';
			attrib(n, xp);
			if (xp & N_ENVNAM)
			{
				n->namenv = n->namval = argscan;
				if (n == &pathnod)
					set_builtins_path();
			}
			else
				assign(n, argscan);

			dolocale(n->namid);
			return;
		}
	}
}

void
replace(unsigned char **a, unsigned char *v)
{
	free(*a);
	*a = make(v);
}

void
dfault(struct namnod *n, unsigned char	*v)
{
	if (n->namval == 0)
		assign(n, v);
}

void
assign(struct namnod *n, unsigned char *v)
{
	if (n->namflg & N_RDONLY)
		failed(n->namid, wtfailed);

#ifndef RES

	else if (flags & rshflg)
	{
		if (n == &pathnod || eq(n->namid,"SHELL"))
			failed(n->namid, restricted);
	}
#endif

	else if (n->namflg & N_FUNCTN)
	{
		func_unhash(n->namid);
		freefunc(n);

		n->namenv = 0;
		n->namflg = N_DEFAULT;
	}

	if (n == &mchknod)
	{
		mailchk = stoi(v);
	}

	replace(&n->namval, v);
	attrib(n, N_ENVCHG);

	if (n == &pathnod)
	{
		zaphash();
		set_dotpath();
		set_builtins_path();
		return;
	}

	if (flags & prompt)
	{
		if ((n == &mailpnod) || (n == &mailnod && mailpnod.namflg == N_DEFAULT))
			setmail(n->namval);
	}
}

static void
set_builtins_path()
{
	unsigned char *path;

        ucb_builtins = 0;
        path = getpath("");
        while (path && *path)
        {
                if (patheq(path, "/usr/ucb"))
                {
                        ucb_builtins++;
                        break;
                }
                else if (patheq(path, "/usr/bin"))
                        break;
                else if (patheq(path, "/bin"))
                        break;
                else if (patheq(path, "/usr/5bin"))
                        break;
                path = nextpath(path);
        }
}

static int
patheq(unsigned char *component, char *dir)
{
	unsigned char   c;

        for (;;)
        {
                c = *component++;
                if (c == COLON)
                        c = '\0';       /* end of component of path */
		if (c != *dir++)
			return (0);
                if (c == '\0')
                        return(1);
        }
}

int
readvar(unsigned char **names)
{
	struct fileblk	fb;
	struct fileblk *f = &fb;
	unsigned char	c[MULTI_BYTE_MAX+1];
	int	rc = 0;
	struct namnod *n = lookup(*names++);	/* done now to avoid storage mess */
	unsigned char	*rel = (unsigned char *)relstak();
	unsigned char *oldstak;
	unsigned char *pc, *rest;
	int		d;

	push(f);
	initf(dup(0));

	/*
	 * If stdin is a pipe then this lseek(2) will fail with ESPIPE, so
	 * the read buffer size is set to 1 because we will not be able
	 * lseek(2) back towards the beginning of the file, so we have
	 * to read a byte at a time instead
	 *
	 */
	if (lseek(0, (off_t)0, SEEK_CUR) == -1)
		f->fsiz = 1;

	/*
	 * If stdin is a socket then this isastream(3C) will return 1, so
	 * the read buffer size is set to 1 because we will not be able
	 * lseek(2) back towards the beginning of the file, so we have
	 * to read a byte at a time instead
	 *
	 */
	if (isastream(0) == 1)
		f->fsiz = 1;

	/*
	 * strip leading IFS characters
	 */
	for (;;)
	{
		d = nextwc();
		if(eolchar(d))
			break;
		rest = readw(d);
		pc = c;
		while(*pc++ = *rest++);
		if(!anys(c, ifsnod.namval))
			break;
	}

	oldstak = curstak();
	for (;;)
	{
		if ((*names && anys(c, ifsnod.namval)) || eolchar(d))
		{
			if (staktop >= brkend)
				growstak(staktop);
			zerostak();
			assign(n, absstak(rel));
			setstak(rel);
			if (*names)
				n = lookup(*names++);
			else
				n = 0;
			if (eolchar(d))
			{
				break;
			}
			else		/* strip imbedded IFS characters */
				while(1) {
					d = nextwc();
					if(eolchar(d))
						break;
					rest = readw(d);
					pc = c;
					while(*pc++ = *rest++);
					if(!anys(c, ifsnod.namval))
						break;
				}
		}
		else
		{
			if(d == '\\') {
				d = readwc();
				rest = readw(d);
				while(d = *rest++) {
					if (staktop >= brkend)
						growstak(staktop);
					pushstak(d);
				}
				oldstak = staktop;
			}
			else
			{
				pc = c;
				while(d = *pc++) {
					if (staktop >= brkend)
						growstak(staktop);
					pushstak(d);
				}
				if(!anys(c, ifsnod.namval))
					oldstak = staktop;
			}
			d = nextwc();

			if (eolchar(d))
				staktop = oldstak;
			else
			{
				rest = readw(d);
				pc = c;
				while(*pc++ = *rest++);
			}
		}
	}
	while (n)
	{
		assign(n, (unsigned char *)nullstr);
		if (*names)
			n = lookup(*names++);
		else
			n = 0;
	}

	if (eof)
		rc = 1;

	if (isastream(0) != 1)
		/*
		 * If we are reading on a stream do not attempt to
		 * lseek(2) back towards the start because this is
		 * logically meaningless, but there is nothing in
		 * the standards to pervent the stream implementation
		 * from attempting it and breaking our code here
		 *
		 */
		lseek(0, (off_t)(f->nxtoff - f->endoff), SEEK_CUR);

	pop();
	return(rc);
}

void
assnum(unsigned char **p, long i)
{
	int j = ltos(i);
	replace(p, &numbuf[j]);
}

unsigned char *
make(v)
unsigned char	*v;
{
	unsigned char	*p;

	if (v)
	{
		movstr(v, p = (unsigned char *)alloc(length(v)));
		return(p);
	}
	else
		return(0);
}


struct namnod *
lookup(unsigned char *nam)
{
	struct namnod *nscan = namep;
	struct namnod **prev;
	int		LR;

	if (!chkid(nam))
		failed(nam, notid);

	while (nscan)
	{
		if ((LR = cf(nam, nscan->namid)) == 0)
			return(nscan);

		else if (LR < 0)
			prev = &(nscan->namlft);
		else
			prev = &(nscan->namrgt);
		nscan = *prev;
	}
	/*
	 * add name node
	 */
	nscan = (struct namnod *)alloc(sizeof *nscan);
	nscan->namlft = nscan->namrgt = (struct namnod *)NIL;
	nscan->namid = make(nam);
	nscan->namval = 0;
	nscan->namflg = N_DEFAULT;
	nscan->namenv = 0;

	return(*prev = nscan);
}

BOOL
chkid(nam)
unsigned char	*nam;
{
	unsigned char *cp = nam;

	if (!letter(*cp))
		return(FALSE);
	else
	{
		while (*++cp)
		{
			if (!alphanum(*cp))
				return(FALSE);
		}
	}
	return(TRUE);
}

static void (*namfn)();

void
namscan(void (*fn)())
{
	namfn = fn;
	namwalk(namep);
}

static void
namwalk(struct namnod *np)
{
	if (np)
	{
		namwalk(np->namlft);
		(*namfn)(np);
		namwalk(np->namrgt);
	}
}

void
printnam(struct namnod *n)
{
	unsigned char	*s;

	sigchk();

	if (n->namflg & N_FUNCTN)
	{
		struct fndnod *f = fndptr(n->namenv);

		prs_buff(n->namid);
		prs_buff("(){\n");
		if (f != NULL)
			prf(f->fndval);
		prs_buff("\n}\n");
	}
	else if (s = n->namval)
	{
		prs_buff(n->namid);
		prc_buff('=');
		prs_buff(s);
		prc_buff(NL);
	}
}

static int namec;

void
printro(struct namnod *n)
{
	if (n->namflg & N_RDONLY)
	{
		prs_buff(_gettext(readonly));
		prc_buff(SPACE);
		prs_buff(n->namid);
		prc_buff(NL);
	}
}

void
printexp(struct namnod *n)
{
	if (n->namflg & N_EXPORT)
	{
		prs_buff(_gettext(export));
		prc_buff(SPACE);
		prs_buff(n->namid);
		prc_buff(NL);
	}
}

void
setup_env(void)
{
	unsigned char **e = environ;

	while (*e)
		setname(*e++, N_ENVNAM);
}


static unsigned char **argnam;

static void
countnam(struct namnod *n)
{
	if (n->namval)
		namec++;
}

static void
pushnam(struct namnod *n)
{
	int 	flg = n->namflg;
	unsigned char	*p;
	unsigned char	*namval;

	if (((flg & N_ENVCHG) && (flg & N_EXPORT)) || (flg & N_FUNCTN))
		namval = n->namval;
	else {
		/* Discard Local variable in child process */
		if (!(flg & ~N_ENVCHG)) {
			n->namflg = 0;
			n->namenv = 0;
			if (n->namval) {
				/* Release for re-use */
				free(n->namval);
				n->namval = (unsigned char *)NIL;
			}
		}
		namval = n->namenv;
	}

	if (namval)
	{
		p = movstrstak(n->namid, staktop);
		p = movstrstak("=", p);
		p = movstrstak(namval, p);
		*argnam++ = getstak(p + 1 - (unsigned char *)(stakbot));
	}
}

unsigned char **
local_setenv()
{
	unsigned char	**er;

	namec = 0;
	namscan(countnam);

	argnam = er = (unsigned char **)getstak(namec * BYTESPERWORD + BYTESPERWORD);
	namscan(pushnam);
	*argnam++ = 0;
	return(er);
}

struct namnod *
findnam(nam)
	unsigned char	*nam;
{
	struct namnod	*nscan = namep;
	int		LR;

	if (!chkid(nam))
		return(0);
	while (nscan)
	{
		if ((LR = cf(nam, nscan->namid)) == 0)
			return(nscan);
		else if (LR < 0)
			nscan = nscan->namlft;
		else
			nscan = nscan->namrgt;
	}
	return(0);
}

void
unset_name(unsigned char 	*name)
{
	struct namnod	*n;
	unsigned char 	call_dolocale = 0;

	if (n = findnam(name))
	{
		if (n->namflg & N_RDONLY)
			failed(name, wtfailed);

		if (n == &pathnod ||
		    n == &ifsnod ||
		    n == &ps1nod ||
		    n == &ps2nod ||
		    n == &mchknod)
		{
			failed(name, badunset);
		}

#ifndef RES

		if ((flags & rshflg) && eq(name, "SHELL"))
			failed(name, restricted);

#endif

		if (n->namflg & N_FUNCTN)
		{
			func_unhash(name);
			freefunc(n);
		}
		else
		{
			call_dolocale++;
			free(n->namval);
			free(n->namenv);
		}

		n->namval = n->namenv = 0;
		n->namflg = N_DEFAULT;

		if (call_dolocale)
			dolocale(name);

		if (flags & prompt)
		{
			if (n == &mailpnod)
				setmail(mailnod.namval);
			else if (n == &mailnod && mailpnod.namflg == N_DEFAULT)
				setmail(0);
		}
	}
}

/*
 * The environment variables which affect locale.
 * Note: if all names in this list do not begin with 'L',
 * you MUST modify dolocale().  Also, be sure that the
 * fake_env has the same number of elements as localevar.
 */
static char *localevar[] = {
	"LC_ALL",
	"LC_CTYPE",
	"LC_MESSAGES",
	"LANG",
	0
};

static char *fake_env[] = {
	0,
	0,
	0,
	0,
	0
};

/*
 * If name is one of several special variables which affect the locale,
 * do a setlocale().
 */
static void
dolocale(nm)
	char *nm;
{
	char **real_env;
	struct namnod *n;
	int lv, fe;
	int i;

	/*
	 * Take advantage of fact that names of these vars all start
	 * with 'L' to avoid unnecessary work.
	 * Do locale processing only if /usr is mounted.
	 */
	if ((*nm != 'L') || !localedir_exists ||
	    (!(eq(nm, "LC_ALL") || eq(nm, "LC_CTYPE") ||
	    eq(nm, "LANG") || eq(nm, "LC_MESSAGES"))))
		return;

	/*
	 * setlocale() has all the smarts built into it, but
	 * it works by examining the environment.  Unfortunately,
	 * when you set an environment variable, the shell does
	 * not modify its own environment; it just remembers that the
	 * variable needs to be exported to any children.  We hack around
	 * this by consing up a fake environment for the use of setlocale()
	 * and substituting it for the real env before calling setlocale().
	 */

	/*
	 * Build the fake environment.
	 * Look up the value of each of the special environment
	 * variables, and put their value into the fake environment,
	 * if they are exported.
	 */
	for (lv = 0, fe = 0; localevar[lv]; lv++) {
		if ((n = findnam(localevar[lv]))) {
			char *p, *q;

			if (!n->namval)
				continue;

			fake_env[fe++] = p = alloc(length(localevar[lv])
					       + length(n->namval) + 2);
			/* copy name */
			q = localevar[lv];
			while (*q)
				*p++ = *q++;

			*p++ = '=';

			/* copy value */
			q = (char*)(n->namval);
			while (*q)
				*p++ = *q++;
			*p++ = '\0';
		}
	}
	fake_env[fe] = (char *)0;

	/*
	 * Switch fake env for real and call setlocale().
	 */
	real_env = (char **)environ;
	environ = (unsigned char **)fake_env;

	if (setlocale(LC_ALL, "") == NULL)
		prs(_gettext(badlocale));

	/*
	 * Switch back and tear down the fake env.
	 */
	environ = (unsigned char **)real_env;
	for (i = 0; i < fe; i++) {
		free(fake_env[i]);
		fake_env[i] = (char *)0;
	}
}
