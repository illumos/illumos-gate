/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"
#include <locale.h>	/* For LC_ALL */
#include "sh.tconst.h"
#include <sys/types.h>
#include <stdlib.h>

/*
 * N.B.: Some of the limits change from SunOS 4.x to SunOS 5.0.  In
 * particular, RLIMIT_RSS is gone and RLIMIT_VMEM is new.  Beware of consusing
 * the keywords that the command prints for these two.  The old one was
 * "memoryuse" and the new one is "memorysize".  Note also that a given limit
 * doesn't necessarily appear in the same position in the two releases.
 */
struct limits {
	int	limconst;
	tchar *limname;
	int	limdiv;
	tchar *limscale;
} limits[] = {
	RLIMIT_CPU,	S_cputime,	/* "cputime" */
		1,	S_seconds,	/* "seconds" */
	RLIMIT_FSIZE,	S_filesize,	/* "filesize" */
		1024,	S_kbytes,	/* "kbytes" */
	RLIMIT_DATA,	S_datasize,	/* "datasize" */
		1024,	S_kbytes,	/* "kbytes" */
	RLIMIT_STACK,	S_stacksize,	/* "stacksize" */
		1024,	S_kbytes,	/* "kbytes" */
	RLIMIT_CORE,	S_coredumpsize, /* "coredumpsize" */
		1024,	S_kbytes,	/* "kbytes" */
	RLIMIT_NOFILE,	S_descriptors,	/* "descriptors" */
		1,	S_,		/* "" */
	RLIMIT_VMEM,	S_memorysize,	/* "memorysize" */
		1024,	S_kbytes,	/* "kbytes" */
	-1,		0,
};


static int getval(struct limits *lp, tchar **v, rlim_t *);
void islogin(void);
int dolabel(void);
void reexecute(struct command *kp);
void preread_(void);
void doagain(void);
void toend(void);
void wfree(void);
void echo(tchar sep, tchar **v);
void local_setenv(tchar *name, tchar *val);
void local_unsetenv(tchar *name);
void limtail(tchar *cp, tchar *str0);
void plim(struct limits *lp, tchar hard);
void search();

#define	BUFSZ	1028

/*
 * C shell
 */

struct biltins *
isbfunc(struct command *t)
{
	tchar *cp = t->t_dcom[0];
	struct biltins *bp, *bp1, *bp2;
	int dofg1(), dobg1();

	static struct biltins label = { S_, dolabel, 0, 0 };
	static struct biltins foregnd = { S_Pjob, dofg1, 0, 0 };
	static struct biltins backgnd = { S_PjobAND, dobg1, 0, 0 };
#ifdef TRACE
	tprintf("TRACE- isbfunc()\n");
#endif
	if (lastchr(cp) == ':') {
		label.bname = cp;
		return (&label);
	}
	if (*cp == '%') {
		if (t->t_dflg & FAND) {
			t->t_dflg &= ~FAND;
			backgnd.bname = cp;
			return (&backgnd);
		}
		foregnd.bname = cp;
		return (&foregnd);
	}
	/*
	 * Binary search
	 * Bp1 is the beginning of the current search range.
	 * Bp2 is one past the end.
	 */
	for (bp1 = bfunc, bp2 = bfunc + nbfunc; bp1 < bp2; ) {
		int i;

		bp = bp1 + (bp2 - bp1 >> 1);
		if ((i = *cp - *bp->bname) == 0 &&
		    (i = strcmp_(cp, bp->bname)) == 0) {
			return (bp);
		}
		if (i < 0) {
			bp2 = bp;
		} else {
			bp1 = bp + 1;
		}
	}
	return (0);
}

void
func(struct command *t, struct biltins *bp)
{
	int i;

#ifdef TRACE
	tprintf("TRACE- func()\n");
#endif
	xechoit(t->t_dcom);
	setname(bp->bname);
	i = blklen(t->t_dcom) - 1;
	if (i < bp->minargs) {
		bferr("Too few arguments");
	}
	if (i > bp->maxargs) {
		bferr("Too many arguments");
	}
	(*bp->bfunct)(t->t_dcom, t);
}

int
dolabel(void)
{
#ifdef TRACE
	tprintf("TRACE- dolabel()\n");
#endif
	return (0);
}

void
doonintr(tchar **v)
{
	tchar *cp;
	tchar *vv = v[1];

#ifdef TRACE
	tprintf("TRACE- doonintr()\n");
#endif
	if (parintr == SIG_IGN) {
		return;
	}
	if (setintr && intty) {
		bferr("Can't from terminal");
	}
	cp = gointr, gointr = 0, xfree(cp);
	if (vv == 0) {
		if (setintr) {
			(void) sigblock(sigmask(SIGINT));
		} else {
			(void) signal(SIGINT, SIG_DFL);
		}
		gointr = 0;
	} else if (eq((vv = strip(vv)), S_MINUS)) {
		(void) signal(SIGINT, SIG_IGN);
		gointr = S_MINUS;
	} else {
		gointr = savestr(vv);
		(void) signal(SIGINT, pintr);
	}
}

void
donohup(void)
{

#ifdef TRACE
	tprintf("TRACE- donohup()\n");
#endif
	if (intty) {
		bferr("Can't from terminal");
	}
	if (setintr == 0) {
		(void) signal(SIGHUP, SIG_IGN);
#ifdef CC
		submit(getpid());
#endif
	}
}

void
dozip(void)
{
	;
}

void
prvars(void)
{
#ifdef TRACE
	tprintf("TRACE- prvars()\n");
#endif

	plist(&shvhed);
}

void
doalias(tchar **v)
{
	struct varent *vp;
	tchar *p;

#ifdef TRACE
	tprintf("TRACE- doalias()\n");
#endif
	v++;
	p = *v++;
	if (p == 0) {
		plist(&aliases);
	} else if (*v == 0) {
		vp = adrof1(strip(p), &aliases);
		if (vp) {
			blkpr(vp->vec), printf("\n");
		}
	} else {
		if (eq(p, S_alias) ||
		    eq(p, S_unalias)) {
			setname(p);
			bferr("Too dangerous to alias that");
		}
		set1(strip(p), saveblk(v), &aliases);
	}
}

void
unalias(tchar **v)
{

#ifdef TRACE
	tprintf("TRACE- unalias()\n");
#endif
	unset1(v, &aliases);
}

void
dologout(void)
{

#ifdef TRACE
	tprintf("TRACE- dologout()\n");
#endif
	islogin();
	goodbye();
}

void
dologin(tchar **v)
{

	char *v_;	/* work */
#ifdef TRACE
	tprintf("TRACE- dologin()\n");
#endif
	islogin();
	rechist();
	(void) signal(SIGTERM, parterm);
	if (v[1] != NULL) {
		v_ = tstostr(NULL, v[1]);	/* No need to free */
	} else {
		v_ = 0;
	}
	execl("/bin/login", "login", v_, 0);
	untty();
	exit(1);
}

#ifdef NEWGRP
void
donewgrp(tchar **v)
{

	char *v_;	/* work */
#ifdef TRACE
	tprintf("TRACE- donewgrp()\n");
#endif
	if (chkstop == 0 && setintr) {
		panystop(0);
	}
	(void) signal(SIGTERM, parterm);

	if (v[1] != NULL) {
		v_ = tstostr(NOSTR, v[1]);	/* No need to free */
	} else {
		v_ = 0;
	}
	execl("/bin/newgrp", "newgrp", v_, 0);
	execl("/usr/bin/newgrp", "newgrp", v_, 0);
	untty();
	exit(1);
}
#endif

void
islogin(void)
{

#ifdef TRACE
	tprintf("TRACE- islogin()\n");
#endif
	if (chkstop == 0 && setintr) {
		panystop(0);
	}
	if (loginsh) {
		return;
	}
	error("Not login shell");
}

void
doif(tchar **v, struct command *kp)
{
	int i;
	tchar **vv;

#ifdef TRACE
	tprintf("TRACE- doif()\n");
#endif
	v++;
	i = exp(&v);
	vv = v;
	if (*vv == NOSTR) {
		bferr("Empty if");
	}
	if (eq(*vv, S_then)) {
		if (*++vv) {
			bferr("Improper then");
		}
		setname(S_then);
		/*
		 * If expression was zero, then scan to else,
		 * otherwise just fall into following code.
		 */
		if (!i) {
			search(ZIF, 0);
		}
		return;
	}
	/*
	 * Simple command attached to this if.
	 * Left shift the node in this tree, munging it
	 * so we can reexecute it.
	 */
	if (i) {
		lshift(kp->t_dcom, vv - kp->t_dcom);
		reexecute(kp);
		donefds();
	}
}

/*
 * Reexecute a command, being careful not
 * to redo i/o redirection, which is already set up.
 */
void
reexecute(struct command *kp)
{

#ifdef TRACE
	tprintf("TRACE- reexecute()\n");
#endif
	kp->t_dflg &= FSAVE;
	kp->t_dflg |= FREDO;
	/*
	 * If tty is still ours to arbitrate, arbitrate it;
	 * otherwise dont even set pgrp's as the jobs would
	 * then have no way to get the tty (we can't give it
	 * to them, and our parent wouldn't know their pgrp, etc.
	 */
	execute(kp, tpgrp > 0 ? tpgrp : -1);
}

void
doelse(void)
{

#ifdef TRACE
	tprintf("TRACE- doelse()\n");
#endif
	search(ZELSE, 0);
}

void
dogoto(tchar **v)
{
	struct whyle *wp;
	tchar *lp;
#ifdef TRACE
	tprintf("TRACE- dogoto()\n");
#endif

	/*
	 * While we still can, locate any unknown ends of existing loops.
	 * This obscure code is the WORST result of the fact that we
	 * don't really parse.
	 */
	for (wp = whyles; wp; wp = wp->w_next) {
		if (wp->w_end == 0) {
			search(ZBREAK, 0);
			wp->w_end = btell();
		} else {
			bseek(wp->w_end);
		}
	}
	search(ZGOTO, 0, lp = globone(v[1]));
	xfree(lp);
	/*
	 * Eliminate loops which were exited.
	 */
	wfree();
}

void
doswitch(tchar **v)
{
	tchar *cp, *lp;

#ifdef TRACE
	tprintf("TRACE- doswitch()\n");
#endif
	v++;
	if (!*v || *(*v++) != '(') {
		goto syntax;
	}
	cp = **v == ')' ? S_ : *v++;
	if (*(*v++) != ')') {
		v--;
	}
	if (*v) {
syntax:
		error("Syntax error");
	}
	search(ZSWITCH, 0, lp = globone(cp));
	xfree(lp);
}

void
dobreak(void)
{

#ifdef TRACE
	tprintf("TRACE- dobreak()\n");
#endif
	if (whyles) {
		toend();
	} else {
		bferr("Not in while/foreach");
	}
}

void
doexit(tchar **v)
{

#ifdef TRACE
	tprintf("TRACE- doexit()\n");
#endif
	if (chkstop == 0) {
		panystop(0);
	}
	/*
	 * Don't DEMAND parentheses here either.
	 */
	v++;
	if (*v) {
		set(S_status, putn(exp(&v)));
		if (*v) {
			bferr("Expression syntax");
		}
	}
	btoeof();
	if (intty) {
		(void) close(SHIN);
		unsetfd(SHIN);
	}
}

void
doforeach(tchar **v)
{
	tchar *cp;
	struct whyle *nwp;

#ifdef TRACE
	tprintf("TRACE- doforeach()\n");
#endif
	v++;
	cp = strip(*v);
	while (*cp && alnum(*cp)) {
		cp++;
	}
	if (*cp || strlen_(*v) >= MAX_VAR_LEN || !letter(**v)) {
		bferr("Invalid variable");
	}
	cp = *v++;
	if (v[0][0] != '(' || v[blklen(v) - 1][0] != ')') {
		bferr("Words not ()'ed");
	}
	v++;
	gflag = 0, tglob(v);
	v = glob(v);
	if (v == 0) {
		bferr("No match");
	}
	nwp = (struct whyle *)xcalloc(1, sizeof (*nwp));
	nwp->w_fe = nwp->w_fe0 = v; gargv = 0;
	nwp->w_start = btell();
	nwp->w_fename = savestr(cp);
	nwp->w_next = whyles;
	whyles = nwp;
	/*
	 * Pre-read the loop so as to be more
	 * comprehensible to a terminal user.
	 */
	if (intty) {
		preread_();
	}
	doagain();
}

void
dowhile(tchar **v)
{
	int status;
	bool again = whyles != 0 && whyles->w_start == lineloc &&
	    whyles->w_fename == 0;

#ifdef TRACE
	tprintf("TRACE- dowhile()\n");
#endif
	v++;
	/*
	 * Implement prereading here also, taking care not to
	 * evaluate the expression before the loop has been read up
	 * from a terminal.
	 */
	if (intty && !again) {
		status = !exp0(&v, 1);
	} else {
		status = !exp(&v);
	}
	if (*v) {
		bferr("Expression syntax");
	}
	if (!again) {
		struct whyle *nwp = (struct whyle *)xcalloc(1, sizeof (*nwp));

		nwp->w_start = lineloc;
		nwp->w_end = 0;
		nwp->w_next = whyles;
		whyles = nwp;
		if (intty) {
			/*
			 * The tty preread
			 */
			preread_();
			doagain();
			return;
		}
	}
	if (status) {
		/* We ain't gonna loop no more, no more! */
		toend();
	}
}

void
preread_(void)
{
#ifdef TRACE
	tprintf("TRACE- preread()\n");
#endif

	whyles->w_end = -1;
	if (setintr) {
		(void) sigsetmask(sigblock(0) & ~sigmask(SIGINT));
	}
	search(ZBREAK, 0);
	if (setintr) {
		(void) sigblock(sigmask(SIGINT));
	}
	whyles->w_end = btell();
}

void
doend(void)
{

#ifdef TRACE
	tprintf("TRACE- doend()\n");
#endif
	if (!whyles) {
		bferr("Not in while/foreach");
	}
	whyles->w_end = btell();
	doagain();
}

void
docontin(void)
{
#ifdef TRACE
	tprintf("TRACE- docontin()\n");
#endif

	if (!whyles) {
		bferr("Not in while/foreach");
	}
	doagain();
}

void
doagain(void)
{

#ifdef TRACE
	tprintf("TRACE- doagain()\n");
#endif
	/* Repeating a while is simple */
	if (whyles->w_fename == 0) {
		bseek(whyles->w_start);
		return;
	}
	/*
	 * The foreach variable list actually has a spurious word
	 * ")" at the end of the w_fe list.  Thus we are at the
	 * of the list if one word beyond this is 0.
	 */
	if (!whyles->w_fe[1]) {
		dobreak();
		return;
	}
	set(whyles->w_fename, savestr(*whyles->w_fe++));
	bseek(whyles->w_start);
}

void
dorepeat(tchar **v, struct command *kp)
{
	int i, omask;

#ifdef TRACE
	tprintf("TRACE- dorepeat()\n");
#endif
	i = getn(v[1]);
	if (setintr) {
		omask = sigblock(sigmask(SIGINT)) & ~sigmask(SIGINT);
	}
	lshift(v, 2);
	while (i > 0) {
		if (setintr) {
			(void) sigsetmask(omask);
		}
		reexecute(kp);
		--i;
	}
	donefds();
	if (setintr) {
		(void) sigsetmask(omask);
	}
}

void
doswbrk(void)
{

#ifdef TRACE
	tprintf("TRACE- doswbrk()\n");
#endif
	search(ZBRKSW, 0);
}

int
srchx(tchar *cp)
{
	struct srch *sp, *sp1, *sp2;
	int i;

#ifdef TRACE
	tprintf("TRACE- srchx()\n");
#endif
	/*
	 * Binary search
	 * Sp1 is the beginning of the current search range.
	 * Sp2 is one past the end.
	 */
	for (sp1 = srchn, sp2 = srchn + nsrchn; sp1 < sp2; ) {
		sp = sp1 + (sp2 - sp1 >> 1);
		if ((i = *cp - *sp->s_name) == 0 &&
		    (i = strcmp_(cp, sp->s_name)) == 0) {
			return (sp->s_value);
		}
		if (i < 0) {
			sp2 = sp;
		} else {
			sp1 = sp + 1;
		}
	}
	return (-1);
}

tchar Stype;
tchar *Sgoal;

/*VARARGS2*/
void
search(type, level, goal)
	int type; int level; tchar *goal;
{
	tchar wordbuf[BUFSIZ];
	tchar *aword = wordbuf;
	tchar *cp;

#ifdef TRACE
	tprintf("TRACE- search()\n");
#endif
	Stype = type; Sgoal = goal;
	if (type == ZGOTO) {
		bseek((off_t)0);
	}
	do {
		if (intty && fseekp == feobp) {
			printf("? "), flush();
		}
		aword[0] = 0;
		(void) getword(aword);

		switch (srchx(aword)) {

		case ZELSE:
			if (level == 0 && type == ZIF) {
				return;
			}
			break;

		case ZIF:
			while (getword(aword)) {
				continue;
			}
			if ((type == ZIF || type == ZELSE) &&
			    eq(aword, S_then)) {
				level++;
			}
			break;

		case ZENDIF:
			if (type == ZIF || type == ZELSE) {
				level--;
			}
			break;

		case ZFOREACH:
		case ZWHILE:
			if (type == ZBREAK) {
				level++;
			}
			break;

		case ZEND:
			if (type == ZBREAK) {
				level--;
			}
			break;

		case ZSWITCH:
			if (type == ZSWITCH || type == ZBRKSW) {
				level++;
			}
			break;

		case ZENDSW:
			if (type == ZSWITCH || type == ZBRKSW) {
				level--;
			}
			break;

		case ZLABEL:
			if (type == ZGOTO && getword(aword) &&
			    eq(aword, goal)) {
				level = -1;
			}
			break;

		default:
			if (type != ZGOTO && (type != ZSWITCH || level != 0)) {
				break;
			}
			if (lastchr(aword) != ':') {
				break;
			}
			aword[strlen_(aword) - 1] = 0;
			if (type == ZGOTO && eq(aword, goal) ||
			    type == ZSWITCH && eq(aword, S_default)) {
				level = -1;
			}
			break;

		case ZCASE:
			if (type != ZSWITCH || level != 0) {
				break;
			}
			(void) getword(aword);
			if (lastchr(aword) == ':') {
				aword[strlen_(aword) - 1] = 0;
			}
			cp = strip(Dfix1(aword));
			if (Gmatch(goal, cp)) {
				level = -1;
			}
			xfree(cp);
			break;

		case ZDEFAULT:
			if (type == ZSWITCH && level == 0) {
				level = -1;
			}
			break;
		}
		(void) getword(NOSTR);
	} while (level >= 0);
}

int
getword(tchar *wp)
{
	int found = 0;
	int c, d;
#ifdef TRACE
	tprintf("TRACE- getword()\n");
#endif

	c = readc(1);
	d = 0;
	do {
		while (issp(c)) {
			c = readc(1);
		}
		if (c == '#') {
			do {
				c = readc(1);
			} while (c >= 0 && c != '\n');
		}
		if (c < 0) {
			goto past;
		}
		if (c == '\n') {
			if (wp) {
				break;
			}
			return (0);
		}

		/* ( and ) form separate words */
		if (c == '(' || c == ')') {
			return (1);
		}

		unreadc(c);
		found = 1;
		do {
			c = readc(1);
			if (c == '\\' && (c = readc(1)) == '\n') {
				c = ' ';
			}
			if (c == '\'' || c == '"') {
				if (d == 0) {
					d = c;
				} else if (d == c) {
					d = 0;
				}
			}
			if (c < 0) {
				goto past;
			}
			if (wp) {
				*wp++ = c;
			}
		} while ((d || !issp(c) && c != '(' && c != ')') && c != '\n');
	} while (wp == 0);
	unreadc(c);
	if (found) {
		*--wp = 0;
	}
	return (found);

past:
	switch (Stype) {

	case ZIF:
		bferr("then/endif not found");

	case ZELSE:
		bferr("endif not found");

	case ZBRKSW:
	case ZSWITCH:
		bferr("endsw not found");

	case ZBREAK:
		bferr("end not found");

	case ZGOTO:
		setname(Sgoal);
		bferr("label not found");
	}
	/*NOTREACHED*/

	return (0);
}

void
toend(void)
{

#ifdef TRACE
	tprintf("TRACE- toend()\n");
#endif
	if (whyles->w_end == 0) {
		search(ZBREAK, 0);
		whyles->w_end = btell() - 1;
	} else {
		bseek(whyles->w_end);
	}
	wfree();
}

void
wfree(void)
{
	long o = btell();

#ifdef TRACE
	tprintf("TRACE- wfree()\n");
#endif
	while (whyles) {
		struct whyle *wp = whyles;
		struct whyle *nwp = wp->w_next;

		if (o >= wp->w_start && (wp->w_end == 0 || o < wp->w_end)) {
			break;
		}
		if (wp->w_fe0) {
			blkfree(wp->w_fe0);
		}
		if (wp->w_fename) {
			xfree(wp->w_fename);
		}
		xfree((char *)wp);
		whyles = nwp;
	}
}

void
doecho(tchar **v)
{

#ifdef TRACE
	tprintf("TRACE- doecho()\n");
#endif
	echo(' ', v);
}

void
doglob(tchar **v)
{

#ifdef TRACE
	tprintf("TRACE- doglob()\n");
#endif
	echo(0, v);
	flush();
}

void
echo(tchar sep, tchar **v)
{
	tchar *cp;
	int nonl = 0;

#ifdef TRACE
	tprintf("TRACE- echo()\n");
#endif
	if (setintr) {
		(void) sigsetmask(sigblock(0) & ~sigmask(SIGINT));
	}
	v++;
	if (*v == 0) {
		/*
		 * echo command needs to have newline when there are no
		 * flags or arguments.  glob should have no newline.  If
		 * the separator is a blank, we are doing an echo.  If the
		 * separator is zero, we are globbing.
		 */
		if (sep == (tchar)' ')
			Putchar('\n');
		return;
	}
	gflag = 0, tglob(v);
	if (gflag) {
		v = glob(v);
		if (v == 0) {
			bferr("No match");
		}
	}
	/* check for -n arg, NOTE: it might be quoted */
	if (sep == ' ' && *v && strlen_(*v) == 2 &&
	    ((**v&TRIM) == '-' && (*(*v + 1) & TRIM) == 'n' &&
	    (*(*v+2)&TRIM) == 0)) {
		nonl++, v++;
	}
	while (cp = *v++) {
		int c;

		while (c = *cp++) {
			Putchar(c | QUOTE);
		}
		if (*v) {
			Putchar(sep | QUOTE);
		}
	}
	if (sep && nonl == 0) {
		Putchar('\n');
	} else {
		flush();
	}
	if (setintr) {
		(void) sigblock(sigmask(SIGINT));
	}
	if (gargv) {
		blkfree(gargv), gargv = 0;
	}
}

extern char **environ;

/*
 * Check if the environment variable vp affects this csh's behavior
 * and therefore we should call setlocale() or not.
 * This function has two side effects when it returns 1:
 *	variable islocalevar_catnum is set to the LC_xxx value.
 *	variable islocalevar_catname is set to the string "LC_xxx"
 */
static int	islocalevar_catnum;
static char	*islocalevar_catname;

static
bool
islocalevar(tchar *vp)
{
	static struct lcinfo {
		tchar *	evname; /* The name of the env. var. */
	} categories_we_care[] = {
	    S_LANG, S_LC_ALL, S_LC_CTYPE, S_LC_MESSAGES,
	    NOSTR		/* assumption: LC_xxx >= 0 */
	};
	struct lcinfo *p = categories_we_care;

	do {
		if (strcmp_(vp, p->evname) == 0) {
			return (1);
		}
	} while (((++p)->evname) != NOSTR);
	return (0);
}

void
dosetenv(tchar **v)
{
	tchar *vp, *lp;

#ifdef TRACE
	tprintf("TRACE- dosetenv()\n");
#endif
	v++;
	if ((vp = *v++) == 0) {
		char **ep;

		if (setintr) {
			(void) sigsetmask(sigblock(0) & ~ sigmask(SIGINT));
		}
		for (ep = environ; *ep; ep++) {
			printf("%s\n", *ep);
		}
		return;
	}

	if ((lp = *v++) == 0) {
		lp = S_;	/* "" */
	}
	local_setenv(vp, lp = globone(lp));
	if (eq(vp, S_PATH)) {
		importpath(lp);
		dohash(xhash);
	} else if (islocalevar(vp)) {
		if (!setlocale(LC_ALL, "")) {
			error("Locale could not be set properly");
		}
	}

	xfree(lp);
}

void
dounsetenv(tchar **v)
{
#ifdef TRACE
	tprintf("TRACE- dounsetenv()\n");
#endif
	v++;
	do {
		local_unsetenv(*v);
		if (islocalevar(*v++)) {
			setlocale(LC_ALL, "");	/* Hope no error! */
		}
	} while (*v);
}

void
local_setenv(tchar *name, tchar *val)
{
	char **ep = environ;
	tchar *cp;
	char *dp;
	tchar *ep_;	/* temporary */
	char *blk[2], **oep = ep;

#ifdef TRACE
	/* tprintf("TRACE- local_setenv(%t, %t)\n", name, val); */
	/* printf("IN local_setenv args = (%t)\n", val); */
#endif
	for (; *ep; ep++) {
#ifdef MBCHAR
		for (cp = name, dp = *ep; *cp && *dp; cp++) {
			/*
			 * This loop compares two chars in different
			 * representations, EUC (as char *) and wchar_t
			 * (in tchar), and ends when they are different.
			 */
			wchar_t	dwc;
			int	n;

			n = mbtowc(&dwc, dp, MB_CUR_MAX);
			if (n <= 0) {
				break; /* Illegal multibyte. */
			}
			dp += n; /* Advance to next multibyte char. */
			if (dwc == (wchar_t)(*cp & TRIM)) {
				continue;
			} else  {
				break;
			}
		}
#else /* !MBCHAR */
		for (cp = name, dp = *ep; *cp && (char)*cp == *dp; cp++, dp++) {
			continue;
		}
#endif /* !MBCHAR */
		if (*cp != 0 || *dp != '=') {
			continue;
		}
		cp = strspl(S_EQ, val);
		xfree(*ep);
		ep_ = strspl(name, cp);		/* ep_ is xalloc'ed */
		xfree(cp);
		/*
		 * Trimming is not needed here.
		 * trim();
		 */
		*ep = tstostr(NULL, ep_);
		xfree(ep_);			/* because temp.  use */
		return;
	}
	ep_ = strspl(name, S_EQ);		/* ep_ is xalloc'ed */
	blk[0] = tstostr(NULL, ep_);
	blk[1] = 0;
	xfree(ep_);
	environ = (char **)blkspl_((char **)environ, blk);
	xfree((void *)oep);
	local_setenv(name, val);
}

void
local_unsetenv(tchar *name)
{
	char **ep = environ;
	tchar *cp;
	char *dp;
	char **oep = ep;
	char *cp_;	/* tmp use */
	static int cnt = 0;	/* delete counter */

#ifdef TRACE
	tprintf("TRACE- local_unsetenv()\n");
#endif
	for (; *ep; ep++) {
#ifdef MBCHAR
		for (cp = name, dp = *ep; *cp && *dp; cp++) {
			/*
			 * This loop compares two chars in different
			 * representations, EUC (as char *) and wchar_t
			 * (in tchar), and ends when they are different.
			 */
			wchar_t	dwc;
			int	n;

			n = mbtowc(&dwc, dp, MB_CUR_MAX);
			if (n <= 0) {
				break; /* Illegal multibyte. */
			}
			dp += n; /* Advance to next multibyte char. */
			if (dwc == (wchar_t)(*cp & TRIM)) {
				continue;
			} else {
				break;
			}
		}
#else /* !MBCHAR */
		for (cp = name, dp = *ep; *cp && (char)*cp == *dp; cp++, dp++) {
			continue;
		}
#endif /* !MBCHAR */
		if (*cp != 0 || *dp != '=') {
			continue;
		}
		cp_ = *ep;
		*ep = 0;
		environ = (char **)blkspl_((char **)environ, ep+1);
		*ep = cp_;
		xfree(cp_);
		xfree((void *)oep);
		return;
	}
}

void
doumask(tchar **v)
{
	tchar *cp = v[1];
	int i;

#ifdef TRACE
	tprintf("TRACE- dounmask()\n");
#endif
	if (cp == 0) {
		i = umask(0);
		(void) umask(i);
		printf("%o\n", i);
		return;
	}
	i = 0;
	while (digit(*cp) && *cp != '8' && *cp != '9') {
		i = i * 8 + *cp++ - '0';
	}
	if (*cp || i < 0 || i > 0777) {
		bferr("Improper mask");
	}
	(void) umask(i);
}


struct limits *
findlim(tchar *cp)
{
	struct limits *lp, *res;

#ifdef TRACE
	tprintf("TRACE- findlim()\n");
#endif
	res = 0;
	for (lp = limits; lp->limconst >= 0; lp++) {
		if (prefix(cp, lp->limname)) {
			if (res) {
				bferr("Ambiguous");
			}
			res = lp;
		}
	}
	if (res) {
		return (res);
	}
	bferr("No such limit");
	/*NOTREACHED*/
}

void
dolimit(tchar **v)
{
	struct limits *lp;
	rlim_t limit;
	tchar hard = 0;

#ifdef TRACE
	tprintf("TRACE- dolimit()\n");
#endif
	v++;
	if (*v && eq(*v, S_h)) {
		hard = 1;
		v++;
	}
	if (*v == 0) {
		for (lp = limits; lp->limconst >= 0; lp++) {
			plim(lp, hard);
		}
		return;
	}
	lp = findlim(v[0]);
	if (v[1] == 0) {
		plim(lp,  hard);
		return;
	}
	switch (getval(lp, v+1, &limit)) {
	case 0:
		error("Value specified for limit is too large");
		return;
	case (-1):
		error("Numeric conversion failed");
		return;
	default:
		if (setlim(lp, hard, limit) < 0) {
			error(NOSTR);
		}
	}
}

static int
getval(struct limits *lp, tchar **v, rlim_t *retval)
{
	rlim_t value, tmp, tmp2;
	tchar *cp = *v++;
	char chbuf[BUFSIZ * MB_LEN_MAX];

#ifdef TRACE
	tprintf("TRACE- getval()\n");
#endif

	tstostr(chbuf, cp);
	errno = 0;
	value = strtoull(chbuf, NULL, 0);
/*
 * we must accept zero, but the conversion can fail and give us
 * zero as well...try to deal with it as gracefully as possible
 * by checking for EINVAL
 */
	if (value == 0 && errno == EINVAL)
		return (-1);

	while (digit(*cp) || *cp == '.' || *cp == 'e' || *cp == 'E') {
		cp++;
	}
	if (*cp == 0) {
		if (*v == 0) {
			tmp = value * (rlim_t)lp->limdiv;
			/* Check for overflow */
			if (tmp >= value) {
				*retval = tmp;
				return (1);
			} else {
				return (0);
			}
		}
		cp = *v;
	}
	switch (*cp) {

	case ':':
		if (lp->limconst != RLIMIT_CPU) {
			goto badscal;
		}
		tstostr(chbuf, cp + 1);
		tmp = strtoull(chbuf, NULL, 0);
		tmp2 = value * 60 + tmp;
		if (tmp2 >= value) {
			*retval = tmp2;
			return (1);
		} else {
			return (0);
		}

	case 'h':
		if (lp->limconst != RLIMIT_CPU) {
			goto badscal;
		}
		limtail(cp, S_hours);
		tmp = value * 3600;
		if (tmp < value) {
			return (0);
		}
		value = tmp;
		break;

	case 'm':
		if (lp->limconst == RLIMIT_CPU) {
			limtail(cp, S_minutes);
			tmp = value * 60;
			if (tmp < value) {
				return (0);
			}
			value = tmp;
			break;
		}
	case 'M':
		if (lp->limconst == RLIMIT_CPU) {
			goto badscal;
		}
		*cp = 'm';
		limtail(cp, S_megabytes);
		tmp = value * 1024 * 1024;
		if (tmp < value) {
			return (0);
		}
		value = tmp;
		break;

	case 's':
		if (lp->limconst != RLIMIT_CPU) {
			goto badscal;
		}
		limtail(cp, S_seconds);
		break;

	case 'k':
		if (lp->limconst == RLIMIT_CPU) {
			goto badscal;
		}
		limtail(cp, S_kbytes);
		tmp = value * 1024;
		if (tmp < value) {
			return (0);
		}
		value = tmp;
		break;

	case 'u':
		limtail(cp, S_unlimited);
		*retval = RLIM_INFINITY;
		return (1);

	default:
badscal:
		bferr("Improper or unknown scale factor");
	}
	*retval = value;
	return (1);
}

void
limtail(tchar *cp, tchar *str0)
{
	tchar *str = str0;
#ifdef TRACE
	tprintf("TRACE- limtail()\n");
#endif

	while (*cp && *cp == *str) {
		cp++, str++;
	}
	if (*cp) {
		error("Bad scaling; did you mean ``%t''?", str0);
	}
}

void
plim(struct limits *lp, tchar hard)
{
	struct rlimit rlim;
	char buf[BUFSZ];
	char *pbuf;
	rlim_t limit;

#ifdef TRACE
	tprintf("TRACE- plim()\n");
#endif
	printf("%t \t", lp->limname);
	(void) getrlimit(lp->limconst, &rlim);
	limit = hard ? rlim.rlim_max : rlim.rlim_cur;
	if (limit == RLIM_INFINITY) {
		printf("unlimited");
	} else if (lp->limconst == RLIMIT_CPU) {
		psecs_ull(limit);
	} else {
		buf[BUFSZ - 1] = '\0';
		pbuf = ulltostr((limit / lp->limdiv), &buf[BUFSZ - 1]);
		printf("%s %t", pbuf, lp->limscale);
	}
	printf("\n");
}

void
dounlimit(tchar **v)
{
	struct limits *lp;
	int err = 0;
	tchar hard = 0;
#ifdef TRACE
	tprintf("TRACE- dounlimit()\n");
#endif

	v++;
	if (*v && eq(*v, S_h)) {
		hard = 1;
		v++;
	}
	if (*v == 0) {
		for (lp = limits; lp->limconst >= 0; lp++) {
			if (setlim(lp, hard, RLIM_INFINITY) < 0) {
				err++;
			}
		}
		if (err) {
			error(NULL);
		}
		return;
	}
	while (*v) {
		lp = findlim(*v++);
		if (setlim(lp, hard, RLIM_INFINITY) < 0) {
			error(NULL);
		}
	}
}

int
setlim(struct limits *lp, tchar hard, rlim_t limit)
{
	struct rlimit rlim;

#ifdef TRACE
	tprintf("TRACE- setlim()\n");
#endif
	(void) getrlimit(lp->limconst, &rlim);
	if (hard) {
		rlim.rlim_max = limit;
	} else if (limit == RLIM_INFINITY && geteuid() != 0) {
		rlim.rlim_cur = rlim.rlim_max;
	} else {
		rlim.rlim_cur = limit;
	}
	if (setrlimit(lp->limconst, &rlim) < 0) {
		printf("%t: %t: Can't %s%s limit\n", bname, lp->limname,
		    limit == RLIM_INFINITY ? "remove" : "set",
		    hard ? " hard" : "");
		return (-1);
	}
	return (0);
}

void
dosuspend()
{
	int ctpgrp;
	void (*old)();

#ifdef TRACE
	tprintf("TRACE- dosuspend()\n");
#endif
	if (loginsh) {
		error("Can't suspend a login shell (yet)");
	}
	if (getpid() == getsid(0)) {
		error("Can't suspend this shell");
	}
	untty();
	old = (void (*)())signal(SIGTSTP, SIG_DFL);
	(void) kill(0, SIGTSTP);
	/* the shell stops here */
	(void) signal(SIGTSTP, old);
	if (tpgrp != -1) {
retry:
		(void) ioctl(FSHTTY, TIOCGPGRP,  (char *)&ctpgrp);
		if (ctpgrp != opgrp) {
			old = (void (*)())signal(SIGTTIN, SIG_DFL);
			(void) kill(0, SIGTTIN);
			(void) signal(SIGTTIN, old);
			goto retry;
		}
		(void) setpgid(0, shpgrp);
		(void) ioctl(FSHTTY, TIOCSPGRP, (char *)&shpgrp);
	}
}

void
doeval(tchar **v)
{
	tchar **oevalvec = evalvec;
	tchar *oevalp = evalp;
	jmp_buf osetexit;
	int reenter;
	tchar **gv = 0;

#ifdef TRACE
	tprintf("TRACE- doeval()\n");
#endif
	v++;
	if (*v == 0) {
		return;
	}
	gflag = 0, tglob(v);
	if (gflag) {
		gv = v = glob(v);
		gargv = 0;
		if (v == 0) {
			error("No match");
		}
		v = copyblk(v);
	} else {
		trim(v);
	}
	getexit(osetexit);
	reenter = 0;
	setexit();
	reenter++;
	if (reenter == 1) {
		evalvec = v;
		evalp = 0;
		process(0);
	}
	evalvec = oevalvec;
	evalp = oevalp;
	doneinp = 0;
	if (gv) {
		blkfree(gv);
	}
	resexit(osetexit);
	if (reenter >= 2) {
		error(NULL);
	}
}
