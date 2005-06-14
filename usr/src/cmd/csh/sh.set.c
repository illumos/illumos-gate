/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"
#include "sh.tconst.h"
extern didchdir;

/*
 * C Shell
 */

doset(v)
	register tchar **v;
{
	register tchar *p;
	tchar *vp, op;
	tchar **vecp;
	bool hadsub;
	int subscr;
	tchar *retp;

#ifdef TRACE
	tprintf("TRACE- doset()\n");
#endif
	v++;
	p = *v++;
	if (p == 0) {
		prvars();
		return;
	}
	do {
		hadsub = 0;
		/*
		 * check for proper variable syntax
		 * must be alphanumeric, start with a letter and
		 * be at most 20 characters
		 */
		for (vp = p; alnum(*p); p++)
			continue;
		if (vp == p || !letter(*vp))
			goto setsyn;
		if ( (p - vp) > MAX_VAR_LEN )
			bferr("Variable name too long");
		if (*p == '[') {
			hadsub++;
			p = getinx(p, &subscr);
		}
		if (op = *p) {
			*p++ = 0;
			if (*p == 0 && *v && **v == '(')
				p = *v++;
		} else if (*v && eq(*v, S_EQ/*"="*/)) {
			op = '=', v++;
			if (*v)
				p = *v++;
		}
		if (op && op != '=')
setsyn:
			bferr("Syntax error");
		if (eq(p, S_LPAR/*"("*/)) {
			register tchar **e = v;

			if (hadsub)
				goto setsyn;
			for (;;) {
				if (!*e)
					bferr("Missing )");
				if (**e == ')')
					break;
				e++;
			}
			p = *e;
			*e = 0;
			vecp = saveblk(v);
			set1(vp, vecp, &shvhed);
			*e = p;
			v = e + 1;
		} else if (hadsub) {
			retp = savestr(p);
			asx(vp, subscr, retp);
			xfree(retp);
			retp = 0;
		} else
			set(vp, savestr(p));
		if (eq(vp, S_path/*"path"*/)) {
			exportpath(adrof(S_path/*"path"*/)->vec);
			dohash(xhash);
		} else if (eq(vp, S_histchars/*"histchars"*/)) {
			register tchar *p = value(S_histchars/*"histchars"*/);
			HIST = *p++;
			HISTSUB = *p;
		} else if (eq(vp, S_user/*"user"*/))
			local_setenv(S_USER/*"USER"*/, value(vp));
		else if (eq(vp, S_term/*"term"*/))
			local_setenv(S_TERM/*"TERM"*/, value(vp));
		else if (eq(vp, S_home/*"home"*/))
			local_setenv(S_HOME/*"HOME"*/, value(vp));
#ifdef FILEC
		else if (eq(vp, S_filec/*"filec"*/))
			filec = 1;
		else if (eq(vp, S_cdpath/*"cdpath"*/))
			dohash(xhash2);
#endif
	} while (p = *v++);
}

tchar *
getinx(cp, ip)
	register tchar *cp;
	register int *ip;
{

#ifdef TRACE
	tprintf("TRACE- getinx()\n");
#endif
	*ip = 0;
	*cp++ = 0;
	while (*cp && digit(*cp))
		*ip = *ip * 10 + *cp++ - '0';
	if (*cp++ != ']')
		bferr("Subscript error");
	return (cp);
}

asx(vp, subscr, p)
	tchar *vp;
	int subscr;
	tchar *p;
{
	register struct varent *v = getvx(vp, subscr);

#ifdef TRACE
	tprintf("TRACE- asx()\n");
#endif
	xfree(v->vec[subscr - 1]);
	v->vec[subscr - 1] = globone(p);
}

struct varent *
getvx(vp, subscr)
	tchar *vp;
{
	register struct varent *v = adrof(vp);

#ifdef TRACE
	tprintf("TRACE- getvx()\n");
#endif
	if (v == 0)
		udvar(vp);
	if (subscr < 1 || subscr > blklen(v->vec))
		bferr("Subscript out of range");
	return (v);
}

tchar plusplus[2] = { '1', 0 };

dolet(v)
	tchar **v;
{
	register tchar *p;
	tchar *vp, c, op;
	bool hadsub;
	int subscr;

	v++;
	p = *v++;
	if (p == 0) {
		prvars();
		return;
	}
	do {
		hadsub = 0;
		for (vp = p; alnum(*p); p++)
			continue;
		if (vp == p || !letter(*vp))
			goto letsyn;
		if (*p == '[') {
			hadsub++;
			p = getinx(p, &subscr);
		}
		if (*p == 0 && *v)
			p = *v++;
		if (op = *p)
			*p++ = 0;
		else
			goto letsyn;
		vp = savestr(vp);
		if (op == '=') {
			c = '=';
			p = xset(p, &v);
		} else {
			c = *p++;
			/* if (any(c, "+-")) { */
			if (c == '+' || c == '-') {
				if (c != op || *p)
					goto letsyn;
				p = plusplus;
			} else {
				/*if (any(op, "<>")) {*/
				if (op == '<' || op == '>') {
					if (c != op)
						goto letsyn;
					c = *p++;
letsyn:
					bferr("Syntax error");
				}
				if (c != '=')
					goto letsyn;
				p = xset(p, &v);
			}
		}
		if (op == '=')
			if (hadsub)
				asx(vp, subscr, p);
			else
				set(vp, p);
		else
			if (hadsub)
#ifndef V6
				/* avoid bug in vax CC */
				{
					struct varent *gv = getvx(vp, subscr);

					asx(vp, subscr, operate(op, gv->vec[subscr - 1], p));
				}
#else
				asx(vp, subscr, operate(op, getvx(vp, subscr)->vec[subscr - 1], p));
#endif
			else
				set(vp, operate(op, value(vp), p));
		if (eq(vp, S_path/*"path"*/)) {
			exportpath(adrof(S_path/*"path"*/)->vec);
			dohash(xhash);
		}

		if (eq(vp, S_cdpath/*"cdpath"*/))
			dohash(xhash2);

		XFREE(vp)
		if (c != '=')
			XFREE(p)
	} while (p = *v++);
}

tchar *
xset(cp, vp)
	tchar *cp, ***vp;
{
	register tchar *dp;

#ifdef TRACE
	tprintf("TRACE- xset()\n");
#endif
	if (*cp) {
		dp = savestr(cp);
		--(*vp);
		xfree(**vp);
		**vp = dp;
	}
	return (putn(exp(vp)));
}

tchar *
operate(op, vp, p)
	tchar op, *vp, *p;
{
	tchar opr[2];
	tchar *vec[5];
	register tchar **v = vec;
	tchar **vecp = v;
	register int i;

	if (op != '=') {
		if (*vp)
			*v++ = vp;
		opr[0] = op;
		opr[1] = 0;
		*v++ = opr;
		if (op == '<' || op == '>')
			*v++ = opr;
	}
	*v++ = p;
	*v++ = 0;
	i = exp(&vecp);
	if (*vecp)
		bferr("Expression syntax");
	return (putn(i));
}

static tchar *putp;
 
tchar *
putn(n)
	register int n;
{
	static tchar number[15];

#ifdef TRACE
	tprintf("TRACE- putn()\n");
#endif
	putp = number;
	if (n < 0) {
		n = -n;
		*putp++ = '-';
	}
	if (sizeof (int) == 2 && n == -32768) {
		*putp++ = '3';
		n = 2768;
#ifdef pdp11
	}
#else
	} else if (sizeof (int) == 4 && n == 0x80000000) {
		*putp++ = '2';
		n = 147483648;
	}
#endif
	putn1(n);
	*putp = 0;
	return (savestr(number));
}

putn1(n)
	register int n;
{
#ifdef TRACE
	tprintf("TRACE- putn1()\n");
#endif
	if (n > 9)
		putn1(n / 10);
	*putp++ = n % 10 + '0';
}

getn(cp)
	register tchar *cp;
{
	register int n;
	int sign;

#ifdef TRACE
	tprintf("TRACE- getn()\n");
#endif
	sign = 0;
	if (cp[0] == '+' && cp[1])
		cp++;
	if (*cp == '-') {
		sign++;
		cp++;
		if (!digit(*cp))
			goto badnum;
	}
	n = 0;
	while (digit(*cp))
		n = n * 10 + *cp++ - '0';
	if (*cp)
		goto badnum;
	return (sign ? -n : n);
badnum:
	bferr("Badly formed number");
	return (0);
}

tchar *
value1(var, head)
	tchar *var;
	struct varent *head;
{
	register struct varent *vp;

#ifdef TRACE
	tprintf("TRACE- value1()\n");
#endif
	vp = adrof1(var, head);
	return (vp == 0 || vp->vec[0] == 0 ? S_/*""*/ : vp->vec[0]);
}

struct varent *
madrof(pat, vp)
	tchar *pat;
	register struct varent *vp;
{
	register struct varent *vp1;

#ifdef TRACE
	tprintf("TRACE- madrof()\n");
#endif
	for (; vp; vp = vp->v_right) {
		if (vp->v_left && (vp1 = madrof(pat, vp->v_left)))
			return vp1;
		if (Gmatch(vp->v_name, pat))
			return vp;
	}
	return vp;
}

struct varent *
adrof1(name, v)
	register tchar *name;
	register struct varent *v;
{
	register cmp;

#ifdef TRACE
	tprintf("TRACE- adrof1()\n");
#endif
	v = v->v_left;
	while (v && ((cmp = *name - *v->v_name) ||
		     (cmp = strcmp_(name, v->v_name))))
		if (cmp < 0)
			v = v->v_left;
		else
			v = v->v_right;
	return v;
}

/*
 * The caller is responsible for putting value in a safe place
 */
set(var, val)
	tchar *var, *val;
{
	register tchar **vec =  (tchar **) xalloc(2 * sizeof  (tchar **));

#ifdef TRACE
	tprintf("TRACE- set()\n");
#endif
	vec[0] = onlyread(val) ? savestr(val) : val;
	vec[1] = 0;
	set1(var, vec, &shvhed);
}

set1(var, vec, head)
	tchar *var, **vec;
	struct varent *head;
{
	register tchar **oldv = vec;

#ifdef TRACE
	tprintf("TRACE- set1()\n");
#endif
	gflag = 0;
	/* If setting cwd variable via "set cwd=/tmp/something"
	 * then do globbing.  But if we are setting the cwd
 	 * becuz of a cd, chdir, pushd, popd, do not do globbing.
	 */
	if ( (!(eq(var,S_cwd))) || (eq(var,S_cwd) && (didchdir == 0)) )
		{
        	tglob(oldv);
		}
	if (gflag) {
		vec = glob(oldv);
		if (vec == 0) {
			bferr("No match");
			blkfree(oldv);
			return;
		}
		blkfree(oldv);
		gargv = 0;
	}
	setq(var, vec, head);
}

setq(name, vec, p)
	tchar *name, **vec;
	register struct varent *p;
{
	register struct varent *c;
	register f;

#ifdef TRACE
	tprintf("TRACE- setq()\n");
#endif
	f = 0;			/* tree hangs off the header's left link */
	while (c = p->v_link[f]) {
		if ((f = *name - *c->v_name) == 0 &&
		    (f = strcmp_(name, c->v_name)) == 0) {
			blkfree(c->vec);
			goto found;
		}
		p = c;
		f = f > 0;
	}
	p->v_link[f] = c = (struct varent *)xalloc(sizeof (struct varent));
	c->v_name = savestr(name);
	c->v_bal = 0;
	c->v_left = c->v_right = 0;
	c->v_parent = p;
	balance(p, f, 0);
found:
	trim(c->vec = vec);
}

unset(v)
	tchar *v[];
{

#ifdef TRACE
	tprintf("TRACE- unset()\n");
#endif
	unset1(v, &shvhed);
	if (adrof(S_histchars/*"histchars"*/) == 0) {
		HIST = '!';
		HISTSUB = '^';
	}
#ifdef FILEC
	if (adrof(S_filec/*"filec"*/) == 0)
		filec = 0;
#endif
}

unset1(v, head)
	register tchar *v[];
	struct varent *head;
{
	register struct varent *vp;
	register int cnt;

#ifdef TRACE
	tprintf("TRACE- unset1()\n");
#endif
	while (*++v) {
		cnt = 0;
		while (vp = madrof(*v, head->v_left))
			unsetv1(vp), cnt++;
		if (cnt == 0)
			setname(*v);
	}
}

unsetv(var)
	tchar *var;
{
	register struct varent *vp;

#ifdef TRACE
	tprintf("TRACE- unsetv()\n");
#endif
	if ((vp = adrof1(var, &shvhed)) == 0)
		udvar(var);
	unsetv1(vp);
}

unsetv1(p)
	register struct varent *p;
{
	register struct varent *c, *pp;
	register f;

#ifdef TRACE
	tprintf("TRACE- unsetv1()\n");
#endif
	/*
	 * Free associated memory first to avoid complications.
	 */
	blkfree(p->vec);
	XFREE(p->v_name);
	/*
	 * If p is missing one child, then we can move the other
	 * into where p is.  Otherwise, we find the predecessor
	 * of p, which is guaranteed to have no right child, copy
	 * it into p, and move it's left child into it.
	 */
	if (p->v_right == 0)
		c = p->v_left;
	else if (p->v_left == 0)
		c = p->v_right;
	else {
		for (c = p->v_left; c->v_right; c = c->v_right)
			;
		p->v_name = c->v_name;
		p->vec = c->vec;
		p = c;
		c = p->v_left;
	}
	/*
	 * Move c into where p is.
	 */
	pp = p->v_parent;
	f = pp->v_right == p;
	if (pp->v_link[f] = c)
		c->v_parent = pp;
	/*
	 * Free the deleted node, and rebalance.
	 */
	XFREE( (tchar *)p);
	balance(pp, f, 1);
}

setNS(cp)
	tchar *cp;
{
#ifdef TRACE
	tprintf("TRACE- setNS()\n");
#endif

	set(cp, S_/*""*/);
}

shift(v)
	register tchar **v;
{
	register struct varent *argv;
	register tchar *name;

#ifdef TRACE
	tprintf("TRACE- shift()\n");
#endif
	v++;
	name = *v;
	if (name == 0)
		name = S_argv/*"argv"*/;
	else
		(void) strip(name);
	argv = adrof(name);
	if (argv == 0)
		udvar(name);
	if (argv->vec[0] == 0)
		bferr("No more words");
	lshift(argv->vec, 1);
}

exportpath(val)
	tchar **val;
{
	tchar exppath[PATHSIZ];

#ifdef TRACE
	tprintf("TRACE- exportpath()\n");
#endif
	exppath[0] = 0;
	if (val)
		while (*val) {
			if (strlen_(*val) + strlen_(exppath) + 2 > PATHSIZ) {
				printf("Warning: ridiculously long PATH truncated\n");
				break;
			}
			(void) strcat_(exppath, *val++);
			if (*val == 0 || eq(*val, S_RPAR/*")"*/))
				break;
			(void) strcat_(exppath, S_COLON/*":"*/);
		}
	local_setenv(S_PATH/*"PATH"*/, exppath);
}

	/* macros to do single rotations on node p */
#define rright(p) (\
	t = (p)->v_left,\
	(t)->v_parent = (p)->v_parent,\
	((p)->v_left = t->v_right) ? (t->v_right->v_parent = (p)) : 0,\
	(t->v_right = (p))->v_parent = t,\
	(p) = t)
#define rleft(p) (\
	t = (p)->v_right,\
	(t)->v_parent = (p)->v_parent,\
	((p)->v_right = t->v_left) ? (t->v_left->v_parent = (p)) : 0,\
	(t->v_left = (p))->v_parent = t,\
	(p) = t)

/*
 * Rebalance a tree, starting at p and up.
 * F == 0 means we've come from p's left child.
 * D == 1 means we've just done a delete, otherwise an insert.
 */
balance(p, f, d)
	register struct varent *p;
	register f;
{
	register struct varent *pp;
	register struct varent *t;		/* used by the rotate macros */
	register ff;

#ifdef TRACE
	tprintf("TRACE- balance()\n");
#endif
	/*
	 * Ok, from here on, p is the node we're operating on;
	 * pp is it's parent; f is the branch of p from which we have come;
	 * ff is the branch of pp which is p.
	 */
	for (; pp = p->v_parent; p = pp, f = ff) {
		ff = pp->v_right == p;
		if (f ^ d) {		/* right heavy */
			switch (p->v_bal) {
			case -1:		/* was left heavy */
				p->v_bal = 0;
				break;
			case 0:			/* was balanced */
				p->v_bal = 1;
				break;
			case 1:			/* was already right heavy */
				switch (p->v_right->v_bal) {
				case 1:			/* sigle rotate */
					pp->v_link[ff] = rleft(p);
					p->v_left->v_bal = 0;
					p->v_bal = 0;
					break;
				case 0:			/* single rotate */
					pp->v_link[ff] = rleft(p);
					p->v_left->v_bal = 1;
					p->v_bal = -1;
					break;
				case -1:		/* double rotate */
					rright(p->v_right);
					pp->v_link[ff] = rleft(p);
					p->v_left->v_bal =
						p->v_bal < 1 ? 0 : -1;
					p->v_right->v_bal =
						p->v_bal > -1 ? 0 : 1;
					p->v_bal = 0;
					break;
				}
				break;
			}
		} else {		/* left heavy */
			switch (p->v_bal) {
			case 1:			/* was right heavy */
				p->v_bal = 0;
				break;
			case 0:			/* was balanced */
				p->v_bal = -1;
				break;
			case -1:		/* was already left heavy */
				switch (p->v_left->v_bal) {
				case -1:		/* single rotate */
					pp->v_link[ff] = rright(p);
					p->v_right->v_bal = 0;
					p->v_bal = 0;
					break;
				case 0:			/* signle rotate */
					pp->v_link[ff] = rright(p);
					p->v_right->v_bal = -1;
					p->v_bal = 1;
					break;
				case 1:			/* double rotate */
					rleft(p->v_left);
					pp->v_link[ff] = rright(p);
					p->v_left->v_bal =
						p->v_bal < 1 ? 0 : -1;
					p->v_right->v_bal =
						p->v_bal > -1 ? 0 : 1;
					p->v_bal = 0;
					break;
				}
				break;
			}
		}
		/*
		 * If from insert, then we terminate when p is balanced.
		 * If from delete, then we terminate when p is unbalanced.
		 */
		if ((p->v_bal == 0) ^ d)
			break;
	}
}

plist(p)
	register struct varent *p;
{
	register struct varent *c;
	register len;

#ifdef TRACE
	tprintf("TRACE- plist()\n");
#endif
	if (setintr)
		(void) sigsetmask(sigblock(0) & ~ sigmask(SIGINT));
	for (;;) {
		while (p->v_left)
			p = p->v_left;
	x:
		if (p->v_parent == 0)		/* is it the header? */
			return;
		len = blklen(p->vec);
		printf("%t", p->v_name);
		Putchar('\t');
		if (len != 1)
			Putchar('(');
		blkpr(p->vec);
		if (len != 1)
			Putchar(')');
		Putchar('\n');
		if (p->v_right) {
			p = p->v_right;
			continue;
		}
		do {
			c = p;
			p = p->v_parent;
		} while (p->v_right == c);
		goto x;
	}
}
