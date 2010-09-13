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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Network name modification routines.
 */

#include "rcv.h"
#include "configdefs.h"
#include <locale.h>

static char		*arpafix(char name[], char from[]);
static char		*lasthost(char *addr);
static char		*makeremote(char name[], char from[]);
static int		mstash(char name[], int attnet);
static int		mtype(int mid);
static int		netlook(char machine[], int attnet);
static int		nettype(int mid);
static int		ntype(register int nc);
static void		stradd(register char *str, int n, register int c);
static char		*tackon(char *sys, char *rest);
static struct xtrahash	*xlocate(char name[]);
#ifdef OPTIM
static char		best(int src, int dest);
static char		*mlook(int mid);
static int		netkind(register int nt);
static void		optiboth(char net[]);
static void		optim(char net[], char name[]);
static void		optim1(char netstr[], char name[]);
static int		optimex(char net[], char name[]);
static int		optimimp(char net[], char name[]);
static void		prefer(char name[]);
static char		*rpair(char str[], int mach);
#endif

/*
 * Map a name into the correct network "view" of the
 * name.  This is done by prepending the name with the
 * network address of the sender, then optimizing away
 * nonsense.
 */

char *
netmap(char name[], char from[])
{
	char nbuf[BUFSIZ], ret[BUFSIZ];
	register char *cp, *oname;

	if (debug) fprintf(stderr, "netmap(name '%s', from '%s')\n", name, from);
	if (strlen(from) == 0)
		return(name);	/* "from" is empty - can't do anything */

	if (strcmp(from, name) == 0)
		return(name);	/* "from" and "name" are the same, do nothing */

	/*
	 * If the name contains an "@" or a "%", remove it and the host
	 * following it if that host is "known".
	 */
	if (any('@', name) || any('%', name))
		return(arpafix(name, from));

	/*
	 * If the sender contains a "@" or a "%", make "name" into an
	 * address on that host, on the presumption that it should
	 * really have read "name@from" when we received the message
	 * rather than just "name".
	 */
	if (any('@', from) || any('%', from))
		return(unuucp(makeremote(name, from)));
	if (value("onehop") && (cp = strchr(name, '!')) && cp > name) {
		/*
		 * "onehop" is set, meaning all machines are one UUCP
		 * hop away (fat chance, in this day and age), and "name"
		 * is a UUCP path rather than just a name.  Leave it alone.
		 */
		nstrcpy(nbuf, sizeof (nbuf), name);
	} else {
		from = tackon(host, from);
		*strrchr(from, '!') = 0;
		name = tackon(lasthost(from), name);
		while (((cp = lasthost(from)) != 0) && ishost(cp, name)) {
			oname = name;
			name = strchr(name, '!') + 1;
			if (cp == from) {
				from[strlen(from)] = '!';
				if (value("mustbang") && !strchr(name, '!'))
					name = oname;
				return(unuucp(name));
			}
			*--cp = 0;
		}
		from[strlen(from)] = '!';
		from = strchr(from, '!') + 1;
		snprintf(nbuf, sizeof (nbuf), "%s!%s", from, name);
	}
	if (debug) fprintf(stderr, "before optim, nbuf '%s'\n", name);
#ifdef	OPTIM
	if ((cp = value("conv"))==NOSTR || strcmp(cp, "optimize") != 0)
		nstrcpy(ret, sizeof (ret), nbuf);
	else
		optim(nbuf, ret);
#else
	nstrcpy(ret, sizeof (ret), nbuf);
#endif	/* OPTIM */
	if (debug) fprintf(stderr, "after  optim, nbuf '%s', ret '%s'\n", nbuf, ret);
	cp = ret;
	if (debug) fprintf(stderr, "wind up with '%s'\n", name);
	if (!icequal(name, cp))
		return(unuucp((char *) savestr(cp)));
	return(unuucp(name));
}

/*
 * Stick a host on the beginning of a uucp
 * address if it isn't there already.
 */
static char *
tackon(char *sys, char *rest)
{
	while (*rest == '!')
		rest++;
	if (!ishost(sys, rest)) {
		char *r = (char *)salloc(strlen(sys) + strlen(rest) + 2);
		sprintf(r, "%s!%s", sys, rest);
		rest = r;
	}
	return rest;
}

/*
 * Check equality of the first host in a uucp address.
 */
int 
ishost(char *sys, char *rest)
{
	while (*sys && *sys == *rest)
		sys++, rest++;
	return(*sys == 0 && *rest == '!');
}

/*
 * Return last host in a uucp address.
 */
static char *
lasthost(char *addr)
{
	char *r = strrchr(addr, '!');
	return r ? ++r : addr;
}

/*
 * Optionally translate an old format uucp name into a new one, e.g.
 * "mach1!mach2!user" becomes "user@mach2.UUCP".  This optional because
 * some information is necessarily lost (e.g. the route it got here
 * via) and if we don't have the host in our routing tables, we lose.
 * XXX THIS IS NO LONGER VALID WITH THE NEW UUCP PROJECT PLANS TO
 * REGISTER UUCP HOSTS IN THE STANDARD INTERNET NAMESPACE, E.G.
 * ihnp4 BECOMES "ihnp4.att.com".
 */
char *
unuucp(char *name)
{
	register char *np, *hp, *cp;
	char result[100];
	char tname[300];

	if (UnUUCP==0 &&
	    ((cp = value("conv"))==NOSTR || strcmp(cp, "internet")))
		return name;
	if (debug) fprintf(stderr, "unuucp(%s)\n", name);
	nstrcpy(tname, sizeof (tname), name);
	np = strrchr(tname, '!');
	if (np == NOSTR)
		return name;
	*np++ = 0;
	hp = strrchr(tname, '!');
	if (hp == NOSTR)
		hp = tname;
	else
		*hp++ = 0;
	cp = strchr(np, '@');
	if (cp == NOSTR)
		cp = strchr(np, '%');
	if (cp)
		*cp = 0;
	if (debug) fprintf(stderr, "host %s, name %s\n", hp, np);
	snprintf(result, sizeof (result), "%s@%s.UUCP", np, hp);
	if (debug) fprintf(stderr, "unuucp returns %s\n", result);
	return savestr(result);
}

/*
 * Turn a network machine name into a unique character
 */
static int 
netlook(char machine[], int attnet)
{
	register struct netmach *np;
	register char *cp, *cp2;
	char nbuf[BUFSIZ];

	/*
	 * Make into lower case.
	 */
	for (cp = machine, cp2 = nbuf;
	     *cp && cp2 < &nbuf[BUFSIZ-1];
	     *cp2++ = tolower(*cp++))
		/*nothing*/;
	*cp2 = 0;

	/*
	 * If a single letter machine, look through those first.
	 */

	if (strlen(nbuf) == 1)
		for (np = netmach; np->nt_mid != 0; np++)
			if (np->nt_mid == nbuf[0])
				return(nbuf[0]);

	/*
	 * Look for usual name
	 */

	for (np = netmach; np->nt_mid != 0; np++)
		if (strcmp(np->nt_machine, nbuf) == 0)
			return(np->nt_mid);

	/*
	 * Look in side hash table.
	 */

	return(mstash(nbuf, attnet));
}

#ifdef OPTIM
/*
 * Turn a network unique character identifier into a network name.
 */

static char *
netname(int mid)
{
	register struct netmach *np;

	if (mid & 0200)
		return(mlook(mid));
	for (np = netmach; np->nt_mid != 0; np++)
		if (np->nt_mid == mid)
			return(np->nt_machine);
	return(NOSTR);
}
#endif

/*
 * Deal with arpa net addresses.  The way this is done is strange.
 * name contains an "@" or "%".  Look up the machine after it in
 * the hash table.  If it isn't found, return name unmolested.
 * If ???, return name unmolested.
 * Otherwise, delete the "@" or "%" and the machine after it from
 * name, and return the new string.
 */
static char *
arpafix(char name[], char from[])
{
	register char *cp;
	register int arpamach;
	char newname[BUFSIZ];

	if (debug) {
		fprintf(stderr, "arpafix(%s, %s)\n", name, from);
	}
	cp = strrchr(name, '@');
	if (cp == NOSTR)
		cp = strrchr(name, '%');
	if (cp == NOSTR) {
		fprintf(stderr,
		    gettext("Something's amiss -- no @ or %% in arpafix\n"));
		return(name);
	}
	cp++;
	arpamach = netlook(cp, '@');
	if (debug)
		fprintf(stderr,
		    "cp '%s', arpamach %o, nettypes arpamach %o LOCAL %o\n",
		    cp, arpamach, nettype(arpamach), nettype(LOCAL));
	if (arpamach == 0) {
		if (debug)
			fprintf(stderr, "machine %s unknown, uses: %s\n",
			    cp, name);
		return(name);
	}
	if (((nettype(arpamach) & nettype(LOCAL)) & ~AN) == 0) {
		if (debug)
			fprintf(stderr, "machine %s known but remote, uses: %s\n",
			    cp, name);
		return(name);
	}
	nstrcpy(newname, sizeof (newname), name);
	cp = strrchr(newname, '@');
	if (cp == NOSTR)
		cp = strrchr(newname, '%');
	*cp = 0;
	if (debug) fprintf(stderr, "local address, return '%s'\n", newname);
	return(savestr(newname));
}

/*
 * We have name with no @'s in it, and from with @'s.
 * Assume that name is meaningful only on the site in from,
 * and return "name@site_in_from".
 */
static char *
makeremote(char name[], char from[])
{
	register char *cp;
	char rbuf[BUFSIZ];

	if (!value("makeremote"))
		return(name);
	if (debug) fprintf(stderr, "makeremote(%s, %s) returns ", name, from);
	cp = strrchr(from, '@');
	if (cp == NOSTR)
		cp = strrchr(from, '%');
	snprintf(rbuf, sizeof (rbuf), "%s%s", name, cp);
	if (debug) fprintf(stderr, "%s\n", rbuf);
	return(savestr(rbuf));
}

/*
 * Take a network machine descriptor and find the types of connected
 * nets and return it.
 */
static int 
nettype(int mid)
{
	register struct netmach *np;

	if (mid & 0200)
		return(mtype(mid));
	for (np = netmach; np->nt_mid != 0; np++)
		if (np->nt_mid == mid)
			return(np->nt_type);
	return(0);
}

/*
 * Hashing routines to salt away machines seen scanning
 * networks paths that we don't know about.
 */

#define	XHSIZE		97		/* Size of extra hash table */
#define	NXMID		(XHSIZE*3/4)	/* Max extra machines */

struct xtrahash {
	char	*xh_name;		/* Name of machine */
	short	xh_mid;			/* Machine ID */
	short	xh_attnet;		/* Attached networks */
} xtrahash[XHSIZE];

static struct xtrahash	*xtab[XHSIZE];		/* F: mid-->machine name */

static short	midfree;			/* Next free machine id */

/*
 * Initialize the extra host hash table.
 * Called by sreset.
 */
void 
minit(void)
{
	register struct xtrahash *xp, **tp;

	midfree = 0;
	tp = &xtab[0];
	for (xp = &xtrahash[0]; xp < &xtrahash[XHSIZE]; xp++) {
		xp->xh_name = NOSTR;
		xp->xh_mid = 0;
		xp->xh_attnet = 0;
		*tp++ = (struct xtrahash *) 0;
	}
}

/*
 * Stash a net name in the extra host hash table.
 * If a new entry is put in the hash table, deduce what
 * net the machine is attached to from the net character.
 *
 * If the machine is already known, add the given attached
 * net to those already known.
 */
static int 
mstash(char name[], int attnet)
{
	register struct xtrahash *xp;
	int x;

	xp = xlocate(name);
	if (xp == (struct xtrahash *) 0) {
		printf(gettext("Ran out of machine id spots\n"));
		return(0);
	}
	if (xp->xh_name == NOSTR) {
		if (midfree >= XHSIZE) {
			printf(gettext("Out of machine ids\n"));
			return(0);
		}
		xtab[midfree] = xp;
		xp->xh_name = savestr(name);
		xp->xh_mid = 0200 + midfree++;
	}
	x = ntype(attnet);
	if (x == 0)
		xp->xh_attnet |= AN;
	else
		xp->xh_attnet |= x;
	return(xp->xh_mid);
}

/*
 * Search for the given name in the hash table
 * and return the pointer to it if found, or to the first
 * empty slot if not found.
 *
 * If no free slots can be found, return 0.
 */

static struct xtrahash *
xlocate(char name[])
{
	register int h, q, i;
	register char *cp;
	register struct xtrahash *xp;

	for (h = 0, cp = name; *cp; h = (h << 2) + *cp++)
		;
	if (h < 0 && (h = -h) < 0)
		h = 0;
	h = h % XHSIZE;
	cp = name;
	for (i = 0, q = 0; q < XHSIZE; i++, q = i * i) {
		xp = &xtrahash[(h + q) % XHSIZE];
		if (xp->xh_name == NOSTR)
			return(xp);
		if (strcmp(cp, xp->xh_name) == 0)
			return(xp);
		if (h - q < 0)
			h += XHSIZE;
		xp = &xtrahash[(h - q) % XHSIZE];
		if (xp->xh_name == NOSTR)
			return(xp);
		if (strcmp(cp, xp->xh_name) == 0)
			return(xp);
	}
	return((struct xtrahash *) 0);
}

#ifdef OPTIM
/*
 * Return the name from the extra host hash table corresponding
 * to the passed machine id.
 */

static char *
mlook(int mid)
{
	register int m;

	if ((mid & 0200) == 0)
		return(NOSTR);
	m = mid & 0177;
	if (m >= midfree) {
		printf(gettext("Use made of undefined machine id\n"));
		return(NOSTR);
	}
	return(xtab[m]->xh_name);
}
#endif

/*
 * Return the bit mask of net's that the given extra host machine
 * id has so far.
 */
static int 
mtype(int mid)
{
	register int m;

	if ((mid & 0200) == 0)
		return(0);
	m = mid & 0177;
	if (m >= midfree) {
		printf(gettext("Use made of undefined machine id\n"));
		return(0);
	}
	return(xtab[m]->xh_attnet);
}

#ifdef	OPTIM
/*
 * Take a network name and optimize it.  This gloriously messy
 * operation takes place as follows:  the name with machine names
 * in it is tokenized by mapping each machine name into a single
 * character machine id (netlook).  The separator characters (network
 * metacharacters) are left intact.  The last component of the network
 * name is stripped off and assumed to be the destination user name --
 * it does not participate in the optimization.  As an example, the
 * name "res!vax!res!uvax!bill" becomes, tokenized,
 * "r!x!r!v!" and "bill"  A low level routine, optim1, fixes up the
 * network part (eg, "r!x!r!v!"), then we convert back to network
 * machine names and tack the user name on the end.
 *
 * The result of this is copied into the parameter "name"
 */

static void
optim(char net[], char name[])
{
	char netcomp[BUFSIZ], netstr[STSIZ], xfstr[STSIZ];
	register char *cp, *cp2;
	register int c;

	if (debug) fprintf(stderr, "optim(%s, %s) called\n", net, name);
	*netstr = '\0';
	cp = net;
	for (;;) {
		/*
		 * Rip off next path component into netcomp
		 */
		cp2 = netcomp;
		while (*cp && !any(*cp, metanet))
			*cp2++ = *cp++;
		*cp2 = 0;
		/*
		 * If we hit null byte, then we just scanned
		 * the destination user name.  Go off and optimize
		 * if its so.
		 */
		if (*cp == 0)
			break;
		if ((c = netlook(netcomp, *cp)) == 0) {
			printf(gettext("No host named \"%s\"\n"), netcomp);
err:
			nstrcpy(name, BUFSIZ, net);
			return;
		}
		stradd(name, BUFSIZ, c);
		stradd(name, BUFSIZ, *cp++);
		/*
		 * If multiple network separators given,
		 * throw away the extras.
		 */
		while (any(*cp, metanet))
			cp++;
	}
	if (strlen(netcomp) == 0) {
		printf(gettext("net name syntax\n"));
		goto err;
	}
	if (debug) fprintf(stderr, "optim1(%s,%s) called\n", netstr, xfstr);
	optim1(netstr, xfstr);
	if (debug) fprintf(stderr, "optim1(%s,%s) returns\n", netstr, xfstr);

	/*
	 * Convert back to machine names.
	 */

	cp = xfstr;
	*name = '\0';
	while (*cp) {
		if ((cp2 = netname(*cp++)) == NOSTR) {
			printf(gettext("Made up bad net name\n"));
			printf(gettext("Machine code %c (0%o)\n"), cp[-1],
cp[-1]);
			printf(gettext("Sorry.\n"));
			goto err;
		}
		nstrcat(name, BUFSIZ, cp2);
		stradd(name, BUFSIZ, *cp++);
	}
	nstrcat(name, BUFSIZ, netcomp);
	if (debug) fprintf(stderr, "optim returns %s in name\n", name);
}

/*
 * Take a string of network machine id's and separators and
 * optimize them.  We process these by pulling off maximal
 * leading strings of the same type, passing these to the appropriate
 * optimizer and concatenating the results.
 */

static void 
optim1(char netstr[], char name[])
{
	char path[STSIZ], rpath[STSIZ];
	register char *cp, *cp2;
	register int tp, nc;
	
	cp = netstr;
	prefer(cp);
	*name  = '\0';
	/*
	 * If the address ultimately points back to us,
	 * just return a null network path.
	 */
	if ((int)strlen(cp) > 1 && cp[strlen(cp) - 2] == LOCAL)
		return;
	while (*cp != 0) {
		*path = '\0';

		tp = ntype(cp[1]);
		nc = cp[1];
		while (*cp && tp == ntype(cp[1])) {
			stradd(path, sizeof (path), *cp++);
			cp++;
		}
		switch (netkind(tp)) {
		default:
			nstrcpy(rpath, sizeof (rpath), path);
			break;

		case IMPLICIT:
			optimimp(path, rpath);
			break;

		case EXPLICIT:
			optimex(path, rpath);
			break;
		}
		for (cp2 = rpath; *cp2 != 0; cp2++) {
			stradd(name, BUFSIZ, *cp2);
			stradd(name, BUFSIZ, nc);
		}
	}
	optiboth(name);
	prefer(name);
}
#endif	/* OPTIM */

/*
 * Return the network of the separator --
 *	AN for arpa net
 *	BN for Bell labs net	(e.g. UUCP, NOT Berknet)
 *	SN for Schmidt net	(Berknet)
 *	0 if we don't know.
 */
static int 
ntype(register int nc)
{
	register struct ntypetab *np;

	for (np = ntypetab; np->nt_char != 0; np++)
		if (np->nt_char == nc)
			return(np->nt_bcode);
	return(0);
}

#ifdef	OPTIM
/*
 * Return the kind of routing used for the particular net
 * EXPLICIT means explicitly routed
 * IMPLICIT means implicitly routed
 * 0 means don't know
 */

static int 
netkind(register int nt)
{
	register struct nkindtab *np;

	for (np = nkindtab; np->nk_type != 0; np++)
		if (np->nk_type == nt)
			return(np->nk_kind);
	return(0);
}

/*
 * Do name optimization for an explicitly routed network (eg uucp).
 */

static int 
optimex(char net[], char name[])
{
	register char *cp, *rp;
	register int m;

	nstrcpy(name, STSIZ, net);
	cp = name;
	if (strlen(cp) == 0)
		return(-1);
	if (cp[strlen(cp)-1] == LOCAL) {
		name[0] = 0;
		return(0);
	}
	for (cp = name; *cp; cp++) {
		m = *cp;
		rp = strrchr(cp+1, m);
		if (rp != NOSTR)
			strcpy(cp, rp);
	}
	return(0);
}

/*
 * Do name optimization for implicitly routed network (eg, arpanet).
 */

static int 
optimimp(char net[], char name[])
{
	register char *cp;
	register char m;

	cp = net;
	if (strlen(cp) == 0)
		return(-1);
	m = cp[strlen(cp) - 1];
	if (m == LOCAL) {
		*name = '\0';
		return(0);
	}
	name[0] = m;
	name[1] = 0;
	return(0);
}

/*
 * Perform global optimization on the given network path.
 * The trick here is to look ahead to see if there are any loops
 * in the path and remove them.  The interpretation of loops is
 * more strict here than in optimex since both the machine and net
 * type must match.
 */

static void 
optiboth(char net[])
{
	register char *cp, *cp2;

	cp = net;
	if (strlen(cp) == 0)
		return;
	if (((int)strlen(cp) % 2) != 0) {
		printf(gettext("Strange arg to optiboth\n"));
		return;
	}
	while (*cp) {
		cp2 = rpair(cp+2, *cp);
		if (cp2 != NOSTR)
			strcpy(cp, cp2);
		cp += 2;
	}
}

/*
 * Find the rightmost instance of the given (machine, type) pair.
 */

static char *
rpair(char str[], int mach)
{
	register char *cp, *last;

	cp = str;
	last = NOSTR;
	while (*cp) {
		if (*cp == mach)
			last = cp;
		cp += 2;
	}
	return(last);
}

/*
 * Change the network separators in the given network path
 * to the preferred network transmission means.
 */

static void 
prefer(char name[])
{
	register char *cp, n;
	register int state;

	state = LOCAL;
	for (cp = name; *cp; cp += 2) {
		n = best(state, *cp);
		if (n)
			cp[1] = n;
		state = *cp;
	}
}

/*
 * Return the best network separator for the given machine pair.
 */

static char 
best(int src, int dest)
{
	register int dtype, stype;
	register struct netorder *np;

	stype = nettype(src);
	dtype = nettype(dest);
	fflush(stdout);
	if (stype == 0 || dtype == 0) {
		printf(gettext("ERROR:  unknown internal machine id\n"));
		return(0);
	}
	if ((stype & dtype) == 0)
		return(0);
	np = &netorder[0];
	while ((np->no_stat & stype & dtype) == 0)
		np++;
	return(np->no_char);
}
#endif	/* OPTIM */

#ifdef notdef
/*
 * Code to twist around arpa net names.
 */

#define WORD 257			/* Token for a string */

static	char netbuf[256];
static	char *yylval;

/*
 * Reverse all of the arpa net addresses in the given name to
 * be of the form "host @ user" instead of "user @ host"
 * This function is its own inverse.
 */

char *
revarpa(char str[])
{

	if (yyinit(str) < 0)
		return(NOSTR);
	if (name())
		return(NOSTR);
	if (strcmp(str, netbuf) == 0)
		return(str);
	return(savestr(netbuf));
}

/*
 * Parse (by recursive descent) network names, using the following grammar:
 *	name:
 *		term {':' term}
 *		term {'^' term}
 *		term {'!' term}
 *		term '@' name
 *		term '%' name
 *
 *	term:
 *		string of characters.
 */

static int 
name(void)
{
	register int t;
	register char *cp;

	for (;;) {
		t = yylex();
		if (t != WORD)
			return(-1);
		cp = yylval;
		t = yylex();
		switch (t) {
		case 0:
			nstrcat(netbuf, sizeof (netbuf), cp);
			return(0);

		case '@':
		case '%':
			if (name())
				return(-1);
			stradd(netbuf, sizeof (netbuf), '@');
			nstrcat(netbuf, sizeof (netbuf), cp);
			return(0);	
		case WORD:
			return(-1);

		default:
			nstrcat(netbuf, sizeof (netbuf), cp);
			stradd(netbuf, sizeof (netbuf), t);
		}
	}
}

/*
 * Scanner for network names.
 */

static	char *charp;			/* Current input pointer */
static	int nexttok;			/* Salted away next token */

/*
 * Initialize the network name scanner.
 */

int 
yyinit(char str[])
{
	static char lexbuf[BUFSIZ];

	netbuf[0] = 0;
	if (strlen(str) >= sizeof lexbuf - 1)
		return(-1);
	nexttok = 0;
	nstrcpy(lexbuf, sizeof (lexbuf), str);
	charp = lexbuf;
	return(0);
}

/*
 * Scan and return a single token.
 * yylval is set to point to a scanned string.
 */

int 
yylex(void)
{
	register char *cp, *dotp;
	register int s;

	if (nexttok) {
		s = nexttok;
		nexttok = 0;
		return(s);
	}
	cp = charp;
	while (*cp && isspace(*cp))
		cp++;
	if (*cp == 0)
		return(0);
	if (any(*cp, metanet)) {
		charp = cp+1;
		return(*cp);
	}
	dotp = cp;
	while (*cp && !any(*cp, metanet) && !any(*cp, " \t"))
		cp++;
	if (any(*cp, metanet))
		nexttok = *cp;
	if (*cp == 0)
		charp = cp;
	else
		charp = cp+1;
	*cp = 0;
	yylval = dotp;
	return(WORD);
}
#endif

/*
 * Add a single character onto a string. Here dstsize is the size of the 
 * destnation buffer.
 */

static void 
stradd(register char *dst, int dstsize, register int c)
{
	while (*dst != '\0') {
		dst++;
		dstsize--;
	}
	if (--dstsize > 0)
		*dst++ = (char)c;
	*dst = '\0';
}
