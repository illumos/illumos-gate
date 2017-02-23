/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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
#include "sh.dir.h"
#include "sh.tconst.h"

/*
 * C Shell - directory management
 */

struct directory	*dfind(tchar *);
tchar	*dfollow(tchar *);
tchar	*dcanon(tchar *, tchar *);
void	dtildepr(tchar *, tchar *);
void	dfree(struct directory *);
void	dnewcwd(struct directory *);

struct	directory dhead;		/* "head" of loop */
int	printd;				/* force name to be printed */
static tchar *fakev[] = { S_dirs, NOSTR };

/*
 * dinit - initialize current working directory
 */
void
dinit(tchar *hp)
{
	tchar *cp;
	struct directory *dp;
	tchar path[MAXPATHLEN];

#ifdef TRACE
	tprintf("TRACE- dinit()\n");
#endif
	/*
	 * If this is a login shell, we should have a home directory.  But,
	 * if we got here via 'su - <user>' where the user has no directory
	 * in their passwd file, then su has passed HOME=<nothing>, so hp is
	 * non-null, but has zero length.  Thus, we do not know the current
	 * working directory based on the home directory.
	 */
	if (loginsh && hp && *hp)
		cp = hp;
	else {
		cp = getwd_(path);
		if (cp == NULL) {
			printf("Warning: cannot determine current directory\n");
			cp = S_DOT;
		}
	}
	dp = (struct directory *)xcalloc(sizeof (struct directory), 1);
	dp->di_name = savestr(cp);
	dp->di_count = 0;
	dhead.di_next = dhead.di_prev = dp;
	dp->di_next = dp->di_prev = &dhead;
	printd = 0;
	dnewcwd(dp);
}

/*
 * dodirs - list all directories in directory loop
 */
void
dodirs(tchar **v)
{
	struct directory *dp;
	bool lflag;
	tchar *hp = value(S_home);

#ifdef TRACE
	tprintf("TRACE- dodirs()\n");
#endif
	if (*hp == '\0')
		hp = NOSTR;
	if (*++v != NOSTR)
		if (eq(*v, S_MINl /* "-l" */) && *++v == NOSTR)
			lflag = 1;
		else
			error("Usage: dirs [ -l ]");
	else
		lflag = 0;
	dp = dcwd;
	do {
		if (dp == &dhead)
			continue;
		if (!lflag && hp != NOSTR) {
			dtildepr(hp, dp->di_name);
		} else
			printf("%t", dp->di_name);
		printf(" ");
	} while ((dp = dp->di_prev) != dcwd);
	printf("\n");
}

void
dtildepr(tchar *home, tchar *dir)
{

#ifdef TRACE
	tprintf("TRACE- dtildepr()\n");
#endif
	if (!eq(home, S_SLASH /* "/" */) && prefix(home, dir))
		printf("~%t", dir + strlen_(home));
	else
		printf("%t", dir);
}

/*
 * dochngd - implement chdir command.
 */
void
dochngd(tchar **v)
{
	tchar *cp;
	struct directory *dp;

#ifdef TRACE
	tprintf("TRACE- dochngd()\n");
#endif
	printd = 0;
	if (*++v == NOSTR) {
		if ((cp = value(S_home)) == NOSTR || *cp == 0)
			bferr("No home directory");
		if (chdir_(cp) < 0)
			bferr("Can't change to home directory");
		cp = savestr(cp);
	} else if ((dp = dfind(*v)) != 0) {
		printd = 1;
		if (chdir_(dp->di_name) < 0)
			Perror(dp->di_name);
		dcwd->di_prev->di_next = dcwd->di_next;
		dcwd->di_next->di_prev = dcwd->di_prev;
		goto flushcwd;
	} else
		cp = dfollow(*v);
	dp = (struct directory *)xcalloc(sizeof (struct directory), 1);
	dp->di_name = cp;
	dp->di_count = 0;
	dp->di_next = dcwd->di_next;
	dp->di_prev = dcwd->di_prev;
	dp->di_prev->di_next = dp;
	dp->di_next->di_prev = dp;
flushcwd:
	dfree(dcwd);
	dnewcwd(dp);
}

/*
 * dfollow - change to arg directory; fall back on cdpath if not valid
 */
tchar *
dfollow(tchar *cp)
{
	tchar *dp;
	struct varent *c;
	int cdhashval, cdhashval1;
	int index;
	int slash; /* slashes in the argument */
	tchar *fullpath;
	tchar *slashcp; /* cp string prepended with a slash */

#ifdef TRACE
	tprintf("TRACE- dfollow()\n");
#endif
	cp = globone(cp);
	if (chdir_(cp) >= 0)
		goto gotcha;

	/*
	 * If the directory argument has a slash in it,
	 * for example, directory/directory, then can't
	 * find that in the cache table.
	 */
	slash = any('/', cp);

	/*
	 * Try interpreting wrt successive components of cdpath.
	 * cdpath caching is turned off or directory argument
	 * has a slash in it.
	 */
	if (cp[0] != '/'
	    && !prefix(S_DOTSLA /* "./" */, cp)
	    && !prefix(S_DOTDOTSLA /* "../" */, cp)
	    && (c = adrof(S_cdpath))
	    && (!havhash2 || slash)) {
		tchar **cdp;
		tchar *p;
		tchar buf[MAXPATHLEN];

		for (cdp = c->vec; *cdp; cdp++) {
			for (dp = buf, p = *cdp; *dp++ = *p++; )
				;
			dp[-1] = '/';
			for (p = cp; *dp++ = *p++; )
				;
			if (chdir_(buf) >= 0) {
				printd = 1;
				xfree(cp);
				cp = savestr(buf);
				goto gotcha;
			}
		}
	}

	/* cdpath caching turned on */
	if (cp[0] != '/'
	    && !prefix(S_DOTSLA /* "./" */, cp)
	    && !prefix(S_DOTDOTSLA /* "../" */, cp)
	    && (c = adrof(S_cdpath))
	    && havhash2 && !slash) {
		tchar **pv;

		/* If no cdpath or no paths in cdpath, leave */
		if (c == 0 || c->vec[0] == 0)
			pv = justabs;
		else
			pv = c->vec;

		slashcp = strspl(S_SLASH, cp);

		cdhashval = hashname(cp);

		/* index points to next path component to test */
		index = 0;

		/*
		 * Look at each path in cdpath until get a match.
		 * Only look at those path beginning with a slash
		 */
		do {
			/* only check cache for absolute pathnames */
			if (pv[0][0] == '/') {
				cdhashval1 = hash(cdhashval, index);
				if (bit(xhash2, cdhashval1)) {
					/*
					 * concatenate found path with
					 * arg directory
					 */
					fullpath = strspl(*pv, slashcp);
					if (chdir_(fullpath) >= 0) {
						printd = 1;
						xfree(cp);
						cp = savestr(fullpath);
						xfree(slashcp);
						xfree(fullpath);
						goto gotcha;
					}
				}
			}
			/*
			 * relative pathnames are not cached, and must be
			 * checked manually
			 */
			else {
				tchar *p;
				tchar buf[MAXPATHLEN];

				for (dp = buf, p = *pv; *dp++ = *p++; )
					;
				dp[-1] = '/';
				for (p = cp; *dp++ = *p++; )
					;
				if (chdir_(buf) >= 0) {
					printd = 1;
					xfree(cp);
					cp = savestr(buf);
					xfree(slashcp);
					goto gotcha;
				}
			}
			pv++;
			index++;
		} while (*pv);
	}

	/*
	 * Try dereferencing the variable named by the argument.
	 */
	dp = value(cp);
	if ((dp[0] == '/' || dp[0] == '.') && chdir_(dp) >= 0) {
		xfree(cp);
		cp = savestr(dp);
		printd = 1;
		goto gotcha;
	}
	xfree(cp);			/* XXX, use after free */
	Perror(cp);

gotcha:
	if (*cp != '/') {
		tchar *p, *q;
		int cwdlen;
		int len;

		/*
		 * All in the name of efficiency?
		 */

		if ((cwdlen = (strlen_(dcwd->di_name))) == 1) {
			if (*dcwd->di_name == '/') /* root */
				cwdlen = 0;
			else
			{
				/*
				 * if we are here, when the shell started
				 * it was unable to getwd(), lets try it again
				 */
				tchar path[MAXPATHLEN];

				p = getwd_(path);
				if (p == NULL)
					error("cannot determine current directory");
				else
				{
					xfree(dcwd->di_name);
					dcwd->di_name = savestr(p);
					xfree(cp);
					cp = savestr(p);
					return dcanon(cp, cp);
				}

			}
		}
		/*
		 *
		 * for (p = cp; *p++;)
		 * 	;
		 * dp = (tchar *)xalloc((unsigned) (cwdlen + (p - cp) + 1)*sizeof (tchar))
		 */
		len = strlen_(cp);
		dp = (tchar *)xalloc((unsigned)(cwdlen + len + 2) * sizeof (tchar));
		for (p = dp, q = dcwd->di_name; *p++ = *q++; )
			;
		if (cwdlen)
			p[-1] = '/';
		else
			p--;			/* don't add a / after root */
		for (q = cp; *p++ = *q++; )
			;
		xfree(cp);
		cp = dp;
		dp += cwdlen;
	} else
		dp = cp;
	return dcanon(cp, dp);
}

/*
 * dopushd - push new directory onto directory stack.
 *	with no arguments exchange top and second.
 *	with numeric argument (+n) bring it to top.
 */
void
dopushd(tchar **v)
{
	struct directory *dp;

#ifdef TRACE
	tprintf("TRACE- dopushd()\n");
#endif
	printd = 1;
	if (*++v == NOSTR) {
		if ((dp = dcwd->di_prev) == &dhead)
			dp = dhead.di_prev;
		if (dp == dcwd)
			bferr("No other directory");
		if (chdir_(dp->di_name) < 0)
			Perror(dp->di_name);
		dp->di_prev->di_next = dp->di_next;
		dp->di_next->di_prev = dp->di_prev;
		dp->di_next = dcwd->di_next;
		dp->di_prev = dcwd;
		dcwd->di_next->di_prev = dp;
		dcwd->di_next = dp;
	} else if (dp = dfind(*v)) {
		if (chdir_(dp->di_name) < 0)
			Perror(dp->di_name);
	} else {
		tchar *cp;

		cp = dfollow(*v);
		dp = (struct directory *)xcalloc(sizeof (struct directory), 1);
		dp->di_name = cp;
		dp->di_count = 0;
		dp->di_prev = dcwd;
		dp->di_next = dcwd->di_next;
		dcwd->di_next = dp;
		dp->di_next->di_prev = dp;
	}
	dnewcwd(dp);
}

/*
 * dfind - find a directory if specified by numeric (+n) argument
 */
struct directory *
dfind(tchar *cp)
{
	struct directory *dp;
	int i;
	tchar *ep;

#ifdef TRACE
	tprintf("TRACE- dfind()\n");
#endif
	if (*cp++ != '+')
		return (0);
	for (ep = cp; digit(*ep); ep++)
		continue;
	if (*ep)
		return (0);
	i = getn(cp);
	if (i <= 0)
		return (0);
	for (dp = dcwd; i != 0; i--) {
		if ((dp = dp->di_prev) == &dhead)
			dp = dp->di_prev;
		if (dp == dcwd)
			bferr("Directory stack not that deep");
	}
	return (dp);
}

/*
 * dopopd - pop a directory out of the directory stack
 *	with a numeric argument just discard it.
 */
void
dopopd(tchar **v)
{
	struct directory *dp, *p;

#ifdef TRACE
	tprintf("TRACE- dopopd()\n");
#endif
	printd = 1;
	if (*++v == NOSTR)
		dp = dcwd;
	else if ((dp = dfind(*v)) == 0)
		bferr("Invalid argument");
	if (dp->di_prev == &dhead && dp->di_next == &dhead)
		bferr("Directory stack empty");
	if (dp == dcwd) {
		if ((p = dp->di_prev) == &dhead)
			p = dhead.di_prev;
		if (chdir_(p->di_name) < 0)
			Perror(p->di_name);
	}
	dp->di_prev->di_next = dp->di_next;
	dp->di_next->di_prev = dp->di_prev;
	if (dp == dcwd)
		dnewcwd(p);
	else
		dodirs(fakev);
	dfree(dp);
}

/*
 * dfree - free the directory (or keep it if it still has ref count)
 */
void
dfree(struct directory *dp)
{

#ifdef TRACE
	tprintf("TRACE- dfree()\n");
#endif
	if (dp->di_count != 0)
		dp->di_next = dp->di_prev = 0;
	else
		xfree(dp->di_name), xfree((tchar *)dp);
}

/*
 * dcanon - canonicalize the pathname, removing excess ./ and ../ etc.
 *	We are of course assuming that the file system is standardly
 *	constructed (always have ..'s, directories have links).
 *
 *	If the hardpaths shell variable is set, resolve the
 *	resulting pathname to contain no symbolic link components.
 */
tchar *
dcanon(tchar *cp, tchar *p)
{
	tchar *sp;	/* rightmost component currently under
				consideration */
	tchar *p1,	/* general purpose */
	    *p2;
	bool slash, dotdot, hardpaths;

#ifdef TRACE
	tprintf("TRACE- dcannon()\n");
#endif

	if (*cp != '/')
		abort();

	if (hardpaths = (adrof(S_hardpaths) != NULL)) {
		/*
		 * Be paranoid: don't trust the initial prefix
		 * to be symlink-free.
		 */
		p = cp;
	}

	/*
	 * Loop invariant: cp points to the overall path start,
	 * p to its as yet uncanonicalized trailing suffix.
	 */
	while (*p) {			/* for each component */
		sp = p;			/* save slash address */

		while (*++p == '/')	/* flush extra slashes */
			;
		if (p != ++sp)
			for (p1 = sp, p2 = p; *p1++ = *p2++; )
				;

		p = sp;			/* save start of component */
		slash = 0;
		if (*p)
			while (*++p)	/* find next slash or end of path */
				if (*p == '/') {
					slash = 1;
					*p = '\0';
					break;
				}

		if (*sp == '\0') {
			/* component is null */
			if (--sp == cp)	/* if path is one tchar (i.e. /) */
				break;
			else
				*sp = '\0';
			continue;
		}

		if (sp[0] == '.' && sp[1] == '\0') {
			/* Squeeze out component consisting of "." */
			if (slash) {
				for (p1 = sp, p2 = p + 1; *p1++ = *p2++; )
					;
				p = --sp;
			} else if (--sp != cp)
				*sp = '\0';
			continue;
		}

		/*
		 * At this point we have a path of the form "x/yz",
		 * where "x" is null or rooted at "/", "y" is a single
		 * component, and "z" is possibly null.  The pointer cp
		 * points to the start of "x", sp to the start of "y",
		 * and p to the beginning of "z", which has been forced
		 * to a null.
		 */
		/*
		 * Process symbolic link component.  Provided that either
		 * the hardpaths shell variable is set or "y" is really
		 * ".." we replace the symlink with its contents.  The
		 * second condition for replacement is necessary to make
		 * the command "cd x/.." produce the same results as the
		 * sequence "cd x; cd ..".
		 *
		 * Note that the two conditions correspond to different
		 * potential symlinks.  When hardpaths is set, we must
		 * check "x/y"; otherwise, when "y" is known to be "..",
		 * we check "x".
		 */
		dotdot = sp[0] == '.' && sp[1] == '.' && sp[2] == '\0';
		if (hardpaths || dotdot) {
			tchar link[MAXPATHLEN];
			int cc;
			tchar *newcp;

			/*
			 * Isolate the end of the component that is to
			 * be checked for symlink-hood.
			 */
			sp--;
			if (! hardpaths)
				*sp = '\0';

			/*
			 * See whether the component is really a symlink by
			 * trying to read it.  If the read succeeds, it is.
			 */
			if ((hardpaths || sp > cp) &&
			    (cc = readlink_(cp, link, MAXPATHLEN)) >= 0) {
				/*
				 * readlink_ put null, so we don't need this.
				 */
				/* link[cc] = '\0'; */

				/* Restore path. */
				if (slash)
					*p = '/';

				/*
				 * Point p at the start of the trailing
				 * path following the symlink component.
				 * It's already there is hardpaths is set.
				 */
				if (! hardpaths) {
					/* Restore path as well. */
					*(p = sp) = '/';
				}

				/*
				 * Find length of p.
				 */
				for (p1 = p; *p1++; )
					;

				if (*link != '/') {
					/*
					 * Relative path: replace the symlink
					 * component with its value.  First,
					 * set sp to point to the slash at
					 * its beginning.  If hardpaths is
					 * set, this is already the case.
					 */
					if (! hardpaths) {
						while (*--sp != '/')
							;
					}

					/*
					 * Terminate the leading part of the
					 * path, including trailing slash.
					 */
					sp++;
					*sp = '\0';

					/*
					 * New length is: "x/" + link + "z"
					 */
					p1 = newcp = (tchar *)xalloc((unsigned)
						((sp - cp) + cc + (p1 - p)) * sizeof (tchar));
					/*
					 * Copy new path into newcp
					 */
					for (p2 = cp; *p1++ = *p2++; )
						;
					for (p1--, p2 = link; *p1++ = *p2++; )
						;
					for (p1--, p2 = p; *p1++ = *p2++; )
						;
					/*
					 * Restart canonicalization at
					 * expanded "/y".
					 */
					p = sp - cp - 1 + newcp;
				} else {
					/*
					 * New length is: link + "z"
					 */
					p1 = newcp = (tchar *)xalloc((unsigned)
						(cc + (p1 - p))*sizeof (tchar));
					/*
					 * Copy new path into newcp
					 */
					for (p2 = link; *p1++ = *p2++; )
						;
					for (p1--, p2 = p; *p1++ = *p2++; )
						;
					/*
					 * Restart canonicalization at beginning
					 */
					p = newcp;
				}
				xfree(cp);
				cp = newcp;
				continue;	/* canonicalize the link */
			}

			/* The component wasn't a symlink after all. */
			if (! hardpaths)
				*sp = '/';
		}

		if (dotdot) {
			if (sp != cp)
				while (*--sp != '/')
					;
			if (slash) {
				for (p1 = sp + 1, p2 = p + 1; *p1++ = *p2++; )
					;
				p = sp;
			} else if (cp == sp)
				*++sp = '\0';
			else
				*sp = '\0';
			continue;
		}

		if (slash)
			*p = '/';
	}
	return cp;
}

/*
 * dnewcwd - make a new directory in the loop the current one
 *	and export its name to the PWD environment variable.
 */
void
dnewcwd(struct directory *dp)
{

#ifdef TRACE
	tprintf("TRACE- dnewcwd()\n");
#endif
	dcwd = dp;
#ifdef notdef
	/*
	 * If we have a fast version of getwd available
	 * and hardpaths is set, it would be reasonable
	 * here to verify that dcwd->di_name really does
	 * name the current directory.  Later...
	 */
#endif /* notdef */

	didchdir = 1;
	set(S_cwd, savestr(dcwd->di_name));
	didchdir = 0;
	local_setenv(S_PWD, dcwd->di_name);
	if (printd)
		dodirs(fakev);
}
