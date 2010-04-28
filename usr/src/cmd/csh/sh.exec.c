/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "sh.h"
#include <dirent.h>
#include <string.h>
#include "sh.tconst.h"


/*
 * C shell
 */

/*
 * System level search and execute of a command.
 * We look in each directory for the specified command name.
 * If the name contains a '/' then we execute only the full path name.
 * If there is no search path then we execute only full path names.
 */

/*
 * As we search for the command we note the first non-trivial error
 * message for presentation to the user.  This allows us often
 * to show that a file has the wrong mode/no access when the file
 * is not in the last component of the search path, so we must
 * go on after first detecting the error.
 */
char *exerr;			/* Execution error message */

void	pexerr(void);
void	texec(struct command *, tchar *, tchar **);
void	xechoit(tchar **);
void	dohash(char []);

static void	tconvert(struct command *, tchar *, tchar **);


extern DIR *opendir_(tchar *);

void
doexec(struct command *t)
{
	tchar *sav;
	tchar *dp, **pv, **av;
	struct varent *v;
	bool slash;
	int hashval, hashval1, i;
	tchar *blk[2];
#ifdef TRACE
	tprintf("TRACE- doexec()\n");
#endif

	/*
	 * Glob the command name.  If this does anything, then we
	 * will execute the command only relative to ".".  One special
	 * case: if there is no PATH, then we execute only commands
	 * which start with '/'.
	 */
	dp = globone(t->t_dcom[0]);
	sav = t->t_dcom[0];
	exerr = 0; t->t_dcom[0] = dp;
	setname(dp);
	xfree(sav);
	v = adrof(S_path /* "path" */);
	if (v == 0 && dp[0] != '/') {
		pexerr();
	}
	slash = gflag;

	/*
	 * Glob the argument list, if necessary.
	 * Otherwise trim off the quote bits.
	 */
	gflag = 0; av = &t->t_dcom[1];
	tglob(av);
	if (gflag) {
		av = glob(av);
		if (av == 0)
			error("No match");
	}
	blk[0] = t->t_dcom[0];
	blk[1] = 0;
	av = blkspl(blk, av);
#ifdef VFORK
	Vav = av;
#endif
	trim(av);
	slash |= any('/', av[0]);

	xechoit(av);		/* Echo command if -x */
	/*
	 * Since all internal file descriptors are set to close on exec,
	 * we don't need to close them explicitly here.  Just reorient
	 * ourselves for error messages.
	 */
	SHIN = 0; SHOUT = 1; SHDIAG = 2; OLDSTD = 0;

	/*
	 * We must do this AFTER any possible forking (like `foo`
	 * in glob) so that this shell can still do subprocesses.
	 */
	(void) sigsetmask(0);

	/*
	 * If no path, no words in path, or a / in the filename
	 * then restrict the command search.
	 */
	if (v == 0 || v->vec[0] == 0 || slash)
		pv = justabs;
	else
		pv = v->vec;
	/* / command name for postpending */
	sav = strspl(S_SLASH /* "/" */, *av);
#ifdef VFORK
	Vsav = sav;
#endif
	if (havhash)
		hashval = hashname(*av);
	i = 0;
#ifdef VFORK
	hits++;
#endif
	do {
		if (!slash && pv[0][0] == '/' && havhash) {
			hashval1 = hash(hashval, i);
			if (!bit(xhash, hashval1))
				goto cont;
		}

		/* don't make ./xxx */
		if (pv[0][0] == 0 || eq(pv[0], S_DOT /* "." */)) {
			texec(t, *av, av);
		} else {
			dp = strspl(*pv, sav);
#ifdef VFORK
			Vdp = dp;
#endif
			texec(t, dp, av);
#ifdef VFORK
			Vdp = 0;
#endif
			xfree(dp);
		}
#ifdef VFORK
		misses++;
#endif
cont:
		pv++;
		i++;
	} while (*pv);
#ifdef VFORK
	hits--;
#endif
#ifdef VFORK
	Vsav = 0;
	Vav = 0;
#endif
	xfree(sav);
	xfree((char *)av);
	pexerr();
}

void
pexerr(void)
{

#ifdef TRACE
	tprintf("TRACE- pexerr()\n");
#endif
	/* Couldn't find the damn thing */
	if (exerr)
		bferr(exerr);
	bferr("Command not found");
}

/*
 * Execute command f, arg list t.
 * Record error message if not found.
 * Also do shell scripts here.
 */
void
texec(struct command *cmd, tchar *f, tchar **t)
{
	struct	varent *v;
	tchar	**vp;
	tchar		*lastsh[2];

#ifdef TRACE
	tprintf("TRACE- texec()\n");
#endif
	/* convert cfname and cargs from tchar to char */
	tconvert(cmd, f, t);

	execv(cmd->cfname, cmd->cargs);

	/*
	 * exec returned, free up allocations from above
	 * tconvert(), zero cfname and cargs to prevent
	 * duplicate free() in freesyn()
	 */
	xfree(cmd->cfname);
	chr_blkfree(cmd->cargs);
	cmd->cfname = (char *)0;
	cmd->cargs = (char **)0;

	switch (errno) {
	case ENOEXEC:
		/* check that this is not a binary file */
		{
			int ff = open_(f, 0);
			tchar ch[MB_LEN_MAX];

			if (ff != -1 && read_(ff, ch, 1) == 1 &&
			    !isprint(ch[0]) && !isspace(ch[0])) {
				printf("Cannot execute binary file.\n");
				Perror(f);
				(void) close(ff);
				unsetfd(ff);
				return;
			}
			(void) close(ff);
			unsetfd(ff);
		}
		/*
		 * If there is an alias for shell, then
		 * put the words of the alias in front of the
		 * argument list replacing the command name.
		 * Note no interpretation of the words at this point.
		 */
		v = adrof1(S_shell /* "shell" */, &aliases);
		if (v == 0) {
#ifdef OTHERSH
			int ff = open_(f, 0);
			tchar ch[MB_LEN_MAX];
#endif

			vp = lastsh;
			vp[0] = adrof(S_shell /* "shell" */) ?
			    value(S_shell /* "shell" */) :
			    S_SHELLPATH /* SHELLPATH */;
			vp[1] =  (tchar *) NULL;
#ifdef OTHERSH
			if (ff != -1 && read_(ff, ch, 1) == 1 && ch[0] != '#')
				vp[0] = S_OTHERSH /* OTHERSH */;
			(void) close(ff);
			unsetfd(ff);
#endif
		} else
			vp = v->vec;
		t[0] = f;
		t = blkspl(vp, t);		/* Splice up the new arglst */
		f = *t;

		tconvert(cmd, f, t);		/* convert tchar to char */

		/*
		 * now done with tchar arg list t,
		 * free the space calloc'd by above blkspl()
		 */
		xfree((char *)t);

		execv(cmd->cfname, cmd->cargs);	/* exec the command */

		/* exec returned, same free'ing as above */
		xfree(cmd->cfname);
		chr_blkfree(cmd->cargs);
		cmd->cfname = (char *)0;
		cmd->cargs = (char **)0;

		/* The sky is falling, the sky is falling! */

	case ENOMEM:
		Perror(f);

	case ENOENT:
		break;

	default:
		if (exerr == 0) {
			exerr = strerror(errno);
			setname(f);
		}
	}
}


static void
tconvert(struct command *cmd, tchar *fname, tchar **list)
{
	char **rc;
	int len;

	cmd->cfname = tstostr(NULL, fname);

	len = blklen(list);
	rc = cmd->cargs = (char **)
	    xcalloc((uint_t)(len + 1), sizeof (char **));
	while (len--)
		*rc++ = tstostr(NULL, *list++);
	*rc = NULL;
}


/*ARGSUSED*/
void
execash(tchar **t, struct command *kp)
{
#ifdef TRACE
	tprintf("TRACE- execash()\n");
#endif

	rechist();
	(void) signal(SIGINT, parintr);
	(void) signal(SIGQUIT, parintr);
	(void) signal(SIGTERM, parterm);	/* if doexec loses, screw */
	lshift(kp->t_dcom, 1);
	exiterr++;
	doexec(kp);
	/*NOTREACHED*/
}

void
xechoit(tchar **t)
{
#ifdef TRACE
	tprintf("TRACE- xechoit()\n");
#endif

	if (adrof(S_echo /* "echo" */)) {
		flush();
		haderr = 1;
		blkpr(t), Putchar('\n');
		haderr = 0;
	}
}

/*
 * This routine called when user enters "rehash".
 * Both the path and cdpath caching arrays will
 * be rehashed, via calling dohash.  If either
 * variable is not set with a value, then dohash
 * just exits.
 */
void
dorehash(void)
{
	dohash(xhash);
	dohash(xhash2);
}

/*
 * Fill up caching arrays for path and cdpath
 */
void
dohash(char cachearray[])
{
	struct stat stb;
	DIR *dirp;
	struct dirent *dp;
	int cnt;
	int i = 0;
	struct varent *v;
	tchar **pv;
	int hashval;
	tchar curdir_[MAXNAMLEN+1];

#ifdef TRACE
	tprintf("TRACE- dohash()\n");
#endif
	/* Caching $path */
	if (cachearray == xhash) {
		havhash = 1;
		v = adrof(S_path /* "path" */);
	} else {    /* Caching $cdpath */
		havhash2 = 1;
		v = adrof(S_cdpath /* "cdpath" */);
	}

	for (cnt = 0; cnt < (HSHSIZ / 8); cnt++)
		cachearray[cnt] = 0;
	if (v == 0)
		return;
	for (pv = v->vec; *pv; pv++, i++) {
		if (pv[0][0] != '/')
			continue;
		dirp = opendir_(*pv);
		if (dirp == NULL)
			continue;
		if (fstat(dirp->dd_fd, &stb) < 0 || !isdir(stb)) {
			unsetfd(dirp->dd_fd);
			closedir_(dirp);
			continue;
		}
		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_ino == 0)
				continue;
			if (dp->d_name[0] == '.' &&
			    (dp->d_name[1] == '\0' ||
			    dp->d_name[1] == '.' && dp->d_name[2] == '\0'))
				continue;
			hashval = hash(hashname(strtots(curdir_, dp->d_name)),
			    i);
			bis(cachearray, hashval);
		}
		unsetfd(dirp->dd_fd);
		closedir_(dirp);
	}
}

void
dounhash(void)
{

#ifdef TRACE
	tprintf("TRACE- dounhash()\n");
#endif
	havhash = 0;
	havhash2 = 0;
}

#ifdef VFORK
void
hashstat(void)
{
#ifdef TRACE
	tprintf("TRACE- hashstat_()\n");
#endif

	if (hits+misses)
		printf("%d hits, %d misses, %d%%\n",
		    hits, misses, 100 * hits / (hits + misses));
}
#endif

/*
 * Hash a command name.
 */
int
hashname(tchar *cp)
{
	long h = 0;

#ifdef TRACE
	tprintf("TRACE- hashname()\n");
#endif
	while (*cp)
		h = hash(h, *cp++);
	return ((int)h);
}
