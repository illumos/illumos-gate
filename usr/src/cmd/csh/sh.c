/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <locale.h>
#include "sh.h"
/* #include <sys/ioctl.h> */
#include <fcntl.h>
#include <sys/filio.h>
#include "sh.tconst.h"
#include <pwd.h>
#include <stdlib.h>
#ifdef	TRACE
#include <stdio.h>
#endif

/*
 * We use these csh(1) private versions of the select macros, (see select(3C))
 * so as not to be limited by the size of struct fd_set (ie 1024).
 */
#define	CSH_FD_SET(n, p)   ((*((p) + ((n)/NFDBITS))) |= (1 << ((n) % NFDBITS)))
#define	CSH_FD_CLR(n, p)   ((*((p) + ((n)/NFDBITS))) &= ~(1 << ((n) % NFDBITS)))
#define	CSH_FD_ISSET(n, p) ((*((p) + ((n)/NFDBITS))) & (1 << ((n) % NFDBITS)))
#define	CSH_FD_ZERO(p, n)  memset((void *)(p), 0,  (n))

tchar *pathlist[] =	{ S_usrbin /* "/usr/bin" */, S_DOT /* "." */, 0 };
tchar *dumphist[] =	{ S_history /* "history" */, S_h /* "-h" */, 0, 0 };
tchar *loadhist[] =	{ S_source /* "source" */, S_h /* "-h" */,
    S_NDOThistory /* "~/.history" */, 0 };
tchar HIST = '!';
tchar HISTSUB = '^';
int	nofile;
bool	reenter;
bool	nverbose;
bool	nexececho;
bool	quitit;
bool	fast;
bool	batch;
bool	prompt = 1;
bool	enterhist = 0;

extern	gid_t getegid(), getgid();
extern	uid_t geteuid(), getuid();
extern tchar **strblktotsblk(/* char **, int */);

extern void hupforegnd(void);
void interactive_hup(void);
void interactive_login_hup(void);

void	importpath(tchar *);
void	srccat(tchar *, tchar *);
void	srccat_inlogin(tchar *, tchar *);
void	srcunit(int, bool, bool);
void	rechist(void);
void	goodbye(void);
void	pintr1(bool);
void	process(bool);
void	dosource(tchar **);
void	mailchk(void);
void	printprompt(void);
void	sigwaiting(void);
void	siglwp(void);
void	initdesc(int, char *[]);
void	initdesc_x(int, char *[], int);
void	closem(void);
void	unsetfd(int);
void	phup(void);

#ifdef	TRACE
FILE *trace;
/*
 * Trace routines
 */
#define	TRACEFILE	"/tmp/trace.XXXXXX"

/*
 * Initialize trace file.
 * Called from main.
 */
void
trace_init(void)
{
	char name[128];
	char *p;

	strcpy(name, TRACEFILE);
	p = mktemp(name);
	trace = fopen(p, "w");
}

/*
 * write message to trace file
 */
/*VARARGS1*/
void
tprintf(fmt, a, b, c, d, e, f, g, h, i, j)
	char *fmt;
{
	if (trace) {
		fprintf(trace, fmt, a, b, c, d, e, f, g, h, i, j);
		fflush(trace);
	}
}
#endif

int
main(int c, char **av)
{
	tchar **v, *cp, *r;
	int f;
	struct sigvec osv;
	struct sigaction sa;
	tchar s_prompt[MAXHOSTNAMELEN+3];
	char *c_max_var_len;
	int c_max_var_len_size;

	/*
	 * set up the error exit, if there is an error before
	 * this is done, it will core dump, and we don't
	 * tolerate core dumps
	 */
	haderr = 0;
	setexit();
	if (haderr) {
		/*
		 *  if were here, there was an error in the csh
		 *  startup so just punt
		 */
		printf("csh startup error, csh exiting...\n");
		flush();
		exitstat();
	}


	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Copy arguments */
	v = strblktotsblk(av, c);

	/*
	 * Initialize paraml list
	 */
	paraml.next = paraml.prev = &paraml;

	settimes();			/* Immed. estab. timing base */

	if (eq(v[0], S_aout /* "a.out" */))	/* A.out's are quittable */
		quitit = 1;
	uid = getuid();
	loginsh = **v == '-';
	if (loginsh)
		(void) time(&chktim);

	/*
	 * Move the descriptors to safe places.
	 * The variable didfds is 0 while we have only FSH* to work with.
	 * When didfds is true, we have 0,1,2 and prefer to use these.
	 *
	 * Also, setup data for csh internal file descriptor book keeping.
	 */
	initdesc(c, av);

	/*
	 * Initialize the shell variables.
	 * ARGV and PROMPT are initialized later.
	 * STATUS is also munged in several places.
	 * CHILD is munged when forking/waiting
	 */

	c_max_var_len_size = snprintf(NULL, 0, "%ld", MAX_VAR_LEN);
	c_max_var_len = (char *)xalloc(c_max_var_len_size + 1);
	(void) snprintf(c_max_var_len, (c_max_var_len_size + 1),
	    "%ld", MAX_VAR_LEN);
	set(S_SUNW_VARLEN,  strtots(NOSTR, c_max_var_len));
	xfree(c_max_var_len);

	/* don't do globbing here, just set exact copies */
	setNS(S_noglob);

	set(S_status /* "status" */, S_0 /* "0" */);
	dinit(cp = getenvs_("HOME"));	/* dinit thinks that HOME==cwd in a */
					/* login shell */
	if (cp == NOSTR)
		fast++;			/* No home -> can't read scripts */
	else {
		if (strlen_(cp) >= BUFSIZ - 10) {
			cp = NOSTR;
			fast++;
			printf("%s\n", gettext("Pathname too long"));
			set(S_home /* "home" */, savestr(cp));
			local_setenv(S_HOME, savestr(cp));
		}
		set(S_home /* "home" */, savestr(cp));
	}
	/*
	 * Grab other useful things from the environment.
	 * Should we grab everything??
	 */
	if ((cp = getenvs_("USER")) != NOSTR)
		set(S_user /* "user" */, savestr(cp));
	else {
		/*
		 * If USER is not defined, set it here.
		 */
		struct passwd *pw;
		pw = getpwuid(getuid());

		if (pw != NULL) {
			set(S_user, strtots((tchar *)0, pw->pw_name));
			local_setenv(S_USER, strtots((tchar *)0, pw->pw_name));
		} else if (loginsh) { /* Give up setting USER variable. */
	printf("Warning: USER environment variable could not be set.\n");
		}
	}
	if ((cp = getenvs_("TERM")) != NOSTR)
		set(S_term /* "term" */, savestr(cp));
	/*
	 * Re-initialize path if set in environment
	 */
	if ((cp = getenvs_("PATH")) == NOSTR)
		set1(S_path /* "path" */, saveblk(pathlist), &shvhed);
	else
		importpath(cp);
	set(S_shell /* "shell" */, S_SHELLPATH);

	doldol = putn(getpid());		/* For $$ */

	/* restore globbing until the user says otherwise */
	unsetv(S_noglob);

	/*
	 * Record the interrupt states from the parent process.
	 * If the parent is non-interruptible our hand must be forced
	 * or we (and our children) won't be either.
	 * Our children inherit termination from our parent.
	 * We catch it only if we are the login shell.
	 */
		/* parents interruptibility */
	(void) sigvec(SIGINT, (struct sigvec *)0, &osv);
	parintr = osv.sv_handler;
		/* parents terminability */
	(void) sigvec(SIGTERM, (struct sigvec *)0, &osv);
	parterm = osv.sv_handler;

	_signal(SIGLWP, siglwp);
	_signal(SIGWAITING, sigwaiting);
	if (loginsh) {
		(void) signal(SIGHUP, phup);	/* exit processing on HUP */
		(void) signal(SIGXCPU, phup);	/* ...and on XCPU */
		(void) signal(SIGXFSZ, phup);	/* ...and on XFSZ */
	}

	/*
	 * Process the arguments.
	 *
	 * Note that processing of -v/-x is actually delayed till after
	 * script processing.
	 */
	c--, v++;
	while (c > 0 && (cp = v[0])[0] == '-' && *++cp != '\0' && !batch) {
		do switch (*cp++) {

		case 'b':		/* -b	Next arg is input file */
			batch++;
			break;

		case 'c':		/* -c	Command input from arg */
			if (c == 1)
				exit(0);
			c--, v++;
			arginp = v[0];
			prompt = 0;
			nofile++;
			cflg++;
			break;

		case 'e':		/* -e	Exit on any error */
			exiterr++;
			break;

		case 'f':		/* -f	Fast start */
			fast++;
			break;

		case 'i':		/* -i	Interactive, even if !intty */
			intact++;
			nofile++;
			break;

		case 'n':		/* -n	Don't execute */
			noexec++;
			break;

		case 'q':		/* -q	(Undoc'd) ... die on quit */
			quitit = 1;
			break;

		case 's':		/* -s	Read from std input */
			nofile++;
			break;

		case 't':		/* -t	Read one line from input */
			onelflg = 2;
			prompt = 0;
			nofile++;
			break;
#ifdef TRACE
		case 'T':		/* -T 	trace switch on */
			trace_init();
			break;
#endif

		case 'v':		/* -v	Echo hist expanded input */
			nverbose = 1;			/* ... later */
			break;

		case 'x':		/* -x	Echo just before execution */
			nexececho = 1;			/* ... later */
			break;

		case 'V':		/* -V	Echo hist expanded input */
			setNS(S_verbose /* "verbose" */);	/* NOW! */
			break;

		case 'X':		/* -X	Echo just before execution */
			setNS(S_echo /* "echo" */);		/* NOW! */
			break;

		} while (*cp);
		v++, c--;
	}

	if (quitit)			/* With all due haste, for debugging */
		(void) signal(SIGQUIT, SIG_DFL);

	/*
	 * Unless prevented by -c, -i, -s, or -t, if there
	 * are remaining arguments the first of them is the name
	 * of a shell file from which to read commands.
	 */
	if (!batch && (uid != geteuid() || getgid() != getegid())) {
		errno = EACCES;
		child++;			/* So this ... */
		Perror(S_csh /* "csh" */);	/* ... doesn't return */
	}

	if (nofile == 0 && c > 0) {
		nofile = open_(v[0], 0);
		if (nofile < 0) {
			child++;		/* So this ... */
			Perror(v[0]);		/* ... doesn't return */
		}
		file = v[0];
		SHIN = dmove(nofile, FSHIN);	/* Replace FSHIN */
		(void) fcntl(SHIN, F_SETFD, 1);
		prompt = 0;
		c--, v++;
	}

	/*
	 * Consider input a tty if it really is or we are interactive.
	 */
	intty = intact || isatty(SHIN);

	/*
	 * Decide whether we should play with signals or not.
	 * If we are explicitly told (via -i, or -) or we are a login
	 * shell (arg0 starts with -) or the input and output are both
	 * the ttys("csh", or "csh</dev/ttyx>/dev/ttyx")
	 * Note that in only the login shell is it likely that parent
	 * may have set signals to be ignored
	 */
	if (loginsh || intact || intty && isatty(SHOUT))
		setintr = 1;
#ifdef TELL
	settell();
#endif
	/*
	 * Save the remaining arguments in argv.
	 */
	setq(S_argv /* "argv" */, copyblk(v), &shvhed);

	/*
	 * Set up the prompt.
	 */
	if (prompt) {
		gethostname_(s_prompt, MAXHOSTNAMELEN);
		strcat_(s_prompt,
		    uid == 0 ? S_SHARPSP /* "# " */ : S_PERSENTSP /* "% " */);
		set(S_prompt /* "prompt" */, s_prompt);
	}

	/*
	 * If we are an interactive shell, then start fiddling
	 * with the signals; this is a tricky game.
	 */
	shpgrp = getpgid(0);
	opgrp = tpgrp = -1;
	if (setintr) {
		**av = '-';
		if (!quitit)		/* Wary! */
			(void) signal(SIGQUIT, SIG_IGN);
		(void) signal(SIGINT, pintr);
		(void) sigblock(sigmask(SIGINT));
		(void) signal(SIGTERM, SIG_IGN);

		/*
		 * Explicitly terminate foreground jobs and exit if we are
		 * interactive shell
		 */
		if (loginsh) {
			(void) signal(SIGHUP, interactive_login_hup);
		} else {
			(void) signal(SIGHUP, interactive_hup);
		}

		if (quitit == 0 && arginp == 0) {
			(void) signal(SIGTSTP, SIG_IGN);
			(void) signal(SIGTTIN, SIG_IGN);
			(void) signal(SIGTTOU, SIG_IGN);
			/*
			 * Wait till in foreground, in case someone
			 * stupidly runs
			 *	csh &
			 * dont want to try to grab away the tty.
			 */
			if (isatty(FSHDIAG))
				f = FSHDIAG;
			else if (isatty(FSHOUT))
				f = FSHOUT;
			else if (isatty(OLDSTD))
				f = OLDSTD;
			else
				f = -1;
retry:
			if (ioctl(f, TIOCGPGRP,  (char *)&tpgrp) == 0 &&
			    tpgrp != -1) {
				if (tpgrp != shpgrp) {
					void (*old)() = (void (*)())
					    signal(SIGTTIN, SIG_DFL);
					(void) kill(0, SIGTTIN);
					(void) signal(SIGTTIN, old);
					goto retry;
				}
				opgrp = shpgrp;
				shpgrp = getpid();
				tpgrp = shpgrp;
				(void) setpgid(0, shpgrp);
				(void) ioctl(f, TIOCSPGRP,  (char *)&shpgrp);
				(void) fcntl(dcopy(f, FSHTTY), F_SETFD, 1);
			} else {
notty:
printf("Warning: no access to tty; thus no job control in this shell...\n");
				tpgrp = -1;
			}
		}
	}
	if (setintr == 0 && parintr == SIG_DFL)
		setintr++;

	/*
	 * Set SIGCHLD handler, making sure that reads restart after it runs.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = pchild;
	sa.sa_flags = SA_RESTART;
	(void) sigaction(SIGCHLD, &sa, (struct sigaction *)NULL);

	/*
	 * Set an exit here in case of an interrupt or error reading
	 * the shell start-up scripts.
	 */
	setexit();
	haderr = 0;		/* In case second time through */
	if (!fast && reenter == 0) {
		reenter++;

		/*
		 * If this is a login csh, and /etc/.login exists,
		 * source /etc/.login first.
		 */
		if (loginsh) {
			tchar tmp_etc[4+1];	/* strlen("/etc")+1 */
			tchar tmp_login[7+1];	/* strlen("/.login")+1 */

			strtots(tmp_etc, "/etc");
			strtots(tmp_login, "/.login");
			srccat_inlogin(tmp_etc, tmp_login);
		}

		/* Will have value("home") here because set fast if don't */
		srccat(value(S_home /* "home" */),
		    S_SLADOTcshrc /* "/.cshrc" */);

		/* Hash path */
		if (!fast && !arginp && !onelflg && !havhash)
			dohash(xhash);


		/*
		 * Reconstruct the history list now, so that it's
		 * available from within .login.
		 */
		dosource(loadhist);
		if (loginsh) {
			srccat_inlogin(value(S_home /* "home" */),
			    S_SLADOTlogin /* "/.login" */);
		}

		/*
		 * To get cdpath hashing $cdpath must have a
		 * value, not $CDPATH.  So if after reading
		 * the startup files ( .cshrc ), and
		 * user has specified a value for cdpath, then
		 * cache $cdpath paths. xhash2 is global array
		 * for $cdpath caching.
		 */
		if (!fast && !arginp && !onelflg && !havhash2)
				dohash(xhash2);
	}

	/*
	 * Now are ready for the -v and -x flags
	 */
	if (nverbose)
		setNS(S_verbose /* "verbose" */);
	if (nexececho)
		setNS(S_echo /* "echo" */);

	/*
	 * All the rest of the world is inside this call.
	 * The argument to process indicates whether it should
	 * catch "error unwinds".  Thus if we are a interactive shell
	 * our call here will never return by being blown past on an error.
	 */
	process(setintr);

	/*
	 * Mop-up.
	 */
	if (loginsh) {
		printf("logout\n");
		(void) close(SHIN);	/* No need for unsetfd(). */
		child++;
		goodbye();
	}
	rechist();
	exitstat();
}

void
untty(void)
{

	if (tpgrp > 0) {
		(void) setpgid(0, opgrp);
		(void) ioctl(FSHTTY, TIOCSPGRP,  (char *)&opgrp);
	}
}

void
importpath(tchar *cp)
{
	int i = 0;
	tchar *dp;
	tchar **pv;
	int c;
	static tchar dot[2] = {'.', 0};

	for (dp = cp; *dp; dp++)
		if (*dp == ':')
			i++;
	/*
	 * i+2 where i is the number of colons in the path.
	 * There are i+1 directories in the path plus we need
	 * room for a zero terminator.
	 */
	pv =  (tchar **)xcalloc((unsigned)(i + 2), sizeof (tchar **));
	dp = cp;
	i = 0;
	if (*dp)
	for (;;) {
		if ((c = *dp) == ':' || c == 0) {
			*dp = 0;
			pv[i++] = savestr(*cp ? cp : dot);
			if (c) {
				cp = dp + 1;
				*dp = ':';
			} else
				break;
		}
		dp++;
	}
	pv[i] = 0;
	set1(S_path /* "path" */, pv, &shvhed);
}

/*
 * Source to the file which is the catenation of the argument names.
 */
void
srccat(tchar *cp, tchar *dp)
{
	tchar *ep = strspl(cp, dp);
	int unit = dmove(open_(ep, 0), -1);

	(void) fcntl(unit, F_SETFD, 1);
	xfree(ep);
#ifdef INGRES
	srcunit(unit, 0, 0);
#else
	srcunit(unit, 1, 0);
#endif
}

/*
 * Source to the file which is the catenation of the argument names.
 * 	This one does not check the ownership.
 */
void
srccat_inlogin(tchar *cp, tchar *dp)
{
	tchar *ep = strspl(cp, dp);
	int unit = dmove(open_(ep, 0), -1);

	(void) fcntl(unit, F_SETFD, 1);
	xfree(ep);
	srcunit(unit, 0, 0);
}

/*
 * Source to a unit.  If onlyown it must be our file or our group or
 * we don't chance it.	This occurs on ".cshrc"s and the like.
 */
void
srcunit(int unit, bool onlyown, bool hflg)
{
	/* We have to push down a lot of state here */
	/* All this could go into a structure */
	int oSHIN = -1, oldintty = intty;
	struct whyle *oldwhyl = whyles;
	tchar *ogointr = gointr, *oarginp = arginp;
	tchar *oevalp = evalp, **oevalvec = evalvec;
	int oonelflg = onelflg;
	bool oenterhist = enterhist;
	tchar OHIST = HIST;
#ifdef TELL
	bool otell = cantell;
#endif
	struct Bin saveB;

	/* The (few) real local variables */
	jmp_buf oldexit;
	int reenter, omask;

	if (unit < 0)
		return;
	if (didfds)
		donefds();
	if (onlyown) {
		struct stat stb;

		if (fstat(unit, &stb) < 0 ||
		    (stb.st_uid != uid && stb.st_gid != getgid())) {
			(void) close(unit);
			unsetfd(unit);
			return;
		}
	}

	/*
	 * There is a critical section here while we are pushing down the
	 * input stream since we have stuff in different structures.
	 * If we weren't careful an interrupt could corrupt SHIN's Bin
	 * structure and kill the shell.
	 *
	 * We could avoid the critical region by grouping all the stuff
	 * in a single structure and pointing at it to move it all at
	 * once.  This is less efficient globally on many variable references
	 * however.
	 */
	getexit(oldexit);
	reenter = 0;
	if (setintr)
		omask = sigblock(sigmask(SIGINT));
	setexit();
	reenter++;
	if (reenter == 1) {
		/* Setup the new values of the state stuff saved above */
		copy((char *)&saveB, (char *)&B, sizeof (saveB));
		fbuf =  (tchar **) 0;
		fseekp = feobp = fblocks = 0;
		oSHIN = SHIN, SHIN = unit, arginp = 0, onelflg = 0;
		intty = isatty(SHIN), whyles = 0, gointr = 0;
		evalvec = 0; evalp = 0;
		enterhist = hflg;
		if (enterhist)
			HIST = '\0';
		/*
		 * Now if we are allowing commands to be interrupted,
		 * we let ourselves be interrupted.
		 */
		if (setintr)
			(void) sigsetmask(omask);
#ifdef TELL
		settell();
#endif
		process(0);		/* 0 -> blow away on errors */
	}
	if (setintr)
		(void) sigsetmask(omask);
	if (oSHIN >= 0) {
		int i;

		/* We made it to the new state... free up its storage */
		/* This code could get run twice but xfree doesn't care */
		for (i = 0; i < fblocks; i++)
			xfree(fbuf[i]);
		xfree((char *)fbuf);

		/* Reset input arena */
		copy((char *)&B, (char *)&saveB, sizeof (B));

		(void) close(SHIN), SHIN = oSHIN;
		unsetfd(SHIN);
		arginp = oarginp, onelflg = oonelflg;
		evalp = oevalp, evalvec = oevalvec;
		intty = oldintty, whyles = oldwhyl, gointr = ogointr;
		if (enterhist)
			HIST = OHIST;
		enterhist = oenterhist;
#ifdef TELL
		cantell = otell;
#endif
	}

	resexit(oldexit);
	/*
	 * If process reset() (effectively an unwind) then
	 * we must also unwind.
	 */
	if (reenter >= 2)
		error(NULL);
}

void
rechist(void)
{
	tchar buf[BUFSIZ];
	int fp, ftmp, oldidfds;

	if (!fast) {
		if (value(S_savehist /* "savehist" */)[0] == '\0')
			return;
		(void) strcpy_(buf, value(S_home /* "home" */));
		(void) strcat_(buf, S_SLADOThistory /* "/.history" */);
		fp = creat_(buf, 0666);
		if (fp == -1)
			return;
		oldidfds = didfds;
		didfds = 0;
		ftmp = SHOUT;
		SHOUT = fp;
		(void) strcpy_(buf, value(S_savehist /* "savehist" */));
		dumphist[2] = buf;
		dohist(dumphist);
		(void) close(fp);
		unsetfd(fp);
		SHOUT = ftmp;
		didfds = oldidfds;
	}
}

void
goodbye(void)
{
	if (loginsh) {
		(void) signal(SIGQUIT, SIG_IGN);
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGTERM, SIG_IGN);
		setintr = 0;		/* No interrupts after "logout" */
		if (adrof(S_home /* "home" */))
			srccat(value(S_home /* "home" */),
			    S_SLADOTlogout /* "/.logout" */);
	}
	rechist();
	exitstat();
}

void
exitstat(void)
{

#ifdef PROF
	monitor(0);
#endif
	/*
	 * Note that if STATUS is corrupted (i.e. getn bombs)
	 * then error will exit directly because we poke child here.
	 * Otherwise we might continue unwarrantedly (sic).
	 */
	child++;
	untty();
	exit(getn(value(S_status /* "status" */)));
}

/*
 * in the event of a HUP we want to save the history
 */
void
phup(void)
{
	rechist();
	exit(1);
}

void
interactive_hup(void)
{
	hupforegnd();
	exit(1);
}

void
interactive_login_hup(void)
{
	rechist();
	hupforegnd();
	exit(1);
}

tchar *jobargv[2] = { S_jobs /* "jobs" */, 0 };
/*
 * Catch an interrupt, e.g. during lexical input.
 * If we are an interactive shell, we reset the interrupt catch
 * immediately.  In any case we drain the shell output,
 * and finally go through the normal error mechanism, which
 * gets a chance to make the shell go away.
 */
void
pintr(void)
{
	pintr1(1);
}

void
pintr1(bool wantnl)
{
	tchar **v;
	int omask;

	omask = sigblock(0);
	if (setintr) {
		(void) sigsetmask(omask & ~sigmask(SIGINT));
		if (pjobs) {
			pjobs = 0;
			printf("\n");
			dojobs(jobargv);
			bferr("Interrupted");
		}
	}
	(void) sigsetmask(omask & ~sigmask(SIGCHLD));
	draino();

	/*
	 * If we have an active "onintr" then we search for the label.
	 * Note that if one does "onintr -" then we shan't be interruptible
	 * so we needn't worry about that here.
	 */
	if (gointr) {
		search(ZGOTO, 0, gointr);
		timflg = 0;
		if (v = pargv)
			pargv = 0, blkfree(v);
		if (v = gargv)
			gargv = 0, blkfree(v);
		reset();
	} else if (intty && wantnl)
		printf("\n");		/* Some like this, others don't */
	error(NULL);
}

/*
 * Process is the main driving routine for the shell.
 * It runs all command processing, except for those within { ... }
 * in expressions (which is run by a routine evalav in sh.exp.c which
 * is a stripped down process), and `...` evaluation which is run
 * also by a subset of this code in sh.glob.c in the routine backeval.
 *
 * The code here is a little strange because part of it is interruptible
 * and hence freeing of structures appears to occur when none is necessary
 * if this is ignored.
 *
 * Note that if catch is not set then we will unwind on any error.
 * If an end-of-file occurs, we return.
 */
void
process(bool catch)
{
	jmp_buf osetexit;
	struct command *t;

	getexit(osetexit);
	for (;;) {
		pendjob();
		freelex(&paraml);
		paraml.next = paraml.prev = &paraml;
		paraml.word = S_ /* "" */;
		t = 0;
		setexit();
		justpr = enterhist;	/* execute if not entering history */

		/*
		 * Interruptible during interactive reads
		 */
		if (setintr)
			(void) sigsetmask(sigblock(0) & ~sigmask(SIGINT));

		/*
		 * For the sake of reset()
		 */
		freelex(&paraml), freesyn(t), t = 0;

		if (haderr) {
			if (!catch) {
				/* unwind */
				doneinp = 0;
				resexit(osetexit);
				reset();
			}
			haderr = 0;
			/*
			 * Every error is eventually caught here or
			 * the shell dies.  It is at this
			 * point that we clean up any left-over open
			 * files, by closing all but a fixed number
			 * of pre-defined files.  Thus routines don't
			 * have to worry about leaving files open due
			 * to deeper errors... they will get closed here.
			 */
			closem();
			continue;
		}
		if (doneinp) {
			doneinp = 0;
			break;
		}
		if (chkstop)
			chkstop--;
		if (neednote)
			pnote();
		if (intty && prompt && evalvec == 0) {
			mailchk();
			/*
			 * If we are at the end of the input buffer
			 * then we are going to read fresh stuff.
			 * Otherwise, we are rereading input and don't
			 * need or want to prompt.
			 */
			if (fseekp == feobp)
				printprompt();
		}
		err = 0;

		/*
		 * Echo not only on VERBOSE, but also with history expansion.
		 */
		if (lex(&paraml) && intty ||
		    adrof(S_verbose /* "verbose" */)) {
			haderr = 1;
			prlex(&paraml);
			haderr = 0;
		}

		/*
		 * The parser may lose space if interrupted.
		 */
		if (setintr)
			(void) sigblock(sigmask(SIGINT));

		/*
		 * Save input text on the history list if
		 * reading in old history, or it
		 * is from the terminal at the top level and not
		 * in a loop.
		 */
		if (enterhist || catch && intty && !whyles)
			savehist(&paraml);

		/*
		 * Print lexical error messages, except when sourcing
		 * history lists.
		 */
		if (!enterhist && err)
			error("%s", gettext(err));

		/*
		 * If had a history command :p modifier then
		 * this is as far as we should go
		 */
		if (justpr)
			reset();

		alias(&paraml);

		/*
		 * Parse the words of the input into a parse tree.
		 */
		t = syntax(paraml.next, &paraml, 0);
		if (err)
			error("%s", gettext(err));

		/*
		 * Execute the parse tree
		 */
		{
			/*
			 * POSIX requires SIGCHLD to be held
			 * until all processes have joined the
			 * process group in order to avoid race
			 * condition.
			 */
			int omask;

			omask = sigblock(sigmask(SIGCHLD));
			execute(t, tpgrp);
			(void) sigsetmask(omask &~ sigmask(SIGCHLD));
		}

		if (err)
			error("%s", gettext(err));
		/*
		 * Made it!
		 */
		freelex(&paraml), freesyn(t);
	}
	resexit(osetexit);
}

void
dosource(tchar **t)
{
	tchar *f;
	int u;
	bool hflg = 0;
	tchar buf[BUFSIZ];

	t++;
	if (*t && eq(*t, S_h /* "-h" */)) {
		if (*++t == NOSTR)
			bferr("Too few arguments.");
		hflg++;
	}
	(void) strcpy_(buf, *t);
	f = globone(buf);
	u = dmove(open_(f, 0), -1);
	xfree(f);
	freelex(&paraml);
	if (u < 0 && !hflg)
		Perror(f);
	(void) fcntl(u, F_SETFD, 1);
	srcunit(u, 0, hflg);
}

/*
 * Check for mail.
 * If we are a login shell, then we don't want to tell
 * about any mail file unless its been modified
 * after the time we started.
 * This prevents us from telling the user things they already
 * know, since the login program insists on saying
 * "You have mail."
 */
void
mailchk(void)
{
	struct varent *v;
	tchar **vp;
	time_t t;
	int intvl, cnt;
	struct stat stb;
	bool new;

	v = adrof(S_mail /* "mail" */);
	if (v == 0)
		return;
	(void) time(&t);
	vp = v->vec;
	cnt = blklen(vp);
	intvl = (cnt && number(*vp)) ? (--cnt, getn(*vp++)) : MAILINTVL;
	if (intvl < 1)
		intvl = 1;
	if (chktim + intvl > t)
		return;
	for (; *vp; vp++) {
		if (stat_(*vp, &stb) < 0)
			continue;
		new = stb.st_mtime > time0.tv_sec;
		if (stb.st_size == 0 || stb.st_atime >= stb.st_mtime ||
		    (stb.st_atime <= chktim && stb.st_mtime <= chktim) ||
		    loginsh && !new)
			continue;
		if (cnt == 1)
			printf("You have %smail.\n", new ? "new " : "");
		else
			printf("%s in %t.\n", new ? "New mail" : "Mail", *vp);
	}
	chktim = t;
}

/*
 * Extract a home directory from the password file
 * The argument points to a buffer where the name of the
 * user whose home directory is sought is currently.
 * We write the home directory of the user back there.
 */
int
gethdir(tchar *home)
{
	/* getpwname will not be modified, so we need temp. buffer */
	char home_str[BUFSIZ];
	tchar home_ts[BUFSIZ];
	struct passwd *pp /* = getpwnam(home) */;

	pp = getpwnam(tstostr(home_str, home));
	if (pp == 0)
		return (1);
	(void) strcpy_(home, strtots(home_ts, pp->pw_dir));
	return (0);
}


#if 0
void
#ifdef PROF
done(int i)
#else
exit(int i)
#endif
{

	untty();
	_exit(i);
}
#endif

void
printprompt(void)
{
	tchar *cp;

	if (!whyles) {
		/*
		 * Print the prompt string
		 */
		for (cp = value(S_prompt /* "prompt" */); *cp; cp++)
			if (*cp == HIST)
				printf("%d", eventno + 1);
			else {
				if (*cp == '\\' && cp[1] == HIST)
					cp++;
				Putchar(*cp | QUOTE);
			}
	} else
		/*
		 * Prompt for forward reading loop
		 * body content.
		 */
		printf("? ");
	flush();
}

/*
 * Save char * block.
 */
tchar **
strblktotsblk(char **v, int num)
{
	tchar **newv =
	    (tchar **)xcalloc((unsigned)(num+ 1), sizeof (tchar **));
	tchar **onewv = newv;

	while (*v && num--)
		*newv++ = strtots(NOSTR, *v++);
	*newv = 0;
	return (onewv);
}

void
sigwaiting(void)
{
	_signal(SIGWAITING, sigwaiting);
}

void
siglwp(void)
{
	_signal(SIGLWP, siglwp);
}


/*
 * Following functions and data are used for csh to do its
 * file descriptors book keeping.
 */

static int *fdinuse = NULL;	/* The list of files opened by csh */
static int nbytesused = 0;	/* no of bytes allocated to fdinuse */
static int max_fd = 0;		/* The maximum descriptor in fdinuse */
static int my_pid;		/* The process id set in initdesc() */
static int NoFile = NOFILE;	/* The number of files I can use. */

/*
 * Get the number of files this csh can use.
 *
 * Move the initial descriptors to their eventual
 * resting places, closing all other units.
 *
 * Also, reserve 0/1/2, so NIS+ routines do not get
 * hold of them. And initialize fdinuse list and set
 * the current process id.
 *
 * If this csh was invoked from setuid'ed script file,
 * do not close the third argument passed. The file
 * must be one of /dev/fd/0,1,2,,,
 *	(execv() always passes three arguments when it execs a script
 *	 file in a form of #! /bin/csh -b.)
 *
 * If is_reinit is set in initdesc_x(), then we only close the file
 * descriptors that we actually opened (as recorded in fdinuse).
 */
void
initdesc(int argc, char *argv[])
{
	initdesc_x(argc, argv, 0);
}

void
reinitdesc(int argc, char *argv[])
{
	initdesc_x(argc, argv, 1);
}

/*
 * Callback functions for closing all file descriptors.
 */
static int
close_except(void *cd, int fd)
{
	int script_fd = *(int *)cd;

	if (fd >= 3 && fd < NoFile && fd != script_fd)
		(void) close(fd);
	return (0);
}

static int
close_inuse(void *cd, int fd)
{
	int script_fd = *(int *)cd;

	if (fd >= 3 && fd < NoFile && fd != script_fd &&
	    CSH_FD_ISSET(fd, fdinuse)) {
		(void) close(fd);
		unsetfd(fd);
	}
	return (0);
}

void
initdesc_x(int argc, char *argv[], int is_reinit)
{

	int script_fd = -1;
	struct stat buf;
	struct rlimit rlp;

	/*
	 * Get pid of this shell
	 */
	my_pid = getpid();

	/*
	 * Get the hard limit numbers of descriptors
	 * this csh can use.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlp) == 0)
		NoFile = rlp.rlim_cur;

	/*
	 * If this csh was invoked for executing setuid script file,
	 * the third argument passed is the special file name
	 * which should not be closed.  This special file name is
	 * in the form /dev/fd/X.
	 */
	if (argc >= 3)
		if (sscanf(argv[2], "/dev/fd/%d", &script_fd) != 1)
			script_fd = -1;
		else
			/* Make sure to close this file on exec.  */
			fcntl(script_fd, F_SETFD, 1);

	if (fdinuse == NULL) {
		nbytesused = sizeof (int) *
		    howmany(NoFile, sizeof (int) * NBBY);
		fdinuse = (int *)xalloc(nbytesused);
	}

	/*
	 * Close all files except 0/1/2 to get a clean
	 * file descritor space.
	 */
	if (!is_reinit)
		(void) fdwalk(close_except, &script_fd);
	else
		(void) fdwalk(close_inuse, &script_fd);

	didfds = 0;			/* 0, 1, 2 aren't set up */

	if (fstat(0, &buf) < 0)
		open("/dev/null", 0);

	(void) fcntl(SHIN = dcopy(0, FSHIN), F_SETFD,  1);
	(void) fcntl(SHOUT = dcopy(1, FSHOUT), F_SETFD,  1);
	(void) fcntl(SHDIAG = dcopy(2, FSHDIAG), F_SETFD,  1);
	(void) fcntl(OLDSTD = dcopy(SHIN, FOLDSTD), F_SETFD,  1);

	/*
	 * Open 0/1/2 to avoid Nis+ functions to pick them up.
	 *	Now, 0/1/2 are saved, close them and open them.
	 */
	close(0); close(1); close(2);
	open("/dev/null", 0);
	dup(0);
	dup(0);

	/*
	 * Clear fd_set mask
	 */
	if (!is_reinit)
		CSH_FD_ZERO(fdinuse, nbytesused);
}

/*
 * This routine is called after an error to close up
 * any units which may have been left open accidentally.
 *
 * You only need to remove files in fdinuse list.
 * After you have removed the files, you can clear the
 * list and max_fd.
 */
void
closem(void)
{
	int f;

	for (f = 3; f <= max_fd; f++) {
		if (CSH_FD_ISSET(f, fdinuse) &&
		    f != SHIN && f != SHOUT && f != SHDIAG &&
		    f != OLDSTD && f != FSHTTY)
			close(f);
	}
	CSH_FD_ZERO(fdinuse, nbytesused);
	max_fd = 0;
}

/*
 * Reset my_pid when a new process is created.  Only call this
 * if you want the process to affect fdinuse (e.g., fork, but
 * not vfork).
 */
void
new_process(void)
{
	my_pid = getpid();
}


/*
 * Whenever Csh open/create/dup/pipe a file or files,
 * Csh keeps track of its open files. The open files
 * are kept in "fdinuse, Fd In Use" list.
 *
 * When a file descriptor is newly allocated, setfd() is
 * used to mark the fact in "fdinuse" list.
 *	For example,
 *		fd = open("newfile", 0);
 *		setfd(fd);
 *
 * When a file is freed by close() function, unsetfd() is
 * used to remove the fd from "fdinuse" list.
 *	For example,
 *		close(fd);
 *		unsetfd(fd);
 */
void
setfd(int fd)
{
	/*
	 * Because you want to avoid
	 * conflict due to vfork().
	 */
	if (my_pid != getpid())
		return;

	if (fd >= NoFile || fd < 0)
		return;

	if (fd > max_fd)
		max_fd = fd;
	CSH_FD_SET(fd, fdinuse);
}

void
unsetfd(int fd)
{
	int i;

	/*
	 * Because you want to avoid
	 * conflict due to vfork().
	 */
	if (my_pid != getpid())
		return;

	if (fd >= NoFile || fd < 0)
		return;

	CSH_FD_CLR(fd, fdinuse);
	if (fd == max_fd) {
		for (i = max_fd-1; i >= 3; i--)
			if (CSH_FD_ISSET(i, fdinuse)) {
				max_fd = i;
				return;
			}
		max_fd = 0;
	}
}
