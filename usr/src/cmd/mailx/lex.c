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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcv.h"
#include <locale.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Lexical processing of commands.
 */

#ifdef SIGCONT
static void		contin(int);
#endif
static int		isprefix(char *as1, char *as2);
static const struct cmd	*lex(char word[]);
static int		Passeren(void);
static void		setmsize(int sz);

/*
 * Set up editing on the given file name.
 * If isedit is true, we are considered to be editing the file,
 * otherwise we are reading our mail which has signficance for
 * mbox and so forth.
 */

int
setfile(char *name, int isedit)
{
	FILE *ibuf;
	int i;
	static int shudclob;
	static char efile[PATHSIZE];
	char fortest[128];
	struct stat stbuf;
	int exrc = 1;
	int rc = -1;
	int fd = -1;

	if (!isedit && issysmbox)
		lockmail();
	if (stat(name, &stbuf) < 0 && errno == EOVERFLOW) {
		fprintf(stderr, gettext("mailbox %s is too large to"
		    " accept incoming mail\n"), name);
		goto doret;
	}
	if ((ibuf = fopen(name, "r")) == NULL) {
		extern int errno;
		int sverrno = errno;
		int filethere = (access(name, 0) == 0);
		errno = sverrno;
		if (exitflg)
			goto doexit;	/* no mail, return error */
		if (isedit || filethere)
			perror(name);
		else if (!Hflag) {
			char *f = strrchr(name, '/');
			if (f == NOSTR)
				fprintf(stderr, gettext("No mail.\n"));
			else
				fprintf(stderr, gettext("No mail for %s\n"),
f+1);
		}
		goto doret;
	}
	fstat(fileno(ibuf), &stbuf);
	if (stbuf.st_size == 0L || (stbuf.st_mode&S_IFMT) != S_IFREG) {
		if (exitflg)
			goto doexit;	/* no mail, return error */
		if (isedit)
			if (stbuf.st_size == 0L)
				fprintf(stderr, gettext("%s: empty file\n"),
name);
			else
				fprintf(stderr,
				    gettext("%s: not a regular file\n"), name);
		else if (!Hflag) {
			if (strrchr(name, '/') == NOSTR)
				fprintf(stderr, gettext("No mail.\n"));
			else
				fprintf(stderr, gettext("No mail for %s\n"),
strrchr(name, '/') + 1);
		}
		fclose(ibuf);
		goto doret;
	}

	if (fgets(fortest, sizeof (fortest), ibuf) == NULL) {
		perror(gettext("mailx: Unable to read from mail file"));
		goto doexit;
	}

	fseek(ibuf, (long)(BUFSIZ+1), 0);	/* flush input buffer */
	fseek(ibuf, 0L, 0);
	if (strncmp(fortest, "Forward to ", 11) == 0) {
		if (exitflg)
			goto doexit;	/* no mail, return error */
		fprintf(stderr, gettext("Your mail is being forwarded to %s"),
fortest+11);
		fclose(ibuf);
		goto doret;
	}
	if (exitflg) {
		exrc = 0;
		goto doexit;	/* there is mail, return success */
	}

	/*
	 * Looks like all will be well. Must hold signals
	 * while we are reading the new file, else we will ruin
	 * the message[] data structure.
	 * Copy the messages into /tmp and set pointers.
	 */

	holdsigs();
	if (shudclob) {
		/*
		 * Now that we know we can switch to the new file
		 * it's safe to close out the current file.
		 *
		 * If we're switching to the file we are currently
		 * editing, don't allow it to be removed as a side
		 * effect of closing it out.
		 */
		if (edit)
			edstop(strcmp(editfile, name) == 0);
		else {
			quit(strcmp(editfile, name) == 0);
			if (issysmbox)
				Verhogen();
		}
		fflush(stdout);
		fclose(itf);
		fclose(otf);
		free(message);
		space = 0;
	}
	readonly = 0;
	if (!isedit && issysmbox && !Hflag)
		readonly = Passeren() == -1;
	lock(ibuf, "r", 1);
	fstat(fileno(ibuf), &stbuf);
	utimep->actime = stbuf.st_atime;
	utimep->modtime = stbuf.st_mtime;

	if (!readonly)
		if ((i = open(name, O_WRONLY)) < 0)
			readonly++;
		else
			close(i);
	shudclob = 1;
	edit = isedit;
	nstrcpy(efile, PATHSIZE, name);
	editfile = efile;
#ifdef notdef
	if (name != mailname)
		nstrcpy(mailname, PATHSIZE, name);
#endif
	mailsize = fsize(ibuf);
	if ((fd = open(tempMesg, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(otf = fdopen(fd, "w")) == NULL) {
		perror(tempMesg);
		if (!edit && issysmbox)
			Verhogen();
		goto doexit;
	}
	if ((itf = fopen(tempMesg, "r")) == NULL) {
		perror(tempMesg);
		if (!edit && issysmbox)
			Verhogen();
		goto doexit;
	}
	removefile(tempMesg);
	setptr(ibuf);
	setmsize(msgCount);
	fclose(ibuf);
	relsesigs();
	sawcom = 0;
	rc = 0;

doret:
	if (!isedit && issysmbox)
		unlockmail();
	return (rc);

doexit:
	if (!isedit && issysmbox)
		unlockmail();
	exit(exrc ? exrc : rpterr);
	/* NOTREACHED */
}

/* global to semaphores */
static char semfn[128];
static FILE *semfp = NULL;

/*
 *  return -1 if file is already being read, 0 otherwise
 */
static int
Passeren(void)
{
	char *home;

	if ((home = getenv("HOME")) == NULL)
		return (0);
	snprintf(semfn, sizeof (semfn), "%s%s", home, "/.Maillock");
	if ((semfp = fopen(semfn, "w")) == NULL) {
		fprintf(stderr,
	    gettext("WARNING: Can't open mail lock file (%s).\n"), semfn);
		fprintf(stderr,
	    gettext("\t Assuming you are not already reading mail.\n"));
		return (0);
	}
	if (lock(semfp, "w", 0) < 0) {
		if (errno == ENOLCK) {
			fprintf(stderr,
gettext("WARNING: Unable to acquire mail lock, no record locks available.\n"));
			fprintf(stderr,
		    gettext("\t Assuming you are not already reading mail.\n"));
			return (0);
		}
		fprintf(stderr,
		    gettext("WARNING: You are already reading mail.\n"));
		fprintf(stderr,
		    gettext("\t This instance of mail is read only.\n"));
		fclose(semfp);
		semfp = NULL;
		return (-1);
	}
	return (0);
}

void
Verhogen(void)
{
	if (semfp != NULL) {
		unlink(semfn);
		fclose(semfp);
	}
}

/*
 * Interpret user commands one by one.  If standard input is not a tty,
 * print no prompt.
 */

static int	*msgvec;
static int	shudprompt;

void
commands(void)
{
	int eofloop;
	register int n;
	char linebuf[LINESIZE];
	char line[LINESIZE];
	struct stat minfo;
	FILE *ibuf;

#ifdef SIGCONT
	sigset(SIGCONT, SIG_DFL);
#endif
	if (rcvmode && !sourcing) {
		if (sigset(SIGINT, SIG_IGN) != SIG_IGN)
			sigset(SIGINT, stop);
		if (sigset(SIGHUP, SIG_IGN) != SIG_IGN)
			sigset(SIGHUP, hangup);
	}
	for (;;) {
		setjmp(srbuf);

		/*
		 * Print the prompt, if needed.  Clear out
		 * string space, and flush the output.
		 */

		if (!rcvmode && !sourcing)
			return;
		eofloop = 0;
top:
		if ((shudprompt = (intty && !sourcing)) != 0) {
			if (prompt == NOSTR) {
				if ((int)value("bsdcompat"))
					prompt = "& ";
				else
					prompt = "";
			}
#ifdef SIGCONT
			sigset(SIGCONT, contin);
#endif
			if (intty && value("autoinc") &&
			    stat(editfile, &minfo) >= 0 &&
			    minfo.st_size > mailsize) {
				int OmsgCount, i;

				OmsgCount = msgCount;
				fseek(otf, 0L, 2);
				holdsigs();
				if (!edit && issysmbox)
					lockmail();
				if ((ibuf = fopen(editfile, "r")) == NULL) {
					fprintf(stderr,
					    gettext("Can't reopen %s\n"),
					    editfile);
					if (!edit && issysmbox)
						unlockmail();
					exit(1);
					/* NOTREACHED */
				}
				if (edit || !issysmbox)
					lock(ibuf, "r", 1);
				fseek(ibuf, mailsize, 0);
				mailsize = fsize(ibuf);
				setptr(ibuf);
				setmsize(msgCount);
				fclose(ibuf);
				if (!edit && issysmbox)
					unlockmail();
				if (msgCount-OmsgCount > 0) {
					printf(gettext(
					    "New mail has arrived.\n"));
					if (msgCount - OmsgCount == 1)
						printf(gettext(
						    "Loaded 1 new message\n"));
					else
						printf(gettext(
						    "Loaded %d new messages\n"),
						    msgCount-OmsgCount);
					if (value("header") != NOSTR)
						for (i = OmsgCount+1;
						    i <= msgCount; i++) {
							printhead(i);
							sreset();
						}
				}
				relsesigs();
			}
			printf("%s", prompt);
		}
		flush();
		sreset();

		/*
		 * Read a line of commands from the current input
		 * and handle end of file specially.
		 */

		n = 0;
		linebuf[0] = '\0';
		for (;;) {
			if (readline(input, line) <= 0) {
				if (n != 0)
					break;
				if (loading)
					return;
				if (sourcing) {
					unstack();
					goto more;
				}
				if (value("ignoreeof") != NOSTR && shudprompt) {
					if (++eofloop < 25) {
						printf(gettext(
						    "Use \"quit\" to quit.\n"));
						goto top;
					}
				}
				return;
			}
			if ((n = strlen(line)) == 0)
				break;
			n--;
			if (line[n] != '\\')
				break;
			line[n++] = ' ';
			if (n > LINESIZE - (int)strlen(linebuf) - 1)
				break;
			strcat(linebuf, line);
		}
		n = LINESIZE - strlen(linebuf) - 1;
		if ((int)strlen(line) > n) {
			printf(gettext(
		"Line plus continuation line too long:\n\t%s\n\nplus\n\t%s\n"),
			    linebuf, line);
			if (loading)
				return;
			if (sourcing) {
				unstack();
				goto more;
			}
			return;
		}
		strncat(linebuf, line, n);
#ifdef SIGCONT
		sigset(SIGCONT, SIG_DFL);
#endif
		if (execute(linebuf, 0))
			return;
more:;
	}
}

/*
 * Execute a single command.  If the command executed
 * is "quit," then return non-zero so that the caller
 * will know to return back to main, if it cares.
 * Contxt is non-zero if called while composing mail.
 */

int
execute(char linebuf[], int contxt)
{
	char word[LINESIZE];
	char *arglist[MAXARGC];
	const struct cmd *com;
	register char *cp, *cp2;
	register int c, e;
	int muvec[2];

	/*
	 * Strip the white space away from the beginning
	 * of the command, then scan out a word, which
	 * consists of anything except digits and white space.
	 *
	 * Handle |, ! and # differently to get the correct
	 * lexical conventions.
	 */

	cp = linebuf;
	while (any(*cp, " \t"))
		cp++;
	cp2 = word;
	if (any(*cp, "!|#"))
		*cp2++ = *cp++;
	else
		while (*cp && !any(*cp, " \t0123456789$^.:/-+*'\""))
			*cp2++ = *cp++;
	*cp2 = '\0';

	/*
	 * Look up the command; if not found, complain.
	 * Normally, a blank command would map to the
	 * first command in the table; while sourcing,
	 * however, we ignore blank lines to eliminate
	 * confusion.
	 */

	if (sourcing && equal(word, ""))
		return (0);
	com = lex(word);
	if (com == NONE) {
		fprintf(stderr, gettext("Unknown command: \"%s\"\n"), word);
		if (loading) {
			cond = CANY;
			return (1);
		}
		if (sourcing) {
			cond = CANY;
			unstack();
		}
		return (0);
	}

	/*
	 * See if we should execute the command -- if a conditional
	 * we always execute it, otherwise, check the state of cond.
	 */

	if ((com->c_argtype & F) == 0)
		if (cond == CRCV && !rcvmode || cond == CSEND && rcvmode ||
		    cond == CTTY && !intty || cond == CNOTTY && intty)
			return (0);

	/*
	 * Special case so that quit causes a return to
	 * main, who will call the quit code directly.
	 * If we are in a source file, just unstack.
	 */

	if (com->c_func == (int (*)(void *))edstop) {
		if (sourcing) {
			if (loading)
				return (1);
			unstack();
			return (0);
		}
		return (1);
	}

	/*
	 * Process the arguments to the command, depending
	 * on the type it expects.  Default to an error.
	 * If we are sourcing an interactive command, it's
	 * an error.
	 */

	if (!rcvmode && (com->c_argtype & M) == 0) {
		fprintf(stderr,
		    gettext("May not execute \"%s\" while sending\n"),
		    com->c_name);
		if (loading)
			return (1);
		if (sourcing)
			unstack();
		return (0);
	}
	if (sourcing && com->c_argtype & I) {
		fprintf(stderr,
		    gettext("May not execute \"%s\" while sourcing\n"),
		    com->c_name);
		rpterr = 1;
		if (loading)
			return (1);
		unstack();
		return (0);
	}
	if (readonly && com->c_argtype & W) {
		fprintf(stderr, gettext(
		    "May not execute \"%s\" -- message file is read only\n"),
		    com->c_name);
		if (loading)
			return (1);
		if (sourcing)
			unstack();
		return (0);
	}
	if (contxt && com->c_argtype & R) {
		fprintf(stderr, gettext("Cannot recursively invoke \"%s\"\n"),
		    com->c_name);
		return (0);
	}
	e = 1;
	switch (com->c_argtype & ~(F|P|I|M|T|W|R)) {
	case MSGLIST:
		/*
		 * A message list defaulting to nearest forward
		 * legal message.
		 */
		if (msgvec == 0) {
			fprintf(stderr,
			    gettext("Illegal use of \"message list\"\n"));
			return (-1);
		}
		if ((c = getmsglist(cp, msgvec, com->c_msgflag)) < 0)
			break;
		if (c  == 0)
			if (msgCount == 0)
				*msgvec = NULL;
			else {
				*msgvec = first(com->c_msgflag,
					com->c_msgmask);
				msgvec[1] = NULL;
			}
		if (*msgvec == NULL) {
			fprintf(stderr, gettext("No applicable messages\n"));
			break;
		}
		e = (*com->c_func)(msgvec);
		break;

	case NDMLIST:
		/*
		 * A message operand with no defaults, but no error
		 * if none exists. There will be an error if the
		 * msgvec pointer is of zero value.
		 */
		if (msgvec == 0) {
			fprintf(stderr,
			    gettext("Illegal use of \"message operand\"\n"));
			return (-1);
		}
		if (getmessage(cp, msgvec, com->c_msgflag) < 0)
			break;
		e = (*com->c_func)(msgvec);
		break;

	case STRLIST:
		/*
		 * Just the straight string, with
		 * leading blanks removed.
		 */
		while (any(*cp, " \t"))
			cp++;
		e = (*com->c_func)(cp);
		break;

	case RAWLIST:
		/*
		 * A vector of strings, in shell style.
		 */
		if ((c = getrawlist(cp, arglist,
				sizeof (arglist) / sizeof (*arglist))) < 0)
			break;
		if (c < com->c_minargs) {
			fprintf(stderr,
			    gettext("%s requires at least %d arg(s)\n"),
			    com->c_name, com->c_minargs);
			break;
		}
		if (c > com->c_maxargs) {
			fprintf(stderr,
			    gettext("%s takes no more than %d arg(s)\n"),
			    com->c_name, com->c_maxargs);
			break;
		}
		e = (*com->c_func)(arglist);
		break;

	case NOLIST:
		/*
		 * Just the constant zero, for exiting,
		 * eg.
		 */
		e = (*com->c_func)(0);
		break;

	default:
		panic("Unknown argtype");
	}

	/*
	 * Exit the current source file on
	 * error.
	 */

	if (e && loading)
		return (1);
	if (e && sourcing)
		unstack();
	if (com->c_func == (int (*)(void *))edstop)
		return (1);
	if (value("autoprint") != NOSTR && com->c_argtype & P)
		if ((dot->m_flag & MDELETED) == 0) {
			muvec[0] = dot - &message[0] + 1;
			muvec[1] = 0;
			type(muvec);
		}
	if (!sourcing && (com->c_argtype & T) == 0)
		sawcom = 1;
	return (0);
}

#ifdef SIGCONT
/*
 * When we wake up after ^Z, reprint the prompt.
 */
static void
#ifdef	__cplusplus
contin(int)
#else
/* ARGSUSED */
contin(int s)
#endif
{
	if (shudprompt)
		printf("%s", prompt);
	fflush(stdout);
}
#endif

/*
 * Branch here on hangup signal and simulate quit.
 */
void
#ifdef	__cplusplus
hangup(int)
#else
/* ARGSUSED */
hangup(int s)
#endif
{

	holdsigs();
#ifdef OLD_BSD_SIGS
	sigignore(SIGHUP);
#endif
	if (edit) {
		if (setjmp(srbuf))
			exit(rpterr);
		edstop(0);
	} else {
		if (issysmbox)
			Verhogen();
		if (value("exit") != NOSTR)
			exit(1);
		else
			quit(0);
	}
	exit(rpterr);
}

/*
 * Set the size of the message vector used to construct argument
 * lists to message list functions.
 */

static void
setmsize(int sz)
{

	if (msgvec != (int *)0)
		free(msgvec);
	if (sz < 1)
		sz = 1; /* need at least one cell for terminating 0 */
	if ((msgvec = (int *)
	    calloc((unsigned)(sz + 1), sizeof (*msgvec))) == NULL)
		panic("Failed to allocate memory for message vector");
}

/*
 * Find the correct command in the command table corresponding
 * to the passed command "word"
 */

static const struct cmd *
lex(char word[])
{
	register const struct cmd *cp;

	for (cp = &cmdtab[0]; cp->c_name != NOSTR; cp++)
		if (isprefix(word, cp->c_name))
			return (cp);
	return (NONE);
}

/*
 * Determine if as1 is a valid prefix of as2.
 */
static int
isprefix(char *as1, char *as2)
{
	register char *s1, *s2;

	s1 = as1;
	s2 = as2;
	while (*s1++ == *s2)
		if (*s2++ == '\0')
			return (1);
	return (*--s1 == '\0');
}

/*
 * The following gets called on receipt of a rubout.  This is
 * to abort printout of a command, mainly.
 * Dispatching here when command() is inactive crashes rcv.
 * Close all open files except 0, 1, 2, and the temporary.
 * The special call to getuserid() is needed so it won't get
 * annoyed about losing its open file.
 * Also, unstack all source files.
 */

static int	inithdr;		/* am printing startup headers */

void
stop(int s)
{
	register NODE *head;

	noreset = 0;
	if (!inithdr)
		sawcom++;
	inithdr = 0;
	while (sourcing)
		unstack();
	(void) getuserid((char *)0);
	for (head = fplist; head != (NODE *)NULL; head = head->next) {
		if (head->fp == stdin || head->fp == stdout)
			continue;
		if (head->fp == itf || head->fp == otf)
			continue;
		if (head->fp == stderr)
			continue;
		if (head->fp == semfp)
			continue;
		if (head->fp == pipef) {
			npclose(pipef);
			pipef = NULL;
			continue;
		}
		fclose(head->fp);
	}
	if (image >= 0) {
		close(image);
		image = -1;
	}
	if (s) {
		fprintf(stderr, gettext("Interrupt\n"));
		fflush(stderr);
#ifdef OLD_BSD_SIGS
		sigrelse(s);
#endif
	}
	longjmp(srbuf, 1);
}

/*
 * Announce the presence of the current mailx version,
 * give the message count, and print a header listing.
 */

#define	GREETING	"%s  Type ? for help.\n"

void
announce(void)
{
	int vec[2], mdot;
	extern const char *const version;

	if (!Hflag && value("quiet") == NOSTR)
		printf(gettext(GREETING), version);
	mdot = newfileinfo(1);
	vec[0] = mdot;
	vec[1] = 0;
	dot = &message[mdot - 1];
	if (msgCount > 0 && !noheader) {
		inithdr++;
		headers(vec);
		inithdr = 0;
	}
}

/*
 * Announce information about the file we are editing.
 * Return a likely place to set dot.
 */
int
newfileinfo(int start)
{
	register struct message *mp;
	register int u, n, mdot, d, s;
	char fname[BUFSIZ], zname[BUFSIZ], *ename;

	if (Hflag)
		return (1);		/* fake it--return message 1 */
	for (mp = &message[start - 1]; mp < &message[msgCount]; mp++)
		if ((mp->m_flag & (MNEW|MREAD)) == MNEW)
			break;
	if (mp >= &message[msgCount])
		for (mp = &message[start - 1]; mp < &message[msgCount]; mp++)
			if ((mp->m_flag & MREAD) == 0)
				break;
	if (mp < &message[msgCount])
		mdot = mp - &message[0] + 1;
	else
		mdot = 1;
	n = u = d = s = 0;
	for (mp = &message[start - 1]; mp < &message[msgCount]; mp++) {
		if (mp->m_flag & MNEW)
			n++;
		if ((mp->m_flag & MREAD) == 0)
			u++;
		if (mp->m_flag & MDELETED)
			d++;
		if (mp->m_flag & MSAVED)
			s++;
	}
	ename = origname;
	if (getfold(fname) >= 0) {
		nstrcat(fname, sizeof (fname), "/");
		if (strncmp(fname, editfile, strlen(fname)) == 0) {
			snprintf(zname, sizeof (zname),
				"+%s", editfile + strlen(fname));
			ename = zname;
		}
	}
	printf("\"%s\": ", ename);
	if (msgCount == 1)
		printf(gettext("1 message"));
	else
		printf(gettext("%d messages"), msgCount);
	if (n > 0)
		printf(gettext(" %d new"), n);
	if (u-n > 0)
		printf(gettext(" %d unread"), u);
	if (d > 0)
		printf(gettext(" %d deleted"), d);
	if (s > 0)
		printf(gettext(" %d saved"), s);
	if (readonly)
		printf(gettext(" [Read only]"));
	printf("\n");
	return (mdot);
}

/*
 * Print the current version number.
 */

int
#ifdef	__cplusplus
pversion(char *)
#else
/* ARGSUSED */
pversion(char *s)
#endif
{
	printf("%s\n", version);
	return (0);
}

/*
 * Load a file of user definitions.
 */
void
load(char *name)
{
	register FILE *in, *oldin;

	if ((in = fopen(name, "r")) == NULL)
		return;
	oldin = input;
	input = in;
	loading = 1;
	sourcing = 1;
	commands();
	loading = 0;
	sourcing = 0;
	input = oldin;
	fclose(in);
}

/*
 * Incorporate any new mail into the current session.
 *
 * XXX - Since autoinc works on "edited" files as well as the
 * system mailbox, this probably ought to as well.
 */

int
inc(void)
{
	FILE *ibuf;
	int mdot;
	struct stat stbuf;
	int firstnewmsg = msgCount + 1;

	if (edit) {
		fprintf(stderr, gettext("Not in system mailbox\n"));
		return (-1);
	}
	if (((ibuf = fopen(mailname, "r")) == NULL) ||
	    (fstat(fileno(ibuf), &stbuf) < 0) || stbuf.st_size == 0L ||
	    stbuf.st_size == mailsize || (stbuf.st_mode&S_IFMT) != S_IFREG) {
		if (strrchr(mailname, '/') == NOSTR)
			fprintf(stderr, gettext("No new mail.\n"));
		else
			fprintf(stderr, gettext("No new mail for %s\n"),
			    strrchr(mailname, '/')+1);
		if (ibuf != NULL)
			fclose(ibuf);
		return (-1);
	}

	fseek(otf, 0L, 2);
	holdsigs();
	if (issysmbox)
		lockmail();
	fseek(ibuf, mailsize, 0);
	mailsize = fsize(ibuf);
	setptr(ibuf);
	setmsize(msgCount);
	fclose(ibuf);
	if (issysmbox)
		unlockmail();
	relsesigs();
	mdot = newfileinfo(firstnewmsg);
	dot = &message[mdot - 1];
	sawcom = 0;
	return (0);
}
