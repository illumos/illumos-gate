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
 * Copyright (c) 1985, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Collect input from standard input, handling
 * ~ escapes.
 */

#include "rcv.h"
#include <locale.h>

#ifdef SIGCONT
static void	collcont(int);
#endif
static void	collrub(int s);
static void	cpout(char *str, FILE *ofd);
static int	exwrite(char name[], FILE *ibuf);
static int	forward(char ms[], FILE *obuf, int f);
static void	intack(int);
static int	forward(char ms[], FILE *obuf, int f);
static FILE	*mesedit(FILE *ibuf, FILE *obuf, int c, struct header *hp);
static FILE	*mespipe(FILE *ibuf, FILE *obuf, char cmd[]);
static void	resetsigs(int resethup);
static int	stripnulls(char *linebuf, int nread);
static void	xhalt(void);
static char	**Xaddone(char **hf, char news[]);
static int	tabputs(const char *line, FILE *obuf);

/*
 * Read a message from standard output and return a read file to it
 * or NULL on error.
 */

/*
 * The following hokiness with global variables is so that on
 * receipt of an interrupt signal, the partial message can be salted
 * away on dead.letter.  The output file must be available to flush,
 * and the input to read.  Several open files could be saved all through
 * mailx if stdio allowed simultaneous read/write access.
 */

static void		(*savesig)(int);	/* Previous SIGINT value */
static void		(*savehup)(int);	/* Previous SIGHUP value */
#ifdef SIGCONT
static void		(*savecont)(int);	/* Previous SIGCONT value */
#endif
static FILE		*newi;		/* File for saving away */
static FILE		*newo;		/* Output side of same */
static int		ignintr;	/* Ignore interrups */
static int		hadintr;	/* Have seen one SIGINT so far */
static struct header	*savehp;
static jmp_buf		coljmp;		/* To get back to work */

FILE *
collect(struct header *hp)
{
	FILE *ibuf, *fbuf, *obuf;
	int escape, eof;
	long lc, cc;
	int c, t;
	int hdrs;
	char linebuf[LINESIZE+1], *cp;
	char *iprompt;
	int inhead;
	void (*sigpipe)(int), (*sigint)(int);
	int fd = -1;

	noreset++;
	ibuf = obuf = NULL;
	newi = newo = NULL;
	if ((fd = open(tempMail, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(obuf = fdopen(fd, "w")) == NULL) {
		perror(tempMail);
		goto err;
	}
	newo = obuf;
	if ((ibuf = fopen(tempMail, "r")) == NULL) {
		perror(tempMail);
		newo = NULL;
		fclose(obuf);
		goto err;
	}
	newi = ibuf;
	removefile(tempMail);

	ignintr = (int)value("ignore");
	hadintr = 1;
	inhead = 1;
	savehp = hp;
# ifdef VMUNIX
	if ((savesig = sigset(SIGINT, SIG_IGN)) != SIG_IGN)
		sigset(SIGINT, ignintr ? intack : collrub), sigblock(sigmask(SIGINT));
	if ((savehup = sigset(SIGHUP, SIG_IGN)) != SIG_IGN)
		sigset(SIGHUP, collrub), sigblock(sigmask(SIGHUP));
# else /* VMUNIX */
# ifdef OLD_BSD_SIGS
	if ((savesig = sigset(SIGINT, SIG_IGN)) != SIG_IGN)
		sigset(SIGINT, ignintr ? intack : collrub);
	if ((savehup = sigset(SIGHUP, SIG_IGN)) != SIG_IGN)
		sigset(SIGHUP, collrub);
# else
	if ((savesig = sigset(SIGINT, SIG_IGN)) != SIG_IGN) {
		sigset_t mask;

		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigset(SIGINT, ignintr ? intack : collrub);
		sigprocmask(SIG_BLOCK, &mask, NULL);
	}
	if ((savehup = sigset(SIGHUP, SIG_IGN)) != SIG_IGN) {
		sigset_t mask;

		sigemptyset(&mask);
		sigaddset(&mask, SIGHUP);
		sigset(SIGHUP, collrub);
		sigprocmask(SIG_BLOCK, &mask, NULL);
	}
# endif
# endif /* VMUNIX */
#ifdef SIGCONT
	savecont = sigset(SIGCONT, collcont);
#endif
	/*
	 * If we are going to prompt for subject/cc/bcc,
	 * refrain from printing a newline after
	 * the headers (since some people mind).
	 */

	if (hp->h_subject == NOSTR) {
		hp->h_subject = sflag;
		sflag = NOSTR;
	}
	if (hp->h_cc == NOSTR) {
		hp->h_cc = cflag;
		cflag = NOSTR;
	}
	if (hp->h_bcc == NOSTR) {
		hp->h_bcc = bflag;
		bflag = NOSTR;
	}
	t = GMASK;
	hdrs = 0;
	if (intty && !tflag) {
		if (hp->h_to == NOSTR)
			hdrs |= GTO;
		if (hp->h_subject == NOSTR && value("asksub"))
			hdrs |= GSUBJECT;
		if (hp->h_cc == NOSTR && value("askcc"))
			hdrs |= GCC;
		if (hp->h_bcc == NOSTR && value("askbcc"))
			hdrs |= GBCC;
		if (hdrs)
			t &= ~GNL;
	}
	if (hp->h_seq != 0) {
		puthead(hp, stdout, t, 0);
		fflush(stdout);
	}
	if (setjmp(coljmp))
		goto err;
	escape = SENDESC;
	if ((cp = value("escape")) != NOSTR)
		escape = *cp;
	eof = 0;
	if ((cp = value("MAILX_HEAD")) != NOSTR) {
	      cpout( cp, obuf);
	      if (isatty(fileno(stdin)))
		    cpout( cp, stdout);
	}
	iprompt = value("iprompt");
	fflush(obuf);
	hadintr = 0;
	for (;;) {
		int nread, hasnulls;
# ifdef VMUNIX
		int omask = sigblock(0) &~ (sigmask(SIGINT)|sigmask(SIGHUP));
# else
# ifndef OLD_BSD_SIGS
		sigset_t omask;
		sigprocmask(0, NULL, &omask);
		sigdelset(&omask, SIGINT);
		sigdelset(&omask, SIGHUP);
# endif
# endif

		setjmp(coljmp);
# ifdef VMUNIX
		sigsetmask(omask);
# else /* VMUNIX */
# ifdef OLD_BSD_SIGS
		sigrelse(SIGINT);
		sigrelse(SIGHUP);
# else
		sigprocmask(SIG_SETMASK, &omask, NULL);
# endif
# endif /* VMUNIX */
		if (intty && !tflag && outtty && iprompt)
			fputs(iprompt, stdout);
		flush();
		if (hdrs) {
			grabh(hp, hdrs, 1);
			hdrs = 0;
			continue;
		}
		if ((nread = getaline(linebuf,LINESIZE,stdin,&hasnulls)) == 0) {
			if (intty && value("ignoreeof") != NOSTR) {
				if (++eof > 35)
					break;
				printf(gettext(
				    "Use \".\" to terminate letter\n"));
				continue;
			}
			break;
		}
		eof = 0;
		hadintr = 0;
		if (intty && equal(".\n", linebuf) &&
		    (value("dot") != NOSTR || value("ignoreeof") != NOSTR))
			break;
		/*
		 * If -t, scan text for headers.
		 */
		if (tflag) {
			char *cp2;

			if (!inhead) {
			writeit:
				if (write(fileno(obuf),linebuf,nread) != nread)
					goto werr;
				continue;
			}
			if (linebuf[0] == '\n') {
				/* got blank line after header, ignore it */
				inhead = 0;
				continue;
			}
			if (!headerp(linebuf)) {
				/* got non-header line, save it */
				inhead = 0;
				goto writeit;
			}
			if (hasnulls)
				nread = stripnulls(linebuf, nread);
			for (;;) {
				char line2[LINESIZE];

				c = getc(stdin);
				ungetc(c, stdin);
				if (!isspace(c) || c == '\n')
					break;
				if (readline(stdin, line2) < 0)
					break;
				for (cp2 = line2; *cp2 != 0 && isspace(*cp2);
				    cp2++)
					;
				if (strlen(linebuf) + strlen(cp2) >=
				    (unsigned)LINESIZE-2)
					break;
				cp = &linebuf[strlen(linebuf)];
				while (cp > linebuf &&
				    (isspace(cp[-1]) || cp[-1] == '\\'))
					cp--;
				*cp++ = ' ';
				strcpy(cp, cp2);
			}
			if ((c = strlen(linebuf)) > 0) {
				cp = &linebuf[c-1];
				while (cp > linebuf && isspace(*cp))
					cp--;
				*++cp = 0;
			}
			if (ishfield(linebuf, "to"))
				hp->h_to = addto(hp->h_to, hcontents(linebuf));
			else if (ishfield(linebuf, "subject"))
				hp->h_subject =
				    addone(hp->h_subject, hcontents(linebuf));
			else if (ishfield(linebuf, "cc"))
				hp->h_cc = addto(hp->h_cc, hcontents(linebuf));
			else if (ishfield(linebuf, "bcc"))
				hp->h_bcc =
				    addto(hp->h_bcc, hcontents(linebuf));
			else if (ishfield(linebuf, "default-options"))
				hp->h_defopt =
				    addone(hp->h_defopt, hcontents(linebuf));
			else
				hp->h_others = Xaddone(hp->h_others, linebuf);
			hp->h_seq++;
			continue;
		}
		if ((linebuf[0] != escape) || (rflag != NOSTR) ||
		    (!intty && !(int)value("escapeok"))) {
			if (write(fileno(obuf),linebuf,nread) != nread)
				goto werr;
			continue;
		}
		/*
		 * On double escape, just send the single one.
		 */
		if ((nread > 1) && (linebuf[1] == escape)) {
			if (write(fileno(obuf),linebuf+1,nread-1) != (nread-1))
				goto werr;
			continue;
		}
		if (hasnulls)
			nread = stripnulls(linebuf, nread);
		c = linebuf[1];
		linebuf[nread - 1] = '\0';
		switch (c) {
		default:
			/*
			 * Otherwise, it's an error.
			 */
			printf(gettext("Unknown tilde escape.\n"));
			break;

		case 'a':
		case 'A':
			/*
			 * autograph; sign the letter.
			 */

			if (cp = value(c=='a' ? "sign":"Sign")) {
			      if (*cp)
			          cpout( cp, obuf);
			      if (isatty(fileno(stdin))) {
			          if (*cp)
				      cpout( cp, stdout);
			    }
			}

			break;

		case 'i':
			/*
			 * insert string
			 */
			for (cp = &linebuf[2]; any(*cp, " \t"); cp++)
				;
			if (*cp)
				cp = value(cp);
			if (cp != NOSTR) {
				if (*cp)
				    cpout(cp, obuf);
				if (isatty(fileno(stdout))) {
					if (*cp)
					    cpout(cp, stdout);
				}
			}
			break;

		case '!':
			/*
			 * Shell escape, send the balance of the
			 * line to sh -c.
			 */

			shell(&linebuf[2]);
			break;

		case ':':
		case '_':
			/*
			 * Escape to command mode, but be nice!
			 */

			execute(&linebuf[2], 1);
			iprompt = value("iprompt");
			if (cp = value("escape"))
				escape = *cp;
			printf(gettext("(continue)\n"));
			break;

		case '.':
			/*
			 * Simulate end of file on input.
			 */
			goto eofl;

		case 'q':
		case 'Q':
			/*
			 * Force a quit of sending mail.
			 * Act like an interrupt happened.
			 */

			hadintr++;
			collrub(SIGINT);
			exit(1);
			/* NOTREACHED */

		case 'x':
			xhalt();
			break; 	/* not reached */

		case 'h':
			/*
			 * Grab a bunch of headers.
			 */
			if (!intty || !outtty) {
				printf(gettext("~h: no can do!?\n"));
				break;
			}
			grabh(hp, GMASK, (int)value("bsdcompat"));
			printf(gettext("(continue)\n"));
			break;

		case 't':
			/*
			 * Add to the To list.
			 */

			hp->h_to = addto(hp->h_to, &linebuf[2]);
			hp->h_seq++;
			break;

		case 's':
			/*
			 * Set the Subject list.
			 */

			cp = &linebuf[2];
			while (any(*cp, " \t"))
				cp++;
			hp->h_subject = savestr(cp);
			hp->h_seq++;
			break;

		case 'c':
			/*
			 * Add to the CC list.
			 */

			hp->h_cc = addto(hp->h_cc, &linebuf[2]);
			hp->h_seq++;
			break;

		case 'b':
			/*
			 * Add stuff to blind carbon copies list.
			 */
			hp->h_bcc = addto(hp->h_bcc, &linebuf[2]);
			hp->h_seq++;
			break;

		case 'R':
			hp->h_defopt = addone(hp->h_defopt, myname);
			hp->h_seq++;
			fprintf(stderr, gettext("Return receipt marked.\n"));
			receipt_flg = 1;
			break;

		case 'd':
			copy(Getf("DEAD"), &linebuf[2]);
			/* FALLTHROUGH */

		case '<':
		case 'r': {
			int	ispip;
			/*
			 * Invoke a file:
			 * Search for the file name,
			 * then open it and copy the contents to obuf.
			 *
			 * if name begins with '!', read from a command
			 */

			cp = &linebuf[2];
			while (any(*cp, " \t"))
				cp++;
			if (*cp == '\0') {
				printf(gettext("Interpolate what file?\n"));
				break;
			}
			if (*cp=='!') {
				/* take input from a command */
				ispip = 1;
				if ((fbuf = npopen(++cp, "r"))==NULL) {
					perror("");
					break;
				}
				sigint = sigset(SIGINT, SIG_IGN);
			} else {
				ispip = 0;
				cp = expand(cp);
				if (cp == NOSTR)
					break;
				if (isdir(cp)) {
					printf(gettext("%s: directory\n"), cp);
					break;
				}
				if ((fbuf = fopen(cp, "r")) == NULL) {
					perror(cp);
					break;
				}
			}
			printf("\"%s\" ", cp);
			flush();
			lc = cc = 0;
			while ((t = getc(fbuf)) != EOF) {
				if (t == '\n')
					lc++;
				if (putc(t, obuf) == EOF) {
					if (ispip) {
						npclose(fbuf);
						sigset(SIGINT, sigint);
					} else
						fclose(fbuf);
					goto werr;
				}
				cc++;
			}
			if (ispip) {
				npclose(fbuf);
				sigset(SIGINT, sigint);
			} else
				fclose(fbuf);
			printf("%ld/%ld\n", lc, cc);
			fflush(obuf);
			break;
			}

		case 'w':
			/*
			 * Write the message on a file.
			 */

			cp = &linebuf[2];
			while (any(*cp, " \t"))
				cp++;
			if (*cp == '\0') {
				fprintf(stderr, gettext("Write what file!?\n"));
				break;
			}
			if ((cp = expand(cp)) == NOSTR)
				break;
			fflush(obuf);
			rewind(ibuf);
			exwrite(cp, ibuf);
			break;

		case 'm':
		case 'M':
		case 'f':
		case 'F':
			/*
			 * Interpolate the named messages, if we
			 * are in receiving mail mode.  Does the
			 * standard list processing garbage.
			 * If ~f or ~F is given, we don't shift over.
			 */

			if (!rcvmode) {
				printf(gettext(
				    "No messages to send from!?!\n"));
				break;
			}
			cp = &linebuf[2];
			while (any(*cp, " \t"))
				cp++;
			if (forward(cp, obuf, c) < 0)
				goto werr;
			fflush(obuf);
			printf(gettext("(continue)\n"));
			break;

		case '?':
			if ((fbuf = fopen(THELPFILE, "r")) == NULL) {
				printf(gettext("No help just now.\n"));
				break;
			}
			t = getc(fbuf);
			while (t != -1) {
				putchar(t);
				t = getc(fbuf);
			}
			fclose(fbuf);
			break;

		case 'p': {
			/*
			 * Print out the current state of the
			 * message without altering anything.
			 */
			int nlines;
			extern jmp_buf pipestop;
			extern void brokpipe(int);

			fflush(obuf);
			rewind(ibuf);
			fbuf = stdout;
			if (setjmp(pipestop))
				goto ret0;
			if (intty && outtty && (cp = value("crt")) != NOSTR) {
				nlines =
				    (*cp == '\0' ? screensize() : atoi(cp)) - 7;
				    /* 7 for hdr lines */
				while ((t = getc(ibuf)) != EOF) {
					if (t == '\n')
						if (--nlines <= 0)
							break;
				}
				rewind(ibuf);
				if (nlines <= 0) {
					fbuf = npopen(MORE, "w");
					if (fbuf == NULL) {
						perror(MORE);
						fbuf = stdout;
					} else {
						sigint = sigset(SIGINT, SIG_IGN);
						sigpipe = sigset(SIGPIPE, brokpipe);
					}
				}
			}
			fprintf(fbuf, gettext("-------\nMessage contains:\n"));
			puthead(hp, fbuf, GMASK, 0);
			while ((t = getc(ibuf))!=EOF)
				putc(t, fbuf);
		ret0:
			if (fbuf != stdout) {
				npclose(fbuf);
				sigset(SIGPIPE, sigpipe);
				sigset(SIGINT, sigint);
			}
			printf(gettext("(continue)\n"));
			break;
		}

		case '^':
		case '|':
			/*
			 * Pipe message through command.
			 * Collect output as new message.
			 */

			obuf = mespipe(ibuf, obuf, &linebuf[2]);
			newo = obuf;
			ibuf = newi;
			newi = ibuf;
			printf(gettext("(continue)\n"));
			break;

		case 'v':
		case 'e':
			/*
			 * Edit the current message.
			 * 'e' means to use EDITOR
			 * 'v' means to use VISUAL
			 */

			if ((obuf = mesedit(ibuf, obuf, c, hp)) == NULL)
				goto err;
			newo = obuf;
			ibuf = newi;
			printf(gettext("(continue)\n"));
			break;
		}
		fflush(obuf);
	}
eofl:
	fflush(obuf);
	if ((cp = value("MAILX_TAIL")) != NOSTR) {
	      cpout( cp, obuf);
	      if (isatty(fileno(stdin)))
		    cpout( cp, stdout);
	}
	fclose(obuf);
	rewind(ibuf);
	resetsigs(0);
	noreset = 0;
	return(ibuf);

werr:
	/*
	 * Write error occurred on tmp file, save partial
	 * message in dead.letter.
	 */
	perror(tempMail);
	fflush(obuf);
	rewind(ibuf);
	if (fsize(ibuf) > 0) {
		char *deadletter;

		deadletter = Getf("DEAD");
		fprintf(stderr, gettext("Saving partial message in %s\n"),
		    deadletter);
		if ((fbuf = fopen(deadletter,
		    value("appenddeadletter") == NOSTR ? "w" : "a")) != NULL) {
			chmod(deadletter, DEADPERM);
			puthead(hp, fbuf, GMASK|GCLEN, fsize(ibuf));
			lcwrite(deadletter, ibuf, fbuf, value("appenddeadletter") != NOSTR);
			fclose(fbuf);
		} else
			perror(deadletter);
	}

err:
	if (ibuf != NULL)
		fclose(ibuf);
	if (obuf != NULL)
		fclose(obuf);
	resetsigs(0);
	noreset = 0;
	return(NULL);
}

static void 
resetsigs(int resethup)
{
	(void) sigset(SIGINT, savesig);
	if (resethup)
		(void) sigset(SIGHUP, savehup);
#ifdef SIGCONT
# ifdef preSVr4
	(void) sigset(SIGCONT, savecont);
# else
	{
	struct sigaction nsig;
	nsig.sa_handler = (void (*)())savecont;
	sigemptyset(&nsig.sa_mask);
	nsig.sa_flags = SA_RESTART;
	(void) sigaction(SIGCONT, &nsig, (struct sigaction*)0);
	}
# endif
#endif
}

/*
 * Write a file ex-like.
 */

static int
exwrite(char name[], FILE *ibuf)
{
	FILE *of;
	struct stat junk;
	void (*sigint)(int), (*sigpipe)(int);
	int pi = (*name == '!');

	if ((of = pi ? npopen(++name, "w") : fopen(name, "a")) == NULL) {
		perror(name);
		return(-1);
	}
	if (pi) {
		sigint = sigset(SIGINT, SIG_IGN);
		sigpipe = sigset(SIGPIPE, SIG_IGN);
	}
	lcwrite(name, ibuf, of, 0);
	pi ? npclose(of) : fclose(of);
	if (pi) {
		sigset(SIGPIPE, sigpipe);
		sigset(SIGINT, sigint);
	}
	return(0);
}

void
lcwrite(char *fn, FILE *fi, FILE *fo, int addnl)
{
	int c;
	long lc, cc;

	printf("\"%s\" ", fn);
	fflush(stdout);
	lc = cc = 0;
	while ((c = getc(fi)) != EOF) {
		cc++;
		if (putc(c, fo) == '\n')
			lc++;
		if (ferror(fo)) {
			perror("");
			return;
		}
	}
	if (addnl) {
		putc('\n', fo);
		lc++;
		cc++;
	}
	fflush(fo);
	if (fferror(fo)) {
		perror("");
		return;
	}
	printf("%ld/%ld\n", lc, cc);
	fflush(stdout);
}

/*
 * Edit the message being collected on ibuf and obuf.
 * Write the message out onto some poorly-named temp file
 * and point an editor at it.
 *
 * On return, make the edit file the new temp file.
 */

static FILE *
mesedit(FILE *ibuf, FILE *obuf, int c, struct header *hp)
{
	pid_t pid;
	FILE *fbuf;
	int t;
	void (*sigint)(int);
#ifdef SIGCONT
	void (*sigcont)(int);
#endif
	struct stat sbuf;
	char *edit;
	char hdr[LINESIZE];
	char *oto, *osubject, *occ, *obcc, **oothers;
	int fd = -1;

	if (stat(tempEdit, &sbuf) >= 0) {
		printf(gettext("%s: file exists\n"), tempEdit);
		goto out;
	}
	if ((fd = open(tempEdit, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(fbuf = fdopen(fd, "w")) == NULL) {
		perror(tempEdit);
		goto out;
	}
	fflush(obuf);
	rewind(ibuf);
	puthead(hp, fbuf, GMASK, 0);
	while ((t = getc(ibuf)) != EOF)
		putc(t, fbuf);
	fflush(fbuf);
	if (fferror(fbuf)) {
		perror(tempEdit);
		removefile(tempEdit);
		goto out;
	}
	fclose(fbuf);
	if ((edit = value(c == 'e' ? "EDITOR" : "VISUAL")) == NOSTR ||
	    *edit == '\0')
		edit = c == 'e' ? EDITOR : VISUAL;
	edit = safeexpand(edit);

	/*
	 * Fork/execlp the editor on the edit file
	*/

	pid = vfork();
	if (pid == (pid_t)-1) {
		perror("fork");
		removefile(tempEdit);
		goto out;
	}
	if (pid == 0) {
		char ecmd[BUFSIZ];
		char *Shell;

		sigchild();
		execlp(edit, edit, tempEdit, (char *)0);
		/*
		 * If execlp fails, "edit" might really be a complete
		 * shell command, not a simple pathname.  Try using
		 * the shell to run it.
		 */
		snprintf(ecmd, sizeof (ecmd), "exec %s %s", edit, tempEdit);
		if ((Shell = value("SHELL")) == NULL || *Shell=='\0')
			Shell = SHELL;
		execlp(Shell, Shell, "-c", ecmd, NULL);
		perror(edit);
		_exit(1);
	}
	sigint = sigset(SIGINT, SIG_IGN);
#ifdef SIGCONT
	sigcont = sigset(SIGCONT, SIG_DFL);
#endif
	while (wait((int *)0) != pid)
		;
	sigset(SIGINT, sigint);
#ifdef SIGCONT
	sigset(SIGCONT, sigcont);
#endif
	/*
	 * Now switch to new file.
	 */

	if ((fbuf = fopen(tempEdit, "r")) == NULL) {
		perror(tempEdit);
		removefile(tempEdit);
		goto out;
	}
	removefile(tempEdit);

	/* save the old headers, in case they are accidentally deleted */
	osubject = hp->h_subject;
	oto = hp->h_to;
	occ = hp->h_cc;
	obcc = hp->h_bcc;
	oothers = hp->h_others;
	hp->h_to = hp->h_subject = hp->h_cc = hp->h_bcc = hp->h_defopt = NOSTR;
	hp->h_others = NOSTRPTR;
	hp->h_seq = 0;
	while (gethfield(fbuf, hdr, 9999L) > 0) {
		if (ishfield(hdr, "to"))
			hp->h_to = addto(hp->h_to, hcontents(hdr));
		else if (ishfield(hdr, "subject"))
			hp->h_subject = addone(hp->h_subject, hcontents(hdr));
		else if (ishfield(hdr, "cc"))
			hp->h_cc = addto(hp->h_cc, hcontents(hdr));
		else if (ishfield(hdr, "bcc"))
			hp->h_bcc = addto(hp->h_bcc, hcontents(hdr));
		else if (ishfield(hdr, "default-options"))
			hp->h_defopt = addone(hp->h_defopt, hcontents(hdr));
		else
			hp->h_others = Xaddone(hp->h_others, hdr);
		hp->h_seq++;
	}
	if (hp->h_seq == 0) {
		/* if we didn't see any headers, restore the original headers */
		hp->h_subject = osubject;
		hp->h_to = oto;
		hp->h_cc = occ;
		hp->h_bcc = obcc;
		hp->h_others = oothers;
		printf(gettext(
		    "(Deleted headers restored to original values)\n"));
	}
	if ((fd = open(tempMail, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(obuf = fdopen(fd, "w")) == NULL) {
		perror(tempMail);
		fclose(fbuf);
		goto out;
	}
	if ((ibuf = fopen(tempMail, "r")) == NULL) {
		perror(tempMail);
		removefile(tempMail);
		fclose(fbuf);
		fclose(obuf);
		goto out;
	}
	removefile(tempMail);
	if (strlen(hdr) != 0) {
		fputs(hdr, obuf);
		putc('\n', obuf);
	}
	while ((t = getc(fbuf)) != EOF)
		putc(t, obuf);
	fclose(fbuf);
	fclose(newo);
	fclose(newi);
	newo = obuf;
	newi = ibuf;
out:
	return(newo);
}

/*
 * Pipe the message through the command.
 * Old message is on stdin of command;
 * New message collected from stdout.
 * Sh -c must return 0 to accept the new message.
 */

static FILE *
mespipe(FILE *ibuf, FILE *obuf, char cmd[])
{
	FILE *ni, *no;
	pid_t pid;
	int s;
	void (*sigint)(int);
	char *Shell;
	int fd = -1;

	newi = ibuf;
	if ((fd = open(tempEdit, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(no = fdopen(fd, "w")) == NULL) {
		perror(tempEdit);
		return(obuf);
	}
	if ((ni = fopen(tempEdit, "r")) == NULL) {
		perror(tempEdit);
		fclose(no);
		removefile(tempEdit);
		return(obuf);
	}
	removefile(tempEdit);
	fflush(obuf);
	rewind(ibuf);
	if ((Shell = value("SHELL")) == NULL || *Shell=='\0')
		Shell = SHELL;
	if ((pid = vfork()) == (pid_t)-1) {
		perror("fork");
		goto err;
	}
	if (pid == 0) {
		/*
		 * stdin = current message.
		 * stdout = new message.
		 */

		sigchild();
		close(0);
		dup(fileno(ibuf));
		close(1);
		dup(fileno(no));
		for (s = 4; s < 15; s++)
			close(s);
		execlp(Shell, Shell, "-c", cmd, (char *)0);
		perror(Shell);
		_exit(1);
	}
	sigint = sigset(SIGINT, SIG_IGN);
	while (wait(&s) != pid)
		;
	sigset(SIGINT, sigint);
	if (s != 0 || pid == (pid_t)-1) {
		fprintf(stderr, gettext("\"%s\" failed!?\n"), cmd);
		goto err;
	}
	if (fsize(ni) == 0) {
		fprintf(stderr, gettext("No bytes from \"%s\" !?\n"), cmd);
		goto err;
	}

	/*
	 * Take new files.
	 */

	newi = ni;
	fclose(ibuf);
	fclose(obuf);
	return(no);

err:
	fclose(no);
	fclose(ni);
	return(obuf);
}

static char *indentprefix;	/* used instead of tab by tabputs */

/*
 * Interpolate the named messages into the current
 * message, preceding each line with a tab.
 * Return a count of the number of characters now in
 * the message, or -1 if an error is encountered writing
 * the message temporary.  The flag argument is 'm' if we
 * should shift over and 'f' if not.
 */
static int
forward(char ms[], FILE *obuf, int f)
{
	int *msgvec, *ip;

	msgvec = (int *) salloc((msgCount+1) * sizeof *msgvec);
	if (msgvec == NOINTPTR)
		return(0);
	if (getmsglist(ms, msgvec, 0) < 0)
		return(0);
	if (*msgvec == 0) {
		*msgvec = first(0, MMNORM);
		if (*msgvec == 0) {
			printf(gettext("No appropriate messages\n"));
			return(0);
		}
		msgvec[1] = 0;
	}
	if (tolower(f) == 'm')
		indentprefix = value("indentprefix");
	printf(gettext("Interpolating:"));
	for (ip = msgvec; *ip != 0; ip++) {
		touch(*ip);
		printf(" %d", *ip);
		if (msend(&message[*ip-1], obuf, islower(f) ? M_IGNORE : 0,
		    tolower(f) == 'm' ? tabputs : fputs) < 0) {
			perror(tempMail);
			return(-1);
		}
	}
	fflush(obuf);
	if (fferror(obuf)) {
		perror(tempMail);
		return(-1);
	}
	printf("\n");
	return(0);
}

static int
tabputs(const char *line, FILE *obuf)
{

	if (indentprefix)
		fputs(indentprefix, obuf);
	/* Don't create lines with only a tab on them */
	else if (line[0] != '\n')
		fputc('\t', obuf);
	return (fputs(line, obuf));
}

/*
 * Print (continue) when continued after ^Z.
 */
#ifdef SIGCONT
static void 
#ifdef	__cplusplus
collcont(int)
#else
/* ARGSUSED */
collcont(int s)
#endif
{
	printf(gettext("(continue)\n"));
	fflush(stdout);
}
#endif /* SIGCONT */

/*
 * On interrupt, go here to save the partial
 * message on ~/dead.letter.
 * Then restore signals and execute the normal
 * signal routine.  We only come here if signals
 * were previously set anyway.
 */
static void 
collrub(int s)
{
	FILE *dbuf;
	char *deadletter;

# ifdef OLD_BSD_SIGS
	if (s == SIGHUP)
		sigignore(SIGHUP);
# endif
	if (s == SIGINT && hadintr == 0) {
		hadintr++;
		fflush(stdout);
		fprintf(stderr,
		    gettext("\n(Interrupt -- one more to kill letter)\n"));
# ifdef OLD_BSD_SIGS
		sigrelse(s);
# endif
		longjmp(coljmp, 1);
	}
	fclose(newo);
	rewind(newi);
	if (s == SIGINT && value("save")==NOSTR || fsize(newi) == 0)
		goto done;
	deadletter = Getf("DEAD");
	if ((dbuf = fopen(deadletter,
	    (value("appenddeadletter") == NOSTR ? "w" : "a"))) == NULL) {
		perror(deadletter);
		goto done;
	}
	chmod(deadletter, DEADPERM);
	puthead(savehp, dbuf, GMASK|GCLEN, fsize(newi));
	lcwrite(deadletter, newi, dbuf, value("appenddeadletter") != NOSTR);
	fclose(dbuf);
done:
	fclose(newi);
	resetsigs(1);
	if (rcvmode) {
		if (s == SIGHUP)
			hangup(s);
		else
			stop(s);
	}
	else
		exit(1);
}

/*
 * Acknowledge an interrupt signal from the tty by typing an @
 */
static void 
#ifdef	__cplusplus
intack(int)
#else
/* ARGSUSED */
intack(int s)
#endif
{

	puts("@");
	fflush(stdout);
	clearerr(stdin);
	longjmp(coljmp,1);
}

/* Read line from stdin, noting any NULL characters.
   Return the number of characters read. Note that the buffer
   passed must be 1 larger than "size" for the trailing NUL byte.
 */
int
getaline(char *line, int size, FILE *f, int *hasnulls)
{
	int i, ch;
	for (i = 0; (i < size) && ((ch=getc(f)) != EOF); ) {
		if ( ch == '\0' )
			*hasnulls = 1;
		if ((line[i++] = (char)ch) == '\n') break;
	}
	line[i] = '\0';
	return(i);
}

void 
#ifdef	__cplusplus
savedead(int)
#else
/* ARGSUSED */
savedead(int s)
#endif
{
	collrub(SIGINT);
	exit(1);
	/* NOTREACHED */
}

/*
 * Add a list of addresses to the end of a header entry field.
 */
char *
addto(char hf[], char news[])
{
	char name[LINESIZE];
	int comma = docomma(news);

	while (news = yankword(news, name, sizeof (name), comma)) {
		nstrcat(name, sizeof (name), ", ");
		hf = addone(hf, name);
	}
	return hf;
}

/*
 * Add a string to the end of a header entry field.
 */
char *
addone(char hf[], char news[])
{
	char *cp, *cp2, *linebuf;

	if (hf == NOSTR)
		hf = savestr("");
	if (*news == '\0')
		return(hf);
	linebuf = (char *)srealloc(hf, (unsigned)(strlen(hf) + strlen(news) + 2));
	cp2 = strchr(linebuf, '\0');
	if (cp2 > linebuf && cp2[-1] != ' ')
		*cp2++ = ' ';
	for (cp = news; any(*cp, " \t"); cp++)
		;
	while (*cp != '\0')
		*cp2++ = *cp++;
	*cp2 = '\0';
	return(linebuf);
}

static int 
nptrs(char **hf)
{
	int i;

	if (!hf)
		return(0);
	for (i = 0; *hf; hf++)
		i++;
	return(i);
}

/*
 * Add a non-standard header to the end of the non-standard headers.
 */
static char **
Xaddone(char **hf, char news[])
{
	char *linebuf;
	char **ohf = hf;
	int nhf = nptrs(hf);

	if (hf == NOSTRPTR)
		hf = (char**)salloc(sizeof(char*) * 2);
	else
		hf = (char**)srealloc(hf, sizeof(char*) * (nhf + 2));
	if (hf == NOSTRPTR) {
		fprintf(stderr, gettext("No room, header lost: %s\n"), news);
		return(ohf);
	}
	linebuf = (char *)salloc((unsigned)(strlen(news) + 1));
	strcpy(linebuf, news);
	hf[nhf++] = linebuf;
	hf[nhf] = NOSTR;
	return(hf);
}

static void
cpout(char *str, FILE *ofd)
{
	char *cp = str;

	while (*cp) {
		if (*cp == '\\') {
			switch (*(cp+1)) {
			case 'n':
				putc('\n', ofd);
				cp++;
				break;
			case 't':
				putc('\t', ofd);
				cp++;
				break;
			default:
				putc('\\', ofd);
			}
		} else {
			putc(*cp, ofd);
		}
		cp++;
	}
	putc('\n', ofd);
	fflush(ofd);
}

static void 
xhalt(void)
{
	fclose(newo);
	fclose(newi);
	sigset(SIGINT, savesig);
	sigset(SIGHUP, savehup);
	if (rcvmode)
		stop(0);
	exit(1);
	/* NOTREACHED */
}

/*
 * Strip the nulls from a buffer of length n
 */
static int 
stripnulls(char *linebuf, int nread)
{
	int i, j;

	for (i = 0; i < nread; i++)
		if (linebuf[i] == '\0')
			break;
	for (j = i; j < nread; j++)
		if (linebuf[j] != '\0')
			linebuf[i++] = linebuf[j];
	linebuf[i] = '\0';
	return(i);
}
