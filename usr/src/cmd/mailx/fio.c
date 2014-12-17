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
 * Copyright 2014 Joyent, Inc.
 */

/*
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "rcv.h"
#include <locale.h>
#include <wordexp.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * File I/O.
 */

static int getln(char *line, int max, FILE *f);
static int linecount(char *lp, long size);

/*
 * Set up the input pointers while copying the mail file into
 * /tmp.
 */

void
setptr(register FILE *ibuf)
{
	int n, newline = 1, blankline = 1;
	int StartNewMsg = TRUE;
	int ToldUser = FALSE;
	long clen = -1L;
	int hdr = 0;
	int cflg = 0;			/* found Content-length in header */
	register char *cp;
	register int l;
	register long s;
	off_t offset;
	char linebuf[LINESIZE];
	int inhead, newmail, Odot;
	short flag;

	if (!space) {
		msgCount = 0;
		offset = 0;
		space = 32;
		newmail = 0;
		message =
		    (struct message *)calloc(space, sizeof (struct message));
		if (message == NULL) {
			fprintf(stderr, gettext(
			    "calloc: insufficient memory for %d messages\n"),
			    space);
			exit(1);
			/* NOTREACHED */
		}
		dot = message;
	} else {
		newmail = 1;
		offset = fsize(otf);
	}
	s = 0L;
	l = 0;
	/*
	 * Set default flags.  When reading from
	 * a folder, assume the message has been
	 * previously read.
	 */
	if (edit)
		flag = MUSED|MREAD;
	else
		flag = MUSED|MNEW;

	inhead = 0;
	while ((n = getln(linebuf, sizeof (linebuf), ibuf)) > 0) {
		if (!newline) {
			goto putout;
		}
	top:
		hdr = inhead && (headerp(linebuf) ||
		    (linebuf[0] == ' ' || linebuf[0] == '\t'));
		if (!hdr && cflg) {	/* nonheader, Content-length seen */
			if (clen > 0 && clen < n) {	/* read too much */
				/*
				 * NB: this only can happen if there is a
				 * small content that is NOT \n terminated
				 * and has no leading blank line, i.e., never.
				 */
				if (fwrite(linebuf, 1, (int)clen, otf) !=
					clen) {
					fclose(ibuf);
					fflush(otf);
				} else {
					l += linecount(linebuf, clen);
				}
				offset += clen;
				s += clen;
				n -= (int)clen;
				/* shift line to the left, copy null as well */
				memcpy(linebuf, linebuf+clen, n+1);
				cflg = 0;
				message[msgCount-1].m_clen = clen + 1;
				blankline = 1;
				StartNewMsg = TRUE;
				goto top;
			}
			/* here, clen == 0 or clen >= n */
			if (n == 1 && linebuf[0] == '\n') {
				/* leading empty line */
				clen++;		/* cheat */
				inhead = 0;
			}
			offset += clen;
			s += (long)clen;
			message[msgCount-1].m_clen = clen;
			for (;;) {
				if (fwrite(linebuf, 1, n, otf) != n) {
					fclose(ibuf);
					fflush(otf);
				} else {
					l += linecount(linebuf, n);
				}
				clen -= n;
				if (clen <= 0) {
					break;
				}
				n = clen < sizeof (linebuf) ?
				    (int)clen : (int)sizeof (linebuf);
				if ((n = fread(linebuf, 1, n, ibuf)) <= 0) {
					fprintf(stderr, gettext(
			"%s:\tYour mailfile was found to be corrupted.\n"),
					    progname);
					fprintf(stderr, gettext(
					    "\t(Unexpected end-of-file).\n"));
					fprintf(stderr, gettext(
					"\tMessage #%d may be truncated.\n\n"),
					    msgCount);
					offset -= clen;
					s -= clen;
					clen = 0; /* stop the loop */
				}
			}
			/* All done, go to top for next message */
			cflg = 0;
			blankline = 1;
			StartNewMsg = TRUE;
			continue;
		}

		/* Look for a From line that starts a new message */
		if (blankline && linebuf[0] == 'F' && is_headline(linebuf)) {
			if (msgCount > 0 && !newmail) {
				message[msgCount-1].m_size = s;
				message[msgCount-1].m_lines = l;
				message[msgCount-1].m_flag = flag;
			}
			if (msgCount >= space) {
				/*
				 * Limit the speed at which the
				 * allocated space grows.
				 */
				if (space < 512)
					space = space*2;
				else
					space += 512;
				errno = 0;
				Odot = dot - &(message[0]);
				message = (struct message *)
				    realloc(message,
					space*(sizeof (struct message)));
				if (message == NULL) {
					perror("realloc failed");
					fprintf(stderr, gettext(
			"realloc: insufficient memory for %d messages\n"),
					    space);
					exit(1);
				}
				dot = &message[Odot];
			}
			message[msgCount].m_offset = offset;
			message[msgCount].m_text = TRUE;
			message[msgCount].m_clen = 0;
			newmail = 0;
			msgCount++;
			if (edit)
				flag = MUSED|MREAD;
			else
				flag = MUSED|MNEW;
			inhead = 1;
			s = 0L;
			l = 0;
			StartNewMsg = FALSE;
			ToldUser = FALSE;
			goto putout;
		}

		/* if didn't get a header line, we're no longer in the header */
		if (!hdr)
			inhead = 0;
		if (!inhead)
			goto putout;

		/*
		 * Look for Status: line.  Do quick check for second character,
		 * many headers start with "S" but few have "t" as second char.
		 */
		if ((linebuf[1] == 't' || linebuf[1] == 'T') &&
		    ishfield(linebuf, "status")) {
			cp = hcontents(linebuf);
			flag = MUSED|MNEW;
			if (strchr(cp, 'R'))
				flag |= MREAD;
			if (strchr(cp, 'O'))
				flag &= ~MNEW;
		}
		/*
		 * Look for Content-Length and Content-Type headers.  Like
		 * above, do a quick check for the "-", which is rare.
		 */
		if (linebuf[7] == '-') {
			if (ishfield(linebuf, "content-length")) {
				if (!cflg) {
					clen = atol(hcontents(linebuf));
					cflg = clen >= 0;
				}
			} else if (ishfield(linebuf, "content-type")) {
				char word[LINESIZE];
				char *cp2;

				cp = hcontents(linebuf);
				cp2 = word;
				while (!isspace(*cp))
					*cp2++ = *cp++;
				*cp2 = '\0';
				if (icequal(word, "binary"))
					message[msgCount-1].m_text = FALSE;
			}
		}
putout:
		offset += n;
		s += (long)n;
		if (fwrite(linebuf, 1, n, otf) != n) {
			fclose(ibuf);
			fflush(otf);
		} else {
			l++;
		}
		if (ferror(otf)) {
			perror("/tmp");
			exit(1);
		}
		if (msgCount == 0) {
			fclose(ibuf);
			fflush(otf);
		}
		if (linebuf[n-1] == '\n') {
			blankline = newline && n == 1;
			newline = 1;
			if (n == 1) {
				/* Blank line. Skip StartNewMsg check below */
				continue;
			}
		} else {
			newline = 0;
		}
		if (StartNewMsg && !ToldUser) {
			fprintf(stderr, gettext(
			    "%s:\tYour mailfile was found to be corrupted\n"),
			    progname);
			fprintf(stderr,
			    gettext("\t(Content-length mismatch).\n"));
			fprintf(stderr, gettext(
			    "\tMessage #%d may be truncated,\n"), msgCount);
			fprintf(stderr, gettext(
			    "\twith another message concatenated to it.\n\n"));
			ToldUser = TRUE;
		}
	}

	if (n == 0) {
		fflush(otf);
		if (fferror(otf)) {
			perror("/tmp");
			exit(1);
		}
		if (msgCount) {
			message[msgCount-1].m_size = s;
			message[msgCount-1].m_lines = l;
			message[msgCount-1].m_flag = flag;
		}
		fclose(ibuf);
	}
}

/*
 * Compute the content length of a message and set it into m_clen.
 */

void
setclen(register struct message *mp)
{
	long c;
	FILE *ibuf;
	char line[LINESIZE];
	int fline, nread;

	ibuf = setinput(mp);
	c = mp->m_size;
	fline = 1;
	while (c > 0L) {
		nread = getln(line, sizeof (line), ibuf);
		c -= nread;
		/*
		 * First line is the From line, so no headers
		 * there to worry about.
		 */
		if (fline) {
			fline = 0;
			continue;
		}
		/*
		 * If line is blank, we've reached end of headers.
		 */
		if (line[0] == '\n')
			break;
		/*
		 * If this line is a continuation
		 * of a previous header field, keep going.
		 */
		if (isspace(line[0]))
			continue;
		/*
		 * If we are no longer looking at real
		 * header lines, we're done.
		 * This happens in uucp style mail where
		 * there are no headers at all.
		 */
		if (!headerp(line)) {
			c += nread;
			break;
		}
	}
	if (c == 0)
		c = 1;
	mp->m_clen = c;
}

static int
getln(char *line, int max, FILE *f)
{
	register int c;
	register char *cp, *ecp;

	cp = line;
	ecp = cp + max - 1;
	while (cp < ecp && (c = getc(f)) != EOF)
		if ((*cp++ = (char)c) == '\n')
			break;
	*cp = '\0';
	return (cp - line);
}

/*
 * Read up a line from the specified input into the line
 * buffer.  Return the number of characters read.  Do not
 * include the newline at the end.
 */

int
readline(FILE *ibuf, char *linebuf)
{
	register char *cp;
	register int c;
	int seennulls = 0;

	clearerr(ibuf);
	c = getc(ibuf);
	for (cp = linebuf; c != '\n' && c != EOF; c = getc(ibuf)) {
		if (c == 0) {
			if (!seennulls) {
				fprintf(stderr,
				    gettext("mailx: NUL changed to @\n"));
				seennulls++;
			}
			c = '@';
		}
		if (cp - linebuf < LINESIZE-2)
			*cp++ = (char)c;
	}
	*cp = 0;
	if (c == EOF && cp == linebuf)
		return (0);
	return (cp - linebuf + 1);
}

/*
 * linecount - determine the number of lines in a printable file.
 */

static int
linecount(char *lp, long size)
{
	register char *cp, *ecp;
	register int count;

	count = 0;
	cp = lp;
	ecp = cp + size;
	while (cp < ecp)
		if (*cp++ == '\n')
			count++;
	return (count);
}

/*
 * Return a file buffer all ready to read up the
 * passed message pointer.
 */

FILE *
setinput(register struct message *mp)
{
	fflush(otf);
	if (fseek(itf, mp->m_offset, 0) < 0) {
		perror("fseek");
		panic("temporary file seek");
	}
	return (itf);
}


/*
 * Delete a file, but only if the file is a plain file.
 */

int
removefile(char name[])
{
	struct stat statb;
	extern int errno;

	if (stat(name, &statb) < 0)
		if (errno == ENOENT)
			return (0);	/* it's already gone, no error */
		else
			return (-1);
	if ((statb.st_mode & S_IFMT) != S_IFREG) {
		errno = EISDIR;
		return (-1);
	}
	return (unlink(name));
}

/*
 * Terminate an editing session by attempting to write out the user's
 * file from the temporary.  Save any new stuff appended to the file.
 */
int
edstop(
    int noremove	/* don't allow the file to be removed, trunc instead */
)
{
	register int gotcha, c;
	register struct message *mp;
	FILE *obuf, *ibuf, *tbuf = 0, *readstat;
	struct stat statb;
	char tempname[STSIZ], *id;
	int tmpfd = -1;

	if (readonly)
		return (0);
	holdsigs();
	if (Tflag != NOSTR) {
		if ((readstat = fopen(Tflag, "w")) == NULL)
			Tflag = NOSTR;
	}
	for (mp = &message[0], gotcha = 0; mp < &message[msgCount]; mp++) {
		if (mp->m_flag & MNEW) {
			mp->m_flag &= ~MNEW;
			mp->m_flag |= MSTATUS;
		}
		if (mp->m_flag & (MODIFY|MDELETED|MSTATUS))
			gotcha++;
		if (Tflag != NOSTR && (mp->m_flag & (MREAD|MDELETED)) != 0) {
			if ((id = hfield("article-id", mp, addone)) != NOSTR)
				fprintf(readstat, "%s\n", id);
		}
	}
	if (Tflag != NOSTR)
		fclose(readstat);
	if (!gotcha || Tflag != NOSTR)
		goto done;
	if ((ibuf = fopen(editfile, "r+")) == NULL) {
		perror(editfile);
		relsesigs();
		longjmp(srbuf, 1);
	}
	lock(ibuf, "r+", 1);
	if (fstat(fileno(ibuf), &statb) >= 0 && statb.st_size > mailsize) {
		nstrcpy(tempname, STSIZ, "/tmp/mboxXXXXXX");
		if ((tmpfd = mkstemp(tempname)) == -1) {
			perror(tempname);
			fclose(ibuf);
			relsesigs();
			longjmp(srbuf, 1);
		}
		if ((obuf = fdopen(tmpfd, "w")) == NULL) {
			perror(tempname);
			fclose(ibuf);
			removefile(tempname);
			relsesigs();
			(void) close(tmpfd);
			longjmp(srbuf, 1);
		}
		fseek(ibuf, mailsize, 0);
		while ((c = getc(ibuf)) != EOF)
			putc(c, obuf);
		fclose(obuf);
		if ((tbuf = fopen(tempname, "r")) == NULL) {
			perror(tempname);
			fclose(ibuf);
			removefile(tempname);
			relsesigs();
			longjmp(srbuf, 1);
		}
		removefile(tempname);
	}
	if ((obuf = fopen(editfile, "r+")) == NULL) {
		if ((obuf = fopen(editfile, "w")) == NULL) {
			perror(editfile);
			fclose(ibuf);
			if (tbuf)
				fclose(tbuf);
			relsesigs();
			longjmp(srbuf, 1);
		}
	}
	printf("\"%s\" ", editfile);
	flush();
	c = 0;
	for (mp = &message[0]; mp < &message[msgCount]; mp++) {
		if ((mp->m_flag & MDELETED) != 0)
			continue;
		c++;
		if (msend(mp, obuf, 0, fputs) < 0) {
			perror(editfile);
			fclose(ibuf);
			fclose(obuf);
			if (tbuf)
				fclose(tbuf);
			relsesigs();
			longjmp(srbuf, 1);
		}
	}
	gotcha = (c == 0 && tbuf == NULL);
	if (tbuf != NULL) {
		while ((c = getc(tbuf)) != EOF)
			putc(c, obuf);
		fclose(tbuf);
	}
	fflush(obuf);
	if (fferror(obuf)) {
		perror(editfile);
		fclose(ibuf);
		fclose(obuf);
		relsesigs();
		longjmp(srbuf, 1);
	}
	if (gotcha && !noremove && (value("keep") == NOSTR)) {
		removefile(editfile);
		printf(gettext("removed.\n"));
	}
	else
		printf(gettext("updated.\n"));
	fclose(ibuf);
	trunc(obuf);
	fclose(obuf);
	flush();

done:
	relsesigs();
	return (1);
}

#ifndef OLD_BSD_SIGS
static int sigdepth = 0;		/* depth of holdsigs() */
#ifdef VMUNIX
static int omask = 0;
#else
static	sigset_t mask, omask;
#endif
#endif
/*
 * Hold signals SIGHUP - SIGQUIT.
 */
void
holdsigs(void)
{
#ifndef OLD_BSD_SIGS
	if (sigdepth++ == 0) {
#ifdef VMUNIX
		omask = sigblock(sigmask(SIGHUP) |
		    sigmask(SIGINT)|sigmask(SIGQUIT));
#else
		sigemptyset(&mask);
		sigaddset(&mask, SIGHUP);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGQUIT);
		sigprocmask(SIG_BLOCK, &mask, &omask);
#endif
	}
#else
	sighold(SIGHUP);
	sighold(SIGINT);
	sighold(SIGQUIT);
#endif
}

/*
 * Release signals SIGHUP - SIGQUIT
 */
void
relsesigs(void)
{
#ifndef OLD_BSD_SIGS
	if (--sigdepth == 0)
#ifdef VMUNIX
		sigsetmask(omask);
#else
		sigprocmask(SIG_SETMASK, &omask, NULL);
#endif
#else
	sigrelse(SIGHUP);
	sigrelse(SIGINT);
	sigrelse(SIGQUIT);
#endif
}

#if !defined(OLD_BSD_SIGS) && !defined(VMUNIX)
void
(*sigset(int sig, void (*act)(int)))(int)
{
	struct sigaction sa, osa;

	sa.sa_handler = (void (*)())act;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(sig, &sa, &osa) < 0)
		return ((void (*)(int))-1);
	return ((void (*)(int))osa.sa_handler);
}
#endif

/*
 * Flush the standard output.
 */

void
flush(void)
{
	fflush(stdout);
	fflush(stderr);
}

/*
 * Determine the size of the file possessed by
 * the passed buffer.
 */

off_t
fsize(FILE *iob)
{
	register int f;
	struct stat sbuf;

	f = fileno(iob);
	if (fstat(f, &sbuf) < 0)
		return (0);
	return (sbuf.st_size);
}

/*
 * Check for either a stdio recognized error, or
 * a possibly delayed write error (in case it's
 * an NFS file, for instance).
 */

int
fferror(FILE *iob)
{
	return (ferror(iob) || fsync(fileno(iob)) < 0);
}

/*
 * Take a file name, possibly with shell meta characters
 * in it and expand it by using wordexp().
 * Return the file name as a dynamic string.
 * If the name cannot be expanded (for whatever reason)
 * return NULL.
 */

char *
expand(char *name)
{
	char xname[BUFSIZ];
	char foldbuf[BUFSIZ];
	register char *cp;
	register int l;
	wordexp_t wrdexp_buf;

	if (debug) fprintf(stderr, "expand(%s)=", name);
	cp = strchr(name, '\0') - 1;	/* pointer to last char of name */
	if (isspace(*cp)) {
		/* strip off trailing blanks */
		while (cp > name && isspace(*cp))
			cp--;
		l = *++cp;	/* save char */
		*cp = '\0';
		name = savestr(name);
		*cp = (char)l;	/* restore char */
	}
	if (name[0] == '+' && getfold(foldbuf) >= 0) {
		snprintf(xname, sizeof (xname), "%s/%s", foldbuf, name + 1);
		cp = safeexpand(savestr(xname));
		if (debug) fprintf(stderr, "%s\n", cp);
		return (cp);
	}
	if (!anyof(name, "~{[*?$`'\"\\")) {
		if (debug) fprintf(stderr, "%s\n", name);
		return (name);
	}
	if (wordexp(name, &wrdexp_buf, WRDE_NOCMD) != 0) {
		fprintf(stderr, gettext("Syntax error in \"%s\"\n"), name);
		fflush(stderr);
		return (NOSTR);
	}
	if (wrdexp_buf.we_wordc > 1) {
		fprintf(stderr, gettext("\"%s\": Ambiguous\n"), name);
		fflush(stderr);
		return (NOSTR);
	}
	if (debug) fprintf(stderr, "%s\n", wrdexp_buf.we_wordv[0]);
	return (savestr(wrdexp_buf.we_wordv[0]));
}

/*
 * Take a file name, possibly with shell meta characters
 * in it and expand it by using "sh -c echo filename"
 * Return the file name as a dynamic string.
 * If the name cannot be expanded (for whatever reason)
 * return the original file name.
 */

char *
safeexpand(char name[])
{
	char *t = expand(name);
	return (t) ? t : savestr(name);
}

/*
 * Determine the current folder directory name.
 */
int
getfold(char *name)
{
	char *folder;

	if ((folder = value("folder")) == NOSTR || *folder == '\0')
		return (-1);
	/*
	 * If name looks like a folder name, don't try
	 * to expand it, to prevent infinite recursion.
	 */
	if (*folder != '+' && (folder = expand(folder)) == NOSTR ||
	    *folder == '\0')
		return (-1);
	if (*folder == '/') {
		nstrcpy(name, BUFSIZ, folder);
	} else
		snprintf(name, BUFSIZ, "%s/%s", homedir, folder);
	return (0);
}

/*
 * A nicer version of Fdopen, which allows us to fclose
 * without losing the open file.
 */

FILE *
Fdopen(int fildes, char *mode)
{
	register int f;

	f = dup(fildes);
	if (f < 0) {
		perror("dup");
		return (NULL);
	}
	return (fdopen(f, mode));
}

/*
 * return the filename associated with "s".  This function always
 * returns a non-null string (no error checking is done on the receiving end)
 */
char *
Getf(register char *s)
{
	register char *cp;
	static char defbuf[PATHSIZE];

	if (((cp = value(s)) != 0) && *cp) {
		return (safeexpand(cp));
	} else if (strcmp(s, "MBOX") == 0) {
		snprintf(defbuf, sizeof (defbuf), "%s/%s", Getf("HOME"),
			"mbox");
		return (defbuf);
	} else if (strcmp(s, "DEAD") == 0) {
		snprintf(defbuf, sizeof (defbuf), "%s/%s", Getf("HOME"),
			"dead.letter");
		return (defbuf);
	} else if (strcmp(s, "MAILRC") == 0) {
		snprintf(defbuf, sizeof (defbuf), "%s/%s", Getf("HOME"),
			".mailrc");
		return (defbuf);
	} else if (strcmp(s, "HOME") == 0) {
		/* no recursion allowed! */
		return (".");
	}
	return ("DEAD");	/* "cannot happen" */
}
