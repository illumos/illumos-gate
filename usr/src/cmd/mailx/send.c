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
 * Copyright (c) 2016 by Delphix. All rights reserved.
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

#include "rcv.h"
#include <locale.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Mail to others.
 */

static void		fmt(register char *str, register FILE *fo);
static FILE		*infix(struct header *hp, FILE *fi);
static void		statusput(register struct message *mp, register FILE *obuf, int doign, int (*fp)(const char *, FILE *));
static int		savemail(char name[], struct header *hp, FILE *fi);
static int		sendmail(char *str);
static int		Sendmail(char *str);

static off_t textpos;

/*
 * Send message described by the passed pointer to the
 * passed output buffer.  Return -1 on error, but normally
 * the number of lines written.  Adjust the status: field
 * if need be.  If doign is set, suppress ignored header fields.
 * Call (*fp)(line, obuf) to print the line.
 */
long
msend(
	struct message *mailp,
	FILE *obuf,
	int flag,
	int (*fp)(const char *, FILE *))
{
	register struct message *mp;
	long clen, n, c;
	FILE *ibuf;
	char line[LINESIZE], field[BUFSIZ];
	int ishead, infld, fline, dostat, doclen, nread, unused;
	char *cp, *cp2;
	int doign = flag & M_IGNORE;
	int oldign = 0;	/* previous line was ignored */
	long lc;

	mp = mailp;
	if (mp->m_clen == 0)
		setclen(mp);
	ibuf = setinput(mp);
	c = mp->m_size;
	ishead = 1;
	dostat = 1;
	doclen = 1;
	infld = 0;
	fline = 1;
	lc = 0;
	clearerr(obuf);
	while (c > 0L) {
		nread = getaline(line, LINESIZE, ibuf, &unused);
		c -= nread;
		lc++;
		if (ishead) {
			/*
			 * First line is the From line, so no headers
			 * there to worry about
			 */
			if (fline) {
				fline = 0;
				goto writeit;
			}
			/*
			 * If line is blank, we've reached end of
			 * headers, so force out status: field
			 * and note that we are no longer in header
			 * fields.  Also force out Content-Length: field.
			 */
			if (line[0] == '\n') {
				if (dostat) {
					statusput(mailp, obuf, doign, fp);
					dostat = 0;
				}
				if (doclen &&
				    !isign("content-length", flag&M_SAVING)) {
					snprintf(field, sizeof (field),
						"Content-Length: %ld\n",
						mp->m_clen - 1);
					(*fp)(field, obuf);
					if (ferror(obuf))
						return(-1);
					doclen = 0;
				}
				ishead = 0;
				goto writeit;
			}
			/*
			 * If this line is a continuation
			 * of a previous header field, just echo it.
			 */
			if (isspace(line[0]) && infld)
				if (oldign)
					continue;
				else
					goto writeit;
			infld = 0;
			/*
			 * If we are no longer looking at real
			 * header lines, force out status:
			 * This happens in uucp style mail where
			 * there are no headers at all.
			 */
			if (!headerp(line)) {
				if (dostat) {
					statusput(mailp, obuf, doign, fp);
					dostat = 0;
				}
				(*fp)("\n", obuf);
				ishead = 0;
				goto writeit;
			}
			infld++;
			/*
			 * Pick up the header field.
			 * If it is an ignored field and
			 * we care about such things, skip it.
			 */
			cp = line;
			cp2 = field;
			while (*cp && *cp != ':' && !isspace(*cp))
				*cp2++ = *cp++;
			*cp2 = 0;
			oldign = doign && isign(field, flag&M_SAVING);
			if (oldign)
				continue;
			/*
			 * If the field is "status," go compute and print the
			 * real Status: field
			 */
			if (icequal(field, "status")) {
				if (dostat) {
					statusput(mailp, obuf, doign, fp);
					dostat = 0;
				}
				continue;
			}
			if (icequal(field, "content-length")) {
				if (doclen) {
					snprintf(line, sizeof (line),
						"Content-Length: %ld\n",
						mp->m_clen - 1);
					(*fp)(line, obuf);
					if (ferror(obuf))
						return(-1);
					doclen = 0;
				}
				continue;
			}
		}
writeit:
		if (!ishead && !mp->m_text && mp->m_clen != 0) {
			if (line[0] == '\n')
				putc('\n', obuf);
			clen = mp->m_clen-1;
			for (;;) {
				n = clen < sizeof line ? clen : sizeof line;
				if ((n = fread(line, 1, (int)n, ibuf)) <= 0) {
					fprintf(stderr, gettext(
					    "\t(Unexpected end-of-file).\n"));
					clen = 0;
				} else {
					if (fwrite(line, 1, (int)n, obuf) != n) {
						fprintf(stderr, gettext(
					"\tError writing to the new file.\n"));
						fflush(obuf);
						if (fferror(obuf))
							return (-1);
					}
				}
				clen -= n;
				if (clen <= 0) {
					break;
				}
			}
			c = 0L;
		} else {
			(*fp)(line, obuf);
			if (ferror(obuf))
				return(-1);
		}
	}
	fflush(obuf);
	if (ferror(obuf))
		return(-1);
	if (ishead && (mailp->m_flag & MSTATUS))
		printf(gettext("failed to fix up status field\n"));
	return(lc);
}

/*
 * Test if the passed line is a header line, RFC 822 style.
 */
int
headerp(register char *line)
{
	register char *cp = line;

	while (*cp && *cp != ' ' && *cp != '\t' && *cp != ':')
		cp++;
	return(*cp == ':');
}

/*
 * Output a reasonable looking status field.
 * But if "status" is ignored and doign, forget it.
 */
static void
statusput(
	register struct message *mp,
	register FILE *obuf,
	int doign,
	int (*fp)(const char *, FILE *))
{
	char statout[12];

	if (doign && isign("status", 0))
		return;
	if ((mp->m_flag & (MNEW|MREAD)) == MNEW)
		return;
	strcpy(statout, "Status: ");
	if (mp->m_flag & MREAD)
		strcat(statout, "R");
	if ((mp->m_flag & MNEW) == 0)
		strcat(statout, "O");
	strcat(statout, "\n");
	(*fp)(statout, obuf);
}

/*
 * Interface between the argument list and the mail1 routine
 * which does all the dirty work.
 */

int
mail(char **people)
{
	register char *cp2, *cp3;
	register int s;
	char *buf, **ap;
	struct header head;

	for (s = 0, ap = people; *ap; ap++)
		s += strlen(*ap) + 2;
	buf = (char *)salloc((unsigned)(s+1));
	cp2 = buf;
	for (ap = people; *ap; ap++) {
		for (cp3 = *ap; *cp3; ) {
			if (*cp3 == ' ' || *cp3 == '\t') {
				*cp3++ = ',';
				while (*cp3 == ' ' || *cp3 == '\t')
					cp3++;
			} else
				cp3++;
		}
		cp2 = copy(*ap, cp2);
		*cp2++ = ',';
		*cp2++ = ' ';
	}
	*cp2 = '\0';
	head.h_to = buf;
	head.h_subject = head.h_cc = head.h_bcc = head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	head.h_seq = 0;
	mail1(&head, Fflag, NOSTR);
	return(0);
}

int
sendm(char *str)
{
	if (value("flipm") != NOSTR)
		return(Sendmail(str));
	else return(sendmail(str));
}

int
Sendm(char *str)
{
	if (value("flipm") != NOSTR)
		return(sendmail(str));
	else return(Sendmail(str));
}

/*
 * Interface to the mail1 routine for the -t flag
 * (read headers from text).
 */
int
tmail(void)
{
	struct header head;

	head.h_to = NOSTR;
	head.h_subject = head.h_cc = head.h_bcc = head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	head.h_seq = 0;
	mail1(&head, Fflag, NOSTR);
	return(0);
}

/*
 * Send mail to a bunch of user names.  The interface is through
 * the mail routine below.
 */
static int
sendmail(char *str)
{
	struct header head;

	if (blankline(str))
		head.h_to = NOSTR;
	else
		head.h_to = addto(NOSTR, str);
	head.h_subject = head.h_cc = head.h_bcc = head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	head.h_seq = 0;
	mail1(&head, 0, NOSTR);
	return(0);
}

/*
 * Send mail to a bunch of user names.  The interface is through
 * the mail routine below.
 * save a copy of the letter
 */
static int
Sendmail(char *str)
{
	struct header head;

	if (blankline(str))
		head.h_to = NOSTR;
	else
		head.h_to = addto(NOSTR, str);
	head.h_subject = head.h_cc = head.h_bcc = head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	head.h_seq = 0;
	mail1(&head, 1, NOSTR);
	return(0);
}

/*
 * Walk the list of fds, closing all but one.
 */
static int
closefd_walk(void *special_fd, int fd)
{
	if (fd > STDERR_FILENO && fd != *(int *)special_fd)
		(void) close(fd);
	return (0);
}

/*
 * Mail a message on standard input to the people indicated
 * in the passed header.  (Internal interface).
 */
void
mail1(struct header *hp, int use_to, char *orig_to)
{
	pid_t p, pid;
	int i, s, gotcha;
	char **namelist, *deliver;
	struct name *to, *np;
	FILE *mtf, *fp;
	int remote = rflag != NOSTR || rmail;
	char **t;
	char *deadletter;
	char recfile[PATHSIZE];

	/*
	 * Collect user's mail from standard input.
	 * Get the result as mtf.
	 */

	pid = (pid_t)-1;
	if ((mtf = collect(hp)) == NULL)
		return;
	hp->h_seq = 1;
	if (hp->h_subject == NOSTR)
		hp->h_subject = sflag;
	if (fsize(mtf) == 0 && hp->h_subject == NOSTR) {
		printf(gettext("No message !?!\n"));
		goto out;
	}
	if (intty) {
		printf(gettext("EOT\n"));
		flush();
	}

	/*
	 * If we need to use the To: line to determine the record
	 * file, save a copy of it before it's sorted below.
	 */

	if (use_to && orig_to == NOSTR && hp->h_to != NOSTR)
		orig_to = strcpy((char *)salloc(strlen(hp->h_to)+1), hp->h_to);
	else if (orig_to == NOSTR)
		orig_to = "";

	/*
	 * Now, take the user names from the combined
	 * to and cc lists and do all the alias
	 * processing.
	 */

	senderr = 0;
	to = cat(extract(hp->h_bcc, GBCC),
	     cat(extract(hp->h_to, GTO),
	     extract(hp->h_cc, GCC)));
	to = translate(outpre(elide(usermap(to))));
	if (!senderr)
		mapf(to, myname);
	mechk(to);
	for (gotcha = 0, np = to; np != NIL; np = np->n_flink)
		if ((np->n_type & GDEL) == 0)
			gotcha++;
	hp->h_to = detract(to, GTO);
	hp->h_cc = detract(to, GCC);
	hp->h_bcc = detract(to, GBCC);
	if ((mtf = infix(hp, mtf)) == NULL) {
		fprintf(stderr, gettext(". . . message lost, sorry.\n"));
		return;
	}
	rewind(mtf);
	if (askme && isatty(0)) {
		char ans[64];
		puthead(hp, stdout, GTO|GCC|GBCC, 0);
		printf(gettext("Send? "));
		printf("[yes] ");
		if (fgets(ans, sizeof(ans), stdin) && ans[0] &&
				(tolower(ans[0]) != 'y' && ans[0] != '\n'))
			goto dead;
	}
	if (senderr)
		goto dead;
	/*
	 * Look through the recipient list for names with /'s
	 * in them which we write to as files directly.
	 */
	i = outof(to, mtf);
	rewind(mtf);
	if (!gotcha && !i) {
		printf(gettext("No recipients specified\n"));
		goto dead;
	}
	if (senderr)
		goto dead;

	getrecf(orig_to, recfile, use_to, sizeof (recfile));
	if (recfile != NOSTR && *recfile)
		savemail(safeexpand(recfile), hp, mtf);
	if (!gotcha)
		goto out;
	namelist = unpack(to);
	if (debug) {
		fprintf(stderr, "Recipients of message:\n");
		for (t = namelist; *t != NOSTR; t++)
			fprintf(stderr, " \"%s\"", *t);
		fprintf(stderr, "\n");
		return;
	}

	/*
	 * Wait, to absorb a potential zombie, then
	 * fork, set up the temporary mail file as standard
	 * input for "mail" and exec with the user list we generated
	 * far above. Return the process id to caller in case it
	 * wants to await the completion of mail.
	 */

#ifdef VMUNIX
	while (wait3((int *)0, WNOHANG, (struct rusage *)0) > 0)
		;
#else
#ifdef preSVr4
	wait((int *)0);
#else
	while (waitpid((pid_t)-1, (int *)0, WNOHANG) > 0)
		;
#endif
#endif
	rewind(mtf);
	pid = fork();
	if (pid == (pid_t)-1) {
		perror("fork");
dead:
		deadletter = Getf("DEAD");
		if (fp = fopen(deadletter,
		    value("appenddeadletter") == NOSTR ? "w" : "a")) {
			chmod(deadletter, DEADPERM);
			puthead(hp, fp, GMASK|GCLEN, fsize(mtf) - textpos);
			fseek(mtf, textpos, 0);
			lcwrite(deadletter, mtf, fp,
			    value("appenddeadletter") != NOSTR);
			fclose(fp);
		} else
			perror(deadletter);
		goto out;
	}
	if (pid == 0) {
		sigchild();
#ifdef SIGTSTP
		if (remote == 0) {
			sigset(SIGTSTP, SIG_IGN);
			sigset(SIGTTIN, SIG_IGN);
			sigset(SIGTTOU, SIG_IGN);
		}
#endif
		sigset(SIGHUP, SIG_IGN);
		sigset(SIGINT, SIG_IGN);
		sigset(SIGQUIT, SIG_IGN);
		s = fileno(mtf);
		(void) fdwalk(closefd_walk, &s);
		close(0);
		dup(s);
		close(s);
#ifdef CC
		submit(getpid());
#endif /* CC */
		if ((deliver = value("sendmail")) == NOSTR)
#ifdef SENDMAIL
			deliver = SENDMAIL;
#else
			deliver = MAIL;
#endif
		execvp(safeexpand(deliver), namelist);
		perror(deliver);
		exit(1);
	}

	if (value("sendwait")!=NOSTR)
		remote++;
out:
	if (remote) {
		while ((p = wait(&s)) != pid && p != (pid_t)-1)
			;
		if (s != 0)
			senderr++;
		pid = 0;
	}
	fclose(mtf);
	return;
}

/*
 * Prepend a header in front of the collected stuff
 * and return the new file.
 */

static FILE *
infix(struct header *hp, FILE *fi)
{
	register FILE *nfo, *nfi;
	register int c;
	char *postmark, *returnaddr;
	int fd = -1;

	rewind(fi);
	if ((fd = open(tempMail, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
	(nfo = fdopen(fd, "w")) == NULL) {
		perror(tempMail);
		return(fi);
	}
	if ((nfi = fopen(tempMail, "r")) == NULL) {
		perror(tempMail);
		fclose(nfo);
		return(fi);
	}
	removefile(tempMail);
	postmark = value("postmark");
	returnaddr = value("returnaddr");
	if ((postmark != NOSTR) || (returnaddr != NOSTR)) {
		if (returnaddr && *returnaddr)
			fprintf(nfo, "From: %s", returnaddr);
		else
			fprintf(nfo, "From: %s@%s", myname, host);
		if (postmark && *postmark)
			fprintf(nfo, " (%s)", postmark);
		putc('\n', nfo);
	}
	puthead(hp, nfo, (GMASK & ~GBCC) | GCLEN, fsize(fi));
	textpos = ftell(nfo);
	while ((c = getc(fi)) != EOF)
		putc(c, nfo);
	if (ferror(fi)) {
		perror("read");
		return(fi);
	}
	fflush(nfo);
	if (fferror(nfo)) {
		perror(tempMail);
		fclose(nfo);
		fclose(nfi);
		return(fi);
	}
	fclose(nfo);
	fclose(fi);
	rewind(nfi);
	return(nfi);
}

/*
 * Dump the message header on the
 * passed file buffer.
 */

int
puthead(struct header *hp, FILE *fo, int w, long clen)
{
	register int gotcha;

	gotcha = 0;
	if (hp->h_to != NOSTR && (w & GTO))
		fprintf(fo, "To: "), fmt(hp->h_to, fo), gotcha++;
	if ((w & GSUBJECT) && (int)value("bsdcompat"))
		if (hp->h_subject != NOSTR && *hp->h_subject)
			fprintf(fo, "Subject: %s\n", hp->h_subject), gotcha++;
		else
			if (sflag && *sflag)
				fprintf(fo, "Subject: %s\n", sflag), gotcha++;
	if (hp->h_cc != NOSTR && (w & GCC))
		fprintf(fo, "Cc: "), fmt(hp->h_cc, fo), gotcha++;
	if (hp->h_bcc != NOSTR && (w & GBCC))
		fprintf(fo, "Bcc: "), fmt(hp->h_bcc, fo), gotcha++;
	if (hp->h_defopt != NOSTR && (w & GDEFOPT))
		if (receipt_flg)
			fprintf(fo, "Return-Receipt-To: %s\n",
				hp->h_defopt), gotcha++;
		else
		fprintf(fo, "Default-Options: %s\n", hp->h_defopt), gotcha++;
	if ((w & GSUBJECT) && !(int)value("bsdcompat"))
		if (hp->h_subject != NOSTR && *hp->h_subject)
			fprintf(fo, "Subject: %s\n", hp->h_subject), gotcha++;
		else
			if (sflag && *sflag)
				fprintf(fo, "Subject: %s\n", sflag), gotcha++;
	if (hp->h_others != NOSTRPTR && (w & GOTHER)) {
		char **p;
		for (p = hp->h_others; *p; p++)
			fprintf(fo, "%s\n", *p);
		gotcha++;
	}
#ifndef preSVr4
	if (w & GCLEN)
		fprintf(fo, "Content-Length: %ld\n", clen), gotcha++;
#endif
	if (gotcha && (w & GNL))
		putc('\n', fo);
	return(0);
}

/*
 * Format the given text to not exceed 78 characters.
 */
static void
fmt(register char *str, register FILE *fo)
{
	register int col = 4;
	char name[256];
	int len;

	str = strcpy((char *)salloc(strlen(str)+1), str);
	while (str = yankword(str, name, sizeof (name), 1)) {
		len = strlen(name);
		if (col > 4) {
			if (col + len > 76) {
				fputs(",\n    ", fo);
				col = 4;
			} else {
				fputs(", ", fo);
				col += 2;
			}
		}
		fputs(name, fo);
		col += len;
	}
	putc('\n', fo);
}

/*
 * Save the outgoing mail on the passed file.
 */
static int
savemail(char name[], struct header *hp, FILE *fi)
{
	register FILE *fo;
	time_t now;
	char *n;
#ifdef preSVr4
	char line[BUFSIZ];
#else
	int c;
#endif

	if (debug)
		fprintf(stderr, gettext("save in '%s'\n"), name);
	if ((fo = fopen(name, "a")) == NULL) {
		perror(name);
		return(-1);
	}
	time(&now);
	n = rflag;
	if (n == NOSTR)
		n = myname;
	fprintf(fo, "From %s %s", n, ctime(&now));
	puthead(hp, fo, GMASK|GCLEN, fsize(fi) - textpos);
	fseek(fi, textpos, 0);
#ifdef preSVr4
	while (fgets(line, sizeof line, fi)) {
		if (!strncmp(line, "From ", 5))
			putc('>', fo);
		fputs(line, fo);
	}
#else
	while ((c = getc(fi)) != EOF)
		putc(c, fo);
#endif
	putc('\n', fo);
	fflush(fo);
	if (fferror(fo))
		perror(name);
	fclose(fo);
	return(0);
}
