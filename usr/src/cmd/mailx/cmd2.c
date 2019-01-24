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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * More user commands.
 */

static int	igshow(void);
static int	igcomp(const void *l, const void *r);
static int	save1(char str[], int mark);
static int	Save1(int *msgvec, int mark);
static void	savemsglist(char *file, int *msgvec, int flag);
static int	put1(char str[], int doign);
static int	svputs(const char *line, FILE *obuf);
static int	wrputs(const char *line, FILE *obuf);
static int	retshow(void);

/* flags for savemsglist() */
#define	S_MARK		1		/* mark the message as saved */
#define	S_NOHEADER	2		/* don't write out the header */
#define	S_SAVING	4		/* doing save/copy */
#define	S_NOIGNORE	8		/* don't do ignore processing */

/*
 * If any arguments were given, print the first message
 * identified by the first argument. If no arguments are given,
 * print the next applicable message after dot.
 */

int
next(int *msgvec)
{
	register struct message *mp;
	int list[2];

	if (*msgvec != 0) {
		if (*msgvec < 0) {
			printf((gettext("Negative message given\n")));
			return (1);
		}
		mp = &message[*msgvec - 1];
		if ((mp->m_flag & MDELETED) == 0) {
			dot = mp;
			goto hitit;
		}
		printf(gettext("No applicable message\n"));
		return (1);
	}

	/*
	 * If this is the first command, select message 1.
	 * Note that this must exist for us to get here at all.
	 */
	if (!sawcom)
		goto hitit;

	/*
	 * Just find the next good message after dot, no
	 * wraparound.
	 */
	for (mp = dot+1; mp < &message[msgCount]; mp++)
		if ((mp->m_flag & (MDELETED|MSAVED)) == 0)
			break;
	if (mp >= &message[msgCount]) {
		printf(gettext("At EOF\n"));
		return (0);
	}
	dot = mp;
hitit:
	/*
	 * Print dot.
	 */
	list[0] = dot - &message[0] + 1;
	list[1] = 0;
	return (type(list));
}

/*
 * Save a message in a file.  Mark the message as saved
 * so we can discard when the user quits.
 */
int
save(char str[])
{
	return (save1(str, S_MARK));
}

/*
 * Copy a message to a file without affected its saved-ness
 */
int
copycmd(char str[])
{
	return (save1(str, 0));
}

/*
 * Save/copy the indicated messages at the end of the passed file name.
 * If mark is true, mark the message "saved."
 */
static int
save1(char str[], int mark)
{
	char *file, *cmd;
	int f, *msgvec;

	cmd = mark ? "save" : "copy";
	msgvec = (int *)salloc((msgCount + 2) * sizeof (*msgvec));
	if ((file = snarf(str, &f, 0)) == NOSTR)
		file = Getf("MBOX");
	if (f == -1)
		return (1);
	if (!f) {
		*msgvec = first(0, MMNORM);
		if (*msgvec == 0) {
			printf(gettext("No messages to %s.\n"), cmd);
			return (1);
		}
		msgvec[1] = 0;
	}
	if (f && getmsglist(str, msgvec, 0) < 0)
		return (1);
	if ((file = expand(file)) == NOSTR)
		return (1);
	savemsglist(file, msgvec, mark | S_SAVING);
	return (0);
}

int
Save(int *msgvec)
{
	return (Save1(msgvec, S_MARK));
}

int
Copy(int *msgvec)
{
	return (Save1(msgvec, 0));
}

/*
 * save/copy the indicated messages at the end of a file named
 * by the sender of the first message in the msglist.
 */
static int
Save1(int *msgvec, int mark)
{
	register char *from;
	char recfile[BUFSIZ];

#ifdef notdef
	from = striphosts(nameof(&message[*msgvec-1], 0));
#else
	from = nameof(&message[*msgvec-1]);
#endif
	getrecf(from, recfile, 1, sizeof (recfile));
	if (*recfile != '\0')
		savemsglist(safeexpand(recfile), msgvec, mark | S_SAVING);
	return (0);
}

int
sput(char str[])
{
	return (put1(str, 0));
}

int
Sput(char str[])
{
	return (put1(str, S_NOIGNORE));
}

/*
 * Put the indicated messages at the end of the passed file name.
 */
static int
put1(char str[], int doign)
{
	char *file;
	int f, *msgvec;

	msgvec = (int *)salloc((msgCount + 2) * sizeof (*msgvec));
	if ((file = snarf(str, &f, 0)) == NOSTR)
		file = Getf("MBOX");
	if (f == -1)
		return (1);
	if (!f) {
		*msgvec = first(0, MMNORM);
		if (*msgvec == 0) {
			printf(gettext("No messages to put.\n"));
			return (1);
		}
		msgvec[1] = 0;
	}
	if (f && getmsglist(str, msgvec, 0) < 0)
		return (1);
	if ((file = expand(file)) == NOSTR)
		return (1);
	savemsglist(file, msgvec, doign);
	return (0);
}

/*
 * save a message list in a file.
 * if wr set, doing "write" instead
 * of "save" or "copy" so don't put
 * out header.
 */

static	int wr_linecount;		/* count of lines written */
static	int wr_charcount;		/* char count of lines written */
static	int wr_inlines;			/* count of lines read */
static	long wr_maxlines;		/* total lines in message */
static	int wr_inhead;			/* in header of message */

static void
savemsglist(char *file, int *msgvec, int flag)
{
	register int *ip, mesg;
	register struct message *mp;
	char *disp;
	FILE *obuf;
	struct stat statb;
	long lc, cc, t;
	int bnry, mflag;

	printf("\"%s\" ", file);
	flush();
	if (stat(file, &statb) >= 0)
		disp = "[Appended]";
	else
		disp = "[New file]";
	if ((obuf = fopen(file, "a")) == NULL) {
		perror("");
		return;
	}
	lc = cc = 0;
	bnry = 0;
	if (flag & S_SAVING)
		mflag = (int)value("alwaysignore")?(M_IGNORE|M_SAVING):M_SAVING;
	else if (flag & S_NOIGNORE)
		mflag = 0;
	else
		mflag = M_IGNORE;
	for (ip = msgvec; *ip && ip-msgvec < msgCount; ip++) {
		mesg = *ip;
		mp = &message[mesg-1];
		if (!mp->m_text) {
			bnry = 1;
		}
		wr_linecount = 0;
		wr_charcount = 0;
		if (flag & S_NOHEADER) {
			wr_inhead = 1;
			wr_maxlines = mp->m_lines;
			wr_inlines = 0;
			t = msend(mp, obuf, 0, wrputs);
		} else {
			t = msend(mp, obuf, mflag, svputs);
		}
		if (t < 0) {
			perror(file);
			fclose(obuf);
			return;
		}
		touch(mesg);
		dot = mp;
		lc += wr_linecount;
		cc += wr_charcount;
		if (flag & S_MARK)
			mp->m_flag |= MSAVED;
	}
	fflush(obuf);
	if (fferror(obuf))
		perror(file);
	fclose(obuf);
	if (!bnry) {
		printf("%s %ld/%ld\n", disp, lc, cc);
	} else {
		printf("%s binary/%ld\n", disp, cc);
	}
}

static int
svputs(const char *line, FILE *obuf)
{
	wr_linecount++;
	wr_charcount += strlen(line);
	return (fputs(line, obuf));
}

static int
wrputs(const char *line, FILE *obuf)
{
	/*
	 * If this is a header line or
	 * the last line, don't write it out.  Since we may add a
	 * "Status" line the line count may be off by one so insist
	 * that the last line is blank before we skip it.
	 */
	wr_inlines++;
	if (wr_inhead) {
		if (strcmp(line, "\n") == 0)
			wr_inhead = 0;
		return (0);
	}
	if (wr_inlines >= wr_maxlines && strcmp(line, "\n") == 0)
		return (0);
	wr_linecount++;
	wr_charcount += strlen(line);
	return (fputs(line, obuf));
}

/*
 * Write the indicated messages at the end of the passed
 * file name, minus header and trailing blank line.
 */

int
swrite(char str[])
{
	register char *file;
	int f, *msgvec;

	msgvec = (int *)salloc((msgCount + 2) * sizeof (*msgvec));
	if ((file = snarf(str, &f, 1)) == NOSTR)
		return (1);
	if (f == -1)
		return (1);
	if ((file = expand(file)) == NOSTR)
		return (1);
	if (!f) {
		*msgvec = first(0, MMNORM);
		if (*msgvec == 0) {
			printf(gettext("No messages to write.\n"));
			return (1);
		}
		msgvec[1] = 0;
	}
	if (f && getmsglist(str, msgvec, 0) < 0)
		return (1);
	savemsglist(file, msgvec, S_MARK|S_NOHEADER);
	return (0);
}

/*
 * Snarf the file from the end of the command line and
 * return a pointer to it.  If there is no file attached,
 * just return NOSTR.  Put a null in front of the file
 * name so that the message list processing won't see it,
 * unless the file name is the only thing on the line, in
 * which case, return 0 in the reference flag variable.
 */

/*
 * The following definitions are used to characterize the syntactic
 * category of the preceding character in the following parse procedure.
 * The variable pc_type assumes these values.
 */

#define	SN_DELIM	1	/* Delimiter (<blank> or line beginning) */
#define	SN_TOKEN	2	/* A part of a token */
#define	SN_QUOTE	4	/* An entire quoted string (ie, "...") */

char *
snarf(char linebuf[], int *flag, int erf)
{
	register char *p;		/* utility pointer */
	register char qc;		/* quotation character to match */
	register unsigned int  pc_type;	/* preceding character type */
	register char *tok_beg;		/* beginning of last token */
	register char *tok_end;		/* end of last token */
	char *line_beg;			/* beginning of line, after */
					/* leading whitespace */

	/*
	 * Skip leading whitespace.
	 */
	for (line_beg = linebuf;
	    *line_beg && any(*line_beg, " \t");
	    line_beg++) {
		/* empty body */
	}
	if (!*line_beg) {
		if (erf) {
			printf(gettext("No file specified.\n"));
		}
		*flag = 0;
		return (NOSTR);
	}
	/*
	 * Process line from left-to-right, 1 char at a time.
	 */
	pc_type = SN_DELIM;
	tok_beg = tok_end = NOSTR;
	p = line_beg;
	while (*p != '\0') {
		if (any(*p, " \t")) {
			/* This character is a DELIMITER */
			if (pc_type & (SN_TOKEN|SN_QUOTE)) {
				tok_end = p - 1;
			}
			pc_type = SN_DELIM;
			p++;
		} else if ((qc = *p) == '"' || qc == '\'') {
			/* This character is a QUOTE character */
			if (pc_type == SN_TOKEN) {
				/* embedded quotation symbols are simply */
				/* token characters. */
				p++;
				continue;
			}
			/* Search for the matching QUOTE character */
			for (tok_beg = p, tok_end = NOSTR, p++;
			    *p != '\0' && *p != qc;
			    p++) {
				if (*p == '\\' && *(p+1) == qc) {
					p++;
				}
			}
			if (*p == '\0') {
				printf(gettext("Syntax error: missing "
				    "%c.\n"), qc);
				*flag = -1;
				return (NOSTR);
			}
			tok_end = p;
			pc_type = SN_QUOTE;
			p++;
		} else {
			/* This character should be a TOKEN character */
			if (pc_type & (SN_DELIM|SN_TOKEN)) {
				if (pc_type & SN_DELIM) {
					tok_beg = p;
					tok_end = NOSTR;
				}
			} else {
				printf(gettext("improper quotes"
				    " at \"%s\".\n"), p);
				*flag = -1;
				return (NOSTR);
			}
			if (*p == '\\' && *++p == '\0') {
				printf(gettext("\'\\\' at "
				    "end of line.\n"));
				*flag = -1;
				return (NOSTR);
			}
			pc_type = SN_TOKEN;
			p++;
		}
	}
	if (pc_type == SN_TOKEN) {
		tok_end = p - 1;
	}
	if (tok_beg != NOSTR && tok_end != NOSTR) {
		if (tok_beg == line_beg) {
			*flag = 0;
		} else {
			tok_beg[-1] = '\0';
			*flag = 1;
		}
		tok_end[1] = '\0';
		return (tok_beg);
	} else {
		if (erf) {
			printf(gettext("No file specified.\n"));
		}
		*flag = 0;
		return (NOSTR);
	}
}

/*
 * Delete messages, then type the new dot.
 */

int
deltype(int msgvec[])
{
	int list[2];
	int lastdot;

	lastdot = dot - &message[0] + 1;
	if (delm(msgvec) >= 0) {
		list[0] = dot - &message[0];
		list[0]++;
		if (list[0] > lastdot) {
			touch(list[0]);
			list[1] = 0;
			return (type(list));
		}
		printf(gettext("At EOF\n"));
		return (0);
	} else {
		printf(gettext("No more messages\n"));
		return (0);
	}
}

/*
 * Delete the indicated messages.
 * Set dot to some nice place afterwards.
 */
int
delm(int *msgvec)
{
	register struct message *mp;
	int *ip, mesg;
	int last;

	last = 0;
	for (ip = msgvec; *ip != 0; ip++) {
		mesg = *ip;
		touch(mesg);
		mp = &message[mesg-1];
		mp->m_flag |= MDELETED|MTOUCH;
		mp->m_flag &= ~(MPRESERVE|MSAVED|MBOX);
		last = mesg;
	}
	if (last != 0) {
		dot = &message[last-1];
		last = first(0, MDELETED);
		if (last != 0) {
			dot = &message[last-1];
			return (0);
		} else {
			dot = &message[0];
			return (-1);
		}
	}

	/*
	 * Following can't happen -- it keeps lint happy
	 */

	return (-1);
}

/*
 * Undelete the indicated messages.
 */
int
undelete(int *msgvec)
{
	register struct message *mp;
	int *ip, mesg;

	for (ip = msgvec; ip-msgvec < msgCount; ip++) {
		mesg = *ip;
		if (mesg == 0)
			return (0);
		touch(mesg);
		mp = &message[mesg-1];
		dot = mp;
		mp->m_flag &= ~MDELETED;
	}
	return (0);
}

/*
 * Add the given header fields to the retained list.
 * If no arguments, print the current list of retained fields.
 */
int
retfield(char *list[])
{
	char field[BUFSIZ];
	register int h;
	register struct ignore *igp;
	char **ap;

	if (argcount(list) == 0)
		return (retshow());
	for (ap = list; *ap != 0; ap++) {
		istrcpy(field, sizeof (field), *ap);

		if (member(field, retain))
			continue;

		h = hash(field);
		if ((igp = (struct ignore *)
		    calloc(1, sizeof (struct ignore))) == NULL) {
			panic("Couldn't allocate memory");
		}
		if ((igp->i_field = (char *)
		    calloc(strlen(field) + 1, sizeof (char))) == NULL) {
			panic("Couldn't allocate memory");
		}
		strcpy(igp->i_field, field);
		igp->i_link = retain[h];
		retain[h] = igp;
		nretained++;
	}
	return (0);
}

/*
 * Print out all currently retained fields.
 */
static int
retshow(void)
{
	register int h, count;
	struct ignore *igp;
	char **ap, **ring;

	count = 0;
	for (h = 0; h < HSHSIZE; h++)
		for (igp = retain[h]; igp != 0; igp = igp->i_link)
			count++;
	if (count == 0) {
		printf(gettext("No fields currently being retained.\n"));
		return (0);
	}
	ring = (char **)salloc((count + 1) * sizeof (char *));
	ap = ring;
	for (h = 0; h < HSHSIZE; h++)
		for (igp = retain[h]; igp != 0; igp = igp->i_link)
			*ap++ = igp->i_field;
	*ap = 0;
	qsort(ring, count, sizeof (char *), igcomp);
	for (ap = ring; *ap != 0; ap++)
		printf("%s\n", *ap);
	return (0);
}

/*
 * Remove a list of fields from the retain list.
 */
int
unretfield(char *list[])
{
	char **ap, field[BUFSIZ];
	register int h, count = 0;
	register struct ignore *ig1, *ig2;

	if (argcount(list) == 0) {
		for (h = 0; h < HSHSIZE; h++) {
			ig1 = retain[h];
			while (ig1) {
				free(ig1->i_field);
				ig2 = ig1->i_link;
				free((char *)ig1);
				ig1 = ig2;
				count++;
			}
			retain[h] = NULL;
		}
		if (count == 0)
			printf(gettext(
			    "No fields currently being retained.\n"));
		nretained = 0;
		return (0);
	}
	for (ap = list; *ap; ap++) {
		istrcpy(field, sizeof (field), *ap);
		h = hash(field);
		for (ig1 = retain[h]; ig1; ig2 = ig1, ig1 = ig1->i_link)
			if (strcmp(ig1->i_field, field) == 0) {
				if (ig1 == retain[h])
					retain[h] = ig1->i_link;
				else
					ig2->i_link = ig1->i_link;
				free(ig1->i_field);
				free((char *)ig1);
				nretained--;
				break;
			}
	}
	return (0);
}

/*
 * Add the given header fields to the ignored list.
 * If no arguments, print the current list of ignored fields.
 */
int
igfield(char *list[])
{
	char field[BUFSIZ];
	register int h;
	register struct ignore *igp;
	char **ap;

	if (argcount(list) == 0)
		return (igshow());
	for (ap = list; *ap != 0; ap++) {
		if (isign(*ap, 0))
			continue;
		istrcpy(field, sizeof (field), *ap);
		h = hash(field);
		if ((igp = (struct ignore *)
		    calloc(1, sizeof (struct ignore))) == NULL) {
			panic("Couldn't allocate memory");
		}
		if ((igp->i_field = (char *)
		    calloc((unsigned)strlen(field) + 1,
		    sizeof (char))) == NULL) {
			panic("Couldn't allocate memory");
		}
		strcpy(igp->i_field, field);
		igp->i_link = ignore[h];
		ignore[h] = igp;
	}
	return (0);
}

/*
 * Print out all currently ignored fields.
 */
static int
igshow(void)
{
	register int h, count;
	struct ignore *igp;
	char **ap, **ring;

	count = 0;
	for (h = 0; h < HSHSIZE; h++)
		for (igp = ignore[h]; igp != 0; igp = igp->i_link)
			count++;
	if (count == 0) {
		printf(gettext("No fields currently being ignored.\n"));
		return (0);
	}
	ring = (char **)salloc((count + 1) * sizeof (char *));
	ap = ring;
	for (h = 0; h < HSHSIZE; h++)
		for (igp = ignore[h]; igp != 0; igp = igp->i_link)
			*ap++ = igp->i_field;
	*ap = 0;
	qsort((char *)ring, (unsigned)count, sizeof (char *), igcomp);
	for (ap = ring; *ap != 0; ap++)
		printf("%s\n", *ap);
	return (0);
}

/*
 * Compare two names for sorting ignored field list.
 */
static int
igcomp(const void *l, const void *r)
{
	return (strcmp(*(char **)l, *(char **)r));
}

/*
 * Remove a list of fields from the ignore list.
 */
int
unigfield(char *list[])
{
	char **ap, field[BUFSIZ];
	register int h, count = 0;
	register struct ignore *ig1, *ig2;

	if (argcount(list) == 0) {
		for (h = 0; h < HSHSIZE; h++) {
			ig1 = ignore[h];
			while (ig1) {
				free(ig1->i_field);
				ig2 = ig1->i_link;
				free((char *)ig1);
				ig1 = ig2;
				count++;
			}
			ignore[h] = NULL;
		}
		if (count == 0)
			printf(gettext("No fields currently being ignored.\n"));
		return (0);
	}
	for (ap = list; *ap; ap++) {
		istrcpy(field, sizeof (field), *ap);
		h = hash(field);
		for (ig1 = ignore[h]; ig1; ig2 = ig1, ig1 = ig1->i_link)
			if (strcmp(ig1->i_field, field) == 0) {
				if (ig1 == ignore[h])
					ignore[h] = ig1->i_link;
				else
					ig2->i_link = ig1->i_link;
				free(ig1->i_field);
				free((char *)ig1);
				break;
			}
	}
	return (0);
}
