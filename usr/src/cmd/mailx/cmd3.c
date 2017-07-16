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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
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
 * Still more user commands.
 */

static int	bangexp(char *str);
static int	diction(const void *a, const void *b);
static char	*getfilename(char *name, int *aedit);
static int	resp1(int *msgvec, int useauthor);
static int	Resp1(int *msgvec, int useauthor);
static char	*reedit(char *subj);
static int	shell1(char *str);
static void	sort(char **list);
static char	*replyto(struct message *mp, char **f);
static int	reply2sender(void);

static char	prevfile[PATHSIZE];
static char	origprevfile[PATHSIZE];
static char	lastbang[BUFSIZ];

/*
 * Process a shell escape by saving signals, ignoring signals,
 * and forking a sh -c
 */

int 
shell(char *str)
{
	shell1(str);
	printf("!\n");
	return(0);
}

static int 
shell1(char *str)
{
	void (*sig[2])(int);
	register int t;
	register pid_t p;
	char *Shell;
	char cmd[BUFSIZ];
	
	nstrcpy(cmd, sizeof (cmd), str);
	if (bangexp(cmd) < 0)
		return(-1);
	if ((Shell = value("SHELL")) == NOSTR || *Shell=='\0')
		Shell = SHELL;
	for (t = SIGINT; t <= SIGQUIT; t++)
		sig[t-SIGINT] = sigset(t, SIG_IGN);
	p = vfork();
	if (p == 0) {
		setuid(getuid());
		sigchild();
		for (t = SIGINT; t <= SIGQUIT; t++)
			if (sig[t-SIGINT] != SIG_IGN)
				sigsys(t, SIG_DFL);
		execlp(Shell, Shell, "-c", cmd, (char *)0);
		perror(Shell);
		_exit(1);
	}
	while (wait(0) != p)
		;
	if (p == (pid_t)-1)
		perror("fork");
	for (t = SIGINT; t <= SIGQUIT; t++)
		sigset(t, sig[t-SIGINT]);
	return(0);
}

/*
 * Fork an interactive shell.
 */

int 
#ifdef	__cplusplus
dosh(char *)
#else
/* ARGSUSED */
dosh(char *s)
#endif
{
	void (*sig[2])(int);
	register int t;
	register pid_t p;
	char *Shell;

	if ((Shell = value("SHELL")) == NOSTR || *Shell=='\0')
		Shell = SHELL;
	for (t = SIGINT; t <= SIGQUIT; t++)
		sig[t-SIGINT] = sigset(t, SIG_IGN);
	p = vfork();
	if (p == 0) {
		setuid(getuid());
		sigchild();
		for (t = SIGINT; t <= SIGQUIT; t++)
			if (sig[t-SIGINT] != SIG_IGN)
				sigset(t, SIG_DFL);
		execlp(Shell, Shell, (char *)0);
		perror(Shell);
		_exit(1);
	}
	while (wait(0) != p)
		;
	if (p == (pid_t)-1)
		perror("fork");
	for (t = SIGINT; t <= SIGQUIT; t++)
		sigset(t, sig[t-SIGINT]);
	putchar('\n');
	return(0);
}

/*
 * Expand the shell escape by expanding unescaped !'s into the
 * last issued command where possible.
 */
static int 
bangexp(char *str)
{
	char bangbuf[BUFSIZ];
	register char *cp, *cp2;
	register int n;
	int changed = 0;
	int bangit = (value("bang")!=NOSTR);

	cp = str;
	cp2 = bangbuf;
	n = BUFSIZ;
	while (*cp) {
		if (*cp=='!' && bangit) {
			if (n < (int)strlen(lastbang)) {
overf:
				printf(gettext("Command buffer overflow\n"));
				return(-1);
			}
			changed++;
			strcpy(cp2, lastbang);
			cp2 += strlen(lastbang);
			n -= strlen(lastbang);
			cp++;
			continue;
		}
		if (*cp == '\\' && cp[1] == '!') {
			if (--n <= 1)
				goto overf;
			*cp2++ = '!';
			cp += 2;
			changed++;
		}
		if (--n <= 1)
			goto overf;
		*cp2++ = *cp++;
	}
	*cp2 = 0;
	if (changed) {
		printf("!%s\n", bangbuf);
		fflush(stdout);
	}
	nstrcpy(str, BUFSIZ, bangbuf);
	nstrcpy(lastbang, sizeof (lastbang), bangbuf);
	return(0);
}

/*
 * Print out a nice help message from some file or another.
 */

int 
help(void)
{
	int c;
	register FILE *f;

	if ((f = fopen(HELPFILE, "r")) == NULL) {
		printf(gettext("No help just now.\n"));
		return(1);
	}
	while ((c = getc(f)) != EOF)
		putchar(c);
	fclose(f);
	return(0);
}

/*
 * Change user's working directory.
 */

int 
schdir(char *str)
{
	register char *cp;
	char cwd[PATHSIZE], file[PATHSIZE];
	static char efile[PATHSIZE];

	for (cp = str; *cp == ' '; cp++)
		;
	if (*cp == '\0')
		cp = homedir;
	else
		if ((cp = expand(cp)) == NOSTR)
			return(1);
	if (editfile != NOSTR && (*editfile != '/' || mailname[0] != '/')) {
		if (getcwd(cwd, (int)sizeof (cwd)) == 0) {
			fprintf(stderr,
			    gettext("Can't get current directory: %s\n"), cwd);
			return(1);
		}
	}
	if (chdir(cp) < 0) {
		perror(cp);
		return(1);
	}
	/*
	 * Convert previously relative names to absolute names.
	 */
	if (editfile != NOSTR && *editfile != '/') {
		snprintf(file, sizeof (file), "%s/%s", cwd, editfile);
		nstrcpy(efile, sizeof (efile), file);
		editfile = efile;
	}
	if (mailname[0] != '/') {
		snprintf(file, sizeof (file), "%s/%s", cwd, mailname);
		nstrcpy(mailname, PATHSIZE, file);
	}
	return(0);
}

/*
 * Two versions of reply.  Reply to all names in message or reply
 * to only sender of message, depending on setting of "replyall".
 */

int 
respond(int *msgvec)
{
	if (reply2sender())
		return(resp1(msgvec, 0));
	else
		return(Resp1(msgvec, 0));
}

int 
followup(int *msgvec)
{
	if (reply2sender())
		return(resp1(msgvec, 1));
	else
		return(Resp1(msgvec, 1));
}

int 
replyall(int *msgvec)
{
	return(resp1(msgvec, 0));
}

static int 
resp1(int *msgvec, int useauthor)
{
	struct message *mp;
	char *cp, *buf, *rcv, *skin_rcv, *reply2, **ap, *returnaddr;
	struct name *np;
	struct header head;
	char mylocalname[BUFSIZ], mydomname[BUFSIZ];

	if (msgvec[1] != 0) {
		printf(gettext(
		    "Sorry, can't reply to multiple messages at once\n"));
		return(1);
	}
	snprintf(mydomname, sizeof (mydomname), "%s@%s", myname, domain);
	snprintf(mylocalname, sizeof (mylocalname), "%s@%s", myname, host);
	returnaddr = value("returnaddr");
	
	mp = &message[msgvec[0] - 1];
	dot = mp;
	reply2 = replyto(mp, &rcv);
	cp = skin(hfield("to", mp, addto));
	if (cp != NOSTR) {
		buf = (char *)salloc(strlen(reply2) + strlen(cp) + 2);
		strcpy(buf, reply2);
		strcat(buf, " ");
		strcat(buf, cp);
	} else
		buf = reply2;
	np = elide(extract(buf, GTO));
#ifdef	OPTIM
	/* rcv = netrename(rcv); */
#endif	/* OPTIM */
	/*
	 * Delete my name from the reply list,
	 * and with it, all my alternate names.
	 */
	skin_rcv = skin(rcv);
	mapf(np, skin_rcv);
	np = delname(np, myname);
	np = delname(np, mylocalname);
	np = delname(np, mydomname);
	if (returnaddr && *returnaddr)
		np = delname(np, returnaddr);
	if (altnames != 0)
		for (ap = altnames; *ap; ap++)
			np = delname(np, *ap);
	head.h_seq = 1;
	cp = detract(np, 0);
	if (cp == NOSTR) {
		if (reply2)
			cp = unuucp(reply2);
		else
			cp = unuucp(rcv);
	}
	head.h_to = cp;
	head.h_subject = hfield("subject", mp, addone);
	if (head.h_subject == NOSTR)
		head.h_subject = hfield("subj", mp, addone);
	head.h_subject = reedit(head.h_subject);
	head.h_cc = NOSTR;
	cp = skin(hfield("cc", mp, addto));
	if (cp != NOSTR) {
		np = elide(extract(cp, GCC));
		mapf(np, skin_rcv);
		np = delname(np, myname);
		np = delname(np, mylocalname);
		np = delname(np, mydomname);
		if (returnaddr && *returnaddr)
			np = delname(np, returnaddr);
		np = delname(np, skin_rcv);
		if (altnames != 0)
			for (ap = altnames; *ap; ap++)
				np = delname(np, *ap);
		head.h_cc = detract(np, 0);
	}
	head.h_bcc = NOSTR;
	head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	mail1(&head, useauthor, useauthor ? rcv : NOSTR);
	return(0);
}

void 
getrecf(char *buf, char *recfile, int useauthor, int sz_recfile)
{
	register char *bp, *cp;
	register char *recf = recfile;
	register int folderize;
	char fldr[BUFSIZ];

	folderize = (value("outfolder")!=NOSTR && getfold(fldr) == 0);

	if (useauthor) {
		if (folderize)
			*recf++ = '+';
		if (debug) fprintf(stderr, "buf='%s'\n", buf);
		for (bp=skin(buf), cp=recf; *bp && !any(*bp, ", "); bp++) {
			if (*bp=='!')
				cp = recf;
			else
				*cp++ = *bp;

			if (cp >= &recfile[sz_recfile - 1]) {
				printf(gettext("File name buffer overflow\n"));
				break;
			}
		}
		*cp = '\0';
		if (cp==recf)
			*recfile = '\0';
		/* now strip off any Internet host names */
		if ((cp = strchr(recf, '%')) == NOSTR)
			cp = strchr(recf, '@');
		if (cp != NOSTR)
			*cp = '\0';
	} else {
		if (cp = value("record")) {
			int sz = PATHSIZE;
			if (folderize && *cp!='+' && *cp!='/'
			 && *safeexpand(cp)!='/') {
				*recf++ = '+';
				sz--;
			}
			nstrcpy(recf, sz, cp);
		} else
			*recf = '\0';
	}
	if (debug) fprintf(stderr, "recfile='%s'\n", recfile);
}

/*
 * Modify the subject we are replying to to begin with Re: if
 * it does not already.
 */

static char *
reedit(char *subj)
{
	char sbuf[10];
	register char *newsubj;

	if (subj == NOSTR)
		return(NOSTR);
	strncpy(sbuf, subj, 3);
	sbuf[3] = 0;
	if (icequal(sbuf, "re:"))
		return(subj);
	newsubj = (char *)salloc((unsigned)(strlen(subj) + 5));
	sprintf(newsubj, "Re: %s", subj);
	return(newsubj);
}

/*
 * Preserve the named messages, so that they will be sent
 * back to the system mailbox.
 */

int 
preserve(int *msgvec)
{
	register struct message *mp;
	register int *ip, mesg;

	if (edit) {
		printf(gettext("Cannot \"preserve\" in edit mode\n"));
		return(1);
	}
	for (ip = msgvec; *ip != NULL; ip++) {
		mesg = *ip;
		mp = &message[mesg-1];
		mp->m_flag |= MPRESERVE;
		mp->m_flag &= ~MBOX;
		dot = mp;
	}
	return(0);
}

/*
 * Mark all given messages as unread.
 */
int 
unread(int msgvec[])
{
	register int *ip;

	for (ip = msgvec; *ip != NULL; ip++) {
		dot = &message[*ip-1];
		dot->m_flag &= ~(MREAD|MTOUCH);
		dot->m_flag |= MSTATUS;
	}
	return(0);
}

/*
 * Print the size of each message.
 */

int 
messize(int *msgvec)
{
	register struct message *mp;
	register int *ip, mesg;

	for (ip = msgvec; *ip != NULL; ip++) {
		mesg = *ip;
		mp = &message[mesg-1];
		dot = mp;
		printf("%d: %ld\n", mesg, mp->m_size);
	}
	return(0);
}

/*
 * Quit quickly.  If we are sourcing, just pop the input level
 * by returning an error.
 */

int 
rexit(int e)
{
	if (sourcing)
		return(1);
	if (Tflag != NOSTR)
		close(creat(Tflag, TEMPPERM));
	if (!edit)
		Verhogen();
	exit(e ? e : rpterr);
	/* NOTREACHED */
	return (0);	/* shut up lint and CC */
}

/*
 * Set or display a variable value.  Syntax is similar to that
 * of csh.
 */

int 
set(char **arglist)
{
	register struct var *vp;
	register char *cp, *cp2;
	char varbuf[BUFSIZ], **ap, **p;
	int errs, h, s;

	if (argcount(arglist) == 0) {
		for (h = 0, s = 1; h < HSHSIZE; h++)
			for (vp = variables[h]; vp != NOVAR; vp = vp->v_link)
				s++;
		ap = (char **) salloc(s * sizeof *ap);
		for (h = 0, p = ap; h < HSHSIZE; h++)
			for (vp = variables[h]; vp != NOVAR; vp = vp->v_link)
				*p++ = vp->v_name;
		*p = NOSTR;
		sort(ap);
		for (p = ap; *p != NOSTR; p++)
			if (((cp = value(*p)) != 0) && *cp)
				printf("%s=\"%s\"\n", *p, cp);
			else
				printf("%s\n", *p);
		return(0);
	}
	errs = 0;
	for (ap = arglist; *ap != NOSTR; ap++) {
		cp = *ap;
		cp2 = varbuf;
		while (*cp != '=' && *cp != '\0')
			*cp2++ = *cp++;
		*cp2 = '\0';
		if (*cp == '\0')
			cp = "";
		else
			cp++;
		if (equal(varbuf, "")) {
			printf(gettext("Non-null variable name required\n"));
			errs++;
			continue;
		}
		assign(varbuf, cp);
	}
	return(errs);
}

/*
 * Unset a bunch of variable values.
 */

int 
unset(char **arglist)
{
	register int errs;
	register char **ap;

	errs = 0;
	for (ap = arglist; *ap != NOSTR; ap++)
		errs += deassign(*ap);
	return(errs);
}

/*
 * Add users to a group.
 */

int 
group(char **argv)
{
	register struct grouphead *gh;
	register struct mgroup *gp;
	register int h;
	int s;
	char **ap, *gname, **p;

	if (argcount(argv) == 0) {
		for (h = 0, s = 1; h < HSHSIZE; h++)
			for (gh = groups[h]; gh != NOGRP; gh = gh->g_link)
				s++;
		ap = (char **) salloc(s * sizeof *ap);
		for (h = 0, p = ap; h < HSHSIZE; h++)
			for (gh = groups[h]; gh != NOGRP; gh = gh->g_link)
				*p++ = gh->g_name;
		*p = NOSTR;
		sort(ap);
		for (p = ap; *p != NOSTR; p++)
			printgroup(*p);
		return(0);
	}
	if (argcount(argv) == 1) {
		printgroup(*argv);
		return(0);
	}
	gname = *argv;
	h = hash(gname);
	if ((gh = findgroup(gname)) == NOGRP) {
		if ((gh = (struct grouphead *)
		    calloc(sizeof (*gh), 1)) == NULL) {
			panic("Failed to allocate memory for group");
	}
		gh->g_name = vcopy(gname);
		gh->g_list = NOGE;
		gh->g_link = groups[h];
		groups[h] = gh;
	}

	/*
	 * Insert names from the command list into the group.
	 * Who cares if there are duplicates?  They get tossed
	 * later anyway.
	 */

	for (ap = argv+1; *ap != NOSTR; ap++) {
		if ((gp = (struct mgroup *)
		    calloc(sizeof (*gp), 1)) == NULL) {
			panic("Failed to allocate memory for group");
	}
	gp->ge_name = vcopy(*ap);
		gp->ge_link = gh->g_list;
		gh->g_list = gp;
	}
	return(0);
}

/*
 * Remove users from a group.
 */

int 
ungroup(char **argv)
{
	register struct grouphead *gh, **ghp;
	register struct mgroup *gp, *gpnext;
	register int h;
	char **ap, *gname;

	if (argcount(argv) == 0) {
		printf("Must specify alias or group to remove\n");
		return(1);
	}

	/*
	 * Remove names on the command list from the group list.
	 */

	for (ap = argv; *ap != NOSTR; ap++) {
		gname = *ap;
		h = hash(gname);
		for (ghp = &groups[h]; *ghp != NOGRP; ghp = &((*ghp)->g_link)) {
			gh = *ghp;
			if (equal(gh->g_name, gname)) {
				/* remove from list */
				*ghp = gh->g_link;
				/* free each member of gorup */
				for (gp = gh->g_list; gp != NOGE; gp = gpnext) {
					gpnext = gp->ge_link;
					vfree(gp->ge_name);
					free(gp);
				}
				vfree(gh->g_name);
				free(gh);
				break;
			}
		}
	}
	return(0);
}

/*
 * Sort the passed string vecotor into ascending dictionary
 * order.
 */

static void 
sort(char **list)
{
	register char **ap;

	for (ap = list; *ap != NOSTR; ap++)
		;
	if (ap-list < 2)
		return;
	qsort((char *) list, (unsigned) (ap-list), sizeof *list, diction);
}

/*
 * Do a dictionary order comparison of the arguments from
 * qsort.
 */
static int 
diction(const void *a, const void *b)
{
	return(strcmp(*(char **)a, *(char **)b));
}

/*
 * The do nothing command for comments.
 */

int 
#ifdef	__cplusplus
null(char *)
#else
/* ARGSUSED */
null(char *s)
#endif
{
	return(0);
}

/*
 * Print out the current edit file, if we are editing.
 * Otherwise, print the name of the person who's mail
 * we are reading.
 */
int 
file(char **argv)
{
	register char *cp;
	int editing, mdot;

	if (argv[0] == NOSTR) {
		mdot = newfileinfo(1);
		dot = &message[mdot - 1];
		return(0);
	}

	/*
	 * Acker's!  Must switch to the new file.
	 * We use a funny interpretation --
	 *	# -- gets the previous file
	 *	% -- gets the invoker's post office box
	 *	%user -- gets someone else's post office box
	 *	& -- gets invoker's mbox file
	 *	string -- reads the given file
	 */

	cp = getfilename(argv[0], &editing);
	if (cp == NOSTR)
		return(-1);
	if (setfile(cp, editing)) {
		nstrcpy(origname, PATHSIZE, origprevfile);
		return(-1);
	}
	mdot = newfileinfo(1);
	dot = &message[mdot - 1];
	return(0);
}

/*
 * Evaluate the string given as a new mailbox name.
 * Ultimately, we want this to support a number of meta characters.
 * Possibly:
 *	% -- for my system mail box
 *	%user -- for user's system mail box
 *	# -- for previous file
 *	& -- get's invoker's mbox file
 *	file name -- for any other file
 */

static char *
getfilename(char *name, int *aedit)
{
	register char *cp;
	char savename[BUFSIZ];
	char oldmailname[BUFSIZ];
	char tmp[BUFSIZ];

	/*
	 * Assume we will be in "edit file" mode, until
	 * proven wrong.
	 */
	*aedit = 1;
	switch (*name) {
	case '%':
		*aedit = 0;
		nstrcpy(prevfile, sizeof (prevfile), editfile);
		nstrcpy(origprevfile, sizeof (origprevfile), origname);
		if (name[1] != 0) {
			nstrcpy(oldmailname, sizeof (oldmailname), mailname);
			findmail(name+1);
			cp = savestr(mailname);
			nstrcpy(origname, PATHSIZE, cp);
			nstrcpy(mailname, PATHSIZE, oldmailname);
			return(cp);
		}
		nstrcpy(oldmailname, sizeof (oldmailname), mailname);
		findmail(NULL);
		cp = savestr(mailname);
		nstrcpy(mailname, PATHSIZE, oldmailname);
		nstrcpy(origname, PATHSIZE, cp);
		return(cp);

	case '#':
		if (name[1] != 0)
			goto regular;
		if (prevfile[0] == 0) {
			printf(gettext("No previous file\n"));
			return(NOSTR);
		}
		cp = savestr(prevfile);
		nstrcpy(prevfile, sizeof (prevfile), editfile);
		nstrcpy(tmp, sizeof (tmp), origname);
		nstrcpy(origname, PATHSIZE, origprevfile);
		nstrcpy(origprevfile, sizeof (origprevfile), tmp);
		return(cp);

	case '&':
		nstrcpy(prevfile, sizeof (prevfile), editfile);
		nstrcpy(origprevfile, sizeof (origprevfile), origname);
		if (name[1] == 0) {
			cp=Getf("MBOX");
			nstrcpy(origname, PATHSIZE, cp);
			return(cp);
		}
		/* FALLTHROUGH */

	default:
regular:
		nstrcpy(prevfile, sizeof (prevfile), editfile);
		nstrcpy(origprevfile, sizeof (origprevfile), origname);
		cp = safeexpand(name);
		nstrcpy(origname, PATHSIZE, cp);
		if (cp[0] != '/') {
			name = getcwd(NOSTR, PATHSIZE);
			nstrcat(name, PATHSIZE, "/");
			nstrcat(name, PATHSIZE, cp);
			cp = name;
		}
		return(cp);
	}
}

/*
 * Expand file names like echo
 */

int 
echo(register char **argv)
{
	register char *cp;
	int neednl = 0;

	while (*argv != NOSTR) {
		cp = *argv++;
		if ((cp = expand(cp)) != NOSTR) {
			neednl++;
			printf("%s", cp);
			if (*argv!=NOSTR)
				putchar(' ');
		}
	}
	if (neednl)
		putchar('\n');
	return(0);
}

/*
 * Reply to a series of messages by simply mailing to the senders
 * and not messing around with the To: and Cc: lists as in normal
 * reply.
 */

int 
Respond(int *msgvec)
{
	if (reply2sender())
		return(Resp1(msgvec, 0));
	else
		return(resp1(msgvec, 0));
}

int 
Followup(int *msgvec)
{
	if (reply2sender())
		return(Resp1(msgvec, 1));
	else
		return(resp1(msgvec, 1));
}

int 
replysender(int *msgvec)
{
	return(Resp1(msgvec, 0));
}

static int 
Resp1(int *msgvec, int useauthor)
{
	struct header head;
	struct message *mp;
	register int s, *ap;
	register char *cp, *cp2, *subject;

	for (s = 0, ap = msgvec; *ap != 0; ap++) {
		mp = &message[*ap - 1];
		dot = mp;
		cp = replyto(mp, NOSTRPTR);
		s += strlen(cp) + 1;
	}
	if (s == 0)
		return(0);
	cp = (char *)salloc(s + 2);
	head.h_to = cp;
	for (ap = msgvec; *ap != 0; ap++) {
		mp = &message[*ap - 1];
		cp2 = replyto(mp, NOSTRPTR);
		cp = copy(cp2, cp);
		*cp++ = ' ';
	}
	*--cp = 0;
	mp = &message[msgvec[0] - 1];
	subject = hfield("subject", mp, addone);
	head.h_seq = 1;
	if (subject == NOSTR)
		subject = hfield("subj", mp, addone);
	head.h_subject = reedit(subject);
	if (subject != NOSTR)
		head.h_seq++;
	head.h_cc = NOSTR;
	head.h_bcc = NOSTR;
	head.h_defopt = NOSTR;
	head.h_others = NOSTRPTR;
	mail1(&head, useauthor, NOSTR);
	return(0);
}

/*
 * Conditional commands.  These allow one to parameterize one's
 * .mailrc and do some things if sending, others if receiving.
 */

int 
ifcmd(char **argv)
{
	register char *cp;

	if (cond != CANY) {
		printf(gettext("Illegal nested \"if\"\n"));
		return(1);
	}
	cond = CANY;
	cp = argv[0];
	switch (*cp) {
	case 'r': case 'R':
		cond = CRCV;
		break;

	case 's': case 'S':
		cond = CSEND;
		break;

	case 't': case 'T':
		cond = CTTY;
		break;

	default:
		printf(gettext("Unrecognized if-keyword: \"%s\"\n"), cp);
		return(1);
	}
	return(0);
}

/*
 * Implement 'else'.  This is pretty simple -- we just
 * flip over the conditional flag.
 */

int 
elsecmd(void)
{

	switch (cond) {
	case CANY:
		printf(gettext("\"Else\" without matching \"if\"\n"));
		return(1);

	case CSEND:
		cond = CRCV;
		break;

	case CRCV:
		cond = CSEND;
		break;

	case CTTY:
		cond = CNOTTY;
		break;

	case CNOTTY:
		cond = CTTY;
		break;

	default:
		printf(gettext("invalid condition encountered\n"));
		cond = CANY;
		break;
	}
	return(0);
}

/*
 * End of if statement.  Just set cond back to anything.
 */

int 
endifcmd(void)
{

	if (cond == CANY) {
		printf(gettext("\"Endif\" without matching \"if\"\n"));
		return(1);
	}
	cond = CANY;
	return(0);
}

/*
 * Set the list of alternate names.
 */
int 
alternates(char **namelist)
{
	register int c;
	register char **ap, **ap2, *cp;

	c = argcount(namelist) + 1;
	if (c == 1) {
		if (altnames == 0)
			return(0);
		for (ap = altnames; *ap; ap++)
			printf("%s ", *ap);
		printf("\n");
		return (0);
	}
	if (altnames != 0)
		free((char *)altnames);
	if ((altnames = (char **)
	    calloc((unsigned)c, sizeof (char *))) == NULL)
		panic("Failed to allocate memory");
	for (ap = namelist, ap2 = altnames; *ap; ap++, ap2++) {
		if ((cp = (char *)
		    calloc((unsigned)strlen(*ap) + 1, sizeof (char))) == NULL)
			panic("Failed to allocate memory");
		strcpy(cp, *ap);
		*ap2 = cp;
	}
	*ap2 = 0;
	return(0);
}

/*
 * Figure out who to reply to.
 * Return the real sender in *f.
 */
static char *
replyto(struct message *mp, char **f)
{
	char *r, *rf;

	if ((rf = skin(hfield("from", mp, addto)))==NOSTR)
		rf = skin(addto(NOSTR, nameof(mp)));
	if ((r = skin(hfield("reply-to", mp, addto)))==NOSTR)
		r = rf;
	if (f)
		*f = rf;
	return (r);
}

/* 
 * reply2sender - determine whether a "reply" command should reply to the
 *                sender of the messages, or to all the recipients of the
 *                message.                
 *
 *                With the advent of POSIX.2 compliance, this has become
 *                a bit more complicated, and so should be done in one
 *                place, for all to use.
 */

static int
reply2sender (void)
{
	register int rep = (value("replyall") != NOSTR);
	register int flp = (value("flipr") != NOSTR);

	return((rep && !flp)|| (!rep && flp));
}
