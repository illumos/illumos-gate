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
 * Copyright 2014 Joyent, Inc.
 */

/*
 * Copyright (c) 1985, 2010, Oracle and/or its affiliates. All rights reserved.
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

#ifndef _MAILX_DEF_H
#define	_MAILX_DEF_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <termio.h>
#include <setjmp.h>
#include <time.h>
#include <sys/stat.h>
#include <maillock.h>
#include <ctype.h>
#include <errno.h>
#ifndef preSVr4
#include <unistd.h>
#include <stdlib.h>
#include <ulimit.h>
#include <wait.h>
#include <libcmdutils.h>
#endif
#ifdef VMUNIX
#include <sys/wait.h>
#endif
#include "local.h"
#include "uparm.h"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 */

#define	SENDESC		'~'		/* Default escape for sending */
#define	NMLSIZE		1024		/* max names in a message list */
#define	PATHSIZE	1024		/* Size of pathnames throughout */
#define	HSHSIZE		59		/* Hash size for aliases and vars */
#define	HDRFIELDS	3		/* Number of header fields */
#define	LINESIZE	5120		/* max readable line width */
#define	STRINGSIZE	((unsigned)128) /* Dynamic allocation units */
#define	MAXARGC		1024		/* Maximum list of raw strings */
#define	NOSTR		((char *)0)	/* Nill string pointer */
#define	NOSTRPTR	((char **)0)	/* Nill pointer to string pointer */
#define	NOINTPTR	((int *)0)	/* Nill pointer */
#define	MAXEXP		25		/* Maximum expansion of aliases */

/* A nice function to string compare */
#define	equal(a, b)	(strcmp(a, b) == 0)

/* Keep a list of all opened files */
#define	fopen(s, t)	my_fopen(s, t)

/* Delete closed file from the list */
#define	fclose(s)	my_fclose(s)

struct message {
	off_t	m_offset;		/* offset in block of message */
	long	m_size;			/* Bytes in the message */
	long	m_lines;		/* Lines in the message */
	long	m_clen;			/* Content-Length of the mesg   */
	short	m_flag;			/* flags, see below */
	char	m_text;			/* TRUE if the contents is text */
					/* False otherwise		*/
};

typedef struct fplst {
	FILE	*fp;
	struct	fplst	*next;
} NODE;

/*
 * flag bits.
 */

#define	MUSED		(1<<0)		/* entry is used, but this bit isn't */
#define	MDELETED	(1<<1)		/* entry has been deleted */
#define	MSAVED		(1<<2)		/* entry has been saved */
#define	MTOUCH		(1<<3)		/* entry has been noticed */
#define	MPRESERVE	(1<<4)		/* keep entry in sys mailbox */
#define	MMARK		(1<<5)		/* message is marked! */
#define	MODIFY		(1<<6)		/* message has been modified */
#define	MNEW		(1<<7)		/* message has never been seen */
#define	MREAD		(1<<8)		/* message has been read sometime. */
#define	MSTATUS		(1<<9)		/* message status has changed */
#define	MBOX		(1<<10)		/* Send this to mbox, regardless */
#define	MBOXED		(1<<11)		/* message has been sent to mbox */

#define	H_AFWDCNT	1		/* "Auto-Forward-Count:"  */
#define	H_AFWDFROM	2		/* "Auto-Forwarded-From:" */
#define	H_CLEN		3		/* "Content-Length:"	*/
#define	H_CTYPE		4		/* "Content-Type:"	*/
#define	H_DATE		5		/* "Date:"		*/
#define	H_DEFOPTS	6		/* "Default-Options:"	*/
#define	H_EOH		7		/* "End-of-Header:"	*/
#define	H_FROM		8		/* "From "		*/
#define	H_FROM1		9		/* ">From "		*/
#define	H_FROM2		10		/* "From: "		*/
#define	H_MTSID		11		/* "MTS-Message-ID:"	*/
#define	H_MTYPE		12		/* "Message-Type:"	*/
#define	H_MVERS		13		/* "Message-Version:"	*/
#define	H_MSVC		14		/* "Message-Service:"	*/
#define	H_RECEIVED	15		/* "Received:"		*/
#define	H_RVERS		16		/* "Report-Version:"	*/
#define	H_STATUS	17		/* "Status:"		*/
#define	H_SUBJ		18		/* "Subject:"		*/
#define	H_TO		19		/* "To:"		*/
#define	H_TCOPY		20		/* ">To:"		*/
#define	H_TROPTS	21		/* "Transport-Options:"   */
#define	H_UAID		22		/* "UA-Content-ID:"	  */

#define	H_DAFWDFROM	23	/* Hold A-F-F when sending Del. Notf. */
#define	H_DTCOPY	24	/* Hold ">To:" when sending Del. Notf. */
#define	H_DRECEIVED	25	/* Hold Rcvd: when sending Del. Notf. */
#define	H_CONT		26	/* Continuation of previous line */
#define	H_NAMEVALUE	27	/* unrecognized "name: value" hdr line */

/*
 * Format of the command description table.
 * The actual table is declared and initialized
 * in lex.c
 */

struct cmd {
	char	*c_name;		/* Name of command */
	int	(*c_func)(void *);	/* Implementor of the command */
	short	c_argtype;		/* Type of arglist (see below) */
	short	c_msgflag;		/* Required flags of messages */
	short	c_msgmask;		/* Relevant flags of messages */
};

/* can't initialize unions */

#define	c_minargs c_msgflag		/* Minimum argcount for RAWLIST */
#define	c_maxargs c_msgmask		/* Max argcount for RAWLIST */

/*
 * Argument types.
 */

#define	MSGLIST	 0		/* Message list type */
#define	STRLIST	 1		/* A pure string */
#define	RAWLIST	 2		/* Shell string list */
#define	NOLIST	 3		/* Just plain 0 */
#define	NDMLIST	 4		/* Message list, no defaults */

#define	P	040		/* Autoprint dot after command */
#define	I	0100		/* Interactive command bit */
#define	M	0200		/* Legal from send mode bit */
#define	W	0400		/* Illegal when read only bit */
#define	F	01000		/* Is a conditional command */
#define	T	02000		/* Is a transparent command */
#define	R	04000		/* Cannot be called from collect */

/*
 * Oft-used mask values
 */

#define	MMNORM	(MDELETED|MSAVED) /* Look at both save and delete bits */
#define	MMNDEL	MDELETED	/* Look only at deleted bit */

/*
 * Structure used to return a break down of a head
 * line
 */

typedef struct headline {
	custr_t	*hl_from;	/* The name of the sender */
	custr_t	*hl_tty;	/* Its tty string (if any) */
	custr_t	*hl_date;	/* The entire date string */
} headline_t;

#define	GTO	1		/* Grab To: line */
#define	GSUBJECT 2		/* Likewise, Subject: line */
#define	GCC	4		/* And the Cc: line */
#define	GBCC	8		/* And also the Bcc: line */
#define	GDEFOPT	16		/* And the Default-Options: lines */
#define	GNL	32		/* Print blank line after */
#define	GOTHER	64		/* Other header lines */
#define	GMASK	(GTO|GSUBJECT|GCC|GBCC|GDEFOPT|GNL|GOTHER)
				/* Mask of all header lines */
#define	GDEL	128		/* Entity removed from list */
#define	GCLEN	256		/* Include Content-Length header */

/*
 * Structure used to pass about the current
 * state of the user-typed message header.
 */

struct header {
	char	*h_to;			/* Dynamic "To:" string */
	char	*h_subject;		/* Subject string */
	char	*h_cc;			/* Carbon copies string */
	char	*h_bcc;			/* Blind carbon copies */
	char	*h_defopt;		/* Default options */
	char	**h_others;		/* Other header lines */
	int	h_seq;			/* Sequence for optimization */
};

/*
 * Structure of namelist nodes used in processing
 * the recipients of mail and aliases and all that
 * kind of stuff.
 */

struct name {
	struct	name *n_flink;		/* Forward link in list. */
	struct	name *n_blink;		/* Backward list link */
	short	n_type;			/* From which list it came */
	char	*n_name;		/* This fella's name */
	char	*n_full;		/* Full name */
};

/*
 * Structure of a variable node.  All variables are
 * kept on a singly-linked list of these, rooted by
 * "variables"
 */

struct var {
	struct	var *v_link;		/* Forward link to next variable */
	char	*v_name;		/* The variable's name */
	char	*v_value;		/* And it's current value */
};

struct mgroup {
	struct	mgroup *ge_link;	/* Next person in this group */
	char	*ge_name;		/* This person's user name */
};

struct grouphead {
	struct	grouphead *g_link;	/* Next grouphead in list */
	char	*g_name;		/* Name of this group */
	struct	mgroup *g_list;		/* Users in group. */
};

#define	NIL	((struct name *)0)	/* The nil pointer for namelists */
#define	NONE	((struct cmd *)0)	/* The nil pointer to command tab */
#define	NOVAR	((struct var *)0)	/* The nil pointer to variables */
#define	NOGRP	((struct grouphead *)0) /* The nil grouphead pointer */
#define	NOGE	((struct mgroup *)0)	/* The nil group pointer */
#define	NOFP	((struct fplst *)0)	/* The nil file pointer */

#define	TRUE	1
#define	FALSE	0

#define	DEADPERM	0600		/* permissions of dead.letter */
#define	TEMPPERM	0600		/* permissions of temp files */
#define	MBOXPERM	0600		/* permissions of ~/mbox */

#ifndef	MFMODE
#define	MFMODE		0600		/* create mode for `/var/mail' files */
#endif

/*
 * Structure of the hash table of ignored header fields
 */
struct ignore {
	struct ignore	*i_link;	/* Next ignored field in bucket */
	char		*i_field;	/* This ignored field */
};

#ifdef preSVr4
struct utimbuf {
	time_t	actime;
	time_t	modtime;
};
#else
#include	<utime.h>
#endif

/*
 * Token values returned by the scanner used for argument lists.
 * Also, sizes of scanner-related things.
 */

#define	TEOL		0		/* End of the command line */
#define	TNUMBER		1		/* A message number */
#define	TDASH		2		/* A simple dash */
#define	TSTRING		3		/* A string (possibly containing -) */
#define	TDOT		4		/* A "." */
#define	TUP		5		/* An "^" */
#define	TDOLLAR		6		/* A "$" */
#define	TSTAR		7		/* A "*" */
#define	TOPEN		8		/* An '(' */
#define	TCLOSE		9		/* A ')' */
#define	TPLUS		10		/* A '+' */

#define	REGDEP		2		/* Maximum regret depth. */
#define	STRINGLEN	1024		/* Maximum length of string token */

/*
 * Constants for conditional commands.  These describe whether
 * we should be executing stuff or not.
 */

#define	CANY		0		/* Execute in send or receive mode */
#define	CRCV		1		/* Execute in receive mode only */
#define	CSEND		2		/* Execute in send mode only */
#define	CTTY		3		/* Execute if attached to a tty only */
#define	CNOTTY		4		/* Execute if not attached to a tty */

/*
 * Flags for msend().
 */

#define	M_IGNORE	1		/* Do "ignore/retain" processing */
#define	M_SAVING	2		/* Saving to a file/folder */

/*
 * VM/UNIX has a vfork system call which is faster than forking.  If we
 * don't have it, fork(2) will do . . .
 */

#if !defined(VMUNIX) && defined(preSVr4)
#define	vfork()	fork()
#endif
#ifndef	SIGRETRO
#define	sigchild()
#endif


/*
 * 4.2bsd signal interface help...
 */
#ifdef VMUNIX
#define	sigset(s, a)	signal(s, a)
#define	sigsys(s, a)	signal(s, a)
#else
#ifndef preSVr4
/* SVr4 version of sigset() in fio.c */
#define	sigsys(s, a)	signal(s, a)
#define	setjmp(x)	sigsetjmp((x), 1)
#define	longjmp		siglongjmp
#define	jmp_buf		sigjmp_buf
#else
#define	OLD_BSD_SIGS
#endif
#endif

/*
 * Truncate a file to the last character written. This is
 * useful just before closing an old file that was opened
 * for read/write.
 */
#define	trunc(stream)	ftruncate(fileno(stream), (long)ftell(stream))

/*
 * The pointers for the string allocation routines,
 * there are NSPACE independent areas.
 * The first holds STRINGSIZE bytes, the next
 * twice as much, and so on.
 */

#define	NSPACE	25			/* Total number of string spaces */
struct strings {
	char	*s_topFree;		/* Beginning of this area */
	char	*s_nextFree;		/* Next alloctable place here */
	unsigned s_nleft;		/* Number of bytes left here */
};

/* The following typedefs must be used in SVR4 */
#ifdef preSVr4
#ifndef sun
typedef int gid_t;
typedef int uid_t;
typedef int mode_t;
typedef int pid_t;
#endif
#endif

#define	STSIZ	40
#define	TMPSIZ	14
/*
 * Forward declarations of routine types to keep lint and cc happy.
 */

extern int		Copy(int *msgvec);
extern FILE		*Fdopen(int fildes, char *mode);
extern int		Followup(int *msgvec);
extern char		*Getf(register char *s);
extern int		More(int *msgvec);
extern int		Respond(int *msgvec);
extern int		Save(int *msgvec);
extern int		Sendm(char *str);
extern int		Sput(char str[]);
extern int		Type(int *msgvec);
extern void		Verhogen(void);
extern char		*addone(char hf[], char news[]);
extern char		*addto(char hf[], char news[]);
extern void		alter(char name[]);
extern int		alternates(char **namelist);
extern void		announce(void);
extern int		any(int ch, char *str);
extern int		anyof(register char *s1, register char *s2);
extern int		argcount(char **argv);
extern void		assign(char name[], char value[]);
extern int		blankline(const char linebuf[]);
extern struct name	*cat(struct name *n1, struct name *n2);
extern FILE		*collect(struct header *hp);
extern void		commands(void);
extern char		*copy(char *str1, char *str2);
extern int		copycmd(char str[]);
extern int		deassign(register char *s);
extern int		delm(int *msgvec);
extern struct name	*delname(register struct name *np, char name[]);
extern int		deltype(int msgvec[]);
extern char		*detract(register struct name *np, int ntype);
extern int		docomma(char *s);
extern int		dopipe(char str[]);
extern int		dosh(char *str);
extern int		echo(register char **argv);
extern int		editor(int *msgvec);
extern int		edstop(int noremove);
extern struct name	*elide(struct name *names);
extern int		elsecmd(void);
extern int		endifcmd(void);
extern int		execute(char linebuf[], int contxt);
extern char		*expand(char *name);
extern struct name	*extract(char line[], int arg_ntype);
extern int		fferror(FILE *iob);
extern int		field(char str[]);
extern int		file(char **argv);
extern struct grouphead	*findgroup(char name[]);
extern void		findmail(char *name);
extern int		first(int f, int m);
extern void		flush(void);
extern int		folders(char **arglist);
extern int		followup(int *msgvec);
extern int		from(int *msgvec);
extern off_t		fsize(FILE *iob);
extern int		getfold(char *name);
extern int	gethfield(register FILE *f, char linebuf[], register long rem);
extern int	getaline(char *line, int size, FILE *f, int *hasnulls);
extern int	getmessage(char *buf, int *vector, int flags);
extern int	getmsglist(char *buf, int *vector, int flags);
extern int	getname(uid_t uid, char namebuf[]);
extern int	getrawlist(char line[], char **argv, int argc);
extern void	getrecf(char *buf, char *recfile,
		    int useauthor, int sz_recfile);
extern uid_t	getuserid(char name[]);
extern int	grabh(register struct header *hp, int gflags, int subjtop);
extern int	group(char **argv);
extern void	hangup(int);
extern int	hash(char name[]);
extern char	*hcontents(char hfield[]);
extern int	headerp(register char *line);
extern int	headers(int *msgvec);
extern int	headline_alloc(headline_t **);
extern void	headline_free(headline_t *);
extern void	headline_reset(headline_t *);
extern int	help(void);
extern char	*helppath(char *file);
extern char	*hfield(char field[], struct message *mp,
		    char *(*add)(char *, char *));
extern void	holdsigs(void);
extern int	icequal(register char *s1, register char *s2);
extern int	ifcmd(char **argv);
extern int	igfield(char *list[]);
extern int	inc(void);
extern void	inithost(void);
extern int	isdir(char name[]);
extern boolean_t is_headline(const char *);
extern int	ishfield(char linebuf[], char field[]);
extern int	ishost(char *sys, char *rest);
extern int	isign(char *field, int saving);
extern void	istrcpy(char *dest, int dstsize, char *src);
extern void	lcwrite(char *fn, FILE *fi, FILE *fo, int addnl);
extern void	load(char *name);
extern int	loadmsg(char str[]);
extern int	lock(FILE *fp, char *mode, int blk);
extern void	lockmail(void);
extern int	mail(char **people);
extern void	mail1(struct header *hp, int use_to, char *orig_to);
extern void	mapf(register struct name *np, char *from);
extern int	mboxit(int msgvec[]);
extern void	mechk(struct name *names);
extern int	member(register char *realfield,
		    register struct ignore **table);
extern int	messize(int *msgvec);
extern void	minit(void);
extern int	more(int *msgvec);
extern long	msend(struct message *mailp, FILE *obuf,
		    int flag, int (*fp)(const char *, FILE *));
extern int	my_fclose(register FILE *iop);
extern FILE	*my_fopen(char *file, char *mode);
extern char	*nameof(register struct message *mp);
extern char	*netmap(char name[], char from[]);
extern int	newfileinfo(int start);
extern int	next(int *msgvec);
extern int	npclose(FILE *ptr);
extern FILE	*npopen(char *cmd, char *mode);
extern char	*nstrcpy(char *dst, int dstsize, char *src);
extern char	*nstrcat(char *dst, int dstsize, char *src);
extern int	null(char *e);
extern int	outof(struct name *names, FILE *fo);
extern struct name	*outpre(struct name *to);
extern void	panic(char *str);
extern int	parse_headline(const char *, headline_t *);
extern int	pcmdlist(void);
extern int	pdot(void);
extern int	preserve(int *msgvec);
extern void	printgroup(char name[]);
extern void	printhead(int mesg);
extern int	puthead(struct header *hp, FILE *fo, int w, long clen);
extern int	pversion(char *e);
extern void	quit(int noremove);
extern int	readline(FILE *ibuf, char *linebuf);
extern void	receipt(struct message *mp);
extern void	relsesigs(void);
extern int	removefile(char name[]);
extern int	replyall(int *msgvec);
extern int	replysender(int *msgvec);
extern int	respond(int *msgvec);
extern int	retfield(char *list[]);
extern int	rexit(int e);
extern char	*safeexpand(char name[]);
extern void	*salloc(unsigned size);
extern void	*srealloc(void *optr, unsigned size);
extern int	samebody(register char *user, register char *addr,
		    int fuzzy);
extern int	save(char str[]);
extern void	savedead(int s);
extern char	*savestr(char *str);
extern int	schdir(char *str);
extern int	screensize(void);
extern int	scroll(char arg[]);
extern int	sendm(char *str);
extern int	set(char **arglist);
extern void	setclen(register struct message *mp);
extern int	setfile(char *name, int isedit);
extern FILE	*setinput(register struct message *mp);
extern void	setptr(register FILE *ibuf);
extern int	shell(char *str);
#ifndef sigchild
extern void		sigchild(void);
#endif
#ifndef sigset
extern void		(*sigset())();
#endif
extern char		*skin(char *name);
extern char		*snarf(char linebuf[], int *flag, int erf);
extern int		source(char name[]);
extern char		*splice(char *addr, char *hdr);
extern int		sput(char str[]);
extern void		sreset(void);
extern void		stop(int s);
extern int		stouch(int msgvec[]);
extern int		substr(char *string1, char *string2);
extern int		swrite(char str[]);
extern struct name	*tailof(struct name *name);
extern void		tinit(void);
extern int		tmail(void);
extern int		top(int *msgvec);
extern void		touch(int mesg);
extern struct name	*translate(struct name *np);
extern int		type(int *msgvec);
extern int		undelete(int *msgvec);
extern int		ungroup(char **argv);
extern int		unigfield(char *list[]);
extern void		unlockmail(void);
extern char		**unpack(struct name *np);
extern int		unread(int msgvec[]);
extern int		unretfield(char *list[]);
extern int		unset(char **arglist);
extern int		unstack(void);
extern char		*unuucp(char *name);
extern struct name	*usermap(struct name *names);
extern char		*value(char name[]);
extern char		*vcopy(char str[]);
extern void		vfree(register char *cp);
extern int		visual(int *msgvec);
extern char		*yankword(char *name, char *word, int sz, int comma);

/*
 * These functions are defined in libmail.a
 */
#ifdef	__cplusplus
extern "C" {
#endif
extern int		delempty(mode_t, char *);
extern char		*maildomain(void);
extern void		touchlock(void);
extern char		*xgetenv(char *);
extern int		xsetenv(char *);
#ifdef	__cplusplus
}
#endif

/*
 * Standard functions from the C library.
 * These are all defined in <stdlib.h> and <wait.h> in SVr4.
 */
#ifdef preSVr4
extern long		atol();
extern char		*getcwd();
extern char		*calloc();
extern char		*getenv();
extern void		exit();
extern void		free();
extern char		*malloc();
extern time_t		time();
extern long		ulimit();
extern int		utime();
extern int		wait();
extern int		fputs();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _MAILX_DEF_H */
