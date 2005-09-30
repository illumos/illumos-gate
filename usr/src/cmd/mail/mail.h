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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _MAIL_H
#define	_MAIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

 /*
  * All global externs defined here. All variables are initialized
  * in init.c
  *
  * !!!!!IF YOU CHANGE (OR ADD) IT HERE, DO IT THERE ALSO !!!!!!!!
  *
  */
#include	<errno.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<errno.h>
#include	<pwd.h>
#include	<signal.h>
#include	<string.h>
#include	<grp.h>
/* The following is a kludge to allow for inconsistent header files in SVR4 */
#define		_CLOCK_T
#include	<time.h>
#include	<sys/stat.h>
#include	<setjmp.h>
#include	<sys/utsname.h>
#include        <limits.h>

#ifdef SVR3
   struct utimbuf {
	time_t	actime;
	time_t	modtime;
   };
#else
#  include	<utime.h>
#endif
#include	"libmail.h"

/* The following typedefs must be used in SVR4 */
#ifdef SVR3
# ifndef sun
typedef int gid_t;
typedef int uid_t;
# endif
typedef int pid_t;
#endif

#define CHILD		0
#define SAME		0

#define	BELL		07

#   define	PIPER	"/usr/lib/mail/mail_pipe"

#define SENDMAIL "/usr/lib/sendmail"

#define CERROR		-1
#define CSUCCESS	0

#define TRUE	1
#define FALSE	0

#define	HEAD	1
#define TAIL	0

#define	REAL	1
#define DEFAULT	0

/* findSurg() return values */
#define	NOMATCH		-1
#define	DELIVER		0
#define	POSTDELIVER	1
#define	DENY		2
#define	TRANSLATE	3

/* sendsurg() return values */
#define	FAILURE		0
#define	CONTINUE	1
#define	SUCCESS		2
/*	TRANSLATE	3 */

#define	HDRSIZ	1024	/* maximum length of header line */

#define E_FLGE	1	/* flge error */
#define E_FLGE_OM 2	/* flgE error, mail present but already accessed */
#define	E_REMOTE 1	/* unknown remote */
#define E_FILE	2	/* file error */
#define E_SPACE	3	/* no space */
#define E_FRWD	4	/* cannot forward */
#define E_SYNTAX 5      /* syntax error */
#define E_FRWL	6	/* forwarding loop */
#define E_SNDR  7	/* invalid sender */
#define E_USER  8	/* invalid user */
#define E_FROM  9	/* too many From lines */
#define E_PERM  10 	/* bad permissions */
#define E_MBOX  11 	/* mbox problem */
#define E_TMP	12 	/* temporary file problem */
#define E_DEAD  13 	/* Cannot create dead.letter */
#define E_UNBND 14 	/* Unbounded forwarding */
#define E_LOCK  15 	/* cannot create lock file */
#define E_GROUP	16	/* no group id of 'mail' */
#define	E_MEM	17	/* malloc failure */
#define E_FORK	18	/* could not fork */
#define	E_PIPE	19	/* could not pipe */
#define	E_OWNR	20	/* invoker does not own mailfile */
#define	E_DENY	21	/* permission denied by mailsurr file */
#define E_SURG	22	/* surrogate command failed - rc != 0 || 99 */

#define	H_AFWDCNT		1	/* "Auto-Forward-Count:"  */
#define	H_AFWDFROM		2	/* "Auto-Forwarded-From:" */
#define	H_CLEN			3	/* "Content-Length:"      */
#define	H_CTYPE			4	/* "Content-Type:"        */
#define	H_DATE			5	/* "Date:" 		  */
#define	H_DEFOPTS		6	/* "Default-Options:" 	  */
#define	H_EOH			7	/* "End-of-Header:" 	  */
#define	H_FROM			8	/* "From " 		  */
#define	H_FROM1			9	/* ">From " 		  */
#define	H_FROM2			10	/* "From: " 		  */
#define	H_MIMEVERS		11	/* "MIME-Version:"        */
#define	H_MTSID			12	/* "MTS-Message-ID:" 	  */
#define	H_MTYPE			13	/* "Message-Type:" 	  */
#define	H_MVERS			14	/* "Message-Version:" 	  */
#define	H_MSVC			15	/* "Message-Service:" 	  */
#define	H_RECEIVED		16	/* "Received:"	 	  */
#define	H_RVERS			17	/* "Report-Version:" 	  */
#define	H_SUBJ			18	/* "Subject:" 		  */
#define	H_TO			19	/* "To:" 		  */
#define	H_TCOPY			20	/* ">To:" 		  */
#define	H_TROPTS		21	/* "Transport-Options:"   */
#define	H_UAID			22	/* "UA-Content-ID:"	  */
#define	H_DAFWDFROM		23	/* Hold A-F-F when sending Del. Notf. */
#define	H_DTCOPY		24	/* Hold ">To:" when sending Del. Notf.*/
#define	H_DRECEIVED		25	/* Hold Rcvd: when sending Del. Notf.*/
#define	H_CONT			26	/* Continuation of previous line */
#define	H_NAMEVALUE		27	/* unrecognized "name: value" hdr line*/

/* MTA Transport Options */
#define	DELIVERY	001
#define	NODELIVERY	002
#define	REPORT		010
#define	RETURN		020
#define	IGNORE		040

/*
	copylet flags
*/
#define	REMOTE		1		/* remote mail, add rmtmsg */
#define ORDINARY	2
#define ZAP		3		/* zap header and trailing empty line */
#define FORWARD		4
#define TTY		5		/* suppress binary to tty */

#define	LSIZE		(2*BUFSIZ)	/* maximum size of a line */
#define	MAXLET		1000		/* maximum number of letters */
#define FROMLEVELS	20		/* maxium number of forwards */
#ifdef FILENAME_MAX
# define MAXFILENAME	FILENAME_MAX	/* max length of a filename */
#else
# define MAXFILENAME	512		/* max length of a filename */
#endif
#define DEADPERM	0600		/* permissions of dead.letter */

#ifndef	MFMODE
#define	MFMODE		0660		/* create mode for `/var/mail' files */
#endif

#define A_OK		0		/* return value for access */
#define A_EXECUTE	1
#define A_EXIST		0		/* access check for existence */
#define A_WRITE		2		/* access check for write permission */
#define A_READ		4		/* access check for read permission */

#  define MAILSURR "/etc/mail/mailsurr"
#  define MAILCNFG "/etc/mail/mailcnfg"

struct hdr {
	char	*tag;
	int	default_display;
};

struct hdrs {
	struct	hdrs	*next;
	struct	hdrs	*prev;
	struct	hdrs	*cont;	/* Continuation lines */
		char	value[HDRSIZ+1];
};

struct hdrlines {
	struct	hdrs	*head;
	struct	hdrs	*tail;
};

typedef struct recip {
	struct recip	*next;
	char		*name;
} recip;

typedef struct reciplist {
	recip *last_recip;
	recip recip_list;
} reciplist;

struct let {
	long	adr;		/* offset in mailfile of letter n */
	char	change;		/* disposition status of letter n */
	char	text;		/* 1 ==> text content, 0 ==> binary content.
				 * This is determined INDEPENDENTLY of what
				 * the Content-type, if present, says...
				 */
};

typedef enum t_surrtype
{
    t_eof, t_transport = '<',
    t_accept = 'a', t_deny = 'd',
    t_translate = 't', t_postprocess = '>'
} t_surrtype;

typedef struct t_surrfile
{
    /* originator's regular expression */
    string *orig_pattern;
    char *orig_regex;
    int orig_reglen;
    int orig_nbra;

    /* recipient's regular expression */
    string *recip_pattern;
    char *recip_regex;
    int recip_reglen;
    int recip_nbra;

    /* the type of the command string */
    t_surrtype surr_type;

    int batchsize;	/* transport	translate	postprocess */
    char *statlist;	/* transport				    */
    string *cmd_left;	/* transport	translate	postprocess */
    string *cmd_right;	/* transport	translate	postprocess */
    int fullyresolved;	/*		translate		    */
} t_surrfile;

#include <stdlib.h>
#include <unistd.h>

extern	void	Dout(char *subname, int level, char *fmt, ...);
extern	void	Tout(char *subname, char *msg, ...);
extern	int	add_recip(reciplist *plist, char *name, int checkdups);
extern	char	*altcompile(const char *instring, char *expbuf, char *endbuf);
extern	int	areforwarding(char *mailfile);
extern	void	cat(char*, char*, char*);
extern	int	ckdlivopts(int tcopy_hdr, int *svopts);
extern	void	cksaved(char *user);
extern	int	cksurg_rc(int surr_num, int rc);
extern	void	clr_hinfo(void);
extern	void	clrhdr(int hdrtype);
extern	void	cmdexpand(int letnum, string *instr, string *outstr, char **lbraslist, char **lbraelist);
extern	void	copyback(void);
extern	int	copylet(int letnum, FILE *f, int type);
extern	void	copymt(FILE *f1, FILE *f2);
extern	void	createmf(uid_t uid, char *file);
extern	void	del_reciplist (reciplist *list);
extern	void	delete(int);
extern	void	doFopt(void);
extern	void	done(int) __NORETURN;
extern	void	sig_done(int);
extern	FILE	*doopen(char *file, char *type, int errnum);
extern	int	dowait(pid_t pidval);
extern	void	dumpaff(int type, int htype, int *didafflines, int *suppress, FILE *f);
extern	void	dumprcv(int type, int htype, int *didrcvlines, int *suppress, FILE *f);
extern	void	errmsg(int error_value, char *error_message);
extern	int	findSurg(int letnum, string *execbuf, int flag, int *psurr_num, int *paccept, string *lorig, string *lrecipname);
extern	void	gendeliv(FILE *fp, int rc, char *name);
extern	int	getcomment(char *s, char *q);
extern	int	gethead(int	current, int all);
extern	int	getline(char *ptr2line, int max, FILE *f);
extern	int	getnumbr(char *s);
extern	int	getsurr(FILE *fp, string *buf, int firstfield);
extern	void	goback(int letnum);
extern	int	init(void);
extern	void	initsurrfile(void);
extern	int	isheader(char *lp, int *ctfp);
extern	int	isit(char *lp, int type);
extern	int	islocal(char *user, uid_t *puid);
extern	int	istext(unsigned char *s, int size);
extern	int	legal(char *file);
extern	void	lock(char	*user);
extern	void	madd_recip(reciplist *plist, char *name, int checkdups);
extern	char	*mailcompile(string *pattern, int *retlen, int *retnbra);
extern	void	mkdead(void);
extern	void	mktmp(void);
extern	void	mta_ercode(FILE *outfile);
extern	void	new_reciplist (reciplist *list);
extern	int	notme(char *fto, char *myname);
extern	int	parse(int argc, char **argv);
extern	int	pckaffspot(void);
extern	int	pckrcvspot(void);
extern	void	pickFrom(char *lineptr);
extern	int	pipletr(int letter, char *command, int cltype);
extern	void	poplist (int hdrtype, int where);
extern	int	printhdr (int type, int hdrtype, struct hdrs *hptr, FILE *fp);
extern	void	printmail(void);
extern	void	pushlist(int hdrtype, int where, char *s, int contflg);
extern	void	savdead(void);
extern	void	savehdrs(char *s, int hdrtype);
extern	int	sel_disp (int type, int hdrtype, char *s);
extern	int	sendlist(reciplist *list, int letnum, int level);
extern	void	sendmail(int argc, char **argv);
extern	int	sendsurg(reciplist *plist, int  letnum, int flag, int local);
extern	void	setletr(int letter, int status);
extern	void	(*setsig(int i, void(*f)()))();
extern	void	setsurg_bt(string *st, int *pbatchsize, int *presolved);
extern	char	*setsurg_rc(string *st, int defreal, int *pbatchsize);
extern	char	**setup_exec(char*);
extern	void	stamp(void);
extern	int	systm(char *s);
extern	void	tmperr(void);
extern	string	*tokdef(string *fld, string *tok, char *name);
extern	int	translate(reciplist *plist, char *cmdstr, char *origname);
extern	void	unlock(void);
extern	int	validmsg(int);
extern	int	wtmpf(char *str, int length);

extern	int	ac;		/* argument list count */
extern	char	**av;		/* argument list */
extern	int	affbytecnt;     /* Total bytes of Auto-Fwd. info in msg. */
extern	int	affcnt;		/* Number of Auto-Fwd.-From: lines in msg. */
extern	int	Daffbytecnt;    /* Hold affbytecnt when sending Deliv. Notif. */
extern	int	Daffcnt;	/* Hold affcnt when sending Deliv. Notif. */
extern	char	binmsg[];
extern	int	changed;	/* > 0 says mailfile has changed */
extern	char	datestring[60];
extern	char	dbgfname[20];	/* name of file for debugging output */
extern	FILE	*dbgfp;		/* FILE* for debugging output */
extern	char	dead[];		/* name of dead.letter */
extern	int	debug;		/* Controls debugging level. 0 ==> no debugging */
extern	int	delflg;
extern	int	dflag;		/* 1 says returning unsendable mail */
extern	char	*errlist[];
extern	int	error;		/* Local value for error */
extern	char	*failsafe;	/* $FAILSAFE */
extern	int	file_size;
extern	int	flge;		/* 1 ==> 'e' option specified */
extern  int     flgE;		/* 1 ==> 'E' option specified */
extern	int	flgF;		/* 1 ==> Installing/Removing  Forwarding */
extern	int	flgf;		/* 1 ==> 'f' option specified */
extern	int	flgh;		/* 1 ==> 'h' option specified */
extern	int	flgm;
extern	int	flgp;		/* 1 ==> 'p' option specified */
extern	int	flgP;		/* 1 ==> 'P' option specified */
extern	int	flgr;		/* 1 ==> 'r' option -- print in fifo order */
extern	int	flgt;		/* 1 ==> 't' option -- add To: line to letter */
extern	int	flgT;		/* 1 ==> 'T' option specified */
extern	int	flgw;		/* 1 ==> 'w' option specified */
extern	int	fnuhdrtype;	/* type of first non-UNIX header line */
extern	char	forwmsg[];	/* " forwarded by %s" */
extern	char	frwlmsg[];	/* "Forwarding loop detected in mailfile" */
extern	char	fromS[1024];	/* stored here by sendmail for sendsurg */
extern	char	fromU[1024];	/* stored here by sendmail for sendsurg */
extern	char	frwrd[];	/* forwarding sentinel */
extern	char	fwdFrom[1024];
extern	int	goerr;		/* counts parsing errors */
extern	struct	group *grpptr;	/* pointer to struct group */
extern	struct hdrlines hdrlines[H_CONT];
extern	struct hdr header[];	/* H_* #define's used to index into array */
extern	char	*help[];
extern	char	*hmbox;		/* pointer to $HOME/mbox */
extern	char	*hmdead;	/* pointer to $HOME/dead.letter */
extern	char	*home;		/* pointer to $HOME */
extern	time_t	iop;
extern	int	interactive;	/* 1 says user is interactive */
extern	int	ismail;		/* default to program=mail */
extern  int     deliverflag;     /* -d flag, bypass sendmail and go to mbox */
extern  int     fromflag;       /* -f from_user while sending */
extern	int	keepdbgfile;	/* does debug file get deleted at end? */
extern	struct let let[MAXLET];
extern	char	*lettmp;	/* pointer to tmp filename */
extern	char	lfil[MAXFILENAME];
extern	char	line[LSIZE];	/* holds a line of a letter in many places */
extern	char	*mailfile;	/* pointer to mailfile */
extern	char	mailcnfg[];	/* /etc/mail/mailcnfg */
extern	char	maildir[];	/* directory for mail files */
extern	gid_t	mailgrp;	/* numeric id of group 'mail' */
extern	char	mailsave[];	/* dir for save files */
extern	char	*mailsurr;	/* surrogate file name */
extern	FILE	*malf;		/* File pointer for mailfile */
extern	int	maxerr;		/* largest value of error */
extern	char	mbox[];		/* name for mbox */
extern	uid_t	mf_uid;		/* uid of user's mailfile */
extern	gid_t	mf_gid;		/* gid of user's mailfile */
extern	char	*msgtype;
extern	char	my_name[1024];	/* user's name who invoked this command */
extern	char	from_user[1024];/* name of user mail's from, used w/ -f */
extern	uid_t	my_euid;	/* user's euid */
extern	gid_t	my_egid;	/* user's egid */
extern	uid_t	my_uid;		/* user's uid */
extern	gid_t	my_gid;		/* user's gid */
extern	int	nlet;		/* current number of letters in mailfile */
extern	int	onlet;		/* number of letters in mailfile at startup*/
extern	int	optcnt;		/* Number of options specified */
extern	int	orig_aff;	/* orig. msg. contained H_AFWDFROM lines */
extern	int	orig_dbglvl;	/* argument to -x invocation option */
extern	int	orig_rcv;	/* orig. msg. contained H_RECEIVED lines */
extern	int	orig_tcopy;	/* orig. msg. contained H_TCOPY lines */
extern	struct	passwd *pwd;	/* holds passwd entry for this user */
extern	int	pflg;		/* binary message display override flag */
extern	int	Pflg;		/* Selective display flag; 1 ==> display all */
extern	char	*program;	/* program name */
extern	int	rcvbytecnt;     /* Total bytes of Received: info in msg. */
extern	int	Drcvbytecnt;    /* Hold rcvbytecnt when sending Del. Notif. */
extern	char	*recipname;	/* full recipient name/address */
extern	int	replying;	/* 1 says we are replying to a letter */
extern	char	RFC822datestring[60];/* Date in RFC822 date format */
extern	char	rmtmsg[];	/* "remote from %s" */
extern	char	Rpath[1024];	/* return path to sender of message */
extern	char	rtrnmsg[];	/* "UNDELIVERABLE MAIL being returned by %s" */
extern	int	sav_errno;
extern	char	savefile[MAXFILENAME];	/* holds filename of save file */
extern	void	(*saveint)(int);
extern	char	*seldisp[];
extern	int	sending;	/* TRUE==>sending mail; FALSE==>printing mail */
extern	char	m_sendto[1024];
extern	jmp_buf	sjbuf;
extern	int	surg_rc;	/* exit code of surrogate command */
extern	t_surrfile *surrfile;	/* the compiled surrogate file */
extern	int	surr_len;	/* # entries in surrogate file */
extern	char	*SURRcmdstr;	/* save in case of FAILURE */
extern	FILE	*SURRerrfile;	/* stderr from surrogate in case of failure */
extern	char	*thissys;	/* Holds name of the system we are on */
extern	FILE	*tmpf;		/* file pointer for temporary files */
extern	mode_t	umsave;
extern	struct	utsname utsn;
extern	struct utimbuf *utimep;
extern	char	uval[1024];

#ifdef NOTDEF
#ifdef sun
#define _NFILE getdtablesize()
#endif
#endif /* NOTDEF */

#endif /* _MAIL_H */
