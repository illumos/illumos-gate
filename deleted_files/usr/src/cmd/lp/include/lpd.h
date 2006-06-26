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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/
#define LPDNET			"lpd"

/* 
 *  buffer sizes
 */

#define CFSIZE_INIT		BUFSIZ
#define CFSIZE_INC		(BUFSIZ/2)
#define LOGBUFSZ		1024

#define MAX_LPD_FILES	52	/* Max# of files per LPD print req. */
#define MAX_SV_SPFN_SZ	50	/* Maximum size of SVr4 spool file name */
#define MAX_LPD_SPFN_SZ	50	/* Maximum size of LPD spool file name */
#define MAX_REQID_SZ	50	/* Maximum size of SVr4 request-id */

#ifdef SYS_NMLN
#define HOSTNM_LEN	SYS_NMLN	/* Host name length */
#else
#define HOSTNM_LEN	50
#endif
/*
 * LPD Protocol Definitions
 */
#define PRINTJOB	'\1'
#define RECVJOB		'\2'
#define RECVJOB_2NDARY	'\6'
#define 	CLEANUP		'\1'
#define 	READCFILE	'\2'
#define 	READDFILE	'\3'
#define DISPLAYQS	'\3'
#define DISPLAYQL	'\4'
#define RMJOB		'\5'

#define LPD_PROTO_MSG(c) ((c) >= PRINTJOB && (c) <= RMJOB)

#define ACKBYTE	'\0'
#if defined(BUG_1133272)
#define ACK()	(void)write(CIP->fd, "", 1)
#define NAK1()	(void)write(CIP->fd, "\1", 1)
#define NAK2()	(void)write(CIP->fd, "\2", 1)
#define ACK_SENT()	(write(CIP->fd, "", 1) == 1)
#else
#define ACK()	(void)TLIWrite(CIP->fd, "", 1)
#define NAK1()	(void)TLIWrite(CIP->fd, "\1", 1)
#define NAK2()	(void)TLIWrite(CIP->fd, "\2", 1)
#define ACK_SENT()	(TLIWrite(CIP->fd, "", 1) == 1)
#endif /* BUG_1133272 */

/*
 * Maximum number of user and job requests for lpq and lprm.
 */
#define MAXUSERS	50	/* Max# of users in LPD protocol message */
#define MAXREQUESTS	50	/* Max# of jobids in LPD protocol message */

/*
 * Macros to parse LPD-style spool file name
 */
#define LPD_FILEX(cp)		(*((cp)+2))
#define LPD_JOBID(cp)		((cp)+3)
#define LPD_HOSTNAME(cp)	((cp)+6)
#define LPD_FILENO(cp)	(LPD_FILEX(cp) > 'Z' ?	LPD_FILEX(cp)-'a'+26 : \
						LPD_FILEX(cp)-'A')
#define LPD_FILEID(n)	((n) > 25 ? 'a'+(n)-26 : 'A'+(n))	/* 0=A, 26=a */
#define SIZEOF_JOBID		3
#define NJOBIDS			1000

/*
 * cf file key characters
 */
#define HOST		'H'
#define JOBNAME		'J'
#define CLASS		'C'
#define LITERAL		'L'
#define TITLE		'T'
#define PERSON		'P'
#define MAILUSER	'M'
#define FFRMT		'f'
#define FFRMTCC		'l'
#define FPR		'p'
#define FTROFF		't'
#define FDITROFF	'n'
#define FDVI		'd'
#define FGRAPH		'g'
#define FCIF		'c'
#define FRASTER		'v'
#define FFORTRAN	'r'
#define FONTR		'1'
#define FONTI		'2'
#define FONTB		'3'
#define FONTS		'4'
#define WIDTH		'W'
#define INDENT		'I'
#define UNLINK		'U'
#define FILENAME	'N'
/*  BSD_EXTENSION */
#define LP_OPTIONS      'O'
#define LP_FUNCTION	'5'
#define SYSV_FORM		'f'
#define SYSV_HANDLING		'H'
#define SYSV_NOTIFICATION	'p'
#define SYSV_PAGES		'P'
#define SYSV_PRIORITY		'q'
#define SYSV_CHARSET		'S'
#define SYSV_TYPE		'T'
#define SYSV_MODE		'y'

#define FORMAT_LINE(c)	islower(c)

#define	FORTRAN		"fortran"
#define	RASTER		"raster"
#define	CIF		"cif"
#define	PLOT		"plot"
#define	TEX		"tex"
#define	TROFF		"troff"
#define	OTROFF		"otroff"
#define	SIMPLE		"simple"
#define	POSTSCRIPT	"postscript"

#define MIN(x,y)	((x)<(y) ? (x) : (y))
#define MAX(x,y)	((x)>(y) ? (x) : (y))

#define HEAD0		"Rank   Owner      Job             Files"
#define HEAD1		"Total Size\n"
#define JOBCOL		40	/* column for job entry in long format */
#define OWNCOL		 7	/* start of Owner column in normal format */
#define REQCOL		18	/* start of Job column in normal format */
#define FILCOL		34	/* start of Files column in normal format */
#define SIZCOL		62	/* start of Size column in normal format */

#define PRINTER_STATUS_TAG	"-:"

/* string separating job name and class on title line */
#define JCSEP		"\\n#####\\n#####\\t\\t  "  

#define NO_FILENAME		"<File name not available>"
#define	NOBANNER		"nobanner"
#define CATVFILTER		"catv_filter"
#define NOFILEBREAK		"nofilebreak"
#define FLIST			"flist="
#define IDENT			"indent="
#define WIDTHFLD		"width="
#define PRTITLE			"prtitle="
#define LPDFLD			"lpd="

#define LPDOPTS			"JC1234"
#define JOB_IDX			0
#define CLASS_IDX		1
#define FONT1_IDX		2
#define FONT2_IDX		3
#define FONT3_IDX		4
#define FONT4_IDX		5

struct fmt_map {		/* map content type to format key char */
	char	*type;
	char	 keyc;
};

struct status_map {		/* map rmjob messages to HPI status */
	char	*msg;
	short	 status;
};

#define CFPREFIX	"cfA"
#define DFPREFIX	"df"
#define NOENTRIES	"no entries\n"

#define FLIST_ESCHARS		" '\"\\" 
#define PRTITLE_ESCHARS		"'\"\\" 
#define LPD_ESCHARS		" '\"\\"	/* Not used by lpdNet */
#define TITLE_ESCHARS		"\"\\"		/* Not used by lpdNet */

/* function flags */
#define CFILE		0
#define DFILE		1
#define READ_FILE	READDFILE
#define READ_BUF	READCFILE
#define LOG_DEBUG	1
#define LOG_INFO	2
#define LOG_WARNING	4
#define LOG_ERR		8
#ifdef DEBUG
#define LOG_MASK	(LOG_DEBUG|LOG_INFO|LOG_WARNING|LOG_ERR)
#else
#define LOG_MASK	(LOG_INFO|LOG_WARNING|LOG_ERR)
#endif

#ifndef NULL
#define NULL		0
#endif

#ifndef STRSIZE
#define STRSIZE(s)	(sizeof(s) - 1)
#endif

#define BINMAIL		"/bin/mail"
#define DEFLP		"lp"			/* used by commands */
#define ALL		"-all"
#define REPRINT		(-1)
  

#if defined (__STDC__)
char	* basename(char *);
char	* find_listfld(char *, char **);
char	* find_strfld(char *, char *);
char	* getNets(char *, int);
char	* gethostname(void);
char	* getitem(char *, char);
char	* s_cancel(char *);
char	* s_get_status(char *);
char	* s_print_request(char *);
char	* mkreqid(char *, char *);
char	* rid2jid(char *);

int	  displayq(int);
int	  escaped(char *);
int	  openRemote(void);
int	  parseflist(char *, int, char **, char **);
int	  psfile(char *);
int	  snd_lpd_msg(int, ...);

#if !defined(BUG_1133272)
int	  TLIRead(int, char *, int);
int	  TLIWrite(int, char *, int);
#endif /* BUG_1133272 */

void	  _lp_msg(long, va_list);
void	  canonize(char *, char *, char *);
void	  closeRemote(void);
void	  done(int);
void	  fatal(char *, ...);
void	  logit(int, char *, ...);
void	  lp_fatal(long, ...);
void	  lp_msg(long, ...);
void	  parseReqid(char *, char **, char **);
void	  parseUser(char *, char **, char **);
void	  printjob(void);
void	  recvjob(void);
void	  rmjob(void);
void	  r_send_job(int, char *);
void	  rcv_msg(int, ...);
void	  rmesc(char *);
void	  snd_msg(int, ...);
#else
char	* basename();
char	* find_listfld();
char	* find_strfld();
char	* getNets();
char	* gethostname();
char	* getitem();
char	* s_cancel();
char	* s_get_status();
char	* s_print_request();
char	* mkreqid();
char	* rid2jid();

int	  displayq();
int	  escaped();
int	  openRemote();
int	  parseflist();
int	  psfile();
int	  snd_lpd_msg();

void	  _lp_msg();
void	  canonize();
void	  closeRemote();
void	  done();
void	  fatal();
void	  logit();
void	  lp_fatal();
void	  lp_msg();
void	  parseReqid();
void	  parseUser();
void	  printjob();
void	  recvjob();
void	  rmjob();
void	  r_send_job();
void	  rcv_msg();
void	  rmesc();
void	  snd_msg();
#endif

extern char	 Buf[];
extern char	 Msg[];
extern char	*Lhost;
extern char	*Rhost;
extern char	*Name;
extern char	*Netbuf;
extern char	*Person;
extern char	*Printer;
extern char	*Request[];
extern char	*User[];
extern int	 Nrequests;
extern int	 Nusers;
