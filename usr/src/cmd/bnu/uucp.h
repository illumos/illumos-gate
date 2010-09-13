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


#ifndef _UUCP_H
#define _UUCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <wchar.h>
#include <widec.h>
#include <wctype.h>
#include <ulimit.h>
#include <values.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "parms.h"

#ifdef ATTSV
#define ATTSVKILL
#define ATTSVTTY
#define UNAME
#ifdef ATTSVR4
#define	ATTSVR3
#endif /*ATTSVR4*/
#endif /*ATTSV*/

#ifdef BSD4_3
#define BSD4_2
#define	BSDINETD
#endif /*BSD4_3 */

#ifdef DIAL
#define EXTERN static
#define GLOBAL static
#else
#define EXTERN extern
#define GLOBAL
#endif

#ifdef BSD4_2
#define V7
#define ATTSVKILL
#undef NONAP	/* conn.c has a nap() for 4.2 -- it's called select() */
#undef FASTTIMER
#endif /* BSD4_2 */

#ifdef V8
#define V7
#define ATTSVKILL
#define UNAME
#endif /* V8 */

#ifdef FASTTIMER
#undef NONAP
#endif

#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/param.h>

/*
 * param.h includes types.h and signal.h in 4bsd
 */
#ifdef V7
#ifdef ATTSVTTY
#include <termio.h>
#else /* ATTSVTTY */
#include <sgtty.h>
#endif /* ATTSVTTY */
#include <sys/timeb.h>
#ifdef BSD4_2
#include <fcntl.h>
#endif /* BSD4_2 */
#else /* !V7 */
#include <termio.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#endif /* V7 */

#include <sys/stat.h>
#include <utime.h>
#include <dirent.h>

#ifdef BSD4_2
#include <sys/time.h>
#else /* !BSD4_2 */
#include <time.h>
#endif /* BSD4_2 */

#include <sys/times.h>
#include <errno.h>

#ifdef ATTSV
#ifdef ATTSVR4
#include <sys/mkdev.h>
#else /* !ATTSVR4 */
#include <sys/sysmacros.h>
#endif /* ATTSVR4 */
#endif /* ATTSV */

#ifdef	RT
#include "rt/types.h"
#include "rt/unix/param.h"
#include "rt/stat.h"
#include <sys/ustat.h>
#endif /* RT */

#include <sysexits.h>

#ifndef ATTSVR4
#define	const
#endif /* ATTSVR4 */

/* what mode should user files be allowed to have upon creation? */
/* NOTE: This does not allow setuid or execute bits on transfer. */
#define LEGALMODE (mode_t) 0666

/* what mode should public files have upon creation? */
#define PUB_FILEMODE (mode_t) 0666

/* what mode should log files have upon creation? */
#define LOGFILEMODE (mode_t) 0644

/* what mode should C. files have upon creation? */
#define CFILEMODE (mode_t) 0644

/* what mode should D. files have upon creation? */
#define DFILEMODE (mode_t) 0600

/* define the value of PUBMASK, used for creating "public" directories */
#define PUBMASK (mode_t) 0000

/* what mode should public directories have upon creation? */
#define PUB_DIRMODE (mode_t) 0777

/* define the value of DIRMASK, used for creating "system" subdirectories */
#define DIRMASK (mode_t) 0022

#define MAXSTART	300	/* how long to wait on startup */

/* define the last characters for ACU  (used for 801/212 dialers) */
#define ACULAST "<"

/*  caution - the fillowing names are also in Makefile 
 *    any changes here have to also be made there
 *
 * it's a good idea to make directories .foo, since this ensures
 * that they'll be ignored by processes that search subdirectories in SPOOL
 *
 *  XQTDIR=/var/uucp/.Xqtdir
 *  CORRUPT=/var/uucp/.Corrupt
 *  LOGDIR=/var/uucp/.Log
 *  SEQDIR=/var/uucp/.Sequence
 *  STATDIR=/var/uucp/.Status
 *  
 */

/* where to put the STST. files? */
#define STATDIR		"/var/uucp/.Status"

/* where should logfiles be kept? */
#define LOGUUX		"/var/uucp/.Log/uux"
#define LOGUUXQT	"/var/uucp/.Log/uuxqt"
#define LOGUUCP		"/var/uucp/.Log/uucp"
#define LOGCICO		"/var/uucp/.Log/uucico"

/* some sites use /var/uucp/.Corrupt and /var/uucp/.Xqtdir here */
/* use caution since things are linked into there from /var/spool/uucp */
#define CORRUPTDIR	"/var/spool/uucp/.Corrupt"
#define XQTDIR		"/var/spool/uucp/.Xqtdir"

/* how much of a system name can we print in a [CX]. file? */
/* MAXBASENAME - 1 (pre) - 1 ('.') - 1 (grade) - 4 (sequence number) */
#define SYSNSIZE (MAXBASENAME - 7)

#ifdef USRSPOOLLOCKS
#define LOCKPRE		"/var/spool/locks/LCK."
#else /*!USRSPOOLLOCKS*/
#define LOCKPRE		"/var/spool/uucp/LCK."
#endif /* USRSPOOLLOCKS */

#define SQFILE		"/etc/uucp/SQFILE"
#define SQTMP		"/etc/uucp/SQTMP"
#define SLCKTIME	5400	/* system/device timeout (LCK.. files) */
#define DIALCODES	"/etc/uucp/Dialcodes"
#define PERMISSIONS	"/etc/uucp/Permissions"
#define SYSNAMEFILE	"/etc/uucp/Sysname"

#define SPOOL		"/var/spool/uucp"
#define SEQDIR		"/var/uucp/.Sequence"

#define X_LOCKTIME	3600
#ifdef USRSPOOLLOCKS
#define SEQLOCK		"/var/spool/locks/LCK.SQ."
#define SQLOCK		"/var/spool/locks/LCK.SQ"
#define X_LOCK		"/var/spool/locks/LCK.X"
#define S_LOCK		"/var/spool/locks/LCK.S"
#define L_LOCK		"/var/spool/locks/LK"
#define X_LOCKDIR	"/var/spool/locks"	/* must be dir part of above */
#else /*!USRSPOOLLOCKS*/
#define SEQLOCK		"/var/spool/uucp/LCK.SQ."
#define SQLOCK		"/var/spool/uucp/LCK.SQ"
#define X_LOCK		"/var/spool/uucp/LCK.X"
#define S_LOCK		"/var/spool/uucp/LCK.S"
#define L_LOCK		"/var/spool/uucp/LK"
#define X_LOCKDIR	"/var/spool/uucp"	/* must be dir part of above */
#endif /* USRSPOOLLOCKS */
#define X_LOCKPRE	"LCK.X"		/* must be last part of above */
#define	S_LOCKPRE	"LCK.S"

/*
 * Note: this should be "/usr/spool/uucppublic", not "/var/spool/uucppublic",
 * because if a Permissions file entry doesn't explicitly list directories to
 * which and from which files can be copied you can only copy files to and from
 * PUBDIR, and most systems out there will think PUBDIR is
 * "/usr/spool/uucppublic" not "/var/spool/uucppublic" (i.e., if you change
 * this, other systems may be rudely surprised when they try to get things from
 * or to PUBDIR).
 */
#define PUBDIR		"/usr/spool/uucppublic"
#define ADMIN		"/var/uucp/.Admin"
#define ERRLOG		"/var/uucp/.Admin/errors"
#define SYSLOG		"/var/uucp/.Admin/xferstats"
#define RMTDEBUG	"/var/uucp/.Admin/audit"
#define CLEANUPLOGFILE	"/var/uucp/.Admin/uucleanup"
#define CMDLOG		"/var/uucp/.Admin/command"
#define PERFLOG		"/var/uucp/.Admin/perflog"
#define ACCOUNT		"/var/uucp/.Admin/account"
#define SECURITY	"/var/uucp/.Admin/security"

/*
 * WORKSPACE should be in the same filesystem as SPOOL so that "mv"
 * between the two will work.  Otherwise, the file must be copied
 * and a window exists during which the file is mode 666.
 */
#define	WORKSPACE	"/var/spool/uucp/.Workspace"

#define SQTIME		60
#define TRYCALLS	2	/* number of tries to dial call */
#define MINULIMIT	(1L<<11)	/* minimum reasonable ulimit */
#define	MAX_LOCKTRY	5	/* number of attempts to lock device */

/*
 * CDEBUG is for communication line debugging 
 * DEBUG is for program debugging 
 * #define SMALL to compile without the DEBUG code
 */

#ifndef DIAL
#define CDEBUG(l, f, s) if (Debug >= l) fprintf(stderr, f, s)
#else
#define CDEBUG(l, f, s)
#define SMALL
#endif

#ifndef SMALL
#define DEBUG(l, f, s) if (Debug >= l) fprintf(stderr, f, s)
#else
#define DEBUG(l, f, s) 
#endif /* SMALL */

/*
 * VERBOSE is used by cu and ct to inform the user of progress
 * In other programs, the Value of Verbose is always 0.
 */
#define VERBOSE(f, s) { if (Verbose > 0) fprintf(stderr, f, s); }

#define PREFIX(pre, str)	(strncmp((pre), (str), strlen(pre)) == SAME)
#define BASENAME(str, c) ((Bnptr = strrchr((str), c)) ? (Bnptr + 1) : (str))
#define EQUALS(a,b)	((a != CNULL) && (b != CNULL) && (strcmp((a),(b))==SAME))
#define WEQUALS(a,b)	((a != CNULL) && (b != CNULL) && (wcscmp((a),(b))==SAME))
#define EQUALSN(a,b,n)	((a != CNULL) && (b != CNULL) && (strncmp((a),(b),(n))==SAME))
#define WEQUALSN(a,b,n)	((a != CNULL) && (b != CNULL) && (wcsncmp((a),(b),(n))==SAME))
#define LASTCHAR(s)	(s+strlen(s)-1)

#define SAME 0
#define ANYREAD 04
#define ANYWRITE 02
#define FAIL -1
#define SUCCESS 0
#define NULLCHAR	'\0'
#define CNULL ((void *) 0)
#define STBNULL (struct sgttyb *) 0
#define MASTER 1
#define SLAVE 0
#define MAXBASENAME 14 /* should be DIRSIZ but that is now fs dependent */
#define MAXFULLNAME BUFSIZ
#define MAXNAMESIZE	64	/* /var/spool/uucp/<14 chars>/<14 chars>+slop */
#define CONNECTTIME 30
#define EXPECTTIME 45
#define MSGTIME 60
#define NAMESIZE MAXBASENAME+1
#define	SIZEOFPID	10		/* maximum number of digits in a pid */
#define EOTMSG "\004\n\004\n"
#define CALLBACK 1

/* manifests for sysfiles.c's sysaccess()	*/
/* check file access for REAL user id */
#define	ACCESS_SYSTEMS	1
#define	ACCESS_DEVICES	2
#define	ACCESS_DIALERS	3
/* check file access for EFFECTIVE user id */
#define	EACCESS_SYSTEMS	4
#define	EACCESS_DEVICES	5
#define	EACCESS_DIALERS	6

/* manifest for chkpth flag */
#define CK_READ		0
#define CK_WRITE	1

/*
 * commands
 */
#define SHELL		"/usr/bin/sh"
#define MAIL		"mail"
#define UUCICO		"/usr/lib/uucp/uucico"
#define UUXQT		"/usr/lib/uucp/uuxqt"
#define UUX		"/usr/bin/uux"
#define UUCP		"/usr/bin/uucp"


/* system status stuff */
#define SS_OK			0
#define SS_NO_DEVICE		1
#define SS_TIME_WRONG		2
#define SS_INPROGRESS		3
#define SS_CONVERSATION		4
#define SS_SEQBAD		5
#define SS_LOGIN_FAILED		6
#define SS_DIAL_FAILED		7
#define SS_BAD_LOG_MCH		8
#define SS_LOCKED_DEVICE	9
#define SS_ASSERT_ERROR		10
#define SS_BADSYSTEM		11
#define SS_CANT_ACCESS_DEVICE	12
#define SS_DEVICE_FAILED	13	/* used for interface failure */
#define SS_WRONG_MCH		14
#define SS_CALLBACK		15
#define SS_RLOCKED		16
#define SS_RUNKNOWN		17
#define SS_RLOGIN		18
#define SS_UNKNOWN_RESPONSE	19
#define SS_STARTUP		20
#define SS_CHAT_FAILED		21
#define SS_CALLBACK_LOOP	22

#define MAXPH	60	/* maximum phone string size */
#define	MAXC	BUFSIZ

#define	TRUE	1
#define	FALSE	0
#define NAMEBUF	32

/* The call structure is used by ct.c, cu.c, and dial.c.	*/

struct call {
	char *speed;		/* transmission baud rate */
	char *line;		/* device name for outgoing line */
	char *telno;		/* ptr to tel-no digit string */
	char *type;		/* type of device to use for call. */
};

/* structure of an Systems file line */
#define F_MAX	50	/* max number of fields in Systems file line */
#define F_NAME 0
#define F_TIME 1
#define F_TYPE 2
#define F_CLASS 3	/* an optional prefix and the speed */
#define F_PHONE 4
#define F_LOGIN 5

/* structure of an Devices file line */
#define D_TYPE 0
#define D_LINE 1
#define D_CALLDEV 2
#define D_CLASS 3
#define D_CALLER 4
#define D_ARG 5
#define D_MAX	50	/* max number of fields in Devices file line */

#define D_ACU 1
#define D_DIRECT 2
#define D_PROT 4

#define GRADES "/etc/uucp/Grades"

#define	D_QUEUE	'Z'	/* default queue */

/* past here, local changes are not recommended */
#define CMDPRE		'C'
#define DATAPRE		'D'
#define XQTPRE		'X'

/*
 * stuff for command execution
 */
#define X_RQDFILE	'F'
#define X_STDIN		'I'
#define X_STDOUT	'O'
#define X_STDERR	'E'
#define X_CMD		'C'
#define X_USER		'U'
#define X_BRINGBACK	'B'
#define X_MAILF		'M'
#define X_RETADDR	'R'
#define X_COMMENT	'#'
#define X_NONZERO	'Z'
#define X_SENDNOTHING	'N'
#define X_SENDZERO	'n'
#define X_JOBID		'J'


/* This structure describes call routines */
struct caller {
	char	*CA_type;
	int	(*CA_caller)();
};

/* structure for a saved C file */

struct cs_struct {
	char	file[NAMESIZE];
	char	sys[NAMESIZE+5];
	char	sgrade[NAMESIZE];
	char	grade;
	long	jsize;
};

/* This structure describes dialing routines */
struct dialer {
	char	*DI_type;
	int	(*DI_dialer)();
};

struct nstat {
	pid_t	t_pid;		/* process id				*/
	time_t	t_start;	/* start time				*/
	time_t	t_scall;	/* start call to system			*/
	time_t	t_ecall;	/* end call to system			*/
	time_t	t_tacu;		/* acu time				*/
	time_t	t_tlog;		/* login time				*/
	time_t	t_sftp;		/* start file transfer protocol		*/
	time_t	t_sxf;		/* start xfer 				*/
	time_t	t_exf;		/* end xfer 				*/
	time_t	t_eftp;		/* end file transfer protocol		*/
	time_t	t_qtime;	/* time file queued			*/
	int	t_ndial;	/* # of dials				*/
	int	t_nlogs;	/* # of login trys			*/
	struct tms t_tbb;	/* start execution times		*/
	struct tms t_txfs;	/* xfer start times			*/
	struct tms t_txfe;	/* xfer end times 			*/
	struct tms t_tga;	/* garbage execution times		*/
};

/* This structure describes the values from Limits file */
struct limits {
	int	totalmax;	/* overall limit */
	int	sitemax;	/* limit per site */
	char	mode[64];	/* uucico mode */
};

/* external declarations */

EXTERN ssize_t (*Read)(), (*Write)();
#if defined(__STDC__)
EXTERN int (*Ioctl)(int,int,...);
#else
EXTERN int (*Ioctl)();
#endif
EXTERN int Ifn, Ofn;
EXTERN int Debug, Verbose;
EXTERN uid_t Uid, Euid;		/* user-id and effective-uid */
EXTERN long Ulimit;
EXTERN mode_t Dev_mode;		/* save device mode here */
EXTERN char Wrkdir[];
EXTERN long Retrytime;
EXTERN char **Env;
EXTERN char Uucp[];
EXTERN char Pchar;
EXTERN struct nstat Nstat;
EXTERN char Dc[];			/* line name			*/
EXTERN int Seqn;			/* sequence #			*/
EXTERN int Role;
EXTERN int Sgrades;		/* flag for administrator defined service grades */
EXTERN char Grade;
EXTERN char Logfile[MAXFULLNAME];
EXTERN char Rmtname[MAXFULLNAME];
EXTERN char JobGrade[MAXBASENAME+1];
EXTERN char User[MAXFULLNAME];
EXTERN char Loginuser[NAMESIZE];
EXTERN char *Spool;
EXTERN char *Pubdir;
EXTERN char Myname[];
EXTERN char Progname[];
EXTERN char RemSpool[];
EXTERN char *Bnptr;		/* used when BASENAME macro is expanded */
EXTERN char *Shchar;		/* shell meta-charaters */
EXTERN int SizeCheck;		/* ulimit check supported flag */
EXTERN long RemUlimit;		/* remote ulimit if supported */
EXTERN int Restart;		/* checkpoint restart supported flag */

EXTERN char Jobid[NAMESIZE];	/* Jobid of current C. file */
EXTERN int Uerror;		/* global error code */
EXTERN char *UerrorText[];	/* text for error code */

#define UERRORTEXT		UerrorText[Uerror]
#define UTEXT(x)		UerrorText[x]

/* things get kind of tricky beyond this point -- please stay out */

#ifdef ATTSV
#define index strchr
#define rindex strrchr 
#else /*!ATTSV*/
#define strchr index
#define strrchr rindex
#endif /*ATTSV*/

#ifdef BSD4_2
#define memcpy(s1,s2,n) bcopy(s2,s1,n)
extern void	bcopy();
#else
#ifndef ATTSVR4
#define vfork fork
extern char	*memcpy();
#endif
#endif

EXTERN struct stat __s_;
#define F_READANY(f)	((fstat((f),&__s_)==0) && ((__s_.st_mode&(0004))!=0) )
#define READANY(f)	((stat((f),&__s_)==0) && ((__s_.st_mode&(0004))!=0) )

#define WRITEANY(f)	((stat((f),&__s_)==0) && ((__s_.st_mode&(0002))!=0) )
#define DIRECTORY(f)	((stat((f),&__s_)==0) && ((__s_.st_mode&(S_IFMT))==S_IFDIR) )
#define NOTEMPTY(f)	((stat((f),&__s_)==0) && (__s_.st_size!=0) )

/* uucp functions and subroutine */
EXTERN void	(*genbrk)();
extern int	iswrk(), gtwvec();			/* anlwrk.c */
extern void	findgrade();				/* grades.c */
extern void	chremdir(), mkremdir();			/* chremdir.c */
extern void	toCorrupt();				/* cpmv.c  */
extern int	xmv();					/* cpmv.c  */

EXTERN int	getargs();				/* getargs.c */
EXTERN void	bsfix();				/* getargs.c */
extern char	*_uu_setlocale();			/* getargs.c */
extern void	_uu_resetlocale();			/* getargs.c */
extern char	*getprm();				/* getprm.c */

extern char	*next_token();				/* permission.c */
extern char	*nextarg();				/* permission.c */
extern int	getuline();				/* permission.c */

EXTERN void	logent(), usyslog(), ucloselog();	/* logent.c */
extern void	commandlog();				/* logent.c */
extern time_t	millitick();				/* logent.c */

extern unsigned long	getfilesize();			/* statlog.c */
extern void 		putfilesize();			/* statlog.c */

EXTERN char	*protoString();				/* permission.c */
extern int	logFind(), mchFind();			/* permission.c */
extern int	chkperm(), chkpth();			/* permission.c */
extern int	cmdOK(), switchRole();			/* permission.c */
extern int	callBack(), requestOK();		/* permission.c */
extern int	noSpool();				/* permission.c */
extern void	myName();				/* permission.c */

extern int	mkdirs();				/* expfile.c */
extern int	scanlimit();				/* limits.c */
extern void	systat();				/* systat.c */
EXTERN int	fd_mklock(), fd_cklock();		/* ulockf.c */
EXTERN int	fn_cklock();				/* ulockf.c */
EXTERN int	mklock(), cklock(), umlock();		/* ulockf.c */
EXTERN void	fd_rmlock(), delock(), rmlock();	/* ulockf.c */
extern char	*timeStamp();				/* utility.c */
EXTERN void	assert(), errent();			/* utility.c */
extern void	uucpname();				/* uucpname.c */
extern int	versys();				/* versys.c */
extern void	xuuxqt(), xuucico();			/* xqt.c */
EXTERN void	cleanup();				/* misc main.c */

#define ASSERT(e, s1, s2, i1) if (!(e)) {\
	assert(s1, s2, i1, __FILE__, __LINE__);\
	cleanup(FAIL);};

#ifdef ATTSV
void	setbuf();
#else /* !ATTSV */
int	setbuf(), ftime();
char	*mktemp();
#endif /*ATTSV*/

#ifdef UNAME
#include <sys/utsname.h>
#endif /* UNAME */

#ifndef NOUSTAT
#ifdef V7USTAT
struct  ustat {
	daddr_t	f_tfree;	/* total free */
	ino_t	f_tinode;	/* total inodes free */
};
#else /* !NOUSTAT && !V7USTAT */
#ifdef STATFS
#include <sys/vfs.h>
#else
#include <ustat.h>
#endif /* STATFS */
#endif /* V7USTAT */
#endif /* NOUSTAT */

#ifdef BSD4_2
int	gethostname();
#endif /* BSD4_2 */

/* messages */
EXTERN char *Ct_OPEN;
EXTERN char *Ct_WRITE;
EXTERN char *Ct_READ;
EXTERN char *Ct_CREATE;
EXTERN char *Ct_ALLOCATE;
EXTERN char *Ct_LOCK;
EXTERN char *Ct_STAT;
EXTERN char *Ct_CHOWN;
EXTERN char *Ct_CHMOD;
EXTERN char *Ct_LINK;
EXTERN char *Ct_CHDIR;
EXTERN char *Ct_UNLINK;
EXTERN char *Wr_ROLE;
EXTERN char *Ct_CORRUPT;
EXTERN char *Ct_FORK;
EXTERN char *Ct_CLOSE;
EXTERN char *Ct_BADOWN;
EXTERN char *Fl_EXISTS;


#ifdef __cplusplus
}
#endif

#endif	/* _UUCP_H */
