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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UUCP_H
#define	_UUCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <parms.h>

#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/param.h>
#include <termio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>
#include <dirent.h>
#include <time.h>
#include <sys/times.h>
#include <errno.h>
#include <sys/mkdev.h>
#include <strings.h>
#include <ulimit.h>
#include <sys/utsname.h>
#include <ustat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* what mode should user files be allowed to have upon creation? */
/* NOTE: This does not allow setuid or execute bits on transfer. */
#define	LEGALMODE (mode_t)0666

/* what mode should public files have upon creation? */
#define	PUB_FILEMODE (mode_t)0666

/* what mode should log files have upon creation? */
#define	LOGFILEMODE (mode_t)0644

/* what mode should C. files have upon creation? */
#define	CFILEMODE (mode_t)0644

/* what mode should D. files have upon creation? */
#define	DFILEMODE (mode_t)0600

/* define the value of PUBMASK, used for creating "public" directories */
#define	PUBMASK (mode_t)0000

/* what mode should public directories have upon creation? */
#define	PUB_DIRMODE (mode_t)0777

/* define the value of DIRMASK, used for creating "system" subdirectories */
#define	DIRMASK (mode_t)0022

#define	MAXSTART	300	/* how long to wait on startup */

/* define the last characters for ACU  (used for 801/212 dialers) */
#define	ACULAST "<"

/*
 * caution - the fillowing names are also in Makefile
 * any changes here have to also be made there
 *
 * it's a good idea to make directories .foo, since this ensures
 * that they'll be ignored by processes that search subdirectories in SPOOL
 *
 *	XQTDIR = /var/uucp/.Xqtdir
 *	CORRUPT = /var/uucp/.Corrupt
 *	LOGDIR = /var/uucp/.Log
 *	SEQDIR = /var/uucp/.Sequence
 *	STATDIR = /var/uucp/.Status
 */

/* where to put the STST. files? */
#define	STATDIR		(const char *)"/var/uucp/.Status"

/* where should logfiles be kept? */
#define	LOGUUX		(const char *)"/var/uucp/.Log/uux"
#define	LOGUUXQT	(const char *)"/var/uucp/.Log/uuxqt"
#define	LOGUUCP		(const char *)"/var/uucp/.Log/uucp"
#define	LOGCICO		(const char *)"/var/uucp/.Log/uucico"
#define	CORRUPTDIR	(const char *)"/var/uucp/.Corrupt"

/* some sites use /var/uucp/.XQTDIR here */
/* use caution since things are linked into there */
#define	XQTDIR		(const char *)"/var/uucp/.Xqtdir"

/* how much of a system name can we print in a [CX]. file? */
/* MAXBASENAME - 1 (pre) - 1 ('.') - 1 (grade) - 4 (sequence number) */
#define	SYSNSIZE (MAXBASENAME - 7)

#ifdef USRSPOOLLOCKS
#define	LOCKPRE		(const char *)"/var/spool/locks/LCK."
#else
#define	LOCKPRE		(const char *)"/var/spool/uucp/LCK."
#endif /* USRSPOOLLOCKS */

#define	SQFILE		(const char *)"/etc/uucp/SQFILE"
#define	SQTMP		(const char *)"/etc/uucp/SQTMP"
#define	SLCKTIME	5400	/* system/device timeout (LCK.. files) */
#define	DIALCODES	(const char *)"/etc/uucp/Dialcodes"
#define	PERMISSIONS	(const char *)"/etc/uucp/Permissions"

#define	SPOOL		(const char *)"/var/spool/uucp"
#define	SEQDIR		(const char *)"/var/uucp/.Sequence"

#define	X_LOCKTIME	3600
#ifdef USRSPOOLLOCKS
#define	SEQLOCK		(const char *)"/var/spool/locks/LCK.SQ."
#define	SQLOCK		(const char *)"/var/spool/locks/LCK.SQ"
#define	X_LOCK		(const char *)"/var/spool/locks/LCK.X"
#define	S_LOCK		(const char *)"/var/spool/locks/LCK.S"
#define	L_LOCK		(const char *)"/var/spool/locks/LK"
#define	X_LOCKDIR	(const char *)"/var/spool/locks"
						/* must be dir part of above */
#else
#define	SEQLOCK		(const char *)"/var/spool/uucp/LCK.SQ."
#define	SQLOCK		(const char *)"/var/spool/uucp/LCK.SQ"
#define	X_LOCK		(const char *)"/var/spool/uucp/LCK.X"
#define	S_LOCK		(const char *)"/var/spool/uucp/LCK.S"
#define	L_LOCK		(const char *)"/var/spool/uucp/LK"
#define	X_LOCKDIR	(const char *)"/var/spool/uucp"
						/* must be dir part of above */
#endif /* USRSPOOLLOCKS */
#define	X_LOCKPRE	(const char *)"LCK.X"	/* must be last part of above */

#define	PUBDIR		(const char *)"/var/spool/uucppublic"
#define	ADMIN		(const char *)"/var/uucp/.Admin"
#define	ERRLOG		(const char *)"/var/uucp/.Admin/errors"
#define	SYSLOG		(const char *)"/var/uucp/.Admin/xferstats"
#define	RMTDEBUG	(const char *)"/var/uucp/.Admin/audit"
#define	CLEANUPLOGFILE	(const char *)"/var/uucp/.Admin/uucleanup"
#define	CMDLOG		(const char *)"/var/uucp/.Admin/command"
#define	PERFLOG		(const char *)"/var/uucp/.Admin/perflog"
#define	ACCOUNT		(const char *)"/var/uucp/.Admin/account"
#define	SECURITY	(const char *)"/var/uucp/.Admin/security"

#define	WORKSPACE	(const char *)"/var/uucp/.Workspace"

#define	SQTIME		60
#define	TRYCALLS	2	/* number of tries to dial call */
#define	MINULIMIT	(1L<<11)	/* minimum reasonable ulimit */
#define	MAX_LOCKTRY	5	/* number of attempts to lock device */

/*
 * CDEBUG is for communication line debugging
 * DEBUG is for program debugging
 * #define SMALL to compile without the DEBUG code
 */

#define	CDEBUG(l, f, s)
#define	SMALL

#ifndef SMALL
#define	DEBUG(l, f, s) if (Debug >= l) fprintf(stderr, f, s)
#else
#define	DEBUG(l, f, s)
#endif /* SMALL */

/*
 * VERBOSE is used by cu and ct to inform the user of progress
 * In other programs, the Value of Verbose is always 0.
 */
#define	VERBOSE(f, s) { if (Verbose > 0) (void) fprintf(stderr, f, s); }

#define	PREFIX(pre, str)	(strncmp((pre), (str), strlen(pre)) == SAME)
#define	BASENAME(str, c) ((Bnptr = strrchr((str), c)) ? (Bnptr + 1) : (str))
#define	EQUALS(a, b)		((a != CNULL) && (b != CNULL) && \
					(strcmp((a), (b)) == SAME))
#define	EQUALSN(a, b, n)	((a != CNULL) && (b != CNULL) && \
					(strncmp((a), (b), (n)) == SAME))
#define	LASTCHAR(s)	(s+strlen(s)-1)

#define	SAME 0
#define	ANYREAD 04
#define	ANYWRITE 02
#define	FAIL -1
#define	SUCCESS 0
#define	NULLCHAR	'\0'
#define	CNULL (char *)0
#define	STBNULL (struct sgttyb *)0
#define	MASTER 1
#define	SLAVE 0
#define	MAXBASENAME 14 /* should be DIRSIZ but that is now fs dependent */
#define	MAXFULLNAME BUFSIZ
#define	MAXNAMESIZE	64	/* /var/spool/uucp/<14 chars>/<14 chars>+slop */
#define	CONNECTTIME 30
#define	EXPECTTIME 45
#define	MSGTIME 60
#define	NAMESIZE MAXBASENAME+1
#define	SIZEOFPID	10		/* maximum number of digits in a pid */
#define	EOTMSG "\004\n\004\n"
#define	CALLBACK 1

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
#define	CK_READ		0
#define	CK_WRITE	1

/*
 * commands
 */
#define	SHELL		(const char *)"/usr/bin/sh"
#define	MAIL		(const char *)"mail"
#define	UUCICO		(const char *)"/usr/lib/uucp/uucico"
#define	UUXQT		(const char *)"/usr/lib/uucp/uuxqt"
#define	UUX		(const char *)"/usr/bin/uux"
#define	UUCP		(const char *)"/usr/bin/uucp"


/* system status stuff */
#define	SS_OK			0
#define	SS_NO_DEVICE		1
#define	SS_TIME_WRONG		2
#define	SS_INPROGRESS		3
#define	SS_CONVERSATION		4
#define	SS_SEQBAD		5
#define	SS_LOGIN_FAILED		6
#define	SS_DIAL_FAILED		7
#define	SS_BAD_LOG_MCH		8
#define	SS_LOCKED_DEVICE	9
#define	SS_ASSERT_ERROR		10
#define	SS_BADSYSTEM		11
#define	SS_CANT_ACCESS_DEVICE	12
#define	SS_DEVICE_FAILED	13	/* used for interface failure */
#define	SS_WRONG_MCH		14
#define	SS_CALLBACK		15
#define	SS_RLOCKED		16
#define	SS_RUNKNOWN		17
#define	SS_RLOGIN		18
#define	SS_UNKNOWN_RESPONSE	19
#define	SS_STARTUP		20
#define	SS_CHAT_FAILED		21
#define	SS_CALLBACK_LOOP	22

#define	MAXPH	60	/* maximum phone string size */
#define	MAXC	BUFSIZ

#define	TRUE	1
#define	FALSE	0
#define	NAMEBUF	32

/* The call structure is used by ct.c, cu.c, and dial.c.	*/

struct call {
	char *speed;		/* transmission baud rate */
	char *line;		/* device name for outgoing line */
	char *telno;		/* ptr to tel-no digit string */
	char *type;		/* type of device to use for call. */
};

/* structure of an Systems file line */
#define	F_MAX	50	/* max number of fields in Systems file line */
#define	F_NAME 0
#define	F_TIME 1
#define	F_TYPE 2
#define	F_CLASS 3	/* an optional prefix and the speed */
#define	F_PHONE 4
#define	F_LOGIN 5

/* structure of an Devices file line */
#define	D_TYPE 0
#define	D_LINE 1
#define	D_CALLDEV 2
#define	D_CLASS 3
#define	D_CALLER 4
#define	D_ARG 5
#define	D_MAX	50	/* max number of fields in Devices file line */

#define	D_ACU 1
#define	D_DIRECT 2
#define	D_PROT 4

#define	GRADES "/etc/uucp/Grades"

#define	D_QUEUE	'Z'	/* default queue */

/* past here, local changes are not recommended */
#define	CMDPRE		'C'
#define	DATAPRE		'D'
#define	XQTPRE		'X'

/*
 * stuff for command execution
 */
#define	X_RQDFILE	'F'
#define	X_STDIN		'I'
#define	X_STDOUT	'O'
#define	X_STDERR	'E'
#define	X_CMD		'C'
#define	X_USER		'U'
#define	X_BRINGBACK	'B'
#define	X_MAILF		'M'
#define	X_RETADDR	'R'
#define	X_COMMENT	'#'
#define	X_NONZERO	'Z'
#define	X_SENDNOTHING	'N'
#define	X_SENDZERO	'n'


/* This structure describes call routines */
struct caller {
	const char	*CA_type;
	int		(*CA_caller)();
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
	time_t	t_sxf;		/* start xfer				*/
	time_t	t_exf;		/* end xfer				*/
	time_t	t_eftp;		/* end file transfer protocol		*/
	time_t	t_qtime;	/* time file queued			*/
	int	t_ndial;	/* # of dials				*/
	int	t_nlogs;	/* # of login trys			*/
	struct tms t_tbb;	/* start execution times		*/
	struct tms t_txfs;	/* xfer start times			*/
	struct tms t_txfe;	/* xfer end times			*/
	struct tms t_tga;	/* garbage execution times		*/
};

/* This structure describes the values from Limits file */
struct limits {
	int	totalmax;	/* overall limit */
	int	sitemax;	/* limit per site */
	char	mode[64];	/* uucico mode */
};

/* external declarations */

static ssize_t (*Read)(), (*Write)();
static int (*Ioctl)(int, int, ...);
static int Debug, Verbose;
static uid_t Uid, Euid;		/* user-id and effective-uid */
static mode_t Dev_mode;		/* save device mode here */
static long Retrytime;
static char Dc[];			/* line name			*/
static const char *Spool;
static const char *Pubdir;
static char Progname[];
static char *Bnptr;		/* used when BASENAME macro is expanded */

static int Uerror;		/* global error code */
static char *UerrorText[];	/* text for error code */

#define	UERRORTEXT		UerrorText[Uerror]
#define	UTEXT(x)		UerrorText[x]

/* things get kind of tricky beyond this point -- please stay out */

/* uucp functions and subroutine */
static void	(*genbrk)();
extern int	iswrk(), gtwvec();			/* anlwrk.c */
extern void	findgrade();				/* grades.c */
extern void	chremdir(), mkremdir();			/* chremdir.c */
extern void	toCorrupt();				/* cpmv.c  */
extern int	xmv();					/* cpmv.c  */

static int	getargs();				/* getargs.c */
static void	bsfix();				/* getargs.c */
extern char	*getprm();				/* getprm.c */

extern char	*next_token();				/* permission.c */
extern char	*nextarg();				/* permission.c */
extern int	getuline();				/* permission.c */

static void	logent(const char *, const char *);	/* logent.c */
extern void	commandlog();				/* logent.c */
extern time_t	millitick();				/* logent.c */

extern unsigned long	getfilesize();			/* statlog.c */
extern void		putfilesize();			/* statlog.c */

extern int	logFind(), mchFind();			/* permission.c */
extern int	chkperm(), chkpth();			/* permission.c */
extern int	cmdOK(), switchRole();			/* permission.c */
extern int	callBack(), requestOK();		/* permission.c */
extern int	noSpool();				/* permission.c */
extern void	myName();				/* permission.c */

extern int	mkdirs();				/* expfile.c */
extern int	scanlimit();				/* limits.c */
extern void	systat();				/* systat.c */
static int	fd_mklock();				/* ulockf.c */
static int	mklock(), cklock();			/* ulockf.c */
static void	fd_rmlock(),  rmlock();	/* ulockf.c */
extern char	*timeStamp();				/* utility.c */
static void	assert(const char *s1, const char *s2,
		    int i1, const char *s3, int i2);	/* utility.c */
extern void	uucpname();				/* uucpname.c */
extern int	versys();				/* versys.c */
extern void	xuuxqt(), xuucico();			/* xqt.c */
static void	cleanup();				/* misc main.c */

#define	ASSERT(e, s1, s2, i1) if (!(e)) { \
	assert(s1, s2, i1, __FILE__, __LINE__); \
	cleanup(FAIL); \
};

/* messages */
static const char Ct_OPEN[];
static const char Ct_WRITE[];
static const char Ct_READ[];
static const char Ct_CREATE[];
static const char Ct_ALLOCATE[];
static const char Ct_LOCK[];
static const char Ct_STAT[];
static const char Ct_CHOWN[];
static const char Ct_CHMOD[];
static const char Ct_LINK[];
static const char Ct_CHDIR[];
static const char Ct_UNLINK[];
static const char Wr_ROLE[];
static const char Ct_CORRUPT[];
static const char Ct_FORK[];
static const char Ct_CLOSE[];
static const char Ct_BADOWN[];
static const char Fl_EXISTS[];

#ifdef	__cplusplus
}
#endif

#endif /* _UUCP_H */
