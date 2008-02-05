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

#ifndef	_DEFS_H
#define	_DEFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	UNIX shell
 */

/* execute flags */
#define		XEC_EXECED	01
#define			XEC_LINKED	02
#define		XEC_NOSTOP	04

/* endjobs flags */
#define			JOB_STOPPED	01
#define			JOB_RUNNING	02

/* error exits from various parts of shell */
#define		ERROR		1
#define		SYNBAD		2
#define		SIGFAIL 	2000
#define		SIGFLG		0200

/* command tree */
#define		FPIN		0x0100
#define		FPOU		0x0200
#define		FAMP		0x0400
#define		COMMSK		0x00F0
#define			CNTMSK		0x000F

#define		TCOM		0x0000
#define		TPAR		0x0010
#define		TFIL		0x0020
#define		TLST		0x0030
#define		TIF			0x0040
#define		TWH			0x0050
#define		TUN			0x0060
#define		TSW			0x0070
#define		TAND		0x0080
#define		TORF		0x0090
#define		TFORK		0x00A0
#define		TFOR		0x00B0
#define			TFND		0x00C0

/* execute table */
#define		SYSSET		1
#define		SYSCD		2
#define		SYSEXEC		3

#ifdef RES	/*	include login code	*/
#define		SYSLOGIN	4
#else
#define		SYSNEWGRP 	4
#endif

#define		SYSTRAP		5
#define		SYSEXIT		6
#define		SYSSHFT 	7
#define		SYSWAIT		8
#define		SYSCONT 	9
#define		SYSBREAK	10
#define		SYSEVAL 	11
#define		SYSDOT		12
#define		SYSRDONLY 	13
#define		SYSTIMES 	14
#define		SYSXPORT	15
#define		SYSNULL 	16
#define		SYSREAD 	17
#define			SYSTST		18

#ifndef RES	/*	exclude umask code	*/
#define		SYSUMASK 	20
#define		SYSULIMIT 	21
#endif

#define		SYSECHO		22
#define			SYSHASH		23
#define			SYSPWD		24
#define		SYSRETURN	25
#define			SYSUNS		26
#define			SYSMEM		27
#define			SYSTYPE  	28
#define			SYSGETOPT	29
#define		SYSJOBS		30
#define		SYSFGBG		31
#define		SYSKILL		32
#define		SYSSUSP		33
#define		SYSSTOP		34

/* used for input and output of shell */
#define		INIO 		19

/* io nodes */
#define		USERIO		10
#define		IOUFD		15
#define		IODOC		0x0010
#define		IOPUT		0x0020
#define		IOAPP		0x0040
#define		IOMOV		0x0080
#define		IORDW		0x0100
#define		IOSTRIP		0x0200
#define		IODOC_SUBST	0x0400
#define		INPIPE		0
#define		OTPIPE		1

/* arg list terminator */
#define		ENDARGS		0

#include	<unistd.h>
#include 	"mac.h"
#include	"mode.h"
#include	"name.h"
#include	<signal.h>
#include	<sys/types.h>

/* id's */
extern pid_t	mypid;
extern pid_t	mypgid;
extern pid_t	mysid;

/* getopt */

extern int		optind;
extern int		opterr;
extern int 		_sp;
extern char 		*optarg;


/* use sh-private versions of memory allocation routines */

#define		alloc 		malloc

/* result type declarations */

extern int handle();
extern void chktrap();
extern void done(int)
	__NORETURN;
extern void sh_free();
extern unsigned char *make();
extern unsigned char *movstr();
extern unsigned char *movstrn();
extern unsigned char *cwdget();
extern struct trenod *cmd();
extern struct trenod *makefork();
extern struct namnod *lookup();
extern struct namnod *findnam();
extern struct dolnod *useargs();
extern float expr();
extern unsigned char *catpath();
extern unsigned char *getpath();
extern unsigned char *nextpath();
extern unsigned char **scan();
extern unsigned char *mactrim();
extern unsigned char *macro();
extern void exname(struct namnod *);
extern void printnam(struct namnod *);
extern void printro(struct namnod *);
extern void printexp(struct namnod *);
extern unsigned int readwc();
extern unsigned int nextwc();
extern unsigned char skipc();
extern unsigned char **local_setenv();
extern time_t time();
extern void exitsh(int)
	__NORETURN;
extern void failed_real(unsigned char *, const char *, unsigned char *)
    __NORETURN;
extern void error(const char *) __NORETURN;
extern void prf();
extern void assign(struct namnod *, unsigned char *);
extern void setmode(int);
extern void trim(unsigned char *);
extern void preacct(unsigned char *);



#define		attrib(n, f)		(n->namflg |= f)
#define		round(a, b)		(((int)(((char *)(a)+b)-1))&~((b)-1))
#define		closepipe(x)		(close(x[INPIPE]), close(x[OTPIPE]))
#define		eq(a, b)		(cf(a, b) == 0)
#define		max(a, b)		((a) > (b)?(a):(b))
#define		assert(x)
#define		_gettext(s)		(unsigned char *)gettext(s)

/*
 * macros using failed_real(). Only s2 is gettext'd with both functions.
 */
#define		failed(s1, s2)		failed_real(s1, s2, NULL)
#define		bfailed(s1, s2, s3)	failed_real(s1, s2, s3)

/*
 * macros using failure_real(). s1 and s2 is gettext'd with gfailure(), but
 * only s2 is gettext'd with failure().
 */
#define		failure(s1, s2)		failure_real(s1, s2, 0)
#define		gfailure(s1, s2)	failure_real(s1, s2, 1)

/* temp files and io */
extern int				output;
extern int				ioset;
extern struct ionod	*iotemp; /* files to be deleted sometime */
extern struct ionod	*fiotemp; /* function files to be deleted sometime */
extern struct ionod	*iopend; /* documents waiting to be read at NL */
extern struct fdsave	fdmap[];
extern int savpipe;

/* substitution */
extern int				dolc;
extern unsigned char				**dolv;
extern struct dolnod	*argfor;
extern struct argnod	*gchain;

/* stak stuff */
#include		"stak.h"

/*
 * If non-ANSI C, make const go away.  We bring it back
 * at the end of the file to avoid side-effects.
 */
#ifndef __STDC__
#define	const
#endif

/* string constants */
extern const char				atline[];
extern const char				readmsg[];
extern const char				colon[];
extern const char				minus[];
extern const char				nullstr[];
extern const char				sptbnl[];
extern const char				unexpected[];
extern const char				endoffile[];
extern const char				synmsg[];

/* name tree and words */
extern const struct sysnod	reserved[];
extern const int				no_reserved;
extern const struct sysnod	commands[];
extern const int				no_commands;

extern int				wdval;
extern int				wdnum;
extern int				fndef;
extern int				nohash;
extern struct argnod	*wdarg;
extern int				wdset;
extern BOOL				reserv;

/* prompting */
extern const char				stdprompt[];
extern const char				supprompt[];
extern const char				profile[];
extern const char				sysprofile[];

/* locale testing */
extern const char			localedir[];
extern int				localedir_exists;

/* built in names */
extern struct namnod	fngnod;
extern struct namnod	cdpnod;
extern struct namnod	ifsnod;
extern struct namnod	homenod;
extern struct namnod	mailnod;
extern struct namnod	pathnod;
extern struct namnod	ps1nod;
extern struct namnod	ps2nod;
extern struct namnod	mchknod;
extern struct namnod	acctnod;
extern struct namnod	mailpnod;

/* special names */
extern unsigned char				flagadr[];
extern unsigned char				*pcsadr;
extern unsigned char				*pidadr;
extern unsigned char				*cmdadr;

/* names always present */
extern const char				defpath[];
extern const char				mailname[];
extern const char				homename[];
extern const char				pathname[];
extern const char				cdpname[];
extern const char				ifsname[];
extern const char				ps1name[];
extern const char				ps2name[];
extern const char				mchkname[];
extern const char				acctname[];
extern const char				mailpname[];

/* transput */
extern unsigned char				tmpout[];
extern int 					tmpout_offset;
extern unsigned int				serial;

/*
 * allow plenty of room for size for temp file name:
 * "/tmp/sh"(7) + <pid> (<=6) + <unsigned int #> (<=10) + \0 (1)
 */
#define			TMPOUTSZ 		32

extern struct fileblk	*standin;

#define		input		(standin->fdes)
#define		eof			(standin->feof)

extern int				peekc;
extern int				peekn;
extern unsigned char				*comdiv;
extern
#ifdef __STDC__
const
#endif
char				devnull[];

/* flags */
#define			noexec		01
#define			sysflg		01
#define			intflg		02
#define			prompt		04
#define			setflg		010
#define			errflg		020
#define			ttyflg		040
#define			forked		0100
#define			oneflg		0200
#define			rshflg		0400
#define			subsh		01000
#define			stdflg		02000
#define			STDFLG		's'
#define			execpr		04000
#define			readpr		010000
#define			keyflg		020000
#define			hashflg		040000
#define			nofngflg	0200000
#define			exportflg	0400000
#define			monitorflg	01000000
#define			jcflg		02000000
#define			privflg		04000000
#define			forcexit	010000000
#define			jcoff		020000000
#define			pfshflg		040000000

extern long				flags;
extern int				rwait;	/* flags read waiting */

/* error exits from various parts of shell */
#include	<setjmp.h>
extern jmp_buf			subshell;
extern jmp_buf			errshell;

/* fault handling */
#include	"brkincr.h"

extern unsigned			brkincr;
#define		MINTRAP		0
#define		MAXTRAP		NSIG

#define		TRAPSET		2
#define		SIGSET		4
#define			SIGMOD		8
#define			SIGIGN		16

extern BOOL				trapnote;

/* name tree and words */
extern unsigned char				**environ;
extern unsigned char				numbuf[];
extern const char				export[];
extern const char				duperr[];
extern const char				readonly[];

/* execflgs */
extern int				exitval;
extern int				retval;
extern BOOL				execbrk;
extern int				loopcnt;
extern int				breakcnt;
extern int				funcnt;
extern int				tried_to_exit;

/* messages */
extern const char				mailmsg[];
extern const char				coredump[];
extern const char				badopt[];
extern const char				badparam[];
extern const char				unset[];
extern const char				badsub[];
extern const char				nospace[];
extern const char				nostack[];
extern const char				notfound[];
extern const char				badtrap[];
extern const char				baddir[];
extern const char				badshift[];
extern const char				restricted[];
extern const char				execpmsg[];
extern const char				notid[];
extern const char 				badulimit[];
extern const char 				ulimit[];
extern const char				wtfailed[];
extern const char				badcreate[];
extern const char				nofork[];
extern const char				noswap[];
extern const char				piperr[];
extern const char				badopen[];
extern const char				badnum[];
extern const char				badsig[];
extern const char				badid[];
extern const char				arglist[];
extern const char				txtbsy[];
extern const char				toobig[];
extern const char				badexec[];
extern const char				badfile[];
extern const char				badreturn[];
extern const char				badexport[];
extern const char				badunset[];
extern const char				nohome[];
extern const char				badperm[];
extern const char				mssgargn[];
extern const char				libacc[];
extern const char				libbad[];
extern const char				libscn[];
extern const char				libmax[];
extern const char				emultihop[];
extern const char				nulldir[];
extern const char				enotdir[];
extern const char				enoent[];
extern const char				eacces[];
extern const char				enolink[];
extern const char				exited[];
extern const char				running[];
extern const char				ambiguous[];
extern const char				nosuchjob[];
extern const char				nosuchpid[];
extern const char				nosuchpgid[];
extern const char				usage[];
extern const char				nojc[];
extern const char				killuse[];
extern const char				jobsuse[];
extern const char				stopuse[];
extern const char				ulimuse[];
extern const char				nocurjob[];
extern const char				loginsh[];
extern const char				jobsstopped[];
extern const char				jobsrunning[];
extern const char				nlorsemi[];
extern const char				signalnum[];
extern const char				badpwd[];
extern const char				badlocale[];
extern const char				nobracket[];
extern const char				noparen[];
extern const char				noarg[];

/*	'builtin' error messages	*/

extern const char				btest[];
extern const char				badop[];

#ifndef __STDC__
#undef const 					/* bring back const */
#endif

/*	fork constant	*/

#define		FORKLIM 	32

extern address			end[];

#include	"ctype.h"
#include	<ctype.h>
#include	<locale.h>

extern int				eflag;
extern int				ucb_builtins;

/*
 * Find out if it is time to go away.
 * `trapnote' is set to SIGSET when fault is seen and
 * no trap has been set.
 */

#define		sigchk()	if (trapnote & SIGSET)	\
					exitsh(exitval ? exitval : SIGFAIL)

#define		exitset()	retval = exitval

/* Multibyte characters */
unsigned char *readw();
#include <stdlib.h>
#include <limits.h>
#define	MULTI_BYTE_MAX MB_LEN_MAX


#ifdef	__cplusplus
}
#endif

#endif	/* _DEFS_H */
