/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_TIP_H
#define	_TIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * tip - terminal interface program
 */

#include <sys/types.h>
#ifdef USG
#include <fcntl.h>	/* for O_RDWR, etc. */
#include <unistd.h>	/* for R_OK, etc. */
#else
#include <sys/file.h>
#endif

#include <sys/termios.h>
#include <sys/filio.h>	/* XXX - for FIONREAD only */
#include <signal.h>
#include <stdio.h>
#include <pwd.h>
#include <ctype.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/isa_defs.h>	/* for ENDIAN defines */
#include <stdlib.h>
#include <sys/wait.h>

#define	_CTRL(c)	(c&037)

#ifdef USG
#define	signal(_sig_, _hdlr_)	sigset((_sig_), (_hdlr_))
#endif
typedef	void (*sig_handler_t)(int);	/* works on BSD and SV */

/*
 * Remote host attributes
 */
char	*DV;			/* UNIX device(s) to open */
char	*EL;			/* chars marking an EOL */
char	*CM;			/* initial connection message */
char	*IE;			/* EOT to expect on input */
char	*OE;			/* EOT to send to complete FT */
char	*CU;			/* call unit if making a phone call */
char	*AT;			/* acu type */
char	*PN;			/* phone number(s) */
char	*DI;			/* disconnect string */
char	*PA;			/* parity to be generated */

char	*PH;			/* phone number file */
char	*RM;			/* remote file name */
char	*HO;			/* host name */

int	BR;			/* line speed for conversation */
int	FS;			/* frame size for transfers */

signed char	DU;		/* this host is dialed up */
char	HW;			/* this device is hardwired, see hunt.c */
char	*ES;			/* escape character */
char	*EX;			/* exceptions */
char	*FO;			/* force (literal next) char */
char	*RC;			/* raise character */
char	*RE;			/* script record file */
char	*PR;			/* remote prompt */
int	DL;			/* line delay for file transfers to remote */
int	CL;			/* char delay for file transfers to remote */
int	ET;			/* echocheck timeout */
int	DB;			/* dialback - ignore hangup */

/*
 * String value table
 */
typedef
	struct {
		char	*v_name;	/* whose name is it */
		char	v_type;		/* for interpreting set's */
		char	v_access;	/* protection of touchy ones */
		char	*v_abrev;	/* possible abreviation */
		char	*v_value;	/* casted to a union later */
	}
	value_t;

#define	STRING	01		/* string valued */
#define	BOOL	02		/* true-false value */
#define	NUMBER	04		/* numeric value */
#define	CHAR	010		/* character value */

#define	WRITE	01		/* write access to variable */
#define	READ	02		/* read access */

#define	CHANGED	01		/* low bit is used to show modification */
#define	PUBLIC	1		/* public access rights */
#define	PRIVATE	03		/* private to definer */
#define	ROOT	05		/* root defined */

#define	TRUE	1
#define	FALSE	0

#define	ENVIRON	020		/* initialize out of the environment */
#define	IREMOTE	040		/* initialize out of remote structure */
#define	INIT	0100		/* static data space used for initialization */
#define	TMASK	017

/*
 * Definition of ACU line description
 */
typedef
	struct {
		char	*acu_name;
		int	(*acu_dialer)(char *, char *);
		void	(*acu_disconnect)(void);
		void	(*acu_abort)(void);
	}
	acu_t;

#define	equal(a, b)	(strcmp(a, b) == 0)	/* A nice function to compare */

/*
 * variable manipulation stuff --
 *   if we defined the value entry in value_t, then we couldn't
 *   initialize it in vars.c, so we cast it as needed to keep lint
 *   happy.
 */
typedef
	union {
		int	zz_number;
		int	*zz_address;
#if defined(_LITTLE_ENDIAN)
		short	zz_boolean;
		char	zz_character;
#endif
#if defined(_BIG_ENDIAN)
		int	zz_boolean;
		int	zz_character;
#endif
	}
	zzhack;

#define	value(v)	vtable[v].v_value

#define	boolean(v)	((((zzhack *)(&(v))))->zz_boolean)
#define	number(v)	((((zzhack *)(&(v))))->zz_number)
#define	character(v)	((((zzhack *)(&(v))))->zz_character)
#define	address(v)	((((zzhack *)(&(v))))->zz_address)

/*
 * Escape command table definitions --
 *   lookup in this table is performed when ``escapec'' is recognized
 *   at the begining of a line (as defined by the eolmarks variable).
 */

typedef
	struct {
		char	e_char;		/* char to match on */
		char	e_flags;	/* experimental, priviledged */
		char	*e_help;	/* help string */
		void 	(*e_func)(int);	/* command */
	}
	esctable_t;

#define	NORM	00		/* normal protection, execute anyone */
#define	EXP	01		/* experimental, mark it with a `*' on help */
#define	PRIV	02		/* priviledged, root execute only */

extern int	vflag;		/* verbose during reading of .tiprc file */
extern value_t	vtable[];	/* variable table */
extern int	noparity;


#ifndef ACULOG
#define	logent(a, b, c, d)
#define	loginit()
#else
extern void	logent(char *, char *, char *, char *);
extern void	loginit(void);
#endif

/*
 * Definition of indices into variable table so
 *  value(DEFINE) turns into a static address.
 */

#define	BEAUTIFY	0
#define	BAUDRATE	1
#define	DIALTIMEOUT	2
#define	EOFREAD		3
#define	EOFWRITE	4
#define	EOL		5
#define	ESCAPE		6
#define	EXCEPTIONS	7
#define	FORCE		8
#define	FRAMESIZE	9
#define	HOST		10
#define	LOG		11
#define	PHONES		12
#define	PROMPT		13
#define	RAISE		14
#define	RAISECHAR	15
#define	RECORD		16
#define	REMOTE		17
#define	SCRIPT		18
#define	TABEXPAND	19
#define	VERBOSE		20
#define	SHELL		21
#define	HOME		22
#define	ECHOCHECK	23
#define	DISCONNECT	24
#define	TAND		25
#define	LDELAY		26
#define	CDELAY		27
#define	ETIMEOUT	28
#define	RAWFTP		29
#define	HALFDUPLEX	30
#define	LECHO		31
#define	PARITY		32
#define	HARDWAREFLOW	33

#define	NOVAL	((value_t *)NULL)
#define	NOACU	((acu_t *)NULL)
#define	NOSTR	((char *)NULL)
#define	NOFILE	((FILE *)NULL)
#define	NOPWD	((struct passwd *)0)

struct termios	arg;		/* current mode of local terminal */
struct termios	defarg;		/* initial mode of local terminal */

FILE	*fscript;		/* FILE for scripting */
FILE	*phfd;			/* FILE for PHONES file */

int	fildes[2];		/* file transfer synchronization channel */
int	repdes[2];		/* read process sychronization channel */
int	FD;			/* open file descriptor to remote host */
int	AC;			/* open file descriptor to dialer (v831 only) */
int	vflag;			/* print .tiprc initialization sequence */
int	sfd;			/* for ~< operation */
int	pid;			/* pid of tipout */
int	uid, euid;		/* real and effective user id's */
int	gid, egid;		/* real and effective group id's */
int	stoprompt;		/* for interrupting a prompt session */
int	timedout;		/* ~> transfer timedout */
int	cumode;			/* simulating the "cu" program */

char	fname[80];		/* file name buffer for ~< */
char	copyname[80];		/* file name buffer for ~> */
char	ccc;			/* synchronization character */
char	ch;			/* for tipout */
char	*uucplock;		/* name of lock file for uucp's */
extern int trusted_device;


extern char	*connect(void);
extern char	*ctrl(char);
extern char	*getremote(char *);
extern char	*expand(char []);
extern char	*vinterp(char *, char);
extern void	cumain(int, char *[]);
extern void	delock(char *);
extern void	disconnect(char *);
extern void	myperm(void);
extern void	parwrite(int, unsigned char *, int);
extern void	raw(void);
extern void	setparity(char *);
extern void	setscript(void);
extern void	tandem(char *);
extern void	tip_abort(char *);
extern void	ttysetup(int);
extern void	unraw(void);
extern void	userperm(void);
extern void	vinit(void);
extern void	vlex(char *);
extern int	any(char, char *);
extern int	hunt(char *);
extern int	prompt(char *, char *, size_t);
extern int	rgetent(char *, char *, int);
extern int	rgetflag(char *);
extern int	rgetnum(char *);
extern int	speed(int);
extern int	tip_mlock(char *);
extern int	vstring(char *, char *);

#endif /* _TIP_H */
