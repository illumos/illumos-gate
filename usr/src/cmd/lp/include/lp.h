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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _LP_LP_H
#define	_LP_LP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>

/*
 * Types:
 */

typedef struct SCALED {
	float	val;	/* value of number, scaled according to "sc" */
	char	sc;	/* 'i' inches, 'c' centimeters, ' ' lines/cols */
}			SCALED;

typedef struct FALERT {
	char	*shcmd;	/* shell command used to perform the alert */
	int	Q;	/* # requests queued to activate alert */
	int	W;	/* alert is sent every "W" minutes */
} FALERT;


#define	LP_USE_PAPI_ATTR 1	/* use PAPI attributes for printing */
				/* TODO: is this best place for this ? */

/*
 * Places:
 */

/*
 * These functions no longer exist.  The defines take care
 * of recompiling code that expects these and the null functions
 * in getpaths.c take care of relinking objects that expect these.
 */
#define	getpaths()
#define	getadminpaths(x)

#define	LPDIR		"/usr/lib/lp"
#define	ETCDIR		"/etc/lp"
#define	SPOOLDIR	"/var/spool/lp"
#define	LOGDIR		"/var/lp/logs"

#define	TERMINFO	"/usr/share/lib/terminfo"

#define	LPUSER		"lp"
#define	ROOTUSER	"root"

#define	BANG_S		"!"
#define	BANG_C		'!'

#define	LOCAL_LPUSER	BANG_S LPUSER
#define	LOCAL_ROOTUSER	BANG_S ROOTUSER
#define	ALL_BANG_ALL	NAME_ALL BANG_S NAME_ALL

/* #define	ADMINSDIR	"admins"  */
/* # define CLASSESDIR	"classes" */
/* # define FORMSDIR	"forms" */
/* # define INTERFACESDIR	"interfaces" */
/* # define PRINTERSDIR	"printers" */
/* # define PRINTWHEELSDIR	"pwheels" */
/* #define BINDIR		"bin" */
/* #define LOGSDIR		"logs" */
/* #define MODELSDIR	"model" */
/* #define NETWORKDIR	"network" */
#define	FIFOSDIR	"fifos"
/* # define PRIVFIFODIR	"private" */
/* # define PUBFIFODIR	"public" */
/* #define REQUESTSDIR	"requests" */
/* #define SYSTEMDIR	"system" */
/* #define TEMPDIR		"temp" */
/* #define TMPDIR		"tmp" */

/* #define SCHEDLOCK	"SCHEDLOCK" */
/* #define FIFO		"FIFO" */

#define	FILTERTABLE	"filter.table"
#define	FILTERTABLE_I	"filter.table.i"

/* #define DESCRIBEFILE	"describe" */
/* #define ALIGNFILE	"align_ptrn" */
#define	COMMENTFILE	"comment"
#define	ALLOWFILE	"allow"
#define	DENYFILE	"deny"
#define	ALERTSHFILE	"alert.sh"
#define	ALERTVARSFILE	"alert.vars"
#define	ALERTPROTOFILE	"alert.proto"
#define	CONFIGFILE	"configuration"
#define	FACCESSPREFIX	"forms."
#define	PACCESSPREFIX	"paper."
#define	UACCESSPREFIX	"users."
#define	FALLOWFILE	FACCESSPREFIX ALLOWFILE
#define	FDENYFILE	FACCESSPREFIX DENYFILE
#define	UALLOWFILE	UACCESSPREFIX ALLOWFILE
#define	UDENYFILE	UACCESSPREFIX DENYFILE
/* #define DEFAULTFILE	"default" */
#define	STATUSFILE	"status"
/* #define USERSFILE	"users" */
/* #define NAMEFILE	"name" */
/* #define XFERFILE	"transfer" */
/* #define EXECFILE	"execute" */
#define	PSTATUSFILE	"pstatus"
#define	CSTATUSFILE	"cstatus"
/* #define REQLOGFILE	"requests" */

#define	STANDARD	"standard"
/* #define SLOWFILTER	"slow.filter" */
#define	FAULTMESSAGEFILE "faultMessage"
#define	FORMMESSAGEFILE "formMessage"

#define	LPNET		"/usr/lib/lp/lpNet"

#ifdef LP_USE_PAPI_ATTR
#define	STANDARD_FOOMATIC	"standard_foomatic"
	/*
	 * The default model interface script to use if a printer is configured
	 * with a PPD (PostScript Printer Definition) file.
	 */
#define	LP_PAPIATTRNAME "attributes"
	/*
	 * Job attributes filename extension,
	 * eg. /var/spool/lp/temp/123-attributes
	 */
#endif

/*
 * Names and phrases:
 */

/*
 * If you change these from macros to defined (char *) strings,
 * be aware that in several places the lengths of the strings
 * are computed using "sizeof()", not "strlen()"!
 */
#define	NAME_ALL	"all"
#define	NAME_ANY	"any"
#define	NAME_NONE	"none"
#define	NAME_TERMINFO	"terminfo"
#define	NAME_SIMPLE	"simple"
#define	NAME_HOLD	"hold"
#define	NAME_RESUME	"resume"
#define	NAME_IMMEDIATE	"immediate"
#define	NAME_CONTINUE	"continue"
#define	NAME_BEGINNING	"beginning"
#define	NAME_WAIT	"wait"
#define	NAME_MAIL	"mail"
#define	NAME_WRITE	"write"
#define	NAME_QUIET	"quiet"
#define	NAME_LIST	"list"
#define	NAME_ON		"on"
#define	NAME_OFF	"off"
#define	NAME_OPTIONAL	"optional"
#define	NAME_ALWAYS	"Always"
#define	NAME_UNKNOWN	"unknown"
#define	NAME_REJECTING	"rejecting"
#define	NAME_ACCEPTING	"accepting"
#define	NAME_DISABLED	"disabled"
#define	NAME_ENABLED	"enabled"
#define	NAME_DIRECT	"direct"
#define	NAME_PICA	"pica"
#define	NAME_ELITE	"elite"
#define	NAME_COMPRESSED	"compressed"
#define	NAME_ALLOW	"allow"
#define	NAME_DENY	"deny"
#define	NAME_ONCE	"once"
#define	NAME_DEFAULT	"default"
#define	NAME_KEEP	"keep"

/*
 * Common messages:
 */

#define	CUZ_NEW_PRINTER		"new printer"
#define	CUZ_NEW_DEST		"new destination"
#define	CUZ_STOPPED		"stopped with printer fault"
#define	CUZ_FAULT		"printer fault"
#define	CUZ_LOGIN_PRINTER	"disabled by Spooler: login terminal"
#define	CUZ_MOUNTING		"mounting a form"
#define	CUZ_NOFORK		"can't fork"
#define	CUZ_PRINTING_OK		"ready and printing"

#define	TIMEOUT_FAULT \
"Timed-out trying to open the printer port.\n"

#define	OPEN_FAULT \
"Failed to open the printer port.\n"

#define	PUSH_FAULT \
"Failed to push module(s) onto the printer port stream.\n"

/*
 * When the Spooler detected the hangup, this message is used.
 */
#define	HANGUP_FAULT \
"The connection to the printer dropped; perhaps the printer went off-line!\n"

/*
 * When lp.cat detected the hangup, this message is used.
 */
#define	HANGUP_FAULT_LPCAT \
"The connection to the printer dropped; perhaps the printer went off-line.\n"

#define	INTERRUPT_FAULT	\
"Received an interrupt from the printer. The reason is unknown,\n\
although a common cause is that the printer's buffer capacity\n\
was exceeded. Using XON/XOFF flow control, adding carriage-return\n\
delays, or lowering the baud rate may fix the problem.\n\
See stty(1) and lpadmin(8) man-pages for help in doing this.\n"

#define	PIPE_FAULT \
"The output ``port'', a FIFO, was closed before all output was written.\n"

#define	EXIT_FAULT \
"The interface program returned with a reserved exit code.\n"

/*
 * Lp-errno #defines, etc.
 */

#define	LP_EBADSDN	1
#define	LP_EBADINT	2
#define	LP_EBADNAME	3
#define	LP_EBADARG	4
#define	LP_ETRAILIN	5
#define	LP_ENOCMT	6
#define	LP_EBADCTYPE	7
#define	LP_ENOALP	8
#define	LP_ENULLPTR	9
#define	LP_EBADHDR	10
#define	LP_ETEMPLATE	11
#define	LP_EKEYWORD	12
#define	LP_EPATTERN	13
#define	LP_ERESULT	14
#define	LP_EREGEX	15  /* and see extern int regerrno, regexpr(3GEN) */
#define	LP_ENOMEM	99

extern int		lp_errno;

/*
 * Misc. Macros
 */

#define	LP_WS		" "	/* Whitespace (also list separator) */
#define	LP_SEP		","	/* List separator */
#define	LP_QUOTES	"'\""

#define	MAIL		"mail"
#define	WRITE		"write"

#define	STATUS_BREAK	"=========="

#define	STREQU(A, B)	((!(A) || !(B)) ? 0 : (strcmp((A), (B)) == 0))
#define	STRNEQU(A, B, N) ((!(A) || !(B)) ? 0 : (strncmp((A), (B), (N)) == 0))
#define	CS_STREQU(A, B)	(cs_strcmp((A), (B)) == 0)
#define	CS_STRNEQU(A, B, N) (cs_strncmp((A), (B), (N)) == 0)
#define	STRSIZE(X)	(sizeof (X) - 1)

/*
 * Almost STREQU but compares null pointers as equal, too.
 */
#define	SAME(A, B)	((A) == (B) || (A) && (B) && STREQU((A), (B)))

#define	PRINTF		(void)printf
#define	SPRINTF		(void)sprintf
#define	FPRINTF		(void)fprintf

#define	NB(X)		(X? X : "")

#define	PERROR		strerror(errno)

/*
 * Largest number we'll ever expect to get from doing %ld in printf,
 * as a string and number. ULONG_MAX from limits.h gives us the number,
 * but I can't figure out how to get that into a string.
 */
#define	BIGGEST_NUMBER		ULONG_MAX
#define	BIGGEST_NUMBER_S	"4294967295"

/*
 * Largest request ID (numerical part), as string and number.
 * See comment above.
 */
#define	BIGGEST_REQID		999999
#define	BIGGEST_REQID_S		"999999"

/*
 * Maximum number of files queued per request, as string and number.
 * See earlier comment above.
 */
#define	MOST_FILES	999999
#define	MOST_FILES_S	"999999"

/*
 * Alert macros:
 */

/*
 * Type of alert to be S_QUIET'd
 */
#define	QA_FORM		1
#define	QA_PRINTER	2
#define	QA_PRINTWHEEL	3

/*
 * File modes:
 * (The "NO" prefix is relative to ``others''.)
 */

#define	MODE_READ	(mode_t)0664
#define	MODE_NOREAD	(mode_t)0660
#define	MODE_EXEC	(mode_t)0775
#define	MODE_NOEXEC	(mode_t)0770
#define	MODE_DIR	(mode_t)0775
#define	MODE_NODIR	(mode_t)0770

extern int	printlist_qsep;

extern char	Lp_Spooldir[],
		Lp_Admins[],
		Lp_Bin[],
		Lp_FIFO[],
		Lp_Logs[],
		Lp_ReqLog[],
		Lp_Model[],
		Lp_Requests[],
		Lp_Secure[],
		Lp_Schedlock[],
		Lp_Slow_Filter[],
		Lp_System[],
		Lp_Temp[],
		Lp_Tmp[],
		Lp_Users[],
		Lp_A[],
		Lp_A_Classes[],
		Lp_A_Forms[],
		Lp_A_Interfaces[],
		Lp_A_Logs[],
		Lp_A_Printers[],
		Lp_A_PrintWheels[],
		Lp_A_Filters[],
		Lp_A_Systems[],
		Lp_Default[],
		Lp_A_Faults[];

/*
 * File access:
 */

extern int	open_locked(char *, char *, mode_t);
extern char	*fdgets(char *, int, int);
extern int	fdprintf(int, char *, ...);
extern int	fdputs(char *, int);
extern int	fdputc(char, int);

extern int	is_printer_uri(char *);

FILE		*open_lpfile(char *, char *, mode_t);
int		close_lpfile(FILE *);
int		chown_lppath(char *);
int		mkdir_lpdir(char *, int);
int		rmfile(char *);
int		dumpstring(char *, char *);

char		*loadstring(char *);
char		*loadline(char *);
char		*sop_up_rest(int, char *);

/*
 * List manipulation routines:
 */

#define	emptylist(LP)	(!(LP) || !(LP)[0])

int		addlist(char ***, char *);
int		addstring(char **, char *);
int		appendlist(char ***, char *);
int		dellist(char ***, char *);
int		joinlist(char ***, char **);
int		lenlist(char **);
int		printlist(FILE *, char **);
int		fdprintlist(int, char **);
int		searchlist(char *, char **);
int		searchlist_with_terminfo(char *, char **);

char		**duplist(char **);
char		**getlist(char *, char *, char *);
char		**dashos(char *);
char		**wherelist(char *, char **);

char		*sprintlist(char **);
char		*search_cslist(char *, char **);

void		freelist(char **);
void		printlist_setup(char *, char *, char *, char *);
void		printlist_unsetup(void);

/*
 * Scaled decimal number routines:
 */

#define	getsdn(S)	_getsdn(S, (char **)0, 0)
#define	getcpi(S)	_getsdn(S, (char **)0, 1)

#define	N_COMPRESSED	9999

void		printsdn(FILE *, SCALED);
void		fdprintsdn(int, SCALED);
void		printsdn_setup(char *, char *, char *);
void		printsdn_unsetup(void);

SCALED		_getsdn(char *, char **, int);

/*
 * File name routines:
 */

char		*makepath(char *, ...);
char		*getspooldir(void);
char		*getrequestfile(char *);
char		*getprinterfile(char *, char *);
char		*getsystemfile(char *, char *);
char		*getclassfile(char *);
char		*getfilterfile(char *);
char		*getformfile(char *, char *);

/*
 * Additional string manipulation routines:
 */

int		cs_strcmp(char *, char *);
int		cs_strncmp(char *, char *, int);

/*
 * Syntax checking routines:
 */

int		syn_name(char *);
int		syn_text(char *);
int		syn_comment(char *);
int		syn_machine_name(char *);
int		syn_option(char *);

/*
 * Alert management routines:
 */

int		putalert(char *, char *, FALERT *);
int		delalert(char *, char *);

FALERT		*getalert(char *, char *);

void		printalert(FILE *, FALERT *, int);

/*
 * Terminfo Database Inquiry Tool
 */

int		tidbit(char *, char *, ...);
void		untidbit(char *);

/*
 * Auto-restarting and other system calls:
 * The two versions are here to reduce the chance of colliding
 * with similar names in standard libraries (e.g. dial(3C) uses
 * Read/Write).
 */

#define	Access	_Access
#define	Chdir	_Chdir
#define	Chmod	_Chmod
#define	Chown	_Chown
#define	Close	_Close
#define	Creat	_Creat
#define	Fcntl	_Fcntl
#define	Fstat	_Fstat
#define	Link	_Link
#define	Lstat	_Lstat
#define	Mknod	_Mknod
#define	Open	_Open
#define	Read	_Read
#define	Readlink _Readlink
#define	Rename	_Rename
#define	Stat	_Stat
#define	Symlink	_Symlink
#define	Unlink	_Unlink
#define	Wait	_Wait
#define	Write	_Write

#define	Malloc(size)		_Malloc(size, __FILE__, __LINE__)
#define	Realloc(ptr, size)	_Realloc(ptr, size, __FILE__, __LINE__)
#define	Calloc(nelem, elsize)	_Calloc(nelem, elsize, __FILE__, __LINE__)
#define	Strdup(s)		_Strdup(s, __FILE__, __LINE__)
#define	Free(ptr)		_Free(ptr, __FILE__, __LINE__)

int		_Access(char *, int);
int		_Chdir(char *);
int		_Chmod(char *, int);
int		_Chown(char *, int, int);
int		_Close(int);
int		_Creat(char *, int);
int		_Fcntl(int, int, ...);
int		_Fstat(int, struct stat *);
int		_Link(char *, char *);
int		_Lstat(char *, struct stat *);
int		_Mknod(char *, int, int);
int		_Mkpipe(char *, int, int);
int		_Open(char *, int, ... /* mode_t */);
int		_Read(int, char *, unsigned int);
int		_Readlink(char *, char *, unsigned int);
int		_Rename(char *, char *);
int		_Symlink(char *, char *);
int		_Stat(char *, struct stat *);
int		_Unlink(char *);
int		_Wait(int *);
int		_Write(int, char *, unsigned int);

void		*_Malloc(size_t, const char *, int);
void		*_Realloc(void *, size_t, const char *, int);
void		*_Calloc(size_t, size_t, const char *, int);
char		*_Strdup(const char *, const char *, int);
void		_Free(void *, const char *, int);

/*
 * Misc. routines:
 */

int		isterminfo(char *);
int		isprinter(char *);
int		isrequest(char *);
int		isnumber(char *);

char		*getname(void);
char		*makestr(char *, ...);
char		*strip(char *);

void		sendmail(char *, char *);

extern void	(*lp_alloc_fail_handler)(void);

/*
 * Originally part of liblpfs.a and fs.h, now no longer needed
 * since the code doesn't have to work on pre-SVR4.0.
 */
#define	Opendir		opendir
#define	Telldir		telldir
#define	Seekdir		seekdir
#define	Rewinddir(dirp)	Seekdir(dirp, 0L)
#define	Closedir	closedir
#define	Readdir		readdir
#define	Mkdir		mkdir
#define	Rmdir		rmdir

#define	next_dir(base, ptr)	next_x(base, ptr, S_IFDIR)
#define	next_file(base, ptr)	next_x(base, ptr, S_IFREG)

extern int chownmod(char *, uid_t, gid_t, mode_t);


char		*next_x(char *, long *, unsigned int);

/*
 * Stuff needed for Trusted Extensions
 */

extern	char	*get_labeled_zonename(char *);
extern int	get_peer_label(int, char **);


#ifdef __cplusplus
}
#endif

#endif	/* _LP_LP_H */
