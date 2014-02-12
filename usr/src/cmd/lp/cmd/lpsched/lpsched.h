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
/*	  All Rights Reserved  	*/


#include "stdio.h"
#include "sys/types.h"
#include "memory.h"
#include "string.h"
#include "pwd.h"
#include "fcntl.h"
#include "errno.h"
#include "signal.h"
#include "unistd.h"
#include "stdlib.h"

#include "lp.h"
#include "access.h"
#include "form.h"
#include "requests.h"
#include "filters.h"
#include "printers.h"
#include "class.h"
#include "users.h"
#include "secure.h"
#include "msgs.h"

#include "nodes.h"

/**
 ** Defines:
 **/

/*
 * These are the fields in the PSTATUS and CLSTATUS files,
 * found in the SYSTEM directory.
 */

#define PST_MAX	8
# define PST_BRK	0
# define PST_NAME	1
# define PST_STATUS	2
# define PST_DATE	3
# define PST_DISREAS	4
# define PST_REJREAS	5
# define PST_PWHEEL	6
# define PST_FORM	7

#define CST_MAX	5
# define CST_BRK	0
# define CST_NAME	1
# define CST_STATUS	2
# define CST_DATE	3
# define CST_REJREAS	4

/*
 * Exit codes from child processes:
 *
 *    0 <= exit <= 0177 (127) are reserved for ``normal'' exits.
 * 0200 <= exit <= 0377 (255) are reserved for special failures.
 *
 * If bit 0200 is set, then we have three sets of special error
 * codes available, with 32 values in each set (except the first):
 *
 *	0201 - 0237	Printer faults
 *	0240 - 0277	Dial problems
 *	0300 - 0337	Port problems
 *	0340 - 0377	Exec problems
 *
 *	0200		Interface received SIGTERM
 */
#define EXEC_EXIT_OKAY	0	/* success */
#define EXEC_EXIT_USER	0177	/* user exit codes, 7 bits */
#define EXEC_EXIT_NMASK	0340	/* mask to uncover reason bits */
#define EXEC_EXIT_FAULT	0201	/* printer fault */
#define EXEC_EXIT_HUP	0202	/* got hangup early in exec */
#define EXEC_EXIT_INTR	0203	/* got interrupt early in exec */
#define EXEC_EXIT_PIPE	0204	/* got close of FIFO early in exec */
#define EXEC_EXIT_EXIT	0237	/* interface used reserved exit code */
#define EXEC_EXIT_NDIAL	0240	/* can't dial, low 5 bits abs(dial()) */
#define EXEC_EXIT_NPORT	0300	/* can't open port */
#define EXEC_EXIT_TMOUT	0301	/* can't open port in N seconds */
#define EXEC_EXIT_NOPEN	0340	/* can't open input/output file */
#define EXEC_EXIT_NEXEC	0341	/* can't exec */
#define EXEC_EXIT_NOMEM	0342	/* malloc failed */
#define EXEC_EXIT_NFORK	0343	/* fork failed, must try again */
#define EXEC_EXIT_NPUSH 0344	/* could not push streams module(s) */

#define EXIT_RETRY	129	/* interface failed, try again */

/*
 * If killed, return signal, else 0.
 */
#define	KILLED(x) (!(x & 0xFF00)? (x & 0x7F) : 0)

/*
 * If exited, return exit code, else -1.
 */
#define	EXITED(x) (!(x & 0xFF)? ((x >> 8) & 0xFF) : -1)

/*
 * Events that can be scheduled:
 */
#define EV_SLOWF	1
#define	EV_INTERF	2
#define EV_NOTIFY	3
#define EV_LATER	4
#define EV_ALARM	5
#define	EV_MESSAGE	6
#define EV_ENABLE	7
#define	EV_FORM_MESSAGE	8

/*
 * How long to wait before retrying an event:
 * (For best results, make CLOCK_TICK a factor of 60.)
 */
#define CLOCK_TICK	10		/* no. seconds between alarms	*/
#define MINUTE		(60/CLOCK_TICK)	/* number of ticks per minute	*/
#define WHEN_FORK	(MINUTE)	/* retry forking child process	*/
#define WHEN_PRINTER	(1*MINUTE)	/* retry faulted printer	*/

/*
 * Alert types:
 */
#define	A_PRINTER	1
#define	A_PWHEEL	2
#define	A_FORM		3

/*
 * How to handle active requests when disabling a printer:
 */
#define DISABLE_STOP    0
#define DISABLE_FINISH  1
#define DISABLE_CANCEL  2

/*
 * validate_request() - VERIFY REQUEST CAN BE PRINTED
 * evaluate_request() - TRY REQUEST ON A PARTICULAR PRINTER
 * reevaluate_request() - TRY TO MOVE REQUEST TO ANOTHER PRINTER
 */

#define validate_request(PRS,PREFIXP,MOVING) \
	_validate((PRS), (PSTATUS *)0, (PSTATUS *)0, (PREFIXP), (MOVING))

#define evaluate_request(PRS,PPS,MOVING) \
	_validate((PRS), (PPS), (PSTATUS *)0, (char **)0, (MOVING))

#define reevaluate_request(PRS,PPS) \
	_validate((PRS), (PSTATUS *)0, (PPS), (char **)0, 0)

/*
 * Request is ready to be slow-filtered:
 */
#define	NEEDS_FILTERING(PRS) \
	((PRS)->slow && !((PRS)->request->outcome & RS_FILTERED))

/*
 * Misc:
 */

#define	isadmin(ID)		(!(ID) || (ID) == Lp_Uid)

#define makereqerr(PRS) \
	makepath( \
		Lp_Temp, \
		getreqno((PRS)->secure->req_id), \
		(char *)0 \
	)

#define	EVER			;;

#define	DEFAULT_SHELL		"/bin/sh"

#define	BINMAIL			"/bin/mail"
#define	BINWRITE		"/bin/write"

#define RMCMD			"/usr/bin/rm -f"


#if	defined(MLISTENDEL_WORKS)
#define DROP_MD(MD)	if (MD) { \
			        mlistendel (MD); \
			        mdisconnect (MD); \
				MD = 0; \
			} else /*EMPTY*/
#else
#define DROP_MD(MD)	if (MD) { \
				Close ((MD)->readfd); \
				if ((MD)->writefd == (MD)->readfd) \
					(MD)->writefd = -1; \
				(MD)->readfd = -1; \
				MD = 0; \
			} else /*EMPTY*/
#endif

/**
 ** External routines:
 **/

typedef int (*qchk_fnc_type)( RSTATUS * );

CLASS *		Getclass ( char * );

extern void GetRequestFiles(REQUEST *req, char *buffer, int length);


PRINTER *	Getprinter ( char * );

PWHEEL *	Getpwheel ( char * );


REQUEST *	Getrequest ( char * );

RSTATUS *	request_by_id ( char * );
RSTATUS *	request_by_id_num ( long );
RSTATUS *	request_by_jobid ( char * , char * );

SECURE *	Getsecure ( char * );

USER *		Getuser ( char * );

_FORM *		Getform ( char * );

char *		_alloc_files ( int , char * , uid_t , gid_t);
char *		dispatchName(int);
char *		statusName(int);
char *		getreqno ( char * );

int		Loadfilters ( char * );
int		Putsecure(char *, SECURE *);
int		cancel ( RSTATUS * , int );
int		disable ( PSTATUS * , char * , int );
int		enable ( PSTATUS * );
int		exec ( int , ... );
int		one_printer_with_charsets ( RSTATUS * );
int		open_dialup ( char * , PRINTER * );
int		open_direct ( char * , PRINTER * );
int		qchk_filter ( RSTATUS * );
int		qchk_form ( RSTATUS * );
int		qchk_pwheel ( RSTATUS * );
int		qchk_waiting ( RSTATUS * );
int		queue_repel ( PSTATUS * , int , int (*)( RSTATUS * ) );
int		rsort ( RSTATUS ** , RSTATUS ** );

long		getkey ( void );
long		_alloc_req_id ( void );

off_t		chfiles ( char ** , uid_t , gid_t );

short		_validate ( RSTATUS * , PSTATUS * , PSTATUS * , char ** , int );

void		add_flt_act ( MESG * , ... );
void		alert ( int , ... );
void		cancel_alert ( int , ... );
void		check_children ( void );
void		check_form_alert ( FSTATUS * , _FORM * );
void		check_pwheel_alert ( PWSTATUS * , PWHEEL * );
void		check_request ( RSTATUS * );
void		del_flt_act ( MESG * , ... );
void		dial_problem ( PSTATUS * , RSTATUS * , int );
void		dispatch ( int , char * , MESG * );
void		dowait ( void );
void		dump_cstatus ( void );
void		dump_fault_status(PSTATUS *);
void		dump_pstatus ( void );
void		dump_status ( void );
void		execlog ( char * , ... );
void		fail ( char * , ... );
void		free_form ( _FORM * );
void		freerstatus ( register RSTATUS * );
void		init_memory ( void );
void		init_messages ( void );
void		insertr ( RSTATUS * );
void		load_sdn ( char ** , SCALED );
void		load_status ( void );
void		load_str ( char ** , char * );
void		lp_endpwent ( void );
void		lp_setpwent ( void );
void		lpfsck ( void );
void		lpshut ( int );
void		mallocfail ( void );
void		maybe_schedule ( RSTATUS * );
void		note ( char * ,	... );
void		notify ( RSTATUS * , char * , int , int , int );
void		printer_fault ( PSTATUS * , RSTATUS * , char * , int );
void		clear_printer_fault ( PSTATUS * ,  char * );
void		putjobfiles ( RSTATUS * );
void		queue_attract ( PSTATUS * , int (*)( RSTATUS * ) , int );
void		queue_check ( int (*)( RSTATUS * ) );
void		queue_form ( RSTATUS * , FSTATUS * );
void		queue_pwheel ( RSTATUS * , char * );
void		remount_form(register PSTATUS *, FSTATUS *, short);
void		remover ( RSTATUS * );
void		rmfiles ( RSTATUS * , int );
void		rmreq ( RSTATUS * );
void		schedule ( int , ... );
void		take_message ( void );
void		terminate ( EXEC * );
void		unload_list ( char *** );
void		unload_str ( char ** );
void		unqueue_form ( RSTATUS * );
void		unqueue_pwheel ( RSTATUS * );
void		update_req ( char * , long );
int		isFormMountedOnPrinter ( PSTATUS *, FSTATUS * );
int		isFormUsableOnPrinter ( PSTATUS *, FSTATUS * );
char		*allTraysWithForm ( PSTATUS *, FSTATUS * );
extern int		list_append(void ***, void *);
extern void		list_remove(void ***, void *);

extern RSTATUS	*new_rstatus(REQUEST *, SECURE *);
extern PSTATUS	*new_pstatus(PRINTER *);
extern CLSTATUS	*new_cstatus(CLASS *);
extern FSTATUS	*new_fstatus(_FORM *f);
extern PWSTATUS	*new_pwstatus(PWHEEL *p);
extern ALERT	*new_alert(char *fmt, int i);
extern EXEC	*new_exec(int type, void *ex);

extern void	pstatus_add_printer(PSTATUS *, PRINTER *);

extern void	free_exec(EXEC *);
extern void	free_alert(ALERT *);
extern void	free_pwstatus(PWSTATUS *);
extern void	free_fstatus(FSTATUS *);
extern void	free_cstatus(CLSTATUS *);
extern void	free_pstatus(PSTATUS *);
extern void	free_rstatus(RSTATUS *);

extern CLSTATUS	*search_cstatus ( char * );
extern FSTATUS	*search_fptable(register char *);
extern FSTATUS	*search_fstatus ( char * );
extern PSTATUS	*search_pstatus ( char * );
extern PWSTATUS	*search_pwstatus ( char * );

/*
 * Things that can't be passed as parameters:
 */

extern FSTATUS		*form_in_question;

extern char		*pwheel_in_question;

/**
 ** External tables, lists:
 **/

extern CLSTATUS		**CStatus;	/* Status of classes       */
extern PSTATUS		**PStatus;	/* Status of printers      */
extern FSTATUS		**FStatus;	/* Status of forms	   */
extern PWSTATUS		**PWStatus;	/* Status of print wheels  */

extern EXEC		**Exec_Table;	/* Running processes       */
extern EXEC		**Exec_Slow,	/* First slow filter exec  */
			**Exec_Notify;	/* First notification exec */

extern RSTATUS		*Request_List;	/* Queue of print requests */
extern RSTATUS		*NewRequest;	/* Not in Request_List yet */

extern int		ET_SlowSize,	/* Number of filter execs  	*/
			ET_NotifySize;	/* Number of notify execs  	*/

#if	defined(DEBUG)
#define DB_ABORT	0x00000008
#define DB_SDB		0x00000020
#define DB_ALL		0xFFFFFFFF

extern unsigned long	debug;
#endif

extern char		*Local_System,	/* Node name of local system	*/
			*SHELL;		/* value of $SHELL, or default	*/

extern int		lock_fd;

extern uid_t		Lp_Uid;

extern gid_t		Lp_Gid;

extern int		Starting,
			OpenMax,
			Sig_Alrm,
			DoneChildren,
			am_in_background,
			Shutdown;

extern unsigned long	chkprinter_result;

#if defined(MDL)
#include	"mdl.h"
#endif
# define	CLOSE_ON_EXEC(fd)	(void) Fcntl(fd, F_SETFD, 1)
