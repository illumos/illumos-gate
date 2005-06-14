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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef struct alert_node	ALERT;
typedef struct cstat_node	CSTATUS;
typedef struct exec_node	EXEC;
typedef struct form_node	_FORM;
typedef struct fstat_node	FSTATUS;
typedef struct pfstat_node	PFSTATUS;
typedef struct pstat_node	PSTATUS;
typedef struct pwstat_node	PWSTATUS;
typedef struct rstat_node	RSTATUS;
typedef struct waiting_node	WAITING;
typedef struct susp_node	SUSPENDED;

struct alert_node
{
    short	active;			/* Non-zero if triggered     */
    EXEC	*exec;			/* Index into EXEC table     */
    char	*msgfile;
};

struct cstat_node
{
    short	status;
    char	*rej_reason;
    time_t	rej_date;
    CLASS	*class;
};

struct exec_node
{
    int		pid;			/* process-id of exec		*/
    int		status;			/* low order bits from wait	*/
    long	key;			/* private key for security	*/
    short	Errno;			/* copy of child's errno	*/
    short	type;			/* type of exec, EX_...		*/
    ushort	flags;			/* flags, EXF_...		*/
    MESG	*md;
    union ex
    {
	RSTATUS		*request;
	FSTATUS		*form;
	PWSTATUS	*pwheel;
	PSTATUS		*printer;
    } ex;
};

struct waiting_node
{
    WAITING	*next;
    MESG	*md;
};

struct susp_node
{
    SUSPENDED	*next;
    char	*message;
    MESG	*md;
};

#define	EX_INTERF	1	/* exec interface for ex.printer	*/
#define	EX_SLOWF	2	/* exec slow filter for ex.request	*/
#define	EX_ALERT	3	/* exec alert for ex.printer		*/
#define	EX_FALERT	4	/* exec alert for ex.form		*/
#define	EX_PALERT	5	/* exec alert for ex.pwheel		*/
#define	EX_NOTIFY	6	/* exec notification for ex.request	*/
#define	EX_FAULT_MESSAGE 7	/* exec fault message*/
#define	EX_FORM_MESSAGE	8	/* form fault message*/

#define REX_INTERF	1	/* send print request to remote		*/
#define REX_CANCEL	2	/* send cancellation to remote		*/
#define REX_NOTIFY	3	/* send job termination note to remote	*/
#define REX_STATUS	4	/* send status request to remote	*/
#define REX_FAULT_MESSAGE 5	/* fault message to remote */
#define REX_FORM_MESSAGE 6	/* form message to remote */

#define	EXF_RESTART	0x0001	/* restart the exec			*/
#define	EXF_KILLED	0x0002	/* terminate() has killed the exec	*/
#define	EXF_GONE	0x0004	/* child has disappeared		*/
#define EXF_WAITCHILD	0x0008	/* waiting for R_NEW_CHILD		*/
#define EXF_WAITJOB	0x0010	/* waiting for R_SEND_JOB		*/

/*
**	Possible values for FLT.type
*/
#define        FLT_FILES       1	/* remove alloc'd files		*/
#define        FLT_CHANGE      2	/* clear RS_CHANGING for .r1	*/

struct fstat_node
{
    _FORM	*form;
    ALERT	*alert;
    short	requests;		/* Number of events thus far */
    short	requests_last;		/* # when alert last sent */
    short	trigger;		/* Trigger when this value   */
    short	mounted;		/* # times currently mounted */
    char	**users_allowed;
    char	**users_denied;
    char	*cpi;
    char	*lpi;
    char	*plen;
    char	*pwid;
};

struct pfstat_node
{
	FSTATUS	*form;
	short isAvailable;
};

struct pstat_node
{
    short	status;			/* Current Status of printer */
    RSTATUS	*request;
    PRINTER	*printer;
    ALERT	*alert;
    EXEC	*exec;
    PFSTATUS	*forms;
    char	*pwheel_name;
    PWSTATUS	*pwheel;
    char	*dis_reason;
    char	*rej_reason;
    char	**users_allowed;
    char	**users_denied;
    char	**forms_allowed;
    char	**forms_denied;
    char	*cpi;
    char	*lpi;
    char	*plen;
    char	*pwid;
    time_t	dis_date;
    time_t	rej_date;
    short	last_dial_rc;		/* last exit from dial() */
    short	nretry;			/* number of dial attempts */
    char	*remote_name;
    short	nrequests;		/* TEMP ONLY! (used variously) */
    char	*fault_reason;
    EXEC	*fault_exec;
    short	numForms;
    char	**paper_allowed;
};

struct pwstat_node
{
    PWHEEL	*pwheel;
    ALERT	*alert;
    short	requests;
    short	requests_last;		/* # when alert last sent */
    short	trigger;
    short	mounted;
};

#if	defined(OLD_MSG_STUFF)

#define CLIENT_NEW		1
#define CLIENT_PROTOCOL		2
#define CLIENT_TALKING		3

struct mque_node
{
    char		*msgbuf;
    unsigned int	size;
    struct mque_node	*next;
};

struct client_node
{
    ushort		uid;		/* User id of client		*/
    ushort		gid;		/* Group id of client		*/
    char		admin;		/* Non-zero if client is admin	*/
    char		state;		/* (CLIENT_... value)		*/
    FLT			*flt;		/* Linked list of fault actions */
    char		*fifo;		/* Name of client's fifo	*/
    char		*system;	/* Name of client's system	*/
    int			fd;		/* File-descriptor of open fifo	*/
    char		authcode[HEAD_AUTHCODE_LEN];
					/* ``Password'' to verify client*/
    MQUE		*mque;		/* Linked list of pending msgs.	*/
};

#else

#define	NODE		MESG
#define send		mputm

#endif

struct rstat_node
{
    long	status;
    long	rank;
    MESG	*md;
    
    char	*req_file;
    char	*slow;
    char	*fast;
    short	copies;		/* # copies interface is to make */    
    short	reason;		/* reason for failing _validate() */

    SECURE	*secure;
    REQUEST	*request;
    PSTATUS	*printer;
    FSTATUS	*form;
    char	*pwheel_name;
    PWSTATUS	*pwheel;
    EXEC	*exec;		/* Pointer to running filter or notify */

    char	*printer_type;
    char	*output_type;
    char	*cpi;
    char	*lpi;
    char	*plen;
    char	*pwid;

    RSTATUS	*next;
    RSTATUS	*prev;
    short	msgType; /* for getting status */
    short	trayNum; /* for mounting trays remotely */
    char	*formName; /* for mounting forms remotely */
};

# define	RSS_MARK	0x00000001
# define	RSS_RANK	0x00000002
# define	RSS_SENDREMOTE	0x00000004 /* request needs to be sent */
# define	RSS_PWMAND	0x00000008 /* pwheel must be mounted */
# define	RSS_GETSTATUS	0x00000010 /* get remote status */
# define	RSS_RECVSTATUS	0x00000020 /* waiting for remote status */
# define	RSS_SEND_FAULT_MESSAGE	0x00000040 /* need to send message*/
# define	RSS_SEND_FORM_MESSAGE	0x00000080 /* need to send form message*/

struct form_node
{
    SCALED	plen;
    SCALED	pwid;
    SCALED	lpi;
    SCALED	cpi;
    int	np;
    char	*chset;
    short	mandatory;
    char	*rcolor;
    char	*comment;
    char	*conttype;
    char	*name;
    FALERT	alert;
    char	*paper;
    short	isDefault;
};

# define	LP_EXEC		0
# define	LP_SCHED	1
# define	LP_NET		2
# define	LP_FILTER	3
# define	LP_PRINTER	4
# define	LP_ALERT	5
# define	LP_NOTIFY	6
# define	LP_SYSTEM	7
# define	LP_PWHEEL	8
# define	LP_FORM		9
# define	LP_LATER	10
# define	LP_ALARM	11

# define	LP_ACTIVE	0x080
# define	LP_ALERTING	0x100

# define	MINUTES			(60)

# define	USER_STATUS_EXPIRED	(3 * MINUTES)

# define	SYSTEM_STATUS_EXPIRED	(10 * MINUTES)

#define BEGIN_WALK_LOOP(PRS, CONDITION) \
	_BEGIN_WALK_LOOP("WALK", PRS, CONDITION) 

#define _BEGIN_WALK_LOOP(X, PRS, CONDITION) \
	{ \
		register RSTATUS	*pnext = 0; \
		for (PRS = Request_List; PRS; PRS = pnext) { \
			pnext = PRS->next; \
			if (CONDITION) {

#define	END_WALK_LOOP \
			} \
		} \
	}

#define BEGIN_WALK_BY_PRINTER_LOOP(PRS, PPS)	\
	_BEGIN_WALK_LOOP("WALK_BY_PRINTER", PRS, PRS->printer == PPS)

#define BEGIN_WALK_BY_DEST_LOOP(PRS, DEST) \
	_BEGIN_WALK_LOOP("WALK_BY_DEST", PRS, STREQU(PRS->request->destination, DEST))

#define BEGIN_WALK_BY_FORM_LOOP(PRS, PFS) \
	_BEGIN_WALK_LOOP("WALK_BY_FORM", PRS, PRS->form == PFS)

#define	BEGIN_WALK_BY_PWHEEL_LOOP(PRS, NAME) \
	_BEGIN_WALK_LOOP("WALK_BY_PWHEEL", PRS, PRS->pwheel_name && STREQU(PRS->pwheel_name, NAME))
