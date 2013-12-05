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


typedef struct alert_node	ALERT;
typedef struct cstat_node	CLSTATUS;
typedef struct exec_node	EXEC;
typedef struct form_node	_FORM;
typedef struct fstat_node	FSTATUS;
typedef struct pfstat_node	PFSTATUS;
typedef struct pstat_node	PSTATUS;
typedef struct pwstat_node	PWSTATUS;
typedef struct rstat_node	RSTATUS;

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

#define	EX_INTERF	1	/* exec interface for ex.printer	*/
#define	EX_SLOWF	2	/* exec slow filter for ex.request	*/
#define	EX_ALERT	3	/* exec alert for ex.printer		*/
#define	EX_FALERT	4	/* exec alert for ex.form		*/
#define	EX_PALERT	5	/* exec alert for ex.pwheel		*/
#define	EX_NOTIFY	6	/* exec notification for ex.request	*/
#define	EX_FAULT_MESSAGE 7	/* exec fault message*/
#define	EX_FORM_MESSAGE	8	/* form fault message*/

#define	EXF_RESTART	0x0001	/* restart the exec			*/
#define	EXF_KILLED	0x0002	/* terminate() has killed the exec	*/
#define	EXF_GONE	0x0004	/* child has disappeared		*/

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

#define send		mputm

struct rstat_node
{
    long	status;
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

# define	RSS_PWMAND	0x00000008 /* pwheel must be mounted */
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
