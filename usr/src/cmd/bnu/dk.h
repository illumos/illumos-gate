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
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _BNU_DK_H
#define _BNU_DK_H

#ifdef DIAL
#define GLOBAL static
#define EXTERN static
#else
#define EXTERN extern
#define GLOBAL
#endif

/*
 *	DATAKIT VCS User Level definitions
 *		@(#)dk.h	2.13+BNU DKHOST 87/06/01
 *
 *	CommKit(R) Software - Datakit(R) VCS Interface Release
 */


/*
 *	ioctl codes
 */

#define	DKIODIAL	(('k'<<8)|0)	/* dial out */
#define	DKIOCNEW	(('k'<<8)|1)	/* offer a service */
#define	DKIOCREQ	(('k'<<8)|2)	/* request service (SU only) */
#define	DKIORESET	(('k'<<8)|3)	/* reset interface */
#define DKKMCSET	(('k'<<8)|4)	/* associate logical interface
					   with physical KMC # */

#define DKIOCSPL	(('s'<<8)|1)	/* splice two circuits together (SU only) */
#define	DIOCSWAIT	(('s'<<8)|2)	/* wait for splice to take place */


/*     driver control        */

#define DIOCEXCL	(('d'<<8)|1)	/* exclusive use */
#define DIOCNXCL	(('d'<<8)|2)	/* reset exclusive use */
#define	DIOCRMODE	(('d'<<8)|3)	/* set receiver termination modes */
#define	DIOCQQABO	(('d'<<8)|4)	/* inquire status of last read */
#define	DIOCSIG		(('d'<<8)|5)	/* start short read, signal when done */

#define	DIOCXCTL	(('d'<<8)|8)	/* send ctl envelope on next write */
#define DIOCFLUSH	(('d'<<8)|9)	/* flush output */
#define DIOCSETK	(('d'<<8)|10)	/* debug info from kmc xmit&recv */
#define	DIOCQSTAT	(('d'<<8)|11)	/* return 3B hw/fw log data */
#define	DIOCBSIZE	(('d'<<8)|12)	/* set URP block size */
#define	DIOCTIME	(('d'<<8)|13)	/* set stagnation timeout value */
#define	DIOCTRAP	(('d'<<8)|14)	/* activate trsave trace for channel */

/*	interface memory read/write codes	 */

#define	DIOCHWREAD	(('d'<<8)|15)	/* read interface RAM */
#define	DIOCHWRITE	(('d'<<8)|16)	/* write interface RAM */

/*	diagnostic control codes	*/

#define	DIOCDKDGN	(('d'<<8)|17)	/* execute on-line diagnostics */
#define	DIOCDGNSET	(('d'<<8)|18)	/* initialize diagnostic mode */
#define	DIOCDGNCLR	(('d'<<8)|19)	/* clear diagnostic mode */

/*	3b2/PE codes			*/
#define TCDKIDLD	(('d'<<8)|20)	/* download the PE */
#define TCDKIFCF	(('d'<<8)|21)	/* Force call to function */
#define TCDKIRST	(('d'<<8)|22)	/* Reset the PE board */
#define	TCDKISYSG	(('d'<<8)|23)	/*sysgen the PE board */

/* Get info from driver */
#define DIOCINFO	(('d'<<8)|24)	/* get chans per interface*/
#define	TCDKIBUG	(('d'<<8)|25)	/*turn debug on on the PE board */
#define	DIOOPEN 	(('d'<<8)|26)	/* inquire channel open status*/
/*	special codes used by dkxstdio	*/

#define	DXIOEXIT	(('D'<<8)|'T')	/* process exit code */

/*
 *	structure returned from DIOCQQABO giving receive status
 */
struct dkqqabo {
	short	rcv_resid ;		/* residual length in buffer */
	short	rcv_reason ;		/* set of bits giving reasons */
	short	rcv_ctlchar ;		/* ctl char that finished block */
} ;

/*
 *   receive mode, and completion indicators
 *	also defined in sys/dkit.h
 */

#ifndef DKR_FULL
#define	DKR_FULL	01	/* buffer full, normal read done */
#define	DKR_CNTL	02	/* read terminated on control character */
#define	DKR_ABORT	010	/* receive aborted by higher level command */
#define	DKR_BLOCK	040	/* end of block */
#define	DKR_TIME	0100	/* end of time limit reached */
#endif



/*
 *	structure passed with ioctl to request a service
 *	actually used as a general-purpose struct to pass
 *	info from a kernel ioctl to user space.
 */
struct diocreq {
	short	req_traffic ;		/* traffic intensity generated */
	short	req_1param ;		/* typ: service requested */
	short	req_2param ;		/* parameter to server */
} ;


/*
 *	values returned from service request
 */
#define	req_error	req_traffic
#define	req_driver	req_traffic
#define	req_chans	req_traffic
#define	req_chmin	req_1param


/*
 *	structure received by server when new connection made
 */
struct mgrmsg {
	short	m_chan ;		/* channel number of connection */
	unsigned short	m_tstamp ;	/* time stamp of request */
	char *	m_protocol ;		/* protocol options from user */
	char *	m_origtype ;		/* type of originating device */
	char *	m_parm ;		/* parameter string from user */
	char *	m_uid ;			/* param from system/user, aka UID */
	char *	m_dial ;		/* dial string entered */
	char *	m_source ;		/* originator, as known to remote node */
	char *	m_lname ;		/* originator, as known to local node */
	char *	m_service ;		/* service type requested by user */
	char *	m_lflag ;		/* L == call from local node,
					 * R == call from a remote one.   */
	char *	m_srcnode;		/* originating node (last segment)   */
	char *	m_srcmod;		/* originating mod		     */
	char *	m_srcchan;		/* originating channel		     */
	char *	m_cflag;		/* call flag: F=first, P=previous    */
	char *	m_errmsg ;		/* possible error msg if m_chan <= 0 */
} ;



/*
 *	routines declared in libdk.a
 */
EXTERN char		*dknamer();
EXTERN char		*dtnamer();
EXTERN char		*dxnamer();
EXTERN char		*dkfcanon(), *dktcanon();
EXTERN char		*dkerr();
EXTERN char		*maphost(), *miscfield();
#ifndef DIAL
EXTERN char		mh_hostname[];
#endif
EXTERN struct mgrmsg	*dkmgr();

EXTERN int		dk_verbose, dk_errno;


/*
 *	structure passed with ioctl to request a splice
 */
struct diocspl {
	short	spl_fdin;		/* the other file descriptor */
	short	spl_un1used;
	short	spl_un2used;
} ;

/*
 * Default file names
 */

#define SRVTAB "/etc/dksrvtab"
#define UIDTAB "/etc/dkuidtab"
#define SRVLOG "/usr/adm/dksrvlog"
#define HOSTAB "/etc/dkhosts"
#define DOTAB  "/usr/lib/dkdotab"

/*
 * Number of longs in the stat array returned by the firmware
 */
#define	STATLEN	16

#endif
