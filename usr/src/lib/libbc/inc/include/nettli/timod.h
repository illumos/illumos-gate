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
/*	from S5R3 sys/timod.h	10.3.1.1" */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/* #ident	"@(#)kern-port:sys/timod.h	10.3.1.1" */

#ifndef _nettli_timod_h
#define _nettli_timod_h

/* internal flags */
#define USED		0x01	/* data structure in use          */
#define FATAL		0x02	/* fatal error M_ERROR occurred   */
#define WAITIOCACK	0x04	/* waiting for info for ioctl act */
#define MORE	        0x08	/* more data */



/* timod ioctls */
#define		TIMOD 		('T'<<8)
#define		TI_GETINFO	(TIMOD|100)
#define		TI_OPTMGMT	(TIMOD|101)
#define		TI_BIND		(TIMOD|102)
#define		TI_UNBIND	(TIMOD|103)


/* TI interface user level structure - one per open file */

struct _ti_user {
	ushort	ti_flags;	/* flags              */
	int	ti_rcvsize;	/* rcv buffer size    */
	char   *ti_rcvbuf;	/* rcv buffer         */
	int	ti_ctlsize;	/* ctl buffer size    */
	char   *ti_ctlbuf;	/* ctl buffer         */
	char   *ti_lookdbuf;	/* look data buffer   */
	char   *ti_lookcbuf;	/* look ctl buffer    */
	int	ti_lookdsize;  /* look data buf size */
	int	ti_lookcsize;  /* look ctl buf size  */
	int	ti_maxpsz;	/* TIDU size          */
	long	ti_servtype;	/* service type       */
	int     ti_lookflg;	/* buffered look flag */
};


/* This should be replaced */
#define OPENFILES     getdtablesize()

#endif /*!_nettli_timod_h*/
