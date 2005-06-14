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


#ifndef _SYS_STERMIO_H
#define	_SYS_STERMIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.2 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl commands for control channels
 */
#define	STSTART		1	/* start protocol */
#define	STHALT		2	/* cease protocol */
#define	STPRINT		3	/* assign device to printer */
#define	STENABLE	4	/* enable polling */
#define	STDISABLE	5	/* disable polling */
#define	STPOLL		6	/* set polling rate */
#define	STCNTRS		7	/* poke for status reports */
#define	STTCHAN		8	/* set trace channel number */

/*
 * ioctl commands for terminal and printer channels
 */
#define	STGET	(('X'<<8)|0)	/* get line options */
#define	STSET	(('X'<<8)|1)	/* set line options */
#define	STTHROW	(('X'<<8)|2)	/* throw away queued input */
#define	STWLINE	(('X'<<8)|3)	/* get synchronous line # */
#define	STTSV	(('X'<<8)|4)	/* get all line information */

struct stio {
	unsigned short	ttyid;
	char		row;
	char		col;
	char		orow;
	char		ocol;
	char		tab;
	char		aid;
	char		ss1;
	char		ss2;
	unsigned short	imode;
	unsigned short	lmode;
	unsigned short	omode;
};

/*
 *	Mode Definitions.
 */
#define	STFLUSH	00400	/* FLUSH mode; lmode */
#define	STWRAP	01000	/* WRAP mode; lmode */
#define	STAPPL	02000	/* APPLICATION mode; lmode */

struct sttsv {
	char	st_major;
	short	st_pcdnum;
	char	st_devaddr;
	int	st_csidev;
};

struct stcntrs {
	char	st_lrc;
	char	st_xnaks;
	char	st_rnaks;
	char	st_xwaks;
	char	st_rwaks;
	char	st_scc;
};

/* trace message definitions */

#define	LOC	113	/* loss of carrier */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STERMIO_H */
