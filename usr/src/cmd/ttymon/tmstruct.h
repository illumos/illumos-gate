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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef	_TMSTRUCT_H
#define	_TMSTRUCT_H

/*
 * /etc/ttydefs structure
 */
struct Gdef {
	char		*g_id;		/* id for modes & speeds	*/
	char		*g_iflags;	/* initial terminal flags	*/
	char		*g_fflags;	/* final terminal flags		*/
	short		g_autobaud;	/* autobaud indicator		*/
	char		*g_nextid;	/* next id if this speed is wrong */
};

/*
 *	pmtab structure + internal data for ttymon
 */
struct pmtab {
	/* the following fields are from pmtab			*/
	char	*p_tag;		/* port/service tag		*/
	long	p_flags;	/* flags			*/
	char	*p_identity;	/* id for service to run as	*/
	char	*p_res1;	/* reserved field		*/
	char	*p_res2;	/* reserved field		*/
	char	*p_res3;	/* reserved field		*/
	char	*p_device;	/* full path name of device	*/
	long	p_ttyflags;	/* ttyflags			*/
	int	p_count;	/* wait_read count		*/
	char	*p_server;	/* full service cmd line	*/
	int	p_timeout;	/* timeout for input		*/
	char	*p_ttylabel;	/* ttylabel in /etc/ttydefs	*/
	char	*p_modules;	/* modules to push		*/
	char	*p_prompt;	/* prompt message		*/
	char	*p_dmsg;	/* disable message		*/
	char	*p_termtype;	/* terminal type		*/
	char	*p_softcar;	/* use softcarrier		*/

	/* the following fields are for ttymon internal use	*/
	int	p_status;	/* status of entry		*/
	int	p_fd;		/* fd for the open device	*/
	pid_t	p_childpid;	/* pid of child on the device	*/
	int	p_inservice;	/* service invoked		*/
	int	p_respawn;	/* respawn count in this series */
	long	p_time;		/* start time of a series	*/
	uid_t	p_uid;		/* uid of p_identity		*/
	gid_t	p_gid;		/* gid of p_identity		*/
	char	*p_dir;		/* home dir of p_identity	*/
	char	*p_ttymode;	/* mode line for serial device	*/
	struct	pmtab	*p_next;
};

/*
 *	valid flags for p_flags field of pmtab
 */
#define	X_FLAG	0x1	/* port/service disabled		*/
#define	U_FLAG  0x2	/* create utmp entry for the service	*/

/*
 *	valid flags for p_ttyflags field of pmtab
 */
#define	C_FLAG	0x1	/* invoke service on carrier		*/
#define	H_FLAG	0x2	/* hangup the line			*/
#define	B_FLAG	0x4	/* bi-directional line			*/
#define	R_FLAG	0x8	/* do wait_read				*/
#define	I_FLAG	0x10	/* initialize only			*/

/*
 *	autobaud enabled flag
 */
#define	A_FLAG	0x20	/* autobaud flag			*/

/*
 *	values for p_status field of pmtab
 */
#define	NOTVALID	0	/* entry is not valid		*/
#define	VALID		1	/* entry is valid		*/
#define	CHANGED		2	/* entry is valid but changed	*/
#define	GETTY		3	/* entry is for ttymon express	*/

#define	ALLOC_PMTAB \
	((struct pmtab *)calloc((unsigned)1, \
		(unsigned)sizeof (struct pmtab)))

#endif /* _TMSTRUCT_H */
