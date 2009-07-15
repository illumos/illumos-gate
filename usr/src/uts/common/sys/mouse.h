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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_SYS_MOUSE_H
#define	_SYS_MOUSE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * AT&T 320 (PS/2 style) Mouse Commands
 */
#define	MSERESET	0xff	/* reset mouse */
#define	MSERESEND	0xfe	/* resend last data stream */
#define	MSEERROR	0xfc	/* error */
#define	MSESETDEF	0xf6	/* set default status */
#define	MSEOFF		0xf5	/* disable mouse */
#define	MSEON		0xf4	/* enable mouse */
#define	MSECHGMOD	0xf3	/* set sampling rate and/or button mode */
#define	MSEGETDEV	0xf2	/* read device type */
#define	MSESPROMPT	0xf0	/* set prompt mode (resets stream mode) */
#define	MSEECHON	0xee	/* set echo mode */
#define	MSEECHOFF	0xec	/* reset echo mode */
#define	MSEREPORT	0xeb	/* read mouse report */
#define	MSESTREAM	0xea	/* set Incremental Stream Mode */
#define	MSESTATREQ	0xe9	/* status request */
#define	MSESETRES	0xe8	/* set counts per mm. resolution */
#define	MSESCALE2	0xe7	/* set 2:1 scaling */
#define	MSESCALE1	0xe6	/* set 1:1 scaling */

#define	MSE_ACK		0xFA	/* Acknowledgement byte from 8042 */

/* Post-reset return values */
#define	MSE_AA		0xaa
#define	MSE_00		0x00


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MOUSE_H */
