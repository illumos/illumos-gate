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
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

#ifndef _SYS5_FDIO_H
#define	_SYS5_FDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Disk io control commands
 */
#define	S5FDIOC			(0x04 << 8)
#define	S5FDIOGCHAR		(S5FDIOC|51)		/* GetCharacteristics */
#define	S5FDIOSCHAR		(S5FDIOC|52)		/* SetCharacteristics */
#define	S5FDEJECT		(S5FDIOC|53)		/* Eject floppy disk */
#define	S5FDGETCHANGE		(S5FDIOC|54)		/* Get diskchng stat */
#define	S5FDGETDRIVECHAR	(S5FDIOC|55)		/* Get drivechar */
#define	S5FDSETDRIVECHAR	(S5FDIOC|56)		/* Set drivechar */
#define	S5FDGETSEARCH		(S5FDIOC|57)		/* Get search tbl */
#define	S5FDSETSEARCH		(S5FDIOC|58)		/* Set search tbl */
#define	S5FDIOCMD		(S5FDIOC|59)		/* Floppy command */
#define	S5FDRAW			(S5FDIOC|70)		/* ECDstyle genericcmd*/

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS5_FDIO_H */
