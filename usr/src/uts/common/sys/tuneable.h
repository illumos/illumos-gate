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


#ifndef _SYS_TUNEABLE_H
#define	_SYS_TUNEABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.7 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct tune {
	int	t_gpgslo;	/* If freemem < t_getpgslow, then start	*/
				/* to steal pages from processes.	*/
	int	t_pad[7];	/* Padding for driver compatibility.    */
	int	t_fsflushr;	/* The rate at which fsflush is run in	*/
				/* seconds.				*/
	int	t_minarmem;	/* The minimum available resident (not	*/
				/* swappable) memory to maintain in 	*/
				/* order to avoid deadlock.  In pages.	*/
	int	t_minasmem;	/* The minimum available swappable	*/
				/* memory to maintain in order to avoid	*/
				/* deadlock.  In pages.			*/
	int	t_flckrec;	/* max number of active frlocks */
} tune_t;

extern tune_t	tune;

/*
 * The following is the default value for t_gpgsmsk.  It cannot be
 * defined in /etc/master or /stand/system due to limitations of the
 * config program.
 */

#define	GETPGSMSK	PG_REF|PG_NDREF

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TUNEABLE_H */
