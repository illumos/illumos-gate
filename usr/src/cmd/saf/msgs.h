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


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5*/


# define CONT		0	/* continue after logging message */
# define EXIT		1	/* exit after logging message */

/*
 * message ids for logging
 */

# define E_SACOPEN	0	/* could not open _sactab */
# define E_MALLOC	1	/* malloc failed */
# define E_BADFILE	2	/* _sactab corrupt */
# define E_BADVER	3	/* version mismatch on _sactab */
# define E_CHDIR	4	/* couldn't chdir */
# define E_NOPIPE	5	/* could not open _sacpipe */
# define E_BADSTATE	6	/* internal error - bad state */
# define E_BADREAD	7	/* _sacpipe read failed */
# define E_FATTACH	8	/* fattach failed */
# define E_SETSIG	9	/* I_SETSIG failed */
# define E_READ		10	/* read failed */
# define E_POLL		11	/* poll failed */
# define E_SYSCONF	12	/* system error in _sysconfig */
# define E_BADSYSCONF	13	/* interpretation error in _sysconfig */
# define E_PIPE		14	/* pipe failed */
# define E_CMDPIPE	15	/* could not create _cmdpipe */
