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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

# define	SYS_PASSWD	0
# define	SYS_PROTO	1
# define	SYS_TMO		2
# define	SYS_RETRY	3
# define	SYS_COMMENT	4
# define	SYS_MAX		5

/**
 ** The internal copy of a system as seen by the rest of the world:
 **/

typedef struct SYSTEM
{
    char	*name;		/* name of system (redundant) */
    char	*passwd;        /* the encrypted passwd of the system */
    char	*reserved1;
    int		protocol;	/* lp networking protocol bsd */
    int		threshold;	/* job threshold before poll */
    int		timeout;	/* maximum permitted idle time */
    int		retry;		/* minutes before trying failed conn */
    char	*extensions;
    char	*reserved4;
    char	*comment;
} SYSTEM;

# define	NAME_S5PROTO	"s5"
# define	NAME_BSDPROTO	"bsd"

# define	S5_PROTO	1
# define	BSD_PROTO	2

/**
 ** Various routines.
 **/

SYSTEM		*getsystem ( const char * );

int		putsystem ( const char *, const SYSTEM * ),
		delystem ( const char * );

void		freesystem(SYSTEM *);
