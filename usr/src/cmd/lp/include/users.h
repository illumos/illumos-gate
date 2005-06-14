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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

#if	!defined(_LP_USERS_H)
#define	_LP_USERS_H

#include "stdio.h"

typedef struct
{
    short	priority_limit;
}
USER;

int		putuser ( char * , USER * );
int		deluser ( char * );
int		getdfltpri ( void );
void		trashusers ( void );

USER *		getuser ( char *);

#define LEVEL_DFLT 20
#define LIMIT_DFLT 0

#define TRUE  1
#define FALSE 0

#define PRI_MAX 39
#define	PRI_MIN	 0

#define LPU_MODE 0644

struct user_priority
{
    short	deflt;		/* priority to use when not specified */
    short	deflt_limit;	/* priority limit for users not
				   otherwise specified */
    char	**users[PRI_MAX - PRI_MIN + 1];
};

#endif
