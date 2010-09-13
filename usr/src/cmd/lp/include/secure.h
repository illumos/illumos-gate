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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if	!defined(_LP_SECURE_H)
#define _LP_SECURE_H

#include "sys/types.h"

/**
 ** The disk copy of the secure request files:
 **/

/*
 * There are 8 fields in the secure request file.
 */
#define	SC_MAX  7
# define SC_REQID	0	/* Original request id */
# define SC_UID		1	/* Originator's user ID */
# define SC_USER	2	/* Originator's real login name */
# define SC_GID		3	/* Originator's group ID */
# define SC_SIZE	4	/* Total size of the request data */
# define SC_DATE	5	/* Date submitted (in seconds) */
# define SC_SLABEL	6	/* Sensitivity Label */

/**
 ** The internal copy of a request as seen by the rest of the world:
 **/

typedef struct SECURE {
    uid_t	uid;
    gid_t	gid;
    off_t	size;
    time_t	date;
    char	*user;
    char	*req_id;
    char	*slabel;
}			SECURE;

/**
 ** Various routines.
 **/

SECURE *	getsecure ( char * );
int		putsecure ( char *, SECURE * );
int		rmsecure (char *);
void		freesecure ( SECURE * );

#endif
