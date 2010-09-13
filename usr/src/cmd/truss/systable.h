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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _TRUSS_SYSTABLE_H
#define	_TRUSS_SYSTABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>



#ifdef	__cplusplus
extern "C" {
#endif

struct systable {
	const char *name;	/* name of system call */
	short	nargs;		/* number of arguments */
	char	rval[2];	/* return value types */
	char	arg[8];		/* argument types */
};

/* the system call table */
extern const struct systable systable[];


struct sysalias {
	const char *name;	/* alias name of system call */
	int	number;		/* number of system call */
};

extern const struct sysalias sysalias[];

extern const struct systable *subsys(int, int);

extern const char * const afcodes[];
#define	MAX_AFCODES (AF_MAX+1)

extern const char * const socktype_codes[];
#define	MAX_SOCKTYPES 7

#ifdef	__cplusplus
}
#endif

#endif	/* _TRUSS_SYSTABLE_H */
