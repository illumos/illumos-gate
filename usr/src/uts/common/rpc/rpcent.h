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
 *
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * rpcent.h,
 * For converting rpc program numbers to names etc.
 *
 */

#ifndef _RPC_RPCENT_H
#define	_RPC_RPCENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct rpcent {
	char	*r_name;	/* name of server for this rpc program */
	char	**r_aliases;	/* alias list */
	int	r_number;	/* rpc program number */
};

#ifdef __STDC__
extern struct rpcent *getrpcbyname_r
		(const char *,	  struct rpcent *, char *, int);
extern struct rpcent *getrpcbynumber_r
		(const int,	  struct rpcent *, char *, int);
extern struct rpcent *getrpcent_r(struct rpcent *, char *, int);

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
extern struct rpcent *getrpcbyname(const char *);
extern struct rpcent *getrpcbynumber(const int);
extern struct rpcent *getrpcent(void);
extern void setrpcent(const int);
extern void endrpcent(void);
#else
extern struct rpcent *getrpcbyname_r();
extern struct rpcent *getrpcbynumber_r();
extern struct rpcent *getrpcent_r();

/* Old interfaces that return a pointer to a static area;  MT-unsafe */
extern struct rpcent *getrpcbyname();
extern struct rpcent *getrpcbynumber();
extern struct rpcent *getrpcent();
extern void setrpcent();
extern void endrpcent();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _RPC_RPCENT_H */
