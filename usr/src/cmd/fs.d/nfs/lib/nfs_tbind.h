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

/*
 * nfs_tbind.h, common code for nfsd and lockd
 */

#ifndef	_NFS_TBIND_H
#define	_NFS_TBIND_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netconfig.h>
#include <netdir.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Globals which should be initialised by daemon main().
 */
extern  size_t  end_listen_fds;
extern  size_t  num_fds;
extern	int	listen_backlog;
extern	int	(*Mysvc)(int, struct netbuf, struct netconfig *);
extern	int	(*Mysvc4)(int, struct netbuf *, struct netconfig *,
		int, struct netbuf *);
extern  int	max_conns_allowed;

/*
 * RPC protocol block.  Useful for passing registration information.
 */
struct protob {
	char *serv;		/* ASCII service name, e.g. "NFS" */
	int versmin;		/* minimum version no. to be registered */
	int versmax;		/* maximum version no. to be registered */
	int program;		/* program no. to be registered */
	struct protob *next;	/* next entry on list */
};

/*
 * Declarations for protocol types and comparison.
 */
#define	NETSELDECL(x)	char *x
#define	NETSELPDECL(x)	char **x
#define	NETSELEQ(x, y)	(strcmp((x), (y)) == 0)

/*
 * nfs library routines
 */
extern int	nfslib_transport_open(struct netconfig *);
extern int	nfslib_bindit(struct netconfig *, struct netbuf **,
			struct nd_hostserv *, int);
extern void	nfslib_log_tli_error(char *, int, struct netconfig *);
extern int	do_all(struct protob *,
			int (*)(int, struct netbuf, struct netconfig *),
			int use_pmap);
extern void	do_one(char *, char *, struct protob *,
			int (*)(int, struct netbuf, struct netconfig *),
			int use_pmap);
extern void	poll_for_action(void);

#ifdef __cplusplus
}
#endif

#endif	/* _NFS_TBIND_H */
