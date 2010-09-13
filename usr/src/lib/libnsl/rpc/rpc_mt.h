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
 *	Contains the mt libraries include definitions
 */

#ifndef	_RPC_MT_H
#define	_RPC_MT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/rpc.h>
#include <netconfig.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * declaration to private interfaces in rpc library
 */

extern int svc_npollfds;
extern int svc_npollfds_set;
extern int svc_pollfd_allocd;
extern rwlock_t svc_fd_lock;

/*
 * macros to handle pollfd array; ***** Note that the macro takes
 * address of the array ( &array[0] ) always not the address of an
 * element *****.
 */

#define	MASKVAL	(POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)
#define	POLLFD_EXTEND		64
#define	POLLFD_SHRINK		(2 * POLLFD_EXTEND)
#define	POLLFD_SET(x, y)	{ \
					(y)[(x)].fd = (x); \
					(y)[(x)].events = MASKVAL; \
				}
#define	POLLFD_CLR(x, y)	{ \
					(y)[(x)].fd = -1; \
					(y)[(x)].events = 0; \
					(y)[(x)].revents = 0; \
				}
#define	POLLFD_ISSET(x, y)	((y)[(x)].fd >= 0)


extern int __rpc_use_pollfd_done;
extern int __rpc_rlim_max(void);

/* Following functions create and manipulates the dgfd lock object */

extern void *rpc_fd_init(void);
extern int rpc_fd_lock(const void *handle, int fd);
extern void rpc_fd_unlock(const void *handle, int fd);

#define	RPC_FD_NOTIN_FDSET(x)	(!__rpc_use_pollfd_done && (x) >= FD_SETSIZE)
#define	FD_INCREMENT FD_SETSIZE

/*
 * External functions without prototypes.  This is somewhat crufty, but
 * there is no other header file for this directory.  One should probably
 * be created and this stuff moved there if there turns out to be no better
 * way to avoid the warnings.
 */

#define	RPC_MINFD	3

#define	RPC_RAISEFD(fd)		if (fd < RPC_MINFD) \
					fd = __rpc_raise_fd(fd)

extern int	__getpublickey_cached(char *, char *, int *);
extern void	__getpublickey_flush(const char *);
extern int	__can_use_af(sa_family_t);
extern int	__rpc_raise_fd(int);
extern void	__rpc_set_mac_options(int, const struct netconfig *,
	rpcprog_t);
extern void	__tli_sys_strerror(char *, size_t, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* !_RPC_MT_H */
