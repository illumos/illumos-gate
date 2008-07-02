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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DOOR_DATA_H
#define	_SYS_DOOR_DATA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/door.h>

#if defined(_KERNEL)
#include <sys/thread.h>
#include <sys/file.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)
/* door_return() stack layout */
typedef struct door_layout {
	caddr_t		dl_descp;	/* start of descriptors (or 0) */
	caddr_t		dl_datap;	/* start of data (or 0) */
	caddr_t		dl_infop;	/* start of door_info_t (or 0) */
	caddr_t		dl_resultsp;	/* start of door_results{32}_t */
	caddr_t		dl_sp;		/* final stack pointer (non-biased) */
} door_layout_t;

/* upcall invocation information */
typedef struct door_upcall_data {
	cred_t		*du_cred;	/* Credential associated w/ upcall */
	size_t		du_max_data;	/* Maximum amount of reply data */
	uint_t		du_max_descs;	/* Maximum number of reply descs */
} door_upcall_t;

/*
 * Per-thread data associated with door invocations.  Each door invocation
 * effects the client structure of one thread and the server structure of
 * another.  This way, the server thread for one door_call() can make door
 * calls of its own without interference.
 */
typedef struct door_client {
	door_arg_t	d_args;		/* Door arg/results */
	door_upcall_t	*d_upcall;	/* upcall information */
	caddr_t		d_buf;		/* Temp buffer for data transfer */
	int		d_bufsize;	/* Size of temp buffer */
	int		d_fpp_size;	/* Number of File ptrs */
	struct file	**d_fpp;	/* File ptrs  */
	int		d_error;	/* Error (if any) */
	kcondvar_t	d_cv;
	uchar_t		d_args_done;	/* server has processed client's args */
	uchar_t		d_hold;		/* Thread needs to stick around */
	uchar_t		d_noresults;	/* No results allowed */
	uchar_t		d_overflow;	/* Result overflow occurred */
	uchar_t		d_kernel;	/* Kernel door server */
} door_client_t;

typedef struct door_server {
	struct _kthread	*d_caller;	/* Door caller */
	struct _kthread *d_servers;	/* List of door servers */
	struct door_node *d_active;	/* Active door */
	struct door_node *d_pool;	/* our server thread pool */
	door_layout_t	d_layout;
	caddr_t		d_sp;		/* Saved thread stack base */
	size_t		d_ssize;	/* Saved thread stack size */
	kcondvar_t	d_cv;
	uchar_t		d_hold;		/* Thread needs to stick around */
	uchar_t		d_invbound;	/* Thread is bound to invalid door */
	uchar_t		d_layout_done;	/* d_layout has been filled */
} door_server_t;

typedef struct door_data {
	door_client_t d_client;
	door_server_t d_server;
} door_data_t;

#define	DOOR_CLIENT(dp) (&(dp)->d_client)
#define	DOOR_SERVER(dp) (&(dp)->d_server)

/*
 * Macros for holding a thread in place.  Takes a door_server_t or
 * door_client_t pointer as an argument.
 */
#define	DOOR_T_HELD(cst)	((cst)->d_hold)

#define	DOOR_T_HOLD(cst) \
	(ASSERT(!DOOR_T_HELD(cst)), ((cst)->d_hold = 1))
#define	DOOR_T_RELEASE(cst) \
	(ASSERT(DOOR_T_HELD(cst)), ((cst)->d_hold = 0), \
	    cv_broadcast(&(cst)->d_cv))

/*
 * Roundup buffer size when passing/returning data via kernel buffer.
 * This cuts down on the number of overflows that occur on return
 */
#define	DOOR_ROUND	128

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DOOR_DATA_H */
