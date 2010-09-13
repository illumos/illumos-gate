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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include "libproc.h"

static int
get_sock_peer_name(struct ps_prochandle *Pr,
	int syscall, int sock, struct sockaddr *name, socklen_t *namelen)
{
	sysret_t rval;		/* return value from get{sock|peer}name() */
	argdes_t argd[4];	/* arg descriptors for get{sock|peer}name() */
	argdes_t *adp;
	int error;

	adp = &argd[0];		/* sock argument */
	adp->arg_value = sock;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* name argument */
	adp->arg_value = 0;
	adp->arg_object = name;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
	adp->arg_size = *namelen;

	adp++;			/* namelen argument */
	adp->arg_value = 0;
	adp->arg_object = namelen;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INOUT;
	adp->arg_size = sizeof (*namelen);

	adp++;			/* version argument */
	adp->arg_value = SOV_DEFAULT;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (0);
}

/* libc system call interface */
extern int _so_getsockname(int, struct sockaddr *, socklen_t *, int);
extern int _so_getpeername(int, struct sockaddr *, socklen_t *, int);
extern int _so_getsockopt(int, int, int, void *, int *);

/*
 * getsockname() system call -- executed by subject process
 */
int
pr_getsockname(struct ps_prochandle *Pr,
	int sock, struct sockaddr *name, socklen_t *namelen)
{
	if (Pr == NULL)		/* no subject process */
		return (_so_getsockname(sock, name, namelen, SOV_DEFAULT));

	return (get_sock_peer_name(Pr, SYS_getsockname, sock, name, namelen));
}

/*
 * getpeername() system call -- executed by subject process
 */
int
pr_getpeername(struct ps_prochandle *Pr,
	int sock, struct sockaddr *name, socklen_t *namelen)
{
	if (Pr == NULL)		/* no subject process */
		return (_so_getpeername(sock, name, namelen, SOV_DEFAULT));

	return (get_sock_peer_name(Pr, SYS_getpeername, sock, name, namelen));
}

int
pr_getsockopt(struct ps_prochandle *Pr,
	int sock, int level, int optname, void *optval, int *optlen)
{
	sysret_t rval;		/* return value from getsockopt() */
	argdes_t argd[5];	/* arg descriptors for getsockopt() */
	argdes_t *adp;
	int error;

	if (Pr == NULL)		/* no subject process */
		return (_so_getsockopt(sock, level, optname, optval, optlen));

	adp = &argd[0];		/* sock argument */
	adp->arg_value = sock;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* level argument */
	adp->arg_value = level;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* optname argument */
	adp->arg_value = optname;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	adp++;			/* optval argument */
	adp->arg_value = 0;
	adp->arg_object = optval;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
	adp->arg_size = optlen == NULL ? 0 : *optlen;

	adp++;			/* optlen argument */
	adp->arg_value = 0;
	adp->arg_object = optlen;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INOUT;
	adp->arg_size = sizeof (*optlen);

	error = Psyscall(Pr, &rval, SYS_getsockopt, 5, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
	return (0);
}
