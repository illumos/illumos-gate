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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <tiuser.h>
#include <unistd.h>
#include <stropts.h>

/*
 * TLI_WRAPPERS is defined below, before inclusion of "tx.h". This is
 * done so that the function prototypes and associated data structure
 * definitions of new interfaces introduced in XNS 5 are not seen
 * in this file.
 */
#define	TLI_WRAPPERS
#include "tx.h"

int
t_accept(int fd, int resfd, struct t_call *call)
{
	return (_tx_accept(fd, resfd, call, TX_TLI_API));
}

char *
t_alloc(int fd, int struct_type, int fields)
{
	return (_tx_alloc(fd, struct_type, fields, TX_TLI_API));
}

int
t_bind(int fd, struct t_bind *req, struct t_bind *ret)
{
	return (_tx_bind(fd, req, ret, TX_TLI_API));
}

int
t_close(int fd)
{
	return (_tx_close(fd, TX_TLI_API));
}

int
t_connect(int fd, struct t_call *sndcall, struct t_call *rcvcall)
{
	return (_tx_connect(fd, sndcall, rcvcall, TX_TLI_API));
}

/*
 * Note t_error() return type changed by XTI to be char *. The spec should
 * probably be fixed to make it void *
 */
void
t_error(const char *s)
{
	(void) _tx_error(s, TX_TLI_API);
}

int
t_free(char *ptr, int struct_type)
{
	return (_tx_free(ptr, struct_type, TX_TLI_API));
}

/*
 * Note: The "struct t_info" parameter here refers to XTI one which
 * added a field. The implmentation should not reference it. The applications
 * will pass the shorter TLI one.
 */
int
t_getinfo(int fd, struct t_info *info)
{
	return (_tx_getinfo(fd, info, TX_TLI_API));
}

int
t_getstate(int fd)
{
	return (_tx_getstate(fd, TX_TLI_API));
}

int
t_listen(int fd, struct t_call *call)
{
	return (_tx_listen(fd, call, TX_TLI_API));
}

int
t_look(int fd)
{
	return (_tx_look(fd, TX_TLI_API));
}

/*
 * Note: The "struct t_info" parameter here refers to XTI one which
 * added a field. The implmentation should not reference it. The applications
 * will pass the shorter TLI one.
 */
int
t_open(const char *path, int flags, struct t_info *info)
{
	return (_tx_open(path, flags, info, TX_TLI_API));
}

int
t_optmgmt(int fd, struct t_optmgmt *req, struct t_optmgmt *ret)
{
	return (_tx_optmgmt(fd, req, ret, TX_TLI_API));
}

int
t_rcv(int fd, char *buf, unsigned int nbytes, int *flags)
{
	return (_tx_rcv(fd, buf, nbytes, flags, TX_TLI_API));
}

int
t_rcvconnect(int fd, struct t_call *call)
{
	return (_tx_rcvconnect(fd, call, TX_TLI_API));
}

int
t_rcvdis(int fd, struct t_discon *discon)
{
	return (_tx_rcvdis(fd, discon, TX_TLI_API));
}

int
t_rcvrel(int fd)
{
	return (_tx_rcvrel(fd, TX_TLI_API));
}

int
t_rcvudata(int fd, struct t_unitdata *unitdata, int *flags)
{
	return (_tx_rcvudata(fd, unitdata, flags, TX_TLI_API));
}

int
t_rcvuderr(int fd, struct t_uderr *uderr)
{
	return (_tx_rcvuderr(fd, uderr, TX_TLI_API));
}

int
t_snd(int fd, char *buf, unsigned int nbytes, int flags)
{
	return (_tx_snd(fd, buf, nbytes, flags, TX_TLI_API));
}

int
t_snddis(int fd, struct t_call *call)
{
	return (_tx_snddis(fd, call, TX_TLI_API));
}

int
t_sndrel(int fd)
{
	return (_tx_sndrel(fd, TX_TLI_API));
}

int
t_sndudata(int fd, struct t_unitdata *unitdata)
{
	return (_tx_sndudata(fd, unitdata, TX_TLI_API));
}

char *
t_strerror(int errnum)
{
	return (_tx_strerror(errnum, TX_TLI_API));
}

int
t_sync(int fd)
{
	return (_tx_sync(fd, TX_TLI_API));
}

int
t_unbind(int fd)
{
	return (_tx_unbind(fd, TX_TLI_API));
}

int
t_getname(int fd, struct netbuf *name, int type)
{
	return (_tx_getname(fd, name, type, TX_TLI_API));
}
