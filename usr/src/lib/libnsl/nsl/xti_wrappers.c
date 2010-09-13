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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "mt.h"
#include <xti.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/stream.h>
#include "tx.h"

/*
 * Prefix: _xti_
 *
 * The _xti_ prefix is the default prefix for these functions. A function
 * having the _xti_ prefix means one of the following.
 *	a. This interface remains unchanged in all versions of XTI, starting
 *	   with the version of XTI in which it was first introduced.
 *	   Consequently there is no other entry point, with a different
 *	   prefix for this interface.
 *	b. This interface has changed subsequent to when it was first. This
 *	   function is meant for compatibility and provides the semantics of
 *	   the XTI version when it was first introduced.
 *
 * The _xti_xns5_ prefix is used for functions that provide XNS Issue 5
 * (UNIX98) semantics. It means the following.
 *	   The UNIX98 version of this interface has different semantics
 *	   as compared to UNIX95, and this function provides UNIX98 semantics
 *
 */

int
_xti_accept(int fd, int resfd, const struct t_call *call)
{
	return (_tx_accept(fd, resfd, call, TX_XTI_API));
}

int
_xti_xns5_accept(int fd, int resfd, const struct t_call *call)
{
	return (_tx_accept(fd, resfd, call, TX_XTI_XNS5_API));
}

void *
_xti_alloc(int fd, int struct_type, int fields)
{
	return (_tx_alloc(fd, struct_type, fields, TX_XTI_API));
}

int
_xti_bind(int fd, const struct t_bind *req, struct t_bind *ret)
{
	return (_tx_bind(fd, req, ret, TX_XTI_API));
}

int
_xti_close(int fd)
{
	return (_tx_close(fd, TX_XTI_API));
}

int
_xti_connect(int fd, const struct t_call *sndcall, struct t_call *rcvcall)
{
	return (_tx_connect(fd, sndcall, rcvcall, TX_XTI_API));
}

/*
 * Note: The TLI version of t_error has return type void. XTI has "int".
 * The spec probably needs to change to void *
 */
int
_xti_error(const char *errmsg)
{
	return (_tx_error(errmsg, TX_XTI_API));
}

int
_xti_free(void *ptr, int struct_type)
{
	return (_tx_free(ptr, struct_type, TX_XTI_API));
}

int
_xti_getinfo(int fd, struct t_info *info)
{
	return (_tx_getinfo(fd, info, TX_XTI_API));
}

int
_xti_getprotaddr(int fd, struct t_bind *boundaddr, struct t_bind *peeraddr)
{
	return (_tx_getprotaddr(fd, boundaddr, peeraddr, TX_XTI_API));
}

int
_xti_getstate(int fd)
{
	return (_tx_getstate(fd, TX_XTI_API));
}

int
_xti_listen(int fd, struct t_call *call)
{
	return (_tx_listen(fd, call, TX_XTI_API));
}

int
_xti_look(int fd)
{
	return (_tx_look(fd, TX_XTI_API));
}

int
_xti_open(const char *path, int flags, struct t_info *info)
{
	return (_tx_open(path, flags, info, TX_XTI_API));
}

int
_xti_optmgmt(int fd, const struct t_optmgmt *req, struct t_optmgmt *ret)
{
	return (_tx_optmgmt(fd, req, ret, TX_XTI_API));
}

int
_xti_rcv(int fd, void *buf, unsigned int nbytes, int *flags)
{
	return (_tx_rcv(fd, buf, nbytes, flags, TX_XTI_API));
}

int
_xti_rcvconnect(int fd, struct t_call *call)
{
	return (_tx_rcvconnect(fd, call, TX_XTI_API));
}

int
_xti_rcvdis(int fd, struct t_discon *discon)
{
	return (_tx_rcvdis(fd, discon, TX_XTI_API));
}

int
_xti_rcvrel(int fd)
{
	return (_tx_rcvrel(fd, TX_XTI_API));
}

int
_xti_rcvreldata(int fd, struct t_discon *discon)
{
	return (_tx_rcvreldata(fd, discon, TX_XTI_XNS5_API));
}

int
_xti_rcvudata(int fd, struct t_unitdata *unitdata, int *flags)
{
	return (_tx_rcvudata(fd, unitdata, flags, TX_XTI_API));
}

int
_xti_rcvuderr(int fd, struct t_uderr *uderr)
{
	return (_tx_rcvuderr(fd, uderr, TX_XTI_API));
}

int
_xti_rcvv(int fd, struct t_iovec *tiov, unsigned int tiovcount, int *flags)
{
	return (_tx_rcvv(fd, tiov, tiovcount, flags, TX_XTI_XNS5_API));
}

int
_xti_rcvvudata(int fd, struct t_unitdata *unitdata, struct t_iovec *tiov,
    unsigned int tiovcount, int *flags)
{
	return (_tx_rcvvudata(fd, unitdata, tiov, tiovcount, flags,
	    TX_XTI_XNS5_API));
}

int
_xti_snd(int fd, void *buf, unsigned int nbytes, int flags)
{
	return (_tx_snd(fd, buf, nbytes, flags, TX_XTI_API));
}

int
_xti_xns5_snd(int fd, void *buf, unsigned int nbytes, int flags)
{
	return (_tx_snd(fd, buf, nbytes, flags, TX_XTI_XNS5_API));
}

int
_xti_snddis(int fd, const struct t_call *call)
{
	return (_tx_snddis(fd, call, TX_XTI_API));

}

int
_xti_sndrel(int fd)
{
	return (_tx_sndrel(fd, TX_XTI_API));
}

int
_xti_sndreldata(int fd, struct t_discon *discon)
{
	return (_tx_sndreldata(fd, discon, TX_XTI_XNS5_API));
}

int
_xti_sndudata(int fd, const struct t_unitdata *unitdata)
{
	return (_tx_sndudata(fd, unitdata, TX_XTI_API));
}

int
_xti_sndv(int fd, const struct t_iovec *tiov, unsigned int tiovcount, int flags)
{
	return (_tx_sndv(fd, tiov, tiovcount, flags, TX_XTI_XNS5_API));
}

int
_xti_sndvudata(int fd, struct t_unitdata *unitdata, struct t_iovec *tiov,
    unsigned int tiovcount)
{
	return (_tx_sndvudata(fd, unitdata, tiov, tiovcount, TX_XTI_XNS5_API));
}

const char *
_xti_strerror(int errnum)
{
	return (_tx_strerror(errnum, TX_XTI_API));
}

int
_xti_sync(int fd)
{
	return (_tx_sync(fd, TX_XTI_API));
}

int
_xti_sysconf(int name)
{
	return (_tx_sysconf(name, TX_XTI_XNS5_API));
}

int
_xti_unbind(int fd)
{
	return (_tx_unbind(fd, TX_XTI_API));
}
