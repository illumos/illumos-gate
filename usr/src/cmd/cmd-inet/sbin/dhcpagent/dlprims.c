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
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * heavily cannibalized from
 *
 * #ident	"@(#)dlprims.c	1.12	97/03/27 SMI"
 */

#pragma ident	"%W%	%E% SMI"

/*
 * TODO: get rid of this code as soon as possible and replace it with a
 *	 version from a standard library.  this stuff is barf-o-riffic.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/dlpi.h>
#include <stropts.h>
#include <sys/poll.h>

#include "dlpi_io.h"

static int strgetmsg(int, struct strbuf *, struct strbuf *);

/*
 * dlinforeq(): issue DL_INFO_REQ and fetch DL_INFO_ACK on stream
 *
 *   input: int: the stream to do the DL_INFO_REQ on
 *	    dl_info_ack_t: a place to store the DL_INFO_ACK
 *	    size_t: the size of the dl_info_ack_t
 *  output: int: 0 on success, 1 on failure (errno is set)
 */

int
dlinforeq(int fd, dl_info_ack_t *infoackp, size_t infoack_size)
{
	struct strbuf		ctl;

	infoackp->dl_primitive = DL_INFO_REQ;

	ctl.maxlen	= infoack_size;
	ctl.len		= DL_INFO_REQ_SIZE;
	ctl.buf		= (caddr_t)infoackp;

	if (putmsg(fd, &ctl, NULL, 0) == -1)
		return (1);

	if (strgetmsg(fd, &ctl, NULL) == 1)
		return (1);

	if (infoackp->dl_primitive != DL_INFO_ACK ||
	    ctl.len < DL_INFO_ACK_SIZE) {
		errno = EPROTO;
		return (1);
	}

	return (0);
}

/*
 * dlattachreq(): issue DL_ATTACH_REQ and fetch DL_OK_ACK on stream
 *
 *   input: int: the stream to do the DL_ATTACH_REQ on
 *	    t_uscalar_t: the ppa to do the attach to
 *  output: int: 0 on success, 1 on failure (errno is set)
 */

int
dlattachreq(int fd, t_uscalar_t ppa)
{
	union DL_primitives	*dlp;
	uint32_t		buf[DLPI_BUF_MAX / sizeof (uint32_t)];
	struct strbuf		ctl;

	dlp = (union DL_primitives *)buf;
	dlp->attach_req.dl_primitive	= DL_ATTACH_REQ;
	dlp->attach_req.dl_ppa		= ppa;

	ctl.maxlen	= sizeof (buf);
	ctl.len		= DL_ATTACH_REQ_SIZE;
	ctl.buf		= (caddr_t)dlp;

	if (putmsg(fd, &ctl, NULL, 0) == -1)
		return (1);

	if (strgetmsg(fd, &ctl, NULL) == 1)
		return (1);

	if (dlp->dl_primitive != DL_OK_ACK) {
		errno = EPROTO;
		return (1);
	}

	return (0);
}

/*
 * dlbindreq(): issue DL_BIND_REQ and fetch DL_BIND_ACK on stream
 *
 *   input: int: the stream to do the DL_BIND_REQ on
 *	    t_uscalar_t: the sap to bind to
 *	    t_uscalar_t: the max number of outstanding DL_CONNECT_IND messages
 *	    uint16_t: the service mode (connectionless/connection-oriented)
 *	    uint16_t: whether this is a connection management stream
 *  output: int: 0 on success, 1 on failure (errno is set)
 */

int
dlbindreq(int fd, t_uscalar_t sap, t_uscalar_t max_conind,
    uint16_t service_mode, uint16_t conn_mgmt)
{
	union DL_primitives	*dlp;
	uint32_t		buf[DLPI_BUF_MAX / sizeof (uint32_t)];
	struct strbuf		ctl;

	dlp = (union DL_primitives *)buf;
	dlp->bind_req.dl_primitive	= DL_BIND_REQ;
	dlp->bind_req.dl_sap		= sap;
	dlp->bind_req.dl_max_conind	= max_conind;
	dlp->bind_req.dl_service_mode	= service_mode;
	dlp->bind_req.dl_conn_mgmt	= conn_mgmt;
	dlp->bind_req.dl_xidtest_flg	= 0;

	ctl.maxlen	= sizeof (buf);
	ctl.len		= DL_BIND_REQ_SIZE;
	ctl.buf		= (caddr_t)dlp;

	if (putmsg(fd, &ctl, NULL, 0) == -1)
		return (1);

	if (strgetmsg(fd, &ctl, NULL) == 1)
		return (1);

	if (dlp->dl_primitive != DL_BIND_ACK || ctl.len < DL_BIND_ACK_SIZE) {
		errno = EPROTO;
		return (1);
	}

	return (0);
}

/*
 * strgetmsg(): timed getmsg(3C)
 *
 *   input: int: the stream to wait for the message on
 *	    struct strbuf *: a buffer to hold the control part of the message
 *	    struct strbuf *: a buffer to hold the data part of the message
 *  output: int: 0 on success, 1 on failure (errno is set)
 */

static int
strgetmsg(int fd, struct strbuf *ctlp, struct strbuf *datap)
{
	struct pollfd	fds;
	int		flags = 0;
	int		retval;

	fds.fd		= fd;
	fds.events	= POLLIN|POLLPRI;

	switch (poll(&fds, 1, DLPI_TIMEOUT * 1000)) {

	case 0:
		errno = ETIME;
		return (1);

	case -1:
		return (1);

	default:

		retval = getmsg(fd, ctlp, datap, &flags);
		if (retval == -1)
			return (1);

		if (retval > 0 || ctlp->len < sizeof (t_uscalar_t)) {
			errno = EPROTO;
			return (1);
		}

		break;
	}

	return (0);
}
