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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rusersxdr.c
 * These are the non-rpcgen-able XDR routines for version 2 of the rusers
 * protocol.
 *
 */

#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpcsvc/rusers.h>

int
xdr_ru_utmp(xdrsp, up)
	XDR *xdrsp;
	struct ru_utmp *up;
{
	u_int len;
	char *p;

	/*
	 * This code implements demented byte vectors:  we send out the length
	 * of fixed-length vectors, followed by the opaque bytes.  This is to
	 * be compatible with the over-the-wire protocol, as well as the
	 * rusers.h definition for struct ru_utmp.
	 */
	len = (int)sizeof (up->ut_line);
	if (xdr_u_int(xdrsp, &len) == FALSE)
		return (0);
	if (len != sizeof (up->ut_line)) {
		return (0);
	}
	if (!xdr_opaque(xdrsp, (char *)up->ut_line, len)) {
		return (0);
	}
	len = (int)sizeof (up->ut_name);
	if (xdr_u_int(xdrsp, &len) == FALSE)
		return (0);
	if (len != sizeof (up->ut_name)) {
		return (0);
	}
	if (!xdr_opaque(xdrsp, (char *)up->ut_name, len)) {
		return (0);
	}
	len = (int)sizeof (up->ut_host);
	if (xdr_u_int(xdrsp, &len) == FALSE)
		return (0);
	if (len != sizeof (up->ut_host)) {
		return (0);
	}
	if (!xdr_opaque(xdrsp, (char *)up->ut_host, len)) {
		return (0);
	}
	if (xdr_int(xdrsp, (int32_t *) &up->ut_time) == FALSE)
		return (0);
	return (1);
}

int
xdr_utmpidle(xdrsp, ui)
	XDR *xdrsp;
	struct utmpidle *ui;
{
	if (xdr_ru_utmp(xdrsp, &ui->ui_utmp) == FALSE)
		return (0);
	if (xdr_u_int(xdrsp, &ui->ui_idle) == FALSE)
		return (0);
	return (1);
}

int
xdr_utmpidleptr(xdrsp, up)
	XDR *xdrsp;
	struct utmpidle **up;
{
	if (xdr_reference(xdrsp, (char **) up, sizeof (struct utmpidle),
			xdr_utmpidle) == FALSE)
		return (0);
	return (1);
}

int
xdr_utmpidlearr(xdrsp, up)
	XDR *xdrsp;
	struct utmpidlearr *up;
{
	return (xdr_array(xdrsp, (char **) &up->uia_arr,
		(u_int *)&(up->uia_cnt), MAXUSERS, sizeof (struct utmpidle *),
		xdr_utmpidleptr));
}
