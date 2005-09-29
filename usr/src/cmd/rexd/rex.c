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
 * rex_xdr - remote execution external data representations
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* XXX - Bad, Bad, Bad.... Fix this. This isn't allowed in the base */
#define	BSD_COMP

#include <stdio.h>
#include <rpc/rpc.h>
#include <sys/errno.h>
#include <sys/ttold.h>
#include <stropts.h>
#include <sys/stream.h>
#include <sys/tty.h>
#include <sys/ptyvar.h>

#include "rex.h"

/*
 * xdr_rex_start - process the command start structure
 */
int
xdr_rex_start(XDR *xdrs,  struct rex_start *rst)
{
	return
		xdr_argv(xdrs, &rst->rst_cmd) &&
		xdr_string(xdrs, &rst->rst_host, 1024) &&
		xdr_string(xdrs, &rst->rst_fsname, 1024) &&
		xdr_string(xdrs, &rst->rst_dirwithin, 1024) &&
		xdr_argv(xdrs, &rst->rst_env) &&
		xdr_u_short(xdrs, &rst->rst_port0) &&
		xdr_u_short(xdrs, &rst->rst_port1) &&
		xdr_u_short(xdrs, &rst->rst_port2) &&
		xdr_u_long(xdrs, &rst->rst_flags);
}

int
xdr_argv(XDR *xdrs, char ***argvp)
{
	register char **argv = *argvp;
	register char **ap;
	int i, count;

	/*
	 * find the number of args to encode or free
	 */
	if ((xdrs->x_op) != XDR_DECODE)
		for (count = 0, ap = argv; *ap != 0; ap++)
			count++;
	/* XDR the count */
	if (!xdr_u_int(xdrs, (unsigned *) &count))
		return (FALSE);

	/*
	 * now deal with the strings
	 */
	if (xdrs->x_op == XDR_DECODE) {
		*argvp = argv = (char **)
			mem_alloc((unsigned)(count+1)*sizeof (char **));
		for (i = 0; i <= count; i++)	/* Note: <=, not < */
			argv[i] = 0;
	}

	for (i = 0, ap = argv; i < count; i++, ap++)
		if (!xdr_string(xdrs, ap, 10240))
			return (FALSE);

	if (xdrs->x_op == XDR_FREE && argv != NULL) {
		mem_free((char *) argv, (count+1)*sizeof (char **));
		*argvp = NULL;
	}
	return (TRUE);
}

/*
 * xdr_rex_result - process the result of a start or wait operation
 */
int
xdr_rex_result(XDR *xdrs, struct rex_result *result)
{
	return
		xdr_int(xdrs, &result->rlt_stat) &&
		xdr_string(xdrs, &result->rlt_message, 1024);

}

/*
 * xdr_rex_ttymode - process the tty mode information
 */
int
xdr_rex_ttymode(XDR *xdrs, struct rex_ttymode *mode)
{
	u_int six = 6;
	u_int four = 4;
	char *speedp = NULL;
	char *morep = NULL;
	char *yetmorep = NULL;

	if (xdrs->x_op != XDR_FREE) {
		speedp = &mode->basic.sg_ispeed;
		morep = (char *)&mode->more;
		yetmorep = (char *)&mode->yetmore;
	}
	return
		xdr_bytes(xdrs, (char **) &speedp, (u_int *)&four, 4) &&
		xdr_short(xdrs, (short *) &mode->basic.sg_flags) &&
		xdr_bytes(xdrs, (char **) &morep, (u_int *)&six, 6) &&
		xdr_bytes(xdrs, (char **) &yetmorep, (u_int *)&six, 6) &&
		xdr_u_long(xdrs, &mode->andmore);
}


/*
 * xdr_rex_ttysize - process the tty size information
 */
int
xdr_rex_ttysize(XDR *xdrs, struct ttysize *size)
{
	return
		xdr_int(xdrs, &size->ts_lines) &&
		xdr_int(xdrs, &size->ts_cols);
}
