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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <tiuser.h>
#include <string.h>
#include <stropts.h>
#include <netinet/tcp.h>
#include <stdlib.h>

#define	MAXOPTSIZE 64

int
__td_setnodelay(int fd)
{
	int rval = 0;
	static mutex_t td_opt_lock = DEFAULTMUTEX;
	static struct t_optmgmt t_optreq, t_optret;
	int state;


	/* VARIABLES PROTECTED BY td_opt_lock: t_optreq, t_optret */

	if ((state = t_getstate(fd)) == -1)
		return (-1);

	(void) mutex_lock(&td_opt_lock);
	if ((state == T_IDLE) && (t_optreq.flags != T_NEGOTIATE)) {
		int i = 1;
		struct opthdr *opt;

		t_optreq.flags = T_NEGOTIATE;
		t_optreq.opt.maxlen = MAXOPTSIZE;
		t_optreq.opt.buf = malloc(MAXOPTSIZE);
		if (t_optreq.opt.buf == NULL) {
			(void) mutex_unlock(&td_opt_lock);
			t_errno = TSYSERR;
			return (-1);
		}
		/* LINTED pointer cast */
		opt = (struct opthdr *)(t_optreq.opt.buf);
		opt->name = TCP_NODELAY;
		opt->len = 4;
		opt->level = IPPROTO_TCP;
		(void) memcpy((caddr_t)(t_optreq.opt.buf +
				sizeof (struct opthdr)), &i, sizeof (int));
		t_optreq.opt.len = (int)(sizeof (struct opthdr) +
						sizeof (int));

		t_optret.opt.maxlen = MAXOPTSIZE;
		t_optret.opt.len = 0;
		t_optret.opt.buf = malloc(MAXOPTSIZE);
		if (t_optret.opt.buf == NULL) {
			(void) mutex_unlock(&td_opt_lock);
			free(t_optreq.opt.buf);
			t_errno = TSYSERR;
			return (-1);
		}
	}

	if (state == T_IDLE)
		rval = t_optmgmt(fd, &t_optreq, &t_optret);

	(void) mutex_unlock(&td_opt_lock);
	return (rval);
}
