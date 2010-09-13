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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * wrappers.c: utility for scadm command processing functions
 */

#include <libintl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>  /* required by rsc.h */

#include "librsc.h"
#include "adm.h"


void
ADM_Start()
{
	if (rscp_start() != 0) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: SC firmware not responding"));
		exit(-1);
	}
}


void
ADM_Send(rscp_msg_t *msg)
{
	int err;

	err = rscp_send(msg);

	if (err == ENOTSUP) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: command/option not supported"));
		exit(-1);

	} else if (err != 0) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: unable to send data to SC"));
		exit(-1);
	}
}


int
ADM_Send_ret(rscp_msg_t *msg)
{
	return (rscp_send(msg));
}


void
ADM_Recv(rscp_msg_t *msg, struct timespec *timeout, int expectType,
    int expectSize)
{
	if (rscp_recv(msg, timeout) != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: SC not responding to requests"));
		exit(-1);
	}

	if ((msg->type != expectType) || (msg->len < expectSize)) {
		(void) fprintf(stderr, "\n%s: 0x%08x:0x%08lx\n\n",
		    gettext("scadm: SC returned garbage"),
		    msg->type, msg->len);
		exit(-1);
	}

}


void
ADM_Free(rscp_msg_t *msg)
{
	if (rscp_free_msg(msg) != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: SC unable to free up memory"));
		exit(-1);
	}
}
