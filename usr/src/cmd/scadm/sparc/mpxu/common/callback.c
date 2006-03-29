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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * callback.c: callback routine called whenever a BP message is received from
 * the service processor (BP messages are received ONLY in a firmware download
 * context)
 */

#include <libintl.h>
#include <stdio.h>
#include <time.h>

#include "adm.h"
#include "librsc.h"
#include "smq.h"


smq_t		ADM_bpMsgQueue;
smq_msg_t	ADM_bpMsgBuffer[ADM_BP_BUFF_SIZE];


void
ADM_Callback(bp_msg_t *Message)
{
	void *msgp = (void *)Message;

	if (smq_send(&ADM_bpMsgQueue, (smq_msg_t *)msgp) != 0) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: INTERNAL ERROR, overflow in callback"));
		exit(-1);
	}
}
