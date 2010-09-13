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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	SCRIPT_HANDLER_H
#define	SCRIPT_HANDLER_H

#include "common.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The signal SIGTERM is sent to a script process if it does not exit after
 * SCRIPT_TIMEOUT seconds; and the signal SIGKILL is sent if it is still alive
 * SCRIPT_TIMEOUT_GRACE seconds after SIGTERM is sent. (SCRIPT_TIMEOUT +
 * SCRIPT_TIMEOUT_GRACE) should be less than DHCP_ASYNC_WAIT.
 */
#define	SCRIPT_TIMEOUT		55
#define	SCRIPT_TIMEOUT_GRACE	3

/*
 * script exit status as dhcpagent sees it, for debug purpose only.
 *
 * SCRIPT_OK:		script exits ok, no timeout
 * SCRIPT_KILLED:	script timeout, killed
 * SCRIPT_FAILED:	unknown status
 */

enum { SCRIPT_OK, SCRIPT_KILLED, SCRIPT_FAILED };

/*
 * event names for script.
 */
#define	EVENT_BOUND	"BOUND"
#define	EVENT_EXTEND	"EXTEND"
#define	EVENT_EXPIRE	"EXPIRE"
#define	EVENT_DROP	"DROP"
#define	EVENT_INFORM	"INFORM"
#define	EVENT_RELEASE	"RELEASE"

#define	EVENT_BOUND6	"BOUND6"
#define	EVENT_EXTEND6	"EXTEND6"
#define	EVENT_EXPIRE6	"EXPIRE6"
#define	EVENT_DROP6	"DROP6"
#define	EVENT_INFORM6	"INFORM6"
#define	EVENT_LOSS6	"LOSS6"
#define	EVENT_RELEASE6	"RELEASE6"

/*
 * script location.
 */
#define	SCRIPT_PATH	"/etc/dhcp/eventhook"

/*
 * the number of running scripts.
 */
extern unsigned int	script_count;

void		script_init(dhcp_smach_t *);
boolean_t	script_start(dhcp_smach_t *, const char *, script_callback_t *,
		    void *, int *);
void		script_stop(dhcp_smach_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* SCRIPT_HANDLER_H */
