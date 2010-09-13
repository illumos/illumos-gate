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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MBOXSC_H
#define	_MBOXSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the Starcat Domain Mailbox Interface, as implemented in
 * the mboxsc module.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Mailbox message types, for use in mboxsc_putmsg() and mboxsc_getmsg() calls.
 * NOTE: Clients should not use the MBOXSC_NUM_MSG_TYPES value, which
 *       is used internally to simplify future code maintenance.
 */

#define	MBOXSC_MSG_REQUEST	0x01
#define	MBOXSC_MSG_REPLY	0x02
#define	MBOXSC_MSG_EVENT	0x04
#define	MBOXSC_NUM_MSG_TYPES	3

/*
 * Mailbox directions, for use in mboxsc_init().
 */
#define	MBOXSC_MBOX_IN		0
#define	MBOXSC_MBOX_OUT		1


#ifdef _KERNEL
/*
 * Mailbox control commands, for use in mboxsc_ctrl().
 */
#define	MBOXSC_CMD_VERSION			1
#define	MBOXSC_CMD_MAXVERSION			2
#define	MBOXSC_CMD_MAXDATALEN			3
#define	MBOXSC_CMD_PUTMSG_TIMEOUT_RANGE		4
#define	MBOXSC_CMD_GETMSG_TIMEOUT_RANGE		5

/*
 * The argument for the TIMEOUT_RANGE control commands is a pointer to one of
 * these.
 */
typedef struct mboxsc_timeout_range {
	clock_t min_timeout;
	clock_t max_timeout;
} mboxsc_timeout_range_t;

/*
 * Mailbox interface functions available to in-kernel clients on Starcat
 * Domains.
 * NOTE: The timeout arguments to mboxsc_putmsg() and mboxsc_getmsg() are
 *       interpreted as milliseconds.
 */
extern int mboxsc_init(uint32_t key, int direction, void
	(*event_handler)(void));
extern int mboxsc_fini(uint32_t key);
extern int mboxsc_putmsg(uint32_t key, uint32_t type, uint32_t cmd,
	uint64_t *transid, uint32_t length, void *datap, clock_t timeout);
extern int mboxsc_getmsg(uint32_t key, uint32_t *type, uint32_t *cmd,
	uint64_t *transid, uint32_t *length, void *datap, clock_t timeout);
extern int mboxsc_ctrl(uint32_t key, uint32_t cmd, void *arg);
extern clock_t mboxsc_putmsg_def_timeout(void);
#define	MBOXSC_PUTMSG_DEF_TIMEOUT	mboxsc_putmsg_def_timeout()

#ifdef DEBUG
/*
 * The following commands may be passed in to the mboxsc_debug() function to
 * dump data to the console that wouldn't be available through normal
 * (non-debug) functions.
 */
#define	MBOXSC_PRNMBOX		1	/* display a particular mailbox */
#define	MBOXSC_PRNHASHTBL	2	/* display the whole hash table */
#define	MBOXSC_SETDBGMASK	3	/* set the debug mask */

/*
 * Debugging interface routine.
 */
extern int mboxsc_debug(int cmd, void *arg);

#endif /* DEBUG */
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _MBOXSC_H */
