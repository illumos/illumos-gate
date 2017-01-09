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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IPC_RCTL_H
#define	_SYS_IPC_RCTL_H

#include <sys/rctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ipc_rqty {		/* datum protected by:	*/
	rctl_qty_t	ipcq_shmmni;	/* shm's ipcs_lock	*/
	rctl_qty_t	ipcq_semmni;	/* sem's ipcs_lock	*/
	rctl_qty_t	ipcq_msgmni;	/* msg's ipcs_lock	*/
} ipc_rqty_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IPC_RCTL_H */
