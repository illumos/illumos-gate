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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_HOTPLUG_HPCSVC_H
#define	_SYS_HOTPLUG_HPCSVC_H

#include <sys/hotplug/hpctrl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* flags for event handling */
#define	HPC_EVENT_NORMAL	0	/* normal, queued event handling */
#define	HPC_EVENT_SYNCHRONOUS	1	/* unqueued sync. event handling */

extern int hpc_nexus_register_bus(dev_info_t *dip,
	int (* callback)(dev_info_t *dip, hpc_slot_t handle,
		hpc_slot_info_t *slot_info, int slot_state),
	uint_t flags);
extern int hpc_nexus_unregister_bus(dev_info_t *dip);
extern int hpc_nexus_connect(hpc_slot_t handle, void *data, uint_t flags);
extern int hpc_nexus_disconnect(hpc_slot_t handle, void *data, uint_t flags);
extern int hpc_nexus_insert(hpc_slot_t handle, void *data, uint_t flags);
extern int hpc_nexus_remove(hpc_slot_t handle, void *data, uint_t flags);
extern int hpc_nexus_control(hpc_slot_t handle, int request, caddr_t arg);
extern int hpc_install_event_handler(hpc_slot_t handle, uint_t event_mask,
	int (*event_handler)(caddr_t, uint_t), caddr_t arg);
extern int hpc_remove_event_handler(hpc_slot_t handle);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_HPCSVC_H */
