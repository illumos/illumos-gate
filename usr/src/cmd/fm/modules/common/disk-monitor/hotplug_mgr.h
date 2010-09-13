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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _HOTPLUG_MGR_H
#define	_HOTPLUG_MGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hotplug Manager declarations
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* These errors are OR'able */
typedef enum {
	HPM_ERR_POLLTHR_CREATION_FAILURES	= 1,
	HPM_ERR_SYSEVENT_INIT			= 2
} hotplug_mgr_init_err_t;

extern hotplug_state_t disk_ap_state_to_hotplug_state(diskmon_t *diskp);
extern hotplug_mgr_init_err_t init_hotplug_manager(void);
extern void cleanup_hotplug_manager(void);
extern void adjust_dynamic_ap(const char *, char *);

#ifdef	__cplusplus
}
#endif

#endif /* _HOTPLUG_MGR_H */
