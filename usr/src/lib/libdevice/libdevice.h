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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBDEVICE_H
#define	_LIBDEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/devctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DC_EXCL		0x01
#define	DC_RDONLY	0x02

typedef struct devctl_dummy_struct *devctl_hdl_t;
typedef struct devctl_dummy_ddef *devctl_ddef_t;


devctl_hdl_t
devctl_device_acquire(char *devfs_path, uint_t flags);

devctl_hdl_t
devctl_bus_acquire(char *devfs_path, uint_t flags);

devctl_hdl_t
devctl_ap_acquire(char *devfs_path, uint_t flags);

devctl_hdl_t
devctl_pm_dev_acquire(char *devfs_path, uint_t flags);

devctl_hdl_t
devctl_pm_bus_acquire(char *devfs_path, uint_t flags);

void
devctl_release(devctl_hdl_t hdl);

int
devctl_device_offline(devctl_hdl_t hdl);

int
devctl_device_remove(devctl_hdl_t hdl);

int
devctl_pm_raisepower(devctl_hdl_t hdl);

int
devctl_pm_changepowerlow(devctl_hdl_t hdl);

int
devctl_pm_changepowerhigh(devctl_hdl_t hdl);

int
devctl_pm_idlecomponent(devctl_hdl_t hdl);

int
devctl_pm_busycomponent(devctl_hdl_t hdl);

int
devctl_pm_testbusy(devctl_hdl_t hdl, uint_t *busyp);

int
devctl_pm_failsuspend(devctl_hdl_t hdl);

int
devctl_pm_bus_teststrict(devctl_hdl_t hdl, uint_t *strict);

int
devctl_pm_device_changeonresume(devctl_hdl_t hdl);

int
devctl_pm_device_no_lower_power(devctl_hdl_t hdl);

int
devctl_pm_bus_no_invol(devctl_hdl_t hdl);

int
devctl_pm_device_promprintf(devctl_hdl_t hdl);

int
devctl_device_online(devctl_hdl_t hdl);

int
devctl_device_reset(devctl_hdl_t hdl);

int
devctl_device_getstate(devctl_hdl_t hdl, uint_t *statep);

int
devctl_bus_quiesce(devctl_hdl_t hdl);

int
devctl_bus_unquiesce(devctl_hdl_t hdl);

int
devctl_bus_reset(devctl_hdl_t hdl);

int
devctl_bus_resetall(devctl_hdl_t hdl);

int
devctl_bus_getstate(devctl_hdl_t hdl, uint_t *statep);

int
devctl_bus_configure(devctl_hdl_t hdl);

int
devctl_bus_unconfigure(devctl_hdl_t hdl);

int
devctl_ap_insert(devctl_hdl_t, nvlist_t *);

int
devctl_ap_remove(devctl_hdl_t, nvlist_t *);

int
devctl_ap_connect(devctl_hdl_t, nvlist_t *);

int
devctl_ap_disconnect(devctl_hdl_t, nvlist_t *);

int
devctl_ap_configure(devctl_hdl_t, nvlist_t *);

int
devctl_ap_unconfigure(devctl_hdl_t, nvlist_t *);

int
devctl_ap_getstate(devctl_hdl_t, nvlist_t *, devctl_ap_state_t *);

devctl_ddef_t
devctl_ddef_alloc(char *, int);

void
devctl_ddef_free(devctl_ddef_t);

int
devctl_ddef_int(devctl_ddef_t, char *, int32_t);

int
devctl_ddef_int_array(devctl_ddef_t, char *, int, int32_t *);

int
devctl_ddef_string(devctl_ddef_t ddef_hdl, char *, char *);

int
devctl_ddef_string_array(devctl_ddef_t, char *, int, char **);

int
devctl_ddef_byte_array(devctl_ddef_t, char *, int, uchar_t *);

int
devctl_bus_dev_create(devctl_hdl_t, devctl_ddef_t, uint_t, devctl_hdl_t *);

char *
devctl_get_pathname(devctl_hdl_t, char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDEVICE_H */
