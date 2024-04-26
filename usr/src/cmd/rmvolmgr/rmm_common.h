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

#ifndef	_COMMON_H
#define	_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <unistd.h>
#include <zone.h>

#include <glib.h>
#include <libhal.h>
#include <libhal-storage.h>

#include "vold.h"

typedef enum {
	RMM_EOK = 0,
	RMM_EDBUS_CONNECT,	/* cannot connect to DBUS */
	RMM_EHAL_CONNECT	/* cannot connect to HAL */
} rmm_error_t;

enum {
	RMM_PRINT_MOUNTABLE	= 0x1,
	RMM_PRINT_EJECTABLE	= 0x2
};

/* D-Bus timeout in milliseconds */
enum {
	RMM_MOUNT_TIMEOUT	= 60000,
	RMM_UNMOUNT_TIMEOUT	= 60000,
	RMM_EJECT_TIMEOUT	= 60000,
	RMM_CLOSETRAY_TIMEOUT	= 60000
};

#define	HAL_BRANCH_LOCAL	"/org/freedesktop/Hal/devices/local"

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

extern char *progname;

LibHalContext	*rmm_hal_init(LibHalDeviceAdded, LibHalDeviceRemoved,
		LibHalDevicePropertyModified, LibHalDeviceCondition,
		DBusError *, rmm_error_t *);
void		rmm_hal_fini(LibHalContext *hal_ctx);

LibHalDrive	*rmm_hal_volume_find(LibHalContext *, const char *,
		DBusError *, GSList **);
LibHalDrive	*rmm_hal_volume_find_default(LibHalContext *, DBusError *,
		const char **, GSList **);
LibHalDrive	*rmm_hal_volume_findby(LibHalContext *, const char *,
		const char *, GSList **);
LibHalDrive	*rmm_hal_volume_findby_nickname(LibHalContext *, const char *,
		GSList **);
void		rmm_print_volume_nicknames(LibHalContext *, DBusError *, int);
void		rmm_volumes_free(GSList *);

boolean_t	rmm_hal_mount(LibHalContext *, const char *,
		char **, int, char *, DBusError *);
boolean_t	rmm_hal_unmount(LibHalContext *, const char *, DBusError *);
boolean_t	rmm_hal_eject(LibHalContext *, const char *, DBusError *);
boolean_t	rmm_hal_closetray(LibHalContext *, const char *, DBusError *);
boolean_t	rmm_hal_rescan(LibHalContext *, const char *, DBusError *);
boolean_t	rmm_hal_claim_branch(LibHalContext *, const char *);
boolean_t	rmm_hal_unclaim_branch(LibHalContext *, const char *);

boolean_t	rmm_action(LibHalContext *, const char *name, action_t action,
		struct action_arg *aap, char **, int, char *);
boolean_t	rmm_rescan(LibHalContext *, const char *, boolean_t);

void		rmm_update_vold_mountpoints(LibHalContext *, const char *,
		struct action_arg *);

boolean_t	rmm_volume_aa_from_prop(LibHalContext *, const char *,
		LibHalVolume *, struct action_arg *);
void		rmm_volume_aa_update_mountpoint(LibHalContext *, const char *,
		struct action_arg *aap);
void		rmm_volume_aa_free(struct action_arg *);

char		*rmm_get_mnttab_mount_point(const char *);
const char	*rmm_strerror(DBusError *, int);
void		rmm_dbus_error_free(DBusError *);

char		*rmm_vold_convert_volume_label(const char *name, size_t len);
int		makepath(char *, mode_t);
void		dbgprintf(const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _COMMON_H */
