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

#ifndef _PLUGIN_MGR_H
#define	_PLUGIN_MGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Declarations for the disk monitor plugin manager
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "dm_plugin.h"
#include "ipmi_plugin.h"

#define	DM_PLUGIN_DIR "/usr/lib/fm/fmd/plugins/dm"
#define	DM_PLUGIN_PREFIX "dmpi_"
#define	PROTOCOL_SEPARATOR ':'

typedef enum {
	DMPS_NONE,
	DMPS_LOADED,
	DMPS_INITED
} dm_plugin_state_t;

typedef struct dm_plugin {
	char			*protocol;
	dm_plugin_state_t	state;
	dm_plugin_ops_t		*ops;
	pthread_mutex_t		*mutex;
	struct dm_plugin	*next;
} dm_plugin_t;

typedef struct dm_plugin_action_handle_impl {
	dm_plugin_t				*plugin;
	char					*actionString;
	dm_plugin_action_handle_t		handle;
	struct dm_plugin_action_handle_impl	*next;
} dm_plugin_action_handle_impl_t;

extern int init_plugin_manager(void);
extern void cleanup_plugin_manager(void);

extern dm_plugin_error_t dm_pm_update_fru(const char *action, dm_fru_t *frup);
extern dm_plugin_error_t dm_pm_indicator_execute(const char *action);

#ifdef __cplusplus
}
#endif

#endif /* _PLUGIN_MGR_H */
