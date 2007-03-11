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

#ifndef _DM_PLUGIN_H
#define	_DM_PLUGIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Declarations for the disk monitor plugin interface
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "dm_types.h"

/*
 * The name of the symbol that is of type dm_plugin_ops_t that points to the
 * implementation of the plugin.
 */
#define	DM_PLUGIN_OPS_NAME "dm_plugin_ops"

#define	DM_PLUGIN_VERSION_1	1
#define	DM_PLUGIN_VERSION DM_PLUGIN_VERSION_1

typedef enum {
	DMPE_SUCCESS,
	DMPE_FAILURE
} dm_plugin_error_t;

typedef void *dm_plugin_action_handle_t;

typedef struct dm_plugin_ops {
	int			version;
	dm_plugin_error_t	(*_init)(void);
	dm_plugin_error_t	(*indicator_fru_update)(
	    const char *actionString, dm_fru_t *frup);
	dm_plugin_error_t	(*indicator_bind_handle)(
	    const char *actionString, dm_plugin_action_handle_t *hdlp);
	dm_plugin_error_t	(*indicator_execute)(
	    dm_plugin_action_handle_t hdl);
	dm_plugin_error_t	(*indicator_free_handle)(
	    dm_plugin_action_handle_t *hdlp);
	dm_plugin_error_t	(*_fini)(void);
} dm_plugin_ops_t;

extern const char *dm_plugin_prop_lookup(const char *propname);
extern pthread_t dm_plugin_thr_create(void (*fn)(void *), void *);
extern void dm_plugin_thr_signal(pthread_t);
extern void dm_plugin_thr_destroy(pthread_t);

#ifdef __cplusplus
}
#endif

#endif /* _DM_PLUGIN_H */
