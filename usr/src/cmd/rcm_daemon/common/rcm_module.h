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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _RCM_MODULE_H
#define	_RCM_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <librcm.h>

/*
 * Each RCM module is required to define
 *
 * struct rcm_mod_ops *rcm_mod_init();
 * const char *rcm_mod_info();
 * int rcm_mod_fini();
 *
 * The rcm_mod_init() is always invoked when the module is loaded. It should
 * return an rcm_mod_ops vector.
 *
 * Once the module is loaded, the regis() entry point is
 * called to allow the module to inform the framework all the
 * events and devices it cares about.
 *
 * If at any point of time, the module has no outstanding registration
 * against any device, the module will be unloaded. The rcm_mod_fini()
 * entry point, if defined, is always invoked before module unloading.
 */


/*
 * ops vector:
 * The ops version must have a valid version number and all function fields
 * must be non-NULL. Non-conforming RCM modules are rejected.
 *
 * Valid ops versions are defined below.
 */

#define	RCM_MOD_OPS_V1		1
#define	RCM_MOD_OPS_V2		2
#define	RCM_MOD_OPS_VERSION	RCM_MOD_OPS_V2

struct rcm_mod_ops {
	int	version;
	int	(*rcmop_register)(rcm_handle_t *);
	int	(*rcmop_unregister)(rcm_handle_t *);
	int	(*rcmop_get_info)(rcm_handle_t *, char *, id_t, uint_t,
			char **, char **, nvlist_t *, rcm_info_t **);
	int	(*rcmop_request_suspend)(rcm_handle_t *, char *, id_t,
			timespec_t *, uint_t, char **, rcm_info_t **);
	int	(*rcmop_notify_resume)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_request_offline)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_notify_online)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_notify_remove)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	/*
	 * Fields for version 2 and beyond
	 */
	int	(*rcmop_request_capacity_change)(rcm_handle_t *, char *, id_t,
			uint_t, nvlist_t *, char **, rcm_info_t **);
	int	(*rcmop_notify_capacity_change)(rcm_handle_t *, char *, id_t,
			uint_t, nvlist_t *, char **, rcm_info_t **);
	int	(*rcmop_notify_event)(rcm_handle_t *, char *, id_t, uint_t,
			char **, nvlist_t *, rcm_info_t **);
};

/*
 * Version 1 struct for compatibility
 */
struct rcm_mod_ops_v1 {
	int	version;
	int	(*rcmop_register)(rcm_handle_t *);
	int	(*rcmop_unregister)(rcm_handle_t *);
	int	(*rcmop_get_info)(rcm_handle_t *, char *, id_t, uint_t, char **,
			rcm_info_t **);
	int	(*rcmop_request_suspend)(rcm_handle_t *, char *, id_t,
			timespec_t *, uint_t, char **, rcm_info_t **);
	int	(*rcmop_notify_resume)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_request_offline)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_notify_online)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
	int	(*rcmop_notify_remove)(rcm_handle_t *, char *, id_t, uint_t,
			char **, rcm_info_t **);
};

/*
 * RCM modules should use rcm_log_message() instead of syslog().
 * This allows the daemon to control the amount of message to be
 * printed and to redirect output to screen for debugging purposes.
 */

/* message levels for rcm_log_message */

#define	RCM_ERROR	0	/* error message */
#define	RCM_WARNING	1
#define	RCM_NOTICE	2
#define	RCM_INFO	3
				/* 4 is not used for now */
#define	RCM_DEBUG	5	/* debug message */
#define	RCM_TRACE1	6	/* tracing message */
#define	RCM_TRACE2	7
#define	RCM_TRACE3	8
#define	RCM_TRACE4	9

extern void rcm_log_message(int, char *, ...);

#ifdef	__cplusplus
}
#endif

#endif /* _RCM_MODULE_H */
