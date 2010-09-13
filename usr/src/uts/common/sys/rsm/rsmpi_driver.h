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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_RSM_RSMPI_DRIVER_H
#define	_SYS_RSM_RSMPI_DRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/rsm/rsmpi.h>

/*
 * The following is information which each RSMPI driver must
 * provide when registering with the RSMOPS module
 */
#define	MAX_DRVNAME	15

typedef struct rsmops_registry {
	unsigned int rsm_version;	/* version of the RSMPI driver */
	char drv_name[MAX_DRVNAME+1];	/* name of the RSMPI driver */
	int (*rsm_get_controller_handler)(const char *name,
		uint_t number,
		rsm_controller_object_t *pcontroller,
		uint_t version);
	int (*rsm_release_controller_handler)(const char *name,
		uint_t number,
		rsm_controller_object_t *pcontroller);
	void (*rsm_thread_entry_pt)(const char *name /* name of driver */);
} rsmops_registry_t;

typedef struct rsmops_ctrl_registry {
	uint_t	number;
	int refcnt;		/* number of outstanding handles */
	rsm_controller_attr_t *attrp;
	rsm_controller_handle_t handle;
	struct rsmops_ctrl_registry *next;
	struct rsmops_drv_registry *p_drv;	/* back ptr to drvr struct */
} rsmops_ctrl_t;

typedef struct rsmops_drv_registry {
	rsmops_registry_t drv;
	int ctrl_cnt;	/* Number of controllers which have registered */
	struct rsmops_drv_registry *next;
	rsmops_ctrl_t *ctrl_head;
	kthread_id_t thread_id;
} rsmops_drv_t;

int rsm_register_controller(const char *name,
	uint_t number, rsm_controller_attr_t *attrp);

int rsm_unregister_controller(const char *name, uint_t number);

int rsm_register_driver(rsmops_registry_t *p_registry);
int rsm_unregister_driver(rsmops_registry_t *p_registry);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RSM_RSMPI_DRIVER_H */
