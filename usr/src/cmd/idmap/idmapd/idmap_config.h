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

#ifndef _IDMAP_CONFIG_H
#define	_IDMAP_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "idmap.h"
#include <libscf.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_POLICY_SIZE 1023

typedef struct idmap_scf_handles {
	scf_handle_t		*main;
	scf_instance_t		*instance;
	scf_service_t		*service;
	scf_propertygroup_t	*config_pg;
	scf_propertygroup_t	*general_pg;
} idmap_scf_handles_t;

typedef struct idmap_pg_config {
	uint64_t	list_size_limit;
	char		*mapping_domain;	/* mapping dopmain */
	char		*machine_sid;		/* machine sid */
	char		*global_catalog;	/* global catalog host */
	char		*domain_controller;	/* domain controller host */
						/* for mapping domain */
} idmap_pg_config_t;

typedef struct idmap_cfg {
	idmap_pg_config_t	pgcfg;
	idmap_scf_handles_t	handles;
} idmap_cfg_t;

extern idmap_cfg_t	*idmap_cfg_init();
extern int		idmap_cfg_fini(idmap_cfg_t *);
extern int		idmap_cfg_load(idmap_cfg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IDMAP_CONFIG_H */
