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
#include "addisc.h"
#include <libscf.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_POLICY_SIZE 1023

/* SMF and auto-discovery context handles */
typedef struct idmap_cfg_handles {
	pthread_mutex_t		mutex;
	scf_handle_t		*main;
	scf_instance_t		*instance;
	scf_service_t		*service;
	scf_propertygroup_t	*config_pg;
	scf_propertygroup_t	*general_pg;
	ad_disc_t		ad_ctx;
} idmap_cfg_handles_t;

/*
 * This structure stores AD and AD-related configuration
 */
typedef struct idmap_pg_config {
	uint64_t	list_size_limit;
	/*
	 * The idmap_cfg_update_thread() uses the ad_disc_t context in
	 * the idmap_cfg_handles_t (see above) to track which values
	 * came from SMF and which values didn't.  This works for all
	 * items that are discoverable, but default_domain (the domain
	 * that we qualify unqualified names passed to idmap show) is
	 * not discoverable independently of domain_name.  So we need to
	 * track its procedence separately.  The dflt_dom_set_in_smf
	 * field does just that.
	 */
	bool_t		dflt_dom_set_in_smf;
	char		*default_domain;	/* default domain name */
	char		*domain_name;		/* AD domain name */
	char		*machine_sid;		/* machine sid */
	ad_disc_ds_t	*domain_controller;	/* domain controller hosts */
	char		*forest_name;		/* forest name */
	char		*site_name;		/* site name */
	ad_disc_ds_t	*global_catalog;	/* global catalog hosts */
} idmap_pg_config_t;

typedef struct idmap_cfg {
	idmap_pg_config_t	pgcfg;	    /* live AD/ID mapping config */
	idmap_cfg_handles_t	handles;
} idmap_cfg_t;


extern void 		idmap_cfg_unload(idmap_pg_config_t *);
extern int		idmap_cfg_load(idmap_cfg_handles_t *,
					idmap_pg_config_t *);
extern idmap_cfg_t	*idmap_cfg_init(void);
extern int		idmap_cfg_fini(idmap_cfg_t *);
extern int		idmap_cfg_start_updates(idmap_cfg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IDMAP_CONFIG_H */
