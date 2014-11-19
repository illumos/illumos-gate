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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _IDMAP_CONFIG_H
#define	_IDMAP_CONFIG_H


#include "idmap.h"
#include "addisc.h"
#include <libscf.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_POLICY_SIZE 1023

#define	DIRECTORY_MAPPING_NONE	0
#define	DIRECTORY_MAPPING_NAME	1
#define	DIRECTORY_MAPPING_IDMU	2

struct enum_lookup_map {
	int value;
	char *string;
};

extern struct enum_lookup_map directory_mapping_map[];
extern const char *enum_lookup(int value, struct enum_lookup_map *map);

/* SMF and auto-discovery context handles */
typedef struct idmap_cfg_handles {
	pthread_mutex_t		mutex;
	scf_handle_t		*main;
	scf_instance_t		*instance;
	scf_service_t		*service;
	scf_propertygroup_t	*config_pg;
	scf_propertygroup_t	*debug_pg;
	ad_disc_t		ad_ctx;
} idmap_cfg_handles_t;

/*
 * This structure stores AD and AD-related configuration
 */
typedef struct idmap_trustedforest {
	char		*forest_name;
	idmap_ad_disc_ds_t
			*global_catalog;	/* global catalog hosts */
	ad_disc_domainsinforest_t
			*domains_in_forest;
} idmap_trustedforest_t;


typedef struct idmap_pg_config {
	uint64_t	list_size_limit;
	uint64_t	id_cache_timeout;
	uint64_t	name_cache_timeout;
	char		*machine_sid;		/* machine sid */
	char		*default_domain;	/* default domain name */
	char		*domain_name;		/* AD domain name */
	boolean_t		domain_name_auto_disc;
	idmap_ad_disc_ds_t
			*domain_controller;	/* domain controller hosts */
	boolean_t	domain_controller_auto_disc;
	char		*forest_name;		/* forest name */
	boolean_t	forest_name_auto_disc;
	char		*site_name;		/* site name */
	boolean_t	site_name_auto_disc;
	idmap_ad_disc_ds_t
			*global_catalog;	/* global catalog hosts */
	boolean_t	global_catalog_auto_disc;
	ad_disc_domainsinforest_t
			*domains_in_forest;
	ad_disc_trusteddomains_t
			*trusted_domains;	/* Trusted Domains */
	int		num_trusted_forests;
	idmap_trustedforest_t
			*trusted_forests;	/* Array of trusted forests */

	/*
	 * Following properties are associated with directory-based
	 * name-mappings.
	 */
	char		*ad_unixuser_attr;
	char		*ad_unixgroup_attr;
	char		*nldap_winname_attr;
	int		directory_based_mapping;	/* enum */
	boolean_t	eph_map_unres_sids;
	boolean_t	use_ads;
	boolean_t	use_lsa;
	boolean_t	disable_cross_forest_trusts;
} idmap_pg_config_t;

typedef struct idmap_cfg {
	idmap_pg_config_t	pgcfg;	    /* live AD/ID mapping config */
	idmap_cfg_handles_t	handles;
	int			initialized;
} idmap_cfg_t;


extern void 		idmap_cfg_unload(idmap_pg_config_t *);
extern int		idmap_cfg_load(idmap_cfg_t *, int);
extern idmap_cfg_t	*idmap_cfg_init(void);
extern int		idmap_cfg_fini(idmap_cfg_t *);
extern int		idmap_cfg_upgrade(idmap_cfg_t *);
extern int		idmap_cfg_start_updates(void);
extern void		idmap_cfg_poke_updates(void);
extern void		idmap_cfg_hup_handler(int);

#define	CFG_DISCOVER		0x1
#define	CFG_LOG			0x2

#ifdef __cplusplus
}
#endif

#endif /* _IDMAP_CONFIG_H */
