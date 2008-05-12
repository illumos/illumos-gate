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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ADINFO_H
#define	_ADINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "idmap_priv.h"
#include "idmap_prot.h"
#include "idmap_impl.h"

#ifdef __cplusplus
extern "C" {
#endif


enum ad_item_type {
		AD_TYPE_INVALID = 0,	/* The value is not valid */
		AD_TYPE_FIXED,		/* The value was fixed by caller */
		AD_TYPE_AUTO		/* The value is auto discovered */
		};


typedef struct ad_subnet {
	char subnet[24];
} ad_subnet_t;


typedef struct ad_item {
	enum ad_item_type type;
	union {
		char 		*str;
		idmap_ad_disc_ds_t	*ds;
	} value;
	time_t 		ttl;
	unsigned int 	version;	/* Version is only changed if the */
					/* value changes */
#define	PARAM1		0
#define	PARAM2		1
	int 		param_version[2];
					/* These holds the version of */
					/* dependents so that a dependent */
					/* change can be detected */
} ad_item_t;

typedef struct ad_disc {
	struct __res_state state;
	int		res_ninitted;
	ad_subnet_t	*subnets;
	int		subnets_changed;
	time_t		subnets_last_check;
	ad_item_t	domain_name;
	ad_item_t	domain_controller;
	ad_item_t	site_name;
	ad_item_t	forest_name;
	ad_item_t	global_catalog;
	/* Site specfic versions */
	ad_item_t	site_domain_controller;
	ad_item_t	site_global_catalog;
} ad_disc;

typedef struct ad_disc *ad_disc_t;



enum ad_disc_req {
		AD_DISC_PREFER_SITE = 0, /* Prefer Site specific version */
		AD_DISC_SITE_SPECIFIC,	/* Request Site specific version */
		AD_DISC_GLOBAL		/* Request global version */
};

ad_disc_t ad_disc_init(void);

void ad_disc_fini(ad_disc_t);

void ad_disc_refresh(ad_disc_t);

char *ad_disc_get_DomainName(ad_disc_t ctx);

idmap_ad_disc_ds_t *ad_disc_get_DomainController(ad_disc_t ctx,
    enum ad_disc_req req);

char *ad_disc_get_SiteName(ad_disc_t ctx);

char *ad_disc_get_ForestName(ad_disc_t ctx);

idmap_ad_disc_ds_t *ad_disc_get_GlobalCatalog(ad_disc_t ctx, enum ad_disc_req);

int ad_disc_compare_ds(idmap_ad_disc_ds_t *ds1, idmap_ad_disc_ds_t *ds2);

int ad_disc_set_DomainName(ad_disc_t ctx, const char *domainName);

int ad_disc_set_DomainController(ad_disc_t ctx,
				const idmap_ad_disc_ds_t *domainController);

int ad_disc_set_SiteName(ad_disc_t ctx, const char *siteName);

int ad_disc_set_ForestName(ad_disc_t ctx, const char *ForestName);

int ad_disc_set_GlobalCatalog(ad_disc_t ctx,
    const idmap_ad_disc_ds_t *GlobalCatalog);

int ad_disc_unset(ad_disc_t ctx);


int ad_disc_SubnetChanged(ad_disc_t);

int ad_disc_get_TTL(ad_disc_t);

#ifdef __cplusplus
}
#endif

#endif	/* _ADINFO_H */
