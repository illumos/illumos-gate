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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_ADDISC_IMPL_H
#define	_ADDISC_IMPL_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <resolv.h>
#include <ldap.h>
#include <pthread.h>
#include "addisc.h"
#include "libadutils.h"

#ifdef	__cplusplus
extern "C" {
#endif

enum ad_item_state {
		AD_STATE_INVALID = 0,	/* The value is not valid */
		AD_STATE_FIXED,		/* The value was fixed by caller */
		AD_STATE_AUTO		/* The value is auto discovered */
		};

enum ad_data_type {
		AD_STRING = 123,
		AD_UUID,
		AD_DIRECTORY,
		AD_DOMAINS_IN_FOREST,
		AD_TRUSTED_DOMAINS
		};


typedef struct ad_subnet {
	char subnet[24];
} ad_subnet_t;


typedef struct ad_item {
	enum ad_item_state	state;
	enum ad_data_type	type;
	void 			*value;
	time_t 			expires;
	unsigned int 		version;	/* Version is only changed */
						/* if the value changes */
#define	PARAM1		0
#define	PARAM2		1
	int 		param_version[2];
					/* These holds the version of */
					/* dependents so that a dependent */
					/* change can be detected */
} ad_item_t;

typedef struct ad_disc {
	struct __res_state res_state;
	int		res_ninitted;
	ad_subnet_t	*subnets;
	boolean_t	subnets_changed;
	time_t		subnets_last_check;
	time_t		expires_not_before;
	time_t		expires_not_after;
	ad_item_t	domain_name;		/* DNS hostname string */
	ad_item_t	domain_guid;		/* Domain UUID (binary) */
	ad_item_t	domain_controller;	/* Directory hostname and */
						/* port array */
	ad_item_t	preferred_dc;
	ad_item_t	site_name;		/* String */
	ad_item_t	forest_name;		/* DNS forestname string */
	ad_item_t	global_catalog;		/* Directory hostname and */
						/* port array */
	ad_item_t	domains_in_forest;	/* DNS domainname and SID */
						/* array */
	ad_item_t	trusted_domains;	/* DNS domainname and trust */
						/* direction array */
	/* Site specfic versions */
	ad_item_t	site_domain_controller;	/* Directory hostname and */
						/* port array */
	ad_item_t	site_global_catalog;	/* Directory hostname and */
						/* port array */
	/* Optional FILE * for DC Location status. */
	struct __FILE_TAG *status_fp;

	int		debug[AD_DEBUG_MAX+1];	/* Debug levels */
} ad_disc;

/* Candidate Directory Servers (CDS) */
typedef struct ad_disc_cds {
	struct ad_disc_ds cds_ds;
	struct addrinfo *cds_ai;
} ad_disc_cds_t;

ad_disc_ds_t *ldap_ping(ad_disc_t, ad_disc_cds_t *, char *, int);

int srv_getdom(res_state, const char *, char **);
ad_disc_cds_t *srv_query(res_state, const char *, const char *,
    ad_disc_ds_t *);
void srv_free(ad_disc_cds_t *);

void auto_set_DomainGUID(ad_disc_t, uchar_t *);
void auto_set_ForestName(ad_disc_t, char *);
void auto_set_SiteName(ad_disc_t, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _ADDISC_IMPL_H */
