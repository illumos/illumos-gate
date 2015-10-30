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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_ADINFO_H
#define	_ADINFO_H

#include <sys/socket.h>
#include <sys/uuid.h>
#include "libadutils.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum string SID size. 4 bytes for "S-1-", 15 for 2^48 (max authority),
 * another '-', and ridcount (max 15) 10-digit RIDs plus '-' in between, plus
 * a null.
 */
#define	MAXSTRSID		185
#define	MAXDOMAINNAME		256
#define	AD_DISC_MAXHOSTNAME	256

typedef struct ad_disc *ad_disc_t;


typedef struct ad_disc_domains_in_forest {
	char domain[MAXDOMAINNAME];
	char sid[MAXSTRSID];
	int trusted;			/* This is not used by auto */
					/* discovery. It is provided so that */
					/* domains in a forest can be marked */
					/* as trusted. */
} ad_disc_domainsinforest_t;


typedef struct ad_disc_trusted_domains {
		char domain[MAXDOMAINNAME];
		int direction;
} ad_disc_trusteddomains_t;

enum ad_disc_req {
		AD_DISC_PREFER_SITE = 0, /* Prefer Site specific version */
		AD_DISC_SITE_SPECIFIC,	/* Request Site specific version */
		AD_DISC_GLOBAL		/* Request global version */
};

/*
 * First four members of this are like idmap_ad_disc_ds_t
 * (for compatiblity) until that can be eliminated.
 * See PROP_DOMAIN_CONTROLLER in idmapd/server.c
 */
typedef struct ad_disc_ds {
	/* Keep these first four in sync with idmap_ad_disc_ds_t */
	int port;
	int priority;
	int weight;
	char host[AD_DISC_MAXHOSTNAME];
	/* Members after this are private and free to change. */
	char site[AD_DISC_MAXHOSTNAME];
	struct sockaddr_storage addr;
	uint32_t flags;
	uint32_t ttl;
} ad_disc_ds_t;

ad_disc_t ad_disc_init(void);

void ad_disc_fini(ad_disc_t);

/*
 * The following routines auto discover the specific item
 */
char *
ad_disc_get_DomainName(ad_disc_t ctx, boolean_t *auto_discovered);

uchar_t *
ad_disc_get_DomainGUID(ad_disc_t ctx, boolean_t *auto_discovered);

ad_disc_ds_t *
ad_disc_get_DomainController(ad_disc_t ctx,
		enum ad_disc_req req, boolean_t *auto_discovered);

ad_disc_ds_t *
ad_disc_get_PreferredDC(ad_disc_t ctx, boolean_t *auto_discovered);

char *
ad_disc_get_SiteName(ad_disc_t ctx, boolean_t *auto_discovered);

char *
ad_disc_get_ForestName(ad_disc_t ctx, boolean_t *auto_discovered);

ad_disc_ds_t *
ad_disc_get_GlobalCatalog(ad_disc_t ctx, enum ad_disc_req,
				boolean_t *auto_discovered);

ad_disc_trusteddomains_t *
ad_disc_get_TrustedDomains(ad_disc_t ctx,  boolean_t *auto_discovered);

ad_disc_domainsinforest_t *
ad_disc_get_DomainsInForest(ad_disc_t ctx,  boolean_t *auto_discovered);


/*
 * The following routines over ride auto discovery with the
 * specified values
 */
int
ad_disc_set_DomainName(ad_disc_t ctx, const char *domainName);

int
ad_disc_set_DomainGUID(ad_disc_t ctx, uchar_t *u);

int
ad_disc_set_DomainController(ad_disc_t ctx,
		const ad_disc_ds_t *domainController);
int
ad_disc_set_PreferredDC(ad_disc_t ctx, const ad_disc_ds_t *dc);

int
ad_disc_set_SiteName(ad_disc_t ctx, const char *siteName);

int
ad_disc_set_ForestName(ad_disc_t ctx, const char *forestName);

int
ad_disc_set_GlobalCatalog(ad_disc_t ctx,
		const ad_disc_ds_t *globalCatalog);

/*
 * This function sets a FILE * on which this library will write
 * progress information during DC Location.
 */
void
ad_disc_set_StatusFP(ad_disc_t ctx, struct __FILE_TAG *);

int
ad_disc_getnameinfo(char *, int, struct sockaddr_storage *);

/*
 * This routine forces all auto discovery item to be recomputed
 * on request
 */
void ad_disc_refresh(ad_disc_t);

/*
 * This routine marks the end of a discovery cycle and sets
 * the sanity limits on the time before the next cycle.
 */
void ad_disc_done(ad_disc_t);

/* This routine unsets all overridden values */
int ad_disc_unset(ad_disc_t ctx);

/* This routine test for subnet changes */
boolean_t ad_disc_SubnetChanged(ad_disc_t);

/* This routine returns the Time To Live for auto discovered items */
int ad_disc_get_TTL(ad_disc_t);

int ad_disc_compare_uuid(uuid_t *u1, uuid_t *u2);

int ad_disc_compare_ds(ad_disc_ds_t *ds1, ad_disc_ds_t *ds2);

int ad_disc_compare_trusteddomains(ad_disc_trusteddomains_t *td1,
		ad_disc_trusteddomains_t *td2);

int ad_disc_compare_domainsinforest(ad_disc_domainsinforest_t *td1,
		ad_disc_domainsinforest_t *td2);

#ifdef __cplusplus
}
#endif

#endif	/* _ADINFO_H */
