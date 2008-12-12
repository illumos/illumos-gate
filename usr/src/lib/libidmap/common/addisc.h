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

#include "idmap_priv.h"
#include "idmap_prot.h"
#include "idmap_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum string SID size. 4 bytes for "S-1-", 15 for 2^48 (max authority),
 * another '-', and ridcount (max 15) 10-digit RIDs plus '-' in between, plus
 * a null.
 */

#define	AD_DISC_MAXSID	185

typedef struct ad_disc *ad_disc_t;


typedef struct ad_disc_domains_in_forest {
	char domain[AD_DISC_MAXHOSTNAME];
	char sid[AD_DISC_MAXSID];
	int trusted;			/* This is not used by auto */
					/* discovery. It is provided so that */
					/* domains in a forest can be marked */
					/* as trusted. */
} ad_disc_domainsinforest_t;


typedef struct ad_disc_trusted_domains {
		char domain[AD_DISC_MAXHOSTNAME];
		int direction;
} ad_disc_trusteddomains_t;


enum ad_disc_req {
		AD_DISC_PREFER_SITE = 0, /* Prefer Site specific version */
		AD_DISC_SITE_SPECIFIC,	/* Request Site specific version */
		AD_DISC_GLOBAL		/* Request global version */
};

ad_disc_t ad_disc_init(void);

void ad_disc_fini(ad_disc_t);

/*
 * The following routines auto discover the specific item
 */
char *
ad_disc_get_DomainName(ad_disc_t ctx, int *auto_discovered);

idmap_ad_disc_ds_t *
ad_disc_get_DomainController(ad_disc_t ctx,
		enum ad_disc_req req, int *auto_discovered);

char *
ad_disc_get_SiteName(ad_disc_t ctx, int *auto_discovered);

char *
ad_disc_get_ForestName(ad_disc_t ctx, int *auto_discovered);

idmap_ad_disc_ds_t *
ad_disc_get_GlobalCatalog(ad_disc_t ctx, enum ad_disc_req,
				int *auto_discovered);

ad_disc_trusteddomains_t *
ad_disc_get_TrustedDomains(ad_disc_t ctx,  int *auto_discovered);

ad_disc_domainsinforest_t *
ad_disc_get_DomainsInForest(ad_disc_t ctx,  int *auto_discovered);


/*
 * The following routines over ride auto discovery with the
 * specified values
 */
int
ad_disc_set_DomainName(ad_disc_t ctx, const char *domainName);

int
ad_disc_set_DomainController(ad_disc_t ctx,
		const idmap_ad_disc_ds_t *domainController);

int
ad_disc_set_SiteName(ad_disc_t ctx, const char *siteName);

int
ad_disc_set_ForestName(ad_disc_t ctx, const char *forestName);

int
ad_disc_set_GlobalCatalog(ad_disc_t ctx,
		const idmap_ad_disc_ds_t *globalCatalog);


/*
 * This routine forces all auto discovery item to be recomputed
 * on request
 */
void ad_disc_refresh(ad_disc_t);

/* This routine unsets all overridden values */
int ad_disc_unset(ad_disc_t ctx);

/* This routine test for subnet changes */
int ad_disc_SubnetChanged(ad_disc_t);

/* This routine returns the Time To Live for auto discovered items */
int ad_disc_get_TTL(ad_disc_t);

int ad_disc_compare_ds(idmap_ad_disc_ds_t *ds1, idmap_ad_disc_ds_t *ds2);

int ad_disc_compare_trusteddomains(ad_disc_trusteddomains_t *td1,
		ad_disc_trusteddomains_t *td2);

int ad_disc_compare_domainsinforest(ad_disc_domainsinforest_t *td1,
		ad_disc_domainsinforest_t *td2);

#ifdef __cplusplus
}
#endif

#endif	/* _ADINFO_H */
